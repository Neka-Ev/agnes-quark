//! Download engine: parallel chunked file transfers and recursive folder downloads.
//!
//! Downloads are resumable: the partial payload is written to a deterministic
//! per-chunk `.part` files next to the destination and continued with HTTP Range
//! requests after a restart or a transient network failure.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use futures_util::stream;
use futures_util::{StreamExt, TryStreamExt};
use quark_core::domain::{
    DownloadFileRequest, ListFilesRequest, ProviderError, ProviderErrorCategory, ProviderResult,
    RemoteFileItem, RemoteFileKind, StorageProviderAccount,
};
use quark_core::ports::{FileSourceProvider, ProviderCredentialAccess, ProviderFactory};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::db::{Db, DownloadRow};
use crate::vault::Vault;

const MAX_ATTEMPTS: usize = 5;
const MAX_FOLDER_DEPTH: usize = 64;
const MAX_FOLDER_ITEMS: usize = 10_000;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);
const PROGRESS_BYTES: u64 = 1024 * 1024;
const MIN_CHUNK_SIZE: u64 = 64 * 1024;
const MAX_PARALLEL_PER_FILE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("download cancelled")]
    Cancelled,
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

impl From<ProviderError> for DownloadError {
    fn from(error: ProviderError) -> Self {
        Self::Failed(anyhow::Error::new(error))
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(error: std::io::Error) -> Self {
        Self::Failed(error.into())
    }
}

impl From<rusqlite::Error> for DownloadError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Failed(error.into())
    }
}

type DResult<T> = Result<T, DownloadError>;

#[derive(Clone)]
pub struct DownloadEngine {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    vault: Arc<Vault>,
    factory: Arc<quark_core::QuarkDriveFactory>,
    root: PathBuf,
    root_canonical: PathBuf,
    sender: mpsc::UnboundedSender<String>,
    cancellations: StdMutex<HashMap<String, Arc<AtomicBool>>>,
    chunk_size: u64,
    parallel_per_file: usize,
}

/// Runtime tuning for file transfers.
#[derive(Debug, Clone, Copy)]
pub struct DownloadTuning {
    pub concurrency: usize,
    pub chunk_size: u64,
    pub parallel_per_file: usize,
}

impl DownloadEngine {
    /// Create the engine and spawn the worker pool.
    pub fn start(
        db: Db,
        vault: Arc<Vault>,
        factory: Arc<quark_core::QuarkDriveFactory>,
        root: PathBuf,
        root_canonical: PathBuf,
        tuning: DownloadTuning,
    ) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        let engine = Self {
            inner: Arc::new(Inner {
                db,
                vault,
                factory,
                root,
                root_canonical,
                sender,
                cancellations: StdMutex::new(HashMap::new()),
                chunk_size: tuning.chunk_size.clamp(MIN_CHUNK_SIZE, 64 * 1024 * 1024),
                parallel_per_file: tuning.parallel_per_file.clamp(1, MAX_PARALLEL_PER_FILE),
            }),
        };

        for index in 0..tuning.concurrency.max(1) {
            let engine = engine.clone();
            let receiver = receiver.clone();
            tokio::spawn(async move {
                loop {
                    let next = { receiver.lock().await.recv().await };
                    match next {
                        Some(id) => engine.run(id).await,
                        None => break,
                    }
                }
                info!(worker = index, "download worker stopped");
            });
        }

        engine
    }

    /// Queue a previously persisted download row.
    pub fn enqueue(&self, id: String) {
        let _ = self.inner.sender.send(id);
    }

    /// Request cancellation. Queued tasks are cancelled immediately; running
    /// tasks notice the flag between stream chunks.
    pub async fn cancel(&self, id: &str) -> anyhow::Result<bool> {
        let Some(row) = self.inner.db.get_download(id).await? else {
            return Ok(false);
        };
        if matches!(row.status.as_str(), "queued" | "running") {
            if let Ok(mut flags) = self.inner.cancellations.lock() {
                flags
                    .entry(id.to_owned())
                    .or_insert_with(|| Arc::new(AtomicBool::new(false)))
                    .store(true, Ordering::SeqCst);
            }
        }
        if row.status == "queued" {
            self.inner
                .db
                .set_download_status(id, "cancelled", None)
                .await?;
        }
        Ok(true)
    }

    async fn run(&self, id: String) {
        let row = match self.inner.db.get_download(&id).await {
            Ok(Some(row)) => row,
            Ok(None) => return,
            Err(error) => {
                warn!(download = %id, %error, "cannot load download row");
                return;
            }
        };
        if matches!(row.status.as_str(), "completed" | "cancelled") {
            return;
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let already_cancelled = {
            let mut flags = match self.inner.cancellations.lock() {
                Ok(flags) => flags,
                Err(poisoned) => poisoned.into_inner(),
            };
            let was_cancelled = flags
                .get(&id)
                .is_some_and(|flag| flag.load(Ordering::SeqCst));
            if was_cancelled {
                flags.remove(&id);
            } else {
                flags.insert(id.clone(), cancel.clone());
            }
            was_cancelled
        };
        if already_cancelled {
            let _ = self
                .inner
                .db
                .set_download_status(&id, "cancelled", None)
                .await;
            return;
        }

        if let Err(error) = self
            .inner
            .db
            .set_download_status(&id, "running", None)
            .await
        {
            warn!(download = %id, %error, "cannot mark download as running");
            return;
        }

        let result = self.execute(&row, &cancel).await;

        match result {
            Ok(()) => {
                let _ = self
                    .inner
                    .db
                    .set_download_status(&id, "completed", None)
                    .await;
                info!(download = %id, "download completed");
            }
            Err(DownloadError::Cancelled) => {
                let _ = self
                    .inner
                    .db
                    .set_download_status(&id, "cancelled", None)
                    .await;
                info!(download = %id, "download cancelled");
            }
            Err(DownloadError::Failed(error)) => {
                warn!(download = %id, %error, "download failed");
                let _ = self
                    .inner
                    .db
                    .set_download_status(&id, "failed", Some(&format!("{error:#}")))
                    .await;
            }
        }

        if let Ok(mut flags) = self.inner.cancellations.lock() {
            flags.remove(&id);
        }
    }

    async fn execute(&self, row: &DownloadRow, cancel: &AtomicBool) -> DResult<()> {
        let account = self
            .inner
            .db
            .get_account(&row.account_id)
            .await?
            .ok_or_else(|| anyhow!("账户不存在，可能已被删除"))?;

        let credential = Zeroizing::new(
            self.inner
                .vault
                .decrypt(&account.credential)
                .context("无法解密账户凭证")?,
        );
        let (has_official, has_cookie) = quark_core::credential_capabilities(&credential);
        if row.kind == "folder" && !has_cookie {
            return Err(failure(
                "文件夹浏览与递归下载需要 Cookie；请在账户中补充 Cookie",
            ));
        }
        if row.kind == "file" && !has_cookie && !has_official {
            return Err(failure("账户凭证无效，请重新登录"));
        }

        let access = Arc::new(DbCredentialAccess::new(
            self.inner.db.clone(),
            self.inner.vault.clone(),
            account.id.clone(),
        ));
        let provider_account = StorageProviderAccount {
            id: account.id.clone(),
            provider_id: account.provider_id.clone(),
            display_name: account.display_name.clone(),
            account_subject: account.account_subject.clone(),
            config: account.config.clone(),
        };
        let session = self
            .inner
            .factory
            .connect(&provider_account, access)
            .await?;
        let source = session
            .file_source()
            .ok_or_else(|| anyhow!("该账户不支持文件下载"))?;

        if row.kind == "folder" {
            self.execute_folder(row, source, cancel).await
        } else {
            self.execute_file(row, source, cancel).await
        }
    }

    async fn execute_file(
        &self,
        row: &DownloadRow,
        source: &dyn FileSourceProvider,
        cancel: &AtomicBool,
    ) -> DResult<()> {
        let file = source.get_file(&row.remote_id).await?;
        if file.kind == RemoteFileKind::Folder {
            return Err(failure("该任务需要按文件夹下载"));
        }
        let dir = self.ensure_dir(&row.relative_dir).await?;
        self.inner
            .db
            .set_download_totals(&row.id, file.size, Some(1), 0, 0)
            .await?;
        let bytes = self
            .transfer_file(source, &file, &dir, cancel, &row.id, 0)
            .await?;
        self.inner
            .db
            .set_download_totals(&row.id, file.size, Some(1), 1, bytes)
            .await?;
        Ok(())
    }

    async fn execute_folder(
        &self,
        row: &DownloadRow,
        source: &dyn FileSourceProvider,
        cancel: &AtomicBool,
    ) -> DResult<()> {
        let mut items = Vec::new();
        self.walk_folder(
            source,
            &row.remote_id,
            PathBuf::new(),
            0,
            cancel,
            &mut items,
        )
        .await?;

        let total_items = items.len() as u64;
        let total_bytes = if items.iter().all(|item| item.file.size.is_some()) {
            Some(items.iter().filter_map(|item| item.file.size).sum())
        } else {
            None
        };
        self.inner
            .db
            .set_download_totals(&row.id, total_bytes, Some(total_items), 0, 0)
            .await?;

        let mut completed_bytes = 0_u64;
        for (index, item) in items.iter().enumerate() {
            if cancel.load(Ordering::SeqCst) {
                return Err(DownloadError::Cancelled);
            }
            let relative = join_relative(&row.relative_dir, &item.subdir);
            let dir = self.ensure_dir(&relative).await?;
            let bytes = self
                .transfer_file(source, &item.file, &dir, cancel, &row.id, completed_bytes)
                .await?;
            completed_bytes = completed_bytes.saturating_add(bytes);
            self.inner
                .db
                .set_download_totals(
                    &row.id,
                    total_bytes,
                    Some(total_items),
                    (index + 1) as u64,
                    completed_bytes,
                )
                .await?;
        }

        Ok(())
    }

    fn walk_folder<'a>(
        &'a self,
        source: &'a dyn FileSourceProvider,
        folder_id: &'a str,
        subdir: PathBuf,
        depth: usize,
        cancel: &'a AtomicBool,
        out: &'a mut Vec<FolderItem>,
    ) -> Pin<Box<dyn std::future::Future<Output = DResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if depth > MAX_FOLDER_DEPTH {
                return Err(failure(format!("文件夹层级超过 {MAX_FOLDER_DEPTH} 层")));
            }
            let mut page_token: Option<String> = None;
            let mut pages = 0_u32;
            loop {
                if cancel.load(Ordering::SeqCst) {
                    return Err(DownloadError::Cancelled);
                }
                let page = source
                    .list_files(ListFilesRequest {
                        parent_id: Some(folder_id.to_owned()),
                        page_token: page_token.clone(),
                        page_size: 100,
                    })
                    .await?;
                for item in page.items {
                    match item.kind {
                        RemoteFileKind::Folder => {
                            let name = safe_local_name(&item.name, &item.id);
                            let child = subdir.join(name);
                            self.walk_folder(source, &item.id, child, depth + 1, cancel, out)
                                .await?;
                        }
                        _ => {
                            if out.len() >= MAX_FOLDER_ITEMS {
                                return Err(failure(format!(
                                    "文件夹内文件超过 {MAX_FOLDER_ITEMS} 个，请分批下载"
                                )));
                            }
                            out.push(FolderItem {
                                file: item,
                                subdir: subdir.clone(),
                            });
                        }
                    }
                }
                pages += 1;
                page_token = page.next_page_token;
                if page_token.is_none() || pages >= 1_000 {
                    break;
                }
            }
            Ok(())
        })
    }

    async fn transfer_file(
        &self,
        source: &dyn FileSourceProvider,
        file: &RemoteFileItem,
        dir: &Path,
        cancel: &AtomicBool,
        download_id: &str,
        base_bytes: u64,
    ) -> DResult<u64> {
        let safe_name = safe_local_name(&file.name, &file.id);
        let mut target = dir.join(&safe_name);

        // A completed file with the expected size means a previous run already
        // fetched it; skip instead of downloading it again.
        if let Ok(metadata) = tokio::fs::metadata(&target).await {
            if metadata.is_file() && file.size.is_some_and(|size| metadata.len() == size) {
                return Ok(metadata.len());
            }
            target = available_child_path(dir, &safe_name, &file.id);
        }

        let file_name = target
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| safe_name.clone());
        let legacy_part = dir.join(format!(".{file_name}.part"));
        let chunk_size = self.inner.chunk_size;
        let chunk_count = file.size.map(|size| {
            if size == 0 {
                1
            } else {
                size.div_ceil(chunk_size) as usize
            }
        });
        let chunk_count = chunk_count.unwrap_or(1);
        let chunks = (0..chunk_count)
            .map(|index| {
                let start = index as u64 * chunk_size;
                let expected_len = file
                    .size
                    .map(|size| size.saturating_sub(start).min(chunk_size));
                let end = expected_len
                    .filter(|length| *length > 0)
                    .map(|length| start + length - 1);
                ChunkSpec {
                    index,
                    start,
                    end,
                    expected_len,
                    path: dir.join(chunk_file_name(&file_name, index)),
                }
            })
            .collect::<Vec<_>>();

        // Chunk boundaries depend on `chunk_size`, so resuming with a different
        // chunk size while reusing `.part.N` files would silently corrupt the
        // output. Remember the settings with the partials and start over when
        // they changed.
        let meta_path = dir.join(format!(".{file_name}.part.meta"));
        let meta = format!(
            "{chunk_size}\t{}",
            file.size.map(|size| size.to_string()).unwrap_or_default()
        );
        if tokio::fs::read_to_string(&meta_path).await.ok().as_deref() != Some(meta.as_str()) {
            remove_part_chunks(dir, &file_name).await?;
            tokio::fs::write(&meta_path, &meta).await?;
        }

        self.migrate_legacy_partial(&legacy_part, &chunks, file.size)
            .await?;

        let mut initial_bytes = 0_u64;
        for chunk in &chunks {
            let length = tokio::fs::metadata(&chunk.path)
                .await
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            if chunk.expected_len.is_some_and(|expected| length > expected) {
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .open(&chunk.path)
                    .await?
                    .set_len(0)
                    .await?;
            } else {
                initial_bytes = initial_bytes.saturating_add(length);
            }
        }

        let progress = Arc::new(AtomicU64::new(initial_bytes));
        let report_state = Arc::new(tokio::sync::Mutex::new(ProgressReportState {
            last_report: Instant::now(),
            last_reported_bytes: initial_bytes,
        }));
        let db = self.inner.db.clone();
        let file_id = file.id.clone();
        let file_name_for_log = file.name.clone();
        let progress_for_tasks = progress.clone();
        let report_state_for_tasks = report_state.clone();
        let parallel = self.inner.parallel_per_file;

        let task = ChunkTask {
            source,
            file_id: &file_id,
            cancel,
            db: &db,
            download_id,
            base_bytes,
            file_name: &file_name_for_log,
            progress: &progress_for_tasks,
            report_state: &report_state_for_tasks,
        };
        stream::iter(chunks.into_iter().map(|chunk| download_chunk(task, chunk)))
            .buffer_unordered(parallel)
            .try_collect::<Vec<_>>()
            .await?;

        if cancel.load(Ordering::SeqCst) {
            return Err(DownloadError::Cancelled);
        }

        let transferred = progress.load(Ordering::SeqCst);
        if let Some(size) = file.size {
            if transferred != size {
                return Err(failure(format!(
                    "下载完成但大小不一致：本地 {transferred} 字节，远端 {size} 字节"
                )));
            }
        }

        let merged_part = dir.join(format!(".{file_name}.merge.part"));
        let mut output = tokio::fs::File::create(&merged_part).await?;
        for index in 0..chunk_count {
            if cancel.load(Ordering::SeqCst) {
                return Err(DownloadError::Cancelled);
            }
            let chunk_path = dir.join(chunk_file_name(&file_name, index));
            let mut input = tokio::fs::File::open(&chunk_path).await?;
            tokio::io::copy(&mut input, &mut output).await?;
        }
        output.flush().await?;
        output.sync_all().await?;
        drop(output);

        replace_target(&merged_part, &target).await?;
        for index in 0..chunk_count {
            let chunk_path = dir.join(chunk_file_name(&file_name, index));
            let _ = tokio::fs::remove_file(chunk_path).await;
        }
        let _ = tokio::fs::remove_file(legacy_part).await;
        let _ = tokio::fs::remove_file(&meta_path).await;
        self.inner
            .db
            .set_download_progress(
                download_id,
                base_bytes.saturating_add(transferred),
                Some(&file.name),
            )
            .await?;
        Ok(transferred)
    }

    async fn migrate_legacy_partial(
        &self,
        legacy_part: &Path,
        chunks: &[ChunkSpec],
        file_size: Option<u64>,
    ) -> DResult<()> {
        let legacy_size = match tokio::fs::metadata(legacy_part).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if legacy_size == 0 {
            return Ok(());
        }
        if let Some(size) = file_size {
            if legacy_size > size {
                tokio::fs::remove_file(legacy_part).await?;
                return Ok(());
            }
        }

        let mut input = tokio::fs::File::open(legacy_part).await?;
        let mut buffer = vec![0_u8; 128 * 1024];
        for chunk in chunks {
            if tokio::fs::try_exists(&chunk.path).await? {
                continue;
            }
            let available = legacy_size.saturating_sub(chunk.start);
            let to_copy = chunk
                .expected_len
                .map_or(available, |expected| available.min(expected));
            if to_copy == 0 {
                continue;
            }
            input.seek(SeekFrom::Start(chunk.start)).await?;
            let temporary = chunk
                .path
                .with_extension(format!("part.{}.migrate", chunk.index));
            let mut output = tokio::fs::File::create(&temporary).await?;
            let mut remaining = to_copy;
            while remaining > 0 {
                let read_size = remaining.min(buffer.len() as u64) as usize;
                let read = input.read(&mut buffer[..read_size]).await?;
                if read == 0 {
                    break;
                }
                output.write_all(&buffer[..read]).await?;
                remaining -= read as u64;
            }
            output.flush().await?;
            output.sync_all().await?;
            drop(output);
            if !tokio::fs::try_exists(&chunk.path).await? {
                tokio::fs::rename(&temporary, &chunk.path).await?;
            } else {
                let _ = tokio::fs::remove_file(&temporary).await;
            }
        }
        tokio::fs::remove_file(legacy_part).await?;
        Ok(())
    }

    async fn ensure_dir(&self, relative: &str) -> DResult<PathBuf> {
        let normalized = normalize_relative_dir(relative)
            .map_err(|message| DownloadError::Failed(anyhow!(message)))?;
        let dir = if normalized.is_empty() {
            self.inner.root.clone()
        } else {
            self.inner.root.join(&normalized)
        };
        tokio::fs::create_dir_all(&dir).await?;
        let canonical = tokio::fs::canonicalize(&dir).await?;
        if !canonical.starts_with(&self.inner.root_canonical) {
            return Err(failure("下载路径超出下载根目录"));
        }
        Ok(canonical)
    }
}

#[derive(Clone)]
struct ChunkSpec {
    index: usize,
    start: u64,
    end: Option<u64>,
    expected_len: Option<u64>,
    path: PathBuf,
}

struct ProgressReportState {
    last_report: Instant,
    last_reported_bytes: u64,
}

#[derive(Clone, Copy)]
struct ChunkTask<'a> {
    source: &'a dyn FileSourceProvider,
    file_id: &'a str,
    cancel: &'a AtomicBool,
    db: &'a Db,
    download_id: &'a str,
    base_bytes: u64,
    file_name: &'a str,
    progress: &'a Arc<AtomicU64>,
    report_state: &'a Arc<tokio::sync::Mutex<ProgressReportState>>,
}

async fn download_chunk(task: ChunkTask<'_>, chunk: ChunkSpec) -> DResult<u64> {
    let ChunkTask {
        source,
        file_id,
        cancel,
        db,
        download_id,
        base_bytes,
        file_name,
        progress,
        report_state,
    } = task;
    let mut output = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&chunk.path)
        .await?;
    let mut transferred = output.metadata().await?.len();
    if chunk.expected_len == Some(0) {
        output.flush().await?;
        return Ok(0);
    }
    if chunk
        .expected_len
        .is_some_and(|expected| transferred == expected)
    {
        output.sync_all().await?;
        return Ok(transferred);
    }

    let mut attempts = 0_usize;
    loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = output.flush().await;
            return Err(DownloadError::Cancelled);
        }

        let request = DownloadFileRequest {
            file_id: file_id.to_owned(),
            range_start: if chunk.expected_len.is_some() || transferred > 0 {
                Some(chunk.start.saturating_add(transferred))
            } else {
                None
            },
            range_end_inclusive: chunk.end,
            expected_revision: None,
        };
        let mut body = match source.download_file(request).await {
            Ok(body) => body,
            Err(error) => {
                if retryable(&error) && attempts + 1 < MAX_ATTEMPTS {
                    retry_delay(&error, attempts).await;
                    attempts += 1;
                    continue;
                }
                return Err(error.into());
            }
        };

        let mut interrupted = None;
        while let Some(result) = body.next().await {
            if cancel.load(Ordering::SeqCst) {
                let _ = output.flush().await;
                return Err(DownloadError::Cancelled);
            }
            let bytes = match result {
                Ok(bytes) => bytes,
                Err(error) => {
                    interrupted = Some(error);
                    break;
                }
            };
            if bytes.is_empty() {
                continue;
            }
            let next = transferred.saturating_add(bytes.len() as u64);
            if chunk.expected_len.is_some_and(|expected| next > expected) {
                return Err(failure(format!(
                    "分块 {} 返回的数据超过预期大小（{next} > {}）",
                    chunk.index,
                    chunk.expected_len.unwrap_or_default()
                )));
            }
            output.write_all(&bytes).await?;
            transferred = next;
            progress.fetch_add(bytes.len() as u64, Ordering::SeqCst);
            let mut state = report_state.lock().await;
            let total = progress.load(Ordering::SeqCst);
            if state.last_report.elapsed() >= PROGRESS_INTERVAL
                || total.saturating_sub(state.last_reported_bytes) >= PROGRESS_BYTES
            {
                db.set_download_progress(
                    download_id,
                    base_bytes.saturating_add(total),
                    Some(file_name),
                )
                .await?;
                state.last_report = Instant::now();
                state.last_reported_bytes = total;
            }
        }

        output.flush().await?;
        if let Some(error) = interrupted {
            if retryable(&error) && attempts + 1 < MAX_ATTEMPTS {
                warn!(
                    file = %file_name,
                    chunk = chunk.index,
                    offset = transferred,
                    error = %error,
                    "download chunk interrupted, resuming"
                );
                retry_delay(&error, attempts).await;
                attempts += 1;
                continue;
            }
            return Err(error.into());
        }

        if chunk
            .expected_len
            .is_none_or(|expected| transferred == expected)
        {
            output.sync_all().await?;
            return Ok(transferred);
        }

        let error = ProviderError::new(
            ProviderErrorCategory::Network,
            format!(
                "分块 {} 提前结束：已下载 {transferred} 字节，预期 {} 字节",
                chunk.index,
                chunk.expected_len.unwrap_or_default()
            ),
        );
        if attempts + 1 >= MAX_ATTEMPTS {
            return Err(error.into());
        }
        warn!(
            file = %file_name,
            chunk = chunk.index,
            offset = transferred,
            "download chunk ended early, resuming"
        );
        retry_delay(&error, attempts).await;
        attempts += 1;
    }
}

#[derive(Debug)]
struct FolderItem {
    file: RemoteFileItem,
    subdir: PathBuf,
}

pub struct DbCredentialAccess {
    db: Db,
    vault: Arc<Vault>,
    account_id: String,
}

impl DbCredentialAccess {
    pub fn new(db: Db, vault: Arc<Vault>, account_id: impl Into<String>) -> Self {
        Self {
            db,
            vault,
            account_id: account_id.into(),
        }
    }
}

#[async_trait]
impl ProviderCredentialAccess for DbCredentialAccess {
    async fn load(&self) -> ProviderResult<Option<Zeroizing<String>>> {
        let stored = self
            .db
            .get_account(&self.account_id)
            .await
            .map_err(local_error)?
            .map(|account| account.credential);
        match stored {
            Some(cipher) => self
                .vault
                .decrypt(&cipher)
                .map(Zeroizing::new)
                .map(Some)
                .map_err(local_error),
            None => Ok(None),
        }
    }

    async fn store(&self, credential: Zeroizing<String>) -> ProviderResult<()> {
        let cipher = self.vault.encrypt(&credential).map_err(local_error)?;
        self.db
            .update_credential(&self.account_id, &cipher)
            .await
            .map_err(local_error)
    }

    async fn delete(&self) -> ProviderResult<()> {
        Ok(())
    }
}

fn failure(message: impl Into<String>) -> DownloadError {
    DownloadError::Failed(anyhow!(message.into()))
}

fn local_error(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::new(
        ProviderErrorCategory::RemoteUnavailable,
        format!("本地凭证库错误：{error}"),
    )
}

fn retryable(error: &ProviderError) -> bool {
    matches!(
        error.category,
        ProviderErrorCategory::RateLimit
            | ProviderErrorCategory::Network
            | ProviderErrorCategory::RemoteUnavailable
    )
}

async fn retry_delay(error: &ProviderError, attempt: usize) {
    let seconds = error
        .retry_after_seconds
        .unwrap_or_else(|| 1_u64 << attempt.min(5))
        .min(30);
    tokio::time::sleep(Duration::from_secs(seconds.max(1))).await;
}

async fn replace_target(part: &Path, target: &Path) -> DResult<()> {
    if tokio::fs::symlink_metadata(target).await.is_ok() {
        tokio::fs::remove_file(target).await?;
    }
    tokio::fs::rename(part, target).await?;
    Ok(())
}

fn chunk_file_name(file_name: &str, index: usize) -> String {
    format!(".{file_name}.part.{index}")
}

/// Remove per-chunk temporary files for a single target. Used when the chunk
/// layout changed and the old partials can no longer be resumed safely.
async fn remove_part_chunks(dir: &Path, file_name: &str) -> DResult<()> {
    let prefix = format!(".{file_name}.part.");
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        if !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit()) {
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
    Ok(())
}

/// Reject absolute paths, parent traversal, and NUL bytes, then sanitize each
/// component for use below the configured download root.
pub fn normalize_relative_dir(value: &str) -> Result<String, String> {
    let value = value.trim().replace('\\', "/");
    if value.is_empty() {
        return Ok(String::new());
    }
    let path = Path::new(&value);
    if path.is_absolute() {
        return Err("下载目录必须是相对路径".into());
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_string_lossy();
                if part.is_empty() {
                    continue;
                }
                let safe = safe_local_name(&part, "item");
                if safe == "." || safe == ".." {
                    return Err("下载目录包含非法片段".into());
                }
                parts.push(safe);
            }
            Component::CurDir => {}
            _ => return Err("下载目录不能包含 .. 或根路径".into()),
        }
    }
    Ok(parts.join("/"))
}

/// Convert a remote file name into a safe local file name.
pub fn safe_local_name(value: &str, fallback: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '/' || character == '\\' || character.is_control() {
            output.push('_');
        } else {
            output.push(character);
        }
    }
    let trimmed = output.trim();
    let trimmed = trimmed.trim_end_matches(['.', ' ']);
    let mut result = if trimmed.is_empty() || trimmed.chars().all(|character| character == '.') {
        sanitize_fallback(fallback)
    } else {
        trimmed.to_owned()
    };
    if result.chars().count() > 160 {
        result = result.chars().take(160).collect();
    }
    result
}

fn sanitize_fallback(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect();
    if cleaned.is_empty() {
        "untitled".into()
    } else {
        cleaned.chars().take(64).collect()
    }
}

fn join_relative(base: &str, child: &Path) -> String {
    let child = child
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    match (base.is_empty(), child.is_empty()) {
        (true, true) => String::new(),
        (true, false) => child,
        (false, true) => base.to_owned(),
        (false, false) => format!("{base}/{child}"),
    }
}

fn available_child_path(dir: &Path, name: &str, fallback_id: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_owned());
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().into_owned());
    for index in 1..=1_000_u32 {
        let file_name = match &extension {
            Some(extension) => format!("{stem} ({index}).{extension}"),
            None => format!("{stem} ({index})"),
        };
        let candidate = dir.join(file_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    let suffix = sanitize_fallback(fallback_id);
    match extension {
        Some(extension) => dir.join(format!("{stem}-{suffix}.{extension}")),
        None => dir.join(format!("{stem}-{suffix}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use quark_core::domain::{ProviderByteStream, ProviderResult, RemoteFilePage};

    #[test]
    fn relative_dirs_reject_traversal() {
        assert_eq!(normalize_relative_dir("").unwrap(), "");
        assert_eq!(normalize_relative_dir("a/b").unwrap(), "a/b");
        assert_eq!(normalize_relative_dir("./a/./b/").unwrap(), "a/b");
        assert!(normalize_relative_dir("../etc").is_err());
        assert!(normalize_relative_dir("/etc").is_err());
        assert!(normalize_relative_dir("a/../../b").is_err());
    }

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(safe_local_name("a/b\\c", "x"), "a_b_c");
        assert_eq!(safe_local_name("  ..  ", "x"), "x");
        assert_eq!(safe_local_name("\u{7}report\u{7}.pdf", "x"), "_report_.pdf");
        assert_eq!(safe_local_name(".env", "x"), ".env");
    }

    type RangeLog = Arc<StdMutex<Vec<(Option<u64>, Option<u64>)>>>;

    struct FakeSource {
        payload: Vec<u8>,
        requests: RangeLog,
    }

    #[async_trait]
    impl FileSourceProvider for FakeSource {
        async fn list_files(&self, _request: ListFilesRequest) -> ProviderResult<RemoteFilePage> {
            Err(ProviderError::unsupported("list"))
        }

        async fn get_file(&self, file_id: &str) -> ProviderResult<RemoteFileItem> {
            Ok(fake_file(file_id, self.payload.len() as u64))
        }

        async fn download_file(
            &self,
            request: DownloadFileRequest,
        ) -> ProviderResult<ProviderByteStream> {
            self.requests
                .lock()
                .unwrap()
                .push((request.range_start, request.range_end_inclusive));
            let start = request.range_start.unwrap_or(0) as usize;
            let end = request
                .range_end_inclusive
                .map(|end| (end as usize + 1).min(self.payload.len()))
                .unwrap_or(self.payload.len());
            let start = start.min(end).min(self.payload.len());
            let bytes = self.payload[start..end].to_vec();
            Ok(Box::pin(futures_util::stream::iter(vec![Ok(bytes)])))
        }
    }

    fn fake_file(id: &str, size: u64) -> RemoteFileItem {
        RemoteFileItem {
            id: id.to_owned(),
            parent_id: None,
            name: "hello.txt".into(),
            kind: RemoteFileKind::File,
            media_type: Some("text/plain".into()),
            size: Some(size),
            modified_at: None,
            revision: None,
            downloadable: true,
        }
    }

    #[tokio::test]
    async fn resumes_from_partial_file_and_renames() {
        let dir = std::env::temp_dir().join(format!("quark-dl-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let db = Db::open(&dir.join("test.db")).await.unwrap();
        let vault = Arc::new(Vault::from_key([7_u8; 32]));
        let factory = Arc::new(quark_core::QuarkDriveFactory::new().unwrap());
        let engine = DownloadEngine::start(
            db,
            vault,
            factory,
            dir.clone(),
            dir.clone(),
            DownloadTuning {
                concurrency: 1,
                chunk_size: 100_000,
                parallel_per_file: 2,
            },
        );

        let payload = (0..200_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let split = 70_000;
        let part = dir.join(".hello.txt.part");
        tokio::fs::write(&part, &payload[..split]).await.unwrap();

        let source = FakeSource {
            payload: payload.clone(),
            requests: Arc::new(StdMutex::new(Vec::new())),
        };
        let file = fake_file("file-1", payload.len() as u64);
        let cancel = AtomicBool::new(false);
        let written = engine
            .transfer_file(&source, &file, &dir, &cancel, "download-1", 0)
            .await
            .unwrap();

        assert_eq!(written, payload.len() as u64);
        assert_eq!(
            tokio::fs::read(dir.join("hello.txt")).await.unwrap(),
            payload
        );
        assert!(!part.exists());
        assert_eq!(source.requests.lock().unwrap().len(), 2);
        assert!(source
            .requests
            .lock()
            .unwrap()
            .contains(&(Some(70_000), Some(99_999))));
        assert!(source
            .requests
            .lock()
            .unwrap()
            .contains(&(Some(100_000), Some(199_999))));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn discards_partials_when_chunk_layout_changed() {
        let dir = std::env::temp_dir().join(format!("quark-dl-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let db = Db::open(&dir.join("test.db")).await.unwrap();
        let vault = Arc::new(Vault::from_key([7_u8; 32]));
        let factory = Arc::new(quark_core::QuarkDriveFactory::new().unwrap());
        let engine = DownloadEngine::start(
            db,
            vault,
            factory,
            dir.clone(),
            dir.clone(),
            DownloadTuning {
                concurrency: 1,
                chunk_size: 100_000,
                parallel_per_file: 2,
            },
        );

        let payload = (0..200_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        // Leftovers from a previous run with a 50_000-byte chunk size. Reusing
        // them with the new layout would corrupt the merged output.
        tokio::fs::write(dir.join(".hello.txt.part.meta"), "50000\t200000")
            .await
            .unwrap();
        for index in 0..4 {
            tokio::fs::write(
                dir.join(format!(".hello.txt.part.{index}")),
                vec![0xFF_u8; 50_000],
            )
            .await
            .unwrap();
        }

        let source = FakeSource {
            payload: payload.clone(),
            requests: Arc::new(StdMutex::new(Vec::new())),
        };
        let file = fake_file("file-1", payload.len() as u64);
        let cancel = AtomicBool::new(false);
        let written = engine
            .transfer_file(&source, &file, &dir, &cancel, "download-1", 0)
            .await
            .unwrap();

        assert_eq!(written, payload.len() as u64);
        assert_eq!(
            tokio::fs::read(dir.join("hello.txt")).await.unwrap(),
            payload
        );
        assert!(!dir.join(".hello.txt.part.meta").exists());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
