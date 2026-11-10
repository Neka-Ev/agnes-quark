use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use futures_util::StreamExt;
use md5::Digest;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use reqwest::{Method, Response, StatusCode, Url};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::domain::{
    BeginFileUploadRequest, ContentHashAlgorithm, DownloadFileRequest, FileUploadSession,
    ListFilesRequest, MediaPlaybackLink, MediaPlaybackRequest, MediaPlaybackVariant,
    ProviderAuthKind, ProviderAuthorizationRequest, ProviderByteStream, ProviderDescriptor,
    ProviderError, ProviderErrorCategory, ProviderQuota, ProviderResult, ProviderStability,
    RemoteFileItem, RemoteFileKind, RemoteFilePage, SearchFilesRequest, StorageCapabilities,
    StorageProviderAccount, UploadFileChunkRequest, UploadedFileChunk,
};
use super::ports::{
    FileManagementProvider, FileSourceProvider, FileUploadProvider, MediaPlaybackProvider,
    ProviderAuthorizationChallenge, ProviderAuthorizationResult, ProviderAuthorizationStep,
    ProviderCredentialAccess, ProviderFactory, ProviderSession, QuotaProvider,
};

const PROVIDER_ID: &str = "quark_drive";
const API_BASE: &str = "https://drive.quark.cn/1/clouddrive";
const PLAYBACK_API_BASE: &str = API_BASE;
const CAPACITY_PATH: &str = "capacity/growth/info";
const OSS_BUCKET: &str = "ul-zb";
const DEFAULT_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
const DIRECT_UPLOAD_RETRIES: usize = 3;
const PUUS_REFRESH_INTERVAL: Duration = Duration::from_secs(100 * 60);
const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131 Safari/537.36";
const QUARK_DESKTOP_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch";

pub struct QuarkDriveFactory {
    client: reqwest::Client,
    sessions: StdMutex<HashMap<String, Weak<QuarkDriveSession>>>,
    qr_challenges: StdMutex<HashMap<String, QuarkQrChallenge>>,
}

impl QuarkDriveFactory {
    pub fn new() -> ProviderResult<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(120))
            .user_agent(USER_AGENT)
            .build()
            .map_err(network_error)?;
        Ok(Self {
            client,
            sessions: StdMutex::new(HashMap::new()),
            qr_challenges: StdMutex::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl ProviderFactory for QuarkDriveFactory {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: PROVIDER_ID.into(),
            display_name: "夸克网盘".into(),
            auth_kind: ProviderAuthKind::BrowserSession,
            stability: ProviderStability::Community,
            implementation_version: "quark-pan-http-v4".into(),
            capabilities: StorageCapabilities {
                browse_files: true,
                search_files: true,
                read_files: true,
                write_files: true,
                delete_files: true,
                move_files: true,
                range_download: true,
                media_playback: true,
                resumable_upload: true,
                quota: true,
                user_authorization: true,
                recommended_chunk_bytes: Some(DEFAULT_CHUNK_BYTES),
                required_upload_hashes: vec![ContentHashAlgorithm::Md5, ContentHashAlgorithm::Sha1],
                ..StorageCapabilities::default()
            },
        }
    }

    fn invalidate_account(&self, account_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(account_id);
        }
    }

    async fn authorize(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> ProviderResult<ProviderAuthorizationResult> {
        let cookie = cookie_from_authorization_input(&request.input).await?;
        authorized_from_cookie(&self.client, &cookie).await
    }

    async fn begin_authorization(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> ProviderResult<ProviderAuthorizationChallenge> {
        let method = request
            .input
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method != "qr" {
            return Err(invalid_request("夸克网盘授权挑战需要 method=qr"));
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut token_url = Url::parse("https://uop.quark.cn/cas/ajax/getTokenForQrcodeLogin")
            .map_err(|_| invalid_response("夸克二维码地址无效"))?;
        token_url
            .query_pairs_mut()
            .append_pair("client_id", "532")
            .append_pair("v", "1.2")
            .append_pair("request_id", &request_id);
        let response = self
            .client
            .get(token_url)
            .headers(public_headers()?)
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|_| invalid_response("夸克二维码接口返回了无效响应"))?;
        if !status.is_success() {
            return Err(status_error_with_message(status, &value));
        }
        let token = value
            .get("data")
            .and_then(|value| value.get("members"))
            .and_then(|value| value.get("token"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| api_value_error(&value))?;
        let mut qr_url = Url::parse("https://su.quark.cn/4_eMHBJ")
            .map_err(|_| invalid_response("夸克二维码地址无效"))?;
        qr_url
            .query_pairs_mut()
            .append_pair("token", token)
            .append_pair("client_id", "532")
            .append_pair("ssb", "weblogin")
            .append_pair("uc_param_str", "")
            .append_pair(
                "uc_biz_str",
                "S:custom|OPT:SAREA@0|OPT:IMMERSIVE@1|OPT:BACK_BTN_STYLE@0",
            );
        let challenge_id = format!("quark-qr-{}", uuid::Uuid::new_v4());
        let expires_at = Instant::now() + Duration::from_secs(300);
        self.qr_challenges
            .lock()
            .map_err(|_| {
                ProviderError::new(
                    ProviderErrorCategory::RemoteUnavailable,
                    "夸克二维码会话注册表不可用",
                )
            })?
            .insert(
                challenge_id.clone(),
                QuarkQrChallenge {
                    token: token.to_string(),
                    expires_at,
                },
            );
        Ok(ProviderAuthorizationChallenge {
            challenge_id,
            provider_id: PROVIDER_ID.into(),
            kind: "qr_code".into(),
            payload: json!({"qr_url": qr_url.as_str()}),
            expires_at: Some((now_epoch() + 300).to_string()),
        })
    }

    async fn poll_authorization(
        &self,
        challenge_id: &str,
    ) -> ProviderResult<ProviderAuthorizationStep> {
        let challenge = {
            let challenges = self.qr_challenges.lock().map_err(|_| {
                ProviderError::new(
                    ProviderErrorCategory::RemoteUnavailable,
                    "夸克二维码会话注册表不可用",
                )
            })?;
            challenges.get(challenge_id).cloned()
        }
        .ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCategory::NotFound,
                "夸克二维码会话不存在或已过期",
            )
        })?;
        if Instant::now() >= challenge.expires_at {
            self.qr_challenges
                .lock()
                .map_err(|_| invalid_response("夸克二维码会话注册表不可用"))?
                .remove(challenge_id);
            return Err(ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克二维码已过期，请重新获取",
            ));
        }
        let mut status_url =
            Url::parse("https://uop.quark.cn/cas/ajax/getServiceTicketByQrcodeToken")
                .map_err(|_| invalid_response("夸克二维码状态地址无效"))?;
        status_url
            .query_pairs_mut()
            .append_pair("token", &challenge.token);
        let response = self
            .client
            .get(status_url)
            .headers(public_headers()?)
            .send()
            .await
            .map_err(network_error)?;
        let http_status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|_| invalid_response("夸克二维码状态响应无效"))?;
        if !http_status.is_success() {
            return Err(status_error_with_message(http_status, &value));
        }
        let status_code = value.get("status").and_then(Value::as_i64);
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if status_code == Some(2000000) {
            let ticket = value
                .get("data")
                .and_then(|value| value.get("members"))
                .and_then(|value| value.get("service_ticket"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid_response("夸克二维码响应缺少 service_ticket"))?;
            let cookie = exchange_service_ticket(&self.client, ticket).await?;
            let authorized = authorized_from_cookie(&self.client, &cookie).await?;
            self.qr_challenges
                .lock()
                .map_err(|_| invalid_response("夸克二维码会话注册表不可用"))?
                .remove(challenge_id);
            return Ok(ProviderAuthorizationStep::Authorized(authorized));
        }
        if matches!(status_code, Some(50004002 | 50004003 | 50004004))
            || ["expired", "failed", "timeout", "invalid"]
                .iter()
                .any(|value| message.contains(value))
        {
            self.qr_challenges
                .lock()
                .map_err(|_| invalid_response("夸克二维码会话注册表不可用"))?
                .remove(challenge_id);
            return Err(ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克二维码登录失败或已过期",
            ));
        }
        Ok(ProviderAuthorizationStep::Pending)
    }

    async fn connect(
        &self,
        account: &StorageProviderAccount,
        credentials: Arc<dyn ProviderCredentialAccess>,
    ) -> ProviderResult<Arc<dyn ProviderSession>> {
        if account.provider_id != PROVIDER_ID {
            return Err(invalid_request("夸克网盘收到其他 Provider 的账户"));
        }
        let stored = credentials.load().await?.ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克网盘 Cookie 不存在，请重新连接",
            )
        })?;
        validate_cookie(stored.as_str())?;
        let mut sessions = self.sessions.lock().map_err(|_| {
            ProviderError::new(
                ProviderErrorCategory::RemoteUnavailable,
                "夸克网盘会话注册表不可用",
            )
        })?;
        if let Some(session) = sessions.get(&account.id).and_then(Weak::upgrade) {
            return Ok(session);
        }
        sessions.retain(|_, session| session.strong_count() > 0);
        let session = Arc::new(QuarkDriveSession {
            client: self.client.clone(),
            credentials,
            uploads: Mutex::new(HashMap::new()),
            cookie_update_lock: Mutex::new(()),
            cookie_refresh_lock: Mutex::new(Instant::now() - PUUS_REFRESH_INTERVAL),
        });
        sessions.insert(account.id.clone(), Arc::downgrade(&session));
        Ok(session)
    }
}

struct QuarkDriveSession {
    client: reqwest::Client,
    credentials: Arc<dyn ProviderCredentialAccess>,
    uploads: Mutex<HashMap<String, QuarkUploadState>>,
    cookie_update_lock: Mutex<()>,
    cookie_refresh_lock: Mutex<Instant>,
}

#[derive(Clone)]
struct QuarkQrChallenge {
    token: String,
    expires_at: Instant,
}

#[async_trait]
impl FileSourceProvider for QuarkDriveSession {
    async fn list_files(&self, request: ListFilesRequest) -> ProviderResult<RemoteFilePage> {
        let request = request.normalized();
        let page = parse_page_token(request.page_token.as_deref())?;
        let parent_id = request.parent_id.as_deref().unwrap_or("0");
        let response = self
            .api(
                Method::GET,
                "file/sort",
                vec![
                    ("pdir_fid".into(), parent_id.into()),
                    ("_page".into(), page.to_string()),
                    ("_size".into(), request.page_size.min(100).to_string()),
                    ("_fetch_total".into(), "1".into()),
                    ("_fetch_sub_dirs".into(), "1".into()),
                    ("_sort".into(), "file_name:asc".into()),
                ],
                None,
            )
            .await?;
        let data = response.get("data").unwrap_or(&Value::Null);
        let list = data
            .get("list")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_response("夸克网盘文件列表格式无效"))?;
        let items = list
            .iter()
            .map(|value| remote_file_item(value, Some(parent_id)))
            .collect::<ProviderResult<Vec<_>>>()?;
        let total = find_number(data, &["_total", "total", "total_count"]);
        let page_size = request.page_size.min(100) as u64;
        let next_page_token = if total.is_some_and(|total| (page as u64) * page_size < total)
            || (total.is_none() && items.len() >= page_size as usize)
        {
            Some((page + 1).to_string())
        } else {
            None
        };
        Ok(RemoteFilePage {
            items,
            next_page_token,
        })
    }

    async fn search_files(&self, request: SearchFilesRequest) -> ProviderResult<RemoteFilePage> {
        let request = request.normalized();
        request.validate()?;
        let page = parse_page_token(request.page_token.as_deref())?;
        let page_size = request.page_size.min(100);
        let response = self
            .api(
                Method::GET,
                "file/search",
                vec![
                    ("q".into(), request.query),
                    ("_page".into(), page.to_string()),
                    ("_size".into(), page_size.to_string()),
                    ("_fetch_total".into(), "1".into()),
                    ("_sort".into(), "file_type:desc,updated_at:desc".into()),
                    ("_is_hl".into(), "1".into()),
                ],
                None,
            )
            .await?;
        parse_search_page(&response, page, page_size)
    }

    async fn get_file(&self, file_id: &str) -> ProviderResult<RemoteFileItem> {
        validate_id(file_id, "文件 ID")?;
        let response = self
            .api(
                Method::GET,
                "file",
                vec![("fids".into(), file_id.into())],
                None,
            )
            .await?;
        let data = response.get("data").unwrap_or(&Value::Null);
        let list = data
            .get("list")
            .and_then(Value::as_array)
            .or_else(|| data.as_array())
            .ok_or_else(|| invalid_response("夸克网盘文件详情格式无效"))?;
        let value = list
            .iter()
            .find(|value| value_string(value, &["fid", "id"]).as_deref() == Some(file_id))
            .or_else(|| list.first())
            .ok_or_else(|| {
                ProviderError::new(ProviderErrorCategory::NotFound, "夸克网盘文件不存在")
            })?;
        remote_file_item(value, None)
    }

    async fn download_file(
        &self,
        request: DownloadFileRequest,
    ) -> ProviderResult<ProviderByteStream> {
        validate_range(request.range_start, request.range_end_inclusive)?;
        let file = self.get_file(&request.file_id).await?;
        if request
            .expected_revision
            .as_deref()
            .zip(file.revision.as_deref())
            .is_some_and(|(expected, current)| expected != current)
        {
            return Err(ProviderError::new(
                ProviderErrorCategory::Conflict,
                "夸克网盘文件在下载前发生了变化",
            ));
        }
        // Match Alist's working Quark request: the download URL is signed against this
        // exact cookie, desktop UA, and the minimal `pr`/`fr` query. Extra runtime or
        // mobile parameters can trigger Quark's file-size limit for large media files.
        self.refresh_cookie_if_due().await;
        let cookie = self.cookie().await?;
        let response = request_json_with_headers_options(
            &self.client,
            &cookie,
            Method::POST,
            API_BASE,
            "file/download",
            Vec::new(),
            Some(json!({"fids": [request.file_id]})),
            false,
            true,
            QUARK_DESKTOP_USER_AGENT,
        )
        .await?;
        self.merge_response_cookies(&response.headers).await;
        let response = response.value;
        let download = response
            .get("data")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .ok_or_else(|| invalid_response("夸克网盘未返回下载链接"))?;
        let url = download
            .get("download_url")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("https://"))
            .ok_or_else(|| invalid_response("夸克网盘下载链接无效"))?;
        let mut headers = playback_headers_with_user_agent(&cookie, QUARK_DESKTOP_USER_AGENT)?;
        headers.insert("accept", HeaderValue::from_static("*/*"));
        if let Some(range) = range_header(request.range_start, request.range_end_inclusive)? {
            headers.insert(RANGE, range);
        }
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(network_error)?;
        if request.range_start.is_some() {
            if response.status() != StatusCode::PARTIAL_CONTENT {
                return Err(upstream_range_error(&response, "未响应 Range 请求"));
            }
            validate_upstream_range(&response, &request)?;
        }
        if !response.status().is_success() {
            return Err(status_error(response.status(), "夸克网盘下载请求失败"));
        }
        response_stream(response)
    }
}

#[async_trait]
impl MediaPlaybackProvider for QuarkDriveSession {
    async fn get_media_playback_link(
        &self,
        request: MediaPlaybackRequest,
    ) -> ProviderResult<MediaPlaybackLink> {
        validate_id(&request.file_id, "文件 ID")?;
        let response = match self
            .api_with_playback_options(
                Method::POST,
                "file/v2/play/project",
                Vec::new(),
                Some(json!({
                    "fid": request.file_id,
                    "resolutions": "low,normal,high,super,2k,4k",
                    "supports": "fmp4_av,m3u8,dolby_vision"
                })),
            )
            .await
        {
            Ok(response) => response,
            Err(error) if is_transcoding_unavailable(&error) => {
                let cookie = self.cookie().await.ok();
                let diagnostic =
                    format_playback_error(&error, cookie.as_deref().map(|value| value.as_str()));
                return match self.get_download_playback_link(&request.file_id).await {
                    Ok(link) => Ok(link),
                    Err(download_error) => Err(ProviderError::new(
                        ProviderErrorCategory::RemoteUnavailable,
                        format!(
                            "{diagnostic}；同时获取夸克直链失败：{}",
                            download_error.message
                        ),
                    )),
                };
            }
            Err(error) => return Err(error),
        };
        parse_media_playback_link(&response)
    }
}

#[async_trait]
impl QuotaProvider for QuarkDriveSession {
    async fn quota(&self) -> ProviderResult<ProviderQuota> {
        let response = self
            .api(Method::GET, CAPACITY_PATH, Vec::new(), None)
            .await?;
        let data = response.get("data").unwrap_or(&response);
        Ok(ProviderQuota {
            used_bytes: find_number(data, &["use_capacity", "used_capacity", "used", "usage"]),
            total_bytes: find_number(data, &["total_capacity", "total", "capacity", "limit"]),
            trashed_bytes: find_number(data, &["trash_capacity", "used_in_trash"]),
            checked_at: now_epoch().to_string(),
        })
    }
}

#[async_trait]
impl FileUploadProvider for QuarkDriveSession {
    async fn begin_file_upload(
        &self,
        request: BeginFileUploadRequest,
    ) -> ProviderResult<FileUploadSession> {
        validate_upload_request(&request)?;
        let cookie = self.cookie().await?;
        let parent_id = request.parent_id.as_deref().unwrap_or("0");
        let content_md5 = request
            .content_hashes
            .get(&ContentHashAlgorithm::Md5)
            .cloned()
            .unwrap_or_default();
        let content_sha1 = request
            .content_hashes
            .get(&ContentHashAlgorithm::Sha1)
            .cloned()
            .unwrap_or_default();
        let now = now_millis();
        let response = self
            .api_with_cookie(
                &cookie,
                Method::POST,
                "file/upload/pre",
                Vec::new(),
                Some(json!({
                    "ccp_hash_update": true,
                    "parallel_upload": true,
                    "pdir_fid": parent_id,
                    "dir_name": "",
                    "size": request.size,
                    "file_name": request.name.clone(),
                    "format_type": request.media_type.clone(),
                    "l_updated_at": now,
                    "l_created_at": now
                })),
            )
            .await?;
        let data = response
            .get("data")
            .ok_or_else(|| invalid_response("夸克网盘预上传响应缺少 data"))?;
        let task_id = value_string(data, &["task_id"])
            .ok_or_else(|| invalid_response("夸克网盘预上传响应缺少 task_id"))?;
        let auth_info = value_string(data, &["auth_info"]).unwrap_or_default();
        let upload_id = value_string(data, &["upload_id"])
            .ok_or_else(|| invalid_response("夸克网盘预上传响应缺少 upload_id"))?;
        let obj_key = value_string(data, &["obj_key"])
            .ok_or_else(|| invalid_response("夸克网盘预上传响应缺少 obj_key"))?;
        let bucket = value_string(data, &["bucket"]).unwrap_or_else(|| OSS_BUCKET.into());
        validate_bucket(&bucket)?;
        validate_id(&obj_key, "上传对象 ID")?;
        let callback = data
            .get("callback")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| invalid_response("夸克网盘预上传响应缺少 callback"))?;
        self.api_with_cookie(
            &cookie,
            Method::POST,
            "file/update/hash",
            Vec::new(),
            Some(json!({
                "task_id": task_id,
                "md5": content_md5,
                "sha1": content_sha1
            })),
        )
        .await?;
        let session_id = format!("quark-upload-{}", uuid::Uuid::new_v4());
        self.uploads.lock().await.insert(
            session_id.clone(),
            QuarkUploadState {
                task_id,
                auth_info,
                upload_id,
                obj_key,
                bucket,
                callback,
                parent_id: parent_id.into(),
                name: request.name,
                size: request.size,
                media_type: request.media_type,
                chunk_size: request.chunk_size,
                next_offset: 0,
                parts: Vec::new(),
                sha1_ctx: Sha1Context::default(),
            },
        );
        Ok(FileUploadSession {
            session_id,
            next_offset: 0,
            chunk_size: request.chunk_size,
            expires_at: None,
        })
    }

    async fn upload_file_chunk(
        &self,
        request: UploadFileChunkRequest,
    ) -> ProviderResult<UploadedFileChunk> {
        let mut uploads = self.uploads.lock().await;
        let state = uploads.get_mut(&request.session_id).ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCategory::NotFound,
                "夸克网盘上传会话不存在或已过期",
            )
        })?;
        if request.offset != state.next_offset || request.total_size != state.size {
            return Err(invalid_request("夸克网盘上传偏移与会话状态不一致"));
        }
        if request.bytes.len() as u64 > state.chunk_size
            || request.offset.saturating_add(request.bytes.len() as u64) > state.size
            || (request.bytes.is_empty() && state.size != 0)
        {
            return Err(invalid_request("夸克网盘上传分片大小无效"));
        }
        let part_number = (state.next_offset / state.chunk_size) as u32 + 1;
        let hash_ctx = if part_number > 1 {
            Some(state.sha1_ctx.context_header())
        } else {
            None
        };
        let etag = self
            .upload_part(state, part_number, &request.bytes, hash_ctx)
            .await?;
        state.parts.push((part_number, etag));
        state.sha1_ctx.update(&request.bytes);
        state.next_offset = state.next_offset.saturating_add(request.bytes.len() as u64);
        if state.next_offset < state.size {
            return Ok(UploadedFileChunk {
                next_offset: state.next_offset,
                complete: false,
                file: None,
            });
        }
        let file_id = self.complete_upload(state).await?;
        let file = if let Some(file_id) = file_id {
            self.get_file(&file_id).await.ok()
        } else {
            self.find_uploaded_file(state).await.ok()
        };
        let file = file.ok_or_else(|| invalid_response("夸克网盘上传完成但未返回文件信息"))?;
        let size = state.size;
        uploads.remove(&request.session_id);
        Ok(UploadedFileChunk {
            next_offset: size,
            complete: true,
            file: Some(file),
        })
    }

    async fn abort_file_upload(&self, session_id: &str) -> ProviderResult<()> {
        self.uploads.lock().await.remove(session_id);
        Ok(())
    }
}

#[async_trait]
impl FileManagementProvider for QuarkDriveSession {
    async fn trash_files(&self, file_ids: Vec<String>) -> ProviderResult<()> {
        if file_ids.is_empty() || file_ids.len() > 100 {
            return Err(invalid_request("夸克网盘一次最多可移入回收站 100 个项目"));
        }
        for file_id in &file_ids {
            validate_id(file_id, "文件 ID")?;
        }
        self.api(
            Method::POST,
            "file/delete",
            Vec::new(),
            Some(json!({
                "action_type": 2,
                "filelist": file_ids,
                "exclude_fids": []
            })),
        )
        .await?;
        Ok(())
    }

    async fn move_files(
        &self,
        file_ids: Vec<String>,
        target_folder_id: Option<String>,
    ) -> ProviderResult<()> {
        let body = move_files_request(file_ids, target_folder_id)?;
        self.api(Method::POST, "file/move", Vec::new(), Some(body))
            .await?;
        Ok(())
    }
}

impl ProviderSession for QuarkDriveSession {
    fn file_source(&self) -> Option<&dyn FileSourceProvider> {
        Some(self)
    }

    fn media_playback(&self) -> Option<&dyn MediaPlaybackProvider> {
        Some(self)
    }

    fn quota_source(&self) -> Option<&dyn QuotaProvider> {
        Some(self)
    }

    fn file_upload(&self) -> Option<&dyn FileUploadProvider> {
        Some(self)
    }

    fn file_management(&self) -> Option<&dyn FileManagementProvider> {
        Some(self)
    }
}

struct QuarkUploadState {
    task_id: String,
    auth_info: String,
    upload_id: String,
    obj_key: String,
    bucket: String,
    callback: Value,
    parent_id: String,
    name: String,
    size: u64,
    media_type: String,
    chunk_size: u64,
    next_offset: u64,
    parts: Vec<(u32, String)>,
    sha1_ctx: Sha1Context,
}

impl QuarkDriveSession {
    async fn get_download_playback_link(&self, file_id: &str) -> ProviderResult<MediaPlaybackLink> {
        self.refresh_cookie_if_due().await;
        let cookie = self.cookie().await?;
        let response = request_json_with_headers_options(
            &self.client,
            &cookie,
            Method::POST,
            API_BASE,
            "file/download",
            Vec::new(),
            Some(json!({"fids": [file_id]})),
            false,
            true,
            QUARK_DESKTOP_USER_AGENT,
        )
        .await?;
        self.merge_response_cookies(&response.headers).await;
        parse_download_playback_link(&response.value)
    }

    async fn cookie(&self) -> ProviderResult<Zeroizing<String>> {
        let cookie = self.credentials.load().await?.ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克网盘 Cookie 不存在",
            )
        })?;
        validate_cookie(cookie.as_str())?;
        Ok(cookie)
    }

    async fn api(
        &self,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> ProviderResult<Value> {
        self.refresh_cookie_if_due().await;
        let cookie = self.cookie().await?;
        self.api_with_cookie(&cookie, method, path, query, body)
            .await
    }

    async fn api_with_cookie(
        &self,
        cookie: &str,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> ProviderResult<Value> {
        let response =
            request_json_with_headers(&self.client, cookie, method, path, query, body).await?;
        self.merge_response_cookies(&response.headers).await;
        Ok(response.value)
    }

    async fn api_with_playback_options(
        &self,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> ProviderResult<Value> {
        self.refresh_cookie_if_due().await;
        let cookie = self.cookie().await?;
        let response = request_json_with_headers_options(
            &self.client,
            &cookie,
            method,
            PLAYBACK_API_BASE,
            path,
            query,
            body,
            false,
            true,
            QUARK_DESKTOP_USER_AGENT,
        )
        .await?;
        self.merge_response_cookies(&response.headers).await;
        Ok(response.value)
    }

    async fn merge_response_cookies(&self, headers: &HeaderMap) {
        let Some(updated) = cookie_string_from_headers(headers) else {
            return;
        };
        let _guard = self.cookie_update_lock.lock().await;
        let Ok(Some(current)) = self.credentials.load().await else {
            return;
        };
        let Ok(merged) = merge_cookie_strings(current.as_str(), &updated) else {
            return;
        };
        let _ = self.credentials.store(Zeroizing::new(merged)).await;
    }

    async fn refresh_cookie_if_due(&self) {
        let should_refresh = {
            let mut last_refresh = self.cookie_refresh_lock.lock().await;
            if last_refresh.elapsed() < PUUS_REFRESH_INTERVAL {
                false
            } else {
                *last_refresh = Instant::now();
                true
            }
        };
        if !should_refresh {
            return;
        }
        let Ok(cookie) = self.cookie().await else {
            return;
        };
        let stripped = cookie_without(cookie.as_str(), "__puus");
        if let Ok(response) = request_json_with_headers_options(
            &self.client,
            &stripped,
            Method::GET,
            PLAYBACK_API_BASE,
            "config",
            Vec::new(),
            None,
            false,
            true,
            QUARK_DESKTOP_USER_AGENT,
        )
        .await
        {
            self.merge_response_cookies(&response.headers).await;
        }
    }

    async fn upload_part(
        &self,
        state: &QuarkUploadState,
        part_number: u32,
        bytes: &[u8],
        hash_ctx: Option<String>,
    ) -> ProviderResult<String> {
        let date = oss_date();
        let mut auth_meta = format!(
            "PUT\n\n{}\n{}\nx-oss-date:{}\nx-oss-user-agent:aliyun-sdk-js/1.0.0 Chrome Mobile 139.0.0.0 on Google Nexus 5 (Android 6.0)\n/{}/{}?partNumber={}&uploadId={}",
            state.media_type,
            date,
            date,
            state.bucket,
            state.obj_key,
            part_number,
            state.upload_id
        );
        if let Some(hash_ctx) = hash_ctx.as_deref() {
            auth_meta = format!(
                "PUT\n\n{}\n{}\nx-oss-date:{}\nx-oss-hash-ctx:{}\nx-oss-user-agent:aliyun-sdk-js/1.0.0 Chrome Mobile 139.0.0.0 on Google Nexus 5 (Android 6.0)\n/{}/{}?partNumber={}&uploadId={}",
                state.media_type,
                date,
                date,
                hash_ctx,
                state.bucket,
                state.obj_key,
                part_number,
                state.upload_id
            );
        }
        let auth = self
            .api(
                Method::POST,
                "file/upload/auth",
                Vec::new(),
                Some(json!({"task_id": state.task_id, "auth_info": state.auth_info, "auth_meta": auth_meta})),
            )
            .await?;
        let auth_key = auth
            .get("data")
            .and_then(|value| value.get("auth_key"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let url = format!(
            "https://{}.pds.quark.cn/{}?partNumber={}&uploadId={}",
            state.bucket, state.obj_key, part_number, state.upload_id
        );
        let mut headers = base_headers(self.cookie().await?.as_str())?;
        headers.insert(CONTENT_LENGTH, header_value(&bytes.len().to_string())?);
        headers.insert(
            HeaderName::from_static("content-type"),
            header_value(&state.media_type)?,
        );
        headers.insert(HeaderName::from_static("x-oss-date"), header_value(&date)?);
        headers.insert(
            HeaderName::from_static("x-oss-user-agent"),
            HeaderValue::from_static(
                "aliyun-sdk-js/1.0.0 Chrome Mobile 139.0.0.0 on Google Nexus 5 (Android 6.0)",
            ),
        );
        if !auth_key.is_empty() {
            headers.insert(
                HeaderName::from_static("authorization"),
                header_value(auth_key)?,
            );
        }
        if let Some(hash_ctx) = hash_ctx {
            headers.insert(
                HeaderName::from_static("x-oss-hash-ctx"),
                header_value(&hash_ctx)?,
            );
        }
        let upload = self.client.put(url).headers(headers);
        let response = send_direct_upload_with_retry(upload, bytes).await?;
        if !response.status().is_success() {
            return Err(status_error(response.status(), "夸克网盘分片上传失败"));
        }
        response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim_matches('"').to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_response("夸克网盘分片上传未返回 ETag"))
    }

    async fn complete_upload(&self, state: &QuarkUploadState) -> ProviderResult<Option<String>> {
        let mut xml =
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUpload>\n");
        for (part, etag) in &state.parts {
            xml.push_str(&format!(
                "<Part><PartNumber>{part}</PartNumber><ETag>\"{etag}\"</ETag></Part>\n"
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let xml_md5 = BASE64.encode(md5::Md5::digest(xml.as_bytes()));
        let callback = BASE64.encode(
            serde_json::to_vec(&state.callback)
                .map_err(|_| invalid_response("夸克网盘 callback 格式无效"))?,
        );
        let date = oss_date();
        let auth_meta = format!(
            "POST\n{}\napplication/xml\n{}\nx-oss-callback:{}\nx-oss-date:{}\nx-oss-user-agent:aliyun-sdk-js/1.0.0 Chrome 139.0.0.0 on OS X 10.15.7 64-bit\n/{}/{}?uploadId={}",
            xml_md5, date, callback, date, state.bucket, state.obj_key, state.upload_id
        );
        let auth = self
            .api(
                Method::POST,
                "file/upload/auth",
                Vec::new(),
                Some(json!({"task_id": state.task_id, "auth_info": state.auth_info, "auth_meta": auth_meta})),
            )
            .await?;
        let auth_key = auth
            .get("data")
            .and_then(|value| value.get("auth_key"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let url = format!(
            "https://{}.pds.quark.cn/{}?uploadId={}",
            state.bucket, state.obj_key, state.upload_id
        );
        let mut headers = base_headers(self.cookie().await?.as_str())?;
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            HeaderName::from_static("content-md5"),
            header_value(&xml_md5)?,
        );
        headers.insert(HeaderName::from_static("x-oss-date"), header_value(&date)?);
        headers.insert(
            HeaderName::from_static("x-oss-callback"),
            header_value(&callback)?,
        );
        headers.insert(
            HeaderName::from_static("x-oss-user-agent"),
            HeaderValue::from_static("aliyun-sdk-js/1.0.0 Chrome 139.0.0.0 on OS X 10.15.7 64-bit"),
        );
        if !auth_key.is_empty() {
            headers.insert(
                HeaderName::from_static("authorization"),
                header_value(auth_key)?,
            );
        }
        let response = self
            .client
            .post(url)
            .headers(headers)
            .body(xml)
            .send()
            .await
            .map_err(network_error)?;
        if response.status() != StatusCode::OK
            && response.status() != StatusCode::NON_AUTHORITATIVE_INFORMATION
        {
            return Err(status_error(response.status(), "夸克网盘合并分片失败"));
        }
        let finish = self
            .api(
                Method::POST,
                "file/upload/finish",
                Vec::new(),
                Some(json!({"task_id": state.task_id, "obj_key": state.obj_key})),
            )
            .await?;
        Ok(finish
            .get("data")
            .and_then(|value| value.get("fid").or_else(|| value.get("file_id")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned))
    }

    async fn find_uploaded_file(&self, state: &QuarkUploadState) -> ProviderResult<RemoteFileItem> {
        let mut page_token = None;
        for _ in 0..100 {
            let page = self
                .list_files(ListFilesRequest {
                    parent_id: Some(state.parent_id.clone()),
                    page_token,
                    page_size: 100,
                })
                .await?;
            let next_page_token = page.next_page_token.clone();
            if let Some(file) = page
                .items
                .into_iter()
                .find(|item| item.name == state.name && item.size == Some(state.size))
            {
                return Ok(file);
            }
            page_token = next_page_token;
            if page_token.is_none() {
                break;
            }
        }
        Err(ProviderError::new(
            ProviderErrorCategory::NotFound,
            "上传完成后未找到夸克网盘文件",
        ))
    }
}

#[derive(Clone)]
pub(crate) struct Sha1Context {
    state: [u32; 5],
    processed_bits: u64,
    buffer: Vec<u8>,
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            processed_bits: 0,
            buffer: Vec::new(),
        }
    }
}

impl Sha1Context {
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        let complete = self.buffer.len() / 64 * 64;
        for block in self.buffer[..complete].chunks_exact(64) {
            sha1_block(&mut self.state, block);
        }
        self.buffer.drain(..complete);
        self.processed_bits = self.processed_bits.saturating_add((complete as u64) * 8);
    }

    fn context_header(&self) -> String {
        let value = json!({
            "hash_type": "sha1",
            "h0": self.state[0].to_string(),
            "h1": self.state[1].to_string(),
            "h2": self.state[2].to_string(),
            "h3": self.state[3].to_string(),
            "h4": self.state[4].to_string(),
            "Nl": (self.processed_bits & 0xffff_ffff).to_string(),
            "Nh": (self.processed_bits >> 32).to_string(),
            "data": BASE64.encode(&self.buffer),
            "num": self.buffer.len().to_string()
        });
        BASE64.encode(serde_json::to_vec(&value).unwrap_or_default())
    }

    pub(crate) fn parallel_context(&self, part_offset: u64) -> Value {
        json!({
            "part_offset": part_offset,
            "h": self.state,
        })
    }
}

fn sha1_block(state: &mut [u32; 5], block: &[u8]) {
    let mut words = [0_u32; 80];
    for (index, word) in words[..16].iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for (index, word) in words.iter().enumerate() {
        let (function, constant) = match index {
            0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        (e, d, c, b, a) = (d, c, b.rotate_left(30), a, temp);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

struct JsonResponse {
    value: Value,
    headers: HeaderMap,
}

async fn request_json(
    client: &reqwest::Client,
    cookie: &str,
    method: Method,
    path: &str,
    query: Vec<(String, String)>,
    body: Option<Value>,
) -> ProviderResult<Value> {
    Ok(
        request_json_with_headers(client, cookie, method, path, query, body)
            .await?
            .value,
    )
}

async fn request_json_with_headers(
    client: &reqwest::Client,
    cookie: &str,
    method: Method,
    path: &str,
    query: Vec<(String, String)>,
    body: Option<Value>,
) -> ProviderResult<JsonResponse> {
    request_json_with_headers_options(
        client, cookie, method, API_BASE, path, query, body, true, false, USER_AGENT,
    )
    .await
}

async fn request_json_with_headers_options(
    client: &reqwest::Client,
    cookie: &str,
    method: Method,
    base_url: &str,
    path: &str,
    query: Vec<(String, String)>,
    body: Option<Value>,
    include_runtime_params: bool,
    playback_headers: bool,
    user_agent: &str,
) -> ProviderResult<JsonResponse> {
    validate_cookie(cookie)?;
    let url = format!("{base_url}/{path}");
    let mut params = vec![
        ("pr".to_string(), "ucpro".to_string()),
        ("fr".to_string(), "pc".to_string()),
    ];
    if include_runtime_params {
        params.extend([
            ("uc_param_str".to_string(), String::new()),
            ("__t".to_string(), now_millis().to_string()),
            ("__dt".to_string(), "1000".to_string()),
        ]);
    }
    params.extend(query);
    let headers = if playback_headers {
        playback_headers_with_user_agent(cookie, user_agent)?
    } else {
        base_headers_with_user_agent(cookie, user_agent)?
    };
    let mut request = client.request(method, url).headers(headers).query(&params);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(network_error)?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let text = response.text().await.map_err(network_error)?;
    let value: Value = serde_json::from_str(&text).map_err(|_| {
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克网盘 Cookie 已失效",
            )
        } else {
            invalid_response("夸克网盘返回了非 JSON 响应")
        }
    })?;
    if !status.is_success() {
        return Err(status_error_with_message(status, &value));
    }
    let ok = value.get("status").is_none()
        || value.get("status").is_some_and(|status| {
            status.as_bool() == Some(true)
                || status.as_i64() == Some(200)
                || status
                    .as_str()
                    .is_some_and(|value| value == "200" || value == "success")
        });
    let code_ok = value
        .get("code")
        .map(|code| code.as_i64().is_none_or(|value| value == 0 || value == 200))
        .unwrap_or(true);
    if !ok || !code_ok {
        return Err(api_value_error(&value));
    }
    Ok(JsonResponse {
        value,
        headers: response_headers,
    })
}

fn base_headers(cookie: &str) -> ProviderResult<HeaderMap> {
    base_headers_with_user_agent(cookie, USER_AGENT)
}

fn base_headers_with_user_agent(cookie: &str, user_agent: &str) -> ProviderResult<HeaderMap> {
    let mut headers = public_headers_with_user_agent(user_agent)?;
    headers.insert("cookie", header_value(cookie)?);
    Ok(headers)
}

fn playback_headers_with_user_agent(cookie: &str, user_agent: &str) -> ProviderResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/plain, */*"),
    );
    headers.insert("referer", HeaderValue::from_static("https://pan.quark.cn"));
    headers.insert("user-agent", header_value(user_agent)?);
    headers.insert("cookie", header_value(cookie)?);
    Ok(headers)
}

fn public_headers() -> ProviderResult<HeaderMap> {
    public_headers_with_user_agent(USER_AGENT)
}

fn public_headers_with_user_agent(user_agent: &str) -> ProviderResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/plain, */*"),
    );
    headers.insert(
        "accept-language",
        HeaderValue::from_static("zh-CN,zh;q=0.9"),
    );
    headers.insert("origin", HeaderValue::from_static("https://pan.quark.cn"));
    headers.insert("referer", HeaderValue::from_static("https://pan.quark.cn/"));
    headers.insert("user-agent", header_value(user_agent)?);
    Ok(headers)
}

async fn exchange_service_ticket(client: &reqwest::Client, ticket: &str) -> ProviderResult<String> {
    let response = client
        .get("https://pan.quark.cn/account/info")
        .headers(public_headers()?)
        .query(&[("st", ticket), ("lw", "scan")])
        .send()
        .await
        .map_err(network_error)?;
    let status = response.status();
    let cookie = cookie_string_from_headers(response.headers());
    if !status.is_success() {
        return Err(status_error(status, "夸克二维码换取登录 Cookie 失败"));
    }
    let cookie =
        cookie.ok_or_else(|| invalid_response("夸克二维码登录成功，但响应没有返回 Cookie"))?;
    validate_cookie(&cookie)?;
    Ok(cookie)
}

async fn authorized_from_cookie(
    client: &reqwest::Client,
    cookie: &str,
) -> ProviderResult<ProviderAuthorizationResult> {
    validate_cookie(cookie)?;
    request_json(client, cookie, Method::GET, CAPACITY_PATH, Vec::new(), None).await?;
    let uid = cookie_value(cookie, "__uid").unwrap_or_else(|| "account".into());
    Ok(ProviderAuthorizationResult {
        account: StorageProviderAccount {
            id: format!("quark-{}", short_hash(uid.as_bytes())),
            provider_id: PROVIDER_ID.into(),
            display_name: format!("夸克网盘 - {}", truncate(&uid, 64)),
            account_subject: Some(truncate(&uid, 512)),
            config: json!({
                "api_base": API_BASE,
                "community_adapter": true,
                "credential_kind": "cookie"
            }),
        },
        credential: Zeroizing::new(cookie.to_string()),
    })
}

async fn cookie_from_authorization_input(input: &Value) -> ProviderResult<String> {
    if let Some(path) = input
        .get("cookie_json_path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let path = std::path::PathBuf::from(path);
        if !path.is_absolute() {
            return Err(invalid_request("Cookie JSON 文件路径必须是绝对路径"));
        }
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|_| invalid_request("Cookie JSON 文件不存在或无法读取"))?;
        if !metadata.is_file() || metadata.len() > 2 * 1024 * 1024 {
            return Err(invalid_request(
                "Cookie JSON 文件必须是 2 MiB 以内的普通文件",
            ));
        }
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(|_| invalid_request("Cookie JSON 文件不是有效的 UTF-8 文本"))?;
        return cookie_from_json_text(&text);
    }
    if let Some(value) = input.get("cookie_json") {
        if let Some(text) = value.as_str() {
            return cookie_from_json_text(text);
        }
        return cookie_from_json_value(value);
    }
    let cookie = input
        .get("cookie")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_request("请提供夸克网盘 Cookie 或 Cookie JSON 文件"))?;
    if cookie.starts_with('{') || cookie.starts_with('[') {
        return cookie_from_json_text(cookie);
    }
    Ok(cookie.to_string())
}

fn cookie_from_json_text(text: &str) -> ProviderResult<String> {
    let value: Value =
        serde_json::from_str(text).map_err(|_| invalid_request("Cookie JSON 格式无效"))?;
    cookie_from_json_value(&value)
}

fn cookie_from_json_value(value: &Value) -> ProviderResult<String> {
    let mut pairs = Vec::new();
    collect_cookie_pairs(value, &mut pairs);
    if pairs.is_empty() {
        return Err(invalid_request(
            "Cookie JSON 中没有找到 name/value 或 Cookie 字段",
        ));
    }
    Ok(pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; "))
}

fn collect_cookie_pairs(value: &Value, pairs: &mut Vec<(String, String)>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_cookie_pairs(item, pairs);
            }
        }
        Value::Object(object) => {
            if let Some(cookie_string) = object.get("cookie_string").and_then(Value::as_str) {
                collect_raw_cookie_pairs(cookie_string, pairs);
            }
            if let (Some(name), Some(value)) = (
                object.get("name").and_then(Value::as_str),
                object.get("value").and_then(Value::as_str),
            ) {
                push_cookie_pair(name, value, pairs);
                return;
            }
            if let Some(cookies) = object.get("cookies") {
                collect_cookie_pairs(cookies, pairs);
            }
            for (name, value) in object {
                if matches!(
                    name.as_str(),
                    "cookie_string" | "cookies" | "timestamp" | "source"
                ) {
                    continue;
                }
                if let Some(value) = value.as_str() {
                    push_cookie_pair(name, value, pairs);
                }
            }
        }
        _ => {}
    }
}

fn collect_raw_cookie_pairs(raw: &str, pairs: &mut Vec<(String, String)>) {
    for pair in raw.split(';') {
        if let Some((name, value)) = pair.trim().split_once('=') {
            push_cookie_pair(name, value, pairs);
        }
    }
}

fn push_cookie_pair(name: &str, value: &str, pairs: &mut Vec<(String, String)>) {
    let name = name.trim();
    let value = value.trim();
    if name.is_empty()
        || value.is_empty()
        || name
            .chars()
            .any(|char| char.is_control() || matches!(char, ';' | '='))
    {
        return;
    }
    if let Some(existing) = pairs.iter_mut().find(|(key, _)| key == name) {
        existing.1 = value.to_string();
    } else {
        pairs.push((name.to_string(), value.to_string()));
    }
}

fn cookie_string_from_headers(headers: &HeaderMap) -> Option<String> {
    let mut pairs = Vec::new();
    for value in headers.get_all("set-cookie") {
        if let Ok(value) = value.to_str() {
            if let Some((name, value)) = value
                .split_once(';')
                .and_then(|value| value.0.split_once('='))
            {
                push_cookie_pair(name, value, &mut pairs);
            } else if let Some((name, value)) = value.split_once('=') {
                push_cookie_pair(name, value, &mut pairs);
            }
        }
    }
    (!pairs.is_empty()).then(|| {
        pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

fn merge_cookie_strings(existing: &str, updated: &str) -> ProviderResult<String> {
    let mut pairs = Vec::new();
    collect_raw_cookie_pairs(existing, &mut pairs);
    collect_raw_cookie_pairs(updated, &mut pairs);
    if pairs.is_empty() {
        return Err(invalid_response("夸克网盘响应没有有效 Cookie"));
    }
    Ok(pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; "))
}

fn cookie_without(cookie: &str, excluded_name: &str) -> String {
    cookie
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, value)| name.trim() != excluded_name && !value.trim().is_empty())
        .map(|(name, value)| format!("{}={}", name.trim(), value.trim()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn remote_file_item(value: &Value, parent_id: Option<&str>) -> ProviderResult<RemoteFileItem> {
    let id = value_string(value, &["fid", "id"])
        .ok_or_else(|| invalid_response("夸克网盘项目缺少 fid"))?;
    let name = value_string(value, &["file_name", "name"]).unwrap_or_else(|| id.clone());
    let size = find_number(value, &["size", "file_size"]);
    let media_type = value_string(value, &["mime_type", "format_type"]);
    let revision = value_string(value, &["sha1", "md5"]);
    // Quark's list and detail endpoints disagree on numeric `file_type` semantics. Explicit
    // directory markers are authoritative; file metadata disambiguates detail responses.
    let explicit_folder = ["dir", "is_dir", "is_folder", "folder"]
        .iter()
        .find_map(|key| value.get(*key).and_then(value_as_boolish));
    let has_file_metadata = size.is_some_and(|value| value > 0)
        || media_type.as_deref().is_some_and(|value| !value.is_empty())
        || revision.is_some();
    let folder = explicit_folder.unwrap_or_else(|| {
        !has_file_metadata
            && value
                .get("file_type")
                .and_then(file_type_is_folder)
                .unwrap_or(false)
    });
    let modified = value_string(value, &["updated_at", "modified_at", "update_time"]);
    // Quark does not expose a stable revision on every endpoint. Only hashes are safe for
    // optimistic validation; timestamps are kept as display metadata, never as revisions.
    let parent_id = parent_id
        .map(ToOwned::to_owned)
        .or_else(|| value_string(value, &["pdir_fid", "parent_id"]));
    Ok(RemoteFileItem {
        id,
        parent_id,
        name,
        kind: if folder {
            RemoteFileKind::Folder
        } else {
            RemoteFileKind::File
        },
        media_type,
        size,
        modified_at: modified,
        revision,
        downloadable: !folder,
    })
}

fn parse_search_page(
    response: &Value,
    page: usize,
    page_size: usize,
) -> ProviderResult<RemoteFilePage> {
    let data = response.get("data").unwrap_or(&Value::Null);
    let list = data
        .get("list")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response("夸克网盘搜索结果格式无效"))?;
    let items = list
        .iter()
        .map(|value| remote_file_item(value, None))
        .collect::<ProviderResult<Vec<_>>>()?;
    let total = response
        .get("metadata")
        .and_then(|metadata| find_number(metadata, &["_total", "total", "total_count"]))
        .or_else(|| find_number(data, &["_total", "total", "total_count"]));
    let next_page_token = if total.is_some_and(|total| (page as u64) * (page_size as u64) < total)
        || (total.is_none() && items.len() >= page_size)
    {
        Some((page + 1).to_string())
    } else {
        None
    };
    Ok(RemoteFilePage {
        items,
        next_page_token,
    })
}

fn parse_download_playback_link(response: &Value) -> ProviderResult<MediaPlaybackLink> {
    let download = response
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| invalid_response("夸克网盘未返回下载播放链接"))?;
    let url = download
        .get("download_url")
        .and_then(Value::as_str)
        .filter(|value| is_https_url(value))
        .ok_or_else(|| invalid_response("夸克网盘下载播放链接无效"))?;
    Ok(MediaPlaybackLink {
        url: url.into(),
        media_type: Some("video/mp4".into()),
        protocol: "progressive".into(),
        resolution: None,
        variants: Vec::new(),
    })
}

fn parse_media_playback_link(response: &Value) -> ProviderResult<MediaPlaybackLink> {
    let data = response.get("data").unwrap_or(&Value::Null);
    let default_resolution = value_string(data, &["default_resolution"]);
    let video_list = data
        .get("video_list")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response("夸克转码播放响应格式无效"))?;
    let mut candidates = video_list
        .iter()
        .filter_map(|entry| {
            let video_info = entry.get("video_info")?;
            let url = value_string(video_info, &["url"])?;
            if !is_https_url(&url) {
                return None;
            }
            let resolution = value_string(entry, &["resolution"])
                .or_else(|| value_string(video_info, &["resolution", "resoultion"]));
            let format = value_string(video_info, &["format", "hls_type"]);
            let inferred_format = format.clone().or_else(|| {
                Url::parse(&url)
                    .ok()
                    .and_then(|url| url.path_segments()?.last().map(str::to_ascii_lowercase))
                    .filter(|path| path.ends_with(".m3u8") || path.ends_with(".mp4"))
            });
            let is_default = default_resolution
                .as_deref()
                .zip(resolution.as_deref())
                .is_some_and(|(default, current)| default == current);
            Some((
                is_default,
                playback_resolution_rank(resolution.as_deref()),
                MediaPlaybackVariant {
                    url,
                    media_type: inferred_format.as_deref().and_then(playback_media_type),
                    protocol: playback_protocol(inferred_format.as_deref()),
                    resolution,
                },
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(is_default, rank, _)| (!*is_default, *rank));
    let variants = candidates
        .into_iter()
        .map(|(_, _, variant)| variant)
        .collect::<Vec<_>>();
    let selected = variants.first().cloned().ok_or_else(|| {
        ProviderError::new(
            ProviderErrorCategory::RemoteUnavailable,
            "夸克网盘没有可用的转码播放地址",
        )
    })?;
    Ok(MediaPlaybackLink {
        url: selected.url.clone(),
        media_type: selected.media_type.clone(),
        protocol: selected.protocol.clone(),
        resolution: selected.resolution.clone(),
        variants,
    })
}

fn is_transcoding_unavailable(error: &ProviderError) -> bool {
    error.message.to_ascii_lowercase().contains("plf_invalid")
}

fn format_playback_error(error: &ProviderError, cookie: Option<&str>) -> String {
    let has_pus = cookie
        .map(|value| cookie_value(value, "__pus").is_some())
        .unwrap_or(false);
    let has_puus = cookie
        .map(|value| cookie_value(value, "__puus").is_some())
        .unwrap_or(false);
    format!(
        "夸克转码接口返回播放失败：{}；请求=file/v2/play/project，域名=drive.quark.cn，resolutions=low,normal,high,super,2k,4k，supports=fmp4_av,m3u8,dolby_vision；会话字段 __pus={}，__puus={}",
        error.message,
        if has_pus { "存在" } else { "缺失" },
        if has_puus { "存在" } else { "缺失" },
    )
}

fn is_https_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
    })
}

fn playback_resolution_rank(value: Option<&str>) -> u8 {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("low") => 0,
        Some("normal") => 1,
        Some("high") => 2,
        Some("super") => 3,
        Some("2k") => 4,
        Some("4k") => 5,
        _ => 6,
    }
}

fn playback_media_type(value: &str) -> Option<String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("m3u8") || normalized == "hls" {
        Some("application/vnd.apple.mpegurl".into())
    } else if normalized.contains("mp4") || normalized.contains("fmp4") {
        Some("video/mp4".into())
    } else {
        None
    }
}

fn playback_protocol(value: Option<&str>) -> String {
    if value
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| value.contains("m3u8") || value == "hls")
    {
        "hls".into()
    } else {
        "progressive".into()
    }
}

fn parse_page_token(page_token: Option<&str>) -> ProviderResult<usize> {
    match page_token {
        None => Ok(1),
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|page| *page > 0)
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorCategory::InvalidRequest,
                    "夸克网盘分页令牌无效",
                )
            }),
    }
}

fn value_as_boolish(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_i64().map(|value| value != 0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "folder" | "directory" | "dir" => Some(true),
            "0" | "false" | "no" | "file" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn file_type_is_folder(value: &Value) -> Option<bool> {
    match value {
        Value::Number(value) => value.as_i64().map(|value| value == 0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "0" | "folder" | "directory" | "dir" => Some(true),
            "1" | "file" => Some(false),
            _ => None,
        },
        _ => value_as_boolish(value),
    }
}

fn validate_upload_request(request: &BeginFileUploadRequest) -> ProviderResult<()> {
    if request.name.trim().is_empty()
        || request.name.chars().count() > 255
        || request.name.chars().any(char::is_control)
        || request.media_type.is_empty()
        || request.media_type.len() > 255
        || request.chunk_size == 0
        || request
            .content_hashes
            .get(&ContentHashAlgorithm::Md5)
            .is_none_or(|value| value.len() != 32)
        || request
            .content_hashes
            .get(&ContentHashAlgorithm::Sha1)
            .is_none_or(|value| value.len() != 40)
    {
        return Err(invalid_request("夸克网盘上传元数据或文件哈希无效"));
    }
    if let Some(parent) = request.parent_id.as_deref() {
        validate_id(parent, "父文件夹 ID")?;
    }
    Ok(())
}

fn move_files_request(
    file_ids: Vec<String>,
    target_folder_id: Option<String>,
) -> ProviderResult<Value> {
    if file_ids.is_empty() || file_ids.len() > 100 {
        return Err(invalid_request("夸克网盘一次最多可移动 100 个项目"));
    }
    for file_id in &file_ids {
        validate_id(file_id, "文件 ID")?;
    }
    let target_folder_id = target_folder_id.unwrap_or_else(|| "0".into());
    validate_id(&target_folder_id, "目标文件夹 ID")?;
    if file_ids.iter().any(|file_id| file_id == &target_folder_id) {
        return Err(invalid_request("不能将文件夹移动到自身"));
    }
    Ok(json!({
        "action_type": 1,
        "to_pdir_fid": target_folder_id,
        "filelist": file_ids,
        "exclude_fids": []
    }))
}

fn validate_cookie(cookie: &str) -> ProviderResult<()> {
    if cookie.is_empty() || cookie.len() > 64 * 1024 || cookie.chars().any(char::is_control) {
        return Err(ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克网盘 Cookie 格式无效",
        ));
    }
    for name in ["__kps", "__uid"] {
        if cookie_value(cookie, name).is_none() {
            return Err(ProviderError::new(
                ProviderErrorCategory::Authentication,
                format!("夸克网盘 Cookie 缺少 {name}"),
            ));
        }
    }
    Ok(())
}

fn cookie_value(cookie: &str, name: &str) -> Option<String> {
    cookie
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| {
            (key.trim() == name && !value.trim().is_empty()).then(|| value.trim().to_string())
        })
}

fn validate_id(value: &str, label: &str) -> ProviderResult<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(invalid_request(format!("夸克网盘 {label} 无效")))
    } else {
        Ok(())
    }
}

fn validate_bucket(value: &str) -> ProviderResult<()> {
    if value.is_empty()
        || value.len() > 63
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        Err(invalid_response("夸克网盘返回了无效的 OSS bucket"))
    } else {
        Ok(())
    }
}

fn validate_range(start: Option<u64>, end: Option<u64>) -> ProviderResult<()> {
    if end.is_some_and(|end| start.is_none() || start.is_some_and(|start| end < start)) {
        Err(invalid_request("下载范围无效"))
    } else {
        Ok(())
    }
}

fn validate_upstream_range(
    response: &Response,
    request: &DownloadFileRequest,
) -> ProviderResult<()> {
    let Some(start) = request.range_start else {
        return Ok(());
    };
    let expected_end = request.range_end_inclusive;
    let content_range = response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| invalid_response("夸克下载响应缺少 Content-Range"))?;
    let prefix = format!("bytes {start}-");
    if !content_range.starts_with(&prefix) {
        return Err(invalid_response(format!(
            "夸克下载响应 Range 起点不匹配：{content_range}"
        )));
    }
    if let Some(end) = expected_end {
        let actual_end = content_range
            .strip_prefix(&prefix)
            .and_then(|value| value.split('/').next())
            .and_then(|value| value.parse::<u64>().ok());
        if actual_end != Some(end) {
            return Err(invalid_response(format!(
                "夸克下载响应 Range 终点不匹配：{content_range}"
            )));
        }
        if let Some(length) = response.content_length() {
            if length != end.saturating_sub(start).saturating_add(1) {
                return Err(invalid_response(format!(
                    "夸克下载响应长度不匹配：expected={}, actual={length}",
                    end.saturating_sub(start).saturating_add(1)
                )));
            }
        }
    }
    Ok(())
}

fn upstream_range_error(response: &Response, reason: &str) -> ProviderError {
    let status = response.status();
    let content_range = response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("none");
    let content_length = response
        .content_length()
        .map_or_else(|| "unknown".into(), |value| value.to_string());
    invalid_response(format!(
        "夸克下载链接 {reason}：status={}, content-range={content_range}, content-length={content_length}",
        status.as_u16()
    ))
}

fn range_header(start: Option<u64>, end: Option<u64>) -> ProviderResult<Option<HeaderValue>> {
    match (start, end) {
        (None, None) => Ok(None),
        (Some(start), end) => HeaderValue::from_str(&format!(
            "bytes={start}-{}",
            end.map(|value| value.to_string()).unwrap_or_default()
        ))
        .map(Some)
        .map_err(|_| invalid_request("下载范围无效")),
        (None, Some(_)) => Err(invalid_request("下载范围必须包含起始位置")),
    }
}

fn response_stream(response: Response) -> ProviderResult<ProviderByteStream> {
    let stream = response
        .bytes_stream()
        .map(|chunk| chunk.map(|bytes| bytes.to_vec()).map_err(network_error));
    Ok(Box::pin(stream))
}

fn find_number(value: &Value, keys: &[&str]) -> Option<u64> {
    if let Some(object) = value.as_object() {
        for key in keys {
            if let Some(number) = object.get(*key).and_then(value_u64) {
                return Some(number);
            }
        }
        for nested in object.values() {
            if let Some(number) = find_number(nested, keys) {
                return Some(number);
            }
        }
    } else if let Some(array) = value.as_array() {
        for nested in array {
            if let Some(number) = find_number(nested, keys) {
                return Some(number);
            }
        }
    }
    None
}

fn value_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .or_else(|| value.as_i64().map(|value| value.to_string()))
        })
    })
}

fn api_value_error(value: &Value) -> ProviderError {
    let message = error_value(value, &["message", "msg", "error_msg"])
        .unwrap_or_else(|| "夸克网盘 API 请求失败".into());
    let lower = message.to_ascii_lowercase();
    let category = if lower.contains("login")
        || lower.contains("auth")
        || lower.contains("cookie")
        || lower.contains("未登录")
    {
        ProviderErrorCategory::Authentication
    } else if lower.contains("limit") || lower.contains("频繁") || lower.contains("rate") {
        ProviderErrorCategory::RateLimit
    } else if lower.contains("forbidden") || lower.contains("permission") || lower.contains("权限")
    {
        ProviderErrorCategory::Permission
    } else {
        ProviderErrorCategory::RemoteUnavailable
    };
    let mut details = Vec::new();
    if let Some(code) = error_value(value, &["code", "error_code", "errno"]) {
        details.push(format!("code={code}"));
    }
    if let Some(status) = error_value(value, &["status"]) {
        details.push(format!("status={status}"));
    }
    let message = if details.is_empty() {
        message
    } else {
        format!("{} ({})", message, details.join(", "))
    };
    ProviderError::new(category, truncate(&message, 1000))
}

fn error_value(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(safe_scalar)
            .or_else(|| {
                value
                    .get("data")
                    .and_then(|data| data.get(*key))
                    .and_then(safe_scalar)
            })
            .or_else(|| {
                value
                    .get("error")
                    .and_then(|error| error.get(*key))
                    .and_then(safe_scalar)
            })
    })
}

fn safe_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(truncate(value, 300)),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn status_error(status: StatusCode, message: &str) -> ProviderError {
    let category = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ProviderErrorCategory::Authentication,
        StatusCode::NOT_FOUND => ProviderErrorCategory::NotFound,
        StatusCode::TOO_MANY_REQUESTS => ProviderErrorCategory::RateLimit,
        _ if status.is_server_error() => ProviderErrorCategory::RemoteUnavailable,
        _ => ProviderErrorCategory::Network,
    };
    ProviderError::new(category, format!("{message} ({})", status.as_u16()))
}

fn status_error_with_message(status: StatusCode, value: &Value) -> ProviderError {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克网盘 Cookie 已失效或被拒绝",
        )
    } else if status == StatusCode::NOT_FOUND {
        let path = value_string(value, &["path"]).unwrap_or_else(|| "unknown".into());
        let detail =
            value_string(value, &["error", "message"]).unwrap_or_else(|| "Not Found".into());
        ProviderError::new(
            ProviderErrorCategory::RemoteUnavailable,
            format!(
                "夸克网盘接口返回 404 ({path}): {detail}；请确认 Cookie 有效，或接口路径已发生变化"
            ),
        )
    } else {
        api_value_error(value)
    }
}

fn header_value(value: &str) -> ProviderResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| invalid_request("夸克网盘请求头包含非法字符"))
}

fn network_error(error: reqwest::Error) -> ProviderError {
    ProviderError::new(
        ProviderErrorCategory::Network,
        format!("夸克网盘网络请求失败: {error}"),
    )
}

async fn send_direct_upload_with_retry(
    upload: reqwest::RequestBuilder,
    bytes: &[u8],
) -> ProviderResult<Response> {
    for attempt in 0..DIRECT_UPLOAD_RETRIES {
        let request = upload
            .try_clone()
            .ok_or_else(|| invalid_request("夸克上传请求无法重试"))?;
        match request.body(bytes.to_vec()).send().await {
            Ok(response) => return Ok(response),
            Err(_) if attempt + 1 < DIRECT_UPLOAD_RETRIES => {
                tokio::time::sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
            }
            Err(error) => return Err(network_error(error)),
        }
    }
    Err(invalid_response("夸克上传重试未返回结果"))
}

fn invalid_request(message: impl Into<String>) -> ProviderError {
    ProviderError::new(ProviderErrorCategory::InvalidRequest, message)
}

fn invalid_response(message: impl Into<String>) -> ProviderError {
    ProviderError::new(ProviderErrorCategory::InvalidResponse, message)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn oss_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn short_hash(value: &[u8]) -> String {
    let digest = sha2::Sha256::digest(value);
    digest[..10]
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_validation_requires_quark_identity_cookies() {
        assert!(validate_cookie("__uid=u; __kps=k").is_ok());
        assert!(validate_cookie("__uid=u").is_err());
    }

    #[test]
    fn cookie_json_formats_are_normalized_without_metadata_fields() {
        let browser_export = cookie_from_json_text(
            r#"[{"name":"__uid","value":"u","domain":".quark.cn"},{"name":"__kps","value":"k"}]"#,
        )
        .unwrap();
        assert!(validate_cookie(&browser_export).is_ok());
        assert!(!browser_export.contains("domain="));

        let quarkpan_export = cookie_from_json_text(
            r#"{"cookies":{"__uid":"u","__kps":"k"},"cookie_string":"__uid=u; __kps=k","timestamp":1}"#,
        )
        .unwrap();
        assert_eq!(quarkpan_export, "__uid=u; __kps=k");
    }

    #[test]
    fn response_cookies_merge_without_dropping_existing_values() {
        let merged = merge_cookie_strings(
            "__uid=u; __kps=k; __puus=old; theme=dark",
            "__puus=new; __pus=play",
        )
        .unwrap();
        assert_eq!(
            merged,
            "__uid=u; __kps=k; __puus=new; theme=dark; __pus=play"
        );
        assert_eq!(
            cookie_without(&merged, "__puus"),
            "__uid=u; __kps=k; theme=dark; __pus=play"
        );
    }

    #[test]
    fn sha1_context_tracks_complete_blocks_without_padding() {
        let mut context = Sha1Context::default();
        context.update(&[b'a'; 64]);
        assert_eq!(context.processed_bits, 512);
        assert!(context.buffer.is_empty());
        assert!(!context.context_header().is_empty());
    }

    #[test]
    fn sha1_parallel_context_exposes_offset_and_state() {
        let mut context = Sha1Context::default();
        context.update(&[b'a'; 64]);
        let parallel = context.parallel_context(64);

        assert_eq!(parallel["part_offset"], json!(64));
        assert_eq!(parallel["h"].as_array().map(Vec::len), Some(5));
        assert_ne!(parallel["h"][0], json!(0x67452301_u32));
    }

    #[test]
    fn quark_items_and_api_errors_are_normalized() {
        let folder = remote_file_item(
            &json!({
                "fid": "folder-1",
                "file_name": "docs",
                "dir": true,
                "size": 0,
                "updated_at": 123
            }),
            Some("0"),
        )
        .unwrap();
        assert_eq!(folder.kind, RemoteFileKind::Folder);
        assert_eq!(folder.parent_id.as_deref(), Some("0"));
        assert!(!folder.downloadable);

        let file_with_numeric_directory_marker = remote_file_item(
            &json!({
                "fid": "file-1",
                "file_name": "notes.md",
                "dir": 0,
                "file_type": 0,
                "size": 128
            }),
            Some("0"),
        )
        .unwrap();
        assert_eq!(
            file_with_numeric_directory_marker.kind,
            RemoteFileKind::File
        );
        assert!(file_with_numeric_directory_marker.downloadable);

        let numeric_folder = remote_file_item(
            &json!({
                "fid": "folder-2",
                "file_name": "archive",
                "dir": 1,
                "file_type": 1
            }),
            Some("0"),
        )
        .unwrap();
        assert_eq!(numeric_folder.kind, RemoteFileKind::Folder);
        assert!(!numeric_folder.downloadable);

        let ambiguous_detail_file = remote_file_item(
            &json!({
                "fid": "file-2",
                "file_name": "report.pdf",
                "file_type": 0,
                "size": 1024,
                "format_type": "application/pdf"
            }),
            None,
        )
        .unwrap();
        assert_eq!(ambiguous_detail_file.kind, RemoteFileKind::File);
        assert!(ambiguous_detail_file.downloadable);

        let legacy_folder = remote_file_item(
            &json!({
                "fid": "folder-3",
                "file_name": "legacy-folder",
                "file_type": 0,
                "size": 0
            }),
            None,
        )
        .unwrap();
        assert_eq!(legacy_folder.kind, RemoteFileKind::Folder);
        assert!(!legacy_folder.downloadable);

        let timestamp_only_file = remote_file_item(
            &json!({
                "fid": "file-3",
                "file_name": "timestamped.bin",
                "dir": false,
                "updated_at": 123456
            }),
            Some("0"),
        )
        .unwrap();
        assert_eq!(timestamp_only_file.modified_at.as_deref(), Some("123456"));
        assert_eq!(timestamp_only_file.revision, None);

        assert_eq!(
            api_value_error(&json!({"message": "cookie login expired"})).category,
            ProviderErrorCategory::Authentication
        );
        assert_eq!(
            api_value_error(&json!({"message": "rate limit"})).category,
            ProviderErrorCategory::RateLimit
        );
        assert!(validate_bucket("ul-zb").is_ok());
        assert!(validate_bucket("evil.example.com").is_err());
    }

    #[test]
    fn search_pages_use_metadata_total_and_preserve_parent_ids_when_present() {
        let response = json!({
            "metadata": { "_total": 3 },
            "data": {
                "list": [
                    { "fid": "file-1", "file_name": "notes.md", "size": 128, "pdir_fid": "42" },
                    { "fid": "file-2", "file_name": "notes-2.md", "size": 256, "pdir_fid": "42" }
                ]
            }
        });
        let page = parse_search_page(&response, 1, 2).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].parent_id.as_deref(), Some("42"));
        assert_eq!(page.next_page_token.as_deref(), Some("2"));
    }

    #[test]
    fn playback_parser_prefers_default_resolution_and_identifies_hls() {
        let link = parse_media_playback_link(&json!({
            "data": {
                "default_resolution": "high",
                "video_list": [
                    {"resolution": "normal", "video_info": {"url": "https://cdn.example/normal.mp4", "format": "mp4"}},
                    {"resolution": "high", "video_info": {"url": "https://cdn.example/high.m3u8", "format": "m3u8"}}
                ]
            }
        }))
        .unwrap();
        assert_eq!(link.resolution.as_deref(), Some("high"));
        assert_eq!(link.protocol, "hls");
        assert_eq!(
            link.media_type.as_deref(),
            Some("application/vnd.apple.mpegurl")
        );
        assert_eq!(link.variants.len(), 2);
        assert_eq!(link.variants[0].resolution.as_deref(), Some("high"));
        assert_eq!(link.variants[1].resolution.as_deref(), Some("normal"));
        assert_eq!(link.variants[0].url, link.url);
    }

    #[test]
    fn download_playback_parser_accepts_quark_direct_url() {
        let link = parse_download_playback_link(&json!({
            "data": [{
                "download_url": "https://video-play-c-zb.drive.quark.cn/path?auth_key=redacted"
            }]
        }))
        .unwrap();
        assert_eq!(link.protocol, "progressive");
        assert_eq!(link.media_type.as_deref(), Some("video/mp4"));
        assert!(link.variants.is_empty());
    }

    #[test]
    fn playback_parser_rejects_untrusted_or_missing_urls() {
        let response = json!({
            "data": {
                "video_list": [
                    {"resolution": "high", "video_info": {"url": "http://cdn.example/high.mp4", "format": "mp4"}},
                    {"resolution": "normal", "video_info": {"format": "mp4"}}
                ]
            }
        });
        assert_eq!(
            parse_media_playback_link(&response).unwrap_err().category,
            ProviderErrorCategory::RemoteUnavailable
        );
    }

    #[test]
    fn playback_parser_infers_protocol_when_format_is_missing() {
        let link = parse_media_playback_link(&json!({
            "data": {
                "video_list": [
                    {"resolution": "normal", "video_info": {"url": "https://cdn.example/video.m3u8?token=redacted"}}
                ]
            }
        }))
        .unwrap();
        assert_eq!(link.protocol, "hls");
        assert_eq!(
            link.media_type.as_deref(),
            Some("application/vnd.apple.mpegurl")
        );
    }

    #[test]
    fn transcoding_invalid_errors_are_reported_as_playback_failures() {
        assert!(is_transcoding_unavailable(&ProviderError::new(
            ProviderErrorCategory::RemoteUnavailable,
            "data invalid: [plf_invalid]"
        )));
        assert!(!is_transcoding_unavailable(&ProviderError::new(
            ProviderErrorCategory::RateLimit,
            "download file size limit"
        )));
    }

    #[test]
    fn playback_failure_diagnostic_preserves_safe_api_details() {
        let message = format_playback_error(
            &ProviderError::new(
                ProviderErrorCategory::RemoteUnavailable,
                "data invalid: [plf_invalid] (code=400, status=failed)",
            ),
            Some("__uid=u; __kps=k; __pus=p"),
        );
        assert!(message.contains("plf_invalid"));
        assert!(message.contains("code=400"));
        assert!(message.contains("__pus=存在"));
        assert!(message.contains("__puus=缺失"));
        assert!(!message.contains("__kps=k"));
    }

    #[test]
    fn page_tokens_must_be_positive_integers() {
        assert_eq!(parse_page_token(None).unwrap(), 1);
        assert_eq!(parse_page_token(Some("2")).unwrap(), 2);
        assert!(parse_page_token(Some("0")).is_err());
        assert!(parse_page_token(Some("next")).is_err());
    }

    #[test]
    fn move_request_maps_root_and_validates_ids() {
        assert_eq!(
            move_files_request(vec!["file-2".into(), "file-1".into()], None).unwrap(),
            json!({
                "action_type": 1,
                "to_pdir_fid": "0",
                "filelist": ["file-2", "file-1"],
                "exclude_fids": []
            })
        );
        assert_eq!(
            move_files_request(vec!["file-1".into()], Some("folder-1".into())).unwrap()
                ["to_pdir_fid"],
            "folder-1"
        );
        assert!(move_files_request(Vec::new(), None).is_err());
        assert!(move_files_request(vec!["file-1".into(); 101], None).is_err());
        assert!(move_files_request(vec!["bad\nid".into()], None).is_err());
        assert!(move_files_request(vec!["folder-1".into()], Some("folder-1".into())).is_err());
    }
}
