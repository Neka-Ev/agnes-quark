//! SQLite persistence for accounts and download tasks.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Db {
    connection: Arc<Mutex<rusqlite::Connection>>,
}

#[derive(Debug, Clone)]
pub struct AccountRecord {
    pub id: String,
    pub provider_id: String,
    pub display_name: String,
    pub account_subject: Option<String>,
    pub config: serde_json::Value,
    pub credential: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadRow {
    pub id: String,
    pub account_id: String,
    pub kind: String,
    pub remote_id: String,
    pub display_name: String,
    pub relative_dir: String,
    pub status: String,
    pub total_bytes: Option<u64>,
    pub downloaded_bytes: u64,
    pub completed_items: u64,
    pub total_items: Option<u64>,
    pub current_file: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Db {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let connection = rusqlite::Connection::open(path)
            .with_context(|| format!("cannot open database {}", path.display()))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;
                 CREATE TABLE IF NOT EXISTS accounts (
                     id TEXT PRIMARY KEY,
                     provider_id TEXT NOT NULL,
                     display_name TEXT NOT NULL,
                     account_subject TEXT,
                     config TEXT NOT NULL,
                     credential TEXT NOT NULL,
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS downloads (
                     id TEXT PRIMARY KEY,
                     account_id TEXT NOT NULL,
                     kind TEXT NOT NULL,
                     remote_id TEXT NOT NULL,
                     display_name TEXT NOT NULL,
                     relative_dir TEXT NOT NULL,
                     status TEXT NOT NULL,
                     total_bytes INTEGER,
                     downloaded_bytes INTEGER NOT NULL DEFAULT 0,
                     completed_items INTEGER NOT NULL DEFAULT 0,
                     total_items INTEGER,
                     current_file TEXT,
                     error TEXT,
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS downloads_created_at
                     ON downloads(created_at DESC);",
            )
            .context("cannot initialize database schema")?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub async fn list_accounts(&self) -> anyhow::Result<Vec<AccountRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT id, provider_id, display_name, account_subject, config, credential,
                    created_at, updated_at
             FROM accounts ORDER BY created_at ASC",
        )?;
        let rows = statement
            .query_map([], account_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_account(&self, id: &str) -> anyhow::Result<Option<AccountRecord>> {
        let connection = self.connection.lock().await;
        let row = connection
            .query_row(
                "SELECT id, provider_id, display_name, account_subject, config, credential,
                        created_at, updated_at
                 FROM accounts WHERE id = ?1",
                params![id],
                account_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub async fn upsert_account(&self, account: &AccountRecord) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "INSERT INTO accounts
                 (id, provider_id, display_name, account_subject, config, credential,
                  created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 provider_id = excluded.provider_id,
                 display_name = excluded.display_name,
                 account_subject = excluded.account_subject,
                 config = excluded.config,
                 credential = excluded.credential,
                 updated_at = excluded.updated_at",
            params![
                account.id,
                account.provider_id,
                account.display_name,
                account.account_subject,
                serde_json::to_string(&account.config)?,
                account.credential,
                account.created_at,
                account.updated_at,
            ],
        )?;
        Ok(())
    }

    pub async fn update_credential(&self, id: &str, credential: &str) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "UPDATE accounts SET credential = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, credential, now()],
        )?;
        Ok(())
    }

    pub async fn delete_account(&self, id: &str) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute("DELETE FROM downloads WHERE account_id = ?1", params![id])?;
        connection.execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub async fn insert_download(&self, row: &DownloadRow) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "INSERT INTO downloads
                 (id, account_id, kind, remote_id, display_name, relative_dir, status,
                  total_bytes, downloaded_bytes, completed_items, total_items, current_file,
                  error, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                row.id,
                row.account_id,
                row.kind,
                row.remote_id,
                row.display_name,
                row.relative_dir,
                row.status,
                to_i64(row.total_bytes),
                row.downloaded_bytes as i64,
                row.completed_items as i64,
                to_i64(row.total_items),
                row.current_file,
                row.error,
                row.created_at,
                row.updated_at,
            ],
        )?;
        Ok(())
    }

    pub async fn list_downloads(&self, limit: u32) -> anyhow::Result<Vec<DownloadRow>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT id, account_id, kind, remote_id, display_name, relative_dir, status,
                    total_bytes, downloaded_bytes, completed_items, total_items, current_file,
                    error, created_at, updated_at
             FROM downloads ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement
            .query_map(params![limit as i64], download_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn get_download(&self, id: &str) -> anyhow::Result<Option<DownloadRow>> {
        let connection = self.connection.lock().await;
        let row = connection
            .query_row(
                "SELECT id, account_id, kind, remote_id, display_name, relative_dir, status,
                        total_bytes, downloaded_bytes, completed_items, total_items, current_file,
                        error, created_at, updated_at
                 FROM downloads WHERE id = ?1",
                params![id],
                download_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub async fn set_download_status(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "UPDATE downloads SET status = ?2, error = ?3, updated_at = ?4 WHERE id = ?1",
            params![id, status, error, now()],
        )?;
        Ok(())
    }

    pub async fn set_download_progress(
        &self,
        id: &str,
        downloaded_bytes: u64,
        current_file: Option<&str>,
    ) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "UPDATE downloads
             SET downloaded_bytes = ?2, current_file = ?3, updated_at = ?4
             WHERE id = ?1",
            params![id, downloaded_bytes as i64, current_file, now()],
        )?;
        Ok(())
    }

    pub async fn set_download_totals(
        &self,
        id: &str,
        total_bytes: Option<u64>,
        total_items: Option<u64>,
        completed_items: u64,
        downloaded_bytes: u64,
    ) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "UPDATE downloads
             SET total_bytes = ?2, total_items = ?3, completed_items = ?4,
                 downloaded_bytes = ?5, updated_at = ?6
             WHERE id = ?1",
            params![
                id,
                to_i64(total_bytes),
                to_i64(total_items),
                completed_items as i64,
                downloaded_bytes as i64,
                now()
            ],
        )?;
        Ok(())
    }

    pub async fn reset_download_for_retry(&self, id: &str) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute(
            "UPDATE downloads
             SET status = 'queued', error = NULL, downloaded_bytes = 0,
                 completed_items = 0, current_file = NULL, updated_at = ?2
             WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub async fn delete_download(&self, id: &str) -> anyhow::Result<()> {
        let connection = self.connection.lock().await;
        connection.execute("DELETE FROM downloads WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Mark tasks that were running before a restart as queued again.
    pub async fn reset_running_downloads(&self) -> anyhow::Result<usize> {
        let connection = self.connection.lock().await;
        let changed = connection.execute(
            "UPDATE downloads SET status = 'queued', updated_at = ?1 WHERE status = 'running'",
            params![now()],
        )?;
        Ok(changed)
    }
}

fn account_from_row(row: &Row<'_>) -> rusqlite::Result<AccountRecord> {
    let config: String = row.get(4)?;
    Ok(AccountRecord {
        id: row.get(0)?,
        provider_id: row.get(1)?,
        display_name: row.get(2)?,
        account_subject: row.get(3)?,
        config: serde_json::from_str(&config).unwrap_or(serde_json::Value::Null),
        credential: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn download_from_row(row: &Row<'_>) -> rusqlite::Result<DownloadRow> {
    Ok(DownloadRow {
        id: row.get(0)?,
        account_id: row.get(1)?,
        kind: row.get(2)?,
        remote_id: row.get(3)?,
        display_name: row.get(4)?,
        relative_dir: row.get(5)?,
        status: row.get(6)?,
        total_bytes: from_i64(row.get(7)?),
        downloaded_bytes: row.get::<_, i64>(8)?.max(0) as u64,
        completed_items: row.get::<_, i64>(9)?.max(0) as u64,
        total_items: from_i64(row.get(10)?),
        current_file: row.get(11)?,
        error: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn to_i64(value: Option<u64>) -> Option<i64> {
    value.and_then(|value| i64::try_from(value).ok())
}

fn from_i64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
