//! Shared application state handed to every axum handler.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::config::{Config, PreparedPaths};
use crate::db::Db;
use crate::download::DownloadEngine;
use crate::vault::Vault;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub paths: Arc<PreparedPaths>,
    pub db: Db,
    pub vault: Arc<Vault>,
    pub factory: Arc<quark_core::QuarkDriveFactory>,
    pub legacy_factory: Arc<quark_core::LegacyQuarkDriveFactory>,
    pub engine: DownloadEngine,
    pub started_at: DateTime<Utc>,
}
