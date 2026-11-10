//! Entry point for the headless Quark Drive server.

mod api;
mod config;
mod db;
mod download;
mod error;
mod state;
mod vault;
mod web;

use std::sync::Arc;

use chrono::Utc;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::db::Db;
use crate::download::DownloadEngine;
use crate::state::AppState;
use crate::vault::Vault;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    let paths = config.prepare()?;

    let vault = Arc::new(Vault::load_or_create(&paths.data_dir)?);
    let db = Db::open(&paths.data_dir.join("quark.db")).await?;
    let requeued = db.reset_running_downloads().await?;
    if requeued > 0 {
        tracing::info!(count = requeued, "requeued interrupted downloads");
    }

    let factory = Arc::new(quark_core::QuarkDriveFactory::new()?);
    let legacy_factory = Arc::new(quark_core::LegacyQuarkDriveFactory::new()?);

    let engine = DownloadEngine::start(
        db.clone(),
        vault.clone(),
        factory.clone(),
        paths.download_root.clone(),
        paths.download_root.clone(),
        paths.concurrency,
    );

    for row in db.list_downloads(10_000).await? {
        if row.status == "queued" {
            engine.enqueue(row.id);
        }
    }

    let auth_required = paths.token.is_some();
    let listen = config.listen;
    let state = AppState {
        config: Arc::new(config),
        paths: Arc::new(paths),
        db,
        vault,
        factory,
        legacy_factory,
        engine,
        started_at: Utc::now(),
    };

    api::reconcile_accounts(&state).await?;

    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("quark-server listening on http://{listen}/");
    if auth_required {
        println!("access token is required (Authorization: Bearer <token> or ?token=<token>)");
    } else {
        println!("no access token configured; keep the listener on a loopback interface");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
