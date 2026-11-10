//! Command-line configuration for the headless Quark Drive server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "quark-server",
    version,
    about = "Headless Quark Drive download server with a browser UI"
)]
pub struct Config {
    /// Address to listen on. Defaults to loopback so the UI is only reachable
    /// through an SSH tunnel or a local port forward.
    #[arg(long, env = "QUARK_LISTEN", default_value = "127.0.0.1:8787")]
    pub listen: SocketAddr,

    /// Directory for the SQLite database and the encrypted credential vault.
    #[arg(long, env = "QUARK_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Directory that downloaded files are written into.
    #[arg(long, env = "QUARK_DOWNLOAD_ROOT", default_value = "./downloads")]
    pub download_root: PathBuf,

    /// Bearer token required for every API request. Mandatory for non-loopback
    /// listeners unless --allow-insecure is set.
    #[arg(long, env = "QUARK_TOKEN")]
    pub token: Option<String>,

    /// Explicitly allow an unauthenticated non-loopback listener.
    #[arg(long, env = "QUARK_ALLOW_INSECURE", default_value_t = false)]
    pub allow_insecure: bool,

    /// Number of concurrent download workers.
    #[arg(long, env = "QUARK_CONCURRENCY", default_value_t = 1)]
    pub concurrency: usize,
}

impl Config {
    /// Validate configuration and create the data/download directories.
    pub fn prepare(&self) -> anyhow::Result<PreparedPaths> {
        let token = self
            .token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);

        if !self.listen.ip().is_loopback() && token.is_none() && !self.allow_insecure {
            bail!(
                "refusing to listen on {} without --token; use --allow-insecure only on a trusted network",
                self.listen
            );
        }

        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("cannot create data directory {}", self.data_dir.display()))?;
        std::fs::create_dir_all(&self.download_root).with_context(|| {
            format!(
                "cannot create download directory {}",
                self.download_root.display()
            )
        })?;

        let data_dir = canonicalize(&self.data_dir)?;
        let download_root = canonicalize(&self.download_root)?;

        Ok(PreparedPaths {
            data_dir,
            download_root,
            token,
            concurrency: self.concurrency.clamp(1, 8),
        })
    }
}

pub struct PreparedPaths {
    pub data_dir: PathBuf,
    pub download_root: PathBuf,
    pub token: Option<String>,
    pub concurrency: usize,
}

fn canonicalize(path: &Path) -> anyhow::Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("cannot resolve {}", path.display()))
}
