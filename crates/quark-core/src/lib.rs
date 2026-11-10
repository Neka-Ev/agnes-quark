//! Quark Drive provider, extracted from agnes-agent.
//!
//! This crate intentionally contains no Tauri, database, or UI coupling. It
//! exposes the provider ports plus the official and legacy Quark adapters.
#![allow(dead_code)]

pub mod domain;
pub mod ports;
pub mod quark_drive;
#[path = "quark_drive_official.rs"]
pub mod quark_drive_official;

pub use domain::*;
pub use ports::*;
pub use quark_drive::QuarkDriveFactory as LegacyQuarkDriveFactory;
pub use quark_drive_official::{
    credential_capabilities, merge_legacy_cookie, merge_official_credential, QuarkDriveFactory,
};
