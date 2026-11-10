use std::collections::BTreeMap;
use std::fmt;
use std::pin::Pin;

use futures_util::Stream;
use serde::{Deserialize, Serialize};

pub type ProviderByteStream = Pin<Box<dyn Stream<Item = ProviderResult<Vec<u8>>> + Send + 'static>>;
pub type ProviderResult<T> = Result<T, ProviderError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorCategory {
    Authentication,
    Permission,
    RateLimit,
    Network,
    NotFound,
    Conflict,
    Unsupported,
    InvalidRequest,
    RemoteUnavailable,
    Cancelled,
    InvalidResponse,
}

impl ProviderErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Permission => "permission",
            Self::RateLimit => "rate_limit",
            Self::Network => "network",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unsupported => "unsupported",
            Self::InvalidRequest => "invalid_request",
            Self::RemoteUnavailable => "remote_unavailable",
            Self::Cancelled => "cancelled",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderError {
    pub category: ProviderErrorCategory,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

impl ProviderError {
    pub fn new(category: ProviderErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub fn unsupported(capability: &str) -> Self {
        Self::new(
            ProviderErrorCategory::Unsupported,
            format!("Provider does not support {capability}"),
        )
    }

    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for ProviderError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStability {
    #[default]
    Official,
    Community,
    Experimental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthKind {
    OAuth2Pkce,
    BrowserSession,
    ApiToken,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentHashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageCapabilities {
    pub browse_files: bool,
    pub search_files: bool,
    pub read_files: bool,
    pub write_files: bool,
    pub delete_files: bool,
    pub move_files: bool,
    pub share_files: bool,
    pub import_shared_files: bool,
    pub object_storage: bool,
    pub range_download: bool,
    pub media_playback: bool,
    pub resumable_upload: bool,
    pub conditional_write: bool,
    pub stable_revisions: bool,
    pub stable_file_sizes: bool,
    pub quota: bool,
    pub user_authorization: bool,
    pub worker_proxy: bool,
    pub max_object_bytes: Option<u64>,
    pub recommended_chunk_bytes: Option<u64>,
    #[serde(default)]
    pub required_upload_hashes: Vec<ContentHashAlgorithm>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: String,
    pub display_name: String,
    pub auth_kind: ProviderAuthKind,
    pub stability: ProviderStability,
    pub implementation_version: String,
    pub capabilities: StorageCapabilities,
}

impl ProviderDescriptor {
    pub fn validate(&self) -> ProviderResult<()> {
        validate_provider_id(&self.id)?;
        if self.display_name.trim().is_empty() || self.display_name.chars().count() > 80 {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Provider display name must contain between 1 and 80 characters",
            ));
        }
        if self.implementation_version.trim().is_empty()
            || self.implementation_version.chars().count() > 64
        {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Provider implementation version must contain between 1 and 64 characters",
            ));
        }
        Ok(())
    }
}

pub fn validate_provider_id(value: &str) -> ProviderResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if valid {
        Ok(())
    } else {
        Err(ProviderError::new(
            ProviderErrorCategory::InvalidRequest,
            "Provider ID must use 1-64 lowercase ASCII letters, digits, hyphens, or underscores",
        ))
    }
}

pub fn validate_account_id(value: &str) -> ProviderResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(ProviderError::new(
            ProviderErrorCategory::InvalidRequest,
            "Storage account ID contains unsupported characters",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageProviderAccount {
    pub id: String,
    pub provider_id: String,
    pub display_name: String,
    pub account_subject: Option<String>,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderAuthorizationRequest {
    #[serde(default)]
    pub input: serde_json::Value,
}

impl StorageProviderAccount {
    pub fn validate(&self) -> ProviderResult<()> {
        validate_account_id(&self.id)?;
        validate_provider_id(&self.provider_id)?;
        if self.display_name.trim().is_empty() || self.display_name.chars().count() > 120 {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Storage account name must contain between 1 and 120 characters",
            ));
        }
        if self
            .account_subject
            .as_ref()
            .is_some_and(|value| value.chars().count() > 512)
        {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Storage account subject is too long",
            ));
        }
        if !self.config.is_object() || self.config.to_string().len() > 32 * 1024 {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Storage account public config must be a JSON object no larger than 32 KiB",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteFileKind {
    File,
    Folder,
    Shortcut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFileItem {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: RemoteFileKind,
    pub media_type: Option<String>,
    pub size: Option<u64>,
    pub modified_at: Option<String>,
    pub revision: Option<String>,
    /// Advisory capability for list UIs; the provider download call remains authoritative.
    pub downloadable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFilesRequest {
    pub parent_id: Option<String>,
    pub page_token: Option<String>,
    pub page_size: usize,
}

impl ListFilesRequest {
    pub fn normalized(mut self) -> Self {
        self.page_size = self.page_size.clamp(1, 200);
        self.parent_id = trim_optional(self.parent_id);
        self.page_token = trim_optional(self.page_token);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchFilesRequest {
    pub query: String,
    pub page_token: Option<String>,
    pub page_size: usize,
}

impl SearchFilesRequest {
    pub fn normalized(mut self) -> Self {
        self.query = self.query.trim().to_owned();
        self.page_token = trim_optional(self.page_token);
        self.page_size = self.page_size.clamp(1, 200);
        self
    }

    pub fn validate(&self) -> ProviderResult<()> {
        if self.query.is_empty()
            || self.query.chars().count() > 200
            || self.query.chars().any(char::is_control)
        {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Search query must contain 1-200 visible characters",
            ));
        }
        if self
            .page_token
            .as_ref()
            .is_some_and(|value| value.len() > 4096 || value.chars().any(char::is_control))
        {
            return Err(ProviderError::new(
                ProviderErrorCategory::InvalidRequest,
                "Search page token is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShareRequest {
    pub file_ids: Vec<String>,
    pub title: Option<String>,
    pub password: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFileLink {
    pub file_id: String,
    pub url: String,
    pub password: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShareResult {
    pub links: Vec<SharedFileLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSharedFilesRequest {
    pub share_url: String,
    pub password: Option<String>,
    pub file_ids: Option<Vec<String>>,
    pub target_folder_id: Option<String>,
    pub save_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSharedFilesResult {
    pub task_id: Option<String>,
    pub files: Vec<RemoteFileItem>,
    pub completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFilePage {
    pub items: Vec<RemoteFileItem>,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderQuota {
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub trashed_bytes: Option<u64>,
    pub checked_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadFileRequest {
    pub file_id: String,
    pub range_start: Option<u64>,
    pub range_end_inclusive: Option<u64>,
    pub expected_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlaybackRequest {
    pub file_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlaybackVariant {
    pub url: String,
    pub media_type: Option<String>,
    pub protocol: String,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlaybackLink {
    pub url: String,
    pub media_type: Option<String>,
    pub protocol: String,
    pub resolution: Option<String>,
    pub variants: Vec<MediaPlaybackVariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginFileUploadRequest {
    pub parent_id: Option<String>,
    pub name: String,
    pub size: u64,
    pub media_type: String,
    pub chunk_size: u64,
    #[serde(default)]
    pub content_hashes: BTreeMap<ContentHashAlgorithm, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileUploadSession {
    pub session_id: String,
    pub next_offset: u64,
    pub chunk_size: u64,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadFileChunkRequest {
    pub session_id: String,
    pub offset: u64,
    pub total_size: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadedFileChunk {
    pub next_offset: u64,
    pub complete: bool,
    pub file: Option<RemoteFileItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteObjectLocator {
    pub opaque_id: String,
    pub revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteObjectState {
    pub locator: RemoteObjectLocator,
    pub size: u64,
    pub content_hash: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadObjectRequest {
    pub locator: RemoteObjectLocator,
    pub range_start: Option<u64>,
    pub range_end_inclusive: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginObjectUploadRequest {
    pub opaque_name: String,
    pub size: u64,
    pub content_hash: String,
    pub media_type: String,
    pub chunk_size: u64,
    pub publish: Option<ObjectPublishMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPublishMetadata {
    pub object_id: String,
    pub object_kind: String,
    pub logical_version: u64,
    pub key_version: i64,
    pub updated_hlc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectUploadSession {
    pub session_id: String,
    pub next_offset: u64,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadObjectChunkRequest {
    pub session_id: String,
    pub offset: u64,
    pub total_size: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadedObjectChunk {
    pub next_offset: u64,
    pub complete: bool,
    pub object: Option<RemoteObjectState>,
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ids_are_open_but_stable_and_safe() {
        for value in ["google_drive", "quark-pan", "webdav2", "s3"] {
            validate_provider_id(value).unwrap();
        }
        for value in ["", "GoogleDrive", "google drive", "a/b", &"x".repeat(65)] {
            assert!(
                validate_provider_id(value).is_err(),
                "{value} must be rejected"
            );
        }
        assert!(validate_account_id("account-123").is_ok());
        assert!(validate_account_id("account:other").is_err());
    }

    #[test]
    fn file_pages_apply_provider_independent_limits() {
        let request = ListFilesRequest {
            parent_id: Some("  root  ".into()),
            page_token: Some(" ".into()),
            page_size: 10_000,
        }
        .normalized();
        assert_eq!(request.parent_id.as_deref(), Some("root"));
        assert_eq!(request.page_token, None);
        assert_eq!(request.page_size, 200);
    }

    #[test]
    fn search_requests_are_trimmed_bounded_and_validated() {
        let request = SearchFilesRequest {
            query: "  report  ".into(),
            page_token: Some("  next  ".into()),
            page_size: 10_000,
        }
        .normalized();
        assert_eq!(request.query, "report");
        assert_eq!(request.page_token.as_deref(), Some("next"));
        assert_eq!(request.page_size, 200);
        request.validate().unwrap();

        assert!(SearchFilesRequest {
            query: "   ".into(),
            page_token: None,
            page_size: 100,
        }
        .normalized()
        .validate()
        .is_err());
        assert!(SearchFilesRequest {
            query: "bad\nquery".into(),
            page_token: None,
            page_size: 100,
        }
        .validate()
        .is_err());
    }
}
