use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, RANGE, RETRY_AFTER};
use reqwest::{Method, Response, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::domain::{
    BeginFileUploadRequest, ContentHashAlgorithm, CreateShareRequest, CreateShareResult,
    DownloadFileRequest, FileUploadSession, ImportSharedFilesRequest, ImportSharedFilesResult,
    ListFilesRequest, ProviderAuthKind, ProviderAuthorizationRequest, ProviderByteStream,
    ProviderDescriptor, ProviderError, ProviderErrorCategory, ProviderQuota, ProviderResult,
    ProviderStability, RemoteFileItem, RemoteFileKind, RemoteFilePage, SearchFilesRequest,
    SharedFileLink, StorageCapabilities, StorageProviderAccount, UploadFileChunkRequest,
    UploadedFileChunk,
};
use super::ports::{
    FileManagementProvider, FileShareProvider, FileSourceProvider, FileUploadProvider,
    MediaPlaybackProvider, ProviderAuthorizationChallenge, ProviderAuthorizationResult,
    ProviderAuthorizationStep, ProviderCredentialAccess, ProviderFactory, ProviderSession,
    QuotaProvider, SharedFileImportProvider,
};
use super::quark_drive::{QuarkDriveFactory as LegacyQuarkDriveFactory, Sha1Context};

const PROVIDER_ID: &str = "quark_drive";
const OPEN_API: &str = "https://open-api-drive.quark.cn";
const CLIENT_ID: &str = "third_party_agent";
const AGENT_ID: &str = "openclaw";
const AUTH_SCOPE: &str = "clouddrive.base clouddrive.netdisk";
const SIGN_KEY: &str = "cf134812e2de4032bd1cb7c3727e84b3";
const DEFAULT_DEVICE_ID: &str = "agnes_agent";
const DEFAULT_PLATFORM: &str = "linux";
const DEFAULT_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
const DIRECT_UPLOAD_RETRIES: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuarkCredential {
    access_token: String,
    refresh_token: Option<String>,
    device_id: String,
    user_id: String,
    #[serde(default = "default_token_type")]
    token_type: String,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuarkCredentialBundle {
    #[serde(default)]
    official: Option<QuarkCredential>,
    #[serde(default)]
    legacy_cookie: Option<String>,
}

#[derive(Clone)]
struct BundledLegacyCredentialAccess {
    parent: Arc<dyn ProviderCredentialAccess>,
}

#[async_trait]
impl ProviderCredentialAccess for BundledLegacyCredentialAccess {
    async fn load(&self) -> ProviderResult<Option<Zeroizing<String>>> {
        let stored = self.parent.load().await?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        if let Some(bundle) = parse_credential_bundle(stored.as_str()) {
            return Ok(bundle.legacy_cookie.map(Zeroizing::new));
        }
        Ok(Some(stored))
    }

    async fn store(&self, credential: Zeroizing<String>) -> ProviderResult<()> {
        let stored = self.parent.load().await?;
        let Some(stored) = stored else {
            return self.parent.store(credential).await;
        };
        if let Some(mut bundle) = parse_credential_bundle(stored.as_str()) {
            bundle.legacy_cookie = Some(credential.to_string());
            let encoded = serde_json::to_string(&bundle)
                .map_err(|_| invalid_response("夸克多凭证编码失败"))?;
            return self.parent.store(Zeroizing::new(encoded)).await;
        }
        self.parent.store(credential).await
    }

    async fn delete(&self) -> ProviderResult<()> {
        self.parent.delete().await
    }
}

fn default_token_type() -> String {
    "Bearer".into()
}

#[derive(Clone)]
struct AuthChallenge {
    page_code: String,
    client_device_id: String,
    existing_credentials: Vec<QuarkCredential>,
    expires_at: u64,
}

struct AgentAuthExchange {
    status: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    device_id: Option<String>,
    user_id: Option<String>,
    token_type: Option<String>,
    expires_at: u64,
}

struct PollLease<'a> {
    active: &'a StdMutex<HashSet<String>>,
    challenge_id: String,
}

impl Drop for PollLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.challenge_id);
        }
    }
}

pub struct QuarkDriveFactory {
    client: reqwest::Client,
    legacy_factory: LegacyQuarkDriveFactory,
    sessions: StdMutex<HashMap<String, Weak<QuarkDriveSession>>>,
    challenges: StdMutex<HashMap<String, AuthChallenge>>,
    active_polls: StdMutex<HashSet<String>>,
}

impl QuarkDriveFactory {
    pub fn new() -> ProviderResult<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(20))
                .timeout(Duration::from_secs(120))
                .user_agent("Agnes-Agent/0.1 QuarkDriveProvider")
                .build()
                .map_err(network_error)?,
            legacy_factory: LegacyQuarkDriveFactory::new()?,
            sessions: StdMutex::new(HashMap::new()),
            challenges: StdMutex::new(HashMap::new()),
            active_polls: StdMutex::new(HashSet::new()),
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
            stability: ProviderStability::Official,
            implementation_version: "quark-open-api-v1".into(),
            capabilities: StorageCapabilities {
                browse_files: false,
                search_files: true,
                read_files: true,
                write_files: true,
                delete_files: false,
                move_files: true,
                share_files: true,
                import_shared_files: true,
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
        self.legacy_factory.invalidate_account(account_id);
    }

    async fn authorize(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> ProviderResult<ProviderAuthorizationResult> {
        if request.input.get("cookie").is_some()
            || request.input.get("cookie_json").is_some()
            || request.input.get("cookie_json_path").is_some()
        {
            return self.legacy_factory.authorize(request).await;
        }
        let code = request
            .input
            .get("agent_auth_code")
            .or_else(|| request.input.get("token"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_request("请提供夸克官方授权码"))?;
        let existing_credentials = existing_credentials(&request.input);
        let exchange = exchange_agent_auth_code(&self.client, code).await?;
        let credential = credential_from_exchange(exchange, &existing_credentials)?;
        authorized_result(credential)
    }

    async fn begin_authorization(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> ProviderResult<ProviderAuthorizationChallenge> {
        let client_device_id = format!("agnes-{}", uuid::Uuid::new_v4());
        let existing_credentials = existing_credentials(&request.input);
        let current_user_id = existing_credentials
            .first()
            .map(|credential| credential.user_id.clone());
        let mut request_body = json!({
            "client_device_id": client_device_id.clone(),
            "device_name": "Agnes Agent",
            "agent_id": AGENT_ID,
            "client_id": CLIENT_ID,
            "work_dir": "agnes-agent",
            "is_cloud_agent": "false",
            "is_unsure_agent": "false"
        });
        if let Some(user_id) = current_user_id {
            request_body["current_user_id"] = Value::String(user_id);
        }
        let response = signed_request(
            &self.client,
            Method::POST,
            "/agent/v1/get_authorize_page_url",
            vec![("req_id".into(), request_id())],
            Some(request_body),
        )
        .await?;
        let data = response_data(&response)?;
        let raw_authorize_url = string_value(data, &["authorize_page_url", "url"])
            .ok_or_else(|| invalid_response("夸克官方授权接口未返回授权地址"))?;
        let page_code = string_value(data, &["page_code"])
            .ok_or_else(|| invalid_response("夸克官方授权接口未返回 page_code"))?;
        let server_device_id = string_value(data, &["device_id"]);
        let authorize_url = build_authorize_url(
            &raw_authorize_url,
            server_device_id.as_deref(),
            &client_device_id,
        )?;
        let challenge_id = uuid::Uuid::new_v4().to_string();
        self.challenges
            .lock()
            .map_err(|_| invalid_response("夸克授权会话不可用"))?
            .insert(
                challenge_id.clone(),
                AuthChallenge {
                    page_code: page_code.clone(),
                    client_device_id,
                    existing_credentials,
                    expires_at: now_epoch() + 300,
                },
            );
        Ok(ProviderAuthorizationChallenge {
            challenge_id,
            provider_id: PROVIDER_ID.into(),
            kind: "oauth_browser".into(),
            payload: json!({"authorize_url": authorize_url, "page_code": page_code}),
            expires_at: Some((now_epoch() + 300).to_string()),
        })
    }

    async fn poll_authorization(
        &self,
        challenge_id: &str,
    ) -> ProviderResult<ProviderAuthorizationStep> {
        let _poll_lease = {
            let mut active = self
                .active_polls
                .lock()
                .map_err(|_| invalid_response("夸克授权会话不可用"))?;
            if !active.insert(challenge_id.to_owned()) {
                return Ok(ProviderAuthorizationStep::Pending);
            }
            PollLease {
                active: &self.active_polls,
                challenge_id: challenge_id.to_owned(),
            }
        };
        let challenge = self
            .challenges
            .lock()
            .map_err(|_| invalid_response("夸克授权会话不可用"))?
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| invalid_request("夸克授权会话不存在或已过期"))?;
        if now_epoch() >= challenge.expires_at {
            self.challenges
                .lock()
                .map_err(|_| invalid_response("夸克授权会话不可用"))?
                .remove(challenge_id);
            return Err(ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克授权页面已过期，请重新授权",
            ));
        }
        let response = signed_request(
            &self.client,
            Method::GET,
            "/agent/v1/oauth/get_aac_by_pagecode",
            vec![
                ("req_id".into(), request_id()),
                ("page_code".into(), challenge.page_code),
            ],
            None,
        )
        .await?;
        let data = response_data(&response)?;
        if string_value(data, &["status"]).as_deref() != Some("success") {
            return Ok(ProviderAuthorizationStep::Pending);
        }
        let code = string_value(data, &["agent_auth_code"])
            .ok_or_else(|| invalid_response("夸克授权完成但未返回授权码"))?;
        let exchange = exchange_agent_auth_code(&self.client, &code).await?;
        let credential = credential_from_exchange(exchange, &challenge.existing_credentials)?;
        self.challenges
            .lock()
            .map_err(|_| invalid_response("夸克授权会话不可用"))?
            .remove(challenge_id);
        Ok(ProviderAuthorizationStep::Authorized(authorized_result(
            credential,
        )?))
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
                "夸克官方授权不存在，请重新连接",
            )
        })?;
        if let Some(bundle) = parse_credential_bundle(stored.as_str()) {
            let QuarkCredentialBundle {
                official,
                legacy_cookie,
            } = bundle;
            if let Some(official) = official {
                let legacy_session = if legacy_cookie.is_some() {
                    Some(
                        self.legacy_factory
                            .connect(
                                account,
                                Arc::new(BundledLegacyCredentialAccess {
                                    parent: credentials.clone(),
                                }),
                            )
                            .await?,
                    )
                } else {
                    None
                };
                return self
                    .connect_official(account, credentials, official, legacy_session)
                    .await;
            }
            if legacy_cookie.is_some() {
                return self
                    .legacy_factory
                    .connect(
                        account,
                        Arc::new(BundledLegacyCredentialAccess {
                            parent: credentials.clone(),
                        }),
                    )
                    .await;
            }
        }
        if parse_credential(stored.as_str()).is_err() {
            if let Ok(session) = self
                .legacy_factory
                .connect(account, credentials.clone())
                .await
            {
                return Ok(session);
            }
        }
        let official = parse_credential(stored.as_str())?;
        self.connect_official(account, credentials, official, None)
            .await
    }
}

impl QuarkDriveFactory {
    async fn connect_official(
        &self,
        account: &StorageProviderAccount,
        credentials: Arc<dyn ProviderCredentialAccess>,
        _official: QuarkCredential,
        legacy_session: Option<Arc<dyn ProviderSession>>,
    ) -> ProviderResult<Arc<dyn ProviderSession>> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| invalid_response("夸克会话注册表不可用"))?;
        if let Some(session) = sessions.get(&account.id).and_then(Weak::upgrade) {
            return Ok(session);
        }
        let session = Arc::new(QuarkDriveSession {
            client: self.client.clone(),
            credentials,
            legacy_session,
            refresh_lock: Mutex::new(()),
            uploads: Mutex::new(HashMap::new()),
        });
        sessions.insert(account.id.clone(), Arc::downgrade(&session));
        Ok(session)
    }
}

struct QuarkDriveSession {
    client: reqwest::Client,
    credentials: Arc<dyn ProviderCredentialAccess>,
    legacy_session: Option<Arc<dyn ProviderSession>>,
    refresh_lock: Mutex<()>,
    uploads: Mutex<HashMap<String, QuarkUploadState>>,
}

struct QuarkUploadState {
    task_id: String,
    part_size: u64,
    upload_urls: HashMap<u32, UploadUrl>,
    common_headers: HeaderMap,
    next_offset: u64,
    total_size: u64,
    part_etags: HashMap<u32, String>,
    sha1_context: Sha1Context,
    instant_file: Option<RemoteFileItem>,
}

#[derive(Clone)]
struct UploadUrl {
    url: String,
    authorization: Option<String>,
}

#[async_trait]
impl FileSourceProvider for QuarkDriveSession {
    async fn list_files(&self, _request: ListFilesRequest) -> ProviderResult<RemoteFilePage> {
        Err(ProviderError::unsupported(
            "official Quark Drive folder browsing",
        ))
    }

    async fn search_files(&self, request: SearchFilesRequest) -> ProviderResult<RemoteFilePage> {
        let request = request.normalized();
        request.validate()?;
        let response = self.api(Method::POST, "/open/v1/file/search", vec![], Some(json!({
            "search_type": "mix", "keyword": request.query, "size": request.page_size,
            "page": request.page_token.as_deref().and_then(|v| v.parse::<u64>().ok()).unwrap_or(1)
        }))).await?;
        let data = response_data(&response)?;
        let list = data
            .get("file_list")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_response("夸克搜索结果格式无效"))?;
        let items = list
            .iter()
            .map(|item| remote_file(item, None))
            .collect::<ProviderResult<Vec<_>>>()?;
        let page = request
            .page_token
            .as_deref()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);
        Ok(RemoteFilePage {
            items,
            next_page_token: (list.len() >= request.page_size).then(|| (page + 1).to_string()),
        })
    }

    async fn get_file(&self, file_id: &str) -> ProviderResult<RemoteFileItem> {
        validate_id(file_id)?;
        let response = self
            .api(
                Method::GET,
                "/open/v1/file/info",
                vec![("fid".into(), file_id.into())],
                None,
            )
            .await?;
        remote_file(response_data(&response)?, None)
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
            .is_some_and(|(a, b)| a != b)
        {
            return Err(ProviderError::new(
                ProviderErrorCategory::Conflict,
                "夸克网盘文件在下载前发生了变化",
            ));
        }
        let response = self
            .api_without_device_params(
                Method::POST,
                "/open/v1/file/get_download_url",
                vec![],
                Some(json!({"fid": request.file_id})),
            )
            .await?;
        let url = string_value(response_data(&response)?, &["download_url"])
            .ok_or_else(|| invalid_response("夸克官方接口未返回下载地址"))?;
        let mut headers = self.download_headers().await?;
        if let Some(value) = request.range_start {
            headers.insert(
                RANGE,
                HeaderValue::from_str(&format!(
                    "bytes={}-{}",
                    value,
                    request
                        .range_end_inclusive
                        .map(|v| v.to_string())
                        .unwrap_or_default()
                ))
                .map_err(|_| invalid_request("下载范围无效"))?,
            );
        }
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(network_error)?;
        if request.range_start.is_some() && response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(invalid_response("夸克下载地址未响应 Range 请求"));
        }
        if !response.status().is_success() {
            return Err(status_error_with_retry_after(
                response.status(),
                "夸克下载请求失败",
                response.headers().get(RETRY_AFTER),
            ));
        }
        response_stream(response)
    }
}

#[async_trait]
impl QuotaProvider for QuarkDriveSession {
    async fn quota(&self) -> ProviderResult<ProviderQuota> {
        let response = self
            .api(Method::GET, "/open/v1/user/get_vip_info", vec![], None)
            .await?;
        let data = response_data(&response)?;
        Ok(ProviderQuota {
            used_bytes: number_value(data, &["used", "use_capacity"]),
            total_bytes: number_value(data, &["capacity", "total_capacity"]),
            trashed_bytes: None,
            checked_at: now_epoch().to_string(),
        })
    }
}

#[async_trait]
impl FileManagementProvider for QuarkDriveSession {
    async fn create_folder(
        &self,
        parent_id: Option<String>,
        name: String,
    ) -> ProviderResult<RemoteFileItem> {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
            return Err(invalid_request("夸克文件夹名称无效"));
        }
        let parent_id = quark_parent_id(parent_id.as_deref()).to_string();
        validate_id(&parent_id)?;
        let response = self
            .api(
                Method::POST,
                "/open/v1/dir",
                vec![],
                Some(json!({
                    "pdir_fid": parent_id,
                    "dir_path": name,
                })),
            )
            .await?;
        let data = response_data(&response)?;
        let mut folder = remote_file(data, Some(&parent_id))?;
        folder.name = string_value(data, &["file_name", "name"]).unwrap_or_else(|| name.clone());
        folder.kind = RemoteFileKind::Folder;
        folder.downloadable = false;
        Ok(folder)
    }

    async fn trash_files(&self, _file_ids: Vec<String>) -> ProviderResult<()> {
        Err(ProviderError::unsupported(
            "official Quark Drive permanent or trash deletion",
        ))
    }

    async fn move_files(
        &self,
        file_ids: Vec<String>,
        target_folder_id: Option<String>,
    ) -> ProviderResult<()> {
        if file_ids.is_empty() || file_ids.len() > 100 {
            return Err(invalid_request("夸克一次最多移动 100 个项目"));
        }
        let target = target_folder_id.unwrap_or_else(|| "0".into());
        let response = self
            .api(
                Method::POST,
                "/open/v1/file/move",
                vec![],
                Some(json!({"fid_list": file_ids, "to_pdir_fid": target, "action_type": 1})),
            )
            .await?;
        let _ = response_data(&response)?;
        Ok(())
    }
}

#[async_trait]
impl FileShareProvider for QuarkDriveSession {
    async fn create_share(&self, request: CreateShareRequest) -> ProviderResult<CreateShareResult> {
        if request.file_ids.is_empty() || request.file_ids.len() > 100 {
            return Err(invalid_request("夸克一次最多分享 100 个项目"));
        }
        if request.expires_at.is_some() {
            return Err(ProviderError::unsupported(
                "夸克分享有效期需要使用官方 expired_type，通用接口暂不支持日期映射",
            ));
        }
        let mut body =
            json!({"fid_list": request.file_ids, "title": request.title.unwrap_or_default()});
        if let Some(password) = request.password {
            body["passcode"] = json!(password);
        }
        let response = self
            .api(Method::POST, "/agent/v1/share/create", vec![], Some(body))
            .await?;
        let data = response_data(&response)?;
        let url = string_value(data, &["share_url"])
            .ok_or_else(|| invalid_response("夸克未返回分享链接"))?;
        Ok(CreateShareResult {
            links: vec![SharedFileLink {
                file_id: string_value(data, &["fid", "share_id"]).unwrap_or_default(),
                url,
                password: string_value(data, &["passcode"]),
                expires_at: None,
            }],
        })
    }
}

#[async_trait]
impl SharedFileImportProvider for QuarkDriveSession {
    async fn import_shared_files(
        &self,
        request: ImportSharedFilesRequest,
    ) -> ProviderResult<ImportSharedFilesResult> {
        let (pwd_id, embedded_password) = parse_quark_share_url(&request.share_url)?;
        let password = request.password.or(embedded_password);
        let selected = request.file_ids.unwrap_or_default();
        if request.save_all && !selected.is_empty() {
            return Err(invalid_request("夸克转存不能同时指定 save_all 和 file_ids"));
        }
        let detail = self.api(Method::POST, "/open/v1/share/detail", vec![], Some(json!({"pwd_id": pwd_id, "page": 1, "size": 200, "force": 0, "passcode": password}))).await?;
        let detail_data = response_data(&detail)?;
        let stoken = string_value(
            detail_data.get("token_info").unwrap_or(detail_data),
            &["stoken"],
        )
        .ok_or_else(|| invalid_response("夸克分享详情未返回 stoken"))?;
        let save_all = request.save_all || selected.is_empty();
        let list = detail_data
            .get("detail_info")
            .and_then(|value| value.get("list"))
            .and_then(Value::as_array)
            .map_or(&[][..], |value| value);
        let fid_tokens = if save_all {
            None
        } else {
            let token_by_fid = list
                .iter()
                .filter_map(|item| {
                    Some((
                        string_value(item, &["fid"])?,
                        string_value(item, &["share_fid_token"])?,
                    ))
                })
                .collect::<HashMap<_, _>>();
            let tokens = selected
                .iter()
                .map(|fid| token_by_fid.get(fid).cloned())
                .collect::<Option<Vec<_>>>();
            tokens
                .ok_or_else(|| invalid_request("指定的夸克分享文件不在当前分享详情中"))?
                .into()
        };
        let mut body = json!({"pwd_id": pwd_id, "stoken": stoken, "save_all": save_all});
        if !save_all {
            body["fid_list"] = json!(selected);
        }
        if let Some(folder_id) = request.target_folder_id {
            body["to_pdir_fid"] = json!(folder_id);
        }
        if let Some(tokens) = fid_tokens {
            body["fid_token_list"] = json!(tokens);
        }
        let response = self
            .api(Method::POST, "/open/v1/share/saveas", vec![], Some(body))
            .await?;
        let data = response_data(&response)?;
        let task_id = string_value(data, &["task_id"])
            .ok_or_else(|| invalid_response("夸克转存接口未返回 task_id"))?;
        let task = self.wait_for_task(&task_id).await?;
        let completed = number_value(&task, &["status"]).is_some_and(|status| status == 2);
        if !completed {
            return Err(ProviderError::new(
                ProviderErrorCategory::RemoteUnavailable,
                "夸克转存任务未成功完成",
            ));
        }
        Ok(ImportSharedFilesResult {
            task_id: Some(task_id),
            files: Vec::new(),
            completed,
        })
    }
}

impl ProviderSession for QuarkDriveSession {
    fn file_source(&self) -> Option<&dyn FileSourceProvider> {
        self.legacy_session
            .as_deref()
            .and_then(ProviderSession::file_source)
            .or(Some(self))
    }

    fn media_playback(&self) -> Option<&dyn MediaPlaybackProvider> {
        self.legacy_session
            .as_deref()
            .and_then(ProviderSession::media_playback)
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
    fn file_sharing(&self) -> Option<&dyn FileShareProvider> {
        Some(self)
    }
    fn shared_file_import(&self) -> Option<&dyn SharedFileImportProvider> {
        Some(self)
    }
}

#[async_trait]
impl FileUploadProvider for QuarkDriveSession {
    async fn begin_file_upload(
        &self,
        request: BeginFileUploadRequest,
    ) -> ProviderResult<FileUploadSession> {
        let md5 = request
            .content_hashes
            .get(&ContentHashAlgorithm::Md5)
            .cloned()
            .unwrap_or_default();
        let sha1 = request
            .content_hashes
            .get(&ContentHashAlgorithm::Sha1)
            .cloned()
            .unwrap_or_default();
        if md5.len() != 32 || sha1.len() != 40 {
            return Err(invalid_request("夸克官方上传需要 MD5 和 SHA1"));
        }
        let parent_id = quark_parent_id(request.parent_id.as_deref());
        let response = self
            .api(
                Method::POST,
                "/open/v1/file/upload_pre",
                vec![],
                Some(json!({
                    "file_name": request.name, "size": request.size, "sha1": sha1, "md5": md5,
                    "pdir_fid": parent_id, "format_type": request.media_type,
                    "parallel_upload": true, "hash_update": false,
                    "part_info_list": [{
                        "part_number": 1,
                        "part_size": request.size,
                        "parallel_sha1_ctx": Sha1Context::default().parallel_context(0)
                    }]
                })),
            )
            .await?;
        let data = response_data(&response)?;
        if bool_value(data, &["finish"]).unwrap_or(false) {
            let fid = string_value(data, &["fid"])
                .ok_or_else(|| invalid_response("夸克秒传响应未返回 fid"))?;
            let file = self.get_file(&fid).await?;
            let session_id = format!("quark-upload-{}", uuid::Uuid::new_v4());
            self.uploads.lock().await.insert(
                session_id.clone(),
                QuarkUploadState {
                    task_id: String::new(),
                    part_size: request.chunk_size.max(1),
                    upload_urls: HashMap::new(),
                    common_headers: HeaderMap::new(),
                    next_offset: 0,
                    total_size: request.size,
                    part_etags: HashMap::new(),
                    sha1_context: Sha1Context::default(),
                    instant_file: Some(file),
                },
            );
            return Ok(FileUploadSession {
                session_id,
                next_offset: 0,
                chunk_size: request.chunk_size.max(1),
                expires_at: None,
            });
        }
        let task_id = string_value(data, &["task_id"])
            .ok_or_else(|| invalid_response("夸克预上传未返回 task_id"))?;
        let part_size = number_value(data, &["part_size"])
            .or_else(|| {
                response
                    .get("metadata")
                    .and_then(|metadata| number_value(metadata, &["part_size"]))
            })
            .unwrap_or(request.chunk_size)
            .max(1);
        let upload_urls = match data.get("upload_urls") {
            Some(_) => parse_upload_urls(data)?,
            None => HashMap::new(),
        };
        let session_id = format!("quark-upload-{}", uuid::Uuid::new_v4());
        let common_headers = parse_headers(data.get("common_headers"));
        self.uploads.lock().await.insert(
            session_id.clone(),
            QuarkUploadState {
                task_id,
                part_size,
                upload_urls,
                common_headers,
                next_offset: 0,
                total_size: request.size,
                part_etags: HashMap::new(),
                sha1_context: Sha1Context::default(),
                instant_file: None,
            },
        );
        Ok(FileUploadSession {
            session_id,
            next_offset: 0,
            chunk_size: part_size,
            expires_at: None,
        })
    }

    async fn upload_file_chunk(
        &self,
        request: UploadFileChunkRequest,
    ) -> ProviderResult<UploadedFileChunk> {
        let (part_size, instant_upload) = {
            let uploads = self.uploads.lock().await;
            let state = uploads
                .get(&request.session_id)
                .ok_or_else(|| invalid_request("夸克上传会话不存在或已过期"))?;
            (state.part_size, state.instant_file.is_some())
        };
        let part_number = (request.offset / part_size) as u32 + 1;
        let url = if instant_upload {
            None
        } else {
            Some(
                self.ensure_upload_url(&request.session_id, part_number)
                    .await?,
            )
        };
        let mut uploads = self.uploads.lock().await;
        let state = uploads
            .get_mut(&request.session_id)
            .ok_or_else(|| invalid_request("夸克上传会话不存在或已过期"))?;
        if request.offset != state.next_offset || request.total_size != state.total_size {
            return Err(invalid_request("夸克上传偏移无效"));
        }
        if let Some(file) = state.instant_file.clone() {
            state.next_offset = state.next_offset.saturating_add(request.bytes.len() as u64);
            if state.next_offset != state.total_size {
                return Ok(UploadedFileChunk {
                    next_offset: state.next_offset,
                    complete: false,
                    file: None,
                });
            }
            let total_size = state.total_size;
            uploads.remove(&request.session_id);
            return Ok(UploadedFileChunk {
                next_offset: total_size,
                complete: true,
                file: Some(file),
            });
        }
        let url = url.ok_or_else(|| invalid_response("夸克上传会话缺少分片地址"))?;
        let content_length = HeaderValue::from_str(&request.bytes.len().to_string())
            .map_err(|_| invalid_request("夸克上传分片长度无效"))?;
        let mut upload = self
            .client
            .put(url.url)
            .headers(state.common_headers.clone())
            .header(CONTENT_LENGTH, content_length);
        if let Some(signature) = url.authorization {
            upload = upload.header("authorization", signature);
        }
        let response = send_direct_upload_with_retry(upload, &request.bytes).await?;
        if !response.status().is_success() {
            return Err(status_error_with_retry_after(
                response.status(),
                "夸克分片上传失败",
                response.headers().get(RETRY_AFTER),
            ));
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| invalid_response("夸克分片上传响应缺少 ETag"))?;
        state.part_etags.insert(part_number, etag);
        state.sha1_context.update(&request.bytes);
        state.next_offset = state.next_offset.saturating_add(request.bytes.len() as u64);
        if state.next_offset < state.total_size {
            return Ok(UploadedFileChunk {
                next_offset: state.next_offset,
                complete: false,
                file: None,
            });
        }
        let parts = (1..=part_number).map(|part| {
            json!({"part_number": part, "etag": state.part_etags.get(&part).cloned().unwrap_or_default()})
        }).collect::<Vec<_>>();
        let task_id = state.task_id.clone();
        let total_size = state.total_size;
        let finish = self
            .api(
                Method::POST,
                "/open/v1/file/upload_finish",
                vec![],
                Some(json!({"task_id": task_id, "part_info_list": parts})),
            )
            .await?;
        let data = response_data(&finish)?;
        if !bool_value(data, &["finish"]).unwrap_or(false) {
            return Err(invalid_response("夸克上传完成接口未确认 finish"));
        }
        let fid = string_value(data, &["fid"])
            .ok_or_else(|| invalid_response("夸克上传完成接口未返回 fid"))?;
        let file = self.get_file(&fid).await?;
        uploads.remove(&request.session_id);
        Ok(UploadedFileChunk {
            next_offset: total_size,
            complete: true,
            file: Some(file),
        })
    }

    async fn abort_file_upload(&self, session_id: &str) -> ProviderResult<()> {
        self.uploads.lock().await.remove(session_id);
        Ok(())
    }
}

impl QuarkDriveSession {
    async fn upload_part_size(&self, session_id: &str) -> ProviderResult<u64> {
        self.uploads
            .lock()
            .await
            .get(session_id)
            .map(|state| state.part_size)
            .ok_or_else(|| invalid_request("夸克上传会话不存在或已过期"))
    }

    async fn ensure_upload_url(
        &self,
        session_id: &str,
        part_number: u32,
    ) -> ProviderResult<UploadUrl> {
        if let Some(url) = self
            .uploads
            .lock()
            .await
            .get(session_id)
            .and_then(|state| state.upload_urls.get(&part_number).cloned())
        {
            return Ok(url);
        }
        let (task_id, part_size, total_size, part_offset, sha1_context) = {
            let uploads = self.uploads.lock().await;
            let state = uploads
                .get(session_id)
                .ok_or_else(|| invalid_request("夸克上传会话不存在或已过期"))?;
            (
                state.task_id.clone(),
                state.part_size,
                state.total_size,
                state.next_offset,
                state.sha1_context.clone(),
            )
        };
        let remaining = total_size.saturating_sub((u64::from(part_number) - 1) * part_size);
        let mut part_info = json!({
            "part_number": part_number,
            "part_size": remaining.min(part_size),
        });
        if part_number > 1 {
            part_info["parallel_sha1_ctx"] = sha1_context.parallel_context(part_offset);
        }
        let response = self
            .api(
                Method::POST,
                "/open/v1/file/get_upload_urls",
                vec![],
                Some(json!({"task_id": task_id, "part_info_list": [part_info]})),
            )
            .await?;
        let data = response_data(&response)?;
        let urls = parse_upload_urls(data)?;
        let url = urls
            .get(&part_number)
            .cloned()
            .ok_or_else(|| invalid_response("夸克官方接口未返回当前分片地址"))?;
        let mut uploads = self.uploads.lock().await;
        let state = uploads
            .get_mut(session_id)
            .ok_or_else(|| invalid_request("夸克上传会话不存在或已过期"))?;
        state.upload_urls.extend(urls);
        let headers = parse_headers(data.get("common_headers"));
        if !headers.is_empty() {
            state.common_headers = headers;
        }
        Ok(url)
    }

    async fn api(
        &self,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> ProviderResult<Value> {
        self.api_with_options(method, path, query, body, true).await
    }

    async fn api_without_device_params(
        &self,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> ProviderResult<Value> {
        self.api_with_options(method, path, query, body, false)
            .await
    }

    async fn api_with_options(
        &self,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
        include_device_params: bool,
    ) -> ProviderResult<Value> {
        let mut retried = false;
        loop {
            let credential = self.credential(false).await?;
            let mut query = query.clone();
            query.push(("req_id".into(), request_id()));
            query.push(("access_token".into(), credential.access_token.clone()));
            if include_device_params {
                query.push(("device_id".into(), credential.device_id.clone()));
                query.push(("platform".into(), DEFAULT_PLATFORM.into()));
            }
            let response =
                signed_request(&self.client, method.clone(), path, query, body.clone()).await;
            match response {
                Ok(value) => return Ok(value),
                Err(error)
                    if error.category == ProviderErrorCategory::Authentication && !retried =>
                {
                    self.credential(true).await?;
                    retried = true;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn credential(&self, force_refresh: bool) -> ProviderResult<QuarkCredential> {
        let _guard = self.refresh_lock.lock().await;
        let stored = self.credentials.load().await?.ok_or_else(|| {
            ProviderError::new(ProviderErrorCategory::Authentication, "夸克官方授权不存在")
        })?;
        let mut credential = parse_official_credential(stored.as_str())?;
        if force_refresh || credential.expires_at <= now_epoch() + 60 {
            let refresh = credential.refresh_token.clone().ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorCategory::Authentication,
                    "夸克授权已过期，请重新授权",
                )
            })?;
            let response = signed_request(
                &self.client,
                Method::POST,
                "/agent/v1/oauth/access_token/rotate",
                vec![("req_id".into(), request_id())],
                Some(json!({"refresh_token": refresh, "device_id": credential.device_id})),
            )
            .await?;
            let data = response_data(&response)?;
            credential.access_token = string_value(data, &["access_token"])
                .ok_or_else(|| invalid_response("夸克刷新接口未返回 access_token"))?;
            credential.refresh_token =
                string_value(data, &["refresh_token"]).or(credential.refresh_token);
            credential.token_type =
                string_value(data, &["token_type"]).unwrap_or(credential.token_type);
            credential.expires_at = credential_expiry(data);
            let refreshed = serde_json::to_string(&credential)
                .map_err(|_| invalid_response("夸克授权编码失败"))?;
            let stored_value = if let Some(mut bundle) = parse_credential_bundle(stored.as_str()) {
                bundle.official = Some(credential.clone());
                serde_json::to_string(&bundle)
                    .map_err(|_| invalid_response("夸克多凭证编码失败"))?
            } else {
                refreshed
            };
            self.credentials.store(Zeroizing::new(stored_value)).await?;
        }
        Ok(credential)
    }

    async fn download_headers(&self) -> ProviderResult<HeaderMap> {
        let credential = self.credential(false).await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!(
                "x_pan_client_id={CLIENT_ID};x_pan_access_token={}",
                credential.access_token
            ))
            .map_err(|_| invalid_request("夸克下载凭证无效"))?,
        );
        Ok(headers)
    }

    async fn wait_for_task(&self, task_id: &str) -> ProviderResult<Value> {
        for _ in 0..900 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let response = self
                .api(
                    Method::POST,
                    "/open/v1/task/query",
                    vec![],
                    Some(json!({"task_id": task_id})),
                )
                .await?;
            let data = response_data(&response)?;
            let status = number_value(data, &["status"]);
            if matches!(status, Some(2..=4)) {
                return Ok(data.clone());
            }
        }
        Err(ProviderError::new(
            ProviderErrorCategory::RemoteUnavailable,
            "夸克转存任务轮询超时",
        ))
    }
}

async fn exchange_agent_auth_code(
    client: &reqwest::Client,
    code: &str,
) -> ProviderResult<AgentAuthExchange> {
    let response = signed_request(
        client,
        Method::GET,
        "/agent/v1/oauth/agent_auth_code",
        vec![
            ("req_id".into(), request_id()),
            ("agent_auth_code".into(), code.into()),
        ],
        None,
    )
    .await?;
    let data = response_data(&response)?;
    Ok(AgentAuthExchange {
        status: string_value(data, &["status"]),
        access_token: string_value(data, &["access_token"]),
        refresh_token: string_value(data, &["refresh_token"]),
        device_id: string_value(data, &["device_id"]),
        user_id: string_value(data, &["user_id"]),
        token_type: string_value(data, &["token_type"]),
        expires_at: credential_expiry(data),
    })
}

fn existing_credentials(input: &Value) -> Vec<QuarkCredential> {
    input
        .get("existing_credentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|value| {
            parse_credential_bundle(value)
                .and_then(|bundle| bundle.official)
                .or_else(|| serde_json::from_str(value).ok())
        })
        .filter(|credential: &QuarkCredential| {
            !credential.access_token.is_empty() && !credential.user_id.is_empty()
        })
        .collect()
}

fn build_authorize_url(
    raw_url: &str,
    server_device_id: Option<&str>,
    client_device_id: &str,
) -> ProviderResult<String> {
    let mut url = Url::parse(raw_url).map_err(|_| invalid_response("夸克官方授权地址无效"))?;
    let mut params = url.query_pairs().into_owned().collect::<Vec<_>>();
    let set_param = |params: &mut Vec<(String, String)>, key: &str, value: &str| {
        params.retain(|(name, _)| name != key);
        params.push((key.into(), value.into()));
    };
    let set_param_if_absent = |params: &mut Vec<(String, String)>, key: &str, value: &str| {
        if !params.iter().any(|(name, _)| name == key) {
            params.push((key.into(), value.into()));
        }
    };
    set_param(&mut params, "client_id", CLIENT_ID);
    set_param(&mut params, "scope", AUTH_SCOPE);
    set_param(&mut params, "redirect_uri", "");
    if let Some(device_id) = server_device_id.filter(|value| !value.is_empty()) {
        set_param_if_absent(&mut params, "device_id", device_id);
    }
    set_param_if_absent(&mut params, "client_device_id", client_device_id);
    set_param_if_absent(&mut params, "device_name", "Agnes Agent");
    set_param_if_absent(&mut params, "agent_id", AGENT_ID);
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in params {
            query.append_pair(&key, &value);
        }
    }
    Ok(url.to_string())
}

fn credential_from_exchange(
    exchange: AgentAuthExchange,
    existing: &[QuarkCredential],
) -> ProviderResult<QuarkCredential> {
    if exchange.status.as_deref() == Some("expired") {
        return Err(ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克授权码已过期，请重新打开授权页并立即完成授权",
        ));
    }
    if exchange.status.as_deref() == Some("second_confirmed") {
        let user_id = exchange.user_id.ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克二次确认响应未返回 user_id",
            )
        })?;
        return existing
            .iter()
            .find(|credential| credential.user_id == user_id)
            .cloned()
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorCategory::Authentication,
                    "夸克授权已二次确认，但本机没有该账号的旧 access_token，请先在夸克网盘中解除此 Agent 授权后重新授权",
                )
            });
    }
    let access_token = exchange.access_token.ok_or_else(|| {
        ProviderError::new(
            ProviderErrorCategory::Authentication,
            format!(
                "夸克授权码未返回 access_token{}",
                exchange
                    .status
                    .as_deref()
                    .map(|status| format!("（状态：{status}）"))
                    .unwrap_or_default()
            ),
        )
    })?;
    let user_id = exchange
        .user_id
        .ok_or_else(|| invalid_response("夸克授权未返回 user_id"))?;
    Ok(QuarkCredential {
        access_token,
        refresh_token: exchange.refresh_token,
        device_id: exchange
            .device_id
            .unwrap_or_else(|| DEFAULT_DEVICE_ID.into()),
        user_id,
        token_type: exchange.token_type.unwrap_or_else(default_token_type),
        expires_at: exchange.expires_at,
    })
}

fn credential_expiry(value: &Value) -> u64 {
    let now = now_epoch();
    if let Some(mut expires_at) = number_value(
        value,
        &["access_token_expires_at", "access_token_expired_at"],
    ) {
        if expires_at > 100_000_000_000 {
            expires_at /= 1000;
        }
        return expires_at;
    }
    now + number_value(value, &["expires_in"]).unwrap_or(3600)
}

fn authorized_result(credential: QuarkCredential) -> ProviderResult<ProviderAuthorizationResult> {
    let nickname = credential.user_id.clone();
    Ok(ProviderAuthorizationResult {
        account: StorageProviderAccount {
            id: format!("quark-{}", short_hash(credential.user_id.as_bytes())),
            provider_id: PROVIDER_ID.into(),
            display_name: format!("夸克网盘 - {}", truncate(&nickname, 80)),
            account_subject: Some(credential.user_id.clone()),
            config: json!({"api_base": OPEN_API, "official_api": true, "credential_kind": "oauth_agent"}),
        },
        credential: Zeroizing::new(
            serde_json::to_string(&credential).map_err(|_| invalid_response("夸克授权编码失败"))?,
        ),
    })
}

async fn signed_request(
    client: &reqwest::Client,
    method: Method,
    path: &str,
    query: Vec<(String, String)>,
    body: Option<Value>,
) -> ProviderResult<Value> {
    let timestamp = now_millis().to_string();
    let signature = hex_encode(&Sha256::digest(
        format!(
            "{}&{}&{}&{}",
            method.as_str().to_uppercase(),
            path,
            timestamp,
            SIGN_KEY
        )
        .as_bytes(),
    ));
    let mut headers = HeaderMap::new();
    headers.insert("x-pan-client-id", HeaderValue::from_static(CLIENT_ID));
    headers.insert(
        "x-pan-tm",
        HeaderValue::from_str(&timestamp).map_err(|_| invalid_request("夸克请求时间戳无效"))?,
    );
    headers.insert(
        "x-pan-token",
        HeaderValue::from_str(&signature).map_err(|_| invalid_request("夸克请求签名无效"))?,
    );
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("accept", HeaderValue::from_static("application/json"));
    let mut request = client
        .request(method, format!("{OPEN_API}{path}"))
        .headers(headers)
        .query(&query);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(network_error)?;
    let status = response.status();
    let retry_after = response.headers().get(RETRY_AFTER).cloned();
    let value: Value = response
        .json()
        .await
        .map_err(|_| invalid_response("夸克官方接口返回非 JSON"))?;
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克官方授权已失效",
        ));
    }
    if !status.is_success() {
        let detail = string_value(&value, &["error_info", "errorInfo", "message", "msg"]);
        let message = detail
            .map(|detail| format!("夸克官方接口请求失败: {detail}"))
            .unwrap_or_else(|| "夸克官方接口请求失败".into());
        return Err(status_error_with_retry_after(
            status,
            &format!("{path}: {message}"),
            retry_after.as_ref(),
        ));
    }
    if value
        .get("status")
        .and_then(Value::as_i64)
        .is_some_and(|status| status != 0)
    {
        let message = string_value(&value, &["error_info", "errorInfo", "agent_msg"])
            .unwrap_or_else(|| "夸克官方接口请求失败".into());
        let category = if looks_like_authentication_error(&message) {
            ProviderErrorCategory::Authentication
        } else if looks_like_rate_limit_error(&message) {
            ProviderErrorCategory::RateLimit
        } else {
            ProviderErrorCategory::RemoteUnavailable
        };
        let mut error = ProviderError::new(category, format!("{path}: {message}"));
        if let Some(seconds) = number_value(&value, &["retry_after", "retry_after_seconds"]) {
            error = error.with_retry_after(seconds);
        }
        return Err(error);
    }
    Ok(value)
}

fn looks_like_authentication_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "access_token",
        "access token",
        "refresh_token",
        "refresh token",
        "token expired",
        "token invalid",
        "unauthorized",
        "授权",
        "登录",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn looks_like_rate_limit_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    ["rate", "limit", "too many", "频繁", "限流", "请求过快"]
        .iter()
        .any(|needle| message.contains(needle))
}

fn response_data(value: &Value) -> ProviderResult<&Value> {
    value
        .get("data")
        .ok_or_else(|| invalid_response("夸克官方响应缺少 data"))
}

fn parse_credential(value: &str) -> ProviderResult<QuarkCredential> {
    let credential: QuarkCredential = serde_json::from_str(value).map_err(|_| {
        ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克官方授权凭证格式无效",
        )
    })?;
    if credential.access_token.is_empty() || credential.user_id.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克官方授权凭证不完整",
        ));
    }
    Ok(credential)
}

fn parse_credential_bundle(value: &str) -> Option<QuarkCredentialBundle> {
    let parsed: Value = serde_json::from_str(value).ok()?;
    let object = parsed.as_object()?;
    if !object.contains_key("official") && !object.contains_key("legacy_cookie") {
        return None;
    }
    serde_json::from_value(parsed).ok()
}

/// Returns `(has_official, has_legacy_cookie)` for a stored credential.
///
/// The server uses this to decide whether folder browsing is available without
/// exposing the credential format itself.
pub fn credential_capabilities(value: &str) -> (bool, bool) {
    if let Some(bundle) = parse_credential_bundle(value) {
        return (bundle.official.is_some(), bundle.legacy_cookie.is_some());
    }
    if parse_credential(value).is_ok() {
        (true, false)
    } else {
        (false, true)
    }
}

pub fn merge_legacy_cookie(existing: &str, cookie: &str) -> ProviderResult<String> {
    let mut bundle = if let Some(bundle) = parse_credential_bundle(existing) {
        bundle
    } else if let Ok(official) = parse_credential(existing) {
        QuarkCredentialBundle {
            official: Some(official),
            legacy_cookie: None,
        }
    } else {
        QuarkCredentialBundle {
            official: None,
            legacy_cookie: None,
        }
    };
    bundle.legacy_cookie = Some(cookie.to_owned());
    serde_json::to_string(&bundle).map_err(|_| invalid_response("夸克多凭证编码失败"))
}

pub fn merge_official_credential(existing: &str, official: &str) -> ProviderResult<String> {
    let credential = parse_official_credential(official)?;
    let mut bundle = if let Some(bundle) = parse_credential_bundle(existing) {
        bundle
    } else if let Ok(previous_official) = parse_credential(existing) {
        QuarkCredentialBundle {
            official: Some(previous_official),
            legacy_cookie: None,
        }
    } else {
        QuarkCredentialBundle {
            official: None,
            legacy_cookie: Some(existing.to_owned()),
        }
    };
    if bundle
        .official
        .as_ref()
        .is_some_and(|previous| previous.user_id != credential.user_id)
    {
        return Err(ProviderError::new(
            ProviderErrorCategory::Authentication,
            "重新授权的夸克账号与当前账户不一致",
        ));
    }
    bundle.official = Some(credential);
    serde_json::to_string(&bundle).map_err(|_| invalid_response("夸克多凭证编码失败"))
}

fn parse_official_credential(value: &str) -> ProviderResult<QuarkCredential> {
    if let Some(bundle) = parse_credential_bundle(value) {
        return bundle.official.ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCategory::Authentication,
                "夸克官方授权凭证不存在",
            )
        });
    }
    parse_credential(value)
}

fn remote_file(value: &Value, parent_id: Option<&str>) -> ProviderResult<RemoteFileItem> {
    let id = string_value(value, &["fid", "file_id", "id"])
        .ok_or_else(|| invalid_response("夸克文件缺少 fid"))?;
    let name =
        string_value(value, &["file_name", "filename", "name"]).unwrap_or_else(|| id.clone());
    let folder = bool_value(value, &["dir", "is_dir", "is_folder"]).unwrap_or_else(|| {
        matches!(
            string_value(value, &["file_type"]).as_deref(),
            Some("0" | "folder")
        )
    });
    Ok(RemoteFileItem {
        id,
        parent_id: parent_id
            .map(str::to_owned)
            .or_else(|| string_value(value, &["pdir_fid", "parent_id"])),
        name,
        kind: if folder {
            RemoteFileKind::Folder
        } else {
            RemoteFileKind::File
        },
        media_type: string_value(value, &["mime_type", "format_type"]),
        size: number_value(value, &["size", "file_size"]),
        modified_at: string_value(value, &["updated_at", "modified_at"]),
        revision: string_value(value, &["sha1", "md5"]),
        downloadable: !folder,
    })
}

fn parse_upload_urls(value: &Value) -> ProviderResult<HashMap<u32, UploadUrl>> {
    let urls = value
        .get("upload_urls")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response("夸克预上传未返回 upload_urls"))?;
    let mut result = HashMap::new();
    for item in urls {
        let part = number_value(item, &["part_number"])
            .ok_or_else(|| invalid_response("夸克分片编号无效"))? as u32;
        let url = string_value(item, &["upload_url", "url"])
            .ok_or_else(|| invalid_response("夸克分片地址无效"))?;
        let authorization = item
            .get("signature_info")
            .and_then(|value| string_value(value, &["signature"]));
        result.insert(part, UploadUrl { url, authorization });
    }
    if result.is_empty() {
        return Err(invalid_response("夸克预上传未返回有效分片地址"));
    }
    Ok(result)
}

fn parse_headers(value: Option<&Value>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(Value::Object(values)) = value {
        for (name, value) in values {
            if let Some(value) = value.as_str() {
                if let (Ok(name), Ok(value)) =
                    (name.parse::<HeaderName>(), HeaderValue::from_str(value))
                {
                    headers.insert(name, value);
                }
            }
        }
    }
    headers
}

fn parse_quark_share_url(value: &str) -> ProviderResult<(String, Option<String>)> {
    let url = Url::parse(value).map_err(|_| invalid_request("夸克分享链接无效"))?;
    if !matches!(
        url.host_str(),
        Some("pan.quark.cn") | Some("www.pan.quark.cn")
    ) {
        return Err(invalid_request("不是夸克网盘分享链接"));
    }
    let mut segments = url
        .path_segments()
        .ok_or_else(|| invalid_request("夸克分享链接缺少分享 ID"))?;
    if segments.next() != Some("s") {
        return Err(invalid_request("夸克分享链接缺少分享 ID"));
    }
    let id = segments
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_request("夸克分享链接缺少分享 ID"))?;
    let password = url
        .query_pairs()
        .find(|(k, _)| k == "pwd")
        .map(|(_, v)| v.into_owned());
    Ok((id, password))
}

fn string_value(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
    })
}

fn number_value(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    })
}

fn bool_value(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|v| {
            v.as_bool()
                .or_else(|| v.as_i64().map(|n| n != 0))
                .or_else(|| v.as_str().map(|s| s == "1" || s == "true"))
        })
    })
}

fn quark_parent_id(value: Option<&str>) -> &str {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("0")
}

fn validate_id(value: &str) -> ProviderResult<()> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(invalid_request("夸克文件 ID 无效"))
    } else {
        Ok(())
    }
}

fn validate_range(start: Option<u64>, end: Option<u64>) -> ProviderResult<()> {
    if end.is_some() && start.is_none() || start.zip(end).is_some_and(|(a, b)| b < a) {
        Err(invalid_request("下载范围无效"))
    } else {
        Ok(())
    }
}

fn response_stream(response: Response) -> ProviderResult<ProviderByteStream> {
    Ok(Box::pin(response.bytes_stream().map(|chunk| {
        chunk.map(|bytes| bytes.to_vec()).map_err(network_error)
    })))
}

fn status_error(status: StatusCode, message: &str) -> ProviderError {
    status_error_with_retry_after(status, message, None)
}

fn status_error_with_retry_after(
    status: StatusCode,
    message: &str,
    retry_after: Option<&HeaderValue>,
) -> ProviderError {
    let mut error = ProviderError::new(
        if status == StatusCode::TOO_MANY_REQUESTS {
            ProviderErrorCategory::RateLimit
        } else if status.is_server_error() {
            ProviderErrorCategory::RemoteUnavailable
        } else {
            ProviderErrorCategory::Network
        },
        format!("{message} ({})", status.as_u16()),
    );
    if let Some(seconds) = retry_after
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        error = error.with_retry_after(seconds);
    }
    error
}

fn network_error(error: reqwest::Error) -> ProviderError {
    ProviderError::new(
        ProviderErrorCategory::Network,
        format!("夸克网络请求失败: {error}"),
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

fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn short_hash(value: &[u8]) -> String {
    hex_encode(&Sha256::digest(value)[..10])
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCredentialAccess {
        value: Zeroizing<String>,
    }

    #[async_trait]
    impl ProviderCredentialAccess for TestCredentialAccess {
        async fn load(&self) -> ProviderResult<Option<Zeroizing<String>>> {
            Ok(Some(self.value.clone()))
        }

        async fn store(&self, _credential: Zeroizing<String>) -> ProviderResult<()> {
            Ok(())
        }

        async fn delete(&self) -> ProviderResult<()> {
            Ok(())
        }
    }

    fn test_account() -> StorageProviderAccount {
        StorageProviderAccount {
            id: "quark-test".into(),
            provider_id: PROVIDER_ID.into(),
            display_name: "Quark test".into(),
            account_subject: None,
            config: Value::Null,
        }
    }

    #[test]
    fn parses_quark_share_urls_and_embedded_passwords() {
        assert_eq!(
            parse_quark_share_url("https://pan.quark.cn/s/abc123").unwrap(),
            ("abc123".into(), None)
        );
        assert_eq!(
            parse_quark_share_url("https://www.pan.quark.cn/s/abc123?pwd=a%2Bb").unwrap(),
            ("abc123".into(), Some("a+b".into()))
        );
        assert!(parse_quark_share_url("https://pan.quark.cn/abc123").is_err());
        assert!(parse_quark_share_url("https://example.com/s/abc123").is_err());
    }

    #[test]
    fn parses_upload_urls_and_common_headers() {
        let value = json!({
            "upload_urls": [{
                "part_number": 1,
                "upload_url": "https://upload.example/part-1",
                "signature_info": {"signature": "signed"}
            }],
            "common_headers": {"x-test": "value"}
        });
        let urls = parse_upload_urls(&value).unwrap();
        assert_eq!(
            urls.get(&1).and_then(|item| item.authorization.as_deref()),
            Some("signed")
        );
        assert_eq!(
            parse_headers(value.get("common_headers"))
                .get("x-test")
                .and_then(|value| value.to_str().ok()),
            Some("value")
        );
    }

    #[test]
    fn upload_root_uses_quark_root_folder_id() {
        assert_eq!(quark_parent_id(None), "0");
        assert_eq!(quark_parent_id(Some("")), "0");
        assert_eq!(quark_parent_id(Some("folder-1")), "folder-1");
    }

    #[test]
    fn recognizes_quark_folder_file_type() {
        let folder = remote_file(
            &json!({"fid": "folder", "file_name": "docs", "file_type": 0}),
            None,
        )
        .unwrap();
        assert_eq!(folder.kind, RemoteFileKind::Folder);
        assert!(!folder.downloadable);
    }

    #[test]
    fn official_descriptor_exposes_share_and_import_without_folder_browse() {
        let factory = QuarkDriveFactory::new().unwrap();
        let descriptor = factory.descriptor();
        assert!(!descriptor.capabilities.browse_files);
        assert!(descriptor.capabilities.share_files);
        assert!(descriptor.capabilities.import_shared_files);
        assert_eq!(descriptor.auth_kind, ProviderAuthKind::BrowserSession);
        assert_eq!(descriptor.stability, ProviderStability::Official);
    }

    #[test]
    fn preserves_official_absolute_token_expiry() {
        let expiry = now_epoch() + 900;
        assert_eq!(
            credential_expiry(&json!({"access_token_expires_at": expiry})),
            expiry
        );
        assert_eq!(
            credential_expiry(&json!({
                "access_token_expires_at": expiry * 1000
            })),
            expiry
        );
    }

    #[test]
    fn recognizes_token_errors_for_refresh_retry() {
        assert!(looks_like_authentication_error("access token expired"));
        assert!(looks_like_authentication_error("授权已失效"));
        assert!(!looks_like_authentication_error("file not found"));
    }

    #[test]
    fn reuses_existing_token_for_second_confirmation() {
        let credential = QuarkCredential {
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            device_id: "device".into(),
            user_id: "user".into(),
            token_type: "Bearer".into(),
            expires_at: now_epoch() + 3600,
        };
        let exchange = AgentAuthExchange {
            status: Some("second_confirmed".into()),
            access_token: None,
            refresh_token: None,
            device_id: Some("new-device".into()),
            user_id: Some("user".into()),
            token_type: None,
            expires_at: 0,
        };
        let reused = credential_from_exchange(exchange, std::slice::from_ref(&credential)).unwrap();
        assert_eq!(reused.access_token, credential.access_token);
        assert!(credential_from_exchange(
            AgentAuthExchange {
                status: Some("second_confirmed".into()),
                access_token: None,
                refresh_token: None,
                device_id: None,
                user_id: Some("other".into()),
                token_type: None,
                expires_at: 0,
            },
            &[]
        )
        .is_err());
    }

    #[test]
    fn merges_cookie_without_dropping_official_credential() {
        let official = QuarkCredential {
            access_token: "access".into(),
            refresh_token: None,
            device_id: "device".into(),
            user_id: "user".into(),
            token_type: "Bearer".into(),
            expires_at: now_epoch() + 3600,
        };
        let stored = serde_json::to_string(&official).unwrap();
        let merged = merge_legacy_cookie(&stored, "__uid=user; __kps=key").unwrap();
        let bundle = parse_credential_bundle(&merged).unwrap();
        assert_eq!(bundle.official.unwrap().access_token, "access");
        assert_eq!(
            bundle.legacy_cookie.as_deref(),
            Some("__uid=user; __kps=key")
        );
    }

    #[test]
    fn builds_authorize_url_with_skill_parameters() {
        let url = build_authorize_url(
            "https://pan.quark.cn/authorize?foo=bar&device_name=Server%20Name",
            Some("server-device"),
            "client-device",
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        let params = parsed.query_pairs().into_owned().collect::<HashMap<_, _>>();
        assert_eq!(params.get("client_id").map(String::as_str), Some(CLIENT_ID));
        assert_eq!(params.get("scope").map(String::as_str), Some(AUTH_SCOPE));
        assert_eq!(params.get("redirect_uri").map(String::as_str), Some(""));
        assert_eq!(
            params.get("device_id").map(String::as_str),
            Some("server-device")
        );
        assert_eq!(
            params.get("client_device_id").map(String::as_str),
            Some("client-device")
        );
        assert_eq!(
            params.get("device_name").map(String::as_str),
            Some("Server Name")
        );
        assert_eq!(params.get("agent_id").map(String::as_str), Some(AGENT_ID));
        assert_eq!(params.get("foo").map(String::as_str), Some("bar"));
    }

    #[tokio::test]
    async fn legacy_cookie_credentials_fall_back_to_browsable_session() {
        let factory = QuarkDriveFactory::new().unwrap();
        let credentials = Arc::new(TestCredentialAccess {
            value: Zeroizing::new("__uid=u; __kps=k".into()),
        });
        let session = factory.connect(&test_account(), credentials).await.unwrap();

        assert!(session.file_source().is_some());
        assert!(session.file_sharing().is_none());
    }

    #[tokio::test]
    async fn official_credentials_use_official_session() {
        let factory = QuarkDriveFactory::new().unwrap();
        let credentials = Arc::new(TestCredentialAccess {
            value: Zeroizing::new(
                serde_json::to_string(&QuarkCredential {
                    access_token: "access".into(),
                    refresh_token: Some("refresh".into()),
                    device_id: "device".into(),
                    user_id: "user".into(),
                    token_type: "Bearer".into(),
                    expires_at: 0,
                })
                .unwrap(),
            ),
        });
        let session = factory.connect(&test_account(), credentials).await.unwrap();

        assert!(session.file_source().is_some());
        assert!(session.file_sharing().is_some());
        assert!(session.shared_file_import().is_some());
    }
}
