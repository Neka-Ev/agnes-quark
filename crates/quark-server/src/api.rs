//! HTTP JSON API.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures_util::Stream;
use quark_core::domain::{
    ListFilesRequest, ProviderAuthorizationRequest, ProviderError, ProviderErrorCategory,
    RemoteFileKind, SearchFilesRequest, StorageProviderAccount,
};
use quark_core::ports::{
    ProviderAuthorizationResult, ProviderAuthorizationStep, ProviderFactory, ProviderSession,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::db::{AccountRecord, DownloadRow};
use crate::download::{normalize_relative_dir, safe_local_name, DbCredentialAccess};
use crate::error::ApiError;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/config", get(get_config))
        .route("/accounts", get(list_accounts).post(create_account))
        .route("/accounts/challenges", post(begin_challenge))
        .route("/accounts/challenges/{id}", get(poll_challenge))
        .route("/accounts/{id}", delete(delete_account))
        .route("/accounts/{id}/credential", post(supplement_credential))
        .route("/accounts/{id}/quota", get(account_quota))
        .route("/accounts/{id}/files", get(list_files))
        .route("/accounts/{id}/search", get(search_files))
        .route("/accounts/{id}/downloads", post(create_download))
        .route("/downloads", get(list_downloads))
        .route("/downloads/events", get(download_events))
        .route("/downloads/{id}", get(get_download).delete(delete_download))
        .route("/downloads/{id}/cancel", post(cancel_download))
        .route("/downloads/{id}/retry", post(retry_download))
        .fallback(api_not_found)
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state.clone());

    Router::new()
        .nest("/api", api)
        .fallback(crate::web::static_handler)
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Health and configuration
// ---------------------------------------------------------------------------

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": state.started_at.to_rfc3339(),
    }))
}

async fn api_not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "code": "not_found",
                "message": "接口不存在"
            }
        })),
    )
}

async fn get_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "listen": state.config.listen.to_string(),
        "data_dir": state.paths.data_dir.to_string_lossy(),
        "download_root": state.paths.download_root.to_string_lossy(),
        "concurrency": state.paths.concurrency,
        "auth_required": state.paths.token.is_some(),
    }))
}

// ---------------------------------------------------------------------------
// Accounts and authorization
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AccountView {
    id: String,
    provider_id: String,
    display_name: String,
    account_subject: Option<String>,
    config: serde_json::Value,
    credentials: CredentialView,
    capabilities: CapabilityView,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct CredentialView {
    official: bool,
    cookie: bool,
}

#[derive(Serialize)]
struct CapabilityView {
    browse: bool,
    search: bool,
    download: bool,
    folder_download: bool,
}

async fn list_accounts(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let accounts = state.db.list_accounts().await?;
    let views = accounts
        .iter()
        .map(|account| account_view(&state, account))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "accounts": views })))
}

#[derive(Deserialize)]
struct CreateAccountBody {
    cookie: Option<String>,
    official_code: Option<String>,
    display_name: Option<String>,
}

async fn create_account(
    State(state): State<AppState>,
    Json(body): Json<CreateAccountBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = if let Some(cookie) = non_empty(body.cookie) {
        authorize_cookie(&state, &cookie).await?
    } else if let Some(code) = non_empty(body.official_code) {
        state
            .factory
            .authorize(ProviderAuthorizationRequest {
                input: json!({ "agent_auth_code": code }),
            })
            .await?
    } else {
        return Err(ApiError::bad_request("请提供夸克 Cookie 或官方授权码"));
    };

    let view =
        persist_authorized(&state, result.account, result.credential, body.display_name).await?;
    Ok(Json(json!({ "account": view })))
}

#[derive(Deserialize)]
struct ChallengeBody {
    method: Option<String>,
}

async fn begin_challenge(
    State(state): State<AppState>,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let method = body.method.as_deref().unwrap_or("qr");
    let challenge = match method {
        "qr" => {
            state
                .legacy_factory
                .begin_authorization(ProviderAuthorizationRequest {
                    input: json!({ "method": "qr" }),
                })
                .await?
        }
        "official" => {
            state
                .factory
                .begin_authorization(ProviderAuthorizationRequest { input: json!({}) })
                .await?
        }
        other => return Err(ApiError::bad_request(format!("不支持的登录方式：{other}"))),
    };
    Ok(Json(serde_json::to_value(challenge).unwrap_or_default()))
}

async fn poll_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let step = if id.starts_with("quark-qr-") {
        state.legacy_factory.poll_authorization(&id).await
    } else {
        state.factory.poll_authorization(&id).await
    }
    .map_err(challenge_error)?;
    match step {
        ProviderAuthorizationStep::Pending => Ok(Json(json!({ "status": "pending" }))),
        ProviderAuthorizationStep::Authorized(result) => {
            let view = persist_authorized(&state, result.account, result.credential, None).await?;
            Ok(Json(json!({ "status": "authorized", "account": view })))
        }
    }
}

/// Challenge expiry is expected during interactive login. Return `410 Gone`
/// with a dedicated code so the UI can fetch a fresh QR code instead of
/// confusing it with a missing access token or a broken Cookie.
fn challenge_error(error: ProviderError) -> ApiError {
    let expired = matches!(
        error.category,
        ProviderErrorCategory::Authentication | ProviderErrorCategory::NotFound
    ) && (error.message.contains("过期") || error.message.contains("不存在"));
    if expired {
        ApiError::new(StatusCode::GONE, "challenge_expired", error.message)
    } else {
        error.into()
    }
}

#[derive(Deserialize)]
struct SupplementBody {
    cookie: Option<String>,
    official_code: Option<String>,
}

async fn supplement_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SupplementBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let account = state
        .db
        .get_account(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("账户不存在"))?;
    let existing = state.vault.decrypt(&account.credential)?;

    let merged = if let Some(cookie) = non_empty(body.cookie) {
        let authorized = authorize_cookie(&state, &cookie).await?;
        quark_core::merge_legacy_cookie(&existing, authorized.credential.as_str())?
    } else if let Some(code) = non_empty(body.official_code) {
        let authorized = state
            .factory
            .authorize(ProviderAuthorizationRequest {
                input: json!({ "agent_auth_code": code }),
            })
            .await?;
        quark_core::merge_official_credential(&existing, authorized.credential.as_str())?
    } else {
        return Err(ApiError::bad_request("请提供 Cookie 或官方授权码"));
    };

    let cipher = state.vault.encrypt(&merged)?;
    state.db.update_credential(&id, &cipher).await?;
    state.factory.invalidate_account(&id);

    let account = state
        .db
        .get_account(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("账户不存在"))?;
    Ok(Json(json!({ "account": account_view(&state, &account) })))
}

async fn delete_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.factory.invalidate_account(&id);
    state.legacy_factory.invalidate_account(&id);
    state.db.delete_account(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account_quota(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = connect_session(&state, &id).await?;
    let quota = session
        .quota_source()
        .ok_or_else(|| ApiError::bad_request("该账户不支持查询配额"))?
        .quota()
        .await?;
    Ok(Json(serde_json::to_value(quota).unwrap_or_default()))
}

// ---------------------------------------------------------------------------
// File browsing and search
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FilesQuery {
    parent_id: Option<String>,
    page_token: Option<String>,
    page_size: Option<usize>,
}

async fn list_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<FilesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = connect_session(&state, &id).await?;
    let source = session
        .file_source()
        .ok_or_else(|| ApiError::bad_request("该账户不支持浏览文件"))?;
    let page = source
        .list_files(ListFilesRequest {
            parent_id: query.parent_id,
            page_token: query.page_token,
            page_size: query.page_size.unwrap_or(100),
        })
        .await?;
    Ok(Json(serde_json::to_value(page).unwrap_or_default()))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    page_token: Option<String>,
    page_size: Option<usize>,
}

async fn search_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = connect_session(&state, &id).await?;
    let source = session
        .file_source()
        .ok_or_else(|| ApiError::bad_request("该账户不支持搜索文件"))?;
    let page = source
        .search_files(SearchFilesRequest {
            query: query.q,
            page_token: query.page_token,
            page_size: query.page_size.unwrap_or(100),
        })
        .await?;
    Ok(Json(serde_json::to_value(page).unwrap_or_default()))
}

// ---------------------------------------------------------------------------
// Download tasks
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateDownloadBody {
    file_id: Option<String>,
    folder_id: Option<String>,
    relative_dir: Option<String>,
}

async fn create_download(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(body): Json<CreateDownloadBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let file_id = non_empty(body.file_id);
    let folder_id = non_empty(body.folder_id);
    if file_id.is_some() == folder_id.is_some() {
        return Err(ApiError::bad_request(
            "file_id 与 folder_id 必须且只能提供一个",
        ));
    }

    let session = connect_session(&state, &account_id).await?;
    let source = session
        .file_source()
        .ok_or_else(|| ApiError::bad_request("该账户不支持下载文件"))?;
    let base = normalize_relative_dir(body.relative_dir.as_deref().unwrap_or(""))
        .map_err(ApiError::bad_request)?;

    let (kind, remote_id, display_name, relative_dir, total_bytes) =
        if let Some(folder_id) = folder_id {
            let folder = source.get_file(&folder_id).await?;
            if folder.kind != RemoteFileKind::Folder {
                return Err(ApiError::bad_request("folder_id 不是文件夹"));
            }
            let name = safe_local_name(&folder.name, &folder.id);
            let relative = if base.is_empty() {
                name
            } else {
                format!("{base}/{name}")
            };
            ("folder", folder.id, folder.name, relative, None)
        } else {
            let file_id = file_id.expect("validated above");
            let file = source.get_file(&file_id).await?;
            if file.kind == RemoteFileKind::Folder {
                return Err(ApiError::bad_request("file_id 是文件夹，请使用 folder_id"));
            }
            ("file", file.id, file.name, base, file.size)
        };

    let now = Utc::now().to_rfc3339();
    let row = DownloadRow {
        id: Uuid::new_v4().to_string(),
        account_id,
        kind: kind.to_owned(),
        remote_id,
        display_name,
        relative_dir,
        status: "queued".into(),
        total_bytes,
        downloaded_bytes: 0,
        completed_items: 0,
        total_items: None,
        current_file: None,
        error: None,
        created_at: now.clone(),
        updated_at: now,
    };
    state.db.insert_download(&row).await?;
    state.engine.enqueue(row.id.clone());
    Ok(Json(json!({ "download": row })))
}

#[derive(Deserialize)]
struct DownloadsQuery {
    limit: Option<u32>,
}

async fn list_downloads(
    State(state): State<AppState>,
    Query(query): Query<DownloadsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let downloads = state
        .db
        .list_downloads(query.limit.unwrap_or(200).min(1_000))
        .await?;
    Ok(Json(json!({ "downloads": downloads })))
}

async fn get_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let download = state
        .db
        .get_download(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("下载任务不存在"))?;
    Ok(Json(json!({ "download": download })))
}

async fn cancel_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.engine.cancel(&id).await? {
        return Err(ApiError::not_found("下载任务不存在"));
    }
    let download = state.db.get_download(&id).await?;
    Ok(Json(json!({ "download": download })))
}

async fn retry_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let download = state
        .db
        .get_download(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("下载任务不存在"))?;
    if !matches!(download.status.as_str(), "failed" | "cancelled") {
        return Err(ApiError::conflict("只有失败或已取消的任务可以重试"));
    }
    state.db.reset_download_for_retry(&id).await?;
    state.engine.enqueue(id.clone());
    let download = state.db.get_download(&id).await?;
    Ok(Json(json!({ "download": download })))
}

async fn delete_download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let _ = state.engine.cancel(&id).await?;
    state.db.delete_download(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn download_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let db = state.db.clone();
    let stream = futures_util::stream::unfold(0_u64, move |tick| {
        let db = db.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(1_000)).await;
            let rows = db.list_downloads(200).await.unwrap_or_default();
            let data = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_owned());
            let event = Event::default().event("downloads").data(data);
            Some((Ok::<_, Infallible>(event), tick.wrapping_add(1)))
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async fn connect_session(
    state: &AppState,
    account_id: &str,
) -> Result<Arc<dyn ProviderSession>, ApiError> {
    let account = state
        .db
        .get_account(account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账户不存在"))?;
    let access = Arc::new(DbCredentialAccess::new(
        state.db.clone(),
        state.vault.clone(),
        account.id.clone(),
    ));
    let provider_account = StorageProviderAccount {
        id: account.id,
        provider_id: account.provider_id,
        display_name: account.display_name,
        account_subject: account.account_subject,
        config: account.config,
    };
    Ok(state.factory.connect(&provider_account, access).await?)
}

async fn persist_authorized(
    state: &AppState,
    account: StorageProviderAccount,
    credential: zeroize::Zeroizing<String>,
    display_name: Option<String>,
) -> Result<AccountView, ApiError> {
    account.validate()?;
    let cipher = state.vault.encrypt(credential.as_str())?;
    let existing = state.db.get_account(&account.id).await?;
    let created_at = existing
        .as_ref()
        .map(|record| record.created_at.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let display_name = non_empty(display_name)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(account.display_name);
    let record = AccountRecord {
        id: account.id,
        provider_id: account.provider_id,
        display_name,
        account_subject: account.account_subject,
        config: account.config,
        credential: cipher,
        created_at,
        updated_at: Utc::now().to_rfc3339(),
    };
    state.db.upsert_account(&record).await?;
    state.factory.invalidate_account(&record.id);
    Ok(account_view(state, &record))
}

fn account_view(state: &AppState, record: &AccountRecord) -> AccountView {
    let (official, cookie) = state
        .vault
        .decrypt(&record.credential)
        .map(|credential| quark_core::credential_capabilities(&credential))
        .unwrap_or((false, false));
    AccountView {
        id: record.id.clone(),
        provider_id: record.provider_id.clone(),
        display_name: record.display_name.clone(),
        account_subject: record.account_subject.clone(),
        config: record.config.clone(),
        credentials: CredentialView { official, cookie },
        capabilities: CapabilityView {
            browse: cookie,
            search: official || cookie,
            download: official || cookie,
            folder_download: cookie,
        },
        created_at: record.created_at.clone(),
        updated_at: record.updated_at.clone(),
    }
}

async fn authorize_cookie(
    state: &AppState,
    raw: &str,
) -> Result<ProviderAuthorizationResult, ApiError> {
    let cookie =
        normalize_cookie_input(raw).ok_or_else(|| ApiError::bad_request("Cookie 不能为空"))?;
    match state
        .legacy_factory
        .authorize(ProviderAuthorizationRequest {
            input: json!({ "cookie": cookie }),
        })
        .await
    {
        Ok(result) => Ok(result),
        Err(error) => Err(cookie_auth_error(error, &cookie)),
    }
}

/// Accept a raw cookie header value, a full `Cookie: ...` line, a multiline
/// paste (one `name=value` per line), or a JSON cookie export. Control
/// characters are replaced with spaces because the provider rejects them to
/// prevent header injection.
fn normalize_cookie_input(raw: &str) -> Option<String> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let lines = normalized
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut cookie_lines = Vec::new();
    for line in &lines {
        if let Some(prefix) = line.get(..7) {
            if prefix.eq_ignore_ascii_case("cookie:") {
                cookie_lines.push(line[7..].trim());
            }
        }
    }
    let text = if !cookie_lines.is_empty() {
        cookie_lines.join(" ")
    } else if lines.len() > 1
        && lines
            .iter()
            .all(|line| line.contains('=') && !line.starts_with('{') && !line.starts_with('['))
    {
        lines
            .iter()
            .map(|line| line.trim_end_matches(';').trim())
            .collect::<Vec<_>>()
            .join("; ")
    } else {
        normalized.clone()
    };
    let cleaned: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }
    // Cookie values cannot contain raw whitespace; JSON is left untouched.
    if cleaned.starts_with('{') || cleaned.starts_with('[') {
        Some(cleaned.to_owned())
    } else {
        Some(cleaned.split_whitespace().collect::<Vec<_>>().join(" "))
    }
}

fn cookie_names(cookie: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (name, _) in cookie
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.trim(), value))
    {
        if name.is_empty() || names.iter().any(|existing| existing.as_str() == name) {
            continue;
        }
        names.push(name.chars().take(40).collect());
    }
    names
}

fn cookie_auth_error(error: ProviderError, cookie: &str) -> ApiError {
    if error.category != ProviderErrorCategory::Authentication {
        return error.into();
    }

    let names = cookie_names(cookie);
    let mut message = error.message;
    message.push_str(&format!(
        "。收到的 Cookie 字段：{}",
        if names.is_empty() {
            "无".to_owned()
        } else {
            names.join(", ")
        }
    ));

    let required = ["__pus", "__kp", "__kps", "__puus", "__uid"];
    let missing = required
        .iter()
        .copied()
        .filter(|name| !names.iter().any(|present| present == name))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        message.push_str("。请重新登录 pan.quark.cn 后复制最新 Cookie，或直接使用扫码登录");
    } else {
        message.push_str(&format!(
            "。缺少 {}；请确认浏览器处于已登录状态（不是访客），并从任意 drive.quark.cn 请求复制完整 Cookie，或直接使用扫码登录",
            missing.join(", ")
        ));
    }

    ApiError::new(StatusCode::UNAUTHORIZED, "authentication", message)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

// ---------------------------------------------------------------------------
// Token middleware
// ---------------------------------------------------------------------------

async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(expected) = state.paths.token.as_deref() else {
        return next.run(request).await;
    };
    let header_ok = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| token_eq(value.trim(), expected));
    let query_ok = query_token(request.uri().query(), expected);
    if header_ok || query_ok {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": {
                    "code": "unauthorized",
                    "message": "需要访问令牌"
                }
            })),
        )
            .into_response()
    }
}

fn token_eq(candidate: &str, expected: &str) -> bool {
    candidate.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn query_token(query: Option<&str>, expected: &str) -> bool {
    query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "token")
        .map(|(_, value)| percent_decode(value))
        .is_some_and(|value| token_eq(&value, expected))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(decoded) = u8::from_str_radix(hex, 16) {
                    output.push(decoded);
                    index += 3;
                    continue;
                }
                output.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_input_accepts_header_prefix_and_multiline_pastes() {
        assert_eq!(
            normalize_cookie_input("Cookie: __uid=u; __kps=k").as_deref(),
            Some("__uid=u; __kps=k")
        );
        assert_eq!(
            normalize_cookie_input("__uid=u;\n__kps=k\n").as_deref(),
            Some("__uid=u; __kps=k")
        );
        assert_eq!(
            normalize_cookie_input("__uid=u\n__kps=k").as_deref(),
            Some("__uid=u; __kps=k")
        );
        assert_eq!(normalize_cookie_input("   \n\t  "), None);
    }

    #[test]
    fn cookie_input_strips_control_characters() {
        let normalized = normalize_cookie_input("__uid=u;\u{0000}__kps=k").unwrap();
        assert_eq!(normalized, "__uid=u; __kps=k");
        assert!(!normalized.chars().any(char::is_control));
    }

    #[test]
    fn cookie_input_keeps_json_exports_intact() {
        let input = "{\n  \"cookies\": {\"__uid\": \"u\", \"__kps\": \"k\"}\n}";
        let normalized = normalize_cookie_input(input).unwrap();
        assert!(normalized.starts_with('{'));
        assert!(normalized.contains("\"__kps\": \"k\""));
    }

    #[test]
    fn cookie_names_are_unique_and_ignore_malformed_pairs() {
        assert_eq!(
            cookie_names("__uid=u; __kps=k; __uid=other; broken; =empty"),
            vec!["__uid", "__kps"]
        );
    }

    #[test]
    fn authentication_errors_explain_missing_cookie_fields() {
        let error = cookie_auth_error(
            ProviderError::new(ProviderErrorCategory::Authentication, "上游拒绝登录"),
            "__uid=u; __kps=k",
        );
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.code, "authentication");
        assert!(error.message.contains("__pus"));
        assert!(error.message.contains("__puus"));
        assert!(!error.message.contains("缺少 __uid"));
        assert!(!error.message.contains("缺少 __kps"));
    }

    #[test]
    fn non_authentication_errors_keep_their_category() {
        let error = cookie_auth_error(
            ProviderError::new(ProviderErrorCategory::RateLimit, "请求太快"),
            "__uid=u; __kps=k",
        );
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.message, "请求太快");
    }

    #[test]
    fn expired_challenges_are_reported_as_gone() {
        let error = challenge_error(ProviderError::new(
            ProviderErrorCategory::Authentication,
            "夸克二维码已过期，请重新获取",
        ));
        assert_eq!(error.status, StatusCode::GONE);
        assert_eq!(error.code, "challenge_expired");

        let error = challenge_error(ProviderError::new(
            ProviderErrorCategory::RemoteUnavailable,
            "上游暂时不可用",
        ));
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
    }
}
