//! Embedded browser UI.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../web/dist"]
struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(asset) = Assets::get(path) {
        return serve(path, asset.data.into_owned());
    }

    // Single-page application fallback.
    if let Some(asset) = Assets::get("index.html") {
        return serve("index.html", asset.data.into_owned());
    }

    (
        StatusCode::NOT_FOUND,
        "web assets are missing; run `cd web && npm run build` before compiling",
    )
        .into_response()
}

fn serve(path: &str, data: Vec<u8>) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        [
            (header::CONTENT_TYPE, mime.as_ref()),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        data,
    )
        .into_response()
}
