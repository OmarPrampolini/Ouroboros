use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub local_api_token: Option<std::sync::Arc<String>>,
    pub keeper_ingest_token: Option<std::sync::Arc<String>>,
}

fn matches_bearer(auth_str: &str, token: &str) -> bool {
    let expected = format!("Bearer {}", token);
    let auth_bytes = auth_str.as_bytes();
    let expected_bytes = expected.as_bytes();
    auth_bytes.len() == expected_bytes.len() && bool::from(auth_bytes.ct_eq(expected_bytes))
}

pub(crate) fn build_cors_layer() -> CorsLayer {
    // CORS is primarily relevant for the GUI (dev server origin) and protects against drive-by
    // browser access to localhost APIs. We keep an allowlist by default.
    //
    // Override with HANDSHACKE_API_CORS_ORIGINS="origin1,origin2".
    let default_origins = "http://localhost:5173,http://127.0.0.1:5173,tauri://localhost";
    let raw =
        std::env::var("HANDSHACKE_API_CORS_ORIGINS").unwrap_or_else(|_| default_origins.into());

    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let allow_origin = if origins.is_empty() {
        // Safe fallback: disable cross-origin access.
        AllowOrigin::predicate(|_, _| false)
    } else {
        AllowOrigin::list(origins)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
}

pub(crate) async fn require_bearer(
    State(auth): State<AuthConfig>,
    req: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    if req.method() == Method::POST && req.uri().path() == "/v1/keeper/store" {
        // Keeper ingest is a network-facing operator surface, not a localhost control-plane API.
        // Accept either a dedicated keeper-ingest bearer or the local management bearer so the
        // route is never unauthenticated on the network.
        let Some(auth_header) = req.headers().get(AUTHORIZATION) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let Ok(auth_str) = auth_header.to_str() else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let keeper_ok = auth
            .keeper_ingest_token
            .as_deref()
            .map(|ingest_token| matches_bearer(auth_str, ingest_token))
            .unwrap_or(false);
        let local_ok = auth
            .local_api_token
            .as_deref()
            .map(|token| matches_bearer(auth_str, token.as_str()))
            .unwrap_or(false);
        if keeper_ok || local_ok {
            return next.run(req).await;
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(token) = auth.local_api_token.as_ref() else {
        return next.run(req).await;
    };
    let Some(auth_header) = req.headers().get(AUTHORIZATION) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !matches_bearer(auth_str, token.as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}
