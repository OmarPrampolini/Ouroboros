use axum::{
    extract::Extension,
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::{config::DEFAULT_CHANNEL_CAPACITY, state::AppState};

mod auth;
mod connect;
mod connect_helpers;
mod diagnostics;
mod ethersync;
mod phrase;
mod pluggable;
mod session;
mod stream;
mod sync;
mod types;

pub use types::ApiError;

#[derive(Clone)]
pub struct Streams {
    pub tx: mpsc::Sender<Vec<u8>>,                            // RX->SSE
    pub rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>, // RX->SSE
    pub tx_out: mpsc::Sender<Vec<u8>>,                        // /send -> sender task
}

#[derive(Clone)]
pub struct ApiState {
    pub app: AppState,
    pub streams: Streams,
}

impl Streams {
    pub fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        (
            Self {
                tx,
                rx: Arc::new(tokio::sync::Mutex::new(rx)),
                tx_out,
            },
            rx_out,
        )
    }
}

pub async fn create_api_server(
    state: AppState,
    streams: Streams,
    bind: String,
    api_token: Option<String>,
) -> anyhow::Result<()> {
    let state = std::sync::Arc::new(ApiState {
        app: state,
        streams,
    });
    let app = build_router(state, api_token);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("API server listening on http://{}", bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn build_router(state: Arc<ApiState>, api_token: Option<String>) -> Router {
    let mut app = Router::new()
        .route("/v1/connect", post(connect::handle_connect))
        .route("/v1/status", get(stream::handle_status))
        .route("/v1/send", post(stream::handle_send))
        .route("/v1/recv", get(stream::handle_recv_sse))
        .route("/v1/set_passphrase", post(session::handle_set_passphrase))
        .route("/v1/seal", post(session::handle_seal))
        .route("/v1/open", post(session::handle_open))
        .route("/v1/disconnect", post(session::handle_disconnect))
        .route("/v1/metrics", get(diagnostics::handle_metrics))
        .route("/v1/capabilities", get(diagnostics::handle_capabilities))
        .route(
            "/v1/connect/fallbacks",
            get(diagnostics::handle_connect_fallbacks),
        )
        .route(
            "/v1/network/nat-metrics",
            get(diagnostics::handle_nat_metrics),
        )
        .route(
            "/v1/pluggable/protocols",
            get(pluggable::handle_pluggable_protocols),
        )
        .route(
            "/v1/pluggable/check",
            get(pluggable::handle_pluggable_check),
        )
        .route("/v1/rendezvous/sync", post(sync::handle_connect_sync))
        .route("/v1/circuit", get(diagnostics::handle_circuit_status))
        .route("/v1/offer", post(crate::api_offer::handle_offer_generate))
        .route(
            "/v1/qr/hybrid",
            post(crate::api_offer::handle_hybrid_qr_generate),
        )
        .route("/v1/phrase/open", post(phrase::handle_phrase_open))
        .route("/v1/phrase/close", post(phrase::handle_phrase_close))
        .route("/v1/phrase/join", post(phrase::handle_phrase_join))
        .route("/v1/phrase/status", get(phrase::handle_phrase_status))
        .route("/v1/ethersync/start", post(ethersync::handle_start))
        .route("/v1/ethersync/stop", post(ethersync::handle_stop))
        .route("/v1/ethersync/status", get(ethersync::handle_status))
        .route("/v1/ethersync/peers/add", post(ethersync::handle_peer_add))
        .route(
            "/v1/ethersync/spaces/join",
            post(ethersync::handle_join_space),
        )
        .route(
            "/v1/ethersync/spaces/publish",
            post(ethersync::handle_publish),
        )
        .route(
            "/v1/ethersync/files/publish",
            post(ethersync::handle_publish_file),
        )
        .route("/v1/ethersync/events", get(ethersync::handle_events_sse))
        .layer(Extension(state))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    if let Some(token) = api_token {
        let token = std::sync::Arc::new(token);
        app = app.layer(from_fn_with_state(token, auth::require_bearer));
    }

    // IMPORTANT: CORS must be OUTERMOST so preflight OPTIONS does not get blocked by auth.
    app.layer(auth::build_cors_layer())
}
