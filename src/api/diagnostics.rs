use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    Json,
};
use std::{net::SocketAddr, sync::Arc};

use crate::state::{CircuitBreakerStatus, DebugMetrics};

use super::ApiState;

/// Handle /v1/metrics - In-memory debugging metrics (zero persistence)
pub(crate) async fn handle_metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<DebugMetrics>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let metrics = state.app.get_metrics().await;
    let debug_metrics = DebugMetrics::from_collector(&metrics).await;

    Ok(Json(debug_metrics))
}

/// Handle /v1/circuit - Circuit breaker status for debugging
pub(crate) async fn handle_circuit_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<CircuitBreakerStatus>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let status = super::connect::get_connect_circuit_status().await;
    Ok(Json(status))
}
