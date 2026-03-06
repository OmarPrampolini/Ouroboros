use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::interval;

use super::types::{ConnectionResponse, SendRequest};
use super::ApiState;

static UDP_API_SEND_LIMIT: OnceLock<usize> = OnceLock::new();
static WEBRTC_API_SEND_LIMIT: OnceLock<usize> = OnceLock::new();

fn transport_raw_limit_for_mode(mode: Option<&str>) -> usize {
    match mode {
        Some("wan") | Some("lan") => crate::crypto::MAX_UDP_PACKET_BYTES as usize,
        Some("webrtc") => crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES,
        Some("guaranteed") | Some("wan_tor") | Some("wan_tcp") | Some("phrase_tor")
        | Some("quic") => crate::crypto::MAX_TCP_FRAME_BYTES as usize,
        // Unknown mode: keep conservative for datagram safety.
        _ => crate::crypto::MAX_UDP_PACKET_BYTES as usize,
    }
}

fn serialized_encrypted_len_for_app_payload(payload_len: usize) -> Option<usize> {
    let ctrl = crate::protocol::Control::App(vec![0u8; payload_len]);
    let payload = bincode::serialize(&ctrl).ok()?;
    let clear = crate::crypto::ClearPayload {
        ts_ms: 0,
        seq: 1,
        data: payload,
    };
    let pkt = crate::crypto::seal_with_nonce(&[0u8; 32], 0, 0, &clear, &[0u8; 24]).ok()?;
    let raw = crate::crypto::serialize_cipher_packet(&pkt).ok()?;
    Some(raw.len())
}

fn max_app_payload_for_raw_limit(raw_limit: usize) -> usize {
    let hard_cap = crate::crypto::MAX_CLEAR_PAYLOAD_BYTES;
    let mut lo = 0usize;
    let mut hi = hard_cap;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        match serialized_encrypted_len_for_app_payload(mid) {
            Some(n) if n <= raw_limit => lo = mid,
            _ => hi = mid.saturating_sub(1),
        }
    }
    lo
}

fn api_send_payload_limit_for_mode(mode: Option<&str>) -> usize {
    let raw_limit = transport_raw_limit_for_mode(mode);
    if raw_limit >= crate::crypto::MAX_TCP_FRAME_BYTES as usize {
        return crate::crypto::MAX_CLEAR_PAYLOAD_BYTES;
    }

    if raw_limit == crate::crypto::MAX_UDP_PACKET_BYTES as usize {
        return *UDP_API_SEND_LIMIT.get_or_init(|| max_app_payload_for_raw_limit(raw_limit));
    }

    if raw_limit == crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES {
        return *WEBRTC_API_SEND_LIMIT.get_or_init(|| max_app_payload_for_raw_limit(raw_limit));
    }

    max_app_payload_for_raw_limit(raw_limit)
}

pub(crate) async fn handle_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let s = state.app.get_connection_state().await;
    Ok(Json(ConnectionResponse {
        status: format!("{:?}", s.status),
        port: s.port,
        mode: s.mode.unwrap_or_else(|| "unknown".into()),
        peer: s.peer_address,
        resume_status: None,
    }))
}

pub(crate) async fn handle_send(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let Ok(bytes) = general_purpose::STANDARD.decode(&req.packet_b64) else {
        return StatusCode::BAD_REQUEST;
    };
    if bytes.len() < 4 {
        return StatusCode::BAD_REQUEST;
    }

    let mode = state.app.get_connection_state().await.mode;
    let max_payload = api_send_payload_limit_for_mode(mode.as_deref());
    if bytes.len() > max_payload {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    if let Some(tx_out) = state.app.get_tx_out().await {
        match tx_out.try_send(bytes) {
            Ok(()) => StatusCode::OK,
            Err(TrySendError::Full(_)) => StatusCode::TOO_MANY_REQUESTS,
            Err(TrySendError::Closed(_)) => StatusCode::SERVICE_UNAVAILABLE,
        }
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub(crate) async fn handle_recv_sse(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let rx = state.streams.rx.clone();
    let mut ticker = interval(Duration::from_millis(5000));

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                maybe = async {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                } => {
                    if let Some(bytes) = maybe {
                        let ev = Event::default().data(general_purpose::STANDARD.encode(bytes));
                        yield Ok::<Event, Infallible>(ev);
                    } else {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    yield Ok::<Event, Infallible>(Event::default().event("keepalive").data("ok"));
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_send_limit_matches_transport_cap() {
        let limit = api_send_payload_limit_for_mode(Some("wan"));
        let len = serialized_encrypted_len_for_app_payload(limit).unwrap();
        assert!(len <= crate::crypto::MAX_UDP_PACKET_BYTES as usize);
        if limit < crate::crypto::MAX_CLEAR_PAYLOAD_BYTES {
            let next = serialized_encrypted_len_for_app_payload(limit + 1).unwrap();
            assert!(next > crate::crypto::MAX_UDP_PACKET_BYTES as usize);
        }
    }

    #[test]
    fn test_webrtc_send_limit_matches_transport_cap() {
        let limit = api_send_payload_limit_for_mode(Some("webrtc"));
        let len = serialized_encrypted_len_for_app_payload(limit).unwrap();
        assert!(len <= crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES);
        if limit < crate::crypto::MAX_CLEAR_PAYLOAD_BYTES {
            let next = serialized_encrypted_len_for_app_payload(limit + 1).unwrap();
            assert!(next > crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES);
        }
    }

    #[test]
    fn test_stream_modes_keep_clear_cap() {
        for mode in ["guaranteed", "wan_tor", "wan_tcp", "phrase_tor", "quic"] {
            assert_eq!(
                api_send_payload_limit_for_mode(Some(mode)),
                crate::crypto::MAX_CLEAR_PAYLOAD_BYTES
            );
        }
    }
}
