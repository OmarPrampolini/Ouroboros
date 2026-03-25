use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::config::{GuaranteedEgress, PrivacyProfile, ProductMode, TorRole, WanMode};
use crate::offer::RoleHint;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: u16,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: &str) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST.as_u16(),
            message: msg.to_string(),
        }
    }

    pub fn operation_failed() -> Self {
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            message: "operation failed".to_string(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("API error: {:?}", err);
        Self::operation_failed()
    }
}

impl From<crate::offer::OfferError> for ApiError {
    fn from(err: crate::offer::OfferError) -> Self {
        tracing::error!("API offer error: {:?}", err);
        Self::operation_failed()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let code = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (code, Json(self)).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConnectionRequest {
    pub passphrase: Option<String>,
    pub offer: Option<String>,
    pub qr: Option<String>,
    pub local_role: Option<RoleHint>,
    /// `ip:port` for direct target connect or `orp:<16-hex>` for ORP target lookup.
    pub target: Option<String>,
    #[serde(default)]
    pub privacy_profile: PrivacyProfile,
    #[serde(default)]
    pub wan_mode: WanMode,
    #[serde(default)]
    pub tor_role: TorRole,
    #[serde(default)]
    pub product_mode: ProductMode,
    #[serde(default)]
    pub guaranteed_egress: GuaranteedEgress,
    pub guaranteed_relay_url: Option<String>,
    /// Required if wan_mode=Tor && role=Client. Format: "abc...xyz.onion:PORT"
    pub target_onion: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectionResponse {
    pub status: String,
    pub port: Option<u16>,
    pub mode: String,
    pub peer: Option<String>,
    pub resume_status: Option<String>,
    pub privacy_profile: PrivacyProfile,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SendRequest {
    pub packet_b64: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PhraseOpenRequest {
    pub passphrase: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PhraseJoinRequest {
    pub invite: String,
    pub passphrase: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PhraseOpenResponse {
    pub onion: String,
    pub virt_port: u16,
    pub invite: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PhraseStatusResponse {
    pub status: String,
    pub onion: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SetPass {
    pub passphrase: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SealReq {
    pub data_b64: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenReq {
    pub packet_b64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SealRes {
    pub packet_b64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenRes {
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SetPassRes {
    pub status: String,
    pub port: u16,
    pub tag16: u16,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SimultaneousOpenRequest {
    pub my_offer: String,    // Base64 encoded OfferPayload
    pub their_hash: String,  // Base64 encoded offer hash (32 bytes)
    pub relay_onion: String, // Relay onion address
}

#[derive(Debug, Serialize)]
pub(crate) struct SimultaneousOpenResponse {
    pub success: bool,
    pub offset_ms: Option<i64>,
    pub rendezvous_at: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EtherSyncStartRequest {
    pub bind_addr: Option<String>,
    pub bootstrap_peers: Option<Vec<String>>,
    pub gossip_interval_secs: Option<u64>,
    pub sweep_interval_secs: Option<u64>,
    pub gossip_ttl: Option<u8>,
    pub enable_compression: Option<bool>,
    /// Enable ORP route discovery as a transport fallback before Tor.
    pub enable_orp: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EtherSyncPeerAddRequest {
    pub addr: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EtherSyncJoinRequest {
    pub passphrase: String,
    pub label: Option<String>,
    pub retention_tier: Option<String>,
    pub replication_factor: Option<usize>,
    pub route_bias: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EtherSyncPublishRequest {
    pub passphrase: String,
    pub payload_b64: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EtherSyncPublishFileRequest {
    pub passphrase: String,
    pub filename: String,
    pub file_b64: String,
    pub chunk_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct KeeperBackfillRequest {
    pub passphrase: String,
    pub max_messages: Option<usize>,
}
