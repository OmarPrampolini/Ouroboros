use base64::{engine::general_purpose, Engine as _};
use ouroboros_crypto::hash::blake3_hash;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct KeeperClient {
    http: Client,
    timeout: Duration,
    bearer_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperStoreRequest {
    pub space_id: String,
    pub slot_id: u64,
    pub envelope_digest: String,
    pub message_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperStoreResponse {
    pub receipt_id: String,
    pub stored_at_ms: u64,
    pub digest_confirmed: String,
}

#[derive(Debug, Clone)]
pub struct RemoteReceipt {
    pub receipt_id: String,
    pub stored_at_ms: u64,
    pub digest_confirmed: String,
}

#[derive(Debug, Error)]
pub enum KeeperClientError {
    #[error("keeper endpoint is empty")]
    EmptyEndpoint,
    #[error("keeper rejected request with status {0}")]
    Rejected(u16),
    #[error("keeper transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("keeper digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("keeper receipt mismatch: expected {expected}, got {actual}")]
    ReceiptMismatch { expected: String, actual: String },
}

impl KeeperClient {
    pub fn new(timeout: Duration, bearer_token: Option<String>) -> Self {
        Self {
            http: Client::new(),
            timeout,
            bearer_token,
        }
    }

    pub async fn store_envelope(
        &self,
        endpoint: &str,
        space_id: &str,
        slot_id: u64,
        digest: &str,
        message_bytes: &[u8],
    ) -> Result<RemoteReceipt, KeeperClientError> {
        let url = keeper_store_url(endpoint)?;
        let mut request = self
            .http
            .post(url)
            .timeout(self.timeout)
            .json(&KeeperStoreRequest {
                space_id: space_id.to_string(),
                slot_id,
                envelope_digest: digest.to_string(),
                message_b64: general_purpose::STANDARD.encode(message_bytes),
            });
        if let Some(token) = self.bearer_token.as_ref() {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(KeeperClientError::Rejected(response.status().as_u16()));
        }

        let body: KeeperStoreResponse = response.json().await?;
        if body.digest_confirmed != digest {
            return Err(KeeperClientError::DigestMismatch {
                expected: digest.to_string(),
                actual: body.digest_confirmed,
            });
        }
        let expected_receipt_id =
            derive_keeper_store_receipt_id(space_id, slot_id, digest, message_bytes);
        if body.receipt_id != expected_receipt_id {
            return Err(KeeperClientError::ReceiptMismatch {
                expected: expected_receipt_id,
                actual: body.receipt_id,
            });
        }

        Ok(RemoteReceipt {
            receipt_id: body.receipt_id,
            stored_at_ms: body.stored_at_ms,
            digest_confirmed: digest.to_string(),
        })
    }
}

fn keeper_store_url(endpoint: &str) -> Result<String, KeeperClientError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(KeeperClientError::EmptyEndpoint);
    }
    if trimmed.ends_with("/v1/keeper/store") {
        return Ok(trimmed.to_string());
    }
    Ok(format!("{}/v1/keeper/store", trimmed))
}

fn derive_keeper_store_receipt_id(
    space_id: &str,
    slot_id: u64,
    digest_confirmed: &str,
    message_bytes: &[u8],
) -> String {
    let mut seed = Vec::new();
    seed.extend_from_slice(space_id.as_bytes());
    seed.extend_from_slice(&slot_id.to_le_bytes());
    seed.extend_from_slice(digest_confirmed.as_bytes());
    seed.extend_from_slice(message_bytes);
    let hash = blake3_hash(&seed);
    hex::encode(&hash[..10])
}
