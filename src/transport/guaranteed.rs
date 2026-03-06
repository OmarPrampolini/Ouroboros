//! Guaranteed transport (A): relay-backed, deterministic connectivity.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use base64::{engine::general_purpose, Engine as _};
use reqwest::Url;
use thiserror::Error;

use crate::config::{Config, GuaranteedEgress};
use crate::derive::RendezvousParams;
use crate::transport::io::{IoResult, TransportIo, TransportIoError};

#[derive(Debug, Error)]
pub enum GuaranteedError {
    #[error("invalid Tor SOCKS proxy: {0}")]
    InvalidTorSocksProxy(String),
    #[error("http client build failed: {0}")]
    HttpClientBuild(String),
    #[error("Guaranteed mode requires HANDSHACKE_GUARANTEED_RELAY_URL")]
    MissingRelayUrl,
    #[error("Invalid HANDSHACKE_GUARANTEED_RELAY_URL: {0}")]
    InvalidRelayUrl(String),
}

type Result<T> = std::result::Result<T, GuaranteedError>;

#[derive(Clone)]
struct RelayIo {
    client: reqwest::Client,
    relay_url: Url,
    topics: Vec<String>,
    wait_ms: u64,
    rate_limit_addr: SocketAddr,
}

impl RelayIo {
    fn new(
        client: reqwest::Client,
        relay_url: Url,
        topics: Vec<String>,
        wait_ms: u64,
        rate_limit_addr: SocketAddr,
    ) -> Self {
        Self {
            client,
            relay_url,
            topics,
            wait_ms,
            rate_limit_addr,
        }
    }
}

impl TransportIo for RelayIo {
    fn max_packet_limit(&self) -> u64 {
        crate::crypto::MAX_TCP_FRAME_BYTES
    }

    fn rate_limit_addr(&self) -> SocketAddr {
        self.rate_limit_addr
    }

    fn send<'a>(
        &'a self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + 'a>> {
        let client = self.client.clone();
        let relay_url = self.relay_url.clone();
        let topics = self.topics.clone();
        Box::pin(async move {
            let mut sent = false;
            for topic in topics {
                if topic.is_empty() {
                    continue;
                }
                let url = relay_url.join("v1/relay/send").map_err(|e| {
                    TransportIoError::Relay(format!("invalid relay send URL: {}", e))
                })?;
                let payload = RelaySend {
                    topic,
                    data_b64: general_purpose::STANDARD.encode(&data),
                };
                let res = client.post(url).json(&payload).send().await.map_err(|e| {
                    TransportIoError::Relay(format!("relay send request failed: {}", e))
                })?;
                if !res.status().is_success() {
                    return Err(TransportIoError::Relay(format!(
                        "relay send failed: {}",
                        res.status()
                    )));
                }
                sent = true;
            }
            if !sent {
                return Err(TransportIoError::Relay("relay topic missing".to_string()));
            }
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + 'a>> {
        let client = self.client.clone();
        let relay_url = self.relay_url.clone();
        let topics = self.topics.clone();
        let wait_ms = self.wait_ms;
        Box::pin(async move {
            for topic in topics {
                if topic.is_empty() {
                    continue;
                }
                let mut url = relay_url.join("v1/relay/recv").map_err(|e| {
                    TransportIoError::Relay(format!("invalid relay recv URL: {}", e))
                })?;
                {
                    let mut pairs = url.query_pairs_mut();
                    pairs.append_pair("topic", &topic);
                    pairs.append_pair("wait_ms", &wait_ms.to_string());
                }
                let res = client.get(url).send().await.map_err(|e| {
                    TransportIoError::Relay(format!("relay recv request failed: {}", e))
                })?;
                if res.status().as_u16() == 204 {
                    continue;
                }
                if !res.status().is_success() {
                    return Err(TransportIoError::Relay(format!(
                        "relay recv failed: {}",
                        res.status()
                    )));
                }
                let msg: RelayRecv = res.json().await.map_err(|e| {
                    TransportIoError::Relay(format!("relay recv decode failed: {}", e))
                })?;
                let data = general_purpose::STANDARD
                    .decode(&msg.data_b64)
                    .map_err(|e| {
                        TransportIoError::Relay(format!(
                            "relay payload base64 decode failed: {}",
                            e
                        ))
                    })?;
                return Ok(data);
            }
            Ok(Vec::new())
        })
    }
}

#[derive(serde::Serialize)]
struct RelaySend {
    topic: String,
    data_b64: String,
}

#[derive(serde::Deserialize)]
struct RelayRecv {
    data_b64: String,
}

fn derive_relay_topics(key_enc: &[u8; 32], tag16: u16, window_ms: u64) -> Vec<String> {
    let window_ms = window_ms.max(60_000);
    let now_ms = crate::crypto::now_ms();
    let epoch = if window_ms == 0 {
        0
    } else {
        now_ms / window_ms
    };
    let mut topics = Vec::with_capacity(2);
    for e in [epoch, epoch.saturating_sub(1)] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hs/relay/topic/v2");
        hasher.update(b"guaranteed");
        hasher.update(&tag16.to_be_bytes());
        hasher.update(key_enc);
        hasher.update(&e.to_be_bytes());
        topics.push(hasher.finalize().to_hex().to_string());
    }
    topics
}

fn derive_rate_limit_addr(key_enc: &[u8; 32], tag16: u16) -> SocketAddr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hs/relay/ratelimit/v1");
    hasher.update(b"guaranteed");
    hasher.update(&tag16.to_be_bytes());
    hasher.update(key_enc);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    let mut ip_bytes = [0u8; 16];
    ip_bytes.copy_from_slice(&bytes[..16]);
    let ip = IpAddr::V6(Ipv6Addr::from(ip_bytes));
    let port = u16::from_be_bytes([bytes[16], bytes[17]]);
    SocketAddr::new(ip, port)
}

fn build_relay_client(cfg: &Config, egress: GuaranteedEgress) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if egress == GuaranteedEgress::Tor {
        let proxy = reqwest::Proxy::all(format!("socks5h://{}", cfg.tor_socks_addr))
            .map_err(|e| GuaranteedError::InvalidTorSocksProxy(e.to_string()))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| GuaranteedError::HttpClientBuild(e.to_string()))
}

/// Establish a Guaranteed (A) connection using relay-backed IO.
pub async fn establish_connection_guaranteed(
    params: &RendezvousParams,
    cfg: &Config,
    egress: GuaranteedEgress,
) -> Result<Arc<dyn TransportIo>> {
    if cfg.guaranteed_relay_url.is_empty() {
        return Err(GuaranteedError::MissingRelayUrl);
    }
    let relay_url = Url::parse(&cfg.guaranteed_relay_url)
        .map_err(|e| GuaranteedError::InvalidRelayUrl(e.to_string()))?;
    let client = build_relay_client(cfg, egress)?;
    let topics = derive_relay_topics(
        &params.key_enc,
        params.tag16,
        cfg.guaranteed_topic_window_ms,
    );
    let rate_limit_addr = derive_rate_limit_addr(&params.key_enc, params.tag16);
    Ok(Arc::new(RelayIo::new(
        client,
        relay_url,
        topics,
        cfg.guaranteed_relay_wait_ms,
        rate_limit_addr,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_rate_limit_addr_stable() {
        let key = [7u8; 32];
        let a = derive_rate_limit_addr(&key, 0x1337);
        let b = derive_rate_limit_addr(&key, 0x1337);
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_rate_limit_addr_changes_with_inputs() {
        let key1 = [7u8; 32];
        let key2 = [9u8; 32];
        let a = derive_rate_limit_addr(&key1, 0x1337);
        let b = derive_rate_limit_addr(&key1, 0x7331);
        let c = derive_rate_limit_addr(&key2, 0x1337);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
