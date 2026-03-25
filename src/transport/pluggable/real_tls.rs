//! Real TLS transport for DPI evasion
//!
//! Fetches real certificate chains from target domains and performs
//! actual TLS handshakes to evade deep inspection.

use base64::{engine::general_purpose, Engine as _};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream, TlsConnector};
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::Config;

type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, AnyError>;

fn any_error(msg: impl Into<String>) -> AnyError {
    std::io::Error::other(msg.into()).into()
}

/// Cached certificate chain
#[derive(Clone)]
pub struct CertChain {
    pub domain: Arc<str>,
    pub fetched_at: Instant,
    pub certificates: Vec<Vec<u8>>,
}

/// Global certificate cache (24h TTL)
static CERT_CACHE: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, CertChain>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Real TLS transport for DPI evasion
pub struct RealTlsChannel {
    stream: Option<TlsStream<TcpStream>>,
    domain: Arc<str>,
}

impl RealTlsChannel {
    /// Create new RealTlsChannel with domain
    pub fn new(domain: impl Into<Arc<str>>) -> Self {
        Self {
            domain: domain.into(),
            stream: None,
        }
    }

    /// Build rustls client config
    fn build_tls_config() -> Result<Arc<ClientConfig>> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        Ok(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        ))
    }

    /// Fetch certificate chain from domain (cached for 24h)
    async fn fetch_cert_chain(domain: Arc<str>) -> Result<CertChain> {
        let cache = CERT_CACHE.lock().await;

        // Check cache
        if let Some(cached) = cache.get(domain.as_ref()) {
            if cached.fetched_at.elapsed() < Duration::from_secs(86400) {
                return Ok(cached.clone());
            }
        }
        drop(cache);

        // Connect to domain and perform handshake to get cert chain
        tracing::debug!("Fetching certificate chain for {}", domain);
        let addr = format!("{}:443", domain);
        let tcp_stream = TcpStream::connect(&addr).await?;

        let config = Self::build_tls_config()?;
        let connector = TlsConnector::from(config);
        let domain_name = ServerName::try_from(domain.to_string())
            .map_err(|e| any_error(format!("Invalid domain name: {}", e)))?;

        // Perform full handshake to get peer certificates
        let tls_stream = connector
            .connect(domain_name, tcp_stream)
            .await
            .map_err(|e| any_error(format!("TLS handshake: {}", e)))?;

        // Extract certificates
        let (_, conn) = tls_stream.get_ref();
        let certificates: Vec<Vec<u8>> = conn
            .peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
            .unwrap_or_default();

        if certificates.is_empty() {
            return Err(any_error(format!(
                "No certificates received from {}",
                domain
            )));
        }

        let cert_chain = CertChain {
            domain: Arc::clone(&domain),
            fetched_at: Instant::now(),
            certificates,
        };

        // Store in cache
        let mut cache = CERT_CACHE.lock().await;
        cache.insert(domain.to_string(), cert_chain.clone());

        Ok(cert_chain)
    }

    /// Perform real TLS handshake
    pub async fn establish<T: Into<Arc<str>>>(&mut self, peer_addr: T) -> Result<()> {
        let peer_addr = peer_addr.into();

        // Fetch certificate chain first (validates domain is reachable)
        Self::fetch_cert_chain(Arc::clone(&self.domain))
            .await
            .map_err(|e| any_error(format!("fetch certificate chain: {}", e)))?;

        // Connect to peer
        let tcp_stream = TcpStream::connect(peer_addr.as_ref()).await?;

        // Disable TCP_NODELAY for handshake (batch packets)
        tcp_stream.set_nodelay(false)?;

        // Perform TLS handshake
        let config = Self::build_tls_config()?;
        let connector = TlsConnector::from(config);
        let domain_name = ServerName::try_from(self.domain.to_string())
            .map_err(|e| any_error(format!("Invalid domain name: {}", e)))?;

        let tls_stream = connector
            .connect(domain_name, tcp_stream)
            .await
            .map_err(|e| any_error(format!("TLS handshake with peer: {}", e)))?;

        // Mimicry pinning: verify issuer SPKI plausibility for target domain
        let cfg = Config::from_env();
        if let Some((pins, enforce)) = collect_mimicry_pins(&cfg, self.domain.as_ref()) {
            let (_, conn) = tls_stream.get_ref();
            let certs: Vec<Vec<u8>> = conn
                .peer_certificates()
                .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
                .unwrap_or_default();

            if !certs.is_empty() {
                let matches = match_mimicry_pins(&certs, &pins)?;
                if !matches {
                    if enforce {
                        return Err(any_error(format!(
                            "RealTLS mimicry pin mismatch for {}",
                            self.domain
                        )));
                    } else {
                        tracing::warn!(
                            "RealTLS mimicry pin mismatch for {} (warn-only)",
                            self.domain
                        );
                    }
                }
            } else if enforce {
                return Err(any_error(
                    "RealTLS mimicry pinning failed: no peer certificates",
                ));
            }
        }

        // Enable TCP_NODELAY after handshake (efficient data transfer)
        let (tcp, _) = tls_stream.get_ref();
        tcp.set_nodelay(true)?;

        self.stream = Some(tls_stream);

        tracing::info!(
            "Real TLS established to peer {} (SNI: {})",
            peer_addr,
            self.domain
        );
        Ok(())
    }
}

fn collect_mimicry_pins(cfg: &Config, domain: &str) -> Option<(Vec<[u8; 32]>, bool)> {
    if cfg.realtls_mimic_pins.is_empty() {
        return None;
    }
    let mut hashes = Vec::new();
    let mut enforce = false;
    for pin in cfg
        .realtls_mimic_pins
        .iter()
        .filter(|p| p.target_domain == domain)
    {
        hashes.extend_from_slice(&pin.issuer_spki_hashes);
        enforce |= pin.enforce;
    }
    if hashes.is_empty() {
        None
    } else {
        Some((hashes, enforce))
    }
}

fn match_mimicry_pins(cert_chain: &[Vec<u8>], pins: &[[u8; 32]]) -> Result<bool> {
    // Prefer issuer/intermediate certs; fallback to leaf if chain missing.
    let mut hashes = Vec::new();
    if cert_chain.len() > 1 {
        for cert in &cert_chain[1..] {
            if let Ok(h) = spki_hash_from_cert(cert) {
                hashes.push(h);
            }
        }
    } else if let Some(leaf) = cert_chain.first() {
        if let Ok(h) = spki_hash_from_cert(leaf) {
            hashes.push(h);
        }
    }
    if hashes.is_empty() {
        return Ok(false);
    }
    for h in hashes {
        if pins.iter().any(|p| p == &h) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn spki_hash_from_cert(cert_der: &[u8]) -> Result<[u8; 32]> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| any_error(e.to_string()))?;
    let spki = cert.tbs_certificate.subject_pki.raw;
    let digest = sha2::Sha256::digest(spki);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Helper: compute SPKI SHA256 hashes from PEM-encoded certificate bundle.
pub fn spki_hashes_from_pem(pem: &str) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    for pem_block in Pem::iter_from_buffer(pem.as_bytes()) {
        let pem_block = pem_block.map_err(|e| any_error(format!("PEM parse failed: {:?}", e)))?;
        if pem_block.label == "CERTIFICATE" {
            let h = spki_hash_from_cert(&pem_block.contents)?;
            out.push(h);
        }
    }
    if out.is_empty() {
        return Err(any_error("No certificates found in PEM"));
    }
    Ok(out)
}

/// Helper: compute base64-encoded SPKI SHA256 hashes from PEM bundle.
pub fn spki_hashes_base64_from_pem(pem: &str) -> Result<Vec<String>> {
    let hashes = spki_hashes_from_pem(pem)?;
    let mut out = Vec::with_capacity(hashes.len());
    for h in hashes {
        out.push(general_purpose::STANDARD.encode(h));
    }
    Ok(out)
}

// Implement TransportChannel trait
#[async_trait::async_trait]
impl crate::transport::pluggable::TransportChannel for RealTlsChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| any_error("TLS not established"))?;

        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Read message
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;
        Ok(msg)
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| any_error("TLS not established"))?;

        // Write length prefix + data
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;
        Ok(())
    }
}

// Re-export for integration
pub use RealTlsChannel as TlsChannel;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    fn install_crypto_provider() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[tokio::test]
    async fn test_fetch_cert_chain() {
        install_crypto_provider();
        let domains = vec!["www.cloudflare.com", "api.google.com", "www.google.com"];

        for domain in domains {
            match RealTlsChannel::fetch_cert_chain(Arc::from(domain)).await {
                Ok(chain) => {
                    println!(
                        "Fetched {} certificates for {}",
                        chain.certificates.len(),
                        domain
                    );
                    assert!(!chain.certificates.is_empty());
                }
                Err(e) => {
                    println!("Failed to fetch certs for {}: {}", domain, e);
                }
            }
        }
    }
}
