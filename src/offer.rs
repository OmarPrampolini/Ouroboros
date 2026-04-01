use crate::crypto::MAX_TCP_FRAME_BYTES;
use crate::onion::validate_onion_addr;
use crate::security::TimeValidator;
use base64::{engine::general_purpose, Engine as _};
use bincode::Options;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum OfferError {
    #[error("invalid offer: {0}")]
    InvalidOffer(String),
    #[error("time error: {0}")]
    Time(String),
    #[error("onion validation failed: {0}")]
    OnionValidation(String),
    #[error("hmac init failed")]
    HmacInit,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("base64 decode failed: {0}")]
    Base64Decode(String),
    #[error("bincode deserialize failed: {0}")]
    BincodeDeserialize(String),
    #[error("hkdf expand failed: {0}")]
    Hkdf(String),
    #[error("tor endpoint encrypt failed: {0}")]
    TorEncrypt(String),
    #[error("tor endpoint decrypt failed: {0}")]
    TorDecrypt(String),
    #[error("invalid tor endpoint utf8: {0}")]
    TorUtf8(String),
}

type Result<T> = std::result::Result<T, OfferError>;

/// Offer protocol version (breaking v4)
pub const OFFER_VERSION: u8 = 4;

/// TTL default: 5 minutes
pub const DEFAULT_TTL_SECONDS: u64 = 300;
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RoleHint {
    Host,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    Lan,
    Wan,
    Tor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub kind: EndpointKind,
    pub addr: Option<SocketAddr>,
    pub priority: u8,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RendezvousInfo {
    pub port: u16,
    pub tag16: u16,
    pub key_enc: [u8; 32],
}

/// Payload Offer (capability token)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferPayload {
    pub ver: u8,
    pub ttl_s: u64,
    pub issued_at_ms: u64,
    pub role_hint: RoleHint,
    pub endpoints: Vec<Endpoint>,
    pub tor_ephemeral_pk: Option<[u8; 32]>,
    pub tor_endpoint_enc: Option<Vec<u8>>,
    pub rendezvous: RendezvousInfo,
    pub stun_public_addr: Option<SocketAddr>,
    pub per_ephemeral_salt: Option<[u8; 16]>, // ← Per-port randomization salt
    pub commit: [u8; 32],
    pub timestamp: u64,          // UNIX timestamp in ms for simultaneous open
    pub ntp_offset: Option<i64>, // NTP offset after sync (None if not synced)
    pub simultaneous_open: bool, // Flag to enable simultaneous open
}

impl Zeroize for OfferPayload {
    fn zeroize(&mut self) {
        self.tor_ephemeral_pk.zeroize();
        self.tor_endpoint_enc.zeroize();
        self.rendezvous.zeroize();
        self.commit.zeroize();
    }
}

impl Drop for OfferPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl OfferPayload {
    pub fn new(
        role_hint: RoleHint,
        endpoints: Vec<Endpoint>,
        tor_onion_addr: Option<String>,
        rendezvous: RendezvousInfo,
        ttl_s: u64,
    ) -> Result<Self> {
        let issued_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| OfferError::Time(e.to_string()))?
            .as_millis() as u64;

        let mut tor_ephemeral_pk = None;
        let mut tor_endpoint_enc = None;
        if let Some(onion) = tor_onion_addr {
            validate_onion_addr(&onion).map_err(|e| OfferError::OnionValidation(e.to_string()))?;
            let (pk, enc) = encrypt_tor_endpoint(&rendezvous.key_enc, rendezvous.tag16, &onion)?;
            tor_ephemeral_pk = Some(pk);
            tor_endpoint_enc = Some(enc);
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| OfferError::Time(e.to_string()))?
            .as_millis() as u64;

        let mut offer = Self {
            ver: OFFER_VERSION,
            ttl_s,
            issued_at_ms,
            role_hint,
            endpoints,
            tor_ephemeral_pk,
            tor_endpoint_enc,
            rendezvous,
            per_ephemeral_salt: None, // â† Aggiunto
            stun_public_addr: None,
            commit: [0u8; 32],
            timestamp,
            ntp_offset: None,
            simultaneous_open: false,
        };

        let k_offer = derive_offer_key_v2(&offer.rendezvous.key_enc, offer.rendezvous.tag16)?;
        offer.commit = Self::compute_commit(&offer, &k_offer)?;
        Ok(offer)
    }

    pub fn compute_commit(offer: &Self, k_offer: &[u8; 32]) -> Result<[u8; 32]> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(k_offer).map_err(|_| OfferError::HmacInit)?;

        mac.update(&[offer.ver]);
        mac.update(&offer.ttl_s.to_be_bytes());
        mac.update(&offer.issued_at_ms.to_be_bytes());
        mac.update(
            &bincode::serialize(&offer.role_hint)
                .map_err(|e| OfferError::Serialization(e.to_string()))?,
        );
        mac.update(
            &bincode::serialize(&offer.endpoints)
                .map_err(|e| OfferError::Serialization(e.to_string()))?,
        );
        if let Some(pk) = &offer.tor_ephemeral_pk {
            mac.update(pk);
        } else {
            mac.update(&[0u8]);
        }
        if let Some(enc) = &offer.tor_endpoint_enc {
            mac.update(enc);
        } else {
            mac.update(&[0u8]);
        }
        mac.update(&offer.rendezvous.port.to_be_bytes());
        mac.update(&offer.rendezvous.tag16.to_be_bytes());
        mac.update(&offer.rendezvous.key_enc);

        // Include ephemeral salt in commit if present
        if let Some(salt) = &offer.per_ephemeral_salt {
            mac.update(salt);
        } else {
            mac.update(&[0u8; 16]);
        }

        mac.update(
            &bincode::serialize(&offer.stun_public_addr)
                .map_err(|e| OfferError::Serialization(e.to_string()))?,
        );

        let result = mac.finalize();
        Ok(result.into_bytes().into())
    }

    pub fn verify(&self, time_validator: &TimeValidator) -> Result<()> {
        if self.ver != OFFER_VERSION {
            return Err(OfferError::InvalidOffer(format!(
                "Offer version mismatch: {}",
                self.ver
            )));
        }

        // Use TimeValidator for secure time validation against clock manipulation
        if let Err(e) = time_validator.validate_offer_time(self.issued_at_ms, self.ttl_s) {
            return Err(OfferError::InvalidOffer(format!(
                "Offer time validation failed: {}",
                e
            )));
        }

        if self.endpoints.is_empty() {
            return Err(OfferError::InvalidOffer(
                "Offer has no endpoints".to_string(),
            ));
        }

        if self.endpoints.iter().any(|e| e.kind == EndpointKind::Tor) {
            if self.tor_ephemeral_pk.is_none() || self.tor_endpoint_enc.is_none() {
                return Err(OfferError::InvalidOffer(
                    "Tor endpoint present but encrypted tor data missing".to_string(),
                ));
            }
            let tor = self.tor_onion_addr()?.ok_or_else(|| {
                OfferError::InvalidOffer("Encrypted tor endpoint missing".to_string())
            })?;
            validate_onion_addr(&tor).map_err(|e| OfferError::OnionValidation(e.to_string()))?;
        }

        let k_offer = derive_offer_key_v2(&self.rendezvous.key_enc, self.rendezvous.tag16)?;
        let expected = Self::compute_commit(self, &k_offer)?;
        if self.commit != expected {
            return Err(OfferError::InvalidOffer("Offer commit invalid".to_string()));
        }

        Ok(())
    }

    pub fn encode(&self) -> Result<String> {
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(MAX_TCP_FRAME_BYTES)
            .serialize(self)
            .map_err(|e| OfferError::Serialization(e.to_string()))?;
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| OfferError::Base64Decode(e.to_string()))?;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(MAX_TCP_FRAME_BYTES)
            .deserialize(&bytes)
            .map_err(|e| OfferError::BincodeDeserialize(e.to_string()))
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms
            .saturating_add(self.ttl_s.saturating_mul(1000))
    }

    pub fn tor_onion_addr(&self) -> Result<Option<String>> {
        let Some(pk) = &self.tor_ephemeral_pk else {
            return Ok(None);
        };
        let Some(enc) = &self.tor_endpoint_enc else {
            return Ok(None);
        };
        decrypt_tor_endpoint(&self.rendezvous.key_enc, self.rendezvous.tag16, pk, enc).map(Some)
    }
}

pub fn derive_offer_key_v2(base_key: &[u8; 32], tag16: u16) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"handshacke-offer-v3"), base_key);

    let mut k_offer = [0u8; 32];
    let info = [b"offer-commit".as_slice(), &tag16.to_be_bytes()].concat();
    hk.expand(&info, &mut k_offer)
        .map_err(|e| OfferError::Hkdf(format!("{:?}", e)))?;
    Ok(k_offer)
}

fn encrypt_tor_endpoint(
    key_enc: &[u8; 32],
    tag16: u16,
    onion: &str,
) -> Result<([u8; 32], Vec<u8>)> {
    let static_secret = derive_tor_static_secret(key_enc, tag16)?;
    let static_pk = PublicKey::from(&static_secret);

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&static_pk);
    let key = derive_tor_endpoint_key(shared.as_bytes(), tag16)?;

    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(&nonce.into(), onion.as_bytes())
        .map_err(|e| OfferError::TorEncrypt(format!("{:?}", e)))?;

    let mut enc = Vec::with_capacity(12 + ciphertext.len());
    enc.extend_from_slice(&nonce);
    enc.extend_from_slice(&ciphertext);

    Ok((*ephemeral_pk.as_bytes(), enc))
}

fn decrypt_tor_endpoint(
    key_enc: &[u8; 32],
    tag16: u16,
    ephemeral_pk: &[u8; 32],
    enc: &[u8],
) -> Result<String> {
    if enc.len() < 12 + 16 {
        return Err(OfferError::InvalidOffer(
            "Encrypted tor endpoint too short".to_string(),
        ));
    }
    let static_secret = derive_tor_static_secret(key_enc, tag16)?;
    let eph_pk = PublicKey::from(*ephemeral_pk);
    let shared = static_secret.diffie_hellman(&eph_pk);
    let key = derive_tor_endpoint_key(shared.as_bytes(), tag16)?;

    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = &enc[..12];
    let ciphertext = &enc[12..];
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|e| OfferError::TorDecrypt(format!("{:?}", e)))?;
    let onion = String::from_utf8(plaintext).map_err(|e| OfferError::TorUtf8(e.to_string()))?;
    Ok(onion)
}

fn derive_tor_static_secret(key_enc: &[u8; 32], tag16: u16) -> Result<StaticSecret> {
    let hk = Hkdf::<Sha256>::new(Some(b"handshacke-tor-static-v3"), key_enc);
    let mut sk = [0u8; 32];
    let info = [b"tor-static".as_slice(), &tag16.to_be_bytes()].concat();
    hk.expand(&info, &mut sk)
        .map_err(|e| OfferError::Hkdf(format!("{:?}", e)))?;
    Ok(StaticSecret::from(sk))
}

fn derive_tor_endpoint_key(shared: &[u8], tag16: u16) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"handshacke-tor-endpoint-v3"), shared);
    let mut key = [0u8; 32];
    let info = [b"tor-endpoint".as_slice(), &tag16.to_be_bytes()].concat();
    hk.expand(&info, &mut key)
        .map_err(|e| OfferError::Hkdf(format!("{:?}", e)))?;
    Ok(key)
}
