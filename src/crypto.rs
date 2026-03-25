use bincode::Options;
use ouroboros_crypto::{
    aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt},
    hash::blake3_hash,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroize;

pub const NONCE_DOMAIN_NOISE: u8 = 0x01;
pub const NONCE_DOMAIN_APP: u8 = 0x02;
pub const NONCE_DOMAIN_ASSIST: u8 = 0x03;
pub const NONCE_DOMAIN_API: u8 = 0x04;
pub const NONCE_DOMAIN_RESUME: u8 = 0x05;

static BOOT_NONCE_SALT: OnceLock<[u8; 32]> = OnceLock::new();

fn boot_nonce_salt() -> [u8; 32] {
    *BOOT_NONCE_SALT.get_or_init(|| {
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    })
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("hkdf expand failed: {0}")]
    Hkdf(String),
    #[error("nonce counter overflow - consider key rotation")]
    NonceOverflow,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
    #[error("cipher packet too short")]
    PacketTooShort,
    #[error("cipher packet exceeds size limit")]
    PacketTooLarge,
    #[error("encryption failed: {0}")]
    Encrypt(String),
}

type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Clone)]
pub struct NonceSeq {
    prefix: [u8; 16],
    ctr: u64,
}

impl NonceSeq {
    fn new_with_salt(
        key_enc: &[u8; 32],
        domain: u8,
        role: u8,
        salt: Option<&[u8; 32]>,
    ) -> Result<Self> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(b"hs/xchacha20/nonce-prefix/v1"), key_enc);
        let mut prefix = [0u8; 16];
        let info = if let Some(salt) = salt {
            [b"boot:", &salt[..], b"|", &[domain], &[role]].concat()
        } else {
            vec![domain, role]
        };
        hk.expand(&info, &mut prefix)
            .map_err(|e| CryptoError::Hkdf(format!("{:?}", e)))?;
        Ok(Self { prefix, ctr: 0 })
    }

    pub fn new(key_enc: &[u8; 32], domain: u8, role: u8) -> Result<Self> {
        // Deterministic prefix: safe only when key changes per session.
        Self::new_with_salt(key_enc, domain, role, None)
    }

    /// Use a boot-random salt to prevent nonce reuse after restarts.
    /// Required when the key may repeat across process restarts.
    pub fn new_boot_random(key_enc: &[u8; 32], domain: u8, role: u8) -> Result<Self> {
        let salt = boot_nonce_salt();
        Self::new_with_salt(key_enc, domain, role, Some(&salt))
    }

    pub fn next_nonce_and_seq(&mut self) -> Result<([u8; 24], u64)> {
        let ctr = self.ctr.checked_add(1).ok_or(CryptoError::NonceOverflow)?;
        self.ctr = ctr;
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&self.prefix);
        nonce[16..].copy_from_slice(&ctr.to_be_bytes());
        Ok((nonce, ctr))
    }

    pub fn next_nonce(&mut self) -> Result<[u8; 24]> {
        let (nonce, _seq) = self.next_nonce_and_seq()?;
        Ok(nonce)
    }
}

#[cfg(feature = "pq")]
pub mod post_quantum;
pub mod replay;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClearPayload {
    pub ts_ms: u64,
    pub seq: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct KeyRotationPolicy {
    pub interval_ms: u64,
    pub max_messages: u64,
}

impl KeyRotationPolicy {
    pub fn disabled() -> Self {
        Self {
            interval_ms: 0,
            max_messages: 0,
        }
    }

    pub fn enabled(&self) -> bool {
        self.interval_ms > 0 || self.max_messages > 0
    }
}

#[derive(Clone)]
pub struct SessionKeyState {
    current_key: [u8; 32],
    previous_key: Option<[u8; 32]>,
    prev_expires_at_ms: Option<u64>,
    tag16: u16,
    tag8: u8,
    grace_ms: u64,
    last_ack_id: Option<u64>,
}

impl SessionKeyState {
    pub fn new(current_key: [u8; 32], tag16: u16, tag8: u8, grace_ms: u64) -> Self {
        Self {
            current_key,
            previous_key: None,
            prev_expires_at_ms: None,
            tag16,
            tag8,
            grace_ms,
            last_ack_id: None,
        }
    }

    pub fn tag16(&self) -> u16 {
        self.tag16
    }

    pub fn tag8(&self) -> u8 {
        self.tag8
    }

    pub fn current_key(&self) -> &[u8; 32] {
        &self.current_key
    }

    pub fn rotate_to(&mut self, new_key: [u8; 32]) {
        // Ensure any previously retained key does not linger in memory when overwritten.
        if let Some(prev) = self.previous_key.as_mut() {
            prev.zeroize();
        }
        self.previous_key = Some(self.current_key);
        self.prev_expires_at_ms = Some(now_ms().saturating_add(self.grace_ms));
        self.current_key = new_key;
        self.last_ack_id = None;
    }

    pub fn open_packet(&mut self, pkt: &CipherPacket) -> Option<ClearPayload> {
        self.prune_expired();
        if let Some(clear) = open(&self.current_key, pkt, self.tag16, self.tag8) {
            return Some(clear);
        }
        if let Some(prev) = &self.previous_key {
            if self
                .prev_expires_at_ms
                .map(|ts| now_ms() <= ts)
                .unwrap_or(false)
            {
                return open(prev, pkt, self.tag16, self.tag8);
            }
        }
        None
    }

    pub fn prune_expired(&mut self) {
        if let Some(ts) = self.prev_expires_at_ms {
            if now_ms() > ts {
                if let Some(prev) = self.previous_key.as_mut() {
                    prev.zeroize();
                }
                self.previous_key = None;
                self.prev_expires_at_ms = None;
            }
        }
    }

    pub fn set_ack_id(&mut self, ack_id: u64) {
        self.last_ack_id = Some(ack_id);
    }

    pub fn last_ack_id(&self) -> Option<u64> {
        self.last_ack_id
    }
}

impl Drop for SessionKeyState {
    fn drop(&mut self) {
        self.current_key.zeroize();
        if let Some(prev) = self.previous_key.as_mut() {
            prev.zeroize();
        }
    }
}

pub fn key_id_from_key(key: &[u8; 32]) -> u64 {
    let hash = blake3_hash(key);
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

// Wire format notes (release):
// V2 (default/only send): [tag16:2][tag8:1][version:1]...[payload]
// V1 legacy (parse only): [tag16:2][version:1]...[payload]
// Anti-ambiguity guard: tag8 is derived to never equal PROTOCOL_VERSION_V1
// so byte[2] == PROTOCOL_VERSION_V1 uniquely identifies V1 packets.
#[derive(Serialize, Deserialize, Debug)]
pub struct CipherPacket {
    pub tag16: u16,      // primi 2 byte on-wire (early drop)
    pub tag8: u8,        // terzo byte on-wire (tag24)
    pub version: u8,     // protocol version
    pub nonce: [u8; 24], // XChaCha20 nonce
    pub body: Vec<u8>,   // encrypted payload
}

#[derive(Serialize, Deserialize, Debug)]
struct CipherPacketV1 {
    pub tag16: u16,
    pub version: u8,
    pub nonce: [u8; 24],
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CipherPacketV2 {
    pub tag16: u16,
    pub tag8: u8,
    pub version: u8,
    pub nonce: [u8; 24],
    pub body: Vec<u8>,
}

// Protocol versions
pub const PROTOCOL_VERSION_V1: u8 = 1;
pub const PROTOCOL_VERSION_V2: u8 = 2;
pub const MIN_SUPPORTED_VERSION: u8 = 1;
pub const MAX_SUPPORTED_VERSION: u8 = 2;
pub const MAX_UDP_PACKET_BYTES: u64 = 1400;
pub const MAX_TCP_FRAME_BYTES: u64 = 1_048_576;
pub const MAX_CLEAR_PAYLOAD_BYTES: usize = 64 * 1024;

fn ct_eq_u16(a: u16, b: u16) -> bool {
    let mut diff = a ^ b;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    (diff & 1) == 0
}

fn cipher_bincode_opts(limit: u64) -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(limit)
}

/// Serialize a cipher packet (always emits V2 on wire; no V1 sending).
pub fn serialize_cipher_packet(pkt: &CipherPacket) -> Result<Vec<u8>> {
    let v2 = CipherPacketV2 {
        tag16: pkt.tag16,
        tag8: pkt.tag8,
        version: pkt.version,
        nonce: pkt.nonce,
        body: pkt.body.clone(),
    };
    cipher_bincode_opts(MAX_TCP_FRAME_BYTES)
        .serialize(&v2)
        .map_err(|e| CryptoError::Serialization(e.to_string()))
}

/// Add constant padding to reach MTU size (1400 bytes)
/// This prevents traffic analysis by making all packets same size
pub fn pad_to_mtu(packet: &mut Vec<u8>) {
    const MTU_SIZE: usize = 1400;
    if packet.len() < MTU_SIZE {
        let padding_len = MTU_SIZE - packet.len();
        let mut padding = vec![0u8; padding_len];
        rand::rngs::OsRng.fill_bytes(&mut padding);
        packet.extend(padding);
    }
    // If packet is already >= MTU, leave it unchanged
}

pub fn deserialize_cipher_packet(bytes: &[u8]) -> Result<CipherPacket> {
    deserialize_cipher_packet_with_limit(bytes, MAX_TCP_FRAME_BYTES)
}

/// Deserialize from wire; byte[2] == PROTOCOL_VERSION_V1 selects legacy V1 parsing.
pub fn deserialize_cipher_packet_with_limit(bytes: &[u8], limit: u64) -> Result<CipherPacket> {
    if bytes.len() < 3 {
        return Err(CryptoError::PacketTooShort);
    }
    if bytes.len() as u64 > limit {
        return Err(CryptoError::PacketTooLarge);
    }
    let third = bytes[2];
    if third == PROTOCOL_VERSION_V1 {
        let v1: CipherPacketV1 = cipher_bincode_opts(limit)
            .deserialize(bytes)
            .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
        Ok(CipherPacket {
            tag16: v1.tag16,
            tag8: 0,
            version: v1.version,
            nonce: v1.nonce,
            body: v1.body,
        })
    } else {
        let v2: CipherPacketV2 = cipher_bincode_opts(limit)
            .deserialize(bytes)
            .map_err(|e| CryptoError::Deserialization(e.to_string()))?;
        Ok(CipherPacket {
            tag16: v2.tag16,
            tag8: v2.tag8,
            version: v2.version,
            nonce: v2.nonce,
            body: v2.body,
        })
    }
}

/// Cifra un payload con XChaCha20Poly1305
pub fn seal(
    key_enc: &[u8; 32],
    tag16: u16,
    tag8: u8,
    clear: &ClearPayload,
) -> Result<CipherPacket> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let aad = tag16.to_be_bytes();
    let plaintext =
        bincode::serialize(clear).map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let body = xchacha20poly1305_encrypt(key_enc, &nonce, &plaintext, &aad)
        .map_err(|e| CryptoError::Encrypt(format!("{:?}", e)))?;

    Ok(CipherPacket {
        tag16,
        tag8,
        version: PROTOCOL_VERSION_V2,
        nonce,
        body,
    })
}

pub fn seal_with_nonce_seq(
    key_enc: &[u8; 32],
    tag16: u16,
    tag8: u8,
    clear: &ClearPayload,
    ns: &mut NonceSeq,
) -> Result<CipherPacket> {
    let (nonce, _seq) = ns.next_nonce_and_seq()?;

    seal_with_nonce(key_enc, tag16, tag8, clear, &nonce)
}

pub fn seal_with_nonce(
    key_enc: &[u8; 32],
    tag16: u16,
    tag8: u8,
    clear: &ClearPayload,
    nonce: &[u8; 24],
) -> Result<CipherPacket> {
    let aad = tag16.to_be_bytes();
    let plaintext =
        bincode::serialize(clear).map_err(|e| CryptoError::Serialization(e.to_string()))?;
    let body = xchacha20poly1305_encrypt(key_enc, nonce, &plaintext, &aad)
        .map_err(|e| CryptoError::Encrypt(format!("{:?}", e)))?;

    Ok(CipherPacket {
        tag16,
        tag8,
        version: PROTOCOL_VERSION_V2,
        nonce: *nonce,
        body,
    })
}

/// Decifra un pacchetto se il tag corrisponde
pub fn open(
    key_enc: &[u8; 32],
    pkt: &CipherPacket,
    expect_tag16: u16,
    expect_tag8: u8,
) -> Option<ClearPayload> {
    // 1. Early drop: controllo tag (filtro DoS)
    if !ct_eq_u16(pkt.tag16, expect_tag16) {
        return None;
    }
    if pkt.version >= PROTOCOL_VERSION_V2 && pkt.tag8 != expect_tag8 {
        return None;
    }

    // 2. Version check: supporto forward-compatible
    if pkt.version < MIN_SUPPORTED_VERSION || pkt.version > MAX_SUPPORTED_VERSION {
        tracing::warn!("Unsupported protocol version: {}", pkt.version);
        return None;
    }

    // 3. Decrypt del payload
    let aad = expect_tag16.to_be_bytes();
    let plaintext = xchacha20poly1305_decrypt(key_enc, &pkt.nonce, &pkt.body, &aad).ok()?;

    if plaintext.len() > MAX_CLEAR_PAYLOAD_BYTES {
        return None;
    }

    // 4. Deserialize payload
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_CLEAR_PAYLOAD_BYTES as u64);
    opts.deserialize::<ClearPayload>(&plaintext).ok()
}

// ReplayWindow moved to replay.rs module

/// Genera timestamp corrente in millisecondi
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Genera timestamp corrente in microsecondi
pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Calcola hash Blake3 di un OfferPayload per identificazione
pub fn hash_offer(offer: &crate::offer::OfferPayload) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&offer.rendezvous.key_enc);
    data.extend_from_slice(&offer.rendezvous.tag16.to_le_bytes());
    data.extend_from_slice(&offer.rendezvous.port.to_le_bytes());
    if let Some(salt) = &offer.per_ephemeral_salt {
        data.extend_from_slice(salt);
    }
    blake3_hash(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_state_prunes_expired_previous_key() {
        let mut st = SessionKeyState::new([1u8; 32], 0x1337, 0x42, 0);
        st.previous_key = Some([2u8; 32]);
        st.prev_expires_at_ms = Some(now_ms().saturating_sub(1));

        st.prune_expired();

        assert!(st.previous_key.is_none());
        assert!(st.prev_expires_at_ms.is_none());
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let key = [42u8; 32];
        let tag = 0x1337;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: 1,
            data: b"hello world".to_vec(),
        };

        let cipher_packet = seal(&key, tag, 0x42, &payload).unwrap();
        let decrypted = open(&key, &cipher_packet, tag, 0x42).unwrap();

        assert_eq!(payload.ts_ms, decrypted.ts_ms);
        assert_eq!(payload.seq, decrypted.seq);
        assert_eq!(payload.data, decrypted.data);
    }

    #[test]
    fn test_wrong_tag_rejection() {
        let key = [42u8; 32];
        let tag = 0x1337;
        let wrong_tag = 0x4242;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: 1,
            data: b"hello world".to_vec(),
        };

        let cipher_packet = seal(&key, tag, 0x42, &payload).unwrap();
        let should_be_none = open(&key, &cipher_packet, wrong_tag, 0x42);
        assert!(should_be_none.is_none());
    }

    #[test]
    fn test_v1_packet_compatibility() {
        let key = [42u8; 32];
        let tag = 0x1337;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: 7,
            data: b"v1 compat".to_vec(),
        };

        let cipher_packet = seal(&key, tag, 0x42, &payload).unwrap();
        let v1 = CipherPacketV1 {
            tag16: cipher_packet.tag16,
            version: PROTOCOL_VERSION_V1,
            nonce: cipher_packet.nonce,
            body: cipher_packet.body.clone(),
        };
        let bytes = cipher_bincode_opts(MAX_TCP_FRAME_BYTES)
            .serialize(&v1)
            .unwrap();

        let parsed = deserialize_cipher_packet(&bytes).unwrap();
        assert_eq!(parsed.version, PROTOCOL_VERSION_V1);

        let clear = open(&key, &parsed, tag, 0x42).unwrap();
        assert_eq!(payload.data, clear.data);
    }

    #[test]
    fn test_cipher_packet_v2_wire_layout() {
        let key = [42u8; 32];
        let tag = 0x1337u16;
        let tag8 = 0x7b;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: 2,
            data: b"wire".to_vec(),
        };

        let pkt = seal(&key, tag, tag8, &payload).unwrap();
        let bytes = serialize_cipher_packet(&pkt).unwrap();
        assert!(bytes.len() >= 4);
        assert_eq!(bytes[0], (tag & 0xff) as u8);
        assert_eq!(bytes[1], (tag >> 8) as u8);
        assert_eq!(bytes[2], tag8);
        assert_eq!(bytes[3], PROTOCOL_VERSION_V2);
    }

    #[test]
    fn test_replay_window() {
        let mut window = crate::crypto::replay::ReplayWindow::new();

        // Prima sequenza - accettata
        assert!(window.check(100));
        // Duplicato - rifiutato
        assert!(!window.check(100));
        // Sequenza più recente - accettata
        assert!(window.check(101));
        // Sequenza vecchia ma ancora nella finestra - rifiutata
        assert!(!window.check(100));
        // Salto avanti per far uscire seq 100 dalla finestra
        assert!(window.check(300));
        // Sequenza molto vecchia - rifiutata
        assert!(!window.check(100));
    }

    #[test]
    fn test_crypto_performance() {
        if std::env::var("CI").is_ok() {
            return;
        }
        // Keep the perf assertion for optimized runs; debug builds are too noisy
        // to use a hard wall-clock threshold reliably on developer machines.
        if cfg!(debug_assertions) {
            return;
        }
        let key = [42u8; 32];
        let tag = 0x1337;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: 1,
            data: vec![0u8; 1024], // 1KB payload
        };

        let start = std::time::Instant::now();

        for _ in 0..1000 {
            let cipher_packet = seal(&key, tag, 0x42, &payload).unwrap();
            let _decrypted = open(&key, &cipher_packet, tag, 0x42).unwrap();
        }

        let duration = start.elapsed();
        println!("1000 encryption/decryption cycles: {:?}", duration);
        assert!(duration < std::time::Duration::from_secs(1));
    }

    #[test]
    fn test_cipher_packet_bincode_limit() {
        let key = [42u8; 32];
        let tag = 0x1337;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: 1,
            data: vec![0u8; 32],
        };

        let mut pkt = seal(&key, tag, 0x42, &payload).unwrap();
        pkt.body = vec![0u8; (MAX_TCP_FRAME_BYTES as usize) + 1];

        let bytes = bincode::serialize(&pkt).unwrap();
        let res = deserialize_cipher_packet(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_nonce_seq_role_separation() {
        let key = [9u8; 32];
        let mut ns_a = NonceSeq::new(&key, NONCE_DOMAIN_APP, 0x01).unwrap();
        let mut ns_b = NonceSeq::new(&key, NONCE_DOMAIN_APP, 0x02).unwrap();
        let nonce_a = ns_a.next_nonce().unwrap();
        let nonce_b = ns_b.next_nonce().unwrap();
        assert_ne!(&nonce_a[..16], &nonce_b[..16]);
    }

    #[test]
    fn test_nonce_seq_domain_separation() {
        let key = [9u8; 32];
        let mut ns_noise = NonceSeq::new(&key, NONCE_DOMAIN_NOISE, 0x01).unwrap();
        let mut ns_app = NonceSeq::new(&key, NONCE_DOMAIN_APP, 0x01).unwrap();
        let nonce_noise = ns_noise.next_nonce().unwrap();
        let nonce_app = ns_app.next_nonce().unwrap();
        assert_ne!(&nonce_noise[..16], &nonce_app[..16]);
    }

    #[test]
    fn test_nonce_seq_monotonic_and_unique() {
        let key = [3u8; 32];
        let mut ns = NonceSeq::new(&key, NONCE_DOMAIN_APP, 0x01).unwrap();

        let (nonce1, seq1) = ns.next_nonce_and_seq().unwrap();
        let (nonce2, seq2) = ns.next_nonce_and_seq().unwrap();
        let (nonce3, seq3) = ns.next_nonce_and_seq().unwrap();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_nonce_boot_random_prefix_changes_with_salt() {
        let key = [9u8; 32];
        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];
        let mut ns1 =
            NonceSeq::new_with_salt(&key, NONCE_DOMAIN_NOISE, 0x01, Some(&salt1)).unwrap();
        let mut ns2 =
            NonceSeq::new_with_salt(&key, NONCE_DOMAIN_NOISE, 0x01, Some(&salt2)).unwrap();
        let (n1, _) = ns1.next_nonce_and_seq().unwrap();
        let (n2, _) = ns2.next_nonce_and_seq().unwrap();
        assert_ne!(n1[..16], n2[..16]);
    }

    #[test]
    fn test_nonce_boot_random_prefix_stable_in_process() {
        let key = [7u8; 32];
        let mut ns1 = NonceSeq::new_boot_random(&key, NONCE_DOMAIN_NOISE, 0x02).unwrap();
        let mut ns2 = NonceSeq::new_boot_random(&key, NONCE_DOMAIN_NOISE, 0x02).unwrap();
        let (n1, _) = ns1.next_nonce_and_seq().unwrap();
        let (n2, _) = ns2.next_nonce_and_seq().unwrap();
        assert_eq!(n1[..16], n2[..16]);
    }
}
