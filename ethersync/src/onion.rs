//! Onion helpers for ORP-HighRisk circuit payload wrapping.
//!
//! This module provides the cryptographic building blocks needed to move the
//! routed high-risk data plane from plain forwarded payloads to layered
//! per-hop protection. The runtime wiring remains explicit elsewhere, but the
//! codec and handshake envelope live here so the control-plane and data-plane
//! can converge on a shared contract.

use crate::routing::HighRiskRouteDescriptor;
use ouroboros_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt};
use ouroboros_crypto::derive::hkdf_expand_array;
use ouroboros_crypto::CryptoError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Handshake material delivered to a hop during circuit setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopHandshake {
    /// Origin-provided ephemeral public key for future DH-based session setup.
    pub origin_ephemeral_pubkey: [u8; 32],
    /// Slot/epoch used to derive the advertised onion key from the local root.
    pub onion_epoch_slot: u64,
    /// Random salt mixed into the locally-derived onion announcement key.
    pub onion_salt: [u8; 16],
    /// Encrypted per-hop capsule carrying only the metadata needed by the
    /// intended hop. Other peers in the passphrase space can see the handshake
    /// frame but cannot recover the capsule without the hop's derived key.
    pub sealed_capsule: Vec<u8>,
    /// Optional reverse-path onion layers for the exit hop, encrypted under the
    /// exit hop session key so other peers in the space cannot recover them.
    #[serde(default)]
    pub reply_layers_ciphertext: Vec<u8>,
}

/// Encrypted per-hop circuit capsule recovered after the handshake DH succeeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighRiskHopCapsule {
    /// Minimal route descriptor visible only to the intended hop.
    pub descriptor: HighRiskRouteDescriptor,
    /// Encoded local role: 1=entry, 2=middle, 3=exit.
    pub local_role_code: u8,
    /// Origin-provided ephemeral public key used to derive the return-path
    /// session key for this hop. This is intentionally separate from the
    /// forward-path ephemeral key so reply traffic does not reuse forward keys.
    pub reply_origin_ephemeral_pubkey: [u8; 32],
}

/// One onion layer associated with a specific hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    /// Per-hop AEAD key already derived by the circuit handshake.
    pub session_key: [u8; 32],
    /// Hop position inside the circuit.
    pub hop_index: u8,
}

/// Ordered onion codec for a high-risk circuit.
#[derive(Debug, Clone, Default)]
pub struct OnionCodec {
    /// Ordered from entry to exit.
    pub layers: Vec<OnionLayer>,
}

#[derive(Debug, Error)]
pub enum OnionError {
    #[error("onion layer count must be at least one")]
    EmptyCircuit,
    #[error("invalid onion public key material")]
    InvalidPublicKey,
    #[error("invalid onion shared secret")]
    InvalidSharedSecret,
    #[error("onion crypto failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("onion serialization failed")]
    Serialize,
    #[error("onion deserialization failed")]
    Deserialize,
}

/// Derive the published onion public key for a node secret.
pub fn derive_onion_public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_key);
    PublicKey::from(&secret).to_bytes()
}

/// Derive a rotating per-announcement onion secret from the local root secret,
/// space prefix, slot/epoch, and a published random salt.
pub fn derive_rotating_onion_secret_key(
    root_secret_key: &[u8; 32],
    space_prefix: &[u8; 8],
    onion_epoch_slot: u64,
    onion_salt: &[u8; 16],
) -> Result<[u8; 32], OnionError> {
    let mut info = Vec::with_capacity(8 + 8 + 16 + 30);
    info.extend_from_slice(b"orp/onion/announce/v1/");
    info.extend_from_slice(space_prefix);
    info.extend_from_slice(&onion_epoch_slot.to_le_bytes());
    info.extend_from_slice(onion_salt);
    hkdf_expand_array(root_secret_key, None, &info).map_err(OnionError::Crypto)
}

/// Derive the per-hop session key from local secret, peer public key, and circuit id.
///
/// Each hop already uses its own origin ephemeral key, so the circuit id is
/// sufficient as a domain separator here.
pub fn derive_onion_session_key(
    local_secret_key: &[u8; 32],
    remote_public_key: &[u8; 32],
    circuit_id: &[u8; 16],
) -> Result<[u8; 32], OnionError> {
    let local_secret = StaticSecret::from(*local_secret_key);
    let remote_public = PublicKey::from(*remote_public_key);
    let shared_secret = local_secret.diffie_hellman(&remote_public);
    if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(OnionError::InvalidSharedSecret);
    }

    let mut info = Vec::with_capacity(24 + circuit_id.len());
    info.extend_from_slice(b"orp/high-risk/session/v1/");
    info.extend_from_slice(circuit_id);
    Ok(hkdf_expand_array(shared_secret.as_bytes(), None, &info)?)
}

/// Best-effort validation for a published onion public key.
///
/// Rejects obviously invalid material and non-contributory X25519 points by
/// ensuring a probe DH does not collapse to the all-zero shared secret.
pub fn is_valid_onion_public_key(pubkey: &[u8; 32]) -> bool {
    if pubkey.iter().all(|byte| *byte == 0) {
        return false;
    }

    let probe_secret = StaticSecret::from([9u8; 32]);
    let probe_public = PublicKey::from(*pubkey);
    let shared_secret = probe_secret.diffie_hellman(&probe_public);
    !shared_secret.as_bytes().iter().all(|byte| *byte == 0)
}

impl Drop for OnionLayer {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

impl OnionCodec {
    /// Wrap a payload from the innermost hop outward.
    ///
    /// `packet_id` must be unique per packet to guarantee nonce uniqueness.
    pub fn wrap(&self, packet_id: &[u8; 16], payload: &[u8]) -> Result<Vec<u8>, OnionError> {
        if self.layers.is_empty() {
            return Err(OnionError::EmptyCircuit);
        }

        let mut data = payload.to_vec();
        for layer in self.layers.iter().rev() {
            data = encrypt_layer(&layer.session_key, layer.hop_index, packet_id, &data)?;
        }
        Ok(data)
    }

    /// Peel a single hop layer.
    ///
    /// `packet_id` must match the value used during wrapping.
    pub fn peel(
        key: &[u8; 32],
        hop_index: u8,
        packet_id: &[u8; 16],
        data: &[u8],
    ) -> Result<Vec<u8>, OnionError> {
        decrypt_layer(key, hop_index, packet_id, data)
    }
}

fn encrypt_layer(
    session_key: &[u8; 32],
    hop_index: u8,
    packet_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    let nonce = nonce_for_hop(session_key, hop_index, packet_id)?;
    let aad = aad_for_hop(hop_index);
    Ok(xchacha20poly1305_encrypt(
        session_key,
        &nonce,
        plaintext,
        aad.as_slice(),
    )?)
}

fn decrypt_layer(
    session_key: &[u8; 32],
    hop_index: u8,
    packet_id: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    let nonce = nonce_for_hop(session_key, hop_index, packet_id)?;
    let aad = aad_for_hop(hop_index);
    Ok(xchacha20poly1305_decrypt(
        session_key,
        &nonce,
        ciphertext,
        aad.as_slice(),
    )?)
}

fn nonce_for_hop(
    session_key: &[u8; 32],
    hop_index: u8,
    packet_id: &[u8; 16],
) -> Result<[u8; 24], OnionError> {
    let mut info = Vec::with_capacity(14 + 16);
    info.extend_from_slice(b"orp/onion/v1/");
    info.push(hop_index);
    info.extend_from_slice(packet_id);
    Ok(hkdf_expand_array(session_key, None, &info)?)
}

fn aad_for_hop(hop_index: u8) -> Vec<u8> {
    let mut aad = b"orp/high-risk/onion/v1".to_vec();
    aad.push(hop_index);
    aad
}

/// Encrypt reverse-path onion layers so only the exit hop can recover them.
pub fn encrypt_reply_layers(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    layers: &[OnionLayer],
) -> Result<Vec<u8>, OnionError> {
    let plaintext = bincode::serialize(layers).map_err(|_| OnionError::Serialize)?;
    let nonce = reply_layers_nonce(session_key, circuit_id)?;
    Ok(xchacha20poly1305_encrypt(
        session_key,
        &nonce,
        &plaintext,
        b"orp/high-risk/reply-layers/v1",
    )?)
}

/// Decrypt reverse-path onion layers for the exit hop.
pub fn decrypt_reply_layers(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<OnionLayer>, OnionError> {
    let nonce = reply_layers_nonce(session_key, circuit_id)?;
    let plaintext = xchacha20poly1305_decrypt(
        session_key,
        &nonce,
        ciphertext,
        b"orp/high-risk/reply-layers/v1",
    )?;
    bincode::deserialize(&plaintext).map_err(|_| OnionError::Deserialize)
}

fn reply_layers_nonce(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
) -> Result<[u8; 24], OnionError> {
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"orp/high-risk/reply-layers/v1/");
    info.extend_from_slice(circuit_id);
    Ok(hkdf_expand_array(session_key, None, &info)?)
}

/// Encrypt a per-hop capsule so only the intended hop can recover it.
pub fn seal_hop_capsule(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    capsule: &HighRiskHopCapsule,
) -> Result<Vec<u8>, OnionError> {
    let plaintext = bincode::serialize(capsule).map_err(|_| OnionError::Serialize)?;
    let nonce = hop_capsule_nonce(session_key, circuit_id)?;
    Ok(xchacha20poly1305_encrypt(
        session_key,
        &nonce,
        &plaintext,
        b"orp/high-risk/hop-capsule/v1",
    )?)
}

/// Decrypt a per-hop capsule recovered during circuit setup.
pub fn open_hop_capsule(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
    ciphertext: &[u8],
) -> Result<HighRiskHopCapsule, OnionError> {
    let nonce = hop_capsule_nonce(session_key, circuit_id)?;
    let plaintext = xchacha20poly1305_decrypt(
        session_key,
        &nonce,
        ciphertext,
        b"orp/high-risk/hop-capsule/v1",
    )?;
    bincode::deserialize(&plaintext).map_err(|_| OnionError::Deserialize)
}

fn hop_capsule_nonce(
    session_key: &[u8; 32],
    circuit_id: &[u8; 16],
) -> Result<[u8; 24], OnionError> {
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"orp/high-risk/hop-capsule/v1/");
    info.extend_from_slice(circuit_id);
    Ok(hkdf_expand_array(session_key, None, &info)?)
}
