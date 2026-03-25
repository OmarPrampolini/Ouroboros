use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const X25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum PostQuantumError {
    #[error("Hybrid public key length mismatch: expected {expected}, got {got}")]
    HybridPublicKeyLengthMismatch { expected: usize, got: usize },
    #[error("Kyber ciphertext length mismatch: expected {expected}, got {got}")]
    KyberCiphertextLengthMismatch { expected: usize, got: usize },
    #[error("Invalid Kyber ciphertext")]
    InvalidKyberCiphertext,
    #[error("Invalid X25519 public key length")]
    InvalidX25519PublicKeyLength,
    #[error("Invalid Kyber public key")]
    InvalidKyberPublicKey,
    #[error("HKDF expand failed: {0}")]
    HkdfExpand(String),
}

type Result<T> = std::result::Result<T, PostQuantumError>;

pub fn kyber_public_key_bytes() -> usize {
    mlkem768::public_key_bytes()
}

pub fn kyber_ciphertext_bytes() -> usize {
    mlkem768::ciphertext_bytes()
}

pub fn kyber_shared_secret_bytes() -> usize {
    mlkem768::shared_secret_bytes()
}

pub fn hybrid_public_key_bytes() -> usize {
    X25519_PUBLIC_KEY_BYTES + kyber_public_key_bytes()
}

pub struct HybridKeyExchange {
    x25519_secret: StaticSecret,
    kyber_secret: mlkem768::SecretKey,
}

impl HybridKeyExchange {
    pub fn generate_keypair() -> (Self, Vec<u8>) {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let (kyber_public, kyber_secret) = mlkem768::keypair();

        let mut public_key = Vec::with_capacity(hybrid_public_key_bytes());
        public_key.extend_from_slice(x25519_public.as_bytes());
        public_key.extend_from_slice(kyber_public.as_bytes());

        (
            Self {
                x25519_secret,
                kyber_secret,
            },
            public_key,
        )
    }

    pub fn encapsulate(&self, peer_public: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let (peer_x25519, peer_kyber_pk) = parse_peer_public(peer_public)?;

        let x25519_shared = self.x25519_secret.diffie_hellman(&peer_x25519);
        let (kyber_shared, kyber_ct) = mlkem768::encapsulate(&peer_kyber_pk);

        let combined = derive_hybrid_key(x25519_shared.as_bytes(), kyber_shared.as_bytes())?;
        Ok((kyber_ct.as_bytes().to_vec(), combined))
    }

    pub fn decapsulate(&self, peer_public: &[u8], kyber_ct: &[u8]) -> Result<[u8; 32]> {
        let (peer_x25519, _peer_kyber_pk) = parse_peer_public(peer_public)?;
        if kyber_ct.len() != kyber_ciphertext_bytes() {
            return Err(PostQuantumError::KyberCiphertextLengthMismatch {
                expected: kyber_ciphertext_bytes(),
                got: kyber_ct.len(),
            });
        }

        let ct = mlkem768::Ciphertext::from_bytes(kyber_ct)
            .map_err(|_| PostQuantumError::InvalidKyberCiphertext)?;
        let kyber_shared = mlkem768::decapsulate(&ct, &self.kyber_secret);
        let x25519_shared = self.x25519_secret.diffie_hellman(&peer_x25519);

        derive_hybrid_key(x25519_shared.as_bytes(), kyber_shared.as_bytes())
    }
}

fn parse_peer_public(peer_public: &[u8]) -> Result<(X25519PublicKey, mlkem768::PublicKey)> {
    let expected = hybrid_public_key_bytes();
    if peer_public.len() != expected {
        return Err(PostQuantumError::HybridPublicKeyLengthMismatch {
            expected,
            got: peer_public.len(),
        });
    }

    let (x25519_bytes, kyber_bytes) = peer_public.split_at(X25519_PUBLIC_KEY_BYTES);
    let x25519_bytes: [u8; 32] = x25519_bytes
        .try_into()
        .map_err(|_| PostQuantumError::InvalidX25519PublicKeyLength)?;
    let x25519_pk = X25519PublicKey::from(x25519_bytes);
    let kyber_pk = mlkem768::PublicKey::from_bytes(kyber_bytes)
        .map_err(|_| PostQuantumError::InvalidKyberPublicKey)?;

    Ok((x25519_pk, kyber_pk))
}

fn derive_hybrid_key(x25519_shared: &[u8; 32], kyber_shared: &[u8]) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + kyber_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);

    let hk = Hkdf::<Sha256>::new(Some(b"hs/pq-hybrid/v1"), &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"hs/pq-hybrid/key", &mut out)
        .map_err(|e| PostQuantumError::HkdfExpand(format!("{:?}", e)))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange_roundtrip() {
        let (alice, alice_pub) = HybridKeyExchange::generate_keypair();
        let (bob, bob_pub) = HybridKeyExchange::generate_keypair();

        let (ct, alice_key) = alice.encapsulate(&bob_pub).unwrap();
        let bob_key = bob.decapsulate(&alice_pub, &ct).unwrap();

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_public_key_length_validation() {
        let (alice, _alice_pub) = HybridKeyExchange::generate_keypair();
        let bad_peer = vec![0u8; 10];
        let err = alice.encapsulate(&bad_peer).unwrap_err();
        assert!(err
            .to_string()
            .contains("Hybrid public key length mismatch"));
    }
}
