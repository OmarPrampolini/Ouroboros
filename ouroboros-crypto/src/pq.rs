use zeroize::Zeroizing;

use crate::CryptoError;

#[derive(Debug, Clone)]
pub struct KyberKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "post-quantum")]
use pqcrypto_mlkem::mlkem1024;
#[cfg(feature = "post-quantum")]
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

#[cfg(feature = "post-quantum")]
pub fn kyber1024_keypair() -> Result<KyberKeypair, CryptoError> {
    let (public_key, secret_key) = mlkem1024::keypair();

    Ok(KyberKeypair {
        public_key: public_key.as_bytes().to_vec(),
        secret_key: Zeroizing::new(secret_key.as_bytes().to_vec()),
    })
}

#[cfg(not(feature = "post-quantum"))]
pub fn kyber1024_keypair() -> Result<KyberKeypair, CryptoError> {
    Err(CryptoError::FeatureDisabled)
}

#[cfg(feature = "post-quantum")]
pub fn kyber1024_encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let public_key = mlkem1024::PublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("invalid Kyber public key"))?;

    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public_key);
    Ok((
        ciphertext.as_bytes().to_vec(),
        Zeroizing::new(shared_secret.as_bytes().to_vec()),
    ))
}

#[cfg(not(feature = "post-quantum"))]
pub fn kyber1024_encapsulate(
    _public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    Err(CryptoError::FeatureDisabled)
}

#[cfg(feature = "post-quantum")]
pub fn kyber1024_decapsulate(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let ciphertext = mlkem1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| CryptoError::InvalidInput("invalid Kyber ciphertext"))?;
    let secret_key = mlkem1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| CryptoError::InvalidInput("invalid Kyber secret key"))?;

    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret_key);
    Ok(Zeroizing::new(shared_secret.as_bytes().to_vec()))
}

#[cfg(not(feature = "post-quantum"))]
pub fn kyber1024_decapsulate(
    _ciphertext: &[u8],
    _secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    Err(CryptoError::FeatureDisabled)
}

#[cfg(test)]
mod tests {
    use super::kyber1024_keypair;
    #[cfg(feature = "post-quantum")]
    use super::{kyber1024_decapsulate, kyber1024_encapsulate};
    #[cfg(not(feature = "post-quantum"))]
    use crate::CryptoError;

    #[cfg(feature = "post-quantum")]
    #[test]
    fn kyber_roundtrip_shared_secret_matches() {
        let keypair = kyber1024_keypair().unwrap();
        let (ciphertext, ss_sender) = kyber1024_encapsulate(&keypair.public_key).unwrap();
        let ss_receiver =
            kyber1024_decapsulate(&ciphertext, keypair.secret_key.as_slice()).unwrap();

        assert_eq!(ss_sender.as_slice(), ss_receiver.as_slice());
    }

    #[cfg(not(feature = "post-quantum"))]
    #[test]
    fn kyber_is_feature_gated() {
        let result = kyber1024_keypair();
        assert!(matches!(result, Err(CryptoError::FeatureDisabled)));
    }
}
