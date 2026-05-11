use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::hash::Hasher;
use std::sync::Mutex;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::kx::{ActiveKeyExchange, NamedGroup, SharedSecret};
use crate::crypto::tls13::Hkdf;
use crate::crypto::{CryptoProvider, HashAlgorithm, SignatureScheme};
use crate::error::{CertificateError, Error};
use crate::msgs::Random;
use crate::verify::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
    SignatureVerificationInput, SignerPublicKey,
};

/// VLESS Reality protocol configuration.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    server_public_key: [u8; 32],
    short_id: Vec<u8>,
    client_version: [u8; 3],
    pub(crate) auth_key_slot: Arc<Mutex<Option<[u8; 32]>>>,
}

impl RealityConfig {
    /// Create a new Reality configuration.
    pub fn new(server_public_key: [u8; 32], short_id: Vec<u8>) -> Result<Self, RealityConfigError> {
        if short_id.len() > 8 {
            return Err(RealityConfigError::ShortIdTooLong);
        }

        Ok(Self {
            server_public_key,
            short_id,
            client_version: [0, 0, 0],
            auth_key_slot: Arc::new(Mutex::new(None)),
        })
    }

    /// Override the three-byte client version embedded in the Reality payload.
    pub fn with_client_version(mut self, version: [u8; 3]) -> Self {
        self.client_version = version;
        self
    }
}

/// Errors that can occur when creating a Reality configuration.
#[derive(Debug)]
pub enum RealityConfigError {
    /// The short ID must fit in eight bytes.
    ShortIdTooLong,
    /// A cryptographic operation failed.
    CryptoError(String),
}

impl fmt::Display for RealityConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortIdTooLong => write!(f, "Reality short_id must be at most 8 bytes"),
            Self::CryptoError(msg) => write!(f, "Reality crypto error: {msg}"),
        }
    }
}

impl std::error::Error for RealityConfigError {}

#[derive(Clone)]
pub(crate) struct RealitySessionState {
    config: Arc<RealityConfig>,
    client_private: [u8; 32],
    client_public: [u8; 32],
    auth_shared_secret: [u8; 32],
}

impl RealitySessionState {
    pub(crate) fn new(
        config: Arc<RealityConfig>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        let mut client_private = [0u8; 32];
        provider
            .secure_random
            .fill(&mut client_private)?;

        let client_public = PublicKey::from(&StaticSecret::from(client_private)).to_bytes();
        let auth_shared_secret = x25519_ecdh(&client_private, &config.server_public_key);

        Ok(Self {
            config,
            client_private,
            client_public,
            auth_shared_secret,
        })
    }

    pub(crate) fn into_key_exchange(self) -> Box<dyn ActiveKeyExchange> {
        Box::new(RealityKeyExchange {
            client_private: self.client_private,
            client_public: self.client_public,
        })
    }

    pub(crate) fn compute_session_id(
        &self,
        random: &Random,
        hello_bytes: &[u8],
        hkdf: &dyn Hkdf,
        timestamp: u32,
    ) -> Result<[u8; 32], Error> {
        let salt = &random.0[..20];
        let auth_key_expander = hkdf.extract_from_secret(Some(salt), &self.auth_shared_secret);

        let mut auth_key = [0u8; 32];
        auth_key_expander
            .expand_slice(&[b"REALITY"], &mut auth_key)
            .map_err(|_| Error::General("HKDF expand failed".into()))?;

        let mut plaintext = [0u8; 16];
        plaintext[..3].copy_from_slice(&self.config.client_version);
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..8 + self.config.short_id.len()].copy_from_slice(&self.config.short_id);

        let nonce: [u8; 12] = random.0[20..32]
            .try_into()
            .map_err(|_| Error::General("invalid Reality nonce".into()))?;
        let encrypted = aes_256_gcm_encrypt(&auth_key, &nonce, hello_bytes, &plaintext)?;

        if let Ok(mut slot) = self.config.auth_key_slot.lock() {
            *slot = Some(auth_key);
        }

        Ok(encrypted)
    }
}

struct RealityKeyExchange {
    client_private: [u8; 32],
    client_public: [u8; 32],
}

impl ActiveKeyExchange for RealityKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer_public: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::General("invalid peer public key length".into()))?;
        Ok(SharedSecret::from(
            &x25519_ecdh(&self.client_private, &peer_public)[..],
        ))
    }

    fn pub_key(&self) -> &[u8] {
        &self.client_public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

pub(crate) fn get_hkdf_sha256_from_provider(
    provider: &CryptoProvider,
) -> Result<&'static dyn Hkdf, Error> {
    provider
        .tls13_cipher_suites
        .iter()
        .find(|suite| suite.common.hash_provider.algorithm() == HashAlgorithm::SHA256)
        .map(|suite| suite.hkdf_provider)
        .ok_or_else(|| Error::General("Reality requires a TLS1.3 SHA-256 cipher suite".into()))
}

fn x25519_ecdh(private_key: &[u8; 32], peer_public_key: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*private_key)
        .diffie_hellman(&PublicKey::from(*peer_public_key))
        .to_bytes()
}

fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8; 16],
) -> Result<[u8; 32], Error> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::General("Reality AES-256-GCM init failed".into()))?;
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut ciphertext)
        .map_err(|_| Error::General("Reality AES-256-GCM encrypt failed".into()))?;

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&ciphertext);
    out[16..].copy_from_slice(tag.as_slice());
    Ok(out)
}

fn extract_ed25519_pubkey_from_reality_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    const OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    const BIT_STRING_HDR: [u8; 3] = [0x03, 0x21, 0x00];

    let n = cert_der.len();
    if n < OID.len() + BIT_STRING_HDR.len() + 32 {
        return None;
    }

    for i in 0..n.saturating_sub(OID.len()) {
        if cert_der[i..i + OID.len()] != OID {
            continue;
        }

        let search_end = (i + OID.len() + 16).min(n.saturating_sub(BIT_STRING_HDR.len() + 32));
        for j in (i + OID.len())..=search_end {
            if cert_der[j..j + BIT_STRING_HDR.len()] == BIT_STRING_HDR {
                let key_start = j + BIT_STRING_HDR.len();
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&cert_der[key_start..key_start + 32]);
                return Some(pubkey);
            }
        }
    }

    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (lhs, rhs) in a.iter().zip(b.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

fn hmac_sha512(key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("fixed-size HMAC key");
    mac.update(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key
        .verify_strict(message, &signature)
        .is_ok()
}

fn verify_reality_cert(cert: &pki_types::CertificateDer<'_>, auth_key: &[u8; 32]) -> Option<bool> {
    let cert_bytes = cert.as_ref();
    if cert_bytes.len() < 64 {
        return None;
    }

    let pubkey = extract_ed25519_pubkey_from_reality_cert(cert_bytes)?;
    let expected = hmac_sha512(auth_key, &pubkey);
    let cert_tail = &cert_bytes[cert_bytes.len() - 64..];
    Some(constant_time_eq(&expected, cert_tail))
}

/// A [`ServerVerifier`] wrapper that understands Reality certificates.
#[derive(Debug)]
pub(crate) struct RealityServerCertVerifier {
    auth_key_slot: Arc<Mutex<Option<[u8; 32]>>>,
    inner: Arc<dyn ServerVerifier>,
}

impl RealityServerCertVerifier {
    pub(crate) fn new(
        auth_key_slot: Arc<Mutex<Option<[u8; 32]>>>,
        inner: Arc<dyn ServerVerifier>,
    ) -> Arc<Self> {
        Arc::new(Self {
            auth_key_slot,
            inner,
        })
    }
}

impl ServerVerifier for RealityServerCertVerifier {
    fn verify_identity(&self, identity: &ServerIdentity<'_>) -> Result<PeerVerified, Error> {
        let auth_key = self
            .auth_key_slot
            .lock()
            .ok()
            .and_then(|guard| *guard);

        if let (Some(auth_key), crate::crypto::Identity::X509(certificates)) =
            (auth_key, identity.identity)
        {
            if let Some(valid) = verify_reality_cert(&certificates.end_entity, &auth_key) {
                return match valid {
                    true => Ok(PeerVerified::assertion()),
                    false => self.inner.verify_identity(identity),
                };
            }
        }

        self.inner.verify_identity(identity)
    }

    fn verify_tls12_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        if let Ok(valid) = self.inner.verify_tls13_signature(input) {
            return Ok(valid);
        }

        if input.signature.scheme == SignatureScheme::ED25519 {
            if let SignerPublicKey::X509(cert) = input.signer {
                if let Some(pubkey) = extract_ed25519_pubkey_from_reality_cert(cert.as_ref()) {
                    if ed25519_verify(&pubkey, input.message, input.signature.signature()) {
                        return Ok(HandshakeSignatureValid::assertion());
                    }
                }
            }
        }

        Err(Error::InvalidCertificate(CertificateError::BadSignature))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes = self.inner.supported_verify_schemes();
        if !schemes.contains(&SignatureScheme::ED25519) {
            schemes.push(SignatureScheme::ED25519);
        }
        schemes
    }

    fn request_ocsp_response(&self) -> bool {
        self.inner.request_ocsp_response()
    }

    fn supported_certificate_types(&self) -> &'static [crate::enums::CertificateType] {
        self.inner.supported_certificate_types()
    }

    fn root_hint_subjects(&self) -> Option<crate::sync::Arc<[crate::DistinguishedName]>> {
        self.inner.root_hint_subjects()
    }

    fn hash_config(&self, h: &mut dyn Hasher) {
        self.inner.hash_config(h)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_reality_config_creation() {
        let config = RealityConfig::new([1u8; 32], vec![0x12, 0x34]).unwrap();
        assert_eq!(config.short_id.len(), 2);
        assert_eq!(config.client_version, [0, 0, 0]);
    }

    #[test]
    fn test_short_id_too_long() {
        assert!(matches!(
            RealityConfig::new([1u8; 32], vec![0u8; 9]),
            Err(RealityConfigError::ShortIdTooLong)
        ));
    }

    #[test]
    fn test_with_client_version() {
        let config = RealityConfig::new([1u8; 32], vec![0x12])
            .unwrap()
            .with_client_version([1, 2, 3]);
        assert_eq!(config.client_version, [1, 2, 3]);
    }
}
