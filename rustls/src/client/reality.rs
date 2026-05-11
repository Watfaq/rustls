//! VLESS Reality protocol implementation
//!
//! Reality is a protocol extension that provides enhanced privacy by encrypting
//! the TLS session ID using a shared secret derived from X25519 ECDH with the
//! server's static public key.
//!
//! # Protocol Overview
//!
//! The Reality protocol uses a single X25519 keypair for two purposes:
//!
//! ## 1. Reality Authentication (session_id encryption)
//! 1. Client generates ephemeral X25519 keypair (client_private, client_public)
//! 2. Client performs ECDH with server's **static public key**: auth_shared_secret = ECDH(client_private, server_static_public_key)
//! 3. Client derives auth_key using HKDF-SHA256(auth_shared_secret, hello_random[:20], "REALITY") → 32 bytes
//! 4. Client constructs 16-byte plaintext: [version(3) | reserved(1) | timestamp(4) | short_id(8)]
//! 5. Client encrypts plaintext using AES-256-GCM with:
//!    - key: auth_key
//!    - nonce: hello_random[20..32]
//!    - aad: full ClientHello bytes
//! 6. Result (ciphertext + tag = 32 bytes) becomes the session_id
//!
//! ## 2. TLS Key Exchange (standard TLS 1.3 ECDHE)
//! 7. Client's public key (client_public) is sent in the ClientHello key_share extension
//! 8. Server responds with ServerHello containing its ephemeral public key
//! 9. Client performs ECDH with server's **ephemeral public key**: tls_shared_secret = ECDH(client_private, server_hello_public_key)
//! 10. tls_shared_secret is used for the TLS 1.3 key schedule (handshake and application traffic keys)
//!
//! **Key Point**: The same client_private is used for both ECDH operations, but with different
//! server public keys, resulting in two different shared secrets for different purposes.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::crypto::tls13::Hkdf;
use crate::crypto::{ActiveKeyExchange, CryptoProvider, SecureRandom, SharedSecret};
use crate::enums::CipherSuite;
use crate::error::Error;
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::{KeyShareEntry, Random};
use crate::SupportedCipherSuite;

#[cfg(feature = "std")]
use std::sync::Mutex;

/// VLESS Reality protocol configuration
///
/// This configuration specifies the parameters needed for the Reality protocol,
/// including the server's public key and client identification.
///
/// # Example
///
/// ```no_run
/// use watfaq_rustls::client::RealityConfig;
///
/// let server_pubkey = [0u8; 32]; // Server's X25519 public key
/// let short_id = vec![0x12, 0x34, 0x56, 0x78];
///
/// let config = RealityConfig::new(server_pubkey, short_id)
///     .expect("valid configuration");
/// ```
///
/// # Security Considerations
///
/// - The server public key must be obtained through a secure channel
/// - The short_id serves as a client identifier; keep it confidential
/// - Reality requires X25519 key exchange support in the crypto provider
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// Server's X25519 public key (32 bytes)
    server_public_key: [u8; 32],
    /// Client identifier (max 8 bytes, zero-padded in protocol)
    short_id: Vec<u8>,
    /// Protocol version (3 bytes, default [0, 0, 0])
    client_version: [u8; 3],
    /// Shared slot for the derived auth_key, populated during handshake
    /// and consumed by RealityServerCertVerifier
    #[cfg(feature = "std")]
    pub(crate) auth_key_slot: Arc<Mutex<Option<[u8; 32]>>>,
}

impl RealityConfig {
    /// Create a new Reality configuration
    ///
    /// # Parameters
    ///
    /// - `server_public_key`: The server's X25519 public key (32 bytes)
    /// - `short_id`: Client identifier, must be at most 8 bytes
    ///
    /// # Errors
    ///
    /// Returns `RealityConfigError::ShortIdTooLong` if `short_id` exceeds 8 bytes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use watfaq_rustls::client::RealityConfig;
    ///
    /// let server_pk = [0u8; 32];
    /// let short_id = vec![0x12, 0x34, 0x56, 0x78];
    /// let config = RealityConfig::new(server_pk, short_id).unwrap();
    /// ```
    pub fn new(server_public_key: [u8; 32], short_id: Vec<u8>) -> Result<Self, RealityConfigError> {
        if short_id.len() > 8 {
            return Err(RealityConfigError::ShortIdTooLong);
        }
        Ok(Self {
            server_public_key,
            short_id,
            client_version: [0, 0, 0],
            #[cfg(feature = "std")]
            auth_key_slot: Arc::new(Mutex::new(None)),
        })
    }

    /// Set the client version field
    ///
    /// The client version is a 3-byte field in the Reality protocol.
    /// Default is `[0, 0, 0]`.
    pub fn with_client_version(mut self, version: [u8; 3]) -> Self {
        self.client_version = version;
        self
    }
}

/// Errors that can occur when creating a Reality configuration
#[derive(Debug)]
pub enum RealityConfigError {
    /// The short_id exceeds the maximum length of 8 bytes
    ShortIdTooLong,
    /// A cryptographic operation failed
    CryptoError(alloc::string::String),
}

impl core::fmt::Display for RealityConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ShortIdTooLong => {
                write!(f, "Reality short_id must be at most 8 bytes")
            }
            Self::CryptoError(msg) => {
                write!(f, "Reality crypto error: {}", msg)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RealityConfigError {}

/// Generate X25519 keypair using x25519-dalek (ring feature)
#[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
fn x25519_generate_keypair(
    secure_random: &dyn SecureRandom,
) -> Result<([u8; 32], [u8; 32]), Error> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut private_bytes = [0u8; 32];
    secure_random.fill(&mut private_bytes)?;

    let secret = StaticSecret::from(private_bytes);
    let public: [u8; 32] = PublicKey::from(&secret).to_bytes();

    Ok((private_bytes, public))
}

/// Perform X25519 ECDH using x25519-dalek (ring feature)
#[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
fn x25519_ecdh(private_key: &[u8; 32], peer_public_key: &[u8; 32]) -> Result<[u8; 32], Error> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(*private_key);
    let peer_public = PublicKey::from(*peer_public_key);
    let shared = secret.diffie_hellman(&peer_public);

    Ok(shared.to_bytes())
}

/// Generate X25519 keypair using aws-lc-rs
#[cfg(feature = "aws_lc_rs")]
fn x25519_generate_keypair(
    secure_random: &dyn SecureRandom,
) -> Result<([u8; 32], [u8; 32]), Error> {
    use aws_lc_rs::agreement;

    // Generate random private key
    let mut private_bytes = [0u8; 32];
    secure_random.fill(&mut private_bytes)?;

    // Compute public key from private key using PrivateKey
    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_bytes)
        .map_err(|_| Error::General("X25519 private key creation failed".into()))?;

    let public_key_bytes = private_key
        .compute_public_key()
        .map_err(|_| Error::General("X25519 public key computation failed".into()))?;

    let mut public = [0u8; 32];
    public.copy_from_slice(public_key_bytes.as_ref());

    Ok((private_bytes, public))
}

/// Perform X25519 ECDH using aws-lc-rs
#[cfg(feature = "aws_lc_rs")]
fn x25519_ecdh(private_key: &[u8; 32], peer_public_key: &[u8; 32]) -> Result<[u8; 32], Error> {
    use aws_lc_rs::agreement;

    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, private_key)
        .map_err(|_| Error::General("X25519 private key creation failed".into()))?;

    let peer_public =
        agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key.as_ref());

    let mut shared_secret = [0u8; 32];
    agreement::agree(&private_key, &peer_public, (), |key_material| {
        shared_secret.copy_from_slice(key_material);
        Ok(())
    })
    .map_err(|_| Error::General("X25519 ECDH failed".into()))?;

    Ok(shared_secret)
}

/// Internal state for Reality protocol during TLS handshake
///
/// This struct holds the ephemeral keys and shared secret needed to compute
/// the Reality session_id.
#[derive(Clone)]
pub(crate) struct RealitySessionState {
    config: Arc<RealityConfig>,
    /// Client's ephemeral X25519 private key (32 bytes)
    client_private: [u8; 32],
    /// Client's ephemeral X25519 public key (32 bytes)
    client_public: [u8; 32],
    /// ECDH shared secret with server's static public key (32 bytes)
    /// Used for Reality authentication (session_id encryption)
    auth_shared_secret: [u8; 32],
}

impl RealitySessionState {
    /// Initialize Reality state by performing X25519 ECDH
    ///
    /// This generates an ephemeral X25519 keypair and performs ECDH with
    /// the server's static public key to derive the auth shared secret.
    pub(crate) fn new(
        config: Arc<RealityConfig>,
        crypto_provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        // Step 1: Generate X25519 keypair
        let (client_private, client_public) =
            x25519_generate_keypair(crypto_provider.secure_random)?;

        // Step 2: Perform ECDH with server's static public key (for Reality authentication)
        let auth_shared_secret = x25519_ecdh(&client_private, &config.server_public_key)?;

        Ok(Self {
            config,
            client_private,
            client_public,
            auth_shared_secret,
        })
    }

    /// Generate KeyShareEntry for ClientHello key_share extension
    ///
    /// Returns a key_share entry containing the client's ephemeral X25519 public key.
    pub(crate) fn key_share_entry(&self) -> KeyShareEntry {
        KeyShareEntry::new(NamedGroup::X25519, self.client_public.to_vec())
    }

    /// Convert Reality state into an ActiveKeyExchange for TLS handshake
    ///
    /// This wraps the Reality X25519 keypair so it can be used in the TLS key schedule.
    pub(crate) fn into_key_exchange(self) -> Box<dyn ActiveKeyExchange> {
        Box::new(RealityKeyExchange {
            client_private: self.client_private,
            client_public: self.client_public,
        })
    }

    /// Compute Reality session_id using the full protocol
    ///
    /// # Parameters
    ///
    /// - `random`: The ClientHello random value (32 bytes)
    /// - `hello_bytes`: The full encoded ClientHello message
    /// - `hkdf`: HKDF-SHA256 provider
    ///
    /// # Returns
    ///
    /// 32 bytes: ciphertext (16 bytes) + authentication tag (16 bytes)
    pub(crate) fn compute_session_id(
        &self,
        random: &Random,
        hello_bytes: &[u8],
        hkdf: &dyn Hkdf,
        time_provider: &dyn crate::time_provider::TimeProvider,
    ) -> Result<[u8; 32], Error> {
        // Step 1: Derive auth_key using HKDF-SHA256
        // auth_key = HKDF(auth_shared_secret, salt=hello_random[:20], info="REALITY")
        // Key is 32 bytes → used with AES-256-GCM (matching Xray reference implementation)
        let salt = &random.0[..20];
        let auth_key_expander = hkdf.extract_from_secret(Some(salt), &self.auth_shared_secret);

        let mut auth_key = [0u8; 32];
        auth_key_expander
            .expand_slice(&[b"REALITY"], &mut auth_key)
            .map_err(|_| Error::General("HKDF expand failed".into()))?;

        // Step 2: Construct plaintext (16 bytes)
        let mut plaintext = [0u8; 16];

        // Bytes [0..3]: client_version (3 bytes) + reserved (1 byte)
        plaintext[0..3].copy_from_slice(&self.config.client_version);
        plaintext[3] = 0; // reserved

        // Bytes [4..8]: Unix timestamp (big-endian u32)
        let timestamp = current_timestamp(time_provider)?;
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());

        // Bytes [8..16]: short_id (zero-padded to 8 bytes)
        let short_id_len = self.config.short_id.len();
        plaintext[8..8 + short_id_len].copy_from_slice(&self.config.short_id);
        // Remaining bytes are already zero

        // Step 3: AES-256-GCM encryption
        // nonce = hello_random[20..32] (12 bytes)
        // aad = full ClientHello bytes
        let nonce: &[u8; 12] = random.0[20..32]
            .try_into()
            .map_err(|_| Error::General("Invalid nonce length".into()))?;

        let result = aes_256_gcm_encrypt(&auth_key, nonce, hello_bytes, &plaintext)?;

        // Store auth_key in the slot so RealityServerCertVerifier can use it
        #[cfg(feature = "std")]
        if let Some(mut slot) = self.config.auth_key_slot.lock().ok() {
            *slot = Some(auth_key);
        }

        Ok(result)
    }
}

/// ActiveKeyExchange implementation for Reality protocol
///
/// This wraps the Reality X25519 keypair to provide it to the TLS key schedule.
/// Reality uses the same X25519 keypair for both:
/// 1. Authentication ECDH with server's static public key (for session_id encryption)
/// 2. TLS ECDH with server's ephemeral public key from ServerHello (for TLS key schedule)
struct RealityKeyExchange {
    client_private: [u8; 32],
    client_public: [u8; 32],
}

impl ActiveKeyExchange for RealityKeyExchange {
    /// Complete the key exchange
    ///
    /// Performs ECDH with the server's ephemeral public key from ServerHello
    /// to derive the TLS shared secret for the key schedule.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // Convert peer_pub_key to [u8; 32]
        let peer_public: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::General("Invalid peer public key length".into()))?;

        // Perform ECDH with ServerHello's ephemeral public key (for TLS key schedule)
        let tls_shared_secret = x25519_ecdh(&self.client_private, &peer_public)?;

        Ok(SharedSecret::from(&tls_shared_secret[..]))
    }

    /// Return the client's public key
    fn pub_key(&self) -> &[u8] {
        &self.client_public
    }

    /// Return the named group (always X25519 for Reality)
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// X25519 ECDH is now handled through the unified CryptoProvider::x25519_provider interface
// No need for provider-specific implementations here

/// AES-256-GCM encryption for Reality session_id
///
/// Encrypts 16-byte plaintext and returns ciphertext + tag (32 bytes total).
/// Uses a 32-byte key, matching the Xray reference implementation which derives
/// a 32-byte AuthKey via HKDF-SHA256 and uses it with AES-256-GCM.
fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8; 16],
) -> Result<[u8; 32], Error> {
    #[cfg(feature = "ring")]
    {
        aes_256_gcm_encrypt_ring(key, nonce, aad, plaintext)
    }

    #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
    {
        aes_256_gcm_encrypt_aws_lc_rs(key, nonce, aad, plaintext)
    }

    #[cfg(not(any(feature = "ring", feature = "aws_lc_rs")))]
    {
        Err(Error::General(
            "Reality requires either 'ring' or 'aws_lc_rs' feature".into(),
        ))
    }
}

/// AES-256-GCM encryption using ring
#[cfg(feature = "ring")]
fn aes_256_gcm_encrypt_ring(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8; 16],
) -> Result<[u8; 32], Error> {
    use ring::aead;

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| Error::General("AES-256-GCM key creation failed".into()))?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.to_vec();
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let aad = aead::Aad::from(aad);

    sealing_key
        .seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|_| Error::General("AES-256-GCM encryption failed".into()))?;

    // in_out now contains: plaintext (16 bytes) + tag (16 bytes) = 32 bytes
    let mut result = [0u8; 32];
    result.copy_from_slice(&in_out);
    Ok(result)
}

/// AES-256-GCM encryption using aws-lc-rs
#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
fn aes_256_gcm_encrypt_aws_lc_rs(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8; 16],
) -> Result<[u8; 32], Error> {
    use aws_lc_rs::aead;

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| Error::General("AES-256-GCM key creation failed".into()))?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.to_vec();
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let aad = aead::Aad::from(aad);

    sealing_key
        .seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|_| Error::General("AES-256-GCM encryption failed".into()))?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&in_out);
    Ok(result)
}

/// Get current Unix timestamp as u32
fn current_timestamp(time_provider: &dyn crate::time_provider::TimeProvider) -> Result<u32, Error> {
    let now = time_provider
        .current_time()
        .ok_or(Error::FailedToGetCurrentTime)?;
    Ok((now.as_secs() % (1u64 << 32)) as u32)
}

/// Get HKDF-SHA256 provider from ClientConfig
pub(crate) fn get_hkdf_sha256_from_config(
    cipher_suites: &[SupportedCipherSuite],
) -> Result<&'static dyn Hkdf, Error> {
    cipher_suites
        .iter()
        .find_map(|suite| {
            if let SupportedCipherSuite::Tls13(tls13) = suite {
                if tls13.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256 {
                    return Some(tls13.hkdf_provider);
                }
            }
            None
        })
        .ok_or_else(|| Error::General("No SHA256 HKDF available for Reality".into()))
}

// ============================================================================
// RealityServerCertVerifier
// ============================================================================

/// Extract the Ed25519 public key bytes from a REALITY server certificate DER.
///
/// REALITY server certs embed an Ed25519 public key. We locate it by searching
/// for the Ed25519 OID (1.3.101.112 = `06 03 2b 65 70`) followed by a BIT
/// STRING header (`03 21 00`) and then 32 bytes of public key material.
fn extract_ed25519_pubkey_from_reality_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Ed25519 OID bytes: 06 03 2b 65 70
    const OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    // BIT STRING: 03 (tag) 21 (length=33) 00 (unused bits=0)
    const BIT_STRING_HDR: [u8; 3] = [0x03, 0x21, 0x00];

    let n = cert_der.len();
    if n < OID.len() + BIT_STRING_HDR.len() + 32 {
        return None;
    }

    for i in 0..n.saturating_sub(OID.len()) {
        if cert_der[i..i + OID.len()] != OID {
            continue;
        }
        // OID found; scan forward a small window for the BIT STRING header
        let search_end = (i + OID.len() + 16).min(n.saturating_sub(BIT_STRING_HDR.len() + 32));
        for j in (i + OID.len())..=search_end {
            if cert_der[j..j + BIT_STRING_HDR.len()] == BIT_STRING_HDR {
                let key_start = j + BIT_STRING_HDR.len();
                if key_start + 32 <= n {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&cert_der[key_start..key_start + 32]);
                    return Some(pubkey);
                }
            }
        }
    }
    None
}

/// Constant-time byte slice comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute HMAC-SHA512 using ring
#[cfg(feature = "ring")]
fn hmac_sha512(key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    use ring::hmac;
    let k = hmac::Key::new(hmac::HMAC_SHA512, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Compute HMAC-SHA512 using aws-lc-rs
#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
fn hmac_sha512(key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    use aws_lc_rs::hmac;
    let k = hmac::Key::new(hmac::HMAC_SHA512, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Verify an Ed25519 signature using ring
#[cfg(feature = "ring")]
fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    use ring::signature;
    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey.as_ref());
    pk.verify(message, signature).is_ok()
}

/// Verify an Ed25519 signature using aws-lc-rs
#[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    use aws_lc_rs::signature;
    let pk = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey.as_ref());
    pk.verify(message, signature).is_ok()
}

/// Check whether a certificate is a valid REALITY server certificate.
///
/// Returns `Some(Ok(...))` if the cert passes REALITY HMAC verification,
/// `None` if it does not look like a REALITY cert (caller should try the
/// inner verifier), and `Some(Err(...))` on internal error.
#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
fn verify_reality_cert(
    cert: &pki_types::CertificateDer<'_>,
    auth_key: &[u8; 32],
) -> Option<Result<crate::verify::ServerCertVerified, Error>> {
    let cert_bytes = cert.as_ref();
    if cert_bytes.len() < 64 {
        return None;
    }

    let pubkey = extract_ed25519_pubkey_from_reality_cert(cert_bytes)?;

    let expected = hmac_sha512(auth_key, &pubkey);
    let cert_tail = &cert_bytes[cert_bytes.len() - 64..];

    if constant_time_eq(&expected, cert_tail) {
        Some(Ok(crate::verify::ServerCertVerified::assertion()))
    } else {
        // HMAC mismatch — not a Reality cert for this session
        None
    }
}

#[cfg(not(any(feature = "ring", feature = "aws_lc_rs")))]
fn verify_reality_cert(
    _cert: &pki_types::CertificateDer<'_>,
    _auth_key: &[u8; 32],
) -> Option<Result<crate::verify::ServerCertVerified, Error>> {
    None
}

/// A `ServerCertVerifier` that understands REALITY's custom certificate format.
///
/// REALITY servers present a minimal Ed25519 X.509v1 certificate whose last
/// 64 bytes are overwritten with `HMAC-SHA512(auth_key, ed25519_public_key)`.
/// Standard verifiers (e.g. webpki) reject this cert as `BadEncoding` because
/// X.509v1 certs lack the `version` field that webpki requires.
///
/// This verifier first attempts the REALITY HMAC check; if it passes the cert
/// is accepted without a CA chain. If it fails (normal TLS destination), the
/// inner verifier is tried.
///
/// `verify_tls13_signature` similarly tries the inner verifier first; if that
/// fails it falls back to direct Ed25519 verification using the pubkey found
/// in the cert DER.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct RealityServerCertVerifier {
    /// Slot containing the auth_key computed during ClientHello construction
    auth_key_slot: Arc<Mutex<Option<[u8; 32]>>>,
    /// Fallback verifier (used when the cert is not a REALITY cert)
    inner: Arc<dyn crate::verify::ServerCertVerifier>,
}

#[cfg(feature = "std")]
impl RealityServerCertVerifier {
    /// Create a new verifier wrapping `inner`.
    pub fn new(
        auth_key_slot: Arc<Mutex<Option<[u8; 32]>>>,
        inner: Arc<dyn crate::verify::ServerCertVerifier>,
    ) -> Arc<Self> {
        Arc::new(Self { auth_key_slot, inner })
    }
}

#[cfg(feature = "std")]
impl crate::verify::ServerCertVerifier for RealityServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        intermediates: &[pki_types::CertificateDer<'_>],
        server_name: &pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: pki_types::UnixTime,
    ) -> Result<crate::verify::ServerCertVerified, Error> {
        // Try REALITY cert verification if we have the auth_key
        let auth_key: Option<[u8; 32]> = self
            .auth_key_slot
            .lock()
            .ok()
            .and_then(|g| *g);

        if let Some(ref key) = auth_key {
            if let Some(result) = verify_reality_cert(end_entity, key) {
                return result;
            }
        }

        // Not a REALITY cert — fall back to the inner verifier
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &crate::verify::DigitallySignedStruct,
    ) -> Result<crate::verify::HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &crate::verify::DigitallySignedStruct,
    ) -> Result<crate::verify::HandshakeSignatureValid, Error> {
        // Try the inner verifier first (handles normal TLS destinations)
        if let Ok(valid) = self.inner.verify_tls13_signature(message, cert, dss) {
            return Ok(valid);
        }

        // Inner verifier failed; try direct Ed25519 verification for REALITY certs
        if dss.scheme == crate::enums::SignatureScheme::ED25519 {
            if let Some(pubkey) = extract_ed25519_pubkey_from_reality_cert(cert.as_ref()) {
                #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
                if ed25519_verify(&pubkey, message, dss.signature()) {
                    return Ok(crate::verify::HandshakeSignatureValid::assertion());
                }
            }
        }

        Err(Error::InvalidCertificate(
            crate::error::CertificateError::BadSignature,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<crate::enums::SignatureScheme> {
        let mut schemes = self.inner.supported_verify_schemes();
        if !schemes.contains(&crate::enums::SignatureScheme::ED25519) {
            schemes.push(crate::enums::SignatureScheme::ED25519);
        }
        schemes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_reality_config_creation() {
        let server_pk = [1u8; 32];
        let short_id = vec![0x12, 0x34];
        let config = RealityConfig::new(server_pk, short_id).unwrap();
        assert_eq!(config.short_id.len(), 2);
        assert_eq!(config.client_version, [0, 0, 0]);
    }

    #[test]
    fn test_short_id_too_long() {
        let server_pk = [1u8; 32];
        let short_id = vec![0u8; 9]; // Too long
        assert!(matches!(
            RealityConfig::new(server_pk, short_id),
            Err(RealityConfigError::ShortIdTooLong)
        ));
    }

    #[test]
    fn test_with_client_version() {
        let server_pk = [1u8; 32];
        let short_id = vec![0x12];
        let config = RealityConfig::new(server_pk, short_id)
            .unwrap()
            .with_client_version([1, 2, 3]);
        assert_eq!(config.client_version, [1, 2, 3]);
    }

    #[test]
    fn test_short_id_max_length() {
        let server_pk = [1u8; 32];
        let short_id = vec![0u8; 8]; // Exactly 8 bytes - should work
        assert!(RealityConfig::new(server_pk, short_id).is_ok());
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn test_x25519_keypair_and_ecdh() {
        // Install provider
        #[cfg(feature = "ring")]
        let _ = crate::crypto::ring::default_provider().install_default();
        #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
        let _ = crate::crypto::aws_lc_rs::default_provider().install_default();

        let provider = CryptoProvider::get_default().unwrap();

        // Test keypair generation
        let result = x25519_generate_keypair(provider.secure_random);
        assert!(result.is_ok());
        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 32);

        // Test ECDH with a test peer public key
        let peer_public = [2u8; 32];
        let result = x25519_ecdh(&private_key, &peer_public);
        assert!(result.is_ok());
        let shared_secret = result.unwrap();
        assert_eq!(shared_secret.len(), 32);
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn test_reality_two_ecdh_operations() {
        // Install provider
        #[cfg(feature = "ring")]
        let _ = crate::crypto::ring::default_provider().install_default();
        #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
        let _ = crate::crypto::aws_lc_rs::default_provider().install_default();

        let provider = CryptoProvider::get_default().unwrap();

        // Simulate server's static and ephemeral public keys
        let server_static_pubkey = [0xAAu8; 32];
        let server_ephemeral_pubkey = [0xBBu8; 32];

        // Generate client keypair
        let (client_private, _client_public) =
            x25519_generate_keypair(provider.secure_random).unwrap();

        // Perform ECDH with server's static public key (for Reality authentication)
        let auth_secret = x25519_ecdh(&client_private, &server_static_pubkey).unwrap();

        // Perform ECDH with server's ephemeral public key (for TLS key schedule)
        let tls_secret = x25519_ecdh(&client_private, &server_ephemeral_pubkey).unwrap();

        // The two shared secrets should be different
        assert_ne!(auth_secret, tls_secret);
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn test_aes_256_gcm_encryption() {
        // Test AES-256-GCM encryption produces 32-byte output (16 bytes ciphertext + 16 bytes tag)
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"test aad";
        let plaintext = [0u8; 16];

        let result = aes_256_gcm_encrypt(&key, &nonce, aad, &plaintext);
        assert!(result.is_ok());
        let ciphertext_with_tag = result.unwrap();
        assert_eq!(ciphertext_with_tag.len(), 32);
    }

    #[test]
    fn test_session_id_plaintext_structure() {
        // Test that plaintext is constructed correctly
        let server_pk = [1u8; 32];
        let short_id = vec![0x12, 0x34, 0x56, 0x78];
        let config = RealityConfig::new(server_pk, short_id)
            .unwrap()
            .with_client_version([1, 2, 3]);

        // Verify config structure
        assert_eq!(config.client_version, [1, 2, 3]);
        assert_eq!(config.short_id.len(), 4);

        // Verify plaintext would have correct layout:
        // [0..3]: client_version + reserved
        // [4..8]: timestamp
        // [8..16]: short_id (zero-padded)
        let mut plaintext = [0u8; 16];
        plaintext[0..3].copy_from_slice(&config.client_version);
        plaintext[3] = 0; // reserved
                          // Skip timestamp for this test
        plaintext[8..12].copy_from_slice(&config.short_id);
        // Rest should be zeros (padding)

        assert_eq!(plaintext[0], 1);
        assert_eq!(plaintext[1], 2);
        assert_eq!(plaintext[2], 3);
        assert_eq!(plaintext[3], 0);
        assert_eq!(plaintext[8], 0x12);
        assert_eq!(plaintext[9], 0x34);
        assert_eq!(plaintext[10], 0x56);
        assert_eq!(plaintext[11], 0x78);
        assert_eq!(plaintext[12], 0);
        assert_eq!(plaintext[15], 0);
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn test_reality_session_state_creation() {
        use crate::crypto::CryptoProvider;

        // Install default provider
        #[cfg(feature = "ring")]
        let _ = crate::crypto::ring::default_provider().install_default();
        #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
        let _ = crate::crypto::aws_lc_rs::default_provider().install_default();

        let server_pk = [1u8; 32];
        let short_id = vec![0x12, 0x34];
        let config = Arc::new(RealityConfig::new(server_pk, short_id).unwrap());

        // Get the default crypto provider
        let provider = CryptoProvider::get_default().expect("No default crypto provider installed");

        let state = RealitySessionState::new(config, provider);
        assert!(state.is_ok());

        let state = state.unwrap();
        assert_eq!(state.client_private.len(), 32);
        assert_eq!(state.client_public.len(), 32);
        assert_eq!(state.auth_shared_secret.len(), 32);
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn test_key_share_entry_generation() {
        use crate::crypto::CryptoProvider;
        use crate::msgs::enums::NamedGroup;

        // Install default provider
        #[cfg(feature = "ring")]
        let _ = crate::crypto::ring::default_provider().install_default();
        #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
        let _ = crate::crypto::aws_lc_rs::default_provider().install_default();

        let server_pk = [1u8; 32];
        let short_id = vec![0x12, 0x34];
        let config = Arc::new(RealityConfig::new(server_pk, short_id).unwrap());

        let provider = CryptoProvider::get_default().expect("No default crypto provider installed");

        let state = RealitySessionState::new(config, provider).unwrap();
        let key_share = state.key_share_entry();

        // Verify key_share uses X25519
        assert_eq!(key_share.group, NamedGroup::X25519);
        // Verify key_share payload is 32 bytes (X25519 public key)
        assert_eq!(key_share.payload.0.len(), 32);
    }

    #[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
    #[test]
    fn test_compute_session_id_output_length() {
        use crate::crypto::CryptoProvider;
        use crate::msgs::handshake::Random;
        use crate::time_provider::TimeProvider;

        #[derive(Debug)]
        struct MockTimeProvider;
        impl TimeProvider for MockTimeProvider {
            fn current_time(&self) -> Option<pki_types::UnixTime> {
                Some(pki_types::UnixTime::since_unix_epoch(
                    core::time::Duration::from_secs(1234567890),
                ))
            }
        }

        // Install default provider
        #[cfg(feature = "ring")]
        let _ = crate::crypto::ring::default_provider().install_default();
        #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
        let _ = crate::crypto::aws_lc_rs::default_provider().install_default();

        let server_pk = [1u8; 32];
        let short_id = vec![0x12, 0x34, 0x56, 0x78];
        let config = Arc::new(RealityConfig::new(server_pk, short_id).unwrap());

        let provider = CryptoProvider::get_default().expect("No default crypto provider installed");

        let state = RealitySessionState::new(config.clone(), provider).unwrap();

        // Create a mock random value
        let random = Random([0u8; 32]);

        // Create mock ClientHello bytes
        let hello_bytes = vec![0u8; 100];

        // Get HKDF provider
        let hkdf = get_hkdf_sha256_from_config(&provider.cipher_suites);
        assert!(hkdf.is_ok());
        let hkdf = hkdf.unwrap();

        let time_provider = MockTimeProvider;

        // Compute session_id
        let session_id = state.compute_session_id(&random, &hello_bytes, hkdf, &time_provider);
        assert!(session_id.is_ok());

        let session_id = session_id.unwrap();
        // Verify session_id is exactly 32 bytes (16 bytes ciphertext + 16 bytes tag)
        assert_eq!(session_id.len(), 32);
    }
}
