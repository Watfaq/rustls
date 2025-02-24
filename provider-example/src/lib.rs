#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::sync::Arc;

use watfaq_rustls::crypto::CryptoProvider;
use watfaq_rustls::pki_types::PrivateKeyDer;

mod aead;
mod hash;
mod hmac;
pub mod hpke;
mod kx;
mod sign;
mod verify;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

#[derive(Debug)]
struct Provider;

impl watfaq_rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), watfaq_rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| watfaq_rustls::crypto::GetRandomFailed)
    }
}

impl watfaq_rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn watfaq_rustls::sign::SigningKey>, watfaq_rustls::Error> {
        Ok(Arc::new(
            sign::EcdsaSigningKeyP256::try_from(key_der).map_err(|err| {
                #[cfg(feature = "std")]
                let err = watfaq_rustls::OtherError(Arc::new(err));
                #[cfg(not(feature = "std"))]
                let err = watfaq_rustls::Error::General(alloc::format!("{}", err));
                err
            })?,
        ))
    }
}

static ALL_CIPHER_SUITES: &[watfaq_rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: watfaq_rustls::SupportedCipherSuite =
    watfaq_rustls::SupportedCipherSuite::Tls13(&watfaq_rustls::Tls13CipherSuite {
        common: watfaq_rustls::crypto::CipherSuiteCommon {
            suite: watfaq_rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &watfaq_rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: watfaq_rustls::SupportedCipherSuite =
    watfaq_rustls::SupportedCipherSuite::Tls12(&watfaq_rustls::Tls12CipherSuite {
        common: watfaq_rustls::crypto::CipherSuiteCommon {
            suite: watfaq_rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        kx: watfaq_rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            watfaq_rustls::SignatureScheme::RSA_PSS_SHA256,
            watfaq_rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        prf_provider: &watfaq_rustls::crypto::tls12::PrfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
    });
