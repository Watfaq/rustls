#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use pki_types::{CertificateDer, ServerName};

use crate::client::{ClientConfig, ClientConnection, Resumption, Tls12Resumption};
use crate::crypto::CryptoProvider;
use crate::enums::{CipherSuite, ProtocolVersion, SignatureScheme};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::Reader;
use crate::msgs::enums::{Compression, NamedGroup};
use crate::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, HelloRetryRequest, Random,
    ServerHelloPayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload, OutboundOpaqueMessage};
use crate::sync::Arc;
use crate::{Error, PeerIncompatible, PeerMisbehaved, RootCertStore};

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use std::sync::OnceLock;

    use super::super::*;
    use crate::client::AlwaysResolvesClientRawPublicKeys;
    use crate::crypto::cipher::MessageEncrypter;
    use crate::crypto::tls13::OkmBlock;
    use crate::enums::CertificateType;
    use crate::msgs::base::PayloadU8;
    use crate::msgs::enums::ECCurveType;
    use crate::msgs::handshake::{
        CertificateChain, EcParameters, HelloRetryRequestExtensions, KeyShareEntry,
        ServerEcdhParams, ServerExtensions, ServerKeyExchange, ServerKeyExchangeParams,
        ServerKeyExchangePayload,
    };
    use crate::msgs::message::PlainMessage;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{PrivateKeyDer, UnixTime};
    use crate::sign::CertifiedKey;
    use crate::tls13::key_schedule::{derive_traffic_iv, derive_traffic_key};
    use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use crate::{DigitallySignedStruct, DistinguishedName, KeyLog, version};

    /// Tests that session_ticket(35) extension
    /// is not sent if the client does not support TLS 1.2.
    #[test]
    fn test_no_session_ticket_request_on_tls_1_3() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.resumption = Resumption::in_memory_sessions(128)
            .tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(ch.extensions.session_ticket.is_none());
    }

    #[test]
    fn test_no_renegotiation_scsv_on_tls_1_3() {
        let ch = client_hello_sent_for_config(
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth(),
        )
        .unwrap();
        assert!(
            !ch.cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        );
    }

    #[test]
    fn test_client_does_not_offer_sha1() {
        for version in crate::ALL_VERSIONS {
            let config =
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots())
                    .with_no_client_auth();
            let ch = client_hello_sent_for_config(config).unwrap();
            assert!(
                !ch.extensions
                    .signature_schemes
                    .as_ref()
                    .unwrap()
                    .contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }

    #[test]
    fn test_client_rejects_hrr_with_varied_session_id() {
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        // server replies with HRR, but does not echo `session_id` as required.
        let hrr = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: HelloRetryRequestExtensions {
                        cookie: Some(PayloadU16::new(vec![1, 2, 3, 4])),
                        ..HelloRetryRequestExtensions::default()
                    },
                }),
            )),
        };

        conn.read_tls(&mut hrr.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId.into()
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }

        let config = Arc::new(config);
        let mut conn =
            ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random::new(config.provider.secure_random).unwrap(),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions::default()),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into())
        );
    }

    #[test]
    fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
        let cas_sending_server_verifier =
            ServerVerifierWithAuthorityNames(vec![DistinguishedName::from(b"hello".to_vec())]);

        for (protocol_version, cas_extension_expected) in
            [(&version::TLS12, false), (&version::TLS13, true)]
        {
            let client_hello = client_hello_sent_for_config(
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[protocol_version])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(cas_sending_server_verifier.clone()))
                    .with_no_client_auth(),
            )
            .unwrap();
            assert_eq!(
                client_hello
                    .extensions
                    .certificate_authority_names
                    .is_some(),
                cas_extension_expected
            );
        }
    }

    /// Regression test for <https://github.com/seanmonstar/reqwest/issues/2191>
    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_with_custom_verifier_can_accept_ecdsa_sha1_signatures() {
        let verifier = Arc::new(ExpectSha1EcdsaVerifier::default());
        let config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let cert = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::Certificate(CertificateChain(vec![CertificateDer::from(
                    &b"does not matter"[..],
                )])),
            )),
        };
        conn.read_tls(&mut cert.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_kx = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(
                    ServerKeyExchange {
                        dss: DigitallySignedStruct::new(
                            SignatureScheme::ECDSA_SHA1_Legacy,
                            b"also does not matter".to_vec(),
                        ),
                        params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
                            curve_params: EcParameters {
                                curve_type: ECCurveType::NamedCurve,
                                named_group: NamedGroup::X25519,
                            },
                            public: PayloadU8::new(vec![0xab; 32]),
                        }),
                    },
                )),
            )),
        };
        conn.read_tls(&mut server_kx.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_done = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHelloDone,
            )),
        };
        conn.read_tls(&mut server_done.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        assert!(
            verifier
                .seen_sha1_signature
                .load(Ordering::SeqCst)
        );
    }

    #[derive(Debug, Default)]
    struct ExpectSha1EcdsaVerifier {
        seen_sha1_signature: AtomicBool,
    }

    impl ServerCertVerifier for ExpectSha1EcdsaVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            assert_eq!(dss.scheme, SignatureScheme::ECDSA_SHA1_Legacy);
            self.seen_sha1_signature
                .store(true, Ordering::SeqCst);
            Ok(HandshakeSignatureValid::assertion())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_SHA1_Legacy]
        }
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions::default()),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::X509),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::X509),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_accepts_rpk_server() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::RawPublicKey),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Ok(())
        );
    }

    fn client_requiring_rpk_receives_server_ee(
        encrypted_extensions: ServerExtensions<'_>,
    ) -> Result<(), Error> {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut conn = ClientConnection::new(
            client_config_for_rpk(fake_server_crypto.clone()).into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(encrypted_extensions)),
            )),
        };

        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let enc_ee = encrypter
            .encrypt(PlainMessage::from(ee).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut enc_ee.encode().as_slice())
            .unwrap();
        conn.process_new_packets().map(|_| ())
    }

    fn client_config_for_rpk(key_log: Arc<dyn KeyLog>) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifierRequiringRpk))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
                client_certified_key(),
            ))));
        config.key_log = key_log;
        config
    }

    fn client_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(client_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new(public_key_as_cert, key)
    }

    fn client_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/client.key").as_slice(),
        )
        .unwrap()
    }

    fn x25519_provider() -> CryptoProvider {
        // ensures X25519 is offered irrespective of cfg(feature = "fips"), which eases
        // creation of fake server messages.
        CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        }
    }

    #[derive(Clone, Debug)]
    struct ServerVerifierWithAuthorityNames(Vec<DistinguishedName>);

    impl ServerCertVerifier for ServerVerifierWithAuthorityNames {
        fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
            Some(self.0.as_slice())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }
    }

    #[derive(Debug)]
    struct ServerVerifierRequiringRpk;

    impl ServerCertVerifier for ServerVerifierRequiringRpk {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct FakeServerCrypto {
        server_handshake_secret: OnceLock<Vec<u8>>,
    }

    impl FakeServerCrypto {
        fn new() -> Self {
            Self {
                server_handshake_secret: OnceLock::new(),
            }
        }

        fn server_handshake_encrypter(&self) -> Box<dyn MessageEncrypter> {
            let cipher_suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();

            let secret = self
                .server_handshake_secret
                .get()
                .unwrap();

            let expander = cipher_suite
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(secret));

            // Derive Encrypter
            let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
            let iv = derive_traffic_iv(expander.as_ref());
            cipher_suite.aead_alg.encrypter(key, iv)
        }
    }

    impl KeyLog for FakeServerCrypto {
        fn will_log(&self, _label: &str) -> bool {
            true
        }

        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
                self.server_handshake_secret
                    .set(secret.to_vec())
                    .unwrap();
            }
        }
    }
}

// invalid with fips, as we can't offer X25519 separately
#[cfg(all(
    feature = "aws-lc-rs",
    feature = "prefer-post-quantum",
    not(feature = "fips")
))]
#[test]
fn hybrid_kx_component_share_offered_if_supported_separately() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(crate::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 2);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
    assert_eq!(key_shares[1].group, NamedGroup::X25519);
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn hybrid_kx_component_share_not_offered_unless_supported_separately() {
    use crate::crypto::aws_lc_rs;
    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    };
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
}

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

fn client_hello_sent_with_session_id_generator(
    config: ClientConfig,
    generator: impl Fn(&[u8]) -> [u8; 32],
) -> Result<ClientHelloPayload, Error> {
    let mut conn = ClientConnection::new_with_session_id_generator(
        config.into(),
        ServerName::try_from("localhost").unwrap(),
        Some(generator),
    )?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

fn roots() -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}

/// Tests that when Reality is configured, the session_id_generator does not
/// overwrite Reality's cryptographically-computed session_id.
#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn test_reality_session_id_not_overwritten_by_session_id_generator() {
    use super::reality::RealityConfig;

    #[cfg(feature = "ring")]
    let provider = crate::crypto::ring::default_provider();
    #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
    let provider = crate::crypto::aws_lc_rs::default_provider();

    let server_pk = [1u8; 32];
    let short_id = vec![0x12, 0x34];
    let reality = RealityConfig::new(server_pk, short_id).unwrap();

    let config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&crate::version::TLS13])
        .unwrap()
        .with_root_certificates(roots())
        .with_reality(reality)
        .with_no_client_auth();

    // Get ClientHello with Reality only (no session_id_generator)
    let ch_reality_only = client_hello_sent_for_config(config.clone()).unwrap();

    // Get ClientHello with Reality + a session_id_generator that would produce all-0xFF
    let ch_reality_with_generator =
        client_hello_sent_with_session_id_generator(config, |_| [0xFF; 32]).unwrap();

    // Reality session_id should NOT be all zeros (it's encrypted data)
    assert_ne!(ch_reality_only.session_id.data, [0u8; 32]);

    // With both Reality and session_id_generator, the session_id should come from
    // Reality (not the generator's all-0xFF value)
    assert_ne!(
        ch_reality_with_generator
            .session_id
            .data,
        [0xFF; 32],
        "session_id_generator should not overwrite Reality's session_id"
    );

    // The session_id should still be non-zero (Reality-computed)
    assert_ne!(
        ch_reality_with_generator
            .session_id
            .data,
        [0u8; 32]
    );
}

// ---------------------------------------------------------------------------
// ClientHello shaping
//
// These read the bytes that actually left, not the parsed structure: parsing
// throws away exactly what is under test here - GREASE, extensions rustls does
// not model, and the order everything went out in.

/// A `ClientHello` as it went on the wire.
#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
struct WireClientHello {
    /// Handshake message body, without the four byte header.
    body: Vec<u8>,
    cipher_suites: Vec<u16>,
    /// Extensions in the order they were written, unknown ones included.
    extensions: Vec<(u16, Vec<u8>)>,
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
impl WireClientHello {
    fn capture(config: ClientConfig) -> Self {
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut bytes = Vec::new();
        conn.write_tls(&mut bytes).unwrap();

        // Whatever we did to the hello, it must still be a hello. Reading it
        // back with rustls own parser is the cheapest way to be sure every
        // length field still agrees with its contents.
        let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
            .unwrap()
            .into_plain_message();
        match Message::try_from(message).unwrap() {
            Message {
                payload:
                    MessagePayload::Handshake {
                        parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(_)),
                        ..
                    },
                ..
            } => {}
            other => panic!("unexpected message {other:?}"),
        }

        Self::parse(&bytes)
    }

    fn parse(record: &[u8]) -> Self {
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        let handshake = &record[5..5 + record_len];
        assert_eq!(handshake[0], 0x01, "not a ClientHello");

        let hs_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
        let body = handshake[4..4 + hs_len].to_vec();

        let mut at = 2 + 32; // legacy_version, random
        at += 1 + body[at] as usize; // legacy_session_id

        let suites_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let cipher_suites = body[at..at + suites_len]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        at += suites_len;

        at += 1 + body[at] as usize; // legacy_compression_methods

        let exts_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let exts_end = at + exts_len;

        let mut extensions = Vec::new();
        while at < exts_end {
            let typ = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            at += 4;
            extensions.push((typ, body[at..at + len].to_vec()));
            at += len;
        }
        assert_eq!(
            at, exts_end,
            "extension list length disagrees with contents"
        );
        assert_eq!(at, body.len(), "trailing bytes after the extension list");

        Self {
            body,
            cipher_suites,
            extensions,
        }
    }

    fn extension_types(&self) -> Vec<u16> {
        self.extensions
            .iter()
            .map(|(typ, _)| *typ)
            .collect()
    }

    fn extension(&self, typ: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, body)| body.as_slice())
    }

    /// supported_groups(10): a u16 length, then u16 group ids.
    fn named_groups(&self) -> Vec<u16> {
        let body = self
            .extension(10)
            .expect("no supported_groups");
        body[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect()
    }

    /// key_share(51): a u16 length, then entries of group, u16 length, body.
    fn key_shares(&self) -> Vec<(u16, Vec<u8>)> {
        let body = self
            .extension(51)
            .expect("no key_share");
        let mut at = 2;
        let mut out = Vec::new();
        while at < body.len() {
            let group = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            at += 4;
            out.push((group, body[at..at + len].to_vec()));
            at += len;
        }
        out
    }

    /// supported_versions(43): a u8 length, then u16 versions.
    fn versions(&self) -> Vec<u16> {
        let body = self
            .extension(43)
            .expect("no supported_versions");
        body[1..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect()
    }
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
fn client_config_with_profile(profile: crate::client::ClientHelloProfile) -> ClientConfig {
    #[cfg(feature = "ring")]
    let provider = crate::crypto::ring::default_provider();
    #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
    let provider = crate::crypto::aws_lc_rs::default_provider();

    let mut config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots())
        .with_no_client_auth();
    config.client_hello_profile = Arc::new(profile);
    config
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn default_profile_changes_nothing() {
    let hello = WireClientHello::capture(client_config_with_profile(Default::default()));

    assert!(
        !hello
            .cipher_suites
            .iter()
            .copied()
            .any(is_grease),
        "cipher suites: {:04x?}",
        hello.cipher_suites
    );
    assert!(
        !hello
            .extension_types()
            .into_iter()
            .any(is_grease),
        "extensions: {:04x?}",
        hello.extension_types()
    );
    assert!(
        !hello
            .named_groups()
            .into_iter()
            .any(is_grease)
    );
    assert!(hello.extension(21).is_none(), "unasked-for padding");
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn grease_reaches_every_list_that_browsers_grease() {
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            grease: true,
            ..Default::default()
        },
    ));

    // Always first in its list: a peer that reads the list in order and gives
    // up on the first value it does not know is caught by the next connection
    // rather than years later.
    assert!(
        is_grease(hello.cipher_suites[0]),
        "cipher suites: {:04x?}",
        hello.cipher_suites
    );
    assert!(
        is_grease(hello.named_groups()[0]),
        "groups: {:04x?}",
        hello.named_groups()
    );
    assert!(
        is_grease(hello.versions()[0]),
        "versions: {:04x?}",
        hello.versions()
    );

    let key_shares = hello.key_shares();
    assert!(is_grease(key_shares[0].0));
    assert_eq!(
        key_shares[0].1,
        vec![0x00],
        "the GREASE key share is one zero byte, as BoringSSL sends it"
    );

    // And what rustls meant to send is still behind it.
    assert!(
        hello.cipher_suites[1..]
            .iter()
            .copied()
            .any(|suite| !is_grease(suite))
    );
    assert!(key_shares.len() > 1, "GREASE displaced the real key share");
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn grease_extensions_bracket_the_list() {
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            grease: true,
            ..Default::default()
        },
    ));

    let types = hello.extension_types();
    let grease: Vec<u16> = types
        .iter()
        .copied()
        .filter(|typ| is_grease(*typ))
        .collect();

    assert_eq!(grease.len(), 2, "extensions: {types:04x?}");
    assert_ne!(
        grease[0], grease[1],
        "two extensions of one type is a protocol error"
    );
    assert!(is_grease(types[0]), "first extension: {:04x}", types[0]);
    assert!(
        is_grease(*types.last().unwrap()),
        "last extension: {:04x}",
        types.last().unwrap()
    );

    assert_eq!(hello.extension(grease[0]), Some(&[][..]));
    assert_eq!(hello.extension(grease[1]), Some(&[0x00][..]));
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn verbatim_extensions_go_where_they_were_put() {
    use crate::msgs::handshake::RawExtension;

    // signed_certificate_timestamp and ALPS: two extensions rustls has no
    // reason to model, and two no browser omits.
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            prepend_extensions: vec![RawExtension::empty(0x0012)],
            append_extensions: vec![RawExtension {
                typ: 0x4469,
                payload: b"\x00\x03\x02h2".to_vec(),
            }],
            ..Default::default()
        },
    ));

    let types = hello.extension_types();
    assert_eq!(types[0], 0x0012, "extensions: {types:04x?}");
    assert_eq!(*types.last().unwrap(), 0x4469);

    assert_eq!(hello.extension(0x0012), Some(&[][..]));
    assert_eq!(hello.extension(0x4469), Some(&b"\x00\x03\x02h2"[..]));
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn padding_brings_the_hello_to_the_target_length() {
    use crate::client::Padding;

    // A window wide enough that the hello lands inside it whatever rustls
    // decides to send. The rule itself is unit tested; what matters here is
    // that the arithmetic agrees with the bytes.
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            padding: Some(Padding {
                only_above: 0,
                up_to: 1024,
            }),
            ..Default::default()
        },
    ));

    assert_eq!(hello.body.len(), 1024);
    assert_eq!(*hello.extension_types().last().unwrap(), 21);
    assert!(
        hello
            .extension(21)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn padding_stays_out_of_a_hello_already_long_enough() {
    use crate::client::Padding;

    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            padding: Some(Padding {
                only_above: 0,
                up_to: 16,
            }),
            ..Default::default()
        },
    ));

    assert!(hello.body.len() > 16);
    assert!(hello.extension(21).is_none());
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn padding_counts_the_grease_and_verbatim_extensions_too() {
    use crate::client::Padding;
    use crate::msgs::handshake::RawExtension;

    // Padding is measured last, so everything else has to be in place by then.
    // Get that order wrong and the hello comes out short by the size of the
    // other extensions - which is the length signal padding exists to erase.
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            grease: true,
            append_extensions: vec![RawExtension {
                typ: 0x4469,
                payload: vec![0xab; 64],
            }],
            padding: Some(Padding {
                only_above: 0,
                up_to: 1024,
            }),
            ..Default::default()
        },
    ));

    assert_eq!(hello.body.len(), 1024);
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn the_cipher_suite_list_can_be_dictated() {
    // Chrome's list, GREASE aside. The last four are static RSA key exchange,
    // which rustls does not implement and will never negotiate - they are here
    // to be counted by whoever is looking, and for no other reason.
    let chrome = vec![
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x009d,
        0x002f, 0x0035,
    ];

    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            cipher_suites: Some(chrome.clone()),
            ..Default::default()
        },
    ));

    assert_eq!(hello.cipher_suites, chrome);
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn a_dictated_cipher_list_does_not_get_the_scsv_appended() {
    // rustls signals "no renegotiation" with the SCSV; browsers use the
    // renegotiation_info extension instead. An extra pseudo-suite in the list
    // is as visible as any real one, so the caller's list has to be final.
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            cipher_suites: Some(vec![0x1301, 0x1302, 0x1303]),
            ..Default::default()
        },
    ));

    assert_eq!(hello.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
    assert!(
        !hello.cipher_suites.contains(&0x00ff),
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV added behind the caller's back"
    );
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn the_default_cipher_list_still_carries_the_scsv() {
    // The flip side of the test above: leaving the profile alone must not
    // quietly change what rustls has always sent.
    let hello = WireClientHello::capture(client_config_with_profile(Default::default()));

    assert!(
        hello.cipher_suites.contains(&0x00ff),
        "suites: {:04x?}",
        hello.cipher_suites
    );
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn grease_goes_in_front_of_a_dictated_cipher_list_too() {
    let hello = WireClientHello::capture(client_config_with_profile(
        crate::client::ClientHelloProfile {
            grease: true,
            cipher_suites: Some(vec![0x1301, 0x1302]),
            ..Default::default()
        },
    ));

    assert!(is_grease(hello.cipher_suites[0]));
    assert_eq!(hello.cipher_suites[1..], [0x1301, 0x1302]);
}

#[cfg(feature = "aws_lc_rs")]
#[test]
fn grease_ech_carries_the_kem_of_the_suite_it_was_given() {
    use crate::client::{EchGreaseConfig, EchMode};
    use crate::crypto::aws_lc_rs::hpke::{
        DH_KEM_P256_HKDF_SHA256_AES_128, DH_KEM_X25519_HKDF_SHA256_AES_128,
    };
    use crate::crypto::hpke::Hpke;

    // The `enc` field carries an ephemeral public key, and its length is the
    // KEM's own: 32 bytes for X25519, 65 for an uncompressed P-256 point.
    // GREASE that always claims P-256 no matter which suite it was handed is
    // distinguishable from a client that GREASEs with X25519 - which is what
    // browsers do, and the whole point of GREASE is to be indistinguishable.
    for (suite, enc_len) in [
        (DH_KEM_X25519_HKDF_SHA256_AES_128 as &'static dyn Hpke, 32),
        (DH_KEM_P256_HKDF_SHA256_AES_128 as &'static dyn Hpke, 65),
    ] {
        let (public_key, _) = suite.generate_key_pair().unwrap();

        let config = ClientConfig::builder_with_provider(
            crate::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_ech(EchMode::Grease(EchGreaseConfig::new(suite, public_key)))
        .unwrap()
        .with_root_certificates(roots())
        .with_no_client_auth();

        let hello = WireClientHello::capture(config);
        let body = hello
            .extension(0xfe0d)
            .expect("no encrypted_client_hello extension");

        // 0x00 outer, kdf u16, aead u16, config_id u8, then enc as a
        // length-prefixed payload.
        assert_eq!(body[0], 0x00, "not an outer ECH");
        assert_eq!(
            u16::from_be_bytes([body[6], body[7]]) as usize,
            enc_len,
            "{:?}",
            suite.suite().kem
        );
    }
}

#[cfg(feature = "aws_lc_rs")]
#[test]
fn grease_ech_does_not_drop_tls12_from_the_hello() {
    use crate::client::{EchGreaseConfig, EchMode};
    use crate::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    use crate::crypto::hpke::Hpke;

    // Real ECH needs TLS 1.3 and says so by pinning the version. GREASE ECH
    // negotiates nothing, so it has no such requirement - and a client that
    // sends the placeholder extension while quietly dropping TLS 1.2 has
    // changed the very thing it was trying to blend into.
    let suite = DH_KEM_X25519_HKDF_SHA256_AES_128 as &'static dyn Hpke;
    let (public_key, _) = suite.generate_key_pair().unwrap();

    let config =
        ClientConfig::builder_with_provider(crate::crypto::aws_lc_rs::default_provider().into())
            .with_ech(EchMode::Grease(EchGreaseConfig::new(suite, public_key)))
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();

    let hello = WireClientHello::capture(config);

    assert!(hello.extension(0xfe0d).is_some(), "no GREASE ECH");
    assert_eq!(hello.versions(), vec![0x0304, 0x0303]);
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn grease_ech_needs_no_hpke_provider() {
    use crate::client::{EchGreaseConfig, EchMode};
    use crate::crypto::hpke::HpkeSuite;
    use crate::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
    use crate::msgs::handshake::HpkeSymmetricCipherSuite;

    // The suite browsers GREASE with. Nothing here has to be implemented by
    // the provider - the payload is random and the encapsulated key addresses
    // nobody - which is the point: `ring` ships no HPKE, and `ring` is what
    // every MIPS and embedded build uses.
    let suite = HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
    };

    #[cfg(feature = "ring")]
    let provider = crate::crypto::ring::default_provider();
    #[cfg(all(not(feature = "ring"), feature = "aws_lc_rs"))]
    let provider = crate::crypto::aws_lc_rs::default_provider();

    let config = ClientConfig::builder_with_provider(provider.into())
        .with_ech(EchMode::Grease(
            EchGreaseConfig::without_provider(suite).unwrap(),
        ))
        .unwrap()
        .with_root_certificates(roots())
        .with_no_client_auth();

    let hello = WireClientHello::capture(config);
    let body = hello
        .extension(0xfe0d)
        .expect("no encrypted_client_hello");

    // 0x00 outer, kdf u16, aead u16, config_id u8, then the encapsulated key
    // as a length-prefixed payload. X25519 keys are 32 bytes, and a GREASE
    // value of any other length would be the one thing a placeholder must not
    // be: distinguishable.
    assert_eq!(body[0], 0x00, "not an outer ECH");
    assert_eq!(u16::from_be_bytes([body[1], body[2]]), 0x0001, "kdf");
    assert_eq!(u16::from_be_bytes([body[3], body[4]]), 0x0001, "aead");
    assert_eq!(u16::from_be_bytes([body[6], body[7]]), 32, "enc length");

    // And the payload is sized like a real sealed inner hello: long enough to
    // be one, and not a round number that would give it away.
    let enc_end = 8 + 32;
    let payload_len = u16::from_be_bytes([body[enc_end], body[enc_end + 1]]);
    assert!(
        payload_len > 64,
        "payload of {payload_len} bytes is too short to pass"
    );
}

#[cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn grease_ech_refuses_a_kem_it_cannot_size() {
    use crate::client::EchGreaseConfig;
    use crate::crypto::hpke::HpkeSuite;
    use crate::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
    use crate::msgs::handshake::HpkeSymmetricCipherSuite;

    // Guessing a length would produce an encapsulated key of the wrong size,
    // which is worse than declining: it looks like a client that does not know
    // its own KEM.
    let suite = HpkeSuite {
        kem: HpkeKem::Unknown(0x1234),
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
    };
    assert!(EchGreaseConfig::without_provider(suite).is_err());
}
