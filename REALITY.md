# VLESS Reality Protocol Implementation

This document describes the implementation of the VLESS Reality protocol in rustls.

## Overview

Reality is a protocol extension that provides enhanced privacy by encrypting the TLS session ID using a shared secret derived from X25519 ECDH with the server's public key. This implementation allows rustls clients to establish TLS connections with Reality-enabled servers.

## Protocol Specification

The Reality protocol follows these steps:

1. **Key Generation**: Client generates an ephemeral X25519 keypair (`client_secret`, `client_public`)

2. **ECDH**: Client performs Elliptic Curve Diffie-Hellman with server's public key:
   ```
   shared_secret = client_secret.diffie_hellman(server_public_key)
   ```

3. **Key Derivation**: Client derives authentication key using HKDF-SHA256:
   ```
   auth_key = HKDF-SHA256(
       ikm=shared_secret,
       salt=hello_random[:20],
       info="REALITY"
   )
   ```

4. **Plaintext Construction**: Client constructs 16-byte plaintext:
   ```
   [0..3]  = client_version (3 bytes) + reserved (1 byte)
   [4..8]  = Unix timestamp (big-endian u32)
   [8..16] = short_id (zero-padded to 8 bytes)
   ```

5. **Encryption**: Client encrypts plaintext using AES-128-GCM:
   ```
   session_id = AES-128-GCM(
       key=auth_key,
       nonce=hello_random[20..32],
       aad=full_ClientHello_bytes,
       plaintext=plaintext
   )
   ```
   The result is 32 bytes: ciphertext (16 bytes) + authentication tag (16 bytes)

6. **Key Share Injection**: Client's public key (`client_public`) is injected into the ClientHello `key_share` extension as an X25519 key exchange

## API Usage

### Basic Example

```rust
use std::sync::Arc;
use watfaq_rustls::client::RealityConfig;
use watfaq_rustls::{ClientConfig, RootCertStore};

// Server's X25519 public key (obtained securely out-of-band)
let server_pubkey = [0u8; 32]; // Replace with actual key

// Client identifier
let short_id = vec![0x12, 0x34, 0x56, 0x78];

// Create Reality configuration
let reality = RealityConfig::new(server_pubkey, short_id)?;

// Build client configuration with Reality
let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_reality(reality)
    .with_no_client_auth();

// Use normally
let conn = ClientConnection::new(Arc::new(config), server_name)?;
```

### Advanced Configuration

```rust
// Customize client version
let reality = RealityConfig::new(server_pubkey, short_id)?
    .with_client_version([1, 2, 3]);
```

### Running the Example

The `reality-client` example demonstrates a complete Reality connection:

```bash
cd examples
cargo run --bin reality-client -- \
    example.com:443 \
    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    12345678
```

Arguments:
- `example.com:443` - Server address and port
- Second argument - Server's X25519 public key (64 hex characters = 32 bytes)
- Third argument - Short ID (up to 16 hex characters = 8 bytes)

## Architecture

### Module Structure

```
rustls/src/client/
├── reality.rs          # Core Reality implementation
├── hs.rs              # Handshake integration
├── client_conn.rs     # ClientConfig with reality_config field
└── builder.rs         # Builder pattern (with_reality method)
```

### Key Components

#### `RealityConfig` (Public API)

```rust
pub struct RealityConfig {
    server_public_key: [u8; 32],  // Server's X25519 public key
    short_id: Vec<u8>,             // Client identifier (max 8 bytes)
    client_version: [u8; 3],       // Protocol version
}
```

#### `RealitySessionState` (Internal)

```rust
pub(crate) struct RealitySessionState {
    config: Arc<RealityConfig>,
    client_public: [u8; 32],      // Client's ephemeral public key
    shared_secret: [u8; 32],      // ECDH shared secret
}
```

### Handshake Integration

The Reality protocol is integrated into the TLS handshake at key points:

1. **Initialization** (`hs.rs:start_handshake`):
   - Creates `RealitySessionState` if Reality is configured
   - Performs X25519 ECDH to derive shared secret

2. **Key Share Injection** (`hs.rs:emit_client_hello_for_retry`):
   - Replaces normal key_share with Reality X25519 public key
   - Ensures ClientHello contains the correct key exchange

3. **Session ID Computation** (`hs.rs:emit_client_hello_for_retry`):
   - After ClientHello is constructed with zero session_id
   - Encodes ClientHello to get full bytes
   - Computes encrypted session_id using Reality protocol
   - Updates ClientHello with computed session_id

## Cryptographic Implementation

### Crypto Provider Support

Reality implementation supports both `ring` and `aws-lc-rs` crypto providers through conditional compilation:

```rust
#[cfg(feature = "ring")]
fn perform_x25519_ecdh(...) { /* ring implementation */ }

#[cfg(feature = "aws_lc_rs")]
fn perform_x25519_ecdh(...) { /* aws-lc-rs implementation */ }
```

### Cryptographic Operations

1. **X25519 ECDH**: Uses provider's X25519 implementation
2. **HKDF-SHA256**: Obtained from TLS13_AES_128_GCM_SHA256 cipher suite
3. **AES-128-GCM**: Uses provider's AEAD implementation
4. **Randomness**: Uses provider's secure random generator

## Security Considerations

### Requirements

- **Server Public Key Security**: The server's X25519 public key must be obtained through a secure, authenticated channel. An attacker with the ability to substitute the server public key can break the Reality protocol's privacy guarantees.

- **Short ID Confidentiality**: The `short_id` serves as a client identifier. Keep it confidential to prevent tracking.

- **Crypto Provider**: Reality requires X25519 and AES-128-GCM support. Use either `ring` or `aws-lc-rs` features.

- **TLS Version**: Reality is compatible with both TLS 1.2 and TLS 1.3, but works best with TLS 1.3.

### Threat Model

Reality protects against:
- **Passive Observation**: Session IDs are encrypted, preventing observers from correlating connections
- **Active Probing**: Without the correct server private key, attackers cannot decrypt or forge valid session IDs

Reality does NOT protect against:
- **Compromised Server**: If the server's private key is compromised, past session IDs can be decrypted
- **Traffic Analysis**: Connection timing and size metadata may still leak information

## Testing

### Unit Tests

```bash
cargo test --package watfaq-rustls --lib reality
```

Tests include:
- Configuration validation
- X25519 ECDH correctness
- AES-128-GCM encryption
- Session ID plaintext structure
- Full session ID computation pipeline

### Integration Tests

Integration tests verify:
- RealitySessionState creation
- Key share entry generation
- Complete session_id computation with both crypto providers
- Builder pattern integration

## Implementation Notes

### Design Decisions

1. **Inline Computation**: Session ID is computed inline during handshake emission rather than using a callback, providing access to `Random` value and full `ClientHello` bytes.

2. **State Management**: Reality state is passed through the handshake state machine to maintain access to cryptographic materials.

3. **Provider Abstraction**: Uses rustls's existing crypto provider system for all cryptographic operations.

4. **No Protocol Breaking Changes**: Reality is implemented as an optional extension without modifying core TLS protocol handling.

### Limitations

- **One-Time Use**: The ephemeral X25519 keypair is generated per connection and not reused.

- **No HelloRetryRequest**: Reality state is not carried through HelloRetryRequest flows (set to `None` on retry).

- **Fixed Crypto**: Currently requires HKDF-SHA256 (from TLS13_AES_128_GCM_SHA256) and AES-128-GCM.

## References

- [VLESS Protocol Specification](https://github.com/XTLS/REALITY)
- [RFC 7748: Elliptic Curves for Security (X25519)](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 5869: HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 5116: AES-GCM](https://datatracker.ietf.org/doc/html/rfc5116)

## Changelog

### Version 0.23.21

- Initial implementation of VLESS Reality protocol
- Support for both `ring` and `aws-lc-rs` crypto providers
- Public API: `RealityConfig`, `RealityConfigError`
- Builder method: `ConfigBuilder::with_reality()`
- Example: `reality-client` binary
- Comprehensive unit and integration tests

## License

This implementation follows the same license as rustls: Apache-2.0 OR ISC OR MIT.
