//! Example client demonstrating the VLESS Reality protocol
//!
//! Reality is a protocol extension that provides enhanced privacy by encrypting
//! the TLS session ID using a shared secret derived from X25519 ECDH with the
//! server's public key.
//!
//! This example shows how to:
//! 1. Create a RealityConfig with server public key and short_id
//! 2. Build a ClientConfig with Reality enabled
//! 3. Make a TLS connection using the Reality protocol
//!
//! Note: This example requires a Reality-enabled server to complete the handshake.
//! The server must be configured with the corresponding X25519 private key.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example reality-client <server_addr> <public_key_base64> <short_id_hex>
//! ```
//!
//! Example (using airport Reality config format):
//! ```bash
//! cargo run --example reality-client example.com:443 \
//!   Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs \
//!   1bc2c1ef1c
//! ```
//!
//! Note: You can directly copy-paste the values from airport Reality config!
//!
//! ## Method 2: Parsing airport Reality configuration format
//!
//! Many airports/VPN providers give Reality config in YAML format like:
//! ```yaml
//! reality-opts:
//!     public-key: Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs
//!     short-id: 1bc2c1ef1c
//! ```
//!
//! See the `parse_airport_reality_config()` function below for how to parse this format.
//! The public-key is Base64 encoded and short-id is hexadecimal.

use std::env;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use watfaq_rustls::client::RealityConfig;
use watfaq_rustls::pki_types;
use watfaq_rustls::RootCertStore;

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <server_addr> <public_key_base64> <short_id_hex>", args[0]);
        eprintln!();
        eprintln!("Parameters:");
        eprintln!("  <server_addr>        Server address (e.g., example.com:443)");
        eprintln!("  <public_key_base64>  Server's X25519 public key in Base64 format");
        eprintln!("  <short_id_hex>       Client identifier in hexadecimal format");
        eprintln!();
        eprintln!("Example (using airport Reality config):");
        eprintln!("  {} example.com:443 \\", args[0]);
        eprintln!("    Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs \\");
        eprintln!("    1bc2c1ef1c");
        eprintln!();
        eprintln!("If you have airport Reality config in this format:");
        eprintln!("  reality-opts:");
        eprintln!("    public-key: Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs");
        eprintln!("    short-id: 1bc2c1ef1c");
        eprintln!();
        eprintln!("Just copy and paste the values directly!");
        std::process::exit(1);
    }

    let server_addr = args[1].clone();
    let public_key_base64 = args[2].clone();
    let short_id_hex = args[3].clone();

    // Parse server public key from Base64 (airport format)
    let server_pubkey = base64_to_bytes(&public_key_base64)
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            } else {
                Err(format!(
                    "Server public key must be exactly 32 bytes, got {} bytes",
                    bytes.len()
                ))
            }
        })
        .unwrap_or_else(|e| {
            eprintln!("Error parsing server public key (Base64): {}", e);
            std::process::exit(1);
        });

    // Parse short_id
    let short_id = hex_to_bytes(&short_id_hex).unwrap_or_else(|e| {
        eprintln!("Error parsing short_id: {}", e);
        std::process::exit(1);
    });

    if short_id.len() > 8 {
        eprintln!("Error: short_id must be at most 8 bytes (16 hex characters)");
        std::process::exit(1);
    }

    // Create Reality configuration
    let reality_config = RealityConfig::new(server_pubkey, short_id)
        .unwrap_or_else(|e| {
            eprintln!("Error creating Reality config: {}", e);
            std::process::exit(1);
        });

    println!("Reality configuration created successfully");
    println!("  Server public key: {}", bytes_to_hex(&server_pubkey));
    println!("  Short ID: {}", short_id_hex);

    // Load root certificates
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // Build client configuration with Reality
    let mut config = watfaq_rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_reality(reality_config)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE for debugging
    config.key_log = Arc::new(watfaq_rustls::KeyLogFile::new());

    println!("\nConnecting to {}...", &server_addr);

    // Extract server name from address
    let server_name: pki_types::ServerName<'static> = server_addr
        .split(':')
        .next()
        .unwrap()
        .to_string()
        .try_into()
        .unwrap_or_else(|e| {
            eprintln!("Error parsing server name: {:?}", e);
            std::process::exit(1);
        });

    // Create TLS connection
    let mut conn = watfaq_rustls::ClientConnection::new(Arc::new(config), server_name)
        .unwrap_or_else(|e| {
            eprintln!("Error creating client connection: {}", e);
            std::process::exit(1);
        });

    // Connect to server
    let mut sock = TcpStream::connect(&server_addr).unwrap_or_else(|e| {
        eprintln!("Error connecting to server: {}", e);
        std::process::exit(1);
    });

    let mut tls = watfaq_rustls::Stream::new(&mut conn, &mut sock);

    // Complete the handshake first
    println!("Performing TLS handshake...");
    tls.conn.complete_io(&mut sock).unwrap_or_else(|e| {
        eprintln!("Error during TLS handshake: {}", e);
        std::process::exit(1);
    });

    println!("✓ TLS handshake completed successfully with Reality protocol!");

    // Print negotiated cipher suite
    if let Some(ciphersuite) = tls.conn.negotiated_cipher_suite() {
        println!("✓ Cipher suite: {:?}", ciphersuite.suite());
    }

    // Print protocol version
    if let Some(version) = tls.conn.protocol_version() {
        println!("✓ Protocol version: {:?}", version);
    }

    // Send a simple HTTP request
    println!("\nSending HTTP request...");
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        server_addr.split(':').next().unwrap()
    );

    tls.write_all(request.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("Error sending request: {}", e);
            std::process::exit(1);
        });

    println!("✓ Request sent successfully");

    // Read and print response
    println!("\nServer response:");
    println!("----------------------------------------");
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap_or_else(|e| {
        eprintln!("Error reading response: {}", e);
        std::process::exit(1);
    });
    stdout().write_all(&plaintext).unwrap();
    println!("----------------------------------------");
    println!("\nConnection closed successfully");
}

/// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length");
    }

    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Helper function to convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Example: Parse airport Reality configuration format
///
/// Many airports/VPN providers give Reality config in this format:
/// ```yaml
/// reality-opts:
///     public-key: Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs
///     short-id: 1bc2c1ef1c
/// ```
///
/// This function demonstrates how to parse such configuration into RealityConfig.
///
/// # Example
///
/// ```no_run
/// use watfaq_rustls::client::RealityConfig;
///
/// // Configuration from airport
/// let public_key_base64 = "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs";
/// let short_id_hex = "1bc2c1ef1c";
///
/// // Parse public key from Base64
/// let public_key_bytes = base64_to_bytes(public_key_base64)
///     .expect("Invalid base64 public key");
/// let mut public_key = [0u8; 32];
/// public_key.copy_from_slice(&public_key_bytes);
///
/// // Parse short_id from hex
/// let short_id = hex_to_bytes(short_id_hex)
///     .expect("Invalid hex short_id");
///
/// // Create RealityConfig
/// let reality_config = RealityConfig::new(public_key, short_id)
///     .expect("Invalid Reality configuration");
/// ```
#[allow(dead_code)]
fn parse_airport_reality_config(
    public_key_base64: &str,
    short_id_hex: &str,
) -> Result<RealityConfig, String> {
    // Parse public key from Base64
    let public_key_bytes = base64_to_bytes(public_key_base64)
        .map_err(|e| format!("Failed to decode public key: {}", e))?;

    if public_key_bytes.len() != 32 {
        return Err(format!(
            "Invalid public key length: expected 32 bytes, got {}",
            public_key_bytes.len()
        ));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);

    // Parse short_id from hex
    let short_id = hex_to_bytes(short_id_hex)
        .map_err(|e| format!("Failed to decode short_id: {}", e))?;

    if short_id.len() > 8 {
        return Err(format!(
            "short_id too long: expected max 8 bytes, got {}",
            short_id.len()
        ));
    }

    // Create RealityConfig
    RealityConfig::new(public_key, short_id)
        .map_err(|e| format!("Failed to create RealityConfig: {}", e))
}

/// Helper function to decode Base64 string to bytes
///
/// Supports both standard Base64 and Base64 URL-safe encoding.
#[allow(dead_code)]
fn base64_to_bytes(base64_str: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;

    // Try standard Base64 first
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(base64_str) {
        return Ok(bytes);
    }

    // Try URL-safe Base64 (some airports use this)
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(base64_str)
        .map_err(|e| format!("Invalid Base64: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_airport_reality_config() {
        // Example configuration from an airport
        let public_key_base64 = "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs";
        let short_id_hex = "1bc2c1ef1c";

        let config = parse_airport_reality_config(public_key_base64, short_id_hex);
        assert!(config.is_ok(), "Should parse valid airport config");

        let config = config.unwrap();
        // Verify we can use it (this just checks it was created successfully)
        drop(config);
    }

    #[test]
    fn test_base64_to_bytes() {
        // Standard Base64
        let result = base64_to_bytes("SGVsbG8gV29ybGQ=");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello World");

        // URL-safe Base64
        let result = base64_to_bytes("Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32); // X25519 public key is 32 bytes
    }

    #[test]
    fn test_hex_to_bytes() {
        let result = hex_to_bytes("1bc2c1ef1c");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x1b, 0xc2, 0xc1, 0xef, 0x1c]);
    }
}
