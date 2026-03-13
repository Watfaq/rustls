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
    if args.len() != 5 {
        eprintln!(
            "Usage: {} <server_addr> <sni_servername> <public_key_base64> <short_id_hex>",
            args[0]
        );
        eprintln!();
        eprintln!("Parameters:");
        eprintln!("  <server_addr>        Real server address (e.g., tw04.ctg.wtf:443)");
        eprintln!("  <sni_servername>     SNI hostname for disguise (e.g., www.microsoft.com)");
        eprintln!("  <public_key_base64>  Server's X25519 public key in Base64 format");
        eprintln!("  <short_id_hex>       Client identifier in hexadecimal format");
        eprintln!();
        eprintln!("Example using VLESS Reality config:");
        eprintln!("  If you have this config:");
        eprintln!("    server: tw04.ctg.wtf");
        eprintln!("    port: 443");
        eprintln!("    servername: www.microsoft.com");
        eprintln!("    reality-opts:");
        eprintln!("      public-key: Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs");
        eprintln!("      short-id: 1bc2c1ef1c");
        eprintln!();
        eprintln!("Run:");
        eprintln!("  {} tw04.ctg.wtf:443 \\", args[0]);
        eprintln!("    www.microsoft.com \\");
        eprintln!("    Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs \\");
        eprintln!("    1bc2c1ef1c");
        std::process::exit(1);
    }

    let server_addr = args[1].clone();
    let sni_servername = args[2].clone();
    let public_key_base64 = args[3].clone();
    let short_id_hex = args[4].clone();

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

    let short_id_len = short_id.len();

    // Create Reality configuration
    let reality_config = RealityConfig::new(server_pubkey, short_id).unwrap_or_else(|e| {
        eprintln!("Error creating Reality config: {}", e);
        std::process::exit(1);
    });

    println!("Reality configuration created successfully");
    println!("  Server public key: {}", bytes_to_hex(&server_pubkey));
    println!("  Short ID: {}", short_id_hex);
    println!("\nDebug Info:");
    println!("  Base64 public key input: {}", public_key_base64);
    println!("  Hex short_id input: {}", short_id_hex);
    println!("  Short ID length: {} bytes", short_id_len);

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

    println!(
        "\nConnecting to {} (SNI: {})...",
        &server_addr, &sni_servername
    );

    // Use SNI servername for TLS connection (for disguise/camouflage)
    let server_name: pki_types::ServerName<'static> = sni_servername
        .to_string()
        .try_into()
        .unwrap_or_else(|e| {
            eprintln!("Error parsing SNI servername: {:?}", e);
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

    // Send a simple HTTP request
    println!("Performing TLS handshake and sending HTTP request...");
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        sni_servername
    );

    if let Err(e) = tls.write_all(request.as_bytes()) {
        eprintln!("\n❌ Error during TLS communication: {}", e);
        eprintln!("\nPossible reasons:");
        eprintln!("  1. Server's private key doesn't match the provided public key");
        eprintln!("  2. Server is not a Reality-enabled server");
        eprintln!("  3. Reality protocol version mismatch");
        eprintln!("  4. Network/firewall issues");
        std::process::exit(1);
    }

    println!("✓ TLS handshake completed successfully with Reality protocol!");

    // Print connection details
    if let Some(ciphersuite) = tls.conn.negotiated_cipher_suite() {
        println!("✓ Cipher suite: {:?}", ciphersuite.suite());
    }
    if let Some(version) = tls.conn.protocol_version() {
        println!("✓ Protocol version: {:?}", version);
    }
    println!("✓ Request sent successfully");

    // Read and print response
    println!("\nServer response:");
    println!("----------------------------------------");
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)
        .unwrap_or_else(|e| {
            eprintln!("Error reading response: {}", e);
            std::process::exit(1);
        });
    stdout().write_all(&plaintext).unwrap();
    println!("----------------------------------------");
    println!("\nConnection closed successfully");
}

/// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    if !hex.len().is_multiple_of(2) {
        return Err("Hex string must have even length");
    }

    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Helper function to convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Helper function to decode Base64 string to bytes
///
/// Supports both standard Base64 and Base64 URL-safe encoding.
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
