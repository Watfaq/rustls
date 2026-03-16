//! VLESS Reality probe: sends a VLESS frame after the Reality TLS handshake
//! to distinguish between Reality auth success and fallback.
//!
//! Outcome interpretation:
//!   - Response from <proxy_target>  → Reality auth OK, UUID accepted → full proxy working
//!   - Connection closed / reset     → Reality auth OK, UUID rejected (server recognised us as Reality client)
//!   - Response from <sni_servername>→ Reality auth FAILED → server fell back to SNI destination
//!
//! Usage:
//!   cargo run --bin reality-vless-probe \
//!     <server_addr> <sni_servername> <public_key_base64> <short_id_hex> <uuid>
//!
//! Example:
//!   cargo run --bin reality-vless-probe \
//!     tw05.ctg.wtf:443 www.microsoft.com \
//!     Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs 1bc2c1ef1c \
//!     5415d8e0-df92-3655-afa4-b79de66413f5

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use watfaq_rustls::client::RealityConfig;
use watfaq_rustls::pki_types;
use watfaq_rustls::RootCertStore;

// Target we ask the proxy to reach. Plain HTTP so the response is readable.
const PROXY_TARGET_HOST: &str = "example.com";
const PROXY_TARGET_PORT: u16 = 80;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "Usage: {} <server_addr> <sni_servername> <public_key_base64> <short_id_hex> <uuid>",
            args[0]
        );
        eprintln!("  UUID format: 5415d8e0-df92-3655-afa4-b79de66413f5  (with or without dashes)");
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let sni_servername = &args[2];
    let public_key_base64 = &args[3];
    let short_id_hex = &args[4];
    let uuid_str = &args[5];

    // --- Parse server public key ---
    let server_pubkey: [u8; 32] = base64_to_bytes(public_key_base64)
        .and_then(|b| {
            b.try_into()
                .map_err(|_| "Server public key must be exactly 32 bytes".to_string())
        })
        .unwrap_or_else(|e| {
            eprintln!("Error parsing server public key: {}", e);
            std::process::exit(1);
        });

    // --- Parse short_id ---
    let short_id = hex_to_bytes(short_id_hex).unwrap_or_else(|e| {
        eprintln!("Error parsing short_id: {}", e);
        std::process::exit(1);
    });
    if short_id.len() > 8 {
        eprintln!("Error: short_id must be at most 8 bytes");
        std::process::exit(1);
    }

    // --- Parse UUID (accepts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" or raw 32 hex chars) ---
    let uuid: [u8; 16] = parse_uuid(uuid_str).unwrap_or_else(|e| {
        eprintln!("Error parsing UUID: {}", e);
        std::process::exit(1);
    });

    // Install the default crypto provider (aws-lc-rs is the default feature for watfaq-rustls)
    let _ = watfaq_rustls::crypto::aws_lc_rs::default_provider().install_default();

    println!("=== Reality VLESS Probe ===");
    println!("  Server addr : {}", server_addr);
    println!("  SNI         : {}", sni_servername);
    println!("  short_id    : {}", short_id_hex);
    println!("  UUID        : {}", format_uuid(&uuid));
    println!("  Proxy target: {}:{}", PROXY_TARGET_HOST, PROXY_TARGET_PORT);

    // --- Build TLS client config with Reality ---
    let reality_config = RealityConfig::new(server_pubkey, short_id).unwrap_or_else(|e| {
        eprintln!("Error creating Reality config: {}", e);
        std::process::exit(1);
    });

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = watfaq_rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_reality(reality_config)
        .with_no_client_auth();

    let server_name: pki_types::ServerName<'static> = sni_servername
        .clone()
        .try_into()
        .unwrap_or_else(|e| {
            eprintln!("Error parsing SNI servername: {:?}", e);
            std::process::exit(1);
        });

    let mut conn = watfaq_rustls::ClientConnection::new(Arc::new(config), server_name)
        .unwrap_or_else(|e| {
            eprintln!("Error creating client connection: {}", e);
            std::process::exit(1);
        });

    let mut sock = TcpStream::connect(server_addr).unwrap_or_else(|e| {
        eprintln!("Error connecting to {}: {}", server_addr, e);
        std::process::exit(1);
    });

    // Set read timeout before creating the TLS stream (which mutably borrows sock)
    sock.set_read_timeout(Some(std::time::Duration::from_secs(8)))
        .ok();

    let mut tls = watfaq_rustls::Stream::new(&mut conn, &mut sock);

    // --- Build VLESS frame ---
    //
    // VLESS request header:
    //   [1]  version   = 0x00
    //   [16] UUID
    //   [1]  addon_len = 0x00  (no addons)
    //   [1]  command   = 0x01  (TCP)
    //   [2]  port      (big-endian)
    //   [1]  addr_type = 0x02  (domain)
    //   [1]  domain_len
    //   [N]  domain
    //
    // Followed immediately by the proxied TCP payload.
    let mut frame: Vec<u8> = Vec::new();
    frame.push(0x00); // version
    frame.extend_from_slice(&uuid); // UUID
    frame.push(0x00); // addon length
    frame.push(0x01); // command: TCP
    frame.extend_from_slice(&PROXY_TARGET_PORT.to_be_bytes()); // port
    frame.push(0x02); // addr type: domain
    frame.push(PROXY_TARGET_HOST.len() as u8); // domain length
    frame.extend_from_slice(PROXY_TARGET_HOST.as_bytes()); // domain

    // Proxied HTTP request to PROXY_TARGET_HOST
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        PROXY_TARGET_HOST
    );
    frame.extend_from_slice(http_req.as_bytes());

    println!(
        "\n[1] Sending VLESS frame ({} bytes) over Reality TLS...",
        frame.len()
    );

    if let Err(e) = tls.write_all(&frame) {
        eprintln!("\n[FAIL] TLS write error: {}", e);
        eprintln!("  → Reality TLS handshake itself failed (cert mismatch / wrong public key?)");
        std::process::exit(1);
    }
    println!("[2] Frame sent. Reading response...\n");

    let mut buf = vec![0u8; 65536];
    let mut response = Vec::new();

    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 4096 {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }

    // --- Print raw response ---
    println!("=== Response ({} bytes) ===", response.len());
    if let Ok(text) = std::str::from_utf8(&response[..response.len().min(1024)]) {
        println!("{}", text);
    } else {
        println!(
            "(binary, first 32 bytes: {})",
            bytes_to_hex(&response[..response.len().min(32)])
        );
    }

    // --- Verdict ---
    println!("\n=== Verdict ===");
    let s = String::from_utf8_lossy(&response);
    if response.is_empty() {
        println!("✓ Reality auth likely SUCCEEDED — connection closed with no data.");
        println!("  Server recognised us as a VLESS client but something was rejected.");
        println!("  (UUID mismatch, command unsupported, or proxy target unreachable.)");
    } else if s.contains("example.com")
        || s.contains("IANA")
        || s.contains("illustrative examples")
        || s.contains("Example Domain")
    {
        println!("✓✓ Reality auth SUCCEEDED and UUID accepted!");
        println!("   Got response from {} via VLESS proxy.", PROXY_TARGET_HOST);
    } else if s.contains("microsoft")
        || s.contains("Microsoft")
        || s.contains("AkamaiNetStorage")
        || s.contains("AkamaiGHost")
        || s.contains("Akamai")
        || s.contains("mscom")
    {
        println!("✗ Reality auth FAILED — fell back to SNI destination ({}).", sni_servername);
        println!("  Possible causes: wrong public key, short_id not allowed,");
        println!("  or timestamp drift exceeds server tolerance.");
    } else {
        println!(
            "? Inconclusive — {} bytes received, cannot identify source.",
            response.len()
        );
    }
}

/// Parse UUID in "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" or "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" form.
fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let hex_only: String = s.chars().filter(|&c| c != '-').collect();
    if hex_only.len() != 32 {
        return Err(format!(
            "UUID must be 32 hex chars (got {})",
            hex_only.len()
        ));
    }
    let bytes = hex_to_bytes(&hex_only)?;
    bytes
        .try_into()
        .map_err(|_| "UUID conversion failed".into())
}

fn format_uuid(b: &[u8; 16]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        bytes_to_hex(&b[0..4]),
        bytes_to_hex(&b[4..6]),
        bytes_to_hex(&b[6..8]),
        bytes_to_hex(&b[8..10]),
        bytes_to_hex(&b[10..16]),
    )
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "Invalid hex character".into())
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| format!("Invalid Base64: {}", e))
}
