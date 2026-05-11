#![cfg(feature = "ring")]
#![allow(clippy::disallowed_types)]

use bencher::{benchmark_group, benchmark_main, Bencher};
use watfaq_rustls::crypto::ring as provider;

#[path = "../tests/common/mod.rs"]
mod test_utils;
use std::io;
use std::sync::Arc;

use test_utils::*;
use watfaq_rustls::ServerConnection;

fn bench_ewouldblock(c: &mut Bencher) {
    let server_config = make_server_config(KeyType::Rsa2048, &provider::default_provider());
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    c.iter(|| server.read_tls(&mut TestNonBlockIo::default()));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
