#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use watfaq_rustls::internal::fuzzing::fuzz_deframer;

fuzz_target!(|bytes: &[u8]| { fuzz_deframer(bytes) });
