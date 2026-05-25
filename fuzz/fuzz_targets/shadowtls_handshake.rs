#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use blackwire_transport::shadowtls::{compute_marker, validate_first_application_record};

const SERVER_RANDOM: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 4096);
    let expected = compute_marker(b"fuzz-shadowtls-psk", &SERVER_RANDOM);
    let _ = validate_first_application_record(&expected, data);
});
