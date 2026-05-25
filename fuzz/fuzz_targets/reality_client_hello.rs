#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use blackwire_transport::reality::parse_client_hello;

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 4096);
    let _ = parse_client_hello(data);
});
