#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use blackwire_protocol::ss2022::try_decrypt_chunk_for_fuzz;

const SUBKEY: [u8; 32] = [0x33; 32];

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 4096);
    let _ = try_decrypt_chunk_for_fuzz(&SUBKEY, data);
});
