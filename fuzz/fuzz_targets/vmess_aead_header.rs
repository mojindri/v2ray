#![no_main]

#[path = "common.rs"]
mod common;

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use blackwire_protocol::vmess::codec::decode_header;

const CMD_KEY: [u8; 16] = [0x11; 16];
const AUTH_ID: [u8; 16] = [0x22; 16];

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 4096);
    common::block_on(async {
        let mut cursor = Cursor::new(data);
        let _ = decode_header(&mut cursor, &CMD_KEY, &AUTH_ID, data.len()).await;
    });
});
