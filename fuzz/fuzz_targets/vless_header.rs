#![no_main]

#[path = "common.rs"]
mod common;

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use blackwire_protocol::vless::codec::decode_request;

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 4096);
    common::block_on(async {
        let mut cursor = Cursor::new(data);
        let _ = decode_request(&mut cursor).await;
    });
});
