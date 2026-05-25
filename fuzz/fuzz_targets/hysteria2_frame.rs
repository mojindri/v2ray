#![no_main]

#[path = "common.rs"]
mod common;

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use blackwire_transport::hysteria2::proto::{decode_tcp_request, decode_tcp_response};
use blackwire_transport::hysteria2::udp::decode_udp_datagram;

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 8192);

    common::block_on(async {
        let mut cursor = Cursor::new(data);
        let _ = decode_tcp_request(&mut cursor).await;
    });
    common::block_on(async {
        let mut cursor = Cursor::new(data);
        let _ = decode_tcp_response(&mut cursor).await;
    });

    let _ = decode_udp_datagram(data);
});
