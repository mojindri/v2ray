#![no_main]

#[path = "common.rs"]
mod common;

use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;
use proxy_common::Address;
use proxy_protocol::vless::codec as vless_codec;
use proxy_transport::{decode_grpc_frame, encode_grpc_frame};

fuzz_target!(|data: &[u8]| {
    let data = common::bounded(data, 4096);

    // Stateful sequence model:
    // - Append bytes incrementally
    // - Alternate decode attempts
    // - Mix malformed+valid frames
    let mut grpc_buf = BytesMut::new();
    let mut cursor = 0usize;

    while cursor < data.len() {
        let step = (data[cursor] as usize % 32).max(1);
        let end = (cursor + step).min(data.len());
        grpc_buf.extend_from_slice(&data[cursor..end]);
        cursor = end;
        let _ = decode_grpc_frame(&mut grpc_buf);
    }

    // Build a valid VLESS frame, then splice in fuzz bytes at various points
    // to exercise parser recovery across partial/invalid transitions.
    let good = vless_codec::encode_request(
        &[0x11; 16],
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("stateful.example".into(), 443),
    )
    .unwrap_or_else(|_| Bytes::from_static(&[]));
    let mut stream = Vec::with_capacity(good.len() + data.len());
    stream.extend_from_slice(&good);
    stream.extend_from_slice(data);
    stream.extend_from_slice(&encode_grpc_frame(data));

    common::block_on(async {
        let mut rd = std::io::Cursor::new(stream.clone());
        let _ = vless_codec::decode_request(&mut rd).await;
        let _ = vless_codec::decode_request(&mut rd).await;

        // close-mid-frame analogue: truncated cursor slices
        for cut in 0..stream.len().min(64) {
            let mut c = std::io::Cursor::new(&stream[..cut]);
            let _ = vless_codec::decode_request(&mut c).await;
        }
    });
});
