use blackwire_common::Address;
use blackwire_protocol::vless::codec as vless_codec;
use blackwire_transport::{decode_grpc_frame, encode_grpc_frame};
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn vless_partial_frame_then_more_bytes_decodes_cleanly() {
    let uuid = [0x11u8; 16];
    let msg = vless_codec::encode_request(
        &uuid,
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("example.com".into(), 443),
    )
    .expect("encode");

    for split in 1..msg.len() {
        let (mut w, mut r) = tokio::io::duplex(4096);
        let m = msg.clone();
        tokio::spawn(async move {
            w.write_all(&m[..split]).await.expect("write a");
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            w.write_all(&m[split..]).await.expect("write b");
        });
        let req = vless_codec::decode_request(&mut r).await.expect("decode");
        assert_eq!(req.uuid, uuid);
        assert_eq!(req.dest, Address::Domain("example.com".into(), 443));
    }
}

#[tokio::test]
async fn invalid_frame_then_valid_frame_does_not_corrupt_next_parse() {
    let bad = vec![0xFF, 0x00, 0x00];
    let good = vless_codec::encode_request(
        &[0x22; 16],
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("good.example".into(), 80),
    )
    .expect("encode");

    let mut bad_cursor = std::io::Cursor::new(bad);
    let first = vless_codec::decode_request(&mut bad_cursor).await;
    assert!(first.is_err(), "invalid first frame must fail");

    // New parser instance on the next frame must still decode correctly.
    let mut good_cursor = std::io::Cursor::new(good);
    let second = vless_codec::decode_request(&mut good_cursor)
        .await
        .expect("decode second");
    assert_eq!(second.uuid, [0x22; 16]);
    assert_eq!(second.dest, Address::Domain("good.example".into(), 80));
}

#[tokio::test]
async fn valid_auth_then_malformed_command_rejected_without_stuck_state() {
    let mut frame = vless_codec::encode_request(
        &[0x33; 16],
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("ok.example".into(), 443),
    )
    .expect("encode")
    .to_vec();
    // command byte position: ver(1)+uuid(16)+addons_len(1)=18
    frame[18] = 0xFF;
    let mut c = std::io::Cursor::new(frame);
    let res = vless_codec::decode_request(&mut c).await;
    assert!(res.is_err(), "malformed command must be rejected");
}

#[test]
fn grpc_decode_partial_then_retry_and_close_mid_frame() {
    let payload = b"hello-stateful";
    let wire = encode_grpc_frame(payload);
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&wire[..3]);
    assert!(decode_grpc_frame(&mut buf).expect("decode").is_none());

    buf.extend_from_slice(&wire[3..]);
    let decoded = decode_grpc_frame(&mut buf)
        .expect("decode")
        .expect("full frame");
    assert_eq!(&decoded[..], payload);

    // close mid-frame equivalent: header advertises length but bytes truncated
    let mut truncated = BytesMut::new();
    truncated.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x20]);
    truncated.extend_from_slice(b"short");
    let res = decode_grpc_frame(&mut truncated).expect("decode");
    assert!(
        res.is_none(),
        "truncated frame must wait for more bytes, not panic"
    );
}

#[tokio::test]
async fn read_timeout_then_retry_then_success() {
    let msg = vless_codec::encode_request(
        &[0x44; 16],
        "",
        vless_codec::Command::Tcp,
        &Address::Domain("retry.example".into(), 8443),
    )
    .expect("encode");
    let (mut w, mut r) = tokio::io::duplex(4096);

    let timed = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        vless_codec::decode_request(&mut r),
    )
    .await;
    assert!(
        timed.is_err(),
        "initial decode should time out before bytes arrive"
    );

    tokio::spawn(async move {
        w.write_all(&msg).await.expect("write");
    });

    let req = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        vless_codec::decode_request(&mut r),
    )
    .await
    .expect("decode timeout")
    .expect("decode");
    assert_eq!(req.uuid, [0x44; 16]);
}
