use bytes::BytesMut;
use proxy_common::Address;
use proxy_protocol::vless::codec as vless_codec;
use proxy_transport::hysteria2::udp::{
    decode_udp_datagram, encode_udp_datagram, Destination, UdpDatagram,
};
use proxy_transport::{
    decode_grpc_frame, grpc_accept, grpc_connect, ws_accept, ws_connect, WsConnectConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn vless_rejects_oversized_domain_and_flow() {
    let uuid = [0x11u8; 16];
    let long_domain = "d".repeat(300);
    let long_flow = "f".repeat(512);

    let domain_res = vless_codec::encode_request(
        &uuid,
        "",
        vless_codec::Command::Tcp,
        &Address::Domain(long_domain, 443),
    );
    assert!(domain_res.is_err(), "oversized domain must be rejected");

    let flow_res = vless_codec::encode_request(
        &uuid,
        &long_flow,
        vless_codec::Command::Tcp,
        &Address::Domain("example.com".into(), 443),
    );
    assert!(flow_res.is_err(), "oversized addons/flow must be rejected");
}

#[tokio::test]
async fn grpc_rejects_oversized_frame_header() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0x00]);
    buf.extend_from_slice(&(17u32 * 1024 * 1024).to_be_bytes());
    buf.extend_from_slice(&[0u8; 8]);
    let res = decode_grpc_frame(&mut buf);
    assert!(res.is_err(), "gRPC decoder must reject >16MiB frame");
}

#[tokio::test]
async fn websocket_large_binary_frame_roundtrips() {
    let payload = vec![0x7Au8; 512 * 1024];
    let (a, b) = tokio::io::duplex(1 << 22);
    let server = tokio::spawn(async move { ws_accept(Box::new(b)).await });
    let mut client = ws_connect(
        Box::new(a),
        WsConnectConfig {
            path: "/big".into(),
            host: "localhost".into(),
            headers: vec![],
        },
    )
    .await
    .expect("ws connect");
    let mut accepted = server.await.expect("join").expect("accept");

    client.write_all(&payload).await.expect("write");
    client.flush().await.expect("flush");

    let mut got = vec![0u8; payload.len()];
    accepted.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload);
}

#[tokio::test]
async fn grpc_large_data_frame_roundtrips_without_corruption() {
    let payload = vec![0x55u8; 256 * 1024];
    let (a, b) = tokio::io::duplex(1 << 22);
    let server = tokio::spawn(async move { grpc_accept(Box::new(b), "svc.Big").await });
    let mut client = grpc_connect(Box::new(a), "localhost", "svc.Big")
        .await
        .expect("grpc connect");
    let mut accepted = server.await.expect("join").expect("accept");

    client.write_all(&payload).await.expect("write");
    client.flush().await.expect("flush");

    let mut got = vec![0u8; payload.len()];
    accepted.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload);
}

#[test]
fn hysteria2_udp_domain_length_overflow_does_not_decode_as_original_domain() {
    let long = "x".repeat(300);
    let dg = UdpDatagram {
        session_id: 1,
        packet_id: 2,
        frag_id: 0,
        frag_num: 1,
        dest: Destination::Domain(long.clone(), 53),
        data: bytes::Bytes::from_static(b"payload"),
    };
    let wire = encode_udp_datagram(&dg);
    let decoded = decode_udp_datagram(&wire).expect("decode");
    match decoded.dest {
        Destination::Domain(name, _) => {
            assert_ne!(
                name.len(),
                long.len(),
                "overflowed domain length must not silently preserve oversized value"
            );
        }
        _ => panic!("expected domain destination"),
    }
}

#[test]
fn mkcp_segment_decode_rejects_truncated_large_payload_packet() {
    let mut packet = vec![];
    // conv + cmd + frg + wnd + ts + sn + una
    packet.extend_from_slice(&1u32.to_le_bytes());
    packet.push(proxy_transport::mkcp::segment::CMD_PUSH);
    packet.push(0);
    packet.extend_from_slice(&0u16.to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend_from_slice(&1u32.to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    // claimed payload length (huge) with no actual payload bytes
    packet.extend_from_slice(&(64u32 * 1024).to_le_bytes());

    let mut slice = packet.as_slice();
    let seg = proxy_transport::mkcp::segment::Segment::decode(&mut slice);
    assert!(
        seg.is_none(),
        "truncated large mKCP payload must fail decode cleanly"
    );
}
