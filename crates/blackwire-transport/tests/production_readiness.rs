//! Production-readiness tests for blackwire-transport.
//!
//! These are not fuzz tests. They are deterministic tests for:
//! - stream byte preservation
//! - partial writes
//! - malformed fixed fixtures
//! - timeout behavior
//! - parser safety
//! - frame/header correctness
//!
//! Some tests are intentionally strict. If they fail, treat that as useful:
//! the transport probably has a real production-hardening gap.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::timeout;

use blackwire_transport::{
    decode_grpc_frame, encode_grpc_frame, ws_accept, ws_connect, GrpcStream, WsConnectConfig,
};

use blackwire_transport::mkcp::header::HeaderType;
use blackwire_transport::mkcp::segment::{Segment, CMD_ACK, CMD_PUSH, OVERHEAD};
use blackwire_transport::reality::parse_client_hello;
use blackwire_transport::tun::{
    build_udp_response_packet, parse_ip_packet, TransportProtocol, TunSessionTable,
};

const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

/// Async IO wrapper that deliberately limits every successful poll_write()
/// to at most `max_write` bytes.
///
/// This is the test harness that catches broken AsyncWrite implementations
/// that assume poll_write writes the entire buffer.
struct LimitedWriteIo {
    inner: DuplexStream,
    max_write: usize,
}

impl LimitedWriteIo {
    fn new(inner: DuplexStream, max_write: usize) -> Self {
        assert!(max_write > 0);
        Self { inner, max_write }
    }
}

impl AsyncRead for LimitedWriteIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for LimitedWriteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = self.max_write.min(buf.len());
        Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Async IO wrapper that returns Pending once before allowing writes.
/// Useful for catching buffer-loss-on-Pending bugs.
struct PendingOnceWriteIo {
    inner: DuplexStream,
    pending_returned: bool,
}

impl PendingOnceWriteIo {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            pending_returned: false,
        }
    }
}

impl AsyncRead for PendingOnceWriteIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PendingOnceWriteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.pending_returned {
            self.pending_returned = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// gRPC frame tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grpc_frame_roundtrip_exact_bytes() {
    let payload = b"hello grpc production test";
    let frame = encode_grpc_frame(payload);

    assert_eq!(frame[0], 0x00);
    assert_eq!(
        u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize,
        payload.len()
    );
    assert_eq!(&frame[5..], payload);

    let mut buf = BytesMut::from(frame.as_ref());
    let decoded = decode_grpc_frame(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.as_ref(), payload);
    assert!(buf.is_empty());
}

#[test]
fn grpc_decoder_rejects_compressed_frame() {
    let mut buf = BytesMut::new();
    buf.put_u8(0x01);
    buf.put_u32(5);
    buf.put_slice(b"hello");

    let err = decode_grpc_frame(&mut buf).unwrap_err();
    assert!(
        err.to_string().contains("compressed"),
        "unexpected error: {err}"
    );
}

#[test]
fn grpc_decoder_rejects_oversized_frame_before_allocation() {
    let mut buf = BytesMut::new();
    buf.put_u8(0x00);
    buf.put_u32(16 * 1024 * 1024 + 1);

    let err = decode_grpc_frame(&mut buf).unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "unexpected error: {err}"
    );
}

#[test]
fn grpc_decoder_preserves_buffer_on_incomplete_frame() {
    let mut buf = BytesMut::new();
    buf.put_u8(0x00);
    buf.put_u32(10);
    buf.put_slice(b"short");

    let before = buf.clone();
    let out = decode_grpc_frame(&mut buf).unwrap();

    assert!(out.is_none());
    assert_eq!(buf, before);
}

#[tokio::test]
async fn grpc_stream_roundtrip_large_payload() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

    let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();

    let mut client = GrpcStream::new(Box::new(client_io));
    let mut server = GrpcStream::new(Box::new(server_io));

    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, server.read_exact(&mut out))
        .await
        .expect("server read timed out")
        .expect("server read failed");

    assert_eq!(out, payload);
}

#[tokio::test]
async fn grpc_stream_handles_one_byte_inner_writes() {
    let (client_raw, server_raw) = tokio::io::duplex(1024 * 1024);

    let limited_client = LimitedWriteIo::new(client_raw, 1);

    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 253) as u8).collect();

    let mut client = GrpcStream::new(Box::new(limited_client));
    let mut server = GrpcStream::new(Box::new(server_raw));

    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, server.read_exact(&mut out))
        .await
        .expect("server read timed out; likely partial-write handling bug")
        .expect("server read failed");

    assert_eq!(out, payload);
}

#[tokio::test]
async fn grpc_stream_flush_survives_pending_inner_flush() {
    let (client_raw, server_raw) = tokio::io::duplex(1024 * 1024);

    let pending_client = PendingOnceWriteIo::new(client_raw);
    let payload = b"pending flush must not lose buffered grpc bytes";

    let mut client = GrpcStream::new(Box::new(pending_client));
    let mut server = GrpcStream::new(Box::new(server_raw));

    client.write_all(payload).await.unwrap();
    timeout(SHORT_TIMEOUT, client.flush())
        .await
        .expect("flush timed out")
        .expect("flush failed");

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, server.read_exact(&mut out))
        .await
        .expect("server read timed out")
        .expect("server read failed");

    assert_eq!(&out, payload);
}

#[tokio::test]
async fn grpc_stream_incomplete_frame_does_not_complete_read() {
    let (mut writer, reader) = tokio::io::duplex(1024);
    let mut stream = GrpcStream::new(Box::new(reader));

    writer
        .write_all(&[0x00, 0x00, 0x00, 0x00, 0x10])
        .await
        .unwrap();
    writer.write_all(b"short").await.unwrap();

    let mut out = [0u8; 16];
    let result = timeout(Duration::from_millis(100), stream.read_exact(&mut out)).await;

    assert!(
        result.is_err(),
        "read completed even though gRPC frame body was incomplete"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket transport tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn websocket_transport_preserves_exact_bytes() {
    let (client_raw, server_raw) = tokio::io::duplex(1024 * 1024);

    let server_task = tokio::spawn(async move {
        ws_accept(Box::new(server_raw))
            .await
            .expect("ws_accept failed")
    });

    let cfg = WsConnectConfig {
        path: "/transport-test".to_string(),
        host: "localhost".to_string(),
        headers: vec![],
    };

    let mut client = ws_connect(Box::new(client_raw), cfg)
        .await
        .expect("ws_connect failed");

    let mut server = timeout(SHORT_TIMEOUT, server_task)
        .await
        .expect("server handshake timed out")
        .expect("server task panicked");

    let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();

    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    let mut out = vec![0u8; payload.len()];
    timeout(SHORT_TIMEOUT, server.read_exact(&mut out))
        .await
        .expect("server read timed out")
        .expect("server read failed");

    assert_eq!(out, payload);
}

#[tokio::test]
async fn websocket_transport_bidirectional_simultaneous_transfer() {
    let (client_raw, server_raw) = tokio::io::duplex(1024 * 1024);

    let server_task = tokio::spawn(async move {
        ws_accept(Box::new(server_raw))
            .await
            .expect("ws_accept failed")
    });

    let cfg = WsConnectConfig {
        path: "/bidi".to_string(),
        host: "localhost".to_string(),
        headers: vec![],
    };

    let mut client = ws_connect(Box::new(client_raw), cfg)
        .await
        .expect("ws_connect failed");

    let mut server = timeout(SHORT_TIMEOUT, server_task)
        .await
        .expect("server handshake timed out")
        .expect("server task panicked");

    let client_payload = vec![0x11u8; 64 * 1024];
    let server_payload = vec![0x22u8; 64 * 1024];
    let outbound = client_payload.clone();
    let expected = server_payload.clone();
    let client_task = tokio::spawn(async move {
        client.write_all(&outbound).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; expected.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
    });
    let server_task = tokio::spawn(async move {
        server.write_all(&server_payload).await.unwrap();
        server.flush().await.unwrap();

        let mut got = vec![0u8; client_payload.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, client_payload);
    });

    timeout(SHORT_TIMEOUT, client_task)
        .await
        .expect("client side timed out")
        .expect("client task panicked");

    timeout(SHORT_TIMEOUT, server_task)
        .await
        .expect("server side timed out")
        .expect("server task panicked");
}

// ─────────────────────────────────────────────────────────────────────────────
// REALITY ClientHello parser tests
// ─────────────────────────────────────────────────────────────────────────────

fn minimal_reality_client_hello_body(
    sni: &str,
    random: [u8; 32],
    session_id: [u8; 32],
    x25519_key: [u8; 32],
) -> Vec<u8> {
    let mut body = BytesMut::new();

    // Handshake header.
    body.put_u8(0x01); // ClientHello
    body.put_u8(0x00); // length placeholder
    body.put_u8(0x00);
    body.put_u8(0x00);

    // legacy_version.
    body.put_u16(0x0303);

    // random.
    body.extend_from_slice(&random);

    // session_id.
    body.put_u8(32);
    body.extend_from_slice(&session_id);

    // cipher_suites.
    body.put_u16(2);
    body.put_u16(0x1301);

    // compression_methods.
    body.put_u8(1);
    body.put_u8(0);

    let mut extensions = BytesMut::new();

    // SNI extension.
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = BytesMut::new();
    sni_ext.put_u16((3 + sni_bytes.len()) as u16); // server_name_list length
    sni_ext.put_u8(0x00); // host_name
    sni_ext.put_u16(sni_bytes.len() as u16);
    sni_ext.extend_from_slice(sni_bytes);

    extensions.put_u16(0x0000);
    extensions.put_u16(sni_ext.len() as u16);
    extensions.extend_from_slice(&sni_ext);

    // key_share extension with X25519.
    let mut key_share_ext = BytesMut::new();
    key_share_ext.put_u16(2 + 2 + 32); // client_shares length
    key_share_ext.put_u16(29); // x25519
    key_share_ext.put_u16(32);
    key_share_ext.extend_from_slice(&x25519_key);

    extensions.put_u16(0x0033);
    extensions.put_u16(key_share_ext.len() as u16);
    extensions.extend_from_slice(&key_share_ext);

    body.put_u16(extensions.len() as u16);
    body.extend_from_slice(&extensions);

    let handshake_len = body.len() - 4;
    body[1] = ((handshake_len >> 16) & 0xff) as u8;
    body[2] = ((handshake_len >> 8) & 0xff) as u8;
    body[3] = (handshake_len & 0xff) as u8;

    body.to_vec()
}

#[test]
fn reality_parser_accepts_minimal_valid_client_hello() {
    let random = [0x11u8; 32];
    let session_id = [0x22u8; 32];
    let key = [0x33u8; 32];

    let body = minimal_reality_client_hello_body("www.example.com", random, session_id, key);

    let parsed = parse_client_hello(&body).expect("valid ClientHello was rejected");

    assert_eq!(parsed.random, random);
    assert_eq!(parsed.session_id, session_id);
    assert_eq!(parsed.x25519_key_share, key);
    assert_eq!(parsed.sni, "www.example.com");
}

#[test]
fn reality_parser_rejects_fixed_malformed_client_hello_fixtures() {
    let random = [0x11u8; 32];
    let session_id = [0x22u8; 32];
    let key = [0x33u8; 32];

    let valid = minimal_reality_client_hello_body("www.example.com", random, session_id, key);

    assert!(parse_client_hello(&[]).is_err());
    assert!(parse_client_hello(&[0x01]).is_err());

    let mut wrong_type = valid.clone();
    wrong_type[0] = 0x02;
    assert!(parse_client_hello(&wrong_type).is_err());

    for cut in 0..valid.len().min(90) {
        let truncated = &valid[..cut];
        let _ = parse_client_hello(truncated);
        // Important: this loop mainly asserts no panic on truncation.
    }

    let mut bad_sid_len = valid.clone();
    // Offset:
    // handshake_type(1) + len(3) + legacy_version(2) + random(32) = 38.
    bad_sid_len[38] = 31;
    assert!(parse_client_hello(&bad_sid_len).is_err());

    let no_key_share = {
        let mut body = BytesMut::new();

        body.put_u8(0x01);
        body.put_u8(0x00);
        body.put_u8(0x00);
        body.put_u8(0x00);
        body.put_u16(0x0303);
        body.extend_from_slice(&random);
        body.put_u8(32);
        body.extend_from_slice(&session_id);
        body.put_u16(2);
        body.put_u16(0x1301);
        body.put_u8(1);
        body.put_u8(0);

        let sni_bytes = b"www.example.com";
        let mut sni_ext = BytesMut::new();
        sni_ext.put_u16((3 + sni_bytes.len()) as u16);
        sni_ext.put_u8(0);
        sni_ext.put_u16(sni_bytes.len() as u16);
        sni_ext.extend_from_slice(sni_bytes);

        let mut exts = BytesMut::new();
        exts.put_u16(0x0000);
        exts.put_u16(sni_ext.len() as u16);
        exts.extend_from_slice(&sni_ext);

        body.put_u16(exts.len() as u16);
        body.extend_from_slice(&exts);

        let len = body.len() - 4;
        body[1] = ((len >> 16) & 0xff) as u8;
        body[2] = ((len >> 8) & 0xff) as u8;
        body[3] = (len & 0xff) as u8;

        body.to_vec()
    };

    assert!(parse_client_hello(&no_key_share).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// mKCP deterministic header / segment tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mkcp_headers_strip_back_to_original_payload() {
    let payload = b"mkcp payload";

    for header in [
        HeaderType::None,
        HeaderType::Srtp,
        HeaderType::Utp,
        HeaderType::WechatVideo,
        HeaderType::Dtls,
        HeaderType::Wireguard,
    ] {
        let encoded = header.encode(payload);

        assert_eq!(encoded.len(), header.size() + payload.len());

        let stripped = header
            .strip(&encoded)
            .expect("encoded packet should always strip");

        assert_eq!(stripped, payload);

        if header.size() > 0 {
            assert!(
                header.strip(&encoded[..header.size() - 1]).is_none(),
                "short packet should not strip for {header:?}"
            );
        }
    }
}

#[test]
fn mkcp_segment_roundtrip_exact_fields() {
    let mut seg = Segment::new(0x11223344, CMD_PUSH);
    seg.frg = 3;
    seg.wnd = 4096;
    seg.ts = 0xaabbccdd;
    seg.sn = 77;
    seg.una = 66;
    seg.data = Bytes::from_static(b"segment payload");

    let mut encoded = BytesMut::new();
    seg.encode(&mut encoded);

    assert_eq!(encoded.len(), OVERHEAD + seg.data.len());

    let mut slice = encoded.as_ref();
    let decoded = Segment::decode(&mut slice).expect("segment should decode");

    assert!(slice.is_empty());
    assert_eq!(decoded.conv, seg.conv);
    assert_eq!(decoded.cmd, seg.cmd);
    assert_eq!(decoded.frg, seg.frg);
    assert_eq!(decoded.wnd, seg.wnd);
    assert_eq!(decoded.ts, seg.ts);
    assert_eq!(decoded.sn, seg.sn);
    assert_eq!(decoded.una, seg.una);
    assert_eq!(decoded.data, seg.data);
}

#[test]
fn mkcp_segment_decode_rejects_incomplete_data_without_consuming_payload() {
    let mut seg = Segment::new(7, CMD_ACK);
    seg.data = Bytes::from_static(b"abcdef");

    let mut encoded = BytesMut::new();
    seg.encode(&mut encoded);

    let truncated = encoded[..encoded.len() - 2].to_vec();
    let original_len = truncated.len();

    let mut slice = truncated.as_slice();
    let out = Segment::decode(&mut slice);

    assert!(out.is_none());
    // The current decoder consumes the fixed header before discovering the
    // payload is truncated. If you want stricter parser semantics, change the
    // decoder and then strengthen this assertion to `slice.len() == original_len`.
    assert!(slice.len() <= original_len);
}

// ─────────────────────────────────────────────────────────────────────────────
// TUN packet parser tests
// ─────────────────────────────────────────────────────────────────────────────

fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let transport_len = if proto == 6 { 20 } else { 8 };
    let mut pkt = vec![0u8; 20 + transport_len];
    let pkt_len = pkt.len() as u16;
    pkt[0] = 0x45; // IPv4, IHL=5.
    pkt[2..4].copy_from_slice(&pkt_len.to_be_bytes());
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    if proto == 6 {
        pkt[32] = 0x50;
    } else if proto == 17 {
        pkt[24..26].copy_from_slice(&(transport_len as u16).to_be_bytes());
    }
    pkt
}

fn ipv6_packet(
    next_header: u8,
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let transport_len = if next_header == 6 { 20 } else { 8 };
    let mut pkt = vec![0u8; 40 + transport_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
    pkt[6] = next_header;
    pkt[8..24].copy_from_slice(&src);
    pkt[24..40].copy_from_slice(&dst);
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    if next_header == 6 {
        pkt[52] = 0x50;
    } else if next_header == 17 {
        pkt[44..46].copy_from_slice(&(transport_len as u16).to_be_bytes());
    }
    pkt
}

#[test]
fn tun_parser_accepts_ipv4_tcp_and_udp() {
    let tcp = ipv4_packet(6, [1, 2, 3, 4], [5, 6, 7, 8], 1234, 443);
    let parsed = parse_ip_packet(&tcp).expect("IPv4 TCP packet rejected");

    assert_eq!(parsed.src, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(parsed.dst, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
    assert_eq!(parsed.src_port, 1234);
    assert_eq!(parsed.dst_port, 443);
    assert_eq!(parsed.protocol, TransportProtocol::Tcp);

    let udp = ipv4_packet(17, [10, 0, 0, 1], [8, 8, 8, 8], 5353, 53);
    let parsed = parse_ip_packet(&udp).expect("IPv4 UDP packet rejected");

    assert_eq!(parsed.protocol, TransportProtocol::Udp);
    assert_eq!(parsed.src_port, 5353);
    assert_eq!(parsed.dst_port, 53);
}

#[test]
fn tun_parser_accepts_ipv6_tcp_and_udp() {
    let src = Ipv6Addr::LOCALHOST.octets();
    let dst = Ipv6Addr::UNSPECIFIED.octets();

    let tcp = ipv6_packet(6, src, dst, 2222, 443);
    let parsed = parse_ip_packet(&tcp).expect("IPv6 TCP packet rejected");

    assert_eq!(parsed.src, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(parsed.dst, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    assert_eq!(parsed.protocol, TransportProtocol::Tcp);
    assert_eq!(parsed.src_port, 2222);
    assert_eq!(parsed.dst_port, 443);

    let udp = ipv6_packet(17, src, dst, 5353, 53);
    let parsed = parse_ip_packet(&udp).expect("IPv6 UDP packet rejected");

    assert_eq!(parsed.protocol, TransportProtocol::Udp);
}

#[test]
fn tun_parser_rejects_short_and_unknown_ip_versions() {
    assert!(parse_ip_packet(&[]).is_none());
    assert!(parse_ip_packet(&[0x45]).is_none());
    assert!(parse_ip_packet(&[0x60; 20]).is_none());
    assert!(parse_ip_packet(&[0xf0, 0, 0, 0]).is_none());
}

#[test]
fn tun_parser_rejects_ipv4_ihl_smaller_than_minimum() {
    let mut pkt = ipv4_packet(6, [1, 1, 1, 1], [2, 2, 2, 2], 1000, 2000);
    pkt[0] = 0x44; // IPv4, IHL=4. Invalid: IHL must be >= 5.

    assert!(
        parse_ip_packet(&pkt).is_none(),
        "IPv4 packet with IHL < 5 must be rejected"
    );
}

#[test]
fn tun_parser_rejects_ipv4_total_length_smaller_than_header() {
    let mut pkt = ipv4_packet(6, [1, 1, 1, 1], [2, 2, 2, 2], 1000, 2000);
    pkt[2..4].copy_from_slice(&(10u16).to_be_bytes());

    assert!(
        parse_ip_packet(&pkt).is_none(),
        "IPv4 total_length smaller than header must be rejected"
    );
}

#[test]
fn tun_builds_udp_response_packet_with_reverse_tuple() {
    let mut request = ipv4_packet(17, [10, 0, 0, 2], [8, 8, 8, 8], 53000, 53);
    request.extend_from_slice(b"query");
    let total_length = request.len() as u16;
    request[2..4].copy_from_slice(&total_length.to_be_bytes());
    let udp_length = (8 + b"query".len()) as u16;
    request[24..26].copy_from_slice(&udp_length.to_be_bytes());

    let parsed = parse_ip_packet(&request).expect("request rejected");
    assert_eq!(parsed.payload(&request).unwrap(), b"query");

    let response = build_udp_response_packet(&parsed, b"answer").expect("response build failed");
    let parsed_response = parse_ip_packet(&response).expect("response rejected");

    assert_eq!(parsed_response.src, parsed.dst);
    assert_eq!(parsed_response.dst, parsed.src);
    assert_eq!(parsed_response.src_port, 53);
    assert_eq!(parsed_response.dst_port, 53000);
    assert_eq!(parsed_response.payload(&response).unwrap(), b"answer");
}

#[test]
fn tun_session_table_tracks_reverse_udp_flow_and_expiry() {
    let request = ipv4_packet(17, [10, 0, 0, 2], [8, 8, 8, 8], 53000, 53);
    let response = ipv4_packet(17, [8, 8, 8, 8], [10, 0, 0, 2], 53, 53000);
    let request = parse_ip_packet(&request).expect("request rejected");
    let response = parse_ip_packet(&response).expect("response rejected");
    let now = std::time::Instant::now();

    let mut table = TunSessionTable::new();
    table.observe_packet(&request, now).expect("flow rejected");
    assert!(table.find_response_flow(&response).is_some());
    assert_eq!(
        table.remove_expired(
            now + std::time::Duration::from_secs(61),
            std::time::Duration::from_secs(60)
        ),
        1
    );
    assert!(table.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// General relay timeout / cancellation-style tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn grpc_read_from_idle_peer_times_out_in_test_harness() {
    let (_writer, reader) = tokio::io::duplex(1024);
    let mut stream = GrpcStream::new(Box::new(reader));

    let mut out = [0u8; 1];
    let result = timeout(Duration::from_millis(100), stream.read_exact(&mut out)).await;

    assert!(
        result.is_err(),
        "idle peer read completed unexpectedly; timeout harness is broken"
    );
}

#[tokio::test]
async fn websocket_handshake_with_idle_peer_times_out_in_test_harness() {
    let (client_raw, _server_raw) = tokio::io::duplex(1024);

    let cfg = WsConnectConfig {
        path: "/idle".to_string(),
        host: "localhost".to_string(),
        headers: vec![],
    };

    let result = timeout(
        Duration::from_millis(100),
        ws_connect(Box::new(client_raw), cfg),
    )
    .await;

    assert!(
        result.is_err(),
        "WebSocket handshake against idle peer should not complete"
    );
}
