use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use blackwire_common::{Address, BoxedStream};
use blackwire_core::Instance;
use blackwire_protocol::http_connect::parse_connect_request;
use blackwire_protocol::ss2022::{password_to_psk, Ss2022Stream};
use blackwire_protocol::trojan::codec as trojan_codec;
use blackwire_protocol::vless::codec as vless_codec;
use blackwire_protocol::vmess::auth as vmess_auth;
use blackwire_protocol::vmess::codec as vmess_codec;
use blackwire_protocol::vmess::codec::Security as VmessSecurity;
use blackwire_transport::hysteria2::proto::{decode_tcp_request, encode_tcp_request};
use blackwire_transport::mkcp::segment::{Segment, CMD_PUSH};
use blackwire_transport::WsConnectConfig;
use blackwire_transport::{
    grpc_accept, grpc_connect, shadowtls_marker_accept, shadowtls_marker_connect, ws_accept,
    ws_connect,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

struct ChunkedIo<S> {
    inner: S,
    max_read: usize,
    max_write: usize,
}

impl<S> ChunkedIo<S> {
    fn new(inner: S, max_read: usize, max_write: usize) -> Self {
        Self {
            inner,
            max_read: max_read.max(1),
            max_write: max_write.max(1),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ChunkedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let cap = self.max_read.min(buf.remaining()).max(1);
        let mut tmp = vec![0u8; cap];
        let mut rb = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                buf.put_slice(&rb.filled()[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ChunkedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let n = self.max_write.min(buf.len()).max(1);
        Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn write_fragmented(s: &mut TcpStream, data: &[u8]) {
    for b in data {
        s.write_all(&[*b]).await.unwrap();
    }
    s.flush().await.unwrap();
}

fn parse_cfg(v: serde_json::Value) -> Arc<blackwire_config::schema::Config> {
    Arc::new(serde_json::from_value(v).unwrap())
}

async fn spawn_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let lst = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = lst.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = lst.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, task)
}

async fn socks_connect_fragmented(port: u16, host: &str, dest_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    write_fragmented(&mut s, &[5, 1, 0]).await;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let hb = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&dest_port.to_be_bytes());
    write_fragmented(&mut s, &req).await;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s
}

#[tokio::test]
async fn vless_header_decodes_with_every_boundary_fragmentation() {
    let uuid = [0x22u8; 16];
    let encoded = vless_codec::encode_request(
        &uuid,
        "xtls-rprx-vision",
        vless_codec::Command::Tcp,
        &Address::Domain("example.com".to_string(), 443),
    )
    .unwrap();

    for split in 1..encoded.len() {
        let (mut left, right) = tokio::io::duplex(4096);
        let payload = encoded.clone();
        tokio::spawn(async move {
            left.write_all(&payload[..split]).await.unwrap();
            left.write_all(&payload[split..]).await.unwrap();
        });
        let mut frag = ChunkedIo::new(right, 1, 1);
        let decoded = vless_codec::decode_request(&mut frag).await.unwrap();
        assert_eq!(decoded.uuid, uuid);
    }
}

#[tokio::test]
async fn vmess_header_decodes_with_every_boundary_fragmentation() {
    let uuid = [0x44u8; 16];
    let cmd_key = vmess_auth::cmd_key(&uuid);
    let auth_id = vmess_auth::generate_auth_id(&cmd_key);
    let (_iv, _key, _v, conn_nonce, enc_len, enc_header) = vmess_codec::encode_header(
        &cmd_key,
        &auth_id,
        &Address::Domain("example.com".into(), 443),
        VmessSecurity::Aes128Gcm,
    )
    .unwrap();

    let enc_len_arr: [u8; 18] = enc_len
        .as_slice()
        .try_into()
        .expect("vmess encrypted length is 18 bytes");
    let enc_body_len =
        vmess_codec::decrypt_length_field(&cmd_key, &auth_id, &conn_nonce, &enc_len_arr).unwrap();
    for split in 1..enc_header.len() {
        let (mut left, right) = tokio::io::duplex(8192);
        let hdr = enc_header.clone();
        tokio::spawn(async move {
            left.write_all(&hdr[..split]).await.unwrap();
            left.write_all(&hdr[split..]).await.unwrap();
        });
        let mut frag = ChunkedIo::new(right, 1, 1);
        let decoded =
            vmess_codec::decode_header(&mut frag, &cmd_key, &auth_id, &conn_nonce, enc_body_len)
                .await
                .unwrap();
        assert_eq!(decoded.dest, Address::Domain("example.com".into(), 443));
    }
}

#[tokio::test]
async fn trojan_header_decodes_with_every_boundary_fragmentation() {
    let token = trojan_codec::compute_token("fragmented-password");
    let encoded =
        trojan_codec::encode_request(&token, &Address::Domain("example.com".into(), 443)).unwrap();
    for split in 1..encoded.len() {
        let (mut left, right) = tokio::io::duplex(4096);
        let payload = encoded.clone();
        tokio::spawn(async move {
            left.write_all(&payload[..split]).await.unwrap();
            left.write_all(&payload[split..]).await.unwrap();
        });
        let mut frag = ChunkedIo::new(right, 1, 1);
        let req = trojan_codec::decode_request(&mut frag).await.unwrap();
        assert_eq!(req.dest, Address::Domain("example.com".into(), 443));
    }
}

#[tokio::test]
async fn http_connect_parser_handles_byte_by_byte_headers() {
    let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (mut a, b) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        for b in req {
            a.write_all(&[*b]).await.unwrap();
        }
    });
    let (dest, _stream) = parse_connect_request(Box::new(ChunkedIo::new(b, 1, 1)))
        .await
        .unwrap();
    assert_eq!(dest, Address::Domain("example.com".to_string(), 443));
}

#[tokio::test]
async fn hysteria2_request_parser_handles_1_to_32_byte_chunks() {
    let mut frame = vec![];
    encode_tcp_request(&mut frame, "example.com:443")
        .await
        .unwrap();
    for max in 1..=32 {
        let (mut a, b) = tokio::io::duplex(4096);
        let payload = frame.clone();
        tokio::spawn(async move {
            a.write_all(&payload).await.unwrap();
        });
        let mut frag = ChunkedIo::new(b, max, max);
        let req = decode_tcp_request(&mut frag).await.unwrap();
        assert_eq!(req.addr, "example.com:443");
    }
}

#[tokio::test]
async fn shadowtls_marker_accept_handles_fragmented_first_record() {
    let psk = b"shadowtls-frag";
    let (a, b) = tokio::io::duplex(4096);
    let client: BoxedStream = Box::new(ChunkedIo::new(a, 1, 1));
    let server = ChunkedIo::new(b, 1, 1);
    let dest = "fragment.example:443";

    tokio::spawn(async move {
        let _ = shadowtls_marker_connect(client, psk, dest).await.unwrap();
    });

    let _stream = shadowtls_marker_accept(Box::new(server), psk, dest)
        .await
        .unwrap();
}

#[tokio::test]
async fn websocket_handshake_succeeds_with_fragmented_io() {
    for chunk in 1..=32usize {
        let (client_raw, server_raw) = tokio::io::duplex(512);
        let srv = tokio::spawn(async move { ws_accept(Box::new(server_raw)).await });
        let mut client = ws_connect(
            Box::new(client_raw),
            WsConnectConfig {
                path: "/frag".into(),
                host: "localhost".into(),
                headers: vec![],
            },
        )
        .await
        .unwrap();
        let mut server = srv.await.unwrap().unwrap();
        for part in b"ping".chunks(chunk) {
            client.write_all(part).await.unwrap();
        }
        client.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}

#[tokio::test]
async fn grpc_handshake_succeeds_with_fragmented_io() {
    let (client_raw, server_raw) = tokio::io::duplex(1 << 20);
    let srv = tokio::spawn(async move {
        grpc_accept(Box::new(ChunkedIo::new(server_raw, 1, 1)), "frag.Service").await
    });
    let mut client = grpc_connect(
        Box::new(ChunkedIo::new(client_raw, 1, 1)),
        "localhost",
        "frag.Service",
    )
    .await
    .unwrap();
    let mut server = srv.await.unwrap().unwrap();
    client.write_all(b"hello").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0u8; 5];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
}

#[tokio::test]
async fn socks5_inbound_accepts_byte_by_byte_fragmented_handshake() {
    let (echo_port, _echo_task) = spawn_echo().await;
    let socks_port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = parse_cfg(serde_json::json!({
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port
        }],
        "outbounds": [{
            "tag": "direct",
            "protocol": "freedom"
        }]
    }));
    let _instance = Instance::from_config(cfg).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let mut s = socks_connect_fragmented(socks_port, "127.0.0.1", echo_port).await;
    s.write_all(b"frag").await.unwrap();
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(&r, b"frag");
}

#[tokio::test]
async fn ss2022_stream_handles_random_1_to_32_byte_fragmentation() {
    let psk = password_to_psk("ss2022-frag-password");
    let payload = vec![0x4Fu8; 32 * 1024];

    for n in 1..=32usize {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut client = Ss2022Stream::new_with_nonce(Box::new(ChunkedIo::new(a, n, n)), &psk, 2);
        let mut server = Ss2022Stream::new_with_nonce(Box::new(ChunkedIo::new(b, n, n)), &psk, 2);
        let want = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&want).await.unwrap();
            client.flush().await.unwrap();
        });
        let mut got = vec![0u8; payload.len()];
        server.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, payload);
    }
}

#[test]
fn mkcp_segment_decodes_after_fragmented_reassembly() {
    let mut seg = Segment::new(7, CMD_PUSH);
    seg.sn = 11;
    seg.una = 10;
    seg.data = bytes::Bytes::from_static(b"mkcp-fragment");
    let mut wire = bytes::BytesMut::new();
    seg.encode(&mut wire);

    let raw = wire.to_vec();
    for chunk in 1..=32usize {
        let mut assembled = Vec::new();
        for part in raw.chunks(chunk) {
            assembled.extend_from_slice(part);
        }
        let mut slice = assembled.as_slice();
        let decoded = Segment::decode(&mut slice).expect("decode");
        assert_eq!(decoded.conv, 7);
        assert_eq!(decoded.sn, 11);
        assert_eq!(&decoded.data[..], b"mkcp-fragment");
    }
}
