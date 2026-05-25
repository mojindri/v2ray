use std::pin::Pin;
use std::task::{Context, Poll};

use blackwire_common::Address;
use blackwire_protocol::http_connect::parse_connect_request;
use blackwire_protocol::trojan::codec as trojan_codec;
use blackwire_protocol::vless::codec as vless_codec;
use blackwire_protocol::vmess::auth as vmess_auth;
use blackwire_protocol::vmess::codec as vmess_codec;
use blackwire_protocol::vmess::codec::Security as VmessSecurity;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

struct ChunkedRead<S> {
    inner: S,
    max: usize,
}

impl<S> ChunkedRead<S> {
    fn new(inner: S, max: usize) -> Self {
        Self {
            inner,
            max: max.max(1),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ChunkedRead<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let cap = self.max.min(buf.remaining()).max(1);
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

impl<S: AsyncWrite + Unpin> AsyncWrite for ChunkedRead<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn vless_header_fragmented_at_every_byte_boundary() {
    let msg = vless_codec::encode_request(
        &[0xAA; 16],
        "xtls-rprx-vision",
        vless_codec::Command::Tcp,
        &Address::Domain("frag.example".into(), 443),
    )
    .expect("encode");
    for split in 1..msg.len() {
        let (mut w, r) = tokio::io::duplex(4096);
        let m = msg.clone();
        tokio::spawn(async move {
            w.write_all(&m[..split]).await.expect("write a");
            w.write_all(&m[split..]).await.expect("write b");
        });
        let mut rr = ChunkedRead::new(r, 1);
        let req = vless_codec::decode_request(&mut rr).await.expect("decode");
        assert_eq!(req.uuid, [0xAA; 16]);
    }
}

#[tokio::test]
async fn vmess_header_fragmented_at_every_byte_boundary() {
    let uuid = [0xBB; 16];
    let cmd_key = vmess_auth::cmd_key(&uuid);
    let auth_id = vmess_auth::generate_auth_id(&cmd_key);
    let (_iv, _key, _v, nonce, enc_len, enc_header) = vmess_codec::encode_header(
        &cmd_key,
        &auth_id,
        &Address::Domain("frag.example".into(), 443),
        VmessSecurity::Aes128Gcm,
    )
    .expect("encode");
    let enc_len_arr: [u8; 18] = enc_len
        .as_slice()
        .try_into()
        .expect("vmess encrypted length is 18 bytes");
    let body_len = vmess_codec::decrypt_length_field(&cmd_key, &auth_id, &nonce, &enc_len_arr)
        .expect("dec len");
    for split in 1..enc_header.len() {
        let (mut w, r) = tokio::io::duplex(8192);
        let hdr = enc_header.clone();
        tokio::spawn(async move {
            w.write_all(&hdr[..split]).await.expect("write a");
            w.write_all(&hdr[split..]).await.expect("write b");
        });
        let mut rr = ChunkedRead::new(r, 1);
        let req = vmess_codec::decode_header(&mut rr, &cmd_key, &auth_id, &nonce, body_len)
            .await
            .expect("decode");
        assert_eq!(req.dest, Address::Domain("frag.example".into(), 443));
    }
}

#[tokio::test]
async fn trojan_header_fragmented_at_every_byte_boundary() {
    let token = trojan_codec::compute_token("frag-password");
    let msg = trojan_codec::encode_request(&token, &Address::Domain("frag.example".into(), 443))
        .expect("encode");
    for split in 1..msg.len() {
        let (mut w, r) = tokio::io::duplex(4096);
        let m = msg.clone();
        tokio::spawn(async move {
            w.write_all(&m[..split]).await.expect("write a");
            w.write_all(&m[split..]).await.expect("write b");
        });
        let mut rr = ChunkedRead::new(r, 1);
        let req = trojan_codec::decode_request(&mut rr).await.expect("decode");
        assert_eq!(req.dest, Address::Domain("frag.example".into(), 443));
    }
}

#[tokio::test]
async fn http_connect_parser_accepts_random_1_to_32_chunks() {
    let req = b"CONNECT frag.example:443 HTTP/1.1\r\nHost: frag.example\r\n\r\n";
    for chunk in 1..=32usize {
        let (mut w, r) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            for part in req.chunks(chunk) {
                w.write_all(part).await.expect("write");
            }
        });
        let (dest, _stream) = parse_connect_request(Box::new(ChunkedRead::new(r, chunk)))
            .await
            .expect("parse");
        assert_eq!(dest, Address::Domain("frag.example".into(), 443));
    }
}
