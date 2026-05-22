use bytes::{BufMut, BytesMut};

use super::*;

#[test]
fn encode_frame_structure() {
    let payload = b"hello grpc";
    let frame = encode_grpc_frame(payload);

    assert_eq!(frame.len(), FRAME_HEADER_LEN + payload.len());
    assert_eq!(frame[0], 0x00);
    let len = u32::from_be_bytes(frame[1..5].try_into().unwrap());
    assert_eq!(len as usize, payload.len());
    assert_eq!(&frame[5..], payload);
}

#[test]
fn decode_frame_complete() {
    let payload = b"test data";
    let frame = encode_grpc_frame(payload);
    let mut buf = BytesMut::from(frame.as_ref());

    let decoded = decode_grpc_frame(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.as_ref(), payload);
    assert!(buf.is_empty());
}

#[test]
fn decode_frame_incomplete() {
    let payload = b"needs more data";
    let mut frame = encode_grpc_frame(payload).to_vec();
    frame.truncate(frame.len() - 3);

    let mut buf = BytesMut::from(frame.as_slice());
    let result = decode_grpc_frame(&mut buf).unwrap();
    assert!(result.is_none());
}

#[test]
fn decode_frame_insufficient_header() {
    let mut buf = BytesMut::from(&[0x00, 0x00][..]);
    let result = decode_grpc_frame(&mut buf).unwrap();
    assert!(result.is_none());
}

#[test]
fn decode_multiple_frames() {
    let payload1 = b"first";
    let payload2 = b"second";
    let mut combined = BytesMut::new();
    combined.extend_from_slice(&encode_grpc_frame(payload1));
    combined.extend_from_slice(&encode_grpc_frame(payload2));

    let first = decode_grpc_frame(&mut combined).unwrap().unwrap();
    let second = decode_grpc_frame(&mut combined).unwrap().unwrap();
    assert_eq!(first.as_ref(), payload1);
    assert_eq!(second.as_ref(), payload2);
}

#[test]
fn decode_compressed_frame_returns_error() {
    let mut buf = BytesMut::new();
    buf.put_u8(0x01);
    buf.put_u32(5u32);
    buf.put_slice(b"hello");

    let result = decode_grpc_frame(&mut buf);
    assert!(result.is_err());
}

#[tokio::test]
async fn grpc_stream_write_read_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, server_io) = tokio::io::duplex(65536);
    let payload = b"grpc roundtrip test data";

    let mut client = GrpcStream::new(Box::new(client_io));
    let mut server = GrpcStream::new(Box::new(server_io));

    client.write_all(payload).await.unwrap();
    client.flush().await.unwrap();

    let mut out = vec![0u8; payload.len()];
    server.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, payload);
}

#[tokio::test]
async fn grpc_stream_multi_chunk() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, server_io) = tokio::io::duplex(65536);
    let chunks: &[&[u8]] = &[b"chunk-one", b"chunk-two", b"chunk-three"];

    let mut client = GrpcStream::new(Box::new(client_io));
    let mut server = GrpcStream::new(Box::new(server_io));

    for chunk in chunks {
        client.write_all(chunk).await.unwrap();
        client.flush().await.unwrap();

        let mut out = vec![0u8; chunk.len()];
        server.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, chunk);
    }
}

#[tokio::test]
async fn grpc_stream_large_payload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let payload = vec![0x42u8; 65536];

    let mut client = GrpcStream::new(Box::new(client_io));
    let mut server = GrpcStream::new(Box::new(server_io));

    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();

    let mut out = vec![0u8; payload.len()];
    server.read_exact(&mut out).await.unwrap();
    assert_eq!(out, payload);
}
