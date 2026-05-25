use bytes::{BufMut, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion};

fn frame_once(payload_len: usize) -> usize {
    let payload = vec![0x11u8; payload_len];
    let mut ws = BytesMut::with_capacity(payload_len + 8);
    ws.put_u32(payload_len as u32);
    ws.extend_from_slice(&payload);

    let mut grpc = BytesMut::with_capacity(payload_len + 5);
    grpc.put_u8(0);
    grpc.put_u32(payload_len as u32);
    grpc.extend_from_slice(&payload);

    ws.len() + grpc.len()
}

fn bench_framing(c: &mut Criterion) {
    c.bench_function("websocket_grpc_framing_overhead", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for n in [128usize, 1024, 4096, 16 * 1024] {
                total += frame_once(n);
            }
            total
        })
    });
}

criterion_group!(benches, bench_framing);
criterion_main!(benches);
