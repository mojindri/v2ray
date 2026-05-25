use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn relay_copy(buf: &[u8], rounds: usize) -> usize {
    let mut total = 0usize;
    for _ in 0..rounds {
        let mut dst = Vec::with_capacity(buf.len());
        dst.extend_from_slice(buf);
        total += dst.len();
    }
    total
}

fn bench_tcp_relay(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_relay_throughput");
    for size in [1024usize, 16 * 1024, 64 * 1024] {
        let payload = vec![0xAB; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, p| {
            b.iter(|| relay_copy(p, 64))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_tcp_relay);
criterion_main!(benches);
