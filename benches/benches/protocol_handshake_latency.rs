use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn synthetic_handshake(rounds: usize) -> u64 {
    let mut acc = 0u64;
    for i in 0..rounds {
        acc = acc.rotate_left(5) ^ (i as u64).wrapping_mul(0x9E37_79B9);
        acc = acc.wrapping_add(0xD6E8_FD9D);
    }
    acc
}

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_handshake_latency");
    for rounds in [64usize, 256, 1024] {
        group.bench_with_input(BenchmarkId::from_parameter(rounds), &rounds, |b, r| {
            b.iter(|| synthetic_handshake(*r))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
