use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::HashMap;

fn build_route_map() -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for i in 0..10_000usize {
        m.insert(format!("domain-{i}.example.com"), i);
    }
    m
}

fn bench_routing_lookup(c: &mut Criterion) {
    let map = build_route_map();
    c.bench_function("routing_lookup_latency", |b| {
        b.iter(|| {
            for i in 0..500usize {
                let _ = map.get(&format!("domain-{i}.example.com"));
            }
        })
    });
}

fn bench_dns_cache_latency(c: &mut Criterion) {
    let map = build_route_map();
    c.bench_function("dns_cache_latency", |b| {
        b.iter(|| {
            for i in 500..1000usize {
                let _ = map.get(&format!("domain-{i}.example.com"));
            }
        })
    });
}

fn bench_fakeip_allocation(c: &mut Criterion) {
    c.bench_function("fakeip_allocation", |b| {
        b.iter(|| {
            let mut next = 0x0A00_0001u32;
            for _ in 0..1000usize {
                next = next.wrapping_add(1);
                let _fake_ip = next;
            }
        })
    });
}

criterion_group!(
    benches,
    bench_routing_lookup,
    bench_dns_cache_latency,
    bench_fakeip_allocation
);
criterion_main!(benches);
