//! Criterion registration for the full e2e protocol bench matrix.

use std::time::{Duration, Instant};

use bench_harness::{
    alloc_reset, alloc_snapshot, bench_runtime, concurrent_short_lived, log_alloc,
    mixed_small_writes, relay_bulk, short_lived_session, ProtocolPath,
};
use bench_harness::{
    bulk_chunk_sizes, bulk_transfer_sizes, concurrency_levels, mixed_write_chunk_sizes,
    short_lived_payload_sizes,
};
use criterion::{BenchmarkId, Criterion, Throughput};

fn iter_timeout() -> Duration {
    if let Ok(raw) = std::env::var("BENCH_ITER_TIMEOUT_MS") {
        if let Ok(ms) = raw.parse::<u64>() {
            if ms > 0 {
                return Duration::from_millis(ms);
            }
        }
    }
    if std::env::var("BENCH_QUICK").is_ok() {
        Duration::from_secs(8)
    } else {
        Duration::from_secs(20)
    }
}

fn max_connects_per_sample() -> u64 {
    std::env::var("BENCH_MAX_CONNECTS_PER_SAMPLE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            std::env::var("BENCH_HANDSHAKE_MAX_CONNECTS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
        })
        .filter(|v| *v > 0)
        .unwrap_or(32)
}

fn handshake_max_connects_per_sample() -> u64 {
    max_connects_per_sample()
}

fn short_lived_max_iters_per_sample(sessions_per_iter: usize) -> u64 {
    let base = max_connects_per_sample();
    let sessions = sessions_per_iter.max(1) as u64;
    (base / sessions).max(1)
}

fn scale_sample_elapsed(elapsed: Duration, actual_iters: u64, requested_iters: u64) -> Duration {
    if actual_iters == requested_iters {
        elapsed
    } else {
        elapsed.mul_f64(requested_iters as f64 / actual_iters as f64)
    }
}

fn capped_connect_sample_time(
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    requested_iters: u64,
) -> Duration {
    let actual_iters = requested_iters
        .min(handshake_max_connects_per_sample())
        .max(1);
    let elapsed = rt.block_on(async {
        let start = Instant::now();
        for i in 0..actual_iters {
            let stream = pair.connect().await;
            bench_harness::abort_tcp_on_close(&stream);
            drop(stream);
            // Brief pause every few connects so macOS can recycle local ports (EADDRNOTAVAIL).
            if i > 0 && i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        start.elapsed()
    });
    scale_sample_elapsed(elapsed, actual_iters, requested_iters)
}

fn capped_short_lived_sample_time(
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    payload: usize,
    requested_iters: u64,
) -> Duration {
    let actual_iters = requested_iters
        .min(short_lived_max_iters_per_sample(1))
        .max(1);
    let elapsed = rt.block_on(async {
        let start = Instant::now();
        for i in 0..actual_iters {
            alloc_reset();
            short_lived_session(pair, payload).await;
            if i > 0 && i % 4 == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        start.elapsed()
    });
    scale_sample_elapsed(elapsed, actual_iters, requested_iters)
}

fn capped_concurrency_sample_time(
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    sessions: usize,
    payload: usize,
    requested_iters: u64,
) -> Duration {
    let actual_iters = requested_iters
        .min(short_lived_max_iters_per_sample(sessions))
        .max(1);
    let elapsed = rt.block_on(async {
        let start = Instant::now();
        for i in 0..actual_iters {
            alloc_reset();
            concurrent_short_lived(pair, sessions, payload).await;
            if i > 0 && i % 2 == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        start.elapsed()
    });
    scale_sample_elapsed(elapsed, actual_iters, requested_iters)
}

pub fn register_protocol_benches(c: &mut Criterion, path: ProtocolPath) {
    let name = path.bench_name();
    let rt = bench_runtime();
    let pair = rt.block_on(path.setup(false));
    let bulk_only =
        std::env::var("BENCH_BULK_ONLY").is_ok() || std::env::var("BENCH_BULK_SWEEP").is_ok();
    let skip_handshake = std::env::var("BENCH_SKIP_HANDSHAKE").is_ok() || bulk_only;
    if !skip_handshake {
        register_handshake(c, &rt, &pair, name);
    }
    register_bulk(c, &rt, &pair, name);
    if !bulk_only {
        register_short_lived(c, &rt, &pair, name);
        register_mixed_writes(c, &rt, &pair, name);
        register_concurrency(c, &rt, &pair, name);
    }

    if !skip_handshake && std::env::var("BENCH_SNIFF").is_ok() && !path.uses_http_connect() {
        let sniff_pair = rt.block_on(path.setup(true));
        register_handshake_sniff(c, &rt, &sniff_pair, name);
    }
}

fn register_handshake(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    name: &str,
) {
    let mut group = c.benchmark_group(format!("{name}/handshake"));
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(250));
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("connect", |b| {
        // Criterion can request very high iteration counts for tiny operations.
        // Cap real connects per sample to avoid exhausting local ephemeral ports.
        b.iter_custom(|iters| capped_connect_sample_time(rt, pair, iters));
    });
    group.finish();
}

fn register_handshake_sniff(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    name: &str,
) {
    let mut group = c.benchmark_group(format!("{name}/handshake_sniff"));
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(250));
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("connect_with_sniffing", |b| {
        b.iter_custom(|iters| capped_connect_sample_time(rt, pair, iters));
    });
    group.finish();
}

fn register_bulk(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    name: &str,
) {
    let timeout = iter_timeout();
    let mut group = c.benchmark_group(format!("{name}/bulk_relay"));
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_secs(5));

    for chunk in bulk_chunk_sizes() {
        for total in bulk_transfer_sizes() {
            group.throughput(Throughput::Bytes(total as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("steady_state/chunk_{chunk}"), total),
                &total,
                |b, &total| {
                    // iter_custom allows measuring N iterations over one long-lived stream.
                    // This avoids opening thousands of connections, which exhausts macOS's
                    // ephemeral port pool (~16k ports).
                    b.iter_custom(|iters| {
                        rt.block_on(async {
                            let mut stream = pair.connect().await;
                            let mut total_time = Duration::ZERO;
                            for _ in 0..iters {
                                alloc_reset();
                                let t0 = Instant::now();
                                let moved = match tokio::time::timeout(
                                    timeout,
                                    relay_bulk(&mut stream, total, chunk),
                                )
                                .await
                                {
                                    Ok(moved) => moved,
                                    Err(_) => panic!(
                                        "bench timeout: {name}/bulk_relay total={total} chunk={chunk} exceeded {:?}; tune via BENCH_ITER_TIMEOUT_MS",
                                        timeout
                                    ),
                                };
                                total_time += t0.elapsed();
                                log_alloc(name, "bulk", alloc_snapshot(), moved);
                            }
                            total_time
                        })
                    });
                },
            );
        }
    }
    group.finish();
}

fn register_short_lived(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    name: &str,
) {
    let mut group = c.benchmark_group(format!("{name}/short_lived"));
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(250));
    group.measurement_time(Duration::from_secs(3));

    for payload in short_lived_payload_sizes() {
        group.throughput(Throughput::Bytes(payload as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload),
            &payload,
            |b, &payload| {
                b.iter_custom(|iters| capped_short_lived_sample_time(rt, pair, payload, iters));
            },
        );
    }
    group.finish();
}

fn register_mixed_writes(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    name: &str,
) {
    let timeout = iter_timeout();
    let mut group = c.benchmark_group(format!("{name}/mixed_small_writes"));
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_secs(5));
    const ROUNDS: usize = 64;

    for chunk in mixed_write_chunk_sizes() {
        group.throughput(Throughput::Bytes((chunk * ROUNDS) as u64));
        group.bench_with_input(
            BenchmarkId::new("chunk_x64", chunk),
            &chunk,
            |b, &chunk| {
                b.iter_custom(|iters| {
                    rt.block_on(async {
                        let mut stream = pair.connect().await;
                        let mut total_time = Duration::ZERO;
                        for _ in 0..iters {
                            alloc_reset();
                            let t0 = Instant::now();
                            let moved = match tokio::time::timeout(
                                timeout,
                                mixed_small_writes(&mut stream, chunk, ROUNDS),
                            )
                            .await
                            {
                                Ok(moved) => moved,
                                Err(_) => panic!(
                                    "bench timeout: {name}/mixed_small_writes chunk={chunk} exceeded {:?}; tune via BENCH_ITER_TIMEOUT_MS",
                                    timeout
                                ),
                            };
                            total_time += t0.elapsed();
                            log_alloc(name, "mixed_writes", alloc_snapshot(), moved);
                        }
                        total_time
                    })
                });
            },
        );
    }
    group.finish();
}

fn register_concurrency(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    pair: &bench_harness::ProxyPair,
    name: &str,
) {
    let mut group = c.benchmark_group(format!("{name}/concurrency"));
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(250));
    group.measurement_time(Duration::from_secs(3));
    let payload = 256usize;

    for sessions in concurrency_levels() {
        group.throughput(Throughput::Bytes((payload * sessions) as u64));
        group.bench_with_input(
            BenchmarkId::new("short_lived_fanout", sessions),
            &sessions,
            |b, &sessions| {
                b.iter_custom(|iters| {
                    capped_concurrency_sample_time(rt, pair, sessions, payload, iters)
                });
            },
        );
    }
    group.finish();
}
