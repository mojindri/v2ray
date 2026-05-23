#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import statistics
import subprocess
import time


def one_request(proxy: str, url: str, timeout: float) -> dict:
    start = time.perf_counter()
    p = subprocess.run(
        [
            "curl",
            "-fsS",
            "--max-time",
            str(timeout),
            "-x",
            proxy,
            url,
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return {
        "ok": p.returncode == 0 and p.stdout.strip().startswith(("2", "3")),
        "code": p.stdout.strip(),
        "elapsed_ms": elapsed_ms,
        "stderr": p.stderr.strip()[:300],
    }


def pct(values, p):
    if not values:
        return None
    values = sorted(values)
    idx = int(round((p / 100.0) * (len(values) - 1)))
    return values[idx]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default="socks5h://127.0.0.1:1080")
    ap.add_argument("--url", default="http://127.0.0.1:18080/")
    ap.add_argument("--requests", type=int, default=250)
    ap.add_argument("--concurrency", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--min-success-rate", type=float, default=0.99)
    args = ap.parse_args()

    results = []
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(one_request, args.proxy, args.url, args.timeout) for _ in range(args.requests)]
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())

    elapsed = time.perf_counter() - started
    ok = sum(1 for r in results if r["ok"])
    failed = len(results) - ok
    lat = [r["elapsed_ms"] for r in results if r["ok"]]

    report = {
        "requests": len(results),
        "concurrency": args.concurrency,
        "ok": ok,
        "failed": failed,
        "success_rate": ok / max(1, len(results)),
        "elapsed_seconds": elapsed,
        "requests_per_second": len(results) / max(0.001, elapsed),
        "latency_ms": {
            "min": min(lat) if lat else None,
            "p50": pct(lat, 50),
            "p95": pct(lat, 95),
            "p99": pct(lat, 99),
            "max": max(lat) if lat else None,
            "mean": statistics.mean(lat) if lat else None,
        },
        "sample_failures": [r for r in results if not r["ok"]][:5],
    }

    print(json.dumps(report, indent=2))

    if report["success_rate"] < args.min_success_rate:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
