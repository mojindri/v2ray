#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_memory_regression.py <baseline.json> <result.json>", file=sys.stderr)
        return 2

    baseline = json.loads(Path(sys.argv[1]).read_text())
    result = json.loads(Path(sys.argv[2]).read_text())

    memory = result.get("memory") or {}
    peak_rss_kb = float(memory.get("peak_rss_kb") or 10**12)
    peak_fd = float(memory.get("peak_fd") or 10**12)
    peak_threads = float(memory.get("peak_threads") or 10**12)
    rps = float(result.get("requests_per_second") or 0.0)
    p95 = float((result.get("latency_ms") or {}).get("p95") or 10**12)
    p99 = float((result.get("latency_ms") or {}).get("p99") or 10**12)

    failures = []
    if peak_rss_kb > float(baseline["max_peak_rss_kb"]):
        failures.append(f"peak_rss_kb regression: {peak_rss_kb} > {baseline['max_peak_rss_kb']}")
    if peak_fd > float(baseline["max_peak_fd"]):
        failures.append(f"peak_fd regression: {peak_fd} > {baseline['max_peak_fd']}")
    if peak_threads > float(baseline["max_peak_threads"]):
        failures.append(f"peak_threads regression: {peak_threads} > {baseline['max_peak_threads']}")
    if rps < float(baseline["min_requests_per_second"]):
        failures.append(f"rps regression: {rps} < {baseline['min_requests_per_second']}")
    if p95 > float(baseline["max_p95_latency_ms"]):
        failures.append(f"p95 regression: {p95} > {baseline['max_p95_latency_ms']}")
    if p99 > float(baseline["max_p99_latency_ms"]):
        failures.append(f"p99 regression: {p99} > {baseline['max_p99_latency_ms']}")

    if failures:
        print("MEMORY PERF REGRESSION DETECTED")
        for item in failures:
            print(f"- {item}")
        return 1

    print("memory perf gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
