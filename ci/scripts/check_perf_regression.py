#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_perf_regression.py <baseline.json> <result.json>", file=sys.stderr)
        return 2

    baseline = json.loads(Path(sys.argv[1]).read_text())
    result = json.loads(Path(sys.argv[2]).read_text())

    rps = float(result.get("requests_per_second", 0.0))
    p95 = float((result.get("latency_ms") or {}).get("p95") or 10**9)
    p99 = float((result.get("latency_ms") or {}).get("p99") or 10**9)
    success_rate = float(result.get("success_rate", 0.0))
    error_rate = 1.0 - success_rate

    failures = []
    if rps < float(baseline["min_requests_per_second"]):
        failures.append(f"rps regression: {rps} < {baseline['min_requests_per_second']}")
    if p95 > float(baseline["max_p95_latency_ms"]):
        failures.append(f"p95 regression: {p95} > {baseline['max_p95_latency_ms']}")
    if p99 > float(baseline["max_p99_latency_ms"]):
        failures.append(f"p99 regression: {p99} > {baseline['max_p99_latency_ms']}")
    if error_rate > float(baseline["max_error_rate"]):
        failures.append(f"error_rate regression: {error_rate} > {baseline['max_error_rate']}")

    if failures:
        print("PERF REGRESSION DETECTED")
        for f in failures:
            print(f"- {f}")
        return 1

    print("perf regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
