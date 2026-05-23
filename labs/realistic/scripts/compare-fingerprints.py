#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def run(cmd):
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def tshark_summary(path):
    p = run([
        "tshark",
        "-r", str(path),
        "-Y", "tls.handshake.type == 1",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.extensions_alpn_str",
    ])
    if p is None:
        return {"available": False, "reason": "tshark not installed"}
    if p.returncode != 0:
        return {"available": False, "reason": p.stderr.strip()[:500]}

    lines = [line for line in p.stdout.splitlines() if line.strip()]
    return {
        "available": True,
        "client_hello_count": len(lines),
        "client_hello_fields": lines[:20],
    }


def collect_pcap_items(paths):
    items = []
    for path in paths:
        items.append({
            "path": str(path),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "tshark": tshark_summary(path),
        })
    return items


def count_client_hellos(items):
    total = 0
    for item in items:
        tshark = item.get("tshark") or {}
        if tshark.get("available"):
            total += int(tshark.get("client_hello_count") or 0)
    return total


def count_sni(items, expected_sni):
    if not expected_sni:
        return 0

    total = 0
    for item in items:
        tshark = item.get("tshark") or {}
        if not tshark.get("available"):
            continue
        for line in tshark.get("client_hello_fields") or []:
            if expected_sni in line:
                total += 1
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports/production")
    ap.add_argument("--strict", action="store_true", help="fail if artifacts or baselines are missing or unverifiable")
    ap.add_argument("--expect-baseline-sni", default="", help="when strict, require at least one baseline ClientHello with this SNI")
    args = ap.parse_args()

    reports = pathlib.Path(args.reports)
    if not reports.is_absolute():
        reports = pathlib.Path.cwd() / reports

    baseline_dir = reports / "baselines"

    all_pcaps = sorted(reports.glob("**/*.pcap")) + sorted(reports.glob("**/*.pcapng"))

    baseline_pcaps = []
    if baseline_dir.exists():
        baseline_pcaps = sorted(baseline_dir.glob("*.pcap")) + sorted(baseline_dir.glob("*.pcapng"))

    baseline_set = {p.resolve() for p in baseline_pcaps}
    pcaps = [p for p in all_pcaps if p.resolve() not in baseline_set]

    artifacts = collect_pcap_items(pcaps)
    baselines = collect_pcap_items(baseline_pcaps)

    result = {
        "reports": str(reports),
        "pcaps_found": len(pcaps),
        "baseline_pcaps_found": len(baseline_pcaps),
        "strict": args.strict,
        "expect_baseline_sni": args.expect_baseline_sni,
        "note": "Functional interop is not fingerprint proof. This helper compares available pcap artifacts and summarizes ClientHello fields when tshark exists.",
        "artifacts": artifacts,
        "baselines": baselines,
    }

    out = reports / "fingerprint-compare.json"
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

    if not args.strict:
        if not pcaps:
            print("SKIP: no artifact pcap files found. Run make local-pcap or make local-pcap-docker first.", file=sys.stderr)
        if not baseline_pcaps:
            print("SKIP: no baseline pcap files found. Run make local-chrome-baseline-real first.", file=sys.stderr)
        return 0

    errors = []

    if not pcaps:
        errors.append("no artifact pcaps found")
    if not baseline_pcaps:
        errors.append("no baseline pcaps found")

    artifact_hello_count = count_client_hellos(artifacts)
    baseline_hello_count = count_client_hellos(baselines)
    expected_sni_count = count_sni(baselines, args.expect_baseline_sni)

    if artifact_hello_count < 1:
        errors.append("artifact pcaps contain no parsed TLS ClientHello records")
    if baseline_hello_count < 1:
        errors.append("baseline pcaps contain no parsed TLS ClientHello records")
    if args.expect_baseline_sni and expected_sni_count < 1:
        errors.append(f"baseline pcaps contain no ClientHello for expected SNI: {args.expect_baseline_sni}")

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("STRICT fingerprint verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
