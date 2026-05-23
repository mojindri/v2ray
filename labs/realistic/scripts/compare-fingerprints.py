#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="labs/realistic/reports/production")
    args = ap.parse_args()

    reports = pathlib.Path(args.reports)
    pcaps = sorted(reports.glob("**/*.pcap")) + sorted(reports.glob("**/*.pcapng"))

    baseline_dir = reports / "baselines"
    baseline_pcaps = []
    if baseline_dir.exists():
        baseline_pcaps = sorted(baseline_dir.glob("*.pcap")) + sorted(baseline_dir.glob("*.pcapng"))

    result = {
        "reports": str(reports),
        "pcaps_found": len(pcaps),
        "baseline_pcaps_found": len(baseline_pcaps),
        "note": "Functional interop is not fingerprint proof. This helper compares available pcap artifacts and summarizes ClientHello fields when tshark exists.",
        "artifacts": [],
        "baselines": [],
    }

    for path in pcaps:
        result["artifacts"].append({
            "path": str(path),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "tshark": tshark_summary(path),
        })

    for path in baseline_pcaps:
        result["baselines"].append({
            "path": str(path),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "tshark": tshark_summary(path),
        })

    out = reports / "fingerprint-compare.json"
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

    if not pcaps:
        print("SKIP: no pcap artifacts found. Run make local-pcap first.", file=sys.stderr)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
