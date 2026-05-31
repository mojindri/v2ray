#!/usr/bin/env python3
"""report.py — render latency JSON results as Markdown or HTML.

Usage:
    python3 report.py [--format md|html] [--dir REPORTS_DIR]

Reads the most recent JSON file per variant from REPORTS_DIR and produces
a comparison table sorted by p99 latency.
"""
import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def report_identity(data: dict, fallback: str) -> tuple:
    """Stable identity for a measured row."""
    return (
        data.get("variant", fallback),
        data.get("payload", "unknown"),
        bool(data.get("keepalive", True)),
        int_field(data, "concurrency"),
    )


def find_latest(reports_dir: str) -> list[dict]:
    """Return the most recent result per variant/payload/keepalive/concurrency row."""
    files = glob.glob(os.path.join(reports_dir, "*.json"))
    by_row: dict[tuple, tuple[str, dict]] = {}
    for path in files:
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        key = report_identity(data, os.path.basename(path))
        ts = data.get("timestamp", "")
        prev_ts = by_row.get(key, ("", {}))[0]
        if ts > prev_ts:
            by_row[key] = (ts, data)
    return [v for _, v in sorted(by_row.values(), key=lambda x: x[0])]


def ms(secs) -> str:
    """Format seconds as milliseconds with 2 decimal places."""
    try:
        return f"{float(secs) * 1000:.2f}"
    except (TypeError, ValueError):
        return "—"


def int_field(result: dict, key: str) -> int:
    try:
        return int(result.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def result_failed(result: dict) -> bool:
    return (
        bool(result.get("benchmark_failed", False))
        or int_field(result, "errors") > 0
        or int_field(result, "non_200_responses") > 0
        or int_field(result, "timeout_errors") > 0
        or int_field(result, "eof_errors") > 0
        or int_field(result, "reset_errors") > 0
        or int_field(result, "connection_refused_errors") > 0
        or int_field(result, "other_errors") > 0
    )


def parse_variant(variant: str) -> dict | None:
    """Parse known latency variant names into comparison dimensions."""
    pattern = re.compile(
        r"^(?P<client>xray|singbox)-(?P<server>xray|singbox|bw)(?:-(?P<profile>compat|fast))?-(?P<transport>tcp|ws)(?:-(?P<payload>[^-]+)-(?P<ka>ka|noka))?$"
    )
    match = pattern.match(variant)
    if not match:
        return None
    data = match.groupdict()
    data["profile"] = data.get("profile") or ("baseline" if data["client"] == data["server"] else "default")
    return data


def result_key(result: dict) -> tuple | None:
    parsed = parse_variant(str(result.get("variant", "")))
    if not parsed:
        return None
    payload = result.get("payload") or parsed.get("payload") or "unknown"
    keepalive = bool(result.get("keepalive", True))
    return (
        parsed["client"],
        parsed["server"],
        parsed["profile"],
        parsed["transport"],
        payload,
        keepalive,
        int_field(result, "concurrency"),
    )


def competitor_key(result: dict) -> tuple | None:
    parsed = parse_variant(str(result.get("variant", "")))
    if not parsed or parsed["server"] != "bw":
        return None
    payload = result.get("payload") or parsed.get("payload") or "unknown"
    keepalive = bool(result.get("keepalive", True))
    server = "singbox" if parsed["client"] == "singbox" else "xray"
    return (
        parsed["client"],
        server,
        "baseline",
        parsed["transport"],
        payload,
        keepalive,
        int_field(result, "concurrency"),
    )


def pct_delta(new: float, old: float) -> float | None:
    if old <= 0:
        return None
    return ((new - old) / old) * 100.0


def row_status(result: dict, competitor: dict | None) -> str:
    if result_failed(result):
        return "FAIL"
    if not competitor:
        return "PASS"
    rps_delta = pct_delta(float(result.get("requests_per_sec", 0) or 0), float(competitor.get("requests_per_sec", 0) or 0))
    p99_delta = pct_delta(float(result.get("p99_s", 0) or 0), float(competitor.get("p99_s", 0) or 0))
    if rps_delta is not None and p99_delta is not None and abs(rps_delta) < 3.0 and abs(p99_delta) < 3.0:
        return "NEEDS_REPEAT"
    if (rps_delta is not None and rps_delta < -5.0) or (p99_delta is not None and p99_delta > 5.0):
        return "REGRESSION"
    return "PASS"


def server_gate_rows(results: list[dict]) -> list[dict]:
    by_key = {key: r for r in results if (key := result_key(r)) is not None}
    rows = []
    for result in results:
        parsed = parse_variant(str(result.get("variant", "")))
        if not parsed or parsed["server"] != "bw":
            continue
        competitor = by_key.get(competitor_key(result))
        rps = float(result.get("requests_per_sec", 0) or 0)
        p99 = float(result.get("p99_s", 0) or 0)
        comp_rps = float(competitor.get("requests_per_sec", 0) or 0) if competitor else 0.0
        comp_p99 = float(competitor.get("p99_s", 0) or 0) if competitor else 0.0
        rows.append({
            "result": result,
            "competitor": competitor,
            "parsed": parsed,
            "rps_gap_pct": -pct_delta(rps, comp_rps) if comp_rps > 0 else None,
            "p99_gap_pct": pct_delta(p99, comp_p99) if comp_p99 > 0 else None,
            "status": row_status(result, competitor),
        })
    return rows


def direct_failures(results: list[dict]) -> list[dict]:
    return [
        r for r in results
        if isinstance(r.get("variant"), str)
        and r["variant"].startswith("direct")
        and result_failed(r)
    ]


def render_markdown(results: list[dict], baseline_results: list[dict] | None = None) -> str:
    if not results:
        return "_No results found._\n"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Latency Comparison — {now}",
        "",
        "All times in **milliseconds**. Lower is better.",
        "",
        "| Variant | payload | keepalive | conc | warmup | p50 | p90 | p95 | p99 | req/s | errors | non-200 | status |",
        "|---------|---------|-----------|-----:|--------|-----|-----|-----|-----|-------|--------|---------|--------|",
    ]
    direct_failed = direct_failures(results)
    if direct_failed:
        lines += [
            "> **RUN INVALID:** direct baseline has request failures. Treat Fast/Xray/sing-box comparisons as diagnostic only until the upstream/load environment is clean.",
            "",
        ]
    for r in results:
        failed = result_failed(r)
        row = "| {variant} | {payload} | {keepalive} | {conc} | {warmup} | {p50} | {p90} | {p95} | {p99} | {rps} | {err} | {non200} | {status} |".format(
            variant=r.get("variant", "?"),
            payload=r.get("payload", "—"),
            keepalive="on" if r.get("keepalive", True) else "off",
            conc=int_field(r, "concurrency"),
            warmup=r.get("warmup_s", 0),
            p50=ms(r.get("p50_s")),
            p90=ms(r.get("p90_s")),
            p95=ms(r.get("p95_s")),
            p99=ms(r.get("p99_s")),
            rps=f"{float(r.get('requests_per_sec', 0)):.0f}",
            err=r.get("errors", 0),
            non200=r.get("non_200_responses", 0),
            status="FAIL" if failed else "ok",
        )
        lines.append(row)

    gate_lines = render_fast_gate(results)
    if gate_lines:
        lines += ["", "## Fast Profile Gate", "", *gate_lines]

    server_gate_lines = render_server_gate(results, baseline_results or [])
    if server_gate_lines:
        lines += ["", "## Server Gate Gap Report", "", *server_gate_lines]

    lines += [
        "",
        "## Raw",
        "",
        "```json",
        json.dumps(results, indent=2),
        "```",
        "",
        "> Generated by `labs/realistic/latency/scripts/report.py`",
        "> Baselines are machine-specific — do not treat committed samples as universal truth.",
    ]
    return "\n".join(lines) + "\n"


def render_fast_gate(results: list[dict]) -> list[str]:
    by_variant = {r.get("variant"): r for r in results}
    direct_failed = direct_failures(results)
    if direct_failed:
        lines = [
            f"- RUN INVALID: {len(direct_failed)} direct baseline variant(s) failed. Fix the benchmark environment before using this as a release gate."
        ]
        for r in direct_failed:
            lines.append(
                f"- Direct `{r.get('variant')}` failed with errors={int_field(r, 'errors')}, non_200={int_field(r, 'non_200_responses')}, timeouts={int_field(r, 'timeout_errors')}, eof={int_field(r, 'eof_errors')}, reset={int_field(r, 'reset_errors')}."
            )
        return lines
    pairs = []
    for variant, result in by_variant.items():
        if not isinstance(variant, str):
            continue
        if variant.startswith("xray-bw-fast-tcp"):
            pairs.append(("Xray", result, by_variant.get(variant.replace("xray-bw-fast-tcp", "xray-xray-tcp", 1))))
        elif variant.startswith("singbox-bw-fast-tcp"):
            pairs.append((
                "sing-box",
                result,
                by_variant.get(variant.replace("singbox-bw-fast-tcp", "singbox-singbox-tcp", 1)),
            ))
    lines: list[str] = []
    for label, fast, competitor in pairs:
        if not fast or not competitor:
            continue
        checks = []
        for key in ("p50_s", "p95_s", "p99_s"):
            checks.append(float(fast.get(key, 0)) <= float(competitor.get(key, 0)) * 1.05)
        checks.append(
            float(fast.get("requests_per_sec", 0))
            >= float(competitor.get("requests_per_sec", 0)) * 0.95
        )
        checks.append(not result_failed(fast))
        status = "PASS" if all(checks) else "FAIL"
        lines.append(
            f"- {label} `{fast.get('variant')}`: {status} — fast vs matching baseline must be within 5% on p50/p95/p99/req/s with zero errors and zero non-200 responses."
        )
    return lines


def render_gap_table(title: str, rows: list[dict], gap_key: str) -> list[str]:
    selected = [r for r in rows if r.get(gap_key) is not None and r[gap_key] > 0]
    selected.sort(key=lambda r: r[gap_key], reverse=True)
    selected = selected[:10]
    if not selected:
        return []
    lines = [
        f"### {title}",
        "",
        "| Variant | payload | keepalive | conc | req/s | competitor req/s | req/s gap | p99 | competitor p99 | p99 gap | status |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in selected:
        result = row["result"]
        competitor = row["competitor"] or {}
        rps_gap = row["rps_gap_pct"]
        p99_gap = row["p99_gap_pct"]
        lines.append(
            "| {variant} | {payload} | {keepalive} | {conc} | {rps:.0f} | {comp_rps:.0f} | {rps_gap} | {p99} | {comp_p99} | {p99_gap} | {status} |".format(
                variant=result.get("variant", "?"),
                payload=result.get("payload", "—"),
                keepalive="on" if result.get("keepalive", True) else "off",
                conc=int_field(result, "concurrency"),
                rps=float(result.get("requests_per_sec", 0) or 0),
                comp_rps=float(competitor.get("requests_per_sec", 0) or 0),
                rps_gap="—" if rps_gap is None else f"{rps_gap:.1f}%",
                p99=ms(result.get("p99_s")),
                comp_p99=ms(competitor.get("p99_s")),
                p99_gap="—" if p99_gap is None else f"{p99_gap:.1f}%",
                status=row["status"],
            )
        )
    return lines


def render_baseline_regressions(results: list[dict], baseline_results: list[dict]) -> list[str]:
    if not baseline_results:
        return []
    baseline = {report_identity(r, str(r.get("variant", "?"))): r for r in baseline_results}
    rows = []
    for result in results:
        previous = baseline.get(report_identity(result, str(result.get("variant", "?"))))
        if not previous:
            continue
        rps_delta = pct_delta(float(result.get("requests_per_sec", 0) or 0), float(previous.get("requests_per_sec", 0) or 0))
        p99_delta = pct_delta(float(result.get("p99_s", 0) or 0), float(previous.get("p99_s", 0) or 0))
        if (rps_delta is not None and rps_delta < -5.0) or (p99_delta is not None and p99_delta > 5.0):
            rows.append((result, previous, rps_delta, p99_delta))
    if not rows:
        return ["### Previous-baseline regressions", "", "- No >5% req/s or p99 regressions versus the provided baseline directory."]
    rows.sort(key=lambda item: max(abs(item[2] or 0), abs(item[3] or 0)), reverse=True)
    lines = [
        "### Previous-baseline regressions",
        "",
        "| Variant | payload | keepalive | conc | req/s delta | p99 delta |",
        "|---|---:|---|---:|---:|---:|",
    ]
    for result, _previous, rps_delta, p99_delta in rows[:10]:
        lines.append(
            "| {variant} | {payload} | {keepalive} | {conc} | {rps_delta} | {p99_delta} |".format(
                variant=result.get("variant", "?"),
                payload=result.get("payload", "—"),
                keepalive="on" if result.get("keepalive", True) else "off",
                conc=int_field(result, "concurrency"),
                rps_delta="—" if rps_delta is None else f"{rps_delta:.1f}%",
                p99_delta="—" if p99_delta is None else f"{p99_delta:.1f}%",
            )
        )
    return lines


def render_server_gate(results: list[dict], baseline_results: list[dict]) -> list[str]:
    rows = server_gate_rows(results)
    if not rows:
        return []
    lines = [
        f"- Compared {len(rows)} Blackwire server row(s) against same-client native baselines where available.",
        "- Status thresholds: `FAIL` for errors/non-200/timeouts, `REGRESSION` for >5% req/s loss or >5% p99 worse, `NEEDS_REPEAT` for <3% movement on both req/s and p99.",
    ]
    upstreams = sorted({str(r.get("upstream")) for r in results if r.get("upstream")})
    if upstreams:
        lines.append(f"- Upstream labels present: {', '.join(upstreams)}.")
    gap_lines = render_gap_table("Top req/s gaps", rows, "rps_gap_pct")
    if gap_lines:
        lines += ["", *gap_lines]
    p99_lines = render_gap_table("Top p99 gaps", rows, "p99_gap_pct")
    if p99_lines:
        lines += ["", *p99_lines]
    wins = [
        row for row in rows
        if (row.get("rps_gap_pct") is not None and row["rps_gap_pct"] < 0)
        or (row.get("p99_gap_pct") is not None and row["p99_gap_pct"] < 0)
    ][:10]
    if wins:
        lines += [
            "",
            "### Blackwire wins or partial wins",
            "",
            "| Variant | payload | keepalive | conc | req/s gap | p99 gap | status |",
            "|---|---:|---|---:|---:|---:|---|",
        ]
        for row in wins:
            result = row["result"]
            lines.append(
                "| {variant} | {payload} | {keepalive} | {conc} | {rps_gap} | {p99_gap} | {status} |".format(
                    variant=result.get("variant", "?"),
                    payload=result.get("payload", "—"),
                    keepalive="on" if result.get("keepalive", True) else "off",
                    conc=int_field(result, "concurrency"),
                    rps_gap="—" if row["rps_gap_pct"] is None else f"{row['rps_gap_pct']:.1f}%",
                    p99_gap="—" if row["p99_gap_pct"] is None else f"{row['p99_gap_pct']:.1f}%",
                    status=row["status"],
                )
            )
    baseline_lines = render_baseline_regressions(results, baseline_results)
    if baseline_lines:
        lines += ["", *baseline_lines]
    return lines


def render_html(results: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = ""
    for r in results:
        failed = result_failed(r)
        rows += (
            f"<tr><td>{r.get('variant','?')}</td>"
            f"<td>{r.get('payload','—')}</td>"
            f"<td>{'on' if r.get('keepalive', True) else 'off'}</td>"
            f"<td>{r.get('warmup_s', 0)}</td>"
            f"<td>{ms(r.get('p50_s'))}</td>"
            f"<td>{ms(r.get('p90_s'))}</td>"
            f"<td>{ms(r.get('p95_s'))}</td>"
            f"<td>{ms(r.get('p99_s'))}</td>"
            f"<td>{float(r.get('requests_per_sec',0)):.0f}</td>"
            f"<td>{r.get('errors',0)}</td>"
            f"<td>{r.get('non_200_responses',0)}</td>"
            f"<td>{'FAIL' if failed else 'ok'}</td></tr>\n"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Latency Comparison — {now}</title>
<style>
body {{ font-family: monospace; max-width: 900px; margin: 2em auto; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px 12px; text-align: right; }}
th {{ background: #f4f4f4; text-align: center; }}
td:first-child {{ text-align: left; }}
</style>
</head>
<body>
<h1>Latency Comparison</h1>
<p>{now} — all times in <strong>milliseconds</strong></p>
<table>
<tr><th>Variant</th><th>payload</th><th>keepalive</th><th>warmup</th><th>p50</th><th>p90</th><th>p95</th><th>p99</th><th>req/s</th><th>errors</th><th>non-200</th><th>status</th></tr>
{rows}</table>
<p><small>
  Generated by <code>labs/realistic/latency/scripts/report.py</code><br>
  Baselines are machine-specific — do not treat committed samples as universal truth.
</small></p>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Render latency JSON results")
    parser.add_argument("--format", choices=["md", "html"], default="md")
    parser.add_argument(
        "--dir",
        default=os.path.join(os.path.dirname(__file__), "..", "reports"),
        help="Directory containing result JSON files",
    )
    parser.add_argument("--out", help="Output file (default: stdout)")
    parser.add_argument(
        "--baseline-dir",
        help="Optional previous accepted baseline directory for regression ranking",
    )
    args = parser.parse_args()

    reports_dir = os.path.realpath(args.dir)
    if not os.path.isdir(reports_dir):
        print(f"ERROR: reports directory not found: {reports_dir}", file=sys.stderr)
        sys.exit(1)

    results = find_latest(reports_dir)
    if not results:
        print(f"No JSON result files found in {reports_dir}", file=sys.stderr)

    baseline_results = []
    if args.baseline_dir:
        baseline_dir = os.path.realpath(args.baseline_dir)
        if not os.path.isdir(baseline_dir):
            print(f"ERROR: baseline directory not found: {baseline_dir}", file=sys.stderr)
            sys.exit(1)
        baseline_results = find_latest(baseline_dir)

    output = render_markdown(results, baseline_results) if args.format == "md" else render_html(results)

    if args.out:
        Path(args.out).write_text(output)
        print(f"Wrote {args.out}")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
