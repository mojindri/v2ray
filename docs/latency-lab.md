# Latency Lab

The latency lab measures end-to-end proxy latency (TTFB) across multiple variants using [hey](https://github.com/rakyll/hey) as the load generator. Results are JSON files that can be rendered as Markdown or HTML tables.

All scripts live in `labs/realistic/latency/`. All Makefile targets are invoked from `labs/realistic/`.

---

## Quick start

```bash
# Install hey (macOS)
brew install hey

# Install hey (Linux)
go install github.com/rakyll/hey@latest

# Smoke run: 30s × 32 conc, 3 variants (requires: blackwire in PATH + target on :18080)
cd labs/realistic
make latency-local

# Render results
make latency-report

# Dry-run (no processes, no hey required)
make latency-local-dry
```

---

## Environment policy

| Environment | Target | Command | Notes |
|---|---|---|---|
| macOS | `latency-local` | `make latency-local` | Smoke only; NOT a hard perf gate |
| Linux / Lima VM | `latency-lima` | `make latency-lima` | Repeatable; supports tc-netem |
| VPS pair | `latency-vps` | `make latency-vps VPS_CLIENT_HOST=...` | Release evidence only; manual |
| Chaos | `latency-chaos` | `make latency-chaos` | Linux only, needs root |
| Flamegraph | `latency-profile` | `make latency-profile` | Linux only, needs perf + FlameGraph |

**macOS `latency-local` is not a performance gate.** Results are loopback-only, timer resolution varies, and OS scheduling is not controlled. Use Linux/Lima for repeatable numbers and VPS for production-like evidence.

---

## Scenarios

| Scenario | What it runs |
|---|---|
| `local-smoke` | direct + blackwire-socks-direct + blackwire-fast-lab (loopback) |
| `local-full` | local-smoke with longer duration and higher concurrency |
| `xray-compare` | Xray client vs Xray server, BW Compat, BW Fast (same-client fairness) |
| `singbox-compare` | sing-box client vs sing-box server, BW Compat, BW Fast |
| `compare-all` | local-smoke + xray-compare + singbox-compare |

**Same-client fairness**: Xray-series variants all use the same Xray client process. Only the server changes. This ensures client-side differences don't pollute server conclusions.

---

## Benchmark matrix

### Xray client series

| Variant | Client | Server | Transport |
|---|---|---|---|
| `direct` | hey (no proxy) | target HTTP | plain TCP |
| `blackwire-socks-direct` | hey + BW SOCKS5 | Freedom | SOCKS5 → direct |
| `blackwire-fast-lab` | hey + BW SOCKS5 | BW Fast + BW Fast | SOCKS5 → VLESS TCP |
| `xray-xray-tcp` | Xray | Xray | VLESS TCP |
| `xray-bw-compat-tcp` | Xray | BW Compat | VLESS TCP |
| `xray-bw-fast-tcp` | Xray | BW Fast | VLESS TCP |

### sing-box client series

| Variant | Client | Server | Transport |
|---|---|---|---|
| `singbox-singbox-tcp` | sing-box | sing-box | VLESS TCP |
| `singbox-bw-compat-tcp` | sing-box | BW Compat | VLESS TCP |
| `singbox-bw-fast-tcp` | sing-box | BW Fast | VLESS TCP |

---

## Test scenarios

| Scenario | Concurrency | Duration |
|---|---|---|
| smoke (macOS) | 32 | 30 s |
| short requests | 32 | 60 s |
| high concurrency | 1000 | 60 s |
| new conn per req | 100 | 60 s |
| chaos: 50ms jitter | 256 | 60 s |
| chaos: 5% loss | 256 | 60 s |
| soak | 256 | 3600 s |

---

## Makefile targets reference

```bash
make latency-local              # macOS smoke (30s × 32)
make latency-local-dry          # dry-run — no processes, no hey
make latency-report             # Markdown to stdout
make latency-report-html        # HTML to latency/reports/report.html

make latency-compare            # all local variants (xray + singbox required in PATH)
make latency-compare BENCH_DURATION=60 BENCH_CONC=256

make latency-vps \
  VPS_CLIENT_HOST=client.example.com \
  VPS_SERVER_HOST=server.example.com  # SSH + run + scp results back

make latency-lima               # run inside Lima Linux VM (limactl required)
make latency-lima-build         # cargo build inside Lima VM

make latency-chaos              # tc-netem 50ms jitter + 5% loss (Linux, root required)
make latency-chaos \
  CHAOS_DELAY=100ms \
  CHAOS_LOSS=10%

make latency-profile            # perf flamegraph (Linux, perf + FlameGraph required)
make latency-profile FLAMEGRAPH_DIR=/opt/FlameGraph
```

---

## Configuration files

All configs are in `labs/realistic/latency/configs/`. Lab configs use loopback (`127.0.0.1`) and a fixed UUID (`00000000-0000-4000-8000-000000000001`) — not for production use.

| File | Purpose |
|---|---|
| `blackwire-socks-direct.json` | SOCKS5 inbound (1080) → Freedom |
| `blackwire-fast-lab-server.json` | VLESS inbound (10080), Fast Profile, security=none |
| `blackwire-fast-lab-client.json` | SOCKS5 inbound (1081) → VLESS to :10080 |
| `blackwire-compat-server-tcp.json` | VLESS inbound (10083), no Fast Profile |
| `xray-server-tcp.json` | Xray VLESS server (10081) |
| `xray-client-tcp.json` | Xray SOCKS5→VLESS (1082), uses `${SERVER_ADDR}:${SERVER_PORT}` |
| `singbox-server-tcp.json` | sing-box VLESS server (10082) |
| `singbox-client-tcp.json` | sing-box SOCKS5→VLESS (1083), uses `${SERVER_ADDR}:${SERVER_PORT}` |
| `.env.example` | Template for VPS and binary path variables |

---

## VPS setup

```bash
# Copy env template and fill in your hosts
cp labs/realistic/latency/configs/.env.example .env.latency
# edit VPS_CLIENT_HOST, VPS_SERVER_HOST, VPS_SSH_KEY

source .env.latency
make latency-vps
```

The client VPS must have:
- `blackwire` in PATH (or `BW_BIN` set)
- `hey` in PATH
- `python3` in PATH
- This repo cloned at `VPS_REPO_PATH` (default `~/Blackwire`)

A target HTTP server (nginx, caddy, etc.) must be running on `VPS_SERVER_HOST:18080`.

---

## Result files

Results are written as `labs/realistic/latency/reports/<variant>-<timestamp>.json`. The `.gitignore` excludes generated result files from git; only `baselines/` is committed.

Each file contains:
```json
{
  "variant": "blackwire-fast-lab",
  "timestamp": "20260527T183521Z",
  "target": "http://127.0.0.1:18080/",
  "duration_s": 30,
  "concurrency": 32,
  "proxy": "127.0.0.1:1081",
  "requests_per_sec": 4821.3,
  "p50_s": 0.0061,
  "p90_s": 0.0089,
  "p95_s": 0.0104,
  "p99_s": 0.0198,
  "fastest_s": 0.0012,
  "slowest_s": 0.0891,
  "successful_responses": 144639,
  "errors": 0
}
```

---

## Baseline policy

**Baselines are machine-specific.** Results committed to `reports/baselines/` are sample/reference only. Do not treat them as universal pass/fail thresholds.

1. First run on a new machine: collect baselines, no gates. Commit to `baselines/` as reference.
2. **PR smoke gate**: `latency-local` short run, macOS-compatible, checks for obvious regressions only. Not a hard performance gate.
3. **Regression gate** (after stable Linux baselines on a controlled runner): p99 must not regress > 10% vs. that runner's baseline.
4. **Full gate**: manual or release-only — Linux + chaos + soak.
5. **VPS gate**: manual only — release evidence, not normal PR gates.

---

## Chaos testing

```bash
# Linux only, needs root/CAP_NET_ADMIN
sudo -E make latency-chaos

# Custom parameters
sudo -E make latency-chaos CHAOS_DELAY=100ms CHAOS_JITTER=20ms CHAOS_LOSS=10%

# Or run setup-chaos.sh directly
sudo CHAOS_DELAY=50ms bash labs/realistic/latency/scripts/setup-chaos.sh add
make latency-local
sudo bash labs/realistic/latency/scripts/setup-chaos.sh del
```

---

## Flamegraph

```bash
# Requires: perf (linux-perf), FlameGraph scripts in PATH or FLAMEGRAPH_DIR
# Clone FlameGraph: git clone https://github.com/brendangregg/FlameGraph ~/FlameGraph

sudo FLAMEGRAPH_DIR=~/FlameGraph make latency-profile
# Opens: latency/reports/flamegraph-blackwire-fast-lab-<ts>.svg
```

For CPU profiling of a specific inbound handler or relay path, set `SERVER_CONFIG` directly:
```bash
SERVER_CONFIG=path/to/config.json \
PROXY_ADDR=127.0.0.1:1081 \
bash labs/realistic/latency/scripts/run-flamegraph.sh my-variant http://target/
```
