# Fast Profile

Blackwire has two operating modes:

| Mode | Purpose |
|---|---|
| **Compat** (default) | Broad protocol/transport matrix, Xray/sing-box interop, experiments, feature parity work |
| **Fast** | Narrow, latency-first production path — strict defaults, lower complexity, benchmarked head-to-head against Xray and sing-box |

These are different promises. Compatibility Mode may be slower or more complex — that is intentional and acceptable. Fast Profile rejects useful features when they add latency overhead.

**Security rule**: Fast Profile means _less complexity_, not _less safety_. Auth, REALITY validation, TLS, timeouts, and parser strictness are identical in both modes.

---

## Enabling Fast Profile

**In config:**
```json
{ "profile": "fast", ... }
```

**CLI override:**
```bash
blackwire run -c config.json --profile fast
```

The CLI flag wins over the config field. This allows using an existing config without editing it.

---

## `fast` block (optional)

```json
{
  "profile": "fast",
  "fast": { "strictProduction": true }
}
```

| Field | Default | Meaning |
|---|---|---|
| `strictProduction` | `true` | Rejects `security = none`. Set to `false` only for local benchmarking labs. |

### Freedom pool tuning (optional)

Fast Profile uses adaptive Freedom TCP pooling by default. You can tune it per
outbound in `settings`:

```json
{
  "tag": "freedom",
  "protocol": "freedom",
  "settings": {
    "pool": {
      "mode": "adaptive",
      "maxPerDest": 8,
      "maxGlobalIdle": 256,
      "maxDests": 512,
      "idleTtlMs": 8000,
      "hotnessWindowMs": 12000,
      "minHotnessForPool": 8
    }
  }
}
```

Accepted `pool.mode` values:
- `adaptive` (default in Fast Profile)
- `fixed` (uses fixed per-destination capacity)
- `disabled` / `off` / `none`

Legacy `poolSize` is still supported for lab/debug compatibility.

---

## Validation rules

When `profile = fast`, `validate_fast_profile()` runs at startup and rejects or warns on the following:

| Setting | Behaviour |
|---|---|
| `protocol = vless` inbound | ✅ allowed |
| `protocol = vmess` inbound | ❌ error |
| `network = tcp` | ✅ allowed |
| `network = ws / grpc / kcp / splithttp / tun` | ❌ error |
| `security = reality` or `tls` | ✅ allowed |
| `security = none` + `strictProduction: false` | ⚠️ warning — lab-only |
| `security = none` + `strictProduction: true` | ❌ error |
| `sniffing.enabled = true` | ❌ error |
| `dns.fakeIp.enabled = true` | ❌ error |
| `routing.domainStrategy = IpOnDemand` | ❌ error |
| `routing.rules` count > 50 | ⚠️ warning |
| `protocol = freedom` or `vless` outbound | ✅ allowed |
| GeoSite/GeoIP heavy rules (> 20) | ⚠️ warning |

Errors abort startup. Warnings are printed to stderr and then startup continues.

---

## Log level changes

Under `profile = fast`, per-connection relay logs (`relay started`, `relay finished`, `route selected`) are emitted at `DEBUG` level instead of `INFO`. This avoids log I/O on the hot path at production log levels.

Security events (auth failures, config errors, startup messages) remain at `INFO`/`WARN`/`ERROR` regardless of profile.

---

## Lab config example (security = none, loopback only)

```json
{
  "profile": "fast",
  "fast": { "strictProduction": false },
  "log": { "level": "warn" },
  "inbounds": [
    {
      "tag": "vless-in",
      "protocol": "vless",
      "listen": "127.0.0.1",
      "port": 10080,
      "settings": {
        "clients": [{ "id": "00000000-0000-4000-8000-000000000001" }]
      }
    }
  ],
  "outbounds": [{ "tag": "freedom", "protocol": "freedom" }]
}
```

Never use `security = none` on a publicly reachable port. This is a loopback-only latency lab config.

---

## Production config example (REALITY)

```json
{
  "profile": "fast",
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "protocol": "vless",
      "listen": "0.0.0.0",
      "port": 10443,
      "settings": {
        "clients": [{ "id": "<uuid>", "flow": "" }],
        "fallback": { "dest": "<reality-dest>:443" }
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "<reality-dest>:443",
          "serverName": "<sni>",
          "privateKey": "<private-key>",
          "shortIds": ["<short-id>"]
        }
      }
    }
  ],
  "outbounds": [{ "tag": "freedom", "protocol": "freedom" }]
}
```

---

## What Fast Profile does NOT do

- Does not bypass REALITY key verification
- Does not skip TLS certificate validation
- Does not relax UUID parsing
- Does not shorten handshake timeouts
- Does not disable parser error checks
- Does not introduce a separate code path for dispatch

All of the above remain identical to Compatibility Mode.

---

## Measurement-driven optimization policy

Performance improvements beyond the current scope (profile validation, log gating, histograms) require profiling evidence. Decisions based on assumptions rather than measurements are explicitly out of scope.

See `docs/latency-lab.md` for the benchmarking methodology.
