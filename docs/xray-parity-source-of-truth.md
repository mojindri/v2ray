# Xray / sing-box as source of truth

blackwire does **not** define wire behavior. For parity work, behavior is defined by
upstream implementations and proven with **real upstream clients** against our server.

## Rule

| Question | Answer |
|----------|--------|
| Is a feature “done”? | A configured **Xray-core** and/or **sing-box** client completes the scenario in [`labs/realistic/external-clients/`](../labs/realistic/external-clients/) (or documented equivalent), including negative-auth cases where applicable. |
| How do we implement bytes? | Read and match the relevant upstream **Go source** (and XTLS/REALITY repos where split out)—not blackwire comments, schema-only fields, or this repo’s feature matrix. |
| Can we invent framing? | **No.** If upstream has no equivalent, the feature is out of scope until upstream defines it. |
| Internal unit tests? | Support development only; they do not change “Supported” in the feature matrix without upstream client proof. |

## Which upstream for what

Use the **primary** reference first; validate with the **secondary** when both are common in the wild.

| Area | Primary reference | Secondary / also test |
|------|-------------------|------------------------|
| VLESS, VMess AEAD, Trojan, Freedom | [XTLS/Xray-core](https://github.com/XTLS/Xray-core) `proxy/*`, `transport/internet/*` | sing-box `protocol/*`, `transport/*` |
| REALITY (TLS camouflage) | [XTLS/REALITY](https://github.com/XTLS/REALITY) + Xray `transport/internet/reality` | sing-box `common/tls/reality_*` — see [reality-interop.md](reality-interop.md) |
| ShadowTLS, mKCP, Hysteria2 | Xray where implemented; else sing-box | Whichever ships the transport clients use |
| SplitHTTP / xHTTP | [SagerNet/sing-box](https://github.com/SagerNet/sing-box) (leading client configs) | Xray if/when equivalent paths exist |
| Sniffing, routing, DNS, FakeIP | Xray `app/dispatcher`, `app/dns`, routing rules (`domainStrategy`: AsIs / IPIfNonMatch / IPOnDemand) | sing-box route/DNS when behavior differs—document delta |
| SOCKS5 / HTTP CONNECT | RFC + Xray inbound behavior | sing-box inbound tests in lab |
| SS2022 | Xray / outline spec as used by Xray | sing-box `shadowsocks` implementation |
| gRPC Gun transport | Xray `transport/internet/grpc` | sing-box gRPC transport |
| Management gRPC (Stats/Handler) | Xray `.proto` services | Only if panel parity is required |

When Xray and sing-box **disagree**, do not pick blackwire’s preference:

1. Document the delta in the PR and [parity-status.md](parity-status.md).
2. Gate the scenario with the client named in `labs/realistic/external-clients/scenarios.env`.
3. Add a second lab row for the other client if both must be supported.

## Matrix SKIP vs server support

A **SKIP** in `reports/external-clients/summary.txt` means the lab did not run that **client** binary/config for the row. It is **not** the same as **Unsupported** in [feature-matrix.md](feature-matrix.md).

| Typical pattern | Meaning |
|-----------------|--------|
| Server e2e PASS + matrix client SKIP | blackwire implements the transport; latest Xray/sing-box clients cannot be configured the way the row expects (or we skip by policy). |
| sing-box PASS + Xray SKIP | Row is proven for interop; document Xray upstream limitation (e.g. QUIC on Xray 26+). |
| Both clients SKIP, negatives PASS | Server config loads; auth rejection works; no positive client proof in matrix. |

See the SKIP table in [parity-status.md](parity-status.md).

## Verification ladder (required per gap)

1. **Upstream source** — link to file:line or tagged release in PR description.
2. **Golden / vector test** (optional) — bytes captured from Xray or documented fixtures (e.g. [`golden_vless.rs`](../tests/tests/golden_vless.rs)).
3. **In-process e2e** — fast regression only; not sufficient alone.
4. **External client** — `make -C labs/realistic interop-server-docker` (or VPS) for the scenario row in [`scenarios.env`](../labs/realistic/external-clients/scenarios.env).

A row in [feature-matrix.md](feature-matrix.md) may move to **Supported** only after step **4** for that feature (or explicit documented exception in intentional deviations).

## External-client matrix: sequential only

**Never run Xray and sing-box (or two scenarios) in parallel.**

- One scenario at a time: start blackwire server → start **one** client (Xray **or** sing-box) → curl probe → tear down → next case.
- Do not background multiple `make interop-server-docker` / `external-clients-docker` runs; the matrix scripts use a lock file under the report directory.
- CI and local agents must not overlap Docker matrix invocations on the same host.

On **FAIL**, use [external-client-failure-triage.md](external-client-failure-triage.md): logs first, then upstream Xray/sing-box source.

## Repo map (quick links)

| blackwire crate | Upstream to read |
|-----------------|------------------|
| `blackwire-protocol` | Xray `proxy/vless`, `vmess`, `trojan`, `socks`, `http`, `shadowsocks_2022` |
| `blackwire-transport` | Xray `transport/internet/{tcp,tls,websocket,grpc,httpupgrade,splithttp,quic,reality,kcp}`; sing-box for xHTTP |
| `blackwire-tls` | uTLS/Chrome profiles as used by REALITY clients; Xray TLS settings |
| `blackwire-app` | Xray `app/router`, `app/dispatcher`, `app/dns` |
| `blackwire-config` | Shape inspired by Xray/sing-box JSON; **semantic** truth is still upstream behavior, not our schema |

## Explicit non-goals (even if Xray has them)

Listed in [feature-matrix.md](feature-matrix.md) intentional deviations (e.g. VMess alterId, V2Ray JSON import). Do not implement from blackwire convenience—these require an explicit product decision.

## Related docs

- [feature-matrix.md](feature-matrix.md) — current status (evidence-based)
- [parity-status.md](parity-status.md) — shipped gates, matrix SKIPs, backlog
- [xray-parity-roadmap.md](xray-parity-roadmap.md) — gap tracker
- [reality-interop.md](reality-interop.md) — REALITY upstream links and lab gates
- [labs/realistic/external-clients/README.md](../labs/realistic/external-clients/README.md) — server-compat lab
- [11-testing.md](11-testing.md) — verification tiers
