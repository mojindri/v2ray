# Make target inventory

Generated for the verification refactor. **Canonical** targets are the supported public API; **compat** targets print a deprecation hint.

Legend — **environment**: `host` | `docker` | `lima` | `vps` | `privileged` | `fuzz` | `perf`  
**mutates local**: changes repo reports/containers/VM on dev machine  
**mutates remote**: changes or loads real VPS hosts

---

## Canonical (root `make/verify.mk` + root atoms)

| Target | File | Summary | Environment | Env vars | Tools | Duration | Artifacts | Local | Remote | Visibility |
|--------|------|---------|-------------|----------|-------|----------|-----------|-------|--------|------------|
| `verify-local` | `make/verify.mk` | fmt-check, check, clippy, test | host | — | cargo | 2–15 min | — | no | no | **public** |
| `verify-check-compat` | `make/verify.mk` | verify-local + lab docker + prod-readiness + fuzz-smoke | host,docker,fuzz | — | cargo,docker,nightly | 30–90 min | `labs/realistic/reports/` | yes | no | internal (old `check`) |
| `verify-lab` | `make/verify.mk` | verify-lab-docker + verify-lab-lima | docker,lima | `LIMA_INSTANCE` | docker,limactl | 20–60 min | `labs/realistic/reports/` | yes | no | **public** |
| `verify-lab-docker` | `make/verify.mk` | Docker stable + interop-docker + advanced-features-smoke + negative-auth | docker | — | docker,cargo | 15–45 min | `labs/realistic/reports/` | yes | no | **public** |
| `verify-lab-lima` | `make/verify.mk` | Lima browser baseline + fingerprint verify | lima | `LIMA_INSTANCE` | limactl,brew | 10–30 min | `reports/production/` | yes | no | **public** |
| `verify-lab-fingerprint` | `make/verify.mk` | alias → verify-lab-lima | lima | same | same | same | same | yes | no | **public** |
| `verify-remote` | `make/verify.mk` | full VPS gate | vps,privileged,perf | `SSH_SERVER`, `SSH_CLIENT`, `SSH_KEY`, … | ssh | 20–60 min | `labs/realistic/reports/` | no | **yes** | **public** |
| `verify-remote-*` | `make/verify.mk` | remote sub-gates (smoke, protocols, fingerprint, …) | vps | SSH_* | ssh | varies | reports | no | **yes** | **public** |
| `verify-sweep` | `make/verify.mk` | local + lab + security + fuzz-smoke (+ remote if SSH set) | mixed | SSH optional | mixed | 45–120 min | reports | partial | optional | **public** |
| `verify-release` | `make/verify.mk` | sweep + perf + soak + fuzz-long | mixed | SSH optional, `FUZZ_RUNS` | mixed | hours | reports | yes | optional | **public** |
| `lab-docker-preflight` | `make/verify.mk` | `docker info` | docker | — | docker | seconds | — | no | no | internal |
| `lab-docker-up` | `make/verify.mk` | → `labs/realistic docker-up` | docker | — | docker | 1–5 min | image txt | yes | no | internal |
| `lab-docker-test` | `make/verify.mk` | stable,interop-docker,advanced-features-smoke,negative-auth | docker | — | docker,cargo | 15–40 min | reports | yes | no | internal |
| `lab-docker-down` | `make/verify.mk` | → `docker-down` | docker | — | docker | 1 min | — | yes | no | internal |
| `lab-lima-preflight` | `make/verify.mk` | checks `limactl` | lima | — | limactl | seconds | — | no | no | internal |
| `lab-lima-test-fingerprint` | `make/verify.mk` | → `lima-fingerprint-total` | lima | `LIMA_INSTANCE` | limactl | 10–30 min | pcaps, logs | yes | no | internal |
| `lab-lima-down` | `make/verify.mk` | → `lima-stop` | lima | — | limactl | seconds | — | yes | no | internal |
| `remote-preflight` | `make/verify.mk` | → `vps-preflight` | vps | SSH_* | ssh | 1 min | — | no | read | internal |
| `remote-deploy` | `make/verify.mk` | vps-server-setup + vps-client-setup | vps | SSH_* | ssh,rsync | 5–15 min | remote `/root/lab` | no | **yes** | internal |
| `remote-test-smoke` | `make/verify.mk` | SSH echo on server+client | vps | SSH_* | ssh | seconds | — | no | no | internal |
| `remote-test-protocols` | `make/verify.mk` | → `vps-test` | vps | SSH_CLIENT | ssh | 10–30 min | `reports/vps-matrix-*.log` | no | **yes** | internal |
| `remote-test-fingerprint` | `make/verify.mk` | interop-server-vps | vps | SSH_* | ssh | 10–20 min | `external-clients-vps/` | no | **yes** | internal |
| `remote-test-fallback` | `make/verify.mk` | → `vps-tun` (sudo) | vps,privileged | SSH_SERVER | ssh,sudo | 5–15 min | tun logs | no | **yes** | internal |
| `remote-collect` | `make/verify.mk` | → `vps-netem` | vps,privileged | SSH_SERVER | ssh,tc | 5–15 min | netem logs | no | **yes** | internal |
| `remote-clean` | `make/verify.mk` | guidance only | — | — | — | — | — | no | no | internal |
| `security` | `make/verify.mk` | audit-optional + deny-optional + lab `security` | host | — | cargo-audit, cargo-deny | 2–10 min | `reports/production/security.log` | no | no | **public** |
| `fuzz-smoke` | root `Makefile` | 6× cargo-fuzz @ 100 runs | fuzz | — | nightly,cargo-fuzz | 5–20 min | — | no | no | **public** |
| `fuzz-long` | `make/verify.mk` | → lab `fuzz-total` | fuzz | `FUZZ_RUNS` | nightly | 30+ min | fuzz logs | no | no | **public** |
| `perf` | root | → `bench-vm-total` | lima,perf | `LIMA_INSTANCE` | limactl | 10–30 min | bench reports | yes | no | **public** |
| `perf-remote` | `make/verify.mk` | → `bench-vps-total` | vps,perf | SSH_* | ssh | 10–30 min | bench reports | no | **yes** | **public** |
| `soak` | `make/verify.mk` | → lab `soak` | host | soak.env | bash | configurable | soak log | no | no | internal |

### Root atoms (`Makefile`)

| Target | Commands | Environment | Duration | Visibility |
|--------|----------|-------------|----------|------------|
| `build` | `cargo build --release` | host | 1–5 min | public |
| `dev` | debug build | host | 1–3 min | public |
| `test` | `cargo test --workspace` | host | 1–10 min | public |
| `fmt` / `fmt-check` | rustfmt | host | seconds | public |
| `lint` | clippy with `-D warnings` | host | 2–10 min | public |
| `lint-strict` | clippy + unwrap/expect denies | host | 2–10 min | public |
| `audit` / `audit-optional` | cargo audit | host | 1–5 min | public / internal |
| `deny` / `deny-optional` | cargo deny | host | 1–5 min | public / internal |
| `fuzz-build` | nightly fuzz build | fuzz | 2–10 min | internal |
| `clean-generated` | rm reports + bench | host | seconds | **public** |
| `clean` | `cargo clean` | host | seconds | public |
| `gen-keys` | blackwire x25519 | host | seconds | public |
| `update-geoip` | script | host | 1 min | public |

### Compatibility aliases (`make/aliases.mk`)

| Alias | Canonical replacement | Notes |
|-------|----------------------|-------|
| `local-fast`, `ci` | `verify-local` | |
| `local`, `ci-all` | `labs/realistic ci` | full lab CI, not only Docker |
| `local-total`, `check` | `verify-check-compat` | |
| `check-browser` | `verify-lab-lima` | |
| `check-all-local` | verify-check-compat + verify-lab-lima | |
| `check-vps`, `vps-total` | verify-check-compat + verify-remote | |
| `vps`, `ci-vps` | `verify-remote` | old `ci-vps` was `ci-full` |
| `vps-total-with-fuzz` | verify-check-compat + verify-remote | |
| `local-prod`, `ci-prod-readiness` | `labs/realistic prod-readiness` | |
| `local-fuzz`, `ci-fuzz-smoke` | `fuzz-smoke` | |
| `local-fuzz-total`, `ci-fuzz-total` | `fuzz-long` | |
| `check-perf-vm` | `perf` | |
| `check-perf-vps` | `perf-remote` | |
| `perf-all` | perf + perf-remote | |

---

## `labs/realistic/Makefile` (+ `production-readiness.mk`)

| Target | Environment | Env vars | Mutates local | Mutates remote | Visibility |
|--------|-------------|----------|---------------|----------------|------------|
| `build` | docker | — | image | no | internal |
| `docker-up` / `docker-down` | docker | — | containers | no | internal |
| `stable` | host | — | no | no | internal |
| `xray` | docker | — | containers | no | internal |
| `advanced-features-smoke` | `labs/realistic/Makefile` | ShadowTLS, mKCP, health, DNS/routing smoke | host | — | cargo | ~30s | `advanced-features-smoke.log` | no | no | internal |
| `negative-auth` | host | — | no | no | internal |
| `restart-smoke` | docker | — | containers | no | internal |
| `stress` | host | — | no | no | internal |
| `docker-full` | docker+host | — | yes | no | internal |
| `realistic-all` | docker+host | — | yes | no | internal |
| `interop-docker` | `labs/realistic/Makefile` | server-compat + client-compat (Docker) | docker | matrix.env | docker,cargo | 5–15 min | `interop-client-reality.log`, `external-clients/` | yes | no | internal |
| `interop-server-docker` | `labs/realistic/Makefile` | Xray/sing-box clients → our server | docker | matrix.env | docker | 3–10 min | `external-clients/` | yes | no | internal |
| `interop-client-reality` | `labs/realistic/Makefile` | our Rust client → Xray server (d1) | docker | — | docker,cargo | ~1 min | `interop-client-reality.log` | yes | no | internal |
| `interop-server-vps` | `labs/realistic/Makefile` | Xray/sing-box clients → our server (VPS) | vps | SSH_*, matrix.env | ssh | 10–20 min | `external-clients-vps/` | no | **yes** | internal |
| `external-clients-docker` | docker | matrix.env | yes | no | atom (use interop-server-docker) |
| `external-clients-vps` | vps | SSH_*, matrix.env | no | **yes** | atom (use interop-server-vps) |
| `xray` | labs/realistic | compat → interop-client-reality | docker | — | docker,cargo | ~1 min | log | yes | no | **compat** |
| `external-clients-report` | host | — | no | no | internal |
| `vps-preflight` | vps | SSH_SERVER, SSH_CLIENT | no | read | internal |
| `vps-server-setup` | vps | SSH_SERVER | no | **yes** | internal |
| `vps-client-setup` | vps | SSH_CLIENT | no | **yes** | internal |
| `vps-test` | vps | SSH_CLIENT | no | **yes** | internal |
| `vps-tun` | vps,privileged | SSH_SERVER | no | **yes** | internal |
| `vps-netem` | vps,privileged | SSH_SERVER | no | **yes** | internal |
| `ci` | host+docker+fuzz | — | yes | no | internal (heavy) |
| `ci-full` | +vps | SSH_* | yes | **yes** | internal |
| `prod-readiness` | host | — | reports | no | internal |
| `fuzz-smoke` / `fuzz-total` | fuzz | FUZZ_RUNS | reports | no | internal |
| `lima-fingerprint-total` | lima | LIMA_* | VM+reports | no | internal |
| `bench-vm-*` / `bench-vps-*` | perf | SSH_* for vps | reports | optional | internal |
| `load` / `soak` / `security` | host | load.env, soak.env | reports | no | internal |
| `pcap-local`, `fingerprint-*`, `chrome-baseline-*` | docker/host/lima | CHROME_* | reports | partial | internal |

**Reports root:** `labs/realistic/reports/` (logs, `summary.txt`, `external-clients/`, `production/`).

---

## `tests/interop/Makefile`

| Target | Environment | Env vars | Tools | Mutates local | Visibility |
|--------|-------------|----------|-------|---------------|------------|
| `keys` | docker | — | docker | keys/ | internal |
| `configs` | host | REALITY_* from keys | envsubst | configs | internal |
| `up` / `down` | docker | — | docker compose | containers | internal |
| `test` | docker+host | — | cargo,docker | reports | internal |
| `selftest` | host | — | cargo | no | internal |
| `pcap` | docker | — | tcpdump | pcaps | internal |
| `analyze` | host | — | scripts | reports | internal |
| `clean` | docker+host | — | — | removes generated | internal |

---

## References in repo docs/scripts

Scripts and docs may still mention legacy `make check` in examples outside this
repo; compatibility aliases preserve those entrypoints. **Primary docs** (README,
11-testing, 15-make-command-guide, 16-environment-cheatsheet) now use `verify-*`.

Search used during refactor:

- `rg 'make '` across `*.md`, `*.sh`, `Makefile`
- Patterns: `ci-all`, `check-vps`, `local-total`, `lima`, `vps`, `prod-readiness`, `fuzz`
