# Documentation

This folder is the project documentation map. Keep long-lived facts in one
place: duplicate summaries drift quickly.

## Sources Of Truth

| Question | Canonical doc |
| --- | --- |
| What is supported, experimental, or unsupported for release? | [release.md](release.md) |
| What is the detailed feature status and evidence? | [feature-matrix.md](feature-matrix.md) |
| Which tests/gates should be run? | [11-testing.md](11-testing.md) |
| Which `make` command should I use day to day? | [test-workflows.md](test-workflows.md) |
| What exact Make targets exist? | [15-make-command-guide.md](15-make-command-guide.md), [make-target-inventory.md](make-target-inventory.md) |
| What does the external-client matrix prove? | [parity-status.md](parity-status.md), [../labs/realistic/external-clients/README.md](../labs/realistic/external-clients/README.md) |

Guideline: beginner docs should explain concepts and link to these files for
status. They should not carry independent support matrices or PASS/SKIP counts.

Recommended reading order:

1. [00-project-map.md](00-project-map.md)
   Start here if you want the big picture first.
2. [01-request-lifecycle.md](01-request-lifecycle.md)
   Read this next if you want to understand what happens when traffic enters the proxy.
3. [02-crate-guide.md](02-crate-guide.md)
   Read this when you are ready to navigate the workspace crate by crate.
4. [03-protocols-and-transports.md](03-protocols-and-transports.md)
   Read this when names like VLESS, VMess, REALITY, TLS, WebSocket, and gRPC start blending together.

Related docs:

- [parity-status.md](parity-status.md)
  Shipped parity, external-client matrix SKIPs (vs server support), backlog.
- [feature-matrix.md](feature-matrix.md)
  Evidence-based feature status.
- [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md)
  Upstream-first rules for wire parity.
- [../tests/interop/README.md](../tests/interop/README.md)
  REALITY and Xray interop notes, including `d0` and `d1`.
- [../labs/realistic/README.md](../labs/realistic/README.md)
  Realistic Docker and two-VPS test gates.

Second-wave deep dives:

5. [04-reality-for-dummies.md](04-reality-for-dummies.md)
   The practical, plain-English explanation of REALITY in this repo.
6. [05-vless-vmess-trojan-comparison.md](05-vless-vmess-trojan-comparison.md)
   Helps separate the three most confusing proxy protocols.
7. [06-how-to-debug.md](06-how-to-debug.md)
   A workflow for debugging this codebase without getting lost.
8. [07-how-to-add-a-new-protocol-or-transport.md](07-how-to-add-a-new-protocol-or-transport.md)
   Contributor guide for extending the repo cleanly.

Third-wave practical docs:

9. [08-config-for-dummies.md](08-config-for-dummies.md)
   Annotated config guide with examples and field meanings.
10. [09-trace-one-connection-in-code.md](09-trace-one-connection-in-code.md)
   File-by-file walkthrough of one real connection path.
11. [10-glossary.md](10-glossary.md)
   Plain-English dictionary of project terms.
12. [11-testing.md](11-testing.md)
   How to run every test tier: unit, integration, Docker, Xray interop, VPS matrix, TUN privileged.
13. [test-workflows.md](test-workflows.md)
   Which `verify-*` command to run for everyday dev, lab, VPS, and release gates.
14. [15-make-command-guide.md](15-make-command-guide.md)
   Command-oriented map for Make targets and when to use each one.
15. [16-environment-cheatsheet.md](16-environment-cheatsheet.md)
   One-page separation of local, Docker, Lima VM, real VPS, and direct-on-VPS debugging commands.
16. [make-target-inventory.md](make-target-inventory.md)
   Full target inventory (canonical, lab, interop, compatibility aliases).

Example-driven learning:

- [../examples/vless-client-server/README.md](../examples/vless-client-server/README.md)
- [../examples/reality-client-server/README.md](../examples/reality-client-server/README.md)
- [../examples/vless-ws-local/README.md](../examples/vless-ws-local/README.md)
- [../examples/http-vmess-grpc-local/README.md](../examples/http-vmess-grpc-local/README.md)
- [../examples/ss2022-local/README.md](../examples/ss2022-local/README.md)
