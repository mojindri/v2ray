# v2ray

Beginner-friendly docs live in [docs/README.md](docs/README.md).

Recommended starting path:

1. [Project Map](docs/00-project-map.md)
2. [Request Lifecycle](docs/01-request-lifecycle.md)
3. [Crate Guide](docs/02-crate-guide.md)
4. [Protocols And Transports](docs/03-protocols-and-transports.md)

Deep dives:

- [REALITY For Dummies](docs/04-reality-for-dummies.md)
- [VLESS, VMess, And Trojan Comparison](docs/05-vless-vmess-trojan-comparison.md)
- [How To Debug This Repo](docs/06-how-to-debug.md)
- [How To Add A New Protocol Or Transport](docs/07-how-to-add-a-new-protocol-or-transport.md)

Practical docs:

- [Config For Dummies](docs/08-config-for-dummies.md)
- [Trace One Connection In Code](docs/09-trace-one-connection-in-code.md)
- [Glossary](docs/10-glossary.md)

Example configs and local demos live under `examples/`.

Good entry points:

- [Phase 1 Client/Server](examples/phase1-client-server/README.md)
- [Phase 2 REALITY Client/Server](examples/phase2-reality-client-server/README.md)
- [Phase 4 VLESS + WebSocket Local](examples/phase4-vless-ws-local/README.md)
- [Phase 5 HTTP + VMess + gRPC Local](examples/phase5-http-vmess-grpc-local/README.md)
- [Phase 6 SS2022 Local](examples/phase6-ss2022-local/README.md)

REALITY and Xray interop notes live in [tests/interop/README.md](tests/interop/README.md).

That guide explains:

- what `d0` vs `d1` are proving
- why REALITY still needs a full TLS 1.3 handshake
- how the local Xray Docker harness is wired
- why the Xray `dest` must be a real HTTPS endpoint on port 443
