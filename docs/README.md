# Documentation

This folder is the beginner-friendly map of the project.

Recommended reading order:

1. `00-project-map.md`
   Start here if you want the big picture first.
2. `01-request-lifecycle.md`
   Read this next if you want to understand what happens when traffic enters the proxy.
3. `02-crate-guide.md`
   Read this when you are ready to navigate the workspace crate by crate.
4. `03-protocols-and-transports.md`
   Read this when names like VLESS, VMess, REALITY, TLS, WebSocket, and gRPC start blending together.

Related docs:

- `../tests/interop/README.md`
  REALITY and Xray interop notes, including `d0` and `d1`.

Second-wave deep dives:

5. `04-reality-for-dummies.md`
   The practical, plain-English explanation of REALITY in this repo.
6. `05-vless-vmess-trojan-comparison.md`
   Helps separate the three most confusing proxy protocols.
7. `06-how-to-debug.md`
   A workflow for debugging this codebase without getting lost.
8. `07-how-to-add-a-new-protocol-or-transport.md`
   Contributor guide for extending the repo cleanly.
