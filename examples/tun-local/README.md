# TUN Mode Example

This example shows full-device TUN interception on Linux, macOS, and Windows:

```text
applications
  -> OS TUN adapter
  -> Blackwire TUN runtime
  -> local SOCKS inbound on 127.0.0.1:7890
  -> routing rules
  -> proxy or direct outbound
```

Use the base config on Linux:

```sh
sudo -E cargo run -q -p blackwire -- run -c examples/tun-local/config.json
```

Use the macOS variant when running through utun. Replace `en0` with the active
physical interface if needed:

```sh
route -n get default | awk '/interface:/ {print $2}'
sudo -E cargo run -q -p blackwire -- run -c examples/tun-local/config.macos.json
```

Use the Windows variant from an elevated shell. Set `wintunFile` to the real
`wintun.dll` path or place `wintun.dll` where the process DLL loader can find it:

```powershell
cargo run -q -p blackwire -- run -c examples\tun-local\config.windows.json
```

Platform notes:

- Linux installs policy routing, `ip route`, and iptables rules. Outbound proxy
  sockets use `SO_MARK` so they do not loop back into TUN.
- macOS creates an utun device, installs split default routes, and loads a scoped
  PF anchor for TCP/DNS redirection. `tun.outboundInterface` is required so proxy
  egress bypasses utun capture.
- Windows creates a Wintun adapter, installs split default routes, and bridges
  TCP packets from Wintun to the local SOCKS listener configured by
  `tun.redirect_port`. `tun.wintunFile` can point at a bundled `wintun.dll`.

Validate config shape without starting privileged runtime:

```sh
cargo run -q -p blackwire -- test -c examples/tun-local/config.json
cargo run -q -p blackwire -- test -c examples/tun-local/config.macos.json
cargo run -q -p blackwire -- test -c examples/tun-local/config.windows.json
```

Author: @moji.ndr
