# Black UI

Black UI is the Blackwire-native control panel. The old `ui/` tree is used as a
feature and workflow reference only; production work happens in `black-ui/`.

## Support Model

Black UI aims to cover the full Blackwire supported feature surface. Common
server operations have structured forms, and advanced areas use raw JSON editors
that are validated through `blackwire-config` before write or apply.

Supported in the first Black UI package:

- Admin setup, login, logout, and expiring sessions.
- Inbound management for Blackwire-supported protocols.
- Outbound management for Blackwire-supported outbound protocols.
- Protocol-specific user credentials with quota, expiry, enable/disable, usage
  reset, UUID rotation, and subscription-token rotation.
- Raw validated config sections for routing, DNS, TUN, limits, stats, API,
  metrics, profile, and fast-profile tuning.
- Config preview, validate, import, write, and live apply.
- gRPC live sync through Blackwire Handler API.
- Linux `systemctl` status, restart, and recent `journalctl` logs.
- Optional Linux UFW auto-open for enabled public inbound ports.

Unsupported Blackwire features should not be shown. Experimental runtime data,
such as StatsService traffic, is shown as runtime-dependent.

## Linux VPS Install

Black UI is packaged as a companion Linux service when release assets include
`black-ui-linux-*.tar.gz`.

```sh
curl -fsSL https://raw.githubusercontent.com/mojindri/Blackwire/v0.1.0-rc.3/scripts/install.sh \
  | VERSION=v0.1.0-rc.3 INSTALL_BLACK_UI=1 START_SERVICE=1 bash
```

Defaults:

- Black UI data: `/var/lib/black-ui`
- Black UI listen: `127.0.0.1:18080`
- Black UI static frontend: `/usr/local/share/black-ui/frontend/dist`
- Blackwire config: `/etc/blackwire/config.json`
- Blackwire gRPC API: `127.0.0.1:62789`

With nginx domain setup:

```sh
curl -fsSL https://raw.githubusercontent.com/mojindri/Blackwire/v0.1.0-rc.3/scripts/install.sh \
  | VERSION=v0.1.0-rc.3 SETUP=domain DOMAIN=proxy.example.com PROXY_PATH=/secret-path INSTALL_NGINX=1 INSTALL_CERTBOT=1 INSTALL_BLACK_UI=1 START_SERVICE=1 bash
```

The installer adds an nginx reverse proxy at `/panel/` when
`INSTALL_BLACK_UI=1` is combined with `SETUP=domain`.

## Operations

```sh
systemctl status black-ui
journalctl -u black-ui -f
systemctl restart black-ui
```

Black UI controls Blackwire through local files and localhost gRPC:

```sh
blackwire test -c /etc/blackwire/config.json
systemctl restart blackwire
journalctl -u blackwire -f
```

Keep the panel bound to localhost and expose it through authenticated HTTPS
reverse proxy. Do not bind `BLACK_UI_LISTEN=0.0.0.0:18080` on a public VPS
without an external access-control layer.

Admin sessions use HttpOnly SameSite cookies. Set `BLACK_UI_COOKIE_SECURE=1`
when the panel is served through HTTPS; the domain installer enables this
automatically.

## Firewall Auto-Open

The Settings page includes `Auto-open UFW ports for public enabled inbounds`.
When enabled, Black UI runs `ufw allow <port>/<protocol>` after config save/apply
for enabled inbounds that listen on a public address. Localhost-only inbounds are
skipped.

This only adds or confirms rules; it does not delete firewall rules. The Black UI
service must have permission to run `ufw`, usually by running as root or through a
separate sudoers policy.
