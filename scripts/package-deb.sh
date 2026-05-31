#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: package-deb.sh <version> <deb-arch> <binary-path> <output-dir>}"
deb_arch="${2:?usage: package-deb.sh <version> <deb-arch> <binary-path> <output-dir>}"
binary="${3:?usage: package-deb.sh <version> <deb-arch> <binary-path> <output-dir>}"
out_dir="${4:?usage: package-deb.sh <version> <deb-arch> <binary-path> <output-dir>}"

case "$deb_arch" in
    amd64|arm64) ;;
    *) echo "unsupported Debian arch: $deb_arch" >&2; exit 1 ;;
esac

[ -x "$binary" ] || { echo "binary is not executable: $binary" >&2; exit 1; }

deb="blackwire_${version}_${deb_arch}.deb"
root="$out_dir/deb-root-$deb_arch"
rm -rf "$root"

install -d "$root/DEBIAN" \
    "$root/usr/bin" \
    "$root/etc/blackwire" \
    "$root/var/lib/blackwire" \
    "$root/lib/systemd/system" \
    "$root/usr/share/doc/blackwire"

install -m 0755 "$binary" "$root/usr/bin/blackwire"
install -m 0644 deploy/systemd/blackwire.deb.service "$root/lib/systemd/system/blackwire.service"
install -m 0644 README.md CHANGELOG.md "$root/usr/share/doc/blackwire/"

cat > "$root/etc/blackwire/README" <<'README'
Place your blackwire JSON config at /etc/blackwire/config.json.
Validate it with: blackwire test -c /etc/blackwire/config.json
Start with: systemctl enable --now blackwire
README

cat > "$root/DEBIAN/control" <<CONTROL
Package: blackwire
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: Blackwire maintainers <noreply@example.invalid>
Description: Rust-native proxy runtime for server and local proxy paths
 Blackwire is a Rust-native proxy runtime targeting selected Xray-core
 and sing-box wire-compatible server and local proxy paths.
CONTROL

cat > "$root/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
mkdir -p /etc/blackwire /var/lib/blackwire /run/blackwire
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
exit 0
POSTINST

cat > "$root/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop blackwire >/dev/null 2>&1 || true
fi
exit 0
PRERM

cat > "$root/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
exit 0
POSTRM

chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$root" "$out_dir/$deb"
(cd "$out_dir" && sha256sum "$deb" > "$deb.sha256")

echo "$out_dir/$deb"
