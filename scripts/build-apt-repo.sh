#!/usr/bin/env bash
set -euo pipefail

input_dir="${1:?usage: build-apt-repo.sh <deb-input-dir> <repo-root> [suite] [component]}"
repo_root="${2:?usage: build-apt-repo.sh <deb-input-dir> <repo-root> [suite] [component]}"
suite="${3:-stable}"
component="${4:-main}"

command -v dpkg-scanpackages >/dev/null 2>&1 || {
    echo "dpkg-scanpackages not found; install dpkg-dev" >&2
    exit 1
}

mkdir -p "$repo_root/pool/${component}" "$repo_root/dists/${suite}/${component}/binary-amd64" "$repo_root/dists/${suite}/${component}/binary-arm64"
cp "$input_dir"/*.deb "$repo_root/pool/${component}/"

for arch in amd64 arm64; do
    pkg_dir="$repo_root/dists/${suite}/${component}/binary-${arch}"
    (
        cd "$repo_root"
        dpkg-scanpackages --arch "$arch" "pool/${component}" /dev/null > "dists/${suite}/${component}/binary-${arch}/Packages"
        gzip -9c "dists/${suite}/${component}/binary-${arch}/Packages" > "dists/${suite}/${component}/binary-${arch}/Packages.gz"
    )
done

release="$repo_root/dists/${suite}/Release"
now="$(date -Ru)"
cat > "$release" <<RELEASE
Origin: Blackwire
Label: Blackwire
Suite: ${suite}
Codename: ${suite}
Date: ${now}
Architectures: amd64 arm64
Components: ${component}
Description: Blackwire apt repository
RELEASE

(
    cd "$repo_root/dists/${suite}"
    {
        echo "SHA256:"
        for file in "${component}"/binary-*/Packages "${component}"/binary-*/Packages.gz; do
            size="$(wc -c < "$file" | tr -d ' ')"
            hash="$(sha256sum "$file" | awk '{print $1}')"
            printf ' %s %16s %s\n' "$hash" "$size" "$file"
        done
    } >> Release
)
