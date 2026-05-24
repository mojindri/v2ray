#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
REPORT_DIR_ARG="${1:-reports/production}"

case "$REPORT_DIR_ARG" in
  /*) REPORT_DIR="$REPORT_DIR_ARG" ;;
  *) REPORT_DIR="$PROJECT_ROOT/labs/realistic/$REPORT_DIR_ARG" ;;
esac

LOG_DIR="$REPORT_DIR/artifacts/logs"
mkdir -p "$LOG_DIR"

VM_HOST="${VM_HOST:-}"
VM_USER="${VM_USER:-lab}"
VM_SSH_PORT="${VM_SSH_PORT:-22}"
VM_REMOTE_DIR="${VM_REMOTE_DIR:-/tmp/blackwire-vm-browser-lab}"

if [ -z "$VM_HOST" ]; then
  echo "ERROR: VM_HOST is required. Example:"
  echo "  VM_HOST=192.168.64.10 VM_USER=lab make vm-browser-setup"
  exit 1
fi

SSH=(ssh -p "$VM_SSH_PORT" "$VM_USER@$VM_HOST")

echo "==> connecting to VM: $VM_USER@$VM_HOST:$VM_SSH_PORT"

"${SSH[@]}" 'bash -s' <<'REMOTE'
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: this setup helper expects Debian/Ubuntu with apt-get."
  exit 1
fi

sudo -v

sudo apt-get update
sudo apt-get install -y \
  curl \
  ca-certificates \
  gnupg \
  tcpdump \
  tshark \
  xvfb

if apt-cache show chromium >/dev/null 2>&1; then
  sudo apt-get install -y chromium
elif apt-cache show chromium-browser >/dev/null 2>&1; then
  sudo apt-get install -y chromium-browser
else
  echo "WARN: chromium package not found via apt. Install Google Chrome or Chromium manually."
fi

mkdir -p /tmp/blackwire-vm-browser-lab

echo "VM browser lab setup complete."
echo "Browser candidates:"
command -v chromium || true
command -v chromium-browser || true
command -v google-chrome || true
command -v google-chrome-stable || true
echo "tshark: $(command -v tshark || true)"
echo "tcpdump: $(command -v tcpdump || true)"
REMOTE
