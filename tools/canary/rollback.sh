#!/usr/bin/env bash
set -euo pipefail

PREV_TAG="${1:-}"
if [ -z "$PREV_TAG" ]; then
  echo "Usage: $0 <previous-release-tag>"
  exit 2
fi

cat <<EOF
rollback_steps:
  1. Shift traffic to stable deployment target.
  2. Redeploy image/tag: ${PREV_TAG}
  3. Reload config from last-known-good snapshot.
  4. Verify health endpoints and synthetic probes.
  5. Confirm rss/fd/task counters return to baseline.
EOF
