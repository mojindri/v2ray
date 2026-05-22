#!/usr/bin/env bash
# wait_for_port.sh <port> [max_wait_seconds]
# Polls until 127.0.0.1:<port> is accepting connections.
set -euo pipefail

PORT="${1:?usage: $0 <port> [max_seconds]}"
MAX="${2:-30}"

echo -n "Waiting for 127.0.0.1:$PORT"
for i in $(seq 1 "$MAX"); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
        echo " ready (${i}s)"
        exit 0
    fi
    echo -n "."
    sleep 1
done

echo " TIMEOUT after ${MAX}s"
exit 1
