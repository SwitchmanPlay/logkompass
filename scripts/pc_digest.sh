#!/usr/bin/env bash
# Run the digest on your own machine against the local model, without exposing it.
#
#   bash scripts/pc_digest.sh danya@<public-ip> 2242 2026-09-20
#
# The server only ships the aggregate JSON. Raw log lines never leave it.
set -euo pipefail

TARGET="${1:?usage: pc_digest.sh user@host [port] [day]}"
PORT="${2:-2242}"
DAY="${3:-$(date -u -d yesterday +%F)}"
LOCAL_CONFIG="${LOCAL_CONFIG:-config.local.toml}"

ssh -p "$PORT" "$TARGET" \
  "sudo -u logkompass /opt/logkompass/.venv/bin/logkompass --config /etc/logkompass/config.toml aggregate --day $DAY" \
  > "agg-$DAY.json"

logkompass --config "$LOCAL_CONFIG" digest --input "agg-$DAY.json" --no-store --notify stdout
