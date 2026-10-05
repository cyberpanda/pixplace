#!/usr/bin/env bash
# Simple launcher.
#   ./start.sh                      local, unencrypted (127.0.0.1:9998)
#   HOST=0.0.0.0 ./start.sh         listen on all interfaces
#   TLS_CERT=cert.pem TLS_KEY=key.pem ./start.sh   direct TLS (wss/https)
set -euo pipefail
cd "$(dirname "$0")"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-9998}"
ARGS=(--host "$HOST" --port "$PORT")
[ -n "${TLS_CERT:-}" ] && [ -n "${TLS_KEY:-}" ] && ARGS+=(--tls-cert "$TLS_CERT" --tls-key "$TLS_KEY")
exec python3 server.py "${ARGS[@]}"
