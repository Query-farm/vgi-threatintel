#!/bin/sh
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Dispatch the single vgi-threatintel image into one of its transports:
#   http   (default) the HTTP server on $PORT (8000), bound 0.0.0.0 so a
#                    published host port reaches it. Serves /health.
#   stdio            a worker DuckDB spawns over stdio (on-host execution).
#   unix             the AF_UNIX launcher transport on $VGI_UNIX_SOCKET.
# Any other first argument is exec'd verbatim (escape hatch for debugging).
#
# The worker is stateless (offline classifiers compiled in; the reputation
# table function calls out per request), so there is no /data to create and no
# state env to wire — each mode just exec's the binary.
set -e

case "${1:-http}" in
  http)
    shift 2>/dev/null || true
    # The Go SDK's RunHttp binds EXACTLY the address passed to --http-addr. In a
    # container we must bind 0.0.0.0 on a FIXED port so `-p $PORT:$PORT` and the
    # HEALTHCHECK reach it (the dev/CI default is an ephemeral loopback port).
    exec vgi-threatintel-worker --http --http-addr "0.0.0.0:${PORT:-8000}" "$@"
    ;;
  stdio)
    shift 2>/dev/null || true
    exec vgi-threatintel-worker "$@"
    ;;
  unix)
    shift 2>/dev/null || true
    exec vgi-threatintel-worker --unix "${VGI_UNIX_SOCKET:-/tmp/threatintel.sock}" "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
