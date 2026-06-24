#!/usr/bin/env bash
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Run this repo's sqllogictest suite (test/sql/*.test) against the vgi-threatintel
# VGI worker, using a prebuilt standalone `haybarn-unittest` and the signed
# community `vgi` extension — no C++ build from source. See ci/README.md.
#
# Multi-transport: the same suite runs over whichever transport the TRANSPORT
# env var selects, by changing what `VGI_THREATINTEL_WORKER` resolves to (the
# vgi extension picks the transport from the ATTACH LOCATION string):
#
#   subprocess (default)  VGI_THREATINTEL_WORKER = the stdio worker binary
#                         -> extension spawns it over stdin/stdout.
#   http                  start `<worker> --http` (prints "PORT:<n>"), parse the
#                         port, VGI_THREATINTEL_WORKER = http://127.0.0.1:<port>.
#   unix                  start `<worker> --unix /tmp/threatintel.sock` (prints
#                         "UNIX:<path>"), VGI_THREATINTEL_WORKER = unix:///tmp/threatintel.sock.
#
# In every transport the reputation table function hits the reputation source,
# so the suite ALWAYS needs the mock reputation server: this script builds the
# repo's `mockserver`, starts it on a free port, and points the tests at it via
# VGI_THREATINTEL_TEST_URL (base + /reputation, the base_url option). All started
# processes are trap-killed on exit.
#
# Required environment:
#   HAYBARN_UNITTEST         path to the haybarn-unittest binary
#   VGI_THREATINTEL_WORKER   for TRANSPORT=subprocess: the worker LOCATION the
#                            .test files ATTACH (the built Go worker binary,
#                            spawned over stdio). For http/unix this is OVERRIDDEN
#                            by this script, but the binary it points at is reused
#                            to launch the out-of-band server, so it must still be
#                            the worker path.
# Optional:
#   TRANSPORT                subprocess (default) | http | unix
#   STAGE                    scratch dir for the preprocessed tests (default: mktemp)
set -euo pipefail

: "${HAYBARN_UNITTEST:?path to the haybarn-unittest binary}"
: "${VGI_THREATINTEL_WORKER:?worker LOCATION (the built Go worker binary)}"

TRANSPORT="${TRANSPORT:-subprocess}"
case "$TRANSPORT" in
  subprocess|http|unix) ;;
  *) echo "ERROR: unknown TRANSPORT='$TRANSPORT' (expected subprocess|http|unix)" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
STAGE="${STAGE:-$(mktemp -d)}"

# The worker binary the subprocess transport ATTACHes to is also the binary we
# launch out-of-band for http/unix. Capture it before we possibly overwrite
# VGI_THREATINTEL_WORKER with a URL.
WORKER_BIN="$VGI_THREATINTEL_WORKER"

MOCK_PID=""
WORKER_PID=""
UNIX_SOCK=""
cleanup() {
  # Preserve the script's exit status (this runs on EXIT).
  local rc=$?
  if [ -n "$WORKER_PID" ]; then kill "$WORKER_PID" 2>/dev/null || true; wait "$WORKER_PID" 2>/dev/null || true; fi
  if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true; fi
  if [ -n "$UNIX_SOCK" ]; then rm -f "$UNIX_SOCK"; fi
  return "$rc"
}
trap cleanup EXIT

# --- Start the mock reputation server (the .test files query it; all transports)
MOCK_BIN="$STAGE/mockserver"
echo "Building mock reputation server ..."
( cd "$REPO" && go build -o "$MOCK_BIN" ./cmd/mockserver )

MOCK_PORT_FILE="$(mktemp)"
"$MOCK_BIN" --addr 127.0.0.1:0 >"$MOCK_PORT_FILE" 2>/dev/null &
MOCK_PID=$!

PORT=""
for _ in $(seq 1 30); do
  PORT="$(sed -n 's/^PORT:\([0-9][0-9]*\)$/\1/p' "$MOCK_PORT_FILE" 2>/dev/null | head -1)"
  [ -n "$PORT" ] && break
  sleep 0.2
done
if [ -z "$PORT" ]; then
  echo "ERROR: mock server did not report a port" >&2
  exit 1
fi
rm -f "$MOCK_PORT_FILE"
export VGI_THREATINTEL_TEST_URL="http://127.0.0.1:$PORT/reputation"
echo "Mock reputation server listening on $VGI_THREATINTEL_TEST_URL (pid $MOCK_PID)"

# --- Per-transport: resolve VGI_THREATINTEL_WORKER (the ATTACH LOCATION) ------
case "$TRANSPORT" in
  subprocess)
    echo "Transport: subprocess/stdio — VGI_THREATINTEL_WORKER=$VGI_THREATINTEL_WORKER"
    ;;

  http)
    WORKER_PORT_FILE="$(mktemp)"
    echo "Transport: http — starting '$WORKER_BIN --http' ..."
    "$WORKER_BIN" --http >"$WORKER_PORT_FILE" 2>/dev/null &
    WORKER_PID=$!
    WPORT=""
    for _ in $(seq 1 50); do
      WPORT="$(sed -n 's/^PORT:\([0-9][0-9]*\)$/\1/p' "$WORKER_PORT_FILE" 2>/dev/null | head -1)"
      [ -n "$WPORT" ] && break
      kill -0 "$WORKER_PID" 2>/dev/null || { echo "ERROR: http worker exited before reporting a port" >&2; cat "$WORKER_PORT_FILE" >&2 || true; exit 1; }
      sleep 0.2
    done
    rm -f "$WORKER_PORT_FILE"
    if [ -z "$WPORT" ]; then
      echo "ERROR: http worker did not report a port" >&2
      exit 1
    fi
    # Bare scheme://host:port with NO path (the extension POSTs each RPC method
    # at <LOCATION>/<method>, mounted at the server root).
    export VGI_THREATINTEL_WORKER="http://127.0.0.1:$WPORT"
    echo "HTTP worker listening on $VGI_THREATINTEL_WORKER (pid $WORKER_PID)"
    ;;

  unix)
    UNIX_SOCK="${TMPDIR:-/tmp}/threatintel.$$.sock"
    rm -f "$UNIX_SOCK"
    WORKER_OUT_FILE="$(mktemp)"
    echo "Transport: unix — starting '$WORKER_BIN --unix $UNIX_SOCK' ..."
    "$WORKER_BIN" --unix "$UNIX_SOCK" >"$WORKER_OUT_FILE" 2>/dev/null &
    WORKER_PID=$!
    READY=""
    for _ in $(seq 1 50); do
      if grep -q '^UNIX:' "$WORKER_OUT_FILE" 2>/dev/null && [ -S "$UNIX_SOCK" ]; then
        READY=1; break
      fi
      kill -0 "$WORKER_PID" 2>/dev/null || { echo "ERROR: unix worker exited before the socket was ready" >&2; cat "$WORKER_OUT_FILE" >&2 || true; exit 1; }
      sleep 0.2
    done
    rm -f "$WORKER_OUT_FILE"
    if [ -z "$READY" ]; then
      echo "ERROR: unix worker did not report a ready socket at $UNIX_SOCK" >&2
      exit 1
    fi
    export VGI_THREATINTEL_WORKER="unix://$UNIX_SOCK"
    echo "Unix worker listening on $VGI_THREATINTEL_WORKER (pid $WORKER_PID)"
    ;;
esac

# --- Stage the preprocessed tests -------------------------------------------
echo "Staging preprocessed tests into $STAGE ..."
mkdir -p "$STAGE/test/sql"
for f in "$REPO"/test/sql/*.test; do
  awk -f "$HERE/preprocess-require.awk" "$f" > "$STAGE/test/sql/$(basename "$f")"
done

# The HTTP transport drives the worker-RPC POSTs through DuckDB's HTTP client,
# only registered when `httpfs` is loaded. The .test files only `LOAD vgi`, so
# over HTTP those POSTs fail with an "HTTP"-flavoured error (which the runner
# silently SKIPS). Inject a signed httpfs INSTALL+LOAD after each `LOAD vgi;`
# for the http transport only.
if [ "$TRANSPORT" = "http" ]; then
  echo "Transport http: injecting 'LOAD httpfs' (required for the worker HTTP RPC) ..."
  for f in "$STAGE"/test/sql/*.test; do
    awk '
      { print }
      /^LOAD[ \t]+vgi;[ \t]*$/ {
        print "";
        print "statement ok";
        print "INSTALL httpfs FROM core;";
        print "";
        print "statement ok";
        print "LOAD httpfs;";
      }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
fi

cd "$STAGE"

# Warm the extension cache once: vgi from the signed community channel.
echo "Warming the extension cache (vgi from community) ..."
mkdir -p "$STAGE/test"
cat > "$STAGE/test/_warm.test" <<'EOF'
# name: test/_warm.test
# group: [warm]
statement ok
INSTALL vgi FROM community;
EOF
"$HAYBARN_UNITTEST" "test/_warm.test" >/dev/null 2>&1 || echo "::warning::extension warm step did not fully succeed"
rm -f "$STAGE/test/_warm.test"

# Run the whole suite in one invocation, capturing the runner's native
# sqllogictest report so we can both stream it AND guard against a silent skip.
#
# IMPORTANT: the runner SKIPS (exit 0) a test whose error message matches a
# built-in network-error allowlist that includes "HTTP". A broken HTTP transport
# would otherwise show "All tests were skipped" and go GREEN having run nothing.
# We detect that and fail explicitly.
echo "Running suite (transport: $TRANSPORT, worker: $VGI_THREATINTEL_WORKER) ..."
RUN_LOG="$STAGE/run.log"
set +e
"$HAYBARN_UNITTEST" "test/sql/*" 2>&1 | tee "$RUN_LOG"
RUN_RC="${PIPESTATUS[0]}"
set -e

if [ "$RUN_RC" -ne 0 ]; then
  echo "ERROR: suite failed (transport: $TRANSPORT, rc=$RUN_RC)" >&2
  exit "$RUN_RC"
fi

if grep -q 'All tests were skipped' "$RUN_LOG"; then
  echo "ERROR: every test was SKIPPED on transport '$TRANSPORT' (the runner's" >&2
  echo "       built-in network-error skip swallowed the real error). This is" >&2
  echo "       NOT a pass. Skip reason reported by the runner:" >&2
  grep -A3 'Skipped tests for the following reasons' "$RUN_LOG" >&2 || true
  exit 1
fi
