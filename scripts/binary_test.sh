#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STATE_DIR="$(mktemp -d -t mosaic-cli-e2e.XXXXXX)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$STATE_DIR"' EXIT

export MOSAIC_STATE_DIR="$STATE_DIR/state"
export MOSAIC_SECRET_PATH="$STATE_DIR/mosec.key"
mkdir -p "$MOSAIC_STATE_DIR"

run_with_timeout() {
  python3 - "$@" <<'PY'
import subprocess, sys
cmd = sys.argv[1:]
try:
    result = subprocess.run(cmd, timeout=20, check=False)
except subprocess.TimeoutExpired:
    print("Command timed out:", " ".join(cmd), file=sys.stderr)
    sys.exit(124)
sys.exit(result.returncode)
PY
}

zig build > /dev/null

MO_BIN="./zig-out/bin/mo"
MOS_BIN="./zig-out/bin/mos"

$MOS_BIN --host 127.0.0.1 --port 8787 &
SERVER_PID=$!

ready=0
for _ in {1..50}; do
  if python3 - <<'PY'
import socket
s = socket.socket()
try:
    s.connect(("127.0.0.1", 8787))
except OSError:
    raise SystemExit(1)
else:
    s.close()
    raise SystemExit(0)
PY
  then
    ready=1
    break
  fi
  sleep 0.1
done

if [[ "$ready" != "1" ]]; then
  echo "Server did not become ready" >&2
  exit 1
fi

run_with_timeout "$MO_BIN" keygen > /dev/null || true

PUBLISH_OUTPUT=$(run_with_timeout "$MO_BIN" --server 127.0.0.1 --port 8787 --no-tls publish --text "mosaic zig e2e")
echo "$PUBLISH_OUTPUT"
RECORD_ID=$(echo "$PUBLISH_OUTPUT" | awk '/^published / {print $2}')

# Wipe local cache so timeline must fetch from the server.
rm -rf "$MOSAIC_STATE_DIR"
mkdir -p "$MOSAIC_STATE_DIR"

TIMELINE_OUTPUT=$(run_with_timeout "$MO_BIN" --server 127.0.0.1 --port 8787 --no-tls timeline --limit 10 --reference "$RECORD_ID")
echo "$TIMELINE_OUTPUT"
if ! echo "$TIMELINE_OUTPUT" | grep -q "mosaic zig e2e"; then
  echo "Timeline did not contain published message" >&2
  exit 1
fi

echo "Shutting down server..."
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
