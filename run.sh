#!/usr/bin/env bash
# Lawbat — one-command launcher (Linux/macOS dev box).
#
# Mirrors run.bat for the dev machine: cd to the repo root, set PYTHONPATH=.,
# locate the redact-cli engine (env -> vendor/core -> target/release ->
# target/debug) and export LAWDATAMAN_REDACT_CLI, run the setup doctor, then
# start the server and open the Redaction page. If the engine is missing it still
# starts the server (redaction shows the honest "Tool offline" state).
#
# Dependency-free shell — POSIX-ish bash, no extra tools required.
set -u

# --- 0. optional demo mode: index demo/sample-room and open Home --------------
DEMO=0
if [ "${1:-}" = "--demo" ]; then
  DEMO=1
fi

# --- 1. cd to this script's own directory (the repo root) ---------------------
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT" || { echo "could not cd to $REPO_ROOT"; exit 1; }

# Demo indexes a fictional folder. Keep that database in the clone, not in the
# user's real DataRoomReview directory. Set this before the doctor, which
# creates the data dir as part of its writability check.
if [ "$DEMO" = "1" ]; then
  export LAWDATAMAN_DATA_DIR="$REPO_ROOT/.demo-data"
fi

# --- 2. PYTHONPATH=. so `python -m app.serve` finds the `app` package ---------
export PYTHONPATH=.

echo ""
echo "Lawbat launcher"
echo "  folder: $REPO_ROOT"

# --- find a Python interpreter -----------------------------------------------
PY=""
for cmd in python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then PY="$cmd"; break; fi
done
if [ -z "$PY" ]; then
  echo ""
  echo "Python was not found. Install Python 3.11 or 3.12 and try again." >&2
  exit 1
fi

# --- 3. locate the redaction engine (env -> vendor -> release -> debug) -------
ENGINE=""
if [ -n "${LAWDATAMAN_REDACT_CLI:-}" ] && [ -x "${LAWDATAMAN_REDACT_CLI}" ]; then
  ENGINE="${LAWDATAMAN_REDACT_CLI}"
else
  for c in \
    "$REPO_ROOT/vendor/core/redact-cli" \
    "$REPO_ROOT/core/target/release/redact-cli" \
    "$REPO_ROOT/core/target/debug/redact-cli"; do
    if [ -x "$c" ]; then ENGINE="$c"; break; fi
  done
fi

if [ -n "$ENGINE" ]; then
  export LAWDATAMAN_REDACT_CLI="$ENGINE"
  echo "  engine: $ENGINE"
else
  echo "  engine: NOT FOUND — redaction will show the honest 'Tool offline' state."
  echo "    Build it:  cargo build -p redact-cli --release"
  echo "    (it lands at core/target/release/redact-cli), or drop redact-cli into vendor/core/."
fi

# Home's worklist uses viewgen. The Python locator does not look in core/target
# on its own, so this script exports the path when a local build exists.
VIEWGEN=""
if [ -n "${LAWDATAMAN_VIEWGEN:-}" ] && [ -x "${LAWDATAMAN_VIEWGEN}" ]; then
  VIEWGEN="${LAWDATAMAN_VIEWGEN}"
else
  for c in \
    "$REPO_ROOT/vendor/core/viewgen" \
    "$REPO_ROOT/core/target/release/viewgen" \
    "$REPO_ROOT/core/target/debug/viewgen"; do
    if [ -x "$c" ]; then VIEWGEN="$c"; break; fi
  done
fi
if [ -n "$VIEWGEN" ]; then
  export LAWDATAMAN_VIEWGEN="$VIEWGEN"
  echo "  viewgen: $VIEWGEN"
else
  echo "  viewgen: NOT FOUND — Home will show the labelled sample preview."
  echo "    Build it:  cargo build -p viewgen --release"
fi

# --- 4. run the setup doctor (informational; never blocks the launch) --------
echo ""
echo "Running setup doctor..."
if ! "$PY" -m app.doctor; then
  echo ""
  echo "The doctor reported a problem (see the table above)."
  echo "  If a dependency is missing, run:  pip install -r requirements.txt"
  echo "  Starting anyway so you can see the app..."
fi

# --- 5. start the server, wait for the port, open the browser ----------------
PORT=8077
if [ "$DEMO" = "1" ]; then
  URL="http://127.0.0.1:${PORT}/"
  SERVE_ARGS=(--demo)
else
  URL="http://127.0.0.1:${PORT}/redaction"
  SERVE_ARGS=()
fi

echo ""
echo "Starting Lawbat on ${URL} ..."

"$PY" -m app.serve "${SERVE_ARGS[@]}" &
SERVER_PID=$!

# stop the server when this script is interrupted/terminated.
trap 'kill "$SERVER_PID" 2>/dev/null' INT TERM EXIT

# Poll the port until it accepts a connection or we time out (~30s).
bound=0
for _ in $(seq 1 60); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi   # server died on startup
  if "$PY" - "$PORT" <<'PYEOF' 2>/dev/null
import socket, sys
s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
PYEOF
  then bound=1; break; fi
  sleep 0.5
done

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo ""
  echo "The server stopped during startup — usually a missing dependency." >&2
  echo "  Run:  pip install -r requirements.txt   then:  python -m app.doctor" >&2
  exit 1
fi

if [ "$bound" = "1" ]; then
  echo "Opening ${URL}"
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 &
  else echo "  (open ${URL} in your browser)"; fi
else
  echo "The server is taking a while — open ${URL} yourself if it does not appear."
fi

echo ""
echo "Lawbat is running. Press Ctrl+C to stop it."
wait "$SERVER_PID"
