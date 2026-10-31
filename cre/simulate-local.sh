#!/usr/bin/env bash
# Local dry-run of the redaction attestation path.
#
# This is not `cre workflow simulate`. The CRE CLI refuses to simulate without
# a Chainlink account, and this environment does not create one or spend funds.
# What this script does instead:
#   1. Lawbat writes a fictional attestation (hashes and counts only).
#   2. A localhost HTTP server serves it. That is the external system.
#   3. The script fetches that URL, the same call the CRE HTTP capability makes.
#   4. Anvil (chain id 11155111) receives RedactionRegistry.onReport from the
#      public Anvil account 0. That account is the stand-in for KeystoneForwarder.
#   5. getAttestation(docHash) reads the record back.
#
# The private key below is the well-known Anvil/Hardhat development key.
# It is not a secret. Do not fund it and do not reuse it anywhere else.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$CRE_DIR/.local-sim"
mkdir -p "$WORK"
ATT="$WORK/attestation.json"
PORT="${ATTESTATION_PORT:-8765}"
RPC="http://127.0.0.1:${ANVIL_PORT:-18545}"
# Anvil account 0. Public development key, local chain only.
ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

export PATH="${HOME}/.foundry/bin:${PATH}"
export PYTHONPATH="$ROOT"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [[ -n "${ANVIL_PID:-}" ]]; then kill "$ANVIL_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

echo "== build fictional attestation =="
python3 -m app.attestation sample --now --out "$ATT"
python3 - <<PY
import json
att = json.load(open("$ATT"))
blob = json.dumps(att)
for banned in ("filename", "reviewer", "client", "@", "safe to send"):
    if banned in blob:
        raise SystemExit(f"attestation contains {banned!r}")
print("document_sha256", att["document_sha256"])
print("report_sha256", att["report_sha256"])
print("risk", att["reid_risk"]["level"], att["reid_risk"]["level_code"])
print("counts", att["counts_by_category"])
PY

echo "== serve attestation on 127.0.0.1:${PORT} =="
python3 -m app.attestation serve --file "$ATT" --host 127.0.0.1 --port "$PORT" \
  >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null; then break; fi
  sleep 0.2
done
echo "== fetch attestation (external HTTP call) =="
curl -sf "http://127.0.0.1:${PORT}/attestation" | python3 -m json.tool | head -n 40

echo "== anvil chain-id 11155111 on ${RPC} =="
anvil --host 127.0.0.1 --port "${ANVIL_PORT:-18545}" --chain-id 11155111 --silent \
  >"$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
echo "chain-id $(cast chain-id --rpc-url "$RPC")"

echo "== deploy RedactionRegistry (forwarder = anvil account 0) =="
DEPLOY="$(forge create "$CRE_DIR/contracts/src/RedactionRegistry.sol:RedactionRegistry" \
  --root "$CRE_DIR/contracts" \
  --rpc-url "$RPC" \
  --private-key "$ANVIL_KEY" \
  --broadcast \
  --constructor-args "$ANVIL_ADDR")"
echo "$DEPLOY"
REG="$(printf '%s\n' "$DEPLOY" | awk '/Deployed to:/ {print $3}')"
echo "registry $REG"

echo "== abi-encode the attestation and call onReport =="
read -r DOC REPORT LEVEL TS < <(python3 - <<PY
import json
from datetime import datetime, timezone
att = json.load(open("$ATT"))
ts = int(datetime.strptime(att["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
print("0x"+att["document_sha256"], "0x"+att["report_sha256"], att["reid_risk"]["level_code"], ts)
PY
)
ENCODED="$(cast abi-encode "f(bytes32,bytes32,uint8,uint64)" "$DOC" "$REPORT" "$LEVEL" "$TS")"
cast send "$REG" "onReport(bytes,bytes)" "0x" "$ENCODED" \
  --rpc-url "$RPC" --private-key "$ANVIL_KEY"

echo "== read back getAttestation(docHash) =="
READBACK="$(cast call "$REG" "getAttestation(bytes32)(bytes32,uint8,uint64,uint64)" "$DOC" --rpc-url "$RPC")"
echo "$READBACK"
python3 - <<PY
def token(line):
    return line.strip().split()[0]

readback = """$READBACK""".strip().splitlines()
report = token(readback[0])
level = int(token(readback[1]))
ts = int(token(readback[2]))
expected_report = "$REPORT".lower()
expected_level = int("$LEVEL")
expected_ts = int("$TS")
if report.lower() != expected_report or level != expected_level or ts != expected_ts:
    raise SystemExit(f"read-back mismatch: {readback}")
print("read-back matches docHash")
PY

echo "== RedactionAttested logs =="
cast logs --from-block 1 --to-block latest --address "$REG" \
  "RedactionAttested(bytes32 indexed docHash, bytes32 reportHash, uint8 riskLevel, uint64 ts)" \
  --rpc-url "$RPC"

echo "LOCAL_DRY_RUN_OK registry=$REG"
