# Chainlink CRE audit trail

Optional companion to Lawbat for the DoraHacks **Best workflow with CRE** bounty.

Lawbat redacts on the lawyer's machine and can export a **redaction attestation** (hashes and category counts only — no document text, no names). A Chainlink CRE workflow fetches that attestation over loopback HTTP, validates it, signs an EVM report, and submits it to `RedactionRegistry`, which emits `RedactionAttested`.

**Honest status:** this repository documents a successful **`cre workflow simulate`** run. CRE **deploy access is not enabled** on the account used for that run. Nothing was broadcast to a public network. See [SIMULATION.md](SIMULATION.md) and [simulation.log](simulation.log).

## Bounty requirements → this repo

| Requirement | Where it lives |
|---|---|
| CRE workflow as orchestration (TypeScript or Go SDK + CLI) | [`workflow/main.ts`](workflow/main.ts) (TypeScript CRE SDK) |
| Connect at least one blockchain to an external API / system | EVM Sepolia (local Anvil with Sepolia chain id) ← HTTP GET of Lawbat attestation on `127.0.0.1` |
| Successful CRE CLI simulation or live deployment | Simulation recorded in [SIMULATION.md](SIMULATION.md) (`cre workflow simulate`, CLI v1.39.0) |

## Layout

| Path | Role |
|---|---|
| [`workflow/main.ts`](workflow/main.ts) | HTTP trigger → fetch attestation → validate → `runtime.report` → `evmClient.writeReport` |
| [`workflow/attestation.ts`](workflow/attestation.ts) | Schema + report-hash check (shared with `bun test`) |
| [`contracts/src/RedactionRegistry.sol`](contracts/src/RedactionRegistry.sol) | Consumer: `onReport` → `RedactionAttested` |
| [`fixtures/sample-attestation.json`](fixtures/sample-attestation.json) | Deterministic fictional attestation |
| [`simulate-local.sh`](simulate-local.sh) | Offline dry-run (no CRE login): HTTP fetch + Anvil `onReport` |
| [`project.yaml`](project.yaml) | Local RPC target for simulation (`127.0.0.1:18545`) |

## Reproduce the CRE CLI simulation

Prerequisites: Node/Bun, Foundry (`forge`, `anvil`), and the [CRE CLI](https://docs.chain.link/cre) (`cre`), plus a free Chainlink CRE account (`cre login`).

From the repository root:

```bash
# 1. Python deps for the attestation helper (venv recommended)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Workflow deps + unit tests (hash parity with Python)
cd cre/workflow && bun install && bun test && cd ../..

# 3. Consumer contract tests
cd cre/contracts
forge install foundry-rs/forge-std
forge test
cd ../..

# 4. Start Anvil with the Sepolia chain id on the port in project.yaml
anvil --chain-id 11155111 --port 18545 &

# 5. Deploy RedactionRegistry with Anvil account 0 as the forwarder stand-in
#    (Foundry requires --broadcast). Exact commands are in simulate-local.sh.
#    Put the deployed address in cre/workflow/config.local.json → consumerAddress.
#    The recorded simulation used 0x5FbDB2315678afecb367f032d93F642f64180aa3
#    (Anvil's first CREATE address when account 0 deploys first on a fresh node).

# 6. Serve a loopback attestation (hashes/counts only)
PYTHONPATH=. python3 -m app.attestation sample --out cre/fixtures/sample-attestation.json
PYTHONPATH=. python3 -m app.attestation serve --file cre/fixtures/sample-attestation.json --port 8765 &

# 7. Simulate (CRE login required once: `cre login`)
cd cre
cre workflow simulate workflow --target local-simulation --non-interactive \
  --trigger-index 0 \
  --http-payload '{"attestationUrl":"http://127.0.0.1:8765/attestation"}'
```

Steps 4–6 are also what [`simulate-local.sh`](simulate-local.sh) automates for the **offline** path (no `cre login`). Prefer that script if you only need to confirm the attestation → registry wiring without the CRE runtime:

```bash
./cre/simulate-local.sh
```

## What goes on chain

Only:

- redacted-output SHA-256 (`document_sha256`)
- attestation report hash (`report_sha256`)
- risk level `0..3` (`not_assessed` / `noted` / `high` / `unique`)
- Unix timestamp

A higher risk code is a concern signal only. It never means the document is cleared to send.

## Security notes

- Attestation HTTP is loopback-only; the workflow rejects non-loopback attestation URLs.
- `POST /api/attestation` on the Lawbat app requires the session token; the sample server used for CRE simulation serves a pre-built JSON file with no privileged report text.
- This tree does not commit CRE API keys, `.env` files, or funded private keys. The Anvil development key used in `simulate-local.sh` is the public Well-Known Hardhat/Anvil key and must not be funded or reused elsewhere.
