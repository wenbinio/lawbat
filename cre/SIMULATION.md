# Simulation record

## Real CRE CLI simulation

Recorded **2026-10-31 ~23:50 SGT** (Asia/Singapore, UTC+8). CRE CLI **v1.39.0**, logged in. No transaction was broadcast to a public network (`--broadcast` was not set). The CLI used its default simulation private key for the chain-write dry-run.

Working directory: `cre/`.

Services running for the run:

- Attestation HTTP server on `http://127.0.0.1:8765/attestation` (hashes and counts only)
- Anvil on `http://127.0.0.1:18545`, chain id `11155111` (Sepolia id)
- `RedactionRegistry` deployed at `0x5FbDB2315678afecb367f032d93F642f64180aa3` (Anvil account 0 as the KeystoneForwarder stand-in)

Config fix applied for this run: Zod's `.url()` rejects loopback hosts inside the CRE WASM runtime, so `cre/workflow/main.ts` validates `attestationUrl` as a non-empty string and `assertLoopbackAttestationUrl` still enforces `http://127.0.0.1|localhost:<port>/attestation`.

```
$ cre version
CRE CLI version v1.39.0

$ cre workflow simulate workflow --target local-simulation --non-interactive \
    --trigger-index 0 \
    --http-payload '{"attestationUrl":"http://127.0.0.1:8765/attestation"}'
Initializing...
Loading settings...
! Using default private key for chain write simulation. To use your own key, set CRE_ETH_PRIVATE_KEY in your .env file or system environment.
Checking RPC connectivity...
Compiling workflow...
✓ Workflow compiled
✓ Simulation limits enabled
  Binary hash: 68f28ff1721cc425d2bd761aa8a2aaccf061bcf559a04a5c5ac7f8edea19aef3
  Config hash: d74f04afd9c90eacc1239e8f694c2702f3b74d5c87d3bd5b793ed8fc5f0038a9
✓ Parsed JSON input successfully
✓ Created HTTP trigger payload with 1 fields
2026-10-31T23:50:49Z [SIMULATION] Simulator Initialized

2026-10-31T23:50:49Z [SIMULATION] Running trigger trigger=http-trigger@1.0.0-alpha
2026-10-31T23:50:49Z [USER LOG] Validated attestation doc=c00fa5552c2163e586279bec72ed7436b095b4d07c46a0485dce535359b7cf61 risk=high categories=3
2026-10-31T23:50:49Z [USER LOG] Signed the EVM report. Submitting it to RedactionRegistry.
2026-10-31T23:50:49Z [USER LOG] RedactionAttested dry-run succeeded tx=0x0000000000000000000000000000000000000000000000000000000000000000

✓ Workflow Simulation Result:
"{\"document_sha256\":\"c00fa5552c2163e586279bec72ed7436b095b4d07c46a0485dce535359b7cf61\",\"report_sha256\":\"a2ad3d397b3a6f3117726ab028fd8a2a055c1319efe5a4e0196446d0edbb462e\",\"risk_level\":2,\"tx_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}"

2026-10-31T23:50:49Z [SIMULATION] Execution finished signal received
2026-10-31T23:50:49Z [SIMULATION] Skipping WorkflowEngineV2

╭──────────────────────────────────────────────────────╮
│ Simulation complete! Ready to deploy your workflow?  │
│                                                      │
│ Run cre account access to request deployment access. │
╰──────────────────────────────────────────────────────╯
```

Result: **`cre workflow simulate` succeeded.** Exit code 0. The HTTP trigger ran, the workflow fetched and validated the Lawbat attestation over loopback HTTP, signed an EVM report, and completed `writeReport` as a dry-run (tx hash all zeros because broadcast was off). The raw combined log is [simulation.log](simulation.log).

Caveats:

- Deploy Access on the CRE account is **not enabled**. This run is simulation only; it does not deploy a live workflow.
- No Sepolia broadcast. The zero `tx_hash` is expected without `--broadcast`.
- Timestamps in the CLI log are wall-clock on the machine (SGT) printed with a `Z` suffix by the simulator.

## Earlier local dry-run (no CRE login)

Before the CRE account existed, `./cre/simulate-local.sh` ran the same attestation path offline: HTTP fetch from Lawbat on `127.0.0.1`, then `RedactionRegistry.onReport` on Anvil. That offline path remains available. The first attempt at `cre workflow simulate` without a login stopped at authentication and is superseded by the section above.
