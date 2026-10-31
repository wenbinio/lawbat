<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `core/` — trusted-core foundation + WASM substrate spike + first-party modules

The Rust "trusted core" the platform is becoming (see project `CLAUDE.md` → "Direction"). What
started as a thin foundation (**buys the option** on the platform architecture without building
the platform) has grown a full first-party module set on top; this README documents the
FOUNDATION — the two original parts below. For the module set (`redaction`, the `mailbox`→
`extract`→`inbox` email pipeline, `ingest`, `search`, `timesheet`, `audit-store`, `view`,
`viewgen`, `redact-cli`) see `CLAUDE.md` → "The Rust core" and each module's own doc.

1. **Trusted-core SEAMS** (`crates/runtime`) — capability broker, audit log, matter context,
   mediated storage, default-deny egress, as Rust traits + minimal in-memory impls. std-only
   **except** the two pure-compute crypto crates that key the audit chain (`sha2`+`hmac`,
   RustCrypto — no RNG, no network).
2. **A WASM substrate SPIKE** (`crates/host` + `modules/hello` + `wit/`) — the smallest proof
   that the chosen sandbox substrate (WASM components / WASI) delivers the one property the
   architecture hangs on.

## The one idea this proves

> The sandbox, the capability model, and the audit log are the **same chokepoint**.

- **(a) A granted, brokered call works and is logged.** The guest calls `host.note`; the host
  records it in the append-only, **HMAC-SHA-256 keyed** hash-chained audit log.
- **(b) The guest physically cannot reach the network.** There is **no** egress/socket/
  filesystem import in the guest's world — **the absence is the guarantee.**

## Layout
```
core/
  Cargo.toml / Cargo.lock   # committed (apps/bins, not libraries); default-members excludes the wasm guest
  wit/world.wit             # MINIMAL v0 / UNSTABLE world (spike only)
  crates/runtime/           # trusted-core seams (traits + in-memory impls) + tests    <- this doc
  crates/host/              # wasmtime host binary (the spike runner)                 <- this doc
  crates/{audit-store,redaction,extract,ingest,inbox,mailbox,search,timesheet,view,
           viewgen,redact-cli}/   # first-party modules on the seams above — see CLAUDE.md
  modules/hello/            # guest module -> wasm32-wasip2 component
```

## Build & run
The wasm guest builds first (only compiles for `wasm32-wasip2`, excluded from default build):
```sh
rustup target add wasm32-wasip2                              # one-time
cargo build -p hello --target wasm32-wasip2 --release        # the guest component
cargo build                    # runtime + host + all native first-party modules (default-members)
cargo run -p host    # loads target/wasm32-wasip2/release/hello.wasm (override: LAWDATAMAN_SPIKE_GUEST)
cargo test -p runtime
```
The host prints PROOF (a) + PROOF (b) and exits 0 only if both hold.

## Status: the WIT is v0 / UNSTABLE — do NOT harden

`wit/world.wit` is a **deliberately minimal v0 spike world**, NOT the module ABI. The real
typed surface is the private DRAFT `core-api.wit`. Per the architecture spec (§3 substrate,
§10 build discipline), the module ABI is a **one-way door**: do not freeze it until a working
substrate spike — *this* — has signed off and the redaction module has dogfooded it. Grow the
real world from the reconciled `core-api.wit` then, not from this file.

## Non-negotiables honored here (`CLAUDE.md`)
- **Local-only / no egress.** No networking crate anywhere; the `Egress` seam is a default-deny
  *gate*, not a transport — opens no socket.
- **Deterministic, no model/LLM calls.** No `compute.model` wired to anything.
- **AGPL-3.0.** Every source file carries an `SPDX-License-Identifier` header.

## Notes / rough edges
- **Audit = HMAC-SHA-256 keyed (DONE).** See `crates/runtime/src/audit.rs`. `runtime`'s own
  in-memory audit still can't self-detect total **erasure** (an empty log verifies `true`) or
  tail **truncation** — that needs external head-anchoring (`head_hash()`+`len()`) +
  WORM/append-only persistence, unsolvable in an erasable in-memory store. **`crates/audit-store`
  now supplies that durable, externally-anchored implementation** (verify-on-open detects
  Erasure/Truncation/ChainBroken/WrongKey/AnchorMismatch); real OS key custody (replacing the
  dev key) remains owed. (Full ledger: `core.to-fix.md`.)
- **Host error context** uses `map_err`, not `anyhow`'s `.context()` (wasmtime 45 ships its own
  `Error` that converts *into* but doesn't satisfy `anyhow::Context`).
- **WIT package-path nesting:** both `wit-bindgen` (guest) + wasmtime `bindgen!` (host) nest the
  interface under the package path (`dataroom::spike::host`); both need a matching `use`.
- **Guest `crate-type=["cdylib"]` + `default-members`:** a bare `cargo build` excludes the guest;
  CI must add the explicit `--target wasm32-wasip2` step.
- **No `wasm-tools`/`cargo-component` needed** — `cargo build --target wasm32-wasip2` emits a
  component directly.
