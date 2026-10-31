<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Wire `redact_pdf` through `Core` (the binary/blob matter class) — AS BUILT

**Shipped (Option B):** `MatterContent{Text,Blob}`, `DocRef.kind` (`ContentKind`),
`matter_read_blob`/`document_transform_blob` (`core/crates/runtime/src/{matter,lib}.rs`,
byte-length-only audit), and redaction's `scan_matter_pdf`/`redact_matter_pdf`
(`core/crates/redaction/src/lib.rs`) — no new capability/class; RNG-free core preserved. **v1 =
apply-all + config-level review at the `Core` layer** (below); the underlying per-span
`PdfCandidateId`/`PdfSelection` primitive (`redaction/src/pdf.rs`, `redact_pdf_with_selection`) IS
built and wired directly into `redact-cli`'s `pdf_apply` (`redaction.README.md`), but is **not yet
Core-wired** — `redact_matter_pdf` itself stays apply-all-only (its own doc comment: "There is NO
per-span PDF `Selection`... not built here").

## D1 — the matter model: `MatterContent` enum
`enum MatterContent { Text(String), Blob(Vec<u8>) }` — text XOR bytes, ONE data plane (one
entitlement filter, one audit posture); only read/transform accessors become content-kind aware.
Rejected: base64-into-`String` (+33% size, muddies text-path invariants); a parallel blob store
(two entitlement paths that could drift).

## D2 — no new capability, no new data class
Text-vs-blob is a content-kind dimension, NOT an entitlement one: PDF read/transform uses the
EXISTING `matter.read:document` + `document.transform`; the store just records content kind.

## D3 — `Core` methods (mirror the text pair exactly)
`matter_read_blob`: default-deny (no audit on refusal) → entitlement-filter (doc exists AND is
`class` AND is `Blob`) → audit-before-return. A `Text` doc read via `_blob` is a **content-kind
mismatch error**, never coerced. `document_transform_blob` mirrors `document_transform`'s three
fail-closed audit entries (read; transform start; transform complete). **Audit = counts/
attribution + BYTE LENGTH ONLY, never bytes** (mirrors `egress_send`/`egress_fetch`).

## D4 — redaction-side wiring + the v1 review model (honest scope)
`scan_matter_pdf`: `matter_read_blob` → `redact_pdf` (keep candidates, discard redacted bytes) →
audit a SCAN (counts/breakdown only); needs only `matter.read:document`. `redact_matter_pdf`:
`matter_read_blob` → `redact_pdf` → audit-note BEFORE the write (fail-closed) → write via
`document_transform_blob`; bytes computed ONCE (no second `redact_pdf` call to diverge, no
write-unchanged-on-error fallback).

**Review model.** PDF candidate offsets are per-content-stream reconstructed, with no stable
cross-call identity (re-parsing can renumber/recompress objects), so a `Core`-mediated per-span
`Selection` would be fragile. v1 review is **config-level**: the lawyer sees every candidate via
`scan_matter_pdf`, adjusts the engine config, re-scans, and runs `redact_matter_pdf` — accepting
at recognizer-config granularity, not per-span, through `Core`. (The per-span primitive already
exists in `pdf.rs` and is used by `redact-cli` directly, outside `Core`.)

## Unchanged disciplines + RNG guard
Audit: doc id + class + count + breakdown + byte lengths, NEVER bytes/matched values;
`PdfRedaction` stays sealed (not `Clone`). `redact_pdf` is byte-deterministic (capped flate
decode, no RNG). The `Core` methods only move `Vec<u8>` + audit — they never call `lopdf`
themselves (`redact_pdf` does, inside `redaction`); the CI RNG guard keeps `getrandom`/`rand` out
of `runtime` (checked; `host` legitimately carries wasmtime's platform RNG and never pulls `lopdf`).
