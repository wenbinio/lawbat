<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `matter.read:metadata` (structured email-header metadata seam) — AS BUILT

**Shipped:** `runtime::EmailHeaders` + `parse_email_headers` (the `firmos.meta/1` form) +
`Core::matter_read_metadata` (`core/crates/runtime/src/{metadata,lib}.rs`); the producer
serializer `extract::{to_canonical, percent_encode}` (`core/crates/extract/src/metadata.rs`) —
verified by a cross-crate round-trip through the REAL `parse_email_headers` (50k fuzz, zero
mismatches). No `MatterStore` trait change (variant B-b, as decided). **Not built:** the
ingestion JOB that calls the serializer over a real `.eml` and writes the doc into the matter
store (see "Still owed").

## The decision (kept for rationale)

Core-side parse over the existing `matter_read_text` storage path — no `MatterStore` trait
change. Rejected: raw-string reuse of `matter_read_text(Metadata)` (pushes RFC 2047/multi-
address/Bcc/date parsing into EACH consumer — the duplication behind the `.eml` extractor's
multibyte-slice Critical); a `MatterStore` trait method (every impl changes, could parse
differently); a typed structured store class (forks the data model early). `runtime` must not
depend on a mail parser or hand-roll RFC 822/2047 in its most-trusted code, so `extract` (the
producer) parses ONCE and writes a trivial canonical form the core only DESERIALIZES. A module is
never the producer.

## The `firmos.meta/1` canonical form (the cross-crate contract)

Versioned, line-based, percent-encoded. Line 1 = `firmos.meta/1` (unknown version → fail-closed
refuse). Each line after is `TAG<SP>percent-encoded-value`, `TAG ∈ {from,to,cc,bcc,reply-to,
subject,date,message-id}`; multi-value fields repeat the TAG (source order); single-value fields
emit at most one. Percent-encoding escapes `%`/CR/LF/controls so every value is one line. **Absent
field → no line → `None`** (never fabricated). `date` = RFC 3339 when parseable, else omitted.

## Load-bearing decisions kept

`EmailHeaders` is `runtime`-owned + inert (not a re-export of `extract`'s type); **Bcc is an
explicit field** (a named leak vector no consumer can "miss"). `parse_email_headers` is std-only,
never-panics, fail-closed (bad line skipped, not crashed; unknown TAGs ignored). Read path:
default-deny (no audit on refusal) → entitlement-filter (doc exists AND is `Metadata` class — a
`matter.read:document`-only module can't reach headers) → audit-before-return (log failure
`?`-aborts, value dropped) → parse → return. **Audit = doc id + class only, NEVER a header value.**

## Still owed
- **The ingestion JOB** (`extract` over `.eml` → doc in the matter store via `Core`) doesn't exist
  yet; the reader is tested against seeded/round-tripped docs until it lands.
- **F-1 graceful degradation:** percent-encoding can 3×-expand a value, so an oversized
  subject/recipient list can push a doc past the 256 KiB `MAX_CANONICAL_BYTES`, failing CLOSED the
  WHOLE message's metadata (a readability cliff, not a leak). Fix on landing: clamp/truncate with
  a surfaced warning instead of all-or-nothing.
- Deferred to the persistence gate: the persisted metadata SCHEMA; any non-email metadata shape.
