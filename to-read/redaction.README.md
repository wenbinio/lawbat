<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# redaction — module #1 (the flagship), native first-party module

Deterministic identifier-stripping over a matter's documents, dogfooding the trusted-core ABI
(spec §10). A NATIVE first-party module bound directly to the `Core` traits — no WASM, no model,
no network. Deps: `runtime` + `regex` (+ `lopdf`/`flate2` for `pdf.rs`). Sister docs:
`RECOGNIZER-PACKS-SPEC.md`, `LEVER2-CONTEXT-CONFIDENCE.md`, `INDUCTION-SPEC.md`.

## Honest framing (do NOT overclaim — load-bearing)

- **REMOVES matched identifiers, including the underlying text** (replaced with `[REDACTED]` via
  mediated `document.transform`; the span is overwritten, not masked/annotated).
- **Reasonable-efforts, NEVER "safe to send."** The guarantee is **control + accountability**
  (what was stripped is audited; the engine holds no egress path), NOT content-safety. Residual
  re-identification (*"the only S$11bn deal closing this quarter"*) is irreducibly the lawyer's
  judgment and cannot be removed by string matching.
- **Recall-tuned by design:** a false flag costs a reviewer seconds; a **miss is a Rule-6
  (confidentiality) breach.** Patterns are deliberately broad.
- **Statistical detection (NER, Presidio-class) is a LATER `compute.model` tier** (local, scoped,
  logged), not this deterministic increment — the Tier-2 lawyer review owns residual judgment.

## What it recognizes

1. **Explicit term list** — caller-supplied party names / deal codenames / matter numbers.
   `regex::escape`d (metacharacters in `A.B (Pte)` are literal), case-insensitive on real char
   boundaries, incl. non-ASCII whose lowercase differs in byte length (`İ`).
2. **GLOBAL built-ins** (pure compute, no ML): email, phone-like digit runs, ID shapes
   (`AB1234`/`PROJ2026`/`S-2026-014`), the **`Name` HEURISTIC** (below), **credit-card** (Luhn),
   **IBAN** (mod-97), **IPv4/IPv6**, **URL**, and the **structured `Address`** family (number+
   street+suffix `50 Raffles Place` / floor-unit `#16-03`, `Level 12` / PO-Box — CAREFUL-review
   tier, never quick-confirm; FREE-TEXT/prose addresses stay a reviewer gap) — a
   `BuiltinRecognizers` toggle per recognizer (default all-on). Checksum recognizers use an
   optional `validate` predicate so a broad pattern stays precise without a miss (a real card/IBAN
   always passes; a checksum miss DOWNGRADES, never silently drops). Jurisdiction national-IDs +
   **POSTAL codes** are **opt-in `Locale` packs** (off by default; SG NRIC/FIN + `sg:postal` =
   `.locales([Locale::Singapore])`; also `uk:postcode`/`us:zip`/`ca:postal`/`au:postcode`), and
   **role-context person names** in a labelled list (`ctx:role-name`, `Directors\nLee Wai Keong…`)
   are an opt-in **context** recognizer — see `RECOGNIZER-PACKS-SPEC.md`.
3. **Firm-defined recognizers ("super find & replace")** — ADDED to the presets, below.

## The `Name` recognizer is a HEURISTIC, not name detection (read this)

Two forms only: **title-prefixed** (default) — an honorific (`Mr Mrs Ms Mdm Miss Dr Prof
Professor Justice Judge Hon Messrs`, optional `.`) + Capitalized words, Unicode-aware
(`\p{Lu}`/`\p{L}`) so accented/multi-word Asian names are caught; and **any capitalized
multi-word run** (OPT-IN, OFF by default, `.aggressive()`) — off because it flags every
sentence-initial pair / place / company / heading, unreadable unless a human triages hard.

It MISSES names with no title and no capitalization (`met john at the office`, an all-lowercase
signature). Claiming this heuristic "detects names" as a deterministic guarantee is **forbidden**
— the claim is "flags title-prefixed (and optionally capitalized-run) name forms," nothing
stronger. Real NER is a statistical MODEL → the later `compute.model` tier.

## Firm-defined recognizers ("super find & replace")

`RedactionEngine::builder().terms(..).recognizers(..).classes(..).build()` (`classes` defaults
`document`+`party`). Each `UserRecognizer`: `label` (the recognizer NAME, shown in the audit
breakdown — config, never a matched value); `pattern`+`mode` (`Literal` escapes, the safe default
for a non-technical user; `Regex` is raw, e.g. `M-\d{4}`); `case_sensitive` (default false);
`whole_word` (`\b(...)\b`, **Literal-only** — rejected for Regex fail-closed, since a `\b`
against a `\s`/`\W`-edged raw body would silently defeat the match); `replacement` (optional;
`None` → `[REDACTED]`). Two rules compiling to the SAME pattern dedupe (one compile/scan; a
matched span surfaces with ALL matching labels via `candidate.recognizers()`).

**`build()` is fallible**, never panics: a malformed `Regex` pattern returns
`CoreError::Backend(..)` and fails construction (fail-closed) rather than silently dropping the
rule (a dropped rule = a confidentiality risk). Arbitrary user regex is safe because `regex` is
**linear-time** (no backreferences → no ReDoS; even `(a+)+$` completes).

## Output: actual redactions (candidates), not just counts

`redact_matter` → `RedactionReport` whose per-doc `DocReport` carries
`candidates: Vec<RedactionCandidate>`: `start`/`end` (BYTE offsets in the **original** content,
on valid char boundaries → `original[start..end] == matched_value`), `matched_value`,
`recognizer` (`Term`/`Email`/`Phone`/`Id`/`Name`/`Address`/`Custom(label)`/`Locale(label)`/
`Context(label)`/…), `context` (±40-char snippet).
`identifiers_removed` is DERIVED (`== candidates.len()`).

**Single authoritative pass + deterministic overlap rule.** ONE pass collects candidates (correct
original byte spans) AND produces the redacted string, so returned candidates are EXACTLY what
was replaced. Overlapping/adjacent spans **merge into one** (no double-count, no surviving
fragment): sort by start asc / end desc / priority / label, sweep-merge any `next.start <=
acc.end`. The merged `recognizer` is the most-specific primary (priority `Custom > Term > Email >
Id > Phone > Name` — a firm rule is an explicit decision so it wins), ties by earliest start.

**Replacement on merge:** a lone firm-recognizer span with `replacement: Some(s)` writes `s`;
when **≥2 raw matches merge** the replacement falls back to `[REDACTED]` (combining different
replacements over one union span is ambiguous — the marker is the unambiguous safe fallback).

### Confidentiality split: cleartext candidates vs audit (load-bearing)

The candidate list carries cleartext (`matched_value`, `context`), returned **in-process** for
review, **never egressed** (`egress: []`). The **audit note is different**: it records **count +
per-recognizer breakdown** (`term=1, email=1, party-name=2`) + per-tier counts (LEVER2 §5) —
**NEVER the matched-value strings** — so the tamper-evident chain never becomes a cleartext store
of the identifiers it redacted. Breakdown order: built-ins first, then custom labels sorted;
locale rows namespaced `locale:<label>` (injective vs `custom:`). The per-doc audit count is "N
redactions applied" (merged spans written) — NOT distinct source identifiers (overlaps merge).

## Workflow: scan → review → apply (the Tier-1/Tier-2 path)

- `scan_matter` detects + audits a SCAN, writes NOTHING, needs only `matter.read` (NOT
  `document.transform`); annotates each candidate with a `Confidence` tier (Low/Medium/High,
  deterministic, no clock).
- Reviewer builds a `Selection` (span COORDINATES only, no cleartext); `apply_selection` commits
  ONLY accepted spans, skipping `stale` ones. `redact_matter` is the one-shot apply-all.

**Two-tier review routing (the confidence tier, made LOAD-BEARING).** A `ReviewPolicy`
(quick-confirm **floor**, default `High`) routes each candidate: **Tier 1 `QuickConfirm`** —
checksum IDs, structural shapes + a class keyword, context matches with a CLOSE keyword;
`Selection::quick_confirm(&scan,&policy)` pre-accepts these (bulk-confirm / spot-reject). **Tier
2 `CarefulReview`** — the rest (Medium/Low); reviewer opts each in via `Selection::accept`.
`ReviewSummary::of(&scan,&policy)` is the cleartext-FREE per-doc split ("*N to confirm, M to
review*"), the graduated middle between `Selection::all` and `::none`. This made the High tier's
precision operationally load-bearing → the `Close` proximity rung tightened to a **strict
≤20-byte gap**, so a same-line-but-far keyword routes to careful review, not auto-accept. See
`LEVER2-CONTEXT-CONFIDENCE.md` §4+§9.

## Host wiring — `redact-cli` + the Python review UI

The engine reaches the user through the **`redact-cli`** bin (thin subprocess/JSON boundary,
same pattern as `viewgen` — no Rust HTTP server, no `pyo3`). Python owns the UI (`/redaction`,
`app/ui/redaction.*`, `app/redactionmodel.py`) over stdin/stdout (`firmos.redaction/0`):
- **`scan`** → tiered candidates + a `summary` (Tier-1 pre-checked vs Tier-2).
- **`apply`** (`accept:[[start,end],…]`) → text with ONLY accepted spans redacted (the pure,
  Core-free `RedactionEngine::redact_with_selection`).
- **`extract_scan`** (`filename`/`data_b64`) → a non-PDF FILE through `extract`
  (`.eml`/`.msg`/`.docx`/`.pdf`; headers incl. **Bcc**; UTF-8 fallback) → then scanned.
- **`pdf_scan`/`pdf_apply`** → FORMAT-PRESERVING PDF via `redaction::redact_pdf` (TRUE in-PDF
  byte removal): `pdf_scan` → candidates + `redactions` + `low_text` + `diagnostics`;
  `pdf_apply` → redacted bytes (`pdf_b64`), honoring an optional `accept_ids` (per-span, via the
  `PdfCandidateId`/`PdfSelection` primitive; apply-all otherwise). Host writes bytes to its
  exports dir + reveals them (the bin holds no filesystem capability).

Matter text/file bytes are **stdin only, never argv** (`ps`-visible); binary travels as base64.
The bin holds NO Core/audit/egress/filesystem, logs nothing but a generic error, is
deterministic. PDF redaction **only removes the text layer** — a scanned/image PDF is flagged
`low_text` rather than implied clean. The audited-`Core` path (routing this bin's calls through
`Core::scan_matter_pdf`/`redact_matter_pdf`) is the documented follow-up.

## Capabilities (declared in `module.json`)
`matter.read:document`, `matter.read:party` (the classes it strips); `document.transform`
(rewrite in place, through the core); `audit.note` (per-document match counts, ungated);
`egress: []` — **no egress**; an egress attempt with this grant set is refused by the core
(proven in tests).

## Trust + determinism
First-party trust tier (spec §5.3): may run native, still scoped + audited. Fully deterministic
(same input → identical output), no model/LLM, no Python, no network (CLAUDE.md non-negotiables).
