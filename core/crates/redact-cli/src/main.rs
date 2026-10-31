// SPDX-License-Identifier: AGPL-3.0-or-later
//! # `redact-cli` — the host-wiring JSON CLI for the redaction module.
//!
//! The SAME thin subprocess/JSON boundary as `viewgen`: the Python shell owns the
//! two-tier review UI and drives this bin, which runs the deterministic
//! [`redaction`] engine. It is the Rust side of the seam that makes the redaction
//! engine reachable from the UI without a Rust HTTP server or `pyo3`.
//!
//! ## Why stdin (not argv)
//!
//! The host hands the matter text on **STDIN**, never as a command-line argument:
//! process arguments are visible to other users via `ps`/Task Manager, so passing
//! cleartext matter data there would leak it. The response goes to **STDOUT** as JSON.
//! This bin logs NOTHING to stderr beyond a generic, value-free diagnostic on failure,
//! mirroring the engine's confidentiality discipline (never log a matched value).
//!
//! ## Contract — `firmos.redaction/0`
//!
//! Request (one JSON object on stdin):
//! ```json
//! { "op": "scan",  "text": "<document text>" }
//! { "op": "apply", "text": "<document text>", "accept": [[start,end], ...],
//!   "replacement_style": "redacted" | "labels" }   // default/absent = "redacted"
//! { "op": "extract_scan", "filename": "report.pdf", "data_b64": "<base64 file bytes>" }
//! { "op": "pdf_scan",  "data_b64": "<base64 PDF bytes>" }
//! { "op": "pdf_apply", "data_b64": "<base64 PDF bytes>", "accept_ids": [id, ...] }
//! // verify — POST-REDACTION verification probes over a redacted OUTPUT: the host
//! // hands the redacted text OR pdf (never both), the accepted cleartext values,
//! // and optionally the artifact kind ("text"/"pdf"; absent = inferred from which
//! // payload field is present). Bounded: <=1000 values, each 1..=1024 bytes after
//! // trim (an empty value would match vacuously — refused, never probed as "clean").
//! { "op": "verify", "text": "<redacted text>",  "values": ["S1234567D", ...] }
//! { "op": "verify", "pdf_b64": "<base64 redacted PDF>", "values": [...], "kind": "pdf" }
//! ```
//!
//! Every request MAY ALSO carry the OPT-IN recognizer-pack options (absent = today's
//! built-ins-only behavior, byte-identical):
//! ```json
//! { "op": "scan", "text": "...",
//!   "locales": ["sg","us","uk","au","ca"],   // jurisdiction national-ID packs
//!   "profiles": ["pci-dss-cardholder"],      // compliance profiles (only PCI exists)
//!   "context": true,                         // the context-required recognizers (DOB,
//!                                            // undashed SSN/account near keywords)
//!   "lei": true,                             // OPT-IN ISO 17442 LEI recognizer (OFF by
//!                                            // default — a public LEI is borderline PII,
//!                                            // so flagging it is a user decision)
//!   "sg_nric_loose": true,                   // OPT-IN aggressive SG-NRIC loose net (OFF by
//!                                            // default): two `aggressive` SG rows
//!                                            // (sg:nric-loose / sg:nric-context) whose hits
//!                                            // are ADVISORY (advisory:true, default-OFF in
//!                                            // apply). A real NRIC is still precise+default-on.
//!   "name_expansion": true,                  // OPT-IN name-propagation EXPANSION tier (OFF
//!                                            // by default): a detected name token (e.g.
//!                                            // `Greco`, from `Mr Greco`) pulls in any
//!                                            // Capitalized run containing it (`Massimo
//!                                            // Greco`). The SAFE tier (exact re-occurrences
//!                                            // of a detected full name) is ALWAYS on.
//!   "terms": ["Massimo Greco","A.B (Pte)"],  // OPT-IN user-supplied terms ("super find &
//!                                            // replace"): KNOWN party/director/company names
//!                                            // + matter numbers no recognizer auto-detects,
//!                                            // matched as escaped literals (case-insensitive,
//!                                            // metacharacters literal). Bounded: <=1000
//!                                            // terms, <=200 bytes each; empty dropped.
//!   "disable_builtins": ["id"] }             // GLOBAL built-ins to turn OFF (recall-
//!                                            // reducing; absent = all on, the default)
//! ```
//! The options are parsed via an ALLOWLIST — an unknown locale/profile label is IGNORED
//! (never an error, never a panic), so a forward-compatible host can send labels this
//! binary does not know yet. The engine is built ONCE per request from these options and
//! used for EVERY op, so an `apply` always re-detects with the SAME config as the `scan`
//! that produced its spans (else the offsets/recognizers diverge — a redaction hazard).
//! The resulting `recognizer` field then carries the namespaced labels (`sg:nric`,
//! `sg:uen`, `us:ssn`, `ctx:dob`, …) — all already cleartext-free.
//! Response (one JSON object on stdout):
//! ```json
//! // scan
//! { "schema":"firmos.redaction/0", "op":"scan",
//!   "candidates":[ { "start":N,"end":N,"value":"...","context":"...",
//!                    "recognizer":"email","confidence":"high","tier":"quick-confirm",
//!                    "advisory":false } ],   // advisory:true iff the PRIMARY recognizer is an
//!                                            // aggressive locale row (default-OFF in apply)
//!   "summary":{ "quick_confirm":N,"careful_review":N,"total":N,"floor":"high" } }
//! // apply (default style "redacted": every removed span -> the "[REDACTED]" marker)
//! { "schema":"firmos.redaction/0", "op":"apply", "redacted":"...", "applied":N, "stale":N }
//! // apply (style "labels": AI-safe pseudonymization — each DISTINCT removed entity gets a
//! //   STABLE, DISTINCT placeholder + a LOCAL legend the host keeps to re-identify. TEXT
//! //   path only — pdf_apply is unchanged.) ENTITY family (user terms + the Name heuristic)
//! //   -> letters [A],[B],…,[Z],[AA],…; TYPED family -> [email],[phone],[Singapore ID],…
//! //   numbered per-type ONLY when >=2 distinct values of that type ([email 1],[email 2]).
//! { "schema":"firmos.redaction/0", "op":"apply", "redacted":"...", "applied":N, "stale":N,
//!   "legend":[ { "label":"[A]", "value":"Jefferson Tan", "count":3 },
//!              { "label":"[email]", "value":"jane@acme.example", "count":1 } ] }
//! // extract_scan (extract a FILE -> text, then scan it)
//! { "schema":"firmos.redaction/0", "op":"extract_scan", "format":"pdf",
//!   "text":"<extracted text the host echoes back on apply>", "warnings":["..."],
//!   "candidates":[ ... ], "summary":{ ... } }
//! // pdf_scan (PER-SPAN review: each candidate carries a stable id + 1-based page)
//! { "schema":"firmos.redaction/0", "op":"pdf_scan",
//!   "candidates":[ { "id":N,"page":N,"value":"...","context":"...",
//!                    "recognizer":"email","confidence":"high","tier":"quick-confirm" } ],
//!   "summary":{ ... }, "low_text":false, "diagnostics":["..."] }
//! // pdf_apply (removes ONLY the accepted ids; true byte removal)
//! // `could_not_remove`: accepted spans that could NOT be truly removed (no resolvable
//! // source bytes) — NOT counted in `redactions`; when > 0 the host MUST warn (manual
//! // review needed) and never present a clean count as fully redacted.
//! { "schema":"firmos.redaction/0", "op":"pdf_apply", "pdf_b64":"...",
//!   "redactions":N, "could_not_remove":0, "low_text":false, "diagnostics":["..."] }
//! // verify — its OWN stable schema string, `firmos.verify/0` (the client-attachable
//! // VERIFICATION REPORT data plane; the app renders wording, this op returns FACTS).
//! // HONESTY IS STRUCTURAL: results are VALUE-FREE (`value_index` into the request
//! // list — class/count/pages only, NEVER the matched cleartext, so the response can
//! // feed a client-facing report without re-disclosing the redacted identifiers);
//! // field names are residual-shaped (`residual_found`, never "passed"/"clean"/
//! // "safe"); `not_probed` enumerates the vector ids this op structurally does NOT
//! // probe (v1: the image/pixel layer, unsupported-filter streams, attachment
//! // container content); and `limitations` is ALWAYS populated with STABLE FLAG KEYS
//! // (the app owns human wording). `artifact_sha256` binds the report to the exact
//! // bytes probed. Apply-time page knowledge (could_not_remove pages, unmapped-font
//! // ranges, OCR confidence) is NOT recoverable from the output alone — a report
//! // wanting those must carry them from the pdf_apply/apply response, not this op.
//! { "schema":"firmos.verify/0", "op":"verify", "kind":"text"|"pdf",
//!   "engine_version":"<redaction crate version>",
//!   "artifact_sha256":"<hex sha-256 of the probed bytes>",
//!   "vectors":["pdf_text_strict","pdf_text_lenient","pdf_raw_bytes","pdf_streams",
//!              "pdf_annotations","pdf_metadata"],       // or the text_* four
//!   "results":[ { "value_index":0, "residual_found":true,
//!                 "probes":[ { "vector":"pdf_annotations", "residual_found":true,
//!                              "matches":2, "mode":"raw", "pages":[3] }, ... ] } ],
//!   "values_probed":N, "total_residual_findings":N, "values_with_residuals":N,
//!   "flags":{ "low_text":false, "unmapped_fonts":false, "degenerate_layout":false },
//!   "not_probed":["image_pixel_content","unsupported_filter_streams",
//!                 "attachment_container_content"],      // [] for kind "text"
//!   "limitations":["supplied_values_scope_only","no_finding_is_not_removal_proof",
//!                  "undetected_values_not_covered", ...pdf keys],  // ALWAYS non-empty
//!   "diagnostics":["<content-free skip/budget notes>"] }
//! // error (also: process exits non-zero)
//! { "schema":"firmos.redaction/0", "error":"<reason, never matter text>" }
//! ```
//!
//! `start`/`end` are BYTE offsets into the request `text` (char boundaries), exactly as
//! reported on a [`redaction::RedactionCandidate`]; an `apply` accept-set is those
//! coordinates echoed back. A `pdf_scan` candidate's `id` is a stable
//! [`redaction::PdfCandidateId`] (its ordinal in the deterministic detection traversal);
//! echo the accepted ids back in `pdf_apply.accept_ids` to remove ONLY those. Apply is
//! deterministic over the SAME PDF bytes + engine config, so the ids align (the host must
//! send the SAME bytes to `pdf_apply` it scanned). For `extract_scan` the host hands the FILE bytes as base64
//! inside the JSON (the stdin boundary is text); the bin runs the deterministic
//! [`extract`] engine (`.eml`/`.docx`/`.pdf`, plus a UTF-8 plain-text fallback for other
//! extensions), then scans the extracted text and RETURNS it so the host can review and
//! `apply` over the SAME text. `value`/`context`/`text` are CLEARTEXT for the in-process
//! review — they travel only the local parent→child pipe, never the network.
//!
//! ## Engine config + determinism
//!
//! The engine runs the GLOBAL built-in recognizers (email/phone/id/name/credit-card/
//! IBAN/IP/URL) — each ON unless named in `disable_builtins` — and on top of those enables
//! the OPT-IN locale / profile / context packs the request names (see the contract above),
//! plus the OPT-IN ISO 17442 LEI recognizer when `"lei": true` (OFF by default — a public
//! LEI is borderline PII, so flagging it is a deliberate user decision, NOT a global
//! built-in). A compliance profile's required built-ins are OR-merged AFTER the disables, so
//! a profile guarantee can never be silently turned off by `disable_builtins`. The
//! name-propagation pass always runs (the SAFE tier — exact re-occurrences of a detected
//! full name); its broader EXPANSION tier is enabled only when `"name_expansion": true` (OFF
//! by default). With NO options the engine is byte-identical to [`RedactionEngine::new`]
//! (all built-ins on, no LEI, no expansion) — the historical default. The two-tier routing
//! uses the default [`ReviewPolicy`] (quick-confirm floor = `High`). Detection + extraction
//! are deterministic (no clock, no RNG, no network): the same input + the same options
//! yields the same output.

use std::collections::HashSet;
use std::io::Read as _;

use base64::Engine as _;
use redaction::{
    BuiltinRecognizers, Confidence, ContextRecognizers, Locale, PdfCandidateId, PdfSelection,
    Profile, RedactionEngine, ReviewPolicy, ReviewTier,
};
use serde::{Deserialize, Serialize};

/// The contract schema string the host validates before rendering.
const SCHEMA: &str = "firmos.redaction/0";

/// Hard cap on the stdin payload (the whole JSON envelope, text/base64 included). The
/// engine is linear-time so a large input is merely slow — the host also bounds it with a
/// timeout — but a cap keeps peak memory bounded regardless. 16 MiB is far beyond any
/// paste-in / single document this tool targets (a base64 file fits a ~12 MiB document).
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Cap on the number of USER-SUPPLIED TERMS ("super find & replace") accepted in one
/// request. Far beyond any realistic party/director list for a single matter; bounds the
/// combined regex program the engine compiles (the engine itself degrades gracefully past
/// its own internal `RegexSet` size limit, but this keeps the request sane). Excess terms
/// past the cap are DROPPED (the kept prefix still redacts — never an error/panic).
const MAX_TERMS: usize = 1000;

/// Cap on the BYTE length of a single user-supplied term. A name / matter number / deal
/// codename is short; a longer "term" is almost certainly a paste mistake. A term over the
/// cap is DROPPED (not truncated — a truncated literal could match an unintended substring).
const MAX_TERM_BYTES: usize = 200;

/// The request envelope (one JSON object on stdin).
#[derive(Deserialize)]
struct Request {
    /// `"scan"`, `"apply"`, or `"extract_scan"`.
    op: String,
    /// The document text to scan / redact (`scan` / `apply`).
    #[serde(default)]
    text: String,
    /// For `apply`: the reviewer's accepted spans as `[start, end]` byte coordinates
    /// (absent / empty otherwise).
    #[serde(default)]
    accept: Vec<[usize; 2]>,
    /// For `pdf_apply`: the reviewer's accepted PDF candidate ids (the stable `id`s from
    /// `pdf_scan`). Absent/empty removes nothing (default-deny). These are the raw
    /// ordinals of a [`PdfCandidateId`]; the engine config + bytes MUST match the scan.
    #[serde(default)]
    accept_ids: Vec<u64>,
    /// For `apply`: the replacement TOKEN style — `"redacted"` (default/absent: every
    /// removed span → the `[REDACTED]` marker, byte-identical to today) or `"labels"`
    /// (AI-safe pseudonymization — each DISTINCT removed entity → a stable, distinct
    /// placeholder `[A]`/`[email 1]`/…, and the response ALSO carries a `legend`). An
    /// unknown / misspelt style maps to `"redacted"` (never an error — fail to the safe,
    /// byte-identical default). Ignored by every non-`apply` op. SCOPE: TEXT path only —
    /// `pdf_apply` is UNCHANGED (variable-length labels would break its byte-splice; PDF
    /// pseudonymization is an explicit follow-up).
    #[serde(default)]
    replacement_style: String,
    /// For `extract_scan`: the original filename (used ONLY to pick the extractor by
    /// extension — never opened).
    #[serde(default)]
    filename: String,
    /// For `extract_scan`: the file's raw bytes, base64-encoded (the stdin boundary is
    /// JSON/text, so binary arrives base64).
    #[serde(default)]
    data_b64: String,
    /// OPT-IN jurisdiction packs to enable (e.g. `["sg","us"]`). Each label is matched
    /// against the [`Locale`] ALLOWLIST ([`parse_locale`]); an unknown label is IGNORED
    /// (never an error). Absent/empty = no locale packs (today's behavior).
    #[serde(default)]
    locales: Vec<String>,
    /// OPT-IN compliance profiles to enable (e.g. `["pci-dss-cardholder"]`). Matched
    /// against the [`Profile`] ALLOWLIST ([`parse_profile`]); an unknown label is
    /// IGNORED. Absent/empty = no profiles (today's behavior).
    #[serde(default)]
    profiles: Vec<String>,
    /// OPT-IN: enable ALL the context-required recognizers (undashed SSN / DOB / age /
    /// account-MRN, each keyword-gated). `false`/absent = off (today's behavior).
    #[serde(default)]
    context: bool,
    /// OPT-IN: enable the ISO 17442 Legal Entity Identifier recognizer
    /// ([`Recognizer::Lei`]). `false`/absent = OFF (today's behavior, byte-identical).
    /// A public LEI is borderline PII, so flagging it is a deliberate USER DECISION, NOT
    /// a global built-in — it stays off even when every built-in is on. When `true`, a
    /// 20-char `[A-Z0-9]{18}[0-9]{2}` token that PASSES the ISO 7064 mod-97-10 check is
    /// flagged (the checksum keeps the broad pattern precise — no miss, like card/IBAN).
    #[serde(default)]
    lei: bool,
    /// OPT-IN: enable the AGGRESSIVE SG-NRIC "loose net" — two extra `aggressive` SG rows
    /// (`sg:nric-loose` = any-letter / 6–8-digit / optionally space-or-dash-separated
    /// NRIC-shaped tokens; `sg:nric-context` = a bare 7–9-digit run keyword-gated on an
    /// NRIC/FIN/IC label). `false`/absent = OFF (today's behavior, byte-identical SG output).
    /// Plumbed exactly like `lei`. Because both rows are `aggressive`, their candidates are
    /// surfaced as ADVISORY (`advisory:true` on the DTO) — DEFAULT-OFF in the apply
    /// accept-set; the human opts in. They are DEMOTED below the precise `sg:nric` row, so a
    /// REAL `S1234567D` is still attributed to `sg:nric` (default-ON, `advisory:false`).
    #[serde(default)]
    sg_nric_loose: bool,
    /// OPT-IN: enable the name-propagation EXPANSION tier
    /// ([`RedactionEngineBuilder::name_expansion`]). `false`/absent = OFF (today's behavior,
    /// byte-identical where nothing propagates). When `true`, an already-detected name TOKEN
    /// (e.g. `Greco`, recovered from a `Mr Greco` match) pulls in any Capitalized multi-word
    /// run that contains it as a whole word — so a board director listed with NO honorific
    /// (`Massimo Greco`, `Peter Thomas Schwicht`) is redacted from a single titled mention
    /// elsewhere. The SAFE tier (exact re-occurrences of a detected FULL name) is ALWAYS on
    /// independent of this flag; this opt-in adds only the broader, slightly-higher-FP
    /// expansion (it can pull in a capitalized run that merely shares a surname).
    #[serde(default)]
    name_expansion: bool,
    /// OPT-IN: enable ORGANISATION-name detection ([`RedactionEngineBuilder::organisations`]).
    /// `false`/absent = OFF (today's behavior, byte-identical). When `true`, a dedicated
    /// deterministic pass flags company / organisation names via a SUFFIX-ANCHORED arm
    /// (`… Pte Ltd`/`… LLP`/`… S.A.`) AND a BROAD ORG-CONTEXT arm (a Capitalized run near a cue
    /// like `incorporated in`/`trustee`/`registrar`). They form their OWN `ctx:org` recognizer
    /// class — CAREFUL-review only (never auto-accepted) and EXCLUDED from every person-name
    /// propagation seed — rendering as an ENTITY placeholder (`[A]`) in labels mode. Broad by
    /// design (fund / index names WILL flag — the ratified choice; a keep-list is the mitigation).
    #[serde(default)]
    organisations: bool,
    /// OPT-IN: enable the BROADENED ADDRESS recognizers
    /// ([`RedactionEngineBuilder::addresses_full`]). `false`/absent = OFF (today's behavior,
    /// byte-identical). When `true`, three extra `address` rows are added — foreign-format
    /// streets (`2, place Winston Churchill`, `19 rue de Bitbourg`), building/premises names
    /// (`Chater House`, `South Beach Tower`), and the Luxembourg postal shape (`L-1855`) — all
    /// riding the existing `address` family (careful review). DEFAULT address rows are unchanged.
    #[serde(default)]
    addresses_full: bool,
    /// OPT-IN: the NAMES of GLOBAL built-in recognizers to turn OFF for this request
    /// (e.g. `["id"]` to silence the broad id recognizer on a code-heavy doc). Each label
    /// is matched against the [`apply_builtin_disable`] ALLOWLIST (the [`Recognizer::label`]
    /// spellings: `email`/`phone`/`id`/`name`/`credit-card`/`iban`/`ip`/`url`); an unknown
    /// label is IGNORED (never an error, never a panic). Absent/empty = ALL built-ins on
    /// (byte-identical to the recall-first default).
    ///
    /// HONESTY: disabling a built-in REDUCES recall — that is the caller's deliberate
    /// choice. A compliance [`Profile`]'s `required_builtins` STILL win (they are OR-merged
    /// AFTER these disables inside the engine builder), so a profile guarantee can never be
    /// silently defeated by a disable.
    #[serde(default)]
    disable_builtins: Vec<String>,
    /// OPT-IN: USER-SUPPLIED TERMS to redact ("super find & replace") — the KNOWN
    /// party / director / company names and matter numbers no recognizer can auto-detect
    /// (a honorific-less full name like `Massimo Greco`, a deal codename). Each term is
    /// matched case-insensitively as an ESCAPED LITERAL by the engine
    /// ([`RedactionEngine::builder().terms`]) — regex metacharacters (`A.B (Pte)`) are
    /// escaped, so a name is matched verbatim, never interpreted as a pattern. Absent/empty
    /// = no terms (today's behavior, byte-identical). BOUNDED ([`sanitize_terms`]): at most
    /// [`MAX_TERMS`] terms, each at most [`MAX_TERM_BYTES`] bytes; empty / whitespace-only
    /// terms are dropped. The SAME sanitized terms are built into the engine for EVERY op,
    /// so a `scan` and its matching `apply` detect identically (no span drift). A matched
    /// term carries the `term` recognizer label (a CONFIG string — a recognizer name, never
    /// a matched value).
    #[serde(default)]
    terms: Vec<String>,
    /// For `verify`: the accepted (removed) cleartext VALUES to probe the redacted
    /// output for. Cleartext matter data — travels only the local pipe; the RESPONSE
    /// identifies each value by INDEX into this list, never by echoing it. Bounded
    /// ([`MAX_VERIFY_VALUES`] / [`MAX_VERIFY_VALUE_BYTES`]); an empty/whitespace-only
    /// value is REFUSED (it would match vacuously — a fake "residual everywhere" or,
    /// worse, a fake probe of nothing).
    #[serde(default)]
    values: Vec<String>,
    /// For `verify`: the redacted PDF bytes, base64 (the `text` field carries a
    /// redacted TEXT output instead — exactly one of the two).
    #[serde(default)]
    pdf_b64: String,
    /// For `verify`: optional artifact kind, `"text"` or `"pdf"`. Absent = inferred
    /// from which payload field is present. A kind that CONTRADICTS the payload is an
    /// error (never a silent guess — this op feeds a client-attachable report).
    #[serde(default)]
    kind: String,
}

#[derive(Serialize)]
struct CandidateOut {
    start: usize,
    end: usize,
    value: String,
    context: String,
    recognizer: String,
    confidence: &'static str,
    tier: &'static str,
    /// TRUE iff this candidate's PRIMARY recognizer is an AGGRESSIVE locale row (a broad,
    /// format-only "last-resort" shape: driver's licence / passport / generic account /
    /// BSB / transit / sort code, and the opt-in loose SG-NRIC net) — driven off the
    /// engine's `is_aggressive` (the SAME `aggressive_locales` set the merge demotion uses).
    /// ADVISORY: an advisory candidate is SURFACED for review but DEFAULT-OFF in the apply
    /// accept-set — the human opts IN to redact it. A PRECISE recognizer (email/phone/
    /// checksummed card/IBAN/IP/URL/name heuristic, `sg:nric`/`sg:uen`, every non-aggressive
    /// locale row) is `false` → default-ON / auto-redacted, exactly as today.
    advisory: bool,
}

#[derive(Serialize)]
struct SummaryOut {
    quick_confirm: usize,
    careful_review: usize,
    total: usize,
    floor: &'static str,
}

#[derive(Serialize)]
struct ScanOut {
    schema: &'static str,
    op: &'static str,
    candidates: Vec<CandidateOut>,
    summary: SummaryOut,
}

/// One LEGEND row for the AI-safe-labels apply: `{ label, value, count }`. The `value` is
/// CLEARTEXT (the first-seen surface form the placeholder stands for) — it travels only the
/// local parent→child pipe for the in-process review, exactly like a candidate `value`, and
/// is NEVER logged or audited.
#[derive(Serialize)]
struct LegendEntryOut {
    /// The placeholder as written into the text, e.g. `[A]` or `[email 2]`.
    label: String,
    /// The first-seen surface form of the value the placeholder stands for (cleartext).
    value: String,
    /// How many occurrences this placeholder replaced (>= 1).
    count: usize,
}

#[derive(Serialize)]
struct ApplyOut {
    schema: &'static str,
    op: &'static str,
    redacted: String,
    applied: usize,
    stale: usize,
    /// AI-safe-labels mode ONLY: the label → value legend in deterministic order (entities
    /// by letter, then types). OMITTED entirely in the default `"redacted"` style (so that
    /// response is byte-identical to today). `skip_serializing_if` keeps a `redacted`-style
    /// apply free of an empty `legend` key.
    #[serde(skip_serializing_if = "Option::is_none")]
    legend: Option<Vec<LegendEntryOut>>,
}

#[derive(Serialize)]
struct ExtractScanOut {
    schema: &'static str,
    op: &'static str,
    /// The detected format: `eml` / `docx` / `pdf`, or `text` for the UTF-8 fallback.
    format: &'static str,
    /// The extracted text — the host echoes it back on `apply` (apply works on text).
    text: String,
    /// Non-fatal extraction warnings (leak vectors, "scanned PDF — no text layer",
    /// fallbacks). Surfaced so the user knows what extraction did / could not do.
    warnings: Vec<String>,
    candidates: Vec<CandidateOut>,
    summary: SummaryOut,
}

/// A PDF candidate for PER-SPAN review (v2): a stable [`PdfCandidateId`] `id` + 1-based
/// `page` + the cleartext review fields. The host shows these, the reviewer accepts/rejects
/// individual ones, and echoes the accepted `id`s back in `pdf_apply.accept_ids` to remove
/// ONLY those. `id` is stable across the scan/apply pair for the SAME bytes + engine.
#[derive(Serialize)]
struct PdfCandidateOut {
    /// The stable PdfCandidateId ordinal — echo back in `pdf_apply.accept_ids`.
    id: u64,
    /// 1-based page the candidate sits on (for grouping/display).
    page: u32,
    value: String,
    context: String,
    recognizer: String,
    confidence: &'static str,
    tier: &'static str,
    /// TRUE iff this candidate's PRIMARY recognizer is an AGGRESSIVE locale row (see
    /// [`CandidateOut::advisory`]). ADVISORY: the per-span PDF review renders it UNCHECKED
    /// by default (the host does NOT pre-accept its id); a precise candidate stays
    /// default-checked. Driven off the engine's `is_aggressive`.
    advisory: bool,
}

#[derive(Serialize)]
struct PdfScanOut {
    schema: &'static str,
    op: &'static str,
    /// Every detected candidate with its stable id (the per-span review list).
    candidates: Vec<PdfCandidateOut>,
    summary: SummaryOut,
    /// TRUE when the PDF has little/no extractable text (e.g. a scanned / image-only
    /// PDF) — text redaction CANNOT remove identifiers baked into images. Load-bearing
    /// honesty: the host must warn rather than imply the PDF was cleaned.
    low_text: bool,
    /// TRUE when one or more pages used a font whose encoding could NOT be exactly
    /// mapped (a Type0/CID/multi-byte or unknown-name font). Those pages were decoded
    /// only best-effort, so detection coverage was incomplete — a zero/low candidate
    /// count must NOT be read as "this page is clean". DISTINCT from `low_text`
    /// (image-only): this signals incomplete TEXT analysis. Load-bearing honesty: the
    /// host must surface it so the user is never told a PDF was fully analyzed when a
    /// page wasn't. `#[serde(default)]` keeps an older host that omits it deserializing
    /// to `false` (backward-compatible).
    #[serde(default)]
    unmapped_fonts: bool,
    /// TRUE when one or more pages have a DEGENERATE spaceless text layout (an
    /// implausibly long alphabetic run with no word boundary): recognizers may be blind
    /// on those pages even though every font decoded cleanly — `unmapped_fonts` gives NO
    /// signal for this class. A zero/low candidate count there must NOT be read as
    /// "clean". Same load-bearing honesty posture (and the same backward-compatible
    /// `#[serde(default)]`) as `unmapped_fonts`.
    #[serde(default)]
    degenerate_layout: bool,
    /// Content-free per-stream diagnostics (skipped/undecodable streams, budget cut-offs).
    diagnostics: Vec<String>,
}

#[derive(Serialize)]
struct PdfApplyOut {
    schema: &'static str,
    op: &'static str,
    /// The redacted PDF bytes, base64-encoded (the host writes them to disk + reveals).
    pdf_b64: String,
    redactions: usize,
    /// ACCEPTED spans that could NOT be truly removed (no resolvable source bytes). NOT
    /// included in `redactions`. The HONEST over-report guard: when > 0 the host MUST warn
    /// the user (manual review needed) — never present a clean count as "fully redacted".
    /// (Host/UI follow-up: surface this prominently in the redaction review page.)
    could_not_remove: usize,
    low_text: bool,
    diagnostics: Vec<String>,
    /// The document-structure CATEGORIES this apply pass actually removed matching content
    /// from, derived from the removed candidates' recognizer labels (COUNTS/FLAGS ONLY — no
    /// matched value). Honest per-run visibility of what the byte-splice path cleaned: the
    /// document body / annotation text, the `/Info` information dictionary fields, and/or the
    /// XMP `/Metadata` stream. A category appears ONLY when at least one field of that kind
    /// was actually scrubbed on THIS document — so an empty list means nothing of that kind
    /// was found + removed, never a claim of coverage. See [`cleaned_categories`].
    cleaned: Vec<String>,
    /// Document-structure surfaces this FORMAT-PRESERVING path does NOT touch (a static,
    /// honest capability disclosure — these are never scrubbed by the byte-splice engine, so
    /// an identifier living ONLY here can survive). Surfaced so the host can tell the user
    /// what to review manually rather than implying a whole-file clean. NOT a per-run signal:
    /// it lists the engine's known structural gaps regardless of the document.
    not_removed: Vec<&'static str>,
}

/// Document-structure surfaces the format-preserving [`redaction::redact_pdf_with_selection`]
/// path does NOT scrub. Static + honest: these are never touched by the byte-splice engine
/// (confirmed against `redaction/src/pdf.rs` — the body, annotation, `/Info` and XMP passes
/// are all it runs), so an identifier that lives ONLY in one of these can survive a
/// "redacted" PDF. Surfaced verbatim to the host so the user is told to review them by hand
/// rather than being led to believe the whole file was cleaned. Extending the engine to these
/// (esp. embedded attachments) is a deliberate future increment, NOT risky ad-hoc surgery.
const PDF_NOT_REMOVED: &[&str] = &[
    "embedded file attachments",
    "text inside images / scanned pages",
    "form and image XObject streams",
    "named destinations",
];

/// Categorize removed candidates into the document-structure surfaces actually scrubbed on
/// THIS document — for honest, per-run "Cleaned: …" visibility in the host. COUNTS/FLAGS
/// ONLY: this reads recognizer LABELS (config strings), never a matched value. The metadata
/// passes attribute their removals to synthetic `metadata:*` recognizers (`metadata:xmp` for
/// the XMP stream, `metadata:<Key>` for an `/Info` field); every other label
/// (email/phone/sg:nric/url/…) is a body- or annotation-text removal. A category is emitted
/// ONLY when ≥1 field of that kind was removed, so the list can never over-claim (an absent
/// category == nothing of that kind found+removed, not "we skipped it").
fn categories_from_labels<'a>(labels: impl Iterator<Item = &'a str>) -> Vec<String> {
    let (mut has_body, mut has_info, mut has_xmp) = (false, false, false);
    for label in labels {
        if label == "metadata:xmp" {
            has_xmp = true;
        } else if label.starts_with("metadata:") {
            has_info = true;
        } else {
            has_body = true;
        }
    }
    let mut out = Vec::new();
    if has_body {
        out.push("document body and annotation text".to_string());
    }
    if has_info {
        out.push("document information fields (e.g. Author, Title)".to_string());
    }
    if has_xmp {
        out.push("XMP metadata".to_string());
    }
    out
}

/// The [`categories_from_labels`] view over a removed-candidate slice (maps each candidate to
/// its recognizer label). Allocates the label strings; the candidate count on an apply is
/// small (identifiers in one document), so this is cheap and keeps the categorizer pure +
/// unit-testable off plain `&str` labels.
fn cleaned_categories(candidates: &[redaction::RedactionCandidate]) -> Vec<String> {
    let labels: Vec<String> = candidates
        .iter()
        .map(|c| c.recognizer().to_string())
        .collect();
    categories_from_labels(labels.iter().map(String::as_str))
}

#[derive(Serialize)]
struct ErrorOut {
    schema: &'static str,
    error: String,
}

// ===========================================================================
// verify — the `firmos.verify/0` VERIFICATION REPORT data plane
// ===========================================================================

/// The verify response's OWN stable schema string (distinct from the redaction
/// contract): the client-attachable verification-report data plane. The renderer
/// validates this before citing anything.
const VERIFY_SCHEMA: &str = "firmos.verify/0";

/// Cap on the number of probe values in one `verify` request (far beyond any
/// single document's accepted redactions; bounds probe work). Over-cap is an
/// ERROR, not a silent drop — a verification op must never silently probe less
/// than it was asked to.
const MAX_VERIFY_VALUES: usize = 1000;

/// Cap on one probe value's byte length after trim. An accepted redaction value
/// is a short identifier/name/address; anything longer is a paste mistake.
/// Over-cap is an ERROR (same never-silently-probe-less reasoning).
const MAX_VERIFY_VALUE_BYTES: usize = 1024;

/// Limitation FLAG KEYS every `verify` response carries (STABLE ids — the app
/// owns the human wording; never rename, only append):
/// - `supplied_values_scope_only` — only the supplied values were probed;
/// - `no_finding_is_not_removal_proof` — an empty residual list means these
///   vectors did not recover the values, NOT that removal is guaranteed;
/// - `undetected_values_not_covered` — a value no recognizer/reviewer ever
///   detected was never in the list and carries no finding either way.
const VERIFY_LIMITATIONS_COMMON: &[&str] = &[
    "supplied_values_scope_only",
    "no_finding_is_not_removal_proof",
    "undetected_values_not_covered",
];

/// PDF-only limitation keys (appended after the common ones):
/// - `image_pixel_layer_not_probed` — text burned into scanned/rasterized pages
///   is invisible to every vector in v1;
/// - `unsupported_filter_streams_not_probed` — only raw + single-FlateDecode
///   streams are decompressed;
/// - `attachment_container_content_not_extracted` — embedded files are probed
///   only as bytes, not extracted.
const VERIFY_LIMITATIONS_PDF: &[&str] = &[
    "image_pixel_layer_not_probed",
    "unsupported_filter_streams_not_probed",
    "attachment_container_content_not_extracted",
];

/// One per-vector probe outcome (VALUE-FREE — see [`VerifyValueOut`]).
#[derive(Serialize)]
struct VerifyProbeOut {
    /// Stable vector id (`text_raw`/…/`pdf_metadata`).
    vector: &'static str,
    residual_found: bool,
    matches: usize,
    /// PDF surfaces only: the strictest text-ladder mode that hit. Omitted when
    /// not applicable (text vectors; the strict engine surface; no hit).
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
    /// 1-based pages the residual was recovered on where the output determines
    /// them (0 = the document-metadata surface). EMPTY means UNDETERMINED for
    /// vectors without page geometry — never "nowhere".
    pages: Vec<u32>,
}

/// All probes for ONE value, identified ONLY by `value_index` (the ordinal in
/// the request's `values` list). The matched cleartext NEVER appears in the
/// response — class/count/pages only — so the response can feed a client-facing
/// report without re-disclosing the redacted identifiers.
#[derive(Serialize)]
struct VerifyValueOut {
    value_index: usize,
    /// `true` iff ANY vector recovered this value.
    residual_found: bool,
    probes: Vec<VerifyProbeOut>,
}

/// The strict scan's honesty flags over the redacted OUTPUT (PDF only) — echoed
/// so a rendered report can never read "no residuals" over a document whose text
/// layer was not fully analyzable.
#[derive(Serialize)]
struct VerifyFlagsOut {
    low_text: bool,
    unmapped_fonts: bool,
    degenerate_layout: bool,
}

#[derive(Serialize)]
struct VerifyOut {
    schema: &'static str,
    op: &'static str,
    /// `"text"` or `"pdf"`.
    kind: &'static str,
    /// The redaction ENGINE version (citable lineage — distinct from any binary
    /// hash; `artifact_sha256` binds the probed bytes instead).
    engine_version: &'static str,
    /// Hex SHA-256 of the exact bytes probed (the decoded PDF bytes / the UTF-8
    /// text), so the report binds "what was probed" to "what was delivered".
    artifact_sha256: String,
    /// The vector ids probed, in `results[].probes` order.
    vectors: Vec<&'static str>,
    results: Vec<VerifyValueOut>,
    values_probed: usize,
    /// Probe entries with `residual_found` across all values/vectors.
    total_residual_findings: usize,
    values_with_residuals: usize,
    /// PDF only; omitted for text.
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<VerifyFlagsOut>,
    /// Vector-shaped ids of surfaces this op structurally does NOT probe (v1) —
    /// enumerated HERE so a renderer never hardcodes them. `[]` for text (the
    /// supplied text IS the whole artifact).
    not_probed: Vec<&'static str>,
    /// ALWAYS non-empty: stable limitation flag keys (see the consts above).
    limitations: Vec<&'static str>,
    /// Content-free skip/budget notes (never a probe value, never matter text).
    diagnostics: Vec<String>,
}

/// Map a library [`redaction::verify::ProbeOutcome`] to the wire DTO.
fn verify_probe_out(p: &redaction::verify::ProbeOutcome) -> VerifyProbeOut {
    VerifyProbeOut {
        vector: p.vector,
        residual_found: p.residual_found,
        matches: p.matches,
        mode: p.mode,
        pages: p.pages.clone(),
    }
}

/// Map the per-value library results to wire DTOs + the report tallies
/// `(results, total_residual_findings, values_with_residuals)`.
fn verify_results_out(
    results: &[redaction::verify::ValueVerification],
) -> (Vec<VerifyValueOut>, usize, usize) {
    let mut total = 0usize;
    let mut with_residuals = 0usize;
    let out = results
        .iter()
        .map(|r| {
            let probes: Vec<VerifyProbeOut> = r.probes.iter().map(verify_probe_out).collect();
            let found = r.residual_found();
            total += probes.iter().filter(|p| p.residual_found).count();
            if found {
                with_residuals += 1;
            }
            VerifyValueOut {
                value_index: r.value_index,
                residual_found: found,
                probes,
            }
        })
        .collect();
    (out, total, with_residuals)
}

/// Hex SHA-256 of `bytes` (binds the report to the exact artifact probed).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Validate + trim the request's probe values. ERRORS (never a silent drop /
/// truncation — a verification op must probe exactly what it was asked to, or
/// refuse): too many values, an empty/whitespace-only value, an over-length
/// value. Returns the trimmed values in request order (`value_index` order).
fn verify_values(raw: &[String]) -> Result<Vec<String>, String> {
    if raw.len() > MAX_VERIFY_VALUES {
        return Err(format!(
            "verify: too many values ({} > {MAX_VERIFY_VALUES})",
            raw.len()
        ));
    }
    let mut out = Vec::with_capacity(raw.len());
    for (i, v) in raw.iter().enumerate() {
        let t = v.trim();
        if t.is_empty() {
            return Err(format!("verify: value at index {i} is empty after trim"));
        }
        if t.len() > MAX_VERIFY_VALUE_BYTES {
            return Err(format!(
                "verify: value at index {i} exceeds {MAX_VERIFY_VALUE_BYTES} bytes"
            ));
        }
        out.push(t.to_string());
    }
    Ok(out)
}

/// Run the `verify` op: resolve the artifact kind (explicit `kind` must AGREE
/// with the payload — a contradiction is an error, never a guess), probe, and
/// assemble the `firmos.verify/0` response.
fn run_verify(req: &Request) -> Result<String, String> {
    let values = verify_values(&req.values)?;
    let has_pdf = !req.pdf_b64.is_empty();
    let is_pdf = match req.kind.as_str() {
        "pdf" => {
            if !has_pdf {
                return Err("verify: kind is \"pdf\" but pdf_b64 is empty".to_string());
            }
            true
        }
        "text" => {
            if has_pdf {
                return Err(
                    "verify: kind is \"text\" but pdf_b64 was supplied (contradiction)".to_string(),
                );
            }
            false
        }
        "" => has_pdf,
        other => return Err(format!("verify: unknown kind {other:?}")),
    };

    let out = if is_pdf {
        let pdf = base64::engine::general_purpose::STANDARD
            .decode(req.pdf_b64.as_bytes())
            .map_err(|_| "invalid base64 file data".to_string())?;
        let v = redaction::verify::verify_pdf(&pdf, &values).map_err(|_| {
            "could not verify the PDF (it may be encrypted, malformed, or too large)".to_string()
        })?;
        let (results, total, with_residuals) = verify_results_out(&v.results);
        VerifyOut {
            schema: VERIFY_SCHEMA,
            op: "verify",
            kind: "pdf",
            engine_version: redaction::verify::ENGINE_VERSION,
            artifact_sha256: sha256_hex(&pdf),
            vectors: redaction::verify::PDF_VECTORS.to_vec(),
            results,
            values_probed: values.len(),
            total_residual_findings: total,
            values_with_residuals: with_residuals,
            flags: Some(VerifyFlagsOut {
                low_text: v.flags.low_text,
                unmapped_fonts: v.flags.unmapped_fonts,
                degenerate_layout: v.flags.degenerate_layout,
            }),
            not_probed: redaction::verify::PDF_NOT_PROBED.to_vec(),
            limitations: [VERIFY_LIMITATIONS_COMMON, VERIFY_LIMITATIONS_PDF].concat(),
            diagnostics: v.diagnostics,
        }
    } else {
        let results = redaction::verify::verify_text(&req.text, &values);
        let (results, total, with_residuals) = verify_results_out(&results);
        VerifyOut {
            schema: VERIFY_SCHEMA,
            op: "verify",
            kind: "text",
            engine_version: redaction::verify::ENGINE_VERSION,
            artifact_sha256: sha256_hex(req.text.as_bytes()),
            vectors: redaction::verify::TEXT_VECTORS.to_vec(),
            results,
            values_probed: values.len(),
            total_residual_findings: total,
            values_with_residuals: with_residuals,
            flags: None,
            not_probed: Vec::new(),
            limitations: VERIFY_LIMITATIONS_COMMON.to_vec(),
            diagnostics: Vec::new(),
        }
    };
    serde_json::to_string(&out).map_err(|e| format!("serialize failed: {e}"))
}

/// Stable lowercase tier label (audit-/display-safe — a tier name, never a value).
fn confidence_label(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

/// Scan `text` with `engine` under `policy`: return the tiered candidate DTOs + the
/// routing summary. Shared by `scan` and `extract_scan` so both tier identically.
fn scan_text(
    engine: &RedactionEngine,
    policy: &ReviewPolicy,
    text: &str,
) -> (Vec<CandidateOut>, SummaryOut) {
    let cands = engine.candidates(text);
    let mut candidates = Vec::with_capacity(cands.len());
    let (mut quick_confirm, mut careful_review) = (0usize, 0usize);
    for c in &cands {
        let tier = policy.tier(c.confidence());
        match tier {
            ReviewTier::QuickConfirm => quick_confirm += 1,
            ReviewTier::CarefulReview => careful_review += 1,
        }
        candidates.push(CandidateOut {
            start: c.start(),
            end: c.end(),
            value: c.matched_value().to_string(),
            context: c.context().to_string(),
            recognizer: c.recognizer().to_string(),
            confidence: confidence_label(c.confidence()),
            tier: tier.label(),
            // ADVISORY iff the (post-merge) primary recognizer is an aggressive locale row —
            // the engine consults its `aggressive_locales` set, so this can never drift from
            // the merge-priority demotion.
            advisory: engine.is_aggressive(c.recognizer()),
        });
    }
    let summary = SummaryOut {
        quick_confirm,
        careful_review,
        total: candidates.len(),
        floor: confidence_label(policy.quick_confirm_floor()),
    };
    (candidates, summary)
}

/// Stable lowercase label for an [`extract::Format`] (plus `"text"` for the UTF-8
/// plain-text fallback). A format name, never matter content.
fn format_label(fmt: extract::Format) -> &'static str {
    match fmt {
        extract::Format::Eml => "eml",
        extract::Format::Msg => "msg",
        extract::Format::Docx => "docx",
        extract::Format::Pdf => "pdf",
        extract::Format::Unknown => "text",
    }
}

/// Turn raw FILE bytes into the redactable text + warnings, deterministically.
///
/// `.eml`/`.docx`/`.pdf` go through the [`extract`] engine. An email ALSO has its
/// routing headers (From/To/Cc/**Bcc**/Reply-To/Subject/Date) — PII the body text omits
/// — so they are composed ABOVE the body into the scannable text (otherwise redacting an
/// email would miss every recipient address). Any other extension is treated as plain
/// UTF-8 text (a `.txt`/`.md`/`.csv` the user pasted as a file); non-UTF-8 bytes with an
/// unknown extension are an error. Returns `(text, format_label, warnings)`; an
/// extraction failure (corrupt / unimplemented / non-text) is a generic error string
/// (the [`extract::ExtractError`] messages are documented to carry no matter content).
///
/// CONFIDENTIALITY NOTE on `warnings` (distinct from errors): a warning MAY carry a
/// matter-identifying string — e.g. `extract` lists attachment filenames ("Bcc present",
/// "attachment Settlement_Smith.pdf not extracted"). That is fine HERE because warnings
/// are returned for the host's LOCAL, `esc()`-rendered review UI only — they are never
/// logged, never egressed, and shown only to the data owner. Do NOT start logging them.
fn compose_from_file(
    filename: &str,
    bytes: Vec<u8>,
) -> Result<(String, &'static str, Vec<String>), String> {
    let fmt = extract::detect(filename);
    match extract::extract(filename, &bytes) {
        Ok(r) => {
            let mut text = String::new();
            // Compose email headers above the body so recipient PII is scannable.
            if let Some(em) = &r.metadata.email {
                let mut push = |label: &str, vals: &[String]| {
                    if !vals.is_empty() {
                        text.push_str(label);
                        text.push_str(": ");
                        text.push_str(&vals.join(", "));
                        text.push('\n');
                    }
                };
                push("From", &em.from);
                push("To", &em.to);
                push("Cc", &em.cc);
                push("Bcc", &em.bcc);
                push("Reply-To", &em.reply_to);
                if let Some(s) = &em.subject {
                    text.push_str("Subject: ");
                    text.push_str(s);
                    text.push('\n');
                }
                if let Some(d) = &em.date {
                    text.push_str("Date: ");
                    text.push_str(d);
                    text.push('\n');
                }
                if !text.is_empty() {
                    text.push('\n'); // blank line between headers and body
                }
            }
            text.push_str(&r.text);
            Ok((text, format_label(fmt), r.warnings))
        }
        // Unknown extension: treat the bytes as a plain-text file if they are UTF-8.
        Err(extract::ExtractError::Unsupported(_)) => match String::from_utf8(bytes) {
            Ok(s) => Ok((s, "text", Vec::new())),
            Err(_) => {
                Err("unsupported file type (not a .docx/.pdf/.eml, and not UTF-8 text)".into())
            }
        },
        Err(extract::ExtractError::NotImplemented(f)) => Err(format!(
            "extraction for {} files is not available yet",
            format_label(f)
        )),
        Err(extract::ExtractError::Malformed(reason)) => {
            // `reason` is documented to contain NO matter content.
            Err(format!("could not read the file: {reason}"))
        }
    }
}

/// SCAN a PDF (`redaction::scan_pdf`) and map each detected candidate to the per-span
/// DTO (stable id + page + cleartext review fields) with its review tier. Read-only: no
/// bytes are produced. A parse failure (encrypted / malformed / over-cap PDF) is a
/// GENERIC error string — never the underlying parser message, so nothing matter-derived
/// leaks.
fn pdf_scan_out(
    engine: &RedactionEngine,
    policy: &ReviewPolicy,
    pdf: &[u8],
) -> Result<PdfScanOut, String> {
    let scan = redaction::scan_pdf(pdf, engine).map_err(|_| {
        "could not read the PDF (it may be encrypted, malformed, or too large)".to_string()
    })?;
    let mut candidates = Vec::with_capacity(scan.items().len());
    let (mut quick_confirm, mut careful_review) = (0usize, 0usize);
    for item in scan.items() {
        let c = item.candidate();
        let tier = policy.tier(c.confidence());
        match tier {
            ReviewTier::QuickConfirm => quick_confirm += 1,
            ReviewTier::CarefulReview => careful_review += 1,
        }
        candidates.push(PdfCandidateOut {
            id: item.id().get(),
            page: item.page(),
            value: c.matched_value().to_string(),
            context: c.context().to_string(),
            recognizer: c.recognizer().to_string(),
            confidence: confidence_label(c.confidence()),
            tier: tier.label(),
            // ADVISORY iff the primary recognizer is an aggressive locale row (see scan_text).
            advisory: engine.is_aggressive(c.recognizer()),
        });
    }
    let total = candidates.len();
    Ok(PdfScanOut {
        schema: SCHEMA,
        op: "pdf_scan",
        candidates,
        summary: SummaryOut {
            quick_confirm,
            careful_review,
            total,
            floor: confidence_label(policy.quick_confirm_floor()),
        },
        low_text: scan.low_text(),
        unmapped_fonts: scan.unmapped_fonts(),
        degenerate_layout: scan.degenerate_layout(),
        diagnostics: scan.diagnostics().to_vec(),
    })
}

/// APPLY a PDF selection (`redaction::redact_pdf_with_selection`): remove ONLY the
/// accepted ids (default-deny — an empty `accept_ids` removes nothing) and return the
/// redacted bytes DTO. `redactions` is what was ACTUALLY removed. The bytes + engine must
/// match the `pdf_scan` the ids came from (the host re-sends the same PDF). Same GENERIC
/// error posture as [`pdf_scan_out`].
fn pdf_apply_out(
    engine: &RedactionEngine,
    pdf: &[u8],
    accept_ids: &[u64],
) -> Result<PdfApplyOut, String> {
    let selection = PdfSelection::of(accept_ids.iter().map(|&r| PdfCandidateId::from_raw(r)));
    let parts = redaction::redact_pdf_with_selection(pdf, engine, &selection)
        .map_err(|_| {
            "could not redact the PDF (it may be encrypted, malformed, or too large)".to_string()
        })?
        .into_parts();
    // Per-run "Cleaned: …" categories from the removed candidates (labels only, no value),
    // plus the static honest disclosure of the surfaces this path never touches.
    let cleaned = cleaned_categories(&parts.candidates);
    Ok(PdfApplyOut {
        schema: SCHEMA,
        op: "pdf_apply",
        pdf_b64: base64::engine::general_purpose::STANDARD.encode(&parts.bytes),
        redactions: parts.total_redactions,
        could_not_remove: parts.could_not_remove,
        low_text: parts.low_text,
        diagnostics: parts.diagnostics,
        cleaned,
        not_removed: PDF_NOT_REMOVED.to_vec(),
    })
}

/// Map a lowercase jurisdiction LABEL (the [`Locale::label`] form) to its [`Locale`],
/// or `None` for an unknown label. The ALLOWLIST that keeps an unrecognized value from
/// erroring or panicking — a forward-compatible host may send a label this binary does
/// not know yet, which is simply ignored (recall-first never DROPS a known pack, but an
/// unknown one cannot enable a recognizer that does not exist). NOTE: the match is over
/// the `&str` LABEL, not the `Locale` enum, so the `_ => None` arm catches any unknown
/// string — a new `Locale` variant is NOT forced into an arm here by the compiler; it is
/// silently unreachable (mapped to `None`) until a new label arm is added. Adding a
/// jurisdiction therefore requires adding its label arm here (and to `parse_profile`'s
/// sibling for profiles) by hand — the `#[non_exhaustive]` enum forces arms only in
/// matches over the enum VALUE, which this is not.
fn parse_locale(label: &str) -> Option<Locale> {
    match label {
        "sg" => Some(Locale::Singapore),
        "us" => Some(Locale::UnitedStates),
        "uk" => Some(Locale::UnitedKingdom),
        "au" => Some(Locale::Australia),
        "ca" => Some(Locale::Canada),
        _ => None,
    }
}

/// Map a compliance-profile LABEL (the [`Profile::label`] form) to its [`Profile`], or
/// `None` for an unknown label. ONLY the profiles that are actually implemented are
/// exposed (today: just `pci-dss-cardholder`); an unknown / not-yet-built label
/// (`hipaa`, `gdpr`, `glba`) is IGNORED rather than silently claimed.
fn parse_profile(label: &str) -> Option<Profile> {
    // Compare against each built profile's own label so the mapping cannot drift from
    // the source of truth (`Profile::label`).
    [Profile::PciDssCardholder]
        .into_iter()
        .find(|p| p.label() == label)
}

/// Turn the request's `disable_builtins` NAME list into the [`BuiltinRecognizers`] toggle
/// set: start from all-on (the recall-first default) and flip OFF each named built-in. The
/// names are matched by an ALLOWLIST against the [`Recognizer::label`] spellings — an
/// unknown / misspelt name is IGNORED (never an error, never a panic), so a
/// forward-compatible host can send a name this binary does not recognize. An absent/empty
/// list leaves every built-in ON, byte-identical to [`BuiltinRecognizers::all`].
///
/// This is purely the CALLER's choice and does NOT have the final word: a compliance
/// [`Profile`]'s `required_builtins` are OR-merged on top INSIDE the engine builder
/// (`RedactionEngine::base`), AFTER this disable, so e.g. a PCI profile always keeps the
/// credit-card recognizer ON even if it appears here — a profile guarantee cannot be
/// silently defeated by a disable. The default (no list) keeps full recall.
fn builtins_from_disables(disable: &[String]) -> BuiltinRecognizers {
    let mut b = BuiltinRecognizers::all();
    for name in disable {
        match name.as_str() {
            "email" => b.email = false,
            "phone" => b.phone = false,
            "id" => b.id = false,
            "name" => b.name = false,
            "credit-card" => b.credit_card = false,
            "iban" => b.iban = false,
            // BIC + ISIN are GLOBAL-ON like the IBAN (deliberate: both are precise — the
            // ISIN checksum-validated, the BIC structure-validated + label-cue-gated on
            // its 8-char form — and a BIC/ISIN beside a redacted IBAN re-identifies the
            // institution/security). Disableable here like any built-in.
            "bic" => b.bic = false,
            "isin" => b.isin = false,
            "ip" => b.ip = false,
            "url" => b.url = false,
            "address" => b.address = false,
            // Unknown label: ignored (the allowlist — never errors / panics).
            _ => {}
        }
    }
    b
}

/// Sanitize the request's USER-SUPPLIED TERMS into the bounded list handed to the engine:
/// drop empty / whitespace-only terms, drop any term longer than [`MAX_TERM_BYTES`] bytes,
/// and keep at most [`MAX_TERMS`] of the survivors (the kept prefix). NEVER errors / panics
/// — an abusive list simply degrades to its acceptable subset (recall on what is kept is
/// unaffected). The engine ALSO trims + escapes each term, so this is defence in depth +
/// the size bound (the engine has no count/length cap of its own at this seam).
///
/// The terms are passed to the engine VERBATIM (only trimmed/escaped there) — a term is
/// matched LITERALLY (case-insensitive), so metacharacters in a name (`A.B (Pte)`) match as
/// themselves, never as a regex. An absent/empty list yields an empty `Vec`, byte-identical
/// to today (the engine builds with no term recognizers).
fn sanitize_terms(terms: &[String]) -> Vec<String> {
    terms
        .iter()
        .filter(|t| !t.trim().is_empty())
        .filter(|t| t.len() <= MAX_TERM_BYTES)
        .take(MAX_TERMS)
        .cloned()
        .collect()
}

/// Build the request's [`RedactionEngine`] ONCE: the global built-ins (on by default, minus
/// any the request named in `disable_builtins`) PLUS the OPT-IN locale / profile / context
/// packs the request named, each via its ALLOWLIST, PLUS the OPT-IN ISO 17442 LEI recognizer
/// when `req.lei` is true (OFF by default). Unknown labels are dropped (see [`parse_locale`]
/// / [`parse_profile`] / [`builtins_from_disables`]). With no options this is byte-identical
/// to [`RedactionEngine::new`] (all built-ins on, no packs, no LEI).
///
/// PROFILE RECONCILIATION: the caller's built-in disables are passed as the BASE set; each
/// enabled profile's `required_builtins` are then OR-merged on top inside the engine builder
/// — so a profile's required recognizer stays ON even if the caller tried to disable it.
///
/// FALLIBLE only because the builder is fallible (firm-recognizer validation) — here
/// there are no firm recognizers and every locale/profile/context pattern is a
/// compiled-in static, so in practice it never fails; the `?` keeps the error fail-closed
/// regardless rather than `unwrap`.
fn build_engine(req: &Request) -> Result<RedactionEngine, String> {
    let locales: Vec<Locale> = req.locales.iter().filter_map(|l| parse_locale(l)).collect();
    let profiles: Vec<Profile> = req
        .profiles
        .iter()
        .filter_map(|p| parse_profile(p))
        .collect();
    let context = if req.context {
        ContextRecognizers::all()
    } else {
        ContextRecognizers::none()
    };
    let builtins = builtins_from_disables(&req.disable_builtins);
    let terms = sanitize_terms(&req.terms);
    RedactionEngine::builder()
        // USER-SUPPLIED TERMS ("super find & replace"): known party/director/company names
        // + matter numbers, matched as escaped literals (case-insensitive) by the engine.
        // Built into EVERY op's engine so scan↔apply detect identically (no span drift).
        .terms(terms)
        .builtins(builtins)
        .locales(locales)
        .profiles(profiles)
        .context_recognizers(context)
        // OPT-IN LEI (OFF by default — `false` here is byte-identical to today).
        .lei(req.lei)
        // OPT-IN AGGRESSIVE SG-NRIC loose net (OFF by default — `false` is byte-identical SG
        // output; ON registers the two advisory/demoted `sg:nric-loose`/`sg:nric-context`
        // rows). NOT folded into the SG locale pack.
        .sg_nric_loose(req.sg_nric_loose)
        // OPT-IN name-propagation EXPANSION tier (OFF by default — `false` is byte-identical
        // where nothing propagates; the SAFE tier is always on inside the engine).
        .name_expansion(req.name_expansion)
        // OPT-IN ORGANISATION detection (OFF by default — `false` is byte-identical; ON runs
        // the dedicated `ctx:org` pass, careful-review, excluded from name propagation).
        .organisations(req.organisations)
        // OPT-IN BROADENED ADDRESSES (OFF by default — `false` is byte-identical; ON adds the
        // three extra address rows, riding the existing careful-review address family).
        .addresses_full(req.addresses_full)
        .build()
        .map_err(|_| "could not build the redaction engine".to_string())
}

/// Run one request, returning the response JSON string on success or a generic,
/// value-free error message on failure. PURE: no I/O beyond the engine (which itself
/// touches none) — the caller owns stdin/stdout — so this is unit-testable directly.
fn run(input: &str) -> Result<String, String> {
    let req: Request =
        serde_json::from_str(input).map_err(|e| format!("invalid request JSON: {e}"))?;

    // One engine config for every op (so an `apply` re-detects with the SAME config as
    // its `scan`): the global built-ins PLUS the request's opt-in locale/profile/context
    // packs (default none = built-ins only). Built once, shared across the op match.
    let engine = build_engine(&req)?;

    let policy = ReviewPolicy::default();
    match req.op.as_str() {
        "capabilities" => {
            let locales: Vec<_> = Locale::ALL.iter().map(|locale| locale.label()).collect();
            let profiles: Vec<_> = Profile::ALL.iter().map(|profile| profile.label()).collect();
            let out = serde_json::json!({
                "schema": SCHEMA, "op": "capabilities", "contract_version": 1,
                "engine_version": env!("CARGO_PKG_VERSION"),
                "verification_schema": "firmos.verify/0",
                "locales": locales, "profiles": profiles,
                "disable_builtins": ["email", "phone", "id", "name", "credit-card", "iban",
                                     "bic", "isin", "ip", "url", "address"],
                "boolean_options": ["context", "lei", "sg_nric_loose", "name_expansion",
                                    "organisations", "addresses_full"],
                "limits": {"terms": MAX_TERMS, "term_bytes": MAX_TERM_BYTES}
            });
            serde_json::to_string(&out).map_err(|_| "could not report capabilities".to_string())
        }
        "scan" => {
            let (candidates, summary) = scan_text(&engine, &policy, &req.text);
            let out = ScanOut { schema: SCHEMA, op: "scan", candidates, summary };
            serde_json::to_string(&out).map_err(|e| format!("serialize failed: {e}"))
        }
        "apply" => {
            let accepted: HashSet<(usize, usize)> =
                req.accept.iter().map(|a| (a[0], a[1])).collect();
            // AI-safe LABELS (pseudonymization) is opted in by `replacement_style:"labels"`;
            // ANY other value (incl. absent / unknown / misspelt) is the byte-identical
            // `redacted` default — fail to the safe, unchanged token style. Recall parity:
            // both paths remove the SAME accepted spans (same `merged_spans`); only the
            // written TOKEN differs, and `applied`/`stale` are identical for the same set.
            let out = if req.replacement_style == "labels" {
                let (redacted, legend, applied, stale) =
                    engine.redact_with_selection_labeled(&req.text, &accepted);
                let legend = legend
                    .into_iter()
                    .map(|e| LegendEntryOut { label: e.label, value: e.value, count: e.count })
                    .collect();
                ApplyOut {
                    schema: SCHEMA,
                    op: "apply",
                    redacted,
                    applied,
                    stale,
                    legend: Some(legend),
                }
            } else {
                let (redacted, applied, stale) =
                    engine.redact_with_selection(&req.text, &accepted);
                ApplyOut { schema: SCHEMA, op: "apply", redacted, applied, stale, legend: None }
            };
            serde_json::to_string(&out).map_err(|e| format!("serialize failed: {e}"))
        }
        "extract_scan" => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(req.data_b64.as_bytes())
                .map_err(|_| "invalid base64 file data".to_string())?;
            let (text, format, warnings) = compose_from_file(&req.filename, bytes)?;
            let (candidates, summary) = scan_text(&engine, &policy, &text);
            let out = ExtractScanOut {
                schema: SCHEMA,
                op: "extract_scan",
                format,
                text,
                warnings,
                candidates,
                summary,
            };
            serde_json::to_string(&out).map_err(|e| format!("serialize failed: {e}"))
        }
        "pdf_scan" => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(req.data_b64.as_bytes())
                .map_err(|_| "invalid base64 file data".to_string())?;
            let out = pdf_scan_out(&engine, &policy, &bytes)?;
            serde_json::to_string(&out).map_err(|e| format!("serialize failed: {e}"))
        }
        "pdf_apply" => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(req.data_b64.as_bytes())
                .map_err(|_| "invalid base64 file data".to_string())?;
            // Remove ONLY the reviewer-accepted ids (the stable ids from pdf_scan).
            let out = pdf_apply_out(&engine, &bytes, &req.accept_ids)?;
            serde_json::to_string(&out).map_err(|e| format!("serialize failed: {e}"))
        }
        // Post-redaction verification probes — its own schema (firmos.verify/0).
        // The shared `engine` built above is NOT used: verify builds its own
        // terms-only probe engine from the VALUES (the request's recognizer
        // options are irrelevant to probing a finished output).
        "verify" => run_verify(&req),
        other => Err(format!(
            "unknown op: {other:?} (expected \"scan\", \"apply\", \"extract_scan\", \"pdf_scan\", \"pdf_apply\", or \"verify\")"
        )),
    }
}

/// Read at most [`MAX_INPUT_BYTES`] of UTF-8 from stdin. A larger payload, or invalid
/// UTF-8, is a generic error (never echoes the bytes).
fn read_stdin() -> Result<String, String> {
    let mut input = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut input)
        .map_err(|e| format!("could not read stdin: {e}"))?;
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    Ok(input)
}

fn main() {
    let result = read_stdin().and_then(|input| run(&input));
    match result {
        Ok(json) => {
            println!("{json}");
        }
        Err(reason) => {
            // Emit the error on STDOUT as the contract envelope (so the host always
            // parses a JSON object), AND a value-free line on STDERR for diagnostics.
            // `reason` is our own constructed message — it never contains matter text.
            let err = ErrorOut {
                schema: SCHEMA,
                error: reason.clone(),
            };
            match serde_json::to_string(&err) {
                Ok(s) => println!("{s}"),
                // Last-resort hand-built JSON if even error serialization fails.
                Err(_) => println!("{{\"schema\":\"{SCHEMA}\",\"error\":\"internal error\"}}"),
            }
            eprintln!("redact-cli: {reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn scan(text: &str) -> Value {
        let req = serde_json::json!({ "op": "scan", "text": text }).to_string();
        serde_json::from_str(&run(&req).expect("scan ok")).unwrap()
    }

    #[test]
    fn scan_emits_contract_with_tiers_and_summary() {
        let v = scan("Email: jane@acme.example and card 4111 1111 1111 1111.");
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["op"], "scan");
        let cands = v["candidates"].as_array().unwrap();
        assert!(!cands.is_empty(), "found candidates");
        // The checksum-valid card is High -> quick-confirm.
        let card = cands
            .iter()
            .find(|c| c["recognizer"] == "credit-card")
            .expect("card detected");
        assert_eq!(card["confidence"], "high");
        assert_eq!(card["tier"], "quick-confirm");
        // Summary totals are consistent and the floor is the default High.
        let s = &v["summary"];
        assert_eq!(s["floor"], "high");
        assert_eq!(
            s["total"].as_u64().unwrap(),
            cands.len() as u64,
            "summary total == candidate count"
        );
        assert_eq!(
            s["quick_confirm"].as_u64().unwrap() + s["careful_review"].as_u64().unwrap(),
            cands.len() as u64,
            "every candidate routes to exactly one tier"
        );
    }

    #[test]
    fn scan_then_apply_accepted_span_redacts_only_that_span() {
        // Scan, accept ONLY the card span, apply, and assert the card is removed while a
        // sub-High email (no class keyword) survives.
        let text = "Ping jane@acme.example soon; pay 4111 1111 1111 1111 now.";
        let v = scan(text);
        let card = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "credit-card")
            .expect("card detected")
            .clone();
        let accept = serde_json::json!([[
            card["start"].as_u64().unwrap(),
            card["end"].as_u64().unwrap()
        ]]);
        let req = serde_json::json!({ "op": "apply", "text": text, "accept": accept }).to_string();
        let out: Value = serde_json::from_str(&run(&req).expect("apply ok")).unwrap();
        assert_eq!(out["op"], "apply");
        assert_eq!(out["applied"].as_u64().unwrap(), 1);
        assert_eq!(out["stale"].as_u64().unwrap(), 0);
        let redacted = out["redacted"].as_str().unwrap();
        assert!(
            !redacted.contains("4111 1111 1111 1111"),
            "accepted card removed: {redacted:?}"
        );
        assert!(
            redacted.contains("jane@acme.example"),
            "unaccepted email survives: {redacted:?}"
        );
    }

    #[test]
    fn unknown_op_and_bad_json_are_errors_not_panics() {
        assert!(run(r#"{"op":"frobnicate","text":"x"}"#).is_err());
        assert!(run("not json at all").is_err());
        // A stale-only accept-set redacts nothing and reports it.
        let req =
            serde_json::json!({ "op": "apply", "text": "nothing here", "accept": [[100, 110]] })
                .to_string();
        let out: Value = serde_json::from_str(&run(&req).unwrap()).unwrap();
        assert_eq!(out["applied"].as_u64().unwrap(), 0);
        assert_eq!(out["stale"].as_u64().unwrap(), 1);
        assert_eq!(out["redacted"], "nothing here");
    }

    #[test]
    fn cleaned_categories_map_labels_to_structure_surfaces() {
        // The per-run "Cleaned: …" categorizer: body/annotation text vs the two metadata
        // surfaces, keyed off recognizer LABELS only (never a value). A category appears
        // ONLY when a matching label is present, so it can never over-claim.
        let c = categories_from_labels(
            ["email", "sg:nric", "metadata:Author", "metadata:xmp"].into_iter(),
        );
        assert!(c.iter().any(|s| s.contains("body")), "body text: {c:?}");
        assert!(
            c.iter().any(|s| s.contains("information fields")),
            "info fields: {c:?}"
        );
        assert!(c.iter().any(|s| s.contains("XMP")), "xmp: {c:?}");
        // No metadata labels -> no metadata categories claimed.
        let body_only = categories_from_labels(["email", "url"].into_iter());
        assert_eq!(body_only.len(), 1, "only body: {body_only:?}");
        assert!(body_only[0].contains("body"));
        // Empty removals -> empty cleaned list (never a false "cleaned everything").
        assert!(categories_from_labels(std::iter::empty()).is_empty());
    }

    #[test]
    fn determinism_same_text_same_output() {
        let a = run(r#"{"op":"scan","text":"SSN-ish 4111 1111 1111 1111 a@b.co"}"#).unwrap();
        let b = run(r#"{"op":"scan","text":"SSN-ish 4111 1111 1111 1111 a@b.co"}"#).unwrap();
        assert_eq!(a, b);
    }

    /// Scan with explicit options (the opt-in pack wiring).
    fn scan_with(text: &str, opts: serde_json::Value) -> Value {
        let mut req = serde_json::json!({ "op": "scan", "text": text });
        if let Value::Object(o) = opts {
            for (k, v) in o {
                req[k] = v;
            }
        }
        serde_json::from_str(&run(&req.to_string()).expect("scan ok")).unwrap()
    }

    /// The set of `recognizer` labels in a scan response.
    fn recs(v: &Value) -> Vec<String> {
        v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["recognizer"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn default_no_options_does_not_enable_locale_packs() {
        // Byte-identical to the historical default: an NRIC/UEN is NOT attributed to an
        // sg:* recognizer without an explicit locale opt-in.
        let v = scan_with("NRIC S1234567A UEN 201912345A", serde_json::json!({}));
        let r = recs(&v);
        assert!(
            !r.iter().any(|x| x.starts_with("sg:")),
            "no sg:* recognizer without an opt-in, got {r:?}"
        );
    }

    #[test]
    fn locales_sg_enables_nric_and_uen_full_span() {
        // {"locales":["sg"]} lights up the SG pack: an NRIC AND a UEN are flagged, and
        // the UEN candidate's value covers the WHOLE token incl. the check letter.
        let v = scan_with(
            "Director NRIC S1234567A, entity UEN 201912345A.",
            serde_json::json!({ "locales": ["sg"] }),
        );
        let r = recs(&v);
        assert!(
            r.contains(&"sg:nric".to_string()),
            "NRIC flagged via sg pack, got {r:?}"
        );
        assert!(
            r.contains(&"sg:uen".to_string()),
            "UEN flagged via sg pack, got {r:?}"
        );
        // The UEN candidate covers the full token (the check letter is inside the span).
        let uen = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "sg:uen")
            .expect("uen candidate");
        assert_eq!(
            uen["value"], "201912345A",
            "UEN value covers the check letter"
        );
    }

    #[test]
    fn locales_us_enables_dashed_ssn() {
        // {"locales":["us"]} lights up the US pack: a structurally-valid dashed SSN is
        // attributed to us:ssn (the synthetic value 212-34-5678 passes ssn_valid).
        let v = scan_with(
            "Taxpayer SSN 212-34-5678 on file.",
            serde_json::json!({ "locales": ["us"] }),
        );
        let r = recs(&v);
        assert!(
            r.contains(&"us:ssn".to_string()),
            "dashed SSN flagged via us pack, got {r:?}"
        );
    }

    #[test]
    fn address_recognizer_is_default_on_and_routes_to_careful_review() {
        // ZERO UI change: the structured-address built-in is default-ON, so a plain scan
        // (no opts) surfaces it — and it routes to CAREFUL review (never quick-confirm),
        // and is NOT advisory (it is a normal built-in, not an aggressive-locale row).
        let v = scan_with(
            "The registered office is 50 Raffles Place, per the deed.",
            serde_json::json!({}),
        );
        assert!(
            recs(&v).contains(&"address".to_string()),
            "address flagged by default, got {:?}",
            recs(&v)
        );
        let addr = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "address")
            .expect("address candidate");
        assert_eq!(addr["tier"], "careful-review", "address is careful-review");
        assert_eq!(addr["advisory"], false, "address is not advisory");
    }

    #[test]
    fn address_is_disableable_via_disable_builtins() {
        // The address built-in is a normal per-recognizer toggle: naming it in
        // `disable_builtins` turns it OFF (so a UI checkbox can un-tick it).
        let text = "Office at 50 Raffles Place today.";
        assert!(
            recs(&scan_with(text, serde_json::json!({}))).contains(&"address".to_string()),
            "address on by default"
        );
        assert!(
            !recs(&scan_with(
                text,
                serde_json::json!({ "disable_builtins": ["address"] })
            ))
            .iter()
            .any(|x| x == "address"),
            "address off when disabled"
        );
    }

    #[test]
    fn context_enables_role_name_after_a_role_heading() {
        // {"context":true} lights up the role-name row: a manager/director NAME LIST under
        // a heading is captured (the motivating miss). OFF without the opt-in.
        let text = "Managers\nLee Wai Keong\nTan Peng Ho";
        let v = scan_with(text, serde_json::json!({ "context": true }));
        assert!(
            recs(&v).contains(&"ctx:role-name".to_string()),
            "role-name via context, got {:?}",
            recs(&v)
        );
        let v0 = scan_with(text, serde_json::json!({}));
        assert!(
            !recs(&v0).iter().any(|x| x == "ctx:role-name"),
            "role-name is off without the context opt-in, got {:?}",
            recs(&v0)
        );
    }

    #[test]
    fn context_enables_dob_near_keyword_invisible_by_default() {
        // {"context":true} enables the context recognizers. A DOB date token near "DOB"
        // is invisible to the default built-ins (no recognizer matches a slashed date),
        // so it is the clean demonstration that context ADDS a candidate: ctx:dob fires
        // ONLY with the opt-in.
        let text = "Patient DOB 12/03/1980 admitted.";
        // Default: nothing matches the date token.
        let v0 = scan_with(text, serde_json::json!({}));
        assert!(
            !recs(&v0).iter().any(|x| x.starts_with("ctx:")),
            "no ctx:* recognizer without the context opt-in, got {:?}",
            recs(&v0)
        );
        // With context: the DOB is flagged via ctx:dob (keyword in-window, so it survives
        // the additive-only gate).
        let v = scan_with(text, serde_json::json!({ "context": true }));
        let r = recs(&v);
        assert!(
            r.contains(&"ctx:dob".to_string()),
            "DOB flagged via context, got {r:?}"
        );
    }

    #[test]
    fn context_undashed_ssn_is_a_non_primary_member_broad_phone_stays_primary() {
        // HONEST behaviour note (not a regression): an undashed 9-digit SSN is ALREADY
        // grabbed by the broad `phone` built-in, which is higher priority than a context
        // row, so even with context on the merged span's PRIMARY recognizer (the only
        // label the CLI surfaces) stays `phone`. The context row corroborates as a
        // non-primary member but does not change the visible `recognizer`/`confidence`
        // here. (The DOB case above is where context ADDS an otherwise-invisible
        // candidate — the clean, surface-observable demonstration.) This test pins the
        // documented behaviour so a future change to it is a deliberate, reviewed one.
        let text = "SSN: 212345678 confirmed.";
        let c = &scan_with(text, serde_json::json!({ "context": true }))["candidates"][0];
        assert_eq!(
            c["recognizer"], "phone",
            "broad phone wins as primary over a context row"
        );
    }

    #[test]
    fn unknown_locale_or_profile_label_is_ignored_not_an_error() {
        // An unknown pack label must NOT error or panic — it is dropped by the
        // allowlist, leaving the engine at the recognized subset (here: just sg).
        let v = scan_with(
            "NRIC S1234567A",
            serde_json::json!({ "locales": ["sg", "zz", "bogus"], "profiles": ["hipaa", "gdpr"] }),
        );
        assert!(
            recs(&v).contains(&"sg:nric".to_string()),
            "known sg label still applied"
        );
    }

    #[test]
    fn apply_uses_same_engine_config_so_uen_span_redacts_fully() {
        // The apply path MUST build the SAME engine config as the scan: scan with the SG
        // pack, accept the UEN span, apply with the SAME options, and assert no fragment
        // (incl. the check letter) of the UEN survives.
        let text = "Pay entity 201912345A by Friday.";
        let v = scan_with(text, serde_json::json!({ "locales": ["sg"] }));
        let uen = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "sg:uen")
            .expect("uen candidate")
            .clone();
        let accept =
            serde_json::json!([[uen["start"].as_u64().unwrap(), uen["end"].as_u64().unwrap()]]);
        let req = serde_json::json!({
            "op": "apply", "text": text, "accept": accept, "locales": ["sg"]
        })
        .to_string();
        let out: Value = serde_json::from_str(&run(&req).expect("apply ok")).unwrap();
        assert_eq!(out["applied"].as_u64().unwrap(), 1, "UEN span applied");
        assert_eq!(
            out["stale"].as_u64().unwrap(),
            0,
            "not stale (same engine config)"
        );
        let redacted = out["redacted"].as_str().unwrap();
        assert!(
            !redacted.contains("201912345"),
            "UEN digits removed: {redacted:?}"
        );
        assert!(
            !redacted.contains("A by Friday."),
            "no orphaned check letter: {redacted:?}"
        );
    }

    #[test]
    fn lei_off_by_default_on_when_opted_in() {
        // A digit-leading LEI is invisible to the default recognizers (the broad `id` is
        // letter-leading), so the default scan finds NOTHING — the clean off-by-default
        // demonstration that absent `lei` is byte-identical to today.
        let text = "Counterparty LEI 549300ABCDEFGHIJKL19 on the trade.";
        let off = scan_with(text, serde_json::json!({}));
        assert!(
            off["candidates"].as_array().unwrap().is_empty(),
            "no candidates without the LEI opt-in, got {:?}",
            off["candidates"]
        );
        // {"lei": false} is byte-identical to the no-option default.
        let plain = run(&serde_json::json!({ "op": "scan", "text": text }).to_string()).unwrap();
        let lei_false =
            run(&serde_json::json!({ "op": "scan", "text": text, "lei": false }).to_string())
                .unwrap();
        assert_eq!(plain, lei_false, "lei:false == no option (byte-identical)");

        // {"lei": true} lights up the recognizer: the LEI is flagged as `lei`, High tier.
        let on = scan_with(text, serde_json::json!({ "lei": true }));
        let r = recs(&on);
        assert!(
            r.contains(&"lei".to_string()),
            "LEI flagged via the opt-in, got {r:?}"
        );
        let lei = on["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "lei")
            .expect("lei candidate");
        assert_eq!(
            lei["value"], "549300ABCDEFGHIJKL19",
            "span is the whole LEI"
        );
        assert_eq!(lei["confidence"], "high", "a checksum-valid LEI is High");
        assert_eq!(lei["tier"], "quick-confirm");
    }

    #[test]
    fn lei_apply_uses_same_engine_config_so_lei_span_redacts() {
        // The apply path MUST build the SAME engine config (lei on) as the scan: scan with
        // lei, accept the LEI span, apply with lei on, and assert the LEI is removed.
        let text = "Trade for entity 549300ABCDEFGHIJKL19 booked.";
        let v = scan_with(text, serde_json::json!({ "lei": true }));
        let lei = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "lei")
            .expect("lei candidate")
            .clone();
        let accept =
            serde_json::json!([[lei["start"].as_u64().unwrap(), lei["end"].as_u64().unwrap()]]);
        let req = serde_json::json!({
            "op": "apply", "text": text, "accept": accept, "lei": true
        })
        .to_string();
        let out: Value = serde_json::from_str(&run(&req).expect("apply ok")).unwrap();
        assert_eq!(out["applied"].as_u64().unwrap(), 1, "LEI span applied");
        assert_eq!(
            out["stale"].as_u64().unwrap(),
            0,
            "not stale (same engine config)"
        );
        assert!(
            !out["redacted"]
                .as_str()
                .unwrap()
                .contains("549300ABCDEFGHIJKL19"),
            "accepted LEI removed: {:?}",
            out["redacted"]
        );
    }

    /// The set of candidate VALUES in a scan response.
    fn vals(v: &Value) -> Vec<String> {
        v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["value"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn name_expansion_off_by_default_safe_tier_still_propagates() {
        // SAFE tier is always on: "Mr Greco" re-flags the bare token "Greco" even with no
        // option. But WITHOUT name_expansion the bare "Massimo Greco" run is NOT covered.
        let text = "Mr Greco attended. Director Massimo Greco of Milan also signed.";
        let v = scan_with(text, serde_json::json!({}));
        let values = vals(&v);
        assert!(
            values.iter().any(|x| x == "Greco"),
            "SAFE re-flags bare 'Greco', got {values:?}"
        );
        assert!(
            !values.iter().any(|x| x == "Massimo Greco"),
            "without name_expansion the bare full name is NOT covered, got {values:?}"
        );
    }

    #[test]
    fn name_expansion_catches_bare_full_name() {
        // {"name_expansion": true} pulls the bare "Massimo Greco" in from the detected
        // "Greco" token (lowercase separators keep the run exactly the name, so the assert
        // is on the precise span; in real text a leading Capitalized word like "Director"
        // would be absorbed into the run too — that still REDACTS the name, just with a
        // wider span).
        let text = "Mr Greco attended. The director massimo? no — Massimo Greco of milan signed.";
        let v = scan_with(text, serde_json::json!({ "name_expansion": true }));
        let values = vals(&v);
        assert!(
            values.iter().any(|x| x.contains("Massimo Greco")),
            "name_expansion pulls in the bare full name, got {values:?}"
        );
        // The bare full name is genuinely covered (not just the surname).
        let off = vals(&scan_with(text, serde_json::json!({})));
        assert!(
            !off.iter().any(|x| x.contains("Massimo Greco")),
            "without expansion the bare full name is uncovered, got {off:?}"
        );
    }

    #[test]
    fn name_expansion_false_is_byte_identical_to_no_option() {
        // {"name_expansion": false} is byte-identical to omitting it.
        let text = "Mr Greco met Massimo Greco; ref AB1234.";
        let plain = run(&serde_json::json!({ "op": "scan", "text": text }).to_string()).unwrap();
        let off = run(
            &serde_json::json!({ "op": "scan", "text": text, "name_expansion": false }).to_string(),
        )
        .unwrap();
        assert_eq!(
            plain, off,
            "name_expansion:false == no option (byte-identical)"
        );
    }

    #[test]
    fn disable_builtins_drops_only_that_recognizer() {
        // A doc with an email, a phone-shaped run, AND a broad-id-shaped token. Disabling
        // `id` removes ONLY the id candidates; email/phone still fire (recall is reduced
        // exactly where the caller asked, nowhere else).
        let text = "Email jane@acme.example call 415 555 0173 ref AB1234 done.";
        let base = scan_with(text, serde_json::json!({}));
        let base_recs = recs(&base);
        assert!(
            base_recs.contains(&"id".to_string()),
            "default flags an id, got {base_recs:?}"
        );

        let off = scan_with(text, serde_json::json!({ "disable_builtins": ["id"] }));
        let off_recs = recs(&off);
        assert!(
            !off_recs.contains(&"id".to_string()),
            "id disabled, got {off_recs:?}"
        );
        // The other built-ins are unaffected.
        assert!(
            off_recs.contains(&"email".to_string()),
            "email still fires, got {off_recs:?}"
        );
        assert!(
            off_recs.contains(&"phone".to_string()),
            "phone still fires, got {off_recs:?}"
        );
    }

    #[test]
    fn default_no_disable_is_byte_identical() {
        // Absent / empty `disable_builtins` is byte-identical to no option at all.
        let text = "Email jane@acme.example ref AB1234 and card 4111 1111 1111 1111.";
        let plain = run(&serde_json::json!({ "op": "scan", "text": text }).to_string()).unwrap();
        let empty = run(
            &serde_json::json!({ "op": "scan", "text": text, "disable_builtins": [] }).to_string(),
        )
        .unwrap();
        assert_eq!(
            plain, empty,
            "empty disable list == no option (byte-identical)"
        );
    }

    #[test]
    fn unknown_disable_builtin_name_is_ignored_not_an_error() {
        // An unknown / misspelt built-in name (wrong case, the snake_case field name, or a
        // bogus token) is dropped by the allowlist — no error, no panic, and it does not
        // disable anything (so a real `id` still fires).
        let text = "Ref AB1234 noted.";
        let v = scan_with(
            text,
            serde_json::json!({ "disable_builtins": ["ID", "credit_card", "bogus"] }),
        );
        assert!(
            recs(&v).contains(&"id".to_string()),
            "no real name matched -> id still on"
        );
    }

    #[test]
    fn profile_required_builtin_wins_over_a_disable() {
        // The PCI profile REQUIRES the credit-card recognizer. Even if the caller tries to
        // disable `credit-card`, the profile's requirement wins (the card still fires) —
        // a profile guarantee cannot be silently defeated by a disable.
        let text = "Pay card 4111 1111 1111 1111 today.";
        // Disable credit-card WITHOUT the profile: the card is gone.
        let no_prof = scan_with(
            text,
            serde_json::json!({ "disable_builtins": ["credit-card"] }),
        );
        assert!(
            !recs(&no_prof).contains(&"credit-card".to_string()),
            "without the profile a credit-card disable takes effect, got {:?}",
            recs(&no_prof)
        );
        // Disable credit-card WITH the PCI profile: the profile re-enables it.
        let with_prof = scan_with(
            text,
            serde_json::json!({
                "disable_builtins": ["credit-card"],
                "profiles": ["pci-dss-cardholder"],
            }),
        );
        assert!(
            recs(&with_prof).contains(&"credit-card".to_string()),
            "PCI profile keeps the card recognizer ON despite the disable, got {:?}",
            recs(&with_prof)
        );
    }

    #[test]
    fn apply_uses_same_disabled_builtins_as_scan() {
        // scan with `id` disabled, accept the (still-detected) email span, then apply with
        // the SAME disable list. The apply re-detects with the SAME engine config, so the
        // accepted span resolves cleanly (not stale) and the email is removed.
        let text = "Reach jane@acme.example, ref AB1234.";
        let v = scan_with(text, serde_json::json!({ "disable_builtins": ["id"] }));
        let email = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "email")
            .expect("email candidate")
            .clone();
        let accept = serde_json::json!([[
            email["start"].as_u64().unwrap(),
            email["end"].as_u64().unwrap()
        ]]);
        let req = serde_json::json!({
            "op": "apply", "text": text, "accept": accept, "disable_builtins": ["id"]
        })
        .to_string();
        let out: Value = serde_json::from_str(&run(&req).expect("apply ok")).unwrap();
        assert_eq!(out["applied"].as_u64().unwrap(), 1, "email span applied");
        assert_eq!(
            out["stale"].as_u64().unwrap(),
            0,
            "not stale (same engine config)"
        );
        assert!(
            !out["redacted"]
                .as_str()
                .unwrap()
                .contains("jane@acme.example"),
            "accepted email removed: {:?}",
            out["redacted"]
        );
    }

    #[test]
    fn terms_redact_a_known_name_case_insensitively_across_text() {
        // A honorific-less director name no recognizer auto-detects, supplied as a term, is
        // flagged with the `term` recognizer and matched case-insensitively. Apply with the
        // SAME term removes every occurrence (no remnant), incl. the lowercased one.
        let text = "Director Massimo Greco signed. Also massimo greco initialed page 2.";
        let v = scan_with(text, serde_json::json!({ "terms": ["Massimo Greco"] }));
        let r = recs(&v);
        assert!(
            r.contains(&"term".to_string()),
            "term recognizer fires, got {r:?}"
        );
        // Both the exact-case and lowercased occurrences are caught (>=2 term hits).
        let term_hits = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["recognizer"] == "term")
            .count();
        assert!(
            term_hits >= 2,
            "case-insensitive: both occurrences flagged, got {term_hits}"
        );

        // Accept ALL spans and apply with the SAME term: no occurrence survives.
        let accept: Vec<[u64; 2]> = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| [c["start"].as_u64().unwrap(), c["end"].as_u64().unwrap()])
            .collect();
        let req = serde_json::json!({
            "op": "apply", "text": text, "accept": accept, "terms": ["Massimo Greco"]
        })
        .to_string();
        let out: Value = serde_json::from_str(&run(&req).expect("apply ok")).unwrap();
        let redacted = out["redacted"].as_str().unwrap().to_lowercase();
        assert!(
            !redacted.contains("massimo greco"),
            "every occurrence removed: {redacted:?}"
        );
    }

    #[test]
    fn terms_with_regex_metacharacters_match_literally() {
        // A name with regex metacharacters (`.` `(` `)`) must match as a LITERAL, never as a
        // pattern: it fires on the verbatim text and does NOT over-match a `.`-as-any-char.
        let text = "Counsel A.B (Pte) attended; AxB (Pte) is a different entity.";
        let v = scan_with(text, serde_json::json!({ "terms": ["A.B (Pte)"] }));
        let values = vals(&v);
        assert!(
            values.iter().any(|x| x == "A.B (Pte)"),
            "literal term matched verbatim, got {values:?}"
        );
        assert!(
            !values.iter().any(|x| x == "AxB (Pte)"),
            "the `.` did NOT match an arbitrary char (escaped literal), got {values:?}"
        );
    }

    #[test]
    fn terms_absent_or_empty_is_byte_identical() {
        // No `terms`, an empty list, and a whitespace-only term are all byte-identical to the
        // no-option default (the engine drops empties; we cap/drop here too).
        let text = "Director Massimo Greco met counsel; ref AB1234.";
        let plain = run(&serde_json::json!({ "op": "scan", "text": text }).to_string()).unwrap();
        let empty =
            run(&serde_json::json!({ "op": "scan", "text": text, "terms": [] }).to_string())
                .unwrap();
        let blank = run(
            &serde_json::json!({ "op": "scan", "text": text, "terms": ["", "   ", "\t"] })
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            plain, empty,
            "empty term list == no option (byte-identical)"
        );
        assert_eq!(
            plain, blank,
            "whitespace-only terms dropped == no option (byte-identical)"
        );
    }

    #[test]
    fn terms_over_length_dropped_others_kept() {
        // An over-MAX_TERM_BYTES term is dropped; a normal term alongside it still fires.
        let long = "x".repeat(MAX_TERM_BYTES + 1);
        let text = "The codename Falcon appears once.";
        let v = scan_with(text, serde_json::json!({ "terms": [long, "Falcon"] }));
        let values = vals(&v);
        assert!(
            values.iter().any(|x| x == "Falcon"),
            "kept term fires, got {values:?}"
        );
        // The over-length term cannot match anything in this text anyway; the point is that
        // including it neither errors nor disables the kept term.
        assert_eq!(v["schema"], SCHEMA, "no error envelope");
    }

    #[test]
    fn terms_redact_a_name_in_a_pdf_and_apply_removes_it() {
        // INTEGRATION shape (the deliverable): a term redacts a known name inside a PDF and a
        // pdf_apply of that id removes it from the re-extracted text (true byte removal).
        let pdf = build_pdf("Board director Massimo Greco of Milan signed the resolution.");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pdf);
        let req =
            serde_json::json!({ "op": "pdf_scan", "data_b64": b64, "terms": ["Massimo Greco"] })
                .to_string();
        let s: Value = serde_json::from_str(&run(&req).expect("pdf_scan ok")).unwrap();
        let cands = s["candidates"].as_array().unwrap();
        let term = cands
            .iter()
            .find(|c| c["recognizer"] == "term")
            .expect("term candidate in PDF");
        assert_eq!(term["value"], "Massimo Greco", "the name span");
        let id = term["id"].as_u64().unwrap();

        let areq = serde_json::json!({
            "op": "pdf_apply", "data_b64": b64, "accept_ids": [id], "terms": ["Massimo Greco"]
        })
        .to_string();
        let a: Value = serde_json::from_str(&run(&areq).expect("pdf_apply ok")).unwrap();
        assert!(
            a["redactions"].as_u64().unwrap() >= 1,
            "the term span removed"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(a["pdf_b64"].as_str().unwrap())
            .unwrap();
        let re = extract::extract("out.pdf", &bytes).expect("re-extract redacted pdf");
        assert!(
            !re.text.contains("Massimo Greco"),
            "name removed from PDF: {:?}",
            re.text
        );
    }

    fn extract_scan(filename: &str, bytes: &[u8]) -> Value {
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let req =
            serde_json::json!({ "op": "extract_scan", "filename": filename, "data_b64": b64 })
                .to_string();
        serde_json::from_str(&run(&req).expect("extract_scan ok")).unwrap()
    }

    #[test]
    fn extract_scan_eml_composes_headers_and_scans_body() {
        // A minimal .eml: the recipient addresses live in the headers (which the body
        // text omits), so composing them in is what lets redaction catch them.
        let eml = b"From: Alice <alice@example.com>\r\n\
                    To: Bob <bob@example.com>\r\n\
                    Subject: Payment\r\n\
                    \r\n\
                    Please pay card 4111 1111 1111 1111 today.\r\n";
        let v = extract_scan("msg.eml", eml);
        assert_eq!(v["op"], "extract_scan");
        assert_eq!(v["format"], "eml");
        let text = v["text"].as_str().unwrap();
        assert!(
            text.contains("bob@example.com"),
            "headers composed into scannable text"
        );
        assert!(text.contains("4111 1111 1111 1111"), "body included");
        // The card AND the header email addresses are detected.
        let recs: Vec<&str> = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["recognizer"].as_str().unwrap())
            .collect();
        assert!(recs.contains(&"credit-card"), "card found: {recs:?}");
        assert!(recs.contains(&"email"), "header email found: {recs:?}");
    }

    #[test]
    fn extract_scan_eml_nbsp_joined_phone_is_caught() {
        // REVIEW C1 regression pin: mail clients / word processors join phone groups
        // with a single NBSP (U+00A0) to prevent wrapping. The OLD default caught the
        // number; the column-gap guard must keep catching it THROUGH extract_scan.
        let eml = "From: Alice <alice@example.com>\r\n\
                   To: Bob <bob@example.com>\r\n\
                   Subject: Call\r\n\
                   \r\n\
                   Call +65\u{00A0}6812\u{00A0}4477 with any queries.\r\n"
            .as_bytes()
            .to_vec();
        let v = extract_scan("msg.eml", &eml);
        assert_eq!(v["format"], "eml");
        let covered = v["candidates"].as_array().unwrap().iter().any(|c| {
            c["recognizer"] == "phone" && c["value"].as_str().unwrap().contains("6812\u{00A0}4477")
        });
        assert!(covered, "NBSP-joined phone caught via .eml, got {v}");
    }

    #[test]
    fn extract_scan_docx_nbsp_joined_phone_is_caught() {
        // REVIEW C1 regression pin, .docx leg: Word inserts NBSP inside phone numbers.
        use std::io::Write as _;
        let doc_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
             <w:body><w:p><w:r><w:t xml:space=\"preserve\">Call +65\u{00A0}6812\u{00A0}4477 with queries.</w:t></w:r></w:p></w:body></w:document>";
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("word/document.xml", opts)
                .expect("start_file");
            zw.write_all(doc_xml.as_bytes()).expect("write part");
            zw.finish().expect("finish zip");
        }
        let v = extract_scan("letter.docx", &buf);
        assert_eq!(v["format"], "docx");
        let covered = v["candidates"].as_array().unwrap().iter().any(|c| {
            c["recognizer"] == "phone" && c["value"].as_str().unwrap().contains("6812\u{00A0}4477")
        });
        assert!(covered, "NBSP-joined phone caught via .docx, got {v}");
    }

    #[test]
    fn extract_scan_plain_text_fallback_for_unknown_extension() {
        let v = extract_scan("notes.txt", b"call me at jane@acme.example");
        assert_eq!(v["format"], "text");
        assert_eq!(v["text"], "call me at jane@acme.example");
        assert!(v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["recognizer"] == "email"));
    }

    #[test]
    fn extract_scan_msg_composes_headers_and_scans_body() {
        // End-to-end: an Outlook .msg flows through extract -> header composition -> scan,
        // exactly like a .eml. Build a minimal .msg (CFB) with a body card + a recipient.
        use std::io::{Cursor, Write as _};
        fn u16le(s: &str) -> Vec<u8> {
            s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
        }
        let mut buf = Vec::new();
        {
            let mut comp = cfb::CompoundFile::create(Cursor::new(&mut buf)).unwrap();
            for (id_ty, data) in [
                ("0037001F", u16le("Payment")),                        // subject
                ("1000001F", u16le("Wire card 4111 1111 1111 1111.")), // body
                ("0E04001F", u16le("Bob Jones")),                      // display-to
                ("0C1A001F", u16le("Alice")),                          // sender name
                ("5D01001F", u16le("alice@firm.example")),             // sender smtp
            ] {
                let mut st = comp.create_stream(format!("/__substg1.0_{id_ty}")).unwrap();
                st.write_all(&data).unwrap();
            }
            comp.flush().unwrap();
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
        let req = serde_json::json!({ "op": "extract_scan", "filename": "m.msg", "data_b64": b64 })
            .to_string();
        let v: Value = serde_json::from_str(&run(&req).expect("extract_scan ok")).unwrap();
        assert_eq!(v["format"], "msg");
        let text = v["text"].as_str().unwrap();
        assert!(
            text.contains("Bob Jones"),
            "recipient composed into scannable text: {text:?}"
        );
        assert!(text.contains("4111 1111 1111 1111"), "body included");
        assert!(v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["recognizer"] == "credit-card"));
    }

    #[test]
    fn extract_scan_non_utf8_unknown_extension_is_error_not_panic() {
        // An unknown extension whose bytes are not UTF-8 (and not a known container) is a
        // clean error, never a panic.
        let req = serde_json::json!({
            "op": "extract_scan", "filename": "blob.bin",
            "data_b64": base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe, 0x00, 0x01]),
        })
        .to_string();
        assert!(run(&req).is_err());
    }

    #[test]
    fn extract_scan_bad_base64_is_error_not_panic() {
        assert!(
            run(r#"{"op":"extract_scan","filename":"x.txt","data_b64":"not!base64!"}"#).is_err()
        );
    }

    /// Build a tiny one-page PDF whose content stream shows `body` via a `Tj` operator
    /// (uncompressed). Mirrors the redaction crate's own PDF test builder.
    fn build_pdf(body: &str) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream, StringFormat};
        let mut doc = Document::with_version("1.5");
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(
                    body.as_bytes().to_vec(),
                    StringFormat::Literal,
                )],
            ),
            Operation::new("ET", vec![]),
        ];
        let content_id = doc.add_object(Stream::new(
            dictionary! {},
            Content { operations: ops }.encode().unwrap(),
        ));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id =
            doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            }),
        );
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    /// Build a one-page PDF that lays out `pieces` GLYPH-CLUSTER BY GLYPH-CLUSTER on one
    /// line — each piece its own `Tj` with a small horizontal `Td` nudge between — the
    /// fragmented-word layout that defeated the literal term match (JP Morgan p.323).
    fn build_pdf_glyph_split(pieces: &[&str]) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream, StringFormat};
        let mut doc = Document::with_version("1.5");
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (i, piece) in pieces.iter().enumerate() {
            if i > 0 {
                ops.push(Operation::new("Td", vec![3.into(), 0.into()]));
            }
            ops.push(Operation::new(
                "Tj",
                vec![Object::String(
                    piece.as_bytes().to_vec(),
                    StringFormat::Literal,
                )],
            ));
        }
        ops.push(Operation::new("ET", vec![]));
        let content_id = doc.add_object(Stream::new(
            dictionary! {},
            Content { operations: ops }.encode().unwrap(),
        ));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id =
            doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            }),
        );
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    #[test]
    fn pdf_apply_reports_could_not_remove_field_and_glyph_split_term_is_removed() {
        // End-to-end through the CLI: a user term whose word is fragmented across Td-nudged
        // show ops (`Daniel` `J.` `W` `at` `kins`) is detected via the whitespace-insensitive
        // pass and TRULY removed; the `pdf_apply` output carries the honest `could_not_remove`
        // field (0 here — every accepted span was removed).
        let pdf = build_pdf_glyph_split(&["Daniel", "J.", "W", "at", "kins"]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pdf);
        let scan_req = serde_json::json!({
            "op": "pdf_scan", "data_b64": b64, "terms": ["Daniel J. Watkins"]
        })
        .to_string();
        let s: Value = serde_json::from_str(&run(&scan_req).expect("pdf_scan ok")).unwrap();
        let cands = s["candidates"].as_array().unwrap();
        let term = cands
            .iter()
            .find(|c| c["recognizer"] == "term")
            .expect("the fragmented term is detected");
        let id = term["id"].as_u64().unwrap();

        let apply_req = serde_json::json!({
            "op": "pdf_apply", "data_b64": b64, "accept_ids": [id], "terms": ["Daniel J. Watkins"]
        })
        .to_string();
        let a: Value = serde_json::from_str(&run(&apply_req).expect("pdf_apply ok")).unwrap();
        assert_eq!(
            a["redactions"].as_u64().unwrap(),
            1,
            "the term is removed + counted"
        );
        assert_eq!(
            a["could_not_remove"].as_u64().unwrap(),
            0,
            "the honest field is present and 0 (the term was truly removed)"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(a["pdf_b64"].as_str().unwrap())
            .unwrap();
        let re = extract::extract("out.pdf", &bytes).expect("re-extract");
        assert!(
            !re.text.contains("Watkins"),
            "term GONE from re-extracted text: {:?}",
            re.text
        );
        assert!(
            !re.text.contains("atkins"),
            "no fragment survives: {:?}",
            re.text
        );
    }

    fn pdf_op(op: &str, pdf: &[u8]) -> Value {
        let b64 = base64::engine::general_purpose::STANDARD.encode(pdf);
        let req = serde_json::json!({ "op": op, "data_b64": b64 }).to_string();
        serde_json::from_str(&run(&req).unwrap_or_else(|e| panic!("{op} failed: {e}"))).unwrap()
    }

    fn pdf_apply_ids(pdf: &[u8], accept_ids: &[u64]) -> Value {
        let b64 = base64::engine::general_purpose::STANDARD.encode(pdf);
        let req =
            serde_json::json!({ "op": "pdf_apply", "data_b64": b64, "accept_ids": accept_ids })
                .to_string();
        serde_json::from_str(&run(&req).unwrap_or_else(|e| panic!("pdf_apply failed: {e}")))
            .unwrap()
    }

    #[test]
    fn pdf_scan_enumerates_ids_and_apply_removes_only_accepted() {
        // A PDF with TWO identifiers; per-span review removes ONLY the accepted one.
        let pdf = build_pdf("card 4111 1111 1111 1111 and email jane@acme.example here");
        let s = pdf_op("pdf_scan", &pdf);
        assert_eq!(s["op"], "pdf_scan");
        assert_eq!(s["low_text"], false, "a real text PDF is not low_text");
        let cands = s["candidates"].as_array().unwrap();
        assert!(
            cands.len() >= 2,
            "card + email detected, got {}",
            cands.len()
        );
        // Every candidate now carries a stable id + 1-based page (the per-span contract).
        for c in cands {
            assert!(c.get("id").is_some(), "per-span id present");
            assert_eq!(c["page"], 1, "single-page fixture");
        }

        // Accept ONLY the card's id.
        let card = cands
            .iter()
            .find(|c| c["recognizer"] == "credit-card")
            .expect("card");
        let card_id = card["id"].as_u64().unwrap();
        let a = pdf_apply_ids(&pdf, &[card_id]);
        assert_eq!(a["op"], "pdf_apply");
        assert_eq!(
            a["redactions"].as_u64().unwrap(),
            1,
            "only the accepted id removed"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(a["pdf_b64"].as_str().unwrap())
            .unwrap();
        assert!(bytes.starts_with(b"%PDF"), "output is a PDF");
        let re = extract::extract("out.pdf", &bytes).expect("re-extract redacted pdf");
        assert!(
            !re.text.contains("4111 1111 1111 1111"),
            "card removed: {:?}",
            re.text
        );
        assert!(
            re.text.contains("jane@acme.example"),
            "email KEPT (not accepted): {:?}",
            re.text
        );
    }

    #[test]
    fn pdf_apply_with_empty_accept_removes_nothing_default_deny() {
        let pdf = build_pdf("pay card 4111 1111 1111 1111 today");
        let a = pdf_apply_ids(&pdf, &[]);
        assert_eq!(
            a["redactions"].as_u64().unwrap(),
            0,
            "default-deny: nothing accepted"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(a["pdf_b64"].as_str().unwrap())
            .unwrap();
        let re = extract::extract("out.pdf", &bytes).expect("re-extract");
        assert!(
            re.text.contains("4111 1111 1111 1111"),
            "card kept (none accepted)"
        );
    }

    #[test]
    fn pdf_ops_on_non_pdf_are_errors_not_panics() {
        assert!(run(r#"{"op":"pdf_scan","data_b64":"aGVsbG8="}"#).is_err()); // "hello"
        assert!(run(r#"{"op":"pdf_apply","data_b64":"aGVsbG8="}"#).is_err());
        assert!(run(r#"{"op":"pdf_scan","data_b64":"not!base64"}"#).is_err()); // bad b64
    }

    // ---- AI-safe LABELS (pseudonymization) — the `apply` `replacement_style` contract ----

    /// Run `apply` over `text` accepting EVERY scanned span, with the given options merged
    /// in (e.g. `replacement_style`/`terms`). Returns the parsed response.
    fn apply_all(text: &str, opts: serde_json::Value) -> Value {
        // Scan with the SAME options so the accept-set matches the apply's engine config.
        let v = scan_with(text, opts.clone());
        let accept: Vec<[u64; 2]> = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| [c["start"].as_u64().unwrap(), c["end"].as_u64().unwrap()])
            .collect();
        let mut req = serde_json::json!({ "op": "apply", "text": text, "accept": accept });
        if let Value::Object(o) = opts {
            for (k, val) in o {
                req[k] = val;
            }
        }
        serde_json::from_str(&run(&req.to_string()).expect("apply ok")).unwrap()
    }

    #[test]
    fn apply_labels_emits_legend_and_pseudonymizes() {
        // The labels-mode contract: `redacted` carries placeholders, `legend` is the
        // label->value->count map in deterministic order (entities, then types).
        let text = "Jefferson Tan emailed jane@acme.example and bob@acme.example.";
        let v = apply_all(
            text,
            serde_json::json!({ "replacement_style": "labels", "terms": ["Jefferson Tan"] }),
        );
        assert_eq!(v["op"], "apply");
        let red = v["redacted"].as_str().unwrap();
        assert!(red.contains("[A]"), "named party -> [A]: {red:?}");
        // Two distinct emails -> numbered.
        assert!(
            red.contains("[email 1]") && red.contains("[email 2]"),
            "numbered: {red:?}"
        );
        assert!(!red.contains("jane@acme.example"), "email removed: {red:?}");
        let legend = v["legend"]
            .as_array()
            .expect("legend present in labels mode");
        // Deterministic order: entity row first.
        assert_eq!(legend[0]["label"], "[A]");
        assert_eq!(legend[0]["value"], "Jefferson Tan");
        assert_eq!(legend[0]["count"].as_u64().unwrap(), 1);
        // Each legend row has the { label, value, count } shape.
        for row in legend {
            assert!(row["label"].is_string() && row["value"].is_string());
            assert!(row["count"].as_u64().is_some());
        }
    }

    #[test]
    fn apply_default_style_is_byte_identical_no_legend() {
        // [REDACTED]-MODE NO-OP REGRESSION: absent / "redacted" / an unknown style all
        // produce the SAME response, and it carries NO `legend` key.
        let text = "Email jane@acme.example, card 4111 1111 1111 1111.";
        let accept = {
            let v = scan(text);
            let a: Vec<[u64; 2]> = v["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| [c["start"].as_u64().unwrap(), c["end"].as_u64().unwrap()])
                .collect();
            serde_json::json!(a)
        };
        let absent =
            run(&serde_json::json!({ "op": "apply", "text": text, "accept": accept }).to_string())
                .unwrap();
        let redacted = run(&serde_json::json!(
            { "op": "apply", "text": text, "accept": accept, "replacement_style": "redacted" }
        )
        .to_string())
        .unwrap();
        let unknown = run(&serde_json::json!(
            { "op": "apply", "text": text, "accept": accept, "replacement_style": "bogus" }
        )
        .to_string())
        .unwrap();
        assert_eq!(absent, redacted, "absent == \"redacted\" (byte-identical)");
        assert_eq!(absent, unknown, "unknown style falls back to \"redacted\"");
        let v: Value = serde_json::from_str(&absent).unwrap();
        assert!(
            v.get("legend").is_none(),
            "no legend key in redacted mode: {v}"
        );
        assert!(
            v["redacted"].as_str().unwrap().contains("[REDACTED]"),
            "marker written"
        );
    }

    #[test]
    fn apply_labels_recall_parity_same_spans_removed() {
        // RECALL PARITY at the CLI seam: labels-mode `applied`/`stale` equal the marker
        // mode's for the SAME accept-set; the SAME identifiers vanish from both outputs.
        let text = "Jefferson Tan, jane@acme.example, 4111 1111 1111 1111.";
        let opts = serde_json::json!({ "terms": ["Jefferson Tan"] });
        let marker = apply_all(text, opts.clone());
        let mut lbl_opts = opts.clone();
        lbl_opts["replacement_style"] = serde_json::json!("labels");
        let labels = apply_all(text, lbl_opts);
        assert_eq!(marker["applied"], labels["applied"], "applied parity");
        assert_eq!(marker["stale"], labels["stale"], "stale parity");
        for needle in ["Jefferson Tan", "jane@acme.example", "4111 1111 1111 1111"] {
            assert!(
                !marker["redacted"].as_str().unwrap().contains(needle),
                "marker removed"
            );
            assert!(
                !labels["redacted"].as_str().unwrap().contains(needle),
                "labels removed"
            );
        }
    }

    #[test]
    fn apply_labels_determinism() {
        // DETERMINISM at the CLI seam: identical request -> byte-identical labeled response.
        let text = "Acme a@x.co b@y.co Acme";
        let opts = serde_json::json!({ "replacement_style": "labels", "terms": ["Acme"] });
        let v = apply_all(text, opts.clone());
        let v2 = apply_all(text, opts);
        assert_eq!(v, v2, "same input -> identical labeled response");
    }

    #[test]
    fn apply_labels_logs_no_cleartext_value() {
        // CONFIDENTIALITY: the labels path logs no cleartext (the bin logs nothing but a
        // generic error). `run()` returns the response on STDOUT only — the legend's
        // cleartext is a RETURN value, never written anywhere else. Here we assert the
        // structural guarantee: a SUCCESSFUL run produces a JSON response and NO error
        // string (the only thing the bin would ever emit on stderr). We cannot capture the
        // child's stderr from `run()` (it writes none on success), so we pin that `run`
        // returns Ok with the cleartext confined to the structured legend field.
        let text = "Jefferson Tan jane@acme.example";
        let v = apply_all(
            text,
            serde_json::json!({
                "replacement_style": "labels", "terms": ["Jefferson Tan"]
            }),
        );
        // The cleartext lives ONLY inside the structured `legend[].value` (and nowhere in a
        // recognizer/label string), so a host that drops `legend` before logging logs no
        // value. The recognizer-free response (`redacted` + counts) carries no cleartext.
        let legend = v["legend"].as_array().unwrap();
        assert!(
            legend.iter().any(|r| r["value"] == "Jefferson Tan"),
            "value in legend only"
        );
        assert!(
            !v["redacted"].as_str().unwrap().contains("Jefferson Tan"),
            "not in output"
        );
    }

    // ---- Change A (advisory) + Change B (SG NRIC loose net) at the CLI seam ----

    /// The candidate (by recognizer) from a scan response, or panic.
    fn cand_by_rec<'a>(v: &'a Value, rec: &str) -> &'a Value {
        v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == rec)
            .unwrap_or_else(|| panic!("no {rec} candidate in {v}"))
    }

    #[test]
    fn precise_recognizer_is_not_advisory_default_on() {
        // HARD BOUNDARY: a PRECISE recognizer (email here) carries advisory:false — it stays
        // default-ON / auto-redacted exactly as today. This pins that ONLY aggressive rows
        // flip; a precise recognizer's default is unchanged.
        let v = scan("Reach jane@acme.example today.");
        let email = cand_by_rec(&v, "email");
        assert_eq!(
            email["advisory"], false,
            "a precise recognizer is never advisory"
        );
    }

    #[test]
    fn every_candidate_carries_advisory_field() {
        // The DTO change: every candidate carries the `advisory` bool (a precise card is false).
        let v = scan("card 4111 1111 1111 1111 ok");
        for c in v["candidates"].as_array().unwrap() {
            assert!(
                c.get("advisory").is_some(),
                "advisory present on every candidate, got {c}"
            );
        }
    }

    #[test]
    fn aggressive_us_dl_is_advisory_cross_pack_flip() {
        // CROSS-PACK CONSEQUENCE: an aggressive row (us:dl) is now ADVISORY (default-OFF).
        // A bare 7-digit run near a "licence" keyword is matched ONLY by us:dl (the `id`
        // built-in needs a letter prefix; phone/account need >=8 digits), so the primary is
        // the aggressive us:dl row -> advisory:true.
        let v = scan_with(
            "Driver licence 1234567 issued.",
            serde_json::json!({ "locales": ["us"] }),
        );
        let dl = cand_by_rec(&v, "us:dl");
        assert_eq!(
            dl["advisory"], true,
            "an aggressive us:dl row is advisory (default-off)"
        );
    }

    #[test]
    fn sg_nric_loose_off_by_default_byte_identical() {
        // With `sg_nric_loose` absent/false, SG output is byte-identical to today: a
        // lowercase NRIC-shaped token is NOT attributed to sg:nric-loose.
        let text = "Holder s1234567d and bare 1234567 near NRIC no.";
        let plain =
            run(&serde_json::json!({ "op": "scan", "text": text, "locales": ["sg"] }).to_string())
                .unwrap();
        let off = run(&serde_json::json!(
            { "op": "scan", "text": text, "locales": ["sg"], "sg_nric_loose": false }
        )
        .to_string())
        .unwrap();
        assert_eq!(plain, off, "sg_nric_loose:false == absent (byte-identical)");
        let v: Value = serde_json::from_str(&plain).unwrap();
        assert!(
            !recs(&v)
                .iter()
                .any(|r| r == "sg:nric-loose" || r == "sg:nric-context"),
            "no loose/context rows without the opt-in, got {:?}",
            recs(&v)
        );
    }

    #[test]
    fn sg_nric_loose_catches_variants_and_is_advisory() {
        // The opt-in catches the user's variants as the PRIMARY (advisory) recognizer for
        // tokens NOT also grabbed by a default-ON built-in. The broad `id` built-in is
        // case-SENSITIVE (uppercase-letter-led) + needs a separator-clean shape, so a
        // LOWERCASE NRIC-shaped token (and the spaced/dashed lowercase forms) is matched
        // ONLY by the loose row -> it is the primary -> advisory:true. (An UPPERCASE token
        // `id` already catches is redacted default-ON via `id`, the SAFE direction — proven
        // separately; the loose net never ESCALATES, only ADDS advisory candidates.)
        for s in [
            "s1234567d",
            "a123456b",
            "x12345678z",
            "s 1234567 d",
            "s-1234567-d",
        ] {
            let text = format!("ref {s} end");
            let v = scan_with(&text, serde_json::json!({ "sg_nric_loose": true }));
            let hit = v["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["recognizer"] == "sg:nric-loose")
                .unwrap_or_else(|| panic!("sg:nric-loose must be the primary for {s:?} in {v}"));
            assert_eq!(hit["advisory"], true, "loose hit is advisory for {s:?}");
        }
    }

    #[test]
    fn sg_nric_context_keyword_gated_and_advisory() {
        // The bare-digit context row fires ONLY with an NRIC/FIN/IC keyword in-window and is
        // advisory. Without the keyword it does NOT contribute.
        let near = scan_with(
            "NRIC no 7654321 on file",
            serde_json::json!({ "sg_nric_loose": true }),
        );
        let ctx = cand_by_rec(&near, "sg:nric-context");
        assert_eq!(ctx["advisory"], true, "context row is advisory");
        let far = scan_with(
            "the lucky number 7654321 was drawn at the unrelated padded gala",
            serde_json::json!({ "sg_nric_loose": true }),
        );
        assert!(
            !recs(&far).iter().any(|r| r == "sg:nric-context"),
            "context row must NOT fire without a keyword, got {:?}",
            recs(&far)
        );
    }

    #[test]
    fn sg_nric_loose_word_bounded() {
        // `\b` excludes a window inside a longer alphanumeric run.
        for s in ["PO12345678XY", "AB1234567C"] {
            let text = format!("code {s} done");
            let v = scan_with(&text, serde_json::json!({ "sg_nric_loose": true }));
            assert!(
                !v["candidates"].as_array().unwrap().iter().any(|c| {
                    c["recognizer"] == "sg:nric-loose"
                        && c["value"]
                            .as_str()
                            .map(|x| x.len() < s.len())
                            .unwrap_or(false)
                }),
                "loose row must not match inside {s:?}, got {v}"
            );
        }
    }

    #[test]
    fn sg_precise_wins_real_nric_default_on_not_advisory() {
        // PRECISE-WINS at the CLI seam: a real S1234567D (precise pack + loose net both on)
        // is attributed to sg:nric and is advisory:false (default-redacted), while ONLY an
        // EXTRA loose-only token carries advisory:true.
        let v = scan_with(
            "Director NRIC S1234567D and odd token a987654b too",
            serde_json::json!({ "locales": ["sg"], "sg_nric_loose": true }),
        );
        // The real NRIC -> precise sg:nric, advisory false.
        let nric = cand_by_rec(&v, "sg:nric");
        assert_eq!(nric["value"], "S1234567D", "the real NRIC span");
        assert_eq!(
            nric["advisory"], false,
            "a real NRIC is default-ON (precise primary)"
        );
        // The extra odd token -> sg:nric-loose, advisory true.
        let loose = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "sg:nric-loose")
            .expect("the extra odd token is a loose advisory hit");
        assert_eq!(
            loose["advisory"], true,
            "the extra loose-only token is advisory"
        );
    }

    #[test]
    fn sg_loose_pdf_candidates_carry_advisory() {
        // The per-span PDF DTO also carries advisory: a loose hit in a PDF is advisory:true.
        let pdf = build_pdf("Holder s1234567d on the resolution.");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pdf);
        let req = serde_json::json!({ "op": "pdf_scan", "data_b64": b64, "sg_nric_loose": true })
            .to_string();
        let s: Value = serde_json::from_str(&run(&req).expect("pdf_scan ok")).unwrap();
        let loose = s["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["recognizer"] == "sg:nric-loose")
            .expect("loose hit in PDF");
        assert_eq!(loose["advisory"], true, "PDF loose candidate is advisory");
        assert!(loose.get("id").is_some(), "per-span id present");
    }

    #[test]
    fn sg_nric_loose_pathological_input_completes_fast() {
        // Linear-time guard: a long digit/letter run + many separators must not blow up.
        let text = format!(
            "{} NRIC no {}",
            "a1234567b ".repeat(2000),
            "1".repeat(50000)
        );
        let start = std::time::Instant::now();
        let v = scan_with(&text, serde_json::json!({ "sg_nric_loose": true }));
        assert_eq!(v["schema"], SCHEMA, "no error/panic on pathological input");
        assert!(start.elapsed().as_secs() < 10, "completes fast");
    }

    /// EXHAUSTIVENESS (M-2): every `Locale` variant's stable label MUST round-trip through
    /// `parse_locale` back to that same variant. `parse_locale` matches on the `&str` LABEL
    /// (not the enum), so a NEW `Locale` variant is NOT forced into an arm by the compiler —
    /// it would silently map to `None` (unselectable) until its label arm is added. This test
    /// closes that gap: it drives `Locale::ALL` (kept exhaustive by `assert_all_covers_locale`
    /// in the redaction crate), so a newly-added-but-unwired jurisdiction FAILS here. Defends
    /// the "a new jurisdiction = one label arm" contract the parser doc promises.
    #[test]
    fn capabilities_reports_compiled_packs_and_limits() {
        let raw = run(r#"{"op":"capabilities"}"#).unwrap();
        let out: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(out["schema"], SCHEMA);
        assert_eq!(out["op"], "capabilities");
        assert_eq!(out["contract_version"], 1);
        assert_eq!(out["verification_schema"], "firmos.verify/0");
        assert_eq!(out["limits"]["terms"], MAX_TERMS);
        assert_eq!(out["limits"]["term_bytes"], MAX_TERM_BYTES);
        assert_eq!(out["locales"].as_array().unwrap().len(), Locale::ALL.len());
        assert_eq!(out["profiles"].as_array().unwrap().len(), Profile::ALL.len());
        for locale in Locale::ALL {
            assert!(out["locales"].as_array().unwrap().iter().any(|v| v == locale.label()));
        }
        for profile in Profile::ALL {
            assert!(out["profiles"].as_array().unwrap().iter().any(|v| v == profile.label()));
        }
        assert!(out.get("text").is_none());
    }

    #[test]
    fn parse_locale_round_trips_every_variant() {
        for &loc in Locale::ALL {
            let label = loc.label();
            assert_eq!(
                parse_locale(label),
                Some(loc),
                "Locale::{loc:?} (label {label:?}) must parse back via parse_locale — \
                 add its arm to parse_locale's match",
            );
        }
        // And an unknown label is still a clean `None` (the allowlist's fail-closed default).
        assert_eq!(
            parse_locale("zz"),
            None,
            "an unknown jurisdiction label maps to None"
        );
    }

    /// EXHAUSTIVENESS (M-2): every `Profile` variant's stable label MUST round-trip through
    /// `parse_profile`. `parse_profile` already compares against `Profile::label()` per built
    /// profile, but the SET it iterates is hand-listed — this drives `Profile::ALL` (kept
    /// exhaustive by `assert_all_covers_profile`) so a newly-added-but-unwired profile FAILS
    /// here rather than silently mapping to `None`.
    #[test]
    fn parse_profile_round_trips_every_variant() {
        for &prof in Profile::ALL {
            let label = prof.label();
            assert_eq!(
                parse_profile(label),
                Some(prof),
                "Profile::{prof:?} (label {label:?}) must parse back via parse_profile — \
                 wire it into parse_profile",
            );
        }
        assert_eq!(
            parse_profile("hipaa"),
            None,
            "an unbuilt profile label maps to None"
        );
    }

    // =======================================================================
    // verify — the firmos.verify/0 op
    // =======================================================================

    #[test]
    fn verify_text_reports_residuals_value_free_with_limitations() {
        let req = serde_json::json!({
            "op": "verify",
            "text": "residual S1234567D survives; s1234567d too",
            "values": ["S1234567D", "Massimo Greco"],
        })
        .to_string();
        let raw = run(&req).expect("verify ok");
        // VALUE-FREE: the response must never echo the probed cleartext.
        assert!(!raw.contains("S1234567D") && !raw.contains("Massimo"));
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schema"], VERIFY_SCHEMA);
        assert_eq!(v["op"], "verify");
        assert_eq!(v["kind"], "text");
        assert!(!v["engine_version"].as_str().unwrap().is_empty());
        assert_eq!(v["artifact_sha256"].as_str().unwrap().len(), 64);
        let results = v["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["value_index"], 0);
        assert_eq!(results[0]["residual_found"], true);
        // Vector ids are the stable text ladder, all four hit for value 0
        // (raw once + the ci occurrence).
        let probes = results[0]["probes"].as_array().unwrap();
        let by = |vec_id: &str| {
            probes
                .iter()
                .find(|p| p["vector"] == vec_id)
                .unwrap_or_else(|| panic!("vector {vec_id} missing"))
                .clone()
        };
        assert_eq!(by("text_raw")["matches"], 1);
        assert_eq!(by("text_case_insensitive")["matches"], 2);
        // Value 1 was never in the output: no residual, but still fully probed.
        assert_eq!(results[1]["residual_found"], false);
        assert_eq!(v["values_with_residuals"], 1);
        // The honest framing is STRUCTURAL: limitations always populated, no
        // "passed"/"safe"/"clean" key anywhere.
        assert!(!v["limitations"].as_array().unwrap().is_empty());
        for forbidden in ["passed", "clean", "safe"] {
            assert!(
                v.get(forbidden).is_none(),
                "a {forbidden:?} verdict field must not exist"
            );
        }
    }

    #[test]
    fn verify_text_clean_output_still_carries_limitations() {
        let req = serde_json::json!({
            "op": "verify",
            "text": "nothing sensitive remains here",
            "values": ["S1234567D"],
        })
        .to_string();
        let v: Value = serde_json::from_str(&run(&req).expect("verify ok")).unwrap();
        assert_eq!(v["total_residual_findings"], 0);
        assert_eq!(v["values_with_residuals"], 0);
        assert!(
            !v["limitations"].as_array().unwrap().is_empty(),
            "zero residuals must NOT read as a certificate — limitations stay"
        );
        assert_eq!(v["not_probed"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn verify_pdf_probes_output_and_enumerates_not_probed() {
        // The plain (uncompressed) test PDF: the plant is visible to the strict,
        // lenient, raw-bytes, and stream vectors at once — this test pins the
        // CLI seam (schema/flags/not_probed), not surface isolation (the
        // redaction crate's unit tests own that).
        let pdf = build_pdf("Director ID S1234567D appears here.");
        let req = serde_json::json!({
            "op": "verify",
            "pdf_b64": base64::engine::general_purpose::STANDARD.encode(&pdf),
            "values": ["S1234567D"],
        })
        .to_string();
        let raw = run(&req).expect("verify ok");
        assert!(!raw.contains("S1234567D"), "value-free response");
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schema"], VERIFY_SCHEMA);
        assert_eq!(v["kind"], "pdf");
        let probes = v["results"][0]["probes"].as_array().unwrap();
        let by = |vec_id: &str| {
            probes
                .iter()
                .find(|p| p["vector"] == vec_id)
                .unwrap_or_else(|| panic!("vector {vec_id} missing"))
                .clone()
        };
        assert_eq!(by("pdf_text_strict")["residual_found"], true);
        assert_eq!(by("pdf_text_strict")["pages"][0], 1);
        assert_eq!(by("pdf_text_lenient")["residual_found"], true);
        assert_eq!(by("pdf_raw_bytes")["residual_found"], true);
        // Honesty echoes: flags present; not_probed enumerates the v1 gaps so a
        // renderer never hardcodes them; pdf limitation keys appended.
        assert_eq!(v["flags"]["low_text"], false);
        let not_probed = v["not_probed"].as_array().unwrap();
        assert!(not_probed.iter().any(|s| s == "image_pixel_content"));
        let lims = v["limitations"].as_array().unwrap();
        assert!(lims.iter().any(|s| s == "image_pixel_layer_not_probed"));
        assert!(lims.iter().any(|s| s == "no_finding_is_not_removal_proof"));
    }

    #[test]
    fn verify_is_deterministic_byte_identical() {
        let pdf = build_pdf("ID S1234567D here.");
        let req = serde_json::json!({
            "op": "verify",
            "pdf_b64": base64::engine::general_purpose::STANDARD.encode(&pdf),
            "values": ["S1234567D", "another value"],
        })
        .to_string();
        assert_eq!(run(&req).unwrap(), run(&req).unwrap());
    }

    #[test]
    fn verify_hostile_and_contradictory_requests_error_structurally() {
        // Garbage base64.
        let bad_b64 = serde_json::json!({
            "op": "verify", "pdf_b64": "!!!not-base64!!!", "values": ["x"],
        });
        assert!(run(&bad_b64.to_string()).is_err());
        // Bomb-shaped / non-PDF bytes: bounded structured error, no panic.
        let junk = base64::engine::general_purpose::STANDARD.encode(b"junk not a pdf");
        let bad_pdf = serde_json::json!({
            "op": "verify", "pdf_b64": junk, "values": ["x"],
        });
        assert!(run(&bad_pdf.to_string()).is_err());
        // An empty value would probe vacuously — refused, never a fake finding.
        let empty_value = serde_json::json!({
            "op": "verify", "text": "t", "values": ["ok", "   "],
        });
        assert!(run(&empty_value.to_string()).is_err());
        // Kind contradicting the payload: an error, never a silent guess.
        let contradiction = serde_json::json!({
            "op": "verify", "kind": "text",
            "pdf_b64": base64::engine::general_purpose::STANDARD.encode(b"x"),
            "values": ["x"],
        });
        assert!(run(&contradiction.to_string()).is_err());
        let pdf_no_payload = serde_json::json!({
            "op": "verify", "kind": "pdf", "values": ["x"],
        });
        assert!(run(&pdf_no_payload.to_string()).is_err());
        // Over-cap value counts/lengths: an ERROR (probing less than asked,
        // silently, would let a report over-claim coverage).
        let too_long = serde_json::json!({
            "op": "verify", "text": "t", "values": ["y".repeat(MAX_VERIFY_VALUE_BYTES + 1)],
        });
        assert!(run(&too_long.to_string()).is_err());
    }
}
