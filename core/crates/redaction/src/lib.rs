// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Redaction engine — module #1 (the flagship), NATIVE first-party module.
//!
//! Deterministic identifier-stripping over a matter's documents, dogfooding the
//! trusted-core ABI (architecture spec §10): this module touches matter data
//! ONLY through the brokered, granted, scoped, logged `Core` methods
//! ([`runtime::Core::matter_list_docs`] / [`runtime::Core::matter_read_text`] /
//! [`runtime::Core::document_transform`] / [`runtime::Core::audit_note`]). It
//! holds no filesystem, no socket, and **no egress capability** — the engine
//! cannot send anything anywhere.
//!
//! ## Honest framing (read before trusting this — it is load-bearing)
//!
//! - **This REMOVES matched identifiers, including the underlying text.** Each
//!   match is replaced with a [`REDACTION_MARKER`] (`[REDACTED]`) via the core's
//!   `document_transform`, so the identifier string is genuinely GONE from the
//!   stored content — it is not masked alongside the original.
//! - **Reasonable-efforts, NEVER "safe to send."** Matching the platform's
//!   redaction posture (CLAUDE.md / spec §8): the guarantee is *control +
//!   accountability* (what was stripped is audited; data has no egress path),
//!   NOT content-safety. Residual re-identification — e.g. "the only S$11bn deal
//!   closing this quarter" — is irreducibly the lawyer's judgment and CANNOT be
//!   removed by string matching. Do not let this overclaim.
//! - **Recall-tuned by design.** The recognizers prefer over-matching: a false
//!   flag costs a reviewer a few seconds, a MISS is a Rule-6 (confidentiality)
//!   breach. So patterns are deliberately broad.
//! - **This increment is DETERMINISTIC term + pattern matching only.** No
//!   Presidio / spaCy / ML / model / Python / network — anywhere. Statistical /
//!   Presidio-class detection would arrive LATER, behind the brokered
//!   `compute.model` capability (local, scoped, logged) — it is NOT in this
//!   increment.
//! - **This is the AI-prep strip path, NOT the production-privilege path.** The
//!   production-privilege redaction path must gate behind explicit lawyer review;
//!   this engine prepares content (e.g. for downstream tooling) on a
//!   reasonable-efforts basis and records exactly what it did.
//!
//! ## The `Name` recognizer is a HEURISTIC, not name detection
//!
//! [`Recognizer::Name`] is a **deterministic heuristic**, NOT name detection. It
//! catches *title-prefixed* names (`Mr. Smith`, `Dr. Tan Wei Ming`) and — only in
//! an OPT-IN [`RedactionEngine::aggressive`] mode that is OFF by default — any
//! capitalized multi-word run. It is recall-first (a false flag costs a reviewer
//! seconds) and it MISSES names that carry no title and no capitalization. Real
//! name detection (NER) is a statistical MODEL: it does NOT live here, it belongs
//! behind the brokered `compute.model` capability in a later increment, and it is
//! forbidden to claim "detects names" as a deterministic guarantee.
//!
//! ## Confidentiality split: cleartext candidates vs. audit (load-bearing)
//!
//! [`redact_matter`](RedactionEngine::redact_matter) returns the actual matched
//! [`RedactionCandidate`]s — INCLUDING the cleartext `matched_value` — for the
//! in-process review workflow. That list is sensitive matter data: it stays
//! local, behind the engine's empty egress grant, and is never sent anywhere.
//! The **audit note**, by contrast, records ONLY the count + a per-recognizer
//! breakdown (never the cleartext values) so the tamper-evident audit chain does
//! NOT become a cleartext store of the very identifiers being redacted.

// ===================================================================
// Internal module map (decomposed from the former ~10k-line monolith)
// ===================================================================
// Each module owns one seam of the former single file; the crate's PUBLIC API is
// re-exported UNCHANGED below (every `redaction::Foo` path is preserved), and the
// crate-internal items are re-exported at `pub(crate)` so sibling modules + the
// unit tests keep reaching them by their old crate-root paths.
mod builder;
mod candidate;
mod engine;
mod helpers;
mod labels;
mod recognizer;
mod report;
mod user_recognizer;

// Public API re-exports — these paths are load-bearing (redact-cli / viewgen /
// tests / the Python bridge reference `redaction::<Item>`); do NOT change them.
pub use builder::RedactionEngineBuilder;
pub use candidate::RedactionCandidate;
pub use engine::{BuiltinRecognizers, ContextRecognizers, RedactionEngine};
pub use labels::{Legend, LegendEntry, ReplacementStyle};
pub use recognizer::{Confidence, Recognizer, ReviewPolicy, ReviewTier};
pub use report::{
    ApplyReport, DocApply, DocReport, DocReviewSummary, DocScan, PdfDocRedaction, PdfDocScan,
    PdfRedactionReport, PdfScanReport, RedactionReport, ReviewSummary, ScanReport, Selection,
};
pub use user_recognizer::{Compiled, MatchMode, UserRecognizer};

// Crate-internal re-exports: surface each module's `pub(crate)` items (helpers,
// sealed-type constructors, etc.) at the crate root so `crate::<item>` and the
// unit tests' `use super::*` resolve exactly as before the split. (Re-exports are
// exempt from the unused-import lint, so an item used only by tests is fine.)
pub(crate) use engine::*;
pub(crate) use helpers::*;
pub(crate) use labels::*;
pub(crate) use recognizer::*;
pub(crate) use user_recognizer::*;

// The unit tests (`tests.rs`) reach these external-crate symbols through `use
// super::*`, exactly as when the tests lived inline and the crate root imported
// them privately. `#[cfg(test)]` so they are not unused imports in the library
// build (the split moved the code that used them into the submodules above).
#[cfg(test)]
use {
    runtime::{Audit, CoreResult, DataClass, Egress},
    std::sync::Arc,
};

/// True in-PDF text redaction (`redact_pdf`) — a PURE, self-contained function on
/// PDF BYTES, separate from the `&str -> String` `document_transform` path (PDF
/// bytes are not a UTF-8 `String`; see the module docs for the Core-mediation
/// follow-up). It REUSES this engine's detection (the single source of truth for
/// *what* is an identifier) and rewrites page content-stream text operators so the
/// matched glyphs are removed from the underlying text. Honest about its limits
/// (split glyphs / CID fonts / annotations / encryption) — read `pdf`'s docs.
pub mod pdf;
pub use pdf::{
    redact_pdf, redact_pdf_with_selection, scan_pdf, PdfCandidateId, PdfPageReport, PdfRedaction,
    PdfRedactionParts, PdfScan, PdfScanItem, PdfSelection,
};

/// Post-redaction VERIFICATION probes (`verify_text` / `verify_pdf`): the
/// recovery-red-team discipline productized — probe a redacted OUTPUT for the
/// accepted values across multiple recovery vectors (multi-decoder text layers,
/// raw bytes, decompressed streams, annotations, metadata) and return VALUE-FREE
/// structured probe outcomes. Deliberately residual-shaped (no "passed"/"safe"
/// state exists) — a verification result is never a safety certificate; read the
/// module docs before rendering one.
pub mod verify;

/// Lever 2 — the context-proximity + confidence layer: the four OPT-IN
/// context-required recognizer rows ([`ContextRecognizer`]) + the deterministic
/// proximity probe. Context is purely ADDITIVE (the gate is in `merged_spans`); the
/// rows are DATA (adding one is a row, mirroring `packs`). See
/// `to-read/redaction.LEVER2-CONTEXT-CONFIDENCE.md`.
pub mod context;
/// The recognizer-pack layer: the OPT-IN jurisdiction ([`Locale`]) + compliance
/// ([`Profile`]) axes, as DATA rows, plus the shared checksum validators. Each
/// jurisdiction lives in its own `packs/<cc>.rs`; adding one is the mechanical,
/// append-only diff documented at the top of `packs/mod.rs` ("ADDING A JURISDICTION").
pub mod packs;
pub use context::ContextRecognizer;
/// Induction (programming-by-example): SYNTHESIZE a recognizer regex from a few
/// EXAMPLE strings. The output is a plain regex wrapped in the EXISTING
/// [`UserRecognizer`] `{ mode: MatchMode::Regex, .. }` — an induced recognizer IS
/// a [`Recognizer::Custom`] (rung 4 of the recognizer ladder; no new variant, no
/// new built-in) and inherits every fail-closed `compile` guard. SECURITY-CRITICAL:
/// a synthesized matcher that misses its own example is an under-redaction leak —
/// see the module's CORRECTNESS INVARIANT + `to-read/redaction.INDUCTION-SPEC.md`.
pub mod induce;
pub use induce::{
    induce, induce_with, InducedPattern, InductionError, InductionOptions, NamedRecognizer,
    RecognizerLibrary, Strategy,
};
pub use packs::profiles::{Profile, ProfileRecognizer, ProfileSpec};
pub use packs::validators::{
    bic_structure_valid, digit_sum, iban_valid, isin_valid, lei_valid, luhn_valid, mod10_valid,
    weighted_mod_n,
};
pub use packs::{Locale, LocaleRecognizer};

// ===================================================================
// Recognizer-pack axes — selectable, OPT-IN jurisdiction + compliance recognizers
// ===================================================================
//
// Some identifiers are jurisdiction-specific (an SG NRIC, a US SSN, …) or
// compliance-regime-specific (PCI-DSS, …). Running them everywhere is noise + false-
// flag cost, so they are NOT global built-ins; they live in OPT-IN packs a firm
// enables for the jurisdictions / regimes it actually works in
// (`.locales([Locale::Singapore])` / `.profiles([Profile::PciDssCardholder])`).
//
// The pack layer now lives in its OWN module tree (`packs/`): the jurisdiction axis
// ([`Locale`] / [`LocaleRecognizer`] / `locale_recognizers`, one file per
// jurisdiction), the compliance axis ([`Profile`] / [`ProfileSpec`] /
// [`ProfileRecognizer`]), and the shared checksum validators ([`luhn_valid`] /
// [`iban_valid`] / [`mod10_valid`] / [`weighted_mod_n`] / [`digit_sum`]). All are
// re-exported above. DESIGN (so a NEW jurisdiction/profile drops in with minimal
// ceremony): recognizers are DATA ROWS, NOT per-recognizer [`Recognizer`] enum
// variants — attribution flows through the single generic [`Recognizer::Locale`] /
// [`Recognizer::Profile`] variant carrying a namespaced label. See the "ADDING A
// JURISDICTION" comment at the top of `packs/mod.rs` for the exact 4-point diff.

/// What every matched identifier is replaced with. The matched span (the
/// identifier text itself) is REMOVED and this marker put in its place, so the
/// original text is gone from stored content (not masked beside it).
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// How many characters of surrounding context each candidate snippet carries on
/// either side of the matched span (clamped to char boundaries / doc edges).
const CONTEXT_CHARS: usize = 40;

#[cfg(test)]
mod tests;
