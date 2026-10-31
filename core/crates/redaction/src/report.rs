// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealed report / scan / selection / apply types for the redaction workflows
//! (text + PDF). Extracted from `lib.rs`.

use runtime::DataClass;

use crate::{Confidence, RedactionCandidate, ReviewPolicy, ReviewTier};

/// A per-document redaction result for the review workflow.
///
/// SEALED (FIX, medium): fields are PRIVATE and the type is NOT `Clone` — it
/// holds [`RedactionCandidate`]s that carry cleartext, so the same no-bulk-copy
/// discipline applies. Access is via the accessors.
#[derive(Debug, PartialEq, Eq)]
pub struct DocReport {
    /// The document id processed.
    pub(crate) doc_id: u64,
    /// The data class it was read/transformed under.
    pub(crate) class: DataClass,
    /// The actual redaction candidates removed from this doc (with cleartext, for
    /// in-process review). Each was replaced ONCE with the marker.
    pub(crate) candidates: Vec<RedactionCandidate>,
    /// How many redactions were written. DERIVED — always `== candidates.len()`
    /// (one merged span = one redaction). Kept for convenience / back-compat.
    pub(crate) identifiers_removed: usize,
}

impl DocReport {
    /// The document id processed.
    pub fn doc_id(&self) -> u64 {
        self.doc_id
    }
    /// The data class it was read/transformed under.
    pub fn class(&self) -> DataClass {
        self.class
    }
    /// The actual redaction candidates removed from this doc (with cleartext, for
    /// in-process review only — never egress these).
    pub fn candidates(&self) -> &[RedactionCandidate] {
        &self.candidates
    }
    /// How many redactions were written (`== candidates().len()`).
    pub fn identifiers_removed(&self) -> usize {
        self.identifiers_removed
    }
}

/// The outcome of redacting a matter: which docs were processed and the actual
/// candidates stripped from each. Returned IN-PROCESS for the review workflow;
/// the candidates carry cleartext but the engine holds no egress (nothing
/// leaves the box).
///
/// SEALED (FIX, medium): `docs` is PRIVATE and the type is NOT `Clone`, so the
/// cleartext-bearing candidate list cannot be bulk-cloned out of a report. Access
/// is via [`docs`](RedactionReport::docs) and the summary accessors.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RedactionReport {
    pub(crate) docs: Vec<DocReport>,
}

impl RedactionReport {
    /// The per-document reports (borrowed; the report owns the cleartext).
    pub fn docs(&self) -> &[DocReport] {
        &self.docs
    }

    /// Total documents processed.
    pub fn docs_processed(&self) -> usize {
        self.docs.len()
    }

    /// Total identifiers removed across all documents.
    pub fn total_identifiers_removed(&self) -> usize {
        self.docs.iter().map(|d| d.identifiers_removed).sum()
    }
}

// ===================================================================
// scan -> review -> apply workflow (the Tier-1/Tier-2 human-review path)
// ===================================================================
//
// The one-shot [`RedactionEngine::redact_matter`] detects AND commits every
// candidate. Real legal redaction needs the lawyer's judgment in the loop — the
// crate docs are explicit that this is "reasonable-efforts, never safe-to-send;
// the residual-identification judgment is the lawyer's." So the workflow splits
// into three phases:
//
//   1. [`RedactionEngine::scan_matter`] — detect candidates, audit the SCAN, write
//      NOTHING. Needs only `matter.read` (NOT `document.transform`), so a review
//      pass cannot mutate a document even by accident.
//   2. The reviewer builds a [`Selection`] over the [`ScanReport`] — accept the
//      true positives, reject the false ones. The selection is SPAN-COORDINATE
//      only (doc id + class + byte span); it carries NO cleartext.
//   3. [`RedactionEngine::apply_selection`] — commit ONLY the accepted spans via
//      the mediated `document_transform`, audited. A previously-detected span that
//      is no longer present (the document changed between scan and apply) is
//      counted as `stale` and skipped — never blindly written at the old offset.

/// One document's SCAN result: the candidates detected for review, with cleartext
/// `matched_value`/`context` for the IN-PROCESS review workflow only (never
/// egressed, never audited). NOTHING has been written yet.
///
/// SEALED (like [`DocReport`]): fields PRIVATE, NOT `Clone` — the cleartext-bearing
/// candidate list cannot be bulk-copied out.
#[derive(Debug, PartialEq, Eq)]
pub struct DocScan {
    pub(crate) doc_id: u64,
    pub(crate) class: DataClass,
    pub(crate) candidates: Vec<RedactionCandidate>,
}

impl DocScan {
    /// The document id scanned.
    pub fn doc_id(&self) -> u64 {
        self.doc_id
    }
    /// The data class it was read under.
    pub fn class(&self) -> DataClass {
        self.class
    }
    /// The detected candidates (cleartext, in-process review only — never egress).
    pub fn candidates(&self) -> &[RedactionCandidate] {
        &self.candidates
    }
}

/// The result of [`scan_matter`](RedactionEngine::scan_matter): per-document
/// candidates for review. Nothing has been written; the engine holds no egress, so
/// the cleartext candidates never leave the box.
///
/// SEALED: `docs` is PRIVATE and the type is NOT `Clone`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub(crate) docs: Vec<DocScan>,
}

impl ScanReport {
    /// The per-document scans (borrowed; the report owns the cleartext).
    pub fn docs(&self) -> &[DocScan] {
        &self.docs
    }
    /// Total documents scanned.
    pub fn docs_scanned(&self) -> usize {
        self.docs.len()
    }
    /// Total candidates detected across all documents.
    pub fn total_candidates(&self) -> usize {
        self.docs.iter().map(|d| d.candidates.len()).sum()
    }
}

/// The coordinate key identifying one candidate span for [`Selection`]: the
/// document, its class, and the BYTE span in the document's content. NO cleartext
/// — a selection is safe to persist / pass around without carrying identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SpanKey {
    pub(crate) doc_id: u64,
    pub(crate) class: DataClass,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// A reviewer's accept/reject decision over a [`ScanReport`] — the set of spans to
/// actually apply. Carries SPAN COORDINATES only (no cleartext), so it can be held,
/// serialized by the host, or round-tripped through review UI without ever moving
/// an identifier.
///
/// Build it from a scan with [`Selection::all`] (accept everything — the
/// recall-first default a reviewer then prunes) or [`Selection::none`] (accept
/// nothing — then opt specific spans IN), and adjust with
/// [`accept`](Selection::accept) / [`reject`](Selection::reject).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Selection {
    pub(crate) accepted: std::collections::HashSet<SpanKey>,
}

impl Selection {
    /// An empty selection — nothing accepted. Opt spans in with
    /// [`accept`](Selection::accept).
    pub fn none() -> Self {
        Self::default()
    }

    /// Accept EVERY candidate in a scan (the recall-first default: the reviewer
    /// then [`reject`](Selection::reject)s the false positives).
    pub fn all(scan: &ScanReport) -> Self {
        let mut sel = Self::none();
        for doc in &scan.docs {
            for c in &doc.candidates {
                sel.accept(doc.doc_id, doc.class, c.start(), c.end());
            }
        }
        sel
    }

    /// Build the TIERED recall-first selection: pre-accept every Tier-1
    /// ([`ReviewTier::QuickConfirm`]) candidate per `policy`, and leave every Tier-2
    /// ([`ReviewTier::CarefulReview`]) candidate UNaccepted for the reviewer to opt in.
    ///
    /// This is the LOAD-BEARING consumer of the [`Confidence`] tier — the tier now drives
    /// which spans start accepted, not just how each is labeled. With the default
    /// [`ReviewPolicy`] (High floor) the high-confidence bulk is pre-accepted (the
    /// reviewer bulk-confirms / spot-rejects it), while Medium/Low await a per-item
    /// decision via [`accept`](Selection::accept).
    ///
    /// It is the graduated middle between the two extremes:
    /// [`Selection::all`] accepts everything (prune false positives down) and
    /// [`Selection::none`] accepts nothing (opt every span in); `quick_confirm` accepts
    /// the strong candidates and leaves the weak ones pending. (With a floor of
    /// [`Confidence::Low`] it coincides with [`all`](Selection::all); the per-doc/per-tier
    /// counts are available cleartext-free via [`ReviewSummary::of`].)
    pub fn quick_confirm(scan: &ScanReport, policy: &ReviewPolicy) -> Self {
        let mut sel = Self::none();
        for doc in &scan.docs {
            for c in &doc.candidates {
                if policy.tier(c.confidence()) == ReviewTier::QuickConfirm {
                    sel.accept(doc.doc_id, doc.class, c.start(), c.end());
                }
            }
        }
        sel
    }

    /// Accept a span (by document + class + byte offsets, as reported on a
    /// [`RedactionCandidate`]). Idempotent.
    pub fn accept(&mut self, doc_id: u64, class: DataClass, start: usize, end: usize) -> &mut Self {
        self.accepted.insert(SpanKey {
            doc_id,
            class,
            start,
            end,
        });
        self
    }

    /// Reject (remove) a previously-accepted span. Idempotent (rejecting an absent
    /// span is a no-op).
    pub fn reject(&mut self, doc_id: u64, class: DataClass, start: usize, end: usize) -> &mut Self {
        self.accepted.remove(&SpanKey {
            doc_id,
            class,
            start,
            end,
        });
        self
    }

    /// Is this span currently accepted?
    pub fn is_accepted(&self, doc_id: u64, class: DataClass, start: usize, end: usize) -> bool {
        self.accepted.contains(&SpanKey {
            doc_id,
            class,
            start,
            end,
        })
    }

    /// Total accepted spans.
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    /// Whether the selection is empty (no spans accepted).
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}

/// A cleartext-FREE, per-document split of how a [`ScanReport`] routes under a
/// [`ReviewPolicy`]: how many candidates land in Tier-1 (quick-confirm) vs Tier-2
/// (careful review). COUNTS ONLY — no `matched_value`, no surrounding context, no span —
/// so a summary is safe to log, display, or hand across a boundary (unlike the
/// cleartext-bearing [`ScanReport`]). The host renders Tier-1 as a single "confirm N"
/// action and Tier-2 as an N-item worklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocReviewSummary {
    pub(crate) doc_id: u64,
    pub(crate) class: DataClass,
    pub(crate) quick_confirm: usize,
    pub(crate) careful_review: usize,
}

impl DocReviewSummary {
    /// The document id summarized.
    pub fn doc_id(&self) -> u64 {
        self.doc_id
    }
    /// The data class it was scanned under.
    pub fn class(&self) -> DataClass {
        self.class
    }
    /// Tier-1 ([`ReviewTier::QuickConfirm`]) candidate count for this document.
    pub fn quick_confirm(&self) -> usize {
        self.quick_confirm
    }
    /// Tier-2 ([`ReviewTier::CarefulReview`]) candidate count for this document.
    pub fn careful_review(&self) -> usize {
        self.careful_review
    }
    /// Total candidates for this document (`quick_confirm() + careful_review()`).
    pub fn total(&self) -> usize {
        self.quick_confirm + self.careful_review
    }
}

/// The cleartext-FREE routing summary for a whole [`ScanReport`] under a [`ReviewPolicy`]:
/// the per-document Tier-1/Tier-2 split plus the policy floor it was computed under. Built
/// by [`ReviewSummary::of`]. COUNTS ONLY (see [`DocReviewSummary`]) — it never carries an
/// identifier, so it is the audit-/display-safe face of the routing decision the
/// cleartext [`ScanReport`] drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSummary {
    pub(crate) floor: Confidence,
    pub(crate) docs: Vec<DocReviewSummary>,
}

impl ReviewSummary {
    /// Compute the routing summary for `scan` under `policy`. PURE + DETERMINISTIC and
    /// touches no [`Core`](runtime::Core) — the review step is the reviewer's, between the
    /// audited [`scan_matter`](RedactionEngine::scan_matter) and
    /// [`apply_selection`](RedactionEngine::apply_selection). The per-doc counts are over
    /// the SAME candidates [`Selection::quick_confirm`] routes, so
    /// `ReviewSummary::of(scan, policy).quick_confirm()` equals
    /// `Selection::quick_confirm(scan, policy).len()`.
    pub fn of(scan: &ScanReport, policy: &ReviewPolicy) -> Self {
        let docs = scan
            .docs
            .iter()
            .map(|d| {
                let mut quick_confirm = 0usize;
                let mut careful_review = 0usize;
                for c in &d.candidates {
                    match policy.tier(c.confidence()) {
                        ReviewTier::QuickConfirm => quick_confirm += 1,
                        ReviewTier::CarefulReview => careful_review += 1,
                    }
                }
                DocReviewSummary {
                    doc_id: d.doc_id,
                    class: d.class,
                    quick_confirm,
                    careful_review,
                }
            })
            .collect();
        Self {
            floor: policy.quick_confirm_floor(),
            docs,
        }
    }

    /// The per-document summaries, in scan order.
    pub fn docs(&self) -> &[DocReviewSummary] {
        &self.docs
    }
    /// The quick-confirm [`Confidence`] floor this summary was computed under.
    pub fn floor(&self) -> Confidence {
        self.floor
    }
    /// Total Tier-1 (quick-confirm) candidates across every document.
    pub fn quick_confirm(&self) -> usize {
        self.docs.iter().map(|d| d.quick_confirm).sum()
    }
    /// Total Tier-2 (careful-review) candidates across every document.
    pub fn careful_review(&self) -> usize {
        self.docs.iter().map(|d| d.careful_review).sum()
    }
    /// Total candidates across every document (`quick_confirm() + careful_review()`).
    pub fn total(&self) -> usize {
        self.quick_confirm() + self.careful_review()
    }
}

/// One document's APPLY result: how many accepted spans were written, and how many
/// were `stale` (accepted in the selection but no longer present in the document
/// at apply time — the content changed between scan and apply, so they were skipped
/// rather than written at a now-wrong offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocApply {
    pub(crate) doc_id: u64,
    pub(crate) class: DataClass,
    pub(crate) applied: usize,
    pub(crate) stale: usize,
}

impl DocApply {
    /// The document id.
    pub fn doc_id(&self) -> u64 {
        self.doc_id
    }
    /// The data class.
    pub fn class(&self) -> DataClass {
        self.class
    }
    /// Accepted spans actually written (one marker/replacement each).
    pub fn applied(&self) -> usize {
        self.applied
    }
    /// Accepted spans skipped because they were no longer present at apply time.
    pub fn stale(&self) -> usize {
        self.stale
    }
}

/// The result of [`apply_selection`](RedactionEngine::apply_selection): per-document
/// applied/stale counts.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub(crate) docs: Vec<DocApply>,
}

impl ApplyReport {
    /// The per-document apply results.
    pub fn docs(&self) -> &[DocApply] {
        &self.docs
    }
    /// Total spans applied across all documents.
    pub fn total_applied(&self) -> usize {
        self.docs.iter().map(|d| d.applied).sum()
    }
    /// Total accepted-but-stale spans skipped across all documents.
    pub fn total_stale(&self) -> usize {
        self.docs.iter().map(|d| d.stale).sum()
    }
}

// ===================================================================
// PDF (blob) workflow — Core-mediated true in-PDF redaction reports
// ===================================================================
//
// The byte-typed siblings of the text [`ScanReport`]/[`RedactionReport`], for the
// `redact_pdf` path wired THROUGH `Core` over the binary content plane (see
// [`RedactionEngine::scan_matter_pdf`] / [`RedactionEngine::redact_matter_pdf`] and
// `to-read/runtime.PDF-CORE-WIRING-PROPOSAL.md` §5). The confidentiality split is UNCHANGED:
// candidates carry cleartext for the in-process review only (never egressed, never
// audited); the audit chain gets COUNTS / BREAKDOWN / BYTE LENGTHS only. The reports
// are SEALED (fields private, NOT `Clone`) like [`DocScan`]/[`ScanReport`], so the
// cleartext-bearing candidate list cannot be bulk-copied out.
//
// v1 SCOPE (proposal §5): apply-all + CONFIG-LEVEL review only. A PDF candidate's
// byte offsets are PER-OPERAND reconstructed coordinates with NO stable cross-call
// identity (re-parsing a PDF can renumber/recompress objects), so there is NO
// per-span PDF `Selection` (that is the documented v2 `PdfCandidateId` follow-on,
// deliberately not built). The reviewer sees every candidate from a scan, adjusts
// the ENGINE config, re-scans, and runs the apply-all when satisfied.

/// One PDF document's SCAN result: the candidates `redact_pdf` detected for review
/// (cleartext `matched_value`/`context`, IN-PROCESS review only — never egressed,
/// never audited), the document's redacted bytes DISCARDED. NOTHING was written.
///
/// `low_text` / `diagnostics` are surfaced from [`PdfRedaction`] so a reviewer never
/// mistakes a low candidate count on an image-only/scanned (or bomb-skipped) PDF for
/// "clean" — those pages were not truly examined for identifiers.
///
/// SEALED (like [`DocScan`]): fields PRIVATE, NOT `Clone`.
#[derive(Debug)]
pub struct PdfDocScan {
    pub(crate) doc_id: u64,
    pub(crate) class: DataClass,
    pub(crate) candidates: Vec<RedactionCandidate>,
    pub(crate) low_text: bool,
    pub(crate) diagnostics: Vec<String>,
}

impl PdfDocScan {
    /// The document id scanned.
    pub fn doc_id(&self) -> u64 {
        self.doc_id
    }
    /// The data class it was read under.
    pub fn class(&self) -> DataClass {
        self.class
    }
    /// The detected candidates (cleartext, in-process review only — never egress).
    pub fn candidates(&self) -> &[RedactionCandidate] {
        &self.candidates
    }
    /// `true` when the PDF yielded little/no extractable text (image-only/scanned,
    /// an unmappable font, or a bomb-skipped stream) — do NOT read a low candidate
    /// count as "clean". Carried straight from [`PdfRedaction::low_text`].
    pub fn low_text(&self) -> bool {
        self.low_text
    }
    /// Non-fatal per-stream diagnostics from the PDF parse (skipped/undecodable
    /// streams, budget cut-offs). Content-free (never cleartext).
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
}

/// The result of [`scan_matter_pdf`](RedactionEngine::scan_matter_pdf): per-PDF
/// candidates for review. Nothing has been written; the engine holds no egress, so
/// the cleartext candidates never leave the box.
///
/// SEALED: `docs` is PRIVATE and the type is NOT `Clone`.
#[derive(Debug, Default)]
pub struct PdfScanReport {
    pub(crate) docs: Vec<PdfDocScan>,
}

impl PdfScanReport {
    /// The per-PDF scans (borrowed; the report owns the cleartext).
    pub fn docs(&self) -> &[PdfDocScan] {
        &self.docs
    }
    /// Total PDF documents scanned.
    pub fn docs_scanned(&self) -> usize {
        self.docs.len()
    }
    /// Total candidates detected across all PDFs.
    pub fn total_candidates(&self) -> usize {
        self.docs.iter().map(|d| d.candidates.len()).sum()
    }
}

/// One PDF document's APPLY-ALL redaction result: the candidates removed (cleartext,
/// in-process review only) + the count actually written, plus the `low_text` /
/// `diagnostics` honesty signals. The redacted bytes were written back THROUGH the
/// core (`document_transform_blob`); this report does NOT also hold them (it would
/// be more cleartext to copy around — read them back via [`runtime::Core::matter_read_blob`]).
///
/// SEALED (like [`DocReport`]): fields PRIVATE, NOT `Clone`.
#[derive(Debug)]
pub struct PdfDocRedaction {
    pub(crate) doc_id: u64,
    pub(crate) class: DataClass,
    pub(crate) candidates: Vec<RedactionCandidate>,
    pub(crate) identifiers_removed: usize,
    pub(crate) low_text: bool,
    pub(crate) diagnostics: Vec<String>,
}

impl PdfDocRedaction {
    /// The document id processed.
    pub fn doc_id(&self) -> u64 {
        self.doc_id
    }
    /// The data class it was read/transformed under.
    pub fn class(&self) -> DataClass {
        self.class
    }
    /// The candidates removed from this PDF (cleartext, in-process review only —
    /// never egress these).
    pub fn candidates(&self) -> &[RedactionCandidate] {
        &self.candidates
    }
    /// How many identifier spans were removed (`== candidates().len()`).
    pub fn identifiers_removed(&self) -> usize {
        self.identifiers_removed
    }
    /// `true` when little/no text was extractable (image-only/scanned, unmappable
    /// font, or a bomb-skipped stream) — do NOT read a low count as "clean".
    pub fn low_text(&self) -> bool {
        self.low_text
    }
    /// Non-fatal per-stream diagnostics from the PDF parse (content-free).
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
}

/// The outcome of [`redact_matter_pdf`](RedactionEngine::redact_matter_pdf): which
/// PDFs were processed and the candidates stripped from each. Returned IN-PROCESS
/// for review; the candidates carry cleartext but the engine holds no egress.
///
/// SEALED: `docs` is PRIVATE and the type is NOT `Clone`.
#[derive(Debug, Default)]
pub struct PdfRedactionReport {
    pub(crate) docs: Vec<PdfDocRedaction>,
}

impl PdfRedactionReport {
    /// The per-PDF reports (borrowed; the report owns the cleartext).
    pub fn docs(&self) -> &[PdfDocRedaction] {
        &self.docs
    }
    /// Total PDF documents processed.
    pub fn docs_processed(&self) -> usize {
        self.docs.len()
    }
    /// Total identifiers removed across all PDFs.
    pub fn total_identifiers_removed(&self) -> usize {
        self.docs.iter().map(|d| d.identifiers_removed).sum()
    }
}
