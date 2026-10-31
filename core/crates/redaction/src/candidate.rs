// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealed `RedactionCandidate` type. Extracted from `lib.rs`.

use std::sync::Arc;

use crate::{Confidence, Recognizer};

/// One redaction candidate: an exact matched span in the ORIGINAL document
/// content, plus the cleartext it matched and a short review snippet.
///
/// `start..end` are BYTE offsets into the ORIGINAL content and always fall on
/// valid char boundaries, so `original[start..end] == matched_value()`. CARRIES
/// CLEARTEXT (`matched_value` / `context`): this is sensitive matter data for
/// the in-process review workflow only — it is never egressed and never written
/// to the audit chain (see the crate-level confidentiality split).
///
/// SEALED (FIX, medium): the cleartext-bearing fields are PRIVATE and this type
/// is NOT `Clone`, so a caller holding a [`RedactionReport`] cannot bulk-clone
/// the candidate list (with its matched text + surrounding context) into a
/// `static`, a `Storage` bucket, or a log line. Read access is via the accessors
/// only. (This is intent-enforcement + defense-in-depth; the hard egress
/// guarantee is still the Core's egress broker — this type just stops the
/// cleartext from being trivially copied around as the module count grows.)
#[derive(Debug, PartialEq, Eq)]
pub struct RedactionCandidate {
    /// Byte offset of the match start in the ORIGINAL content (char boundary).
    pub(crate) start: usize,
    /// Byte offset of the match end in the ORIGINAL content (char boundary).
    pub(crate) end: usize,
    /// The exact matched text (the confidential identifier). Cleartext.
    pub(crate) matched_value: String,
    /// Which recognizer matched (PRIMARY recognizer if spans were merged).
    pub(crate) recognizer: Recognizer,
    /// EVERY recognizer that matched this exact span, deterministically ordered
    /// (priority ASC, then label ASC), deduplicated. For an un-merged span this is
    /// just `[recognizer]`. FIX #5: two firm rules that compile to the SAME pattern
    /// scan ONCE and BOTH surface here, so no label is silently lost to the merge.
    /// (The audit breakdown still counts the PRIMARY recognizer only — see
    /// [`recognizer_breakdown`] — so this richer attribution does NOT change the
    /// audit counts.)
    pub(crate) recognizers: Vec<Recognizer>,
    /// A short surrounding snippet (±[`CONTEXT_CHARS`]) for human review.
    /// Cleartext — never egressed, never audited.
    pub(crate) context: String,
    /// The Lever-2 CONFIDENCE tier — a PURE, deterministic ADDITIVE annotation
    /// computed at finalization from (span position, window text, fixed lexicons). It
    /// never changes WHICH candidates fire or their spans; it only annotates this one.
    /// NOT cleartext (a tier, not a value), so it is audit-safe (the audit note records
    /// per-tier COUNTS only). See [`Confidence`].
    pub(crate) confidence: Confidence,
}

impl RedactionCandidate {
    /// Byte offset of the match start in the ORIGINAL content (char boundary).
    pub fn start(&self) -> usize {
        self.start
    }
    /// Byte offset of the match end in the ORIGINAL content (char boundary).
    pub fn end(&self) -> usize {
        self.end
    }
    /// The exact matched text (the confidential identifier). CLEARTEXT — never
    /// egress this; it is review-only matter data.
    pub fn matched_value(&self) -> &str {
        &self.matched_value
    }
    /// Which recognizer matched (PRIMARY recognizer if spans were merged).
    pub fn recognizer(&self) -> &Recognizer {
        &self.recognizer
    }
    /// EVERY recognizer that matched this exact span (deterministically ordered,
    /// deduplicated); `[recognizer()]` for an un-merged span. FIX #5: two firm
    /// rules with the SAME compiled pattern scan once and BOTH appear here.
    pub fn recognizers(&self) -> &[Recognizer] {
        &self.recognizers
    }
    /// A short surrounding snippet (±[`CONTEXT_CHARS`]) for human review.
    /// CLEARTEXT — review-only, never egressed, never audited.
    pub fn context(&self) -> &str {
        &self.context
    }
    /// The Lever-2 CONFIDENCE tier for this candidate — a deterministic ADDITIVE
    /// annotation (NOT cleartext; a tier, not a value). See [`Confidence`].
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Construct a SYNTHETIC candidate NOT produced by the engine's text detection — used
    /// by the PDF metadata pass (`pdf.rs`) to record a removed `/Info` key or the removed
    /// XMP `/Metadata` stream in the review list. These removals are decided by a
    /// scrub-by-default policy (an authoring/path/provenance field) or by a stream-level
    /// detection, not by a text-span match, so they have no meaningful `start`/`end` span
    /// into a document-wide string (both 0). `recognizer_label` is a recognizer NAME (e.g.
    /// `"metadata:Author"`) — never a matched value, so it is audit-safe; it becomes a
    /// [`Recognizer::Custom`]. `matched_value`/`context` are CLEARTEXT review-only (the
    /// caller passes an empty value when surfacing the cleartext would itself leak).
    ///
    /// `pub(crate)`: this bypasses the normal detection pipeline, so it stays internal —
    /// only the PDF metadata pass constructs one.
    pub(crate) fn synthetic(
        matched_value: String,
        recognizer_label: String,
        context: String,
    ) -> Self {
        let recognizer = Recognizer::Custom(Arc::from(recognizer_label.as_str()));
        RedactionCandidate {
            start: 0,
            end: 0,
            matched_value,
            recognizer: recognizer.clone(),
            recognizers: vec![recognizer],
            context,
            // Metadata removals are a deliberate policy/stream decision, not a graded text
            // match; record the lowest tier (advisory only — the candidate is already
            // removed). Keeps the audit per-tier breakdown honest (not a false "High").
            confidence: Confidence::Low,
        }
    }

    /// Construct a synthetic user-TERM candidate for the PDF whitespace-insensitive recall
    /// pass (`pdf.rs`). The ordinary detection missed this term only because a glyph-by-
    /// glyph PDF layout fabricated separator spaces inside it; it IS a user-supplied term
    /// match, so it is recorded with the real [`Recognizer::Term`] (rendered `term`, the
    /// same label a non-fragmented match would carry) and the actual matched cleartext for
    /// the in-process review list. `start`/`end` are the candidate's byte offsets into the
    /// reconstructed RUN text (review metadata only — the PDF splice uses the per-char
    /// source map, not these offsets). Confidence is `High`: a user term is an explicit,
    /// known identifier the firm asked to redact.
    ///
    /// `pub(crate)`: bypasses the normal pipeline, so it stays internal to the crate.
    pub(crate) fn synthetic_term(
        start: usize,
        end: usize,
        matched_value: String,
        context: String,
    ) -> Self {
        RedactionCandidate {
            start,
            end,
            matched_value,
            recognizer: Recognizer::Term,
            recognizers: vec![Recognizer::Term],
            context,
            confidence: Confidence::High,
        }
    }

    /// Construct a synthetic PERSON-NAME candidate for the PDF whitespace-elastic
    /// DETECTED-NAME recall pass (round 6, `pdf.rs`): a name the engine detected
    /// ORGANICALLY elsewhere in the document, re-found at an occurrence a PDF generator
    /// kerning-split mid-word (`Ka thy V ancomerbeke`) or fragmented across runs. It IS a
    /// person-name detection, so it carries the real [`Recognizer::Name`] (same label,
    /// routing, and entity-family placeholder as a directly-matched name). Confidence is
    /// `Medium` (careful review — the elastic re-match is corroborated by the organic
    /// detection but is not itself checksum/structural).
    ///
    /// `pub(crate)`: bypasses the normal pipeline, so it stays internal to the crate.
    pub(crate) fn synthetic_name(
        start: usize,
        end: usize,
        matched_value: String,
        context: String,
    ) -> Self {
        RedactionCandidate {
            start,
            end,
            matched_value,
            recognizer: Recognizer::Name,
            recognizers: vec![Recognizer::Name],
            context,
            confidence: Confidence::Medium,
        }
    }

    /// Construct a synthetic ADDRESS-FAMILY candidate for the PDF whitespace-insensitive
    /// recall pass (`pdf.rs`) — the address-family analogue of [`synthetic_term`]. The
    /// ordinary detection missed this structured address only because a glyph-by-glyph PDF
    /// layout fabricated separator whitespace INSIDE it (`#16-03` reconstructed as
    /// `# 16-0 3`); it IS a real structured-address / postal match, recorded with the SAME
    /// `recognizer` a non-fragmented match would carry (`Recognizer::Address`, or a precise
    /// locale postal `Recognizer::Locale(<cc>:postal)`) so its audit/type label is identical.
    /// `start`/`end` are byte offsets into the reconstructed RUN text (review metadata only —
    /// the PDF splice uses the per-char source map, not these offsets).
    ///
    /// `confidence` is caller-supplied: the address family is CAREFUL-tier (never High, never
    /// quick-confirm — [`Recognizer::Address`] is neither checksum nor structural, and a
    /// precise postal locale row has no class lexicon), so the caller passes the same tier a
    /// non-fragmented address candidate would receive. It is a NORMAL built-in/locale (NOT
    /// advisory — advisory is the aggressive-locale flag), so it stays default-ON in apply.
    ///
    /// `pub(crate)`: bypasses the normal pipeline, so it stays internal to the crate.
    pub(crate) fn synthetic_address(
        start: usize,
        end: usize,
        matched_value: String,
        context: String,
        recognizer: Recognizer,
        confidence: Confidence,
    ) -> Self {
        RedactionCandidate {
            start,
            end,
            matched_value,
            recognizer: recognizer.clone(),
            recognizers: vec![recognizer],
            context,
            confidence,
        }
    }
}
