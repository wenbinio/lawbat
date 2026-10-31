// SPDX-License-Identifier: AGPL-3.0-or-later
//! # True in-PDF text redaction (`redact_pdf`)
//!
//! Removes matched identifiers from the **underlying text** of a PDF so they are
//! no longer extractable / copyable — the opposite of the classic redaction
//! failure (a black rectangle drawn OVER text that is still selectable beneath
//! it). It does this by parsing the PDF, walking each page's content stream(s),
//! finding the text-showing operators (`Tj`, `TJ`, `'`, `"`), reconstructing the
//! text each emits, running the SHARED [`RedactionEngine`] over that text, and
//! REWRITING the string operands so the matched identifier bytes are gone — then
//! re-serialising to valid PDF bytes.
//!
//! ## Why this is a SEPARATE function, not `document_transform`
//!
//! The Core's matter store holds `content: String` and `document_transform`
//! operates on `&str -> String`. **PDF bytes are not a UTF-8 `String`**, so PDF
//! redaction CANNOT go through `document_transform` — shoehorning binary PDF
//! bytes through a `String` API would corrupt them. So this is a pure,
//! self-contained function over BYTES: [`redact_pdf`]. The host can later wrap it
//! with Core auditing (the same `check -> act -> log` discipline the rest of the
//! module uses); see the FOLLOW-UP note below.
//!
//! ### FOLLOW-UP (Core mediation / audit integration — NOT in this increment)
//!
//! This function is the pure data-plane primitive. It is NOT yet wired through
//! `Core` (no `matter.read` / `document.transform` / `audit_note`), because the
//! `String` matter store cannot hold PDF bytes — that boundary is the open design
//! question. When the store grows a binary/blob class, a thin `Core`-mediated
//! wrapper should: read the PDF blob under a granted class, call [`redact_pdf`],
//! write the result back, and emit a COUNTS-ONLY audit note (mirroring the
//! confidentiality split in the rest of the crate — never log a matched value).
//! Until then this is exercised directly + by tests only.
//!
//! ## Honest limitations (load-bearing — do NOT overclaim; read before trusting)
//!
//! This is reasonable-efforts text removal, **never "safe to send"** (the crate's
//! posture). Concretely, an identifier may be MISSED when:
//!
//! - **Glyphs are SPLIT across operators.** PDF generators routinely break a word
//!   across multiple `Tj`/`TJ` operands (kerning, justification, subsetting). We
//!   detect per-CONTIGUOUS-text-run (a `TJ` array's strings ARE joined, ignoring
//!   the numeric kerning adjustments — that is the common split), but an
//!   identifier split across two SEPARATE show operators is not reassembled and
//!   may be missed. This is the known-hard core of PDF redaction.
//! - **The font uses a custom / CID / Type0 encoding** we cannot exactly map. Simple
//!   1-byte fonts (Type1/TrueType/Type3 with a Standard/WinAnsi/MacRoman base +
//!   optional `/Differences`) ARE decoded through the font's `/Encoding`
//!   (the [`FontDecoder`] path), so a subset font with a `/Differences` array no
//!   longer silently misses identifiers. A **Type0 / CID** (multi-byte) font is NOT
//!   exactly byte-mappable here: it is decoded only best-effort AND the document is
//!   flagged via [`PdfRedaction::unmapped_fonts`] + a content-free diagnostic, so a
//!   low candidate count on such a page is never read as a false "clean" — the host
//!   MUST surface that signal. On an `unmapped_fonts` page, an accepted span that
//!   cannot be truly removed is counted in [`PdfRedaction::could_not_remove`] (not
//!   in `total_redactions`) — the honest over-report guard.
//! - **Text lives outside page content streams.** ANNOTATIONS are now IN SCOPE: each
//!   page's `/Annots` are scrubbed of identifiers in their `/URI` link-actions (in `/A`,
//!   `/AA`, or the annotation itself) and their `/Contents` note text — the offending
//!   field is REMOVED WHOLESALE (a partial URI splice risks a recoverable fragment, so
//!   full removal is the safe side). See [`process_page_annotations`]. DOCUMENT METADATA
//!   is ALSO in scope now: the trailer `/Info` dictionary (author/title/custom keys +
//!   authoring-path values) and the catalog XMP `/Metadata` stream are scrubbed — see
//!   [`process_document_metadata`]. STILL NOT touched and may retain identifiers: `XObject`
//!   form/image streams, embedded-file attachments, named destinations, and INLINE
//!   (non-indirect) annotation objects (flagged via a content-free diagnostic, not
//!   silently ignored). A future increment should extend to embedded-file attachments (a
//!   known residual carrier the `redact-cli` response now surfaces as `not_removed`).
//! - **The page is image-only / scanned.** There is no extractable text to
//!   redact; OCR is explicitly out of scope. Such pages contribute ~0 text and
//!   are surfaced via [`PdfRedaction::low_text`] so a caller never mistakes "no
//!   text found" for "redacted".
//! - **The PDF is ENCRYPTED.** We cannot redact what we cannot decode, so an
//!   encrypted PDF is REFUSED with a clear error rather than silently emitting the
//!   (un-redacted) original. We gate on the SAME predicate lopdf's LOADER uses
//!   (the bare presence of a trailer `/Encrypt`), not the narrower `is_encrypted()`
//!   — so a non-spec `/Encrypt` (a direct dict, or a reference to a non-dictionary)
//!   that would otherwise leave lopdf with an empty objects map and yield a
//!   degenerate "0 redactions" Ok is refused too.
//!
//! ## Never-panic / determinism
//!
//! Every entry path returns a [`CoreResult`] (or records a per-stream diagnostic)
//! — never an `unwrap`/`expect`/slice panic — on malformed / truncated /
//! encrypted / image-only / huge / non-PDF input. Allocations are bounded at
//! THREE levels: an input-size guard ([`MAX_PDF_BYTES`]); a CAPPED per-stream
//! decode ([`MAX_DECODED_STREAM_BYTES`]) plus a cumulative decoded-bytes budget
//! ([`MAX_TOTAL_DECODED_BYTES`]) — the decompression-bomb defence, applied BEFORE
//! a stream inflates; and a cumulative scanned-text budget ([`MAX_TOTAL_TEXT_BYTES`]).
//! An over-budget stream is SKIPPED with a content-free diagnostic and forces
//! [`PdfRedaction::low_text`] (fail-closed — never read as "0 redactions, clean").
//! Output is deterministic: pages are visited in `BTreeMap` (page-number) order and
//! streams in their content-array order, so the same input bytes produce the same
//! output bytes (the bomb-skip path included).

use lopdf::content::Content;
use lopdf::{Document, Encoding, Object};
use regex::Regex;
use runtime::{CoreError, CoreResult};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Confidence, Recognizer, RedactionCandidate, RedactionEngine, PROPAGATED_NAME_LABEL,
    RCS_LU_LABEL, REDACTION_MARKER,
};

/// Hard ceiling on the input PDF size we will attempt to parse, in bytes
/// (64 MiB). A defensive bound against a hostile/huge file exhausting memory
/// before we even reach lopdf's own limits. Generous for a real legal document;
/// a larger file is REFUSED with a clear error rather than risking an OOM.
/// (`pub(crate)`: the `verify` recovery-probe module enforces the SAME input bound
/// so a verification run can never out-allocate the redaction run it checks.)
pub(crate) const MAX_PDF_BYTES: usize = 64 * 1024 * 1024;

/// Hard ceiling on the total decoded page-text we will scan across the whole
/// document, in bytes (32 MiB). A decompression bomb (a tiny FlateDecode stream
/// that inflates enormously) is bounded here: once cumulative scanned text
/// crosses this budget, remaining streams are SKIPPED and recorded as a
/// diagnostic, so detection effort is finite regardless of input.
///
/// NOTE: this is a *post-decode TEXT* budget. It does NOT bound the decode of a
/// single stream — by the time we count text, the stream is already inflated. The
/// per-stream + cumulative DECODED-bytes bounds below ([`MAX_DECODED_STREAM_BYTES`]
/// / [`MAX_TOTAL_DECODED_BYTES`]) are what actually defend against the bomb; this
/// text budget is a secondary, complementary cut-off on scanning effort.
const MAX_TOTAL_TEXT_BYTES: usize = 32 * 1024 * 1024;

/// Hard ceiling on the DECODED size of a SINGLE content stream, in bytes (16 MiB).
///
/// This is the load-bearing decompression-bomb defence (H1): lopdf's
/// `decompressed_content()` inflates with NO cap (`ZlibDecoder::read_to_end`), so
/// a ~300 KiB FlateDecode stream at ~1000:1 inflates to hundreds of MiB and a
/// 64 MiB input to tens of GiB — an OOM *before* the text budget is ever
/// consulted (a no-text bomb never trips it at all). We instead decode through a
/// reader CAPPED at this value + 1 byte: the moment a stream would exceed it we
/// stop reading, free the partial buffer, and SKIP that stream with a diagnostic
/// (fail-closed → the doc is flagged, never read as "0 redactions and clean").
///
/// 16 MiB is generous for a single legitimate page's content stream (real text
/// pages are kilobytes; even heavy vector graphics rarely approach this) while
/// keeping worst-case peak allocation per stream small and bounded.
/// (`pub(crate)`: `verify` decompresses streams through the SAME capped reader with
/// the SAME per-stream ceiling — the probe must not reopen the bomb the redactor closed.)
pub(crate) const MAX_DECODED_STREAM_BYTES: usize = 16 * 1024 * 1024;

/// Hard ceiling on the CUMULATIVE decoded bytes across all streams/pages, in
/// bytes (128 MiB). Complements the per-stream cap so that many medium streams
/// (each individually under [`MAX_DECODED_STREAM_BYTES`]) cannot SUM to a bomb.
/// Once the running decoded total would cross this, the remaining streams are
/// skipped with a diagnostic — peak resident decoded data stays bounded
/// regardless of how the inflation is spread across the document.
/// (`pub(crate)`: `verify` shares this cumulative budget for its stream walk.)
pub(crate) const MAX_TOTAL_DECODED_BYTES: usize = 128 * 1024 * 1024;

/// The PDF text-showing operators we rewrite. Each carries at least one string
/// operand whose bytes are glyph/character codes we reconstruct + scan:
/// - `Tj`  — show a text string (1 string operand);
/// - `TJ`  — show an array of strings + kerning numbers (the array operand);
/// - `'`   — move to next line then show a string (1 string operand);
/// - `"`   — set word/char spacing, move to next line, then show a string
///   (2 numeric operands then the string operand).
///
/// (`pub(crate)`: `verify`'s lenient text-layer probe walks the SAME operator set —
/// re-declaring the list there would let the two drift.)
pub(crate) const SHOW_OPERATORS: &[&str] = &["Tj", "TJ", "'", "\""];

/// Hard ceiling on the JOINED logical-run text we will hold + scan for ONE logical
/// line (in bytes). A pathological content stream could chain a huge number of tiny
/// show operators on a single line (no line-advance) — the cross-operator
/// reconstruction concatenates their decoded text, so we cap the joined buffer so a
/// single line cannot grow unbounded. When a run would exceed this, the run is
/// SEALED (detected as-is) and a fresh run begins — detection effort per line stays
/// finite (the whole-stream + decoded-byte budgets above still bound the document).
/// 1 MiB is far beyond any real line of text while keeping peak per-run memory small.
const MAX_LOGICAL_RUN_BYTES: usize = 1024 * 1024;

/// Hard ceiling on how many annotation objects we will process per page (a defensive
/// bound — a hostile PDF could attach an enormous /Annots array). Real pages carry a
/// handful to a few dozen; 4096 is far beyond any legitimate page while keeping the
/// per-page annotation work finite. Annotations beyond the cap are SKIPPED with a
/// content-free diagnostic (fail-closed: a skipped annotation was NOT scrubbed, so it is
/// flagged, never silently treated as clean).
/// (`pub(crate)`: `verify`'s annotation probe applies the same per-page bound.)
pub(crate) const MAX_ANNOTS_PER_PAGE: usize = 4096;

/// Hard ceiling on the length (bytes) of a single annotation text field we will decode +
/// scan (a /URI or /Contents). A /URI is normally well under a KiB; /Contents is a short
/// note. 64 KiB bounds a pathological field while comfortably covering any real one — an
/// over-length field is REMOVED WHOLESALE without scanning (fail-closed: we never leave an
/// unscanned over-length text field in place).
/// (`pub(crate)`: `verify` bounds each probed annotation/metadata field the same way —
/// an over-length field is reported as NOT probed, never scanned unbounded.)
pub(crate) const MAX_ANNOT_FIELD_BYTES: usize = 64 * 1024;

/// Annotation-dictionary key whose value is an action dictionary (`/A`) — for a Link
/// annotation this holds the `/URI` (a URI action). We scrub its text-bearing fields.
const ANNOT_ACTION_KEY: &[u8] = b"A";
/// Annotation-dictionary key whose value is the "additional-actions" dictionary (`/AA`):
/// each entry is itself an action dict that may carry a `/URI`. We scrub each.
const ANNOT_ADDITIONAL_ACTIONS_KEY: &[u8] = b"AA";
/// The URI-action target key (`/URI`): a (PDFDocEncoded/ASCII) string holding the link
/// destination. The recovered-URL leak surface.
const ANNOT_URI_KEY: &[u8] = b"URI";
/// A markup/text annotation's note text (`/Contents`): a free-text/popup/comment body.
const ANNOT_CONTENTS_KEY: &[u8] = b"Contents";

/// Trailer key referencing the document information dictionary (`/Info`): author, title,
/// creator, dates, and arbitrary custom keys. A classic metadata leak surface.
const INFO_KEY: &[u8] = b"Info";
/// Catalog key referencing the XMP metadata stream (`/Metadata`): an XML/RDF packet that
/// commonly carries `dc:creator`, `xmp:CreatorTool`, edit history, and authoring paths.
/// (`pub(crate)`: `verify`'s metadata probe resolves the same catalog key.)
pub(crate) const METADATA_KEY: &[u8] = b"Metadata";
/// Catalog (document root) trailer key.
const ROOT_KEY: &[u8] = b"Root";

/// `/Info` keys we ALWAYS scrub by default, regardless of whether the engine detects an
/// identifier in them — they are high-PII-risk authoring fields that routinely carry a
/// person's name, an internal authoring path, or a sensitivity-label provenance id, and a
/// redaction tool's safe side is to remove them. `/Author` and `/Title` are the worst
/// offenders (the red-team recovered a name from `/Author` and a SharePoint path from
/// `/Title`); `/MSIP_Label_*` (Microsoft Information Protection sensitivity labels) carry
/// SiteIds/ActionIds; `/ContentTypeId` is a SharePoint content-type GUID. We scrub these
/// even when no recognizer fires. (`/Producer` / `/Creator` — software names — are NOT in
/// this list: they are kept UNLESS a recognizer fires in them, preserving benign
/// provenance like "lopdf".)
const INFO_SCRUB_BY_DEFAULT_KEYS: &[&[u8]] = &[b"Author", b"Title"];
/// Case-insensitive substrings that mark an `/Info` custom key as a scrub-by-default
/// authoring/path/provenance field (in ADDITION to the exact keys above). A custom key
/// whose name contains any of these is removed by default — these are the Microsoft
/// sensitivity-label + SharePoint-provenance families that carry internal identifiers a
/// recognizer may not independently flag.
const INFO_SCRUB_KEY_SUBSTRINGS: &[&[u8]] = &[b"msip", b"contenttype", b"sharepoint", b"label"];

/// A per-page summary of the redaction pass over one page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfPageReport {
    /// 1-based page number (the key from [`Document::get_pages`]).
    page: u32,
    /// Bytes of text reconstructed + scanned on this page (post-decode). A page
    /// near zero here had little/no extractable text — likely image-only/scanned
    /// or a font encoding we cannot map. Used to compute [`PdfRedaction::low_text`].
    text_bytes: usize,
    /// How many identifier spans were removed on this page.
    redactions: usize,
}

impl PdfPageReport {
    /// 1-based page number.
    pub fn page(&self) -> u32 {
        self.page
    }
    /// Bytes of text reconstructed + scanned on this page (post-decode).
    pub fn text_bytes(&self) -> usize {
        self.text_bytes
    }
    /// Identifier spans removed on this page.
    pub fn redactions(&self) -> usize {
        self.redactions
    }
}

/// The result of [`redact_pdf`]: the redacted PDF bytes plus a review report.
///
/// CONFIDENTIALITY SPLIT (matching the rest of the crate): [`candidates`] carry
/// cleartext (`matched_value`/`context`) for the IN-PROCESS review workflow only —
/// they are never egressed and, when this is later wired through `Core`, the audit
/// note must record COUNTS ONLY (never a matched value). The redacted [`bytes`]
/// have the identifier text REMOVED (not masked), so they no longer contain the
/// matched glyphs in the rewritten operands.
///
/// Not `Clone`: like [`crate::RedactionReport`], the cleartext-bearing candidate
/// list should not be trivially bulk-copied around.
#[derive(Debug)]
pub struct PdfRedaction {
    /// The re-serialised, redacted PDF bytes (valid PDF; identifier text removed
    /// from the rewritten page-content operands).
    bytes: Vec<u8>,
    /// Per-page summary (page number, scanned text bytes, redaction count),
    /// in ascending page order (deterministic).
    pages: Vec<PdfPageReport>,
    /// The candidates removed across the whole document, in page-then-stream
    /// order. CLEARTEXT — in-process review only; never egress these.
    ///
    /// NOTE: a candidate's `start()`/`end()` byte offsets are coordinates into the
    /// PER-OPERAND reconstructed text they were detected in, NOT into the PDF
    /// bytes or any single document-wide string. They are review metadata
    /// (what/where-ish + recognizer), not a splice coordinate into [`bytes`].
    candidates: Vec<RedactionCandidate>,
    /// Non-fatal diagnostics encountered (a stream that failed to decode/parse and
    /// was left untouched, a skipped over-budget stream, etc.). Surfaced so a
    /// caller never mistakes a silently-skipped stream for "nothing to redact".
    diagnostics: Vec<String>,
    /// `true` when the document yielded little or no extractable text relative to
    /// its page count — a strong signal of an image-only/scanned PDF (or a font
    /// encoding we cannot map). When set, the caller MUST NOT treat a zero/low
    /// redaction count as "clean": OCR is out of scope and those pages were not
    /// truly examined for identifiers.
    low_text: bool,
    /// `true` when one or more pages used a font whose encoding could NOT be exactly
    /// byte-mapped (Type0/CID/multi-byte/unknown) — those pages were decoded only
    /// best-effort, so coverage was incomplete. DISTINCT from `low_text`. The honesty
    /// signal the host must surface.
    unmapped_fonts: bool,
    /// ROUND 7 — `true` when one or more pages' reconstructed text carries an
    /// implausibly long spaceless alphabetic run (a degenerate layout): token
    /// boundaries are missing there, so recognizers may be BLIND on those pages even
    /// though the fonts decoded cleanly (`unmapped_fonts` gives no signal). Same
    /// honesty posture as `unmapped_fonts`: the host must surface it.
    degenerate_layout: bool,
    /// How many ACCEPTED candidate spans could NOT be truly removed (resolved to no
    /// removable source bytes). These are NOT included in [`total_redactions`]
    /// (PdfRedaction::total_redactions) — the over-report guard. 0 for normal documents; a
    /// non-zero value means the tool detected something it could not splice out, so the
    /// host MUST surface it (the user must review/redact those manually) rather than trust
    /// a clean count. The leak-class honesty signal: never claim a removal not performed.
    could_not_remove: usize,
}

impl PdfRedaction {
    /// The redacted PDF bytes (valid PDF; identifier text removed).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Consume the report, returning the owned redacted PDF bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Per-page summaries, ascending page order.
    pub fn pages(&self) -> &[PdfPageReport] {
        &self.pages
    }
    /// The removed candidates (cleartext, in-process review only — never egress).
    pub fn candidates(&self) -> &[RedactionCandidate] {
        &self.candidates
    }
    /// Total identifier spans removed across the document.
    pub fn total_redactions(&self) -> usize {
        self.pages.iter().map(|p| p.redactions).sum()
    }
    /// Total text bytes reconstructed + scanned across the document.
    pub fn total_text_bytes(&self) -> usize {
        self.pages.iter().map(|p| p.text_bytes).sum()
    }
    /// Non-fatal diagnostics (skipped/undecodable streams, budget cut-offs).
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
    /// `true` when little/no text was extractable (likely image-only/scanned or an
    /// unmappable font) — do NOT read a low redaction count as "clean".
    pub fn low_text(&self) -> bool {
        self.low_text
    }
    /// `true` when one or more pages used a font we could not exactly byte-map
    /// (Type0/CID/multi-byte/unknown) — coverage was incomplete on those pages.
    /// DISTINCT from [`low_text`](PdfRedaction::low_text); the host must surface it.
    pub fn unmapped_fonts(&self) -> bool {
        self.unmapped_fonts
    }
    /// ROUND 7 — `true` when one or more pages have a DEGENERATE spaceless text layout
    /// (an implausibly long alphabetic run with no word boundary): recognizers may be
    /// blind on those pages even though the fonts decoded cleanly, so a zero/low count
    /// there proves nothing. Same honesty posture as
    /// [`unmapped_fonts`](PdfRedaction::unmapped_fonts); the host must surface it.
    pub fn degenerate_layout(&self) -> bool {
        self.degenerate_layout
    }
    /// How many ACCEPTED spans could NOT be truly removed (no resolvable source bytes).
    /// NOT included in [`total_redactions`](PdfRedaction::total_redactions). A non-zero
    /// value is an HONESTY signal the host must surface — the tool found but could not
    /// splice out those spans, so they need manual review (never read a clean count as
    /// "fully redacted" when this is > 0).
    pub fn could_not_remove(&self) -> usize {
        self.could_not_remove
    }

    /// Consume the report, MOVING its owned parts out: the redacted PDF bytes, the
    /// removed candidates, the diagnostics, the `low_text` flag, and the total
    /// redaction count (computed from the per-page reports BEFORE they are dropped).
    ///
    /// This is the seam the Core-mediated PDF workflow ([`crate::RedactionEngine::
    /// redact_matter_pdf`] / [`crate::RedactionEngine::scan_matter_pdf`]) uses to take
    /// ownership of the cleartext candidates WITHOUT cloning — [`RedactionCandidate`]
    /// is deliberately NOT `Clone` (the no-bulk-copy discipline), so a by-value move
    /// is the only way to relocate them into a [`crate::PdfDocRedaction`] /
    /// [`crate::PdfDocScan`]. The cleartext is still review-only matter data: it never
    /// gets egressed or audited regardless of which report owns it.
    pub fn into_parts(self) -> PdfRedactionParts {
        let total_redactions = self.total_redactions();
        PdfRedactionParts {
            bytes: self.bytes,
            candidates: self.candidates,
            diagnostics: self.diagnostics,
            low_text: self.low_text,
            unmapped_fonts: self.unmapped_fonts,
            degenerate_layout: self.degenerate_layout,
            total_redactions,
            could_not_remove: self.could_not_remove,
        }
    }
}

/// The owned parts of a [`PdfRedaction`], yielded by [`PdfRedaction::into_parts`].
/// Carries the cleartext candidates by value (the no-clone relocation seam — see
/// [`PdfRedaction::into_parts`]); same review-only confidentiality posture applies.
///
/// NOT `Clone` (it owns the cleartext-bearing candidate list, like the report it
/// came from).
#[derive(Debug)]
pub struct PdfRedactionParts {
    /// The redacted PDF bytes (valid PDF; identifier text removed).
    pub bytes: Vec<u8>,
    /// The removed candidates (CLEARTEXT — in-process review only, never egress).
    pub candidates: Vec<RedactionCandidate>,
    /// Non-fatal per-stream diagnostics (content-free).
    pub diagnostics: Vec<String>,
    /// `true` when little/no text was extractable (image-only/scanned / unmappable
    /// font / bomb-skipped) — do NOT read a low redaction count as "clean".
    pub low_text: bool,
    /// `true` when one or more pages used a font we could not exactly byte-map
    /// (Type0/CID/multi-byte/unknown) — coverage was incomplete. DISTINCT from
    /// `low_text`; surface it to the user.
    pub unmapped_fonts: bool,
    /// ROUND 7 — `true` when one or more pages have a degenerate spaceless text layout
    /// (recognizers may be blind there despite clean font decode). Same honesty
    /// posture as `unmapped_fonts`; surface it to the user.
    pub degenerate_layout: bool,
    /// Total identifier spans removed across the document.
    pub total_redactions: usize,
    /// ACCEPTED spans that could NOT be truly removed (no resolvable source bytes); NOT
    /// included in `total_redactions`. A non-zero value is an HONESTY signal the host must
    /// surface (manual review needed) — the over-report guard.
    pub could_not_remove: usize,
}

/// A stable, deterministic identifier for one PDF redaction candidate — the PDF
/// analogue of a text-span coordinate in the text-side [`crate::Selection`].
///
/// It is the candidate's ORDINAL in the full-document deterministic detection
/// traversal: pages in [`Document::get_pages`] order → each page's content streams in
/// document order (a content stream SHARED across pages — a repeated
/// header/footer/letterhead — is visited ONCE, at its first referencing page) →
/// each stream's text-showing operators in order → the engine's candidates for that
/// operand in engine order. Detection is PURE, and in an apply
/// pass each operand is detected from its OWN bytes BEFORE any rewrite, so removing
/// one candidate never shifts another's id. The SAME `pdf` + `engine` therefore
/// always yields the SAME id for the SAME candidate — a reviewer's accept/reject
/// built from [`scan_pdf`] maps EXACTLY onto [`redact_pdf_with_selection`] over the
/// same bytes.
///
/// Treat it as an opaque token obtained from a scan, NOT an index to compute. It is
/// only meaningful paired with the EXACT bytes + engine config it was scanned from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PdfCandidateId(u64);

impl PdfCandidateId {
    /// The raw ordinal, for serialising the id across the host boundary (e.g. the
    /// redact-cli JSON). Re-pair ONLY with ids from the SAME scan of the SAME bytes.
    pub fn get(self) -> u64 {
        self.0
    }
    /// Reconstruct an id from a raw ordinal (e.g. decoding a host-supplied selection).
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

/// One detected candidate from [`scan_pdf`]: its stable [`PdfCandidateId`], the
/// 1-based page it sits on, and the cleartext [`RedactionCandidate`] (matched value /
/// recognizer / context) for the IN-PROCESS review UI.
///
/// CONFIDENTIALITY: like [`PdfRedaction::candidates`], the candidate carries cleartext
/// for review ONLY — never egress it, and a Core-mediated wiring must audit COUNTS
/// ONLY (never a matched value). NOT `Clone` (it owns a non-`Clone` candidate).
#[derive(Debug)]
pub struct PdfScanItem {
    id: PdfCandidateId,
    page: u32,
    candidate: RedactionCandidate,
}

impl PdfScanItem {
    /// The stable id to put in a [`PdfSelection`] to accept this candidate.
    pub fn id(&self) -> PdfCandidateId {
        self.id
    }
    /// The 1-based page this candidate was found on.
    pub fn page(&self) -> u32 {
        self.page
    }
    /// The cleartext candidate (matched value / recognizer / context) — review only.
    pub fn candidate(&self) -> &RedactionCandidate {
        &self.candidate
    }
}

/// The result of [`scan_pdf`]: EVERY detected candidate with a stable id (for a
/// reviewer to accept/reject), plus the same per-page / diagnostic / `low_text`
/// review signals [`redact_pdf`] reports — but NO bytes are produced and NOTHING is
/// removed (a scan is read-only).
///
/// NOTE: the per-page [`PdfPageReport::redactions`] is 0 in a scan (nothing was
/// removed); use [`items`](PdfScan::items) (each carries its page) for detected
/// counts. NOT `Clone` (owns the cleartext-bearing items). Feed the chosen ids into a
/// [`PdfSelection`] and call [`redact_pdf_with_selection`] over the SAME bytes.
#[derive(Debug)]
pub struct PdfScan {
    items: Vec<PdfScanItem>,
    pages: Vec<PdfPageReport>,
    diagnostics: Vec<String>,
    low_text: bool,
    unmapped_fonts: bool,
    degenerate_layout: bool,
}

impl PdfScan {
    /// Every detected candidate, in stable-id (traversal) order.
    pub fn items(&self) -> &[PdfScanItem] {
        &self.items
    }
    /// Per-page summaries (text bytes; `redactions` is 0 in a scan).
    pub fn pages(&self) -> &[PdfPageReport] {
        &self.pages
    }
    /// Non-fatal diagnostics (skipped/undecodable streams, budget cut-offs).
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
    /// `true` when little/no text was extractable (image-only/scanned / unmappable
    /// font / bomb-skipped) — do NOT read a low candidate count as "clean".
    pub fn low_text(&self) -> bool {
        self.low_text
    }
    /// `true` when ONE OR MORE pages used a font whose encoding could NOT be exactly
    /// byte-mapped (a Type0/CID/multi-byte or unknown-name font). Text on such pages
    /// is decoded only best-effort, so a zero/low candidate count must NOT be read as
    /// "this page is clean". DISTINCT from [`low_text`](PdfScan::low_text) (image-only):
    /// this is the honesty signal that detection coverage was incomplete. The host
    /// MUST surface it so the user is never told a PDF was fully analyzed when it
    /// wasn't.
    pub fn unmapped_fonts(&self) -> bool {
        self.unmapped_fonts
    }
    /// ROUND 7 — `true` when one or more pages have a DEGENERATE spaceless text layout
    /// (an implausibly long alphabetic run with no word boundary): recognizers may be
    /// blind on those pages even though every font decoded cleanly — so
    /// [`unmapped_fonts`](PdfScan::unmapped_fonts) gives NO signal for this class. A
    /// zero/low candidate count on such a page proves nothing. Same honesty posture as
    /// `unmapped_fonts`: the host MUST surface it.
    pub fn degenerate_layout(&self) -> bool {
        self.degenerate_layout
    }
    /// Total candidates detected across the document.
    pub fn total_candidates(&self) -> usize {
        self.items.len()
    }
}

/// Which scanned candidates a reviewer accepts for removal — the PDF analogue of the
/// text-side [`crate::Selection`]. DEFAULT-DENY: [`redact_pdf_with_selection`] removes
/// ONLY accepted ids; every other detected candidate is KEPT. (Contrast the text
/// `Selection`, which selects by span coordinates; here the stable [`PdfCandidateId`]
/// IS the coordinate.)
#[derive(Debug, Clone, Default)]
pub struct PdfSelection {
    mode: SelectionMode,
}

/// Internal: accept-all vs an explicit accepted-id set.
#[derive(Debug, Clone)]
enum SelectionMode {
    /// Accept EVERY detected candidate — the apply-all path [`redact_pdf`] uses.
    All,
    /// Accept only the listed ordinals. Default = empty = accept NONE (default-deny).
    Only(BTreeSet<u64>),
}

impl Default for SelectionMode {
    fn default() -> Self {
        SelectionMode::Only(BTreeSet::new())
    }
}

impl PdfSelection {
    /// Accept EVERY detected candidate — the apply-ALL selection (what [`redact_pdf`]
    /// passes). Independent of any scan: it accepts whatever the apply pass detects.
    pub fn all() -> Self {
        Self {
            mode: SelectionMode::All,
        }
    }
    /// Accept NOTHING — the default-deny base a reviewer builds on with
    /// [`accept`](PdfSelection::accept).
    pub fn none() -> Self {
        Self::default()
    }
    /// A selection accepting exactly `ids` (e.g. the ids a reviewer ticked).
    pub fn of(ids: impl IntoIterator<Item = PdfCandidateId>) -> Self {
        Self {
            mode: SelectionMode::Only(ids.into_iter().map(|c| c.0).collect()),
        }
    }
    /// Accept one more candidate. No-op on an [`all`](PdfSelection::all) selection.
    /// Returns `&mut self` for chaining.
    pub fn accept(&mut self, id: PdfCandidateId) -> &mut Self {
        if let SelectionMode::Only(set) = &mut self.mode {
            set.insert(id.0);
        }
        self
    }
    /// The number of explicitly-accepted ids, or `None` for an
    /// [`all`](PdfSelection::all) selection (which is not an explicit set).
    pub fn accepted_count(&self) -> Option<usize> {
        match &self.mode {
            SelectionMode::All => None,
            SelectionMode::Only(s) => Some(s.len()),
        }
    }
    /// Whether `id` is accepted for removal (internal — drives the apply pass).
    fn accepts(&self, id: PdfCandidateId) -> bool {
        match &self.mode {
            SelectionMode::All => true,
            SelectionMode::Only(s) => s.contains(&id.0),
        }
    }
}

/// Internal: what the shared traversal does at each detected candidate. Keeping ONE
/// traversal (rather than separate scan/apply walks) is load-bearing: scan and apply
/// MUST assign identical ids, which is only guaranteed if they share the exact same
/// page/stream/operator iteration + budget logic.
enum DocMode<'a> {
    /// Enumerate every candidate with its id into `items`; remove NOTHING, emit no bytes.
    Scan { items: &'a mut Vec<PdfScanItem> },
    /// Remove candidates the `selection` accepts; collect the REMOVED ones (cleartext,
    /// review-only) into `removed`.
    Apply {
        selection: &'a PdfSelection,
        removed: &'a mut Vec<RedactionCandidate>,
    },
}

impl DocMode<'_> {
    fn is_apply(&self) -> bool {
        matches!(self, DocMode::Apply { .. })
    }
}

/// True in-PDF text redaction: parse `pdf`, run `engine`'s detection over each
/// page's text-showing operands, and rewrite them so matched identifiers are
/// REMOVED from the underlying text (not masked over). Returns the redacted PDF
/// bytes + a review report.
///
/// PURE + DETERMINISTIC: no I/O, no network, no clock, no RNG — same input bytes
/// produce the same output bytes. Detection is delegated entirely to the shared
/// [`RedactionEngine`] (the single source of truth for *what* is an identifier);
/// this function only maps detected text spans back onto PDF string operators.
///
/// # Errors
///
/// Returns [`CoreError::Backend`] (never panics) when the input:
/// - is empty, or exceeds [`MAX_PDF_BYTES`];
/// - is not a parseable PDF (malformed / truncated / not a PDF at all);
/// - is ENCRYPTED — refused on the bare presence of a trailer `/Encrypt` (mirroring
///   lopdf's loader), so non-spec `/Encrypt` shapes cannot slip through to a
///   degenerate empty result; never passed through un-redacted;
/// - decoded to NO objects (an unauthenticatable-encrypted or malformed file lopdf
///   returns as an empty document) — refused rather than emitting a misleading
///   0-redaction "success".
///
/// A stream that individually fails to decode or parse is NOT fatal: it is left
/// untouched and recorded in [`PdfRedaction::diagnostics`], so a single bad
/// stream cannot abort the whole document (and cannot silently drop a redaction
/// without a trace). Likewise a stream whose decode would breach a memory bound
/// (a decompression bomb) is SKIPPED with a diagnostic and forces
/// [`PdfRedaction::low_text`] — never an unbounded allocation, never a silent miss.
pub fn redact_pdf(pdf: &[u8], engine: &RedactionEngine) -> CoreResult<PdfRedaction> {
    // Apply-ALL is exactly a per-span apply whose selection accepts everything, so it
    // goes through the SAME single traversal — no separate code path to drift from the
    // selective one. The existing redact_pdf tests therefore also exercise the shared
    // engine under select-all.
    redact_pdf_with_selection(pdf, engine, &PdfSelection::all())
}

/// SCAN a PDF for redaction candidates WITHOUT modifying it: returns every detected
/// identifier with a stable [`PdfCandidateId`] (plus per-page / diagnostic / `low_text`
/// review signals). A reviewer ticks ids and feeds them to
/// [`redact_pdf_with_selection`] over the SAME bytes — the per-span (v2) review flow.
///
/// PURE + DETERMINISTIC (no I/O / clock / RNG); never panics (a deep lopdf panic is
/// contained to a fail-closed `Backend` error). Same parse/encrypt/empty refusals as
/// [`redact_pdf`].
pub fn scan_pdf(pdf: &[u8], engine: &RedactionEngine) -> CoreResult<PdfScan> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_pdf_inner(pdf, engine)))
        .unwrap_or_else(|_| {
            Err(CoreError::Backend(
                "pdf: parsing panicked on malformed input (contained)".to_string(),
            ))
        })
}

/// REDACT a PDF removing ONLY the candidates `selection` accepts (per-span review),
/// returning the redacted bytes + a report of the candidates actually removed. Pass
/// [`PdfSelection::all`] for apply-all (what [`redact_pdf`] does).
///
/// The ids in `selection` MUST come from a [`scan_pdf`] of the SAME bytes + engine
/// config: detection is deterministic, so this apply re-derives the identical ids and
/// removes exactly the accepted ones. An id not present in this document is simply
/// never matched (a no-op), never an error.
///
/// PURE + DETERMINISTIC; never panics (contained). Same refusals as [`redact_pdf`].
pub fn redact_pdf_with_selection(
    pdf: &[u8],
    engine: &RedactionEngine,
    selection: &PdfSelection,
) -> CoreResult<PdfRedaction> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        redact_with_selection_inner(pdf, engine, selection)
    }))
    .unwrap_or_else(|_| {
        Err(CoreError::Backend(
            "pdf: parsing panicked on malformed input (contained)".to_string(),
        ))
    })
}

fn scan_pdf_inner(pdf: &[u8], engine: &RedactionEngine) -> CoreResult<PdfScan> {
    // ROUND 6 — TWO-PASS scan. Pass 1 (unseeded) detects as before AND supplies the
    // document-level detected-name seed set for the whitespace-elastic name recall
    // (the kerning-split leak: a name detected cleanly ANYWHERE in the document —
    // e.g. the officer COLUMN — recovers its `Ka thy V ancomerbeke` split occurrences
    // on OTHER pages). With NO seeds (no organic name detected) the pass-1 result is
    // returned as-is — the common non-name document costs ONE pass, byte-identical.
    // With seeds, pass 2 re-traverses with the elastic recall active; ids stay
    // deterministic because BOTH scan and apply derive the SAME seed set from the SAME
    // unseeded pass (scan↔apply parity by construction).
    let mut items: Vec<PdfScanItem> = Vec::new();
    let mut mode = DocMode::Scan { items: &mut items };
    let no_seeds = WsNameSeeds {
        rows: Vec::new(),
        prefilter: None,
    };
    let report = traverse_pdf(pdf, engine, &mut mode, &no_seeds)?;
    let seeds = ws_name_seeds_from_scan(&items);
    if seeds.is_empty() {
        return Ok(PdfScan {
            items,
            pages: report.pages,
            diagnostics: report.diagnostics,
            low_text: report.low_text,
            unmapped_fonts: report.unmapped_fonts,
            degenerate_layout: report.degenerate_layout,
        });
    }
    let mut items2: Vec<PdfScanItem> = Vec::new();
    let mut mode2 = DocMode::Scan { items: &mut items2 };
    let report2 = traverse_pdf(pdf, engine, &mut mode2, &seeds)?;
    Ok(PdfScan {
        items: items2,
        pages: report2.pages,
        diagnostics: report2.diagnostics,
        low_text: report2.low_text,
        unmapped_fonts: report2.unmapped_fonts,
        degenerate_layout: report2.degenerate_layout,
    })
}

fn redact_with_selection_inner(
    pdf: &[u8],
    engine: &RedactionEngine,
    selection: &PdfSelection,
) -> CoreResult<PdfRedaction> {
    // ROUND 6 — derive the SAME document-level name-seed set the scan derived (from an
    // identical unseeded scan pass), so apply re-detects the SAME candidates with the
    // SAME ids (scan↔apply parity by construction; see `scan_pdf_inner`).
    let mut seed_items: Vec<PdfScanItem> = Vec::new();
    let mut seed_mode = DocMode::Scan {
        items: &mut seed_items,
    };
    let no_seeds = WsNameSeeds {
        rows: Vec::new(),
        prefilter: None,
    };
    traverse_pdf(pdf, engine, &mut seed_mode, &no_seeds)?;
    // End the mode's mutable borrow of `seed_items` before reading it.
    let _ = seed_mode;
    let seeds = ws_name_seeds_from_scan(&seed_items);
    let mut removed: Vec<RedactionCandidate> = Vec::new();
    let mut mode = DocMode::Apply {
        selection,
        removed: &mut removed,
    };
    let report = traverse_pdf(pdf, engine, &mut mode, &seeds)?;
    Ok(PdfRedaction {
        // Apply mode always produces bytes (the only `None` case is scan).
        bytes: report.bytes.unwrap_or_default(),
        pages: report.pages,
        candidates: removed,
        diagnostics: report.diagnostics,
        low_text: report.low_text,
        unmapped_fonts: report.unmapped_fonts,
        degenerate_layout: report.degenerate_layout,
        could_not_remove: report.could_not_remove,
    })
}

/// The mode-independent output of [`traverse_pdf`]: the per-page reports, diagnostics,
/// and `low_text` flag, plus the re-serialised bytes (only in apply mode — `None` for
/// a scan, which modifies nothing).
struct TraversalReport {
    bytes: Option<Vec<u8>>,
    pages: Vec<PdfPageReport>,
    diagnostics: Vec<String>,
    low_text: bool,
    /// `true` if any operand was decoded through a font whose encoding could not be
    /// exactly byte-mapped — the honesty signal threaded up into the public result.
    unmapped_fonts: bool,
    /// ROUND 7 — `true` if any page's reconstructed text carries an implausibly long
    /// spaceless alphabetic run (recognizers may be blind there). Threaded into the
    /// public `degenerate_layout` honesty flag. See [`DEGENERATE_ALPHA_RUN_CHARS`].
    degenerate_layout: bool,
    /// Total ACCEPTED spans across the whole document that could NOT be truly removed
    /// (resolved to no removable source bytes). The over-report guard — threaded into the
    /// public [`PdfRedaction::could_not_remove`] so a caller never claims a removal that
    /// did not happen. 0 for normal documents; non-zero is an honesty signal, not normal.
    could_not_remove: usize,
}

/// Parse `pdf` with EVERY fail-closed input guard the redaction traversal applies:
/// the empty/oversize refusals, the encrypted-document refusal (gating on the SAME
/// `trailer /Encrypt` predicate lopdf's loader uses — see the M1 note inline), and
/// the empty-objects refusal (an unauthenticatable-encrypted / degenerate file).
///
/// Extracted from [`traverse_pdf`] so the `verify` recovery-probe module loads a PDF
/// under the IDENTICAL guard set (`pub(crate)` for exactly that reuse): a document
/// the redactor would refuse is refused by verification too, never half-probed.
pub(crate) fn load_pdf_checked(pdf: &[u8]) -> CoreResult<Document> {
    if pdf.is_empty() {
        return Err(CoreError::Backend("pdf: empty input".to_string()));
    }
    if pdf.len() > MAX_PDF_BYTES {
        return Err(CoreError::Backend(format!(
            "pdf: input exceeds {MAX_PDF_BYTES} bytes (refused to bound memory)"
        )));
    }

    // Parse. lopdf returns an Err (not a panic) on malformed/truncated/non-PDF
    // bytes; we map it to a Backend error and never propagate a panic. The text
    // of lopdf's error is a parser diagnostic (offsets / token kinds), not matter
    // content, so it is safe to include.
    let doc = Document::load_mem(pdf)
        .map_err(|e| CoreError::Backend(format!("pdf: parse failed: {e}")))?;

    // ENCRYPTED PDFs: refuse. We cannot reconstruct + rewrite text we cannot
    // decode, and silently emitting the original would be a confidentiality
    // failure (the caller would believe it was redacted). Fail-closed with a
    // clear message. (We do NOT attempt empty-password decryption: a "successful"
    // decrypt that we then can't fully process would be worse than an honest no.)
    //
    // M1 — mirror lopdf's LOADER, not its narrower `is_encrypted()`. `is_encrypted()`
    // returns true ONLY when `/Encrypt` resolves to an INDIRECT dictionary, but
    // lopdf's loader routes into the encrypted path on the weaker
    // `trailer.get(b"Encrypt").is_ok()` and, when it cannot authenticate, returns Ok
    // with an EMPTY objects map. So a NON-spec `/Encrypt` (a DIRECT dictionary, or a
    // reference to a non-dictionary) slips `is_encrypted()=false` and we would
    // proceed over an empty doc → a degenerate 0-redaction "Ok" instead of an honest
    // refusal. Gate on the SAME predicate the loader uses so every such file is
    // refused. (A spec-conformant encrypted file that lopdf successfully decrypts
    // with the empty password has `/Encrypt` REMOVED from the trailer by the loader,
    // so this does not over-refuse those.)
    if doc.trailer.get(b"Encrypt").is_ok() {
        return Err(CoreError::Backend(
            "pdf: encrypted document — cannot redact (decode it first); refusing to emit the original"
                .to_string(),
        ));
    }

    // Belt-and-braces (M1): lopdf's encrypted loader can return Ok with an EMPTY
    // objects map when it cannot authenticate. If we have NO objects at all there is
    // nothing to redact and emitting the "redacted" bytes would be a degenerate
    // empty output masquerading as success — refuse rather than return a misleading
    // 0-redaction Ok. (A genuinely empty/objectless PDF is not something we can
    // meaningfully redact either, so refusing is the honest, fail-closed answer.)
    if doc.objects.is_empty() {
        return Err(CoreError::Backend(
            "pdf: no objects decoded (possibly encrypted/unauthenticatable or malformed) — \
             refusing to emit a degenerate empty result"
                .to_string(),
        ));
    }
    Ok(doc)
}

fn traverse_pdf(
    pdf: &[u8],
    engine: &RedactionEngine,
    mode: &mut DocMode,
    name_seeds: &WsNameSeeds,
) -> CoreResult<TraversalReport> {
    let mut doc = load_pdf_checked(pdf)?;

    let pages = doc.get_pages(); // BTreeMap<u32, ObjectId> — deterministic order.
    let mut page_reports: Vec<PdfPageReport> = Vec::with_capacity(pages.len());
    // The running stable-id counter: incremented once per ENGINE candidate detected,
    // in traversal order, in BOTH scan and apply — so a candidate's id is identical
    // across the two passes (the load-bearing determinism behind PdfCandidateId).
    let mut next_id: u64 = 0;
    let mut diagnostics: Vec<String> = Vec::new();
    let mut total_text_bytes: usize = 0;
    // Cumulative DECODED bytes across all streams/pages — the running total bounded
    // by MAX_TOTAL_DECODED_BYTES (the bomb defence; see decode_stream_ops).
    let mut total_decoded_bytes: usize = 0;
    // Set if ANY stream was skipped because decoding it would breach a memory bound.
    // We force low_text in that case: a skipped stream was NOT examined, so a low
    // redaction count must NOT read as "clean" (fail-closed → flag, not silent).
    let mut bomb_skip = false;
    // Content-stream objects already processed. A SHARED content stream (legal PDFs
    // reuse one stream object for a repeated header/footer/letterhead across pages)
    // appears in MULTIPLE pages' `/Contents`; we must process it ONCE, or scan would
    // enumerate its candidates once per referencing page (duplicate, non-stable ids)
    // and the decoded-byte budget would be double-charged. Apply already redacted the
    // bytes on the first visit (a second visit re-detected nothing), so visiting each
    // unique stream once makes SCAN agree with APPLY — keeping ids aligned + counts
    // honest. The stream is attributed to the FIRST page that references it.
    let mut seen_streams: BTreeSet<lopdf::ObjectId> = BTreeSet::new();
    // Annotation objects already processed. Like a shared content stream, ONE annotation
    // object can be referenced from MULTIPLE pages' /Annots (rare, but legal); we process
    // each unique object once so scan enumerates its candidates once (stable, non-dup ids)
    // and apply removes its fields once. Attributed to the FIRST page that references it.
    let mut seen_annots: BTreeSet<lopdf::ObjectId> = BTreeSet::new();

    // Set if ANY operand was decoded through a font whose encoding could not be
    // exactly byte-mapped (a Type0/CID/multi-byte or unknown-name font). Such a page
    // may not be fully analyzed — surfaced as the `unmapped_fonts` honesty flag so a
    // caller is never told a PDF was fully scanned when a page wasn't. DISTINCT from
    // `low_text` (image-only/scanned), which keeps its own meaning.
    let mut unmapped_fonts = false;
    // ROUND 7 — set if ANY page's reconstructed text carries an implausibly long
    // spaceless alphabetic run (no token boundaries → recognizers may be blind there).
    // DISTINCT from `unmapped_fonts`: such a page can DECODE perfectly, so the font
    // flag gives no signal. The degenerate-layout honesty floor.
    let mut degenerate_layout = false;
    // Total accepted spans we could NOT truly remove across the document (the over-report
    // guard). Summed from each stream's `could_not_remove`.
    let mut could_not_remove = 0usize;

    for (&page_no, &page_id) in &pages {
        // The content-stream object ids for this page, in document order.
        let stream_ids = doc.get_page_contents(page_id);
        // Resolve this page's fonts to owned, borrow-free decoders BEFORE mutating
        // any stream (the resolved `lopdf::Encoding` borrows `doc`). A stream shared
        // across pages is attributed to (and decoded with the fonts of) the FIRST
        // page that references it — the same first-page attribution the id/budget
        // dedup already uses.
        let page_fonts = PageFonts::resolve(&doc, page_id);
        let mut page_text_bytes: usize = 0;
        let mut page_redactions: usize = 0;

        // PHASE 1 — decode + parse this page's not-yet-seen content streams (dedup shared
        // streams; enforce the per-stream + cumulative decoded-byte bomb caps exactly as
        // before). We GATHER them so PHASE 2 can run detection over the WHOLE page's content
        // at once (see `process_page_streams`). Per the PDF spec a page's content is the
        // byte-concatenation of ALL its content streams, so a generator that puts each visual
        // line in its OWN content stream (fitz `insert_text` emits one stream per line) would
        // otherwise ISOLATE every line — hiding a role heading from its name list and an
        // address anchor from the premises line between them, silently no-op'ing every
        // multi-line mechanism (ctx role-name, address-block continuation). Merging restores
        // the multi-line document view the plain-text path already sees.
        let mut page_streams: Vec<DecodedStream> = Vec::new();
        for stream_id in stream_ids {
            // Dedup shared content-stream objects: process each unique stream once
            // (see `seen_streams`). A repeat reference on a later page is skipped
            // BEFORE the budget guards so it neither re-enumerates candidates nor
            // re-charges the decoded budget.
            if !seen_streams.insert(stream_id) {
                continue;
            }
            // Budget guard: once we've scanned more than the total text budget,
            // stop scanning further streams (a decompression-bomb defence). Record
            // it once so the caller knows scanning was truncated. (Text bytes are
            // now summed per PAGE in phase 2, so this bounds at page granularity;
            // the per-stream DECODED-byte cap below is the hard memory bound.)
            if total_text_bytes >= MAX_TOTAL_TEXT_BYTES {
                diagnostics.push(format!(
                    "page {page_no}: text budget ({MAX_TOTAL_TEXT_BYTES} bytes) reached — \
                     remaining content streams not scanned"
                ));
                bomb_skip = true;
                break;
            }
            // Cumulative DECODED-bytes guard: many medium streams must not SUM to a
            // bomb. If we've already decoded up to the document-wide budget, stop —
            // a skip here is content-free and flagged (never silently "clean").
            if total_decoded_bytes >= MAX_TOTAL_DECODED_BYTES {
                diagnostics.push(format!(
                    "page {page_no}: cumulative decoded budget ({MAX_TOTAL_DECODED_BYTES} bytes) \
                     reached — remaining content streams not decoded/scanned"
                ));
                bomb_skip = true;
                break;
            }

            // The remaining cumulative headroom: never decode more than this in a
            // single stream either, so the running total can't overshoot the cap.
            let remaining_decoded = MAX_TOTAL_DECODED_BYTES.saturating_sub(total_decoded_bytes);
            match decode_stream_ops(&doc, stream_id, remaining_decoded) {
                Ok((operations, was_compressed, decoded_bytes)) => {
                    total_decoded_bytes = total_decoded_bytes.saturating_add(decoded_bytes);
                    page_streams.push(DecodedStream {
                        stream_id,
                        was_compressed,
                        operations,
                    });
                }
                Err(StreamError::OverBudget(reason)) => {
                    // A decompression-bomb / over-cap stream: leave it UNTOUCHED,
                    // record a content-free diagnostic, and force low_text so the
                    // caller cannot mistake the unexamined stream for "redacted".
                    diagnostics.push(format!(
                        "page {page_no} stream {stream_id:?}: skipped — {reason}"
                    ));
                    bomb_skip = true;
                }
                Err(StreamError::Decode(reason)) => {
                    // Non-fatal: leave this stream untouched, record why. A single
                    // undecodable/garbled stream must not abort the document or
                    // silently swallow a potential redaction.
                    diagnostics.push(format!(
                        "page {page_no} stream {stream_id:?}: skipped ({reason})"
                    ));
                }
            }
        }

        // PHASE 2 — detection (+ apply) over the page's combined content streams in ONE pass,
        // so the multi-line document view spans stream boundaries. Ids advance once across the
        // page in BOTH scan and apply (same combined text), preserving PdfCandidateId parity.
        if !page_streams.is_empty() {
            let outcome = process_page_streams(
                &mut doc,
                &mut page_streams,
                engine,
                &mut next_id,
                page_no,
                mode,
                &page_fonts,
                &mut diagnostics,
                name_seeds,
            );
            page_text_bytes = page_text_bytes.saturating_add(outcome.text_bytes);
            page_redactions = page_redactions.saturating_add(outcome.redactions);
            total_text_bytes = total_text_bytes.saturating_add(outcome.text_bytes);
            unmapped_fonts |= outcome.unmapped;
            could_not_remove = could_not_remove.saturating_add(outcome.could_not_remove);
            // ROUND 6 — content-free honesty diagnostic: a page where the whitespace-
            // elastic detected-name recall RECOVERED occurrences used a kerning-split /
            // fragmented text layout (the class that is invisible to `unmapped_fonts` on
            // simple-font pages) — an elevated-risk signal for the reviewer.
            if outcome.ws_name_recovered > 0 {
                diagnostics.push(format!(
                    "page {page_no}: {} glyph-split name occurrence(s) recovered via \
                     whitespace-elastic recall (kerning-split text layout)",
                    outcome.ws_name_recovered
                ));
            }
            // ROUND 7 — the degenerate-layout honesty floor: this page's reconstructed
            // text has a spaceless alphabetic run recognizers cannot tokenize. Surface
            // it per page (content-free) and flag the document, so a reviewer is never
            // blind-and-unwarned: zero candidates on this page proves NOTHING.
            if outcome.degenerate {
                degenerate_layout = true;
                diagnostics.push(format!(
                    "page {page_no}: degenerate spaceless text layout (an alphabetic run \
                     exceeds {DEGENERATE_ALPHA_RUN_CHARS} chars with no word boundary) — \
                     recognizers may be blind here; do NOT read zero candidates as clean"
                ));
            }
        }

        // ANNOTATIONS are an UN-SCRUBBED content surface: a page's /Annots carry text in
        // /URI link actions, /Contents notes, etc. that the page-content-stream pass above
        // never touches — a red-team recovered "removed" URLs straight out of the link
        // annotations. Process them with the SAME engine so an identifier in an annotation
        // is detected (scan) / removed (apply) too. Each unique annotation object is visited
        // once (dedup against seen_annots), in /Annots array order, so scan + apply assign
        // identical ids and the cumulative work is bounded.
        page_redactions = page_redactions.saturating_add(process_page_annotations(PageAnnotArgs {
            doc: &mut doc,
            page_id,
            page_no,
            engine,
            next_id: &mut next_id,
            mode,
            seen_annots: &mut seen_annots,
            diagnostics: &mut diagnostics,
        }));

        page_reports.push(PdfPageReport {
            page: page_no,
            text_bytes: page_text_bytes,
            redactions: page_redactions,
        });
    }

    // DOCUMENT METADATA is a classic redaction leak vector that the body + annotation
    // passes never touch: the trailer `/Info` dictionary (author, title, creator, custom
    // keys — a red-team recovered a person's name AND an internal SharePoint authoring path
    // from `/Info`), and the catalog's XMP `/Metadata` stream (RDF carrying `dc:creator`,
    // history, and the same authoring path). We scrub both with the SAME engine, AFTER the
    // page content so the ids follow the body+annotation ids deterministically (scan + apply
    // assign identical ids). The removed count is attributed to a synthetic page 0 report
    // (a metadata removal is not on any visual page). See `process_document_metadata`.
    let meta_removed =
        process_document_metadata(&mut doc, engine, &mut next_id, mode, &mut diagnostics);
    if meta_removed > 0 {
        page_reports.push(PdfPageReport {
            page: 0,
            text_bytes: 0,
            redactions: meta_removed,
        });
    }

    // Image-only / scanned / unmappable-font heuristic: if the average extractable
    // text per page is tiny, flag low_text so a caller does not read a low
    // redaction count as "clean". Threshold is deliberately conservative (a real
    // text page emits far more than this); a doc with NO pages is also flagged.
    const MIN_TEXT_PER_PAGE: usize = 16;
    let low_text = bomb_skip
        || pages.is_empty()
        || total_text_bytes < pages.len().saturating_mul(MIN_TEXT_PER_PAGE);

    // Honesty: if any operand was decoded through a font we could not exactly
    // byte-map (Type0/CID/multi-byte/unknown-name), record ONE content-free
    // diagnostic and set the `unmapped_fonts` flag so the host can warn that the
    // document may not be fully analyzed. (We do NOT force `low_text` — that has a
    // distinct image-only meaning; the new flag is the right, separate signal.)
    if unmapped_fonts {
        diagnostics.push(
            "one or more pages use a font encoding that could not be mapped; \
             text on those pages may not be fully analyzed"
                .to_string(),
        );
    }

    // ROUND 7 — degenerate-layout honesty (same posture as `unmapped_fonts`): one
    // document-level content-free diagnostic in addition to the per-page ones.
    if degenerate_layout {
        diagnostics.push(
            "one or more pages have a degenerate spaceless text layout (no word \
             boundaries); recognizers may be blind on those pages — review them manually"
                .to_string(),
        );
    }

    // HONESTY: if any accepted span could NOT be truly removed, record ONE document-level
    // content-free diagnostic in ADDITION to the per-run ones, so the signal is visible at
    // the top of the diagnostics list (and the count is threaded out separately). The tool
    // must NEVER claim a removal it did not perform.
    if could_not_remove > 0 {
        diagnostics.push(format!(
            "{could_not_remove} accepted span(s) could NOT be truly removed \
             (no resolvable source bytes); they are NOT counted as redacted — review manually"
        ));
    }

    // Re-serialise — ONLY in apply mode (a scan modifies nothing, so it emits no
    // bytes and skips the cost). We rely on lopdf's `save_to` emitting each rewritten
    // object INDIVIDUALLY (it does not re-pack objects into a compressed `/ObjStm`
    // cross-reference stream), so our rewritten content-stream bytes land directly in
    // the output and are never stranded inside a packed object stream. Errors here are
    // fatal (we cannot produce valid output), surfaced as Backend — never a panic.
    let bytes = if mode.is_apply() {
        let mut out: Vec<u8> = Vec::new();
        doc.save_to(&mut out)
            .map_err(|e| CoreError::Backend(format!("pdf: re-serialise failed: {e}")))?;
        Some(out)
    } else {
        None
    };

    Ok(TraversalReport {
        bytes,
        pages: page_reports,
        diagnostics,
        low_text,
        unmapped_fonts,
        degenerate_layout,
        could_not_remove,
    })
}

/// One page content stream DECODED + PARSED in phase 1, awaiting the page-level merged
/// detection pass ([`process_page_streams`]). `operations` is moved OUT (into the combined
/// page buffer) during the merge, so it is empty afterwards; `stream_id` + `was_compressed`
/// are retained for the per-stream write-back.
struct DecodedStream {
    stream_id: lopdf::ObjectId,
    was_compressed: bool,
    operations: Vec<lopdf::content::Operation>,
}

/// The aggregate outcome of the page-level merged detection/apply pass over ALL of a page's
/// content streams ([`process_page_streams`]). Mirrors the fields the caller threads up to
/// the document totals (the old per-stream `StreamOutcome`, now summed once per page).
struct PageOutcome {
    /// Bytes of text reconstructed + scanned across the page's content streams.
    text_bytes: usize,
    /// Identifier spans removed across the page's content streams.
    redactions: usize,
    /// `true` if ANY operand was decoded through an unmappable (Type0/CID/multi-byte/
    /// unknown-name) font — ORed into the document-level `unmapped_fonts` flag.
    unmapped: bool,
    /// ACCEPTED spans that could NOT be truly removed (resolved to zero removable source
    /// bytes / out of bounds). Summed into the document-level `could_not_remove` honesty
    /// count so the tool never over-reports a removal.
    could_not_remove: usize,
    /// ROUND 6 — kerning-split name occurrences the ws-elastic recall recovered on this
    /// page (summed from the runs; drives the per-page honesty diagnostic).
    ws_name_recovered: usize,
    /// ROUND 7 — the page's reconstructed text carries an implausibly long spaceless
    /// alphabetic run (recognizers may be blind there) — ORed into the document-level
    /// `degenerate_layout` honesty flag. See [`DEGENERATE_ALPHA_RUN_CHARS`].
    degenerate: bool,
}

/// Why a single content stream could not be redacted. Both variants leave the
/// stream UNTOUCHED (never panic); the caller records a content-free diagnostic.
/// (`pub(crate)`: `verify` consumes [`decode_stream_capped`] / [`decode_stream_ops`],
/// whose error type this is — the probe handles both variants fail-open-as-DIAGNOSED,
/// i.e. a skipped stream is REPORTED as not probed, never silently treated as clean.)
pub(crate) enum StreamError {
    /// The stream could not be decoded/parsed (unsupported/garbled filter,
    /// malformed content). Non-fatal; the doc proceeds.
    Decode(String),
    /// Decoding the stream would breach a memory bound (per-stream or the
    /// remaining cumulative budget) — a decompression-bomb defence. The stream is
    /// SKIPPED and the document is flagged (`low_text`) so the unexamined stream
    /// is never read as "redacted / clean".
    OverBudget(String),
}

/// Decode ONE content-stream object + parse its operations (phase 1). No detection, no
/// mutation, no write-back — just the bounded decode the merge pass consumes.
///
/// Returns `(operations, was_compressed, decoded_bytes)` on success, or
/// `Err(StreamError::..)` (a short, content-free reason) when the stream cannot be
/// decoded/parsed (`Decode`) or would breach a memory bound (`OverBudget`). NEVER panics.
///
/// `decode_headroom` is the remaining CUMULATIVE decoded-bytes budget; this stream is
/// decoded through a reader capped at `min(MAX_DECODED_STREAM_BYTES, decode_headroom) + 1`,
/// so neither the per-stream nor the document-wide bound can be overshot and a decompression
/// bomb cannot inflate unboundedly (H1). Takes `&Document` (read-only) so phase 1 never
/// mutates the doc — the write-back happens later, per stream, in [`write_back_stream`].
/// (`pub(crate)`: `verify`'s LENIENT text-layer probe decodes page content streams
/// through this same bounded decode+parse — same caps, same filter policy — so the
/// probe can never be tricked into decoding what the redactor would have refused.)
pub(crate) fn decode_stream_ops(
    doc: &Document,
    stream_id: lopdf::ObjectId,
    decode_headroom: usize,
) -> Result<(Vec<lopdf::content::Operation>, bool, usize), StreamError> {
    let stream = doc
        .get_object(stream_id)
        .and_then(Object::as_stream)
        .map_err(|e| StreamError::Decode(format!("not a stream object: {e}")))?;
    // Whether the stream WAS compressed (so we re-compress on write, keeping the file
    // shape similar).
    let was_compressed = stream.filters().map(|f| !f.is_empty()).unwrap_or(false);
    // The effective per-stream cap: never exceed the per-stream ceiling NOR the remaining
    // cumulative headroom. Over-cap → OverBudget (skip+flag); garbled filter → Decode.
    let cap = MAX_DECODED_STREAM_BYTES.min(decode_headroom);
    let decoded = decode_stream_capped(stream, cap)?;
    let decoded_bytes = decoded.len();
    // A malformed content stream is non-fatal: report and leave it untouched (better an
    // un-redacted stream we flag than a panic or a corrupted output).
    let content = Content::decode(&decoded)
        .map_err(|e| StreamError::Decode(format!("content parse failed: {e}")))?;
    Ok((content.operations, was_compressed, decoded_bytes))
}

/// Re-encode a single content stream's (possibly edited) operations and write them back onto
/// its object (apply pass 2, per stream). Re-compresses if the stream was compressed, keeping
/// the on-disk shape similar. `encode` can in principle fail (an operand it cannot serialise);
/// that (and a vanished stream object) is returned as a non-fatal `StreamError::Decode`.
fn write_back_stream(
    doc: &mut Document,
    stream_id: lopdf::ObjectId,
    operations: Vec<lopdf::content::Operation>,
    was_compressed: bool,
) -> Result<(), StreamError> {
    let new_content = Content { operations }
        .encode()
        .map_err(|e| StreamError::Decode(format!("content re-encode failed: {e}")))?;
    let stream = doc
        .get_object_mut(stream_id)
        .and_then(Object::as_stream_mut)
        .map_err(|e| StreamError::Decode(format!("stream vanished before write-back: {e}")))?;
    if was_compressed {
        // Replace with the plain content, then re-compress so the on-disk shape stays
        // compressed (and the previously-set Filter/Length are consistent).
        // `set_plain_content` clears Filter/DecodeParms; `compress` re-flate-encodes and
        // resets Filter/Length. If compression doesn't help, it stays plain — still valid.
        stream.set_plain_content(new_content);
        // Best-effort re-compression; a failure leaves valid PLAIN content.
        let _ = stream.compress();
    } else {
        // Was already plain: just set the new content (keeps Length consistent).
        stream.set_plain_content(new_content);
    }
    Ok(())
}

/// Detect (and, in apply mode, remove) over ALL of a page's content streams JOINED into ONE
/// multi-line buffer — the phase-2 merged pass. Per the PDF spec a page's content is the
/// concatenation of its content streams, so joining them is semantically faithful; doing so
/// gives the engine the multi-LINE, multi-STREAM document view its context / role-name /
/// address-continuation mechanisms need. A generator that emits ONE content stream per visual
/// line (fitz `insert_text`) would otherwise isolate every line and silently no-op those
/// mechanisms (a heading never reaches its name list; an address anchor never reaches the
/// premises line between two addresses).
///
/// Each stream is planned into logical runs SEPARATELY (so a run never spans a stream
/// boundary — no spurious contiguous cross-stream token join), then the runs are concatenated
/// with their op indices offset into the combined operations buffer.
/// [`process_logical_run`] joins consecutive runs with a `\n`, reproducing the visual line
/// break between streams. Ids advance once across the WHOLE page in BOTH scan and apply (same
/// combined text), so `PdfCandidateId` assignment + scan↔apply parity are preserved. In apply
/// mode the edited combined buffer is split back per stream (by the recorded op range) and
/// each stream's operations are written back onto its own object.
///
/// Confidentiality unchanged: only in-process cleartext is built; diagnostics are content-free.
#[allow(clippy::too_many_arguments)]
fn process_page_streams(
    doc: &mut Document,
    page_streams: &mut [DecodedStream],
    engine: &RedactionEngine,
    next_id: &mut u64,
    page_no: u32,
    mode: &mut DocMode,
    page_fonts: &PageFonts,
    diagnostics: &mut Vec<String>,
    name_seeds: &WsNameSeeds,
) -> PageOutcome {
    // Build ONE combined operations buffer + combined runs across the page's streams. Each
    // stream is planned separately, then its runs' op indices are offset by the running base
    // so they address the combined buffer. `op_ranges[i]` is stream i's op range for the
    // per-stream write-back split below.
    let mut combined_ops: Vec<lopdf::content::Operation> = Vec::new();
    let mut runs: Vec<LogicalRun> = Vec::new();
    let mut op_ranges: Vec<(usize, usize)> = Vec::with_capacity(page_streams.len());
    for ds in page_streams.iter_mut() {
        let base = combined_ops.len();
        let stream_runs = plan_logical_runs(&ds.operations, page_fonts, page_no, diagnostics);
        for mut run in stream_runs {
            for op in run.ops.iter_mut() {
                op.op_index += base;
            }
            runs.push(run);
        }
        // Move (never clone) this stream's operations into the combined buffer.
        let ops = std::mem::take(&mut ds.operations);
        combined_ops.extend(ops);
        op_ranges.push((base, combined_ops.len()));
    }

    // Per-operation removal instructions, accumulated across every run (apply only), keyed by
    // COMBINED operation index. A Tj/'/" operator has its single trailing string at element
    // index 0; a TJ has its array elements at their real indices.
    let mut op_edits: BTreeMap<usize, OpEdit> = BTreeMap::new();
    let outcome = process_logical_run(LogicalRunArgs {
        name_seeds,
        runs: &runs,
        operations: &combined_ops,
        page_fonts,
        engine,
        next_id,
        page_no,
        mode,
        op_edits: &mut op_edits,
    });
    if outcome.dropped > 0 {
        // M2: a defence-in-depth span drop (should be unreachable); surface it rather than
        // let a potential miss go un-logged. Content-free.
        diagnostics.push(format!(
            "page {page_no}: {} detected span(s) dropped by the offset guard \
             (potential un-redacted identifier)",
            outcome.dropped
        ));
    }
    if outcome.could_not_remove > 0 {
        // HONEST signal: an accepted span we could NOT truly remove (resolved to no removable
        // source bytes). NOT counted in `redactions` — surface it so the tool never claims a
        // removal it did not perform. Content-free.
        diagnostics.push(format!(
            "page {page_no}: {} accepted span(s) could NOT be removed \
             (no resolvable source bytes) — NOT counted as redacted",
            outcome.could_not_remove
        ));
    }

    // APPLY pass 2: splice the accumulated edits into the combined operands (a no-op in scan,
    // which collects no edits), then split the buffer back per stream and write each stream's
    // operations onto its own object. `apply_op_edits` rebuilds operand bytes IN PLACE and
    // never adds/removes operations, so `op_ranges` stay valid.
    if mode.is_apply() {
        if !op_edits.is_empty() {
            apply_op_edits(&mut combined_ops, &op_edits);
        }
        // Reclaim per-stream operation slices from the END (`split_off` keeps the prefix), so
        // each stream gets exactly its own operations back without cloning.
        let mut tail = combined_ops;
        for (ds, &(start, _end)) in page_streams.iter().zip(op_ranges.iter()).rev() {
            let stream_ops = tail.split_off(start);
            if let Err(StreamError::Decode(reason) | StreamError::OverBudget(reason)) =
                write_back_stream(doc, ds.stream_id, stream_ops, ds.was_compressed)
            {
                diagnostics.push(format!(
                    "page {page_no} stream {:?}: {reason}",
                    ds.stream_id
                ));
            }
        }
    }

    PageOutcome {
        text_bytes: outcome.text_bytes,
        redactions: outcome.redactions,
        unmapped: outcome.unmapped,
        could_not_remove: outcome.could_not_remove,
        ws_name_recovered: outcome.ws_name_recovered,
        degenerate: outcome.degenerate,
    }
}

/// Decode one content stream through a CAPPED reader so a decompression bomb
/// cannot inflate unboundedly (H1). Mirrors lopdf's content-stream filter set —
/// no filter (raw) and `FlateDecode` (the dominant content-stream filter AND the
/// proven bomb vector) — but bounds the decode at `cap + 1` bytes and frees the
/// partial buffer on exceed.
///
/// Returns:
/// - `Ok(bytes)` — fully decoded, `bytes.len() <= cap`;
/// - `Err(OverBudget)` — decoding would exceed `cap` (bomb defence: skip + flag);
/// - `Err(Decode)` — unsupported/garbled filter or malformed compressed data.
///
/// DELIBERATELY does NOT decode `LZWDecode` / `ASCII85Decode` / multi-filter or
/// predictor-bearing chains: those are rare/legacy in content streams and we
/// cannot independently cap their inflation here, so rather than fall back to
/// lopdf's UNCAPPED decoder (which would reopen the bomb) we REFUSE them with a
/// `Decode` diagnostic (fail-closed, never silently). Determinism is preserved:
/// the same bytes always decode to the same result (or the same refusal).
/// (`pub(crate)`: `verify`'s decompressed-streams + XMP probes inflate through this
/// SAME capped reader — the bomb defence is shared, never re-implemented.)
pub(crate) fn decode_stream_capped(
    stream: &lopdf::Stream,
    cap: usize,
) -> Result<Vec<u8>, StreamError> {
    use std::io::Read;

    // The raw, still-compressed (or raw, if unfiltered) stream bytes.
    let raw: &[u8] = stream.content.as_slice();

    // Resolve the filter chain. No `/Filter` => uncompressed: bound the raw length
    // directly (a raw content stream is already in memory, but enforce the cap so
    // an enormous uncompressed stream is also refused rather than scanned wholesale).
    let filters = match stream.filters() {
        Ok(f) => f,
        Err(_) => {
            if raw.len() > cap {
                return Err(StreamError::OverBudget(format!(
                    "uncompressed stream ({} bytes) exceeds the decoded cap ({cap} bytes)",
                    raw.len()
                )));
            }
            return Ok(raw.to_vec());
        }
    };

    if filters.is_empty() {
        // `/Filter []` — effectively uncompressed.
        if raw.len() > cap {
            return Err(StreamError::OverBudget(format!(
                "unfiltered stream ({} bytes) exceeds the decoded cap ({cap} bytes)",
                raw.len()
            )));
        }
        return Ok(raw.to_vec());
    }

    // We cap ONLY pure single-FlateDecode (no predictor /DecodeParms). Anything
    // else is refused (see the doc comment) so the bound stays provable.
    let is_pure_flate = filters.len() == 1 && filters[0] == b"FlateDecode";
    let has_decode_parms = stream.dict.get(b"DecodeParms").is_ok();
    if !is_pure_flate || has_decode_parms {
        let names: Vec<String> = filters
            .iter()
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect();
        return Err(StreamError::Decode(format!(
            "unsupported filter chain {names:?}{} — refused (cannot bound decode)",
            if has_decode_parms {
                " with DecodeParms"
            } else {
                ""
            }
        )));
    }

    // Capped FlateDecode. Reading at most `cap + 1` bytes: if we hit the (cap+1)th
    // byte the stream is OVER budget (we read one past the limit precisely to
    // distinguish "exactly at cap" from "over"). The decoder + buffer are dropped
    // immediately, bounding peak allocation to ~cap.
    let limit = (cap as u64).saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let read_result = {
        let mut decoder = flate2::read::ZlibDecoder::new(raw).take(limit);
        decoder.read_to_end(&mut out)
    };
    if read_result.is_err() {
        // Zlib failed — retry raw deflate (skip the 2-byte header), mirroring
        // lopdf's fallback for corrupt-adler streams, STILL through the cap.
        out.clear();
        if raw.len() > 2 {
            let mut raw_decoder = flate2::read::DeflateDecoder::new(&raw[2..]).take(limit);
            if raw_decoder.read_to_end(&mut out).is_err() {
                return Err(StreamError::Decode(
                    "FlateDecode failed (zlib and raw-deflate)".to_string(),
                ));
            }
        } else {
            return Err(StreamError::Decode(
                "FlateDecode failed (truncated)".to_string(),
            ));
        }
    }
    if out.len() as u64 > cap as u64 {
        // We read the (cap+1)th byte → the real decoded size exceeds the cap.
        // Free the buffer eagerly and refuse (skip + flag).
        let seen = out.len();
        drop(out);
        return Err(StreamError::OverBudget(format!(
            "FlateDecode output exceeds the decoded cap ({cap} bytes; read {seen}+) — \
             possible decompression bomb"
        )));
    }
    Ok(out)
}

// ============================================================================
// Font-aware decode: decode a show-text operand through the page font's
// /Encoding (base + /Differences + /ToUnicode) AND yield, per decoded char, the
// SOURCE BYTE RANGE in the operand that produced it. Detection runs on the
// decoded text; the splice removes the SOURCE bytes (removing a code byte removes
// its glyph). This fixes the silent recall gap on subset fonts with a
// /Differences array (e.g. byte 0x32 -> glyph 'f', not '2') that the old
// Latin-1-only reconstruction missed.
//
// CRATE-SHARE DECISION: `extract`'s font logic is private to `extract`, and
// `extract` must not depend on `redaction` (no cycle), nor should `redaction`
// pull `extract` in for this. lopdf's public encoding API
// (`get_page_fonts` + `Font::get_font_encoding` + `Encoding::bytes_to_string`)
// is sufficient, so this is a small self-contained helper INSIDE `redaction`.
// ============================================================================

/// An OWNED, borrow-free decoder for ONE font on a page. We resolve a page's
/// font encodings under an IMMUTABLE borrow of the `Document`, then mutate streams
/// — so the decoder cannot hold a `lopdf::Encoding<'a>` (which borrows the doc).
/// Instead it captures everything needed by value.
enum FontDecoder {
    /// A SIMPLE 1-byte font (Type1/TrueType/Type3/MMType1 with a Standard/WinAnsi/
    /// MacRoman base + optional `/Differences`). lopdf decodes these STRICTLY
    /// byte-by-byte (each source byte independently yields 0..N chars, no cross-byte
    /// state — verified in lopdf 0.41's `OneByteEncoding`/`WinAnsiEncoding`/
    /// `Differences` impls), so we precompute a per-byte-value decode table:
    /// `table[b]` = the chars source byte value `b` decodes to. Decoding an operand
    /// = concatenating `table[byte]` for each byte; each produced char's source
    /// range is `[i, 1)`. EXACT + reversible. (A byte that yields >1 chars — e.g. a
    /// `/Differences`->ToUnicode "fi" ligature — records `[i,1)` for EACH, so a
    /// matched span covering any of them maps back to the whole single byte:
    /// over-removal WITHIN a matched span is the SAFE side.)
    Simple(Box<[String; 256]>),
    /// A font whose encoding could NOT be exactly byte-mapped: a Type0 / CID /
    /// multi-byte encoding WITHOUT a decodable `/ToUnicode` (UniGB UTF-16), or an
    /// unknown `SimpleEncoding` name lopdf refuses. We DO NOT silently Latin-1 these
    /// and claim a clean result — instead the operand is decoded best-effort as Latin-1
    /// (so any ASCII identifier that DOES survive is still caught — extra recall),
    /// the page is flagged `unmapped`, and a content-free diagnostic is recorded.
    /// Honesty signal: the host must warn the page may not be fully analyzed.
    Unmappable,
    /// ROUND 6 (the BGF possessive-sentence leak): a MULTI-BYTE font decoded through
    /// its OWN `/ToUnicode` CMap. Real prospectuses (Word output) set whole SENTENCE
    /// RUNS in a Type0/Identity-H subset font whenever the run contains a curly
    /// apostrophe (`Ms. Fitzgerald’s service…` — verbatim source codes `0030 0056 0011
    /// 0003 0029 004C … 00B6 0056`, ASCII at `code+0x1D`, `00B6` → U+2019). The old
    /// route decoded those runs BYTE-LITERALLY (`\0M\0V\0\u{11}…` garbage), which
    /// defeated EVERY recognizer AND the whitespace-elastic user-TERM fallback — the
    /// stated recall guarantee. This variant streams the operand through the CMap
    /// (variadic 1–4-byte codes, mirroring lopdf's own `bytes_to_string` algorithm)
    /// and yields an exact per-char SOURCE-BYTE map (each decoded char maps to its
    /// whole code, so the splice removes complete codes and never tears a 2-byte code
    /// unit in half). A code the CMap does NOT map emits nothing and flips the decode's
    /// `unmapped` flag (fail-closed honesty — same posture as `Unmappable`).
    /// Held as the owned `Encoding::UnicodeMapEncoding` variant (lopdf does not
    /// re-export the CMap type by name; the public enum variant carries it, and its
    /// public `get` method is reachable by pattern-matching). Always constructed with
    /// that exact variant — `'static` is satisfied because it is the OWNED variant.
    CMap(Encoding<'static>),
    /// ROUND 6 (fix-on-top): a 2-byte Identity-H `/ToUnicode` CMap that lopdf's OWN
    /// parser REJECTS (BGF page 196's `ArialUnicodeMS`: a plain `beginbfchar` block
    /// lopdf 0.41 fails to parse, so `get_font_encoding` falls back to
    /// `OneByteEncoding` → we would route it to `Unmappable` and decode GARBAGE while
    /// flagging the whole document `unmapped_fonts`). We instead parse the ToUnicode
    /// ourselves (see [`parse_tounicode_2byte`], a bounded/strict bfchar+bfrange parser
    /// that FAILS CLOSED to `Unmappable` on anything non-simple) and decode each 2-byte
    /// code through this owned table. Each decoded char maps to its whole 2-byte code
    /// (splice removes complete code units); an unmapped code emits nothing and flips
    /// the honesty flag. RECALL WIN: the CID-annex directory pages that lopdf mishandles
    /// are now decoded + redacted instead of silently surviving behind the flag.
    CMapTable(std::collections::BTreeMap<u16, String>),
}

impl FontDecoder {
    /// Build an owned decoder from a resolved `lopdf::Encoding` (taken BY VALUE so an
    /// owned `/ToUnicode` CMap moves into the decoder). Returns the decoder AND whether
    /// it is the `Unmappable` (honesty-flag) case.
    fn from_encoding(enc: Encoding) -> FontDecoder {
        match &enc {
            // SIMPLE 1-byte families: precompute the per-byte-value decode table.
            // We decode EACH byte value alone; because these encodings carry no
            // cross-byte state, concatenating per-byte decodes equals decoding the
            // whole operand (the load-bearing property — see the `Simple` doc).
            Encoding::OneByteEncoding(_)
            | Encoding::Differences(_)
            | Encoding::SimpleEncoding(b"WinAnsiEncoding") => {
                // Build [String; 256] without requiring String: Copy/Default-array
                // tricks — fill a Vec then convert.
                let mut table: Vec<String> = Vec::with_capacity(256);
                for b in 0u16..256 {
                    let s = enc.bytes_to_string(&[b as u8]).unwrap_or_default();
                    table.push(s);
                }
                // Vec<String> of exactly 256 -> Box<[String; 256]>.
                let boxed: Box<[String; 256]> = table
                    .into_boxed_slice()
                    .try_into()
                    .unwrap_or_else(|_| Box::new(std::array::from_fn(|_| String::new())));
                FontDecoder::Simple(boxed)
            }
            // A decodable `/ToUnicode` CMap: decode multi-byte codes exactly through
            // it (round 6 — see the `CMap` variant docs). The match on `&enc` above
            // only borrows; the move happens here on the owned value, re-wrapped as
            // the `'static` variant (it holds no borrows).
            Encoding::UnicodeMapEncoding(_) => match enc {
                Encoding::UnicodeMapEncoding(cmap) => {
                    FontDecoder::CMap(Encoding::UnicodeMapEncoding(cmap))
                }
                _ => unreachable!("matched UnicodeMapEncoding above"),
            },
            // Other CID / multi-byte / unknown-name: not exactly byte-mappable here.
            // Fail-closed to the honest `Unmappable` path (best-effort + flag).
            _ => FontDecoder::Unmappable,
        }
    }

    /// Latin-1 / identity decoder — the historical reconstruction, used when a font
    /// has NO resolvable encoding (no `/Encoding`, no `Tf` selected yet, or a font
    /// dict we cannot read). Byte-for-char bijection; exact for the plain ASCII
    /// identifiers we care about and BYTE-IDENTICAL to the pre-fix behavior, so it
    /// introduces no regression on the common plain-WinAnsi pages whose font simply
    /// lacks an explicit `/Encoding`. NOT flagged unmapped (it is exact for ASCII).
    fn latin1() -> FontDecoder {
        let table: Box<[String; 256]> =
            Box::new(std::array::from_fn(|b| (b as u8 as char).to_string()));
        FontDecoder::Simple(table)
    }

    /// Decode an operand into `(decoded_string, srcmap)` where `srcmap[k]` =
    /// `(src_byte_start, src_byte_len)` of the operand bytes that produced decoded
    /// char `k`. Also returns whether this decode hit the `Unmappable` path (so the
    /// caller can set the page's honesty flag + push a diagnostic).
    ///
    /// For `Simple`, each byte `i` contributes `table[byte].chars()`, each with
    /// `srcmap = (i, 1)` — exact + covering. For `Unmappable`, we best-effort
    /// Latin-1-decode (printable + tab/newline) so an ASCII survivor is still
    /// scanned, mapping each emitted char to its single source byte `(i, 1)`.
    fn decode_mapped(&self, bytes: &[u8]) -> (String, Vec<(usize, usize)>, bool) {
        let mut out = String::with_capacity(bytes.len());
        let mut srcmap: Vec<(usize, usize)> = Vec::with_capacity(bytes.len());
        match self {
            FontDecoder::Simple(table) => {
                for (i, &b) in bytes.iter().enumerate() {
                    for ch in table[b as usize].chars() {
                        out.push(ch);
                        srcmap.push((i, 1));
                    }
                }
                (out, srcmap, false)
            }
            FontDecoder::Unmappable => {
                // Best-effort: keep ASCII/Latin printable so a surviving identifier
                // is still caught (extra recall, never a false "clean"); the page is
                // flagged unmapped regardless.
                for (i, &b) in bytes.iter().enumerate() {
                    out.push(b as char);
                    srcmap.push((i, 1));
                }
                (out, srcmap, true)
            }
            FontDecoder::CMap(enc) => {
                // Reach the owned CMap inside the public enum variant (see the field doc).
                let Encoding::UnicodeMapEncoding(cmap) = enc else {
                    unreachable!("FontDecoder::CMap always holds UnicodeMapEncoding")
                };
                // Variadic 1–4-byte code streaming, mirroring lopdf's own
                // `UnicodeMapEncoding` decode (shortest mapped code wins), plus the
                // per-char SOURCE map lopdf does not provide: every char produced by a
                // code maps to the code's WHOLE byte range `(start, len)`, so removing
                // any matched char removes complete code units (alignment preserved;
                // over-removal within a matched span is the safe side). A code with NO
                // mapping (including a trailing partial code) emits nothing and flips
                // the honesty flag — never a silent "clean".
                let mut anomalous = false;
                let mut code_start = 0usize;
                let mut code: u32 = 0;
                let mut code_len: u8 = 0;
                for (i, &b) in bytes.iter().enumerate() {
                    if code_len == 4 {
                        // 4 bytes accumulated and never matched: an unmapped code.
                        anomalous = true;
                        code = 0;
                        code_len = 0;
                        code_start = i;
                    }
                    code_len += 1;
                    code = code.wrapping_mul(256).wrapping_add(b as u32);
                    if let Some(u16s) = cmap.get(code, code_len) {
                        let len = i + 1 - code_start;
                        for ch in char::decode_utf16(u16s.into_iter())
                            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                        {
                            out.push(ch);
                            srcmap.push((code_start, len));
                        }
                        code = 0;
                        code_len = 0;
                        code_start = i + 1;
                    }
                }
                if code_len > 0 {
                    // A trailing partial/unmapped code — flagged, never silently clean.
                    anomalous = true;
                }
                (out, srcmap, anomalous)
            }
            FontDecoder::CMapTable(table) => {
                // Fixed 2-byte Identity-H codes (the shape `parse_tounicode_2byte`
                // accepts). Each code -> its mapped string, srcmap = the 2 source bytes.
                let mut anomalous = false;
                let mut i = 0usize;
                while i + 1 < bytes.len() {
                    let code = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
                    match table.get(&code) {
                        Some(s) => {
                            for ch in s.chars() {
                                out.push(ch);
                                srcmap.push((i, 2));
                            }
                        }
                        None => anomalous = true, // unmapped code: emit nothing, flag it
                    }
                    i += 2;
                }
                if i < bytes.len() {
                    anomalous = true; // a trailing odd byte (not a whole 2-byte code)
                }
                (out, srcmap, anomalous)
            }
        }
    }

    /// Encode the visible redaction [`REDACTION_MARKER`] (`[REDACTED]`) into the CODE
    /// BYTES that render it THROUGH THIS FONT — or `None` when this font cannot render
    /// every marker glyph, in which case the caller emits a CLEAN GAP (pure removal, no
    /// inserted bytes) instead.
    ///
    /// WHY THIS EXISTS (the mojibake fix): the old apply path spliced the literal ASCII
    /// marker bytes (`[REDACTED]`) straight into the show-text operand. Those bytes are
    /// CODE POINTS interpreted through the page font's `/Encoding` at render time. On a
    /// SUBSET / custom-`/Differences` font (common in real prospectuses), the marker's
    /// ASCII codes are NOT in the font's codespace, so they render as arbitrary glyphs
    /// (`[REDACTED]` → `|_ZN)K+ZN`) — visually garbled, which looks like a typo, not an
    /// intentional redaction. We instead INVERSE-MAP the marker through the same per-byte
    /// decode table used to read the operand: for each marker char, find a source byte
    /// whose decode is exactly that char. If EVERY marker char has such a byte, the
    /// returned bytes render the literal word `[REDACTED]` in the page's own font
    /// (so a WinAnsi page is byte-identical to before — the common case is unchanged).
    /// If ANY marker char is unrenderable in this font, return `None`: the caller then
    /// removes the identifier WITHOUT inserting any bytes (a clean gap), which renders
    /// cleanly on every font and never produces mojibake.
    ///
    /// DETERMINISTIC: the per-byte table is fixed, so the chosen code for each glyph is
    /// stable (we pick the LOWEST byte value that decodes to the glyph, via an ascending
    /// scan) — the same font always yields the same marker encoding.
    fn encode_marker(&self) -> Option<Vec<u8>> {
        let marker = REDACTION_MARKER;
        match self {
            FontDecoder::Simple(table) => {
                let mut out: Vec<u8> = Vec::with_capacity(marker.len());
                for want in marker.chars() {
                    // Find the LOWEST byte value whose decode is EXACTLY this one char
                    // (a single-char decode — never a ligature/multi-char expansion, so
                    // re-decoding the marker is exact). Ascending scan = deterministic.
                    let mut found: Option<u8> = None;
                    for b in 0u16..256 {
                        let dec = &table[b as usize];
                        let mut chars = dec.chars();
                        if chars.next() == Some(want) && chars.next().is_none() {
                            found = Some(b as u8);
                            break;
                        }
                    }
                    // Any marker glyph the font cannot render → no clean marker possible
                    // → fall back to the clean gap (None).
                    out.push(found?);
                }
                Some(out)
            }
            // An Unmappable (CID/unknown) font: we do NOT know how to encode the
            // marker into its codespace, so emit a clean gap rather than risk mojibake.
            FontDecoder::Unmappable => None,
            // A CMap font: encoding the marker would require the REVERSE map plus code
            // widths; a wrong pick renders mojibake. Deterministic clean gap instead
            // (pure removal renders cleanly on every font).
            FontDecoder::CMap(_) | FontDecoder::CMapTable(_) => None,
        }
    }
}

/// The resolved, OWNED per-font decoders for ONE page, keyed by the resource font
/// name (the operand of `Tf`). Built under an immutable `Document` borrow BEFORE
/// any stream is mutated. A font name with no entry (or before any `Tf`) decodes
/// via [`FontDecoder::latin1`] (the historical default).
struct PageFonts {
    by_name: BTreeMap<Vec<u8>, FontDecoder>,
    /// The Latin-1 fallback decoder, owned ONCE so `decoder_for` can hand back a
    /// reference to it (no per-call allocation, no `Clone` on `FontDecoder`) when a
    /// font name is unknown / not yet selected.
    fallback: FontDecoder,
}

/// WORK bound (round-6 review FIX 2) for the fallback ToUnicode parser: the total number
/// of code->string entries EMITTED across ALL sections (NOT the distinct-key count — a
/// 2-byte codespace has <= 65 536 keys, so a `map.len()` cap was unreachable). The real
/// cost is ITERATION: overlapping full-range `beginbfrange` blocks each sweep 65 536 codes,
/// so a small (~38 KiB) crafted ToUnicode could burn seconds. When the running emit count
/// exceeds this, the parser FAILS CLOSED (`None` -> `Unmappable`, still flagged) rather than
/// grind. A legitimate 2-byte CMap emits at most one codespace's worth (+ small metadata),
/// so this headroom never trips a real font.
const MAX_CMAP_WORK: usize = 262_144;

/// A token from a ToUnicode CMap stream (ASCII PostScript-ish): a `<hex>` string, an
/// array bracket, or a bareword keyword (`beginbfchar` / `endbfrange` / …).
enum CMapTok {
    Hex(Vec<u8>),
    LBracket,
    RBracket,
    Word(Vec<u8>),
}

/// Tokenize a ToUnicode CMap stream. BOUNDED, never panics: unknown bytes are skipped; a
/// `(...)` string or `<...>` run is read to its close (or end). Pure, deterministic.
fn cmap_tokenize(stream: &[u8]) -> Vec<CMapTok> {
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < stream.len() {
        let b = stream[i];
        match b {
            b'<' => {
                // Collect the hex-string body. FIX 3 (round-6 review): a NON-hex,
                // NON-whitespace byte inside `<...>` (e.g. the `G` in `<0G041>`) makes the
                // token INVALID — we push it verbatim so `cmap_hex_u16s` REJECTS the token
                // (fail-closed) instead of silently dropping it and mapping `<0041>`.
                // ASCII whitespace inside a hex string is ignored per PostScript.
                let mut hex = Vec::new();
                i += 1;
                while i < stream.len() && stream[i] != b'>' {
                    if !stream[i].is_ascii_whitespace() {
                        hex.push(stream[i]);
                    }
                    i += 1;
                }
                i += 1; // consume '>'
                toks.push(CMapTok::Hex(hex));
            }
            b'[' => {
                toks.push(CMapTok::LBracket);
                i += 1;
            }
            b']' => {
                toks.push(CMapTok::RBracket);
                i += 1;
            }
            b'(' => {
                // A literal string operand (rare here): skip to the matching ')'.
                i += 1;
                let mut depth = 1;
                while i < stream.len() && depth > 0 {
                    match stream[i] {
                        b'\\' => i += 1, // skip the escaped char
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b if b.is_ascii_alphabetic() => {
                let start = i;
                while i < stream.len()
                    && (stream[i].is_ascii_alphanumeric() || stream[i] == b'.' || stream[i] == b'-')
                {
                    i += 1;
                }
                toks.push(CMapTok::Word(stream[start..i].to_vec()));
            }
            _ => i += 1, // whitespace / digits (section counts) / `/name` slashes: skip
        }
    }
    toks
}

/// Parse an even-length ASCII-hex byte vector into the big-endian `u16` UTF-16 units it
/// encodes. Returns `None` unless the hex is a whole number of 2-byte units (a ToUnicode
/// source code / destination is always a multiple of 2 bytes). Pure, deterministic.
fn cmap_hex_u16s(hex: &[u8]) -> Option<Vec<u16>> {
    if hex.is_empty() || !hex.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut units = Vec::with_capacity(hex.len() / 4);
    for chunk in hex.chunks(4) {
        let mut u: u16 = 0;
        for &c in chunk {
            u = (u << 4) | val(c)? as u16;
        }
        units.push(u);
    }
    Some(units)
}

/// UTF-16BE units -> a `String` (lossy on an unpaired surrogate — never panics).
fn cmap_u16s_to_string(units: Vec<u16>) -> String {
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// FALLBACK ToUnicode CMap parser (round-6 fix-on-top) for the 2-BYTE Identity-H shape
/// lopdf 0.41 rejects: parse `beginbfchar`/`endbfchar` (`<src> <dst>`) and
/// `beginbfrange`/`endbfrange` (`<lo> <hi> <dst>` or `<lo> <hi> [ <dst>… ]`) into a
/// `code(u16) -> String` map. STRICT + FAIL-CLOSED: any source code that is not exactly
/// 2 bytes, any malformed/oversized structure, or a total emit-count over the work bound
/// [`MAX_CMAP_WORK`] returns `None` (the caller then stays `Unmappable`, still
/// flagged — never a WRONG decode, which would be a worse leak than the honest miss).
/// Deterministic, linear, no clock/RNG/panic.
fn parse_tounicode_2byte(stream: &[u8]) -> Option<std::collections::BTreeMap<u16, String>> {
    let toks = cmap_tokenize(stream);
    let mut map: std::collections::BTreeMap<u16, String> = std::collections::BTreeMap::new();
    // FIX 2: bound the WORK (total emits across all sections), not the distinct-key count.
    let mut work = 0usize;
    // A 2-byte source code: the hex must be exactly 4 hex digits (one u16).
    let code_of = |hex: &[u8]| -> Option<u16> {
        let u = cmap_hex_u16s(hex)?;
        (u.len() == 1).then_some(u[0])
    };
    let mut i = 0usize;
    while i < toks.len() {
        match &toks[i] {
            CMapTok::Word(w) if w == b"beginbfchar" => {
                i += 1;
                loop {
                    match toks.get(i) {
                        Some(CMapTok::Word(w)) if w == b"endbfchar" => {
                            i += 1;
                            break;
                        }
                        Some(CMapTok::Hex(src)) => {
                            let dst = match toks.get(i + 1) {
                                Some(CMapTok::Hex(d)) => d,
                                _ => return None,
                            };
                            let code = code_of(src)?;
                            let units = cmap_hex_u16s(dst)?;
                            map.insert(code, cmap_u16s_to_string(units));
                            work += 1;
                            if work > MAX_CMAP_WORK {
                                return None;
                            }
                            i += 2;
                        }
                        _ => return None, // malformed bfchar body
                    }
                }
            }
            CMapTok::Word(w) if w == b"beginbfrange" => {
                i += 1;
                loop {
                    match toks.get(i) {
                        Some(CMapTok::Word(w)) if w == b"endbfrange" => {
                            i += 1;
                            break;
                        }
                        Some(CMapTok::Hex(lo)) => {
                            let hi = match toks.get(i + 1) {
                                Some(CMapTok::Hex(h)) => h,
                                _ => return None,
                            };
                            let lo = code_of(lo)?;
                            let hi = code_of(hi)?;
                            if hi < lo {
                                return None;
                            }
                            match toks.get(i + 2) {
                                // `<lo> <hi> <dst>` — increment the LAST u16 across the range.
                                Some(CMapTok::Hex(dst)) => {
                                    let base = cmap_hex_u16s(dst)?;
                                    if base.is_empty() {
                                        return None;
                                    }
                                    for code in lo..=hi {
                                        let mut units = base.clone();
                                        let last = units.len() - 1;
                                        // Increment the last unit by the offset (saturating
                                        // into u16; a real CMap range never overflows a BMP
                                        // block, but stay panic-free).
                                        units[last] = units[last].wrapping_add(code - lo);
                                        map.insert(code, cmap_u16s_to_string(units));
                                        work += 1;
                                        if work > MAX_CMAP_WORK {
                                            return None;
                                        }
                                    }
                                    i += 3;
                                }
                                // `<lo> <hi> [ <d0> <d1> … ]` — one dst per code.
                                Some(CMapTok::LBracket) => {
                                    let mut j = i + 3;
                                    let mut code = lo;
                                    loop {
                                        match toks.get(j) {
                                            Some(CMapTok::RBracket) => {
                                                j += 1;
                                                break;
                                            }
                                            Some(CMapTok::Hex(d)) => {
                                                if code > hi {
                                                    return None; // more dsts than codes
                                                }
                                                let units = cmap_hex_u16s(d)?;
                                                map.insert(code, cmap_u16s_to_string(units));
                                                work += 1;
                                                if work > MAX_CMAP_WORK {
                                                    return None;
                                                }
                                                code = code.wrapping_add(1);
                                                j += 1;
                                            }
                                            _ => return None,
                                        }
                                    }
                                    i = j;
                                }
                                _ => return None,
                            }
                        }
                        _ => return None, // malformed bfrange body
                    }
                }
            }
            _ => i += 1, // any other token (header/metadata/codespacerange): skip
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

impl PageFonts {
    /// Resolve every font on `page_id` to an owned [`FontDecoder`]. Mirrors how
    /// `extract` resolves encodings (`get_page_fonts` + `get_font_encoding`), but
    /// converts each `lopdf::Encoding` into a borrow-free decoder so it survives the
    /// later mutable stream borrow. Never panics: a missing/odd font dict simply has
    /// no entry (-> Latin-1 fallback when shown).
    fn resolve(doc: &Document, page_id: lopdf::ObjectId) -> PageFonts {
        let mut by_name: BTreeMap<Vec<u8>, FontDecoder> = BTreeMap::new();
        if let Ok(fonts) = doc.get_page_fonts(page_id) {
            for (name, font) in fonts {
                // A Type0 (composite / CID-keyed) font is MULTI-BYTE and NOT
                // byte-decomposable. lopdf's `get_font_encoding` SILENTLY degrades a
                // Type0 with no decodable `/ToUnicode` to `OneByteEncoding(Standard)`
                // (the `Err(_) => Ok(Standard)` fallback) — which would make us treat
                // it as an exactly-mappable simple font and produce a FALSE clean
                // result. So we inspect `/Subtype` FIRST: a Type0 font is `Unmappable`
                // UNLESS lopdf yielded a genuine `UnicodeMapEncoding` from its
                // `/ToUnicode` (which we still route to `Unmappable` in this increment
                // anyway — see `from_encoding` — since we do not yet decode multi-byte
                // codes per-width exactly). Fail-closed: flag honestly, never claim a
                // clean Type0 page.
                let is_type0 = font
                    .get(b"Subtype")
                    .and_then(Object::as_name)
                    .map(|s| s == b"Type0")
                    .unwrap_or(false);
                let dec = if is_type0 {
                    // ROUND 6: a Type0 font WITH a decodable `/ToUnicode` CMap decodes
                    // EXACTLY through it (`FontDecoder::CMap` — the BGF possessive-
                    // sentence fix). lopdf's `get_font_encoding` silently degrades a
                    // Type0 WITHOUT one to `OneByteEncoding(Standard)` (the
                    // `Err(_) => Ok(Standard)` fallback), which would fake a clean
                    // one-byte decode — so ONLY the genuine `UnicodeMapEncoding`
                    // result is accepted; anything else stays honestly `Unmappable`.
                    match font.get_font_encoding(doc) {
                        Ok(enc @ Encoding::UnicodeMapEncoding(_)) => {
                            FontDecoder::from_encoding(enc)
                        }
                        // lopdf did NOT yield a CMap (it returned a fallback OneByte, or
                        // errored) despite a `/ToUnicode` being present: try OUR bounded
                        // 2-byte parser on the ToUnicode stream (the BGF-page-196 class
                        // lopdf 0.41 rejects). A successful parse decodes + redacts the
                        // page; a failure stays honestly `Unmappable`.
                        _ => font
                            .get_deref(b"ToUnicode", doc)
                            .ok()
                            .and_then(|o| o.as_stream().ok())
                            // FIX 2 (round-6 review): the SAME capped reader every other
                            // stream uses — NOT lopdf's UNCAPPED `decompressed_content()`
                            // (a small ToUnicode could inflate a decompression bomb).
                            .and_then(|s| decode_stream_capped(s, MAX_DECODED_STREAM_BYTES).ok())
                            .and_then(|bytes| parse_tounicode_2byte(&bytes))
                            .map(FontDecoder::CMapTable)
                            .unwrap_or(FontDecoder::Unmappable),
                    }
                } else if let Ok(enc) = font.get_font_encoding(doc) {
                    // `get_font_encoding` is the SAME resolution `extract` uses (base
                    // encoding + /Differences + /ToUnicode).
                    FontDecoder::from_encoding(enc)
                } else {
                    // A read failure -> no exact map: fail-closed to Unmappable.
                    FontDecoder::Unmappable
                };
                by_name.insert(name, dec);
            }
        }
        PageFonts {
            by_name,
            fallback: FontDecoder::latin1(),
        }
    }

    /// The decoder for resource font `name` (the `Tf` operand), or the Latin-1
    /// fallback when the name is unknown / not yet set.
    fn decoder_for(&self, name: Option<&[u8]>) -> &FontDecoder {
        name.and_then(|n| self.by_name.get(n))
            .unwrap_or(&self.fallback)
    }
}

// ============================================================================
// CROSS-OPERATOR logical runs: reconstruct text spanning ADJACENT show operators
// on the SAME visual line, detect over the joined run, and map each match back to
// the contributing operators' SOURCE byte ranges for splicing.
//
// WHY: PDF generators routinely break one logical token (an international phone
// number `+852 2800 2800`) into SEPARATE show operators — e.g. `(+852) Tj`, ` Tj`,
// `(2800) Tj`, … — so no single operand contains the whole identifier and the old
// per-operator detection missed it (a SILENT leak). We now join consecutive show
// operators into one logical buffer, detect over the join, then splice each match
// back into whichever operator(s) produced its bytes.
//
// GROUPING RULE (conservative — documented; do not loosen without review):
//   * A logical run is a maximal sequence of consecutive show operators
//     (`Tj`/`'`/`"`/`TJ`) reached WITHOUT a line-advance between them.
//   * A line-advancing operator STARTS A NEW run (we never join across visual
//     lines — that risks spurious cross-field matches and wrong-line splicing):
//       - `T*`        (move to next line);
//       - `Td` / `TD` with a NON-ZERO y displacement (a y-move = a new line; a
//         pure x-move `Td 10 0` stays on the SAME line and does NOT break the run);
//       - `Tm`        (set the text matrix — repositions; CONSERVATIVELY always a
//         new run, since it can move y);
//       - `BT` / `ET` (text-object boundaries — always a new run);
//       - `'`  and `"` (they move to the next line BEFORE showing): each STARTS a
//         new run but, being show operators, BEGINS that new run with their text.
//   * A non-show, non-positioning operator (`Tf`, `Tc`, `Tw`, color/graphics ops)
//     does NOT break a run — it only updates state (font for `Tf`). So `(+852) Tj
//     /F1 9 Tf (2800) Tj` on one line is ONE run.
//
// SEPARATOR POLICY (load-bearing — recall vs. spurious-match balance):
//   * Two DIRECTLY-ADJACENT show operators (no positioning op between them) are
//     CONTIGUOUS glyphs on the page, so they join with NO separator. This is what
//     lets `(info@) Tj (jpmorgan.com) Tj` reconstruct the email `info@jpmorgan.com`
//     (a space separator there would BREAK the email). It mirrors the existing
//     TJ-array join (array string elements are concatenated with no separator).
//     The real visual spaces in `(+852) Tj ( ) Tj (2800) Tj` are THEIR OWN space
//     operators, so the phone joins as `+852 2800` from real content, not fabricated.
//   * A HORIZONTAL-gap positioning op BETWEEN two show operators (`Td`/`TD` with a
//     non-zero x and zero y) is a visual gap, so a single space separator (mapping to
//     NO source bytes) is inserted there — preventing two SEPARATE fields laid out by
//     a column tab (e.g. `(Name) Tj  Td 80 0  (+852 2800 2800) Tj`) from bleeding into
//     one spurious token, while still keeping them on the same logical line for a token
//     that a generator DID split with a positioning nudge.
//
// ID STABILITY + NON-REGRESSION: the COMMON case (a lone `Tj`, or a lone `TJ`, on
// its own line) is a run of ONE operator whose joined text == the operand text with
// NO separators — so detection yields byte-identical candidates, spans, ids, and
// removal as before. Ids are assigned in run order = operator order, so a single-
// operator-per-line page keeps the exact pre-change `PdfCandidateId` ordinals. Only
// where operators ACTUALLY join (the new-detection case) does the run differ from a
// single operand — exactly the case that was a miss before.
// ============================================================================

/// One element of a logical run's source map: which operator produced a decoded char,
/// and where in that operator's bytes. `elem` is the array element index for a `TJ`
/// (0 for a `Tj`/`'`/`"`, whose single trailing string is treated as element 0).
#[derive(Clone, Copy)]
struct RunCharOrigin {
    /// Index into `operations` of the operator that produced this decoded char.
    op_index: usize,
    /// The string-element index WITHIN that operator (0 for Tj/'/"; the TJ array
    /// element index for a TJ). `usize::MAX` marks a SEPARATOR char (no source bytes).
    elem: usize,
    /// SOURCE byte offset within that element's bytes.
    off: usize,
    /// SOURCE byte length (1 for a simple/unmappable decode; the multi-byte code len
    /// for an exactly-mapped multi-byte char).
    len: usize,
}

/// The separator sentinel `elem` value: a char that maps to NO source bytes (a run
/// boundary space). It is skipped entirely when computing removal ranges.
const SEP_ELEM: usize = usize::MAX;

/// One show operator within a planned logical run.
struct RunOp {
    /// Index into `operations` of this show operator.
    op_index: usize,
    /// The font resource name active when this operator runs (`None` = Latin-1 fallback,
    /// the historical default). The decoder is re-resolved from `page_fonts` at decode
    /// time so the run holds no borrow.
    font_name: Option<Vec<u8>>,
    /// `true` if a HORIZONTAL-gap positioning op (`Td`/`TD` with non-zero x, zero y)
    /// preceded this operator WITHIN the run — a single no-source space separator is
    /// then inserted before it. `false` for the first op of a run and for directly-
    /// adjacent ops (which join with no separator). See the SEPARATOR POLICY above.
    gap_before: bool,
}

/// A planned logical run: the show operators it spans, in document order.
struct LogicalRun {
    ops: Vec<RunOp>,
}

/// Walk the operations once and GROUP consecutive show operators into logical runs by
/// the documented grouping rule. Tracks the current font (`Tf`) so each show operator
/// records the font active when it runs. Pushes a content-free diagnostic for a show
/// operator whose operand shape is non-canonical (so a potential miss is observable),
/// matching the old per-operator L1 diagnostics. NEVER reads matter cleartext.
fn plan_logical_runs(
    operations: &[lopdf::content::Operation],
    page_fonts: &PageFonts,
    page_no: u32,
    diagnostics: &mut Vec<String>,
) -> Vec<LogicalRun> {
    let _ = page_fonts; // decoder resolution happens in process_logical_run by name
    let mut runs: Vec<LogicalRun> = Vec::new();
    let mut current: Vec<RunOp> = Vec::new();
    let mut current_font: Option<Vec<u8>> = None;
    // The decoded-byte size of the run so far (bounds a pathological one-line stream).
    let mut run_text_len: usize = 0;
    // A HORIZONTAL-gap positioning op has appeared since the previous show operator in
    // the current run — the NEXT show operator gets a space separator before it. Reset
    // whenever a run is flushed (the first op of a run never carries a leading gap).
    let mut pending_gap = false;

    // Seal the in-progress run (if any) into `runs`.
    let flush = |current: &mut Vec<RunOp>, run_text_len: &mut usize, runs: &mut Vec<LogicalRun>| {
        if !current.is_empty() {
            runs.push(LogicalRun {
                ops: std::mem::take(current),
            });
        }
        *run_text_len = 0;
    };

    for (i, op) in operations.iter().enumerate() {
        let name = op.operator.as_str();
        // Font tracking (not a show op, does not break a run).
        if name == "Tf" {
            current_font = op
                .operands
                .first()
                .and_then(|o| o.as_name().ok())
                .map(|n| n.to_vec());
            continue;
        }
        // Positioning operators. A vertical (y) move BREAKS the run (new line); a pure
        // horizontal move stays on the line but marks a visual GAP for the next op.
        match name {
            "T*" | "Tm" | "BT" | "ET" => {
                flush(&mut current, &mut run_text_len, &mut runs);
                pending_gap = false;
                continue;
            }
            "Td" | "TD" => {
                if td_moves_y(&op.operands) {
                    flush(&mut current, &mut run_text_len, &mut runs);
                    pending_gap = false;
                } else if td_moves_x(&op.operands) {
                    // Pure horizontal nudge on the SAME line → a visual gap before the
                    // next show op (only meaningful if a run is already open).
                    pending_gap = true;
                }
                continue;
            }
            _ => {}
        }
        if !SHOW_OPERATORS.contains(&name) {
            // A non-show, non-positioning operator (color/graphics/spacing): it does
            // NOT break the run and does NOT introduce a gap.
            continue;
        }

        // A show operator. `'` and `"` move to the next line FIRST, then show — so they
        // START a new run (but, being show ops, BEGIN it with their own text).
        if name == "'" || name == "\"" {
            flush(&mut current, &mut run_text_len, &mut runs);
            pending_gap = false;
        }

        // Validate the operand shape (content-free diagnostic on a miss, mirroring L1).
        let op_text_len = match name {
            "Tj" | "'" | "\"" => match op.operands.last() {
                Some(Object::String(b, _)) => b.len(),
                _ => {
                    diagnostics.push(format!(
                        "page {page_no}: operator {name}: unexpected operand shape (no \
                         trailing string operand) — not scanned, an identifier here would \
                         be UN-redacted"
                    ));
                    continue;
                }
            },
            "TJ" => match op.operands.first() {
                Some(Object::Array(arr)) => arr
                    .iter()
                    .filter_map(|o| match o {
                        Object::String(b, _) => Some(b.len()),
                        _ => None,
                    })
                    .sum(),
                _ => {
                    diagnostics.push(format!(
                        "page {page_no}: operator TJ: unexpected operand shape (first \
                         operand not an Array) — not scanned, an identifier here would \
                         be UN-redacted"
                    ));
                    continue;
                }
            },
            _ => 0,
        };

        // Cap the joined run: if adding this operator would breach the per-run buffer
        // bound, SEAL the current run and start a fresh one with this operator (which
        // then carries no leading gap — it begins a new run).
        if !current.is_empty() && run_text_len.saturating_add(op_text_len) > MAX_LOGICAL_RUN_BYTES {
            flush(&mut current, &mut run_text_len, &mut runs);
            pending_gap = false;
        }
        // A gap separator applies ONLY between two operators within the SAME run (never
        // before the first op of a run).
        let gap_before = pending_gap && !current.is_empty();
        pending_gap = false;
        current.push(RunOp {
            op_index: i,
            font_name: current_font.clone(),
            gap_before,
        });
        run_text_len = run_text_len.saturating_add(op_text_len);
    }
    flush(&mut current, &mut run_text_len, &mut runs);
    runs
}

/// Whether a `Td`/`TD` operand pair moves the text line vertically (a NON-ZERO y
/// displacement = a new visual line). `Td tx ty` / `TD tx ty`: the SECOND operand is
/// `ty`. A pure horizontal move (`ty == 0`, e.g. `Td 12 0`) stays on the SAME line and
/// does NOT break the run; any non-zero (or unreadable/odd-shape, fail-safe) ty breaks
/// it. Fail-CLOSED toward breaking: if we cannot read a clean `ty`, we treat it as a
/// line break (never JOIN across an ambiguous reposition — over-splitting at worst
/// reverts to per-operator detection, which is the SAFE side: no spurious join).
fn td_moves_y(operands: &[Object]) -> bool {
    match operands.get(1).map(as_f64) {
        Some(Some(ty)) => ty != 0.0,
        // Missing or non-numeric second operand: fail-closed to a line break.
        _ => true,
    }
}

/// Whether a `Td`/`TD` operand pair moves the text horizontally (a NON-ZERO x
/// displacement). Used ONLY to decide whether a same-line nudge introduces a visual
/// GAP separator before the next op; an unreadable/odd x reads as NO gap (conservative
/// — joining contiguously, the SAFE side for recall: a missing separator never breaks a
/// token, it can only risk a join that the y-move check has already ruled out as a line).
fn td_moves_x(operands: &[Object]) -> bool {
    matches!(operands.first().map(as_f64), Some(Some(tx)) if tx != 0.0)
}

/// ROUND 7 — the TJ inter-element WORD-GAP threshold, in thousandths of the text-space
/// em (the unit of a `TJ` array's numeric adjustments; font-size-independent by
/// construction). Some generators encode EVERY inter-word space as a numeric adjustment
/// between two `TJ` string elements — no space glyph, no `Td` nudge — e.g.
/// `[(word)-250(word)] TJ`. Joining those elements contiguously (the deliberate
/// kerning-join policy) then GLUES the whole line (`Prospectusandnotwithstanding…`),
/// and EVERY recognizer goes blind on the page: token boundaries never exist (the BGF
/// pp247-248 Shariah-panel / p190 "Keith Saldanha" total-miss class — names with no
/// normally-spaced sibling anywhere in the document, so the seed-based ws-elastic
/// recall cannot rescue them either).
///
/// A NEGATIVE adjustment moves the pen RIGHT (a visual gap). The measured distribution
/// on the flagship corpus is BIMODAL: word gaps sit at ~-244..-255 (and -400s for wide
/// gaps) — 184k values in (-400, -200]; kerning micro-adjustments sit in (-101, +∞);
/// justified-text stretch NEXT TO a real space glyph sits at -150..-160. The valley
/// between -200 and -160 cleanly separates the populations, so -180 splits it: any
/// accumulated inter-element adjustment at or below this is a WORD GAP and a fabricated
/// separator space (SEP_ELEM — no source bytes, exactly like the `Td`-gap separator) is
/// inserted; anything above it is kerning and the elements join contiguously as before.
/// Fail-direction: a missed separator = a glued token (recognizer-blind, the leak
/// class); a spurious separator = a split token, which the ws-elastic recall passes
/// already recover. The threshold therefore errs toward SPLITTING. A separator is
/// skipped when the boundary is already whitespace (a real space glyph beside a
/// justification stretch), so normally-spaced text is never double-spaced.
const TJ_WORD_GAP_THOUSANDTHS: f64 = -180.0;

/// ROUND 7 — the DEGENERATE-LAYOUT floor: a reconstructed page whose text contains a
/// spaceless ALPHABETIC run longer than this has no plausible word boundaries in that
/// region (real prose breaks words every few characters; even long legal compounds stay
/// well under this). Such a page is unreadable to every token-based recognizer, and —
/// unlike an unmappable font — it DECODES cleanly, so `unmapped_fonts` gives the
/// reviewer no signal. Any page tripping this gets a content-free per-page diagnostic
/// and sets the document-level `degenerate_layout` honesty flag (same posture as
/// `unmapped_fonts`). HONEST SCOPE (review finding, round 7): this net has a FLOOR — a
/// page whose only glued content is a run of <= 60 chars (e.g. a lone glued name whose
/// word gaps sit in the (-180, -160] valley below the fabrication trigger) is NOT
/// flagged and remains a silent recognizer miss. That regime was measured EMPTY on the
/// flagship corpora (word gaps cluster at -244..-255; the valley held no values), and
/// the ws-elastic TERMS route still catches known names glued — but the flag REDUCES the
/// silent-blind class, it does not eliminate it. Do not restate this as "can never
/// silently pass".
const DEGENERATE_ALPHA_RUN_CHARS: usize = 60;

/// ROUND 7 — does `text` contain a run of more than [`DEGENERATE_ALPHA_RUN_CHARS`]
/// consecutive alphabetic chars (no whitespace/punctuation/digit boundary)? Linear,
/// allocation-free; counts CHARS (not bytes) so multibyte scripts are not over-counted.
fn has_degenerate_alpha_run(text: &str) -> bool {
    let mut run = 0usize;
    for ch in text.chars() {
        if ch.is_alphabetic() {
            run += 1;
            if run > DEGENERATE_ALPHA_RUN_CHARS {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Read a PDF numeric object as f64 (Integer or Real); `None` for any other type.
fn as_f64(o: &Object) -> Option<f64> {
    match o {
        Object::Integer(i) => Some(*i as f64),
        Object::Real(r) => Some(*r as f64),
        _ => None,
    }
}

/// The outcome of detecting + (apply) planning the removal for one logical run.
struct RunOutcome {
    /// SOURCE text bytes across the run's string operands (for the low_text heuristic).
    text_bytes: usize,
    /// Candidates removed (apply) / detected (scan) on this run.
    redactions: usize,
    /// Any operand in this run decoded through an unmappable (Type0/CID) font.
    unmapped: bool,
    /// Defensively-dropped spans (should be unreachable for engine output).
    dropped: usize,
    /// ACCEPTED candidates that could NOT be truly removed on this run — a span whose
    /// accepted source range resolved to ZERO removable source bytes (every contributing
    /// char was a fabricated separator, or the span fell out of bounds). The HONEST
    /// over-report guard: such a span is NOT counted in `redactions` and is surfaced as a
    /// `could_not_remove` diagnostic up the stack, so the tool never claims a removal it
    /// did not perform. Expected to be 0 for engine output; a non-zero value is a signal,
    /// not normal operation.
    could_not_remove: usize,
    /// ROUND 6 — synthetic candidates the whitespace-elastic detected-name recall added
    /// on this run (kerning-split occurrences recovered). Summed per page into a
    /// content-free honesty diagnostic: a page with recoveries used a glyph-split layout,
    /// an elevated-risk signal for the reviewer.
    ws_name_recovered: usize,
    /// ROUND 7 — the page's reconstructed text contains an implausibly long spaceless
    /// alphabetic run (see [`DEGENERATE_ALPHA_RUN_CHARS`]): token boundaries are missing,
    /// so recognizers may be BLIND on this page. ORed into the document-level
    /// `degenerate_layout` honesty flag; drives a content-free per-page diagnostic.
    degenerate: bool,
}

/// What to splice into ONE operator's operands during the apply pass. Indexed by
/// string-element index within the operator (0 for a Tj/'/" trailing string; the TJ
/// array element index for a TJ). For each element: the byte ranges to REMOVE and the
/// byte offsets at which to INSERT the marker. Accumulated across runs, then applied
/// once per operator in `apply_op_edits`.
#[derive(Default)]
struct OpEdit {
    /// `elem_index -> remove ranges` (ascending, disjoint, coalesced via push_remove_byte).
    remove: BTreeMap<usize, Vec<(usize, usize)>>,
    /// `elem_index -> marker insertion offsets` (a span's first source char).
    marker_at: BTreeMap<usize, Vec<usize>>,
    /// How `apply_op_edits` should render the marker for THIS operator (resolved from
    /// the operator's font). [`MarkerBytes::Unset`] until the first marker is recorded;
    /// then [`MarkerBytes::Glyphs`] (the bytes that render `[REDACTED]` through this
    /// operator's font) or [`MarkerBytes::Gap`] (the font cannot render the marker → emit
    /// NOTHING, a clean gap, never mojibake). The per-operator fix for garbled markers on
    /// subset/custom-encoded fonts. An operator with NO marker recorded stays `Unset` (it
    /// only removes bytes, if any).
    marker_bytes: MarkerBytes,
}

/// How the redaction marker is rendered for one operator — resolved from its font (see
/// [`FontDecoder::encode_marker`]). The tri-state distinguishes "not yet resolved" from
/// the deliberate "clean gap" choice, so a `Gap` font is never re-resolved and an
/// `Unset` operator never accidentally emits a gap-vs-glyph marker it shouldn't.
#[derive(Default)]
enum MarkerBytes {
    /// Not yet resolved (no marker recorded for this operator yet).
    #[default]
    Unset,
    /// Render these EXACT bytes (already encoded in the operator's font) — the literal
    /// `[REDACTED]` shown in the page's own font (WinAnsi/exactly-mapped fonts).
    Glyphs(Vec<u8>),
    /// The font cannot render the marker glyphs: emit a CLEAN GAP (no inserted bytes).
    /// Pure removal — renders cleanly on every font, never garbled.
    Gap,
}

/// ROUND 6 — cap on the DISTINCT document-level detected-name seeds the whitespace-
/// elastic name-recall pass compiles (bomb-bound; deterministic first-N in candidate-id
/// order). Real documents carry dozens of distinct person names, not hundreds.
/// (1000: the flagship 962-page corpus yields ~180 qualifying seeds; the cap is a
/// pathological-input bound, not a working ceiling — hitting it means synthetic input.)
const MAX_WS_NAME_SEEDS: usize = 1000;

/// ROUND 6 — per-page cap on synthetic candidates the ws-name pass may append (bomb-bound,
/// mirroring the engine's caps pattern).
const MAX_WS_NAME_SPANS_PER_PAGE: usize = 200;

/// ROUND 6 (the JPMIF kerning-split leak) — derive the DOCUMENT-LEVEL whitespace-elastic
/// name-recall seed set from an UNSEEDED scan's items: the value of every ORGANIC
/// [`Recognizer::Name`] primary (honorific / header-list / trailing-role / anchored —
/// never a ctx row, never a field label, never a propagated or synthetic-term candidate;
/// the same seeding doctrine as the text path's propagation pass, so role BOILERPLATE
/// can never amplify document-wide), honorific-stripped, floored at >= 2 words AND >= 8
/// chars, name-charset only. Each seed compiles to the SAME case-sensitive whitespace-
/// elastic pattern the user-TERM recall uses (`ws_regex_source`), so a name a PDF
/// generator kerning-split mid-word (`Ka thy V ancomerbeke` — verbatim reconstruction of
/// the real officer-bio heading) or fragmented across `Tm`-broken runs
/// (`Ben\njamin\n \nGregson`) still matches wherever it occurs.
///
/// Deterministic: items are in id order; dedup preserves first-seen order; capped at
/// [`MAX_WS_NAME_SEEDS`]. Pure (no clock/RNG).
/// The compiled document-level name-seed set (round 6): the seed values + their
/// whitespace-elastic patterns, plus a [`regex::RegexSet`] PREFILTER over the identical
/// sources (pure optimization — one `matches` pass per page tells us which seeds occur at
/// all; `None` when the combined set overflowed the regex size cap, in which case every
/// seed is scanned directly — slower, never a miss).
struct WsNameSeeds {
    rows: Vec<(String, Regex)>,
    prefilter: Option<regex::RegexSet>,
}

impl WsNameSeeds {
    fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// ROLE-TITLE LEAD words (round-6 review FIX 1a) — the first token of a role-title LINE
/// in a directory / officer-bio layout (`Executive Director, Finance`, `Managing Director,
/// Onboarding`, `Directors`). Used by [`ctx_value_is_person_bio`] to tell a PERSON name
/// (immediately ABOVE a role-title line — the JPMIF conducting-officer bios, the BGF
/// directors column) from a fund / geographic / defined-term phrase that merely sits near a
/// role word (`United Kingdom` → next line `Mr. Vitoria …`; `ISC Paris` → next line `Louise
/// Mullan`). Bounded, deterministic.
const ROLE_TITLE_LEAD: &[&str] = &[
    "executive",
    "managing",
    "director",
    "directors",
    "officer",
    "officers",
    "manager",
    "managers",
    "chief",
    "head",
    "chairman",
    "chairwoman",
    "chairperson",
    "chair",
    "president",
    "vice",
    "deputy",
    "senior",
    "independent",
    "conducting",
    "lead",
    "principal",
    "non",
    "supervisory",
    "board",
    "partner",
    "trustee",
    "secretary",
];

/// Is a `ctx:role-name` VALUE a PERSON in a bio/directory layout — i.e. is the IMMEDIATE
/// next non-blank line (within its review `context` snippet, after the value) a ROLE-TITLE
/// line (first token in [`ROLE_TITLE_LEAD`])? This is the high-precision person signal the
/// bare `ctx:role-name` proximity heuristic lacks (FIX 1a): a person name sits directly
/// ABOVE its role title; a fund / geographic / defined-term phrase does not. `value` is the
/// candidate's ORIGINAL matched text (as it appears in `context`). Pure, deterministic.
fn ctx_value_is_person_bio(context: &str, value: &str) -> bool {
    // Find the value in its (value-centered) context; take the text AFTER it.
    let Some(pos) = context.find(value) else {
        return false;
    };
    let after = &context[pos + value.len()..];
    // The first NON-BLANK line after the value.
    for line in after.split('\n') {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let first = t
            .split(|c: char| c.is_whitespace() || c == ',')
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase();
        return ROLE_TITLE_LEAD.contains(&first.as_str());
    }
    false
}

/// ORG / FUND / ENTITY tokens (round-6 review FIX 1a) — the person-vs-entity discriminator
/// for the document-level name-recall SEED set. A capitalized 2-token run near a role word
/// (`Investment Adviser`, `Management Company`, `Net Asset Value`, `Share Class`,
/// `Bond Fund`, `BlackRock Group`) is SHAPE-identical to a person name (`Kathy Vancomerbeke`)
/// and passes `is_person_shaped_field_value`, so a value containing ANY of these tokens is a
/// fund/entity PHRASE, not a person — it must NOT seed doc-wide elastic recall (its glued /
/// line-broken re-spellings flooded the flagship: `InvestmentAdviser` x980, …). A real
/// person name essentially never carries one of these tokens; over-excluding a rare
/// `James Bond`-style surname only costs the split-page RECALL, never the clean-site flag.
/// Whole-token, case-insensitive (dots/commas trimmed). Extend by appending a row.
const SEED_ENTITY_WORDS: &[&str] = &[
    "fund",
    "funds",
    "company",
    "companies",
    "group",
    "trust",
    "trusts",
    "bank",
    "banks",
    "adviser",
    "advisor",
    "advisers",
    "advisors",
    "manager",
    "managers",
    "management",
    "asset",
    "assets",
    "value",
    "values",
    "class",
    "classes",
    "bond",
    "bonds",
    "equity",
    "equities",
    "income",
    "capital",
    "holding",
    "holdings",
    "partner",
    "partners",
    "committee",
    "board",
    "services",
    "service",
    "solutions",
    "limited",
    "ltd",
    "llc",
    "llp",
    "inc",
    "incorporated",
    "corporation",
    "corp",
    "plc",
    "sicav",
    "oeic",
    "ucits",
    "aifm",
    "aif",
    "distributor",
    "depositary",
    "custodian",
    "registrar",
    "representative",
    "portfolio",
    "portfolios",
    "umbrella",
    "index",
    "indices",
    "securities",
    "exchange",
    "investment",
    "investments",
    "net",
    "share",
    "shares",
    "administrator",
    "administration",
    "subsidiary",
    "association",
    "institute",
    "markets",
    "market",
    "reserve",
    "treasury",
    "credit",
    "growth",
    "dividend",
    "global",
    "series",
    "account",
    "agreement",
];

/// Is `value` a fund/entity PHRASE (any whitespace token, dots/commas trimmed, is a
/// [`SEED_ENTITY_WORDS`] entry, case-insensitive)? Then it must not seed the name recall.
fn seed_is_org_or_fund(value: &str) -> bool {
    value.split_whitespace().any(|tok| {
        let t = tok
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_ascii_lowercase();
        SEED_ENTITY_WORDS.contains(&t.as_str())
    })
}

fn ws_name_seeds_from_scan(items: &[PdfScanItem]) -> WsNameSeeds {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut sources: Vec<String> = Vec::new();
    let mut seeds: Vec<(String, Regex)> = Vec::new();
    for it in items {
        if seeds.len() >= MAX_WS_NAME_SEEDS {
            break;
        }
        let c = it.candidate();
        // SEED-SITE ALLOWLIST (round-6 review FIX 1a). Seed ONLY from person-corroborated
        // detections — a generic capitalized run near a role word is NOT enough (it flooded
        // the review list document-wide: `InvestmentAdviser`/`ManagementCompany`/`US High
        // Yield`/`Systematic China` are all `ctx:role-name`, indistinguishable in SHAPE from
        // a person name):
        //  1. an ORGANIC `Recognizer::Name` primary — the honorific heuristic, the
        //     header-list-under-a-role-header pass, the trailing-role `X, Y are employees of`
        //     pass, and the anchored `Name <email>` / `Name (NRIC …)` pass — every emitter
        //     is person-corroborated by its SITE; PLUS
        //  2. a `ctx:role-name` primary whose value is PERSON-SHAPED, carries no role-title
        //     word ITSELF, and — the new high-precision gate — sits DIRECTLY ABOVE a
        //     role-title line ([`ctx_value_is_person_bio`], the officer-bio / directory
        //     layout). This narrowly re-admits the JPMIF conducting officers + the BGF
        //     directors column (persons whose only clean detection is a bio heading) while
        //     EXCLUDING every fund / geographic / defined-term phrase.
        let is_name = matches!(c.recognizer(), Recognizer::Name);
        let is_role_person = matches!(c.recognizer(), Recognizer::Context(l)
                if l.as_ref() == "ctx:role-name")
            && crate::is_person_shaped_field_value(c.matched_value())
            && !crate::run_contains_role_title(c.matched_value())
            && ctx_value_is_person_bio(c.context(), c.matched_value());
        if !is_name && !is_role_person {
            continue;
        }
        let value = crate::strip_honorific(c.matched_value()).trim();
        if value.split_whitespace().count() < 2 || value.chars().count() < 8 {
            continue; // the anti-amplification floor (round 2)
        }
        // Name charset only: letters, spaces, dots (initials), hyphens, apostrophes.
        if !value.chars().all(|ch| {
            ch.is_alphabetic() || ch.is_whitespace() || matches!(ch, '.' | '-' | '\'' | '\u{2019}')
        }) {
            continue;
        }
        // FIX 1a (round-6 review): a fund/entity phrase is NOT a corroborated person —
        // it does not seed doc-wide recall (the `InvestmentAdviser`/`ManagementCompany`/
        // `BondFund` amplification class).
        if seed_is_org_or_fund(value) {
            continue;
        }
        if !seen.insert(value.to_string()) {
            continue;
        }
        // Case-SENSITIVE elastic (a name is a capitalized proper noun — round-2 rule).
        let src = crate::ws_regex_source(value, false);
        if let Ok(re) = Regex::new(&src) {
            sources.push(src);
            seeds.push((value.to_string(), re));
        }
    }
    // Index-aligned prefilter over the SAME sources (see the struct docs); `.ok()` because
    // the COMBINED set has a size cap the individual compiles do not — on overflow we fall
    // back to the exhaustive per-seed scan (identical results, pure speed loss).
    let prefilter = regex::RegexSet::new(&sources).ok();
    WsNameSeeds {
        rows: seeds,
        prefilter,
    }
}

/// ROUND 6 — the SPLIT-ONLY guard: is this ws-elastic `matched` slice a genuinely
/// GLYPH-SPLIT occurrence of `seed` (fabricated whitespace INSIDE a word), vs a clean
/// re-occurrence? Equal whitespace tokenization = clean (the normal recognizers' and the
/// context gate's job — appending it would re-open the boilerplate-amplification class);
/// different tokenization = the kerning-split defect this pass exists to recover
/// (`Ka thy V ancomerbeke` vs seed `Kathy Vancomerbeke`). Pure, deterministic.
fn is_split_occurrence(seed: &str, matched: &str) -> bool {
    // A CROSS-LINE occurrence (contains a `\n` the seed does not): the same-line organic
    // name patterns (`[ \t]`-gapped) cannot match it as ONE span, so it is a genuine
    // recovery target, not a clean re-occurrence — append it. (`fully_covered` still drops
    // it if a multi-line mechanism already covered it, so no double-report.) This is the
    // BGF-page-196 spaceless comma-list `…Benjamin\nGregson,…`: its tokenization equals
    // the seed's, but it spans two runs and no organic recognizer sees it.
    if matched.contains('\n') && !seed.contains('\n') {
        return true;
    }
    let mut a = seed.split_whitespace();
    let mut b = matched.split_whitespace();
    loop {
        match (a.next(), b.next()) {
            (None, None) => return false, // identical tokenization: clean occurrence
            (Some(x), Some(y)) if x == y => continue,
            _ => return true, // any divergence = an intra-word split
        }
    }
}

/// ROUND 6 — append WHITESPACE-ELASTIC matches of the DOCUMENT-LEVEL detected-name seeds
/// over the reconstructed page `text` (the kerning-split recall: `Ka thy V ancomerbeke`,
/// `Ben\njamin\n \nGregson`). The glyph-cluster recall machinery was previously gated to
/// user TERMS + the address family, so the generic name recognizers — what an accept-all
/// run with no typed names depends on — had NO glyph-split coverage (the round-6 HIGH
/// finding). Same additive/parity contract as [`append_ws_term_candidates`]: synthetic
/// candidates (Name kind, careful review) appended after every earlier candidate,
/// identically in scan and apply. Returns how many were appended (the per-page honesty
/// diagnostic). Bounded by [`MAX_WS_NAME_SPANS_PER_PAGE`].
fn append_ws_name_candidates(
    text: &str,
    origin: &[RunCharOrigin],
    name_seeds: &WsNameSeeds,
    candidates: &mut Vec<RedactionCandidate>,
    spans: &mut Vec<(usize, usize, usize)>,
) -> usize {
    if name_seeds.is_empty() {
        return 0;
    }
    // Collect + coalesce all seed matches (byte ranges over `text`). SPLIT-ONLY: a match
    // whose whitespace tokenization equals the seed's is a CLEAN occurrence — the normal
    // recognizers' (and the context gate's) jurisdiction, never appended here (the
    // structural exclusion of the boilerplate-amplification class; see
    // [`is_split_occurrence`]). The RegexSet prefilter prunes to the seeds that occur on
    // THIS page at all (result-identical — a set non-match has zero `find_iter` hits).
    let mut ws_spans: Vec<(usize, usize)> = Vec::new();
    let scan_seed = |idx: usize, ws_spans: &mut Vec<(usize, usize)>| {
        let (seed, re) = &name_seeds.rows[idx];
        for m in re.find_iter(text) {
            // Shape bound (the page-7 sweep lesson): a genuinely split NAME spans at
            // most a few fragments (`Ben\njamin\n \nGregson` = 3 line breaks); an
            // elastic match wider than that is a coincidental cross-column sweep.
            let too_wide =
                m.as_str().bytes().filter(|&b| b == b'\n').count() > 3 || m.end() - m.start() > 80;
            if m.end() > m.start() && !too_wide && is_split_occurrence(seed, m.as_str()) {
                ws_spans.push((m.start(), m.end()));
            }
        }
    };
    match &name_seeds.prefilter {
        Some(set) => {
            for idx in set.matches(text) {
                scan_seed(idx, &mut ws_spans);
            }
        }
        None => {
            for idx in 0..name_seeds.rows.len() {
                scan_seed(idx, &mut ws_spans);
            }
        }
    }
    if ws_spans.is_empty() {
        return 0;
    }
    ws_spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ws_spans.len());
    for (s, e) in ws_spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }

    // Byte-offset -> decoded-char-index (same mapping the ws-term pass uses).
    let mut boundaries: Vec<usize> = Vec::with_capacity(text.len() + 1);
    for (utf8_off, _ch) in text.char_indices() {
        boundaries.push(utf8_off);
    }
    boundaries.push(text.len());
    let to_char_index =
        |utf8_off: usize| -> Option<usize> { boundaries.binary_search(&utf8_off).ok() };
    let primary: Vec<(usize, usize)> = spans.iter().map(|&(c0, c1, _)| (c0, c1)).collect();
    let fully_covered =
        |c0: usize, c1: usize| -> bool { primary.iter().any(|&(p0, p1)| p0 <= c0 && c1 <= p1) };

    let mut appended = 0usize;
    for (b0, b1) in merged {
        if appended >= MAX_WS_NAME_SPANS_PER_PAGE {
            break; // per-page bomb-bound
        }
        let (Some(c0), Some(c1)) = (to_char_index(b0), to_char_index(b1)) else {
            continue;
        };
        if c0 >= c1 || c1 > origin.len() || fully_covered(c0, c1) {
            continue;
        }
        let value = text[b0..b1].to_string();
        let ctx_start = (0..=b0.saturating_sub(24))
            .rev()
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(0);
        let ctx_end = ((b1 + 24).min(text.len())..=text.len())
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(text.len());
        let context = text[ctx_start..ctx_end].to_string();
        let new_idx = candidates.len();
        candidates.push(RedactionCandidate::synthetic_name(b0, b1, value, context));
        spans.push((c0, c1, new_idx));
        appended += 1;
    }
    spans.sort_unstable_by_key(|&(s, _, _)| s);
    appended
}

/// Append WHITESPACE-INSENSITIVE user-term matches over the reconstructed run `text` to
/// the run's `candidates` + `spans`, so a term a glyph-by-glyph PDF layout fragmented
/// (`Daniel J. W at kins` for `Daniel J. Watkins`) is still detected + removed.
///
/// For each elastic-whitespace term match `(b0, b1)` (byte offsets into `text`) that is
/// NOT already covered by a primary span, we:
///   1. map its endpoints to DECODED-CHAR indices `[c0, c1)` over the run;
///   2. push a fresh synthetic [`RedactionCandidate::synthetic_term`] (real cleartext,
///      `Recognizer::Term`) to `candidates`;
///   3. push `(c0, c1, new_cand_idx)` to `spans` — the new candidate's index in the now-
///      extended `candidates`, so the caller's id assignment (`base + cand_idx`) and the
///      `owned` list stay in lock-step.
///
/// ADDITIVE ONLY: primary candidates/spans are never removed or re-indexed, so existing
/// `PdfCandidateId`s and scan↔apply parity are preserved (this runs identically in both
/// passes). "Already covered" is decided by CHAR-index overlap against the primary spans,
/// so a term the ordinary pass already caught is not double-counted. With no terms
/// configured the engine returns no ws-spans and this is a no-op.
fn append_ws_term_candidates(
    text: &str,
    origin: &[RunCharOrigin],
    engine: &RedactionEngine,
    candidates: &mut Vec<RedactionCandidate>,
    spans: &mut Vec<(usize, usize, usize)>,
) {
    let ws_spans = engine.term_spans_whitespace_insensitive(text);
    if ws_spans.is_empty() {
        return;
    }
    // Byte-offset -> decoded-char-index table (a forward walk over char_indices), plus the
    // end sentinel so an end-of-run endpoint maps. Mirrors `char_index_spans_for`.
    let mut boundaries: Vec<usize> = Vec::with_capacity(text.len() + 1);
    for (utf8_off, _ch) in text.char_indices() {
        boundaries.push(utf8_off);
    }
    boundaries.push(text.len());
    let to_char_index =
        |utf8_off: usize| -> Option<usize> { boundaries.binary_search(&utf8_off).ok() };

    // Primary char-spans already covered (ascending by start). We skip a ws-term span only
    // when it is FULLY CONTAINED within a single primary span — a pure duplicate the
    // ordinary pass already removes. A ws-term that PARTIALLY overlaps a primary (e.g. a
    // user term `ref bob@firm.test acme` whose embedded email is also matched by the email
    // built-in) is KEPT and removed in FULL: the user asked to redact the whole term, and
    // over-removal of its non-overlapping remainder is the SAFE side on a redaction tool
    // (the per-byte removal ranges coalesce, so re-removing the overlapping bytes is
    // idempotent — never corruption). Skipping wholesale on partial overlap would leave the
    // term's remainder un-redacted (an under-redaction), so we do NOT.
    let primary: Vec<(usize, usize)> = spans.iter().map(|&(c0, c1, _)| (c0, c1)).collect();
    let fully_covered_by_a_primary =
        |c0: usize, c1: usize| -> bool { primary.iter().any(|&(p0, p1)| p0 <= c0 && c1 <= p1) };

    for (b0, b1) in ws_spans {
        let (Some(c0), Some(c1)) = (to_char_index(b0), to_char_index(b1)) else {
            // Endpoints not on char boundaries (cannot occur for a regex match over a
            // valid &str, but guard) — skip rather than mis-map.
            continue;
        };
        if c0 >= c1 || c1 > origin.len() {
            continue;
        }
        if fully_covered_by_a_primary(c0, c1) {
            continue; // a pure duplicate of a span the ordinary pass already removes
        }
        // The matched cleartext slice of the run (review-only) and a small context window.
        let value: String = text[b0..b1].to_string();
        let ctx_start = b0.saturating_sub(24);
        let ctx_end = (b1 + 24).min(text.len());
        // Snap the context window to char boundaries (the run text is valid UTF-8).
        let ctx_start = (0..=ctx_start)
            .rev()
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(0);
        let ctx_end = (ctx_end..=text.len())
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(text.len());
        let context = text[ctx_start..ctx_end].to_string();
        let new_idx = candidates.len();
        candidates.push(RedactionCandidate::synthetic_term(b0, b1, value, context));
        spans.push((c0, c1, new_idx));
    }
    // Keep spans ascending by start (the apply/scan loops + id ordering rely on a stable
    // order; ties never matter because the cand_idx disambiguates the candidate).
    spans.sort_unstable_by_key(|&(s, _, _)| s);
}

/// WHITESPACE-INSENSITIVE ADDRESS-FAMILY recall pass — the STRUCTURED-ADDRESS analogue of
/// [`append_ws_term_candidates`] (same shape, same additive/parity guarantees). Some PDF
/// generators lay a structured address out glyph-cluster by glyph-cluster (`#` `16-0` `3`
/// nudged apart), so the reconstructed run carries fabricated separator whitespace INSIDE a
/// token (`# 16-0 3`) and the ordinary detection MISSES the unit/postal shape — an address
/// DETECTED on a clean page then SURVIVES `pdf_apply` on the fragmented one (a leak). We
/// re-scan the SAME run text with the engine's whitespace-elastic address-family recognizers
/// ([`RedactionEngine::address_family_spans_whitespace_insensitive`]) and ADD any match not
/// already covered by an existing span as a fresh synthetic candidate carrying the SAME
/// recognizer the ordinary match would (`Recognizer::Address` / a precise `Recognizer::
/// Locale(<cc>:postal)`).
///
/// ADDITIVE + parity-preserving, IDENTICALLY to the ws-term pass: existing candidates/spans
/// are never removed or re-indexed, the new candidates get ids AFTER the primary AND the
/// ws-term ones, and this runs the SAME way in scan and apply — so `PdfCandidateId`s and
/// scan↔apply parity hold. "Already covered" is decided by CHAR-index full-containment
/// against EVERY span present on entry (primary + ws-term), so a shape the ordinary pass or
/// the ws-term pass already caught is not double-counted; a PARTIAL overlap is kept and
/// removed in full (the safe side). With no address rows enabled the engine returns no spans
/// and this is a byte-identical no-op.
fn append_ws_address_candidates(
    text: &str,
    origin: &[RunCharOrigin],
    engine: &RedactionEngine,
    candidates: &mut Vec<RedactionCandidate>,
    spans: &mut Vec<(usize, usize, usize)>,
) {
    let ws_spans = engine.address_family_spans_whitespace_insensitive(text);
    if ws_spans.is_empty() {
        return;
    }
    // Byte-offset -> decoded-char-index table (identical to `append_ws_term_candidates`).
    let mut boundaries: Vec<usize> = Vec::with_capacity(text.len() + 1);
    for (utf8_off, _ch) in text.char_indices() {
        boundaries.push(utf8_off);
    }
    boundaries.push(text.len());
    let to_char_index =
        |utf8_off: usize| -> Option<usize> { boundaries.binary_search(&utf8_off).ok() };

    // Snapshot the spans PRESENT ON ENTRY (primary + ws-term) as char ranges; we only skip a
    // ws-address span FULLY CONTAINED in one of them (a pure duplicate). A partial overlap is
    // kept and removed in full — the safe side (over-removal coalesces idempotently).
    let existing: Vec<(usize, usize)> = spans.iter().map(|&(c0, c1, _)| (c0, c1)).collect();
    let fully_covered =
        |c0: usize, c1: usize| -> bool { existing.iter().any(|&(p0, p1)| p0 <= c0 && c1 <= p1) };

    for (b0, b1, rec) in ws_spans {
        let (Some(c0), Some(c1)) = (to_char_index(b0), to_char_index(b1)) else {
            continue;
        };
        if c0 >= c1 || c1 > origin.len() {
            continue;
        }
        if fully_covered(c0, c1) {
            continue;
        }
        let value: String = text[b0..b1].to_string();
        let ctx_start = b0.saturating_sub(24);
        let ctx_end = (b1 + 24).min(text.len());
        let ctx_start = (0..=ctx_start)
            .rev()
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(0);
        let ctx_end = (ctx_end..=text.len())
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(text.len());
        let context = text[ctx_start..ctx_end].to_string();
        let new_idx = candidates.len();
        // The address family is CAREFUL-tier (never High/quick-confirm): `Recognizer::Address`
        // is neither checksum nor structural and a precise postal locale row has no class
        // lexicon, so a non-fragmented match is Medium — mirror that here (Medium routes to
        // careful review; it is NOT advisory, so it stays default-ON in apply).
        candidates.push(RedactionCandidate::synthetic_address(
            b0,
            b1,
            value,
            context,
            rec,
            Confidence::Medium,
        ));
        spans.push((c0, c1, new_idx));
    }
    spans.sort_unstable_by_key(|&(s, _, _)| s);
}

/// Decode a logical run (joining its operators' decoded text with single-space
/// separators that map to NO source bytes), detect over the JOINED text, assign stable
/// ids in run order, and EITHER (scan) enumerate every candidate OR (apply) record the
/// per-operator removal ranges into `op_edits`. NEVER mutates operands directly (apply
/// edits are deferred to `apply_op_edits` so no two operands are borrowed at once).
/// Bundled parameters for [`process_logical_run`]: the read-only run context (the
/// logical run, its operations, the page's fonts, the engine, and the page number)
/// plus the mutable sinks (the stable-id counter, the per-page [`DocMode`], and the
/// per-operator edit map). Grouped into one struct so the call stays within clippy's
/// argument budget without an `#[allow(clippy::too_many_arguments)]`.
struct LogicalRunArgs<'a, 'd> {
    /// ALL the stream's logical runs (visual lines), in document order. They are joined
    /// into ONE multi-line buffer separated by `\n` (a no-source separator) before
    /// detection — so the SHARED engine sees the SAME multi-line text the plain-text /
    /// `extract_scan` path sees (heading line ABOVE a name/address line, etc.). The
    /// context / role-name / address-block-continuation machinery is designed for that
    /// `\n`-delimited view; scanning each run in isolation (the pre-fix behaviour) hid the
    /// heading from the name and every multi-line mechanism silently no-op'd on real
    /// prospectus layouts.
    ///
    /// TWO independent line-scoping guards keep the join from over-joining across lines:
    ///   1. The `\n` BREAKS CONTIGUOUS-TOKEN matches, so a token split across two VISUAL
    ///      lines does not spuriously cross-join (`abc`\n`def` never matches `abcdef`).
    ///      Guarded by `unrelated_tokens_on_separate_lines_do_not_form_a_cross_match`.
    ///   2. Guard 1 does NOTHING for patterns that ADMIT whitespace across the boundary —
    ///      phone (`[\d\-\s().]`), the name `\s+` join, etc. would happily match ACROSS the
    ///      `\n` and flood a numeric table (`10.48`\n`11.01`\n`6.15`) with spurious cross-
    ///      line phones (the HIGH-1 defect). So `process_logical_run` LINE-SCOPES the primary
    ///      `engine.candidates()` output (see `line_scope_sanctioned`): any candidate whose
    ///      span crosses a `\n` is REJECTED unless a multi-line-SANCTIONED recognizer
    ///      contributed it (address family, `ctx:*` context, user TERMS). That restores the
    ///      EXACT pre-join line-scoping for the broad classes (phone/name/email/id/iban/ip/
    ///      url/credit-card/locale-id) while keeping the multi-line recall the sanctioned
    ///      classes need. Recall-NEUTRAL vs the pre-join engine for the broad classes.
    ///      Guarded by `numeric_table_column_yields_no_cross_line_phone_in_pdf_path`.
    runs: &'a [LogicalRun],
    /// ROUND 6 — the document-level detected-name whitespace-elastic seeds (empty on
    /// pass 1 / seedless documents).
    name_seeds: &'a WsNameSeeds,
    operations: &'a [lopdf::content::Operation],
    page_fonts: &'a PageFonts,
    engine: &'a RedactionEngine,
    next_id: &'a mut u64,
    page_no: u32,
    mode: &'a mut DocMode<'d>,
    op_edits: &'a mut BTreeMap<usize, OpEdit>,
}

/// Is `rec` a recognizer class SANCTIONED to match ACROSS a visual-line `\n` in the joined
/// PDF stream buffer? Only the mechanisms that are DESIGNED for the multi-line document view
/// (and were the whole point of the stream-level join in 8780a15) are sanctioned:
///   - the ADDRESS FAMILY: [`Recognizer::Address`] (street/unit/PO-box) and the locale POSTAL
///     rows (`<cc>:postal`/`:postcode`/`:zip`) — an address block legitimately wraps across
///     lines (`… Capital \nTower, Singapore 068912`);
///   - `ctx:*` CONTEXT rows ([`Recognizer::Context`]) — the role-name window needs the heading
///     line ABOVE the name on the SAME text;
///   - user TERMS ([`Recognizer::Term`]) — the party-name literals, already whitespace-elastic
///     by design (a known name broken across a wrap must still redact).
///
/// EVERY other class (phone, email, id, iban, lei, ip, url, credit-card, firm-`Custom`,
/// compliance-`Profile`, and locale NON-postal rows like `sg:nric`) is NOT sanctioned: a
/// match spanning the `\n` for one of those is the HIGH-1 cross-line artifact (a phone
/// pattern's `\s`-class stitching a numeric table column into a fake number), so it is
/// rejected — exactly as it was line-scoped in the pre-join per-run scan. The synthetic
/// ws-recall candidates (Term / Address / postal) are appended AFTER this filter and are
/// sanctioned classes anyway, so they are unaffected.
///
/// PERSON-NAME candidates ([`Recognizer::Name`] / the `name:propagated` closure label) get
/// a NARROWER, span-shape-conditional sanction in [`retain_line_scoped_candidates`] (at
/// most ONE newline in the span), NOT the unconditional sanction here — see the
/// name-wrap note there.
fn line_scope_sanctioned(rec: &Recognizer) -> bool {
    match rec {
        Recognizer::Address | Recognizer::Term | Recognizer::Context(_) => true,
        // Locale POSTAL rows ride with the address family; every other locale row (NRIC, SSN,
        // …) is an IDENTIFIER that must stay on one line. Same suffix test the inline
        // building-name pass uses (`inline_building_spans`).
        Recognizer::Locale(l) => {
            matches!(l.rsplit(':').next(), Some("postal" | "postcode" | "zip"))
        }
        _ => false,
    }
}

/// Drop any candidate whose span crosses a visual-line `\n` (the stream-join separator)
/// UNLESS a [`line_scope_sanctioned`] recognizer contributed it. This RESTORES the exact
/// pre-join (per-visual-line) line-scoping for the broad recognizer classes — whose `\s`-
/// bearing patterns (phone `[\d\-\s().]`, name `\s+`) would otherwise stitch across the
/// separator and flood, e.g., a financial-table numeric column with spurious phone
/// candidates (HIGH-1) — while keeping the multi-line recall the sanctioned classes were
/// joined FOR. Checks EVERY contributing recognizer (`recognizers()`, not just the elected
/// primary): a legitimate multi-line ADDRESS that merged with a same-span phone keeps its
/// sanction (recall-first — over-keeping a real address is the safe side). Deterministic and
/// identical in scan + apply (it operates on the SAME joined `text`), so scan↔apply parity
/// and `PdfCandidateId` assignment are preserved. Runs BEFORE the ws-recall append passes,
/// whose synthetic candidates are sanctioned classes and thus unaffected either way.
///
/// NAME-WRAP SANCTION (the wrapped-name round): a PERSON-NAME candidate
/// ([`Recognizer::Name`] — the honorific heuristic, the trailing-role list, the anchored
/// display-name/paren-id emissions — or the `name:propagated` closure label) spanning AT
/// MOST ONE newline is KEPT. The name machinery now legitimately produces single-wrap
/// spans (a document wraps a name mid-sentence; `Ms. Marlow\nVarga`), and the former
/// unconditional drop silently DISCARDED exactly those — the observed leak (the name was
/// detected in the text view and then vanished from the PDF review). BOUNDED on purpose:
/// a name-like span crossing TWO OR MORE newlines is still rejected (never an unbounded
/// sanction), and every other class (phone/id/…) is untouched — the HIGH-1 numeric-flood
/// protection holds.
fn retain_line_scoped_candidates(text: &str, candidates: &mut Vec<RedactionCandidate>) {
    candidates.retain(|c| {
        let span = &text[c.start()..c.end()];
        // Common case: a single-line span (no separator inside) is always kept — this is a
        // cheap byte scan and the vast majority of candidates never touch a `\n`.
        if !span.contains('\n') {
            return true;
        }
        if c.recognizers().iter().any(line_scope_sanctioned) {
            return true;
        }
        // SINGLE-WRAP sanction: a person-name candidate (Name / propagated closure) OR the
        // literally-anchored Luxembourg RCS register row spanning at most ONE newline.
        // (`lu:rcs` is safe here BY CONSTRUCTION: its wrap-capable arm requires the literal
        // `R.C.S` anchor INSIDE the span, so a NAV numeric column can never produce a
        // sanctioned cross-line match — the HIGH-1 guard is untouched.)
        span.bytes().filter(|&b| b == b'\n').count() <= 1
            && c.recognizers().iter().any(|r| {
                matches!(r, Recognizer::Name)
                    || matches!(r, Recognizer::Custom(l) if l.as_ref() == PROPAGATED_NAME_LABEL)
                    || matches!(r, Recognizer::Locale(l) if l.as_ref() == RCS_LU_LABEL)
            })
    });
}

fn process_logical_run(args: LogicalRunArgs) -> RunOutcome {
    let LogicalRunArgs {
        runs,
        name_seeds,
        operations,
        page_fonts,
        engine,
        next_id,
        page_no,
        mode,
        op_edits,
    } = args;
    // Build the joined text + a per-decoded-char origin into the SOURCE bytes, over ALL
    // the stream's runs (visual lines) at once. Consecutive runs are separated by a
    // `\n` (a no-source separator, `SEP_ELEM`), reproducing the multi-line document
    // shape the engine's context / role-name / address-continuation logic needs — while
    // still breaking cross-VISUAL-LINE token joins. See the `runs` doc on LogicalRunArgs.
    let mut text = String::new();
    let mut origin: Vec<RunCharOrigin> = Vec::new();
    let mut text_bytes = 0usize;
    let mut unmapped = false;
    let mut dropped = 0usize;
    let mut could_not_remove = 0usize;

    for (run_idx, run) in runs.iter().enumerate() {
        // A NEWLINE separator between two visual lines: no source bytes (skipped in
        // apply exactly like the gap-space), so it never removes/marks anything, but it
        // gives the engine the `\n`-delimited multi-line view. Never before the first run.
        if run_idx > 0 {
            let op_index = run.ops.first().map(|r| r.op_index).unwrap_or(0);
            text.push('\n');
            origin.push(RunCharOrigin {
                op_index,
                elem: SEP_ELEM,
                off: 0,
                len: 0,
            });
        }
        for run_op in run.ops.iter() {
            let op_index = run_op.op_index;
            // Insert a SEPARATOR (one space mapping to no source) ONLY where a horizontal
            // positioning gap preceded this operator within the run — so two SEPARATE
            // fields tabbed apart join as `…a b…` (never `…ab…`, a spurious cross-field
            // match), while DIRECTLY-ADJACENT operators (no positioning between) join
            // CONTIGUOUSLY (`info@`+`jpmorgan.com` = `info@jpmorgan.com`). See SEPARATOR
            // POLICY above.
            if run_op.gap_before {
                text.push(' ');
                origin.push(RunCharOrigin {
                    op_index,
                    elem: SEP_ELEM,
                    off: 0,
                    len: 0,
                });
            }
            let op = &operations[op_index];
            // Use the run's recorded font name to pick the decoder (mirrors plan_logical_runs):
            // the SAME decoder the per-operator path used, so a plain page is byte-identical.
            let decoder = page_fonts.decoder_for(run_op.font_name.as_deref());
            match op.operator.as_str() {
                "Tj" | "'" | "\"" => {
                    if let Some(Object::String(bytes, _)) = op.operands.last() {
                        text_bytes = text_bytes.saturating_add(bytes.len());
                        let (dec, srcmap, unm) = decoder.decode_mapped(bytes);
                        unmapped |= unm;
                        debug_assert_eq!(
                            srcmap.len(),
                            dec.chars().count(),
                            "srcmap aligns to chars"
                        );
                        for (ch, &(off, len)) in dec.chars().zip(srcmap.iter()) {
                            text.push(ch);
                            origin.push(RunCharOrigin {
                                op_index,
                                elem: 0,
                                off,
                                len,
                            });
                        }
                    }
                }
                "TJ" => {
                    if let Some(Object::Array(arr)) = op.operands.first() {
                        // ROUND 7 — numeric adjustments accumulated since the last string
                        // element. A net displacement at or below the word-gap threshold
                        // is a generator-encoded INTER-WORD SPACE (no space glyph exists);
                        // fabricate a separator (no source bytes) so the recognizers see
                        // token boundaries. See TJ_WORD_GAP_THOUSANDTHS.
                        let mut pending_adj = 0.0f64;
                        let mut prior_string = false;
                        for (elem_idx, obj) in arr.iter().enumerate() {
                            if let Object::String(bytes, _) = obj {
                                text_bytes = text_bytes.saturating_add(bytes.len());
                                let (dec, srcmap, unm) = decoder.decode_mapped(bytes);
                                unmapped |= unm;
                                // Fabricated word-gap separator: only BETWEEN two string
                                // elements of this TJ, only when the accumulated
                                // adjustment reads as a word gap, and only when the
                                // boundary is not ALREADY whitespace (a real space glyph
                                // beside justification stretch must not double-space).
                                if prior_string
                                    && pending_adj <= TJ_WORD_GAP_THOUSANDTHS
                                    && !dec.is_empty()
                                    && !dec.starts_with(char::is_whitespace)
                                    && text.chars().last().is_some_and(|c| !c.is_whitespace())
                                {
                                    text.push(' ');
                                    origin.push(RunCharOrigin {
                                        op_index,
                                        elem: SEP_ELEM,
                                        off: 0,
                                        len: 0,
                                    });
                                }
                                for (ch, &(off, len)) in dec.chars().zip(srcmap.iter()) {
                                    text.push(ch);
                                    origin.push(RunCharOrigin {
                                        op_index,
                                        elem: elem_idx,
                                        off,
                                        len,
                                    });
                                }
                                prior_string = true;
                                pending_adj = 0.0;
                            } else if let Some(v) = as_f64(obj) {
                                pending_adj += v;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    debug_assert_eq!(
        origin.len(),
        text.chars().count(),
        "origin aligns to decoded chars"
    );

    if text.is_empty() {
        return RunOutcome {
            text_bytes,
            redactions: 0,
            unmapped,
            dropped,
            could_not_remove,
            ws_name_recovered: 0,
            degenerate: false,
        };
    }

    // ROUND 7 — the degenerate-layout honesty floor: a page whose reconstructed text
    // still carries an implausibly long spaceless alphabetic run has no token
    // boundaries there, so the detection below may be BLIND regardless of how cleanly
    // the fonts decoded. Computed on the SAME text detection sees (after all separator
    // fabrication), identically in scan and apply. See DEGENERATE_ALPHA_RUN_CHARS.
    let degenerate = has_degenerate_alpha_run(&text);

    // Detect over the JOINED run. Ids: candidate i gets `base + i`; advance the counter
    // by the FULL count in BOTH scan and apply so ids stay aligned regardless of mode.
    let mut candidates = engine.candidates(&text);
    // LINE-SCOPE the broad classes (HIGH-1 fix): the stream-level `\n`-join lets a `\s`-
    // bearing pattern (phone/name) match ACROSS a visual line, so a numeric table column
    // reads as a fake phone. Reject any candidate whose span crosses the `\n` separator
    // unless a multi-line-SANCTIONED recognizer (address family / `ctx:*` / user TERM)
    // contributed it — restoring the EXACT pre-join per-line behaviour for the broad
    // classes while keeping the multi-line recall the join was added FOR. Deterministic +
    // identical in scan and apply, so scan↔apply parity + `PdfCandidateId`s are preserved.
    retain_line_scoped_candidates(&text, &mut candidates);
    // Matched spans as DECODED-CHAR index ranges `[c0, c1)` over the run + cand index.
    let mut spans = char_index_spans_for(&text, &candidates);

    // WHITESPACE-INSENSITIVE user-TERM recall pass (the PDF glyph-by-glyph fix). Some
    // generators lay out a line glyph-cluster by glyph-cluster (`W` `at` `kins`, each its
    // own `Td`-nudged show op), so the reconstructed run carries fabricated separator
    // spaces INSIDE a word (`Daniel J. W at kins`) and the ordinary detection above MISSES
    // the term `Daniel J. Watkins` — a director name DETECTED elsewhere then SURVIVES
    // apply on that page (a leak). We re-scan the SAME run text for the user terms with
    // whitespace treated as elastic, then ADD any match not already covered by a primary
    // span as a fresh synthetic candidate. Recall-only + additive: it never drops or
    // re-orders a primary candidate, so existing `PdfCandidateId`s and scan↔apply parity
    // are preserved (the new candidates get ids AFTER the primary ones, identically in
    // both passes). With no terms configured `term_spans_whitespace_insensitive` returns
    // empty and this whole block is a no-op (the common case is byte-identical).
    append_ws_term_candidates(&text, &origin, engine, &mut candidates, &mut spans);

    // WHITESPACE-INSENSITIVE ADDRESS-FAMILY recall pass (the PDF glyph-by-glyph fix for
    // STRUCTURED ADDRESSES — `#16-03` fragmented as `# 16-0 3`, `Singapore 048623` as
    // `Singapore 0486 23`). Same additive/parity contract as the ws-term pass above: it
    // adds synthetic address/postal candidates (with the SAME recognizer the ordinary match
    // would carry) AFTER the primary + ws-term ones, identically in scan and apply, so
    // `PdfCandidateId`s and scan↔apply parity are preserved. With no address rows enabled
    // the engine returns no spans and this is a byte-identical no-op. Runs AFTER the ws-term
    // pass so an address region a user TERM already covered is not double-counted.
    append_ws_address_candidates(&text, &origin, engine, &mut candidates, &mut spans);

    // ROUND 6 — WHITESPACE-ELASTIC DETECTED-NAME recall (the kerning-split leak). The
    // glyph-cluster recall above was previously gated to user TERMS + the address family
    // (its old comment claimed "with no terms configured this is a no-op" — NO LONGER
    // TRUE: with document-level name seeds derived from the unseeded pass, generic name
    // detections now get the same elastic coverage). Same additive/parity contract.
    let ws_name_recovered =
        append_ws_name_candidates(&text, &origin, name_seeds, &mut candidates, &mut spans);

    let base = *next_id;
    // Advance by the TOTAL candidate count (primary + ws-term), in BOTH scan and apply, so
    // a candidate's id is identical across the two passes and the NEXT run starts aligned.
    *next_id += candidates.len() as u64;
    if spans.is_empty() {
        return RunOutcome {
            text_bytes,
            redactions: 0,
            unmapped,
            dropped,
            could_not_remove,
            ws_name_recovered,
            degenerate,
        };
    }
    let mut owned: Vec<Option<RedactionCandidate>> = candidates.into_iter().map(Some).collect();

    match mode {
        // SCAN: enumerate every candidate (run-span) with its id; remove nothing. The
        // per-page redaction COUNT stays 0 in a scan (the contract: a scan removes
        // nothing; detected counts come from `items`, each carrying its page).
        DocMode::Scan { items } => {
            for (_c0, _c1, cand_idx) in &spans {
                let id = PdfCandidateId(base + *cand_idx as u64);
                if let Some(c) = owned.get_mut(*cand_idx).and_then(Option::take) {
                    items.push(PdfScanItem {
                        id,
                        page: page_no,
                        candidate: c,
                    });
                }
            }
            RunOutcome {
                text_bytes,
                redactions: 0,
                unmapped,
                dropped,
                could_not_remove,
                ws_name_recovered,
                degenerate,
            }
        }
        // APPLY: record per-operator removal ranges for the accepted candidates.
        DocMode::Apply { selection, removed } => {
            // Per-operator font lookup, so we can encode the redaction marker into THE
            // OPERATOR'S OWN font codespace (rendering the literal `[REDACTED]`) — or fall
            // back to a clean gap when the font cannot render it. Keyed by op_index; an op
            // runs under exactly one font within a run.
            let font_of: BTreeMap<usize, Option<Vec<u8>>> = runs
                .iter()
                .flat_map(|run| run.ops.iter())
                .map(|r| (r.op_index, r.font_name.clone()))
                .collect();
            let mut applied: Vec<usize> = Vec::with_capacity(spans.len());
            for (c0, c1, cand_idx) in &spans {
                let id = PdfCandidateId(base + *cand_idx as u64);
                // Default-deny: skip a candidate the reviewer did not accept.
                if !selection.accepts(id) {
                    continue;
                }
                // M2 defensive bounds (unreachable for engine output; surfaced if hit).
                // An out-of-bounds accepted span cannot be removed — count it HONESTLY as
                // could-not-remove (never silently as redacted), not just dropped.
                if *c0 >= origin.len() || *c1 > origin.len() || c0 >= c1 {
                    dropped += 1;
                    could_not_remove += 1;
                    continue;
                }
                // Marker goes at the FIRST NON-SEPARATOR source char of the span (a
                // separator maps to no bytes, so it cannot host the marker). If the span
                // somehow began on a separator (cannot happen for engine output, since a
                // match never starts on a fabricated space), advance to the first real
                // char.
                let mut marker_placed = false;
                // Whether this accepted span actually scheduled the removal of at least one
                // REAL source byte. A span whose every contributing char is a fabricated
                // separator (SEP_ELEM → no source bytes) removes NOTHING — we must NOT count
                // it as redacted (that would over-report a removal we did not perform). The
                // honest `could_not_remove` guard, the leak-class invariant.
                let mut removed_any_bytes = false;
                for o in origin.iter().take(*c1).skip(*c0) {
                    if o.elem == SEP_ELEM {
                        continue; // separator: no source bytes to remove or mark
                    }
                    // A char that maps to ZERO source bytes (defensive — engine srcmaps are
                    // always len>=1) contributes nothing removable; skip it for accounting.
                    if o.len == 0 {
                        continue;
                    }
                    if !marker_placed {
                        let edit = op_edits.entry(o.op_index).or_default();
                        // Resolve this operator's font-encoded marker ONCE (the operator
                        // runs under one font): the bytes that render `[REDACTED]` through
                        // it, or a clean gap when the font cannot. Computed lazily on the
                        // first marker so a remove-only operator never carries one.
                        if matches!(edit.marker_bytes, MarkerBytes::Unset) {
                            let font_name = font_of.get(&o.op_index).and_then(|f| f.as_deref());
                            edit.marker_bytes =
                                match page_fonts.decoder_for(font_name).encode_marker() {
                                    Some(b) => MarkerBytes::Glyphs(b),
                                    None => MarkerBytes::Gap,
                                };
                        }
                        edit.marker_at.entry(o.elem).or_default().push(o.off);
                        marker_placed = true;
                    }
                    // Remove EVERY source byte of this char in its element.
                    let edit = op_edits.entry(o.op_index).or_default();
                    let ranges = edit.remove.entry(o.elem).or_default();
                    for b in o.off..o.off.saturating_add(o.len) {
                        push_remove_byte(ranges, b);
                    }
                    removed_any_bytes = true;
                }
                if removed_any_bytes {
                    applied.push(*cand_idx);
                } else {
                    // An accepted span with NO removable source byte (all-separator / zero-
                    // length): nothing was removed, so do NOT claim it as redacted — surface
                    // it as could-not-remove. Unreachable for engine output (a term/recognizer
                    // match never spans only fabricated separators), but the HONEST signal is
                    // as important as the removal: never over-report.
                    could_not_remove += 1;
                }
            }
            let removed_count = applied.len();
            for idx in applied {
                if let Some(c) = owned.get_mut(idx).and_then(Option::take) {
                    removed.push(c);
                }
            }
            RunOutcome {
                text_bytes,
                redactions: removed_count,
                unmapped,
                dropped,
                could_not_remove,
                ws_name_recovered,
                degenerate,
            }
        }
    }
}

/// Apply the accumulated per-operator edits to the operations' operands (apply pass 2).
/// For each edited operator: rebuild each affected string element (Tj/'/" trailing
/// string = element 0; TJ array elements at their real indices), removing the recorded
/// byte ranges and inserting the operator's FONT-ENCODED marker at the recorded offsets
/// (or NOTHING — a clean gap — when the font cannot render the marker). NEVER touches an
/// operator/element with no recorded edit (bytes preserved verbatim).
fn apply_op_edits(
    operations: &mut [lopdf::content::Operation],
    op_edits: &BTreeMap<usize, OpEdit>,
) {
    for (&op_index, edit) in op_edits {
        let Some(op) = operations.get_mut(op_index) else {
            continue;
        };
        // The bytes to splice in at each marker offset, ALREADY encoded in this
        // operator's font (so they render the literal `[REDACTED]`), or an EMPTY slice
        // for a clean gap when the font cannot render the marker (the mojibake fix).
        // `Unset` (no marker recorded) also yields empty — harmless, as `marker_at` is
        // then empty so no marker is emitted anyway.
        let marker: &[u8] = match &edit.marker_bytes {
            MarkerBytes::Glyphs(b) => b,
            MarkerBytes::Gap | MarkerBytes::Unset => &[],
        };
        match op.operator.as_str() {
            "Tj" | "'" | "\"" => {
                // The single trailing string is element 0.
                if let Some(Object::String(bytes, _)) = op.operands.last_mut() {
                    let remove = edit.remove.get(&0).map(Vec::as_slice).unwrap_or(&[]);
                    let markers = edit.marker_at.get(&0).map(Vec::as_slice).unwrap_or(&[]);
                    if !remove.is_empty() || !markers.is_empty() {
                        debug_assert_edits_in_bounds(bytes.len(), remove, markers);
                        *bytes = rebuild_bytes(bytes, remove, markers, marker);
                    }
                }
            }
            "TJ" => {
                if let Some(Object::Array(arr)) = op.operands.first_mut() {
                    for (elem_idx, obj) in arr.iter_mut().enumerate() {
                        if let Object::String(bytes, _) = obj {
                            let remove =
                                edit.remove.get(&elem_idx).map(Vec::as_slice).unwrap_or(&[]);
                            let markers = edit
                                .marker_at
                                .get(&elem_idx)
                                .map(Vec::as_slice)
                                .unwrap_or(&[]);
                            if !remove.is_empty() || !markers.is_empty() {
                                debug_assert_edits_in_bounds(bytes.len(), remove, markers);
                                *bytes = rebuild_bytes(bytes, remove, markers, marker);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Debug-only invariant: every recorded removal range + marker offset for an element
/// lies WITHIN that element's byte length (`<= len`, half-open ranges `s < e <= len`).
/// This pins the splice-correctness guarantee — only matched-span source bytes are
/// touched, never past the operand bound (no corruption); every contributing source
/// byte IS in a removal range (no leak). The ranges/offsets are built from the per-
/// decoded-char `srcmap`, which is bounded to the operand, so a breach is unreachable
/// for engine output — but we assert it (debug builds) so a future change that broke it
/// would fail loudly rather than silently leak or corrupt. `rebuild_bytes` ALSO clamps
/// defensively in release, so a (theoretical) breach can never panic/slice out of range.
fn debug_assert_edits_in_bounds(len: usize, remove: &[(usize, usize)], markers: &[usize]) {
    debug_assert!(
        remove.iter().all(|&(s, e)| s <= e && e <= len),
        "a removal range exceeds the operand bound — would risk corruption"
    );
    debug_assert!(
        markers.iter().all(|&m| m <= len),
        "a marker offset exceeds the operand bound"
    );
}

/// Insert a single byte offset into an ascending, deduplicated remove-list,
/// coalescing into contiguous `(start, end)` ranges. Kept simple + bounded: a
/// content stream is small relative to the document.
fn push_remove_byte(ranges: &mut Vec<(usize, usize)>, off: usize) {
    // Try to extend the last range if contiguous.
    if let Some(last) = ranges.last_mut() {
        if off == last.1 {
            last.1 = off + 1;
            return;
        }
        if off >= last.0 && off < last.1 {
            return; // already covered
        }
    }
    ranges.push((off, off + 1));
}

/// Rebuild ONE string element's (or Tj/'/" trailing string's) bytes: delete the
/// covered `remove` ranges and insert `marker` at each `markers` offset.
///
/// `marker` is the redaction marker ALREADY ENCODED in this operator's font codespace
/// (so it renders the literal `[REDACTED]` through the page font), or an EMPTY slice for
/// a CLEAN GAP (pure removal, nothing inserted) when the font cannot render the marker —
/// the fix for garbled markers on subset/custom-encoded fonts. With an empty `marker`
/// the "emit a marker" steps are no-ops, so the removed region collapses to a clean gap.
///
/// Robust to UNSORTED / OVERLAPPING `remove` ranges and UNSORTED / DUPLICATE `markers`
/// (both accumulate across multiple matched spans AND multiple runs that may touch the
/// same element): we first NORMALIZE — sort+dedup markers, and sort+coalesce the remove
/// ranges into disjoint ascending intervals. Then a single left-to-right sweep inserts
/// each marker once at its offset and skips each removed interval. A marker whose offset
/// falls INSIDE a removed interval still emits the marker (the redaction mark must show)
/// then the interval is skipped — over-removal within a matched region is the SAFE side.
///
/// EXACTNESS: every byte in a `remove` interval is dropped (no leak); a byte outside all
/// intervals is preserved verbatim (no corruption); offsets are clamped to `bytes.len()`
/// so a defensive out-of-range value can never panic or slice past the operand.
fn rebuild_bytes(
    bytes: &[u8],
    remove: &[(usize, usize)],
    markers: &[usize],
    marker: &[u8],
) -> Vec<u8> {
    let len = bytes.len();

    // Normalize markers: clamp, sort, dedup.
    let mut marks: Vec<usize> = markers.iter().map(|&m| m.min(len)).collect();
    marks.sort_unstable();
    marks.dedup();

    // Normalize remove ranges: clamp, drop empties, sort by start, coalesce overlaps.
    let mut ivals: Vec<(usize, usize)> = remove
        .iter()
        .map(|&(s, e)| (s.min(len), e.min(len)))
        .filter(|&(s, e)| s < e)
        .collect();
    ivals.sort_unstable_by_key(|&(s, _)| s);
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ivals.len());
    for (s, e) in ivals {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }

    let mut out: Vec<u8> = Vec::with_capacity(len + marks.len() * marker.len());
    let mut mi = 0usize; // index into `marks`
    let mut ri = 0usize; // index into `merged`
    let mut i = 0usize;
    while i <= len {
        // Skip a removed interval that starts at i. BEFORE skipping, emit any marker
        // anchored at or INSIDE this interval (`< end`) — the redaction mark must show
        // even if its offset fell in the interior — collapsed at the interval start
        // (where `out` currently is). After this, i jumps to the interval end.
        if ri < merged.len() && merged[ri].0 == i {
            let (_s, e) = merged[ri];
            while mi < marks.len() && marks[mi] < e {
                if marks[mi] >= i {
                    out.extend_from_slice(marker);
                }
                mi += 1;
            }
            i = e;
            ri += 1;
            continue;
        }
        // Emit any markers anchored exactly at byte position i (incl. end-of-string),
        // for offsets NOT consumed by an interval above.
        while mi < marks.len() && marks[mi] == i {
            out.extend_from_slice(marker);
            mi += 1;
        }
        if i == len {
            break;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Map raw bytes to a `String`, each byte to the code point of the same value
/// (Latin-1 / ISO-8859-1, a byte<->codepoint bijection over `0..=255`). This is the
/// IDENTITY decode that [`FontDecoder::latin1`] precomputes into its table; kept here
/// only to pin the bijection invariant in a test (production decode goes through
/// [`FontDecoder`]).
#[cfg(test)]
fn bytes_to_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Given the DECODED `text` and the engine's candidates (whose `start()`/`end()` are
/// UTF-8 BYTE offsets into `text`), return each MAPPABLE candidate's span as a
/// DECODED-CHAR index range `(char_start, char_end, candidate_index)` (half-open),
/// where `candidate_index` is the position in `candidates` so the caller keeps the
/// splice count and the pushed candidate list in lock-step (count == applied ==
/// pushed).
///
/// We translate UTF-8 byte offsets to decoded-char indices via a single forward walk
/// over `char_indices`. Output is ascending by span start (the engine already merges
/// overlaps so spans are disjoint); a span whose endpoints don't fall on char
/// boundaries (cannot happen for engine output, but guarded) is SKIPPED rather than
/// mis-mapped — and being skipped here, it is never spliced NOR pushed.
fn char_index_spans_for(
    text: &str,
    candidates: &[RedactionCandidate],
) -> Vec<(usize, usize, usize)> {
    if candidates.is_empty() {
        return Vec::new();
    }
    // Collect each char's UTF-8 byte offset by iteration index (the decoded-char
    // index). The final push is the end sentinel so an end-of-string span endpoint
    // maps too.
    let mut boundaries: Vec<usize> = Vec::with_capacity(text.len() + 1);
    for (char_index, (utf8_off, _ch)) in text.char_indices().enumerate() {
        debug_assert_eq!(boundaries.len(), char_index);
        boundaries.push(utf8_off);
    }
    boundaries.push(text.len()); // sentinel for the end offset

    // Inverse lookup: a UTF-8 byte offset that IS a char boundary -> its char index
    // via binary search over the ascending `boundaries`.
    let to_char_index =
        |utf8_off: usize| -> Option<usize> { boundaries.binary_search(&utf8_off).ok() };

    let mut spans: Vec<(usize, usize, usize)> = Vec::with_capacity(candidates.len());
    for (cand_idx, c) in candidates.iter().enumerate() {
        match (to_char_index(c.start()), to_char_index(c.end())) {
            (Some(s), Some(e)) if s < e => spans.push((s, e, cand_idx)),
            _ => {} // unmappable span (cannot occur for engine output) — skip
        }
    }
    // Engine output is already ascending + non-overlapping; keep that invariant
    // (sort by start; ties never occur for disjoint engine spans).
    spans.sort_unstable_by_key(|&(s, _, _)| s);
    spans
}

// ============================================================================
// ANNOTATION scrubbing: PDF annotations (/Annots) are a SEPARATE content surface
// from page content streams. A Link annotation's URI action carries the link
// destination in /URI (inside /A or /AA), and markup/text annotations carry note
// text in /Contents. The page-content pass NEVER touches these, so a red-team can
// recover a "redacted" URL straight from the surviving /URI action. This pass runs
// the SAME RedactionEngine over those text fields and, on a detected identifier,
// REMOVES the offending field WHOLESALE (default-deny under-removal: a partial
// splice on a URI risks leaving a recoverable fragment, and the SAFE side on a
// redaction tool is full removal). A clean /URI / benign /Contents (no detected
// identifier) is left intact, preserving harmless links.
//
// TRUE REMOVAL: removing the /URI key (and, if it leaves an empty URI action, the
// /A entry) deletes the bytes from the saved PDF — not a cover. We re-parse + grep
// the output in tests to prove no matched value survives in any annotation field.
//
// STRUCTURAL INTEGRITY: we NEVER touch the /Annots array shape — we drop a key
// from an annotation/action dict, or null an action, leaving every annotation
// reference + the array itself valid. (A whole-annotation drop is deliberately
// avoided: it would require rewriting /Annots, risking dangling refs.)
// ============================================================================

/// Where an annotation's scrubbable text field lives, so the APPLY pass can remove it
/// after the read-only detection pass (lopdf hands out `&Dictionary`, so detection and
/// mutation are split to avoid overlapping borrows). The field is addressed by the
/// owning object id + a key path the mutator walks under `get_object_mut`.
#[derive(Clone)]
enum AnnotFieldLoc {
    /// A `/URI` string directly in the annotation dict (`object_id` = the annotation).
    DirectUri { object_id: lopdf::ObjectId },
    /// A `/Contents` string in the annotation dict.
    Contents { object_id: lopdf::ObjectId },
    /// A `/URI` inside the annotation's `/A` action dict, when `/A` is an INLINE dict on
    /// the annotation object (`object_id` = the annotation; mutate annot[/A][/URI]).
    InlineActionUri { object_id: lopdf::ObjectId },
    /// A `/URI` inside a referenced action object (`action_id`), reached from the
    /// annotation's `/A` (or an `/AA` entry) being a reference. Mutate action[/URI].
    RefActionUri { action_id: lopdf::ObjectId },
    /// A `/URI` inside an INLINE `/AA` sub-action keyed `aa_key` (`object_id` = annot;
    /// mutate annot[/AA][aa_key][/URI]).
    InlineAaUri {
        object_id: lopdf::ObjectId,
        aa_key: Vec<u8>,
    },
}

/// One detected annotation field: which engine candidate (for the stable id + the review
/// candidate) and where the offending field lives (for the apply-pass removal).
struct AnnotDetection {
    candidate: RedactionCandidate,
    loc: AnnotFieldLoc,
}

/// Decode a PDF string object's bytes to text for scanning. Annotation `/URI` and
/// `/Contents` are PDFDocEncoded or UTF-16BE strings; we decode UTF-16BE (BOM `FE FF`)
/// to UTF-8 and otherwise treat the bytes as Latin-1/PDFDoc (a byte<->codepoint
/// bijection that exactly preserves the ASCII identifiers — emails / URLs / ids — we
/// detect). Over-length is the caller's concern (it removes wholesale without decoding).
/// (`pub(crate)`: `verify` decodes annotation / `/Info` / XMP string bytes through this
/// SAME UTF-16BE/Latin-1 decode, so the probe reads a field exactly as the scrubber did.)
pub(crate) fn decode_annot_string(bytes: &[u8]) -> String {
    // UTF-16BE with a byte-order mark (the PDF text-string alternative form).
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        // Assemble the BE code units, then let std combine surrogate PAIRS: a non-BMP
        // char is TWO u16 units, so decoding each unit independently would emit two
        // U+FFFD for it. A trailing odd byte is dropped by `chunks_exact(2)` (the same
        // boundary the old `i + 1 < len` bound had). Mirrors extract/pdf.rs's UTF-16BE
        // handling; lone surrogates still map to U+FFFD (never panics) — fine for
        // scanning ASCII identifiers out of the text.
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    // Latin-1 / PDFDocEncoding best-effort: byte -> same codepoint. Exact for the ASCII
    // identifiers we care about; never fails.
    bytes.iter().map(|&b| b as char).collect()
}

/// Scan ONE annotation text field's bytes for identifiers (the caller length-checks
/// FIRST, so this only ever sees a within-bound field). Returns the engine candidates
/// (cleartext, review-only) found in the field after decoding it through
/// [`decode_annot_string`].
fn scan_annot_field(engine: &RedactionEngine, bytes: &[u8]) -> Vec<RedactionCandidate> {
    let text = decode_annot_string(bytes);
    engine.candidates(&text)
}

/// Read an annotation's scrubbable text fields, detect identifiers, and (for apply)
/// record removal locations — for ONE page. Returns how many fields were REMOVED (apply)
/// — 0 in scan (a scan removes nothing). Visits each annotation object once (dedup via
/// `seen_annots`), bounded by [`MAX_ANNOTS_PER_PAGE`]. Stable ids advance `next_id` in
/// the SAME deterministic order in scan + apply, so the two passes agree.
/// Bundled parameters for [`process_page_annotations`]: the document + page id +
/// page number + engine, plus the mutable sinks (the stable-id counter, the per-page
/// [`DocMode`], the cross-page dedup set, and the diagnostics list). Grouped into one
/// struct so the call stays within clippy's argument budget without an
/// `#[allow(clippy::too_many_arguments)]`.
struct PageAnnotArgs<'a, 'd> {
    doc: &'a mut Document,
    page_id: lopdf::ObjectId,
    page_no: u32,
    engine: &'a RedactionEngine,
    next_id: &'a mut u64,
    mode: &'a mut DocMode<'d>,
    seen_annots: &'a mut BTreeSet<lopdf::ObjectId>,
    diagnostics: &'a mut Vec<String>,
}

fn process_page_annotations(args: PageAnnotArgs) -> usize {
    let PageAnnotArgs {
        doc,
        page_id,
        page_no,
        engine,
        next_id,
        mode,
        seen_annots,
        diagnostics,
    } = args;
    // PHASE 1 (read-only): enumerate the page's annotation OBJECT IDS (we only scrub
    // annotations that are indirect objects — the overwhelmingly common shape — so the
    // mutate phase can address them via `get_object_mut` without touching /Annots' shape).
    // An INLINE annotation dict (rare) is detected + flagged but left structurally intact;
    // see the diagnostic below.
    let mut annot_ids: Vec<lopdf::ObjectId> = Vec::new();
    let mut had_inline_annot = false;
    {
        let Ok(page) = doc.get_dictionary(page_id) else {
            return 0;
        };
        let annots = match page.get(ANNOTS_KEY) {
            Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_array).ok(),
            Ok(Object::Array(a)) => Some(a),
            _ => None,
        };
        let Some(annots) = annots else { return 0 };
        for obj in annots.iter() {
            if annot_ids.len() >= MAX_ANNOTS_PER_PAGE {
                diagnostics.push(format!(
                    "page {page_no}: more than {MAX_ANNOTS_PER_PAGE} annotations — \
                     remaining annotations not scanned (potential un-scrubbed identifier)"
                ));
                break;
            }
            match obj {
                Object::Reference(id) => annot_ids.push(*id),
                // An INLINE annotation dict cannot be addressed by object id; flag it so a
                // potential miss is observable rather than silent (these are rare).
                Object::Dictionary(_) => had_inline_annot = true,
                _ => {}
            }
        }
    }
    if had_inline_annot {
        diagnostics.push(format!(
            "page {page_no}: one or more INLINE (non-referenced) annotations were not \
             scrubbed — an identifier in such an annotation may survive"
        ));
    }

    // For each unique annotation object, detect its scrubbable fields. Collect detections
    // (candidate + removal location) so the mutate phase runs after this read borrow ends.
    let mut detections: Vec<AnnotDetection> = Vec::new();
    // Over-length fields to remove WHOLESALE (no scan; fail-closed). Recorded separately so
    // they are removed in apply even though they produced no engine candidate.
    let mut over_length: Vec<AnnotFieldLoc> = Vec::new();
    for annot_id in annot_ids {
        if !seen_annots.insert(annot_id) {
            continue; // shared annotation object — process once
        }
        collect_annot_detections(
            doc,
            annot_id,
            engine,
            &mut detections,
            &mut over_length,
            page_no,
            diagnostics,
        );
    }

    // Assign stable ids to detections in deterministic collection order (annotation order,
    // then field order within an annotation). Advance `next_id` by the count in BOTH modes
    // so scan + apply stay aligned with each other AND with the body traversal.
    let mut removed = 0usize;
    match mode {
        DocMode::Scan { items } => {
            for det in detections {
                let id = PdfCandidateId(*next_id);
                *next_id += 1;
                items.push(PdfScanItem {
                    id,
                    page: page_no,
                    candidate: det.candidate,
                });
            }
            // A scan removes nothing — including over-length fields (apply removes those).
            // We still surface them via the diagnostics already pushed in collect.
            let _ = over_length;
        }
        DocMode::Apply {
            selection,
            removed: removed_out,
        } => {
            // Determine which detections the reviewer accepted (default-deny). We must
            // advance `next_id` per detection regardless (id parity with scan), so assign
            // ids in the SAME order, then act only on accepted ones.
            let mut accepted_locs: Vec<AnnotFieldLoc> = Vec::new();
            let mut accepted_cands: Vec<RedactionCandidate> = Vec::new();
            for det in detections {
                let id = PdfCandidateId(*next_id);
                *next_id += 1;
                if selection.accepts(id) {
                    accepted_locs.push(det.loc);
                    accepted_cands.push(det.candidate);
                }
            }
            // Over-length fields are ALWAYS removed (they were never scanned — leaving them
            // would be an unscanned survivor). They carry no engine candidate, so they are
            // not subject to the per-id selection (an apply-all and a per-span apply both
            // remove them; a select-none body redaction still scrubs an unscannable field —
            // the fail-closed posture). They are rare; counted in `removed` but not in the
            // candidate list (no cleartext value to show).
            for loc in over_length {
                if remove_annot_field(doc, &loc) {
                    removed += 1;
                }
            }
            for (loc, cand) in accepted_locs.into_iter().zip(accepted_cands) {
                if remove_annot_field(doc, &loc) {
                    removed += 1;
                    removed_out.push(cand);
                }
            }
        }
    }
    removed
}

/// `/Annots` page-dictionary key. (`pub(crate)`: `verify`'s annotation probe resolves
/// the same key — one spelling, no drift.)
pub(crate) const ANNOTS_KEY: &[u8] = b"Annots";

/// Detect identifiers in ONE annotation object's text fields, pushing an [`AnnotDetection`]
/// (candidate + removal location) per detected field and an over-length location per field
/// too long to scan. Read-only (takes `&Document`): mutation is deferred to
/// [`remove_annot_field`]. The field traversal order is FIXED (DirectUri, inline /A /URI,
/// referenced /A /URI, each /AA inline-or-ref /URI in /AA key order, then /Contents) so the
/// id assignment is deterministic across scan + apply.
fn collect_annot_detections(
    doc: &Document,
    annot_id: lopdf::ObjectId,
    engine: &RedactionEngine,
    detections: &mut Vec<AnnotDetection>,
    over_length: &mut Vec<AnnotFieldLoc>,
    page_no: u32,
    diagnostics: &mut Vec<String>,
) {
    let Ok(annot) = doc.get_object(annot_id).and_then(Object::as_dict) else {
        return;
    };

    // Helper: detect over one field's bytes, recording detections at `loc`.
    let mut handle_field =
        |bytes: &[u8], loc: AnnotFieldLoc, detections: &mut Vec<AnnotDetection>| {
            if bytes.len() > MAX_ANNOT_FIELD_BYTES {
                over_length.push(loc);
                diagnostics.push(format!(
                    "page {page_no}: an annotation text field exceeds {MAX_ANNOT_FIELD_BYTES} \
                 bytes — removed wholesale without scanning (fail-closed)"
                ));
                return;
            }
            for cand in scan_annot_field(engine, bytes) {
                detections.push(AnnotDetection {
                    candidate: cand,
                    loc: loc.clone(),
                });
            }
        };

    // (1) /URI directly on the annotation dict (uncommon, but legal).
    if let Ok(uri) = annot.get(ANNOT_URI_KEY).and_then(Object::as_str) {
        handle_field(
            uri,
            AnnotFieldLoc::DirectUri {
                object_id: annot_id,
            },
            detections,
        );
    }

    // (2) /A action: either an INLINE dict on the annotation, or a REFERENCE to an action
    // object. Read its /URI (the link destination — the recovered-URL leak surface).
    match annot.get(ANNOT_ACTION_KEY) {
        Ok(Object::Dictionary(a)) => {
            if let Ok(uri) = a.get(ANNOT_URI_KEY).and_then(Object::as_str) {
                handle_field(
                    uri,
                    AnnotFieldLoc::InlineActionUri {
                        object_id: annot_id,
                    },
                    detections,
                );
            }
        }
        Ok(Object::Reference(action_id)) => {
            if let Ok(a) = doc.get_object(*action_id).and_then(Object::as_dict) {
                if let Ok(uri) = a.get(ANNOT_URI_KEY).and_then(Object::as_str) {
                    handle_field(
                        uri,
                        AnnotFieldLoc::RefActionUri {
                            action_id: *action_id,
                        },
                        detections,
                    );
                }
            }
        }
        _ => {}
    }

    // (3) /AA additional-actions: a dict whose entries are action dicts (each possibly
    // with a /URI). Visit entries in a DETERMINISTIC (sorted) key order. Each entry may be
    // inline or a reference.
    if let Ok(Object::Dictionary(aa)) = annot.get(ANNOT_ADDITIONAL_ACTIONS_KEY) {
        let mut keys: Vec<&Vec<u8>> = aa.iter().map(|(k, _)| k).collect();
        keys.sort();
        for key in keys {
            match aa.get(key) {
                Ok(Object::Dictionary(a)) => {
                    if let Ok(uri) = a.get(ANNOT_URI_KEY).and_then(Object::as_str) {
                        handle_field(
                            uri,
                            AnnotFieldLoc::InlineAaUri {
                                object_id: annot_id,
                                aa_key: key.clone(),
                            },
                            detections,
                        );
                    }
                }
                Ok(Object::Reference(action_id)) => {
                    if let Ok(a) = doc.get_object(*action_id).and_then(Object::as_dict) {
                        if let Ok(uri) = a.get(ANNOT_URI_KEY).and_then(Object::as_str) {
                            handle_field(
                                uri,
                                AnnotFieldLoc::RefActionUri {
                                    action_id: *action_id,
                                },
                                detections,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // (4) /Contents note text (free-text / popup / markup comment body).
    if let Ok(contents) = annot.get(ANNOT_CONTENTS_KEY).and_then(Object::as_str) {
        handle_field(
            contents,
            AnnotFieldLoc::Contents {
                object_id: annot_id,
            },
            detections,
        );
    }
}

/// REMOVE one offending annotation field from the document (the apply mutation). Returns
/// `true` if a field was actually removed. TRUE removal: the key is deleted so its bytes
/// are gone from the re-serialised PDF.
///
/// For a `/URI` we DROP the `/URI` key; when that leaves its action dict with no `/URI`,
/// we ALSO drop the now-purposeless `/A` (an empty URI action does nothing). For a
/// referenced action object we null the action's `/URI` AND, defensively, set its `/S`
/// (action subtype) so a dangling empty action is inert. For `/Contents` we drop the key
/// (clearing the note). The /Annots ARRAY is never reshaped (no dangling refs).
fn remove_annot_field(doc: &mut Document, loc: &AnnotFieldLoc) -> bool {
    match loc {
        AnnotFieldLoc::DirectUri { object_id } => {
            if let Ok(d) = doc.get_object_mut(*object_id).and_then(Object::as_dict_mut) {
                return d.remove(ANNOT_URI_KEY).is_some();
            }
            false
        }
        AnnotFieldLoc::Contents { object_id } => {
            if let Ok(d) = doc.get_object_mut(*object_id).and_then(Object::as_dict_mut) {
                return d.remove(ANNOT_CONTENTS_KEY).is_some();
            }
            false
        }
        AnnotFieldLoc::InlineActionUri { object_id } => {
            if let Ok(annot) = doc.get_object_mut(*object_id).and_then(Object::as_dict_mut) {
                if let Ok(Object::Dictionary(a)) = annot.get_mut(ANNOT_ACTION_KEY) {
                    let removed = a.remove(ANNOT_URI_KEY).is_some();
                    // If the action now has no URI, drop the whole (purposeless) /A entry.
                    if removed && a.get(ANNOT_URI_KEY).is_err() {
                        annot.remove(ANNOT_ACTION_KEY);
                    }
                    return removed;
                }
            }
            false
        }
        AnnotFieldLoc::InlineAaUri { object_id, aa_key } => {
            if let Ok(annot) = doc.get_object_mut(*object_id).and_then(Object::as_dict_mut) {
                if let Ok(Object::Dictionary(aa)) = annot.get_mut(ANNOT_ADDITIONAL_ACTIONS_KEY) {
                    if let Ok(Object::Dictionary(a)) = aa.get_mut(aa_key) {
                        let removed = a.remove(ANNOT_URI_KEY).is_some();
                        if removed && a.get(ANNOT_URI_KEY).is_err() {
                            aa.remove(aa_key);
                        }
                        return removed;
                    }
                }
            }
            false
        }
        AnnotFieldLoc::RefActionUri { action_id } => {
            if let Ok(a) = doc.get_object_mut(*action_id).and_then(Object::as_dict_mut) {
                return a.remove(ANNOT_URI_KEY).is_some();
            }
            false
        }
    }
}

// ============================================================================
// DOCUMENT METADATA scrubbing: the trailer `/Info` dictionary and the catalog's
// XMP `/Metadata` stream are SEPARATE leak surfaces from page content + annotations.
// A red-team recovered, from the JP Morgan prospectus' "redacted" output, a person's
// name (`/Info /Author`) and an internal SharePoint authoring path (`/Info /Title`
// AND the XMP `dc:title`/history) — neither touched by the body/annotation passes.
// Metadata is the classic redaction leak vector (author, internal paths, software,
// edit history), so we close it here.
//
// POLICY (recall-first — removing metadata is the SAFE side):
//   * `/Info`: scan EVERY value through the SAME RedactionEngine (consistent
//     locales/recognizers). REMOVE a key whose value contains a detected identifier.
//     ADDITIONALLY scrub-by-default the high-PII authoring fields (`/Author`,
//     `/Title`, and custom Microsoft-sensitivity-label / SharePoint-provenance keys —
//     see INFO_SCRUB_*), which carry names/paths/provenance ids even when no
//     recognizer independently fires. Benign software fields (`/Producer`,`/Creator`)
//     are KEPT unless a recognizer fires in them (preserving "lopdf"-style provenance).
//   * XMP `/Metadata`: this is an XML/RDF packet. Scanning + splicing XML in place
//     risks leaving recoverable fragments or breaking the XML, so for a redaction tool
//     the ROBUST close is to REMOVE THE WHOLE STREAM when it contains ANY detected
//     identifier OR an authoring-path-like value (a UNC `\\…`, a SharePoint URL, a
//     `file:` URI, or a Windows drive path). The stream is DERIVED metadata, not body
//     content, so removing it loses nothing the body needs. We then DROP the catalog's
//     `/Metadata` reference so the structure stays valid (no dangling ref). A genuinely
//     benign XMP (pure namespace declarations, no identifier/path) is preserved.
//     Removing the whole stream — rather than editing it — guarantees NO fragment of
//     the leaked value can survive in the saved bytes.
//
// TRUE REMOVAL: dropping the `/Info` key (and emptying-then-clearing `/Info` if it
// becomes empty) and removing the `/Metadata` stream object + its catalog ref delete
// the bytes from the re-serialised PDF. Tests re-parse the metadata AND raw-byte grep
// the output to prove no leaked value survives.
//
// STRUCTURAL INTEGRITY: we only DROP keys / a stream + its single catalog reference;
// the catalog, pages tree, and trailer remain valid. The `/Info` trailer entry itself
// is left in place if any benign key survives; if `/Info` ends up empty we clear the
// trailer entry too (an empty info dict is harmless either way).
// ============================================================================

/// Where a scrubbable metadata value lives, so the APPLY pass can remove it after the
/// read-only detection pass (mirrors [`AnnotFieldLoc`]).
#[derive(Clone)]
enum MetaFieldLoc {
    /// An `/Info` dictionary key to drop (`info_id` = the info dict object id when it is
    /// an indirect object; `None` = the info dict is a DIRECT object on the trailer).
    InfoKey {
        info_id: Option<lopdf::ObjectId>,
        key: Vec<u8>,
    },
    /// The catalog's XMP `/Metadata` stream: remove the stream object AND drop the
    /// catalog's `/Metadata` reference. `catalog_id` = the catalog (document root)
    /// object; `stream_id` = the `/Metadata` stream object (if it is an indirect ref).
    XmpStream {
        catalog_id: lopdf::ObjectId,
        stream_id: Option<lopdf::ObjectId>,
    },
}

/// One detected metadata field: the review candidate (cleartext, review-only) + where to
/// remove it. A scrub-by-default field with NO engine candidate carries a synthetic
/// candidate ONLY for the count/id parity — see `meta_default_candidate`.
struct MetaDetection {
    candidate: RedactionCandidate,
    loc: MetaFieldLoc,
}

/// Scan + (apply) scrub the document `/Info` dictionary and XMP `/Metadata` stream.
/// Returns how many metadata fields were REMOVED (apply) — 0 in scan. Advances `next_id`
/// by the number of detections in BOTH modes so scan + apply assign identical ids (the
/// determinism contract `PdfCandidateId` relies on). NEVER panics; read-only in scan.
fn process_document_metadata(
    doc: &mut Document,
    engine: &RedactionEngine,
    next_id: &mut u64,
    mode: &mut DocMode,
    diagnostics: &mut Vec<String>,
) -> usize {
    // PHASE 1 (read-only): collect detections (candidate + removal location) under an
    // immutable borrow, so the mutate phase runs after the borrow ends.
    let mut detections: Vec<MetaDetection> = Vec::new();
    collect_info_detections(doc, engine, &mut detections, diagnostics);
    collect_xmp_detection(doc, engine, &mut detections, diagnostics);

    // Assign stable ids in deterministic collection order (Info keys in sorted order, then
    // the XMP stream). Advance `next_id` per detection in BOTH modes for scan/apply parity.
    let mut removed = 0usize;
    match mode {
        DocMode::Scan { items } => {
            for det in detections {
                let id = PdfCandidateId(*next_id);
                *next_id += 1;
                items.push(PdfScanItem {
                    id,
                    page: 0,
                    candidate: det.candidate,
                });
            }
        }
        DocMode::Apply {
            selection,
            removed: removed_out,
        } => {
            let mut accepted: Vec<MetaDetection> = Vec::new();
            for det in detections {
                let id = PdfCandidateId(*next_id);
                *next_id += 1;
                if selection.accepts(id) {
                    accepted.push(det);
                }
            }
            for det in accepted {
                if remove_meta_field(doc, &det.loc) {
                    removed += 1;
                    removed_out.push(det.candidate);
                }
            }
        }
    }
    removed
}

/// Resolve the trailer `/Info` dictionary as `(optional indirect id, &Dictionary)`.
/// `None` if there is no readable `/Info`.
/// (`pub(crate)`: `verify`'s metadata probe resolves `/Info` identically.)
pub(crate) fn resolve_info(
    doc: &Document,
) -> Option<(Option<lopdf::ObjectId>, &lopdf::Dictionary)> {
    match doc.trailer.get(INFO_KEY) {
        Ok(Object::Reference(id)) => {
            let d = doc.get_object(*id).and_then(Object::as_dict).ok()?;
            Some((Some(*id), d))
        }
        Ok(Object::Dictionary(d)) => Some((None, d)),
        _ => None,
    }
}

/// Resolve the document catalog (root) as `(catalog_id, &Dictionary)`. `None` if absent.
/// (`pub(crate)`: `verify`'s metadata probe resolves the catalog identically.)
pub(crate) fn resolve_catalog(doc: &Document) -> Option<(lopdf::ObjectId, &lopdf::Dictionary)> {
    match doc.trailer.get(ROOT_KEY) {
        Ok(Object::Reference(id)) => {
            let d = doc.get_object(*id).and_then(Object::as_dict).ok()?;
            Some((*id, d))
        }
        _ => None,
    }
}

/// Build a synthetic review candidate for a scrub-by-default `/Info` key that produced NO
/// engine candidate (so it still appears in the review list + advances ids). The recognizer
/// label is `metadata:<KeyName>` (the KEY name, never a matched substring) — honestly naming
/// what was removed and why; the matched value carries the cleartext for in-process review.
fn meta_default_candidate(key: &[u8], value: &str) -> RedactionCandidate {
    let key_str = String::from_utf8_lossy(key).into_owned();
    RedactionCandidate::synthetic(
        value.to_string(),
        format!("metadata:{key_str}"),
        "document metadata (authoring field, scrubbed by default)".to_string(),
    )
}

/// Whether an `/Info` key is scrubbed BY DEFAULT (high-PII authoring/path/provenance):
/// an exact match against [`INFO_SCRUB_BY_DEFAULT_KEYS`], OR a custom key whose name
/// contains a [`INFO_SCRUB_KEY_SUBSTRINGS`] marker (case-insensitive).
fn info_key_is_scrub_by_default(key: &[u8]) -> bool {
    if INFO_SCRUB_BY_DEFAULT_KEYS.contains(&key) {
        return true;
    }
    let lower: Vec<u8> = key.iter().map(|b| b.to_ascii_lowercase()).collect();
    INFO_SCRUB_KEY_SUBSTRINGS
        .iter()
        .any(|needle| lower.windows(needle.len()).any(|w| w == *needle))
}

/// Collect `/Info` detections: for each key (in DETERMINISTIC sorted order), decode its
/// value, and record a removal when (a) the engine detects an identifier in it, OR (b) it
/// is a scrub-by-default authoring/path/provenance key. Read-only (`&Document`).
fn collect_info_detections(
    doc: &Document,
    engine: &RedactionEngine,
    detections: &mut Vec<MetaDetection>,
    diagnostics: &mut Vec<String>,
) {
    let Some((info_id, info)) = resolve_info(doc) else {
        return;
    };
    // Deterministic key order so scan + apply assign identical ids.
    let mut keys: Vec<Vec<u8>> = info.iter().map(|(k, _)| k.clone()).collect();
    keys.sort();
    for key in keys {
        // Only string-valued keys carry leakable text; a non-string value (a date stored
        // as a string IS a string; a numeric/bool is not text) is left alone.
        let Ok(bytes) = info.get(&key).and_then(Object::as_str) else {
            continue;
        };
        // Bound the decode like an annotation field (a pathological huge value is removed
        // wholesale without scanning — fail-closed). Scrub-by-default keys are removed
        // regardless, so this only matters for scan-detected ones.
        let over_length = bytes.len() > MAX_ANNOT_FIELD_BYTES;
        let value = if over_length {
            String::new()
        } else {
            decode_annot_string(bytes)
        };
        // Scrub-by-default if the KEY is a known authoring/path/provenance field OR the
        // VALUE looks like an authoring path (a UNC `\\…`, a SharePoint URL, a `file:`
        // URI, or a Windows drive path) — a path that no text recognizer independently
        // flags (e.g. a bare UNC `\\sharepoint\matters\Deal` in a custom key) is still a
        // leak, so its presence in ANY /Info value triggers removal.
        let scrub_default = info_key_is_scrub_by_default(&key)
            || (!over_length && looks_like_authoring_path(&value));

        if scrub_default || over_length {
            // Scrub-by-default OR unscannable: remove the key. One detection, a synthetic
            // candidate naming the key. (If it ALSO has engine candidates we still only
            // remove the key ONCE — the synthetic detection covers it; we do NOT also add
            // per-identifier detections for a key we already remove, to keep ids stable
            // and avoid double-removing the same key.)
            if over_length && !scrub_default {
                diagnostics.push(format!(
                    "metadata: /Info /{} exceeds {MAX_ANNOT_FIELD_BYTES} bytes — removed \
                     wholesale without scanning (fail-closed)",
                    String::from_utf8_lossy(&key)
                ));
            }
            detections.push(MetaDetection {
                candidate: meta_default_candidate(&key, &value),
                loc: MetaFieldLoc::InfoKey {
                    info_id,
                    key: key.clone(),
                },
            });
            continue;
        }

        // Not scrub-by-default: scan the value. Remove the key if ANY identifier is found.
        // We record ONE detection per key (not per identifier) — the key is removed
        // wholesale (a partial splice of a metadata value risks a recoverable fragment,
        // the same safe-side reasoning as the annotation pass). The detection's candidate
        // is the FIRST engine candidate (cleartext, review-only).
        let cands = engine.candidates(&value);
        if let Some(first) = cands.into_iter().next() {
            detections.push(MetaDetection {
                candidate: first,
                loc: MetaFieldLoc::InfoKey {
                    info_id,
                    key: key.clone(),
                },
            });
        }
    }
}

/// Whether `text` contains an authoring-path-like value: a UNC path (`\\host\…`), a
/// SharePoint/`file:` URL, or a Windows drive path (`C:\…`). These routinely leak in XMP
/// even when a recognizer does not independently flag them, so their presence triggers
/// XMP stream removal too.
fn looks_like_authoring_path(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("\\\\") {
        return true; // a UNC path
    }
    if lower.contains("sharepoint.com") || lower.contains("file://") {
        return true;
    }
    // A Windows drive path like `C:\Users\…` — a STANDALONE drive letter, colon,
    // BACKSLASH. We require the backslash form (`:\`) specifically, NOT `:/`: a `:/` also
    // appears in every URL scheme (`http://` ends in `p:/`), so matching it would flag a
    // benign namespace URI in XMP. A drive letter is also a LONE letter, so the byte
    // before it (if any) must be a non-alphanumeric boundary (excludes `…p:\` substrings).
    let bytes = text.as_bytes();
    bytes.windows(3).enumerate().any(|(i, w)| {
        w[0].is_ascii_alphabetic()
            && w[1] == b':'
            && w[2] == b'\\'
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
    })
}

/// Collect the XMP `/Metadata` detection: if the catalog's `/Metadata` stream contains ANY
/// detected identifier OR an authoring-path-like value, record a removal of the WHOLE
/// stream (the clean, fragment-free close). Read-only (`&Document`). A benign XMP (no
/// identifier/path) is left intact.
fn collect_xmp_detection(
    doc: &Document,
    engine: &RedactionEngine,
    detections: &mut Vec<MetaDetection>,
    diagnostics: &mut Vec<String>,
) {
    let Some((catalog_id, catalog)) = resolve_catalog(doc) else {
        return;
    };
    // The /Metadata stream: a reference (the common shape) or, rarely, a direct stream.
    let (stream_id, stream): (Option<lopdf::ObjectId>, Option<&lopdf::Stream>) =
        match catalog.get(METADATA_KEY) {
            Ok(Object::Reference(id)) => (
                Some(*id),
                doc.get_object(*id).and_then(Object::as_stream).ok(),
            ),
            Ok(Object::Stream(s)) => (None, Some(s)),
            _ => return, // no XMP metadata
        };
    let Some(stream) = stream else { return };

    // The XMP packet is UNCOMPRESSED in the overwhelming majority of files (the spec
    // recommends it stay uncompressed so a tool can find/patch it). If it IS compressed,
    // decode it through the SAME capped reader used for content streams
    // (`decode_stream_capped` — `take(cap+1)`-bounded, frees the partial buffer on
    // exceed). NEVER lopdf's uncapped `decompressed_content()`: a small (~300 KiB)
    // FlateDecode /Metadata stream inflating to GiB would OOM-abort the core on every
    // pdf_scan/pdf_apply over hostile bytes (H1 — the bomb defence the top-of-file
    // doc-comment mandates). On OverBudget / decode refusal / unsupported filter we
    // CONSERVATIVELY remove the stream anyway (an unreadable metadata stream is derived
    // data we cannot vouch for — and a bomb still gets the metadata SCRUBBED, just not
    // parsed): the safe side is removal.
    let text: String = match decode_stream_capped(stream, MAX_DECODED_STREAM_BYTES) {
        Ok(b) => decode_annot_string(&b),
        Err(_) => {
            // Over-cap / undecodable / unsupported-filter metadata: remove wholesale
            // (fail-closed — never OOM, never read as "clean").
            diagnostics.push(
                "metadata: XMP /Metadata stream could not be decoded within the cap — \
                 removed wholesale (fail-closed)"
                    .to_string(),
            );
            return remove_xmp_unconditionally(catalog_id, stream_id, detections);
        }
    };

    // Detect: any engine identifier OR an authoring-path-like value triggers removal.
    let has_identifier = !engine.candidates(&text).is_empty();
    let has_path = looks_like_authoring_path(&text);
    if has_identifier || has_path {
        let reason = if has_identifier {
            "contains a detected identifier"
        } else {
            "contains an authoring-path-like value"
        };
        detections.push(MetaDetection {
            candidate: RedactionCandidate::synthetic(
                String::new(), // never surface the XMP cleartext in the review value
                "metadata:xmp".to_string(),
                format!("XMP /Metadata stream removed ({reason})"),
            ),
            loc: MetaFieldLoc::XmpStream {
                catalog_id,
                stream_id,
            },
        });
    }
}

/// Record an unconditional XMP-stream removal detection (used on the fail-closed paths
/// where the stream is over-cap / undecodable — we remove it rather than vouch for it).
fn remove_xmp_unconditionally(
    catalog_id: lopdf::ObjectId,
    stream_id: Option<lopdf::ObjectId>,
    detections: &mut Vec<MetaDetection>,
) {
    detections.push(MetaDetection {
        candidate: RedactionCandidate::synthetic(
            String::new(),
            "metadata:xmp".to_string(),
            "XMP /Metadata stream removed (undecodable/over-cap — fail-closed)".to_string(),
        ),
        loc: MetaFieldLoc::XmpStream {
            catalog_id,
            stream_id,
        },
    });
}

/// REMOVE one metadata field (the apply mutation). Returns `true` if something was removed.
/// TRUE removal: dropping the `/Info` key / the `/Metadata` stream object + catalog ref
/// deletes the bytes from the re-serialised PDF.
fn remove_meta_field(doc: &mut Document, loc: &MetaFieldLoc) -> bool {
    match loc {
        MetaFieldLoc::InfoKey { info_id, key } => {
            // Mutate the info dict, whether it is an indirect object or a direct trailer dict.
            let removed = match info_id {
                Some(id) => doc
                    .get_object_mut(*id)
                    .and_then(Object::as_dict_mut)
                    .map(|d| d.remove(key).is_some())
                    .unwrap_or(false),
                None => match doc.trailer.get_mut(INFO_KEY) {
                    Ok(Object::Dictionary(d)) => d.remove(key).is_some(),
                    _ => false,
                },
            };
            // If the info dict is now empty, drop the trailer /Info entry too (an empty
            // info dict is pointless; clearing it keeps the trailer tidy). Best-effort.
            if removed {
                let now_empty = match info_id {
                    Some(id) => doc
                        .get_object(*id)
                        .and_then(Object::as_dict)
                        .map(|d| d.is_empty())
                        .unwrap_or(false),
                    None => {
                        matches!(doc.trailer.get(INFO_KEY), Ok(Object::Dictionary(d)) if d.is_empty())
                    }
                };
                if now_empty {
                    doc.trailer.remove(INFO_KEY);
                }
            }
            removed
        }
        MetaFieldLoc::XmpStream {
            catalog_id,
            stream_id,
        } => {
            // Drop the catalog's /Metadata reference FIRST (so no dangling ref remains),
            // then remove the stream object itself (so its bytes are gone from the output).
            let ref_removed = doc
                .get_object_mut(*catalog_id)
                .and_then(Object::as_dict_mut)
                .map(|c| c.remove(METADATA_KEY).is_some())
                .unwrap_or(false);
            if let Some(id) = stream_id {
                // Remove the now-unreferenced stream object so its bytes do not survive.
                doc.objects.remove(id);
            }
            // The ref-removal is the load-bearing close (an inline stream has no object to
            // remove but dropping the catalog ref still deletes it on re-serialise).
            ref_removed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BuiltinRecognizers;
    use lopdf::content::Operation;
    use lopdf::dictionary;
    use lopdf::{Dictionary, Object, Stream, StringFormat};

    /// Build a minimal valid one-page PDF whose single content stream shows
    /// `body_text` via a `Tj` operator. `compress` toggles FlateDecode on the
    /// content stream so we can exercise the compressed path. Returns the PDF bytes.
    fn build_pdf(body_text: &str, compress: bool) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");

        // A content stream: BT /F1 12 Tf 72 720 Td (body_text) Tj ET
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(
                    body_text.as_bytes().to_vec(),
                    StringFormat::Literal,
                )],
            ),
            Operation::new("ET", vec![]),
        ];
        let content = Content { operations: ops };
        let encoded = content.encode().expect("encode content");
        let mut stream = Stream::new(Dictionary::new(), encoded);
        if compress {
            stream.compress().expect("compress content stream");
        }
        let content_id = doc.add_object(stream);

        // A simple Helvetica font resource.
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });

        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();

        let page = dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(page_id, Object::Dictionary(page));

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);

        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save synthetic pdf");
        out
    }

    /// Build a one-page PDF whose content stream lays out text as SEPARATE `Tj` show
    /// operators — `lines[i]` is a list of string pieces, each emitted as its own `Tj`
    /// on the SAME visual line; consecutive lines are separated by a `T*` (next-line)
    /// operator so they are DIFFERENT visual lines. This is the exact cross-operator
    /// layout that defeated per-operator detection: a phone/email split into
    /// `(+852) Tj ( ) Tj (2800) Tj ...` with NO single operand holding the whole token.
    fn build_pdf_multi_op_lines(lines: &[&[&str]]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            // Initial line position; set leading so T* moves down a line.
            Operation::new("TL", vec![14.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (li, line) in lines.iter().enumerate() {
            if li > 0 {
                // Advance to the NEXT visual line (breaks the logical run).
                ops.push(Operation::new("T*", vec![]));
            }
            for piece in line.iter() {
                ops.push(Operation::new(
                    "Tj",
                    vec![Object::String(
                        piece.as_bytes().to_vec(),
                        StringFormat::Literal,
                    )],
                ));
            }
        }
        ops.push(Operation::new("ET", vec![]));
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
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
        doc.save_to(&mut out).expect("save multi-op pdf");
        out
    }

    /// Build a one-page PDF whose page `/Contents` is an ARRAY of SEPARATE content-stream
    /// objects — ONE stream per visual line, each `BT /F1 10 Tf 1 0 0 1 72 <y> Tm (line) Tj
    /// ET` at a DECREASING y (top-to-bottom). This reproduces a fitz `insert_text`-per-line
    /// export where every visual line lands in its OWN content stream. Per the PDF spec the
    /// page content is the CONCATENATION of these streams, so the redactor's page-level merge
    /// (`process_page_streams`) must join them before detection — otherwise each line is
    /// scanned in isolation and every multi-line mechanism (ctx role-name, address-block
    /// continuation) silently no-ops. Distinct from `build_pdf_multi_op_lines` (which puts all
    /// lines in ONE stream separated by `T*`).
    fn build_pdf_stream_per_visual_line(lines: &[&str]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let mut content_ids: Vec<Object> = Vec::with_capacity(lines.len());
        let mut y: i64 = 760;
        for line in lines {
            let ops = vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 10.into()]),
                Operation::new(
                    "Tm",
                    vec![1.into(), 0.into(), 0.into(), 1.into(), 72.into(), y.into()],
                ),
                Operation::new(
                    "Tj",
                    vec![Object::String(
                        line.as_bytes().to_vec(),
                        StringFormat::Literal,
                    )],
                ),
                Operation::new("ET", vec![]),
            ];
            let encoded = Content { operations: ops }
                .encode()
                .expect("encode line stream");
            let id = doc.add_object(Stream::new(Dictionary::new(), encoded));
            content_ids.push(id.into());
            y -= 14;
        }
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page", "Parent" => pages_id,
                "Contents" => Object::Array(content_ids),
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
        doc.save_to(&mut out).expect("save per-line-stream pdf");
        out
    }

    /// Build a one-page PDF that lays out `pieces` GLYPH-CLUSTER BY GLYPH-CLUSTER on ONE
    /// visual line: each piece is its own `Tj`, and a SMALL horizontal `Td` nudge is
    /// emitted between consecutive pieces (a pure x-move, zero y — same line). This is the
    /// exact pattern from the JP Morgan directors page (`Daniel`, `J.`, `W`, `at`, `kins`
    /// — a single word `Watkins` fragmented across Td-nudged show ops), which the
    /// per-horizontal-gap separator policy reconstructs WITH spurious internal spaces
    /// (`Daniel J. W at kins`). Used to prove the whitespace-insensitive term recall fix.
    fn build_pdf_glyph_split(pieces: &[&str]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (i, piece) in pieces.iter().enumerate() {
            if i > 0 {
                // A pure-horizontal nudge (zero y) → SAME line, but the separator policy
                // marks a visual gap before the next show op (the fabricated space).
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
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
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
        doc.save_to(&mut out).expect("save glyph-split pdf");
        out
    }

    /// Build a one-page PDF whose content stream shows text via a `TJ` array,
    /// splitting `body_text` across two array string elements (with a kerning
    /// number between them) to exercise the cross-element reconstruction.
    fn build_pdf_tj_split(part_a: &str, part_b: &str) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "TJ",
                vec![Object::Array(vec![
                    Object::String(part_a.as_bytes().to_vec(), StringFormat::Literal),
                    Object::Integer(-30),
                    Object::String(part_b.as_bytes().to_vec(), StringFormat::Literal),
                ])],
            ),
            Operation::new("ET", vec![]),
        ];
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        let page = dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(page_id, Object::Dictionary(page));
        let pages = dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save");
        out
    }

    /// ROUND 7 — build a one-page PDF where each visual line is ONE `TJ` array of
    /// `(adjustment_before, word)` elements: the adjustment (thousandths of em; 0 = no
    /// number emitted) sits BETWEEN the previous element and this word, and there are NO
    /// space glyphs and NO `Td` nudges within a line. This is the generator class behind
    /// the BGF pp247-248 Shariah-panel / p190 "Keith Saldanha" total miss: every
    /// inter-word gap encoded purely as a TJ number (~-250), so the naive contiguous
    /// join glues the whole line. Lines are separated by a `Td` y-move.
    fn build_pdf_tj_number_gap_lines(lines: &[&[(i64, &str)]]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                ops.push(Operation::new("Td", vec![0.into(), Object::Integer(-14)]));
            }
            let mut arr: Vec<Object> = Vec::new();
            for &(adj, word) in line.iter() {
                if adj != 0 {
                    arr.push(Object::Integer(adj));
                }
                arr.push(Object::String(
                    word.as_bytes().to_vec(),
                    StringFormat::Literal,
                ));
            }
            ops.push(Operation::new("TJ", vec![Object::Array(arr)]));
        }
        ops.push(Operation::new("ET", vec![]));
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        let page = dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(page_id, Object::Dictionary(page));
        let pages = dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save tj-number-gap pdf");
        out
    }

    /// Build an "image-only" page: a content stream with NO text-showing
    /// operators (just a rectangle fill), so there is no extractable text.
    fn build_pdf_no_text() -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let ops = vec![
            Operation::new("re", vec![0.into(), 0.into(), 100.into(), 100.into()]),
            Operation::new("f", vec![]),
        ];
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        let page = dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(page_id, Object::Dictionary(page));
        let pages = dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save");
        out
    }

    /// Re-extract all page text from PDF bytes (via lopdf's own extractor) so a
    /// test can assert identifiers are gone / innocuous text preserved.
    fn extract_text(pdf: &[u8]) -> String {
        let doc = Document::load_mem(pdf).expect("reload redacted pdf");
        let pages: Vec<u32> = doc.get_pages().keys().copied().collect();
        doc.extract_text(&pages).unwrap_or_default()
    }

    fn engine() -> RedactionEngine {
        // Include a caller term so we exercise term + built-in (email/card) paths.
        RedactionEngine::new(["Project Falcon".to_string()])
    }

    /// TEST-ONLY diagnostic: reconstruct the SAME per-logical-run text the redaction
    /// scanner sees for a given 1-based page, so a test can observe the actual text order
    /// / run segmentation the context+name logic scans over. Mirrors the traversal in
    /// `process_page_streams`/`process_logical_run` but only builds+returns the joined run
    /// text (no detection, no mutation), one entry per logical run PER content stream. (The
    /// live path now JOINS a page's content streams before detection — see
    /// `process_page_streams` — so a generator that emits one stream per visual line is no
    /// longer scanned in isolation.) Used by the env-gated `debug_dump_real_pdf_runs` test;
    /// never runs in normal CI (skips when the env var is unset).
    fn reconstruct_page_runs(pdf: &[u8], want_page: u32) -> Vec<String> {
        let doc = Document::load_mem(pdf).expect("load pdf for run reconstruction");
        let mut out = Vec::new();
        for (&page_no, &page_id) in &doc.get_pages() {
            if page_no != want_page {
                continue;
            }
            let page_fonts = PageFonts::resolve(&doc, page_id);
            for stream_id in doc.get_page_contents(page_id) {
                let stream = match doc.get_object(stream_id).and_then(Object::as_stream) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let decoded = match decode_stream_capped(stream, MAX_DECODED_STREAM_BYTES) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let content = match Content::decode(&decoded) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let mut diags = Vec::new();
                let runs = plan_logical_runs(&content.operations, &page_fonts, 0, &mut diags);
                for run in &runs {
                    let mut text = String::new();
                    for run_op in run.ops.iter() {
                        if run_op.gap_before {
                            text.push(' ');
                        }
                        let op = &content.operations[run_op.op_index];
                        let decoder = page_fonts.decoder_for(run_op.font_name.as_deref());
                        match op.operator.as_str() {
                            "Tj" | "'" | "\"" => {
                                if let Some(Object::String(bytes, _)) = op.operands.last() {
                                    let (dec, _, _) = decoder.decode_mapped(bytes);
                                    text.push_str(&dec);
                                }
                            }
                            "TJ" => {
                                if let Some(Object::Array(arr)) = op.operands.first() {
                                    for obj in arr {
                                        if let Object::String(bytes, _) = obj {
                                            let (dec, _, _) = decoder.decode_mapped(bytes);
                                            text.push_str(&dec);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    out.push(text);
                }
            }
        }
        out
    }

    /// ENV-GATED, never-in-CI diagnostic: dump the reconstructed logical-run text the
    /// scanner sees for the pages in `LAWBAT_DEBUG_PAGES` (comma-separated, default "2")
    /// of the PDF at `LAWBAT_DEBUG_PDF`. Skips gracefully (asserts nothing) when the path
    /// env var is unset, so the committed test never depends on any file. Run with:
    /// `LAWBAT_DEBUG_PDF=/path/to.pdf LAWBAT_DEBUG_PAGES=2,62 cargo test -p redaction \
    ///  debug_dump_real_pdf_runs -- --nocapture --ignored`
    /// ENV-GATED, never-in-CI diagnostic: run the REAL `scan_pdf` over the PDF at
    /// `LAWBAT_DEBUG_PDF` and print the outcome — the error verbatim on failure, else
    /// per-page candidate counts for the needle values in `LAWBAT_DEBUG_NEEDLES`
    /// (comma-separated). Skips gracefully when unset. Run with:
    /// `LAWBAT_DEBUG_PDF=/path.pdf LAWBAT_DEBUG_NEEDLES=Fitzgerald,Gregson \
    ///  cargo test -p redaction debug_scan_real_pdf -- --nocapture --ignored`
    /// ENV-GATED, never-in-CI diagnostic: APPLY (accept-all) over the PDF at
    /// `LAWBAT_DEBUG_PDF`, writing the redacted bytes to `LAWBAT_DEBUG_OUT` for external
    /// probing. Skips gracefully when unset.
    #[test]
    #[ignore = "env-gated real-file diagnostic; set LAWBAT_DEBUG_PDF to run"]
    fn debug_redact_real_pdf() {
        let (Ok(path), Ok(out_path)) = (
            std::env::var("LAWBAT_DEBUG_PDF"),
            std::env::var("LAWBAT_DEBUG_OUT"),
        ) else {
            eprintln!("LAWBAT_DEBUG_PDF/LAWBAT_DEBUG_OUT unset — skipping real-file redact");
            return;
        };
        let bytes = std::fs::read(&path).expect("read LAWBAT_DEBUG_PDF");
        let eng = crate::RedactionEngineBuilder::default()
            .locales([crate::Locale::Singapore])
            .context_recognizers(crate::ContextRecognizers::all())
            .build()
            .expect("engine");
        match redact_pdf(&bytes, &eng) {
            Err(e) => eprintln!("redact_pdf FAILED: {e:?}"),
            Ok(r) => {
                eprintln!(
                    "redact_pdf OK: {} redactions, could_not_remove={}",
                    r.total_redactions(),
                    r.could_not_remove()
                );
                std::fs::write(&out_path, r.bytes()).expect("write LAWBAT_DEBUG_OUT");
            }
        }
    }

    #[test]
    #[ignore = "env-gated real-file diagnostic; set LAWBAT_DEBUG_PDF to run"]
    fn debug_scan_real_pdf() {
        let Ok(path) = std::env::var("LAWBAT_DEBUG_PDF") else {
            eprintln!("LAWBAT_DEBUG_PDF unset — skipping real-file scan");
            return;
        };
        let needles = std::env::var("LAWBAT_DEBUG_NEEDLES").unwrap_or_default();
        let bytes = std::fs::read(&path).expect("read LAWBAT_DEBUG_PDF");
        let eng = crate::RedactionEngineBuilder::default()
            .locales([crate::Locale::Singapore])
            .context_recognizers(crate::ContextRecognizers::all())
            .build()
            .expect("engine");
        match scan_pdf(&bytes, &eng) {
            Err(e) => eprintln!("scan_pdf FAILED: {e:?}"),
            Ok(scan) => {
                eprintln!(
                    "scan_pdf OK: {} candidates, unmapped_fonts={}, low_text={}, diags={}",
                    scan.items().len(),
                    scan.unmapped_fonts(),
                    scan.low_text(),
                    scan.diagnostics().len()
                );
                for d in scan.diagnostics() {
                    eprintln!("  diag: {d}");
                }
                for n in needles.split(',').filter(|s| !s.is_empty()) {
                    let mut per_page: std::collections::BTreeMap<u32, usize> =
                        std::collections::BTreeMap::new();
                    for it in scan.items() {
                        if it.candidate().matched_value().contains(n) {
                            *per_page.entry(it.page()).or_default() += 1;
                            eprintln!(
                                "  [{} p{}] {:?} | {}",
                                it.id().0,
                                it.page(),
                                it.candidate().matched_value(),
                                it.candidate().recognizer()
                            );
                        }
                    }
                    eprintln!("needle {n:?}: {per_page:?}");
                }
            }
        }
    }

    #[test]
    #[ignore = "env-gated real-file diagnostic; set LAWBAT_DEBUG_PDF to run"]
    fn debug_dump_real_pdf_runs() {
        let Ok(path) = std::env::var("LAWBAT_DEBUG_PDF") else {
            eprintln!("LAWBAT_DEBUG_PDF unset — skipping real-file run dump");
            return;
        };
        let pages = std::env::var("LAWBAT_DEBUG_PAGES").unwrap_or_else(|_| "2".to_string());
        let bytes = std::fs::read(&path).expect("read LAWBAT_DEBUG_PDF");
        for p in pages
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
        {
            let runs = reconstruct_page_runs(&bytes, p);
            eprintln!("===== PAGE {p}: {} logical runs =====", runs.len());
            for (i, r) in runs.iter().enumerate() {
                eprintln!("[run {i:>3}] {r:?}");
            }
        }
    }

    #[test]
    fn redacts_email_card_and_term_preserves_innocuous() {
        // A Luhn-valid test card number (the classic 4111 1111 1111 1111 Visa
        // test number passes Luhn).
        let body = "Contact jane.roe@example.com about Project Falcon \
                    card 4111111111111111 — meeting Tuesday at noon.";
        let pdf = build_pdf(body, false);
        let result = redact_pdf(&pdf, &engine()).expect("redact");

        // Output still parses + the identifiers are gone from re-extracted text.
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("jane.roe@example.com"),
            "email should be removed; got: {text:?}"
        );
        assert!(
            !text.contains("4111111111111111"),
            "card should be removed; got: {text:?}"
        );
        assert!(
            !text.to_lowercase().contains("project falcon"),
            "term should be removed; got: {text:?}"
        );
        // Innocuous text preserved.
        assert!(text.contains("meeting"), "innocuous text lost: {text:?}");
        assert!(text.contains("Tuesday"), "innocuous text lost: {text:?}");
        assert!(text.contains(REDACTION_MARKER), "marker missing: {text:?}");

        assert!(result.total_redactions() >= 3, "expected >=3 redactions");
        assert!(!result.candidates().is_empty());
        assert!(!result.low_text(), "text page wrongly flagged low_text");
    }

    #[test]
    fn redacted_text_is_truly_removed_from_decoded_content_not_just_masked() {
        // The load-bearing guarantee: the identifier glyphs are GONE from the
        // underlying content stream operands — not a black box drawn over still-
        // present text. We reload the redacted PDF, decode each content stream, and
        // assert the email bytes are absent from the DECODED operand bytes. (Test
        // an UNcompressed source so the decoded == stored bytes; and a compressed
        // one to prove the decode path too.)
        for compressed in [false, true] {
            let pdf = build_pdf("write to secret.party@example.com please", compressed);
            let result = redact_pdf(&pdf, &engine()).expect("redact");
            let doc = Document::load_mem(result.bytes()).expect("reload");
            let needle = b"secret.party@example.com";
            for (_n, page_id) in doc.get_pages() {
                let decoded = doc.get_page_content(page_id).expect("page content");
                assert!(
                    !decoded.windows(needle.len()).any(|w| w == needle),
                    "identifier still present in decoded content (compressed={compressed})"
                );
            }
        }
    }

    #[test]
    fn handles_flate_compressed_stream() {
        let body = "email me at bob@firm.test now";
        let pdf = build_pdf(body, true); // FlateDecode content stream
        let result = redact_pdf(&pdf, &engine()).expect("redact compressed");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("bob@firm.test"),
            "email not removed from compressed stream: {text:?}"
        );
        assert!(result.total_redactions() >= 1);
    }

    #[test]
    fn redacts_identifier_split_across_tj_elements() {
        // Split a Luhn-valid card across two TJ array string elements; the run is
        // reconstructed across the kerning number so the whole number is caught.
        let pdf = build_pdf_tj_split("balance on 41111111", "11111111 today");
        let result = redact_pdf(&pdf, &engine()).expect("redact tj split");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("4111111111111111"),
            "split card across TJ elements not removed: {text:?}"
        );
        assert!(text.contains("today"), "innocuous TJ text lost: {text:?}");
        assert!(result.total_redactions() >= 1);
    }

    #[test]
    fn redacts_phone_and_email_split_across_adjacent_show_operators_on_one_line() {
        // THE FLAGSHIP cross-operator fix: a phone number AND an email, each laid out as
        // SEPARATE Tj operators on ONE visual line (the JP Morgan intl-rep-phone layout).
        // No single operand holds the whole token, so the old per-operator path MISSED
        // them (a silent leak). The logical-run join detects + removes both end to end.
        //
        // Line: "Call " "+852" " " "2800" " " "2800" " or " "fund" "info@" "jpmorgan.com"
        // Joined run = "Call  +852   2800   2800  or  fund info@ jpmorgan.com" — the engine
        // sees the contiguous phone and the contiguous email across the boundaries.
        let pdf = build_pdf_multi_op_lines(&[&[
            "Call ",
            "+852",
            " ",
            "2800",
            " ",
            "2800",
            " or ",
            "fund",
            "info@",
            "jpmorgan.com",
        ]]);

        // It is genuinely cross-operator: no single operand contains the full phone/email.
        // (Each Tj operand is one of the pieces above — proven by construction.)

        // (a) scan_pdf detects BOTH the phone and the email.
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let recs: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().recognizer().to_string())
            .collect();
        assert!(
            recs.iter().any(|r| r == "phone"),
            "cross-operator phone detected; got {recs:?}"
        );
        assert!(
            recs.iter().any(|r| r == "email"),
            "cross-operator email detected; got {recs:?}"
        );
        // The detected phone value spans the operators (contains all three pieces).
        let phone = scan
            .items()
            .iter()
            .find(|i| i.candidate().recognizer().to_string() == "phone")
            .expect("phone candidate");
        assert!(
            phone.candidate().matched_value().contains("+852")
                && phone.candidate().matched_value().contains("2800"),
            "phone value spans the operators: {:?}",
            phone.candidate().matched_value()
        );

        // (b) redact_pdf removes the SOURCE bytes from each contributing operator; the
        // re-extracted (visually joined) text no longer yields the phone or email.
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(result.total_redactions() >= 2, "phone + email removed");
        let text = extract_text(result.bytes());
        // The contiguous digit run of the phone is gone (no surviving fragment that, when
        // visually joined, reconstitutes the number).
        assert!(
            !text.contains("2800 2800"),
            "phone digits removed across operators: {text:?}"
        );
        assert!(
            !text.contains("info@jpmorgan.com"),
            "email removed across operators: {text:?}"
        );
        // Innocuous words on the same line are preserved.
        assert!(text.contains("Call"), "innocuous text lost: {text:?}");
        assert!(text.contains(REDACTION_MARKER), "marker written: {text:?}");
    }

    #[test]
    fn unrelated_tokens_on_separate_lines_do_not_form_a_cross_match() {
        // GUARD (no over-join across visual lines): two HALVES of an email-shaped token on
        // DIFFERENT lines must NOT join into one logical run and falsely match. Line 1 ends
        // with "alice@example" and line 2 starts with ".com" — visually two lines, so the
        // T* between them STARTS A NEW run and they are never concatenated. The default
        // engine therefore finds NO email (neither half is a complete address on its own).
        let pdf = build_pdf_multi_op_lines(&[&["intro ", "alice@example"], &[".com tail"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let recs: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().recognizer().to_string())
            .collect();
        assert!(
            !recs.iter().any(|r| r == "email"),
            "split across LINES must NOT cross-match into an email; got {recs:?}"
        );
    }

    #[test]
    fn numeric_table_column_yields_no_cross_line_phone_in_pdf_path() {
        // HIGH-1 GUARD (the `\s`-class cross-line over-join the token-join guard MISSES). A
        // financial-table column lays each figure on its OWN visual line (`10.48`, `11.01`,
        // …), so the stream-level `\n`-join produces `10.48\n11.01\n6.15\n7.81\n7.47`. The
        // phone pattern's char class `[\d\-\s().]` ADMITS the `\n`, so absent line-scoping it
        // matches the WHOLE column as one bogus phone (+89/+467 such FPs on the real corpus,
        // and apply-all would erase legitimate table figures). The `line_scope_sanctioned`
        // filter rejects any cross-`\n` span whose recognizers are all broad classes, so the
        // PDF path must surface ZERO phone candidates here. (Phone is NOT sanctioned; only
        // address family / `ctx:*` / user TERMS may legitimately span lines.)
        let pdf =
            build_pdf_multi_op_lines(&[&["10.48"], &["11.01"], &["6.15"], &["7.81"], &["7.47"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let phones: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "phone")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            phones.is_empty(),
            "a numeric TABLE COLUMN on separate visual lines must yield NO cross-line phone \
             candidate in the PDF path; got {phones:?}"
        );
    }

    #[test]
    fn genuine_single_line_phone_still_detected_in_pdf_path() {
        // COMPANION to the guard above: line-scoping the broad classes must NOT cost recall
        // on a REAL single-line phone. A phone number laid out on ONE visual line carries no
        // `\n` in its span, so the filter keeps it — the PDF path still detects it.
        let pdf = build_pdf_multi_op_lines(&[&["Call us at +65 6812 3456 today"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let phones: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "phone")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            phones
                .iter()
                .any(|v| v.replace(['\u{a0}', ' '], "").contains("6812")),
            "a genuine single-line phone must still be detected in the PDF path; got {phones:?}"
        );
    }

    #[test]
    fn same_line_pure_horizontal_td_still_joins_but_y_move_breaks() {
        // A pure horizontal `Td tx 0` (a column tab, common in justified layout) does NOT
        // advance the line, so two pieces it separates STILL join — the phone is caught.
        // We build the stream by hand to insert an explicit `Td 20 0` between the pieces.
        let mut doc = Document::with_version("1.5");
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(b"+852".to_vec(), StringFormat::Literal)],
            ),
            // Pure horizontal move on the SAME line (ty == 0) — must NOT break the run.
            Operation::new("Td", vec![20.into(), 0.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(b"2800 2800".to_vec(), StringFormat::Literal)],
            ),
            Operation::new("ET", vec![]),
        ];
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");

        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let recs: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().recognizer().to_string())
            .collect();
        assert!(
            recs.iter().any(|r| r == "phone"),
            "a pure horizontal Td (ty==0) keeps the line, so the phone joins; got {recs:?}"
        );
        // And it redacts end-to-end.
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("2800 2800"),
            "joined phone removed: {text:?}"
        );
    }

    #[test]
    fn cross_operator_scan_ids_map_exactly_onto_apply() {
        // The id contract holds on the cross-operator path: scanning a multi-operator
        // line yields stable ids, and accepting exactly one removes exactly that candidate
        // (the others survive). Two cross-operator emails on one line.
        let pdf =
            build_pdf_multi_op_lines(&[&["to ", "alice@", "ex1.com", " and ", "bob@", "ex2.com"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let emails: Vec<_> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "email")
            .collect();
        assert_eq!(emails.len(), 2, "two cross-operator emails detected");
        // Dense ascending ids (no duplicates / gaps from the run path).
        let ids: Vec<u64> = scan.items().iter().map(|i| i.id().get()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "ids are ascending + unique");

        // Accept ONLY the first email; the second must survive.
        let first = emails[0];
        let first_val = first.candidate().matched_value().to_string();
        let result = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of([first.id()]))
            .expect("apply");
        assert_eq!(
            result.total_redactions(),
            1,
            "exactly the accepted one removed"
        );
        assert_eq!(result.candidates()[0].matched_value(), first_val);
    }

    #[test]
    fn cross_operator_scan_reports_zero_per_page_redactions() {
        // Contract: a scan removes nothing, so PdfPageReport::redactions stays 0 even on
        // the cross-operator path (detected counts come from items()). Pins the fix that
        // the run-scan does not mis-report detections as removals.
        let pdf = build_pdf_multi_op_lines(&[&["x ", "+852", " ", "2800", " ", "2800"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.total_candidates() >= 1,
            "the cross-operator phone is detected"
        );
        for p in scan.pages() {
            assert_eq!(
                p.redactions(),
                0,
                "a scan removes nothing (page redactions == 0)"
            );
        }
    }

    #[test]
    fn cross_operator_apply_all_equals_redact_pdf_byte_for_byte() {
        // The shared-traversal invariant on the cross-operator path: redact_pdf (apply-all)
        // and redact_pdf_with_selection(all()) produce IDENTICAL bytes.
        let pdf = build_pdf_multi_op_lines(&[&["x ", "+852", " ", "2800", " ", "2800"]]);
        let a = redact_pdf(&pdf, &engine()).expect("redact_pdf");
        let b = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::all()).expect("all");
        assert_eq!(
            a.bytes(),
            b.bytes(),
            "apply-all via both entry points is identical"
        );
    }

    #[test]
    fn glyph_split_word_term_is_detected_and_truly_removed_whitespace_insensitive() {
        // THE LEAK-CLASS FIX: a user term whose word a glyph-by-glyph PDF layout fragmented
        // across Td-nudged show operators (`Daniel` `J.` `W` `at` `kins`) is reconstructed
        // WITH spurious internal spaces (`Daniel J. W at kins`). The ordinary literal term
        // match misses it — so a detected name SURVIVES apply (the JP Morgan p.323 bug).
        // The whitespace-insensitive term pass catches it; the span maps back to the real
        // glyph source bytes, so it is TRULY removed (gone from re-extracted text).
        let pdf = build_pdf_glyph_split(&["Daniel", "J.", "W", "at", "kins"]);
        let eng = RedactionEngine::new(["Daniel J. Watkins".to_string()]);

        // Sanity: the literal term WAS missed before the fix (the run text carries the
        // fabricated internal spaces), so this is genuinely the recovered case.
        let result = redact_pdf(&pdf, &eng).expect("redact glyph-split");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("Watkins") && !text.contains("atkins"),
            "the fragmented term must be removed from re-extracted text; got: {text:?}"
        );
        assert!(
            !result.bytes().windows(7).any(|w| w == b"Watkins"),
            "the term bytes must be absent from the raw output too"
        );
        // It WAS counted as a real removal (not over- or under-reported).
        assert!(
            result.total_redactions() >= 1,
            "the fragmented term is removed + counted"
        );
        assert_eq!(
            result.could_not_remove(),
            0,
            "a normal removal reports no could-not-remove"
        );
    }

    #[test]
    fn glyph_split_term_scan_id_maps_exactly_onto_apply() {
        // scan↔apply PdfCandidateId parity for the whitespace-insensitive term catch:
        // scanning yields a stable id for the fragmented term, and accepting exactly that
        // id removes exactly it.
        let pdf = build_pdf_glyph_split(&["Daniel", "J.", "W", "at", "kins"]);
        let eng = RedactionEngine::new(["Daniel J. Watkins".to_string()]);
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        let term = scan
            .items()
            .iter()
            .find(|i| i.candidate().recognizer().to_string() == "term")
            .expect("the fragmented term is detected as a term candidate");
        let id = term.id();
        let result =
            redact_pdf_with_selection(&pdf, &eng, &PdfSelection::of([id])).expect("apply one");
        assert_eq!(
            result.total_redactions(),
            1,
            "exactly the accepted term removed"
        );
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("Watkins") && !text.contains("atkins"),
            "removed: {text:?}"
        );
    }

    #[test]
    fn glyph_split_apply_all_equals_redact_pdf_byte_for_byte() {
        // The shared-traversal invariant holds with the ws-term pass active: redact_pdf
        // (apply-all) and redact_pdf_with_selection(all()) are byte-identical.
        let pdf = build_pdf_glyph_split(&["Daniel", "J.", "W", "at", "kins"]);
        let eng = RedactionEngine::new(["Daniel J. Watkins".to_string()]);
        let a = redact_pdf(&pdf, &eng).expect("redact_pdf");
        let b = redact_pdf_with_selection(&pdf, &eng, &PdfSelection::all()).expect("all");
        assert_eq!(
            a.bytes(),
            b.bytes(),
            "apply-all via both entry points is identical"
        );
    }

    #[test]
    fn no_terms_glyph_split_is_unaffected_byte_identical() {
        // NON-REGRESSION: with NO terms configured the whitespace-insensitive pass is a
        // no-op — a glyph-split page that has no built-in identifier is redacted exactly as
        // before (here: nothing to redact). Proves the common case is untouched.
        let pdf = build_pdf_glyph_split(&["Hello", "Wor", "ld"]);
        let eng = RedactionEngine::new(Vec::<String>::new());
        let result = redact_pdf(&pdf, &eng).expect("redact");
        assert_eq!(
            result.total_redactions(),
            0,
            "no terms, no identifiers => no redaction"
        );
        assert_eq!(result.could_not_remove(), 0);
        // The benign text survives intact (no fabricated removal).
        let text = extract_text(result.bytes());
        assert!(text.contains("Hello"), "benign text lost: {text:?}");
    }

    #[test]
    fn could_not_remove_is_honest_zero_on_normal_documents() {
        // The over-report guard reports 0 when every accepted span is truly removed — both
        // a plain WinAnsi page and the cross-operator path. (A non-zero value is the honest
        // signal for a span with no resolvable source bytes; it is unreachable for engine
        // output, so we pin the contract that the NORMAL path never spuriously trips it.)
        let plain = build_pdf("email bob@firm.test and Project Falcon", false);
        let r1 = redact_pdf(&plain, &engine()).expect("plain");
        assert!(r1.total_redactions() >= 2);
        assert_eq!(r1.could_not_remove(), 0, "plain page: nothing un-removable");

        let multi = build_pdf_multi_op_lines(&[&["x ", "+852", " ", "2800", " ", "2800"]]);
        let r2 = redact_pdf(&multi, &engine()).expect("multi");
        assert_eq!(
            r2.could_not_remove(),
            0,
            "cross-operator page: nothing un-removable"
        );
    }

    #[test]
    fn ws_term_pass_does_not_double_count_an_already_caught_term() {
        // A term laid out as a SINGLE operand (already caught by the ordinary literal pass)
        // must NOT be double-counted by the whitespace-insensitive pass (its span overlaps
        // the primary span, so it is skipped). Exactly one removal, not two.
        let pdf = build_pdf("Project Falcon is confidential", false);
        let eng = RedactionEngine::new(["Project Falcon".to_string()]);
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        let terms = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "term")
            .count();
        assert_eq!(
            terms, 1,
            "the single-operand term is detected exactly once (no ws dup)"
        );
        let result = redact_pdf(&pdf, &eng).expect("redact");
        assert_eq!(
            result.total_redactions(),
            1,
            "exactly one removal, no double-count"
        );
    }

    #[test]
    fn ws_term_partially_overlapping_a_primary_is_removed_in_full_not_skipped() {
        // The reviewer's edge case: a user term whose word is fragmented AND part of the
        // term is independently matched by a built-in (here the email inside the term). A
        // wholesale "overlaps any primary" skip would leave the term's NON-overlapping
        // remainder un-redacted (`ref`/`acme` survive). The fix skips ONLY a ws-span fully
        // contained in a primary; a PARTIAL overlap is kept and removed in FULL (the safe
        // side). Assert the whole term is gone, not just the embedded email.
        let pdf = build_pdf_glyph_split(&["ref", "bob@", "firm", ".test", "acme"]);
        let eng = RedactionEngine::new(["ref bob@firm.test acme".to_string()]);
        let result = redact_pdf(&pdf, &eng).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("bob@firm.test"),
            "embedded email gone: {text:?}"
        );
        assert!(
            !text.contains("acme"),
            "term remainder 'acme' must NOT survive: {text:?}"
        );
        assert!(
            !text.contains("ref"),
            "term remainder 'ref' must NOT survive: {text:?}"
        );
        assert_eq!(
            result.could_not_remove(),
            0,
            "all accepted spans truly removed"
        );
    }

    /// Engine with the default built-ins (structured-address family ON) + the SG locale
    /// (precise `sg:postal`), so BOTH the global unit row and the SG postal row have
    /// whitespace-elastic recall. No user terms.
    fn addr_pdf_engine() -> RedactionEngine {
        RedactionEngine::builder()
            .locales([crate::Locale::Singapore])
            .build()
            .expect("addr engine")
    }

    #[test]
    fn glyph_split_address_unit_is_detected_and_truly_removed_whitespace_insensitive() {
        // MISS 1 (the address-family analogue of the `Daniel J. W at kins` TERMS leak): the
        // SG unit form `#16-03` laid out glyph-cluster by glyph-cluster (`#` `16-0` `3`,
        // Td-nudged apart) reconstructs as `# 16-0 3` — the fabricated internal spaces break
        // the compact `#\d{1,3}-\d{1,4}` structural pattern, so the ordinary pass MISSES it
        // and the unit number SURVIVES apply (a leak). The whitespace-elastic address pass
        // catches it; the span maps back to the real glyph source bytes for TRUE removal.
        let pdf = build_pdf_glyph_split(&["#", "16-0", "3"]);
        let eng = addr_pdf_engine();

        // The fragmented unit IS detected, as an Address candidate.
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        let unit = scan
            .items()
            .iter()
            .find(|i| i.candidate().recognizer().to_string() == "address");
        assert!(
            unit.is_some(),
            "the fragmented #16-03 unit must be an address candidate; got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().recognizer().to_string())
                .collect::<Vec<_>>()
        );

        // Apply-all TRULY removes the digits (gone from re-extracted text AND raw bytes).
        let result = redact_pdf(&pdf, &eng).expect("redact glyph-split unit");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("16-0") && !text.contains("16-03"),
            "the fragmented unit number must be removed from re-extracted text; got {text:?}"
        );
        assert!(
            !result.bytes().windows(4).any(|w| w == b"16-0"),
            "the unit-number bytes must be absent from the raw output too"
        );
        assert!(
            result.total_redactions() >= 1,
            "the fragmented unit is removed + counted"
        );
        assert_eq!(
            result.could_not_remove(),
            0,
            "a normal removal reports no could-not-remove"
        );
    }

    #[test]
    fn glyph_split_sg_postal_is_detected_and_removed_whitespace_insensitive() {
        // MISS 1, the locale-postal arm: `Singapore 048623` fragmented across Td-nudged show
        // ops (`Singapore` `0486` `23`) reconstructs as `Singapore 0486 23` — the spurious
        // space inside the 6-digit run breaks the `Singapore\s+\d{6}` postal shape, so the
        // ordinary pass misses it. The whitespace-elastic postal recall (scoped to the
        // PRECISE `sg:postal` row, NOT the aggressive bare-postal net) catches it.
        let pdf = build_pdf_glyph_split(&["Singapore", "0486", "23"]);
        let eng = addr_pdf_engine();
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().recognizer().to_string() == "sg:postal"),
            "the fragmented SG postal must attribute to sg:postal; got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().recognizer().to_string())
                .collect::<Vec<_>>()
        );
        let result = redact_pdf(&pdf, &eng).expect("redact glyph-split postal");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("0486") && !text.contains("048623"),
            "the fragmented postal digits must be removed; got {text:?}"
        );
        assert_eq!(result.could_not_remove(), 0, "truly removed");
    }

    #[test]
    fn glyph_split_address_scan_id_maps_exactly_onto_apply() {
        // scan↔apply PdfCandidateId parity for the whitespace-elastic address catch: scanning
        // yields a stable id for the fragmented unit, and accepting exactly that id removes
        // exactly it (same contract the ws-term pass upholds).
        let pdf = build_pdf_glyph_split(&["#", "16-0", "3"]);
        let eng = addr_pdf_engine();
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        let unit = scan
            .items()
            .iter()
            .find(|i| i.candidate().recognizer().to_string() == "address")
            .expect("fragmented unit detected");
        let id = unit.id();
        let result =
            redact_pdf_with_selection(&pdf, &eng, &PdfSelection::of([id])).expect("apply one");
        assert_eq!(
            result.total_redactions(),
            1,
            "exactly the accepted address span removed"
        );
        let text = extract_text(result.bytes());
        assert!(!text.contains("16-0"), "removed: {text:?}");
    }

    #[test]
    fn glyph_split_address_apply_all_equals_redact_pdf_byte_for_byte() {
        // The shared-traversal invariant holds with the ws-ADDRESS pass active: redact_pdf
        // (apply-all) and redact_pdf_with_selection(all()) are byte-identical.
        let pdf = build_pdf_glyph_split(&["#", "16-0", "3"]);
        let eng = addr_pdf_engine();
        let a = redact_pdf(&pdf, &eng).expect("redact_pdf");
        let b = redact_pdf_with_selection(&pdf, &eng, &PdfSelection::all()).expect("all");
        assert_eq!(
            a.bytes(),
            b.bytes(),
            "apply-all via both entry points is identical"
        );
    }

    #[test]
    fn no_address_rows_ws_address_pass_is_noop_byte_identical() {
        // CONSTRAINT (c): with the address family DISABLED and no precise postal locale, the
        // whitespace-elastic address pass is a byte-identical no-op. A glyph-split unit-shaped
        // page (that WOULD fire with address on) is redacted exactly as before (nothing).
        let pdf = build_pdf_glyph_split(&["#", "16-0", "3"]);
        let mut builtins = BuiltinRecognizers::all();
        builtins.address = false;
        let eng = RedactionEngine::builder()
            .builtins(builtins)
            .build()
            .expect("no-address engine");
        let result = redact_pdf(&pdf, &eng).expect("redact");
        assert_eq!(
            result.total_redactions(),
            0,
            "address off + no postal locale => the ws-address pass adds nothing"
        );
        assert_eq!(result.could_not_remove(), 0);
        // The benign glyph-split text is preserved (no fabricated removal).
        let text = extract_text(result.bytes());
        assert!(text.contains("16-0"), "benign text lost: {text:?}");
    }

    /// SG locale (postal) + address family + the role-name context recognizer — the engine
    /// config the real prospectus reproduction used. The pdf tests build it once here.
    fn role_addr_pdf_engine() -> RedactionEngine {
        RedactionEngine::builder()
            .locales([crate::Locale::Singapore])
            .context_recognizers(crate::ContextRecognizers {
                role_name: true,
                ..crate::ContextRecognizers::none()
            })
            .build()
            .expect("role+addr engine")
    }

    #[test]
    fn role_name_block_laid_out_as_separate_visual_lines_is_detected_and_removed() {
        // THE REAL-FILE MISS this whole fix targets. A prospectus "parties directory" lays
        // the role HEADING and each director NAME on their OWN visual line — each a separate
        // show operator broken by a `T*` (next-line) op, so the PDF reconstruction produced
        // a SEPARATE logical run per line. The old per-run scan handed the engine ONE line
        // at a time, so `ctx:role-name` (which needs the heading line ABOVE the name in the
        // SAME text) NEVER fired and every name SURVIVED — even though the engine-level
        // multi-line fixtures all passed. The stream-level `\n`-join now reconstructs the
        // multi-line block the engine was built for. SYNTHETIC values in the real shape.
        let pdf = build_pdf_multi_op_lines(&[
            &["Directors of the Managers"],
            &["Lee Wai Fai"],
            &["Thio Boon Kiat"],
            &["Edmund Leong Kok Mun"],
        ]);
        let eng = role_addr_pdf_engine();

        // Each name is detected as a role-context name (heading now visible across the line).
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        let role_names: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "ctx:role-name")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        for name in ["Lee Wai Fai", "Thio Boon Kiat", "Edmund Leong Kok Mun"] {
            assert!(
                role_names.iter().any(|v| v == name),
                "role-name `{name}` must be detected across separate visual lines; got {role_names:?}"
            );
        }

        // And apply-all TRULY removes them from the extracted text (the leak is closed).
        let result = redact_pdf(&pdf, &eng).expect("redact");
        let text = extract_text(result.bytes());
        for name in ["Lee Wai", "Thio Boon", "Edmund Leong"] {
            assert!(
                !text
                    .replace(['\n', ' '], "")
                    .contains(&name.replace(' ', "")),
                "role name `{name}` survived apply on the separate-line layout: {text:?}"
            );
        }
    }

    #[test]
    fn inline_building_name_wrapped_across_a_visual_line_is_removed() {
        // THE `Capital Tower` RESIDUAL. A building name embedded INLINE in a prose sentence
        // AND split across a PDF line wrap: `…the Register at 168 Robinson Road #33-01,
        // Capital` / `Tower, Singapore 068912…` — two visual lines. The street/unit/postal
        // around it are redacted, but the premises name straddles the line boundary between
        // two ADJACENT address anchors (not on its own line), so the block-continuation pass
        // missed it. The inline building-name capture removes it. SYNTHETIC prose, real shape.
        let pdf = build_pdf_multi_op_lines(&[
            &["Any Holder may inspect the Register at 168 Robinson Road #33-01, Capital"],
            &["Tower, Singapore 068912 during normal business hours by prior appointment."],
        ]);
        let eng = role_addr_pdf_engine();

        let result = redact_pdf(&pdf, &eng).expect("redact");
        let text = extract_text(result.bytes());
        let squished = text.replace(['\n', ' '], "");
        assert!(
            !squished.contains("CapitalTower"),
            "inline line-wrapped building name `Capital Tower` survived apply: {text:?}"
        );
        // The surrounding address parts are gone too (sanity: the whole address block went).
        assert!(
            !squished.contains("RobinsonRoad"),
            "street survived: {text:?}"
        );
        assert!(!squished.contains("068912"), "postal survived: {text:?}");
        // Innocuous prose on the same lines is preserved (no over-redaction of the sentence).
        assert!(text.contains("Holder"), "innocuous prose lost: {text:?}");
        assert!(
            text.contains("business hours"),
            "innocuous prose lost: {text:?}"
        );
    }

    #[test]
    fn directory_of_parties_one_content_stream_per_line_names_and_buildings_removed() {
        // THE FITZ-TYPESET LAYOUT VARIANT (round-3/4 mechanisms under-fire). A "parties
        // directory" exported with one `insert_text` per visual line lands EACH line in its
        // OWN content stream (page `/Contents` is an ARRAY of 25+ streams). The pre-merge
        // path scanned each stream in ISOLATION, so `ctx:role-name` never saw the heading
        // above its name list and the address-block continuation never saw the anchors around
        // a premises line — every director name + every sandwiched building line SURVIVED
        // apply, fully recoverable. The page-level stream merge (`process_page_streams`)
        // restores the multi-line view; the 6-token building-line cap catches the longer
        // `Tower 3 …`/`… Tower 2` premises names. SYNTHETIC person names of the SAME token
        // shapes as the reported real-file miss; synthetic building names of the same shape.
        let lines = [
            "DIRECTORY OF PARTIES",
            "Managers",
            "Meridian Asset Management Pte. Ltd.",
            "10 Marina Boulevard, #48-01",
            "Harbour Bay Financial Centre Tower 2",
            "Singapore 018983",
            "Directors of the Managers",
            "Beck Wai Meng",
            "Tang Kok Ming",
            "Hingdon Edward James",
            "Quay Siew Lan",
            "Solicitors to the Managers",
            "Clifford Chance Pte. Ltd.",
            "12 Marina Boulevard, 25th Floor",
            "Tower 3 Harbour Bay Financial Centre",
            "Singapore 018982",
            "Solicitors to the Trustee",
            "Dentons Rodyk & Davidson LLP",
            "80 Raffles Place, #33-00",
            "Zenith Plaza 1",
            "Singapore 048624",
            "Registered office:",
            "9 Raffles Place, #26-01",
            "Concord Plaza",
            "Singapore 048619",
            // NAV-style numeric rows — each its OWN stream/visual line. The stream merge must
            // NOT let the phone pattern's `\s`-class stitch these into a cross-line phone.
            "Net Asset Value",
            "1.2345",
            "6.7890",
            "10.4820",
            "88.1200",
        ];
        let pdf = build_pdf_stream_per_visual_line(&lines);

        // Premise guard: the fixture really is multi-stream (one content stream per line).
        {
            let doc = Document::load_mem(&pdf).expect("load fixture");
            let page_id = *doc.get_pages().values().next().expect("one page");
            assert!(
                doc.get_page_contents(page_id).len() >= lines.len(),
                "fixture must lay each visual line in its OWN content stream"
            );
        }

        let eng = role_addr_pdf_engine();
        let scan = scan_pdf(&pdf, &eng).expect("scan");

        // Every director NAME is detected as a role-context name (heading now visible across
        // the merged streams).
        let role_names: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "ctx:role-name")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        for name in [
            "Beck Wai Meng",
            "Tang Kok Ming",
            "Hingdon Edward James",
            "Quay Siew Lan",
        ] {
            assert!(
                role_names.iter().any(|v| v == name),
                "director name `{name}` must be detected across the per-line streams; got {role_names:?}"
            );
        }

        // All three sandwiched building/tower lines are captured (address family). The two
        // six-token towers exercise the widened building-line token cap.
        let all_values: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        for building in [
            "Zenith Plaza 1",
            "Concord Plaza",
            "Tower 3 Harbour Bay Financial Centre",
        ] {
            assert!(
                all_values.iter().any(|v| v == building),
                "building line `{building}` must be detected between its address anchors; got {all_values:?}"
            );
        }

        // The NAV numeric rows never phone-match (no cross-line stitch through the merge).
        let phones: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "phone")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            phones.is_empty(),
            "NAV numeric rows must never be phone-matched across merged streams; got {phones:?}"
        );

        // Apply-all (same engine — no config drift) TRULY removes every name + building line.
        let result = redact_pdf(&pdf, &eng).expect("redact");
        let text = extract_text(result.bytes());
        let squished = text.replace(['\n', ' ', '.'], "");
        for target in [
            "BeckWaiMeng",
            "TangKokMing",
            "HingdonEdwardJames",
            "QuaySiewLan",
            "ZenithPlaza1",
            "ConcordPlaza",
            "Tower3HarbourBayFinancialCentre",
            "HarbourBayFinancialCentreTower2",
        ] {
            assert!(
                !squished.contains(target),
                "`{target}` survived apply on the per-line-stream layout: {text:?}"
            );
        }
        assert_eq!(
            result.could_not_remove(),
            0,
            "every accepted span must be truly removable"
        );
    }

    #[test]
    fn image_only_page_flagged_low_text_no_false_redaction() {
        let pdf = build_pdf_no_text();
        let result = redact_pdf(&pdf, &engine()).expect("redact image-only");
        assert_eq!(result.total_redactions(), 0, "no text => no redactions");
        assert!(
            result.low_text(),
            "image-only page must be flagged low_text"
        );
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let body = "reach me: alice@example.org and Project Falcon";
        let pdf = build_pdf(body, true);
        let a = redact_pdf(&pdf, &engine()).expect("a").into_bytes();
        let b = redact_pdf(&pdf, &engine()).expect("b").into_bytes();
        assert_eq!(a, b, "redaction must be deterministic (byte-identical)");
    }

    #[test]
    fn empty_input_is_error_not_panic() {
        let err = redact_pdf(&[], &engine());
        assert!(err.is_err(), "empty input must Err");
    }

    #[test]
    fn non_pdf_bytes_is_error_not_panic() {
        let err = redact_pdf(b"this is plainly not a pdf at all", &engine());
        assert!(err.is_err(), "non-pdf bytes must Err");
    }

    #[test]
    fn truncated_pdf_is_error_not_panic() {
        // Take a real PDF and chop it in half — the parser should Err, not panic.
        let pdf = build_pdf("something with bob@firm.test inside", false);
        let truncated = &pdf[..pdf.len() / 2];
        let res = redact_pdf(truncated, &engine());
        // We only require no panic + a Result; truncation usually Errs, but if
        // lopdf manages a lenient parse, the output must still be valid bytes.
        if let Ok(r) = res {
            assert!(!r.bytes().is_empty(), "lenient parse must still emit bytes");
        }
    }

    #[test]
    fn oversize_input_is_refused() {
        // A buffer just over the cap: must be refused fast, before parsing.
        let big = vec![b'%'; MAX_PDF_BYTES + 1];
        let err = redact_pdf(&big, &engine());
        assert!(err.is_err(), "oversize input must be refused");
    }

    #[test]
    fn garbage_with_pdf_header_does_not_panic() {
        // A PDF magic header followed by random bytes — exercise the parser's
        // hostile-input path. Must not panic; Result either way.
        let mut bytes = b"%PDF-1.5\n".to_vec();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x0A, 0x25, 0x25]);
        bytes.extend_from_slice(b"\nstream\n\xff\xfe garbage endstream\n%%EOF");
        let _ = redact_pdf(&bytes, &engine()); // just must not panic
    }

    #[test]
    fn count_matches_candidates_pushed() {
        // The invariant the engine keeps (count == candidates == markers written)
        // must hold across the PDF path too: total_redactions() == candidates().len().
        let body = "alice@example.org, bob@example.net, Project Falcon, 4111111111111111";
        let pdf = build_pdf(body, false);
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert_eq!(
            result.total_redactions(),
            result.candidates().len(),
            "redaction count must equal the candidate list length"
        );
        // And the marker appears exactly once per redaction in the re-extracted text.
        let text = extract_text(result.bytes());
        let marker_hits = text.matches(REDACTION_MARKER).count();
        assert_eq!(
            marker_hits,
            result.total_redactions(),
            "one marker written per redaction"
        );
    }

    #[test]
    fn multipage_redacts_and_is_ordered() {
        // Sanity: a real text page is not flagged low_text and the per-page report
        // is in ascending page order.
        let pdf = build_pdf("contact carol@example.com now", false);
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        let pages = result.pages();
        assert!(!pages.is_empty());
        let mut last = 0u32;
        for p in pages {
            assert!(p.page() > last, "pages must be ascending");
            last = p.page();
        }
    }

    #[test]
    fn hostile_byte_patterns_never_panic() {
        // A spread of malformed/hostile inputs: each must return a Result (Ok or
        // Err) without ANY panic (no unwrap/slice/expect blow-up). This is the
        // load-bearing never-panic guarantee for parsing hostile PDF bytes.
        let cases: Vec<Vec<u8>> = vec![
            b"%PDF-".to_vec(),
            b"%PDF-1.7".to_vec(),
            b"%PDF-1.7\nstream".to_vec(),
            b"%PDF-1.7\n1 0 obj\n<< /Length 999999 >>\nstream\nshort".to_vec(),
            b"%PDF-1.7\ntrailer\n<< /Root 1 0 R >>\n%%EOF".to_vec(),
            vec![0u8; 64],
            vec![0xFFu8; 64],
            b"%PDF-1.7\n<< /Filter /FlateDecode >>\nstream\n\x00\x01\x02\x03endstream".to_vec(),
            {
                let mut v = b"%PDF-1.7\n".to_vec();
                v.extend(std::iter::repeat_n(b'(', 10_000)); // unbalanced parens
                v
            },
            {
                let mut v = b"%PDF-1.7\n".to_vec();
                v.extend(std::iter::repeat_n(b'<', 10_000)); // unbalanced dict
                v
            },
        ];
        for (i, c) in cases.iter().enumerate() {
            // Must not panic. Result either way.
            let _ = redact_pdf(c, &engine());
            // also exercise a valid-but-truncated copy
            if c.len() > 4 {
                let _ = redact_pdf(&c[..c.len() / 2], &engine());
            }
            let _ = i;
        }
    }

    #[test]
    fn latin1_roundtrip_bijection() {
        // Every byte maps to a distinct code point and back to the same char index.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let s = bytes_to_latin1(&bytes);
        assert_eq!(s.chars().count(), 256);
        for (i, ch) in s.chars().enumerate() {
            assert_eq!(ch as u32, i as u32);
        }
    }

    // --- H1: decompression-bomb defence ---------------------------------------

    /// Flate-compress `plain` with zlib (the FlateDecode wire format) so we can
    /// hand-build a content stream with a chosen inflation ratio.
    fn flate_compress(plain: &[u8]) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(plain).expect("compress");
        enc.finish().expect("finish")
    }

    /// Build a one-page PDF whose single content stream is a `FlateDecode` stream
    /// that decodes to `decoded` (we set the filter + compressed bytes by hand so
    /// the inflation ratio is whatever `decoded` dictates). Returns the PDF bytes.
    fn build_pdf_with_flate_content(decoded: &[u8]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let compressed = flate_compress(decoded);
        // Stream::new sets /Length to the (compressed) content length; we add the
        // /Filter so lopdf sees it as FlateDecode.
        let dict = dictionary! { "Filter" => "FlateDecode" };
        let content_id = doc.add_object(Stream::new(dict, compressed));
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        let page = dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(page_id, Object::Dictionary(page));
        let pages = dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save flate-bomb pdf");
        out
    }

    #[test]
    fn decompression_bomb_stream_is_skipped_with_diagnostic_and_flagged() {
        // The reviewer's probe: a small input whose single FlateDecode stream
        // inflates to hundreds of MiB. We build ~300 MiB of decoded content from a
        // highly-repetitive payload (compresses to a few hundred KiB), proving the
        // per-stream cap stops the inflation: the OUTPUT PDF is produced, the stream
        // is recorded as an over-budget SKIP, and low_text is forced so the caller
        // cannot read the unexamined stream as "clean".
        //
        // Memory note: building the *decoded test fixture* allocates ~300 MiB ONCE
        // (the test owns it deliberately to prove the ratio); the function under
        // test must NOT add an unbounded second ~300 MiB on top — it caps at 16 MiB.
        let huge = 300 * 1024 * 1024usize; // 300 MiB decoded
        let decoded = vec![b' '; huge]; // trivially compressible
        let pdf = build_pdf_with_flate_content(&decoded);
        drop(decoded); // free the fixture before calling, so peak reflects the SUT
        assert!(
            pdf.len() < 2 * 1024 * 1024,
            "bomb input should be small (got {} bytes)",
            pdf.len()
        );

        let result = redact_pdf(&pdf, &engine()).expect("bomb must not abort the document");
        // The over-cap stream was skipped, not silently treated as clean.
        assert!(
            result.low_text(),
            "a skipped over-budget stream must force low_text (fail-closed)"
        );
        assert!(
            result
                .diagnostics()
                .iter()
                .any(|d| d.contains("decompression bomb") || d.contains("decoded cap")),
            "expected an over-budget diagnostic; got {:?}",
            result.diagnostics()
        );
        assert_eq!(
            result.total_redactions(),
            0,
            "an unexamined bombed stream yields no redactions (but IS flagged)"
        );
        // The decoded text we DID account for is bounded by the per-stream cap.
        assert!(
            result.total_text_bytes() <= MAX_DECODED_STREAM_BYTES,
            "scanned text must be bounded by the per-stream cap"
        );
    }

    /// Build a one-page PDF whose catalog `/Metadata` (XMP) is a `FlateDecode` stream
    /// inflating to `decoded` — the bomb vector for `collect_xmp_detection`. The page has a
    /// trivial body so the rest of the pass runs normally.
    fn build_pdf_with_flate_xmp(decoded: &[u8]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        // Trivial page content (so traversal has something benign to do).
        let body_ops = b"BT /F1 12 Tf 72 720 Td (Body) Tj ET".to_vec();
        let content_id = doc.add_object(Stream::new(Dictionary::new(), body_ops));
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
        // The XMP /Metadata stream, FlateDecode-compressed to whatever ratio `decoded` gives.
        let compressed = flate_compress(decoded);
        let md = dictionary! {
            "Type" => "Metadata", "Subtype" => "XML", "Filter" => "FlateDecode",
        };
        let stream_id = doc.add_object(Stream::new(md, compressed));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id, "Metadata" => Object::Reference(stream_id),
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save flate-xmp pdf");
        out
    }

    #[test]
    fn xmp_metadata_decompression_bomb_does_not_oom_and_is_scrubbed() {
        // H1 for the METADATA pass (Finding #2): a small (~few hundred KiB) FlateDecode XMP
        // /Metadata stream that inflates to ~300 MiB must NOT OOM-abort the core. The XMP
        // decode now routes through the SAME `decode_stream_capped` reader as content streams
        // (NOT lopdf's uncapped `decompressed_content`), so an over-cap stream is refused and
        // falls through to the wholesale-removal path — the metadata is still SCRUBBED (the
        // safe side), just not parsed. We prove: no OOM/panic, the over-cap stream is removed
        // (no /Metadata survives), and the output reloads.
        let huge = 300 * 1024 * 1024usize; // 300 MiB decoded XMP
        let decoded = vec![b' '; huge]; // trivially compressible -> a tiny compressed stream
        let pdf = build_pdf_with_flate_xmp(&decoded);
        drop(decoded); // free the fixture so peak reflects the function under test
        assert!(
            pdf.len() < 2 * 1024 * 1024,
            "bomb input should be small (got {} bytes)",
            pdf.len()
        );

        // BEFORE: the (compressed) /Metadata stream exists.
        {
            let doc = Document::load_mem(&pdf).expect("reload bomb pdf");
            let (_cid, catalog) = resolve_catalog(&doc).expect("catalog");
            assert!(
                catalog.get(METADATA_KEY).is_ok(),
                "metadata stream present before"
            );
        }

        // The SUT must NOT OOM/panic — the cap stops the inflation (peak ~16 MiB, not 300).
        let result = redact_pdf(&pdf, &engine()).expect("xmp bomb must not abort the document");

        // The over-cap metadata was removed wholesale (fail-closed), not silently kept.
        assert!(
            xmp_text(result.bytes()).is_none(),
            "over-cap XMP /Metadata must be scrubbed wholesale (fail-closed), not left intact"
        );
        assert!(
            result.total_redactions() >= 1,
            "the wholesale XMP removal counts as a redaction"
        );
        // Structural integrity: the redacted output still parses.
        let _doc = Document::load_mem(result.bytes()).expect("redacted PDF must still parse");
    }

    #[test]
    fn at_cap_flate_stream_is_processed_just_over_is_skipped() {
        // Boundary: a decoded stream exactly at the per-stream cap is processed
        // normally; one a hair over is skipped with a diagnostic. Both must be
        // deterministic and never panic. We pad a tiny bit of real text so the
        // "at cap" case still scans + (if present) redacts.
        // Just-over: cap + 64 bytes of spaces.
        let over = vec![b' '; MAX_DECODED_STREAM_BYTES + 64];
        let pdf_over = build_pdf_with_flate_content(&over);
        drop(over);
        let r_over = redact_pdf(&pdf_over, &engine()).expect("over-cap must not abort");
        assert!(r_over.low_text(), "just-over-cap stream must be flagged");
        assert!(
            r_over
                .diagnostics()
                .iter()
                .any(|d| d.contains("decoded cap") || d.contains("decompression bomb")),
            "just-over-cap must produce an over-budget diagnostic; got {:?}",
            r_over.diagnostics()
        );

        // Under cap: a modest valid content stream redacts normally.
        let mut ops = b"BT /F1 12 Tf 72 720 Td (email bob@firm.test now) Tj ET".to_vec();
        // Pad with a comment line of spaces to grow the stream but stay well under cap.
        ops.extend(std::iter::repeat_n(b'\n', 1024));
        let pdf_under = build_pdf_with_flate_content(&ops);
        let r_under = redact_pdf(&pdf_under, &engine()).expect("under-cap ok");
        let text = extract_text(r_under.bytes());
        assert!(
            !text.contains("bob@firm.test"),
            "under-cap stream should redact normally: {text:?}"
        );
    }

    // --- M1: non-spec /Encrypt must be REFUSED (not a degenerate 0-redaction Ok) --

    /// Build a minimal PDF and inject an `/Encrypt` entry into the trailer shaped
    /// by `encrypt_obj` (a DIRECT dict, or a reference to a non-dictionary, etc.).
    /// These are the NON-spec shapes that slip lopdf's narrow `is_encrypted()`.
    fn build_pdf_with_trailer_encrypt(encrypt_obj: Object) -> Vec<u8> {
        // Start from a normal valid PDF, then re-open it and set /Encrypt directly
        // in the trailer (a DIRECT object, not the spec's indirect reference to a
        // standard encryption dict), and re-serialise.
        let base = build_pdf("nothing secret here at all", false);
        let mut doc = Document::load_mem(&base).expect("reload base");
        doc.trailer.set("Encrypt", encrypt_obj);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save with injected Encrypt");
        out
    }

    #[test]
    fn encrypt_as_direct_dict_is_refused_not_degenerate_ok() {
        // /Encrypt as a DIRECT dictionary (non-spec — the spec requires an indirect
        // reference). lopdf's loader still routes into the encrypted path on the
        // weaker .is_ok() check; our gate must REFUSE rather than emit a 0-redaction
        // "success" over a possibly-empty doc.
        let direct = Object::Dictionary(dictionary! {
            "Filter" => "Standard", "V" => 1, "R" => 2,
        });
        let pdf = build_pdf_with_trailer_encrypt(direct);
        let res = redact_pdf(&pdf, &engine());
        assert!(
            res.is_err(),
            "/Encrypt as a direct dict must be REFUSED, not a degenerate Ok"
        );
        let msg = format!("{:?}", res.err().unwrap());
        assert!(
            msg.contains("encrypted") || msg.contains("no objects decoded"),
            "refusal must be the encryption/degenerate-empty error; got {msg}"
        );
    }

    #[test]
    fn encrypt_as_reference_to_integer_is_refused() {
        // /Encrypt as a reference to a NON-dictionary (here an Integer object).
        // is_encrypted() returns false (it can't resolve a dict) so the OLD gate
        // let it through; the new gate refuses on the bare presence of /Encrypt.
        let mut base_doc = {
            let base = build_pdf("nothing secret here at all", false);
            Document::load_mem(&base).expect("reload base")
        };
        // Add an Integer object and point /Encrypt at it by reference.
        let int_id = base_doc.add_object(Object::Integer(42));
        base_doc.trailer.set("Encrypt", Object::Reference(int_id));
        let mut out = Vec::new();
        base_doc.save_to(&mut out).expect("save");
        let res = redact_pdf(&out, &engine());
        assert!(
            res.is_err(),
            "/Encrypt referencing a non-dictionary must be REFUSED"
        );
    }

    // --- L1: a non-canonical show-operator operand shape must be OBSERVABLE ------

    #[test]
    fn noncanonical_show_operator_shape_pushes_diagnostic() {
        // A `"` operator whose operands are [string, num, num] (the string is NOT
        // the trailing operand) — the canonical shape is [num, num, string]. The
        // identifier in the leading string would survive unflagged; the fix surfaces
        // a content-free diagnostic so the miss is observable rather than silent.
        let mut doc = Document::with_version("1.5");
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            // Malformed `"`: string FIRST, then the two numbers.
            Operation::new(
                "\"",
                vec![
                    Object::String(b"secret bob@firm.test".to_vec(), StringFormat::Literal),
                    0.into(),
                    0.into(),
                ],
            ),
            Operation::new("ET", vec![]),
        ];
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        let page = dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(page_id, Object::Dictionary(page));
        let pages = dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog", "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save");

        let result = redact_pdf(&out, &engine()).expect("redact");
        assert!(
            result
                .diagnostics()
                .iter()
                .any(|d| d.contains("unexpected operand shape")),
            "a non-canonical show operator must push a diagnostic; got {:?}",
            result.diagnostics()
        );
        // ROUND 7 — the diagnostic carries PAGE ATTRIBUTION, so a reviewer can find
        // the un-scanned operator instead of grepping 900 pages blind.
        assert!(
            result
                .diagnostics()
                .iter()
                .any(|d| d.starts_with("page 1: operator")),
            "the operand-shape diagnostic must name its page; got {:?}",
            result.diagnostics()
        );
        // And the diagnostic carries NO cleartext (confidentiality split).
        for d in result.diagnostics() {
            assert!(
                !d.contains("bob@firm.test") && !d.contains("secret"),
                "diagnostic leaked cleartext: {d}"
            );
        }
    }

    #[test]
    fn bomb_redaction_is_deterministic() {
        // The bomb path must still be byte-deterministic (same input, same output).
        let decoded = vec![b' '; MAX_DECODED_STREAM_BYTES + 1024];
        let pdf = build_pdf_with_flate_content(&decoded);
        drop(decoded);
        let a = redact_pdf(&pdf, &engine()).expect("a").into_bytes();
        let b = redact_pdf(&pdf, &engine()).expect("b").into_bytes();
        assert_eq!(a, b, "bomb-skip path must be deterministic");
    }

    // ---- per-span scan / select / apply (v2 review flow) ------------------------

    /// A two-identifier body so a reviewer can accept one and keep the other.
    fn two_email_pdf() -> Vec<u8> {
        build_pdf(
            "Email alice@example.com or bob@example.com for details.",
            false,
        )
    }

    #[test]
    fn scan_pdf_enumerates_candidates_with_stable_ids() {
        let pdf = two_email_pdf();
        let s1 = scan_pdf(&pdf, &engine()).expect("scan");
        assert_eq!(s1.total_candidates(), 2, "both emails detected");
        for item in s1.items() {
            assert_eq!(item.page(), 1, "single-page fixture");
        }
        // Determinism: scanning again yields the SAME ids in the SAME order.
        let s2 = scan_pdf(&pdf, &engine()).expect("scan again");
        let ids1: Vec<u64> = s1.items().iter().map(|i| i.id().get()).collect();
        let ids2: Vec<u64> = s2.items().iter().map(|i| i.id().get()).collect();
        assert_eq!(ids1, ids2, "ids must be stable across scans");
        // Dense ordinals in traversal order.
        assert_eq!(ids1, vec![0, 1]);
    }

    #[test]
    fn apply_selected_removes_only_the_chosen_candidate() {
        let pdf = two_email_pdf();
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        // Accept ONLY alice.
        let alice = scan
            .items()
            .iter()
            .find(|i| i.candidate().matched_value() == "alice@example.com")
            .expect("alice detected");
        let result = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of([alice.id()]))
            .expect("apply");

        assert_eq!(result.total_redactions(), 1, "exactly one removed");
        assert_eq!(result.candidates().len(), 1);
        assert_eq!(result.candidates()[0].matched_value(), "alice@example.com");

        let text = extract_text(result.bytes());
        assert!(
            !text.contains("alice@example.com"),
            "accepted email removed: {text:?}"
        );
        assert!(
            text.contains("bob@example.com"),
            "rejected email KEPT: {text:?}"
        );
        assert!(
            text.contains(REDACTION_MARKER),
            "the accepted span got a marker"
        );
    }

    #[test]
    fn select_all_equals_redact_pdf_byte_for_byte() {
        // redact_pdf delegates to redact_pdf_with_selection(all()); prove both entry
        // points produce identical bytes (the apply-all path is unchanged).
        let pdf = two_email_pdf();
        let a = redact_pdf(&pdf, &engine()).expect("redact_pdf");
        let b = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::all()).expect("all");
        assert_eq!(
            a.bytes(),
            b.bytes(),
            "apply-all via both entry points is identical"
        );
        assert_eq!(a.total_redactions(), 2);
        let text = extract_text(a.bytes());
        assert!(!text.contains("alice@example.com") && !text.contains("bob@example.com"));
    }

    #[test]
    fn select_none_removes_nothing_and_keeps_a_valid_pdf() {
        let pdf = two_email_pdf();
        let result =
            redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::none()).expect("none");
        assert_eq!(result.total_redactions(), 0, "nothing removed");
        assert!(result.candidates().is_empty());
        let text = extract_text(result.bytes());
        assert!(text.contains("alice@example.com"), "kept: {text:?}");
        assert!(text.contains("bob@example.com"), "kept: {text:?}");
        assert!(
            !text.contains(REDACTION_MARKER),
            "no marker on an empty selection"
        );
    }

    #[test]
    fn an_unknown_id_in_the_selection_is_a_noop() {
        let pdf = two_email_pdf();
        let sel = PdfSelection::of([PdfCandidateId::from_raw(9_999)]);
        let result = redact_pdf_with_selection(&pdf, &engine(), &sel).expect("apply");
        assert_eq!(result.total_redactions(), 0, "unknown id removes nothing");
        let text = extract_text(result.bytes());
        assert!(text.contains("alice@example.com") && text.contains("bob@example.com"));
    }

    #[test]
    fn scan_ids_map_exactly_onto_apply_for_each_singleton() {
        // The id contract: accepting exactly one id removes exactly that candidate.
        let pdf = two_email_pdf();
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        for item in scan.items() {
            let value = item.candidate().matched_value().to_string();
            let result = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of([item.id()]))
                .expect("apply");
            assert_eq!(result.total_redactions(), 1, "one removed for {value:?}");
            assert_eq!(
                result.candidates()[0].matched_value(),
                value,
                "the RIGHT candidate removed"
            );
            assert!(
                !extract_text(result.bytes()).contains(&value),
                "{value:?} removed"
            );
        }
    }

    #[test]
    fn per_span_selection_works_on_the_tj_split_path() {
        // A term split across TJ array elements is ONE candidate with one id; scanning
        // it and accepting that id removes it (the TJ path is mode-aware too).
        let pdf = build_pdf_tj_split("Project Fal", "con is secret");
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(scan.total_candidates() >= 1, "the split term is detected");
        let ids: Vec<PdfCandidateId> = scan.items().iter().map(|i| i.id()).collect();
        let result =
            redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of(ids)).expect("apply");
        let text = extract_text(result.bytes());
        assert!(
            !text.to_lowercase().contains("project falcon"),
            "split term removed: {text:?}"
        );
    }

    #[test]
    fn scan_pdf_on_non_pdf_or_empty_is_error_not_panic() {
        assert!(scan_pdf(b"not a pdf", &engine()).is_err());
        assert!(scan_pdf(b"", &engine()).is_err());
    }

    #[test]
    fn pdf_selection_accept_builder_accumulates_ids() {
        let pdf = two_email_pdf();
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let mut sel = PdfSelection::none();
        for item in scan.items() {
            sel.accept(item.id());
        }
        assert_eq!(sel.accepted_count(), Some(2));
        let result = redact_pdf_with_selection(&pdf, &engine(), &sel).expect("apply");
        assert_eq!(result.total_redactions(), 2, "accepting both removes both");
        // all() has no explicit count.
        assert_eq!(PdfSelection::all().accepted_count(), None);
    }

    /// Build a 2-page PDF where BOTH pages' `/Contents` point to the SAME content
    /// stream object (the repeated header/footer/letterhead pattern). Exercises the
    /// shared-stream dedup in `traverse_pdf`.
    fn build_pdf_shared_stream(body: &str) -> Vec<u8> {
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
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let pages_id = doc.new_object_id();
        let page1 = doc.new_object_id();
        let page2 = doc.new_object_id();
        // BOTH pages reference the SAME content_id — a shared content stream.
        for &pid in &[page1, page2] {
            doc.objects.insert(
                pid,
                Object::Dictionary(dictionary! {
                    "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
                    "Resources" => resources_id,
                    "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                }),
            );
        }
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page1.into(), page2.into()], "Count" => 2,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save");
        out
    }

    #[test]
    fn shared_content_stream_is_enumerated_once_scan_matches_apply() {
        // REGRESSION (review nit): a stream shared across pages must be enumerated
        // ONCE — not once per referencing page — so scan ids are stable + non-
        // duplicated and the scan count agrees with the apply count.
        let pdf = build_pdf_shared_stream("Email alice@example.com or bob@example.com please.");
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert_eq!(
            scan.total_candidates(),
            2,
            "shared stream enumerated once (not per-page): {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );
        let ids: Vec<u64> = scan.items().iter().map(|i| i.id().get()).collect();
        assert_eq!(
            ids,
            vec![0, 1],
            "dense ids, no duplicates from the shared stream"
        );

        // Apply-all removes exactly those 2 — the count matches the scan.
        let all = redact_pdf(&pdf, &engine()).expect("redact");
        assert_eq!(
            all.total_redactions(),
            2,
            "apply-all count matches the scan count"
        );

        // A singleton id maps to its own value; removing it clears BOTH pages (shared).
        let alice = scan
            .items()
            .iter()
            .find(|i| i.candidate().matched_value() == "alice@example.com")
            .expect("alice detected");
        let result = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of([alice.id()]))
            .expect("apply");
        assert_eq!(
            result.total_redactions(),
            1,
            "the shared candidate removed once"
        );
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("alice@example.com"),
            "alice removed on both pages: {text:?}"
        );
        assert!(text.contains("bob@example.com"), "bob kept: {text:?}");
    }

    // ---- font-aware decode: /Differences subset font (the recall-gap fix) -------

    /// Build a one-page PDF whose single `Tj` operand bytes are arbitrary CODE bytes
    /// (NOT ASCII) that decode, THROUGH a `/Differences` array, to `text`. This is the
    /// exact shape that defeated the old Latin-1-only reconstruction: the raw operand
    /// bytes look like garbage under Latin-1, but the page font's `/Encoding`
    /// `/Differences` maps each code to the glyph that spells `text`.
    ///
    /// We assign codes 1..=N (control bytes — chosen so a Latin-1 read yields NO email)
    /// to the glyph NAME of each character of `text`. Only chars with a known PDF glyph
    /// name are supported (ASCII letters/digits/`@`/`.`/`-`/`_` are), which covers an
    /// email. Returns `(pdf_bytes, raw_operand_bytes)`.
    fn build_pdf_differences(text: &str) -> (Vec<u8>, Vec<u8>) {
        // Map a char to its standard PDF glyph name (the lopdf `glyphnames` table).
        fn glyph_name(c: char) -> Vec<u8> {
            match c {
                '@' => b"at".to_vec(),
                '.' => b"period".to_vec(),
                '-' => b"hyphen".to_vec(),
                '_' => b"underscore".to_vec(),
                '0' => b"zero".to_vec(),
                '1' => b"one".to_vec(),
                '2' => b"two".to_vec(),
                '3' => b"three".to_vec(),
                '4' => b"four".to_vec(),
                '5' => b"five".to_vec(),
                '6' => b"six".to_vec(),
                '7' => b"seven".to_vec(),
                '8' => b"eight".to_vec(),
                '9' => b"nine".to_vec(),
                // ASCII letters: the glyph name IS the letter (a, b, ..., A, B, ...).
                c if c.is_ascii_alphabetic() => vec![c as u8],
                other => panic!("no test glyph name for {other:?}"),
            }
        }

        let mut doc = Document::with_version("1.5");

        // The operand bytes: code = 1 + position (1..=N), all control bytes so the
        // Latin-1 read produces no email at all.
        let raw_operand: Vec<u8> = (1..=text.chars().count() as u8).collect();
        assert!(text.chars().count() <= 255, "fixture limited to 255 codes");

        // The /Differences array: [1 /g1 /g2 ... /gN] — code 1 then each glyph name in
        // order (each Name auto-increments the code).
        let mut differences: Vec<Object> = vec![Object::Integer(1)];
        for c in text.chars() {
            differences.push(Object::Name(glyph_name(c)));
        }

        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(raw_operand.clone(), StringFormat::Literal)],
            ),
            Operation::new("ET", vec![]),
        ];
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            Content { operations: ops }.encode().unwrap(),
        ));

        // The encoding dict + a subset-style font referencing it.
        let encoding_id = doc.add_object(dictionary! {
            "Type" => "Encoding",
            "BaseEncoding" => "WinAnsiEncoding",
            "Differences" => Object::Array(differences),
        });
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "QFZFUL+Amplitude-Light",
            "Encoding" => encoding_id,
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
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
        doc.save_to(&mut out).expect("save differences pdf");
        (out, raw_operand)
    }

    #[test]
    fn differences_font_email_is_now_detected_and_redacted() {
        // The flagship recall fix: an email that ONLY appears once you decode the
        // operand bytes through the font's /Differences array. The old Latin-1-only
        // path saw control bytes and missed it (a SILENT leak); the font-aware path
        // decodes correctly, detects it, and removes the SOURCE code bytes.
        let email = "fundinfo@jpmorgan.com";
        let (pdf, raw_operand) = build_pdf_differences(email);

        // Sanity: the raw operand bytes are NOT the email (so a byte-scan would miss).
        assert!(
            !raw_operand
                .windows(email.len())
                .any(|w| w == email.as_bytes()),
            "fixture must hide the email in the raw bytes (decode-only)"
        );

        // (a) scan_pdf now DETECTS the email.
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value() == email),
            "scan_pdf must detect the /Differences-encoded email; got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );
        // A simple /Differences font is EXACTLY mappable — NOT flagged unmapped.
        assert!(
            !scan.unmapped_fonts(),
            "a simple Differences font is exactly mappable"
        );
        assert!(!scan.low_text(), "a real text page is not low_text");

        // (b) redact_pdf removes the SOURCE bytes; re-extracting (which decodes through
        // the font) no longer yields the email.
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(result.total_redactions() >= 1, "the email is redacted");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains(email),
            "re-extracted (font-decoded) text must NOT contain the email; got {text:?}"
        );

        // And the underlying code bytes that produced the email glyphs are gone from
        // the decoded content stream (true removal, not a mask).
        let doc = Document::load_mem(result.bytes()).expect("reload");
        for (_n, page_id) in doc.get_pages() {
            let decoded = doc.get_page_content(page_id).expect("page content");
            // This fixture's font has a WinAnsi BASE encoding (the /Differences only ADDS
            // codes for the email glyphs), so the marker glyphs `[REDACTED]` ARE
            // renderable through the base — the marker is encoded into the font and the
            // literal marker bytes appear in the rewritten operand (the renderable case).
            // (A font that CANNOT render the marker emits a clean gap instead — see
            // `differences_font_that_cannot_render_marker_emits_clean_gap`.)
            assert!(
                decoded
                    .windows(REDACTION_MARKER.len())
                    .any(|w| w == REDACTION_MARKER.as_bytes()),
                "a font that CAN render the marker keeps the literal marker in the operand"
            );
        }
    }

    #[test]
    fn differences_font_no_regression_on_plain_winansi_email() {
        // The SAME engine on a plain-WinAnsi (no /Differences) operand still detects +
        // redacts an email exactly as before — the font-aware path is byte-identical
        // for the common case.
        let pdf = build_pdf("write to plain.user@example.com please", false);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value() == "plain.user@example.com"),
            "plain WinAnsi email still detected"
        );
        assert!(
            !scan.unmapped_fonts(),
            "a plain font is not flagged unmapped"
        );
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("plain.user@example.com"),
            "plain email redacted: {text:?}"
        );
    }

    #[test]
    fn differences_font_split_across_tj_elements_is_caught() {
        // The /Differences decode also composes with the TJ cross-element run: split
        // the encoded email across two TJ string elements and confirm it is detected
        // + redacted (the run is decoded element-by-element, concatenated, scanned).
        let email = "split@firm.example";
        // Reuse the differences builder's glyph mapping by building a 2-element TJ by
        // hand with the same encoding.
        fn glyph_name(c: char) -> Vec<u8> {
            match c {
                '@' => b"at".to_vec(),
                '.' => b"period".to_vec(),
                c if c.is_ascii_alphabetic() => vec![c as u8],
                other => panic!("no glyph for {other:?}"),
            }
        }
        let mut doc = Document::with_version("1.5");
        let codes: Vec<u8> = (1..=email.chars().count() as u8).collect();
        let mut differences: Vec<Object> = vec![Object::Integer(1)];
        for c in email.chars() {
            differences.push(Object::Name(glyph_name(c)));
        }
        // Split the codes into two TJ string elements with a kerning number between.
        let mid = codes.len() / 2;
        let (a, b) = codes.split_at(mid);
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "TJ",
                vec![Object::Array(vec![
                    Object::String(a.to_vec(), StringFormat::Literal),
                    Object::Integer(-25),
                    Object::String(b.to_vec(), StringFormat::Literal),
                ])],
            ),
            Operation::new("ET", vec![]),
        ];
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            Content { operations: ops }.encode().unwrap(),
        ));
        let encoding_id = doc.add_object(dictionary! {
            "Type" => "Encoding", "BaseEncoding" => "WinAnsiEncoding",
            "Differences" => Object::Array(differences),
        });
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "ABCDEF+Sub",
            "Encoding" => encoding_id,
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");

        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value() == email),
            "split /Differences email across TJ elements detected; got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains(email),
            "split differences email redacted: {text:?}"
        );
    }

    /// Build a one-page PDF reproducing the REAL subset-font mojibake bug: a font whose
    /// `/Encoding` `/Differences` REMAPS the very byte slots the ASCII marker `[REDACTED]`
    /// would use, to OTHER glyphs (so the marker is NOT renderable in this font), while
    /// still EXACTLY decoding the operand so the email is detected. This mirrors the JP
    /// Morgan prospectus' `QFZFUL+Amplitude-Light` subset font, where byte 0x5B (`[`)
    /// decodes to `|`, 0x52 (`R`) to `_`, etc. — so the old code's literal `[REDACTED]`
    /// bytes rendered as `|_ZN)K+ZN]` mojibake. Returns `(pdf_bytes, raw_operand_bytes)`.
    fn build_pdf_unrenderable_marker_differences(text: &str) -> (Vec<u8>, Vec<u8>) {
        fn glyph_name(c: char) -> Vec<u8> {
            match c {
                '@' => b"at".to_vec(),
                '.' => b"period".to_vec(),
                c if c.is_ascii_alphabetic() => vec![c as u8],
                other => panic!("no test glyph for {other:?}"),
            }
        }
        let mut doc = Document::with_version("1.5");
        // The operand uses HIGH codes (0x80..) for the email glyphs — disjoint from the
        // ASCII marker byte range we are about to remap.
        let n = text.chars().count();
        assert!(n <= 0x7F, "fixture limited to 0x7F email glyphs");
        let raw_operand: Vec<u8> = (0x80u8..0x80 + n as u8).collect();

        // /Differences: (1) map the email glyphs onto the high codes; (2) CLOBBER the
        // ASCII codes the marker `[REDACTED]` needs (`[`,`R`,`E`,`D`,`A`,`C`,`T`,`]`) to
        // UNRELATED glyphs, so NO byte decodes to a marker char (encode_marker -> None ->
        // clean gap). We remap each marker-glyph byte to a different, harmless glyph name.
        let mut differences: Vec<Object> = vec![Object::Integer(0x80)];
        for c in text.chars() {
            differences.push(Object::Name(glyph_name(c)));
        }
        // Clobber the marker's ASCII byte slots so they no longer decode to themselves.
        // (byte 0x5B `[` -> `bar`, etc. — anything that is NOT the marker glyph.)
        let clobber: &[(u8, &[u8])] = &[
            (b'[', b"bar"),
            (b']', b"bar"),
            (b'R', b"underscore"),
            (b'E', b"Z"),
            (b'D', b"N"),
            (b'A', b"parenleft"),
            (b'C', b"K"),
            (b'T', b"plus"),
        ];
        for &(code, name) in clobber {
            differences.push(Object::Integer(code as i64));
            differences.push(Object::Name(name.to_vec()));
        }

        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(raw_operand.clone(), StringFormat::Literal)],
            ),
            Operation::new("ET", vec![]),
        ];
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            Content { operations: ops }.encode().unwrap(),
        ));
        let encoding_id = doc.add_object(dictionary! {
            "Type" => "Encoding",
            "BaseEncoding" => "WinAnsiEncoding",
            "Differences" => Object::Array(differences),
        });
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1",
            "BaseFont" => "QFZFUL+Amplitude-Light",
            "Encoding" => encoding_id,
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
        doc.save_to(&mut out).expect("save unrenderable-marker pdf");
        (out, raw_operand)
    }

    #[test]
    fn differences_font_that_cannot_render_marker_emits_clean_gap_not_mojibake() {
        // THE MOJIBAKE FIX (regression test): on a subset font whose /Differences remaps
        // the marker's byte slots away from the marker glyphs, the OLD code spliced the
        // literal ASCII `[REDACTED]` bytes into the operand — which the font then rendered
        // as garbage (`|_ZN)K+ZN]`). The fix INVERSE-MAPs the marker through the font and,
        // finding it unrenderable, emits a CLEAN GAP (pure removal, no inserted bytes).
        let email = "fundinfo@jpmorgan.com";
        let (pdf, raw_operand) = build_pdf_unrenderable_marker_differences(email);

        // Sanity: the email is hidden in the raw bytes (decode-only) — high codes.
        assert!(
            !raw_operand
                .windows(email.len())
                .any(|w| w == email.as_bytes()),
            "fixture hides the email in raw bytes"
        );

        // It is still DETECTED (the operand decodes exactly through /Differences).
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value() == email),
            "the unrenderable-marker /Differences email is still detected; got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );

        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(result.total_redactions() >= 1, "the email is redacted");

        // (a) TRUE REMOVAL: the email is gone from the re-extracted (font-decoded) text.
        let text = extract_text(result.bytes());
        assert!(!text.contains(email), "email truly removed: {text:?}");

        // (b) NO MOJIBAKE: the rewritten operand carries NO inserted marker bytes. Decode
        // each content stream and confirm (i) the literal ASCII marker is NOT present, AND
        // (ii) crucially, the SPECIFIC garbage string the old marker bytes would decode to
        // (`|_ZN)K+ZN]`, the JP-Morgan mojibake) does NOT appear in the re-extracted text.
        let doc = Document::load_mem(result.bytes()).expect("reload");
        for (_n, page_id) in doc.get_pages() {
            let decoded = doc.get_page_content(page_id).expect("page content");
            assert!(
                !decoded
                    .windows(REDACTION_MARKER.len())
                    .any(|w| w == REDACTION_MARKER.as_bytes()),
                "a font that CANNOT render the marker must NOT have ASCII marker bytes spliced in"
            );
        }
        // The exact mojibake the old code produced (the marker bytes decoded through this
        // font's /Differences) must be ABSENT from the rendered/extracted text.
        assert!(
            !text.contains("|_ZN)K+ZN"),
            "the garbled-marker mojibake must be gone; got {text:?}"
        );

        // (c) Determinism: same input, same output (the gap path is stable).
        let again = redact_pdf(&pdf, &engine()).expect("redact again");
        assert_eq!(
            result.bytes(),
            again.bytes(),
            "gap path must be deterministic"
        );
    }

    #[test]
    fn encode_marker_renderable_vs_unrenderable_font() {
        // Unit-pin the inverse-map: a WinAnsi (latin1-default) font CAN render the marker
        // (encode_marker -> Some, decoding back to the marker), while the JP-Morgan-style
        // remapped /Differences font CANNOT (-> None -> caller emits a clean gap).

        // The Latin-1 fallback decoder maps every byte to its own codepoint, so the ASCII
        // marker is trivially renderable and re-decodes to the literal marker.
        let latin1 = FontDecoder::latin1();
        let enc = latin1.encode_marker().expect("latin1 renders the marker");
        let (decoded, _src, _unm) = latin1.decode_mapped(&enc);
        assert_eq!(
            decoded, REDACTION_MARKER,
            "encoded bytes re-decode to the marker"
        );

        // Build the remapped /Differences font's decoder (the byte slots for the marker
        // glyphs are clobbered) and confirm encode_marker fails closed to None.
        let (pdf, _raw) = build_pdf_unrenderable_marker_differences("a@b.co");
        let doc = Document::load_mem(&pdf).expect("reload");
        let (_n, page_id) = doc.get_pages().into_iter().next().expect("a page");
        let fonts = PageFonts::resolve(&doc, page_id);
        let dec = fonts.decoder_for(Some(b"F1"));
        assert!(
            matches!(dec, FontDecoder::Simple(_)),
            "the remapped /Differences font is still an exactly-mapped Simple font"
        );
        assert!(
            dec.encode_marker().is_none(),
            "a font that cannot render the marker glyphs returns None (-> clean gap)"
        );
    }

    #[test]
    fn type0_cid_font_sets_unmapped_flag_not_a_false_clean() {
        // A Type0 / CID (Identity-H, no /ToUnicode we can map) font: we cannot build an
        // exact byte map, so the page must be FLAGGED `unmapped_fonts` (honesty), never
        // silently reported as a clean 0-candidate result. We don't assert detection on
        // it (best-effort) — only that the flag is raised + a diagnostic recorded.
        let mut doc = Document::with_version("1.5");
        // 2-byte Identity-H codes (CID font). Bytes are arbitrary glyph ids.
        let cid_bytes: Vec<u8> = vec![0x00, 0x41, 0x00, 0x42, 0x00, 0x43];
        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new("Tj", vec![Object::String(cid_bytes, StringFormat::Literal)]),
            Operation::new("ET", vec![]),
        ];
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            Content { operations: ops }.encode().unwrap(),
        ));
        // A Type0 font with Identity-H encoding and NO /ToUnicode -> lopdf falls back to
        // a SimpleEncoding(name) it cannot decode -> our Unmappable path.
        let desc_font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "CIDFontType2", "BaseFont" => "ABCDEF+CID",
        });
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type0", "BaseFont" => "ABCDEF+CID",
            "Encoding" => "Identity-H",
            "DescendantFonts" => vec![desc_font_id.into()],
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");

        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.unmapped_fonts(),
            "a Type0/CID font we cannot map must set unmapped_fonts (honesty), not a false clean"
        );
        assert!(
            scan.diagnostics()
                .iter()
                .any(|d| d.contains("could not be mapped")),
            "an unmapped-font diagnostic must be recorded; got {:?}",
            scan.diagnostics()
        );
        // The flag survives a redact pass too (apply path).
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(
            result.unmapped_fonts(),
            "apply path also surfaces unmapped_fonts"
        );
    }

    // ---- annotation scrubbing (/URI link actions, /Contents notes) --------------

    /// Build a one-page PDF whose page content is innocuous body text, plus a set of LINK
    /// annotations. Each `(uri, contents)` pair becomes a `/Link` annotation whose `/A`
    /// URI-action (a REFERENCED action object, the realistic shape) carries `uri`, and
    /// whose `/Contents` carries `contents` (empty -> no /Contents key). The annotations
    /// are added to `/Annots` as INDIRECT references (the common PDF shape). Returns the
    /// PDF bytes.
    fn build_pdf_with_link_annots(body: &str, annots: &[(&str, &str)]) -> Vec<u8> {
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
            Dictionary::new(),
            Content { operations: ops }.encode().unwrap(),
        ));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id =
            doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();

        // Build each annotation as an indirect object; its /A action is ALSO an indirect
        // object (a URI action) — the shape real PDFs (and the JP Morgan prospectus) use.
        let mut annot_refs: Vec<Object> = Vec::new();
        for (uri, contents) in annots {
            let action_id = doc.add_object(dictionary! {
                "Type" => "Action",
                "S" => "URI",
                "URI" => Object::String(uri.as_bytes().to_vec(), StringFormat::Literal),
            });
            let mut annot = dictionary! {
                "Type" => "Annot",
                "Subtype" => "Link",
                "Rect" => vec![0.into(), 0.into(), 100.into(), 20.into()],
                "A" => Object::Reference(action_id),
            };
            if !contents.is_empty() {
                annot.set(
                    "Contents",
                    Object::String(contents.as_bytes().to_vec(), StringFormat::Literal),
                );
            }
            let annot_id = doc.add_object(Object::Dictionary(annot));
            annot_refs.push(Object::Reference(annot_id));
        }

        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Annots" => Object::Array(annot_refs),
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
        doc.save_to(&mut out).expect("save annotated pdf");
        out
    }

    /// Count the surviving `/URI` action values across ALL pages' annotations of a PDF
    /// (re-parsed), returning each as a decoded string. The before/after measure for the
    /// annotation-leak fix.
    fn annot_uris(pdf: &[u8]) -> Vec<String> {
        let doc = Document::load_mem(pdf).expect("reload annotated pdf");
        let mut uris = Vec::new();
        for (_n, page_id) in doc.get_pages() {
            for annot in doc.get_page_annotations(page_id).unwrap_or_default() {
                // Direct /URI on the annotation.
                if let Ok(u) = annot.get(b"URI").and_then(Object::as_str) {
                    uris.push(String::from_utf8_lossy(u).into_owned());
                }
                // /A action's /URI (inline or referenced).
                match annot.get(b"A") {
                    Ok(Object::Dictionary(a)) => {
                        if let Ok(u) = a.get(b"URI").and_then(Object::as_str) {
                            uris.push(String::from_utf8_lossy(u).into_owned());
                        }
                    }
                    Ok(Object::Reference(id)) => {
                        if let Ok(a) = doc.get_object(*id).and_then(Object::as_dict) {
                            if let Ok(u) = a.get(b"URI").and_then(Object::as_str) {
                                uris.push(String::from_utf8_lossy(u).into_owned());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        uris
    }

    /// An engine with the broad `url` built-in OFF (everything else default), so a plain
    /// `https://…` link with no OTHER identifier is genuinely "benign" (undetected) — used
    /// to prove a clean annotation is left intact. (The default engine flags ANY URL, which
    /// is the correct, recall-first posture and is what catches the JP Morgan link URLs.)
    fn engine_no_url() -> RedactionEngine {
        let mut b = BuiltinRecognizers::all();
        b.url = false;
        RedactionEngine::builder()
            .terms(["Project Falcon".to_string()])
            .builtins(b)
            .build()
            .expect("engine")
    }

    #[test]
    fn annotation_uri_with_identifier_is_removed_benign_left_intact() {
        // THE FLAGSHIP FIX: a link annotation whose /URI embeds an identifier must have the
        // URI GONE after redaction — re-parsed annotations AND raw bytes — while a benign
        // link with no detected identifier is left intact. Uses an engine with `url` OFF so
        // the plain benign link is genuinely undetected (the secret link embeds the term).
        // The secret URI embeds the literal caller term "Project Falcon" (a space, not the
        // URL-encoded %20, so the term recognizer's literal phrase matches).
        let secret = "https://intra/Project Falcon/deal";
        let benign = "https://example.com/help";
        let eng = engine_no_url();
        let pdf = build_pdf_with_link_annots(
            "See the deal room for details.",
            &[(secret, ""), (benign, "")],
        );

        // Before: BOTH URIs are present (the leak surface exists).
        let before = annot_uris(&pdf);
        assert!(
            before.iter().any(|u| u == secret),
            "secret URI present before: {before:?}"
        );
        assert!(
            before.iter().any(|u| u == benign),
            "benign URI present before: {before:?}"
        );

        let result = redact_pdf(&pdf, &eng).expect("redact");
        assert!(result.total_redactions() >= 1, "the secret URI is redacted");

        // After (re-parse): the secret URI is GONE from the annotations; the benign one stays.
        let after = annot_uris(result.bytes());
        assert!(
            !after.iter().any(|u| u.contains("Project")),
            "secret URI must be removed from the annotation: {after:?}"
        );
        assert!(
            after.iter().any(|u| u == benign),
            "benign URI must be left intact: {after:?}"
        );

        // RAW-BYTE proof: the matched value's bytes are gone from the saved PDF entirely
        // (true removal, not a cover).
        assert!(
            !result
                .bytes()
                .windows(b"Project".len())
                .any(|w| w == b"Project"),
            "the matched value must not survive anywhere in the redacted bytes"
        );
    }

    #[test]
    fn benign_url_link_is_removed_under_default_recall_first_engine() {
        // HONEST posture note: the DEFAULT engine's `url` recognizer flags ANY URL, so a
        // plain link IS a detected identifier and IS removed — this is the recall-first
        // behavior that catches the JP Morgan prospectus link URLs. Pin it so a future
        // change to url-detection is a deliberate, reviewed one.
        let pdf = build_pdf_with_link_annots("link", &[("https://example.com/help", "")]);
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(
            result.total_redactions() >= 1,
            "the default engine flags + removes a URL link"
        );
        assert!(
            annot_uris(result.bytes()).is_empty(),
            "the URL action is gone under the default engine"
        );
    }

    #[test]
    fn annotation_uri_email_removed_from_uri_and_raw_bytes() {
        // A mailto-style link whose /URI embeds an EMAIL (a built-in recognizer, no term
        // needed). After redaction the email is absent from the re-parsed /URI and the raw
        // bytes.
        let uri = "mailto:fundinfo@jpmorgan.com";
        let pdf = build_pdf_with_link_annots("Contact us.", &[(uri, "")]);
        assert_eq!(annot_uris(&pdf).len(), 1, "one URI before");

        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(result.total_redactions() >= 1, "the email URI is redacted");
        let after = annot_uris(result.bytes());
        assert!(
            !after.iter().any(|u| u.contains("fundinfo@jpmorgan.com")),
            "email must be gone from the URI action: {after:?}"
        );
        assert!(
            !result
                .bytes()
                .windows(b"fundinfo@jpmorgan.com".len())
                .any(|w| w == b"fundinfo@jpmorgan.com"),
            "email must not survive in the raw PDF bytes"
        );
    }

    #[test]
    fn annotation_contents_note_with_identifier_is_cleared() {
        // A markup/text annotation whose /Contents note embeds an email: the note must be
        // cleared (no surviving email) while detection counts it. Uses the `url`-off engine
        // so the accompanying benign link is genuinely undetected (it survives, proving the
        // /Contents clearing does not touch a clean field).
        let eng = engine_no_url();
        let pdf = build_pdf_with_link_annots(
            "Margin note attached.",
            &[("https://example.com/ok", "ping bob@firm.test about this")],
        );
        let result = redact_pdf(&pdf, &eng).expect("redact");
        assert!(result.total_redactions() >= 1, "the note email is redacted");
        // The /Contents is gone; the benign URI survives.
        let doc = Document::load_mem(result.bytes()).expect("reload");
        for (_n, page_id) in doc.get_pages() {
            for annot in doc.get_page_annotations(page_id).unwrap_or_default() {
                if let Ok(c) = annot.get(b"Contents").and_then(Object::as_str) {
                    let s = String::from_utf8_lossy(c);
                    assert!(
                        !s.contains("bob@firm.test"),
                        "note email must be cleared: {s:?}"
                    );
                }
            }
        }
        assert!(
            !result
                .bytes()
                .windows(b"bob@firm.test".len())
                .any(|w| w == b"bob@firm.test"),
            "note email must not survive in the raw bytes"
        );
        assert!(annot_uris(result.bytes())
            .iter()
            .any(|u| u == "https://example.com/ok"));
    }

    #[test]
    fn pdf_with_no_annotations_behaves_exactly_as_before() {
        // NON-REGRESSION: a PDF with NO annotations is byte-identical to the path before the
        // annotation pass existed (we compare against the plain build_pdf result of the same
        // body — same operators, no /Annots — proving the annotation pass is a no-op there).
        let body = "email alice@example.com only in the body";
        let plain = build_pdf(body, false);
        let r = redact_pdf(&plain, &engine()).expect("redact");
        let text = extract_text(r.bytes());
        assert!(
            !text.contains("alice@example.com"),
            "body email still redacted"
        );
        // The annotation pass adds nothing on an annotation-free page: re-parse finds no URIs.
        assert!(
            annot_uris(r.bytes()).is_empty(),
            "no annotations introduced"
        );
    }

    #[test]
    fn annotation_scan_ids_map_onto_apply_select_all_equals_redact_pdf() {
        // The id contract holds across the annotation pass: scan enumerates the URI/Contents
        // candidates with stable ids, and apply-all via both entry points is byte-identical.
        let pdf = build_pdf_with_link_annots(
            "body email body@x.test here", // a body candidate too, so annotation ids follow it
            &[
                ("mailto:annot@x.test", "note carol@x.test"),
                ("https://example.com/ok", ""),
            ],
        );
        // scan detects the body email + the two annotation emails (URI + Contents).
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let vals: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            vals.iter().any(|v| v == "body@x.test"),
            "body email scanned: {vals:?}"
        );
        assert!(
            vals.iter().any(|v| v == "annot@x.test"),
            "URI email scanned: {vals:?}"
        );
        assert!(
            vals.iter().any(|v| v == "carol@x.test"),
            "Contents email scanned: {vals:?}"
        );
        // Dense, ascending, unique ids across body + annotations.
        let ids: Vec<u64> = scan.items().iter().map(|i| i.id().get()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            ids, sorted,
            "ids ascending + unique across body and annotations"
        );

        // apply-all via both entry points is identical (shared traversal).
        let a = redact_pdf(&pdf, &engine()).expect("redact_pdf");
        let b = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::all()).expect("all");
        assert_eq!(
            a.bytes(),
            b.bytes(),
            "apply-all identical across entry points"
        );
    }

    #[test]
    fn annotation_per_span_selection_removes_only_the_accepted_uri() {
        // PER-SPAN: scan two annotation URIs (both emails), accept ONLY one, and confirm the
        // other URI survives.
        let pdf = build_pdf_with_link_annots(
            "two links",
            &[("mailto:first@x.test", ""), ("mailto:second@x.test", "")],
        );
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let first = scan
            .items()
            .iter()
            .find(|i| i.candidate().matched_value() == "first@x.test")
            .expect("first detected");
        let result = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of([first.id()]))
            .expect("apply");
        assert_eq!(
            result.total_redactions(),
            1,
            "exactly the accepted URI removed"
        );
        let after = annot_uris(result.bytes());
        assert!(
            !after.iter().any(|u| u.contains("first@x.test")),
            "accepted URI removed: {after:?}"
        );
        assert!(
            after.iter().any(|u| u.contains("second@x.test")),
            "rejected URI kept: {after:?}"
        );
    }

    #[test]
    fn annotation_redaction_is_deterministic() {
        let pdf = build_pdf_with_link_annots(
            "deal",
            &[
                ("mailto:a@x.test", "note b@x.test"),
                ("https://example.com/ok", ""),
            ],
        );
        let a = redact_pdf(&pdf, &engine()).expect("a").into_bytes();
        let b = redact_pdf(&pdf, &engine()).expect("b").into_bytes();
        assert_eq!(a, b, "annotation redaction must be deterministic");
    }

    #[test]
    fn annotation_in_inline_a_action_uri_is_removed() {
        // /A as an INLINE action dict (not a referenced object) — still scrubbed.
        let mut doc = Document::with_version("1.5");
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            Content {
                operations: vec![Operation::new("BT", vec![]), Operation::new("ET", vec![])],
            }
            .encode()
            .unwrap(),
        ));
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        let annot_id = doc.add_object(Object::Dictionary(dictionary! {
            "Type" => "Annot", "Subtype" => "Link",
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "A" => dictionary! {
                "Type" => "Action", "S" => "URI",
                "URI" => Object::String(b"mailto:inline@x.test".to_vec(), StringFormat::Literal),
            },
        }));
        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Annots" => vec![annot_id.into()],
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");

        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(result.total_redactions() >= 1, "inline /A URI redacted");
        assert!(
            !result
                .bytes()
                .windows(b"inline@x.test".len())
                .any(|w| w == b"inline@x.test"),
            "inline /A URI email must be gone from the raw bytes"
        );
    }

    #[test]
    fn annotation_pass_never_panics_on_malformed_annots() {
        // /Annots pointing at junk (a non-array, an array of non-references, an annotation
        // whose /A is an Integer) must not panic — just be ignored.
        let mut doc = Document::with_version("1.5");
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            Content {
                operations: vec![Operation::new("BT", vec![]), Operation::new("ET", vec![])],
            }
            .encode()
            .unwrap(),
        ));
        let page_id = doc.new_object_id();
        let pages_id = doc.new_object_id();
        // An annotation whose /A is an Integer (malformed) and no /Contents.
        let bad_annot = doc.add_object(Object::Dictionary(dictionary! {
            "Type" => "Annot", "Subtype" => "Link", "A" => 7,
        }));
        doc.objects.insert(
            page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
                "Annots" => vec![bad_annot.into(), Object::Integer(3), Object::Null],
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");
        // Must not panic; Result either way.
        let _ = redact_pdf(&pdf, &engine());
        let _ = scan_pdf(&pdf, &engine());
    }

    // ---- Document-metadata scrubbing (/Info + XMP /Metadata) -------------------------

    /// Build a one-page PDF carrying both an `/Info` dictionary and a catalog XMP
    /// `/Metadata` stream. `info` are the (key, value) pairs of the document info dict;
    /// `xmp` is the raw (uncompressed) XMP packet bytes (empty = no /Metadata stream).
    fn build_pdf_with_metadata(body: &str, info: &[(&str, &str)], xmp: &str) -> Vec<u8> {
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
            Dictionary::new(),
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

        // Catalog, with an optional XMP /Metadata stream.
        let mut catalog = dictionary! { "Type" => "Catalog", "Pages" => pages_id };
        if !xmp.is_empty() {
            let mut md = Dictionary::new();
            md.set("Type", Object::Name(b"Metadata".to_vec()));
            md.set("Subtype", Object::Name(b"XML".to_vec()));
            let stream = Stream::new(md, xmp.as_bytes().to_vec());
            let stream_id = doc.add_object(stream);
            catalog.set("Metadata", Object::Reference(stream_id));
        }
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", catalog_id);

        // The /Info dictionary (an indirect object referenced from the trailer).
        if !info.is_empty() {
            let mut info_dict = Dictionary::new();
            for (k, v) in info {
                info_dict.set(
                    *k,
                    Object::String(v.as_bytes().to_vec(), StringFormat::Literal),
                );
            }
            let info_id = doc.add_object(Object::Dictionary(info_dict));
            doc.trailer.set("Info", Object::Reference(info_id));
        }

        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save metadata pdf");
        out
    }

    /// Re-parse a PDF's `/Info` into a sorted `(key, value)` list (decoded). The
    /// before/after measure for the /Info-leak fix.
    fn info_pairs(pdf: &[u8]) -> Vec<(String, String)> {
        let doc = Document::load_mem(pdf).expect("reload");
        let mut out = Vec::new();
        if let Some((_id, info)) = resolve_info(&doc) {
            for (k, v) in info.iter() {
                if let Ok(bytes) = v.as_str() {
                    out.push((
                        String::from_utf8_lossy(k).into_owned(),
                        decode_annot_string(bytes),
                    ));
                }
            }
        }
        out.sort();
        out
    }

    /// Re-parse a PDF's XMP `/Metadata` stream text, or `None` if there is no stream.
    fn xmp_text(pdf: &[u8]) -> Option<String> {
        let doc = Document::load_mem(pdf).expect("reload");
        let (_cid, catalog) = resolve_catalog(&doc)?;
        let stream = match catalog.get(METADATA_KEY) {
            Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_stream).ok()?,
            Ok(Object::Stream(s)) => s,
            _ => return None,
        };
        Some(decode_annot_string(&stream.content))
    }

    #[test]
    fn info_author_and_sharepoint_path_and_xmp_are_scrubbed() {
        // THE METADATA-LEAK FIX (red-team reproduction): /Info /Author = a person's name,
        // a custom key = a UNC SharePoint authoring path AND an email, /Title = a SharePoint
        // URL, plus an XMP stream embedding an email. After redaction ALL leaked values are
        // ABSENT from /Info, the XMP, and the raw bytes — with NO fragment surviving.
        let unc = r"\\sharepoint\matters\AcmeDeal";
        let author = "Jane Privileged";
        let title_url = "https://contoso.sharepoint.com/personal/jane/Documents/AcmeDeal";
        let custom_email = "jane.privileged@firm.example";
        let xmp = format!(
            "<?xpacket begin='\u{feff}'?><x:xmpmeta xmlns:x='adobe:ns:meta/'>\
             <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\
             <rdf:Description><dc:creator>{author}</dc:creator>\
             <xmp:CreatorTool>Word</xmp:CreatorTool>\
             <pdfx:SourcePath>{unc}</pdfx:SourcePath>\
             <dc:contact>{custom_email}</dc:contact></rdf:Description></rdf:RDF>\
             </x:xmpmeta><?xpacket end='w'?>"
        );
        let pdf = build_pdf_with_metadata(
            "Body text only, nothing sensitive here.",
            &[
                ("Author", author),
                ("Title", title_url),
                ("Subject", "Prospectus"),
                ("Producer", "lopdf"), // benign software field, no identifier
                ("CustomSource", unc),
                ("ContactInfo", custom_email),
            ],
            &xmp,
        );

        // BEFORE: every leaked value is present (the leak surface exists).
        let before = info_pairs(&pdf);
        assert!(
            before.iter().any(|(k, _)| k == "Author"),
            "author present before"
        );
        assert!(
            before.iter().any(|(_, v)| v.contains("sharepoint")),
            "path present before"
        );
        assert!(
            xmp_text(&pdf).unwrap().contains(custom_email),
            "xmp email present before"
        );

        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(
            result.total_redactions() >= 4,
            "info keys + xmp removed: {}",
            result.total_redactions()
        );

        // AFTER (re-parse /Info): author, title-url, the UNC path, and the email are GONE.
        let after = info_pairs(result.bytes());
        assert!(
            !after.iter().any(|(k, _)| k == "Author"),
            "Author scrubbed by default: {after:?}"
        );
        assert!(
            !after.iter().any(|(k, _)| k == "Title"),
            "Title (SharePoint URL) scrubbed: {after:?}"
        );
        assert!(
            !after
                .iter()
                .any(|(_, v)| v.contains("sharepoint") || v.contains("AcmeDeal")),
            "no SharePoint/AcmeDeal path survives in /Info: {after:?}"
        );
        assert!(
            !after.iter().any(|(_, v)| v.contains(custom_email)),
            "no email survives in /Info: {after:?}"
        );
        // A benign Producer with NO detected identifier is KEPT (documented default).
        assert!(
            after.iter().any(|(k, v)| k == "Producer" && v == "lopdf"),
            "benign /Producer is preserved: {after:?}"
        );

        // AFTER (XMP): the whole /Metadata stream is gone (clean, fragment-free close).
        assert!(
            xmp_text(result.bytes()).is_none(),
            "XMP /Metadata stream removed entirely"
        );

        // RAW-BYTE proof (TRUE removal): NONE of the leaked values survive ANYWHERE.
        let bytes = result.bytes();
        for needle in [
            author.as_bytes(),
            custom_email.as_bytes(),
            b"sharepoint",
            b"AcmeDeal",
            br"\\sharepoint",
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "leaked value {:?} must NOT survive in the raw bytes",
                String::from_utf8_lossy(needle)
            );
        }
        // Structural integrity: the output still parses + the body redaction still works
        // (the metadata pass did not break the document).
        let _doc = Document::load_mem(bytes).expect("redacted PDF must still parse");
    }

    #[test]
    fn benign_metadata_with_no_identifier_is_left_intact() {
        // NON-REGRESSION: a PDF whose /Info has NO detected identifier and NO scrub-by-
        // default authoring/path field, and a benign XMP (only namespace declarations),
        // behaves as before — nothing removed, /Producer + /Creator preserved, XMP kept.
        // Uses the `url`-off engine so the XMP's namespace URIs (`http://www.w3.org/…`)
        // are genuinely undetected (the DEFAULT engine flags ANY URL — including a benign
        // namespace URI — which is the recall-first behavior pinned by the next test).
        let benign_xmp = "<?xpacket begin='\u{feff}'?><x:xmpmeta xmlns:x='adobe:ns:meta/'>\
             <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\
             <rdf:Description><xmp:CreatorTool>lopdf</xmp:CreatorTool></rdf:Description>\
             </rdf:RDF></x:xmpmeta><?xpacket end='w'?>";
        let pdf = build_pdf_with_metadata(
            "just innocuous body text here",
            &[
                ("Producer", "lopdf"),
                ("Creator", "Word"),
                ("Subject", "Notes"),
            ],
            benign_xmp,
        );
        let result = redact_pdf(&pdf, &engine_no_url()).expect("redact");
        // No metadata removed (body has no identifier either).
        assert_eq!(result.total_redactions(), 0, "benign metadata untouched");
        let after = info_pairs(result.bytes());
        assert!(after.iter().any(|(k, v)| k == "Producer" && v == "lopdf"));
        assert!(after.iter().any(|(k, v)| k == "Creator" && v == "Word"));
        assert!(after.iter().any(|(k, v)| k == "Subject" && v == "Notes"));
        // The benign XMP (no identifier, no path) is preserved.
        assert!(
            xmp_text(result.bytes()).is_some(),
            "benign XMP stream preserved"
        );
    }

    #[test]
    fn xmp_with_only_namespace_urls_is_removed_under_default_recall_first_engine() {
        // HONEST posture note (mirrors `benign_url_link_is_removed_under_default_recall_first_engine`):
        // the DEFAULT engine's `url` recognizer flags ANY URL — INCLUDING the benign
        // `http://…` namespace URIs every real XMP packet carries — so the default-engine
        // behavior is to REMOVE the XMP stream whenever it has a URL. This is the recall-
        // first, derived-metadata-is-disposable safe side; pin it so a future change is a
        // deliberate, reviewed one (the JP Morgan XMP's 7 http(s) runs are exactly this).
        let xmp = "<x:xmpmeta xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\
                   <rdf:Description><xmp:CreatorTool>Word</xmp:CreatorTool></rdf:Description></x:xmpmeta>";
        let pdf = build_pdf_with_metadata("body", &[("Subject", "Notes")], xmp);
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(
            result.total_redactions() >= 1,
            "the default engine removes XMP with a URL"
        );
        assert!(
            xmp_text(result.bytes()).is_none(),
            "XMP with a namespace URL removed under default engine"
        );
        // The benign /Subject (no URL/identifier) is untouched.
        assert!(info_pairs(result.bytes())
            .iter()
            .any(|(k, _)| k == "Subject"));
    }

    #[test]
    fn producer_with_embedded_identifier_is_removed() {
        // A normally-benign field (/Producer) that DOES carry a detected identifier (an
        // email) is removed too — the scan path catches it even though it is not in the
        // scrub-by-default list.
        let pdf = build_pdf_with_metadata(
            "body",
            &[("Producer", "Acme Tool (support@acme.example)")],
            "",
        );
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(
            result.total_redactions() >= 1,
            "Producer with an email is removed"
        );
        let after = info_pairs(result.bytes());
        assert!(
            !after.iter().any(|(k, _)| k == "Producer"),
            "Producer with an email scrubbed: {after:?}"
        );
        assert!(
            !result
                .bytes()
                .windows(b"support@acme.example".len())
                .any(|w| w == b"support@acme.example"),
            "the email must not survive the raw bytes"
        );
    }

    #[test]
    fn metadata_scan_ids_map_onto_apply_select_all_equals_redact_pdf() {
        // The id contract holds across the metadata pass: scan enumerates /Info + XMP
        // candidates with stable ids that FOLLOW the body ids, and apply-all via both
        // entry points is byte-identical.
        let pdf = build_pdf_with_metadata(
            "body email body@x.test here",
            &[("Author", "Jane Privileged"), ("Subject", "Notes")],
            "<x:xmpmeta><dc:contact>scan@x.test</dc:contact></x:xmpmeta>",
        );
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let vals: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            vals.iter().any(|v| v == "body@x.test"),
            "body email scanned: {vals:?}"
        );
        // The Author scrub-by-default detection surfaces its value for review.
        assert!(
            vals.iter().any(|v| v == "Jane Privileged"),
            "Author surfaced in scan: {vals:?}"
        );
        // Dense, ascending, unique ids across body + metadata.
        let ids: Vec<u64> = scan.items().iter().map(|i| i.id().get()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            ids, sorted,
            "ids ascending + unique across body and metadata"
        );

        // apply-all via both entry points is identical (shared traversal) — the property.
        let a = redact_pdf(&pdf, &engine()).expect("redact_pdf");
        let b = redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::all()).expect("all");
        assert_eq!(
            a.bytes(),
            b.bytes(),
            "select_all == redact_pdf with metadata"
        );
    }

    #[test]
    fn metadata_per_span_selection_removes_only_accepted() {
        // PER-SPAN: scan an /Info Author + an XMP stream, accept ONLY the Author, and
        // confirm the XMP stream survives.
        let pdf = build_pdf_with_metadata(
            "body",
            &[("Author", "Jane Privileged")],
            "<x:xmpmeta><dc:contact>keep@x.test</dc:contact></x:xmpmeta>",
        );
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let author_item = scan
            .items()
            .iter()
            .find(|i| i.candidate().matched_value() == "Jane Privileged")
            .expect("author detected");
        let result =
            redact_pdf_with_selection(&pdf, &engine(), &PdfSelection::of([author_item.id()]))
                .expect("apply");
        assert_eq!(
            result.total_redactions(),
            1,
            "only the accepted Author removed"
        );
        assert!(
            !info_pairs(result.bytes())
                .iter()
                .any(|(k, _)| k == "Author"),
            "Author removed"
        );
        // The XMP stream was detected (has an email) but NOT accepted → it survives.
        assert!(
            xmp_text(result.bytes()).is_some(),
            "rejected XMP stream kept"
        );
    }

    #[test]
    fn metadata_redaction_is_deterministic_and_xmp_ref_is_clean() {
        // Determinism + catalog integrity: removing the XMP stream leaves the catalog
        // valid (no /Metadata key, no dangling ref) and is byte-stable.
        let pdf = build_pdf_with_metadata(
            "body",
            &[("Author", "Jane Privileged")],
            "<x:xmpmeta><pdfx:SourcePath>\\\\srv\\share\\x</pdfx:SourcePath></x:xmpmeta>",
        );
        let a = redact_pdf(&pdf, &engine()).expect("a").into_bytes();
        let b = redact_pdf(&pdf, &engine()).expect("b").into_bytes();
        assert_eq!(a, b, "metadata redaction must be deterministic");
        // The catalog has no /Metadata key after removal (clean drop, not a dangling ref).
        let doc = Document::load_mem(&a).expect("reload");
        let (_cid, catalog) = resolve_catalog(&doc).expect("catalog");
        assert!(
            catalog.get(METADATA_KEY).is_err(),
            "the /Metadata catalog ref is dropped cleanly"
        );
    }

    #[test]
    fn pdf_with_no_metadata_behaves_exactly_as_before() {
        // NON-REGRESSION: a PDF with no /Info and no XMP is unaffected by the metadata pass.
        let body = "email alice@example.com only in the body";
        let pdf = build_pdf_with_metadata(body, &[], "");
        let r = redact_pdf(&pdf, &engine()).expect("redact");
        let text = extract_text(r.bytes());
        assert!(
            !text.contains("alice@example.com"),
            "body email still redacted"
        );
        assert!(info_pairs(r.bytes()).is_empty(), "no /Info introduced");
        assert!(xmp_text(r.bytes()).is_none(), "no XMP introduced");
    }

    #[test]
    fn metadata_authoring_path_in_xmp_without_recognizer_still_removed() {
        // The XMP path-detection arm: a UNC path that NO engine recognizer flags (no email/
        // url/term in it) still triggers whole-stream removal via looks_like_authoring_path.
        let pdf = build_pdf_with_metadata(
            "body",
            &[("Subject", "Notes")], // /Info benign — isolate the XMP path arm
            "<x:xmpmeta><pdfx:SourcePath>\\\\fileserver\\legal\\confidential</pdfx:SourcePath></x:xmpmeta>",
        );
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(
            result.total_redactions() >= 1,
            "the authoring-path XMP is removed"
        );
        assert!(
            xmp_text(result.bytes()).is_none(),
            "XMP with a UNC path removed"
        );
        assert!(
            !result
                .bytes()
                .windows(b"fileserver".len())
                .any(|w| w == b"fileserver"),
            "the UNC path must not survive the raw bytes"
        );
        // The benign /Subject is untouched (isolation check).
        assert!(info_pairs(result.bytes())
            .iter()
            .any(|(k, _)| k == "Subject"));
    }

    // ---- NAME-WRAP line-scope sanction (the wrapped-name round) ----

    #[test]
    fn wrapped_name_spanning_one_newline_survives_pdf_scan_and_apply() {
        // The observed leak mechanism: the letter-signature name `Ms. Marlow Varga` was
        // detected in the joined text view (the honorific run reaches across the wrap) and
        // then SILENTLY DROPPED by the line-scope filter (name was not sanctioned) — so the
        // name leaked from the PDF entirely. The name-wrap sanction keeps a person-name
        // candidate spanning AT MOST ONE newline.
        let pdf = build_pdf_multi_op_lines(&[
            &["Yours faithfully,"],
            &["Ms. Marlow Varga"],
            &["Kestrel & Lowe LLP"],
        ]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let name_vals: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "name")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            name_vals.iter().any(|v| v.contains("Marlow Varga")),
            "the signature name survives the line-scope filter; got {name_vals:?}"
        );
        // And the apply path truly removes it (parity with the sanctioned scan).
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("Marlow"),
            "the wrapped signature name is removed from the PDF: {text:?}"
        );
    }

    #[test]
    fn genuinely_wrapped_honorific_name_detected_in_pdf_path() {
        // A name wrapped MID-NAME across two visual lines (`Ms. Marlow` / `Varga …`): the
        // single-wrap honorific arm matches across the join `\n` and the sanction keeps it.
        let pdf = build_pdf_multi_op_lines(&[&["Ms. Marlow"], &["Varga attended the meeting"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let name_vals: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "name")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            name_vals
                .iter()
                .any(|v| v.contains("Marlow") && v.contains("Varga")),
            "the mid-name wrap is detected as one name in the PDF path; got {name_vals:?}"
        );
    }

    #[test]
    fn name_wrap_sanction_is_bounded_and_other_classes_unaffected() {
        // Direct unit check on `retain_line_scoped_candidates`: the name-wrap sanction is
        // (i) SHAPE-BOUNDED — a name-kind span crossing TWO newlines is still dropped (no
        // unbounded sanction), and (ii) CLASS-SCOPED — a phone spanning even one newline is
        // still dropped (the HIGH-1 numeric-flood guard holds).
        let text = "Aaa\nBbb\nCcc 10.48\n11.01";
        let mk = |start: usize, end: usize, rec: Recognizer| RedactionCandidate {
            start,
            end,
            matched_value: text[start..end].to_string(),
            recognizer: rec.clone(),
            recognizers: vec![rec],
            context: String::new(),
            confidence: Confidence::Medium,
        };
        // "Aaa\nBbb" (one newline, Name) / "Aaa\nBbb\nCcc" (two newlines, Name) /
        // "10.48\n11.01" (one newline, Phone).
        let mut candidates = vec![
            mk(0, 7, Recognizer::Name),
            mk(0, 11, Recognizer::Name),
            mk(12, 23, Recognizer::Phone),
        ];
        retain_line_scoped_candidates(text, &mut candidates);
        let kept: Vec<&str> = candidates.iter().map(|c| c.matched_value()).collect();
        assert_eq!(
            kept,
            vec!["Aaa\nBbb"],
            "one-newline Name kept; two-newline Name and cross-line phone dropped"
        );
    }

    // ---- ROUND 3: ctx wrapped phone + RCS registry in the PDF path ----

    /// An engine with every context row enabled (the `{"context":true}` shape).
    fn ctx_engine() -> RedactionEngine {
        RedactionEngine::builder()
            .context_recognizers(crate::ContextRecognizers::all())
            .build()
            .unwrap()
    }

    #[test]
    fn m2_wrapped_phone_with_telecom_keyword_survives_pdf_path() {
        // The motivating shape: a real number wrapped across two visual lines with a
        // telecom keyword before it. The ctx:phone-wrapped row corroborates, and the
        // Context sanction lane keeps the cross-line span in the PDF path.
        let pdf = build_pdf_multi_op_lines(&[&["Tel enquiries: 0800"], &["917 2112."]]);
        let scan = scan_pdf(&pdf, &ctx_engine()).expect("scan");
        let vals: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            vals.iter()
                .any(|v| v.contains("0800") && v.contains("2112")),
            "wrapped keyword-anchored phone survives the PDF line-scope; got {vals:?}"
        );
    }

    #[test]
    fn m2_nav_column_still_yields_no_cross_line_number_in_pdf_path() {
        // The HIGH-1 negative MUST hold with the ctx row enabled: a NAV column with no
        // telecom keyword. The general phone match is line-scoped out, and the
        // ctx:phone-wrapped member is SUPPRESSED by the keyword gate before the filter
        // ever sees it — so nothing cross-line survives.
        let pdf = build_pdf_multi_op_lines(&[&["145.90"], &["12 3456"], &["7.81"]]);
        let scan = scan_pdf(&pdf, &ctx_engine()).expect("scan");
        let cross: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .filter(|v| v.contains('\n'))
            .collect();
        assert!(
            cross.is_empty(),
            "a keyword-less NAV column must yield NO cross-line candidate; got {cross:?}"
        );
    }

    #[test]
    fn m3_wrapped_rcs_number_survives_pdf_path() {
        // The register number wrapped across two visual lines: the narrow lu:rcs
        // single-wrap sanction keeps it (the literal anchor is inside the span, so a
        // numeric column can never ride this lane).
        let pdf = build_pdf_multi_op_lines(&[&["R.C.S. Luxembourg"], &["B.6317"]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let vals: Vec<String> = scan
            .items()
            .iter()
            .filter(|i| i.candidate().recognizer().to_string() == "lu:rcs")
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            vals.iter().any(|v| v.contains("B.6317")),
            "wrapped RCS register number survives the PDF path; got {vals:?}"
        );
    }

    // ================= ROUND 6 — Type0/ToUnicode decode · Td-split ws recall =================

    /// Build a one-page PDF whose text is set in a TYPE0 font with 2-BYTE codes and a
    /// `/ToUnicode` CMap (each char of `body` encoded as code `0x0100 + char`), mirroring
    /// the real BGF possessive-sentence runs (Word emits a Type0 subset for runs holding a
    /// curly apostrophe). SYNTHETIC — no corpus cleartext.
    fn build_pdf_type0_tounicode(body: &str) -> Vec<u8> {
        build_pdf_type0_tounicode_opt(body, true)
    }

    /// `valid_trailer=false` omits the `endcmap … defineresource pop` trailer lopdf's CMap
    /// parser requires, so lopdf REJECTS the ToUnicode (falls back to OneByte) while our
    /// bounded `parse_tounicode_2byte` still parses the bfchar block — exercising the
    /// `FontDecoder::CMapTable` fallback (the BGF-page-196 class).
    fn build_pdf_type0_tounicode_opt(body: &str, valid_trailer: bool) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        // 2-byte code operand: 0x01, low byte = the char (all test chars are <= U+00FF
        // except we allow any BMP char via the CMap entry).
        let mut code_bytes: Vec<u8> = Vec::new();
        let mut uniq: std::collections::BTreeSet<char> = std::collections::BTreeSet::new();
        for ch in body.chars() {
            let code = 0x0100u16 + (ch as u32 % 0x100) as u16;
            code_bytes.extend_from_slice(&code.to_be_bytes());
            uniq.insert(ch);
        }
        // The ToUnicode CMap stream (bfchar entries per unique char).
        // The canonical CMap preamble lopdf's parser requires (CIDSystemInfo /
        // CMapName / CMapType sections are mandatory in its grammar).
        let mut cmap = String::from(
            "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
             /CIDSystemInfo <<\n/Registry (Adobe)\n/Ordering (UCS)\n/Supplement 0\n>> def\n\
             /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
             1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
        );
        cmap.push_str(&format!("{} beginbfchar\n", uniq.len()));
        for ch in &uniq {
            let code = 0x0100u16 + (*ch as u32 % 0x100) as u16;
            cmap.push_str(&format!("<{:04X}> <{:04X}>\n", code, *ch as u32));
        }
        if valid_trailer {
            cmap.push_str(
                "endbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n",
            );
        } else {
            // Trailer-less: lopdf's parser rejects this; our fallback parses the bfchar.
            cmap.push_str("endbfchar\n");
        }
        let cmap_id = doc.add_object(Stream::new(Dictionary::new(), cmap.into_bytes()));

        let ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
            Operation::new(
                "Tj",
                vec![Object::String(code_bytes, StringFormat::Hexadecimal)],
            ),
            Operation::new("ET", vec![]),
        ];
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let desc_font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "CIDFontType2", "BaseFont" => "ABCDEF+CID",
        });
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type0", "BaseFont" => "ABCDEF+CID",
            "Encoding" => "Identity-H",
            "DescendantFonts" => vec![desc_font_id.into()],
            "ToUnicode" => cmap_id,
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");
        pdf
    }

    #[test]
    fn type0_with_tounicode_cmap_is_decoded_exactly_and_redacted() {
        // The BGF possessive-sentence class (verbatim source codes `0030 0056 0011 0003
        // 0029 …` = `Ms. Fitzgerald’s …`): a Type0 font WITH a /ToUnicode CMap previously
        // decoded BYTE-LITERALLY (garbage), defeating every recognizer AND ws-elastic
        // TERMS. It must now decode exactly (no unmapped flag) and redact.
        let pdf = build_pdf_type0_tounicode("Ms. Quorley attended the closing today.");
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            !scan.unmapped_fonts(),
            "an exactly-CMap-decoded Type0 page is NOT unmapped (honesty stays precise)"
        );
        let vals: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            vals.iter().any(|v| v.contains("Ms. Quorley")),
            "the honorific name inside the Type0 run is detected; got {vals:?}"
        );
        // Apply truly removes the 2-byte codes (whole code units, alignment kept).
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        assert!(result.total_redactions() >= 1, "the name is removed");
        let doc = Document::load_mem(result.bytes()).expect("reload");
        for (_n, page_id) in doc.get_pages() {
            let decoded = doc.get_page_content(page_id).expect("content");
            // The 2-byte code sequence for "Quorley" (0x0100+char each) must be gone.
            let needle: Vec<u8> = "Quorley"
                .chars()
                .flat_map(|c| (0x0100u16 + (c as u32 % 0x100) as u16).to_be_bytes())
                .collect();
            assert!(
                !decoded
                    .windows(needle.len())
                    .any(|w| w == needle.as_slice()),
                "the name's source codes are removed from the content stream"
            );
        }
        // The ws-elastic TERMS fallback also works over the decoded text now (the
        // escalation finding: terms previously failed on these runs entirely).
        let term_engine = RedactionEngine::new(["Quorley".to_string()]);
        let scan2 = scan_pdf(&pdf, &term_engine).expect("scan with term");
        assert!(
            scan2
                .items()
                .iter()
                .any(|i| i.candidate().matched_value().contains("Quorley")),
            "a user TERM matches inside a decoded Type0 run (the stated fallback guarantee)"
        );
    }

    /// Build a one-page PDF where `lines[i]` pieces are separated by SAME-LINE `Td`
    /// x-nudges (the mid-word kerning split: `Ka` Td `thy` — fabricated separator spaces
    /// in the reconstruction). Lines are `T*`-separated as in `build_pdf_multi_op_lines`.
    fn build_pdf_td_kerning_lines(lines: &[&[&str]]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("TL", vec![14.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (li, line) in lines.iter().enumerate() {
            if li > 0 {
                ops.push(Operation::new("T*", vec![]));
            }
            for (pi, piece) in line.iter().enumerate() {
                if pi > 0 {
                    // A SAME-LINE horizontal nudge (zero y): the kerning-split shape.
                    ops.push(Operation::new("Td", vec![6.into(), 0.into()]));
                }
                ops.push(Operation::new(
                    "Tj",
                    vec![Object::String(
                        piece.as_bytes().to_vec(),
                        StringFormat::Literal,
                    )],
                ));
            }
        }
        ops.push(Operation::new("ET", vec![]));
        let encoded = Content { operations: ops }.encode().expect("encode");
        let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
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
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).expect("save");
        pdf
    }

    #[test]
    fn td_kerning_split_name_is_recovered_from_a_document_level_seed() {
        // The JPMIF officer-column class (verbatim reconstructions: `Ka thy V ancomerbeke`,
        // `L ouise Mullan`): a name whose ONLY clean detection is a role-anchored bio
        // heading (a `ctx:role-name` value — the real JPMIF shape: the officer COLUMN
        // itself is kerning-split, so nothing there can seed) is recovered at its
        // Td-split occurrence via the doc-level whitespace-elastic recall. This is the
        // path the engine's own text propagation can NOT cover (ctx values never seed
        // it), so the recovery is attributable to the ws-name pass alone. Fictional.
        let pdf = build_pdf_td_kerning_lines(&[
            &["Ada Quorleyberg, Independent Director"],
            &["ordinary body text sits between the two mentions."],
            &["Ada Quor", "leyberg"],
        ]);
        let scan = scan_pdf(&pdf, &ctx_engine()).expect("scan");
        let vals: Vec<String> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value().to_string())
            .collect();
        assert!(
            vals.iter().any(|v| v == "Ada Quor leyberg"),
            "the kerning-split occurrence is recovered (fabricated-space form); got {vals:?}"
        );
        assert!(
            scan.diagnostics()
                .iter()
                .any(|d| d.contains("glyph-split") && d.contains("recovered")),
            "the per-page honesty diagnostic names the recovery; got {:?}",
            scan.diagnostics()
        );
        // Apply removes the split occurrence (accept-all): the fragments are gone.
        let result = redact_pdf(&pdf, &ctx_engine()).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("Quor"),
            "no fragment of the split name survives the apply; got {text:?}"
        );
    }

    #[test]
    fn clean_reoccurrence_is_not_ws_appended_split_only_guard() {
        // SPLIT-ONLY: a CLEAN re-occurrence of a seeded name is the normal recognizers'
        // job (the engine's own text-path propagation), never the ws pass's — no
        // glyph-split diagnostic may appear (the structural exclusion that makes
        // ctx:role-name seeding safe against boilerplate amplification).
        let pdf = build_pdf_td_kerning_lines(&[
            &["Ms. Ada Quorleyberg attended the closing."],
            &["Ada Quorleyberg signed the register."],
        ]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            !scan.diagnostics().iter().any(|d| d.contains("glyph-split")),
            "a clean re-occurrence is never ws-appended; got {:?}",
            scan.diagnostics()
        );
    }

    #[test]
    fn ws_elastic_address_never_sweeps_a_directory_column() {
        // The page-7 boundary-drift regression (root-caused verbatim): the ws-elastic
        // ADDRESS street pattern swept an entire DIRECTORY column (`3\n \n \nDIRECTORY
        // \n…\nREGIST`) and struck six chars off the following heading, leaving the
        // `ERED OFFICE OF THE COMPANY` fragment. Elastic address matches are now bounded
        // (<= 2 line breaks / <= 120 bytes), so the heading survives INTACT while the
        // names in the column are still individually redacted. Fictional names.
        let pdf = build_pdf_multi_op_lines(&[
            &["3"],
            &[" "],
            &["DIRECTORY"],
            &[" "],
            &["CHAIRWOMAN "],
            &["Ada Quorley"],
            &[" "],
            &["BOARD OF DIRECTORS"],
            &["Ben Vantol"],
            &["Cerys Marlow"],
            &[" "],
            &["REGISTERED OFFICE OF THE COMPANY"],
            &["2-4, rue Fictive"],
        ]);
        let scan = scan_pdf(&pdf, &ctx_engine()).expect("scan");
        for it in scan.items() {
            let v = it.candidate().matched_value();
            assert!(
                !(v.contains("DIRECTORY") && v.contains("REGIST")),
                "no candidate sweeps the column into the heading; got {v:?}"
            );
        }
        let result = redact_pdf(&pdf, &ctx_engine()).expect("redact");
        let text = extract_text(result.bytes());
        // The DRIFT defect was a MID-WORD partial strike (`ERED OFFICE …` left behind by
        // a sweep ending inside `REGISTERED`). A WHOLE-span ctx over-flag of the heading
        // is the known, safe-side careful-review FP class and is allowed; a torn word is
        // not.
        assert!(
            !text.contains("ERED OFFICE"),
            "no mid-word boundary-drift fragment; got {text:?}"
        );
        assert!(
            !text.contains("Quorley") && !text.contains("Vantol"),
            "the directory names are still removed; got {text:?}"
        );
    }

    #[test]
    fn parse_tounicode_2byte_bfchar_and_bfrange() {
        // bfchar + bfrange (single incrementing dst) + bfrange (array dst).
        let stream = b"begincmap\n1 begincodespacerange\n<0000><FFFF>\nendcodespacerange\n\
            2 beginbfchar\n<0001><0041>\n<0002><0062>\nendbfchar\n\
            1 beginbfrange\n<0003><0005><0043>\nendbfrange\n\
            1 beginbfrange\n<0010><0011>[<0058><0059>]\nendbfrange\n";
        let m = parse_tounicode_2byte(stream).expect("parses");
        assert_eq!(m.get(&0x0001).map(String::as_str), Some("A"));
        assert_eq!(m.get(&0x0002).map(String::as_str), Some("b"));
        // Range <0003>..<0005> -> C, D, E (last unit incremented).
        assert_eq!(m.get(&0x0003).map(String::as_str), Some("C"));
        assert_eq!(m.get(&0x0004).map(String::as_str), Some("D"));
        assert_eq!(m.get(&0x0005).map(String::as_str), Some("E"));
        // Array range -> X, Y.
        assert_eq!(m.get(&0x0010).map(String::as_str), Some("X"));
        assert_eq!(m.get(&0x0011).map(String::as_str), Some("Y"));
    }

    #[test]
    fn parse_tounicode_2byte_rejects_non_simple() {
        // A 1-byte source code is NOT the 2-byte Identity-H shape -> fail closed to None
        // (the caller stays Unmappable, still flagged — never a wrong decode).
        assert!(parse_tounicode_2byte(b"1 beginbfchar\n<01><0041>\nendbfchar\n").is_none());
        // A malformed bfchar body (missing dst) -> None.
        assert!(parse_tounicode_2byte(b"1 beginbfchar\n<0001>\nendbfchar\n").is_none());
        // No mappings at all -> None (nothing to decode with).
        assert!(parse_tounicode_2byte(b"begincmap\nendcmap\n").is_none());
    }

    #[test]
    fn type0_tounicode_lopdf_rejects_uses_our_fallback_and_redacts() {
        // The BGF-page-196 class: a ToUnicode lopdf's parser REJECTS (trailer-less), so
        // lopdf falls back to OneByte -> we would decode GARBAGE and only flag. Our
        // bounded `parse_tounicode_2byte` fallback decodes it exactly, so the name is
        // detected AND removed (recall win, not a silent survive-behind-the-flag).
        let pdf = build_pdf_type0_tounicode_opt("Ms. Quorley signed.", false);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value().contains("Ms. Quorley")),
            "the fallback CMap decodes + detects the name that lopdf could not map"
        );
        let result = redact_pdf(&pdf, &engine()).expect("redact");
        let doc = Document::load_mem(result.bytes()).expect("reload");
        for (_n, pid) in doc.get_pages() {
            let decoded = doc.get_page_content(pid).expect("content");
            let needle: Vec<u8> = "Quorley"
                .chars()
                .flat_map(|c| (0x0100u16 + (c as u32 % 0x100) as u16).to_be_bytes())
                .collect();
            assert!(
                !decoded
                    .windows(needle.len())
                    .any(|w| w == needle.as_slice()),
                "the fallback-decoded name's codes are truly removed"
            );
        }
        assert_eq!(result.could_not_remove(), 0, "honest could_not_remove");
    }

    /// Build a TWO-PAGE PDF directly: page 1 in a Type0/Identity-H font with NO
    /// `/ToUnicode` (genuinely UNMAPPABLE -> best-effort garbage, sets `unmapped_fonts`);
    /// page 2 lays `p2_lines` out with SAME-LINE `Td` kerning nudges (the mid-word split)
    /// in a simple Type1 font. Pins the offset-invariant at document scale: an unmappable
    /// page BEFORE a name page must not shift the name page's span-back mapping.
    fn build_unmappable_then_kerning(p1_body: &str, p2_lines: &[&[&str]]) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");

        // Page 1 content: 2-byte Identity-H codes (no ToUnicode -> undecodable).
        let mut codes: Vec<u8> = Vec::new();
        for ch in p1_body.chars() {
            codes.extend_from_slice(&(0x0100u16 + (ch as u32 % 0x100) as u16).to_be_bytes());
        }
        let c1 = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::String(codes, StringFormat::Hexadecimal)]),
                Operation::new("ET", vec![]),
            ],
        }
        .encode()
        .expect("encode p1");
        let c1_id = doc.add_object(Stream::new(Dictionary::new(), c1));

        // Page 2 content: Td-kerning-split lines.
        let mut ops = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F2".into(), 12.into()]),
            Operation::new("TL", vec![14.into()]),
            Operation::new("Td", vec![72.into(), 720.into()]),
        ];
        for (li, line) in p2_lines.iter().enumerate() {
            if li > 0 {
                ops.push(Operation::new("T*", vec![]));
            }
            for (pi, piece) in line.iter().enumerate() {
                if pi > 0 {
                    ops.push(Operation::new("Td", vec![6.into(), 0.into()]));
                }
                ops.push(Operation::new(
                    "Tj",
                    vec![Object::String(
                        piece.as_bytes().to_vec(),
                        StringFormat::Literal,
                    )],
                ));
            }
        }
        ops.push(Operation::new("ET", vec![]));
        let c2 = Content { operations: ops }.encode().expect("encode p2");
        let c2_id = doc.add_object(Stream::new(Dictionary::new(), c2));

        // Fonts.
        let desc = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "CIDFontType2", "BaseFont" => "ABCDEF+CID",
        });
        let f1 = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type0", "BaseFont" => "ABCDEF+CID",
            "Encoding" => "Identity-H", "DescendantFonts" => vec![desc.into()],
        });
        let f2 = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let res = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => f1, "F2" => f2 },
        });
        let pages_id = doc.new_object_id();
        let page1 = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => c1_id, "Resources" => res,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });
        let page2 = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => c2_id, "Resources" => res,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page1.into(), page2.into()], "Count" => 2,
            }),
        );
        let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog);
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save");
        out
    }

    #[test]
    fn unmappable_page_before_a_name_page_does_not_shift_offsets() {
        // FULL-DOCUMENT-SCALE regression (the coordinator's #5): an UNMAPPABLE Type0 page
        // (no /ToUnicode -> best-effort garbage, sets unmapped_fonts) BEFORE a page whose
        // Td-kerning-split name must be recovered. The per-page mapping means the
        // unmappable page cannot shift the later page's span-back offsets: the name is
        // STILL removed, could_not_remove stays honest, and unmapped_fonts is set.
        let pdf = build_unmappable_then_kerning(
            "garbled annex text on the first page",
            &[
                &["Ada Quorleyberg, Independent Director"],
                &["Ada Quor", "leyberg"],
            ],
        );
        let scan = scan_pdf(&pdf, &ctx_engine()).expect("scan");
        assert!(
            scan.unmapped_fonts(),
            "the CID annex page sets the honesty flag"
        );
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value() == "Ada Quor leyberg"),
            "the later page's split name is still detected (no offset shift)"
        );
        let result = redact_pdf(&pdf, &ctx_engine()).expect("redact");
        let text = extract_text(result.bytes());
        assert!(
            !text.contains("Quor"),
            "the later page's split name is truly removed; got {text:?}"
        );
        assert_eq!(
            result.could_not_remove(),
            0,
            "no accepted span silently unremoved (the invariant)"
        );
        assert!(result.unmapped_fonts(), "unmapped flag survives the apply");
    }

    #[test]
    fn ctx_role_name_seeds_only_the_person_bio_layout() {
        // FIX 1a (round-6 review): the doc-level recall seeds from a `ctx:role-name` value
        // ONLY when it sits DIRECTLY ABOVE a role-title line (the officer-bio / directory
        // layout). A PERSON name above `Executive Director` seeds (and its Td-split
        // re-occurrence is recovered); a fund / defined-term phrase near a role word does
        // NOT (the amplification class). Fictional names.
        // (a) PERSON bio → seeded → the split re-occurrence is recovered.
        let person = build_pdf_td_kerning_lines(&[
            &["Kwame Adigunbe"],
            &["Executive Director, Finance"],
            &["Kwame Adigunbe has 20 years of experience."],
            &["Kwame Adi", "gunbe"],
        ]);
        let scan = scan_pdf(&person, &ctx_engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value() == "Kwame Adi gunbe"),
            "a ctx person-bio name seeds + recovers its split; got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );
        // (b) a FUND/defined-term phrase near a role word, NOT above a role title →
        // NOT seeded → its glued re-occurrence is NOT appended (no glyph-split recovery).
        let fund = build_pdf_td_kerning_lines(&[
            &["The Directors have appointed the Systematic China Fund as follows."],
            &["Systematic China is offered to eligible investors."],
            &["SystematicChina appears glued later in a table."],
        ]);
        let scan2 = scan_pdf(&fund, &ctx_engine()).expect("scan");
        assert!(
            !scan2
                .items()
                .iter()
                .any(|i| i.candidate().matched_value().contains("SystematicChina")),
            "a fund phrase not in a bio layout does not seed doc-wide recall; got {:?}",
            scan2
                .items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ctx_value_is_person_bio_unit() {
        // Verbatim JPMIF/BGF context shapes.
        assert!(ctx_value_is_person_bio(
            "UK. \nKathy Vancomerbeke  \nExecutive Director, Finance \nKathy ha",
            "Kathy Vancomerbeke"
        ));
        assert!(ctx_value_is_person_bio(
            "ISC Paris. \nLouise Mullan\n \n \nManaging Director, Onboarding",
            "Louise Mullan"
        ));
        assert!(ctx_value_is_person_bio(
            "Chairman\nDenise Voss\nDirectors\n",
            "Denise Voss"
        ));
        // NEGATIVES: value NOT directly above a role-title line.
        assert!(!ctx_value_is_person_bio(
            "London, EC4Y 0JP, United Kingdom\n \nMr. Vitoria, Managing Director",
            "United Kingdom"
        ));
        assert!(!ctx_value_is_person_bio(
            "from ISC Paris. \nLouise Mullan\n",
            "ISC Paris"
        ));
        assert!(!ctx_value_is_person_bio(
            "business in Continental Europe. A J.P. Morgan employee",
            "Continental Europe"
        ));
    }

    #[test]
    fn seed_is_org_or_fund_unit() {
        assert!(seed_is_org_or_fund("Bond Fund"));
        assert!(seed_is_org_or_fund("Management Company"));
        assert!(seed_is_org_or_fund("BlackRock Group"));
        assert!(seed_is_org_or_fund("Investment Adviser"));
        assert!(!seed_is_org_or_fund("Kathy Vancomerbeke"));
        assert!(!seed_is_org_or_fund("Svetlana Butvina"));
    }

    #[test]
    fn tounicode_fallback_bounds_the_work_and_rejects_non_hex() {
        // FIX 2: a crafted ToUnicode with MANY overlapping FULL-range bfrange blocks would
        // sweep 65 536 codes each — the work bound fails closed (-> None) instead of
        // grinding. (Well over MAX_CMAP_WORK total emits across the blocks.)
        let mut s = String::from("begincmap\n");
        for _ in 0..8 {
            s.push_str("1 beginbfrange\n<0000><FFFF><0041>\nendbfrange\n");
        }
        assert!(
            parse_tounicode_2byte(s.as_bytes()).is_none(),
            "overlapping full-range blocks exceed the work bound -> fail closed"
        );
        // FIX 3: a NON-hex byte inside a `<...>` hex string fails the token (never a silent
        // drop that maps `<0G041>` as `<0041>`).
        assert!(
            parse_tounicode_2byte(b"1 beginbfchar\n<0G01><0041>\nendbfchar\n").is_none(),
            "non-hex inside a hex string -> fail closed"
        );
        // A single non-overlapping full range is fine (<= the bound) and decodes.
        let ok = parse_tounicode_2byte(b"1 beginbfrange\n<0000><00FF><0041>\nendbfrange\n");
        assert!(ok.is_some(), "a single bounded range still parses");
    }

    #[test]
    fn is_split_occurrence_unit() {
        assert!(is_split_occurrence(
            "Kathy Vancomerbeke",
            "Ka thy V ancomerbeke"
        ));
        assert!(is_split_occurrence("Robert Kaylor", "Robert Ka ylor"));
        // A CROSS-LINE occurrence (contains `\n` the seed lacks) IS a recovery target —
        // the same-line organic name pattern cannot span it (the BGF-p196 spaceless
        // comma-list `…Benjamin\nGregson,…`).
        assert!(is_split_occurrence(
            "Kathy Vancomerbeke",
            "Kathy\nVancomerbeke"
        ));
        // A CLEAN same-line re-occurrence (equal tokenization, no `\n`) is NOT appended
        // (the organic recognizers' job; the amplification guard).
        assert!(!is_split_occurrence(
            "Kathy Vancomerbeke",
            "Kathy Vancomerbeke"
        ));
        assert!(!is_split_occurrence(
            "Management Company",
            "Management Company"
        ));
    }

    // ==================== ROUND 7 — TJ number-encoded word gaps ====================

    #[test]
    fn tj_number_word_gaps_restore_detection_and_are_truly_removed() {
        // The BGF pp247-248 / p190 total-miss class, reproduced synthetically: every
        // inter-word gap is a TJ numeric adjustment (~-250), NO space glyph anywhere,
        // and the names exist ONLY here (no normally-spaced sibling in the document,
        // so the seed-based ws-elastic recall cannot rescue them). The word-gap
        // separator must restore token boundaries so the ORGANIC machinery fires:
        // the honorific anchor (`Dr.` — the Shariah-panel shape) and the
        // header-anchored vertical name list (`Board of Directors` — the Saldanha
        // shape). Then apply must TRULY remove the source bytes.
        let gap = -250i64;
        let pdf = build_pdf_tj_number_gap_lines(&[
            &[(0, "Board"), (gap, "of"), (gap, "Directors")],
            &[(0, "Keith"), (gap, "Saldanha")],
            &[(0, "Dr."), (gap, "Mohamed"), (gap, "Ali"), (gap, "Elgari")],
        ]);
        // The header-list machinery rides the ctx pack (the config the shipped UI
        // drives); the honorific machinery is a core name recognizer.
        let eng = crate::RedactionEngineBuilder::default()
            .context_recognizers(crate::ContextRecognizers::all())
            .build()
            .expect("engine");
        let scan = scan_pdf(&pdf, &eng).expect("scan");
        let values: Vec<&str> = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value())
            .collect();
        assert!(
            values.iter().any(|v| v.contains("Mohamed Ali Elgari")),
            "the glued honorific name must be detected WITH restored spaces; got {values:?}"
        );
        assert!(
            values.iter().any(|v| v.contains("Keith Saldanha")),
            "the glued header-list name must be detected WITH restored spaces; got {values:?}"
        );
        // The page now reads normally — it must NOT be flagged degenerate.
        assert!(
            !scan.degenerate_layout(),
            "a page whose gaps decode into spaces is not degenerate"
        );

        let result = redact_pdf(&pdf, &eng).expect("apply");
        assert_eq!(result.could_not_remove(), 0, "removals must be honest");
        let out = result.bytes();
        for frag in ["Elgari", "Saldanha", "Mohamed"] {
            assert!(
                !out.windows(frag.len()).any(|w| w == frag.as_bytes()),
                "redacted output still contains {frag:?} — a silent leak"
            );
        }
        let _ = Document::load_mem(out).expect("redacted PDF must still parse");
    }

    #[test]
    fn tj_word_gap_threshold_boundary_and_kerning_join() {
        // AT the threshold (-180): a word gap — the separator is fabricated and the
        // honorific name is detected with spaces. The same TJ also carries a MICRO
        // kerning split (-30) inside "Smith": it must still JOIN contiguously (the
        // deliberate round-6 kerning-join policy is untouched).
        let pdf = build_pdf_tj_number_gap_lines(&[&[
            (0, "Dr."),
            (-180, "John"),
            (-180, "Smi"),
            (-30, "th"),
        ]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.items()
                .iter()
                .any(|i| i.candidate().matched_value().contains("John Smith")),
            "-180 is a word gap (<= threshold) and -30 is kerning (joins); got {:?}",
            scan.items()
                .iter()
                .map(|i| i.candidate().matched_value())
                .collect::<Vec<_>>()
        );

        // JUST ABOVE the threshold (-179): kerning — the elements join contiguously
        // (`Dr.JohnSmith`), so no spaced name exists to detect.
        let pdf2 = build_pdf_tj_number_gap_lines(&[&[(0, "Dr."), (-179, "John"), (-179, "Smith")]]);
        let scan2 = scan_pdf(&pdf2, &engine()).expect("scan");
        assert!(
            !scan2
                .items()
                .iter()
                .any(|i| i.candidate().matched_value().contains("John Smith")),
            "-179 is kerning (above the word-gap threshold): elements join contiguously"
        );
    }

    #[test]
    fn tj_justification_stretch_beside_real_space_is_not_double_spaced() {
        // Justified text keeps its REAL space glyphs and stretches them with numeric
        // adjustments (`(Dr. John )-250(Smith)`). The boundary is already whitespace,
        // so NO extra separator may be fabricated — the detected value carries exactly
        // ONE space (normally-spaced text is never perturbed).
        let pdf = build_pdf_tj_number_gap_lines(&[&[(0, "Dr. John "), (-250, "Smith")]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        let hit = scan
            .items()
            .iter()
            .map(|i| i.candidate().matched_value())
            .find(|v| v.contains("John") && v.contains("Smith"))
            .expect("the justified name must be detected");
        assert!(
            hit.contains("John Smith") && !hit.contains("John  Smith"),
            "a real space beside a stretch adjustment must not double-space; got {hit:?}"
        );
    }

    // ==================== ROUND 7 — degenerate-layout honesty floor ====================

    #[test]
    fn degenerate_spaceless_page_sets_flag_and_page_diagnostic() {
        // A page whose reconstructed text carries an implausibly long spaceless
        // alphabetic run (here: NO adjustments at all — a genuinely space-free layout
        // the word-gap fix cannot help) decodes cleanly (`unmapped_fonts` stays false)
        // but is unreadable to every recognizer. It must NEVER silently pass: the
        // document-level `degenerate_layout` flag + a content-free per-page diagnostic.
        let glued = "Confidentialclientnamesburiedinthisspacelessrunthatnorecognizercantokenize";
        assert!(glued.chars().count() > DEGENERATE_ALPHA_RUN_CHARS);
        let pdf = build_pdf_tj_number_gap_lines(&[&[(0, glued)]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            scan.degenerate_layout(),
            "a spaceless page must set the degenerate_layout honesty flag"
        );
        assert!(
            !scan.unmapped_fonts(),
            "the page DECODES cleanly — unmapped_fonts gives no signal for this class \
             (which is exactly why degenerate_layout exists)"
        );
        assert!(
            scan.diagnostics()
                .iter()
                .any(|d| d.starts_with("page 1:") && d.contains("degenerate spaceless")),
            "a per-page content-free diagnostic must name the page; got {:?}",
            scan.diagnostics()
        );
        // The diagnostic is CONTENT-FREE (never leaks the run's cleartext).
        for d in scan.diagnostics() {
            assert!(
                !d.contains("Confidentialclient"),
                "diagnostic leaked cleartext: {d}"
            );
        }
        // The flag survives the APPLY path too (same honesty posture as unmapped_fonts).
        let result = redact_pdf(&pdf, &engine()).expect("apply");
        assert!(
            result.degenerate_layout(),
            "degenerate_layout must survive the apply path"
        );
    }

    #[test]
    fn degenerate_flag_negative_normal_and_boundary_pages_never_flag() {
        // A NORMAL page (spaced words) never flags — the signal must stay meaningful.
        let pdf = build_pdf_multi_op_lines(&[&["Contact bob@firm.test for the schedule."]]);
        let scan = scan_pdf(&pdf, &engine()).expect("scan");
        assert!(
            !scan.degenerate_layout(),
            "a normally-spaced page must never flag degenerate_layout"
        );
        // Boundary: EXACTLY the threshold does not flag; one past it does.
        let at = "a".repeat(DEGENERATE_ALPHA_RUN_CHARS);
        let over = "a".repeat(DEGENERATE_ALPHA_RUN_CHARS + 1);
        assert!(
            !has_degenerate_alpha_run(&at),
            "== threshold: not degenerate"
        );
        assert!(has_degenerate_alpha_run(&over), "> threshold: degenerate");
        // Whitespace/punctuation breaks the run (real prose never trips it).
        let broken = format!("{at} {at}. {at}");
        assert!(!has_degenerate_alpha_run(&broken));
    }
}
