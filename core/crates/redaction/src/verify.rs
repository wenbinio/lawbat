// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Post-redaction VERIFICATION probes (`verify_text` / `verify_pdf`)
//!
//! Productizes the recovery-probe discipline (CLAUDE.md: *"a self-scan of '0
//! candidates' never proves zero; only a recovery red-team — multi-decoder + raw
//! bytes + annotations + metadata — verifies true removal"*) into a deterministic,
//! machine-checkable probe pass a host can run over a redacted OUTPUT and attach
//! to a production as structured report data (`firmos.verify/0` at the CLI seam).
//!
//! ## What this IS and IS NOT (load-bearing honesty — read before trusting)
//!
//! - **It probes ONLY the supplied values.** The caller hands the accepted
//!   (removed) cleartext values; each is searched for across multiple recovery
//!   vectors. A value NOT in the list is NOT probed and carries no finding either
//!   way. Detection gaps (a value no recognizer/reviewer ever saw) are out of
//!   scope by construction.
//! - **A finding is a RESIDUAL — a probe recovered the value from the output.**
//!   That is always a defect signal worth surfacing.
//! - **No finding is NOT a guarantee of removal.** It means THESE vectors did not
//!   recover the value. The image/pixel layer is not probed at all (v1);
//!   unsupported-filter streams are not decompressed; container-format
//!   attachments are not extracted. The result structures force this framing:
//!   there is no "passed"/"safe"/"clean" state anywhere — only per-vector probe
//!   outcomes plus honesty flags, and the CLI layer adds a mandatory
//!   `limitations` key list. **Never render this as a safety certificate.**
//! - **Results are VALUE-FREE.** A [`ValueVerification`] identifies its value by
//!   `value_index` (the ordinal in the caller's request list) — class / count /
//!   page locations only, never the matched cleartext — so the result can travel
//!   into a client-facing report without re-disclosing the very identifiers that
//!   were redacted. The caller holds the list and can resolve indices locally.
//!
//! ## Vectors (stable ids — a rendered report cites them verbatim)
//!
//! Text output ([`verify_text`]) — four increasingly permissive presence probes,
//! each reported independently: `text_raw` (exact substring) →
//! `text_case_insensitive` → `text_ws_normalized` (case-insensitive + whitespace
//! runs collapsed to one space) → `text_ws_stripped` (case-insensitive + ALL
//! whitespace removed — the glyph-/kerning-split recovery decoder).
//!
//! PDF output ([`verify_pdf`]) — six SURFACES, each probed with the text ladder
//! above (the strictest mode that hit is reported as `mode`):
//! - `pdf_text_strict` — a [`scan_pdf`] pass with a TERMS-ONLY engine built from
//!   the probe values: the values are searched through the engine's OWN decoders
//!   (font `/Encoding`+`/Differences`+`/ToUnicode` decode, logical-run
//!   reconstruction, whitespace-elastic term recall) — the exact machinery the
//!   redactor detected with, so "would the redactor still see it?" is answered by
//!   the redactor itself. Also yields the honesty flags
//!   (`low_text`/`unmapped_fonts`/`degenerate_layout`) echoed in the result.
//! - `pdf_text_lenient` — every show-operator string operand decoded WITHOUT
//!   font mapping (UTF-16BE-BOM else Latin-1 identity), per page: the
//!   naive-extractor view a copy-paste attacker gets.
//! - `pdf_raw_bytes` — the output bytes themselves, Latin-1-decoded:
//!   uncompressed residue anywhere in the file.
//! - `pdf_streams` — EVERY stream object (content streams, form XObjects,
//!   embedded files, …) inflated through the SAME capped, budgeted reader the
//!   redactor uses ([`decode_stream_capped`]), Latin-1-decoded. Deliberately
//!   BROADER than what the redactor rewrites — it reaches surfaces the redactor
//!   honestly reports as `not_removed`.
//! - `pdf_annotations` — every annotation dictionary's string fields (incl.
//!   nested `/A`/`/AA` action dicts and INLINE annotation dicts the scrubber
//!   cannot address), decoded via [`decode_annot_string`].
//! - `pdf_metadata` — every `/Info` string value + the catalog XMP `/Metadata`
//!   stream.
//!
//! ## Page locations (and the apply-report seam)
//!
//! Where the OUTPUT itself determines a location, a probe outcome carries the
//! 1-based `pages` it hit on (`pdf_text_strict` from the scan items — page 0
//! meaning the document-metadata surface; `pdf_text_lenient` / `pdf_annotations`
//! from their per-page walks). `pdf_raw_bytes` / `pdf_streams` / `pdf_metadata`
//! have no page geometry — their `pages` list is empty, meaning UNDETERMINED,
//! not "page-less is fine". Apply-time page knowledge (`could_not_remove` pages,
//! unmapped-font page ranges, OCR-confidence pages) is NOT recoverable from the
//! redacted output alone — a report wanting those must carry them over from the
//! apply response, not from this op.
//!
//! ## Determinism / bounds / confidentiality
//!
//! Pure compute: no I/O, no clock, no RNG — same input, same result. Every decode
//! rides the redactor's own caps ([`MAX_PDF_BYTES`], [`MAX_DECODED_STREAM_BYTES`],
//! [`MAX_TOTAL_DECODED_BYTES`], [`MAX_ANNOT_FIELD_BYTES`], [`MAX_ANNOTS_PER_PAGE`])
//! so a hostile file (bomb-shaped, garbled, encrypted) yields a bounded structured
//! error or a diagnosed skip — never a panic, never an unbounded allocation. A
//! skipped/undecodable surface is recorded in `diagnostics` (content-free) so it
//! reads as NOT PROBED, never as clean. Probe values are cleartext matter data:
//! they exist only in the caller's request — nothing here logs them, no result
//! field echoes them, and every diagnostic string is value-free.
//!
//! [`MAX_PDF_BYTES`]: crate::pdf::MAX_PDF_BYTES

use std::collections::BTreeSet;

use lopdf::{Document, Object};
use runtime::{CoreError, CoreResult};

use crate::pdf::{
    decode_annot_string, decode_stream_capped, decode_stream_ops, load_pdf_checked, scan_pdf,
    StreamError, ANNOTS_KEY, MAX_ANNOTS_PER_PAGE, MAX_ANNOT_FIELD_BYTES, MAX_DECODED_STREAM_BYTES,
    MAX_TOTAL_DECODED_BYTES, METADATA_KEY, SHOW_OPERATORS,
};
use crate::{BuiltinRecognizers, ContextRecognizers, RedactionEngine};

/// The redaction-engine crate version a rendered report cites (the workspace
/// version — the engine and this probe pass always ship together). Distinct from
/// any binary hash: this names the ENGINE lineage, not an artifact.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The text-output vector ids, in report order. STABLE strings — a rendered
/// report cites them; never rename, only append.
pub const TEXT_VECTORS: &[&str] = &[
    "text_raw",
    "text_case_insensitive",
    "text_ws_normalized",
    "text_ws_stripped",
];

/// The PDF-output vector (surface) ids, in report order. STABLE strings.
pub const PDF_VECTORS: &[&str] = &[
    "pdf_text_strict",
    "pdf_text_lenient",
    "pdf_raw_bytes",
    "pdf_streams",
    "pdf_annotations",
    "pdf_metadata",
];

/// Surfaces a PDF verification structurally does NOT probe in v1 — STABLE ids
/// (not prose; the renderer owns wording) echoed so a report can never imply
/// they were checked:
/// - `image_pixel_content` — text burned into scanned/rasterized pages is
///   invisible to every vector here (OCR is out of scope for this op);
/// - `unsupported_filter_streams` — only raw + single-`FlateDecode` streams are
///   decompressed (the redactor's own bounded filter policy); anything else is
///   skipped with a diagnostic;
/// - `attachment_container_content` — embedded files are probed only as
///   raw/decompressed BYTES; text inside a container format (a `.docx`
///   attachment's XML inside its ZIP) is not extracted.
pub const PDF_NOT_PROBED: &[&str] = &[
    "image_pixel_content",
    "unsupported_filter_streams",
    "attachment_container_content",
];

/// The probe-mode id ladder, strictest first. `mode` in a [`ProbeOutcome`] is
/// the STRICTEST mode that recovered the value on that vector (a raw hit is a
/// stronger signal than a whitespace-stripped one). STABLE ids.
const MODE_LABELS: [&str; 4] = ["raw", "case_insensitive", "ws_normalized", "ws_stripped"];

/// One probe outcome: did `vector` recover the value from the output?
///
/// Field names are deliberately residual-shaped: `residual_found == false` states
/// only that THIS probe did not recover the value — it is never a "passed"/
/// "safe"/"clean" verdict, and no such field exists anywhere in the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// The vector id (a [`TEXT_VECTORS`] / [`PDF_VECTORS`] entry).
    pub vector: &'static str,
    /// `true` iff this probe recovered the value from the output.
    pub residual_found: bool,
    /// Non-overlapping occurrences recovered (0 when `residual_found` is false).
    pub matches: usize,
    /// PDF surfaces only: the STRICTEST text-ladder mode that hit (a
    /// [`MODE_LABELS`] entry). `None` for text vectors (the vector IS the mode)
    /// and for `pdf_text_strict` (engine detection, not a text ladder).
    pub mode: Option<&'static str>,
    /// 1-based pages the residual was recovered on, where the output determines
    /// them (`pdf_text_strict` — 0 = the document-metadata surface;
    /// `pdf_text_lenient`; `pdf_annotations`). EMPTY for vectors with no page
    /// geometry (`pdf_raw_bytes` / `pdf_streams` / `pdf_metadata` / all text
    /// vectors) — empty means UNDETERMINED there, never "nowhere".
    pub pages: Vec<u32>,
}

/// All probe outcomes for ONE value, identified VALUE-FREE by `value_index` (the
/// ordinal in the caller's value list). The result never carries the cleartext:
/// class/count/pages only, so it can feed a client-facing report without
/// re-disclosing the redacted identifiers. The caller resolves indices locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueVerification {
    /// Index into the caller's `values` list.
    pub value_index: usize,
    /// One outcome per vector, in [`TEXT_VECTORS`] / [`PDF_VECTORS`] order.
    pub probes: Vec<ProbeOutcome>,
}

impl ValueVerification {
    /// `true` iff ANY vector recovered this value.
    pub fn residual_found(&self) -> bool {
        self.probes.iter().any(|p| p.residual_found)
    }
}

/// The honesty flags the strict scan of the OUTPUT surfaces — echoed so a report
/// can never read "no residuals" over a document whose text layer was not fully
/// analyzable (the exact false-clean the flags exist to prevent). Document-level
/// only: per-page unmapped-font/OCR detail is apply-time knowledge this op cannot
/// recover from the output (see the module docs' apply-report seam note).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfVerifyFlags {
    /// Little/no extractable text (image-only/scanned) — the text vectors have
    /// almost nothing to probe; identifiers baked into images are NOT probed.
    pub low_text: bool,
    /// A font's encoding could not be exactly mapped — the strict pass decoded
    /// those pages only best-effort; absence of a finding there proves less.
    pub unmapped_fonts: bool,
    /// A page has a degenerate spaceless layout — recognizer-blind text the
    /// strict pass may not tokenize; same caveat.
    pub degenerate_layout: bool,
}

/// The full PDF verification result: per-value probe outcomes + honesty flags +
/// content-free diagnostics (skipped/undecodable surfaces — each one reads as
/// NOT PROBED, never as clean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfVerification {
    /// One entry per probed value, in input order (`value_index` ascending).
    pub results: Vec<ValueVerification>,
    /// The strict scan's honesty flags over the OUTPUT document.
    pub flags: PdfVerifyFlags,
    /// Content-free diagnostics (never a probe value, never matter text).
    pub diagnostics: Vec<String>,
}

// ---------------------------------------------------------------------------
// The text ladder
// ---------------------------------------------------------------------------

/// The four normalized forms of a haystack or needle, computed once.
struct Forms {
    raw: String,
    ci: String,
    ws_norm: String,
    ws_strip: String,
}

impl Forms {
    fn of(s: &str) -> Self {
        let ci = s.to_lowercase();
        Forms {
            ws_norm: normalize_ws(&ci),
            ws_strip: strip_ws(&ci),
            raw: s.to_string(),
            ci,
        }
    }
}

/// Collapse every whitespace run to a single ASCII space and trim the ends.
fn normalize_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(' ');
            }
            in_ws = false;
            out.push(ch);
        }
    }
    out
}

/// Remove ALL whitespace.
fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Non-overlapping occurrence count; 0 for an empty needle (an empty needle
/// matches everywhere vacuously — callers exclude empty values, this guard keeps
/// the function total and honest).
fn count_hits(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    hay.matches(needle).count()
}

/// Run the ladder over one haystack chunk: per mode index (strictest first), the
/// non-overlapping hit count.
fn ladder_counts(hay: &Forms, needle: &Forms) -> [usize; 4] {
    [
        count_hits(&hay.raw, &needle.raw),
        count_hits(&hay.ci, &needle.ci),
        count_hits(&hay.ws_norm, &needle.ws_norm),
        count_hits(&hay.ws_strip, &needle.ws_strip),
    ]
}

/// Per-value accumulator for one SURFACE probed across multiple chunks: the
/// strictest mode that hit anywhere, the match count AT that mode (summed
/// across chunks), and the pages hit (when the caller knows the chunk's page).
#[derive(Clone)]
struct SurfaceAcc {
    /// Index into [`MODE_LABELS`] of the strictest mode that hit; `usize::MAX`
    /// when nothing hit yet.
    best_mode: usize,
    matches: usize,
    pages: BTreeSet<u32>,
}

impl SurfaceAcc {
    fn new() -> Self {
        SurfaceAcc {
            best_mode: usize::MAX,
            matches: 0,
            pages: BTreeSet::new(),
        }
    }

    /// Fold one chunk's ladder counts in. A stricter mode REPLACES the running
    /// count (the report cites the strongest recovery signal); the same mode
    /// ADDS (occurrences across chunks sum). Only the strictest hitting mode of
    /// the chunk contributes (a raw hit implies the laxer modes also hit —
    /// counting those too would double-report the same occurrence). `page`, when
    /// known, is recorded on ANY hit regardless of mode.
    fn fold(&mut self, counts: [usize; 4], page: Option<u32>) {
        for (mode, &n) in counts.iter().enumerate() {
            if n == 0 {
                continue;
            }
            match mode.cmp(&self.best_mode) {
                std::cmp::Ordering::Less => {
                    self.best_mode = mode;
                    self.matches = n;
                }
                std::cmp::Ordering::Equal => self.matches += n,
                std::cmp::Ordering::Greater => {}
            }
            if let Some(p) = page {
                self.pages.insert(p);
            }
            break;
        }
    }

    /// A direct engine-detection hit (the strict surface): no ladder mode.
    fn hit_direct(&mut self, page: u32) {
        self.best_mode = 0;
        self.matches += 1;
        self.pages.insert(page);
    }

    fn outcome(&self, vector: &'static str, keep_mode: bool) -> ProbeOutcome {
        if self.best_mode == usize::MAX {
            ProbeOutcome {
                vector,
                residual_found: false,
                matches: 0,
                mode: None,
                pages: Vec::new(),
            }
        } else {
            ProbeOutcome {
                vector,
                residual_found: true,
                matches: self.matches,
                mode: if keep_mode {
                    Some(MODE_LABELS[self.best_mode])
                } else {
                    None
                },
                pages: self.pages.iter().copied().collect(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TEXT verification
// ---------------------------------------------------------------------------

/// Probe a redacted TEXT output for each value across the four text vectors,
/// each reported INDEPENDENTLY (a `text_raw` hit necessarily also hits the laxer
/// vectors — the per-vector view lets a report show exactly which decodings
/// recover the value).
///
/// `values` should be non-empty, trimmed strings (the CLI enforces this); an
/// empty value yields all-zero probes rather than a vacuous everything-match.
/// Deterministic, linear in `text.len() * values.len()`; never panics.
pub fn verify_text(text: &str, values: &[String]) -> Vec<ValueVerification> {
    let hay = Forms::of(text);
    values
        .iter()
        .enumerate()
        .map(|(value_index, v)| {
            let needle = Forms::of(v.trim());
            let counts = ladder_counts(&hay, &needle);
            let probes = TEXT_VECTORS
                .iter()
                .zip(counts.iter())
                .map(|(&vector, &n)| ProbeOutcome {
                    vector,
                    residual_found: n > 0,
                    matches: n,
                    mode: None,
                    pages: Vec::new(),
                })
                .collect();
            ValueVerification {
                value_index,
                probes,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PDF verification
// ---------------------------------------------------------------------------

/// Probe a redacted PDF output for each value across the six PDF surfaces (see
/// the module docs for what each covers and what is NOT probed).
///
/// # Errors
///
/// Same fail-closed refusals as the redactor ([`load_pdf_checked`]): empty /
/// oversize / unparseable / encrypted / objectless input. A single bad stream or
/// field inside an otherwise readable PDF is NOT fatal — it is skipped with a
/// content-free diagnostic (reads as NOT PROBED, never as clean). Never panics
/// (a deep lopdf panic is contained to a `Backend` error, mirroring
/// [`scan_pdf`]).
pub fn verify_pdf(pdf: &[u8], values: &[String]) -> CoreResult<PdfVerification> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_pdf_inner(pdf, values)
    }))
    .unwrap_or_else(|_| {
        Err(CoreError::Backend(
            "pdf: parsing panicked on malformed input (contained)".to_string(),
        ))
    })
}

fn verify_pdf_inner(pdf: &[u8], values: &[String]) -> CoreResult<PdfVerification> {
    let doc = load_pdf_checked(pdf)?;
    let needles: Vec<Forms> = values.iter().map(|v| Forms::of(v.trim())).collect();
    let mut diagnostics: Vec<String> = Vec::new();

    // Per value, per surface (PDF_VECTORS order), the running accumulator.
    let mut acc: Vec<[SurfaceAcc; 6]> = (0..needles.len())
        .map(|_| std::array::from_fn(|_| SurfaceAcc::new()))
        .collect();

    // --- Surface 0: strict text layer (the engine's own decoders) -----------
    // A TERMS-ONLY engine: every built-in / context recognizer OFF, the probe
    // values as user terms. scan_pdf then searches the values through the exact
    // decode + whitespace-elastic term machinery the redactor detects with, and
    // ALSO walks annotations + /Info + XMP with that engine (extra recall there
    // is fine — surfaces are independent probes). Its flags are the honesty echo.
    let engine = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .context_recognizers(ContextRecognizers::none())
        .terms(
            values
                .iter()
                .map(|v| v.trim().to_string())
                .filter(|t| !t.is_empty()),
        )
        .build()
        .map_err(|_| CoreError::Backend("verify: could not build the probe engine".to_string()))?;
    let scan = scan_pdf(pdf, &engine)?;
    for item in scan.items() {
        let matched = strip_ws(&item.candidate().matched_value().to_lowercase());
        if matched.is_empty() {
            continue;
        }
        for (vi, needle) in needles.iter().enumerate() {
            // Attribute by whitespace-stripped case-insensitive CONTAINMENT of
            // the needle in the match: a term candidate always covers the FULL
            // term (the literal and ws-elastic term regexes both match the whole
            // term), so equality is the norm and `matched ⊇ needle` covers a
            // match that engulfs the value. The REVERSE direction (needle ⊇
            // matched) is deliberately NOT counted: with many probe values, a
            // short value's ubiquitous hits (a 1-digit value matches everywhere)
            // would be attributed to EVERY longer value containing it — a false
            // residual FLOOD that buries the real findings (the us:dl lesson:
            // noise that drowns signal is not the safe side).
            if needle.ws_strip.is_empty() {
                continue;
            }
            if matched.contains(&needle.ws_strip) {
                acc[vi][0].hit_direct(item.page());
            }
        }
    }
    let flags = PdfVerifyFlags {
        low_text: scan.low_text(),
        unmapped_fonts: scan.unmapped_fonts(),
        degenerate_layout: scan.degenerate_layout(),
    };
    diagnostics.extend(scan.diagnostics().iter().cloned());

    // --- Surface 1: lenient text layer (no font mapping) ---------------------
    probe_lenient_text_layer(&doc, &needles, &mut acc, &mut diagnostics);

    // --- Surface 2: raw bytes ------------------------------------------------
    {
        let raw_text: String = pdf.iter().map(|&b| b as char).collect();
        let hay = Forms::of(&raw_text);
        for (vi, needle) in needles.iter().enumerate() {
            acc[vi][2].fold(ladder_counts(&hay, needle), None);
        }
    }

    // --- Surface 3: every decompressed stream --------------------------------
    probe_decompressed_streams(&doc, &needles, &mut acc, &mut diagnostics);

    // --- Surface 4: annotations ----------------------------------------------
    probe_annotations(&doc, &needles, &mut acc, &mut diagnostics);

    // --- Surface 5: metadata (/Info + XMP) -----------------------------------
    probe_metadata(&doc, &needles, &mut acc, &mut diagnostics);

    // Assemble per-value outcomes in PDF_VECTORS order (mode is meaningless for
    // the strict surface — engine detection, not a text ladder).
    let results = acc
        .into_iter()
        .enumerate()
        .map(|(value_index, surfaces)| {
            let probes = PDF_VECTORS
                .iter()
                .zip(surfaces.iter())
                .enumerate()
                .map(|(si, (&vector, a))| a.outcome(vector, si != 0))
                .collect();
            ValueVerification {
                value_index,
                probes,
            }
        })
        .collect();

    Ok(PdfVerification {
        results,
        flags,
        diagnostics,
    })
}

/// Surface 1: per page, decode each content stream's operations (bounded, shared
/// streams deduped, attributed to the FIRST referencing page like the redactor)
/// and join every show-operator string operand — decoded WITHOUT font mapping
/// ([`decode_annot_string`]: UTF-16BE-BOM else Latin-1) — into one page buffer
/// probed with the ladder. Operand pieces inside one operator join directly (a
/// `TJ` array's kerning splits become adjacent); separate operators join with
/// `\n` (the whitespace-stripped mode still recovers values split across
/// operators).
fn probe_lenient_text_layer(
    doc: &Document,
    needles: &[Forms],
    acc: &mut [[SurfaceAcc; 6]],
    diagnostics: &mut Vec<String>,
) {
    let mut seen: BTreeSet<lopdf::ObjectId> = BTreeSet::new();
    let mut decoded_budget = MAX_TOTAL_DECODED_BYTES;
    let mut skipped = 0usize;
    let mut truncated = false;
    for (page_no, page_id) in doc.get_pages() {
        let mut page_text = String::new();
        for stream_id in doc.get_page_contents(page_id) {
            if !seen.insert(stream_id) {
                continue;
            }
            if decoded_budget == 0 {
                truncated = true;
                break;
            }
            match decode_stream_ops(doc, stream_id, decoded_budget) {
                Ok((operations, _was_compressed, decoded_bytes)) => {
                    decoded_budget = decoded_budget.saturating_sub(decoded_bytes);
                    for op in &operations {
                        if !SHOW_OPERATORS.contains(&op.operator.as_str()) {
                            continue;
                        }
                        let mut emitted = false;
                        for operand in &op.operands {
                            match operand {
                                Object::String(bytes, _) => {
                                    page_text.push_str(&decode_annot_string(bytes));
                                    emitted = true;
                                }
                                Object::Array(elems) => {
                                    for elem in elems {
                                        if let Object::String(bytes, _) = elem {
                                            page_text.push_str(&decode_annot_string(bytes));
                                            emitted = true;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        if emitted {
                            page_text.push('\n');
                        }
                    }
                }
                Err(StreamError::Decode(_) | StreamError::OverBudget(_)) => skipped += 1,
            }
        }
        if !page_text.is_empty() {
            let hay = Forms::of(&page_text);
            for (vi, needle) in needles.iter().enumerate() {
                acc[vi][1].fold(ladder_counts(&hay, needle), Some(page_no));
            }
        }
        if truncated {
            break;
        }
    }
    if skipped > 0 {
        diagnostics.push(format!(
            "verify: lenient text layer — {skipped} content stream(s) not decoded \
             (unsupported filter / over budget); their text was NOT probed"
        ));
    }
    if truncated {
        diagnostics.push(
            "verify: lenient text layer — decoded-bytes budget reached; remaining \
             content streams NOT probed"
                .to_string(),
        );
    }
}

/// Surface 3: inflate EVERY stream object through the capped reader and probe its
/// Latin-1 view. Deterministic (`doc.objects` is a `BTreeMap`); cumulative budget
/// shared across the walk; an undecodable/over-cap stream is counted and
/// diagnosed as NOT probed.
fn probe_decompressed_streams(
    doc: &Document,
    needles: &[Forms],
    acc: &mut [[SurfaceAcc; 6]],
    diagnostics: &mut Vec<String>,
) {
    let mut decoded_budget = MAX_TOTAL_DECODED_BYTES;
    let mut skipped = 0usize;
    let mut truncated = false;
    for (_id, obj) in doc.objects.iter() {
        let Object::Stream(stream) = obj else {
            continue;
        };
        if decoded_budget == 0 {
            truncated = true;
            break;
        }
        let cap = MAX_DECODED_STREAM_BYTES.min(decoded_budget);
        match decode_stream_capped(stream, cap) {
            Ok(bytes) => {
                decoded_budget = decoded_budget.saturating_sub(bytes.len());
                let text: String = bytes.iter().map(|&b| b as char).collect();
                let hay = Forms::of(&text);
                for (vi, needle) in needles.iter().enumerate() {
                    acc[vi][3].fold(ladder_counts(&hay, needle), None);
                }
            }
            Err(StreamError::Decode(_) | StreamError::OverBudget(_)) => skipped += 1,
        }
    }
    if skipped > 0 {
        diagnostics.push(format!(
            "verify: {skipped} stream(s) not decompressed (unsupported filter / over \
             budget); their contents were NOT probed"
        ));
    }
    if truncated {
        diagnostics.push(
            "verify: decompressed-streams budget reached; remaining streams NOT probed".to_string(),
        );
    }
}

/// Collect every string value reachable from a dictionary — its own fields plus
/// nested dicts / references / arrays (annotation `/A`/`/AA` action shapes) to a
/// small fixed depth — into `out`, joined by `\n`. Depth-limited (cycles /
/// hostile nesting) and per-field length-bounded; an over-length field increments
/// `skipped` (probed as NOTHING, diagnosed by the caller — never a silent skip).
fn collect_dict_strings(
    doc: &Document,
    dict: &lopdf::Dictionary,
    depth: usize,
    out: &mut String,
    skipped: &mut usize,
) {
    for (_key, value) in dict.iter() {
        collect_obj_strings(doc, value, depth, out, skipped);
    }
}

fn collect_obj_strings(
    doc: &Document,
    obj: &Object,
    depth: usize,
    out: &mut String,
    skipped: &mut usize,
) {
    match obj {
        Object::String(bytes, _) => {
            if bytes.len() > MAX_ANNOT_FIELD_BYTES {
                *skipped += 1;
            } else {
                out.push_str(&decode_annot_string(bytes));
                out.push('\n');
            }
        }
        Object::Dictionary(d) if depth > 0 => {
            collect_dict_strings(doc, d, depth - 1, out, skipped);
        }
        Object::Reference(id) if depth > 0 => {
            if let Ok(inner) = doc.get_object(*id) {
                // Follow ONE reference hop per level; the depth budget bounds
                // total work even on a reference cycle.
                collect_obj_strings(doc, inner, depth - 1, out, skipped);
            }
        }
        Object::Array(elems) if depth > 0 => {
            for elem in elems {
                collect_obj_strings(doc, elem, depth - 1, out, skipped);
            }
        }
        _ => {}
    }
}

/// Surface 4: every page's `/Annots` (referenced AND inline dicts — the probe is
/// read-only, so it can reach the inline annotations the scrubber structurally
/// cannot address), each annotation's strings collected to depth 3 and probed.
fn probe_annotations(
    doc: &Document,
    needles: &[Forms],
    acc: &mut [[SurfaceAcc; 6]],
    diagnostics: &mut Vec<String>,
) {
    let mut seen: BTreeSet<lopdf::ObjectId> = BTreeSet::new();
    let mut skipped_fields = 0usize;
    let mut capped_pages = 0usize;
    for (page_no, page_id) in doc.get_pages() {
        let Ok(page) = doc.get_dictionary(page_id) else {
            continue;
        };
        let annots = match page.get(ANNOTS_KEY) {
            Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_array).ok(),
            Ok(Object::Array(a)) => Some(a),
            _ => None,
        };
        let Some(annots) = annots else { continue };
        for (visited_this_page, entry) in annots.iter().enumerate() {
            if visited_this_page >= MAX_ANNOTS_PER_PAGE {
                capped_pages += 1;
                break;
            }
            let mut text = String::new();
            match entry {
                Object::Reference(id) => {
                    if !seen.insert(*id) {
                        continue;
                    }
                    if let Ok(dict) = doc.get_object(*id).and_then(Object::as_dict) {
                        collect_dict_strings(doc, dict, 3, &mut text, &mut skipped_fields);
                    }
                }
                Object::Dictionary(dict) => {
                    collect_dict_strings(doc, dict, 3, &mut text, &mut skipped_fields);
                }
                _ => {}
            }
            if !text.is_empty() {
                let hay = Forms::of(&text);
                for (vi, needle) in needles.iter().enumerate() {
                    acc[vi][4].fold(ladder_counts(&hay, needle), Some(page_no));
                }
            }
        }
    }
    if skipped_fields > 0 {
        diagnostics.push(format!(
            "verify: {skipped_fields} over-length annotation field(s) NOT probed \
             (exceeds {MAX_ANNOT_FIELD_BYTES} bytes)"
        ));
    }
    if capped_pages > 0 {
        diagnostics.push(format!(
            "verify: {capped_pages} page(s) exceed {MAX_ANNOTS_PER_PAGE} annotations — \
             annotations beyond the cap were NOT probed"
        ));
    }
}

/// Surface 5: `/Info` string values (each length-bounded) + the catalog XMP
/// `/Metadata` stream (capped decode), joined and probed. No page geometry —
/// `pages` stays empty (the metadata surface is document-level).
fn probe_metadata(
    doc: &Document,
    needles: &[Forms],
    acc: &mut [[SurfaceAcc; 6]],
    diagnostics: &mut Vec<String>,
) {
    let mut text = String::new();
    let mut skipped_fields = 0usize;
    if let Some((_info_id, info)) = crate::pdf::resolve_info(doc) {
        // Deterministic key order (mirrors the scrubber's sorted walk).
        let mut keys: Vec<Vec<u8>> = info.iter().map(|(k, _)| k.clone()).collect();
        keys.sort();
        for key in keys {
            if let Ok(bytes) = info.get(&key).and_then(Object::as_str) {
                if bytes.len() > MAX_ANNOT_FIELD_BYTES {
                    skipped_fields += 1;
                } else {
                    text.push_str(&decode_annot_string(bytes));
                    text.push('\n');
                }
            }
        }
    }
    if let Some((_catalog_id, catalog)) = crate::pdf::resolve_catalog(doc) {
        let stream: Option<&lopdf::Stream> = match catalog.get(METADATA_KEY) {
            Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_stream).ok(),
            Ok(Object::Stream(s)) => Some(s),
            _ => None,
        };
        if let Some(stream) = stream {
            match decode_stream_capped(stream, MAX_DECODED_STREAM_BYTES) {
                Ok(bytes) => {
                    text.push_str(&decode_annot_string(&bytes));
                    text.push('\n');
                }
                Err(_) => diagnostics.push(
                    "verify: XMP /Metadata stream could not be decoded within the cap — \
                     NOT probed"
                        .to_string(),
                ),
            }
        }
    }
    if skipped_fields > 0 {
        diagnostics.push(format!(
            "verify: {skipped_fields} over-length /Info field(s) NOT probed \
             (exceeds {MAX_ANNOT_FIELD_BYTES} bytes)"
        ));
    }
    if !text.is_empty() {
        let hay = Forms::of(&text);
        for (vi, needle) in needles.iter().enumerate() {
            acc[vi][5].fold(ladder_counts(&hay, needle), None);
        }
    }
}

#[cfg(test)]
mod tests;
