// SPDX-License-Identifier: AGPL-3.0-or-later
//! PDF text + metadata extraction — pure-Rust, deterministic, BEST-EFFORT.
//!
//! Built on the pure-Rust [`lopdf`] crate (MIT). We parse the cross-reference
//! table + page tree, decode each page's content stream (FlateDecode etc. via
//! lopdf), and pull text from the text-showing operators (`Tj` / `'` / `"` / `TJ`),
//! mapping bytes through each page font's `/Encoding` (WinAnsi / MacRoman /
//! Standard + `/Differences`) and `/ToUnicode` CMap where reachable (lopdf's
//! `get_font_encoding` + `decode_text`).
//!
//! ## HONEST first increment — read this before trusting the output
//!
//! PDF text extraction is genuinely hard, and this is a FIRST increment, not a
//! complete engine. What it does NOT yet do (each is SURFACED as a
//! [`warning`](super::ExtractResult::warnings), never silently swallowed):
//! - **Encrypted PDFs** — detected and flagged; NO decryption is attempted (we hold
//!   no password and never write/decrypt). Body text is empty for an encrypted doc.
//! - **Scanned / image-only PDFs** — a page with no text operators (just an image
//!   XObject) has NO text layer; we emit a "needs OCR" warning rather than return
//!   empty as if the page were blank. OCR is the LATER `compute.model` tier, NOT
//!   here.
//! - **Undecodable content streams / unknown font encodings** — a stream lopdf
//!   can't decode, or a font whose encoding we can't resolve, is flagged
//!   (partial-extraction) so the reviewer knows the text is incomplete.
//! - Reading order, columns/tables, ligatures, CID/Type0 composite fonts beyond
//!   what lopdf maps, and embedded-font glyph reconstruction are NOT handled.
//!
//! ## Pure compute, no network, NEVER panics
//!
//! No network, no temp files, no shelling out — `lopdf` parses bytes in-process.
//! lopdf is third-party and CAN panic internally on adversarial input (e.g. its
//! `bytes_to_string` does `String::from_utf16(..).expect(..)`), so the WHOLE
//! extraction runs inside [`std::panic::catch_unwind`]: a panic deep in the parser
//! becomes a content-free [`super::ExtractError::Malformed`], never an aborted CORE
//! indexer. Every unbounded dimension (input size, page count, per-page text,
//! assembled body) is capped (see [`limits`]).
//!
//! ## Decompression-bomb defence — the load-bearing memory bound
//!
//! Two distinct bombs are bounded:
//! - **Operator-tokenization bomb** — a modest decoded stream that explodes into a
//!   multi-GiB `Vec<Operation>` when tokenized. Bounded by the per-page byte check
//!   ([`limits::MAX_PAGE_CONTENT_BYTES`]) BEFORE `Content::decode` runs.
//! - **Raw-flate decompression bomb** — a tiny FlateDecode content stream that
//!   inflates to GiB of RAW BYTES (few/no operators). This OOMs DURING
//!   decompression, before the per-page byte check could ever run, because lopdf's
//!   `get_page_content` → `decompressed_content` inflates via an UNCAPPED
//!   `ZlibDecoder::read_to_end`. We therefore decode each page's content streams
//!   OURSELVES via [`decode_stream_capped`] — a `flate2` reader wrapped in
//!   `Read::take(cap + 1)` — so the per-page budget is enforced AS the stream
//!   inflates, not after. A stream that would exceed the cap is dropped eagerly and
//!   the page is SKIPPED with a warning. Rare/legacy non-Flate content-stream filters
//!   (LZW / ASCII85 / multi-filter / predictor / `DecodeParms`) cannot be capped this
//!   way, so they are REFUSED (skipped-with-warning) rather than routed back through
//!   lopdf's uncapped decoder — a small, fail-closed RECALL tradeoff (see
//!   [`decode_stream_capped`]).

use lopdf::{Document, Object};

use crate::{ExtractError, ExtractResult, Metadata};

/// Hard bounds for hostile / adversarial PDF input.
pub(crate) mod limits {
    /// Largest PDF we will parse at all. Refuse before lopdf touches it.
    pub const MAX_PDF_BYTES: usize = 256 * 1024 * 1024;

    /// Maximum number of pages we will walk. A PDF can declare an enormous page
    /// tree; cap the walk and flag truncation.
    pub const MAX_PAGES: usize = 50_000;

    /// Cap on the assembled body text.
    pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

    /// Per-metadata-field char cap.
    pub const MAX_META_CHARS: usize = 2000;

    /// Cap on the DECODED (FlateDecoded) content stream of a SINGLE page, checked
    /// BEFORE the bytes are tokenized into operators.
    ///
    /// This is the operator-tokenization-bomb guard (the Critical DoS). A page's
    /// content stream is FlateDecoded into a `Vec<u8>` and then `Content::decode`d
    /// into a `Vec<Operation>` where EACH show operator (`(A)Tj`, ~5 input bytes) is
    /// a heap `Operation { operator: String, operands: Vec<Object> }`. A 68 KiB PDF
    /// whose one content stream inflates ~686x to tens of MiB of `(A)Tj` ops drives
    /// the resulting operator vector to MULTIPLE GiB of RSS — an OOM-kill of the core
    /// indexer on a single document. The crate's other caps (`MAX_PDF_BYTES` on the
    /// COMPRESSED input; `MAX_BODY_BYTES` on the OUTPUT text) do not engage until
    /// AFTER that blow-up.
    ///
    /// We therefore decode the page content WITHOUT tokenizing it (via our own
    /// capped [`super::decode_stream_capped`], which FlateDecodes but does NOT build
    /// operators), check its byte length against this cap, and only call
    /// `Content::decode` when the page is in budget. Because every operation needs at
    /// least a few input bytes, this byte cap bounds the operator COUNT (and thus the
    /// operator-vector memory): 8 MiB / ~5 bytes-per-show-op ≈ 1.6M ops, whose
    /// `Vec<Operation>` is on the order of a few hundred MiB worst case — bounded, not
    /// multi-GiB. 8 MiB of a single page's decoded content is already far beyond any
    /// real document page (real legal PDF pages decode to a few hundred KiB), so an
    /// in-budget page is never affected; an over-cap page is SKIPPED with a warning,
    /// never silently dropped or partially extracted.
    ///
    /// CRITICAL: this cap is now also the RAW-FLATE bomb bound. We do NOT call lopdf's
    /// `get_page_content` (whose `ZlibDecoder::read_to_end` is UNCAPPED and would OOM
    /// during decompression of a tiny stream that inflates to GiB). Instead each
    /// stream is decoded through a reader capped at this value, so a decompression
    /// bomb is bounded AS it inflates — peak per-page decoded memory stays ~8 MiB.
    pub const MAX_PAGE_CONTENT_BYTES: usize = 8 * 1024 * 1024;

    /// Cumulative cap on decoded page-content bytes summed ACROSS pages. A single
    /// page can't exceed `MAX_PAGE_CONTENT_BYTES`, but a PDF with tens of thousands
    /// of pages each just under that per-page cap could still sum to a bomb. Once the
    /// running total of decoded content reaches this budget we stop extracting
    /// further pages and warn — so total tokenization work is bounded regardless of
    /// page count. Sized to comfortably cover a large real document while still being
    /// finite.
    pub const MAX_TOTAL_CONTENT_BYTES: usize = 256 * 1024 * 1024;
}

/// Extract text + [`Metadata`] from PDF bytes. See [`super::PdfExtractor`] for the
/// public contract. Runs the real work under `catch_unwind` so a panic inside the
/// third-party parser degrades to a content-free `Malformed`, never a crash.
pub(crate) fn extract(bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
    if bytes.len() > limits::MAX_PDF_BYTES {
        return Err(ExtractError::Malformed(format!(
            "pdf exceeds size limit ({} bytes > {} max)",
            bytes.len(),
            limits::MAX_PDF_BYTES
        )));
    }

    // lopdf is third-party and may panic on crafted input; contain it. The closure
    // is unwind-safe: it borrows only `bytes` and returns owned data.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| extract_inner(bytes)));
    match result {
        Ok(r) => r,
        Err(_) => Err(ExtractError::Malformed(
            "pdf parsing panicked on malformed input (contained)".to_string(),
        )),
    }
}

/// The actual extraction (may panic deep inside lopdf; the caller contains it).
fn extract_inner(bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
    let doc = Document::load_mem(bytes)
        .map_err(|e| ExtractError::Malformed(format!("not a readable PDF: {e}")))?;

    let mut warnings: Vec<String> = Vec::new();
    let metadata = read_metadata(&doc);

    // ENCRYPTED: detect and flag. We never decrypt (no password; we never write).
    // The body is empty — the reviewer must know it's encrypted, not "blank".
    if doc.is_encrypted() {
        warnings.push(
            "PDF is encrypted — text not extracted (no decryption is attempted; this extractor \
             never holds a password or writes/decrypts)"
                .to_string(),
        );
        return Ok(ExtractResult {
            text: String::new(),
            metadata,
            warnings,
        });
    }

    let pages = doc.get_pages(); // BTreeMap<page_no, ObjectId> — deterministic order.
    if pages.is_empty() {
        warnings.push("PDF declares no pages — nothing to extract".to_string());
        return Ok(ExtractResult {
            text: String::new(),
            metadata,
            warnings,
        });
    }

    let mut body = String::new();
    let mut pages_no_text = 0usize; // pages that yielded no text (image-only / empty).
    let mut pages_undecodable = 0usize; // pages whose content stream couldn't be read.
    let mut pages_oversized = 0usize; // pages skipped: decoded content over the per-page cap.
    let mut pages_refused_filter = 0usize; // pages skipped: uncappable filter chain refused.
                                           // Running total of DECODED page-content bytes inspected, so a flood of pages each
                                           // just under the per-page cap can't sum to a tokenization bomb (cumulative guard).
    let mut total_content_bytes: usize = 0;

    for (walked, (_, &page_id)) in pages.iter().enumerate() {
        if walked >= limits::MAX_PAGES {
            warnings.push(format!(
                "page count exceeds the {}-page cap; remaining pages were not extracted",
                limits::MAX_PAGES
            ));
            break;
        }

        // CUMULATIVE-budget guard: stop BEFORE decoding another page once the running
        // total of decoded content has reached the budget. (Checked before the next
        // page's content is fetched so total tokenization work stays bounded.)
        if total_content_bytes >= limits::MAX_TOTAL_CONTENT_BYTES {
            warnings.push(format!(
                "cumulative decoded page-content reached the {}-byte budget; remaining pages were \
                 not extracted (guards against a many-page tokenization bomb)",
                limits::MAX_TOTAL_CONTENT_BYTES
            ));
            break;
        }

        match extract_page_text(&doc, page_id) {
            PageOutcome::Text {
                text,
                content_bytes,
            } => {
                total_content_bytes = total_content_bytes.saturating_add(content_bytes);
                if text.trim().is_empty() {
                    // Content stream decoded but produced no text -> likely an
                    // image-only (scanned) page.
                    pages_no_text += 1;
                } else {
                    if !body.is_empty() {
                        push_bounded(&mut body, "\n");
                    }
                    push_bounded(&mut body, &text);
                }
            }
            // The page's decoded content exceeded the per-page cap; we did NOT tokenize
            // it (that is the bomb). Count its decoded size toward the cumulative budget
            // anyway so an over-cap page still consumes budget rather than being free.
            PageOutcome::Oversized { content_bytes } => {
                total_content_bytes = total_content_bytes.saturating_add(content_bytes);
                pages_oversized += 1;
            }
            PageOutcome::RefusedFilter => pages_refused_filter += 1,
            PageOutcome::Undecodable => pages_undecodable += 1,
        }

        if body.len() >= limits::MAX_BODY_BYTES {
            warnings.push(format!(
                "extracted text exceeded the {}-byte cap and was truncated",
                limits::MAX_BODY_BYTES
            ));
            break;
        }
    }

    // SCANNED / IMAGE-ONLY: if many pages produced no text, the PDF likely has no
    // text layer. Say so explicitly — never return empty as if the doc were blank.
    if pages_no_text > 0 {
        if body.trim().is_empty() {
            warnings.push(format!(
                "no text layer found on any of the {pages_no_text} page(s) inspected: this is \
                 likely a scanned / image-only PDF that needs OCR (OCR is the later compute.model \
                 tier, not this deterministic extractor)"
            ));
        } else {
            warnings.push(format!(
                "{pages_no_text} page(s) produced no text (likely scanned/image-only pages mixed \
                 with text pages); their content needs OCR"
            ));
        }
    }
    if pages_undecodable > 0 {
        warnings.push(format!(
            "{pages_undecodable} page(s) had a content stream that could not be decoded — \
             extracted text is partial"
        ));
    }
    if pages_oversized > 0 {
        warnings.push(format!(
            "{pages_oversized} page(s) had a decoded content stream exceeding the {}-byte \
             per-page cap and were SKIPPED to avoid an operator-tokenization or \
             decompression-bomb memory blow-up — their text was NOT extracted (extracted text \
             is partial)",
            limits::MAX_PAGE_CONTENT_BYTES
        ));
    }
    if pages_refused_filter > 0 {
        warnings.push(format!(
            "{pages_refused_filter} page(s) used a content-stream filter we cannot decode within \
             a memory bound (LZW / ASCII85 / multi-filter / predictor / DecodeParms) and were \
             SKIPPED rather than risk a decompression bomb — their text was NOT extracted \
             (extracted text is partial)"
        ));
    }

    Ok(ExtractResult {
        text: body.trim_end().to_string(),
        metadata,
        warnings,
    })
}

/// What a single page yielded.
enum PageOutcome {
    /// Text was extracted (possibly empty if the page is image-only). `content_bytes`
    /// is the size of the DECODED (FlateDecoded) content stream we inspected, fed
    /// into the cumulative-budget guard.
    Text { text: String, content_bytes: usize },
    /// The page's decoded content exceeded [`limits::MAX_PAGE_CONTENT_BYTES`] — either
    /// the operator-tokenization cap OR the raw-flate decode cap (a decompression
    /// bomb caught mid-inflate). Either way we did NOT tokenize it (the DoS).
    /// `content_bytes` is the decoded bytes we DID accumulate before the cut-off
    /// (charged to the cumulative budget so an over-cap page still consumes budget).
    Oversized { content_bytes: usize },
    /// The page's content stream(s) could not be decoded at all (malformed / garbled
    /// compressed data, or a stream object that isn't a stream).
    Undecodable,
    /// The page used a content-stream filter chain we deliberately REFUSE to decode
    /// because we cannot independently cap its inflation (LZW / ASCII85 / multi-filter
    /// / predictor / `DecodeParms`). Routing it through lopdf's uncapped decoder would
    /// reopen the decompression bomb, so we fail-closed: the page is SKIPPED and the
    /// caller warns. A small, honest RECALL tradeoff for rare/legacy content streams.
    RefusedFilter,
}

/// Extract text from one page by walking the content stream's text-showing
/// operators ourselves, mapping each shown string through the current font's
/// encoding. This mirrors lopdf's own `extract_text_chunks` but stays inside our
/// bounds and lets us treat the per-page outcome (text vs. image-only vs.
/// undecodable) as a diagnostic.
///
/// Operators handled:
/// - `Tf` — set current font (selects the encoding for subsequent shows).
/// - `Tj`, `'`, `"` — show a string. `'` and `"` also move to the next line first.
/// - `TJ` — show an array of strings + numeric adjustments (a large negative
///   adjustment is a word space; lopdf's `collect_text` already inserts one).
/// - `Td`, `TD`, `T*`, `'`, `"` — line/paragraph movement -> newline, so lines
///   don't run together.
/// - `ET` — end text object -> newline.
fn extract_page_text(doc: &Document, page_id: lopdf::ObjectId) -> PageOutcome {
    // Resolve per-font encodings for this page. A missing/odd font dict is not
    // fatal: we fall back to a permissive decode for shows under that font.
    use std::collections::BTreeMap;
    let fonts = doc.get_page_fonts(page_id);
    let encodings: BTreeMap<Vec<u8>, lopdf::Encoding> = match fonts {
        Ok(fonts) => fonts
            .into_iter()
            .filter_map(|(name, font)| font.get_font_encoding(doc).ok().map(|enc| (name, enc)))
            .collect(),
        Err(_) => BTreeMap::new(),
    };

    // Get the DECODED (FlateDecoded) page content as RAW BYTES, WITHOUT tokenizing it
    // into operators. This is the load-bearing split that bounds BOTH bombs:
    //
    // 1. Operator-tokenization bomb — `Content::decode` builds an UNBOUNDED
    //    `Vec<Operation>`; we stop at the byte buffer and check ITS length first.
    // 2. Raw-flate decompression bomb — lopdf's `get_page_content` →
    //    `decompressed_content` inflates each stream via an UNCAPPED
    //    `ZlibDecoder::read_to_end`, so a tiny stream that FlateDecodes to GiB of raw
    //    bytes OOMs DURING decompression, before any size could be observed. We do
    //    NOT call it; instead we decode each of the page's content streams ourselves
    //    through `decode_stream_capped`, which bounds the inflate AS it happens.
    //
    // A page may have MULTIPLE content streams (an array); we concatenate them like
    // lopdf does, but bound the RUNNING total at the per-page cap so the sum cannot
    // overshoot. We read one stream's headroom = (cap + 1) - already-accumulated, so
    // crossing the cap is detected the moment it happens and the page is skipped.
    let stream_ids = doc.get_page_contents(page_id);
    let mut content_data: Vec<u8> = Vec::new();
    for stream_id in stream_ids {
        let stream = match doc.get_object(stream_id).and_then(Object::as_stream) {
            Ok(s) => s,
            // A content-stream object that isn't a stream: skip it (mirrors lopdf's
            // own `get_page_content`, which silently skips non-stream entries).
            Err(_) => continue,
        };
        // Headroom against the per-page cap. `+ 1` so we can read ONE byte past the
        // cap and reliably distinguish "exactly at cap" from "over".
        let headroom = limits::MAX_PAGE_CONTENT_BYTES
            .saturating_add(1)
            .saturating_sub(content_data.len());
        match decode_stream_capped(stream, headroom) {
            DecodeOutcome::Decoded(bytes) => content_data.extend_from_slice(&bytes),
            // Over the per-page cap (a decompression bomb caught mid-inflate, or an
            // over-large raw stream). Charge what we accumulated to the cumulative
            // budget and skip the page, never partial-extract. We free the partial
            // page buffer eagerly so peak memory stays bounded.
            DecodeOutcome::OverBudget => {
                let content_bytes = content_data.len();
                drop(content_data);
                return PageOutcome::Oversized { content_bytes };
            }
            // A filter chain we refuse to decode (cannot cap its inflation). Fail
            // closed: skip the page with a distinct warning (the recall tradeoff).
            DecodeOutcome::RefusedFilter => return PageOutcome::RefusedFilter,
            // Garbled/undecodable compressed data: skip the page.
            DecodeOutcome::Undecodable => return PageOutcome::Undecodable,
        }
        // Belt-and-braces: the running total can equal cap+1 if the last stream filled
        // exactly to the boundary; treat that as over-budget too.
        if content_data.len() > limits::MAX_PAGE_CONTENT_BYTES {
            let content_bytes = content_data.len();
            drop(content_data);
            return PageOutcome::Oversized { content_bytes };
        }
    }
    let content_bytes = content_data.len();

    // In budget: NOW it is safe to tokenize the (bounded) byte buffer into operators.
    let content = match lopdf::content::Content::decode(&content_data) {
        Ok(c) => c,
        Err(_) => return PageOutcome::Undecodable,
    };
    // The decoded bytes are no longer needed once tokenized; drop early to keep peak
    // memory to one copy (operator vector) rather than two.
    drop(content_data);

    let mut text = String::new();
    let mut current_encoding: Option<&lopdf::Encoding> = None;

    // Append a single line break only when the text is non-empty and does not
    // already end with one (deduped from the Td/TD/T*, '/", and ET arms — a sole
    // `if` inside a match arm trips clippy::collapsible_match on newer toolchains).
    let break_line = |text: &mut String| {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
    };

    for op in &content.operations {
        match op.operator.as_str() {
            "Tf" => {
                current_encoding = op
                    .operands
                    .first()
                    .and_then(|o| o.as_name().ok())
                    .and_then(|name| encodings.get(name));
            }
            "Td" | "TD" | "T*" => break_line(&mut text),
            "Tj" | "TJ" => {
                show_operands(&mut text, current_encoding, &op.operands);
            }
            // `'` = move to next line then show; `"` = set spacing, move to next
            // line, then show. Both take the string as the LAST operand.
            "'" | "\"" => {
                break_line(&mut text);
                show_operands(&mut text, current_encoding, &op.operands);
            }
            "ET" => break_line(&mut text),
            _ => {}
        }
        if text.len() >= limits::MAX_BODY_BYTES {
            break;
        }
    }

    PageOutcome::Text {
        text,
        content_bytes,
    }
}

/// The result of decoding ONE content stream through the capped reader.
enum DecodeOutcome {
    /// Fully decoded; `bytes.len()` is within the requested cap.
    Decoded(Vec<u8>),
    /// Decoding would exceed the cap (a decompression bomb caught mid-inflate, or an
    /// over-large unfiltered/raw stream). The partial buffer is dropped eagerly.
    OverBudget,
    /// A filter chain we deliberately REFUSE to decode (cannot independently cap it):
    /// LZW / ASCII85 / multi-filter / predictor / `DecodeParms`.
    RefusedFilter,
    /// Unsupported/garbled filter or malformed compressed data.
    Undecodable,
}

/// Decode one PDF content stream's RAW bytes through a CAPPED reader so a
/// decompression bomb cannot inflate unboundedly DURING decompression.
///
/// This is the raw-flate-bomb defence. lopdf's `Stream::decompressed_content` (used
/// by `get_page_content`) inflates `FlateDecode` via `ZlibDecoder::read_to_end` with
/// NO cap, so a tiny stream that FlateDecodes to GiB of raw bytes OOMs before any
/// size could be observed. We instead decode the raw stream ourselves through a
/// `flate2` reader wrapped in `Read::take(cap as u64)`: the read stops at the cap, so
/// peak allocation is bounded to ~`cap`. The caller passes `cap = headroom` (the
/// per-page byte budget remaining); reading exactly up to `cap` (= per-page cap + 1)
/// lets the caller detect "over the per-page cap" by length.
///
/// Filter handling — DELIBERATELY NARROW (a fail-closed RECALL tradeoff):
/// - **No `/Filter`** (or `/Filter []`): the stream is already raw bytes — length-check
///   against the cap and return them (an enormous unfiltered stream is refused too).
/// - **Pure single `FlateDecode` with NO `DecodeParms`**: decoded through the cap.
/// - **Anything else** (LZW / ASCII85 / multi-filter chain / predictor / any
///   `DecodeParms`): REFUSED. We cannot independently cap their inflation here, and
///   routing them back through lopdf's UNCAPPED `decompressed_content` would reopen
///   the very bomb we are closing. Such content streams are rare/legacy, so flagging
///   them as not-fully-extracted (the page is skipped + warned) is the honest,
///   fail-closed choice rather than risking an OOM of the CORE indexer. Determinism is
///   preserved: the same bytes always decode to the same result (or the same refusal).
fn decode_stream_capped(stream: &lopdf::Stream, cap: usize) -> DecodeOutcome {
    use std::io::Read;

    // The raw, still-compressed (or raw, if unfiltered) stream bytes.
    let raw: &[u8] = stream.content.as_slice();

    // Resolve the filter chain. No `/Filter` => uncompressed: bound the raw length
    // directly. (lopdf's `filters()` returns Err when `/Filter` is absent.)
    let filters = match stream.filters() {
        Ok(f) => f,
        Err(_) => {
            if raw.len() > cap {
                return DecodeOutcome::OverBudget;
            }
            return DecodeOutcome::Decoded(raw.to_vec());
        }
    };
    if filters.is_empty() {
        // `/Filter []` — effectively uncompressed.
        if raw.len() > cap {
            return DecodeOutcome::OverBudget;
        }
        return DecodeOutcome::Decoded(raw.to_vec());
    }

    // We cap ONLY pure single-FlateDecode with NO predictor/DecodeParms. Anything
    // else is refused (see the doc comment) so the bound stays provable.
    let is_pure_flate = filters.len() == 1 && filters[0] == b"FlateDecode";
    let has_decode_parms = stream.dict.get(b"DecodeParms").is_ok();
    if !is_pure_flate || has_decode_parms {
        return DecodeOutcome::RefusedFilter;
    }

    // Capped FlateDecode. `take(cap as u64)` stops the read at the cap, bounding peak
    // allocation to ~cap. The caller sets `cap = per-page cap + 1`, so a full read of
    // `cap` bytes is exactly the "one past the per-page cap" signal it length-checks.
    let limit = cap as u64;
    let mut out: Vec<u8> = Vec::new();
    let read_result = {
        let mut decoder = flate2::read::ZlibDecoder::new(raw).take(limit);
        decoder.read_to_end(&mut out)
    };
    if read_result.is_err() {
        // Zlib failed — retry raw deflate (skip the 2-byte zlib header), mirroring
        // lopdf's own fallback for corrupt-adler / non-spec streams, STILL through the
        // cap so the bomb stays bounded on the fallback path too.
        out.clear();
        out.shrink_to_fit();
        if raw.len() > 2 {
            let mut raw_decoder = flate2::read::DeflateDecoder::new(&raw[2..]).take(limit);
            if raw_decoder.read_to_end(&mut out).is_err() {
                return DecodeOutcome::Undecodable;
            }
        } else {
            return DecodeOutcome::Undecodable;
        }
    }
    if out.len() as u64 >= limit {
        // We filled the reader to its limit (= per-page cap + 1): the real decoded
        // size is at/over the cap. Free the buffer eagerly and report over-budget.
        drop(out);
        return DecodeOutcome::OverBudget;
    }
    DecodeOutcome::Decoded(out)
}

/// Append the text of a show operator's operands, decoding each `Object::String`
/// through the current font encoding (or a permissive fallback). Handles the `TJ`
/// array form (strings interleaved with numeric kerning adjustments).
fn show_operands(text: &mut String, encoding: Option<&lopdf::Encoding>, operands: &[Object]) {
    for operand in operands {
        match operand {
            Object::String(bytes, _) => push_bounded(text, &decode_string(encoding, bytes)),
            Object::Array(arr) => {
                for inner in arr {
                    match inner {
                        Object::String(bytes, _) => {
                            push_bounded(text, &decode_string(encoding, bytes));
                        }
                        // A large negative adjustment in a TJ array is an inter-word
                        // gap; render it as a space so words don't fuse.
                        Object::Integer(i) if *i < -100 => push_bounded(text, " "),
                        Object::Real(r) if *r < -100.0 => push_bounded(text, " "),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Decode a shown string's bytes to text. With a known font encoding, use lopdf's
/// `decode_text` (WinAnsi / MacRoman / Standard / `/Differences` / ToUnicode). If
/// that fails or there is no encoding, fall back to a permissive Latin-1-style
/// single-byte decode of the printable bytes — best-effort, never a panic. (lopdf's
/// own decoder can panic; the page is already inside the outer `catch_unwind`, but
/// we also guard the most common panic path by catching here so ONE bad string
/// doesn't lose the whole page.)
fn decode_string(encoding: Option<&lopdf::Encoding>, bytes: &[u8]) -> String {
    if let Some(enc) = encoding {
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Document::decode_text(enc, bytes)
        }));
        if let Ok(Ok(s)) = decoded {
            return s;
        }
    }
    // Fallback: treat bytes as Latin-1 (the WinAnsi/PDFDoc printable range overlaps
    // Latin-1), dropping control bytes. Honest and lossy, but never empty/garbled
    // for plain ASCII/Latin text and never a panic.
    bytes
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || b >= 0x20)
        .map(|&b| b as char)
        .collect()
}

/// Read the PDF document information dictionary (the trailer `/Info`) into
/// [`Metadata`]. Best-effort: any missing/odd field is simply skipped.
fn read_metadata(doc: &Document) -> Metadata {
    let mut meta = Metadata::default();
    // The /Info dictionary is referenced from the trailer.
    let info = doc
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|o| match o {
            Object::Reference(id) => doc.get_object(*id).ok(),
            other => Some(other),
        })
        .and_then(|o| o.as_dict().ok());

    let Some(info) = info else {
        return meta;
    };

    let get = |key: &[u8]| -> Option<String> {
        info.get(key)
            .ok()
            .and_then(pdf_string_to_utf8)
            .map(|s| clamp_chars(&s, limits::MAX_META_CHARS))
            .filter(|s| !s.trim().is_empty())
    };

    meta.author = get(b"Author");
    meta.title = get(b"Title");
    meta.subject = get(b"Subject");
    meta.created = get(b"CreationDate");
    meta.modified = get(b"ModDate");
    // Producer / Creator both map to the application/provenance field; prefer
    // Producer (the generating library), fall back to Creator (the authoring app).
    meta.application = get(b"Producer").or_else(|| get(b"Creator"));
    meta
}

/// Convert a PDF string [`Object`] to a UTF-8 [`String`]. PDF text strings are
/// either PDFDocEncoding (single-byte, ASCII-compatible for the printable range)
/// or UTF-16BE with a `FE FF` byte-order mark. Handles both; lossy and bounded.
fn pdf_string_to_utf8(obj: &Object) -> Option<String> {
    let Object::String(bytes, _) = obj else {
        return None;
    };
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        // UTF-16BE with BOM.
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        // PDFDocEncoding ~ Latin-1 for the printable range; drop control bytes.
        Some(
            bytes
                .iter()
                .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || b >= 0x20)
                .map(|&b| b as char)
                .collect(),
        )
    }
}

/// Append `s` to `out` up to [`limits::MAX_BODY_BYTES`] (char-boundary safe).
fn push_bounded(out: &mut String, s: &str) {
    let remaining = limits::MAX_BODY_BYTES.saturating_sub(out.len());
    if remaining == 0 {
        return;
    }
    if s.len() <= remaining {
        out.push_str(s);
    } else {
        let mut cut = remaining;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        out.push_str(&s[..cut]);
    }
}

/// Clamp a string to at most `max` characters (char-boundary safe).
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}
