// SPDX-License-Identifier: AGPL-3.0-or-later
//! OOXML word-processing (`.docx`) text + metadata extraction.
//!
//! A `.docx` is a ZIP ("OPC") container of XML "parts". The body text lives in
//! `word/document.xml` as `<w:t>` runs grouped into `<w:p>` paragraphs; document
//! properties live in `docProps/core.xml` (`dc:creator`, `cp:lastModifiedBy`,
//! `dcterms:created`, …) and `docProps/app.xml` (`<Application>`).
//!
//! This module is PURE COMPUTE and HOSTILE-INPUT-BOUNDED: a `.docx` is untrusted
//! input (it may be truncated, a ZIP bomb, a deeply-nested XML, or not a docx at
//! all). Every recursive/unbounded dimension is capped (see [`limits`]) and the
//! extractor degrades to a [`warning`](super::ExtractResult::warnings) or a
//! content-free [`super::ExtractError::Malformed`] — it never panics, loops without
//! bound, or allocates without limit. It does NOT execute anything embedded (it is
//! a parser, not a renderer); macros / OLE objects / external relationships are
//! never followed.

use std::io::Read as _;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::{ExtractError, ExtractResult, Metadata};

/// Hard bounds for hostile / adversarial OOXML input. A `.docx` is untrusted: it
/// can be a ZIP bomb (a tiny archive that inflates to gigabytes), declare a huge
/// number of entries, or carry a maliciously deep / enormous `document.xml`.
pub(crate) mod limits {
    /// Largest `.docx` (the raw ZIP bytes) we will open at all. A multi-hundred-MB
    /// "document" is hostile or mis-detected; refuse before touching the ZIP.
    pub const MAX_DOCX_BYTES: usize = 128 * 1024 * 1024;

    /// Cap on the DECOMPRESSED size of any single ZIP part we read (document.xml,
    /// core.xml, app.xml, …). This is the ZIP-bomb guard: we read at most this many
    /// bytes out of the inflater regardless of the entry's declared size, then flag
    /// truncation. 64 MiB of XML is far beyond any real Word document.
    pub const MAX_PART_BYTES: usize = 64 * 1024 * 1024;

    /// Cap on the assembled body text, so a degenerate document declaring a vast
    /// number of tiny runs can't produce unbounded output.
    pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

    /// Maximum XML element nesting we will descend before bailing. quick-xml is a
    /// flat pull parser (no recursion), but we still bound the depth COUNTER so a
    /// pathologically deep tree is reported rather than processed forever.
    pub const MAX_XML_DEPTH: usize = 4096;

    /// Per-metadata-field char cap, so one absurd property value can't bloat
    /// [`super::Metadata`].
    pub const MAX_META_CHARS: usize = 2000;
}

/// Extract text + [`Metadata`] from `.docx` ZIP bytes. See [`super::DocxExtractor`]
/// for the public contract.
///
/// PANIC CONTAINMENT (parity with the PDF path): the third-party `zip` / `quick-xml`
/// parsers are trusted to be panic-free on hostile input, but "never panics on any
/// input" must be a UNIFORM guarantee of THIS crate, not a dependency-trust
/// assumption. So the whole engine runs inside [`std::panic::catch_unwind`]: a panic
/// deep in a parser becomes a content-free [`ExtractError::Malformed`] (NO partial
/// cleartext), never an aborted CORE indexer — exactly as `pdf::extract` does. The
/// closure is unwind-safe: it borrows only `bytes` and returns owned data.
pub(crate) fn extract(
    bytes: &[u8],
    include_annotations: bool,
) -> Result<ExtractResult, ExtractError> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        extract_inner(bytes, include_annotations)
    }));
    match result {
        Ok(r) => r,
        Err(_) => Err(ExtractError::Malformed(
            "docx parsing panicked on malformed input (contained)".to_string(),
        )),
    }
}

/// The actual extraction (may panic deep inside a third-party parser; the caller
/// contains it). On a caught panic the caller returns a content-free `Malformed`.
fn extract_inner(bytes: &[u8], include_annotations: bool) -> Result<ExtractResult, ExtractError> {
    // BOUND 1 (size): refuse an oversized blob BEFORE opening the ZIP. Content-free
    // reason (a byte count, never matter content).
    if bytes.len() > limits::MAX_DOCX_BYTES {
        return Err(ExtractError::Malformed(format!(
            "docx exceeds size limit ({} bytes > {} max)",
            bytes.len(),
            limits::MAX_DOCX_BYTES
        )));
    }

    // Open the ZIP central directory. A truncated / non-ZIP blob fails here with a
    // content-free reason — `zip` returns an Err, it does not panic.
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| {
        ExtractError::Malformed(format!("not a readable .docx (zip) container: {e}"))
    })?;

    let mut warnings: Vec<String> = Vec::new();

    // --- BODY: word/document.xml (required) -------------------------------
    // Read it as decompressed bytes (bomb-bounded), then pull text out. A missing
    // document.xml means this is not a valid word-processing OOXML doc: that is the
    // one fatal case for the body (we still surface it as Malformed, not a panic).
    let (doc_xml, doc_truncated) = match read_part(&mut archive, "word/document.xml") {
        Some(part) => part,
        None => {
            return Err(ExtractError::Malformed(
                "missing word/document.xml — not a valid OOXML word document".to_string(),
            ));
        }
    };
    if doc_truncated {
        warnings.push(format!(
            "word/document.xml exceeded the {}-byte decompression cap and was truncated — body \
             text may be incomplete",
            limits::MAX_PART_BYTES
        ));
    }

    let body = match parse_document_xml(&doc_xml, &mut warnings) {
        Ok(text) => text,
        Err(why) => {
            // A corrupt document.xml is fatal for the body (we have nothing
            // reliable to index). Content-free reason.
            return Err(ExtractError::Malformed(format!(
                "word/document.xml could not be parsed: {why}"
            )));
        }
    };

    // --- METADATA: docProps/core.xml + docProps/app.xml (optional) ---------
    let mut metadata = Metadata::default();
    if let Some((core_xml, truncated)) = read_part(&mut archive, "docProps/core.xml") {
        if truncated {
            warnings.push("docProps/core.xml was truncated at the decompression cap".to_string());
        }
        // Property parsing is best-effort: a corrupt core.xml drops metadata with a
        // warning, never aborts (the body is what matters for the index).
        if let Err(why) = parse_core_props(&core_xml, &mut metadata) {
            warnings.push(format!("docProps/core.xml could not be parsed: {why}"));
        }
    }
    if let Some((app_xml, truncated)) = read_part(&mut archive, "docProps/app.xml") {
        if truncated {
            warnings.push("docProps/app.xml was truncated at the decompression cap".to_string());
        }
        if let Err(why) = parse_app_props(&app_xml, &mut metadata) {
            warnings.push(format!("docProps/app.xml could not be parsed: {why}"));
        }
    }

    // --- LEAK VECTORS a naive "save as text" misses (the whole point) ------
    // We surface (and optionally inline) the parts where confidential content
    // hides. The body text from document.xml already INCLUDES `<w:delText>`
    // tracked-deletion text flagged inline (see parse_document_xml), so a
    // reviewer is never fooled into thinking accepted-then-deleted text is gone.
    let mut body = body;
    let inlined =
        flag_and_maybe_inline_annotations(&mut archive, include_annotations, &mut warnings);
    if !inlined.is_empty() {
        push_bounded(&mut body, &inlined);
    }

    Ok(ExtractResult {
        text: body,
        metadata,
        warnings,
    })
}

/// Read a named ZIP entry, decompressing at most [`limits::MAX_PART_BYTES`].
/// Returns `(utf8_lossy_text, truncated)`, or `None` if the entry is absent. Never
/// panics: a decompression error yields whatever was read so far (best-effort).
///
/// The ZIP-bomb guard is `Read::take(MAX_PART_BYTES + 1)`: we read at most one byte
/// past the cap so we can DETECT (and flag) truncation, regardless of the entry's
/// (attacker-controlled) declared uncompressed size.
fn read_part(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    name: &str,
) -> Option<(String, bool)> {
    // `by_name` returns Err for a missing entry — treat that as "absent", not fatal.
    let file = archive.by_name(name).ok()?;
    let mut limited = file.take(limits::MAX_PART_BYTES as u64 + 1);
    let mut buf: Vec<u8> = Vec::new();
    // read_to_end on a corrupt/lying entry can error mid-stream; keep whatever we
    // got (best-effort) rather than discarding partial-but-useful text.
    let _ = limited.read_to_end(&mut buf);
    let truncated = buf.len() > limits::MAX_PART_BYTES;
    if truncated {
        buf.truncate(limits::MAX_PART_BYTES);
    }
    // OOXML XML is UTF-8; decode lossily so a corrupt byte becomes U+FFFD rather
    // than aborting. The XML declaration may claim another charset, but Word always
    // writes UTF-8 and we never fetch an external charset.
    Some((String::from_utf8_lossy(&buf).into_owned(), truncated))
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

/// The local name of a quick-xml element/end event (the part after any `w:`
/// namespace prefix), as a borrowed `&[u8]`. quick-xml gives us the raw qualified
/// name; OOXML uses the `w:` prefix conventionally, but we match on the LOCAL name
/// so a document declaring the WordprocessingML namespace under a different prefix
/// still parses.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Parse `word/document.xml` into body text.
///
/// Rules (the visible reading order of the document body):
/// - `<w:t>…</w:t>` — a run of literal text. Concatenated verbatim (entities
///   decoded by quick-xml). `xml:space="preserve"` whitespace is honored because we
///   take the text event as-is.
/// - `<w:tab/>` — a tab character.
/// - `<w:br/>` / `<w:cr/>` — a line break (newline).
/// - `</w:p>` — end of a paragraph: emit a newline so paragraphs don't run
///   together.
/// - `<w:delText>…</w:delText>` — TRACKED-DELETION text. This text is STILL PRESENT
///   in the file even after a user "accepted all changes" in the UI; a naive dump
///   that ignores it would hide a confidentiality leak. We INCLUDE it, wrapped in a
///   clear `[deleted: …]` marker so it is never silently blended into the body, and
///   raise a tracked-changes warning (in the caller).
///
/// Hostile-input bounded: the parser is a flat pull loop (no recursion); a depth
/// counter guards against a pathologically deep tree, and the assembled body is
/// capped.
fn parse_document_xml(xml: &str, warnings: &mut Vec<String>) -> Result<String, String> {
    let mut reader = Reader::from_str(xml);
    let cfg = reader.config_mut();
    cfg.trim_text(false); // preserve significant whitespace inside <w:t>.
    cfg.check_end_names = false; // be liberal: don't abort on a mismatched close tag.

    let mut body = String::new();
    let mut depth: usize = 0;
    // True while we are inside a <w:t> (literal text) or <w:delText> (deleted text)
    // element, so a `Text` event is emitted as body content. Other text nodes
    // (whitespace between elements, instrText field codes) are ignored.
    let mut in_text = false;
    let mut in_deltext = false;
    let mut saw_tracked_change = false;
    let mut paragraph_pending = false;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                depth = depth.saturating_add(1);
                if depth > limits::MAX_XML_DEPTH {
                    warnings.push(format!(
                        "word/document.xml nesting exceeds depth limit ({}); deeper structure not \
                         traversed",
                        limits::MAX_XML_DEPTH
                    ));
                    break;
                }
                match local_name(e.name().as_ref()) {
                    b"t" => in_text = true,
                    b"delText" => {
                        in_deltext = true;
                        saw_tracked_change = true;
                        // Open a clear marker so deleted text is never mistaken for
                        // live body text.
                        push_bounded(&mut body, "[deleted: ");
                    }
                    b"ins" | b"del" => saw_tracked_change = true,
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                depth = depth.saturating_sub(1);
                match local_name(e.name().as_ref()) {
                    b"t" => in_text = false,
                    b"delText" => {
                        in_deltext = false;
                        push_bounded(&mut body, "]");
                    }
                    b"p" => {
                        // End of a paragraph -> newline. Defer the actual newline
                        // until the next content so we don't emit trailing blanks.
                        paragraph_pending = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                // Self-closing elements: structural breaks inside a run.
                match local_name(e.name().as_ref()) {
                    b"tab" => push_text(&mut body, "\t", &mut paragraph_pending),
                    b"br" | b"cr" => push_text(&mut body, "\n", &mut paragraph_pending),
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_text || in_deltext {
                    // quick-xml decodes XML entities (&amp; &#NN; …) for us; the
                    // `unescape` returns Cow<str>. On a decode error, fall back to
                    // the raw bytes lossily rather than aborting.
                    let text = match e.unescape() {
                        Ok(cow) => cow.into_owned(),
                        Err(_) => String::from_utf8_lossy(e.as_ref()).into_owned(),
                    };
                    push_text(&mut body, &text, &mut paragraph_pending);
                }
            }
            // CData inside <w:t> is unusual but possible; treat like text.
            Ok(Event::CData(e)) => {
                if in_text || in_deltext {
                    let text = String::from_utf8_lossy(e.as_ref()).into_owned();
                    push_text(&mut body, &text, &mut paragraph_pending);
                }
            }
            Ok(_) => {}
            // A malformed XML token. Be liberal: stop cleanly and keep what we have,
            // flagging the issue — better a partial body than an aborted index.
            Err(e) => {
                warnings.push(format!(
                    "word/document.xml has a malformed XML token; body may be incomplete ({e})"
                ));
                break;
            }
        }
        if body.len() >= limits::MAX_BODY_BYTES {
            warnings.push(format!(
                "document body exceeded the {}-byte cap and was truncated",
                limits::MAX_BODY_BYTES
            ));
            break;
        }
    }

    if saw_tracked_change {
        warnings.push(
            "tracked changes present (revisions): inserted/deleted runs found. Deleted text is \
             STILL in the file even after \"accept all changes\" and is included inline as \
             [deleted: …]"
                .to_string(),
        );
    }

    Ok(body.trim_end().to_string())
}

/// Emit body text, first flushing a pending paragraph break. Keeping the
/// paragraph-newline deferred until real content arrives avoids runs of blank
/// lines from empty paragraphs while still separating paragraphs.
fn push_text(body: &mut String, text: &str, paragraph_pending: &mut bool) {
    if *paragraph_pending {
        if !body.is_empty() {
            push_bounded(body, "\n");
        }
        *paragraph_pending = false;
    }
    push_bounded(body, text);
}

/// Parse `docProps/core.xml` (Dublin Core + cp: properties) into [`Metadata`].
/// Best-effort: a malformed file returns Err (the caller warns + drops metadata).
fn parse_core_props(xml: &str, meta: &mut Metadata) -> Result<(), String> {
    for (local, value) in iter_simple_elements(xml)? {
        let v = clamp_chars(&value, limits::MAX_META_CHARS);
        if v.is_empty() {
            continue;
        }
        match local.as_slice() {
            b"creator" => meta.author.get_or_insert(v),
            b"lastModifiedBy" => meta.last_modified_by.get_or_insert(v),
            b"title" => meta.title.get_or_insert(v),
            b"subject" => meta.subject.get_or_insert(v),
            b"created" => meta.created.get_or_insert(v),
            b"modified" => meta.modified.get_or_insert(v),
            _ => continue,
        };
    }
    Ok(())
}

/// Parse `docProps/app.xml` (extended properties) into [`Metadata::application`].
fn parse_app_props(xml: &str, meta: &mut Metadata) -> Result<(), String> {
    for (local, value) in iter_simple_elements(xml)? {
        let v = clamp_chars(&value, limits::MAX_META_CHARS);
        if v.is_empty() {
            continue;
        }
        if local.as_slice() == b"Application" {
            meta.application.get_or_insert(v);
        }
    }
    Ok(())
}

/// Pull `(local_name, text)` pairs out of a flat OOXML properties document
/// (`<dc:creator>Alice</dc:creator>`, `<Application>…</Application>`). Bounded:
/// stops after a generous element cap so a hostile props file can't produce an
/// unbounded vector. Concatenates a property's text children (rare to have more
/// than one) and decodes entities.
#[allow(clippy::type_complexity)]
fn iter_simple_elements(xml: &str) -> Result<Vec<(Vec<u8>, String)>, String> {
    const MAX_ELEMENTS: usize = 4096;
    let mut reader = Reader::from_str(xml);
    let cfg = reader.config_mut();
    cfg.trim_text(true);
    cfg.check_end_names = false;

    let mut out: Vec<(Vec<u8>, String)> = Vec::new();
    let mut current: Option<(Vec<u8>, String)> = None;
    let mut depth: usize = 0;

    loop {
        if out.len() >= MAX_ELEMENTS {
            break;
        }
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                depth = depth.saturating_add(1);
                if depth > limits::MAX_XML_DEPTH {
                    break;
                }
                // Begin collecting text for this element (only the innermost leaf
                // text is of interest; nested structure just resets the buffer).
                current = Some((local_name(e.name().as_ref()).to_vec(), String::new()));
            }
            Ok(Event::Text(e)) => {
                if let Some((_, buf)) = current.as_mut() {
                    let text = match e.unescape() {
                        Ok(cow) => cow.into_owned(),
                        Err(_) => String::from_utf8_lossy(e.as_ref()).into_owned(),
                    };
                    // Bound a single property value too.
                    if buf.len() < limits::MAX_META_CHARS * 4 {
                        buf.push_str(&text);
                    }
                }
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
                if let Some(pair) = current.take() {
                    if !pair.1.trim().is_empty() {
                        out.push(pair);
                    }
                }
            }
            Ok(_) => {}
            Err(e) => return Err(format!("{e}")),
        }
    }
    Ok(out)
}

/// Detect and (optionally) inline the OOXML annotation parts a body-only sweep
/// misses — comments, footnotes, endnotes — surfacing each as a warning so a
/// reviewer knows the content exists, and inlining it (clearly labeled) only when
/// asked. Tracked-changes deleted text is handled inline in [`parse_document_xml`].
///
/// Returns the labeled inline text to APPEND to the body (empty unless
/// `include_annotations` is set and an annotation part carried text). The caller
/// owns the body and appends this (bounded).
fn flag_and_maybe_inline_annotations(
    archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    include_annotations: bool,
    warnings: &mut Vec<String>,
) -> String {
    // (part name, human label, warning sentence). Comments are the classic
    // candid-internal-commentary leak; footnotes/endnotes are real body content a
    // `<w:t>`-only sweep of document.xml drops entirely — both are surfaced.
    let annotations: [(&str, &str, &str); 3] = [
        (
            "word/comments.xml",
            "comment",
            "comments present ({part}): margin comments in a separate OOXML part a body-only view \
             does not show — often candid internal commentary",
        ),
        (
            "word/footnotes.xml",
            "footnote",
            "footnotes present ({part}): real body content in a separate OOXML part that a \
             document.xml-only text sweep drops",
        ),
        (
            "word/endnotes.xml",
            "endnote",
            "endnotes present ({part}): real body content in a separate OOXML part that a \
             document.xml-only text sweep drops",
        ),
    ];
    let mut inlined = String::new();
    for (part, label, sentence) in annotations {
        let Some((xml, truncated)) = read_part(archive, part) else {
            continue;
        };
        // Reuse the body parser: it pulls <w:t>/<w:delText> the same way these
        // parts store their text. Discard its (annotation-local) warnings.
        let mut scratch: Vec<String> = Vec::new();
        let text = parse_document_xml(&xml, &mut scratch).unwrap_or_default();
        if text.trim().is_empty() && !truncated {
            continue;
        }
        warnings.push(sentence.replace("{part}", part));
        if truncated {
            warnings.push(format!("{part} was truncated at the decompression cap"));
        }
        if include_annotations && !text.trim().is_empty() {
            push_bounded(&mut inlined, &format!("\n\n--- {label}s ---\n"));
            push_bounded(&mut inlined, &text);
        }
    }
    inlined
}

/// Clamp a string to at most `max` characters (char-boundary safe).
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}
