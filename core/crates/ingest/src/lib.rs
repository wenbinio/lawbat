// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Ingest — the trusted CORE-PLANE document + email ingestion jobs.
//!
//! Two sibling producers that land matter documents the trusted core then mediates:
//!
//! 1. **Body** ([`ingest_document_text`]): RUN [`extract`] over ANY supported file
//!    (`.eml`/`.msg`/`.docx`/`.pdf`) and land its extracted plain-text body in the
//!    matter store under [`DataClass::Document`] — the text a consumer (the inbox)
//!    reads via `runtime::Core::matter_read_text` and triages.
//! 2. **Metadata** ([`ingest_email_metadata`]): the producer end of the
//!    `matter.read:metadata` seam — serialize an email's recovered
//!    [`extract::EmailMetadata`] into the `firmos.meta/1` canonical form (extract's
//!    [`extract::to_canonical`]) and land it under [`DataClass::Metadata`], so
//!    `runtime::Core::matter_read_metadata` hands a consumer already-parsed, typed
//!    `runtime::EmailHeaders` instead of re-parsing RFC 822 itself.
//!
//! [`ingest_email`] runs BOTH in one pass over a single `extract` parse: one `.eml`
//! becomes a `document` body doc + a `metadata` headers doc.
//!
//! ```text
//!   mailbox (fetch .eml)  ->  ingest (THIS: extract -> body doc + metadata doc)
//!         body  -> Core::matter_read_text     -> inbox (triage)
//!         meta  -> Core::matter_read_metadata -> typed EmailHeaders
//! ```
//!
//! ## Why this is CORE-PLANE, not a module (spec §6)
//!
//! The indexer/walker is a CORE responsibility — modules get NO raw filesystem /
//! matter-store access. Ingestion is the same: it POPULATES the matter store the
//! trusted host owns BEFORE that store is moved into a [`runtime::Core`]. So this
//! job writes through the trusted seeding path
//! ([`runtime::InMemoryMatterStore::insert`]) — it does **NOT** use a mediated
//! `matter.write` module capability. `matter.write` is the spec's one-way-door
//! taxonomy item with NO mediated `Core` method yet (CLAUDE.md: "do NOT YOLO"); a
//! TRUSTED, audited `Core` ingestion seam is a deliberate later design step (it
//! intersects the audit-persistence gate), not invented here.
//!
//! It is deliberately SEPARATE from [`mailbox`-the-connector] which holds the ONE
//! `egress:<named>` grant and explicitly disclaims matter-store access. This job has
//! the OPPOSITE posture: it writes the matter store and holds NO egress.
//!
//! [`mailbox`-the-connector]: https://example.invalid/  "the mailbox crate"
//!
//! ## F-1 graceful degradation (review F-1 — the load-bearing correctness guard)
//!
//! The reader (`runtime::parse_email_headers`) REFUSES a canonical form over
//! [`runtime::MAX_CANONICAL_BYTES`] (256 KiB) fail-closed, and
//! `Core::matter_read_metadata` PROPAGATES that `Err` — so an over-cap doc makes the
//! WHOLE message's metadata unreadable, not just the offending field. This is not
//! theoretical: [`extract`] caps each recipient list at 256 addresses and each value
//! at ~200 chars, but 256 × 5 fields × (long display names, percent-expanded up to
//! 3×) can still cross 256 KiB. So a hostile `.eml` with many long-display-name
//! recipients would otherwise serialize to an UNREADABLE doc.
//!
//! This job therefore CLAMPS: it guarantees the produced canonical form is
//! `<= MAX_CANONICAL_BYTES` (so the reader always accepts it), preserving as much as
//! possible and SURFACING every clamp as a warning, rather than emitting an
//! all-or-nothing-unreadable doc. The clamp is engaged ONLY when the full
//! serialization is over the cap — under the cap the output is
//! [`extract::to_canonical`] VERBATIM (byte-identical; zero drift from the shared
//! producer). See [`serialize_metadata`].
//!
//! F-1 is METADATA-specific: only the `firmos.meta/1` reader caps its input. A
//! `document`-class BODY doc has NO canonical-form reader cap, so body ingestion does
//! NOT clamp — extract's own `MAX_BODY_BYTES` (32 MiB) already bounds the body text.
//!
//! ## Confidentiality (mirrors redaction/inbox/mailbox)
//!
//! Email headers ARE matter data (addresses / subject / **Bcc**). Every warning this
//! job emits is CLEARTEXT-FREE — field TAGS + COUNTS / byte numbers only, NEVER an
//! address / subject / Bcc value. (extract's own warnings, surfaced too, are
//! likewise structural — "bcc recipients present (N)", "recipient list(s) truncated
//! at the cap", "date header present but did not parse".) The canonical bytes flow
//! into the matter store; from there ONLY the mediated, audited
//! `Core::matter_read_metadata` reaches them, and even it logs counts only.
//!
//! Everything here is pure, deterministic, std-only orchestration that NEVER panics
//! on any input — the clamp operates at the BYTE/char level (it can never slice a
//! multi-byte codepoint, the Critical-bug class the `.eml` extractor already hit).

use extract::{percent_encode, to_canonical, EmailMetadata, ExtractError, ExtractResult};
use runtime::{DataClass, InMemoryMatterStore, MAX_CANONICAL_BYTES};

/// Per-VALUE encoded byte cap used ONLY on the clamp path (when the full
/// serialization is already over [`MAX_CANONICAL_BYTES`]). It bounds any single
/// field's contribution so one pathological value (a control-stuffed subject, a
/// single 100 KiB display name) can never starve the others out of the budget. 8
/// KiB is far above any realistic single header value (a subject / address is well
/// under 1 KiB) while leaving room for the small high-signal fields. It is NEVER
/// applied on the under-cap path (which returns [`to_canonical`] verbatim), so a
/// legitimate-but-long value is only ever touched when the doc is ALREADY too big.
const MAX_VALUE_BYTES: usize = 8 * 1024;

/// The version line every `firmos.meta/1` document opens with (mirrors extract's
/// and runtime's `VERSION_TAG`, with the line terminator). Always fits the cap.
const VERSION_LINE: &str = "firmos.meta/1\n";

/// A built `firmos.meta/1` metadata document, ready to land in the matter store.
///
/// `canonical` is GUARANTEED `<= runtime::MAX_CANONICAL_BYTES`, so the reader
/// (`runtime::parse_email_headers` / `Core::matter_read_metadata`) always accepts
/// it. `warnings` is CLEARTEXT-FREE (field tags + counts only) — see the crate docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltDoc {
    /// The serialized `firmos.meta/1` canonical form (`<= MAX_CANONICAL_BYTES`).
    pub canonical: String,
    /// Whether F-1 clamping was engaged (the full serialization was over the cap).
    pub clamped: bool,
    /// Non-fatal, CLEARTEXT-FREE warnings: the F-1 clamp notes (field tags + counts)
    /// plus, when built via [`build_email_metadata_doc`], extract's own structural
    /// warnings (Bcc presence, truncated recipient lists, unparseable date).
    pub warnings: Vec<String>,
}

/// The outcome of landing one doc in the matter store (body OR metadata).
/// Counts/attribution only — carries NO content value (the bytes live in the store,
/// reached only through the mediated reader).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestReport {
    /// The id the doc was inserted under (the caller's choice; opaque to the store).
    pub doc_id: u64,
    /// The class the doc was landed under: [`DataClass::Document`] for a body doc,
    /// [`DataClass::Metadata`] for a `firmos.meta/1` headers doc.
    pub class: DataClass,
    /// The byte length of the landed doc — the body text length, or the canonical
    /// metadata length (`<= MAX_CANONICAL_BYTES`). A count, never the content.
    pub doc_bytes: usize,
    /// Whether F-1 clamping was engaged. METADATA-ONLY — always `false` for a body
    /// doc (a `document`-class doc has no canonical-form reader cap; see the crate
    /// docs).
    pub clamped: bool,
    /// CLEARTEXT-FREE warnings (see [`BuiltDoc::warnings`]).
    pub warnings: Vec<String>,
}

/// The outcome of [`ingest_email`]: the two docs one `.eml`/`.msg` produces — the
/// `document`-class BODY and the `metadata`-class headers — landed under distinct
/// ids in one `extract` pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailIngest {
    /// The landed body doc ([`DataClass::Document`]); its `warnings` carry extract's
    /// (cleartext-free) extraction warnings.
    pub body: IngestReport,
    /// The landed metadata doc ([`DataClass::Metadata`]); its `warnings` carry the
    /// F-1 clamp notes (also cleartext-free).
    pub metadata: IngestReport,
}

/// Why an ingestion could not produce a metadata doc. CONTENT-FREE: no variant
/// carries an address / subject / body — extract's own error strings are documented
/// to exclude matter content, and [`IngestError::NotEmail`] carries nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// Extraction failed outright (corrupt container, unsupported/empty file). Wraps
    /// extract's content-free [`ExtractError`].
    Extract(ExtractError),
    /// The file extracted successfully but is NOT an email (no email header block —
    /// e.g. a `.docx`/`.pdf`). There is no metadata doc to land; ingest the BODY via
    /// [`ingest_document_text`] instead.
    NotEmail,
    /// [`ingest_email`] was given the SAME id for the body and the metadata doc.
    /// The store is keyed by id (last-write-wins), so landing both under one id would
    /// SILENTLY drop the first — refused fail-closed BEFORE anything is landed, so a
    /// caller bug can never lose a doc (mirrors the mailbox staging-key collision
    /// fix). Carries no content.
    DuplicateDocId,
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Extract(e) => write!(f, "ingest: extraction failed: {e}"),
            IngestError::NotEmail => {
                f.write_str("ingest: not an email (no header block to serialize)")
            }
            IngestError::DuplicateDocId => {
                f.write_str("ingest: body and metadata doc ids must differ")
            }
        }
    }
}

impl std::error::Error for IngestError {}

/// Serialize [`EmailMetadata`] to a `firmos.meta/1` [`BuiltDoc`], applying F-1
/// graceful degradation. PURE (no extract, no store) so it is the directly-testable
/// F-1 entry point and is reusable by any caller that already holds an
/// `EmailMetadata`.
///
/// - **Under the cap (the overwhelmingly common path):** returns
///   [`to_canonical`]`(meta)` VERBATIM — `clamped == false`, no warnings, byte-
///   identical to extract's shared producer (zero drift).
/// - **Over the cap:** rebuilds within a [`MAX_CANONICAL_BYTES`] budget, reserving
///   the small high-signal fields first (date, message-id, subject) then the
///   recipient lists (from, to, cc, bcc, reply-to), truncating list TAILS and giant
///   single VALUES to fit, and SURFACING every clamp as a cleartext-free warning.
///   The result is GUARANTEED `<= MAX_CANONICAL_BYTES`, so the reader accepts it.
pub fn serialize_metadata(meta: &EmailMetadata) -> BuiltDoc {
    let full = to_canonical(meta);
    if full.len() <= MAX_CANONICAL_BYTES {
        // The common path: emit the shared producer's output verbatim. No drift,
        // no clamp, no warnings.
        return BuiltDoc {
            canonical: full,
            clamped: false,
            warnings: Vec::new(),
        };
    }
    let (canonical, warnings) = clamp_to_canonical(meta);
    BuiltDoc {
        canonical,
        clamped: true,
        warnings,
    }
}

/// Run [`extract`] over `bytes`, dispatched by `filename`'s extension. Maps a
/// failure to [`IngestError::Extract`]. The single parse point shared by all jobs.
fn run_extract(filename: &str, bytes: &[u8]) -> Result<ExtractResult, IngestError> {
    extract::extract(filename, bytes).map_err(IngestError::Extract)
}

/// Build the metadata [`BuiltDoc`] from an ALREADY-EXTRACTED result (F-1 clamp
/// warnings ONLY — the caller decides whether to also surface extract's warnings).
/// [`IngestError::NotEmail`] if the result has no email header block.
fn metadata_doc(result: &ExtractResult) -> Result<BuiltDoc, IngestError> {
    let email = result
        .metadata
        .email
        .as_ref()
        .ok_or(IngestError::NotEmail)?;
    Ok(serialize_metadata(email))
}

/// Run [`extract`] over `bytes` (dispatched by `filename` — `.eml`/`.msg`), then
/// [`serialize_metadata`] the recovered email headers. Extract's own cleartext-free
/// warnings are appended after the clamp warnings.
///
/// Returns [`IngestError::Extract`] if extraction fails, or [`IngestError::NotEmail`]
/// if the file is not an email (no header block). Never panics.
pub fn build_email_metadata_doc(filename: &str, bytes: &[u8]) -> Result<BuiltDoc, IngestError> {
    let result = run_extract(filename, bytes)?;
    let mut built = metadata_doc(&result)?;
    // Standalone metadata ingestion has no body report to hold extract's structural
    // (cleartext-free) warnings, so surface them here, AFTER the clamp warnings.
    built.warnings.extend(result.warnings);
    Ok(built)
}

/// The full METADATA ingestion job: [`build_email_metadata_doc`] then LAND the doc in
/// `store` under [`DataClass::Metadata`] at `doc_id`, via the trusted seeding path
/// (`store.insert`). Returns an [`IngestReport`] (counts/attribution only).
///
/// This is the trusted CORE-PLANE write: the host owns `store` here, before moving
/// it into a [`runtime::Core`]; from then on the doc is reachable ONLY through the
/// mediated, audited `Core::matter_read_metadata`. See the crate docs on why this is
/// not a `matter.write` module path.
pub fn ingest_email_metadata(
    store: &mut InMemoryMatterStore,
    doc_id: u64,
    filename: &str,
    bytes: &[u8],
) -> Result<IngestReport, IngestError> {
    let built = build_email_metadata_doc(filename, bytes)?;
    let doc_bytes = built.canonical.len();
    let clamped = built.clamped;
    let warnings = built.warnings;
    // Trusted seeding path (NOT a mediated module write). The (id, Metadata, Text)
    // doc is exactly what `Core::matter_read_metadata` reads back.
    store.insert(doc_id, DataClass::Metadata, built.canonical);
    Ok(IngestReport {
        doc_id,
        class: DataClass::Metadata,
        doc_bytes,
        clamped,
        warnings,
    })
}

/// The BODY ingestion job: RUN [`extract`] over `bytes` (ANY supported format —
/// `.eml`/`.msg`/`.docx`/`.pdf`) and LAND its extracted plain-text body in `store`
/// under [`DataClass::Document`] at `doc_id`, via the trusted seeding path. Returns
/// an [`IngestReport`] whose `clamped` is always `false` (a body doc has no reader
/// cap — extract's `MAX_BODY_BYTES` bounds it) and whose `warnings` carry extract's
/// (cleartext-free) extraction warnings ("scanned PDF — no text layer", "bcc present").
///
/// A doc with an EMPTY body (e.g. a scanned PDF with no text layer) is still landed —
/// honest, never fabricated — and the empty/needs-OCR condition is surfaced via the
/// warnings, not hidden. This is the doc the inbox reads via `Core::matter_read_text`.
pub fn ingest_document_text(
    store: &mut InMemoryMatterStore,
    doc_id: u64,
    filename: &str,
    bytes: &[u8],
) -> Result<IngestReport, IngestError> {
    let result = run_extract(filename, bytes)?;
    let doc_bytes = result.text.len();
    // Trusted seeding path. The (id, Document, Text) doc is exactly what
    // `Core::matter_read_text` / the inbox read back.
    store.insert(doc_id, DataClass::Document, result.text);
    Ok(IngestReport {
        doc_id,
        class: DataClass::Document,
        doc_bytes,
        clamped: false,
        warnings: result.warnings,
    })
}

/// Ingest one `.eml`/`.msg` as BOTH a `document` BODY doc (at `body_id`) and a
/// `metadata` headers doc (at `meta_id`), in a SINGLE [`extract`] pass — the natural
/// email-pipeline step (mailbox → ingest → inbox).
///
/// FAIL-CLOSED, no half-ingest:
/// - `body_id` and `meta_id` MUST differ (else the store's last-write-wins would
///   silently drop one) — [`IngestError::DuplicateDocId`] is returned BEFORE anything
///   is landed.
/// - A non-email file returns [`IngestError::NotEmail`] BEFORE the body is landed (the
///   metadata is built first), so a non-email never leaves a half-ingested body.
///
/// Warning attribution (no duplication): the BODY report carries extract's extraction
/// warnings; the METADATA report carries the F-1 clamp warnings. Both cleartext-free.
pub fn ingest_email(
    store: &mut InMemoryMatterStore,
    body_id: u64,
    meta_id: u64,
    filename: &str,
    bytes: &[u8],
) -> Result<EmailIngest, IngestError> {
    if body_id == meta_id {
        return Err(IngestError::DuplicateDocId);
    }
    let result = run_extract(filename, bytes)?;
    // Build the metadata FIRST so a non-email (NotEmail) aborts BEFORE we land a body
    // doc — no half-ingested state on the not-an-email path.
    let meta_built = metadata_doc(&result)?;

    // Land the BODY (Document) with extract's extraction warnings.
    let body_bytes = result.text.len();
    store.insert(body_id, DataClass::Document, result.text);
    let body = IngestReport {
        doc_id: body_id,
        class: DataClass::Document,
        doc_bytes: body_bytes,
        clamped: false,
        warnings: result.warnings,
    };

    // Land the METADATA (Metadata) with the F-1 clamp warnings.
    let meta_bytes = meta_built.canonical.len();
    store.insert(meta_id, DataClass::Metadata, meta_built.canonical);
    let metadata = IngestReport {
        doc_id: meta_id,
        class: DataClass::Metadata,
        doc_bytes: meta_bytes,
        clamped: meta_built.clamped,
        warnings: meta_built.warnings,
    };

    Ok(EmailIngest { body, metadata })
}

// ---------------------------------------------------------------------------
// F-1 clamp internals. Reached ONLY when `to_canonical(meta).len() > cap`.
// ---------------------------------------------------------------------------

/// Rebuild a `firmos.meta/1` doc within the [`MAX_CANONICAL_BYTES`] budget.
///
/// Budget is reserved in PRIORITY order (small high-signal fields first, then the
/// recipient lists), but the doc is EMITTED in the canonical field order so that —
/// were nothing clamped — it would be byte-identical to [`to_canonical`]. Every line
/// admitted is accounted against `used`, and a line is admitted only when
/// `used + line.len() <= cap`, so the final `out.len() == used <= cap` by
/// construction. Returns the canonical string + the cleartext-free warnings.
fn clamp_to_canonical(meta: &EmailMetadata) -> (String, Vec<String>) {
    let cap = MAX_CANONICAL_BYTES;
    let mut used = VERSION_LINE.len();
    let mut warnings = Vec::new();

    // Kept, already-encoded lines, built in PRIORITY order, emitted CANONICALLY below.
    let mut date_line = None;
    let mut msgid_line = None;
    let mut subject_line = None;
    let mut from_lines = Vec::new();
    let mut to_lines = Vec::new();
    let mut cc_lines = Vec::new();
    let mut bcc_lines = Vec::new();
    let mut reply_lines = Vec::new();

    // Single-value essentials first (tiny + high-value; subject may be truncated).
    add_single(
        &mut used,
        cap,
        "date",
        meta.date.as_deref(),
        &mut date_line,
        &mut warnings,
    );
    add_single(
        &mut used,
        cap,
        "message-id",
        meta.message_id.as_deref(),
        &mut msgid_line,
        &mut warnings,
    );
    add_single(
        &mut used,
        cap,
        "subject",
        meta.subject.as_deref(),
        &mut subject_line,
        &mut warnings,
    );

    // Multi-value recipient lists, priority from > to > cc > bcc > reply-to. Each
    // truncated field (incl. bcc — the leak surface) emits a count warning, so a
    // dropped Bcc is SURFACED (its presence/count), never silently lost.
    add_multi(
        &mut used,
        cap,
        "from",
        &meta.from,
        &mut from_lines,
        &mut warnings,
    );
    add_multi(&mut used, cap, "to", &meta.to, &mut to_lines, &mut warnings);
    add_multi(&mut used, cap, "cc", &meta.cc, &mut cc_lines, &mut warnings);
    add_multi(
        &mut used,
        cap,
        "bcc",
        &meta.bcc,
        &mut bcc_lines,
        &mut warnings,
    );
    add_multi(
        &mut used,
        cap,
        "reply-to",
        &meta.reply_to,
        &mut reply_lines,
        &mut warnings,
    );

    // Emit in CANONICAL order (matches `to_canonical`): from, to, cc, bcc, reply-to,
    // subject, date, message-id.
    let mut out = String::with_capacity(used);
    out.push_str(VERSION_LINE);
    for l in from_lines
        .iter()
        .chain(&to_lines)
        .chain(&cc_lines)
        .chain(&bcc_lines)
        .chain(&reply_lines)
    {
        out.push_str(l);
    }
    if let Some(l) = &subject_line {
        out.push_str(l);
    }
    if let Some(l) = &date_line {
        out.push_str(l);
    }
    if let Some(l) = &msgid_line {
        out.push_str(l);
    }

    // A top-level note (first) that the metadata is incomplete because it was clamped.
    warnings.insert(
        0,
        format!(
            "email metadata exceeded the {cap}-byte readable limit and was clamped to fit; \
             some fields were truncated (see the field warnings) — the stored metadata is incomplete"
        ),
    );
    debug_assert!(out.len() <= cap, "clamp must never exceed the reader cap");
    (out, warnings)
}

/// Try to admit one single-value field as a line within budget. Truncates the value
/// to fit if needed (warning on truncation); drops it if not even an empty value
/// line fits (warning on drop). Updates `used` and `slot` on success.
fn add_single(
    used: &mut usize,
    cap: usize,
    tag: &str,
    value: Option<&str>,
    slot: &mut Option<String>,
    warnings: &mut Vec<String>,
) {
    let Some(v) = value else { return };
    match fit_line(*used, cap, tag, v) {
        Some((line, truncated)) => {
            if truncated {
                warnings.push(format!(
                    "{tag}: value truncated to fit the metadata size limit"
                ));
            }
            *used += line.len();
            *slot = Some(line);
        }
        None => warnings.push(format!(
            "{tag}: dropped — no room within the metadata size limit"
        )),
    }
}

/// Admit as many of a multi-value field's entries (in order) as fit the budget,
/// truncating individual values as needed. Records a cleartext-free "kept K of N"
/// warning when the list (or any value in it) was clamped.
fn add_multi(
    used: &mut usize,
    cap: usize,
    tag: &str,
    values: &[String],
    lines: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let total = values.len();
    let mut any_truncated = false;
    for v in values {
        match fit_line(*used, cap, tag, v) {
            Some((line, truncated)) => {
                any_truncated |= truncated;
                *used += line.len();
                lines.push(line);
            }
            // Budget is full for this field; remaining entries are dropped.
            None => break,
        }
    }
    let kept = lines.len();
    if kept < total {
        warnings.push(format!(
            "{tag}: kept {kept} of {total} entries (clamped to fit the metadata size limit)"
        ));
    } else if any_truncated {
        warnings.push(format!(
            "{tag}: some values truncated to fit the metadata size limit"
        ));
    }
}

/// Build one `TAG<SP>value\n` line whose total byte length keeps `used + line <= cap`,
/// clamping the percent-encoded value to at most [`MAX_VALUE_BYTES`] AND to whatever
/// budget remains. Returns `(line, was_value_truncated)`, or `None` when not even an
/// empty-value line fits.
fn fit_line(used: usize, cap: usize, tag: &str, value: &str) -> Option<(String, bool)> {
    // overhead = tag bytes + one space + one newline. The minimal line is `tag \n`.
    let overhead = tag.len() + 2;
    if used + overhead > cap {
        return None;
    }
    // Bytes available for the ENCODED value, bounded by the per-value cap so one
    // field can't starve the rest. `clamp_encoded` guarantees encoded.len() <= this,
    // hence line.len() = overhead + encoded.len() <= cap - used (since avail = cap -
    // used - overhead), i.e. used + line.len() <= cap.
    let avail = cap - used - overhead;
    let value_budget = avail.min(MAX_VALUE_BYTES);
    let (encoded, truncated) = clamp_encoded(value, value_budget);
    let mut line = String::with_capacity(overhead + encoded.len());
    line.push_str(tag);
    line.push(' ');
    line.push_str(&encoded);
    line.push('\n');
    Some((line, truncated))
}

/// Percent-encode `value`, truncating the ORIGINAL by WHOLE characters so the
/// encoded result is `<= budget` bytes. Returns `(encoded, was_truncated)`.
///
/// NEVER slices a multi-byte codepoint and never splits a `%XX` escape: it accounts
/// each char's full encoded cost up front and cuts only at a char boundary, so the
/// encoded prefix is exactly `percent_encode(&value[..end])` (encoding is per-byte).
fn clamp_encoded(value: &str, budget: usize) -> (String, bool) {
    let full = percent_encode(value);
    if full.len() <= budget {
        return (full, false);
    }
    let mut enc_len = 0usize;
    let mut end = 0usize;
    for (i, ch) in value.char_indices() {
        let ce = char_encoded_len(ch);
        if enc_len + ce > budget {
            break;
        }
        enc_len += ce;
        end = i + ch.len_utf8();
    }
    (percent_encode(&value[..end]), true)
}

/// The number of bytes `ch` occupies once percent-encoded: each UTF-8 byte costs 3
/// (`%XX`) if it is `%` or an ASCII control char, else 1 — mirroring
/// [`extract::percent_encode`]'s escape set exactly.
fn char_encoded_len(ch: char) -> usize {
    let mut buf = [0u8; 4];
    ch.encode_utf8(&mut buf)
        .as_bytes()
        .iter()
        .map(|&b| {
            if b == b'%' || b.is_ascii_control() {
                3
            } else {
                1
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{
        Audit, Capability, Core, CoreContext, FixedClock, GrantSet, InMemoryAudit, InMemoryEgress,
        InMemoryMatterStore, InMemoryStorage,
    };

    // A synthetic `.eml` (RFC822-ish) with obvious cleartext + a Bcc leak surface,
    // so the round-trip + cleartext-free-audit assertions have real values to check.
    const EML: &[u8] = b"From: Jane Roe <jane.roe@acme.example>\r\n\
To: a@x.example, b@y.example\r\n\
Cc: c@z.example\r\n\
Bcc: hidden@watcher.example\r\n\
Reply-To: reply@acme.example\r\n\
Subject: Re: Project Condor \xe2\x80\x94 urgent\r\n\
Date: Fri, 19 Jun 2026 09:30:00 +0000\r\n\
Message-ID: <abc123@acme.example>\r\n\
\r\n\
Please counter-sign the NDA.";

    // ---- the integration test: round-trip through the REAL Core reader -----------

    /// Build a Core over `store` granting only `matter.read:metadata`, with the
    /// deterministic dev audit double.
    fn core_over(
        store: InMemoryMatterStore,
    ) -> Core<
        GrantSet,
        InMemoryAudit,
        InMemoryStorage,
        InMemoryEgress,
        CoreContext,
        InMemoryMatterStore,
    > {
        Core::new(
            "sg.ingest.job",
            GrantSet::from_manifest(vec![Capability::MatterRead(DataClass::Metadata)]),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            InMemoryEgress::new(),
            CoreContext::new("Acme v Beta", "j.smith"),
            store,
        )
    }

    #[test]
    fn ingest_then_read_back_through_the_real_core_reader() {
        // INTEGRATION-VERIFY (CLAUDE.md discipline): prove the producer -> store ->
        // READER contract through the REAL `Core::matter_read_metadata`, not a local
        // copy of the decode logic.
        let mut store = InMemoryMatterStore::new();
        let report = ingest_email_metadata(&mut store, 7, "disclosure.eml", EML).unwrap();
        assert_eq!(report.class, DataClass::Metadata);
        assert!(!report.clamped, "a normal email is nowhere near the cap");
        assert!(report.doc_bytes <= MAX_CANONICAL_BYTES);

        // What extract recovered (the producer's source of truth).
        let expected = extract::extract("disclosure.eml", EML)
            .unwrap()
            .metadata
            .email
            .unwrap();

        // Read it back THROUGH THE CORE as typed EmailHeaders.
        let mut core = core_over(store);
        let headers = core.matter_read_metadata(7, DataClass::Metadata).unwrap();

        // Field-for-field identity: the reader reconstructs exactly what extract saw.
        assert_eq!(headers.from, expected.from);
        assert_eq!(headers.to, expected.to);
        assert_eq!(headers.cc, expected.cc);
        assert_eq!(
            headers.bcc, expected.bcc,
            "Bcc (leak surface) survives the round-trip"
        );
        assert_eq!(headers.reply_to, expected.reply_to);
        assert_eq!(headers.subject, expected.subject);
        assert_eq!(headers.date, expected.date);
        assert_eq!(headers.message_id, expected.message_id);
        // The mediated read was audited and the keyed chain verifies.
        assert!(core.audit().verify_chain());
    }

    #[test]
    fn wrong_class_grant_cannot_read_the_metadata_doc() {
        // Defense-in-depth: a doc landed under Metadata is not reachable via a
        // different class's grant (the core's entitlement filter still applies).
        let mut store = InMemoryMatterStore::new();
        ingest_email_metadata(&mut store, 1, "m.eml", EML).unwrap();
        let mut core = Core::new(
            "sg.ingest.job",
            GrantSet::from_manifest(vec![Capability::MatterRead(DataClass::Document)]),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            InMemoryEgress::new(),
            CoreContext::new("Acme v Beta", "j.smith"),
            store,
        );
        // Granted Document, not Metadata -> default-deny on the metadata read.
        assert!(core.matter_read_metadata(1, DataClass::Metadata).is_err());
    }

    // ---- the under-cap path is byte-identical to the shared producer -------------

    #[test]
    fn under_cap_is_byte_identical_to_to_canonical_no_clamp_no_warnings() {
        let meta = extract::extract("m.eml", EML)
            .unwrap()
            .metadata
            .email
            .unwrap();
        let built = serialize_metadata(&meta);
        assert_eq!(
            built.canonical,
            to_canonical(&meta),
            "no drift from the producer"
        );
        assert!(!built.clamped);
        assert!(built.warnings.is_empty());
    }

    #[test]
    fn empty_metadata_is_just_the_version_line() {
        let built = serialize_metadata(&EmailMetadata::default());
        assert_eq!(built.canonical, "firmos.meta/1\n");
        assert!(!built.clamped);
    }

    // ---- F-1: an over-cap doc is clamped to stay READABLE ------------------------

    /// An EmailMetadata whose serialization blows past the reader cap: thousands of
    /// recipients, each with a long display name (extract's per-field 256 cap does
    /// not apply to a hand-built metadata, and even at 256×5 long names it can cross
    /// the cap — here we go large to make the over-cap deterministic).
    fn oversized_metadata() -> EmailMetadata {
        let addr = |i: usize| {
            format!(
                "Recipient Number {i} With A Deliberately Long Display Name <user{i}@some-very-long-domain.example>"
            )
        };
        EmailMetadata {
            from: vec!["Sender <sender@acme.example>".to_string()],
            to: (0..6000).map(addr).collect(),
            cc: (0..6000).map(addr).collect(),
            bcc: vec!["hidden@watcher.example".to_string()],
            reply_to: vec!["reply@acme.example".to_string()],
            subject: Some("Re: Mass distribution".to_string()),
            date: Some("2026-06-19T09:30:00Z".to_string()),
            message_id: Some("<mass@acme.example>".to_string()),
        }
    }

    #[test]
    fn over_cap_metadata_is_clamped_under_cap_and_stays_readable() {
        let meta = oversized_metadata();
        // Precondition: the UNCLAMPED form really is over the cap (else the test is
        // not exercising F-1).
        assert!(
            to_canonical(&meta).len() > MAX_CANONICAL_BYTES,
            "fixture must exceed the cap to exercise F-1"
        );

        let built = serialize_metadata(&meta);
        assert!(built.clamped, "an over-cap doc must report it was clamped");
        assert!(
            built.canonical.len() <= MAX_CANONICAL_BYTES,
            "clamped doc must be within the reader cap, got {}",
            built.canonical.len()
        );
        // THE point of F-1: the clamped doc READS BACK through the REAL reader
        // (without the clamp it would be Err — an unreadable all-or-nothing doc).
        let headers = runtime::parse_email_headers(&built.canonical)
            .expect("clamped doc must be readable by the real core reader");
        // Essentials reserved first survive in full.
        assert_eq!(headers.from, meta.from, "from (identity) preserved");
        assert_eq!(headers.subject, meta.subject, "subject preserved");
        assert_eq!(headers.date, meta.date, "date preserved");
        assert_eq!(headers.message_id, meta.message_id, "message-id preserved");
        // The big lists were truncated (kept some, not all).
        assert!(
            headers.to.len() < meta.to.len(),
            "the giant `to` list was truncated"
        );
        assert!(!headers.to.is_empty(), "but some recipients were kept");
        // A top-level + per-field warning surfaced the truncation.
        assert!(
            built.warnings.iter().any(|w| w.contains("exceeded")),
            "top-level clamp warning"
        );
        assert!(
            built.warnings.iter().any(|w| w.starts_with("to: kept")),
            "the `to` truncation is surfaced with a count: {:?}",
            built.warnings
        );
    }

    #[test]
    fn clamp_truncates_a_giant_single_value_and_stays_readable() {
        // A control-stuffed subject alone over the cap (each control byte -> 3 bytes).
        let subject: String = "\u{7}".repeat(MAX_CANONICAL_BYTES); // 256 KiB -> ~768 KiB encoded
        let meta = EmailMetadata {
            from: vec!["s@x.example".to_string()],
            subject: Some(subject),
            ..EmailMetadata::default()
        };
        assert!(to_canonical(&meta).len() > MAX_CANONICAL_BYTES);

        let built = serialize_metadata(&meta);
        assert!(built.clamped);
        assert!(built.canonical.len() <= MAX_CANONICAL_BYTES);
        // Readable, from preserved, subject present-but-truncated.
        let headers = runtime::parse_email_headers(&built.canonical).unwrap();
        assert_eq!(headers.from, meta.from);
        let kept = headers
            .subject
            .expect("a (truncated) subject is still present");
        assert!(
            kept.len() < MAX_CANONICAL_BYTES,
            "the subject was truncated to fit"
        );
        assert!(built
            .warnings
            .iter()
            .any(|w| w.starts_with("subject: value truncated")));
    }

    #[test]
    fn dropped_bcc_is_surfaced_never_silent() {
        // Bcc is the leak surface. Engineer a clamp where the budget is exhausted by
        // higher-priority fields BEFORE bcc, so bcc entries are dropped — and assert
        // the drop is SURFACED (count warning), not silent. `from` is priority 1, so
        // a huge `from` flood starves the rest.
        let big = |i: usize| format!("Flood Sender {i} <flood{i}@very-long-domain-name.example>");
        let meta = EmailMetadata {
            from: (0..12000).map(big).collect(),
            bcc: vec![
                "secret1@watcher.example".to_string(),
                "secret2@watcher.example".to_string(),
            ],
            ..EmailMetadata::default()
        };
        assert!(to_canonical(&meta).len() > MAX_CANONICAL_BYTES);
        let built = serialize_metadata(&meta);
        assert!(built.canonical.len() <= MAX_CANONICAL_BYTES);
        let headers = runtime::parse_email_headers(&built.canonical).unwrap();
        // bcc could not be kept (budget consumed by the from flood)...
        assert!(
            headers.bcc.is_empty(),
            "bcc was crowded out in this fixture"
        );
        // ...but the drop is SURFACED with a count (leak surface never silently lost).
        assert!(
            built
                .warnings
                .iter()
                .any(|w| w.starts_with("bcc: kept 0 of 2")),
            "a dropped Bcc must be surfaced with its count: {:?}",
            built.warnings
        );
    }

    // ---- confidentiality: warnings are cleartext-free ---------------------------

    #[test]
    fn clamp_warnings_carry_no_cleartext() {
        // The clamp warnings must name field TAGS + COUNTS only — never an address or
        // subject VALUE from the (clamped) metadata.
        let mut meta = oversized_metadata();
        meta.to = (0..6000)
            .map(|i| format!("SECRETNAME{i} <secret{i}@confidential-domain.example>"))
            .collect();
        let built = serialize_metadata(&meta);
        for w in &built.warnings {
            assert!(
                !w.contains("SECRETNAME"),
                "no display-name cleartext in warning: {w:?}"
            );
            assert!(
                !w.contains("confidential-domain"),
                "no address cleartext in warning: {w:?}"
            );
            assert!(
                !w.contains('@'),
                "a warning should carry no address at all: {w:?}"
            );
        }
    }

    // ---- error surface ----------------------------------------------------------

    #[test]
    fn unsupported_file_is_an_extract_error() {
        let err = build_email_metadata_doc("notes.xyz", b"whatever").unwrap_err();
        assert!(matches!(err, IngestError::Extract(_)));
        // The error Display carries no matter content.
        assert!(!err.to_string().is_empty());
    }

    // ---- never-panic on adversarial input ---------------------------------------

    #[test]
    fn never_panics_on_adversarial_eml_bytes() {
        let adversarial: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"not an email at all".to_vec(),
            b"From: \xff\xfe broken utf8 \x00\x01\r\nSubject: \xc3\x28\r\n\r\nbody".to_vec(),
            b"To: "
                .to_vec()
                .into_iter()
                .chain(std::iter::repeat_n(b'a', 100_000))
                .collect(),
            vec![b'\n'; 10_000],
        ];
        for bytes in adversarial {
            // Must return a Result (Ok or Err), never panic. We also confirm any Ok
            // doc is within the cap.
            if let Ok(doc) = build_email_metadata_doc("x.eml", &bytes) {
                assert!(doc.canonical.len() <= MAX_CANONICAL_BYTES);
            }
        }
    }

    #[test]
    fn clamp_value_helper_never_slices_a_codepoint() {
        // A run of 4-byte emoji clamped to an odd budget never produces invalid UTF-8
        // and never exceeds the budget.
        let value = "😀".repeat(1000); // 4000 bytes, no escapables
        for budget in [0usize, 1, 2, 3, 4, 5, 7, 9, 4001] {
            let (enc, truncated) = clamp_encoded(&value, budget);
            assert!(enc.len() <= budget || (budget < 4 && enc.is_empty()));
            assert!(std::str::from_utf8(enc.as_bytes()).is_ok(), "valid utf-8");
            if budget >= 4000 {
                assert!(!truncated);
            }
        }
    }

    // ---- body-document ingestion (the sibling job) ------------------------------

    /// A minimal valid PDF carrying `body` as its only text — a NON-email,
    /// extractable document fixture (mirrors redact-cli's test helper). lopdf is a
    /// dev-dependency; this never ships.
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

    /// A Core over `store` with the given matter.read grants + the deterministic dev
    /// audit double.
    fn core_reading(
        store: InMemoryMatterStore,
        grants: Vec<Capability>,
    ) -> Core<
        GrantSet,
        InMemoryAudit,
        InMemoryStorage,
        InMemoryEgress,
        CoreContext,
        InMemoryMatterStore,
    > {
        Core::new(
            "sg.ingest.job",
            GrantSet::from_manifest(grants),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            InMemoryEgress::new(),
            CoreContext::new("Acme v Beta", "j.smith"),
            store,
        )
    }

    #[test]
    fn ingest_document_text_round_trips_the_eml_body_through_matter_read_text() {
        let mut store = InMemoryMatterStore::new();
        let report = ingest_document_text(&mut store, 3, "disclosure.eml", EML).unwrap();
        assert_eq!(report.class, DataClass::Document);
        assert!(!report.clamped, "body docs never clamp");
        let expected = extract::extract("disclosure.eml", EML).unwrap().text;
        assert_eq!(report.doc_bytes, expected.len());

        let mut core = core_reading(store, vec![Capability::MatterRead(DataClass::Document)]);
        let body = core.matter_read_text(3, DataClass::Document).unwrap();
        assert_eq!(body, expected, "the landed body reads back verbatim");
        assert!(body.contains("counter-sign"), "the body text is present");
        assert!(core.audit().verify_chain());
    }

    #[test]
    fn ingest_document_text_lands_a_non_email_pdf_body() {
        // A PDF is a NON-email document: ingest_document_text still lands its body.
        let pdf = build_pdf("Confidential memo: settlement figure is one million.");
        let mut store = InMemoryMatterStore::new();
        let report = ingest_document_text(&mut store, 5, "memo.pdf", &pdf).unwrap();
        assert_eq!(report.class, DataClass::Document);
        let mut core = core_reading(store, vec![Capability::MatterRead(DataClass::Document)]);
        let body = core.matter_read_text(5, DataClass::Document).unwrap();
        assert!(
            body.contains("settlement"),
            "PDF body text extracted + landed: {body:?}"
        );
    }

    #[test]
    fn ingest_email_lands_both_body_and_metadata_readable_with_their_grants() {
        let mut store = InMemoryMatterStore::new();
        let out = ingest_email(&mut store, 10, 11, "disclosure.eml", EML).unwrap();
        assert_eq!(out.body.class, DataClass::Document);
        assert_eq!(out.metadata.class, DataClass::Metadata);
        assert_eq!(out.body.doc_id, 10);
        assert_eq!(out.metadata.doc_id, 11);

        let mut core = core_reading(
            store,
            vec![
                Capability::MatterRead(DataClass::Document),
                Capability::MatterRead(DataClass::Metadata),
            ],
        );
        // Body reads as text; metadata reads as typed headers (incl. the Bcc surface).
        let body = core.matter_read_text(10, DataClass::Document).unwrap();
        assert!(body.contains("counter-sign"));
        let headers = core.matter_read_metadata(11, DataClass::Metadata).unwrap();
        assert_eq!(headers.bcc, vec!["hidden@watcher.example"]);
        assert_eq!(
            headers.subject.as_deref(),
            Some("Re: Project Condor — urgent")
        );
    }

    #[test]
    fn ingest_email_rejects_a_shared_id_before_landing_anything() {
        let mut store = InMemoryMatterStore::new();
        let err = ingest_email(&mut store, 9, 9, "m.eml", EML).unwrap_err();
        assert_eq!(err, IngestError::DuplicateDocId);
        // Nothing landed: a Core over the store finds no doc of either class at id 9.
        let mut core = core_reading(
            store,
            vec![
                Capability::MatterRead(DataClass::Document),
                Capability::MatterRead(DataClass::Metadata),
            ],
        );
        assert!(core.matter_read_text(9, DataClass::Document).is_err());
        assert!(core.matter_read_metadata(9, DataClass::Metadata).is_err());
    }

    #[test]
    fn ingest_email_on_a_non_email_is_not_email_and_lands_no_body() {
        // A PDF has a body but NO email headers: ingest_email must return NotEmail and
        // (crucially) must NOT have landed a half-ingested body doc.
        let pdf = build_pdf("not an email, just a memo");
        let mut store = InMemoryMatterStore::new();
        let err = ingest_email(&mut store, 1, 2, "memo.pdf", &pdf).unwrap_err();
        assert_eq!(err, IngestError::NotEmail);
        let mut core = core_reading(store, vec![Capability::MatterRead(DataClass::Document)]);
        assert!(
            core.matter_read_text(1, DataClass::Document).is_err(),
            "no body doc may be landed when the file is not an email"
        );
    }
}
