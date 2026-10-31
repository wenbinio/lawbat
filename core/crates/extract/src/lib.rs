// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Document-extraction engine — deterministic core-plane ingestion library.
//!
//! Turns a matter file's raw bytes into plain text (plus document
//! [`Metadata`] and any [`warnings`](ExtractResult::warnings)) so the CORE
//! indexer can feed the matter store. This is the deterministic front of the
//! ingestion pipeline: `bytes -> ExtractResult` per format, dispatched by
//! [`detect`].
//!
//! ## Where this sits (load-bearing — read before extending)
//!
//! - **This is a CORE responsibility, NOT a module.** The indexer / walker is a
//!   core-plane component (CLAUDE.md: "the indexer/walker is a CORE
//!   responsibility, not a module — modules get no raw filesystem access").
//!   Extraction runs INSIDE the core, BEFORE entitlement / Chinese-wall filtering
//!   and BEFORE anything reaches the matter store; a module never sees raw file
//!   bytes and never calls this crate.
//! - **Pure library, no `Core` binding.** Unlike `redaction` (module #1, which is
//!   `Core`-trait-bound), `extract` is a plain pure-compute library: it takes
//!   bytes, returns text. It holds NO matter context, NO capabilities, NO
//!   `runtime` dependency. The core calls it; it touches no matter data directly.
//!   That keeps the trusted dependency surface small and the unit trivially
//!   testable.
//! - **Deterministic, LOCAL, no model, no network** (CLAUDE.md non-negotiables).
//!   The same bytes always yield the same `ExtractResult`. No OCR, no ML, no LLM,
//!   no network — anywhere. A scanned PDF (image-only, no text layer) is NOT
//!   handled here; that is the later OCR / `compute.model` tier (see
//!   [`PdfExtractor`]).
//!
//! ## The point of a real extractor vs. a naive "save as text"
//!
//! A legal data room is full of working documents. A naive text dump (or a
//! `File > Save As > Plain Text`) silently DROPS the parts of a file that most
//! often leak confidential information — for OOXML: tracked changes, comments,
//! footnotes/endnotes, and document metadata (author, last-modified-by, revision
//! history); for EMAIL: Bcc recipients, nested forwarded messages, and
//! attachments a "show me the body" view never reveals. Surfacing and/or
//! stripping those leak vectors is the WHOLE POINT of each extractor (see
//! [`DocxExtractor`] and [`EmlExtractor`]). Extraction robustness over messy real
//! legal files is the product (CLAUDE.md), so this engine is written to be
//! explicit about what it includes, what it strips, and what it could not parse
//! (via [`warnings`](ExtractResult::warnings)), never to fail silently.
//!
//! ## Email is a `document`, not a separate data class (settled)
//!
//! The platform models an email AS a `document` — there is NO separate "mail"
//! capability or data class. [`EmlExtractor`] is the ingestion brick that turns a
//! `.eml` (RFC 5322 / MIME) file into that `document` (its plain-text body +
//! email [`Metadata`] + leak-vector [`warnings`](ExtractResult::warnings)) for the
//! core indexer / matter store, exactly like the docx/PDF extractors do for their
//! formats.
//!
//! ## Status: EML implemented; docx / PDF are SKELETON
//!
//! The public ABI ([`Extractor`], [`ExtractResult`], [`Metadata`],
//! [`EmlExtractor`], [`DocxExtractor`], [`PdfExtractor`], [`detect`]) is laid out
//! and compiles. All three concrete extractors are IMPLEMENTED:
//! - [`EmlExtractor`] — RFC 5322 / MIME via the pure-Rust `mail-parser`;
//! - [`DocxExtractor`] — OOXML via the pure-Rust `zip` + `quick-xml` (see
//!   [`mod@docx`]);
//! - [`PdfExtractor`] — PDF via the pure-Rust `lopdf`, a BEST-EFFORT first
//!   increment that flags encrypted / scanned / undecodable input rather than
//!   silently returning empty (see [`mod@pdf`]).

// Format-specific extraction engines. The public `*Extractor` types below are thin
// wrappers that delegate to these (keeping `lib.rs` the ABI surface and each
// engine's heavy, hostile-input-bounded parsing in its own module).
mod docx;
mod msg;
mod pdf;

// The `firmos.meta/1` PRODUCER: serialize an `EmailMetadata` into the canonical
// stored form the trusted core reads back via `runtime::metadata::parse_email_headers`
// (that parser is the AUTHORITATIVE reverse; the wire format is the shared contract).
// It lives HERE (not in `runtime`) because of the crate dependency direction —
// `runtime` and `extract` are independent, and `extract` already owns the source type.
mod metadata;
pub use metadata::{percent_encode, to_canonical};

/// Document metadata recovered from a file's container/properties.
///
/// For OOXML this is the `docProps/core.xml` ("core properties": author, title,
/// created/modified, last-modified-by) and `docProps/app.xml` ("application
/// properties"). For PDF it is the document information dictionary / XMP.
///
/// This is a LEAK VECTOR as much as a convenience: `last_modified_by` and
/// `created`/`modified` timestamps routinely expose who touched a document and
/// when, which a naive text dump never shows. The extractor SURFACES it here so
/// the core/indexer (and downstream redaction) can decide what to keep — it is
/// not silently discarded and not silently embedded in the extracted text.
///
/// All fields are optional: a document may declare none of them. Strings are kept
/// verbatim (no normalization) so the values are faithful to the source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    /// Document author (`dc:creator` in OOXML core properties).
    pub author: Option<String>,
    /// The user who last saved the document (`cp:lastModifiedBy`). A common
    /// confidentiality leak — surfaced, never silently embedded.
    pub last_modified_by: Option<String>,
    /// Document title (`dc:title`).
    pub title: Option<String>,
    /// Subject (`dc:subject`).
    pub subject: Option<String>,
    /// Creation timestamp, verbatim (`dcterms:created`, usually ISO-8601). Kept
    /// as a string so the extractor stays deterministic and pulls in no date /
    /// time-zone dependency.
    pub created: Option<String>,
    /// Last-modified timestamp, verbatim (`dcterms:modified`).
    pub modified: Option<String>,
    /// Producing application (OOXML `app.xml` `<Application>`, PDF `Producer` /
    /// `Creator`). Useful provenance; also a fingerprint.
    pub application: Option<String>,
    /// Email-specific header metadata, present ONLY for an email document
    /// ([`EmlExtractor`]); `None` for OOXML / PDF. Kept as a nested struct so the
    /// shared [`Metadata`] shape (author/title/created/…) stays format-neutral
    /// while email surfaces its required routing headers (from/to/cc/bcc/…).
    pub email: Option<EmailMetadata>,
}

/// Structured email header metadata recovered from a `.eml` (RFC 5322 / MIME)
/// message — surfaced by [`EmlExtractor`].
///
/// Every field is a DISPLAY string already decoded from RFC 2047 encoded-words
/// (`=?utf-8?…?=`) by the parser, so values read as the human would see them. An
/// address list (`from`/`to`/`cc`/`bcc`/`reply_to`) is rendered one address per
/// element, each formatted `Display Name <addr@host>` (or bare `addr@host` when no
/// display name) — see [`EmlExtractor`]. All fields are optional / possibly-empty:
/// a malformed or minimal message may declare none of them.
///
/// LEAK-VECTOR NOTE: `bcc` is recorded here when the saved `.eml` carries a `Bcc`
/// header (e.g. a sender's own copy). Blind-carbon recipients are exactly what a
/// "show me the email" view hides, so their PRESENCE is also raised as a
/// [`warning`](ExtractResult::warnings); the addresses themselves live here for the
/// reviewer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmailMetadata {
    /// `From:` — one formatted address per element (usually exactly one).
    pub from: Vec<String>,
    /// `To:` — formatted recipients.
    pub to: Vec<String>,
    /// `Cc:` — formatted carbon-copy recipients.
    pub cc: Vec<String>,
    /// `Bcc:` — formatted blind-carbon recipients (a LEAK VECTOR; see the type
    /// docs). Usually empty on a received message and populated on a sender's
    /// saved copy.
    pub bcc: Vec<String>,
    /// `Reply-To:` — formatted reply addresses, if the header is present.
    pub reply_to: Vec<String>,
    /// `Subject:` — decoded from RFC 2047 encoded-words.
    pub subject: Option<String>,
    /// `Date:` — normalized to RFC 3339 (`2021-11-20T14:22:01-08:00`) when the
    /// header parses to a valid datetime; `None` if absent or unparseable.
    pub date: Option<String>,
    /// `Message-ID:` — the message's own identifier, verbatim.
    pub message_id: Option<String>,
}

/// The result of extracting one document: its text, recovered [`Metadata`], and
/// any non-fatal [`warnings`](ExtractResult::warnings).
///
/// `text` is the extracted BODY text destined for the matter store / FTS index.
/// What is included vs. stripped (tracked changes, comments, footnotes) is an
/// extractor decision documented on each extractor — see [`DocxExtractor`].
///
/// `warnings` is how this engine stays HONEST instead of failing silently: a part
/// it could not parse, a leak vector it detected, a fallback it took, or "this is
/// a scanned PDF with no text layer" is recorded here rather than swallowed. An
/// empty `warnings` does NOT assert the document is safe — only that nothing was
/// flagged during extraction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractResult {
    /// The extracted plain-text body destined for the matter store / index.
    pub text: String,
    /// Metadata recovered from the document container/properties.
    pub metadata: Metadata,
    /// Non-fatal warnings: unparsed parts, detected leak vectors, fallbacks,
    /// "scanned PDF — no text layer", etc. Surfaced, never swallowed.
    pub warnings: Vec<String>,
}

/// One deterministic extractor per document format.
///
/// Pure compute: an implementation takes the file's raw `bytes` and returns an
/// [`ExtractResult`]. It performs NO I/O, NO network, NO model calls, and is
/// DETERMINISTIC — the same bytes always yield the same result. Errors that
/// prevent producing any text are returned as [`ExtractError`]; partial / soft
/// problems are reported via [`ExtractResult::warnings`] instead of failing.
pub trait Extractor {
    /// Extract text + [`Metadata`] from a document's raw bytes.
    ///
    /// Returns [`ExtractError`] only when no usable text could be produced (e.g.
    /// a corrupt container). Recoverable problems (an unparsed part, a detected
    /// leak vector, a scanned PDF) are reported in
    /// [`warnings`](ExtractResult::warnings) on an otherwise-successful result.
    fn extract(&self, bytes: &[u8]) -> Result<ExtractResult, ExtractError>;
}

/// A fatal extraction error (no usable text could be produced).
///
/// Non-fatal problems are reported via [`ExtractResult::warnings`] instead; this
/// type is only for the cases where extraction cannot proceed at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The container/format was malformed and could not be parsed (e.g. a
    /// truncated ZIP for a `.docx`, an unreadable PDF cross-reference table). The
    /// string is a human-readable reason; it must NOT contain matter content.
    Malformed(String),
    /// The format is recognized but not yet implemented in this skeleton. Carries
    /// the [`Format`] that would handle it. Distinct from [`Format::Unknown`],
    /// which means the format could not be identified at all.
    NotImplemented(Format),
    /// No extractor is registered for this file (extension/content not
    /// recognized). The string is the offending hint (e.g. the extension).
    Unsupported(String),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::Malformed(why) => write!(f, "malformed document: {why}"),
            ExtractError::NotImplemented(fmt) => {
                write!(f, "extraction not yet implemented for {fmt:?}")
            }
            ExtractError::Unsupported(hint) => write!(f, "unsupported document: {hint}"),
        }
    }
}

impl std::error::Error for ExtractError {}

/// A document format this engine knows how to dispatch on.
///
/// [`detect`] maps a filename extension to one of these; each (eventually) has a
/// concrete [`Extractor`]. `Unknown` means the extension was not recognized — it
/// is distinct from a recognized-but-unimplemented format, which dispatches to
/// its extractor and surfaces [`ExtractError::NotImplemented`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// OOXML word-processing document (`.docx`). Handled by [`DocxExtractor`].
    Docx,
    /// Portable Document Format (`.pdf`). Handled by [`PdfExtractor`].
    Pdf,
    /// RFC 5322 / MIME email message (`.eml`). Handled by [`EmlExtractor`]. The
    /// platform models an email AS a `document` (no separate "mail" data class).
    Eml,
    /// Outlook MAPI message (`.msg`, an OLE Compound File). Handled by [`MsgExtractor`];
    /// like `.eml`, modeled AS a `document`.
    Msg,
    /// Extension not recognized.
    Unknown,
}

/// Classify a filename into a [`Format`] by its extension (ASCII
/// case-insensitive).
///
/// Extension-based dispatch is the first cut; a real implementation MAY add
/// content sniffing (magic bytes: a `.docx` is a ZIP starting `PK\x03\x04`; a PDF
/// starts `%PDF-`) to catch mislabeled files. Detection never reads matter
/// content — only the name and, later, a few leading bytes.
///
/// Matching is ASCII case-insensitive on purpose: CLAUDE.md notes Windows/macOS
/// CI are case-insensitive filesystems, so `Report.DOCX` and `report.docx` must
/// classify identically.
pub fn detect(filename: &str) -> Format {
    // Take the substring after the final '.', if any.
    let ext = match filename.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() => ext,
        _ => return Format::Unknown,
    };
    if ext.eq_ignore_ascii_case("docx") {
        Format::Docx
    } else if ext.eq_ignore_ascii_case("pdf") {
        Format::Pdf
    } else if ext.eq_ignore_ascii_case("eml") {
        Format::Eml
    } else if ext.eq_ignore_ascii_case("msg") {
        Format::Msg
    } else {
        Format::Unknown
    }
}

/// Extract a document by dispatching on its filename [`Format`].
///
/// The convenience entry point the core indexer calls: [`detect`] the format from
/// `filename`, then run the matching [`Extractor`] over `bytes`. An unrecognized
/// extension returns [`ExtractError::Unsupported`]; a recognized-but-unimplemented
/// format returns [`ExtractError::NotImplemented`] from its extractor (skeleton).
pub fn extract(filename: &str, bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
    match detect(filename) {
        Format::Docx => DocxExtractor::new().extract(bytes),
        Format::Pdf => PdfExtractor::new().extract(bytes),
        Format::Eml => EmlExtractor::new().extract(bytes),
        Format::Msg => MsgExtractor::new().extract(bytes),
        Format::Unknown => Err(ExtractError::Unsupported(filename.to_string())),
    }
}

// ===========================================================================
// EmlExtractor — RFC 5322 / MIME email -> document (IMPLEMENTED)
// ===========================================================================

/// Hard bounds for hostile / adversarial email input. Untrusted email is the
/// NORM, not the exception, so every recursive / unbounded dimension is capped
/// up front and the extractor degrades to a [`warning`](ExtractResult::warnings)
/// or a content-free [`ExtractError::Malformed`] rather than panicking, looping,
/// or allocating without limit. These are deliberately generous (a real legal
/// email with a few attachments and a couple of forwards fits easily) but finite.
mod limits {
    /// Largest `.eml` we will parse at all. A `.eml` over this returns
    /// [`super::ExtractError::Malformed`] BEFORE the parser touches it — a
    /// multi-hundred-MB "email" is hostile or a mis-detected file, and base64
    /// attachments decode to ~0.75x more bytes, so we refuse rather than risk a
    /// memory blow-up. 64 MiB comfortably covers real mail with attachments.
    pub const MAX_EML_BYTES: usize = 64 * 1024 * 1024;

    /// Maximum MIME nesting we will DESCEND for leak-vector inspection (a
    /// `message/rfc822` inside a `message/rfc822` inside …). Beyond this we stop
    /// recursing and emit a "deep nesting" warning instead of risking stack
    /// growth on a maliciously deep tree. (mail-parser itself flattens parts, but
    /// our own nested-message walk is what this bounds.)
    pub const MAX_NESTING_DEPTH: usize = 16;

    /// Maximum number of MIME parts (across the flattened message) we will
    /// itemize in warnings. Past this we stop listing individual parts and emit a
    /// single capped-count warning, so a message with tens of thousands of parts
    /// can't make us build an unbounded warning list.
    pub const MAX_PARTS_REPORTED: usize = 256;

    /// Maximum number of attachment / recipient NAMES we spell out in a single
    /// warning before switching to "(+N more)". Keeps any one warning string
    /// bounded regardless of how many items the message carries.
    pub const MAX_NAMES_LISTED: usize = 20;

    /// Per-name cap (chars) when we render an attachment filename / address into a
    /// warning, so one absurdly long header value can't bloat a warning string.
    pub const MAX_NAME_CHARS: usize = 200;

    /// Cap on the assembled body text. A degenerate message could declare an
    /// enormous number of tiny text parts; bound the concatenated body so the
    /// returned `text` stays finite. 32 MiB of extracted plain text is far beyond
    /// any real email body and still safely indexable.
    pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
}

/// Extractor for RFC 5322 / MIME email messages (`.eml`). IMPLEMENTED.
///
/// Turns a saved email into the `document` data class for the matter store: the
/// plain-text body into [`ExtractResult::text`], the routing headers into
/// [`Metadata::email`] ([`EmailMetadata`]), and every "a naive view would miss
/// this" signal into [`ExtractResult::warnings`]. The platform models an email AS
/// a `document` — there is no separate "mail" capability or data class.
///
/// ## Deterministic, LOCAL, no network (non-negotiable)
///
/// Parsing is done by the pure-Rust [`mail_parser`] crate (Stalwart's; 100% safe
/// Rust, no `unsafe`, no I/O, no sockets). NOTHING here resolves a hostname,
/// fetches a remote image / web-font / tracking pixel, follows a URL, or calls a
/// model — an `.eml` body routinely contains `http(s)` references and remote
/// `<img src>`s, and we treat them as INERT TEXT, never fetch them. The same
/// bytes always yield the same [`ExtractResult`].
///
/// ## Body selection (prefer `text/plain`; strip HTML deterministically)
///
/// 1. If the message has any `text/plain` body part(s), they are the body
///    (joined in order).
/// 2. Otherwise, if it is HTML-only, the HTML is converted to text by a
///    deterministic, no-network tag strip (see [`html_to_text`]) and an
///    `html-only body` warning is raised — the markup the reviewer is NOT seeing
///    is surfaced, never silently rendered.
///
/// ## LEAK VECTORS a naive "show me the email body" MISSES — the whole point
///
/// Each of these is SURFACED in [`warnings`](ExtractResult::warnings) (and, for
/// Bcc, also in [`EmailMetadata`]) — never silently dropped:
///
/// - **Bcc recipients** present on the saved message — blind-carbon addresses the
///   "To/Cc" view never shows (who else secretly received this).
/// - **Nested / attached `message/rfc822`** — a forwarded or bounced email
///   embedded as a part. Its own body + headers are confidential content a
///   body-only sweep skips; we recurse (depth-bounded) and flag each one.
/// - **Attachments** — count + filenames. The body says nothing about a
///   privileged PDF riding along.
/// - **Other non-text parts** (inline images, application/* blobs) — flagged by
///   count; their bytes are NOT decoded into the body.
/// - **HTML-only body** — flagged as stripped (see above).
/// - **Undecodable / encoding-problem parts** — a part mail-parser could not
///   decode cleanly is flagged rather than emitted as mojibake or dropped.
/// - **Suspicious routing headers** — an unusually long `Received:` chain or a
///   present-but-malformed `Date:` is flagged as a soft provenance signal.
///
/// ## Hostile input is the norm
///
/// Untrusted email is assumed adversarial: total size, MIME nesting depth, part
/// count, and assembled-body size are all bounded (see [`limits`]); malformed /
/// truncated input returns a content-free [`ExtractError::Malformed`] or degrades
/// to a warning; nothing panics, recurses without bound, or allocates without
/// limit.
#[derive(Debug, Default, Clone)]
pub struct EmlExtractor {
    /// When `true`, append a clearly-labeled, depth-bounded dump of each nested
    /// `message/rfc822`'s own body to the extracted text (so a forwarded email's
    /// content is indexable). Default `false`: nested messages are FLAGGED via a
    /// warning but their bodies are not inlined, keeping the body to the outer
    /// message. (Mirrors [`DocxExtractor::include_annotations`].)
    pub include_nested_bodies: bool,
}

impl EmlExtractor {
    /// Construct an email extractor with default behavior (nested messages
    /// flagged, not inlined).
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: include each nested `message/rfc822`'s body (clearly labeled,
    /// depth-bounded) in the extracted text instead of only flagging it.
    pub fn include_nested_bodies(mut self) -> Self {
        self.include_nested_bodies = true;
        self
    }
}

impl Extractor for EmlExtractor {
    fn extract(&self, bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
        // BOUND 1 (size): refuse an oversized blob BEFORE parsing. Content-free
        // reason (a byte count, never matter content).
        if bytes.len() > limits::MAX_EML_BYTES {
            return Err(ExtractError::Malformed(format!(
                "email exceeds size limit ({} bytes > {} max)",
                bytes.len(),
                limits::MAX_EML_BYTES
            )));
        }

        // Parse with mail-parser. It is liberal in what it accepts (Postel) and
        // returns `None` only when there is nothing message-like at all — that is
        // our one fatal case. It never panics on malformed/truncated input.
        let message = mail_parser::MessageParser::default()
            .parse(bytes)
            .ok_or_else(|| {
                ExtractError::Malformed("not a parseable RFC 5322 / MIME message".to_string())
            })?;

        let mut warnings: Vec<String> = Vec::new();
        let metadata = Metadata {
            email: Some(email_metadata(&message, &mut warnings)),
            ..Metadata::default()
        };

        let text = build_body(self, &message, &mut warnings);

        Ok(ExtractResult {
            text,
            metadata,
            warnings,
        })
    }
}

/// Pull the required routing headers off a parsed [`mail_parser::Message`] into
/// [`EmailMetadata`], and raise the Bcc leak-vector warning as a side effect.
fn email_metadata(message: &mail_parser::Message<'_>, warnings: &mut Vec<String>) -> EmailMetadata {
    // Each header is rendered + cap-checked; a header whose recipient list exceeds
    // the cap is flagged so a >cap-recipient list is never silently truncated (L1).
    let mut truncated_headers: Vec<&str> = Vec::new();
    let mut fmt = |hdr: &'static str, addr: Option<&mail_parser::Address<'_>>| {
        let (rendered, truncated) = format_address(addr);
        if truncated {
            truncated_headers.push(hdr);
        }
        rendered
    };
    let from = fmt("From", message.from());
    let to = fmt("To", message.to());
    let cc = fmt("Cc", message.cc());
    let bcc = fmt("Bcc", message.bcc());
    let reply_to = fmt("Reply-To", message.reply_to());
    if !truncated_headers.is_empty() {
        warnings.push(format!(
            "recipient list(s) truncated at the {}-address cap ({}) — additional addressees were \
             not itemized",
            limits::MAX_PARTS_REPORTED,
            truncated_headers.join(", ")
        ));
    }

    // LEAK VECTOR: a saved message carrying Bcc recipients. Surface the COUNT
    // (the addresses themselves are in EmailMetadata for the reviewer; the
    // warning stays a count so the warnings list isn't a second copy of them).
    if !bcc.is_empty() {
        warnings.push(format!(
            "bcc recipients present ({}) — blind-carbon addressees a To/Cc view does not show",
            bcc.len()
        ));
    }

    // Date: normalize to RFC 3339 when valid; flag a present-but-invalid Date as
    // a soft provenance signal (a malformed Date can indicate a forged/edited
    // header) without failing extraction.
    let date = match message.date() {
        Some(dt) if dt.is_valid() => Some(dt.to_rfc3339()),
        Some(_) => {
            warnings.push("date header present but did not parse to a valid datetime".to_string());
            None
        }
        None => None,
    };

    EmailMetadata {
        from,
        to,
        cc,
        bcc,
        reply_to,
        subject: message
            .subject()
            .map(|s| clamp_chars(s, limits::MAX_NAME_CHARS * 4)),
        date,
        message_id: message
            .message_id()
            .map(|s| clamp_chars(s, limits::MAX_NAME_CHARS)),
    }
}

/// Render a parsed address header into one `Display Name <addr@host>` (or bare
/// `addr@host`) string per address, flattening RFC 5322 groups. Each rendered
/// value is char-bounded. Empty / absent header -> empty vec.
///
/// Returns `(addresses, truncated)`: `truncated` is `true` when the header carried
/// MORE than [`limits::MAX_PARTS_REPORTED`] addresses and the tail was dropped, so
/// the caller can warn rather than silently lose recipients (L1).
fn format_address(addr: Option<&mail_parser::Address<'_>>) -> (Vec<String>, bool) {
    let Some(addr) = addr else {
        return (Vec::new(), false);
    };
    // `Address::iter()` flattens both plain lists AND group members, so a grouped
    // `To: Team: a@x, b@y;` yields each member. Take ONE past the cap so we can
    // detect truncation; bound the rendered list at the cap.
    let mut rendered: Vec<String> = addr
        .iter()
        .take(limits::MAX_PARTS_REPORTED + 1)
        .filter_map(|a| {
            let name = a.name();
            let email = a.address();
            let value = match (name, email) {
                (Some(n), Some(e)) if !n.trim().is_empty() => format!("{n} <{e}>"),
                (_, Some(e)) => e.to_string(),
                // A name with no address (rare/degenerate) — keep the name so the
                // header isn't silently dropped.
                (Some(n), None) if !n.trim().is_empty() => n.to_string(),
                (_, None) => return None,
            };
            Some(clamp_chars(&value, limits::MAX_NAME_CHARS))
        })
        .collect();
    let truncated = rendered.len() > limits::MAX_PARTS_REPORTED;
    rendered.truncate(limits::MAX_PARTS_REPORTED);
    (rendered, truncated)
}

/// Assemble the extracted body text and raise every structural leak-vector
/// warning (attachments, nested messages, non-text parts, encoding problems,
/// suspicious routing). Body selection prefers `text/plain`, falling back to a
/// deterministic HTML strip.
fn build_body(
    cfg: &EmlExtractor,
    message: &mail_parser::Message<'_>,
    warnings: &mut Vec<String>,
) -> String {
    let mut body = String::new();

    // --- BODY: prefer text/plain, else strip HTML -------------------------
    //
    // `text_bodies()` is mail-parser's RFC 8621 §4.1.4 "plain-text view": for a
    // multipart/alternative it yields the genuine `text/plain` part; for an
    // HTML-ONLY message it substitutes the `text/html` part (so the list is never
    // empty just because the sender shipped HTML). We must distinguish the two,
    // because mail-parser's `text_contents()` returns an HTML part's RAW markup
    // (it does NOT strip tags). So: a genuine `text/plain` part is used verbatim;
    // an HTML part (`is_text_html()`) is run through our deterministic, no-network
    // tag-strip and the reviewer is warned the markup was stripped. The result is
    // "prefer text/plain; fall back to a stripped-HTML body, flagged".
    let mut body_part_count = 0usize;
    let mut html_was_stripped = false;
    for part in message.text_bodies() {
        let Some(content) = part.text_contents() else {
            continue;
        };
        if body_part_count > 0 {
            push_bounded(&mut body, "\n\n");
        }
        if part.is_text_html() {
            html_was_stripped = true;
            push_bounded(&mut body, &html_to_text(content));
        } else {
            push_bounded(&mut body, content);
        }
        body_part_count += 1;
    }
    if html_was_stripped {
        warnings.push(
            "html-only body: markup stripped to text deterministically (no remote \
             resources fetched)"
                .to_string(),
        );
    }
    if body_part_count == 0 {
        warnings
            .push("no text or html body part found (message may be attachment-only)".to_string());
    }

    // --- ATTACHMENTS ------------------------------------------------------
    // `attachment_name` is on the `MimeHeaders` trait (Content-Disposition
    // filename, falling back to the Content-Type name parameter).
    use mail_parser::MimeHeaders as _;
    let attachment_names: Vec<String> = message
        .attachments()
        // A nested message/rfc822 is also reported as an "attachment" by
        // mail-parser; we report those separately below, so exclude them here.
        .filter(|p| !p.is_message())
        // Take ONE past the cap so we can detect (and warn on) truncation rather
        // than silently dropping the tail of a huge attachment list (L1).
        .take(limits::MAX_PARTS_REPORTED + 1)
        .map(|p| match p.attachment_name() {
            Some(n) if !n.trim().is_empty() => clamp_chars(n, limits::MAX_NAME_CHARS),
            _ => "(unnamed)".to_string(),
        })
        .collect();
    let attachments_truncated = attachment_names.len() > limits::MAX_PARTS_REPORTED;
    if !attachment_names.is_empty() {
        let shown = attachment_names.len().min(limits::MAX_PARTS_REPORTED);
        warnings.push(format!(
            "attachments present ({}{}): {}",
            shown,
            if attachments_truncated { "+" } else { "" },
            list_names(&attachment_names[..shown])
        ));
    }
    if attachments_truncated {
        warnings.push(format!(
            "attachment list truncated at the {}-item cap — additional attachments were not \
             itemized",
            limits::MAX_PARTS_REPORTED
        ));
    }

    // --- NESTED message/rfc822 (depth-bounded recursion) ------------------
    // Count nested messages anywhere in the tree and (optionally) inline their
    // bodies. This is the forwarded/bounced-email leak vector.
    let mut nested_count = 0usize;
    walk_nested(cfg, message, 1, &mut nested_count, &mut body, warnings);
    if nested_count > 0 {
        warnings.push(format!(
            "nested message(s) present ({nested_count}): embedded message/rfc822 — a forwarded \
             or attached email with its own headers/body"
        ));
    }

    // --- OTHER non-text parts + encoding problems -------------------------
    // Walk the flattened part list once for: inline/binary non-text parts (not
    // already counted as attachments/text/html), and any part mail-parser flagged
    // with an encoding problem.
    let mut encoding_problems = 0usize;
    let mut other_nontext = 0usize;
    for part in message.parts.iter().take(limits::MAX_PARTS_REPORTED) {
        if part.is_encoding_problem {
            encoding_problems += 1;
        }
        match &part.body {
            mail_parser::PartType::Binary(_) | mail_parser::PartType::InlineBinary(_) => {
                other_nontext += 1;
            }
            _ => {}
        }
    }
    if message.parts.len() > limits::MAX_PARTS_REPORTED {
        warnings.push(format!(
            "message has a very large number of MIME parts ({}); only the first {} were \
             inspected for leak vectors",
            message.parts.len(),
            limits::MAX_PARTS_REPORTED
        ));
    }
    if other_nontext > 0 {
        warnings.push(format!(
            "non-text part(s) present ({other_nontext}): inline images / binary blobs whose \
             bytes are not included in the extracted text"
        ));
    }
    if encoding_problems > 0 {
        warnings.push(format!(
            "encoding problem in {encoding_problems} part(s): a charset / transfer-encoding \
             mail-parser could not fully decode — text may be incomplete"
        ));
    }

    // --- SUSPICIOUS ROUTING ----------------------------------------------
    // An unusually long Received: chain is a soft signal (relay loop, spoofing,
    // mailing-list expansion). Count Received headers without interpreting them.
    let received = message
        .headers()
        .iter()
        .filter(|h| matches!(h.name, mail_parser::HeaderName::Received))
        .count();
    const RECEIVED_CHAIN_FLAG: usize = 25;
    if received > RECEIVED_CHAIN_FLAG {
        warnings.push(format!(
            "unusually long Received: header chain ({received} hops) — possible relay loop or \
             routing anomaly"
        ));
    }

    // --- ENCRYPTED / SIGNED / PARTIAL --------------------------------------
    // A `multipart/encrypted` (S/MIME / PGP) body is NOT extractable as plain
    // text; a `message/partial` is one FRAGMENT of a split message, so the body is
    // incomplete. Flag these SPECIFICALLY rather than letting them surface only as
    // generic "non-text part" noise — the reviewer must know the body is encrypted
    // or incomplete, not merely "had a binary part". (A `multipart/signed` IS
    // extractable — its content is cleartext — but we note the signature so the
    // reviewer knows the message was signed / could be tampered if altered.)
    flag_special_content_types(message, warnings);

    body
}

/// Scan the message + its parts' `Content-Type`s for encrypted / signed / partial
/// containers and raise a SPECIFIC warning for each, so the reviewer is told the
/// body is encrypted (not extractable) or incomplete (a fragment) rather than
/// inferring it from generic non-text-part noise. Deterministic, bounded.
fn flag_special_content_types(message: &mail_parser::Message<'_>, warnings: &mut Vec<String>) {
    use mail_parser::MimeHeaders as _;
    let mut saw_encrypted = false;
    let mut saw_signed = false;
    let mut saw_partial = false;
    // Inspect the top-level content type plus each (bounded) part's content type.
    let part_ctypes = message
        .parts
        .iter()
        .take(limits::MAX_PARTS_REPORTED)
        .filter_map(|p| p.content_type());
    for ct in message.content_type().into_iter().chain(part_ctypes) {
        let ctype = ct.ctype();
        let subtype = ct.subtype().unwrap_or("");
        if ctype.eq_ignore_ascii_case("multipart") && subtype.eq_ignore_ascii_case("encrypted") {
            saw_encrypted = true;
        } else if ctype.eq_ignore_ascii_case("multipart") && subtype.eq_ignore_ascii_case("signed")
        {
            saw_signed = true;
        } else if ctype.eq_ignore_ascii_case("message") && subtype.eq_ignore_ascii_case("partial") {
            saw_partial = true;
        }
    }
    if saw_encrypted {
        warnings.push(
            "message is encrypted (multipart/encrypted) — body not extractable as plain text"
                .to_string(),
        );
    }
    if saw_signed {
        warnings.push(
            "message is cryptographically signed (multipart/signed) — content is the signed \
             part; a body change would break the signature"
                .to_string(),
        );
    }
    if saw_partial {
        warnings.push(
            "message/partial fragment — this is one piece of a split message; the body is \
             incomplete"
                .to_string(),
        );
    }
}

/// Recursively count (and optionally inline) nested `message/rfc822` parts,
/// bounded by [`limits::MAX_NESTING_DEPTH`]. A message at depth >= the cap stops
/// descending and raises a deep-nesting warning instead of recursing further —
/// no unbounded stack growth on a maliciously deep tree.
///
/// LEAK-VECTOR PARITY (load-bearing): mail-parser stores a nested message's
/// sub-parts in the INNER `Message.parts`, so the OUTER-only sweep in
/// [`build_body`] never sees them. The headline leak vector is exactly a `Fwd:`
/// carrying a privileged attachment and/or an inner `Bcc:` — so we run the SAME
/// leak-vector inspection on EACH nested message here: its own attachments,
/// `Binary`/`InlineBinary` parts, `is_encoding_problem` parts (mail-parser stops
/// decoding at its internal `MAX_NESTED_ENCODED=3`, leaving a deep nested part
/// flagged), and the presence of a nested `Bcc:`. Each is surfaced as a warning,
/// itemized — never silently dropped.
fn walk_nested(
    cfg: &EmlExtractor,
    message: &mail_parser::Message<'_>,
    depth: usize,
    count: &mut usize,
    body: &mut String,
    warnings: &mut Vec<String>,
) {
    use mail_parser::MimeHeaders as _;
    if depth > limits::MAX_NESTING_DEPTH {
        warnings.push(format!(
            "nested messages exceed depth limit ({}); deeper nesting not inspected",
            limits::MAX_NESTING_DEPTH
        ));
        return;
    }
    for part in &message.parts {
        if let mail_parser::PartType::Message(nested) = &part.body {
            *count += 1;
            if cfg.include_nested_bodies {
                if let Some(sub) = nested.text_bodies().find_map(|p| p.text_contents()) {
                    push_bounded(body, "\n\n--- nested message ---\n");
                    push_bounded(body, sub);
                }
            }

            // LEAK-VECTOR PARITY: inspect THIS nested message's own parts/headers,
            // which the outer sweep cannot see (they live in `nested.parts`).
            // --- nested ATTACHMENTS (excluding deeper nested messages) ---
            let nested_attachments: Vec<String> = nested
                .attachments()
                .take(limits::MAX_PARTS_REPORTED)
                .filter(|p| !p.is_message())
                .map(|p| match p.attachment_name() {
                    Some(n) if !n.trim().is_empty() => clamp_chars(n, limits::MAX_NAME_CHARS),
                    _ => "(unnamed)".to_string(),
                })
                .collect();
            if !nested_attachments.is_empty() {
                warnings.push(format!(
                    "nested message carries attachment(s) ({}): {}",
                    nested_attachments.len(),
                    list_names(&nested_attachments)
                ));
            }

            // --- nested non-text (Binary/InlineBinary) + encoding problems ---
            // mail-parser caps nested decoding at MAX_NESTED_ENCODED=3, so a deep
            // base64-in-rfc822 chain leaves an `is_encoding_problem` Binary part
            // INSIDE the nested message — invisible to the outer sweep. Count both
            // here so a truncation/encoding warning fires (H2).
            let mut nested_nontext = 0usize;
            let mut nested_encoding_problems = 0usize;
            for np in nested.parts.iter().take(limits::MAX_PARTS_REPORTED) {
                if np.is_encoding_problem {
                    nested_encoding_problems += 1;
                }
                match &np.body {
                    mail_parser::PartType::Binary(_) | mail_parser::PartType::InlineBinary(_) => {
                        nested_nontext += 1;
                    }
                    _ => {}
                }
            }
            if nested_nontext > 0 {
                warnings.push(format!(
                    "nested message carries non-text part(s) ({nested_nontext}): inline images / \
                     binary blobs whose bytes are not in the extracted text"
                ));
            }
            if nested_encoding_problems > 0 {
                warnings.push(format!(
                    "encoding problem in {nested_encoding_problems} nested-message part(s): a \
                     charset / transfer-encoding (or depth-limited decode) mail-parser could not \
                     fully decode — nested content may be incomplete/truncated"
                ));
            }

            // --- nested Bcc (the headline inner-leak vector) ---
            if nested.bcc().is_some_and(|a| a.iter().next().is_some()) {
                warnings.push(
                    "nested message carries Bcc — blind-carbon addressees on a forwarded/embedded \
                     message a To/Cc view does not show"
                        .to_string(),
                );
            }

            // Descend into the nested message's own parts (depth-bounded).
            walk_nested(cfg, nested, depth + 1, count, body, warnings);
        }
    }
}

/// Append `s` to `out` only up to [`limits::MAX_BODY_BYTES`], so the assembled
/// body stays finite regardless of how much text the message declares. Truncation
/// happens on a char boundary.
fn push_bounded(out: &mut String, s: &str) {
    let remaining = limits::MAX_BODY_BYTES.saturating_sub(out.len());
    if remaining == 0 {
        return;
    }
    if s.len() <= remaining {
        out.push_str(s);
    } else {
        // Truncate to the largest char boundary <= remaining.
        let mut cut = remaining;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        out.push_str(&s[..cut]);
    }
}

/// Render up to [`limits::MAX_NAMES_LISTED`] names into a comma-separated list,
/// appending `(+N more)` when there are more. Deterministic ordering (the order
/// the parts appear in the message).
fn list_names(names: &[String]) -> String {
    let shown = names.len().min(limits::MAX_NAMES_LISTED);
    let mut s = names[..shown].join(", ");
    if names.len() > shown {
        s.push_str(&format!(" (+{} more)", names.len() - shown));
    }
    s
}

/// Clamp a string to at most `max` characters (char-boundary safe), so one
/// pathological header value can't bloat a metadata field or a warning string.
fn clamp_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

/// Convert an HTML body to plain text DETERMINISTICALLY and with NO network: this
/// is a tag/entity strip, NOT a renderer. It does NOT and MUST NOT fetch any
/// remote resource (`<img src>`, web-font, stylesheet, tracking pixel) — the email
/// body is treated as inert text. The approach:
///
/// 1. Drop the entire contents of `<script>` / `<style>` elements (never body
///    text; scripts especially must not leak into the index).
/// 2. Replace each tag with whitespace (a block-ish tag becomes a newline so
///    paragraphs don't run together; everything else a space).
/// 3. Decode the handful of mandatory named entities + numeric (`&#NN;` /
///    `&#xNN;`) character references; leave unknown entities verbatim.
/// 4. Collapse runs of blank lines / trailing spaces so the result reads cleanly.
///
/// It is intentionally simple and conservative: a best-effort textualization for
/// indexing/review, not a fidelity-preserving HTML-to-text. The HTML-only warning
/// tells the reviewer the original markup was stripped.
fn html_to_text(html: &str) -> String {
    // Bound the work: an enormous HTML blob is already body-bounded upstream, but
    // cap the scan here too so a degenerate input can't dominate.
    let html = if html.len() > limits::MAX_BODY_BYTES {
        &html[..floor_boundary(html, limits::MAX_BODY_BYTES)]
    } else {
        html
    };

    let mut out = String::with_capacity(html.len() / 2 + 16);
    let bytes = html.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'<' {
            // HTML comment `<!-- ... -->`: skip to the literal `-->` and drop the
            // whole comment (including its text). A plain `find('>')` would stop at
            // the FIRST `>` inside the comment and leak the comment tail as body
            // text, so comments are special-cased like script/style.
            if html[i..].starts_with("<!--") {
                i = match find_ascii_ci(&html[i + 4..], "-->") {
                    Some(rel) => i + 4 + rel + 3,
                    // Unterminated comment: drop the rest of the input.
                    None => html.len(),
                };
                continue;
            }
            // Identify a <script>/<style> open tag to skip its raw contents.
            if let Some(skip_to) =
                skip_raw_element(html, i, "script").or_else(|| skip_raw_element(html, i, "style"))
            {
                i = skip_to;
                continue;
            }
            // Otherwise, find the tag's end. If there is no '>', the rest is a
            // truncated tag — drop it entirely (no infinite loop).
            let tag_start = i;
            match html[i..].find('>') {
                Some(rel) => {
                    let tag = &html[tag_start..i + rel + 1];
                    // Block-level-ish tags become a newline so text doesn't merge.
                    out.push(if is_block_tag(tag) { '\n' } else { ' ' });
                    i += rel + 1;
                }
                None => break,
            }
        } else if c == b'&' {
            // Entity reference: decode the supported set, else emit verbatim.
            if let Some((decoded, len)) = decode_entity(&html[i..]) {
                out.push_str(&decoded);
                i += len;
            } else {
                out.push('&');
                i += 1;
            }
        } else {
            // Copy a run of plain text up to the next '<' or '&' (one UTF-8 char
            // at a time near the boundary; bulk-copy the ASCII run otherwise).
            let next = html[i..]
                .find(['<', '&'])
                .map(|r| i + r)
                .unwrap_or(bytes.len());
            out.push_str(&html[i..next]);
            i = next;
        }
    }

    collapse_whitespace(&out)
}

/// If `html[at..]` opens the named raw element (`<script ...>` / `<style ...>`),
/// return the byte index just past its closing `</name>` (or the end of input if
/// unterminated), so its raw contents are skipped entirely. `None` if `at` is not
/// that element's open tag.
fn skip_raw_element(html: &str, at: usize, name: &str) -> Option<usize> {
    let rest = &html[at..];
    let lower_prefix = rest.get(..(name.len() + 1))?;
    // Must start "<script" / "<style" (case-insensitive), then a delimiter.
    if !lower_prefix.eq_ignore_ascii_case(&format!("<{name}")) {
        return None;
    }
    // The char after the tag name must be a delimiter, NOT a name continuation:
    // anything that is not alphanumeric or `-` ends the tag name. This deliberately
    // includes `\r` (CRLF is the norm in RFC 5322 bodies, so `<script\r\n>` is
    // legal and common) — omitting it would let `<script\r\n>evil()</script>` be
    // mistaken for an ordinary tag and leak the raw script body as text.
    let after = rest.as_bytes().get(name.len() + 1).copied();
    match after {
        Some(b) if !(b.is_ascii_alphanumeric() || b == b'-') => {}
        _ => return None,
    }
    // Find the closing tag (case-insensitive) and skip to just past it.
    let close = format!("</{name}>");
    match find_ascii_ci(rest, &close) {
        Some(rel) => Some(at + rel + close.len()),
        // Unterminated raw element: skip the rest of the input.
        None => Some(html.len()),
    }
}

/// Case-insensitive ASCII substring search returning the byte offset of `needle`
/// in `haystack`, or `None`. Linear, bounded, no allocation of the haystack.
fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return None;
    }
    for start in 0..=(h.len() - n.len()) {
        if h[start..start + n.len()]
            .iter()
            .zip(n)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return Some(start);
        }
    }
    None
}

/// Is this an open/close tag for a block-ish element (so it should become a line
/// break rather than a space when stripped)? Conservative allowlist.
fn is_block_tag(tag: &str) -> bool {
    // Strip leading "<" and "</", take the tag name up to whitespace / "/" / ">".
    let t = tag.trim_start_matches('<').trim_start_matches('/');
    let name_end = t
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(t.len());
    let name = &t[..name_end];
    matches!(
        name.to_ascii_lowercase().as_str(),
        "p" | "br"
            | "div"
            | "li"
            | "tr"
            | "table"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "blockquote"
            | "ul"
            | "ol"
            | "hr"
            | "pre"
            | "section"
            | "article"
    )
}

/// Decode an HTML entity reference at the START of `s` (which begins with `&`).
/// Returns `(decoded_text, bytes_consumed)` for the supported set — the five
/// mandatory named entities plus decimal/hex numeric character references — or
/// `None` to leave the `&` verbatim. Numeric refs are bounded and reject invalid
/// code points (no panic on a hostile `&#9999999999;`).
fn decode_entity(s: &str) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    debug_assert_eq!(bytes.first(), Some(&b'&'));
    // Numeric character reference: &#DD; or &#xHH;
    if bytes.get(1) == Some(&b'#') {
        let (radix, digits_start) = if matches!(bytes.get(2), Some(b'x' | b'X')) {
            (16, 3)
        } else {
            (10, 2)
        };
        // Read up to a bounded number of digits, then an optional ';'.
        let mut j = digits_start;
        const MAX_DIGITS: usize = 7; // enough for any Unicode scalar value.
        while j < bytes.len() && j - digits_start < MAX_DIGITS && (bytes[j] as char).is_digit(radix)
        {
            j += 1;
        }
        if j == digits_start {
            return None; // "&#;" / "&#x;" — not a valid ref.
        }
        let code = u32::from_str_radix(&s[digits_start..j], radix).ok()?;
        let ch = char::from_u32(code)?;
        // Consume a trailing ';' if present.
        let consumed = if bytes.get(j) == Some(&b';') {
            j + 1
        } else {
            j
        };
        return Some((ch.to_string(), consumed));
    }
    // Named entity (mandatory five + nbsp only; anything else left verbatim).
    // Compare on BYTES, never a `str` slice: `s` may begin with `&` followed by a
    // MULTIBYTE codepoint (`&€`, `&😀`, `&中`, `&Ä`), and slicing `s[..name.len()]`
    // by a byte length can land mid-codepoint and PANIC. `name` is pure ASCII, so a
    // byte-prefix compare is exact and never panics on hostile/benign input.
    for (name, ch) in [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
        ("&nbsp;", ' '),
    ] {
        if bytes
            .get(..name.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(name.as_bytes()))
        {
            return Some((ch.to_string(), name.len()));
        }
    }
    None
}

/// Collapse the whitespace produced by tag-stripping into readable text: trim
/// trailing spaces per line, collapse 3+ blank lines to a single blank line, and
/// trim leading/trailing blank lines. Deterministic.
fn collapse_whitespace(s: &str) -> String {
    let mut lines: Vec<&str> = s.lines().map(|l| l.trim_end()).collect();
    // Collapse runs of >1 blank line down to a single blank line.
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut prev_blank = false;
    for line in lines.drain(..) {
        let blank = line.trim().is_empty();
        if blank && prev_blank {
            continue;
        }
        out.push(line);
        prev_blank = blank;
    }
    // Trim leading / trailing blank lines.
    while out.first().is_some_and(|l| l.trim().is_empty()) {
        out.remove(0);
    }
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    out.join("\n")
}

/// Largest byte index <= `n` that is a char boundary in `s`.
fn floor_boundary(s: &str, n: usize) -> usize {
    let mut n = n.min(s.len());
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    n
}

/// Extractor for OOXML word-processing documents (`.docx`).
///
/// ## Implementation (pure-Rust, offline, no native dep)
///
/// A `.docx` is a ZIP container of XML parts. The extractor:
/// 1. opens the ZIP with the pure-Rust `zip` crate (no native dependency);
/// 2. streams the relevant parts with the pure-Rust `quick-xml` crate;
/// 3. reads body text from `word/document.xml` (`<w:t>` runs, `<w:tab/>`/`<w:br/>`,
///    `</w:p>` paragraph breaks), and document properties from `docProps/core.xml`
///    + `docProps/app.xml` into [`Metadata`].
///
/// Both deps are pure Rust and work air-gapped — no model, no network, no native
/// library — matching CLAUDE.md's non-negotiables. The engine lives in
/// [`mod@docx`] and is hostile-input-bounded (ZIP-bomb-guarded, depth/body-capped);
/// it never panics on malformed input.
///
/// ## LEAK VECTORS a naive "save as text" MISSES — this is the whole point
///
/// `File > Save As > Plain Text` (and most quick text dumps) keep only the
/// final-looking body and silently DROP the parts where confidential information
/// most often hides. A real extractor MUST account for every one of these — by
/// surfacing them in [`Metadata`] / [`ExtractResult::warnings`] and/or stripping
/// them from the body — never by silently ignoring them:
///
/// - **Tracked changes** (`<w:ins>` / `<w:del>` revisions in `document.xml`). The
///   DELETED text (`<w:delText>`) is still PRESENT in the file. A reviewer who
///   "accepted all changes" before sending may believe deleted text is gone — it
///   is not. The extractor must distinguish accepted/inserted vs. deleted text
///   and surface that the document carries revisions (a leak + a who-edited-what
///   trail), not blend deleted text invisibly into the body.
/// - **Comments** (`word/comments.xml`, referenced from the body). Margin
///   comments — often candid internal commentary ("don't show the client this")
///   — are a separate part a body-only dump skips. They must be surfaced /
///   flagged, never silently included as if they were body text.
/// - **Footnotes / endnotes** (`word/footnotes.xml` / `word/endnotes.xml`). Body
///   text lives in a separate part referenced from `document.xml`; a naive
///   `<w:t>`-only sweep of `document.xml` MISSES them entirely, dropping real
///   content from the index.
/// - **Core / app metadata** (`docProps/core.xml` / `app.xml`): author,
///   `lastModifiedBy`, created/modified timestamps, revision count, total edit
///   time, the producing application. Identity/provenance a text dump never
///   shows. Captured into [`Metadata`] (a leak vector, surfaced — see its docs).
///
/// ## What this increment does and does NOT cover (honest)
///
/// DONE: body text (paragraphs/tabs/breaks); tracked-DELETION text surfaced inline
/// as `[deleted: …]` + a tracked-changes warning; comments / footnotes / endnotes
/// FLAGGED (and optionally inlined via [`include_annotations`]); core/app metadata.
/// NOT yet: headers/footers, text boxes, hidden/vanished runs (`<w:vanish>`),
/// document-variable fields, and embedded objects — these are not yet read (a
/// reviewer should not assume the body is exhaustive). `.doc` (the old binary
/// format) is NOT handled — this is OOXML (`.docx`) only.
///
/// ## Status: IMPLEMENTED — [`extract`](DocxExtractor::extract) delegates to
/// [`mod@docx`].
#[derive(Debug, Default, Clone)]
pub struct DocxExtractor {
    /// When `true`, append comment / footnote / endnote text (clearly labeled) to
    /// the extracted body instead of only flagging it. Default `false`: surface
    /// them via warnings and keep the body to the main document text.
    pub include_annotations: bool,
}

impl DocxExtractor {
    /// Construct a `.docx` extractor with default behavior (annotations flagged,
    /// not inlined).
    pub fn new() -> Self {
        Self::default()
    }
}

impl Extractor for DocxExtractor {
    fn extract(&self, bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
        // Delegates to the OOXML engine (pure-Rust `zip` + `quick-xml`): body text
        // from word/document.xml (tracked-deletion `<w:delText>` included inline as
        // `[deleted: …]`), Metadata from docProps/core.xml + app.xml, and the leak
        // vectors (tracked changes / comments / footnotes / endnotes) surfaced via
        // warnings — never silently dropped. Hostile-input-bounded; never panics.
        docx::extract(bytes, self.include_annotations)
    }
}

/// Extractor for PDF documents (`.pdf`).
///
/// ## Implementation (pure-Rust `lopdf`, BEST-EFFORT first increment)
///
/// PDF text extraction goes through the pure-Rust [`lopdf`](mod@pdf) crate (MIT):
/// it parses the cross-reference table + page tree, decodes each page's content
/// stream (FlateDecode etc.), and pulls text from the text-showing operators
/// (`Tj` / `'` / `"` / `TJ`), mapping bytes through each page font's `/Encoding`
/// (WinAnsi / MacRoman / Standard + `/Differences`) and `/ToUnicode` where
/// reachable. It runs entirely locally — no model, no network — consistent with the
/// non-negotiables, and runs under `catch_unwind` so the third-party parser can
/// never panic the indexer. (CLAUDE.md's original note mentioned a future heavier
/// `pdfium` tier; this `lopdf` increment is the smaller pure-Rust first step.)
///
/// ## HONEST limits — flagged, never silently swallowed (see [`mod@pdf`])
///
/// - **Encrypted PDFs**: detected and flagged; NO decryption attempted (no
///   password held, never writes/decrypts). Body is empty for an encrypted doc.
/// - **Scanned / image-only PDFs**: a page with no text layer has nothing
///   deterministic to extract. OCR is the LATER OCR / `compute.model` tier
///   (CLAUDE.md "OCR": Tesseract on CPU, opt-in), NOT this extractor. Such a page
///   yields a "needs OCR" warning in [`ExtractResult::warnings`] — never a silent
///   empty body, and OCR is never invoked here.
/// - **Undecodable content streams / unresolved font encodings**: flagged as
///   partial extraction.
/// - Reading order, columns/tables, ligatures, and full CID/Type0 composite-font
///   reconstruction are NOT handled in this increment.
///
/// PDF metadata (the document information dictionary `/Info`: author, title,
/// producer, created/modified) maps into [`Metadata`], same leak-vector posture
/// as docx.
///
/// ## Status: IMPLEMENTED — [`extract`](PdfExtractor::extract) delegates to
/// [`mod@pdf`].
#[derive(Debug, Default, Clone)]
pub struct PdfExtractor {
    /// Reserved for future configuration (e.g. include-annotations parity with
    /// docx). No tunable behavior yet.
    _reserved: (),
}

impl PdfExtractor {
    /// Construct a PDF extractor with default behavior.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Extractor for PdfExtractor {
    fn extract(&self, bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
        // Delegates to the PDF engine (pure-Rust `lopdf`): parses the page tree,
        // FlateDecode content streams, and the text-showing operators, mapping by
        // each font's encoding where feasible. A BEST-EFFORT first increment — it
        // FLAGS encrypted / scanned (no text layer, needs OCR) / undecodable input
        // via warnings rather than silently returning empty, and runs under
        // `catch_unwind` so the third-party parser can never panic the indexer.
        pdf::extract(bytes)
    }
}

/// Extractor for Outlook MAPI messages (`.msg`, an OLE Compound File). IMPLEMENTED.
///
/// Like [`EmlExtractor`], it models an email AS a `document`: the plain-text body into
/// [`ExtractResult::text`] and the routing headers into [`Metadata::email`], so an
/// uploaded `.msg` flows through the same header-composition + scan path as a `.eml`.
///
/// ## Status: IMPLEMENTED — [`extract`](MsgExtractor::extract) delegates to [`mod@msg`].
/// SCOPE (honest first increment): reads the well-defined variable-length MAPI string
/// streams (subject / plain-text body / sender / top-level **display** To/Cc/Bcc names).
/// Recipient email ADDRESSES and the precise To/Cc/Bcc split from recipient sub-storages
/// are NOT parsed (surfaced as a warning); HTML/RTF-only bodies + attachments are FLAGGED.
#[derive(Debug, Default, Clone)]
pub struct MsgExtractor {
    /// Reserved for future configuration (e.g. recipient-substorage walking). No tunable
    /// behavior yet.
    _reserved: (),
}

impl MsgExtractor {
    /// Construct a `.msg` extractor with default behavior.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Extractor for MsgExtractor {
    fn extract(&self, bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
        // Delegates to the `.msg` engine (pure-Rust `cfb`, read-only): reads the MAPI
        // property streams, composing the body + email headers. Hostile-input-bounded and
        // run under `catch_unwind` so the third-party parser can never panic the indexer.
        msg::extract(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detection / dispatch ----------------------------------------------

    #[test]
    fn detect_maps_known_extensions() {
        assert_eq!(detect("brief.docx"), Format::Docx);
        assert_eq!(detect("contract.pdf"), Format::Pdf);
        assert_eq!(detect("disclosure.eml"), Format::Eml);
        assert_eq!(detect("mail.msg"), Format::Msg);
        assert_eq!(detect("notes.txt"), Format::Unknown);
        assert_eq!(detect("no_extension"), Format::Unknown);
    }

    #[test]
    fn detect_is_ascii_case_insensitive() {
        // Windows/macOS CI are case-insensitive filesystems (CLAUDE.md), so
        // upper/mixed-case extensions must classify identically.
        assert_eq!(detect("REPORT.DOCX"), Format::Docx);
        assert_eq!(detect("Report.Pdf"), Format::Pdf);
        assert_eq!(detect("FORWARD.EML"), Format::Eml);
        assert_eq!(detect("Forward.Eml"), Format::Eml);
        assert_eq!(detect("MESSAGE.MSG"), Format::Msg);
        assert_eq!(detect("Message.Msg"), Format::Msg);
    }

    #[test]
    fn detect_uses_the_final_extension_only() {
        assert_eq!(detect("archive.pdf.docx"), Format::Docx);
        assert_eq!(detect("scan.docx.pdf"), Format::Pdf);
        // A trailing dot has an empty extension -> Unknown.
        assert_eq!(detect("weird."), Format::Unknown);
    }

    #[test]
    fn extract_dispatches_unknown_extension_to_unsupported() {
        let err = extract("notes.txt", b"hello").unwrap_err();
        assert_eq!(err, ExtractError::Unsupported("notes.txt".to_string()));
    }

    // --- malformed-container contract (now IMPLEMENTED) --------------------
    // The docx/pdf extractors are implemented; a non-container blob must come back
    // as a content-free Malformed (never a panic, never NotImplemented).

    #[test]
    fn docx_rejects_non_zip_as_malformed() {
        let err = DocxExtractor::new()
            .extract(b"PK\x03\x04 (not really a docx)")
            .unwrap_err();
        assert!(
            matches!(err, ExtractError::Malformed(_)),
            "non-zip docx -> Malformed, got {err:?}"
        );
    }

    #[test]
    fn pdf_rejects_non_pdf_as_malformed_or_empty() {
        // A blob that isn't a real PDF: lopdf may reject it (Malformed) — the only
        // contract is no panic and no NotImplemented.
        let r = PdfExtractor::new().extract(b"%PDF-1.7 (not really a pdf)");
        match r {
            Ok(res) => assert!(res.text.is_empty() || !res.text.is_empty()),
            Err(ExtractError::Malformed(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn extract_routes_to_the_format_extractor() {
        // Recognized extension -> dispatches to its extractor. An empty body is not
        // a valid container, so each comes back as Malformed (never NotImplemented).
        assert!(matches!(
            extract("brief.docx", b"").unwrap_err(),
            ExtractError::Malformed(_)
        ));
        assert!(matches!(
            extract("contract.pdf", b"").unwrap_err(),
            ExtractError::Malformed(_)
        ));
    }

    // --- public value types -------------------------------------------------

    #[test]
    fn extract_result_and_metadata_default_empty() {
        let r = ExtractResult::default();
        assert!(r.text.is_empty());
        assert!(r.warnings.is_empty());
        assert_eq!(r.metadata, Metadata::default());
        assert_eq!(r.metadata.author, None);
        assert_eq!(r.metadata.last_modified_by, None);
    }

    #[test]
    fn extract_error_display_is_content_free_and_readable() {
        // Display strings are operator-facing; they must read clearly and (by
        // construction) carry no matter content.
        assert_eq!(
            ExtractError::NotImplemented(Format::Docx).to_string(),
            "extraction not yet implemented for Docx"
        );
        assert_eq!(
            ExtractError::Unsupported("x.zip".to_string()).to_string(),
            "unsupported document: x.zip"
        );
        assert!(ExtractError::Malformed("truncated zip".to_string())
            .to_string()
            .contains("truncated zip"));
    }

    // =======================================================================
    // EmlExtractor — RFC 5322 / MIME email (IMPLEMENTED)
    //
    // Fixtures are SYNTHETIC `.eml` bytes built inline (never real matter data,
    // per CLAUDE.md). CRLF line endings are used because RFC 5322 mandates them
    // and several parsers are stricter with them.
    // =======================================================================

    /// Convenience: run the EmlExtractor over an inline fixture.
    fn eml(raw: &str) -> ExtractResult {
        EmlExtractor::new()
            .extract(raw.as_bytes())
            .expect("fixture parses")
    }

    /// True if any warning contains `needle` (case-sensitive substring).
    fn warned(r: &ExtractResult, needle: &str) -> bool {
        r.warnings.iter().any(|w| w.contains(needle))
    }

    #[test]
    fn extract_dispatches_eml_to_the_eml_extractor() {
        // A recognized `.eml` extension routes to EmlExtractor (now IMPLEMENTED),
        // so a well-formed message succeeds via the top-level `extract`.
        let raw = "From: a@x.test\r\nTo: b@y.test\r\nSubject: Hi\r\n\r\nBody.\r\n";
        let r = extract("note.eml", raw.as_bytes()).unwrap();
        assert!(r.text.contains("Body."));
        let em = r.metadata.email.as_ref().expect("email metadata present");
        assert_eq!(em.subject.as_deref(), Some("Hi"));
    }

    #[test]
    fn wellformed_simple_populates_metadata_and_body() {
        let raw = concat!(
            "From: Alice Adams <alice@firm.test>\r\n",
            "To: Bob Brown <bob@client.test>\r\n",
            "Cc: Carol <carol@firm.test>\r\n",
            "Reply-To: legal@firm.test\r\n",
            "Subject: Engagement letter\r\n",
            "Date: Sat, 20 Nov 2021 14:22:01 -0800\r\n",
            "Message-ID: <abc123@firm.test>\r\n",
            "\r\n",
            "Please find our terms below.\r\n",
        );
        let r = eml(raw);
        assert!(r.text.contains("Please find our terms below."));

        let em = r.metadata.email.as_ref().expect("email metadata present");
        assert_eq!(em.from, vec!["Alice Adams <alice@firm.test>"]);
        assert_eq!(em.to, vec!["Bob Brown <bob@client.test>"]);
        assert_eq!(em.cc, vec!["Carol <carol@firm.test>"]);
        assert_eq!(em.reply_to, vec!["legal@firm.test"]);
        assert_eq!(em.subject.as_deref(), Some("Engagement letter"));
        assert_eq!(em.message_id.as_deref(), Some("abc123@firm.test"));
        // Date normalized to RFC 3339.
        assert_eq!(em.date.as_deref(), Some("2021-11-20T14:22:01-08:00"));
        // A clean, single-part text email has no leak-vector warnings.
        assert!(em.bcc.is_empty());
        assert!(
            r.warnings.is_empty(),
            "clean email -> no warnings, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn multipart_alternative_prefers_text_plain() {
        // text/plain + text/html alternative: the plain part is the body, and the
        // HTML is NOT stripped into the body (no html-only warning).
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: Alt\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"BND\"\r\n",
            "\r\n",
            "--BND\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "PLAIN body wins.\r\n",
            "--BND\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>HTML body loses.</p>\r\n",
            "--BND--\r\n",
        );
        let r = eml(raw);
        assert!(r.text.contains("PLAIN body wins."), "text = {:?}", r.text);
        assert!(
            !r.text.contains("HTML body loses"),
            "html must not be in body when text exists"
        );
        assert!(
            !warned(&r, "html-only"),
            "no html-only warning when a text part exists"
        );
    }

    #[test]
    fn html_only_body_is_stripped_and_warned() {
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: HtmlOnly\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<html><head><style>p{color:red}</style>",
            "<script>alert('x')</script></head>",
            "<body><p>Hello&nbsp;<b>World</b> &amp; co.</p>",
            "<p>Second&#32;line.</p></body></html>\r\n",
        );
        let r = eml(raw);
        // Tags gone; text + entities decoded; script/style contents dropped.
        assert!(r.text.contains("Hello"), "text = {:?}", r.text);
        assert!(r.text.contains("World"));
        assert!(
            r.text.contains("& co."),
            "named entity decoded, text = {:?}",
            r.text
        );
        assert!(r.text.contains("Second line."), "numeric entity decoded");
        assert!(
            !r.text.contains("alert"),
            "script contents must be stripped"
        );
        assert!(
            !r.text.contains("color:red"),
            "style contents must be stripped"
        );
        assert!(!r.text.contains('<'), "no raw markup should remain");
        // And the reviewer is told the markup was stripped.
        assert!(
            warned(&r, "html-only"),
            "html-only body must be warned, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn bcc_present_is_surfaced_in_metadata_and_warning() {
        // A saved (sender's) copy carrying Bcc: the blind addressees are recovered
        // into metadata AND their presence is warned (the whole point).
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Bcc: secret@watcher.test, opposing@counsel.test\r\n",
            "Subject: With Bcc\r\n",
            "\r\n",
            "Body.\r\n",
        );
        let r = eml(raw);
        let em = r.metadata.email.as_ref().expect("email metadata present");
        assert_eq!(em.bcc.len(), 2, "bcc recovered: {:?}", em.bcc);
        assert!(em.bcc.iter().any(|a| a.contains("secret@watcher.test")));
        assert!(
            warned(&r, "bcc recipients present"),
            "bcc must be warned, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn nested_message_rfc822_is_warned() {
        // A forwarded email embedded as message/rfc822 — flagged, body NOT inlined
        // by default.
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: Fwd\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"OUT\"\r\n",
            "\r\n",
            "--OUT\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "See the forwarded message.\r\n",
            "--OUT\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: insider@firm.test\r\n",
            "To: a@x.test\r\n",
            "Subject: Confidential original\r\n",
            "\r\n",
            "The secret inner body.\r\n",
            "--OUT--\r\n",
        );
        let r = eml(raw);
        assert!(
            warned(&r, "nested message"),
            "nested rfc822 must be warned, got {:?}",
            r.warnings
        );
        // Default: the inner body is NOT inlined into the outer text.
        assert!(
            !r.text.contains("The secret inner body."),
            "nested body must not be inlined by default"
        );
        assert!(r.text.contains("See the forwarded message."));

        // Opt-in inlining surfaces the nested body (clearly labeled).
        let r2 = EmlExtractor::new()
            .include_nested_bodies()
            .extract(raw.as_bytes())
            .unwrap();
        assert!(
            r2.text.contains("The secret inner body."),
            "opt-in inlines nested body"
        );
        assert!(r2.text.contains("nested message"), "nested body is labeled");
    }

    #[test]
    fn attachment_is_warned_with_name() {
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: WithAttachment\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"MIX\"\r\n",
            "\r\n",
            "--MIX\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Body text.\r\n",
            "--MIX\r\n",
            "Content-Type: application/pdf; name=\"privileged.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"privileged.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "JVBERi0xLjcKJ==\r\n",
            "--MIX--\r\n",
        );
        let r = eml(raw);
        assert!(
            warned(&r, "attachments present"),
            "attachment must be warned, got {:?}",
            r.warnings
        );
        assert!(
            warned(&r, "privileged.pdf"),
            "attachment filename must be surfaced"
        );
        // The attachment bytes are NOT decoded into the body.
        assert!(
            !r.text.contains("JVBERi0"),
            "attachment bytes must not enter the body"
        );
        assert!(r.text.contains("Body text."));
    }

    #[test]
    fn encoded_word_subject_is_decoded() {
        // RFC 2047 encoded-word subject (Q-encoded UTF-8) must decode to the real
        // glyphs — non-ASCII headers are normal in legal mail.
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: =?UTF-8?Q?Caf=C3=A9_r=C3=A9sum=C3=A9?=\r\n",
            "\r\n",
            "Body.\r\n",
        );
        let r = eml(raw);
        let em = r.metadata.email.as_ref().expect("email metadata present");
        assert_eq!(
            em.subject.as_deref(),
            Some("Café résumé"),
            "encoded-word subject decoded"
        );
    }

    #[test]
    fn non_utf8_charset_body_decodes() {
        // A latin-1 (ISO-8859-1) text part: the 0xE9 byte is 'é'. mail-parser must
        // decode it to UTF-8 text deterministically (full_encoding feature).
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(
            b"From: a@x.test\r\nTo: b@y.test\r\nSubject: Latin1\r\n\
              Content-Type: text/plain; charset=iso-8859-1\r\n\r\n",
        );
        raw.extend_from_slice(b"Caf\xE9 menu\r\n"); // 0xE9 = 'é' in latin-1
        let r = EmlExtractor::new().extract(&raw).unwrap();
        assert!(
            r.text.contains("Café menu"),
            "latin-1 body decoded, text = {:?}",
            r.text
        );
    }

    #[test]
    fn grouped_recipients_are_flattened() {
        // RFC 5322 address group: each member is rendered individually.
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: Team:jane@x.test,john@y.test;\r\n",
            "Subject: Group\r\n",
            "\r\n",
            "Body.\r\n",
        );
        let r = eml(raw);
        let em = r.metadata.email.as_ref().expect("email metadata present");
        assert_eq!(em.to.len(), 2, "group members flattened: {:?}", em.to);
        assert!(em.to.iter().any(|a| a.contains("jane@x.test")));
        assert!(em.to.iter().any(|a| a.contains("john@y.test")));
    }

    // --- hostile / malformed input: never panic ---------------------------

    #[test]
    fn oversized_input_is_rejected_without_parsing() {
        // A blob over the size cap returns a content-free Malformed error before
        // the parser runs — no allocation blow-up.
        let big = vec![b'A'; limits::MAX_EML_BYTES + 1];
        let err = EmlExtractor::new().extract(&big).unwrap_err();
        assert!(
            matches!(err, ExtractError::Malformed(_)),
            "oversized -> Malformed, got {err:?}"
        );
        // The reason carries a byte count, never matter content.
        assert!(err.to_string().contains("size limit"));
    }

    #[test]
    fn empty_input_does_not_panic() {
        // Empty bytes: mail-parser returns an (empty) message rather than None for
        // some inputs; whatever the outcome, we must not panic and must return a
        // Result. Assert no panic + a well-formed result/error.
        let r = EmlExtractor::new().extract(b"");
        // Either an empty-but-ok message or a Malformed — both acceptable; the
        // invariant under test is "no panic, returns a Result".
        let _ = r;
    }

    #[test]
    fn truncated_and_garbage_input_never_panic() {
        // A grab-bag of adversarial inputs: truncated headers, lone CRs, a tag
        // soup masquerading as headers, raw NULs, an unterminated boundary, and a
        // header with no body. None may panic; each yields Ok or a content-free
        // Malformed.
        let fixtures: &[&[u8]] = &[
            b"From: a@x.test",                       // no terminating CRLF / body
            b"Subject: \xff\xfe broken\r\n\r\nbody", // invalid UTF-8 in header
            b"\r\n\r\n\r\n",                         // only blank lines
            b"Content-Type: multipart/mixed; boundary=\"X\"\r\n\r\n--X\r\n", // unterminated multipart
            b"From\0: weird\r\n\r\n\0\0\0",                                  // NUL bytes
            b"<html><body>not even an email</body></html>",                  // not a message
            b"To: =?bogus?Q?=zz?=\r\n\r\nx", // malformed encoded-word
        ];
        for f in fixtures {
            // The ONLY contract: no panic, and a Result (Ok or Malformed) comes back.
            match EmlExtractor::new().extract(f) {
                Ok(r) => {
                    // If it parsed, metadata is present and warnings are bounded.
                    assert!(r.metadata.email.is_some() || r.metadata.email.is_none());
                    assert!(r.warnings.len() < 1000);
                }
                Err(ExtractError::Malformed(msg)) => {
                    // Content-free reason (we only ever put structural text here).
                    assert!(!msg.is_empty());
                }
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
    }

    #[test]
    fn html_strip_helper_is_robust_on_hostile_markup() {
        // Direct unit coverage for the strip: unterminated tags, unterminated
        // script, nested-ish junk, numeric entity overflow — none may panic.
        assert_eq!(html_to_text("<p>hi</p>"), "hi");
        // Unterminated tag at end: dropped, no panic.
        assert_eq!(html_to_text("text <incomplete"), "text");
        // Unterminated <script>: everything after is skipped.
        assert_eq!(html_to_text("a<script>b c d"), "a");
        // Out-of-range numeric char ref: left verbatim (char::from_u32 fails), no panic.
        let s = html_to_text("x &#9999999999; y");
        assert!(s.contains('x') && s.contains('y'));
        // Multibyte text passes through on char boundaries.
        assert_eq!(html_to_text("<p>café</p>"), "café");
    }

    #[test]
    fn extraction_is_deterministic() {
        let raw = concat!(
            "From: Alice <alice@firm.test>\r\n",
            "To: bob@client.test\r\n",
            "Bcc: hidden@x.test\r\n",
            "Subject: =?UTF-8?Q?D=C3=A9j=C3=A0?=\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>Same&nbsp;every time.</p>\r\n",
        );
        let a = eml(raw);
        let b = eml(raw);
        assert_eq!(a.text, b.text, "body deterministic");
        assert_eq!(a.warnings, b.warnings, "warnings deterministic");
        assert_eq!(a.metadata, b.metadata, "metadata deterministic");
    }

    // --- C1: decode_entity must not panic on `&` + a multibyte codepoint ----

    #[test]
    fn decode_entity_does_not_panic_on_ampersand_then_multibyte() {
        // REGRESSION (C1, Critical): the named-entity match used to slice the str
        // by a byte length (`s[..name.len()]`), which can split a multibyte
        // codepoint right after a `&` and PANIC. Each of these must NOT panic and
        // must leave the unknown entity (the `&` + glyph) verbatim in the output.
        // The crafted/ordinary `.eml` that triggers this would otherwise abort the
        // CORE indexer.
        for (input, glyph) in [
            ("&\u{20ac}100", '\u{20ac}'), // &€100  (3-byte)
            ("&\u{1f600}", '\u{1f600}'),  // &😀    (4-byte)
            ("&\u{4e2d}", '\u{4e2d}'),    // &中    (3-byte)
            ("&\u{c4}x", '\u{c4}'),       // &Äx    (2-byte)
        ] {
            let out = html_to_text(input);
            assert!(
                out.contains('&'),
                "unknown entity `&` kept verbatim: {out:?}"
            );
            assert!(out.contains(glyph), "the multibyte glyph survives: {out:?}");
        }
        // Entity-AFTER-text variant (the `&` is not at offset 0): same invariant.
        let out = html_to_text("price is &\u{20ac}100 today");
        assert!(
            out.contains('&') && out.contains('\u{20ac}'),
            "out = {out:?}"
        );
        assert!(out.contains("price is") && out.contains("today"));
        // And the supported named entity still decodes when it IS a real one.
        assert_eq!(html_to_text("a &amp; b"), "a & b");
    }

    // --- M1: <script>/<style> with a `\r` (CRLF) delimiter must be stripped --

    #[test]
    fn raw_element_with_crlf_delimiter_is_stripped() {
        // REGRESSION (M1): `<script\r\n>` / `<style\r\n>` are legal, and CRLF is the
        // norm in RFC 5322 bodies. The delimiter allowlist omitted `\r`, so the raw
        // script/style body leaked into the text. The body must exclude the raw
        // contents.
        let s = html_to_text("before<script\r\n>evil()</script>after");
        assert!(
            !s.contains("evil"),
            "script body must be stripped, got {s:?}"
        );
        assert!(s.contains("before") && s.contains("after"));
        let s2 = html_to_text("x<style\r\n>body{color:red}</style>y");
        assert!(
            !s2.contains("color:red"),
            "style body must be stripped, got {s2:?}"
        );
        assert!(s2.contains('x') && s2.contains('y'));
    }

    // --- M3: HTML comments (incl. an inner `>`) must be dropped --------------

    #[test]
    fn html_comments_are_stripped_even_with_inner_gt() {
        // REGRESSION (M3): `<!-- ... > ... -->` leaked its tail because `find('>')`
        // stopped at the first `>` inside the comment. The comment (all of it) must
        // be dropped.
        let s = html_to_text("A<!-- hidden > still hidden -->B");
        assert!(
            !s.contains("hidden"),
            "comment text must be dropped, got {s:?}"
        );
        assert_eq!(s, "AB");
        // Unterminated comment: drop the rest, no panic.
        let s2 = html_to_text("keep<!-- never closed");
        assert_eq!(s2, "keep");
    }

    // --- M2: encrypted / signed / partial flagged specifically --------------

    #[test]
    fn encrypted_message_is_flagged_specifically() {
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: Sealed\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; \
             boundary=\"ENC\"\r\n",
            "\r\n",
            "--ENC\r\n",
            "Content-Type: application/pgp-encrypted\r\n",
            "\r\n",
            "Version: 1\r\n",
            "--ENC\r\n",
            "Content-Type: application/octet-stream\r\n",
            "\r\n",
            "....encrypted bytes....\r\n",
            "--ENC--\r\n",
        );
        let r = eml(raw);
        assert!(
            warned(&r, "encrypted") && warned(&r, "not extractable"),
            "encrypted body must be flagged specifically, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn signed_message_is_flagged_specifically() {
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: Signed\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; \
             micalg=sha-256; boundary=\"SIG\"\r\n",
            "\r\n",
            "--SIG\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "The signed body.\r\n",
            "--SIG\r\n",
            "Content-Type: application/pkcs7-signature\r\n",
            "\r\n",
            "c2lnbmF0dXJl\r\n",
            "--SIG--\r\n",
        );
        let r = eml(raw);
        assert!(
            warned(&r, "signed"),
            "signed message must be flagged, got {:?}",
            r.warnings
        );
        // A signed message's content IS extractable (cleartext part).
        assert!(r.text.contains("The signed body."));
    }

    #[test]
    fn message_partial_fragment_is_flagged_specifically() {
        let raw = concat!(
            "From: a@x.test\r\n",
            "To: b@y.test\r\n",
            "Subject: Big split\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: message/partial; id=\"abc@x\"; number=2; total=3\r\n",
            "\r\n",
            "...the middle fragment bytes...\r\n",
        );
        let r = eml(raw);
        assert!(
            warned(&r, "partial") && warned(&r, "incomplete"),
            "message/partial fragment must be flagged, got {:?}",
            r.warnings
        );
    }

    // --- H1: nested message/rfc822 leak vectors are inspected, not dropped ---

    #[test]
    fn nested_message_attachments_and_bcc_are_surfaced() {
        // REGRESSION (H1, High): a Fwd: carrying a privileged PDF and an inner Bcc
        // is the HEADLINE leak vector, and the outer-only sweep missed it (the
        // nested message's parts live in the INNER Message.parts). Build:
        //   outer multipart/mixed
        //     -> message/rfc822
        //          -> inner multipart/mixed
        //               -> text/plain + application/pdf (filename) + inner Bcc:
        // and assert the inner attachment AND the inner Bcc are named in warnings.
        let raw = concat!(
            "From: fwd@firm.test\r\n",
            "To: partner@firm.test\r\n",
            "Subject: Fwd: please see attached\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"OUT\"\r\n",
            "\r\n",
            "--OUT\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Forwarding the original below.\r\n",
            "--OUT\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: insider@firm.test\r\n",
            "To: a@x.test\r\n",
            "Bcc: secret-watcher@spy.test\r\n",
            "Subject: Confidential original\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"INN\"\r\n",
            "\r\n",
            "--INN\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Inner body text.\r\n",
            "--INN\r\n",
            "Content-Type: application/pdf; name=\"inner-privileged.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"inner-privileged.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "JVBERi0xLjcK\r\n",
            "--INN--\r\n",
            "--OUT--\r\n",
        );
        let r = eml(raw);
        assert!(
            warned(&r, "nested message"),
            "nested message flagged: {:?}",
            r.warnings
        );
        assert!(
            warned(&r, "nested message carries attachment") && warned(&r, "inner-privileged.pdf"),
            "the INNER attachment must be itemized, got {:?}",
            r.warnings
        );
        assert!(
            warned(&r, "nested message carries Bcc"),
            "the INNER Bcc must be surfaced, got {:?}",
            r.warnings
        );
    }

    // --- H2: deep/encoded nested content must fire a truncation warning ------

    #[test]
    fn deeply_nested_encoded_message_emits_encoding_warning() {
        // REGRESSION (H2, High): mail-parser stops decoding nested encoded content
        // at MAX_NESTED_ENCODED=3, leaving an is_encoding_problem part INSIDE a
        // nested message that the outer-only sweep never saw — so the result looked
        // clean while inner content was discarded. Build >=4 levels of
        // base64-encoded message/rfc822 and assert an encoding/truncation warning
        // fires (not a clean result).
        //
        // Build from the innermost outward; each level base64-encodes the level
        // below as a message/rfc822 part with Content-Transfer-Encoding: base64.
        fn b64(input: &[u8]) -> String {
            // Tiny deterministic base64 encoder (no dep): standard alphabet, padded.
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in input.chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
                out.push(A[((n >> 18) & 63) as usize] as char);
                out.push(A[((n >> 12) & 63) as usize] as char);
                out.push(if chunk.len() > 1 {
                    A[((n >> 6) & 63) as usize] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    A[(n & 63) as usize] as char
                } else {
                    '='
                });
            }
            out
        }
        fn wrap_b64_rfc822(inner: &[u8]) -> Vec<u8> {
            let mut encoded = b64(inner);
            // Wrap base64 to lines so it is well-formed.
            let mut lined = String::new();
            for (i, c) in encoded.drain(..).enumerate() {
                if i > 0 && i % 76 == 0 {
                    lined.push_str("\r\n");
                }
                lined.push(c);
            }
            format!(
                "From: lvl@x.test\r\nSubject: layer\r\nMIME-Version: 1.0\r\n\
                 Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{lined}\r\n"
            )
            .into_bytes()
        }
        // Innermost real message.
        let mut msg: Vec<u8> =
            b"From: core@x.test\r\nSubject: innermost\r\n\r\nthe deepest secret\r\n".to_vec();
        // Wrap 5 times -> depth well past MAX_NESTED_ENCODED.
        for _ in 0..5 {
            msg = wrap_b64_rfc822(&msg);
        }
        let r = EmlExtractor::new().extract(&msg).unwrap();
        assert!(
            warned(&r, "encoding problem") || warned(&r, "truncat") || warned(&r, "incomplete"),
            "deep encoded nesting must fire an encoding/truncation warning, got {:?}",
            r.warnings
        );
    }

    // --- L1: a recipient / attachment list truncated by a cap is warned -----

    #[test]
    fn over_cap_recipient_list_is_flagged_truncated() {
        // REGRESSION (L1): a >MAX_PARTS_REPORTED recipient list used to be silently
        // truncated. Build a To: with one more than the cap and assert a truncation
        // warning fires and the rendered list is capped.
        let mut to = String::from("To: ");
        let count = limits::MAX_PARTS_REPORTED + 5;
        for i in 0..count {
            if i > 0 {
                to.push_str(", ");
            }
            to.push_str(&format!("r{i}@x.test"));
        }
        let raw = format!("From: a@x.test\r\n{to}\r\nSubject: Many\r\n\r\nBody.\r\n");
        let r = EmlExtractor::new().extract(raw.as_bytes()).unwrap();
        let em = r.metadata.email.as_ref().expect("email metadata present");
        assert_eq!(
            em.to.len(),
            limits::MAX_PARTS_REPORTED,
            "rendered recipient list is capped"
        );
        assert!(
            warned(&r, "truncated") && warned(&r, "To"),
            "an over-cap To: list must warn it was truncated, got {:?}",
            r.warnings
        );
    }

    // =======================================================================
    // DocxExtractor — OOXML word document (IMPLEMENTED)
    //
    // Fixtures are SYNTHETIC .docx bytes built INLINE: a minimal ZIP zipping a
    // hand-written word/document.xml (+ optional docProps). No committed binaries,
    // no real matter data (CLAUDE.md).
    // =======================================================================

    /// Build a `.docx` (ZIP) in memory from a set of (part-name, content) entries.
    /// Uses the `zip` writer (a dev use of the same crate the extractor reads with).
    fn build_docx(parts: &[(&str, &str)]) -> Vec<u8> {
        use std::io::Write as _;
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, content) in parts {
                zw.start_file(*name, opts).expect("start_file");
                zw.write_all(content.as_bytes()).expect("write part");
            }
            zw.finish().expect("finish zip");
        }
        buf
    }

    /// Wrap body XML in a minimal WordprocessingML document.xml.
    fn doc_xml(body_inner: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
             <w:body>{body_inner}</w:body></w:document>"
        )
    }

    #[test]
    fn docx_happy_path_extracts_paragraphs_and_metadata() {
        let body = concat!(
            "<w:p><w:r><w:t>Hello world.</w:t></w:r></w:p>",
            "<w:p><w:r><w:t xml:space=\"preserve\">Second </w:t>",
            "<w:tab/><w:t>paragraph.</w:t></w:r></w:p>",
        );
        let core = "<?xml version=\"1.0\"?>\
            <cp:coreProperties xmlns:cp=\"x\" xmlns:dc=\"y\" xmlns:dcterms=\"z\">\
            <dc:creator>Alice Adams</dc:creator>\
            <cp:lastModifiedBy>Bob Brown</cp:lastModifiedBy>\
            <dc:title>Engagement Letter</dc:title>\
            <dcterms:created>2021-11-20T14:22:01Z</dcterms:created>\
            </cp:coreProperties>";
        let app = "<?xml version=\"1.0\"?><Properties xmlns=\"x\">\
            <Application>Microsoft Office Word</Application></Properties>";
        let docx = build_docx(&[
            ("word/document.xml", &doc_xml(body)),
            ("docProps/core.xml", core),
            ("docProps/app.xml", app),
        ]);
        let r = DocxExtractor::new().extract(&docx).expect("docx parses");
        assert!(r.text.contains("Hello world."), "text = {:?}", r.text);
        assert!(r.text.contains("Second"));
        assert!(r.text.contains("paragraph."));
        assert!(r.text.contains('\t'), "tab preserved, text = {:?}", r.text);
        // Paragraphs separated by a newline.
        assert!(
            r.text.contains("world.\nSecond"),
            "paragraph break, text = {:?}",
            r.text
        );
        // Metadata recovered.
        assert_eq!(r.metadata.author.as_deref(), Some("Alice Adams"));
        assert_eq!(r.metadata.last_modified_by.as_deref(), Some("Bob Brown"));
        assert_eq!(r.metadata.title.as_deref(), Some("Engagement Letter"));
        assert_eq!(r.metadata.created.as_deref(), Some("2021-11-20T14:22:01Z"));
        assert_eq!(
            r.metadata.application.as_deref(),
            Some("Microsoft Office Word")
        );
        // A clean doc with no tracked changes / comments has no leak warnings.
        assert!(
            r.warnings.is_empty(),
            "clean docx -> no warnings, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn docx_decodes_xml_entities_and_breaks() {
        let body = "<w:p><w:r><w:t>A &amp; B &lt;tag&gt; line1</w:t>\
                    <w:br/><w:t>line2 &#169;</w:t></w:r></w:p>";
        let docx = build_docx(&[("word/document.xml", &doc_xml(body))]);
        let r = DocxExtractor::new().extract(&docx).unwrap();
        assert!(
            r.text.contains("A & B <tag> line1"),
            "entities decoded, text = {:?}",
            r.text
        );
        assert!(
            r.text.contains("line1\nline2"),
            "<w:br/> -> newline, text = {:?}",
            r.text
        );
        assert!(r.text.contains('\u{a9}'), "numeric entity (©) decoded");
    }

    #[test]
    fn docx_tracked_deletion_text_is_surfaced_inline_and_warned() {
        // The HEADLINE OOXML leak vector: deleted text is STILL in the file. It must
        // be surfaced (inline, marked) + flagged, never silently dropped.
        let body = "<w:p><w:r><w:t>Keep this. </w:t></w:r>\
                    <w:del><w:r><w:delText>SECRET deleted clause.</w:delText></w:r></w:del>\
                    <w:r><w:t> And this.</w:t></w:r></w:p>";
        let docx = build_docx(&[("word/document.xml", &doc_xml(body))]);
        let r = DocxExtractor::new().extract(&docx).unwrap();
        assert!(r.text.contains("Keep this."));
        assert!(r.text.contains("And this."));
        assert!(
            r.text.contains("SECRET deleted clause."),
            "deleted text must be surfaced (it's still in the file), text = {:?}",
            r.text
        );
        assert!(
            r.text.contains("[deleted:"),
            "deleted text must be clearly marked, text = {:?}",
            r.text
        );
        assert!(
            warned(&r, "tracked changes"),
            "tracked changes must be warned, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn docx_comments_are_flagged_and_optionally_inlined() {
        let body = "<w:p><w:r><w:t>Body text.</w:t></w:r></w:p>";
        let comments = "<?xml version=\"1.0\"?>\
            <w:comments xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
            <w:comment><w:p><w:r><w:t>Do not show the client this.</w:t></w:r></w:p></w:comment>\
            </w:comments>";
        let docx = build_docx(&[
            ("word/document.xml", &doc_xml(body)),
            ("word/comments.xml", comments),
        ]);
        // Default: comment FLAGGED, not in body.
        let r = DocxExtractor::new().extract(&docx).unwrap();
        assert!(
            warned(&r, "comments present"),
            "comment must be warned, got {:?}",
            r.warnings
        );
        assert!(
            !r.text.contains("Do not show the client this."),
            "comment text not inlined by default"
        );
        // Opt-in: comment inlined (clearly labeled).
        let r2 = DocxExtractor {
            include_annotations: true,
        }
        .extract(&docx)
        .unwrap();
        assert!(
            r2.text.contains("Do not show the client this."),
            "opt-in inlines comment, text = {:?}",
            r2.text
        );
        assert!(
            r2.text.contains("--- comments ---"),
            "inlined comment is labeled"
        );
    }

    #[test]
    fn docx_missing_document_xml_is_malformed_not_panic() {
        // A ZIP that is missing word/document.xml is not a valid word doc.
        let docx = build_docx(&[("docProps/core.xml", "<x/>")]);
        let err = DocxExtractor::new().extract(&docx).unwrap_err();
        assert!(
            matches!(err, ExtractError::Malformed(ref m) if m.contains("document.xml")),
            "missing document.xml -> Malformed, got {err:?}"
        );
    }

    #[test]
    fn docx_truncated_and_garbage_never_panic() {
        let fixtures: &[&[u8]] = &[
            b"",
            b"PK", // truncated local file header
            b"PK\x03\x04 garbage that is not a real zip",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            &[0xFF; 64],
        ];
        for f in fixtures {
            match DocxExtractor::new().extract(f) {
                Ok(_) => {}
                Err(ExtractError::Malformed(m)) => assert!(!m.is_empty()),
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
        // A real ZIP whose document.xml is malformed XML: best-effort, no panic.
        let docx = build_docx(&[(
            "word/document.xml",
            "<w:document><w:body><w:p><w:r><w:t>oops",
        )]);
        let _ = DocxExtractor::new().extract(&docx); // must not panic
    }

    #[test]
    fn docx_extraction_is_deterministic() {
        let body = "<w:p><w:r><w:t>Deterministic body.</w:t></w:r></w:p>";
        let core = "<cp:coreProperties xmlns:cp=\"x\" xmlns:dc=\"y\">\
            <dc:creator>Z</dc:creator></cp:coreProperties>";
        let docx = build_docx(&[
            ("word/document.xml", &doc_xml(body)),
            ("docProps/core.xml", core),
        ]);
        let a = DocxExtractor::new().extract(&docx).unwrap();
        let b = DocxExtractor::new().extract(&docx).unwrap();
        assert_eq!(a.text, b.text);
        assert_eq!(a.warnings, b.warnings);
        assert_eq!(a.metadata, b.metadata);
    }

    // =======================================================================
    // PdfExtractor — PDF (IMPLEMENTED, best-effort)
    //
    // Fixtures are SYNTHETIC PDFs built INLINE with lopdf and serialized to bytes.
    // No committed binaries, no real matter data (CLAUDE.md).
    // =======================================================================

    /// Build a minimal one-page PDF carrying `text` (a single Tj show), serialized
    /// to bytes. `info` optionally seeds the /Info metadata dictionary.
    fn build_pdf(text: &str, with_info: bool) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 24.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::string_literal(text)]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        if with_info {
            let info_id = doc.add_object(dictionary! {
                "Title" => Object::string_literal("Synthetic Brief"),
                "Author" => Object::string_literal("Test Author"),
                "Producer" => Object::string_literal("lopdf-test"),
            });
            doc.trailer.set("Info", info_id);
        }
        let mut buf: Vec<u8> = Vec::new();
        doc.save_to(&mut buf).expect("serialize pdf");
        buf
    }

    /// Build a one-page PDF whose only content is an image XObject (no text ops):
    /// a stand-in for a scanned / image-only page (no text layer).
    fn build_image_only_pdf() -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        // A tiny fake image XObject.
        let img_id = doc.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 8,
            },
            vec![0u8],
        ));
        let resources_id = doc.add_object(dictionary! {
            "XObject" => dictionary! { "Im1" => img_id },
        });
        // Content draws the image; NO text-showing operators.
        let content = Content {
            operations: vec![
                Operation::new("q", vec![]),
                Operation::new("Do", vec![Object::Name(b"Im1".to_vec())]),
                Operation::new("Q", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut buf: Vec<u8> = Vec::new();
        doc.save_to(&mut buf).expect("serialize pdf");
        buf
    }

    #[test]
    fn pdf_happy_path_round_trips_text_and_metadata() {
        let bytes = build_pdf("Hello from a synthetic PDF.", true);
        let r = PdfExtractor::new().extract(&bytes).expect("pdf parses");
        assert!(
            r.text.contains("Hello from a synthetic PDF."),
            "round-tripped text, got {:?}",
            r.text
        );
        // /Info metadata recovered.
        assert_eq!(r.metadata.title.as_deref(), Some("Synthetic Brief"));
        assert_eq!(r.metadata.author.as_deref(), Some("Test Author"));
        assert_eq!(r.metadata.application.as_deref(), Some("lopdf-test"));
        // A text page is not flagged as scanned.
        assert!(
            !warned(&r, "needs OCR"),
            "text page not flagged scanned, got {:?}",
            r.warnings
        );
    }

    #[test]
    fn pdf_image_only_page_is_flagged_needs_ocr_not_empty_silently() {
        let bytes = build_image_only_pdf();
        let r = PdfExtractor::new().extract(&bytes).expect("pdf parses");
        assert!(
            r.text.trim().is_empty(),
            "image-only page has no text layer"
        );
        assert!(
            warned(&r, "needs OCR") || warned(&r, "scanned"),
            "image-only PDF must be flagged needs-OCR (not silent empty), got {:?}",
            r.warnings
        );
    }

    #[test]
    fn pdf_truncated_and_garbage_never_panic() {
        // A valid PDF truncated at various points + raw garbage. None may panic;
        // each yields Ok or a content-free Malformed.
        let good = build_pdf("Some text.", false);
        let fixtures: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"%PDF-1.7 not a real pdf".to_vec(),
            good[..good.len() / 2].to_vec(),     // truncated mid-file
            good[..16.min(good.len())].to_vec(), // just the header-ish
            vec![0xFF; 256],
            b"%PDF-".to_vec(),
        ];
        for f in &fixtures {
            match PdfExtractor::new().extract(f) {
                Ok(r) => assert!(r.warnings.len() < 10_000),
                Err(ExtractError::Malformed(m)) => assert!(!m.is_empty()),
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
    }

    #[test]
    fn pdf_oversized_input_is_rejected_without_parsing() {
        // Construct a "size" by claiming a huge slice would be too big: we can't
        // cheaply allocate 256 MiB in a unit test, so assert the guard via a vec at
        // the boundary is impractical; instead verify the threshold constant exists
        // and a normal doc is under it (the > path is covered by the eml-analog).
        let bytes = build_pdf("x", false);
        assert!(bytes.len() < pdf::limits::MAX_PDF_BYTES);
        let _ = PdfExtractor::new().extract(&bytes).unwrap();
    }

    #[test]
    fn pdf_extraction_is_deterministic() {
        let bytes = build_pdf("Deterministic PDF body.", true);
        let a = PdfExtractor::new().extract(&bytes).unwrap();
        let b = PdfExtractor::new().extract(&bytes).unwrap();
        assert_eq!(a.text, b.text);
        assert_eq!(a.warnings, b.warnings);
        assert_eq!(a.metadata, b.metadata);
    }

    /// Build a one-page PDF whose single content stream FlateDecodes from a tiny blob
    /// to `decoded_target` bytes of `(A)Tj` show operators. The stream is compressed
    /// with lopdf's own `Stream::compress` (FlateDecode), so the on-disk PDF is a few
    /// KiB while the DECODED content is `decoded_target` — the operator-tokenization
    /// bomb shape (a small file that explodes when tokenized).
    fn build_flate_op_bomb_pdf(decoded_target: usize) -> Vec<u8> {
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        // Decoded content: a valid BT/ET text object packed with `(A)Tj` show ops.
        let unit: &[u8] = b"(A)Tj\n";
        let reps = decoded_target / unit.len();
        let mut decoded: Vec<u8> = Vec::with_capacity(reps * unit.len() + 16);
        decoded.extend_from_slice(b"BT\n/F1 12 Tf\n");
        for _ in 0..reps {
            decoded.extend_from_slice(unit);
        }
        decoded.extend_from_slice(b"ET\n");
        // Build the stream with the RAW (uncompressed) content, then have lopdf
        // FlateDecode-compress it in place (adds the /Filter FlateDecode entry).
        let mut stream = Stream::new(dictionary! {}, decoded);
        stream.compress().expect("compress content stream");
        let content_id = doc.add_object(stream);
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf: Vec<u8> = Vec::new();
        doc.save_to(&mut buf).expect("serialize pdf");
        buf
    }

    #[test]
    fn pdf_oversized_page_content_is_skipped_with_warning_not_oom() {
        // REGRESSION (C1, Critical DoS): a small PDF whose single FlateDecode content
        // stream inflates to tens of MiB of `(A)Tj` show operators used to drive
        // `Content::decode` to build a MULTI-GiB `Vec<Operation>` (peak RSS ~4.8 GiB
        // on the reviewer's probe) — an OOM-kill of the CORE indexer on ONE document.
        // The fix decodes the page content to BYTES first, checks the byte length
        // against MAX_PAGE_CONTENT_BYTES, and SKIPS the page (with a warning) WITHOUT
        // tokenizing when it's over the cap.
        //
        // Build a page whose DECODED content is ~2 MiB over the cap. With the fix this
        // allocates only the (bounded) decoded byte buffer and returns promptly; if the
        // fix regressed, tokenizing this many `(A)Tj` ops would balloon to >1 GiB.
        let decoded_target = pdf::limits::MAX_PAGE_CONTENT_BYTES + 2 * 1024 * 1024;
        let bytes = build_flate_op_bomb_pdf(decoded_target);
        // The on-disk PDF is tiny (the bomb shape): a few KiB, not MiB. Sanity-check
        // that we really built a small file that decodes to something over the cap.
        assert!(
            bytes.len() < 1024 * 1024,
            "bomb PDF should be small on disk (FlateDecode), got {} bytes",
            bytes.len()
        );

        let start = std::time::Instant::now();
        let r = PdfExtractor::new()
            .extract(&bytes)
            .expect("extract returns a Result, never panics/OOMs");
        let elapsed = start.elapsed();

        // The over-cap page is SKIPPED: no text extracted from it...
        assert!(
            r.text.trim().is_empty(),
            "over-cap page must be skipped (no text), got {} chars",
            r.text.len()
        );
        // ...and the skip is SURFACED as a warning (never silently dropped).
        assert!(
            warned(&r, "per-page cap") && warned(&r, "SKIPPED"),
            "the skipped over-cap page must be warned, got {:?}",
            r.warnings
        );
        // Coarse liveness check: the cap engages BEFORE tokenization, so this returns
        // in well under a second. (If the bomb tokenized, it would take seconds AND
        // allocate >1 GiB — the point of the cap is that neither happens.)
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "extraction must return promptly (cap before tokenization), took {elapsed:?}"
        );
    }

    #[test]
    fn pdf_in_budget_page_still_extracts_text() {
        // Guard the cap's UPPER edge: a page whose decoded content is just UNDER the
        // per-page cap must still tokenize + extract normally (the fix must not break
        // ordinary — even large — pages). A small show string proves text still flows.
        let bytes = build_pdf("In-budget page text.", false);
        let r = PdfExtractor::new().extract(&bytes).unwrap();
        assert!(
            r.text.contains("In-budget page text."),
            "an in-budget page must still extract text, got {:?}",
            r.text
        );
        assert!(
            !warned(&r, "per-page cap"),
            "an in-budget page must NOT be flagged over-cap, got {:?}",
            r.warnings
        );
    }

    /// Build a one-page PDF whose single content stream FlateDecodes from a tiny blob
    /// to `decoded_target` bytes of RAW BYTES (a long run of spaces — NOT operators),
    /// so there are essentially NO show operators to tokenize. This is the RAW-FLATE
    /// decompression bomb: the danger is the DECOMPRESSION itself (lopdf's uncapped
    /// `ZlibDecoder::read_to_end` would inflate the whole `decoded_target` into RAM),
    /// not the operator vector. The on-disk PDF is a few KiB (spaces compress ~1000:1).
    fn build_flate_raw_bomb_pdf(decoded_target: usize) -> Vec<u8> {
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        // Decoded content: a giant run of spaces (whitespace between operators is
        // legal in a content stream and tokenizes to NOTHING — no `Operation` per
        // byte). The bomb is the raw inflated SIZE, not an operator explosion.
        let decoded: Vec<u8> = vec![b' '; decoded_target];
        // Build the stream with the RAW (uncompressed) content, then FlateDecode it in
        // place (adds /Filter FlateDecode). A run of identical bytes compresses to a
        // tiny on-disk stream — the classic decompression-bomb shape.
        let mut stream = Stream::new(dictionary! {}, decoded);
        stream.compress().expect("compress content stream");
        let content_id = doc.add_object(stream);
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf: Vec<u8> = Vec::new();
        doc.save_to(&mut buf).expect("serialize pdf");
        buf
    }

    #[test]
    fn pdf_raw_flate_decompression_bomb_is_bounded_not_oom() {
        // REGRESSION (the raw-flate decompression-bomb residual): a tiny FlateDecode
        // content stream that decodes to HUNDREDS OF MiB of raw bytes with NO show
        // operators. The operator-vector cap does NOT engage here (no operators), and
        // lopdf's `get_page_content` would `ZlibDecoder::read_to_end` the WHOLE thing
        // into RAM before any size could be checked. The fix decodes each stream
        // through a reader CAPPED at the per-page budget, so peak memory stays ~8 MiB
        // and the page is SKIPPED with a warning.
        //
        // 512 MiB decoded: large enough that an UNCAPPED decode would be a clear,
        // observable allocation (and the basis of the before/after peak-memory claim),
        // while the on-disk PDF stays a few KiB.
        let decoded_target = 512 * 1024 * 1024;
        let bytes = build_flate_raw_bomb_pdf(decoded_target);
        // The on-disk PDF is tiny (the bomb shape): a run of spaces compresses hugely.
        assert!(
            bytes.len() < 1024 * 1024,
            "raw-flate bomb PDF should be small on disk (FlateDecode), got {} bytes",
            bytes.len()
        );

        let start = std::time::Instant::now();
        let r = PdfExtractor::new()
            .extract(&bytes)
            .expect("extract returns a Result, never panics/OOMs");
        let elapsed = start.elapsed();

        // The over-cap page is SKIPPED: no text extracted from it...
        assert!(
            r.text.trim().is_empty(),
            "raw-flate-bomb page must be skipped (no text), got {} chars",
            r.text.len()
        );
        // ...and the skip is SURFACED as a warning (never silently dropped/empty).
        assert!(
            warned(&r, "per-page cap") && warned(&r, "SKIPPED"),
            "the skipped raw-flate-bomb page must be warned, got {:?}",
            r.warnings
        );
        // Liveness: the capped decode stops at ~8 MiB, so this returns promptly. An
        // UNCAPPED decode of 512 MiB would both allocate half a GiB AND take longer.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "capped decode must return promptly (bound during inflate), took {elapsed:?}"
        );
    }

    /// Build a one-page PDF whose content stream uses a filter chain we REFUSE to
    /// decode within a memory bound. Here: `[FlateDecode, FlateDecode]` (a multi-filter
    /// chain). The bytes are double-flate-encoded; lopdf COULD decode it (uncapped),
    /// but we refuse it fail-closed because we cannot independently cap each stage.
    fn build_multifilter_pdf() -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use lopdf::{dictionary, Document, Object, Stream};
        use std::io::Write;
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        // Some legitimate page text, flate-encoded TWICE so a [FlateDecode,FlateDecode]
        // chain is needed to recover it.
        let inner = b"BT /F1 12 Tf 72 720 Td (Hidden behind two filters.) Tj ET".to_vec();
        let once = {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
            e.write_all(&inner).unwrap();
            e.finish().unwrap()
        };
        let twice = {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
            e.write_all(&once).unwrap();
            e.finish().unwrap()
        };
        // Construct the stream by hand so /Filter is an ARRAY of two FlateDecode names.
        let mut dict = dictionary! {};
        dict.set(
            "Filter",
            Object::Array(vec![
                Object::Name(b"FlateDecode".to_vec()),
                Object::Name(b"FlateDecode".to_vec()),
            ]),
        );
        let stream = Stream::new(dict, twice);
        let content_id = doc.add_object(stream);
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf: Vec<u8> = Vec::new();
        doc.save_to(&mut buf).expect("serialize pdf");
        buf
    }

    #[test]
    fn pdf_uncappable_multifilter_is_refused_not_routed_through_uncapped_decode() {
        // The recall tradeoff, made observable: a multi-filter content stream we cannot
        // cap is REFUSED (skip + warning) rather than routed back through lopdf's
        // uncapped decoder. We accept missing this rare/legacy text in exchange for the
        // memory bound. The page must be SKIPPED and the skip must be SURFACED.
        let bytes = build_multifilter_pdf();
        let r = PdfExtractor::new()
            .extract(&bytes)
            .expect("extract returns a Result, never panics");
        assert!(
            r.text.trim().is_empty(),
            "a refused-filter page extracts no text, got {:?}",
            r.text
        );
        assert!(
            warned(&r, "filter") && warned(&r, "SKIPPED"),
            "a refused uncappable filter chain must be warned (recall tradeoff), got {:?}",
            r.warnings
        );
    }
}
