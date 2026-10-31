// SPDX-License-Identifier: AGPL-3.0-or-later
//! Outlook `.msg` (MAPI / OLE Compound File) text + header extraction.
//!
//! A `.msg` is a Compound File Binary (OLE structured storage): a little filesystem
//! of "storages" (dirs) and "streams" (files). MAPI properties live in streams named
//! `__substg1.0_<ID><TYPE>` (ID = 4 hex property id, TYPE = 4 hex property type), e.g.
//! the subject is `__substg1.0_0037001F` (PR_SUBJECT_W, Unicode) or `_0037001E` (ANSI).
//!
//! This extractor turns a saved Outlook message into the `document` data class for the
//! redaction / matter pipeline: the plain-text body into [`ExtractResult::text`] and the
//! routing headers into [`Metadata::email`] ([`EmailMetadata`]), exactly like the `.eml`
//! extractor — so an uploaded `.msg` flows through the SAME header-composition + scan path.
//!
//! ## Deterministic, LOCAL, no network, no clock (non-negotiable)
//!
//! Parsing is the pure-Rust [`cfb`] crate, used READ-ONLY over an in-memory cursor — we
//! never create/write a CFB, so cfb's only clock-touching code (root-entry timestamps,
//! write path) is never reached. NOTHING resolves a hostname, fetches a remote resource,
//! or calls a model. The same bytes always yield the same [`ExtractResult`].
//!
//! ## SCOPE
//!
//! We read the well-defined VARIABLE-LENGTH string streams (`__substg1.0_*`): subject,
//! plain-text body, and sender (name + address). For RECIPIENTS we walk the per-recipient
//! sub-storages (`__recip_version1.0_#XXXXXXXX`): each recipient's DISPLAY NAME + SMTP/
//! email ADDRESS streams, plus its `PR_RECIPIENT_TYPE` (a fixed `PT_LONG` property in the
//! recipient's `__properties_version1.0` stream) to bucket it precisely into **To / Cc /
//! Bcc**. So recipient ADDRESSES and the exact split ARE extracted (`Display Name <addr>`).
//! A `.msg` with NO recipient sub-storages falls back to the top-level **display** To/Cc/
//! Bcc strings (NAMES only; addresses unavailable, surfaced as a warning). HTML-only /
//! RTF-only bodies and attachments are FLAGGED (leak vectors), never silently dropped. A
//! date is not decoded (the MAPI dates are binary FILETIME; decoding would add a date
//! dependency). Reply-To is not decoded (a MAPI reply-recipient table; out of scope).
//!
//! ## Hostile input is the norm
//!
//! Untrusted `.msg` is assumed adversarial: total size, per-stream size, body size, and
//! recipient/attachment counts are all bounded ([`limits`]); a malformed container is a
//! content-free [`ExtractError::Malformed`]; the whole parse runs under `catch_unwind` so
//! the third-party parser can never panic the caller; nothing recurses or allocates
//! without bound.

use std::io::{Cursor, Read as _};
use std::panic::AssertUnwindSafe;

use crate::{clamp_chars, EmailMetadata, ExtractError, ExtractResult, Metadata};

/// Hard bounds for hostile `.msg` input.
pub(crate) mod limits {
    /// Largest `.msg` (the raw CFB bytes) we will open at all.
    pub const MAX_MSG_BYTES: usize = 64 * 1024 * 1024;
    /// Cap on a single property stream we read (the body can be large; a string header
    /// is tiny). Bounds peak allocation per property regardless of declared size.
    pub const MAX_PROP_BYTES: usize = 16 * 1024 * 1024;
    /// Cap on the assembled body text (chars), so a degenerate stream can't produce
    /// unbounded output.
    pub const MAX_BODY_CHARS: usize = 8 * 1024 * 1024;
    /// Cap on recipients split out of a display string.
    pub const MAX_RECIPIENTS: usize = 1024;
    /// Cap on the number of root entries we will iterate (attachment / recipient count).
    pub const MAX_ROOT_ENTRIES: usize = 100_000;
}

// MAPI property IDs (the 4-hex `<ID>` half of a `__substg1.0_<ID><TYPE>` stream name).
const PR_SUBJECT: u16 = 0x0037;
const PR_BODY: u16 = 0x1000;
const PR_SENDER_NAME: u16 = 0x0C1A;
const PR_SENDER_EMAIL: u16 = 0x0C1F;
const PR_SENDER_SMTP: u16 = 0x5D01;
const PR_DISPLAY_TO: u16 = 0x0E04;
const PR_DISPLAY_CC: u16 = 0x0E03;
const PR_DISPLAY_BCC: u16 = 0x0E02;
// Per-recipient (sub-storage) property IDs.
const PR_DISPLAY_NAME: u16 = 0x3001;
const PR_EMAIL_ADDRESS: u16 = 0x3003; // may be an Exchange "EX" address
const PR_SMTP_ADDRESS: u16 = 0x39FE; // the real SMTP address (preferred)
const PR_RECIPIENT_TYPE: u16 = 0x0C15; // a FIXED PT_LONG property: 1=To, 2=Cc, 3=Bcc

// Property TYPEs (the 4-hex `<TYPE>` half).
const PT_UNICODE: u16 = 0x001F; // UTF-16LE
const PT_STRING8: u16 = 0x001E; // 8-bit (codepage; we best-effort Windows-1252)
const PT_LONG: u16 = 0x0003; // 32-bit signed int (a FIXED property in __properties_version1.0)

// PR_RECIPIENT_TYPE values (MS-OXOMSG).
const MAPI_TO: u32 = 1;
const MAPI_CC: u32 = 2;
const MAPI_BCC: u32 = 3;

/// The `__properties_version1.0` header length for a RECIPIENT (or attachment) object
/// (MS-OXMSG §2.4.1: top-level = 32, embedded = 24, attachment/recipient = 8). After the
/// header the stream is a packed array of 16-byte property entries.
const RECIPIENT_PROPS_HEADER: usize = 8;

type Comp<'a> = cfb::CompoundFile<Cursor<&'a [u8]>>;

/// Public contract: extract a `.msg`'s text + email metadata, hostile-input-bounded and
/// never-panicking (the real work runs under `catch_unwind`).
pub(crate) fn extract(bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
    if bytes.len() > limits::MAX_MSG_BYTES {
        return Err(ExtractError::Malformed(format!(
            "msg exceeds size limit ({} bytes > {} max)",
            bytes.len(),
            limits::MAX_MSG_BYTES
        )));
    }
    // cfb is third-party and could panic on crafted input; contain it. The closure is
    // unwind-safe: it borrows only `bytes` and returns owned data.
    match std::panic::catch_unwind(AssertUnwindSafe(|| extract_inner(bytes))) {
        Ok(r) => r,
        Err(_) => Err(ExtractError::Malformed(
            "msg parsing panicked on malformed input (contained)".to_string(),
        )),
    }
}

fn extract_inner(bytes: &[u8]) -> Result<ExtractResult, ExtractError> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|e| {
        ExtractError::Malformed(format!("not a readable .msg (compound file): {e}"))
    })?;

    let mut warnings: Vec<String> = Vec::new();

    let subject = read_string_prop(&mut comp, PR_SUBJECT);
    let body = read_string_prop(&mut comp, PR_BODY);
    let sender_name = read_string_prop(&mut comp, PR_SENDER_NAME);
    let sender_email = read_string_prop(&mut comp, PR_SENDER_SMTP)
        .or_else(|| read_string_prop(&mut comp, PR_SENDER_EMAIL));
    // Recipients (v2): walk the per-recipient sub-storages for ADDRESSES + the precise
    // To/Cc/Bcc split. Fall back to the top-level display NAME strings only when the
    // message has NO recipient sub-storages.
    let (to, cc, bcc, recip_untyped, recip_from_substorages) = match parse_recipients(&mut comp) {
        Some(rs) => (rs.to, rs.cc, rs.bcc, rs.untyped, true),
        None => (
            split_recipients(read_string_prop(&mut comp, PR_DISPLAY_TO).as_deref()),
            split_recipients(read_string_prop(&mut comp, PR_DISPLAY_CC).as_deref()),
            split_recipients(read_string_prop(&mut comp, PR_DISPLAY_BCC).as_deref()),
            0,
            false,
        ),
    };
    let from = format_sender(sender_name, sender_email);

    // Enumerate the root once for attachment count + HTML/RTF-only body detection
    // (existence checks via entry names — no extra stream reads, no &mut borrow).
    let (attach_count, has_html, has_rtf) = scan_root(&comp);

    // Reject a non-`.msg` CFB (e.g. a mislabeled .xls): if NO message property and NO
    // attachment is present, this is not a recognizable Outlook message — an honest error
    // beats a misleading empty "0 identifiers" success.
    let any_content = subject.is_some()
        || body.is_some()
        || !from.is_empty()
        || !to.is_empty()
        || !cc.is_empty()
        || !bcc.is_empty()
        || attach_count > 0;
    if !any_content {
        return Err(ExtractError::Malformed(
            "not a recognizable Outlook .msg (no message properties found)".to_string(),
        ));
    }

    if !bcc.is_empty() {
        // COUNT only (mirrors the `.eml` extractor's exact wording): the Bcc names are
        // already in `EmailMetadata.bcc`, so the warning must NOT be a second copy of that
        // cleartext.
        warnings.push(format!(
            "Bcc recipients present ({}) — blind-carbon addresses a To/Cc view hides",
            bcc.len()
        ));
    }

    let text = match &body {
        Some(b) => clamp_chars(b, limits::MAX_BODY_CHARS),
        None => {
            if has_html {
                warnings.push(
                    "message body is HTML-only — not extracted (no plain-text body present)"
                        .to_string(),
                );
            } else if has_rtf {
                warnings.push(
                    "message body is RTF-only — not extracted (no plain-text body present)"
                        .to_string(),
                );
            } else {
                warnings.push("no plain-text body found in the message".to_string());
            }
            String::new()
        }
    };

    if attach_count > 0 {
        warnings.push(format!(
            "{attach_count} attachment(s) present — not extracted (the body says nothing \
             about a file riding along)"
        ));
    }

    // v2: addresses + the precise split come from the recipient sub-storages. Only when
    // we FELL BACK to the display strings (no sub-storages) are addresses unavailable —
    // surface that honestly. Also surface any recipient whose type we could not read.
    if !recip_from_substorages && (!to.is_empty() || !cc.is_empty() || !bcc.is_empty()) {
        warnings.push(
            "recipient email addresses (vs display names) and the exact To/Cc/Bcc split are \
             unavailable — this message has no recipient sub-storages, only display names"
                .to_string(),
        );
    }
    if recip_untyped > 0 {
        warnings.push(format!(
            "{recip_untyped} recipient(s) had no/unknown recipient-type — treated as To \
             (the MAPI default)"
        ));
    }

    let metadata = Metadata {
        email: Some(EmailMetadata {
            from,
            to,
            cc,
            bcc,
            reply_to: Vec::new(),
            subject,
            date: None,
            message_id: None,
        }),
        ..Default::default()
    };

    Ok(ExtractResult {
        text,
        metadata,
        warnings,
    })
}

/// Read a MAPI string property by id at the TOP level: prefer the Unicode (`001F`)
/// stream, fall back to the 8-bit (`001E`) stream. `None` if neither exists / is empty.
fn read_string_prop(comp: &mut Comp<'_>, id: u16) -> Option<String> {
    read_string_prop_in(comp, "", id)
}

/// Read a MAPI string property by id INSIDE a storage `prefix` (e.g. a recipient
/// sub-storage `/__recip_version1.0_#00000000`, or `""` for the top level). Unicode
/// first, then 8-bit.
fn read_string_prop_in(comp: &mut Comp<'_>, prefix: &str, id: u16) -> Option<String> {
    read_stream_string(comp, &substg_path(prefix, id, PT_UNICODE), true)
        .or_else(|| read_stream_string(comp, &substg_path(prefix, id, PT_STRING8), false))
}

/// `<prefix>/__substg1.0_<ID><TYPE>` (uppercase hex — the form Outlook writes). `prefix`
/// is `""` for a top-level property, or a storage path (no trailing slash) for a nested one.
fn substg_path(prefix: &str, id: u16, ty: u16) -> String {
    format!("{prefix}/__substg1.0_{id:04X}{ty:04X}")
}

/// The recipients parsed from a `.msg`'s per-recipient sub-storages: the To/Cc/Bcc
/// buckets (each `Display Name <addr>`), plus a count of recipients whose type could not
/// be read (defaulted to To, surfaced as a warning).
struct RecipientSet {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    untyped: usize,
}

/// Walk the per-recipient sub-storages (`__recip_version1.0_#XXXXXXXX`) and bucket each
/// recipient into To/Cc/Bcc by its `PR_RECIPIENT_TYPE`, formatting `Display Name <addr>`
/// (SMTP preferred, then the generic email address). Returns `None` when the message has
/// NO recipient sub-storages (the caller then falls back to the display-name strings).
fn parse_recipients(comp: &mut Comp<'_>) -> Option<RecipientSet> {
    // Collect the recipient storage paths first (an IMMUTABLE root borrow), bounded. The
    // per-recipient stream reads below need `&mut comp`, so enumeration must finish first.
    let mut paths: Vec<String> = Vec::new();
    for entry in comp.read_root_storage().take(limits::MAX_ROOT_ENTRIES) {
        if entry.is_storage()
            && entry
                .name()
                .to_ascii_uppercase()
                .starts_with("__RECIP_VERSION1.0_")
        {
            paths.push(format!("/{}", entry.name()));
            if paths.len() >= limits::MAX_RECIPIENTS {
                break;
            }
        }
    }
    if paths.is_empty() {
        return None;
    }
    let (mut to, mut cc, mut bcc, mut untyped) = (Vec::new(), Vec::new(), Vec::new(), 0usize);
    for prefix in &paths {
        let name = read_string_prop_in(comp, prefix, PR_DISPLAY_NAME);
        let addr = read_string_prop_in(comp, prefix, PR_SMTP_ADDRESS)
            .or_else(|| read_string_prop_in(comp, prefix, PR_EMAIL_ADDRESS));
        let formatted = format_recipient(name, addr);
        if formatted.is_empty() {
            continue; // a recipient with neither a name nor an address — nothing to record
        }
        match read_recipient_type(comp, prefix) {
            Some(MAPI_TO) => to.push(formatted),
            Some(MAPI_CC) => cc.push(formatted),
            Some(MAPI_BCC) => bcc.push(formatted),
            // Missing/unknown type: default to To (the MAPI default) and COUNT it so the
            // uncertainty is surfaced (never silently mis-bucketed).
            _ => {
                untyped += 1;
                to.push(formatted);
            }
        }
    }
    Some(RecipientSet {
        to,
        cc,
        bcc,
        untyped,
    })
}

/// Read a recipient's `PR_RECIPIENT_TYPE` (a fixed `PT_LONG`) from its
/// `__properties_version1.0` stream. `None` if the stream/entry is absent or malformed.
fn read_recipient_type(comp: &mut Comp<'_>, prefix: &str) -> Option<u32> {
    let mut stream = comp
        .open_stream(format!("{prefix}/__properties_version1.0"))
        .ok()?;
    let mut buf = Vec::new();
    (&mut stream)
        .take(limits::MAX_PROP_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    fixed_prop_u32(&buf, RECIPIENT_PROPS_HEADER, PR_RECIPIENT_TYPE, PT_LONG)
}

/// Find a fixed property in a packed `__properties_version1.0` body and return its u32
/// value. After `header` bytes the body is an array of 16-byte entries:
/// `[type:u16][id:u16][flags:u32][value:8]`; a `PT_LONG` value is the first 4 of the 8
/// value bytes. NEVER panics — bounds-checked, and `chunks_exact` drops a trailing
/// partial entry.
fn fixed_prop_u32(buf: &[u8], header: usize, want_id: u16, want_type: u16) -> Option<u32> {
    let body = buf.get(header..)?;
    for e in body.chunks_exact(16) {
        let ty = u16::from_le_bytes([e[0], e[1]]);
        let id = u16::from_le_bytes([e[2], e[3]]);
        if id == want_id && ty == want_type {
            return Some(u32::from_le_bytes([e[8], e[9], e[10], e[11]]));
        }
    }
    None
}

/// Format one recipient as `Display Name <addr>` (both present), or whichever exists, each
/// clamped. Empty when neither is present.
fn format_recipient(name: Option<String>, addr: Option<String>) -> String {
    let name = name.map(|n| clamp_chars(&n, crate::limits::MAX_NAME_CHARS));
    let addr = addr.map(|a| clamp_chars(&a, crate::limits::MAX_NAME_CHARS));
    match (name, addr) {
        (Some(n), Some(a)) => format!("{n} <{a}>"),
        (Some(n), None) => n,
        (None, Some(a)) => a,
        (None, None) => String::new(),
    }
}

/// Read a property stream (bounded) and decode it. `utf16` selects UTF-16LE vs an 8-bit
/// (Windows-1252 best-effort) decode. Trailing NULs are trimmed. Empty → `None`.
fn read_stream_string(comp: &mut Comp<'_>, path: &str, utf16: bool) -> Option<String> {
    let mut stream = comp.open_stream(path).ok()?;
    let mut buf = Vec::new();
    // Bounded read: never trust the declared length; cap peak allocation.
    (&mut stream)
        .take(limits::MAX_PROP_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    let decoded = if utf16 {
        decode_utf16le(&buf)
    } else {
        encoding_rs::WINDOWS_1252.decode(&buf).0.into_owned()
    };
    let trimmed = decoded.trim_matches('\u{0}').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Decode UTF-16LE bytes to a String (lossy on unpaired surrogates; a trailing odd byte
/// is ignored). Pure std — no extra dependency.
fn decode_utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Format the sender as one `EmailMetadata.from` element: `Name <addr>` when both are
/// present, else whichever exists (each clamped). Empty when neither is present.
fn format_sender(name: Option<String>, email: Option<String>) -> Vec<String> {
    let name = name.map(|n| clamp_chars(&n, crate::limits::MAX_NAME_CHARS));
    let email = email.map(|e| clamp_chars(&e, crate::limits::MAX_NAME_CHARS));
    match (name, email) {
        (Some(n), Some(e)) => vec![format!("{n} <{e}>")],
        (Some(n), None) => vec![n],
        (None, Some(e)) => vec![e],
        (None, None) => Vec::new(),
    }
}

/// Split a MAPI display recipient string (semicolon-separated display names) into trimmed,
/// clamped, bounded entries.
fn split_recipients(s: Option<&str>) -> Vec<String> {
    match s {
        None => Vec::new(),
        Some(s) => s
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .take(limits::MAX_RECIPIENTS)
            .map(|p| clamp_chars(p, crate::limits::MAX_NAME_CHARS))
            .collect(),
    }
}

/// One bounded pass over the root entries: attachment storage count + whether an
/// HTML (`1013`) or RTF (`1009`) body stream exists. Entry NAMES only — no stream reads.
fn scan_root(comp: &Comp<'_>) -> (usize, bool, bool) {
    let (mut attach, mut has_html, mut has_rtf) = (0usize, false, false);
    for entry in comp.read_root_storage().take(limits::MAX_ROOT_ENTRIES) {
        let up = entry.name().to_ascii_uppercase();
        if entry.is_storage() && up.starts_with("__ATTACH_VERSION1.0_") {
            attach += 1;
        } else if entry.is_stream() {
            if up.starts_with("__SUBSTG1.0_1013") {
                has_html = true;
            } else if up.starts_with("__SUBSTG1.0_1009") {
                has_rtf = true;
            }
        }
    }
    (attach, has_html, has_rtf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal `.msg` (CFB) carrying the given properties, via the `cfb` writer.
    /// `props` is `(id, type, bytes)`; we write each as `/__substg1.0_<ID><TYPE>`.
    fn build_msg(props: &[(u16, u16, Vec<u8>)], storages: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut comp = cfb::CompoundFile::create(cursor).expect("create cfb");
            for s in storages {
                comp.create_storage(format!("/{s}"))
                    .expect("create storage");
            }
            for (id, ty, data) in props {
                let path = format!("/__substg1.0_{id:04X}{ty:04X}");
                use std::io::Write as _;
                let mut st = comp.create_stream(&path).expect("create stream");
                st.write_all(data).expect("write stream");
            }
            comp.flush().expect("flush cfb");
        }
        buf
    }

    fn u16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn extracts_subject_body_sender_and_recipients() {
        let msg = build_msg(
            &[
                (PR_SUBJECT, PT_UNICODE, u16le("Payment due")),
                (
                    PR_BODY,
                    PT_UNICODE,
                    u16le("Wire card 4111 1111 1111 1111 today."),
                ),
                (PR_SENDER_NAME, PT_UNICODE, u16le("Alice")),
                (PR_SENDER_SMTP, PT_UNICODE, u16le("alice@firm.example")),
                (PR_DISPLAY_TO, PT_UNICODE, u16le("Bob Jones; Carol Smith")),
                (PR_DISPLAY_BCC, PT_UNICODE, u16le("Secret Watcher")),
            ],
            &[],
        );
        let r = extract(&msg).expect("extract msg");
        assert!(
            r.text.contains("4111 1111 1111 1111"),
            "body extracted: {:?}",
            r.text
        );
        let em = r.metadata.email.expect("email metadata");
        assert_eq!(em.subject.as_deref(), Some("Payment due"));
        assert_eq!(em.from, vec!["Alice <alice@firm.example>".to_string()]);
        assert_eq!(
            em.to,
            vec!["Bob Jones".to_string(), "Carol Smith".to_string()]
        );
        assert_eq!(em.bcc, vec!["Secret Watcher".to_string()]);
        // Bcc presence is a surfaced leak warning.
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("Bcc recipients present")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn ansi_string8_fallback_is_decoded() {
        // No Unicode subject; an 8-bit (001E) one must still be read.
        let msg = build_msg(
            &[
                (PR_SUBJECT, PT_STRING8, b"Re: contract".to_vec()),
                (PR_BODY, PT_UNICODE, u16le("see attached")),
            ],
            &[],
        );
        let r = extract(&msg).expect("extract");
        assert_eq!(
            r.metadata.email.unwrap().subject.as_deref(),
            Some("Re: contract")
        );
    }

    #[test]
    fn attachments_and_html_only_body_are_flagged() {
        let msg = build_msg(
            &[
                (PR_SUBJECT, PT_UNICODE, u16le("Has attachment")),
                // PR_HTML 0x1013 / PT_BINARY 0x0102 present, but NO plain-text body.
                (0x1013, 0x0102, b"<html>hi</html>".to_vec()),
            ],
            &["__attach_version1.0_#00000000"],
        );
        let r = extract(&msg).expect("extract");
        assert!(r.text.is_empty(), "no plain-text body");
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("attachment(s) present")),
            "{:?}",
            r.warnings
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("HTML-only")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn non_msg_compound_file_is_malformed_not_empty() {
        // A CFB with no message properties (a mislabeled .xls-like file) is an honest
        // error, not a misleading empty success.
        let msg = build_msg(
            &[(0x9999, PT_UNICODE, u16le("irrelevant"))],
            &["SomeOtherStorage"],
        );
        assert!(matches!(extract(&msg), Err(ExtractError::Malformed(_))));
    }

    #[test]
    fn garbage_bytes_are_malformed_not_panic() {
        assert!(matches!(
            extract(b"not a compound file at all"),
            Err(ExtractError::Malformed(_))
        ));
        assert!(matches!(extract(&[]), Err(ExtractError::Malformed(_))));
    }

    // ---- v2: recipient sub-storage walk (addresses + precise To/Cc/Bcc) ----------

    /// A recipient `__properties_version1.0` body: the 8-byte recipient header + one
    /// 16-byte `PT_LONG` entry carrying `PR_RECIPIENT_TYPE`.
    fn props_with_recipient_type(t: u32) -> Vec<u8> {
        let mut v = vec![0u8; RECIPIENT_PROPS_HEADER];
        v.extend_from_slice(&PT_LONG.to_le_bytes()); // [type:u16] = 0x0003
        v.extend_from_slice(&PR_RECIPIENT_TYPE.to_le_bytes()); // [id:u16] = 0x0C15
        v.extend_from_slice(&[0u8; 4]); // [flags:u32]
        v.extend_from_slice(&t.to_le_bytes()); // value (first 4 of the 8 value bytes)
        v.extend_from_slice(&[0u8; 4]); // value pad
        v
    }

    /// Build a `.msg` with top-level `props` AND per-recipient sub-storages. Each recipient
    /// is `(display_name, smtp_addr, recipient_type)`: we write its DISPLAY_NAME + SMTP
    /// streams and a `__properties_version1.0` carrying the type.
    fn build_msg_with_recipients(
        props: &[(u16, u16, Vec<u8>)],
        recips: &[(&str, &str, u32)],
    ) -> Vec<u8> {
        use std::io::Write as _;
        let mut buf = Vec::new();
        {
            let mut comp = cfb::CompoundFile::create(Cursor::new(&mut buf)).expect("create cfb");
            for (id, ty, data) in props {
                let path = format!("/__substg1.0_{id:04X}{ty:04X}");
                comp.create_stream(&path).unwrap().write_all(data).unwrap();
            }
            for (i, (name, addr, rtype)) in recips.iter().enumerate() {
                let stg = format!("/__recip_version1.0_#{i:08X}");
                comp.create_storage(&stg).unwrap();
                comp.create_stream(format!("{stg}/__substg1.0_3001001F"))
                    .unwrap()
                    .write_all(&u16le(name))
                    .unwrap();
                comp.create_stream(format!("{stg}/__substg1.0_39FE001F"))
                    .unwrap()
                    .write_all(&u16le(addr))
                    .unwrap();
                comp.create_stream(format!("{stg}/__properties_version1.0"))
                    .unwrap()
                    .write_all(&props_with_recipient_type(*rtype))
                    .unwrap();
            }
            comp.flush().expect("flush");
        }
        buf
    }

    #[test]
    fn v2_recipient_substorages_give_addresses_and_precise_split() {
        let msg = build_msg_with_recipients(
            &[
                (PR_SUBJECT, PT_UNICODE, u16le("Deal")),
                (PR_BODY, PT_UNICODE, u16le("see below")),
                (PR_SENDER_NAME, PT_UNICODE, u16le("Alice")),
                (PR_SENDER_SMTP, PT_UNICODE, u16le("alice@firm.example")),
                // A stale top-level display string the sub-storages SUPERSEDE.
                (PR_DISPLAY_TO, PT_UNICODE, u16le("Stale Name")),
            ],
            &[
                ("Bob Jones", "bob@acme.example", MAPI_TO),
                ("Carol", "carol@acme.example", MAPI_CC),
                ("Watcher", "watch@x.example", MAPI_BCC),
            ],
        );
        let r = extract(&msg).expect("extract");
        let em = r.metadata.email.unwrap();
        // Addresses + the precise split from the sub-storages (NOT the stale display string).
        assert_eq!(em.to, vec!["Bob Jones <bob@acme.example>"]);
        assert_eq!(em.cc, vec!["Carol <carol@acme.example>"]);
        assert_eq!(em.bcc, vec!["Watcher <watch@x.example>"]);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("Bcc recipients present")),
            "Bcc surfaced: {:?}",
            r.warnings
        );
        // The fallback "addresses unavailable" scope warning is GONE (we extracted them).
        assert!(
            !r.warnings.iter().any(|w| w.contains("unavailable")),
            "no scope warning when addresses ARE extracted: {:?}",
            r.warnings
        );
    }

    #[test]
    fn v2_recipient_without_smtp_falls_back_to_email_address() {
        use std::io::Write as _;
        let mut buf = Vec::new();
        {
            let mut comp = cfb::CompoundFile::create(Cursor::new(&mut buf)).unwrap();
            comp.create_stream("/__substg1.0_0037001F")
                .unwrap()
                .write_all(&u16le("S"))
                .unwrap();
            comp.create_storage("/__recip_version1.0_#00000000")
                .unwrap();
            comp.create_stream("/__recip_version1.0_#00000000/__substg1.0_3001001F")
                .unwrap()
                .write_all(&u16le("Dave"))
                .unwrap();
            // No PR_SMTP_ADDRESS (0x39FE); only PR_EMAIL_ADDRESS (0x3003), an EX address.
            comp.create_stream("/__recip_version1.0_#00000000/__substg1.0_3003001F")
                .unwrap()
                .write_all(&u16le("/O=EX/CN=dave"))
                .unwrap();
            comp.create_stream("/__recip_version1.0_#00000000/__properties_version1.0")
                .unwrap()
                .write_all(&props_with_recipient_type(MAPI_TO))
                .unwrap();
            comp.flush().unwrap();
        }
        let r = extract(&buf).expect("extract");
        assert_eq!(r.metadata.email.unwrap().to, vec!["Dave </O=EX/CN=dave>"]);
    }

    #[test]
    fn v2_recipient_missing_type_defaults_to_to_with_warning() {
        // A recipient sub-storage with NO __properties_version1.0 → type unknown → To + warn.
        use std::io::Write as _;
        let mut buf = Vec::new();
        {
            let mut comp = cfb::CompoundFile::create(Cursor::new(&mut buf)).unwrap();
            comp.create_stream("/__substg1.0_0037001F")
                .unwrap()
                .write_all(&u16le("S"))
                .unwrap();
            comp.create_storage("/__recip_version1.0_#00000000")
                .unwrap();
            comp.create_stream("/__recip_version1.0_#00000000/__substg1.0_3001001F")
                .unwrap()
                .write_all(&u16le("Eve"))
                .unwrap();
            comp.create_stream("/__recip_version1.0_#00000000/__substg1.0_39FE001F")
                .unwrap()
                .write_all(&u16le("eve@x.example"))
                .unwrap();
            // (no __properties_version1.0)
            comp.flush().unwrap();
        }
        let r = extract(&buf).expect("extract");
        let em = r.metadata.email.unwrap();
        assert_eq!(em.to, vec!["Eve <eve@x.example>"]);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("no/unknown recipient-type")),
            "untyped recipient surfaced: {:?}",
            r.warnings
        );
    }

    #[test]
    fn v2_no_substorages_falls_back_to_display_names_with_scope_warning() {
        // The display-string fallback (a message with no recipient sub-storages): NAMES
        // only, and the "addresses unavailable" scope warning fires.
        let msg = build_msg(
            &[
                (PR_SUBJECT, PT_UNICODE, u16le("S")),
                (PR_DISPLAY_TO, PT_UNICODE, u16le("Bob; Carol")),
            ],
            &[],
        );
        let r = extract(&msg).expect("extract");
        assert_eq!(
            r.metadata.email.unwrap().to,
            vec!["Bob".to_string(), "Carol".to_string()]
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("unavailable")),
            "fallback path surfaces the scope warning: {:?}",
            r.warnings
        );
    }

    #[test]
    fn fixed_prop_u32_is_bounds_safe_on_truncated_input() {
        // Shorter than the header, empty, and a trailing partial entry — all None, never
        // a panic. (The whole extract also runs under catch_unwind, but the parser itself
        // must be bounds-safe.)
        assert_eq!(
            fixed_prop_u32(&[], RECIPIENT_PROPS_HEADER, PR_RECIPIENT_TYPE, PT_LONG),
            None
        );
        assert_eq!(
            fixed_prop_u32(
                &[0u8; 4],
                RECIPIENT_PROPS_HEADER,
                PR_RECIPIENT_TYPE,
                PT_LONG
            ),
            None
        );
        // Header + a 7-byte partial entry (chunks_exact drops it).
        assert_eq!(
            fixed_prop_u32(
                &[0u8; RECIPIENT_PROPS_HEADER + 7],
                RECIPIENT_PROPS_HEADER,
                PR_RECIPIENT_TYPE,
                PT_LONG
            ),
            None
        );
        // A well-formed entry round-trips.
        let v = props_with_recipient_type(MAPI_BCC);
        assert_eq!(
            fixed_prop_u32(&v, RECIPIENT_PROPS_HEADER, PR_RECIPIENT_TYPE, PT_LONG),
            Some(MAPI_BCC)
        );
    }
}
