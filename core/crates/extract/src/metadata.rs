// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `firmos.meta/1` PRODUCER — serialize [`EmailMetadata`] to the canonical
//! stored form the trusted core reads back.
//!
//! ## What this is (and the authoritative reverse)
//!
//! The trusted core (`runtime`) has a READER —
//! `runtime::metadata::parse_email_headers(&str) -> CoreResult<EmailHeaders>` — that
//! DESERIALIZES the `firmos.meta/1` canonical form into typed, already-parsed email
//! headers (the `matter.read:metadata` seam; see
//! `to-read/runtime.METADATA-SEAM-PROPOSAL.md` §6–§9). That parser is the
//! **AUTHORITATIVE reverse** of this module: every string [`to_canonical`] emits
//! MUST read back losslessly through `parse_email_headers`.
//!
//! The `firmos.meta/1` wire format is the SHARED CONTRACT between the two crates.
//! This serializer lives in `extract` (NOT `runtime`) because of the crate
//! DEPENDENCY DIRECTION (the load-bearing decision in `to-read/runtime.METADATA-SEAM-PROPOSAL.md` §6):
//! `runtime` must NOT depend on `extract` and `extract` must NOT depend on
//! `runtime` (they are independent). `extract` already owns [`EmailMetadata`] (the
//! source type the `.eml` extractor populates), so it is the natural home for the
//! producer. We therefore mirror the wire format BY SPEC — reading `metadata.rs` —
//! never by importing `runtime`'s code.
//!
//! ## The producer's obligations (mirroring `runtime`'s `metadata.rs`)
//!
//! - **Line 1 is the version tag** `firmos.meta/1`; the reader REFUSES anything else
//!   fail-closed, so we always emit it first, exactly.
//! - **Each value is one line** `TAG<SP>percent-encoded-value`. The reader splits on
//!   the FIRST ASCII space (TAG before, value after), so a value may itself contain
//!   spaces — we do NOT encode spaces.
//! - **Percent-encoding** escapes `%`, CR (`\r`), LF (`\n`), and every other ASCII
//!   control char (see [`percent_encode`]) so each value is exactly one line and
//!   round-trips losslessly; all other (incl. multi-byte UTF-8) content passes
//!   through verbatim.
//! - **Multi-value fields** (`from`/`to`/`cc`/`bcc`/`reply-to`) emit ONE line per
//!   element, repeating the TAG, in vector order.
//! - **Single-value fields** (`subject`/`date`/`message-id`) emit at most one line —
//!   present (`Some`) or omitted (`None`).
//! - **A missing field emits NO line** — the reader treats an absent line as
//!   `None`/empty and NEVER fabricates, so the no-fabrication rule carries through.
//! - **Bcc is emitted explicitly when present** — a deliberate LEAK SURFACE the
//!   design SURFACES, never hides.
//!
//! Everything here is pure, deterministic, std-only string processing that NEVER
//! panics on any input (it operates at the BYTE level for the escaped chars and so
//! can never slice a multi-byte UTF-8 codepoint — the Critical-bug class the `.eml`
//! extractor already hit).

use crate::EmailMetadata;

/// The version tag that is line 1 of every `firmos.meta/1` document. The reader
/// (`runtime::metadata`) REFUSES any other first line fail-closed, so this must be
/// byte-identical to the reader's `VERSION_TAG`.
const VERSION_TAG: &str = "firmos.meta/1";

/// Uppercase hex digit table for `%XX` encoding.
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Percent-encode a single canonical VALUE — the exact inverse of the reader's
/// `percent_decode` (`runtime/src/metadata.rs`).
///
/// ## Exactly what is escaped, and why (mirroring the reader)
///
/// The reader decodes `%XX` (two ASCII hex digits) back to the byte `0xXX` and
/// takes every other byte verbatim, then interprets the result as UTF-8. So this
/// producer must escape exactly the bytes that would otherwise corrupt the wire
/// form, and may pass everything else through:
///
/// - **`%` (0x25)** — MUST be escaped: a literal `%` in the output would be read as
///   the start of a `%XX` escape by the decoder. (Reader: the `b'%'` branch.)
/// - **CR `\r` (0x0D) and LF `\n` (0x0A)** — MUST be escaped: the reader splits the
///   document with `str::lines()`, which breaks on `\n` and strips a trailing `\r`.
///   An un-escaped newline/CR in a value would split it across lines (data loss) or
///   silently drop the `\r`. (Spec: `to-read/runtime.METADATA-SEAM-PROPOSAL.md` §6 + `metadata.rs`
///   line 29 — "Percent-encoding escapes `%`, CR/LF, and ASCII control chars".)
/// - **All other ASCII control chars (0x00–0x1F and 0x7F DEL)** — escaped per the
///   same spec line. `\r`/`\n` are a subset; we escape the whole control range so a
///   stray control byte never lands in the single-line wire form. The leading-space
///   separator is NOT a control char and a space INSIDE a value is fine (the reader
///   keeps everything after the first space), so SPACE (0x20) is NOT escaped.
///
/// Every OTHER byte — printable ASCII (including `:` `<` `>` `@` etc.) and every byte
/// of a multi-byte UTF-8 character — passes through VERBATIM. The reader accepts a
/// non-ASCII character either verbatim OR as percent-escaped UTF-8 bytes; we choose
/// verbatim for the human-readable, minimal form (e.g. an em-dash `—` stays `—`).
///
/// ## Never-panic / never mid-codepoint
///
/// We iterate the input's BYTES and build a byte buffer. The bytes we escape (`%`,
/// control chars) are all ASCII (< 0x80), so they can NEVER be a continuation or
/// lead byte of a multi-byte UTF-8 sequence (those are all >= 0x80). Every other
/// byte — including every byte of a multi-byte char — is copied VERBATIM into the
/// buffer, so the original UTF-8 is reproduced exactly. The buffer is therefore
/// always valid UTF-8 (escaped bytes become ASCII `%XX`, all else is the input's own
/// bytes), so the final `String::from_utf8` cannot fail. This byte-level discipline
/// is what avoids the `&s[..n]`-mid-codepoint Critical bug; it never panics.
pub fn percent_encode(value: &str) -> String {
    // Worst case (every byte escaped) is 3x; a typical value escapes nothing.
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    for &b in value.as_bytes() {
        // INVARIANT — DO NOT NARROW THIS SET (adversarial review F-3). The reader
        // structurally requires only `{ %, CR, LF }` escaped (it splits on `\n`,
        // strips a trailing `\r`, and reads `%` as the `%XX` escape introducer); we
        // escape the WHOLE ASCII-control range as a SUPERSET so a stray control byte
        // can never reach the single-line wire form. A future "simplification" that
        // dropped below `{ %, \r, \n }` would reintroduce a split-/merged-value bug.
        if b == b'%' || b.is_ascii_control() {
            // Uppercase hex, two digits, matching the reader's case-insensitive
            // `%XX` decode (it accepts either case; we emit a canonical upper form).
            out.push(b'%');
            out.push(HEX_UPPER[(b >> 4) as usize]);
            out.push(HEX_UPPER[(b & 0x0F) as usize]);
        } else {
            // Verbatim byte copy of the ORIGINAL UTF-8 byte (printable ASCII or a
            // lead/continuation byte of a multi-byte char) — never reinterpreted.
            out.push(b);
        }
    }
    // INVARIANT: `out` is valid UTF-8 — escaped bytes are ASCII `%XX`, every other
    // byte is copied verbatim from the input's own valid UTF-8 — so this never errs.
    // We still handle the impossible case fail-safe rather than `unwrap()`.
    String::from_utf8(out).unwrap_or_default()
}

/// Serialize an [`EmailMetadata`] to a full `firmos.meta/1` document.
///
/// The output is the version line followed by one line per PRESENT value, in a
/// stable, deterministic order (byte-identical across runs for the same input):
///
/// 1. `from` (multi-value, vector order)
/// 2. `to` (multi-value)
/// 3. `cc` (multi-value)
/// 4. `bcc` (multi-value — emitted EXPLICITLY when present; a leak surface)
/// 5. `reply-to` (multi-value)
/// 6. `subject` (single-value; one line iff `Some`)
/// 7. `date` (single-value)
/// 8. `message-id` (single-value)
///
/// An empty vector emits NO lines for that field; a `None` single-value field emits
/// no line. Each value is [`percent_encode`]d. The trailing line ends with a `\n`
/// (so an empty `EmailMetadata` yields exactly `"firmos.meta/1\n"`), which the
/// reader's `str::lines()` tolerates (a trailing newline produces no extra line).
///
/// This is the documented INVERSE of `runtime::metadata::parse_email_headers`,
/// which is the AUTHORITATIVE reverse; the `firmos.meta/1` wire format is the shared
/// contract. This lives in `extract` (not `runtime`) due to the crate dependency
/// direction — see the module docs.
///
/// ## Size contract — the reader's 256 KiB cap and a 3× worst case (review F-1/F-2)
///
/// The shipped reader (`runtime::metadata::parse_email_headers`) REFUSES a canonical
/// form over `MAX_CANONICAL_BYTES` (256 KiB) fail-closed, and `Core::matter_read_metadata`
/// PROPAGATES that `Err` — so an over-cap document makes the WHOLE message's metadata
/// unreadable, not just the offending field. Percent-encoding expands an all-escapable
/// value up to **3×** (each byte → `%XX`), so a control-stuffed subject (~85 KiB) or a
/// very large recipient list can cross the cap from a source much smaller than 256 KiB.
/// This producer does NOT clamp — it is a pure, lossless serializer. Graceful degradation
/// (e.g. truncating an enormous recipient list with a SURFACED warning, rather than
/// emitting an all-or-nothing-unreadable doc) belongs to the INGESTION JOB that calls this
/// — owed when that job lands, NOT built speculatively here. Realistic email headers are
/// nowhere near the cap.
pub fn to_canonical(meta: &EmailMetadata) -> String {
    let mut out = String::new();
    out.push_str(VERSION_TAG);
    out.push('\n');

    // Multi-value fields: one line per element, in vector order, TAG repeated.
    for v in &meta.from {
        push_line(&mut out, "from", v);
    }
    for v in &meta.to {
        push_line(&mut out, "to", v);
    }
    for v in &meta.cc {
        push_line(&mut out, "cc", v);
    }
    // Bcc is emitted EXPLICITLY when present — the deliberate leak surface.
    for v in &meta.bcc {
        push_line(&mut out, "bcc", v);
    }
    for v in &meta.reply_to {
        push_line(&mut out, "reply-to", v);
    }

    // Single-value fields: one line iff `Some`; omitted (no line) when `None`.
    if let Some(v) = &meta.subject {
        push_line(&mut out, "subject", v);
    }
    if let Some(v) = &meta.date {
        push_line(&mut out, "date", v);
    }
    if let Some(v) = &meta.message_id {
        push_line(&mut out, "message-id", v);
    }

    out
}

/// Append one `TAG<SP>percent-encoded-value\n` line to `out`. The value is encoded
/// via [`percent_encode`]; the TAG is a static literal, never user-derived.
fn push_line(out: &mut String, tag: &str, value: &str) {
    out.push_str(tag);
    out.push(' ');
    out.push_str(&percent_encode(value));
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // A LOCAL, faithful inverse of the wire format (a copy of the reader's
    // decode logic) so we can assert encode/decode symmetry WITHOUT importing
    // `runtime` (extract must not depend on runtime). This mirrors
    // `runtime/src/metadata.rs`'s `percent_decode` + `parse_email_headers`.
    // -----------------------------------------------------------------------

    /// Mirror of `runtime`'s `EmailHeaders` shape, for round-trip assertions.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct DecodedHeaders {
        from: Vec<String>,
        to: Vec<String>,
        cc: Vec<String>,
        bcc: Vec<String>,
        reply_to: Vec<String>,
        subject: Option<String>,
        date: Option<String>,
        message_id: Option<String>,
    }

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    /// Faithful copy of the reader's `percent_decode`: `%XX` -> byte, else verbatim,
    /// then UTF-8; a malformed escape -> `None`.
    fn percent_decode(value: &str) -> Option<String> {
        let bytes = value.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%' {
                let hi = hex_val(*bytes.get(i + 1)?)?;
                let lo = hex_val(*bytes.get(i + 2)?)?;
                out.push((hi << 4) | lo);
                i += 3;
            } else {
                out.push(b);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }

    /// Faithful copy of the reader's `parse_email_headers` (minus the size cap /
    /// `CoreResult` wrapping, which are irrelevant to round-trip symmetry). Returns
    /// `None` on a missing/unknown version line; skips malformed lines lossily.
    fn decode(canonical: &str) -> Option<DecodedHeaders> {
        let mut lines = canonical.lines();
        match lines.next() {
            Some(v) if v == VERSION_TAG => {}
            _ => return None,
        }
        let mut h = DecodedHeaders::default();
        for line in lines {
            let Some(space) = line.find(' ') else {
                continue;
            };
            let tag = &line[..space];
            let Some(value) = percent_decode(&line[space + 1..]) else {
                continue;
            };
            match tag {
                "from" => h.from.push(value),
                "to" => h.to.push(value),
                "cc" => h.cc.push(value),
                "bcc" => h.bcc.push(value),
                "reply-to" => h.reply_to.push(value),
                "subject" => h.subject = Some(value),
                "date" => h.date = Some(value),
                "message-id" => h.message_id = Some(value),
                _ => {}
            }
        }
        Some(h)
    }

    /// Project an `EmailMetadata` (the source type) onto the decoder's header shape,
    /// so a round-trip can be asserted field-for-field.
    fn project(m: &EmailMetadata) -> DecodedHeaders {
        DecodedHeaders {
            from: m.from.clone(),
            to: m.to.clone(),
            cc: m.cc.clone(),
            bcc: m.bcc.clone(),
            reply_to: m.reply_to.clone(),
            subject: m.subject.clone(),
            date: m.date.clone(),
            message_id: m.message_id.clone(),
        }
    }

    // --- percent_encode: exact-char escaping --------------------------------

    #[test]
    fn percent_encode_passes_plain_text_through() {
        // Printable ASCII (incl. : < > @ . space) passes through verbatim — the
        // reader keeps everything after the first space, so a space in a value is
        // fine and is NOT escaped.
        assert_eq!(
            percent_encode("Jane Roe <jane.roe@acme.example>"),
            "Jane Roe <jane.roe@acme.example>"
        );
    }

    #[test]
    fn percent_encode_escapes_percent() {
        // `%` MUST be escaped (else it reads as an escape introducer). %25 == '%'.
        assert_eq!(percent_encode("100%"), "100%25");
        assert_eq!(percent_encode("%%%"), "%25%25%25");
    }

    #[test]
    fn percent_encode_escapes_cr_lf_and_controls() {
        // CR / LF must be escaped (the reader splits on lines). 0x0D == %0D, 0x0A ==
        // %0A, TAB 0x09 == %09, NUL 0x00 == %00, DEL 0x7F == %7F.
        assert_eq!(percent_encode("a\rb"), "a%0Db");
        assert_eq!(percent_encode("a\nb"), "a%0Ab");
        assert_eq!(percent_encode("a\r\nb"), "a%0D%0Ab");
        assert_eq!(percent_encode("a\tb"), "a%09b");
        assert_eq!(percent_encode("a\u{0}b"), "a%00b");
        assert_eq!(percent_encode("a\u{7f}b"), "a%7Fb");
    }

    #[test]
    fn percent_encode_does_not_escape_colon_or_space() {
        // `:` is printable and is NOT special on the wire; a space inside a value is
        // preserved (only the FIRST space is the TAG separator).
        assert_eq!(percent_encode("Re: hello"), "Re: hello");
    }

    #[test]
    fn percent_encode_passes_multibyte_utf8_verbatim() {
        // An em-dash, CJK, and an emoji all pass through as their raw UTF-8 bytes —
        // NEVER sliced mid-codepoint, NEVER percent-escaped by us.
        assert_eq!(percent_encode("a—b"), "a—b");
        assert_eq!(percent_encode("条件"), "条件");
        assert_eq!(percent_encode("ok 😀 done"), "ok 😀 done");
        // A multibyte char ADJACENT to an escaped char: the control byte is escaped,
        // the multibyte char is intact.
        assert_eq!(percent_encode("—\n—"), "—%0A—");
        assert_eq!(percent_encode("😀\t😀"), "😀%09😀");
    }

    #[test]
    fn percent_encode_roundtrips_through_the_reader_decode() {
        // Every escaped value decodes back to the original via the reader's logic.
        for original in [
            "100%",
            "Re: Project Condor — urgent",
            "line1\r\nline2",
            "tab\there",
            "nul\u{0}del\u{7f}",
            "条件\n— mixed 😀 %",
            "",
        ] {
            let encoded = percent_encode(original);
            assert_eq!(
                percent_decode(&encoded).as_deref(),
                Some(original),
                "round-trip failed for {original:?} (encoded {encoded:?})"
            );
        }
    }

    // --- to_canonical: exact-string output ----------------------------------

    #[test]
    fn to_canonical_empty_is_just_the_version_line() {
        let m = EmailMetadata::default();
        assert_eq!(to_canonical(&m), "firmos.meta/1\n");
    }

    #[test]
    fn to_canonical_full_message_exact_output() {
        let m = EmailMetadata {
            from: vec!["Jane Roe <jane.roe@acme.example>".to_string()],
            to: vec!["a@x.example".to_string(), "b@y.example".to_string()],
            cc: vec!["c@z.example".to_string()],
            bcc: vec!["hidden@watcher.example".to_string()],
            reply_to: vec!["reply@acme.example".to_string()],
            subject: Some("Re: Project Condor — urgent".to_string()),
            date: Some("2026-06-19T09:30:00Z".to_string()),
            message_id: Some("<abc123@acme.example>".to_string()),
        };
        let expected = "firmos.meta/1\n\
            from Jane Roe <jane.roe@acme.example>\n\
            to a@x.example\n\
            to b@y.example\n\
            cc c@z.example\n\
            bcc hidden@watcher.example\n\
            reply-to reply@acme.example\n\
            subject Re: Project Condor — urgent\n\
            date 2026-06-19T09:30:00Z\n\
            message-id <abc123@acme.example>\n";
        assert_eq!(to_canonical(&m), expected);
    }

    #[test]
    fn to_canonical_bcc_present_is_emitted_explicitly() {
        // Bcc is the deliberate leak surface: when present it MUST appear.
        let m = EmailMetadata {
            bcc: vec!["secret@watcher.example".to_string()],
            ..EmailMetadata::default()
        };
        assert_eq!(
            to_canonical(&m),
            "firmos.meta/1\nbcc secret@watcher.example\n"
        );
    }

    #[test]
    fn to_canonical_multivalue_to_and_cc_one_line_each_in_order() {
        let m = EmailMetadata {
            to: vec![
                "first@x.example".to_string(),
                "second@x.example".to_string(),
                "third@x.example".to_string(),
            ],
            cc: vec!["cc1@y.example".to_string(), "cc2@y.example".to_string()],
            ..EmailMetadata::default()
        };
        assert_eq!(
            to_canonical(&m),
            "firmos.meta/1\n\
             to first@x.example\n\
             to second@x.example\n\
             to third@x.example\n\
             cc cc1@y.example\n\
             cc cc2@y.example\n"
        );
    }

    #[test]
    fn to_canonical_unicode_subject_exact_output() {
        // CJK + emoji in the subject pass through verbatim (no escaping).
        let m = EmailMetadata {
            subject: Some("会議の件 😀 urgent".to_string()),
            ..EmailMetadata::default()
        };
        assert_eq!(
            to_canonical(&m),
            "firmos.meta/1\nsubject 会議の件 😀 urgent\n"
        );
    }

    #[test]
    fn to_canonical_subject_with_special_chars_is_escaped() {
        // A subject containing % : \r \n and an ASCII control char: % and the
        // control chars are escaped; `:` and spaces pass through.
        let m = EmailMetadata {
            subject: Some("Re: 100% off\r\ndeal\u{7}now".to_string()),
            ..EmailMetadata::default()
        };
        // %25 == '%', %0D == CR, %0A == LF, %07 == BEL.
        assert_eq!(
            to_canonical(&m),
            "firmos.meta/1\nsubject Re: 100%25 off%0D%0Adeal%07now\n"
        );
        // And it round-trips back to the original subject through the reader logic.
        let decoded = decode(&to_canonical(&m)).unwrap();
        assert_eq!(
            decoded.subject.as_deref(),
            Some("Re: 100% off\r\ndeal\u{7}now")
        );
    }

    #[test]
    fn to_canonical_all_none_optionals_omit_those_lines() {
        // subject/date/message-id all None -> no lines for them.
        let m = EmailMetadata {
            from: vec!["a@x.example".to_string()],
            ..EmailMetadata::default()
        };
        let out = to_canonical(&m);
        assert_eq!(out, "firmos.meta/1\nfrom a@x.example\n");
        assert!(!out.contains("subject"));
        assert!(!out.contains("date"));
        assert!(!out.contains("message-id"));
    }

    #[test]
    fn to_canonical_empty_vectors_emit_no_lines() {
        // Empty multi-value vectors -> no lines for those fields.
        let m = EmailMetadata {
            subject: Some("only a subject".to_string()),
            ..EmailMetadata::default()
        };
        let out = to_canonical(&m);
        assert_eq!(out, "firmos.meta/1\nsubject only a subject\n");
        assert!(!out.contains("from"));
        assert!(!out.contains("\nto "));
        assert!(!out.contains("cc"));
        assert!(!out.contains("bcc"));
        assert!(!out.contains("reply-to"));
    }

    // --- round-trip symmetry over a battery of inputs -----------------------

    #[test]
    fn roundtrip_decode_of_encode_is_identity() {
        let cases = vec![
            EmailMetadata::default(),
            EmailMetadata {
                from: vec!["Jane Roe <jane.roe@acme.example>".to_string()],
                to: vec!["a@x.example".to_string(), "b@y.example".to_string()],
                cc: vec!["c@z.example".to_string()],
                bcc: vec!["hidden@watcher.example".to_string()],
                reply_to: vec!["reply@acme.example".to_string()],
                subject: Some("Re: Project Condor — urgent".to_string()),
                date: Some("2026-06-19T09:30:00Z".to_string()),
                message_id: Some("<abc123@acme.example>".to_string()),
            },
            // Values laden with escapables and unicode.
            EmailMetadata {
                from: vec!["Z 100% <z@x.example>".to_string()],
                to: vec!["line\r\nbreak@x.example".to_string()],
                subject: Some("会議 😀\t% : <weird>".to_string()),
                message_id: Some("<id with spaces and %25>".to_string()),
                ..EmailMetadata::default()
            },
            // Deliberately-empty string values for multi- and single-value fields:
            // the reader preserves an empty multi-value (a line was emitted) and an
            // empty single-value stays Some("").
            EmailMetadata {
                to: vec!["".to_string()],
                subject: Some("".to_string()),
                ..EmailMetadata::default()
            },
        ];
        for m in cases {
            let canonical = to_canonical(&m);
            let decoded = decode(&canonical).expect("version line present");
            assert_eq!(decoded, project(&m), "round-trip mismatch for {m:?}");
        }
    }

    // --- never-panic on adversarial input -----------------------------------

    #[test]
    fn never_panics_on_adversarial_values() {
        let adversarial = vec![
            // Pure control chars.
            "\u{0}\u{1}\u{2}\u{3}\r\n\t\u{7f}".to_string(),
            // Very long string.
            "x".repeat(1_000_000),
            // All percent signs.
            "%".repeat(10_000),
            // `%` not followed by hex (we emit `%25` for each, so this is fine, but
            // exercise it anyway).
            "%zz %4 % %g".to_string(),
            // Multibyte chars adjacent to escaped chars, repeated.
            "😀\n条—\r%".repeat(1000),
            // A lone `%` at the very end.
            "trailing%".to_string(),
        ];
        for v in adversarial {
            let m = EmailMetadata {
                subject: Some(v.clone()),
                from: vec![v.clone()],
                ..EmailMetadata::default()
            };
            // Must not panic, and must produce a parseable, round-trippable doc.
            let canonical = to_canonical(&m);
            let decoded = decode(&canonical).expect("version line present");
            assert_eq!(decoded.subject.as_deref(), Some(v.as_str()));
            assert_eq!(decoded.from, vec![v]);
        }
    }

    #[test]
    fn percent_encode_never_panics_on_empty_and_pure_escapables() {
        assert_eq!(percent_encode(""), "");
        // A string that is entirely escapable bytes.
        assert_eq!(percent_encode("\r\n"), "%0D%0A");
    }
}
