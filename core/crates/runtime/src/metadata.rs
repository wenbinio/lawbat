// SPDX-License-Identifier: AGPL-3.0-or-later
//! Structured email-header metadata (the `matter.read:metadata` seam — see
//! `to-read/runtime.METADATA-SEAM-PROPOSAL.md` §6–§9).
//!
//! The trusted core reads per-message email headers (From / To / Cc / **Bcc** /
//! Reply-To / Subject / Date / Message-ID) so a consumer (the inbox) triages
//! against typed, already-parsed fields instead of re-parsing them out of body
//! text — exactly the duplicated-parser leak surface that the `.eml` extractor's
//! Critical multibyte-slice panic warned about.
//!
//! ## Division of labor (the load-bearing decision, proposal §6)
//! The trusted core (`runtime`) MUST NOT depend on a mail parser and MUST NOT
//! hand-roll RFC 822 / RFC 2047 parsing in its most-trusted code. So the PRODUCER
//! (`extract`, at ingestion) does ALL the hard RFC parsing ONCE and writes a
//! TRIVIAL, std-safely-parseable canonical form (`firmos.meta/1`). The core only
//! DESERIALIZES that trivial form — no RFC parsing in the core, no new core dep
//! (this module is std-only; the crate stays `sha2`+`hmac`).
//!
//! ## `firmos.meta/1` — the canonical stored form (proposal §6)
//! - **Line 1 is the version tag:** `firmos.meta/1`. A missing/unknown version is
//!   REFUSED fail-closed (a format change can never be silently mis-read).
//! - **Each subsequent line is one field value:** `TAG<SP>percent-encoded-value`,
//!   where `TAG ∈ { from, to, cc, bcc, reply-to, subject, date, message-id }`.
//! - **Multi-value fields** (`from`/`to`/`cc`/`bcc`/`reply-to`) emit one line per
//!   value, repeating the TAG, in source order.
//! - **Single-value fields** (`subject`/`date`/`message-id`) emit at most one
//!   line. If duplicated (a malformed producer), we keep the LAST line (documented
//!   below) — a deterministic last-write-wins, never a panic.
//! - **Percent-encoding** escapes `%`, CR/LF, and ASCII control chars so every
//!   value is exactly one line and round-trips losslessly. The core decodes `%XX`
//!   with std-only code.
//! - **Absent field → no line → `None`/empty** in the result (NEVER fabricated —
//!   the extractor's no-fabrication rule carries through the seam).
//!
//! Nothing here opens a socket or touches the filesystem; it is pure, deterministic
//! string processing that NEVER panics on any input (fail-closed: a malformed line
//! is skipped lossily; a bad version is an `Err`).

use crate::error::{CoreError, CoreResult};

/// Defensive bound on the canonical input the core will deserialize. The producer
/// is the TRUSTED ingestion job, but the stored bytes originate from matter data
/// (addresses/subjects), so a hostile or corrupt blob must never let the parser
/// allocate unboundedly. 256 KiB is far larger than any realistic header block
/// (RFC 5322 lines + a handful of recipients) while bounding abuse. An input over
/// the cap is REFUSED fail-closed rather than parsed.
///
/// PUBLIC because the INGESTION JOB (`ingest` crate) must target this exact cap: it
/// is the producer's contract that a serialized `firmos.meta/1` doc stays readable.
/// A doc over the cap is refused WHOLE here (not per-field), so the job clamps to
/// `<= MAX_CANONICAL_BYTES` with a surfaced warning rather than emit an
/// all-or-nothing-unreadable doc (review F-1). Exposing the constant means the job
/// references the SAME number the reader enforces — the two can never drift.
pub const MAX_CANONICAL_BYTES: usize = 256 * 1024;

/// The version tag the core understands. Line 1 of the canonical form MUST equal
/// this exactly; anything else is refused (so a future `firmos.meta/2` is never
/// silently mis-read as v1).
const VERSION_TAG: &str = "firmos.meta/1";

/// Structured email headers, parsed ONCE in the trusted core from the
/// `firmos.meta/1` canonical form and handed to a consumer as an INERT typed value.
///
/// This is a runtime-owned type (NOT a re-export of `extract::EmailMetadata` —
/// `runtime` must not depend on `extract`; the data plane depends on the core, not
/// vice-versa). Its shape deliberately MIRRORS `extract::EmailMetadata` so the
/// producer can populate it field-for-field.
///
/// It is **inert**: plain data with no methods that act. A consumer reads the
/// fields; it cannot make the value DO anything (no socket, no store, no audit).
///
/// **Bcc is an explicit field** (proposal §2): a named LEAK VECTOR. A typed field
/// forces every consumer to handle Bcc deliberately — it can never be "missed" the
/// way a substring of a flat string can. Absent fields stay `None` / empty and are
/// NEVER fabricated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmailHeaders {
    /// `From:` — one formatted address per element (usually exactly one).
    pub from: Vec<String>,
    /// `To:` — formatted recipients, in source order.
    pub to: Vec<String>,
    /// `Cc:` — formatted carbon-copy recipients.
    pub cc: Vec<String>,
    /// `Bcc:` — formatted blind-carbon recipients. A LEAK VECTOR: surfaced
    /// explicitly, never silently dropped.
    pub bcc: Vec<String>,
    /// `Reply-To:` — formatted reply addresses.
    pub reply_to: Vec<String>,
    /// `Subject:` — already RFC 2047-decoded by the producer. `None` if absent
    /// (never fabricated).
    pub subject: Option<String>,
    /// `Date:` — RFC 3339 when the producer could parse it, else `None` (the core
    /// never guesses a date — consistent with the inbox's no-anchor posture).
    pub date: Option<String>,
    /// `Message-ID:` — the message's own identifier, verbatim. `None` if absent.
    pub message_id: Option<String>,
}

impl EmailHeaders {
    /// Total recipient COUNT across the From / To / Cc / Bcc / Reply-To fields.
    /// Used ONLY to build a counts-only audit detail — a number, NEVER a value.
    /// Kept here so the audit-detail format has a single, header-value-free source
    /// of the count it is allowed to record.
    pub(crate) fn recipient_count(&self) -> usize {
        self.from.len() + self.to.len() + self.cc.len() + self.bcc.len() + self.reply_to.len()
    }
}

/// Percent-decode a single canonical VALUE, std-only and NEVER-panic.
///
/// `%XX` (two ASCII hex digits) decodes to the byte `0xXX`; every other byte is
/// taken verbatim. A malformed escape — a trailing `%` with fewer than two
/// following chars, or a `%` followed by a non-hex char — makes the WHOLE value
/// malformed: we return `None` so the caller can SKIP that line lossily (the
/// fail-closed posture: a value we cannot decode unambiguously is dropped, never
/// guessed and never panicked on).
///
/// Decoding is byte-oriented (the canonical form percent-escapes any byte the
/// producer chose to, including the UTF-8 bytes of non-ASCII characters), then the
/// resulting bytes are interpreted as UTF-8. Invalid UTF-8 after decode → `None`
/// (skip the line) rather than a lossy replacement, so a value never silently
/// mutates.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            // Need exactly two more chars, both ASCII hex.
            let hi = bytes.get(i + 1).copied()?;
            let lo = bytes.get(i + 2).copied()?;
            let hi = hex_val(hi)?;
            let lo = hex_val(lo)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    // The decoded bytes must be valid UTF-8 (the producer encodes UTF-8 values).
    String::from_utf8(out).ok()
}

/// ASCII hex digit (0-9, a-f, A-F) → its 0..=15 value, or `None` if not hex.
/// std-only, no allocation.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse the `firmos.meta/1` canonical form into typed [`EmailHeaders`].
///
/// **std-only, NEVER-panic, fail-closed.** The ONLY "parsing" in the trusted core,
/// and it is trivial (line split + percent-decode), NOT RFC 822.
///
/// Behavior, precisely (proposal §7):
/// - **Input bound:** an input over [`MAX_CANONICAL_BYTES`] is REFUSED with
///   `Err(Backend)` (defensive — never allocate unboundedly over matter-derived
///   bytes).
/// - **Version line:** line 1 MUST equal `firmos.meta/1` (CRLF-tolerant — the
///   `lines()` iterator strips a trailing CR). A missing or unknown version →
///   `Err(Backend)` (fail-closed: a format change is never silently mis-read).
/// - **Field lines:** each is `TAG<SP>value`. The TAG is the text BEFORE the first
///   ASCII space; the value is everything AFTER it (so a value may itself contain
///   spaces). The value is percent-decoded.
/// - **Multi-value fields** (`from`/`to`/`cc`/`bcc`/`reply-to`) APPEND in order.
/// - **Single-value fields** (`subject`/`date`/`message-id`) take the LAST line
///   (last-write-wins) if a malformed producer emitted more than one — chosen for
///   determinism; a single well-formed doc has at most one anyway.
/// - **Malformed line — SKIPPED lossily, never a panic:** a line with no space
///   (no TAG/value separator), or whose value fails to percent-decode, is
///   IGNORED. We do not abort the whole parse on one bad line (a single corrupt
///   value must not lose the other headers), and we never fabricate a value.
/// - **Unknown TAG — IGNORED** (forward-compat within the same version: a
///   `firmos.meta/1` producer may add a tag we don't model; we skip it rather than
///   error, so an additive change stays readable).
/// - **Absent field → `None`/empty** (never fabricated).
///
/// An empty value (`"to "` — TAG, space, nothing after) percent-decodes to the
/// empty string and IS recorded for a multi-value field (the producer emitted a
/// line, so the value existed); a single-value field set to empty stays `Some("")`.
/// The producer never emits a line for a truly absent field, so this only arises
/// from a deliberately-empty value, which is preserved faithfully rather than
/// dropped.
pub fn parse_email_headers(canonical: &str) -> CoreResult<EmailHeaders> {
    if canonical.len() > MAX_CANONICAL_BYTES {
        return Err(CoreError::Backend(format!(
            "metadata canonical form too large: {} bytes (max {MAX_CANONICAL_BYTES})",
            canonical.len()
        )));
    }

    // `lines()` splits on \n and strips a trailing \r, so CRLF and LF both work and
    // it never panics. An empty input yields no lines → no version line → Err below.
    let mut lines = canonical.lines();

    // Line 1 MUST be the version tag (fail-closed on missing/unknown).
    match lines.next() {
        Some(v) if v == VERSION_TAG => {}
        Some(other) => {
            return Err(CoreError::Backend(format!(
                "metadata: unknown/unsupported version line (expected {VERSION_TAG:?}, got {:?})",
                // Bound the echoed line: it is the version tag, not a header value,
                // but stay defensive against a huge first line.
                other.chars().take(64).collect::<String>()
            )));
        }
        None => {
            return Err(CoreError::Backend(
                "metadata: empty input (missing firmos.meta/1 version line)".into(),
            ));
        }
    }

    let mut headers = EmailHeaders::default();

    for line in lines {
        // Split on the FIRST ASCII space: TAG before, value after. A line with no
        // space has no TAG/value separator → malformed → SKIP (never panic).
        let Some(space) = line.find(' ') else {
            continue;
        };
        let tag = &line[..space];
        let raw_value = &line[space + 1..];

        // Percent-decode the value. A value we cannot unambiguously decode is a
        // malformed line → SKIP it lossily (fail-closed: never guess, never panic).
        let Some(value) = percent_decode(raw_value) else {
            continue;
        };

        match tag {
            "from" => headers.from.push(value),
            "to" => headers.to.push(value),
            "cc" => headers.cc.push(value),
            "bcc" => headers.bcc.push(value),
            "reply-to" => headers.reply_to.push(value),
            // Single-value fields: last-write-wins (documented above).
            "subject" => headers.subject = Some(value),
            "date" => headers.date = Some(value),
            "message-id" => headers.message_id = Some(value),
            // Unknown TAG: ignore for forward-compat within the same version.
            _ => {}
        }
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_basic_and_passthrough() {
        // Plain ASCII passes through unchanged.
        assert_eq!(
            percent_decode("counsel@firm.example").as_deref(),
            Some("counsel@firm.example")
        );
        // %XX decodes; %3A is ':', %20 is space, %25 is '%'.
        assert_eq!(
            percent_decode("Re%3A%20100%25").as_deref(),
            Some("Re: 100%")
        );
        // Non-ASCII via percent-encoded UTF-8 bytes: '—' (U+2014) = E2 80 94.
        assert_eq!(percent_decode("a%E2%80%94b").as_deref(), Some("a—b"));
        // Lowercase hex works too.
        assert_eq!(percent_decode("%e2%80%94").as_deref(), Some("—"));
    }

    #[test]
    fn percent_decode_malformed_is_none_never_panics() {
        // A trailing '%' with nothing after → None (malformed), not a panic.
        assert_eq!(percent_decode("%"), None);
        // A '%' with only one following char → None.
        assert_eq!(percent_decode("%4"), None);
        // A '%' followed by a non-hex char → None.
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%4g"), None);
        // Malformed in the MIDDLE of an otherwise-fine value → whole value None.
        assert_eq!(percent_decode("ok%then"), None);
        // Bytes that don't form valid UTF-8 after decode → None (no lossy mutate).
        // 0xFF is never valid UTF-8 on its own.
        assert_eq!(percent_decode("%ff"), None);
    }

    #[test]
    fn parse_requires_known_version_line() {
        // Empty input → Err (no version line).
        assert!(matches!(
            parse_email_headers(""),
            Err(CoreError::Backend(_))
        ));
        // Wrong/unknown version → Err (fail-closed; never mis-read as v1).
        assert!(matches!(
            parse_email_headers("firmos.meta/2\nto x"),
            Err(CoreError::Backend(_))
        ));
        assert!(matches!(
            parse_email_headers("not a version\nto x"),
            Err(CoreError::Backend(_))
        ));
        // Exactly the version line and nothing else → Ok with all-empty headers.
        let h = parse_email_headers(VERSION_TAG).unwrap();
        assert_eq!(h, EmailHeaders::default());
    }

    #[test]
    fn parse_multi_value_and_single_value_fields() {
        let canonical = "firmos.meta/1\n\
            from Jane%20Roe%20%3Cjane.roe@acme.example%3E\n\
            to a@x.example\n\
            to b@y.example\n\
            cc c@z.example\n\
            bcc hidden@watcher.example\n\
            reply-to reply@acme.example\n\
            subject Re%3A%20Project%20Condor%20%E2%80%94%20urgent\n\
            date 2026-06-19T09:30:00Z\n\
            message-id <abc123@acme.example>\n";
        let h = parse_email_headers(canonical).unwrap();
        assert_eq!(h.from, vec!["Jane Roe <jane.roe@acme.example>"]);
        assert_eq!(h.to, vec!["a@x.example", "b@y.example"]); // multi-value, in order
        assert_eq!(h.cc, vec!["c@z.example"]);
        assert_eq!(h.bcc, vec!["hidden@watcher.example"]); // Bcc surfaced
        assert_eq!(h.reply_to, vec!["reply@acme.example"]);
        assert_eq!(h.subject.as_deref(), Some("Re: Project Condor — urgent")); // : % unicode
        assert_eq!(h.date.as_deref(), Some("2026-06-19T09:30:00Z"));
        assert_eq!(h.message_id.as_deref(), Some("<abc123@acme.example>"));
    }

    #[test]
    fn parse_missing_field_is_none_never_fabricated() {
        // No subject/date/message-id/cc/bcc lines → they stay None / empty.
        let h = parse_email_headers("firmos.meta/1\nfrom a@x.example\nto b@y.example").unwrap();
        assert_eq!(h.from, vec!["a@x.example"]);
        assert_eq!(h.to, vec!["b@y.example"]);
        assert!(h.cc.is_empty());
        assert!(h.bcc.is_empty());
        assert!(h.reply_to.is_empty());
        assert_eq!(h.subject, None);
        assert_eq!(h.date, None);
        assert_eq!(h.message_id, None);
    }

    #[test]
    fn parse_skips_malformed_lines_lossily_keeps_the_rest() {
        // One line with no space (no separator), one with a bad %XX value: BOTH are
        // skipped, but the good lines around them survive — never a panic.
        let canonical = "firmos.meta/1\n\
            to good@x.example\n\
            noSpaceHereSoMalformed\n\
            cc bad%zzvalue\n\
            subject fine";
        let h = parse_email_headers(canonical).unwrap();
        assert_eq!(h.to, vec!["good@x.example"]);
        assert!(
            h.cc.is_empty(),
            "the bad-%XX cc line was skipped, not parsed/fabricated"
        );
        assert_eq!(h.subject.as_deref(), Some("fine"));
    }

    #[test]
    fn parse_ignores_unknown_tags_forward_compat() {
        let h =
            parse_email_headers("firmos.meta/1\nto a@x.example\nx-future thing\nimportance high")
                .unwrap();
        assert_eq!(h.to, vec!["a@x.example"]);
        // Unknown tags left no trace; no panic, no error.
        assert!(h.cc.is_empty() && h.subject.is_none());
    }

    #[test]
    fn parse_single_value_field_is_last_write_wins() {
        // A malformed producer that emits subject twice: deterministic last-wins.
        let h = parse_email_headers("firmos.meta/1\nsubject first\nsubject second").unwrap();
        assert_eq!(h.subject.as_deref(), Some("second"));
    }

    #[test]
    fn parse_crlf_tolerant() {
        // CRLF line endings parse identically (lines() strips the trailing \r).
        let h = parse_email_headers("firmos.meta/1\r\nto a@x.example\r\nsubject hi\r\n").unwrap();
        assert_eq!(h.to, vec!["a@x.example"]);
        assert_eq!(h.subject.as_deref(), Some("hi"));
    }

    #[test]
    fn parse_rejects_oversized_input_fail_closed() {
        // An input over the cap is refused, not parsed (defensive bound).
        let big = format!("firmos.meta/1\n{}", "x".repeat(MAX_CANONICAL_BYTES));
        assert!(matches!(
            parse_email_headers(&big),
            Err(CoreError::Backend(_))
        ));
    }

    #[test]
    fn parse_empty_value_for_multivalue_is_preserved() {
        // "to " — TAG, space, empty value → an empty-string recipient is recorded
        // faithfully (the producer emitted a line, so the value existed).
        let h = parse_email_headers("firmos.meta/1\nto ").unwrap();
        assert_eq!(h.to, vec![""]);
    }

    #[test]
    fn recipient_count_sums_all_address_fields() {
        let h = parse_email_headers(
            "firmos.meta/1\nfrom a\nto b\nto c\ncc d\nbcc e\nreply-to f\nsubject s",
        )
        .unwrap();
        // from(1)+to(2)+cc(1)+bcc(1)+reply-to(1) = 6; subject is NOT a recipient.
        assert_eq!(h.recipient_count(), 6);
    }
}
