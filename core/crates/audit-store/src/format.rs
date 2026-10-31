// SPDX-License-Identifier: AGPL-3.0-or-later
//! On-disk framing for the durable audit log (`audit.log`) + the entry codec.
//!
//! ## One canonical form, two consumers
//!
//! The trusted core MACs an [`AuditEntry`] with [`runtime::compute_entry_hash`]
//! over a fixed, length-prefixed serialization of its fields (inc 0 factored that
//! into a free function so a second backend computes byte-identical tags). This
//! module's entry body uses the SAME length-prefix vocabulary, so ONE function
//! ([`read_entry_body`]) both deserializes a record into an `AuditEntry` AND yields
//! the field bytes the chain re-MACs — there is no second, drift-prone serializer
//! of the authoritative record. No serde anywhere on the chained record.
//!
//! ## File layout
//!
//! ```text
//! [ header ]                                              (once, at offset 0)
//!   magic   : 8 bytes  = b"LWBTAUD1"
//!   version : u8       = FORMAT_VERSION
//!   key_id  : 32 bytes = SHA-256(key)   (identifies WHICH key, NEVER the key)
//! [ record ]  (append-only, one per AuditEntry, repeated)
//!   record_len : u32 LE  = length of (entry body) ONLY  (excludes hash + crc)
//!   entry body : record_len bytes  (the canonical field bytes — see below)
//!   stored_hash: 32 bytes  (the entry's recorded MAC, AuditEntry::hash)
//!   crc32      : u32 LE  over (record_len bytes || entry body || stored_hash)
//! ```
//!
//! The entry body is:
//! ```text
//!   seq        : u64 LE
//!   timestamp  : u64 LE
//!   acting_user: u64 LE len || bytes
//!   matter     : u64 LE len || bytes
//!   module     : u64 LE len || bytes
//!   capability : u64 LE len || bytes   (the Display form, as the MAC uses)
//!   detail     : u64 LE len || bytes
//! ```
//! i.e. EXACTLY the MAC's field order/encoding, MINUS the leading `prev` hash (the
//! chaining input, supplied by the reader during replay) — so re-MACing a read
//! body is `compute_entry_hash(key, prev, &entry)`.
//!
//! ## Crash / torn-record handling (read side)
//!
//! `record()` does ONE `write_all` of header-or-record then `fsync`, so a crash
//! mid-append can leave a trailing PARTIAL record (truncated `record_len`, body, or
//! crc). On read, a trailing record whose declared length overruns EOF, or whose
//! CRC fails, is a TORN FINAL record (crash mid-write) → it is dropped and a
//! [`ReadDiagnostic::TornFinalRecord`] surfaced; verification continues on the
//! clean prefix. A bad record in the MIDDLE (valid records follow it) is real
//! corruption, NOT a torn tail → [`read_log`] returns the position so the caller
//! reports `ChainBroken`. This distinction is load-bearing: a torn tail is benign
//! crash recovery; mid-stream damage is tampering/bit-rot and must be refused.

use runtime::{AuditEntry, AuditHash};
use std::str::FromStr;

/// Magic at the start of every `audit.log`. The trailing `1` mirrors
/// [`FORMAT_VERSION`]; bumping the wire format bumps both.
pub const MAGIC: [u8; 8] = *b"LWBTAUD1";

/// On-disk format version. A reader refuses a version it does not understand
/// (fail-closed) rather than guessing at a future layout.
pub const FORMAT_VERSION: u8 = 1;

/// Header byte length: magic(8) + version(1) + key_id(32).
pub const HEADER_LEN: usize = 8 + 1 + 32;

/// Fixed trailer per record: stored_hash(32) + crc32(4). The `record_len` u32
/// prefix is counted separately by [`record_frame_len`].
const HASH_LEN: usize = 32;
const CRC_LEN: usize = 4;

/// Hard ceiling on a single record's declared body length (sanity bound before
/// allocating from an attacker-supplied `record_len`). 16 MiB is far above any
/// real audit entry (a few short strings) yet stops a corrupt/huge length prefix
/// from triggering a giant allocation. A body claiming more is treated as a torn
/// tail (if final) or corruption (if mid-stream) — never allocated.
pub const MAX_RECORD_BODY: usize = 16 * 1024 * 1024;

/// Diagnostics a read-back may surface WITHOUT being a verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadDiagnostic {
    /// A trailing partial/corrupt record was dropped as a crash-mid-append. The
    /// byte offset where it began is carried for the operational log. The clean
    /// prefix is still verified + matched against the anchor.
    TornFinalRecord { at_offset: u64 },
}

/// Outcome of replaying the on-disk records (framing-level; chain/anchor checks
/// happen above this in `lib.rs`).
#[derive(Debug)]
pub struct ReadLog {
    /// The fully-parsed, framing-valid records (the clean prefix).
    pub entries: Vec<AuditEntry>,
    /// Any non-fatal recovery note (a dropped torn final record).
    pub diagnostic: Option<ReadDiagnostic>,
}

/// A framing-level failure that means the log is CORRUPT (not merely torn at the
/// tail) — the caller maps this to `ChainBroken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// File shorter than the header, or the header magic/version is wrong.
    BadHeader,
    /// A record BEFORE the final one is malformed (overruns, bad CRC, bad body):
    /// real mid-stream corruption, not a torn tail.
    CorruptRecord { index: usize, at_offset: u64 },
}

/// Encode the one-time header bytes: magic || version || key_id.
pub fn encode_header(key_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(key_id);
    out
}

/// Parse + validate the header. Returns the embedded key-id on success.
/// Fail-closed: a wrong magic or unknown version is [`FormatError::BadHeader`].
pub fn read_header(buf: &[u8]) -> Result<[u8; 32], FormatError> {
    if buf.len() < HEADER_LEN {
        return Err(FormatError::BadHeader);
    }
    if buf[0..8] != MAGIC {
        return Err(FormatError::BadHeader);
    }
    if buf[8] != FORMAT_VERSION {
        return Err(FormatError::BadHeader);
    }
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&buf[9..9 + 32]);
    Ok(key_id)
}

/// Serialize JUST the entry body (the canonical field bytes, MINUS the leading
/// `prev` hash). Mirrors [`runtime::compute_entry_hash`]'s field order/encoding so
/// re-MACing a read-back body reproduces the stored hash.
fn encode_entry_body(e: &AuditEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&e.seq.to_le_bytes());
    out.extend_from_slice(&e.timestamp.to_le_bytes());
    push_lp(&mut out, e.acting_user.as_bytes());
    push_lp(&mut out, e.matter.as_bytes());
    push_lp(&mut out, e.module.as_bytes());
    push_lp(&mut out, e.capability.to_string().as_bytes());
    push_lp(&mut out, e.detail.as_bytes());
    out
}

/// Encode a complete on-disk record: `record_len || body || stored_hash || crc32`.
/// The CRC covers the framed bytes (len prefix + body + hash) so a torn write or a
/// flipped byte is caught on read-back before the (more expensive, keyed) MAC check.
pub fn encode_record(e: &AuditEntry) -> Vec<u8> {
    let body = encode_entry_body(e);
    // L-2-style explicit narrowing: a body over u32::MAX cannot occur (entries are
    // a few short strings); clamp defensively so the cast never silently wraps.
    let body_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut framed = Vec::with_capacity(4 + body.len() + HASH_LEN + CRC_LEN);
    framed.extend_from_slice(&body_len.to_le_bytes());
    framed.extend_from_slice(&body);
    framed.extend_from_slice(e.hash.as_bytes());
    let crc = crc32(&framed);
    framed.extend_from_slice(&crc.to_le_bytes());
    framed
}

/// Total on-disk byte length of a record framing a body of `body_len` bytes:
/// record_len(4) + body + stored_hash(32) + crc32(4).
fn record_frame_len(body_len: usize) -> usize {
    4 + body_len + HASH_LEN + CRC_LEN
}

/// Replay every record after the header. Distinguishes a TORN FINAL record (crash
/// mid-append → dropped + diagnostic, clean prefix kept) from MID-STREAM corruption
/// (a malformed record with valid records after it → [`FormatError::CorruptRecord`]).
///
/// Two-pass shape: we walk forward; if a record fails to frame, we check whether
/// ANY well-framed record could still follow. Because records are self-describing
/// (length-prefixed + CRC), a failure that is the LAST thing in the file is a torn
/// tail; a failure with more bytes that DO frame into valid records afterwards is
/// mid-stream corruption.
///
/// DEFENCE IN DEPTH: this framing-level classification is NOT the only guard. Even
/// if mid-stream corruption were misclassified here as a torn tail (its cascade
/// leaves nothing parseable after it), the caller's ANCHOR reconciliation is the
/// backstop — a dropped record that the anchor still counts surfaces as
/// `TruncationDetected` (or a head mismatch at the anchored position), never a
/// silent `Verified`. A torn tail is benign ONLY because the anchor independently
/// confirms the surviving clean prefix equals the trusted head.
pub fn read_log(buf: &[u8]) -> Result<ReadLog, FormatError> {
    let key_id_consumed = HEADER_LEN; // header already validated by caller
    let mut entries = Vec::new();
    let mut pos = key_id_consumed;
    let mut diagnostic = None;

    while pos < buf.len() {
        match try_read_record(buf, pos) {
            RecordRead::Ok { entry, next } => {
                entries.push(entry);
                pos = next;
            }
            RecordRead::Bad => {
                // This record at `pos` is malformed. Decide torn-tail vs mid-stream
                // corruption by asking: does any VALID record frame later in the
                // file? If a valid record can be parsed starting at some offset >
                // pos, then bytes after the bad one are real records → the bad one
                // is mid-stream corruption. If nothing valid follows, the bad bytes
                // are a torn final record (crash mid-append) → drop + diagnostic.
                if has_valid_record_after(buf, pos) {
                    return Err(FormatError::CorruptRecord {
                        index: entries.len(),
                        at_offset: pos as u64,
                    });
                }
                diagnostic = Some(ReadDiagnostic::TornFinalRecord {
                    at_offset: pos as u64,
                });
                break;
            }
        }
    }

    Ok(ReadLog {
        entries,
        diagnostic,
    })
}

/// Result of attempting to frame one record at `pos`.
enum RecordRead {
    Ok { entry: AuditEntry, next: usize },
    Bad,
}

/// Attempt to read + CRC-verify a single record beginning at `pos`. Returns the
/// decoded entry and the next offset, or `Bad` (overrun / bad CRC / undecodable
/// body). Never panics on hostile bytes — every slice is bounds-checked first.
fn try_read_record(buf: &[u8], pos: usize) -> RecordRead {
    // Need the 4-byte length prefix.
    if pos + 4 > buf.len() {
        return RecordRead::Bad;
    }
    let body_len =
        u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    // Reject an absurd/corrupt length BEFORE computing the frame extent (the cast
    // above is lossless: u32 always fits usize on the targets we build).
    if body_len > MAX_RECORD_BODY {
        return RecordRead::Bad;
    }
    let frame_len = record_frame_len(body_len);
    // Guard the addition (frame_len) and the slice end against EOF.
    let end = match pos.checked_add(frame_len) {
        Some(e) => e,
        None => return RecordRead::Bad,
    };
    if end > buf.len() {
        return RecordRead::Bad; // declared length overruns EOF — torn or corrupt
    }
    let framed = &buf[pos..end];
    // CRC covers everything except the trailing 4 CRC bytes.
    let crc_off = frame_len - CRC_LEN;
    let stored_crc = u32::from_le_bytes([
        framed[crc_off],
        framed[crc_off + 1],
        framed[crc_off + 2],
        framed[crc_off + 3],
    ]);
    if crc32(&framed[..crc_off]) != stored_crc {
        return RecordRead::Bad; // flipped byte / torn write
    }
    // Decode the body into an AuditEntry. The stored hash sits between body and crc.
    let body = &framed[4..4 + body_len];
    let hash_off = 4 + body_len;
    let mut stored_hash = [0u8; 32];
    stored_hash.copy_from_slice(&framed[hash_off..hash_off + 32]);
    match read_entry_body(body, AuditHash(stored_hash)) {
        Some(entry) => RecordRead::Ok { entry, next: end },
        None => RecordRead::Bad, // body bytes are not a well-formed entry
    }
}

/// Is there ANY well-framed, CRC-valid record beginning at some offset strictly
/// after `bad_pos`? Used to tell a torn FINAL record (nothing valid follows) from
/// mid-stream corruption (valid records do follow). We scan candidate start
/// offsets; a single valid record after the damage proves mid-stream corruption.
fn has_valid_record_after(buf: &[u8], bad_pos: usize) -> bool {
    // A torn tail means the damage is the last thing in the file: there is no
    // complete record after it. We look for the NEXT offset at which a record
    // frames cleanly. Scanning byte-by-byte is bounded by the file size and only
    // runs on the (rare) damaged-record path, never on the happy path.
    //
    // BOUND the scan window (#14): a genuine following record begins right after the
    // damaged frame. A real append writes records back-to-back, so if any well-formed
    // record exists after `bad_pos` it starts within ONE max-frame's worth of bytes of
    // the damage — the largest gap a single corrupt/torn frame can introduce. Capping
    // the probe window at `record_frame_len(MAX_RECORD_BODY)` past `bad_pos` keeps this
    // from degenerating into a full O(file) byte-walk on a pathological input (e.g. a
    // huge run of near-miss bytes), while still finding a true mid-stream record. The
    // caller's ANCHOR reconciliation is the backstop if a record beyond the window were
    // ever dropped: a count/head mismatch surfaces, never a silent `Verified`.
    let window_end = bad_pos
        .saturating_add(record_frame_len(MAX_RECORD_BODY))
        .min(buf.len());
    // INCLUSIVE upper bound: a max-size damaged frame pushes the next record's start
    // offset to exactly `bad_pos + record_frame_len(MAX_RECORD_BODY)` == window_end, so
    // a strict `<` would miss a genuine boundary record and mislabel mid-stream
    // corruption as a torn tail. `try_read_record` bounds-checks the frame (and `probe
    // == buf.len()` reads no bytes -> not Ok), so probing at the boundary is safe.
    let mut probe = bad_pos + 1;
    while probe <= window_end {
        if let RecordRead::Ok { .. } = try_read_record(buf, probe) {
            return true;
        }
        probe += 1;
    }
    false
}

/// Decode an entry body (the bytes between the length prefix and the stored hash)
/// into an [`AuditEntry`], attaching `stored_hash`. Returns `None` on any malformed
/// length-prefix / truncation / non-UTF-8 field / unparsable capability — the
/// caller treats `None` as a bad record. Never panics on hostile input.
pub fn read_entry_body(body: &[u8], stored_hash: AuditHash) -> Option<AuditEntry> {
    let mut c = Cursor { buf: body, pos: 0 };
    let seq = c.take_u64()?;
    let timestamp = c.take_u64()?;
    let acting_user = c.take_lp_string()?;
    let matter = c.take_lp_string()?;
    let module = c.take_lp_string()?;
    let capability_str = c.take_lp_string()?;
    let detail = c.take_lp_string()?;
    // The body must be fully consumed — trailing bytes mean a framing mismatch.
    if c.pos != body.len() {
        return None;
    }
    // Parse the capability back from its canonical Display form. A capability the
    // current taxonomy does not recognise is a corrupt/forward-incompatible record
    // → None (fail-closed), never a guessed value.
    let capability = runtime::Capability::from_str(&capability_str).ok()?;
    Some(AuditEntry {
        seq,
        timestamp,
        acting_user,
        matter,
        module,
        capability,
        detail,
        hash: stored_hash,
    })
}

/// A bounds-checked forward reader over a byte slice. Every `take` returns `None`
/// rather than panicking when the slice is too short — hostile-input safe.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }

    fn take_u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn take_lp_string(&mut self) -> Option<String> {
        let len = self.take_u64()? as usize;
        // Reject an absurd field length before slicing (defence in depth; the outer
        // record length already bounds this, but a corrupt inner length must not
        // index past the body).
        if len > self.buf.len() {
            return None;
        }
        let bytes = self.take(len)?;
        // The audit fields are UTF-8 `String`s by construction; non-UTF-8 is a
        // corrupt record.
        std::str::from_utf8(bytes).ok().map(|s| s.to_string())
    }
}

/// Append a length-prefixed field (u64 LE length, then bytes) — the on-disk twin
/// of the MAC's `update_lp`, so the body bytes match the MAC's field encoding.
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

/// CRC-32 (IEEE 802.3 / zlib polynomial 0xEDB88320), table-free bit-at-a-time.
///
/// Hand-rolled, std-only, to keep this security-critical crate's dependency surface
/// to `runtime` alone (no `crc32fast`). The CRC is NOT a security primitive — the
/// keyed HMAC chain is — it only cheaply catches torn writes / bit-rot on read-back
/// so a torn final record is recovered rather than misread. Standard 0xFFFFFFFF
/// init + final XOR; this matches the common `crc32` of any byte string.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vector() {
        // The standard CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        // Empty input → 0 after init+xor.
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn header_round_trips_and_rejects_garbage() {
        let key_id = [7u8; 32];
        let h = encode_header(&key_id);
        assert_eq!(h.len(), HEADER_LEN);
        assert_eq!(read_header(&h), Ok(key_id));
        // Wrong magic.
        let mut bad = h.clone();
        bad[0] = b'X';
        assert_eq!(read_header(&bad), Err(FormatError::BadHeader));
        // Wrong version.
        let mut badv = h.clone();
        badv[8] = 99;
        assert_eq!(read_header(&badv), Err(FormatError::BadHeader));
        // Too short.
        assert_eq!(
            read_header(&h[..HEADER_LEN - 1]),
            Err(FormatError::BadHeader)
        );
    }
}
