// SPDX-License-Identifier: AGPL-3.0-or-later
//! Increment-1 tests for the durable audit store: round-trip + head-equivalence
//! with `InMemoryAudit` (the one-canonical-form proof), every adversarial
//! `OpenOutcome`, torn-final-record recovery, append-refused-after-non-clean-open,
//! and byte-for-byte determinism under a fixed clock.

use super::*;
use runtime::{Audit, Capability, DataClass, FixedClock, InMemoryAudit};
use std::fs;
use std::path::Path;

/// A unique scratch dir per test under the scratchpad, so tests never collide.
fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join("lawbat-audit-store-tests");
    let dir = base.join(format!("{tag}-{}", std::process::id()));
    // Fresh each run.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("mk scratch dir");
    dir
}

const KEY: &[u8] = b"durable-audit-test-key-000000000";
const TS: u64 = 1_700_000_000_000;

fn record_one(a: &mut dyn Audit, detail: &str) {
    a.record(
        "j.smith",
        "Acme v Beta",
        "sg.test.module",
        Capability::MatterRead(DataClass::Metadata),
        detail,
    )
    .expect("record must succeed");
}

/// Build an N-entry durable store under a fixed clock, returning the dir.
fn make_store(dir: &Path, n: usize) {
    let mut d = DurableAudit::create_with_clock(dir, KEY, FixedClock::new(TS)).expect("create");
    for i in 0..n {
        record_one(&mut d, &format!("e{i}"));
    }
    assert!(d.verify_chain(), "freshly built durable chain must verify");
}

#[test]
fn round_trip_reopens_verified_and_matches_in_memory_head() {
    let dir = scratch("round-trip");
    make_store(&dir, 5);

    // Reopen → Verified with the expected count + head.
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    let (count, head) = match &outcome {
        OpenOutcome::Verified {
            count,
            head,
            diagnostic,
        } => {
            assert!(
                diagnostic.is_none(),
                "clean reopen has no torn-record diagnostic"
            );
            (*count, *head)
        }
        other => panic!("expected Verified, got {other:?}"),
    };
    assert_eq!(count, 5);
    let handle = handle.expect("Verified yields an appendable handle");
    assert_eq!(handle.len(), 5);
    assert!(handle.verify_chain());

    // The durable head EQUALS an InMemoryAudit fed the SAME entries + key — proof
    // the two backends share ONE canonical MAC form (inc 0).
    let mut mem = InMemoryAudit::with_clock_and_key(FixedClock::new(TS), KEY.to_vec());
    for i in 0..5 {
        record_one(&mut mem, &format!("e{i}"));
    }
    assert_eq!(
        head,
        mem.head_hash(),
        "durable head must equal in-memory head"
    );
    assert_eq!(handle.head_hash(), mem.head_hash());
}

#[test]
fn appending_after_verified_reopen_extends_the_chain() {
    let dir = scratch("append-after-open");
    make_store(&dir, 2);
    {
        let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
        assert!(matches!(outcome, OpenOutcome::Verified { count: 2, .. }));
        let mut d = handle.expect("appendable");
        record_one(&mut d, "third");
        assert_eq!(d.len(), 3);
    }
    // Reopen again → now 3, still Verified.
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::Verified { count: 3, .. }),
        "got {outcome:?}"
    );
    let d = handle.unwrap();
    assert!(d.verify_chain());
}

#[test]
fn erasure_detected_when_log_deleted() {
    let dir = scratch("erasure");
    make_store(&dir, 4);
    fs::remove_file(dir.join(LOG_FILE)).expect("rm log");
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::ErasureDetected),
        "got {outcome:?}"
    );
    assert!(handle.is_none(), "erasure yields NO appendable handle");
}

#[test]
fn erasure_detected_when_log_truncated_to_header_only() {
    // Truncate the log to JUST the header (zero records) while the anchor still
    // expects entries → the recorded entries were erased.
    let dir = scratch("erasure-header");
    make_store(&dir, 3);
    let log = dir.join(LOG_FILE);
    let hdr = format::HEADER_LEN as u64;
    let f = OpenOptions::new().write(true).open(&log).unwrap();
    f.set_len(hdr).unwrap();
    f.sync_all().unwrap();
    let (outcome, _h) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::ErasureDetected),
        "got {outcome:?}"
    );
}

#[test]
fn truncation_detected_when_tail_records_dropped() {
    let dir = scratch("truncation");
    make_store(&dir, 6);
    // Drop the last ~2 records by truncating the file to a length BETWEEN record
    // boundaries is risky; instead truncate to a clean prefix of 4 records. We
    // recompute the offset by re-reading the file and finding the 4th record end.
    let log = dir.join(LOG_FILE);
    let bytes = fs::read(&log).unwrap();
    // Walk records to find the byte offset after the 4th record.
    let cut = nth_record_end(&bytes, 4);
    let f = OpenOptions::new().write(true).open(&log).unwrap();
    f.set_len(cut as u64).unwrap();
    f.sync_all().unwrap();

    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(
            outcome,
            OpenOutcome::TruncationDetected {
                on_disk: 4,
                anchored: 6
            }
        ),
        "got {outcome:?}"
    );
    assert!(handle.is_none(), "truncation yields NO appendable handle");
}

#[test]
fn chain_broken_when_middle_record_byte_flipped() {
    let dir = scratch("chain-broken");
    make_store(&dir, 5);
    let log = dir.join(LOG_FILE);
    let mut bytes = fs::read(&log).unwrap();
    // Flip a byte INSIDE the body of the 2nd record (a middle record, so there are
    // valid records after it → mid-stream corruption, NOT a torn tail). The record
    // body begins 4 bytes (len prefix) into the record; flip the first body byte.
    let r1_start = nth_record_end(&bytes, 1); // end of record 0 = start of record 1
    let flip_at = r1_start + 4 + 8; // skip len prefix + seq → land in the timestamp
    bytes[flip_at] ^= 0xFF;
    fs::write(&log, &bytes).unwrap();

    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::ChainBroken),
        "got {outcome:?}"
    );
    assert!(handle.is_none());
}

#[test]
fn chain_broken_when_middle_record_edited_with_recomputed_crc() {
    // The KEYED MAC, not the CRC, is the real tamper backstop. An attacker who edits
    // a middle record's body AND recomputes its CRC frames cleanly, so CRC alone
    // would pass — but the entry's recomputed HMAC won't match its stored hash, so
    // verify_entries (keyed) rejects it → ChainBroken. (Without the key the attacker
    // cannot also fix the stored hash + all downstream hashes.)
    let dir = scratch("chain-broken-crc-fixed");
    make_store(&dir, 5);
    let log = dir.join(LOG_FILE);
    let mut bytes = fs::read(&log).unwrap();

    // Locate record 1 (a middle record). Edit a body byte then recompute its CRC so
    // the framing check passes and only the keyed MAC catches it.
    let r1_start = nth_record_end(&bytes, 1);
    let body_len = u32::from_le_bytes([
        bytes[r1_start],
        bytes[r1_start + 1],
        bytes[r1_start + 2],
        bytes[r1_start + 3],
    ]) as usize;
    let frame_len = 4 + body_len + 32 + 4;
    let crc_off = r1_start + frame_len - 4;
    // Flip a body byte (the first detail/timestamp byte).
    bytes[r1_start + 4 + 8] ^= 0xFF;
    // Recompute the CRC over (len prefix + body + stored hash).
    let new_crc = format::crc32(&bytes[r1_start..crc_off]);
    bytes[crc_off..crc_off + 4].copy_from_slice(&new_crc.to_le_bytes());
    fs::write(&log, &bytes).unwrap();

    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::ChainBroken),
        "a CRC-consistent mid-stream edit must still be caught by the keyed MAC, got {outcome:?}"
    );
    assert!(handle.is_none());
}

#[test]
fn anchor_mismatch_when_anchor_file_edited() {
    let dir = scratch("anchor-mismatch");
    make_store(&dir, 4);
    let anchor = dir.join(ANCHOR_FILE);
    let mut bytes = fs::read(&anchor).unwrap();
    // Flip a byte in the anchor's count field (offset 9 + 32 = 41). The MAC then
    // fails to verify → AnchorMismatch.
    bytes[9 + 32] ^= 0xFF;
    fs::write(&anchor, &bytes).unwrap();

    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::AnchorMismatch),
        "got {outcome:?}"
    );
    assert!(handle.is_none());
}

#[test]
fn wrong_key_detected_via_header_key_id() {
    let dir = scratch("wrong-key");
    make_store(&dir, 3);
    let wrong = b"a-totally-different-audit-keyyyyy";
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, wrong, FixedClock::new(TS));
    assert!(matches!(outcome, OpenOutcome::WrongKey), "got {outcome:?}");
    assert!(handle.is_none());
}

#[test]
fn torn_final_record_is_recovered_with_diagnostic() {
    // Simulate a crash mid-append: write a clean store, then append a HALF record
    // (garbage shorter than a full frame) onto the end. Reopen must recover the
    // clean prefix → Verified WITH a TornFinalRecord diagnostic, because the clean
    // prefix still matches the anchor's prior head.
    let dir = scratch("torn-final");
    make_store(&dir, 3);
    let log = dir.join(LOG_FILE);
    // Append a partial record: a plausible length prefix claiming a big body, then
    // only a few bytes (so it overruns EOF → torn tail).
    let mut f = OpenOptions::new().append(true).open(&log).unwrap();
    let fake_len: u32 = 1000;
    f.write_all(&fake_len.to_le_bytes()).unwrap();
    f.write_all(b"only-a-few-bytes").unwrap();
    f.sync_all().unwrap();

    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    match outcome {
        OpenOutcome::Verified {
            count, diagnostic, ..
        } => {
            assert_eq!(count, 3, "the clean 3-record prefix survives");
            assert!(
                matches!(diagnostic, Some(ReadDiagnostic::TornFinalRecord { .. })),
                "a torn final record must surface a diagnostic, got {diagnostic:?}"
            );
        }
        other => panic!("expected Verified+diagnostic, got {other:?}"),
    }
    let d = handle.expect("a recovered torn-tail store is still appendable");
    assert!(d.verify_chain());
}

#[test]
fn torn_final_record_with_bad_crc_is_recovered() {
    // A torn tail can also be a FULLY-FRAMED-LOOKING record whose CRC fails (the
    // write was interrupted after the length but the bytes are partial/garbage). If
    // nothing valid follows it, it is still a torn tail.
    let dir = scratch("torn-crc");
    make_store(&dir, 2);
    let log = dir.join(LOG_FILE);
    // Take a real record's bytes and append a corrupted copy whose CRC won't match.
    let bytes = fs::read(&log).unwrap();
    let r0_end = nth_record_end(&bytes, 1);
    let mut bad = bytes[format::HEADER_LEN..r0_end].to_vec(); // a full record's frame
                                                              // Corrupt a body byte but leave the (now-wrong) CRC → CRC mismatch.
    bad[5] ^= 0xFF;
    let mut f = OpenOptions::new().append(true).open(&log).unwrap();
    f.write_all(&bad).unwrap();
    f.sync_all().unwrap();

    let (outcome, _h) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(
            outcome,
            OpenOutcome::Verified {
                count: 2,
                diagnostic: Some(_),
                ..
            }
        ),
        "a bad-CRC torn tail with nothing valid after it must recover, got {outcome:?}"
    );
}

#[test]
fn torn_tail_that_drops_an_anchored_record_is_truncation_not_verified() {
    // DEFENCE IN DEPTH: corrupt the FINAL record so framing recovers a torn tail and
    // drops it — but that record WAS anchored (anchor count = N). The framing layer
    // alone would call the surviving N-1 prefix a clean torn-tail recovery; the
    // ANCHOR backstop must override that to TruncationDetected (the dropped record is
    // still counted by the trusted head). Proves a torn-tail recovery is benign ONLY
    // when it matches the anchor.
    let dir = scratch("torn-drops-anchored");
    make_store(&dir, 4); // anchor.count == 4
    let log = dir.join(LOG_FILE);
    let mut bytes = fs::read(&log).unwrap();
    // Corrupt the LAST record's CRC so it fails to frame, and there is nothing valid
    // after it → framing classifies it as a torn final record (dropped → prefix 3).
    let last_start = nth_record_end(&bytes, 3); // start of the 4th (final) record
    let total = bytes.len();
    bytes[total - 1] ^= 0xFF; // flip the final CRC byte of the last record
    let _ = last_start;
    fs::write(&log, &bytes).unwrap();

    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::TruncationDetected { on_disk: 3, anchored: 4 }),
        "a torn tail that drops an ANCHORED record must be Truncation, not Verified, got {outcome:?}"
    );
    assert!(
        handle.is_none(),
        "no appendable handle when the anchored head is missing"
    );
}

#[test]
fn determinism_identical_bytes_for_identical_inputs() {
    // Same inputs + same fixed clock + same key → byte-identical log AND anchor.
    let dir_a = scratch("determinism-a");
    let dir_b = scratch("determinism-b");
    make_store(&dir_a, 4);
    make_store(&dir_b, 4);
    assert_eq!(
        fs::read(dir_a.join(LOG_FILE)).unwrap(),
        fs::read(dir_b.join(LOG_FILE)).unwrap(),
        "log bytes must be identical for identical inputs"
    );
    assert_eq!(
        fs::read(dir_a.join(ANCHOR_FILE)).unwrap(),
        fs::read(dir_b.join(ANCHOR_FILE)).unwrap(),
        "anchor bytes must be identical for identical inputs"
    );
}

#[test]
fn create_refuses_to_clobber_an_existing_log() {
    let dir = scratch("no-clobber");
    make_store(&dir, 1);
    // A second create on the same dir must fail (never silently erase the chain).
    let res = DurableAudit::create_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        res.is_err(),
        "create must refuse to overwrite an existing audit.log"
    );
}

#[test]
fn fresh_directory_with_no_files_is_not_openable() {
    // Opening a dir that was never `create`d (no log, no anchor) must NOT silently
    // succeed — there is nothing to open.
    let dir = scratch("never-created");
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::ErasureDetected),
        "got {outcome:?}"
    );
    assert!(handle.is_none());
}

#[test]
fn missing_anchor_with_present_log_is_anchor_mismatch() {
    // The trusted head reference is gone → we cannot prove non-truncation.
    let dir = scratch("no-anchor");
    make_store(&dir, 3);
    fs::remove_file(dir.join(ANCHOR_FILE)).unwrap();
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::AnchorMismatch),
        "got {outcome:?}"
    );
    assert!(handle.is_none());
}

/// Walk the on-disk records and return the byte offset at the END of the `n`th
/// record (n=1 → end of the first record, i.e. start of the second). Used by the
/// truncation/corruption tests to cut at a clean record boundary. Mirrors the
/// framing in `format.rs` (len prefix + body + 32 hash + 4 crc).
fn nth_record_end(bytes: &[u8], n: usize) -> usize {
    let mut pos = format::HEADER_LEN;
    for _ in 0..n {
        let body_len =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4 + body_len + 32 + 4;
    }
    pos
}

/// #14: a staged OVERSIZE file is refused (IoError) BEFORE its bytes are read, so a
/// hostile multi-GB `audit.log` cannot OOM the open path. We use a SPARSE file
/// (`set_len` past the cap) so the test costs no real disk; `read_file_opt`
/// size-checks via metadata and refuses, and `open` surfaces that as `IoError` with
/// no appendable handle (fail-closed).
#[test]
fn oversize_log_is_refused_before_read() {
    use std::io::Write;
    let dir = scratch("oversize-log");
    make_store(&dir, 2); // a valid store first, then bloat the log file

    // read_file_opt refuses an over-cap file directly.
    let big = dir.join("big.sparse");
    {
        let f = fs::File::create(&big).expect("create sparse");
        f.set_len(MAX_AUDIT_FILE_BYTES + 1)
            .expect("set_len past cap");
    }
    let err = read_file_opt(&big).expect_err("an over-cap file must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err:?}");

    // A file AT the cap is allowed (boundary): create one exactly at the cap is too
    // costly even sparse on some FS, so just prove an ordinary small file still reads.
    let small = dir.join("small.bin");
    {
        let mut f = fs::File::create(&small).expect("create small");
        f.write_all(b"hello").unwrap();
    }
    let ok = read_file_opt(&small)
        .expect("small file reads")
        .expect("present");
    assert_eq!(ok, b"hello");

    // End-to-end: bloat the real LOG_FILE past the cap and confirm open fail-closes
    // to IoError with NO appendable handle.
    let log = dir.join(LOG_FILE);
    {
        let f = OpenOptions::new().write(true).open(&log).expect("open log");
        f.set_len(MAX_AUDIT_FILE_BYTES + 1)
            .expect("bloat log past cap");
    }
    let (outcome, handle) = DurableAudit::open_with_clock(&dir, KEY, FixedClock::new(TS));
    assert!(
        matches!(outcome, OpenOutcome::IoError(_)),
        "got {outcome:?}"
    );
    assert!(
        handle.is_none(),
        "a refused-read open must not yield an appendable handle"
    );
}
