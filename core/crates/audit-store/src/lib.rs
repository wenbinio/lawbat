// SPDX-License-Identifier: AGPL-3.0-or-later
//! # audit-store — durable, tamper-evident audit backend (persistence gate, inc 0+1)
//!
//! A [`DurableAudit`] persists the HMAC-SHA-256 keyed, hash-chained audit log to
//! disk and ANCHORS its head (count + head hash) in a separate file, so the chain's
//! two head-relative blind spots — total erasure and tail truncation — become
//! detectable at open time. It implements [`runtime::Audit`], so a `Core` can use it
//! exactly where it uses [`runtime::InMemoryAudit`].
//!
//! ## Where this sits relative to `runtime`
//!
//! `runtime` is the MINIMAL trusted core: std-only + pure-compute `sha2`/`hmac`, with
//! NO filesystem and NO RNG (a CI guard enforces no RNG reaches it). The durable
//! backend's filesystem I/O lives HERE so `runtime` stays minimal. The crate has NO
//! RNG of its own either.
//!
//! ## One canonical MAC, two backends
//!
//! Both backends compute MACs via the SAME free function [`runtime::compute_entry_hash`]
//! (extracted in inc 0) and verify via [`runtime::verify_entries`]. The on-disk record
//! body reuses the MAC's exact length-prefixed field encoding (see [`format`]), so the
//! bytes stored ARE the bytes MAC'd — there is no second serializer to drift. The
//! round-trip test asserts a `DurableAudit` head equals an `InMemoryAudit` head over
//! the same entries+key, proving the one-form invariant.
//!
//! ## Key custody is still DEFERRED (this is inc 1)
//!
//! The key is INJECTED as `&[u8]` — there is NO platform key custody here yet (that
//! is increment 2: an OS-protected secret + an OS-mirrored anchor). The on-disk
//! header stores `SHA-256(key)` as a KEY-ID — it identifies WHICH key the log was
//! written under (so a wrong-key open is detected) and NEVER the key itself.
//!
//! ## Fail-closed on every seam
//!
//! - [`DurableAudit::record`] does serialize → one `write_all` → `fsync` the log →
//!   advance + `fsync` the anchor. ANY fs/fsync error returns `Err`; the `Audit`
//!   trait is fallible and the mediators expect check→log→act, so a log that cannot
//!   be durably written aborts the brokered op rather than proceeding unlogged.
//! - [`open`] never silently returns "ok": it returns an [`OpenOutcome`] enum that
//!   names erasure / truncation / chain-break / wrong-key / anchor-mismatch.
//! - A store that did NOT open `Verified` REFUSES to append (appending onto a
//!   tampered/truncated log would destroy the evidence) — see [`DurableAudit`].

pub mod anchor;
pub mod format;

use anchor::{Anchor, AnchorError};
use format::{FormatError, ReadDiagnostic};
use runtime::{
    Audit, AuditEntry, AuditHash, Capability, Clock, CoreError, CoreResult, SystemClock,
};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Standard log/anchor file names within a store directory.
pub const LOG_FILE: &str = "audit.log";
pub const ANCHOR_FILE: &str = "audit.anchor";

/// SHA-256 of the key — the on-disk KEY-ID. Identifies which key a log/anchor was
/// written under (so a wrong-key open is caught) and NEVER the key itself.
pub fn key_id(key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.finalize().into()
}

/// The result of opening a durable audit store. NEVER a bare bool — every failure
/// mode is named so the caller (and a human operator) sees exactly what went wrong.
#[derive(Debug)]
pub enum OpenOutcome {
    /// Log head == anchor head == the chain verifies from genesis. The store is
    /// trustworthy and may be appended to. Carries the verified entry count, the
    /// head hash, and any benign recovery note (a dropped torn-final record).
    Verified {
        count: u64,
        head: AuditHash,
        /// `Some` if a torn final record (crash mid-append) was recovered. The
        /// remaining log is clean AND matches the anchor's prior state.
        diagnostic: Option<ReadDiagnostic>,
    },
    /// The anchor says there were entries (count > 0) but the log is missing or
    /// empty — the log was erased. (Erasure with a genesis anchor, i.e. a never-used
    /// store, is NOT this; that opens `Verified` with count 0.)
    ErasureDetected,
    /// The replayed log holds FEWER entries than the anchor expects (records were
    /// dropped from the tail), or the head at the anchored count disagrees. Carries
    /// both counts so the operator sees the gap.
    TruncationDetected { on_disk: u64, anchored: u64 },
    /// `verify_entries` fails: a record was edited/reordered mid-stream, or a
    /// mid-stream record is corrupt. The keyed chain no longer links.
    ChainBroken,
    /// The log/anchor header key-id != SHA-256(the supplied key): the store was
    /// written under a different key.
    WrongKey,
    /// The anchor's MAC does not verify, the anchor is malformed, or the anchor
    /// disagrees with a clean, chain-valid log (count/head mismatch that is NOT a
    /// pure tail truncation).
    AnchorMismatch,
    /// A low-level I/O error reading the store (not a tamper signal). Carries a
    /// diagnostic string; fail-closed — the caller must not treat this as openable.
    IoError(String),
}

/// A durable, anchored, tamper-evident [`Audit`] backend.
///
/// Construct via [`DurableAudit::open`] (or, for the first-ever use of an empty
/// directory, [`DurableAudit::create`]). A store only becomes APPENDABLE if it
/// opened `Verified`; a non-clean open yields the diagnostic [`OpenOutcome`] and NO
/// appendable handle, so an operator cannot accidentally append onto tampered
/// evidence (that would overwrite the truncation/erasure signal). To deliberately
/// start over, archive/move the old files and [`create`](DurableAudit::create) fresh.
pub struct DurableAudit {
    /// The open, append-positioned log file handle (kept open for the store's life).
    log: File,
    /// Path to the anchor file (rewritten in full on each advance — it is fixed-size).
    anchor_path: PathBuf,
    /// The injected HMAC key. NOT logged / NOT Debug-printed.
    key: Vec<u8>,
    /// Precomputed key-id (SHA-256(key)) for the headers.
    key_id: [u8; 32],
    /// The full in-memory chain (the durable store keeps the chain to recompute the
    /// head and to satisfy `verify_chain`). Loaded on open, appended on record.
    entries: Vec<AuditEntry>,
    /// Injected clock for entry timestamps (production: system clock; tests: fixed).
    clock: Box<dyn Clock>,
    /// The current anchored head (advanced after each durable append).
    anchor: Anchor,
}

impl std::fmt::Debug for DurableAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The KEY is deliberately never printed. The clock is not Debug.
        f.debug_struct("DurableAudit")
            .field("anchor_path", &self.anchor_path)
            .field("entries", &self.entries.len())
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}

impl DurableAudit {
    /// CREATE a fresh, empty durable store in `dir` (must not already contain a log)
    /// keyed by `key`, using the system clock. Writes the log header + a genesis
    /// anchor and fsyncs both. Errors if a log already exists (use [`open`] to
    /// resume, or archive the old files first).
    pub fn create(dir: impl AsRef<Path>, key: impl Into<Vec<u8>>) -> CoreResult<Self> {
        Self::create_with_clock(dir, key, SystemClock::new())
    }

    /// CREATE with an explicit clock (tests pass a `FixedClock` for deterministic
    /// timestamps → deterministic on-disk bytes).
    pub fn create_with_clock<C: Clock + 'static>(
        dir: impl AsRef<Path>,
        key: impl Into<Vec<u8>>,
        clock: C,
    ) -> CoreResult<Self> {
        let dir = dir.as_ref();
        let key = key.into();
        let kid = key_id(&key);
        let log_path = dir.join(LOG_FILE);
        let anchor_path = dir.join(ANCHOR_FILE);

        // `create_new` fails if the log already exists — never silently clobber an
        // existing chain (that would be erasure-by-recreate).
        let mut log = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&log_path)
            .map_err(|e| backend(format!("create audit.log: {e}")))?;
        let header = format::encode_header(&kid);
        log.write_all(&header)
            .map_err(|e| backend(format!("write header: {e}")))?;
        log.sync_all()
            .map_err(|e| backend(format!("fsync log header: {e}")))?;

        let mut me = DurableAudit {
            log,
            anchor_path,
            key,
            key_id: kid,
            entries: Vec::new(),
            clock: Box::new(clock),
            anchor: Anchor::genesis(),
        };
        // Write the genesis anchor so an open-after-create sees a consistent pair.
        me.write_anchor()?;
        Ok(me)
    }

    /// OPEN an existing durable store in `dir` under `key`, using the system clock.
    /// Returns the diagnostic [`OpenOutcome`]; the appendable handle is produced ONLY
    /// when the outcome is `Verified` (via [`OpenOutcome::into_audit`] would couple
    /// the two — instead the handle is returned alongside). See [`open_with_clock`].
    pub fn open(dir: impl AsRef<Path>, key: impl Into<Vec<u8>>) -> (OpenOutcome, Option<Self>) {
        Self::open_with_clock(dir, key, SystemClock::new())
    }

    /// OPEN with an explicit clock. Returns the [`OpenOutcome`] AND, only when that
    /// outcome is `Verified`, an appendable [`DurableAudit`] handle. A non-`Verified`
    /// outcome yields `None` for the handle, so the caller CANNOT append onto a
    /// tampered/truncated/erased log (the refuse-after-non-clean-open invariant).
    pub fn open_with_clock<C: Clock + 'static>(
        dir: impl AsRef<Path>,
        key: impl Into<Vec<u8>>,
        clock: C,
    ) -> (OpenOutcome, Option<Self>) {
        let dir = dir.as_ref();
        let key = key.into();
        let kid = key_id(&key);
        let log_path = dir.join(LOG_FILE);
        let anchor_path = dir.join(ANCHOR_FILE);

        // 1) Load the anchor (it is the trusted head reference). A missing anchor on
        //    a missing log = a never-created store (treat as genesis); a missing
        //    anchor with a present log is an AnchorMismatch (the head reference is
        //    gone). We read the anchor first so erasure (anchor>0 but log gone) and
        //    wrong-key are decidable.
        let anchor_bytes = match read_file_opt(&anchor_path) {
            Ok(b) => b,
            Err(e) => return (OpenOutcome::IoError(format!("read anchor: {e}")), None),
        };
        let log_bytes = match read_file_opt(&log_path) {
            Ok(b) => b,
            Err(e) => return (OpenOutcome::IoError(format!("read log: {e}")), None),
        };

        match (anchor_bytes, log_bytes) {
            // Neither file exists → nothing to open. Caller should `create`.
            (None, None) => (OpenOutcome::ErasureDetected, None),
            // Anchor exists, log gone. The log file (with its header) is ALWAYS
            // written by `create`, so a missing log is never normal:
            //   - anchor count > 0  → the recorded entries were deleted: ERASURE.
            //   - anchor count == 0 → the header is gone but the anchor is genesis:
            //     a corrupt half-state, not "erased evidence" (there was none) →
            //     AnchorMismatch. Wrong key / malformed anchor are decided first.
            (Some(ab), None) => match anchor::verify_anchor(&ab, &key, &kid) {
                Ok(a) if a.count > 0 => (OpenOutcome::ErasureDetected, None),
                Ok(_) => (OpenOutcome::AnchorMismatch, None),
                Err(AnchorError::WrongKey) => (OpenOutcome::WrongKey, None),
                Err(_) => (OpenOutcome::AnchorMismatch, None),
            },
            // Log exists, anchor gone → the trusted head reference is missing. We
            // cannot prove non-truncation/erasure → AnchorMismatch (fail-closed).
            (None, Some(_lb)) => (OpenOutcome::AnchorMismatch, None),
            // Both present → the full verification path.
            (Some(ab), Some(lb)) => Self::verify_pair(dir, &anchor_path, key, kid, clock, &ab, &lb),
        }
    }

    /// The full both-files-present verification: header key-id → anchor MAC → replay
    /// log framing → chain verify → reconcile log vs anchor. Returns the outcome and
    /// (only when Verified) the appendable handle.
    #[allow(clippy::too_many_arguments)]
    fn verify_pair<C: Clock + 'static>(
        dir: &Path,
        anchor_path: &Path,
        key: Vec<u8>,
        kid: [u8; 32],
        clock: C,
        anchor_bytes: &[u8],
        log_bytes: &[u8],
    ) -> (OpenOutcome, Option<Self>) {
        // (a) Log header: validate magic/version + key-id. A wrong key-id is the
        //     clearest WrongKey signal.
        let header_kid = match format::read_header(log_bytes) {
            Ok(k) => k,
            Err(FormatError::BadHeader) => return (OpenOutcome::AnchorMismatch, None),
            Err(_) => return (OpenOutcome::ChainBroken, None),
        };
        if header_kid != kid {
            return (OpenOutcome::WrongKey, None);
        }

        // (b) Anchor: verify its MAC under the key (and that its key-id matches).
        let anchor = match anchor::verify_anchor(anchor_bytes, &key, &kid) {
            Ok(a) => a,
            Err(AnchorError::WrongKey) => return (OpenOutcome::WrongKey, None),
            Err(AnchorError::BadMac) | Err(AnchorError::Malformed) => {
                return (OpenOutcome::AnchorMismatch, None)
            }
        };

        // (c) Replay the log records (framing level). A mid-stream corrupt record is
        //     ChainBroken; a torn FINAL record is recovered with a diagnostic.
        let read = match format::read_log(log_bytes) {
            Ok(r) => r,
            Err(FormatError::CorruptRecord { .. }) => return (OpenOutcome::ChainBroken, None),
            Err(FormatError::BadHeader) => return (OpenOutcome::AnchorMismatch, None),
        };
        let entries = read.entries;
        let diagnostic = read.diagnostic;

        // (d) Verify the keyed chain over the (clean-prefix) entries.
        if !runtime::verify_entries(&key, &entries) {
            return (OpenOutcome::ChainBroken, None);
        }

        // (e) Reconcile the replayed log against the anchor.
        let on_disk = entries.len() as u64;
        let head = entries.last().map(|e| e.hash).unwrap_or(AuditHash::GENESIS);

        // Erasure: the anchor expected entries but the (clean) log has none.
        if anchor.count > 0 && on_disk == 0 {
            return (OpenOutcome::ErasureDetected, None);
        }
        // Truncation, two shapes (spec): the log is SHORTER than the anchor expects,
        // OR — even at/above the anchored count — the record AT the anchored position
        // does not carry the anchored head hash. The latter means the anchored
        // entry itself was dropped/changed and a different one now sits at that
        // index: records were removed from at/before the anchored head. Both are
        // tail-loss relative to the trusted anchor → TruncationDetected.
        let anchored_pos_head = if anchor.count == 0 {
            AuditHash::GENESIS
        } else {
            // anchor.count <= on_disk here (the < case returned above), so index is
            // in range. Compare the chain-valid log's hash AT the anchored count.
            match entries.get((anchor.count - 1) as usize) {
                Some(e) => e.hash,
                None => AuditHash::GENESIS,
            }
        };
        if on_disk < anchor.count || !anchored_pos_head.ct_eq(&anchor.head_hash) {
            return (
                OpenOutcome::TruncationDetected {
                    on_disk,
                    anchored: anchor.count,
                },
                None,
            );
        }
        // The clean log must end EXACTLY at the anchored head (equal count + the head
        // already matched via `anchored_pos_head` at this point only when counts are
        // equal). A LONGER log than the anchor — extra chain-valid records past the
        // anchored head — is the anchor disagreeing with the log. The anchor is the
        // source of truth for "how far the durable head got" (it is advanced+fsynced
        // AFTER each record), so an over-long log is fail-closed AnchorMismatch:
        // we never silently trust un-anchored tail records (preserves the evidence;
        // an operator investigates rather than the store auto-accepting). NOTE: this
        // also means a crash BETWEEN the record-fsync and the anchor-fsync (log = N+1,
        // anchor = N) surfaces as AnchorMismatch — a deliberate fail-closed choice
        // for inc 1 (the spec's torn-tail recovery covers overrun/CRC-fail partial
        // WRITES, not a fully-written-but-unanchored record). Increment 2's OS-mirror
        // can revisit promoting a one-behind anchor.
        if on_disk != anchor.count || !head.ct_eq(&anchor.head_hash) {
            return (OpenOutcome::AnchorMismatch, None);
        }

        // VERIFIED. Re-open the log for append at EOF and hand back the handle.
        let log = match OpenOptions::new()
            .read(true)
            .append(true)
            .open(dir.join(LOG_FILE))
        {
            Ok(f) => f,
            Err(e) => {
                return (
                    OpenOutcome::IoError(format!("reopen log for append: {e}")),
                    None,
                )
            }
        };
        let me = DurableAudit {
            log,
            anchor_path: anchor_path.to_path_buf(),
            key,
            key_id: kid,
            entries,
            clock: Box::new(clock),
            anchor,
        };
        (
            OpenOutcome::Verified {
                count: on_disk,
                head,
                diagnostic,
            },
            Some(me),
        )
    }

    /// Read-only accessor for the verified chain (for a verify-on-open caller or a
    /// test). DELIBERATELY mirrors `InMemoryAudit::entries` (inherent, NOT on the
    /// `Audit` trait) so a module's generic `&dyn Audit` still cannot read the raw
    /// chain — the same confidentiality invariant.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// The current head hash (genesis if empty).
    pub fn head_hash(&self) -> AuditHash {
        self.entries
            .last()
            .map(|e| e.hash)
            .unwrap_or(AuditHash::GENESIS)
    }

    /// Rewrite the anchor file in full (it is fixed-size) for the current head, then
    /// fsync it. Called after each durable log append and on create.
    fn write_anchor(&mut self) -> CoreResult<()> {
        let bytes = anchor::encode_anchor(&self.key, &self.key_id, &self.anchor)
            .ok_or_else(|| backend("compute anchor MAC".to_string()))?;
        // Write to a temp sibling then rename, so a crash mid-write can never leave a
        // PARTIAL anchor (rename is atomic on the same dir); the old anchor stays
        // valid until the new one is fully durable.
        let tmp = self.anchor_path.with_extension("anchor.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| backend(format!("create anchor tmp: {e}")))?;
            f.write_all(&bytes)
                .map_err(|e| backend(format!("write anchor tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| backend(format!("fsync anchor tmp: {e}")))?;
        }
        std::fs::rename(&tmp, &self.anchor_path)
            .map_err(|e| backend(format!("rename anchor: {e}")))?;
        Ok(())
    }
}

impl Audit for DurableAudit {
    fn record(
        &mut self,
        acting_user: &str,
        matter: &str,
        module: &str,
        capability: Capability,
        detail: &str,
    ) -> CoreResult<AuditHash> {
        let prev = self.head_hash();
        let seq = u64::try_from(self.entries.len())
            .map_err(|_| backend("audit entry count exceeds u64".to_string()))?;
        let timestamp = self.clock.now_millis();
        let mut entry = AuditEntry {
            seq,
            timestamp,
            acting_user: acting_user.to_string(),
            matter: matter.to_string(),
            module: module.to_string(),
            capability,
            detail: detail.to_string(),
            hash: AuditHash::GENESIS,
        };
        // ONE canonical MAC (shared with InMemoryAudit). Fail-closed: a MAC we
        // cannot compute aborts the brokered op without writing anything.
        entry.hash = runtime::compute_entry_hash(&self.key, prev, &entry)?;
        let head = entry.hash;

        // Serialize → single write_all → fsync the LOG before touching state, so a
        // returned Ok means the record is durable.
        let framed = format::encode_record(&entry);
        self.log
            .write_all(&framed)
            .map_err(|e| backend(format!("append record: {e}")))?;
        self.log
            .sync_all()
            .map_err(|e| backend(format!("fsync log: {e}")))?;

        // Advance the anchor (count+head) and fsync it. Only AFTER both fsyncs do we
        // mutate the in-memory chain, so a failure leaves the in-memory state
        // consistent with what is durable (the record was appended+fsynced; the
        // anchor advance failing means the next open sees a torn tail at worst).
        let prev_anchor = self.anchor;
        self.anchor = Anchor {
            count: seq + 1,
            head_hash: head,
        };
        if let Err(e) = self.write_anchor() {
            // Roll the in-memory anchor back so it matches the last durable anchor;
            // the appended record then looks like a torn-tail at the next open
            // (recoverable), never a silent count/head divergence.
            self.anchor = prev_anchor;
            return Err(e);
        }

        self.entries.push(entry);
        Ok(head)
    }

    fn verify_chain(&self) -> bool {
        // Same ONE rule as the in-memory backend.
        runtime::verify_entries(&self.key, &self.entries)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Helper: wrap a string in `CoreError::Backend`.
fn backend(msg: String) -> CoreError {
    CoreError::Backend(msg)
}

/// Hard ceiling on a whole-file read at open time (#14). `open` reads the log AND the
/// anchor fully into memory before verifying. An attacker who can drop files in the
/// store dir could otherwise stage a multi-GB `audit.log` (or anchor) and OOM the
/// process on open — a denial of the very integrity check. 512 MiB is FAR above any
/// real audit log (each record is a few short strings, and the chain is verified
/// record-by-record after the read) yet bounds the allocation; a larger file is refused
/// as an IoError (fail-closed: a non-`Verified` open yields no appendable handle).
pub const MAX_AUDIT_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Read a whole file, returning `Ok(None)` if it does not exist (so the open path
/// can distinguish "absent" from "present-but-unreadable"). An empty file returns
/// `Ok(Some(vec![]))`. REFUSES (an `InvalidData` error) a file whose size exceeds
/// [`MAX_AUDIT_FILE_BYTES`] BEFORE reading its bytes, so a staged huge file cannot OOM
/// the open path (#14).
fn read_file_opt(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(mut f) => {
            // Size-check from metadata BEFORE read_to_end so we never allocate the
            // whole (possibly hostile) file. A metadata error is surfaced (fail-closed).
            let len = f.metadata()?.len();
            if len > MAX_AUDIT_FILE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "audit file too large ({len} bytes > {MAX_AUDIT_FILE_BYTES} cap) — refusing to read"
                    ),
                ));
            }
            // Pre-size from the (now-bounded) length to avoid reallocation churn; the
            // cap above guarantees this cannot request an unbounded allocation.
            let mut buf = Vec::with_capacity(len as usize);
            f.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
