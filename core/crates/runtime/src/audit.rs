// SPDX-License-Identifier: AGPL-3.0-or-later
//! Append-only, **HMAC-SHA-256 keyed** hash-chained audit log (spec §2.7, §7).
//!
//! Core-mediated, never self-reported: the core logs at the chokepoint. Modules
//! may *add* context (`audit.note`) but cannot suppress or forge core events.
//! Entries are chained with a KEYED MAC — each entry's hash is
//! `HMAC-SHA-256(key, prev_hash || this entry's fields)`, so it folds in the
//! previous entry's hash (and the timestamp) AND a secret key. A naive in-place
//! edit that does not recompute every downstream MAC breaks the chain and is
//! detectable by [`Audit::verify_chain`].
//!
//! ## What this KEYED chain DOES and DOES NOT guarantee (read before trusting it)
//!
//! The MAC is **HMAC-SHA-256** (RustCrypto `hmac` over `sha2`), keyed and
//! collision-resistant, and the serialization fed to it is deterministic (a
//! fixed, length-prefixed canonical form), so with the injected [`Clock`] and a
//! fixed key the digests are reproducible under test. Keying the chain is the
//! authenticity foundation: it closes the rewrite-and-recompute hole a keyless
//! SHA-256 chain left open. Precisely, this chain:
//!
//! - **Detects** naive in-place edits (mutating a field without recomputing that
//!   entry's MAC and every later MAC), and proves the log's *internal
//!   consistency* GIVEN a trusted head reference (a head-hash + entry count you
//!   obtained from outside this log and trust).
//! - **Defeats the rewrite-and-recompute forgery** that a keyless chain could
//!   not: an attacker who can rewrite ALL entries but does **NOT** hold the key
//!   cannot produce a fresh, internally-consistent chain — every recomputed MAC
//!   needs the secret key, so `verify_chain` (which recomputes under the real
//!   key) rejects the forgery. This holds **only while the key is secret and
//!   held separately** from the entries the attacker can write.
//! - Does **NOT** detect **total erasure**: an EMPTY log verifies `true`
//!   (genesis with no entries is internally consistent). Nor does it detect
//!   **tail truncation** — dropping the last N entries leaves a shorter chain
//!   that still verifies internally. Catching those still requires **external
//!   anchoring** of [`InMemoryAudit::head_hash`] + [`Audit::len`] to a trusted
//!   store the attacker cannot rewrite (so erasure/truncation surface as a
//!   head/count mismatch).
//!
//! ### Key custody is the load-bearing assumption (current limitation)
//!
//! The HMAC's real value is realized only when the log is persisted to a store
//! the attacker can *write* but whose key they *cannot read*. In the current
//! **in-memory, single-process** model the key co-locates with the entries: an
//! attacker who can read the process memory reads the key and can still forge.
//! Worse, [`InMemoryAudit::new`] / [`InMemoryAudit::with_clock`] use a FIXED,
//! compiled-in **DEV placeholder key** ([`DEV_AUDIT_KEY`]) — public in this open
//! repo, so it is *no protection at all* on its own. Production MUST inject a
//! real secret via [`InMemoryAudit::with_clock_and_key`] / [`InMemoryAudit::with_key`],
//! holding that key separately from the audit store. So this module is now the
//! authenticity *foundation* (the chain is keyed); full, compliance-grade
//! tamper-evidence additionally needs: (a) a real secret key under separate
//! custody — NOT the dev placeholder — so the log writer cannot silently
//! re-forge; (b) external anchoring of head-hash + count; and (c) append-only /
//! WORM persistence. Designing the anchored/persistent backend is a separate,
//! deliberate step.

use crate::capability::Capability;
use crate::clock::Clock;
use crate::error::{CoreError, CoreResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA-256 instance type used to key the audit chain.
type HmacSha256 = Hmac<Sha256>;

/// FIXED, compiled-in **development placeholder** audit key.
///
/// This exists ONLY so the keyless-era constructors ([`InMemoryAudit::new`] and
/// [`InMemoryAudit::with_clock`]) keep working and so unit tests using a
/// `FixedClock` stay fully deterministic without needing an RNG. Because it is a
/// constant compiled into this **public** repository, it is **NOT a secret and
/// NOT real protection**: anyone reading the source knows it, so a chain keyed
/// with it can be re-forged by anyone.
///
/// PRODUCTION MUST inject a real secret key via
/// [`InMemoryAudit::with_clock_and_key`] / [`InMemoryAudit::with_key`], generated
/// and stored OUTSIDE this binary and held separately from the audit log itself
/// (see the module-level "Key custody" note). Treat any chain still keyed with
/// `DEV_AUDIT_KEY` as unauthenticated.
pub const DEV_AUDIT_KEY: &[u8] = b"lawdataman-DEV-PLACEHOLDER-audit-key-NOT-A-SECRET";

/// A 32-byte HMAC-SHA-256 tag used as a per-entry / chain-head hash. Newtype so
/// the audit hash is its own type (not just `[u8; 32]`) and renders as lowercase
/// hex for display. HMAC-SHA-256 is 32 bytes, so the width is unchanged from the
/// former keyless SHA-256 chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditHash(pub [u8; 32]);

impl AuditHash {
    /// The genesis prev-hash: all-zero 32 bytes. Chains the first entry.
    pub const GENESIS: AuditHash = AuditHash([0u8; 32]);

    /// The raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering (64 chars) for display / logs.
    pub fn to_hex(&self) -> String {
        // SECURITY (C-2/L-1): no panic in the crypto/audit path. `write!(.. "{:02x}")`
        // into a `String` is infallible — the `fmt::Write` impl for `String` never
        // errors and `{:02x}` can never panic on any byte — unlike the former
        // `char::from_digit(..).unwrap()`, which (although the masked nibble was
        // always < 16) put two `.unwrap()`s on the audit hot path. Same lowercase
        // two-hex-digits-per-byte output, no panic site. (The `let _ =` discards the
        // always-`Ok` result without an `.unwrap()` — so still no panic site.)
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Constant-time equality against another hash.
    ///
    /// The chain verify + anchor reconciliation compare MAC OUTPUTS; the derived
    /// `PartialEq` on `[u8; 32]` is a variable-time, early-exit `==` that leaks (via
    /// timing) how many leading bytes of a supplied/forged hash matched the keyed
    /// recompute. Low-severity here (an OFFLINE, local, batch open-time check over
    /// public MAC outputs — no online oracle), but this makes the audit subsystem
    /// match the constant-time posture the anchor MAC verify already uses
    /// (`hmac::Mac::verify_slice`). Branch-free XOR-fold over all 32 bytes; the final
    /// `== 0` is the ONLY comparison and is independent of input contents/position
    /// (the same shape `subtle` uses internally — but no new dep in the trusted core).
    pub fn ct_eq(&self, other: &AuditHash) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (*a ^ *b))
            == 0
    }
}

impl std::fmt::Display for AuditHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// What the audit log captures (spec §7): acting user, matter, module+version,
/// capability invoked, optional detail (e.g. data class / egress destination),
/// a monotonic sequence, and a per-call timestamp. The timestamp comes from an
/// INJECTED [`Clock`] (production: wall time; tests: a fixed clock) so it is
/// recorded AND folded into the hash — altering a timestamp after the fact
/// breaks `verify_chain` — while tests stay deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    /// Milliseconds since UNIX epoch, stamped from the injected clock at record
    /// time. Folded into the per-entry hash (tamper-evident).
    pub timestamp: u64,
    pub acting_user: String,
    pub matter: String,
    pub module: String,
    pub capability: Capability,
    pub detail: String,
    /// `HMAC-SHA-256(key, prev_hash || this entry's fields)`. Keys + chains the
    /// log: recomputing it requires the secret key, not just the field bytes.
    pub hash: AuditHash,
}

/// Trait seam for the audit sink (spec §2.7). Append-only by contract: there is
/// no `remove` / `truncate` on this interface.
///
/// CONFIDENTIALITY INVARIANT: reading the recorded entries is DELIBERATELY *not* on
/// this trait — `entries()` is an INHERENT method on [`InMemoryAudit`]. A module
/// only ever holds a generic `A: Audit` (via [`crate::Core::audit`]), so keeping
/// `entries()` off the trait means a module cannot read the raw chain (all matters /
/// users / cleartext `detail`) and bypass the entitlement-filtered, cleartext-free
/// [`crate::Core::matter_read_activity`] projection. This must NOT compile:
/// ```compile_fail
/// fn cannot_read_raw_chain(a: &dyn runtime::Audit) {
///     let _ = a.entries(); // error: no method `entries` on `dyn Audit`
/// }
/// ```
pub trait Audit {
    /// Record a brokered call at the chokepoint. Returns the new head hash on
    /// success.
    ///
    /// **Fail-closed:** returns `Err` if the entry could not be recorded. The
    /// mediator propagates that error so a brokered op never proceeds *unlogged*
    /// — an audit failure aborts the action rather than letting it slip through
    /// without a chokepoint entry.
    fn record(
        &mut self,
        acting_user: &str,
        matter: &str,
        module: &str,
        capability: Capability,
        detail: &str,
    ) -> CoreResult<AuditHash>;

    /// Verify the keyed (HMAC-SHA-256) chain links contiguously from genesis to
    /// head. `true` means the log is INTERNALLY consistent under the configured
    /// key: each entry's `seq` is its index, and each entry's MAC — recomputed
    /// here under the SAME key the log was recorded with — folds in the prior
    /// entry's hash.
    ///
    /// Because the recompute is keyed, an attacker who rewrote entries but lacks
    /// the key cannot make this return `true`: the recomputed MACs will not match
    /// the forged tags. (A chain recorded under key A also fails to verify if it
    /// is checked under a different key B — the key is load-bearing.)
    ///
    /// INVARIANT / LIMITATION: this verifies by INDEX (`entries[i].seq == i`),
    /// so it requires a COMPLETE log from genesis held in one place. It cannot
    /// validate a persisted, rotated, or partial log (a slice that does not start
    /// at genesis), and — being head-relative — it cannot detect total erasure
    /// (an empty log verifies `true`) or tail truncation on its own. Those
    /// require an EXTERNAL ANCHOR of [`InMemoryAudit::head_hash`] + [`Audit::len`]
    /// (see the module-level docs). `true` here means "internally consistent
    /// under this key given a trusted head", not "provably untampered" — and in
    /// the in-memory model the dev key co-locates with the entries, so the keying
    /// is a foundation, not full protection, until persistence separates the key.
    fn verify_chain(&self) -> bool;

    /// Number of recorded entries.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory, HMAC-SHA-256 keyed hash-chained audit log. The genesis prev-hash
/// is the all-zero 32-byte digest ([`AuditHash::GENESIS`]).
///
/// Holds an injected [`Clock`] used to stamp each entry's `timestamp` at record
/// time. The clock is a boxed trait object so the same concrete `InMemoryAudit`
/// type can carry a real clock in production and a fixed clock under test
/// without changing the `Audit` trait's `record` signature.
///
/// Also holds the **audit key** used to MAC the chain. Constructors that do not
/// take a key use the FIXED [`DEV_AUDIT_KEY`] placeholder (deterministic for
/// tests, but NO real protection — see the type-level / module-level docs);
/// production injects a real secret via [`InMemoryAudit::with_clock_and_key`] or
/// [`InMemoryAudit::with_key`].
pub struct InMemoryAudit {
    // FLAG (#1): this Vec is DELIBERATELY UNBOUNDED BY DEFAULT — do NOT cap /
    // ring-buffer it by DROPPING. The chain is APPEND-ONLY + HMAC hash-chained for
    // tamper-evidence; silently dropping or compacting entries would BREAK
    // `verify_chain` (it verifies by index from genesis) and DESTROY the compliance
    // record. This is the OPPOSITE of the egress sink (egress.rs #2), whose records
    // are inspection-only and so are safely bounded by a ring. The ONLY safe
    // in-memory bound is a fail-CLOSED soft cap that ERRORS (never silently drops) —
    // now available, OPT-IN, via [`InMemoryAudit::with_max_entries`] (`max_entries`
    // below; default `None` = unbounded, preserving this flag's default). It bounds
    // an OOM/DoS in a long-lived process by REFUSING further auditable work once
    // full, not by erasing history. The correct DURABLE answer is still the deferred
    // audit PERSISTENCE / WORM / external-anchoring gate; see `to-read/core.to-fix.md`.
    entries: Vec<AuditEntry>,
    /// OPT-IN fail-closed soft cap on retained entries (#1). `None` = unbounded
    /// (default). `Some(max)` makes [`Audit::record`] return `Err` once `max`
    /// entries are present, so the brokered op aborts (fail-closed) rather than
    /// growing without bound — NEVER drops a recorded entry (that would break the
    /// chain). NOTE: there is intentionally NO drain/persist/reset method on this
    /// in-memory store (the [`Audit`] trait is append-only by design), so once the
    /// cap is hit the chain stays FULL and every subsequent brokered op fails-closed
    /// until the audit is persisted+reset by the DEFERRED persistence layer or the
    /// `Core` is reconstructed. The generous ceiling makes this a last-resort OOM
    /// backstop, not a routine path.
    max_entries: Option<usize>,
    clock: Box<dyn Clock>,
    /// The HMAC key. `compute_hash`/`verify_chain` MAC the chain with this; two
    /// audits with different keys produce different chains over the same inputs.
    key: Vec<u8>,
}

impl std::fmt::Debug for InMemoryAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The clock is not Debug; show only the entries (the auditable state).
        // The audit KEY is deliberately NOT printed — a secret key must never
        // leak into Debug output / logs.
        f.debug_struct("InMemoryAudit")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

// SECURITY (C-1): `Default` is dev-only too — it would otherwise be a silent
// back-door to a dev-key-keyed chain in production. Gated behind the same
// `dev-audit-key` feature (+ `cfg(test)`) as the dev-key constructors it calls.
#[cfg(any(test, feature = "dev-audit-key"))]
impl Default for InMemoryAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAudit {
    /// Production-shaped constructor for the system clock, but keyed with the
    /// FIXED [`DEV_AUDIT_KEY`] placeholder. Real deployments MUST instead call
    /// [`InMemoryAudit::with_clock_and_key`] / [`InMemoryAudit::with_key`] with a
    /// secret key held separately from the log — a chain keyed with the dev
    /// placeholder is NOT authenticated (see the module docs).
    ///
    /// SECURITY (C-1): GATED behind the `dev-audit-key` cargo feature (and
    /// `cfg(test)` for this crate's own unit tests). A pure production build of
    /// `runtime` does NOT compile this constructor, so production cannot SILENTLY
    /// key an audit chain with the public dev placeholder — it must call the
    /// authenticated [`InMemoryAudit::with_key`] path with a real secret. Opting
    /// into the dev key is therefore an explicit, deliberate `dev-audit-key`
    /// feature choice, never an accident. (Residual: full KEY CUSTODY — a real
    /// secret under separate-store custody — remains DEFERRED to the persistence
    /// layer; see the module-level "Key custody" note.)
    #[cfg(any(test, feature = "dev-audit-key"))]
    pub fn new() -> Self {
        Self::with_clock(crate::clock::SystemClock::new())
    }

    /// Construct with an explicit clock, keyed with the FIXED [`DEV_AUDIT_KEY`]
    /// placeholder. Production passes `SystemClock`; tests pass a `FixedClock` so
    /// that — together with the fixed dev key — the timestamp-in-MAC stays
    /// deterministic without needing an RNG. NOT for real authenticity: inject a
    /// secret key via [`InMemoryAudit::with_clock_and_key`].
    ///
    /// SECURITY (C-1): GATED behind the `dev-audit-key` cargo feature (and
    /// `cfg(test)`). See [`InMemoryAudit::new`] for the rationale — a production
    /// build can never reach the dev key without explicitly enabling the feature.
    #[cfg(any(test, feature = "dev-audit-key"))]
    pub fn with_clock<K: Clock + 'static>(clock: K) -> Self {
        Self::with_clock_and_key(clock, DEV_AUDIT_KEY.to_vec())
    }

    /// Construct with the real system clock and an injected secret audit key.
    /// This is the production entry point for an authenticated chain: pass a key
    /// generated and stored OUTSIDE this binary, held separately from the audit
    /// log (see the module-level "Key custody" note).
    pub fn with_key(key: impl Into<Vec<u8>>) -> Self {
        Self::with_clock_and_key(crate::clock::SystemClock::new(), key)
    }

    /// Construct with both an explicit clock AND an injected audit key. The key
    /// keys the HMAC-SHA-256 chain; with a fixed clock + fixed key the digests
    /// are deterministic (no RNG involved). HMAC accepts a key of any length, so
    /// no length precondition is imposed here.
    pub fn with_clock_and_key<K: Clock + 'static>(clock: K, key: impl Into<Vec<u8>>) -> Self {
        Self {
            entries: Vec::new(),
            max_entries: None,
            clock: Box::new(clock),
            key: key.into(),
        }
    }

    /// OPT-IN fail-closed soft cap on the entry count (#1). Builder-style so it
    /// composes with the key/clock constructors. Once `max` entries are present,
    /// [`Audit::record`] returns `Err` (the brokered op then aborts fail-closed)
    /// instead of appending — it NEVER drops an already-recorded entry (that would
    /// break `verify_chain`). `max` is clamped to a minimum of 1. Default (no call)
    /// is unbounded, preserving the documented default. This bounds an in-memory
    /// OOM/DoS; durable retention is the deferred persistence gate.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = Some(max.max(1));
        self
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn head_hash(&self) -> AuditHash {
        self.entries
            .last()
            .map(|e| e.hash)
            .unwrap_or(AuditHash::GENESIS)
    }

    /// Test-only: tamper a stored entry's `detail` IN PLACE without recomputing
    /// its hash, simulating after-the-fact log mutation. The production
    /// [`Audit::verify_chain`] must then detect the break. Exposed only under
    /// `cfg(test)` so it can never be reached in shipped code.
    #[cfg(test)]
    pub(crate) fn tamper_detail(&mut self, index: usize, new_detail: &str) {
        self.entries[index].detail = new_detail.to_string();
    }

    /// Test-only: tamper a stored entry's `timestamp` IN PLACE without
    /// recomputing its hash. Because the timestamp is folded into the per-entry
    /// hash, the production [`Audit::verify_chain`] must detect this. Exposed
    /// only under `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn tamper_timestamp(&mut self, index: usize, new_timestamp: u64) {
        self.entries[index].timestamp = new_timestamp;
    }

    /// Test-only: swap two stored entries IN PLACE without recomputing any
    /// hashes, simulating reordering of an already-recorded log. Because each
    /// entry's `seq` is fixed at record time and folded into its MAC (and the MAC
    /// chains the previous entry's hash), reordering must break the production
    /// [`Audit::verify_chain`] on BOTH the `seq != index` check and the keyed-MAC
    /// linkage. Exposed only under `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn swap_entries(&mut self, a: usize, b: usize) {
        self.entries.swap(a, b);
    }

    /// Deterministic `HMAC-SHA-256(self.key, prev || entry payload)`.
    ///
    /// Thin method wrapper over the FREE function [`compute_entry_hash`] (inc 0):
    /// the canonical serialization now lives in ONE place so a different backend
    /// (the durable `audit-store`) computes BYTE-IDENTICAL MACs. The in-memory
    /// store and any persistent store therefore share exactly one wire format —
    /// see [`compute_entry_hash`] for the canonical layout + security notes.
    fn compute_hash(&self, prev: AuditHash, e: &AuditEntry) -> CoreResult<AuditHash> {
        compute_entry_hash(&self.key, prev, e)
    }
}

/// Compute the canonical per-entry MAC: `HMAC-SHA-256(key, prev || entry payload)`.
///
/// This is THE one canonical serialization the entire audit subsystem MACs — the
/// in-memory [`InMemoryAudit`] and the durable backend (`audit-store`) both call
/// it, so two backends fed the same entries + key produce byte-identical hashes
/// (proved by the `audit-store` round-trip test against `InMemoryAudit`). Keep
/// the serialization here and NOWHERE else; the `audit_serialization_is_byte_stable`
/// test is the tripwire that this byte stream never silently changes.
///
/// Keyed by `key`: recomputing the tag requires the key. The previous entry's
/// 32-byte hash is fed FIRST (the chaining), then a canonical, LENGTH-PREFIXED
/// serialization of this entry's fields. Variable-length fields are length-prefixed
/// (each field's byte-length precedes its bytes) rather than joined with a
/// separator. A raw `|` separator made field boundaries ambiguous — e.g.
/// `("a", "b|c")` and `("a|b", "c")` produced the same byte stream and could
/// collide. Prefixing each field's length removes that ambiguity. Order is fixed;
/// any reordering changes the tag (that's the point). Deterministic: HMAC-SHA-256
/// of a fixed key + fixed byte stream is reproducible.
///
/// SECURITY (C-2/L-1): FALLIBLE — never panics on the audit hot path. HMAC
/// accepts a key of any length, so `new_from_slice` should not fail in practice;
/// but rather than `.expect(..)` (a panic site in the chokepoint), the error is
/// threaded via `CoreResult`. `record` aborts the brokered op (fail-closed) and
/// the verifiers treat a compute error as verification FALSE (fail-closed) — a
/// MAC we cannot compute can never be trusted.
///
/// NOTE: the [`AuditEntry::hash`] field is DELIBERATELY NOT fed in — it is the
/// OUTPUT of this function, so an entry's stored hash is `compute_entry_hash(key,
/// prev, &entry)` regardless of what `entry.hash` currently holds. Callers may
/// therefore pass an entry whose `hash` is genesis/stale and compare the result.
pub fn compute_entry_hash(key: &[u8], prev: AuditHash, e: &AuditEntry) -> CoreResult<AuditHash> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|err| CoreError::Backend(format!("audit HMAC key rejected: {err}")))?;
    // Chaining: the previous entry's digest is the first input.
    mac.update(prev.as_bytes());
    // Fixed-width numeric fields are unambiguous as raw bytes.
    mac.update(&e.seq.to_le_bytes());
    // Timestamp (u64 LE) is folded in so altering it breaks verification.
    mac.update(&e.timestamp.to_le_bytes());
    // Variable-length fields: write u64 length, then bytes. `update_lp` takes
    // `impl AsRef<[u8]>` (#17), so `&str` / `String` go in directly — no
    // `.as_bytes()` — and the bytes MAC'd are byte-identical to before.
    update_lp(&mut mac, &e.acting_user);
    update_lp(&mut mac, &e.matter);
    update_lp(&mut mac, &e.module);
    update_lp(&mut mac, e.capability.to_string());
    update_lp(&mut mac, &e.detail);
    Ok(AuditHash(mac.finalize().into_bytes().into()))
}

/// Verify a COMPLETE, genesis-to-head keyed (HMAC-SHA-256) chain held in `entries`.
///
/// Same contract as [`Audit::verify_chain`], factored into a FREE function (inc 0)
/// so the durable backend (`audit-store`) verifies a replayed log with the
/// identical rule the in-memory store uses. `true` means: the slice is contiguous
/// from genesis (each entry's `seq` equals its index) AND each entry's stored hash
/// equals the recompute of [`compute_entry_hash`] under `key` over (prev_hash ||
/// fields).
///
/// Because the recompute is keyed, a chain forged/rewritten without the key, or
/// verified under the wrong key, fails here. This is an INDEX-based check, so it
/// requires a complete log starting at genesis: it cannot validate a rotated /
/// partial slice, and — being head-relative — it cannot by itself detect total
/// erasure (an EMPTY slice verifies `true`) or tail truncation. Those need an
/// EXTERNAL ANCHOR of head-hash + count (the `audit-store` anchor file).
///
/// Fail-closed: a hash that cannot be recomputed (an HMAC key error) is treated
/// as verification FALSE — never declare a chain valid on a MAC we could not
/// produce.
pub fn verify_entries(key: &[u8], entries: &[AuditEntry]) -> bool {
    let mut prev = AuditHash::GENESIS;
    for (i, e) in entries.iter().enumerate() {
        // seq must link contiguously to its index (complete-from-genesis).
        // L-2: explicit 64-bit assumption; an index that does not fit a u64
        // cannot exist on a real platform — treat the impossible as a failure.
        let i_u64 = match u64::try_from(i) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if e.seq != i_u64 {
            return false;
        }
        // keyed MAC must link to the previous entry's hash. Fail-closed: a hash
        // we cannot compute (an HMAC key error) is a verification FAILURE.
        match compute_entry_hash(key, prev, e) {
            Ok(h) if h.ct_eq(&e.hash) => {}
            _ => return false,
        }
        prev = e.hash;
    }
    true
}

impl Audit for InMemoryAudit {
    fn record(
        &mut self,
        acting_user: &str,
        matter: &str,
        module: &str,
        capability: Capability,
        detail: &str,
    ) -> CoreResult<AuditHash> {
        // OPT-IN fail-closed cap (#1): refuse BEFORE any state change once full, so
        // the brokered op aborts unredacted rather than the log growing without
        // bound. NEVER drops an existing entry (dropping would break the chain).
        if let Some(max) = self.max_entries {
            if self.entries.len() >= max {
                return Err(CoreError::Backend(format!(
                    "audit log is full (max {max} entries) — refusing to proceed unlogged; \
                     the audit must be persisted+reset (deferred persistence layer) or the \
                     Core reconstructed to continue"
                )));
            }
        }
        let prev = self.head_hash();
        // L-2: make the 64-bit assumption explicit. An entry count that does not
        // fit a u64 is impossible on any real platform (it would need >1.8e19
        // entries); `try_from(..).expect(..)` documents that rather than a silent
        // lossy `as` cast.
        let seq = u64::try_from(self.entries.len()).expect("audit entry count must fit in u64");
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
        // Fail-closed: if the MAC cannot be computed the entry is NOT appended
        // and the brokered op aborts (the `?` propagates to the mediator).
        entry.hash = self.compute_hash(prev, &entry)?;
        let h = entry.hash;
        self.entries.push(entry);
        // In-memory append cannot fail; a durable backend would return Err here
        // (e.g. WORM write failure), which the mediator must propagate so the
        // brokered op aborts rather than proceeding unlogged.
        Ok(h)
    }

    fn verify_chain(&self) -> bool {
        // Delegate to the FREE `verify_entries` (inc 0): the in-memory store and
        // the durable backend share ONE verification rule (index-contiguity +
        // keyed-MAC linkage). The recompute is keyed, so a chain forged/rewritten
        // without the key — or verified under a different key — fails. This
        // assumes a COMPLETE log starting at genesis held in one place; being
        // index-based + head-relative it cannot by itself detect total erasure
        // (an empty log verifies `true`) or tail truncation, which need an
        // external anchor of head_hash() + len(). (Tie-in to #7.)
        verify_entries(&self.key, &self.entries)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Feed a length-prefixed field into the MAC: the field's byte-length as a u64
/// (little-endian) followed by the field bytes. This makes the serialization
/// unambiguous so distinct field tuples cannot MAC to the same byte stream.
///
/// Takes `impl AsRef<[u8]>` so call sites pass a `&str`/`String`/`&[u8]` directly
/// without an explicit `.as_bytes()`. ZERO behaviour change (#17): the bytes fed
/// to the MAC are byte-identical to the previous `&[u8]` form — `.as_ref()` on a
/// `&[u8]` is the identity, and `str::as_bytes()` is exactly what the old call
/// sites passed — so the audit hashes are unchanged.
fn update_lp(mac: &mut HmacSha256, field: impl AsRef<[u8]>) {
    // F12 (Medium — fixed): the `len() as u64` cast below is LOSSLESS only while
    // `usize` is at most 64 bits — true on every platform this core targets
    // (64-bit, plus 32-bit where usize < u64). A hypothetical >64-bit `usize`
    // would let the cast SILENTLY TRUNCATE a field length, changing the canonical
    // serialization the HMAC commits to (two different fields could MAC to the same
    // length prefix) and quietly breaking the tamper-evidence guarantee with no
    // signal. This const assertion makes that assumption a COMPILE-TIME contract: a
    // target with `usize::BITS > 64` fails to BUILD here rather than producing a
    // subtly forgeable audit chain. On 32/64-bit the canonical byte stream is
    // unchanged (the cast is the identity for any real length), so the audit hashes
    // stay byte-identical — see the `audit_serialization_is_byte_stable` tripwire.
    const _: () = assert!(usize::BITS <= 64, "audit requires usize <= 64 bits");
    let field = field.as_ref();
    mac.update(&(field.len() as u64).to_le_bytes());
    mac.update(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, DataClass};
    use crate::clock::FixedClock;

    fn record_one(audit: &mut InMemoryAudit, detail: &str) {
        audit
            .record(
                "j.smith",
                "Acme v Beta",
                "sg.test.module",
                Capability::MatterRead(DataClass::Metadata),
                detail,
            )
            .expect("in-memory record must succeed");
    }

    #[test]
    fn max_entries_caps_fail_closed_without_dropping() {
        // #1: an OPT-IN soft cap REFUSES further records once full (fail-closed) and
        // NEVER drops an existing entry, so the chain still verifies. Default = unbounded.
        let mut audit = InMemoryAudit::with_clock(FixedClock::new(7)).with_max_entries(2);
        record_one(&mut audit, "one");
        record_one(&mut audit, "two");
        let third = audit.record(
            "j.smith",
            "Acme v Beta",
            "sg.test.module",
            Capability::MatterRead(DataClass::Metadata),
            "three",
        );
        assert!(
            matches!(third, Err(crate::error::CoreError::Backend(_))),
            "over-cap record must fail-closed, got {third:?}"
        );
        assert_eq!(
            audit.entries().len(),
            2,
            "the refused record is NOT appended (none dropped)"
        );
        assert!(audit.verify_chain(), "the existing chain stays intact");

        // Default (no cap) stays unbounded.
        let mut unbounded = InMemoryAudit::with_clock(FixedClock::new(7));
        for i in 0..50 {
            record_one(&mut unbounded, &format!("e{i}"));
        }
        assert_eq!(unbounded.entries().len(), 50, "default is unbounded");
    }

    #[test]
    fn timestamp_is_stamped_from_injected_clock() {
        let mut audit = InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000));
        record_one(&mut audit, "first");
        assert_eq!(audit.entries()[0].timestamp, 1_700_000_000_000);
        assert!(audit.verify_chain());
    }

    #[test]
    fn tampering_timestamp_in_place_breaks_chain() {
        // Fold-the-timestamp-into-the-hash guarantee: editing a recorded
        // entry's timestamp after the fact must fail the production verify.
        let mut audit = InMemoryAudit::with_clock(FixedClock::new(42));
        record_one(&mut audit, "a");
        record_one(&mut audit, "b");
        assert!(audit.verify_chain());

        audit.tamper_timestamp(0, 9_999_999);
        assert!(
            !audit.verify_chain(),
            "in-place timestamp tampering must break the production hash chain"
        );
    }

    #[test]
    fn fixed_clock_makes_hashes_deterministic() {
        // Same fixed clock + same inputs + same (fixed dev) key => identical
        // 32-byte HMAC-SHA-256 head hash, run to run. We do NOT hardcode the
        // digest literal (that would couple the test to the exact serialization);
        // instead we assert the two identical sequences produce the SAME tag.
        // `with_clock` uses the FIXED DEV_AUDIT_KEY, so no RNG enters and the
        // chain stays deterministic.
        let mk = || {
            let mut a = InMemoryAudit::with_clock(FixedClock::new(7));
            record_one(&mut a, "x");
            record_one(&mut a, "y");
            a.head_hash()
        };
        let h1 = mk();
        let h2 = mk();
        assert_eq!(
            h1, h2,
            "deterministic clock + inputs + key must yield the same HMAC digest"
        );
        // It is a real 32-byte tag, not the genesis seed.
        assert_eq!(h1.as_bytes().len(), 32);
        assert_ne!(
            h1,
            AuditHash::GENESIS,
            "a recorded chain head must not be the genesis hash"
        );
        // Hex rendering is lowercase and 64 chars.
        let hex = h1.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn audit_serialization_is_byte_stable() {
        // #17 regression guard: pin the exact head hash of a KNOWN two-entry chain
        // recorded under the fixed dev key + a fixed clock. The `update_lp`
        // signature change (`&[u8]` -> `impl AsRef<[u8]>`) must be byte-identical,
        // so this literal must NOT change. If a future edit to the canonical
        // serialization (field order, length-prefixing, what gets MAC'd) shifts the
        // bytes, this digest changes and the test fails LOUDLY — a deliberate
        // tripwire on the audit chain's wire format. (`record_one` records
        // user=j.smith matter="Acme v Beta" module=sg.test.module
        // cap=matter.read:metadata; here detail is "x" then "y".)
        let mut a = InMemoryAudit::with_clock_and_key(FixedClock::new(7), DEV_AUDIT_KEY.to_vec());
        record_one(&mut a, "x");
        record_one(&mut a, "y");
        assert_eq!(
            a.head_hash().to_hex(),
            "4e21f26f2d0f68c2cdb2ace8af3bb60cc3d48c865f8429438f6242070f14011f",
            "audit canonical serialization changed — #17 must be a byte-identical refactor"
        );
    }

    #[test]
    fn tampering_detail_in_place_breaks_chain() {
        // The keyed chain must still catch a naive in-place field edit: mutating
        // a recorded entry's `detail` without recomputing its MAC (and every
        // later MAC) fails verify_chain.
        let mut audit = InMemoryAudit::with_clock(FixedClock::new(42));
        record_one(&mut audit, "a");
        record_one(&mut audit, "b");
        assert!(audit.verify_chain());

        audit.tamper_detail(0, "forged");
        assert!(
            !audit.verify_chain(),
            "in-place detail tampering must break the keyed HMAC chain"
        );
    }

    #[test]
    fn reordering_entries_breaks_chain() {
        // Reordering an already-recorded log must be detected. Each entry's `seq`
        // is fixed at record time and folded into its MAC, and the MAC chains the
        // previous entry's hash — so swapping two entries in place (without
        // recomputing any hash) exercises BOTH halves of verify_chain together:
        // the `seq != index` contiguity check AND the keyed-MAC linkage.
        let mut audit = InMemoryAudit::with_clock(FixedClock::new(42));
        record_one(&mut audit, "first");
        record_one(&mut audit, "second");
        record_one(&mut audit, "third");
        assert!(audit.verify_chain(), "freshly recorded chain must verify");
        assert_eq!(audit.len(), 3);

        // Swap the first two entries in place. Their stored `seq` values now no
        // longer match their indices, and the MAC linkage no longer holds.
        audit.swap_entries(0, 1);
        assert!(
            !audit.verify_chain(),
            "reordering recorded entries must break the keyed hash chain"
        );
    }

    /// Record an identical two-entry sequence into an audit keyed with `key`,
    /// under a fixed clock, and return the resulting entries + head hash. Used by
    /// the key-sensitivity tests so they vary ONLY the key.
    fn record_seq_with_key(key: &[u8]) -> (Vec<AuditEntry>, AuditHash) {
        let mut a = InMemoryAudit::with_clock_and_key(FixedClock::new(99), key.to_vec());
        record_one(&mut a, "x");
        record_one(&mut a, "y");
        (a.entries().to_vec(), a.head_hash())
    }

    #[test]
    fn wrong_key_fails_verification() {
        // L-4: model the REAL attacker-rewrite scenario rather than asserting on
        // raw `entries` insertion. (1) Build a genuine chain by RECORDING under
        // key A — `record()` computes each MAC with key A, so this is exactly the
        // log a legitimate writer produced. (2) An attacker relocates those
        // recorded entries into a store the defender will verify under a DIFFERENT
        // key B (the attacker holds the entries but NOT key A). verify_chain
        // recomputes the MAC under its own key, so it must reject the chain under
        // key B — the key, not just the field bytes, is load-bearing.
        let key_a = b"audit-key-AAAAAAAAAAAAAAAAAAAAAAA";
        let key_b = b"audit-key-BBBBBBBBBBBBBBBBBBBBBBB";

        // (1) Genuine chain recorded under key A via the production `record` path.
        let mut authored = InMemoryAudit::with_clock_and_key(FixedClock::new(99), key_a.to_vec());
        record_one(&mut authored, "x");
        record_one(&mut authored, "y");
        assert!(
            authored.verify_chain(),
            "a chain RECORDED under key A must verify under key A"
        );
        let recorded_entries = authored.entries().to_vec();

        // (2) The SAME recorded entries, verified under the WRONG key B, must NOT
        // verify (the relocated-but-unkeyed-attacker case).
        let mut under_b = InMemoryAudit::with_clock_and_key(FixedClock::new(99), key_b.to_vec());
        for e in &recorded_entries {
            under_b.entries.push(e.clone());
        }
        assert!(
            !under_b.verify_chain(),
            "a chain recorded under key A must NOT verify under a different key B"
        );
    }

    #[test]
    fn different_keys_yield_different_head_hashes() {
        // Identical inputs (same fixed clock, same recorded fields) under two
        // distinct keys must produce distinct head MACs — proof the key actually
        // feeds the digest, not just the field bytes.
        let key_a = b"key-one-distinct-material-aaaaaaa";
        let key_b = b"key-two-distinct-material-bbbbbbb";

        let (_entries_a, head_a) = record_seq_with_key(key_a);
        let (_entries_b, head_b) = record_seq_with_key(key_b);

        assert_ne!(
            head_a, head_b,
            "same inputs under different keys must yield different HMAC head hashes"
        );
        // And the dev-key chain differs from both real-key chains.
        let (_entries_dev, head_dev) = record_seq_with_key(DEV_AUDIT_KEY);
        assert_ne!(head_dev, head_a);
        assert_ne!(head_dev, head_b);
    }
}
