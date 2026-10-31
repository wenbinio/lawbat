// SPDX-License-Identifier: AGPL-3.0-or-later
//! Egress control — the killer primitive (spec §2.5, §5.4).
//!
//! DEFAULT-DENY network. The core mediates ALL egress. A module never holds a
//! socket; to send anything out it hands the core a payload plus a NAMED
//! destination capability. The core policy-checks the destination, logs it,
//! sends it, and can globally revoke. No module gets wildcard egress, ever.
//!
//! IMPORTANT (CLAUDE.md non-negotiable + spec §0): this crate writes NO network
//! code. The `Egress` seam here does not — and must not — open a socket. The
//! "send" here is a stand-in sink that records the destination + payload so the
//! spike can prove the *gating*: a send is refused unless the specific named
//! destination is in the grant set. Wiring a real transport is a deliberate,
//! reviewed, separate step behind the same gate (and out of scope for the free
//! local-only tool — see CLAUDE.md "Local-only. No network egress.").

use crate::error::{CoreError, CoreResult};
use std::collections::VecDeque;

/// A record of an egress that PASSED the gate (so the spike/tests can inspect
/// what would have been sent). Holding this record is not the same as sending;
/// no transport is attached.
///
/// RETENTION (#2): the in-memory sink that holds these is now BOUNDED — it keeps
/// at most `max_records` (default [`DEFAULT_MAX_EGRESS_RECORDS`]) and drops the
/// OLDEST on overflow, and the host can [`Egress::drain`] to take + clear them.
/// That bounds the in-memory footprint of retained payloads (which may be matter
/// data). It is SOUND to bound/drop here precisely because egress records are
/// inspection-only and NOT a tamper-evident chain — unlike the audit log (#1),
/// which must never be lossily capped.
///
/// DEFERRED (H-4): this record still retains the FULL `payload` for the records it
/// DOES keep. The egress-record retention policy and the AUDIT chain's retention
/// policy remain DIFFERENT concerns to be designed SEPARATELY at persistence time:
/// the audit chain logs only metadata (count + destination + byte length — never
/// the payload bytes), whereas this record keeps the bytes. A real (persisted)
/// egress path still needs its own TTL / payload-stripping / redaction-at-rest
/// design so retained egress payloads do not become a durable secondary copy of
/// matter data with no expiry. The bound here addresses unbounded GROWTH; the
/// at-rest payload policy is the persistence-layer item. See `to-read/core.to-fix.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRecord {
    pub destination: String,
    pub payload: Vec<u8>,
}

/// The egress seam. The mediator ([`crate::Core`]) calls `send` / `fetch` only
/// AFTER the `egress:<destination>` capability check passes — so this trait never
/// has to re-check, but it must also never provide an ambient/wildcard path.
pub trait Egress {
    /// "Send" to a named destination. In the spike this records the attempt
    /// (no network). Returns Err for an unknown/blocked destination.
    fn send(&mut self, destination: &str, payload: &[u8]) -> CoreResult<()>;

    /// "Fetch" FROM a named destination — the INGRESS twin of [`Egress::send`].
    /// It pulls bytes IN from a named, consented endpoint, under the SAME
    /// default-deny named-destination gate. It WIDENS the egress surface, so it is
    /// mediated EXACTLY like `send`: the mediator ([`crate::Core::egress_fetch`])
    /// has already capability-checked + logged `egress:<destination>` before this
    /// is reached, so (like `send`) this trait never re-checks the grant — but it
    /// must NEVER provide an ambient/wildcard path. The sink still re-validates the
    /// destination shape defensively (belt-and-braces, mirroring `send`).
    ///
    /// In the spike this performs NO network I/O: it returns the seeded response
    /// bytes for the given named destination (a stand-in for the bytes a real,
    /// core-held transport would return), or `Err` for an unknown/blocked/
    /// malformed destination. `request` is an opaque request blob carried for
    /// shape-fidelity with the real seam; the in-memory double ignores its
    /// contents (the canned response is keyed by destination only).
    ///
    /// IMPORTANT (CLAUDE.md non-negotiable + spec §0): like `send`, this seam
    /// writes NO network code and opens NO socket. Wiring a real transport behind
    /// this same gate (the sign-off-gated mailbox connector) is a deliberate,
    /// reviewed, SEPARATE step. The negative space (no socket here) is the
    /// guarantee.
    fn fetch(&mut self, destination: &str, request: &[u8]) -> CoreResult<Vec<u8>>;

    /// Inspect what passed the gate (spike/test affordance only).
    fn sent(&self) -> &[EgressRecord];

    /// Take ALL retained egress records, leaving the sink empty (#2). Returns the
    /// records in arrival order and CLEARS the retained buffer, so the host can
    /// periodically drain accumulated egress payloads instead of letting them
    /// grow without bound. Egress records are NOT a tamper-evident chain (unlike
    /// the audit log — see #1), so draining them here is sound: nothing
    /// security-load-bearing depends on retaining the full history in memory.
    fn drain(&mut self) -> Vec<EgressRecord>;
}

/// Default maximum number of egress records [`InMemoryEgress`] retains. On
/// overflow the OLDEST record is dropped (bounded ring) — see #2. Egress records
/// are inspection-only and NOT a tamper-evident chain, so dropping the oldest is
/// safe (the audit log, which IS tamper-evident, is never bounded this way — see
/// #1 in `to-read/core.to-fix.md`). The host can also [`Egress::drain`] proactively.
pub const DEFAULT_MAX_EGRESS_RECORDS: usize = 1024;

/// In-memory egress sink. Knows a fixed set of *configured* destinations; an
/// unconfigured destination is a backend error even if (hypothetically) the
/// capability were granted — belt and braces, but the real gate is the broker.
///
/// Retention is BOUNDED (#2): at most `max_records` records are kept; once full,
/// recording a new send drops the OLDEST first (a ring), so a long-lived sink
/// cannot accumulate matter-data payloads without limit. The host may also
/// [`Egress::drain`] to take + clear the buffer between runs.
#[derive(Debug)]
pub struct InMemoryEgress {
    known_destinations: Vec<String>,
    /// Front = oldest, back = newest. A `VecDeque` so dropping the oldest on
    /// overflow is O(1) (`pop_front`); [`Egress::sent`] makes it contiguous for
    /// the `&[EgressRecord]` slice view.
    sent: VecDeque<EgressRecord>,
    /// Upper bound on retained records; the oldest is dropped past this. Always
    /// >= 1 (a zero cap is clamped to 1 in [`InMemoryEgress::with_max_records`]).
    max_records: usize,
    /// Canned FETCH responses keyed by named destination — the stand-in for the
    /// bytes a real, core-held transport would return on a `fetch`. A destination
    /// absent here yields a not-connected `Backend` error (the air-gapped default:
    /// nothing is fetchable unless explicitly seeded). A seeded destination is also
    /// implicitly a configured one (see [`InMemoryEgress::with_fetch_response`]), so
    /// the sink's belt-and-braces configured-destination check still holds for
    /// fetch. NO network: this map IS the "wire" in the spike.
    fetch_responses: std::collections::HashMap<String, Vec<u8>>,
}

impl Default for InMemoryEgress {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEgress {
    /// A sink with NO configured destinations — the default-deny posture. With
    /// this, even a (wrongly) granted egress capability cannot reach anywhere.
    /// Retains up to [`DEFAULT_MAX_EGRESS_RECORDS`] records (bounded, #2).
    pub fn new() -> Self {
        Self {
            known_destinations: Vec::new(),
            sent: VecDeque::new(),
            max_records: DEFAULT_MAX_EGRESS_RECORDS,
            fetch_responses: std::collections::HashMap::new(),
        }
    }

    /// Set the retained-record bound (#2). Clamped to a minimum of 1 (a sink that
    /// retained zero records could not satisfy the `sent()` inspection contract
    /// the spike/tests rely on). Builder-style so it composes with
    /// [`InMemoryEgress::with_destination`].
    pub fn with_max_records(mut self, max_records: usize) -> Self {
        self.max_records = max_records.max(1);
        // Trim immediately in case the cap was lowered below the current size.
        while self.sent.len() > self.max_records {
            self.sent.pop_front();
        }
        self
    }

    /// Configure a known destination (the firm-side, consented endpoint, §5.4).
    ///
    /// Defense in depth (§5.4): a MALFORMED destination (empty / whitespace-only
    /// / wildcard / all-routes — anything that fails
    /// [`crate::capability::egress_destination_is_named`]) is NOT registered, so
    /// it can never become a configured, sendable destination at this sink even
    /// if it somehow reached this layer. The broker is still the primary gate;
    /// this is belt-and-braces at the sink.
    pub fn with_destination(mut self, dest: impl Into<String>) -> Self {
        let dest = dest.into();
        // Dedup: a destination already configured is not added again, so the same
        // endpoint can never appear twice (a duplicate could mislead a host into
        // thinking a dest is single-module-restricted when it is not).
        if crate::capability::egress_destination_is_named(&dest)
            && !self.known_destinations.iter().any(|d| d == &dest)
        {
            self.known_destinations.push(dest);
        }
        self
    }

    /// Seed a canned FETCH response for a named destination (test/spike only — it
    /// stands in for the bytes a real, core-held transport would return). It both
    /// (a) registers the destination as a configured one (so the sink's
    /// belt-and-braces configured-destination check passes for a fetch) and
    /// (b) records the response bytes. Builder-style so it composes with
    /// [`InMemoryEgress::with_destination`] / [`InMemoryEgress::with_max_records`].
    ///
    /// Defense in depth (§5.4), mirroring [`InMemoryEgress::with_destination`]: a
    /// MALFORMED destination (empty / whitespace-only / wildcard / all-routes —
    /// anything that fails [`crate::capability::egress_destination_is_named`]) is
    /// NOT seeded, so it can never become a fetchable destination at this sink even
    /// if it somehow reached this layer. The broker is still the primary gate; this
    /// is the sink-side belt-and-braces. NO network is implied: this only fills the
    /// in-memory `fetch_responses` map.
    pub fn with_fetch_response(
        mut self,
        dest: impl Into<String>,
        response: impl Into<Vec<u8>>,
    ) -> Self {
        let dest = dest.into();
        if crate::capability::egress_destination_is_named(&dest) {
            // Keep the configured-destination list in sync (dedup via the shared
            // builder) so a fetched destination is also a "known" one for the
            // sink's configured-destination check.
            if !self.known_destinations.iter().any(|d| d == &dest) {
                self.known_destinations.push(dest.clone());
            }
            self.fetch_responses.insert(dest, response.into());
        }
        self
    }
}

impl Egress for InMemoryEgress {
    fn send(&mut self, destination: &str, payload: &[u8]) -> CoreResult<()> {
        // Defense in depth (§5.4): even if a malformed destination reached this
        // layer it must NOT be sendable. Reject it at the sink before the
        // configured-destination check, so an ambient-by-another-name value can
        // never leave the box here.
        if !crate::capability::egress_destination_is_named(destination) {
            // M-8: truncate the echoed destination (it may derive from matter data).
            return Err(CoreError::Backend(format!(
                "malformed egress destination (empty/whitespace/wildcard/all-routes/broadcast/multicast/loopback): {}",
                crate::capability::truncate_for_error(destination)
            )));
        }
        if !self.known_destinations.iter().any(|d| d == destination) {
            // M-8: truncate the echoed destination (it may derive from matter data).
            return Err(CoreError::Backend(format!(
                "no configured egress destination: {}",
                crate::capability::truncate_for_error(destination)
            )));
        }
        // Bounded ring (#2): if at capacity, drop the OLDEST record before pushing
        // the new one, so a long-lived sink never accumulates payloads without
        // bound. (max_records is always >= 1.)
        if self.sent.len() >= self.max_records {
            self.sent.pop_front();
        }
        self.sent.push_back(EgressRecord {
            destination: destination.to_string(),
            payload: payload.to_vec(),
        });
        // Keep the deque contiguous so the `&self` `sent()` accessor can return a
        // single slice without needing `&mut` to defragment it.
        self.sent.make_contiguous();
        Ok(())
    }

    fn fetch(&mut self, destination: &str, _request: &[u8]) -> CoreResult<Vec<u8>> {
        // Defense in depth (§5.4), IDENTICAL to `send`'s sink-side checks: even if a
        // malformed destination reached this layer it must NOT be fetchable. Reject
        // it before the configured-destination check, so an ambient-by-another-name
        // value can never pull bytes here. (The broker is the primary gate; this is
        // belt-and-braces.)
        if !crate::capability::egress_destination_is_named(destination) {
            // M-8: truncate the echoed destination (it may derive from matter data).
            return Err(CoreError::Backend(format!(
                "malformed egress destination (empty/whitespace/wildcard/all-routes/broadcast/multicast/loopback): {}",
                crate::capability::truncate_for_error(destination)
            )));
        }
        if !self.known_destinations.iter().any(|d| d == destination) {
            // M-8: truncate the echoed destination (it may derive from matter data).
            return Err(CoreError::Backend(format!(
                "no configured egress destination: {}",
                crate::capability::truncate_for_error(destination)
            )));
        }
        // The spike "wire": return the seeded bytes. A configured destination with
        // NO seeded response is NOT-CONNECTED (the air-gapped default — nothing is
        // fetchable unless explicitly seeded), surfaced as a Backend error rather
        // than an empty success, so the caller cannot mistake "no source" for
        // "source returned nothing". `_request` is ignored by the in-memory double
        // (the canned response is keyed by destination only). NO socket is opened.
        match self.fetch_responses.get(destination) {
            Some(bytes) => Ok(bytes.clone()),
            None => Err(CoreError::Backend(format!(
                "no fetch source configured for egress destination: {}",
                crate::capability::truncate_for_error(destination)
            ))),
        }
    }

    fn sent(&self) -> &[EgressRecord] {
        // `send` (and `with_max_records`) keep the deque contiguous, so the front
        // slice is the whole buffer; `.1` (the wrapped tail) is always empty here.
        self.sent.as_slices().0
    }

    fn drain(&mut self) -> Vec<EgressRecord> {
        // Take everything, leaving the sink empty (#2). `drain(..)` over a
        // VecDeque yields front-to-back (oldest-first), preserving arrival order.
        self.sent.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_destination_is_not_registered() {
        // with_destination must refuse malformed destinations: none survive.
        let sink = InMemoryEgress::new()
            .with_destination("")
            .with_destination(" ")
            .with_destination("*")
            .with_destination("0.0.0.0")
            .with_destination("::/0");
        assert!(
            sink.known_destinations.is_empty(),
            "no malformed destination may register"
        );

        // A well-formed one does register.
        let sink = InMemoryEgress::new().with_destination("counsel-vault");
        assert_eq!(sink.known_destinations, vec!["counsel-vault".to_string()]);
    }

    #[test]
    fn send_rejects_malformed_destination_even_if_unchecked_upstream() {
        // Belt-and-braces: even if a malformed value reaches the sink directly,
        // send must refuse it (a Backend error), and nothing leaves the box.
        let mut sink = InMemoryEgress::new().with_destination("counsel-vault");
        for bad in ["", " ", "\t", "a b", "*", "0.0.0.0", "::"] {
            let res = sink.send(bad, b"x");
            assert!(
                matches!(res, Err(CoreError::Backend(_))),
                "malformed destination {bad:?} must be refused, got {res:?}"
            );
        }
        assert!(sink.sent().is_empty(), "no malformed send may be recorded");
    }

    #[test]
    fn with_destination_dedups_repeated_destination() {
        // Adding the same destination twice yields exactly one entry, so a host
        // can never mistake a duplicate for two distinct configured endpoints.
        let sink = InMemoryEgress::new()
            .with_destination("counsel-vault")
            .with_destination("counsel-vault");
        assert_eq!(sink.known_destinations, vec!["counsel-vault".to_string()]);
    }

    #[test]
    fn send_to_configured_named_destination_succeeds() {
        let mut sink = InMemoryEgress::new().with_destination("counsel-vault");
        sink.send("counsel-vault", b"ok").unwrap();
        assert_eq!(sink.sent().len(), 1);
        assert_eq!(sink.sent()[0].destination, "counsel-vault");
    }

    #[test]
    fn drain_returns_and_clears_records_in_order() {
        // #2: drain() returns every retained record (oldest-first) AND leaves the
        // sink empty, so the host can periodically reclaim accumulated payloads.
        let mut sink = InMemoryEgress::new().with_destination("counsel-vault");
        sink.send("counsel-vault", b"a").unwrap();
        sink.send("counsel-vault", b"b").unwrap();
        sink.send("counsel-vault", b"c").unwrap();
        assert_eq!(sink.sent().len(), 3);

        let drained = sink.drain();
        let payloads: Vec<&[u8]> = drained.iter().map(|r| r.payload.as_slice()).collect();
        assert_eq!(
            payloads,
            vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()],
            "drain yields records oldest-first"
        );
        // The sink is now empty.
        assert!(
            sink.sent().is_empty(),
            "drain must clear the retained buffer"
        );

        // A further send still works (and is the only retained record).
        sink.send("counsel-vault", b"d").unwrap();
        assert_eq!(sink.sent().len(), 1);
        assert_eq!(sink.sent()[0].payload, b"d");
    }

    #[test]
    fn bounded_ring_drops_oldest_on_overflow() {
        // #2: with a small cap, the sink keeps only the most recent `max_records`
        // and drops the OLDEST first — bounded retention, no unbounded growth.
        let mut sink = InMemoryEgress::new()
            .with_destination("counsel-vault")
            .with_max_records(2);
        sink.send("counsel-vault", b"1").unwrap();
        sink.send("counsel-vault", b"2").unwrap();
        sink.send("counsel-vault", b"3").unwrap(); // evicts "1"

        assert_eq!(sink.sent().len(), 2, "retention is capped at max_records");
        let payloads: Vec<&[u8]> = sink.sent().iter().map(|r| r.payload.as_slice()).collect();
        assert_eq!(
            payloads,
            vec![b"2".as_slice(), b"3".as_slice()],
            "the oldest record is dropped, newest kept, order preserved"
        );

        // The slice view stays contiguous across many wrap-around sends.
        for _ in 0..10 {
            sink.send("counsel-vault", b"x").unwrap();
        }
        assert_eq!(sink.sent().len(), 2, "still capped after many sends");
        assert!(sink.sent().iter().all(|r| r.payload == b"x"));
    }

    #[test]
    fn fetch_returns_seeded_bytes_for_a_configured_destination() {
        // A destination seeded via with_fetch_response is both configured AND has a
        // canned response: fetch returns exactly those bytes. The `request` blob is
        // ignored by the in-memory double (response keyed by destination only).
        let mut sink =
            InMemoryEgress::new().with_fetch_response("acme-m365", b"raw .eml bytes".to_vec());
        let got = sink.fetch("acme-m365", b"any request").unwrap();
        assert_eq!(got, b"raw .eml bytes".to_vec());
        // Idempotent: a second fetch returns the same canned bytes (no mutation).
        let got2 = sink.fetch("acme-m365", b"different request").unwrap();
        assert_eq!(got2, b"raw .eml bytes".to_vec());
    }

    #[test]
    fn fetch_rejects_malformed_destination_even_if_unchecked_upstream() {
        // Belt-and-braces, IDENTICAL to send: even if a malformed value reaches the
        // sink directly, fetch must refuse it (a Backend error), pulling nothing.
        let mut sink = InMemoryEgress::new().with_fetch_response("acme-m365", b"x".to_vec());
        for bad in ["", " ", "\t", "a b", "*", "0.0.0.0", "::"] {
            let res = sink.fetch(bad, b"req");
            assert!(
                matches!(res, Err(CoreError::Backend(_))),
                "malformed destination {bad:?} must be refused, got {res:?}"
            );
        }
    }

    #[test]
    fn fetch_unconfigured_destination_is_a_backend_error() {
        // A well-formed but NOT-configured destination is refused at the sink (no
        // configured endpoint) — the air-gapped default, nothing fetchable.
        let mut sink = InMemoryEgress::new().with_fetch_response("acme-m365", b"x".to_vec());
        let res = sink.fetch("other-source", b"req");
        assert!(
            matches!(res, Err(CoreError::Backend(_))),
            "unconfigured dest must be refused, got {res:?}"
        );
    }

    #[test]
    fn fetch_configured_but_unseeded_destination_is_not_connected() {
        // A destination configured (via with_destination) but with NO seeded fetch
        // response is NOT-CONNECTED: fetch is a Backend error, never an empty-success
        // (so "no source" can't be mistaken for "source returned nothing").
        let mut sink = InMemoryEgress::new().with_destination("acme-m365");
        let res = sink.fetch("acme-m365", b"req");
        assert!(
            matches!(res, Err(CoreError::Backend(_))),
            "configured-but-unseeded must be not-connected, got {res:?}"
        );
    }

    #[test]
    fn with_fetch_response_refuses_malformed_destination() {
        // Mirror with_destination: a malformed fetch destination is NOT seeded, so
        // it can never become fetchable at this sink.
        let mut sink = InMemoryEgress::new()
            .with_fetch_response("", b"x".to_vec())
            .with_fetch_response("*", b"x".to_vec())
            .with_fetch_response("0.0.0.0", b"x".to_vec());
        for bad in ["", "*", "0.0.0.0"] {
            assert!(matches!(
                sink.fetch(bad, b"req"),
                Err(CoreError::Backend(_))
            ));
        }
    }

    #[test]
    fn with_max_records_clamps_zero_to_one() {
        // A zero cap is clamped to 1 so `sent()` can still hold the latest record.
        let mut sink = InMemoryEgress::new()
            .with_destination("counsel-vault")
            .with_max_records(0);
        sink.send("counsel-vault", b"a").unwrap();
        sink.send("counsel-vault", b"b").unwrap();
        assert_eq!(sink.sent().len(), 1, "zero cap is clamped to 1");
        assert_eq!(
            sink.sent()[0].payload,
            b"b",
            "the single retained record is the newest"
        );
    }
}
