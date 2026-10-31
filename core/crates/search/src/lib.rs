// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Search re-rank/present module — SKELETON (native first-party).
//!
//! A presentation-tier module that **re-ranks and presents** search results the
//! trusted core has ALREADY produced. It is a deliberate skeleton: the public
//! shape is defined and the seams are flagged, but the ranking/presentation logic
//! is unimplemented (a NON-PANICKING placeholder: `rerank` returns no hits,
//! `present` the empty default view) and lands in a later increment.
//!
//! ## Ratified architecture (load-bearing — do NOT invert this)
//!
//! **The CORE owns the index and runs the entitlement-filtered query** (spec
//! §2.3, CLAUDE.md "search = the CORE owns the index + an entitlement-filtered
//! query, modules only re-rank/present"). A module-owned index would defeat the
//! Chinese walls *from inside the instance*: it could retain or correlate matter
//! data across screen groups that the core's per-query entitlement filter is
//! meant to keep apart. So this module:
//!
//! - **does NOT build, hold, or persist an index** — there is no index field, no
//!   storage of hits, nothing here that could become a shadow index;
//! - **receives [`Hit`]s the core already entitlement-filtered** and only changes
//!   their ORDER (re-rank) and how they are PRESENTED — it never widens the set,
//!   never fetches more, and never reaches matter content directly;
//! - keeps [`rerank`](SearchModule::rerank) **PURE**: it takes only the
//!   core-provided hits and returns a reordering. It holds no [`runtime::Core`]
//!   handle and performs no I/O, so it CANNOT escape the result set it was given.
//!
//! ## Honest framing (what this module is and is NOT)
//!
//! - It is a RANKER/PRESENTER, not a search engine. "Search" here means "improve
//!   the presentation of a core search result", not "find documents".
//! - It cannot broaden a query, bypass entitlement, or read a document the core
//!   did not already return as a [`Hit`]. The entitlement decision happened in the
//!   core, BEFORE these hits existed (see the `TODO(core)` seam below).
//! - Re-ranking is intended to be DETERMINISTIC (no model, no network, no RNG) so
//!   the same query + hits always yield the same order — consistent with the
//!   platform's local-only / auditable non-negotiables.
//!
//! ## Capabilities (declared, default-deny — spec §5.1)
//!
//! This module needs almost nothing, because the core does the privileged work:
//!
//! - **`audit.note` (ungated)** — the ONLY core seam it touches: to record that a
//!   re-rank/present pass ran (count of hits in/out), so the activity is
//!   attributable. It can never suppress or forge a core event.
//! - **`egress: []`** — NO egress capability. Like [`redaction`], this module
//!   holds no destination grant; nothing it produces can leave the box.
//! - **NO `matter.read:<class>`** — it does NOT read matter content. The core has
//!   already read + entitlement-filtered the content into [`Hit`]s; the module
//!   only sees those. (Contrast [`redaction`], which DOES hold `matter.read` +
//!   `document.transform` because it rewrites content.)
//! - **NO index capability of any kind** — there is no such capability, by
//!   design; the index is a CORE responsibility, never a module's.
//!
//! See [`SearchModule::CAPABILITY_NOTE`] for the machine-checkable summary used in
//! tests / the (future) module manifest.

use runtime::{
    Audit, CapabilityBroker, CoreResult, DataClass, Egress, MatterContext, MatterStore, Storage,
};

/// One search result the CORE has ALREADY produced and entitlement-filtered. The
/// module receives these; it never constructs them from raw matter data (it has
/// no access to do so).
///
/// `doc_id` + `class` mirror [`runtime::DocRef`] (the opaque matter-doc handle):
/// the module sees an opaque id + the data class the core matched it under, NOT a
/// path or a raw db id. `snippet` is a short, core-prepared excerpt for display.
///
/// CONFIDENTIALITY: `snippet` is matter-derived text the CORE chose to surface in
/// THIS entitlement context. The module may reorder/present it but, holding no
/// egress, can never send it anywhere.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// Opaque matter-document id (as the core issued it; never a path/db id).
    pub doc_id: u64,
    /// The data class the core matched + entitlement-filtered this hit under.
    pub class: DataClass,
    /// The relevance score the CORE assigned (e.g. an FTS rank). The module may
    /// re-rank RELATIVE to this; it does not recompute it from raw content.
    pub score: f64,
    /// A short, core-prepared excerpt for display. Matter-derived; never egressed.
    pub snippet: String,
}

/// A user query, as the module sees it for RE-RANKING purposes only.
///
/// NOTE (load-bearing): the query that actually SELECTS documents is run by the
/// CORE against the core-owned index, under entitlement filtering. This type is a
/// re-rank/present hint (e.g. the raw terms, so the module can boost exact-phrase
/// hits) — it is NOT executed against any index here. The module cannot turn this
/// into a broader fetch; it only influences the ORDER of the hits it was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The raw query text the user typed (a re-rank hint only — see the type doc).
    pub text: String,
}

impl Query {
    /// Construct a query from raw user text.
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// A [`Hit`] after the module's re-rank pass: the original (core-provided) hit
/// plus the module's assigned rank position and the re-rank score it computed.
///
/// The module produces a NEW ordering; it never invents hits. Every `RankedHit`
/// in the output corresponds to exactly one input [`Hit`] (re-ranking is a
/// permutation/scoring of the input set, never an expansion of it).
#[derive(Debug, Clone, PartialEq)]
pub struct RankedHit {
    /// The core-provided hit being ranked (unchanged — order is expressed by the
    /// position in the returned `Vec` and by `rank`/`rerank_score`).
    pub hit: Hit,
    /// Zero-based rank position the module assigned (0 = most relevant).
    pub rank: usize,
    /// The module's re-rank score (deterministic; higher = more relevant). Derived
    /// only from `query` + the core-provided [`Hit`] fields — never from a fresh
    /// read of matter content (the module has no such access).
    pub rerank_score: f64,
}

/// A sanitized, non-scripting view model for a presented result list.
///
/// RATIFIED (CLAUDE.md / spec §8): a module's UI is **sanitized, non-scripting
/// HTML rendered into a host-provided slot — NO module JS**. So this view model
/// carries only inert, display-ready strings the host will sanitize and place into
/// its slot; it deliberately exposes NO event hooks, NO script, and NO raw HTML
/// the module controls. (This skeleton just defines the SHAPE; the host-side
/// rendering + the real sanitizer are out of scope here.)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResultView {
    /// One inert, display-ready row per presented hit (plain text the host will
    /// escape + place into its slot). NO module-controlled markup or script.
    pub rows: Vec<ResultRow>,
}

/// One inert row in a [`ResultView`]: plain, display-ready text only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResultRow {
    /// A display label for the document (opaque id rendered as text; no path).
    pub label: String,
    /// The display snippet (plain text; the host escapes it before rendering).
    pub snippet: String,
}

/// The search re-rank/present module (skeleton).
///
/// Holds NO index and NO [`runtime::Core`] handle for ranking — [`rerank`] is pure
/// over the core-provided hits. A `Core` handle is taken ONLY by the optional
/// [`note_pass`](SearchModule::note_pass) helper, purely to append an `audit.note`
/// (the one seam this module consumes).
///
/// [`rerank`]: SearchModule::rerank
#[derive(Debug, Default)]
pub struct SearchModule {
    // Intentionally EMPTY: no index, no cached hits, no Core handle. The absence
    // of any index field is part of the guarantee (see the crate docs) — the core
    // owns the index; this module must not be able to retain one.
}

impl SearchModule {
    /// Machine-checkable summary of this module's capability posture, for tests
    /// and the (future) module manifest. Encodes the ratified architecture: only
    /// `audit.note`, an EMPTY egress set, and NO `matter.read` / index capability.
    pub const CAPABILITY_NOTE: &'static str =
        "search: capabilities = [audit.note]; egress = []; matter.read = none; index = core-owned";

    /// Construct the (stateless) module.
    pub fn new() -> Self {
        Self {}
    }

    /// Re-rank the core-provided, ALREADY-entitlement-filtered `hits` for `query`.
    /// **PURE**: operates only on its inputs — no [`runtime::Core`], no index, no
    /// I/O — so it can never widen, refetch, or escape the result set it was given.
    ///
    /// Contract (to be honored when implemented): the output is a PERMUTATION of
    /// `hits` (every input hit appears exactly once, no hit invented), ordered by a
    /// DETERMINISTIC re-rank score, with `rank` set to the 0-based position.
    ///
    /// SKELETON: unimplemented this increment.
    pub fn rerank(&self, _query: &Query, _hits: Vec<Hit>) -> Vec<RankedHit> {
        // TODO(search): deterministic re-rank over (query, core-provided hits).
        // Must be a permutation of the input (no hit added/removed), score derived
        // ONLY from `query` + the `Hit` fields (never a fresh matter read).
        // SKELETON: a NON-PANICKING placeholder until the core-owned-index seam lands
        // (see the crate docs) — it returns no ranked hits and never invents one.
        Vec::new()
    }

    /// Build a sanitized, non-scripting [`ResultView`] from ranked hits, for
    /// rendering into a host-provided UI slot (NO module JS — ratified). Pure:
    /// transforms the ranked hits into inert display rows only.
    ///
    /// SKELETON: unimplemented this increment.
    pub fn present(&self, _ranked: &[RankedHit]) -> ResultView {
        // TODO(search): map ranked hits -> inert ResultRows (plain text only; the
        // host sanitizes + renders into its slot — the module emits no markup/JS).
        // SKELETON: a NON-PANICKING placeholder — an empty view until implemented.
        ResultView::default()
    }

    /// OPTIONAL: append an `audit.note` recording that a re-rank/present pass ran
    /// (hits in/out counts), so the activity is attributable. This is the ONLY
    /// core seam this module consumes — it is `audit.note` (ungated; a module may
    /// always append context), and it touches nothing privileged.
    ///
    /// Fail-closed: propagates a `CoreResult` error from the audit chokepoint.
    /// SKELETON: minimal — records a fixed-shape, cleartext-FREE note (counts only,
    /// never a snippet/matched value), mirroring redaction's confidentiality split.
    pub fn note_pass<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
        hits_in: usize,
        hits_out: usize,
    ) -> CoreResult<()>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        // Counts ONLY — never a query string or a snippet (matter-derived). Keeps
        // the audit chain from becoming a store of the very content it presents.
        core.audit_note(&format!(
            "search: re-rank/present pass — {hits_in} hit(s) in, {hits_out} hit(s) out"
        ))
    }
}

// TODO(core): this module CONSUMES a core-owned search/query seam that does not
// exist yet and is NOT built here — it belongs in `runtime`/the core, later.
//
// Needed shape (to live on `runtime::Core`, mediated like `matter_*`):
//
//     fn search(&mut self, query: &Query, class: DataClass) -> CoreResult<Vec<Hit>>;
//
// It MUST: (1) own the index (modules get no index — spec §2.3); (2) run the
// query against it; (3) entitlement-filter the results BEFORE returning them, so
// every `Hit` handed to this module is already screen-group / data-class filtered
// (the Chinese-wall filter happens in the core, never in the module); (4) audit
// the query as a brokered call. ONLY THEN does this module re-rank/present the
// `Hit`s. Do not build the index or the query here — that would put matter
// selection inside the (less-trusted) module and defeat the wall from inside the
// instance.

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{
        Capability, Core, CoreContext, FixedClock, GrantSet, InMemoryAudit, InMemoryEgress,
        InMemoryMatterStore, InMemoryStorage,
    };

    type TestCore = Core<
        GrantSet,
        InMemoryAudit,
        InMemoryStorage,
        InMemoryEgress,
        CoreContext,
        InMemoryMatterStore,
    >;

    /// A core with a minimal grant set for the search module: NO egress, NO
    /// matter.read, NO index capability — `audit.note` is ungated so it always
    /// works. Mirrors redaction's test-core wiring (deterministic fixed clock).
    fn search_core() -> TestCore {
        Core::new(
            "sg.search.module",
            // Empty manifest: the module needs no GATED capability. `audit.note`
            // is ungated, so it records regardless of the grant set.
            GrantSet::from_manifest(vec![]),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            // A destination IS configured so that IF egress were ever (wrongly)
            // granted, the broker gate — not a missing sink — is what we test.
            InMemoryEgress::new().with_destination("counsel-vault"),
            CoreContext::new("Acme v Beta", "j.smith"),
            InMemoryMatterStore::new(),
        )
    }

    /// A couple of core-provided, already-entitlement-filtered hits.
    fn sample_hits() -> Vec<Hit> {
        vec![
            Hit {
                doc_id: 1,
                class: DataClass::Document,
                score: 0.4,
                snippet: "…contract terms…".to_string(),
            },
            Hit {
                doc_id: 2,
                class: DataClass::Document,
                score: 0.9,
                snippet: "…governing law…".to_string(),
            },
        ]
    }

    #[test]
    fn module_constructs_and_holds_no_index() {
        // The module is stateless (no index, no Core handle). Constructing it is
        // infallible and the type carries no fields that could become a shadow
        // index — the architectural guarantee, asserted at the type level.
        let _m = SearchModule::new();
        // Zero-sized: nothing retained.
        assert_eq!(
            std::mem::size_of::<SearchModule>(),
            0,
            "the module holds no state/index"
        );
    }

    #[test]
    fn capability_note_declares_audit_note_only_and_no_egress_or_index() {
        // Encodes the ratified posture: audit.note only, empty egress, no
        // matter.read, core-owned index.
        let note = SearchModule::CAPABILITY_NOTE;
        assert!(note.contains("audit.note"), "declares audit.note: {note}");
        assert!(note.contains("egress = []"), "holds no egress: {note}");
        assert!(
            note.contains("matter.read = none"),
            "reads no matter content: {note}"
        );
        assert!(
            note.contains("index = core-owned"),
            "the core owns the index: {note}"
        );
    }

    #[test]
    fn note_pass_records_an_audit_note_with_counts_and_no_cleartext() {
        // The one seam the module consumes: an ungated audit.note. It records
        // COUNTS only — never a snippet/query (matter-derived) — mirroring
        // redaction's confidentiality split.
        let mut core = search_core();
        let hits = sample_hits();
        let snippet = hits[0].snippet.clone();
        SearchModule::new()
            .note_pass(&mut core, hits.len(), hits.len())
            .unwrap();

        let notes: Vec<&str> = core
            .audit()
            .entries()
            .iter()
            .filter(|e| e.capability == Capability::AuditNote)
            .map(|e| e.detail.as_str())
            .collect();
        assert_eq!(notes.len(), 1, "exactly one re-rank/present note recorded");
        assert!(
            notes[0].contains("2 hit(s) in"),
            "note carries the in-count: {:?}",
            notes[0]
        );
        // No matter-derived cleartext (snippet) leaks into the audit chain.
        assert!(
            !notes[0].contains(&snippet),
            "audit must not carry a snippet: {:?}",
            notes[0]
        );
        assert!(
            core.audit().verify_chain(),
            "the keyed hash chain must verify"
        );
    }

    #[test]
    fn module_holds_no_egress_grant() {
        // Defense-in-depth assertion mirroring redaction's test: with the search
        // module's (empty) grant set, the core REFUSES any egress — nothing it
        // presents can leave the box.
        let mut core = search_core();
        SearchModule::new().note_pass(&mut core, 0, 0).unwrap();
        let err = core.egress_send("counsel-vault", b"x").unwrap_err();
        assert!(
            matches!(err, runtime::CoreError::Denied(Capability::Egress(_))),
            "no egress grant -> egress refused, got {err:?}"
        );
        assert!(core.egress().sent().is_empty(), "nothing left the box");
    }

    #[test]
    fn rerank_is_a_skeleton_stub() {
        // SKELETON: rerank is intentionally unimplemented this increment — it is now a
        // NON-PANICKING placeholder (was `todo!()`). Pins that it returns no ranked hits
        // and never panics (flips to a real ranking test when the seam lands).
        assert!(SearchModule::new()
            .rerank(&Query::new("governing law"), sample_hits())
            .is_empty());
    }

    #[test]
    fn present_is_a_skeleton_stub() {
        // SKELETON: present is intentionally unimplemented this increment — a
        // NON-PANICKING placeholder (was `todo!()`) returning the empty default view.
        assert_eq!(SearchModule::new().present(&[]), ResultView::default());
    }
}
