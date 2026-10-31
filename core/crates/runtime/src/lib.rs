// SPDX-License-Identifier: AGPL-3.0-or-later
//! # lawdataman trusted-core runtime (seams)
//!
//! The trusted-core SEAMS for the lawdataman platform, as Rust traits + minimal
//! in-memory impls, mirroring the architecture spec §2 / §5.1. std-only so the
//! most-trusted code builds fast, offline, and with the smallest dependency
//! surface (spec §8: minimise what you must trust).
//!
//! The one idea (spec §0): **the sandbox, the capability model, and the audit
//! log are the same chokepoint, enforced three ways.** This crate implements the
//! capability + audit halves as host-side core logic; the sandbox half is the
//! WASM substrate spiked by the `host` bin + `hello` guest. Every mediated call
//! here follows: **check capability → act → log at the chokepoint.**
//!
//! NOTE: nothing here opens a socket or touches the filesystem (CLAUDE.md
//! non-negotiable: local-only, no network egress; source tree read-only).

pub mod audit;
pub mod broker;
pub mod capability;
pub mod clock;
pub mod context;
pub mod egress;
pub mod error;
pub mod matter;
pub mod metadata;
pub mod storage;

pub use audit::{compute_entry_hash, verify_entries, Audit, AuditEntry, AuditHash, InMemoryAudit};
pub use broker::{CapabilityBroker, GrantSet};
pub use capability::{Capability, CapabilityParseError, DataClass, StorageScope};
pub use clock::{Clock, FixedClock, SystemClock};
pub use context::{CoreContext, MatterContext, MatterInfo, UserInfo};
pub use egress::DEFAULT_MAX_EGRESS_RECORDS;
pub use egress::{Egress, EgressRecord, InMemoryEgress};
pub use error::{CoreError, CoreResult};
pub use matter::{ContentKind, DocRef, InMemoryMatterStore, MatterContent, MatterDoc, MatterStore};
pub use metadata::{parse_email_headers, EmailHeaders, MAX_CANONICAL_BYTES};
pub use storage::{storage_capability, InMemoryStorage, Storage};

/// A SAFE, cleartext-free projection of one audit-chain event, surfaced by
/// [`Core::matter_read_activity`] as the ACTIVITY-trail signal. Carries only
/// structured METADATA — never the audit `detail` string or any matter content —
/// so a module can derive document-review time without ever seeing document content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEvent {
    /// Milliseconds since the UNIX epoch — the audit entry's recorded timestamp.
    /// (The source chain `seq` is DELIBERATELY not surfaced: it is a global index
    /// across all matters/users, so exposing it would leak the volume/existence of
    /// other matters' hidden activity as a side-channel.)
    pub timestamp_millis: u64,
    /// The user who performed the activity. The projection is filtered to the
    /// current user, so this is always that user; surfaced for provenance.
    pub actor: String,
    /// The module that performed the touch (e.g. `sg.redaction.engine`). NOT matter
    /// content — surfaced so a consumer can distinguish automated module access from
    /// (future) user-initiated review when deciding what is billable.
    pub module: String,
    /// The typed kind of touch (no cleartext).
    pub kind: ActivityEventKind,
}

/// The kind of document-touch event surfaced by [`Core::matter_read_activity`]. A
/// tight ALLOWLIST: only matter READS (by class) and document TRANSFORMS are
/// activity-trail events. Storage / egress / audit-note / context-switch entries —
/// and a module's own `matter.read:activity` reads — are NOT projected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivityEventKind {
    /// A `matter.read:<class>` of the given data class.
    Read(DataClass),
    /// A `document.transform` (an in-place document rewrite).
    Transform,
}

/// Classify an audit entry's capability as a document-touch ACTIVITY kind, or
/// `None` if it is not an activity-trail event. The allowlist is deliberately
/// tight: a read of the [`DataClass::Activity`] trail itself is NOT an activity
/// event (so a module reading the trail never sees trail-reads as billable
/// touches); only CONTENT reads + transforms count.
fn activity_kind_of(cap: &Capability) -> Option<ActivityEventKind> {
    match cap {
        Capability::MatterRead(DataClass::Activity) => None,
        Capability::MatterRead(class) => Some(ActivityEventKind::Read(*class)),
        Capability::DocumentTransform => Some(ActivityEventKind::Transform),
        _ => None,
    }
}

// The activity-trail read is bound to the CONCRETE [`InMemoryAudit`] ON PURPOSE,
// not the generic `A: Audit`. The projection needs to read the recorded entries,
// and `entries()` is an INHERENT method on `InMemoryAudit` — deliberately NOT on
// the `Audit` trait, so a module holding a generic `&Core<.., A, ..>` cannot reach
// raw entries via `core.audit()` (that would bypass this projection entirely — the
// detail strings, all matters, all users). Binding the concrete type keeps the raw
// chain off the module-reachable trait surface while still letting the mediator
// build the safe projection. There is one audit impl in the data plane; a future
// audit backend gets its own concrete activity-read impl behind the same gate.
impl<B, S, E, C, M> Core<B, InMemoryAudit, S, E, C, M>
where
    B: CapabilityBroker,
    S: Storage,
    E: Egress,
    C: MatterContext,
    M: MatterStore,
{
    /// Mediated read of the current matter's ACTIVITY trail — a SAFE,
    /// entitlement-filtered, cleartext-free PROJECTION of the audit chain. Returns
    /// the document-touch events (matter reads + document transforms) performed by
    /// the CURRENT user in the CURRENT matter, oldest-first. Gated by
    /// `matter.read:activity` (default-deny). This is the signal source the
    /// timesheet module derives DOCUMENT-REVIEW time from.
    ///
    /// CONFIDENTIALITY (the load-bearing property): the projection carries the
    /// timestamp + the typed event kind + actor + module ONLY — it DROPS the audit
    /// `detail` string and never exposes matter content. It is filtered DOWN, inside
    /// the core, to the granted scope BEFORE anything leaves: OTHER users' and OTHER
    /// matters' entries are excluded, and only the document-touch ALLOWLIST
    /// ([`activity_kind_of`]) is projected — storage / egress / audit-note /
    /// context-switch entries, and the module's own `matter.read:activity` reads, are
    /// NOT activity-trail events and never appear. So granting this exposes activity
    /// METADATA, never document content. The audit chain records COUNTS (not doc
    /// ids), so the projection is doc-id-free by construction.
    ///
    /// HONESTY (read before deriving billable time from this): today these events
    /// are MODULE-brokered touches (a module read/transformed a doc on the user's
    /// behalf), NOT user-interface "document opened" events — the core does not yet
    /// observe manual review. A consumer must treat them as a DRAFT signal a human
    /// attests, never as measured human review time (see the timesheet's
    /// conservative, `Proposed`-only derivation). The `module` field is surfaced so a
    /// consumer can tell automated access apart from (future) user-initiated review.
    ///
    /// The read is itself audited (count-only); a log failure aborts fail-closed and
    /// the events are dropped (never returned unlogged).
    pub fn matter_read_activity(&mut self) -> CoreResult<Vec<ActivityEvent>> {
        let cap = Capability::MatterRead(DataClass::Activity);
        self.broker.check(&cap)?; // default-deny: refused unless granted
        let matter = self.context.current_matter().name;
        let user = self.context.acting_user().display_name;
        // Project the chain DOWN to the granted scope INSIDE the core: current
        // matter + current user + the document-touch allowlist. `detail` is dropped
        // (cleartext-free). This is the only place audit entries are read for a
        // module, and only this safe shape leaves.
        let mut events: Vec<ActivityEvent> = Vec::new();
        for e in self.audit.entries() {
            if e.matter != matter || e.acting_user != user {
                continue;
            }
            let Some(kind) = activity_kind_of(&e.capability) else {
                continue; // not a document-touch activity event
            };
            events.push(ActivityEvent {
                timestamp_millis: e.timestamp,
                actor: e.acting_user.clone(),
                module: e.module.clone(),
                kind,
            });
        }
        // Audit the read itself, count-only (the projection content never reaches
        // the audit — the chokepoint record is just "how many events were surfaced").
        self.log(
            cap,
            &format!("matter read activity ({} events)", events.len()),
        )?;
        Ok(events)
    }
}

/// The fully-concrete in-memory `Core` (#10): the six-generic [`Core`] wired with
/// this crate's default in-memory seam impls. A convenience alias so call sites
/// (the host spike, tests, a single-process shell) can name the common
/// composition without repeating all six type parameters.
///
/// Note the broker parameter is the concrete [`GrantSet`] (the `CapabilityBroker`
/// IMPL), not the `CapabilityBroker` trait — a type alias names concrete types.
/// Constructing one still requires the `dev-audit-key` feature (or `cfg(test)`)
/// if the [`InMemoryAudit`] is built via a dev-key constructor; a production build
/// keys it via [`InMemoryAudit::with_key`].
pub type DefaultCore = Core<
    GrantSet,
    InMemoryAudit,
    InMemoryStorage,
    InMemoryEgress,
    CoreContext,
    InMemoryMatterStore,
>;

/// The trusted core: composes the seams and enforces the chokepoint for every
/// mediated call (check → act → log). A module in this design holds NO direct
/// reference to broker/audit/storage/egress — only a handle that routes here.
pub struct Core<B, A, S, E, C, M>
where
    B: CapabilityBroker,
    A: Audit,
    S: Storage,
    E: Egress,
    C: MatterContext,
    M: MatterStore,
{
    // PRIVATE by design: the only way to reach broker/storage/egress is through
    // the mediated methods below, which enforce check → act → log. Exposing these
    // as `pub` would let any `&mut Core` holder call `core.storage.put(..)` /
    // `core.egress.send(..)` directly and bypass the chokepoint. Read-only
    // accessors (`audit()`, `egress()`) below allow legitimate inspection without
    // handing out a write path.
    broker: B,
    audit: A,
    storage: S,
    egress: E,
    context: C,
    /// The matter document store (spec §2.3, §6). PRIVATE by design: a module
    /// never holds a reference to it — the only way to list/read/transform a
    /// matter document is through the mediated `matter_*` / `document_transform`
    /// methods, which enforce capability-check → entitlement-filter → act → log.
    matter_store: M,
    /// The module identity actions are attributed to (spec §7).
    ///
    /// INVARIANT: module identity MUST be pinned by the trusted host/core from
    /// the VERIFIED manifest at load time, and never supplied by the module
    /// itself. A module that could name its own `module_id` could claim another
    /// module's storage namespace (and audit attribution). Today this is host-set
    /// (see `Core::new`, and the spike's `HostState.module_id`); this comment
    /// records the invariant before a real module loader exists so it is not lost.
    module_id: String,
}

impl<B, A, S, E, C, M> Core<B, A, S, E, C, M>
where
    B: CapabilityBroker,
    A: Audit,
    S: Storage,
    E: Egress,
    C: MatterContext,
    M: MatterStore,
{
    /// `module_id` MUST be set by the trusted host/core from the VERIFIED
    /// manifest at load time — never accepted from the module itself (a module
    /// naming its own id could claim another module's namespace; see the field
    /// doc above).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_id: impl Into<String>,
        broker: B,
        audit: A,
        storage: S,
        egress: E,
        context: C,
        matter_store: M,
    ) -> Self {
        Self {
            broker,
            audit,
            storage,
            egress,
            context,
            matter_store,
            module_id: module_id.into(),
        }
    }

    /// Read-only access to the audit log for inspection (verify_chain, head_hash,
    /// entries). Immutable by design: there is NO `&mut` accessor for the audit
    /// sink, so external code can never append/forge/suppress entries — only the
    /// mediated methods below record, at the chokepoint.
    pub fn audit(&self) -> &A {
        &self.audit
    }

    /// Read-only access to the egress sink for inspection (e.g. `sent()` in the
    /// spike/tests). Immutable by design: there is NO `&mut` accessor, so external
    /// code can never call `send` directly and bypass the check → act → log gate.
    pub fn egress(&self) -> &E {
        &self.egress
    }

    /// Read-only access to the capability broker / grant set for INSPECTION (e.g.
    /// the host proving the negative space — that no `Egress` capability is granted).
    /// Immutable by design: a `&B` cannot grant or mutate capabilities, so external
    /// code can inspect what was granted but never widen authority — the grant set
    /// is fixed at construction from the verified manifest.
    pub fn broker(&self) -> &B {
        &self.broker
    }

    /// The name of the matter this `Core` is currently scoped to (spec §2.1). A
    /// read-only projection of the context — the SAME attribution every brokered
    /// call is logged under — so a module (e.g. timesheet) can label its work
    /// product with the matter without a separate, forgeable channel. It cannot
    /// CHANGE the matter (that is the audited [`Core::switch_context`]); it only
    /// reports it. Carries no entitlement (it is the already-known current matter,
    /// not a cross-matter lookup), so it needs no capability gate.
    pub fn current_matter(&self) -> String {
        self.context.current_matter().name
    }

    /// Internal: log a brokered call at the chokepoint (spec §2.7, §7).
    ///
    /// Fail-closed: propagates an audit-record error so a brokered op aborts
    /// rather than completing with no audit entry. (See the ordering note on the
    /// mediated egress/storage methods for the residual durable-backend concern.)
    fn log(&mut self, capability: Capability, detail: &str) -> CoreResult<()> {
        let user = self.context.acting_user().display_name;
        let matter = self.context.current_matter().name;
        self.audit
            .record(&user, &matter, &self.module_id.clone(), capability, detail)?;
        Ok(())
    }

    /// `audit.note` (spec §4.3): a module ADDS context to the log. Cannot
    /// suppress or forge core events; it can only append. Returns `Err` if the
    /// note could not be recorded (fail-closed).
    pub fn audit_note(&mut self, event: &str) -> CoreResult<()> {
        // M-6: cap the note length. `audit.note` is UNGATED, so a module could
        // otherwise append an arbitrarily large blob on every call to bloat the
        // (in-memory, append-only) chain. Reject an over-cap note with a Backend
        // error rather than recording it. 4 KiB is generous for legitimate context
        // while bounding abuse. Measured in bytes (the underlying storage unit).
        const MAX_NOTE_BYTES: usize = 4096;
        if event.len() > MAX_NOTE_BYTES {
            return Err(CoreError::Backend(format!(
                "audit note too long: {} bytes (max {MAX_NOTE_BYTES})",
                event.len()
            )));
        }
        // UNGATED by design (spec §2.7/§4.3): a module may ALWAYS append context;
        // it can never suppress a core event, so there is no capability gate on
        // adding a note. The entry is still attributed + hash-chained like every
        // other entry — and recorded under the DEDICATED `audit.note` marker, NOT
        // `matter.read:metadata`, so a note can never be mistaken for a genuine
        // core read in the chain.
        let user = self.context.acting_user().display_name;
        let matter = self.context.current_matter().name;
        self.audit.record(
            &user,
            &matter,
            &self.module_id.clone(),
            Capability::AuditNote,
            &format!("note: {event}"),
        )?;
        Ok(())
    }

    /// Switch the matter / acting-user attribution of a long-lived core, FAIL-
    /// CLOSED (spec §2.1, §2.2, §7). A long-lived `Core` that re-attributes
    /// silently would log subsequent brokered calls against the OLD matter/user
    /// — a confidentiality + attribution defect. So this:
    ///
    /// 1. FIRST records an audit entry describing the transition (old->new
    ///    matter, old->new user), under the OLD attribution still in effect;
    /// 2. only if that record SUCCEEDS, updates `self.context` to the new values.
    ///
    /// If the audit record errors, the error propagates and the context is NOT
    /// changed — the core never switches unlogged.
    ///
    /// This is a CORE/SHELL context event, recorded under the
    /// [`Capability::AuditNote`] marker — it is a core-recorded transition, NOT a
    /// module-supplied note (a module cannot reach this path).
    pub fn switch_context(&mut self, matter: &str, user: &str) -> CoreResult<()> {
        // H-2: validate the NEW matter/user BEFORE recording anything. Reject
        // empty/whitespace, control/separator chars, and over-length values — a
        // malformed attribution must never enter the audit chain (it could inject
        // line breaks / forge structure) and must never become the live context.
        // This runs before the record below, so a bad switch writes NO entry and
        // changes NO state (fail-closed).
        context::validate_context_field("matter", matter)?;
        context::validate_context_field("user", user)?;
        let old_matter = self.context.current_matter().name;
        let old_user = self.context.acting_user().display_name;
        // Record the transition under the OLD attribution still in effect, BEFORE
        // mutating anything. If this fails, we propagate and do NOT switch.
        self.audit.record(
            &old_user,
            &old_matter,
            &self.module_id.clone(),
            Capability::AuditNote,
            &format!(
                "context switch: matter {old_matter:?}->{matter:?} user {old_user:?}->{user:?}"
            ),
        )?;
        // Audited successfully — now (and only now) re-point attribution.
        self.context.set_context(matter, user);
        Ok(())
    }

    /// Mediated egress (spec §2.5, §5.4): check the NAMED destination capability,
    /// then LOG, then act. Refused if the destination is not granted.
    ///
    /// ORDERING (F2, Critical — fixed): the brokered send is **recorded BEFORE the
    /// side effect**. A real send is an irreversible external act; if it ran before
    /// the audit entry, a crash (or, with a future durable audit backend, an audit
    /// write failure) BETWEEN the act and the log would leave an UNRECORDED send —
    /// a hole in the compliance chain. So the order is **check → log → act**:
    ///
    /// 1. `broker.check` — default-deny; a refusal propagates and logs nothing.
    /// 2. `self.log` — record the send. Fail-closed: if the audit record errors,
    ///    the `?` aborts and the payload is NEVER sent.
    /// 3. `self.egress.send` — only now does the payload leave the box.
    ///
    /// A failure at the sink (step 3) leaves a logged-but-not-sent entry, which is
    /// the SAFE direction: the log may over-claim an attempt, but can never UNDER-
    /// claim a send that actually happened. With a future durable audit backend
    /// this ordering is what guarantees no real send is ever lost from the chain.
    pub fn egress_send(&mut self, destination: &str, payload: &[u8]) -> CoreResult<()> {
        let cap = Capability::Egress(destination.to_string());
        self.broker.check(&cap)?; // default-deny: refused unless granted
                                  // Log BEFORE the irreversible send (fail-closed): an audit-record error
                                  // aborts here and nothing leaves the box.
        self.log(
            cap,
            &format!("egress to {destination} ({} bytes)", payload.len()),
        )?;
        // Audited — now (and only now) perform the side effect. A sink error here
        // leaves a logged-but-not-sent entry (the safe direction).
        self.egress.send(destination, payload)?;
        Ok(())
    }

    /// Mediated egress FETCH (spec §2.5, §5.4) — the INGRESS twin of
    /// [`Core::egress_send`]. It pulls bytes IN from a NAMED, consented destination
    /// (e.g. the mailbox connector pulling new mail), under the SAME default-deny
    /// `egress:<destination>` gate. This WIDENS the egress surface (egress controls
    /// *where* data may go; fetch also pulls data IN from a named endpoint), so it
    /// is mediated EXACTLY like a send: **check → log → act**, fail-closed.
    ///
    /// **The core holds the socket; the module never does.** The module hands the
    /// core a NAMED destination + an opaque `request` blob; the core checks the
    /// grant, logs the attempt, and performs the transport via the [`Egress::fetch`]
    /// seam. In this crate that seam opens NO socket (it returns seeded bytes — see
    /// the seam's IMPORTANT note); a real transport behind the same gate is a
    /// deliberate, sign-off-gated, separate step (the mailbox connector).
    ///
    /// ORDERING (mirrors F2 on [`Core::egress_send`]): the brokered fetch is
    /// **recorded BEFORE the side effect**. A real fetch is an external act with a
    /// remote endpoint; recording it first means a crash (or, with a future durable
    /// audit backend, an audit write failure) BETWEEN the act and the log can never
    /// leave an UNRECORDED fetch. So:
    ///
    /// 1. `broker.check` — default-deny; a refusal propagates and logs NOTHING (and
    ///    fetches nothing — no audit on refusal, like every other mediated method).
    /// 2. `self.log` — record the ATTEMPT. Fail-closed: if the audit record errors,
    ///    the `?` aborts and NO fetch is performed.
    /// 3. `self.egress.fetch` — only now does the core reach the named endpoint.
    ///
    /// CONFIDENTIALITY (mirrors the egress/transform audit posture): the fetched
    /// bytes are matter data (e.g. raw `.eml`), so the audit detail carries
    /// COUNTS/ATTRIBUTION ONLY — the destination name (truncated, M-8) + the
    /// REQUEST byte length — and NEVER the fetched cleartext. The intent is logged
    /// before the fetch, so the response length is not yet known at log time; that
    /// is intentional (we never want the response bytes — only that a fetch from
    /// this named destination was attempted, and how large the request was). The
    /// returned bytes flow to the caller IN-PROCESS (for `extract`/staging), never
    /// to the audit chain.
    ///
    /// A failure at the sink (step 3) leaves a logged-but-not-fetched entry — the
    /// SAFE direction: the log may over-claim an attempt, but can never UNDER-claim
    /// a fetch that actually happened.
    pub fn egress_fetch(&mut self, destination: &str, request: &[u8]) -> CoreResult<Vec<u8>> {
        let cap = Capability::Egress(destination.to_string());
        self.broker.check(&cap)?; // default-deny: refused unless granted
                                  // Log the ATTEMPT BEFORE the fetch (fail-closed): an audit-record error
                                  // aborts here and the core never reaches the endpoint. Detail is
                                  // COUNTS/ATTRIBUTION only — destination + REQUEST byte length, NEVER the
                                  // fetched response bytes (which are matter data).
        self.log(
            cap,
            &format!(
                "egress fetch from {destination} (request {} bytes)",
                request.len()
            ),
        )?;
        // Audited — now (and only now) perform the side effect (no socket here; the
        // seam returns seeded bytes). A sink error leaves a logged-but-not-fetched
        // entry (the safe direction). The bytes are returned IN-PROCESS to the
        // caller and are NEVER written to the audit chain.
        let response = self.egress.fetch(destination, request)?;
        Ok(response)
    }

    /// Mediated storage put (spec §2.4): check scope capability, LOG, then act.
    ///
    /// ORDERING (F3, High — fixed): same act-before-log defect as [`Core::egress_send`]
    /// (F2). A persisted write is a durable side effect; recording it BEFORE the
    /// `storage.put` means a crash (or a durable-audit-backend write failure)
    /// between act and log can never leave an UNRECORDED write. So **check → log →
    /// act**: the audit record is taken first (fail-closed — an audit error aborts
    /// before any write), then the value is stored. A `put` failure after the log
    /// leaves a logged-but-not-stored entry (the safe direction).
    pub fn storage_put(
        &mut self,
        scope: StorageScope,
        key: &str,
        value: Vec<u8>,
    ) -> CoreResult<()> {
        let cap = storage_capability(scope);
        self.broker.check(&cap)?;
        let module = self.module_id.clone();
        // Log BEFORE the write (fail-closed): an audit-record error aborts here and
        // nothing is persisted.
        self.log(cap, &format!("storage put {scope}/{key}"))?;
        // Audited — now perform the write.
        self.storage.put(scope, &module, key, value)?;
        Ok(())
    }

    /// Mediated storage get (spec §2.4): check scope capability, act, log.
    ///
    /// ORDERING NOTE: see [`Core::egress_send`] for the durable-backend ordering
    /// concern. No behavior change now.
    pub fn storage_get(&mut self, scope: StorageScope, key: &str) -> CoreResult<Option<Vec<u8>>> {
        let cap = storage_capability(scope);
        self.broker.check(&cap)?;
        let module = self.module_id.clone();
        // check → act → log: record only after the op returns Ok. Fail-closed on
        // the audit record.
        let value = self.storage.get(scope, &module, key)?;
        self.log(cap, &format!("storage get {scope}/{key}"))?;
        Ok(value)
    }

    /// Mediated storage CLEAR (scratch drain, #3): check the scope capability, LOG,
    /// then drain THIS module's namespace, returning the count removed. The host
    /// calls it between module runs so per-module scratch storage cannot accumulate
    /// without bound — and it goes through the chokepoint exactly like every other
    /// op. **check → log → act**, fail-closed: an audit-record error aborts before
    /// anything is removed (the safe direction — a drain after a logged clear is at
    /// worst a logged-but-not-cleared entry, never a silent unlogged wipe).
    ///
    /// DELIBERATE COUPLING (audit integrity wins): because this logs BEFORE it
    /// drains, a FULL audit (the opt-in [`InMemoryAudit::with_max_entries`] cap, #1)
    /// makes this drain fail-closed too — i.e. once the audit ceiling is hit the
    /// system can no longer reclaim scratch memory either. This is the accepted
    /// trade-off, not an oversight: allowing an UNLOGGED wipe to reclaim memory
    /// would defeat the tamper-evident chain, and the audit ceiling is a generous
    /// last-resort OOM backstop (the real fix is the deferred persistence layer).
    pub fn storage_clear(&mut self, scope: StorageScope) -> CoreResult<usize> {
        let cap = storage_capability(scope);
        self.broker.check(&cap)?;
        let module = self.module_id.clone();
        // Log BEFORE the drain (fail-closed): an audit error aborts here, nothing removed.
        self.log(cap, &format!("storage clear {scope}"))?;
        let removed = self.storage.clear_namespace(scope, &module)?;
        Ok(removed)
    }

    /// Mediated matter LIST (spec §2.3): check `matter.read:<class>`, then apply
    /// the entitlement pre-filter (return ONLY docs of the granted class — the
    /// Chinese-wall / screen-group filter happens HERE in the core, before the
    /// module sees anything), then audit, then return.
    ///
    /// Refused (`CoreError::Denied`) if `matter.read:<class>` is not granted —
    /// and a refusal writes NO audit entry, consistent with the other mediated
    /// methods (default-deny leaves no trace of a call that never happened).
    ///
    /// check → act → log: the listing is materialized only after the grant
    /// check passes, and the entry is recorded only after a successful list.
    /// Fail-closed on the audit record.
    pub fn matter_list_docs(&mut self, class: DataClass) -> CoreResult<Vec<DocRef>> {
        let cap = Capability::MatterRead(class);
        self.broker.check(&cap)?; // default-deny: refused unless granted
                                  // Entitlement pre-filter (spec §2.3): the store returns ONLY docs of the
                                  // exact granted class, so a non-granted class is never materialized here.
        let refs = self.matter_store.list(class);
        self.log(cap, &format!("matter list {class} ({} docs)", refs.len()))?;
        Ok(refs)
    }

    /// Mediated matter READ (spec §2.3): check `matter.read:<class>`,
    /// entitlement-filter (the doc must exist AND be of the granted `class` —
    /// guessing another class's id returns `NotFound`, never its content), then
    /// audit, then return the text.
    ///
    /// Refused if `matter.read:<class>` is not granted (no audit entry on
    /// refusal). A granted read of a missing/other-class id is a `Backend`
    /// not-found error AFTER the grant check — but it is still audited, because
    /// an *attempt* to read under a granted class is itself an attributable
    /// brokered call (spec §7).
    pub fn matter_read_text(&mut self, doc_id: u64, class: DataClass) -> CoreResult<String> {
        let cap = Capability::MatterRead(class);
        self.broker.check(&cap)?; // default-deny: refused unless granted
                                  // Entitlement filter: read returns Some only if the doc exists AND is of
                                  // the granted class. A wrong-class / absent id yields None -> not-found.
        let lookup = self.matter_store.read(doc_id, class);
        // H-5 — AUDIT-BEFORE-RETURN, made explicit + refactor-safe. A brokered
        // read that passed the gate is an attributable event whether or not the
        // doc was found, so we audit the ATTEMPT FIRST — unconditionally, before
        // either returning the content or surfacing the not-found error. Ordering
        // the `self.log(..)?` ahead of BOTH return paths means:
        //   - a found read is never returned UNLESS it was logged (a log failure
        //     `?`-aborts and the content is dropped — fail-closed);
        //   - a not-found read is still recorded (the log runs before the error is
        //     surfaced).
        // Keeping the audit on its own line ABOVE the match (rather than buried in
        // one branch) makes it refactor-safe: neither branch can be edited to skip
        // the audit, because the audit no longer lives inside a branch.
        self.log(cap, &format!("matter read doc {doc_id} ({class})"))?;
        match lookup {
            Some(text) => Ok(text),
            None => Err(CoreError::Backend(format!(
                "matter doc {doc_id} not found in class {class}"
            ))),
        }
    }

    /// Mediated matter METADATA read (the `matter.read:metadata` seam — see
    /// `to-read/runtime.METADATA-SEAM-PROPOSAL.md` §6–§9). A typed sibling of
    /// [`Core::matter_read_text`]: it mirrors that method's gate + entitlement
    /// filter + audit-before-return EXACTLY, but returns a parsed, INERT
    /// [`EmailHeaders`] instead of a raw string — so the confidential header block
    /// is parsed ONCE, in the trusted core, behind the chokepoint, and a consumer
    /// (the inbox) can never reintroduce a parser bug.
    ///
    /// `class` is parameterized like `matter_read_text` (the entitlement is per
    /// class), but the seam is email-header specific: the stored content MUST be the
    /// `firmos.meta/1` canonical form, so in practice this is called with
    /// [`DataClass::Metadata`] — and the grant the broker checks is then
    /// `matter.read:metadata` (which already EXISTS in the taxonomy; no taxonomy
    /// change). Calling it under a different class checks THAT class's grant and
    /// only succeeds if a doc of that class holds a `firmos.meta/1` string.
    ///
    /// ORDERING — identical to [`Core::matter_read_text`] (H-5 audit-before-return):
    /// 1. `broker.check(matter.read:<class>)` — default-deny; a refusal propagates
    ///    and writes NO audit entry (a call that never happened leaves no trace).
    /// 2. entitlement-filter via the EXISTING `matter_store.read(doc_id, class)` —
    ///    the doc must exist AND be of `class`, else `None` → not-found AFTER the
    ///    gate (guessing another class's id never reaches its content).
    /// 3. **audit-before-return** — the attempt is logged BEFORE the parsed value is
    ///    returned or the not-found error surfaced. A log error `?`-aborts and the
    ///    value is DROPPED (fail-closed): a found read is never returned unless it
    ///    was logged. The audit is on its own line ABOVE the match so neither branch
    ///    can be edited to skip it (refactor-safe, like `matter_read_text`).
    /// 4. parse the stored canonical string into the typed value and return it.
    ///
    /// CONFIDENTIALITY — the load-bearing constraint. Email headers ARE matter data,
    /// and the addresses / subject / **Bcc** are exactly the sensitive fields. The
    /// audit detail carries **COUNTS / ATTRIBUTION ONLY** — the doc id + class + a
    /// recipient COUNT — and **NEVER a header VALUE** (no address, no subject, no
    /// Bcc). This is the SAME split as `egress_send` (destination + byte length,
    /// never the payload), `egress_fetch` (destination + request length, never the
    /// fetched bytes), and `document_transform` (doc id, never the cleartext). The
    /// parsed [`EmailHeaders`] flow to the caller IN-PROCESS; they NEVER touch the
    /// audit chain.
    ///
    /// IMPORTANT — the audit happens BEFORE the parse, deliberately. We log the
    /// READ ATTEMPT (id + class), then parse. So:
    /// - the COUNT in the detail is derived from the parse and appended only after a
    ///   SUCCESSFUL parse (a count is not a value); and
    /// - if the stored string is a malformed/unknown-version canonical form, the
    ///   READ was still a real, attributable brokered call — so the read attempt is
    ///   audited (step 3, before the parse) and THEN the parse error surfaces. The
    ///   read is never silently unlogged just because the bytes failed to parse.
    pub fn matter_read_metadata(
        &mut self,
        doc_id: u64,
        class: DataClass,
    ) -> CoreResult<EmailHeaders> {
        let cap = Capability::MatterRead(class);
        self.broker.check(&cap)?; // default-deny: refused unless granted
                                  // Entitlement filter (identical to matter_read_text): read returns Some only
                                  // if the doc exists AND is of the granted class. A wrong-class / absent id
                                  // yields None -> not-found AFTER the gate.
        let lookup = self.matter_store.read(doc_id, class);
        // H-5 — AUDIT-BEFORE-RETURN, on its own line above the match (refactor-safe):
        // a brokered metadata read that passed the gate is an attributable event
        // whether or not the doc was found / parses, so we audit the ATTEMPT FIRST.
        // CONFIDENTIALITY: the detail is doc id + class ONLY here — NO header value.
        // (The recipient COUNT, also value-free, is appended in a SECOND entry only
        // after a successful parse below, so the first entry never depends on the
        // possibly-malformed stored bytes and a not-found read is still logged.)
        self.log(
            cap.clone(),
            &format!("matter read metadata doc {doc_id} ({class})"),
        )?;
        let canonical = match lookup {
            Some(text) => text,
            None => {
                return Err(CoreError::Backend(format!(
                    "matter doc {doc_id} not found in class {class}"
                )))
            }
        };
        // Parse the stored canonical form into the typed value. This is the trivial
        // std-only deserialize (NOT RFC 822); a malformed/unknown-version blob is a
        // fail-closed Err (the read was already audited above, so a parse failure
        // never leaves the read unlogged).
        let headers = metadata::parse_email_headers(&canonical)?;
        // A SECOND, value-free audit entry recording the recipient COUNT — a number,
        // never an address/subject/Bcc value. This is the only place a parse-derived
        // datum reaches the audit, and it is explicitly a count, mirroring the
        // egress/transform "counts-only" posture. Fail-closed: a log error aborts and
        // the parsed headers are DROPPED (never returned unlogged).
        self.log(
            cap,
            &format!(
                "matter read metadata doc {doc_id} ({class}): {} recipients",
                headers.recipient_count()
            ),
        )?;
        Ok(headers)
    }

    /// Mediated matter BLOB read (the binary content path — `PDF-CORE-WIRING-
    /// PROPOSAL.md` §4). The BYTE-typed sibling of [`Core::matter_read_text`]:
    /// it mirrors that method's gate + entitlement filter + audit-before-return
    /// (H-5) EXACTLY, but returns the document's opaque `Vec<u8>` (a PDF / `.docx`
    /// / other binary doc) instead of a `String`. It lets `redaction::redact_pdf`
    /// read a PDF THROUGH the chokepoint — a PDF is bytes, and `content: String`
    /// could not hold it losslessly (see [`matter::MatterContent`]).
    ///
    /// NO new capability and NO new [`DataClass`]: a PDF is a `document`-class doc,
    /// gated by the EXISTING `matter.read:<class>` (in practice
    /// `matter.read:document`). Text-vs-blob is a content-KIND dimension, not an
    /// entitlement one — the store's [`MatterStore::read_blob`] returns `Some` only
    /// for a doc that exists AND is of `class` AND is a [`MatterContent::Blob`]; a
    /// TEXT doc accessed via `_blob` is a content-kind MISMATCH → `None` → not-found
    /// AFTER the gate (never a coerced/garbled read).
    ///
    /// ORDERING — identical to [`Core::matter_read_text`] (H-5 audit-before-return):
    /// 1. `broker.check(matter.read:<class>)` — default-deny; a refusal propagates
    ///    and writes NO audit entry (a call that never happened leaves no trace).
    /// 2. entitlement + content-kind filter via [`MatterStore::read_blob`] — the doc
    ///    must exist AND be of `class` AND be a `Blob`, else `None` → not-found AFTER
    ///    the gate (guessing another class's id, or a text doc's id, never reaches
    ///    bytes).
    /// 3. **audit-before-return** — the attempt is logged BEFORE the bytes are
    ///    returned or the not-found error surfaced. A log error `?`-aborts and the
    ///    bytes are DROPPED (fail-closed): a found read is never returned unless it
    ///    was logged. The audit is on its own line ABOVE the match so neither branch
    ///    can be edited to skip it (refactor-safe, like `matter_read_text`).
    ///
    /// CONFIDENTIALITY — the load-bearing constraint. The PDF bytes ARE matter data,
    /// so the audit detail carries **COUNTS / ATTRIBUTION ONLY** — the doc id +
    /// class + the BYTE LENGTH — and **NEVER the bytes**. Logging a byte length is
    /// the SAME counts-only posture as `egress_send`/`egress_fetch` (destination +
    /// length, never the payload) and `matter_read_metadata` (recipient count, never
    /// a value). The bytes flow to the caller IN-PROCESS (for `redact_pdf`); they
    /// NEVER touch the audit chain.
    pub fn matter_read_blob(&mut self, doc_id: u64, class: DataClass) -> CoreResult<Vec<u8>> {
        let cap = Capability::MatterRead(class);
        self.broker.check(&cap)?; // default-deny: refused unless granted
                                  // Entitlement + content-kind filter: read_blob returns Some only if the doc
                                  // exists AND is of the granted class AND is a Blob. A wrong-class / absent /
                                  // text-kind id yields None -> not-found AFTER the gate (never coerced).
        let lookup = self.matter_store.read_blob(doc_id, class);
        // H-5 — AUDIT-BEFORE-RETURN, on its own line above the match (refactor-safe),
        // identical to matter_read_text. A brokered blob read that passed the gate is
        // an attributable event whether or not the doc was found, so we audit the
        // ATTEMPT FIRST. CONFIDENTIALITY: the detail is doc id + class + BYTE LENGTH
        // only — NEVER the bytes themselves. The length is derived from the lookup so
        // a not-found read logs 0 bytes (a count, never a value).
        let byte_len = lookup.as_ref().map(Vec::len).unwrap_or(0);
        self.log(
            cap,
            &format!("matter read blob doc {doc_id} ({class}): {byte_len} bytes"),
        )?;
        match lookup {
            Some(bytes) => Ok(bytes),
            None => Err(CoreError::Backend(format!(
                "matter doc {doc_id} not found in class {class} (or not a blob)"
            ))),
        }
    }

    /// Mediated DOCUMENT TRANSFORM (spec §6): check `document.transform`
    /// (default-deny) AND `matter.read:<class>` (a transform reads then
    /// rewrites, so it needs the read entitlement for the class too), read the
    /// doc content, apply `f` IN THE CORE, write the result back to the store,
    /// and audit the transform. The module supplies only the pure rewrite
    /// closure `f`; it never holds the store, so the content is rewritten in
    /// place THROUGH the core, mediated + logged (spec §6: the module never holds
    /// the store).
    ///
    /// Refused if either capability is missing (no audit entry on refusal). A
    /// granted transform of a missing/other-class id is a not-found `Backend`
    /// error after the checks.
    ///
    /// AUDIT TRAIL — a granted transform writes THREE entries, all counts/
    /// attribution only (never the cleartext), in order:
    ///
    /// 1. `matter.read:<class>` — the READ the transform performs (F8): a brokered
    ///    read must be audited even when it is a step inside a transform, not only
    ///    when invoked via `matter_read_text`.
    /// 2. `document.transform … : start` — written BEFORE `f` runs (F9), so a
    ///    panic/non-termination inside the module closure still leaves a trail that
    ///    the transform was attempted over the cleartext.
    /// 3. `document.transform … : complete` — written AFTER `f`, BEFORE write-back.
    ///
    /// **Fail-closed:** every entry is taken with `?` BEFORE the side effect it
    /// guards (the read entry before `f` sees cleartext; the start entry before
    /// `f`; the complete entry before persisting), so any audit error aborts and
    /// the content is neither processed-without-record nor silently rewritten.
    pub fn document_transform(
        &mut self,
        doc_id: u64,
        class: DataClass,
        mut f: impl FnMut(&str) -> String,
    ) -> CoreResult<()> {
        let transform_cap = Capability::DocumentTransform;
        self.broker.check(&transform_cap)?; // default-deny
                                            // A transform reads the content first, so it also needs the read
                                            // entitlement for the class — entitlement is enforced in the core before
                                            // the module's closure ever sees the text.
        let read_cap = Capability::MatterRead(class);
        self.broker.check(&read_cap)?;
        // Read (entitlement-filtered): the doc must exist AND be of `class`.
        let original = self.matter_store.read(doc_id, class).ok_or_else(|| {
            CoreError::Backend(format!("matter doc {doc_id} not found in class {class}"))
        })?;
        // F8 (Medium — fixed): a transform EXERCISES `matter.read:<class>` (it reads
        // the doc content before rewriting), and a brokered act must be audited. The
        // old code checked the read capability but logged only the transform, so the
        // read it actually performed left no trail. Record the read here, under its
        // own `matter.read:<class>` capability, after the content is materialized.
        // Fail-closed: an audit error `?`-aborts before the cleartext reaches `f`.
        self.log(
            read_cap,
            &format!("matter read: class={class} doc={doc_id}"),
        )?;
        // F9 (Medium — fixed): write a "start" entry BEFORE handing cleartext to the
        // module closure `f`. The original content reaches `f` before any transform
        // audit existed, so a panic (or non-termination) inside `f` could process
        // matter cleartext with NO record that the transform was attempted. Logging
        // the start first means even a panicking `f` leaves an attributable trail.
        // Fail-closed: an audit error here aborts before `f` ever runs. (Detail is
        // COUNTS/ATTRIBUTION only — doc id + class, never the cleartext.)
        self.log(
            transform_cap.clone(),
            &format!("document transform doc {doc_id} ({class}): start"),
        )?;
        // Apply the module-supplied pure rewrite IN THE CORE.
        let rewritten = f(&original);
        // Fail-closed ordering: record the transform COMPLETION BEFORE persisting,
        // so an audit failure aborts the write-back and the content is never
        // silently rewritten unlogged. (For an in-memory store this also means the
        // write is the last, infallible step.)
        self.log(
            transform_cap,
            &format!("document transform doc {doc_id} ({class}): complete"),
        )?;
        // Write back through the core. The (id, class) match is re-checked by the
        // store; it succeeded on read, so this writes.
        let wrote = self.matter_store.set_content(doc_id, class, rewritten);
        if !wrote {
            return Err(CoreError::Backend(format!(
                "matter doc {doc_id} ({class}) vanished before transform write-back"
            )));
        }
        Ok(())
    }

    /// Mediated DOCUMENT TRANSFORM over BLOB content (the binary content path —
    /// `to-read/runtime.PDF-CORE-WIRING-PROPOSAL.md` §4). The BYTE-typed sibling of
    /// [`Core::document_transform`]: it mirrors that method's capability gate,
    /// entitlement + content-kind filter, and THREE fail-closed audit entries
    /// EXACTLY, but the rewrite closure is `&[u8] -> Vec<u8>` (a PDF in, redacted
    /// PDF out) instead of `&str -> String`. The module supplies only the pure
    /// rewrite closure `f`; it never holds the store, so the bytes are rewritten in
    /// place THROUGH the core, mediated + logged (spec §6).
    ///
    /// NO new capability and NO new [`DataClass`]: a PDF is a `document`-class doc,
    /// gated by the EXISTING `document.transform` + `matter.read:<class>` (a
    /// transform reads then rewrites, so it needs the read entitlement for the class
    /// too). Text-vs-blob is a content-KIND dimension: the store's
    /// [`MatterStore::read_blob`]/[`MatterStore::set_blob`] operate ONLY on a
    /// [`MatterContent::Blob`] doc, so a TEXT doc at (id, class) is a content-kind
    /// mismatch → not-found AFTER the checks (never coerced into bytes and back).
    ///
    /// Refused if either capability is missing (no audit entry on refusal). A
    /// granted transform of a missing / other-class / TEXT-kind id is a not-found
    /// `Backend` error after the checks.
    ///
    /// AUDIT TRAIL — identical SHAPE + ORDERING to [`Core::document_transform`]: a
    /// granted transform writes THREE entries, all COUNTS / ATTRIBUTION + BYTE
    /// LENGTH only (NEVER the bytes), in order:
    ///
    /// 1. `matter.read:<class>` — the READ the transform performs, logged with the
    ///    INPUT byte length, BEFORE the cleartext bytes reach `f` (so a brokered
    ///    read is audited even as a step inside a transform).
    /// 2. `document.transform … : start` — written BEFORE `f` runs, so a panic /
    ///    non-termination inside the module closure still leaves a trail that the
    ///    transform was attempted over the matter bytes.
    /// 3. `document.transform … : complete` — written AFTER `f`, BEFORE write-back,
    ///    with the OUTPUT byte length.
    ///
    /// **Fail-closed:** every entry is taken with `?` BEFORE the side effect it
    /// guards (the read entry before `f` sees the bytes; the start entry before `f`;
    /// the complete entry before persisting), so any audit error aborts and the
    /// bytes are neither processed-without-record nor silently rewritten.
    ///
    /// CONFIDENTIALITY: the PDF bytes ARE matter data — the audit detail records the
    /// doc id + class + the input/output BYTE LENGTHS only, NEVER the bytes. This is
    /// the SAME counts-only posture as [`Core::matter_read_blob`] and the text
    /// transform. The redaction COUNT / per-recognizer breakdown is the redaction
    /// module's own `audit_note` (also value-free), recorded BEFORE this call.
    pub fn document_transform_blob(
        &mut self,
        doc_id: u64,
        class: DataClass,
        mut f: impl FnMut(&[u8]) -> Vec<u8>,
    ) -> CoreResult<()> {
        let transform_cap = Capability::DocumentTransform;
        self.broker.check(&transform_cap)?; // default-deny
                                            // A transform reads the content first, so it also needs the read
                                            // entitlement for the class — enforced in the core before the module's
                                            // closure ever sees the bytes.
        let read_cap = Capability::MatterRead(class);
        self.broker.check(&read_cap)?;
        // Read (entitlement + content-kind filtered): the doc must exist AND be of
        // `class` AND be a Blob. A wrong-class / absent / text-kind id is not-found.
        let original = self.matter_store.read_blob(doc_id, class).ok_or_else(|| {
            CoreError::Backend(format!(
                "matter doc {doc_id} not found in class {class} (or not a blob)"
            ))
        })?;
        // Mirror document_transform's F8 read entry, here with the INPUT byte length
        // (a count, never the bytes). Fail-closed: an audit error `?`-aborts before
        // the bytes reach `f`.
        self.log(
            read_cap,
            &format!(
                "matter read blob: class={class} doc={doc_id} ({} bytes)",
                original.len()
            ),
        )?;
        // Mirror F9: write a "start" entry BEFORE handing the bytes to `f`, so even a
        // panicking closure leaves an attributable trail that the transform was
        // attempted over the matter bytes. Counts/attribution only (doc id + class +
        // input byte length), never the bytes.
        self.log(
            transform_cap.clone(),
            &format!(
                "document transform blob doc {doc_id} ({class}): start ({} bytes)",
                original.len()
            ),
        )?;
        // Apply the module-supplied pure rewrite IN THE CORE.
        let rewritten = f(&original);
        // Fail-closed ordering: record the transform COMPLETION (with the OUTPUT byte
        // length) BEFORE persisting, so an audit failure aborts the write-back and
        // the bytes are never silently rewritten unlogged.
        self.log(
            transform_cap,
            &format!(
                "document transform blob doc {doc_id} ({class}): complete ({} bytes)",
                rewritten.len()
            ),
        )?;
        // Write back through the core (Blob set: the (id, class) + Blob KIND match is
        // re-checked by the store; it succeeded on read_blob, so this writes).
        let wrote = self.matter_store.set_blob(doc_id, class, rewritten);
        if !wrote {
            return Err(CoreError::Backend(format!(
                "matter doc {doc_id} ({class}) vanished before blob transform write-back"
            )));
        }
        Ok(())
    }
}

// F15 (Low — fixed): test-only SEAMS so the unit tests never reach into `Core`'s
// PRIVATE fields (`core.audit`, `core.egress`, `core.matter_store`) directly.
// Poking private fields from a test couples the test to the struct's internals
// and quietly bypasses the encapsulation the whole chokepoint design relies on —
// a refactor of a field could silently invalidate a test, or a test could exercise
// an invariant through a path production code can't. These `#[cfg(test)]` methods
// expose the SAME invariant through a supported, intention-revealing seam, and
// (being `cfg(test)`) can never be reached in shipped code. They are split across
// small impl blocks so each carries only the concrete bound its method needs.
#[cfg(test)]
impl<B, S, E, C, M> Core<B, InMemoryAudit, S, E, C, M>
where
    B: CapabilityBroker,
    S: Storage,
    E: Egress,
    C: MatterContext,
    M: MatterStore,
{
    /// Test-only: tamper a recorded audit entry's `detail` IN PLACE (without
    /// recomputing its MAC), via a supported Core seam instead of reaching the
    /// private `audit` field. The production `verify_chain()` (through `audit()`)
    /// must then detect the break.
    pub(crate) fn tamper_audit_detail_for_test(&mut self, index: usize, new_detail: &str) {
        self.audit.tamper_detail(index, new_detail);
    }
}

#[cfg(test)]
impl<B, A, S, E, C> Core<B, A, S, E, C, InMemoryMatterStore>
where
    B: CapabilityBroker,
    A: Audit,
    S: Storage,
    E: Egress,
    C: MatterContext,
{
    /// Test-only: read a matter doc's raw content (ignoring class), via a supported
    /// Core seam instead of reaching the private `matter_store` field. Used to
    /// assert what the store holds after (or in the absence of) a transform.
    pub(crate) fn raw_content_for_test(&self, id: u64) -> Option<&str> {
        self.matter_store.raw_content(id)
    }

    /// Test-only: seed a doc into the matter store, via a supported Core seam
    /// instead of reaching the private `matter_store` field. (Production seeding is
    /// the trusted host's job through `InMemoryMatterStore::insert` before the store
    /// is moved into the Core; this seam lets a test that built an empty-store Core
    /// populate it without poking internals.)
    pub(crate) fn seed_doc_for_test(&mut self, id: u64, class: DataClass, content: &str) {
        self.matter_store.insert(id, class, content);
    }

    /// Test-only: seed a BLOB doc into the matter store, via a supported Core seam
    /// (the byte-typed sibling of [`Core::seed_doc_for_test`]).
    pub(crate) fn seed_blob_doc_for_test(&mut self, id: u64, class: DataClass, content: &[u8]) {
        self.matter_store.insert_blob(id, class, content.to_vec());
    }

    /// Test-only: read a matter doc's raw BLOB content (ignoring class), via a
    /// supported Core seam (the byte-typed sibling of
    /// [`Core::raw_content_for_test`]). Returns `None` for a Text doc.
    pub(crate) fn raw_blob_for_test(&self, id: u64) -> Option<&[u8]> {
        self.matter_store.raw_blob(id)
    }
}

#[cfg(test)]
impl<B, A, S, E, C, M> Core<B, A, S, E, C, M>
where
    B: CapabilityBroker,
    A: Audit,
    S: Storage,
    E: Egress,
    C: MatterContext,
    M: MatterStore,
{
    /// Test-only: replace the egress sink, via a supported Core seam instead of
    /// assigning the private `egress` field directly. Lets a test reconfigure the
    /// sink (e.g. to add a second configured destination) while still driving sends
    /// through the mediated `egress_send` chokepoint.
    pub(crate) fn set_egress_for_test(&mut self, egress: E) {
        self.egress = egress;
    }

    /// Test-only: inspect what passed the egress gate, via a supported seam. Same
    /// view as the public `egress()` accessor; offered here so a test reads the
    /// sink without naming the private field.
    pub(crate) fn egress_sent_for_test(&self) -> &[EgressRecord] {
        self.egress.sent()
    }
}

#[cfg(test)]
impl<B, A, E, C, M> Core<B, A, InMemoryStorage, E, C, M>
where
    B: CapabilityBroker,
    A: Audit,
    E: Egress,
    C: MatterContext,
    M: MatterStore,
{
    /// Test-only: read the backing store DIRECTLY (no capability check, no audit),
    /// keyed by this Core's own pinned module id, via a supported seam instead of
    /// reaching the private `storage` field. This is how F3 proves a put did/did
    /// NOT land when the mediated `storage_get` itself fails-closed under a failing
    /// audit (so it cannot be used to observe the store's state).
    pub(crate) fn raw_storage_get_for_test(
        &self,
        scope: StorageScope,
        key: &str,
    ) -> CoreResult<Option<Vec<u8>>> {
        self.storage.get(scope, &self.module_id, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #10: the test composition IS the DefaultCore alias — use it to cut the
    // six-generic noise here (a worked example of the alias).
    type TestCore = DefaultCore;

    fn core_with(grants: Vec<Capability>) -> TestCore {
        core_with_docs(grants, InMemoryMatterStore::new())
    }

    fn core_with_docs(grants: Vec<Capability>, matter_store: InMemoryMatterStore) -> TestCore {
        // F6: use the reject-surfacing constructor and ASSERT no grant was refused
        // — every test that wires a Core via this helper passes valid, enforceable
        // capabilities, so a non-empty reject list here is a test bug, not a silent
        // drop. (A test that DELIBERATELY exercises rejection calls
        // `from_manifest_checked` directly; see `from_manifest_checked_surfaces_rejects`.)
        let (grant_set, rejected) = GrantSet::from_manifest_checked(grants);
        assert!(
            rejected.is_empty(),
            "test grants must all be valid, rejected: {rejected:?}"
        );
        Core::new(
            "sg.test.module",
            grant_set,
            // Inject a FIXED clock so the timestamp-in-hash stays deterministic
            // across test runs (the production path uses SystemClock).
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            // Configure a real destination so the gate, not the sink, is what blocks.
            InMemoryEgress::new().with_destination("counsel-vault"),
            CoreContext::new("Acme v Beta", "j.smith"),
            matter_store,
        )
    }

    /// Test-only `Audit` double whose `record` always returns `Err`. Used to
    /// prove the mediator is FAIL-CLOSED: if the chokepoint cannot record an
    /// entry, the brokered op must propagate that `Err` and abort, never complete
    /// silently unlogged. `Core` is generic over `A: Audit`, so this composes in
    /// place of `InMemoryAudit`. Compiled only under `cfg(test)`.
    struct FailingAudit;

    impl Audit for FailingAudit {
        fn record(
            &mut self,
            _acting_user: &str,
            _matter: &str,
            _module: &str,
            _capability: Capability,
            _detail: &str,
        ) -> CoreResult<AuditHash> {
            // Simulate a durable-backend write failure (e.g. WORM write error).
            Err(CoreError::Backend("audit backend unavailable".into()))
        }

        // An empty/never-populated chain is internally consistent.
        fn verify_chain(&self) -> bool {
            true
        }

        fn len(&self) -> usize {
            0
        }
    }

    /// A `Core` wired with the [`FailingAudit`] double but otherwise functional
    /// (real grants, storage, egress). The grant lets a call reach the
    /// act-then-log step so the failing audit is what aborts it.
    fn core_with_failing_audit(
        grants: Vec<Capability>,
    ) -> Core<
        GrantSet,
        FailingAudit,
        InMemoryStorage,
        InMemoryEgress,
        CoreContext,
        InMemoryMatterStore,
    > {
        // F6: surface + assert-empty the rejects (same rationale as core_with_docs).
        let (grant_set, rejected) = GrantSet::from_manifest_checked(grants);
        assert!(
            rejected.is_empty(),
            "test grants must all be valid, rejected: {rejected:?}"
        );
        Core::new(
            "sg.test.module",
            grant_set,
            FailingAudit,
            InMemoryStorage::new(),
            InMemoryEgress::new().with_destination("counsel-vault"),
            CoreContext::new("Acme v Beta", "j.smith"),
            InMemoryMatterStore::new(),
        )
    }

    #[test]
    fn ungranted_capability_is_denied() {
        // Default-deny: no grants at all.
        let mut core = core_with(vec![]);
        let err = core
            .storage_put(StorageScope::Own, "k", b"v".to_vec())
            .unwrap_err();
        match err {
            CoreError::Denied(Capability::Storage(StorageScope::Own)) => {}
            other => panic!("expected Denied(Storage(Own)), got {other:?}"),
        }
        // A denied call writes NO audit entry: the log stays empty.
        assert_eq!(core.audit.len(), 0, "denial must leave no audit entry");
    }

    #[test]
    fn granted_capability_is_allowed_and_logged() {
        let mut core = core_with(vec![Capability::Storage(StorageScope::Own)]);
        core.storage_put(StorageScope::Own, "k", b"v".to_vec())
            .unwrap();
        let got = core.storage_get(StorageScope::Own, "k").unwrap();
        assert_eq!(got, Some(b"v".to_vec()));
        // put + get were both logged at the chokepoint.
        assert_eq!(core.audit.len(), 2);
    }

    #[test]
    fn egress_with_no_granted_destination_is_refused() {
        // Grant a DIFFERENT destination than the one we try to use.
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);

        // Refused: "evil.example" is not the granted destination.
        let err = core.egress_send("evil.example", b"secret").unwrap_err();
        match err {
            CoreError::Denied(Capability::Egress(d)) if d == "evil.example" => {}
            other => panic!("expected Denied(Egress(evil.example)), got {other:?}"),
        }
        // Nothing left the box.
        assert!(core.egress.sent().is_empty());
        // And nothing was logged for the refused send.
        assert_eq!(
            core.audit.len(),
            0,
            "refused egress must leave no audit entry"
        );
    }

    #[test]
    fn egress_with_no_grant_at_all_is_refused() {
        let mut core = core_with(vec![]); // default-deny
        let err = core.egress_send("counsel-vault", b"x").unwrap_err();
        assert!(matches!(err, CoreError::Denied(Capability::Egress(_))));
        assert!(core.egress.sent().is_empty());
        // Default-deny refusal logs nothing.
        assert_eq!(
            core.audit.len(),
            0,
            "ungranted egress must leave no audit entry"
        );
    }

    #[test]
    fn egress_to_granted_destination_passes_gate() {
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);
        core.egress_send("counsel-vault", b"ok").unwrap();
        assert_eq!(core.egress.sent().len(), 1);
        assert_eq!(core.egress.sent()[0].destination, "counsel-vault");
    }

    #[test]
    fn audit_chain_links_and_detects_tampering() {
        let mut core = core_with(vec![Capability::Storage(StorageScope::Own)]);
        core.audit_note("starting work").unwrap();
        core.storage_put(StorageScope::Own, "a", b"1".to_vec())
            .unwrap();
        core.storage_put(StorageScope::Own, "b", b"2".to_vec())
            .unwrap();

        // The chain verifies as recorded.
        assert!(core.audit.verify_chain());
        assert!(core.audit.len() >= 3);

        // Tamper with a middle entry's detail IN PLACE inside the REAL log via the
        // supported test seam (F15: no reaching the private `audit` field), then
        // assert the PRODUCTION verify_chain() (not a test double) detects it.
        core.tamper_audit_detail_for_test(1, "FORGED");
        assert!(
            !core.audit().verify_chain(),
            "in-place tampering must break the production hash chain"
        );
    }

    #[test]
    fn readonly_accessors_expose_audit_and_egress_for_inspection() {
        // The mediator's fields are PRIVATE; external code inspects via the
        // immutable accessors `audit()` / `egress()`. These return `&A` / `&E`
        // (never `&mut`), so a caller can read state but cannot drive `send` /
        // `record` directly and bypass check → act → log.
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);
        core.egress_send("counsel-vault", b"ok").unwrap();

        // Inspect via the read-only accessors (the same shape external code uses).
        assert_eq!(core.egress().sent().len(), 1);
        assert_eq!(core.egress().sent()[0].destination, "counsel-vault");
        assert_eq!(core.audit().len(), 1, "the successful send was logged");
        assert!(core.audit().verify_chain());
    }

    #[test]
    fn audit_note_is_ungated_and_recorded_under_audit_note_marker() {
        // Ungated: a note records even with a DEFAULT-DENY (empty) grant set —
        // a module may always add context (spec §2.7/§4.3).
        let mut core = core_with(vec![]);
        core.audit_note("module commentary").unwrap();

        assert_eq!(core.audit.len(), 1, "ungated note must be recorded");
        let entry = &core.audit.entries()[0];
        // Recorded under the DEDICATED audit.note marker, NOT matter.read:metadata,
        // so a note can never be mistaken for a genuine core read in the chain.
        assert_eq!(entry.capability, Capability::AuditNote);
        assert_ne!(
            entry.capability,
            Capability::MatterRead(DataClass::Metadata),
            "a note must be distinguishable from a real metadata read"
        );
        // ATTRIBUTION (spec §7): a note is attributed to the acting human + the
        // host-pinned module, in the current matter — same chokepoint as any
        // other entry — and its detail carries the note text verbatim.
        assert_eq!(entry.acting_user, "j.smith");
        assert_eq!(entry.matter, "Acme v Beta");
        assert_eq!(entry.module, "sg.test.module");
        assert!(
            entry.detail.contains("module commentary"),
            "note detail must contain the note text, got {:?}",
            entry.detail
        );
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn storage_put_records_full_attribution() {
        // ATTRIBUTION chokepoint (spec §7): a granted storage put must log the
        // acting HUMAN (not the module alone), the current matter, the
        // host-pinned module id, the EXACT capability invoked, and a detail that
        // identifies the scope+key. A chokepoint that logged the wrong
        // user/module/detail would otherwise pass every existing test.
        let mut core = core_with(vec![Capability::Storage(StorageScope::Own)]);
        core.storage_put(StorageScope::Own, "k", b"v".to_vec())
            .unwrap();

        assert_eq!(core.audit.len(), 1, "a granted put logs exactly one entry");
        let entry = &core.audit.entries()[0];
        assert_eq!(entry.acting_user, "j.smith", "attributed to the human");
        assert_eq!(
            entry.matter, "Acme v Beta",
            "attributed to the current matter"
        );
        assert_eq!(
            entry.module, "sg.test.module",
            "attributed to the host-pinned module"
        );
        assert_eq!(
            entry.capability,
            Capability::Storage(StorageScope::Own),
            "the exact capability invoked is recorded"
        );
        assert!(
            entry.detail.contains("storage put own/k"),
            "detail must identify scope+key, got {:?}",
            entry.detail
        );
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn storage_clear_drains_namespace_audited_and_default_deny() {
        // #3: a mediated clear drains THIS module's scratch, is audited
        // (check -> log -> act), and is default-deny without the storage grant.
        let mut core = core_with(vec![Capability::Storage(StorageScope::Own)]);
        core.storage_put(StorageScope::Own, "a", b"1".to_vec())
            .unwrap();
        core.storage_put(StorageScope::Own, "b", b"2".to_vec())
            .unwrap();

        let removed = core.storage_clear(StorageScope::Own).unwrap();
        assert_eq!(removed, 2, "both of this module's keys are drained");
        assert_eq!(core.storage_get(StorageScope::Own, "a").unwrap(), None);
        assert_eq!(core.storage_get(StorageScope::Own, "b").unwrap(), None);

        assert!(core.audit.verify_chain());
        let clears: Vec<_> = core
            .audit
            .entries()
            .iter()
            .filter(|e| e.detail.contains("storage clear own"))
            .collect();
        assert_eq!(clears.len(), 1, "exactly one clear is logged");
        assert_eq!(clears[0].capability, Capability::Storage(StorageScope::Own));

        // Default-deny: no grant -> refused, and a denied clear leaves NO audit entry.
        let mut ungranted = core_with(vec![]);
        let before = ungranted.audit.len();
        assert!(matches!(
            ungranted.storage_clear(StorageScope::Own),
            Err(CoreError::Denied(_))
        ));
        assert_eq!(
            ungranted.audit.len(),
            before,
            "a denied clear leaves no audit entry"
        );
    }

    #[test]
    fn egress_send_records_destination_and_byte_count() {
        // The SUCCESS entry for a granted egress must name the destination
        // capability and carry the destination + byte count in the detail, so the
        // audit log shows exactly what left (and how much).
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);
        core.egress_send("counsel-vault", b"hello").unwrap();

        assert_eq!(core.audit.len(), 1, "a granted send logs exactly one entry");
        let entry = &core.audit.entries()[0];
        assert_eq!(
            entry.capability,
            Capability::Egress("counsel-vault".into()),
            "the named destination capability is recorded"
        );
        assert!(
            entry.detail.contains("egress to counsel-vault"),
            "detail must name the destination, got {:?}",
            entry.detail
        );
        assert!(
            entry.detail.contains("5 bytes"),
            "detail must carry the byte count (5), got {:?}",
            entry.detail
        );
        // Attribution holds for egress too.
        assert_eq!(entry.acting_user, "j.smith");
        assert_eq!(entry.matter, "Acme v Beta");
        assert_eq!(entry.module, "sg.test.module");
        assert!(core.audit.verify_chain());
    }

    // ---- egress_fetch (the INGRESS twin of egress_send) -----------------------

    #[test]
    fn egress_fetch_with_no_grant_at_all_is_refused_and_fetches_nothing() {
        // Default-deny: no egress grant -> fetch refused, NOTHING fetched, and (like
        // every other mediated method) a default-deny refusal writes NO audit entry.
        let mut core = core_with(vec![]); // default-deny
                                          // Seed a fetch response so it is the GATE, not the sink, that blocks.
        core.set_egress_for_test(
            InMemoryEgress::new().with_fetch_response("counsel-vault", b"raw bytes".to_vec()),
        );
        let err = core.egress_fetch("counsel-vault", b"req").unwrap_err();
        assert!(matches!(err, CoreError::Denied(Capability::Egress(_))));
        // Default-deny refusal logs nothing.
        assert_eq!(
            core.audit.len(),
            0,
            "ungranted fetch must leave no audit entry"
        );
    }

    #[test]
    fn egress_fetch_with_no_granted_destination_is_refused() {
        // Grant a DIFFERENT destination than the one we try to fetch from.
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);
        core.set_egress_for_test(
            InMemoryEgress::new().with_fetch_response("evil.example", b"loot".to_vec()),
        );
        let err = core.egress_fetch("evil.example", b"req").unwrap_err();
        match err {
            CoreError::Denied(Capability::Egress(d)) if d == "evil.example" => {}
            other => panic!("expected Denied(Egress(evil.example)), got {other:?}"),
        }
        // A refused fetch leaves no audit entry.
        assert_eq!(
            core.audit.len(),
            0,
            "refused fetch must leave no audit entry"
        );
    }

    #[test]
    fn egress_fetch_to_a_wildcard_or_all_routes_destination_is_refused() {
        // A wildcard / all-routes destination is ambient egress by another name; it
        // can never be granted (validate() refuses it) so the gate rejects the fetch
        // and nothing is fetched / logged. Cover both the broker reject (the cap was
        // never grantable) for a few ambient forms.
        let mut core = core_with(vec![]);
        core.set_egress_for_test(
            InMemoryEgress::new().with_fetch_response("counsel-vault", b"x".to_vec()),
        );
        for bad in ["*", "0.0.0.0/0", "::/0", "0.0.0.0"] {
            let err = core.egress_fetch(bad, b"req").unwrap_err();
            assert!(
                matches!(err, CoreError::Denied(Capability::Egress(_))),
                "ambient destination {bad:?} must be refused at the gate, got {err:?}"
            );
        }
        assert_eq!(
            core.audit.len(),
            0,
            "no ambient-destination fetch may be logged"
        );
    }

    #[test]
    fn egress_fetch_to_granted_destination_returns_seeded_bytes_and_audits() {
        // The happy path: a granted, configured, seeded destination -> fetch returns
        // exactly the seeded bytes AND writes one audit entry that names the
        // destination + REQUEST byte count, with NO fetched cleartext.
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);
        core.set_egress_for_test(
            InMemoryEgress::new().with_fetch_response("counsel-vault", b"raw .eml bytes".to_vec()),
        );

        let got = core.egress_fetch("counsel-vault", b"sync-plan").unwrap();
        assert_eq!(
            got,
            b"raw .eml bytes".to_vec(),
            "fetch returns the seeded bytes"
        );

        // Exactly one audit entry, attributed + naming the destination.
        assert_eq!(
            core.audit.len(),
            1,
            "a granted fetch logs exactly one entry"
        );
        let entry = &core.audit.entries()[0];
        assert_eq!(
            entry.capability,
            Capability::Egress("counsel-vault".into()),
            "the named destination capability is recorded"
        );
        assert!(
            entry.detail.contains("egress fetch from counsel-vault"),
            "detail must name the destination, got {:?}",
            entry.detail
        );
        // The REQUEST length is logged ("sync-plan" = 9 bytes); the RESPONSE bytes
        // are NEVER logged.
        assert!(
            entry.detail.contains("request 9 bytes"),
            "detail must carry the request byte count, got {:?}",
            entry.detail
        );
        // CONFIDENTIALITY: the fetched cleartext must NEVER appear in the audit.
        assert!(
            !entry.detail.contains("raw .eml bytes") && !entry.detail.contains(".eml"),
            "audit detail must never carry the fetched cleartext, got {:?}",
            entry.detail
        );
        // Attribution holds for fetch too.
        assert_eq!(entry.acting_user, "j.smith");
        assert_eq!(entry.matter, "Acme v Beta");
        assert_eq!(entry.module, "sg.test.module");
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn egress_fetch_logs_before_fetching_no_bytes_if_audit_fails() {
        // FAIL-CLOSED (mirrors F2 on egress_send): the audit entry is taken BEFORE
        // the fetch, so if the audit record fails the core must NOT reach the
        // endpoint and the caller gets the error, not bytes. We wire a FailingAudit
        // and a seeded fetch sink; a GRANTED fetch then reaches the log step, which
        // aborts. (Under fetch-then-log this would return bytes despite the failure.)
        let mut core = core_with_failing_audit(vec![Capability::Egress("counsel-vault".into())]);
        // Replace the sink with one that WOULD return bytes if reached.
        core.set_egress_for_test(
            InMemoryEgress::new().with_fetch_response("counsel-vault", b"secret mail".to_vec()),
        );
        let err = core.egress_fetch("counsel-vault", b"req").unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit must abort the fetch, got {err:?}"
        );
    }

    #[test]
    fn egress_fetch_from_configured_but_unseeded_destination_is_a_sink_error_after_audit() {
        // A GRANTED + configured destination with NO seeded response is
        // not-connected at the sink: the gate + log SUCCEED (the attempt is
        // attributable), then the sink errors. So the call errors AND one audit
        // entry exists (the logged-but-not-fetched attempt — the safe direction).
        let mut core = core_with(vec![Capability::Egress("counsel-vault".into())]);
        core.set_egress_for_test(InMemoryEgress::new().with_destination("counsel-vault"));
        let err = core.egress_fetch("counsel-vault", b"req").unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "an unseeded source must surface as a sink Backend error, got {err:?}"
        );
        // The ATTEMPT was logged before the sink failed (log-before-act).
        assert_eq!(
            core.audit.len(),
            1,
            "the fetch attempt is logged before the sink error"
        );
        assert!(core.audit.entries()[0]
            .detail
            .contains("egress fetch from counsel-vault"));
    }

    #[test]
    fn deny_revokes_one_destination_and_leaves_the_other() {
        // deny() revokes ONLY the named destination (spec §2.5), not all egress.
        // Grant two, deny one, and assert the denied one is now refused at the
        // Core chokepoint while the other still passes — exercising selective
        // revocation through the full check → act → log path.
        let mut core = core_with(vec![
            Capability::Egress("counsel-vault".into()),
            Capability::Egress("vault.internal.example".into()),
        ]);
        // Reconfigure the egress sink so the second destination is also a
        // configured endpoint (the broker is the gate; the sink is belt-and-braces).
        // F15: replace it via the supported test seam, not by assigning the private
        // `egress` field.
        core.set_egress_for_test(
            InMemoryEgress::new()
                .with_destination("counsel-vault")
                .with_destination("vault.internal.example"),
        );

        // Revoke only "counsel-vault".
        core.broker
            .deny(&Capability::Egress("counsel-vault".into()));

        // The denied destination is now refused at the Core, nothing leaves.
        let err = core.egress_send("counsel-vault", b"x").unwrap_err();
        match err {
            CoreError::Denied(Capability::Egress(d)) if d == "counsel-vault" => {}
            other => panic!("expected Denied(Egress(counsel-vault)), got {other:?}"),
        }

        // The other destination still passes the gate and is logged.
        core.egress_send("vault.internal.example", b"ok").unwrap();
        assert_eq!(
            core.egress.sent().len(),
            1,
            "only the still-granted send went out"
        );
        assert_eq!(core.egress.sent()[0].destination, "vault.internal.example");
        assert_eq!(core.audit.len(), 1, "only the successful send was logged");
    }

    #[test]
    fn storage_put_propagates_audit_record_error_fail_closed() {
        // FAIL-CLOSED: if the audit chokepoint cannot record, a brokered op must
        // propagate the Err and abort — never complete silently unlogged. Wire a
        // Core with a FailingAudit whose record() always Errs; a GRANTED put then
        // reaches act-then-log and the log step's Err must surface to the caller.
        let mut core = core_with_failing_audit(vec![Capability::Storage(StorageScope::Own)]);
        let err = core
            .storage_put(StorageScope::Own, "k", b"v".to_vec())
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit record must propagate as Err, got {err:?}"
        );
    }

    #[test]
    fn switch_context_re_attributes_and_audits_the_transition() {
        // A long-lived core that switches matter/user must (a) record the
        // transition and (b) attribute SUBSEQUENT brokered calls to the NEW
        // matter/user — never silently keep the old attribution.
        let mut core = core_with(vec![Capability::Storage(StorageScope::Own)]);

        core.switch_context("Beta v Gamma", "k.lee").unwrap();

        // The switch itself recorded a transition entry under the OLD attribution.
        assert_eq!(
            core.audit.len(),
            1,
            "the switch must record one audit entry"
        );
        let transition = &core.audit.entries()[0];
        assert_eq!(transition.capability, Capability::AuditNote);
        assert_eq!(
            transition.acting_user, "j.smith",
            "transition logged under the OLD user"
        );
        assert_eq!(
            transition.matter, "Acme v Beta",
            "transition logged under the OLD matter"
        );
        assert!(
            transition.detail.contains("Beta v Gamma") && transition.detail.contains("k.lee"),
            "transition detail must capture the new matter+user, got {:?}",
            transition.detail
        );

        // A subsequent granted op is attributed to the NEW matter/user.
        core.storage_put(StorageScope::Own, "k", b"v".to_vec())
            .unwrap();
        let entry = &core.audit.entries()[1];
        assert_eq!(entry.matter, "Beta v Gamma", "new attribution after switch");
        assert_eq!(entry.acting_user, "k.lee", "new attribution after switch");

        // The chain still verifies across the switch.
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn switch_context_rejects_malformed_attribution_before_recording() {
        // H-2: a malformed new matter/user is rejected BEFORE any audit entry is
        // written and the context is left unchanged (fail-closed).
        let mut core = core_with(vec![]);
        for (m, u) in [
            ("", "k.lee"),                    // empty matter
            ("   ", "k.lee"),                 // whitespace-only matter
            ("Beta v Gamma", ""),             // empty user
            ("Beta\nv Gamma", "k.lee"),       // control char in matter
            ("Beta v Gamma", "k\u{2028}lee"), // line separator in user
            (&"x".repeat(257), "k.lee"),      // over-length matter (cap 256)
        ] {
            let err = core.switch_context(m, u).unwrap_err();
            assert!(
                matches!(err, CoreError::Backend(_)),
                "malformed switch ({m:?},{u:?}) must be a Backend error, got {err:?}"
            );
        }
        // Nothing recorded, context unchanged.
        assert_eq!(
            core.audit.len(),
            0,
            "a rejected switch writes no audit entry"
        );
        assert_eq!(core.context.current_matter().name, "Acme v Beta");
        assert_eq!(core.context.acting_user().display_name, "j.smith");

        // A well-formed switch at exactly the cap still works.
        core.switch_context(&"y".repeat(256), "k.lee").unwrap();
        assert_eq!(core.audit.len(), 1);
    }

    #[test]
    fn audit_note_rejects_oversized_event() {
        // M-6: an over-cap note (>4 KiB) is rejected with a Backend error and not
        // recorded; a note at the cap is accepted.
        let mut core = core_with(vec![]);
        let too_big = "x".repeat(4097);
        let err = core.audit_note(&too_big).unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "oversized note must be refused, got {err:?}"
        );
        assert_eq!(core.audit.len(), 0, "a rejected note writes no entry");
        // Exactly at the cap is accepted.
        core.audit_note(&"y".repeat(4096)).unwrap();
        assert_eq!(core.audit.len(), 1);
    }

    #[test]
    fn switch_context_is_fail_closed_when_audit_fails() {
        // If the transition cannot be recorded, switch_context must propagate the
        // Err and NOT change attribution (never switch unlogged).
        let mut core = core_with_failing_audit(vec![]);
        let err = core.switch_context("Beta v Gamma", "k.lee").unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit record must abort the switch, got {err:?}"
        );
        // Context unchanged: still the original matter/user.
        assert_eq!(core.context.current_matter().name, "Acme v Beta");
        assert_eq!(core.context.acting_user().display_name, "j.smith");
    }

    #[test]
    fn audit_note_propagates_audit_record_error_fail_closed() {
        // FAIL-CLOSED for the ungated path too: even an audit.note (which needs no
        // capability) must abort if it cannot be recorded — a module must not be
        // told its note landed when the record failed.
        let mut core = core_with_failing_audit(vec![]);
        let err = core.audit_note("commentary").unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit record must propagate from audit_note, got {err:?}"
        );
    }

    // ---- matter.read / document.transform mediated methods (Part A) ---------

    fn seeded_store() -> InMemoryMatterStore {
        let mut s = InMemoryMatterStore::new();
        s.insert(1, DataClass::Document, "memo: Project Condor terms");
        s.insert(2, DataClass::Document, "second document");
        s.insert(3, DataClass::Party, "Acme Holdings Pte Ltd");
        s
    }

    #[test]
    fn matter_read_activity_denied_without_grant() {
        // Default-deny: matter.read:document is NOT matter.read:activity.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_store(),
        );
        let err = core.matter_read_activity().unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::Denied(Capability::MatterRead(DataClass::Activity))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn matter_read_activity_projects_document_touches_cleartext_free() {
        let mut core = core_with_docs(
            vec![
                Capability::MatterRead(DataClass::Document),
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Activity),
            ],
            seeded_store(),
        );
        // Generate brokered document touches (these are the activity).
        core.matter_read_text(1, DataClass::Document).unwrap();
        core.document_transform(1, DataClass::Document, |s| s.to_string())
            .unwrap();

        let events = core.matter_read_activity().unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.kind == ActivityEventKind::Read(DataClass::Document)),
            "a document read is projected"
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == ActivityEventKind::Transform),
            "a document transform is projected"
        );
        // Projected scope: current user, with module attribution + timestamp.
        assert!(events.iter().all(|e| e.actor == "j.smith"));
        assert!(events.iter().all(|e| e.module == "sg.test.module"));
        assert!(events
            .iter()
            .all(|e| e.timestamp_millis == 1_700_000_000_000));
        // The trail read NEVER projects itself (no Activity-class events).
        assert!(
            events
                .iter()
                .all(|e| e.kind != ActivityEventKind::Read(DataClass::Activity)),
            "the activity-trail read must never appear as an event"
        );
        // The seam is itself audited, count-only (no cleartext detail).
        assert!(core.audit().verify_chain());
        assert!(core.audit().entries().iter().any(|e| e.capability
            == Capability::MatterRead(DataClass::Activity)
            && e.detail.contains("matter read activity")));
    }

    #[test]
    fn matter_read_activity_excludes_other_users() {
        let mut core = core_with_docs(
            vec![
                Capability::MatterRead(DataClass::Document),
                Capability::MatterRead(DataClass::Activity),
            ],
            seeded_store(),
        );
        core.matter_read_text(1, DataClass::Document).unwrap(); // j.smith touch
        core.switch_context("Acme v Beta", "other.user").unwrap();
        core.matter_read_text(2, DataClass::Document).unwrap(); // other.user touch
        core.switch_context("Acme v Beta", "j.smith").unwrap();

        let events = core.matter_read_activity().unwrap();
        let doc_reads = events
            .iter()
            .filter(|e| e.kind == ActivityEventKind::Read(DataClass::Document))
            .count();
        assert_eq!(
            doc_reads, 1,
            "only the current user's touch is projected, got {doc_reads}"
        );
    }

    #[test]
    fn matter_list_default_deny_refused_with_no_audit() {
        // Default-deny: no matter.read grant -> list refused, ZERO audit entries.
        let mut core = core_with_docs(vec![], seeded_store());
        let err = core.matter_list_docs(DataClass::Document).unwrap_err();
        match err {
            CoreError::Denied(Capability::MatterRead(DataClass::Document)) => {}
            other => panic!("expected Denied(MatterRead(Document)), got {other:?}"),
        }
        assert_eq!(
            core.audit.len(),
            0,
            "a refused list must leave no audit entry"
        );
    }

    #[test]
    fn matter_read_default_deny_refused_with_no_audit() {
        let mut core = core_with_docs(vec![], seeded_store());
        let err = core.matter_read_text(1, DataClass::Document).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Denied(Capability::MatterRead(DataClass::Document))
        ));
        assert_eq!(
            core.audit.len(),
            0,
            "a refused read must leave no audit entry"
        );
    }

    #[test]
    fn document_transform_default_deny_refused_with_no_audit() {
        // No document.transform grant -> refused, nothing rewritten, no audit.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_store(),
        );
        let err = core
            .document_transform(1, DataClass::Document, |_| "X".to_string())
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Denied(Capability::DocumentTransform)
        ));
        assert_eq!(
            core.audit.len(),
            0,
            "a refused transform must leave no audit entry"
        );
        // Content untouched. (F15: via the supported test seam, not the private field.)
        assert_eq!(
            core.raw_content_for_test(1),
            Some("memo: Project Condor terms")
        );
    }

    #[test]
    fn matter_list_entitlement_filters_to_granted_class() {
        // Granted Document only: list returns only Document-class docs; the Party
        // class is refused entirely (not granted).
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_store(),
        );
        let docs = core.matter_list_docs(DataClass::Document).unwrap();
        let ids: Vec<u64> = docs.iter().map(|d| d.id).collect();
        assert_eq!(ids, vec![1, 2], "only Document-class docs are listed");
        assert!(docs.iter().all(|d| d.class == DataClass::Document));

        // The non-granted Party class is refused (default-deny per class).
        let err = core.matter_list_docs(DataClass::Party).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Denied(Capability::MatterRead(DataClass::Party))
        ));
    }

    #[test]
    fn matter_read_entitlement_blocks_wrong_class_id() {
        // Granted Document: reading doc 3 (a Party doc) under Document returns
        // not-found — its content is never reachable via a Document grant.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_store(),
        );
        assert_eq!(
            core.matter_read_text(1, DataClass::Document).unwrap(),
            "memo: Project Condor terms"
        );
        let err = core.matter_read_text(3, DataClass::Document).unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "wrong-class id must be not-found, got {err:?}"
        );
    }

    #[test]
    fn matter_read_records_full_attribution() {
        // A granted read logs the human, matter, host-pinned module, the exact
        // matter.read:<class> capability, and a detail naming the doc + class.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_store(),
        );
        core.matter_read_text(1, DataClass::Document).unwrap();
        assert_eq!(core.audit.len(), 1);
        let e = &core.audit.entries()[0];
        assert_eq!(e.acting_user, "j.smith");
        assert_eq!(e.matter, "Acme v Beta");
        assert_eq!(e.module, "sg.test.module");
        assert_eq!(e.capability, Capability::MatterRead(DataClass::Document));
        assert!(
            e.detail.contains("matter read doc 1"),
            "detail must name the doc, got {:?}",
            e.detail
        );
        assert!(
            e.detail.contains("document"),
            "detail must name the class, got {:?}",
            e.detail
        );
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn document_transform_rewrites_content_and_audits() {
        // A granted transform (document.transform + matter.read:document) reads,
        // applies f in the core, writes back, and audits — and the chain holds.
        let mut core = core_with_docs(
            vec![
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Document),
            ],
            seeded_store(),
        );
        core.document_transform(1, DataClass::Document, |s| {
            s.replace("Condor", "[REDACTED]")
        })
        .unwrap();
        // Content was rewritten in place in the store. (F15: via the supported seam.)
        assert_eq!(
            core.raw_content_for_test(1),
            Some("memo: Project [REDACTED] terms")
        );
        // The transform was audited under document.transform with attribution.
        let last = core.audit.entries().last().unwrap();
        assert_eq!(last.capability, Capability::DocumentTransform);
        assert_eq!(last.acting_user, "j.smith");
        assert_eq!(last.matter, "Acme v Beta");
        assert!(
            last.detail.contains("document transform doc 1"),
            "got {:?}",
            last.detail
        );
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn document_transform_fail_closed_does_not_persist() {
        // FAIL-CLOSED: if the audit record errors, the content is NOT rewritten.
        let mut core = core_with_failing_audit(vec![
            Capability::DocumentTransform,
            Capability::MatterRead(DataClass::Document),
        ]);
        core.seed_doc_for_test(1, DataClass::Document, "original");
        let err = core
            .document_transform(1, DataClass::Document, |_| "rewritten".to_string())
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "failing audit must abort the transform"
        );
        // Content unchanged: the write-back never happened. (F15: via the seam.)
        assert_eq!(core.raw_content_for_test(1), Some("original"));
    }

    // ---- F2 / F3 / F8 / F9: log-before-act ordering + transform audit trail ----

    #[test]
    fn egress_send_logs_before_sending_no_send_if_audit_fails() {
        // F2 (Critical): the audit entry is taken BEFORE the irreversible send, so
        // if the audit record fails the payload must NEVER leave the box. With the
        // old act-then-log order this test would observe a sent record despite the
        // audit failing — exactly the unrecorded-send hole F2 closes.
        let mut core = core_with_failing_audit(vec![Capability::Egress("counsel-vault".into())]);
        let err = core.egress_send("counsel-vault", b"secret").unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit must abort the send, got {err:?}"
        );
        // NOTHING left the box: log-before-act means the failed log aborted before
        // the send. (The proof of the ordering: under send-then-log this would be 1.)
        assert!(
            core.egress_sent_for_test().is_empty(),
            "log-before-send: a failed audit must leave NO sent record"
        );
    }

    #[test]
    fn storage_put_logs_before_writing_no_write_if_audit_fails() {
        // F3 (High): the audit entry is taken BEFORE the durable write, so a failing
        // audit must leave the store UNCHANGED. We read the backing store directly
        // (the mediated `storage_get` also fails-closed under the failing audit, so
        // it can't observe the state) to prove the value never landed.
        let mut core = core_with_failing_audit(vec![Capability::Storage(StorageScope::Own)]);
        let err = core
            .storage_put(StorageScope::Own, "k", b"v".to_vec())
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit must abort the put, got {err:?}"
        );
        // The store never received the write (log-before-act): under put-then-log
        // this would be Some(b"v").
        assert_eq!(
            core.raw_storage_get_for_test(StorageScope::Own, "k")
                .unwrap(),
            None,
            "log-before-put: a failed audit must leave NO stored value"
        );
    }

    #[test]
    fn document_transform_audits_the_read_and_the_transform_bounds() {
        // F8 (Medium): a transform EXERCISES matter.read, so a granted transform
        // must audit the read under matter.read:<class> in ADDITION to the
        // transform entries. F9 (Medium): a "start" entry is written BEFORE the
        // module closure runs. Assert the full ordered trail:
        //   [0] matter.read:document   (F8 — the read the transform performed)
        //   [1] document.transform … start    (F9 — before f)
        //   [2] document.transform … complete  (after f, before write-back)
        let mut core = core_with_docs(
            vec![
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Document),
            ],
            seeded_store(),
        );
        core.document_transform(1, DataClass::Document, |s| {
            s.replace("Condor", "[REDACTED]")
        })
        .unwrap();

        let entries = core.audit().entries();
        assert_eq!(
            entries.len(),
            3,
            "transform writes read + start + complete, got {entries:?}"
        );

        // [0] the READ (F8) — its own capability, not document.transform.
        assert_eq!(
            entries[0].capability,
            Capability::MatterRead(DataClass::Document)
        );
        assert!(
            entries[0].detail.contains("matter read") && entries[0].detail.contains("doc=1"),
            "read entry must name the doc, got {:?}",
            entries[0].detail
        );
        // [1] the START (F9) under document.transform, BEFORE the rewrite.
        assert_eq!(entries[1].capability, Capability::DocumentTransform);
        assert!(
            entries[1].detail.contains("start"),
            "a start entry must precede the closure, got {:?}",
            entries[1].detail
        );
        // [2] the COMPLETE under document.transform, AFTER the rewrite.
        assert_eq!(entries[2].capability, Capability::DocumentTransform);
        assert!(
            entries[2].detail.contains("complete"),
            "a complete entry must follow the closure, got {:?}",
            entries[2].detail
        );

        // Confidentiality split preserved: NO entry carries the matched cleartext.
        for e in entries {
            assert!(
                !e.detail.contains("Condor"),
                "audit detail must never carry cleartext, got {:?}",
                e.detail
            );
            assert!(
                !e.detail.contains("[REDACTED]"),
                "audit detail must never carry rewritten cleartext, got {:?}",
                e.detail
            );
        }

        // The rewrite still landed, and the chain verifies.
        assert_eq!(
            core.raw_content_for_test(1),
            Some("memo: Project [REDACTED] terms")
        );
        assert!(core.audit().verify_chain());
    }

    #[test]
    fn document_transform_logs_start_before_a_panicking_closure() {
        // F9 (Medium): even if the module closure PANICS, the "start" entry (and the
        // F8 read entry) were already recorded BEFORE f ran, so the panic leaves a
        // trail that the transform was attempted over the cleartext. Catch the panic
        // and inspect the audit the Core left behind.
        use std::panic::AssertUnwindSafe;
        let mut core = core_with_docs(
            vec![
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Document),
            ],
            seeded_store(),
        );
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            core.document_transform(1, DataClass::Document, |_| panic!("module closure blew up"))
        }));
        assert!(
            result.is_err(),
            "the closure panic must propagate out of the transform"
        );

        // The pre-closure trail survives: the read (F8) and the start (F9) entries
        // were both recorded before f panicked.
        let entries = core.audit().entries();
        assert_eq!(
            entries.len(),
            2,
            "read + start were logged before the panic, got {entries:?}"
        );
        assert_eq!(
            entries[0].capability,
            Capability::MatterRead(DataClass::Document)
        );
        assert_eq!(entries[1].capability, Capability::DocumentTransform);
        assert!(entries[1].detail.contains("start"));
        // No "complete" entry (the closure never returned).
        assert!(
            !entries.iter().any(|e| e.detail.contains("complete")),
            "no complete entry may exist when the closure panicked"
        );
        // The content was NOT rewritten (the write-back is after the closure).
        assert_eq!(
            core.raw_content_for_test(1),
            Some("memo: Project Condor terms")
        );
    }

    // ---- matter.read:metadata mediated method (the metadata seam) -------------

    /// A hand-written `firmos.meta/1` canonical doc (the PRODUCER does not exist
    /// yet — the contract decouples reader from writer, proposal §8). It covers,
    /// deliberately: a multi-value `To`, an explicit `Bcc`, a `Subject` with `:`,
    /// `%`, and a non-ASCII char (percent-encoded), and a MISSING field (no `cc`,
    /// no `reply-to`, no `message-id` line). These cleartext fragments are then
    /// asserted ABSENT from the audit detail.
    const SEEDED_META: &str = "firmos.meta/1\n\
        from Jane%20Roe%20%3Cjane.roe@acme.example%3E\n\
        to alice@acme.example\n\
        to bob@acme.example\n\
        bcc hidden-watcher@spy.example\n\
        subject Re%3A%20Spend%2050%25%20%E2%80%94%20Project%20Condor\n\
        date 2026-06-19T09:30:00Z";

    fn seeded_meta_store() -> InMemoryMatterStore {
        let mut s = InMemoryMatterStore::new();
        s.insert(10, DataClass::Metadata, SEEDED_META);
        // A Document-class doc at a different id, to prove a metadata grant cannot
        // reach it and a metadata read of a Document id is not-found after the gate.
        s.insert(11, DataClass::Document, "memo: Project Condor terms");
        s
    }

    #[test]
    fn matter_read_metadata_returns_typed_value_with_bcc_multivalue_and_no_fabrication() {
        // Granted matter.read:metadata: the seam returns the typed headers with the
        // Bcc surfaced, the multi-value To in order, a lossless round-trip of the
        // : / % / non-ASCII subject, and the missing fields as None/empty (never
        // fabricated).
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Metadata)],
            seeded_meta_store(),
        );
        let h = core.matter_read_metadata(10, DataClass::Metadata).unwrap();

        assert_eq!(h.from, vec!["Jane Roe <jane.roe@acme.example>"]);
        assert_eq!(
            h.to,
            vec!["alice@acme.example", "bob@acme.example"],
            "multi-value To, in order"
        );
        assert_eq!(
            h.bcc,
            vec!["hidden-watcher@spy.example"],
            "Bcc surfaced, never dropped"
        );
        assert_eq!(
            h.subject.as_deref(),
            Some("Re: Spend 50% — Project Condor"),
            "lossless round-trip of : % and the em-dash"
        );
        assert_eq!(h.date.as_deref(), Some("2026-06-19T09:30:00Z"));
        // MISSING fields are None / empty — NEVER fabricated.
        assert!(h.cc.is_empty(), "absent cc stays empty");
        assert!(h.reply_to.is_empty(), "absent reply-to stays empty");
        assert_eq!(h.message_id, None, "absent message-id stays None");
    }

    #[test]
    fn matter_read_metadata_audit_carries_no_header_value() {
        // CONFIDENTIALITY: the audit detail for a metadata read must carry COUNTS /
        // ATTRIBUTION ONLY — never an address, subject, or Bcc value. Assert that
        // none of the seeded cleartext fragments appears in ANY audit entry's detail.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Metadata)],
            seeded_meta_store(),
        );
        core.matter_read_metadata(10, DataClass::Metadata).unwrap();

        // The forbidden cleartext fragments (decoded AND raw-percent forms): every
        // address, the display name, and decoded + encoded subject tokens.
        let forbidden = [
            "jane.roe@acme.example",
            "Jane Roe",
            "alice@acme.example",
            "bob@acme.example",
            "hidden-watcher@spy.example",
            "spy.example",
            "Project Condor",
            "Spend 50%",
            "Re: Spend",
            // raw-encoded forms, in case detail echoed the stored bytes verbatim
            "%E2%80%94",
            "%3C",
            "Jane%20Roe",
        ];
        for entry in core.audit().entries() {
            for needle in forbidden {
                assert!(
                    !entry.detail.contains(needle),
                    "audit detail must never carry a header value; found {needle:?} in {:?}",
                    entry.detail
                );
            }
        }
        // The entries that DO exist are value-free: doc id + class, and a recipient
        // COUNT (a number). from(1)+to(2)+bcc(1) = 4 recipients.
        let entries = core.audit().entries();
        assert_eq!(
            entries.len(),
            2,
            "a granted metadata read logs the attempt + the count"
        );
        assert_eq!(
            entries[0].capability,
            Capability::MatterRead(DataClass::Metadata)
        );
        assert!(entries[0].detail.contains("matter read metadata doc 10"));
        assert!(entries[0].detail.contains("metadata"), "class is named");
        assert!(
            entries[1].detail.contains("4 recipients"),
            "the count entry records a NUMBER, got {:?}",
            entries[1].detail
        );
        // Full attribution holds, and the chain verifies.
        assert_eq!(entries[1].acting_user, "j.smith");
        assert_eq!(entries[1].matter, "Acme v Beta");
        assert_eq!(entries[1].module, "sg.test.module");
        assert!(core.audit().verify_chain());
    }

    #[test]
    fn matter_read_metadata_default_deny_refused_with_no_audit() {
        // Default-deny: without matter.read:metadata, the read is refused and writes
        // NO audit entry (a call that never happened leaves no trace).
        let mut core = core_with_docs(vec![], seeded_meta_store());
        let err = core
            .matter_read_metadata(10, DataClass::Metadata)
            .unwrap_err();
        match err {
            CoreError::Denied(Capability::MatterRead(DataClass::Metadata)) => {}
            other => panic!("expected Denied(MatterRead(Metadata)), got {other:?}"),
        }
        assert_eq!(
            core.audit.len(),
            0,
            "a refused metadata read must leave no audit entry"
        );
    }

    #[test]
    fn matter_read_metadata_a_document_grant_cannot_reach_metadata() {
        // Finer Chinese wall: a module granted ONLY matter.read:document cannot read
        // headers — the metadata grant is SEPARATE. Reading id 10 (a metadata doc)
        // under a Document grant + Document class is not-found after the gate; and a
        // Metadata read is refused outright (no Metadata grant).
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_meta_store(),
        );
        // Refused: no metadata grant at all.
        let err = core
            .matter_read_metadata(10, DataClass::Metadata)
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Denied(Capability::MatterRead(DataClass::Metadata))
        ));
        assert_eq!(
            core.audit.len(),
            0,
            "the refused metadata read logs nothing"
        );
    }

    #[test]
    fn matter_read_metadata_wrong_class_is_not_found_after_the_gate() {
        // Granted matter.read:metadata, but id 11 is a DOCUMENT-class doc: the
        // entitlement filter yields not-found AFTER the gate (its content is never
        // reachable via a metadata grant) — and the ATTEMPT is still audited (it was
        // a real brokered call), exactly like matter_read_text.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Metadata)],
            seeded_meta_store(),
        );
        let err = core
            .matter_read_metadata(11, DataClass::Metadata)
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "wrong-class id must be not-found, got {err:?}"
        );
        // The read attempt was audited (one entry: the attempt), but NOT the count
        // entry (no successful parse happened).
        assert_eq!(
            core.audit.len(),
            1,
            "a not-found metadata read still audits the attempt"
        );
        let e = &core.audit.entries()[0];
        assert_eq!(e.capability, Capability::MatterRead(DataClass::Metadata));
        assert!(e.detail.contains("matter read metadata doc 11"));
        // And the detail is value-free (there is no value to leak; defensive check).
        assert!(
            !e.detail.contains("recipients"),
            "no count entry for a not-found read"
        );
    }

    #[test]
    fn matter_read_metadata_unknown_version_fails_closed_after_auditing_the_read() {
        // A stored doc whose canonical form has an UNKNOWN version line must FAIL
        // CLOSED (Err), never be mis-read as v1 — but the READ that fetched those
        // bytes was a real brokered call, so the attempt is still audited (the parse
        // error surfaces AFTER the audit-before-return).
        let mut s = InMemoryMatterStore::new();
        s.insert(20, DataClass::Metadata, "firmos.meta/999\nto a@x.example");
        let mut core = core_with_docs(vec![Capability::MatterRead(DataClass::Metadata)], s);
        let err = core
            .matter_read_metadata(20, DataClass::Metadata)
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "unknown version must fail closed, got {err:?}"
        );
        // The read attempt was audited before the parse error (no count entry — the
        // parse failed, so no parse-derived datum was recorded).
        assert_eq!(
            core.audit.len(),
            1,
            "the read attempt is logged before the parse error"
        );
        assert!(core.audit.entries()[0]
            .detail
            .contains("matter read metadata doc 20"));
        assert!(!core.audit.entries()[0].detail.contains("recipients"));
    }

    #[test]
    fn matter_read_metadata_malformed_line_is_skipped_not_panicked() {
        // A canonical doc with a malformed line (no space separator, and a bad %XX)
        // must SKIP those lines lossily and return the rest — never a panic, never a
        // fabrication. The good headers around the bad lines survive.
        let mut s = InMemoryMatterStore::new();
        s.insert(
            30,
            DataClass::Metadata,
            "firmos.meta/1\n\
             to good@x.example\n\
             noSpaceSeparatorMalformed\n\
             cc bad%zzvalue\n\
             subject ok",
        );
        let mut core = core_with_docs(vec![Capability::MatterRead(DataClass::Metadata)], s);
        let h = core.matter_read_metadata(30, DataClass::Metadata).unwrap();
        assert_eq!(h.to, vec!["good@x.example"], "good line survives");
        assert!(
            h.cc.is_empty(),
            "the bad-%XX cc line was skipped, not fabricated"
        );
        assert_eq!(
            h.subject.as_deref(),
            Some("ok"),
            "the trailing good line survives"
        );
        // The read + count entries exist; only to(1) is a recipient here.
        assert_eq!(core.audit.len(), 2);
        assert!(core.audit.entries()[1].detail.contains("1 recipients"));
    }

    #[test]
    fn matter_read_metadata_fail_closed_when_audit_fails() {
        // FAIL-CLOSED (mirrors matter_read_text / egress): if the audit-before-return
        // record fails, the read aborts and NO parsed value is returned. Wire a
        // FailingAudit + grant the cap; the granted read reaches the log step, which
        // aborts before returning the headers.
        let mut core = core_with_failing_audit(vec![Capability::MatterRead(DataClass::Metadata)]);
        core.seed_doc_for_test(10, DataClass::Metadata, SEEDED_META);
        let err = core
            .matter_read_metadata(10, DataClass::Metadata)
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit must abort the metadata read, got {err:?}"
        );
    }

    // ---- matter_read_blob / document_transform_blob (the binary content path) ---

    /// A store with a BLOB document (id 1) + a TEXT document (id 2), both
    /// `document`-class — to exercise content-kind isolation in BOTH directions.
    fn seeded_blob_store() -> InMemoryMatterStore {
        let mut s = InMemoryMatterStore::new();
        s.insert_blob(
            1,
            DataClass::Document,
            b"\x00\x01PDF-ish\xff bytes".to_vec(),
        );
        s.insert(2, DataClass::Document, "a plain text document");
        s
    }

    #[test]
    fn matter_read_blob_default_deny_refused_with_no_audit() {
        // Default-deny: no matter.read grant -> blob read refused, ZERO audit.
        let mut core = core_with_docs(vec![], seeded_blob_store());
        let err = core.matter_read_blob(1, DataClass::Document).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Denied(Capability::MatterRead(DataClass::Document))
        ));
        assert_eq!(
            core.audit.len(),
            0,
            "a refused blob read must leave no audit entry"
        );
    }

    #[test]
    fn matter_read_blob_returns_bytes_and_audits_byte_length_only() {
        // A granted blob read returns the exact bytes AND logs the doc id + class +
        // BYTE LENGTH only — never the bytes themselves.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_blob_store(),
        );
        let bytes = core.matter_read_blob(1, DataClass::Document).unwrap();
        assert_eq!(
            bytes,
            b"\x00\x01PDF-ish\xff bytes".to_vec(),
            "exact bytes returned"
        );

        assert_eq!(
            core.audit.len(),
            1,
            "a granted blob read logs exactly one entry"
        );
        let e = &core.audit.entries()[0];
        assert_eq!(e.capability, Capability::MatterRead(DataClass::Document));
        assert_eq!(e.acting_user, "j.smith");
        assert_eq!(e.matter, "Acme v Beta");
        assert_eq!(e.module, "sg.test.module");
        assert!(
            e.detail.contains("matter read blob doc 1"),
            "names the doc, got {:?}",
            e.detail
        );
        assert!(
            e.detail.contains("document"),
            "names the class, got {:?}",
            e.detail
        );
        // BYTE LENGTH is recorded (16 bytes); the bytes themselves are NEVER logged.
        assert!(
            e.detail.contains("16 bytes"),
            "records the byte length, got {:?}",
            e.detail
        );
        assert!(
            !e.detail.contains("PDF-ish"),
            "audit must never carry the bytes, got {:?}",
            e.detail
        );
        assert!(core.audit.verify_chain());
    }

    #[test]
    fn matter_read_blob_on_a_text_doc_is_content_kind_mismatch_not_coerced() {
        // The load-bearing content-kind guard: matter_read_blob on a TEXT doc (id 2)
        // is a content-kind mismatch -> not-found AFTER the gate, never a coerced read
        // of the text bytes. The attempt is still audited (a real brokered call).
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_blob_store(),
        );
        let err = core.matter_read_blob(2, DataClass::Document).unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "text doc via _blob must be not-found, got {err:?}"
        );
        // Audited attempt, value-free, with 0 bytes (a count, never the text).
        assert_eq!(core.audit.len(), 1);
        let e = &core.audit.entries()[0];
        assert!(e.detail.contains("matter read blob doc 2"));
        assert!(
            e.detail.contains("0 bytes"),
            "a not-found blob read logs 0 bytes, got {:?}",
            e.detail
        );
        assert!(
            !e.detail.contains("plain text"),
            "never the coerced text, got {:?}",
            e.detail
        );
    }

    #[test]
    fn matter_read_text_on_a_blob_doc_is_content_kind_mismatch_not_coerced() {
        // The reverse guard: matter_read_text on a BLOB doc (id 1) is a content-kind
        // mismatch -> not-found, never a (lossy) coercion of the bytes to a String.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_blob_store(),
        );
        let err = core.matter_read_text(1, DataClass::Document).unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "blob doc via _text must be not-found, got {err:?}"
        );
    }

    #[test]
    fn matter_read_blob_fail_closed_when_audit_fails() {
        // FAIL-CLOSED (mirrors matter_read_text): if the audit-before-return record
        // fails, the read aborts and NO bytes are returned.
        let mut core = core_with_failing_audit(vec![Capability::MatterRead(DataClass::Document)]);
        core.seed_blob_doc_for_test(1, DataClass::Document, b"secret pdf bytes");
        let err = core.matter_read_blob(1, DataClass::Document).unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "a failing audit must abort the blob read, got {err:?}"
        );
    }

    #[test]
    fn document_transform_blob_rewrites_bytes_and_audits_lengths_only() {
        // A granted blob transform (document.transform + matter.read:document) reads
        // the bytes, applies f in the core, writes them back, and audits the read +
        // start + complete entries with INPUT/OUTPUT byte LENGTHS only (never bytes).
        let mut core = core_with_docs(
            vec![
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Document),
            ],
            seeded_blob_store(),
        );
        // f appends a sentinel so we can prove the rewrite landed + lengths differ.
        core.document_transform_blob(1, DataClass::Document, |b| {
            let mut out = b.to_vec();
            out.extend_from_slice(b"-REDACTED");
            out
        })
        .unwrap();

        // The bytes were rewritten in place (read back via the blob test seam).
        assert_eq!(
            core.raw_blob_for_test(1),
            Some(&b"\x00\x01PDF-ish\xff bytes-REDACTED"[..]),
            "the blob was rewritten in place"
        );

        // THREE entries, ordered read -> start -> complete, byte-length only.
        let entries = core.audit().entries();
        assert_eq!(
            entries.len(),
            3,
            "blob transform writes read + start + complete, got {entries:?}"
        );
        assert_eq!(
            entries[0].capability,
            Capability::MatterRead(DataClass::Document)
        );
        assert!(
            entries[0].detail.contains("matter read blob"),
            "read entry, got {:?}",
            entries[0].detail
        );
        assert!(
            entries[0].detail.contains("16 bytes"),
            "input length, got {:?}",
            entries[0].detail
        );
        assert_eq!(entries[1].capability, Capability::DocumentTransform);
        assert!(
            entries[1].detail.contains("start"),
            "start before f, got {:?}",
            entries[1].detail
        );
        assert!(
            entries[1].detail.contains("16 bytes"),
            "input length on start, got {:?}",
            entries[1].detail
        );
        assert_eq!(entries[2].capability, Capability::DocumentTransform);
        assert!(
            entries[2].detail.contains("complete"),
            "complete after f, got {:?}",
            entries[2].detail
        );
        assert!(
            entries[2].detail.contains("25 bytes"),
            "OUTPUT length on complete, got {:?}",
            entries[2].detail
        );
        // No entry carries the bytes (defensive).
        for e in entries {
            assert!(
                !e.detail.contains("PDF-ish"),
                "audit must never carry the bytes, got {:?}",
                e.detail
            );
            assert!(
                !e.detail.contains("REDACTED"),
                "audit must never carry the rewritten bytes, got {:?}",
                e.detail
            );
        }
        assert!(core.audit().verify_chain());
    }

    #[test]
    fn document_transform_blob_default_deny_refused_with_no_audit() {
        // No document.transform grant -> refused, nothing rewritten, no audit.
        let mut core = core_with_docs(
            vec![Capability::MatterRead(DataClass::Document)],
            seeded_blob_store(),
        );
        let err = core
            .document_transform_blob(1, DataClass::Document, |b| b.to_vec())
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Denied(Capability::DocumentTransform)
        ));
        assert_eq!(
            core.audit.len(),
            0,
            "a refused blob transform must leave no audit entry"
        );
        // Bytes untouched.
        assert_eq!(
            core.raw_blob_for_test(1),
            Some(&b"\x00\x01PDF-ish\xff bytes"[..])
        );
    }

    #[test]
    fn document_transform_blob_on_a_text_doc_is_not_found_not_coerced() {
        // A blob transform of a TEXT doc (id 2) is a content-kind mismatch ->
        // not-found after the checks. The bytes path never converts a text doc.
        let mut core = core_with_docs(
            vec![
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Document),
            ],
            seeded_blob_store(),
        );
        let err = core
            .document_transform_blob(2, DataClass::Document, |b| b.to_vec())
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "text doc via blob transform must be not-found, got {err:?}"
        );
        // The text doc is unchanged + still text (never became a blob).
        assert_eq!(core.raw_content_for_test(2), Some("a plain text document"));
        assert_eq!(core.raw_blob_for_test(2), None);
    }

    #[test]
    fn document_transform_blob_fail_closed_does_not_persist() {
        // FAIL-CLOSED: if the audit record errors, the bytes are NOT rewritten.
        let mut core = core_with_failing_audit(vec![
            Capability::DocumentTransform,
            Capability::MatterRead(DataClass::Document),
        ]);
        core.seed_blob_doc_for_test(1, DataClass::Document, b"original bytes");
        let err = core
            .document_transform_blob(1, DataClass::Document, |_| b"rewritten".to_vec())
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Backend(_)),
            "failing audit must abort the blob transform"
        );
        // Bytes unchanged: the write-back never happened.
        assert_eq!(core.raw_blob_for_test(1), Some(&b"original bytes"[..]));
    }

    #[test]
    fn document_transform_blob_logs_start_before_a_panicking_closure() {
        // Mirrors the text transform F9: even if the module closure PANICS, the read
        // + start entries were recorded BEFORE f ran (no complete entry), and the
        // bytes were NOT rewritten.
        use std::panic::AssertUnwindSafe;
        let mut core = core_with_docs(
            vec![
                Capability::DocumentTransform,
                Capability::MatterRead(DataClass::Document),
            ],
            seeded_blob_store(),
        );
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            core.document_transform_blob(1, DataClass::Document, |_| panic!("blob closure blew up"))
        }));
        assert!(result.is_err(), "the closure panic must propagate");
        let entries = core.audit().entries();
        assert_eq!(
            entries.len(),
            2,
            "read + start logged before the panic, got {entries:?}"
        );
        assert_eq!(
            entries[0].capability,
            Capability::MatterRead(DataClass::Document)
        );
        assert_eq!(entries[1].capability, Capability::DocumentTransform);
        assert!(entries[1].detail.contains("start"));
        assert!(
            !entries.iter().any(|e| e.detail.contains("complete")),
            "no complete on panic"
        );
        // Bytes unchanged (write-back is after the closure).
        assert_eq!(
            core.raw_blob_for_test(1),
            Some(&b"\x00\x01PDF-ish\xff bytes"[..])
        );
    }
}
