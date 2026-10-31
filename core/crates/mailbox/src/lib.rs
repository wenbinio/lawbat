// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Mailbox — the live-mail-source connector (SOURCE end of the email pipeline).
//!
//! A NATIVE first-party module SKELETON. It is the SOURCE of the email pipeline:
//!
//! ```text
//!   mailbox  (fetch live mail -> land .eml locally)
//!     -> extract  (parse .eml -> document)
//!     -> inbox    (triage -> worklist)
//! ```
//!
//! This crate builds out ONLY the `mailbox` stage: the connector that, GIVEN a
//! granted + consented NAMED source, would fetch new messages and yield raw
//! `.eml` bytes for `extract` to parse and the core to land as `document`s.
//!
//! ## The egress posture (the MOST sensitive primitive — read first)
//!
//! The platform is **LOCAL-ONLY / air-gapped by default, with NO network egress**
//! (CLAUDE.md non-negotiable). A live mail connector is allowed ONLY as the
//! architecture's *sanctioned exception*, and that exception is built around one
//! invariant:
//!
//! - **The CORE holds the socket; a module NEVER holds a raw socket.** This
//!   connector does not open a socket, hold a transport, or know an endpoint. To
//!   fetch, it hands the core a request plus a **NAMED, granted, consented
//!   destination** ([`NamedSource`]). The core policy-checks the destination,
//!   performs the fetch, logs it, and can revoke. Egress is **default-deny**:
//!   named destinations only, **never** a wildcard.
//! - **With NO grant, the connector does NOTHING** — it reports
//!   [`MailboxError::NotConnected`] and the app stays fully offline. The
//!   live-mail feature is strictly **opt-in, consented, and logged**; the default
//!   remains no-egress. This is the one place that is allowed to hold an egress
//!   grant at all, and it is empty until a firm consents to a specific source.
//!
//! This is the egress-HOLDING member of the pipeline — in deliberate contrast to
//! `inbox` and `redaction`, which hold `egress: []`. The justification for the
//! asymmetry is wholly in the *shape*: a named, consented, broker-checked,
//! audited, revocable destination is not ambient egress.
//!
//! ## STATUS: SKELETON (this increment — establishes the API SHAPE only)
//!
//! The brokered SHAPE, the type surface, the declared capabilities, the
//! named-source validation, and the confidentiality split are REAL and compile +
//! test green. The LIVE TRANSPORT is a STUB. **There is NO real network call, NO
//! socket, NO secret, NO baked-in endpoint, NO OAuth/Graph/IMAP client anywhere
//! in this crate.** "Fetching" is a deterministic read over an in-memory
//! [`MailSource`] (synthetic `.eml` fixtures) so the connector logic is testable
//! OFFLINE. The live M365/Exchange/IMAP transport + OAuth is a SEPARATE later
//! increment requiring the spec owner's sign-off — see the `TODO(core)` block on
//! [`MailConnector::sync_mailbox`]. We are buying the option here, not shipping a
//! working M365 client.
//!
//! ## Honest framing (do not overclaim — load-bearing)
//!
//! - **No model, no LLM, no network, no RNG — anywhere** (CLAUDE.md). The
//!   connector is deterministic: the same source + plan yields the same
//!   [`FetchResult`]. The live transport, when built, fetches bytes only; all
//!   parsing/triage happens DOWNSTREAM (`extract` / `inbox`).
//! - **The connector does not parse `.eml`.** It yields raw bytes; `extract` is
//!   the parser. The handoff to `extract` is noted but OUT OF SCOPE here.
//! - **Final placement into the matter store is the CORE's ingestion job.** This
//!   module lands `.eml` into its OWN `storage:own` namespace as a staging step;
//!   it never writes to the matter store directly (modules get no raw filesystem
//!   / matter-store access — spec §6). The core ingests the staged bytes into the
//!   matter store under the right data class.
//!
//! ## Confidentiality split: cleartext bytes vs. audit (mirrors redaction/inbox)
//!
//! A [`FetchResult`] carries the landed message IDs + counts for the in-process
//! pipeline — it carries **NO cleartext** subject / sender / address / body. The
//! raw `.eml` bytes flow to the staging store and to `extract`, never to the
//! audit chain. The **audit note** records ONLY counts (fetched / landed /
//! skipped) and the (config-supplied, audit-safe) source LABEL — **never** a
//! subject, sender, address, or any message content. So the tamper-evident audit
//! chain does not become a store of the very mail being ingested.

use std::collections::HashSet;

use runtime::{
    Audit, Capability, CapabilityBroker, CoreError, Egress, MatterContext, MatterStore, Storage,
    StorageScope,
};

/// A consented, NAMED live-mail source — the egress destination the core will be
/// asked to fetch from. OPAQUE + VALIDATED: it carries a config-supplied LABEL
/// (audit-safe, e.g. `acme-m365`) and the NAMED destination token the core's
/// egress broker checks (e.g. a firm-side, consented endpoint name).
///
/// CONSTRUCTION IS VALIDATED, mirroring the runtime's egress-destination posture
/// ([`runtime`]'s `egress:<named>` rule): the destination must be a single named
/// endpoint — non-empty (after trim), no embedded whitespace, no control chars,
/// no wildcard (`*`), and not an all-routes / broadcast / multicast / loopback
/// ambient form. A malformed source can never become a [`NamedSource`], so it can
/// never reach the broker as a granted destination. (The broker re-validates at
/// grant + at the sink; this is the module-side belt-and-braces so a bad config
/// fails CLOSED at construction, not silently at fetch time.)
///
/// The `label` is config (a source NAME), not matter data, so it is safe to show
/// in the audit note. The `destination` is the named egress endpoint; it is NEVER
/// a secret, a URL with credentials, or a baked-in vendor endpoint — those belong
/// in the (future, signed-off) live-transport increment, behind the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSource {
    /// A human/config-facing source NAME (audit-safe — a label, not matter data).
    label: String,
    /// The single, named egress destination the core's broker checks. Validated
    /// to the same shape as a `Capability::Egress` destination.
    destination: String,
}

impl NamedSource {
    /// Construct a validated named source. FALLIBLE: the `destination` must pass
    /// the runtime's egress-destination shape rule (single named endpoint — no
    /// empty/whitespace/control/wildcard/all-routes/broadcast/multicast/loopback)
    /// AND the `label` must be a non-empty, single-line, control-char-free token.
    /// A malformed source returns [`MailboxError::InvalidSource`] (never a panic),
    /// so it can never become a usable, sendable destination (fail-closed).
    pub fn new(
        label: impl Into<String>,
        destination: impl Into<String>,
    ) -> Result<Self, MailboxError> {
        let label = label.into();
        let destination = destination.into();
        // The destination must be a single named egress endpoint — reuse the
        // runtime's canonical rule so this module can never diverge from the
        // broker it will hand the destination to (no wildcard / all-routes /
        // ambient forms; no whitespace / control chars; non-empty after trim).
        if !runtime::capability::egress_destination_is_named(&destination) {
            return Err(MailboxError::InvalidSource);
        }
        // The label is rendered into the audit note — require a single, non-empty
        // token with no control chars / line separators, so a label can never
        // inject a line break into the audit detail or be empty/ambiguous there.
        if !label_is_audit_safe(&label) {
            return Err(MailboxError::InvalidSource);
        }
        Ok(Self { label, destination })
    }

    /// The config-supplied source LABEL (audit-safe — a name, never matter data).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The single, named egress destination the core's broker checks. NEVER a
    /// secret / credentialed URL / baked-in endpoint (those live behind the core
    /// in the future live-transport increment).
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The egress capability this source corresponds to — the NAMED-destination
    /// grant the connector declares + the core checks at fetch time. This is the
    /// ONLY egress capability the pipeline ever holds.
    pub fn egress_capability(&self) -> Capability {
        Capability::Egress(self.destination.clone())
    }
}

/// True iff `label` is a single, audit-safe token: non-empty after trimming, with
/// no ASCII/Unicode control chars and no line/paragraph separators (so it can
/// never inject a line break into the audit detail string). Bounded in length so
/// a label can never bloat the (in-memory, append-only) audit chain.
fn label_is_audit_safe(label: &str) -> bool {
    const MAX_LABEL_LEN: usize = 64;
    if label.trim().is_empty() || label.chars().count() > MAX_LABEL_LEN {
        return false;
    }
    !label
        .chars()
        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
}

/// A raw mail message as the source would yield it: an opaque source-side id plus
/// the raw `.eml` bytes. The connector does NOT parse these — it hands the bytes
/// to `extract` (downstream) and stages them via `storage:own`.
///
/// CONFIDENTIALITY: `raw_eml` is matter-bound content (headers + body); it flows
/// to the staging store + `extract`, NEVER to the audit chain. `source_id` is an
/// opaque source-side handle (e.g. a server message id), used only to de-duplicate
/// and to report landed ids — it is treated as opaque, never logged as cleartext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessage {
    /// An opaque source-side message id (e.g. a server uid). Used to key the
    /// landed message + to skip already-seen messages on re-sync.
    pub source_id: String,
    /// The raw `.eml` bytes. NOT parsed here (that is `extract`'s job). Never
    /// egressed back out and never written to the audit chain.
    pub raw_eml: Vec<u8>,
}

/// The mail-source seam — the connector's testable boundary. Mirrors how
/// `runtime` has a [`runtime::MatterStore`] trait + an in-memory double: the
/// connector is generic over a `MailSource`, so its fetch logic can be exercised
/// OFFLINE against synthetic `.eml` fixtures with NO network.
///
/// IMPORTANT (load-bearing): in the SHIPPED design this seam is implemented BY THE
/// CORE, behind the mediated, broker-checked, audited fetch the connector
/// requests (see the `TODO(core)` on [`MailConnector::sync_mailbox`]). A module
/// NEVER implements a live `MailSource` itself, because a live implementation
/// would hold a socket — exactly what the architecture forbids. The only impl in
/// this crate is the in-memory test double; a real implementation is core-side
/// and lands in the signed-off live-transport increment.
pub trait MailSource {
    /// Fetch the new messages available from `source` per `plan`. In this skeleton
    /// the implementation is the in-memory double; in the shipped design the CORE
    /// performs the actual brokered, logged fetch over the named destination and
    /// the module never sees a socket.
    ///
    /// Returns [`MailboxError::NotConnected`] if the source is not reachable /
    /// not consented (the default, air-gapped posture). Never opens a socket in
    /// this crate.
    fn fetch(
        &self,
        source: &NamedSource,
        plan: &FetchPlan,
    ) -> Result<Vec<RawMessage>, MailboxError>;
}

/// An in-memory [`MailSource`] test double: a deterministic, canned set of
/// synthetic `.eml` fixtures keyed by source LABEL. Mirrors
/// [`runtime::InMemoryMatterStore`] — it lets the connector be tested OFFLINE.
///
/// A source with NO seeded fixtures behaves as NOT CONNECTED (the default,
/// air-gapped posture) — so a fetch with no configured/consented source yields
/// [`MailboxError::NotConnected`], proving "no grant / no source -> no fetch".
#[derive(Debug, Default)]
pub struct InMemoryMailSource {
    /// Canned messages keyed by source label. A label absent here is "not
    /// connected" (no consented source), never an error of a different kind.
    by_source: std::collections::HashMap<String, Vec<RawMessage>>,
}

impl InMemoryMailSource {
    /// An empty source — the default air-gapped posture (nothing connected).
    pub fn new() -> Self {
        Self {
            by_source: std::collections::HashMap::new(),
        }
    }

    /// Seed a canned `.eml` fixture for a given source label (test/spike only —
    /// stands in for what the CORE would fetch over the wire). NOT a
    /// module-reachable path: a real connector never seeds its own source.
    pub fn seed(
        &mut self,
        source_label: impl Into<String>,
        source_id: impl Into<String>,
        raw_eml: impl Into<Vec<u8>>,
    ) {
        self.by_source
            .entry(source_label.into())
            .or_default()
            .push(RawMessage {
                source_id: source_id.into(),
                raw_eml: raw_eml.into(),
            });
    }
}

impl MailSource for InMemoryMailSource {
    fn fetch(
        &self,
        source: &NamedSource,
        plan: &FetchPlan,
    ) -> Result<Vec<RawMessage>, MailboxError> {
        // A source with no seeded fixtures is NOT CONNECTED (air-gapped default).
        let all = self
            .by_source
            .get(source.label())
            .ok_or(MailboxError::NotConnected)?;
        // Deterministic: honor the plan's max and skip already-seen ids, in the
        // seeded order. (The live core fetch would apply the same plan over the
        // wire.) Nothing here opens a socket.
        let msgs: Vec<RawMessage> = all
            .iter()
            .filter(|m| !plan.is_seen(&m.source_id))
            .take(plan.max_messages())
            .cloned()
            .collect();
        Ok(msgs)
    }
}

/// What to fetch on a sync pass: a cap on how many messages to pull and the set of
/// already-seen source ids to skip (so a re-sync is incremental, not a re-pull).
/// DETERMINISTIC — no `now()`, no ambient state.
#[derive(Debug, Clone, Default)]
pub struct FetchPlan {
    /// Max messages to pull this pass (0 = unbounded within this skeleton's
    /// in-memory double). Bounds a runaway fetch.
    max_messages: usize,
    /// Source ids already landed on a previous pass — skipped this pass so a
    /// re-sync does not re-land duplicates.
    seen: std::collections::HashSet<String>,
}

impl FetchPlan {
    /// A plan that pulls up to `max_messages` new messages (0 = unbounded in the
    /// in-memory double), seeing nothing as already-landed.
    pub fn new(max_messages: usize) -> Self {
        Self {
            max_messages,
            seen: std::collections::HashSet::new(),
        }
    }

    /// Mark a source id as already landed (skipped on this pass). Builder style.
    pub fn skipping(mut self, source_id: impl Into<String>) -> Self {
        self.seen.insert(source_id.into());
        self
    }

    /// The cap on messages to pull (`usize::MAX` when `max_messages == 0`).
    fn max_messages(&self) -> usize {
        if self.max_messages == 0 {
            usize::MAX
        } else {
            self.max_messages
        }
    }

    /// Whether `source_id` was already landed (so it is skipped this pass).
    fn is_seen(&self, source_id: &str) -> bool {
        self.seen.contains(source_id)
    }
}

/// The outcome of a sync pass: COUNTS plus the landed message ids. Carries NO
/// cleartext (no subject / sender / address / body) — the raw `.eml` bytes flow to
/// the staging store + `extract`, never into this result or the audit chain.
///
/// `landed_ids` are the opaque source-side ids that were staged this pass — used
/// downstream to feed `extract` and to update the next [`FetchPlan`]'s seen-set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchResult {
    /// How many messages the source returned this pass.
    fetched: usize,
    /// How many were staged into `storage:own` (landed) this pass.
    landed: usize,
    /// How many were skipped (already seen on a prior pass).
    skipped: usize,
    /// The opaque source-side ids that were landed this pass (no cleartext).
    landed_ids: Vec<String>,
}

impl FetchResult {
    /// How many messages the source returned this pass.
    pub fn fetched(&self) -> usize {
        self.fetched
    }
    /// How many were staged into `storage:own` (landed) this pass.
    pub fn landed(&self) -> usize {
        self.landed
    }
    /// How many were skipped (already seen on a prior pass).
    pub fn skipped(&self) -> usize {
        self.skipped
    }
    /// The opaque source-side ids landed this pass (no cleartext). Feeds the next
    /// plan's seen-set + the downstream `extract` handoff.
    pub fn landed_ids(&self) -> &[String] {
        &self.landed_ids
    }
}

/// Connector errors — CONTENT-FREE by construction. No variant carries a subject,
/// sender, address, body byte, or destination string, so an error can never leak
/// matter data into an operational log or an error surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxError {
    /// The source is not reachable / not consented (the default, air-gapped
    /// posture): there is no granted, configured live source, so the connector
    /// does nothing. NOT a failure of a connected source — the OFFLINE default.
    NotConnected,
    /// A [`NamedSource`] failed validation (malformed label/destination). Carries
    /// no value (the offending string is never echoed — it may derive from config
    /// that names a real endpoint).
    InvalidSource,
    /// A brokered core call failed (e.g. egress denied, a failed audit record).
    /// Wraps the runtime's content-free [`CoreError`] so the fail-closed behavior
    /// of the core propagates unchanged.
    Core(CoreError),
}

impl From<CoreError> for MailboxError {
    fn from(e: CoreError) -> Self {
        MailboxError::Core(e)
    }
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailboxError::NotConnected => {
                f.write_str("mailbox: no connected/consented live source (air-gapped default)")
            }
            MailboxError::InvalidSource => {
                f.write_str("mailbox: invalid source (malformed label or destination)")
            }
            // Defer to CoreError's own content-free Display.
            MailboxError::Core(e) => write!(f, "mailbox: core error: {e}"),
        }
    }
}

impl std::error::Error for MailboxError {}

/// The live-mail-source connector (skeleton). Holds only CONFIGURATION (the
/// consented named source it is wired to); it reaches the wire ONLY through a
/// `&mut Core` that brokers + logs every touch, and it holds no socket / no
/// transport / no secret.
///
/// SKELETON: the configuration + the brokered entry point are real; the live
/// transport is a STUB over a [`MailSource`] (the in-memory double in tests).
pub struct MailConnector {
    /// The consented, validated live source this connector is wired to. `None`
    /// means NOT configured — the connector reports [`MailboxError::NotConnected`]
    /// and does nothing (the air-gapped default).
    source: Option<NamedSource>,
}

impl MailConnector {
    /// A machine-checkable summary of this module's capability posture, for tests
    /// and the (future) module manifest. Encodes the egress-HOLDING posture: a
    /// SINGLE named egress destination (the consented source), `storage:own` (to
    /// stage `.eml`), and `audit.note` — and nothing else. The destination is the
    /// configured source's; this template names it `<named-source>`.
    pub const CAPABILITY_NOTE: &'static str = "mailbox: capabilities = [egress:<named-source>, storage:own, audit.note]; egress = [<named-source>] (the ONE egress-holder; named + consented + revocable); matter.read = none";

    /// Construct a connector wired to a consented [`NamedSource`].
    pub fn new(source: NamedSource) -> Self {
        Self {
            source: Some(source),
        }
    }

    /// Construct an UNCONFIGURED connector (no consented source). It does nothing
    /// — every sync reports [`MailboxError::NotConnected`] — proving the
    /// air-gapped-by-default posture: with no granted/consented source, no fetch.
    pub fn disconnected() -> Self {
        Self { source: None }
    }

    /// The consented source this connector is wired to (if any).
    pub fn source(&self) -> Option<&NamedSource> {
        self.source.as_ref()
    }

    /// The capabilities this module DECLARES (spec §5.1 / §5.2) — the manifest
    /// grant request. The core grants/denies these; every runtime call is then
    /// checked against the grant (default-deny). Returns EXACTLY:
    ///
    /// - `egress:<named-source>` — the live source as a SINGLE NAMED destination.
    ///   This connector is the ONE part of the pipeline that holds an egress grant
    ///   (in contrast to `inbox` / `redaction`, which hold `egress: []`). It is
    ///   safe BECAUSE: default-deny (no grant -> no fetch); a single NAMED endpoint
    ///   (never wildcard / all-routes); firm-CONSENTED; broker-CHECKED at fetch;
    ///   AUDITED; and core-REVOCABLE. An UNCONFIGURED connector declares NO egress
    ///   at all (the empty, air-gapped default).
    /// - `storage:own` — land `.eml` into the module's OWN namespace as a staging
    ///   step. NOTE: this is the module's own staging area, NOT the matter store —
    ///   final placement into the matter store under the right data class is the
    ///   CORE's ingestion job (modules get no raw matter-store/filesystem access,
    ///   spec §6). We deliberately do NOT use an unaccepted `workspace.write`
    ///   capability — `storage:own` is the enforced, audited path that exists today.
    /// - `audit.note` — append per-pass COUNTS (fetched/landed/skipped) + the
    ///   source LABEL to the audit chain (ungated; never a subject/sender/address —
    ///   see the confidentiality split).
    ///
    /// See [`MailConnector::CAPABILITY_NOTE`] for the machine-checkable summary.
    pub fn required_capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::new();
        // EGRESS — the named, consented source. ONLY declared when a source is
        // configured: an unconfigured connector requests NO egress at all (the
        // air-gapped default). This is the one egress grant in the whole pipeline.
        if let Some(source) = &self.source {
            caps.push(source.egress_capability());
        }
        // STORAGE:OWN — stage the landed `.eml` in the module's own namespace.
        // (Final matter-store ingestion is the core's job — see the method doc.)
        caps.push(Capability::Storage(StorageScope::Own));
        // AUDIT.NOTE — per-pass counts + source label (ungated; cleartext-free).
        caps.push(Capability::AuditNote);
        caps
    }

    /// Sync the connected mailbox: fetch new messages from the consented named
    /// source THROUGH the core, stage each as `.eml` in `storage:own`, and record
    /// a cleartext-FREE per-pass audit note (counts only). Returns a [`FetchResult`]
    /// with counts + landed ids (NO cleartext) for the downstream `extract` handoff.
    ///
    /// Mirrors [`redaction`]/[`inbox`]'s generic `Core<B,A,S,E,C,M>` brokered shape:
    /// the connector never holds the broker/audit/storage/egress — only a `&mut
    /// Core` that mediates + logs every touch.
    ///
    /// # Air-gapped default (load-bearing)
    ///
    /// An UNCONFIGURED connector ([`MailConnector::disconnected`]) returns
    /// [`MailboxError::NotConnected`] immediately and touches NOTHING — no fetch,
    /// no store, no note. With no consented source, the connector does nothing and
    /// the app stays fully offline.
    ///
    /// # Confidentiality split (load-bearing)
    ///
    /// The returned [`FetchResult`] carries counts + opaque landed ids only; the
    /// raw `.eml` bytes flow to the staging store + `extract`, NEVER to the audit
    /// chain. The audit note records ONLY counts + the source LABEL (config, not
    /// matter data) — never a subject/sender/address/body.
    ///
    /// # Fail-closed ordering
    ///
    /// As in redaction/inbox: the per-pass audit note is recorded as module context
    /// (ungated `audit.note`) so a failed note ABORTS the pass rather than returning
    /// an unlogged result. Any refusal (egress denied / a failed core call)
    /// propagates as a [`MailboxError`] — fail-closed, consistent with the core.
    ///
    /// # SKELETON
    ///
    /// The brokered shape (validate-source -> fetch-via-source-seam -> stage ->
    /// audit) is wired + tested. The LIVE TRANSPORT is a STUB: `fetch` runs over the
    /// supplied [`MailSource`] (the in-memory double in tests), NOT a socket. The
    /// real fetch is a CORE seam that does not exist yet — see the `TODO(core)`
    /// block below.
    ///
    // TODO(core): this connector CONSUMES a core-side mediated FETCH seam that does
    // NOT exist yet and is NOT built here — it belongs in `runtime`/the core, later,
    // and is a SIGN-OFF-GATED increment (it widens the egress surface — a one-way-
    // door-adjacent decision; do NOT add it to `runtime` without the spec owner).
    //
    // Needed shape (an INGRESS variant of egress — egress controls *where* data may
    // go; this also pulls data IN from a named, consented endpoint, under the SAME
    // gate). To live on `runtime::Core`, mediated like `egress_send`:
    //
    //     fn egress_fetch(
    //         &mut self,
    //         destination: &str,            // a NAMED, granted egress destination
    //         request: &[u8],               // an opaque request blob (no socket here)
    //     ) -> CoreResult<Vec<u8>>;         // raw response bytes (the .eml stream)
    //
    // It MUST: (1) check `egress:<destination>` (default-deny — no grant, no fetch);
    // (2) hold the socket IN THE CORE (the module never sees a transport); (3) pin
    // the destination to a SINGLE named, firm-consented endpoint (never wildcard /
    // all-routes); (4) AUDIT the fetch as a brokered call (count + destination +
    // byte length — never the message bytes); (5) be REVOCABLE (deny the
    // destination -> the connector goes dark, app stays offline). The connector
    // then (a) hands the returned bytes to `extract` (the .eml PARSER — OUT OF SCOPE
    // here; this crate does not parse), and (b) stages them via `storage:own` for
    // the core to ingest into the matter store under the right data class.
    //
    // SEPARATELY, the LIVE M365/Exchange/IMAP transport + OAuth/token handling is a
    // later, signed-off increment behind that same gate (it is what actually opens a
    // socket, in the CORE, never here). NO secret / endpoint / OAuth client may
    // enter THIS crate. Until `egress_fetch` lands, `sync_mailbox` takes a
    // `MailSource` seam and runs the in-memory double, so it dogfoods the shape +
    // the confidentiality split today without forking the runtime or touching a wire.
    pub fn sync_mailbox<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
        mail_source: &impl MailSource,
        plan: &FetchPlan,
    ) -> Result<FetchResult, MailboxError>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        // AIR-GAPPED DEFAULT: no consented source -> do nothing. No fetch, no
        // store, no note — the app stays fully offline.
        let source = self.source.as_ref().ok_or(MailboxError::NotConnected)?;

        // STUB FETCH (TODO(core): becomes a brokered `core.egress_fetch(..)`): in
        // this skeleton the bytes come from the `MailSource` seam (the in-memory
        // double in tests), NOT a socket. The live core fetch checks
        // `egress:<destination>` (default-deny), holds the socket, and audits — the
        // module never sees a transport. We DO prove the gate here by asserting the
        // core would refuse egress to the source's destination unless granted (see
        // the test `no_egress_grant_means_the_source_is_unreachable`).
        let fetched = mail_source.fetch(source, plan)?;
        let fetched_count = fetched.len();

        // STAGE each `.eml` into the module's OWN storage namespace (mediated +
        // audited by the core; default-deny if `storage:own` is not granted). This
        // is the module's STAGING area, NOT the matter store — the core ingests the
        // staged bytes into the matter store later (its job, not the module's).
        let mut landed_ids = Vec::with_capacity(fetched.len());
        let mut skipped = 0usize;
        // Within-pass dedup by the STAGING KEY (the actual on-disk identity). Two
        // RawMessages carrying the same source_id collide on one staging key, so the
        // second storage_put OVERWRITES the first — only ONE .eml is staged. Counting
        // both as `landed` would let the audit report landed=2 while 1 file exists:
        // the exact "audit conceals a missed/merged document" class the seen-id
        // re-check guards against, for the identical-id-WITHIN-one-fetch case. Count an
        // in-batch repeat as skipped so `landed` can never exceed distinct .eml written.
        let mut staged: HashSet<String> = HashSet::new();
        for msg in &fetched {
            if plan.is_seen(&msg.source_id) {
                // Defensive: the source seam already filters seen ids, but re-check
                // so a future live fetch that does NOT pre-filter still won't
                // re-land a duplicate. Counted as skipped, not landed.
                skipped += 1;
                continue;
            }
            // Stage under a sanitized, per-message key in the module's own
            // namespace. The core's storage layer re-sanitizes the key (rejects
            // traversal / separators / control chars), so a crafted source id can
            // never escape the namespace — but we pre-sanitize to a stable form so
            // the staging key is deterministic.
            let key = staging_key(&msg.source_id);
            if !staged.insert(key.clone()) {
                // A duplicate staging key within this same fetch pass: the prior
                // storage_put already wrote these bytes. Don't double-count.
                skipped += 1;
                continue;
            }
            core.storage_put(StorageScope::Own, &key, msg.raw_eml.clone())?;
            landed_ids.push(msg.source_id.clone());
        }

        let result = FetchResult {
            fetched: fetched_count,
            landed: landed_ids.len(),
            skipped,
            landed_ids,
        };

        // FAIL-CLOSED (mirrors redaction/inbox): record the per-pass COUNTS + the
        // source LABEL as module context (ungated audit.note) — NEVER a
        // subject/sender/address/body, so the audit chain never stores the mail. A
        // failed note ABORTS the pass (the `?`) rather than returning an unlogged
        // result. The source LABEL is config (audit-safe), not matter data.
        core.audit_note(&format!(
            "mailbox: sync from source {:?} — fetched={}, landed={}, skipped={}",
            source.label(),
            result.fetched,
            result.landed,
            result.skipped,
        ))?;

        Ok(result)
    }
}

/// Build a deterministic, namespace-safe, COLLISION-FREE staging key for a landed
/// message from its opaque source id.
///
/// SECURITY (Medium): the key MUST be lossless. A previous version mapped
/// `/ \ . control whitespace` all to `_`, so DISTINCT source ids (`uid.1`, `uid/1`,
/// `uid 1`) collapsed to ONE key and a second `storage_put` OVERWROTE the first —
/// silently dropping a landed message while BOTH were counted as landed and pushed
/// to `landed_ids`. That is a missed-document risk the audit actively conceals
/// (the counts say two landed; only one is in the store). The fix mirrors
/// `app/paths.py`'s invariant: key on a hex SHA-256 of the FULL raw `source_id`, so
/// two ids that differ in ANY byte (including sanitized chars) get DISTINCT keys.
///
/// The hash is over the full UTF-8 bytes; the hex output is `[0-9a-f]` only, so the
/// key is inherently namespace-safe (no separator / traversal / control chars — the
/// core's storage layer re-sanitizes anyway, but this never relies on that).
/// Cleartext-free: an opaque id digest, never message content; the id itself is not
/// recoverable from the key.
fn staging_key(source_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(source_id.as_bytes());
    let mut hex = String::with_capacity(2 * digest.len());
    for byte in digest {
        // Lowercase hex, two chars per byte — deterministic, allocation-bounded.
        hex.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble < 16"));
        hex.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble < 16"));
    }
    format!("eml_{hex}")
}

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

    const SOURCE_LABEL: &str = "acme-m365";
    const SOURCE_DEST: &str = "mail.acme-law.example";

    // Synthetic `.eml` fixtures (RFC822-ish). They carry obvious cleartext
    // (subject/sender/body) so the counts-only-audit test can assert NONE of it
    // leaks into the audit chain.
    const EML_ONE: &[u8] =
        b"From: alice@counterparty.example\r\nSubject: Re: Project Condor NDA\r\n\r\nPlease counter-sign.";
    const EML_TWO: &[u8] =
        b"From: bob@acme-law.example\r\nSubject: filed the signed copy\r\n\r\nDone.";

    fn named_source() -> NamedSource {
        NamedSource::new(SOURCE_LABEL, SOURCE_DEST).expect("a well-formed named source")
    }

    fn seeded_source() -> InMemoryMailSource {
        let mut src = InMemoryMailSource::new();
        src.seed(SOURCE_LABEL, "uid-1", EML_ONE.to_vec());
        src.seed(SOURCE_LABEL, "uid-2", EML_TWO.to_vec());
        src
    }

    fn core_with(grants: Vec<Capability>) -> TestCore {
        Core::new(
            "sg.mailbox.connector",
            GrantSet::from_manifest(grants),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            // Configure the source destination at the sink so the BROKER gate — not
            // a missing sink — is what we are testing when egress is (not) granted.
            InMemoryEgress::new().with_destination(SOURCE_DEST),
            CoreContext::new("Acme v Beta", "j.smith"),
            InMemoryMatterStore::new(),
        )
    }

    /// The grant set the connector declares: the NAMED egress source + storage:own
    /// + audit.note. The egress destination is the consented source's.
    fn mailbox_grants() -> Vec<Capability> {
        vec![
            Capability::Egress(SOURCE_DEST.to_string()),
            Capability::Storage(StorageScope::Own),
            Capability::AuditNote,
        ]
    }

    #[test]
    fn connector_constructs_from_a_named_source() {
        let c = MailConnector::new(named_source());
        assert_eq!(c.source().map(|s| s.label()), Some(SOURCE_LABEL));
        assert_eq!(c.source().map(|s| s.destination()), Some(SOURCE_DEST));
    }

    #[test]
    fn required_capabilities_is_exactly_egress_named_storage_own_and_audit_note() {
        let caps = MailConnector::new(named_source()).required_capabilities();

        // EXACTLY one Egress(named) + Storage(Own) + AuditNote, and nothing else.
        let egress: Vec<&Capability> = caps
            .iter()
            .filter(|c| matches!(c, Capability::Egress(_)))
            .collect();
        assert_eq!(
            egress.len(),
            1,
            "exactly one named egress destination, got {caps:?}"
        );
        assert_eq!(
            egress[0],
            &Capability::Egress(SOURCE_DEST.to_string()),
            "the egress is the consented source's NAMED destination"
        );
        assert!(
            caps.contains(&Capability::Storage(StorageScope::Own)),
            "declares storage:own (the staging area), got {caps:?}"
        );
        assert!(
            caps.contains(&Capability::AuditNote),
            "declares audit.note, got {caps:?}"
        );
        // Nothing else: exactly three capabilities.
        assert_eq!(
            caps.len(),
            3,
            "exactly [Egress(named), Storage(Own), AuditNote], got {caps:?}"
        );
        // Explicitly NOT a matter.read / transform / compute capability.
        assert!(
            !caps.iter().any(|c| matches!(
                c,
                Capability::MatterRead(_)
                    | Capability::MatterWrite(_)
                    | Capability::DocumentTransform
                    | Capability::ComputeModel
            )),
            "the connector declares no matter.read/write/transform/compute, got {caps:?}"
        );
    }

    #[test]
    fn an_unconfigured_connector_declares_no_egress() {
        // Air-gapped default: with NO consented source, the connector requests NO
        // egress at all (only storage:own + audit.note for an inert module).
        let caps = MailConnector::disconnected().required_capabilities();
        assert!(
            !caps.iter().any(|c| matches!(c, Capability::Egress(_))),
            "an unconfigured connector must declare NO egress, got {caps:?}"
        );
        assert!(caps.contains(&Capability::Storage(StorageScope::Own)));
        assert!(caps.contains(&Capability::AuditNote));
        assert_eq!(
            caps.len(),
            2,
            "exactly [Storage(Own), AuditNote] when disconnected, got {caps:?}"
        );
    }

    #[test]
    fn capability_note_declares_the_egress_holder_posture() {
        let note = MailConnector::CAPABILITY_NOTE;
        assert!(
            note.contains("egress:<named-source>"),
            "names a single egress dest: {note}"
        );
        assert!(note.contains("storage:own"), "declares storage:own: {note}");
        assert!(note.contains("audit.note"), "declares audit.note: {note}");
        assert!(
            note.contains("matter.read = none"),
            "reads no matter content: {note}"
        );
        // It is the egress-holder, and the destination is named/consented/revocable.
        assert!(
            note.contains("egress-holder"),
            "is the pipeline's egress holder: {note}"
        );
    }

    #[test]
    fn named_source_validation_rejects_empty_wildcard_and_control_destinations() {
        // Mirrors the runtime's egress-destination posture: empty / whitespace /
        // wildcard / all-routes / control-char destinations are refused at
        // construction, so a malformed source can never become a granted dest.
        for bad in [
            "",                  // empty
            "   ",               // whitespace-only
            "mail acme.example", // embedded whitespace
            "*",                 // wildcard
            "*.acme.example",    // wildcard
            "0.0.0.0/0",         // all-routes
            "::/0",              // all-routes
            "127.0.0.1",         // loopback ambient form
            "255.255.255.255",   // broadcast
            "x\u{0001}y",        // control char
        ] {
            assert_eq!(
                NamedSource::new("acme-m365", bad),
                Err(MailboxError::InvalidSource),
                "destination {bad:?} must be rejected"
            );
        }
        // A bad label is rejected too (empty / control char / line separator).
        for bad_label in ["", "  ", "src\nname", "src\u{2028}name"] {
            assert_eq!(
                NamedSource::new(bad_label, SOURCE_DEST),
                Err(MailboxError::InvalidSource),
                "label {bad_label:?} must be rejected"
            );
        }
        // A well-formed named source constructs.
        assert!(NamedSource::new("acme-m365", "mail.acme-law.example").is_ok());
    }

    #[test]
    fn stub_fetch_yields_expected_result_counts() {
        // A stub fetch over the in-memory source lands both seeded fixtures and
        // reports the expected counts + landed ids (no cleartext).
        let mut core = core_with(mailbox_grants());
        let result = MailConnector::new(named_source())
            .sync_mailbox(&mut core, &seeded_source(), &FetchPlan::new(0))
            .unwrap();

        assert_eq!(result.fetched(), 2, "both seeded fixtures fetched");
        assert_eq!(result.landed(), 2, "both landed into storage:own");
        assert_eq!(result.skipped(), 0, "none skipped on a first pass");
        assert_eq!(
            result.landed_ids(),
            &["uid-1".to_string(), "uid-2".to_string()]
        );

        // The staged `.eml` bytes are in the module's own namespace (mediated).
        let staged = core
            .storage_get(StorageScope::Own, &staging_key("uid-1"))
            .unwrap();
        assert_eq!(
            staged.as_deref(),
            Some(EML_ONE),
            "the .eml was staged verbatim"
        );

        // The reads/writes + the per-pass note were audited at the chokepoint.
        let caps: Vec<&Capability> = core
            .audit()
            .entries()
            .iter()
            .map(|e| &e.capability)
            .collect();
        assert!(
            caps.contains(&&Capability::Storage(StorageScope::Own)),
            "staging puts were audited"
        );
        assert!(
            caps.contains(&&Capability::AuditNote),
            "the per-pass note was audited"
        );
        assert!(
            core.audit().verify_chain(),
            "the keyed hash chain must verify"
        );
    }

    #[test]
    fn re_sync_skips_already_seen_ids() {
        // A plan that has already seen uid-1 lands only uid-2 (incremental sync).
        let mut core = core_with(mailbox_grants());
        let plan = FetchPlan::new(0).skipping("uid-1");
        let result = MailConnector::new(named_source())
            .sync_mailbox(&mut core, &seeded_source(), &plan)
            .unwrap();
        assert_eq!(result.landed(), 1, "only the unseen message lands");
        assert_eq!(result.landed_ids(), &["uid-2".to_string()]);
    }

    #[test]
    fn audit_note_is_counts_only_and_carries_no_cleartext() {
        // CONFIDENTIALITY SPLIT: the audit note records counts + the source LABEL
        // ONLY — never a subject/sender/body from the synthetic `.eml` fixtures.
        let mut core = core_with(mailbox_grants());
        MailConnector::new(named_source())
            .sync_mailbox(&mut core, &seeded_source(), &FetchPlan::new(0))
            .unwrap();

        let notes: Vec<&str> = core
            .audit()
            .entries()
            .iter()
            .filter(|e| e.capability == Capability::AuditNote)
            .map(|e| e.detail.as_str())
            .collect();
        assert!(
            notes.iter().any(|d| d.contains("fetched=2")),
            "note carries the count: {notes:?}"
        );
        assert!(
            notes.iter().any(|d| d.contains("landed=2")),
            "note carries the landed count"
        );

        // NONE of the fixtures' cleartext substrings may appear in the audit chain.
        for note in &notes {
            for needle in [
                "Project Condor",
                "alice@counterparty.example",
                "bob@acme-law.example",
                "counter-sign",
                "signed copy",
                "Subject",
                "From:",
            ] {
                assert!(
                    !note.contains(needle),
                    "audit note must NOT carry cleartext {needle:?}, note = {note:?}"
                );
            }
        }
    }

    #[test]
    fn no_grant_means_no_fetch_not_connected() {
        // DEFAULT-DENY / air-gapped-by-default: an UNCONFIGURED connector does
        // nothing — it reports NotConnected and touches no store / no note, so the
        // app stays fully offline with no consented source.
        let mut core = core_with(mailbox_grants());
        let err = MailConnector::disconnected()
            .sync_mailbox(&mut core, &seeded_source(), &FetchPlan::new(0))
            .unwrap_err();
        assert_eq!(err, MailboxError::NotConnected, "no source -> NotConnected");
        // Nothing was staged and nothing was logged: the connector did nothing.
        assert_eq!(
            core.audit().len(),
            0,
            "a disconnected sync writes no audit entry"
        );
    }

    #[test]
    fn an_unseeded_source_is_not_connected() {
        // A configured connector whose source has no fixtures behaves as NOT
        // CONNECTED (the air-gapped default) — proving "no live source -> no fetch".
        let mut core = core_with(mailbox_grants());
        let empty_source = InMemoryMailSource::new(); // nothing seeded
        let err = MailConnector::new(named_source())
            .sync_mailbox(&mut core, &empty_source, &FetchPlan::new(0))
            .unwrap_err();
        assert_eq!(
            err,
            MailboxError::NotConnected,
            "no fixtures -> NotConnected"
        );
    }

    #[test]
    fn no_egress_grant_means_the_source_is_unreachable() {
        // The connector reaches the wire ONLY via the core. Prove the core would
        // REFUSE egress to the source's NAMED destination unless the egress
        // capability is granted — this is the gate the live `egress_fetch` will
        // pass through (default-deny). With no egress grant, nothing can leave.
        let grants_without_egress = vec![
            Capability::Storage(StorageScope::Own),
            Capability::AuditNote,
            // NOTE: no Capability::Egress(SOURCE_DEST) — the source is ungranted.
        ];
        let mut core = core_with(grants_without_egress);
        let err = core.egress_send(SOURCE_DEST, b"fetch-request").unwrap_err();
        assert!(
            matches!(err, CoreError::Denied(Capability::Egress(_))),
            "no egress grant -> the source is unreachable, got {err:?}"
        );
        assert!(core.egress().sent().is_empty(), "nothing left the box");
    }

    #[test]
    fn storage_default_deny_aborts_the_sync_fail_closed() {
        // FAIL-CLOSED: without storage:own granted, the first staging put is
        // refused and the sync aborts (the error propagates as MailboxError::Core).
        let grants_without_storage = vec![
            Capability::Egress(SOURCE_DEST.to_string()),
            Capability::AuditNote,
        ];
        let mut core = core_with(grants_without_storage);
        let err = MailConnector::new(named_source())
            .sync_mailbox(&mut core, &seeded_source(), &FetchPlan::new(0))
            .unwrap_err();
        assert!(
            matches!(
                err,
                MailboxError::Core(CoreError::Denied(Capability::Storage(StorageScope::Own)))
            ),
            "a refused staging put must abort the sync fail-closed, got {err:?}"
        );
    }

    #[test]
    fn staging_keys_are_collision_free_across_sanitized_chars() {
        // REGRESSION (Medium): the old key mapped `/ \ . control whitespace` -> `_`,
        // so `uid.1`, `uid/1`, `uid 1`, `uid\1`, `uid\t1` all collapsed to ONE key
        // and a second staging put OVERWROTE the first — silently dropping a landed
        // message while BOTH were counted as landed. Distinct ids must map to
        // DISTINCT keys now (hash of the FULL raw id).
        let ids = [
            "uid.1", "uid/1", "uid 1", "uid\\1", "uid\t1", "uid-1", "uid_1",
        ];
        let keys: std::collections::HashSet<String> = ids.iter().map(|s| staging_key(s)).collect();
        assert_eq!(
            keys.len(),
            ids.len(),
            "every distinct source id must get a distinct staging key (no overwrite/loss)"
        );
        // The key derivation is deterministic (same id -> same key, every time).
        assert_eq!(staging_key("uid.1"), staging_key("uid.1"));
        // The key is namespace-safe: only `eml_` + lowercase hex, no separators.
        let k = staging_key("a/b\\c..d");
        assert!(
            k.strip_prefix("eml_").is_some_and(|h| h
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())),
            "key must be eml_ + lowercase hex, got {k:?}"
        );
    }

    #[test]
    fn colliding_sanitized_ids_both_land_without_overwrite() {
        // End-to-end: two messages whose ids differ ONLY in sanitized chars
        // (`uid.1` vs `uid/1`) must BOTH be staged under distinct keys, so neither
        // overwrites the other and both are recoverable from storage. Previously the
        // second put clobbered the first while the counts still claimed two landed.
        let mut core = core_with(mailbox_grants());
        let mut src = InMemoryMailSource::new();
        const A: &[u8] = b"From: a@x.example\r\nSubject: first\r\n\r\nbody A";
        const B: &[u8] = b"From: b@x.example\r\nSubject: second\r\n\r\nbody B";
        src.seed(SOURCE_LABEL, "uid.1", A.to_vec());
        src.seed(SOURCE_LABEL, "uid/1", B.to_vec());

        let result = MailConnector::new(named_source())
            .sync_mailbox(&mut core, &src, &FetchPlan::new(0))
            .unwrap();
        assert_eq!(result.landed(), 2, "both colliding-when-sanitized ids land");

        // BOTH staged blobs are independently recoverable (no overwrite).
        let a = core
            .storage_get(StorageScope::Own, &staging_key("uid.1"))
            .unwrap();
        let b = core
            .storage_get(StorageScope::Own, &staging_key("uid/1"))
            .unwrap();
        assert_eq!(a.as_deref(), Some(A), "first message staged intact");
        assert_eq!(
            b.as_deref(),
            Some(B),
            "second message staged intact (not overwritten)"
        );
        assert_ne!(
            staging_key("uid.1"),
            staging_key("uid/1"),
            "keys are distinct"
        );
    }

    #[test]
    fn identical_source_id_within_one_pass_lands_exactly_once() {
        // Two RawMessages carrying the SAME source_id in ONE fetch collide on one
        // staging key — the second storage_put would overwrite the first, so only ONE
        // .eml exists. The audit count must reflect that: landed=1, the in-batch
        // repeat counted as skipped (never landed). This closes the
        // audit-conceals-a-merged-document case for the identical-id-within-a-pass
        // path (the seen-set re-check only covers ACROSS passes).
        let mut core = core_with(mailbox_grants());
        let mut src = InMemoryMailSource::new();
        const A: &[u8] = b"From: a@x.example\r\nSubject: first copy\r\n\r\nbody A";
        const B: &[u8] = b"From: a@x.example\r\nSubject: duplicate id\r\n\r\nbody B";
        src.seed(SOURCE_LABEL, "uid-dup", A.to_vec());
        src.seed(SOURCE_LABEL, "uid-dup", B.to_vec());

        let result = MailConnector::new(named_source())
            .sync_mailbox(&mut core, &src, &FetchPlan::new(0))
            .unwrap();
        assert_eq!(result.fetched(), 2, "the source yielded both copies");
        assert_eq!(
            result.landed(),
            1,
            "only one distinct .eml is actually staged"
        );
        assert_eq!(
            result.skipped(),
            1,
            "the in-batch repeat is counted skipped, not landed"
        );
        assert_eq!(
            result.landed_ids(),
            &["uid-dup".to_string()],
            "exactly one landed id"
        );

        // Exactly one staged blob exists under the shared key (the FIRST write wins —
        // `staged.insert` rejects the second before its put). The audit's landed count
        // can never exceed distinct files written.
        let staged = core
            .storage_get(StorageScope::Own, &staging_key("uid-dup"))
            .unwrap();
        assert_eq!(
            staged.as_deref(),
            Some(A),
            "the first copy is what was staged"
        );
        assert!(
            core.audit().verify_chain(),
            "the keyed hash chain must verify"
        );
    }

    #[test]
    fn errors_are_content_free() {
        // The error type carries no matter data: its Display never echoes a
        // destination/subject/sender. (A reviewer relies on this so an error in a
        // support log can never leak the consented endpoint or a message header.)
        assert!(!MailboxError::NotConnected.to_string().contains(SOURCE_DEST));
        assert!(!MailboxError::InvalidSource
            .to_string()
            .contains(SOURCE_DEST));
        // Even a Core-wrapped error stays content-free (CoreError truncates).
        let wrapped = MailboxError::Core(CoreError::Denied(Capability::Egress(SOURCE_DEST.into())));
        // The capability Display does name the destination, which is config, not
        // matter content — but the NotConnected/InvalidSource variants never do.
        let _ = wrapped.to_string();
    }
}
