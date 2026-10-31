// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Timesheet — automated legal time-capture / draft billing (Increment 1).
//!
//! A first-party "firmOS" module that derives **DRAFT** time entries from
//! observed activity (emails sent/received, document touches via the core audit
//! trail, tasks, calendar, focus-time) so a lawyer recovers time that would
//! otherwise leak. It dogfoods the SAME trusted-core ABI as redaction (module
//! #1): every matter touch goes through the brokered, granted, scoped, logged
//! `Core` methods; the engine holds no filesystem, no socket, and **no egress**.
//!
//! ## STATUS: INCREMENT 2 — email + document-review capture both work
//!
//! Working end-to-end through the brokered ABI ([`Timesheet::collect_drafts`]):
//! - **Email-time** capture from email METADATA (the headers `ingest` lands from
//!   `.eml`/`.msg`) over the `matter.read:metadata` seam (one conservative draft per
//!   email, `DEFAULT_UNIT`/`Default`).
//! - **Document-review** capture from the document-touch ACTIVITY trail
//!   (`Core::matter_read_activity`, gated by `matter.read:activity`): touches group
//!   into review SESSIONS (idle gaps > [`SESSION_GAP`] split a session, so an idle
//!   period is never billed), one Proposed draft per session with the session SPAN
//!   floored at `DEFAULT_UNIT` and [`DurationSource::AuditTouch`] provenance. The
//!   narrative is cleartext-free (the audit trail has no doc names — only a count).
//!   HONESTY: today the trail's touches are MODULE-brokered accesses, not UI
//!   "document opened" events, so these are a DRAFT signal the lawyer attests — never
//!   measured human review (see the per-method + `DurationSource::AuditTouch` docs).
//!
//! Proposals persist to the `storage:own` draft store
//! ([`Timesheet::save_drafts`] / [`Timesheet::load_drafts`]); [`export_csv`]
//! serializes a review schedule; the human-attestation lifecycle is enforced by
//! [`DraftEntry::transition`].
//!
//! STILL `todo!()` (NOT implemented — do not present their output as billable):
//! Export (all deterministic + DEP-FREE): [`export_csv`] (config-free working
//! timesheet); and behind a [`BillingConfig`] (the "LEDES/UTBMS opt-in, solo-slice
//! default" decision; integer-cent money; attested-only) [`export_ledes_1998b`] (the
//! canonical pipe-delimited legal e-billing flat file), [`export_pdf`] (a
//! human-readable, hand-written multi-page Courier invoice PDF), and
//! [`export_ledes_xml`] (the same billed-line data as well-formed LEDES-XML — validate
//! against your e-biller's exact XSD; the 1998B flat file is the format-stable path).
//!
//! ## Honest framing (read before trusting this — it is load-bearing)
//!
//! - **DRAFT only — the lawyer attests every line.** This engine NEVER
//!   auto-submits, auto-approves, or pushes time to a billing system. It proposes
//!   [`DraftEntry`]s with [`EntryStatus::Proposed`]; a human reviews, edits, and
//!   confirms each one. Attestation is a legal + ethical requirement (a lawyer
//!   certifies the work was done and the time is accurate), and it is the human's,
//!   not the software's.
//! - **Optimize for CAPTURE, never inflation.** The goal is to recover time that
//!   genuinely happened but went un-recorded (leakage) — NOT to maximize the bill.
//!   Durations are derived conservatively and round in the CLIENT's favor where a
//!   choice exists; the engine must never pad, stack, or double-count activity.
//!   A defensible under-capture beats an indefensible over-bill.
//! - **Provenance is recorded for defensibility.** Every entry carries a
//!   [`DurationSource`] saying HOW its duration was derived (a real timer, a
//!   calendar event, measured focus-time, or a bare default). On a fee dispute or
//!   taxation, "this 0.4h came from a 24-minute calendar event" is defensible;
//!   "the software guessed" is not. The provenance is part of the entry, not a
//!   detached log.
//! - **Deterministic. No model / LLM anywhere.** Narrative generation is a
//!   fixed-template substitution ([`narrative`]), NOT generative text. Activity is
//!   classified by deterministic rules. There is no inference tier in this module;
//!   if a statistical activity-classifier is ever wanted it belongs behind the
//!   brokered `compute.model` capability in a LATER increment, never here.
//!
//! ## Capabilities (declared, default-deny)
//!
//! See [`TIMESHEET_CAPABILITIES`]. The engine declares:
//! - `storage:own` — the DRAFT BILLING STORE (proposed/edited/confirmed entries),
//!   in the module's OWN namespace via the mediated `Core::storage_*` methods.
//! - `audit.note` — append count/provenance context to the compliance chain
//!   (ungated; never the cleartext narrative — see the confidentiality split).
//!
//! It holds **`egress: []`** on purpose: exports ([`Timesheet::export_csv`] /
//! `export_pdf` / `export_ledes_1998b` / `export_ledes_xml`) write LOCAL files,
//! and pushing entries to a practice-management system is a FUTURE networked
//! connector (a separate, consented, named-destination egress grant), NOT this
//! crate.
//!
//! ### Two log systems — never conflate them (CLAUDE.md two-log discipline)
//!
//! The `storage:own` DRAFT BILLING STORE (the entries themselves) is DISTINCT
//! from the `core` audit chain (the HMAC-keyed, tamper-evident compliance trail
//! of every brokered call). The billing store holds the work product; the audit
//! chain holds the accountability record of how it was produced. Different
//! purposes, different guarantees — they stay separate.
//!
//! ### Confidentiality split (mirrors redaction)
//!
//! A [`DraftEntry`]'s `narrative` can quote matter content ("Email to {recipient}
//! re {subject}") and is sensitive matter data: it stays local behind the engine's
//! empty egress grant. The AUDIT note, by contrast, records only COUNTS +
//! per-source provenance breakdown (never a cleartext narrative / recipient /
//! subject), so the compliance chain does not become a cleartext store of the
//! very matter content being billed.

use std::time::Duration;

use runtime::{
    ActivityEvent, ActivityEventKind, Audit, Capability, CapabilityBroker, CoreError, CoreResult,
    DataClass, Egress, InMemoryAudit, MatterContext, MatterStore, Storage, StorageScope,
};
use serde::{Deserialize, Serialize};

/// The capabilities this module declares to the broker (default-deny, spec §5.1).
/// The trusted host/core grants these from the VERIFIED manifest at load time.
///
/// - `matter.read:metadata` — read email headers (the email-time signal source,
///   landed by `ingest`); entitlement-filtered by the core like any matter read.
/// - `matter.read:activity` — read the matter's ACTIVITY trail (the cleartext-free
///   document-touch projection of the audit chain — the document-review signal),
///   via the mediated `Core::matter_read_activity`.
/// - `storage:own` — the draft billing store (the module's OWN namespace).
/// - `audit.note`  — append provenance context to the compliance chain (ungated).
///
/// NOTE the DELIBERATE absence of `egress:<dest>`: exports are local files and a
/// practice-management push is a future networked connector, not this crate. (It
/// also omits `document.transform`: time-capture READS activity, it never
/// rewrites matter documents.)
pub const TIMESHEET_CAPABILITIES: &[Capability] = &[
    Capability::MatterRead(DataClass::Metadata),
    Capability::MatterRead(DataClass::Activity),
    Capability::Storage(StorageScope::Own),
    Capability::AuditNote,
];

/// The storage key (in `storage:own`) under which the draft billing store is
/// persisted. The store is the module's work product — DISTINCT from the core
/// audit chain (two-log discipline).
pub const DRAFT_STORE_KEY: &str = "draft-entries";

/// What KIND of billable activity a draft entry was derived from. Deterministic,
/// rule-classified — NOT model-inferred. Drives the narrative template chosen in
/// [`narrative`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActivityKind {
    /// An email sent or received (recipient + subject feed the narrative).
    Email,
    /// A document was opened / touched (observed via the core audit trail).
    DocumentReview,
    /// A discrete task / matter action.
    Task,
    /// A calendar event (meeting, hearing, call) on the matter.
    Meeting,
    /// A measured focus-time block attributed to the matter.
    FocusBlock,
}

/// HOW a draft entry's [`DraftEntry::duration`] was derived — provenance, for
/// DEFENSIBILITY on a fee dispute / taxation. Ordered most-to-least authoritative;
/// `Default` is the weakest and should be flagged for the lawyer's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurationSource {
    /// A real running timer measured the elapsed time (most authoritative).
    Timer,
    /// Derived from a calendar event's scheduled span.
    Calendar,
    /// Derived from a measured focus-time / active-window block.
    FocusTime,
    /// Derived from the core AUDIT TRAIL of recorded document touches (the span of
    /// a document-access session). DEFENSIBLE provenance ("this came from N recorded
    /// touches between T1 and T2") but NOT a measurement of continuous human review —
    /// today the touches are module-brokered accesses, so the lawyer must attest the
    /// time was genuine review before billing. Weaker than a real timer/calendar.
    AuditTouch,
    /// A bare fallback default (e.g. a fixed minimum unit) — no measurement.
    /// LEAST authoritative; surface it so the lawyer scrutinizes / overrides it.
    Default,
}

/// Where a draft entry is in the human-attestation lifecycle. An entry starts
/// [`Proposed`](EntryStatus::Proposed) and only a HUMAN advances it — the engine
/// never auto-confirms or auto-submits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryStatus {
    /// Engine-proposed, awaiting human review. The ONLY status this engine emits.
    Proposed,
    /// A human reviewed + attested the entry (ready to be acted on).
    Confirmed,
    /// Exported / posted downstream (terminal).
    Done,
    /// A human rejected the entry (terminal; kept for an auditable trail of what
    /// was proposed and declined — never silently dropped).
    Dismissed,
}

/// One DRAFT time entry derived from observed activity. CARRIES MATTER CONTENT
/// (`narrative` can quote a recipient / subject / document name): it is sensitive
/// matter data for the in-process review workflow only — it is never egressed
/// (the engine holds no egress) and never written to the audit chain (see the
/// crate-level confidentiality split).
///
/// Always emitted as [`EntryStatus::Proposed`]; the lawyer attests every line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftEntry {
    /// The activity date, BEST-EFFORT as a `String`: ISO-8601 `YYYY-MM-DD` where
    /// derivable, otherwise the source's raw date verbatim (e.g. an email's RFC 822
    /// `Date`) or a neutral placeholder when absent. A plain `String` keeps the
    /// crate dependency-free (no date crate) and deterministic; normalizing RFC 822
    /// → ISO is a future refinement (needs a date dep / sign-off).
    pub date: String,
    /// The matter the time is booked to (the core's current matter context).
    pub matter: String,
    /// What kind of activity this entry was derived from.
    pub activity_kind: ActivityKind,
    /// Human-readable, DETERMINISTICALLY TEMPLATED narrative (see [`narrative`]).
    /// Cleartext matter content — review-only, never egressed, never audited.
    pub narrative: String,
    /// The derived billable duration.
    pub duration: Duration,
    /// HOW `duration` was derived — provenance for defensibility.
    pub duration_source: DurationSource,
    /// Optional UTBMS task/activity code (e.g. `L120`) for code-based billing.
    /// `None` until classified / set by the lawyer.
    pub utbms: Option<String>,
    /// Attestation-lifecycle status. The engine only ever emits `Proposed`.
    pub status: EntryStatus,
}

/// A raw observed activity signal, BEFORE it becomes a [`DraftEntry`]. This is
/// the engine's INPUT shape — what the core (eventually) hands the engine after
/// the entitlement pre-filter. The fields it needs are flagged with `TODO(core):`
/// because the core does not expose these signal sources yet (see the crate /
/// [`Timesheet::collect_drafts`] notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivitySignal {
    /// Activity date (`YYYY-MM-DD`).
    pub date: String,
    /// The kind of activity observed.
    pub kind: ActivityKind,
    /// Fields the narrative template substitutes (recipient, subject, doc name…).
    /// Kept as opaque key/value pairs so the skeleton does not over-commit a shape
    /// before the real signal sources exist.
    pub fields: Vec<(String, String)>,
    /// Derived duration + its provenance, if the signal carried timing.
    pub duration: Option<(Duration, DurationSource)>,
}

/// The default minimum billing unit used when no measured duration is available
/// (provenance [`DurationSource::Default`]). 0.1h = 6 minutes is the common legal
/// minimum increment. SKELETON value; the real engine should make this
/// firm-configurable AND round in the client's favor.
pub const DEFAULT_UNIT: Duration = Duration::from_secs(6 * 60);

/// The deterministic time-capture engine. Holds the engine configuration (the
/// data classes it reads activity from); the brokered methods
/// ([`Timesheet::collect_drafts`] / [`Timesheet::save_drafts`] /
/// [`Timesheet::load_drafts`]) are implemented for Increment 1 (email-time
/// capture). Construction is infallible and pure.
///
/// Mirrors [`runtime`]'s redaction `RedactionEngine`: generic-free state here,
/// generic over the `Core` traits at the brokered entry point
/// ([`Timesheet::collect_drafts`]).
#[derive(Debug, Default)]
pub struct Timesheet {
    /// The data classes this engine reads activity signals from (each must be
    /// separately granted via `matter.read:<class>` or the core refuses it).
    /// Empty by default; set via [`Timesheet::with_classes`].
    classes: Vec<DataClass>,
}

impl Timesheet {
    /// A default engine (no configured classes yet). SKELETON.
    pub fn new() -> Self {
        Self::default()
    }

    /// An engine configured to read activity from an explicit set of data classes
    /// (each must be separately granted via `matter.read:<class>`). SKELETON.
    pub fn with_classes(classes: Vec<DataClass>) -> Self {
        Self { classes }
    }

    /// The data classes this engine is configured to read activity from.
    pub fn classes(&self) -> &[DataClass] {
        &self.classes
    }

    /// ENTRY POINT: collect DRAFT time entries for the current matter from observed
    /// activity, going THROUGH the core for every matter touch (mediated,
    /// entitlement-filtered, audited) — mirroring redaction's `redact_matter` shape.
    ///
    /// Two signal sources, each attempted only if the engine is configured for its
    /// class (via [`Timesheet::with_classes`]) AND the core has granted it (else the
    /// core refuses fail-closed and nothing is seen):
    /// - **EMAIL-time** ([`DataClass::Metadata`]): for each `matter.read:metadata`
    ///   document (email headers `ingest` landed), read the headers via the mediated
    ///   `Core::matter_read_metadata` and propose one [`ActivityKind::Email`] draft
    ///   per email — a deterministic [`narrative`] from recipient+subject, conservative
    ///   [`DEFAULT_UNIT`] / [`DurationSource::Default`] (no measured time for an email).
    /// - **DOCUMENT-review** ([`DataClass::Activity`]): read the document-touch
    ///   ACTIVITY trail via `Core::matter_read_activity`, group touches into review
    ///   SESSIONS ([`document_review_sessions`]; idle gaps > [`SESSION_GAP`] split a
    ///   session so an idle period is never billed), and propose one
    ///   [`ActivityKind::DocumentReview`] draft per session — the session SPAN floored
    ///   at [`DEFAULT_UNIT`], [`DurationSource::AuditTouch`] provenance, a
    ///   cleartext-free narrative (touch COUNT only — see the honesty note on
    ///   [`DurationSource::AuditTouch`]).
    ///
    /// All drafts are emitted [`EntryStatus::Proposed`]. It then AUDIT-NOTEs the
    /// COUNT + per-source breakdown (never the cleartext narrative — confidentiality
    /// split) and PERSISTS the proposals to the `storage:own` draft store, returning
    /// them for human attestation. Returns a `CoreResult` so every refusal
    /// (un-granted class, storage, audit) propagates fail-closed.
    ///
    /// NOTE on re-runs: this DERIVES the full proposal set and `save_drafts` REPLACES
    /// the store — re-running is a fresh proposal, it does NOT merge with prior human
    /// attestations (a stable-identity merge is a follow-up).
    ///
    /// `// TODO(core):` signal sources still NOT exposed by `Core` (deriving from
    /// matter INVENTORY instead would over-propose, violating capture-not-inflate):
    /// - `// TODO(core):` CALENDAR / FOCUS-TIME / TASK signal sources — no mediated
    ///   reads exist; each needs a new class/capability, entitlement-filtered, local
    ///   only (focus-time is additionally a privacy-sensitive design gate).
    /// - `// TODO(core):` a `matter.write` / dedicated time-entry capability if
    ///   drafts should live in the matter rather than module `storage:own` — NOT in
    ///   the spec's §5.1 taxonomy yet (a PROPOSED addition; do not assume it).
    // NOTE: bound to the CONCRETE `InMemoryAudit` (not generic `A: Audit`) because it
    // calls `Core::matter_read_activity`, which is itself concrete-audit-bound so the
    // raw audit chain stays off the module-reachable trait surface (see that method's
    // docs). `save_drafts`/`load_drafts` remain generic over `A: Audit`.
    pub fn collect_drafts<B, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, InMemoryAudit, S, E, C, M>,
    ) -> CoreResult<Vec<DraftEntry>>
    where
        B: CapabilityBroker,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let matter = core.current_matter();
        let mut drafts: Vec<DraftEntry> = Vec::new();
        let mut email_count = 0usize;
        let mut docreview_count = 0usize;

        // INCREMENT 1 signal source: EMAIL metadata. Attempted only when the engine
        // is configured for Metadata; the core still default-deny-checks the grant,
        // so an un-granted read is refused fail-closed (it never reaches a doc).
        if self.classes.contains(&DataClass::Metadata) {
            for doc in core.matter_list_docs(DataClass::Metadata)? {
                let headers = core.matter_read_metadata(doc.id, DataClass::Metadata)?;
                drafts.push(email_draft(&matter, &headers));
                email_count += 1;
            }
        }

        // INCREMENT 2 signal source: the document-touch ACTIVITY trail (the
        // cleartext-free projection of the audit chain). Attempted only when
        // configured for Activity; the core default-deny-checks `matter.read:activity`.
        // Touches are grouped into review SESSIONS (idle gaps split sessions, so an
        // idle period is never billed — capture-not-inflate), one Proposed
        // DocumentReview draft per session, conservative AuditTouch provenance.
        if self.classes.contains(&DataClass::Activity) {
            let events = core.matter_read_activity()?;
            for session in document_review_sessions(&events) {
                drafts.push(document_review_draft(&matter, &session));
                docreview_count += 1;
            }
        }

        // Persist the work product to the storage:own draft billing store FIRST
        // (fail-closed: a storage refusal aborts before we claim a proposal count).
        self.save_drafts(core, &drafts)?;

        // AUDIT-NOTE: COUNT + per-source breakdown ONLY — never a cleartext
        // narrative / recipient / subject (the confidentiality split). Ungated note.
        core.audit_note(&format!(
            "timesheet: proposed {} draft entries ({email_count} email, {docreview_count} document-review)",
            drafts.len()
        ))?;

        Ok(drafts)
    }

    /// Persist a batch of draft entries to the `storage:own` billing store via the
    /// mediated `Core::storage_put`. DISTINCT from the audit chain (two-log
    /// discipline): this stores the WORK PRODUCT (incl. the sensitive cleartext
    /// narratives — which stay local behind the engine's empty egress grant), not
    /// the compliance trail. Serialization is deterministic JSON (struct field
    /// order); a serialize failure is a fail-closed `Backend` error. The whole
    /// batch REPLACES the stored value (the caller owns the merge/append policy).
    pub fn save_drafts<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
        drafts: &[DraftEntry],
    ) -> CoreResult<()>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        // Confidentiality hygiene: do NOT interpolate the serde error — a serde
        // message can echo offending input. Return a structural message only.
        let bytes = serde_json::to_vec(drafts)
            .map_err(|_| CoreError::Backend("timesheet: serialize drafts failed".into()))?;
        core.storage_put(StorageScope::Own, DRAFT_STORE_KEY, bytes)
    }

    /// Load the persisted draft billing store from `storage:own` via the mediated
    /// `Core::storage_get`. Returns an EMPTY vec on a first run (nothing stored
    /// yet), and a fail-closed `Backend` error if the stored bytes are unreadable
    /// (corrupt / wrong shape) rather than silently dropping the work product.
    pub fn load_drafts<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
    ) -> CoreResult<Vec<DraftEntry>>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        match core.storage_get(StorageScope::Own, DRAFT_STORE_KEY)? {
            // Confidentiality hygiene: do NOT interpolate the serde error — on a
            // corrupt/forged store blob serde echoes the offending token, which
            // could ride matter content out in the returned error. Structural only.
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
                CoreError::Backend(
                    "timesheet: draft store is corrupt or unreadable (deserialize failed)".into(),
                )
            }),
            None => Ok(Vec::new()),
        }
    }
}

/// Build one EMAIL draft from recovered email headers (deterministic, pure). The
/// recipient/subject feed the [`narrative`] (cleartext matter content — review-only,
/// never egressed/audited); the date is best-effort from the header (see
/// [`DraftEntry::date`]). Email has no measured time, so the duration is the
/// conservative [`DEFAULT_UNIT`] with [`DurationSource::Default`] provenance —
/// flagged so the lawyer scrutinizes an unmeasured entry. Always `Proposed`.
fn email_draft(matter: &str, headers: &runtime::EmailHeaders) -> DraftEntry {
    let recipient = headers
        .to
        .first()
        .cloned()
        .unwrap_or_else(|| "(no recipient)".to_string());
    let subject = headers
        .subject
        .clone()
        .unwrap_or_else(|| "(no subject)".to_string());
    let date = headers
        .date
        .clone()
        .unwrap_or_else(|| "(no date)".to_string());
    DraftEntry {
        date,
        matter: matter.to_string(),
        activity_kind: ActivityKind::Email,
        narrative: narrative(
            ActivityKind::Email,
            &[
                ("recipient".to_string(), recipient),
                ("subject".to_string(), subject),
            ],
        ),
        duration: DEFAULT_UNIT,
        duration_source: DurationSource::Default,
        utbms: None,
        status: EntryStatus::Proposed,
    }
}

/// The maximum gap between two consecutive document touches that still counts as
/// the SAME review session. A larger gap SPLITS the session, so an idle period is
/// never folded into a billed span (capture-not-inflate). SKELETON value
/// (firm-configurable later).
pub const SESSION_GAP: Duration = Duration::from_secs(10 * 60);

/// A contiguous run of document touches treated as one review session.
struct ReviewSession {
    first_ms: u64,
    last_ms: u64,
    touches: usize,
}

/// Is this activity-event kind a DOCUMENT touch (the document-review signal)? Only
/// document reads + transforms count; a `Read(Metadata)` is the EMAIL signal (it
/// would double-count) and other classes are not document review.
fn is_document_touch(kind: ActivityEventKind) -> bool {
    matches!(
        kind,
        ActivityEventKind::Read(DataClass::Document) | ActivityEventKind::Transform
    )
}

/// Group document-touch ACTIVITY events into review SESSIONS: keep only document
/// touches, order by time, and start a new session whenever the gap from the
/// previous touch exceeds [`SESSION_GAP`]. Deterministic + pure.
fn document_review_sessions(events: &[ActivityEvent]) -> Vec<ReviewSession> {
    let mut times: Vec<u64> = events
        .iter()
        .filter(|e| is_document_touch(e.kind))
        .map(|e| e.timestamp_millis)
        .collect();
    times.sort_unstable();
    let gap_ms = SESSION_GAP.as_millis() as u64;
    let mut sessions: Vec<ReviewSession> = Vec::new();
    for t in times {
        match sessions.last_mut() {
            Some(s) if t.saturating_sub(s.last_ms) <= gap_ms => {
                s.last_ms = t;
                s.touches += 1;
            }
            _ => sessions.push(ReviewSession {
                first_ms: t,
                last_ms: t,
                touches: 1,
            }),
        }
    }
    sessions
}

/// Build a DocumentReview draft from a review session. The duration is the session
/// SPAN (first→last touch) floored at [`DEFAULT_UNIT`] (a lone touch still books
/// the 0.1h minimum); provenance [`DurationSource::AuditTouch`]. The narrative
/// carries NO cleartext — the audit trail has no doc names, only a touch COUNT — so
/// a document-review draft is cleartext-free by construction. Always `Proposed`.
///
/// The count is phrased "recorded touches", NOT "documents": one logical operation
/// can emit several audit entries (e.g. a `document_transform` logs an internal read
/// plus a start+complete), so the touch count is a magnitude signal, not a document
/// tally — honest phrasing avoids implying N distinct documents.
fn document_review_draft(matter: &str, session: &ReviewSession) -> DraftEntry {
    let span = Duration::from_millis(session.last_ms.saturating_sub(session.first_ms));
    DraftEntry {
        date: epoch_ms_to_ymd(session.first_ms),
        matter: matter.to_string(),
        activity_kind: ActivityKind::DocumentReview,
        narrative: format!(
            "Document review ({} recorded {})",
            session.touches,
            if session.touches == 1 {
                "touch"
            } else {
                "touches"
            }
        ),
        duration: span.max(DEFAULT_UNIT),
        duration_source: DurationSource::AuditTouch,
        utbms: None,
        status: EntryStatus::Proposed,
    }
}

/// Convert epoch MILLISECONDS to a `YYYY-MM-DD` UTC date string — deterministic,
/// dep-free (the inverse days-from-civil algorithm, Howard Hinnant, public domain).
/// Used to date a document-review session from its first touch. Integer-only; for
/// the post-1970 timestamps the audit clock produces, `days` is non-negative.
///
/// NOTE (shared algorithm): `inbox::dateparse::civil_from_days` holds this SAME Hinnant
/// inverse (test-only there). The two are deliberately kept as small dep-free copies
/// rather than a new shared crate (one ~15-line public-domain algorithm, test-only on
/// the other side) — keep them in sync if either changes.
fn epoch_ms_to_ymd(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64; // whole days since 1970-01-01 (UTC)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

impl ActivityKind {
    /// Stable, deterministic (non-localized) label for exports / display.
    pub fn label(self) -> &'static str {
        match self {
            ActivityKind::Email => "Email",
            ActivityKind::DocumentReview => "Document review",
            ActivityKind::Task => "Task",
            ActivityKind::Meeting => "Meeting",
            ActivityKind::FocusBlock => "Focus block",
        }
    }
}

impl DurationSource {
    /// Stable label for exports / provenance display.
    pub fn label(self) -> &'static str {
        match self {
            DurationSource::Timer => "timer",
            DurationSource::Calendar => "calendar",
            DurationSource::FocusTime => "focus-time",
            DurationSource::AuditTouch => "audit-touch",
            DurationSource::Default => "default",
        }
    }
}

impl EntryStatus {
    /// Stable label for exports.
    pub fn label(self) -> &'static str {
        match self {
            EntryStatus::Proposed => "proposed",
            EntryStatus::Confirmed => "confirmed",
            EntryStatus::Done => "done",
            EntryStatus::Dismissed => "dismissed",
        }
    }

    /// The attestation-lifecycle transitions a HUMAN may apply (the engine only
    /// ever EMITS `Proposed`). One-way flow so a transition can't resurrect a
    /// Dismissed entry, un-confirm a Done one, or skip review:
    ///   `Proposed`  -> `Confirmed` | `Dismissed`
    ///   `Confirmed` -> `Done` | `Dismissed`
    /// `Done` / `Dismissed` are TERMINAL. Anything else is illegal.
    pub fn can_transition_to(self, to: EntryStatus) -> bool {
        matches!(
            (self, to),
            (EntryStatus::Proposed, EntryStatus::Confirmed)
                | (EntryStatus::Proposed, EntryStatus::Dismissed)
                | (EntryStatus::Confirmed, EntryStatus::Done)
                | (EntryStatus::Confirmed, EntryStatus::Dismissed)
        )
    }
}

impl DraftEntry {
    /// Apply a human attestation-lifecycle transition, FAIL-CLOSED: an illegal
    /// transition (see [`EntryStatus::can_transition_to`]) is refused with an error
    /// and the entry is left unchanged. The engine never calls this — only a human
    /// review action does (the engine emits `Proposed` and stops).
    pub fn transition(&mut self, to: EntryStatus) -> CoreResult<()> {
        if !self.status.can_transition_to(to) {
            return Err(CoreError::Backend(format!(
                "illegal draft transition {:?} -> {:?}",
                self.status, to
            )));
        }
        self.status = to;
        Ok(())
    }
}

/// The billable duration of `d` in TENTHS of an hour (the 0.1h legal increment),
/// rounded DOWN (truncated) — the conservative, client-favoured direction (never
/// bill more than the recorded time). Deterministic integer math, no float. Real
/// entries are floored at [`DEFAULT_UNIT`] (0.1h) in derivation, so this is ≥ 1 for
/// them; a hypothetical sub-unit duration truncates to 0 tenths (a $0 line), never
/// rounds up.
fn tenths_of_hour(d: Duration) -> u64 {
    d.as_secs() / 360
}

/// Billable hours as a decimal string to ONE place (the 0.1h increment), e.g.
/// `"0.1"`, `"2.5"`. Deterministic (integer-derived from [`tenths_of_hour`]).
pub fn billable_hours(d: Duration) -> String {
    let t = tenths_of_hour(d);
    format!("{}.{}", t / 10, t % 10)
}

/// Build a DETERMINISTIC, TEMPLATED narrative for an activity (SKELETON). NO
/// model / generative text — a fixed template per [`ActivityKind`] with field
/// substitution (e.g. "Email to {recipient} re {subject}", "Review of {doc}").
/// Missing fields fall back to a neutral placeholder so output stays deterministic.
///
/// CLEARTEXT: the result can quote matter content (recipient / subject / doc
/// name) — it is review-only, never egressed, never audited.
pub fn narrative(kind: ActivityKind, fields: &[(String, String)]) -> String {
    // SKELETON: minimal deterministic substitution helper. The real engine will
    // expand this (firm-configurable templates, UTBMS-aware phrasing) but it MUST
    // remain a fixed template — never a generative model.
    let field = |name: &str| -> String {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| format!("{{{name}}}"))
    };
    match kind {
        ActivityKind::Email => {
            format!("Email to {} re {}", field("recipient"), field("subject"))
        }
        ActivityKind::DocumentReview => format!("Review of {}", field("doc")),
        ActivityKind::Task => format!("Attend to {}", field("task")),
        ActivityKind::Meeting => format!("Meeting re {}", field("subject")),
        ActivityKind::FocusBlock => format!("Work on {}", field("matter")),
    }
}

// ---- Exporters: LOCAL files only, NO network -------------------------------
//
// These produce serialized byte output for a LOCAL file the host writes (the
// engine holds no filesystem and no egress — it returns bytes, it does not
// write/send them). A practice-management PUSH is a future networked connector
// behind a named-destination egress grant, NOT any of these.
//
// `export_csv` (config-free working timesheet) and `export_ledes_1998b` (the
// canonical pipe-delimited legal e-billing flat file) are implemented, deterministic
// + dep-free. LEDES needs a [`BillingConfig`] (rates / timekeeper + client IDs /
// invoice metadata the draft entry does not carry) — the "LEDES/UTBMS opt-in,
// solo-slice default" decision. `export_pdf` (a human-readable invoice PDF) and
// `export_ledes_xml` (the heavier LEDES 2.x XML schema, same data) are still
// `todo!()`.
//
// BILLING SAFETY: the LEDES/PDF *invoice* exporters REFUSE to serialize a draft that
// is not human-attested (only `Confirmed`/`Done` are billable) and refuse an empty
// set — you cannot generate a bill from `Proposed`/`Dismissed` time. CSV (a working
// timesheet, not a bill) has no such restriction.

/// Export draft entries as deterministic RFC 4180 CSV bytes — a human-reviewable
/// "schedule of draft time" (LOCAL file only: the engine RETURNS bytes; the host
/// writes them — there is no filesystem/egress here). Fields containing a comma,
/// double-quote, CR or LF are quoted, with embedded quotes doubled; rows end CRLF.
/// CLEARTEXT: the `narrative` column quotes matter content — review-only, the host
/// must keep the file local (the module holds no egress to send it).
pub fn export_csv(entries: &[DraftEntry]) -> CoreResult<Vec<u8>> {
    let mut out = String::new();
    out.push_str("date,matter,activity,narrative,hours,duration_source,utbms,status\r\n");
    for e in entries {
        let hours = billable_hours(e.duration);
        let row = [
            e.date.as_str(),
            e.matter.as_str(),
            e.activity_kind.label(),
            e.narrative.as_str(),
            hours.as_str(),
            e.duration_source.label(),
            e.utbms.as_deref().unwrap_or(""),
            e.status.label(),
        ];
        for (i, field) in row.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&csv_field(field));
        }
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

/// Quote + escape one CSV field per RFC 4180: wrap in double quotes if it contains
/// a comma, double-quote, CR or LF, escaping embedded quotes by doubling. A field
/// with none of those is emitted verbatim. Deterministic.
///
/// FORMULA-INJECTION GUARD (mirrors `app/automations.py::_csv_safe`): a cell whose
/// first character is `= + - @` or a leading tab/CR/LF is interpreted as a live
/// formula by Excel / Sheets / LibreOffice. The matter / narrative cells are
/// attacker-influenced (they originate from matter data), so prefix a single
/// apostrophe — which spreadsheets strip on display but which defuses the formula —
/// BEFORE the RFC-4180 quoting. Applied to EVERY field so the guard can't be
/// sidestepped by column choice.
fn csv_field(s: &str) -> String {
    let guarded = match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r' | '\n') => {
            let mut g = String::with_capacity(s.len() + 1);
            g.push('\'');
            g.push_str(s);
            g
        }
        _ => s.to_string(),
    };
    if guarded.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// The billing context an INVOICE export ([`export_ledes_1998b`] and [`export_pdf`])
/// needs but a [`DraftEntry`] deliberately does not carry: invoice identity, the
/// client/firm/matter IDs, the billing period, and the SOLO timekeeper and hourly
/// rate. This is the "LEDES/UTBMS opt-in, solo-slice default" decision — a single
/// timekeeper and rate (the common solo/small-firm case); multi-timekeeper rate
/// tables are a later expansion. The host builds this from firm settings.
///
/// Money is integer CENTS (no float — deterministic, exact); dates are `YYYYMMDD`
/// (LEDES's format). The string IDs are caller-supplied and SANITIZED at emit time
/// (the pipe delimiter / newlines are stripped) so a value can never break the
/// pipe-delimited row structure.
#[derive(Debug, Clone)]
pub struct BillingConfig {
    /// `YYYYMMDD` invoice date.
    pub invoice_date: String,
    /// The firm's invoice number / identifier.
    pub invoice_number: String,
    /// The client's identifier for this client (LEDES `CLIENT_ID`).
    pub client_id: String,
    /// The firm's internal matter identifier (LEDES `LAW_FIRM_MATTER_ID`).
    pub law_firm_matter_id: String,
    /// The client's matter identifier (LEDES `CLIENT_MATTER_ID`).
    pub client_matter_id: String,
    /// The firm's own identifier (LEDES `LAW_FIRM_ID`, e.g. a tax/registration id).
    pub law_firm_id: String,
    /// `YYYYMMDD` first day covered by the invoice.
    pub billing_start_date: String,
    /// `YYYYMMDD` last day covered by the invoice.
    pub billing_end_date: String,
    /// A short invoice description (LEDES `INVOICE_DESCRIPTION`).
    pub invoice_description: String,
    /// The (solo) timekeeper's identifier (LEDES `TIMEKEEPER_ID`).
    pub timekeeper_id: String,
    /// The timekeeper's name (LEDES `TIMEKEEPER_NAME`).
    pub timekeeper_name: String,
    /// The timekeeper's classification, e.g. `"PARTNER"` / `"ASSOCIATE"`
    /// (LEDES `TIMEKEEPER_CLASSIFICATION`).
    pub timekeeper_classification: String,
    /// The hourly rate in integer CENTS (e.g. `35000` = $350.00/hour).
    pub hourly_rate_cents: u64,
}

/// Format integer cents as a 2-decimal money string, e.g. `17500` → `"175.00"`.
/// Deterministic, no float, locale-independent (always `.`). `u128` so a large
/// invoice total cannot overflow.
fn fmt_money(cents: u128) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// Format tenths-of-an-hour as a 2-decimal hours string (LEDES units), e.g. `5`
/// (0.5h) → `"0.50"`, `23` → `"2.30"`.
fn fmt_units(tenths: u64) -> String {
    format!("{}.{:02}", tenths / 10, (tenths % 10) * 10)
}

/// The cents billed for `tenths` tenths-of-an-hour at `rate_cents`/hour, exact
/// integer math: `rate_cents * tenths / 10`. Truncates a fractional cent DOWN
/// (client-favoured). `u128` + `saturating` so even absurd inputs cannot overflow.
fn line_total_cents(rate_cents: u64, tenths: u64) -> u128 {
    (rate_cents as u128).saturating_mul(tenths as u128) / 10
}

/// Normalize a draft entry's `date` to LEDES `YYYYMMDD`: an ISO `YYYY-MM-DD` becomes
/// `YYYYMMDD`; anything else (e.g. an email's best-effort raw RFC-822 date) falls
/// back to the invoice date, so a line is always validly dated. Deterministic.
fn ledes_date(entry_date: &str, fallback_yyyymmdd: &str) -> String {
    let b = entry_date.as_bytes();
    let iso = b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        });
    if iso {
        format!(
            "{}{}{}",
            &entry_date[0..4],
            &entry_date[5..7],
            &entry_date[8..10]
        )
    } else {
        fallback_yyyymmdd.to_string()
    }
}

/// Sanitize one LEDES field value so it can never break the row structure for EITHER
/// parser style: the pipe DELIMITER and CR/LF (a newline-record parser) become a
/// space, and the `[` / `]` RECORD-TERMINATOR brackets (a `[]`-splitting parser)
/// become `(` / `)`. LEDES 1998B defines no field-escape mechanism, so neutralizing
/// the structural characters is the safe, standard approach (e.g. `[REDACTED]` in a
/// narrative renders `(REDACTED)`).
fn ledes_field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '|' | '\r' | '\n' => ' ',
            '[' => '(',
            ']' => ')',
            other => other,
        })
        .collect()
}

/// Refuse to build a BILL from non-attested or empty drafts: every entry must be
/// human-attested ([`EntryStatus::Confirmed`] or [`EntryStatus::Done`]) and there
/// must be at least one. This encodes the honesty invariant — `Proposed`/`Dismissed`
/// time is never emitted as billable. Fail-closed `CoreResult`.
fn ensure_billable(entries: &[DraftEntry]) -> CoreResult<()> {
    if entries.is_empty() {
        return Err(CoreError::Backend(
            "timesheet: cannot export an empty invoice".into(),
        ));
    }
    let unattested = entries
        .iter()
        .filter(|e| !matches!(e.status, EntryStatus::Confirmed | EntryStatus::Done))
        .count();
    if unattested > 0 {
        return Err(CoreError::Backend(format!(
            "timesheet: refusing to bill {unattested} un-attested entr{} (only Confirmed/Done are billable)",
            if unattested == 1 { "y" } else { "ies" }
        )));
    }
    Ok(())
}

/// Export attested draft entries as a LEDES 1998B flat file (the canonical
/// pipe-delimited legal e-billing format) — LOCAL bytes only (the engine RETURNS
/// them; the host writes the file; no filesystem/egress here). Deterministic,
/// dep-free.
///
/// Every entry is a FEE line item (`F`); units come from the entry duration in 0.1h
/// increments ([`tenths_of_hour`], client-favoured), the unit cost is the config
/// rate, and the line total is exact integer cents ([`line_total_cents`]). The
/// `INVOICE_TOTAL` (repeated on each row per the spec) is the sum of line totals.
/// Field values are [`ledes_field`]-sanitized so a narrative cannot break the row.
///
/// BILLING SAFETY ([`ensure_billable`]): refuses unless every entry is attested
/// (`Confirmed`/`Done`) and the set is non-empty — a bill is never made from
/// `Proposed` time. CLEARTEXT: `LINE_ITEM_DESCRIPTION` carries the narrative (matter
/// content) — that is the bill's purpose; the host keeps the file local.
pub fn export_ledes_1998b(entries: &[DraftEntry], config: &BillingConfig) -> CoreResult<Vec<u8>> {
    ensure_billable(entries)?;

    // Pre-compute each line's units + total, and the invoice total, so the repeated
    // INVOICE_TOTAL field is consistent across rows.
    let lines: Vec<(u64, u128)> = entries
        .iter()
        .map(|e| {
            let tenths = tenths_of_hour(e.duration);
            (tenths, line_total_cents(config.hourly_rate_cents, tenths))
        })
        .collect();
    // saturating sum (mirrors the per-line saturating_mul) so an absurd total can
    // never wrap silently in release / panic in debug.
    let invoice_total: u128 = lines
        .iter()
        .fold(0u128, |acc, (_, total)| acc.saturating_add(*total));
    let unit_cost = fmt_money(config.hourly_rate_cents as u128);
    let invoice_total_str = fmt_money(invoice_total);

    let mut out = String::new();
    out.push_str("LEDES1998B[]\n");
    out.push_str(concat!(
        "INVOICE_DATE|INVOICE_NUMBER|CLIENT_ID|LAW_FIRM_MATTER_ID|INVOICE_TOTAL|",
        "BILLING_START_DATE|BILLING_END_DATE|INVOICE_DESCRIPTION|LINE_ITEM_NUMBER|",
        "EXP/FEE/INV_ADJ_TYPE|LINE_ITEM_NUMBER_OF_UNITS|LINE_ITEM_ADJUSTMENT_AMOUNT|",
        "LINE_ITEM_TOTAL|LINE_ITEM_DATE|LINE_ITEM_TASK_CODE|LINE_ITEM_EXPENSE_CODE|",
        "LINE_ITEM_ACTIVITY_CODE|TIMEKEEPER_ID|LINE_ITEM_DESCRIPTION|LAW_FIRM_ID|",
        "LINE_ITEM_UNIT_COST|TIMEKEEPER_NAME|TIMEKEEPER_CLASSIFICATION|CLIENT_MATTER_ID[]\n"
    ));

    for (i, (entry, (tenths, total))) in entries.iter().zip(lines.iter()).enumerate() {
        let fields = [
            ledes_field(&config.invoice_date),
            ledes_field(&config.invoice_number),
            ledes_field(&config.client_id),
            ledes_field(&config.law_firm_matter_id),
            invoice_total_str.clone(),
            ledes_field(&config.billing_start_date),
            ledes_field(&config.billing_end_date),
            ledes_field(&config.invoice_description),
            (i + 1).to_string(),
            "F".to_string(),
            fmt_units(*tenths),
            "0.00".to_string(),
            fmt_money(*total),
            ledes_date(&entry.date, &config.invoice_date),
            ledes_field(entry.utbms.as_deref().unwrap_or("")),
            String::new(), // LINE_ITEM_EXPENSE_CODE — not an expense line
            String::new(), // LINE_ITEM_ACTIVITY_CODE — not classified yet
            ledes_field(&config.timekeeper_id),
            ledes_field(&entry.narrative),
            ledes_field(&config.law_firm_id),
            unit_cost.clone(),
            ledes_field(&config.timekeeper_name),
            ledes_field(&config.timekeeper_classification),
            ledes_field(&config.client_matter_id),
        ];
        out.push_str(&fields.join("|"));
        out.push_str("[]\n");
    }

    Ok(out.into_bytes())
}

/// Char-safe truncate to at most `max` chars (no panic on a multibyte boundary).
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Escape one display line as a PDF literal string body (the bytes that go inside
/// `(...)`). PDF strings are byte strings: `\`, `(`, `)` are escaped; CR/LF become a
/// space (a line is single); every other byte outside printable ASCII is octal-
/// escaped (`\ooo`) so it is parser-safe — with `/WinAnsiEncoding` a Latin-1 byte
/// renders its accented glyph. A codepoint above U+00FF (outside WinAnsi) becomes
/// `?` (the exact text is in the CSV/LEDES exports; the PDF is the human view).
fn pdf_escape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for ch in s.chars() {
        let b = if (ch as u32) <= 0xFF { ch as u8 } else { b'?' };
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'(' => out.extend_from_slice(b"\\("),
            b')' => out.extend_from_slice(b"\\)"),
            b'\r' | b'\n' => out.push(b' '),
            0x20..=0x7E => out.push(b),
            _ => out.extend_from_slice(format!("\\{b:03o}").as_bytes()),
        }
    }
    out
}

/// Build one page's content stream: Courier 10pt, 14pt leading, text from the top
/// margin down, one display line per row.
fn pdf_page_content(lines: &[String]) -> Vec<u8> {
    let mut c = Vec::new();
    // Begin text; set font F1 @ 10pt; leading 14; first baseline at (50, 742).
    c.extend_from_slice(b"BT\n/F1 10 Tf\n14 TL\n50 742 Td\n");
    for line in lines {
        c.push(b'(');
        c.extend_from_slice(&pdf_escape(line));
        c.extend_from_slice(b") Tj\nT*\n");
    }
    c.extend_from_slice(b"ET\n");
    c
}

/// Export attested draft entries as a human-readable invoice PDF — LOCAL bytes only
/// (the engine RETURNS them; the host writes the file; no filesystem/egress here).
/// HAND-WRITTEN, deterministic, DEP-FREE: a minimal multi-page PDF 1.4 using the
/// standard Courier font (monospace, so the columns align with space padding; no font
/// embedding). No timestamps / no RNG, so byte-identical for identical input.
///
/// Layout: an invoice header (number / date / client / matter / timekeeper / rate),
/// a `Date | Description | Hours | Amount` table (one row per entry, description
/// truncated to fit, amounts = duration-in-0.1h × rate), and a total — paginated at
/// [`PDF_ROWS_PER_PAGE`] lines/page.
///
/// BILLING SAFETY ([`ensure_billable`]): refuses unless every entry is attested
/// (`Confirmed`/`Done`) and the set is non-empty. CLEARTEXT: the description column
/// quotes the narrative (matter content) — the bill's purpose; the host keeps it local.
pub fn export_pdf(entries: &[DraftEntry], config: &BillingConfig) -> CoreResult<Vec<u8>> {
    ensure_billable(entries)?;

    // --- Build the display lines (Courier monospace -> space-padded columns align).
    let mut total: u128 = 0;
    let mut lines: Vec<String> = Vec::new();
    lines.push("INVOICE".to_string());
    lines.push(format!(
        "Invoice {}   Date {}",
        config.invoice_number, config.invoice_date
    ));
    lines.push(format!(
        "Client {}   Matter {}",
        config.client_id, config.client_matter_id
    ));
    lines.push(format!(
        "Timekeeper {} ({})   Rate {}/h",
        config.timekeeper_name,
        config.timekeeper_classification,
        fmt_money(config.hourly_rate_cents as u128)
    ));
    lines.push(String::new());
    lines.push(format!(
        "{:<10} {:<50} {:>6} {:>11}",
        "Date", "Description", "Hours", "Amount"
    ));
    for e in entries {
        let tenths = tenths_of_hour(e.duration);
        let amount = line_total_cents(config.hourly_rate_cents, tenths);
        total = total.saturating_add(amount);
        lines.push(format!(
            "{:<10} {:<50} {:>6} {:>11}",
            truncate_chars(&e.date, 10),
            truncate_chars(&e.narrative, 50),
            fmt_units(tenths),
            fmt_money(amount)
        ));
    }
    lines.push(String::new());
    lines.push(format!("TOTAL {}", fmt_money(total)));
    // Defensive per-line cap so a long config field can never run absurdly wide.
    for l in &mut lines {
        if l.chars().count() > 95 {
            *l = truncate_chars(l, 95);
        }
    }

    // --- Paginate, then assemble objects, recording each object's byte offset for
    // the xref. Object numbering: 1=Catalog, 2=Pages, 3=Font, then per page p:
    // page object = 4+2p, content object = 5+2p.
    let pages: Vec<&[String]> = lines.chunks(PDF_ROWS_PER_PAGE).collect();
    let num_pages = pages.len();
    let num_objs = 3 + 2 * num_pages;
    let mut offsets = vec![0usize; num_objs + 1]; // 1-indexed
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n");

    offsets[1] = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets[2] = buf.len();
    let kids: String = (0..num_pages)
        .map(|i| format!("{} 0 R", 4 + 2 * i))
        .collect::<Vec<_>>()
        .join(" ");
    buf.extend_from_slice(
        format!("2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>\nendobj\n")
            .as_bytes(),
    );

    offsets[3] = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n",
    );

    for (i, page_lines) in pages.iter().enumerate() {
        let page_obj = 4 + 2 * i;
        let content_obj = 5 + 2 * i;
        let content = pdf_page_content(page_lines);

        offsets[page_obj] = buf.len();
        buf.extend_from_slice(
            format!(
                "{page_obj} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                 /Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj} 0 R >>\nendobj\n"
            )
            .as_bytes(),
        );

        offsets[content_obj] = buf.len();
        buf.extend_from_slice(
            format!(
                "{content_obj} 0 obj\n<< /Length {} >>\nstream\n",
                content.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&content);
        buf.extend_from_slice(b"endstream\nendobj\n");
    }

    // --- xref (each entry EXACTLY 20 bytes) + trailer.
    let xref_offset = buf.len();
    buf.extend_from_slice(format!("xref\n0 {}\n", num_objs + 1).as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for &off in &offsets[1..=num_objs] {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            num_objs + 1
        )
        .as_bytes(),
    );

    Ok(buf)
}

/// Display lines per PDF page (US-Letter, 10pt Courier @ 14pt leading from a 742pt
/// top baseline leaves room for ~48 rows above the bottom margin).
pub const PDF_ROWS_PER_PAGE: usize = 48;

/// Escape one text value for an XML element body / attribute: the five predefined
/// entities (`& < > " '`), with the XML-1.0-illegal control characters neutralized
/// (tab/CR/LF → space, others dropped — they cannot be represented in XML 1.0 even as
/// entities). Non-ASCII is kept verbatim (the document is UTF-8), so names render
/// correctly. Deterministic.
fn xml_escape(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(' '),
            c if (c as u32) < 0x20 => {} // other control chars: invalid in XML 1.0 — drop
            c => out.push(c),
        }
    }
    out
}

/// Append one XML element line. The `tag` is a fixed literal (never user input, so
/// not escaped); the `value` is [`xml_escape`]d. An element whose value is empty
/// AFTER escaping (truly empty, or only XML-illegal control chars that get dropped)
/// emits a self-closing `<tag/>` — decided post-escape so the empty form is consistent.
fn xml_el(out: &mut String, indent: &str, tag: &str, value: &str) {
    let escaped = xml_escape(value);
    if escaped.is_empty() {
        out.push_str(indent);
        out.push('<');
        out.push_str(tag);
        out.push_str("/>\n");
    } else {
        out.push_str(&format!("{indent}<{tag}>{escaped}</{tag}>\n"));
    }
}

/// Export attested draft entries as a LEDES-XML billing document — LOCAL bytes only
/// (the engine RETURNS them; the host writes the file; no filesystem/egress here).
/// HAND-WRITTEN, deterministic, DEP-FREE.
///
/// Carries the canonical LEDES 1998B field SET (same invoice-level identity + per-line
/// fee fields, and the SAME integer-cent money / 0.1h-floored units / `ledes_date` as
/// [`export_ledes_1998b`] — the totals cross-check) as XML elements under an
/// `invoice → line_items → line_item` hierarchy (so invoice-level fields appear ONCE,
/// not repeated per row as in the flat file). The output is well-formed UTF-8 XML with
/// every value [`xml_escape`]d.
///
/// SCHEMA CAVEAT (honest): there are several LEDES XML versions (2.0 / 2.1 / Ebilling
/// 2.2) whose exact element names + namespace differ, and the official schema is not
/// reproduced here. This emits a well-formed, deterministic LEDES-shaped document using
/// the canonical field names; VALIDATE it against your e-billing receiver's exact XSD
/// before submitting. The 1998B flat file ([`export_ledes_1998b`]) is the
/// format-stable path.
///
/// BILLING SAFETY ([`ensure_billable`]): refuses unless every entry is attested
/// (`Confirmed`/`Done`) and the set is non-empty. CLEARTEXT: `line_item_description`
/// carries the narrative (matter content) — the bill's purpose; the host keeps the
/// file local.
pub fn export_ledes_xml(entries: &[DraftEntry], config: &BillingConfig) -> CoreResult<Vec<u8>> {
    ensure_billable(entries)?;

    // Per-line units + total, and the saturating invoice total — IDENTICAL math to the
    // 1998B exporter (a test cross-checks the totals match).
    let lines: Vec<(u64, u128)> = entries
        .iter()
        .map(|e| {
            let tenths = tenths_of_hour(e.duration);
            (tenths, line_total_cents(config.hourly_rate_cents, tenths))
        })
        .collect();
    let invoice_total: u128 = lines
        .iter()
        .fold(0u128, |acc, (_, t)| acc.saturating_add(*t));
    let unit_cost = fmt_money(config.hourly_rate_cents as u128);

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<ledes>\n  <invoice>\n");
    xml_el(&mut out, "    ", "invoice_date", &config.invoice_date);
    xml_el(&mut out, "    ", "invoice_number", &config.invoice_number);
    xml_el(&mut out, "    ", "client_id", &config.client_id);
    xml_el(
        &mut out,
        "    ",
        "law_firm_matter_id",
        &config.law_firm_matter_id,
    );
    xml_el(
        &mut out,
        "    ",
        "client_matter_id",
        &config.client_matter_id,
    );
    xml_el(&mut out, "    ", "law_firm_id", &config.law_firm_id);
    xml_el(&mut out, "    ", "invoice_total", &fmt_money(invoice_total));
    xml_el(
        &mut out,
        "    ",
        "billing_start_date",
        &config.billing_start_date,
    );
    xml_el(
        &mut out,
        "    ",
        "billing_end_date",
        &config.billing_end_date,
    );
    xml_el(
        &mut out,
        "    ",
        "invoice_description",
        &config.invoice_description,
    );
    out.push_str("    <line_items>\n");
    for (i, (entry, (tenths, total))) in entries.iter().zip(lines.iter()).enumerate() {
        out.push_str("      <line_item>\n");
        xml_el(
            &mut out,
            "        ",
            "line_item_number",
            &(i + 1).to_string(),
        );
        xml_el(&mut out, "        ", "exp_fee_inv_adj_type", "F");
        xml_el(
            &mut out,
            "        ",
            "line_item_number_of_units",
            &fmt_units(*tenths),
        );
        xml_el(&mut out, "        ", "line_item_adjustment_amount", "0.00");
        xml_el(&mut out, "        ", "line_item_total", &fmt_money(*total));
        xml_el(
            &mut out,
            "        ",
            "line_item_date",
            &ledes_date(&entry.date, &config.invoice_date),
        );
        xml_el(
            &mut out,
            "        ",
            "line_item_task_code",
            entry.utbms.as_deref().unwrap_or(""),
        );
        xml_el(&mut out, "        ", "line_item_expense_code", "");
        xml_el(&mut out, "        ", "line_item_activity_code", "");
        xml_el(&mut out, "        ", "timekeeper_id", &config.timekeeper_id);
        xml_el(
            &mut out,
            "        ",
            "line_item_description",
            &entry.narrative,
        );
        xml_el(&mut out, "        ", "line_item_unit_cost", &unit_cost);
        xml_el(
            &mut out,
            "        ",
            "timekeeper_name",
            &config.timekeeper_name,
        );
        xml_el(
            &mut out,
            "        ",
            "timekeeper_classification",
            &config.timekeeper_classification,
        );
        out.push_str("      </line_item>\n");
    }
    out.push_str("    </line_items>\n  </invoice>\n</ledes>\n");

    Ok(out.into_bytes())
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

    /// Build a test core with the given grants and a seeded matter store, mirroring
    /// the redaction module's test harness (deterministic FixedClock; a configured
    /// egress destination so a wrongly-granted egress would be gated by the broker,
    /// not by a missing sink).
    fn core_with(grants: Vec<Capability>, store: InMemoryMatterStore) -> TestCore {
        Core::new(
            "sg.timesheet.engine",
            GrantSet::from_manifest(grants),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            InMemoryEgress::new().with_destination("counsel-vault"),
            CoreContext::new("Acme v Beta", "j.smith"),
            store,
        )
    }

    /// The capabilities the timesheet module declares — as a grant set for tests.
    fn timesheet_grants() -> Vec<Capability> {
        TIMESHEET_CAPABILITIES.to_vec()
    }

    #[test]
    fn declares_metadata_read_storage_own_and_audit_note_but_no_egress() {
        // The module declares matter.read:metadata (email signal) +
        // matter.read:activity (document-review signal), storage:own (the draft
        // store) and audit.note — and crucially NO egress (exports are local; a PM
        // push is a future networked connector).
        assert!(TIMESHEET_CAPABILITIES.contains(&Capability::MatterRead(DataClass::Metadata)));
        assert!(TIMESHEET_CAPABILITIES.contains(&Capability::MatterRead(DataClass::Activity)));
        assert!(TIMESHEET_CAPABILITIES.contains(&Capability::Storage(StorageScope::Own)));
        assert!(TIMESHEET_CAPABILITIES.contains(&Capability::AuditNote));
        assert!(
            !TIMESHEET_CAPABILITIES
                .iter()
                .any(|c| matches!(c, Capability::Egress(_))),
            "the timesheet module must declare NO egress capability"
        );
        // It also declares no document.transform (time-capture reads, never rewrites).
        assert!(!TIMESHEET_CAPABILITIES.contains(&Capability::DocumentTransform));
    }

    #[test]
    fn no_egress_grant_means_an_egress_attempt_is_refused() {
        // Mirror redaction: prove the core REFUSES egress under the module's grant
        // set (which declares no egress), so the "exports are local" posture is
        // enforced by the broker, not just by convention.
        let mut core = core_with(timesheet_grants(), InMemoryMatterStore::new());
        let err = core
            .egress_send("counsel-vault", b"draft entries")
            .unwrap_err();
        assert!(
            matches!(err, runtime::CoreError::Denied(Capability::Egress(_))),
            "no egress grant -> egress refused, got {err:?}"
        );
        assert!(core.egress().sent().is_empty(), "nothing left the box");
    }

    #[test]
    fn engine_constructs_with_and_without_classes() {
        // Construction is pure + infallible (SKELETON shape check).
        assert!(Timesheet::new().classes().is_empty());
        let e = Timesheet::with_classes(vec![DataClass::Document, DataClass::Party]);
        assert_eq!(e.classes(), &[DataClass::Document, DataClass::Party]);
    }

    #[test]
    fn narrative_templates_are_deterministic_and_no_model() {
        // Fixed-template substitution: same input -> identical output, twice.
        let fields = vec![
            ("recipient".to_string(), "opposing counsel".to_string()),
            ("subject".to_string(), "discovery schedule".to_string()),
        ];
        let a = narrative(ActivityKind::Email, &fields);
        let b = narrative(ActivityKind::Email, &fields);
        assert_eq!(a, b, "templated narrative must be deterministic");
        assert_eq!(a, "Email to opposing counsel re discovery schedule");
        // A document-review template.
        let docf = vec![("doc".to_string(), "share purchase agreement".to_string())];
        assert_eq!(
            narrative(ActivityKind::DocumentReview, &docf),
            "Review of share purchase agreement"
        );
        // A missing field falls back to a neutral placeholder (still deterministic).
        assert_eq!(
            narrative(ActivityKind::Email, &[]),
            "Email to {recipient} re {subject}"
        );
    }

    #[test]
    fn draft_entry_records_duration_provenance() {
        // A DraftEntry carries its duration AND how it was derived (defensibility),
        // and is emitted as Proposed (the lawyer attests). This is a shape test.
        let entry = DraftEntry {
            date: "2026-06-19".to_string(),
            matter: "Acme v Beta".to_string(),
            activity_kind: ActivityKind::Meeting,
            narrative: narrative(
                ActivityKind::Meeting,
                &[("subject".to_string(), "status call".to_string())],
            ),
            duration: Duration::from_secs(24 * 60),
            duration_source: DurationSource::Calendar,
            utbms: Some("L120".to_string()),
            status: EntryStatus::Proposed,
        };
        assert_eq!(
            entry.duration_source,
            DurationSource::Calendar,
            "provenance recorded"
        );
        assert_eq!(
            entry.status,
            EntryStatus::Proposed,
            "engine emits drafts, never auto-confirmed"
        );
        assert_eq!(entry.narrative, "Meeting re status call");
    }

    #[test]
    fn default_unit_is_a_six_minute_minimum() {
        // The bare-default fallback is the 0.1h legal minimum increment, and an
        // entry built from it must record DurationSource::Default so the lawyer can
        // scrutinize an unmeasured entry.
        assert_eq!(DEFAULT_UNIT, Duration::from_secs(360));
    }

    /// Seed a `firmos.meta/1` metadata doc (the form `matter_read_metadata` parses)
    /// with the given recipient/subject/date. Values are space-free so percent
    /// encode==decode is identity (the reader passes literal non-`%` chars through),
    /// keeping the fixture independent of the producer crate.
    fn seed_email_metadata(
        store: &mut InMemoryMatterStore,
        id: u64,
        to: &str,
        subj: &str,
        date: &str,
    ) {
        let canonical = format!("firmos.meta/1\nto {to}\nsubject {subj}\ndate {date}\n");
        store.insert(id, DataClass::Metadata, canonical);
    }

    #[test]
    fn collect_drafts_captures_email_time_audits_and_persists() {
        // Increment 1: an email metadata doc -> one Proposed Email draft with the
        // templated narrative + the conservative Default duration/provenance; the
        // proposal is audited (count-only note) and persisted to storage:own.
        let mut store = InMemoryMatterStore::new();
        seed_email_metadata(
            &mut store,
            1,
            "counsel@example.com",
            "discovery",
            "2026-06-19",
        );
        let mut core = core_with(timesheet_grants(), store);

        let drafts = Timesheet::with_classes(vec![DataClass::Metadata])
            .collect_drafts(&mut core)
            .expect("collect_drafts must succeed with the granted classes");

        assert_eq!(drafts.len(), 1, "one email -> one draft");
        let d = &drafts[0];
        assert_eq!(d.activity_kind, ActivityKind::Email);
        assert_eq!(
            d.status,
            EntryStatus::Proposed,
            "engine emits Proposed only"
        );
        assert_eq!(d.duration, DEFAULT_UNIT);
        assert_eq!(
            d.duration_source,
            DurationSource::Default,
            "email has no measured time"
        );
        assert_eq!(d.matter, "Acme v Beta", "labelled with the current matter");
        assert_eq!(d.narrative, "Email to counsel@example.com re discovery");

        // Persisted: a fresh load returns the same drafts.
        let loaded = Timesheet::new().load_drafts(&mut core).expect("load");
        assert_eq!(loaded, drafts, "drafts round-trip through storage:own");

        // Audited: the chain verifies and carries a COUNT-only note (no cleartext).
        assert!(core.audit().verify_chain());
        let note = core
            .audit()
            .entries()
            .iter()
            .find(|e| e.detail.starts_with("note: timesheet:"))
            .expect("a timesheet proposal note is recorded");
        assert!(note
            .detail
            .contains("proposed 1 draft entries (1 email, 0 document-review)"));
        assert!(
            !note.detail.contains("counsel@example.com") && !note.detail.contains("discovery"),
            "the audit note must NOT carry cleartext recipient/subject, got {:?}",
            note.detail
        );
    }

    /// Build a synthetic document-touch activity event at a given epoch-ms.
    fn touch(ms: u64, kind: ActivityEventKind) -> ActivityEvent {
        ActivityEvent {
            timestamp_millis: ms,
            actor: "j.smith".to_string(),
            module: "sg.test".to_string(),
            kind,
        }
    }

    #[test]
    fn is_document_touch_only_counts_document_reads_and_transforms() {
        assert!(is_document_touch(ActivityEventKind::Read(
            DataClass::Document
        )));
        assert!(is_document_touch(ActivityEventKind::Transform));
        // Metadata reads are the EMAIL signal (would double-count); excluded.
        assert!(!is_document_touch(ActivityEventKind::Read(
            DataClass::Metadata
        )));
        assert!(!is_document_touch(ActivityEventKind::Read(
            DataClass::Party
        )));
    }

    #[test]
    fn document_review_sessions_split_on_idle_gap() {
        let min = 60_000u64;
        // 10:00, 10:05 (gap 5m ≤ 10m) -> one session; then 10:30 (gap 25m) -> new.
        let events = vec![
            touch(0, ActivityEventKind::Read(DataClass::Document)),
            touch(5 * min, ActivityEventKind::Transform),
            touch(30 * min, ActivityEventKind::Read(DataClass::Document)),
            // A Metadata read interleaved must NOT count as a document touch.
            touch(6 * min, ActivityEventKind::Read(DataClass::Metadata)),
        ];
        let sessions = document_review_sessions(&events);
        assert_eq!(
            sessions.len(),
            2,
            "a >SESSION_GAP idle period splits sessions"
        );
        assert_eq!(sessions[0].touches, 2);
        assert_eq!(sessions[0].first_ms, 0);
        assert_eq!(sessions[0].last_ms, 5 * min);
        assert_eq!(
            sessions[1].touches, 1,
            "the late lone touch is its own session"
        );
    }

    #[test]
    fn document_review_draft_spans_session_floored_at_default_unit() {
        let min = 60_000u64;
        // A 15-minute session (span above the 6-min DEFAULT_UNIT floor) -> 15 min
        // duration, AuditTouch, dated from first touch.
        let multi = ReviewSession {
            first_ms: 0,
            last_ms: 15 * min,
            touches: 3,
        };
        let d = document_review_draft("Acme v Beta", &multi);
        assert_eq!(d.activity_kind, ActivityKind::DocumentReview);
        assert_eq!(d.duration, Duration::from_secs(15 * 60));
        assert_eq!(d.duration_source, DurationSource::AuditTouch);
        assert_eq!(d.status, EntryStatus::Proposed);
        assert_eq!(d.date, "1970-01-01");
        assert_eq!(d.narrative, "Document review (3 recorded touches)");
        // No cleartext can be present — the audit trail has no doc names.
        // A lone touch (span 0) is floored at the 0.1h minimum.
        let lone = ReviewSession {
            first_ms: 100,
            last_ms: 100,
            touches: 1,
        };
        let d2 = document_review_draft("Acme v Beta", &lone);
        assert_eq!(d2.duration, DEFAULT_UNIT, "a lone touch books the floor");
        assert_eq!(d2.narrative, "Document review (1 recorded touch)");
    }

    #[test]
    fn epoch_ms_to_ymd_known_dates() {
        assert_eq!(epoch_ms_to_ymd(0), "1970-01-01");
        // 1_700_000_000 s = 2023-11-14T22:13:20Z.
        assert_eq!(epoch_ms_to_ymd(1_700_000_000_000), "2023-11-14");
        // A leap day.
        assert_eq!(epoch_ms_to_ymd(1_583_020_800_000), "2020-03-01"); // 2020-03-01T00:00Z
    }

    #[test]
    fn collect_drafts_captures_document_review_from_activity_trail() {
        // Generate document touches, then derive a DocumentReview draft from the
        // activity trail. With the FixedClock all touches share one timestamp, so
        // they form ONE session floored at DEFAULT_UNIT.
        let grants = vec![
            Capability::MatterRead(DataClass::Document),
            Capability::MatterRead(DataClass::Activity),
            Capability::Storage(StorageScope::Own),
            Capability::AuditNote,
        ];
        let mut store = InMemoryMatterStore::new();
        store.insert(1, DataClass::Document, "memo");
        store.insert(2, DataClass::Document, "brief");
        let mut core = core_with(grants, store);
        // Two document reads = two touches (same FixedClock ms -> one session).
        core.matter_read_text(1, DataClass::Document)
            .expect("read 1");
        core.matter_read_text(2, DataClass::Document)
            .expect("read 2");

        let drafts = Timesheet::with_classes(vec![DataClass::Activity])
            .collect_drafts(&mut core)
            .expect("collect");
        let dr: Vec<_> = drafts
            .iter()
            .filter(|d| d.activity_kind == ActivityKind::DocumentReview)
            .collect();
        assert_eq!(
            dr.len(),
            1,
            "two same-instant touches -> one review session"
        );
        assert_eq!(dr[0].duration_source, DurationSource::AuditTouch);
        assert_eq!(dr[0].duration, DEFAULT_UNIT, "zero-span session floored");
        assert_eq!(dr[0].status, EntryStatus::Proposed);
        // Audited with a document-review count (no cleartext).
        assert!(core.audit().verify_chain());
        assert!(core
            .audit()
            .entries()
            .iter()
            .any(|e| e.detail.contains("1 document-review")));
        // Persisted.
        assert_eq!(Timesheet::new().load_drafts(&mut core).unwrap(), drafts);
    }

    #[test]
    fn collect_drafts_without_activity_grant_is_refused() {
        // Configured for Activity but NOT granted matter.read:activity -> refused.
        let grants = vec![
            Capability::Storage(StorageScope::Own),
            Capability::AuditNote,
        ];
        let mut core = core_with(grants, InMemoryMatterStore::new());
        let err = Timesheet::with_classes(vec![DataClass::Activity])
            .collect_drafts(&mut core)
            .unwrap_err();
        assert!(
            matches!(
                err,
                runtime::CoreError::Denied(Capability::MatterRead(DataClass::Activity))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn collect_drafts_without_metadata_grant_is_refused() {
        // Default-deny: configured for Metadata but NOT granted matter.read:metadata
        // -> the core refuses fail-closed and nothing is persisted.
        let mut store = InMemoryMatterStore::new();
        seed_email_metadata(&mut store, 1, "a@b.com", "x", "2026-06-19");
        // Grants WITHOUT matter.read:metadata.
        let grants = vec![
            Capability::Storage(StorageScope::Own),
            Capability::AuditNote,
        ];
        let mut core = core_with(grants, store);

        let err = Timesheet::with_classes(vec![DataClass::Metadata])
            .collect_drafts(&mut core)
            .unwrap_err();
        assert!(
            matches!(
                err,
                runtime::CoreError::Denied(Capability::MatterRead(DataClass::Metadata))
            ),
            "un-granted metadata read must be refused, got {err:?}"
        );
        // Nothing was persisted (the refusal aborted before save).
        let loaded = Timesheet::new().load_drafts(&mut core).expect("load");
        assert!(loaded.is_empty(), "a refused collect must persist nothing");
    }

    #[test]
    fn collect_drafts_with_no_configured_classes_proposes_nothing() {
        // An engine configured for no classes reads no signal and proposes nothing,
        // but still persists (an empty store) + audits the zero count.
        let mut core = core_with(timesheet_grants(), InMemoryMatterStore::new());
        let drafts = Timesheet::new().collect_drafts(&mut core).expect("ok");
        assert!(drafts.is_empty());
        assert!(Timesheet::new().load_drafts(&mut core).unwrap().is_empty());
    }

    #[test]
    fn save_load_round_trip_preserves_entries() {
        let mut core = core_with(timesheet_grants(), InMemoryMatterStore::new());
        let entries = vec![DraftEntry {
            date: "2026-06-19".to_string(),
            matter: "Acme v Beta".to_string(),
            activity_kind: ActivityKind::Meeting,
            narrative: "Meeting re status call".to_string(),
            duration: Duration::from_secs(24 * 60),
            duration_source: DurationSource::Calendar,
            utbms: Some("L120".to_string()),
            status: EntryStatus::Proposed,
        }];
        Timesheet::new()
            .save_drafts(&mut core, &entries)
            .expect("save");
        assert_eq!(
            Timesheet::new().load_drafts(&mut core).expect("load"),
            entries
        );
    }

    #[test]
    fn load_drafts_is_empty_on_first_run() {
        let mut core = core_with(timesheet_grants(), InMemoryMatterStore::new());
        assert!(Timesheet::new()
            .load_drafts(&mut core)
            .expect("load")
            .is_empty());
    }

    #[test]
    fn export_csv_is_deterministic_and_rfc4180_quotes() {
        // A narrative containing a comma + a double-quote must be quoted with the
        // quote doubled; output is byte-identical across two calls.
        let entries = vec![DraftEntry {
            date: "2026-06-19".to_string(),
            matter: "Acme v Beta".to_string(),
            activity_kind: ActivityKind::Email,
            narrative: "Email to a@b.com re \"urgent\", reply".to_string(),
            duration: DEFAULT_UNIT,
            duration_source: DurationSource::Default,
            utbms: None,
            status: EntryStatus::Proposed,
        }];
        let a = export_csv(&entries).expect("csv");
        let b = export_csv(&entries).expect("csv");
        assert_eq!(a, b, "CSV export is deterministic");
        let s = String::from_utf8(a).expect("utf8");
        assert!(
            s.starts_with("date,matter,activity,narrative,hours,duration_source,utbms,status\r\n")
        );
        // The comma+quote field is wrapped and its quotes doubled.
        assert!(
            s.contains("\"Email to a@b.com re \"\"urgent\"\", reply\""),
            "got: {s}"
        );
        assert!(
            s.contains(",0.1,default,,proposed\r\n"),
            "hours/source/empty-utbms/status, got: {s}"
        );
        assert!(s.ends_with("\r\n"));
    }

    #[test]
    fn export_csv_defuses_spreadsheet_formula_injection() {
        // A matter (or narrative) beginning with a formula trigger (= + - @ or a
        // leading tab) must be neutralized with a leading apostrophe so it can't
        // execute on open in Excel/Sheets — matching app/automations.py's guard.
        let entries = vec![DraftEntry {
            date: "2026-06-19".to_string(),
            matter: "=HYPERLINK(\"http://evil\",\"x\")".to_string(),
            activity_kind: ActivityKind::Email,
            narrative: "+1+2 from a cell".to_string(),
            duration: DEFAULT_UNIT,
            duration_source: DurationSource::Default,
            utbms: None,
            status: EntryStatus::Proposed,
        }];
        let s = String::from_utf8(export_csv(&entries).expect("csv")).expect("utf8");
        // The matter cell starts with =, contains a comma+quote -> apostrophe-prefixed
        // THEN RFC-4180 quoted (the apostrophe is inside the quotes, the formula defused).
        assert!(
            s.contains("\"'=HYPERLINK("),
            "matter formula must be apostrophe-guarded, got: {s}"
        );
        // The narrative cell starts with + (no comma/quote) -> apostrophe-prefixed, unquoted.
        assert!(
            s.contains(",'+1+2 from a cell,"),
            "narrative formula must be guarded, got: {s}"
        );
    }

    #[test]
    fn export_csv_empty_is_header_only() {
        let s = String::from_utf8(export_csv(&[]).expect("csv")).expect("utf8");
        assert_eq!(
            s,
            "date,matter,activity,narrative,hours,duration_source,utbms,status\r\n"
        );
    }

    #[test]
    fn draft_transition_enforces_attestation_lifecycle() {
        let base = DraftEntry {
            date: "2026-06-19".to_string(),
            matter: "Acme v Beta".to_string(),
            activity_kind: ActivityKind::Email,
            narrative: "Email to x re y".to_string(),
            duration: DEFAULT_UNIT,
            duration_source: DurationSource::Default,
            utbms: None,
            status: EntryStatus::Proposed,
        };
        // Legal: Proposed -> Confirmed -> Done.
        let mut e = base.clone();
        e.transition(EntryStatus::Confirmed)
            .expect("proposed->confirmed");
        e.transition(EntryStatus::Done).expect("confirmed->done");
        assert_eq!(e.status, EntryStatus::Done);
        // Illegal: skipping review (Proposed -> Done) is refused, entry unchanged.
        let mut e2 = base.clone();
        assert!(
            e2.transition(EntryStatus::Done).is_err(),
            "must not skip Confirmed"
        );
        assert_eq!(
            e2.status,
            EntryStatus::Proposed,
            "refused transition leaves status unchanged"
        );
        // Terminal: Done/Dismissed cannot move on.
        assert!(
            e.transition(EntryStatus::Dismissed).is_err(),
            "Done is terminal"
        );
        let mut e3 = base.clone();
        e3.transition(EntryStatus::Dismissed)
            .expect("proposed->dismissed");
        assert!(
            e3.transition(EntryStatus::Confirmed).is_err(),
            "Dismissed is terminal"
        );
    }

    /// A test billing config: $350/h solo partner, fixed invoice identity.
    fn test_billing_config() -> BillingConfig {
        BillingConfig {
            invoice_date: "20260622".to_string(),
            invoice_number: "INV-001".to_string(),
            client_id: "ACME".to_string(),
            law_firm_matter_id: "M-42".to_string(),
            client_matter_id: "ACME-LIT-7".to_string(),
            law_firm_id: "FIRM-1".to_string(),
            billing_start_date: "20260601".to_string(),
            billing_end_date: "20260630".to_string(),
            invoice_description: "June fees".to_string(),
            timekeeper_id: "TK-1".to_string(),
            timekeeper_name: "Jane Smith".to_string(),
            timekeeper_classification: "PARTNER".to_string(),
            hourly_rate_cents: 35000,
        }
    }

    /// A billable (attested) entry with the given duration + narrative + date.
    fn billable_entry(secs: u64, narrative: &str, date: &str) -> DraftEntry {
        DraftEntry {
            date: date.to_string(),
            matter: "Acme v Beta".to_string(),
            activity_kind: ActivityKind::DocumentReview,
            narrative: narrative.to_string(),
            duration: Duration::from_secs(secs),
            duration_source: DurationSource::AuditTouch,
            utbms: Some("L120".to_string()),
            status: EntryStatus::Confirmed,
        }
    }

    #[test]
    fn money_and_units_helpers_are_exact_integer_math() {
        assert_eq!(fmt_money(17500), "175.00");
        assert_eq!(fmt_money(0), "0.00");
        assert_eq!(fmt_money(5), "0.05");
        assert_eq!(fmt_units(5), "0.50");
        assert_eq!(fmt_units(23), "2.30");
        // 0.5h at $350/h = $175.00 exactly.
        assert_eq!(line_total_cents(35000, 5), 17500);
        // tenths floor (client-favoured): 0.25h -> 0.2h.
        assert_eq!(tenths_of_hour(Duration::from_secs(900)), 2);
        assert_eq!(billable_hours(Duration::from_secs(900)), "0.2");
        assert_eq!(billable_hours(DEFAULT_UNIT), "0.1");
    }

    #[test]
    fn ledes_date_normalizes_iso_and_falls_back() {
        assert_eq!(ledes_date("2026-06-19", "20260622"), "20260619");
        // A non-ISO (raw email) date falls back to the invoice date.
        assert_eq!(
            ledes_date("Mon, 19 Jun 2026 10:00:00 +0000", "20260622"),
            "20260622"
        );
        assert_eq!(ledes_date("", "20260622"), "20260622");
    }

    #[test]
    fn ledes_field_strips_structure_breakers() {
        assert_eq!(ledes_field("a|b\nc\rd"), "a b c d");
        assert_eq!(ledes_field("clean text"), "clean text");
        // The [] record-terminator brackets are neutralized too (both parser styles).
        assert_eq!(ledes_field("see [REDACTED] now"), "see (REDACTED) now");
        assert_eq!(ledes_field("end[]marker"), "end()marker");
    }

    #[test]
    fn export_ledes_1998b_is_well_formed_and_deterministic() {
        let entries = vec![
            billable_entry(360, "Email to counsel re discovery", "2026-06-19"), // 0.1h
            billable_entry(
                15 * 60,
                "Document review (3 recorded touches)",
                "2026-06-20",
            ), // 0.25h->0.2h
        ];
        let cfg = test_billing_config();
        let a = export_ledes_1998b(&entries, &cfg).expect("ledes");
        let b = export_ledes_1998b(&entries, &cfg).expect("ledes");
        assert_eq!(a, b, "LEDES export is deterministic");
        let s = String::from_utf8(a).expect("utf8");
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "LEDES1998B[]");
        assert!(lines[1].starts_with("INVOICE_DATE|INVOICE_NUMBER|"));
        assert!(lines[1].ends_with("CLIENT_MATTER_ID[]"));
        // Two data rows, each 24 fields, each terminated with [].
        assert_eq!(lines.len(), 4, "header block (2) + 2 data rows");
        for row in &lines[2..] {
            assert!(row.ends_with("[]"), "row terminated: {row}");
            let body = row.strip_suffix("[]").unwrap();
            assert_eq!(body.split('|').count(), 24, "24 fields: {row}");
        }
        // Row 1: 0.1h at $350 = $35.00; UTBMS L120; ISO date normalized; F type.
        let r1: Vec<&str> = lines[2].strip_suffix("[]").unwrap().split('|').collect();
        assert_eq!(r1[9], "F");
        assert_eq!(r1[10], "0.10"); // units
        assert_eq!(r1[12], "35.00"); // line total
        assert_eq!(r1[13], "20260619"); // line date normalized
        assert_eq!(r1[14], "L120"); // task code
        assert_eq!(r1[18], "Email to counsel re discovery"); // description
        assert_eq!(r1[20], "350.00"); // unit cost
                                      // Row 2: 0.2h at $350 = $70.00.
        let r2: Vec<&str> = lines[3].strip_suffix("[]").unwrap().split('|').collect();
        assert_eq!(r2[10], "0.20");
        assert_eq!(r2[12], "70.00");
        // INVOICE_TOTAL (field 5, index 4) = 35.00 + 70.00 = 105.00, same on both rows.
        assert_eq!(r1[4], "105.00");
        assert_eq!(r2[4], "105.00");
    }

    #[test]
    fn export_ledes_1998b_refuses_unattested_and_empty() {
        let cfg = test_billing_config();
        // Empty -> refused.
        assert!(export_ledes_1998b(&[], &cfg).is_err());
        // A Proposed (un-attested) entry -> refused (cannot bill un-attested time).
        let mut proposed = billable_entry(360, "x", "2026-06-19");
        proposed.status = EntryStatus::Proposed;
        let err = export_ledes_1998b(&[proposed], &cfg).unwrap_err();
        assert!(matches!(err, runtime::CoreError::Backend(_)));
        // A Dismissed entry -> refused.
        let mut dismissed = billable_entry(360, "x", "2026-06-19");
        dismissed.status = EntryStatus::Dismissed;
        assert!(export_ledes_1998b(&[dismissed], &cfg).is_err());
    }

    #[test]
    fn export_ledes_1998b_sanitizes_pipe_injection_in_narrative() {
        // A narrative with pipes/newlines/[] must NOT add fields or break rows for
        // either a newline-record or a []-splitting parser.
        let entries = vec![billable_entry(
            360,
            "Call re A|B\nwith [notes]",
            "2026-06-19",
        )];
        let cfg = test_billing_config();
        let s = String::from_utf8(export_ledes_1998b(&entries, &cfg).unwrap()).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "header block (2) + 1 row — newline did not split"
        );
        let body = lines[2].strip_suffix("[]").unwrap();
        assert_eq!(
            body.split('|').count(),
            24,
            "pipe in narrative did not add a field"
        );
        assert!(body.contains("Call re A B with (notes)"), "got: {body}");
        // Exactly one [] in the whole row (the record terminator) — the narrative's
        // [] was neutralized, so a []-splitting parser sees one record.
        assert_eq!(
            lines[2].matches("[]").count(),
            1,
            "only the terminator is []"
        );
    }

    #[test]
    fn export_pdf_is_wellformed_and_roundtrips_via_lopdf() {
        let entries = vec![
            billable_entry(360, "Email to counsel re discovery", "2026-06-19"), // 0.1h -> $35
            billable_entry(15 * 60, "Document review", "2026-06-20"),           // 0.2h -> $70
        ];
        let cfg = test_billing_config();
        let a = export_pdf(&entries, &cfg).expect("pdf");
        let b = export_pdf(&entries, &cfg).expect("pdf");
        assert_eq!(a, b, "PDF export is deterministic");
        assert!(a.starts_with(b"%PDF-1.4"), "PDF header present");
        // Parse it back with a REAL PDF parser — proves the xref byte offsets are
        // correct (a malformed PDF would fail to load) and the text round-trips.
        let doc = lopdf::Document::load_mem(&a).expect("lopdf parses the generated PDF");
        let page_nums: Vec<u32> = doc.get_pages().keys().copied().collect();
        assert_eq!(page_nums.len(), 1, "two entries fit on one page");
        let text = doc.extract_text(&page_nums).expect("extract text");
        assert!(text.contains("INVOICE"), "got: {text}");
        assert!(text.contains("INV-001"), "invoice number, got: {text}");
        assert!(text.contains("discovery"), "narrative, got: {text}");
        assert!(text.contains("105.00"), "total 35.00+70.00, got: {text}");
    }

    #[test]
    fn export_pdf_paginates_many_entries() {
        let entries: Vec<DraftEntry> = (0..120)
            .map(|i| billable_entry(360, &format!("entry {i}"), "2026-06-19"))
            .collect();
        let bytes = export_pdf(&entries, &test_billing_config()).expect("pdf");
        let doc = lopdf::Document::load_mem(&bytes).expect("lopdf parses multi-page PDF");
        assert!(
            doc.get_pages().len() >= 2,
            "120 rows + header span multiple pages"
        );
    }

    #[test]
    fn export_pdf_escapes_parens_and_pipes_without_breaking() {
        let entries = vec![billable_entry(360, "Call re (urgent) A|B", "2026-06-19")];
        let bytes = export_pdf(&entries, &test_billing_config()).expect("pdf");
        let doc = lopdf::Document::load_mem(&bytes).expect("lopdf parses despite parens");
        let pn: Vec<u32> = doc.get_pages().keys().copied().collect();
        let text = doc.extract_text(&pn).expect("text");
        assert!(
            text.contains("urgent"),
            "escaped parens still render, got: {text}"
        );
    }

    #[test]
    fn export_pdf_refuses_unattested_and_empty() {
        let cfg = test_billing_config();
        assert!(export_pdf(&[], &cfg).is_err(), "empty invoice refused");
        let mut p = billable_entry(360, "x", "2026-06-19");
        p.status = EntryStatus::Proposed;
        assert!(export_pdf(&[p], &cfg).is_err(), "un-attested time refused");
    }

    /// Parse XML bytes with quick-xml, asserting WELL-FORMEDNESS (no parse error to
    /// EOF) and returning the concatenated text content for value assertions.
    fn xml_text_or_panic(bytes: &[u8]) -> String {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;
        let mut reader = Reader::from_reader(bytes);
        let mut buf = Vec::new();
        let mut text = String::new();
        loop {
            match reader
                .read_event_into(&mut buf)
                .expect("XML must be well-formed")
            {
                Event::Text(e) => text.push_str(&e.unescape().expect("valid escapes")),
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        text
    }

    #[test]
    fn export_ledes_xml_is_wellformed_deterministic_and_matches_1998b_total() {
        let entries = vec![
            billable_entry(360, "Email to counsel re discovery", "2026-06-19"), // 0.1h -> $35
            billable_entry(15 * 60, "Document review", "2026-06-20"),           // 0.2h -> $70
        ];
        let cfg = test_billing_config();
        let a = export_ledes_xml(&entries, &cfg).expect("xml");
        let b = export_ledes_xml(&entries, &cfg).expect("xml");
        assert_eq!(a, b, "LEDES XML export is deterministic");
        let text = xml_text_or_panic(&a); // also asserts well-formedness
        assert!(text.contains("INV-001"), "invoice number, got: {text}");
        assert!(
            text.contains("Email to counsel re discovery"),
            "narrative, got: {text}"
        );
        assert!(text.contains("105.00"), "invoice_total 35+70, got: {text}");
        // Totals cross-check: XML invoice_total == LEDES 1998B INVOICE_TOTAL.
        let flat = String::from_utf8(export_ledes_1998b(&entries, &cfg).unwrap()).unwrap();
        let r1: Vec<&str> = flat
            .lines()
            .nth(2)
            .unwrap()
            .strip_suffix("[]")
            .unwrap()
            .split('|')
            .collect();
        assert_eq!(r1[4], "105.00", "1998B INVOICE_TOTAL agrees with XML");
    }

    #[test]
    fn export_ledes_xml_escapes_markup_and_drops_control_chars() {
        // A narrative with XML metacharacters + a control char must stay well-formed.
        let entries = vec![billable_entry(
            360,
            "A < B & \"C\" > D\u{0}\t end",
            "2026-06-19",
        )];
        let bytes = export_ledes_xml(&entries, &test_billing_config()).expect("xml");
        let raw = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            raw.contains("&lt;") && raw.contains("&amp;") && raw.contains("&quot;"),
            "escaped: {raw}"
        );
        assert!(!raw.contains('\u{0}'), "NUL dropped");
        // Round-trips through a real parser back to the (escape-decoded) text.
        let text = xml_text_or_panic(&bytes);
        assert!(
            text.contains("A < B & \"C\" > D"),
            "unescaped round-trip, got: {text}"
        );
    }

    #[test]
    fn export_ledes_xml_refuses_unattested_and_empty() {
        let cfg = test_billing_config();
        assert!(export_ledes_xml(&[], &cfg).is_err(), "empty refused");
        let mut p = billable_entry(360, "x", "2026-06-19");
        p.status = EntryStatus::Proposed;
        assert!(export_ledes_xml(&[p], &cfg).is_err(), "un-attested refused");
    }
}
