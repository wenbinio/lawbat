// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Inbox — email-triage module (the productivity dashboard's BRAIN).
//!
//! A NATIVE first-party module (like redaction = module #1) that turns a matter's
//! emails into a curated **worklist**: each message → `{ gist, action, due-by,
//! internal/external }`. It dogfoods the trusted-core ABI exactly as redaction
//! does — it touches matter data ONLY through the brokered, granted, scoped,
//! logged `Core` methods, holds no filesystem, no socket, and **no egress
//! capability** — the engine cannot send anything anywhere.
//!
//! ## Email IS the `document` data class (SETTLED)
//!
//! Emails are read through the EXISTING mediated `matter.read` path as
//! [`DataClass::Document`] ([`EMAIL_CLASS`]) — there is NO `mail.read` capability,
//! NO mail subsystem, and NO new `Core` method. The body text returned by
//! `matter_read_text` is the email; when richer per-message headers are needed
//! they will arrive via the EXISTING `metadata` data class (an existing-taxonomy
//! capability), NOT a new one. See the `TODO(core)` on [`Inbox::build_worklist`].
//!
//! ## Honest framing (read before trusting a worklist — load-bearing)
//!
//! - **ALL DETERMINISTIC, model-free** (CLAUDE.md non-negotiable). Triage, date
//!   parsing, and classification are rule-based — NO model / LLM / ML / NLP,
//!   anywhere. A statistical summarizer/classifier would be a LATER
//!   `compute.model` tier (local, scoped, logged), NOT this increment.
//! - **Rules PROPOSE; the human curates.** Every worklist item is a *suggestion*
//!   the lawyer accepts, edits, or discards. The module NEVER auto-replies,
//!   auto-files, or commits a deadline to a calendar. A misparsed deadline or a
//!   wrong auto-action on a legal email is a real malpractice risk, so the
//!   worklist is advisory by construction (mirrors redaction's "reasonable-
//!   efforts, never safe-to-send").
//! - **Never auto-trust a deadline.** A [`WorklistItem`]'s `due_at` carries a
//!   [`dateparse::DuePrecision`] so the dashboard shows an explicit date very
//!   differently from a vague "ASAP" — the lawyer confirms before anything
//!   relies on it. The `provenance.rule` records WHICH rule fired, so the human
//!   can see WHY an action/priority was proposed.
//!
//! ## Confidentiality split: cleartext worklist vs. audit (load-bearing)
//!
//! Mirrors redaction. [`Inbox::build_worklist`] returns a [`Worklist`] whose
//! items carry CLEARTEXT (the gist, the matched sender) for the IN-PROCESS review
//! workflow — that is sensitive matter data; it stays local behind the engine's
//! empty egress grant and is never sent anywhere. The **audit note**, by
//! contrast, records ONLY counts + a per-classification/action breakdown, NEVER
//! the cleartext gist/sender, so the tamper-evident audit chain does not become
//! a cleartext store of the very emails being triaged.

pub mod classify;
pub mod dateparse;
pub mod triage;
/// Maps the worklist into the shared inert [`view`] types (the external crate);
/// named `viewmodel` to avoid shadowing the `view` crate name.
pub mod viewmodel;

use runtime::{
    Audit, Capability, CapabilityBroker, CoreResult, DataClass, Egress, MatterContext, MatterStore,
    Storage, StorageScope,
};

pub use classify::{Category, Classification, FirmDomains, ProtectedHandling};
pub use dateparse::{DateConvention, DueDate, DuePrecision};
pub use triage::{Action, DeadlineProximity, Priority, Rule};
pub use viewmodel::to_view;

/// The data class the inbox engine reads to build a worklist.
///
/// SETTLED: email IS the `document` data class. Emails are read via the EXISTING
/// mediated `matter.read` path as [`DataClass::Document`] — no dedicated mail
/// subsystem, no `mail.read` capability, no new `Core` method. Richer per-message
/// headers, when needed, arrive via the existing `metadata` class (see the
/// `TODO(core)` on [`Inbox::build_worklist`]).
const EMAIL_CLASS: DataClass = DataClass::Document;

/// The placeholder [`dateparse::Anchor`] used while the core supplies NO real
/// per-message received time (the `metadata` seam on [`Inbox::build_worklist`] is
/// not wired yet). It is a DETERMINISTIC sentinel (epoch 0), never the wall clock,
/// so triage stays reproducible. Relative-date resolution and priority nearness
/// both special-case it (see [`triage::suggest_priority`]) — when the metadata
/// seam lands, the engine passes the real received time instead and the sentinel
/// path is no longer taken.
///
/// CAVEAT — PRIORITY BADGE + RELATIVE DEADLINES ARE SUPPRESSED UNDER THIS SENTINEL
/// (honest framing, load-bearing; verdict DANGER fix #3). Under the epoch-0 anchor,
/// "nearness" of a deadline would be measured against epoch 0, so EVERY resolved
/// deadline reads as "near" and the algorithmic priority badge degenerates to
/// "High-on-everything". Rather than ship a badge nobody should act on, the engine:
/// - SUPPRESSES the priority badge ([`triage::suggest_priority`] returns `None`),
///   and instead surfaces FACTUAL [`triage::DeadlineProximity`] (which under this
///   sentinel honestly reports `NeedsAnchor` for any resolved deadline — it cannot
///   compute "due in N days" without a real received time); and
/// - does NOT resolve RELATIVE deadlines ("by Friday", computed against epoch-0 =
///   meaningless) into surfaced dates — they are flagged `NeedsAnchor` (needs the
///   received time), never shown as a resolved deadline.
///
/// When the metadata seam lands and the engine passes the real received time, the
/// badge + true proximity facts come back. The lawyer confirms every deadline
/// regardless (the worklist is advisory by construction). See the worklist-level
/// [`Caveat`]s, which make the deeper honest limits (legally-arising deadlines,
/// deadlines in attachments, limitation periods are NOT caught) explicit as DATA.
pub const NO_ANCHOR: dateparse::Anchor = 0;

/// A single email to triage — a minimal, model-free shape constructed by the
/// engine from the text it read THROUGH the core.
///
/// Carries CLEARTEXT (`sender`/`subject`/`body`): sensitive matter data for the
/// in-process triage only — never egressed, never written to the audit chain
/// (see the crate-level confidentiality split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The stable matter-doc id this email was read under (used for provenance +
    /// for confirming tasks against it in `storage:own`).
    pub id: u64,
    /// The sender address (cleartext). Classified internal/external by
    /// [`classify::classify_sender`].
    pub sender: String,
    /// The subject line (cleartext).
    pub subject: String,
    /// The message body (cleartext) — already read THROUGH the core.
    pub body: String,
    /// The received time, used as the deterministic [`dateparse::Anchor`] for
    /// resolving relative due dates (never an ambient `now()`).
    pub received_at: dateparse::Anchor,
}

impl Message {
    /// Construct a message (used by the engine + tests).
    pub fn new(
        id: u64,
        sender: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
        received_at: dateparse::Anchor,
    ) -> Self {
        Self {
            id,
            sender: sender.into(),
            subject: subject.into(),
            body: body.into(),
            received_at,
        }
    }

    /// Construct a [`Message`] from the text the core returned for a doc.
    ///
    /// The core today returns the email BODY text. Many exported emails carry a
    /// simple RFC822-style header block at the top (`From:` / `Subject:` / `Date:`
    /// lines, then a blank line, then the body). If we see such a block we parse
    /// `sender`/`subject` out of it and use the remainder as the body; OTHERWISE
    /// we treat the whole text as body with empty headers (no fabrication — an
    /// absent header stays empty, never guessed).
    ///
    /// DETERMINISTIC: a fixed line-prefix parse, no model. `received_at` is the
    /// caller-supplied anchor (the doc's received time), never the wall clock — a
    /// `Date:` header is NOT trusted as the anchor here (parsing arbitrary mail
    /// date formats is out of scope for this increment and would risk a wrong
    /// anchor; the relative-date anchor must stay caller-controlled/deterministic).
    pub fn from_doc_text(id: u64, text: &str, received_at: dateparse::Anchor) -> Self {
        let (sender, subject, body) = parse_rfc822ish(text);
        Self {
            id,
            sender,
            subject,
            body,
            received_at,
        }
    }
}

/// Parse a leading RFC822-style header block out of `text`, returning
/// `(sender, subject, body)`. If no recognizable header block is present, returns
/// empty sender/subject and the whole `text` as the body (never fabricates).
///
/// A header block is recognized only when the FIRST line looks like `Key: value`
/// AND at least one of `From:`/`Subject:`/`Date:`/`To:`/`Cc:` appears before the
/// first blank line — so an ordinary body that happens to contain a colon is not
/// misread as headers. The body is everything after the first blank line (or the
/// whole text if there is no blank line but a header block was found).
fn parse_rfc822ish(text: &str) -> (String, String, String) {
    // A header line: starts with a known key (case-insensitively) followed by ':'.
    fn header_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let line = line.trim_end_matches('\r');
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(key) {
            Some(v.trim())
        } else {
            None
        }
    }
    fn is_known_header(line: &str) -> bool {
        let line = line.trim_end_matches('\r');
        match line.split_once(':') {
            Some((k, _)) => matches!(
                k.trim().to_ascii_lowercase().as_str(),
                "from" | "to" | "cc" | "bcc" | "subject" | "date" | "reply-to" | "sender"
            ),
            None => false,
        }
    }

    let mut lines = text.lines().peekable();
    // Header block must START with a known header line.
    let starts_with_header = lines.peek().map(|l| is_known_header(l)).unwrap_or(false);
    if !starts_with_header {
        return (String::new(), String::new(), text.to_string());
    }

    // SPLIT the header block from the body on the FIRST blank line, WITHOUT
    // re-deriving byte offsets from `lines()`.
    //
    // SECURITY (Medium): the previous version summed `line.len() + 1` over
    // `text.lines()` to find where the body starts, but `lines()` strips the FULL
    // `\r\n` on CRLF input while the code only added back ONE byte per line. On real
    // (CRLF) `.eml` / Outlook mail this undercounts by 1 byte per header line, so a
    // leading `\r\n` (and progressively more) leaked into the body — degrading the
    // gist/date scan. Splitting on the literal blank-line separator is offset-exact
    // for both CRLF and LF and never miscounts the stripped `\r`.
    let (header_block, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        // Fall back to an LF-only blank line; if neither separator exists the whole
        // text is the header block (a header-only message) and the body is empty.
        None => match text.split_once("\n\n") {
            Some((h, b)) => (h, b),
            None => (text, ""),
        },
    };

    let mut sender = String::new();
    let mut subject = String::new();
    let mut header_line_count = 0usize;

    for line in header_block.lines() {
        // A blank line cannot appear inside `header_block` (we split on the first
        // blank line), so every line here is part of the header block.
        if is_known_header(line) {
            header_line_count += 1;
            if sender.is_empty() {
                if let Some(v) = header_value(line, "from").or_else(|| header_value(line, "sender"))
                {
                    sender = v.to_string();
                }
            }
            if subject.is_empty() {
                if let Some(v) = header_value(line, "subject") {
                    subject = v.to_string();
                }
            }
        } else {
            // A non-header line before the first blank line: not a clean header
            // block. Bail out and treat the whole text as body (no fabrication).
            return (String::new(), String::new(), text.to_string());
        }
    }

    if header_line_count == 0 {
        return (String::new(), String::new(), text.to_string());
    }

    (sender, subject, body.to_string())
}

/// An HONEST-LIMITS banner the worklist carries as DATA (not just a doc comment),
/// so the presentation MUST confront the user with what triage does NOT catch
/// (verdict DANGER fix #1 / MISSING #9). Encoded as an enum (stable, cleartext-free)
/// the host renders verbatim — never a fabricated reassurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caveat {
    /// THE load-bearing one (DANGER fix #1): "no date detected" is NOT "no
    /// deadline". Legally-arising deadlines (limitation periods, deadlines that
    /// arise from the law rather than being written as a date), deadlines stated in
    /// ATTACHMENTS (not the body text triage reads), and relative deadlines that
    /// could not be resolved are NOT caught. The lawyer must never read a blank
    /// "due" column as "nothing is due".
    DeadlinesNotAllCaught,
    /// The received-time anchor is not wired ([`NO_ANCHOR`]), so the priority badge
    /// is SUPPRESSED and deadline PROXIMITY ("due in N days") cannot be computed —
    /// resolved deadlines show as needs-confirm until the received time lands.
    PriorityAndProximitySuppressed,
    /// Triage is rule-based + advisory: every action/deadline is a SUGGESTION the
    /// lawyer confirms or edits; the engine never auto-files, auto-replies, or
    /// commits a deadline to a calendar.
    AdvisoryNotAuthoritative,
}

impl Caveat {
    /// The honest, self-contained banner text (plain, inert, no markup). The host
    /// renders this verbatim into a sanitized slot.
    pub fn message(self) -> &'static str {
        match self {
            Caveat::DeadlinesNotAllCaught => {
                "No date detected — deadline unclear. Deadlines that arise in law \
                 (e.g. limitation periods), deadlines stated only in attachments, and unresolved \
                 relative dates are NOT caught here. Check every matter independently."
            }
            Caveat::PriorityAndProximitySuppressed => {
                "Message received-times are not wired yet, so the priority badge and \
                 \"due in N days\" proximity are suppressed — a detected deadline shows as \
                 needs-confirm until the received time is available."
            }
            Caveat::AdvisoryNotAuthoritative => {
                "This worklist is advisory and rule-based. Every suggested action and deadline is \
                 a proposal for you to confirm or edit — nothing is auto-filed, auto-sent, or \
                 added to a calendar."
            }
        }
    }

    /// A stable, cleartext-free label (for audit/tests). A caveat NAME, never content.
    pub fn label(self) -> &'static str {
        match self {
            Caveat::DeadlinesNotAllCaught => "deadlines-not-all-caught",
            Caveat::PriorityAndProximitySuppressed => "priority-proximity-suppressed",
            Caveat::AdvisoryNotAuthoritative => "advisory-not-authoritative",
        }
    }
}

/// A confidentiality / leak-vector flag derived from the extractor's warnings
/// (verdict KEEP #8). Carried on a [`WorklistItem`] so the dashboard can show
/// "⚠ Bcc / hidden attachment" — a genuine lawyer-pleaser.
///
/// HONEST FRAMING: these flag STRUCTURAL leak vectors the extractor detected (a Bcc
/// header, a nested forwarded message). They are a heads-up, NOT a safety
/// determination. Absence of a flag is not a claim the message is leak-free.
///
/// TODO(core): the extractor (`extract` crate) already emits these as
/// `ExtractResult::warnings`, but the inbox does not yet RECEIVE them — email is
/// read as `DataClass::Document` body text only, and the warnings travel a separate
/// path. When the `matter.read:metadata` seam (see the `TODO(core)` on
/// [`Inbox::build_worklist`]) lands, the engine will populate this from the
/// extractor's warnings for the doc. Until then it stays
/// [`ConfidentialityFlag::default`] (`None`) — the FIELD + the propagation contract
/// exist now so the dashboard shape is stable; nothing is fabricated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfidentialityFlag {
    /// The message carries Bcc recipients (blind-carbon addressees a To/Cc view does
    /// not show) — a disclosure leak vector.
    pub bcc_present: bool,
    /// The message has a nested forwarded/attached message (`message/rfc822`) whose
    /// own headers/recipients may leak content the sender did not intend to show.
    pub nested_message: bool,
}

impl ConfidentialityFlag {
    /// Whether ANY confidentiality leak vector is flagged.
    pub fn is_flagged(self) -> bool {
        self.bcc_present || self.nested_message
    }

    /// Build a flag from an extractor warnings list (the `extract` crate's
    /// `ExtractResult::warnings`). DETERMINISTIC substring match on the stable
    /// warning shapes the extractor emits ("bcc recipients present", "nested …
    /// message"). Cleartext-free: it reads only the warning STRINGS (which are
    /// counts/labels, never matched addresses), never matter content.
    ///
    /// TODO(core): not yet CALLED from [`Inbox::build_worklist`] (the warnings seam
    /// is unwired — see [`ConfidentialityFlag`]); provided so the wiring is a
    /// one-liner when the metadata/warnings path lands, and unit-tested now.
    pub fn from_warnings<S: AsRef<str>>(warnings: &[S]) -> Self {
        let mut flag = Self::default();
        for w in warnings {
            let lw = w.as_ref().to_ascii_lowercase();
            if lw.contains("bcc recipients present") || lw.starts_with("bcc ") {
                flag.bcc_present = true;
            }
            if lw.contains("nested") && lw.contains("message") {
                flag.nested_message = true;
            }
        }
        flag
    }
}

/// Where a worklist item came from — the matter-doc id it was derived from plus
/// the rule that fired, for audit/traceability and for keying any human
/// confirmation/override in storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    /// The matter-doc id the item was derived from.
    pub doc_id: u64,
    /// The data class it was read under.
    pub class: DataClass,
    /// Which deterministic triage rule produced the action/priority (so the human
    /// can see WHY). A stable, cleartext-free LABEL via [`Rule::label`].
    pub rule: Rule,
}

/// One curated worklist row: the rule-derived triage of a single message, for
/// the human to confirm/edit. CARRIES CLEARTEXT (`excerpt`, `subject_label`):
/// in-process review data only — never egressed, never audited (see the crate
/// confidentiality split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorklistItem {
    /// A short, rule-derived one-line EXCERPT — the first NEW body line (verdict
    /// #4), cleartext, review-only. NOT the "RE: RE: FW:" subject.
    pub excerpt: String,
    /// The SECONDARY subject label (cleartext, review-only) — shown alongside the
    /// excerpt, never as the primary gist (verdict #4).
    pub subject_label: String,
    /// The suggested next action — an EDITABLE hint the human confirms/overrides
    /// (verdict #7); `Unclassified` is the honest default when nothing clearly fires.
    pub action: Action,
    /// The coarse priority bucket for ordering — `None` when SUPPRESSED because the
    /// received-time anchor is not wired (verdict DANGER fix #3; see
    /// [`triage::suggest_priority`]). When `None`, order by `proximity` instead.
    pub priority: Option<Priority>,
    /// The FACTUAL deadline proximity ("overdue by N days" / "due in N days" / "due
    /// today" / needs-confirm / ambiguous), surfaced in place of the badge under
    /// `NO_ANCHOR` and alongside it otherwise (verdict DANGER fix #3).
    pub proximity: DeadlineProximity,
    /// The proposed due date + how precisely it was pinned. `due_at` may be
    /// `None`; a deadline is NEVER auto-trusted (see the honest framing). For an
    /// AMBIGUOUS date this is the convention's reading; see `due_ambiguous_alt`.
    pub due_at: Option<dateparse::Anchor>,
    /// How precisely the due date was pinned (the honesty knob — see
    /// [`dateparse::DuePrecision`], incl. the AMBIGUOUS state).
    pub due_precision: DuePrecision,
    /// For an AMBIGUOUS numeric date ONLY: the OTHER candidate day, so the
    /// presentation renders the date as a QUESTION ("3 Apr or 4 Mar?"). `None`
    /// otherwise (verdict DANGER fix #2).
    pub due_ambiguous_alt: Option<dateparse::Anchor>,
    /// Whether MORE THAN ONE distinct date-bearing span was detected in the message
    /// (M1 silent-miss fix). The `due_at`/`due_precision` above carry only the ONE
    /// shown date (chosen deterministically by precedence); when this is `true` the
    /// text contains at least one OTHER date the shown one does NOT represent, so the
    /// presentation surfaces a visible "⚠ multiple dates detected — review" note. It
    /// is NOT a heuristic guess at the "operative" date (which could be wrong) — it
    /// surfaces the ambiguity so a confident single shown date never reads as the only
    /// date present. Cleartext-free (a bool), so it is safe to count in the audit.
    pub multiple_dates_detected: bool,
    /// Internal (a colleague) vs. external (counterparty/client/court) — the TRUSTED
    /// classifier (verdict KEEP #6), a triage hint, NOT a security/privilege boundary.
    pub classification: Classification,
    /// The coarse message category — a triage hint, NOT an authoritative/privileged
    /// label. NOTE: Client/OpposingCounsel/InternalAdmin are DEMOTED to internal
    /// hints ([`Category::is_surfaced`] == false; verdict #5).
    pub category: Category,
    /// Protected-handling posture from explicit privilege markers (without-prejudice
    /// / privileged-and-confidential) — high-value, low-risk (verdict MISSING #9).
    pub protected_handling: ProtectedHandling,
    /// Confidentiality / leak-vector flag (Bcc / nested message) propagated from the
    /// extractor's warnings (verdict KEEP #8). Defaults to unflagged until the
    /// warnings seam is wired (see [`ConfidentialityFlag`]).
    pub confidentiality: ConfidentialityFlag,
    /// Where this row was derived from (for traceability + human confirmation).
    pub provenance: Provenance,
}

/// The outcome of triaging a matter's emails: the curated rows PLUS the honest-
/// limits [`Caveat`]s, IN-PROCESS for the human review/curation workflow. The items
/// carry cleartext (`excerpt`, subject) but the engine holds no egress, so nothing
/// leaves the box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worklist {
    items: Vec<WorklistItem>,
    caveats: Vec<Caveat>,
}

impl Default for Worklist {
    /// A worklist always carries its honest-limits caveats — even an EMPTY one
    /// (verdict DANGER fix #1): "no items" must never read as "nothing is due".
    fn default() -> Self {
        Self {
            items: Vec::new(),
            caveats: default_caveats(),
        }
    }
}

impl Worklist {
    /// The curated rows (borrowed; the worklist owns the cleartext).
    pub fn items(&self) -> &[WorklistItem] {
        &self.items
    }

    /// The honest-limits [`Caveat`]s that ALWAYS accompany the worklist (verdict
    /// DANGER fix #1) — the presentation MUST surface these.
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Total messages triaged into the worklist.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the worklist has no ITEMS. (It still carries caveats — see
    /// [`caveats`](Worklist::caveats).)
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Map this worklist into the shared, inert [`view::Section`]s the trusted host
    /// renders (the "cleaner structure" presentation seam). Reflects the Phase-1
    /// presentation — excerpt gist, factual proximity not a priority badge, demoted
    /// categories, confidentiality + protected-handling flags, and the
    /// "no date ≠ no deadline" caveat. PURE: see [`viewmodel::to_view`].
    pub fn to_view(&self) -> Vec<view::Section> {
        viewmodel::to_view(self)
    }
}

/// Convenience: a borrowed [`Worklist`] converts into the inert view-model sections
/// the host renders (`let sections: Vec<view::Section> = (&worklist).into();`).
impl From<&Worklist> for Vec<view::Section> {
    fn from(worklist: &Worklist) -> Self {
        viewmodel::to_view(worklist)
    }
}

/// The honest-limits caveats every worklist carries. ALWAYS includes the
/// deadlines-not-all-caught + advisory banners; adds the suppression banner because
/// the received-time anchor is not wired yet ([`NO_ANCHOR`]). Encoded as DATA so the
/// presentation cannot omit them (verdict DANGER fixes #1 + #3).
fn default_caveats() -> Vec<Caveat> {
    vec![
        Caveat::DeadlinesNotAllCaught,
        Caveat::PriorityAndProximitySuppressed,
        Caveat::AdvisoryNotAuthoritative,
    ]
}

/// The email-triage engine — the dashboard's brain. Holds only configuration
/// (the firm domains used to classify senders, the numeric-date convention, and the
/// data classes it reads); it reaches matter data exclusively through a `&mut Core`,
/// never directly.
pub struct Inbox {
    /// The firm's email domains, for internal/external classification. Supplied by
    /// the trusted shell from firm config (never by a message).
    firm: FirmDomains,
    /// The EXPLICIT numeric-date ordering convention (verdict DANGER fix #2). Set by
    /// the firm; defaults to UK/Commonwealth day-first. Never hard-coded silently —
    /// a US/mixed-mail firm flips it so a deadline is not parsed a month off.
    date_convention: DateConvention,
    /// The data classes this engine reads (must align with the granted
    /// `matter.read:<class>` capabilities; a non-granted class is refused by the
    /// core). `[EMAIL_CLASS]` today — email IS the document class.
    classes: Vec<DataClass>,
}

impl Inbox {
    /// Build an inbox engine for a set of firm domains, reading the email class,
    /// with the DEFAULT (day-first) numeric-date convention. Use
    /// [`with_date_convention`](Inbox::with_date_convention) to set it explicitly.
    pub fn new(firm: FirmDomains) -> Self {
        Self {
            firm,
            date_convention: DateConvention::default(),
            classes: vec![EMAIL_CLASS],
        }
    }

    /// Set the EXPLICIT numeric-date convention (verdict DANGER fix #2). Builder-style
    /// so the firm's setting is wired in at construction:
    /// `Inbox::new(firm).with_date_convention(DateConvention::MonthFirst)`.
    pub fn with_date_convention(mut self, convention: DateConvention) -> Self {
        self.date_convention = convention;
        self
    }

    /// The configured numeric-date convention.
    pub fn date_convention(&self) -> DateConvention {
        self.date_convention
    }

    /// The firm domains this engine classifies senders against.
    pub fn firm(&self) -> &FirmDomains {
        &self.firm
    }

    /// The capabilities this module DECLARES (spec §5.1 / §5.2) — the manifest
    /// grant request. The core grants/denies these; every runtime call is then
    /// checked against the grant (default-deny).
    ///
    /// - `matter.read:document` — read the matter's emails (email IS the document
    ///   data class). The EXISTING, enforced + audited read path; no new
    ///   capability. When richer per-message metadata wiring lands it ADDS
    ///   `matter.read:metadata` (an existing-taxonomy capability — see the
    ///   `TODO(core)` on [`build_worklist`](Inbox::build_worklist)), NOT a new one.
    /// - `storage:own` — persist the human's CONFIRMED tasks / overrides in the
    ///   module's own namespace (a confirmed deadline, a dismissed row), so
    ///   curation survives across runs.
    /// - `audit.note` — append per-run COUNTS / breakdown to the audit chain
    ///   (ungated; never the cleartext gist/sender — see the confidentiality split).
    ///
    /// NOTE — **NO egress** (`egress: []`): the engine holds no egress capability,
    /// so the worklist (cleartext) can never leave the box. Mirrors redaction.
    pub fn required_capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::new();
        // Declare the EXISTING, enforceable read capability the engine uses (one
        // per configured class). matter.read is enforced + audited by the core, so
        // the grant set stays HONEST (every declared cap maps to a real mediated
        // path). Email IS the document class — no `mail.read` stand-in.
        for &class in &self.classes {
            caps.push(Capability::MatterRead(class));
        }
        // Persist the human's confirmed tasks/overrides in the module's namespace.
        caps.push(Capability::Storage(StorageScope::Own));
        // Append per-run counts/breakdown (ungated; cleartext-free).
        caps.push(Capability::AuditNote);
        // DELIBERATELY NO Capability::Egress(..) — the engine holds no egress grant.
        caps
    }

    /// Build the worklist for the matter the engine is granted to read: for each
    /// email, LIST via the mediated read path, READ its content THROUGH the core,
    /// triage it (gist/action/priority/due/classification) with the PURE
    /// submodules, AUDIT-NOTE the counts/breakdown, and collect a [`WorklistItem`].
    ///
    /// Mirrors [`redaction::RedactionEngine::redact_matter`]'s generic bounds +
    /// brokered shape: the engine never holds the store/broker/audit — only a
    /// `&mut Core` that mediates + logs every touch.
    ///
    /// # Confidentiality split (load-bearing)
    ///
    /// The returned [`Worklist`] carries cleartext (`gist`, sender) for the
    /// in-process review workflow — the engine holds no egress, so it never leaves
    /// the box. The `audit_note` records ONLY counts + a per-classification/action
    /// breakdown, NEVER the cleartext gist/sender, so the audit chain does not
    /// become a cleartext store of the triaged emails.
    ///
    /// # Fail-closed ordering
    ///
    /// As in redaction: the per-run audit note is recorded as module context
    /// (ungated `audit.note`) so a failed note ABORTS the run rather than
    /// returning an unlogged worklist. Any refusal (un-granted class / read)
    /// propagates as a `CoreResult` error — fail-closed, consistent with the core.
    ///
    // TODO(core): richer email metadata (From/To/Cc/Bcc/Subject/Date) should
    // arrive via the EXISTING 'metadata' data class through a future mediated
    // matter.read:metadata read seam on Core — an existing-taxonomy capability,
    // NOT a new one. Email stays DataClass::Document. Until that seam exists this
    // engine constructs each Message from the document text it reads: if the text
    // carries a simple RFC822-style header block it parses From/Subject from it
    // (see Message::from_doc_text), otherwise it is body-only with empty headers.
    pub fn build_worklist<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
    ) -> CoreResult<Worklist>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let mut worklist = Worklist::default();

        for &class in &self.classes {
            // Entitlement: the core refuses a non-granted class here (default-deny),
            // via the existing matter.read path. Email IS the document class.
            let docs = core.matter_list_docs(class)?;
            for doc in docs {
                // Read the email THROUGH the core (mediated, entitlement-filtered,
                // audited). The core returns the body text today; construct a
                // Message from it, parsing a leading RFC822-style header block if
                // present (see the TODO(core) above for the metadata seam).
                let text = core.matter_read_text(doc.id, class)?;
                // No real per-message received time from the core yet (the metadata
                // seam is not wired) -> the deterministic NO_ANCHOR sentinel.
                let message = Message::from_doc_text(doc.id, &text, NO_ANCHOR);

                // Triage with the PURE submodules (no Core handle).
                let item = self.triage_message(&message, doc.id, class);
                worklist.items.push(item);
            }
        }

        // FAIL-CLOSED (mirrors redaction): record the per-run COUNT + breakdown as
        // module context (ungated audit.note) — never a cleartext excerpt/sender, so
        // the audit chain never stores the triaged emails. A failed note ABORTS
        // the run (the `?`) rather than returning an unlogged worklist. The
        // protected-handling breakdown is COUNTS + fixed LABELS only (verdict #9) —
        // never the matched marker text.
        core.audit_note(&format!(
            "inbox: built worklist — {} message(s) triaged [{}] [{}] [{}] [multi-date={}]",
            worklist.len(),
            classification_breakdown(&worklist),
            action_breakdown(&worklist),
            protected_handling_breakdown(&worklist),
            // M1: a COUNT of items carrying more than one detected date — a number,
            // never a matched date value (cleartext-free, like the other breakdowns).
            multiple_dates_count(&worklist),
        ))?;

        Ok(worklist)
    }

    /// Triage one already-read message into a [`WorklistItem`] using the PURE
    /// submodules. PURE (no Core).
    fn triage_message(&self, message: &Message, doc_id: u64, class: DataClass) -> WorklistItem {
        let classification = classify::classify_sender(&message.sender, &self.firm);
        let category = classify::classify_category(&message.subject, &message.body, classification);
        let protected_handling =
            classify::classify_protected_handling(&message.subject, &message.body);
        // EXPLICIT date convention (verdict DANGER fix #2) — never hard-coded.
        let due = dateparse::extract_due_date(
            &triage_haystack(message),
            message.received_at,
            self.date_convention,
        );
        let rule = triage::suggest_rule(message, &due);
        let action = triage::suggest_action(message, &due);
        // Priority is SUPPRESSED (None) under NO_ANCHOR; factual proximity is the
        // honest surface in its place (verdict DANGER fix #3).
        let priority = triage::suggest_priority(message, &due, action, classification, category);
        let proximity = triage::compute_proximity(&due, message.received_at);
        let excerpt = triage::excerpt(message);
        let subject_label = triage::subject_label(message);
        WorklistItem {
            excerpt,
            subject_label,
            action,
            priority,
            proximity,
            due_at: due.due_at,
            due_precision: due.precision,
            due_ambiguous_alt: due.ambiguous_alt,
            // M1: surface the "more than one date here" fact so the single shown date
            // never reads as the only date present.
            multiple_dates_detected: due.multiple_dates_detected(),
            classification,
            category,
            protected_handling,
            // TODO(core): populate from the extractor's warnings once the
            // matter.read:metadata / warnings seam is wired (see
            // [`ConfidentialityFlag`]). Until then it is the unflagged default — the
            // engine reads only the document BODY text today (no warnings path).
            confidentiality: ConfidentialityFlag::default(),
            provenance: Provenance {
                doc_id,
                class,
                rule,
            },
        }
    }
}

/// The text the date scanner reads: subject + QUOTE-STRIPPED body (a deadline may
/// live in either). Joined so a span never straddles the boundary spuriously.
///
/// SAFETY (M2 quote-stripping fix, load-bearing): the body is run through
/// [`triage::strip_quoted_history`] FIRST, so the date scan never sees quoted reply
/// history or a signature block. Without this, a weekday/date in a re-quoted "On
/// Monday, Jane wrote:" line or a `>`-quoted prior message could fabricate a phantom
/// deadline from an OLD message. The excerpt already strips this history; the date
/// haystack now matches it.
fn triage_haystack(message: &Message) -> String {
    let stripped_body = triage::strip_quoted_history(&message.body);
    let mut s = String::with_capacity(message.subject.len() + stripped_body.len() + 1);
    s.push_str(&message.subject);
    s.push('\n');
    s.push_str(&stripped_body);
    s
}

/// A deterministic, cleartext-FREE per-classification breakdown for the audit
/// note, e.g. `internal=1, external=2, unknown=0`. Counts + classification LABELS
/// only — never the gist/sender (those are review-only cleartext). Mirrors
/// redaction's `recognizer_breakdown`.
fn classification_breakdown(worklist: &Worklist) -> String {
    let mut internal = 0usize;
    let mut external = 0usize;
    let mut unknown = 0usize;
    for item in worklist.items() {
        match item.classification {
            Classification::Internal => internal += 1,
            Classification::External => external += 1,
            Classification::Unknown => unknown += 1,
        }
    }
    format!("internal={internal}, external={external}, unknown={unknown}")
}

/// A deterministic, cleartext-FREE per-action breakdown for the audit note, e.g.
/// `respond=1, review=0, file=0, pay=1, diarise=0, unclassified=1`. Counts + fixed
/// action LABELS only — never the excerpt/sender.
fn action_breakdown(worklist: &Worklist) -> String {
    let (mut respond, mut review, mut file, mut pay, mut diarise, mut unclassified) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for item in worklist.items() {
        match item.action {
            Action::Respond => respond += 1,
            Action::Review => review += 1,
            Action::File => file += 1,
            Action::Pay => pay += 1,
            Action::Diarise => diarise += 1,
            Action::Unclassified => unclassified += 1,
        }
    }
    format!(
        "respond={respond}, review={review}, file={file}, pay={pay}, diarise={diarise}, unclassified={unclassified}"
    )
}

/// A deterministic, cleartext-FREE per-protected-handling breakdown for the audit
/// note, e.g. `wp=1, privileged=0, none=2` (verdict #9). Counts + fixed LABELS only
/// — NEVER the matched marker text (mirrors the confidentiality split).
fn protected_handling_breakdown(worklist: &Worklist) -> String {
    let (mut wp, mut privileged, mut none) = (0usize, 0usize, 0usize);
    for item in worklist.items() {
        match item.protected_handling {
            ProtectedHandling::WithoutPrejudice => wp += 1,
            ProtectedHandling::Privileged => privileged += 1,
            ProtectedHandling::None => none += 1,
        }
    }
    format!("wp={wp}, privileged={privileged}, none={none}")
}

/// A deterministic, cleartext-FREE COUNT of items carrying MORE THAN ONE detected
/// date (M1). A number only — never a matched date value — so it is safe in the
/// tamper-evident audit chain (mirrors the other breakdowns' confidentiality split).
fn multiple_dates_count(worklist: &Worklist) -> usize {
    worklist
        .items()
        .iter()
        .filter(|i| i.multiple_dates_detected)
        .count()
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

    /// Synthetic emails seeded as EMAIL_CLASS (Document) docs the engine reads.
    /// EMAIL_ONE carries an RFC822-style header block (external counsel + an
    /// explicit deadline); EMAIL_TWO is body-only from an internal colleague.
    const EMAIL_ONE: &str = "From: counsel@other.example\r\n\
Subject: Project Condor — please review the draft SPA\r\n\
Date: Fri, 19 Jun 2026 09:00:00 +0000\r\n\
\r\n\
Please review the attached draft and revert by 2026-06-22.";
    const EMAIL_TWO: &str = "FYI — filed the signed copy in the matter folder.";

    fn engine() -> Inbox {
        Inbox::new(FirmDomains::new(vec!["acme-law.example".to_string()]))
    }

    fn core_with(grants: Vec<Capability>, store: InMemoryMatterStore) -> TestCore {
        Core::new(
            "sg.inbox.engine",
            GrantSet::from_manifest(grants),
            InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
            InMemoryStorage::new(),
            // Configure a destination so, if egress were ever (wrongly) granted,
            // the broker gate — not a missing sink — is what we are testing.
            InMemoryEgress::new().with_destination("counsel-vault"),
            CoreContext::new("Acme v Beta", "j.smith"),
            store,
        )
    }

    fn seeded_core(grants: Vec<Capability>) -> TestCore {
        let mut store = InMemoryMatterStore::new();
        store.insert(1, EMAIL_CLASS, EMAIL_ONE);
        store.insert(2, EMAIL_CLASS, EMAIL_TWO);
        core_with(grants, store)
    }

    /// The grant set the inbox engine declares.
    fn inbox_grants() -> Vec<Capability> {
        vec![
            Capability::MatterRead(EMAIL_CLASS),
            Capability::Storage(StorageScope::Own),
            Capability::AuditNote,
            // NOTE: no Capability::Egress(..) — the engine holds no egress grant.
        ]
    }

    #[test]
    fn required_capabilities_declares_read_storage_note_and_no_egress() {
        let caps = engine().required_capabilities();
        assert!(
            caps.contains(&Capability::MatterRead(EMAIL_CLASS)),
            "declares the read path"
        );
        assert!(
            caps.contains(&Capability::Storage(StorageScope::Own)),
            "declares storage:own"
        );
        assert!(caps.contains(&Capability::AuditNote), "declares audit.note");
        // Load-bearing: NO egress capability is ever declared.
        assert!(
            !caps.iter().any(|c| matches!(c, Capability::Egress(_))),
            "the inbox engine must NEVER declare an egress capability, got {caps:?}"
        );
    }

    #[test]
    fn build_worklist_reads_through_core_and_audits() {
        let mut core = seeded_core(inbox_grants());
        let worklist = engine().build_worklist(&mut core).unwrap();

        // One row per seeded email, each with provenance pointing at its doc.
        assert_eq!(worklist.len(), 2, "both seeded emails are triaged");
        let ids: Vec<u64> = worklist
            .items()
            .iter()
            .map(|i| i.provenance.doc_id)
            .collect();
        assert_eq!(ids, vec![1, 2]);

        // The reads + the per-run note were audited at the chokepoint.
        let caps: Vec<&Capability> = core
            .audit()
            .entries()
            .iter()
            .map(|e| &e.capability)
            .collect();
        assert!(
            caps.contains(&&Capability::MatterRead(EMAIL_CLASS)),
            "a read was audited"
        );
        assert!(
            caps.contains(&&Capability::AuditNote),
            "the per-run note was audited"
        );
        assert!(
            core.audit().verify_chain(),
            "the keyed hash chain must verify"
        );
    }

    #[test]
    fn rfc822_header_block_is_parsed_into_sender_and_subject() {
        // EMAIL_ONE has a header block: the engine must classify the sender as
        // External (counsel@other.example, not a firm domain). The SUBJECT becomes
        // the secondary label (verdict #4), while the EXCERPT leads with the first
        // new body line — proving the header parse + the body-first excerpt.
        let mut core = seeded_core(inbox_grants());
        let worklist = engine().build_worklist(&mut core).unwrap();

        let one = worklist
            .items()
            .iter()
            .find(|i| i.provenance.doc_id == 1)
            .unwrap();
        assert_eq!(
            one.classification,
            Classification::External,
            "external counsel sender"
        );
        // Subject parsed off the header -> the SECONDARY label (verdict #4).
        assert!(
            one.subject_label.contains("Project Condor"),
            "subject_label from the Subject header, got {:?}",
            one.subject_label
        );
        // The EXCERPT leads with the body, not the subject (verdict #4).
        assert!(
            one.excerpt.contains("review the attached draft")
                && !one.excerpt.contains("Project Condor"),
            "excerpt leads with the body line, got {:?}",
            one.excerpt
        );
        // The review cue fired -> Review action.
        assert_eq!(one.action, Action::Review);
        assert_eq!(one.provenance.rule, Rule::ReviewCue);
        // The explicit deadline 2026-06-22 was extracted.
        assert_eq!(one.due_precision, DuePrecision::ExactDate);
        assert!(one.due_at.is_some(), "an explicit deadline was parsed");
        // SAFETY (DANGER fix #3): the engine runs under NO_ANCHOR, so the priority
        // badge is suppressed and the deadline shows as needs-confirm (not "due in
        // N days") even for an explicit date.
        assert_eq!(
            one.priority, None,
            "priority badge suppressed under NO_ANCHOR"
        );
        assert_eq!(
            one.proximity,
            DeadlineProximity::NeedsAnchor,
            "explicit date needs the anchor for proximity"
        );
    }

    #[test]
    fn crlf_header_block_body_has_no_leading_crlf() {
        // REGRESSION (Medium): the body offset was re-derived from `text.lines()`
        // with `line.len() + 1`, undercounting by 1 byte per CRLF header line. On
        // real (CRLF) `.eml`/Outlook mail this leaked a leading `\r\n` (and more)
        // into the body. Parse a CRLF email and assert the body starts cleanly.
        let raw = "From: counsel@other.example\r\n\
Subject: Project Condor\r\n\
Date: Fri, 19 Jun 2026 09:00:00 +0000\r\n\
\r\n\
First body line.\r\n\
Second body line.";
        let (sender, subject, body) = parse_rfc822ish(raw);
        assert_eq!(
            sender, "counsel@other.example",
            "sender parsed off the From header"
        );
        assert_eq!(
            subject, "Project Condor",
            "subject parsed off the Subject header"
        );
        // The body must NOT begin with a stray `\r` or `\n` from the separator.
        assert!(
            !body.starts_with('\r') && !body.starts_with('\n'),
            "body must have no leading CR/LF, got {body:?}"
        );
        assert!(
            body.starts_with("First body line."),
            "body starts at the real content, got {body:?}"
        );

        // End-to-end: the excerpt (first new body line) is correct, not a
        // blank-looking line caused by a leaked separator.
        let message = Message::from_doc_text(7, raw, NO_ANCHOR);
        assert!(
            !message.body.starts_with('\r') && !message.body.starts_with('\n'),
            "Message body must have no leading CR/LF, got {:?}",
            message.body
        );
        let excerpt = triage::excerpt(&message);
        assert!(
            excerpt.contains("First body line"),
            "excerpt reflects the first new body line, got {excerpt:?}"
        );
    }

    #[test]
    fn lf_only_header_block_still_parses() {
        // The LF-only fallback path: a header block separated by a bare `\n\n` still
        // splits correctly (and the body has no leading newline).
        let raw = "From: a@x.example\nSubject: Hi\n\nBody starts here.";
        let (sender, subject, body) = parse_rfc822ish(raw);
        assert_eq!(sender, "a@x.example");
        assert_eq!(subject, "Hi");
        assert_eq!(body, "Body starts here.");
    }

    #[test]
    fn body_only_email_has_empty_headers_and_unknown_sender() {
        // EMAIL_TWO has no header block: empty sender -> Unknown classification,
        // excerpt from the first body line, a File cue ("signed copy" / "FYI").
        let mut core = seeded_core(inbox_grants());
        let worklist = engine().build_worklist(&mut core).unwrap();

        let two = worklist
            .items()
            .iter()
            .find(|i| i.provenance.doc_id == 2)
            .unwrap();
        assert_eq!(
            two.classification,
            Classification::Unknown,
            "no sender header -> Unknown"
        );
        assert!(
            two.excerpt.contains("signed copy"),
            "excerpt from the body, got {:?}",
            two.excerpt
        );
        assert!(
            two.subject_label.is_empty(),
            "no subject header -> empty secondary label"
        );
        assert_eq!(two.action, Action::File);
    }

    #[test]
    fn audit_note_carries_counts_not_cleartext() {
        // CONFIDENTIALITY SPLIT: the audit note records counts/breakdown ONLY,
        // never the cleartext subject/sender/body of a triaged email.
        let mut core = seeded_core(inbox_grants());
        engine().build_worklist(&mut core).unwrap();

        let notes: Vec<String> = core
            .audit()
            .entries()
            .iter()
            .filter(|e| e.capability == Capability::AuditNote)
            .map(|e| e.detail.clone())
            .collect();
        assert!(!notes.is_empty(), "a per-run note was written");
        assert!(
            notes.iter().any(|d| d.contains("2 message(s) triaged")),
            "note carries the count, got {notes:?}"
        );
        // The breakdown is present (counts + labels).
        assert!(
            notes
                .iter()
                .any(|d| d.contains("external=") && d.contains("review=")),
            "note carries classification + action breakdowns, got {notes:?}"
        );

        // The cleartext subject/sender/body substrings must NEVER appear in the
        // audit chain. Probe distinctive fragments of BOTH fixtures.
        let cleartext_probes = [
            "counsel@other.example",
            "Project Condor",
            "review the attached draft",
            "2026-06-22",
            "signed copy",
            "matter folder",
            "j.smith", // distinct user attribution lives in the entry, NOT the detail
        ];
        // Note: j.smith legitimately appears in the audit ENTRY's acting_user
        // field; assert it never leaks into the NOTE DETAIL string specifically.
        for note in &notes {
            for probe in &cleartext_probes[..cleartext_probes.len() - 1] {
                assert!(
                    !note.contains(probe),
                    "audit note must not carry cleartext {probe:?}, got {note:?}"
                );
            }
        }
    }

    #[test]
    fn no_egress_grant_means_an_egress_attempt_is_refused() {
        // The engine never sends; prove the core would REFUSE egress with the
        // engine's grant set (no egress capability granted). Mirrors redaction.
        let mut core = seeded_core(inbox_grants());
        engine().build_worklist(&mut core).unwrap();
        let err = core.egress_send("counsel-vault", b"x").unwrap_err();
        assert!(
            matches!(err, runtime::CoreError::Denied(Capability::Egress(_))),
            "no egress grant -> egress refused, got {err:?}"
        );
        assert!(core.egress().sent().is_empty(), "nothing left the box");
    }

    #[test]
    fn engine_never_declares_egress_even_indirectly() {
        // Belt-and-braces: the declared capability set contains no egress, so a
        // manifest built from it could never request one.
        assert!(
            !engine()
                .required_capabilities()
                .iter()
                .any(|c| matches!(c, Capability::Egress(_))),
            "egress: [] is load-bearing"
        );
    }

    #[test]
    fn non_granted_class_is_refused() {
        // Default-deny per class: with no matter.read grant the first
        // matter_list_docs is refused — fail-closed, like redaction.
        let mut core = seeded_core(vec![Capability::AuditNote]);
        let err = engine().build_worklist(&mut core).unwrap_err();
        assert!(
            matches!(err, runtime::CoreError::Denied(Capability::MatterRead(_))),
            "a non-granted class must be refused, got {err:?}"
        );
    }

    #[test]
    fn worklist_is_deterministic() {
        // The same seeded matter triages to an identical worklist twice.
        let mut core_a = seeded_core(inbox_grants());
        let mut core_b = seeded_core(inbox_grants());
        let a = engine().build_worklist(&mut core_a).unwrap();
        let b = engine().build_worklist(&mut core_b).unwrap();
        assert_eq!(a, b, "triage must be deterministic for the same input");
    }

    #[test]
    fn under_no_anchor_priority_is_suppressed_and_proximity_is_the_surface() {
        // SAFETY (DANGER fix #3): the engine runs under NO_ANCHOR, so the priority
        // badge is SUPPRESSED for every item (no High-on-everything). The honest
        // surface is the FACTUAL proximity: the email WITH an explicit deadline
        // (doc 1) reads needs-confirm (a deadline is detected, awaiting the received
        // time), while the dateless FYI (doc 2) reads no-date-detected.
        let mut core = seeded_core(inbox_grants());
        let worklist = engine().build_worklist(&mut core).unwrap();
        let one = worklist
            .items()
            .iter()
            .find(|i| i.provenance.doc_id == 1)
            .unwrap();
        let two = worklist
            .items()
            .iter()
            .find(|i| i.provenance.doc_id == 2)
            .unwrap();
        assert_eq!(
            one.priority, None,
            "priority badge suppressed under NO_ANCHOR"
        );
        assert_eq!(
            two.priority, None,
            "priority badge suppressed under NO_ANCHOR"
        );
        assert_eq!(
            one.proximity,
            DeadlineProximity::NeedsAnchor,
            "doc 1 has a detected deadline"
        );
        assert_eq!(
            two.proximity,
            DeadlineProximity::NoDateDetected,
            "doc 2 has no detected date"
        );
    }

    #[test]
    fn worklist_always_carries_honest_limit_caveats() {
        // VERDICT DANGER fix #1: the worklist carries the honest-limits caveats as
        // DATA — including "no date detected != no deadline" — so the presentation
        // cannot omit them. Present even though there ARE items.
        let mut core = seeded_core(inbox_grants());
        let worklist = engine().build_worklist(&mut core).unwrap();
        let labels: Vec<&str> = worklist.caveats().iter().map(|c| c.label()).collect();
        assert!(
            labels.contains(&"deadlines-not-all-caught"),
            "the no-date caveat is present: {labels:?}"
        );
        assert!(
            labels.contains(&"priority-proximity-suppressed"),
            "suppression caveat present: {labels:?}"
        );
        // An EMPTY worklist still carries them ("no items" != "nothing due").
        assert!(
            !Worklist::default().caveats().is_empty(),
            "empty worklist still has caveats"
        );
    }

    #[test]
    fn build_worklist_exposes_an_inert_view() {
        // PHASE 2: the worklist maps into inert view::Sections the host renders, and
        // the "no date != no deadline" caveat survives into the view.
        let mut core = seeded_core(inbox_grants());
        let worklist = engine().build_worklist(&mut core).unwrap();
        let sections = worklist.to_view();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].cards.len(), worklist.len(), "one card per item");
        assert!(
            sections[0]
                .caveats
                .iter()
                .any(|c| c.id == "deadlines-not-all-caught"),
            "the honest caveat is carried into the view"
        );
        // No card shows a priority badge (suppressed under NO_ANCHOR).
        assert!(
            sections[0]
                .cards
                .iter()
                .all(|c| !c.badges.iter().any(|b| b.kind == view::BadgeKind::Priority)),
            "no priority badge in the view under NO_ANCHOR"
        );
        // The `From<&Worklist>` conversion agrees with the method.
        let via_into: Vec<view::Section> = (&worklist).into();
        assert_eq!(via_into, sections);
    }

    #[test]
    fn date_convention_is_configurable_on_the_engine() {
        // VERDICT DANGER fix #2: the numeric-date convention is EXPLICIT/configurable
        // on the engine (default day-first; a US firm flips it).
        assert_eq!(
            engine().date_convention(),
            DateConvention::DayFirst,
            "pilot default"
        );
        let us = Inbox::new(FirmDomains::new(vec!["acme-law.example".to_string()]))
            .with_date_convention(DateConvention::MonthFirst);
        assert_eq!(us.date_convention(), DateConvention::MonthFirst);
    }

    #[test]
    fn protected_handling_is_surfaced_and_counted_not_leaked() {
        // VERDICT #9: a without-prejudice email is flagged for protected handling on
        // the item, and the audit note carries the COUNT, never the marker text.
        let wp = "From: counsel@other.example\r\n\
Subject: settlement\r\n\
\r\n\
Without prejudice — we propose to settle.";
        let mut store = InMemoryMatterStore::new();
        store.insert(1, EMAIL_CLASS, wp);
        let mut core = core_with(inbox_grants(), store);
        let worklist = engine().build_worklist(&mut core).unwrap();
        let one = &worklist.items()[0];
        assert_eq!(one.protected_handling, ProtectedHandling::WithoutPrejudice);
        // It must NOT be mis-bucketed as OpposingCounsel from the WP marker.
        assert_ne!(one.category, Category::OpposingCounsel);

        // Audit note carries the WP count, never the matched marker line.
        let notes: Vec<String> = core
            .audit()
            .entries()
            .iter()
            .filter(|e| e.capability == Capability::AuditNote)
            .map(|e| e.detail.clone())
            .collect();
        assert!(
            notes.iter().any(|d| d.contains("wp=1")),
            "WP count audited: {notes:?}"
        );
        for note in &notes {
            assert!(
                !note.contains("propose to settle"),
                "no cleartext marker in audit: {note:?}"
            );
        }
    }

    // ---- M1 (silent-miss): multiple dates flag end-to-end ------------------

    /// Seed a single email with `body` and triage it into its [`WorklistItem`].
    fn triage_one(body: &str) -> WorklistItem {
        let raw = format!("From: counsel@other.example\r\nSubject: matter\r\n\r\n{body}");
        let mut store = InMemoryMatterStore::new();
        store.insert(1, EMAIL_CLASS, &raw);
        let mut core = core_with(inbox_grants(), store);
        engine().build_worklist(&mut core).unwrap().items()[0].clone()
    }

    #[test]
    fn multi_date_body_sets_the_flag_and_the_view_shows_it() {
        // SAFETY (M1): "the order was sealed 2026-01-05; file your appeal by next
        // Friday." carries a PAST ISO date AND the real "next Friday" deadline. The
        // shown date is the precedence winner, but the item must FLAG the second date,
        // and the view must surface a visible "multiple dates detected — review" badge.
        let body = "The order was sealed 2026-01-05; file your appeal by next Friday.";
        let item = triage_one(body);
        assert!(
            item.multiple_dates_detected,
            "two distinct dates -> the item flag is set"
        );

        let worklist = {
            let raw = format!("From: counsel@other.example\r\nSubject: matter\r\n\r\n{body}");
            let mut store = InMemoryMatterStore::new();
            store.insert(1, EMAIL_CLASS, &raw);
            let mut core = core_with(inbox_grants(), store);
            engine().build_worklist(&mut core).unwrap()
        };
        let sections = worklist.to_view();
        let badges = &sections[0].cards[0].badges;
        assert!(
            badges
                .iter()
                .any(|b| b.kind == view::BadgeKind::Warning && b.label.contains("multiple dates")),
            "the view surfaces the multiple-dates review warning: {badges:?}"
        );
    }

    #[test]
    fn single_date_body_does_not_set_the_flag_or_the_badge() {
        // A body with ONE date does NOT raise the flag (and the view shows no badge).
        let item = triage_one("Please file your reply by 2026-06-22.");
        assert!(!item.multiple_dates_detected, "one date -> no flag");

        let raw = "From: counsel@other.example\r\nSubject: matter\r\n\r\nPlease file your reply by 2026-06-22.";
        let mut store = InMemoryMatterStore::new();
        store.insert(1, EMAIL_CLASS, raw);
        let mut core = core_with(inbox_grants(), store);
        let sections = engine().build_worklist(&mut core).unwrap().to_view();
        assert!(
            !sections[0].cards[0]
                .badges
                .iter()
                .any(|b| b.label.contains("multiple dates")),
            "no multiple-dates badge for a single-date body"
        );
    }

    #[test]
    fn multiple_dates_count_is_audited_as_a_number_not_cleartext() {
        // M1: the audit note carries a multi-date COUNT (a number), never a matched
        // date value (confidentiality split holds).
        let body = "Sealed 2026-01-05; appeal due Monday; pay within 14 days.";
        let raw = format!("From: counsel@other.example\r\nSubject: matter\r\n\r\n{body}");
        let mut store = InMemoryMatterStore::new();
        store.insert(1, EMAIL_CLASS, &raw);
        let mut core = core_with(inbox_grants(), store);
        engine().build_worklist(&mut core).unwrap();

        let notes: Vec<String> = core
            .audit()
            .entries()
            .iter()
            .filter(|e| e.capability == Capability::AuditNote)
            .map(|e| e.detail.clone())
            .collect();
        assert!(
            notes.iter().any(|d| d.contains("multi-date=1")),
            "multi-date count audited: {notes:?}"
        );
        for note in &notes {
            assert!(
                !note.contains("2026-01-05"),
                "no cleartext date in audit: {note:?}"
            );
        }
    }

    // ---- M2 (false positive): quoted history is not scanned for dates ------

    #[test]
    fn weekday_in_quoted_on_wrote_attribution_is_not_a_deadline() {
        // SAFETY (M2): a re-quoted "On Monday, Jane wrote:" attribution introduces
        // quoted history; the date scan runs over quote-STRIPPED text, so the weekday
        // in it must NOT fabricate a phantom deadline. The new content has no date.
        let body = "Thanks, noted.\n\nOn Monday, Jane wrote:\n> please advise";
        let item = triage_one(body);
        assert_eq!(
            item.due_precision,
            DuePrecision::None,
            "no deadline from quoted history"
        );
        assert!(!item.multiple_dates_detected);
    }

    #[test]
    fn date_in_quoted_reply_block_is_not_scanned() {
        // A `>`-quoted prior message's date must not be picked up as THIS message's
        // deadline.
        let body = "All sorted on my side.\n\n> file by 2026-01-05\n> regards";
        let item = triage_one(body);
        assert_eq!(
            item.due_precision,
            DuePrecision::None,
            "a quoted date is not this message's deadline"
        );
    }

    #[test]
    fn real_deadline_in_new_content_still_detected_above_quoted_history() {
        // The genuine new-content deadline above the quote is still detected; the old
        // quoted date below is stripped, so it is a SINGLE-date message (no false
        // multiple-dates flag).
        let body = "Please file by Friday.\n\nOn Monday, Jane wrote:\n> sealed 2026-01-05";
        let item = triage_one(body);
        assert_eq!(
            item.due_precision,
            DuePrecision::Relative,
            "the new-content deadline is detected"
        );
        assert!(
            !item.multiple_dates_detected,
            "the quoted old date is stripped -> one date only"
        );
    }
}
