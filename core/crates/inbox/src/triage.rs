// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gist / action / priority extraction (DETERMINISTIC rule-based triage).
//!
//! PURE: no [`runtime::Core`] handle, no matter data — it operates on a plain
//! [`crate::Message`] (plus the already-computed due-date + classification) read
//! THROUGH the core by the [`crate::Inbox`] engine, so it is independently
//! unit-testable (like redaction's pure pass).
//!
//! ## Honest framing (load-bearing)
//!
//! - **DETERMINISTIC, model-free triage** (CLAUDE.md non-negotiable): the gist is
//!   a rule-based summary (subject, else the first meaningful body line, trimmed +
//!   clamped); the action/priority come from a FIXED keyword/structure ruleset
//!   (`please review`, a question mark, an invoice cue, an explicit deadline). NO
//!   model / LLM / NLP summarizer — anywhere.
//! - **Rules PROPOSE; the human curates.** The gist is a *suggested* one-liner and
//!   the action a *suggested* next step — the lawyer edits or discards them on the
//!   worklist. A wrong auto-action on a legal email is a real risk, so the
//!   dashboard never auto-executes; it presents a worklist a human confirms.
//! - **The rule that fired is recorded** (see [`crate::Provenance`]) so the human
//!   can see WHY an action/priority was suggested, not just what.

use crate::classify::{Category, Classification};
use crate::dateparse::{DueDate, DuePrecision};
use crate::Message;

/// The longest a rule-derived [`gist`] may be (characters). A worklist row is one
/// line; a gist longer than this is clamped (on a char boundary) with an ellipsis.
const MAX_GIST_CHARS: usize = 120;

/// The suggested next action for a message — a deterministic, rule-derived hint
/// the human confirms or overrides on the worklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Needs a reply (a question, an explicit ask to respond).
    Respond,
    /// Needs review (a document/draft to read).
    Review,
    /// Needs filing/saving (an attachment / "for your records").
    File,
    /// Needs payment (an invoice / fee note / amount due).
    Pay,
    /// Carries a deadline to put in the diary (a date with no other clear action).
    Diarise,
    /// The rules could not classify it (the safe default before review).
    Unclassified,
}

/// A coarse priority bucket for ordering the worklist. Derived deterministically
/// (see [`suggest_priority`]): an explicit/near deadline or an external sender
/// raises it; an internal FYI lowers it.
///
/// SAFETY (DANGER fix #3): the algorithmic priority badge is an OPINION that is
/// only trustworthy once the real per-message received-time anchor is wired. Under
/// the [`crate::NO_ANCHOR`] sentinel the badge would be "High-on-everything", so it
/// is SUPPRESSED there ([`suggest_priority`] returns `None`); the presentation
/// shows the FACTUAL [`DeadlineProximity`] instead. With a real anchor the badge
/// returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Normal,
    High,
}

/// A FACTUAL statement about a deadline's nearness — NOT an opinion/priority. This
/// is what the worklist surfaces in place of the algorithmic priority badge when
/// the badge cannot be trusted (and alongside it when it can).
///
/// SAFETY (DANGER fix #3, load-bearing):
/// - "overdue by N days" / "due in N days" / "due today" are FACTS, computable only
///   against a REAL received-time anchor. Under [`crate::NO_ANCHOR`] they are NOT
///   computed — surfacing a fact you cannot compute is worse than admitting you
///   cannot.
/// - A RELATIVE deadline ("by Friday") resolved against epoch-0 is MEANINGLESS, so
///   under [`crate::NO_ANCHOR`] it is reported [`DeadlineProximity::NeedsAnchor`]
///   (unresolved / needs the received time) — never as a resolved "due in N days".
/// - An AMBIGUOUS numeric date is itself a QUESTION
///   ([`DeadlineProximity::AmbiguousDate`]) before any proximity can be stated.
/// - "no date DETECTED" is [`DeadlineProximity::NoDateDetected`] — which is NOT "no
///   deadline" (see the crate [`Caveat`](crate::Caveat)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineProximity {
    /// A resolved deadline already in the past, by `days` (>= 1) relative to the
    /// received time. "overdue by N days" — a fact.
    Overdue { days: i64 },
    /// A resolved deadline falling on the received day. "due today" — a fact.
    DueToday,
    /// A resolved deadline `days` (>= 1) in the future relative to the received
    /// time. "due in N days" — a fact.
    DueInDays { days: i64 },
    /// A relative deadline ("by Friday", "in 14 days") was detected but the real
    /// received-time anchor is not wired ([`crate::NO_ANCHOR`]), so it CANNOT be
    /// resolved to a real day. Surfaced as needs-confirm, NEVER as a resolved date.
    NeedsAnchor,
    /// The detected numeric date is irreducibly ambiguous (e.g. "3 Apr or 4 Mar?").
    /// The date itself is a question; no proximity is asserted until it is resolved.
    AmbiguousDate,
    /// A vague urgency cue ("ASAP", "EOD") with no resolvable day.
    VagueUrgency,
    /// No date was DETECTED. NOT a claim that there is no deadline (see the crate
    /// [`Caveat`](crate::Caveat) — legally-arising deadlines are not caught).
    NoDateDetected,
}

/// Which deterministic rule produced an [`Action`] — recorded on the worklist row
/// (see [`crate::Provenance::rule`]) so the human sees WHY, not just what.
///
/// These are STABLE, cleartext-free LABELS (a rule name, never a matched value),
/// so they are safe to show on a row AND to count in the audit breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// An invoice / fee-note / amount-due cue → [`Action::Pay`].
    PaymentCue,
    /// A "please review / draft attached" cue → [`Action::Review`].
    ReviewCue,
    /// A question or "please reply / let me know" cue → [`Action::Respond`].
    RespondCue,
    /// A "for your file / records / FYI with an attachment" cue → [`Action::File`].
    FileCue,
    /// A deadline with no clearer action cue → [`Action::Diarise`].
    DeadlineOnly,
    /// No rule fired → [`Action::Unclassified`].
    NoRule,
}

impl Rule {
    /// A stable, cleartext-free label for the audit breakdown / the row. (A rule
    /// NAME, never a matched value — safe to log.)
    pub fn label(self) -> &'static str {
        match self {
            Rule::PaymentCue => "payment-cue",
            Rule::ReviewCue => "review-cue",
            Rule::RespondCue => "respond-cue",
            Rule::FileCue => "file-cue",
            Rule::DeadlineOnly => "deadline-only",
            Rule::NoRule => "no-rule",
        }
    }

    /// The action this rule proposes.
    fn action(self) -> Action {
        match self {
            Rule::PaymentCue => Action::Pay,
            Rule::ReviewCue => Action::Review,
            Rule::RespondCue => Action::Respond,
            Rule::FileCue => Action::File,
            Rule::DeadlineOnly => Action::Diarise,
            Rule::NoRule => Action::Unclassified,
        }
    }
}

/// A short, rule-derived one-line EXCERPT of a message, for the worklist row.
/// DETERMINISTIC string transform — NO model summarizer.
///
/// CHANGE (verdict #4): the excerpt defaults to the first NEW BODY line, NOT the
/// subject. Legal subjects are "RE: RE: FW:" noise that hides what the message
/// actually says; the lawyer wants the gist of the new content. The subject is kept
/// only as a SECONDARY label (see [`subject_label`]) the presentation can show
/// alongside.
///
/// Rule: take the first MEANINGFUL body line — a non-empty line that is NOT quoted
/// reply history (leading `>` or an `On … wrote:` attribution) and NOT inside a
/// signature block (after a `-- ` sig delimiter). If the body has NO meaningful new
/// line (e.g. a quote-only forward, or an empty body), FALL BACK to the trimmed
/// subject so the row is never blank when a subject exists. Whitespace is collapsed
/// and the result is clamped to [`MAX_GIST_CHARS`] on a char boundary (with `…`).
/// Returns empty only when there is genuinely no new body line AND no subject.
pub fn excerpt(message: &Message) -> String {
    let body_line = first_new_body_line(&message.body);
    let raw = if !body_line.is_empty() {
        body_line
    } else {
        // Fall back to the subject ONLY when there is no new body content.
        collapse_ws(&message.subject)
    };
    clamp_chars(&raw, MAX_GIST_CHARS)
}

/// The trimmed/collapsed subject, as a SECONDARY label for the row (the excerpt
/// leads; this is shown alongside). Empty when the message has no subject.
pub fn subject_label(message: &Message) -> String {
    clamp_chars(&collapse_ws(&message.subject), MAX_GIST_CHARS)
}

/// The first NEW, meaningful body line, whitespace-collapsed. DETERMINISTIC.
///
/// Skips, deterministically:
/// - blank lines;
/// - quoted reply history: a line starting with `>`, OR an `On <…> wrote:` /
///   `From:`-style attribution header that introduces a quoted block;
/// - signature blocks: everything at/after a `-- ` sig delimiter line (the RFC 3676
///   convention) is treated as signature and skipped.
///
/// Returns empty when no such line exists (a quote-only / signature-only / empty
/// body), so the caller can fall back to the subject.
fn first_new_body_line(body: &str) -> String {
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        // Signature delimiter ("-- " per RFC 3676): everything from here down is the
        // signature; stop scanning (nothing meaningful follows for an excerpt).
        if is_signature_delimiter(t) {
            break;
        }
        // Quoted reply history or its attribution header: skip.
        if t.starts_with('>') || is_quote_attribution(t) {
            continue;
        }
        return collapse_ws(t);
    }
    String::new()
}

/// Strip quoted reply history + signature blocks from `body`, returning ONLY the new
/// content lines (joined with `\n`). DETERMINISTIC. Reuses the SAME per-line
/// predicates the excerpt uses ([`first_new_body_line`]): it DROPS `>`-prefixed quoted
/// lines and quote-attribution headers ("On … wrote:" / "From:" /
/// "-----Original Message-----" / an underline rule), and STOPS at an RFC 3676
/// signature delimiter (`-- ` — everything below is the signature).
///
/// SAFETY (M2 quote-stripping fix, load-bearing): the date scan must run over
/// quote-stripped text, NOT the raw subject+body. Without this, a weekday/date in
/// QUOTED HISTORY (a re-quoted "On Monday, Jane wrote:" line, or an old date in a
/// `>`-quoted block) would be scanned and could fabricate a phantom deadline from a
/// PRIOR message. Stripping the history first means the scanner only sees the NEW
/// message's content — the same content the excerpt leads with.
///
/// Unlike [`first_new_body_line`] this keeps ALL new lines (so a date anywhere in the
/// new content is still scanned) rather than just the first. It mirrors the excerpt's
/// SKIP-not-stop treatment of an attribution line (so genuine new content below a
/// bottom-posted attribution is not lost), and keeps each kept line's original
/// (un-collapsed) text. Char-boundary-safe: it operates on whole `lines()`, never
/// slicing mid-codepoint.
pub fn strip_quoted_history(body: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        // Signature delimiter: everything from here down is the signature — stop.
        if is_signature_delimiter(t) {
            break;
        }
        // A `>`-prefixed quoted line OR a quote-attribution header: drop it, but keep
        // scanning (mirrors first_new_body_line's skip, so interleaved/bottom-posted
        // new content is still kept).
        if t.starts_with('>') || is_quote_attribution(t) {
            continue;
        }
        kept.push(line);
    }
    kept.join("\n")
}

/// Whether `line` (already trimmed) is an RFC 3676 signature delimiter. The
/// standard form is exactly `-- ` (dash dash space); we also accept a bare `--`
/// (common in practice) but NOT a longer run of dashes (a horizontal rule).
fn is_signature_delimiter(line: &str) -> bool {
    line == "--" || line == "-- "
}

/// Whether `line` (already trimmed) looks like the ATTRIBUTION header that
/// introduces a quoted reply block, e.g. "On 1 Jan 2026, Jane wrote:" or a
/// re-quoted "From: …" header. DETERMINISTIC, conservative: only a couple of fixed
/// shapes, so a genuine new-content line is not mistaken for quoted history.
fn is_quote_attribution(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    // "On … wrote:" (Gmail/Outlook reply attribution).
    (lower.starts_with("on ") && lower.trim_end().ends_with("wrote:"))
        // A re-quoted header block introducing forwarded/replied content.
        || lower.starts_with("from:")
        || lower.starts_with("-----original message-----")
        || lower.starts_with("________________________________")
}

/// Collapse all runs of ASCII whitespace to single spaces and trim the ends.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Clamp `s` to at most `max` characters on a char boundary, appending `…` if it
/// was truncated. Operates on chars (never bytes), so multibyte text is safe.
fn clamp_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Keyword cues that suggest each action, checked in PRIORITY order in
/// [`fired_rule`]. Lowercase needles matched as substrings of `subject + body`.
const PAYMENT_CUES: &[&str] = &[
    "invoice",
    "fee note",
    "amount due",
    "payment due",
    "remittance",
    "please pay",
    "outstanding balance",
];
const REVIEW_CUES: &[&str] = &[
    "please review",
    "for your review",
    "draft attached",
    "review the attached",
    "comments on the draft",
    "mark up",
];
const RESPOND_CUES: &[&str] = &[
    "please reply",
    "please respond",
    "let me know",
    "your thoughts",
    "can you confirm",
    "please confirm",
    "awaiting your response",
];
const FILE_CUES: &[&str] = &[
    "for your file",
    "for your records",
    "for the file",
    "please file",
    "signed copy",
    "fyi",
];

/// Interrogative openers that, together with a `?`, indicate the message is asking
/// the reader something (so a Respond suggestion is justified). Matched as the start
/// of any line OR after sentence punctuation — see [`asks_a_question`].
const QUESTION_OPENERS: &[&str] = &[
    "who ",
    "what ",
    "when ",
    "where ",
    "why ",
    "how ",
    "which ",
    "whose ",
    "can you",
    "could you",
    "would you",
    "will you",
    "do you",
    "did you",
    "are you",
    "is there",
    "are there",
    "should we",
    "shall we",
    "may i",
    "should i",
];

/// Whether the text plausibly ASKS the reader a question (a `?` PLUS an
/// interrogative opener). DETERMINISTIC + conservative.
///
/// CHANGE (verdict #7): a BARE `?` no longer forces Respond. A stray `?` (a URL, an
/// emoticon, "see attached (rev?)") is not an ask; requiring an interrogative opener
/// keeps `Unclassified` the honest default unless the message really is a question.
fn asks_a_question(hay: &str) -> bool {
    if !hay.contains('?') {
        return false;
    }
    QUESTION_OPENERS.iter().any(|opener| hay.contains(opener))
}

/// Decide which deterministic [`Rule`] fires for a message, given its already-
/// computed due date. PRIORITY order (first match wins): payment → review →
/// respond → file → deadline-only → no-rule.
///
/// CHANGE (verdict #7): the ruleset is LESS eager — a bare `?` alone no longer
/// forces Respond ([`asks_a_question`] now gates the `?` on an interrogative
/// opener), so [`Rule::NoRule`] → [`Action::Unclassified`] is the honest default
/// more often. The buckets are EDITABLE suggestions the human curates, not verdicts.
fn fired_rule(message: &Message, due: &DueDate) -> Rule {
    let mut hay = String::with_capacity(message.subject.len() + message.body.len() + 1);
    hay.push_str(&message.subject.to_ascii_lowercase());
    hay.push(' ');
    hay.push_str(&message.body.to_ascii_lowercase());

    let any = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));

    if any(PAYMENT_CUES) {
        Rule::PaymentCue
    } else if any(REVIEW_CUES) {
        Rule::ReviewCue
    } else if any(RESPOND_CUES) || asks_a_question(&hay) {
        Rule::RespondCue
    } else if any(FILE_CUES) {
        Rule::FileCue
    } else if due.precision != DuePrecision::None {
        // A deadline with no clearer action cue -> put it in the diary.
        Rule::DeadlineOnly
    } else {
        Rule::NoRule
    }
}

/// The [`Rule`] that fires for a message (exposed so the engine can record it as
/// provenance). DETERMINISTIC.
pub fn suggest_rule(message: &Message, due: &DueDate) -> Rule {
    fired_rule(message, due)
}

/// Suggest a next action from a message via the fixed keyword/structure ruleset.
/// Thin wrapper over [`suggest_rule`] so the action and its provenance always
/// agree. DETERMINISTIC.
pub fn suggest_action(message: &Message, due: &DueDate) -> Action {
    fired_rule(message, due).action()
}

/// Suggest a priority bucket — or `None` when the badge cannot be trusted.
/// DETERMINISTIC + EXPLAINABLE.
///
/// SAFETY (DANGER fix #3, load-bearing): the algorithmic badge depends on a REAL
/// received-time anchor (nearness is measured against it). Under the
/// [`crate::NO_ANCHOR`] sentinel — the current reality, the anchor is not wired —
/// the badge degenerates to "High-on-everything", which is an opinion nobody should
/// act on. So this returns **`None`** under `NO_ANCHOR`: the presentation suppresses
/// the badge and shows the FACTUAL [`DeadlineProximity`] ([`compute_proximity`])
/// instead. With a real anchor the full model returns a `Some(Priority)`.
///
/// The model (only applied with a real anchor) is deliberately simple/documented:
/// - **High** — any payment action (money + a clock); OR an EXTERNAL sender with a
///   deadline NEAR (within [`NEAR_DEADLINE_DAYS`] of the received time) — the
///   malpractice-risk quadrant; OR a court/filing message with a deadline.
/// - **Low** — a newsletter, OR an INTERNAL sender with no deadline and no
///   actionable cue (a colleague FYI).
/// - **Normal** — everything else (the neutral default).
///
/// NOTE: an AMBIGUOUS date is treated as a clock for nearness ONLY via its primary
/// candidate; the badge never claims more certainty than the proximity does.
pub fn suggest_priority(
    message: &Message,
    due: &DueDate,
    action: Action,
    classification: Classification,
    category: Category,
) -> Option<Priority> {
    // SUPPRESS the badge entirely until a real received-time anchor is wired:
    // every nearness comparison would be against epoch-0 and rank High.
    if message.received_at == crate::NO_ANCHOR {
        return None;
    }

    let has_clock = due.precision != DuePrecision::None;
    let near = is_near_deadline(due, message.received_at);
    let external = classification == Classification::External;

    // High: the risk quadrants.
    if action == Action::Pay {
        return Some(Priority::High);
    }
    if external && near {
        return Some(Priority::High);
    }
    if category == Category::CourtFiling && (near || has_clock) {
        return Some(Priority::High);
    }

    // Low: low-signal newsletter/internal traffic with no clock.
    if category == Category::Newsletter {
        return Some(Priority::Low);
    }
    if classification == Classification::Internal && !has_clock && action == Action::Unclassified {
        return Some(Priority::Low);
    }

    Some(Priority::Normal)
}

/// The number of days from the received time within which a deadline counts as
/// "near" (and so raises priority).
const NEAR_DEADLINE_DAYS: i64 = 7;

/// Milliseconds per day — for converting a resolved `due_at`/anchor delta to days.
const MS_PER_DAY: i64 = 86_400_000;

/// Whether `due` is a "near" clock relative to `anchor` (the received time). Only
/// meaningful with a REAL anchor (the caller suppresses the badge under
/// [`crate::NO_ANCHOR`], so this is never reached with the sentinel from
/// [`suggest_priority`]).
///
/// - [`DuePrecision::None`] → not a clock (`false`).
/// - [`DuePrecision::Vague`] → always a clock (`true`) — an urgency cue.
/// - A resolved day (incl. an [`DuePrecision::Ambiguous`] primary candidate) →
///   "near" iff it falls within [`NEAR_DEADLINE_DAYS`] of the anchor (a PAST/overdue
///   day is also "near": overdue is at least as urgent).
fn is_near_deadline(due: &DueDate, anchor: crate::dateparse::Anchor) -> bool {
    match due.precision {
        DuePrecision::None => false,
        DuePrecision::Vague => true,
        _ => match due.due_at {
            None => false,
            Some(due_ms) => {
                // No anchor -> nearness is undecidable; conservatively NOT near so
                // the badge (suppressed anyway under NO_ANCHOR) never over-claims.
                if anchor == crate::NO_ANCHOR {
                    return false;
                }
                let delta_days = (due_ms - anchor).div_euclid(MS_PER_DAY);
                delta_days <= NEAR_DEADLINE_DAYS
            }
        },
    }
}

/// Compute the FACTUAL [`DeadlineProximity`] for a message's deadline relative to
/// its received-time `anchor`. DETERMINISTIC. This is what the worklist surfaces in
/// place of the (suppressed) priority badge under [`crate::NO_ANCHOR`], and
/// alongside it with a real anchor.
///
/// SAFETY (DANGER fix #3): under [`crate::NO_ANCHOR`] a RELATIVE deadline cannot be
/// resolved to a real day (it was computed against epoch-0), so it is reported as
/// [`DeadlineProximity::NeedsAnchor`] — never as a resolved "due in N days". An
/// EXPLICIT/AMBIGUOUS date with no anchor still cannot be measured for nearness, so
/// it too reports [`DeadlineProximity::NeedsAnchor`] (an ambiguous date first
/// reports [`DeadlineProximity::AmbiguousDate`], since the date itself is the open
/// question). Proximity FACTS (overdue / today / in N days) are computed ONLY when a
/// real anchor and a resolved day are both present.
pub fn compute_proximity(due: &DueDate, anchor: crate::dateparse::Anchor) -> DeadlineProximity {
    match due.precision {
        DuePrecision::None => DeadlineProximity::NoDateDetected,
        DuePrecision::Vague => DeadlineProximity::VagueUrgency,
        // An ambiguous date is a QUESTION before any proximity can be asserted —
        // regardless of the anchor.
        DuePrecision::Ambiguous => DeadlineProximity::AmbiguousDate,
        // A relative date resolved against epoch-0 is meaningless: needs the anchor.
        DuePrecision::Relative if anchor == crate::NO_ANCHOR => DeadlineProximity::NeedsAnchor,
        // An explicit date is a real day, but its NEARNESS still needs the anchor.
        DuePrecision::ExactDate | DuePrecision::Day if anchor == crate::NO_ANCHOR => {
            DeadlineProximity::NeedsAnchor
        }
        // We have a real anchor and a resolved day -> state the FACT.
        DuePrecision::ExactDate | DuePrecision::Day | DuePrecision::Relative => match due.due_at {
            None => DeadlineProximity::NoDateDetected,
            Some(due_ms) => {
                let delta = (due_ms - anchor).div_euclid(MS_PER_DAY);
                match delta {
                    0 => DeadlineProximity::DueToday,
                    d if d > 0 => DeadlineProximity::DueInDays { days: d },
                    d => DeadlineProximity::Overdue { days: -d },
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Category, Classification};
    use crate::dateparse::{extract_due_date, Anchor, DateConvention, DueDate};
    use crate::Message;

    /// A fixed reference instant for deterministic tests: 2026-06-19 00:00 UTC
    /// (a Friday). `20623 * 86_400_000` (days-since-epoch * ms-per-day).
    const ANCHOR: Anchor = 1_781_827_200_000;

    fn msg(subject: &str, body: &str) -> Message {
        Message::new(1, "counsel@other.example", subject, body, ANCHOR)
    }

    /// Parse a message's text under the pilot-default day-first convention (the
    /// triage tests do not exercise the convention itself — dateparse tests do).
    fn due_for(m: &Message) -> DueDate {
        extract_due_date(&m.body, m.received_at, DateConvention::DayFirst)
    }

    #[test]
    fn excerpt_defaults_to_first_new_body_line_not_subject() {
        // CHANGE (verdict #4): the excerpt is the first NEW body line, NOT the
        // "RE: RE: FW:" subject. The subject is the SECONDARY label.
        let m = msg(
            "Re: Re: FW: Condor",
            "Please review the attached draft and revert.",
        );
        assert_eq!(excerpt(&m), "Please review the attached draft and revert.");
        assert_eq!(
            subject_label(&m),
            "Re: Re: FW: Condor",
            "subject kept as a secondary label"
        );
    }

    #[test]
    fn excerpt_skips_quoted_history_and_signatures() {
        // Quoted reply history (>) and its "On … wrote:" attribution are skipped;
        // the signature block after "-- " is not used as the excerpt.
        let body = "On 1 Jan 2026, Jane wrote:\n> old quoted text\n> more quote\n\nHere is the actual new ask.\n\n-- \nJane Roe\nPartner";
        let m = msg("Re: thread", body);
        assert_eq!(excerpt(&m), "Here is the actual new ask.");
    }

    #[test]
    fn excerpt_falls_back_to_subject_when_no_new_body() {
        // A quote-only forward (no new content) falls back to the subject so the row
        // is never blank when a subject exists.
        let m = msg("FW: signed deed", "> quoted only\n> nothing new here");
        assert_eq!(excerpt(&m), "FW: signed deed");
    }

    #[test]
    fn strip_quoted_history_drops_quotes_attribution_and_signature() {
        // SAFETY (M2): the date haystack runs over quote-stripped text. The new
        // content is kept; the attribution header, the `>`-quoted lines, and the
        // signature block (with its date) are all removed.
        let body = "Please action by Friday.\n\nOn Monday, Jane wrote:\n> old note dated 2026-01-05\n\n-- \nJane Roe\nSee you 2026-12-31";
        let stripped = strip_quoted_history(body);
        assert!(
            stripped.contains("Please action by Friday."),
            "new content kept: {stripped:?}"
        );
        assert!(
            !stripped.contains("Jane wrote"),
            "attribution dropped: {stripped:?}"
        );
        assert!(
            !stripped.contains("2026-01-05"),
            "quoted date dropped: {stripped:?}"
        );
        assert!(
            !stripped.contains("2026-12-31"),
            "signature (and its date) dropped: {stripped:?}"
        );
    }

    #[test]
    fn strip_quoted_history_keeps_bottom_posted_new_content() {
        // New content BELOW a bottom-posted attribution is kept (skip-not-stop), so a
        // genuine date there is still scanned.
        let body =
            "On Monday, Jane wrote:\n> please advise\n\nReplying inline: file by 2026-06-22.";
        let stripped = strip_quoted_history(body);
        assert!(
            stripped.contains("file by 2026-06-22."),
            "bottom-posted content kept: {stripped:?}"
        );
        assert!(
            !stripped.contains("please advise"),
            "quoted line dropped: {stripped:?}"
        );
    }

    #[test]
    fn excerpt_clamps_long_text() {
        let m = msg("subj", &"word ".repeat(200));
        let g = excerpt(&m);
        assert!(
            g.chars().count() <= MAX_GIST_CHARS,
            "excerpt clamped to a row size"
        );
        assert!(
            g.ends_with('…'),
            "a truncated excerpt is marked with an ellipsis"
        );
    }

    #[test]
    fn excerpt_empty_when_no_subject_and_no_body() {
        assert_eq!(excerpt(&msg("", "")), "");
    }

    #[test]
    fn action_payment_cue() {
        let m = msg(
            "Invoice 0042",
            "Amount due: $4,200. Please pay within 14 days.",
        );
        let due = due_for(&m);
        assert_eq!(suggest_action(&m, &due), Action::Pay);
        assert_eq!(suggest_rule(&m, &due), Rule::PaymentCue);
    }

    #[test]
    fn action_review_cue() {
        let m = msg("Draft SPA", "Please review the attached draft and revert.");
        let due = due_for(&m);
        assert_eq!(suggest_action(&m, &due), Action::Review);
    }

    #[test]
    fn action_respond_for_a_question() {
        let m = msg("Quick one", "Are you free to take the call tomorrow?");
        let due = due_for(&m);
        assert_eq!(suggest_action(&m, &due), Action::Respond);
    }

    #[test]
    fn action_bare_question_mark_alone_does_not_force_respond() {
        // CHANGE (verdict #7): a stray `?` with no interrogative opener must NOT
        // force Respond — Unclassified is the honest default.
        let m = msg("Doc rev?", "see attached (final rev?) for the file note");
        let due = due_for(&m);
        assert_ne!(
            suggest_action(&m, &due),
            Action::Respond,
            "a bare ? is not an ask"
        );
    }

    #[test]
    fn action_real_question_still_responds() {
        // A `?` WITH an interrogative opener IS an ask -> Respond.
        let m = msg("re: terms", "Could you confirm the closing figure?");
        let due = due_for(&m);
        assert_eq!(suggest_action(&m, &due), Action::Respond);
    }

    #[test]
    fn action_file_cue() {
        let m = msg("Executed deed", "Attaching the signed copy for your file.");
        let due = due_for(&m);
        assert_eq!(suggest_action(&m, &due), Action::File);
    }

    #[test]
    fn action_diarise_when_only_a_deadline() {
        // A deadline but no review/respond/pay/file cue -> Diarise.
        let m = msg("Note", "The window closes on 2026-07-01.");
        let due = due_for(&m);
        assert_eq!(due.precision, DuePrecision::ExactDate);
        assert_eq!(suggest_action(&m, &due), Action::Diarise);
    }

    #[test]
    fn action_unclassified_when_nothing_fires() {
        let m = msg("Lunch", "See you at noon.");
        let due = due_for(&m);
        assert_eq!(suggest_action(&m, &due), Action::Unclassified);
        assert_eq!(suggest_rule(&m, &due), Rule::NoRule);
    }

    #[test]
    fn priority_high_for_external_near_deadline() {
        let m = msg("Reply needed", "Please respond by 2026-06-22.");
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::External,
            Category::Unknown,
        );
        assert_eq!(
            p,
            Some(Priority::High),
            "external + a near deadline ranks highest"
        );
    }

    #[test]
    fn priority_high_for_payment() {
        let m = msg("Invoice", "Amount due $1,000.");
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::External,
            Category::Unknown,
        );
        assert_eq!(p, Some(Priority::High));
    }

    #[test]
    fn priority_low_for_internal_fyi_no_deadline() {
        // An internal colleague, no deadline, no actionable cue -> Unclassified
        // action -> Low priority (a low-signal internal note).
        let m = Message::new(
            2,
            "colleague@acme-law.example",
            "team update",
            "sharing notes from standup",
            ANCHOR,
        );
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        assert_eq!(action, Action::Unclassified, "no cue fired");
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::Internal,
            Category::InternalAdmin,
        );
        assert_eq!(p, Some(Priority::Low));
    }

    #[test]
    fn priority_low_for_newsletter() {
        let m = msg("Bulletin", "Unsubscribe here.");
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::External,
            Category::Newsletter,
        );
        assert_eq!(p, Some(Priority::Low));
    }

    #[test]
    fn priority_normal_is_the_default() {
        // External, no deadline, a respond cue -> neither High nor Low.
        let m = msg("Question", "What are your thoughts on the heads of terms?");
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::External,
            Category::Unknown,
        );
        assert_eq!(p, Some(Priority::Normal));
    }

    #[test]
    fn far_off_deadline_is_not_near() {
        // A deadline well beyond the window does not, by itself, make an external
        // message High.
        let m = msg("Reminder", "Diarise the long-stop date 2026-12-31.");
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::External,
            Category::Unknown,
        );
        assert_ne!(
            p,
            Some(Priority::High),
            "a far-off deadline alone is not High"
        );
    }

    #[test]
    fn priority_badge_is_suppressed_under_no_anchor() {
        // SAFETY (DANGER fix #3): with the NO_ANCHOR sentinel the badge would be
        // High-on-everything, so it is SUPPRESSED (None) — the presentation shows
        // factual proximity instead. A payment that would be High WITH an anchor
        // returns None WITHOUT one.
        let m = Message::new(
            1,
            "counsel@other.example",
            "Invoice",
            "Amount due $1,000.",
            crate::NO_ANCHOR,
        );
        let due = due_for(&m);
        let action = suggest_action(&m, &due);
        let p = suggest_priority(
            &m,
            &due,
            action,
            Classification::External,
            Category::Unknown,
        );
        assert_eq!(
            p, None,
            "the priority badge must be suppressed under NO_ANCHOR"
        );
        // The SAME message WITH a real anchor does produce a badge.
        let m2 = Message::new(
            1,
            "counsel@other.example",
            "Invoice",
            "Amount due $1,000.",
            ANCHOR,
        );
        let due2 = due_for(&m2);
        let p2 = suggest_priority(
            &m2,
            &due2,
            suggest_action(&m2, &due2),
            Classification::External,
            Category::Unknown,
        );
        assert_eq!(
            p2,
            Some(Priority::High),
            "with a real anchor the badge returns"
        );
    }

    #[test]
    fn proximity_due_today_overdue_and_future_are_facts() {
        // Against the real ANCHOR (2026-06-19): an explicit date on/around it yields
        // FACTUAL proximity, not an opinion.
        let today = compute_proximity(&due_for(&msg("", "file by 2026-06-19")), ANCHOR);
        assert_eq!(today, DeadlineProximity::DueToday);

        let future = compute_proximity(&due_for(&msg("", "file by 2026-06-22")), ANCHOR);
        assert_eq!(future, DeadlineProximity::DueInDays { days: 3 });

        let overdue = compute_proximity(&due_for(&msg("", "was due 2026-06-15")), ANCHOR);
        assert_eq!(overdue, DeadlineProximity::Overdue { days: 4 });
    }

    #[test]
    fn proximity_relative_date_under_no_anchor_needs_confirm() {
        // SAFETY (DANGER fix #3): a relative deadline ("by Monday") under NO_ANCHOR
        // was computed against epoch-0 and is meaningless -> NeedsAnchor, NEVER a
        // resolved "due in N days".
        let m = Message::new(
            1,
            "x@other.example",
            "",
            "please sign by Monday",
            crate::NO_ANCHOR,
        );
        let due = due_for(&m);
        assert_eq!(due.precision, DuePrecision::Relative);
        assert_eq!(
            compute_proximity(&due, crate::NO_ANCHOR),
            DeadlineProximity::NeedsAnchor
        );
    }

    #[test]
    fn proximity_explicit_date_under_no_anchor_needs_anchor_for_nearness() {
        // An EXPLICIT date is a real day, but its NEARNESS still cannot be measured
        // without the received time -> NeedsAnchor (we do not fabricate "due in N").
        let m = Message::new(
            1,
            "x@other.example",
            "",
            "file by 2026-06-22",
            crate::NO_ANCHOR,
        );
        let due = due_for(&m);
        assert_eq!(due.precision, DuePrecision::ExactDate);
        assert_eq!(
            compute_proximity(&due, crate::NO_ANCHOR),
            DeadlineProximity::NeedsAnchor
        );
    }

    #[test]
    fn proximity_ambiguous_date_is_a_question() {
        // An ambiguous numeric date is a QUESTION before proximity -> AmbiguousDate
        // (regardless of the anchor).
        let m = msg("", "respond by 03/04/2026");
        let due = due_for(&m);
        assert_eq!(due.precision, DuePrecision::Ambiguous);
        assert_eq!(
            compute_proximity(&due, ANCHOR),
            DeadlineProximity::AmbiguousDate
        );
    }

    #[test]
    fn proximity_no_date_is_not_no_deadline() {
        // "no date DETECTED" -> NoDateDetected. (The crate Caveat carries the
        // "this is NOT no deadline" honesty banner — asserted in lib.rs tests.)
        let m = msg("Lunch", "see you at noon");
        let due = due_for(&m);
        assert_eq!(due.precision, DuePrecision::None);
        assert_eq!(
            compute_proximity(&due, ANCHOR),
            DeadlineProximity::NoDateDetected
        );
    }

    #[test]
    fn triage_is_deterministic() {
        let m = msg("Invoice 7", "Amount due. Please pay by 2026-06-22.");
        let due = due_for(&m);
        let a1 = (
            suggest_action(&m, &due),
            suggest_rule(&m, &due),
            excerpt(&m),
            compute_proximity(&due, m.received_at),
        );
        let a2 = (
            suggest_action(&m, &due),
            suggest_rule(&m, &due),
            excerpt(&m),
            compute_proximity(&due, m.received_at),
        );
        assert_eq!(a1, a2);
        // Silence an unused-import style warning by asserting the DueDate default
        // helper still works (used by the engine when no date is present).
        assert_eq!(DueDate::none().precision, DuePrecision::None);
    }
}
