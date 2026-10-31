// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic due-date extraction (DETERMINISTIC pattern matching only).
//!
//! PURE: this submodule holds NO [`runtime::Core`] handle and touches no matter
//! data — it operates on plain `&str` already read THROUGH the core by the
//! [`crate::Inbox`] engine. That keeps it independently unit-testable, exactly
//! like redaction's pure `candidates`/`redact_detail` pass.
//!
//! ## Honest framing (load-bearing — read before trusting an extracted date)
//!
//! - **DETERMINISTIC pattern matching ONLY.** No model / LLM / ML / NLP date
//!   library — anywhere (CLAUDE.md non-negotiable). The implementation is a
//!   hand-rolled scanner over a FIXED set of date shapes plus a linear-time
//!   [`regex`] pass (the `regex` crate has no backtracking — no ReDoS; empty
//!   patterns are never used).
//! - **A proposed deadline is NEVER auto-trusted.** This RULE PROPOSES a due
//!   date; a human confirms it. A missed/misparsed deadline is a malpractice
//!   risk, so the dashboard must surface the date as a *suggestion the lawyer
//!   accepts or edits*, never as an authoritative calendar entry. The
//!   [`DuePrecision`] below is the honesty knob: it records HOW sure the rule is
//!   so the UI can show "explicit date" very differently from "vague: ASAP".
//! - **Relative dates need an anchor.** "next Friday" / "in 14 days" resolve
//!   against a caller-supplied reference instant (the message's received time),
//!   passed in deterministically — never `now()` read ambiently (that would make
//!   the same input parse differently run-to-run and break determinism).
//!
//! ## Numeric-date convention (DRAWN FROM THE SYSTEM REGION, load-bearing)
//!
//! A bare numeric date like `03/04/2026` is region-dependent. The convention is
//! NOT a user-facing toggle and NOT hard-coded here: the HOST resolves it from the
//! operating system's REGIONAL setting (`DD/MM` vs `MM/DD`) at the edge and INJECTS
//! it as a [`DateConvention`] (user decision: "just draw from the system"). The
//! parser itself stays pure/deterministic — it only takes the resolved convention as
//! a parameter (so the same input + convention always parse identically, per the
//! determinism non-negotiable; the impurity of reading the OS lives at the host
//! boundary). [`DateConvention::DayFirst`] is the FALLBACK when the host can't
//! determine the region. The rules (for the resolved convention):
//!   - If exactly ONE field is `> 12` it can only be the day, so the date is
//!     UNAMBIGUOUS regardless of convention → [`DuePrecision::ExactDate`] when the
//!     ordering AGREES with the convention; if the ordering DISAGREES with the
//!     convention (e.g. month-first text under a day-first setting) it is still
//!     resolvable but flagged [`DuePrecision::Day`] (reduced precision — the lawyer
//!     should eyeball it).
//!   - If BOTH fields are `<= 12` the date is IRREDUCIBLY AMBIGUOUS (e.g.
//!     `03/04/2026` is "3 Apr OR 4 Mar?"). We DO NOT silently resolve it: it is
//!     surfaced as [`DuePrecision::Ambiguous`], carrying BOTH candidate days so the
//!     presentation can render it as a QUESTION ("3 Apr or 4 Mar?"), never a
//!     confident single guess. (The configured convention orders the candidates so
//!     the *first* listed is the convention's reading, but neither is auto-trusted.)
//!
//! ISO (`YYYY-MM-DD`) and spelled-month (`3 March 2026`) forms are unambiguous and
//! parse at [`DuePrecision::ExactDate`], independent of [`DateConvention`].

use regex::Regex;
use std::sync::OnceLock;

/// A minimal, model-free instant the parser anchors relative dates against:
/// epoch MILLISECONDS (UTC), as supplied by the message's received time. Kept as
/// a plain `i64` (no date crate) so the dependency surface stays
/// deterministic/pure; the scanner converts to/from a civil date with pure
/// integer arithmetic (see [`civil_from_days`] / [`days_from_civil`]).
///
/// It is the message's RECEIVED time, supplied by the caller, so "next Friday"
/// resolves deterministically against a fixed reference rather than an ambient
/// `now()`.
pub type Anchor = i64;

/// Milliseconds per day — the conversion factor between [`Anchor`] (epoch-ms) and
/// the civil-date day count used for relative-date arithmetic.
const MS_PER_DAY: i64 = 86_400_000;

/// The numeric-date ordering convention for `D/M/YYYY`-shaped dates where neither
/// field forces a reading. The HOST resolves this from the OPERATING SYSTEM's
/// regional setting and injects it (user decision: "just draw from the system" — NOT
/// a user-facing toggle). DETERMINISTIC: by the time it reaches the parser it is a
/// fixed value, not an ambient guess (see the module-level docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DateConvention {
    /// `DD/MM/YYYY` — UK / Singapore / Commonwealth. The FALLBACK default when the
    /// host cannot determine the system region.
    #[default]
    DayFirst,
    /// `MM/DD/YYYY` — US.
    MonthFirst,
}

/// How precisely a due date was pinned down — the HONESTY knob the dashboard uses
/// to show an explicit deadline very differently from a vague "ASAP" or a genuinely
/// AMBIGUOUS numeric date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuePrecision {
    /// An UNAMBIGUOUS explicit calendar date (`2026-03-15`, `15 March 2026`, or a
    /// numeric date whose day field is `> 12` AND whose ordering agrees with the
    /// configured [`DateConvention`]).
    ExactDate,
    /// A date resolved to a specific DAY but with reduced confidence: a numeric date
    /// written in the OPPOSITE order to the configured [`DateConvention`] but still
    /// forced unambiguous by a field `> 12` (e.g. `04/25/2026` under DayFirst). We
    /// resolved a single day; the lawyer should eyeball the format.
    Day,
    /// An IRREDUCIBLY AMBIGUOUS numeric date — BOTH fields `<= 12`, so it could be
    /// either reading (e.g. `03/04/2026` = "3 Apr OR 4 Mar?"). `due_at` carries the
    /// configured convention's reading as a PLACEHOLDER, but it is NOT auto-trusted:
    /// [`DueDate::ambiguous_alt`] carries the OTHER candidate day so the presentation
    /// renders it as a QUESTION, never a confident single guess. The lawyer MUST
    /// disambiguate before anything relies on it.
    Ambiguous,
    /// A relative date resolved against the [`Anchor`] (`next Friday`, `in 14
    /// days`, `end of next week`) — to a specific day, but inferred from a
    /// relative expression rather than stated outright.
    Relative,
    /// A vague urgency cue with no resolvable date (`ASAP`, `urgent`, `by EOD`).
    /// `due_at` is `None`.
    Vague,
    /// No due-date signal found at all. `due_at` is `None`.
    ///
    /// HONEST FRAMING (load-bearing): "no date DETECTED" does NOT mean "no
    /// deadline". A legally-arising deadline (a limitation period, a deadline stated
    /// in an attachment, or one that arises from the law rather than written as a
    /// date) is NOT caught by this scanner. The worklist carries an explicit
    /// [`crate::Caveat`] saying so — never let a `None` be read as "nothing is due".
    None,
}

/// The outcome of a parse: an optional resolved due instant plus how sure we are.
///
/// `due_at`, when `Some`, is an [`Anchor`] (epoch-ms, UTC) at 00:00 of the
/// resolved civil day. The TIME-OF-DAY is not meaningful (we resolve to a day);
/// the dashboard should render the day, and the precision tells it how to caveat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueDate {
    /// The resolved due instant (epoch-ms at 00:00 UTC of the due day), if one was
    /// extracted. `None` for [`DuePrecision::Vague`] / [`DuePrecision::None`]. For
    /// [`DuePrecision::Ambiguous`] this is the configured-convention reading — a
    /// PLACEHOLDER, not auto-trusted (see [`ambiguous_alt`](DueDate::ambiguous_alt)).
    pub due_at: Option<Anchor>,
    /// How precisely it was pinned (the honesty knob — see [`DuePrecision`]).
    pub precision: DuePrecision,
    /// For [`DuePrecision::Ambiguous`] ONLY: the OTHER candidate day (epoch-ms at
    /// 00:00 UTC), i.e. the reading you get by swapping day/month. `None` for every
    /// other precision. The presentation uses `due_at` + this to render the date as
    /// a QUESTION ("3 Apr or 4 Mar?") instead of a silent guess.
    pub ambiguous_alt: Option<Anchor>,
    /// How many date-bearing spans were detected in the text BEYOND the one `due_at`
    /// shows (so `0` = "the shown date is the only date here"; `>= 1` = "there is at
    /// least one OTHER date in the text the shown one does not represent").
    ///
    /// SAFETY (M1 silent-miss fix, load-bearing): the scanner shows ONE date by
    /// PRECEDENCE order, but a body like "the order was sealed 2026-01-05; file your
    /// appeal by next Friday." has TWO distinct date spans — the shown (past, ISO)
    /// one and the REAL ("next Friday") deadline that is silently dropped. A confident
    /// single shown date would imply it is the only date. This count makes the
    /// "more than one date here" FACT impossible to miss: a non-zero value drives a
    /// visible "⚠ multiple dates detected — review" surface. We deliberately do NOT
    /// heuristically pick the "operative" date (a heuristic could itself be wrong) —
    /// we keep the deterministic precedence choice AND surface the ambiguity. A
    /// genuinely identical date written twice is NOT double-counted (distinct spans
    /// only; see [`count_distinct_date_spans`]).
    pub additional_dates: usize,
}

impl DueDate {
    /// Whether MORE THAN ONE distinct date-bearing span was detected in the text, so
    /// the single shown date must NOT be read as the only date present (M1). The
    /// presentation surfaces this as a visible "multiple dates detected — review"
    /// caveat/badge. Always `false` when no date was detected at all.
    pub fn multiple_dates_detected(&self) -> bool {
        self.additional_dates > 0
    }
}

impl DueDate {
    /// The "no due-date signal" result. Used as the safe default so a caller never
    /// fabricates a deadline.
    ///
    /// HONEST FRAMING: this is "no date DETECTED", which is NOT "no deadline" — see
    /// [`DuePrecision::None`] and the worklist's [`crate::Caveat`].
    pub fn none() -> Self {
        Self {
            due_at: None,
            precision: DuePrecision::None,
            ambiguous_alt: None,
            additional_dates: 0,
        }
    }

    /// A vague urgency cue (no resolvable day).
    fn vague() -> Self {
        Self {
            due_at: None,
            precision: DuePrecision::Vague,
            ambiguous_alt: None,
            additional_dates: 0,
        }
    }

    /// A resolved due day at `days` (days since the Unix epoch) with `precision`.
    /// (Never [`DuePrecision::Ambiguous`] — that carries two candidates; use
    /// [`ambiguous`](DueDate::ambiguous).)
    ///
    /// `additional_dates` starts at `0`; [`extract_due_date`] fills in the real
    /// "other distinct date spans" count after the shown date is chosen (M1).
    fn at_days(days: i64, precision: DuePrecision) -> Self {
        Self {
            due_at: Some(days * MS_PER_DAY),
            precision,
            ambiguous_alt: None,
            additional_dates: 0,
        }
    }

    /// An irreducibly-ambiguous numeric date carrying BOTH candidate days. `primary`
    /// is the configured-convention reading (the placeholder `due_at`); `alt` is the
    /// swapped reading. Surfaced at [`DuePrecision::Ambiguous`] so the presentation
    /// asks the question rather than silently committing to one.
    ///
    /// NOTE (M1): a single ambiguous numeric date is ONE distinct date SPAN — its two
    /// readings are not two separate dates in the text. So `additional_dates` is the
    /// real count of OTHER spans, filled in by [`extract_due_date`]; the two readings
    /// of this one span never inflate it.
    fn ambiguous(primary_days: i64, alt_days: i64) -> Self {
        Self {
            due_at: Some(primary_days * MS_PER_DAY),
            precision: DuePrecision::Ambiguous,
            ambiguous_alt: Some(alt_days * MS_PER_DAY),
            additional_dates: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure civil-date arithmetic (Howard Hinnant's algorithms — integer-only, no
// crate, no I/O). Proleptic Gregorian; valid across the ranges we care about.
// ---------------------------------------------------------------------------

/// Days since the Unix epoch (1970-01-01) for a civil `(y, m, d)`.
/// `m` in `1..=12`, `d` in `1..=31`. Pure integer math (no overflow for sane
/// years). Reference: Hinnant, "chrono-Compatible Low-Level Date Algorithms".
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The civil `(y, m, d)` for `z` days since the Unix epoch. Inverse of
/// [`days_from_civil`]. Pure integer math. Used by the test suite to decode a
/// resolved `due_at` back to a civil date for assertions (the engine itself only
/// ever produces day counts, never decodes them — so this is test-only).
///
/// NOTE (shared algorithm): `timesheet::epoch_ms_to_ymd` inlines this SAME Hinnant
/// inverse in production — keep the two in sync if either changes.
#[cfg(test)]
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
                                                   // Hinnant: the civil year is `y + 1` when the (March-based) month is Jan/Feb.
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// The day-of-week for a day count (`0 = Sunday .. 6 = Saturday`). The Unix epoch
/// 1970-01-01 was a Thursday (`= 4`).
fn weekday_from_days(z: i64) -> i64 {
    // (z + 4) mod 7, with a non-negative result.
    ((z % 7) + 4 + 7) % 7
}

/// The day count of the [`Anchor`]'s civil day (floor division so a negative
/// epoch still floors to the start of its day).
fn anchor_days(anchor: Anchor) -> i64 {
    anchor.div_euclid(MS_PER_DAY)
}

/// Validate a civil `(y, m, d)` (correct days-per-month incl. leap Feb). Rejects
/// an impossible date like `2026-02-30` so the scanner never proposes a bogus day.
fn valid_civil(y: i64, m: i64, d: i64) -> bool {
    if !(1..=12).contains(&m) || d < 1 {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    d <= dim
}

/// Map a (lowercased) English month name/abbreviation to `1..=12`.
fn month_number(name: &str) -> Option<i64> {
    let m = match name {
        "jan" | "january" => 1,
        "feb" | "february" => 2,
        "mar" | "march" => 3,
        "apr" | "april" => 4,
        "may" => 5,
        "jun" | "june" => 6,
        "jul" | "july" => 7,
        "aug" | "august" => 8,
        "sep" | "sept" | "september" => 9,
        "oct" | "october" => 10,
        "nov" | "november" => 11,
        "dec" | "december" => 12,
        _ => return None,
    };
    Some(m)
}

/// Map a (lowercased) weekday name/abbreviation to `0=Sunday .. 6=Saturday`.
fn weekday_number(name: &str) -> Option<i64> {
    let w = match name {
        "sunday" | "sun" => 0,
        "monday" | "mon" => 1,
        "tuesday" | "tue" | "tues" => 2,
        "wednesday" | "wed" => 3,
        "thursday" | "thu" | "thur" | "thurs" => 4,
        "friday" | "fri" => 5,
        "saturday" | "sat" => 6,
        _ => return None,
    };
    Some(w)
}

// ---------------------------------------------------------------------------
// Compiled scanners. Each regex is a FIXED literal pattern (linear-time, no
// backtracking, never empty); compiled once via `OnceLock`. `expect` documents
// the static-pattern-always-compiles invariant (same discipline as redaction).
// ---------------------------------------------------------------------------

/// ISO `YYYY-MM-DD`.
fn re_iso() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b").expect("static iso date pattern compiles")
    })
}

/// Spelled month: `3 March 2026`, `3rd March 2026`, or `March 3, 2026`.
fn re_spelled() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?ix)
            \b(?:
              (\d{1,2})(?:st|nd|rd|th)?\s+([A-Za-z]{3,9})\s+(\d{4})    # 3 March 2026
              |
              ([A-Za-z]{3,9})\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})  # March 3, 2026
            )\b",
        )
        .expect("static spelled-month pattern compiles")
    })
}

/// Numeric `D/M/YYYY` or `D-M-YYYY` (also `D.M.YYYY`). Convention: DAY-FIRST.
fn re_numeric() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})\b")
            .expect("static numeric date pattern compiles")
    })
}

/// "in N days" / "within N days" / "N days from now".
fn re_in_days() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:within|in)\s+(\d{1,3})\s+days?\b")
            .expect("static in-N-days pattern compiles")
    })
}

/// "<intent> (this|next)? <weekday>" — a weekday gated on a DEADLINE-INTENT cue.
///
/// SAFETY (M2 false-positive fix): the previous pattern made EVERY prefix optional,
/// so a BARE weekday anywhere ("Let's grab lunch Friday", "Monday's all-hands recap",
/// a quoted "On Monday, Jane wrote:") fabricated a phantom `Relative` deadline. A
/// weekday is now a deadline ONLY when introduced by a deadline-intent cue
/// (`by` / `before` / `due` / `no later than`, or `on` followed by the weekday); a
/// weekday with NO intent cue is NOT a deadline. The intent cue is REQUIRED (no
/// longer optional), and the `(this|next)?` qualifier may sit between the cue and the
/// weekday ("due next Friday", "by this Monday"). Still a FIXED literal alternation —
/// linear-time, no backtracking, never empty.
fn re_weekday() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:by|before|due|no later than|on)\s+(this|next)?\s*(sunday|monday|tuesday|wednesday|thursday|friday|saturday|sun|mon|tue|tues|wed|thu|thur|thurs|fri|sat)\b",
        )
        .expect("static weekday pattern compiles")
    })
}

/// "end of (this|next) week".
fn re_eow() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bend of (this|next) week\b").expect("static end-of-week pattern compiles")
    })
}

/// Bare urgency cues with no resolvable day.
fn re_vague() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(asap|urgent(?:ly)?|immediately|end of day|eod|cob)\b")
            .expect("static vague-cue pattern compiles")
    })
}

/// Extract a proposed due date from `text` (subject + body), resolving any
/// relative date against `anchor` (the message's received time) and any ambiguous
/// numeric date against the EXPLICIT `convention`. PURE + DETERMINISTIC.
///
/// The scanner tries the date shapes in PRECEDENCE order (most precise first) and
/// returns the FIRST that matches:
/// 1. ISO `YYYY-MM-DD` → [`DuePrecision::ExactDate`]
/// 2. Spelled month (`3 March 2026` / `March 3, 2026`) → `ExactDate`
/// 3. Numeric `D/M/YYYY` (against the configured [`DateConvention`]; see the module
///    docs) → `ExactDate` if forced unambiguous AND agreeing with the convention,
///    [`DuePrecision::Day`] if forced unambiguous but the OPPOSITE order, or
///    [`DuePrecision::Ambiguous`] (carrying BOTH candidates) if irreducibly ambiguous
/// 4. Relative (`in N days`, `next Friday`, `end of next week`) →
///    [`DuePrecision::Relative`]
/// 5. A bare urgency cue (`ASAP`, `EOD`) → [`DuePrecision::Vague`] (no day)
/// 6. Nothing → [`DueDate::none`] (= "no date DETECTED", NOT "no deadline")
///
/// A parsed date is a PROPOSAL for human confirmation, NOT a committed diary entry
/// (see the module's honest framing). An impossible date (e.g. `2026-02-30`) is
/// REJECTED (skipped), never proposed.
///
/// ## Multiple dates (M1 silent-miss fix, load-bearing)
///
/// The shown date is chosen by PRECEDENCE (most precise first), but a body can carry
/// SEVERAL distinct date-bearing spans — e.g. "the order was sealed 2026-01-05; file
/// your appeal by next Friday." has a past ISO date AND the real "next Friday"
/// deadline. Returning ONLY the precedence winner would let a confident single shown
/// date imply it is the only date, SILENTLY DROPPING the others. So this counts the
/// DISTINCT date spans (see [`count_distinct_date_spans`]) and records
/// [`DueDate::additional_dates`] = (distinct spans − 1) on the returned result. A
/// non-zero value drives a visible "⚠ multiple dates detected — review" surface. We
/// keep the deterministic precedence choice for the SHOWN date (no fragile "operative
/// date" heuristic) but make the ambiguity impossible to miss.
pub fn extract_due_date(text: &str, anchor: Anchor, convention: DateConvention) -> DueDate {
    let mut due = parse_first_date(text, anchor, convention);
    // M1: count OTHER distinct date spans beyond the one we show. When no date was
    // detected at all there is nothing to over-claim, so leave it 0.
    if due.precision != DuePrecision::None {
        let distinct = count_distinct_date_spans(text);
        due.additional_dates = distinct.saturating_sub(1);
    }
    due
}

/// The PRECEDENCE-ordered single-date parse (the SHOWN date), unchanged in behaviour
/// from the original: ISO → spelled → numeric → relative → vague → none. Split out so
/// [`extract_due_date`] can layer the multiple-dates count (M1) on top without
/// touching the precedence logic.
fn parse_first_date(text: &str, anchor: Anchor, convention: DateConvention) -> DueDate {
    if let Some(d) = parse_iso(text) {
        return d;
    }
    if let Some(d) = parse_spelled(text) {
        return d;
    }
    if let Some(d) = parse_numeric(text, convention) {
        return d;
    }
    if let Some(d) = parse_relative(text, anchor) {
        return d;
    }
    if re_vague().is_match(text) {
        return DueDate::vague();
    }
    DueDate::none()
}

/// Count the DISTINCT date-bearing SPANS in `text` (M1). A "date-bearing span" is a
/// byte range matched by one of the resolvable date SHAPES — ISO, spelled-month,
/// numeric (any reading that yields a valid civil date), "in N days", "end of
/// (this|next) week", or an intent-gated weekday — whose content actually resolves
/// (an impossible date like `13/14/2026` or `2026-02-30` is NOT counted). Vague
/// urgency cues ("ASAP") are NOT dates and are excluded.
///
/// DETERMINISTIC + char-boundary-safe: it works on regex match BYTE spans (which the
/// `regex` crate guarantees fall on char boundaries) and never indexes into `text`.
/// Overlapping/touching spans are MERGED so the same physical date matched by more
/// than one shape (or one ambiguous numeric date with two readings) counts ONCE; an
/// identical date written twice in two places counts as TWO distinct spans (they are
/// two separate spans in the text). NO clock / RNG / model.
///
/// The numeric-date `convention` deliberately does NOT enter the count: it only
/// orders the two readings of an already-resolvable span, never whether a span
/// resolves — so the count is the same under either convention (and stays
/// deterministic). Hence this takes no convention parameter.
fn count_distinct_date_spans(text: &str) -> usize {
    let mut spans: Vec<(usize, usize)> = Vec::new();

    // ISO: count a span only when it is a valid civil date.
    for c in re_iso().captures_iter(text) {
        let (Ok(y), Ok(m), Ok(d)) = (
            c[1].parse::<i64>(),
            c[2].parse::<i64>(),
            c[3].parse::<i64>(),
        ) else {
            continue;
        };
        if valid_civil(y, m, d) {
            let whole = c.get(0).expect("group 0 always present");
            spans.push((whole.start(), whole.end()));
        }
    }

    // Spelled month (either order): count only valid civil dates.
    for c in re_spelled().captures_iter(text) {
        let parsed = if let (Some(d), Some(mon), Some(y)) = (c.get(1), c.get(2), c.get(3)) {
            (
                d.as_str().parse::<i64>().ok(),
                month_number(&mon.as_str().to_ascii_lowercase()),
                y.as_str().parse::<i64>().ok(),
            )
        } else if let (Some(mon), Some(d), Some(y)) = (c.get(4), c.get(5), c.get(6)) {
            (
                d.as_str().parse::<i64>().ok(),
                month_number(&mon.as_str().to_ascii_lowercase()),
                y.as_str().parse::<i64>().ok(),
            )
        } else {
            (None, None, None)
        };
        if let (Some(d), Some(m), Some(y)) = parsed {
            if valid_civil(y, m, d) {
                let whole = c.get(0).expect("group 0 always present");
                spans.push((whole.start(), whole.end()));
            }
        }
    }

    // Numeric: count a span when AT LEAST one reading is a valid civil date (an
    // ambiguous date is ONE span; an impossible 13/14/2026 is not counted). The
    // convention does not change WHETHER a span resolves, only which reading is
    // primary — so the count is convention-stable (see the fn doc).
    for c in re_numeric().captures_iter(text) {
        let (Ok(f1), Ok(f2), Ok(y)) = (
            c[1].parse::<i64>(),
            c[2].parse::<i64>(),
            c[3].parse::<i64>(),
        ) else {
            continue;
        };
        let day_first_ok = f2 <= 12 && valid_civil(y, f2, f1);
        let month_first_ok = f1 <= 12 && valid_civil(y, f1, f2);
        if day_first_ok || month_first_ok {
            let whole = c.get(0).expect("group 0 always present");
            spans.push((whole.start(), whole.end()));
        }
    }

    // Relative shapes (each is always resolvable to a span; no validity gate needed):
    // "in N days", "end of (this|next) week", and the intent-gated weekday.
    for re in [re_in_days(), re_eow(), re_weekday()] {
        for m in re.find_iter(text) {
            spans.push((m.start(), m.end()));
        }
    }

    merge_overlapping_count(&mut spans)
}

/// Sort `spans` and count how many DISTINCT (non-overlapping, non-touching) groups
/// remain after merging any that overlap or abut. Pure integer logic — no panics, no
/// allocation beyond the in-place sort. Used by [`count_distinct_date_spans`] so one
/// physical date matched by multiple shapes counts once.
fn merge_overlapping_count(spans: &mut [(usize, usize)]) -> usize {
    if spans.is_empty() {
        return 0;
    }
    spans.sort_unstable();
    let mut count = 1usize;
    let mut cur_end = spans[0].1;
    for &(start, end) in &spans[1..] {
        if start > cur_end {
            // A gap -> a genuinely separate date span.
            count += 1;
            cur_end = end;
        } else {
            // Overlapping or touching -> same physical date; extend the running span.
            cur_end = cur_end.max(end);
        }
    }
    count
}

/// Parse an ISO `YYYY-MM-DD` (first valid match). `ExactDate`.
fn parse_iso(text: &str) -> Option<DueDate> {
    for c in re_iso().captures_iter(text) {
        let y: i64 = c[1].parse().ok()?;
        let m: i64 = c[2].parse().ok()?;
        let d: i64 = c[3].parse().ok()?;
        if valid_civil(y, m, d) {
            return Some(DueDate::at_days(
                days_from_civil(y, m, d),
                DuePrecision::ExactDate,
            ));
        }
    }
    None
}

/// Parse a spelled-month date in either order (first valid match). `ExactDate`.
fn parse_spelled(text: &str) -> Option<DueDate> {
    for c in re_spelled().captures_iter(text) {
        // Branch A: `D Month YYYY`; Branch B: `Month D, YYYY`.
        let parsed = if let (Some(d), Some(mon), Some(y)) = (c.get(1), c.get(2), c.get(3)) {
            (
                d.as_str().parse::<i64>().ok(),
                month_number(&mon.as_str().to_ascii_lowercase()),
                y.as_str().parse::<i64>().ok(),
            )
        } else if let (Some(mon), Some(d), Some(y)) = (c.get(4), c.get(5), c.get(6)) {
            (
                d.as_str().parse::<i64>().ok(),
                month_number(&mon.as_str().to_ascii_lowercase()),
                y.as_str().parse::<i64>().ok(),
            )
        } else {
            (None, None, None)
        };
        if let (Some(d), Some(m), Some(y)) = parsed {
            if valid_civil(y, m, d) {
                return Some(DueDate::at_days(
                    days_from_civil(y, m, d),
                    DuePrecision::ExactDate,
                ));
            }
        }
    }
    None
}

/// Parse a numeric `D/M/YYYY` against the EXPLICIT `convention` (see module docs),
/// surfacing irreducible ambiguity as [`DuePrecision::Ambiguous`] (carrying BOTH
/// candidates) rather than silently committing to one reading.
///
/// `f1`/`f2` are the two leading fields as written. We never trust position blindly:
///   - If exactly ONE field is `> 12`, it can only be the day, so the date is FORCED
///     unambiguous regardless of convention. We resolve it and mark `ExactDate` when
///     the resulting order AGREES with `convention`, else `Day` (reduced precision).
///   - If BOTH fields are `<= 12`, BOTH the day-first and month-first readings are
///     plausible. If both are VALID civil dates the date is irreducibly `Ambiguous`
///     (we carry both candidates, ordered so `due_at` is the convention's reading).
///     If only ONE reading is a valid civil date, that one is FORCED, so we resolve
///     it `ExactDate`/`Day` like the single-`>12` case (no false ambiguity).
fn parse_numeric(text: &str, convention: DateConvention) -> Option<DueDate> {
    for c in re_numeric().captures_iter(text) {
        let f1: i64 = c[1].parse().ok()?;
        let f2: i64 = c[2].parse().ok()?;
        let y: i64 = c[3].parse().ok()?;

        // The two possible readings, as (day, month):
        //   day-first  -> day = f1, month = f2
        //   month-first-> day = f2, month = f1
        let day_first_ok = f2 <= 12 && valid_civil(y, f2, f1); // month=f2, day=f1
        let month_first_ok = f1 <= 12 && valid_civil(y, f1, f2); // month=f1, day=f2

        match (day_first_ok, month_first_ok) {
            // Only the day-first reading is a real date -> FORCED day-first.
            (true, false) => {
                let prec = match convention {
                    DateConvention::DayFirst => DuePrecision::ExactDate,
                    DateConvention::MonthFirst => DuePrecision::Day,
                };
                return Some(DueDate::at_days(days_from_civil(y, f2, f1), prec));
            }
            // Only the month-first reading is a real date -> FORCED month-first.
            (false, true) => {
                let prec = match convention {
                    DateConvention::MonthFirst => DuePrecision::ExactDate,
                    DateConvention::DayFirst => DuePrecision::Day,
                };
                return Some(DueDate::at_days(days_from_civil(y, f1, f2), prec));
            }
            // BOTH readings are valid -> irreducibly ambiguous. Carry both, ordered
            // so `due_at` is the configured convention's reading and `ambiguous_alt`
            // is the other. NEVER silently resolve to one.
            (true, true) => {
                let day_first_days = days_from_civil(y, f2, f1);
                let month_first_days = days_from_civil(y, f1, f2);
                // If the two readings collapse to the SAME day (e.g. 05/05/2026),
                // it is not actually ambiguous in OUTCOME — resolve it ExactDate.
                if day_first_days == month_first_days {
                    return Some(DueDate::at_days(day_first_days, DuePrecision::ExactDate));
                }
                let (primary, alt) = match convention {
                    DateConvention::DayFirst => (day_first_days, month_first_days),
                    DateConvention::MonthFirst => (month_first_days, day_first_days),
                };
                return Some(DueDate::ambiguous(primary, alt));
            }
            // Neither reading is a real date (e.g. 13/14/2026) -> skip this match.
            (false, false) => continue,
        }
    }
    None
}

/// Parse a relative expression against `anchor` (most specific first): "in N
/// days", "end of (this|next) week", then a weekday. `Relative` precision.
fn parse_relative(text: &str, anchor: Anchor) -> Option<DueDate> {
    let today = anchor_days(anchor);

    // "in N days" / "within N days".
    if let Some(c) = re_in_days().captures(text) {
        if let Ok(n) = c[1].parse::<i64>() {
            return Some(DueDate::at_days(today + n, DuePrecision::Relative));
        }
    }

    // "end of (this|next) week" — resolve to the upcoming Friday (this week) or
    // the Friday of next week. A pragmatic legal default (the working week's end).
    if let Some(c) = re_eow().captures(text) {
        let next = c[1].eq_ignore_ascii_case("next");
        let friday = next_weekday_on_or_after(today, 5); // this week's Friday (or today if Fri)
        let day = if next { friday + 7 } else { friday };
        return Some(DueDate::at_days(day, DuePrecision::Relative));
    }

    // "(this|next)? <weekday>" — "this Friday" / "next Friday" / bare "Friday".
    if let Some(c) = re_weekday().captures(text) {
        let qualifier = c.get(1).map(|m| m.as_str().to_ascii_lowercase());
        if let Some(target) = weekday_number(&c[2].to_ascii_lowercase()) {
            let day = match qualifier.as_deref() {
                // "next <weekday>" = the next occurrence STRICTLY AFTER today.
                // CONVENTION (documented): we take the EARLIEST reasonable reading
                // (next occurrence after today), NOT "the weekday of next calendar
                // week" — "next Friday"/"next Monday" is colloquially ambiguous, and
                // for a deadline the safer interpretation is the earlier date (never
                // push a deadline later than the author may have meant). So from a
                // Friday, "next Friday" is +7; "next Monday" is the coming Monday.
                Some("next") => next_weekday_on_or_after(today + 1, target),
                // "this <weekday>" or bare "<weekday>" = the next occurrence
                // on-or-after today (a deadline "by Friday" means the coming
                // Friday, including today if today is Friday).
                _ => next_weekday_on_or_after(today, target),
            };
            return Some(DueDate::at_days(day, DuePrecision::Relative));
        }
    }

    None
}

/// The first day `>= from` whose weekday is `target` (`0=Sun..6=Sat`).
fn next_weekday_on_or_after(from: i64, target: i64) -> i64 {
    let cur = weekday_from_days(from);
    let delta = ((target - cur) % 7 + 7) % 7;
    from + delta
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed reference instant: 2026-06-19 (a Friday) at 00:00 UTC, as epoch-ms.
    /// All relative-date tests resolve against THIS, never the wall clock.
    fn anchor_2026_06_19() -> Anchor {
        days_from_civil(2026, 6, 19) * MS_PER_DAY
    }

    /// Helper: the civil `(y, m, d)` a `DueDate`'s `due_at` resolves to.
    fn due_civil(d: &DueDate) -> (i64, i64, i64) {
        civil_from_days(d.due_at.expect("a resolved day") / MS_PER_DAY)
    }

    /// Helper: the civil `(y, m, d)` an ambiguous `DueDate`'s `ambiguous_alt`
    /// (the OTHER candidate) resolves to.
    fn alt_civil(d: &DueDate) -> (i64, i64, i64) {
        civil_from_days(d.ambiguous_alt.expect("an alternate candidate day") / MS_PER_DAY)
    }

    /// Most tests use the pilot-default day-first convention; helper to keep them terse.
    fn day_first(text: &str, anchor: Anchor) -> DueDate {
        extract_due_date(text, anchor, DateConvention::DayFirst)
    }

    #[test]
    fn civil_round_trips() {
        // Sanity on the pure date arithmetic + the anchor's weekday.
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2026, 6, 19), (2026, 12, 31)] {
            let z = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(z), (y, m, d));
        }
        // 2026-06-19 is a Friday (weekday 5).
        assert_eq!(weekday_from_days(days_from_civil(2026, 6, 19)), 5);
        // 1970-01-01 was a Thursday (weekday 4).
        assert_eq!(weekday_from_days(0), 4);
    }

    #[test]
    fn iso_date_is_exact() {
        let d = day_first("Please file by 2026-03-03.", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 3, 3));
    }

    #[test]
    fn spelled_month_day_first_is_exact() {
        let d = day_first(
            "Hearing on 3 March 2026 at the registry.",
            anchor_2026_06_19(),
        );
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 3, 3));
    }

    #[test]
    fn spelled_month_month_first_is_exact() {
        let d = day_first("Reply due March 3, 2026 sharp.", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 3, 3));
    }

    #[test]
    fn spelled_month_with_ordinal_suffix() {
        let d = day_first("by 3rd March 2026", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 3, 3));
    }

    #[test]
    fn numeric_irreducibly_ambiguous_surfaces_both_candidates() {
        // SAFETY (DANGER fix #2): 03/04/2026 with both fields <= 12 is genuinely
        // ambiguous ("3 Apr OR 4 Mar?"). We must NOT silently resolve it. Under the
        // day-first convention `due_at` carries the convention's reading (3 Apr) but
        // the precision is Ambiguous and `ambiguous_alt` carries the OTHER candidate
        // (4 Mar), so the UI can render it as a question.
        let d = day_first("respond by 03/04/2026", anchor_2026_06_19());
        assert_eq!(
            d.precision,
            DuePrecision::Ambiguous,
            "both fields <= 12 -> AMBIGUOUS, never a silent guess"
        );
        assert_eq!(
            due_civil(&d),
            (2026, 4, 3),
            "day-first reading is the primary candidate (3 Apr)"
        );
        assert_eq!(
            alt_civil(&d),
            (2026, 3, 4),
            "month-first reading is carried as the alternate (4 Mar)"
        );
    }

    #[test]
    fn numeric_ambiguous_orders_candidates_by_convention() {
        // The SAME text under MonthFirst flips which reading is primary vs alternate
        // (still Ambiguous — the convention orders, it does not auto-trust).
        let d = extract_due_date(
            "respond by 03/04/2026",
            anchor_2026_06_19(),
            DateConvention::MonthFirst,
        );
        assert_eq!(d.precision, DuePrecision::Ambiguous);
        assert_eq!(
            due_civil(&d),
            (2026, 3, 4),
            "month-first reading is the primary candidate (4 Mar)"
        );
        assert_eq!(
            alt_civil(&d),
            (2026, 4, 3),
            "day-first reading is carried as the alternate (3 Apr)"
        );
    }

    #[test]
    fn numeric_ambiguous_same_outcome_is_not_ambiguous() {
        // 05/05/2026: both readings collapse to the same day -> not ambiguous in
        // OUTCOME, so resolve it ExactDate (no spurious question, no alt candidate).
        let d = day_first("by 05/05/2026", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 5, 5));
        assert!(
            d.ambiguous_alt.is_none(),
            "a day==month date carries no alternate"
        );
    }

    #[test]
    fn numeric_forced_day_first_when_only_that_reading_is_valid() {
        // 25/03/2026: 25 > 12 -> can only be a day in first position -> FORCED
        // day-first. Agrees with the day-first convention -> ExactDate (no ambiguity).
        let d = day_first("filed on 25/03/2026", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 3, 25));
        assert!(d.ambiguous_alt.is_none());
    }

    #[test]
    fn numeric_month_first_text_under_day_first_convention_is_flagged_day() {
        // 04/25/2026: 25 > 12 -> FORCED month-first (only that reading is a real
        // date). Under the DAY-first convention the order DISAGREES, so resolve the
        // single forced day (25 Apr) but flag reduced precision Day, never Exact.
        let d = day_first("due 04/25/2026", anchor_2026_06_19());
        assert_eq!(
            d.precision,
            DuePrecision::Day,
            "format disagrees with convention -> reduced precision"
        );
        assert_eq!(due_civil(&d), (2026, 4, 25));
    }

    #[test]
    fn numeric_month_first_text_under_month_first_convention_is_exact() {
        // The SAME 04/25/2026 under the MONTH-first convention now AGREES with the
        // format -> ExactDate (a US firm reads its own dates confidently).
        let d = extract_due_date(
            "due 04/25/2026",
            anchor_2026_06_19(),
            DateConvention::MonthFirst,
        );
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 4, 25));
    }

    #[test]
    fn numeric_one_reading_invalid_is_forced_not_ambiguous() {
        // 13/02/2026: 13 > 12 forces day-first (13 Feb). The month-first reading
        // (month=13) is impossible, so this is NOT ambiguous -> a single resolved day.
        let d = day_first("by 13/02/2026", anchor_2026_06_19());
        assert_ne!(
            d.precision,
            DuePrecision::Ambiguous,
            "an impossible alt reading is not ambiguity"
        );
        assert_eq!(due_civil(&d), (2026, 2, 13));
    }

    #[test]
    fn impossible_date_is_not_proposed() {
        // 2026-02-30 is not a real day -> no ISO match; nothing else matches.
        let d = day_first("by 2026-02-30", anchor_2026_06_19());
        assert_eq!(
            d,
            DueDate::none(),
            "an impossible date must not be fabricated"
        );
    }

    #[test]
    fn within_n_days_is_relative_to_anchor() {
        // Anchored at 2026-06-19; +14 days = 2026-07-03.
        let d = day_first("please revert within 14 days", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Relative);
        assert_eq!(due_civil(&d), (2026, 7, 3));
    }

    #[test]
    fn by_next_friday_is_relative() {
        // Anchor 2026-06-19 is itself a Friday. "next Friday" = 2026-06-26.
        let d = day_first("get this to me by next Friday", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Relative);
        assert_eq!(due_civil(&d), (2026, 6, 26));
    }

    #[test]
    fn bare_weekday_is_the_coming_occurrence() {
        // Anchor 2026-06-19 (Fri). "by Monday" = the coming Monday 2026-06-22.
        let d = day_first("please sign by Monday", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Relative);
        assert_eq!(due_civil(&d), (2026, 6, 22));
    }

    #[test]
    fn this_weekday_includes_today() {
        // Anchor is a Friday; "by Friday" (this/bare) resolves to today.
        let d = day_first("turn this around by Friday", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Relative);
        assert_eq!(due_civil(&d), (2026, 6, 19));
    }

    #[test]
    fn end_of_next_week_is_relative() {
        // Anchor 2026-06-19 (Fri). End of THIS week = today's Friday 06-19; end of
        // NEXT week = 06-26.
        let d = day_first("aim for end of next week", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Relative);
        assert_eq!(due_civil(&d), (2026, 6, 26));
    }

    #[test]
    fn vague_cue_has_no_resolved_day() {
        let d = day_first("need this ASAP please", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Vague);
        assert!(d.due_at.is_none(), "a vague cue resolves no specific day");
    }

    #[test]
    fn no_signal_returns_none() {
        let d = day_first("just confirming receipt, thanks", anchor_2026_06_19());
        assert_eq!(d, DueDate::none());
    }

    #[test]
    fn exact_date_beats_a_vague_cue_in_the_same_text() {
        // Precedence: an explicit date wins over a co-occurring "urgent".
        let d = day_first("URGENT — file by 2026-03-03", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 3, 3));
    }

    #[test]
    fn parsing_is_deterministic() {
        let a = day_first("by 03/04/2026 and within 14 days", anchor_2026_06_19());
        let b = day_first("by 03/04/2026 and within 14 days", anchor_2026_06_19());
        assert_eq!(a, b, "same input + anchor -> identical parse");
    }

    // ---- M1: multiple-dates detection (the SILENT-MISS fix) ----------------

    #[test]
    fn multiple_distinct_dates_set_the_flag() {
        // SAFETY (M1): the order was sealed (a PAST ISO date) AND the real "next
        // Friday" deadline. Precedence shows the ISO date FIRST, but the body has TWO
        // distinct date spans — the count must flag it so the single shown date is
        // never read as the only date here.
        let d = day_first(
            "The order was sealed 2026-01-05; file your appeal by next Friday.",
            anchor_2026_06_19(),
        );
        // The shown (precedence) date is still the ISO one (deterministic choice).
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(due_civil(&d), (2026, 1, 5));
        // ...but the OTHER date is surfaced, never dropped.
        assert!(
            d.multiple_dates_detected(),
            "two distinct dates -> flag set"
        );
        assert_eq!(
            d.additional_dates, 1,
            "exactly one OTHER date beyond the shown one"
        );
    }

    #[test]
    fn single_date_does_not_set_the_flag() {
        // A body with ONE date must NOT raise the multiple-dates flag.
        let d = day_first("Please file by 2026-03-03.", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert!(!d.multiple_dates_detected(), "one date -> no flag");
        assert_eq!(d.additional_dates, 0);
    }

    #[test]
    fn three_distinct_dates_count_two_additional() {
        // Three distinct date spans across three shapes -> two beyond the shown one.
        let d = day_first(
            "Sealed 2026-01-05, hearing on 3 March 2026, respond within 14 days.",
            anchor_2026_06_19(),
        );
        assert!(d.multiple_dates_detected());
        assert_eq!(
            d.additional_dates, 2,
            "two OTHER dates beyond the shown ISO date"
        );
    }

    #[test]
    fn one_physical_date_is_not_double_counted() {
        // A single ISO date is matched only by the ISO shape -> ONE span, no flag,
        // even though the scanner runs every shape over the text.
        let d = day_first("hearing 2026-03-03", anchor_2026_06_19());
        assert_eq!(d.additional_dates, 0, "one physical date counts once");
        assert!(!d.multiple_dates_detected());
    }

    #[test]
    fn ambiguous_numeric_date_is_one_span_not_two() {
        // An ambiguous numeric date has TWO readings but is ONE span in the text — it
        // must not, by itself, raise the multiple-dates flag (the ambiguity is already
        // surfaced via DuePrecision::Ambiguous + ambiguous_alt).
        let d = day_first("respond by 03/04/2026", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Ambiguous);
        assert_eq!(
            d.additional_dates, 0,
            "one ambiguous date span is not two dates"
        );
        assert!(!d.multiple_dates_detected());
    }

    #[test]
    fn no_date_never_sets_the_flag() {
        // "no date detected" can never claim multiple dates.
        let d = day_first("just confirming receipt, thanks", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::None);
        assert!(!d.multiple_dates_detected());
        assert_eq!(d.additional_dates, 0);
    }

    #[test]
    fn impossible_extra_date_is_not_counted() {
        // A real date plus an IMPOSSIBLE one (13/14/2026 resolves to nothing) -> only
        // ONE date span, so no spurious multiple-dates flag.
        let d = day_first("file by 2026-03-03 (ref 13/14/2026)", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::ExactDate);
        assert_eq!(
            d.additional_dates, 0,
            "an impossible date is not a date span"
        );
    }

    #[test]
    fn multiple_dates_count_is_deterministic() {
        let text = "Sealed 2026-01-05; appeal by next Friday; pay within 14 days.";
        let a = day_first(text, anchor_2026_06_19());
        let b = day_first(text, anchor_2026_06_19());
        assert_eq!(a, b, "the multiple-dates count is deterministic");
        assert_eq!(a.additional_dates, 2);
    }

    // ---- M2(a): a bare weekday needs a deadline-intent cue ------------------

    #[test]
    fn bare_weekday_with_no_intent_cue_is_not_a_deadline() {
        // SAFETY (M2): "Let's grab lunch Friday" is NOT a deadline — no intent cue.
        let d = day_first("Let's grab lunch Friday", anchor_2026_06_19());
        assert_eq!(
            d,
            DueDate::none(),
            "a bare weekday with no intent cue is not a deadline"
        );
    }

    #[test]
    fn possessive_weekday_recap_is_not_a_deadline() {
        // "Monday's all-hands recap" — a bare weekday, no intent cue -> no deadline.
        let d = day_first("Monday's all-hands recap", anchor_2026_06_19());
        assert_eq!(d, DueDate::none(), "a possessive weekday is not a deadline");
    }

    #[test]
    fn weekday_with_by_or_due_intent_is_still_detected() {
        // The legitimate deadline shapes still resolve.
        let by = day_first("please file by Friday", anchor_2026_06_19());
        assert_eq!(
            by.precision,
            DuePrecision::Relative,
            "\"by Friday\" is a deadline"
        );
        assert_eq!(
            due_civil(&by),
            (2026, 6, 19),
            "by Friday = the coming Friday (today)"
        );

        let due = day_first("response due Monday", anchor_2026_06_19());
        assert_eq!(
            due.precision,
            DuePrecision::Relative,
            "\"due Monday\" is a deadline"
        );
        assert_eq!(
            due_civil(&due),
            (2026, 6, 22),
            "due Monday = the coming Monday"
        );

        let before = day_first("submit before Tuesday", anchor_2026_06_19());
        assert_eq!(
            before.precision,
            DuePrecision::Relative,
            "\"before Tuesday\" is a deadline"
        );

        let nlt = day_first("revert no later than Wednesday", anchor_2026_06_19());
        assert_eq!(
            nlt.precision,
            DuePrecision::Relative,
            "\"no later than Wednesday\" is a deadline"
        );
    }

    #[test]
    fn next_weekday_qualifier_after_intent_cue_still_works() {
        // The qualifier may sit between the intent cue and the weekday.
        let d = day_first("get this to me by next Friday", anchor_2026_06_19());
        assert_eq!(d.precision, DuePrecision::Relative);
        assert_eq!(
            due_civil(&d),
            (2026, 6, 26),
            "by next Friday = +7 from the Friday anchor"
        );
    }
}
