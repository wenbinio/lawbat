// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Lever 2 — context-proximity scoring + the context-required recognizer rows.
//!
//! This module holds the DATA + the pure helpers for Lever 2:
//!
//! - the OPT-IN [`ContextRecognizer`] rows (undashed SSN, DOB, age>89, generic
//!   account/MRN, role-context person name) — each a regex shape + an optional structural
//!   validator + a keyword LEXICON + a default tier (+ an optional tier ceiling), exactly
//!   mirroring the `packs` data-row philosophy
//!   ([`LocaleRecognizer`](crate::packs::LocaleRecognizer)); adding another is one row;
//! - [`keyword_in_window`] — the deterministic, char-boundary-safe proximity probe that
//!   reports whether any lexicon keyword appears near a matched span (and how near).
//!
//! ## The LOAD-BEARING invariant (read before touching this)
//!
//! Context is purely ADDITIVE. These recognizers are OFF by default; when enabled they
//! can ONLY add a candidate (never suppress one). The additive-only GATE lives in
//! [`crate::RedactionEngine::merged_spans`] (a finalization filter on merged spans), NOT
//! here — this module only supplies the rows + the proximity primitive it consults.
//!
//! ## Determinism / no-clock (CLAUDE.md non-negotiable)
//!
//! Every function here is a pure function of (span position, window text, fixed
//! lexicons). There is NO `SystemTime`, NO current date, NO ML. In particular the
//! age>89 recognizer matches an EXPLICIT age number (90..=129) near an age keyword — it
//! does NOT infer age from a birth YEAR (that would need "today" = non-deterministic).
//! Birth-year DOB is covered by the DOB recognizer instead.
//!
//! ## Confidentiality (CLAUDE.md non-negotiable)
//!
//! Nothing here logs a matched value or the surrounding cleartext. The proximity probe
//! returns only a boolean + a distance bucket; the row carries OUR constant `name`
//! label (`ctx:<row>`), never document text. The audit breakdown records per-tier
//! COUNTS only (see [`crate::Confidence`]).

use crate::packs::us::ssn_valid;
use crate::{ceil_char_boundary_fwd, floor_char_boundary_back, is_word_char, Confidence};

/// How far (in CHARACTERS, each side of the matched span) the proximity probe scans for
/// a context keyword.
///
/// RATIFIED WIDENING (the finance round): 40 → 48, DECOUPLED from the review-snippet
/// radius ([`crate::CONTEXT_CHARS`] stays 40 — what a reviewer sees is a presentation
/// choice, what corroborates a candidate is a detection choice; they no longer have to
/// agree). The motivating verified miss: in `…Devraj Chandramohan held 900,000 ordinary
/// shares. No other director held shares.` the cue `director` begins at exactly +41
/// chars from the span end — one char past the old window — so the name leaked
/// post-apply. 48 is the MODEST widening that closes the observed clause-length gap
/// (a short sentence tail: ` held 900,000 ordinary shares. No other ` is 41 chars);
/// going larger needs measurement to back it (volume cost measured for 48 on the QA
/// corpus + both SG prospectuses — see the ratification commit). A keyword may now sit
/// slightly outside the snippet a reviewer sees; the CAREFUL-review routing of every
/// window-corroborated broad row is unchanged ([`CLOSE_BYTES`] = 20 untouched, so the
/// High/quick-confirm promotion distance did NOT widen).
pub(crate) const CONTEXT_WINDOW_CHARS: usize = 48;

/// The "close" threshold (in BYTES) for the High rung of a context-required match:
/// a keyword whose nearest edge is within this many bytes of the match corroborates
/// strongly. 20 bytes ≈ the same-clause distance ("SSN: 123456789").
///
/// TIGHTENED (the two-tier-routing deliverable; `to-read/redaction.LEVER2-CONTEXT-CONFIDENCE.md` §4): the
/// proximity probe now requires a STRICT byte gap — there is no longer a "same line"
/// OR-arm. Previously ANY same-line in-window keyword graded `Close` (→ rung-3 High); that
/// was deliberately permissive while the tier was purely advisory. Now that the tier is
/// LOAD-BEARING (a High candidate is auto-pre-accepted by [`crate::Selection::quick_confirm`]),
/// a same-line-but-far keyword grading High would mean an over-eager auto-accept, so
/// `Close` requires `gap ≤ CLOSE_BYTES` regardless of line. A same-line keyword more than
/// 20 bytes away now grades [`Proximity::Window`] → the candidate is Medium → it routes to
/// Tier-2 careful review (it still FIRES; only its tier — and thus its routing — changes).
pub(crate) const CLOSE_BYTES: usize = 20;

/// How near a context keyword sits to a matched span. The deterministic result of
/// [`keyword_in_window`]; drives the context rung of the confidence ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proximity {
    /// No lexicon keyword anywhere in the ±[`CONTEXT_WINDOW_CHARS`] window.
    None,
    /// A keyword is in-window but its nearest edge is more than [`CLOSE_BYTES`] bytes
    /// from the match (whether or not it is on the same line — proximity is byte-distance
    /// only since the `Close` tightening).
    Window,
    /// A keyword's nearest edge is within [`CLOSE_BYTES`] bytes of the match.
    Close,
}

/// One CONTEXT-REQUIRED recognizer, as DATA (the Lever-2 analogue of a
/// [`LocaleRecognizer`](crate::packs::LocaleRecognizer)). A static row gives:
///
/// - `name` — the bare row name; the audit/attribution label is the `ctx:`-namespaced
///   form `ctx:<name>` (e.g. `ctx:ssn-undashed`), assembled in `RedactionEngine::base`;
/// - `pattern` — the (static, known-good, linear-time) regex shape;
/// - `validate` — an OPTIONAL structural validator run on each raw match (e.g. the SSN
///   structural rules), exactly like [`crate::TaggedPattern`]'s slot; `None` = format-only;
/// - `lexicon` — the keyword set this recognizer is gated on (matched case-insensitively,
///   on word boundaries, within the window); and
/// - `default_tier` — the tier a surviving match gets when a keyword is in-window but not
///   close. (Checksum-validated rows would set this higher; the four format-only rows use
///   [`Confidence::Medium`], promoted to High by a CLOSE keyword — see the ladder.)
///
/// Adding a fifth context recognizer later = one row in [`CONTEXT_RECOGNIZERS`] (and, if it
/// needs a structural validator, a `fn`). No `Recognizer`/`RecognizerKey` churn — the
/// generic [`crate::Recognizer::Context`] variant carries every row's namespaced label.
#[derive(Debug, Clone, Copy)]
pub struct ContextRecognizer {
    /// The bare row name (e.g. `ssn-undashed`). The namespaced label is `ctx:<name>`.
    pub(crate) name: &'static str,
    /// The (static, known-good) regex source for the shape. Linear-time (no ReDoS).
    pub(crate) pattern: &'static str,
    /// Optional structural validator (e.g. SSN area/group/serial rules). `None` =
    /// format-only. Mirrors [`crate::TaggedPattern::validate`].
    pub(crate) validate: Option<fn(&str) -> bool>,
    /// The keyword lexicon this row is gated on (case-insensitive, word-boundary,
    /// within the window). OUR constant strings — never document text.
    pub(crate) lexicon: &'static [&'static str],
    /// The tier a surviving match gets with an in-window (but not close) keyword.
    pub(crate) default_tier: Confidence,
    /// OPTIONAL tier CEILING. `Some(cap)` clamps this row's computed confidence at `cap`
    /// (via `min`) in `RedactionEngine::confidence_for`, so even a CLOSE keyword cannot
    /// promote it above `cap`. Used by the deliberately FP-prone `role-name` row to pin it
    /// to the CAREFUL review tier (`Some(Confidence::Medium)` → never quick-confirm).
    /// `None` (every checksum/structural ctx row) = no ceiling, byte-identical to before.
    pub(crate) cap_tier: Option<Confidence>,
    /// How many WHITESPACE-ONLY lines the proximity probe may reach ACROSS when looking for
    /// this row's keyword (see [`keyword_in_window`]). `0` (every checksum/structural ctx
    /// row) = the fixed ±[`CONTEXT_WINDOW_CHARS`] window, byte-identical to before this
    /// field existed. `>0` extends the window past up to that many whitespace-only lines
    /// REGARDLESS of their length — the fix for a PDF-reconstructed heading/name layout
    /// where a positioning gap becomes a long run of spaces on its own line
    /// (`Solicitors to the Managers\n<many spaces>\nTan Peng Chin LLC`), pushing the role
    /// heading out of the fixed char window. Set `>0` ONLY on the deliberately FP-prone
    /// `role-name` row; recall-first widening on the SAFE side (still capped at CAREFUL
    /// review by `cap_tier`, never quick-confirm).
    pub(crate) blank_line_tolerance: usize,
    /// ROLE-LIST CONTINUATION reach (Round-3 fix A). How many CONSECUTIVE NAME-SHAPED lines
    /// the backward proximity probe may cross to reach this row's keyword. `0` (every row
    /// except `role-name`) = no name-line crossing, byte-identical to before this field.
    /// `>0` lets a name DEEP in a director/manager list reach the role heading that sits
    /// ABOVE the run of preceding name lines: a heading fires the FIRST name(s) within the
    /// fixed char window, but the CONTINUATION names (the 3rd, 4th, … of a multi-name list)
    /// fall outside it and SURVIVED. The probe now steps up across up to this many
    /// name-shaped lines (each a 2–6-token uppercase-initial run, tolerating a trailing
    /// all-caps org suffix like `LLC`/`Pte`) to find the heading; it STOPS at the first
    /// non-name-shaped line (the heading, a blank, or ordinary prose) and includes it in the
    /// window. HARD-BOUNDED at this count so the widening cannot run away, and only crosses
    /// NAME-shaped lines (ordinary prose lines break the chain — a capitalized run buried in
    /// body text never reaches a distant heading). Set `>0` ONLY on the deliberately FP-prone
    /// `role-name` row; still capped at CAREFUL review by `cap_tier`, never quick-confirm.
    /// FP posture: over-captures a Capitalized ORG/prose run that happens to sit in a name
    /// list under a heading — the SAFE side per the crate PRINCIPLE (a miss is the leak).
    pub(crate) name_line_run_back: usize,
    /// LEADING-SPAN CORROBORATION (Round-3 fix B). When `true`, a role keyword CONSUMED as
    /// the LEADING token(s) of the matched capitalized run itself corroborates the candidate
    /// — not only a keyword in the surrounding window. `false` (every row except `role-name`)
    /// = window-only, byte-identical to before this field.
    ///
    /// ROOT CAUSE it fixes: in a TWO-COLUMN / inline layout
    /// (`Solicitors to the Managers<many spaces>Tan Peng Chin LLC` on ONE line), the greedy
    /// capitalized-run scanner starts the run at the heading's own `Managers` token and
    /// consumes `Managers   Tan Peng Chin` as a SINGLE span. The ordinary keyword gate
    /// EXCLUDES the matched span (so a keyword inside the match never self-corroborates), so
    /// with no OTHER role keyword in-window the whole span was SUPPRESSED — the firm/person
    /// name SURVIVED. With this flag, a role keyword at the HEAD of the run satisfies the
    /// gate, so the run FIRES and the name is removed (redacting the extra heading token is
    /// the SAFE side; capped at CAREFUL review, never quick-confirm). Restricted to the
    /// LEADING position (not anywhere in the span) to target the heading-consumed shape.
    pub(crate) corroborate_from_leading_span: bool,
}

/// The OPT-IN context-required recognizer rows (Lever 2). All format-only and
/// gated on a lexicon; the structural SSN validator is the only `validate` (it reuses
/// the US pack's [`ssn_valid`], so the undashed-SSN row honors the SAME 000/666/9xx
/// area, 00 group, 0000 serial, all-identical, known-fake structural rules as the
/// dashed US SSN locale recognizer — no second copy of the rules).
///
/// ENABLE via [`crate::RedactionEngineBuilder::context_recognizers`] /
/// [`crate::ContextRecognizers`]; OFF by default (the candidate set is byte-identical to
/// before unless explicitly opted in).
pub(crate) const CONTEXT_RECOGNIZERS: &[ContextRecognizer] = &[
    // CTX-1 UNDASHED SSN — 9 contiguous digits, no separators (the dashed/spaced form
    // is the US locale `us:ssn` row). The bare-9 shape is hopelessly broad on its own
    // (every 9-digit run), so it is GATED on an SSN keyword AND structurally validated
    // (reusing `ssn_valid`, which strips separators → 9 digits → the SSA structural
    // rules; a contiguous 9-digit run has no separators, so the mixed-separator branch
    // never fires). The `\b…\b` keeps it from firing inside a longer digit run.
    ContextRecognizer {
        name: "ssn-undashed",
        pattern: r"\b\d{9}\b",
        validate: Some(ssn_valid),
        lexicon: &["ssn", "social security", "social security number"],
        default_tier: Confidence::Medium,
        cap_tier: None,
        blank_line_tolerance: 0,
        name_line_run_back: 0,
        corroborate_from_leading_span: false,
    },
    // CTX-2 DOB — a numeric date token (`d/m/y` or `d-m-y`, 1–2 digit day/month, 2–4
    // digit year), a month-NAME form ("12 January 2026" / "January 12, 2026", ordinal
    // suffixes allowed: "14th March 1998" — round 4, Mechanism B), a DOTTED numeric form
    // (`14.03.1998`, either day/month order), or an ISO form (`1998-03-14`) — gated on a
    // date-of-birth keyword. NO clock: this matches the date TOKEN near a DOB keyword; a
    // birth-year alone (no day/month) is NOT inferred to an age here. The alternation is
    // bounded (no unbounded repetition), so it is linear-time.
    //
    // PLAUSIBILITY BOUNDS (round 4): the month-name forms bound the DAY at 01–31 (so the
    // ordinal negative `32nd March` never fires; the leading `\b` already stops a start
    // inside `32nd`), and the NEW dotted/ISO forms bound day 01–31, month 01–12, year
    // 19xx/20xx (so `99.99.9999` stays un-matched). The FIRST alternate (`d/m/y`,`d-m-y`)
    // is deliberately UNTOUCHED — it accepts both day-first and month-first orders today
    // and tightening it would drop existing recall.
    //
    // WHY dotted/ISO matter (the field evidence): both shapes were previously covered
    // only as `phone` MISLABELS — reviewed as phones, and in the PDF path a cross-line
    // phone is line-scope-DROPPED, so the date could silently leak there. As `ctx:dob`
    // they ride the ctx sanction lane (and the merge's date-not-phone attribution fixup
    // labels the span `ctx:dob` — see `merged_spans`).
    ContextRecognizer {
        name: "dob",
        pattern: concat!(
            r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            r"|\b(?:0?[1-9]|[12]\d|3[01])(?i:st|nd|rd|th)?\s+(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+\d{2,4}\b",
            r"|\b(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(?:0?[1-9]|[12]\d|3[01])(?i:st|nd|rd|th)?,?\s+\d{2,4}\b",
            r"|\b(?:0?[1-9]|[12]\d|3[01])\.(?:0?[1-9]|1[0-2])\.(?:19|20)\d{2}\b",
            r"|\b(?:0?[1-9]|1[0-2])\.(?:0?[1-9]|[12]\d|3[01])\.(?:19|20)\d{2}\b",
            r"|\b(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])\b",
        ),
        validate: None,
        lexicon: &["dob", "d.o.b", "date of birth", "born"],
        default_tier: Confidence::Medium,
        cap_tier: None,
        blank_line_tolerance: 0,
        name_line_run_back: 0,
        corroborate_from_leading_span: false,
    },
    // CTX-3 AGE > 89 — an EXPLICIT age number 90..=129 near an age keyword. The pattern
    // `\b(?:9\d|1[0-2]\d)\b` matches 90–99 and 100–129. DELIBERATELY no birth-year
    // inference and NO clock: an age is the lawyer-relevant HIPAA Safe-Harbor signal
    // (ages over 89 must be aggregated); a DOB/birth-year is the DOB row's job. The
    // keyword gate stops "invoice 95" / "Form 1-129" from flagging.
    ContextRecognizer {
        name: "age-over-89",
        pattern: r"\b(?:9\d|1[0-2]\d)\b",
        validate: None,
        lexicon: &["age", "years old", "y/o", "yo", "aged"],
        default_tier: Confidence::Medium,
        cap_tier: None,
        blank_line_tolerance: 0,
        name_line_run_back: 0,
        corroborate_from_leading_span: false,
    },
    // CTX-4 GENERIC ACCOUNT / MRN — a bounded 6–12 char digit/alnum run that contains at
    // least one DIGIT, near an account/medical-record keyword. The `regex` crate has NO
    // lookahead, so "contains ≥1 digit AND total length 6–12" is split: the PATTERN
    // matches a word-bounded alnum run with ≥1 digit (`[A-Za-z0-9]*\d[A-Za-z0-9]*`,
    // linear-time), and the structural [`acct_len_valid`] VALIDATOR enforces the 6–12
    // length (so a 6-letter WORD near "account" never flags — it has no digit — and a
    // long order number is bounded out). The broadest shape, so it is strictly
    // keyword-gated AND the gate plus the length+digit validator supply the precision.
    ContextRecognizer {
        name: "account-mrn",
        pattern: r"\b[A-Za-z0-9]*\d[A-Za-z0-9]*\b",
        validate: Some(acct_len_valid),
        lexicon: &[
            "account",
            "acct",
            "mrn",
            "medical record",
            "record no",
            "record number",
        ],
        default_tier: Confidence::Medium,
        cap_tier: None,
        blank_line_tolerance: 0,
        name_line_run_back: 0,
        corroborate_from_leading_span: false,
    },
    // CTX-5 ROLE-CONTEXT PERSON NAME — a 2–4-token Capitalized name run (`Lee Wai Keong`,
    // `Tan Peng Ho`) gated on a ROLE heading/label keyword in-window. This closes the
    // real-world miss where a director/manager NAME LIST survived (no honorific, not a
    // TERM): the honorific-only `Recognizer::Name` heuristic never fires on `Lee Wai
    // Keong`, but a role heading ("Managers", "Directors", "Chief Executive Officer") sits
    // within the ±window (INCLUDING across the following line in a list layout, since the
    // proximity probe scans a byte window that spans `\n`). DELIBERATELY FP-PRONE (it also
    // flags a Capitalized ORG like `Sumitomo Mitsui Trust Bank` in the same list — fine to
    // over-flag per the crate PRINCIPLE; over-flagging is the SAFE side, a miss is the
    // leak). The review layer + candidate GROUPING absorb the noise; the row is capped at
    // the CAREFUL review tier (`cap_tier: Some(Medium)`) so it can NEVER quick-confirm.
    //
    // The window is BOUNDED two ways so it cannot run away: the pattern matches at most 4
    // Capitalized tokens joined by SPACES/TABS only (`[ \t]+`, never `\n` — one visual line
    // per candidate, so a multi-name list yields ONE candidate PER NAME, cleaner for
    // grouping), and the keyword gate uses the fixed ±`CONTEXT_WINDOW_CHARS` proximity
    // window. `validate: None` (format-only, recall-first). Audit label `ctx:role-name`.
    //
    // NO WRAPPED-NAME ARM, DELIBERATELY (the wrapped-name round, empirically checked):
    // this row's PRIMARY layout is a single-token HEADING above a name list
    // (`Managers\nLee Wai Keong\n…`), which is SHAPE-INDISTINGUISHABLE from a name
    // wrapped at its first gap (`Idris\nBeaumond` — no lookbehind exists to tell a
    // line-initial heading token from a mid-sentence pre-wrap fragment). A wrap-tolerant
    // arm here JOINED the heading into the first name (`Managers\nLee Wai Keong` as ONE
    // span), degrading the per-name spans + grouping and inverting the keyword-gate
    // semantics on exactly the layout the row exists for. Wrapped names remain covered by
    // the machinery that CAN anchor them (the honorific heuristic, the trailing-role list
    // pass, the anchored-name pass — all single-wrap tolerant); a wrapped bare name under
    // a role heading stays an HONEST LIMITATION of this row.
    //
    // HONEST LIMITATION (the LIST layout is the target): the keyword gate excludes the
    // matched span itself, so a role word sitting INLINE as the FIRST token of the run on
    // the SAME line (`Director Lee Wai Keong`, single line) is ABSORBED into the run and,
    // with no OTHER keyword in-window, that span is gated out. The heading-then-list layout
    // (`Directors\nLee Wai Keong\n…`, the actual reported miss) keeps the keyword on its own
    // line OUTSIDE the run, so it fires. Inline `Role Name` prose stays a reviewer / TERM /
    // name-expansion job.
    ContextRecognizer {
        name: "role-name",
        // Round 3 (Mechanism 1): a NON-FINAL token may be a dotted single-letter INITIAL
        // (`John W. Thompson` — the interior initial broke the old two-token shape and the
        // name was MISSED while its sibling was caught); the FINAL token stays a real word
        // (a name never ends in an initial; also keeps the trailing `\b` on a word char).
        // Round 5: a token may be a HYPHENATED COMPOUND (`Fox-Geen`, `Müller-Tan`) — an
        // internal `-` directly joining two Capitalized parts is ONE surname token (the
        // Circle-table leak: `Jeremy Fox-Geen` captured as `Jeremy Fox`, applying left a
        // readable `-Geen` FRAGMENT). A spaced hyphen (`Fox - Geen`) or a digit range
        // (`2019-2024`) can never join: the `-` must abut `\p{Lu}\p{L}+` on both sides.
        // Round 6 (Mechanism 2): interior lowercase PARTICLES (`van`/`von`/`de`/`bin`/…)
        // may sit between capitalized tokens (`Hendrik van Riel` — previously only the
        // honorific form `Mr Van Riel` was caught), at most two per gap (bounded).
        pattern: r"\b(?:(?:\p{Lu}\p{L}+(?:-\p{Lu}\p{L}+)*|\p{Lu}\.)[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}){1,3}\p{Lu}\p{L}+(?:-\p{Lu}\p{L}+)*\b",
        validate: None,
        lexicon: &[
            "director",
            "directors",
            "manager",
            "managers",
            "chairman",
            "chairperson",
            "chair",
            "chief executive officer",
            "chief financial officer",
            "chief operating officer",
            "chief information officer",
            "chief",
            "officer",
            "ceo",
            "cfo",
            "coo",
            "cio",
            "trustee",
            "trustees",
            "partner",
            "partners",
            "secretary",
            "signatory",
            "signatories",
            "name",
            // FINANCE-LABEL cue vocabulary (the finance-corpus recall round). The old
            // list required a role/"Name"-bearing label, so `Account Holder :` /
            // `Customer:` / `Primary Cardholder:` / `Trader:` / `Authorised by:` /
            // `Attn:` produced ZERO candidates while `Employee Name :` fired — a
            // systematic person-name miss on bank/card/trade/payment documents. These
            // rows are the standard finance/insurance party labels; each is a data-row
            // addition to the SAME deliberately-FP-prone, careful-review-capped,
            // NON-seeding row (`cap_tier` Medium; excluded from every propagation seed
            // predicate per review fix 1 — a new cue can never amplify document-wide).
            "account holder",
            "accountholder",
            "customer",
            "cardholder", // also matches inside "Primary Cardholder" (word-boundary)
            "trader",
            "shareholder",
            "shareholders",
            "beneficiary",
            "beneficiaries",
            "attn",
            "attention",
            "authorised by",
            "authorized by",
            "borrower",
            "guarantor",
            "lender",
            "remitter",
            "payee",
            "payer",
            "applicant",
            "insured",
            "policyholder",
            "contact", // `Please contact Gwendolyn Peart-Sims (+65 …)` — the verified miss
        ],
        default_tier: Confidence::Medium,
        // CEILING at Medium — a role heading immediately before a name is CLOSE, which
        // would otherwise promote to High/quick-confirm; capping keeps it CAREFUL-review.
        cap_tier: Some(Confidence::Medium),
        // Reach the keyword window ACROSS up to 2 whitespace-only lines: a PDF-reconstructed
        // heading/name layout puts a positioning gap on its OWN line as a long run of spaces
        // (`Managers\n<many spaces>\nTan Peng Chin LLC`), which the fixed char window would
        // otherwise exclude. Bounded at 2 so the widening cannot run away; the row stays
        // capped at CAREFUL review.
        blank_line_tolerance: 2,
        // ROLE-LIST CONTINUATION (fix A): reach the heading ACROSS up to 6 consecutive
        // name-shaped lines, so a name DEEP in a director/manager list (the 4th, 5th, … name,
        // beyond the fixed char window from the heading) still corroborates. Bounded at 6 and
        // crosses ONLY name-shaped lines (prose breaks the chain).
        name_line_run_back: 6,
        // LEADING-SPAN CORROBORATION (fix B): a two-column heading+name on ONE line
        // (`Solicitors to the Managers   Tan Peng Chin LLC`) makes the run scanner swallow the
        // heading's `Managers` token as the run's HEAD; the window gate (which excludes the
        // match) then found no keyword and SUPPRESSED it. A leading role keyword now
        // corroborates so the run fires and the name is removed.
        corroborate_from_leading_span: true,
    },
    // CTX-6 WRAP-SPLIT PHONE (round 3, Mechanism 2) — a phone-like digit run WRAPPED across
    // exactly ONE line break (`enquiries: 0800\n917 2112.`), gated on a TELECOM keyword
    // in-window. The general phone recognizer is DELIBERATELY newline-blind (a cross-line
    // numeric join is exactly the HIGH-1 NAV-table flood the PDF line-scope filter exists
    // to kill), so the wrapped form of a REAL number was missed while its unwrapped twin
    // was caught. This row closes that gap WITHOUT touching the general recognizer:
    //   - the PATTERN REQUIRES the single line break (an unwrapped number is already the
    //     general phone row's job — this row is additive, never overlapping semantics);
    //   - the keyword GATE (the existing additive-only ctx machinery) kills the NAV-table
    //     shape: `145.90\n12 3456` with no telecom keyword in-window is NEVER a candidate;
    //   - the digit-count VALIDATOR (7–15 digits) bounds it to phone-plausible runs;
    //   - the `ctx:` label rides the EXISTING PDF line-scope sanction lane for context
    //     rows, so the wrapped span survives the PDF path like every ctx row.
    // Capped at the CAREFUL review tier (cap_tier Medium — a wrapped digit run near a
    // telecom keyword is likely a phone but never quick-confirm-grade). OFF by default
    // (all ctx rows are opt-in); `{"context":true}` enables it.
    ContextRecognizer {
        name: "phone-wrapped",
        pattern: r"\+?\d[-\d\t ().]*\d[ \t]*\r?\n[ \t]*\d[-\d\t ().]*\d(?:[ \t]*(?:x|ext\.?)[ \t]*\d+)?",
        validate: Some(phone_digit_count_valid),
        lexicon: &[
            "tel",
            "telephone",
            "phone",
            "fax",
            "freephone",
            "hotline",
            "enquiries",
            "enquiry",
            // SG MOBILE vocabulary (review M2, folded in alongside the always-on cued
            // phone arm's lexicon): the local labels for a handphone number. `m:` keeps
            // its colon — the colon IS the anchor; a bare one-letter `m` would be noise.
            "mobile",
            "hp",
            "handphone",
            "cell",
            "m:",
            // NOT "call": it collides with financial-table prose (call option, capital
            // call, callable) and a wrapped digit pair nearby would then ride the ctx PDF
            // sanction lane as a false phone (review finding F2). The remaining keywords
            // do not occur as ordinary financial-table words.
        ],
        default_tier: Confidence::Medium,
        cap_tier: Some(Confidence::Medium),
        blank_line_tolerance: 0,
        name_line_run_back: 0,
        corroborate_from_leading_span: false,
    },
];

/// CTX-6 structural validator: the matched wrapped run carries a phone-plausible DIGIT
/// count (7–15 — national significant numbers are 7+, E.164 caps at 15). Bounds the broad
/// wrapped shape so a two-digit fragment pair or a long serial dump never qualifies. Pure,
/// deterministic, no allocation of matter data.
fn phone_digit_count_valid(s: &str) -> bool {
    let digits = s.chars().filter(char::is_ascii_digit).count();
    (7..=15).contains(&digits)
}

/// CTX-4 structural validator: the matched run is 6–12 chars long. (The PATTERN already
/// guarantees ≥1 digit + word boundaries; this only bounds the length, which the
/// lookahead-free regex can't.) Pure, deterministic, no allocation of matter data.
fn acct_len_valid(s: &str) -> bool {
    (6..=12).contains(&s.chars().count())
}

/// Return the context recognizer row for a `ctx:`-namespaced label (e.g.
/// `ctx:ssn-undashed`), or `None` if the label is not a context row. Used by the
/// finalization gate to recover a span's lexicon from its primary recognizer's label.
pub(crate) fn row_for_label(label: &str) -> Option<&'static ContextRecognizer> {
    let bare = label.strip_prefix("ctx:")?;
    CONTEXT_RECOGNIZERS.iter().find(|r| r.name == bare)
}

/// Extend a before-window start `base_lo` BACKWARD across up to `k` WHITESPACE-ONLY lines,
/// returning the new (char-boundary) window start `<= base_lo`. `k == 0` returns `base_lo`
/// unchanged (byte-identical to the fixed window). Only kicks in when `base_lo` itself sits
/// inside a whitespace-only (partial) line — i.e. the fixed char window ran into a blank gap
/// — in which case it skips up to `k` whitespace-only lines and includes the CONTENT
/// (heading) line just beyond them. A line is "blank" iff every char between its `\n`
/// bounds is [`char::is_whitespace`] (so a long positioning-gap run of spaces counts,
/// regardless of length). Deterministic; every returned offset lands on a char boundary
/// (all cuts are at ASCII `\n` bounds or `base_lo`).
fn extend_before_across_blank_lines(text: &str, base_lo: usize, k: usize) -> usize {
    if k == 0 {
        return base_lo;
    }
    let mut lo = base_lo;
    let mut budget = k;
    loop {
        // Start of the line `lo` currently sits in (byte after the previous '\n', or 0).
        let line_start = text[..lo].rfind('\n').map(|p| p + 1).unwrap_or(0);
        // The (partial) line content up to `lo` — never contains a '\n' (line_start is the
        // last '\n' before lo), so a whitespace check is a single-line test.
        let seg = &text[line_start..lo];
        if !seg.chars().all(char::is_whitespace) {
            // A CONTENT line: stop. Include its start ONLY if we already crossed a blank
            // line (so the heading beyond the blanks is in-window); else leave base_lo.
            return if budget < k { line_start } else { base_lo };
        }
        if line_start == 0 {
            return 0; // the whole prefix up to lo is whitespace
        }
        if budget == 0 {
            return lo.min(base_lo); // no budget to cross another blank line
        }
        // Cross this whitespace-only line: step onto the '\n' ending the preceding line.
        budget -= 1;
        lo = line_start - 1;
    }
}

/// Forward mirror of [`extend_before_across_blank_lines`]: extend an after-window end
/// `base_hi` FORWARD across up to `k` whitespace-only lines (a heading BELOW the name,
/// separated by blank lines). Returns a char-boundary offset `>= base_hi`; `k == 0` returns
/// it unchanged.
fn extend_after_across_blank_lines(text: &str, base_hi: usize, k: usize) -> usize {
    if k == 0 {
        return base_hi;
    }
    let mut hi = base_hi;
    let mut budget = k;
    loop {
        // End of the line `hi` sits in = the next '\n' at/after `hi` (or end of text).
        let line_end = match text[hi..].find('\n') {
            Some(p) => hi + p,
            None => return text.len(), // no further '\n' — the rest of the text is in-window
        };
        let seg = &text[hi..line_end];
        if !seg.chars().all(char::is_whitespace) {
            // A CONTENT line: stop. Include the whole content line ONLY if we already
            // crossed a blank line below; else leave base_hi.
            return if budget < k { line_end } else { base_hi };
        }
        if budget == 0 {
            return hi.max(base_hi);
        }
        budget -= 1;
        hi = line_end + 1; // step past the '\n' to the next line
    }
}

/// Is `line` NAME-SHAPED — a run of 2..=6 whitespace-separated tokens, EVERY token starting
/// with an uppercase letter (so a director/firm name `Lee Wai Fai`, `Tan Peng Chin LLC`,
/// `Sumitomo Mitsui Trust Bank`, tolerating a trailing all-caps org suffix which is itself
/// uppercase-initial)? Deterministic; used ONLY to decide which lines the role-list
/// continuation reach ([`extend_before_across_name_lines`]) may cross. A line with any
/// lowercase-initial token (ordinary prose, or a heading like `Directors of the Managers`)
/// is NOT name-shaped, so it STOPS the crossing — the bound that keeps a body-text
/// capitalized run from reaching a distant heading. Requires ≥2 tokens so a single-word
/// heading/label also stops the walk. Unicode-aware on each token's first char.
fn is_name_shaped_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut count = 0usize;
    for tok in trimmed.split_whitespace() {
        count += 1;
        if count > 6 {
            return false; // too many tokens — not a tidy name line
        }
        match tok.chars().next() {
            Some(c) if c.is_uppercase() => {}
            _ => return false, // a lowercase-initial (or punctuation) token breaks the chain
        }
    }
    count >= 2
}

/// ROLE-LIST CONTINUATION (fix A): extend a before-window start `base_lo` BACKWARD across up
/// to `max_lines` CONSECUTIVE name-shaped lines above the span at `span_start`, returning the
/// new (char-boundary) window start `<= base_lo`. `max_lines == 0` returns `base_lo`
/// unchanged (byte-identical to before this reach existed).
///
/// It walks up line-by-line from the span's OWN line: each preceding line is INCLUDED in the
/// before-window (so the keyword search covers it), and if that line is [`is_name_shaped_line`]
/// the walk continues (bounded by `max_lines`), otherwise the walk STOPS after including that
/// one line — which is the heading (its role keyword is now in-window), a blank, or prose. So
/// the 4th/5th/… name of a director/manager list reaches the heading above the run of names,
/// while a name in ordinary prose (whose neighbouring lines are not name-shaped) does not.
/// Every returned offset lands on a char boundary (all cuts are at ASCII `\n` bounds or
/// `base_lo`). Deterministic; no clock/RNG.
fn extend_before_across_name_lines(
    text: &str,
    base_lo: usize,
    span_start: usize,
    max_lines: usize,
) -> usize {
    if max_lines == 0 {
        return base_lo;
    }
    // Start of the line the span sits on (byte after the previous '\n', or 0).
    let mut cur_line_start = text[..span_start].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let mut reached = base_lo;
    let mut crossed = 0usize;
    while cur_line_start > 0 && crossed < max_lines {
        let nl = cur_line_start - 1; // the '\n' that ends the preceding line
        let prev_start = text[..nl].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let prev_line = &text[prev_start..nl];
        // Include this preceding line in the before-window regardless (we are extending BACK).
        reached = reached.min(prev_start);
        if is_name_shaped_line(prev_line) {
            crossed += 1;
            cur_line_start = prev_start; // keep walking up across the name run
        } else {
            break; // heading / blank / prose: included above, then stop (bounded reach)
        }
    }
    reached.min(base_lo)
}

/// LEADING-SPAN CORROBORATION (fix B): does the matched `span` text BEGIN with a whole-word
/// keyword from `lexicon` (case-insensitive)? Used ONLY by the `role-name` gate so a role
/// keyword the greedy capitalized-run scanner CONSUMED as the head of the run
/// (`Managers   Tan Peng Chin` in a two-column layout) still corroborates the candidate —
/// the ordinary window probe excludes the matched span, so such a keyword would otherwise be
/// invisible and the name suppressed. Restricted to the LEADING position (a `starts_with` +
/// trailing word-boundary check) to target the heading-consumed shape, not any keyword buried
/// mid-span. Confidentiality-clean (consults OUR constant lexicon; returns a bool, no text).
pub(crate) fn span_leads_with_keyword(span: &str, lexicon: &[&str]) -> bool {
    let span_lc = span.trim_start().to_lowercase();
    for kw in lexicon {
        let kw_lc = kw.to_lowercase();
        if let Some(rest) = span_lc.strip_prefix(&kw_lc) {
            // Whole-word: the char right after the keyword must not be a word char (or the
            // span ends there). `strip_prefix` guarantees the left edge is the span start.
            let right_ok = rest
                .chars()
                .next()
                .map(|c| !is_word_char(c))
                .unwrap_or(true);
            if right_ok {
                return true;
            }
        }
    }
    false
}

/// Does any keyword in `lexicon` appear within the ±[`CONTEXT_WINDOW_CHARS`] window
/// around the byte span `start..end` of `text`, and HOW NEAR?
///
/// DETERMINISTIC + char-boundary-safe + confidentiality-clean (returns only a
/// [`Proximity`], never any matched text). The window is clamped to char boundaries via
/// the SAME [`floor_char_boundary_back`]/[`ceil_char_boundary_fwd`] helpers the review
/// snippet uses, so multibyte text never panics nor mis-indexes.
///
/// Matching is case-insensitive and WORD-BOUNDARY anchored on word-char edges of the
/// keyword (so "ssn" matches "SSN:" / "the ssn is" but not "assignment"; a keyword that
/// is a phrase like "social security" matches across the internal space). A keyword is
/// "close" ([`Proximity::Close`]) when its nearest edge is within [`CLOSE_BYTES`] of the
/// match (a STRICT byte gap, line-agnostic — see the tightening note on [`CLOSE_BYTES`]);
/// in-window but farther => "window" ([`Proximity::Window`]); none in-window =>
/// [`Proximity::None`].
pub(crate) fn keyword_in_window(
    text: &str,
    start: usize,
    end: usize,
    lexicon: &[&str],
    blank_line_tolerance: usize,
    name_line_run_back: usize,
) -> Proximity {
    let lo = floor_char_boundary_back(text, start, CONTEXT_WINDOW_CHARS);
    // Extend the before-window BACK across up to `blank_line_tolerance` whitespace-only
    // lines (0 = unchanged, byte-identical to before this parameter existed). This is the
    // fix for a PDF-reconstructed heading/name layout where a positioning gap becomes a
    // long run of spaces on its own line, pushing the role heading past the fixed char
    // window (`Managers\n<many spaces>\nTan Peng Chin LLC`).
    let lo = extend_before_across_blank_lines(text, lo, blank_line_tolerance);
    // ROLE-LIST CONTINUATION (fix A): additionally reach BACK across up to
    // `name_line_run_back` CONSECUTIVE name-shaped lines to find the heading that sits above
    // a run of preceding name lines (`0` = no crossing, byte-identical). Crosses ONLY
    // name-shaped lines and stops at (and includes) the first non-name-shaped line — the
    // heading, a blank, or ordinary prose — so a capitalized run buried in body text never
    // reaches a distant heading. Independent of the blank-line tolerance (that stays bounded
    // at 2), so the "3 blank lines don't fire" bound is preserved.
    let lo = extend_before_across_name_lines(text, lo, start, name_line_run_back);
    let hi = ceil_char_boundary_fwd(text, end, CONTEXT_WINDOW_CHARS);
    let hi = extend_after_across_blank_lines(text, hi, blank_line_tolerance);
    // The before-window (lo..start) and after-window (end..hi); the match itself is
    // excluded so a keyword embedded INSIDE the match never self-corroborates.
    //
    // MULTIBYTE-SAFE: all keyword matching + boundary + distance work happens ENTIRELY
    // within the LOWERCASED window (`before_lc`/`after_lc`), whose byte offsets are
    // self-consistent. We never cross a lowercased offset back into the original-cased
    // text (`to_lowercase` can change byte length, e.g. 'İ'/'ß', so cross-indexing would
    // mis-slice). Lowercasing preserves whether a char is a word char and preserves `\n`,
    // so word-boundary + same-line checks are valid in `_lc`. Distances are in
    // lowercased-window bytes; CLOSE_BYTES is a coarse threshold, so the (small) drift
    // vs the original byte length is immaterial.
    let before_lc = text[lo..start].to_lowercase();
    let after_lc = text[end..hi].to_lowercase();

    let mut best = Proximity::None;
    for kw in lexicon {
        let kw_lc = kw.to_lowercase();
        // BEFORE the match: distance = bytes from the keyword's END to the match start.
        // CLOSE = a STRICT ≤CLOSE_BYTES gap (see the tightening note on `CLOSE_BYTES`):
        // proximity is now pure byte-distance, line-agnostic.
        for hit_end in word_boundary_matches(&before_lc, &kw_lc) {
            let dist = before_lc.len().saturating_sub(hit_end);
            best = best.max(if dist <= CLOSE_BYTES {
                Proximity::Close
            } else {
                Proximity::Window
            });
        }
        // AFTER the match: distance = bytes from the match end to the keyword's START.
        for hit_start in word_boundary_starts(&after_lc, &kw_lc) {
            best = best.max(if hit_start <= CLOSE_BYTES {
                Proximity::Close
            } else {
                Proximity::Window
            });
        }
        if best == Proximity::Close {
            break; // can't get nearer; short-circuit
        }
    }
    best
}

impl Proximity {
    /// `Proximity` total order for `max`: None < Window < Close.
    fn rank(self) -> u8 {
        match self {
            Proximity::None => 0,
            Proximity::Window => 1,
            Proximity::Close => 2,
        }
    }
    fn max(self, other: Proximity) -> Proximity {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Find every WORD-BOUNDARY-anchored, case-folded occurrence of `needle_lc` in the
/// LOWERCASED haystack `hay_lc`, returning each match's END byte offset (in `hay_lc`).
/// All offsets are in `hay_lc`'s own byte space (the caller works in `_lc` end-to-end —
/// see the multibyte note in [`keyword_in_window`]).
///
/// Word-boundary = the char before the match start is not a word char (or start of
/// string) AND the char after the match end is not a word char (or end of string),
/// checked WITHIN `hay_lc` (lowercasing preserves word-char-ness). Pure, deterministic.
fn word_boundary_matches(hay_lc: &str, needle_lc: &str) -> Vec<usize> {
    word_boundary_starts(hay_lc, needle_lc)
        .into_iter()
        .map(|s| s + needle_lc.len())
        .collect()
}

/// Like [`word_boundary_matches`] but returns each match's START byte offset (in `hay_lc`).
fn word_boundary_starts(hay_lc: &str, needle_lc: &str) -> Vec<usize> {
    if needle_lc.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = hay_lc[from..].find(needle_lc) {
        let s = from + rel;
        let e = s + needle_lc.len();
        // Left boundary: previous char is not a word char (checked in `hay_lc`).
        let left_ok = s == 0
            || !hay_lc[..s]
                .chars()
                .next_back()
                .map(is_word_char)
                .unwrap_or(false);
        // Right boundary: next char is not a word char.
        let right_ok = e == hay_lc.len()
            || !hay_lc[e..]
                .chars()
                .next()
                .map(is_word_char)
                .unwrap_or(false);
        if left_ok && right_ok {
            out.push(s);
        }
        // Advance past this start to find overlapping later matches deterministically.
        from = s + 1;
        if from >= hay_lc.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: place a keyword and a synthetic 9-byte "match" in `text`, probe proximity.
    fn probe(text: &str, lexicon: &[&str]) -> Proximity {
        // Find the digit run "212345678" as the match span.
        let s = text.find("212345678").expect("test text contains the run");
        let e = s + "212345678".len();
        keyword_in_window(text, s, e, lexicon, 0, 0)
    }

    #[test]
    fn close_same_line_and_distance() {
        // Keyword immediately before, within ≤CLOSE_BYTES => Close.
        assert_eq!(probe("SSN: 212345678", &["ssn"]), Proximity::Close);
        // Keyword just after, within ≤CLOSE_BYTES => Close.
        assert_eq!(probe("212345678 is the ssn", &["ssn"]), Proximity::Close);
    }

    #[test]
    fn none_when_no_keyword_in_window() {
        assert_eq!(probe("reference 212345678 here", &["ssn"]), Proximity::None);
    }

    #[test]
    fn word_boundary_anchored_no_substring_false_positive() {
        // "assignment" contains "ssn" but is NOT a word-boundary match => None.
        assert_eq!(
            probe("assignment 212345678 filed", &["ssn"]),
            Proximity::None
        );
    }

    #[test]
    fn window_when_far_but_across_a_newline() {
        // Keyword IN-window (within ±40 chars) but > CLOSE_BYTES away => Window, not
        // Close. "ssn" end (3) to the run start has " xxxxxxxxxxxxxxxxxxxx\n" = 22 bytes
        // between them > CLOSE_BYTES (20) => Window.
        let text = "ssn xxxxxxxxxxxxxxxxxxxx\n212345678 here";
        assert_eq!(probe(text, &["ssn"]), Proximity::Window);
    }

    #[test]
    fn window_when_same_line_but_beyond_close_bytes() {
        // The `Close` TIGHTENING (LEVER2 §4): proximity is a STRICT byte gap with NO
        // same-line OR-arm. A keyword on the SAME line as the match but > CLOSE_BYTES
        // away now grades Window (it once graded Close via the dropped same-line arm).
        // "ssn" end (3) to the run start has " ........................ " = 26 bytes,
        // no '\n', same line — under the old arm this was Close; now it is Window.
        let text = "ssn ........................ 212345678 here";
        assert_eq!(probe(text, &["ssn"]), Proximity::Window);
        // A keyword on the same line WITHIN CLOSE_BYTES is still Close (control).
        assert_eq!(probe("ssn is 212345678 here", &["ssn"]), Proximity::Close);
    }

    #[test]
    fn multibyte_lowercase_length_change_does_not_panic_or_misindex() {
        // 'İ' (U+0130) lowercases to 'i̇' (2 chars / 3 bytes) — a byte-length CHANGE.
        // A window containing it must not panic nor mis-slice; the ASCII keyword still
        // matches. (Boundary work happens entirely in the lowercased window.)
        let text = "İSSN noted İ 212345678 İand more İ";
        let p = probe(text, &["ssn"]); // must not panic
                                       // "İSSN" lowercases to "i̇ssn" — but "ssn" there is preceded by the combining
                                       // dot (a non-word char? the dot above is a Mark, not alphanumeric) — regardless,
                                       // the call is panic-free, which is the load-bearing assertion here.
        let _ = p;
        // A clean keyword token also present nearby still corroborates without panic.
        let text2 = "groß café — ssn — 212345678 — naïve";
        assert_eq!(probe(text2, &["ssn"]), Proximity::Close);
    }

    #[test]
    fn phrase_keyword_matches_across_internal_space() {
        assert_eq!(
            probe("social security 212345678 on file", &["social security"]),
            Proximity::Close
        );
    }

    #[test]
    fn empty_keyword_never_matches() {
        assert!(word_boundary_starts("anything here", "").is_empty());
    }
}
