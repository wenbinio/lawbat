// SPDX-License-Identifier: AGPL-3.0-or-later
//! # `packs` — the recognizer-pack layer (jurisdictions + compliance profiles)
//!
//! Two OPT-IN axes of recognizer rows live here, each as DATA so adding one is a
//! mechanical, low-conflict edit rather than a change to shared detection code:
//!
//! - the **jurisdiction** axis ([`Locale`] → `packs/<cc>.rs`), and
//! - the **compliance-profile** axis ([`self::profiles::Profile`] → [`self::profiles`]).
//!
//! Both compile into the SAME `TaggedPattern` machinery in `lib.rs` (so they merge /
//! dedup / validate identically to the global built-ins) and attribute through a
//! generic, namespaced `Recognizer` variant (`locale:<…>` / `profile:<…>`), so neither
//! axis grows the `Recognizer` enum or the audit machinery.
//!
//! Shared, jurisdiction-AGNOSTIC checksum validators live in [`self::validators`]; a
//! pack file references them (or builds a small jurisdiction-specific `fn` on top)
//! without reaching back into `lib.rs`.
//!
//! ============================================================================
//!  ADDING A JURISDICTION  (the WHOLE diff — 4 mechanical insertion points)
//! ============================================================================
//!
//!   1. CREATE `core/crates/redaction/src/packs/<cc>.rs` exposing
//!        `pub fn rows() -> &'static [LocaleRecognizer] { &[ /* rows */ ] }`
//!      (copy `packs/sg.rs` as the template).
//!   2. ADD `pub mod <cc>;` to the "// registered jurisdiction pack modules" list
//!      below in THIS file.
//!   3. ADD one variant to the `Locale` enum below (e.g. `UnitedStates`) — its
//!      `Locale::label()` arm gives the namespace prefix (e.g. `"us"`).
//!   4. ADD one arm to `locale_recognizers()` below mapping that variant to its
//!      file's rows (e.g. `Locale::UnitedStates => us::rows(),`).
//!
//! That is the entire diff — no new `Recognizer` variant, no new `RecognizerKey`
//! arm, no change to the detection driver or the audit breakdown. Steps 2 and 4 are
//! single APPEND-ONLY lines in distinct list/match positions, so parallel agents each
//! adding a jurisdiction touch disjoint lines (low merge conflict). Adding ANOTHER
//! recognizer to an EXISTING jurisdiction is a single extra `LocaleRecognizer` row in
//! that jurisdiction's `rows()` slice — this file does not change at all.
//! ============================================================================

pub mod profiles;
pub mod validators;

// ---- registered jurisdiction pack modules (step 2: append `pub mod <cc>;`) ----
pub mod au;
pub mod ca;
pub mod sg;
pub mod uk;
pub mod us;

/// A jurisdiction whose identifier recognizers can be enabled as an OPT-IN pack.
///
/// `#[non_exhaustive]` ON PURPOSE: adding a jurisdiction later is a non-breaking
/// change that nonetheless FORCES downstream `match`es to carry a wildcard arm, so a
/// new locale can never silently fall through an exhaustive caller match.
///
/// (Step 3 of "ADDING A JURISDICTION": one variant here + its `label()` arm.)
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    /// Singapore — currently the NRIC/FIN recognizer (`sg:nric`). Rows: `packs/sg.rs`.
    Singapore,
    /// United States — SSN / ITIN / EIN / ABA / NPI / DEA / MBI / passport / DL
    /// (`us:*`). Rows: `packs/us.rs`.
    UnitedStates,
    /// United Kingdom — NHS / NINO / UTR / passport / driving licence / sort code
    /// (`uk:*`). Rows: `packs/uk.rs`.
    UnitedKingdom,
    /// Australia — TFN / ABN / ACN / Medicare / passport / DL / BSB (`au:*`).
    /// Rows: `packs/au.rs`.
    Australia,
    /// Canada — SIN / OHIP / BC-PHN / RAMQ / PHIN / BN / passport / DL (`ca:*`).
    /// Rows: `packs/ca.rs`.
    Canada,
}

impl Locale {
    /// Every [`Locale`] variant, for exhaustive iteration by a caller (e.g. a label
    /// round-trip / parser-coverage test). The companion [`assert_all_covers_locale`]
    /// is an EXHAUSTIVE `match` whose sole purpose is to fail to COMPILE if a new
    /// variant is added without also appending it here — so `ALL` can never silently
    /// fall behind the enum (the `#[non_exhaustive]` attribute is for downstream crates;
    /// it does not stop this in-crate match from being exhaustive).
    ///
    /// (Step of "ADDING A JURISDICTION": append the new variant here too — the compile
    /// guard below will remind you, and the redact-cli parser round-trip test will then
    /// fail until the new label is wired into `parse_locale`.)
    pub const ALL: &'static [Locale] = &[
        Locale::Singapore,
        Locale::UnitedStates,
        Locale::UnitedKingdom,
        Locale::Australia,
        Locale::Canada,
    ];

    /// The short stable label for this jurisdiction (the namespace PREFIX used in a
    /// locale recognizer's name, e.g. `sg` → `sg:nric`). Lowercase, audit-safe.
    pub fn label(self) -> &'static str {
        match self {
            Locale::Singapore => "sg",
            Locale::UnitedStates => "us",
            Locale::UnitedKingdom => "uk",
            Locale::Australia => "au",
            Locale::Canada => "ca",
        }
    }
}

/// COMPILE-TIME exhaustiveness guard for [`Locale::ALL`]: an EXHAUSTIVE match over
/// every variant. Adding a `Locale` variant WITHOUT also appending it to `Locale::ALL`
/// fails to compile here (the match gains a non-exhaustive error), which is the reminder
/// to update `ALL` (and, in turn, the redact-cli `parse_locale` round-trip test). The
/// function is never called — its existence is the check. `#[allow(dead_code)]` because
/// it is a type-level assertion, not runtime code.
#[allow(dead_code)]
fn assert_all_covers_locale(l: Locale) {
    match l {
        Locale::Singapore
        | Locale::UnitedStates
        | Locale::UnitedKingdom
        | Locale::Australia
        | Locale::Canada => {}
    }
}

impl std::fmt::Display for Locale {
    /// Renders the jurisdiction as its short [`label`](Locale::label) (e.g. `sg`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One jurisdiction-specific recognizer, as DATA (the unit of "add a new jurisdiction
/// later"). A static row gives its short `name` (e.g. `nric`), its regex `pattern`,
/// and an OPTIONAL `validate` checksum predicate. The pattern is STATIC + known-good
/// (compiled with `expect`, like the global built-ins) and the `regex` crate is
/// linear-time, so there is no ReDoS.
///
/// The recognizer's audit/attribution label is the jurisdiction-NAMESPACED form
/// `<locale>:<name>` (e.g. `sg:nric`), assembled in `RedactionEngine::base`; the row
/// stores only the bare `name`, so a row never has to repeat its own prefix.
///
/// `validate` mirrors the global `TaggedPattern::validate` slot: `None` = format-only
/// (the recall-first default for a national ID whose checksum is a lookup table we
/// refuse to mis-transcribe into a SILENT MISS); `Some(f)` keeps a match only if the
/// checksum passes — the slot a future checksum-bearing national ID (where a real one
/// always passes) will use. Reusable validators live in [`validators`].
///
/// `context` is the OPTIONAL required-context lexicon (mirroring the Lever-2
/// [`ContextRecognizer`](crate::context::ContextRecognizer) `lexicon`): when
/// `Some(keywords)`, a candidate from this row SURVIVES finalization only when one of
/// the keywords is within the proximity window (the SAME case-insensitive, word-boundary,
/// ±[`CONTEXT_WINDOW_CHARS`](crate::context::CONTEXT_WINDOW_CHARS) probe the `ctx:*` rows
/// use) — UNLESS a normal recognizer also covers the span (the gate is additive-only; it
/// can only ever drop a span THIS row contributed). `None` (the default for almost every
/// row) is unchanged behavior: the row fires unconditionally exactly as before. This is
/// the spec's "context-required / default-OFF" precision lever for the broadest
/// format-only shapes (per-state driver's licences, passports) that have no checksum and
/// whose raw regex matches almost any letter/digit run — without it, e.g. a repeating
/// page-footer document code like `NM0426U-5414319-2/962` floods a reviewer with
/// `us:dl` false positives. Recall-first is preserved: a REAL DL near a licence keyword
/// still fires; only the keyword-LESS noise is suppressed.
///
/// `aggressive` marks a BROAD, format-only row whose shape is so catastrophically
/// unspecific (a driver's licence, a passport, a generic account/BSB/transit/sort-code
/// number, the opt-in loose SG-NRIC net — no checksum, no distinctive structure, matches
/// almost any letter/digit run) that it carries a TWOFOLD meaning:
///
/// 1. **PRECEDENCE in labeling (engine):** it is elected the PRIMARY of an overlapping
///    merged span only as a LAST RESORT (the user's "make the most aggressive ones the
///    last ones"). The engine captures a label→aggressive map at build (like `context`)
///    and DEMOTES the row's merge priority below every precise recognizer (precise locale
///    rows, checksum built-ins, email/id/url) — see `RedactionEngine::recognizer_priority`.
///    This is RECALL-NEUTRAL at the engine level: a token matched only by an aggressive
///    row STILL fires and is still a candidate (it is never dropped) — only its LABEL
///    contest position changes.
/// 2. **ADVISORY / default-OFF in the accept-set (host):** a candidate whose PRIMARY
///    recognizer is an aggressive row is surfaced for REVIEW but is DEFAULT-OFF in the
///    apply accept-set — the human opts IN to redact it (the host consults
///    [`RedactionEngine::is_aggressive`], which reads the SAME `aggressive_locales` set, so
///    "advisory" and "demoted in the label contest" can never drift). So an aggressive row
///    is no longer auto-redacted by default; it is a possible-match the reviewer confirms.
///    Because the precise rows out-LABEL it, a token ALSO covered by a precise/default-ON
///    recognizer keeps that precise primary and stays default-ON — only an EXTRA token
///    matched SOLELY by an aggressive row is advisory.
///
/// `false` (the default for almost every row — every checksum/structural national ID,
/// `sg:nric`, `sg:uen`) keeps the row at the full precise locale priority AND default-ON,
/// unchanged. This is ORTHOGONAL to `context`: an aggressive row may ALSO be `context`-gated
/// (e.g. `us:dl` is both), and a `context: None` aggressive row (e.g. `us:account`,
/// `sg:nric-loose`) is still demoted in the LABEL contest + advisory in the accept-set.
///
/// Fields are `pub(crate)` so a pack file in this module tree can build static rows
/// while the engine in `lib.rs` reads them; they are NOT part of the crate's public
/// API (a row is constructed only by a pack file, never by a downstream caller).
#[derive(Debug, Clone, Copy)]
pub struct LocaleRecognizer {
    /// The bare recognizer name within the jurisdiction (e.g. `nric`). The namespaced
    /// label `<locale>:<name>` is built from this + the [`Locale`].
    pub(crate) name: &'static str,
    /// The (static, known-good) regex source for the identifier shape.
    pub(crate) pattern: &'static str,
    /// Optional checksum validator (see the type docs). `None` = format-only.
    pub(crate) validate: Option<fn(&str) -> bool>,
    /// OPTIONAL required-context lexicon (see the type docs). `None` (the common case)
    /// = fires unconditionally; `Some(keywords)` = the candidate is gated on one of the
    /// keywords being in-window (additive-only — see `RedactionEngine::merged_spans`).
    pub(crate) context: Option<&'static [&'static str]>,
    /// Whether this is a BROAD, format-only "last-resort" row (see the type docs):
    /// `true` (i) DEMOTES it below every precise recognizer in the merge's PRIMARY-LABEL
    /// election (never in engine fire/drop — RECALL-NEUTRAL there) AND (ii) makes its
    /// candidates ADVISORY / default-OFF in the HOST accept-set (surfaced for review, the
    /// human opts in to redact — via `RedactionEngine::is_aggressive`). `false` (the common
    /// case) keeps the full precise locale priority AND default-ON. Set `true` ONLY on the
    /// catastrophic-FP shapes the spec flags (driver's licence, passport, generic account/
    /// BSB/transit/sort-code, the opt-in loose SG-NRIC net).
    pub(crate) aggressive: bool,
}

/// The recognizer rows for a jurisdiction — the single registration seam mapping a
/// [`Locale`] variant to its pack file's `rows()`. Returns a `'static` slice so
/// enabling a pack copies nothing.
///
/// (Step 4 of "ADDING A JURISDICTION": one append-only arm here.)
///
/// The `match` is EXHAUSTIVE over [`Locale`], so adding a `Locale` variant WITHOUT
/// registering its rows fails to compile — a jurisdiction can never be selectable yet
/// silently produce no recognizers.
pub(crate) fn locale_recognizers(locale: Locale) -> &'static [LocaleRecognizer] {
    match locale {
        Locale::Singapore => sg::rows(),
        Locale::UnitedStates => us::rows(),
        Locale::UnitedKingdom => uk::rows(),
        Locale::Australia => au::rows(),
        Locale::Canada => ca::rows(),
    }
}
