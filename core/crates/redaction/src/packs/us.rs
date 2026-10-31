// SPDX-License-Identifier: AGPL-3.0-or-later
//! United States (`us`) jurisdiction recognizer pack.
//!
//! One self-contained file of DATA ROWS — the unit a parallel fan-out adds per
//! jurisdiction (see the "ADDING A JURISDICTION" comment in `packs/mod.rs`). It
//! exposes exactly [`rows`]; `packs/mod.rs` maps [`Locale::UnitedStates`] to it via
//! the single append-only registration seam. Nothing jurisdiction-specific leaks
//! into shared code: the namespaced audit label (`us:ssn`, `us:aba`, …) is assembled
//! by the engine from this jurisdiction's [`Locale::label`](crate::Locale::label)
//! prefix (`us`) + each row's bare `name`.
//!
//! Built to `to-read/redaction.RECOGNIZER-PACKS-SPEC.md` §"PACK 1 — UNITED STATES" (rows US-1..US-10),
//! prior-art-aligned (Presidio / pii-vault / HIPAA) with independently-recomputed
//! checksum test vectors.
//!
//! ## Two tiers (the recall-first / checksum-as-precision split)
//!
//! A row attaches `validate: Some(fn)` ONLY where a checksum/structural rule a REAL
//! identifier ALWAYS satisfies supplies precision — `validate` is a HARD GATE in the
//! engine (a match whose `validate` returns `false` is DROPPED; there is no
//! confidence/booster tier yet), so it is attached only where it can filter
//! NON-instances and NEVER silently miss a true one:
//!
//! - **Checksum/structural-backed (auto-redact-eligible hard gate):** US-1 SSN
//!   (structural range rules), US-3 ABA (weighted mod-10 + prefix range), US-4 NPI
//!   (Luhn over `80840` + the 9-digit body), US-5 DEA (digit checksum + registrant
//!   letter), US-7 EIN (prefix denylist — a cheap structural `validate`, every real
//!   EIN passes), US-2 ITIN (its valid-group range is encoded IN the regex, so the
//!   regex IS the validator).
//! - **Format-only / context-leaning (NO `validate`; broad by design):** US-6 MBI
//!   (positional alphabet mask self-validates), US-8 bank account, US-9 passport,
//!   US-10 driver's licence. The spec marks these context-required / default-OFF; the
//!   engine has no context-proximity dimension yet, so the rows are still ADDED (a
//!   miss is a Rule-6 breach — recall-first never silently drops a category) but are
//!   deliberately BROAD. Per-row comments flag the false-positive cost so a future
//!   context dimension can tighten them without re-deriving the shapes.
//!
//! ## Validators live IN THIS FILE
//!
//! The jurisdiction-SPECIFIC validators ([`ssn_valid`], [`aba_valid`], [`npi_valid`],
//! [`dea_valid`], [`ein_valid`]) are defined here — they compose the GENERIC reusable
//! helpers from [`super::validators`] (`mod10_valid` / `weighted_mod_n`) rather than
//! reinvent the wheel, but their jurisdiction-specific structure (SSN's range rules,
//! NPI's `80840` prefix, DEA's bespoke `(d0+d2+d4)+2*(d1+d3+d5)` sum, EIN's IRS prefix
//! denylist) stays local to this pack, exactly like the SG NRIC weighting would. All
//! are PURE integer compute and NEVER panic on adversarial input (empty / non-digit /
//! huge): they parse defensively, bail on a length mismatch, and allocate nothing
//! beyond the matched slice they inspect.

use super::validators::digits_of;
use super::LocaleRecognizer;

/// The United States recognizer rows (spec §PACK 1, US-1..US-10). Returns a
/// `'static` slice so enabling the pack copies nothing — the engine compiles the rows
/// it is told to. Adding ANOTHER US recognizer later is a single extra
/// [`LocaleRecognizer`] row in this slice — no other file changes.
pub fn rows() -> &'static [LocaleRecognizer] {
    &[
        // US-1 SSN — STRUCTURAL hard gate (no checksum exists; the SSA randomized
        // issuance in 2011, so there is no check digit). The validator encodes the
        // SSA structural-invalid rules a REAL SSN can never violate (area 000/666/≥900,
        // group 00, serial 0000, all-identical, and the known-fake set), so it only
        // filters NON-SSNs — never a miss. RECALL-FIRST: the regex keeps `\b` anchors
        // (a 3-2-4 grouped digit run is the signal) and the structural validator
        // supplies the rest. Separators may be `-`, space, or `.`; the validator
        // rejects a genuinely MIXED-separator token (two different separators) as
        // non-canonical while leaving any consistently- (or un-)separated SSN intact.
        LocaleRecognizer {
            name: "ssn",
            pattern: r"\b\d{3}[- .]?\d{2}[- .]?\d{4}\b",
            validate: Some(ssn_valid),
            context: None,
            aggressive: false, // STRUCTURAL hard gate — precise.
        },
        // US-2 ITIN — the REGEX IS THE VALIDATOR (format-only, but precise): first
        // digit 9, then a valid group range {50–65, 70–88, 90–92, 94–99} encoded
        // directly in the pattern, then 4 digits. No separate `validate` fn is needed
        // (and none could improve it — there is no ITIN checksum). The group-range
        // alternation is what makes a 9-leading SSN-shaped run an ITIN.
        LocaleRecognizer {
            name: "itin",
            pattern: r"\b9\d{2}[- ]?(?:5\d|6[0-5]|7\d|8[0-8]|9(?:[0-2]|[4-9]))[- ]?\d{4}\b",
            validate: None,
            context: None,
            aggressive: false, // the regex (9 + valid group range) IS the validator — precise.
        },
        // US-3 ABA routing — weighted mod-10 hard gate. `c = 3(d0+d3+d6) + 7(d1+d4+d7)
        // + (d2+d5+d8)`, valid iff `c % 10 == 0`, PLUS the Federal Reserve prefix-range
        // gate (first two digits ∈ 00–12 ∪ 21–32 ∪ 61–72 ∪ {80}) and an all-zero
        // reject. The checksum + prefix range make a bare 9-digit run precise WITHOUT a
        // miss (a real routing number always passes both).
        LocaleRecognizer {
            name: "aba",
            pattern: r"\b\d{9}\b",
            validate: Some(aba_valid),
            context: None,
            aggressive: false, // weighted mod-10 + prefix range — precise.
        },
        // US-4 NPI — Luhn with the CONSTANT `80840` prefix (CMS check digit). The 10th
        // digit is the Luhn check over `80840` ++ the first 9 digits. This is NOT plain
        // Luhn over the bare 10 digits — the `80840` prefix is mandatory (spec trap).
        // A real NPI always passes, so the hard gate only filters non-NPIs.
        LocaleRecognizer {
            name: "npi",
            pattern: r"\b[12]\d{9}\b",
            validate: Some(npi_valid),
            context: None,
            aggressive: false, // CMS Luhn over the 80840 prefix — precise.
        },
        // US-5 DEA — registrant-letter set + the DEA digit checksum. The 7 trailing
        // digits d0..d6 (d6 = check); `c = (d0+d2+d4) + 2*(d1+d3+d5)`, valid iff
        // `c % 10 == d6`; the first letter must be in the registrant set
        // {A,B,C,D,E,F,G,H,J,K,L,M,P,R,S,T,U,X}. The regex already restricts the first
        // letter to that set and the second to `[A-Z9]`, but the validator re-checks
        // the registrant letter (defence in depth) and applies the checksum.
        LocaleRecognizer {
            name: "dea",
            pattern: r"\b[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}\b",
            validate: Some(dea_valid),
            context: None,
            aggressive: false, // registrant-letter set + digit checksum — precise.
        },
        // US-6 MBI (Medicare Beneficiary Identifier) — FORMAT-ONLY: the positional
        // ALPHABET MASK self-validates (no checksum exists). Letters exclude the
        // ambiguous S, L, O, I, B, Z; pos1 ∈ 1–9; the digit/letter positions are fixed.
        // `validate: None` — the mask in the regex is the whole precision story.
        // NOTE (spec ambiguity, see module/PR notes): the spec PROSE mentions optional
        // hyphens after positions 4 and 7, but the spec's REGEX (authoritative here)
        // carries NO hyphen allowance — implemented as the unhyphenated 11-char form.
        LocaleRecognizer {
            name: "mbi",
            pattern: r"\b[1-9][AC-HJ-NP-RT-Y][0-9AC-HJ-NP-RT-Y]\d[AC-HJ-NP-RT-Y][0-9AC-HJ-NP-RT-Y]\d[AC-HJ-NP-RT-Y]{2}\d{2}\b",
            validate: None,
            context: None,
            aggressive: false, // the positional alphabet mask self-validates — precise (structural).
        },
        // US-7 EIN — hyphen-after-digit-2 form `NN-NNNNNNN` with a PREFIX DENYLIST as a
        // cheap structural `validate` (there is no EIN checksum). The IRS has never
        // issued certain 2-digit campus prefixes; rejecting them filters obvious
        // non-EINs without a miss (a real EIN's prefix is never in the denylist). The
        // mandatory hyphen-after-2 disambiguates EIN-vs-SSN (spec: separator position).
        // (Spec flags "CONFIRM the IRS prefix table vs live IRM before shipping" — the
        // denylist is the spec's table verbatim; a prefix entering use later is a one-
        // row data edit, never a code change.)
        LocaleRecognizer {
            name: "ein",
            pattern: r"\b\d{2}-\d{7}\b",
            validate: Some(ein_valid),
            context: None,
            aggressive: false, // mandatory hyphen-after-2 + IRS prefix denylist — precise (structural).
        },
        // US-8 bank account — FORMAT-ONLY, context-required (the spec ships ABA as the
        // PRECISE bank recognizer; a raw account number is a bare 8–17 digit run with
        // no checksum). BROAD BY DESIGN: with no context-proximity dimension yet this
        // over-flags any long digit run (an order no., a tracking no.). The row is
        // still ADDED — a missed account number is a Rule-6 breach — but a future
        // context gate (the spec's `account/acct/bank` keyword) is where its precision
        // will come from. `validate: None`.
        LocaleRecognizer {
            name: "account",
            pattern: r"\b\d{8,17}\b",
            validate: None,
            context: None,
            // AGGRESSIVE: a bare 8–17 digit run with no checksum/structure — it over-
            // matches any long digit run (order/tracking no.). Demoted in the merge's
            // PRIMARY-LABEL contest so a precise row (e.g. us:aba/us:npi) always out-
            // labels it; still FIRES (recall-neutral — the span is redacted regardless).
            aggressive: true,
        },
        // US-9 passport — FORMAT-ONLY, default-OFF/context-required per spec (it
        // collides with SSN/EIN/NPI shapes). A US passport book number is 9 digits, or
        // a letter + 8 digits (newer "next-gen" books). BROAD: the 9-digit alternative
        // overlaps ABA/NPI/bare-SSN. CONTEXT-GATED (the new `LocaleRecognizer::context`
        // slot, spec US-9 "Default OFF/context-required"): a passport candidate SURVIVES
        // only with a passport keyword in-window (or a normal recognizer also covering
        // the span). Recall-first holds — a real passport number near "passport" still
        // fires; only the keyword-less SSN/NPI/ABA-shaped collisions are suppressed.
        LocaleRecognizer {
            name: "passport",
            pattern: r"\b(?:\d{9}|[A-Z]\d{8})\b",
            validate: None,
            context: Some(&["passport", "passport no", "passport number", "passport #"]),
            // AGGRESSIVE: the 9-digit alternative collides with SSN/EIN/NPI/ABA shapes —
            // last-resort LABEL, demoted below the precise rows it overlaps. (Orthogonal
            // to the `context` gate above, which governs fire/drop, not the label.)
            aggressive: true,
        },
        // US-10 driver's licence — FORMAT-ONLY, per-state, context-required (no single
        // national format). PORT-BUG FIXED (spec trap): Presidio's `UsLicenseRecognizer`
        // regex has a literal typo `A-Z]{2}` (a missing `[`); the corrected
        // alternative is `[A-Z]{2}\d{5,9}`. BROAD by design (state DL formats are a zoo
        // — a letter-prefixed digit run, or a long bare digit run), so it matches almost
        // ANY letter/digit run: a repeating page-footer document code like
        // `NM0426U-5414319-2/962` once fired 962 false positives, burying the reviewer.
        // CONTEXT-GATED (the new `LocaleRecognizer::context` slot — spec US-10 marks DL
        // "context-required", which is now ENFORCED, not merely aspirational): the
        // candidate SURVIVES only with a driver's-licence keyword in-window (case-
        // insensitive, word-boundary, the same ±window the `ctx:*` rows use) OR when a
        // normal recognizer also covers the span (additive-only gate). RECALL-FIRST is
        // preserved: a real DL near "Driver's Licence"/"DL no" still fires; only the
        // keyword-less noise (the footer code) is dropped.
        LocaleRecognizer {
            name: "dl",
            pattern: r"\b(?:[A-Z]\d{4,12}|[A-Z]{2}\d{5,9}|\d{7,12})\b",
            validate: None,
            context: Some(&[
                "driver",
                "drivers",
                "driving",
                "licence",
                "license",
                "dl no",
                "dl#",
                "dl number",
            ]),
            // AGGRESSIVE: per-state, no national format — matches almost ANY letter/digit
            // run (the 962-FP footer flood). Last-resort LABEL, demoted below every precise
            // row. (Orthogonal to the `context` gate above, which governs fire/drop.)
            aggressive: true,
        },
        // US-11 ZIP / ZIP+4 (spec §"ADDRESS FAMILY — LOCALE POSTAL", US-POST). Two
        // DISTINCTIVE arms fire unconditionally: a ZIP+4 (`NNNNN-NNNN`) is distinctive on
        // its own, and a 2-letter STATE abbreviation + a 5-digit ZIP (`CA 94043`) is bound
        // by the state. Both bias recall while the state / +4 shape bounds the FP cost.
        // CONTEXT:NONE, PRECISE (structural → CAREFUL review — no `zip` class lexicon, so
        // it never reaches High). Audit `us:zip`; type label "postal code".
        LocaleRecognizer {
            name: "zip",
            pattern: r"\b\d{5}-\d{4}\b|\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\s+\d{5}(?:-\d{4})?\b",
            validate: None,
            context: None,
            aggressive: false,
        },
        // US-12 BARE 5-DIGIT ZIP near address context (spec §US-POST, recall net): a bare
        // `NNNNN` run gated on a zip/address keyword in-window (the additive gate `us:dl`
        // uses). AGGRESSIVE (advisory / default-OFF; demoted) because a bare 5-digit run is
        // FP-prone (it overlaps countless numbers). Audit `us:zip-bare`.
        LocaleRecognizer {
            name: "zip-bare",
            pattern: r"\b\d{5}\b",
            validate: None,
            context: Some(&["zip", "zip code", "postal", "postcode", "address"]),
            aggressive: true,
        },
    ]
}

// ===================================================================
// Jurisdiction-specific validators (PURE integer compute, NEVER panic)
// ===================================================================
//
// Each takes the RAW regex match text (`&str`) and returns whether it is a structurally
// valid identifier of that kind. They strip separators defensively, bail on a length
// mismatch (never index out of bounds), and allocate nothing beyond a small fixed
// digit buffer. A `validate` predicate is a HARD GATE in the engine — a `false` DROPS
// the match — so each is attached ONLY where a REAL identifier always returns `true`.

// `digits_of` is now the shared `super::validators::digits_of` (imported above) — the
// identical extraction was hoisted there so every pack composes the same first step.

/// US-1 SSN — STRUCTURAL validity (no checksum; SSA randomized issuance). Returns
/// `true` only for a 9-digit token whose area/group/serial structure a real SSN can
/// actually have. A real SSN always passes, so this only ever filters NON-SSNs.
///
/// Rules (spec US-1): area = d[0:3], group = d[3:5], serial = d[5:9]; INVALID if
/// area ∈ {000, 666} or area ≥ 900, group == 00, serial == 0000, all 9 digits
/// identical, or the token ∈ the known-fake set {078-05-1120, 123-45-6789,
/// 219-09-9999}. ALSO rejects a genuinely MIXED-separator token (two distinct
/// separators) as non-canonical — a consistently- or un-separated SSN is untouched,
/// so a real SSN is never dropped by the separator rule.
pub fn ssn_valid(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 9 {
        return false;
    }
    // Mixed-separator reject: scan the DISTINCT non-digit chars in the matched span;
    // two or more different ones (e.g. `212-34 5678`) is a non-canonical form. A
    // single separator type (or none) is fine — so a real SSN never trips this.
    let mut sep: Option<u8> = None;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            match sep {
                None => sep = Some(b),
                Some(first) if first != b => return false, // two distinct separators
                Some(_) => {}
            }
        }
    }
    let area = u32::from(d[0]) * 100 + u32::from(d[1]) * 10 + u32::from(d[2]);
    let group = u32::from(d[3]) * 10 + u32::from(d[4]);
    let serial =
        u32::from(d[5]) * 1000 + u32::from(d[6]) * 100 + u32::from(d[7]) * 10 + u32::from(d[8]);
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 {
        return false;
    }
    if serial == 0 {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false; // all nine digits identical (e.g. 111-11-1111)
    }
    // Known fakes (widely published example/ad SSNs that were never validly issued).
    const KNOWN_FAKE: [[u8; 9]; 3] = [
        [0, 7, 8, 0, 5, 1, 1, 2, 0], // 078-05-1120 (the famous wallet-card SSN)
        [1, 2, 3, 4, 5, 6, 7, 8, 9], // 123-45-6789
        [2, 1, 9, 0, 9, 9, 9, 9, 9], // 219-09-9999
    ];
    if KNOWN_FAKE.iter().any(|f| f[..] == d[..]) {
        return false;
    }
    true
}

/// US-3 ABA routing number — Federal Reserve weighted mod-10 check digit PLUS the
/// prefix-range gate. Returns `true` only for a 9-digit token that passes both; a
/// real routing number always does, so this only filters non-routing-numbers.
///
/// `c = 3(d0+d3+d6) + 7(d1+d4+d7) + (d2+d5+d8)`, valid iff `c % 10 == 0`. Prefix gate:
/// the first two digits (the Federal Reserve district / routing symbol) must be in
/// 00–12 ∪ 21–32 ∪ 61–72 ∪ {80}. An all-zero token is rejected outright.
pub fn aba_valid(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 9 {
        return false;
    }
    if d.iter().all(|&x| x == 0) {
        return false;
    }
    let prefix = u32::from(d[0]) * 10 + u32::from(d[1]);
    let prefix_ok =
        prefix <= 12 || (21..=32).contains(&prefix) || (61..=72).contains(&prefix) || prefix == 80;
    if !prefix_ok {
        return false;
    }
    // Weighted sum 3,7,1,3,7,1,3,7,1 via the generic weighted-mod-10 helper.
    let c = super::validators::weighted_mod_n(&d, &[3, 7, 1, 3, 7, 1, 3, 7, 1], 10);
    c == 0
}

/// US-4 NPI — CMS Luhn check digit over the CONSTANT prefix `80840` concatenated with
/// the NPI's first 9 digits; the 10th digit is the Luhn check. Returns `true` only for
/// a 10-digit token whose check digit is correct. NOT plain Luhn over the bare 10
/// digits — the `80840` prefix is mandatory (spec trap). A real NPI always passes.
pub fn npi_valid(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 10 {
        return false;
    }
    // Build `80840` ++ all 10 NPI digits (incl. the check digit d[9]) = 15 digits and
    // run the GENERIC mod-10 (Luhn) engine over the whole thing: a valid Luhn number,
    // INCLUDING its check digit, sums ≡ 0 (mod 10). Equivalent to "compute the check
    // over 80840+body and compare to d[9]" but reuses the shared, reviewed mod-10 core
    // with no bespoke check-digit arithmetic.
    let mut full = String::with_capacity(15);
    full.push_str("80840");
    for &x in &d {
        full.push((b'0' + x) as char);
    }
    super::validators::mod10_valid(&full)
}

/// The DEA registrant-type letter set (first character of a DEA number). Excludes the
/// ambiguous `I` and `O` and several unused letters; a registrant letter outside this
/// set means the token is not a DEA registration. (Spec US-5.)
const DEA_REGISTRANT: &[u8] = b"ABCDEFGHJKLMPRSTUX";

/// US-5 DEA registration number — registrant-letter set + the DEA digit checksum.
/// Returns `true` only for a 9-char token (2 letters/`9` + 7 digits) whose first
/// letter is a valid registrant type and whose 7th digit is the correct check digit.
/// A real DEA number always passes.
///
/// Checksum (spec US-5): over the 7 trailing digits d0..d6 (d6 = check),
/// `c = (d0+d2+d4) + 2*(d1+d3+d5)`, valid iff `c % 10 == d6`. The first letter is
/// case-folded before the registrant-set check (defensive — the regex already
/// upper-cases, so this only matters if the validator is ever called directly).
pub fn dea_valid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    // First char: registrant-type letter (case-folded).
    let first = bytes[0].to_ascii_uppercase();
    if !DEA_REGISTRANT.contains(&first) {
        return false;
    }
    // Second char: a letter or `9` (the registrant/identifier char) — not part of the
    // checksum, but it must not be a digit other than 9 (the regex enforces `[A-Z9]`;
    // re-checked here so a direct call stays honest).
    let second = bytes[1].to_ascii_uppercase();
    if !(second.is_ascii_uppercase() || second == b'9') {
        return false;
    }
    // Trailing 7 chars must all be digits.
    let tail = &bytes[2..9];
    if !tail.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let d: Vec<u8> = tail.iter().map(|b| b - b'0').collect();
    let c = (u32::from(d[0]) + u32::from(d[2]) + u32::from(d[4]))
        + 2 * (u32::from(d[1]) + u32::from(d[3]) + u32::from(d[5]));
    c % 10 == u32::from(d[6])
}

/// The IRS EIN campus-prefix DENYLIST (2-digit prefixes the IRS has never assigned).
/// Spec US-7 verbatim. Rejecting a token whose first two digits are here filters
/// obvious non-EINs without a miss — a real EIN's prefix is never in this set. (Spec
/// flags "CONFIRM vs live IRM before shipping"; a prefix entering use later is a one-
/// row data edit, never a code change.)
const EIN_DENY_PREFIXES: [u32; 17] = [
    0, 7, 8, 9, 17, 18, 19, 28, 29, 49, 69, 70, 78, 79, 89, 96, 97,
];

/// US-7 EIN — structural prefix denylist (no EIN checksum exists). Returns `true` for
/// a 9-digit token whose 2-digit campus prefix is NOT in the IRS denylist. A real EIN
/// always passes (its prefix is an issued one), so this only filters non-EINs.
pub fn ein_valid(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 9 {
        return false;
    }
    let prefix = u32::from(d[0]) * 10 + u32::from(d[1]);
    !EIN_DENY_PREFIXES.contains(&prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{recognizer_breakdown, Locale, Recognizer, RedactionEngine};
    use std::sync::Arc;

    // ---- helpers ----

    /// An engine with ONLY the US locale pack enabled (no terms / firm recognizers).
    fn us_engine() -> RedactionEngine {
        RedactionEngine::builder()
            .locales([Locale::UnitedStates])
            .build()
            .unwrap()
    }

    /// The jurisdiction-namespaced US recognizer for a given row name (e.g. `us:ssn`).
    fn us(name: &str) -> Recognizer {
        Recognizer::Locale(Arc::from(format!("us:{name}").as_str()))
    }

    /// Does the US-only engine flag `text` with a candidate ATTRIBUTED to row `name`?
    /// Checks the candidate's full `recognizers()` list, NOT just the primary: when a
    /// broad format-only row (account/passport/dl) overlaps a specific row on the same
    /// span the two merge into one candidate, and the merge picks the primary by label
    /// ASC — so `us:npi` can be present on a span whose PRIMARY is the alphabetically-
    /// earlier `us:account`. The honest "did the dedicated row fire" question is
    /// membership in the merged span's recognizer list.
    fn flagged_by(name: &str, text: &str) -> bool {
        us_engine()
            .candidates(text)
            .iter()
            .any(|c| c.recognizers().contains(&us(name)))
    }

    // ===================================================================
    // Validator unit tests — every checksum-backed row: a VALID vector passes
    // AND a checksum-INVALID vector fails. Vectors are the spec's exact synthetic
    // values (independently recomputed in Python; valids pass, invalids fail).
    // ===================================================================

    #[test]
    fn ssn_structural_valid_and_invalid() {
        for v in ["001-01-0001", "212-34-5678", "457-55-1234"] {
            assert!(ssn_valid(v), "spec SSN valid must pass: {v}");
        }
        for v in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-45-0000",
            "078-05-1120",
            "111-11-1111",
        ] {
            assert!(!ssn_valid(v), "spec SSN invalid must fail: {v}");
        }
        // Mixed separators rejected; a single consistent separator (or none) accepted.
        assert!(!ssn_valid("212-34 5678"), "mixed separators rejected");
        assert!(ssn_valid("212345678"), "unseparated SSN accepted");
        assert!(ssn_valid("212 34 5678"), "space-separated SSN accepted");
    }

    #[test]
    fn aba_mod10_and_prefix_valid_and_invalid() {
        for v in ["021000021", "011401533", "091000019"] {
            assert!(aba_valid(v), "spec ABA valid must pass: {v}");
        }
        // checksum-invalid, prefix-invalid (13), all-zero.
        for v in ["021000020", "131000000", "000000000"] {
            assert!(!aba_valid(v), "spec ABA invalid must fail: {v}");
        }
    }

    #[test]
    fn npi_luhn_with_80840_prefix_valid_and_invalid() {
        for v in ["1234567893", "1987654328", "1000000004"] {
            assert!(npi_valid(v), "spec NPI valid must pass: {v}");
        }
        for v in ["1234567890", "1234567899", "9999999999"] {
            assert!(!npi_valid(v), "spec NPI invalid must fail: {v}");
        }
        // Trap guard: the `80840` constant prefix is mandatory — a valid NPI passes,
        // a corrupted check digit of the same shape fails.
        assert!(npi_valid("1234567893") && !npi_valid("1234567890"));
    }

    #[test]
    fn dea_checksum_and_registrant_valid_and_invalid() {
        for v in ["AB1234563", "BS2233447", "FW9876547"] {
            assert!(dea_valid(v), "spec DEA valid must pass: {v}");
        }
        // checksum-invalid, registrant letter I (not in set), too short.
        for v in ["AB1234560", "IB1234563", "AB123456"] {
            assert!(!dea_valid(v), "spec DEA invalid must fail: {v}");
        }
    }

    #[test]
    fn ein_prefix_denylist_valid_and_invalid() {
        for v in ["12-3456789", "95-1234567", "47-7654321"] {
            assert!(ein_valid(v), "spec EIN valid must pass: {v}");
        }
        for v in ["00-1234567", "07-1234567", "89-1234567"] {
            assert!(
                !ein_valid(v),
                "spec EIN invalid (denied prefix) must fail: {v}"
            );
        }
    }

    // ===================================================================
    // Format-only rows: the regex/mask matches the spec's format vectors.
    // (ITIN's group range is encoded in the regex; MBI's alphabet mask self-validates.)
    // ===================================================================

    #[test]
    fn itin_group_range_format_matches() {
        // Valid group ranges flagged.
        for v in ["912-70-1234", "955-94-6789", "970-92-1234"] {
            assert!(flagged_by("itin", v), "ITIN valid-range must match: {v}");
        }
        // Out-of-range groups / wrong first digit are NOT flagged as an ITIN.
        for v in ["812-70-1234", "912-66-1234", "912-93-1234", "912-89-1234"] {
            assert!(
                !flagged_by("itin", v),
                "ITIN out-of-range must not match as ITIN: {v}"
            );
        }
    }

    #[test]
    fn mbi_alphabet_mask_format_matches() {
        // Spec's MBI vectors that obey the positional mask in the spec regex.
        // (See the module note: the spec's `2W3X4Y5AA67` / `1E54TE5MK73` example
        // vectors disagree with the spec's own REGEX — the regex is authoritative;
        // the substitute vectors below exercise the same positions unambiguously.)
        for v in ["1EG4TE5MK73", "9HJ4KM7NP89"] {
            assert!(flagged_by("mbi", v), "MBI mask-valid must match: {v}");
        }
        // Mask violations: pos1=0, excluded letter S at pos2 / pos5, non-digit at a
        // digit position, non-letter at a letter position.
        for v in [
            "0EG4TE5MK73",
            "1SG4TE5MK73",
            "1EG4SE5MK73",
            "1EGXTE5MK73",
            "1EG4TE5M173",
        ] {
            assert!(
                !flagged_by("mbi", v),
                "MBI mask-invalid must not match: {v}"
            );
        }
    }

    #[test]
    fn passport_and_dl_format_match_when_context_present() {
        // Passport (CONTEXT-GATED, spec US-9 default-OFF/context-required): 9 digits OR a
        // letter + 8 digits, fired only with a passport keyword in-window.
        assert!(flagged_by("passport", "Passport No: 123456789"));
        assert!(flagged_by("passport", "passport A12345678"));
        // DL (per-state, broad) is CONTEXT-GATED (spec US-10): the corrected Presidio
        // shapes (`[A-Z]\d{4,12}` and the port-bug-fixed `[A-Z]{2}\d{5,9}`) still match —
        // when a driver's-licence keyword is in-window.
        assert!(flagged_by("dl", "Driver's Licence: D1234567"));
        assert!(flagged_by("dl", "drivers license CA1234567"));
    }

    #[test]
    fn dl_footer_code_without_context_is_not_flagged() {
        // THE BUG (real 962-page prospectus): the repeating page-footer document code
        // `NM0426U-5414319-2/962` matched the broad `us:dl` shape and fired 962 false
        // positives, burying the reviewer. With `us:dl` CONTEXT-GATED (spec US-10
        // context-required, now ENFORCED) and NO licence keyword anywhere near it, NO
        // `us:dl` candidate is produced.
        assert!(
            !flagged_by("dl", "Page footer NM0426U-5414319-2/962 confidential"),
            "the keyword-less footer code must not flag as us:dl"
        );
        // The bare sub-runs the old broad shape would have grabbed (e.g. `5414319`,
        // `NM0426U`) are likewise NOT attributed to `us:dl` without a keyword.
        assert!(
            !flagged_by("dl", "ref NM0426U is the document code"),
            "a keyword-less letter+digit run must not flag as us:dl"
        );
        assert!(
            !flagged_by("dl", "the sequence 54143190 appears in the footer"),
            "a keyword-less bare digit run must not flag as us:dl"
        );
    }

    #[test]
    fn dl_value_near_keyword_is_flagged_recall_first() {
        // RECALL-FIRST: a real DL VALUE near a licence keyword STILL flags — the gate
        // only suppresses keyword-less noise, it never drops a corroborated identifier.
        assert!(
            flagged_by("dl", "Driver's Licence: D1234567"),
            "a DL value near the keyword must still flag (recall-first)"
        );
        // The keyword may follow the value too (the proximity probe scans both sides).
        assert!(
            flagged_by("dl", "D1234567 (driver's license)"),
            "a DL value with the keyword AFTER it must still flag"
        );
        // A DL covered by a normal recognizer survives even without the keyword (the
        // additive-only gate never removes a span a NORMAL recognizer also covers): the
        // bare-digit DL alt `\d{7,12}` overlaps the broad global `id`/`phone` built-ins,
        // so a keyword-less long digit run is still redacted (just not ATTRIBUTED to
        // us:dl as the gated row). Prove the SPAN survives via the public candidate set.
        let e = us_engine();
        let cands = e.candidates("token 5414319012 in body");
        assert!(
            cands.iter().any(|c| c.matched_value() == "5414319012"),
            "a long digit run is still covered by a normal recognizer, got {cands:?}"
        );
    }

    #[test]
    fn no_context_rows_fire_unconditionally_regression_guard() {
        // REGRESSION GUARD (the `context: Some` field must NOT change `context: None`
        // rows): a checksum/structurally-specific US row with `context: None` (SSN, ITIN)
        // STILL fires with NO keyword anywhere near it — byte-identical to before the
        // context field existed. (Only `us:dl`/`us:passport` are gated; everything else
        // is unconditional, recall-first.)
        assert!(
            flagged_by(
                "ssn",
                "the value 457-55-1234 is in this long unrelated padded sentence"
            ),
            "a dashed SSN with no keyword must still fire (context: None, unchanged)"
        );
        assert!(
            flagged_by(
                "itin",
                "no keyword nearby just 912-70-1234 floating in the text"
            ),
            "an ITIN with no keyword must still fire (context: None, unchanged)"
        );
    }

    // ===================================================================
    // Never-panic over adversarial input (empty / non-digit / huge / unicode).
    // ===================================================================

    #[test]
    fn validators_never_panic_on_adversarial_input() {
        let nasty: Vec<String> = vec![
            String::new(),
            " ".to_string(),
            "----".to_string(),
            "abcdefghi".to_string(),
            "12".to_string(),
            "9".repeat(10_000),
            "1234567890123456789012345".to_string(),
            "S1234567A".to_string(), // an SG NRIC, not a US id
            "café—résumé".to_string(),
            "0".repeat(100_000),
            "\u{0}\u{1}\u{7f}".to_string(),
            "AB123456\u{0}".to_string(),
        ];
        for s in &nasty {
            // None may panic; the result is irrelevant, only that each returns.
            let _ = ssn_valid(s);
            let _ = aba_valid(s);
            let _ = npi_valid(s);
            let _ = dea_valid(s);
            let _ = ein_valid(s);
        }
    }

    // ===================================================================
    // Engine-level: a multi-ID US snippet is flagged with the US pack ON, and a
    // no-locale engine attributes NONE of the US-specific rows. Audit breakdown
    // namespaces `locale:us:<name>`.
    // ===================================================================

    #[test]
    fn us_locale_flags_multi_id_snippet_and_namespaces_audit() {
        // A snippet with one valid instance of each checksum-backed US identifier plus
        // an ITIN. All values are SYNTHETIC spec vectors.
        let snippet = "SSN 212-34-5678, ABA 021000021, NPI 1234567893, DEA AB1234563, \
                       EIN 12-3456789, ITIN 912-70-1234";
        let e = us_engine();
        let cands = e.candidates(snippet);

        // Every dedicated row fired on its identifier (membership in the merged span's
        // recognizer list — the broad account/passport/dl rows overlap several of
        // these, so the PRIMARY may be a broad row; the specific row is still present).
        for name in ["ssn", "aba", "npi", "dea", "ein", "itin"] {
            assert!(
                cands.iter().any(|c| c.recognizers().contains(&us(name))),
                "US pack must flag {name} in {snippet:?}, got {cands:?}"
            );
        }

        // The audit breakdown counts each candidate's PRIMARY recognizer, namespacing
        // every US-attributed bucket under `locale:us:<name>` (never a bare `<name>=`
        // nor a `custom:`/`profile:` form — INJECTIVE). Assert the namespacing shape
        // rather than which specific row won an overlap tie (that is the label-ASC
        // merge rule, exercised elsewhere): every `us:` bucket reads `locale:us:…`.
        let breakdown = recognizer_breakdown(&cands);
        let us_buckets: Vec<&str> = breakdown
            .split(", ")
            .filter(|entry| entry.contains("us:"))
            .collect();
        assert!(
            !us_buckets.is_empty(),
            "expected some us: buckets, got {breakdown:?}"
        );
        for entry in &us_buckets {
            assert!(
                entry.starts_with("locale:us:"),
                "every US bucket must be namespaced `locale:us:…`, got {entry:?} in {breakdown:?}"
            );
        }
        // The six identifiers each yield one primary-attributed candidate, all under
        // the `locale:us:` namespace (ssn/aba/account/dea/dl/itin per the label-ASC
        // overlap tie-break — what matters here is they are all `locale:us:…=1`).
        assert_eq!(
            us_buckets.len(),
            6,
            "six US-attributed buckets, got {breakdown:?}"
        );
        for entry in &us_buckets {
            assert!(
                entry.ends_with("=1"),
                "each US identifier appears once, got {entry:?}"
            );
        }
    }

    #[test]
    fn no_locale_engine_attributes_no_us_specific_rows() {
        // Without the US pack enabled, none of the US-specific rows fire. (The broad
        // GLOBAL built-ins may incidentally cover some shapes — e.g. `phone` over a
        // digit run — but NO candidate is attributed to a `us:*` locale recognizer.)
        let snippet = "SSN 212-34-5678, ABA 021000021, NPI 1234567893, DEA AB1234563, \
                       EIN 12-3456789, ITIN 912-70-1234";
        let bare = RedactionEngine::builder().build().unwrap();
        let cands = bare.candidates(snippet);
        assert!(
            !cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Locale(l) if l.starts_with("us:"))),
            "a no-locale engine must not attribute any candidate to a us:* recognizer, got {cands:?}"
        );
    }

    #[test]
    fn checksum_rows_are_hard_gates_dropping_invalid_instances() {
        // The validate hard gate: a checksum-INVALID instance of a checksum-backed row
        // is NOT flagged by THAT row (it may still be covered by a broad built-in, but
        // never attributed to the us:<row> recognizer).
        // ABA with a corrupted check digit.
        assert!(
            !flagged_by("aba", "ABA 021000020 here"),
            "checksum-invalid ABA dropped"
        );
        // NPI with a corrupted check digit.
        assert!(
            !flagged_by("npi", "NPI 1234567890 here"),
            "checksum-invalid NPI dropped"
        );
        // SSN with a known-fake value.
        assert!(
            !flagged_by("ssn", "SSN 078-05-1120 here"),
            "known-fake SSN dropped"
        );
        // DEA with a bad registrant letter.
        assert!(
            !flagged_by("dea", "Rx IB1234563"),
            "bad-registrant DEA dropped"
        );
        // EIN with a denied prefix.
        assert!(
            !flagged_by("ein", "EIN 07-1234567"),
            "denied-prefix EIN dropped"
        );
        // Sanity: the VALID counterparts ARE flagged by their row.
        assert!(flagged_by("aba", "ABA 021000021 here"));
        assert!(flagged_by("npi", "NPI 1234567893 here"));
        assert!(flagged_by("ssn", "SSN 212-34-5678 here"));
        assert!(flagged_by("dea", "Rx AB1234563"));
        assert!(flagged_by("ein", "EIN 12-3456789"));
    }

    // ---- US ZIP rows ----

    #[test]
    fn zip_row_catches_zip4_and_state_zip5() {
        // ZIP+4 is distinctive; STATE + ZIP5 is bound by the state.
        assert!(flagged_by("zip", "Mail to 94043-1351 by Friday."));
        assert!(flagged_by("zip", "The office at CA 94043 is closed."));
        // A bare 5-digit run with NO state and NO keyword is NOT attributed to us:zip.
        assert!(
            !flagged_by("zip", "lucky number 94043 was drawn"),
            "a bare 5-digit run must not flag as us:zip (needs +4 or a state)"
        );
    }

    #[test]
    fn zip_bare_row_is_context_gated_and_aggressive() {
        assert!(flagged_by("zip-bare", "ZIP 94043 on the form"));
        assert!(flagged_by("zip-bare", "mailing address 94043 west"));
        assert!(
            !flagged_by("zip-bare", "widget 94043 shipped today"),
            "bare 5-digit with no zip/address keyword is gated out"
        );
        assert!(
            us_engine().is_aggressive(&us("zip-bare")),
            "zip-bare is advisory"
        );
        assert!(
            !us_engine().is_aggressive(&us("zip")),
            "us:zip is precise/default-on"
        );
    }
}
