// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canada (`ca`) jurisdiction recognizer pack.
//!
//! One self-contained file of DATA ROWS — the unit a parallel fan-out adds per
//! jurisdiction (template: `packs/sg.rs`). It exposes exactly [`rows`]; `packs/mod.rs`
//! maps `Locale::Canada` to it via the single append-only registration seam (see the
//! "ADDING A JURISDICTION" comment there). Nothing jurisdiction-specific leaks into
//! shared code: the namespaced audit label (`ca:sin`, `ca:ohip`, …) is assembled by
//! the engine from this jurisdiction's [`Locale::label`](crate::Locale::label) prefix
//! (`ca`) + each row's bare `name`.
//!
//! ## Posture (matches the recognizer-pack spec, "PACK 4 — CANADA")
//!
//! Two tiers, recall-first throughout (a checksum NEVER silently drops a real ID — it
//! is attached ONLY where a real identifier always passes it):
//!
//! - **checksum-backed** (`validate: Some(..)`): CA-1 SIN, CA-2 Ontario OHIP, and
//!   CA-3 BC PHN. These are the high-precision / low-false-flag rows.
//! - **format-only** (`validate: None`): CA-4/5 RAMQ/PHIN, CA-6/7 passport/DL, CA-8
//!   Business Number, CA-9 bank transit. A national ID whose check is a lookup table
//!   or an UNPUBLISHED algorithm stays format-only rather than risk a transcription
//!   error becoming a confidentiality MISS.
//!
//! The validators below strip separators (`-`, space) before any math, so the broad
//! recall-first regex (which allows those separators) and the validator agree on the
//! digit body. All validators are PURE integer compute — no allocation of matter data
//! beyond the matched slice, no RNG, no I/O, deterministic, never panic.

use super::validators::{mod10_valid, weighted_mod_n};
use super::LocaleRecognizer;

/// The Canada recognizer rows. Returns a `'static` slice so enabling the pack copies
/// nothing — the engine compiles the rows it is told to.
///
/// Adding ANOTHER CA recognizer later is a single extra [`LocaleRecognizer`] row in
/// this slice — no other file changes.
pub fn rows() -> &'static [LocaleRecognizer] {
    &[
        // ---- CA-1 SIN (Social Insurance Number) — checksum-backed ----
        // Shape: first digit ∈ {1–7, 9} (0 and 8 are NOT issued), then 8 more digits
        // in the 3-3-3 grouping with OPTIONAL separators. NOTE: the spec's "medium"
        // form uses a `\1` BACKREFERENCE to require a CONSISTENT separator — but the
        // `regex` crate is deliberately backref-free (linear-time, no ReDoS), so a
        // backref does not compile here. We therefore allow independent optional
        // separators (recall-first: over-match slightly rather than miss) and lean
        // ENTIRELY on the validator for precision. The validator is the real gate:
        // standard Luhn over the 9 digits AND first digit ∉ {0, 8}. CRITICAL (do NOT
        // collapse the two checks): `046454286` is Luhn-VALID yet an INVALID SIN
        // (leading 0). Luhn alone is insufficient.
        LocaleRecognizer {
            name: "sin",
            pattern: r"\b[1-79]\d{2}[- ]?\d{3}[- ]?\d{3}\b",
            validate: Some(ca_sin_valid),
            context: None,
            aggressive: false, // Luhn + first-digit issuance rule — precise.
        },
        // ---- CA-2 Ontario OHIP health card — checksum-backed ----
        // 10 digits (4-3-3, optional separators) + an OPTIONAL 2-letter version code.
        // Validator: Luhn over the 10 NUMERIC digits only (the version letters are
        // excluded because the validator sums digits and ignores everything else).
        LocaleRecognizer {
            name: "ohip",
            pattern: r"\b\d{4}[- ]?\d{3}[- ]?\d{3}([- ]?[A-Z]{2})?\b",
            validate: Some(ca_ohip_valid),
            context: None,
            aggressive: false, // Luhn over the 10 numeric digits — precise.
        },
        // ---- CA-3 BC PHN (Personal Health Number) — checksum-backed (mod-11) ----
        // Leading 9 + 9 more digits. Validator: MOD-11 weighted check over the 8 body
        // digits, reject if the computed check is 10 or 11. See `ca_bc_phn_valid` —
        // the WEIGHT VECTOR is UNCONFIRMED and flagged confirm-before-shipping.
        LocaleRecognizer {
            name: "phn",
            pattern: r"\b9\d{9}\b",
            validate: Some(ca_bc_phn_valid),
            context: None,
            aggressive: false, // mod-11 weighted checksum — precise.
        },
        // ---- CA-4 RAMQ (Quebec health insurance) — format-only ----
        // 4 letters + 8 digits (4-4). The check is a non-reproducible lookup → no
        // checksum (recall-first: never risk a silent miss). Context-leaning.
        LocaleRecognizer {
            name: "ramq",
            pattern: r"\b[A-Z]{4}[- ]?\d{4}[- ]?\d{4}\b",
            validate: None,
            context: None,
            // PRECISE: a distinctive 4-letter + 8-digit shape (not a bare digit run and
            // not a DL/passport/account row), so it keeps full locale priority.
            aggressive: false,
        },
        // ---- CA-5 PHIN (Manitoba) — format-only ----
        // 9 digits, leading 1. No published checksum → format-only.
        LocaleRecognizer {
            name: "phin",
            pattern: r"\b1\d{8}\b",
            validate: None,
            context: None,
            // PRECISE (kept): a leading-1 provincial health-number row — a national-ID
            // category, not a DL/passport/account/bank row, so outside the aggressive set.
            aggressive: false,
        },
        // ---- CA-6 passport — format-only ----
        // Two issued shapes: 2 letters + 6 digits, or 1 letter + 6 digits + 2 letters.
        // No checksum (context-required in practice). FOLLOW-UP: spec CA-6 marks this
        // context-required; a future pass could `context`-gate it via the new slot. Left
        // `None` (recall-first) here to keep this fix focused on the `us:dl` flood — the
        // CA passport shape (2 letters + 6 digits, or 1 letter + 6 digits + 2 letters) is
        // distinctive enough that it is not the catastrophic over-matcher `us:dl` was.
        LocaleRecognizer {
            name: "passport",
            pattern: r"\b([A-Z]{2}\d{6}|[A-Z]\d{6}[A-Z]{2})\b",
            validate: None,
            context: None,
            // AGGRESSIVE: a format-only passport shape (no checksum) — last-resort LABEL,
            // demoted below precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        // ---- CA-7 driver's licence (ON / QC) — format-only ----
        // Distinctive provincial shapes only (ON: letter + 4-5-5 with optional
        // hyphens; QC: letter + 12 digits). BC/AB have no distinctive national format
        // → omitted in v1 (bare digit runs = catastrophic false positives).
        LocaleRecognizer {
            name: "dl-on",
            pattern: r"\b[A-Z]\d{4}-?\d{5}-?\d{5}\b",
            validate: None,
            // FOLLOW-UP: spec CA-7 marks DL context-required; left `None` (recall-first)
            // to keep this fix focused. The ON shape (letter + 14 digits, 15 chars) and
            // the QC shape (letter + 12 digits) are DISTINCTIVE — not the catastrophic
            // bare letter/digit over-matcher `us:dl` was — so they do not flood.
            context: None,
            // AGGRESSIVE: a driver's-licence row (format-only, no validator) — last-resort
            // LABEL, demoted below precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        LocaleRecognizer {
            name: "dl-qc",
            pattern: r"\b[A-Z]\d{12}\b",
            validate: None,
            context: None,
            // AGGRESSIVE: a driver's-licence row (format-only, no validator) — last-resort
            // LABEL, demoted below precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        // ---- CA-8 Business Number (BN15, suffixed form) — format-only ----
        // Match the 15-char SUFFIXED form PREFERENTIALLY (BN9 + a program-account
        // suffix: RT/RC/RP/RM/RR/RZ + 4 digits). Matching the suffixed form (rather
        // than a bare BN9 = `\d{9}`) avoids STEALING SIN matches, since a bare 9-digit
        // run is indistinguishable from a SIN body. Validator: NONE / format-only — a
        // BN9 Luhn check is COMMUNITY-SOURCED and CRA does NOT publish it; hard-gating
        // an unconfirmed checksum would risk a recall-first MISS (spec CA-8). If a
        // confirmed Luhn ever lands it ships as a BOOSTER, never a hard reject.
        LocaleRecognizer {
            name: "bn",
            pattern: r"\b\d{9}[- ]?(RT|RC|RP|RM|RR|RZ)[- ]?\d{4}\b",
            validate: None,
            context: None,
            // PRECISE (kept): the program-account suffix (RT/RC/.../RZ) makes the BN15 a
            // DISTINCTIVE structural shape, not a bare account/digit run — outside the
            // aggressive set, so it keeps full locale priority.
            aggressive: false,
        },
        // ---- CA-9 bank transit / MICR — format-only ----
        // 5-digit branch transit + 3-digit institution (MICR layout). No checksum →
        // format-only, context-leaning.
        LocaleRecognizer {
            name: "transit",
            pattern: r"\b\d{5}[- ]\d{3}\b",
            validate: None,
            context: None,
            // AGGRESSIVE: a bank transit/MICR row (format-only digit run, no checksum) —
            // last-resort LABEL, demoted below precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        // CA-10 POSTAL CODE (spec §"ADDRESS FAMILY — LOCALE POSTAL", CA-POST): the
        // Canadian `A1A 1A1` forward-sortation + local-delivery shape (letter-digit-letter,
        // optional space, digit-letter-digit), e.g. `K1A 0B1`, `M5V 2T6`. Recall-first (it
        // does NOT restrict to the valid FSA first-letter set — a miss is the leak). The
        // alternating letter/digit shape is DISTINCTIVE, so CONTEXT:NONE and PRECISE
        // (structural → CAREFUL review — no `postal` class lexicon, so never High). Audit
        // `ca:postal`; type label "postal code".
        LocaleRecognizer {
            name: "postal",
            pattern: r"\b[A-Za-z]\d[A-Za-z] ?\d[A-Za-z]\d\b",
            validate: None,
            context: None,
            aggressive: false,
        },
    ]
}

/// CA-1 SIN validator — the headline two-checks trap.
///
/// A real Canadian SIN satisfies BOTH, INDEPENDENTLY:
///   1. standard Luhn (mod-10) over the 9 digits, AND
///   2. the first digit is a digit Service Canada actually issues (NOT 0, NOT 8).
///
/// These are SEPARATE checks and must NOT be collapsed: `046454286` PASSES Luhn but
/// is an INVALID SIN because its leading digit is 0. (Equally `812345678` would be
/// rejected on the first-digit rule even though it would also fail Luhn here.) We do
/// NOT copy pear/Validate_CA's leading-`3` rejection — only 0 and 8 are unissued.
///
/// Recall-first: a REAL SIN always passes both checks, so this validator can only ever
/// filter NON-SINs, never miss a true one. Pure integer compute; never panics.
fn ca_sin_valid(s: &str) -> bool {
    // Strip separators to the 9-digit body. The medium-recall regex already pins the
    // shape, but the validator re-derives the digits so it is self-contained.
    let digits: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    if digits.len() != 9 {
        return false;
    }
    // CHECK 2 (first-digit rule) — kept SEPARATE from Luhn. 0 and 8 are not issued.
    let first = digits[0];
    if first == 0 || first == 8 {
        return false;
    }
    // CHECK 1 (Luhn) — the general mod-10 engine over the same 9 digits. `mod10_valid`
    // ignores non-digits, so passing the raw separator'd string would also work, but
    // we pass the canonical digit string to keep the two checks reading independently.
    let body: String = digits.iter().map(|d| char::from(d + b'0')).collect();
    mod10_valid(&body)
}

/// CA-2 Ontario OHIP validator — Luhn over the 10 NUMERIC digits.
///
/// The raw match may carry a trailing 2-letter version code; `mod10_valid` filters
/// non-digits, so the version letters are excluded automatically. We additionally
/// require EXACTLY 10 digits so a longer/shorter run cannot sneak through. Recall-first:
/// a real OHIP number always passes Luhn, so this only filters non-OHIP runs.
fn ca_ohip_valid(s: &str) -> bool {
    let digit_count = s.bytes().filter(u8::is_ascii_digit).count();
    if digit_count != 10 {
        return false;
    }
    mod10_valid(s)
}

/// CA-3 BC PHN validator — MOD-11 weighted check digit.
///
/// Layout: a leading `9`, then an 8-digit body, then a check digit (10 digits total).
/// The check is a weighted mod-11: weight the 8 body digits, take the sum mod 11, the
/// check digit is `11 - (sum % 11)`; a computed value of 10 or 11 means NO valid PHN
/// has that body, so reject. We then require the computed check to EQUAL the stored
/// last digit.
///
/// ⚠️ CONFIRM-BEFORE-SHIPPING — the WEIGHT VECTOR `[2, 4, 8, 5, 10, 9, 7, 3]` is the
/// value cited in the recognizer-pack spec (CA-3) but is NOT confirmed against the
/// primary source (BC TELEPLAN v4.4). If the real weights differ, attaching this as a
/// HARD gate could turn a real PHN into a recall MISS. Do NOT promote this past the
/// opt-in pack (it is OFF by default) without verifying the weights against TELEPLAN.
/// This is the one row whose `Some(..)` validator carries primary-source risk; the
/// safer fallback if the confirm fails is to drop to `validate: None` (format-only).
fn ca_bc_phn_valid(s: &str) -> bool {
    // ⚠️ UNCONFIRMED weights — see the doc comment. Confirm vs BC TELEPLAN v4.4.
    const PHN_WEIGHTS: [u32; 8] = [2, 4, 8, 5, 10, 9, 7, 3];

    let digits: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    if digits.len() != 10 || digits[0] != 9 {
        return false;
    }
    // Body = digits[1..9] (the 8 weighted positions); check = digits[9].
    let body = &digits[1..9];
    let check = digits[9];
    // `weighted_mod_n` returns the weighted sum mod 11 (it is inert / returns 0 on a
    // length mismatch, which cannot happen here since both slices are length 8).
    let r = weighted_mod_n(body, &PHN_WEIGHTS, 11);
    let computed = 11 - r; // in 1..=11
    if computed == 10 || computed == 11 {
        // No valid PHN check digit can be 10 or 11 — structurally rejected.
        return false;
    }
    u32::from(check) == computed
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the rows() table sanity ----

    #[test]
    fn rows_are_well_formed_and_namespaced_bare() {
        // Every row's regex compiles (the engine `expect`s this), names are bare
        // (no `ca:` prefix — the engine prepends the locale label), and the
        // checksum-vs-format tiering matches the spec.
        for row in rows() {
            regex::Regex::new(row.pattern)
                .unwrap_or_else(|e| panic!("CA row {:?} regex must compile: {e}", row.name));
            assert!(
                !row.name.contains(':'),
                "row name {:?} must be bare (engine adds the ca: prefix)",
                row.name
            );
        }
        // The three checksum-backed rows carry a validator; the rest are format-only.
        let backed: Vec<&str> = rows()
            .iter()
            .filter(|r| r.validate.is_some())
            .map(|r| r.name)
            .collect();
        assert_eq!(
            backed,
            vec!["sin", "ohip", "phn"],
            "exactly SIN/OHIP/PHN are checksum-backed; the rest are format-only"
        );
    }

    // ---- CA-1 SIN: the headline two-checks trap ----

    #[test]
    fn ca_sin_valid_accepts_the_spec_valids() {
        // Spec CA-1 VALID vectors (independently recomputed): Luhn-valid AND first
        // digit issued.
        for v in ["130 692 544", "435 418 165", "948 584 792"] {
            assert!(ca_sin_valid(v), "SIN {v:?} should be VALID");
        }
        // Separator-agnostic: the same body with dashes or no separators also validates.
        assert!(ca_sin_valid("130-692-544"));
        assert!(ca_sin_valid("130692544"));
    }

    #[test]
    fn ca_sin_checksum_invalid_rejected() {
        // Spec CA-1 INVALID (checksum): a corrupted check digit fails Luhn.
        assert!(!ca_sin_valid("130 692 545"));
    }

    #[test]
    fn ca_sin_first_digit_8_rejected() {
        // Spec CA-1 INVALID (first digit): leading 8 is not issued.
        assert!(!ca_sin_valid("812 345 678"));
    }

    #[test]
    fn ca_sin_046454286_is_luhn_valid_but_invalid_sin() {
        // THE HEADLINE TRAP. `046454286` PASSES standard Luhn but is an INVALID SIN
        // because its first digit is 0 (unissued). The validator MUST reject it — the
        // two checks are SEPARATE and must not be collapsed into "just Luhn".
        // Prove the premise (it really is Luhn-valid) so a future refactor that breaks
        // the first-digit check can't hide behind a Luhn-failing fixture.
        assert!(
            mod10_valid("046454286"),
            "premise: 046454286 IS Luhn-valid (so only the first-digit check rejects it)"
        );
        assert!(
            !ca_sin_valid("046 454 286"),
            "046454286 is Luhn-valid but an INVALID SIN (leading 0) — must be REJECTED"
        );
        assert!(!ca_sin_valid("046454286"), "same, separator-free");
    }

    // ---- CA-2 OHIP: Luhn over 10, version letters excluded ----

    #[test]
    fn ca_ohip_valid_accepts_spec_valids() {
        for v in ["1234567897", "5556667771", "1002003000"] {
            assert!(ca_ohip_valid(v), "OHIP {v:?} should be VALID");
        }
        // The optional 2-letter version code is EXCLUDED from the checksum: the same
        // 10 digits with a version suffix still validate (letters ignored).
        assert!(ca_ohip_valid("1234-567-897 AB"));
        assert!(ca_ohip_valid("1234567897XY"));
    }

    #[test]
    fn ca_ohip_checksum_invalid_rejected() {
        for v in ["1234567890", "5556667770"] {
            assert!(!ca_ohip_valid(v), "OHIP {v:?} should be checksum-INVALID");
        }
        // Wrong digit count is rejected even if the run happens to be Luhn-shaped.
        assert!(
            !ca_ohip_valid("123456789"),
            "9 digits is not an OHIP number"
        );
        assert!(
            !ca_ohip_valid("12345678901"),
            "11 digits is not an OHIP number"
        );
    }

    // ---- CA-3 BC PHN: mod-11 (unconfirmed weights, confirm-before-ship) ----

    #[test]
    fn ca_bc_phn_self_consistent_vector_validates() {
        // No published valid PHN vector exists (the very signal the weights are
        // unconfirmed). `9000000018` is SELF-CONSISTENT under the cited weight vector
        // `[2,4,8,5,10,9,7,3]` (body 00000001 -> sum%11=3 -> check 8). It validates; a
        // corrupted check digit does not. If the weights are later corrected, THIS
        // fixture changes with them.
        assert!(
            ca_bc_phn_valid("9000000018"),
            "self-consistent PHN should validate"
        );
        assert!(
            !ca_bc_phn_valid("9000000019"),
            "corrupted PHN check digit rejected"
        );
    }

    #[test]
    fn ca_bc_phn_structural_rejections() {
        assert!(!ca_bc_phn_valid("0000000000"), "must start with 9");
        assert!(
            !ca_bc_phn_valid("912345678"),
            "9 digits is too short for a PHN"
        );
        assert!(
            !ca_bc_phn_valid("91234567890"),
            "11 digits is too long for a PHN"
        );
    }

    // ---- never-panic over hostile / malformed input ----

    #[test]
    fn validators_never_panic_on_hostile_input() {
        // Multibyte / empty / control / oversized inputs must be inert, never panic
        // (deterministic boolean, no slicing a str mid-codepoint).
        let hostile = [
            "",
            "   ",
            "你好世界",
            "S\u{0}1\u{1}2",
            "9999999999999999999999999999999999999999",
            "------",
            "RT0001",
        ];
        for s in hostile {
            // Each validator must just return a bool.
            let _ = ca_sin_valid(s);
            let _ = ca_ohip_valid(s);
            let _ = ca_bc_phn_valid(s);
        }
    }

    // ---- CA-10 POSTAL CODE ----

    #[test]
    fn postal_row_catches_a1a_1a1_shape() {
        use crate::{Locale, Recognizer, RedactionEngine};
        use std::sync::Arc;
        let e = RedactionEngine::builder()
            .locales([Locale::Canada])
            .build()
            .unwrap();
        let ca_postal = Recognizer::Locale(Arc::from("ca:postal"));
        for (text, needle) in [
            ("ship to K1A 0B1 depot", "K1A 0B1"),
            ("addr M5V 2T6 Toronto", "M5V 2T6"),
            ("code H0H0H0 north pole", "H0H0H0"), // no-space variant
        ] {
            let cands = e.candidates(text);
            assert!(
                cands
                    .iter()
                    .any(|c| c.recognizers().contains(&ca_postal)
                        && c.matched_value().contains(needle)),
                "ca:postal must catch {needle:?} in {text:?}, got {cands:?}"
            );
        }
        // A SIN-shaped digit run must NOT be mislabelled a postal code.
        let cands = e.candidates("SIN 046 454 286 on file");
        assert!(
            !cands.iter().any(|c| c.recognizers().contains(&ca_postal)),
            "a SIN must not flag as ca:postal, got {cands:?}"
        );
    }
}
