// SPDX-License-Identifier: AGPL-3.0-or-later
//! Australia (`au`) jurisdiction recognizer pack.
//!
//! One self-contained file of DATA ROWS — the unit a parallel fan-out adds per
//! jurisdiction (see `packs/sg.rs` for the template and the "ADDING A JURISDICTION"
//! seam in `packs/mod.rs`). It exposes exactly [`rows`]; `packs/mod.rs` maps
//! `Locale::Australia` to it via the single append-only registration seam. Nothing
//! jurisdiction-specific leaks into shared code: the namespaced audit label
//! (`au:tfn`, `au:abn`, …) is assembled by the engine from this jurisdiction's
//! [`Locale::label`](crate::Locale::label) prefix (`au`) + each row's bare `name`.
//!
//! ## Recall-first posture (crate invariant)
//!
//! Each `validate` predicate below is attached ONLY to an identifier whose REAL
//! instances ALWAYS satisfy the published checksum, so the validator can only ever
//! FILTER non-instances — never silently MISS a true one (the one failure this crate
//! refuses). The four core IDs (TFN/ABN/ACN/Medicare) carry real, reproducible
//! checksums from primary specs (ATO / ABR / ASIC / Services Australia), so they get
//! `validate: Some(..)`. The passport / driver's-licence / BSB rows have NO national
//! checksum (a state-by-state "zoo" with no recomputable digit), so they stay
//! `validate: None` (format-only, recall-first) — see each row's note.
//!
//! ## Validators (pure integer compute, never panic, deterministic — no RNG/I/O)
//!
//! Each validator strips separators, length-gates, and runs the published weighted
//! checksum over the in-process matched slice only. They are jurisdiction-SPECIFIC
//! (the weights/moduli are AU's), so they live HERE alongside the rows that use them,
//! composing the GENERIC helper in [`super::validators`] (`weighted_mod_n`) rather
//! than re-implementing the arithmetic. A length mismatch / out-of-range input returns
//! `false` (a clean non-match), never a panic.

use super::validators::weighted_mod_n;
use super::LocaleRecognizer;

/// Extract the ASCII-digit VALUES (0–9) of `s` into a small `Vec` (separators `-`,
/// space, `.`, `/` ignored). The matched slices are short national IDs, so this
/// allocation is bounded by the recognizer regex.
fn digit_values(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect()
}

/// AU-1 TFN (Tax File Number) — ATO weighted mod-11.
///
/// 9-digit form: weights `[1,4,3,7,5,8,6,9,10]`, valid iff `Σ(dᵢ·wᵢ) % 11 == 0`.
/// 8-digit (older) form: weights `[10,7,8,4,6,3,5,1]`, same `% 11 == 0` rule. The
/// check digit is the LAST digit and is INCLUDED in the weighted sum (it is not split
/// off), so the whole number is weighted and the total must be ≡ 0 (mod 11). The
/// weakest AU checksum (≈1/11 pass-by-chance) — paired with a `tfn`/`tax file number`
/// context keyword in practice, but the checksum still supplies real precision here.
fn tfn_valid(s: &str) -> bool {
    let d = digit_values(s);
    let weights: &[u32] = match d.len() {
        9 => &[1, 4, 3, 7, 5, 8, 6, 9, 10],
        8 => &[10, 7, 8, 4, 6, 3, 5, 1],
        _ => return false,
    };
    weighted_mod_n(&d, weights, 11) == 0
}

/// AU-2 ABN (Australian Business Number) — ABR mod-89.
///
/// 11 digits. The published algorithm SUBTRACTS 1 FROM THE FIRST DIGIT, then weights
/// the (modified) 11 digits by `[10,1,3,5,7,9,11,13,15,17,19]` and requires the sum
/// ≡ 0 (mod 89). (Weights up to 19 × 9 keep the per-position product small; the shared
/// helper is saturating regardless.) A valid ABN never starts with 0 — the regex
/// `[1-9]` already excludes a leading 0, and the mod-89 check is the precision lever.
fn abn_valid(s: &str) -> bool {
    let mut d = digit_values(s);
    if d.len() != 11 {
        return false;
    }
    // SUBTRACT 1 FROM THE FIRST DIGIT (the documented ABR step). d[0] came from the
    // `[1-9]` regex class, so it is ≥ 1 and this never underflows; guard anyway so the
    // validator can never panic on an unexpected caller.
    if d[0] == 0 {
        return false;
    }
    d[0] -= 1;
    const W: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    weighted_mod_n(&d, &W, 89) == 0
}

/// AU-3 ACN (Australian Company Number) — ASIC complement mod-10.
///
/// 9 digits. Weight the FIRST 8 digits by `[8,7,6,5,4,3,2,1]`, take the remainder
/// `sum % 10`, then the check digit is the COMPLEMENT `(10 - (sum % 10)) % 10` — the
/// `% 10` form, NOT a bare `10 - remainder` (the bare form yields 10 when the remainder
/// is 0, mishandling a multiple-of-10 sum; ASIC's complement is 0 there). Valid iff
/// that complement equals the 9th digit.
///
/// Shares the 9-digit shape with the TFN (an ALIAS): both packs run on the same digit
/// run, and the two DIFFERING checksums disambiguate — a true ACN passes ACN's check,
/// a true TFN passes TFN's; context keywords resolve the rare digit run that happens to
/// satisfy both.
fn acn_valid(s: &str) -> bool {
    let d = digit_values(s);
    if d.len() != 9 {
        return false;
    }
    const W: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    let remainder = weighted_mod_n(&d[..8], &W, 10); // sum % 10
    let complement = (10 - remainder) % 10; // the %10 form — NOT bare 10-remainder
    complement == u32::from(d[8])
}

/// AU-4 Medicare card number — Services Australia weighted mod-10.
///
/// The first digit must be in `2..=6` (the biggest precision lever — also enforced by
/// the regex `[2-6]`). Weight the FIRST 8 DIGITS by `[1,3,7,9,1,3,7,9]` and require
/// `sum % 10 == d[8]` (the 9th digit is the check digit). Digits 10–11 (the issue
/// number and IRN) are NOT part of the checksum, so the validator inspects only the
/// first 9 digits even when the match includes a trailing issue/IRN digit.
fn medicare_valid(s: &str) -> bool {
    let d = digit_values(s);
    if d.len() < 9 {
        return false;
    }
    if !(2..=6).contains(&d[0]) {
        return false;
    }
    const W: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    weighted_mod_n(&d[..8], &W, 10) == u32::from(d[8])
}

/// The Australia recognizer rows. Returns a `'static` slice so enabling the pack
/// copies nothing — the engine compiles the rows it is told to.
///
/// Adding ANOTHER AU recognizer later is a single extra [`LocaleRecognizer`] row in
/// this slice — no other file changes.
pub fn rows() -> &'static [LocaleRecognizer] {
    &[
        // AU-1 TFN (Tax File Number). 8- or 9-digit, common ` `/`-` grouping. The ATO
        // mod-11 checksum supplies precision (recall-first: separators allowed, the
        // `\b` bounds keep it from matching mid-token). Audit label `au:tfn`.
        LocaleRecognizer {
            name: "tfn",
            pattern: r"\b\d{3}[ -]?\d{3}[ -]?\d{2,3}\b",
            validate: Some(tfn_valid),
            context: None,
            aggressive: false, // ATO weighted mod-11 checksum — precise.
        },
        // AU-2 ABN (Australian Business Number). 11 digits, first never 0, common
        // 2-3-3-3 grouping. ABR mod-89 (subtract-1-from-first-digit) is the precision
        // lever. Audit label `au:abn`.
        LocaleRecognizer {
            name: "abn",
            pattern: r"\b[1-9]\d[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}\b",
            validate: Some(abn_valid),
            context: None,
            aggressive: false, // ABR mod-89 checksum — precise.
        },
        // AU-3 ACN (Australian Company Number). 9 digits, common 3-3-3 grouping. ASIC
        // complement mod-10. Aliases the TFN's 9-digit shape — the differing checksum
        // disambiguates (context resolves the rare both-pass case). Audit label
        // `au:acn`.
        LocaleRecognizer {
            name: "acn",
            pattern: r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b",
            validate: Some(acn_valid),
            context: None,
            aggressive: false, // ASIC complement mod-10 checksum — precise.
        },
        // AU-4 Medicare card number. First digit 2–6 (regex-gated, the biggest
        // precision lever), then 4-5-1 with an OPTIONAL trailing issue/IRN digit (not
        // part of the checksum). Services Australia weighted mod-10 over the first 8
        // digits. Audit label `au:medicare`.
        LocaleRecognizer {
            name: "medicare",
            pattern: r"\b[2-6]\d{3}[ -]?\d{5}[ -]?\d(?:[ /-]?\d)?\b",
            validate: Some(medicare_valid),
            context: None,
            aggressive: false, // Services Australia weighted mod-10 checksum — precise.
        },
        // AU-5 Passport. One or two leading letters + 7 digits. FORMAT-ONLY
        // (recall-first): an AU passport has no public check digit to recompute, so a
        // checksum would risk a SILENT MISS — left `validate: None`. The letter-prefix +
        // 7 digits keeps it from matching bare digit runs. CONTEXT-GATED (spec AU-5/6:
        // "OFF-by-default/context-required only") via the new `LocaleRecognizer::context`
        // slot: the candidate SURVIVES only with a passport keyword in-window (or a
        // normal recognizer also covering the span). Recall-first holds — a real passport
        // near "passport" still fires; only the keyword-less collisions are suppressed.
        // Audit label `au:passport`.
        LocaleRecognizer {
            name: "passport",
            pattern: r"\b[A-Z]{1,2}\d{7}\b",
            validate: None,
            context: Some(&["passport", "passport no", "passport number", "passport #"]),
            // AGGRESSIVE: a format-only letter+7-digit shape (no checksum) — last-resort
            // LABEL, demoted below precise rows. (Orthogonal to the `context` fire/drop gate.)
            aggressive: true,
        },
        // AU-6 Driver's licence. AU has NO national DL format — each state/territory
        // issues its own shape (a "zoo"), and bare 6–10 digit runs would be a
        // CATASTROPHIC false-positive source (the spec's explicit warning). So this row
        // deliberately REFUSES to match a bare digit run: it requires a LEADING LETTER
        // (the state-prefixed alphanumeric DL shapes, e.g. SA/NSW), then 5–9 more
        // alphanumerics (6–10 chars total). The `regex` crate is RE2-style (no
        // lookaround — that is the crate's linear-time / no-ReDoS invariant), so the
        // "contains a letter" precision is expressed by anchoring the letter
        // positionally rather than with a lookahead. No national checksum to recompute,
        // so `validate: None`. CONTEXT-GATED (spec AU-5/6: "OFF-by-default/context-
        // required only" — bare letter+alnum runs are a catastrophic FP source, exactly
        // the `us:dl` failure mode) via the new `LocaleRecognizer::context` slot: the
        // candidate SURVIVES only with a driver's-licence keyword in-window (or a normal
        // recognizer also covering the span). Recall-first holds — a real DL near
        // "licence"/"driver" still fires; only the keyword-less noise is dropped. Audit
        // label `au:drivers-licence`.
        LocaleRecognizer {
            name: "drivers-licence",
            pattern: r"\b[A-Z][A-Z0-9]{5,9}\b",
            validate: None,
            context: Some(&[
                "driver", "drivers", "driving", "licence", "license", "dl no", "dl#",
            ]),
            // AGGRESSIVE: state DL "zoo", no national format — a catastrophic-FP letter+alnum
            // run. Last-resort LABEL, demoted below precise rows. (Orthogonal to the `context`
            // fire/drop gate above.)
            aggressive: true,
        },
        // AU-7 BSB + account. The Bank-State-Branch code is a 6-digit `\d{3}-\d{3}`
        // (the hyphenated 3-3 punctuation is the signal), optionally followed by a
        // 4–10 digit account number. FORMAT-ONLY: the BSB has no self-check digit
        // (it indexes the APCA BSB directory), so `validate: None`; context-leaning
        // (`BSB`/`account`). Audit label `au:bsb`.
        LocaleRecognizer {
            name: "bsb",
            pattern: r"\b\d{3}-\d{3}(?:[ -]?\d{4,10})?\b",
            validate: None,
            context: None,
            // AGGRESSIVE: the BSB has no self-check digit (it indexes the APCA directory) —
            // a format-only bank-routing run. Last-resort LABEL, demoted below precise rows
            // (still fires; recall-neutral).
            aggressive: true,
        },
        // AU-8 POSTCODE (spec §"ADDRESS FAMILY — LOCALE POSTAL", AU-POST): a 4-digit
        // postcode is hopelessly broad on its own, so it is bound by an INLINE state/
        // territory abbreviation (`NSW 2000`, `VIC 3000`, `ACT 2601`). The state prefix
        // makes it precise, so CONTEXT:NONE and PRECISE (structural → CAREFUL review — no
        // `postcode` class lexicon, so never High). Audit `au:postcode`; type "postal code".
        LocaleRecognizer {
            name: "postcode",
            pattern: r"\b(?:NSW|VIC|QLD|SA|WA|TAS|NT|ACT)\s+\d{4}\b",
            validate: None,
            context: None,
            aggressive: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AU-1 TFN (ATO weighted mod-11) ----
    #[test]
    fn tfn_checksum_vectors() {
        // Spec AU-1 VALID (9-digit, ATO weights [1,4,3,7,5,8,6,9,10], sum%11==0).
        for v in ["123456782", "876543210", "555555556"] {
            assert!(tfn_valid(v), "TFN {v} must validate");
        }
        // Spec AU-1 INVALID (checksum-broken, same 9-digit shape).
        for v in ["123456783", "876543211", "123456789"] {
            assert!(!tfn_valid(v), "TFN {v} must NOT validate");
        }
        // Separators are stripped before the checksum (recall-first grouping).
        assert!(tfn_valid("123 456 782"));
        assert!(tfn_valid("123-456-782"));
        // Wrong length never validates (clean non-match, never a panic).
        assert!(!tfn_valid("1234567"));
        assert!(!tfn_valid("1234567820"));
    }

    // ---- AU-2 ABN (ABR mod-89, subtract 1 from first digit) ----
    #[test]
    fn abn_checksum_vectors() {
        for v in ["51682616150", "83123456790", "51824753556"] {
            assert!(abn_valid(v), "ABN {v} must validate");
        }
        for v in ["51682616151", "83123456791", "12345678011"] {
            assert!(!abn_valid(v), "ABN {v} must NOT validate");
        }
        // Grouped form still validates (separators stripped).
        assert!(abn_valid("51 682 616 150"));
        assert!(abn_valid("51-682-616-150"));
        // Wrong length never validates.
        assert!(!abn_valid("5168261615"));
        assert!(!abn_valid("516826161500"));
    }

    // ---- AU-3 ACN (ASIC complement mod-10, the (10-(sum%10))%10 form) ----
    #[test]
    fn acn_checksum_vectors() {
        for v in ["123456780", "987654320", "004085616"] {
            assert!(acn_valid(v), "ACN {v} must validate");
        }
        for v in ["123456781", "987654321", "111222337"] {
            assert!(!acn_valid(v), "ACN {v} must NOT validate");
        }
        // Grouped form still validates.
        assert!(acn_valid("123 456 780"));
        assert!(acn_valid("004 085 616"));
        // Wrong length never validates.
        assert!(!acn_valid("12345678"));
        assert!(!acn_valid("1234567800"));
    }

    // ---- AU-4 Medicare (first digit 2..6; weighted mod-10 over first 8 digits) ----
    #[test]
    fn medicare_checksum_vectors() {
        for v in ["2123456701", "2999999201", "4567891241"] {
            assert!(medicare_valid(v), "Medicare {v} must validate");
        }
        // Spec AU-4 INVALID: the good-FORMAT/bad-CHECKSUM case `2123258701`, a
        // corrupted check digit `2123456711`, and a first-digit-out-of-range `1123456701`.
        for v in ["2123258701", "2123456711", "1123456701"] {
            assert!(!medicare_valid(v), "Medicare {v} must NOT validate");
        }
        // The trailing issue/IRN digits (10–11) are NOT in the checksum: only the
        // first 9 digits are weighted, so a valid card still validates with one present.
        assert!(medicare_valid("21234567019")); // 11-digit incl. issue + IRN
                                                // First digit 7–9 / 0–1 is out of range.
        assert!(!medicare_valid("7123456701"));
        // Too short never validates.
        assert!(!medicare_valid("21234567"));
    }

    // ---- Never panics on hostile / malformed input ----
    #[test]
    fn validators_never_panic_on_hostile_input() {
        for v in [
            "",
            "----",
            "   ",
            "abcdefghij",
            ".................",
            "9999999999999999999999999999999999",
            "0",
            "00000000000",
            "S1234567A",
            "12 34",
        ] {
            // None of these should panic; the result is simply false (or whatever the
            // checksum says) — the point is that the call returns.
            let _ = tfn_valid(v);
            let _ = abn_valid(v);
            let _ = acn_valid(v);
            let _ = medicare_valid(v);
        }
    }

    // ---- AU-5/6 passport + driver's-licence CONTEXT-GATING (spec AU-5/6 OFF-by-
    // default/context-required) ----

    /// An engine with ONLY the AU locale pack enabled.
    fn au_engine() -> crate::RedactionEngine {
        crate::RedactionEngine::builder()
            .locales([crate::Locale::Australia])
            .build()
            .unwrap()
    }

    /// The jurisdiction-namespaced AU recognizer for a row name (e.g. `au:passport`).
    fn au(name: &str) -> crate::Recognizer {
        crate::Recognizer::Locale(std::sync::Arc::from(format!("au:{name}").as_str()))
    }

    /// Does the AU-only engine attribute a candidate to row `name`?
    fn au_flagged_by(name: &str, text: &str) -> bool {
        au_engine()
            .candidates(text)
            .iter()
            .any(|c| c.recognizers().contains(&au(name)))
    }

    #[test]
    fn au_passport_and_dl_are_context_gated() {
        // WITHOUT a keyword: the broad letter+digit shapes do NOT flag as the gated rows
        // (the catastrophic FP class the spec warns about for AU DL).
        assert!(
            !au_flagged_by(
                "passport",
                "reference N1234567 in the unrelated padded clause"
            ),
            "keyword-less AU passport-shaped token must not flag as au:passport"
        );
        assert!(
            !au_flagged_by(
                "drivers-licence",
                "code AB12345 floating in an unrelated padded clause"
            ),
            "keyword-less AU DL-shaped token must not flag as au:drivers-licence"
        );
        // WITH a keyword in-window: the real identifier STILL flags (recall-first).
        assert!(
            au_flagged_by("passport", "Passport No: N1234567"),
            "an AU passport near the keyword must still flag (recall-first)"
        );
        assert!(
            au_flagged_by("drivers-licence", "Driver Licence AB12345"),
            "an AU DL near the keyword must still flag (recall-first)"
        );
    }

    #[test]
    fn au_checksum_rows_fire_unconditionally_regression_guard() {
        // REGRESSION GUARD: `context: None` rows (TFN/ABN/ACN/Medicare) still fire with
        // NO keyword — the new context field changed nothing for them. (TFN spec-valid
        // vector, no "TFN" keyword nearby.)
        assert!(
            au_flagged_by(
                "tfn",
                "the figure 123456782 appears alone in this padded line"
            ),
            "a keyword-less valid TFN must still fire (context: None, unchanged)"
        );
    }

    // ---- AU-8 POSTCODE ----

    #[test]
    fn postcode_row_catches_state_plus_four_digits() {
        // The inline state/territory abbreviation binds the otherwise-broad 4-digit code.
        for (text, needle) in [
            ("Sydney NSW 2000 office", "NSW 2000"),
            ("Melbourne VIC 3000 tower", "VIC 3000"),
            ("Canberra ACT 2601 site", "ACT 2601"),
        ] {
            assert!(
                au_engine()
                    .candidates(text)
                    .iter()
                    .any(|c| c.recognizers().contains(&au("postcode"))
                        && c.matched_value().contains(needle)),
                "au:postcode must catch {needle:?} in {text:?}"
            );
        }
        // A bare 4-digit run with no state is NOT attributed to au:postcode.
        assert!(
            !au_flagged_by("postcode", "the ticket 2000 was issued"),
            "a bare 4-digit run must not flag as au:postcode (needs a state)"
        );
    }
}
