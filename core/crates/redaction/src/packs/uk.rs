// SPDX-License-Identifier: AGPL-3.0-or-later
//! United Kingdom (`uk`) jurisdiction recognizer pack.
//!
//! One self-contained file of DATA ROWS (the unit a parallel fan-out adds per
//! jurisdiction). It exposes exactly [`rows`]; `packs/mod.rs` maps
//! `Locale::UnitedKingdom` to it via the single append-only registration seam (see
//! the "ADDING A JURISDICTION" comment there). Nothing jurisdiction-specific leaks
//! into shared code: the namespaced audit label (`uk:nhs`, `uk:nino`, …) is
//! assembled by the engine from this jurisdiction's [`Locale::label`] prefix
//! (`uk`) + each row's bare `name`.
//!
//! Spec: `to-read/redaction.RECOGNIZER-PACKS-SPEC.md` § "PACK 2 — UNITED KINGDOM" (rows UK-1..UK-6),
//! with the independently-recomputed test vectors and correctness traps reproduced
//! in this file's tests. Posture is the crate's recall-first one: a broad regex
//! caught the candidate; a `validate` predicate (when present) only ever FILTERS
//! non-instances, never silently misses a real ID (the load-bearing rule in
//! `packs::validators`).
//!
//! ## Tiering of the six rows (which carry a `validate`, which are bare format)
//!
//! - **UK-1 NHS number** and **UK-3 UTR** are CHECKSUM-backed: a real ID ALWAYS
//!   satisfies the check, so the validator is precision-without-a-miss. Both use a
//!   small jurisdiction-specific `fn` here (their check-character MAPPINGS differ
//!   from any generic helper — the NHS "computed 10 ⇒ invalid / 11 ⇒ 0" rule and
//!   the HMRC remainder→digit array are UK-specific), exactly as
//!   `packs::validators`' module docs prescribe (generic helpers stay
//!   jurisdiction-agnostic; a jurisdiction's bespoke mapping ships beside its rows).
//! - **UK-2 NINO** is FORMAT-only (no checksum exists) but its format is more than a
//!   regex can express in this engine: the `regex` crate has NO lookahead, so the
//!   spec's `(?![DFIQUV])`-style prefix constraints + the reserved-prefix denylist +
//!   the `[A-D]` suffix live in a `validate` predicate ([`nino_format_valid`]). That
//!   predicate is still a pure FORMAT gate (letter membership + a fixed denylist),
//!   not a checksum — a real NINO always passes it, so it only filters non-NINOs.
//! - **UK-4 passport**, **UK-5 driving licence**, **UK-6 sort code** are bare
//!   FORMAT shapes (`validate: None`) — the spec says "Validator none" for each
//!   (the sort-code modulus check needs the ~1,151-rule Pay.UK `valacdos.txt`
//!   weight table, which we deliberately do NOT bundle; UK-6 ships format-only).
//! - **UK IBAN** is NOT a separate row here: a UK IBAN (`GB..`) is already caught by
//!   the GLOBAL built-in IBAN recognizer (ISO mod-97-10, `validators::iban_valid`),
//!   so duplicating it as a locale row would only double-count. The sort-code row IS
//!   the UK-specific bank-account signal the global IBAN recognizer does not cover.

use super::validators::digits_of;
use super::LocaleRecognizer;

/// The United Kingdom recognizer rows. Returns a `'static` slice so enabling the
/// pack copies nothing — the engine compiles the rows it is told to.
///
/// Adding ANOTHER UK recognizer later (e.g. a company number) is a single extra
/// [`LocaleRecognizer`] row in this slice — no other file changes.
pub fn rows() -> &'static [LocaleRecognizer] {
    &[
        // UK-1 NHS number (medical). 3-3-4 grouping, optional `-`/space separators.
        // CHECKSUM-backed (Modulus-11) so the validator turns the broad 10-digit
        // shape precise WITHOUT a miss — a real NHS number always satisfies the
        // check, so `nhs_mod11_valid` only ever filters non-NHS digit runs.
        LocaleRecognizer {
            name: "nhs",
            pattern: r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b",
            validate: Some(nhs_mod11_valid),
            context: None,
            aggressive: false, // Modulus-11 checksum — precise.
        },
        // UK-2 NINO (law/tax). FORMAT-only (no checksum exists). The `regex` crate
        // lacks lookahead, so the broad shape (2 letters + 6 digits + suffix letter,
        // optional spaces) is matched here and the spec's letter rules + reserved-
        // prefix denylist + `[A-D]` suffix are enforced in `nino_format_valid` — a
        // pure format gate (a real NINO always passes), never a checksum.
        LocaleRecognizer {
            name: "nino",
            pattern: r"\b[A-Za-z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-Za-z]\b",
            validate: Some(nino_format_valid),
            context: None,
            aggressive: false, // letter-rule + reserved-prefix structural gate — precise.
        },
        // UK-3 UTR (law/tax). 10 digits (optionally split 5+5, optional trailing K).
        // CHECKSUM-backed (HMRC Modulus-11 with the MAPPING ARRAY, NOT 11-remainder):
        // the validator is precision-without-a-miss (a real UTR always passes).
        LocaleRecognizer {
            name: "utr",
            pattern: r"\b\d{5} ?\d{5}K?\b",
            validate: Some(utr_hmrc_valid),
            context: None,
            aggressive: false, // HMRC Modulus-11 mapping checksum — precise.
        },
        // UK-4 passport (format-only). 9 digits, OR 2 letters + 7 digits. The spec
        // marks this default-OFF/context-required (it collides other 9-digit IDs);
        // within an explicitly opted-in UK pack it ships recall-first, format-only.
        LocaleRecognizer {
            name: "passport",
            pattern: r"\b(?:\d{9}|[A-Za-z]{2}\d{7})\b",
            validate: None,
            // FOLLOW-UP: the 9-digit alternative is broad like `us:passport` and a
            // future pass should `context`-gate it on a passport keyword; left `None`
            // here (recall-first) to keep this fix focused on the `us:dl` flood.
            context: None,
            // AGGRESSIVE: the bare 9-digit alternative collides with other 9-digit IDs —
            // last-resort LABEL, demoted below precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        // UK-5 driving licence (format-only, DOB-encoded). 16-char DVLA shape:
        // 5 surname/initial chars (letters or filler `9`), 6 DOB+gender digits,
        // 2 initials chars, a check digit, 2 issue chars, optional 2-digit issue
        // number. Validator none (the spec's optional month/day precision is not
        // applied — recall-first format-only).
        LocaleRecognizer {
            name: "driving-licence",
            pattern: r"\b[A-Za-z9]{5}\d{6}[A-Za-z9]{2}\d[A-Za-z]{2}(?:\d{2})?\b",
            validate: None,
            context: None,
            // AGGRESSIVE: a 16-char format-only DVLA shape (no validator) — last-resort
            // LABEL, demoted below precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        // UK-6 sort code (bank, format-only). The XX-XX-XX punctuation is the signal.
        // Validator none BY DESIGN: the Pay.UK modulus check needs the ~1,151-rule
        // `valacdos.txt` weight table (only valid if we bundle + refresh it), so the
        // sort code ships format-only. The account number + UK IBAN are covered by
        // the global IBAN recognizer / context, not duplicated here.
        LocaleRecognizer {
            name: "sort-code",
            pattern: r"\b\d{2}[- ]\d{2}[- ]\d{2}\b",
            validate: None,
            context: None,
            // AGGRESSIVE: a bank sort code is a format-only 2-2-2 digit run (the modulus
            // check is deliberately not bundled) — last-resort LABEL, demoted below
            // precise rows (still fires; recall-neutral).
            aggressive: true,
        },
        // UK-7 POSTCODE (spec §"ADDRESS FAMILY — LOCALE POSTAL", UK-POST): the full UK
        // postcode grammar — outward code (1–2 letters, a digit, an OPTIONAL letter/digit)
        // + inward code (a digit + 2 letters), with an OPTIONAL single space (`SW1A 1AA`,
        // `M1 1AE`, `EC1A 1BB`). Case-tolerant. The outward+inward shape is DISTINCTIVE,
        // so CONTEXT:NONE and PRECISE (structural → CAREFUL review — no `postcode` class
        // lexicon, so it never reaches High). Audit `uk:postcode`; type label "postal code".
        LocaleRecognizer {
            name: "postcode",
            pattern: r"\b[A-Za-z]{1,2}\d[A-Za-z\d]? ?\d[A-Za-z]{2}\b",
            validate: None,
            context: None,
            aggressive: false,
        },
    ]
}

// ===================================================================
// Jurisdiction-specific validators (UK-1 NHS, UK-2 NINO, UK-3 UTR)
// ===================================================================
//
// These live HERE (not in `packs::validators`) because each encodes a UK-specific
// check-character MAPPING the generic helpers deliberately do not bake in (the NHS
// "computed-10 ⇒ invalid, 11 ⇒ 0" rule; the HMRC remainder→digit array; the NINO
// letter rules + reserved-prefix denylist). All are PURE integer/byte compute: no
// allocation of matter data beyond the matched slice they inspect, no RNG, no I/O,
// deterministic, and NEVER panic (every index is bounds-checked first).

// `digits_of` is now the shared `super::validators::digits_of` (imported above).

/// UK-1 NHS number — Modulus-11 check (NHS Data Dictionary).
///
/// Strip to 10 digits; weight the first 9 by `[10,9,8,7,6,5,4,3,2]`; `r = sum % 11`;
/// `check = 11 - r`. TRAPS (spec): a computed `check == 11` maps to `0`; a computed
/// `check == 10` makes the number INVALID (there is no check digit "10"). Valid iff
/// the resolved check equals `d[9]`. A real NHS number always satisfies this, so the
/// validator only ever filters non-NHS runs (recall-first).
fn nhs_mod11_valid(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 10 {
        return false;
    }
    const W: [u32; 9] = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = (0..9).map(|i| u32::from(d[i]) * W[i]).sum();
    let r = sum % 11;
    let check = 11 - r; // r ∈ 0..=10, so check ∈ 1..=11
    let check = match check {
        11 => 0,            // 11 ⇒ 0
        10 => return false, // 10 ⇒ INVALID (no such check digit)
        c => c,
    };
    check == u32::from(d[9])
}

/// UK-3 UTR — HMRC Modulus-11 with the MAPPING ARRAY (HMRC reference-checker).
///
/// `d[0]` is the check digit; the body is `d[1..10]` (9 digits) weighted by
/// `[6,7,8,9,10,5,4,3,2]`; `r = sum % 11`. The expected check is
/// `CHECK[r]` where `CHECK = [2,1,9,8,7,6,5,4,3,2,1]` — NOT the naive `11 - r`
/// (they diverge at `r == 0` and `r == 1`, the spec's trap). Valid iff
/// `CHECK[r] == d[0]`. A real UTR always satisfies this (recall-first filter).
fn utr_hmrc_valid(s: &str) -> bool {
    let d = digits_of(s);
    if d.len() != 10 {
        return false;
    }
    // The HMRC remainder→check-digit mapping (index 0..=10), NOT `11 - r`.
    const CHECK: [u8; 11] = [2, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    const W: [u32; 9] = [6, 7, 8, 9, 10, 5, 4, 3, 2];
    // Body is d[1..10] (the 9 digits after the leading check digit d[0]).
    let sum: u32 = (0..9).map(|i| u32::from(d[i + 1]) * W[i]).sum();
    let r = (sum % 11) as usize; // r ∈ 0..=10, a valid CHECK index
    CHECK[r] == d[0]
}

/// UK-2 NINO — FORMAT validation only (DWP CV0013); there is NO NINO checksum.
///
/// The `regex` crate has no lookahead, so the row's broad pattern matched any
/// `LL dd dd dd L` shape and this predicate enforces the actual format rules:
/// - first letter ∉ {D,F,I,Q,U,V}; second letter ∉ {D,F,I,O,Q,U,V};
/// - the two-letter prefix ∉ the reserved set {BG,GB,NK,KN,NT,TN,ZZ};
/// - the suffix letter ∈ {A,B,C,D}.
///
/// Matched case-insensitively (the row pattern allows lowercase letters). These are
/// pure FORMAT constraints a REAL NINO always satisfies (reserved prefixes are never
/// issued, the suffix is always A–D), so this only filters non-NINOs — never a miss.
fn nino_format_valid(s: &str) -> bool {
    // Compact: drop ASCII whitespace, uppercase the letters. The row pattern only
    // admits ASCII letters + digits (+ single spaces), so this stays a clean
    // [A-Z]{2}\d{6}[A-Z] string of length 9 for any real match.
    let compact: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if compact.len() != 9 {
        return false;
    }
    let l1 = compact[0];
    let l2 = compact[1];
    let suffix = compact[8];
    if !l1.is_ascii_uppercase() || !l2.is_ascii_uppercase() || !suffix.is_ascii_uppercase() {
        return false;
    }
    if !compact[2..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    // First-letter and second-letter disallowed sets (DWP CV0013).
    if matches!(l1, b'D' | b'F' | b'I' | b'Q' | b'U' | b'V') {
        return false;
    }
    if matches!(l2, b'D' | b'F' | b'I' | b'O' | b'Q' | b'U' | b'V') {
        return false;
    }
    // Reserved two-letter prefixes (never issued).
    const RESERVED: [[u8; 2]; 7] = [
        [b'B', b'G'],
        [b'G', b'B'],
        [b'N', b'K'],
        [b'K', b'N'],
        [b'N', b'T'],
        [b'T', b'N'],
        [b'Z', b'Z'],
    ];
    if RESERVED.contains(&[l1, l2]) {
        return false;
    }
    // Suffix must be A–D.
    matches!(suffix, b'A' | b'B' | b'C' | b'D')
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- UK-1 NHS (Modulus-11) — spec's EXACT vectors ----

    #[test]
    fn nhs_valid_flagged_invalid_dropped() {
        // VALID (spec): every real NHS number passes the Modulus-11 check.
        for ok in ["943 476 7571", "893 177 0847", "401 023 2137"] {
            assert!(nhs_mod11_valid(ok), "NHS {ok:?} should be valid");
        }
        // INVALID (spec): a corrupted check digit fails.
        assert!(
            !nhs_mod11_valid("401 023 2138"),
            "corrupted NHS check must fail"
        );
        // INVALID (spec trap): body 999000000 computes check == 10 ⇒ INVALID,
        // regardless of the 10th digit appended. Test all ten possible last digits.
        for last in 0..=9 {
            let n = format!("999000000{last}");
            assert!(
                !nhs_mod11_valid(&n),
                "NHS {n:?} (body 999000000 ⇒ check 10) must be invalid"
            );
        }
        // Separator-insensitive: the same number with no separators still validates.
        assert!(nhs_mod11_valid("9434767571"));
        assert!(nhs_mod11_valid("893-177-0847"));
        // Wrong length never validates.
        assert!(!nhs_mod11_valid("943 476 757"));
    }

    #[test]
    fn nhs_check_eleven_maps_to_zero() {
        // The "computed 11 ⇒ check 0" branch must be reachable + correct. Construct a
        // body whose Modulus-11 remainder is 0 (⇒ check 11 ⇒ 0) and append a 0.
        // Body 000000000: sum = 0, r = 0, check = 11 ⇒ 0, so last digit 0 is valid.
        assert!(
            nhs_mod11_valid("0000000000"),
            "all-zero body ⇒ check 0 ⇒ valid with trailing 0"
        );
        // ...and a non-zero last digit on that body is invalid.
        assert!(!nhs_mod11_valid("0000000001"));
    }

    // ---- UK-2 NINO (format/letter rules only) ----

    #[test]
    fn nino_format_valid_invalid() {
        // VALID (spec).
        for ok in ["AA 12 34 56 B", "TW 98 76 54 A", "YZ 61 48 68 B"] {
            assert!(nino_format_valid(ok), "NINO {ok:?} should be valid");
        }
        // INVALID (spec): reserved prefix BG, invalid letters FQ, bad suffix H.
        for bad in ["BG 12 36 12 A", "FQ 00 00 00 C", "AA 12 34 56 H"] {
            assert!(!nino_format_valid(bad), "NINO {bad:?} should be invalid");
        }
        // Reserved-prefix denylist is complete.
        for prefix in ["BG", "GB", "NK", "KN", "NT", "TN", "ZZ"] {
            let n = format!("{prefix} 12 34 56 A");
            assert!(
                !nino_format_valid(&n),
                "reserved prefix {prefix} must be rejected"
            );
        }
        // Compact (no spaces) and lowercase both validate.
        assert!(nino_format_valid("AA123456B"));
        assert!(nino_format_valid("aa 12 34 56 b"));
        // Wrong length never validates.
        assert!(!nino_format_valid("AA 12 34 56"));
    }

    // ---- UK-3 UTR (HMRC Modulus-11, MAPPING ARRAY) ----

    #[test]
    fn utr_valid_flagged_invalid_dropped() {
        // VALID (spec): every real UTR passes the HMRC mapping check.
        for ok in ["2234567890", "6135792468", "9987654321"] {
            assert!(utr_hmrc_valid(ok), "UTR {ok:?} should be valid");
        }
        // INVALID (spec): the SAME body with a wrong leading check digit fails. The
        // first two diverge from naive 11-remainder (r==0 and r==1 traps).
        for bad in ["1234567890", "0234567890", "9234567890"] {
            assert!(!utr_hmrc_valid(bad), "UTR {bad:?} should be invalid");
        }
        // The HMRC array (not 11-r) is what rejects 1234567890 yet accepts 2234567890:
        // both share body 234567890; only the leading check digit differs (1 vs 2).
        assert!(utr_hmrc_valid("2234567890") && !utr_hmrc_valid("1234567890"));
        // Separator / trailing-K tolerant (the row pattern allows `5 5` and a `K`).
        assert!(utr_hmrc_valid("22345 67890"));
        assert!(utr_hmrc_valid("2234567890K")); // K is not a digit; ignored by digits_of
                                                // Wrong length never validates.
        assert!(!utr_hmrc_valid("223456789"));
    }

    // ---- Never-panic over hostile / arbitrary inputs ----

    #[test]
    fn validators_never_panic_on_arbitrary_input() {
        // Multibyte UTF-8, empty, control chars, very long, all-separators — no
        // validator may panic (e.g. a slice on a non-char boundary or an OOB index).
        let nasty = [
            "",
            " ",
            "----",
            "é\u{0301}\u{0000}",
            "九四三四七六七五七一", // CJK "digits", not ASCII
            "999999999999999999999999999999",
            "AA AA AA AA A",
            "\u{1F600}",
        ];
        for s in nasty {
            let _ = nhs_mod11_valid(s);
            let _ = utr_hmrc_valid(s);
            let _ = nino_format_valid(s);
        }
        // A long all-digit run must not panic and must not validate as a 10-digit ID.
        let long: String = "1".repeat(10_000);
        assert!(!nhs_mod11_valid(&long));
        assert!(!utr_hmrc_valid(&long));
    }

    // ---- UK-7 POSTCODE (engine-level) ----

    #[test]
    fn postcode_row_catches_uk_postcode_grammar() {
        use crate::{Locale, Recognizer, RedactionEngine};
        use std::sync::Arc;
        let e = RedactionEngine::builder()
            .locales([Locale::UnitedKingdom])
            .build()
            .unwrap();
        let uk_postcode = Recognizer::Locale(Arc::from("uk:postcode"));
        for (text, needle) in [
            ("write to SW1A 1AA promptly", "SW1A 1AA"),
            ("addr M1 1AE flat", "M1 1AE"),
            ("office EC1A 1BB London", "EC1A 1BB"),
        ] {
            let cands = e.candidates(text);
            assert!(
                cands.iter().any(|c| c.recognizers().contains(&uk_postcode)
                    && c.matched_value().contains(needle)),
                "uk:postcode must catch {needle:?} in {text:?}, got {cands:?}"
            );
        }
        // A NINO shape must NOT be mislabelled as a postcode (distinct inward code).
        let cands = e.candidates("NINO AA123456B on record");
        assert!(
            !cands.iter().any(|c| c.recognizers().contains(&uk_postcode)),
            "a NINO must not flag as uk:postcode, got {cands:?}"
        );
    }
}
