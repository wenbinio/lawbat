// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reusable checksum VALIDATORS for recognizer rows (the `validate: Option<fn(&str)
//! -> bool>` slot on a [`LocaleRecognizer`](super::LocaleRecognizer) /
//! [`ProfileRecognizer`](super::profiles::ProfileRecognizer) and on the global
//! [`TaggedPattern`](crate::TaggedPattern)).
//!
//! ## Why these live here (the pack layer), not in `lib.rs`
//!
//! A jurisdiction pack file (`packs/<cc>.rs`) routinely needs a checksum to turn a
//! broad national-ID pattern PRECISE without a miss — the same trick the global card
//! (Luhn) and IBAN (mod-97) recognizers use. Putting the GENERIC, reusable
//! validators here means a pack file just references `validators::<helper>` (or
//! builds a tiny jurisdiction-specific `fn` on top of one) without reaching back into
//! `lib.rs`. Jurisdiction-SPECIFIC validators (e.g. an SG NRIC weighting table) do
//! NOT live here — they ship inside their own `packs/<cc>.rs` file alongside the rows
//! that use them, so this file stays jurisdiction-agnostic.
//!
//! ## Validator contract (load-bearing — recall-first)
//!
//! A `validate` predicate is run on each RAW regex match's text and keeps the match
//! ONLY when it returns `true`. The recall-first rule (crate docs): a checksum is
//! attached ONLY when a REAL identifier ALWAYS passes it — so the validator can only
//! ever filter NON-instances, never silently MISS a true one. A national ID whose
//! "check digit/letter" is a lookup table we cannot reproduce exactly stays
//! `validate: None` (format-only) rather than risk a transcription error becoming a
//! confidentiality miss.
//!
//! All validators here are PURE integer compute: no allocation of matter data beyond
//! the matched slice they inspect, no RNG, no I/O, deterministic.

/// Luhn (mod-10) check over the ASCII digits in `s` (any non-digit separators are
/// ignored), constrained to a payment-card-length run (13–19 digits). Returns `true`
/// only for a 13–19 digit run that satisfies Luhn — the validator that turns the
/// broad credit-card digit pattern precise. A real card number always passes, so this
/// only ever filters NON-cards (never a miss). Pure compute; inspects only the matched
/// slice.
///
/// This is the CARD-specific wrapper; the general mod-10 engine is [`mod10_valid`]
/// (no length bound) — a jurisdiction whose ID carries a Luhn check digit of a
/// different length calls THAT.
pub fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    // Card length bound (13–19). The generic engine itself imposes no length.
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    mod10_digits(&digits)
}

/// The GENERAL Luhn / mod-10 check over the ASCII digits in `s` (separators ignored),
/// with NO length bound. Returns `true` iff the digit sequence satisfies the Luhn
/// mod-10 checksum AND contains at least one digit. This is the reusable engine a
/// jurisdiction pack calls when its national ID carries a Luhn-style check digit of a
/// length OTHER than a payment card's 13–19 (so [`luhn_valid`] — which bounds to card
/// length — would reject it). Recall-first: attach it only where a REAL ID always
/// passes. Pure integer compute.
pub fn mod10_valid(s: &str) -> bool {
    let digits: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    if digits.is_empty() {
        return false;
    }
    mod10_digits(&digits)
}

/// The shared Luhn core over already-extracted digit VALUES (0–9): from the rightmost
/// digit, double every second digit (subtracting 9 if the doubled value exceeds 9);
/// the total must be ≡ 0 (mod 10). Bounded by its callers' regexes, so no growth.
fn mod10_digits(digits: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = u32::from(d);
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// ISO 7064 mod-97-10 check for an IBAN (any whitespace ignored). Move the first four
/// characters to the end, map letters `A..Z` → `10..35`, interpret the result as one
/// big decimal, and require it ≡ 1 (mod 97). Returns `true` only for a well-formed
/// IBAN (15–34 chars after compaction) that passes — a real IBAN always does, so this
/// only filters NON-IBANs (never a miss). Computes the modulus incrementally (no
/// big-integer allocation). Pure compute; inspects only the matched slice.
pub fn iban_valid(s: &str) -> bool {
    let compact: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    // Rearrange: BBAN+check tail (from index 4) followed by the first 4 chars.
    let rearranged = compact[4..].iter().chain(compact[..4].iter());
    let mut rem: u32 = 0;
    for &c in rearranged {
        if c.is_ascii_digit() {
            rem = (rem * 10 + u32::from(c - b'0')) % 97;
        } else if c.is_ascii_alphabetic() {
            let v = u32::from(c.to_ascii_uppercase() - b'A') + 10; // 10..=35
            rem = (rem * 100 + v) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

/// ISO 17442 mod-97-10 check for a Legal Entity Identifier (LEI). An LEI is exactly
/// 20 characters `[A-Z0-9]{18}[0-9]{2}` — 18 alphanumeric body chars + 2 trailing
/// CHECK DIGITS — and is validated by the SAME ISO 7064 mod-97-10 family as an IBAN,
/// but WITHOUT the IBAN rearrangement: map letters `A..Z` → `10..35`, treat the whole
/// 20-char string as one big decimal, and require it ≡ 1 (mod 97). Returns `true` only
/// for a well-formed 20-char LEI that passes — a real LEI always does, so this only
/// filters NON-LEIs (never a miss). Whitespace is ignored (so a spaced/grouped form
/// still validates); any other non-alphanumeric character rejects. Computes the modulus
/// incrementally (no big-integer allocation). Pure compute; inspects only the matched
/// slice.
///
/// DISTINCT from [`iban_valid`]: an IBAN moves its first four chars to the end before
/// the modulus; an LEI does NOT — the check digits are the LAST two characters of the
/// in-order string. Reusing the IBAN rearrangement here would mis-validate every LEI.
pub fn lei_valid(s: &str) -> bool {
    let compact: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    // An LEI is EXACTLY 20 chars after compaction (18 body + 2 check digits).
    if compact.len() != 20 {
        return false;
    }
    let mut rem: u32 = 0;
    for &c in &compact {
        if c.is_ascii_digit() {
            rem = (rem * 10 + u32::from(c - b'0')) % 97;
        } else if c.is_ascii_alphabetic() {
            let v = u32::from(c.to_ascii_uppercase() - b'A') + 10; // 10..=35
            rem = (rem * 100 + v) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

/// ISO 3166-1 alpha-2 country codes (officially assigned), plus `XK` (Kosovo — used in
/// real BICs) — the country-position (chars 5–6) allowlist for the ISO 9362 BIC
/// structural validator. A FIXED compiled-in table (jurisdiction-agnostic reference
/// data, not matter data). Sorted, so membership is a binary search.
const ISO3166_ALPHA2: &[&str] = &[
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
];

/// ISO 9362 BIC STRUCTURAL validator: 8 or 11 chars — 4 alpha bank code + a VALID
/// ISO 3166-1 alpha-2 country code (chars 5–6, per [`ISO3166_ALPHA2`], plus `XK`) + a
/// 2-char alphanumeric location code (first location char may not be `0`/`1`, per the
/// SWIFT structure rules) + an optional 3-char alphanumeric branch code. STRUCTURE-ONLY
/// (a BIC carries no checksum): the country-code table is what turns the broad
/// letter-run shape precise-ish; the 8-char form additionally needs a BIC/SWIFT label
/// cue nearby (enforced by the engine's labeled-BIC pass, NOT here — this predicate is
/// shared by both forms). A real BIC always satisfies these rules, so this only filters
/// NON-BICs (never a miss). Pure compute; inspects only the matched slice.
pub fn bic_structure_valid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 8 && b.len() != 11 {
        return false;
    }
    // 4-char alpha bank code (the regex already guarantees this; re-checked so the
    // predicate is safe standalone).
    if !b[..4].iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    // Chars 5–6: a REAL country code. ASCII-checked BEFORE the `&s[4..6]` slice so a
    // multibyte char straddling byte 6 can never panic the boundary (fail-closed).
    if !b[4..6].iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    let cc = &s[4..6];
    if ISO3166_ALPHA2.binary_search(&cc).is_err() {
        return false;
    }
    // 2-char location code: alphanumeric, first char not '0'/'1' (SWIFT structure).
    if !b[6..8].iter().all(u8::is_ascii_alphanumeric) || b[6] == b'0' || b[6] == b'1' {
        return false;
    }
    // Optional 3-char branch code: alphanumeric.
    if b.len() == 11 && !b[8..11].iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    true
}

/// ISO 6166 ISIN CHECKSUM validator: exactly 12 chars — 2 alpha (country / `XS`-style
/// prefix) + 9 alphanumeric NSIN + 1 CHECK DIGIT — where the check digit satisfies the
/// ISIN Luhn: expand each letter `A..Z` to its two-digit value `10..35`, keep digits
/// as-is, then run the standard Luhn mod-10 over the expanded digit string (check digit
/// included). A real ISIN always passes, so this only filters NON-ISINs (never a miss)
/// — the same recall-first checksum posture as the card/IBAN/LEI. Pure integer compute;
/// no allocation of matter data beyond the expanded digit buffer.
pub fn isin_valid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 12 {
        return false;
    }
    if !b[..2].iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    if !b[11].is_ascii_digit() {
        return false;
    }
    // Expand letters to 10..35, digits to themselves (the ISO 6166 expansion), then Luhn.
    let mut digits: Vec<u8> = Vec::with_capacity(24);
    for &c in b {
        if c.is_ascii_digit() {
            digits.push(c - b'0');
        } else if c.is_ascii_uppercase() {
            let v = c - b'A' + 10; // 10..=35
            digits.push(v / 10);
            digits.push(v % 10);
        } else {
            return false;
        }
    }
    mod10_digits(&digits)
}

/// A small GENERIC weighted-modulus checksum helper for national IDs that verify a
/// trailing check digit by a positional WEIGHTED sum modulo some `modulus` (the very
/// common government-ID shape: multiply each leading digit by a per-position weight,
/// sum, take it mod `modulus`, and compare against — usually some transform of — the
/// check digit).
///
/// Inputs:
/// - `digits` — the ASCII-digit VALUES (0–9) of the body to weight (the caller has
///   already extracted them and split off any check digit/letter; this helper does NOT
///   parse, so a pack stays in control of where its check character is and how it maps).
/// - `weights` — the per-position multipliers, applied left-to-right; `digits` and
///   `weights` MUST be the same length (a mismatch returns `0` — a deliberately
///   inert, never-panic result the caller treats as "does not validate").
/// - `modulus` — the modulus (e.g. 11 for an ISO 7064 MOD-11-2-style check, 10 for a
///   weighted mod-10).
///
/// Returns the weighted sum taken `mod modulus` (in `0..modulus`). The pack file then
/// maps that remainder to its expected check character (each jurisdiction's mapping
/// differs, so that mapping is the pack's job, not this helper's). Pure integer
/// compute; never panics (a zero modulus or a length mismatch returns `0`).
///
/// Recall-first reminder: a pack attaches a check-digit validator ONLY when a REAL ID
/// always satisfies it; otherwise it leaves the row `validate: None` (format-only).
pub fn weighted_mod_n(digits: &[u8], weights: &[u32], modulus: u32) -> u32 {
    if modulus == 0 || digits.len() != weights.len() {
        return 0;
    }
    // Saturating arithmetic so the documented "never panics" contract holds even for
    // pathological per-position weights (review finding F1). Real checksum weights are
    // tiny (sums far below u32::MAX), but this is now a `pub` helper a future pack author
    // calls, and a debug build panics on `*`/`+` overflow — saturate instead. A saturated
    // sum still yields a deterministic remainder and can never overflow-panic.
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .fold(0u32, |acc, (&d, &w)| {
            acc.saturating_add(u32::from(d).saturating_mul(w))
        });
    sum % modulus
}

/// A simple DIGIT-SUM helper: the sum of the ASCII-digit values in `s` (non-digits
/// ignored). The primitive behind a "sum of digits mod N" check (the simplest national
/// ID checksum family) and a building block a pack composes with [`weighted_mod_n`] or
/// a bare `% n`. Pure integer compute; never panics.
pub fn digit_sum(s: &str) -> u32 {
    // Saturating fold (review finding F1): honors the "never panics" contract for an
    // absurdly long all-digit input; real inputs are tiny.
    s.bytes()
        .filter(u8::is_ascii_digit)
        .fold(0u32, |acc, b| acc.saturating_add(u32::from(b - b'0')))
}

/// Collect the ASCII-digit VALUES (0–9) of `s`, ignoring any non-digit separators —
/// the shared FIRST step of most national-ID checksum validators (each pack's regex has
/// already bounded the slice, so no unbounded growth). Pure integer compute; never
/// panics. Hoisted here (was duplicated verbatim in the `us`/`uk` packs) so every pack
/// composes the SAME extraction.
pub(crate) fn digits_of(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_card_length_bounds_preserved() {
        // The card wrapper keeps its 13–19 length bound: canonical cards pass,
        // a too-short Luhn-valid run is rejected as "not a card".
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("4242 4242 4242 4242"));
        assert!(!luhn_valid("4111111111111112")); // corrupted check digit
        assert!(!luhn_valid("123")); // too short to be a card
                                     // "0" satisfies mod-10 but is far too short for a card.
        assert!(!luhn_valid("0"));
    }

    #[test]
    fn mod10_generalizes_luhn_without_a_length_bound() {
        // The general engine accepts the SAME cards (length is the wrapper's job).
        assert!(mod10_valid("4111111111111111"));
        assert!(!mod10_valid("4111111111111112"));
        // ...AND a SHORT Luhn-valid run the card wrapper rejects on length. "18"
        // is Luhn-valid (1*2=2, +8 = 10 ≡ 0). The card wrapper rejects it (len<13);
        // the general engine accepts it (no length bound) — the whole point.
        assert!(mod10_valid("18"));
        assert!(
            !luhn_valid("18"),
            "the CARD wrapper still rejects a sub-card-length run"
        );
        // Empty / no-digit input never validates.
        assert!(!mod10_valid(""));
        assert!(!mod10_valid("abc"));
    }

    #[test]
    fn iban_mod97_unchanged() {
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(iban_valid("DE89370400440532013000"));
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32")); // spaced
        assert!(!iban_valid("GB82WEST12345698765433")); // corrupted check
        assert!(!iban_valid("GB1")); // too short
    }

    #[test]
    fn lei_mod97_valid_and_invalid_vectors() {
        // A real public LEI (the only non-synthetic vector — public registry data).
        assert!(lei_valid("GV6BTOXCWEVJ5EDH9831"));
        // SYNTHETIC valids (computed offline so the check digits make mod-97-10 == 1),
        // including the DIGIT-LEADING form the broad `id` recognizer misses.
        assert!(lei_valid("549300ABCDEFGHIJKL19")); // digit-leading
        assert!(lei_valid("9845001A2B3C4D5E6F36")); // digit-leading, mixed body
        assert!(lei_valid("ABCDEF123456GHIJKL89")); // letter-leading
        assert!(lei_valid("529900T8BM49AURSDO55")); // digit-leading
                                                    // Whitespace is ignored (a grouped/spaced form still validates).
        assert!(lei_valid("549300 ABCDEFGHIJKL 19"));
        // SYNTHETIC invalids: a corrupted check digit fails mod-97-10.
        assert!(!lei_valid("549300ABCDEFGHIJKL10"));
        assert!(!lei_valid("ABCDEF123456GHIJKL80"));
        // 20-char, format-valid, but checksum-failing.
        assert!(!lei_valid("54930012345678901234"));
        // Wrong LENGTH (19 / 21) is rejected on format alone.
        assert!(!lei_valid("GV6BTOXCWEVJ5EDH983"));
        assert!(!lei_valid("GV6BTOXCWEVJ5EDH98311"));
        // A non-alphanumeric char rejects (never a panic).
        assert!(!lei_valid("549300ABCDEFGHIJK-19"));
        // SANITY: the IBAN rearrangement is NOT used — a valid LEI is generally NOT a
        // valid IBAN under the rearranged check, proving the two validators differ.
        assert!(!iban_valid("549300ABCDEFGHIJKL19"));
    }

    #[test]
    fn bic_structure_valid_and_invalid_vectors() {
        // Real-world 8- and 11-char BICs (public routing data, not matter data).
        assert!(bic_structure_valid("DEUTDEFF")); // Deutsche Bank head office (8)
        assert!(bic_structure_valid("DEUTDEFFXXX")); // 11-char head-office form
        assert!(bic_structure_valid("KESTGB2LXXX")); // synthetic, GB country, digit loc
        assert!(bic_structure_valid("BRNDDEFFXXX"));
        assert!(bic_structure_valid("VANTFRPP"));
        // Country position (chars 5–6) must be a REAL ISO 3166 code: "QQ" is not.
        assert!(!bic_structure_valid("ABCDQQ2LXXX"));
        assert!(!bic_structure_valid("ABCDQQ2L"));
        // "DEUTSCHE" happens to carry a VALID country ("SC" = Seychelles) at 5–6, so it
        // IS structure-valid — the reason the 8-char form is label-cue-gated in the
        // engine (the structural rules alone cannot reject every ordinary word).
        assert!(bic_structure_valid("DEUTSCHE"));
        // Location code may not start with '0' or '1' (SWIFT structure rule).
        assert!(!bic_structure_valid("DEUTDE0F"));
        assert!(!bic_structure_valid("DEUTDE1FXXX"));
        // Wrong lengths reject.
        assert!(!bic_structure_valid("DEUTDEFFXX")); // 10
        assert!(!bic_structure_valid("DEUTDEF")); // 7
                                                  // Lowercase / non-alnum reject (never a panic).
        assert!(!bic_structure_valid("deutdeff"));
        assert!(!bic_structure_valid("DEUT-EFF"));
    }

    #[test]
    fn isin_luhn_valid_and_invalid_vectors() {
        // Real public ISINs (reference identifiers, not matter data).
        assert!(isin_valid("US0378331005")); // Apple
        assert!(isin_valid("GB0002634946")); // BAE Systems
        assert!(isin_valid("US45256BAD38")); // corporate-note form with alpha NSIN
        assert!(isin_valid("DE000BXY0010")); // synthetic DE form (valid check digit)
                                             // A corrupted CHECK DIGIT fails the ISIN Luhn.
        assert!(!isin_valid("US0378331006"));
        assert!(!isin_valid("US45256BAD39"));
        // Final char must be a DIGIT; length must be exactly 12; prefix must be alpha.
        assert!(!isin_valid("US0378331PPP"));
        assert!(!isin_valid("US03783310055"));
        assert!(!isin_valid("US037833100"));
        assert!(!isin_valid("0S0378331005"));
        // An ordinary 12-char caps word never ends in a digit (shape rejects).
        assert!(!isin_valid("CONSOLIDATED"));
    }

    #[test]
    fn iso3166_table_is_sorted_for_binary_search() {
        // The membership test is a `binary_search`, which REQUIRES sorted input — a
        // mis-ordered insertion would silently drop countries (a BIC miss).
        assert!(ISO3166_ALPHA2.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn weighted_mod_n_basic_and_inert_on_misuse() {
        // 1*7 + 2*6 + 3*5 = 7+12+15 = 34; 34 % 11 = 1.
        assert_eq!(weighted_mod_n(&[1, 2, 3], &[7, 6, 5], 11), 1);
        // mod 10 of the same sum (34) = 4.
        assert_eq!(weighted_mod_n(&[1, 2, 3], &[7, 6, 5], 10), 4);
        // Inert (never panics) on a length mismatch or a zero modulus.
        assert_eq!(weighted_mod_n(&[1, 2], &[7, 6, 5], 11), 0);
        assert_eq!(weighted_mod_n(&[1, 2, 3], &[7, 6, 5], 0), 0);
    }

    #[test]
    fn digit_sum_counts_only_digits() {
        assert_eq!(digit_sum("S1234567A"), 1 + 2 + 3 + 4 + 5 + 6 + 7);
        assert_eq!(digit_sum("no digits here"), 0);
        assert_eq!(digit_sum(""), 0);
    }
}
