// SPDX-License-Identifier: AGPL-3.0-or-later
//! Singapore (`sg`) jurisdiction recognizer pack.
//!
//! One self-contained file of DATA ROWS — the unit a parallel fan-out adds per
//! jurisdiction. It exposes exactly [`rows`]; `packs/mod.rs` maps `Locale::Singapore`
//! to it via the single append-only registration seam (see the "ADDING A
//! JURISDICTION" comment there). Nothing jurisdiction-specific leaks into shared code:
//! the namespaced audit label (`sg:nric`) is assembled by the engine from this
//! jurisdiction's [`Locale::label`](crate::Locale::label) prefix + each row's bare
//! `name`.
//!
//! This pack was MIGRATED out of `lib.rs`'s inline `locale_recognizers` table with
//! ZERO behavior change — the same row, the same `sg:nric` label, the same format-only
//! recall-first posture.

use super::LocaleRecognizer;

/// The Singapore recognizer rows. Returns a `'static` slice so enabling the pack
/// copies nothing — the engine compiles the rows it is told to.
///
/// Adding ANOTHER SG recognizer is a single extra [`LocaleRecognizer`] row in this
/// slice — no other file changes (the UEN row below was added exactly that way).
pub fn rows() -> &'static [LocaleRecognizer] {
    &[
        // SG NRIC/FIN: prefix letter (S/T citizens+PRs, F/G/M foreigners) + 7 digits
        // + a check letter. FORMAT-ONLY (recall-first) — the check letter is NOT
        // verified, because the SG checksum is a lookup table whose mis-transcription
        // could SILENTLY MISS a real NRIC (the one failure this crate refuses).
        // Case-sensitive (NRICs are CANONICALLY UPPERCASE — a lowercase `s1234567a` is
        // intentionally OUT OF SCOPE, matching the UEN row below; the prefix-letter +
        // check-letter shape is the precision lever and a lowercased token is not a
        // canonical NRIC), which also trims noise. `\b` bounds keep it from matching
        // mid-token. NO required `context` (`context: None`) — the prefix+check-letter
        // shape is specific enough to fire unconditionally (recall-first). (Was a global
        // built-in; now jurisdiction-gated, opt in with `.locales([Locale::Singapore])`.)
        LocaleRecognizer {
            name: "nric",
            pattern: r"\b[STFGM]\d{7}[A-Z]\b",
            validate: None,
            context: None,
            // PRECISE: the prefix-letter + check-letter shape is a distinctive national
            // ID, not a catastrophic-FP format-only run — keeps full locale priority.
            aggressive: false,
        },
        // SG UEN (Unique Entity Number) — the registered-entity identifier, in three
        // ACRA formats, EACH ending in a check LETTER that MUST be inside the match
        // (else the broad global `phone`/`id` built-ins grab only the digit run and the
        // trailing letter SURVIVES — a partial-redaction leak). Covered, as ONE
        // linear-time alternation (no backrefs, no nested quantifiers → no ReDoS):
        //   (i)   businesses (ROB):       8 digits + check letter      `\d{8}[A-Z]`
        //   (ii)  local companies (ACRA): 9 digits + check letter      `\d{9}[A-Z]`
        //         (4-digit year + 5 digits + letter, e.g. `201912345A`)
        //   (iii) other entities (new):   `[STR]` + 2 digits + 2 alnum + 4 digits +
        //         check letter, e.g. `T08LL1234A`  `[STR]\d{2}[A-Z0-9]{2}\d{4}[A-Z]`
        // FORMAT-ONLY (recall-first) — the UEN has no published self-checking digit a
        // mis-transcription could not SILENTLY MISS, so `validate: None`, exactly like
        // the NRIC row. Case-sensitive (UENs are CANONICALLY UPPERCASE — a lowercase
        // token is intentionally OUT OF SCOPE, exactly like the NRIC row above). `\b`
        // bounds keep it from firing mid-token. Priority-1 (every locale row), so on
        // overlap with the broad built-ins the merge UNIONS the spans and the WHOLE
        // token (check letter included) redacts. NO required `context` (`context: None`)
        // — the trailing-check-letter shape is specific enough to fire unconditionally
        // (recall-first). Audit label `sg:uen` (cleartext-free).
        LocaleRecognizer {
            name: "uen",
            pattern: r"\b(?:\d{8,9}[A-Z]|[STR]\d{2}[A-Z0-9]{2}\d{4}[A-Z])\b",
            validate: None,
            context: None,
            // PRECISE: the trailing-check-letter shape is distinctive (not a bare digit
            // run), so it keeps full locale priority and out-labels the broad built-ins.
            aggressive: false,
        },
        // SG POSTAL CODE (spec §"ADDRESS FAMILY — LOCALE POSTAL", SG-POST): the two
        // DISTINCTIVE forms — `Singapore NNNNNN` and `S(NNNNNN)` — fire unconditionally
        // (the `Singapore`/`S(` prefix makes a 6-digit run precise). CONTEXT:NONE, PRECISE
        // (not aggressive), routes to CAREFUL review (a locale row is structural → Medium,
        // never High for a `postal` row — no `postal` class lexicon). Case-tolerant on the
        // `Singapore` word. Audit label `sg:postal`; type label "postal code".
        LocaleRecognizer {
            name: "postal",
            pattern: r"\b(?i:Singapore)\s+\d{6}\b|\bS\(\d{6}\)",
            validate: None,
            context: None,
            aggressive: false,
        },
        // SG BARE 6-DIGIT POSTAL near address context (spec §SG-POST, recall net): a bare
        // `NNNNNN` run gated on a postal/address keyword in-window (the same additive gate
        // `us:dl` uses). AGGRESSIVE (advisory / default-OFF in the host accept-set; demoted
        // in the label contest) because a bare 6-digit run is FP-prone. Audit `sg:postal-bare`.
        LocaleRecognizer {
            name: "postal-bare",
            pattern: r"\b\d{6}\b",
            validate: None,
            context: Some(&["postal", "postcode", "post code", "address", "singapore"]),
            aggressive: true,
        },
    ]
}

/// The OPT-IN AGGRESSIVE SG-NRIC "loose net" rows — registered ONLY when the request
/// sets the `sg_nric_loose` flag (plumbed like the `lei` opt-in), NEVER as part of the
/// always-on [`rows`] above (so `locales: ["sg"]` alone is byte-identical to today). Both
/// rows are `aggressive: true`, so they ride the Change-A advisory mechanism: their
/// candidates are SURFACED for review but DEFAULT-OFF in the apply accept-set (the human
/// opts IN). They are the recall net for NRIC-shaped tokens the PRECISE `sg:nric` row
/// (canonical `\b[STFGM]\d{7}[A-Z]\b`, default-ON) intentionally excludes — lowercase /
/// any-prefix-letter / odd-length / space-or-dash-separated tokens, and a bare digit run
/// next to an NRIC/FIN/IC label.
///
/// PRECISE-WINS: both rows are `aggressive` → demoted below `sg:nric` (priority 1) in the
/// merge's primary-label election, so a REAL `S1234567D` (which matches BOTH the precise
/// `sg:nric` AND `sg:nric-loose`) is attributed to `sg:nric` → default-ON, advisory:false.
/// Only an EXTRA token matched solely by a loose/context row carries advisory:true.
pub fn loose_rows() -> &'static [LocaleRecognizer] {
    &[
        // sg:nric-loose — the user's "any-letter / 6–8-digit net": one letter (either
        // case) + an OPTIONAL single space or dash + 6–8 digits + an OPTIONAL single
        // space or dash + one letter. Word-bounded (`\b`), so it does NOT fire inside a
        // longer alphanumeric run (`PO12345678XY` / `AB1234567C` do not match — `\b`
        // requires a non-word boundary on each side, which an adjacent letter denies).
        // Linear-time (no backrefs, no nested quantifiers → no ReDoS). FORMAT-ONLY
        // (recall-net): `validate: None`, `context: None` (fires unconditionally WHEN
        // the opt-in is on). AGGRESSIVE: advisory/default-OFF + demoted below `sg:nric`.
        LocaleRecognizer {
            name: "nric-loose",
            pattern: r"\b[A-Za-z][ -]?\d{6,8}[ -]?[A-Za-z]\b",
            validate: None,
            context: None,
            aggressive: true,
        },
        // sg:nric-context — a BARE 7–9-digit run that fires ONLY when an NRIC/FIN/IC
        // keyword is in-window (the SAME additive context gate `us:dl` uses — never an
        // unbounded "any digits"). Word-bounded. AGGRESSIVE: advisory/default-OFF +
        // demoted below the precise rows. The keyword set covers the common SG labels;
        // a trailing space (`ic `) keeps `ic` from matching inside `epic`/`logic`.
        LocaleRecognizer {
            name: "nric-context",
            pattern: r"\b\d{7,9}\b",
            validate: None,
            context: Some(&[
                "nric",
                "fin",
                "ic ",
                "identity card",
                "i/c",
                "nric no",
                "fin no",
            ]),
            aggressive: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::{Locale, Recognizer, RedactionEngine};
    use std::collections::HashSet;
    use std::sync::Arc;

    /// An engine with ONLY the SG locale pack enabled (no terms / firm recognizers).
    fn sg_engine() -> RedactionEngine {
        RedactionEngine::builder()
            .locales([Locale::Singapore])
            .build()
            .unwrap()
    }

    /// The jurisdiction-namespaced SG recognizer for a row name (e.g. `sg:uen`).
    fn sg(name: &str) -> Recognizer {
        Recognizer::Locale(Arc::from(format!("sg:{name}").as_str()))
    }

    #[test]
    fn uen_local_company_full_span_covers_check_letter() {
        // The leak this row fixes: the broad global `phone`/`id` built-ins grab the
        // 9-digit run of `201912345A` and leave the trailing `A`. The priority-1 UEN
        // locale row matches the WHOLE token, and on overlap the merge UNIONS the
        // spans, so the merged candidate covers the check letter too.
        let e = sg_engine();
        let text = "Counterparty UEN 201912345A on the agreement.";
        let cands = e.candidates(text);
        // Find the candidate over the UEN token.
        let over: Vec<&_> = cands
            .iter()
            .filter(|c| c.matched_value().contains("201912345"))
            .collect();
        assert_eq!(over.len(), 1, "one merged UEN candidate, got {cands:?}");
        let c = over[0];
        // The matched value is the ENTIRE UEN incl. the check letter — NOT just the
        // 9-digit run.
        assert_eq!(
            c.matched_value(),
            "201912345A",
            "full UEN incl. check letter"
        );
        assert_eq!(
            &text[c.start()..c.end()],
            "201912345A",
            "span covers the whole token"
        );
        // The UEN locale row fired (membership in the merged span's recognizer list:
        // the broad built-ins overlap, so the PRIMARY is the priority-1 locale row).
        assert!(
            c.recognizers().contains(&sg("uen")),
            "sg:uen attributed, got {cands:?}"
        );
        assert_eq!(
            c.recognizer(),
            &sg("uen"),
            "UEN is the primary (most specific)"
        );
    }

    #[test]
    fn uen_other_format_str_prefix_full_span() {
        // The `[STR]…` "other entities" format, e.g. `T08LL1234A`.
        let e = sg_engine();
        let text = "Trust entity T08LL1234A registered 2008.";
        let cands = e.candidates(text);
        let over: Vec<&_> = cands
            .iter()
            .filter(|c| c.matched_value().contains("T08LL1234A"))
            .collect();
        assert_eq!(
            over.len(),
            1,
            "one UEN candidate for the [STR] form, got {cands:?}"
        );
        assert_eq!(
            over[0].matched_value(),
            "T08LL1234A",
            "full [STR] UEN incl. check letter"
        );
        assert!(
            over[0].recognizers().contains(&sg("uen")),
            "sg:uen attributed"
        );
    }

    #[test]
    fn uen_business_eight_digit_form() {
        // (i) businesses (ROB): 8 digits + check letter.
        let e = sg_engine();
        let cands = e.candidates("Sole prop UEN 53212345A filed.");
        assert!(
            cands
                .iter()
                .any(|c| c.matched_value() == "53212345A" && c.recognizers().contains(&sg("uen"))),
            "8-digit UEN flagged in full, got {cands:?}"
        );
    }

    #[test]
    fn apply_redacts_whole_uen_no_check_letter_survives() {
        // The end-to-end recall guarantee: accepting the UEN candidate and applying
        // leaves NO part of the UEN — in particular the trailing check letter is gone
        // (the leak class this row closes).
        let e = sg_engine();
        let text = "Pay entity 201912345A by Friday.";
        let cands = e.candidates(text);
        let c = cands
            .iter()
            .find(|c| c.matched_value() == "201912345A")
            .expect("UEN detected");
        let accept: HashSet<(usize, usize)> = HashSet::from([(c.start(), c.end())]);
        let (redacted, applied, stale) = e.redact_with_selection(text, &accept);
        assert_eq!((applied, stale), (1, 0), "the UEN span applied cleanly");
        // NO fragment of the UEN survives — not the digits, not the check letter.
        assert!(
            !redacted.contains("201912345"),
            "digit run removed: {redacted:?}"
        );
        assert!(
            !redacted.contains("201912345A"),
            "full UEN removed: {redacted:?}"
        );
        // The surviving text must not leave a stray `A` where the check letter was.
        // After "201912345" comes the marker, then " by Friday." — assert the token
        // boundary is clean (no `<marker>A`).
        assert!(
            redacted.contains(" by Friday."),
            "tail intact: {redacted:?}"
        );
        assert!(
            !redacted.contains("A by Friday."),
            "no orphaned check letter: {redacted:?}"
        );
    }

    #[test]
    fn no_context_rows_fire_unconditionally_regression_guard() {
        // REGRESSION GUARD for the new `LocaleRecognizer::context` field: the SG rows are
        // `context: None`, so they STILL fire with NO keyword anywhere near them —
        // byte-identical to before the field existed. (The gate only suppresses
        // `context: Some` rows like `us:dl`; an SG NRIC/UEN is always-on, recall-first.)
        let e = sg_engine();
        // NRIC with no "NRIC"/"IC" keyword in-window — still flagged.
        let cands = e.candidates("the holder S1234567A is named in the long padded clause here");
        assert!(
            cands.iter().any(|c| c.recognizers().contains(&sg("nric"))),
            "a keyword-less NRIC must still fire (context: None, unchanged), got {cands:?}"
        );
        // UEN with no keyword in-window — still flagged in full.
        let cands2 = e.candidates("counterparty 201912345A signs the unrelated padded agreement");
        assert!(
            cands2.iter().any(|c| c.recognizers().contains(&sg("uen"))),
            "a keyword-less UEN must still fire (context: None, unchanged), got {cands2:?}"
        );
    }

    #[test]
    fn no_locale_engine_does_not_attribute_uen() {
        // Without the SG pack, no candidate is attributed to `sg:uen` (a broad built-in
        // may incidentally cover the digit run, but never as the UEN locale row).
        let bare = RedactionEngine::builder().build().unwrap();
        let cands = bare.candidates("UEN 201912345A here");
        assert!(
            !cands.iter().any(|c| c.recognizers().contains(&sg("uen"))),
            "no sg:uen without the SG locale enabled, got {cands:?}"
        );
    }

    // ---- OPT-IN AGGRESSIVE SG-NRIC LOOSE NET (`sg_nric_loose`) ----

    /// An engine with the OPT-IN aggressive SG-NRIC loose net ON. The precise SG pack is
    /// NOT enabled here UNLESS the test also adds it — so a test can isolate the loose rows.
    fn loose_engine() -> RedactionEngine {
        RedactionEngine::builder()
            .sg_nric_loose(true)
            .build()
            .unwrap()
    }

    #[test]
    fn loose_net_off_by_default_no_loose_rows_registered() {
        // The two loose rows are registered ONLY by the opt-in: a bare SG engine (precise
        // pack on) does NOT attribute anything to sg:nric-loose / sg:nric-context, and a
        // bare builder registers neither in `is_aggressive`.
        let e = sg_engine();
        assert!(
            !e.is_aggressive(&sg("nric-loose")),
            "loose row not registered by default"
        );
        assert!(
            !e.is_aggressive(&sg("nric-context")),
            "context row not registered by default"
        );
        let cands = e.candidates("token s1234567d near here and 1234567 too");
        assert!(
            !cands
                .iter()
                .any(|c| c.recognizers().contains(&sg("nric-loose"))
                    || c.recognizers().contains(&sg("nric-context"))),
            "no loose/context attribution without the opt-in, got {cands:?}"
        );
    }

    #[test]
    fn loose_row_catches_lowercase_and_odd_lengths_and_separators() {
        // The user's net: lowercase, 6/8-digit, and space/dash-separated NRIC-shaped tokens.
        let e = loose_engine();
        for s in [
            "s1234567d",   // lowercase 7-digit
            "A123456B",    // 6 digits
            "X12345678Z",  // 8 digits
            "S 1234567 D", // single-space separated
            "S-1234567-D", // single-dash separated
        ] {
            let text = format!("ref {s} end");
            let cands = e.candidates(&text);
            assert!(
                cands
                    .iter()
                    .any(|c| c.recognizers().contains(&sg("nric-loose"))),
                "loose row must catch {s:?}, got {cands:?}"
            );
        }
        // Both loose rows are aggressive in this engine.
        assert!(
            e.is_aggressive(&sg("nric-loose")),
            "loose row is aggressive"
        );
        assert!(
            e.is_aggressive(&sg("nric-context")),
            "context row is aggressive"
        );
    }

    #[test]
    fn loose_row_word_bounded_does_not_match_inside_longer_alnum() {
        // `\b` must exclude a window inside a longer alphanumeric run.
        let e = loose_engine();
        for s in ["PO12345678XY", "AB1234567C"] {
            let text = format!("code {s} done");
            let cands = e.candidates(&text);
            assert!(
                !cands
                    .iter()
                    .any(|c| c.recognizers().contains(&sg("nric-loose"))
                        && c.matched_value().len() < s.len()),
                "loose row must NOT match inside {s:?}, got {cands:?}"
            );
        }
    }

    #[test]
    fn context_row_fires_only_with_keyword_in_window() {
        // A bare 7-digit run fires via sg:nric-context ONLY when an NRIC/FIN/IC keyword is
        // in-window; with no keyword the context row does NOT contribute (additive gate).
        let e = loose_engine();
        let near = e.candidates("NRIC no 7654321 on file");
        assert!(
            near.iter()
                .any(|c| c.recognizers().contains(&sg("nric-context"))),
            "context row fires with the NRIC keyword in-window, got {near:?}"
        );
        // No keyword: the context row drops (a broad phone built-in may still cover a long
        // digit run, but never the sg:nric-context locale row).
        let far = e.candidates("the lucky number 7654321 was drawn at the unrelated padded gala");
        assert!(
            !far.iter()
                .any(|c| c.recognizers().contains(&sg("nric-context"))),
            "context row must NOT fire without a keyword, got {far:?}"
        );
    }

    #[test]
    fn precise_wins_real_nric_is_attributed_to_precise_row_not_loose() {
        // A REAL `S1234567D` matches BOTH the precise `sg:nric` AND the aggressive
        // `sg:nric-loose`. Precise-wins: the merged candidate's PRIMARY is `sg:nric`
        // (priority 1), NOT the demoted loose row — so it is NOT advisory and is
        // default-redacted. (Enable BOTH the precise pack and the loose net.)
        let e = RedactionEngine::builder()
            .locales([Locale::Singapore])
            .sg_nric_loose(true)
            .build()
            .unwrap();
        let cands = e.candidates("Director NRIC S1234567D signed");
        let over: Vec<&_> = cands
            .iter()
            .filter(|c| c.matched_value().contains("S1234567D"))
            .collect();
        assert_eq!(
            over.len(),
            1,
            "one merged candidate over the real NRIC, got {cands:?}"
        );
        let c = over[0];
        assert_eq!(
            c.recognizer(),
            &sg("nric"),
            "precise sg:nric is the primary, got {:?}",
            c.recognizer()
        );
        assert!(
            !e.is_aggressive(c.recognizer()),
            "the real NRIC is NOT advisory (precise primary)"
        );
        // Both rows still fired (recall-neutral): the loose row corroborates as a member.
        assert!(
            c.recognizers().contains(&sg("nric")),
            "precise row in members"
        );
        assert!(
            c.recognizers().contains(&sg("nric-loose")),
            "loose row also fired (member)"
        );
    }

    #[test]
    fn loose_net_off_is_byte_identical_to_today_for_sg() {
        // With `sg_nric_loose` OFF, an SG-only engine's output is byte-identical to a
        // plain SG engine (no extra candidates from the loose rows).
        let plain = sg_engine();
        let text = "Holder s1234567d and bare 1234567 next to NRIC no, plus S1234567A canonical";
        let a = plain.candidates(text);
        // The same engine built WITHOUT the opt-in produces the same candidate set.
        let b = RedactionEngine::builder()
            .locales([Locale::Singapore])
            .sg_nric_loose(false)
            .build()
            .unwrap();
        let bc = b.candidates(text);
        assert_eq!(
            a.len(),
            bc.len(),
            "sg_nric_loose:false == no opt-in (same candidate count), got {a:?} vs {bc:?}"
        );
    }

    // ---- SG POSTAL rows ----

    #[test]
    fn postal_row_catches_singapore_and_s_paren_forms() {
        let e = sg_engine();
        for (text, needle) in [
            (
                "Registered office Singapore 048623 tower",
                "Singapore 048623",
            ),
            ("postal code S(079120) noted", "S(079120)"),
        ] {
            let cands = e.candidates(text);
            assert!(
                cands.iter().any(|c| c.recognizers().contains(&sg("postal"))
                    && c.matched_value().contains(needle.trim_end())),
                "sg:postal must catch {needle:?} in {text:?}, got {cands:?}"
            );
        }
    }

    #[test]
    fn postal_bare_row_is_context_gated_and_aggressive() {
        let e = sg_engine();
        // Near a postal/address keyword → the bare 6-digit run fires via sg:postal-bare.
        let near = e.candidates("mailing address 640123 west");
        assert!(
            near.iter()
                .any(|c| c.recognizers().contains(&sg("postal-bare"))),
            "bare 6-digit near an address keyword fires, got {near:?}"
        );
        // No keyword → gated out (a broad built-in never attributes to sg:postal-bare).
        let far = e.candidates("the raffle number 640123 was drawn at the padded unrelated gala");
        assert!(
            !far.iter()
                .any(|c| c.recognizers().contains(&sg("postal-bare"))),
            "bare 6-digit with no keyword must not fire, got {far:?}"
        );
        // The bare row is advisory (aggressive); the distinctive `sg:postal` is precise.
        assert!(
            e.is_aggressive(&sg("postal-bare")),
            "postal-bare is advisory"
        );
        assert!(
            !e.is_aggressive(&sg("postal")),
            "sg:postal is precise/default-on"
        );
    }
}
