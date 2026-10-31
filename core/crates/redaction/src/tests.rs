// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unit tests, extracted verbatim from the former inline `mod tests` in `lib.rs`.

use super::*;
use runtime::{
    AuditHash, Capability, Core, CoreContext, CoreError, FixedClock, GrantSet, InMemoryAudit,
    InMemoryEgress, InMemoryMatterStore, InMemoryStorage,
};

type TestCore = Core<
    GrantSet,
    InMemoryAudit,
    InMemoryStorage,
    InMemoryEgress,
    CoreContext,
    InMemoryMatterStore,
>;

/// A doc mentioning a deal codename, a party name (from the term list), and
/// an email — the three identifier kinds this increment recognizes.
const SAMPLE: &str =
    "Project Condor: contact Jane Roe at jane.roe@acme.example re Acme Holdings Pte Ltd.";

fn engine() -> RedactionEngine {
    RedactionEngine::new(vec![
        "Project Condor".to_string(),
        "Acme Holdings Pte Ltd".to_string(),
        "Jane Roe".to_string(),
    ])
}

#[test]
fn ws_term_regex_source_is_whitespace_elastic_between_every_char() {
    // The source allows arbitrary ASCII whitespace between adjacent significant chars,
    // so a fragmented word still matches. (We check the COMPILED behavior, not the raw
    // string, which is the contract that matters.)
    let src = ws_term_regex_source("Daniel J. Watkins");
    let re = regex::Regex::new(&src).expect("compiles");
    // The exact term still matches.
    assert!(re.is_match("Daniel J. Watkins"));
    // A glyph-by-glyph fragmentation with fabricated internal spaces matches.
    assert!(
        re.is_match("Daniel J. W at kins"),
        "fragmented word must match"
    );
    // Extra runs of whitespace anywhere are absorbed.
    assert!(re.is_match("Daniel   J.   Wat kins"));
    // A different name does NOT match.
    assert!(!re.is_match("Daniel J. Watson"));
}

#[test]
fn term_spans_whitespace_insensitive_matches_only_terms_and_coalesces() {
    let eng = RedactionEngine::new(vec!["Massimo Greco".to_string()]);
    // Fragmented across fabricated spaces — caught.
    let spans = eng.term_spans_whitespace_insensitive("dir: Mas simo Gre co, partner");
    assert_eq!(spans.len(), 1, "the fragmented term is found once");
    let (s, e) = spans[0];
    assert_eq!(&"dir: Mas simo Gre co, partner"[s..e], "Mas simo Gre co");
    // An email (a BUILT-IN, not a term) is NOT returned by this terms-only method.
    let none = eng.term_spans_whitespace_insensitive("write to bob@firm.test now");
    assert!(
        none.is_empty(),
        "only user terms are matched, never built-ins"
    );
    // No terms configured => always empty (the common case is a no-op).
    let blank = RedactionEngine::new(Vec::<String>::new());
    assert!(blank
        .term_spans_whitespace_insensitive("anything Massimo Greco")
        .is_empty());
}

fn core_with(grants: Vec<Capability>, store: InMemoryMatterStore) -> TestCore {
    Core::new(
        "sg.redaction.engine",
        GrantSet::from_manifest(grants),
        InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
        InMemoryStorage::new(),
        // Configure a destination so, if egress were ever (wrongly) granted,
        // the broker gate — not a missing sink — is what we are testing.
        InMemoryEgress::new().with_destination("counsel-vault"),
        CoreContext::new("Acme v Beta", "j.smith"),
        store,
    )
}

fn seeded_core(grants: Vec<Capability>) -> TestCore {
    let mut store = InMemoryMatterStore::new();
    store.insert(1, DataClass::Document, SAMPLE);
    // The default engine reads BOTH document + party (matching the manifest),
    // so seed a party-class doc too — exercising the broader default coverage.
    store.insert(2, DataClass::Party, "Acme Holdings Pte Ltd — party file");
    core_with(grants, store)
}

fn redaction_grants() -> Vec<Capability> {
    vec![
        Capability::MatterRead(DataClass::Document),
        // The default engine also strips the party class (manifest parity).
        Capability::MatterRead(DataClass::Party),
        Capability::DocumentTransform,
        // NOTE: no Capability::Egress(..) — the engine holds no egress grant.
    ]
}

#[test]
fn redact_matter_removes_all_identifier_strings() {
    let mut core = seeded_core(redaction_grants());
    let report = engine().redact_matter(&mut core).unwrap();

    // The stored content no longer contains ANY of the identifier strings.
    // Read it back THROUGH the core (granted matter.read) so we assert on
    // exactly what the store holds after the in-place transform.
    let stored = core.matter_read_text(1, DataClass::Document).unwrap();
    for needle in [
        "Project Condor",
        "Acme Holdings Pte Ltd",
        "Jane Roe",
        "jane.roe@acme.example",
    ] {
        assert!(
            !stored.contains(needle),
            "identifier {needle:?} must be removed, stored = {stored:?}"
        );
    }
    assert!(
        stored.contains(REDACTION_MARKER),
        "matches replaced with the marker"
    );
    // Both the document (id 1) and the party-class doc (id 2) are processed,
    // reflecting the default engine's document+party coverage (manifest parity).
    assert_eq!(report.docs_processed(), 2);
    assert!(
        report.total_identifiers_removed() >= 4,
        "at least the 4 seeded identifiers"
    );
}

#[test]
fn audit_chain_records_reads_transforms_and_notes_and_verifies() {
    let mut core = seeded_core(redaction_grants());
    engine().redact_matter(&mut core).unwrap();

    let caps: Vec<&Capability> = core
        .audit()
        .entries()
        .iter()
        .map(|e| &e.capability)
        .collect();
    assert!(
        caps.contains(&&Capability::MatterRead(DataClass::Document)),
        "a read was audited"
    );
    assert!(
        caps.contains(&&Capability::DocumentTransform),
        "a transform was audited"
    );
    assert!(
        caps.contains(&&Capability::AuditNote),
        "a per-doc note was audited"
    );

    // Attribution: every entry is the acting human + the host-pinned module.
    for e in core.audit().entries() {
        assert_eq!(e.acting_user, "j.smith");
        assert_eq!(e.matter, "Acme v Beta");
        assert_eq!(e.module, "sg.redaction.engine");
    }
    assert!(
        core.audit().verify_chain(),
        "the keyed hash chain must verify"
    );
}

#[test]
fn induced_recognizer_audit_never_leaks_pattern_or_example_value() {
    // INDUCTION confidentiality (the load-bearing test): an induced recognizer's
    // regex EMBEDS example cleartext (especially the alternation form), and the
    // matched values are the very identifiers being redacted. NEITHER may reach
    // the audit chain — the audit logs the recognizer LABEL + counts only.
    //
    // Build with ONLY the induced recognizer (no built-ins / no terms) so the
    // sole recognizer is the induced one; seed a doc containing the induced
    // EXAMPLE values; scan + redact through the real Core; then assert no audit
    // `detail` contains either the induced PATTERN source or any example value.
    let induced = induce::induce(["INV-1001", "INV-2002"]).unwrap();
    let pattern_src = induced.regex().to_string();
    let recognizer = induced.into_user_recognizer("invoice-no");

    // A second, ALTERNATION-strategy recognizer (its source literally contains
    // the example cleartext) — the worst case for the audit-leak check.
    let alt = induce::induce(["AB-12", "9999"]).unwrap();
    let alt_src = alt.regex().to_string();
    assert!(
        alt_src.contains("AB"),
        "alternation embeds the example cleartext"
    );
    let alt_recognizer = alt.into_user_recognizer("mixed-codes");

    let mut store = InMemoryMatterStore::new();
    store.insert(
        1,
        DataClass::Document,
        "Invoice INV-1001 and INV-2002 plus codes AB-12 and 9999.",
    );
    let mut core = core_with(
        vec![
            Capability::MatterRead(DataClass::Document),
            Capability::DocumentTransform,
        ],
        store,
    );

    let engine = RedactionEngine::builder()
        .classes(vec![DataClass::Document])
        .builtins(BuiltinRecognizers::none())
        .recognizers(vec![recognizer, alt_recognizer])
        .build()
        .unwrap();

    // Scan (audits a note) AND redact (audits notes + the transform).
    let scan = engine.scan_matter(&mut core).unwrap();
    assert!(
        scan.total_candidates() >= 4,
        "the induced recognizers must fire"
    );
    engine.redact_matter(&mut core).unwrap();

    // The induced recognizers actually matched (the LABELs ARE allowed in the
    // audit — they are config names, not values).
    let details: Vec<&str> = core
        .audit()
        .entries()
        .iter()
        .map(|e| e.detail.as_str())
        .collect();
    assert!(
        details.iter().any(|d| d.contains("invoice-no")),
        "the recognizer LABEL is audit-safe and present"
    );

    // CONFIDENTIALITY: no audit detail may contain the induced PATTERN source or
    // any example/matched VALUE.
    for d in &details {
        for needle in [
            pattern_src.as_str(),
            alt_src.as_str(),
            "INV-1001",
            "INV-2002",
            "AB-12",
            "9999",
        ] {
            assert!(
                !d.contains(needle),
                "audit detail must not leak the pattern/value {needle:?}; detail = {d:?}"
            );
        }
    }
    assert!(
        core.audit().verify_chain(),
        "the audit chain still verifies"
    );
}

#[test]
fn no_egress_grant_means_an_egress_attempt_is_refused() {
    // The engine never sends; but prove the core would REFUSE egress with the
    // engine's grant set (no egress capability granted).
    let mut core = seeded_core(redaction_grants());
    engine().redact_matter(&mut core).unwrap();
    let err = core.egress_send("counsel-vault", b"x").unwrap_err();
    assert!(
        matches!(err, CoreError::Denied(Capability::Egress(_))),
        "no egress grant -> egress refused, got {err:?}"
    );
    assert!(core.egress().sent().is_empty(), "nothing left the box");
}

#[test]
fn non_granted_class_is_refused() {
    // Grant only document.transform but NOT matter.read:document -> the very
    // first matter_list_docs is refused (default-deny per class).
    let mut core = seeded_core(vec![Capability::DocumentTransform]);
    let err = engine().redact_matter(&mut core).unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::Denied(Capability::MatterRead(DataClass::Document))
        ),
        "a non-granted class must be refused, got {err:?}"
    );
}

#[test]
fn redaction_is_deterministic() {
    // Same input -> identical redacted output AND identical count, run twice.
    let e = engine();
    let a = e.redact_text(SAMPLE);
    let b = e.redact_text(SAMPLE);
    assert_eq!(a, b, "redaction must be deterministic");
}

#[test]
fn regex_recognizers_catch_emails_and_ids_without_a_term_list() {
    // Even with NO terms, the deterministic patterns strip an email + an id.
    let e = RedactionEngine::new(Vec::<String>::new());
    let (out, n) = e.redact_text("write to a@b.com about ref PROJ2026 now");
    assert!(!out.contains("a@b.com"));
    assert!(!out.contains("PROJ2026"));
    assert!(n >= 2, "email + id both removed, got {n}");
}

#[test]
fn non_ascii_term_still_removed() {
    // REGRESSION GUARD (FIX 1): a non-ASCII uppercase char ('İ') whose
    // lowercase differs in byte length used to drift the lowercased-haystack
    // offsets and LEAVE the term in place. With per-term escaped (?i) regexes
    // matched against the original, the term is fully removed.
    let e = RedactionEngine::new(vec!["Project Condor".to_string()]);
    let (out, n) = e.redact_text("İstanbul — Project Condor matter");
    assert!(
        !out.contains("Project Condor"),
        "the term must be fully removed even after a non-ASCII char, got {out:?}"
    );
    assert!(n >= 1, "at least the one term replacement, got {n}");
    // The non-ASCII context itself is preserved (no corruption).
    assert!(
        out.contains("İstanbul"),
        "surrounding non-ASCII text is intact, got {out:?}"
    );
}

#[test]
fn regex_metachar_term_literal() {
    // A party name with regex metacharacters is matched LITERALLY (escaped),
    // never interpreted as a pattern — no panic, and it must NOT match a
    // string that only a regex interpretation would (proving it is literal).
    let e = RedactionEngine::new(vec!["A.B (Pte)".to_string()]);
    let (out, n) = e.redact_text("party A.B (Pte) signed");
    assert!(
        !out.contains("A.B (Pte)"),
        "the literal term must be removed, got {out:?}"
    );
    assert!(n >= 1, "the literal term matched once, got {n}");

    // If the metacharacters were interpreted, "A.B" would match "AXB" and the
    // `(Pte)` group would match bare "Pte". Assert it does NOT.
    let (out2, n2) = e.redact_text("party AXB Pte signed");
    assert_eq!(
        out2, "party AXB Pte signed",
        "must not match as a regex, got {out2:?}"
    );
    assert_eq!(
        n2, 0,
        "literal term must not match the regex-only string, got {n2}"
    );
}

#[test]
fn audit_count_equals_spans_written() {
    // The audit note's count must equal the redactions ACTUALLY written to the
    // stored doc (single in-closure run feeds the note). Recompute the count
    // from the original content the store held and compare against the number
    // reported AND the marker count now in the store.
    let mut core = seeded_core(redaction_grants());
    // Capture each doc's original content before redaction.
    let orig1 = core.matter_read_text(1, DataClass::Document).unwrap();
    let orig2 = core.matter_read_text(2, DataClass::Party).unwrap();
    let report = engine().redact_matter(&mut core).unwrap();

    let e = engine();
    let (_red1, expect1) = e.redact_with_count(&orig1);
    let (_red2, expect2) = e.redact_with_count(&orig2);

    // The per-doc report counts equal an independent re-redaction of the same
    // originals (the count is exactly the spans the closure wrote).
    let doc1 = report.docs().iter().find(|d| d.doc_id() == 1).unwrap();
    let doc2 = report.docs().iter().find(|d| d.doc_id() == 2).unwrap();
    assert_eq!(doc1.identifiers_removed(), expect1);
    assert_eq!(doc2.identifiers_removed(), expect2);

    // And the audit note for each doc carries that exact count.
    let notes: Vec<&str> = core
        .audit()
        .entries()
        .iter()
        .filter(|en| en.capability == Capability::AuditNote)
        .map(|en| en.detail.as_str())
        .collect();
    assert!(
        notes
            .iter()
            .any(|d| d.contains("doc 1") && d.contains(&format!("{expect1} redaction"))),
        "audit note for doc 1 must carry the written count {expect1}, notes = {notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|d| d.contains("doc 2") && d.contains(&format!("{expect2} redaction"))),
        "audit note for doc 2 must carry the written count {expect2}, notes = {notes:?}"
    );

    // The number written equals the markers now present in the stored content.
    let stored1 = core.matter_read_text(1, DataClass::Document).unwrap();
    assert_eq!(
        stored1.matches(REDACTION_MARKER).count(),
        doc1.identifiers_removed(),
        "markers in the store must equal the reported/written count"
    );
}

#[test]
fn overlapping_email_and_phone() {
    // A string matching multiple recognizers must be FULLY redacted: no
    // identifier fragment may survive after the cross-recognizer passes.
    let e = RedactionEngine::new(Vec::<String>::new());
    let (out, n) = e.redact_text("reach jane.roe@acme.example or +65 6123 4567 x88");
    assert!(
        !out.contains("jane.roe@acme.example"),
        "email gone, got {out:?}"
    );
    assert!(
        !out.contains("@acme.example"),
        "no email fragment survives, got {out:?}"
    );
    assert!(!out.contains("6123 4567"), "phone digits gone, got {out:?}");
    assert!(!out.contains("x88"), "phone extension gone, got {out:?}");
    assert!(n >= 2, "both recognizers fired, got {n}");
}

#[test]
fn broadened_id_patterns_match_separated_forms() {
    // The id recognizer catches single-letter prefixes, `-`/`/` separators,
    // and mixed forms in addition to the simple "AB1234" shape.
    let e = RedactionEngine::new(Vec::<String>::new());
    for id in ["S-2026-014", "AB/1234", "PROJ2026", "AB1234"] {
        let (out, n) = e.redact_text(&format!("ref {id} here"));
        assert!(
            !out.contains(id),
            "broadened id {id:?} must be stripped, got {out:?}"
        );
        assert!(n >= 1, "id {id:?} matched, got {n}");
    }
}

// ---- PART 1: candidates returned ----

#[test]
fn candidate_spans_point_at_matched_value_in_original() {
    // Every candidate's byte span indexes the ORIGINAL content and yields the
    // exact matched_value (valid char boundaries, no drift).
    let e = engine();
    let cands = e.candidates(SAMPLE);
    assert!(!cands.is_empty(), "the sample has identifiers");
    for c in &cands {
        assert_eq!(
            &SAMPLE[c.start()..c.end()],
            c.matched_value(),
            "candidate span must index its matched_value in the original"
        );
        assert!(c.end() > c.start(), "span is non-empty");
        // The context snippet contains the matched value (surrounding text).
        assert!(
            c.context().contains(c.matched_value()),
            "context must surround the match, got {:?}",
            c.context()
        );
    }
}

#[test]
fn count_equals_candidates_len_equals_markers() {
    // count == candidates.len() == marker occurrences in the redacted string.
    let e = engine();
    let (out, cands) = e.redact_detail(SAMPLE);
    let (_o2, n) = e.redact_with_count(SAMPLE);
    assert_eq!(n, cands.len(), "count == candidates.len()");
    assert_eq!(
        out.matches(REDACTION_MARKER).count(),
        cands.len(),
        "one marker written per candidate"
    );
}

#[test]
fn term_substring_of_marker_does_not_corrupt_the_marker() {
    // Regression for the "redacting a common name corrupts the document" class:
    // "Ted" (a real party name) is a case-insensitive substring of the REDACTED
    // marker (…C-T-E-D). Detection runs over the ORIGINAL text and redact_detail
    // splices merged spans in a SINGLE left-to-right pass, so a term can NEVER
    // match inside an already-written "[REDACTED]" marker — no "[REDAC[REDACTED]]"
    // garble and the count stays exact.
    let e = RedactionEngine::new(vec!["Ted".to_string()]);
    let (out, cands) = e.redact_detail("Contact foo@bar.com about Ted today.");
    assert!(!out.contains("foo@bar.com"), "email removed: {out}");
    assert!(!out.contains("Ted"), "party name removed: {out}");
    assert!(
        !out.contains("[REDAC["),
        "no nested marker corruption: {out}"
    );
    assert!(!out.contains("REDACTED]]"), "no re-scanned marker: {out}");
    // Exactly two redactions (email + Ted); count == candidates == markers written.
    assert_eq!(cands.len(), 2, "email + Ted only, got: {out}");
    assert_eq!(out.matches(REDACTION_MARKER).count(), cands.len());
}

#[test]
fn report_carries_candidates_with_correct_spans_against_original() {
    // redact_matter returns the actual candidates; each indexes the ORIGINAL
    // doc content (captured before the transform).
    let mut core = seeded_core(redaction_grants());
    let orig1 = core.matter_read_text(1, DataClass::Document).unwrap();
    let report = engine().redact_matter(&mut core).unwrap();

    let doc1 = report.docs().iter().find(|d| d.doc_id() == 1).unwrap();
    assert_eq!(
        doc1.identifiers_removed(),
        doc1.candidates().len(),
        "identifiers_removed is derived == candidates.len()"
    );
    assert!(!doc1.candidates().is_empty(), "doc 1 had identifiers");
    for c in doc1.candidates() {
        assert_eq!(
            &orig1[c.start()..c.end()],
            c.matched_value(),
            "report candidate span must index the ORIGINAL doc content"
        );
    }
}

#[test]
fn overlapping_matches_merge_into_one_candidate() {
    // An email whose local part is ALSO a caller term must yield ONE merged
    // candidate over the union span — not two, no fragment.
    let e = RedactionEngine::new(vec!["jane.roe".to_string()]);
    let text = "mail jane.roe@acme.example today";
    let cands = e.candidates(text);
    // Exactly one candidate covers the whole email (term overlaps the email).
    let email_region: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.start() <= text.find('@').unwrap() && c.end() >= text.find('@').unwrap())
        .collect();
    assert_eq!(
        email_region.len(),
        1,
        "overlap merged to one, got {cands:?}"
    );
    let merged = email_region[0];
    assert_eq!(
        merged.matched_value(),
        "jane.roe@acme.example",
        "merged span is the union (full email), got {:?}",
        merged.matched_value()
    );
    // Term is the more specific recognizer -> it wins as primary.
    assert_eq!(
        merged.recognizer(),
        &Recognizer::Term,
        "primary = most specific"
    );

    let (out, _) = e.redact_detail(text);
    assert_eq!(
        out.matches(REDACTION_MARKER).count(),
        cands.len(),
        "one marker per merged candidate (no double-redaction)"
    );
    assert!(
        !out.contains("jane.roe"),
        "no fragment survives, got {out:?}"
    );
}

#[test]
fn audit_note_has_breakdown_but_no_cleartext_matched_value() {
    // CONFIDENTIALITY SPLIT: the audit note carries the count + per-recognizer
    // breakdown but NEVER a cleartext matched_value.
    let mut core = seeded_core(redaction_grants());
    let report = engine().redact_matter(&mut core).unwrap();

    // Collect every cleartext matched_value the engine actually found.
    let cleartext: Vec<String> = report
        .docs()
        .iter()
        .flat_map(|d| d.candidates().iter().map(|c| c.matched_value().to_string()))
        .collect();
    assert!(!cleartext.is_empty(), "the run found identifiers");

    let notes: Vec<&str> = core
        .audit()
        .entries()
        .iter()
        .filter(|en| en.capability == Capability::AuditNote)
        .map(|en| en.detail.as_str())
        .collect();
    assert!(!notes.is_empty(), "per-doc notes were written");

    for note in &notes {
        // Has the count + a recognizer breakdown.
        assert!(
            note.contains("redaction(s) applied"),
            "note has the count, got {note:?}"
        );
        assert!(
            note.contains('=')
                && (note.contains("term=")
                    || note.contains("email=")
                    || note.contains("name=")
                    || note.contains("id=")
                    || note.contains("phone=")
                    || note.contains("none")),
            "note has a per-recognizer breakdown, got {note:?}"
        );
        // Carries NO cleartext identifier.
        for value in &cleartext {
            assert!(
                !note.contains(value.as_str()),
                "audit note must NOT contain cleartext {value:?}, note = {note:?}"
            );
        }
    }
}

// ---- PART 2: deterministic name heuristic ----

#[test]
fn title_prefixed_names_flagged_as_name() {
    let e = RedactionEngine::new(Vec::<String>::new());
    for (text, expected) in [
        ("Met Mr. Smith yesterday", "Mr. Smith"),
        ("From Dr. Tan Wei Ming re filing", "Dr. Tan Wei Ming"),
        ("per Justice Lee at hearing", "Justice Lee"),
    ] {
        let cands = e.candidates(text);
        let name = cands
            .iter()
            .find(|c| c.recognizer() == &Recognizer::Name)
            .unwrap_or_else(|| panic!("expected a Name candidate in {text:?}, got {cands:?}"));
        assert_eq!(name.matched_value(), expected, "name span/value");
        assert_eq!(
            &text[name.start()..name.end()],
            name.matched_value(),
            "span indexes original"
        );
    }
}

#[test]
fn lone_capitalized_word_not_flagged_in_default_mode() {
    // A sentence-initial capitalized word (no title) must NOT be a Name in the
    // default (conservative) mode — otherwise every sentence start redacts.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("Tomorrow we sign the deal.");
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "no Name flag for a lone capitalized word in default mode, got {cands:?}"
    );
}

#[test]
fn aggressive_mode_flags_a_capitalized_bigram() {
    // OPT-IN: with aggressive() a capitalized bigram is flagged as Name; the
    // SAME text is NOT flagged in default mode.
    let text = "Acme Holdings signed the deal";
    let default = RedactionEngine::new(Vec::<String>::new());
    assert!(
        !default
            .candidates(text)
            .iter()
            .any(|c| c.recognizer() == &Recognizer::Name),
        "default mode does not flag a capitalized bigram"
    );

    let aggressive = RedactionEngine::new(Vec::<String>::new()).aggressive();
    let cands = aggressive.candidates(text);
    let name = cands
        .iter()
        .find(|c| c.recognizer() == &Recognizer::Name)
        .unwrap_or_else(|| panic!("aggressive mode flags the bigram, got {cands:?}"));
    assert!(
        name.matched_value().contains("Acme Holdings"),
        "the capitalized run is flagged, got {:?}",
        name.matched_value()
    );
}

// ---- PART 2b: name-propagation ("name closure") ----

/// Helper: does ANY candidate's value EQUAL `want` (an exact-span check, not a substring)?
fn has_exact_name(cands: &[RedactionCandidate], want: &str) -> bool {
    cands
        .iter()
        .any(|c| c.recognizer() == &Recognizer::Name && c.matched_value() == want)
}

#[test]
fn safe_tier_propagates_exact_name_reoccurrences() {
    // "Mr Greco" is detected by the honorific recognizer; the SAFE tier (always on)
    // redacts every ADDITIONAL exact, whole-word occurrence of the name PART "Greco".
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "We met Mr Greco. Later, Greco signed. A grocery is not Greco.";
    let cands = e.candidates(text);
    // The bare "Greco" occurrences are now Name candidates (SAFE propagation).
    let greco_spans: Vec<_> = cands
        .iter()
        .filter(|c| c.recognizer() == &Recognizer::Name && c.matched_value() == "Greco")
        .collect();
    assert!(
        greco_spans.len() >= 2,
        "the two bare 'Greco' occurrences propagate (whole word), got {cands:?}"
    );
    // Whole-word: the "Greco" inside "grocery" is not a match (different letters anyway),
    // and crucially no SUBSTRING flag — assert no candidate value is "grocer"/partial.
    assert!(
        cands.iter().all(|c| c.matched_value() != "grocery"),
        "no substring over-match, got {cands:?}"
    );
}

#[test]
fn safe_tier_alone_does_not_pull_in_bare_full_name() {
    // SAFE only (expansion OFF): detecting "Mr Greco" re-flags the bare token "Greco"
    // but does NOT redact the bare "Massimo Greco" run — that needs the expansion tier.
    // (Lowercase separators keep the run exactly the name, so the assert is precise.)
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "reference Mr Greco. the director Massimo Greco of milan.";
    let cands = e.candidates(text);
    assert!(
        has_exact_name(&cands, "Greco"),
        "SAFE re-flags bare 'Greco', got {cands:?}"
    );
    assert!(
        !has_exact_name(&cands, "Massimo Greco"),
        "SAFE alone does NOT cover the full bare run, got {cands:?}"
    );
}

#[test]
fn expansion_tier_catches_bare_full_name_from_a_token() {
    // EXPANSION on: the detected token "Greco" pulls in the Capitalized run that
    // contains it -> the bare "Massimo Greco" is redacted from one titled mention.
    // (Lowercase separators bound the run to exactly "Massimo Greco"; in real text an
    // adjacent Capitalized word would be absorbed into a WIDER run — still redacting the
    // name, just with a wider span.)
    let e = RedactionEngine::builder()
        .name_expansion(true)
        .build()
        .unwrap();
    let text = "reference Mr Greco. the director Massimo Greco of milan.";
    let cands = e.candidates(text);
    assert!(
        has_exact_name(&cands, "Massimo Greco"),
        "expansion pulls in the bare full name from the 'Greco' token, got {cands:?}"
    );
}

#[test]
fn expansion_does_not_redact_a_run_without_a_detected_name_token() {
    // BOUNDED: with expansion on but only "Greco" detected, an unrelated Capitalized run
    // ("Acme Holdings Limited") with NO detected name token is NOT redacted — this is the
    // guard that distinguishes expansion from the blunt aggressive bigram rule.
    let e = RedactionEngine::builder()
        .name_expansion(true)
        .build()
        .unwrap();
    let text = "Mr Greco attended. Acme Holdings Limited filed the report.";
    let cands = e.candidates(text);
    assert!(
        cands
            .iter()
            .all(|c| !c.matched_value().contains("Acme Holdings")),
        "a run with no detected name token is NOT redacted, got {cands:?}"
    );
}

#[test]
fn name_propagation_off_default_is_byte_identical_when_nothing_propagates() {
    // A document with NO detected name produces ZERO propagated spans, so the candidate
    // set is byte-identical to before the pass existed. Compare SAFE-default vs expansion
    // on a name-free doc: identical (the pass adds nothing either way).
    let text = "Invoice AB1234 emailed to jane@acme.example, card 4111 1111 1111 1111.";
    let default = RedactionEngine::new(Vec::<String>::new()).candidates(text);
    let with_exp = RedactionEngine::builder()
        .name_expansion(true)
        .build()
        .unwrap()
        .candidates(text);
    assert_eq!(
        default, with_exp,
        "no name detected => expansion changes nothing (byte-identical)"
    );
    // And there is no Name candidate at all.
    assert!(
        !default.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "no Name candidate in a name-free doc, got {default:?}"
    );
}

#[test]
fn strip_honorific_recovers_name_part() {
    assert_eq!(strip_honorific("Mr Greco"), "Greco");
    assert_eq!(strip_honorific("Dr. Tan Wei Ming"), "Tan Wei Ming");
    assert_eq!(strip_honorific("Justice Lee"), "Lee");
    // No honorific: unchanged (an aggressive-mode bare run propagates as-is).
    assert_eq!(strip_honorific("Massimo Greco"), "Massimo Greco");
}

// ---- PART 3: user-defined recognizers ("super find & replace") ----

#[test]
fn user_recognizer_case_sensitivity_differs() {
    // case_insensitive (default): "ACME" matches "acme"; case_sensitive: it
    // does NOT.
    let ci = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("co", "ACME")])
        .build()
        .unwrap();
    let (out_ci, n_ci) = ci.redact_text("the acme deal");
    assert!(
        !out_ci.contains("acme"),
        "case-insensitive matches, got {out_ci:?}"
    );
    assert_eq!(n_ci, 1);

    let cs = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("co", "ACME").case_sensitive()])
        .build()
        .unwrap();
    let (out_cs, n_cs) = cs.redact_text("the acme deal");
    assert_eq!(
        out_cs, "the acme deal",
        "case-sensitive must not match, got {out_cs:?}"
    );
    assert_eq!(n_cs, 0);
    // ...but it DOES match the exact case.
    let (out_cs2, n_cs2) = cs.redact_text("the ACME deal");
    assert!(
        !out_cs2.contains("ACME"),
        "case-sensitive matches exact case, got {out_cs2:?}"
    );
    assert_eq!(n_cs2, 1);
}

#[test]
fn user_recognizer_whole_word_matches_cat_not_category() {
    let e = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("animal", "cat").whole_word()])
        .build()
        .unwrap();
    // "cat" as a standalone word IS matched.
    let (out, n) = e.redact_text("the cat sat");
    assert!(
        !out.contains("cat"),
        "whole-word matches the bare word, got {out:?}"
    );
    assert_eq!(n, 1);
    // "category" is NOT matched (no word boundary inside it).
    let (out2, n2) = e.redact_text("the category list");
    assert_eq!(
        out2, "the category list",
        "whole-word must not match a substring, got {out2:?}"
    );
    assert_eq!(n2, 0);
}

#[test]
fn whole_word_literal_with_punctuation_edges_still_matches() {
    // FIX F1 (CRITICAL — silent whole-word miss on punctuation-bounded terms):
    // a `\b(?:…)\b` around a term whose first/last char is a NON-word char
    // requires a word transition that edge can never make, so it compiles,
    // passes the zero-width probe, and silently matches NOTHING. The fix drops
    // the vacuous `\b` on each non-word edge so the term still matches.

    // (a) BOTH edges punctuation: "(Pte Ltd)" -> `\(Pte\ Ltd\)`. The naive
    // `\b(?:…)\b` matched nothing; now it matches the bounded occurrence.
    let e = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("entity", "(Pte Ltd)").whole_word()
        ])
        .build()
        .unwrap();
    let (out, n) = e.redact_text("signed (Pte Ltd) herein");
    assert!(
        !out.contains("(Pte Ltd)"),
        "a punctuation-bounded whole_word term must still be redacted, got {out:?}"
    );
    assert_eq!(n, 1, "the bounded occurrence matched exactly once, got {n}");

    // (b) LEADING-punct term: ".NET" -> `\.NET`. The leading `\b` is vacuous
    // (a `.` edge), the trailing one is real (a `T` edge): drop the leading one.
    let e2 = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("tech", ".NET").whole_word()])
        .build()
        .unwrap();
    let (out2, n2) = e2.redact_text("built on .NET today");
    assert!(
        !out2.contains(".NET"),
        "a leading-punct whole_word term must match, got {out2:?}"
    );
    assert_eq!(n2, 1, "matched exactly once, got {n2}");
    // The surviving TRAILING `\b` still has whole-word force on the word-char
    // edge: ".NETWORK" must NOT match (no boundary after the "T").
    let (out2b, n2b) = e2.redact_text("the .NETWORK stack");
    assert_eq!(
        out2b, "the .NETWORK stack",
        "trailing boundary still enforced, got {out2b:?}"
    );
    assert_eq!(n2b, 0, "no boundary after T inside .NETWORK, got {n2b}");

    // (c) A normal all-word term still respects BOTH word boundaries: "Acme"
    // matches the bare word but NOT inside "Acme2" (regression guard that the
    // fix did NOT weaken whole-word semantics on genuine word-char edges).
    let e3 = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("party", "Acme").whole_word()])
        .build()
        .unwrap();
    let (out3, n3) = e3.redact_text("the Acme deal");
    assert!(!out3.contains("Acme"), "bare word matches, got {out3:?}");
    assert_eq!(n3, 1);
    let (out3b, n3b) = e3.redact_text("the Acme2 unit");
    assert_eq!(
        out3b, "the Acme2 unit",
        "must NOT match inside Acme2, got {out3b:?}"
    );
    assert_eq!(
        n3b, 0,
        "word boundary still enforced on both edges, got {n3b}"
    );
}

#[test]
fn user_recognizer_literal_vs_regex_mode() {
    // LITERAL mode treats "A.B (Pte)" literally: it does NOT match "AXB Pte"
    // (which only a regex interpretation would) and never panics.
    let lit = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("party", "A.B (Pte)")])
        .build()
        .unwrap();
    let (out_a, n_a) = lit.redact_text("party A.B (Pte) signed");
    assert!(
        !out_a.contains("A.B (Pte)"),
        "literal matched, got {out_a:?}"
    );
    assert_eq!(n_a, 1);
    let (out_b, n_b) = lit.redact_text("party AXB Pte signed");
    assert_eq!(
        out_b, "party AXB Pte signed",
        "literal must not match regex-only, got {out_b:?}"
    );
    assert_eq!(n_b, 0);

    // REGEX mode honors a real pattern: a matter-number shape.
    let rx = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer {
            label: "matter-no".to_string(),
            pattern: r"M-\d{4}".to_string(),
            mode: MatchMode::Regex,
            case_sensitive: false,
            whole_word: false,
            replacement: None,
        }])
        .build()
        .unwrap();
    let (out_r, n_r) = rx.redact_text("see matter M-2026 today");
    assert!(
        !out_r.contains("M-2026"),
        "regex pattern matched, got {out_r:?}"
    );
    assert_eq!(n_r, 1);
}

#[test]
fn invalid_user_regex_returns_err_no_panic() {
    // A malformed Regex-mode pattern (unbalanced paren) returns Err, never a
    // panic/unwrap inside the engine. (`RedactionEngine` is not `Debug`, so
    // match the result rather than `unwrap_err`.)
    // Map the Ok value away (RedactionEngine is not Debug) and inspect the err.
    let outcome = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer {
            label: "bad".to_string(),
            pattern: "(".to_string(),
            mode: MatchMode::Regex,
            case_sensitive: false,
            whole_word: false,
            replacement: None,
        }])
        .build()
        .map(|_| ());
    assert!(
        matches!(outcome, Err(CoreError::Backend(_))),
        "invalid user regex -> CoreError::Backend, got {outcome:?}"
    );
}

#[test]
fn user_replacement_written_for_non_overlapping_match() {
    // A non-overlapping match from a recognizer with a replacement writes the
    // replacement string, NOT the default marker.
    let e = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("party", "Acme").with_replacement("[PARTY-A]")
        ])
        .build()
        .unwrap();
    let (out, n) = e.redact_text("the Acme matter");
    assert_eq!(
        out, "the [PARTY-A] matter",
        "find-and-replace writes the replacement, got {out:?}"
    );
    assert!(
        !out.contains(REDACTION_MARKER),
        "no default marker for a replaced span"
    );
    assert_eq!(n, 1, "still one redaction (count == replacements written)");
}

#[test]
fn merged_overlap_uses_marker_not_replacement() {
    // Two recognizers whose spans OVERLAP merge into one — the ambiguous
    // combined replacement falls back to the default marker.
    let e = RedactionEngine::builder()
        .recognizers(vec![
            // "Acme Holdings" with a replacement, and...
            UserRecognizer::literal("party", "Acme Holdings").with_replacement("[A]"),
            // ...an overlapping "Holdings Pte" with a different replacement.
            UserRecognizer::literal("entity", "Holdings Pte").with_replacement("[B]"),
        ])
        .build()
        .unwrap();
    let (out, cands) = e.redact_detail("re Acme Holdings Pte Ltd today");
    // The union span "Acme Holdings Pte" is one candidate.
    assert_eq!(
        cands.len(),
        1,
        "overlap merged to one candidate, got {cands:?}"
    );
    assert!(
        out.contains(REDACTION_MARKER),
        "merged span uses the marker, got {out:?}"
    );
    assert!(
        !out.contains("[A]") && !out.contains("[B]"),
        "no ambiguous replacement, got {out:?}"
    );
    assert!(
        !out.contains("Acme Holdings Pte"),
        "the union span is gone, got {out:?}"
    );
}

#[test]
fn contained_custom_replacement_preserved_when_labels_differ() {
    // FIX F7 (HIGH — custom replacement no longer silently dropped on strict
    // containment): a `Custom` literal span carrying a CUSTOM replacement
    // (`jane.roe -> [PARTY]`) wholly inside a built-in email span (which
    // carries the default marker) must PRESERVE its custom replacement — the
    // union has exactly ONE distinct custom replacement, so it is unambiguous.
    // Before the fix the merge forced the default `[REDACTED]` marker, silently
    // discarding the firm's `[PARTY]` replacement.
    let e = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("party", "jane.roe").with_replacement("[PARTY]")
        ])
        .build()
        .unwrap();
    let text = "mail jane.roe@acme.example today";
    let (out, cands) = e.redact_detail(text);

    // The email span (built-in, default marker) and the contained custom
    // `jane.roe` (replacement `[PARTY]`) overlap -> ONE merged candidate over
    // the full email; the labels DIFFER (email built-in vs custom party).
    assert_eq!(
        cands.len(),
        1,
        "overlap merged to one candidate, got {cands:?}"
    );
    assert_eq!(
        cands[0].matched_value(),
        "jane.roe@acme.example",
        "merged span is the union (full email), got {:?}",
        cands[0].matched_value()
    );
    // The contained custom replacement is PRESERVED (not overwritten by the
    // default marker) — the single distinct custom replacement is unambiguous.
    assert!(
        out.contains("[PARTY]"),
        "custom replacement preserved on containment, got {out:?}"
    );
    assert!(
        !out.contains(REDACTION_MARKER),
        "the default marker must NOT overwrite the lone custom replacement, got {out:?}"
    );
    // The whole identifier (email + name) is gone, replaced exactly once.
    assert!(
        !out.contains("jane.roe@acme.example"),
        "the union span is gone, got {out:?}"
    );
    assert_eq!(
        out, "mail [PARTY] today",
        "one replacement over the union span, got {out:?}"
    );
    assert_eq!(
        out.matches("[PARTY]").count(),
        1,
        "exactly one replacement written"
    );

    // Control: when ≥2 DIFFERENT custom replacements collide over the union it
    // is genuinely ambiguous and STILL falls back to the marker (the prior
    // `merged_overlap_uses_marker_not_replacement` contract is unchanged).
    let e2 = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("a", "jane.roe").with_replacement("[A]"),
            UserRecognizer::literal("b", "roe@acme").with_replacement("[B]"),
        ])
        .build()
        .unwrap();
    let (out2, cands2) = e2.redact_detail(text);
    assert_eq!(
        cands2.len(),
        1,
        "still one merged candidate, got {cands2:?}"
    );
    assert!(
        out2.contains(REDACTION_MARKER),
        "2 distinct customs -> marker, got {out2:?}"
    );
    assert!(
        !out2.contains("[A]") && !out2.contains("[B]"),
        "ambiguous -> no custom, got {out2:?}"
    );
}

#[test]
fn user_label_appears_on_candidate_and_in_breakdown_no_cleartext() {
    // A user recognizer's LABEL is the candidate's recognizer, appears in the
    // audit breakdown, and the breakdown carries NO matched_value cleartext.
    let mut store = InMemoryMatterStore::new();
    store.insert(1, DataClass::Document, "the Globex account here");
    let mut core = core_with(redaction_grants(), store);
    let engine = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("party-name", "Globex")])
        .classes(vec![DataClass::Document])
        .build()
        .unwrap();
    let report = engine.redact_matter(&mut core).unwrap();

    // The candidate is attributed to the custom label.
    let doc = &report.docs()[0];
    let cand = doc
        .candidates()
        .iter()
        .find(|c| c.recognizer() == &Recognizer::Custom(Arc::from("party-name")))
        .unwrap_or_else(|| {
            panic!(
                "expected a party-name candidate, got {:?}",
                doc.candidates()
            )
        });
    assert_eq!(cand.matched_value(), "Globex");

    // The audit breakdown carries the label + count, never the cleartext.
    let notes: Vec<&str> = core
        .audit()
        .entries()
        .iter()
        .filter(|en| en.capability == Capability::AuditNote)
        .map(|en| en.detail.as_str())
        .collect();
    assert!(
        notes.iter().any(|d| d.contains("custom:party-name=1")),
        "breakdown has the namespaced label, notes = {notes:?}"
    );
    for note in &notes {
        assert!(
            !note.contains("Globex"),
            "audit must NOT contain cleartext, note = {note:?}"
        );
    }
}

#[test]
fn breakdown_deterministic_builtins_then_sorted_custom() {
    // Built-ins first (fixed order), then custom labels in sorted order — so
    // the audit string is stable regardless of config / match order.
    let e = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("zeta", "zzz"),
            UserRecognizer::literal("alpha", "aaa"),
        ])
        .build()
        .unwrap();
    // "a@b.com" -> email built-in; "aaa"/"zzz" -> the two customs.
    let cands = e.candidates("mail a@b.com aaa zzz");
    let breakdown = recognizer_breakdown(&cands);
    // email (built-in, bare) precedes the customs (namespaced), and alpha
    // precedes zeta (sorted).
    assert_eq!(
        breakdown, "email=1, custom:alpha=1, custom:zeta=1",
        "got {breakdown:?}"
    );
}

#[test]
fn pathological_pattern_completes_linear_time() {
    // The `regex` crate is linear-time (no catastrophic backtracking), so a
    // pattern + input that would hang a backtracking engine completes and
    // returns a result (we assert it returns, i.e. does not hang).
    let e = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer {
            label: "patho".to_string(),
            pattern: "(a+)+$".to_string(),
            mode: MatchMode::Regex,
            case_sensitive: false,
            whole_word: false,
            replacement: None,
        }])
        .build()
        .unwrap();
    let input = "a".repeat(40) + "!"; // classic ReDoS trigger for backtrackers
    let (_out, _n) = e.redact_text(&input);
    // Reaching here at all is the assertion (linear-time => it returns).
}

// ---- PART 4: review fixes ----

/// Build the engine with a single recognizer and map the Ok away (the engine
/// is not `Debug`), so a test can `matches!` on the error.
fn build_with(rec: UserRecognizer) -> Result<(), CoreError> {
    RedactionEngine::builder()
        .recognizers(vec![rec])
        .build()
        .map(|_| ())
}

#[test]
fn empty_or_zero_width_recognizer_rejected_fail_closed() {
    // FIX 1 (HIGH, fail-open -> FAIL-CLOSED): a recognizer that can only match
    // ZERO-WIDTH text would silently redact NOTHING (every match dropped by the
    // zero-width guard) while the audit reports 0 — a leaked identifier. Each
    // such pattern must abort construction with CoreError::Backend, not no-op.

    // An empty / whitespace-only LITERAL.
    assert!(
        matches!(
            build_with(UserRecognizer::literal("x", "")),
            Err(CoreError::Backend(_))
        ),
        "empty literal must be rejected"
    );
    assert!(
        matches!(
            build_with(UserRecognizer::literal("x", "   \t")),
            Err(CoreError::Backend(_))
        ),
        "whitespace-only literal must be rejected"
    );

    // Zero-width REGEX patterns: each matches the empty string.
    for pat in ["a*", r"\b", "(?:)", "^"] {
        let rec = UserRecognizer {
            label: "zw".to_string(),
            pattern: pat.to_string(),
            mode: MatchMode::Regex,
            case_sensitive: false,
            whole_word: false,
            replacement: None,
        };
        assert!(
            matches!(build_with(rec), Err(CoreError::Backend(_))),
            "zero-width regex {pat:?} must be rejected (no silent no-op)"
        );
    }

    // A genuine one-char-or-more regex still compiles fine (not over-rejected).
    let ok = UserRecognizer {
        label: "ok".to_string(),
        pattern: "a+".to_string(),
        mode: MatchMode::Regex,
        case_sensitive: false,
        whole_word: false,
        replacement: None,
    };
    assert!(
        build_with(ok).is_ok(),
        "a+ matches >=1 char and must be accepted"
    );
}

#[test]
fn custom_label_colliding_with_builtin_is_disambiguated() {
    // FIX 2 (audit ambiguity): a custom recognizer labelled like a built-in
    // (`"email"`) must NOT produce two bare `email=` entries. The built-in stays
    // bare; the custom is namespaced `custom:email=`.
    let e = RedactionEngine::builder()
        // The literal "x" appears twice -> custom:email=2; one real email -> email=1.
        .recognizers(vec![UserRecognizer::literal("email", "x")])
        .build()
        .unwrap();
    let cands = e.candidates("a@b.com has x and x here");
    let breakdown = recognizer_breakdown(&cands);
    assert!(
        breakdown.contains("email=1"),
        "built-in email bare, got {breakdown:?}"
    );
    assert!(
        breakdown.contains("custom:email=2"),
        "custom email namespaced, got {breakdown:?}"
    );
    // It must NOT read as an ambiguous bare collision.
    assert!(
        !breakdown.contains("email=1, email=2") && !breakdown.contains("email=2, email=1"),
        "no ambiguous bare collision, got {breakdown:?}"
    );
}

#[test]
fn invalid_custom_label_rejected_fail_closed() {
    // FIX 3 (label guardrail, fail-closed): empty/whitespace, over-long, and
    // delimiter-bearing labels must abort construction.
    assert!(
        matches!(
            build_with(UserRecognizer::literal("", "Acme")),
            Err(CoreError::Backend(_))
        ),
        "empty label must be rejected"
    );
    assert!(
        matches!(
            build_with(UserRecognizer::literal("   ", "Acme")),
            Err(CoreError::Backend(_))
        ),
        "whitespace-only label must be rejected"
    );
    let long = "x".repeat(100);
    assert!(
        matches!(
            build_with(UserRecognizer::literal(long, "Acme")),
            Err(CoreError::Backend(_))
        ),
        "100-char label must be rejected (>64)"
    );
    // FIX (medium): BOTH brackets are forbidden — a stray `[` ("[party" ->
    // "custom:[party=1]") unbalances the [..]-wrapped breakdown just as `]` does.
    for bad in ["ev=il", "a,b", "x]y", "[party", "x[y"] {
        assert!(
            matches!(
                build_with(UserRecognizer::literal(bad, "Acme")),
                Err(CoreError::Backend(_))
            ),
            "label with breakdown delimiter {bad:?} must be rejected"
        );
    }
    // A control char (tab) inside the label is also rejected.
    assert!(
        matches!(
            build_with(UserRecognizer::literal("a\tb", "Acme")),
            Err(CoreError::Backend(_))
        ),
        "label with a control char must be rejected"
    );
    // A normal label of reasonable length is accepted.
    assert!(
        build_with(UserRecognizer::literal("party-name", "Acme")).is_ok(),
        "a normal label must be accepted"
    );
}

#[test]
fn whole_word_with_regex_mode_rejected_fail_closed() {
    // FIX (HIGH — whole_word + Regex silent miss): whole_word wraps the body
    // in \b(?:…)\b. For a raw Regex whose body starts/ends with \s/\W, the
    // adjacent \b silently breaks the match — a rule that appears to work but
    // redacts nothing, with no signal. So whole_word is Literal-only; Regex
    // mode must REJECT it (fail-closed), directing the author to put \b in the
    // pattern themselves.
    let starts_with_ws = UserRecognizer {
        label: "conf".to_string(),
        pattern: r"\s+confidential\s+".to_string(),
        mode: MatchMode::Regex,
        case_sensitive: false,
        whole_word: true,
        replacement: None,
    };
    assert!(
        matches!(build_with(starts_with_ws), Err(CoreError::Backend(_))),
        "whole_word + Regex (body starting with \\s) must be rejected"
    );

    // The rule is UNIFORM: whole_word is rejected for Regex mode even when the
    // body is word-charactered (e.g. `M-\d{4}`), so there is no fragile
    // start/end heuristic to get wrong. The author uses an explicit \b instead.
    let word_charactered = UserRecognizer {
        label: "mno".to_string(),
        pattern: r"M-\d{4}".to_string(),
        mode: MatchMode::Regex,
        case_sensitive: false,
        whole_word: true,
        replacement: None,
    };
    assert!(
        matches!(build_with(word_charactered), Err(CoreError::Backend(_))),
        "whole_word is Literal-only — rejected for Regex mode uniformly"
    );

    // The supported combinations still compile:
    // (a) Literal + whole_word (the convenience path for a non-technical user);
    assert!(
        build_with(UserRecognizer::literal("cat", "cat").whole_word()).is_ok(),
        "Literal + whole_word remains supported"
    );
    // (b) Regex WITHOUT whole_word, using an explicit \b — the supported idiom.
    let explicit_wb = UserRecognizer {
        label: "wb".to_string(),
        pattern: r"\bcat\b".to_string(),
        mode: MatchMode::Regex,
        case_sensitive: false,
        whole_word: false,
        replacement: None,
    };
    assert!(
        build_with(explicit_wb).is_ok(),
        "explicit \\b in a Regex pattern is the supported word-boundary idiom"
    );
}

#[test]
fn over_long_replacement_rejected_fail_closed() {
    // FIX (LOW — bound the replacement): an unbounded replacement is a
    // memory-amplification footgun (a huge replacement × many matches). It is
    // capped like the label (256 chars). The error names the recognizer.
    let huge = "x".repeat(257);
    assert!(
        matches!(
            build_with(UserRecognizer::literal("p", "Acme").with_replacement(huge)),
            Err(CoreError::Backend(_))
        ),
        "an over-long replacement must be rejected"
    );
    // A normal, descriptive replacement is accepted.
    assert!(
        build_with(UserRecognizer::literal("p", "Acme").with_replacement("[REDACTED — PARTY A]"))
            .is_ok(),
        "a normal-length replacement must be accepted"
    );
    // Exactly at the cap (256) is accepted (boundary), one over is not.
    assert!(
        build_with(UserRecognizer::literal("p", "Acme").with_replacement("y".repeat(256))).is_ok(),
        "a replacement exactly at the cap must be accepted"
    );
}

/// Audit double that DELEGATES to an inner `InMemoryAudit` for every brokered
/// call EXCEPT it FAILS on `audit.note`. Used to prove the act-before-log fix:
/// list + read succeed (so the loop reaches the note), but the per-doc note
/// fails — and the redaction must then NOT commit.
struct NoteFailingAudit {
    inner: InMemoryAudit,
}

impl NoteFailingAudit {
    fn new() -> Self {
        Self {
            inner: InMemoryAudit::with_clock(FixedClock::new(1_700_000_000_000)),
        }
    }
}

impl Audit for NoteFailingAudit {
    fn record(
        &mut self,
        acting_user: &str,
        matter: &str,
        module: &str,
        capability: Capability,
        detail: &str,
    ) -> CoreResult<AuditHash> {
        if capability == Capability::AuditNote {
            return Err(CoreError::Backend("note backend unavailable".into()));
        }
        self.inner
            .record(acting_user, matter, module, capability, detail)
    }

    fn verify_chain(&self) -> bool {
        self.inner.verify_chain()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[test]
fn failed_audit_note_aborts_before_redaction_commits() {
    // FIX (HIGH — act-before-log): the per-doc audit note is recorded BEFORE
    // document_transform commits. If the note FAILS, the strip must NOT land,
    // so there is never a redacted-but-unlogged document. Wire a core whose
    // audit fails on audit.note ONLY (list + read still succeed).
    let mut store = InMemoryMatterStore::new();
    store.insert(1, DataClass::Document, SAMPLE);
    let mut core: Core<
        GrantSet,
        NoteFailingAudit,
        InMemoryStorage,
        InMemoryEgress,
        CoreContext,
        InMemoryMatterStore,
    > = Core::new(
        "sg.redaction.engine",
        GrantSet::from_manifest(vec![
            Capability::MatterRead(DataClass::Document),
            Capability::DocumentTransform,
        ]),
        NoteFailingAudit::new(),
        InMemoryStorage::new(),
        InMemoryEgress::new().with_destination("counsel-vault"),
        CoreContext::new("Acme v Beta", "j.smith"),
        store,
    );

    let engine = RedactionEngine::builder()
        .terms(vec!["Project Condor".to_string()])
        .classes(vec![DataClass::Document])
        .build()
        .unwrap();
    let err = engine.redact_matter(&mut core).unwrap_err();
    assert!(
        matches!(err, CoreError::Backend(_)),
        "the failed note must propagate, got {err:?}"
    );

    // CRUCIAL: the document is UNCHANGED — the identifier is still present and
    // no marker was written, proving the transform did NOT commit after the
    // note failed (fail-closed ordering). Read back through the core (a read
    // does not use audit.note, so it succeeds).
    let stored = core.matter_read_text(1, DataClass::Document).unwrap();
    assert!(
        stored.contains("Project Condor"),
        "redaction must NOT commit when the audit note fails, stored = {stored:?}"
    );
    assert!(
        !stored.contains(REDACTION_MARKER),
        "no marker may be written when the note failed, stored = {stored:?}"
    );
}

// ---- PART 5: review fixes (#5, #12, #13, #14, #15) ----

#[test]
fn builder_is_the_fallible_construction_path() {
    // FIX #12: the builder exposes classes / recognizers / build, and surfaces
    // firm-rule validation at build() time. The thin `new` remains for the
    // term-only case.
    let e = RedactionEngine::builder()
        .terms(vec!["Acme".to_string()])
        .classes(vec![DataClass::Document])
        .recognizers(vec![UserRecognizer::literal("party", "Globex")])
        .build()
        .unwrap();
    let (out, _n) = e.redact_text("Acme and Globex");
    assert!(
        !out.contains("Acme") && !out.contains("Globex"),
        "both stripped, got {out:?}"
    );

    // A bad recognizer fails at build() (fail-closed), never silently dropped.
    let bad = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("x", "")]) // empty literal
        .build()
        .map(|_| ());
    assert!(
        matches!(bad, Err(CoreError::Backend(_))),
        "build surfaces validation, got {bad:?}"
    );

    // `new` is still the infallible term-only convenience.
    let (out2, _n2) = RedactionEngine::new(vec!["Acme".to_string()]).redact_text("Acme deal");
    assert!(!out2.contains("Acme"), "new still works, got {out2:?}");
}

#[test]
fn same_pattern_rules_dedup_to_one_scan_candidate_carries_both_labels() {
    // FIX #5: two firm rules that compile to the SAME pattern (same literal,
    // same case flag) must compile + scan ONCE — not twice — and the matched
    // span must surface with BOTH labels (neither lost to the merge).
    let e = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("party-a", "Acme"),
            UserRecognizer::literal("party-b", "Acme"), // identical underlying pattern
        ])
        .build()
        .unwrap();

    // DEDUP: the two rules collapse to ONE compiled pattern (== one scan).
    assert_eq!(
        e.user_recognizers.len(),
        1,
        "two same-pattern rules must dedup to a single compiled scan"
    );
    // ...carrying BOTH tags off that single regex.
    assert_eq!(
        e.user_recognizers[0].tags.len(),
        2,
        "the single scan carries both labels"
    );

    // The matched span surfaces with BOTH labels (deterministically ordered:
    // both are Custom (priority 0) so by label ASC -> party-a, party-b).
    let cands = e.candidates("the Acme deal");
    assert_eq!(cands.len(), 1, "one span, got {cands:?}");
    let labels: Vec<&str> = cands[0].recognizers().iter().map(|r| r.label()).collect();
    assert_eq!(
        labels,
        vec!["party-a", "party-b"],
        "candidate carries BOTH labels, got {labels:?}"
    );
    // The PRIMARY recognizer (and the breakdown) still count exactly one — the
    // audit string is unchanged by the richer multi-label attribution.
    assert_eq!(
        cands[0].recognizer().label(),
        "party-a",
        "primary = first by order"
    );
    let breakdown = recognizer_breakdown(&cands);
    assert_eq!(
        breakdown, "custom:party-a=1",
        "audit counts the PRIMARY only, got {breakdown:?}"
    );
}

#[test]
fn recognizer_breakdown_single_pass_matches_reference_on_mixed_set() {
    // FIX #13: the single-pass HashMap fold must produce the SAME deterministic
    // string a per-variant reference computes, on a mixed candidate set.
    // Build candidates directly (test module sees the private fields).
    fn cand(rec: Recognizer) -> RedactionCandidate {
        RedactionCandidate {
            start: 0,
            end: 1,
            matched_value: "x".to_string(),
            recognizer: rec.clone(),
            recognizers: vec![rec],
            context: "x".to_string(),
            confidence: Confidence::Low,
        }
    }
    let custom = |name: &str| Recognizer::Custom(Arc::from(name));
    let locale = |name: &str| Recognizer::Locale(Arc::from(name));
    let set = vec![
        cand(Recognizer::Name),
        cand(Recognizer::Email),
        cand(Recognizer::Email),
        cand(custom("zeta")),
        cand(Recognizer::Term),
        cand(custom("alpha")),
        cand(custom("alpha")),
        cand(Recognizer::Id),
        // A locale recognizer sorts after the built-ins, before the customs.
        cand(locale("sg:nric")),
    ];

    // Reference: count primary recognizers, emit built-ins in fixed order, then
    // locale labels lexicographically, then profile labels lexicographically, then
    // customs lexicographically — the documented contract
    // (built-ins < locale: < profile: < custom:).
    let reference = {
        use std::collections::BTreeMap;
        let mut builtins: BTreeMap<u8, (&str, usize)> = BTreeMap::new();
        let mut locales: BTreeMap<String, usize> = BTreeMap::new();
        let mut profiles: BTreeMap<String, usize> = BTreeMap::new();
        let mut customs: BTreeMap<String, usize> = BTreeMap::new();
        let mut contexts: BTreeMap<String, usize> = BTreeMap::new();
        for c in &set {
            match &c.recognizer {
                Recognizer::Term => builtins.entry(0).or_insert(("term", 0)).1 += 1,
                Recognizer::Email => builtins.entry(1).or_insert(("email", 0)).1 += 1,
                Recognizer::Phone => builtins.entry(2).or_insert(("phone", 0)).1 += 1,
                Recognizer::Id => builtins.entry(3).or_insert(("id", 0)).1 += 1,
                Recognizer::Name => builtins.entry(4).or_insert(("name", 0)).1 += 1,
                Recognizer::Lei => builtins.entry(5).or_insert(("lei", 0)).1 += 1,
                Recognizer::CreditCard => builtins.entry(6).or_insert(("credit-card", 0)).1 += 1,
                Recognizer::Iban => builtins.entry(7).or_insert(("iban", 0)).1 += 1,
                Recognizer::Ip => builtins.entry(8).or_insert(("ip", 0)).1 += 1,
                Recognizer::Url => builtins.entry(9).or_insert(("url", 0)).1 += 1,
                Recognizer::Address => builtins.entry(10).or_insert(("address", 0)).1 += 1,
                Recognizer::Bic => builtins.entry(11).or_insert(("bic", 0)).1 += 1,
                Recognizer::Isin => builtins.entry(12).or_insert(("isin", 0)).1 += 1,
                Recognizer::Locale(l) => *locales.entry(l.to_string()).or_insert(0) += 1,
                Recognizer::Profile(l) => *profiles.entry(l.to_string()).or_insert(0) += 1,
                Recognizer::Custom(n) => *customs.entry(n.to_string()).or_insert(0) += 1,
                // Context entries (label already `ctx:`-prefixed) sort/emit LAST,
                // mirroring `RecognizerKey::Context` (declared after `Custom`).
                Recognizer::Context(n) => *contexts.entry(n.to_string()).or_insert(0) += 1,
            }
        }
        let mut parts: Vec<String> = builtins.values().map(|(l, n)| format!("{l}={n}")).collect();
        for (l, n) in locales {
            parts.push(format!("locale:{l}={n}"));
        }
        for (l, n) in profiles {
            parts.push(format!("profile:{l}={n}"));
        }
        for (l, n) in customs {
            parts.push(format!("custom:{l}={n}"));
        }
        for (l, n) in contexts {
            parts.push(format!("{l}={n}"));
        }
        parts.join(", ")
    };

    let actual = recognizer_breakdown(&set);
    assert_eq!(
        actual, reference,
        "single-pass output must equal the reference"
    );
    // And the exact expected string (fixed built-in order, then locale, then
    // sorted customs).
    assert_eq!(
        actual, "term=1, email=2, id=1, name=1, locale:sg:nric=1, custom:alpha=2, custom:zeta=1",
        "got {actual:?}"
    );
    // Empty set -> "none" (unchanged).
    assert_eq!(recognizer_breakdown(&[]), "none");
}

#[test]
fn many_matches_under_one_custom_recognizer_share_the_label() {
    // FIX #14: a single Custom recognizer matching many times shares ONE label
    // allocation (Arc<str>) across every candidate — per-match attribution is a
    // refcount bump, not a heap copy. Assert all candidates point at the SAME
    // backing label (pointer identity) AND that the engine's tag is that Arc.
    let e = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("party", "ACME")])
        .build()
        .unwrap();
    // The engine's single tag holds the canonical Arc<str>.
    let engine_label: &Arc<str> = match &e.user_recognizers[0].tags[0].kind {
        Recognizer::Custom(a) => a,
        other => panic!("expected a Custom tag, got {other:?}"),
    };

    let text = "ACME ACME ACME ACME ACME"; // 5 matches
    let cands = e.candidates(text);
    assert_eq!(cands.len(), 5, "five matches, got {}", cands.len());
    for c in &cands {
        match c.recognizer() {
            Recognizer::Custom(a) => {
                // Same heap allocation as the engine's tag (refcount-shared) —
                // attribution did not clone the label text per match.
                assert!(
                    Arc::ptr_eq(a, engine_label),
                    "every match must SHARE the one label allocation"
                );
            }
            other => panic!("expected a Custom recognizer, got {other:?}"),
        }
    }
    // Label content is correct and the breakdown counts all five.
    assert_eq!(recognizer_breakdown(&cands), "custom:party=5");
}

#[test]
fn context_snippet_bounded_and_char_safe_at_large_offset_multibyte() {
    // FIX #15: a match at a LARGE byte offset must still yield a snippet bounded
    // to ±CONTEXT_CHARS, landing on char boundaries even with multibyte context
    // (no mid-codepoint slice), and identical to the reference window.
    // Build: a long multibyte run, then a target term far in.
    let lead = "é".repeat(500); // 1000 bytes, 500 chars, all multibyte
    let text = format!("{lead} TARGET trailing café");
    let target_byte = text.find("TARGET").unwrap();
    assert!(
        target_byte > 900,
        "the match really is at a large byte offset ({target_byte})"
    );

    let e = RedactionEngine::builder()
        .recognizers(vec![UserRecognizer::literal("t", "TARGET")])
        .build()
        .unwrap();
    let cands = e.candidates(&text);
    let c = cands
        .iter()
        .find(|c| c.matched_value() == "TARGET")
        .expect("TARGET matched");

    let snippet = c.context();
    // The snippet is a valid substring of the original (so it lands on char
    // boundaries — slicing mid-codepoint would have panicked at construction).
    assert!(
        text.contains(snippet),
        "snippet is a real substring of the original"
    );
    // It surrounds the match.
    assert!(
        snippet.contains("TARGET"),
        "snippet contains the match, got {snippet:?}"
    );
    // It is BOUNDED to <= CONTEXT_CHARS on each side (+ the match width). The
    // lead is far longer than CONTEXT_CHARS, so the snippet must NOT contain the
    // whole lead — proving the back-walk stopped early (O(CONTEXT_CHARS)).
    let snippet_chars = snippet.chars().count();
    let max_chars = CONTEXT_CHARS + "TARGET".chars().count() + CONTEXT_CHARS;
    assert!(
        snippet_chars <= max_chars,
        "snippet must be bounded to ±CONTEXT_CHARS, got {snippet_chars} chars: {snippet:?}"
    );
    assert!(
        !snippet.contains(&lead),
        "the full long lead must NOT be in the bounded snippet"
    );

    // Byte-IDENTICAL to the explicit reference window built from the public
    // floor/ceil boundary helpers over the same span.
    let lo = floor_char_boundary_back(&text, c.start(), CONTEXT_CHARS);
    let hi = ceil_char_boundary_fwd(&text, c.end(), CONTEXT_CHARS);
    assert_eq!(
        snippet,
        &text[lo..hi],
        "snippet == the reference ±CONTEXT_CHARS window"
    );

    // Direct multibyte boundary check on the back-walk: from the middle of the
    // multibyte run, the result is a char boundary and exactly CONTEXT_CHARS back.
    let from = lead.len(); // 1000, a boundary between 'é' and ' '
    let back = floor_char_boundary_back(&text, from, CONTEXT_CHARS);
    assert!(
        text.is_char_boundary(back),
        "back index lands on a char boundary"
    );
    assert_eq!(
        text[back..from].chars().count(),
        CONTEXT_CHARS,
        "exactly CONTEXT_CHARS characters were walked back"
    );
}

// ---- PART 6: expanded built-in recognizers (NRIC / card / IBAN / IP / URL) ----

/// Find a candidate of an exact recognizer kind in a candidate list.
fn find_kind<'a>(
    cands: &'a [RedactionCandidate],
    kind: &Recognizer,
) -> Option<&'a RedactionCandidate> {
    cands.iter().find(|c| c.recognizer() == kind)
}

/// The jurisdiction-namespaced NRIC recognizer (now an OPT-IN SG locale pack).
fn sg_nric() -> Recognizer {
    Recognizer::Locale(Arc::from("sg:nric"))
}

/// An engine with ONLY the SG locale pack enabled (no terms / firm recognizers).
fn sg_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .locales([Locale::Singapore])
        .build()
        .unwrap()
}

#[test]
fn nric_format_matched_recall_first() {
    // SG NRIC/FIN: format-only (the check letter is NOT verified — recall-first,
    // never a miss). Every valid prefix (S/T/F/G/M) + 7 digits + a letter is
    // flagged and stripped, regardless of whether the check letter is "correct".
    // It is now an OPT-IN locale pack, enabled via `.locales([Locale::Singapore])`.
    let e = sg_engine();
    for nric in [
        "S1234567A",
        "T0123456Z",
        "F7654321N",
        "G1112223X",
        "M5043212K",
    ] {
        let cands = e.candidates(&format!("holder {nric} on file"));
        let c = find_kind(&cands, &sg_nric())
            .unwrap_or_else(|| panic!("expected NRIC for {nric:?}, got {cands:?}"));
        assert_eq!(c.matched_value(), nric, "span is the whole NRIC");
    }
    // It is removed by a redaction pass.
    let (out, n) = e.redact_text("NRIC S1234567A noted");
    assert!(!out.contains("S1234567A"), "NRIC stripped, got {out:?}");
    assert!(n >= 1);
    // A lowercase prefix is NOT an NRIC (avoids matching prose).
    assert!(
        find_kind(&e.candidates("s1234567a"), &sg_nric()).is_none(),
        "lowercase prefix is not matched as an NRIC"
    );
}

#[test]
fn credit_card_luhn_valid_matched_invalid_rejected() {
    // The Luhn validator is what makes a digit run a CARD: a Luhn-valid number
    // (with or without grouping) is flagged; a Luhn-INVALID one of the same
    // shape is not (the validator filtered it — no false card).
    let e = RedactionEngine::new(Vec::<String>::new());

    for card in [
        "4111111111111111",
        "4111 1111 1111 1111",
        "4242-4242-4242-4242",
    ] {
        let cands = e.candidates(&format!("paid with {card} today"));
        let c = find_kind(&cands, &Recognizer::CreditCard)
            .unwrap_or_else(|| panic!("expected a card for {card:?}, got {cands:?}"));
        assert_eq!(c.matched_value(), card, "span is the whole grouped card");
    }

    // Luhn-INVALID (last digit changed) -> not a card.
    let bad = e.candidates("paid with 4111 1111 1111 1112 today");
    assert!(
        find_kind(&bad, &Recognizer::CreditCard).is_none(),
        "a Luhn-invalid number must NOT be flagged as a card, got {bad:?}"
    );

    // Unit-level Luhn checks (the property the recognizer leans on).
    assert!(luhn_valid("4111111111111111"));
    assert!(luhn_valid("4242 4242 4242 4242"));
    assert!(!luhn_valid("4111111111111112"));
    assert!(!luhn_valid("123")); // too short
}

#[test]
fn card_glued_to_word_char_prefix_still_caught() {
    // REGRESSION (review H1 — recall-first): a leading `\b` used to SILENTLY MISS
    // a Luhn-valid card glued to a word char (no separator). A real card after a
    // label like `customerID` MUST still be detected and stripped.
    let e = RedactionEngine::new(Vec::<String>::new());
    for glued in [
        "customerID4012888888881881",
        "card:4111111111111111",
        "x4242424242424242",
    ] {
        let cands = e.candidates(glued);
        assert!(
            find_kind(&cands, &Recognizer::CreditCard).is_some(),
            "a card glued to a prefix must still be caught in {glued:?}, got {cands:?}"
        );
        let (out, _n) = e.redact_text(glued);
        // The 16-digit run is gone (the digits do not survive).
        assert!(
            !out.contains("4012888888881881")
                && !out.contains("4111111111111111")
                && !out.contains("4242424242424242"),
            "the card digits must be removed, got {out:?}"
        );
    }
}

#[test]
fn iban_mod97_valid_matched_invalid_rejected() {
    // The mod-97 validator defines an IBAN: the canonical valid examples are
    // flagged; a one-digit corruption of the check is rejected.
    let e = RedactionEngine::new(Vec::<String>::new());
    for iban in ["GB82WEST12345698765432", "DE89370400440532013000"] {
        let cands = e.candidates(&format!("remit to {iban} by Friday"));
        let c = find_kind(&cands, &Recognizer::Iban)
            .unwrap_or_else(|| panic!("expected an IBAN for {iban:?}, got {cands:?}"));
        assert_eq!(c.matched_value(), iban);
    }
    // Spaced grouping still validates + matches.
    let spaced = "GB82 WEST 1234 5698 7654 32";
    let cands = e.candidates(&format!("acct {spaced} noted"));
    assert!(
        find_kind(&cands, &Recognizer::Iban).is_some(),
        "spaced IBAN matched, got {cands:?}"
    );

    // A corrupted check digit fails mod-97 -> not an IBAN.
    assert!(
        find_kind(
            &e.candidates("remit to GB82WEST12345698765433 now"),
            &Recognizer::Iban
        )
        .is_none(),
        "a mod-97-invalid IBAN must be rejected"
    );

    // Unit-level mod-97 checks.
    assert!(iban_valid("GB82WEST12345698765432"));
    assert!(iban_valid("DE89 3704 0044 0532 0130 00"));
    assert!(!iban_valid("GB82WEST12345698765433"));
    assert!(!iban_valid("GB00WEST12345698765432"));

    // REGRESSION (review H1): an IBAN glued to a word-char prefix (no separator)
    // must still be caught — the leading `\b` is gone; mod-97 supplies precision.
    let glued = "refGB82WEST12345698765432";
    assert!(
        find_kind(&e.candidates(glued), &Recognizer::Iban).is_some(),
        "a glued-prefix IBAN must still be caught, got {:?}",
        e.candidates(glued)
    );
}

/// An engine with ONLY the OPT-IN LEI recognizer enabled (no terms / firm rules).
fn lei_engine() -> RedactionEngine {
    RedactionEngine::builder().lei(true).build().unwrap()
}

#[test]
fn lei_off_by_default_is_byte_identical() {
    // OFF by default: a DIGIT-LEADING LEI is invisible to every default recognizer
    // (the broad `id` is letter-leading, so it never matches `549300...`). This is
    // the clean off-by-default demonstration: with LEI off the candidate set is
    // EMPTY for a doc whose only identifier is a digit-leading LEI — byte-identical
    // to before this recognizer existed.
    let text = "Counterparty LEI 549300ABCDEFGHIJKL19 on the trade.";
    let default_engine = RedactionEngine::new(Vec::<String>::new());
    let cands = default_engine.candidates(text);
    assert!(
        !cands.iter().any(|c| *c.recognizer() == Recognizer::Lei),
        "no LEI candidate without the opt-in, got {cands:?}"
    );
    assert!(
        cands.is_empty(),
        "a digit-leading LEI is invisible to the default recognizers, got {cands:?}"
    );
    // Even `BuiltinRecognizers::all()` (every global built-in ON) does NOT enable the
    // LEI — it is a deliberate user choice, not an always-on built-in.
    let all_builtins = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::all())
        .build()
        .unwrap();
    assert!(
        !all_builtins
            .candidates(text)
            .iter()
            .any(|c| *c.recognizer() == Recognizer::Lei),
        "BuiltinRecognizers::all() must NOT enable the opt-in LEI"
    );
}

#[test]
fn lei_mod97_valid_matched_invalid_rejected_when_enabled() {
    // With the opt-in ON, a mod-97-10-valid LEI is flagged whole; a checksum-failing
    // token of the same shape is rejected (the validator filters it — no false LEI).
    let e = lei_engine();
    // A real public LEI + several SYNTHETIC valids (digit- AND letter-leading).
    for lei in [
        "GV6BTOXCWEVJ5EDH9831",
        "549300ABCDEFGHIJKL19",
        "9845001A2B3C4D5E6F36",
        "ABCDEF123456GHIJKL89",
        "529900T8BM49AURSDO55",
    ] {
        let cands = e.candidates(&format!("entity {lei} registered"));
        let c = find_kind(&cands, &Recognizer::Lei)
            .unwrap_or_else(|| panic!("expected an LEI for {lei:?}, got {cands:?}"));
        assert_eq!(c.matched_value(), lei, "span is the whole 20-char LEI");
        // A checksum-validated identifier is rung-1 High regardless of context.
        assert_eq!(
            c.confidence(),
            Confidence::High,
            "a mod-97-valid LEI is High"
        );
    }
    // A corrupted check digit fails mod-97-10 -> not an LEI (SYNTHETIC invalids).
    for bad in [
        "549300ABCDEFGHIJKL10",
        "ABCDEF123456GHIJKL80",
        "54930012345678901234",
    ] {
        assert!(
            find_kind(
                &e.candidates(&format!("entity {bad} registered")),
                &Recognizer::Lei
            )
            .is_none(),
            "a checksum-invalid LEI shape must be rejected: {bad:?}"
        );
    }
    // It is removed by a redaction pass (true byte removal of the identifier).
    let (out, n) = e.redact_text("Trade LEI 549300ABCDEFGHIJKL19 booked.");
    assert!(
        !out.contains("549300ABCDEFGHIJKL19"),
        "LEI stripped, got {out:?}"
    );
    assert!(n >= 1);

    // The audit breakdown attributes it under the cleartext-free `lei` label.
    let cands = e.candidates("Two LEIs: 549300ABCDEFGHIJKL19 and 529900T8BM49AURSDO55.");
    let breakdown = recognizer_breakdown(&cands);
    assert!(
        breakdown.contains("lei=2"),
        "breakdown counts both LEIs under `lei`, got {breakdown:?}"
    );
}

#[test]
fn lei_unit_validator_vectors() {
    // Unit-level mod-97-10 checks (the property the recognizer leans on). The IBAN
    // rearrangement is NOT used (an LEI is checked in order), so these are distinct
    // from `iban_valid`.
    assert!(lei_valid("GV6BTOXCWEVJ5EDH9831"));
    assert!(lei_valid("549300ABCDEFGHIJKL19"));
    assert!(lei_valid("549300 ABCDEFGHIJKL 19")); // whitespace ignored
    assert!(!lei_valid("549300ABCDEFGHIJKL10")); // corrupted check
    assert!(!lei_valid("GV6BTOXCWEVJ5EDH983")); // 19 chars (too short)
    assert!(!lei_valid("GV6BTOXCWEVJ5EDH98311")); // 21 chars (too long)
    assert!(
        !iban_valid("549300ABCDEFGHIJKL19"),
        "an LEI is not an IBAN under rearrangement"
    );
}

#[test]
fn ip_v4_and_v6_matched_octet_bounds_enforced() {
    let e = RedactionEngine::new(Vec::<String>::new());
    for ip in [
        "192.168.1.1",
        "255.255.255.255",
        "10.0.0.255",
        "2001:db8::1",
        "fe80::1",
        "2001:0db8:0000:0000:0000:ff00:0042:8329",
    ] {
        let cands = e.candidates(&format!("host {ip} reachable"));
        let c = find_kind(&cands, &Recognizer::Ip)
            .unwrap_or_else(|| panic!("expected an IP for {ip:?}, got {cands:?}"));
        assert_eq!(c.matched_value(), ip, "span is the whole address");
    }
    // Out-of-range octet is NOT an IPv4 (per-octet 0–255 bound).
    assert!(
        find_kind(&e.candidates("not 999.1.1.1 here"), &Recognizer::Ip).is_none(),
        "999.x.x.x is not a valid dotted-quad"
    );
    // A bare time-like "12:34" is NOT matched as IPv6 (needs real hex groups / ::).
    assert!(
        find_kind(&e.candidates("at 12:34 today"), &Recognizer::Ip).is_none(),
        "time-like text must not be flagged as IPv6"
    );
}

#[test]
fn ipv4_mapped_ipv6_fully_covered_by_merge() {
    // REGRESSION (review L1): an IPv4-mapped IPv6 like `::ffff:192.168.1.1` is
    // matched by the IPv6 regex (the `::ffff:` head) AND the IPv4 regex (the
    // dotted-quad tail); the two spans overlap, so the merge must cover the WHOLE
    // address — no embedded IPv4 left in cleartext.
    let e = RedactionEngine::new(Vec::<String>::new());
    let (out, _n) = e.redact_text("peer ::ffff:192.168.1.1 connected");
    assert!(
        !out.contains("192.168.1.1"),
        "the embedded IPv4 must not survive, got {out:?}"
    );
    assert!(
        !out.contains("::ffff:"),
        "the IPv6 head must not survive, got {out:?}"
    );
    // And it is one merged candidate over the full mapped address.
    let cands = e.candidates("peer ::ffff:192.168.1.1 connected");
    let ip = cands
        .iter()
        .find(|c| c.matched_value().contains("192.168.1.1"))
        .expect("a candidate covers the IPv4 tail");
    assert!(
        ip.matched_value().contains("::ffff:192.168.1.1"),
        "the merged span covers the whole mapped address, got {:?}",
        ip.matched_value()
    );
}

#[test]
fn url_scheme_and_bare_www_matched_trailing_punct_excluded() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // Scheme URL: the trailing sentence period is NOT swallowed.
    let cands = e.candidates("see https://example.com/path?q=1 now.");
    let c = find_kind(&cands, &Recognizer::Url).expect("scheme URL matched");
    assert_eq!(c.matched_value(), "https://example.com/path?q=1");
    // Bare www host.
    let cands2 = e.candidates("visit www.example.com today");
    let c2 = find_kind(&cands2, &Recognizer::Url).expect("bare www matched");
    assert_eq!(c2.matched_value(), "www.example.com");
}

#[test]
fn builtins_can_be_disabled_individually() {
    // With every built-in OFF, only the term list runs: an email is left intact
    // but a configured term is still stripped.
    let only_terms = RedactionEngine::builder()
        .terms(vec!["Acme".to_string()])
        .builtins(BuiltinRecognizers::none())
        .build()
        .unwrap();
    let (out, _n) = only_terms.redact_text("Acme at a@b.com ref AB1234");
    assert!(!out.contains("Acme"), "term still stripped, got {out:?}");
    assert!(
        out.contains("a@b.com"),
        "email recognizer OFF -> left intact, got {out:?}"
    );
    assert!(
        out.contains("AB1234"),
        "id recognizer OFF -> left intact, got {out:?}"
    );

    // Selectively enable ONLY the id recognizer off an all-off base.
    let only_id = RedactionEngine::builder()
        .builtins(BuiltinRecognizers {
            id: true,
            ..BuiltinRecognizers::none()
        })
        .build()
        .unwrap();
    let (out2, _n2) = only_id.redact_text("a@b.com and AB1234");
    assert!(out2.contains("a@b.com"), "email OFF, got {out2:?}");
    assert!(!out2.contains("AB1234"), "id ON -> stripped, got {out2:?}");
}

#[test]
fn nric_wins_as_primary_over_broad_id_on_overlap() {
    // An NRIC shape can also satisfy the broad `id` recognizer; the more
    // specific locale NRIC (priority 1) must win as the merged span's PRIMARY
    // recognizer over the broad `id` (priority 3). Needs the SG locale enabled.
    let e = sg_engine();
    let cands = e.candidates("ref S1234567A here");
    // Exactly one merged candidate over the NRIC (id + nric overlap -> merge).
    let over: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.matched_value().contains("1234567"))
        .collect();
    assert_eq!(
        over.len(),
        1,
        "id+nric overlap merged to one, got {cands:?}"
    );
    assert_eq!(
        over[0].recognizer(),
        &sg_nric(),
        "NRIC is the primary (more specific)"
    );
}

// ===================================================================
// "AGGRESSIVE RECOGNIZERS LAST" precedence (recall-NEUTRAL primary-election)
// ===================================================================
//
// A BROAD, format-only locale row (driver's licence / passport / generic account /
// BSB / transit / sort code — marked `aggressive: true` in its pack) must be elected
// the PRIMARY of an overlapping merged span only as a LAST RESORT: a precise sibling
// (a checksum locale row, an NRIC, an email) always out-LABELS it. The demotion is
// PRECEDENCE-ONLY — it NEVER changes whether a candidate fires or is dropped (a token
// matched only by an aggressive row is still redacted, just labeled by it).

/// A US-locale-only engine (no terms / firm recognizers); has the aggressive rows
/// `us:account` / `us:passport` / `us:dl` plus the precise checksum rows.
fn us_locale_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .locales([Locale::UnitedStates])
        .build()
        .unwrap()
}

/// The jurisdiction-namespaced US recognizer for a row name (e.g. `us:npi`).
fn us_locale(name: &str) -> Recognizer {
    Recognizer::Locale(Arc::from(format!("us:{name}").as_str()))
}

#[test]
fn precise_out_labels_aggressive_on_overlap() {
    // THE CORE GUARANTEE. The token `1234567893` is a VALID NPI (precise checksum row
    // `us:npi`, priority 1) AND is covered by TWO aggressive rows on the same span:
    // `us:account` (`\d{8,17}`, fires unconditionally) and `us:dl` (`\d{7,12}`, fired
    // here by the in-window "licence" keyword). The aggressive labels sort BEFORE the
    // precise one (`us:account` < `us:dl` < `us:npi`), so WITHOUT the demotion the
    // label-ASC tie-break would elect `us:account` as PRIMARY. With "aggressive last"
    // the precise `us:npi` is elected instead — the broad rows are demoted below it.
    let e = us_locale_engine();
    let cands = e.candidates("Driver's licence 1234567893 on file");
    let over: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.matched_value().contains("1234567893"))
        .collect();
    assert_eq!(
        over.len(),
        1,
        "one merged candidate over the NPI token, got {cands:?}"
    );
    let c = over[0];
    // PRIMARY is the PRECISE row, not the alphabetically-earlier aggressive `us:account`.
    assert_eq!(
        c.recognizer(),
        &us_locale("npi"),
        "the precise checksum row must out-label the aggressive rows, got {:?}",
        c.recognizers()
    );
    // RECALL-NEUTRAL: both aggressive rows STILL fired (present in the span's
    // recognizer list) — the demotion changed only WHICH row labels the span, never
    // whether the aggressive rows contribute. The span is redacted regardless.
    assert!(
        c.recognizers().contains(&us_locale("account")),
        "the aggressive us:account row still fires, got {:?}",
        c.recognizers()
    );
    assert!(
        c.recognizers().contains(&us_locale("dl")),
        "the aggressive us:dl row still fires (keyword in-window), got {:?}",
        c.recognizers()
    );
}

#[test]
fn precise_email_out_labels_aggressive_account_on_overlap() {
    // A second precise-wins case across a different axis: an EMAIL (precise global
    // built-in, priority 2) whose local-part is a long digit run that the aggressive
    // `us:account` (`\d{8,17}`) also grabs. The merged span must be LABELED `email`,
    // not the demoted `us:account`.
    let e = us_locale_engine();
    let cands = e.candidates("contact 123456789@example.com please");
    let over: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.matched_value().contains("123456789"))
        .collect();
    assert_eq!(
        over.len(),
        1,
        "one merged candidate over the email, got {cands:?}"
    );
    assert_eq!(
        over[0].recognizer(),
        &Recognizer::Email,
        "email (precise) out-labels the aggressive account, got {:?}",
        over[0].recognizers()
    );
}

#[test]
fn token_matched_only_by_aggressive_row_still_redacts() {
    // RECALL REGRESSION GUARD. With ALL global built-ins OFF, the token `X12345678`
    // (a passport shape: letter + 8 digits) can be matched ONLY by the aggressive
    // `us:dl` row (`[A-Z]\d{4,12}`, fired by the "licence" keyword) — there is no
    // precise sibling and no global recognizer to fall back on. The demotion must
    // NOT suppress it: the span is still detected + redacted, attributed to the
    // aggressive row. (This is the load-bearing recall-neutral invariant: "aggressive
    // last" changes the LABEL contest, never fire/drop.)
    let e = RedactionEngine::builder()
        .locales([Locale::UnitedStates])
        .builtins(BuiltinRecognizers::none())
        .build()
        .unwrap();
    let text = "Driver's licence X12345678 noted";
    let cands = e.candidates(text);
    let over: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.matched_value().contains("X12345678"))
        .collect();
    assert_eq!(
        over.len(),
        1,
        "the only-aggressive token must STILL produce a candidate, got {cands:?}"
    );
    // It is attributed to the aggressive row (nothing else could match it here) and
    // is the PRIMARY (last-resort election: there is no precise sibling to prefer).
    assert!(
        over[0].recognizers().contains(&us_locale("dl")),
        "the aggressive us:dl row produced the candidate, got {:?}",
        over[0].recognizers()
    );
    assert_eq!(
        over[0].recognizer(),
        &us_locale("dl"),
        "aggressive row is the last-resort primary"
    );
    // And a redaction pass actually REMOVES the token (true recall, not just a flag).
    let (out, n) = e.redact_text(text);
    assert!(
        !out.contains("X12345678"),
        "the only-aggressive token is redacted, got {out:?}"
    );
    assert!(n >= 1, "at least one redaction applied");
}

#[test]
fn aggressive_precedence_default_path_is_byte_identical() {
    // The demotion is INERT on the default path: an aggressive locale row is only ever
    // ELECTED primary as a last resort, and a CONTEXT-gated aggressive row (`us:dl`,
    // `sg:postal-bare`) does not even fire without its keyword. Prove it by a control:
    // the SAME text through an SG engine — whose ONLY aggressive row (`sg:postal-bare`,
    // context-gated) does not fire here (no postal keyword) — never elects an aggressive
    // primary; every sg:* primary on this text is a PRECISE locale row (priority 1).
    let text = "Counterparty UEN 201912345A, NRIC S1234567A, email a@b.io, 456-78-9012.";
    let sg = sg_engine();
    let with_aggr = us_locale_engine();
    for c in sg.candidates(text) {
        // No candidate is ever attributed to a demoted aggressive priority here —
        // every sg:* primary is a precise locale row (priority 1), unchanged.
        if let Recognizer::Locale(l) = c.recognizer() {
            assert!(
                !with_aggr.aggressive_locales.contains(l),
                "an SG-only engine must never elect an aggressive primary, got {:?}",
                c.recognizer()
            );
        }
    }
    // The SG pack now registers exactly ONE aggressive row — the context-gated
    // `sg:postal-bare` recall net — and NOTHING else (the precise sg:nric/sg:uen/sg:postal
    // rows are default-ON, not aggressive). It does not fire on this keyword-less text, so
    // the default path stays byte-identical.
    assert_eq!(
        sg.aggressive_locales.len(),
        1,
        "SG pack has exactly one aggressive row (sg:postal-bare)"
    );
    assert!(
        sg.aggressive_locales.contains(&Arc::from("sg:postal-bare")),
        "the single SG aggressive row is sg:postal-bare"
    );
    assert!(
        !with_aggr.aggressive_locales.is_empty(),
        "US engine DOES register aggressive rows (account/passport/dl)"
    );
    assert!(
        with_aggr.aggressive_locales.contains(&Arc::from("us:dl")),
        "us:dl is registered aggressive"
    );
    assert!(
        with_aggr
            .aggressive_locales
            .contains(&Arc::from("us:account")),
        "us:account is registered aggressive"
    );
    // A PRECISE US row is NOT in the aggressive set.
    assert!(
        !with_aggr.aggressive_locales.contains(&Arc::from("us:ssn")),
        "us:ssn (precise checksum) is NOT aggressive"
    );
}

#[test]
fn aggressive_precedence_is_deterministic() {
    // Same input → same primary, every run (the order stays total + deterministic
    // through the demotion: priority then label-ASC tie-break). Run the overlap case
    // repeatedly and assert the primary + recognizer list are stable.
    let e = us_locale_engine();
    let text = "Driver's licence 1234567893 on file";
    let first = e.candidates(text);
    for _ in 0..16 {
        let again = e.candidates(text);
        assert_eq!(again.len(), first.len(), "candidate count is stable");
        for (a, b) in again.iter().zip(first.iter()) {
            assert_eq!(
                a.recognizer(),
                b.recognizer(),
                "primary is stable across runs"
            );
            assert_eq!(
                a.recognizers(),
                b.recognizers(),
                "recognizer list is stable"
            );
            assert_eq!(a.start(), b.start());
            assert_eq!(a.end(), b.end());
        }
    }
}

#[test]
fn expanded_recognizers_in_audit_breakdown() {
    // The global recognizers appear in the deterministic breakdown under their
    // fixed labels; the NRIC — now an OPT-IN locale pack — appears under the
    // `locale:sg:nric` namespace, AND only when the SG locale is enabled.
    let e = sg_engine();
    let cands = e.candidates(
        "NRIC S1234567A card 4111 1111 1111 1111 iban GB82WEST12345698765432 \
             host 192.168.1.1 url https://x.io",
    );
    let breakdown = recognizer_breakdown(&cands);
    // The global recognizers are unchanged (bare labels).
    for needle in ["credit-card=1", "iban=1", "ip=1", "url=1"] {
        assert!(
            breakdown.contains(needle),
            "breakdown missing {needle:?}, got {breakdown:?}"
        );
    }
    // The NRIC is now jurisdiction-namespaced under `locale:`, NOT a bare `nric=`.
    assert!(
        breakdown.contains("locale:sg:nric=1"),
        "NRIC namespaced, got {breakdown:?}"
    );
    // No bare `nric=` bucket survives: every `nric=` occurrence is the tail of the
    // namespaced `locale:sg:nric=` form (split on the comma-space delimiter and
    // assert no entry STARTS with `nric=`).
    assert!(
        breakdown
            .split(", ")
            .all(|entry| !entry.starts_with("nric=")),
        "no bare nric= entry (NRIC is now locale-namespaced), got {breakdown:?}"
    );
}

// ---- PART 6b: OPT-IN locale packs (jurisdiction-specific recognizers) ----

#[test]
fn default_engine_does_not_flag_an_nric_without_a_locale() {
    // (a) NRIC is jurisdiction-specific, so it is OFF by default: neither the
    // thin `new` nor a bare `builder().build()` flags an NRIC. (A US-only firm
    // never wanted SG NRIC flagging in the first place.)
    let nric_text = "holder S1234567A on file";

    let bare_new = RedactionEngine::new(Vec::<String>::new());
    assert!(
        find_kind(&bare_new.candidates(nric_text), &sg_nric()).is_none(),
        "RedactionEngine::new must NOT flag an NRIC (no locale enabled)"
    );
    // ...and the NRIC text survives a redaction pass untouched by an NRIC rule.
    let (out, _n) = bare_new.redact_text(nric_text);
    assert!(
        out.contains("S1234567A"),
        "no locale -> NRIC left intact, got {out:?}"
    );

    let bare_builder = RedactionEngine::builder().build().unwrap();
    assert!(
        find_kind(&bare_builder.candidates(nric_text), &sg_nric()).is_none(),
        "a bare builder().build() must NOT flag an NRIC (default = no locales)"
    );
}

#[test]
fn enabling_singapore_locale_flags_an_nric() {
    // (b) Opting the SG pack in DOES flag (and strip) the NRIC — the only change
    // from the default engine is the one `.locales([Locale::Singapore])` call.
    let e = sg_engine();
    let cands = e.candidates("holder S1234567A on file");
    let c = find_kind(&cands, &sg_nric()).expect("SG locale flags the NRIC");
    assert_eq!(c.matched_value(), "S1234567A");
    let (out, n) = e.redact_text("NRIC S1234567A noted");
    assert!(
        !out.contains("S1234567A"),
        "SG locale -> NRIC stripped, got {out:?}"
    );
    assert!(n >= 1);
}

#[test]
fn locale_breakdown_namespaced_and_injective_vs_custom() {
    // (c) The breakdown renders a locale recognizer under `locale:<label>` and
    // stays INJECTIVE against a `custom:`-labelled rule whose label is the SAME
    // string ("sg:nric") — the two buckets read distinctly, never collapsing.
    let e = RedactionEngine::builder()
        .locales([Locale::Singapore])
        // A custom rule deliberately labelled identically to the locale recognizer.
        // (Colons are allowed in a custom label — not a breakdown delimiter.)
        .recognizers(vec![UserRecognizer::literal("sg:nric", "Acme")])
        .build()
        .unwrap();
    let cands = e.candidates("holder S1234567A at Acme");
    let breakdown = recognizer_breakdown(&cands);
    // Both present, distinctly namespaced (locale: sorts before custom:).
    assert_eq!(
        breakdown, "locale:sg:nric=1, custom:sg:nric=1",
        "locale and custom with the same label stay injective, got {breakdown:?}"
    );
}

#[test]
fn locale_candidates_share_the_one_arc_label() {
    // (d) Like FIX #14 for `Custom`: a locale recognizer matching many times
    // shares ONE `Arc<str>` label allocation across every candidate — per-match
    // attribution is a refcount bump, not a heap copy. Every candidate's label
    // is pointer-identical to the engine's compiled tag.
    let e = sg_engine();
    // The engine's compiled locale tag holds the canonical Arc<str>.
    let engine_label: &Arc<str> = e
        .patterns
        .iter()
        .find_map(|tp| match &tp.kind {
            Recognizer::Locale(a) => Some(a),
            _ => None,
        })
        .expect("the SG engine has a compiled locale recognizer");

    // Five NRICs -> five candidates, all sharing the one label allocation.
    let text = "S1234567A T0123456Z F7654321N G1112223X M5043212K";
    let cands = e.candidates(text);
    assert_eq!(cands.len(), 5, "five NRICs, got {}", cands.len());
    for c in &cands {
        match c.recognizer() {
            Recognizer::Locale(a) => assert!(
                Arc::ptr_eq(a, engine_label),
                "every locale match must SHARE the one label allocation"
            ),
            other => panic!("expected a Locale recognizer, got {other:?}"),
        }
    }
    assert_eq!(recognizer_breakdown(&cands), "locale:sg:nric=5");
}

#[test]
fn duplicate_locales_are_deduped_to_one_pack() {
    // Enabling the same locale twice must not double-count or double-compile: the
    // builder dedups the list, so an NRIC is still exactly one candidate.
    let e = RedactionEngine::builder()
        .locales([Locale::Singapore, Locale::Singapore])
        .build()
        .unwrap();
    let cands = e.candidates("holder S1234567A on file");
    let nrics: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.recognizer() == &sg_nric())
        .collect();
    assert_eq!(
        nrics.len(),
        1,
        "a duplicated locale must not double the candidate"
    );
    assert_eq!(recognizer_breakdown(&cands), "locale:sg:nric=1");
}

// ---- PART 6b: compliance PROFILE axis (PCI worked example) ----

#[test]
fn pci_profile_forces_credit_card_even_with_builtins_off() {
    // The PCI profile's required built-ins are OR-merged in, so the card (Luhn)
    // recognizer runs even though the caller explicitly disabled ALL built-ins.
    // That is the profile guaranteeing its deterministic coverage (a pure widen —
    // it never turns a recognizer OFF).
    let e = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .profiles([Profile::PciDssCardholder])
        .build()
        .unwrap();
    let cands = e.candidates("paid with 4111 1111 1111 1111 today");
    let c = find_kind(&cands, &Recognizer::CreditCard)
        .unwrap_or_else(|| panic!("PCI must run the card recognizer, got {cands:?}"));
    assert_eq!(c.matched_value(), "4111 1111 1111 1111");
    // The card attributes under its OWN built-in label (PCI reuses the global
    // recognizer, it does NOT relabel it as `profile:`).
    assert_eq!(recognizer_breakdown(&cands), "credit-card=1");
}

#[test]
fn pci_profile_surfaces_honest_review_gaps_to_the_caller() {
    // The "reasonable-efforts, never safe-to-send" posture as a reachable typed
    // contract: the engine surfaces the profile's human-review gaps so a UI can
    // render "covered the PAN; THESE still need a human".
    let e = RedactionEngine::builder()
        .profiles([Profile::PciDssCardholder])
        .build()
        .unwrap();
    assert_eq!(e.profiles(), &[Profile::PciDssCardholder]);
    let gaps = e.profile_review_gaps();
    assert!(!gaps.is_empty(), "PCI must surface review gaps");
    assert!(
        gaps.iter().any(|g| g.contains("cardholder name")),
        "cardholder name is a human-review gap, got {gaps:?}"
    );
    // A no-profile engine has no gaps (and no profiles) — unchanged default shape.
    let plain = RedactionEngine::new(Vec::<String>::new());
    assert!(plain.profiles().is_empty());
    assert!(plain.profile_review_gaps().is_empty());
}

#[test]
fn profile_breakdown_namespaced_and_injective() {
    // Prove the `profile:<label>` namespace renders + sorts BETWEEN locale: and
    // custom:, and stays injective against a locale/custom rule sharing the label.
    // (The PCI worked example has no bespoke rows, so this exercises the rendering
    // machinery directly with a synthetic profile recognizer — testing the
    // STRUCTURE, not fabricated content.)
    let profile = |name: &str| Recognizer::Profile(Arc::from(name));
    let locale = |name: &str| Recognizer::Locale(Arc::from(name));
    let custom = |name: &str| Recognizer::Custom(Arc::from(name));
    fn cand(rec: Recognizer) -> RedactionCandidate {
        RedactionCandidate {
            start: 0,
            end: 1,
            matched_value: "x".to_string(),
            recognizer: rec.clone(),
            recognizers: vec![rec],
            context: "x".to_string(),
            confidence: Confidence::Low,
        }
    }
    // Same bare label "x:y" under all three axes stays three distinct buckets,
    // ordered locale: < profile: < custom:.
    let set = vec![
        cand(custom("x:y")),
        cand(profile("x:y")),
        cand(locale("x:y")),
        cand(Recognizer::Email),
    ];
    assert_eq!(
        recognizer_breakdown(&set),
        "email=1, locale:x:y=1, profile:x:y=1, custom:x:y=1",
    );
}

#[test]
fn duplicate_profiles_are_deduped() {
    // Enabling the same profile twice must not double the selection: the builder
    // dedups, so `profiles()` reports exactly one.
    let e = RedactionEngine::builder()
        .profiles([Profile::PciDssCardholder, Profile::PciDssCardholder])
        .build()
        .unwrap();
    assert_eq!(e.profiles(), &[Profile::PciDssCardholder]);
}

#[test]
fn profile_selection_is_recorded_in_the_audit_chain() {
    // A profile-enabled redaction records the profile SELECTION (names + gap
    // CATEGORIES, both static config strings — never a matched value) in the audit
    // chain, so the trail shows WHICH compliance regime a redaction targeted.
    let e = RedactionEngine::builder()
        .profiles([Profile::PciDssCardholder])
        .build()
        .unwrap();
    let mut core = seeded_core(redaction_grants());
    e.redact_matter(&mut core).unwrap();

    // The profile note lands in the entry `detail` (as `note: <event>`).
    let found = core
        .audit()
        .entries()
        .iter()
        .any(|en| en.detail.contains("redaction profiles: pci-dss-cardholder"));
    assert!(found, "the profile selection must be in the audit chain");
    // The selection note also surfaces the honest review-gap CATEGORIES (config
    // strings only — never a matched value).
    let with_gaps = core
        .audit()
        .entries()
        .iter()
        .any(|en| en.detail.contains("human-review gaps: cardholder name"));
    assert!(
        with_gaps,
        "the note must carry the honest review-gap categories"
    );
    // The chain still verifies after the extra note.
    assert!(core.audit().verify_chain(), "keyed hash chain verifies");
}

#[test]
fn no_profile_engine_records_no_profile_note() {
    // ZERO behavior change for the no-profile case: a plain engine emits NO
    // profile-selection note, so its audit chain is byte-identical to before this
    // axis existed.
    let e = RedactionEngine::new(Vec::<String>::new());
    let mut core = seeded_core(redaction_grants());
    e.redact_matter(&mut core).unwrap();
    let any_profile_note = core
        .audit()
        .entries()
        .iter()
        .any(|en| en.detail.contains("redaction profiles:"));
    assert!(
        !any_profile_note,
        "a no-profile engine must emit no profile note"
    );
}

// ---- PART 7: scan -> review -> apply workflow ----

#[test]
fn selection_accept_reject_semantics() {
    let mut s = Selection::none();
    assert!(s.is_empty());
    s.accept(1, DataClass::Document, 5, 10);
    assert!(s.is_accepted(1, DataClass::Document, 5, 10));
    assert_eq!(s.len(), 1);
    s.accept(1, DataClass::Document, 5, 10); // idempotent
    assert_eq!(s.len(), 1);
    s.reject(1, DataClass::Document, 5, 10);
    assert!(!s.is_accepted(1, DataClass::Document, 5, 10));
    assert!(s.is_empty());
    // The class is part of the key — same offsets under a different class differ.
    s.accept(1, DataClass::Document, 0, 4);
    assert!(!s.is_accepted(1, DataClass::Party, 0, 4));
}

// ===========================================================================
// Two-tier review routing — ReviewTier / ReviewPolicy / Selection::quick_confirm /
// ReviewSummary. The LOAD-BEARING consumer of the Confidence tier (it now DRIVES the
// selection, not just annotates a candidate).
// ===========================================================================

/// Build a bare candidate at `start..end` with a chosen confidence tier. The
/// recognizer/value/context are immaterial to the routing (it keys on `confidence`
/// + span), so they get deterministic placeholders.
fn tiered_candidate(start: usize, end: usize, confidence: Confidence) -> RedactionCandidate {
    RedactionCandidate {
        start,
        end,
        matched_value: "x".repeat(end - start),
        recognizer: Recognizer::Id,
        recognizers: vec![Recognizer::Id],
        context: String::new(),
        confidence,
    }
}

/// Assemble a [`ScanReport`] from `(doc_id, class, [candidate])` rows.
fn scan_report(docs: Vec<(u64, DataClass, Vec<RedactionCandidate>)>) -> ScanReport {
    ScanReport {
        docs: docs
            .into_iter()
            .map(|(doc_id, class, candidates)| DocScan {
                doc_id,
                class,
                candidates,
            })
            .collect(),
    }
}

#[test]
fn review_policy_default_floor_is_high() {
    let p = ReviewPolicy::default();
    assert_eq!(p.quick_confirm_floor(), Confidence::High);
    assert_eq!(p.tier(Confidence::High), ReviewTier::QuickConfirm);
    assert_eq!(p.tier(Confidence::Medium), ReviewTier::CarefulReview);
    assert_eq!(p.tier(Confidence::Low), ReviewTier::CarefulReview);
    assert_eq!(ReviewPolicy::new(), p, "new() == default()");
}

#[test]
fn review_policy_custom_floor_routes_medium_to_quick_confirm() {
    let p = ReviewPolicy::with_quick_confirm_floor(Confidence::Medium);
    assert_eq!(p.tier(Confidence::High), ReviewTier::QuickConfirm);
    assert_eq!(p.tier(Confidence::Medium), ReviewTier::QuickConfirm);
    assert_eq!(p.tier(Confidence::Low), ReviewTier::CarefulReview);
    // A Low floor makes EVERY tier Tier-1.
    let all_t1 = ReviewPolicy::with_quick_confirm_floor(Confidence::Low);
    for c in [Confidence::High, Confidence::Medium, Confidence::Low] {
        assert_eq!(all_t1.tier(c), ReviewTier::QuickConfirm);
    }
}

#[test]
fn selection_quick_confirm_accepts_only_tier1_spans() {
    // doc 1: High (accepted), Medium + Low (not). doc 2: High (accepted).
    let scan = scan_report(vec![
        (
            1,
            DataClass::Document,
            vec![
                tiered_candidate(0, 4, Confidence::High),
                tiered_candidate(10, 14, Confidence::Medium),
                tiered_candidate(20, 24, Confidence::Low),
            ],
        ),
        (
            2,
            DataClass::Party,
            vec![tiered_candidate(0, 5, Confidence::High)],
        ),
    ]);
    let sel = Selection::quick_confirm(&scan, &ReviewPolicy::default());
    assert!(
        sel.is_accepted(1, DataClass::Document, 0, 4),
        "doc1 High accepted"
    );
    assert!(
        !sel.is_accepted(1, DataClass::Document, 10, 14),
        "doc1 Medium not accepted"
    );
    assert!(
        !sel.is_accepted(1, DataClass::Document, 20, 24),
        "doc1 Low not accepted"
    );
    assert!(
        sel.is_accepted(2, DataClass::Party, 0, 5),
        "doc2 High accepted"
    );
    assert_eq!(sel.len(), 2, "exactly the two High spans");
}

#[test]
fn quick_confirm_floor_low_equals_select_all() {
    let scan = scan_report(vec![(
        1,
        DataClass::Document,
        vec![
            tiered_candidate(0, 4, Confidence::High),
            tiered_candidate(10, 14, Confidence::Medium),
            tiered_candidate(20, 24, Confidence::Low),
        ],
    )]);
    let qc = Selection::quick_confirm(
        &scan,
        &ReviewPolicy::with_quick_confirm_floor(Confidence::Low),
    );
    assert_eq!(
        qc,
        Selection::all(&scan),
        "a Low floor coincides with accept-all"
    );
}

#[test]
fn review_summary_counts_match_quick_confirm_selection() {
    let scan = scan_report(vec![
        (
            1,
            DataClass::Document,
            vec![
                tiered_candidate(0, 4, Confidence::High),
                tiered_candidate(10, 14, Confidence::High),
                tiered_candidate(20, 24, Confidence::Medium),
                tiered_candidate(30, 34, Confidence::Low),
            ],
        ),
        (
            2,
            DataClass::Party,
            vec![tiered_candidate(0, 5, Confidence::Medium)],
        ),
    ]);
    let policy = ReviewPolicy::default();
    let summary = ReviewSummary::of(&scan, &policy);
    assert_eq!(summary.floor(), Confidence::High);
    assert_eq!(summary.quick_confirm(), 2);
    assert_eq!(summary.careful_review(), 3);
    assert_eq!(summary.total(), scan.total_candidates());
    // Per-document split.
    let d1 = summary.docs().iter().find(|d| d.doc_id() == 1).unwrap();
    assert_eq!(
        (d1.quick_confirm(), d1.careful_review(), d1.total()),
        (2, 2, 4)
    );
    let d2 = summary.docs().iter().find(|d| d.doc_id() == 2).unwrap();
    assert_eq!(
        (d2.quick_confirm(), d2.careful_review(), d2.total()),
        (0, 1, 1)
    );
    // The load-bearing invariant: the summary's Tier-1 count is EXACTLY the spans
    // quick_confirm accepts (one merged span = one accepted coordinate).
    assert_eq!(
        summary.quick_confirm(),
        Selection::quick_confirm(&scan, &policy).len()
    );
}

#[test]
fn review_summary_empty_scan_is_all_zero() {
    let summary = ReviewSummary::of(&ScanReport::default(), &ReviewPolicy::default());
    assert_eq!(
        (
            summary.quick_confirm(),
            summary.careful_review(),
            summary.total()
        ),
        (0, 0, 0)
    );
    assert!(summary.docs().is_empty());
}

#[test]
fn tier_routing_is_load_bearing_through_the_real_core() {
    // End-to-end proof the Confidence tier now DRIVES what gets redacted: a High
    // candidate (a checksum-valid card) is quick-confirmed + REMOVED, while a sub-High
    // candidate (a bare email => Medium, no class keyword in-window) routes to careful
    // review and SURVIVES the quick-confirm apply (the reviewer must opt it in).
    let mut store = InMemoryMatterStore::new();
    store.insert(
        1,
        DataClass::Document,
        "Ping jane.roe@acme.example soon; pay 4111 1111 1111 1111 now.",
    );
    let mut core = core_with(redaction_grants(), store);

    let scan = engine().scan_matter(&mut core).unwrap();
    let doc = scan.docs().iter().find(|d| d.doc_id() == 1).unwrap();
    let card = doc
        .candidates()
        .iter()
        .find(|c| matches!(c.recognizer(), Recognizer::CreditCard))
        .expect("the canonical PAN is Luhn-valid and detected");
    assert_eq!(card.confidence(), Confidence::High, "checksum card is High");
    let email = doc
        .candidates()
        .iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Email))
        .expect("the email is detected");
    assert!(
        email.confidence() < Confidence::High,
        "a bare email (no class keyword) is sub-High, got {:?}",
        email.confidence(),
    );

    let sel = Selection::quick_confirm(&scan, &ReviewPolicy::default());
    engine().apply_selection(&mut core, &sel).unwrap();

    let stored = core.matter_read_text(1, DataClass::Document).unwrap();
    assert!(
        !stored.contains("4111 1111 1111 1111"),
        "the High card was quick-confirmed and removed: {stored:?}",
    );
    assert!(
        stored.contains("jane.roe@acme.example"),
        "the sub-High email routed to careful review SURVIVES quick-confirm: {stored:?}",
    );
}

#[test]
fn redact_with_selection_pure_honors_accepted_and_reports_stale() {
    // The Core-free selection apply (for a CLI / paste-in host): only accepted spans
    // are redacted; an accepted coordinate not present in the text is `stale`, never
    // written at a wrong offset.
    let e = RedactionEngine::new(Vec::<String>::new()); // builtins all-on
    let text = "Email a@b.co and card 4111 1111 1111 1111 today.";
    let email = e
        .candidates(text)
        .into_iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Email))
        .expect("email detected");
    let accepted: std::collections::HashSet<(usize, usize)> =
        [(email.start(), email.end())].into_iter().collect();
    let (out, applied, stale) = e.redact_with_selection(text, &accepted);
    assert_eq!((applied, stale), (1, 0));
    assert!(!out.contains("a@b.co"), "accepted email removed: {out:?}");
    assert!(
        out.contains("4111 1111 1111 1111"),
        "unaccepted card survives: {out:?}"
    );

    // A coordinate not present in the text is stale-only: nothing is written.
    let bogus: std::collections::HashSet<(usize, usize)> = [(9999, 10000)].into_iter().collect();
    let (out2, applied2, stale2) = e.redact_with_selection(text, &bogus);
    assert_eq!((applied2, stale2), (0, 1));
    assert_eq!(out2, text, "a stale-only selection redacts nothing");
}

#[test]
fn redact_with_selection_accept_all_equals_redact_detail() {
    // Accepting every detected span must reproduce the one-shot full redaction.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Email a@b.co; card 4111 1111 1111 1111; IBAN GB82 WEST 1234 5698 7654 32.";
    let all: std::collections::HashSet<(usize, usize)> = e
        .candidates(text)
        .iter()
        .map(|c| (c.start(), c.end()))
        .collect();
    let (sel_out, applied, stale) = e.redact_with_selection(text, &all);
    let (full_out, _) = e.redact_detail(text);
    assert_eq!(sel_out, full_out, "accept-all selection == full redaction");
    assert_eq!(stale, 0);
    assert_eq!(applied, all.len());
}

// ---- AI-safe LABELS (pseudonymization) — the alias map + legend ----

/// Build a term-engine + accept EVERY detected span, returning `(labeled, legend)` from
/// the labels path. The common setup for the labels tests.
fn label_all(engine: &RedactionEngine, text: &str) -> (String, Legend) {
    let all: std::collections::HashSet<(usize, usize)> = engine
        .candidates(text)
        .iter()
        .map(|c| (c.start(), c.end()))
        .collect();
    let (out, legend, _applied, _stale) = engine.redact_with_selection_labeled(text, &all);
    (out, legend)
}

#[test]
fn labels_entity_letters_and_typed_routing() {
    // Two distinct NAMED parties (terms) -> [A],[B]; an email (typed, single distinct)
    // -> the UNNUMBERED [email]. Entities get letters, typed values get [type].
    let engine = RedactionEngine::builder()
        .terms(vec!["Jefferson Tan".into(), "Acme Holdings".into()])
        .build()
        .unwrap();
    let text = "Jefferson Tan of Acme Holdings, reach jane@acme.example; \
                    Jefferson Tan signed.";
    let (out, legend) = label_all(&engine, text);
    // First-seen entity letters: Jefferson Tan = [A], Acme Holdings = [B].
    assert!(
        out.contains("[A] of [B]"),
        "entities labeled by first-seen letter: {out:?}"
    );
    // The same value reuses its letter on the second occurrence.
    assert_eq!(
        out.matches("[A]").count(),
        2,
        "[A] reused for both Jefferson Tan: {out:?}"
    );
    // The single-distinct email is UNNUMBERED.
    assert!(
        out.contains("[email]"),
        "single distinct email is unnumbered: {out:?}"
    );
    assert!(!out.contains("jane@acme.example"), "email removed: {out:?}");
    // Legend: entities first (by letter), then the email; counts correct.
    let a = legend
        .iter()
        .find(|e| e.label == "[A]")
        .expect("[A] in legend");
    assert_eq!(a.value, "Jefferson Tan");
    assert_eq!(a.count, 2);
    let b = legend
        .iter()
        .find(|e| e.label == "[B]")
        .expect("[B] in legend");
    assert_eq!(b.value, "Acme Holdings");
    let em = legend
        .iter()
        .find(|e| e.label == "[email]")
        .expect("[email] in legend");
    assert_eq!(em.value, "jane@acme.example");
    assert_eq!(em.count, 1);
    // Deterministic order: entity rows precede typed rows.
    let labels: Vec<&str> = legend.iter().map(|e| e.label.as_str()).collect();
    assert_eq!(
        labels,
        vec!["[A]", "[B]", "[email]"],
        "legend order: {labels:?}"
    );
}

#[test]
fn labels_numbering_rule_unnumbered_then_numbered() {
    // The numbering RULE: exactly 1 distinct value of a type -> UNNUMBERED; >= 2 ->
    // numbered (1-based, first-seen). Two distinct emails -> [email 1],[email 2].
    let engine = RedactionEngine::new(Vec::<String>::new());
    let text = "From a@x.co to b@y.co, cc a@x.co again.";
    let (out, legend) = label_all(&engine, text);
    assert!(
        out.contains("[email 1]"),
        "first distinct email numbered: {out:?}"
    );
    assert!(
        out.contains("[email 2]"),
        "second distinct email numbered: {out:?}"
    );
    assert!(
        !out.contains("[email]"),
        "no bare [email] once a type is numbered: {out:?}"
    );
    // a@x.co (first-seen) is slot 1 and reused; b@y.co is slot 2.
    assert_eq!(
        out.matches("[email 1]").count(),
        2,
        "[email 1] reused: {out:?}"
    );
    assert_eq!(
        out.matches("[email 2]").count(),
        1,
        "[email 2] once: {out:?}"
    );
    let e1 = legend.iter().find(|e| e.label == "[email 1]").unwrap();
    assert_eq!((e1.value.as_str(), e1.count), ("a@x.co", 2));
    let e2 = legend.iter().find(|e| e.label == "[email 2]").unwrap();
    assert_eq!((e2.value.as_str(), e2.count), ("b@y.co", 1));
}

#[test]
fn labels_consistency_and_distinctness() {
    // CONSISTENCY: same normalized value -> same label everywhere (incl. across a
    // case/whitespace variant). DISTINCTNESS: different values -> different labels.
    let engine = RedactionEngine::builder()
        .terms(vec!["Jefferson Tan".into(), "Mary Lee".into()])
        .build()
        .unwrap();
    // `JEFFERSON TAN` (all-caps) is detected by the case-insensitive term recognizer and
    // normalizes to the SAME key as `Jefferson Tan`, so both occurrences reuse [A].
    // (NOTE: detection itself is case-insensitive but NOT whitespace-elastic in the
    //  plain-text path, so we vary CASE here, not internal spacing — the labeling key
    //  folds both, but only a value the engine actually DETECTS reaches the legend.)
    let text = "Jefferson Tan met Mary Lee; later JEFFERSON TAN paid Mary Lee.";
    let (out, _legend) = label_all(&engine, text);
    // Consistency: both spellings of Jefferson Tan share [A]; both Mary Lee share [B].
    assert_eq!(
        out.matches("[A]").count(),
        2,
        "same value -> same label: {out:?}"
    );
    assert_eq!(
        out.matches("[B]").count(),
        2,
        "same value -> same label: {out:?}"
    );
    // Distinctness: the two distinct parties never collide on a label.
    assert!(
        out.contains("[A] met [B]"),
        "distinct values -> distinct labels: {out:?}"
    );
    assert!(
        !out.contains("Jefferson"),
        "no entity surface form survives: {out:?}"
    );
    assert!(
        !out.contains("Mary"),
        "no entity surface form survives: {out:?}"
    );
}

#[test]
fn labels_recall_parity_same_spans_removed_as_marker_mode() {
    // RECALL PARITY: the labeled apply removes EXACTLY the spans the marker apply does,
    // for the same accept-set. We prove it by reconstructing the removed-span set from
    // BOTH modes via `applied` (identical) AND by checking no source value survives
    // either output for the SAME accept-set.
    let engine = RedactionEngine::builder()
        .terms(vec!["Jefferson Tan".into()])
        .build()
        .unwrap();
    let text = "Jefferson Tan, jane@acme.example, card 4111 1111 1111 1111.";
    let all: std::collections::HashSet<(usize, usize)> = engine
        .candidates(text)
        .iter()
        .map(|c| (c.start(), c.end()))
        .collect();
    let (marker_out, m_applied, m_stale) = engine.redact_with_selection(text, &all);
    let (label_out, _legend, l_applied, l_stale) = engine.redact_with_selection_labeled(text, &all);
    // The accept/stale accounting is byte-identical between modes (same span set).
    assert_eq!(
        (m_applied, m_stale),
        (l_applied, l_stale),
        "applied/stale parity"
    );
    // The SAME identifiers are gone from BOTH outputs; only the token differs.
    for needle in ["Jefferson Tan", "jane@acme.example", "4111 1111 1111 1111"] {
        assert!(
            !marker_out.contains(needle),
            "marker removed {needle}: {marker_out:?}"
        );
        assert!(
            !label_out.contains(needle),
            "labels removed {needle}: {label_out:?}"
        );
    }
    // And the marker output is what the original marker path produces (recall unchanged).
    assert!(
        marker_out.contains(REDACTION_MARKER),
        "marker mode writes the marker"
    );
    assert!(
        !label_out.contains(REDACTION_MARKER),
        "labels mode writes NO marker"
    );

    // STRONGER parity: the set of accepted spans that were PRESENT (applied) is the
    // same in both modes — i.e. neither mode removed a span the other did not. We
    // recover it by toggling each span on individually and checking `applied` agrees.
    for c in engine.candidates(text) {
        let one: std::collections::HashSet<(usize, usize)> =
            [(c.start(), c.end())].into_iter().collect();
        let (_o1, a1, s1) = engine.redact_with_selection(text, &one);
        let (_o2, _l, a2, s2) = engine.redact_with_selection_labeled(text, &one);
        assert_eq!(
            (a1, s1),
            (a2, s2),
            "per-span applied/stale parity for {c:?}"
        );
    }
}

#[test]
fn labels_determinism_byte_identical_output_and_legend() {
    // DETERMINISM: same input + same terms -> byte-identical labeled output + identical
    // legend (no clock / RNG).
    let mk = || {
        RedactionEngine::builder()
            .terms(vec!["Jefferson Tan".into(), "Acme".into()])
            .build()
            .unwrap()
    };
    let text = "Jefferson Tan at Acme; a@x.co, b@y.co; Jefferson Tan again.";
    let (out1, legend1) = label_all(&mk(), text);
    let (out2, legend2) = label_all(&mk(), text);
    assert_eq!(out1, out2, "labeled output is byte-identical");
    assert_eq!(legend1, legend2, "legend is identical");
}

#[test]
fn labels_post_z_continuation_rule() {
    // The documented post-[Z] rule: 0->A, 25->Z, 26->AA, 27->AB, 701->ZZ, 702->AAA.
    assert_eq!(entity_letters(0), "A");
    assert_eq!(entity_letters(25), "Z");
    assert_eq!(entity_letters(26), "AA");
    assert_eq!(entity_letters(27), "AB");
    assert_eq!(entity_letters(51), "AZ");
    assert_eq!(entity_letters(52), "BA");
    assert_eq!(entity_letters(701), "ZZ");
    assert_eq!(entity_letters(702), "AAA");
    // And end-to-end: 27 distinct terms produce a 27th label of [AA].
    let terms: Vec<String> = (0..27).map(|i| format!("Party{i:02}")).collect();
    let engine = RedactionEngine::builder()
        .terms(terms.clone())
        .build()
        .unwrap();
    let text = terms.join(" ");
    let (_out, legend) = label_all(&engine, &text);
    let labels: Vec<&str> = legend.iter().map(|e| e.label.as_str()).collect();
    assert_eq!(labels[0], "[A]");
    assert_eq!(labels[25], "[Z]");
    assert_eq!(labels[26], "[AA]", "27th distinct entity continues to [AA]");
}

#[test]
fn labels_redacted_mode_is_unchanged_noop() {
    // [REDACTED]-MODE NO-OP: the marker path is untouched by this feature — accepting
    // all spans still yields the marker output (byte-identical to the historical path).
    let engine = RedactionEngine::new(Vec::<String>::new());
    let text = "Email a@b.co; card 4111 1111 1111 1111.";
    let all: std::collections::HashSet<(usize, usize)> = engine
        .candidates(text)
        .iter()
        .map(|c| (c.start(), c.end()))
        .collect();
    let (marker_out, _, _) = engine.redact_with_selection(text, &all);
    let (full_out, _) = engine.redact_detail(text);
    assert_eq!(
        marker_out, full_out,
        "marker selection == full marker redaction"
    );
    assert!(marker_out.contains(REDACTION_MARKER));
}

#[test]
fn labels_typed_human_names_for_common_recognizers() {
    // The signed-off human type names for the common recognizers (single distinct each
    // -> unnumbered). Card, IBAN, IP, URL, phone all carry their readable type.
    let engine = RedactionEngine::new(Vec::<String>::new());
    let text = "card 4111 1111 1111 1111; IBAN GB82 WEST 1234 5698 7654 32; \
                    host 10.0.0.1; site https://acme.example/x; tel 555 123 4567.";
    let (out, _legend) = label_all(&engine, text);
    for ph in [
        "[credit card]",
        "[IBAN]",
        "[IP address]",
        "[web address]",
        "[phone]",
    ] {
        assert!(out.contains(ph), "expected {ph} in {out:?}");
    }
}

#[test]
fn labels_normalization_trims_and_collapses_whitespace() {
    // The normalization key trims + collapses internal whitespace, so card variants
    // with differing spacing fold onto one label.
    assert_eq!(normalize_label_key("  Jefferson   Tan  "), "jefferson tan");
    assert_eq!(
        normalize_label_key("4111  1111\t1111 1111"),
        "4111 1111 1111 1111"
    );
    assert_eq!(
        normalize_label_key("JANE@ACME.EXAMPLE"),
        "jane@acme.example"
    );
    // Multibyte + length-changing case fold (İ -> i̇) must not panic or mis-key.
    assert_eq!(
        normalize_label_key("Mr İlhan  Çelik"),
        "mr i\u{307}lhan çelik"
    );
}

#[test]
fn labels_multibyte_text_splices_on_char_boundaries() {
    // Char-boundary safety through the labels SPLICE on multibyte text: an accented /
    // İ-containing titled name is removed (reused letter), the email is unnumbered, and
    // nothing panics. Locks in that the splice indexes only `merged_spans` boundaries.
    let engine = RedactionEngine::new(Vec::<String>::new());
    let text = "Mr İlhan Çelik met Dr José García; mail a@b.co. Mr İlhan Çelik left.";
    let (out, legend) = label_all(&engine, text);
    assert!(!out.contains("İlhan"), "multibyte name removed: {out:?}");
    assert!(!out.contains("García"), "accented name removed: {out:?}");
    assert!(
        out.contains("[A]") && out.contains("[B]"),
        "two entities lettered: {out:?}"
    );
    assert!(out.contains("[email]"), "single email unnumbered: {out:?}");
    // The İ-name reuses [A] on both occurrences (consistency across multibyte).
    let a = legend.iter().find(|e| e.label == "[A]").unwrap();
    assert_eq!(a.count, 2, "multibyte name reused, got {legend:?}");
}

#[test]
fn labels_custom_replacement_ignored_entity_letter_used() {
    // DOC-PINNED behavior: a firm UserRecognizer with a configured `replacement` is
    // routed to an ENTITY LETTER in labels mode (its replacement string is ignored —
    // the marker path still honors it). Recall is unaffected: the span is still removed.
    let engine = RedactionEngine::builder()
        .recognizers(vec![
            UserRecognizer::literal("party", "Acme").with_replacement("[PARTY]")
        ])
        .build()
        .unwrap();
    let text = "Acme signed; Acme paid.";
    let all: std::collections::HashSet<(usize, usize)> = engine
        .candidates(text)
        .iter()
        .map(|c| (c.start(), c.end()))
        .collect();
    // Marker path honors the custom replacement.
    let (marker_out, _, _) = engine.redact_with_selection(text, &all);
    assert!(
        marker_out.contains("[PARTY]"),
        "marker mode honors replacement: {marker_out:?}"
    );
    // Labels path uses the entity letter, NOT the custom replacement.
    let (label_out, legend, _, _) = engine.redact_with_selection_labeled(text, &all);
    assert!(
        label_out.contains("[A]"),
        "labels mode uses a letter: {label_out:?}"
    );
    assert!(
        !label_out.contains("[PARTY]"),
        "custom replacement ignored: {label_out:?}"
    );
    assert!(
        !label_out.contains("Acme"),
        "value still removed (recall preserved)"
    );
    assert_eq!(legend[0].value, "Acme");
    assert_eq!(legend[0].count, 2);
}

#[test]
fn quick_confirm_invariant_holds_with_duplicate_classes_in_config() {
    // Regression: a class passed TWICE in the engine config must be scanned ONCE
    // (deduped in `build`), so a duplicate `DocScan` can't double-count in
    // `ReviewSummary` while the `Selection` (keyed by `SpanKey`) collapses to one —
    // which would break the documented count invariant.
    let engine = RedactionEngine::builder()
        .classes(vec![DataClass::Document, DataClass::Document])
        .builtins(BuiltinRecognizers::all())
        .build()
        .unwrap();
    let mut store = InMemoryMatterStore::new();
    store.insert(
        1,
        DataClass::Document,
        "Email: a@b.co; card 4111 1111 1111 1111.",
    );
    let mut core = core_with(
        vec![
            Capability::MatterRead(DataClass::Document),
            Capability::DocumentTransform,
        ],
        store,
    );
    let scan = engine.scan_matter(&mut core).unwrap();
    assert_eq!(
        scan.docs_scanned(),
        1,
        "a duplicate class is scanned once, not twice"
    );
    let policy = ReviewPolicy::default();
    let summary = ReviewSummary::of(&scan, &policy);
    assert_eq!(
        summary.quick_confirm(),
        Selection::quick_confirm(&scan, &policy).len(),
        "the count invariant holds even with a duplicate class in the config",
    );
    assert_eq!(
        summary.total(),
        scan.total_candidates(),
        "no candidate double-counted"
    );
}

#[test]
fn scan_writes_nothing_and_needs_no_transform_grant() {
    // A scan needs ONLY matter.read — NO document.transform — so a review pass
    // cannot mutate a document. Grant only the reads.
    let mut core = seeded_core(vec![
        Capability::MatterRead(DataClass::Document),
        Capability::MatterRead(DataClass::Party),
    ]);
    let before = core.matter_read_text(1, DataClass::Document).unwrap();
    let scan = engine().scan_matter(&mut core).unwrap();
    assert!(scan.total_candidates() >= 4, "found the seeded identifiers");
    assert_eq!(scan.docs_scanned(), 2, "both seeded docs scanned");

    // The store is UNCHANGED: a scan writes nothing.
    let after = core.matter_read_text(1, DataClass::Document).unwrap();
    assert_eq!(before, after, "scan must not modify the document");
    assert!(
        !after.contains(REDACTION_MARKER),
        "no marker written by a scan"
    );

    // A distinct SCAN note (not an apply/redact note) was audited.
    let notes: Vec<&str> = core
        .audit()
        .entries()
        .iter()
        .filter(|e| e.capability == Capability::AuditNote)
        .map(|e| e.detail.as_str())
        .collect();
    assert!(
        notes
            .iter()
            .any(|d| d.contains("redaction scan:") && d.contains("candidate(s)")),
        "a scan note was written, notes = {notes:?}"
    );
}

#[test]
fn apply_refused_without_transform_grant() {
    // Scanning works on reads alone, but applying needs document.transform.
    let mut core = seeded_core(vec![
        Capability::MatterRead(DataClass::Document),
        Capability::MatterRead(DataClass::Party),
    ]);
    let scan = engine().scan_matter(&mut core).unwrap();
    let sel = Selection::all(&scan);
    let err = engine().apply_selection(&mut core, &sel).unwrap_err();
    assert!(
        matches!(err, CoreError::Denied(Capability::DocumentTransform)),
        "apply needs document.transform, got {err:?}"
    );
    // And nothing was written despite the refusal (fail-closed).
    let stored = core.matter_read_text(1, DataClass::Document).unwrap();
    assert!(
        stored.contains("Project Condor"),
        "no strip on a denied apply, got {stored:?}"
    );
}

#[test]
fn scan_then_apply_all_equals_redact_matter() {
    // The workflow's accept-all path must produce a byte-identical store to the
    // one-shot redact_matter — the same span set, just gated through review.
    let mut core_a = seeded_core(redaction_grants());
    engine().redact_matter(&mut core_a).unwrap();
    let a1 = core_a.matter_read_text(1, DataClass::Document).unwrap();
    let a2 = core_a.matter_read_text(2, DataClass::Party).unwrap();

    let mut core_b = seeded_core(redaction_grants());
    let scan = engine().scan_matter(&mut core_b).unwrap();
    let sel = Selection::all(&scan);
    let apply = engine().apply_selection(&mut core_b, &sel).unwrap();
    let b1 = core_b.matter_read_text(1, DataClass::Document).unwrap();
    let b2 = core_b.matter_read_text(2, DataClass::Party).unwrap();

    assert_eq!(
        a1, b1,
        "doc1 identical via redact_matter and scan+apply-all"
    );
    assert_eq!(a2, b2, "doc2 identical via both paths");
    assert_eq!(
        apply.total_applied(),
        scan.total_candidates(),
        "accept-all applies every candidate"
    );
    assert_eq!(
        apply.total_stale(),
        0,
        "nothing stale on an immediate apply"
    );
}

#[test]
fn rejecting_a_span_leaves_that_identifier_intact() {
    // The reviewer's reject is honored: a rejected span survives; accepted
    // spans are still removed. This is the load-bearing human-judgment path.
    let mut core = seeded_core(redaction_grants());
    let scan = engine().scan_matter(&mut core).unwrap();
    let doc1 = scan.docs().iter().find(|d| d.doc_id() == 1).unwrap();
    let email = doc1
        .candidates()
        .iter()
        .find(|c| c.recognizer() == &Recognizer::Email)
        .expect("doc1 has an email candidate");

    let mut sel = Selection::all(&scan);
    sel.reject(1, DataClass::Document, email.start(), email.end());
    engine().apply_selection(&mut core, &sel).unwrap();

    let stored = core.matter_read_text(1, DataClass::Document).unwrap();
    assert!(
        stored.contains("jane.roe@acme.example"),
        "a REJECTED span must survive the apply, got {stored:?}"
    );
    assert!(
        !stored.contains("Project Condor"),
        "an ACCEPTED span must still be removed, got {stored:?}"
    );
}

#[test]
fn stale_span_is_skipped_not_misapplied() {
    // A selection holds COORDINATES. If the document changed since the scan, an
    // accepted span at a now-wrong offset must be reported `stale` and SKIPPED —
    // never written at the stale offset (which could redact the wrong text).
    let mut core = seeded_core(redaction_grants());
    let scan = engine().scan_matter(&mut core).unwrap();
    let sel = Selection::all(&scan);

    // Mutate the docs out from under the selection (redact everything now), so
    // the scan-time offsets no longer hold any identifier.
    engine().redact_matter(&mut core).unwrap();
    let mutated1 = core.matter_read_text(1, DataClass::Document).unwrap();

    let apply = engine().apply_selection(&mut core, &sel).unwrap();
    assert_eq!(
        apply.total_applied(),
        0,
        "no live span matched the stale selection"
    );
    assert!(apply.total_stale() > 0, "the old spans are reported stale");
    // Byte-identical to the post-mutation state — apply wrote nothing (no
    // corruption at the stale offsets).
    assert_eq!(
        core.matter_read_text(1, DataClass::Document).unwrap(),
        mutated1,
        "a stale apply must not change the document"
    );
}

#[test]
fn apply_empty_selection_writes_nothing() {
    let mut core = seeded_core(redaction_grants());
    let before = core.matter_read_text(1, DataClass::Document).unwrap();
    let apply = engine()
        .apply_selection(&mut core, &Selection::none())
        .unwrap();
    assert_eq!(apply.total_applied(), 0);
    assert!(
        apply.docs().is_empty(),
        "no docs touched by an empty selection"
    );
    assert_eq!(
        core.matter_read_text(1, DataClass::Document).unwrap(),
        before
    );
}

#[test]
fn workflow_notes_carry_no_cleartext() {
    // CONFIDENTIALITY SPLIT holds across the workflow: neither the scan note nor
    // the apply note ever contains a cleartext matched_value.
    let mut core = seeded_core(redaction_grants());
    let scan = engine().scan_matter(&mut core).unwrap();
    let cleartext: Vec<String> = scan
        .docs()
        .iter()
        .flat_map(|d| d.candidates().iter().map(|c| c.matched_value().to_string()))
        .collect();
    assert!(!cleartext.is_empty(), "the scan found identifiers");

    let sel = Selection::all(&scan);
    engine().apply_selection(&mut core, &sel).unwrap();

    for e in core
        .audit()
        .entries()
        .iter()
        .filter(|e| e.capability == Capability::AuditNote)
    {
        for v in &cleartext {
            assert!(
                !e.detail.contains(v.as_str()),
                "a workflow note leaked cleartext {v:?}: {}",
                e.detail
            );
        }
    }
}

// ===============================================================
// PDF (blob) workflow wired through Core — scan / redact_matter_pdf
// ===============================================================

/// Build a minimal valid one-page PDF whose single content stream shows
/// `body_text` via a `Tj` operator. Mirrors the synthetic builder in
/// `pdf.rs`'s own tests (that one is `cfg(test)`-private to that module). The
/// font resource etc. keep the PDF well-formed so `redact_pdf` can parse +
/// re-serialise it.
fn build_blob_pdf(body_text: &str) -> Vec<u8> {
    use lopdf::content::{Content, Operation};
    use lopdf::{dictionary, Dictionary, Document, Object, Stream, StringFormat};

    let mut doc = Document::with_version("1.5");
    let ops = vec![
        Operation::new("BT", vec![]),
        Operation::new("Tf", vec!["F1".into(), 12.into()]),
        Operation::new("Td", vec![72.into(), 720.into()]),
        Operation::new(
            "Tj",
            vec![Object::String(
                body_text.as_bytes().to_vec(),
                StringFormat::Literal,
            )],
        ),
        Operation::new("ET", vec![]),
    ];
    let encoded = Content { operations: ops }
        .encode()
        .expect("encode content");
    let content_id = doc.add_object(Stream::new(Dictionary::new(), encoded));
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });
    let page_id = doc.new_object_id();
    let pages_id = doc.new_object_id();
    let page = dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        "Resources" => resources_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
    };
    doc.objects.insert(page_id, Object::Dictionary(page));
    let pages = dictionary! {
        "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
    };
    doc.objects.insert(pages_id, Object::Dictionary(pages));
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);
    let mut out = Vec::new();
    doc.save_to(&mut out).expect("save synthetic pdf");
    out
}

/// Read back the EXTRACTABLE page text of a PDF (the Tj/TJ operand bytes,
/// Latin-1) so a test can assert an identifier is GONE / innocuous text remains
/// WITHOUT depending on `extract`. Concatenates every page's content-stream
/// text-showing operands.
fn pdf_extract_text(pdf: &[u8]) -> String {
    use lopdf::content::Content;
    use lopdf::{Document, Object};
    let doc = Document::load_mem(pdf).expect("reload redacted pdf");
    let mut text = String::new();
    for (_n, page_id) in doc.get_pages() {
        for sid in doc.get_page_contents(page_id) {
            let data = doc
                .get_object(sid)
                .and_then(Object::as_stream)
                .and_then(|s| s.decompressed_content())
                .expect("decompress content");
            let content = Content::decode(&data).expect("decode content");
            for op in content.operations {
                match op.operator.as_str() {
                    "Tj" | "'" | "\"" => {
                        if let Some(Object::String(b, _)) = op.operands.last() {
                            text.extend(b.iter().map(|&c| c as char));
                        }
                    }
                    "TJ" => {
                        if let Some(Object::Array(arr)) = op.operands.first() {
                            for o in arr {
                                if let Object::String(b, _) = o {
                                    text.extend(b.iter().map(|&c| c as char));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    text
}

/// The PDF body: a party name (term list) + an email + a Luhn-valid card +
/// innocuous text that must SURVIVE redaction.
const PDF_BODY: &str = "Memo for Acme Holdings Pte Ltd. Contact jane.roe@acme.example. \
         Card 4111111111111111. The quarterly review is on schedule.";

fn pdf_engine() -> RedactionEngine {
    // Term list catches the party name; built-ins catch the email + card.
    RedactionEngine::new(vec!["Acme Holdings Pte Ltd".to_string()])
}

/// A core seeded with ONE PDF blob (id 1, document) + ONE text doc (id 2,
/// document) so the blob workflow's content-kind SKIP of the text doc is
/// exercised. `core_with` / grants are reused from the text-path tests above.
fn pdf_seeded_core(grants: Vec<Capability>) -> TestCore {
    let mut store = InMemoryMatterStore::new();
    store.insert_blob(1, DataClass::Document, build_blob_pdf(PDF_BODY));
    store.insert(
        2,
        DataClass::Document,
        "an innocuous text doc, no identifiers",
    );
    core_with(grants, store)
}

/// Grants for the PDF redact-all path (read + transform; NO egress). The
/// default engine also covers the party class, so grant it too (parity).
fn pdf_redact_grants() -> Vec<Capability> {
    vec![
        Capability::MatterRead(DataClass::Document),
        Capability::MatterRead(DataClass::Party),
        Capability::DocumentTransform,
    ]
}

#[test]
fn redact_matter_pdf_removes_identifiers_keeps_innocuous_and_valid_pdf() {
    let mut core = pdf_seeded_core(pdf_redact_grants());
    let report = pdf_engine().redact_matter_pdf(&mut core).unwrap();

    // Exactly the ONE PDF blob was processed (the text doc id 2 is content-kind
    // skipped; the party class holds nothing).
    assert_eq!(report.docs_processed(), 1, "only the PDF blob is processed");
    assert!(
        report.total_identifiers_removed() >= 3,
        "party + email + card at least"
    );

    // Read the redacted blob back THROUGH the core and extract its text.
    let redacted = core.matter_read_blob(1, DataClass::Document).unwrap();
    let text = pdf_extract_text(&redacted);
    for needle in [
        "Acme Holdings Pte Ltd",
        "jane.roe@acme.example",
        "4111111111111111",
    ] {
        assert!(
            !text.contains(needle),
            "identifier {needle:?} must be GONE, got {text:?}"
        );
    }
    // Innocuous text SURVIVES, and the marker is present.
    assert!(
        text.contains("quarterly review is on schedule"),
        "innocuous text preserved, got {text:?}"
    );
    assert!(
        text.contains(REDACTION_MARKER),
        "matches replaced with the marker"
    );
    // The output is still a VALID, re-loadable PDF (pdf_extract_text already
    // re-loaded it; assert again explicitly for clarity).
    assert!(
        lopdf::Document::load_mem(&redacted).is_ok(),
        "redacted output is a valid PDF"
    );
}

#[test]
fn redact_matter_pdf_audit_has_count_breakdown_and_byte_length_no_bytes_no_values() {
    let mut core = pdf_seeded_core(pdf_redact_grants());
    pdf_engine().redact_matter_pdf(&mut core).unwrap();

    // The forbidden cleartext: the matched identifiers + raw PDF bytes markers.
    let forbidden = [
        "Acme Holdings Pte Ltd",
        "jane.roe@acme.example",
        "4111111111111111",
        "%PDF",
        "stream",
    ];
    for e in core.audit().entries() {
        for needle in forbidden {
            assert!(
                !e.detail.contains(needle),
                "audit detail must never carry cleartext/bytes; found {needle:?} in {:?}",
                e.detail
            );
        }
    }
    // The redaction audit.note records a count + breakdown (value-free).
    let note = core
        .audit()
        .entries()
        .iter()
        .find(|e| e.capability == Capability::AuditNote && e.detail.contains("redaction pdf:"))
        .expect("a redaction pdf note exists");
    assert!(
        note.detail.contains("doc 1"),
        "names the doc, got {:?}",
        note.detail
    );
    assert!(
        note.detail.contains("redaction(s) applied"),
        "records a count, got {:?}",
        note.detail
    );
    // The core's blob-transform entries record BYTE LENGTHS only.
    let xform = core
        .audit()
        .entries()
        .iter()
        .find(|e| e.capability == Capability::DocumentTransform && e.detail.contains("complete"))
        .expect("a blob transform complete entry exists");
    assert!(
        xform.detail.contains("bytes"),
        "transform records a byte length, got {:?}",
        xform.detail
    );
    assert!(
        core.audit().verify_chain(),
        "the keyed hash chain must verify"
    );
}

#[test]
fn redact_matter_pdf_is_byte_deterministic_across_runs() {
    // Two independent runs over the SAME seeded PDF produce byte-identical
    // redacted output (redact_pdf is byte-deterministic; the Core path adds none).
    let run = || {
        let mut core = pdf_seeded_core(pdf_redact_grants());
        pdf_engine().redact_matter_pdf(&mut core).unwrap();
        core.matter_read_blob(1, DataClass::Document).unwrap()
    };
    let a = run();
    let b = run();
    assert_eq!(a, b, "redacted PDF bytes must be deterministic across runs");
}

#[test]
fn scan_matter_pdf_needs_only_matter_read_and_writes_nothing() {
    // CAPABILITY SPLIT: scan works with ONLY matter.read (NO document.transform)
    // and writes NOTHING (the blob is byte-identical afterwards).
    let mut core = pdf_seeded_core(vec![
        Capability::MatterRead(DataClass::Document),
        Capability::MatterRead(DataClass::Party),
        // deliberately NO Capability::DocumentTransform
    ]);
    let before = core.matter_read_blob(1, DataClass::Document).unwrap();

    let report = pdf_engine().scan_matter_pdf(&mut core).unwrap();
    assert_eq!(report.docs_scanned(), 1, "only the PDF blob is scanned");
    assert!(
        report.total_candidates() >= 3,
        "party + email + card detected"
    );

    // The blob is UNCHANGED — a scan writes nothing.
    let after = core.matter_read_blob(1, DataClass::Document).unwrap();
    assert_eq!(before, after, "scan must not mutate the stored PDF");

    // The candidates carry cleartext for review (in-process only).
    let doc = &report.docs()[0];
    let values: Vec<&str> = doc.candidates().iter().map(|c| c.matched_value()).collect();
    assert!(
        values.iter().any(|v| v.contains("acme.example")),
        "email candidate present"
    );

    // No transform entry was ever logged (scan needs no transform).
    assert!(
        !core
            .audit()
            .entries()
            .iter()
            .any(|e| e.capability == Capability::DocumentTransform),
        "a scan must never log a document.transform"
    );
    // The scan WAS audited (a scan-pdf note).
    assert!(
        core.audit()
            .entries()
            .iter()
            .any(|e| e.detail.contains("redaction scan pdf:")),
        "the scan is audited"
    );
}

#[test]
fn redact_matter_pdf_default_deny_refused() {
    // No grants at all -> the very first matter_list_docs is refused, fail-closed.
    let mut core = pdf_seeded_core(vec![]);
    let err = pdf_engine().redact_matter_pdf(&mut core).unwrap_err();
    assert!(
        matches!(err, CoreError::Denied(Capability::MatterRead(_))),
        "got {err:?}"
    );
}

/// A core seeded with MANY text docs (ids 1..=N) + ONE PDF blob (id N+1), all
/// in the SAME `document` class — the realistic mix the audit-noise fix targets.
fn pdf_noise_core(n_text: u64, grants: Vec<Capability>) -> TestCore {
    let mut store = InMemoryMatterStore::new();
    for id in 1..=n_text {
        store.insert(
            id,
            DataClass::Document,
            "an innocuous text doc, no identifiers",
        );
    }
    store.insert_blob(n_text + 1, DataClass::Document, build_blob_pdf(PDF_BODY));
    core_with(grants, store)
}

/// AUDIT-NOISE FIX: a PDF sweep over a class holding N text docs + 1 PDF must
/// emit EXACTLY ONE blob-read audit entry (for the PDF) — never a value-free
/// "0 bytes" no-op read per text doc. Before the `DocRef.kind` filter, the sweep
/// blindly `matter_read_blob`-ed every doc, so each of the N text docs logged a
/// no-op read (N+1 read entries). After: the text docs are skipped by kind
/// BEFORE any read, so there is exactly 1 read entry.
#[test]
fn scan_matter_pdf_emits_no_per_text_doc_blob_read_audit_noise() {
    const N_TEXT: u64 = 50;
    let mut core = pdf_noise_core(
        N_TEXT,
        vec![
            Capability::MatterRead(DataClass::Document),
            Capability::MatterRead(DataClass::Party),
        ],
    );
    pdf_engine().scan_matter_pdf(&mut core).unwrap();

    // A standalone blob READ logs "matter read blob doc N (document): K bytes";
    // the LIST logs "matter list ..." (a different detail). Count only the per-doc
    // blob-read entries the scan itself performed.
    let blob_reads = core
        .audit()
        .entries()
        .iter()
        .filter(|e| {
            e.capability == Capability::MatterRead(DataClass::Document)
                && e.detail.starts_with("matter read blob doc")
        })
        .count();
    assert_eq!(
        blob_reads, 1,
        "exactly ONE blob read (the PDF) — the {N_TEXT} text docs are kind-skipped \
             with NO read attempt, so they emit no audit noise; got {blob_reads}"
    );

    // Sanity: the PDF that WAS read is the blob (id N_TEXT+1) — proving the one
    // read was the right doc, not a coincidence.
    let pdf_id = N_TEXT + 1;
    assert!(
        core.audit().entries().iter().any(|e| {
            e.detail
                .starts_with(&format!("matter read blob doc {pdf_id} ("))
        }),
        "the single blob read is the PDF doc {pdf_id}"
    );
    assert!(
        core.audit().verify_chain(),
        "the keyed hash chain still verifies"
    );
}

/// The same audit-noise property for the WRITE path (`redact_matter_pdf`): the N
/// text docs are kind-skipped, so neither a per-text-doc blob read NOR a
/// per-text-doc transform is logged — only the single PDF's read + transform.
#[test]
fn redact_matter_pdf_emits_no_per_text_doc_audit_noise() {
    const N_TEXT: u64 = 20;
    let mut core = pdf_noise_core(N_TEXT, pdf_redact_grants());
    let report = pdf_engine().redact_matter_pdf(&mut core).unwrap();
    assert_eq!(
        report.docs_processed(),
        1,
        "only the single PDF blob is processed"
    );

    // The sweep's own standalone blob read logs "matter read blob doc ..."; the
    // transform's INTERNAL read logs "matter read blob: class=..." — count only
    // the sweep's per-doc reads (one, for the PDF; none for the N text docs).
    let blob_reads = core
        .audit()
        .entries()
        .iter()
        .filter(|e| {
            e.capability == Capability::MatterRead(DataClass::Document)
                && e.detail.starts_with("matter read blob doc")
        })
        .count();
    let transforms = core
        .audit()
        .entries()
        .iter()
        .filter(|e| e.capability == Capability::DocumentTransform)
        .count();
    assert_eq!(
        blob_reads, 1,
        "exactly one blob read (the PDF), got {blob_reads}"
    );
    // The blob transform logs a start + a complete entry for the ONE PDF (2),
    // never one per text doc.
    assert_eq!(
        transforms, 2,
        "exactly the one PDF's transform start+complete, got {transforms}"
    );
    assert!(
        core.audit().verify_chain(),
        "the keyed hash chain still verifies"
    );
}

/// A `Blob` (PDF) doc sharing a `document` class with text docs must NOT abort
/// the TEXT sweep: `redact_matter` kind-skips the blob and redacts only the text
/// doc, leaving the PDF bytes untouched. (Before the kind filter, the text sweep
/// would `matter_read_text` the blob, hit a content-kind mismatch, and `?`-abort.)
#[test]
fn redact_matter_text_sweep_coexists_with_a_blob_in_the_same_class() {
    let mut store = InMemoryMatterStore::new();
    // A text doc with identifiers + a PDF blob, both in `document`.
    store.insert(1, DataClass::Document, SAMPLE);
    let original_pdf = build_blob_pdf(PDF_BODY);
    store.insert_blob(2, DataClass::Document, original_pdf.clone());
    let mut core = core_with(redaction_grants(), store);

    let report = engine().redact_matter(&mut core).unwrap();
    // Only the TEXT doc (id 1) was processed; the blob (id 2) was kind-skipped.
    assert_eq!(
        report.docs_processed(),
        1,
        "only the text doc is redacted by the text sweep"
    );
    // The text doc is redacted...
    let stored = core.matter_read_text(1, DataClass::Document).unwrap();
    assert!(!stored.contains("Project Condor"), "text doc was redacted");
    // ...and the PDF blob is byte-IDENTICAL (the text sweep never touched it).
    let pdf_after = core.matter_read_blob(2, DataClass::Document).unwrap();
    assert_eq!(
        pdf_after, original_pdf,
        "the blob is untouched by the text sweep"
    );
}

#[test]
fn united_kingdom_locale_pack_engine_level() {
    // The UK pack (PACK 2) is OPT-IN exactly like SG: enabling
    // `.locales([Locale::UnitedKingdom])` flags a UK snippet, a no-locale engine
    // does not, and the breakdown namespaces every UK recognizer under
    // `locale:uk:<name>`. (The per-row checksum vectors are unit-tested in
    // `packs::uk`; this is the engine wiring + audit-namespacing check.)
    let uk = || Recognizer::Locale(Arc::from("uk:nhs"));

    // (a) A bare engine (no locales) does NOT flag a UK NHS number.
    let bare = RedactionEngine::new(Vec::<String>::new());
    assert!(
        find_kind(&bare.candidates("NHS No 943 476 7571"), &uk()).is_none(),
        "no locale -> the UK NHS recognizer must not run"
    );

    // (b) Enabling the UK pack flags + strips a checksum-VALID NHS number.
    let e = RedactionEngine::builder()
        .locales([Locale::UnitedKingdom])
        .build()
        .unwrap();
    let cands = e.candidates("patient NHS No 943 476 7571 on file");
    let c = find_kind(&cands, &uk()).expect("UK locale flags a valid NHS number");
    assert_eq!(
        c.matched_value(),
        "943 476 7571",
        "span is the whole NHS number"
    );
    let (out, n) = e.redact_text("NHS 943 476 7571 noted");
    assert!(
        !out.contains("943 476 7571"),
        "UK locale -> NHS stripped, got {out:?}"
    );
    assert!(n >= 1);

    // (c) The checksum is a HARD GATE: a check-digit-corrupted NHS number (same
    // shape) is DROPPED, not flagged — `validate` returning false removes the match.
    assert!(
        find_kind(&e.candidates("NHS No 401 023 2138"), &uk()).is_none(),
        "a Modulus-11-INVALID NHS number must be dropped by validate()"
    );

    // (d) The audit breakdown namespaces the PRECISE UK recognizers `locale:uk:<name>`.
    // A snippet exercising the checksum-backed NHS + UTR and the format-only NINO
    // yields three namespaced buckets, deterministically sorted.
    //
    // NOTE on the chosen vectors: NHS and UTR are BOTH 10-digit Modulus-11 IDs,
    // so a number can be valid under BOTH (e.g. the spec's `2234567890` passes
    // each) — a genuine cross-recognizer ambiguity, not a bug. To keep this an
    // unambiguous per-bucket=1 wiring check we deliberately pick vectors that pass
    // exactly ONE checksum: NHS `943 476 7571` is UTR-INVALID, and UTR
    // `6135792468` is NHS-INVALID (both verified against the spec). The spaced
    // NHS shape (3-3-4) also can't match the UTR `\d{5} ?\d{5}` grouping, and the
    // bare UTR digits that DO match the NHS pattern are dropped by the NHS
    // `validate`. (The genuinely-ambiguous double-flag case is exercised at the
    // unit level in `packs::uk`.)
    let mixed = e.candidates("NHS 943 476 7571, UTR 6135792468, NINO AA 12 34 56 B, sort 12-34-56");
    let breakdown = recognizer_breakdown(&mixed);
    for needle in ["locale:uk:nhs=1", "locale:uk:utr=1", "locale:uk:nino=1"] {
        assert!(
            breakdown.contains(needle),
            "breakdown missing {needle:?}, got {breakdown:?}"
        );
    }

    // (e) "AGGRESSIVE LAST" — `uk:sort-code` is a broad, format-only bank row marked
    // `aggressive: true`, so on the `12-34-56` span (which the global `phone`
    // recognizer ALSO covers) the precedence rule DEMOTES sort-code below `phone`:
    // the PRIMARY (hence the breakdown bucket) is now `phone`, not `locale:uk:sort-code`.
    // This is the intended behavior — the broad row labels a span only as a LAST
    // RESORT. CRUCIALLY it is RECALL-NEUTRAL: the sort-code row STILL fires (it is a
    // co-recognizer on the span) and the token is STILL redacted.
    let sort_span: Vec<&RedactionCandidate> = mixed
        .iter()
        .filter(|c| c.matched_value().contains("12-34-56"))
        .collect();
    assert_eq!(
        sort_span.len(),
        1,
        "one merged candidate over the sort code, got {mixed:?}"
    );
    let sc = sort_span[0];
    assert_eq!(
        sc.recognizer(),
        &Recognizer::Phone,
        "the aggressive sort-code is demoted below the broad phone built-in, got {:?}",
        sc.recognizers()
    );
    assert!(
        sc.recognizers()
            .contains(&Recognizer::Locale(Arc::from("uk:sort-code"))),
        "the aggressive uk:sort-code row STILL fired (recall-neutral), got {:?}",
        sc.recognizers()
    );
    let (out, n) = e.redact_text("sort code 12-34-56 on the mandate");
    assert!(
        !out.contains("12-34-56"),
        "the sort code is still redacted, got {out:?}"
    );
    assert!(
        n >= 1,
        "the sort code span is redacted regardless of which row labels it"
    );
}

// ---- PART 6b: the AUSTRALIA locale pack (checksum-backed IDs end-to-end) ----

/// An engine with ONLY the AU locale pack enabled.
fn au_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .locales([Locale::Australia])
        .build()
        .unwrap()
}

#[test]
fn enabling_australia_locale_flags_checksum_valid_ids() {
    // The AU pack, opted in, flags each checksum-VALID core ID (TFN/ABN/ACN/
    // Medicare) under its `au:<row>` label and STRIPS it on a redaction pass. The
    // checksum-INVALID twin of the SAME shape is NOT flagged (the validator filtered
    // it — recall-first precision, no false ID).
    let e = au_engine();
    // (label-suffix, valid example, checksum-broken example)
    let cases = [
        ("au:tfn", "123456782", "123456783"),
        ("au:abn", "51682616150", "51682616151"),
        ("au:medicare", "2123456701", "2123258701"),
    ];
    for (label, good, bad) in cases {
        let cands = e.candidates(&format!("ref {good} on file"));
        let hit = cands
            .iter()
            .find(|c| matches!(c.recognizer(), Recognizer::Locale(a) if &**a == label));
        assert!(
            hit.is_some(),
            "{label}: expected to flag {good}, got {cands:?}"
        );
        assert_eq!(
            hit.unwrap().matched_value(),
            good,
            "{label}: span is the whole ID"
        );

        // The checksum-invalid twin is not flagged under that label.
        let bad_cands = e.candidates(&format!("ref {bad} on file"));
        assert!(
            !bad_cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Locale(a) if &**a == label)),
            "{label}: checksum-invalid {bad} must NOT be flagged, got {bad_cands:?}"
        );

        // ...and a redaction pass removes the valid one.
        let (out, n) = e.redact_text(&format!("ref {good} on file"));
        assert!(
            !out.contains(good),
            "{label}: {good} must be stripped, got {out:?}"
        );
        assert!(n >= 1);
    }
}

#[test]
fn australia_acn_flagged_under_its_own_namespace() {
    // The ACN aliases the TFN's 9-digit shape; the differing checksum is what
    // attributes it. A checksum-valid ACN is flagged under `au:acn`.
    let e = au_engine();
    let cands = e.candidates("company 123456780 incorporated");
    let acn = cands
        .iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Locale(a) if &**a == "au:acn"));
    assert!(
        acn.is_some(),
        "expected au:acn for 123456780, got {cands:?}"
    );
    assert_eq!(acn.unwrap().matched_value(), "123456780");
}

#[test]
fn australia_audit_breakdown_namespaced_au() {
    // The AU recognizers render in the deterministic audit breakdown under the
    // `locale:au:<name>` namespace (counts only — never a matched value).
    let e = au_engine();
    let cands = e.candidates("TFN 876543210, ABN 83123456790, ACN 987654320, Medicare 4567891241");
    let breakdown = recognizer_breakdown(&cands);
    for needle in [
        "locale:au:tfn=",
        "locale:au:abn=",
        "locale:au:acn=",
        "locale:au:medicare=",
    ] {
        assert!(
            breakdown.contains(needle),
            "breakdown missing {needle:?}, got {breakdown:?}"
        );
    }
}

#[test]
fn default_engine_does_not_flag_an_australian_id() {
    // The AU pack is OFF by default: a bare engine (no locale) never attributes a
    // value to an `au:`-namespaced recognizer, so a non-AU firm gets no AU
    // false-flags. (A bare 9-/11-digit run may still be caught by a GLOBAL built-in
    // such as `phone`/`id` — that is unrelated to the AU pack; the invariant under
    // test is specifically "no AU LOCALE recognizer fires without the locale".)
    let bare = RedactionEngine::builder().build().unwrap();
    for text in [
        "TFN 123456782 noted",
        "ABN 51682616150 on record",
        "ACN 123456780",
    ] {
        let cands = bare.candidates(text);
        assert!(
            !cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Locale(a) if a.starts_with("au:"))),
            "a default engine must NOT flag an AU locale ID in {text:?}, got {cands:?}"
        );
        // ...and the deterministic breakdown carries no `locale:au:` bucket.
        let breakdown = recognizer_breakdown(&cands);
        assert!(
            !breakdown.contains("locale:au:"),
            "default breakdown must carry no locale:au: entry for {text:?}, got {breakdown:?}"
        );
    }
}

#[test]
fn canada_locale_is_opt_in_and_flags_a_ca_snippet() {
    // End-to-end through the engine: enabling `.locales([Locale::Canada])` flags a
    // checksum-valid SIN (a real CA snippet), and the default (no-locale) engine
    // does NOT — the CA pack is strictly opt-in, like SG. `130692544` is a
    // checksum-VALID SIN (Luhn-valid, first digit 1).
    let ca_sin = Recognizer::Locale(Arc::from("ca:sin"));
    let text = "SIN 130-692-544 on file";

    // (a) opt-in flags it, under the `ca:sin` namespace.
    let e = RedactionEngine::builder()
        .locales([Locale::Canada])
        .build()
        .unwrap();
    let cands = e.candidates(text);
    let c = find_kind(&cands, &ca_sin).expect("CA locale flags a checksum-valid SIN");
    assert_eq!(c.matched_value(), "130-692-544");
    // The audit breakdown namespaces it `locale:ca:sin` (injective vs custom:).
    assert!(
        recognizer_breakdown(&cands).contains("locale:ca:sin=1"),
        "CA SIN namespaced under locale:ca:, got {:?}",
        recognizer_breakdown(&cands)
    );

    // (b) the default engine (no locale) does NOT flag it — no CA false-flags for
    // a firm that never opted into Canada.
    let bare = RedactionEngine::builder().build().unwrap();
    assert!(
        find_kind(&bare.candidates(text), &ca_sin).is_none(),
        "a bare engine must NOT flag a CA SIN (CA pack is opt-in)"
    );
}

#[test]
fn canada_sin_checksum_gate_filters_invalid_through_the_engine() {
    // The `validate` HARD GATE works end-to-end: a Luhn-valid-but-invalid-SIN
    // (`046454286`, leading 0) is REJECTED by the engine even though it matches the
    // SIN regex shape — the two-checks trap holds through the full pipeline, not
    // just in the unit validator. A checksum-VALID SIN in the same text IS flagged.
    let ca_sin = Recognizer::Locale(Arc::from("ca:sin"));
    let e = RedactionEngine::builder()
        .locales([Locale::Canada])
        .build()
        .unwrap();
    // `130 692 544` is a valid SIN. `046 454 286` is Luhn-VALID but an INVALID SIN
    // (leading 0); the engine drops it — but note the leading 0 is excluded by the
    // SIN regex `[1-79]` ITSELF, so it is filtered at the REGEX layer here, not by the
    // validator. The validator's independent first-digit-not-0/8 rule is defense-in-
    // depth the engine can't reach (the regex already excludes 0/8); it is exercised
    // directly by the unit test `ca_sin_046454286_is_luhn_valid_but_invalid_sin`.
    let cands = e.candidates("good 130 692 544 bad 046 454 286");
    let sins: Vec<&RedactionCandidate> =
        cands.iter().filter(|c| c.recognizer() == &ca_sin).collect();
    assert_eq!(
        sins.len(),
        1,
        "only the checksum-valid SIN survives, got {sins:?}"
    );
    assert_eq!(sins[0].matched_value(), "130 692 544");
}

// ===== RegexSet prefilter — RESULT-PRESERVATION proof =====================

/// An engine with EVERY locale pack enabled (all jurisdictions) — the max-pattern
/// configuration the prefilter is meant to speed up. Default built-ins, no profiles.
fn all_packs_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .locales([
            Locale::Singapore,
            Locale::UnitedStates,
            Locale::UnitedKingdom,
            Locale::Australia,
            Locale::Canada,
        ])
        .build()
        .unwrap()
}

/// BRUTE-FORCE ORACLE: the OLD detection path — scan EVERY `patterns` /
/// `term_patterns` / aggressive / user pattern with NO `RegexSet` prefilter, in
/// the exact same order, applying the same checksum `validate`. Returns the raw
/// (start, end, recognizer, replacement) span set BEFORE sort/merge. This is what
/// `merged_spans` collected before the prefilter; the prefilter must reproduce it
/// IDENTICALLY (it only skips patterns guaranteed to yield nothing).
fn raw_spans_no_prefilter(
    e: &RedactionEngine,
    text: &str,
) -> Vec<(usize, usize, Recognizer, Option<String>)> {
    let mut raw: Vec<(usize, usize, Recognizer, Option<String>)> = Vec::new();
    for tp in &e.patterns {
        for m in tp.re.find_iter(text) {
            if let Some(validate) = tp.validate {
                if !validate(m.as_str()) {
                    continue;
                }
            }
            raw.push((m.start(), m.end(), tp.kind.clone(), None));
        }
    }
    if let Some(re) = &e.aggressive_name {
        for m in re.find_iter(text) {
            raw.push((m.start(), m.end(), Recognizer::Name, None));
        }
    }
    for re in &e.term_patterns {
        for m in re.find_iter(text) {
            raw.push((m.start(), m.end(), Recognizer::Term, None));
        }
    }
    for ur in &e.user_recognizers {
        for m in ur.re.find_iter(text) {
            for tag in &ur.tags {
                raw.push((
                    m.start(),
                    m.end(),
                    tag.kind.clone(),
                    tag.replacement.clone(),
                ));
            }
        }
    }
    raw.retain(|(s, en, _, _)| en > s);
    raw
}

/// The PREFILTERED raw span set — the SAME logic `merged_spans` now runs, driving
/// `patterns`/`term_patterns` through the `RegexSet`s. Compared against the oracle.
fn raw_spans_prefiltered(
    e: &RedactionEngine,
    text: &str,
) -> Vec<(usize, usize, Recognizer, Option<String>)> {
    let mut raw: Vec<(usize, usize, Recognizer, Option<String>)> = Vec::new();
    for idx in e.pattern_set.matches(text) {
        let tp = &e.patterns[idx];
        for m in tp.re.find_iter(text) {
            if let Some(validate) = tp.validate {
                if !validate(m.as_str()) {
                    continue;
                }
            }
            raw.push((m.start(), m.end(), tp.kind.clone(), None));
        }
    }
    if let Some(re) = &e.aggressive_name {
        for m in re.find_iter(text) {
            raw.push((m.start(), m.end(), Recognizer::Name, None));
        }
    }
    // Mirror `merged_spans`: prefilter when present, else exhaustive fallback.
    match &e.term_set {
        Some(set) => {
            for idx in set.matches(text) {
                for m in e.term_patterns[idx].find_iter(text) {
                    raw.push((m.start(), m.end(), Recognizer::Term, None));
                }
            }
        }
        None => {
            for re in &e.term_patterns {
                for m in re.find_iter(text) {
                    raw.push((m.start(), m.end(), Recognizer::Term, None));
                }
            }
        }
    }
    for ur in &e.user_recognizers {
        for m in ur.re.find_iter(text) {
            for tag in &ur.tags {
                raw.push((
                    m.start(),
                    m.end(),
                    tag.kind.clone(),
                    tag.replacement.clone(),
                ));
            }
        }
    }
    raw.retain(|(s, en, _, _)| en > s);
    raw
}

#[test]
fn regexset_prefilter_is_result_identical_to_brute_force() {
    // The prefilter must collect the SAME raw spans as the old per-pattern scan,
    // over a document that exercises only a FEW recognizers (so the set genuinely
    // prunes most packs) — proving the prune dropped nothing and added nothing.
    let e = all_packs_engine();
    // An email + a checksum-valid US SSN (no other identifiers). With all 5 packs
    // enabled the engine has ~40+ patterns; only a handful should fire here.
    let text = "Contact alice.roe@example.com — SSN 123-45-6789 on file.";

    // BEFORE-MERGE raw spans: prefiltered == brute-force oracle, span-for-span.
    let oracle = raw_spans_no_prefilter(&e, text);
    let fast = raw_spans_prefiltered(&e, text);
    assert_eq!(
        fast, oracle,
        "RegexSet prefilter must collect IDENTICAL raw spans to the brute-force scan"
    );

    // AFTER-MERGE candidates: the live `candidates()` (which goes through the
    // prefilter) surfaces exactly the email + the SSN-digit span, nothing dropped
    // or spurious. (The SSN run `123-45-6789` is also matched by the global `phone`
    // recognizer; the overlapping matches merge into ONE candidate. Whatever the
    // primary recognizer of that merged span is, the SPAN itself is present — the
    // oracle-equality assertion just above already proved the raw spans collected
    // are identical to the brute-force scan, so the merge result is unchanged.)
    let cands = e.candidates(text);
    let values: Vec<&str> = cands.iter().map(|c| c.matched_value()).collect();
    assert_eq!(
        values,
        vec!["alice.roe@example.com", "123-45-6789"],
        "exactly the email + the SSN-digit span, nothing dropped, nothing spurious"
    );
    // The email span is attributed to `Email`. (The digit span's primary recognizer
    // is decided by the pre-existing merge priority and is NOT asserted here — the
    // result-preservation guarantee is the oracle equality above; this is just a
    // readable sanity check on the public surface.)
    assert_eq!(
        cands[0].recognizer(),
        &Recognizer::Email,
        "first candidate is the email"
    );

    // PRUNE PROOF: the `RegexSet` reports FEWER matching pattern indices than the
    // total pattern count — most packs (UK NHS, AU TFN, …) are pruned because they
    // have zero matches here. (A pure-perf assertion; it does not affect results.)
    let matched: Vec<usize> = e.pattern_set.matches(text).into_iter().collect();
    assert!(
        matched.len() < e.patterns.len(),
        "the prefilter must prune at least one non-matching pack: matched {} of {} patterns",
        matched.len(),
        e.patterns.len(),
    );
    // And every matched index is in range + aligned with `patterns` (alignment
    // sanity — `matches()` yields indices into the SAME ordered source list).
    assert!(
        matched.iter().all(|&i| i < e.patterns.len()),
        "every prefilter index must be a valid `patterns` index"
    );
}

#[test]
fn regexset_prefilter_empty_patterns_never_panics() {
    // EMPTY-CASE: no built-ins + no locales/profiles + no terms => `patterns`,
    // `term_patterns` both empty. `RegexSet::new([])` matches nothing — `matches()`
    // must yield zero indices and the engine must produce no candidates (no panic,
    // no out-of-range index).
    let e = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .build()
        .unwrap();
    assert!(e.patterns.is_empty(), "no built-ins/locales => no patterns");
    assert!(e.term_patterns.is_empty(), "no terms => no term patterns");
    let text = "alice.roe@example.com SSN 123-45-6789 +1 555 123 4567";
    assert_eq!(
        e.pattern_set.matches(text).into_iter().count(),
        0,
        "an empty pattern set matches nothing"
    );
    // No terms => `RegexSet::new(&[])` succeeds (it's `Some`, not the overflow
    // `None`) and the empty set matches nothing.
    let term_set = e
        .term_set
        .as_ref()
        .expect("empty term sources compile to Some(empty set)");
    assert_eq!(
        term_set.matches(text).into_iter().count(),
        0,
        "an empty term set matches nothing"
    );
    // The whole pipeline runs and returns no candidates — never panics.
    assert!(
        e.candidates(text).is_empty(),
        "no recognizers => no candidates"
    );
}

#[test]
fn regexset_prefilter_term_fallback_matches_prefiltered_path() {
    // Exercise the `term_set == None` FALLBACK branch directly + cheaply. `None`
    // means the combined `RegexSet` overflowed the regex size limit at abusive
    // config scale (the REAL overflow is the `#[ignore]`d test below — it compiles
    // ~10 MiB of regex, far too slow for the default suite). Here we instead FORCE
    // `None` on a small engine (the test module is in-crate, so it can touch the
    // private field), which deterministically drives `merged_spans` down the
    // exhaustive-direct-scan arm. The fallback MUST yield IDENTICAL candidates to the
    // prefiltered path — it is pure-speed degradation, never a skipped term.
    let terms = vec!["Project Halcyon".to_string(), "Acme".to_string()];
    let text = "Memo from Acme re Project Halcyon; cc Project Halcyon working group.";

    let prefiltered = RedactionEngine::builder()
        .terms(terms.clone())
        .build()
        .unwrap();
    assert!(
        prefiltered.term_set.is_some(),
        "a small term set compiles to Some(set)"
    );
    let want = prefiltered.candidates(text);

    let mut fallback = RedactionEngine::builder().terms(terms).build().unwrap();
    fallback.term_set = None; // simulate the overflow degradation
    let got = fallback.candidates(text);

    assert_eq!(
        got, want,
        "the None fallback (exhaustive scan) must equal the prefiltered path — no skip"
    );
    // RECALL preserved: every configured term is still redacted via the fallback.
    assert!(got.iter().any(|c| c.matched_value() == "Project Halcyon"));
    assert!(got.iter().any(|c| c.matched_value() == "Acme"));
}

#[test]
#[ignore = "abusive-scale: compiles ~10 MiB of regex to trigger a REAL RegexSet \
                size-limit overflow; slow. Run with `cargo test -p redaction -- --ignored`."]
fn regexset_prefilter_real_term_overflow_does_not_panic() {
    // The PANIC-FIX proof at real scale: enough long firm-configured terms that the
    // COMBINED `RegexSet` program exceeds the regex size limit (~10 MiB) even though
    // each term compiles fine as a standalone `Regex`. The OLD code `.expect`ed the
    // set and PANICKED at build here; the fix makes `term_set` `None` and falls back.
    // Sizing per the review's empirical finding (regex 1.12.4, the pinned version):
    // ~4000 terms of ~2000 chars overflow the combined set; 4096 x 2048 is safely over.
    let mut terms: Vec<String> = (0..4096)
        .map(|i| format!("zzfiller{:08}{}", i, "x".repeat(2048)))
        .collect();
    terms.push("Project Halcyon".to_string());
    let e = RedactionEngine::builder()
        .terms(terms)
        .build()
        .expect("engine must build at abusive term scale (no panic)");
    assert!(
        e.term_set.is_none(),
        "the combined term set must overflow at this scale => None (pinned regex 1.12.4)"
    );
    // RECALL: the sentinel term is still detected via the direct-scan fallback.
    let cands = e.candidates("Memo re Project Halcyon and next steps.");
    assert!(
        cands.iter().any(|c| c.matched_value() == "Project Halcyon"),
        "the fallback direct scan must still redact a configured term (no skip)"
    );
}

#[test]
fn regexset_prefilter_result_identical_over_dense_doc() {
    // A DENSE document that fires many recognizers across several packs: the
    // prefilter prunes nothing it shouldn't, so prefiltered == oracle here too.
    // (Catches the failure mode where the prefilter wrongly prunes a pattern that
    // DOES match — that would make `fast` a strict subset of `oracle`.)
    let e = all_packs_engine();
    let text = "Email bob@firm.co.uk, phone +44 20 7946 0958, IBAN GB82 WEST 1234 5698 7654 32, \
                    card 4012 8888 8888 1881, IP 192.168.1.1, URL https://example.org/x, \
                    US SSN 123-45-6789, Dr. Tan Wei Ming, ref PROJ-2026-014.";
    let oracle = raw_spans_no_prefilter(&e, text);
    let fast = raw_spans_prefiltered(&e, text);
    assert_eq!(
        fast, oracle,
        "on a dense multi-recognizer doc the prefilter must still match the brute-force scan"
    );
    // Live candidates equal what you'd get re-running through the same engine
    // (determinism + the public API exercises the prefiltered path).
    assert_eq!(e.candidates(text), e.candidates(text));
    assert!(
        !e.candidates(text).is_empty(),
        "the dense doc yields candidates"
    );
}

// ===================================================================
// LEVER 2 — context-proximity + confidence tier (additive-only gate)
// ===================================================================

/// A small mixed corpus exercising every existing recognizer, used by the
/// additive-only proof: with context recognizers OFF (default) the candidate
/// SET + spans + recognizers + order must be byte-identical before/after Lever 2.
const L2_DOCS: &[&str] = &[
    "Project Condor: contact Jane Roe at jane.roe@acme.example",
    "Card 4111 1111 1111 1111 on file; IBAN GB82 WEST 1234 5698 7654 32.",
    "Call +1 (415) 555-0142 or visit https://example.org/x. Server 192.0.2.5.",
    "Matter ref PROJ-2026-014 for Dr. Tan Wei Ming.",
    // WOULD trigger CTX recognizers if enabled: a bare 9-digit SSN-shaped run, a
    // DOB token, an explicit age, an account run — all near keywords.
    "Patient SSN 212345678, DOB 03/14/1957, age 95, account 11203847.",
];

fn default_engine_off() -> RedactionEngine {
    // The bare builder = ALL context recognizers OFF (the default).
    RedactionEngine::builder()
        .terms(vec!["Project Condor".to_string(), "Jane Roe".to_string()])
        .build()
        .unwrap()
}

/// A fingerprint of a candidate's load-bearing fields (NOT the new `confidence` —
/// that is the only addition allowed to differ): span, value, primary recognizer,
/// and the full recognizer list.
fn fingerprint(c: &RedactionCandidate) -> (usize, usize, String, String, Vec<String>) {
    (
        c.start(),
        c.end(),
        c.matched_value().to_string(),
        c.recognizer().to_string(),
        c.recognizers().iter().map(|r| r.to_string()).collect(),
    )
}

#[test]
fn lever2_additive_only_default_off_is_byte_identical_set_and_spans() {
    // With context OFF (default), the candidate SET + spans + recognizers + order
    // are stable across rebuilds — and crucially a context recognizer NEVER fires.
    for doc in L2_DOCS {
        let a = default_engine_off();
        let b = default_engine_off();
        let fa: Vec<_> = a.candidates(doc).iter().map(fingerprint).collect();
        let fb: Vec<_> = b.candidates(doc).iter().map(fingerprint).collect();
        assert_eq!(
            fa, fb,
            "default-off candidate set must be stable for {doc:?}"
        );
        for c in a.candidates(doc) {
            assert!(
                !matches!(c.recognizer(), Recognizer::Context(_)),
                "context recognizer must NOT fire when OFF; doc {doc:?}"
            );
            for r in c.recognizers() {
                assert!(!matches!(r, Recognizer::Context(_)));
            }
        }
    }
}

#[test]
fn lever2_undashed_ssn_does_not_fire_when_gating_off() {
    // A doc that WOULD trigger the undashed-SSN context recognizer: with context
    // OFF (default) the bare 9-digit run is NOT surfaced as a context candidate.
    let e = default_engine_off();
    let doc = "Patient SSN 212345678 on file.";
    let cands = e.candidates(doc);
    assert!(
        cands
            .iter()
            .all(|c| c.recognizer().to_string() != "ctx:ssn-undashed"),
        "undashed-SSN context recognizer must not fire when OFF: {cands:?}",
    );
}

fn ssn_context_engine() -> RedactionEngine {
    // ONLY the undashed-SSN context recognizer on, every BROAD built-in off, so the
    // 9-digit run is attributable to the context recognizer alone (no incidental
    // phone/id overlap muddying the gate proof).
    RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .context_recognizers(ContextRecognizers {
            ssn_undashed: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap()
}

#[test]
fn lever2_gate_undashed_ssn_no_keyword_no_other_recognizer_is_dropped() {
    // A valid 9-digit SSN-shaped run with NO "SSN" keyword and NO other recognizer
    // covering it => NOT a candidate (gate: context-only span, no keyword in-window).
    let e = ssn_context_engine();
    let doc = "Reference number is 212345678 for the file.";
    let cands = e.candidates(doc);
    assert!(
        cands
            .iter()
            .all(|c| c.recognizer().to_string() != "ctx:ssn-undashed"),
        "context-only undashed SSN with no keyword must be GATED OUT: {cands:?}",
    );
}

#[test]
fn lever2_gate_undashed_ssn_with_keyword_fires_at_right_tier() {
    // The SAME run WITH an "SSN:" keyword in-window => a candidate. Close keyword
    // (same clause) => High.
    let e = ssn_context_engine();
    let doc = "SSN: 212345678 on file.";
    let cands = e.candidates(doc);
    let hit = cands
        .iter()
        .find(|c| c.recognizer().to_string() == "ctx:ssn-undashed")
        .expect("undashed SSN fires WITH an in-window keyword");
    assert_eq!(hit.matched_value(), "212345678");
    assert_eq!(
        hit.confidence(),
        Confidence::High,
        "a CLOSE (≤20-byte) SSN keyword promotes the context match to High",
    );
}

#[test]
fn lever2_gate_undashed_ssn_stays_when_a_normal_recognizer_also_covers_it() {
    // ADDITIVE PROOF: a 9-digit run that ALSO matches a normal recognizer stays
    // REGARDLESS of any keyword — the context gate can never remove a normal match.
    let e = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .recognizers(vec![UserRecognizer::literal("acct-no", "212345678")])
        .context_recognizers(ContextRecognizers {
            ssn_undashed: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap();
    let doc = "Reference 212345678 with no PII keyword nearby at all.";
    let cands = e.candidates(doc);
    let hit = cands
        .iter()
        .find(|c| c.start() == doc.find("212345678").unwrap())
        .expect("the run is STILL a candidate — a normal recognizer covers it");
    // Primary is the NORMAL recognizer (the gate kept it).
    assert_eq!(hit.recognizer().to_string(), "acct-no");
    assert!(
        hit.recognizers().iter().any(|r| r.to_string() == "acct-no"),
        "the normal recognizer is recorded on the merged span",
    );
}

#[test]
fn lever2_tier_checksum_card_is_high_regardless_of_context() {
    // Rung 1: a Luhn-valid card => High whether or not a "card" keyword is near.
    let e = RedactionEngine::new(Vec::<String>::new());
    for doc in [
        "4111 1111 1111 1111",                       // no keyword
        "Payment card on file: 4111 1111 1111 1111", // keyword present
    ] {
        let c = e
            .candidates(doc)
            .into_iter()
            .find(|c| matches!(c.recognizer(), Recognizer::CreditCard))
            .expect("the canonical test PAN is Luhn-valid and matches");
        assert_eq!(
            c.confidence(),
            Confidence::High,
            "checksum-valid card is always High: {doc:?}"
        );
    }
}

#[test]
fn lever2_tier_structural_email_high_with_keyword_medium_without() {
    let e = RedactionEngine::new(Vec::<String>::new());
    let with_kw = e
        .candidates("Email: jane.roe@acme.example")
        .into_iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Email))
        .unwrap();
    assert_eq!(
        with_kw.confidence(),
        Confidence::High,
        "email + class keyword => High"
    );
    let no_kw = e
        .candidates("ping jane.roe@acme.example tomorrow about the filing schedule")
        .into_iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Email))
        .unwrap();
    assert_eq!(
        no_kw.confidence(),
        Confidence::Medium,
        "email alone => Medium"
    );
}

#[test]
fn lever2_tier_dashed_ssn_structural_high_with_keyword_medium_without() {
    // Rung 2: a dashed US SSN (the `us:ssn` locale row, STRUCTURAL not checksum) is
    // High near an "SSN" keyword and Medium alone.
    let e = RedactionEngine::builder()
        .locales([Locale::UnitedStates])
        .build()
        .unwrap();
    let with_kw = e
        .candidates("SSN: 212-34-5678 on file")
        .into_iter()
        .find(|c| c.recognizer().to_string() == "us:ssn")
        .expect("dashed SSN matches the us:ssn locale row");
    assert_eq!(
        with_kw.confidence(),
        Confidence::High,
        "dashed SSN + 'SSN' keyword => High"
    );
    let no_kw = e
        .candidates("the value 212-34-5678 appears in a long unrelated padded sentence here")
        .into_iter()
        .find(|c| c.recognizer().to_string() == "us:ssn")
        .expect("dashed SSN still fires without a keyword (structural)");
    assert_eq!(
        no_kw.confidence(),
        Confidence::Medium,
        "dashed SSN alone => Medium (structural floor)"
    );
}

#[test]
fn lever2_age_over_89_fires_near_age_keyword_not_otherwise() {
    let e = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .context_recognizers(ContextRecognizers {
            age_over_89: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap();
    let fires = e.candidates("patient age 95 admitted");
    assert!(
        fires
            .iter()
            .any(|c| c.recognizer().to_string() == "ctx:age-over-89" && c.matched_value() == "95"),
        "explicit age>89 near an age keyword fires: {fires:?}",
    );
    let no_fire = e.candidates("invoice 95 paid in full");
    assert!(
        no_fire
            .iter()
            .all(|c| c.recognizer().to_string() != "ctx:age-over-89"),
        "a bare 95 with no age keyword must be gated out: {no_fire:?}",
    );
}

#[test]
fn lever2_age_over_89_no_clock_dependency_identical_across_calls() {
    // Determinism / no-clock: two calls produce identical results.
    let e = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .context_recognizers(ContextRecognizers::all())
        .build()
        .unwrap();
    // Keep "invoice 95" FAR (> the ±40-char window) from any age keyword.
    let doc = "the claimant, aged 97, and patient age 102. \
                   Unrelated line padded out well beyond the proximity window: invoice 95 paid.";
    let first: Vec<_> = e.candidates(doc).iter().map(fingerprint).collect();
    let second: Vec<_> = e.candidates(doc).iter().map(fingerprint).collect();
    assert_eq!(
        first, second,
        "age recognizer is clock-free + deterministic"
    );
    assert!(first.iter().any(|f| f.2 == "97"));
    assert!(first.iter().any(|f| f.2 == "102"));
    assert!(
        !first.iter().any(|f| f.2 == "95"),
        "bare 95 far from any age keyword is gated out: {first:?}",
    );
}

#[test]
fn lever2_determinism_candidates_equal_across_calls_with_context_on() {
    let e = RedactionEngine::builder()
        .terms(vec!["Acme".to_string()])
        .context_recognizers(ContextRecognizers::all())
        .build()
        .unwrap();
    let doc = "Acme client: SSN 457551234, DOB 03/14/1957, age 95, account 11203847; \
                   email a@b.co, card 4111 1111 1111 1111.";
    let a: Vec<_> = e.candidates(doc).iter().map(fingerprint).collect();
    let b: Vec<_> = e.candidates(doc).iter().map(fingerprint).collect();
    assert_eq!(a, b, "candidates(text) == candidates(text)");
    let ta: Vec<_> = e.candidates(doc).iter().map(|c| c.confidence()).collect();
    let tb: Vec<_> = e.candidates(doc).iter().map(|c| c.confidence()).collect();
    assert_eq!(ta, tb, "confidence is deterministic");
}

#[test]
fn lever2_audit_note_has_tier_counts_and_no_cleartext() {
    // The audit note carries per-tier COUNTS and NO matched value (a planted SSN).
    let mut store = InMemoryMatterStore::new();
    let secret_ssn = "457551234";
    let doc = format!("Email: x@y.co; SSN: {secret_ssn} on file.");
    store.insert(1, DataClass::Document, &doc);
    let mut core = core_with(redaction_grants(), store);
    let e = RedactionEngine::builder()
        .classes(vec![DataClass::Document])
        .context_recognizers(ContextRecognizers {
            ssn_undashed: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap();
    let _ = e.redact_matter(&mut core).unwrap();

    let notes: Vec<String> = core
        .audit()
        .entries()
        .iter()
        .filter(|en| en.capability == Capability::AuditNote)
        .map(|en| en.detail.clone())
        .collect();
    let doc_note = notes
        .iter()
        .find(|n| n.contains("redaction(s) applied"))
        .expect("a per-doc redaction note was written");
    assert!(
        doc_note.contains("high="),
        "tier counts present: {doc_note:?}"
    );
    assert!(
        doc_note.contains("medium="),
        "tier counts present: {doc_note:?}"
    );
    assert!(
        doc_note.contains("low="),
        "tier counts present: {doc_note:?}"
    );
    for n in &notes {
        assert!(
            !n.contains(secret_ssn),
            "audit note must NOT contain the planted SSN {secret_ssn:?}: {n:?}",
        );
    }
}

#[test]
fn lever2_multibyte_keyword_and_match_are_char_boundary_safe() {
    // A multibyte run around the keyword + the match must not panic and must land on
    // char boundaries.
    let e = ssn_context_engine();
    let doc = "café — SSN: 212345678 — naïve façade";
    let cands = e.candidates(doc); // must not panic
    let hit = cands
        .iter()
        .find(|c| c.recognizer().to_string() == "ctx:ssn-undashed")
        .expect("fires near the keyword despite multibyte neighbors");
    assert_eq!(hit.matched_value(), "212345678");
    assert_eq!(&doc[hit.start()..hit.end()], "212345678");
    assert!(!hit.context().is_empty());
}

#[test]
fn lever2_dob_and_account_fire_only_near_their_keywords() {
    let e = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .context_recognizers(ContextRecognizers::all())
        .build()
        .unwrap();
    let dob = e.candidates("DOB 03/14/1957 recorded");
    assert!(
        dob.iter().any(|c| c.recognizer().to_string() == "ctx:dob"),
        "DOB token near a DOB keyword fires: {dob:?}",
    );
    let bare_date = e.candidates("the hearing is on 03/14/1957 sharp");
    assert!(
        bare_date
            .iter()
            .all(|c| c.recognizer().to_string() != "ctx:dob"),
        "a bare date with no DOB keyword is gated out: {bare_date:?}",
    );
    let acct = e.candidates("account 11203847 active");
    assert!(
        acct.iter()
            .any(|c| c.recognizer().to_string() == "ctx:account-mrn"),
        "account run near an account keyword fires: {acct:?}",
    );
    let bare_run = e.candidates("widget 11203847 shipped");
    assert!(
        bare_run
            .iter()
            .all(|c| c.recognizer().to_string() != "ctx:account-mrn"),
        "a bare alnum run with no account keyword is gated out: {bare_run:?}",
    );
}

#[test]
fn lever2_undashed_ssn_structural_validator_rejects_invalid_runs() {
    // The undashed-SSN row reuses `ssn_valid`: a structurally-INVALID 9-digit run
    // (area 000) does not fire even WITH a keyword.
    let e = ssn_context_engine();
    let invalid = e.candidates("SSN: 000123456 on file"); // area 000 invalid
    assert!(
        invalid
            .iter()
            .all(|c| c.recognizer().to_string() != "ctx:ssn-undashed"),
        "structurally-invalid SSN does not fire even with a keyword: {invalid:?}",
    );
}

#[test]
fn lever2_no_systemtime_or_clock_in_crate_source() {
    // Guard: NO clock anywhere in the redaction crate source (determinism /
    // no-current-date non-negotiable). Reads the crate's own sources and flags REAL
    // clock USAGE (a `.now()` on a time type, or a `std::time` import), ignoring
    // comment lines. Needles are built at RUNTIME by concatenation so this test's own
    // source line never contains any needle verbatim.
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let time = "std::".to_string() + "time";
    let needles: [String; 4] = [
        "SystemTime::".to_string() + "now",
        "Instant::".to_string() + "now",
        "use ".to_string() + &time,
        time.clone() + "::",
    ];
    let mut hits: Vec<String> = Vec::new();
    let scan_one = |p: &std::path::Path, hits: &mut Vec<String>| {
        for (i, raw) in std::fs::read_to_string(p).unwrap().lines().enumerate() {
            let line = raw.trim_start();
            if line.starts_with("//") {
                continue;
            }
            for needle in &needles {
                if line.contains(needle.as_str()) {
                    hits.push(format!("{}:{}: {needle}", p.display(), i + 1));
                }
            }
        }
    };
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(std::path::Path::new(src_dir), &mut files);
    for f in &files {
        scan_one(f, &mut hits);
    }
    assert!(
        hits.is_empty(),
        "no clock/current-date in redaction src; found: {hits:?}"
    );
}

// ===================================================================
// ADDRESS FAMILY (global structured-address built-in) + ROLE-CONTEXT NAME
// capture + the motivating-miss SYNTHETIC fixture. Added with the address /
// role-name recognizers. Every value here is FABRICATED / public-shape only.
// ===================================================================

/// A default engine (all built-ins ON, incl. the structured-address family; no packs).
fn addr_engine() -> RedactionEngine {
    RedactionEngine::builder().build().unwrap()
}

/// Does `text` produce a candidate whose primary recognizer is `Address` covering `needle`?
fn address_covers(e: &RedactionEngine, text: &str, needle: &str) -> bool {
    e.candidates(text).iter().any(|c| {
        matches!(c.recognizer(), Recognizer::Address) && text[c.start()..c.end()].contains(needle)
    })
}

#[test]
fn address_street_row_catches_number_streetname_suffix() {
    let e = addr_engine();
    // Positive: the motivating shapes + a spread of street-type suffixes, case-tolerant.
    for (text, needle) in [
        ("Registered at 50 Raffles Place today.", "50 Raffles Place"),
        ("Discharged to 221B Baker Street.", "221B Baker Street"),
        ("Office at 80 Raffles Quay level.", "80 Raffles Quay"),
        ("Meet at 12 Marina View please.", "12 Marina View"),
        ("post to 3 Orchard Boulevard now", "3 Orchard Boulevard"),
        ("at 7 Cecil street lower", "7 Cecil street"), // SUFFIX is case-tolerant (name stays Capitalized)
    ] {
        assert!(
            address_covers(&e, text, needle),
            "street address {needle:?} must be caught in {text:?}"
        );
    }
}

#[test]
fn address_street_row_does_not_flood_on_bare_number_lowercase_run() {
    // RECALL-FIRST but bounded: the street-name tokens are Capitalized-anchored, so a
    // bare-number + lowercase-word run ("14 items on the road") does NOT match — the
    // flood the `\p{Lu}` anchor prevents. (A real Capitalized street name still fires.)
    let e = addr_engine();
    assert!(
        !e.candidates("we sold 14 items on the road that day")
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Address)),
        "a lowercase 'number ... suffix' run must not flag as an address"
    );
    // A statute section / money figure must not flag as an address either.
    for clean in [
        "Section 230 of the Act",
        "USD 1,250,000.00 due",
        "clause 7.2.1",
    ] {
        assert!(
            !e.candidates(clean)
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Address)),
            "{clean:?} must not flag as an address"
        );
    }
}

#[test]
fn address_unit_and_pobox_rows_catch_floor_and_box_forms() {
    let e = addr_engine();
    for (text, needle) in [
        ("unit ref #16-03 signed", "#16-03"),
        ("penthouse #33-01 tower", "#33-01"),
        ("stack #16-0304 core", "#16-0304"),
        ("on Level 12 north wing", "Level 12"),
        ("go to Suite 4 reception", "Suite 4"),
        ("in Unit 8 storeroom", "Unit 8"),
        ("mail to PO Box 12345 depot", "PO Box 12345"),
        ("send P.O. Box 987 today", "P.O. Box 987"),
    ] {
        assert!(
            address_covers(&e, text, needle),
            "floor/unit/box form {needle:?} must be caught in {text:?}"
        );
    }
    // NEGATIVE: "Unit tests" has no trailing number → no match; "United" is not "Unit N".
    for clean in ["Unit tests passed cleanly", "United Nations charter"] {
        assert!(
            !e.candidates(clean)
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Address)),
            "{clean:?} must not flag as an address (no trailing box/unit number)"
        );
    }
}

#[test]
fn address_is_default_on_and_routes_to_careful_review_never_quick_confirm() {
    // The street row is a DEFAULT built-in (no opt-in), and every address candidate is
    // CAREFUL review (never quick-confirm): Address is neither checksum nor structural, so
    // `confidence_for` never reaches High → below the default High quick-confirm floor.
    let e = addr_engine();
    let policy = ReviewPolicy::default();
    let cands = e.candidates("The registered office is 50 Raffles Place, per the deed.");
    let addr: Vec<_> = cands
        .iter()
        .filter(|c| matches!(c.recognizer(), Recognizer::Address))
        .collect();
    assert!(
        !addr.is_empty(),
        "the address must be a candidate by default"
    );
    for c in addr {
        assert_ne!(
            c.confidence(),
            Confidence::High,
            "an address is never High (never quick-confirm)"
        );
        assert_eq!(
            policy.tier(c.confidence()),
            ReviewTier::CarefulReview,
            "an address routes to careful review"
        );
        // It is a normal built-in, NOT advisory (advisory is the aggressive-locale flag).
        assert!(!e.is_aggressive(c.recognizer()), "address is not advisory");
    }
}

#[test]
fn address_labels_mode_renders_bracket_address_type() {
    // In AI-safe LABELS mode a redacted address gets the `[address]` typed placeholder.
    let e = addr_engine();
    let text = "Deliver to 50 Raffles Place before noon.";
    let cands = e.candidates(text);
    let c = cands
        .iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Address))
        .expect("address candidate");
    let accept: std::collections::HashSet<(usize, usize)> =
        std::collections::HashSet::from([(c.start(), c.end())]);
    let (labeled, legend, _applied, _stale) = e.redact_with_selection_labeled(text, &accept);
    assert!(labeled.contains("[address]"), "labeled: {labeled:?}");
    assert!(legend.iter().any(|row| row.label == "[address]"));
}

#[test]
fn address_family_ws_recall_matches_fragmented_and_is_scoped_to_address_family() {
    // The whitespace-elastic recall (the PDF glyph-by-glyph fix) fires on FRAGMENTED
    // address-family shapes but is SCOPED to that family — a general recognizer (phone/id)
    // is NEVER made whitespace-insensitive (constraint (a): that would flood).
    let e = RedactionEngine::builder()
        .locales([Locale::Singapore])
        .build()
        .unwrap();
    // Fragmented unit + postal are caught with the right attribution.
    let unit = e.address_family_spans_whitespace_insensitive("Raffles Place, # 16-0 3 tower");
    assert!(
        unit.iter()
            .any(|(_, _, r)| matches!(r, Recognizer::Address)),
        "fragmented #16-03 caught as Address: {unit:?}"
    );
    let postal = e.address_family_spans_whitespace_insensitive("at Singapore 0486 23 today");
    assert!(
        postal.iter().any(|(_, _, r)| r.to_string() == "sg:postal"),
        "fragmented SG postal caught as sg:postal: {postal:?}"
    );
    // A fragmented PHONE run is NOT in the address-family recall set (phones stay
    // whitespace-significant — only the ordinary, exact pass sees them).
    let phone = e.address_family_spans_whitespace_insensitive("tel + 8 5 2 2 8 0 0 2 8 0 0");
    assert!(
        phone.is_empty(),
        "a fragmented phone must NOT be caught by the address recall: {phone:?}"
    );
}

#[test]
fn address_family_ws_recall_is_empty_when_no_address_rows_enabled() {
    // CONSTRAINT (c) at the engine level: address built-in OFF + no precise postal locale =>
    // the whitespace-elastic address set is empty and the recall method is a no-op, so the
    // PDF pass that consumes it is byte-identical to before.
    let e = RedactionEngine::builder()
        .builtins({
            let mut b = BuiltinRecognizers::all();
            b.address = false;
            b
        })
        .build()
        .unwrap();
    assert!(
        e.address_family_spans_whitespace_insensitive(
            "Raffles Place, # 16-0 3 and Singapore 0486 23"
        )
        .is_empty(),
        "no address rows => empty ws-address recall"
    );
}

// ---- ROLE-CONTEXT NAME (ctx:role-name) ----

/// An engine with ONLY the role-name context recognizer on (built-ins off), so a test
/// isolates the row.
fn role_name_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .context_recognizers(ContextRecognizers {
            role_name: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap()
}

fn has_role_name(cands: &[RedactionCandidate], value: &str) -> bool {
    cands.iter().any(|c| {
        c.recognizers()
            .iter()
            .any(|r| r.to_string() == "ctx:role-name")
            && c.matched_value() == value
    })
}

#[test]
fn role_name_fires_after_a_role_heading_incl_following_lines() {
    // The motivating layout: a "Managers" heading then names on the FOLLOWING lines
    // (the ±window spans '\n'). Every honorific-less, non-TERM name is captured.
    let e = role_name_engine();
    let text = "Managers\nLee Wai Keong\nTan Peng Ho\nSumitomo Mitsui Trust Bank";
    let cands = e.candidates(text);
    assert!(
        has_role_name(&cands, "Lee Wai Keong"),
        "director/manager name #1 caught, got {cands:?}"
    );
    assert!(
        has_role_name(&cands, "Tan Peng Ho"),
        "director/manager name #2 caught, got {cands:?}"
    );
    // Honest over-flag: the trailing ORG line is also captured (fine — over-flag is the
    // SAFE side per the PRINCIPLE; the review layer + grouping absorb it).
    assert!(
        has_role_name(&cands, "Sumitomo Mitsui Trust Bank"),
        "org in the list is over-flagged (acceptable), got {cands:?}"
    );
}

#[test]
fn role_name_requires_a_role_keyword_in_window() {
    // Without a role heading in-window, the same name run is GATED OUT (additive-only).
    let e = role_name_engine();
    let text = "The quick brown notes were filed; Lee Wai Keong then left the padded room here.";
    let cands = e.candidates(text);
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == "ctx:role-name"),
        "a name with no role keyword in-window must not fire, got {cands:?}"
    );
    // Various role labels each corroborate.
    for kw in [
        "Director",
        "Chairman",
        "Chief Executive Officer",
        "Trustee",
        "Secretary",
    ] {
        let t = format!("{kw}\nLee Wai Keong signed");
        assert!(
            has_role_name(&e.candidates(&t), "Lee Wai Keong"),
            "role keyword {kw:?} must corroborate, got {:?}",
            e.candidates(&t)
        );
    }
}

#[test]
fn role_name_is_capped_at_careful_review_even_with_a_close_keyword() {
    // The tier CEILING: a role heading immediately before the name is CLOSE, which would
    // normally promote a ctx row to High/quick-confirm — but `cap_tier: Some(Medium)`
    // pins role-name to CAREFUL review, deliberately (it is FP-prone).
    let e = role_name_engine();
    let policy = ReviewPolicy::default();
    // The heading on its own line (the list layout) keeps the keyword OUTSIDE the matched
    // name run, and immediately adjacent (only the '\n' between) — a CLOSE keyword.
    let cands = e.candidates("Director\nLee Wai Keong signed");
    let c = cands
        .iter()
        .find(|c| c.recognizer().to_string() == "ctx:role-name")
        .expect("role-name fires with a close keyword");
    assert_ne!(c.confidence(), Confidence::High, "capped below High");
    assert_eq!(policy.tier(c.confidence()), ReviewTier::CarefulReview);
}

#[test]
fn role_name_off_by_default() {
    // role-name is OPT-IN (a context recognizer): a default engine never flags it.
    let e = addr_engine();
    let cands = e.candidates("Managers\nLee Wai Keong\nTan Peng Ho");
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == "ctx:role-name"),
        "role-name must be off unless context is enabled, got {cands:?}"
    );
}

#[test]
fn motivating_miss_synthetic_fixture_is_now_covered() {
    // The real-world miss, reproduced EXACTLY in shape (SYNTHETIC values): a redacted
    // prospectus where every address + role-context name survived. One engine: default
    // built-ins (address family ON) + SG locale (postal) + role-name context.
    let e = RedactionEngine::builder()
        .locales([Locale::Singapore])
        .context_recognizers(ContextRecognizers {
            role_name: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap();
    let text = "Registered Office\n50 Raffles Place, #16-03, Singapore 048623\n\
                80 Raffles Place\n\
                Managers\nLee Wai Keong\nTan Peng Ho\nSumitomo Mitsui Trust Bank";
    let cands = e.candidates(text);
    let covered = |needle: &str| -> bool {
        cands
            .iter()
            .any(|c| text[c.start()..c.end()].contains(needle))
    };
    // Addresses (street + unit) — the deterministic engine now removes them.
    assert!(covered("50 Raffles Place"), "street addr #1: {cands:?}");
    assert!(covered("80 Raffles Place"), "street addr #2: {cands:?}");
    assert!(covered("#16-03"), "SG unit number: {cands:?}");
    // SG postal ("Singapore NNNNNN") via the opt-in SG pack.
    assert!(
        cands.iter().any(
            |c| c.recognizers().iter().any(|r| r.to_string() == "sg:postal")
                && c.matched_value().contains("048623")
        ),
        "SG postal code caught: {cands:?}"
    );
    // Role-context manager/director names.
    assert!(
        has_role_name(&cands, "Lee Wai Keong"),
        "manager #1: {cands:?}"
    );
    assert!(
        has_role_name(&cands, "Tan Peng Ho"),
        "manager #2: {cands:?}"
    );
}

#[test]
fn role_name_fires_across_a_long_whitespace_only_line() {
    // MISS 2 (the real prospectus shape): a role heading and the name are separated by a
    // WHITESPACE-ONLY line that PDF reconstruction fills with a long run of positioning
    // spaces (`Solicitors to the Managers\n<many spaces>\nTan Peng Chin LLC`). That run
    // exceeds the fixed ±CONTEXT_WINDOW_CHARS window, pushing the "Managers" heading out of
    // proximity, so `ctx:role-name` MISSED the name. The `blank_line_tolerance` widening
    // lets the probe reach the heading ACROSS up to 2 whitespace-only lines regardless of
    // their length; the name (and its trailing `LLC` org token) is now captured.
    let e = role_name_engine();
    let pad = " ".repeat(60); // a positioning-gap line far longer than the char window
    let one_line = format!("Solicitors to the Managers\n{pad}\nTan Peng Chin LLC");
    let two_lines = format!("Solicitors to the Managers\n{pad}\n{pad}\nTan Peng Chin LLC");
    for (label, text) in [
        ("one blank line", &one_line),
        ("two blank lines", &two_lines),
    ] {
        let cands = e.candidates(text);
        assert!(
            has_role_name(&cands, "Tan Peng Chin LLC"),
            "{label}: the name run must be captured across the long whitespace-only line(s); got {cands:?}"
        );
    }

    // BOUNDED: THREE long whitespace-only lines exceed the tolerance (2), so the heading is
    // out of reach and the name is (correctly) NOT captured on that basis — the widening
    // cannot run away.
    let three_lines = format!("Solicitors to the Managers\n{pad}\n{pad}\n{pad}\nTan Peng Chin LLC");
    let cands = e.candidates(&three_lines);
    assert!(
        !has_role_name(&cands, "Tan Peng Chin LLC"),
        "three long whitespace-only lines exceed the bounded tolerance; got {cands:?}"
    );

    // FP POSTURE preserved: the captured name is capped at CAREFUL review (never High /
    // quick-confirm), even though the widening brought the heading into window.
    let cands = e.candidates(&one_line);
    let c = cands
        .iter()
        .find(|c| c.recognizer().to_string() == "ctx:role-name")
        .expect("role-name fires");
    assert_ne!(c.confidence(), Confidence::High, "still capped below High");
    assert_eq!(
        ReviewPolicy::default().tier(c.confidence()),
        ReviewTier::CarefulReview,
        "still routes to careful review"
    );
}

#[test]
fn role_name_short_blank_line_gap_still_fires_and_normal_window_unchanged() {
    // Control: the SHORT `\n \n` gap (well within the fixed window) already fired and still
    // does; and a name with NO role keyword anywhere is still gated out (the widening only
    // reaches ACROSS whitespace — it never invents a keyword). Guards against the extension
    // loosening the no-keyword case.
    let e = role_name_engine();
    assert!(has_role_name(
        &e.candidates("Solicitors to the Managers\n \nTan Peng Chin LLC"),
        "Tan Peng Chin LLC"
    ));
    // A long whitespace-only line with NO role keyword before it: nothing to corroborate,
    // so the name must NOT fire (the extension crosses blanks, it does not fabricate a hit).
    let pad = " ".repeat(60);
    let text = format!("Some unrelated prose here\n{pad}\nTan Peng Chin LLC");
    assert!(
        !e.candidates(&text)
            .iter()
            .any(|c| c.recognizer().to_string() == "ctx:role-name"),
        "no role keyword => no fire even with the blank-line extension"
    );
}

// ===================================================================
// ROUND-3 recovery red-team: role-list continuation (A), heading-consumed
// two-column run (B), and address-block building-line sandwich (C). Byte-shapes
// replicate the real 62pp prospectus leaks with SYNTHETIC / public-shape values.
// ===================================================================

/// Any `ctx:role-name` candidate whose span CONTAINS `needle` (used where the matched run
/// may include extra tokens, e.g. a consumed heading word in the two-column layout).
fn role_name_span_contains(cands: &[RedactionCandidate], needle: &str) -> bool {
    cands.iter().any(|c| {
        c.recognizers()
            .iter()
            .any(|r| r.to_string() == "ctx:role-name")
            && c.matched_value().contains(needle)
    })
}

#[test]
fn role_name_list_continuation_captures_names_beyond_the_window() {
    // LEAK A: a role heading then a MULTI-name list. Before the fix only the first name(s)
    // within the fixed ±window fired; the CONTINUATION names (4th, 5th, …) survived. The
    // name-line reach now lets each name reach the heading across the run of preceding names.
    let e = role_name_engine();
    let text = "Directors of the Managers\n\
                Lee Wai Fai\n\
                Thio Boon Kiat\n\
                Edmund Leong Kok Mun\n\
                Goh Chin Kiat\n\
                Tan Ah Meng";
    let cands = e.candidates(text);
    for name in [
        "Lee Wai Fai",
        "Thio Boon Kiat",
        "Edmund Leong Kok Mun",
        "Goh Chin Kiat", // 4th — beyond the fixed window before the fix
        "Tan Ah Meng",   // 5th — beyond the fixed window before the fix
    ] {
        assert!(
            has_role_name(&cands, name),
            "continuation name {name:?} must be captured; got {cands:?}"
        );
    }
    // FP posture preserved: every continuation name is capped at CAREFUL review.
    let policy = ReviewPolicy::default();
    for c in cands
        .iter()
        .filter(|c| c.recognizer().to_string() == "ctx:role-name")
    {
        assert_eq!(policy.tier(c.confidence()), ReviewTier::CarefulReview);
    }
}

#[test]
fn role_name_continuation_is_bounded_and_prose_breaks_the_chain() {
    let e = role_name_engine();
    // BOUND: 8 names after the heading — the last (9th line, 8 name lines below the heading)
    // is beyond the 6-name reach, so it is NOT captured on that basis (the widening cannot
    // run away). The earlier names (within reach) still fire.
    let text = "Managers\n\
                Aaa Bbb Ccc\nDdd Eee Fff\nGgg Hhh Iii\nJjj Kkk Lll\n\
                Mmm Nnn Ooo\nPpp Qqq Rrr\nSss Ttt Uuu\nVvv Www Xxx";
    let cands = e.candidates(text);
    assert!(
        has_role_name(&cands, "Aaa Bbb Ccc"),
        "first name fires: {cands:?}"
    );
    assert!(
        !has_role_name(&cands, "Vvv Www Xxx"),
        "the 8th name is beyond the bounded reach and must NOT fire: {cands:?}"
    );

    // NEGATIVE: a heading followed by ORDINARY PROSE must not sweep the prose. The prose
    // lines are not name-shaped, so they break the reach chain; a capitalized run further
    // down never reaches the heading.
    let text2 = "Managers\n\
                 the board convened at the registered premises to review the matter\n\
                 and resolved unanimously to adopt the resolution as circulated to all\n\
                 Confidential Board Circular";
    let cands2 = e.candidates(text2);
    assert!(
        !role_name_span_contains(&cands2, "Confidential Board Circular"),
        "prose below a heading must not be swept into the role list: {cands2:?}"
    );
}

#[test]
fn role_name_two_column_heading_consumed_into_run_still_fires() {
    // LEAK B (root cause): a TWO-COLUMN layout puts the heading and the firm name on ONE
    // line, so the greedy capitalized-run scanner swallows the heading's `Managers` token as
    // the HEAD of the run (`Managers          Tan Peng Chin`). The window gate excludes the
    // matched span, so with no OTHER role keyword in-window the run was SUPPRESSED and the
    // name SURVIVED. Leading-span corroboration now fires it.
    let e = role_name_engine();
    let text = "Solicitors to the Managers          Tan Peng Chin LLC";
    let cands = e.candidates(text);
    assert!(
        role_name_span_contains(&cands, "Tan Peng Chin"),
        "the firm name after a same-line consumed heading must be captured; got {cands:?}"
    );
    // Still capped at CAREFUL review (leading-span corroboration never quick-confirms).
    let c = cands
        .iter()
        .find(|c| c.recognizer().to_string() == "ctx:role-name")
        .expect("a role-name candidate fires");
    assert_eq!(
        ReviewPolicy::default().tier(c.confidence()),
        ReviewTier::CarefulReview
    );

    // NEGATIVE: the SAME capitalized run with NO leading role keyword must NOT fire (the
    // corroboration is strictly a LEADING keyword, not "any capitalized run").
    let text2 = "In witness whereof          Tan Peng Chin LLC";
    assert!(
        !e.candidates(text2)
            .iter()
            .any(|c| c.recognizer().to_string() == "ctx:role-name"),
        "no leading role keyword => no fire: {:?}",
        e.candidates(text2)
    );
}

/// An engine with the address family (default built-ins ON) + the SG postal locale, matching
/// the prospectus fixture's address recognizers.
fn addr_sg_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .locales([Locale::Singapore])
        .build()
        .unwrap()
}

#[test]
fn address_block_captures_building_line_sandwiched_between_components() {
    // LEAK C: a building/tower name on its own line, SANDWICHED between redacted address
    // components (street above, postal below). It matches no address pattern, so it survived.
    let e = addr_sg_engine();

    // C-shape 1: office label opens the block; street + postal bracket the building line.
    let t1 = "Registered office:\n80 Raffles Place\nUOB Plaza\nSingapore 048624";
    assert!(
        address_covers(&e, t1, "UOB Plaza"),
        "sandwiched building name (label-opened block) must be captured: {:?}",
        e.candidates(t1)
    );

    // C-shape 2: street + unit above, a blank line + postal below (≤3-line window).
    let t2 = "50 Raffles Place\n#16-03\nCapital Tower\n \nSingapore 048623";
    assert!(
        address_covers(&e, t2, "Capital Tower"),
        "sandwiched building name across a blank line must be captured: {:?}",
        e.candidates(t2)
    );

    // Captured building lines route to CAREFUL review (Address is never quick-confirm).
    let policy = ReviewPolicy::default();
    for c in e
        .candidates(t2)
        .iter()
        .filter(|c| matches!(c.recognizer(), Recognizer::Address))
    {
        assert_eq!(policy.tier(c.confidence()), ReviewTier::CarefulReview);
    }
}

#[test]
fn address_block_continuation_negatives_do_not_over_capture() {
    let e = addr_sg_engine();

    // Two address candidates FAR APART (>3 lines) must NOT capture the proper-noun line
    // between them — only genuinely sandwiched (≤3-line-window) premises names are swept.
    let far = "80 Raffles Place\n\
               Confidential Strategic Overview\n\
               Some Other Heading Line\n\
               Another Unrelated Caption\n\
               More Filler Content Here\n\
               Singapore 048624";
    assert!(
        !address_covers(&e, far, "Confidential Strategic Overview"),
        "a proper-noun line between DISTANT address candidates must not be captured: {:?}",
        e.candidates(far)
    );

    // A lowercase PROSE line between two close address candidates must NOT be captured.
    let prose = "80 Raffles Place\nthe premises are located here\nSingapore 048624";
    assert!(
        !e.candidates(prose)
            .iter()
            .any(|c| text_of(&e, prose, c).contains("the premises")),
        "a lowercase prose line between address candidates must not be captured: {:?}",
        e.candidates(prose)
    );

    // With the address family OFF entirely, the pass is a no-op (no building-line capture).
    let off = RedactionEngine::builder()
        .builtins(BuiltinRecognizers::none())
        .build()
        .unwrap();
    assert!(
        off.candidates("80 Raffles Place\nUOB Plaza\nSingapore 048624")
            .is_empty(),
        "address family off => no continuation capture"
    );
}

#[test]
fn inline_building_name_between_address_anchors_wrapped_across_a_line_is_captured() {
    // LEAK C', the INLINE + LINE-WRAPPED variant the real prospectus exposed on page 18: a
    // building name embedded in a PROSE sentence and split across a PDF line wrap
    // (`… #33-01, Capital \nTower, Singapore …`) — it is NOT on its own line, it sits INLINE
    // between two ADJACENT address anchors (unit above, postal below). The own-line block
    // pass could not reach it; the inline pass does. Exactly the reconstructed shape the
    // stream-level `\n`-join produces (heading/prose line, then the wrapped continuation).
    let e = addr_sg_engine();
    let text = "Any Holder may inspect the Register at 168 Robinson Road #33-01, Capital \n\
                Tower, Singapore 068912 during normal business hours.";
    assert!(
        address_covers(&e, text, "Capital"),
        "inline line-wrapped building name `Capital Tower` must be captured: {:?}",
        e.candidates(text)
    );
    assert!(
        address_covers(&e, text, "Tower"),
        "the wrapped `Tower` half of the building name must be captured too: {:?}",
        e.candidates(text)
    );
}

#[test]
fn inline_building_pass_does_not_over_capture_prose_between_address_candidates() {
    let e = addr_sg_engine();
    // Lowercase prose words between two inline address candidates must NOT be swept: the
    // inline pass rejects any gap carrying a lowercase-initial (prose) token.
    let prose = "delivered to 168 Robinson Road and later mailed to Singapore 068912 today.";
    for needle in ["and later mailed to", "later", "mailed"] {
        assert!(
            !e.candidates(prose)
                .iter()
                .any(|c| text_of(&e, prose, c).contains(needle)),
            "prose `{needle}` between two address candidates must not be captured: {:?}",
            e.candidates(prose)
        );
    }
    // A gap wider than the inline bound is not swept even if capitalized-shaped, guarding
    // against a runaway sweep across a long capitalized-heavy span.
    let wide = "50 Raffles Place Then A Very Long Capitalised Caption Spanning Well Past \
                The Bound Here Singapore 048623";
    assert!(
        !address_covers(&e, wide, "Very Long Capitalised Caption"),
        "a capitalized run past the inline gap bound must not be captured: {:?}",
        e.candidates(wide)
    );
}

/// The cleartext a candidate covers (test-only convenience).
fn text_of(_e: &RedactionEngine, text: &str, c: &RedactionCandidate) -> String {
    text[c.start()..c.end()].to_string()
}

// ===================================================================
// MECHANISM A — detected-name PROPAGATION  +  MECHANISM B — trailing-role name list
// ===================================================================

/// An engine with role-name context on AND the global built-ins on (the shipped `{"context":
/// true}` shape) — Mechanisms A + B both active. Every value here is FABRICATED.
fn propagation_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .context_recognizers(ContextRecognizers::all())
        .build()
        .unwrap()
}

/// Does ANY candidate cover EXACTLY `value` (exact-span match on the cleartext)?
fn covers_exact(cands: &[RedactionCandidate], value: &str) -> bool {
    cands.iter().any(|c| c.matched_value() == value)
}

/// Does ANY candidate's span CONTAIN `needle` as a substring of its cleartext?
fn some_candidate_contains(cands: &[RedactionCandidate], needle: &str) -> bool {
    cands.iter().any(|c| c.matched_value().contains(needle))
}

// ---- direct unit checks on the seed predicate (Mechanism A seeds `Name` ONLY) ----

#[test]
fn propagation_seeds_only_person_name_kinds() {
    use std::sync::Arc;
    // ONLY the `Name` kind seeds (review fix 1); ids / amounts / ctx rows / emails do NOT.
    assert!(is_person_name_kind(&Recognizer::Name));
    // UPDATED for the review fix: `ctx:role-name` no longer seeds — its FP class is role
    // boilerplate ("Investment Manager" ×311 on the flagship prospectus), which propagation
    // amplified document-wide. It still FLAGS at its own site (see the boilerplate test).
    assert!(!is_person_name_kind(&Recognizer::Context(Arc::from(
        "ctx:role-name"
    ))));
    assert!(!is_person_name_kind(&Recognizer::Context(Arc::from(
        "ctx:dob"
    ))));
    assert!(!is_person_name_kind(&Recognizer::Context(Arc::from(
        "ctx:account-mrn"
    ))));
    assert!(!is_person_name_kind(&Recognizer::Email));
    assert!(!is_person_name_kind(&Recognizer::Id));
    assert!(!is_person_name_kind(&Recognizer::Term));
    // The propagated label is deliberately NOT a name kind (so it never re-seeds — ONE round).
    assert!(!is_person_name_kind(&Recognizer::Custom(Arc::from(
        "name:propagated"
    ))));
}

// ---- MECHANISM A ----
//
// UPDATED for review fix 1 (Name-only seeding): the original versions of the first two
// tests below seeded propagation from a ctx:role-name HEADING detection — the exact seed
// path the fix removes (its FP class is boilerplate, amplified document-wide). The tests
// now seed from `Recognizer::Name` sources (a Mechanism-B trailing-role list / an
// honorific mention), which is how every real person name in the fixtures actually seeds.
// The distant occurrence is WRAPPED across a line break in these tests, because a
// space-identical re-occurrence is already covered by the always-on SAFE tier (as a plain
// `Name` candidate) — the `name:propagated` id surfaces where ONLY the elastic matcher
// reaches.

#[test]
fn mechanism_a_detected_name_propagates_to_a_distant_wrapped_occurrence() {
    // A trailing-role list detects "Joanne Fitzgerald" (Mechanism B → Recognizer::Name). A
    // DISTANT occurrence wrapped across a line break (no role keyword, no employment phrase,
    // missed by the exact SAFE tier because of the newline) must be re-flagged by
    // propagation, carrying the `name:propagated` recognizer id.
    let e = propagation_engine();
    let text = "Svetlana Butvina and Joanne Fitzgerald are employees of the Group.\n\nlots \
                of unrelated filler prose goes on here for a while so the occurrence below \
                is far outside any context window at all, then please contact Joanne\n\
                Fitzgerald for further details today.";
    let cands = e.candidates(text);
    // The list occurrence is a candidate (Mechanism B, Recognizer::Name).
    assert!(
        has_exact_name(&cands, "Joanne Fitzgerald"),
        "list name detected via the trailing-role pass, got {cands:?}"
    );
    // The distant wrapped occurrence is ALSO a candidate, tagged propagated.
    assert!(
        cands.iter().any(|c| {
            c.recognizer().to_string() == "name:propagated"
                && c.matched_value() == "Joanne\nFitzgerald"
        }),
        "distant wrapped 'Joanne Fitzgerald' propagated with the name:propagated id, got {cands:?}"
    );
}

#[test]
fn mechanism_a_seed_is_honorific_stripped() {
    // An honorific mention ("Ms. Joanne Fitzgerald") seeds the BARE name part, so a distant
    // wrapped bare occurrence (which never carries the honorific) still propagates. Without
    // the strip, the seed value would self-match only.
    let e = propagation_engine();
    let text = "We met Ms. Joanne Fitzgerald at the closing.\n\nfiller prose that is long \
                enough to be far outside any context window here, then a wrapped mention of \
                Joanne\nFitzgerald at a line boundary.";
    let cands = e.candidates(text);
    assert!(
        cands.iter().any(|c| {
            c.recognizer().to_string() == "name:propagated"
                && c.matched_value() == "Joanne\nFitzgerald"
        }),
        "honorific-stripped seed catches the wrapped bare occurrence, got {cands:?}"
    );
}

#[test]
fn ctx_role_name_boilerplate_does_not_propagate_but_a_name_detected_person_does() {
    // REVIEW FIX 1 regression: `ctx:role-name` BOILERPLATE ("Management Company" under a
    // role heading — the flagship-prospectus FP class) is flagged AT ITS OWN SITE but does
    // NOT propagate to its other occurrences; a Name-detected PERSON in the same text DOES
    // propagate.
    let e = propagation_engine();
    let text = "Directors\nManagement Company\n\nSvetlana Butvina and Joanne Fitzgerald are \
                employees of the Group.\n\nfiller prose long enough to leave every context \
                window far behind for what follows below, then a wrapped mention of Joanne\n\
                Fitzgerald appears here while Management Company appears again and once more \
                Management Company closes the sentence.";
    let cands = e.candidates(text);
    // The boilerplate IS flagged at its role-anchored site (unchanged behavior)...
    assert!(
        has_role_name(&cands, "Management Company"),
        "boilerplate still flagged at its own ctx:role-name site, got {cands:?}"
    );
    // ...but it does NOT propagate — no name:propagated copy of it anywhere.
    assert!(
        !cands.iter().any(|c| {
            c.recognizer().to_string() == "name:propagated"
                && c.matched_value().contains("Management")
        }),
        "ctx:role-name boilerplate must not propagate, got {cands:?}"
    );
    // While the Name-detected person's wrapped occurrence DOES propagate.
    assert!(
        cands.iter().any(|c| {
            c.recognizer().to_string() == "name:propagated"
                && c.matched_value() == "Joanne\nFitzgerald"
        }),
        "the Name-detected person still propagates, got {cands:?}"
    );
}

#[test]
fn mechanism_a_does_not_propagate_non_name_kinds() {
    // An email + an id repeat in the doc, but neither is a NAME kind, so propagation emits
    // NO name:propagated candidate for them. (They are single-token anyway; this asserts the
    // seed filter's intent end-to-end.)
    let e = propagation_engine();
    let text = "Ref AB1234 to john.doe@acme.example. Again AB1234 and john.doe@acme.example.";
    let cands = e.candidates(text);
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == "name:propagated"),
        "no propagation from non-name kinds, got {cands:?}"
    );
}

#[test]
fn mechanism_a_short_name_value_is_not_propagated() {
    // A 2-word but < 8-char detected name part ("Li Na", 5 chars — seeded via an honorific
    // mention, stripped to the part) is BELOW the propagation floor, so a distant wrapped
    // occurrence is NOT re-flagged. (The floor drops single-token / very-short parts; it is
    // NOT the boilerplate filter — that is the Name-only seed predicate. Review fix 3.)
    let e = propagation_engine();
    let text = "We met Ms. Li Na at the closing.\n\nfiller prose long enough to be well past \
                any context window at all, then a distant wrapped mention of Li\nNa appears.";
    let cands = e.candidates(text);
    // No propagated candidate for the short name part.
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == "name:propagated"),
        "short (< 8 char) name part must not propagate, got {cands:?}"
    );
}

#[test]
fn mechanism_a_no_self_or_overlap_duplicates() {
    // The seed occurrence itself must NOT be re-emitted as a propagated duplicate, an
    // exact re-occurrence already covered by the SAFE tier must not be double-reported, and
    // the final span set stays non-overlapping (a redact_detail invariant).
    let e = propagation_engine();
    let text = "Svetlana Butvina and Joanne Fitzgerald are employees of the Group.\n\nfiller \
                prose that is long enough to sit far outside any window, then contact \
                Joanne Fitzgerald for details, or wrapped: Joanne\nFitzgerald again.";
    let cands = e.candidates(text);
    // Exactly ONE propagated candidate: the WRAPPED occurrence. The exact re-occurrence is
    // covered by the SAFE tier (a plain Name candidate), so propagation must not double-
    // report it; the seed spans themselves are never re-emitted.
    let propagated: Vec<_> = cands
        .iter()
        .filter(|c| c.recognizer().to_string() == "name:propagated")
        .collect();
    assert_eq!(
        propagated.len(),
        1,
        "exactly one propagated occurrence (the wrapped one), got {cands:?}"
    );
    assert_eq!(propagated[0].matched_value(), "Joanne\nFitzgerald");
    // The exact re-occurrence IS covered — by the SAFE tier, not by propagation.
    assert!(
        has_exact_name(&cands, "Joanne Fitzgerald"),
        "exact re-occurrence covered by the SAFE tier, got {cands:?}"
    );
    // Non-overlapping + start-sorted (redact_detail relies on this).
    let mut last_end = 0usize;
    for c in &cands {
        assert!(
            c.start() >= last_end,
            "spans must be non-overlapping + sorted, got {cands:?}"
        );
        last_end = c.end();
    }
}

#[test]
fn mechanism_a_total_candidate_cap_bounds_a_bomb() {
    // BOMB 1: ONE detected name (seeded via a Mechanism-B list — Name-only seeding, review
    // fix 1) with far more WRAPPED occurrences than the total-candidate cap (wrapped so the
    // exact SAFE tier does not pre-cover them and every one reaches the propagation pass).
    // Propagation must TRUNCATE at MAX_PROPAGATED_CANDIDATES and complete promptly.
    let e = propagation_engine();
    let mut text =
        String::from("Alice Kingsleigh and Joanne Fitzgerald are employees of the Group.\n\n");
    for _ in 0..(MAX_PROPAGATED_CANDIDATES + 1_000) {
        text.push_str("x Joanne\nFitzgerald y. ");
    }
    let cands = e.candidates(&text);
    let propagated = cands
        .iter()
        .filter(|c| c.recognizer().to_string() == "name:propagated")
        .count();
    assert!(
        propagated <= MAX_PROPAGATED_CANDIDATES,
        "total propagated candidates capped, got {propagated}"
    );
    assert!(
        propagated > 0,
        "some propagation still happened, got {propagated}"
    );
}

#[test]
fn mechanism_a_distinct_value_cap_bounds_a_bomb() {
    // BOMB 2: many DISTINCT honorific-detected names (Name-only seeding, review fix 1),
    // each with ONE distant WRAPPED occurrence (wrapped so the exact SAFE tier misses it and
    // only propagation could flag it). Only MAX_PROPAGATED_VALUES distinct values may seed,
    // so not all of the > cap distinct names propagate.
    let e = propagation_engine();
    let n = MAX_PROPAGATED_VALUES + 100;
    // ALPHA-only distinct names (a digit would break the name-token shape).
    let name_of = |i: usize| format!("Xy{} Surnameee", entity_letters(i));
    let mut text = String::new();
    for i in 0..n {
        // Each distinct honorific mention (part "Xy<letters> Surnameee", >= 2 words, >= 8 chars).
        text.push_str(&format!("Mr {} attended.\n", name_of(i)));
    }
    // A far-away appendix of WRAPPED re-occurrences of every one of those names.
    text.push_str("\nappendix of mentions:\n");
    for i in 0..n {
        text.push_str(&format!("{}\n", name_of(i).replace(' ', "\n")));
    }
    let cands = e.candidates(&text);
    let propagated = cands
        .iter()
        .filter(|c| c.recognizer().to_string() == "name:propagated")
        .count();
    // At most MAX_PROPAGATED_VALUES distinct names contribute a propagated wrapped span.
    assert!(
        propagated <= MAX_PROPAGATED_VALUES,
        "distinct-value seed cap bounds propagation, got {propagated}"
    );
    assert!(
        propagated > 0,
        "some distinct names still propagate, got {propagated}"
    );
}

#[test]
fn mechanism_b_emission_cap_bounds_a_pathological_list() {
    // REVIEW FIX 2: a pathological 1000-name comma list before one role phrase emits AT
    // MOST MAX_TRAILING_ROLE_NAMES Name spans (the bomb-bound) — and the scan completes
    // fast (pre-cap, 10k names measured 6.3s / 20k 24.9s through the downstream gate).
    let e = propagation_engine();
    let n = 1_000usize;
    let name_of = |i: usize| format!("Qw{} Zxsurname", entity_letters(i));
    let mut list = String::new();
    for i in 0..n {
        if i > 0 {
            list.push_str(if i == n - 1 { " and " } else { ", " });
        }
        list.push_str(&name_of(i));
    }
    let text = format!("{list} are employees of the Group.");
    let cands = e.candidates(&text);
    let name_count = cands
        .iter()
        .filter(|c| c.recognizer() == &Recognizer::Name)
        .count();
    assert!(
        name_count <= MAX_TRAILING_ROLE_NAMES,
        "trailing-role emissions capped, got {name_count}"
    );
    assert!(
        name_count > 0,
        "the pass still emitted up to the cap, got {name_count}"
    );
}

// ---- MECHANISM B ----

#[test]
fn mechanism_b_motivating_sentence_flags_all_five_names() {
    // The EXACT motivating sentence shape: a 2+ comma/'and' list of Capitalized multi-word
    // names immediately preceding "are employees of". All five names are flagged.
    let e = propagation_engine();
    let text = "Svetlana Butvina, Joanne Fitzgerald, Richard Gardner, Benjamin Gregson and \
                Leon Schwab are employees of the BlackRock Group and its affiliates.";
    let cands = e.candidates(text);
    for name in [
        "Svetlana Butvina",
        "Joanne Fitzgerald",
        "Richard Gardner",
        "Benjamin Gregson",
        "Leon Schwab",
    ] {
        assert!(
            covers_exact(&cands, name),
            "trailing-role list name `{name}` flagged, got {cands:?}"
        );
    }
}

#[test]
fn mechanism_b_phrase_wrapped_across_a_line_break_still_flags_all_names() {
    // REGRESSION (live re-probe): the REAL fixture's OCR text wraps MID-PHRASE — the line
    // break falls inside "are employees of" ("are employees\nof the BlackRock Group").
    // Every gap of the sentence shape (incl. phrase-internal spaces) tolerates one line
    // break, so all names are still flagged.
    let e = propagation_engine();
    let text = "Svetlana Butvina, Joanne Fitzgerald and Leon Schwab are employees\nof the \
                BlackRock Group.";
    let cands = e.candidates(text);
    for name in ["Svetlana Butvina", "Joanne Fitzgerald", "Leon Schwab"] {
        assert!(
            covers_exact(&cands, name),
            "phrase-wrap: list name `{name}` flagged, got {cands:?}"
        );
    }
}

#[test]
fn mechanism_b_list_wrapped_across_a_line_break_still_flags_all_names() {
    // REGRESSION (live re-probe): the wrap falls INSIDE the name list, after a comma
    // ("Joanne Fitzgerald,\nRichard Gardner …"). The names BEFORE the newline must not be
    // lost — a single intra-sentence wrap is ordinary whitespace in the list separator too.
    let e = propagation_engine();
    let text = "Svetlana Butvina, Joanne Fitzgerald,\nRichard Gardner and Leon Schwab are \
                employees of the BlackRock Group.";
    let cands = e.candidates(text);
    for name in [
        "Svetlana Butvina",
        "Joanne Fitzgerald",
        "Richard Gardner",
        "Leon Schwab",
    ] {
        assert!(
            covers_exact(&cands, name),
            "list-wrap: list name `{name}` flagged, got {cands:?}"
        );
    }
}

#[test]
fn mechanism_b_blank_line_is_a_paragraph_bound_not_a_wrap() {
    // The wrap tolerance is BOUNDED at one line break per gap: a BLANK line (two consecutive
    // newlines = a paragraph break) is NOT crossed, so a name LIST in a PRECEDING paragraph
    // is not swept into a next-paragraph role phrase.
    let e = propagation_engine();
    let text = "Alice Wonderman and Bob Charleston\n\nare employees of the Group in this \
                later sentence.";
    let cands = e.candidates(text);
    assert!(
        !some_candidate_contains(&cands, "Wonderman")
            && !some_candidate_contains(&cands, "Charleston"),
        "a blank line stops the trailing-role shape, got {cands:?}"
    );
}

#[test]
fn mechanism_b_negative_lowercase_run_is_not_a_person_name() {
    // "The prices are members of the set" — "The prices" is NOT a Capitalized multi-word name
    // (lowercase "prices"), so the trailing-role pass captures nothing.
    let e = propagation_engine();
    let text = "The prices are members of the set of all valid quoted numbers.";
    let cands = e.candidates(text);
    assert!(
        !some_candidate_contains(&cands, "prices"),
        "a lowercase run before a role phrase is not a person name, got {cands:?}"
    );
}

#[test]
fn mechanism_b_off_without_context_optin() {
    // The trailing-role pass is gated on the role-name opt-in: a default engine (context off)
    // does not flag the list names.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Svetlana Butvina and Joanne Fitzgerald are employees of the Group.";
    let cands = e.candidates(text);
    assert!(
        !covers_exact(&cands, "Svetlana Butvina"),
        "trailing-role list is off without the context opt-in, got {cands:?}"
    );
}

// ---- MOTIVATING CASE, END TO END (A + B together) ----

#[test]
fn motivating_case_every_name_covered_at_every_occurrence() {
    // A heading paragraph for ONE name (role-anchored + honorific bio), plus a prose list
    // that contains that name and TWO others before an employment phrase. Every name value
    // must be covered at EVERY occurrence: the heading name via role-name, the list names via
    // Mechanism B, and the heading name's list occurrence via B and/or A propagation.
    let e = propagation_engine();
    let text = "Directors\nJoanne Fitzgerald\nMs. Fitzgerald is a Director of the Manager.\n\n\
                The investment team: Svetlana Butvina, Joanne Fitzgerald and Richard Gardner \
                are employees of the BlackRock Group.";
    let cands = e.candidates(text);

    // Heading occurrence of the shared name.
    assert!(
        has_role_name(&cands, "Joanne Fitzgerald"),
        "heading name via role-name, got {cands:?}"
    );
    // Every name appears (covered) somewhere in the prose list.
    for name in ["Svetlana Butvina", "Joanne Fitzgerald", "Richard Gardner"] {
        assert!(
            covers_exact(&cands, name),
            "prose-list name `{name}` covered, got {cands:?}"
        );
    }
    // And CRUCIALLY: after an apply, the shared name is gone from BOTH occurrences (the leak
    // the mechanisms close — detected once at the heading, no longer readable in the prose).
    let (redacted, _n) = e.redact_text(text);
    assert!(
        !redacted.contains("Joanne Fitzgerald"),
        "no occurrence of the shared name survives the apply, got: {redacted:?}"
    );
    // The two list-only names are removed too.
    assert!(
        !redacted.contains("Svetlana Butvina") && !redacted.contains("Richard Gardner"),
        "list-only names removed, got: {redacted:?}"
    );
}

// ===================================================================
// WRAPPED-NAME round — Mechanism A (bounded wrap tolerance), B (display name beside a
// detected email), C (name before a parenthesized detected structured id)
// ===================================================================

// ---- Mechanism A: honorific single-wrap tolerance (bounded) ----

#[test]
fn honorific_name_wrapped_mid_name_is_detected() {
    // A document wraps a name mid-sentence: `Ms. Marlow\nVarga`. The honorific run now
    // tolerates AT MOST ONE line break in the whole match, so the wrapped name is one
    // Name candidate. The unwrapped control stays exact.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("We wrote to Ms. Marlow\nVarga about the matter.");
    assert!(
        cands.iter().any(
            |c| c.recognizer() == &Recognizer::Name && c.matched_value() == "Ms. Marlow\nVarga"
        ),
        "wrapped honorific name detected as one candidate, got {cands:?}"
    );
    let cands2 = e.candidates("We wrote to Ms. Marlow Varga about the matter.");
    assert!(
        has_exact_name(&cands2, "Ms. Marlow Varga"),
        "unwrapped control unchanged, got {cands2:?}"
    );
}

#[test]
fn honorific_signature_block_detected_with_documented_one_token_overflag() {
    // The motivating letter-signature shape (probe 1, verbatim). The single-wrap arm
    // greedily absorbs ONE line-leading Capitalized word after the wrap (`Kestrel`) — the
    // DOCUMENTED over-flag (safe side; a miss is the leak). The load-bearing assertion is
    // that the person's name is covered; the absorbed extra token is asserted honestly.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Yours faithfully,\nMs. Marlow Varga\nKestrel & Lowe LLP";
    let cands = e.candidates(text);
    assert!(
        cands
            .iter()
            .any(|c| c.recognizer() == &Recognizer::Name
                && c.matched_value().contains("Marlow Varga")),
        "the signature name is covered, got {cands:?}"
    );
    // The span crosses at most ONE newline (the PDF sanction bound).
    for c in &cands {
        assert!(
            c.matched_value().bytes().filter(|&b| b == b'\n').count() <= 1,
            "a name span never crosses more than one newline, got {cands:?}"
        );
    }
}

#[test]
fn honorific_blank_line_is_a_paragraph_bound() {
    // BOUNDED: a BLANK line (two consecutive newlines) is never crossed — `Varga` in the
    // next paragraph is NOT joined to the honorific (the former `\s+` gap DID cross it).
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("signed by Ms. Marlow\n\nVarga Holdings later filed.");
    assert!(
        !cands.iter().any(|c| c.matched_value().contains("Varga")),
        "a blank line stops the honorific run, got {cands:?}"
    );
}

// ---- Mechanism A: trailing-role relative-clause tail + wrapped list name ----

#[test]
fn trailing_role_relative_clause_and_wrapped_list_name() {
    // Probe 2, verbatim: the list is separated from the phrase by `, who` and the FIRST
    // name is wrapped mid-name (`Idris\nBeaumond`). All three names must be flagged.
    let e = propagation_engine();
    let text = "The committee comprises Idris\nBeaumond, Cerys Corrigan and Delia Vantol, \
                who are members of the fund board.";
    let cands = e.candidates(text);
    for name in ["Idris\nBeaumond", "Cerys Corrigan", "Delia Vantol"] {
        assert!(
            covers_exact(&cands, name),
            "list name {name:?} flagged through the relative clause, got {cands:?}"
        );
    }
}

// ---- Mechanism B: display name beside a DETECTED email ----

#[test]
fn display_name_before_detected_email_is_flagged() {
    // Probe 3, verbatim. The email recognizer detects the address; the Capitalized run
    // flush before `<` is the person, emitted as a Name candidate. Default engine — the
    // anchor is the DETECTED email, no context opt-in needed.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("From: Delia Corrigan <delia.corrigan@meridian.example>");
    assert!(
        has_exact_name(&cands, "Delia Corrigan"),
        "display name flagged beside the detected email, got {cands:?}"
    );
}

#[test]
fn display_name_wrapped_and_quoted_forms_are_flagged() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // Wrapped display name (the shared wrapped-name run tolerates one break per gap).
    let cands = e.candidates("From: Delia\nCorrigan <delia.corrigan@meridian.example>");
    assert!(
        has_exact_name(&cands, "Delia\nCorrigan"),
        "wrapped display name flagged, got {cands:?}"
    );
    // Quoted display-name form: the closing quote between name and `<` is junk-tolerated.
    let cands2 = e.candidates("From: \"Delia Corrigan\" <delia.corrigan@meridian.example>");
    assert!(
        has_exact_name(&cands2, "Delia Corrigan"),
        "quoted display name flagged, got {cands2:?}"
    );
}

#[test]
fn lowercase_run_before_email_is_not_a_display_name() {
    // NEGATIVE: a lowercase run before `<email>` is not a person name — nothing emitted.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("From: the sender <box@meridian.example>");
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "a lowercase run before an email must not emit a Name, got {cands:?}"
    );
    // And an UN-bracketed email has no anchor at all.
    let cands2 = e.candidates("Reach Delia Corrigan at delia.corrigan@meridian.example");
    assert!(
        !has_exact_name(&cands2, "Delia Corrigan"),
        "no `<` anchor => no anchored display name (propagation/terms cover prose), got {cands2:?}"
    );
}

#[test]
fn anchored_display_name_seeds_propagation() {
    // A display name emitted by the anchored pass is a Name candidate, so it SEEDS the
    // detected-name propagation pass: a distant WRAPPED prose re-mention is covered too.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "From: Delia Corrigan <delia.corrigan@meridian.example>\n\nlong filler prose \
                that pushes the next mention far away from everything above it here, then \
                please ask Delia\nCorrigan directly.";
    let cands = e.candidates(text);
    assert!(
        cands.iter().any(|c| {
            c.recognizer().to_string() == "name:propagated"
                && c.matched_value() == "Delia\nCorrigan"
        }),
        "the anchored display name seeds propagation to the wrapped re-mention, got {cands:?}"
    );
}

// ---- Mechanism C: name before a parenthesized DETECTED structured id ----

#[test]
fn name_before_parenthesized_nric_is_flagged() {
    // Probe 4, verbatim: the NRIC is detected (sg locale); the Capitalized run flush
    // before `(NRIC …)` is the person, emitted as a Name candidate. (`sg_engine` is the
    // crate-wide SG-locale test engine defined earlier in this module.)
    let e = sg_engine();
    let cands = e.candidates("(2) Delia Quorley (NRIC S7034236G) of 101 Marlow Place");
    assert!(
        has_exact_name(&cands, "Delia Quorley"),
        "name before the parenthesized detected NRIC flagged, got {cands:?}"
    );
}

#[test]
fn paren_id_anchor_negatives() {
    let e = sg_engine();
    // No preceding Capitalized run (the paren opens the text) => nothing emitted.
    let cands = e.candidates("(NRIC S7034236G) applies to the second applicant.");
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "no preceding run => no anchored name, got {cands:?}"
    );
    // A broad-`id` BUILTIN in parens is NOT an anchor (only a locale national-ID row
    // corroborates precision) — the project codename before it is not emitted.
    let cands2 = e.candidates("filed under Project Alpha (REF-12345) yesterday.");
    assert!(
        !cands2.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "a builtin id match is not a paren anchor, got {cands2:?}"
    );
    // A LOCALE POSTAL row is excluded from anchoring (a postal code is not a personal
    // identifier anchor).
    let cands3 = e.candidates("sent to Delia Quorley (Singapore 018989) by post.");
    assert!(
        !cands3.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "a postal row is not a paren anchor, got {cands3:?}"
    );
}

#[test]
fn anchored_names_cap_bounds_a_bomb() {
    // BOMB: far more `<email>` anchors (each with a distinct display name) than the cap.
    // The anchored pass must truncate at MAX_ANCHORED_NAMES and complete promptly.
    let e = RedactionEngine::new(Vec::<String>::new());
    let n = MAX_ANCHORED_NAMES + 100;
    let mut text = String::new();
    for i in 0..n {
        text.push_str(&format!(
            "Xy{} Qsurname <user{i}@meridian.example>\n",
            entity_letters(i)
        ));
    }
    let cands = e.candidates(&text);
    let names = cands
        .iter()
        .filter(|c| c.recognizer() == &Recognizer::Name)
        .count();
    assert!(
        names <= MAX_ANCHORED_NAMES,
        "anchored-name emissions capped, got {names}"
    );
    assert!(
        names > 0,
        "the pass still emitted up to the cap, got {names}"
    );
}

// ===================================================================
// ROUND 3 — M1 interior initials · M2 ctx wrapped phone · M3 RCS Luxembourg ·
// M4 header-anchored vertical name lists
// ===================================================================

// ---- M1: interior single-letter initials in person-name runs ----

#[test]
fn m1_interior_initial_name_is_caught_alongside_its_sibling() {
    // Verbatim motivating shape: 'Mark McLaughlin' was caught (ctx:role-name), while
    // 'John W. Thompson' was MISSED — the interior initial broke the token run.
    let e = propagation_engine();
    let text = "** John W. Thompson, Lead Independent Director, and Mark McLaughlin, \
                Director of the company.";
    let cands = e.candidates(text);
    for name in ["John W. Thompson", "Mark McLaughlin"] {
        assert!(
            covers_exact(&cands, name),
            "{name:?} flagged (interior-initial token shape), got {cands:?}"
        );
    }
}

#[test]
fn m1_leading_initials_and_honorific_forms_do_not_regress() {
    // Leading initials ('J. R. Surname') and the plain honorific forms must keep working.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("We met Mr. J. R. Surname and Dr. Tan Wei Ming today.");
    assert!(
        cands.iter().any(
            |c| c.recognizer() == &Recognizer::Name && c.matched_value() == "Mr. J. R. Surname"
        ),
        "leading initials under an honorific, got {cands:?}"
    );
    assert!(
        has_exact_name(&cands, "Dr. Tan Wei Ming"),
        "plain honorific run unchanged, got {cands:?}"
    );
    // An honorific name with an interior initial is one whole candidate.
    let cands2 = e.candidates("signed by Ms. Ada B. Quorley yesterday");
    assert!(
        has_exact_name(&cands2, "Ms. Ada B. Quorley"),
        "interior initial inside an honorific run, got {cands2:?}"
    );
    // A sentence dot after a full word still ends the run (no absorb across sentences).
    let cands3 = e.candidates("per Mr Smith. The Report followed.");
    assert!(
        has_exact_name(&cands3, "Mr Smith"),
        "a word token never takes the sentence dot, got {cands3:?}"
    );
}

#[test]
fn m1_trailing_role_list_accepts_interior_initials_including_wrapped() {
    let e = propagation_engine();
    // Unwrapped + interior initial in a trailing-role list.
    let cands = e.candidates("John W. Thompson and Cerys Corrigan are employees of the Group.");
    assert!(
        covers_exact(&cands, "John W. Thompson"),
        "interior-initial name in a trailing-role list, got {cands:?}"
    );
    // Wrapped across the initial's gap.
    let cands2 = e.candidates("John W.\nThompson and Cerys Corrigan are employees of the Group.");
    assert!(
        covers_exact(&cands2, "John W.\nThompson"),
        "wrapped interior-initial name in a trailing-role list, got {cands2:?}"
    );
}

// ---- M2: ctx-gated wrap-split phone ----

/// Does any candidate covering `needle` carry the `ctx:phone-wrapped` recognizer
/// (primary OR co-recognizer)?
fn phone_wrapped_covers(cands: &[RedactionCandidate], needle: &str) -> bool {
    cands.iter().any(|c| {
        c.matched_value().contains(needle)
            && c.recognizers()
                .iter()
                .any(|r| r.to_string() == "ctx:phone-wrapped")
    })
}

#[test]
fn m2_wrapped_phone_near_telecom_keyword_carries_the_ctx_row() {
    // Verbatim motivating shape: the number wrapped across a line break, a telecom
    // keyword before it. The ctx row corroborates (and is what sanctions the span in the
    // PDF path); the general phone recognizer stays primary on the merged span.
    let e = propagation_engine();
    let cands = e.candidates("For information enquiries: 0800\n917 2112.");
    assert!(
        phone_wrapped_covers(&cands, "0800"),
        "wrapped phone corroborated by ctx:phone-wrapped, got {cands:?}"
    );
}

#[test]
fn m2_nav_column_without_keyword_never_carries_the_ctx_row() {
    // The HIGH-1 negative: a NAV numeric column with NO telecom keyword. HONEST NOTE:
    // the TEXT path's general phone recognizer has always matched this cross-line shape
    // (its `\s` class spans `\n`; the HIGH-1 flood was the PDF path, where the line-scope
    // filter drops it). The load-bearing assertion is that the ctx row does NOT
    // corroborate — so the PDF path keeps dropping it (see the pdf test).
    let e = propagation_engine();
    let cands = e.candidates("NAV table\n145.90\n12 3456\nmore figures");
    assert!(
        !phone_wrapped_covers(&cands, "145"),
        "no telecom keyword => the ctx row never corroborates, got {cands:?}"
    );
    // Default engine (context off): the row contributes nothing at all.
    let e2 = RedactionEngine::new(Vec::<String>::new());
    let cands2 = e2.candidates("enquiries: 0800\n917 2112.");
    assert!(
        !phone_wrapped_covers(&cands2, "0800"),
        "ctx rows are opt-in; default engine carries no ctx:phone-wrapped, got {cands2:?}"
    );
}

// ---- M3: Luxembourg RCS company-register numbers ----

fn rcs_covers(cands: &[RedactionCandidate], needle: &str) -> bool {
    cands.iter().any(|c| {
        c.matched_value().contains(needle)
            && c.recognizers().iter().any(|r| r.to_string() == "lu:rcs")
    })
}

#[test]
fn m3_rcs_luxembourg_forms_are_caught() {
    // GLOBAL (no locale opt-in): the literal `R.C.S.` anchor is self-identifying.
    let e = RedactionEngine::new(Vec::<String>::new());
    // The verbatim motivating form, on its own line.
    let cands = e.candidates("BlackRock Global Funds\nR.C.S. Luxembourg B.6317\noffice");
    assert!(
        rcs_covers(&cands, "B.6317"),
        "R.C.S. Luxembourg B.6317 caught, got {cands:?}"
    );
    // Wrapped across the register-name gap (<= 1 line break).
    let cands2 = e.candidates("registered as R.C.S. Luxembourg\nB.6317 in the register");
    assert!(
        rcs_covers(&cands2, "B.6317"),
        "wrapped RCS form caught, got {cands2:?}"
    );
    // No-Luxembourg + space-digit forms.
    let cands3 = e.candidates("entered under R.C.S. B 123456 accordingly");
    assert!(
        rcs_covers(&cands3, "B 123456"),
        "R.C.S. B 123456 caught, got {cands3:?}"
    );
}

#[test]
fn m3_bare_b_number_needs_the_rcs_anchor_in_window() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // Bare `B 123456` WITH `R.C.S` in the short preceding window: caught.
    let cands = e.candidates("registered with the R.C.S. Luxembourg under number B 123456 today");
    assert!(
        rcs_covers(&cands, "B 123456"),
        "anchored bare-B form caught, got {cands:?}"
    );
    // Bare `B 123456` with NO anchor anywhere: never a candidate.
    let cands2 = e.candidates("compartment B 123456 of the warehouse holds the files");
    assert!(
        !rcs_covers(&cands2, "123456"),
        "bare B-number without the R.C.S anchor is not flagged, got {cands2:?}"
    );
}

// ---- M4: header-anchored vertical name lists ----

#[test]
fn m4_officer_column_names_are_all_flagged() {
    // The verbatim motivating layout (fictionalized): a role header, then a bare COLUMN
    // of 12 names — no honorifics, no inline roles, no bios. Every line's name must be a
    // candidate. Includes 1.5-spacing (single blank lines) mid-list.
    let e = propagation_engine();
    let names = [
        "Ada Quorley",
        "Ben Vantol",
        "Cerys Marlow",
        "Delia Beaumond",
        "Evan Corrigan",
        "Finn Gardner",
        "Gwen Holloway",
        "Hugh Kestrel",
        "Iris Lowther",
        "John W. Thompson",
        "Kara Mansfield",
        "Liam Norwood",
    ];
    let text = format!(
        "CONDUCTING OFFICERS\n{}\n\nThe rest is prose.",
        names.join("\n\n")
    );
    let cands = e.candidates(&text);
    for name in names {
        assert!(
            covers_exact(&cands, name),
            "officer-column name {name:?} flagged, got {cands:?}"
        );
    }
}

#[test]
fn m4_header_followed_by_prose_emits_nothing() {
    let e = propagation_engine();
    let text = "DIRECTORS\nThe directors of the company accept responsibility for the \
                information contained in this document and confirm it is accurate.";
    let cands = e.candidates(text);
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "a header followed by prose emits no header-list names, got {cands:?}"
    );
}

#[test]
fn m4_all_caps_org_line_is_skipped_not_absorbed_and_list_continues() {
    let e = propagation_engine();
    let text =
        "CONDUCTING OFFICERS\nAda Quorley\nBLACKROCK (LUXEMBOURG) S.A.\nBen Vantol\nprose ends it.";
    let cands = e.candidates(text);
    assert!(
        covers_exact(&cands, "Ada Quorley") && covers_exact(&cands, "Ben Vantol"),
        "names on either side of the ALL-CAPS org line flagged, got {cands:?}"
    );
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer() == &Recognizer::Name
                && c.matched_value().contains("BLACKROCK")),
        "the ALL-CAPS org line is skipped, never emitted as a name, got {cands:?}"
    );
}

#[test]
fn m4_blank_line_rules_one_continues_two_end() {
    let e = propagation_engine();
    // ONE blank between entries: the list continues.
    let one = "OFFICERS\nAda Quorley\n\nBen Vantol\nprose.";
    let cands = e.candidates(one);
    assert!(
        covers_exact(&cands, "Ben Vantol"),
        "one blank line does not end the list, got {cands:?}"
    );
    // TWO consecutive blanks: the list ends; a name-shaped line after them is NOT emitted.
    let two = "OFFICERS\nAda Quorley\n\n\nCerys Marlow walked away.";
    let cands2 = e.candidates(two);
    assert!(
        !cands2
            .iter()
            .any(|c| c.recognizer() == &Recognizer::Name && c.matched_value().contains("Cerys")),
        "two consecutive blanks end the list, got {cands2:?}"
    );
}

#[test]
fn m4_bounds_line_run_and_total_emissions() {
    let e = propagation_engine();
    // LINE-RUN bound: a single header scans at most MAX_HEADER_LIST_LINES lines.
    let mut text = String::from("DIRECTORS\n");
    for i in 0..60usize {
        text.push_str(&format!("Xy{} Qsurname\n", entity_letters(i)));
    }
    let cands = e.candidates(&text);
    let names = cands
        .iter()
        .filter(|c| c.recognizer() == &Recognizer::Name)
        .count();
    assert!(
        names <= MAX_HEADER_LIST_LINES,
        "a single header emits at most the line-run bound, got {names}"
    );
    assert!(names > 0, "the pass emitted, got {names}");
    // TOTAL cap across many headers.
    let mut big = String::new();
    for block in 0..20usize {
        big.push_str("DIRECTORS\n");
        for i in 0..40usize {
            big.push_str(&format!("Zq{} Wsurname\n", entity_letters(block * 40 + i)));
        }
        big.push_str("prose separator line here.\n");
    }
    let cands2 = e.candidates(&big);
    let names2 = cands2
        .iter()
        .filter(|c| c.recognizer() == &Recognizer::Name)
        .count();
    assert!(
        names2 <= MAX_HEADER_LIST_NAMES,
        "total header-list emissions capped, got {names2}"
    );
    assert!(names2 > 0, "the pass emitted under the cap, got {names2}");
}

#[test]
fn m4_off_without_context_optin() {
    // The header-list pass rides the role-name opt-in (like the trailing-role pass).
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("CONDUCTING OFFICERS\nAda Quorley\nBen Vantol\nprose.");
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "header-list capture is off without the context opt-in, got {cands:?}"
    );
}

#[test]
fn m4_qualified_header_anchors_the_column() {
    // The VERBATIM real-world header carries a qualifier prefix — `MANAGEMENT COMPANY
    // CONDUCTING OFFICERS` — and must anchor the bare name column below it (exact-equality
    // header matching missed exactly this). Fictional names.
    let e = propagation_engine();
    let text = "MANAGEMENT COMPANY CONDUCTING OFFICERS\nAda Quorley\nBen Vantol\nCerys \
                Marlow\nThe conducting officers supervise and coordinate the activities.";
    let cands = e.candidates(text);
    for name in ["Ada Quorley", "Ben Vantol", "Cerys Marlow"] {
        assert!(
            covers_exact(&cands, name),
            "qualified header anchors {name:?}, got {cands:?}"
        );
    }
    // A word-boundary guard: a line ending in `subdirectors` is NOT a header.
    let neg = "APPOINTED SUBDIRECTORS\nAda Quorley\nprose.";
    let cands2 = e.candidates(neg);
    assert!(
        !cands2
            .iter()
            .any(|c| c.recognizer() == &Recognizer::Name && c.matched_value() == "Ada Quorley"),
        "no header match without a word boundary, got {cands2:?}"
    );
}

#[test]
fn m4_interleaved_role_lines_are_skipped_not_emitted() {
    // The interleaved real-world layout: NAME line, then a ROLE line (`Managing Director,
    // Fund Administration`) that is SHAPE-identical to a name-with-role-suffix. The role
    // line is skipped (never emitted — boilerplate in the ENTITY family is the round-2
    // amplification class) and the list CONTINUES to the next name.
    let e = propagation_engine();
    let text = "MANAGEMENT COMPANY CONDUCTING OFFICERS\nAda Quorley\nManaging Director, \
                Fund Administration\nBen Vantol\nExecutive Director, Risk Management\n\
                ordinary prose ends the list here.";
    let cands = e.candidates(text);
    for name in ["Ada Quorley", "Ben Vantol"] {
        assert!(
            covers_exact(&cands, name),
            "{name:?} flagged across interleaved role lines, got {cands:?}"
        );
    }
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name
            && c.matched_value().contains("Managing Director")),
        "a bare role-title line is never emitted as a name, got {cands:?}"
    );
}

// ===================================================================
// ROUND 4 — Mechanism A (field-label anchored values) · Mechanism B (date coverage)
// ===================================================================

/// Does any candidate carry the `ctx:field-name` label (primary or co-recognizer) with
/// exactly this value? (Round-4 review fix: name-field values ride this NON-SEEDING
/// person-family label, never `Recognizer::Name`.)
fn field_name_value(cands: &[RedactionCandidate], value: &str) -> bool {
    cands.iter().any(|c| {
        c.matched_value() == value
            && c.recognizers()
                .iter()
                .any(|r| r.to_string() == "ctx:field-name")
    })
}

/// Does any candidate carry the `ctx:field-id` label (primary or co-recognizer) with
/// exactly this value?
fn field_id_value(cands: &[RedactionCandidate], value: &str) -> bool {
    cands.iter().any(|c| {
        c.matched_value() == value
            && c.recognizers()
                .iter()
                .any(|r| r.to_string() == "ctx:field-id")
    })
}

#[test]
fn field_label_transcript_shape_catches_value_and_name() {
    // The verbatim transcript shape (fictional student): the labeled VALUE was missed
    // while the label itself was flagged as boilerplate. Field capture is ALWAYS-ON
    // (default engine — no context opt-in needed).
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Student ID: A0219477B\nName: Tan Wei Ming\nCourse: LAW101 Introduction to Law";
    let cands = e.candidates(text);
    assert!(
        field_id_value(&cands, "A0219477B"),
        "labeled Student ID value flagged, got {cands:?}"
    );
    assert!(
        field_name_value(&cands, "Tan Wei Ming"),
        "name-labeled person-shaped value emitted as ctx:field-name (round-4 review fix: \
         never the seeding Name kind), got {cands:?}"
    );
}

#[test]
fn field_label_negatives_hold() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // UPDATED (round-4 review): an empty-value label line now captures the NEXT line as
    // the value ONLY when it is a plausible value line. A bare label followed by a BLANK
    // line, or by a LONG prose line (> 40 bytes), emits nothing.
    let cands = e.candidates("Student ID:\n\nprose starts later in the document");
    assert!(
        !cands.iter().any(|c| c
            .recognizers()
            .iter()
            .any(|r| r.to_string() == "ctx:field-id")),
        "a bare label before a blank line emits nothing, got {cands:?}"
    );
    let cands0 = e.candidates(
        "Student ID:\nthis following line is a long prose sentence well past the bound",
    );
    assert!(
        !cands0.iter().any(|c| c
            .recognizers()
            .iter()
            .any(|r| r.to_string() == "ctx:field-id")),
        "a bare label before a long prose line emits nothing, got {cands0:?}"
    );
    // MID-SENTENCE 'name:' is not line-leading: nothing captured.
    let cands2 = e.candidates("the fund whose name: is long was renamed later");
    assert!(
        !cands2.iter().any(|c| c.matched_value().contains("is long")),
        "a mid-sentence label never captures, got {cands2:?}"
    );
    // A single space is NOT a separator (prose `Name of the fund` never matches).
    let cands3 = e.candidates("Name of the fund is stated below");
    assert!(
        !cands3.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "single-space separator does not capture, got {cands3:?}"
    );
}

#[test]
fn field_label_value_never_chains_into_another_label_line() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // The next line is a LISTED label: no chaining.
    let cands = e.candidates("Name: Tan Wei Ming\nStudent ID: A0219477B");
    assert!(
        field_name_value(&cands, "Tan Wei Ming"),
        "value bounded to its own line before a label line, got {cands:?}"
    );
    // The next line is a colon-bearing label OUTSIDE the list (`Course:`): no chaining.
    let cands2 = e.candidates("Name: Tan Wei Ming\nCourse: LAW101 Introduction to Law");
    assert!(
        field_name_value(&cands2, "Tan Wei Ming"),
        "a colon-bearing next line never joins, got {cands2:?}"
    );
    // UPDATED (round-4 review): a NON-EMPTY value never joins the next line — the value
    // is bounded to its own line (the cross-line absorption fix). The wrapped tail
    // `Ming` is deliberately no longer joined; only the EMPTY-value columnar form reads
    // the next line.
    let cands3 = e.candidates("Name: Tan Wei\nMing\nStudent ID: A0219477B");
    assert!(
        field_name_value(&cands3, "Tan Wei"),
        "a non-empty value is bounded to its own line, got {cands3:?}"
    );
    assert!(
        !cands3.iter().any(|c| c.matched_value().contains('\n')),
        "no field value crosses a newline, got {cands3:?}"
    );
}

#[test]
fn field_label_columnar_and_dotted_forms() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // Tab-separated and 2+-space columnar forms (forms columnize).
    let cands = e.candidates("Student ID\tA0219477B\nFull Name  Tan Wei Ming");
    assert!(
        field_id_value(&cands, "A0219477B"),
        "tab-columnar field captured, got {cands:?}"
    );
    assert!(
        field_name_value(&cands, "Tan Wei Ming"),
        "space-columnar name field captured (ctx:field-name), got {cands:?}"
    );
    // Abbreviation dot after the label (`ID No.: …`).
    let cands2 = e.candidates("ID No.: X1234567Z");
    assert!(
        field_id_value(&cands2, "X1234567Z"),
        "dotted label form captured, got {cands2:?}"
    );
}

#[test]
fn field_label_emissions_are_capped() {
    let e = RedactionEngine::new(Vec::<String>::new());
    let n = MAX_FIELD_VALUES + 100;
    let mut text = String::new();
    for i in 0..n {
        text.push_str(&format!("Student ID: Z{i:07}X\n"));
    }
    let cands = e.candidates(&text);
    let fields = cands
        .iter()
        .filter(|c| {
            c.recognizers()
                .iter()
                .any(|r| r.to_string() == "ctx:field-id")
        })
        .count();
    assert!(
        fields <= MAX_FIELD_VALUES,
        "field-value emissions capped, got {fields}"
    );
    assert!(fields > 0, "the pass emitted up to the cap, got {fields}");
}

// ---- Mechanism B: date coverage ----

/// Does any candidate whose PRIMARY recognizer is `ctx:dob` equal this value?
fn dob_primary(cands: &[RedactionCandidate], value: &str) -> bool {
    cands
        .iter()
        .any(|c| c.recognizer().to_string() == "ctx:dob" && c.matched_value() == value)
}

#[test]
fn dob_matrix_all_forms_carry_the_ctx_dob_label() {
    // The full field-evidence DOB matrix: the four previously-good forms must not
    // regress; the ordinal, dotted, and ISO forms (previously missed or phone-mislabels)
    // must now surface with the ctx:dob PRIMARY label (the date-not-phone fixup).
    let e = propagation_engine();
    // NOTE: the probe uses the `born` lexicon keyword, NOT `DOB:` — `dob` is ALSO a
    // FIELD LABEL, and a `DOB:`-prefixed line makes the field pass (correctly) capture
    // the whole labeled rest-of-line as a WIDER ctx:field-id span that absorbs the date
    // (safe side, but a different mechanism than the one under test here).
    for d in [
        "14 March 1998",
        "14/03/1998",
        "March 14, 1998",
        "14 Mar 1998",
        "14th March 1998",
        "1st Feb 2020",
        "23rd June 1999",
        "14.03.1998",
        "1998-03-14",
    ] {
        let text = format!("born {d} as recorded");
        let cands = e.candidates(&text);
        assert!(
            dob_primary(&cands, d),
            "{d:?} carries the ctx:dob primary label, got {cands:?}"
        );
    }
}

#[test]
fn dob_ordinal_and_plausibility_negatives() {
    let e = propagation_engine();
    for bad in ["14thh March 1998", "32nd March 1998", "99.99.9999"] {
        let text = format!("born {bad} noted");
        let cands = e.candidates(&text);
        assert!(
            !cands
                .iter()
                .any(|c| c.recognizers().iter().any(|r| r.to_string() == "ctx:dob")),
            "{bad:?} must not match any dob shape, got {cands:?}"
        );
    }
}

#[test]
fn dotted_date_without_dob_keyword_stays_phone_not_dob() {
    // The additive gate: with no DOB keyword in-window the ctx:dob member is suppressed,
    // so a dotted number in a table keeps its plain (pre-existing) phone attribution and
    // never gains the ctx:dob label — the fixup only ever fires on a keyword-
    // corroborated date.
    let e = propagation_engine();
    let cands = e.candidates("invoice reference 14.03.1998 amount due");
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizers().iter().any(|r| r.to_string() == "ctx:dob")),
        "no dob keyword => no ctx:dob attribution, got {cands:?}"
    );
}

// ---- round-4 REVIEW fixes: span shape (no cross-line absorption; punct trim) ----

#[test]
fn field_value_never_crosses_the_newline_probe_verbatim() {
    // REVIEW PROBE 1 verbatim: the filled field's box must NOT swallow the next
    // sentence. The date value is exactly the date — nothing crosses the newline.
    let e = propagation_engine();
    let cands = e.candidates("Date of Birth: 14.03.1998\nMore text.");
    assert!(
        cands.iter().any(|c| c.matched_value() == "14.03.1998"),
        "the value span is exactly the date, got {cands:?}"
    );
    assert!(
        !cands.iter().any(|c| c.matched_value().contains('\n')),
        "no candidate crosses the newline, got {cands:?}"
    );
}

#[test]
fn field_value_trailing_sentence_punctuation_is_trimmed_when_digit_preceded() {
    // REVIEW PROBE 2 verbatim: a sentence-final labeled date drops the trailing period.
    // CONSERVATIVE RULE (stated): at most ONE trailing `.`/`,`/`;` is trimmed and ONLY
    // when preceded by an ASCII DIGIT — an abbreviation (`Jr.`, `Ltd.`) ends in a letter
    // and is never touched.
    let e = propagation_engine();
    let cands = e.candidates("date of birth: 14th March 1998.");
    assert!(
        cands.iter().any(|c| c.matched_value() == "14th March 1998"),
        "digit-preceded trailing period trimmed, got {cands:?}"
    );
    assert!(
        !cands
            .iter()
            .any(|c| c.matched_value() == "14th March 1998."),
        "no value keeps the sentence period, got {cands:?}"
    );
    // Letter-preceded punctuation is NEVER trimmed (abbreviation safety).
    let e2 = RedactionEngine::new(Vec::<String>::new());
    let cands2 = e2.candidates("Name: Tan Wei Ming Jr.");
    assert!(
        field_name_value(&cands2, "Tan Wei Ming Jr."),
        "letter-preceded dot kept (abbreviation), got {cands2:?}"
    );
}

#[test]
fn field_columnar_empty_label_then_value_line_still_joins() {
    // The legit columnar form: label on one line, value on the next — still captured
    // (this is the ONLY case that reads the next line, per the review fix).
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("Student ID:\nA0219477B\nName:\nTan Wei Ming");
    assert!(
        field_id_value(&cands, "A0219477B"),
        "empty-label columnar value captured, got {cands:?}"
    );
    assert!(
        field_name_value(&cands, "Tan Wei Ming"),
        "empty name-label columnar value captured (ctx:field-name), got {cands:?}"
    );
}

#[test]
fn field_nonempty_value_followed_by_short_lowercase_line_does_not_join() {
    // The review's fourth required negative: a filled label line followed by a SHORT
    // lowercase line (which the old join would have absorbed) stays on its own line.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("Name: Tan Wei Ming\nand more words");
    assert!(
        field_name_value(&cands, "Tan Wei Ming"),
        "the value is exactly the rest of the label line, got {cands:?}"
    );
    assert!(
        !cands.iter().any(|c| c.matched_value().contains('\n')),
        "nothing crosses the newline, got {cands:?}"
    );
}

// ---- round-4 REVIEW HIGH fix: field emissions never seed propagation ----

#[test]
fn field_wrapped_org_token_does_not_amplify_document_wide() {
    // The reviewer's JPMIF shape: a columnar `name:` line wrapping to a bare org token,
    // with THREE more occurrences of that token elsewhere. Exactly ONE candidate (the
    // field site); ZERO propagated copies; nothing rides the Name kind.
    let e = propagation_engine();
    let text = "name:\nJPMorgan\n\nfunds managed by JPMorgan include several ranges; \
                JPMorgan discloses fees; contact JPMorgan for details.";
    let cands = e.candidates(text);
    let jpm: Vec<_> = cands
        .iter()
        .filter(|c| c.matched_value().contains("JPMorgan"))
        .collect();
    assert_eq!(
        jpm.len(),
        1,
        "exactly one candidate (the field site), zero amplification, got {cands:?}"
    );
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == "name:propagated"),
        "no propagated copies, got {cands:?}"
    );
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "no field emission rides the seeding Name kind, got {cands:?}"
    );
    // The single-token org value is NOT person-shaped => the typed field label.
    assert!(
        field_id_value(&cands, "JPMorgan"),
        "single-token value carries ctx:field-id, got {cands:?}"
    );
}

#[test]
fn field_person_shaped_name_value_does_not_seed_propagation_either() {
    // Fix-1 pin for the person-shaped case: the labeled name flags at its own site and
    // its bare re-occurrences elsewhere are NOT propagated (only ORGANIC Name detections
    // seed).
    let e = propagation_engine();
    let text = "Name: Tan Wei Ming\n\nlater prose mentions Tan Wei Ming twice; indeed \
                Tan Wei Ming signed.";
    let cands = e.candidates(text);
    // The guarded invariant: NOTHING here rides a seeding kind — no `name:propagated`
    // copies and no `Recognizer::Name` emission. (The RATIFIED 48-char window lets the
    // later prose mentions reach the `Name:` label as INDEPENDENT `ctx:role-name` WINDOW
    // hits — non-seeding site detections, more coverage on the safe side, not
    // propagation; the old exact-count assertion encoded the 40-char window as a side
    // effect.)
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == "name:propagated"),
        "no name:propagated from a field emission, got {cands:?}"
    );
    assert!(
        !cands.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "no field emission rides the seeding Name kind, got {cands:?}"
    );
    // The field site itself still carries the non-seeding ctx:field-name label.
    assert!(
        cands.iter().any(|c| c.matched_value() == "Tan Wei Ming"
            && c.recognizers()
                .iter()
                .any(|r| r.to_string() == FIELD_NAME_LABEL)),
        "field-site candidate present under ctx:field-name, got {cands:?}"
    );
}

#[test]
fn field_value_shape_guard_routes_honest_kinds() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // Digits after a name label: NOT a person — typed field label.
    let c1 = e.candidates("Name: 12345");
    assert!(
        field_id_value(&c1, "12345") && !c1.iter().any(|c| c.recognizer() == &Recognizer::Name),
        "numeric name-field value is ctx:field-id, got {c1:?}"
    );
    // ALL-CAPS org: not person-shaped.
    let c2 = e.candidates("Client Name: MERIDIAN TRUST S.A.");
    assert!(
        !c2.iter().any(|c| c
            .recognizers()
            .iter()
            .any(|r| r.to_string() == "ctx:field-name")),
        "ALL-CAPS value is not person-shaped, got {c2:?}"
    );
    // Stock phrase with lowercase function words: not person-shaped.
    let c3 = e.candidates("Name: see attached");
    assert!(
        field_id_value(&c3, "see attached"),
        "stock phrase is ctx:field-id, got {c3:?}"
    );
    // A Title-Case org under a name label IS person-shaped by this rule (shape cannot
    // distinguish org from person — honest limitation) but crucially does NOT propagate.
    let c4 = e.candidates(
        "Client Name: Meridian Trust Company\n\nMeridian Trust Company appears here and \
         Meridian Trust Company appears again.",
    );
    let mtc = c4
        .iter()
        .filter(|c| c.matched_value().contains("Meridian Trust Company"))
        .count();
    assert_eq!(
        mtc, 1,
        "the org value flags once at the field site, never doc-wide, got {c4:?}"
    );
}

#[test]
fn field_name_label_is_entity_routed_for_placeholders() {
    // AI-safe-labels mode: a person-shaped field value gets a LETTER placeholder (entity
    // family), not a typed one — while staying non-seeding.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Name: Tan Wei Ming";
    let (out, legend) = label_all(&e, text);
    assert!(
        out.contains("[A]"),
        "person-shaped field value gets an entity letter, got {out:?} / {legend:?}"
    );
}

// ===================================================================
// ROUND 5 — hyphenated surname tokens (GAP 1) · address field labels (GAP 2)
// ===================================================================

#[test]
fn hyphenated_surname_covered_in_full_no_fragment_after_apply() {
    // GAP 1, the exact Circle management-table row: `Jeremy Fox-Geen` was captured as
    // `Jeremy Fox`, and the applied output read `[REDACTED]-Geen, 51, …` — a surname
    // FRAGMENT leak. The hyphenated compound is now ONE token at every name-run site.
    let e = propagation_engine();
    let text = "Jeremy Fox-Geen, 51, Chief Financial Officer";
    let cands = e.candidates(text);
    assert!(
        cands.iter().any(|c| c.matched_value() == "Jeremy Fox-Geen"),
        "the full hyphenated name is one candidate, got {cands:?}"
    );
    // Apply round-trip: NO fragment of the surname survives.
    let (redacted, _n) = e.redact_text(text);
    assert!(
        !redacted.contains("Fox") && !redacted.contains("Geen"),
        "no surname fragment survives the apply, got {redacted:?}"
    );
}

#[test]
fn hyphenated_names_work_at_every_name_run_site() {
    // Site-by-site pin (the audit found NO site handled hyphens fully).
    let e = propagation_engine();
    // Honorific run.
    assert!(
        has_exact_name(
            &e.candidates("We met Ms. José Müller-Tan at the closing."),
            "Ms. José Müller-Tan"
        ),
        "honorific run joins the hyphenated surname"
    );
    // Trailing-role list.
    let c = e.candidates("José Müller-Tan and Ada Quorley are employees of the Group.");
    assert!(
        covers_exact(&c, "José Müller-Tan"),
        "trailing-role list accepts a hyphenated name, got {c:?}"
    );
    // Header-anchored list.
    let c2 = e.candidates("DIRECTORS\nJosé Müller-Tan\nordinary prose ends the list.");
    assert!(
        covers_exact(&c2, "José Müller-Tan"),
        "header list accepts a hyphenated name, got {c2:?}"
    );
    // Anchored display name.
    let c3 = e.candidates("From: José Müller-Tan <jose.mt@ex.example>");
    assert!(
        has_exact_name(&c3, "José Müller-Tan"),
        "anchored display name accepts a hyphenated name, got {c3:?}"
    );
    // Field person-shape guard: hyphenated value routes to the person-family label.
    let c4 = e.candidates("Name: Jeremy Fox-Geen");
    assert!(
        field_name_value(&c4, "Jeremy Fox-Geen"),
        "hyphenated field value is person-shaped, got {c4:?}"
    );
}

#[test]
fn hyphen_negatives_spaced_hyphen_and_ranges_never_join() {
    let e = propagation_engine();
    // A SPACED hyphen never joins two tokens into one surname.
    let c = e.candidates("Directors\nFox - Geen\nprose ends it.");
    assert!(
        !c.iter().any(|x| x.matched_value().contains("Fox - Geen")),
        "a spaced hyphen never joins, got {c:?}"
    );
    // A digit range is never a name token (it may still be the broad phone's business).
    let c2 = e.candidates("the Directors served 2019-2024 throughout");
    assert!(
        !c2.iter().any(|x| {
            x.matched_value().contains("2019-2024")
                && x.recognizers()
                    .iter()
                    .any(|r| matches!(r, Recognizer::Name) || r.to_string() == "ctx:role-name")
        }),
        "a digit range is never name-attributed, got {c2:?}"
    );
}

#[test]
fn registered_office_field_captures_the_building_name_address() {
    // GAP 2, the exact evidence line: a building-name address with NO street number
    // slips the structured-address recognizer; the line-leading label anchors it whole.
    let e = RedactionEngine::builder()
        .locales([Locale::UnitedStates])
        .build()
        .unwrap();
    let text = "Registered office: One World Trade Center, 87th Floor, New York, NY 10007";
    let cands = e.candidates(text);
    let whole = "One World Trade Center, 87th Floor, New York, NY 10007";
    assert!(
        cands.iter().any(|c| {
            c.matched_value() == whole
                && c.recognizers()
                    .iter()
                    .any(|r| r.to_string() == "ctx:field-id")
        }),
        "the whole labeled address value is captured via the field pass, got {cands:?}"
    );
}

// ===================================================================
// ROUND 6 — trailing-tail whitespace-line tolerance · lowercase name particles
// ===================================================================

#[test]
fn trailing_role_list_crosses_whitespace_only_spacer_lines() {
    // The BGF comma-list leak (verbatim reconstruction shape): the wrapped list is
    // separated from the phrase by WHITESPACE-ONLY spacer lines (`…Leon Schwab\n \n \nare
    // employees…`), which the single-newline tail gap refused — so ALL the list names
    // went undetected. The tail now crosses up to THREE whitespace-only line breaks.
    let e = propagation_engine();
    let text = "Ada Quorley, Ben Vantol and \nCerys Marlow\n \n \nare employees \nof the \
                Group.";
    let cands = e.candidates(text);
    for name in ["Ada Quorley", "Ben Vantol", "Cerys Marlow"] {
        assert!(
            covers_exact(&cands, name),
            "list name {name:?} detected across the spacer lines, got {cands:?}"
        );
    }
    // BOUND: FOUR whitespace-only breaks exceed the tail tolerance — honestly not matched.
    let far = "Ada Quorley and Ben Vantol\n \n \n \n \nare employees of the Group.";
    let cands2 = e.candidates(far);
    assert!(
        !covers_exact(&cands2, "Ada Quorley"),
        "the tail reach is bounded at three line breaks, got {cands2:?}"
    );
}

#[test]
fn lowercase_name_particles_join_name_runs() {
    let e = propagation_engine();
    // ctx:role-name (the Circle/officer-table shape).
    let cands = e.candidates("Hendrik van Riel, Independent Director");
    assert!(
        covers_exact(&cands, "Hendrik van Riel"),
        "particle surname joined in a ctx run, got {cands:?}"
    );
    // Honorific run (incl. a two-particle compound).
    let cands2 = e.candidates("We met Ms. Ada van der Berg at the closing.");
    assert!(
        has_exact_name(&cands2, "Ms. Ada van der Berg"),
        "particles joined in an honorific run, got {cands2:?}"
    );
    // Trailing-role list.
    let cands3 = e.candidates("Ada van Riel and Ben Vantol are employees of the Group.");
    assert!(
        covers_exact(&cands3, "Ada van Riel"),
        "particle name in a trailing-role list, got {cands3:?}"
    );
    // Field person-shape guard: a particle name still routes person-family.
    let cands4 = e.candidates("Name: Hendrik van Riel");
    assert!(
        field_name_value(&cands4, "Hendrik van Riel"),
        "particle name is person-shaped, got {cands4:?}"
    );
}

// ===================================================================
// OPT-IN organisation detection (`organisations`) + broadened addresses
// (`addresses_full`) — both DEFAULT OFF, byte-identical when off.
// ===================================================================

/// An engine with ONLY organisation detection enabled.
fn org_engine() -> RedactionEngine {
    RedactionEngine::builder()
        .organisations(true)
        .build()
        .expect("org engine builds")
}

/// The `ctx:org` candidates in a scan, as matched values.
fn org_values(cands: &[RedactionCandidate]) -> Vec<String> {
    cands
        .iter()
        .filter(
            |c| matches!(c.recognizer(), Recognizer::Context(l) if l.as_ref() == ORG_CONTEXT_LABEL),
        )
        .map(|c| c.matched_value().replace('\n', " "))
        .collect()
}

#[test]
fn organisations_off_by_default_is_byte_identical() {
    // A bare engine and an explicit `.organisations(false)` flag NO organisation, and the
    // full candidate set is identical — the opt-in adds nothing when off.
    let text = "Contact Acme Holdings Pte Ltd and BlackRock Group about the deal.";
    let default = RedactionEngine::new(Vec::<String>::new());
    let off = RedactionEngine::builder()
        .organisations(false)
        .build()
        .unwrap();
    let a = default.candidates(text);
    let b = off.candidates(text);
    assert!(
        org_values(&a).is_empty(),
        "no org candidates by default: {a:?}"
    );
    assert_eq!(a.len(), b.len(), "explicit off == default");
    assert!(
        !a.iter().any(
            |c| matches!(c.recognizer(), Recognizer::Context(l) if l.as_ref() == ORG_CONTEXT_LABEL)
        ),
        "default path never emits ctx:org"
    );
}

#[test]
fn org_suffix_anchored_positives() {
    let e = org_engine();
    for (text, want) in [
        (
            "Acme Holdings Pte Ltd is the issuer.",
            "Acme Holdings Pte Ltd",
        ),
        (
            "advised by BlackRock Advisors LLC today",
            "BlackRock Advisors LLC",
        ),
        ("JPMorgan Chase & Co. reported", "JPMorgan Chase & Co"),
        (
            "the fund is Nomura Asset Management",
            "Nomura Asset Management",
        ),
        (
            "Elvinger Hoss Prussen S.A. counsel",
            "Elvinger Hoss Prussen S.A",
        ),
        ("units in Genting Berhad rose", "Genting Berhad"),
    ] {
        let cands = e.candidates(text);
        let vals = org_values(&cands);
        assert!(
            vals.iter().any(|v| v.contains(want)),
            "suffix-anchored org {want:?} in {text:?}, got {vals:?}"
        );
    }
}

#[test]
fn org_context_arm_positives() {
    let e = org_engine();
    // The broad org-context arm: a ≥2-token capitalized run near a cue, carrying an org word.
    let cands = e.candidates("The trustee is State Street Bank in this matter.");
    let vals = org_values(&cands);
    assert!(
        vals.iter().any(|v| v.contains("State Street Bank")),
        "org-context arm flags State Street Bank, got {vals:?}"
    );
    // A fund/index phrase near a cue WILL flag (the ratified broad choice): the cue
    // `manager` directly precedes the run, which carries the org word `Fund`.
    let cands2 = e.candidates("The manager, JPMorgan Global Bond Fund, invests widely.");
    let vals2 = org_values(&cands2);
    assert!(
        vals2
            .iter()
            .any(|v| v.contains("Bond Fund") || v.contains("JPMorgan")),
        "org-context arm flags a fund phrase near a cue, got {vals2:?}"
    );
}

#[test]
fn org_negatives_definite_article_generics_do_not_flag() {
    let e = org_engine();
    // Bare definite-article generics — no proper noun, single token — never flag.
    for text in [
        "Payment to the Company is due.",
        "the Fund will invest broadly",
        "the Manager may delegate duties",
    ] {
        let cands = e.candidates(text);
        let vals = org_values(&cands);
        assert!(
            vals.is_empty(),
            "definite-article generic must not flag in {text:?}, got {vals:?}"
        );
    }
}

#[test]
fn org_person_wins_overlap() {
    // A person name that precedes a `Partners` suffix stays a PERSON on the overlapping
    // merged span (person priority 5 beats ctx:org priority 6).
    let e = org_engine();
    let cands = e.candidates("Advised by Dr. Jane Roe Partners on the transaction.");
    // The span covering the person is primary-Name, never primary-ctx:org.
    let person = cands
        .iter()
        .find(|c| c.matched_value().contains("Jane Roe"))
        .expect("person span exists");
    assert_eq!(
        person.recognizer(),
        &Recognizer::Name,
        "person recognizer wins the overlap, got {:?}",
        person.recognizer()
    );
}

#[test]
fn org_never_seeds_name_propagation() {
    // An org flagged 3x elsewhere must NOT propagate as a person name: exactly its own
    // ctx:org occurrences appear, ZERO propagated Custom("name:propagated"), ZERO Name.
    let e = org_engine();
    let text = "Acme Global Partners advises widely. Later, Acme Global Partners again. \
                And once more Acme Global Partners closes the round.";
    let cands = e.candidates(text);
    let orgs = org_values(&cands);
    assert!(orgs.len() >= 3, "each org occurrence flagged, got {orgs:?}");
    assert!(
        !cands
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Name)),
        "org never becomes a Name candidate: {cands:?}"
    );
    assert!(
        !cands.iter().any(
            |c| matches!(c.recognizer(), Recognizer::Custom(l) if l.as_ref() == PROPAGATED_NAME_LABEL)
        ),
        "org never seeds name propagation: {cands:?}"
    );
}

#[test]
fn org_routes_to_careful_review_always() {
    // Every org candidate is Low confidence => below the default High quick-confirm floor
    // => CarefulReview (never quick-confirm/auto-accept).
    let e = org_engine();
    let policy = ReviewPolicy::default();
    let cands = e.candidates("The registrar is Computershare Investor Services Pte Ltd here.");
    let orgs: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(
            |c| matches!(c.recognizer(), Recognizer::Context(l) if l.as_ref() == ORG_CONTEXT_LABEL),
        )
        .collect();
    assert!(!orgs.is_empty(), "found an org candidate, got {cands:?}");
    for c in orgs {
        assert_eq!(c.confidence(), Confidence::Low, "org is Low confidence");
        assert_eq!(
            policy.tier(c.confidence()),
            ReviewTier::CarefulReview,
            "org routes to careful review"
        );
    }
}

#[test]
fn org_maps_to_entity_placeholder_family() {
    // In AI-safe-labels mode, an accepted org renders as an ENTITY letter placeholder
    // ([A]/[B]), NOT a typed [org]/ID placeholder — consistent with a named party.
    let e = org_engine();
    let text = "Issuer: Acme Holdings Pte Ltd.";
    let cands = e.candidates(text);
    let org = cands
        .iter()
        .find(
            |c| matches!(c.recognizer(), Recognizer::Context(l) if l.as_ref() == ORG_CONTEXT_LABEL),
        )
        .expect("org candidate");
    let accepted: std::collections::HashSet<(usize, usize)> =
        [(org.start(), org.end())].into_iter().collect();
    let (labeled, legend, _applied, _stale) = e.redact_with_selection_labeled(text, &accepted);
    // ENTITY routing: the org becomes a letter placeholder, not a typed one.
    assert!(
        labeled.contains("[A]"),
        "org renders as an entity letter placeholder, got {labeled:?}"
    );
    assert!(
        legend.iter().any(|row| row.label == "[A]"),
        "legend carries the entity letter for the org, got {legend:?}"
    );
}

#[test]
fn addresses_off_by_default_is_byte_identical() {
    // A bare engine and an explicit `.addresses_full(false)` produce an identical candidate
    // set — the broadened rows add nothing when off.
    let text = "Registered at 2, place Winston Churchill and Chater House and L-1855.";
    let default = RedactionEngine::new(Vec::<String>::new());
    let off = RedactionEngine::builder()
        .addresses_full(false)
        .build()
        .unwrap();
    let a = default.candidates(text);
    let b = off.candidates(text);
    assert_eq!(a.len(), b.len(), "explicit off == default candidate count");
    // The foreign street / building / Lux-postal shapes are NOT caught by the DEFAULT rows.
    assert!(
        !a.iter()
            .any(|c| c.matched_value().contains("place Winston Churchill")),
        "foreign street NOT caught by default, got {a:?}"
    );
}

#[test]
fn addresses_full_foreign_street_and_building_positives() {
    let e = RedactionEngine::builder()
        .addresses_full(true)
        .build()
        .unwrap();
    for (text, want) in [
        (
            "Offices at 2, place Winston Churchill in the city.",
            "place Winston Churchill",
        ),
        (
            "Located 19 rue de Bitbourg near the park.",
            "rue de Bitbourg",
        ),
        ("Registered 6, route de Trèves today.", "route de Trèves"),
        ("Suite in Chater House downtown.", "Chater House"),
        ("Meet at South Beach Tower lobby.", "South Beach Tower"),
        ("Postal L-1855 Luxembourg on file.", "L-1855"),
    ] {
        let cands = e.candidates(text);
        assert!(
            cands.iter().any(|c| c.recognizer() == &Recognizer::Address
                && want.contains(c.matched_value())
                || c.matched_value().contains(want)),
            "addresses_full catches {want:?} in {text:?} as address, got {:?}",
            cands
                .iter()
                .map(|c| (c.recognizer().to_string(), c.matched_value().to_string()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn addresses_full_routes_to_careful_review() {
    // The broadened rows ride the address family => careful review (never quick-confirm).
    let e = RedactionEngine::builder()
        .addresses_full(true)
        .build()
        .unwrap();
    let policy = ReviewPolicy::default();
    let cands = e.candidates("Offices at Chater House and 19 rue de Bitbourg here.");
    let addrs: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| c.recognizer() == &Recognizer::Address)
        .collect();
    assert!(!addrs.is_empty(), "found address candidates, got {cands:?}");
    for c in addrs {
        assert_eq!(
            policy.tier(c.confidence()),
            ReviewTier::CarefulReview,
            "broadened address routes to careful review"
        );
    }
}

#[test]
fn org_context_does_not_bridge_sentence_boundary() {
    // REVIEW REPRO: the org run must NOT cross a sentence-terminating `. ` + capital and
    // absorb a person name. With context (role-name) + organisations on, the person
    // `Tan Wei Ming` must NOT end up inside any ctx:org span, and the sentence-initial
    // generic `The Company` must NOT flag.
    let e = RedactionEngine::builder()
        .organisations(true)
        .context_recognizers(ContextRecognizers::all())
        .locales([Locale::Singapore])
        .build()
        .unwrap();
    let cands = e.candidates("Director: Tan Wei Ming. The Company shall not be liable.");
    let orgs = org_values(&cands);
    assert!(
        !orgs.iter().any(|v| v.contains("Tan Wei Ming")),
        "org must not bridge the sentence and absorb the person, got {orgs:?}"
    );
    assert!(
        !orgs.iter().any(|v| v.trim() == "The Company"),
        "sentence-initial definite-article generic must not flag, got {orgs:?}"
    );
}

#[test]
fn org_context_same_line_still_works() {
    // A legitimate org-context match on the SAME line still fires after the sentence-safety
    // fix (regression guard that the fix did not over-tighten).
    let e = org_engine();
    let cands = e.candidates("The registrar is Computershare Investor Services here.");
    let orgs = org_values(&cands);
    assert!(
        orgs.iter()
            .any(|v| v.contains("Computershare Investor Services")),
        "same-line org-context match still works, got {orgs:?}"
    );
}

#[test]
fn org_run_does_not_bridge_two_sentences() {
    // A two-sentence sequence near a cue: the run must not bridge the period between the two
    // capitalized phrases into one span.
    let e = org_engine();
    let cands = e.candidates("The trustee: Alpha Beta Gamma. Delta Epsilon Zeta are here.");
    let orgs = org_values(&cands);
    assert!(
        !orgs
            .iter()
            .any(|v| v.contains("Gamma") && v.contains("Delta")),
        "run must not bridge the period across sentences, got {orgs:?}"
    );
}

#[test]
fn org_suffix_definite_article_generic_dropped() {
    // Sentence-initial `The Company` / `A Group` (article + only the suffix) is a generic and
    // must NOT flag, but a real name after the article (`The Management Company`) is kept.
    let e = org_engine();
    let generic = e.candidates("The Company shall not be liable. A Group met today.");
    assert!(
        org_values(&generic).is_empty(),
        "bare article+suffix generics dropped, got {:?}",
        org_values(&generic)
    );
    let real = e.candidates("Issuer: The Management Company acts for the fund.");
    assert!(
        org_values(&real)
            .iter()
            .any(|v| v.contains("Management Company")),
        "article + real name kept, got {:?}",
        org_values(&real)
    );
}

#[test]
fn org_and_addresses_bounded_caps() {
    // Sanity bomb-bound: a pathological repeated org input stays bounded at MAX_ORG_NAMES
    // per arm and never panics / hangs (linear time).
    let e = org_engine();
    let mut text = String::new();
    for _ in 0..(MAX_ORG_NAMES + 50) {
        text.push_str("Acme Widgets Ltd. ");
    }
    let cands = e.candidates(&text);
    let orgs = org_values(&cands);
    assert!(
        orgs.len() <= MAX_ORG_NAMES,
        "suffix arm capped at {MAX_ORG_NAMES}, got {}",
        orgs.len()
    );
}

// ===================================================================
// FINANCE-CORPUS RECALL ROUND — finance label cues, anchored ALL-CAPS arms,
// the ALL-CAPS propagation echo, and the BIC / ISIN recognizers.
// ===================================================================

/// Does any candidate's SPAN cover `value` (by substring of the matched value)? The
/// finance-narrative arms deliberately over-capture (`FR DARIUS OKONKWO-LIM`), so
/// coverage — not exact equality — is the recall assertion that matters.
fn covers(cands: &[RedactionCandidate], value: &str) -> bool {
    cands.iter().any(|c| c.matched_value().contains(value))
}

#[test]
fn finance_labels_cue_the_role_name_row() {
    // The verified corpus misses: person names after standard finance party labels
    // produced ZERO candidates because the old cue vocabulary required a role/"Name"
    // label. Each label now corroborates the (careful-review-capped) role-name row.
    let e = role_name_engine();
    for (text, name) in [
        (
            "Account Holder : Amelia Ng Su Lin\nNRIC: X",
            "Amelia Ng Su Lin",
        ),
        (
            "Customer: Jordan T. Whitfield\nSSN: Y",
            "Jordan T. Whitfield",
        ),
        ("Primary Cardholder: Amelia Ng Su Lin", "Amelia Ng Su Lin"),
        ("Trader: Quentin Marsh-Abello", "Quentin Marsh-Abello"),
        (
            "Authorised by: Gwendolyn Peart-Sims, Treasury",
            "Gwendolyn Peart-Sims",
        ),
        (
            "Authorized by: Gwendolyn Peart-Sims, Treasury",
            "Gwendolyn Peart-Sims",
        ),
        ("Attn: Felicia Tan Wei Ling", "Felicia Tan Wei Ling"),
        (
            "The borrower, Cassian Werner Holt, agrees",
            "Cassian Werner Holt",
        ),
        ("as guarantor: Beatrice Ong Mei Fen", "Beatrice Ong Mei Fen"),
        (
            "Please contact Gwendolyn Peart-Sims with queries",
            "Gwendolyn Peart-Sims",
        ),
        (
            "Shareholder\nAmelia Ng Su Lin  1,250,000",
            "Amelia Ng Su Lin",
        ),
        ("Beneficiary: Henrik Aldervall", "Henrik Aldervall"),
        (
            "Policyholder: Rosalind Teo Hui Xian",
            "Rosalind Teo Hui Xian",
        ),
    ] {
        let cands = e.candidates(text);
        assert!(
            covers(&cands, name),
            "finance label must cue the name in {text:?}, got {cands:?}"
        );
        // Careful-review cap preserved: no role-name candidate ever exceeds Medium.
        for c in &cands {
            if matches!(c.recognizer(), Recognizer::Context(l) if l.as_ref() == "ctx:role-name") {
                assert!(
                    c.confidence() <= Confidence::Medium,
                    "role-name stays careful-review-capped, got {c:?}"
                );
            }
        }
    }
}

#[test]
fn caps_person_arm_catches_transaction_narrative_names() {
    // The verified bank/card-statement leaks: ALL-CAPS counterparty names in
    // transaction narratives, anchored by a rail cue in the run or the window.
    let e = role_name_engine();
    for (text, name) in [
        (
            "03/06/2026  FAST TRANSFER FR DARIUS OKONKWO-LIM        2,500.00",
            "DARIUS OKONKWO-LIM",
        ),
        (
            "09/06/2026  CHEQUE 004512 PRIYA VENKATESAN             7,150.00",
            "PRIYA VENKATESAN",
        ),
        (
            "06/19/2026  ZELLE FROM  TREVOR OAKENSHIELD              +125.50",
            "TREVOR OAKENSHIELD",
        ),
        (
            "06/12/2026  CHECK 1088  MARISOL DUARTE-FENN             -950.00",
            "MARISOL DUARTE-FENN",
        ),
    ] {
        let cands = e.candidates(text);
        assert!(
            covers(&cands, name),
            "caps narrative name must be covered in {text:?}, got {cands:?}"
        );
    }
}

#[test]
fn caps_person_arm_never_fires_on_headings() {
    // The FP bound: caps HEADINGS split at stopwords / finance head nouns into
    // sub-2-token fragments — nothing is emitted even with a cue nearby.
    let e = role_name_engine();
    for text in [
        "Payment due soon.\nSTATEMENT OF ACCOUNT\nAmount: 4,250.00",
        "TERMS AND CONDITIONS\nPayment within 30 days.",
        "PRIVATE AND CONFIDENTIAL\nCheque enclosed for payment.",
        "MERLION TRUST BANK — CREDIT CARD STATEMENT",
    ] {
        let cands = e.candidates(text);
        assert!(
            !cands.iter().any(|c| matches!(
                c.recognizer(),
                Recognizer::Context(l) if l.as_ref() == CAPS_NAME_LABEL
            )),
            "caps heading must not fire in {text:?}, got {cands:?}"
        );
    }
}

#[test]
fn caps_person_arm_requires_a_cue_and_the_opt_in() {
    // A bare 2-token caps run with NO cue anywhere never fires (a bare "any 2+ word
    // caps run" recognizer is FORBIDDEN — headings flood).
    let e = role_name_engine();
    let text = "The parcel was left with GORDON HALVERSEN yesterday afternoon.";
    assert!(
        !e.candidates(text).iter().any(|c| matches!(
            c.recognizer(),
            Recognizer::Context(l) if l.as_ref() == CAPS_NAME_LABEL
        )),
        "no cue => no caps-name candidate"
    );
    // And the DEFAULT engine (role-name off) emits nothing even WITH a cue.
    let default = RedactionEngine::new(Vec::<String>::new());
    let cued = "CHEQUE 004512 PRIYA VENKATESAN 7,150.00";
    assert!(
        !default.candidates(cued).iter().any(|c| matches!(
            c.recognizer(),
            Recognizer::Context(l) if l.as_ref() == CAPS_NAME_LABEL
        )),
        "caps arm is gated on the role-name opt-in (default path byte-identical)"
    );
}

#[test]
fn caps_person_hits_never_seed_propagation() {
    // AMPLIFICATION-CLASS GUARD (the recurring bug, fixed 3x before): a caps-arm hit
    // must NOT re-flag its value elsewhere in the document. The narrative name is
    // caught AT ITS SITE; a second, cue-less mixed-case occurrence stays un-flagged
    // (it would need a Name-kind seed, and ctx:caps-name is not one).
    let e = role_name_engine();
    let text = "CHEQUE 004512 PRIYA VENKATESAN\n\n\
                Later, priya venkatesan's namesake Priya Venkatesan visited the office.";
    let cands = e.candidates(text);
    assert!(covers(&cands, "PRIYA VENKATESAN"), "site hit caught");
    assert!(
        !cands
            .iter()
            .any(|c| c.matched_value() == "Priya Venkatesan"),
        "a caps-arm hit must never propagate to a mixed-case occurrence, got {cands:?}"
    );
    assert!(
        !cands
            .iter()
            .any(|c| c.recognizer().to_string() == PROPAGATED_NAME_LABEL),
        "no name:propagated candidates from a Context-only seed set, got {cands:?}"
    );
}

#[test]
fn propagation_echo_catches_all_caps_reprint_of_a_detected_name() {
    // Arm (c): a name detected once in mixed case (here via the honorific heuristic,
    // a Name-kind seed) catches its ALL-CAPS re-print elsewhere in the document.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Mr Darius Okonkwo-Lim attended.\n\
                Narrative: TRANSFER FROM DARIUS OKONKWO-LIM RECEIVED.";
    let cands = e.candidates(text);
    assert!(
        cands
            .iter()
            .any(|c| c.matched_value() == "DARIUS OKONKWO-LIM"
                && c.recognizer().to_string() == PROPAGATED_NAME_LABEL),
        "the ALL-CAPS echo of a detected name is propagated, got {cands:?}"
    );
}

#[test]
fn propagation_echo_ignores_lowercase_coincidences() {
    // The echo is CAPS-only: a lowercase occurrence of the detected name is a case
    // coincidence, not an echo — the original case-sensitivity rationale is preserved.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Mr Darius Okonkwo-Lim attended. later, darius okonkwo-lim was written in notes.";
    let cands = e.candidates(text);
    assert!(
        !cands
            .iter()
            .any(|c| c.matched_value() == "darius okonkwo-lim"),
        "a lowercase coincidence is never pulled in, got {cands:?}"
    );
}

#[test]
fn org_caps_suffix_arm_catches_all_caps_orgs() {
    // The verified org misses: ALL-CAPS org names with an explicit legal suffix that
    // the case-SENSITIVE suffix literals never matched.
    let e = org_engine();
    for (text, org) in [
        (
            "SALARY CREDIT HELICON ANALYTICS PTE LTD   11,860.00",
            "HELICON ANALYTICS PTE LTD",
        ),
        (
            "(1) NORTHBRIDGE CAPITAL PARTNERS PTE. LTD. (UEN 201812345K), a company",
            "NORTHBRIDGE CAPITAL PARTNERS PTE. LTD",
        ),
        (
            "DIRECT DEP PAYROLL VELTRANE SYSTEMS INC +4,812.66",
            "VELTRANE SYSTEMS INC",
        ),
        (
            "payable to GRAVENOR & PIKE LLP on demand",
            "GRAVENOR & PIKE LLP",
        ),
        (
            "MEGACORP INDUSTRIES SDN BHD of Kuala Lumpur",
            "MEGACORP INDUSTRIES SDN BHD",
        ),
    ] {
        let cands = e.candidates(text);
        assert!(
            org_values(&cands).iter().any(|v| v.contains(org)),
            "caps org must be covered in {text:?}, got {:?}",
            org_values(&cands)
        );
    }
    // The mixed-case arm's posture is unchanged: a lowercase suffix after a MIXED-case
    // run still does not anchor (the ci suffix is scoped to ALL-CAPS runs only).
    let mixed = e.candidates("the Singapore co-operative movement grew");
    assert!(
        org_values(&mixed).is_empty(),
        "lowercase suffix never anchors a mixed-case run, got {:?}",
        org_values(&mixed)
    );
}

#[test]
fn bic_eleven_char_form_stands_alone() {
    // The 11-char (branch) form is precise enough to stand alone — no label needed.
    let e = RedactionEngine::new(Vec::<String>::new());
    for bic in ["KESTGB2LXXX", "BRNDDEFFXXX", "DEUTDEFFXXX"] {
        let text = format!("please wire the funds via {bic} before noon");
        let cands = e.candidates(&text);
        assert!(
            cands
                .iter()
                .any(|c| c.matched_value() == bic && matches!(c.recognizer(), Recognizer::Bic)),
            "standalone 11-char BIC {bic} detected, got {cands:?}"
        );
    }
    // Structure-invalid country at chars 5-6 => rejected even in 11-char form.
    let bad = e.candidates("please wire the funds via ABCDQQ2LXXX before noon");
    assert!(
        !bad.iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Bic)),
        "invalid ISO country rejects the 11-char form, got {bad:?}"
    );
}

#[test]
fn bic_eight_char_form_requires_a_label_cue() {
    let e = RedactionEngine::new(Vec::<String>::new());
    // Labeled: fires (the corpus miss: `BIC : VANTFRPP`).
    let labeled = e.candidates("  IBAN    : X\n  BIC     : VANTFRPP\n  Amount  : EUR 96,400.00");
    assert!(
        labeled
            .iter()
            .any(|c| c.matched_value() == "VANTFRPP" && matches!(c.recognizer(), Recognizer::Bic)),
        "labeled 8-char BIC detected, got {labeled:?}"
    );
    // "SWIFT" also cues.
    let swift = e.candidates("SWIFT: DEUTDEFF for remittance");
    assert!(
        swift.iter().any(|c| c.matched_value() == "DEUTDEFF"),
        "SWIFT label cues the 8-char form, got {swift:?}"
    );
    // Bare: an ordinary 8-letter caps word that happens to be structure-valid
    // ("DEUTSCHE" carries the valid country "SC" at chars 5-6) must NOT fire without
    // a BIC/SWIFT label — the word-shaped-FP guard.
    let bare = e.candidates("DEUTSCHE interests were represented at the hearing");
    assert!(
        !bare
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Bic)),
        "a bare structure-valid 8-char word is not a BIC, got {bare:?}"
    );
    // And a bare real BIC with no label is (honestly) not fired either — documented:
    // the 8-char form NEEDS the cue.
    let bare_real = e.candidates("route it through VANTFRPP as usual");
    assert!(
        !bare_real
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Bic)),
        "the 8-char form is cue-gated by design, got {bare_real:?}"
    );
}

#[test]
fn bic_stays_careful_review_and_is_disableable() {
    // Structure-only (no checksum): a BIC never reaches High / quick-confirm.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("Debit Bank BIC    : KESTGB2LXXX");
    let bic = cands
        .iter()
        .find(|c| matches!(c.recognizer(), Recognizer::Bic))
        .expect("bic candidate");
    assert!(
        bic.confidence() <= Confidence::Medium,
        "BIC is careful-review tier, got {bic:?}"
    );
    // `disable_builtins`-style toggle: bic off => neither form fires.
    let off = RedactionEngine::builder()
        .builtins(BuiltinRecognizers {
            bic: false,
            ..BuiltinRecognizers::all()
        })
        .build()
        .unwrap();
    let none = off.candidates("BIC: KESTGB2LXXX and BIC: VANTFRPP");
    assert!(
        !none
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Bic)),
        "bic:false disables both forms, got {none:?}"
    );
}

#[test]
fn isin_checksum_validated_stands_alone_and_quick_confirms() {
    let e = RedactionEngine::new(Vec::<String>::new());
    for isin in ["US45256BAD38", "DE000BXY0010", "US0378331005"] {
        let text = format!("Security 1: 4.25% Notes due 2031   ISIN {isin}");
        let cands = e.candidates(&text);
        let hit = cands
            .iter()
            .find(|c| c.matched_value() == isin)
            .unwrap_or_else(|| panic!("ISIN {isin} detected, got {cands:?}"));
        assert!(
            matches!(hit.recognizer(), Recognizer::Isin),
            "attributed to isin, got {hit:?}"
        );
        assert_eq!(
            hit.confidence(),
            Confidence::High,
            "a checksum-valid ISIN is High (quick-confirm), got {hit:?}"
        );
    }
    // A corrupted check digit fails the ISIN Luhn — dropped entirely.
    let bad = e.candidates("ISIN US45256BAD39 on the ticket");
    assert!(
        !bad.iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Isin)),
        "corrupted ISIN check digit never fires, got {bad:?}"
    );
    // An ordinary 12-char caps word is shape-rejected (no trailing digit).
    let word = e.candidates("the CONSOLIDATED accounts were approved");
    assert!(
        !word
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Isin)),
        "ordinary caps words never fire as ISIN, got {word:?}"
    );
}

#[test]
fn bic_standalone_rejects_word_shaped_eleven_char_caps_words() {
    // Ordinary 11-letter caps words whose chars 5-6 coincide with a REAL ISO country
    // ("INSTRUCTION" -> RU, "TRANSACTION" -> SA, "PARTNERSHIP" -> NE, "SHAREHOLDER" ->
    // EH) must NOT fire standalone — the letter-only form needs the `XXX` head-office
    // branch (or a digit), which no English word carries. The verified FP class from
    // the finance-corpus acceptance run (a caps heading is not a BIC).
    let e = RedactionEngine::new(Vec::<String>::new());
    for word in ["INSTRUCTION", "TRANSACTION", "PARTNERSHIP", "SHAREHOLDER"] {
        let text = format!("CROSS-BORDER PAYMENT {word} FOR THE PARTIES");
        let cands = e.candidates(&text);
        assert!(
            !cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Bic)),
            "caps word {word} must not fire as a standalone BIC, got {cands:?}"
        );
    }
    // A labeled letter-only NON-XXX 11-char BIC still fires via the cue-gated pass
    // (`DEUTDEFFVIE` — a real branch-code shape).
    let labeled = e.candidates("SWIFT: DEUTDEFFVIE for the Vienna branch");
    assert!(
        labeled.iter().any(
            |c| c.matched_value() == "DEUTDEFFVIE" && matches!(c.recognizer(), Recognizer::Bic)
        ),
        "labeled non-XXX letter-only 11-char BIC detected via the cue, got {labeled:?}"
    );
}

#[test]
fn caps_name_is_pinned_careful_even_with_a_close_role_heading() {
    // REVIEW HIGH (finance round): a caps-name span that merges with a satisfied
    // ctx:role-name sibling (role heading CLOSE) elects `ctx:caps-name` primary on the
    // label-ASC tie-break, and the SPAN-level Close proximity used to promote the
    // no-row label to High => tier-1 bulk-accept of a caps-heading FP. The explicit
    // Medium pin in `confidence_for` closes it: ctx:caps-name can NEVER exceed Medium /
    // careful review, regardless of sibling proximity promotion.
    let e = role_name_engine();
    let policy = ReviewPolicy::default();
    // The reviewer's verified failing input: a role heading directly above a caps run
    // ("Directors" is Close; "payment" cues the caps arm).
    let text = "Directors\nTRANSFERRING SHARES\npayment enclosed";
    let cands = e.candidates(text);
    let caps: Vec<_> = cands
        .iter()
        .filter(|c| {
            matches!(
                c.recognizer(),
                Recognizer::Context(l) if l.as_ref() == CAPS_NAME_LABEL
            )
        })
        .collect();
    assert!(
        !caps.is_empty(),
        "the failing input must still produce a ctx:caps-name candidate (the FIX is \
         the tier, not the firing), got {cands:?}"
    );
    for c in &caps {
        assert!(
            c.confidence() <= Confidence::Medium,
            "ctx:caps-name is pinned <= Medium even with a Close role heading, got {c:?}"
        );
        assert_eq!(
            policy.tier(c.confidence()),
            ReviewTier::CarefulReview,
            "ctx:caps-name never routes to quick-confirm under the default floor, got {c:?}"
        );
    }
}

// ===================================================================
// RATIFIED ROUND — phone column-gap guard, PAN last-4 advisory, wider ctx window.
// ===================================================================

#[test]
fn phone_column_gap_shapes_are_structurally_not_phones() {
    // The RATIFIED structural rule: a newline / tab / >=2-space run inside a digit run
    // is a LAYOUT boundary between fields, never a phone separator. The verified
    // statement-table FP shapes (9-13 FP/page) must yield NO phone candidate.
    let e = RedactionEngine::new(Vec::<String>::new());
    for text in [
        "opening 84,213.57\n03/06/2026 closing", // newline column join
        "withdrawal 1,842.30                    84,871.27", // multi-space column gap
        "Ordinary 1,250,000        25.00 percent", // cap-table row shape
        "col 84,213.57\t\t2,500.00 next",        // tab column gap
        "period 06/01/2026 - 06/30/2026 shown",  // ' - ' range never joins two dates
    ] {
        let cands = e.candidates(text);
        assert!(
            !cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone)),
            "column-gap shape must not be a phone in {text:?}, got {cands:?}"
        );
    }
}

#[test]
fn phone_recall_shapes_still_fire_after_the_column_guard() {
    // POSITIVE control: every real phone shape (single-space groups, dashes, parens,
    // dots, extensions, international prefix) keeps firing.
    let e = RedactionEngine::new(Vec::<String>::new());
    for (text, phone) in [
        ("call +65 6123 4567 today", "+65 6123 4567"),
        ("fax (65) 6123-9999 please", "65) 6123-9999"),
        ("US line 312-555-0186 direct", "312-555-0186"),
        ("dial 0800 917 2112 free", "0800 917 2112"),
        ("office +65 6812 4477.", "+65 6812 4477"),
        ("ext form 6123 4567 x88 works", "6123 4567 x88"),
    ] {
        let cands = e.candidates(text);
        assert!(
            cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone) && c.matched_value() == phone),
            "real phone {phone:?} must still fire in {text:?}, got {cands:?}"
        );
    }
    // A CUED wrapped real phone is caught at the DEFAULT config (review H2 — the
    // always-on label-cued arm; `enquiries` is a cue): old-default coverage restored.
    let wrapped = "enquiries: 0800\n917 2112.";
    let cands = e.candidates(wrapped);
    assert!(
        cands.iter().any(
            |c| c.matched_value().contains('\n') && matches!(c.recognizer(), Recognizer::Phone)
        ),
        "cued wrapped real phone caught at default, got {cands:?}"
    );
    // The keyword-gated ctx row still covers it too when opted in.
    let ctx = RedactionEngine::builder()
        .context_recognizers(ContextRecognizers {
            phone_wrapped: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap();
    let ctx_cands = ctx.candidates(wrapped);
    assert!(
        ctx_cands.iter().any(|c| c.matched_value().contains('\n')),
        "ctx engine covers the wrapped phone, got {ctx_cands:?}"
    );
    // An UNCUED wrapped digit run stays structurally refused by the general row —
    // only the same-line fragment can fire (the ratified column-boundary rule).
    let uncued = "reference: 0800\n917 2112.";
    let plain = e.candidates(uncued);
    assert!(
        !plain.iter().any(|c| c.matched_value().contains('\n')),
        "an uncued wrapped run never crosses a newline, got {plain:?}"
    );
}

#[test]
fn pan_last4_cued_forms_fire_as_advisory() {
    // RATIFIED: referenced / masked card tails are SURFACED. Where the pan-last4 row is
    // the PRIMARY (the worded/starred/x- forms nothing else catches) the candidate is
    // ADVISORY (default-off in apply, human opts in). The `XXXX-XXXX-XXXX-2144` form is
    // ALSO an `Id`-shaped token the always-on broad id recognizer already caught
    // (default-REMOVE) — the merge keeps Id primary, preserving that stronger
    // pre-existing posture (removing more is the safe side); the ctx label still rides
    // the span's recognizer list.
    let e = RedactionEngine::new(Vec::<String>::new());
    for (text, advisory_primary) in [
        ("Card ending 2144:\n02/06 charge", true),
        ("the card ending in 6906 was used", true),
        ("last four digits 2144 on file", true),
        ("masked: **** **** **** 2144 shown", true),
        ("token x-2144 in the export", true),
        ("ref XXXX-XXXX-XXXX-2144 charged", false), // Id-primary (already default-remove)
    ] {
        let cands = e.candidates(text);
        let hit = cands
            .iter()
            .find(|c| {
                c.recognizers()
                    .iter()
                    .any(|r| r.to_string() == PAN_LAST4_LABEL)
            })
            .unwrap_or_else(|| panic!("pan-last4 must fire in {text:?}, got {cands:?}"));
        if advisory_primary {
            assert!(
                matches!(hit.recognizer(), Recognizer::Context(l) if l.as_ref() == PAN_LAST4_LABEL),
                "pan-last4 is the primary in {text:?}, got {hit:?}"
            );
            assert!(
                e.is_aggressive(hit.recognizer()),
                "pan-last4 primary is ADVISORY, got {hit:?}"
            );
        } else {
            assert!(
                !e.is_aggressive(hit.recognizer()),
                "an Id-primary masked form keeps its default-remove posture, got {hit:?}"
            );
        }
    }
}

#[test]
fn pan_last4_never_fires_on_bare_four_digit_numbers() {
    // A bare 4-digit number must NEVER fire — the cue is mandatory.
    let e = RedactionEngine::new(Vec::<String>::new());
    for text in [
        "the year 2026 closed strong",
        "meet at suite 2144 tomorrow",
        "spending 2144 dollars monthly", // 'ending' inside a word never cues
        "invoice total 2,144.00 due",
    ] {
        let cands = e.candidates(text);
        assert!(
            !cands.iter().any(|c| matches!(
                c.recognizer(),
                Recognizer::Context(l) if l.as_ref() == PAN_LAST4_LABEL
            )),
            "bare 4-digit context must not fire pan-last4 in {text:?}, got {cands:?}"
        );
    }
}

#[test]
fn pan_last4_default_apply_leaves_it_explicit_accept_removes_it() {
    // The advisory contract end-to-end: an accept-set built from the NON-advisory
    // defaults leaves the tail readable; explicitly accepting its span removes it.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Card ending 2144: paid to jane.roe@acme.example today";
    let cands = e.candidates(text);
    let defaults: std::collections::HashSet<(usize, usize)> = cands
        .iter()
        .filter(|c| !e.is_aggressive(c.recognizer()))
        .map(|c| (c.start(), c.end()))
        .collect();
    let (out, _, stale) = e.redact_with_selection(text, &defaults);
    assert_eq!(stale, 0);
    assert!(
        out.contains("ending 2144"),
        "advisory tail left by the default accept-set, got {out:?}"
    );
    assert!(
        !out.contains("jane.roe"),
        "non-advisory email removed, got {out:?}"
    );
    // Explicit accept (the human opting in) removes it.
    let all: std::collections::HashSet<(usize, usize)> =
        cands.iter().map(|c| (c.start(), c.end())).collect();
    let (out2, _, stale2) = e.redact_with_selection(text, &all);
    assert_eq!(stale2, 0);
    assert!(
        !out2.contains("2144"),
        "explicitly accepted tail removed, got {out2:?}"
    );
}

#[test]
fn context_window_48_reaches_a_cue_41_chars_out() {
    // RATIFIED widening (40 -> 48): the motivating verified miss — the cue begins at
    // exactly +41 chars from the span end (' held 900,000 ordinary shares. No other '
    // is 41 chars), one past the old window. The fs_notes shape, verbatim.
    let e = role_name_engine();
    let text = "As at 31 December 2026, Amelia Ng Su Lin held 1,250,000 ordinary shares and\n\
                Devraj Chandramohan held 900,000 ordinary shares. No other director held shares.";
    let cands = e.candidates(text);
    assert!(
        cands
            .iter()
            .any(|c| c.matched_value() == "Devraj Chandramohan"),
        "the +41-char cue now corroborates the name, got {cands:?}"
    );
    // The window stays a WINDOW: the same name with the cue pushed past 48 chars is
    // still gated out (the widening is bounded, not open-ended). A trailing newline is
    // present as in any real document — the blank-line extension deliberately treats a
    // no-further-newline TAIL as in-window (a pre-existing recall-first branch), so a
    // bare single-line probe would not exercise the bound.
    let far = "Devraj Chandramohan held 900,000 ordinary shares in escrow anyway. No other \
               director\nheld.";
    let far_cands = e.candidates(far);
    assert!(
        !far_cands
            .iter()
            .any(|c| c.matched_value() == "Devraj Chandramohan"),
        "a cue beyond 48 chars still does not corroborate, got {far_cands:?}"
    );
    // And the review-snippet radius is deliberately DECOUPLED (stays 40).
    assert_eq!(CONTEXT_CHARS, 40, "snippet radius unchanged");
}

#[test]
fn nbsp_joined_phones_are_caught_like_the_old_default() {
    // REVIEW C1: word processors insert a single NBSP (U+00A0) / narrow NBSP (U+202F)
    // INSIDE a phone number to prevent wrapping — an intra-number join, not a column
    // boundary. The old \s-class default removed these; the guard must too.
    let e = RedactionEngine::new(Vec::<String>::new());
    for (text, phone) in [
        (
            "Call +65\u{00A0}6812\u{00A0}4477 with queries.",
            "+65\u{00A0}6812\u{00A0}4477",
        ),
        (
            "Ligne 01\u{202F}42\u{202F}68\u{202F}53\u{202F}00 ouverte.",
            "01\u{202F}42\u{202F}68\u{202F}53\u{202F}00",
        ),
        // Mixed ASCII-space and NBSP joins (one at a time) still one number.
        ("Tel +65 6812\u{00A0}4477 today.", "+65 6812\u{00A0}4477"),
    ] {
        let cands = e.candidates(text);
        assert!(
            cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone) && c.matched_value() == phone),
            "NBSP-joined phone {phone:?} must fire in {text:?}, got {cands:?}"
        );
    }
    // A RUN of two NBSPs (or a 2-char whitespace mix) is a column gap — refused.
    let gapped = "col 84,213.57\u{00A0}\u{00A0}2,500.00 next\n";
    let cands = e.candidates(gapped);
    assert!(
        !cands
            .iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Phone)),
        "a >=2-char NBSP run stays a refused column gap, got {cands:?}"
    );
}

#[test]
fn cued_phone_arm_restores_labeled_multispace_and_wrapped_shapes() {
    // REVIEW H1+H2: at the DEFAULT config, a phone-label cue sanctions the relaxed
    // joiners the column guard refuses uncued.
    let e = RedactionEngine::new(Vec::<String>::new());
    // H1 — same-line double space after a label.
    let c1 = e.candidates("Tel: 6438  1290\nregards");
    assert!(
        c1.iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Phone)
                && c.matched_value() == "6438  1290"),
        "labeled double-space phone caught at default, got {c1:?}"
    );
    // H2 — labeled single-wrap.
    let c2 = e.candidates("Tel: 6438\n1290 is the line.\n");
    assert!(
        c2.iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Phone)
                && c.matched_value() == "6438\n1290"),
        "labeled wrapped phone caught at default, got {c2:?}"
    );
    // M2 — the SG mobile vocabulary cues too (incl. the `m:` label glued to digits).
    for text in [
        "Mobile: 9123  4567 direct",
        "HP: 9123  4567 anytime",
        "M:9123  4567 after hours",
    ] {
        let c = e.candidates(text);
        assert!(
            c.iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone)),
            "SG mobile label must cue in {text:?}, got {c:?}"
        );
    }
    // The UNCUED versions of the same shapes stay refused (the ratified loss).
    for text in ["ref 6438  1290\nregards", "ref 6438\n1290 is noted.\n"] {
        let c = e.candidates(text);
        assert!(
            !c.iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone)),
            "uncued relaxed shapes stay refused in {text:?}, got {c:?}"
        );
    }
    // And `hotel` never cues via `tel` (left word boundary).
    let c3 = e.candidates("hotel 6438  1290 lobby\n");
    assert!(
        !c3.iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Phone)),
        "no cue inside a longer word, got {c3:?}"
    );
}

#[test]
fn cued_phone_arm_never_bridges_into_a_column_row() {
    // A cued line FOLLOWED by a table row: the EXACT candidate set is pinned. The wrap
    // arm is tried only when the same-line match alone is implausible, so it never
    // bridges; and the cue lookback breaks at the newline, so the `Tel:` label never
    // sanctions the NEXT line's shadow (before the hardening this text grew an extra
    // `('phone', '2026   88.00')` over-flag candidate — if it, or any other shadow,
    // ever reappears this fails LOUDLY instead of only checking "no \n-crossing span").
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Tel: 6438 1290\n03/06/2026   88.00\n";
    let cands = e.candidates(text);
    let got: Vec<(String, &str)> = cands
        .iter()
        .map(|c| (c.recognizer().to_string(), c.matched_value()))
        .collect();
    assert_eq!(
        got,
        vec![("phone".to_string(), "6438 1290")],
        "exactly the labeled phone and NOTHING else, got {cands:?}"
    );
}

#[test]
fn cued_phone_label_on_its_own_line_still_cues_the_next_line() {
    // REGRESSION (caught by the independent review of the cue-shadow hardening): the
    // first clamp made the cue strictly same-line and KILLED the label-on-its-own-line
    // recall class the true parent's default caught — a routine extraction artifact
    // (letterhead label cell, value cell on the next line). The line-final-label
    // bridge restores every shape to the FULL span (the `Telephone:` one must be the
    // whole number, not the `+65 6438` prefix — a partial match is false coverage).
    let e = RedactionEngine::new(Vec::<String>::new());
    for (text, want) in [
        ("Tel:\n6438  1290 direct", "6438  1290"),
        ("Tel: \n6438  1290 direct", "6438  1290"),
        ("Tel:\r\n6438  1290 direct", "6438  1290"),
        ("Tel:\n6438\n1290 is the line.\n", "6438\n1290"),
        ("Telephone:\n+65 6438  1290 direct", "+65 6438  1290"),
    ] {
        let cands = e.candidates(text);
        assert!(
            cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone) && c.matched_value() == want),
            "line-final label cues the FULL next-line value {want:?} in {text:?}, got {cands:?}"
        );
        assert!(
            !cands
                .iter()
                .any(|c| matches!(c.recognizer(), Recognizer::Phone)
                    && c.matched_value() != want
                    && want.starts_with(c.matched_value())),
            "no partial-prefix phone survives beside the full span in {text:?}, got {cands:?}"
        );
    }
    // A cue TWO line breaks up never bridges (the label points at its next line only).
    let far = e.candidates("Tel:\n\n6438  1290 direct");
    assert!(
        !far.iter()
            .any(|c| matches!(c.recognizer(), Recognizer::Phone)),
        "a blank line between label and digits breaks the bridge, got {far:?}"
    );
}

#[test]
fn cued_phone_bare_label_line_over_flags_the_column_row_below() {
    // CHARACTERIZATION of the KNOWN ACCEPTED TRADEOFF (ledger-documented, recall-first
    // — do not "fix" without a ratified decision): a BARE label line directly above a
    // pure column row cues that row's relaxed joiners and emits a narrow over-flag
    // candidate. Over-flagging is the safe side; the common shadow (a phone already on
    // the cue's line) stays pinned dead by the exact-set test above.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("Tel:\n03/06/2026   88.00\n");
    let phones: Vec<&str> = cands
        .iter()
        .filter(|c| matches!(c.recognizer(), Recognizer::Phone))
        .map(RedactionCandidate::matched_value)
        .collect();
    assert_eq!(
        phones,
        vec!["2026   88.00"],
        "the documented over-flag on a bare-label + column-row pairing, got {cands:?}"
    );
}

#[test]
fn cued_phone_label_never_sanctions_digit_columns_on_following_lines() {
    // Cue-shadow hardening, the second negative: a cue on line 1 with digit-column
    // rows on lines 2-3 that START inside the 24-char lookback — the label is
    // CONSUMED by the full phone on its own line (not line-final), so it sanctions
    // nothing below and the relaxed (multi-space) joiners stay refused on those rows.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Fax: 6438 1290\n2026  88.00\n2027  91.50\n";
    let cands = e.candidates(text);
    let phones: Vec<&str> = cands
        .iter()
        .filter(|c| matches!(c.recognizer(), Recognizer::Phone))
        .map(RedactionCandidate::matched_value)
        .collect();
    assert_eq!(
        phones,
        vec!["6438 1290"],
        "the labeled phone only — zero relaxed candidates on the column rows, got {cands:?}"
    );
}

#[test]
fn statement_column_shapes_still_refused_with_the_cued_arm_active() {
    // The verified corpus column lines VERBATIM (incl. the Balance/GIRO rows): no
    // phone label anywhere near, so the cued arm must not resurrect the flood.
    let e = RedactionEngine::new(Vec::<String>::new());
    let text = "Date        Description                                    Withdrawal      Deposit       Balance\n\
                01/06/2026  BALANCE B/F                                                                  84,213.57\n\
                03/06/2026  FAST TRANSFER FR DARIUS OKONKWO-LIM               \t\t        2,500.00     86,713.57\n\
                05/06/2026  GIRO PAYMENT UOL PROPERTY MGMT                    1,842.30                    84,871.27\n\
                28/06/2026  INTEREST EARNED                                                     12.11     89,374.94\n";
    let cands = e.candidates(text);
    let phones: Vec<&RedactionCandidate> = cands
        .iter()
        .filter(|c| matches!(c.recognizer(), Recognizer::Phone))
        .collect();
    assert!(
        phones.is_empty(),
        "statement columns stay structurally not-phones, got {phones:?}"
    );
}

#[test]
fn ctx_phone_wrapped_lexicon_covers_the_sg_mobile_vocabulary() {
    // REVIEW M2 fold-in: the opt-in ctx row's lexicon gained mobile/hp/handphone/cell/m:.
    let ctx = RedactionEngine::builder()
        .context_recognizers(ContextRecognizers {
            phone_wrapped: true,
            ..ContextRecognizers::none()
        })
        .build()
        .unwrap();
    let cands = ctx.candidates("handphone enquiries: 0800\n917 2112.");
    assert!(
        cands.iter().any(|c| c
            .recognizers()
            .iter()
            .any(|r| r.to_string() == "ctx:phone-wrapped")),
        "SG mobile keyword corroborates the ctx wrapped row, got {cands:?}"
    );
}

#[test]
fn pan_last4_bullet_masked_forms_fire_as_advisory() {
    // Ledger LOW: `●●●● ●●●● ●●●● 2144` (U+25CF and friends) never fired — the mask
    // class was `[*x]` only. The BULLET maskers (U+25CF / U+2022) now ride the same
    // cue-anchored arms; U+00B7 MIDDLE DOT is deliberately NOT one of them (the TOC
    // dot-leader FP — see the negatives). Posture UNCHANGED: advisory primary,
    // default-off in apply.
    let e = RedactionEngine::new(Vec::<String>::new());
    for text in [
        // Grouped forms, one per kept masker: U+25CF BLACK CIRCLE / U+2022 BULLET.
        "masked: \u{25CF}\u{25CF}\u{25CF}\u{25CF} \u{25CF}\u{25CF}\u{25CF}\u{25CF} \u{25CF}\u{25CF}\u{25CF}\u{25CF} 2144 shown",
        "masked: \u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022} 2144 shown",
        // The unbroken 12-masker runs (the star-run sibling), both kept maskers.
        "shown as \u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}\u{25CF}2144 on file",
        "shown as \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}2144 on file",
    ] {
        let cands = e.candidates(text);
        let hit = cands
            .iter()
            .find(|c| {
                matches!(c.recognizer(), Recognizer::Context(l) if l.as_ref() == PAN_LAST4_LABEL)
            })
            .unwrap_or_else(|| panic!("bullet-masked pan-last4 must fire in {text:?}, got {cands:?}"));
        assert!(
            e.is_aggressive(hit.recognizer()),
            "bullet-masked pan-last4 stays ADVISORY in {text:?}, got {hit:?}"
        );
    }
}

#[test]
fn pan_last4_never_fires_on_a_decorative_bullet_list() {
    // The cue posture holds: single bullets between words are a LIST, not a mask —
    // >=4 CONSECUTIVE maskers per group are required, so none of these fire.
    let e = RedactionEngine::new(Vec::<String>::new());
    for text in [
        "\u{2022} item one \u{2022} item two \u{2022} item three \u{2022} suite 2144",
        "\u{25CF} first point \u{25CF} second point \u{25CF} room 2144 booked",
        "agenda \u{B7} minutes \u{B7} accounts \u{B7} 2144 review",
    ] {
        let cands = e.candidates(text);
        assert!(
            !cands.iter().any(|c| matches!(
                c.recognizer(),
                Recognizer::Context(l) if l.as_ref() == PAN_LAST4_LABEL
            )),
            "a decorative bullet list must not fire pan-last4 in {text:?}, got {cands:?}"
        );
    }
}

#[test]
fn pan_last4_never_fires_on_toc_dot_leaders() {
    // Review Med FP: U+00B7 MIDDLE DOT is the TOC dot-leader character — including it
    // in the mask class resurrected leader lines as advisory candidates. It is OUT of
    // BOTH masker arms (glued run and grouped); these leader shapes stay dead.
    let e = RedactionEngine::new(Vec::<String>::new());
    for text in [
        // Glued 12-dot leader flush against a 4-digit page/section number.
        "Chapter overview \u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}\u{B7}2144",
        // The grouped middle-dot form.
        "Chapter overview \u{B7}\u{B7}\u{B7}\u{B7} \u{B7}\u{B7}\u{B7}\u{B7} \u{B7}\u{B7}\u{B7}\u{B7} 2144",
    ] {
        let cands = e.candidates(text);
        assert!(
            !cands.iter().any(|c| matches!(
                c.recognizer(),
                Recognizer::Context(l) if l.as_ref() == PAN_LAST4_LABEL
            )),
            "a TOC dot-leader line must not fire pan-last4 in {text:?}, got {cands:?}"
        );
    }
}

#[test]
fn pan_last4_en_dash_masked_form_fires() {
    // LOW: the en-dash variant the pattern claims ('x–2144') — now pinned by a test.
    let e = RedactionEngine::new(Vec::<String>::new());
    let cands = e.candidates("token x\u{2013}2144 in the export");
    assert!(
        cands.iter().any(|c| matches!(
            c.recognizer(),
            Recognizer::Context(l) if l.as_ref() == PAN_LAST4_LABEL
        )),
        "en-dash masked PAN tail fires, got {cands:?}"
    );
}
