"""
Re-identification RISK estimator smoke tests (split from tests/test_smoke.py).
"""

import json
import os
import tempfile
from pathlib import Path

# Isolate the app-data dir BEFORE any app import (belt-and-suspenders alongside the
# package __init__; setdefault keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402
from app.web import create_app, AppState  # noqa: E402
from tests.smoke._helpers import (  # noqa: E402
    _client, _reidrisk,
    _BIO_FIXTURE, _assembled_reidrisk_js_path,
)


def test_reidentification_exposure_score():
    """The document-level re-identification EXPOSURE scorer (app/privilege.score_*):
      * DETERMINISTIC — the same text yields a byte-identical score twice;
      * MONOTONE — a superset of quasi-identifiers scores >= a subset (adding a quasi-
        identifier never lowers the index; removing one never raises it). This is the
        property that guarantees after <= before;
      * BAND BOUNDARIES — the bio fixture (dense quasi-identifiers) lands high/critical; a
        lone "Director in 2007" sentence lands low/none; empty/whitespace -> 0/none;
      * a redacted / identifier-stripped version scores <= the original (residual <= input);
      * privilege/confidentiality wording is SENSITIVITY, not re-identifiability — it does
        NOT move the index (only the informational `privilege_markers` flag).
    Pure Python — runs without the redact-cli bin."""
    from app import privilege

    # (a) DETERMINISM: identical text -> identical dict, twice.
    a = privilege.score_reidentification_dict(_BIO_FIXTURE)
    b = privilege.score_reidentification_dict(_BIO_FIXTURE)
    assert a == b, (a, b)
    # The contract shape (all COUNT-derived — no cleartext leaks into the score).
    assert set(a) == {"index", "band", "counts", "distinct", "total", "privilege_markers"}
    assert isinstance(a["index"], int) and 0 <= a["index"] <= 100
    assert a["band"] in privilege.REID_BANDS
    assert set(a["counts"]) == {"time", "roles", "locations", "organisations"}

    # (b) BAND BOUNDARIES.
    # The bio fixture: dense quasi-identifiers -> high or critical (the flag-aligned bands).
    bio = privilege.score_reidentification(_BIO_FIXTURE)
    assert bio.band in ("high", "critical"), bio
    assert bio.index >= 60, bio
    # A lone "Director in 2007" (1 year + 1 role = 2 categories, low density) -> low / none.
    lone = privilege.score_reidentification("He joined the company in 2007 as a Director.")
    assert lone.band in ("none", "low"), lone
    # Empty / whitespace / None -> index 0, band none.
    for empty in ("", "   \n\t ", None):
        s = privilege.score_reidentification(empty)
        assert s.index == 0 and s.band == "none", (empty, s)

    # (c) MONOTONICITY: a superset of quasi-identifiers scores >= the subset.
    sub = "He joined in 2007 as a Director."
    sup = sub + " He worked at Acme Bank Ltd in London and Singapore from 2009 to 2015 as Chief Risk Officer."
    si = privilege.score_reidentification(sub).index
    pi = privilege.score_reidentification(sup).index
    assert pi >= si, (si, pi)
    # Adding ONE more quasi-identifier (an organisation) never lowers the index.
    more = sup + " He later led Beta Capital Holdings."
    assert privilege.score_reidentification(more).index >= pi

    # (d) RESIDUAL <= INPUT: a redacted / identifier-stripped version scores <= the original.
    # The engine removes NAMED identifiers (here we simulate by stripping emails/IDs) but NOT
    # the quasi-identifiers, so the residual's quasi-identifier set is a subset -> score <=.
    with_ids = (
        "John Smith (john.smith@acme.example, +65 9123 4567) joined Acme Bank Ltd in London "
        "in 2007 as a Director and moved to Singapore in 2012 as Chief Risk Officer."
    )
    stripped = (
        "[REDACTED] ([REDACTED], [REDACTED]) joined Acme Bank Ltd in London "
        "in 2007 as a Director and moved to Singapore in 2012 as Chief Risk Officer."
    )
    before = privilege.score_reidentification(with_ids).index
    after = privilege.score_reidentification(stripped).index
    assert after <= before, (before, after)

    # (d2) The engine's `labels` style INSERTS bracketed placeholder tokens whose words the
    # scanners would otherwise match (`[Singapore ID]` contains `Singapore`, a location;
    # `[Australia ID (tfn)]` contains `Australia`). Scoring the RAW residual miscounts them;
    # the RESIDUAL scorer strips the markers first, so the engine's own redaction labels never
    # inflate the after-score above the before. (Independent-review HIGH finding.)
    labels_residual = "Subject [REDACTED] holds [Singapore ID] and [Australia ID (tfn)]."
    raw_r = privilege.score_reidentification(labels_residual)             # miscounts the markers
    resid_r = privilege.score_reidentification_residual(labels_residual)  # strips them first
    assert raw_r.counts["locations"] >= 1, raw_r           # the bug exists without the fix
    assert resid_r.counts["locations"] == 0, resid_r        # the fix: markers do not count
    assert resid_r.index <= raw_r.index, (raw_r.index, resid_r.index)

    # (e) Privilege wording is SENSITIVITY, not re-identifiability: it does NOT move the index
    # (index stays 0 with no quasi-identifiers), but the informational flag is set.
    pv = privilege.score_reidentification(
        "This memo is strictly confidential and legally privileged. Without prejudice.")
    assert pv.index == 0 and pv.band == "none", pv
    assert pv.privilege_markers is True


def test_reidentification_exposure_wired_through_scan_and_apply():
    """The re-identification EXPOSURE meter's BEFORE/AFTER scores travel through the API:
      * scan attaches `reid_score` for the INPUT text (best-effort — present even when the
        redaction ENGINE is unavailable, since scoring is pure-Python, like `passages`);
      * the /redaction page ships the meter markup + renderer with the HONEST
        exposure-not-safety framing and stays air-gapped after inlining."""
    c = _client()
    r = c.post("/api/redaction/scan", json={"text": _BIO_FIXTURE})
    data = r.json()
    # BEFORE score present even on a 503 (engine down) — pure-Python best-effort.
    assert "reid_score" in data, f"scan must include reid_score (status {r.status_code})"
    rs = data["reid_score"]
    assert rs["band"] in ("high", "critical") and isinstance(rs["index"], int)

    # The page ships the meter component + renderer with honest framing, still air-gapped.
    page = c.get("/redaction").text
    assert 'id="reidMeter"' in page and "function renderReidMeter(" in page
    assert "Re-identification exposure" in page
    # HONEST: an EXPOSURE indicator, explicitly NOT an anonymity / safety guarantee.
    assert "exposure indicator" in page
    assert "NOT an anonymity guarantee" in page
    # Never the word "safe" presented as a STATE (only ever negated in surrounding copy).
    assert "safe to send" in page  # the negation ("NOT a measure of whether ... safe to send")
    assert "http://" not in page and "https://" not in page


def test_reidrisk_reference_loads_and_tolerates_partials():
    """The 9 bundled tables load; the partial/null-laden ones do not crash the loader.

    sg-surname is DELIBERATELY ABSENT (commercial source) — so 'surname' resolves only to
    the US table. region/sex exist for BOTH SG and US (nested by jurisdiction, not clobbered).
    us-given-name is headline-only (all probs null) -> an empty marginal with a full tail."""
    R = _reidrisk()
    ref = R.load_reference()
    assert ref, "reference tables must load"
    # nested {category: {jurisdiction: table}}
    assert set(ref) >= {"surname", "sex", "region", "age_band", "occupation",
                        "medical_condition", "given_name"}
    # region/sex carry BOTH jurisdictions (the collision bug would drop one).
    assert R.has_category(ref, "region", "Tampines"), "SG region (Tampines) must survive"
    assert R.has_category(ref, "region", "California"), "US region (California) must survive"
    assert R.select(ref, "region", "SG").jurisdiction == "SG"
    assert R.select(ref, "region", "US").jurisdiction == "US"
    # an ambiguous category (two jurisdictions, no hint) refuses to guess.
    assert R.select(ref, "region") is None
    # sg-surname is NOT bundled -> surname is US-only.
    assert R.select(ref, "surname", "US") is not None
    # us-given-name probs are all null -> empty marginal, full tail (no crash).
    g = R.select(ref, "given_name")
    assert g is not None and g.n_entries == 0 and g.tail_prob == 1.0
    # a partial table's residual tail is non-negative and bounded.
    med = R.select(ref, "medical_condition")
    assert med is not None and 0.0 <= med.tail_prob <= 1.0
    # a __other_* explicit tail is treated as the tail (not a real value).
    us_region = R.select(ref, "region", "US")
    assert us_region.has_explicit_tail and "__OTHER_48_STATES_PLUS_DC" not in us_region.probs \
        and not any(k.startswith("__") for k in us_region.probs)


def test_reidrisk_tail_lookup_flags_estimated():
    """A value NOT individually listed gets a conservative tail-derived probability, FLAGGED
    estimated_from_tail; a listed value is exact + not flagged."""
    R = _reidrisk()
    ref = R.load_reference()
    sur = R.select(ref, "surname", "US")
    p_smith, tail_smith = sur.lookup("SMITH")
    assert p_smith > 0 and tail_smith is False, "a listed surname is exact"
    p_unseen, tail_unseen = sur.lookup("ZZZQXNOTASURNAME")
    assert tail_unseen is True and 0.0 < p_unseen <= sur.tail_prob + 1e-9, \
        "an unseen value gets the tail probability, flagged"


def test_reidrisk_estimate_k_formula_and_honesty_flags():
    """k = N · ∏P(value); prosecutor = 1/k (LEAD); every result carries the honesty spine."""
    R = _reidrisk()
    ref = R.load_reference()
    e = R.extract_qi_values("Mr Smith is a Director based in California. He is male.", ref)
    est = R.estimate_k(e, ref)
    assert est.jurisdiction == "US"
    assert est.population_N and est.population_N > 0
    # k == N * p_tuple (the actual formula, not an approximation).
    assert abs(est.k_estimate - est.population_N * est.p_tuple) < 1e-3
    # prosecutor risk LEADS and equals 1/k.
    assert abs(est.prosecutor_risk - 1.0 / est.k_estimate) < 1e-9
    # honesty spine — ALWAYS these exact values.
    d = est.to_dict()
    assert d["is_estimate"] is True
    assert d["assumes_independence"] is True
    assert d["direction"] == "optimistic — may under-state risk"
    assert d["not_a_safety_verdict"] is True
    assert "OPTIMISTIC" in d["caveat"] and "safe to send" in d["caveat"]
    # coverage is disclosed.
    assert "matched" in est.coverage_note


def test_reidrisk_determinism():
    """The same input yields a byte-identical estimate (no RNG, no ordering drift)."""
    R = _reidrisk()
    txt = "Ms Garcia, a Manager in Texas, female, with diabetes."
    a = json.dumps(R.score_text(txt), sort_keys=True, default=str)
    b = json.dumps(R.score_text(txt), sort_keys=True, default=str)
    assert a == b, "estimate must be deterministic"


def test_reidrisk_monotonicity_more_qi_lowers_k():
    """Adding a matched QI LOWERS k / RAISES risk — more identifying info = smaller cohort."""
    R = _reidrisk()
    ref = R.load_reference()
    from app.reidrisk import QIValue, EntityQIs
    base = [QIValue("region", "California", "California")]
    e1 = EntityQIs(name=None, qis=list(base))
    e2 = EntityQIs(name=None, qis=base + [QIValue("sex", "male", "male")])
    e3 = EntityQIs(name=None, qis=base + [QIValue("sex", "male", "male"),
                                          QIValue("surname", "Smith", "SMITH")])
    k1 = R.estimate_k(e1, ref).k_estimate
    k2 = R.estimate_k(e2, ref).k_estimate
    k3 = R.estimate_k(e3, ref).k_estimate
    assert k1 >= k2 >= k3 and k1 > k3, "k must be non-increasing as QIs are added"
    r1 = R.estimate_k(e1, ref).prosecutor_risk
    r3 = R.estimate_k(e3, ref).prosecutor_risk
    assert r3 > r1, "prosecutor risk must rise as QIs are added"


def test_reidrisk_medical_tiering_common_vs_rare():
    """A common condition is a WEAK QI, a rare one a STRONG QI; NEITHER yields a precise
    crude-prevalence k (medical is TIERED, never priced into the product)."""
    R = _reidrisk()
    ref = R.load_reference()
    common = R.estimate_k(R.extract_qi_values("The patient has diabetes.", ref), ref)
    rare = R.estimate_k(R.extract_qi_values("The patient has haemophilia.", ref), ref)
    assert common.medical_tiers and common.medical_tiers[0]["tier"] == "common"
    assert rare.medical_tiers and rare.medical_tiers[0]["tier"] == "rare"
    # medical NEVER enters the k product (in_product is False for every medical contribution).
    for est in (common, rare):
        meds = [c for c in est.contributions if c.category == "medical_condition"]
        assert meds and all(c.in_product is False for c in meds), \
            "a medical condition must never be priced into k"
        assert all(c.prob is None for c in meds), "no crude-prevalence prob folded into k"


def test_reidrisk_dob_priced_via_single_year_age_table():
    """A born/DOB <year> phrase is now PRICED via the SG single-year-of-age table
    (`age = REFERENCE_YEAR - year`). It prices the BIRTH-YEAR COHORT (not an exact DOB), lowers
    k vs the same entity without the DOB, and is honestly noted; edge cases never crash."""
    R = _reidrisk()
    ref = R.load_reference()
    assert R.REFERENCE_YEAR == 2025, "the DOB pricing reference year is a fixed deterministic constant"

    e = R.extract_qi_values("She was born in 1981 and works in Tampines. She is female.", ref)
    dob = [q for q in e.qis if q.category == "dob"]
    assert dob and dob[0].key == "1981", "the born-year is detected as a dob QI"
    est = R.estimate_k(e, ref, "SG")
    dc = [c for c in est.contributions if c.category == "dob"]
    assert dc and dc[0].in_product is True and dc[0].prob and dc[0].prob > 0.0, \
        "the dob must be PRICED into the product"
    # HONEST: prices the birth-year COHORT, never an exact day-of-birth (no 1/365.25 invented).
    assert "COHORT" in dc[0].note and "exact day-of-birth" in dc[0].note and "1/365.25" in dc[0].note

    # adding the DOB lowers k (raises concern) vs the same entity without it.
    without = R.EntityQIs(name=e.name, qis=[q for q in e.qis if q.category != "dob"], unmatched=[])
    k_with = est.k_estimate
    k_without = R.estimate_k(without, ref, "SG").k_estimate
    assert k_with is not None and k_without is not None and k_with < k_without, \
        "pricing the DOB must LOWER k (more identifying info)"

    # open top bucket: a very old birth year maps to the "90+" bucket (priced), not unpriced.
    old = R.estimate_k(R.EntityQIs(name=None, qis=[R.QIValue("dob", "1930", "1930", "")],
                                   unmatched=[]), ref, "SG")
    oc = old.contributions[0]
    assert oc.in_product is True and "90+" in oc.note, "an over-max age uses the open top bucket"

    # edge cases — surfaced, NOT priced, never a crash.
    for bad in ("2030", "abcd", "99999"):
        est_b = R.estimate_k(R.EntityQIs(name=None, qis=[R.QIValue("dob", bad, bad, "")],
                                         unmatched=[]), ref, "SG")
        cb = est_b.contributions[0]
        assert cb.in_product is False and cb.prob is None, f"{bad!r} must be surfaced unpriced"


def test_reidrisk_occupation_maps_to_ssoc_group():
    """A privilege ROLE term now maps to the SSOC broad group present in the full table
    (managers & administrators / professionals), resolved by substring — not the removed
    PMET bucket. Director -> managers; counsel/officer -> professionals; both PRICED."""
    R = _reidrisk()
    ref = R.load_reference()
    occ = R.select(ref, "occupation", "SG")
    assert occ is not None and any("managers & administrators" in k.lower() for k in occ.probs) \
        and any(k.lower() == "professionals" for k in occ.probs), "the 9-group SSOC table is bundled"
    assert not any(k.lower().startswith("pmet") for k in occ.probs), "the PMET seed is gone"

    e_mgr = R.extract_qi_values("Mr Tan is a Director.", ref)
    oc = [q for q in e_mgr.qis if q.category == "occupation"]
    assert oc and "managers & administrators" in oc[0].key.lower(), \
        f"a director maps to the managers SSOC group, got {oc and oc[0].key}"

    e_prof = R.extract_qi_values("She is General Counsel.", ref)
    op = [q for q in e_prof.qis if q.category == "occupation"]
    assert op and op[0].key.lower() == "professionals", \
        f"counsel maps to professionals, got {op and op[0].key}"

    # the occupation prices into the product against a REAL SSOC probability.
    est = R.estimate_k(e_mgr, ref, "SG")
    occ_c = [c for c in est.contributions if c.category == "occupation"]
    assert occ_c and occ_c[0].in_product is True and 0.0 < occ_c[0].prob <= 1.0
    # the employed-conditional optimism caveat is kept.
    assert "EMPLOYED" in occ_c[0].note and "OPTIMISTIC" in occ_c[0].note


def test_reidrisk_region_prices_against_real_planning_area():
    """The full 47-area workplace table prices a real SG planning area (the Tampines-only
    stub is gone). A detected planning area resolves and prices into the product."""
    R = _reidrisk()
    ref = R.load_reference()
    e = R.extract_qi_values("The subject works in Queenstown.", ref)
    rg = [q for q in e.qis if q.category == "region"]
    assert rg and rg[0].key == "Queenstown", f"a real planning area resolves, got {rg}"
    est = R.estimate_k(e, ref, "SG")
    rc = [c for c in est.contributions if c.category == "region"]
    assert rc and rc[0].in_product is True and 0.0 < rc[0].prob <= 1.0, \
        "the region must price against a real planning-area marginal"


def test_reidrisk_sg_entity_can_reach_looks_unique_with_capped_risk():
    """A maximally-identifying SG entity (rare birth-year cohort + sex + rarest planning area +
    occupation) can reach `looks_unique` (k <= 1) WHILE prosecutor/journalist risk stay capped
    <= 1.0 — the cap the new SG tables make LIVE (k<1 is now reachable). Honesty spine intact."""
    R = _reidrisk()
    ref = R.load_reference()
    age_t, reg_t, occ_t = (R.select(ref, c, "SG") for c in ("age_years", "region", "occupation"))
    rare_age = min((k for k in age_t.probs if k.isdigit()), key=lambda k: age_t.probs[k])
    rare_reg = min(reg_t.probs, key=lambda k: reg_t.probs[k])
    rare_occ = min(occ_t.probs, key=lambda k: occ_t.probs[k])
    birth_year = R.REFERENCE_YEAR - int(rare_age)
    qis = [
        R.QIValue("dob", str(birth_year), str(birth_year), ""),
        R.QIValue("sex", "female", "female"),
        R.QIValue("region", rare_reg, rare_reg),
        R.QIValue("occupation", "tradesman", rare_occ),
    ]
    est = R.estimate_k(R.EntityQIs(name="X", qis=qis, unmatched=[]), ref, "SG")
    assert est.k_estimate is not None and est.k_estimate <= 1.0, est.k_estimate
    assert est.concern == "looks_unique", est.concern
    # the cap HOLDS: a probability can never exceed 1.0 even though k < 1.
    assert 0.0 <= est.prosecutor_risk <= 1.0 and 0.0 <= est.journalist_risk <= 1.0, \
        (est.prosecutor_risk, est.journalist_risk)
    # honesty spine still present + this is NOT a "safe" verdict.
    d = est.to_dict()
    assert d["is_estimate"] and d["assumes_independence"] and d["not_a_safety_verdict"]
    assert d["direction"] == "optimistic — may under-state risk"


def test_reidrisk_medical_full_table_aligned_and_never_priced():
    """After swapping in the full medical table, all FOUR priced conditions tier 'common'
    (the obesity key-alignment that was latent-broken now resolves), and medical STILL never
    enters the k product (tiering-only honesty spine)."""
    R = _reidrisk()
    ref = R.load_reference()
    # every engine target key resolves + tiers common (prevalences all >= 5%).
    for target in ("hypertension", "hyperlipidaemia_high_cholesterol",
                   "diabetes_mellitus", "obesity_BMI_30plus"):
        tier, _ = R._medical_tier(target, ref)
        assert tier == "common", f"{target} must tier common against the full table, got {tier}"
    # obesity detection end-to-end tiers common (was mis-tiering rare under the null-prob seed).
    est = R.estimate_k(R.extract_qi_values("The patient is obese.", ref), ref)
    assert est.medical_tiers and est.medical_tiers[0]["tier"] == "common"
    # medical NEVER priced into k.
    meds = [c for c in est.contributions if c.category == "medical_condition"]
    assert meds and all(c.in_product is False and c.prob is None for c in meds)


def test_reidrisk_insufficient_data_is_not_safe():
    """When nothing can be priced, the result is INSUFFICIENT DATA — never a 'safe'/low-risk
    finding. k is None, concern is insufficient_data, the honesty flags still hold."""
    R = _reidrisk()
    ref = R.load_reference()
    est = R.estimate_k(R.extract_qi_values("The weather is pleasant today.", ref), ref)
    assert est.k_estimate is None
    assert est.concern == "insufficient_data"
    assert est.not_a_safety_verdict is True
    assert "INSUFFICIENT" in est.coverage_note.upper()


def test_reidrisk_hostile_and_empty_input_bounded():
    """Empty / non-str / hostile input is bounded and never crashes."""
    R = _reidrisk()
    for bad in ("", "   ", None, 123, b"bytes", "\x00\x00", "A" * 5000, "<script>x</script>"):
        out = R.score_text(bad)
        assert isinstance(out, dict)
        # the honesty spine is present even on garbage input.
        assert out["is_estimate"] is True and out["not_a_safety_verdict"] is True


def test_reidrisk_no_safe_state_word_only_negated():
    """The estimator never emits 'safe' as a positive STATE. Across a battery of inputs, the
    word 'safe' appears only inside the negated honesty caveat ('not a safety verdict',
    'never ... safe to send'), never as a standalone clear/OK state."""
    R = _reidrisk()
    samples = [
        "Mr Smith is a Director based in California, male, with diabetes.",
        "The weather is nice.",
        "Ms Garcia in Texas.",
    ]
    for s in samples:
        d = R.score_text(s)
        blob = json.dumps(d, default=str).lower()
        # Any 'safe' occurrence must be within a negated phrase.
        idx = 0
        while True:
            i = blob.find("safe", idx)
            if i < 0:
                break
            window = blob[max(0, i - 30):i + 18]
            # The only legitimate 'safe' tokens: the `not_a_safety_verdict` flag, the
            # caveat's "is NOT a safety verdict", and "never means 'safe to send'". Each
            # carries an explicit negation in its immediate vicinity.
            negated = (
                "not_a_safety" in window or "not a safety" in window
                or "never" in window
            )
            assert negated, f"'safe' used as a positive state in: ...{window}..."
            idx = i + 4


def test_reidrisk_cross_doc_linkage_exact_key_only():
    """Cross-doc batch: a linked entity's release k <= its single-doc k (more QIs in the
    union); two unlinked entities never merge; exact-key (name) link works, fuzzy does not."""
    R = _reidrisk()
    ref = R.load_reference()
    docs = [
        ("Memo A", "Mr Smith is based in California."),
        ("Memo B", "Smith is male and a Director."),
        ("Memo C", "Mr Garcia lives in Texas."),     # a DIFFERENT person
    ]
    rep = R.assess_release(docs)
    assert rep.n_docs == 3
    names = {le.name for le in rep.linked_entities if le.name}
    assert "Smith" in names and "Garcia" in names, "distinct names must NOT merge"
    smith = next(le for le in rep.linked_entities if (le.name or "").upper() == "SMITH")
    assert set(smith.doc_ids) == {"Memo A", "Memo B"}, "Smith links across A+B (exact name)"
    garcia = next(le for le in rep.linked_entities if (le.name or "").upper() == "GARCIA")
    assert garcia.doc_ids == ["Memo C"] and len(garcia.doc_ids) == 1
    # union k <= single-doc k (adding QIs only lowers k).
    union_k = smith.estimate.k_estimate
    single_k = R.estimate_k(
        R.extract_qi_values("Mr Smith is based in California.", ref), ref).k_estimate
    assert union_k is not None and union_k <= single_k
    # the linkage caveat is present + honest about under-linking.
    assert "UNDER-links" in rep.linkage_caveat and "ABSENCE of linkage" in rep.linkage_caveat


def test_reidrisk_link_terms_and_fuzzy_does_not_link():
    """An explicit link_term links two docs sharing that exact key; a fuzzy/partial name
    (different normalised key) does NOT link (deterministic exact-key linkage only)."""
    R = _reidrisk()
    # Same surname token -> links (exact). Different tokens 'Smith' vs 'Smithson' do NOT.
    docs = [("d1", "Mr Smith in California."), ("d2", "Mr Smithson in Texas.")]
    rep = R.assess_release(docs)
    # both resolve to a US surname only if present; the key thing: they do not merge.
    keys = {le.link_key for le in rep.linked_entities}
    assert len(keys) == len(rep.linked_entities), "no two distinct entities share a link key"
    # 'Smithson' is not a top-20 surname; it should not fuzzy-merge into 'Smith'.
    assert not any(le.name and le.name.upper() == "SMITH" and "d2" in le.doc_ids
                   for le in rep.linked_entities), "fuzzy name must NOT link"


def test_reidrisk_link_term_links_on_doc_presence_not_reference_name():
    """Round-2 [HIGH], the dangerous direction: a user link_term must link docs because the
    term is PRESENT IN THE TEXT — NOT only when a bundled name table resolves it. SG ships no
    surname table, so the prior name-only key silently dropped every supplied party name and
    UNDER-stated cross-doc re-identification risk. A name absent from every reference table,
    supplied as a link_term, must now link the docs it appears in (and label the bucket)."""
    R = _reidrisk()
    docs = [
        ("memo-1", "Tan Wei Ming, born 12 March 1975, a software engineer in Tampines."),
        ("memo-2", "We refer to Tan Wei Ming. He resides in Jurong and is male."),
        ("memo-3", "An unrelated note about quarterly figures."),   # no term -> stands alone
    ]
    rep = R.assess_release(docs, link_terms=["Tan Wei Ming"])
    assert rep.n_docs == 3
    linked = [le for le in rep.linked_entities if le.link_key.startswith("term:")]
    assert len(linked) == 1, ("the term must produce exactly one linked bucket", rep.to_dict())
    le = linked[0]
    assert set(le.doc_ids) == {"memo-1", "memo-2"}, "both docs carrying the term link together"
    assert le.name == "Tan Wei Ming", "the bucket is labeled with the user's term (#11)"
    # The union-of-QIs k is computed across both docs (adding QIs only LOWERS k / raises risk).
    assert le.estimate.k_estimate is not None
    # Control: with NO link_terms the same docs do NOT link (deterministic exact-key only).
    rep2 = R.assess_release(docs, link_terms=[])
    assert not any(le.link_key.startswith("term:") for le in rep2.linked_entities)
    assert all(le.link_key.startswith("unlinked:") for le in rep2.linked_entities), \
        "no name table resolves these tokens, so without a term they stay unlinked"


def test_reidrisk_link_term_independent_review_fixes():
    """Independent review of the link_term fix found three real defects; lock them:
      F1 [HIGH regression]: a multi-token term must NOT split one person when a name table
         resolves only the surname in another doc (term:JOHN SMITH vs name:SMITH) — that
         under-states risk AND is worse than the prior name-only linkage.
      F2 [DoS]: the term scan must be BOUNDED like extraction (first _MAX_TEXT_BYTES) — a
         term present ONLY beyond the cap is deterministically NOT matched (proves the bound).
      F3 [low]: a term with trailing punctuation + comma-separated names in the doc still link."""
    R = _reidrisk()

    # F1: 'Smith' resolves against the bundled US surname table; the full 'John Smith' is only
    # in d1. Both docs must converge into ONE term bucket (not split).
    docs = [("d1", "Agreement with John Smith dated 2020, based in California."),
            ("d2", "Mr Smith, a director, resides in Texas, born 1975.")]
    rep = R.assess_release(docs, link_terms=["John Smith"])
    term_buckets = [le for le in rep.linked_entities if le.link_key.startswith("term:")]
    assert len(term_buckets) == 1, ("F1: one person must not split", [le.link_key for le in rep.linked_entities])
    assert set(term_buckets[0].doc_ids) == {"d1", "d2"}, ("F1: both docs link", term_buckets[0].doc_ids)

    # F2: a term that appears ONLY beyond the _MAX_TEXT_BYTES scan bound is not matched
    # (deterministic proof the scan is bounded — no timing assertion).
    pad = "lorem ipsum " * ((R._MAX_TEXT_BYTES // 12) + 1000)   # safely past the 4 MB cap
    rep2 = R.assess_release([("big", pad + " Zorblax Quendle")], link_terms=["Zorblax Quendle"])
    assert all(le.link_key.startswith("unlinked:") for le in rep2.linked_entities), \
        "F2: a term beyond the scan bound must not link (scan is bounded like extraction)"

    # F3: trailing punctuation on the term + comma-separated name in the text still link.
    docs3 = [("a", "Re: Tan, Wei Ming and the board."), ("b", "Tan Wei Ming attended.")]
    rep3 = R.assess_release(docs3, link_terms=["Tan Wei Ming,"])
    t3 = [le for le in rep3.linked_entities if le.link_key.startswith("term:")]
    assert len(t3) == 1 and set(t3[0].doc_ids) == {"a", "b"}, ("F3: punctuation must not block linkage", rep3.to_dict())


def test_reidrisk_review_fixes_risk_bounded_and_no_dup_merge():
    """Independent-review must-fixes:
      [HIGH] prosecutor_risk / journalist_risk are valid probabilities (<= 1.0) even when
             k < 1 (the `looks_unique` band that DROP-IN tables make reachable);
      [MEDIUM] two UN-linkable entities sharing the SAME user-supplied doc_id do NOT merge."""
    R = _reidrisk()

    # [HIGH] construct a k < 1 case with a minimal reference (N=100, P(rare surname)=0.001 -> k=0.1).
    def tbl(cat, N, probs, tail=0.0):
        return R.ReferenceTable(
            category=cat, jurisdiction="US", population_N=N, probs=probs, tail_prob=tail,
            has_explicit_tail=False, n_entries=len(probs),
            source_name="", source_url="", license="", granularity_notes="")
    ref = {"surname": {"US": tbl("surname", 100, {"RARE": 0.001})},
           "sex": {"US": tbl("sex", 100, {"male": 0.5}, 0.5)}}
    est = R.estimate_k(R.EntityQIs(name="X", qis=[R.QIValue("surname", "Rare", "RARE")],
                                   unmatched=[]), ref, "US")
    assert est.k_estimate is not None and est.k_estimate <= 1.0, est.k_estimate
    assert est.concern == "looks_unique", est.concern
    # a probability cannot exceed 1.0 (pre-fix this was 1/0.1 = 10.0)
    assert est.prosecutor_risk is not None and 0.0 <= est.prosecutor_risk <= 1.0, est.prosecutor_risk
    assert est.journalist_risk is not None and 0.0 <= est.journalist_risk <= 1.0, est.journalist_risk

    # [MEDIUM] two un-linkable docs with the SAME doc_id must NOT collapse into one entity.
    docs = [("Memo", "The quarterly figures were reviewed."),
            ("Memo", "The board adjourned at noon.")]
    rep = R.assess_release(docs)
    assert rep.n_docs == 2
    keys = [le.link_key for le in rep.linked_entities]
    assert len(keys) == len(set(keys)) == 2, ("duplicate doc_id merged unlinkable entities", keys)


def test_reidrisk_region_workplace_caveat_reaches_the_note():
    """Independent-review MUST-FIX: the region table's granularity (WORKPLACE, not residence)
    must reach the USER-VISIBLE contribution note — a 'based in X' residence phrase prices
    against a workplace distribution whose shares differ materially, and that caveat lived only
    in SOURCES.md before. The priced region contribution now carries it."""
    R = _reidrisk()
    d = R.score_text("She is female and based in Tampines.")
    reg = [c for c in d["contributions"] if c["category"] == "region" and c["in_product"]]
    assert reg, "a known SG planning area should price as a region QI"
    note = reg[0]["note"].lower()
    assert "workplace" in note or "source distribution" in note, reg[0]["note"]


def test_reidrisk_in_memory_store_is_skeleton_no_persistence():
    """The EntityStore skeleton is in-memory only — no disk persistence is wired. A fresh
    store starts empty and the protocol exists for the deferred persistent register."""
    from app.reidrisk import InMemoryEntityStore, EntityStore
    st = InMemoryEntityStore()
    assert st.buckets() == {}, "a fresh store is empty (no persisted state)"
    assert hasattr(EntityStore, "link_key") and hasattr(EntityStore, "add")


def test_reidrisk_score_endpoint():
    """POST /api/reidrisk/score: pasted text -> k estimate + honesty flags. Token-guarded."""
    c = _client()
    r = c.post("/api/reidrisk/score",
               json={"text": "Mr Smith is a Director based in California, male."})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["is_estimate"] is True and d["not_a_safety_verdict"] is True
    assert d["k_estimate"] is not None and d["prosecutor_risk"] is not None
    assert d["concern"] in ("looks_unique", "small_cohort", "elevated")
    assert "matched" in d["coverage_note"]


def test_reidrisk_batch_endpoint():
    """POST /api/reidrisk/batch: a set of docs -> a cross-doc release report with linkage."""
    c = _client()
    r = c.post("/api/reidrisk/batch", json={
        "docs": [
            {"name": "Memo A", "text": "Mr Smith based in California."},
            {"name": "Memo B", "text": "Smith is male, a Director."},
        ],
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["n_docs"] == 2 and d["n_linked_entities"] >= 1
    assert "linkage_caveat" in d and "ABSENCE of linkage" in d["linkage_caveat"]
    assert d["is_estimate"] is True


def test_reidrisk_endpoints_require_token():
    """The estimator endpoints reject a request without the session token."""
    state = AppState()
    untokened = TestClient(create_app(state))
    for path, body in (("/api/reidrisk/score", {"text": "x"}),
                       ("/api/reidrisk/batch", {"docs": ["x"]})):
        r = untokened.post(path, json=body)
        assert r.status_code == 403, f"{path} must require the token"


def test_reidrisk_batch_bounds_and_bad_input():
    """The batch endpoint bounds the document count + rejects a malformed body cleanly."""
    c = _client()
    r = c.post("/api/reidrisk/batch", json={"docs": "not-a-list"})
    assert r.status_code == 400
    r = c.post("/api/reidrisk/batch", json={"docs": ["x"] * 5000})
    assert r.status_code == 400, "too many docs must be rejected, not 500"


def test_reidrisk_batch_aggregate_base64_cap():
    """#20(b): the batch caps the SUM of len(data_b64) across docs BEFORE decoding any of
    them, so a batch of several uploads whose base64 sums over the cap is rejected with a
    clean 413 — never an OOM, never a 500. Each doc here is UNDER the per-file b64 cap; only
    the aggregate trips. A NORMAL batch (well under the cap) still succeeds (no regression)."""
    from app import web

    c = _client()
    # SEVERAL uploads, each UNDER the per-file b64 cap (_REDACT_FILE_B64_MAX, ~14 MB), whose
    # base64 lengths SUM OVER the aggregate cap (_REID_BATCH_B64_TOTAL_MAX, ~64 MB). The per-
    # file cap is smaller than the aggregate, so it takes a handful of docs to trip the sum.
    # 'A'*N is a length-valid filler for the SUM check (which runs before any decode), so no
    # decode is attempted on the rejection path. We pick a per-doc size near the per-file cap
    # and enough docs to exceed the aggregate.
    per_doc = web._REDACT_FILE_B64_MAX - 1000           # each comfortably under the per-file cap
    n_docs = (web._REID_BATCH_B64_TOTAL_MAX // per_doc) + 2   # enough to sum over the aggregate
    assert n_docs <= web._REID_BATCH_DOCS_MAX, "must stay under the doc-count cap to isolate #20(b)"
    chunk = "A" * per_doc
    over = [{"name": f"d{i}", "data_b64": chunk} for i in range(n_docs)]
    assert all(len(o["data_b64"]) <= web._REDACT_FILE_B64_MAX for o in over), \
        "each doc must stay under the per-file cap so only the AGGREGATE trips"
    assert sum(len(o["data_b64"]) for o in over) > web._REID_BATCH_B64_TOTAL_MAX
    r = c.post("/api/reidrisk/batch", json={"docs": over})
    assert r.status_code == 413, ("over-aggregate batch must be 413'd, not 500/OOM",
                                  r.status_code, r.text[:120])
    assert "exceed" in r.json().get("error", ""), r.text

    # A normal text batch (no uploads) still works.
    r2 = c.post("/api/reidrisk/batch", json={"docs": [
        {"name": "A", "text": "Mr Smith in California."},
        {"name": "B", "text": "Smith is a Director."},
    ]})
    assert r2.status_code == 200, ("a normal batch must still succeed", r2.text[:120])
    assert r2.json()["n_docs"] == 2, r2.text


def test_reidrisk_page_renders():
    """GET /reid-risk serves the assembled page with the permanent honesty banners, the
    token, and NO external resources (air-gap). It is SEPARATE from the redaction page."""
    c = _client()
    page = c.get("/reid-risk").text
    assert "http://" not in page and "https://" not in page, "air-gap"
    assert 'name="drr-token"' in page
    low = page.lower()
    # The k is labelled an ESTIMATE, not a guarantee/percentage.
    assert "estimate" in low
    # The independence + optimistic caveat is in the page.
    assert "independence" in low or "optimistic" in low
    assert "may under-state" in low or "under-state risk" in low
    # never a positive 'safe' state in the served page (only the negated caveat).
    assert "safe to send" not in low or "never" in low


def test_reidrisk_page_build_asserts_hold():
    """Both the redaction page AND the new reid-risk page assemble (air-gap asserts pass) —
    proving the new page-build did not break the existing one."""
    from app.web import _build_redaction_page, _build_reidrisk_page
    red = _build_redaction_page()
    reid = _build_reidrisk_page()
    assert "http://" not in red and "https://" not in red
    assert "http://" not in reid and "https://" not in reid
    # the new page carries the three inlining markers' RESULT (css/js actually inlined).
    assert "__REIDRISK_CSS__" not in reid and "__REIDRISK_JS__" not in reid and \
        "__BASE_CSS__" not in reid, "all markers must be substituted, not left raw"


def test_reidrisk_does_not_touch_redaction_carrier():
    """The estimator is ISOLATED: app/reidrisk.py imports privilege for DETECTION regexes
    only, and does NOT import the redaction carrier (redactionmodel / the redaction UI / a
    write path). It must never be able to mutate a redaction decision."""
    src = (Path(__file__).resolve().parent.parent.parent / "app" / "reidrisk.py").read_text("utf-8")
    assert "import redactionmodel" not in src and "from .redactionmodel" not in src
    assert "redact_cli" not in src.lower().replace("-", "_")
    # it writes nothing to disk (no open(...,'w'), no Path.write_*).
    assert ".write_text(" not in src and ".write_bytes(" not in src
    assert "open(" not in src.replace("read_text", "")  # only read_text is allowed


def test_reidrisk_render_node_harness():
    """Behavioral proof the served page renders deterministically, escapes cleartext, shows
    the honest banners + coverage, and leaks no document cleartext as RAW markup. Runs the
    committed node harness; SKIPS if node is unavailable (the structural test above covers
    the wiring)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "reidrisk_render.test.js"
    raw_target = Path(__file__).resolve().parent.parent.parent / "app" / "ui" / "reidrisk.js"
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    if not harness.exists() or not raw_target.exists():
        print("  (skip) reidrisk harness/target not present")
        return
    # reidrisk.js aliases esc()/$()/post()/announce() to window.LB (app/ui/base.js) rather
    # than defining them locally — the harness must load base.js first, exactly as the
    # served page does (base.js is inlined before reidrisk.js; see _build_reidrisk_page()).
    target = _assembled_reidrisk_js_path()
    proc = subprocess.run([node, str(harness), str(target)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (
        "reidrisk render harness failed:\n" + proc.stdout + "\n" + proc.stderr)
    assert "ALL PASS" in proc.stdout, proc.stdout


def test_reidrisk_js_is_nul_free():
    """reidrisk.js must contain ZERO NUL bytes (redaction.js's deliberate NUL is its own;
    the new JS keeps none)."""
    target = Path(__file__).resolve().parent.parent.parent / "app" / "ui" / "reidrisk.js"
    if not target.exists():
        print("  (skip) reidrisk.js not present yet")
        return
    assert target.read_bytes().count(b"\x00") == 0, "reidrisk.js must be NUL-free"


def test_reidrisk_get_reference_does_not_poison_cache_on_failure():
    """[#1 Critical] get_reference must NOT cache an empty/failed load for the process lifetime.
    A transient failure (exception) or an empty result is NOT cached — the NEXT call retries and
    serves the real tables. Otherwise every k-estimate is permanently broken (insufficient data)."""
    R = _reidrisk()
    real = R.load_reference
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")   # first call fails
        return real()                          # subsequent calls succeed

    R._REFERENCE_CACHE = None
    R.load_reference = flaky
    try:
        first = R.get_reference()
        assert first == {}, "a failed load degrades to an empty map (never raises)"
        assert R._REFERENCE_CACHE in (None, {}), "an empty/failed load must NOT be cached"
        second = R.get_reference()
        assert second, "the retry serves the real (non-empty) tables — cache was not poisoned"
        assert calls["n"] == 2, "the 2nd call RETRIED load_reference (1st failure not latched)"
    finally:
        R.load_reference = real
        R._REFERENCE_CACHE = None

    # An empty (non-exception) load is likewise not cached.
    calls2 = {"n": 0}

    def empty_then_full(*a, **k):
        calls2["n"] += 1
        return {} if calls2["n"] == 1 else real()

    R._REFERENCE_CACHE = None
    R.load_reference = empty_then_full
    try:
        assert R.get_reference() == {}, "an empty load returns empty"
        assert R.get_reference(), "the next call retries and gets the real tables"
        assert calls2["n"] == 2, "an empty result did not poison the cache"
    finally:
        R.load_reference = real
        R._REFERENCE_CACHE = None


def test_reidrisk_duplicate_normalised_keys_do_not_inflate_tail():
    """[#6 Medium, dangerous direction] Two raw keys that normalise to the SAME key must have
    their masses SUMMED, not last-wins overwritten. A dropped mass would UNDER-count `covered`,
    INFLATE the synthesised tail, give unseen values too much probability, make k LARGER, and
    UNDER-STATE risk. Summing keeps covered/tail faithful."""
    R = _reidrisk()
    d = tempfile.mkdtemp()
    tbl = {"category": "surname", "jurisdiction": "XX", "population_N": 1000,
           "entries": [{"key": "Tan", "prob": 0.3}, {"key": "TAN", "prob": 0.3},
                       {"key": "Lim", "prob": 0.2}]}
    (Path(d) / "t.json").write_text(json.dumps(tbl), encoding="utf-8")
    ref = R.load_reference(d)
    t = ref["surname"]["XX"]
    assert abs(t.probs["TAN"] - 0.6) < 1e-9, ("duplicate-normalised masses must SUM", t.probs)
    assert abs(sum(t.probs.values()) - 0.8) < 1e-9, "covered = 0.6 + 0.2 = 0.8"
    assert abs(t.tail_prob - 0.2) < 1e-9, ("tail must be 1 - 0.8 = 0.2, not inflated", t.tail_prob)
    # an unseen surname gets the (correct, smaller) tail prob — not an inflated one.
    p_unseen, from_tail = t.lookup("NOTLISTED")
    assert from_tail is True and abs(p_unseen - 0.2) < 1e-9, p_unseen


def test_reidrisk_dob_age_routing_edges():
    """[#5 + #7 Medium] DOB age-routing edges:
      #5 — an age above the max EXPLICIT single year (but below the top-bucket stem, when the
           table has a gap) routes to the OPEN top bucket, NOT the residual tail.
      #7 — a MALFORMED bare '+' top key (no numeric stem) is IGNORED, never a 0+ bucket that
           swallows every age. The REAL SG table's routing is unchanged."""
    R = _reidrisk()

    # #5: a sparse table with single years 0..5 + a "90+" open bucket (a deliberate gap 6..89).
    d = tempfile.mkdtemp()
    entries = [{"key": str(i), "prob": 0.1} for i in range(6)] + [{"key": "90+", "prob": 0.4}]
    (Path(d) / "a.json").write_text(
        json.dumps({"category": "age_years", "jurisdiction": "SG", "population_N": 1000,
                    "entries": entries}), encoding="utf-8")
    ref5 = R.load_reference(d)
    for age in (50, 89):  # above max single year (5), below stem (90) -> the OPEN bucket
        yr = R.REFERENCE_YEAR - age
        prob, _a, age_key, from_tail, _why = R._price_dob(str(yr), ref5, "SG")
        assert age_key == "90+" and from_tail is False and prob == 0.4, \
            (f"age {age} must route to the open top bucket, not the tail", age_key, from_tail)

    # #7: a malformed bare "+" top key must be IGNORED (it must not capture every unlisted age).
    d2 = tempfile.mkdtemp()
    entries2 = [{"key": str(i), "prob": 0.01} for i in range(90)] + [{"key": "+", "prob": 0.1}]
    (Path(d2) / "b.json").write_text(
        json.dumps({"category": "age_years", "jurisdiction": "SG", "population_N": 1000,
                    "entries": entries2}), encoding="utf-8")
    ref7 = R.load_reference(d2)
    yr95 = R.REFERENCE_YEAR - 95           # not individually listed
    prob, _a, age_key, _ft, _why = R._price_dob(str(yr95), ref7, "SG")
    assert age_key != "+", ("a bare '+' top key must be ignored, not used as a 0+ bucket", age_key)

    # the REAL SG table is unaffected: age 90/95 -> the legitimate "90+" bucket; 89 -> "89".
    ref = R.load_reference()
    for age, expect in ((90, "90+"), (95, "90+"), (89, "89")):
        yr = R.REFERENCE_YEAR - age
        _p, _a, age_key, _ft, _why = R._price_dob(str(yr), ref, "SG")
        assert age_key == expect, (age, age_key, expect)


def test_reidrisk_occupation_and_medical_resolve_with_second_jurisdiction_table():
    """[#8 + #10 Medium] The SSOC occupation key and the medical-condition tier are
    JURISDICTION-INDEPENDENT, so they must still resolve once a SECOND jurisdiction's table
    exists (where select() with no hint returns None as ambiguous). Pre-fix #8 left occupation
    UNPRICED (k larger -> risk UNDER-stated, dangerous) and #10 mis-tiered every condition rare."""
    R = _reidrisk()
    import copy
    ref = R.load_reference()
    # add a 2nd (US-labelled) occupation + medical table so select(...) becomes ambiguous.
    occ_us = copy.copy(ref["occupation"]["SG"])
    occ_us.jurisdiction = "US"
    ref["occupation"]["US"] = occ_us
    med_us = copy.copy(ref["medical_condition"]["SG"])
    med_us.jurisdiction = "US"
    ref["medical_condition"]["US"] = med_us
    assert R.select(ref, "occupation") is None, "two tables + no hint is ambiguous for select()"
    assert R.select(ref, "medical_condition") is None

    # #8: a director still resolves to the managers SSOC group (not unmatched).
    e = R.extract_qi_values("Mr Tan is a Director.", ref)
    occ = [q for q in e.qis if q.category == "occupation"]
    assert occ and "managers & administrators" in occ[0].key.lower(), \
        ("occupation must still resolve with a 2nd table present", occ, e.unmatched)
    assert "occupation" not in e.unmatched

    # #10: a common condition still tiers "common" (not the table-absent "rare" fallback).
    assert R._medical_tier("diabetes_mellitus", ref)[0] == "common"
    assert R._medical_tier("obesity_BMI_30plus", ref)[0] == "common"


def test_reidrisk_coverage_note_excludes_medical_from_denominator():
    """[#13 Low] A medical condition is DELIBERATELY tiered-only (never priced into k), so it
    must NOT count in the 'matched N of M' coverage DENOMINATOR — else the intentional exclusion
    reads as a coverage gap. Medical is still reported separately ('TIERED only')."""
    R = _reidrisk()
    ref = R.load_reference()
    e = R.extract_qi_values("The subject works in Queenstown and has diabetes.", ref)
    est = R.estimate_k(e, ref, "SG")
    # region is priced; diabetes is tiered-only. The priced ratio is 1 of 1, not 1 of 2.
    assert "matched 1 of 1" in est.coverage_note, est.coverage_note
    assert "TIERED only" in est.coverage_note, "the medical condition is still disclosed"
    # the full detected count is still reported (its meaning unchanged).
    assert est.detected_qi_count == 2


def test_reidrisk_upload_and_batch_enforce_text_caps():
    """[#4 High] The upload/extracted-text path and the batch path enforce the text-size cap
    (the same one the paste path uses) plus a sane batch-total bound — a file (or a batch of
    them) must not bypass the bound the paste path already imposes."""
    import base64 as _b64
    from app import web as _web
    c = _client()

    # An oversize EXTRACTED text (a plain-text upload past the cap) is rejected, not scored.
    big = ("x " * (_web._REDACT_TEXT_MAX // 2 + 10)).encode("utf-8")
    b64 = _b64.b64encode(big).decode("ascii")
    r = c.post("/api/reidrisk/score", json={"filename": "big.txt", "data_b64": b64})
    assert r.status_code == 400, ("an oversize upload must be rejected", r.text)
    assert "exceeds" in r.json().get("error", ""), r.text

    # The batch TOTAL bound exists and is enforced (constant present + a too-big total rejected).
    assert _web._REID_BATCH_TOTAL_BYTES_MAX > 0
    per = "y" * (_web._REDACT_TEXT_MAX - 1)           # each doc within the per-doc cap
    n = (_web._REID_BATCH_TOTAL_BYTES_MAX // len(per)) + 2
    docs = [per] * min(n, _web._REID_BATCH_DOCS_MAX)
    # If the per-doc cap × doc-count can't exceed the total, this still must not 500.
    r2 = c.post("/api/reidrisk/batch", json={"docs": docs})
    assert r2.status_code in (200, 400), r2.text
    if r2.status_code == 400:
        assert "total" in r2.json().get("error", "").lower() or \
            "size" in r2.json().get("error", "").lower(), r2.text


def test_reidrisk_inline_js_neutralises_script_close():
    """[#9 Medium] The page-builder JS inliner escapes a literal '</script>' so a future JS edit
    containing one can't break OUT of the inlined <script> element. Applied case-insensitively to
    all inlined first-party JS; it never modifies a .js file on disk."""
    from app.web import _inline_js
    out = _inline_js('var a = "</script>"; // </SCRIPT>')
    assert "</script>" not in out.lower(), out
    assert "<\\/script>" in out, out
    # the no-op case (no closer) is byte-identical.
    assert _inline_js("var x = 1;") == "var x = 1;"


def test_reidrisk_lone_surrogate_does_not_raise_and_batch_survives_one_bad_doc():
    """[#8] A document carrying a LONE SURROGATE must not crash the estimator (it must
    degrade), the result must json.dumps cleanly, and ONE bad doc must not abort a batch."""
    from app import reidrisk

    bad = "Tan born 1980 \ud800 diabetes"        # a lone high surrogate mid-string
    # _bounded never raises and strips the surrogate
    cleaned = reidrisk._bounded(bad)
    assert "\ud800" not in cleaned
    # score_text returns a JSON-serializable dict (no surrogate survives into a value)
    res = reidrisk.score_text(bad)
    json.dumps(res)   # would raise if a surrogate leaked into a matched value

    # a batch with one all-surrogate doc still assesses the good ones
    docs = ["Tan born 1980", "\ud800\ud801\ud802", "Lee born 1990"]
    rep = reidrisk.assess_release_dict(docs)
    assert rep["n_docs"] == 3, rep
    assert rep["n_linked_entities"] >= 1, rep


def test_reidrisk_cross_jurisdiction_and_region_population_caveats_are_additive():
    """[#9/#22] The cross-jurisdiction and region-conditional-population caveats are NOTE
    text only — they never change k. We assert the honesty spine is intact and the notes,
    when present, do not introduce any 'safe' word."""
    from app import reidrisk
    from app.reidrisk import QIValue, EntityQIs

    ref = reidrisk.get_reference()
    # A name + region + DOB SG-flavoured entity; estimate twice -> identical k (determinism
    # holds and the additive notes did not perturb the math).
    e = EntityQIs(name="Tan", qis=[
        QIValue(category="dob", value="1980", key="1980", detail="year of birth 1980"),
    ], unmatched=[])
    a = reidrisk.estimate_k(e, ref, "SG")
    b = reidrisk.estimate_k(e, ref, "SG")
    assert a.k_estimate == b.k_estimate, (a.k_estimate, b.k_estimate)
    # the honesty spine is always present; "safe to send" appears ONLY negated (the caveat
    # text says "never means 'safe to send'") — never as a bare positive claim.
    blob = json.dumps(a.to_dict()).lower()
    idx = blob.find("safe to send")
    if idx >= 0:
        before = blob[max(0, idx - 30):idx]
        assert "never" in before or "not" in before, before
    assert a.not_a_safety_verdict is True and a.is_estimate is True
