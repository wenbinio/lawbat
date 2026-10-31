// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Messy-corpus redaction BASELINE — a red-team catch/miss harness.
//!
//! This is a QA / red-team integration test, NOT an engine change. It feeds the
//! CURRENT deterministic redaction engine a deliberately MESSY, fully SYNTHETIC
//! corpus (four realistic genres) and reports an HONEST catch/miss baseline:
//! per-category recall, the false-positive list, and the per-recognizer breakdown.
//!
//! ## HARD RULE — SYNTHETIC ONLY (CLAUDE.md non-negotiable)
//!
//! Every identifier here is FABRICATED and FICTIONAL. Where a positive match is
//! wanted the value is FORMAT-valid (and checksum-valid where the recognizer
//! checks one), but it is a well-known TEST value or an explicitly reserved range:
//!   * card `4111 1111 1111 1111` — the canonical Visa TEST PAN (Luhn-valid);
//!   * IBAN `GB82 WEST 1234 5698 7654 32` — the published example IBAN (mod-97-valid);
//!   * IPs from RFC 5737 (`192.0.2.0/24`) and RFC 3849 (`2001:db8::/32`) — reserved
//!     for documentation, never routable;
//!   * emails / URLs on `example.com` / `example.org` (RFC 2606 reserved);
//!   * SG NRIC `S1234567D` — format-only fictional (check letter not verified);
//!   * names like "Dr. Tan Wei Ming", "Jane Aretha Doe" — invented.
//!
//! NO real personal data is present, in dev or in test, ever.
//!
//! ## What "expected to catch" means (read before trusting the matrix)
//!
//! The engine is RECALL-FIRST and deliberately BROAD. The two broadest built-ins —
//! `phone` (any digit run >= 7) and `id` (uppercase-letters + a 3+ digit run) —
//! INCIDENTALLY cover many identifiers for which there is NO dedicated recognizer
//! yet (an SSN, an EIN, an ABA routing no., an NPI, an MRN, a plain account no. all
//! land as `phone`; a DEA no. lands as `id`). The honest question a redaction tool
//! must answer is "was the identifier SPAN removed at all?" — so each planted
//! instance carries `expected_covered`: TRUE iff today's engine produces a hit whose
//! `[start,end)` covers the instance (by ANY recognizer). It ALSO carries
//! `dedicated`: whether a recognizer PURPOSE-BUILT for that category exists (the
//! global built-ins — now incl. the structured-address family — + the SG NRIC locale
//! pack). The gap this corpus proves is the
//! `dedicated == false` set: identifiers caught only incidentally (fragile — a
//! reformat drops them below the digit-run threshold) or missed outright.
//!
//! The test ASSERTS only the TODAY baseline (`expected_covered` instances ARE
//! covered; decoys flagged `expect_clean` are NOT). It prints — never asserts — the
//! gaps, so it stays green on the current engine and becomes a REGRESSION BASELINE
//! to tighten as the cross-domain fan-out lands (flip an instance's `expected_covered`
//! from false to true when its dedicated recognizer ships; the assert then guards it).

use std::collections::BTreeMap;

use redaction::{BuiltinRecognizers, Locale, RedactionCandidate, RedactionEngine};

// ===================================================================
// Ground-truth model
// ===================================================================

/// A planted, fully-synthetic PII instance with its honest ground truth.
struct Planted {
    /// The EXACT substring as it appears in the document (must be findable verbatim).
    text: &'static str,
    /// The PII category (ssn / ein / aba / npi / dea / nric / nhs / nino / card /
    /// iban / email / phone / ip / url / name / date / age / mrn / account / swift ...).
    category: &'static str,
    /// Jurisdiction (us / uk / sg / intl) — context only, not asserted.
    jurisdiction: &'static str,
    /// Does today's engine produce a hit whose span COVERS this instance (by ANY
    /// recognizer, incidental or dedicated)? The harness ASSERTS this.
    expected_covered: bool,
    /// Does a recognizer PURPOSE-BUILT for this category exist today (vs. covered
    /// only incidentally by the broad phone/id recognizers, or missed)? Printed,
    /// not asserted — it is what separates "robustly caught" from "fan-out target".
    dedicated: bool,
}

impl Planted {
    const fn new(
        text: &'static str,
        category: &'static str,
        jurisdiction: &'static str,
        expected_covered: bool,
        dedicated: bool,
    ) -> Self {
        Self {
            text,
            category,
            jurisdiction,
            expected_covered,
            dedicated,
        }
    }
}

/// A planted innocuous DECOY — text that must NOT be treated as PII. `expect_clean`
/// = the engine should produce NO hit covering it; FALSE means we KNOW the
/// recall-first engine false-positives here and we document the FP rather than
/// asserting it away (printed loudly, never silently tolerated).
struct Decoy {
    text: &'static str,
    note: &'static str,
    expect_clean: bool,
}

impl Decoy {
    const fn new(text: &'static str, note: &'static str, expect_clean: bool) -> Self {
        Self {
            text,
            note,
            expect_clean,
        }
    }
}

/// One document in the corpus: a genre name, its (messy) text, its planted PII, and
/// its decoys.
struct Doc {
    name: &'static str,
    text: &'static str,
    planted: &'static [Planted],
    decoys: &'static [Decoy],
}

// ===================================================================
// Document 1 — LEGAL: engagement / closing letter (messy formatting)
// ===================================================================
//
// Messiness exercised: PII glued to word chars (email after a colon, no space),
// a CSV-ish parties table, an SSN/EIN in a US matter mixed with an SG NRIC (two
// jurisdictions in one doc), and innocuous reference numbers (a clause no., a
// statute section, a dollar figure) that must not over-flag (some of which the
// broad `id` recognizer flags anyway).

const LEGAL: &str = "\
PRIVILEGED & CONFIDENTIAL — ENGAGEMENT LETTER (SYNTHETIC TEST DOCUMENT)\n\
Matter No. M-2026-0042  |  Client file ref: ABC123\n\
\n\
Dear Dr. Tan Wei Ming,\n\
We confirm our engagement re the sale of 14 Marina View. Primary contact\n\
email is jane.doe@example.com; please copy paul.lim@example.org on all\n\
correspondence. Direct line: +65 6123 4567 (fax (65) 6123-9999).\n\
\n\
PARTIES,ROLE,ID\n\
Jane Aretha Doe,Seller,S1234567D\n\
Acme Holdings LLC,Buyer,EIN 12-3456789\n\
Mr. Robert K. Ellison,Guarantor,SSN 078-05-1120\n\
\n\
Trust account for completion: account 000123456789 at the firm's bank.\n\
Our fee estimate is USD 1,250,000.00 plus disbursements (see clause 7.2.1).\n\
This engagement is governed by Section 230 of the Conveyancing Act.\n\
Yours faithfully, Messrs. Tan & Partners.\n";

const LEGAL_PLANTED: &[Planted] = &[
    // name heuristic — title-prefixed, DEDICATED + caught.
    Planted::new("Dr. Tan Wei Ming", "name", "sg", true, true),
    Planted::new("Mr. Robert K. Ellison", "name", "us", true, true),
    Planted::new("Messrs. Tan & Partners", "name", "sg", true, true),
    // name WITHOUT a title — heuristic misses it (no NER). MISS, no dedicated cover.
    Planted::new("Jane Aretha Doe", "name", "sg", false, false),
    // emails — DEDICATED + caught (one glued after a colon/semicolon).
    Planted::new("jane.doe@example.com", "email", "intl", true, true),
    Planted::new("paul.lim@example.org", "email", "intl", true, true),
    // phones — DEDICATED + caught (intl + a parenthesised fax).
    Planted::new("+65 6123 4567", "phone", "sg", true, true),
    Planted::new("(65) 6123-9999", "phone", "sg", true, true),
    // SG NRIC — DEDICATED via the opt-in Singapore locale pack + caught.
    Planted::new("S1234567D", "nric", "sg", true, true),
    // Matter number — caught only INCIDENTALLY by the broad `id` recognizer (no
    // dedicated matter-no recognizer); covered today, fragile.
    Planted::new("M-2026-0042", "matter_no", "intl", true, false),
    // US EIN — NO dedicated recognizer; the 9-digit run is caught INCIDENTALLY by
    // `phone`. Covered today but a reformat (e.g. "12 3456789") could drop it.
    Planted::new("12-3456789", "ein", "us", true, false),
    // US SSN — NO dedicated recognizer; the dashed 9-digit run is caught
    // INCIDENTALLY by `phone`. Covered today, fragile, mis-attributed.
    Planted::new("078-05-1120", "ssn", "us", true, false),
    // Plain trust-account number — NO dedicated recognizer; 12-digit run caught
    // INCIDENTALLY by `phone`.
    Planted::new("000123456789", "account", "sg", true, false),
    // STRUCTURED street address — now DEDICATED + caught by the global address
    // recognizer (number + Capitalized street name + the `View` street-type suffix).
    Planted::new("14 Marina View", "address", "sg", true, true),
];

const LEGAL_DECOYS: &[Decoy] = &[
    Decoy::new(
        "clause 7.2.1",
        "clause reference (dotted), must stay clean",
        true,
    ),
    Decoy::new("Section 230", "statute section, must stay clean", true),
    Decoy::new("USD 1,250,000.00", "money figure, must stay clean", true),
    // KNOWN recall-first FP: the broad `id` recognizer flags an UPPERCASE-letters +
    // 3-digit token, so a client file ref like "ABC123" is wrongly flagged. We
    // DOCUMENT this rather than assert it away.
    Decoy::new("ABC123", "client file ref — FALSE POSITIVE as `id`", false),
];

// ===================================================================
// Document 2 — MEDICAL: discharge summary (HIPAA identifiers, messy)
// ===================================================================
//
// Messiness exercised: identifiers glued to labels, an age > 89 (an HIPAA
// Safe-Harbor identifier), dates of birth in two formats, an MRN / NPI / DEA in a
// clinical-table style, and a fax number. Most of these have NO dedicated
// recognizer — the discharge summary is the corpus's densest GAP cluster.

const MEDICAL: &str = "\
DISCHARGE SUMMARY — SYNTHETIC TEST RECORD (NOT A REAL PATIENT)\n\
Patient: Mr. Albert Two-Names    MRN: 00847221    DOB: 1933-04-02\n\
Age 92 years old. Alt DOB on intake form: 04/02/1933.\n\
SSN on file: 078-05-1120. Contact phone 312-555-0186, fax 312-555-7700.\n\
Patient email albert.twonames@example.com.\n\
Attending: Dr. Susan Ng, NPI 1234567893. Rx by DEA AB1234563.\n\
Discharged to 221B Baker Street. Follow-up 2026-07-15 at 10:30 AM.\n";

const MEDICAL_PLANTED: &[Planted] = &[
    // names — title-prefixed, DEDICATED + caught.
    Planted::new("Mr. Albert Two-Names", "name", "us", true, true),
    Planted::new("Dr. Susan Ng", "name", "us", true, true),
    // MRN — NO dedicated recognizer; 8-digit run caught INCIDENTALLY by `phone`.
    Planted::new("00847221", "mrn", "us", true, false),
    // DOB (ISO) — caught INCIDENTALLY by `phone` (the dashed digit run). The US-format
    // alt DOB below is a true MISS, so date handling is INCONSISTENT today.
    Planted::new("1933-04-02", "date", "us", true, false),
    // DOB (US slash format) — NO recognizer fires. TRUE MISS.
    Planted::new("04/02/1933", "date", "us", false, false),
    // Follow-up date (ISO) — caught INCIDENTALLY by `phone`.
    Planted::new("2026-07-15", "date", "us", true, false),
    // Age > 89 — an HIPAA Safe-Harbor identifier. NO recognizer. TRUE MISS.
    Planted::new("92 years old", "age", "us", false, false),
    // SSN — caught INCIDENTALLY by `phone` (mis-attributed), no dedicated recognizer.
    Planted::new("078-05-1120", "ssn", "us", true, false),
    // phones / fax — DEDICATED + caught.
    Planted::new("312-555-0186", "phone", "us", true, true),
    Planted::new("312-555-7700", "phone", "us", true, true),
    // email — DEDICATED + caught.
    Planted::new("albert.twonames@example.com", "email", "us", true, true),
    // NPI (10-digit) — NO dedicated recognizer; caught INCIDENTALLY by `phone`.
    Planted::new("1234567893", "npi", "us", true, false),
    // DEA registration no. — NO dedicated recognizer; the [A-Z]{2}+7-digit shape is
    // caught INCIDENTALLY by the broad `id` recognizer.
    Planted::new("AB1234563", "dea", "us", true, false),
    // STRUCTURED street address — now DEDICATED + caught by the global address
    // recognizer (`221B` house number + `Baker` + the `Street` suffix). Was a TRUE MISS
    // before the address family landed; the assertion now guards the tightening.
    Planted::new("221B Baker Street", "address", "uk", true, true),
];

const MEDICAL_DECOYS: &[Decoy] = &[
    Decoy::new("10:30 AM", "clock time, must stay clean", true),
    Decoy::new("Follow-up", "ordinary word, must stay clean", true),
];

// ===================================================================
// Document 3 — BANKING: wire instructions / statement (messy)
// ===================================================================
//
// Messiness exercised: a Luhn-valid test PAN both space-grouped and glued to a
// label, a valid example IBAN with the standard 4-char grouping, an ABA routing no.
// and a SWIFT/BIC (neither has a dedicated recognizer), and innocuous amounts / a
// reference no. that must (mostly) stay clean.

const BANKING: &str = "\
WIRE INSTRUCTIONS — SYNTHETIC TEST (DO NOT REMIT REAL FUNDS)\n\
Remit to ACME ESCROW. Card on file (test PAN): 4111 1111 1111 1111.\n\
Backup card glued to ref: customerID4111111111111111 (same test PAN).\n\
Beneficiary IBAN GB82 WEST 1234 5698 7654 32. SWIFT/BIC: DEUTDEFF.\n\
ABA routing 021000021, account 000123456789. SKU 4452310099 is NOT money.\n\
Amount: $4,250.00. Internal ref PO-99821. Value date 2026-08-01.\n";

const BANKING_PLANTED: &[Planted] = &[
    // payment card (grouped) — DEDICATED (Luhn-validated) + caught.
    Planted::new("4111 1111 1111 1111", "card", "intl", true, true),
    // payment card glued to a word-char prefix — DEDICATED + caught (recall-first:
    // no `\b`, so the glued case is the one the engine specifically handles).
    Planted::new("4111111111111111", "card", "intl", true, true),
    // IBAN — DEDICATED (mod-97-validated) + caught, with the 4-char grouping.
    Planted::new("GB82 WEST 1234 5698 7654 32", "iban", "uk", true, true),
    // SWIFT / BIC — DEDICATED (the finance-corpus round): structure-validated
    // (`bic_structure_valid`), the label-cued 8-char form fires off the `SWIFT/BIC:`
    // label. Was a TRUE MISS before the `bic` recognizer landed.
    Planted::new("DEUTDEFF", "swift", "intl", true, true),
    // ABA routing no. — NO dedicated recognizer; 9-digit run caught INCIDENTALLY by `phone`.
    Planted::new("021000021", "aba", "us", true, false),
    // account no. — NO dedicated recognizer; 12-digit run caught INCIDENTALLY by `phone`.
    Planted::new("000123456789", "account", "us", true, false),
    // value date (ISO) — caught INCIDENTALLY by `phone`.
    Planted::new("2026-08-01", "date", "intl", true, false),
];

const BANKING_DECOYS: &[Decoy] = &[
    Decoy::new("$4,250.00", "money figure, must stay clean", true),
    // KNOWN recall-first FP: a 10-digit SKU is a `phone`-shaped digit run.
    Decoy::new(
        "SKU 4452310099",
        "product SKU — FALSE POSITIVE as `phone`",
        false,
    ),
    // KNOWN recall-first FP: an internal PO ref is `id`-shaped.
    Decoy::new(
        "PO-99821",
        "purchase-order ref — FALSE POSITIVE as `id`",
        false,
    ),
];

// ===================================================================
// Document 4 — EMAIL THREAD: headers + body (messy, multi-jurisdiction)
// ===================================================================
//
// Messiness exercised: From/To/Bcc header lines, a UK NHS number and a UK NINO
// (neither dedicated; the NHS number is incidentally phone-caught, the NINO is a
// true miss), reserved-doc IPs (v4 + v6), and example.com URLs.

const EMAIL_THREAD: &str = "\
From: \"Wong, Mei\" <mei.wong@example.com>\n\
To: counsel@example.org\n\
Bcc: leak.watch@example.com\n\
Subject: Re: closing — SYNTHETIC TEST THREAD\n\
\n\
Mei, the server log shows the upload came from 192.0.2.44 (and one hit from\n\
the IPv6 host 2001:db8::8a2e:370:7334). Portal: https://portal.example.com/m/77\n\
and the public page www.example.org/closing.\n\
UK client NHS No 943 476 5919; their NINO is QQ123456C. Ring me on\n\
+44 20 7946 0958 if needed. -- Sent from my device.\n";

const EMAIL_PLANTED: &[Planted] = &[
    // header emails — DEDICATED + caught (incl. the Bcc leak vector).
    Planted::new("mei.wong@example.com", "email", "intl", true, true),
    Planted::new("counsel@example.org", "email", "intl", true, true),
    Planted::new("leak.watch@example.com", "email", "intl", true, true),
    // IPv4 (RFC 5737 reserved) — DEDICATED + caught.
    Planted::new("192.0.2.44", "ip", "intl", true, true),
    // IPv6 (RFC 3849 reserved) — DEDICATED + caught.
    Planted::new("2001:db8::8a2e:370:7334", "ip", "intl", true, true),
    // URLs — DEDICATED + caught (https + bare www).
    Planted::new("https://portal.example.com/m/77", "url", "intl", true, true),
    Planted::new("www.example.org/closing", "url", "intl", true, true),
    // UK NHS number — NO dedicated recognizer; the spaced 10-digit run is caught
    // INCIDENTALLY by `phone`.
    Planted::new("943 476 5919", "nhs", "uk", true, false),
    // UK NINO — NO recognizer (2 letters + 6 digits + a letter breaks the `id`
    // digit-run shape and is not a phone-length pure-digit run). TRUE MISS.
    Planted::new("QQ123456C", "nino", "uk", false, false),
    // UK phone — DEDICATED + caught.
    Planted::new("+44 20 7946 0958", "phone", "uk", true, true),
];

const EMAIL_DECOYS: &[Decoy] = &[
    Decoy::new("closing", "subject word, must stay clean", true),
    Decoy::new("device", "signature word, must stay clean", true),
];

// ===================================================================
// The corpus
// ===================================================================

fn corpus() -> Vec<Doc> {
    vec![
        Doc {
            name: "legal/engagement-letter",
            text: LEGAL,
            planted: LEGAL_PLANTED,
            decoys: LEGAL_DECOYS,
        },
        Doc {
            name: "medical/discharge-summary",
            text: MEDICAL,
            planted: MEDICAL_PLANTED,
            decoys: MEDICAL_DECOYS,
        },
        Doc {
            name: "banking/wire-instructions",
            text: BANKING,
            planted: BANKING_PLANTED,
            decoys: BANKING_DECOYS,
        },
        Doc {
            name: "email/closing-thread",
            text: EMAIL_THREAD,
            planted: EMAIL_PLANTED,
            decoys: EMAIL_DECOYS,
        },
    ]
}

/// The engine under test: the full recall-first config the task specifies —
/// all global built-ins ON (incl. the structured-address family) plus the opt-in
/// Singapore locale pack (NRIC + postal). No
/// caller terms, no firm recognizers (this measures the BUILT-IN baseline).
fn engine() -> RedactionEngine {
    RedactionEngine::builder()
        .builtins(BuiltinRecognizers::all())
        .locales([Locale::Singapore])
        .build()
        .expect("baseline engine builds")
}

// ===================================================================
// Matching helpers
// ===================================================================

/// Find the byte span of `needle` in `hay`. Panics with a clear message if the
/// planted text is not present verbatim (a corpus bug to fix, not an engine result).
fn locate(hay: &str, needle: &str) -> (usize, usize) {
    let start = hay.find(needle).unwrap_or_else(|| {
        panic!("PLANTED text {needle:?} not found verbatim in document — fix the corpus")
    });
    (start, start + needle.len())
}

/// Does any candidate's `[start,end)` cover the byte span `[s,e)`? "Cover" = the
/// candidate span and the instance span OVERLAP (the candidate includes at least
/// part of the instance), which is the honest "was this identifier removed at all"
/// question — the engine may match a slightly different boundary (e.g. it trims the
/// label, or swallows a trailing char) but still redacts the identifier.
fn covered(cands: &[RedactionCandidate], s: usize, e: usize) -> Option<&RedactionCandidate> {
    cands.iter().find(|c| c.start() < e && s < c.end())
}

// ===================================================================
// The harness / report
// ===================================================================

#[derive(Default, Clone, Copy)]
struct Tally {
    planted: usize,
    caught: usize,
    missed: usize,
    /// Of the caught, how many were caught by a DEDICATED recognizer (vs incidental).
    caught_dedicated: usize,
}

#[test]
fn messy_corpus_redaction_baseline() {
    let engine = engine();
    let docs = corpus();

    // Per-category tallies and the running global breakdown.
    let mut by_category: BTreeMap<&'static str, Tally> = BTreeMap::new();
    let mut recognizer_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = Tally::default();

    // Collected for the loud sections at the end.
    let mut surprises: Vec<String> = Vec::new(); // covered==false but dedicated==true => real bug
    let mut gaps: Vec<String> = Vec::new(); // dedicated==false => fan-out target
    let mut false_positives: Vec<String> = Vec::new();

    println!("\n================ MESSY-CORPUS REDACTION BASELINE (SYNTHETIC) ================\n");

    for doc in &docs {
        let cands = engine.candidates(doc.text);
        println!("----- {} -----", doc.name);
        println!(
            "  text bytes: {}, engine hits: {}",
            doc.text.len(),
            cands.len()
        );

        // Per-recognizer breakdown for this doc (and fold into the global one).
        let mut doc_breakdown: BTreeMap<String, usize> = BTreeMap::new();
        for c in &cands {
            let key = c.recognizer().to_string();
            *doc_breakdown.entry(key.clone()).or_default() += 1;
            *recognizer_counts.entry(key).or_default() += 1;
        }
        let bd: Vec<String> = doc_breakdown
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        println!("  breakdown: [{}]", bd.join(", "));

        // Evaluate every planted instance.
        for p in doc.planted {
            let (s, e) = locate(doc.text, p.text);
            let hit = covered(&cands, s, e);
            let is_covered = hit.is_some();

            let t = by_category.entry(p.category).or_default();
            t.planted += 1;
            total.planted += 1;
            if is_covered {
                t.caught += 1;
                total.caught += 1;
                if p.dedicated {
                    t.caught_dedicated += 1;
                    total.caught_dedicated += 1;
                }
            } else {
                t.missed += 1;
                total.missed += 1;
            }

            // The honest cross-checks.
            let attribution = hit.map(|h| h.recognizer().to_string());
            let status = if is_covered { "CAUGHT" } else { "MISSED" };
            let kind = if p.dedicated {
                "dedicated"
            } else {
                "no-dedicated"
            };
            let text_q = format!("{:?}", p.text);
            let attr_s = attribution.clone().unwrap_or_else(|| "(none)".into());
            println!(
                "    [{status:<6}] {:<10} {:<8} {:<14} {text_q} -> {attr_s}",
                p.category, p.jurisdiction, kind,
            );

            // SURPRISE: a category WITH a dedicated recognizer that the engine should
            // catch but DID NOT — that is a real bug, flagged loudly.
            if p.dedicated && !is_covered {
                surprises.push(format!(
                    "{}: {:?} ({}) — DEDICATED recognizer exists but span was NOT covered",
                    doc.name, p.text, p.category
                ));
            }
            // GAP: a category WITHOUT a dedicated recognizer — fan-out target. Note
            // whether it is incidentally covered (fragile) or a true miss.
            if !p.dedicated {
                let how = match &attribution {
                    Some(r) => {
                        format!("incidentally covered as `{r}` (FRAGILE — reformat may drop it)")
                    }
                    None => "MISSED outright".to_string(),
                };
                gaps.push(format!(
                    "{}: {:<9} {:?} — {}",
                    doc.name, p.category, p.text, how
                ));
            }
        }

        // Evaluate decoys (false-positive detection).
        for d in doc.decoys {
            let (s, e) = locate(doc.text, d.text);
            if let Some(hit) = covered(&cands, s, e) {
                let line = format!(
                    "{}: {:?} flagged as `{}` matched={:?} — {}",
                    doc.name,
                    d.text,
                    hit.recognizer(),
                    hit.matched_value(),
                    d.note
                );
                false_positives.push(line);
                // A decoy we asserted should be CLEAN but the engine flagged => fail.
                assert!(
                    !d.expect_clean,
                    "SURPRISE FALSE POSITIVE on a decoy expected clean: {}: {:?} flagged as `{}`",
                    doc.name,
                    d.text,
                    hit.recognizer()
                );
            } else if !d.expect_clean {
                // A decoy we EXPECTED to false-positive but the engine did NOT flag:
                // not a failure (the engine improved), just note it.
                println!(
                    "    [note] documented-FP decoy {:?} did NOT fire (engine stricter than recorded): {}",
                    d.text, d.note
                );
            }
        }
        println!();
    }

    // ---- The matrix ----
    println!("================ PER-CATEGORY RECALL MATRIX ================");
    println!(
        "  {:<12} {:>7} {:>7} {:>7} {:>9} {:>11}",
        "category", "planted", "caught", "missed", "recall%", "dedic/caught"
    );
    for (cat, t) in &by_category {
        let recall = if t.planted == 0 {
            0.0
        } else {
            100.0 * t.caught as f64 / t.planted as f64
        };
        println!(
            "  {:<12} {:>7} {:>7} {:>7} {:>8.0}% {:>7}/{:<3}",
            cat, t.planted, t.caught, t.missed, recall, t.caught_dedicated, t.caught
        );
    }
    let total_recall = if total.planted == 0 {
        0.0
    } else {
        100.0 * total.caught as f64 / total.planted as f64
    };
    println!("  {:-<58}", "");
    println!(
        "  {:<12} {:>7} {:>7} {:>7} {:>8.0}% {:>7}/{:<3}",
        "TOTAL",
        total.planted,
        total.caught,
        total.missed,
        total_recall,
        total.caught_dedicated,
        total.caught
    );
    println!(
        "  (dedic/caught = caught-by-a-purpose-built-recognizer / total-caught; the\n\
        \x20  difference is INCIDENTAL phone/id coverage — fragile, the fan-out target.)\n"
    );

    // ---- Global recognizer breakdown ----
    println!("================ GLOBAL RECOGNIZER BREAKDOWN ================");
    let total_hits: usize = recognizer_counts.values().sum();
    let bd: Vec<String> = recognizer_counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    println!(
        "  [{}]  (total hits across corpus = {})\n",
        bd.join(", "),
        total_hits
    );

    // ---- Gaps (fan-out targets) ----
    println!("================ GAPS — CROSS-DOMAIN FAN-OUT TARGETS ================");
    println!("  (no dedicated recognizer today; incidental coverage is FRAGILE.)");
    for g in &gaps {
        println!("  - {g}");
    }
    println!();

    // ---- False positives ----
    println!("================ FALSE POSITIVES (recall-first cost) ================");
    if false_positives.is_empty() {
        println!("  none observed on the planted decoys.");
    } else {
        for fp in &false_positives {
            println!("  - {fp}");
        }
    }
    println!();

    // ---- Surprises (real bugs) ----
    println!("================ SURPRISES (should-work MISSES = real bugs) ================");
    if surprises.is_empty() {
        println!("  none — every dedicated recognizer caught its planted instances.");
    } else {
        for s in &surprises {
            println!("  !! {s}");
        }
    }
    println!("\n=============================================================================\n");

    // ===================================================================
    // ASSERTIONS — only the TODAY baseline (so this stays green on the
    // current engine and becomes the regression baseline to tighten).
    // ===================================================================

    // 1) Every instance's coverage matches its recorded `expected_covered`. This
    //    catches a regression that DROPS a currently-redacted identifier AND a
    //    silent improvement (a fan-out recognizer landed) that the corpus has not
    //    yet been updated to assert — either way, the ground truth must stay honest.
    for doc in &docs {
        let cands = engine.candidates(doc.text);
        for p in doc.planted {
            let (s, e) = locate(doc.text, p.text);
            let is_covered = covered(&cands, s, e).is_some();
            assert_eq!(
                is_covered, p.expected_covered,
                "BASELINE DRIFT in {}: {:?} ({}) expected_covered={} but engine covered={}. \
                 If a fan-out recognizer just landed, flip this instance's expected_covered \
                 (and dedicated) to true — that is the intended tightening.",
                doc.name, p.text, p.category, p.expected_covered, is_covered
            );
        }
    }

    // 2) No SURPRISE miss: a category with a dedicated recognizer must be caught.
    assert!(
        surprises.is_empty(),
        "{} dedicated-recognizer miss(es) — real bug(s): {:?}",
        surprises.len(),
        surprises
    );

    // 3) Sanity: the corpus actually exercises the engine (the dedicated built-ins
    //    fire). If these drop to zero a recognizer regressed wholesale.
    for must in [
        "email",
        "phone",
        "url",
        "ip",
        "credit-card",
        "iban",
        "name",
        "sg:nric",
    ] {
        assert!(
            recognizer_counts.get(must).copied().unwrap_or(0) > 0,
            "expected dedicated recognizer `{must}` to fire somewhere in the corpus, but it did not"
        );
    }
}
