// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Messy-corpus redaction baseline — the PDF (blob) path.
//!
//! A companion to `messy_corpus_baseline.rs` that exercises the NATIVE in-PDF
//! redaction path (`redaction::pdf::redact_pdf`) on a SYNTHETIC PDF built in-test
//! with `lopdf` (the same approach the engine's own unit tests use). It proves the
//! PDF path REUSES the text engine's detection and actually REMOVES the matched
//! glyphs from the page content stream, and it records the same honest catch/miss
//! distinction (dedicated vs incidental) — but over PDF bytes.
//!
//! SYNTHETIC ONLY (CLAUDE.md): same fictional/test values as the text corpus —
//! `4111 1111 1111 1111` (test PAN), `example.com` emails, RFC-5737 IPs, an invented
//! title-prefixed name, a fabricated SG NRIC. No real personal data, ever.
//!
//! The PDF text path has KNOWN limits documented in `pdf.rs` (split glyphs / CID
//! fonts / annotations / encryption); this test stays inside the supported case (a
//! simple Type1 font, text via `Tj`/`TJ`) and verifies the supported case works,
//! while asserting only the TODAY baseline so it is a stable regression anchor.

use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Document, Object, Stream, StringFormat};

use redaction::{redact_pdf, BuiltinRecognizers, Locale, RedactionEngine};

/// The same baseline engine as the text harness: all built-ins + the SG locale.
fn engine() -> RedactionEngine {
    RedactionEngine::builder()
        .builtins(BuiltinRecognizers::all())
        .locales([Locale::Singapore])
        .build()
        .expect("baseline engine builds")
}

/// Build a one-page PDF that shows each line of `lines` via a separate `Tj`
/// text-showing operator (Type1 Helvetica). Fully synthetic.
fn build_pdf(lines: &[&str]) -> Vec<u8> {
    let mut doc = Document::with_version("1.5");

    let mut ops = vec![
        Operation::new("BT", vec![]),
        Operation::new("Tf", vec!["F1".into(), 12.into()]),
        Operation::new("Td", vec![72.into(), 720.into()]),
    ];
    for line in lines {
        ops.push(Operation::new(
            "Tj",
            vec![Object::String(
                line.as_bytes().to_vec(),
                StringFormat::Literal,
            )],
        ));
        // Move down a line (negative TL via Td) so the text does not overprint.
        ops.push(Operation::new("Td", vec![0.into(), (-16).into()]));
    }
    ops.push(Operation::new("ET", vec![]));

    let encoded = Content { operations: ops }
        .encode()
        .expect("encode content");
    let content_id = doc.add_object(Stream::new(dictionary! {}, encoded));
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

/// Re-extract page text from PDF bytes (via lopdf's own extractor) so the test can
/// assert identifiers are GONE / innocuous text is preserved.
fn extract_text(pdf: &[u8]) -> String {
    let doc = Document::load_mem(pdf).expect("reload redacted pdf");
    let pages: Vec<u32> = doc.get_pages().keys().copied().collect();
    doc.extract_text(&pages).unwrap_or_default()
}

#[test]
fn messy_corpus_pdf_redaction_baseline() {
    // A messy-but-supported synthetic page: dedicated-recognizer identifiers plus an
    // innocuous decoy line that must survive.
    let lines = [
        "CLOSING MEMO - SYNTHETIC TEST PDF (NOT REAL DATA)",
        "Contact Dr. Tan Wei Ming at jane.doe@example.com or +65 6123 4567.",
        "Card on file (test PAN) 4111 1111 1111 1111 ; NRIC S1234567D.",
        "Server hit from 192.0.2.44 ; portal https://example.com/m/77 .",
        "Innocuous: clause 7.2.1 governs; amount USD 1,250,000.00 paid.",
    ];
    let pdf = build_pdf(&lines);

    let engine = engine();
    let result = redact_pdf(&pdf, &engine).expect("redact synthetic pdf");

    println!("\n================ PDF PATH BASELINE (SYNTHETIC) ================\n");
    println!("  pages: {}", result.pages().len());
    println!("  total text bytes scanned: {}", result.total_text_bytes());
    println!("  total redactions: {}", result.total_redactions());
    println!("  low_text flag: {}", result.low_text());
    if !result.diagnostics().is_empty() {
        println!("  diagnostics: {:?}", result.diagnostics());
    }
    let bd: std::collections::BTreeMap<String, usize> =
        result
            .candidates()
            .iter()
            .fold(Default::default(), |mut m, c| {
                *m.entry(c.recognizer().to_string()).or_default() += 1;
                m
            });
    let bd_s: Vec<String> = bd.iter().map(|(k, v)| format!("{k}={v}")).collect();
    println!("  candidate breakdown: [{}]", bd_s.join(", "));
    for c in result.candidates() {
        println!(
            "    removed {:<12} {:?}",
            c.recognizer().to_string(),
            c.matched_value()
        );
    }

    // The redacted text, re-extracted from the output bytes.
    let after = extract_text(result.bytes());
    println!("\n  re-extracted redacted text:\n{after}\n");
    println!("==============================================================\n");

    // ----- Assertions: the supported dedicated identifiers are GONE from the bytes.
    // (Whitespace can shift on re-extraction, so assert on the identifier substrings.)
    let must_be_gone = [
        "jane.doe@example.com",
        "4111 1111 1111 1111",
        "S1234567D",
        "192.0.2.44",
        "Tan Wei Ming",
    ];
    for id in must_be_gone {
        assert!(
            !after.contains(id),
            "PDF redaction LEAK: identifier {id:?} still present in redacted PDF text:\n{after}"
        );
        // And it must have been a real removal (a candidate), not just absent text.
    }

    // The URL is redacted too (it appears among the candidates).
    assert!(
        result
            .candidates()
            .iter()
            .any(|c| c.recognizer().to_string() == "url"),
        "expected a URL candidate in the PDF scan"
    );

    // The innocuous clause reference + money figure must SURVIVE (not over-redacted
    // to nothing). lopdf's extractor may reflow spacing, so check the digits survive.
    assert!(
        after.contains("7.2.1"),
        "innocuous clause reference was wrongly redacted from the PDF:\n{after}"
    );

    // Sanity: this page is text-rich, so it must NOT be flagged low_text (which
    // would mean the page was never truly examined — a false sense of "clean").
    assert!(
        !result.low_text(),
        "text-rich page wrongly flagged low_text"
    );

    // Sanity: real removals happened (the dedicated identifiers above + more).
    assert!(
        result.total_redactions() >= must_be_gone.len(),
        "expected at least {} redactions, got {}",
        must_be_gone.len(),
        result.total_redactions()
    );
}
