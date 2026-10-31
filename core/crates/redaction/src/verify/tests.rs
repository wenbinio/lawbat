// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unit tests for the post-redaction verification probes: per-vector PLANTED
//! residuals (each vector must FIND its plant), negatives (a clean output yields
//! zero residuals — and nothing that reads as "safe"), determinism, hostile
//! inputs (garbage / bomb-shaped / encrypted — bounded, structured, no panic),
//! and the value-free / content-free confidentiality posture of the result.

use super::*;
use lopdf::content::{Content, Operation};
use lopdf::{dictionary, Dictionary, Object, Stream, StringFormat};

/// The synthetic identifier planted in the crafted PDFs. Synthetic test data
/// only — never real matter data (CLAUDE.md).
const VALUE: &str = "S1234567D";

fn values(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Zlib-compress `data` unconditionally (lopdf's `Stream::compress` keeps a TINY
/// stream plain when compression does not shrink it, which would leak the plant
/// into the raw-bytes vector and defeat the surface-isolation assertions). Level
/// 6, NOT `fast`: at level 1 miniz emits a STORED deflate block for tiny input —
/// the cleartext verbatim inside the "compressed" stream, the same leak.
fn zlib(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write as _;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(6));
    enc.write_all(data).expect("zlib write");
    enc.finish().expect("zlib finish")
}

/// Options for the crafted one-page PDF: what to plant where.
#[derive(Default)]
struct Craft {
    /// Body text shown via a single `Tj` (empty = a benign placeholder line).
    body: String,
    /// Show the body as SEPARATE `Tj` operators (kerning-split shape) instead.
    body_split: Vec<String>,
    /// FlateDecode the content stream.
    compress_body: bool,
    /// An annotation `/Contents` note text to attach.
    annot_contents: Option<String>,
    /// An annotation `/A` URI action target to attach.
    annot_uri: Option<String>,
    /// An `/Info` `/Author` value.
    info_author: Option<String>,
    /// An XMP `/Metadata` packet (stored FlateDecode-compressed so only the
    /// metadata/stream vectors can see it, not raw bytes).
    xmp: Option<String>,
    /// An extra UNREFERENCED FlateDecode stream object (reaches only the
    /// decompressed-streams vector).
    hidden_stream: Option<String>,
    /// An extra stream claiming an UNSUPPORTED filter (`LZWDecode`) whose raw
    /// content is stored verbatim (reaches only the raw-bytes vector; the
    /// stream walk must SKIP it with a diagnostic).
    unsupported_stream: Option<String>,
    /// An extra FlateDecode stream whose DECODED size exceeds the per-stream
    /// cap (bomb-shaped: must be skipped + diagnosed, never inflated).
    bomb_stream: bool,
}

fn craft_pdf(c: Craft) -> Vec<u8> {
    let mut doc = Document::with_version("1.5");

    let mut ops = vec![
        Operation::new("BT", vec![]),
        Operation::new("Tf", vec!["F1".into(), 12.into()]),
        Operation::new("Td", vec![72.into(), 720.into()]),
    ];
    let show = |s: &str| {
        Operation::new(
            "Tj",
            vec![Object::String(s.as_bytes().to_vec(), StringFormat::Literal)],
        )
    };
    if !c.body_split.is_empty() {
        for piece in &c.body_split {
            ops.push(show(piece));
        }
    } else if c.body.is_empty() {
        ops.push(show("A benign line of placeholder text."));
    } else {
        ops.push(show(&c.body));
    }
    ops.push(Operation::new("ET", vec![]));
    let encoded = Content { operations: ops }
        .encode()
        .expect("encode content");
    let content = if c.compress_body {
        Stream::new(dictionary! { "Filter" => "FlateDecode" }, zlib(&encoded))
    } else {
        Stream::new(Dictionary::new(), encoded)
    };
    let content_id = doc.add_object(content);

    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });

    // Optional annotations.
    let mut annot_refs: Vec<Object> = Vec::new();
    if let Some(note) = &c.annot_contents {
        let id = doc.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Text",
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "Contents" => Object::String(note.as_bytes().to_vec(), StringFormat::Literal),
        });
        annot_refs.push(id.into());
    }
    if let Some(uri) = &c.annot_uri {
        let id = doc.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Link",
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "A" => dictionary! {
                "S" => "URI",
                "URI" => Object::String(uri.as_bytes().to_vec(), StringFormat::Literal),
            },
        });
        annot_refs.push(id.into());
    }

    let page_id = doc.new_object_id();
    let pages_id = doc.new_object_id();
    let mut page = dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        "Resources" => resources_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
    };
    if !annot_refs.is_empty() {
        page.set("Annots", Object::Array(annot_refs));
    }
    doc.objects.insert(page_id, Object::Dictionary(page));
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        }),
    );

    let mut catalog = dictionary! { "Type" => "Catalog", "Pages" => pages_id };
    if let Some(xmp) = &c.xmp {
        let packet = format!(
            "<?xpacket begin=\"\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\">{xmp}</x:xmpmeta>"
        );
        let s = Stream::new(
            dictionary! {
                "Type" => "Metadata", "Subtype" => "XML", "Filter" => "FlateDecode",
            },
            zlib(packet.as_bytes()),
        );
        let id = doc.add_object(s);
        catalog.set("Metadata", id);
    }
    let catalog_id = doc.add_object(catalog);
    doc.trailer.set("Root", catalog_id);

    if let Some(author) = &c.info_author {
        let info_id = doc.add_object(dictionary! {
            "Author" => Object::String(author.as_bytes().to_vec(), StringFormat::Literal),
        });
        doc.trailer.set("Info", info_id);
    }

    if let Some(hidden) = &c.hidden_stream {
        let s = Stream::new(
            dictionary! { "Filter" => "FlateDecode" },
            zlib(format!("hidden payload {hidden} end").as_bytes()),
        );
        doc.add_object(s);
    }
    if let Some(text) = &c.unsupported_stream {
        // Claim LZWDecode but store the cleartext verbatim: the capped decoder
        // REFUSES the filter (cannot bound it), so only raw bytes can see this.
        let s = Stream::new(
            dictionary! { "Filter" => "LZWDecode" },
            format!("lzw-claimed payload {text} end").into_bytes(),
        );
        doc.add_object(s);
    }
    if c.bomb_stream {
        // A genuine FlateDecode stream whose decoded size (20 MiB of zeros)
        // exceeds MAX_DECODED_STREAM_BYTES: the capped reader must skip it.
        let s = Stream::new(
            dictionary! { "Filter" => "FlateDecode" },
            zlib(&vec![0u8; 20 * 1024 * 1024]),
        );
        doc.add_object(s);
    }

    let mut out = Vec::new();
    doc.save_to(&mut out).expect("save crafted pdf");
    out
}

/// The probe outcome for value 0 on `vector`.
fn probe<'a>(res: &'a PdfVerification, vector: &str) -> &'a ProbeOutcome {
    res.results[0]
        .probes
        .iter()
        .find(|p| p.vector == vector)
        .unwrap_or_else(|| panic!("vector {vector} missing"))
}

// ---------------------------------------------------------------------------
// TEXT vectors
// ---------------------------------------------------------------------------

#[test]
fn text_raw_hit_reports_all_four_vectors() {
    let out = verify_text(&format!("residual {VALUE} here"), &values(&[VALUE]));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value_index, 0);
    assert!(out[0].residual_found());
    for p in &out[0].probes {
        assert!(
            p.residual_found,
            "{} should hit on a raw residual",
            p.vector
        );
        assert_eq!(p.matches, 1);
    }
}

#[test]
fn text_case_insensitive_only() {
    let out = verify_text("residual s1234567d here", &values(&[VALUE]));
    let by = |v: &str| {
        out[0]
            .probes
            .iter()
            .find(|p| p.vector == v)
            .unwrap()
            .residual_found
    };
    assert!(!by("text_raw"));
    assert!(by("text_case_insensitive"));
    assert!(by("text_ws_normalized"));
    assert!(by("text_ws_stripped"));
}

#[test]
fn text_ws_normalized_catches_run_of_spaces_in_value() {
    // The needle carries a single interior space; the output has it doubled.
    let out = verify_text(
        "director massimo  greco attended",
        &values(&["Massimo Greco"]),
    );
    let by = |v: &str| {
        out[0]
            .probes
            .iter()
            .find(|p| p.vector == v)
            .unwrap()
            .residual_found
    };
    assert!(!by("text_raw"));
    assert!(!by("text_case_insensitive"));
    assert!(by("text_ws_normalized"));
    assert!(by("text_ws_stripped"));
}

#[test]
fn text_ws_stripped_catches_glyph_split() {
    // The kerning-split shape: interior whitespace INSIDE the value.
    let out = verify_text("id S12 34567D on file", &values(&[VALUE]));
    let by = |v: &str| {
        out[0]
            .probes
            .iter()
            .find(|p| p.vector == v)
            .unwrap()
            .residual_found
    };
    assert!(!by("text_raw"));
    assert!(!by("text_ws_normalized"));
    assert!(by("text_ws_stripped"));
}

#[test]
fn text_clean_output_reports_no_residuals_and_no_safe_state() {
    let out = verify_text("nothing sensitive remains in this text", &values(&[VALUE]));
    assert!(!out[0].residual_found());
    for p in &out[0].probes {
        assert!(!p.residual_found);
        assert_eq!(p.matches, 0);
    }
}

#[test]
fn text_empty_value_never_vacuously_matches() {
    let out = verify_text("any text", &values(&["", "   "]));
    assert!(!out[0].residual_found());
    assert!(!out[1].residual_found());
}

// ---------------------------------------------------------------------------
// PDF vectors — per-vector planted residuals
// ---------------------------------------------------------------------------

#[test]
fn pdf_body_plant_found_by_strict_and_lenient_but_not_raw_when_compressed() {
    // The body carries repetitive padding so deflate actually COMPRESSES it:
    // miniz emits a STORED (verbatim) block when compression would not shrink a
    // tiny stream, which would surface the plant to the raw-bytes vector and
    // defeat the surface-isolation assertion below.
    let pdf = craft_pdf(Craft {
        body: format!("Director ID {VALUE} appears here. {}", "filler ".repeat(80)),
        compress_body: true,
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    assert!(probe(&res, "pdf_text_strict").residual_found, "strict");
    assert_eq!(probe(&res, "pdf_text_strict").pages, vec![1]);
    assert!(probe(&res, "pdf_text_lenient").residual_found, "lenient");
    assert_eq!(probe(&res, "pdf_text_lenient").pages, vec![1]);
    assert_eq!(probe(&res, "pdf_text_lenient").mode, Some("raw"));
    assert!(
        probe(&res, "pdf_streams").residual_found,
        "decompressed stream walk sees the content stream"
    );
    assert!(
        !probe(&res, "pdf_raw_bytes").residual_found,
        "compressed body must not appear in raw bytes: {:?}",
        probe(&res, "pdf_raw_bytes")
    );
    assert!(!probe(&res, "pdf_annotations").residual_found);
    assert!(!probe(&res, "pdf_metadata").residual_found);
}

#[test]
fn pdf_split_operator_plant_found_by_ws_stripped_lenient_and_strict() {
    // The value split across two Tj operators — the classic kerning-split miss.
    let pdf = craft_pdf(Craft {
        body_split: vec!["ID S12".to_string(), "34567D on file".to_string()],
        compress_body: true,
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    let lenient = probe(&res, "pdf_text_lenient");
    assert!(
        lenient.residual_found,
        "lenient must recover the split value"
    );
    assert_eq!(lenient.mode, Some("ws_stripped"));
    // The strict pass rides the engine's whitespace-elastic term recall, so the
    // split occurrence is recovered there too.
    assert!(
        probe(&res, "pdf_text_strict").residual_found,
        "strict ws-elastic term recall"
    );
}

#[test]
fn pdf_hidden_compressed_stream_plant_found_only_by_stream_walk() {
    let pdf = craft_pdf(Craft {
        hidden_stream: Some(VALUE.to_string()),
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    assert!(probe(&res, "pdf_streams").residual_found, "stream walk");
    assert!(!probe(&res, "pdf_raw_bytes").residual_found, "compressed");
    assert!(
        !probe(&res, "pdf_text_strict").residual_found,
        "not page content"
    );
    assert!(!probe(&res, "pdf_text_lenient").residual_found);
    assert!(!probe(&res, "pdf_annotations").residual_found);
    assert!(!probe(&res, "pdf_metadata").residual_found);
}

#[test]
fn pdf_unsupported_filter_plant_found_by_raw_bytes_and_diagnosed_as_skipped() {
    let pdf = craft_pdf(Craft {
        unsupported_stream: Some(VALUE.to_string()),
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    assert!(probe(&res, "pdf_raw_bytes").residual_found, "raw bytes");
    assert!(
        !probe(&res, "pdf_streams").residual_found,
        "unsupported filter is refused, not inflated"
    );
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.contains("not decompressed")),
        "the skip must be diagnosed (NOT probed, never silently clean): {:?}",
        res.diagnostics
    );
    // Content-free discipline: no diagnostic ever carries the probe value.
    assert!(res.diagnostics.iter().all(|d| !d.contains(VALUE)));
}

#[test]
fn pdf_annotation_contents_plant_found_by_annotation_probe() {
    let pdf = craft_pdf(Craft {
        annot_contents: Some(format!("reviewer note mentions {VALUE}")),
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    let a = probe(&res, "pdf_annotations");
    assert!(a.residual_found, "annotation /Contents plant");
    assert_eq!(a.pages, vec![1]);
    assert!(!probe(&res, "pdf_text_lenient").residual_found);
}

#[test]
fn pdf_annotation_uri_action_plant_found_by_annotation_probe() {
    let pdf = craft_pdf(Craft {
        annot_uri: Some(format!("https://tracker.example/?id={VALUE}")),
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    assert!(
        probe(&res, "pdf_annotations").residual_found,
        "nested /A /URI plant"
    );
}

#[test]
fn pdf_info_author_plant_found_by_metadata_probe() {
    let pdf = craft_pdf(Craft {
        info_author: Some(format!("Prepared by {VALUE}")),
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    let m = probe(&res, "pdf_metadata");
    assert!(m.residual_found, "/Info /Author plant");
    assert!(m.pages.is_empty(), "metadata has no page geometry");
}

#[test]
fn pdf_xmp_plant_found_by_metadata_probe_not_raw() {
    let pdf = craft_pdf(Craft {
        xmp: Some(format!("<dc:creator>{VALUE}</dc:creator>")),
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    assert!(probe(&res, "pdf_metadata").residual_found, "XMP plant");
    assert!(
        !probe(&res, "pdf_raw_bytes").residual_found,
        "compressed XMP is invisible to raw bytes"
    );
}

// ---------------------------------------------------------------------------
// Negatives, determinism, structure
// ---------------------------------------------------------------------------

#[test]
fn pdf_clean_output_reports_zero_residuals_and_flags() {
    let pdf = craft_pdf(Craft {
        body: "Nothing sensitive remains on this page.".to_string(),
        compress_body: true,
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE, "Massimo Greco"])).expect("verify ok");
    assert_eq!(res.results.len(), 2);
    for (i, r) in res.results.iter().enumerate() {
        assert_eq!(r.value_index, i);
        assert!(!r.residual_found(), "clean output must yield no residuals");
        assert_eq!(r.probes.len(), PDF_VECTORS.len());
    }
    // The honesty flags are present (a crafted text PDF is none of these).
    assert!(!res.flags.low_text);
    assert!(!res.flags.unmapped_fonts);
    assert!(!res.flags.degenerate_layout);
}

#[test]
fn pdf_verification_is_deterministic() {
    let pdf = craft_pdf(Craft {
        body: format!("Director ID {VALUE} appears here."),
        compress_body: true,
        annot_contents: Some(format!("note {VALUE}")),
        info_author: Some(VALUE.to_string()),
        ..Craft::default()
    });
    let vals = values(&[VALUE, "unrelated value"]);
    let a = verify_pdf(&pdf, &vals).expect("verify ok");
    let b = verify_pdf(&pdf, &vals).expect("verify ok");
    assert_eq!(a, b, "same input must yield an identical result");
}

#[test]
fn results_are_value_free() {
    // The result structures identify values ONLY by index — assert the probe
    // value never appears in any diagnostic (the only free-text channel).
    let pdf = craft_pdf(Craft {
        body: format!("Director ID {VALUE} appears here."),
        unsupported_stream: Some(VALUE.to_string()),
        bomb_stream: true,
        ..Craft::default()
    });
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok");
    assert!(res.diagnostics.iter().all(|d| !d.contains(VALUE)));
}

// ---------------------------------------------------------------------------
// Hostile inputs
// ---------------------------------------------------------------------------

#[test]
fn hostile_inputs_error_structurally_never_panic() {
    assert!(verify_pdf(b"", &values(&[VALUE])).is_err(), "empty");
    assert!(
        verify_pdf(b"not a pdf at all", &values(&[VALUE])).is_err(),
        "garbage"
    );
    assert!(
        verify_pdf(
            &[0x25, 0x50, 0x44, 0x46, 0xFF, 0x00, 0x01],
            &values(&[VALUE])
        )
        .is_err(),
        "truncated header junk"
    );
}

#[test]
fn encrypted_pdf_is_refused() {
    // Craft a PDF then plant a trailer /Encrypt — the same fail-closed predicate
    // the redactor gates on must refuse verification too.
    let pdf = craft_pdf(Craft::default());
    let mut doc = Document::load_mem(&pdf).expect("load");
    doc.trailer.set("Encrypt", dictionary! {});
    let mut out = Vec::new();
    doc.save_to(&mut out).expect("save");
    assert!(verify_pdf(&out, &values(&[VALUE])).is_err(), "encrypted");
}

#[test]
fn bomb_shaped_stream_is_skipped_bounded_and_diagnosed() {
    let pdf = craft_pdf(Craft {
        body: "benign".to_string(),
        bomb_stream: true,
        ..Craft::default()
    });
    // Must return Ok (the document is otherwise probe-able) with the bomb
    // skipped + diagnosed — and must not inflate it (bounded memory; if the cap
    // failed this test would OOM/telescope, not just fail an assert).
    let res = verify_pdf(&pdf, &values(&[VALUE])).expect("verify ok despite bomb");
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.contains("not decompressed")),
        "bomb skip must be diagnosed: {:?}",
        res.diagnostics
    );
}
