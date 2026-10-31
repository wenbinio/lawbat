"""
Redaction smoke tests: the /api/redaction surface, PDF/text/image redaction,
privilege passages, exposure meter, text-export, previews (split from tests/test_smoke.py).
"""

import os
import re
import tempfile
from pathlib import Path

# Isolate the app-data dir BEFORE any app import (belt-and-suspenders alongside the
# package __init__; setdefault keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402
from app.web import create_app, AppState  # noqa: E402
from tests.smoke._helpers import (  # noqa: E402
    _client, FIXTURES, _BIO_FIXTURE, _assembled_redaction_js_path,
)


from ._helpers import _prepared_result, _prepared_root

def test_pdf_ocr_hybrid_per_page():
    """The pymupdf_ocr backend is PER-PAGE: born-digital pages use the text layer, ONLY
    text-less (scanned) pages are OCR'd, and a mixed PDF keeps both — never OCRing a
    born-digital page (CLAUDE.md). OCR is stubbed so no tesseract is needed."""
    import fitz
    from app import extractors, ocr

    def _mixed_pdf(d):
        doc = fitz.open()
        doc.new_page().insert_text((72, 720), "Born-digital page one.")
        doc.new_page()  # page 2: NO text layer -> scanned-like
        doc.new_page().insert_text((72, 720), "Born-digital page three.")
        out = d / "mixed.pdf"
        doc.save(str(out))
        doc.close()
        return out

    with tempfile.TemporaryDirectory() as dtmp:
        d = Path(dtmp)
        pdf = _mixed_pdf(d)

        # (1) Graceful WITHOUT tesseract: text-layer pages present, scanned page absent.
        if not ocr.available():
            units = extractors._pdf_pymupdf_ocr(pdf)
            locs = [loc for loc, _ in units]
            assert "p.1" in locs and "p.3" in locs, locs
            assert not any("(ocr)" in loc for loc in locs), "no OCR without tesseract"

        # (2) With OCR STUBBED: ONLY the scanned page (0-based idx 1) is sent to OCR, and
        #     its recovered text is merged in page order.
        orig_avail, orig_pages = ocr.available, ocr.ocr_pdf_pages
        captured = {}

        def fake_pages(p, page_indices, **kw):
            captured["indices"] = sorted(int(i) for i in page_indices)
            return {1: "OCR-RECOVERED PAGE TWO"}

        ocr.available = lambda: True
        ocr.ocr_pdf_pages = fake_pages
        try:
            units = extractors._pdf_pymupdf_ocr(pdf)
        finally:
            ocr.available, ocr.ocr_pdf_pages = orig_avail, orig_pages
        assert captured["indices"] == [1], "only the scanned page OCR'd: %r" % captured
        by_loc = dict(units)
        assert [loc for loc, _ in units] == ["p.1", "p.2 (ocr)", "p.3"], units
        assert by_loc["p.2 (ocr)"] == "OCR-RECOVERED PAGE TWO"
        assert "Born-digital page one." in by_loc["p.1"]

        # (3) A fully born-digital PDF NEVER invokes OCR.
        doc = fitz.open()
        doc.new_page().insert_text((72, 720), "All pages have text.")
        alltext = d / "alltext.pdf"
        doc.save(str(alltext))
        doc.close()
        called = {"n": 0}

        def boom(*a, **k):
            called["n"] += 1
            return {}

        ocr.available = lambda: True
        ocr.ocr_pdf_pages = boom
        try:
            units = extractors._pdf_pymupdf_ocr(alltext)
        finally:
            ocr.available, ocr.ocr_pdf_pages = orig_avail, orig_pages
        assert called["n"] == 0, "a born-digital PDF must not invoke OCR"
        assert all("(ocr)" not in loc for loc, _ in units)


def test_image_redaction_mapping_and_tsv_parse():
    """Leak-critical mapping: a detected span over-covers the WHOLE OCR word box(es) it
    touches; a span crossing two words covers BOTH. Plus the tesseract-TSV word parse."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    words = [W("Email", 0, 0, 50, 12), W("jane@acme.example", 60, 0, 200, 12), W("now", 270, 0, 30, 12)]
    text, offsets = imageredact._assemble(words)
    assert text == "Email jane@acme.example now"

    # A span over ONLY the email word -> exactly that whole box (+pad), clamped.
    s = text.index("jane@acme.example")
    e = s + len("jane@acme.example")
    rects = imageredact._rects_for_spans(words, offsets, [(s, e)], (400, 100))
    assert len(rects) == 1
    x0, _, x1, y1 = rects[0]
    assert x0 <= 60 and x1 >= 260 and y1 >= 12, rects  # whole word box covered

    # A span crossing TWO words -> BOTH boxes (cover every part of the identifier).
    rects2 = imageredact._rects_for_spans(words, offsets, [(0, e)], (400, 100))
    assert len(rects2) == 2, rects2

    # Overlapping spans on the SAME word -> a single DEDUPED box (accurate `boxes` count).
    dup = imageredact._rects_for_spans(words, offsets, [(s, e), (s, e), (s + 1, e)], (400, 100))
    assert len(dup) == 1, dup

    # BYTE offsets (not char): the engine reports UTF-8 BYTE spans. A multibyte prefix
    # must still map the byte span to the RIGHT word (the prior non-ASCII byte-offset
    # leak). "日本語 ID7 tail": 日本語 = 9 bytes, so ID7 is at bytes [10, 13).
    mb = [W("日本語", 0, 0, 60, 14), W("ID7", 70, 0, 30, 14), W("tail", 110, 0, 40, 14)]
    text_mb, offs_mb = imageredact._assemble(mb)
    bs = text_mb.encode("utf-8")
    s_mb = bs.index(b"ID7")
    e_mb = s_mb + 3
    assert (s_mb, e_mb) == (10, 13), (s_mb, e_mb)
    assert offs_mb[1] == (10, 13), offs_mb  # the ID7 word's BYTE range
    rects_mb = imageredact._rects_for_spans(mb, offs_mb, [(s_mb, e_mb)], (200, 50))
    assert len(rects_mb) == 1, rects_mb
    x0m, _, x1m, _ = rects_mb[0]
    # The box is over ID7 (x~70-100) — NOT the CJK word (x<60) nor `tail` (x>=110).
    assert 60 <= x0m <= 72 and 98 <= x1m <= 114, rects_mb

    # TSV parse: only level-5 rows with non-empty text + a valid (>0) box survive.
    tsv = (
        "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n"
        "5\t1\t1\t1\t1\t1\t10\t20\t30\t12\t96\tHello\n"
        "5\t1\t1\t1\t1\t2\t50\t20\t0\t12\t95\tzerowidth\n"  # width 0 -> dropped
        "4\t1\t1\t1\t1\t0\t0\t0\t0\t0\t-1\tline\n"          # level 4 -> dropped
        "5\t1\t1\t1\t1\t3\t90\t20\t40\t12\t90\t   \n"        # blank text -> dropped
    )
    ws = ocr._parse_tsv_words(tsv)
    assert len(ws) == 1 and ws[0].text == "Hello" and ws[0].x == 10 and ws[0].w == 30


def test_ocr_tsv_carries_line_identity():
    """`_parse_tsv_words` carries each word's LINE identity — the tesseract
    `(block_num, par_num, line_num)` triple (cols 2/3/4) — so `_assemble` can rebuild
    line breaks. Words on different lines/pars/blocks get DISTINCT ids; a malformed
    line-id col yields a `None` id (never raises)."""
    from app import ocr

    tsv = (
        "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n"
        "5\t1\t1\t1\t1\t1\t10\t20\t30\t12\t96\tDirector\n"   # block1 par1 line1
        "5\t1\t1\t1\t2\t1\t10\t40\t30\t12\t96\tJohn\n"       # same block/par, line2
        "5\t1\t1\t2\t1\t1\t10\t60\t30\t12\t96\tSmith\n"      # par2 line1
        "5\t1\t2\t1\t1\t1\t10\t80\t30\t12\t96\tACME\n"       # block2
        "5\t1\tX\t1\t1\t1\t10\t99\t30\t12\t96\tOops\n"       # malformed block -> None
    )
    ws = ocr._parse_tsv_words(tsv)
    assert [w.text for w in ws] == ["Director", "John", "Smith", "ACME", "Oops"]
    assert ws[0].line_id == (1, 1, 1)
    assert ws[1].line_id == (1, 1, 2), "next line in same par -> distinct line id"
    assert ws[2].line_id == (1, 2, 1), "next par -> distinct id"
    assert ws[3].line_id == (2, 1, 1), "next block -> distinct id"
    assert ws[4].line_id is None, "malformed line-id col -> None, never a raise"
    # All four well-formed ids are distinct (each is its own OCR line).
    assert len({ws[0].line_id, ws[1].line_id, ws[2].line_id, ws[3].line_id}) == 4


def test_assemble_line_aware_newline_and_byte_offsets():
    """`_assemble` joins words on the SAME OCR line with a space and words on DIFFERENT
    lines with a NEWLINE (activating the engine's line-scoped recall on scanned text).
    The separator stays exactly ONE ASCII byte either way, so per-word UTF-8 BYTE offsets
    are unchanged — including a MULTIBYTE word immediately before an identifier (the shape
    of the prior non-ASCII byte-offset Critical). Unknown line ids fall back to a space."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    # Two lines: "Director of" (line 1) then "John Smith" (line 2).
    words = [
        W("Director", 0, 0, 80, 12, (1, 1, 1)),
        W("of", 90, 0, 20, 12, (1, 1, 1)),
        W("John", 0, 20, 40, 12, (1, 1, 2)),
        W("Smith", 50, 20, 50, 12, (1, 1, 2)),
    ]
    text, offsets = imageredact._assemble(words)
    assert text == "Director of\nJohn Smith", repr(text)
    # Every word's BYTE slice maps back to exactly that word.
    bs = text.encode("utf-8")
    for w, (s, e) in zip(words, offsets):
        assert bs[s:e].decode("utf-8") == w.text, (w.text, s, e)

    # Multibyte word (9 bytes) on line 1, identifier on line 2: the 1-byte NEWLINE
    # separator keeps the identifier's byte range correct (would leak if it shifted).
    mb = [W("日本語", 0, 0, 60, 14, (1, 1, 1)), W("ID7", 70, 0, 30, 14, (1, 1, 2))]
    text_mb, offs_mb = imageredact._assemble(mb)
    b = text_mb.encode("utf-8")
    assert b[9:10] == b"\n", "separator is a single ASCII newline byte"
    assert offs_mb[1] == (10, 13), offs_mb  # ID7 at bytes [10,13) — unchanged by '\n'
    assert b[offs_mb[1][0]:offs_mb[1][1]] == b"ID7"

    # Unknown line id on either side -> space (prior behaviour), never a spurious break.
    none_words = [W("a", 0, 0, 5, 5), W("b", 6, 0, 5, 5, (1, 1, 1))]
    assert imageredact._assemble(none_words)[0] == "a b"


def test_scan_scanned_pdf_assembles_multiline_text_for_engine():
    """END-TO-END structural: OCR words on TWO lines (a role label on line 1, a name on
    line 2) reach the detector as text CONTAINING A NEWLINE — so the engine's line-scoped
    context recognizers (which scan back from a role label) can fire on scanned pages, not
    a flattened one-line blob. Captured via a stub scan_fn."""
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact, ocr

    # A text-less full-page image -> classified as a scanned page.
    src = Image.new("RGB", (600, 800), "white")
    sb = _io.BytesIO()
    src.save(sb, "PNG")
    doc = fitz.open()
    doc.new_page(width=600, height=800).insert_image(fitz.Rect(0, 0, 600, 800), stream=sb.getvalue())
    pdf_bytes = doc.tobytes()
    doc.close()

    W = ocr.OcrWord

    def fake_ocr(_path):
        return [
            W("Director", 40, 40, 90, 14, (1, 1, 1)),
            W("John", 40, 80, 50, 14, (1, 1, 2)),
            W("Smith", 100, 80, 60, 14, (1, 1, 2)),
        ]

    seen = {}

    def scan_fn(text):
        seen["text"] = text
        return []  # detection result irrelevant; we only assert the assembled text shape

    pages, report = imageredact.scan_scanned_pdf(pdf_bytes, scan_fn, ocr_fn=fake_ocr, preview_max_px=300)
    assert pages is not None, report
    assert "text" in seen, "scan_fn should have received the assembled OCR text"
    assert "\n" in seen["text"], repr(seen["text"])
    assert seen["text"] == "Director\nJohn Smith", repr(seen["text"])


def test_image_redaction_output_is_compressed_jpeg():
    """FIX B: a rebuilt flat page is inserted as JPEG (DCTDecode), not an effectively
    uncompressed raster — so the burn output is a small fraction of the raw RGB size.
    The burn blacks out identifier pixels BEFORE the (lossy) JPEG encode, so removal is
    intact: the page still carries NO text layer, exactly one flat image, and the region
    under the box is black."""
    import io as _io
    import fitz
    from PIL import Image, ImageDraw
    from app import imageredact, ocr

    src = Image.new("RGB", (600, 800), "white")
    ImageDraw.Draw(src).rectangle([100, 100, 300, 150], fill=(255, 0, 0))  # identifier
    sb = _io.BytesIO()
    src.save(sb, "PNG")
    sdoc = fitz.open()
    sdoc.new_page(width=600, height=800).insert_image(fitz.Rect(0, 0, 600, 800), stream=sb.getvalue())
    pdf_bytes = sdoc.tobytes()
    sdoc.close()

    def fake_ocr(path):
        im = Image.open(path).convert("RGB")
        px = im.load()
        xs, ys = [], []
        for yy in range(0, im.height, 3):
            for xx in range(0, im.width, 3):
                r, g, b = px[xx, yy]
                if r > 180 and g < 70 and b < 70:
                    xs.append(xx)
                    ys.append(yy)
        if not xs:
            return []
        return [ocr.OcrWord("SECRET", min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))]

    out_bytes, report = imageredact.redact_scanned_pdf(
        pdf_bytes, scan_fn=lambda t: [(0, len(t))] if t else [], ocr_fn=fake_ocr
    )
    assert out_bytes is not None, report
    assert report["redacted_pages"] == 1 and report["boxes"] >= 1

    odoc = fitz.open(stream=out_bytes, filetype="pdf")
    assert not odoc[0].get_text("text").strip(), "output page is a flat image (no text layer)"
    imgs = odoc[0].get_images(full=True)
    assert len(imgs) == 1, "exactly one flat redacted raster"
    base = odoc.extract_image(imgs[0][0])
    assert base["ext"] in ("jpeg", "jpg"), f"page must be JPEG/DCTDecode, got {base['ext']!r}"
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    # Under-box pixels are black (burn survived the lossy encode).
    r, g, b = emb.getpixel((int(200 / 600 * emb.width), int(125 / 800 * emb.height)))
    assert r < 60 and g < 60 and b < 60, f"identifier not blacked out: {(r, g, b)}"
    odoc.close()

    # Dramatically smaller than the uncompressed RGB raster (PNG barely compresses a scan;
    # the pre-fix output ran ~90 MB/page). Use the embedded raster's own dimensions.
    raw_rgb = emb.width * emb.height * 3
    assert len(out_bytes) < 0.4 * raw_rgb, (len(out_bytes), raw_rgb)


def test_image_redaction_true_removal():
    """True pixel removal: a scanned page's identifier region is BLACK in the STORED
    (embedded) output image — not an overlay over still-present pixels — and
    non-identifier content survives."""
    import io as _io
    import fitz
    from PIL import Image, ImageDraw
    from app import imageredact, ocr

    # A "scanned" page = a full-page image (no text layer): a red block (the
    # "identifier") and a blue block (must survive).
    src = Image.new("RGB", (600, 800), "white")
    dr = ImageDraw.Draw(src)
    dr.rectangle([100, 100, 300, 150], fill=(255, 0, 0))
    dr.rectangle([200, 400, 300, 450], fill=(0, 0, 255))
    sb = _io.BytesIO()
    src.save(sb, "PNG")
    sdoc = fitz.open()
    sp = sdoc.new_page(width=600, height=800)
    sp.insert_image(sp.rect, stream=sb.getvalue())
    pdf_bytes = sdoc.tobytes()
    sdoc.close()
    chk = fitz.open(stream=pdf_bytes, filetype="pdf")
    assert not chk[0].get_text("text").strip(), "fixture must be a scanned (text-less) page"
    chk.close()

    # Fake OCR: locate the red block in the rendered image, return it as one word.
    def fake_ocr(path):
        im = Image.open(path).convert("RGB")
        px = im.load()
        xs, ys = [], []
        for yy in range(0, im.height, 3):
            for xx in range(0, im.width, 3):
                r, g, b = px[xx, yy]
                if r > 180 and g < 70 and b < 70:
                    xs.append(xx)
                    ys.append(yy)
        if not xs:
            return []
        return [ocr.OcrWord("SECRET", min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))]

    out_bytes, report = imageredact.redact_scanned_pdf(
        pdf_bytes, scan_fn=lambda t: [(0, len(t))] if t else [], ocr_fn=fake_ocr
    )
    assert out_bytes is not None, report
    assert report["scanned"] == 1 and report["redacted_pages"] == 1 and report["boxes"] >= 1

    odoc = fitz.open(stream=out_bytes, filetype="pdf")
    imgs = odoc[0].get_images(full=True)
    assert len(imgs) == 1, "exactly one flat redacted raster (the original is not retained)"
    base = odoc.extract_image(imgs[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()

    def avg(im, fx, fy):
        cx, cy = int(fx * im.width), int(fy * im.height)
        rs = gs = bs = n = 0
        for yy in range(cy - 3, cy + 4):
            for xx in range(cx - 3, cx + 4):
                if 0 <= xx < im.width and 0 <= yy < im.height:
                    r, g, b = im.getpixel((xx, yy))
                    rs += r
                    gs += g
                    bs += b
                    n += 1
        return rs / n, gs / n, bs / n

    # The identifier (red) region is BLACK in the stored image (true removal).
    r, g, b = avg(emb, 200 / 600, 125 / 800)
    assert r < 60 and g < 60 and b < 60, f"identifier not blacked out in stored image: {(r, g, b)}"
    # Non-identifier (blue) content survives.
    r2, g2, b2 = avg(emb, 250 / 600, 425 / 800)
    assert b2 > 150 and r2 < 90, f"non-identifier content lost: {(r2, g2, b2)}"


def test_image_redaction_passthrough_cap_and_graceful():
    """Digital pages pass through unredacted (text path's job); OCR-empty scanned pages
    are flattened + flagged; a malformed PDF errors; over-cap is refused fail-closed."""
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact, ocr

    # (a) A born-digital page (text layer) is COPIED THROUGH unchanged, not redacted.
    ddoc = fitz.open()
    ddoc.new_page().insert_text((72, 720), "Born digital jane@x.example")
    dbytes = ddoc.tobytes()
    ddoc.close()
    out, rep = imageredact.redact_scanned_pdf(
        dbytes, scan_fn=lambda t: [(0, len(t))], ocr_fn=lambda p: [ocr.OcrWord("x", 0, 0, 9, 9)]
    )
    assert out is not None and rep["digital_skipped"] == 1 and rep["scanned"] == 0 and rep["boxes"] == 0
    od = fitz.open(stream=out, filetype="pdf")
    assert "jane@x.example" in od[0].get_text("text"), "digital text-layer page preserved"
    od.close()

    # (b) Graceful: OCR finds nothing -> page flattened, no boxes, flagged ocr_empty.
    img = Image.new("RGB", (200, 200), "white")
    b = _io.BytesIO()
    img.save(b, "PNG")
    sdoc = fitz.open()
    sdoc.new_page(width=200, height=200).insert_image(fitz.Rect(0, 0, 200, 200), stream=b.getvalue())
    sbytes = sdoc.tobytes()
    sdoc.close()
    out2, rep2 = imageredact.redact_scanned_pdf(
        sbytes, scan_fn=lambda t: [(0, len(t))] if t else [], ocr_fn=lambda p: []
    )
    assert out2 is not None and rep2["scanned"] == 1 and rep2["ocr_empty_pages"] == 1 and rep2["boxes"] == 0

    # (c) Malformed bytes -> structured error, never a crash.
    bad, rep3 = imageredact.redact_scanned_pdf(b"not a pdf", scan_fn=lambda t: [], ocr_fn=lambda p: [])
    assert bad is None and "error" in rep3

    # (c2) A zero-page / degenerate PDF -> structured error, never a raise (whether fitz
    # opens it as 0 pages -> our guard, or rejects it -> the open-failure path).
    zero_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF"
    )
    outz, repz = imageredact.redact_scanned_pdf(zero_pdf, scan_fn=lambda t: [], ocr_fn=lambda p: [])
    assert outz is None and "error" in repz, repz

    # (d) Over the page cap -> refused fail-closed (no partial redaction).
    orig_cap = imageredact.MAX_PAGES
    imageredact.MAX_PAGES = 1
    try:
        td = fitz.open()
        td.new_page()
        td.new_page()
        tb = td.tobytes()
        td.close()
        outc, repc = imageredact.redact_scanned_pdf(tb, scan_fn=lambda t: [], ocr_fn=lambda p: [])
        assert outc is None and "too many pages" in repc.get("error", ""), repc
    finally:
        imageredact.MAX_PAGES = orig_cap


def test_image_redaction_mixed_page_is_redacted_not_passed_through():
    """REGRESSION (Critical): a page with BOTH a thin text layer AND a dominant scanned
    image must be IMAGE-redacted — not passed through as 'digital' — so its image-baked
    identifiers cannot escape both paths."""
    import io as _io
    import fitz
    from PIL import Image, ImageDraw
    from app import imageredact, ocr

    img = Image.new("RGB", (600, 800), "white")
    ImageDraw.Draw(img).rectangle([100, 100, 300, 150], fill=(255, 0, 0))  # identifier
    b = _io.BytesIO()
    img.save(b, "PNG")
    doc = fitz.open()
    page = doc.new_page(width=600, height=800)
    page.insert_image(page.rect, stream=b.getvalue())  # dominant scanned image
    page.insert_text((40, 780), "Bates-000123")         # thin text overlay
    pdf_bytes = doc.tobytes()
    doc.close()
    chk = fitz.open(stream=pdf_bytes, filetype="pdf")
    assert chk[0].get_text("text").strip(), "fixture must carry a text layer"
    chk.close()

    def fake_ocr(path):
        im = Image.open(path).convert("RGB")
        px = im.load()
        xs, ys = [], []
        for yy in range(0, im.height, 3):
            for xx in range(0, im.width, 3):
                r, g, bb = px[xx, yy]
                if r > 180 and g < 70 and bb < 70:
                    xs.append(xx)
                    ys.append(yy)
        return [ocr.OcrWord("SECRET", min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))] if xs else []

    out_bytes, rep = imageredact.redact_scanned_pdf(
        pdf_bytes, scan_fn=lambda t: [(0, len(t.encode("utf-8")))] if t else [], ocr_fn=fake_ocr
    )
    assert out_bytes is not None, rep
    # IMAGE-redacted, NOT passed through: counted scanned + mixed, a box burned.
    assert rep["scanned"] == 1 and rep["mixed_pages"] == 1 and rep["digital_skipped"] == 0, rep
    assert rep["boxes"] >= 1, rep
    odoc = fitz.open(stream=out_bytes, filetype="pdf")
    base = odoc.extract_image(odoc[0].get_images(full=True)[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()
    cx, cy = int(200 / 600 * emb.width), int(125 / 800 * emb.height)
    r, g, bb = emb.getpixel((cx, cy))
    assert r < 60 and g < 60 and bb < 60, f"mixed-page identifier not blacked out: {(r, g, bb)}"


def test_image_redaction_textless_small_image_is_redacted():
    """REGRESSION (HIGH): a TEXT-LESS page with a SMALL scanned image (<50% of the page)
    carrying an identifier must still be image-redacted (no text + ANY image) — not
    passed through as 'digital'."""
    import io as _io
    import fitz
    from PIL import Image, ImageDraw
    from app import imageredact, ocr

    sub = Image.new("RGB", (200, 150), "white")
    ImageDraw.Draw(sub).rectangle([20, 20, 180, 80], fill=(255, 0, 0))  # identifier
    b = _io.BytesIO()
    sub.save(b, "PNG")
    doc = fitz.open()
    page = doc.new_page(width=600, height=800)  # page area 480000
    page.insert_image(fitz.Rect(50, 50, 250, 200), stream=b.getvalue())  # 200x150 -> 6.25%
    pdf_bytes = doc.tobytes()
    doc.close()
    chk = fitz.open(stream=pdf_bytes, filetype="pdf")
    assert not chk[0].get_text("text").strip(), "fixture must be text-less"
    has_image, dominant = imageredact._image_coverage(chk[0])
    assert has_image and not dominant, (has_image, dominant)  # small image, not dominant
    chk.close()

    def fake_ocr(path):
        im = Image.open(path).convert("RGB")
        px = im.load()
        xs, ys = [], []
        for yy in range(0, im.height, 2):
            for xx in range(0, im.width, 2):
                r, g, bb = px[xx, yy]
                if r > 180 and g < 70 and bb < 70:
                    xs.append(xx)
                    ys.append(yy)
        return [ocr.OcrWord("SECRET", min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))] if xs else []

    out_bytes, rep = imageredact.redact_scanned_pdf(
        pdf_bytes, scan_fn=lambda t: [(0, len(t.encode("utf-8")))] if t else [], ocr_fn=fake_ocr
    )
    assert out_bytes is not None, rep
    # Image-redacted (NOT passed through) even though the image is small.
    assert rep["scanned"] == 1 and rep["digital_skipped"] == 0 and rep["boxes"] >= 1, rep
    odoc = fitz.open(stream=out_bytes, filetype="pdf")
    base = odoc.extract_image(odoc[0].get_images(full=True)[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()
    # Red block placed at page (70..230, 70..130) -> center ~ (150,100) -> fractions.
    cx, cy = int(150 / 600 * emb.width), int(100 / 800 * emb.height)
    r, g, bb = emb.getpixel((cx, cy))
    assert r < 70 and g < 70 and bb < 70, f"small-exhibit identifier not blacked: {(r, g, bb)}"


def test_image_redaction_bounded_pixmap_caps_giant_page():
    """DoS guard: a giant MediaBox must not allocate a multi-GB raster — the pixmap is
    downscaled to the megapixel budget; a normal page renders at full DPI."""
    import fitz
    from app import imageredact

    orig = imageredact.MAX_PAGE_MEGAPIXELS
    imageredact.MAX_PAGE_MEGAPIXELS = 1  # tiny budget so the test stays light
    try:
        doc = fitz.open()
        doc.new_page(width=20000, height=20000)  # ~3086 MP at 200 DPI if unclamped
        pix = imageredact._bounded_pixmap(doc[0], imageredact.RENDER_DPI)
        mp = (pix.width * pix.height) / 1_000_000.0
        assert mp <= 1.0 * 1.05, mp  # clamped to the budget
        doc.close()
        # A page within budget renders at full DPI (no downscale): 200pt @200dpi ~556px.
        doc2 = fitz.open()
        doc2.new_page(width=200, height=200)
        pix2 = imageredact._bounded_pixmap(doc2[0], 200)
        assert abs(pix2.width - round(200 / 72 * 200)) <= 2, pix2.width
        doc2.close()
    finally:
        imageredact.MAX_PAGE_MEGAPIXELS = orig


def test_image_redaction_multipage_order_preserved():
    """Output preserves page order + count when redacted and passthrough pages
    interleave; digital pages keep their text, scanned pages become a flat image."""
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact

    img = Image.new("RGB", (300, 400), "white")
    b = _io.BytesIO()
    img.save(b, "PNG")
    doc = fitz.open()
    doc.new_page(width=300, height=400).insert_text((40, 40), "PAGE-ZERO digital")  # 0: digital
    doc.new_page(width=300, height=400).insert_image(fitz.Rect(0, 0, 300, 400), stream=b.getvalue())  # 1: scan
    doc.new_page(width=300, height=400).insert_text((40, 40), "PAGE-TWO digital")  # 2: digital
    doc.new_page(width=300, height=400).insert_image(fitz.Rect(0, 0, 300, 400), stream=b.getvalue())  # 3: scan
    pdf_bytes = doc.tobytes()
    doc.close()

    out, rep = imageredact.redact_scanned_pdf(pdf_bytes, scan_fn=lambda t: [], ocr_fn=lambda p: [])
    assert out is not None, rep
    assert rep["pages"] == 4 and rep["scanned"] == 2 and rep["digital_skipped"] == 2, rep
    od = fitz.open(stream=out, filetype="pdf")
    assert od.page_count == 4, od.page_count
    assert "PAGE-ZERO" in od[0].get_text("text")
    assert not od[1].get_text("text").strip() and len(od[1].get_images()) == 1
    assert "PAGE-TWO" in od[2].get_text("text")
    assert not od[3].get_text("text").strip() and len(od[3].get_images()) == 1
    od.close()


def _two_scanned_page_pdf(width=300, height=400, n=2):
    """A PDF of `n` text-LESS full-page white images -> every page classifies as SCANNED.
    Returns the PDF bytes. (A shared builder for the whole-document-scan tests below.)"""
    import io as _io
    import fitz
    from PIL import Image

    img = Image.new("RGB", (width, height), "white")
    b = _io.BytesIO()
    img.save(b, "PNG")
    doc = fitz.open()
    for _ in range(n):
        doc.new_page(width=width, height=height).insert_image(
            fitz.Rect(0, 0, width, height), stream=b.getvalue())
    data = doc.tobytes()
    doc.close()
    return data


def _emb_pixel(out_bytes, page_index, x, y):
    """Sample the (x, y) RASTER pixel of the flat image embedded on output page
    `page_index` — the same pixel space the injected OcrWord boxes use (phase-I and
    phase-III rasters are identical size). Returns (r, g, b)."""
    import io as _io
    import fitz
    from PIL import Image

    doc = fitz.open(stream=out_bytes, filetype="pdf")
    try:
        base = doc.extract_image(doc[page_index].get_images(full=True)[0][0])
        emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
        return emb.getpixel((x, y))
    finally:
        doc.close()


def test_image_redaction_whole_document_single_scan_and_cross_page_burn():
    """WHOLE-DOCUMENT scan: two scanned pages reach the detector as ONE `scan_fn` call
    whose text is the two page texts joined by the 2-byte blank-line separator. A span the
    engine returns in PAGE 2's byte range (the cross-page propagation case) burns a box on
    page 2 and NOT on page 1 — proving the returned spans map back to the right page."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    pdf = _two_scanned_page_pdf(n=2)

    # Both pages OCR to a word "Alice" at the SAME raster box (call order = page order).
    def fake_ocr(_path):
        return [W("Alice", 40, 40, 60, 14, (1, 1, 1))]

    seen = {"count": 0, "texts": []}

    def scan_fn(text):
        seen["count"] += 1
        seen["texts"].append(text)
        # Simulate the engine propagating the name to page 2: return the SECOND occurrence.
        idx = text.rfind("Alice")
        return [(idx, idx + len("Alice"))]

    out, rep = imageredact.redact_scanned_pdf(pdf, scan_fn, ocr_fn=fake_ocr)
    assert out is not None, rep
    assert seen["count"] == 1, f"expected ONE whole-doc scan, got {seen['count']}"
    assert seen["texts"][0] == "Alice\n\nAlice", repr(seen["texts"][0])
    assert rep["scanned"] == 2 and rep["boxes"] == 1 and rep["redacted_pages"] == 1, rep
    # Page 2 (the mapped span) is blacked; page 1 (no span) stays white — same box pixel.
    r2, g2, b2 = _emb_pixel(out, 1, 70, 47)
    assert r2 < 60 and g2 < 60 and b2 < 60, f"page-2 span not burned: {(r2, g2, b2)}"
    r1, g1, b1 = _emb_pixel(out, 0, 70, 47)
    assert r1 > 180 and g1 > 180 and b1 > 180, f"page-1 wrongly burned: {(r1, g1, b1)}"


def test_image_redaction_span_straddling_page_boundary_burns_both():
    """A span that STRADDLES the page join (via ws-elastic cross-page propagation) is
    clamped to EACH page and burns BOTH fragments — never a crash, never a silent drop of
    the out-of-range half."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    pdf = _two_scanned_page_pdf(n=2)
    calls = {"n": 0}

    def fake_ocr(_path):
        calls["n"] += 1
        # page 1 -> "AAAA", page 2 -> "BBBB", each at the same raster box.
        return [W("AAAA" if calls["n"] == 1 else "BBBB", 40, 40, 60, 14, (1, 1, 1))]

    def scan_fn(text):
        # ONE span spanning from the start of page 1 through the join into page 2.
        return [(0, len(text.encode("utf-8")))]

    out, rep = imageredact.redact_scanned_pdf(pdf, scan_fn, ocr_fn=fake_ocr)
    assert out is not None, rep
    assert rep["boxes"] == 2 and rep["redacted_pages"] == 2, rep
    for pno in (0, 1):
        r, g, b = _emb_pixel(out, pno, 70, 47)
        assert r < 60 and g < 60 and b < 60, f"page {pno} fragment not burned: {(r, g, b)}"


def test_image_redaction_empty_ocr_page_keeps_join_alignment():
    """An OCR-EMPTY middle page must STILL occupy a slot in the join so later pages stay
    byte-aligned: page1 words, page2 no words, page3 words -> a span in PAGE 3's range
    still maps to page 3 (the regression this whole-document design could introduce)."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    pdf = _two_scanned_page_pdf(n=3)
    calls = {"n": 0}

    def fake_ocr(_path):
        calls["n"] += 1
        if calls["n"] == 1:
            return [W("AAAA", 40, 40, 60, 14, (1, 1, 1))]
        if calls["n"] == 2:
            return []  # empty OCR page in the middle
        return [W("CCCC", 40, 40, 60, 14, (1, 1, 1))]

    seen = {"count": 0, "text": None}

    def scan_fn(text):
        seen["count"] += 1
        seen["text"] = text
        idx = text.find("CCCC")  # a span in PAGE 3's range
        return [(idx, idx + 4)]

    out, rep = imageredact.redact_scanned_pdf(pdf, scan_fn, ocr_fn=fake_ocr)
    assert out is not None, rep
    assert seen["count"] == 1
    # Empty middle page contributes an empty segment -> two separators flank it.
    assert seen["text"] == "AAAA\n\n\n\nCCCC", repr(seen["text"])
    assert rep["scanned"] == 3 and rep["ocr_empty_pages"] == 1, rep
    assert rep["boxes"] == 1 and rep["redacted_pages"] == 1, rep
    # Page 3 burned; page 1 untouched (proves the span mapped to page 3, not page 1).
    r3, g3, b3 = _emb_pixel(out, 2, 70, 47)
    assert r3 < 60 and g3 < 60 and b3 < 60, f"page-3 span not burned: {(r3, g3, b3)}"
    r1, g1, b1 = _emb_pixel(out, 0, 70, 47)
    assert r1 > 180 and g1 > 180 and b1 > 180, f"page-1 wrongly burned: {(r1, g1, b1)}"


def test_scan_scanned_pdf_whole_document_single_scan_and_page_mapping():
    """Per-span SCAN path is ALSO whole-document: two scanned pages -> ONE `scan_fn` call
    on the joined text; a labeled span in PAGE 2's range produces a candidate on page 2
    (id `1-*`) and NONE on page 1 — the cross-page mapping, resolution-independent."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    pdf = _two_scanned_page_pdf(n=2)

    def fake_ocr(_path):
        return [W("Alice", 40, 40, 60, 14, (1, 1, 1))]

    seen = {"count": 0, "texts": []}

    def scan_fn(text):
        seen["count"] += 1
        seen["texts"].append(text)
        idx = text.rfind("Alice")  # page 2 occurrence
        return [(idx, idx + len("Alice"), "name")]

    pages, report = imageredact.scan_scanned_pdf(pdf, scan_fn, ocr_fn=fake_ocr, preview_max_px=300)
    assert pages is not None, report
    assert seen["count"] == 1 and seen["texts"][0] == "Alice\n\nAlice", seen
    assert report["scanned"] == 2 and report["candidates"] == 1, report
    p0 = [p for p in pages if p["index"] == 0][0]
    p1 = [p for p in pages if p["index"] == 1][0]
    assert p0["candidates"] == [], p0["candidates"]
    assert len(p1["candidates"]) == 1, p1["candidates"]
    assert p1["candidates"][0]["id"].startswith("1-"), p1["candidates"][0]["id"]
    assert p1["candidates"][0]["label"] == "name"


def test_ocr_confidence_parse_pick_better_and_words_to_text():
    """The TSV conf column (col 10) is KEPT per word (honesty spine), `page_confidence`
    averages only real (>= 0) confidences, `_pick_better` implements the documented
    adaptive-retry rule (higher mean wins; tie or unknown keeps the FIRST/default-PSM
    pass), and `words_to_text` rebuilds line breaks for indexing."""
    from app import ocr

    tsv = (
        "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n"
        "5\t1\t1\t1\t1\t1\t10\t20\t30\t12\t96.5\tHello\n"
        "5\t1\t1\t1\t1\t2\t50\t20\t30\t12\t-1\tGhost\n"      # -1 = not a real detection
        "5\t1\t1\t1\t2\t1\t10\t40\t30\t12\tabc\tOdd\n"       # malformed conf -> None
        "5\t1\t1\t1\t2\t2\t50\t40\t30\t12\t83.5\tWorld\n"
    )
    ws = ocr._parse_tsv_words(tsv)
    assert [w.text for w in ws] == ["Hello", "Ghost", "Odd", "World"]
    assert ws[0].conf == 96.5 and ws[1].conf == -1.0 and ws[2].conf is None
    # Mean over conf >= 0 rows only: (96.5 + 83.5) / 2.
    assert ocr.page_confidence(ws) == 90.0
    assert ocr.page_confidence([]) is None
    assert ocr.page_confidence([ocr.OcrWord("x", 0, 0, 5, 5)]) is None, "no conf -> unknown"

    W = ocr.OcrWord
    hi = [W("a", 0, 0, 5, 5, None, 90.0)]
    lo = [W("b", 0, 0, 5, 5, None, 40.0)]
    assert ocr._pick_better(lo, hi) is hi, "higher mean confidence wins"
    assert ocr._pick_better(hi, lo) is hi
    assert ocr._pick_better(lo, lo) is lo, "tie keeps the first (default-PSM) pass"
    assert ocr._pick_better(lo, []) is lo, "an unknown-confidence retry never wins"
    assert ocr._pick_better([], []) == []
    # COVERAGE FLOOR (review finding): a retry that scores a higher MEAN by reading
    # FEWER words must not silently replace the fuller pass — the dropped word can be
    # the identifier. < 80% of the first pass's word count or text length keeps first.
    four_lo = [W(t, 0, 0, 5, 5, None, 50.0) for t in ("NRIC", "S1234567D", "Tan", "Ah")]
    one_hi = [W("clean", 0, 0, 5, 5, None, 95.0)]
    assert ocr._pick_better(four_lo, one_hi) is four_lo, \
        "higher-conf retry with collapsed coverage must NOT win"
    # Same word COUNT but drastically less text also keeps first.
    four_hi_short = [W("a", 0, 0, 5, 5, None, 95.0) for _ in range(4)]
    assert ocr._pick_better(four_lo, four_hi_short) is four_lo
    # An empty first pass is beaten by ANY retry words (coverage can only grow).
    assert ocr._pick_better([], one_hi) is one_hi

    # words_to_text: same line -> space; line change -> newline; unknown ids -> space.
    words = [W("NRIC", 0, 0, 9, 9, (1, 1, 1)), W("S1234567D", 10, 0, 9, 9, (1, 1, 1)),
             W("next", 0, 12, 9, 9, (1, 1, 2)), W("free", 10, 12, 9, 9)]
    assert ocr.words_to_text(words) == "NRIC S1234567D\nnext free"


def test_ocr_langs_env_validated_against_tessdata():
    """LAWDATAMAN_OCR_LANGS composes `-l` as eng+extras, but an extra language rides
    ONLY when its .traineddata is verifiably present (tesseract hard-errors on an
    absent lang — that would kill OCR entirely). Malformed / injection-shaped tokens
    are refused; unset env is byte-identical to the old default ("eng")."""
    import tempfile as _tf
    from app import ocr

    old_langs = os.environ.pop("LAWDATAMAN_OCR_LANGS", None)
    old_prefix = os.environ.pop("TESSDATA_PREFIX", None)
    try:
        with _tf.TemporaryDirectory() as td:
            (Path(td) / "eng.traineddata").write_bytes(b"x")
            (Path(td) / "zzz.traineddata").write_bytes(b"x")
            os.environ["TESSDATA_PREFIX"] = td

            assert ocr.ocr_langs() == "eng", "no env -> today's default, exactly"

            os.environ["LAWDATAMAN_OCR_LANGS"] = "zzz, absent, ../evil, ENG, --psm"
            assert ocr.ocr_langs() == "eng+zzz", ocr.ocr_langs()

            os.environ["LAWDATAMAN_OCR_LANGS"] = "absent_only"
            assert ocr.ocr_langs() == "eng", "an absent pack is never passed"
    finally:
        for k, v in (("LAWDATAMAN_OCR_LANGS", old_langs), ("TESSDATA_PREFIX", old_prefix)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _rotated_scan_pdf_and_finder():
    """Fixture for the rotation-geometry tests: a 'scanned' page (300x150pt, image-only)
    whose raster carries a red 'identifier' block, plus a color-detecting fake OCR that
    reports the block as one word IN WHATEVER PIXEL SPACE it is handed (so it measures
    boxes in the corrected image, exactly like real OCR would)."""
    import io as _io
    import fitz
    from PIL import Image, ImageDraw
    from app import ocr

    src = Image.new("RGB", (600, 300), "white")
    ImageDraw.Draw(src).rectangle([80, 60, 220, 110], fill=(255, 0, 0))
    sb = _io.BytesIO()
    src.save(sb, "PNG")
    doc = fitz.open()
    p = doc.new_page(width=300, height=150)
    p.insert_image(p.rect, stream=sb.getvalue())
    pdf = doc.tobytes()
    doc.close()

    def fake_ocr(path):
        from PIL import Image as _Image
        im = _Image.open(path).convert("RGB")
        px = im.load()
        xs, ys = [], []
        for yy in range(0, im.height, 3):
            for xx in range(0, im.width, 3):
                r, g, b = px[xx, yy]
                if r > 180 and g < 70 and b < 70:
                    xs.append(xx)
                    ys.append(yy)
        if not xs:
            return []
        return [ocr.OcrWord("SECRET", min(xs), min(ys),
                            max(xs) - min(xs), max(ys) - min(ys))]

    return pdf, fake_ocr


def test_image_redaction_rotated_page_burns_in_corrected_space():
    """THE GEOMETRY INVARIANT (leak-relevant): word boxes are measured in the geometry-
    CORRECTED image space, and the corrected raster IS the output page — so with a 90°
    rotation correction the burn lands on the identifier, the output page comes out
    UPRIGHT (aspect swapped), and the identifier pixels are gone. prep_fn is injected
    (no tesseract needed) exactly like ocr_fn."""
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact

    pdf, fake_ocr = _rotated_scan_pdf_and_finder()

    def prep_fn(img):
        # Simulate OSD saying "rotate 90° clockwise to make this upright".
        return img.transpose(Image.ROTATE_270), {"rotate": 90, "deskew": 0.0, "osd_conf": 9.9}

    out, rep = imageredact.redact_scanned_pdf(
        pdf, scan_fn=lambda t: [(0, len(t.encode("utf-8")))] if t else [],
        ocr_fn=fake_ocr, prep_fn=prep_fn)
    assert out is not None, rep
    assert rep["boxes"] >= 1 and rep["redacted_pages"] == 1, rep

    odoc = fitz.open(stream=out, filetype="pdf")
    page = odoc[0]
    # Output page is UPRIGHT: the 300x150 landscape page comes out 150x300 portrait.
    assert abs(page.rect.width - 150) < 1 and abs(page.rect.height - 300) < 1, page.rect
    assert not page.get_text("text").strip(), "flat image output (no text layer)"
    base = odoc.extract_image(page.get_images(full=True)[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()
    # The embedded raster is the CORRECTED (rotated) raster: portrait.
    assert emb.height > emb.width, emb.size
    # TRUE REMOVAL under rotation: no red identifier pixel survives anywhere.
    px = emb.load()
    for yy in range(0, emb.height, 2):
        for xx in range(0, emb.width, 2):
            r, g, b = px[xx, yy]
            assert not (r > 180 and g < 70 and b < 70), \
                f"identifier pixel survived rotation-corrected burn at {(xx, yy)}"


def test_image_redaction_apply_selection_replays_scan_geo():
    """Scan<->apply GEOMETRY PARITY: scan_scanned_pdf returns each page's `geo`; apply
    replays it so the accepted page-fraction rects land in the same corrected pixel
    space the reviewer saw. With the geo echoed, the identifier is burned and the page
    comes out upright; without it, the page keeps the raw orientation (proving the
    replay is load-bearing, not decorative)."""
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact

    pdf, fake_ocr = _rotated_scan_pdf_and_finder()

    def prep_fn(img):
        return img.transpose(Image.ROTATE_270), {"rotate": 90, "deskew": 0.0, "osd_conf": 9.9}

    pages, rep = imageredact.scan_scanned_pdf(
        pdf, scan_fn=lambda t: [(0, len(t.encode("utf-8")), "term")] if t else [],
        ocr_fn=fake_ocr, prep_fn=prep_fn, preview_max_px=300)
    assert pages is not None, rep
    assert pages[0]["geo"] == {"rotate": 90, "deskew": 0.0}, pages[0]["geo"]
    cands = pages[0]["candidates"]
    assert len(cands) == 1, cands
    accepted = {0: cands[0]["rects"]}

    out, arep = imageredact.apply_selection_to_pdf(pdf, accepted, geo={0: pages[0]["geo"]})
    assert out is not None, arep
    assert arep["boxes"] == len(cands[0]["rects"]) and arep["redacted_pages"] == 1, arep
    odoc = fitz.open(stream=out, filetype="pdf")
    assert odoc[0].rect.width < odoc[0].rect.height, "geo replay -> upright output page"
    base = odoc.extract_image(odoc[0].get_images(full=True)[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()
    px = emb.load()
    for yy in range(0, emb.height, 2):
        for xx in range(0, emb.width, 2):
            r, g, b = px[xx, yy]
            assert not (r > 180 and g < 70 and b < 70), \
                f"identifier survived geo-replayed apply at {(xx, yy)}"

    # Without the geo echo the burn happens in RAW space (old-client behaviour): the
    # output page keeps the raw landscape orientation.
    out2, _ = imageredact.apply_selection_to_pdf(pdf, accepted)
    odoc2 = fitz.open(stream=out2, filetype="pdf")
    assert odoc2[0].rect.width > odoc2[0].rect.height, "no geo -> raw orientation"
    odoc2.close()


def test_image_redaction_low_conf_pages_flagged_never_filtered():
    """CONFIDENCE HONESTY: a page whose mean OCR word confidence is under
    `ocr.LOW_CONF_THRESHOLD` is FLAGGED (report `low_conf_pages` + per-page
    `ocr_conf`/`low_conf` in the scan payload) but its text still detects and burns —
    the flag is honesty, never filtering. Unknown confidence is never flagged low."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    pdf = _two_scanned_page_pdf(n=2)
    calls = {"n": 0}

    def fake_ocr(_path):
        calls["n"] += 1
        if calls["n"] == 1:
            # Page 1: low confidence (30 << threshold), still a real word.
            return [W("Alice", 40, 40, 60, 14, (1, 1, 1), 30.0)]
        # Page 2: exactly AT the threshold -> NOT low (strict <).
        return [W("Bob", 40, 40, 60, 14, (1, 1, 1), float(ocr.LOW_CONF_THRESHOLD))]

    out, rep = imageredact.redact_scanned_pdf(
        pdf, scan_fn=lambda t: [(0, len(t.encode("utf-8")))] if t else [], ocr_fn=fake_ocr)
    assert out is not None, rep
    assert rep["low_conf_pages"] == [{"page": 1, "conf": 30}], rep["low_conf_pages"]
    # NEVER filtered: the low-confidence page still burned its box.
    assert rep["boxes"] >= 1 and rep["redacted_pages"] == 2, rep

    calls["n"] = 0
    pages, srep = imageredact.scan_scanned_pdf(
        pdf, scan_fn=lambda t: [(0, len(t.encode("utf-8")), "term")] if t else [],
        ocr_fn=fake_ocr, preview_max_px=200)
    assert pages is not None, srep
    assert srep["low_conf_pages"] == [{"page": 1, "conf": 30}], srep["low_conf_pages"]
    assert pages[0]["low_conf"] is True and pages[0]["ocr_conf"] == 30, pages[0]
    assert pages[1]["low_conf"] is False and pages[1]["ocr_conf"] == int(ocr.LOW_CONF_THRESHOLD)
    assert len(pages[0]["candidates"]) >= 1, "low-confidence page still yields candidates"

    # Unknown confidence (hand-built words with no conf): never flagged low.
    pages2, srep2 = imageredact.scan_scanned_pdf(
        pdf, scan_fn=lambda t: [], ocr_fn=lambda p: [W("x", 1, 1, 5, 5)], preview_max_px=200)
    assert pages2 is not None and srep2["low_conf_pages"] == [], srep2
    assert pages2[0]["ocr_conf"] is None and pages2[0]["low_conf"] is False


def test_redaction_route_geo_and_low_conf_sanitizers():
    """The route-side sanitizers: `_sanitized_page_geo` hard-bounds the client geometry
    echo (right angles only, deskew within ocr.DESKEW_MAX_DEG, NaN/garbage dropped) and
    `_sanitized_low_conf_pages` coerces the honesty signal to plain ints (malformed
    entries dropped, never a raise after the export is written)."""
    import math
    from app import redactionroutes

    geo = redactionroutes._sanitized_page_geo({"geo": {
        "0": {"rotate": 90, "deskew": 0.0},
        1: {"rotate": 0, "deskew": -1.5},
        "2": {"rotate": 45, "deskew": 0.0},        # not a right angle -> dropped
        "3": {"rotate": 90, "deskew": 99.0},        # deskew out of bounds -> dropped
        "4": {"rotate": 90, "deskew": math.nan},    # NaN -> dropped
        "x": {"rotate": 90, "deskew": 0.0},         # bad page key -> dropped
        "5": "garbage",                              # not a dict -> dropped
        "6": {"rotate": 0, "deskew": 0.0},          # identity -> omitted (no-op)
    }})
    assert geo == {0: {"rotate": 90, "deskew": 0.0}, 1: {"rotate": 0, "deskew": -1.5}}, geo
    assert redactionroutes._sanitized_page_geo({}) == {}
    assert redactionroutes._sanitized_page_geo({"geo": "nope"}) == {}

    lcp = redactionroutes._sanitized_low_conf_pages(
        {"low_conf_pages": [{"page": 3, "conf": 41.7}, {"page": "x"}, "bad", {"conf": 5}]})
    assert lcp == [{"page": 3, "conf": 41}], lcp
    assert redactionroutes._sanitized_low_conf_pages({}) == []
    assert redactionroutes._sanitized_low_conf_pages(None) == []


def test_image_redaction_rotated_nric_real_ocr_end_to_end():
    """ITEM-1 PROOF (real engine, skipped without a tesseract binary): a 90°-rotated
    scanned page containing a known NRIC is OSD-corrected, OCR'd, and the NRIC is
    BURNED — the output page is upright, has no text layer, shows a black region, and
    re-OCR of the output can NOT recover the NRIC."""
    import io as _io
    import tempfile as _tf
    import fitz
    from PIL import Image
    from app import imageredact, ocr

    if not ocr.available():
        return  # unit path is the injected fake (above); this proof needs the real binary

    nric = "S1234567D"  # the documented test NRIC (fake)
    lines = [
        "CLIENT ONBOARDING RECORD — PRACTICE DATA ONLY",
        "",
        "This page is a synthetic scanned exhibit used to verify",
        "optical character recognition of rotated pages.",
        f"Subject NRIC: {nric}",  # exactly ONE occurrence (the scan burns one span)
        "Address: 1 Example Way, Singapore 000000",
        "All identifiers on this page are invented for testing.",
        "The quick brown fox jumps over the lazy dog 0123456789.",
        "Enough additional practice text follows so the orientation",
        "detector has a confident signal on this synthetic page.",
        "Pack my box with five dozen liquor jugs, judged quickly.",
        "How vexingly quick daft zebras jump over fences today.",
        "Sphinx of black quartz, judge my vow, said the clerk.",
        "The five boxing wizards jump quickly over the ledger.",
    ]
    src = fitz.open()
    page = src.new_page(width=612, height=792)
    y = 80
    for ln in lines:
        page.insert_text((60, y), ln, fontsize=14, fontname="cour")
        y += 24
    pix = page.get_pixmap(matrix=fitz.Matrix(300 / 72, 300 / 72))
    src.close()
    img = Image.open(_io.BytesIO(pix.tobytes("png"))).convert("RGB")
    rotated = img.transpose(Image.ROTATE_90)  # the scan arrives rotated 90° CCW

    sb = _io.BytesIO()
    rotated.save(sb, "JPEG", quality=90)
    sdoc = fitz.open()
    sp = sdoc.new_page(width=792, height=612)  # landscape page carrying the rotated scan
    sp.insert_image(sp.rect, stream=sb.getvalue())
    pdf = sdoc.tobytes()
    sdoc.close()

    hits = {"n": 0}

    def scan_fn(text):
        # Whitespace-insensitive NRIC find over the OCR'd text (byte offsets).
        enc = text.encode("utf-8")
        i = enc.find(nric.encode("utf-8"))
        if i < 0:
            return []
        hits["n"] += 1
        return [(i, i + len(nric))]

    out, rep = imageredact.redact_scanned_pdf(pdf, scan_fn)  # real OCR + real OSD
    assert out is not None, rep
    assert hits["n"] == 1 and rep["boxes"] >= 1, (hits, rep)

    odoc = fitz.open(stream=out, filetype="pdf")
    opage = odoc[0]
    assert opage.rect.width < opage.rect.height, "OSD-corrected output page is upright"
    assert not opage.get_text("text").strip(), "no text layer in the burned output"
    base = odoc.extract_image(opage.get_images(full=True)[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()
    # A visibly-burned region exists (solid black pixels).
    black = sum(1 for p in emb.getdata() if p[0] < 30 and p[1] < 30 and p[2] < 30)
    assert black > 500, f"no burned region visible ({black} black px)"
    # RECOVERY CHECK: re-OCR the burned output — the NRIC must not be recoverable.
    with _tf.TemporaryDirectory() as td:
        p = Path(td) / "burned.png"
        emb.save(p, "PNG")
        recovered = ocr.words_to_text(ocr.ocr_words(p))
    assert nric not in recovered.replace(" ", ""), "NRIC recoverable from burned output"


def test_image_redaction_multibyte_page_shifts_join_ranges_by_bytes():
    """PIN the historically-Critical byte-offset invariant ACROSS the page join: a
    MULTIBYTE word on page 1 ("café" = 4 chars, 5 UTF-8 bytes) shifts page 2's range by
    BYTES, and the engine's byte span for page 2 still burns page 2 only. The other
    whole-document tests are pure-ASCII (char index == byte offset), so they would keep
    passing if the mapping regressed to CHAR arithmetic — this one would not: in chars,
    "Alice" starts at 6; in bytes, at 7. The independent review of the whole-document
    restructure verified this behavior ad hoc; this test pins it."""
    from app import imageredact, ocr

    W = ocr.OcrWord
    pdf = _two_scanned_page_pdf(n=2)

    calls = {"n": 0}

    def fake_ocr(_path):
        calls["n"] += 1
        # Page 1 OCRs to the multibyte word; page 2 to the target identifier.
        word = "café" if calls["n"] == 1 else "Alice"
        return [W(word, 40, 40, 60, 14, (1, 1, 1))]

    seen = {}

    def scan_fn(text):
        seen["text"] = text
        # The engine reports UTF-8 BYTE offsets: "café"(5B) + "\n\n"(2B) -> 7.
        assert text.encode("utf-8")[7:12] == b"Alice"
        return [(7, 12)]

    out, rep = imageredact.redact_scanned_pdf(pdf, scan_fn, ocr_fn=fake_ocr)
    assert out is not None, rep
    assert seen["text"] == "café\n\nAlice", repr(seen["text"])
    assert rep["boxes"] == 1 and rep["redacted_pages"] == 1, rep
    # Page 2's word box burned; page 1's identical box untouched (char-arithmetic would
    # mis-base the span and burn the wrong page / no page).
    r2, g2, b2 = _emb_pixel(out, 1, 70, 47)
    assert r2 < 60 and g2 < 60 and b2 < 60, f"page-2 span not burned: {(r2, g2, b2)}"
    r1, g1, b1 = _emb_pixel(out, 0, 70, 47)
    assert r1 > 180 and g1 > 180 and b1 > 180, f"page-1 wrongly burned: {(r1, g1, b1)}"


def test_image_redaction_per_span_scan_apply_roundtrip():
    """v2 per-span: scan returns fractional candidate boxes; applying the ACCEPTED
    fractions burns exactly that region (true removal) while a REJECTED box leaves its
    identifier visible — proving the fraction coords round-trip across resolutions."""
    import io as _io
    import fitz
    from PIL import Image, ImageDraw
    from app import imageredact, ocr

    src = Image.new("RGB", (600, 800), "white")
    d = ImageDraw.Draw(src)
    d.rectangle([100, 100, 280, 150], fill=(255, 0, 0))   # candidate A (red, top)
    d.rectangle([100, 400, 280, 450], fill=(0, 180, 0))   # candidate B (green, lower)
    sb = _io.BytesIO()
    src.save(sb, "PNG")
    doc = fitz.open()
    doc.new_page(width=600, height=800).insert_image(fitz.Rect(0, 0, 600, 800), stream=sb.getvalue())
    pdf_bytes = doc.tobytes()
    doc.close()

    def fake_ocr(path):
        im = Image.open(path).convert("RGB")
        px = im.load()

        def bbox(pred):
            xs, ys = [], []
            for yy in range(0, im.height, 3):
                for xx in range(0, im.width, 3):
                    if pred(px[xx, yy]):
                        xs.append(xx)
                        ys.append(yy)
            return (min(xs), min(ys), max(xs), max(ys)) if xs else None

        words = []
        rb = bbox(lambda c: c[0] > 180 and c[1] < 70 and c[2] < 70)
        gb = bbox(lambda c: c[1] > 120 and c[0] < 90 and c[2] < 90)
        if rb:
            words.append(ocr.OcrWord("AAAA", rb[0], rb[1], rb[2] - rb[0], rb[3] - rb[1]))
        if gb:
            words.append(ocr.OcrWord("BBBB", gb[0], gb[1], gb[2] - gb[0], gb[3] - gb[1]))
        return words

    def scan_fn(text):
        out = []
        i = text.find("AAAA")
        if i >= 0:
            out.append((i, i + 4, "idA"))
        j = text.find("BBBB")
        if j >= 0:
            out.append((j, j + 4, "idB"))
        return out

    pages, report = imageredact.scan_scanned_pdf(pdf_bytes, scan_fn, ocr_fn=fake_ocr, preview_max_px=300)
    assert pages is not None and len(pages) == 1, report
    cands = pages[0]["candidates"]
    assert len(cands) == 2 and report["candidates"] == 2, cands
    assert pages[0]["preview"], "a preview image is returned"
    for c in cands:
        for v in c["bbox"] + [x for r in c["rects"] for x in r]:
            assert 0.0 <= v <= 1.0, c  # fractions
    red = [c for c in cands if c["bbox"][1] < 0.4][0]
    green = [c for c in cands if c["bbox"][1] > 0.4][0]
    assert red["label"] == "idA" and green["label"] == "idB"

    # ACCEPT only the red candidate.
    out, rep = imageredact.apply_selection_to_pdf(pdf_bytes, {0: red["rects"]})
    assert out is not None and rep["boxes"] >= 1, rep
    odoc = fitz.open(stream=out, filetype="pdf")
    base = odoc.extract_image(odoc[0].get_images(full=True)[0][0])
    emb = Image.open(_io.BytesIO(base["image"])).convert("RGB")
    odoc.close()

    def avg(im, fx, fy):
        cx, cy = int(fx * im.width), int(fy * im.height)
        rs = gs = bs = n = 0
        for yy in range(cy - 2, cy + 3):
            for xx in range(cx - 2, cx + 3):
                if 0 <= xx < im.width and 0 <= yy < im.height:
                    r, g, b = im.getpixel((xx, yy))
                    rs += r
                    gs += g
                    bs += b
                    n += 1
        return rs / n, gs / n, bs / n

    r, g, b = avg(emb, 190 / 600, 125 / 800)
    assert r < 60 and g < 60 and b < 60, f"accepted (red) not blacked: {(r, g, b)}"
    r2, g2, b2 = avg(emb, 190 / 600, 425 / 800)
    assert g2 > 100 and r2 < 90, f"rejected (green) should survive: {(r2, g2, b2)}"


def test_image_redaction_per_span_caps_and_routes():
    """v2: scan refuses over the preview-page cap; the routes are token-guarded;
    apply-selection works without OCR (pure burn) and bounds the accepted-rect count."""
    import base64
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact, ocr

    # (a) Preview-page cap -> refused with too_many (fail-closed).
    orig = imageredact.SCAN_PREVIEW_MAX_PAGES
    imageredact.SCAN_PREVIEW_MAX_PAGES = 1
    try:
        d2 = fitz.open()
        for _ in range(2):
            pp = d2.new_page(width=200, height=200)
            ib = _io.BytesIO()
            Image.new("RGB", (200, 200), "white").save(ib, "PNG")
            pp.insert_image(pp.rect, stream=ib.getvalue())
        pg2, rp2 = imageredact.scan_scanned_pdf(d2.tobytes(), lambda t: [], ocr_fn=lambda p: [])
        d2.close()
        assert pg2 is None and rp2.get("too_many"), rp2
    finally:
        imageredact.SCAN_PREVIEW_MAX_PAGES = orig

    # (b) Routes: token guard + fail-closed + apply-selection burns without OCR.
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/redaction/pdf-ocr-scan", json={"data_b64": "eA=="}).status_code == 403
    assert c_noauth.post("/api/redaction/pdf-ocr-apply-selection", json={"data_b64": "eA=="}).status_code == 403

    c = _client()
    sd = fitz.open()
    sp = sd.new_page(width=200, height=200)
    ib = _io.BytesIO()
    Image.new("RGB", (200, 200), "white").save(ib, "PNG")
    sp.insert_image(sp.rect, stream=ib.getvalue())
    scanned_b64 = base64.b64encode(sd.tobytes()).decode()
    sd.close()

    if not ocr.available():  # scan needs OCR -> fail-closed 503 in this env
        assert c.post("/api/redaction/pdf-ocr-scan", json={"data_b64": scanned_b64}).status_code == 503

    # apply-selection does NOT need OCR -> burns the given box + saves.
    r = c.post(
        "/api/redaction/pdf-ocr-apply-selection",
        json={"filename": "x.pdf", "data_b64": scanned_b64, "accepted": {"0": [[0.1, 0.1, 0.5, 0.3]]}},
    )
    assert r.status_code == 200, r.status_code
    body = _prepared_result(r.json())
    assert body.get("ok") and body["report"]["boxes"] >= 1, body

    # Accepted-rect cap -> 400.
    huge = {"0": [[0.0, 0.0, 0.01, 0.01]] * (imageredact.MAX_SELECTION_RECTS + 1)}
    rc = c.post(
        "/api/redaction/pdf-ocr-apply-selection",
        json={"filename": "x.pdf", "data_b64": scanned_b64, "accepted": huge},
    )
    assert rc.status_code == 400, rc.status_code



def test_image_redaction_encrypted_and_inf_robustness():
    """v2 review nits: an encrypted PDF -> structured error (not a late raise) across all
    three entry points; an inf fraction in apply-selection skips that box, not the op."""
    import io as _io
    import fitz
    from PIL import Image
    from app import imageredact

    doc = fitz.open()
    doc.new_page().insert_text((72, 72), "secret")
    enc = doc.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="pw", user_pw="pw")
    doc.close()
    out1, e1 = imageredact.redact_scanned_pdf(enc, scan_fn=lambda t: [], ocr_fn=lambda p: [])
    assert out1 is None and "error" in e1, e1
    pg2, e2 = imageredact.scan_scanned_pdf(enc, lambda t: [], ocr_fn=lambda p: [])
    assert pg2 is None and "error" in e2, e2
    out3, e3 = imageredact.apply_selection_to_pdf(enc, {0: [[0.1, 0.1, 0.4, 0.2]]})
    assert out3 is None and "error" in e3, e3

    # inf fraction on a real scanned page -> that box skipped, op still succeeds.
    img = Image.new("RGB", (200, 200), "white")
    b = _io.BytesIO()
    img.save(b, "PNG")
    sd = fitz.open()
    sd.new_page(width=200, height=200).insert_image(fitz.Rect(0, 0, 200, 200), stream=b.getvalue())
    sb = sd.tobytes()
    sd.close()
    out4, rep4 = imageredact.apply_selection_to_pdf(
        sb, {0: [[float("inf"), 0.0, 1.0, 1.0], [0.1, 0.1, 0.5, 0.5]]}
    )
    assert out4 is not None, rep4
    assert rep4["boxes"] == 1, rep4  # the inf box skipped; the valid box burned


def test_ocr_tessdata_bundling_path():
    """Tesseract bundling: ocr locates the language data where the packager stages it
    (vendor/tesseract/tessdata) and passes it via --tessdata-dir (configfile last); with
    no bundled data it falls back to the system tesseract."""
    import os
    import tempfile
    from pathlib import Path

    from app import ocr

    d = Path(tempfile.mkdtemp(prefix="ldm-vendor-"))
    (d / "tesseract" / "tessdata").mkdir(parents=True)
    (d / "tesseract" / "tessdata" / "eng.traineddata").write_bytes(b"x")
    old_vendor = os.environ.get("LAWDATAMAN_VENDOR_DIR")
    old_pref = os.environ.pop("TESSDATA_PREFIX", None)
    os.environ["LAWDATAMAN_VENDOR_DIR"] = str(d)
    try:
        td = ocr.tessdata_dir()
        assert td is not None and td.name == "tessdata" and td.parent.name == "tesseract", td
        cmd = ocr._tess_cmd("tesseract", "/img.png", "eng", "tsv")
        assert cmd[:3] == ["tesseract", "/img.png", "stdout"], cmd
        assert "--tessdata-dir" in cmd and cmd[cmd.index("--tessdata-dir") + 1] == str(td), cmd
        assert cmd[-1] == "tsv", cmd  # the configfile MUST be last
        assert ocr._env().get("TESSDATA_PREFIX") == str(td)
        # No bundled data -> no --tessdata-dir (tesseract uses its own).
        os.environ["LAWDATAMAN_VENDOR_DIR"] = str(d / "nope")
        assert ocr.tessdata_dir() is None
        assert "--tessdata-dir" not in ocr._tess_cmd("tesseract", "/i.png", "eng")
    finally:
        if old_vendor is None:
            os.environ.pop("LAWDATAMAN_VENDOR_DIR", None)
        else:
            os.environ["LAWDATAMAN_VENDOR_DIR"] = old_vendor
        if old_pref is not None:
            os.environ["TESSDATA_PREFIX"] = old_pref


def test_redaction_pdf_ocr_route_fail_closed():
    """The OCR image-redaction route needs a token, validates input, and FAILS CLOSED
    when no OCR engine is present (an absent OCR engine must never silently return an
    unredacted 'redacted' PDF)."""
    import base64
    from app import ocr

    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/redaction/pdf-ocr-apply", json={"data_b64": "eA=="}).status_code == 403
    c = _client()
    assert c.post("/api/redaction/pdf-ocr-apply", json={}).status_code == 400  # no file data
    pdf_b64 = base64.b64encode(b"%PDF-1.4 minimal").decode()
    r = c.post("/api/redaction/pdf-ocr-apply", json={"data_b64": pdf_b64})
    if not ocr.available():
        assert r.status_code == 503, r.status_code
        assert "OCR" in r.json().get("error", ""), r.json()


def test_redaction_page_renders():
    """The /redaction page renders, injects the token, and is air-gapped."""
    c = _client()
    r = c.get("/redaction")
    assert r.status_code == 200, r.text
    assert "Redaction review" in r.text
    assert "__DRR_TOKEN__" not in r.text, "token placeholder must be replaced"
    assert "http://" not in r.text and "https://" not in r.text, "page must be air-gapped"


def test_redaction_review_grouping_is_wired():
    """The review-layer grouping (collapse repeated/boilerplate candidates into one
    row + bulk accept/dismiss) is inlined into the served page and wired to the
    recall-safe source of truth.

    We can't unit-test the JS here (no DOM seam in this suite), so this guards the
    LOAD-BEARING invariant structurally: the apply set is read from the PER-CANDIDATE
    `.memberbox` checkboxes (which every single row AND every grouped member carries),
    NEVER from the group-control `.groupbox`. The pure `groupCandidates`/`digitTemplate`
    helpers and their template-collapse + apply-set-invariance are verified separately
    in the node check (scratchpad); here we confirm the code actually ships in the page
    and reads the right boxes."""
    c = _client()
    page = c.get("/redaction").text
    # The pure grouping helpers ship in the page.
    assert "function digitTemplate(" in page
    assert "function groupCandidates(" in page
    # The apply selection reads the PER-CANDIDATE member boxes (the source of truth),
    # not the group control box — this is the recall-safety invariant.
    assert "#review input.memberbox:checked" in page
    assert page.count("#review input.memberbox:checked") >= 2, \
        "both acceptedSpans (text) and acceptedPdfIds (pdf) must read .memberbox"
    # The group control box is a class distinct from the member box, so it is never
    # mistaken for an apply source.
    assert "groupbox" in page and "memberbox" in page
    # Bulk + override controls are present.
    assert "grouptoggle" in page and "candgroup" in page
    # Still air-gapped after the new JS/CSS is inlined.
    assert "http://" not in page and "https://" not in page


def test_scanned_pdf_imgreview_panel_is_unhidden_on_render():
    """The scanned-PDF per-box review panel must become VISIBLE when it renders.

    Regression class (audit-caught dead end): every scan path adds `hidden` to
    #imgreview as a stale-content reset, and goStage('image') only shows the PARENT
    stage section — so unless renderImgReview() itself removes `hidden`, the per-box
    review renders into an invisible card: the reviewer sees the scanned-PDF banner,
    no boxes, no "Redact & save" button, and the flagship scanned flow is a dead end.
    No DOM seam in this suite, so pin it structurally in the SERVED page: the reset
    (add) exists AND the render-time unhide (remove) exists."""
    c = _client()
    page = c.get("/redaction").text
    assert "imgreview.classList.add('hidden')" in page, (
        "the stale-content reset is gone — if it was removed on purpose, this test and "
        "the unhide below should be rethought together"
    )
    assert "imgreview.classList.remove('hidden')" in page, (
        "renderImgReview() no longer unhides #imgreview — the scanned-PDF per-box "
        "review renders invisible (dead-end flow); see app/ui/redaction.ocr.js"
    )


def test_redaction_reviewer_trust_and_polish_is_wired():
    """Trust + polish pass (UX gating + honest status surfacing) ships in the served page.

    No DOM seam in this suite, so this guards the LOAD-BEARING invariants structurally —
    that the gating + honest-status code actually inlines into the air-gapped page:
      * the "Next: sensitive passages" button starts DISABLED (no silent no-op) and is
        gated on the SINGLE reviewComplete() source of truth, with a plain-language reason;
      * the labels (pseudonymization) radio is disabled for a PDF document (text-path only);
      * empty-text export is guarded (never "export nothing" silently);
      * the engine's honesty signals are surfaced: could_not_remove (apply leak-direction),
        unmapped_fonts (best-effort decode), low_text (scanned) — and the success copy never
        over-claims "safe to send" when there are caveats.
    """
    c = _client()
    page = c.get("/redaction").text

    # A1: the SINGLE Review continue button ships disabled in the markup (no enabled flash, no
    # silent no-op). The sensitive passages fold into Review, so this one button (#toExportBtn)
    # is gated on BOTH gates — careful-review completeness AND passage acknowledgement.
    assert 'id="toExportBtn"' in page and "disabled" in page
    assert "toExportBtn" in page and "reviewComplete()" in page and "passagesAllAcked()" in page
    # Plain-language reason copy.
    assert "decide these first" in page

    # A3a: labels radio disabled for a PDF + a why-disabled hint.
    assert "syncReplStyleForMode" in page
    assert 'id="replPdfHint"' in page
    assert "Labels aren" in page  # "Labels aren't available for a PDF"

    # A3b: empty-text export is guarded (warn, not a silent no-op).
    assert "There is no text to export" in page

    # B4/B6: unmapped_fonts + low_text are both surfaced loudly (banner-class warnings).
    assert "unmapped_fonts" in page
    assert "low_text" in page
    assert "best-effort" in page  # the unmapped-font honesty phrasing

    # B5: could_not_remove (the leak-direction) is surfaced prominently after an apply.
    assert "could_not_remove" in page
    assert "could NOT be removed" in page

    # B7: anti-over-claim — caveat-aware completion copy never headlines a clean success.
    assert "with " in page and "caveat" in page
    assert "safe to send" in page  # the honest never-"safe-to-send" framing is present

    # Still air-gapped after the new JS/CSS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_new_document_resets_state_and_provenance_is_wired():
    """Leak-direction fix (review findings #1/#2) ships in the served page.

    The bug: a NEW document loaded via registerUpload / "Redact another document" reset
    NONE of the scan-derived state (the `cands` scan-candidate state — a closure-local var
    now; formerly window.__cands — plus decided, lastUnmappedFonts/lastLowText) and did NOT
    re-lock the gates — so scan A (clean) -> load B (unmapped) without a re-scan left A's
    open Export gate + A's "clean" flag, and applying B dropped its caveat (THE leak
    direction). No DOM seam in this suite, so guard the load-bearing invariants structurally:
    the reset + provenance fail-safe + tightened review gate all inline into the air-gapped
    page. The behavioral proof is the node harness (test below)."""
    c = _client()
    page = c.get("/redaction").text

    # 1) The new-document reset exists and registerUpload routes through it.
    assert "function resetScanState(" in page
    assert "resetScanState();" in page
    # It drops the scan-derived state (no inherited findings / clean flags / decisions).
    # `cands` was promoted from window.__cands to a closure-local var (task: normalize the
    # window.__cands/__passages/__reidBefore globals) — the reset now assigns the bare name.
    assert "cands = undefined;" in page
    assert "scanProvenanceFile = null;" in page and "scanProvenanceText = null;" in page

    # 2) The provenance fail-safe exists and both apply paths consult it BEFORE writing.
    assert "function scanProvenanceMatches(" in page
    assert page.count("scanProvenanceMatches()") >= 3, \
        "provenance must be checked in doPdfExport AND doTextExport (plus its definition)"
    # On mismatch the export REFUSES with a re-scan prompt (never inherits a prior 'clean').
    assert "scan it again before saving" in page or "Scan it again" in page

    # 3) Review is gated on a FRESH scan, not merely mode==='pdf' (the gate-leak is closed).
    assert "if (name === 'review') return scanned;" in page

    # 4) "Redact another document" restarts cleanly (resets + re-locks via the same path).
    assert 'id="redactAnotherBtn"' in page

    # Still air-gapped after the new JS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_reset_guard_node_harness():
    """Behavioral regression for the leak-direction fix: drive the real redaction.js
    (resetScanState / registerUpload / scanProvenanceMatches / canEnter) under a minimal
    DOM shim and prove the scan-A -> load-B -> export edge FAILS SAFE (Findings #1/#2).

    Runs the committed node harness tests/redaction_reset_guard.test.js. SKIPS (does not
    fail) if `node` is unavailable on the runner, so a node-less CI box still goes green —
    the structural test above guards the wiring everywhere; this adds the behavioral proof
    wherever node exists. Deterministic + air-gapped (no network)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_reset_guard.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run(
        [node, str(harness), str(target)],
        capture_output=True, text=True, timeout=60,
    )
    # Surface the harness output on failure so a regression is legible.
    assert proc.returncode == 0, (
        "redaction reset/provenance harness failed — the scan-A -> load-B -> export leak "
        "edge no longer fails safe:\n" + proc.stdout + "\n" + proc.stderr
    )
    assert "ALL PASS" in proc.stdout, proc.stdout


def test_redaction_pdf_per_span_selection_is_wired():
    """Interactive per-span PDF redaction (deselect before apply) ships in the served page.

    No DOM seam in this suite, so guard the LOAD-BEARING invariants structurally (the
    behavioral proof is the node harness below):
      * default = EVERY candidate SELECTED (renderPdfReview pre-checks both tiers) so an
        untouched review == today's apply-all (the full id list);
      * the apply set is the SELECTED ids — acceptedPdfIds() reads :checked memberboxes and
        pdf-apply sends them as accept_ids;
      * a live "N of M detections will be redacted" count tracks the selection;
      * the empty-selection FAIL-SAFE refuses (never writes a clean "redacted" file);
      * a non-located / capped detection is STILL removed unless deselected (the user is told
        no-box != not-removed).
    """
    c = _client()
    page = c.get("/redaction").text

    # The apply set is the SELECTED candidate ids, sent explicitly as accept_ids.
    assert "function acceptedPdfIds(" in page
    assert "accept_ids:ids" in page or "accept_ids: ids" in page

    # The live "N of M ... will be redacted" count + its updater.
    assert "function updatePdfRedactCount(" in page
    assert "will be redacted" in page
    assert 'id="pdfRedactCount"' in page

    # Box click TOGGLES the candidate (deselect = keep), not just a jump.
    assert "function onPreviewBoxClick(" in page
    assert "box.checked = !box.checked;" in page

    # Single (non-grouped) candidate rows fire a change so the count/boxes/gate stay live.
    assert "onTierMemberChange" in page

    # Empty-selection FAIL-SAFE: refuse, never a clean "redacted" file.
    assert "excluded all detections" in page

    # #7 count↔payload single source of truth: both the count + the payload derive from the
    # SAME classifier, so they can't drift; a SELECTED candidate with NO usable id is reported
    # via missingId and FAILS the apply CLOSED (never silently dropped = no under-removal).
    assert "function selectedPdfCandidates(" in page
    assert "missingId" in page
    assert "sel.missingId > 0" in page  # the fail-closed guard in doPdfExport

    # Non-located / capped detections are STILL removed unless deselected (no-box != not-removed).
    assert 'id="pdfNonLocatedNote"' in page
    assert "STILL removed" in page

    # The seam exposes the per-span selection internals for the node harness.
    assert "acceptedPdfIds: acceptedPdfIds" in page
    assert "updatePdfRedactCount: updatePdfRedactCount" in page
    assert "selectedPdfCandidates: selectedPdfCandidates" in page

    # Still air-gapped after the new JS/CSS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_health_and_a11y_honesty_is_wired():
    """FE H-2 + FE M-2 honesty invariants ship in the served redaction page.

    FE H-2: checkEngineHealth()'s catch must set the OFFLINE state, never "Tool ready" — a
            network/engine error means we COULDN'T reach the tool, so a green chip would be a
            dishonest-ready (violates honest-framing).
    FE M-2: the ARIA live region (announce) must NOT carry cand.value (cleartext PII) — it
            announces a recognizer + position description instead.
    """
    c = _client()
    page = c.get("/redaction").text

    # FE H-2: the health-check catch fails to OFFLINE (false), not a false-ready (true).
    import re as _re
    m = _re.search(r"async function checkEngineHealth\(\).*?\n  \}", page, _re.S)
    assert m, "checkEngineHealth not found"
    body = m.group(0)
    assert "setEngineHealth(false)" in body, "health-check catch must fail to OFFLINE"
    assert "setEngineHealth(true)" not in body, \
        "FE H-2: a network/engine error must NOT show '✓ Tool ready' (dishonest-ready)"

    # FE M-2: the preview-click announce describes the finding by recognizer + position, and
    # does NOT push the matched value (cleartext) into the live region. Capture from the
    # function header to the NEXT top-level function so the body is bounded precisely.
    m2 = _re.search(
        r"function onPreviewClick\(idx\)\{(.*?)\n  // Reflect ONE candidate", page, _re.S)
    assert m2, "onPreviewClick not found"
    click_body = m2.group(1)
    assert "announce(" in click_body
    # The announce arg must not interpolate the matched value (cand.value). (The function has
    # no other use of it now; this asserts the a11y line specifically stays cleartext-free.)
    assert "cand.value" not in click_body, \
        "FE M-2: announce() must not put the matched value (cleartext PII) in the ARIA live region"
    assert "finding " in click_body and "cand.recognizer" in click_body

    # Still air-gapped.
    assert "http://" not in page and "https://" not in page


def test_redaction_pdf_selection_node_harness():
    """Behavioral regression for interactive per-span PDF redaction: drive the REAL
    redaction.js (acceptedPdfIds / updatePdfRedactCount) under a minimal DOM that models the
    #review memberbox checkboxes, and prove the carrier-critical invariants —
    default=all-ids (apply-all equivalence), subset->only-those, empty->[] (refused), a toggle
    changes the payload, and the "N of M" count tracks selection without drifting from the
    payload.

    Runs the committed node harness tests/redaction_pdf_selection.test.js. SKIPS (does not
    fail) if `node` is unavailable on the runner — the structural test above guards the wiring
    everywhere; this adds the behavioral proof wherever node exists. Deterministic + air-gapped.
    """
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_pdf_selection.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run(
        [node, str(harness), str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        "redaction per-span selection harness failed — the deselect-before-apply mapping or "
        "the empty-selection fail-safe regressed:\n" + proc.stdout + "\n" + proc.stderr
    )
    assert "ALL PASS" in proc.stdout, proc.stdout


def test_redaction_reid_meter_node_harness():
    """Behavioral proof for the re-identification EXPOSURE meter: drive the REAL
    redaction.js renderReidMeter() under a minimal DOM shim and prove the meter renders
    deterministically, escapes a hostile band string (degrading it to a safe class), shows
    the before->after gauges + delta + surviving-category breakdown, reports the HONEST
    "unchanged" residual case, hides when there is no before-score, and leaks no document
    cleartext (counts only).

    Runs the committed node harness tests/redaction_reid_meter.test.js. SKIPS (does not
    fail) if `node` is unavailable on the runner — the structural test above guards the
    wiring everywhere; this adds the behavioral proof wherever node exists. Deterministic +
    air-gapped (no network)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_reid_meter.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run(
        [node, str(harness), str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        "redaction re-identification exposure meter harness failed:\n"
        + proc.stdout + "\n" + proc.stderr
    )
    assert "ALL PASS" in proc.stdout, proc.stdout


def test_redaction_term_byte_cap_bridge():
    """Finding #1 (the LEAK CLASS) — the Python bridge caps user TERMS in UTF-8 BYTES (the
    SAME unit the redact-cli bin caps in), not Python characters, AND a dropped over-length
    term is REPORTED (never a silent un-redaction).

    A long multibyte party name (CJK / accented) can be UNDER a CHAR cap yet OVER the BYTE
    cap; the OLD char-based filter sent it to the bin, which then silently dropped it = the
    name was never redacted and the lawyer was not told. This locks: (a) the over-byte term
    is NOT in the request, (b) `term_drop_report` surfaces it, (c) an under-byte multibyte
    term is KEPT, (d) absent terms keep the request byte-identical (empty report)."""
    from app import redactionmodel as rm

    # The cap is bytes — confirm the constant + back-compat alias agree.
    assert rm.MAX_TERM_BYTES == 200
    assert rm.MAX_TERM_CHARS == rm.MAX_TERM_BYTES

    # 67 CJK chars = 201 UTF-8 bytes: PASSES a 200-CHAR cap, FAILS the 200-BYTE cap.
    over = "名" * 67
    assert len(over) == 67 and len(over.encode("utf-8")) == 201
    under = "名" * 66  # 198 bytes — under the cap
    assert len(under.encode("utf-8")) == 198

    opts = {"terms": [over, "Massimo Greco", "   ", under, over]}
    norm = rm.normalize_options(opts)
    kept = norm.get("terms", [])
    # The leak fix: the over-byte name is DROPPED from the request the bin sees.
    assert over not in kept, "an over-BYTE term must not be sent to the bin"
    assert "Massimo Greco" in kept and under in kept
    # de-dup is order-preserving; blank dropped.
    assert kept == ["Massimo Greco", under], kept

    # The drop is REPORTED (never silent) — count + the offending original, for the UI to esc().
    rep = rm.term_drop_report(opts)
    assert rep["count"] == 1, rep
    assert rep["terms"] == [over], rep

    # No terms -> empty report (byte-identical to the historical no-warning behavior).
    assert rm.term_drop_report({}) == {"count": 0, "terms": []}
    assert rm.term_drop_report(None) == {"count": 0, "terms": []}
    assert rm.term_drop_report({"terms": ["fine"]}) == {"count": 0, "terms": []}
    # A blank/whitespace term carries no redaction intent -> NOT reported as a drop.
    assert rm.term_drop_report({"terms": ["   ", ""]}) == {"count": 0, "terms": []}


def test_redaction_term_cap_node_harness():
    """Behavioral proof for the BROWSER side of Finding #1: drive the REAL redaction.js
    byteLen() / parseTerms() / renderTermDrops() under a minimal DOM shim and prove the
    browser caps user TERMS in UTF-8 BYTES (matching the bridge + bin), drops an over-byte
    term that would pass a UTF-16 .length cap, and SURFACES a server `terms_dropped` report
    (esc()'d — no markup injection; cleared on reset) rather than silently un-redacting.

    Runs the committed node harness tests/redaction_term_cap.test.js. SKIPS (does not fail)
    if `node` is unavailable on the runner. Deterministic + air-gapped (no network)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_term_cap.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — the bridge test covers the cap server-side")
        return
    proc = subprocess.run(
        [node, str(harness), str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        "redaction term byte-cap harness failed:\n" + proc.stdout + "\n" + proc.stderr
    )
    assert "ALL PASS" in proc.stdout, proc.stdout


def test_redaction_sample_route_token_and_pdf():
    """GET /api/redaction/sample is token-guarded and returns a valid PDF (magic bytes
    %PDF) of CLEARLY-FAKE identifiers — the "Try a sample document" backend. It synthesizes
    the PDF in memory (no committed binary) and returns it base64 in the SAME shape the
    upload path consumes (filename + data_b64). FAKE-DATA-ONLY: nothing real, no network."""
    import base64 as _b64

    state = AppState()
    client = TestClient(create_app(state))

    # Token-guarded: no token -> 403.
    r0 = client.get("/api/redaction/sample")
    assert r0.status_code == 403, r0.text

    # With the session token -> 200 + a valid PDF.
    client.headers.update({"X-DRR-Token": state.token})
    r = client.get("/api/redaction/sample")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("filename"), "sample must carry a filename for the upload path"
    raw = _b64.b64decode(j["data_b64"], validate=True)
    assert raw[:4] == b"%PDF", "the sample must be a real PDF (magic bytes %PDF)"

    # The synthesized text carries the FAKE identifiers (so the demo shows detection) and
    # uses the documented test NRIC — confirm via the same fitz path the engine reads.
    import fitz  # pymupdf — a hard dep
    doc = fitz.open(stream=raw, filetype="pdf")
    try:
        text = "".join(doc[i].get_text() for i in range(doc.page_count))
    finally:
        doc.close()
    assert "Jane Tan" in text and "jane.tan@example.com" in text
    assert "S1234567D" in text, "the sample uses the documented FAKE test NRIC"
    # Nothing that looks like real matter data should be present (sanity: it is a fixed,
    # fabricated set — no need for a real corpus).
    assert "example.com" in text or "example.org" in text


def test_redaction_sample_button_is_wired():
    """The "Try it with a sample document" button + its handler are wired into the served
    redaction page, and the handler feeds the sample through the SAME upload->scan path as a
    user file (registerUpload) so provenance/gates behave identically. Structural guard."""
    c = _client()
    page = c.get("/redaction").text

    # The button + its plain label ship in the document stage.
    assert 'id="sampleBtn"' in page
    assert "Try it with a sample document" in page

    # The handler exists, fetches the sample route, and routes it through registerUpload
    # (the SAME path a user upload takes — so it sets provenance + resets/locks correctly).
    assert "function loadSample(" in page
    assert "/api/redaction/sample" in page
    assert "registerUpload(file)" in page  # treated exactly like a normal upload

    # The button is actually bound to the handler.
    assert "$('sampleBtn').addEventListener('click', loadSample)" in page

    # Still air-gapped after the new JS/CSS/HTML is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_non_pdf_upload_routes_through_extraction():
    """Round-2 [HIGH] #8: a non-PDF upload (.docx/.eml/.msg/.csv/.txt) must be EXTRACTED to
    text on Scan. Previously registerUpload cleared the textarea and scanUpload -> doScan
    scanned the empty box, so the documented upload->extract->scan path was unreachable
    (doTextUpload was dead code). The wiring: registerUpload holds a non-PDF file in
    pendingTextFile, and scanUpload routes a pending file through doTextUpload. Structural."""
    c = _client()
    page = c.get("/redaction").text
    # The non-PDF branch retains the file for extraction instead of discarding it.
    assert "pendingTextFile = file" in page, "a non-PDF upload must be held for extraction"
    # Scan routes a pending upload through the extract path (/api/redaction/scan-file).
    assert "return doTextUpload(f)" in page, "scanUpload must extract a pending non-PDF upload"
    assert "doTextUpload(file)" in page or "function doTextUpload" in page
    # The extract path is what posts to scan-file (server already validated separately).
    assert "/api/redaction/scan-file" in page
    # pendingTextFile is reset on a new document so it can't leak across uploads.
    assert "pendingTextFile = null" in page
    # The Continue/Scan GATE must treat a held non-PDF upload as a loaded document — else the
    # buttons stay disabled and the whole extract path is unreachable (an earlier cut of this
    # fix regressed exactly here; an independent review caught it).
    assert "!!pendingTextFile" in page, "the scan/continue gate must count a held upload as a doc"
    # Air-gap intact.
    assert "http://" not in page and "https://" not in page


def test_privilege_flag_passages():
    """The deterministic passage flagger (app/privilege.flag_passages):
      * the motivating bio paragraph -> ONE re_identification HIGH flag with a counts-based
        reason (it must flag even though the NAME is already removed — contextual
        re-identification a per-identifier scan cannot solve);
      * a privilege+confidential paragraph -> privilege AND confidentiality flags carrying
        the matched terms;
      * a benign paragraph -> NO flag;
      * empty / whitespace -> [].
    Pure Python — runs without the redact-cli bin."""
    from app import privilege

    # (a) the bio: one re_identification high flag, counts-based reason, name-free trigger.
    bio = privilege.flag_passages(_BIO_FIXTURE)
    reid = [p for p in bio if p.category == "re_identification"]
    assert len(reid) == 1, f"expected one re_identification flag, got {[p.category for p in bio]}"
    p = reid[0]
    assert p.severity == "high"
    assert p.reason.startswith("Possible re-identification:")
    # The reason is built from COUNTS (years / role terms / locations / organisations).
    assert "year" in p.reason and "location" in p.reason and "role term" in p.reason
    # BYTE offsets are sane and char-boundary safe (cover the paragraph).
    assert p.start == 0 and p.end == len(_BIO_FIXTURE.encode("utf-8"))

    # (b) privilege + confidentiality wording -> both categories, with matched terms.
    pc = privilege.flag_passages(
        "These materials are provided without prejudice and remain privileged and confidential.")
    cats = {x.category for x in pc}
    assert "privilege" in cats and "confidentiality" in cats, cats
    priv = next(x for x in pc if x.category == "privilege")
    assert "without prejudice" in [k.lower() for k in priv.keywords]
    conf = next(x for x in pc if x.category == "confidentiality")
    assert any("confidential" in k.lower() for k in conf.keywords)

    # (c) benign prose -> nothing flagged.
    assert privilege.flag_passages("The fund invests in equities.") == []
    # A single year + a single title is NOT enough density to flag re-identification.
    assert privilege.flag_passages("He joined the company in 2007 as a Director.") == []

    # (d) empty / whitespace -> [].
    assert privilege.flag_passages("") == []
    assert privilege.flag_passages("   \n  ") == []
    assert privilege.flag_passages(None) == []


def test_redaction_scan_includes_passages():
    """The text scan endpoint surfaces the confidentiality/privilege `passages` alongside
    the identifier candidates — and does so even when the redaction ENGINE is unavailable
    (passage flagging is pure-Python, no bin needed): the 503 body still carries them."""
    c = _client()
    r = c.post("/api/redaction/scan", json={"text": _BIO_FIXTURE})
    data = r.json()
    assert "passages" in data, f"scan response must include passages (status {r.status_code})"
    reid = [p for p in data["passages"] if p["category"] == "re_identification"]
    assert len(reid) == 1 and reid[0]["severity"] == "high"
    assert reid[0]["reason"].startswith("Possible re-identification:")
    # SURFACE-ONLY: a passage is a read-and-decide highlight, never an accept/redact span —
    # it carries no checkbox-able id, only offsets/category/reason for the lawyer to read.
    assert "category" in reid[0] and "start" in reid[0] and "end" in reid[0]


def test_redaction_page_surfaces_passages():
    """The /redaction page ships the Confidentiality/Privilege section + renderer, with the
    surface-only honest caption and no auto-redaction of passages."""
    c = _client()
    page = c.get("/redaction").text
    # Section heading is the sector-agnostic wording (was "privilege review" — neutralized so
    # the SHARED page reads in both Lawbat and the standalone Redactor).
    assert "Confidentiality / sensitive-content review" in page
    assert "function renderPassages(" in page
    assert 'id="passwrap"' in page and 'id="passToggle"' in page
    # Honest framing: surfaces for judgment, does not make anything "safe to send".
    assert "surface for" in page and "safe to send" in page
    # Still air-gapped after the new section/CSS/JS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_requires_token():
    """The scan/apply endpoints reject a request without the session token."""
    state = AppState()
    c = TestClient(create_app(state))  # NO token header
    assert c.post("/api/redaction/scan", json={"text": "x"}).status_code == 403
    assert c.post("/api/redaction/apply", json={"text": "x", "accept": []}).status_code == 403


def test_redaction_input_validation():
    """Bad/oversized inputs are 400s, not crashes or unbounded work."""
    c = _client()
    assert c.post("/api/redaction/scan", json={"text": 123}).status_code == 400
    assert c.post("/api/redaction/scan", json={"text": "a" * 2_000_001}).status_code == 400
    # accept must be a list of [start, end] non-negative int pairs
    assert c.post("/api/redaction/apply", json={"text": "x", "accept": "nope"}).status_code == 400
    assert c.post("/api/redaction/apply", json={"text": "x", "accept": [[1]]}).status_code == 400
    assert c.post("/api/redaction/apply", json={"text": "x", "accept": [[-1, 2]]}).status_code == 400
    assert c.post("/api/redaction/apply", json={"text": "x", "accept": [["a", "b"]]}).status_code == 400


def test_redaction_scan_apply_or_graceful():
    """With the redact-cli bin available, scan tiers candidates and apply redacts only
    the accepted span; without it (e.g. the Python-only CI job), the route degrades to a
    structured 503 the UI surfaces — never a crash."""
    from app import redactionmodel as rm
    c = _client()
    text = "Card 4111 1111 1111 1111 and a@b.co"
    r = c.post("/api/redaction/scan", json={"text": text})
    if not rm.available():
        assert r.status_code == 503 and "error" in r.json()
        return
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["schema"] == "firmos.redaction/0"
    card = next(x for x in data["candidates"] if x["recognizer"] == "credit-card")
    assert card["confidence"] == "high" and card["tier"] == "quick-confirm"
    # Apply ONLY the card span: the card is removed, the (unaccepted) email survives.
    ap = c.post("/api/redaction/apply",
                json={"text": text, "accept": [[card["start"], card["end"]]]})
    assert ap.status_code == 200, ap.text
    out = ap.json()
    assert out["applied"] == 1 and out["stale"] == 0
    assert "4111 1111 1111 1111" not in out["redacted"]
    assert "a@b.co" in out["redacted"]


def test_redaction_options_normalize_allowlist():
    """The options normalizer (shared by the bridge + the route) keeps only allowlisted
    locale/profile labels, accepts the context + LEI toggles, and drops everything else — no
    crash on garbage. This runs WITHOUT the bin (pure Python)."""
    from app import redactionmodel as rm
    o = rm.normalize_options({
        "locales": ["sg", "us", "zz", "BOGUS", 7, "sg"],     # unknown + dup + non-str
        "profiles": ["pci-dss-cardholder", "hipaa", "gdpr"],  # only PCI exists
        "context": True,
        "lei": True,
    })
    assert o["locales"] == ["sg", "us"], o
    assert o["profiles"] == ["pci-dss-cardholder"], o
    assert o["context"] is True
    assert o["lei"] is True
    # Garbage / absent -> built-ins only (empty dict), never an exception.
    assert rm.normalize_options(None) == {}
    assert rm.normalize_options({"locales": "sg", "context": "yes"}) == {}
    assert rm.normalize_options({"profiles": ["nope"]}) == {}
    # LEI is OFF by default: absent / non-True values omit the key entirely (byte-identical).
    assert "lei" not in rm.normalize_options({})
    assert "lei" not in rm.normalize_options({"lei": False})
    assert "lei" not in rm.normalize_options({"lei": "yes"})  # only literal True opts in
    assert "lei" not in rm.normalize_options({"lei": 1})


def test_redaction_flat_options_include_sg_nric_loose():
    """A direct API caller may send options FLAT (top-level) instead of nested under `options`.
    The flat-fallback key set must include `sg_nric_loose` so the aggressive SG-NRIC net is
    reachable from the flat form — otherwise scan/apply parity breaks for a flat caller (the UI
    always sends nested, so this is a symmetry/consistency fix). Pure Python (no bin)."""
    from app import redactionroutes as routes
    nested = routes._redaction_options({"options": {"locales": ["sg"], "sg_nric_loose": True}})
    flat = routes._redaction_options({"locales": ["sg"], "sg_nric_loose": True})
    assert nested == flat, (nested, flat)
    assert flat.get("sg_nric_loose") is True, flat
    # OFF by default in the flat form too (only literal True opts in — never a truthy value).
    assert "sg_nric_loose" not in routes._redaction_options({"locales": ["sg"]})
    assert "sg_nric_loose" not in routes._redaction_options({"sg_nric_loose": 1})


def test_redaction_disable_builtins_normalize_allowlist():
    """The normalizer keeps only allowlisted built-in NAMES in `disable_builtins`, lowercases,
    de-dups, and drops unknowns / non-strings — never crashes. Absent = full recall (no key).
    Pure Python (no bin)."""
    from app import redactionmodel as rm
    o = rm.normalize_options({
        "disable_builtins": ["id", "ID", "Credit-Card", "bogus", 7, "id"],  # case/dup/unknown/non-str
    })
    assert o["disable_builtins"] == ["id", "credit-card"], o
    # Absent / empty / garbage -> the key is omitted entirely (byte-identical default).
    assert "disable_builtins" not in rm.normalize_options({})
    assert "disable_builtins" not in rm.normalize_options({"disable_builtins": []})
    assert "disable_builtins" not in rm.normalize_options({"disable_builtins": ["nope"]})
    assert "disable_builtins" not in rm.normalize_options({"disable_builtins": "id"})  # str not list


def test_redaction_terms_normalize_bounds():
    """The normalizer keeps only non-empty string TERMS within the length cap, de-dups
    (order-preserving), and caps the count — never lowercases (the engine matches
    case-insensitively but redacts the original bytes), never crashes. Absent/empty = no key
    (byte-identical default). Pure Python (no bin)."""
    from app import redactionmodel as rm
    o = rm.normalize_options({
        # mixed: a real name, a dup, a blank, a whitespace-only, a non-str, an over-cap term.
        "terms": [
            "Massimo Greco", "Massimo Greco", "", "   ", 7, "A.B (Pte)",
            "x" * (rm.MAX_TERM_CHARS + 1),
        ],
    })
    assert o["terms"] == ["Massimo Greco", "A.B (Pte)"], o
    # Absent / empty / garbage -> the key is omitted entirely (byte-identical default).
    assert "terms" not in rm.normalize_options({})
    assert "terms" not in rm.normalize_options({"terms": []})
    assert "terms" not in rm.normalize_options({"terms": ["", "  "]})
    assert "terms" not in rm.normalize_options({"terms": "Greco"})  # str not list
    # The count cap holds (over-MAX_TERMS distinct terms truncate to the kept prefix).
    big = rm.normalize_options({"terms": [f"name{i}" for i in range(rm.MAX_TERMS + 50)]})
    assert len(big["terms"]) == rm.MAX_TERMS


def test_redaction_disable_builtins_scan_or_graceful():
    """With the redact-cli bin, a scan with {disable_builtins:[id]} drops the id candidates
    while email/etc. still fire; a bare scan flags the id. Without the bin, the route degrades
    to a structured 503 — never a crash."""
    from app import redactionmodel as rm
    c = _client()
    text = "Reach jane@acme.example, ref AB1234 here."
    base = c.post("/api/redaction/scan", json={"text": text})
    if not rm.available():
        assert base.status_code == 503 and "error" in base.json()
        return
    assert base.status_code == 200, base.text
    base_recs = [x["recognizer"] for x in base.json()["candidates"]]
    assert "id" in base_recs, base_recs       # default flags the id token
    assert "email" in base_recs, base_recs
    # Disable the id recognizer: no id candidate, email still present.
    r = c.post("/api/redaction/scan",
               json={"text": text, "options": {"disable_builtins": ["id"]}})
    assert r.status_code == 200, r.text
    recs = [x["recognizer"] for x in r.json()["candidates"]]
    assert "id" not in recs, recs
    assert "email" in recs, recs              # other built-ins unaffected (recall reduced only for id)


def test_redaction_locale_pack_scan_or_graceful():
    """With the redact-cli bin, a scan with {locales:[sg]} flags an SG NRIC AND a UEN
    (the pack-wiring deliverable) — and the UEN candidate covers the WHOLE token incl. the
    check letter. A bare scan (no options) does NOT flag them (opt-in). Without the bin,
    the route degrades to a structured 503 — never a crash."""
    from app import redactionmodel as rm
    c = _client()
    text = "Director NRIC S1234567A, entity UEN 201912345A."
    # Built-ins only: no sg:* recognizer.
    base = c.post("/api/redaction/scan", json={"text": text})
    if not rm.available():
        assert base.status_code == 503 and "error" in base.json()
        return
    assert base.status_code == 200, base.text
    base_recs = [x["recognizer"] for x in base.json()["candidates"]]
    assert not any(r.startswith("sg:") for r in base_recs), base_recs
    # Opt in to the SG pack: NRIC + UEN flagged, UEN span covers the check letter.
    r = c.post("/api/redaction/scan", json={"text": text, "options": {"locales": ["sg"]}})
    assert r.status_code == 200, r.text
    cands = r.json()["candidates"]
    recs = [x["recognizer"] for x in cands]
    assert "sg:nric" in recs, recs
    assert "sg:uen" in recs, recs
    uen = next(x for x in cands if x["recognizer"] == "sg:uen")
    assert uen["value"] == "201912345A", uen  # full token incl. check letter
    # Apply the UEN span with the SAME options: no fragment (incl. the check letter) survives.
    ap = c.post("/api/redaction/apply",
                json={"text": text, "accept": [[uen["start"], uen["end"]]],
                      "options": {"locales": ["sg"]}})
    assert ap.status_code == 200, ap.text
    out = ap.json()
    assert out["applied"] == 1 and out["stale"] == 0
    # The UEN (and its check letter) is gone; the unaccepted NRIC survives untouched.
    assert "201912345" not in out["redacted"], out["redacted"]
    assert "201912345A" not in out["redacted"], out["redacted"]  # no orphaned check letter
    assert "UEN [REDACTED]" in out["redacted"], out["redacted"]  # whole UEN token removed
    assert "S1234567A" in out["redacted"], out["redacted"]       # unaccepted NRIC kept


def test_redaction_scan_file_validation():
    """The file-scan endpoint requires a token, a filename, and bounded data."""
    import base64
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/redaction/scan-file",
                         json={"filename": "x.txt", "data_b64": "eA=="}).status_code == 403
    c = _client()
    assert c.post("/api/redaction/scan-file", json={"data_b64": "eA=="}).status_code == 400
    assert c.post("/api/redaction/scan-file", json={"filename": "x.txt"}).status_code == 400
    # 11M raw bytes -> ~14.67M base64 chars, over _REDACT_FILE_B64_MAX (the route caps
    # the ENCODED length, which is what arrives in the request body).
    big = base64.b64encode(b"a" * 11_000_000).decode()
    assert c.post("/api/redaction/scan-file",
                  json={"filename": "x.txt", "data_b64": big}).status_code == 400


def test_redaction_scan_file_or_graceful():
    """With the bin, uploading a .eml extracts headers+body and scans it (the recipient
    address in the header and the card in the body are both found); without the bin, the
    route degrades to a structured 503."""
    import base64
    from app import redactionmodel as rm
    c = _client()
    eml = (b"From: Alice <alice@example.com>\r\nTo: Bob <bob@firm.example>\r\n"
           b"Subject: Pay\r\n\r\nWire via card 4111 1111 1111 1111 today.\r\n")
    data_b64 = base64.b64encode(eml).decode()
    r = c.post("/api/redaction/scan-file", json={"filename": "m.eml", "data_b64": data_b64})
    if not rm.available():
        assert r.status_code == 503 and "error" in r.json()
        return
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["format"] == "eml"
    assert "bob@firm.example" in data["text"], "headers composed into scannable text"
    recs = {x["recognizer"] for x in data["candidates"]}
    assert "credit-card" in recs and "email" in recs, recs
    # apply works on the returned extracted text (same paste path), redacting the card.
    card = next(x for x in data["candidates"] if x["recognizer"] == "credit-card")
    ap = c.post("/api/redaction/apply",
                json={"text": data["text"], "accept": [[card["start"], card["end"]]]})
    assert ap.status_code == 200 and "4111 1111 1111 1111" not in ap.json()["redacted"]


def test_redaction_scan_file_oversize_extracted_text():
    """A file that EXTRACTS to more than the text cap is rejected at scan-file (400),
    consistent with the apply cap — not a confusing later apply failure."""
    import base64
    from app import redactionmodel as rm
    if not rm.available():
        return
    c = _client()
    # Plain-text fallback: 2M+1 'a' -> ~2.67M base64 chars (under the file cap) -> the
    # extracted text exceeds _REDACT_TEXT_MAX -> 400.
    b64 = base64.b64encode(b"a" * 2_000_001).decode()
    r = c.post("/api/redaction/scan-file", json={"filename": "big.txt", "data_b64": b64})
    assert r.status_code == 400, r.text


def test_redaction_pdf_validation():
    """The PDF endpoints require a token, file data, and bounded size."""
    import base64
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/redaction/pdf-scan", json={"data_b64": "eA=="}).status_code == 403
    assert c_noauth.post("/api/redaction/pdf-apply", json={"data_b64": "eA=="}).status_code == 403
    c = _client()
    assert c.post("/api/redaction/pdf-scan", json={}).status_code == 400
    big = base64.b64encode(b"a" * 11_000_000).decode()
    assert c.post("/api/redaction/pdf-scan", json={"data_b64": big}).status_code == 400



def test_redaction_pdf_scan_apply_or_graceful():
    """With the bin, format-preserving PDF redaction scans the fixture and writes a VALID
    redacted PDF to the exports dir; without the bin, the route degrades to a 503."""
    import base64
    from app import redactionmodel as rm
    from app.paths import exports_dir
    c = _client()
    pdf = (Path(FIXTURES) / "disclosure.pdf").read_bytes()
    data_b64 = base64.b64encode(pdf).decode()
    s = c.post("/api/redaction/pdf-scan", json={"data_b64": data_b64})
    if not rm.available():
        assert s.status_code == 503 and "error" in _prepared_result(s.json())
        return
    assert s.status_code == 200, s.text
    sd = _prepared_result(s.json())
    assert sd["op"] == "pdf_scan"
    assert sd["low_text"] is False, "a real text PDF is not flagged low_text"
    # apply -> a redacted PDF is written under exports/ and is a valid PDF.
    a = c.post("/api/redaction/pdf-apply", json={"filename": "disclosure.pdf", "data_b64": data_b64})
    assert a.status_code == 200, a.text
    ad = _prepared_result(a.json())
    assert ad["ok"] is True and ad["filename"].endswith(".redacted.pdf")
    out = _prepared_root(ad) / ad["filename"]
    assert out.is_file() and out.read_bytes()[:5] == b"%PDF-"



def test_redaction_staged_ia_is_wired():
    """The staged reviewer ships into the served page: the 5-stage IA + the gating stepper,
    the text preview + live-redaction renderer, the sensitive-passage ACK gate, and the
    export checklist + replacement-style control + local-only legend key — all inlined and
    still air-gapped. (We can't drive the DOM here, so this guards the LOAD-BEARING wiring
    structurally — the real flow is exercised end-to-end by the route tests below.)"""
    c = _client()
    page = c.get("/redaction").text
    # The persistent stepper + the five stages (Document -> Detect -> Review -> Export ->
    # Report). The former standalone "Sensitive passages" stage folded INTO Review.
    assert 'id="stepperOl"' in page
    for stage in ("stage-document", "stage-detection", "stage-review", "stage-export",
                  "stage-report"):
        assert f'id="{stage}"' in page, f"missing stage section {stage}"
    # The folded sensitive-passages block + its ack gate live inside Review now.
    assert 'id="reviewSensitive"' in page and 'id="passwrap"' in page
    # The gating router + the two real gates (careful-review completeness + passage ack).
    assert "function goStage(" in page and "function canEnter(" in page
    assert "function reviewComplete(" in page and "function passagesAllAcked(" in page
    assert "function updateExportGate(" in page
    # The text preview + live in-place redaction preview.
    assert "function buildTextPreview(" in page and "redacted-preview" in page
    assert 'id="textCanvas"' in page and 'id="pvPdfNote"' in page
    # PDF keeps the list-only honest note as the FALLBACK; Phase 2 adds the on-page
    # visual preview on top (loaded into #pdfPreview, with a graceful list fallback).
    assert "PDF review is done from the findings list" in page
    assert 'id="pdfPreview"' in page and "function loadPdfPreview(" in page
    # Add-a-redaction wired to the terms feature.
    assert "function hideEverywhere(" in page and 'id="termsBox"' in page
    # Export: replacement-style control + the local-only re-identification key warning.
    assert 'name="replstyle"' in page and "replacement_style" in page
    assert "function renderLegend(" in page
    assert "Never paste it into an AI" in page
    # The export apply uses the ACCEPTED-spans source of truth (member boxes), per tier.
    assert "#review input.memberbox:checked" in page
    # Still air-gapped after the staged JS/CSS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_apply_replacement_style_normalizer():
    """The replacement-style normalizer (shared by the bridge + the route) keeps only
    {redacted, labels} and degrades anything else to the safe 'redacted' default — never an
    error. Pure Python (no bin needed)."""
    from app import redactionmodel as rm
    assert rm.normalize_replacement_style("redacted") == "redacted"
    assert rm.normalize_replacement_style("labels") == "labels"
    # Garbage / unknown / wrong type -> the safe default.
    assert rm.normalize_replacement_style("LABELS") == "redacted"
    assert rm.normalize_replacement_style("plain") == "redacted"
    assert rm.normalize_replacement_style(None) == "redacted"
    assert rm.normalize_replacement_style(7) == "redacted"


def test_redaction_apply_labels_or_graceful():
    """With the bin, an apply with replacement_style='labels' returns AI-safe pseudonymized
    text + a local re-identification LEGEND (label -> real value). Without the bin the route
    degrades to a structured 503 — never a crash. The legend carries cleartext for LOCAL
    review only; it is in the response body (never logged/egressed by the route)."""
    from app import redactionmodel as rm
    c = _client()
    text = "Email a@b.co and again a@b.co"
    s = c.post("/api/redaction/scan", json={"text": text})
    if not rm.available():
        # The apply route must also 503 gracefully (no crash) without the engine.
        ap = c.post("/api/redaction/apply",
                    json={"text": text, "accept": [[6, 12]], "replacement_style": "labels"})
        assert ap.status_code == 503 and "error" in ap.json()
        return
    sd = s.json()
    em = next(x for x in sd["candidates"] if x["recognizer"] == "email")
    # Accept the email span(s) and ask for labels.
    spans = [[x["start"], x["end"]] for x in sd["candidates"] if x["recognizer"] == "email"]
    ap = c.post("/api/redaction/apply",
                json={"text": text, "accept": spans, "replacement_style": "labels"})
    assert ap.status_code == 200, ap.text
    out = ap.json()
    assert "a@b.co" not in out["redacted"], "the email must be removed"
    assert "legend" in out and out["legend"], "labels apply must carry a legend"
    # The legend maps a label back to the cleartext value the lawyer keeps locally.
    assert any(e.get("value") == "a@b.co" for e in out["legend"])
    assert em  # (touch em so the lint sees the assignment used)


# ---------------------------------------------------------------- text-export formats --
def test_textexport_normalize_format():
    """normalize_format keeps only the allowlisted formats, lowercases, and degrades anything
    else to the safe 'txt' default — never raises. suffix_for maps each. Pure Python."""
    from app import textexport as te
    assert te.normalize_format("txt") == "txt"
    assert te.normalize_format("MD") == "md"
    assert te.normalize_format("Html") == "html"
    assert te.normalize_format("json") == "json"
    assert te.normalize_format("docx") == "txt"     # unknown -> safe default
    assert te.normalize_format(None) == "txt"
    assert te.normalize_format(7) == "txt"
    assert te.suffix_for("md") == ".md"
    assert te.suffix_for("html") == ".html"
    assert te.suffix_for("bogus") == ".txt"


def test_textexport_formatters_escape_and_structure():
    """The pure formatters render the REDACTED text into each format. .html is escaped +
    self-contained (no http(s):// — air-gap), .json is a structured doc, .md fences the body.
    The redacted text passed in here is already free of original values (the apply output)."""
    from app import textexport as te
    redacted = "Dear [A], your case is open. Contact [email 1]. <b>note</b> & a `tick`."
    # --- HTML: escaped + air-gapped + self-contained ---
    h = te.format_html(redacted, labeled=True)
    assert "<!DOCTYPE html>" in h
    assert "http://" not in h and "https://" not in h, "html export must be air-gapped"
    # The angle brackets / ampersand from the body are escaped, not live markup.
    assert "&lt;b&gt;note&lt;/b&gt;" in h
    assert "<b>note</b>" not in h, "raw markup from the body must be escaped"
    assert "&amp;" in h
    # --- JSON: structured, no original values, machine-readable affirmation ---
    j = te.format_json(redacted, fmt_label="labels", counts={"applied": 2, "stale": 0})
    import json as _j
    doc = _j.loads(j)
    assert doc["schema"] == "lawbat.redacted-text/0"
    assert doc["format"] == "labels"
    assert doc["redacted_text"] == redacted
    assert doc["contains_original_values"] is False
    assert doc["counts"]["applied"] == 2
    # --- Markdown: heading + fenced body that survives backticks in the text ---
    m = te.format_md("text with ``` triple backtick", labeled=False)
    assert m.startswith("# Redacted document")
    # The fence widened past the body's longest backtick run so the body can't break out.
    assert "````" in m


def test_textexport_outputs_carry_no_original_cleartext():
    """SECURITY PROPERTY: the redacted/labeled DOCUMENT outputs (.txt/.md/.html/.json) NEVER
    contain an original cleartext value, even when a legend (which holds the originals) is
    supplied. Only the SEPARATE key file may contain them. This is the core invariant."""
    from app import textexport as te
    # The legend maps labels -> ORIGINAL cleartext values. These must NOT leak into any
    # document output (the JSON keeps label+count only, never the value).
    legend = [
        {"label": "[A]", "value": "Jefferson Tan", "count": 3},
        {"label": "[email 1]", "value": "jefferson@acme.example", "count": 1},
    ]
    redacted = "Dear [A], reach me at [email 1]."
    secrets = ("Jefferson Tan", "jefferson@acme.example")
    for fmt in ("txt", "md", "html", "json"):
        out = te.build_redacted_document(
            redacted, fmt, labeled=True, applied=4, stale=0, legend=legend)
        for s in secrets:
            assert s not in out, f"original value {s!r} leaked into the {fmt} document"
        # The label tokens themselves DO appear (they are not cleartext PII).
        assert "[A]" in out
    # The JSON document carries per-label counts (label + count) but NO value.
    import json as _j
    jdoc = _j.loads(te.build_redacted_document(
        redacted, "json", labeled=True, applied=4, stale=0, legend=legend))
    labels = jdoc["counts"]["labels"]
    assert {"label": "[A]", "count": 3} in labels
    assert all("value" not in row for row in labels), "JSON counts must not carry values"


def test_textexport_key_is_separate_and_marked():
    """The KEY-vs-output separation is the security property. The key file is a SEPARATE
    artifact that DOES carry the original values, carries the loud keep-local banner, and is
    never the same string as any document output."""
    from app import textexport as te
    legend = [{"label": "[A]", "value": "Jefferson Tan", "count": 3}]
    redacted = "Dear [A]."
    key_txt = te.build_key_txt(legend)
    key_json = te.build_key_json(legend)
    # The key DOES contain the original value (that is its whole purpose).
    assert "Jefferson Tan" in key_txt and "Jefferson Tan" in key_json
    assert "[A]" in key_txt
    # The keep-local banner is present + loud in BOTH key formats.
    assert "RE-IDENTIFICATION KEY" in key_txt
    assert "Do NOT send it" in key_txt
    import json as _j
    kj = _j.loads(key_json)
    assert kj["schema"] == "lawbat.reidentification-key/0"
    assert kj["contains_original_values"] is True
    assert "RE-IDENTIFICATION KEY" in kj["WARNING"]
    assert kj["key"][0]["value"] == "Jefferson Tan"
    # SEPARATION: the document output and the key are DISTINCT strings, and the document
    # does NOT contain the value nor the key banner.
    for fmt in ("txt", "md", "html", "json"):
        doc = te.build_redacted_document(redacted, fmt, labeled=True, legend=legend)
        assert doc != key_txt and doc != key_json
        assert "Jefferson Tan" not in doc
        assert "RE-IDENTIFICATION KEY" not in doc, "the key banner must not be in the document"


def test_redaction_text_export_route_writes_and_never_overwrites():
    """The /api/redaction/text-export route saves an already-redacted text to the EXPORTS dir
    (never the source tree) without overwriting; for labels it writes a SEPARATE key file with
    the keep-local banner. Token-guarded. (Pure Python — needs no redact-cli bin: the text is
    already redacted by the time it reaches this route.)"""
    from app.paths import exports_dir
    # Token guard.
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/redaction/text-export",
                         json={"redacted_text": "x", "format": "txt"}).status_code == 403
    c = _client()
    # --- plain text export: written to exports, revealed (reveal is a no-op in tests) ---
    r = c.post("/api/redaction/text-export",
               json={"redacted_text": "Dear [REDACTED].", "format": "txt",
                     "filename": "letter.txt"})
    assert r.status_code == 200, r.text
    d = _prepared_result(r.json())
    assert d["ok"] is True and d["filename"].endswith(".redacted.txt")
    assert d["key_filename"] is None, "no key file in non-labels mode"
    out1 = _prepared_root(d) / d["filename"]
    assert out1.is_file() and "Dear [REDACTED]." in out1.read_text(encoding="utf-8")
    # --- a SECOND save of the same base never overwrites (gets a ' (1)' suffix) ---
    r2 = c.post("/api/redaction/text-export",
                json={"redacted_text": "Dear [REDACTED].", "format": "txt",
                      "filename": "letter.txt"})
    assert r2.status_code == 200
    assert _prepared_root(_prepared_result(r2.json())) != _prepared_root(d), "separate preparations must never overwrite"
    assert (_prepared_root(_prepared_result(r2.json())) / _prepared_result(r2.json())["filename"]).is_file()
    # --- labels mode: the labeled doc + a SEPARATE key file (cleartext + banner) ---
    legend = [{"label": "[A]", "value": "Jefferson Tan", "count": 2}]
    r3 = c.post("/api/redaction/text-export",
                json={"redacted_text": "Dear [A], hello [A].", "format": "md",
                      "labeled": True, "legend": legend, "applied": 2, "filename": "memo.docx"})
    assert r3.status_code == 200, r3.text
    d3 = _prepared_result(r3.json())
    assert d3["filename"].endswith(".redacted.md")
    assert d3["key_filename"] and d3["key_filename"].endswith(".key.txt")
    doc_path = _prepared_root(d3) / d3["filename"]
    key_path = _prepared_root(d3) / d3["key_filename"]
    assert doc_path.is_file() and key_path.is_file()
    # SEPARATION proven on disk: the labeled DOCUMENT has no original value; the KEY does,
    # plus the keep-local banner. They are two distinct files.
    doc_text = doc_path.read_text(encoding="utf-8")
    key_text = key_path.read_text(encoding="utf-8")
    assert "Jefferson Tan" not in doc_text, "document file must not contain the original name"
    assert "Jefferson Tan" in key_text, "key file must contain the original name"
    assert "RE-IDENTIFICATION KEY" in key_text and "Do NOT send it" in key_text
    assert doc_path != key_path
    # Both files live under the exports dir (never the source tree).
    assert _prepared_root(d3) in doc_path.parents and _prepared_root(d3) in key_path.parents



def test_redaction_text_export_validation():
    """The text-export route validates the redacted_text type + size and degrades an unknown
    format to a safe .txt rather than erroring."""
    c = _client()
    assert c.post("/api/redaction/text-export",
                  json={"redacted_text": 123}).status_code == 400
    big = "x" * 2_100_000
    assert c.post("/api/redaction/text-export",
                  json={"redacted_text": big}).status_code == 400
    # An unknown format does not error — it writes a .txt. (No filename hint -> the default
    # stem is "redacted", kept SINGLE: never "redacted.redacted.txt"; a suite-order collision
    # may append " (n)" — the never-overwrite invariant.)
    r = c.post("/api/redaction/text-export",
               json={"redacted_text": "ok", "format": "exe"})
    assert r.status_code == 200, r.text
    import re as _re
    assert _re.fullmatch(r"redacted( \(\d+\))?\.txt", _prepared_result(r.json())["filename"]), _prepared_result(r.json())["filename"]



def test_redaction_text_save_seam_is_wired():
    """The text-path file-export UI ships into the served page: the format picker, the AI-safe
    key warning, the save handler + the route, all inlined + still air-gapped."""
    c = _client()
    page = c.get("/redaction").text
    assert 'id="textSaveSeam"' in page and 'name="textfmt"' in page
    assert "function doTextSave(" in page and "/api/redaction/text-export" in page
    # plain-language format labels (no jargon-only dump)
    assert "Plain text" in page and "Markdown" in page and "Web page" in page
    # the key-warning copy (the key holds real names; keep it local)
    assert 'id="keyWarn"' in page
    assert "never send it with the redacted document" in page
    # still air-gapped after the new JS/CSS/HTML is inlined
    assert "http://" not in page and "https://" not in page



def test_pdf_preview_pure_helpers():
    """The PURE positioning helpers (no PyMuPDF / no Tesseract): finding-page selection,
    per-page candidate filtering, rect->fraction conversion (clamped/flip-safe), and the
    OCR-word value->box matcher. These run in CI without any PDF/OCR library."""
    from app import pdfpreview as pp
    from app import ocr

    # finding_pages: 1-based -> 0-based, deduped + sorted, garbage skipped.
    cands = [
        {"id": 0, "page": 2, "value": "a@b.co", "recognizer": "email"},
        {"id": 1, "page": 1, "value": "x", "recognizer": "id"},
        {"id": 2, "page": 2, "value": "y", "recognizer": "id"},
        {"id": 3, "page": 0, "value": "z"},        # page 0 -> skipped (1-based)
        {"id": 4, "value": "no page"},             # missing page -> skipped
        {"id": 5, "page": True, "value": "bool"},  # bool is not a real page -> skipped
    ]
    assert pp.finding_pages(cands) == [0, 1], pp.finding_pages(cands)
    assert pp.finding_pages([]) == []

    # candidates_on_page: 0-based page maps back to its 1-based candidates, with orig idx.
    on_p1 = pp.candidates_on_page(cands, 1)  # 0-based 1 == 1-based page 2
    assert [i for i, _ in on_p1] == [0, 2], on_p1

    # rect_to_fraction: a 100x40 box at (50,20) on a 200x80 page -> (.25,.25,.5,.5).
    fr = pp.rect_to_fraction((50, 20, 150, 60), 200, 80)
    assert fr is not None
    assert abs(fr[0] - 0.25) < 1e-9 and abs(fr[1] - 0.25) < 1e-9
    assert abs(fr[2] - 0.5) < 1e-9 and abs(fr[3] - 0.5) < 1e-9
    # flipped rect normalizes; degenerate page / zero-area -> None.
    fr2 = pp.rect_to_fraction((150, 60, 50, 20), 200, 80)
    assert fr2 == fr, fr2
    assert pp.rect_to_fraction((0, 0, 10, 10), 0, 80) is None
    assert pp.rect_to_fraction((10, 10, 10, 20), 200, 80) is None  # zero width
    # out-of-page coords clamp to [0,1] (never a >1 fraction).
    frc = pp.rect_to_fraction((-10, -10, 400, 200), 200, 80)
    assert frc == (0.0, 0.0, 1.0, 1.0), frc

    # ocr_word_boxes_for_value: a single-token value matches one OCR word's whole box;
    # a multi-token value matches a consecutive run; case-insensitive; no-match -> [].
    W = ocr.OcrWord
    words = [W("Name", 0, 0, 40, 12), W("Massimo", 50, 0, 70, 12),
             W("Greco", 130, 0, 55, 12), W("tail", 200, 0, 30, 12)]
    one = pp.ocr_word_boxes_for_value("greco", words, 400, 100)
    assert len(one) == 1
    # box is over the "Greco" word region (x ~130..185 of 400 wide -> ~0.325..0.4625).
    assert 0.30 < one[0][0] < 0.34 and one[0][2] > 0, one
    two = pp.ocr_word_boxes_for_value("Massimo Greco", words, 400, 100)
    assert len(two) == 2, two
    assert pp.ocr_word_boxes_for_value("Nobody Here", words, 400, 100) == []
    assert pp.ocr_word_boxes_for_value("", words, 400, 100) == []


def test_pdf_preview_build_locates_value_box():
    """End-to-end (with PyMuPDF): build_preview renders ONLY the finding-page and locates a
    born-digital value via search_for -> a fraction box on the right page. The PNG is an
    inline data: URI (air-gap-safe). Graceful when there is nothing to preview."""
    import fitz
    from app import pdfpreview as pp

    # A 2-page text PDF; the identifier sits on page 2 only.
    doc = fitz.open()
    doc.new_page(width=300, height=400)            # page 1: no finding
    p2 = doc.new_page(width=300, height=400)
    p2.insert_text((72, 200), "Contact zenith@acme.example today", fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()

    cands = [{"id": 0, "page": 2, "value": "zenith@acme.example", "recognizer": "email",
              "tier": "quick-confirm"}]
    out = pp.build_preview(pdf_bytes, cands)
    assert out["preview"] is True, out
    # Only the finding-page (0-based index 1) is rendered (page-virtualization).
    assert len(out["pages"]) == 1 and out["pages"][0]["index"] == 1, out["pages"]
    page = out["pages"][0]
    assert page["png"].startswith("data:image/png;base64,"), "inline data URI (air-gap)"
    assert page["width"] > 0 and page["height"] > 0
    boxes = page["boxes"]
    assert len(boxes) >= 1
    b = boxes[0]
    assert b["located"] is True and b["recognizer"] == "email" and b["value_ref"] == 0
    # The box is a real fraction within the page, not the whole page.
    assert 0 <= b["x"] <= 1 and 0 <= b["y"] <= 1 and 0 < b["w"] < 1 and 0 < b["h"] < 1, b

    # No findings -> a graceful preview:false (the UI keeps the flat list).
    none = pp.build_preview(pdf_bytes, [])
    assert none["preview"] is False and "reason" in none

    # A bad PDF -> graceful preview:false, never a crash.
    bad = pp.build_preview(b"not a pdf", cands)
    assert bad["preview"] is False and "reason" in bad


def test_pdf_preview_unmapped_font_ocr_fallback_and_unlocated():
    """On an unmapped-font page, a value that search_for can't find is retried via OCR
    (injected ocr_fn) -> a located box; a value neither text-search nor OCR finds returns a
    box-LESS honest marker (located:false), never silently dropped."""
    import fitz
    from app import pdfpreview as pp
    from app import ocr

    # A born-digital page whose text is "Alpha Beta"; we pretend it's an unmapped-font page
    # and search for values NOT in the text layer so search_for misses, forcing the OCR path.
    doc = fitz.open()
    page = doc.new_page(width=300, height=400)
    page.insert_text((72, 200), "Alpha Beta", fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()

    # Injected OCR: returns a word box for "Watkins" (so it can be located), but NOT
    # for "Ghostname" (so that one stays unlocated).
    def fake_ocr(path):
        from PIL import Image
        im = Image.open(path)
        w, h = im.size
        # place a plausible word box in the page interior
        return [ocr.OcrWord("Watkins", int(w * 0.2), int(h * 0.45),
                            int(w * 0.2), int(h * 0.04))]

    cands = [
        {"id": 0, "page": 1, "value": "Watkins", "recognizer": "name", "tier": "review"},
        {"id": 1, "page": 1, "value": "Ghostname", "recognizer": "name", "tier": "review"},
    ]
    out = pp.build_preview(pdf_bytes, cands, unmapped_fonts=True, ocr_fn=fake_ocr)
    assert out["preview"] is True, out
    boxes = out["pages"][0]["boxes"]
    by_ref = {b["value_ref"]: b for b in boxes}
    # "Watkins" located via the OCR fallback.
    assert by_ref[0]["located"] is True and by_ref[0]["w"] is not None, by_ref[0]
    # "Ghostname" found by neither -> an honest box-less marker (NOT dropped).
    assert by_ref[1]["located"] is False and by_ref[1]["x"] is None, by_ref[1]

    # When unmapped_fonts is False, an unfound value is NOT OCR-retried -> stays unlocated.
    out2 = pp.build_preview(pdf_bytes, [cands[0]], unmapped_fonts=False, ocr_fn=fake_ocr)
    assert out2["pages"][0]["boxes"][0]["located"] is False


def test_pdf_preview_page_virtualization_caps():
    """Page-virtualization: over the finding-page cap, build_preview renders up to the cap
    and reports the overflow honestly in `note` (never silently truncates)."""
    import fitz
    from app import pdfpreview as pp

    orig_cap = pp.MAX_PREVIEW_PAGES
    pp.MAX_PREVIEW_PAGES = 2
    try:
        doc = fitz.open()
        for _ in range(4):
            pg = doc.new_page(width=200, height=200)
            pg.insert_text((40, 100), "id 12345", fontsize=12)
        pdf_bytes = doc.tobytes()
        doc.close()
        cands = [{"id": i, "page": i + 1, "value": "12345", "recognizer": "id"}
                 for i in range(4)]
        out = pp.build_preview(pdf_bytes, cands, max_pages=2)
        assert out["preview"] is True
        assert len(out["pages"]) == 2, out["pages"]
        assert out["capped"] is True and out["note"] and "more page" in out["note"], out
    finally:
        pp.MAX_PREVIEW_PAGES = orig_cap


def test_pdf_preview_cumulative_render_budget():
    """The CUMULATIVE render budget closes the soft-DoS the per-page clamps leave open: a
    pathological multi-page doc STOPS rendering once the total inline-PNG bytes (or total
    megapixels) budget is hit, reports the overflow honestly via the EXISTING capped+note
    mechanism, and stays graceful (preview:true, never raises). A realistic doc is
    UNAFFECTED (renders all finding-pages, not budget-capped)."""
    import fitz
    from app import pdfpreview as pp

    # 6 pages, every one a finding-page (so all are render-eligible up to the page cap).
    doc = fitz.open()
    for _ in range(6):
        pg = doc.new_page(width=300, height=400)
        pg.insert_text((40, 100), "id 99999", fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()
    cands = [{"id": i, "page": i + 1, "value": "99999", "recognizer": "id"}
             for i in range(6)]

    # (a) Realistic budget (the shipped constants) -> ALL 6 finding-pages render, not capped
    # (these tiny pages are nowhere near the ~150 Mpix / 8 MB ceilings).
    full = pp.build_preview(pdf_bytes, cands)
    assert full["preview"] is True, full
    assert len(full["pages"]) == 6, full["pages"]
    assert full["capped"] is False and full["note"] is None, full

    # (b) Squeeze the inline-PNG-bytes budget so it trips after the first page -> rendering
    # STOPS short, capped flips True, and the note is the honest "preview size limit".
    orig_bytes = pp.MAX_TOTAL_PREVIEW_PNG_BYTES
    pp.MAX_TOTAL_PREVIEW_PNG_BYTES = 1   # any rendered page exceeds this immediately
    try:
        cut = pp.build_preview(pdf_bytes, cands)
        assert cut["preview"] is True, cut
        assert len(cut["pages"]) < 6, cut["pages"]        # stopped short of all findings
        assert cut["capped"] is True, cut
        assert cut["note"] and "preview size limit" in cut["note"], cut["note"]
        # honest count of un-previewed finding-pages
        assert "more page" in cut["note"], cut["note"]
    finally:
        pp.MAX_TOTAL_PREVIEW_PNG_BYTES = orig_bytes

    # (c) Same via the megapixel budget (independent lever).
    orig_mp = pp.MAX_TOTAL_PREVIEW_MEGAPIXELS
    pp.MAX_TOTAL_PREVIEW_MEGAPIXELS = 0.001
    try:
        cut2 = pp.build_preview(pdf_bytes, cands)
        assert cut2["preview"] is True and cut2["capped"] is True, cut2
        assert len(cut2["pages"]) < 6, cut2["pages"]
        assert "preview size limit" in (cut2["note"] or ""), cut2["note"]
    finally:
        pp.MAX_TOTAL_PREVIEW_MEGAPIXELS = orig_mp


def test_pdf_preview_no_cleartext_in_response():
    """Confidentiality: the serialized preview response NEVER carries the cleartext matched
    value — boxes reference the candidate by `value_ref` INDEX + a `recognizer` LABEL, not
    the matter text. Locks the top confidentiality property of the preview path. Checked on
    build_preview AND through the live route."""
    import base64 as _b64
    import json as _json

    import fitz
    from app import pdfpreview as pp

    SECRET = "zenithSECRET@acme.example"
    doc = fitz.open()
    doc.new_page(width=300, height=400)            # page 1: no finding
    p2 = doc.new_page(width=300, height=400)
    p2.insert_text((50, 200), "Email " + SECRET + " for details", fontsize=11)
    pdf_bytes = doc.tobytes()
    doc.close()

    cands = [{"id": 0, "page": 2, "value": SECRET, "recognizer": "email", "tier": "review"}]
    out = pp.build_preview(pdf_bytes, cands)
    assert out["preview"] is True, out
    # The secret string is ABSENT from the FULL serialized response...
    assert SECRET not in _json.dumps(out), "cleartext value leaked into the preview payload"
    # ...and absent from the raw box dicts (value_ref is an int index; recognizer a label).
    for page in out["pages"]:
        for b in page["boxes"]:
            assert b.get("value_ref") == 0 and isinstance(b["value_ref"], int), b
            assert b.get("recognizer") == "email", b
            assert SECRET not in _json.dumps(b), b
            assert "value" not in b, "a box must not carry the cleartext value"

    # Through the live route: the response body must not contain the secret either.
    c = _client()
    b64 = _b64.b64encode(pdf_bytes).decode()
    r = c.post("/api/redaction/pdf-preview", json={"data_b64": b64, "candidates": cands})
    assert r.status_code == 200, r.text
    assert SECRET not in r.text, "cleartext value leaked through the pdf-preview route"
    assert r.json().get("preview") is True


def test_pdf_preview_raster_cleanup_on_ocr_exception():
    """The OCR-fallback temp PNG (matter content) is removed even when OCR RAISES: the
    `finally: os.remove` in `_ocr_page` holds. build_preview still returns gracefully and
    no `ldm-pdfpreview-*` temp file/dir leaks. Driven with an injected ocr_fn (no real
    Tesseract needed), mirroring the other injected-OCR preview tests."""
    import glob
    import tempfile

    import fitz
    from app import pdfpreview as pp

    doc = fitz.open()
    page = doc.new_page(width=300, height=400)
    page.insert_text((72, 200), "Alpha Beta", fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()

    raised = {"n": 0}

    def boom_ocr(path):
        # The temp PNG exists at call time (it is what we OCR); raising here exercises the
        # cleanup-on-exception path.
        assert os.path.exists(path), "the temp raster should exist when ocr_fn is called"
        raised["n"] += 1
        raise RuntimeError("OCR engine blew up")

    # An unmapped-font page + a value text-search can't find -> the OCR fallback fires.
    cands = [{"id": 0, "page": 1, "value": "Ghostname", "recognizer": "name"}]
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "ldm-pdfpreview-*")))
    out = pp.build_preview(pdf_bytes, cands, unmapped_fonts=True, ocr_fn=boom_ocr)
    # (a) graceful: the failing OCR does not crash the build; the finding becomes an honest
    # box-less marker (never dropped) and the page still renders.
    assert out["preview"] is True, out
    assert raised["n"] >= 1, "the injected ocr_fn should have been called"
    boxes = out["pages"][0]["boxes"]
    assert boxes and boxes[0]["located"] is False, boxes
    # (b) no temp raster leaked despite the exception.
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "ldm-pdfpreview-*")))
    assert after <= before, "a pdfpreview temp raster leaked after an OCR exception"


def test_pdf_preview_giant_mediabox_clamps_to_megapixel_ceiling():
    """A hostile giant-MediaBox page clamps to the per-page megapixel ceiling (the raster
    never balloons to a multi-GB allocation) — the same clamp imageredact uses."""
    import fitz
    from app import pdfpreview as pp

    # A tiny PDF byte-wise, but a 20000x20000-point page would render to billions of pixels
    # at 144 DPI without the clamp.
    doc = fitz.open()
    pg = doc.new_page(width=20000, height=20000)
    pg.insert_text((100, 100), "id 4242", fontsize=40)
    pdf_bytes = doc.tobytes()
    doc.close()

    out = pp.build_preview(pdf_bytes, [{"id": 0, "page": 1, "value": "4242", "recognizer": "id"}])
    assert out["preview"] is True, out
    page = out["pages"][0]
    mp = (page["width"] * page["height"]) / 1_000_000.0
    assert mp <= pp.MAX_PAGE_MEGAPIXELS + 0.5, mp   # clamped, not the full ~30000^2 px


def test_pdf_preview_route_token_and_graceful():
    """The pdf-preview route requires the token, validates file data, and degrades
    gracefully (preview:false, HTTP 200) when PyMuPDF or candidates are absent — never a
    500/crash. The route never re-scans; it positions the candidates it is given."""
    import base64
    state = AppState()
    c_noauth = TestClient(create_app(state))
    # token required
    assert c_noauth.post("/api/redaction/pdf-preview",
                         json={"data_b64": "eA=="}).status_code == 403
    c = _client()
    # missing file data -> 400
    assert c.post("/api/redaction/pdf-preview", json={}).status_code == 400
    # oversize -> 400
    big = base64.b64encode(b"a" * 11_000_000).decode()
    assert c.post("/api/redaction/pdf-preview", json={"data_b64": big}).status_code == 400
    # no candidates -> a graceful preview:false (200), the UI keeps the flat list.
    tiny = base64.b64encode(b"%PDF-1.4\n%%EOF\n").decode()
    r = c.post("/api/redaction/pdf-preview", json={"data_b64": tiny, "candidates": []})
    assert r.status_code == 200, r.text
    assert r.json().get("preview") is False
    # garbage bytes WITH a candidate -> still graceful preview:false, never a 500.
    r2 = c.post("/api/redaction/pdf-preview",
                json={"data_b64": base64.b64encode(b"not a pdf").decode(),
                      "candidates": [{"page": 1, "value": "x"}]})
    assert r2.status_code == 200 and r2.json().get("preview") is False, r2.text


def test_pdf_preview_ui_is_wired():
    """The on-page PDF visual preview ships into the served page: the preview container,
    the loader + renderer + box-sync functions, the cross-highlight, the honest unlocated
    marker, and the inline data-URI image source — all inlined and still air-gapped."""
    c = _client()
    page = c.get("/redaction").text
    assert 'id="pdfPreview"' in page
    assert "function loadPdfPreview(" in page and "function renderPdfPreview(" in page
    assert "function syncPreviewBox(" in page and "function onPreviewBoxClick(" in page
    assert "/api/redaction/pdf-preview" in page
    # cross-highlight + the kept (dimmed) box state + the honest unlocated marker.
    assert "pp-box" in page and "cross-flash" in page and "pp-unlocated" in page
    assert "couldn’t be pinpointed" in page
    # the image source is the inline data: URI (no external fetch — air-gap safe).
    assert "img.src = p.png" in page
    assert "http://" not in page and "https://" not in page


def test_redaction_responses_carry_engine_provenance_honesty_fields():
    """TODO §8 honest audit claims: the SHIPPED redaction path is the standalone
    `redact-cli` engine — NOT the audited Rust `Core` (no core mediation, no durable HMAC
    audit trail). The API must say so on the wire: every scan/apply-class redaction
    response carries `core_mediated: false` + `durable_audit: false`. Asserted on the
    text scan AND the pdf-scan; holds on BOTH the 200 (bin present) and the graceful 503
    (bin absent) bodies, so no deployment shape can overclaim."""
    import base64
    c = _client()

    # Text scan — fields present and False regardless of engine availability.
    r = c.post("/api/redaction/scan", json={"text": "Card 4111 1111 1111 1111 and a@b.co"})
    assert r.status_code in (200, 503), r.text
    data = _prepared_result(r.json())
    assert data.get("core_mediated") is False, f"scan must carry core_mediated:false — got {data.get('core_mediated')!r}"
    assert data.get("durable_audit") is False, f"scan must carry durable_audit:false — got {data.get('durable_audit')!r}"

    # PDF scan — same honesty fields on the format-preserving path.
    pdf = (Path(FIXTURES) / "disclosure.pdf").read_bytes()
    s = c.post("/api/redaction/pdf-scan", json={"data_b64": base64.b64encode(pdf).decode()})
    assert s.status_code in (200, 503), s.text
    sd = _prepared_result(s.json())
    assert sd.get("core_mediated") is False, f"pdf-scan must carry core_mediated:false — got {sd.get('core_mediated')!r}"
    assert sd.get("durable_audit") is False, f"pdf-scan must carry durable_audit:false — got {sd.get('durable_audit')!r}"

    # Text-export SUCCESS shape — the write/format path is pure Python (no bin) and its 200
    # body must carry the SAME honesty flags as every sibling export route (a bare dict here
    # was an honesty hole: a saved artifact with no provenance stamp).
    te = c.post("/api/redaction/text-export",
                json={"redacted_text": "Dear [REDACTED].", "format": "txt", "filename": "x.txt"})
    assert te.status_code == 200, te.text
    td = _prepared_result(te.json())
    assert td.get("core_mediated") is False, f"text-export must carry core_mediated:false — got {td.get('core_mediated')!r}"
    assert td.get("durable_audit") is False, f"text-export must carry durable_audit:false — got {td.get('durable_audit')!r}"

    # The fields are ADDITIVE honesty flags: never claimed true anywhere in the shipped app.
    from app import web as webmod
    src = Path(webmod.__file__).read_text(encoding="utf-8")
    assert '"core_mediated": True' not in src and '"durable_audit": True' not in src



# ============================================================================
# Defect 1 — the health probe must EXECUTE the bin, not just check the path.
# ============================================================================
def test_redaction_health_probe_runs_the_bin_not_just_path():
    """/api/redaction/health must report readiness from a REAL round-trip, never from
    path-existence alone. A bin that exists but cannot spawn (missing DLL) or returns
    garbage must report ok:false with a reason that distinguishes the failure — otherwise
    the page shows "✓ Tool ready" and then contradicts itself with a red "tool unavailable"
    banner on the first real scan. Deterministic + cross-platform: we stub corebridge.run
    to simulate each outcome (a located-but-broken bin) rather than depend on a shell script."""
    from app import redactionmodel as rm
    from app import corebridge

    orig_path = rm.redact_cli_path
    orig_run = corebridge.run
    try:
        # Pretend a bin IS located (path check passes) so we exercise the RUN branch.
        rm.redact_cli_path = lambda: "/nonexistent/redact-cli"

        # (1) located but cannot spawn (missing DLL / wrong arch) -> spawn-failed.
        corebridge.run = lambda *a, **k: corebridge.RunResult(started=False, exc_name="OSError")
        h = rm.health()
        assert h == {"ok": False, "reason": "spawn-failed"}, h

        # (2) runs but prints garbage -> bad-response.
        corebridge.run = lambda *a, **k: corebridge.RunResult(started=True, stdout="not json", returncode=3)
        h = rm.health()
        assert h == {"ok": False, "reason": "bad-response"}, h

        # (3) runs but returns a wrong/absent schema -> bad-response.
        corebridge.run = lambda *a, **k: corebridge.RunResult(
            started=True, stdout='{"schema":"other","candidates":[]}', returncode=0)
        assert rm.health() == {"ok": False, "reason": "bad-response"}, rm.health()

        # (4) runs but returns a schema-stamped ERROR envelope -> bad-response (not ready).
        corebridge.run = lambda *a, **k: corebridge.RunResult(
            started=True, stdout='{"schema":"firmos.redaction/0","error":"boom"}', returncode=1)
        assert rm.health() == {"ok": False, "reason": "bad-response"}, rm.health()

        # (5) runs and returns a well-formed scan contract -> ready.
        corebridge.run = lambda *a, **k: corebridge.RunResult(
            started=True, stdout='{"schema":"firmos.redaction/0","candidates":[],"summary":{}}',
            returncode=0)
        assert rm.health() == {"ok": True, "reason": "ready"}, rm.health()
    finally:
        rm.redact_cli_path = orig_path
        corebridge.run = orig_run


def test_redaction_health_endpoint_reports_broken_bin():
    """The /api/redaction/health ENDPOINT surfaces the probe result: ok + a reason field
    (backward-compatible: `ok` unchanged, `reason` added). A located-but-broken bin ->
    ok:false, reason:'spawn-failed'."""
    from app import redactionmodel as rm
    from app import corebridge

    orig_path = rm.redact_cli_path
    orig_run = corebridge.run
    try:
        rm.redact_cli_path = lambda: "/nonexistent/redact-cli"
        corebridge.run = lambda *a, **k: corebridge.RunResult(started=False, exc_name="OSError")
        c = _client()
        r = c.get("/api/redaction/health")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is False, body
        assert body["reason"] == "spawn-failed", body
    finally:
        rm.redact_cli_path = orig_path
        corebridge.run = orig_run


def test_redaction_health_probe_no_bin_is_not_found():
    """With NO redact-cli located, health reports ok:false, reason:'not-found' (distinct
    from a broken-but-present bin), and never even attempts to run anything."""
    from app import redactionmodel as rm
    from app import corebridge

    orig_path = rm.redact_cli_path
    orig_run = corebridge.run
    ran = {"called": False}
    try:
        rm.redact_cli_path = lambda: None
        corebridge.run = lambda *a, **k: (ran.update(called=True) or
                                          corebridge.RunResult(started=False, exc_name="X"))
        assert rm.health() == {"ok": False, "reason": "not-found"}, rm.health()
        assert ran["called"] is False, "health must NOT spawn anything when no bin is located"
        c = _client()
        body = c.get("/api/redaction/health").json()
        assert body["ok"] is False and body["reason"] == "not-found", body
    finally:
        rm.redact_cli_path = orig_path
        corebridge.run = orig_run


def test_redaction_health_route_requires_token():
    """/api/redaction/health is TOKEN-GUARDED (fix-on-top of e3d42f9): unlike the old
    path-exists-only check, health() now SPAWNS THE BIN on every call — an open GET would
    let any local caller repeatedly fork the redact-cli process. No token -> 403 (same
    byte-identical rejection as the other guarded redaction routes); with the session
    token -> 200. Mirrors test_redaction_sample_route_token_and_pdf's shape for /sample."""
    state = AppState()
    client = TestClient(create_app(state))

    r0 = client.get("/api/redaction/health")
    assert r0.status_code == 403, r0.text
    assert r0.content == b'{"error":"forbidden"}', r0.content

    client.headers.update({"X-DRR-Token": state.token})
    r = client.get("/api/redaction/health")
    assert r.status_code == 200, r.text
    assert "ok" in r.json()


def test_redaction_health_probe_real_broken_bin_posix():
    """End-to-end proof of the REAL spawn+classify round-trip: point LAWDATAMAN_REDACT_CLI
    at a script that reads stdin, prints garbage, and exits non-zero -> the endpoint reports
    ok:false, reason:'bad-response'. POSIX-only (a shell script isn't directly spawnable on
    Windows); SKIPS there — the deterministic stub test above covers the classification on
    all platforms."""
    if os.name == "nt":
        print("  (skip) POSIX-only real-script probe; the stub test covers Windows")
        return
    import stat
    from app import redactionmodel as rm

    d = tempfile.mkdtemp(prefix="ldm-fakebin-")
    script = os.path.join(d, "redact-cli")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\ncat > /dev/null 2>&1\necho 'not json at all'\nexit 3\n")
    os.chmod(script, 0o755)
    st = os.stat(script)
    os.chmod(script, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    old = os.environ.get("LAWDATAMAN_REDACT_CLI")
    os.environ["LAWDATAMAN_REDACT_CLI"] = script
    try:
        assert rm.redact_cli_path() == script, rm.redact_cli_path()
        h = rm.health()
        assert h == {"ok": False, "reason": "bad-response"}, h
        c = _client()
        body = c.get("/api/redaction/health").json()
        assert body["ok"] is False and body["reason"] == "bad-response", body
    finally:
        if old is None:
            os.environ.pop("LAWDATAMAN_REDACT_CLI", None)
        else:
            os.environ["LAWDATAMAN_REDACT_CLI"] = old


# ============================================================================
# Defect 2 — an errored scan may never look like a clean, empty scan.
# ============================================================================
def test_redaction_scan_error_blocks_and_is_not_clean_result():
    """Structural pins on the served redaction page for the scan-error honesty fix.

    The invariant (commented in the page): an error path may never be visually
    indistinguishable from a clean empty result — over-blocking is the safe side. We pin:
      * an explicit scanFailed flag exists + is documented as the honesty invariant;
      * markScanFailed clears cands + raises the flag (gates re-lock) and is called on
        every scan/extract error branch (scan / scan-file / pdf-scan);
      * canEnter refuses the downstream stages while scanFailed is set;
      * the stepper paints an 'error' mark (not 'done') and the "0 findings"/"None flagged"
        sub-lines only render when `scanned` (which becomes false on an error);
      * the "Tool ready" chip flips to offline via setEngineChip WITHOUT clobbering the
        friendly red error banner (showEngineError stays).
    The behavioral proof is the node harness in the test below."""
    c = _client()
    page = c.get("/redaction").text

    # The honesty flag + its load-bearing invariant, commented in the page.
    assert "var scanFailed = false;" in page
    assert "from a clean, EMPTY scan" in page
    assert "Over-blocking is the safe side" in page

    # markScanFailed clears cands + raises the flag (re-locks the downstream gates).
    assert "function markScanFailed(" in page
    assert page.count("markScanFailed(") >= 4, \
        "markScanFailed must be wired into all three scan error branches (+ its definition)"
    # It flips the chip via setEngineChip (not setEngineHealth, which would clobber the banner).
    assert "function setEngineChip(" in page
    assert "if (engineOffline) setEngineChip(false);" in page

    # canEnter refuses the downstream stages while scanFailed is set (belt-and-suspenders).
    assert "if (scanFailed) return false;" in page

    # The stepper paints an explicit error mark, never 'done', on a failed scan.
    assert "(cands !== undefined) && !scanFailed" in page
    assert "detection: scanFailed ? 'error'" in page
    assert "review: scanFailed ? 'locked'" in page
    assert "'Scan failed'" in page  # the error mark text
    # And it overwrites any stale reassuring sub-line so "None flagged" can't linger.
    assert "OVERWRITE any stale" in page

    # The friendly error banner behavior is preserved (showEngineError still called on error).
    assert page.count("showEngineError(") >= 3

    # Still air-gapped after the new JS/CSS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_scan_error_node_harness():
    """Behavioral regression for Defect 2: drive the real redaction.js markScanFailed /
    canEnter / getScanState and prove an errored scan re-locks Review/Sensitive/Export,
    sets the explicit error flag, flips the chip on engine-unavailability (but NOT on a
    per-file input error), and that a later successful scan recovers cleanly.

    Runs tests/redaction_scan_error.test.js. SKIPS (does not fail) if `node` is unavailable
    on the runner — the structural test above guards the wiring everywhere; this adds the
    behavioral proof wherever node exists. Deterministic + air-gapped (no network)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_scan_error.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run(
        [node, str(harness), str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        "redaction scan-error harness failed — an errored scan is no longer blocked / "
        "distinguishable from a clean empty result:\n" + proc.stdout + "\n" + proc.stderr
    )
    assert "ALL PASS" in proc.stdout, proc.stdout


# ============================================================================
# Fix-on-top of e3d42f9 (independent review): a REJECTED fetch (transport down, aborted,
# ad-blocked, etc.) previously escaped doScan/doTextUpload/doPdfScan's unguarded
# `await post(...)` entirely — the spinner never cleared and markScanFailed() was never
# called, so an errored scan looked like a permanently-stuck "Scanning…" rather than the
# honest blocked/error state the rest of e3d42f9 built. Each of the three scan entry points
# now wraps its post() in try/catch: the catch hides the spinner, calls markScanFailed(true)
# (the engine-unreachable class — never a per-file input error), and shows the SAME
# tool-unavailable banner the offline chip uses (not the generic error copy).
# ============================================================================
def test_redaction_scan_rejection_is_caught_not_left_hanging():
    """Structural pin: every `await post(...)` scan call in the served page is wrapped in
    try/catch, and each catch hides the spinner, marks the scan failed as engine-unreachable,
    and shows the tool-unavailable banner (never leaves the spinner hanging / silently drops
    the failure as an unhandled promise rejection).

    A full BEHAVIORAL proof (driving a real rejecting fetch() through the node harness) was
    considered but is not cheaply reachable: the harness's top-level Scenarios run
    synchronously and the on-load checkEngineHealth() probe resolves engineDown via a
    microtask that only flushes once the whole script drains — reaching it would need a
    NEW test-only setter for the private `engineDown` closure var (not currently in
    __redactionInternals) plus restructuring the harness around an async IIFE, for marginal
    extra proof over this structural pin + the existing Defect-2 behavioral harness (which
    already proves markScanFailed/canEnter/chip-flip once the flag IS set). This structural
    assert is the pragmatic middle ground."""
    c = _client()
    page = c.get("/redaction").text

    # Each scan entry point's catch comments the SAME rationale (doScan's is referenced by
    # the other two, "see doScan's identical catch") — 2 cross-references pins that
    # doTextUpload and doPdfScan were both actually touched, not just doScan.
    # (redaction.pdf.js's PRE-EXISTING pdf-preview try/catch is a different, already-guarded
    # call — deliberately excluded from this count.)
    assert page.count("see doScan's identical catch") == 2, \
        "doTextUpload's and doPdfScan's catch must reference doScan's rationale"
    # Exactly 3 catch blocks call markScanFailed(true) — one per scan entry point
    # (doScan/doTextUpload/doPdfScan) — the engine-unreachable class, never a per-file
    # input error (a rejected TRANSPORT call carries no information about the document).
    assert page.count("markScanFailed(true);") == 3, \
        "each of the 3 scan entry points' catch must call markScanFailed(true)"
    # Every catch shows the SAME tool-unavailable banner the offline chip uses.
    assert page.count("showEngineOffline();") >= 3

    # The transport-failure branch (an HTTP response DID come back, but not ok, with no
    # parseable error body) also uses the tool-unavailable banner, not the generic
    # "something went wrong" copy — consistent with the chip flipping offline right below it.
    assert page.count("var transportFailure = !r.ok && !r.data.error;") == 3
    assert page.count("if (transportFailure) showEngineOffline(); else showEngineError(emsg);") == 3
    assert page.count("markScanFailed(transportFailure || friendlyError(emsg).engineOffline);") == 3

    # Still air-gapped after the new JS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_quick_group_selectors_is_wired():
    """Quick group selectors ("All" / "Default") on the detection-options groups ship in the
    served page: the jurisdiction multiselect (loc) and the recognizer types + their
    closely-related opt-ins (bi/context/LEI/PCI). No DOM seam in this suite, so guard the
    LOAD-BEARING invariants structurally — the buttons exist, are real <button> elements with
    an aria-label, and there is NO "None"/deselect-all counterpart anywhere (the deliberate
    miss-direction omission — see the code comments in redaction.core.js / redaction.html).
    The behavioral proof (All checks every box, Default restores the AS-LOADED state, neither
    triggers a scan) is the node harness below."""
    c = _client()
    page = c.get("/redaction").text

    # The four buttons ship as real, keyboard-accessible <button type="button"> elements
    # with a descriptive aria-label, one pair per group.
    for btn_id, label in (
        ("locAllBtn", "Select all jurisdictions"),
        ("locDefaultBtn", "Restore default jurisdictions"),
        ("recAllBtn", "Select all recognizers and detection opt-ins"),
        ("recDefaultBtn", "Restore default recognizer and opt-in settings"),
    ):
        needle = f'id="{btn_id}"'
        assert needle in page, f"{btn_id} missing from the served page"
        # Pull the whole <button ...>...</button> tag to check it's a real button + has the label.
        start = page.index(needle)
        tag_start = page.rfind("<button", 0, start)
        tag_end = page.index(">", start)
        tag = page[tag_start:tag_end + 1]
        assert 'type="button"' in tag, f"{btn_id} must be a real <button type=\"button\">"
        assert f'aria-label="{label}"' in tag, f"{btn_id} must carry its aria-label"

    # The JS-side implementation ships: the group registry, the captured-at-init default
    # snapshot, and the two operations.
    assert "var GROUP_BOXES" in page
    assert "function captureGroupDefault(" in page
    assert "function selectAllGroup(" in page
    assert "function restoreGroupDefault(" in page
    # captureGroupDefault runs at init, for BOTH groups — after restoreOptions() (the ordering
    # that makes "Default" reflect a returning user's saved settings, not a hardcoded guess).
    assert page.count("captureGroupDefault('loc')") + page.count('captureGroupDefault("loc")') >= 1
    assert page.count("captureGroupDefault('bi')") + page.count('captureGroupDefault("bi")') >= 1
    # The CALL SITE (the wiring in redaction.stepper.js) must come after restoreOptions()'s
    # call site, not merely after captureGroupDefault's own function DEFINITION (which is
    # declared earlier, in redaction.core.js, and would otherwise match first).
    call_site = page.index("captureGroupDefault('loc');")
    assert page.index("restoreOptions();") < call_site

    # DELIBERATE OMISSION: no "None"/deselect-all button or seam exists anywhere for these
    # two groups (a one-click empty selection is the miss direction — see the code comment).
    assert "locNoneBtn" not in page and "recNoneBtn" not in page
    assert "selectNoneGroup" not in page and "deselectAllGroup" not in page and "clearGroup" not in page

    # Still air-gapped after the new HTML/JS/CSS is inlined.
    assert "http://" not in page and "https://" not in page


def test_redaction_group_selectors_node_harness():
    """Behavioral proof for the quick group selectors: drive the REAL redaction.js
    (selectAllGroup / restoreGroupDefault / captureGroupDefault) under a minimal DOM shim and
    prove: "All" checks every box in a group (including its opt-in members, e.g. LEI/PCI, on
    the recognizer group) via the SAME shared saveOptions() handler a manual click runs;
    "Default" restores the group's state exactly as it was AT PAGE LOAD — including a
    RETURNING user's own localStorage-saved settings, never a hardcoded guess; neither
    operation ever calls the network (no scan is auto-triggered); and there is no
    "None"/deselect-all counterpart on the seam.

    Runs the committed node harness tests/redaction_group_selectors.test.js. SKIPS (does not
    fail) if `node` is unavailable on the runner — the structural test above guards the wiring
    everywhere; this adds the behavioral proof wherever node exists. Deterministic + air-gapped
    (no network)."""
    import shutil
    import subprocess

    node = shutil.which("node")
    harness = Path(__file__).resolve().parent.parent / "redaction_group_selectors.test.js"
    target = _assembled_redaction_js_path()
    if not node:
        print("  (skip) node not available — structural test covers the wiring")
        return
    proc = subprocess.run(
        [node, str(harness), str(target)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, (
        "redaction quick-group-selectors harness failed — 'All'/'Default' no longer behave "
        "as specified:\n" + proc.stdout + "\n" + proc.stderr
    )
    assert "ALL PASS" in proc.stdout, proc.stdout


def test_redaction_banner_inline_emphasis_stays_inline():
    """Regression pin: a bug had a banner's mid-sentence <b> emphasis (e.g. "Use
    <b>Add a redaction</b> for anything it missed") render on its OWN LINE with the
    following words — starting with an orphaned mdash/period/closing-quote — pushed to
    the next line. Two user-visible instances: the review-stage honest banner ("This does
    a thorough first pass.") and the sensitive-passages banner ("You must read these
    before you can export.").

    ROOT CAUSE (app/ui/base.css): `.banner .body b{display:block}` was meant to make only
    the banner HEADLINE <b> — a DIRECT CHILD of .body, immediately before its <p> — stand
    on its own line. Because the selector had no child combinator it matched every <b>
    DESCENDANT, including a <b> nested INSIDE the <p> for inline mid-sentence emphasis,
    forcing that inline span onto its own block-level line too.

    This suite has no headless browser, so it can't compute layout directly. It pins the
    fix at its true cause instead: the CSS rule must use a direct-child combinator
    (`.banner .body > b`) so only the headline is block-ified, and the over-broad
    descendant form must be gone from the assembled page. It also pins that the two named
    banners still carry their nested <b> emphasis, UNCHANGED in wording, genuinely inside
    the <p> (not hoisted out as a second headline) — so a "fix" that instead strips the
    nested <b> (changing emphasis) would fail this test too."""
    page = _client().get("/redaction").text
    # Only look at the served <body> MARKUP — not the inlined <style> block (whose CSS
    # comment on the very rule under test illustrates it with this same example phrase) and
    # not the tail <script> block (a couple of these same phrases also appear there as
    # JS-built innerHTML string literals for a different banner, e.g. the flagged-passage
    # popover) — both would be false-positive matches for a markup-nesting check.
    html_part = page[page.index("</style>"):page.index("<script>")]

    # The scoped (correct) rule ships...
    assert re.search(r"\.banner\s+\.body\s*>\s*b\s*\{\s*display:\s*block\s*\}", page), (
        "expected a direct-child '.banner .body > b{display:block}' CSS rule (or equivalent "
        "spacing) in base.css — the banner HEADLINE <b> must be block via a CHILD combinator")
    # ...and the over-broad descendant form (which also block-ifies a <b> nested inside the
    # <p>, the exact defect this test pins against) must not be present anywhere.
    assert not re.search(r"\.banner\s+\.body\s+b\s*\{\s*display:\s*block\s*\}", page), (
        "found the over-broad '.banner .body b{display:block}' descendant selector — it "
        "forces ANY nested <b> (including mid-sentence emphasis inside a banner's <p>) onto "
        "its own line")

    # The review-stage honest copy: "Add a redaction" is still emphasized, unchanged, genuinely
    # nested inside the <p> that follows the headline <b> (not a second headline). It was
    # RELOCATED by the compression pass from a .banner into a progressive-disclosure .dbody —
    # so the nested <b> emphasis is pinned in its new home (the CSS child-combinator rule that
    # this test's true subject is still asserted above, and still protects the remaining
    # .banner .body headlines).
    add_idx = html_part.index("Add a redaction")
    assert html_part[add_idx - 3:add_idx + 19] == "<b>Add a redaction</b>"
    p_start = html_part.rfind("<p>", 0, add_idx)
    p_end = html_part.index("</p>", add_idx)
    assert "Use <b>Add a redaction</b> for anything it missed" in html_part[p_start:p_end]
    body_start = html_part.rfind('<div class="dbody">', 0, p_start)
    assert "<b>This does a thorough first pass.</b>" in html_part[body_start:p_start], (
        "the headline <b> must still precede the mid-sentence <p>, in the relocated disclosure")

    # The sensitive-passages copy (now relocated into a disclosure): both nested emphasis
    # spans are unchanged and nested — no caveat text was deleted or weakened by the move.
    assert ("<p>These passages aren&rsquo;t identifiers, so they&rsquo;re "
            "<b>not removed automatically</b> &mdash;") in html_part
    assert ('then tick <b>&ldquo;I&rsquo;ve reviewed this&rdquo;</b>. Export stays locked '
            'until they are acknowledged.</p>') in html_part
    sens_idx = html_part.index("not removed automatically")
    sens_body_start = html_part.rfind('<div class="dbody">', 0, sens_idx)
    assert "<b>You must read these before you can export.</b>" in html_part[sens_body_start:sens_idx]


# ============================================================================
# UI COMPRESSION PASS — progressive disclosure, status chips, folded Review,
# the new Report stage + its confined open/reveal route. These pin the LOAD-
# BEARING invariants of the compression: no caveat was deleted (only relocated),
# the honesty wording holds, and the new plumbing is wired to real state/routes.
# ============================================================================
def test_redaction_status_chips_wired_to_state():
    """The status chip strip ships and is wired to REAL state seams (not decorative):
      * `Local only` is static; `OCR unavailable` is driven by the OCR probe;
      * `N findings` reflects the last scan; `Human review required` reflects unacked passages;
      * the health route carries the `ocr` boolean the OCR chip reads."""
    c = _client()
    page = c.get("/redaction").text
    # The strip + the four chips exist.
    assert 'id="chipbar"' in page
    assert ">Local only<" in page
    for cid in ("ocrChip", "findingsChip", "humanReviewChip"):
        assert f'id="{cid}"' in page, f"missing status chip #{cid}"
    # Wired to real state seams in the JS (not hardcoded).
    assert "function updateStatusChips(" in page
    assert "function setOcrAvailable(" in page
    assert "findingsChip" in page and "humanReviewChip" in page
    # The health route now reports OCR availability (the OCR chip's source of truth).
    h = c.get("/api/redaction/health").json()
    assert "ocr" in h and isinstance(h["ocr"], bool)
    # Still air-gapped.
    assert "http://" not in page and "https://" not in page


def test_redaction_disclosures_relocate_caveats_verbatim():
    """The compression pass RELOCATED cautionary paragraphs behind progressive-disclosure
    widgets — it never DELETED them. Pin that the disclosures exist AND still carry the full
    caveat text (verbatim-in-substance), plus the required lawyer-review sentence, plus the
    honest never-'safe-to-send' framing that must survive relocation."""
    page = _client().get("/redaction").text
    # Native <details> disclosure widgets (accessible, no framework) carry a `First pass only`
    # chip as the decisive visible label.
    assert '<details class="disclosure' in page
    assert ">First pass only<" in page
    # The REQUIRED lawyer-review sentence is present verbatim (relocated into the disclosure).
    assert ("This tool helps identify likely redactions, but a lawyer must review the final "
            "document before relying on it.") in page
    # The ORIGINAL first-pass banner copy was preserved, not deleted.
    assert "it never makes a document &ldquo;safe to send&rdquo;" in page
    assert "the only deal" in page and "closing this quarter" in page
    # The re-identification exposure caption + the sensitive-passage caption survive the move
    # into disclosures — including their explicit NOT-a-safety-guarantee wording.
    assert "exposure indicator" in page
    assert "NOT an anonymity guarantee and NOT a measure of whether the" in page
    assert "surface for" in page
    # The honesty invariant: the page still frames output as a first pass, never "safe to send".
    assert "safe to send" in page


def test_redaction_one_primary_action_per_stage():
    """Progressive-disclosure principle: ONE primary action per stage, visually dominant. Each
    working stage section marks its single dominant action with data-primary — pin exactly one
    per stage so a future edit can't quietly add a competing primary."""
    page = _client().get("/redaction").text
    for stage in ("stage-document", "stage-detection", "stage-review", "stage-export",
                  "stage-report"):
        start = page.index(f'id="{stage}"')
        # The stage section runs until the next stage section (or end of the stages).
        rest = page[start + 1:]
        nxt = rest.find('class="stage"')
        section = page[start: start + 1 + (nxt if nxt != -1 else len(rest))]
        n = section.count('data-primary="1"')
        assert n == 1, f"{stage} must have exactly ONE data-primary action, found {n}"


def test_redaction_empty_states_verbatim():
    """The three empty-state strings ship VERBATIM (product-neutral copy shared by Lawbat's
    /redaction and the standalone Redactor's /)."""
    page = _client().get("/redaction").text
    assert "Choose a document to begin." in page
    assert "Add names or terms you already know must be redacted." in page
    assert "Review each finding before export." in page


def test_redaction_human_review_summary_chip_wired_to_real_state():
    """FIX (independent review): the Review-stage disclosure carried a SECOND, STATIC
    "Human review required" chip (#humanReviewSummaryChip) that never reflected real state —
    unlike the top-bar #humanReviewChip, which updateStatusChips() (redaction.gates.js) already
    drives from the real passage-acknowledge gate. Chose to WIRE the duplicate (rather than
    remove it) in the SAME function that toggles the live chip, so both read from one source
    of truth: hidden when nothing was flagged, "Acknowledged" once every flagged passage is
    ticked, "Human review required" while pending."""
    page = _client().get("/redaction").text
    assert 'id="humanReviewSummaryChip"' in page
    js = _assembled_redaction_js_path().read_text(encoding="utf-8")
    m = re.search(r"function updateStatusChips\(\)\{(.*?)\n  \}", js, re.DOTALL)
    assert m, "updateStatusChips body not found"
    body = m.group(1)
    # Both chips are read/toggled from the SAME function + the same `pending`/`total` state.
    assert "humanReviewChip" in body and "humanReviewSummaryChip" in body
    assert "Acknowledged" in body


def test_redaction_report_stage_and_open_export_route_confined():
    """The Report stage ships with its chips + Open-folder / View-report buttons, and the
    open-export route those buttons drive is token-guarded AND confined to the exports dir
    (rejects a path escape; 404 for a name that isn't there; reveals a real exports file)."""
    from app.paths import exports_dir
    page = _client().get("/redaction").text
    # Report stage chips + actions exist.
    for eid in ("repSavedChip", "repReportChip", "repCheckChip", "openFolderBtn",
                "viewReportBtn", "reportChips"):
        assert f'id="{eid}"' in page, f"missing report-stage element #{eid}"
    # The JS wires the buttons + flips the exported gate.
    assert "function renderReportStage(" in page and "function markExported(" in page
    assert "/api/redaction/open-export" in page
    assert "Redacted copy saved" in page and "Workflow report saved" in page

    c = _client()
    # Token-guarded: no token -> 403.
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/redaction/open-export",
                         json={"filename": "x.txt"}).status_code == 403

    # A real file in the exports dir can be revealed (reveal is a no-op under
    # LAWDATAMAN_DISABLE_OS_OPEN, so this exercises the confinement, not a viewer).
    ed = exports_dir()
    ed.mkdir(parents=True, exist_ok=True)
    (ed / "confine-me.report.txt").write_text("ok", encoding="utf-8")
    r_ok = c.post("/api/redaction/open-export",
                  json={"filename": "confine-me.report.txt", "action": "open"})
    assert r_ok.status_code == 200 and r_ok.json().get("ok") is True, r_ok.text

    # A path escape is refused (only a bare filename inside the exports dir).
    for bad in ("../evil.txt", "sub/dir.txt", "..", ""):
        rb = c.post("/api/redaction/open-export", json={"filename": bad})
        assert rb.status_code in (400, 404), (bad, rb.status_code, rb.text)

    # A name that doesn't exist in the exports dir -> 404 (never reveals nothing silently).
    r404 = c.post("/api/redaction/open-export", json={"filename": "nope-not-here.pdf"})
    assert r404.status_code == 404, r404.text


def test_redaction_open_export_rejects_embedded_nul():
    """FIX (independent review): a filename carrying an embedded NUL (or other control char)
    used to reach `(exports_dir() / base).resolve()` unchecked — Path.resolve() raises an
    uncaught `ValueError: embedded null byte` on that input, surfacing as an unhandled 500
    instead of the route's honest 400 invalid-filename response. The route now rejects any
    control character BEFORE building a Path."""
    c = _client()
    for bad in ("x\x00y", "x\x00", "\x00", "x\x01y", "x\x7fy"):
        r = c.post("/api/redaction/open-export", json={"filename": bad})
        assert r.status_code == 400, (repr(bad), r.status_code, r.text)
        assert "invalid filename" in r.json().get("error", "")
