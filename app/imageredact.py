"""
Image-based redaction for SCANNED (image-only) PDF pages.

A scanned PDF's identifiers are PIXELS, not text — the byte-removal PDF path
(`redaction::redact_pdf`) cannot touch them. This module makes them redactable:

  rasterize a text-less page -> OCR it to words+boxes (tesseract) -> detect
  identifiers over the OCR'd text via the SHARED engine (the injected `scan_fn`,
  i.e. redact-cli `scan`) -> BURN filled black boxes into the raster -> rebuild the
  page as a FLAT redacted image.

## True removal (load-bearing)

The redacted page in the output is a flat image whose pixels under each box are
BLACK; the original page image (with the identifier pixels) is NEVER copied into the
output. So this is true removal — not a black rectangle drawn OVER still-present
pixels (the classic redaction failure an annotation/overlay would leave).

## Over-cover, never under-cover (the leak rule)

A detected span redacts the WHOLE OCR word box(es) it touches, plus a small pad —
we would rather cover too much than leave part of an identifier visible. (The user's
own caveat: "box mis-placement = a visible-but-unremoved leak.")

## HONEST framing (do NOT overclaim)

Best-effort, **never "safe to send"**. OCR can MISREAD or MISS text (an undetected
identifier is not redacted); a born-digital page is left to the text path (it has a
real text layer); and the residual-identification judgment is the lawyer's. Pages
where OCR found NO text are reported (`ocr_empty_pages`) so the reviewer eyeballs
them rather than trusting a zero-box result. The CALLER must refuse the whole
operation when no tesseract binary is available (an absent OCR engine must never
yield a silently-unredacted "redacted" output) — see the route guard.

## LOCAL / deterministic / no egress

OCR + raster + detection all run locally; the OCR text + detected spans are matter
data held IN-PROCESS (never logged, never egressed); the report carries COUNTS only.
"""

import io
import os
import tempfile

# Bound a hostile / huge scanned PDF: OCR is the slow step, so cap the pages we will
# process. Over the cap we REFUSE the whole op (fail-closed) rather than emit a
# partially-redacted PDF the user might trust as complete.
MAX_PAGES = 500
# Bound the per-page raster so a tiny crafted PDF with a giant MediaBox can't make
# PyMuPDF attempt a multi-GB allocation (an OOM DoS). A page whose raster at the chosen
# DPI would exceed this is rendered at a reduced scale (lower effective DPI) rather than
# refused, so a genuinely large scan still redacts — only the pathological case shrinks.
MAX_PAGE_MEGAPIXELS = 50
# Over-cover padding (pixels) around each OCR word box.
BOX_PAD_PX = 2
# Rasterization DPI for OCR + the redacted output image. 300 (was 200): tesseract's
# sweet spot — 200 measurably misread checksummed identifiers (NRIC/ISIN confusions)
# on the OCR harness corpus. The megapixel clamp below already bounds the growth.
RENDER_DPI = 300
# Per-span (v2) review caps: bound the preview payload + the accepted-rect count so a
# hostile/huge PDF can't blow up the response or the apply request.
SCAN_PREVIEW_MAX_PAGES = 60
PREVIEW_MAX_PX = 1100
MAX_SELECTION_RECTS = 10000


def _assemble(words):
    """Join OCR words into one text, returning `(text, offsets)` where
    `offsets[i] = (start, end)` is word i's half-open **UTF-8 BYTE** range in `text`.
    The detector (`redact-cli scan`) reports candidate spans as UTF-8 BYTE offsets into
    exactly this text, so the offsets here MUST be byte ranges (not char positions) or a
    multibyte char before an identifier would mis-map the span to the wrong word — a leak
    (the prior non-ASCII byte-offset Critical).

    LINE-AWARE: consecutive words on DIFFERENT OCR lines (their `OcrWord.line_id` — the
    tesseract `(block, par, line)` triple — differs) are joined with a newline instead of
    a space; words on the same line, or with an UNKNOWN line id (`None` on either side,
    e.g. a hand-built word or a malformed TSV row), keep a space (the prior behaviour).
    Rebuilding line breaks lets the engine's line-scoped recall + context recognizers
    (which scan back N lines from a role label) fire on OCR'd scanned text — on a
    one-line-per-page assembly they were structurally blind, and real names went
    undetected. CRITICAL: BOTH separators are exactly ONE ASCII byte ('\\n' and ' ' each
    encode to 1 byte), so the per-word BYTE offsets are identical regardless of which
    separator is chosen — the engine's byte-offset math is unchanged."""
    parts = []
    seps = []
    offsets = []
    pos = 0  # BYTE position into the UTF-8 of the assembled text
    prev_line = None
    for i, w in enumerate(words):
        line_id = getattr(w, "line_id", None)
        if i > 0:
            # A newline ONLY between two words that both KNOW their line and are on
            # different lines; otherwise a space. Either way exactly 1 ASCII byte.
            newline = (
                prev_line is not None and line_id is not None and line_id != prev_line
            )
            seps.append("\n" if newline else " ")
            pos += 1  # the single 1-byte separator (space or newline)
        start = pos
        parts.append(w.text)
        pos += len(w.text.encode("utf-8"))  # BYTE length, matching the engine's offsets
        offsets.append((start, pos))
        prev_line = line_id
    # Interleave words with their chosen 1-byte separators (seps[i] precedes parts[i+1]).
    text = "".join(
        p if i == 0 else seps[i - 1] + p for i, p in enumerate(parts)
    )
    return text, offsets


# Whole-document scan join separator between consecutive page texts. A BLANK line —
# exactly TWO ASCII bytes ('\n\n'). WHY a blank line (not a single '\n' / a space): the
# engine's TRAILING-ROLE context recognizer treats a blank line as a PARAGRAPH boundary
# and will not scan a role label across it, so a role anchored at the FOOT of one page can
# never falsely bind a name at the TOP of the next page via the join — a page join is never
# a spurious context bridge. The engine's DETECTED-NAME propagation (a name detected
# anywhere in one scan text is re-flagged at its other ws-elastic occurrences in that SAME
# text) DOES cross the join — which is exactly the cross-page removal this whole-document
# scan exists to enable. Two ASCII bytes, so the engine's UTF-8 byte-offset math over the
# joined text is exact.
_PAGE_JOIN = "\n\n"


def _join_page_texts(texts):
    """Join per-page OCR texts into ONE whole-document text for a SINGLE engine scan,
    returning `(joined, ranges)` where `ranges[i] = (start, end)` is page i's half-open
    UTF-8 **BYTE** range in `joined`. Pages are joined with [`_PAGE_JOIN`] (a blank line,
    2 bytes). The ranges are BYTE ranges (not char positions) because the engine reports
    candidate spans as UTF-8 byte offsets into `joined` — so the split-back in
    [`_split_spans_by_page`] must clamp in the same coordinate system (the same non-ASCII
    byte-offset invariant `_assemble` documents).

    EVERY page occupies a slot: an EMPTY page (OCR found no words -> its text is "")
    contributes a ZERO-LENGTH range but the separators around it are STILL placed, so a
    later page's range stays byte-aligned with `joined` (an empty page must not collapse
    the offsets of the pages after it — the alignment regression this design could
    otherwise introduce)."""
    joined = _PAGE_JOIN.join(texts)
    sep_len = len(_PAGE_JOIN.encode("utf-8"))  # 2 (both bytes ASCII)
    ranges = []
    pos = 0  # BYTE position into the UTF-8 of `joined`
    for i, t in enumerate(texts):
        if i > 0:
            pos += sep_len  # the separator preceding this page's text
        start = pos
        pos += len(t.encode("utf-8"))  # BYTE length, matching the engine's offsets
        ranges.append((start, pos))
    return joined, ranges


def _split_spans_by_page(spans, ranges):
    """Map whole-document `spans` (byte offsets into the joined text) back to PER-PAGE
    LOCAL spans. `spans[i]` is `(start, end)` or `(start, end, label)` — extra fields
    (the recognizer label, for the per-span variant) ride through unchanged. `ranges[i]`
    is page i's byte range in the joined text (from [`_join_page_texts`]). Returns
    `per_page` where `per_page[i]` is the list of spans that overlap page i, each CLAMPED
    to that page's byte range and RE-BASED to page-LOCAL byte offsets (so it feeds the
    unchanged `_rects_for_spans` / `_candidates_for_spans`, which expect page-local
    offsets against that page's words).

    A span that STRADDLES a page boundary (possible: the engine's ws-elastic cross-page
    name propagation can extend a detected span across the `_PAGE_JOIN`) is assigned to
    BOTH overlapped pages, each side clamped to its page — so both fragments are burned.
    We NEVER silently drop the out-of-range part (dropping it could leave part of an
    identifier visible — the leak side). Bytes that fall in the separator GAP between
    pages belong to no page range and are excluded (they are join scaffolding, not page
    content). Zero-length results (e.g. a span touching only an empty page's point) are
    skipped."""
    per_page = [[] for _ in ranges]
    for span in spans:
        gs, ge = span[0], span[1]
        extra = tuple(span[2:])  # () for (start,end); (label,) for the per-span variant
        if ge <= gs:
            continue
        for i, (rs, re) in enumerate(ranges):
            if gs < re and rs < ge:  # the span overlaps this page's byte range
                ls = max(gs, rs) - rs  # clamp to the page, re-base to page-local
                le = min(ge, re) - rs
                if le > ls:
                    per_page[i].append((ls, le) + extra)
    return per_page


def _rects_for_spans(words, offsets, spans, img_size, pad: int = BOX_PAD_PX):
    """Map detected `spans` (`[(start, end)]`, half-open UTF-8 BYTE ranges in the
    assembled text — the engine's coordinate system, matching `_assemble`'s offsets) to
    redaction rectangles `[(x0, y0, x1, y1)]` in image-pixel coords.

    OVER-COVER: any word whose char range overlaps a span has its WHOLE box redacted
    (plus `pad`), clamped to the image — never a sub-word region (which could leave
    part of an identifier visible)."""
    w_img, h_img = img_size
    rects = []
    seen = set()  # dedup identical boxes (overlapping spans hitting the same word)
    for s, e in spans:
        if e <= s:
            continue
        for i, (ws, we) in enumerate(offsets):
            if ws < e and s < we:  # the word overlaps the detected span
                word = words[i]
                x0 = max(0, word.x - pad)
                y0 = max(0, word.y - pad)
                x1 = min(w_img, word.x + word.w + pad)
                y1 = min(h_img, word.y + word.h + pad)
                rect = (x0, y0, x1, y1)
                if x1 > x0 and y1 > y0 and rect not in seen:
                    seen.add(rect)
                    rects.append(rect)
    return rects


def _candidates_for_spans(words, offsets, spans, img_size, pad: int = BOX_PAD_PX):
    """Per-span (v2) variant of [`_rects_for_spans`]: group each detected identifier into a
    reviewable candidate `{"label": recognizer, "advisory": bool, "rects": [whole-word boxes
    to BURN], "bbox": union box for the OVERLAY}`. `spans` = `[(start, end, label)]` or
    `[(start, end, label, advisory)]` (UTF-8 byte ranges + recognizer + the OPTIONAL advisory
    flag — an aggressive-recognizer hit the review renders DEFAULT-OFF, mirroring the
    born-digital review; absent = False, backward-compatible). The whole-word over-cover is
    identical to `_rects_for_spans`; this just keeps the per-identifier grouping so the
    reviewer can accept/reject one identifier at a time. Pixel-space."""
    assembled = _assemble(words)[0].encode("utf-8")
    w_img, h_img = img_size
    cands = []
    seen = set()
    for span in spans:
        s, e, label = span[0], span[1], span[2]
        advisory = bool(span[3]) if len(span) > 3 else False
        if e <= s:
            continue
        rects = []
        rseen = set()
        for i, (ws, we) in enumerate(offsets):
            if ws < e and s < we:  # the word overlaps the detected span
                word = words[i]
                x0 = max(0, word.x - pad)
                y0 = max(0, word.y - pad)
                x1 = min(w_img, word.x + word.w + pad)
                y1 = min(h_img, word.y + word.h + pad)
                r = (x0, y0, x1, y1)
                if x1 > x0 and y1 > y0 and r not in rseen:
                    rseen.add(r)
                    rects.append(r)
        if not rects:
            continue
        key = (label, advisory, tuple(rects))
        if key in seen:  # dedup identical detections
            continue
        seen.add(key)
        bbox = (
            min(r[0] for r in rects),
            min(r[1] for r in rects),
            max(r[2] for r in rects),
            max(r[3] for r in rects),
        )
        cands.append({"value": assembled[s:e].decode("utf-8", errors="strict"), "label": label, "advisory": advisory, "rects": rects, "bbox": bbox})
    return cands


def _bounded_pixmap(page, dpi):
    """Render `page` to a pixmap at `dpi`, but REDUCE the scale if the raster would exceed
    `MAX_PAGE_MEGAPIXELS` — bounding memory against a hostile giant MediaBox (a tiny PDF
    can otherwise declare a page so large that `get_pixmap` attempts a multi-GB malloc).
    A legitimate large page renders at a lower effective DPI rather than being refused."""
    import math

    import fitz

    scale = dpi / 72.0
    w = abs(page.rect.width) * scale
    h = abs(page.rect.height) * scale
    mp = (w * h) / 1_000_000.0
    if mp > MAX_PAGE_MEGAPIXELS:
        scale *= math.sqrt(MAX_PAGE_MEGAPIXELS / mp)
    return page.get_pixmap(matrix=fitz.Matrix(scale, scale))


def _prepare_geometry(img, prep_fn):
    """GEOMETRY-correct a page raster before OCR: OSD rotation (90/180/270) + small-
    angle deskew, via `prep_fn` (default `ocr.prepare_page_image`; injectable in
    tests). Returns `(corrected_img, geo)`.

    THE GEOMETRY INVARIANT (leak-relevant): OCR word boxes are measured in the
    CORRECTED image's pixel space, so the burn/preview/output raster MUST be that
    same corrected image. We burn on the corrected raster and use it as the output
    page — a rotated scan's redacted page therefore comes out UPRIGHT (deliberate:
    visually identical content, physically re-oriented — same rule as the /Rotate
    normalization documented on `redact_scanned_pdf`). Re-renders (the burn phase,
    which discards phase-I rasters to bound memory) REPLAY the stored geo via
    `ocr.apply_geometry` instead of re-detecting, so both phases land in the
    identical pixel space by construction. FAIL-OPEN: any error -> the original
    raster with identity geo (today's behaviour, never worse)."""
    if prep_fn is None:
        from .ocr import prepare_page_image
        prep_fn = prepare_page_image
    try:
        img2, geo = prep_fn(img)
        rotate = int(geo.get("rotate", 0))
        deskew = float(geo.get("deskew", 0.0))
        if rotate not in (0, 90, 180, 270):
            return img, {"rotate": 0, "deskew": 0.0}
        # Mirror apply_geometry's replay bound (|deskew| <= 3): a prep_fn reporting a
        # wilder angle would put phase-I boxes in a space the replay REFUSES, i.e. a
        # misplaced burn (review finding — unreachable via the default prepare_page_image,
        # which is bounded, but the seam must not trust its injectable). Same fail-open
        # as an invalid rotate: the ORIGINAL raster with identity geo, never a mismatch.
        if not (deskew == deskew and abs(deskew) <= 3.0):  # NaN-safe
            return img, {"rotate": 0, "deskew": 0.0}
        return img2, {"rotate": rotate, "deskew": deskew}
    except Exception:  # noqa: BLE001 - geometry must never break redaction (fail-open)
        return img, {"rotate": 0, "deskew": 0.0}


def _replay_geometry(img, geo):
    """Re-apply a stored `_prepare_geometry` geo to a fresh render of the same page
    (deterministic replay — see the geometry invariant above). Never raises."""
    try:
        from .ocr import apply_geometry
        return apply_geometry(img, geo)
    except Exception:  # noqa: BLE001
        return img


def _page_dims_for_geo(rect, geo):
    """Output page (width_pt, height_pt) for a geometry-corrected raster: a 90/270
    rotation swaps the page's aspect (the redacted page comes out upright)."""
    try:
        rotate = int((geo or {}).get("rotate", 0))
    except (TypeError, ValueError):
        rotate = 0
    if rotate in (90, 270):
        return rect.height, rect.width
    return rect.width, rect.height


def _page_conf(words):
    """Mean OCR word confidence for a page (None when unknown) — the honesty signal.
    `low` is True only for a KNOWN-low page: unknown confidence (hand-built words,
    empty page) is never flagged low (ocr_empty covers the no-words case)."""
    from .ocr import LOW_CONF_THRESHOLD, page_confidence
    conf = page_confidence(words)
    low = conf is not None and conf < LOW_CONF_THRESHOLD
    return conf, low


def _ocr_pixmap_image(img, ocr_fn):
    """OCR a PIL image via `ocr_fn` (which takes an image-file path). Writes a temp
    PNG, OCRs it, cleans up. Returns the word list (or []).

    The temp PNG goes UNDER the app-data temp dir (`paths.temp_dir`), not the system
    temp dir, so a hard kill between the write and the `finally` remove leaves no matter
    raster in system temp — a survivor is swept on the next startup (see `paths.temp_dir`)."""
    from .paths import temp_dir
    fd, path = tempfile.mkstemp(suffix=".png", prefix="ldm-imgredact-", dir=str(temp_dir()))
    os.close(fd)
    try:
        img.save(path, "PNG")
        return ocr_fn(path) or []
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _image_coverage(page):
    """Return `(has_image, dominant)`: whether the page carries ANY raster image, and
    whether raster images cover a LARGE (>=50%) fraction of the page area.

    Conservative on any PyMuPDF quirk: if images exist but we cannot measure them, report
    `dominant=True` (over-redact, never under). Used by [`_should_image_redact`]."""
    try:
        imgs = page.get_images(full=True)
    except Exception:  # noqa: BLE001
        return False, False
    if not imgs:
        return False, False
    try:
        parea = abs(page.rect.width * page.rect.height)
        if parea <= 0:
            return True, True  # cannot measure -> conservative (treat as dominant)
        covered = 0.0
        for img in imgs:
            for r in page.get_image_rects(img[0]):
                covered += abs(r.width * r.height)
                if covered >= 0.5 * parea:
                    return True, True
        return True, False
    except Exception:  # noqa: BLE001 - images exist but measuring failed -> conservative
        return True, True


def _should_image_redact(page):
    """Decide whether a page must be image-redacted (rasterize + OCR + burn boxes).

    A page is image-redacted when:
    - it has NO usable text layer AND carries ANY raster image — a SCANNED page, at ANY
      image size (so a text-LESS scanned exhibit covering <50% of the page can't escape
      as 'digital passthrough'); OR
    - it has a text layer AND a DOMINANT (>=50%) image — a mixed text+image page (e.g. a
      scan with a Bates/page-number overlay); flattened so the image can't escape.

    A page is PASSED THROUGH (text path's job, or nothing to do) when it has a text layer
    and at most a SMALL image (a decorative logo on a born-digital page), or no image at
    all. NOTE (honest residual): a SMALL scanned exhibit embedded on a born-digital TEXT
    page is passed through here — the text path handles its text, but image-baked
    identifiers in that small exhibit are not removed. This is the deliberate trade-off
    that avoids OCR-flattening every logo'd digital page; it is the documented limit of
    best-effort OCR redaction. Returns `(redact: bool, has_text: bool)`."""
    has_text = bool(page.get_text("text").strip())
    has_image, dominant = _image_coverage(page)
    redact = (has_image and not has_text) or (dominant and has_text)
    return redact, has_text


def redact_scanned_pdf(pdf_bytes, scan_fn, ocr_fn=None, dpi: int = RENDER_DPI,
                       prep_fn=None):
    """Redact the SCANNED (text-less) pages of `pdf_bytes` by OCR + burning black
    boxes into a flattened raster. Returns `(redacted_pdf_bytes, report)` on success,
    or `(None, {"error": ...})` fail-closed.

    - `scan_fn(text) -> [(start, end)]`: the detector (the SHARED engine; the web layer
      adapts redact-cli `scan`). Pure text -> spans, so this module stays testable.
    - `ocr_fn(image_path) -> [OcrWord]`: OCR a page image to words+boxes (defaults to
      `ocr.ocr_words`; injected in tests).
    - `prep_fn(img) -> (img, geo)`: GEOMETRY correction (OSD rotation + deskew;
      defaults to `ocr.prepare_page_image`; injectable in tests). Boxes are in the
      corrected image's pixel space and the corrected raster IS the output page, so
      a rotated scan's redacted page comes out UPRIGHT — see `_prepare_geometry`.
    - Born-digital pages (a real text layer) are COPIED THROUGH UNCHANGED (this path is
      image-only; they belong to the text/byte path) and counted in `digital_skipped`.
    - A PDF over `MAX_PAGES` is REFUSED whole (fail-closed) — never a partial redaction;
      an empty (0-page) PDF returns a structured error.
    - A redacted page is rebuilt as a flat image in its DISPLAY orientation, so a page
      with a `/Rotate` comes out physically re-oriented (visually identical, no leak).
    - Detection is WHOLE-DOCUMENT: every scanned page is OCR'd (phase I), the page texts
      are joined with [`_PAGE_JOIN`] and scanned in ONE `scan_fn` call, and the returned
      spans are mapped back to per-page boxes (phase II). This is what lets the engine's
      detected-name propagation reach ACROSS pages — a name role-anchored on one page is
      re-flagged where it recurs on ANOTHER page (a per-page scan left the later bare
      mention readable). Per-scanned-page cost is one OCR + two rasterizations (phase I to
      OCR, phase III to burn — the raster is not retained between them, so peak memory
      stays one page, bounding a 500-page doc); the identifier scan is ONE subprocess for
      the whole document (the redact-cli bin caps its stdin envelope at 16 MiB and
      ERRORS — never truncates — when over, so an oversized join fails CLOSED at the
      route; the joined text of many pages rides ONE request). Total work is bounded
      by `MAX_PAGES`.

    The report is COUNTS only: `pages`, `scanned`, `redacted_pages`, `boxes`,
    `digital_skipped`, `ocr_empty_pages`, `mixed_pages`, plus `low_conf_pages` —
    `[{page: 1-based, conf: int}]` for pages whose mean OCR confidence fell under
    `ocr.LOW_CONF_THRESHOLD` (page numbers + a percentage: diagnostics, not matter
    text; the honest "this page scanned poorly" signal). NEVER carries matter text."""
    import fitz  # PyMuPDF (AGPL-3.0 / Artifex commercial)
    from PIL import Image, ImageDraw

    if ocr_fn is None:
        from .ocr import ocr_words

        ocr_fn = ocr_words

    try:
        src = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:  # noqa: BLE001 - a bad PDF is an error, never a crash
        return None, {"error": "could not open the PDF (it may be malformed or encrypted)"}

    try:
        if getattr(src, "needs_pass", False):  # encrypted: fitz opens but reads raise later
            return None, {"error": "could not open the PDF (it may be malformed or encrypted)"}
        if src.page_count > MAX_PAGES:
            return None, {
                "error": f"PDF has too many pages for OCR redaction (max {MAX_PAGES})"
            }
        if src.page_count == 0:
            return None, {"error": "the PDF has no pages"}
        out = fitz.open()
        report = {
            "pages": src.page_count,
            "scanned": 0,
            "redacted_pages": 0,
            "boxes": 0,
            "digital_skipped": 0,
            "ocr_empty_pages": 0,
            "mixed_pages": 0,
            "low_conf_pages": [],
        }
        # PHASE I — rasterize + OCR every eligible page, collecting per-page
        # (words, page_text, offsets); build a `plan` of ALL pages in output order so
        # phase III can rebuild them (passthrough vs scanned) without re-classifying. The
        # raster image is DISCARDED after OCR (re-rendered in phase III) so peak memory
        # stays one page, not `MAX_PAGES` full-res images.
        segments = []  # scanned pages only, in order: {pno, words, offsets, text}
        plan = []      # every page in order: (pno, seg_idx or None-for-passthrough)
        for pno in range(src.page_count):
            page = src[pno]
            # Classify per [`_should_image_redact`]: a text-LESS page with ANY image is a
            # scanned page (any image size) -> redact; a text page with a DOMINANT image
            # is a mixed page -> redact (flatten); everything else (text-only / small
            # logo on a text page / blank / vector) passes through. This closes the
            # text-less-small-exhibit hole AND the thin-text-overlay hole.
            redact, has_text = _should_image_redact(page)
            if not redact:
                report["digital_skipped"] += 1
                plan.append((pno, None))
                continue

            report["scanned"] += 1
            if has_text:
                # A text layer present but we image-redact (dominant image): flatten +
                # OCR-redact (the selectable text becomes part of the redacted image) so
                # nothing in the image escapes. Surfaced so the user knows it flattened.
                report["mixed_pages"] += 1
            pix = _bounded_pixmap(page, dpi)
            img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            # GEOMETRY: rotate/deskew BEFORE OCR — a rotated scan OCRs to garbage, so
            # the recognizers go blind and the burn silently misses. Boxes are in the
            # corrected space; phase III replays the stored geo (see _prepare_geometry).
            img, geo = _prepare_geometry(img, prep_fn)

            words = _ocr_pixmap_image(img, ocr_fn)
            if not words:
                # OCR found nothing — either a genuinely blank page OR an OCR miss.
                # Flatten it (no boxes) and FLAG it so the reviewer eyeballs it rather
                # than trusting a zero-box "clean" result. It STILL occupies a slot in the
                # join (an empty page-text) so later pages stay byte-aligned.
                report["ocr_empty_pages"] += 1
            conf, low = _page_conf(words)
            if low:
                # HONESTY, never filtering: the low-confidence text still scans/burns —
                # the flag tells the reviewer to eyeball the page (a MISS is the leak).
                report["low_conf_pages"].append({"page": pno + 1, "conf": int(round(conf))})
            text, offsets = _assemble(words)
            plan.append((pno, len(segments)))
            segments.append({"pno": pno, "words": words, "offsets": offsets,
                             "text": text, "geo": geo})

        # PHASE II — ONE whole-document scan, then map the returned spans back to
        # per-page LOCAL spans. Joining every scanned page's text (empty pages included)
        # lets the engine propagate a name detected on one page to its recurrences on
        # other pages — the cross-page removal this restructure exists to enable. Skip the
        # subprocess entirely if OCR found no words anywhere (nothing to detect).
        texts = [seg["text"] for seg in segments]
        joined, ranges = _join_page_texts(texts)
        any_words = any(seg["words"] for seg in segments)
        spans = scan_fn(joined) if any_words else []
        per_page = _split_spans_by_page(spans, ranges)

        # PHASE III — rebuild the output in page order: passthrough pages copy through;
        # scanned pages re-render, burn their mapped local spans, and flatten to a JPEG.
        for pno, seg_idx in plan:
            page = src[pno]
            rect = page.rect
            if seg_idx is None:
                out.insert_pdf(src, from_page=pno, to_page=pno)
                continue
            seg = segments[seg_idx]
            pix = _bounded_pixmap(page, dpi)  # deterministic: same size as the phase-I raster
            img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            # REPLAY the phase-I geometry (never re-detect): the words' boxes are in the
            # corrected pixel space, so the burn raster must be the identical image.
            img = _replay_geometry(img, seg["geo"])
            rects = _rects_for_spans(seg["words"], seg["offsets"], per_page[seg_idx], img.size)
            if rects:
                draw = ImageDraw.Draw(img)
                for x0, y0, x1, y1 in rects:
                    draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))
                report["boxes"] += len(rects)
                report["redacted_pages"] += 1

            # Rebuild the page as a FLAT redacted image — the original page image (with
            # the identifier pixels) is never copied into `out`, so the burned-out
            # regions are truly gone.
            #
            # Encode as JPEG (quality 85), NOT PNG: a rasterized scan is photographic, so
            # PNG barely compresses it (10 flat pages ran ~896 MB). The redaction burn
            # already painted the identifier pixels SOLID BLACK *before* this encode, so
            # lossy JPEG operates only on already-removed content — it cannot resurrect
            # anything under a box (those pixels are (0,0,0) going in). `img` is RGB, so
            # no alpha to lose. The JPEG STREAM is deterministic (PIL writes no
            # timestamps/metadata) — but the enclosing PDF is not byte-reproducible
            # (PyMuPDF stamps a fresh /ID), and nothing audit-hashes this output.
            # Still a single flat image (no text layer), DCTDecode.
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=85)
            # A 90/270-rotated scan comes out UPRIGHT: the output page's aspect follows
            # the corrected raster (see _prepare_geometry's geometry invariant).
            w_pt, h_pt = _page_dims_for_geo(rect, seg["geo"])
            newp = out.new_page(width=w_pt, height=h_pt)
            newp.insert_image(newp.rect, stream=buf.getvalue())

        data = out.tobytes()
        out.close()
        return data, report
    finally:
        src.close()


def scan_scanned_pdf(pdf_bytes, scan_fn, ocr_fn=None, dpi: int = RENDER_DPI,
                     preview_max_px: int = PREVIEW_MAX_PX, prep_fn=None, force_pages=None):
    """Per-span (v2) SCAN: OCR + detect each scanned page and return, per scanned page, a
    DOWNSCALED preview PNG (for visual review) + the detected candidates as PAGE-FRACTION
    coordinates (resolution-independent, so [`apply_selection_to_pdf`] can burn at any DPI).
    Returns `(pages, report)` or `(None, {"error": ...})` fail-closed.

    - `scan_fn(text) -> [(start, end, label)]` or `[(start, end, label, advisory)]`: the
      detector with the recognizer label + the OPTIONAL advisory flag (an aggressive-
      recognizer hit, surfaced but rendered DEFAULT-OFF by the review — parity with the
      born-digital review). Called ONCE on the whole-document join (all scanned page texts joined by
      [`_PAGE_JOIN`]), so the engine's detected-name propagation reaches ACROSS pages —
      a name role-anchored on one page is re-flagged where it recurs on another (the same
      cross-page removal as `redact_scanned_pdf`). Returned spans are mapped back to
      per-page candidates.
    - Bounded: refuses over `MAX_PAGES`, over `SCAN_PREVIEW_MAX_PAGES` scanned pages (the
      preview payload), and a giant MediaBox (megapixel clamp). Previews + candidate labels
      are matter data held in the response only — never logged. The report is counts-only.
    - GEOMETRY (`prep_fn`, default `ocr.prepare_page_image`): each scanned page is
      rotation/deskew-corrected BEFORE OCR; previews + candidate fractions are in the
      CORRECTED space, and each page entry carries its `geo` — the client echoes it to
      [`apply_selection_to_pdf`] so the burn replays the exact same geometry (hard
      scan<->apply parity; a mismatched geo could burn the wrong region — the leak side).
      Each page entry also carries `ocr_conf`/`low_conf` (the honest "this page scanned
      poorly" signal — surfaced, never used to drop text)."""
    force_pages = frozenset(force_pages or ())
    import base64
    import io

    import fitz
    from PIL import Image

    if ocr_fn is None:
        from .ocr import ocr_words

        ocr_fn = ocr_words

    try:
        src = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:  # noqa: BLE001
        return None, {"error": "could not open the PDF (it may be malformed or encrypted)"}
    try:
        if getattr(src, "needs_pass", False):  # encrypted: fitz opens but reads raise later
            return None, {"error": "could not open the PDF (it may be malformed or encrypted)"}
        if src.page_count > MAX_PAGES:
            return None, {"error": f"PDF has too many pages for OCR redaction (max {MAX_PAGES})"}
        if src.page_count == 0:
            return None, {"error": "the PDF has no pages"}
        # Pre-pass: bound the preview payload by the number of scanned pages.
        scanned = sum(1 for pno in range(src.page_count) if pno in force_pages or _should_image_redact(src[pno])[0])
        if scanned > SCAN_PREVIEW_MAX_PAGES:
            return None, {
                "error": (
                    f"{scanned} scanned pages — too many for visual per-box review "
                    f"(max {SCAN_PREVIEW_MAX_PAGES}). Use ‘Redact all’ instead."
                ),
                "too_many": True,
            }
        pages = []
        report = {
            "pages": src.page_count,
            "scanned": 0,
            "digital_skipped": 0,
            "ocr_empty_pages": 0,
            "candidates": 0,
            "low_conf_pages": [],
        }
        # PHASE I — OCR every scanned page + build its preview, collecting per-page
        # (words, page_text, offsets, img_size). The raster is discarded after the preview
        # is encoded; only the (small) OCR words + the downscaled preview are retained
        # (memory bounded by SCAN_PREVIEW_MAX_PAGES previews, as before — no full-res image
        # is held). Digital pages are counted + skipped (not emitted), exactly as before.
        segments = []  # scanned pages only, in order
        for pno in range(src.page_count):
            page = src[pno]
            redact, has_text = _should_image_redact(page)
            redact = redact or pno in force_pages
            if not redact:
                report["digital_skipped"] += 1
                continue
            report["scanned"] += 1
            pix = _bounded_pixmap(page, dpi)
            img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            # GEOMETRY: correct BEFORE OCR; preview + fractions live in the corrected
            # space, and `geo` rides to the client for the apply replay (parity).
            img, geo = _prepare_geometry(img, prep_fn)
            w_img, h_img = img.size
            words = _ocr_pixmap_image(img, ocr_fn)
            if not words:
                report["ocr_empty_pages"] += 1
            conf, low = _page_conf(words)
            if low:
                report["low_conf_pages"].append({"page": pno + 1, "conf": int(round(conf))})
            text, offsets = _assemble(words)
            preview = img.copy()
            preview.thumbnail((preview_max_px, preview_max_px))  # downscale for display
            buf = io.BytesIO()
            preview.save(buf, "PNG")
            segments.append({
                "pno": pno,
                "words": words,
                "offsets": offsets,
                "text": text,
                "img_size": (w_img, h_img),
                "has_text": has_text,
                "geo": geo,
                "conf": conf,
                "low_conf": low,
                "preview": base64.b64encode(buf.getvalue()).decode("ascii"),
            })

        # PHASE II — ONE whole-document scan; map spans back to per-page LOCAL spans (see
        # `redact_scanned_pdf`). Empty pages occupy a slot in the join so page ranges stay
        # aligned. Skip the subprocess if OCR found no words anywhere.
        texts = [seg["text"] for seg in segments]
        joined, ranges = _join_page_texts(texts)
        any_words = any(seg["words"] for seg in segments)
        spans = scan_fn(joined) if any_words else []
        per_page = _split_spans_by_page(spans, ranges)

        # PHASE III — build per-page candidates from the mapped local spans. The candidate
        # id stays PAGE-based (`{pno}-{j}`) and coords are page-FRACTIONS, exactly as before.
        for si, seg in enumerate(segments):
            w_img, h_img = seg["img_size"]
            cands_px = _candidates_for_spans(
                seg["words"], seg["offsets"], per_page[si], (w_img, h_img))
            cands = []
            for j, c in enumerate(cands_px):
                bx0, by0, bx1, by1 = c["bbox"]
                cands.append({
                    "id": f"{seg['pno']}-{j}",
                    "label": c["label"],
                    "value": c["value"],
                    # Advisory (aggressive-recognizer) hit: SURFACED but rendered DEFAULT-OFF
                    # by the review UI, mirroring the born-digital review (the human opts in).
                    "advisory": bool(c.get("advisory", False)),
                    "bbox": [bx0 / w_img, by0 / h_img, bx1 / w_img, by1 / h_img],
                    "rects": [[r[0] / w_img, r[1] / h_img, r[2] / w_img, r[3] / h_img] for r in c["rects"]],
                })
            report["candidates"] += len(cands)
            pages.append({
                "index": seg["pno"],
                "preview": seg["preview"],
                "mixed": bool(seg["has_text"]),
                "ocr_empty": not seg["words"],
                # Honest per-page OCR quality (never a filter — the flag is the product).
                "ocr_conf": None if seg["conf"] is None else int(round(seg["conf"])),
                "low_conf": bool(seg["low_conf"]),
                # The geometry the fractions/preview live in — echoed back on apply so
                # the burn replays the identical pixel space (scan<->apply parity).
                "geo": seg["geo"],
                "candidates": cands,
            })
        return pages, report
    finally:
        src.close()


def apply_selection_to_pdf(pdf_bytes, accepted, dpi: int = RENDER_DPI, geo=None, force_pages=None):
    """Per-span (v2) APPLY: burn the ACCEPTED candidate rects (page-FRACTION coords) into
    the scanned pages and flatten; digital pages pass through unchanged. Returns
    `(out_bytes, report)` or `(None, {"error": ...})`.

    `accepted` = `{page_index: [[fx0, fy0, fx1, fy1], ...]}`. The SERVER re-classifies pages
    (the client only chooses WHICH boxes to burn, never what's a scanned page) and burns at
    full resolution, so true-removal + over-cover are preserved. Fractions are clamped to
    the page; malformed entries are skipped. Total rects are bounded by the caller.

    `geo` = `{page_index: {"rotate": 0|90|180|270, "deskew": float}}` — the per-page
    geometry [`scan_scanned_pdf`] corrected with and echoed to the client. The burn
    REPLAYS it so the accepted fractions land in the identical (corrected) pixel space
    the reviewer saw (scan<->apply parity — a geometry mismatch would burn the wrong
    region, the leak side). The values are validated by `ocr.apply_geometry` (unknown/
    out-of-range -> identity), and the client can only misplace boxes it itself chose —
    it already supplies the fractions, so `geo` adds no new trust surface. Absent geo
    (an old client / no correction) burns the raw render — today's behaviour."""
    force_pages = frozenset(force_pages or ())
    import io

    import fitz
    from PIL import Image, ImageDraw

    try:
        src = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:  # noqa: BLE001
        return None, {"error": "could not open the PDF (it may be malformed or encrypted)"}
    try:
        if getattr(src, "needs_pass", False):  # encrypted: fitz opens but reads raise later
            return None, {"error": "could not open the PDF (it may be malformed or encrypted)"}
        if src.page_count > MAX_PAGES:
            return None, {"error": f"PDF has too many pages for OCR redaction (max {MAX_PAGES})"}
        if src.page_count == 0:
            return None, {"error": "the PDF has no pages"}
        out = fitz.open()
        report = {
            "pages": src.page_count,
            "scanned": 0,
            "redacted_pages": 0,
            "boxes": 0,
            "digital_skipped": 0,
            "mixed_pages": 0,
        }
        for pno in range(src.page_count):
            page = src[pno]
            rect = page.rect
            redact, has_text = _should_image_redact(page)
            redact = redact or pno in force_pages
            if not redact:
                report["digital_skipped"] += 1
                out.insert_pdf(src, from_page=pno, to_page=pno)
                continue
            report["scanned"] += 1
            if has_text:
                report["mixed_pages"] += 1
            pix = _bounded_pixmap(page, dpi)
            img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            page_geo = None
            if isinstance(geo, dict):
                page_geo = geo.get(pno)
                if page_geo is None:
                    page_geo = geo.get(str(pno))
            if page_geo:
                # Replay the scan-time geometry so the accepted fractions land in the
                # same corrected pixel space the reviewer accepted them in (parity).
                img = _replay_geometry(img, page_geo)
            w_img, h_img = img.size
            rects_frac = accepted.get(pno)
            if rects_frac is None:
                rects_frac = accepted.get(str(pno), [])
            drawn = 0
            if rects_frac:
                draw = ImageDraw.Draw(img)
                for fr in rects_frac:
                    if not (isinstance(fr, (list, tuple)) and len(fr) == 4):
                        continue
                    try:
                        x0 = max(0, min(w_img, round(float(fr[0]) * w_img)))
                        y0 = max(0, min(h_img, round(float(fr[1]) * h_img)))
                        x1 = max(0, min(w_img, round(float(fr[2]) * w_img)))
                        y1 = max(0, min(h_img, round(float(fr[3]) * h_img)))
                    except (TypeError, ValueError, OverflowError):
                        continue  # inf/NaN/garbage fraction -> skip this box, not the op
                    if x1 > x0 and y1 > y0:
                        draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))
                        drawn += 1
            if drawn:
                report["boxes"] += drawn
                report["redacted_pages"] += 1
            # Flat redacted image, JPEG (quality 85) not PNG — see `redact_scanned_pdf`'s
            # rebuild note: PNG barely compresses a photographic scan (~896 MB for 10
            # pages). The burn painted the accepted rects SOLID BLACK before this encode,
            # so lossy JPEG cannot resurrect content under a box (black pixels in ->
            # black out). `img` is RGB; the JPEG stream carries no metadata (the PDF
            # around it is not byte-reproducible — see `redact_scanned_pdf`'s note).
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=85)
            # Page aspect follows the corrected raster (upright output for a 90/270
            # rotation) — same rule as redact_scanned_pdf.
            w_pt, h_pt = _page_dims_for_geo(rect, page_geo)
            newp = out.new_page(width=w_pt, height=h_pt)
            newp.insert_image(newp.rect, stream=buf.getvalue())
        data = out.tobytes()
        out.close()
        return data, report
    finally:
        src.close()
