"""
Phase 2 — on-page VISUAL PDF preview for the redaction reviewer (DISPLAY-ONLY).

After a format-preserving `pdf_scan`, this module renders the pages that carry a
finding and locates each detected value's box ON the page, so a lawyer reviews the
findings *in situ* instead of as a flat list. It never changes how bytes are removed
— it imports nothing from the removal path and burns nothing. The reviewer's accept /
reject still drives `pdf_apply`; this is purely a richer way to LOOK at the findings.

## How a box is located (value-based, not byte-offset)

`pdf_scan` reports each candidate with a 1-based `page` and a cleartext `value`. We do
NOT try to translate the engine's byte offsets into page glyph coordinates (the
subset/Type0 font-encoding problem). Instead, per finding-page, PyMuPDF
`page.search_for(value)` returns the on-page rectangle(s) in PDF points; we convert
each to PAGE-FRACTION coords `(x/page_w, y/page_h, w/page_w, h/page_h)` so the browser
can overlay them as `%` boxes that scale with whatever size the image renders at.

## Subset / Type0 fallback (the `unmapped_fonts` class)

`search_for` works off the page's text layer; on a page whose font encoding could not
be mapped (the `unmapped_fonts` class), a value the scan flagged may not be findable
that way. For those values we OCR the rendered page (REUSING `ocr.ocr_words`) and look
the value up among the OCR words. If it STILL cannot be pinpointed we return a
box-LESS, honest marker (`located: false`) — "found on page N but couldn't pinpoint;
review manually" — rather than silently dropping the finding.

## Bounded + confidentiality

- Page-VIRTUALIZED: only pages that carry a finding are rendered, and at most
  `MAX_PREVIEW_PAGES` of them (an honest `note` reports any overflow — never a silent
  truncation).
- Capped DPI (`PREVIEW_DPI`) + the same megapixel clamp as `imageredact` bound the
  raster against a hostile giant MediaBox.
- The rendered rasters are MATTER CONTENT. They live only in memory / a temp dir that
  is cleaned up (even on exception). The response carries the PNG inline as a `data:`
  URI (so no new fetch surface is added and the redaction page's strict air-gap assert
  keeps holding; page-virtualization keeps the inline payload bounded). NO cleartext is
  logged.

## Graceful

If PyMuPDF is unavailable or rendering fails, `build_preview` returns
`{"preview": False, "reason": ...}` so the route/UI fall back to the existing flat
list — never a crash, never a 500.
"""

import base64

# Reuse imageredact's bounds: same megapixel clamp protects the preview raster, and a
# sane page-count cap keeps the inline data-URI payload bounded.
from .imageredact import MAX_PAGE_MEGAPIXELS, MAX_PAGES

# Cap the number of finding-pages we render into one preview response. A reviewer never
# needs hundreds of inline page images at once; over the cap we report the overflow
# honestly (never silently drop pages).
MAX_PREVIEW_PAGES = 50
# Preview render DPI — capped (~144) so the inline PNG stays small; the box overlays are
# resolution-independent fractions, so display fidelity does not depend on the DPI.
PREVIEW_DPI = 144

# CUMULATIVE render budget across the WHOLE response — closes a soft-DoS the per-page
# clamps leave open. The per-page megapixel clamp (~50 Mpix) + the page cap (50) still let
# a crafted ~17 KB 50-page giant-MediaBox PDF cost ~52 s + ~11 MB of inline JSON, because
# each clamped page is independently expensive. These two budgets bound the SUM, so total
# render time AND payload size are bounded regardless of page count.
#
# Sizing (so a realistic doc is UNAFFECTED — only pathological docs hit a budget):
#   - A dense A4 page at 144 DPI is ~1191x1684 px ~= 2.0 Mpix; a realistic A4x50 doc the
#     reviewer measured renders ~100 Mpix / ~1.2 MB inline in ~2.2 s. The megapixel ceiling
#     sits ABOVE that (150 Mpix) so the realistic worst case never trips it; a giant-MediaBox
#     page clamps to ~50 Mpix each, so the budget is hit after ~3 such pages — exactly the
#     pathological case. The inline-bytes ceiling (8 MB) likewise sits above the realistic
#     1.2 MB but below the ~11 MB pathological payload.
# Whichever budget trips first STOPS rendering further finding-pages; the overflow is
# reported through the EXISTING `capped` + `note` mechanism (never a silent truncation).
MAX_TOTAL_PREVIEW_MEGAPIXELS = 150.0
MAX_TOTAL_PREVIEW_PNG_BYTES = 8 * 1024 * 1024


def finding_pages(candidates):
    """Return the SORTED, de-duplicated 0-BASED page indices that carry >=1 finding.

    `pdf_scan` candidates report a 1-based `page`; we convert to 0-based (the index
    PyMuPDF/`pypdfium2` use). A candidate with a missing / non-positive / non-int page
    is skipped (it can't be placed on a page). Pure + bounds-safe — unit-testable
    without any PDF library."""
    pages = set()
    for c in candidates or []:
        p = (c or {}).get("page") if isinstance(c, dict) else None
        if isinstance(p, bool) or not isinstance(p, int):
            continue
        if p >= 1:
            pages.add(p - 1)
    return sorted(pages)


def candidates_on_page(candidates, page0):
    """Return the candidates whose 1-based `page` maps to the 0-based `page0`, paired
    with their ORIGINAL index in `candidates` (so the UI can cross-reference the
    findings list). Pure."""
    out = []
    for idx, c in enumerate(candidates or []):
        if not isinstance(c, dict):
            continue
        p = c.get("page")
        if isinstance(p, bool) or not isinstance(p, int):
            continue
        if p - 1 == page0:
            out.append((idx, c))
    return out


def rect_to_fraction(rect, page_w, page_h):
    """Convert an absolute page rectangle `(x0, y0, x1, y1)` (PDF points, top-left
    origin as PyMuPDF reports) to a `(x, y, w, h)` PAGE-FRACTION box, clamped to
    [0, 1]. Returns None for a degenerate page or a zero-area rect. Pure +
    overflow-safe."""
    try:
        x0, y0, x1, y1 = (float(rect[0]), float(rect[1]), float(rect[2]), float(rect[3]))
        pw, ph = float(page_w), float(page_h)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if not (pw > 0 and ph > 0):
        return None
    # Normalize a possibly-flipped rect (x1<x0 / y1<y0) so w/h are non-negative.
    lo_x, hi_x = (x0, x1) if x1 >= x0 else (x1, x0)
    lo_y, hi_y = (y0, y1) if y1 >= y0 else (y1, y0)
    fx = max(0.0, min(1.0, lo_x / pw))
    fy = max(0.0, min(1.0, lo_y / ph))
    fw = max(0.0, min(1.0 - fx, (hi_x - lo_x) / pw))
    fh = max(0.0, min(1.0 - fy, (hi_y - lo_y) / ph))
    if fw <= 0 or fh <= 0:
        return None
    return (fx, fy, fw, fh)


def ocr_word_boxes_for_value(value, words, img_w, img_h):
    """Locate `value` among OCR `words` (pixel boxes, the `ocr.OcrWord` shape) and
    return matching PAGE-FRACTION boxes `[(x, y, w, h)]`, or [] if not found.

    Matches the value's whitespace-separated tokens against consecutive OCR words
    (case-insensitive), covering the WHOLE word box of each matched token (over-cover,
    never sub-word — the same leak rule as `imageredact`). A single-token value matches
    any one word equal to it; a multi-token value matches a consecutive run. Pure (the
    word list + image size are injected), so this is unit-testable without Tesseract."""
    val = str(value or "").strip()
    if not val or img_w <= 0 or img_h <= 0:
        return []
    tokens = [t for t in val.split() if t]
    if not tokens:
        return []
    norm = [t.lower() for t in tokens]
    n = len(norm)
    ws = list(words or [])
    out = []
    seen = set()
    for i in range(0, max(0, len(ws) - n + 1)):
        window = ws[i:i + n]
        if [str(w.text).strip().lower() for w in window] != norm:
            continue
        for w in window:
            try:
                x, y, ww, hh = float(w.x), float(w.y), float(w.w), float(w.h)
            except (TypeError, ValueError):
                continue
            if ww <= 0 or hh <= 0:
                continue
            fr = rect_to_fraction((x, y, x + ww, y + hh), img_w, img_h)
            if fr and fr not in seen:
                seen.add(fr)
                out.append(fr)
    return out


def _box(fr, idx, c, located):
    """Assemble one overlay-box dict from a fraction-rect + its source candidate. The
    `recognizer` is a CONFIG label (never matter data); `value_ref` is the candidate's
    original list index (NOT the cleartext value — the UI already holds the value in the
    findings list, so we needn't duplicate matter text into the boxes payload)."""
    return {
        "x": fr[0], "y": fr[1], "w": fr[2], "h": fr[3],
        "recognizer": str((c or {}).get("recognizer", "")),
        "value_ref": idx,
        "id": (c or {}).get("id"),
        "tier": str((c or {}).get("tier", "")),
        "located": bool(located),
    }


def _unlocated_box(idx, c):
    """A box-LESS, honest marker for a finding the page-search + OCR could not pinpoint
    (the `unmapped_fonts` residual). `located: false` tells the UI to show an inline
    'review manually' note instead of an overlay rectangle."""
    return {
        "x": None, "y": None, "w": None, "h": None,
        "recognizer": str((c or {}).get("recognizer", "")),
        "value_ref": idx,
        "id": (c or {}).get("id"),
        "tier": str((c or {}).get("tier", "")),
        "located": False,
    }


def build_preview(pdf_bytes, candidates, unmapped_fonts=False,
                  ocr_fn=None, dpi=PREVIEW_DPI, max_pages=MAX_PREVIEW_PAGES):
    """Render the finding-pages of `pdf_bytes` and locate each candidate's box.

    Returns a dict:
        {"preview": True,
         "pages": [{"index": 0based, "png": "data:image/png;base64,...",
                    "width": px, "height": px,
                    "boxes": [{x,y,w,h, recognizer, value_ref, id, tier, located}]}],
         "capped": bool, "note": str|None}
    or, when PyMuPDF is missing / rendering fails / there is nothing to show, a
    graceful `{"preview": False, "reason": ...}` (NEVER raises out to the route).

    - Only pages with a finding are rendered, capped at `max_pages` (overflow reported
      in `note`, never silently dropped).
    - Per page: `search_for(value)` -> fraction boxes. A value not found by text search
      on an `unmapped_fonts` page is retried via OCR (`ocr_fn`, default `ocr.ocr_words`,
      injectable for tests). Still-unlocatable -> a box-less `located: false` marker.
    - The rendered rasters are matter content held only in memory; nothing is persisted
      and no cleartext is logged.
    """
    cands = candidates or []
    pages0 = finding_pages(cands)
    if not pages0:
        return {"preview": False, "reason": "no findings to preview on the page"}

    try:
        import fitz  # PyMuPDF (AGPL-3.0 / Artifex commercial)
    except Exception:  # noqa: BLE001 - no renderer -> graceful fall back to the list
        return {"preview": False, "reason": "the PDF preview renderer is not available"}

    if ocr_fn is None:
        try:
            from .ocr import ocr_words as _ow
            ocr_fn = _ow
        except Exception:  # noqa: BLE001
            ocr_fn = None

    # `capped` flips True if EITHER the page-count cap OR the cumulative render budget
    # (megapixels / inline PNG bytes) stops us short of all finding-pages.
    capped = len(pages0) > max_pages
    budget_hit = False
    render_pages = pages0[:max_pages]

    try:
        src = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:  # noqa: BLE001 - a bad PDF degrades to the list, never a crash
        return {"preview": False, "reason": "could not open the PDF for preview"}

    out_pages = []
    total_megapixels = 0.0
    total_png_bytes = 0
    try:
        if getattr(src, "needs_pass", False):  # encrypted: opens but reads raise later
            return {"preview": False, "reason": "the PDF is encrypted; preview unavailable"}
        if src.page_count == 0:
            return {"preview": False, "reason": "the PDF has no pages"}
        if src.page_count > MAX_PAGES:
            return {"preview": False, "reason": "the PDF has too many pages to preview"}
        for page0 in render_pages:
            if page0 < 0 or page0 >= src.page_count:
                continue
            built = _build_page(src[page0], page0, cands, unmapped_fonts, ocr_fn, dpi, fitz)
            if built is None:
                continue
            page_dict, png_len = built
            # Accumulate this page's cost, then check the CUMULATIVE budget. We add the
            # already-rendered page first (it is in hand) but STOP before rendering any
            # further finding-page once a budget is exceeded, so the response stays bounded
            # in both total render work and inline payload size against a pathological doc.
            total_megapixels += (page_dict["width"] * page_dict["height"]) / 1_000_000.0
            total_png_bytes += png_len
            out_pages.append(page_dict)
            if (total_megapixels >= MAX_TOTAL_PREVIEW_MEGAPIXELS
                    or total_png_bytes >= MAX_TOTAL_PREVIEW_PNG_BYTES):
                budget_hit = True
                break
    except Exception:  # noqa: BLE001 - any render failure -> graceful, never a 500
        return {"preview": False, "reason": "could not render the PDF preview"}
    finally:
        try:
            src.close()
        except Exception:  # noqa: BLE001
            pass

    if not out_pages:
        return {"preview": False, "reason": "could not render any preview page"}

    capped = capped or budget_hit
    note = None
    if capped:
        # Honest overflow: how many finding-pages were NOT previewed, and WHY. A budget cut
        # can stop before even the page-count cap, so count against the full finding set.
        shown = len(out_pages)
        extra = max(0, len(pages0) - shown)
        why = ("preview size limit" if budget_hit
               else "page limit")
        note = (f"{extra} more page{'s' if extra != 1 else ''} with findings "
                f"not previewed ({why}). Use the findings list for the rest.")
    return {"preview": True, "pages": out_pages, "capped": capped, "note": note}


def _bounded_preview_pixmap(page, dpi, fitz):
    """Render `page` to a pixmap at `dpi`, reducing the scale if the raster would exceed
    `MAX_PAGE_MEGAPIXELS` (the same clamp `imageredact._bounded_pixmap` uses) so a
    hostile giant MediaBox can't trigger a multi-GB allocation. Returns the pixmap; the
    EFFECTIVE scale used is `pix.width / page_width_points` (the caller needs it only to
    confirm the fraction overlays are scale-free — boxes are page-fractions regardless)."""
    import math
    scale = dpi / 72.0
    w = abs(page.rect.width) * scale
    h = abs(page.rect.height) * scale
    mp = (w * h) / 1_000_000.0
    if mp > MAX_PAGE_MEGAPIXELS:
        scale *= math.sqrt(MAX_PAGE_MEGAPIXELS / mp)
    return page.get_pixmap(matrix=fitz.Matrix(scale, scale))


def _build_page(page, page0, cands, unmapped_fonts, ocr_fn, dpi, fitz):
    """Render ONE finding-page + locate its candidates' boxes. Returns
    `(page_dict, png_byte_len)` (the caller accumulates the inline-payload size against the
    cumulative budget) or None on a per-page failure (the caller skips it)."""
    page_w = abs(float(page.rect.width))
    page_h = abs(float(page.rect.height))
    if not (page_w > 0 and page_h > 0):
        return None

    pix = _bounded_preview_pixmap(page, dpi, fitz)
    png = pix.tobytes("png")
    data_uri = "data:image/png;base64," + base64.b64encode(png).decode("ascii")

    on_page = candidates_on_page(cands, page0)
    boxes = []
    # Lazily computed (only when a text-search miss needs the OCR fallback) so we never
    # pay OCR cost on a page where text search already located everything.
    ocr_words_cache = None
    ocr_attempted = False

    for idx, c in on_page:
        value = c.get("value", "")
        located = _search_boxes(page, value, page_w, page_h)
        if located:
            for fr in located:
                boxes.append(_box(fr, idx, c, True))
            continue
        # Text search found nothing for this value. On an unmapped-font page, retry via
        # OCR of the rendered raster (reuse ocr.ocr_words: pixel boxes). Only attempt
        # OCR once per page (it is the slow step).
        if unmapped_fonts and ocr_fn is not None:
            if not ocr_attempted:
                ocr_words_cache = _ocr_page(pix, ocr_fn)
                ocr_attempted = True
            ocr_boxes = ocr_word_boxes_for_value(value, ocr_words_cache or [],
                                                  pix.width, pix.height)
            if ocr_boxes:
                for fr in ocr_boxes:
                    boxes.append(_box(fr, idx, c, True))
                continue
        # Still unlocatable -> an HONEST box-less marker (never drop the finding).
        boxes.append(_unlocated_box(idx, c))

    return ({
        "index": page0,
        "png": data_uri,
        "width": int(pix.width),
        "height": int(pix.height),
        "boxes": boxes,
    }, len(png))


def _search_boxes(page, value, page_w, page_h):
    """`page.search_for(value)` -> fraction boxes, never raising. A blank value or a
    search error yields []."""
    val = str(value or "").strip()
    if not val:
        return []
    try:
        rects = page.search_for(val)
    except Exception:  # noqa: BLE001 - a search failure is a miss, not a crash
        return []
    out = []
    seen = set()
    for r in rects or []:
        try:
            fr = rect_to_fraction((r.x0, r.y0, r.x1, r.y1), page_w, page_h)
        except Exception:  # noqa: BLE001
            fr = None
        if fr and fr not in seen:
            seen.add(fr)
            out.append(fr)
    return out


def _ocr_page(pix, ocr_fn):
    """OCR a rendered page pixmap to `[ocr.OcrWord]` (pixel boxes) via `ocr_fn`, which
    takes an image-file path. Writes a temp PNG (matter content), OCRs it, removes it.
    Returns the word list (or []). Never raises.

    The temp PNG goes UNDER the app-data temp dir (`paths.temp_dir`), not the system
    temp dir, so a hard kill between the write and the `finally` remove leaves no matter
    raster in system temp — a survivor is swept on the next startup (see `paths.temp_dir`)."""
    import os
    import tempfile

    from .paths import temp_dir
    fd, path = tempfile.mkstemp(suffix=".png", prefix="ldm-pdfpreview-", dir=str(temp_dir()))
    os.close(fd)
    try:
        with open(path, "wb") as fh:
            fh.write(pix.tobytes("png"))
        return ocr_fn(path) or []
    except Exception:  # noqa: BLE001 - OCR is best-effort; a failure -> no OCR boxes
        return []
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
