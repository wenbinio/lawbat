"""
Text extraction, one function per format. Each returns a list of
(locator, text) tuples so search hits can point at a page / slide / sheet.

Deterministic, no model calls. If a file can't be read, the caller records
the error rather than guessing at contents.
"""

import os
from contextlib import closing
from pathlib import Path
from email import policy
from email.parser import BytesParser

from .classify import IMAGE_EXTS


def _env_int(name: str, default: int) -> int:
    """An int env override (`LAWDATAMAN_<NAME>`); garbage/non-positive -> default.
    Mirrors scan_guard._env_int (house style) so a typo can't disable the cap."""
    raw = os.environ.get("LAWDATAMAN_" + name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return v if v > 0 else default


# Per-format EXPANDED-text ceiling. A small, crafted office file (a ZIP/billion-laughs
# bomb: thousands of paragraphs, a huge sheet, deeply-nested XML) can expand to GiBs of
# text and OOM the indexer even though the file ON DISK is tiny. Each office extractor
# accumulates at most this many UTF-8 bytes of text, then STOPS and appends a truncation
# marker (`_TRUNCATED_LOCATOR`) so the bounded text is still indexed/searchable and the
# truncation is honestly visible. Generous for any genuine document.
MAX_EXTRACT_BYTES = _env_int("MAX_EXTRACT_BYTES", 64 * 1024 * 1024)   # 64 MiB of text
# A coarse element ceiling so a bomb with millions of TINY elements (each well under the
# byte budget individually) still terminates promptly rather than iterating forever.
MAX_EXTRACT_ELEMENTS = _env_int("MAX_EXTRACT_ELEMENTS", 5_000_000)
# The locator stamped on the trailing marker unit when extraction was bounded. `extract()`
# detects it to report a 'truncated' status (still counts as indexed — the text we DID get
# is real); the body explains the cap to a reviewer.
_TRUNCATED_LOCATOR = "truncated"


class _ByteBudget:
    """A running UTF-8 byte + element budget for a bounded extractor. `add(text)` returns
    True while there is room and the element ceiling is not hit; once exceeded it returns
    False so the caller stops accumulating. Deterministic, never raises."""

    __slots__ = ("_left", "_elems", "hit")

    def __init__(self, max_bytes: int = MAX_EXTRACT_BYTES,
                 max_elems: int = MAX_EXTRACT_ELEMENTS):
        self._left = max_bytes
        self._elems = max_elems
        self.hit = False

    def add(self, text: str) -> bool:
        if self._left <= 0 or self._elems <= 0:
            self.hit = True
            return False
        self._elems -= 1
        try:
            self._left -= len(text.encode("utf-8"))
        except (UnicodeError, AttributeError):
            self._left -= len(str(text))
        if self._left <= 0 or self._elems <= 0:
            self.hit = True
        return True

    @property
    def remaining(self) -> int:
        """UTF-8 bytes of headroom left (never negative). Lets a caller CLIP a single
        oversized element to the budget instead of admitting it whole."""
        return max(0, self._left)


def _clip_to_budget(text: str, max_bytes: int) -> str:
    """Slice `text` to at most `max_bytes` UTF-8 bytes on a code-point boundary
    (decode-safe). Bounds a SINGLE giant element (e.g. one PDF page whose text layer
    expands to GiBs) so it can't blow the budget in one add()."""
    if max_bytes <= 0:
        return ""
    enc = text.encode("utf-8")
    if len(enc) <= max_bytes:
        return text
    return enc[:max_bytes].decode("utf-8", "ignore")


# --- Pluggable backends for the two copyleft formats -------------------------
# PDF text extraction defaults to PyMuPDF (AGPL); .msg defaults to extract-msg
# (GPL). Both are dispatched through a registry so a PERMISSIVE backend (e.g.
# pypdf/pdfminer.six, or an olefile-based .msg parser) can be registered and
# selected via an env var to ship a copyleft-free build — without the indexer or
# anything else changing. Default behaviour is unchanged.
_PDF_BACKENDS = {}
_MSG_BACKENDS = {}


def register_pdf_backend(name):
    def deco(fn):
        _PDF_BACKENDS[name] = fn
        return fn
    return deco


def register_msg_backend(name):
    def deco(fn):
        _MSG_BACKENDS[name] = fn
        return fn
    return deco


def _select(backends, env_var, default):
    name = os.environ.get(env_var, default)
    return backends.get(name) or backends[default]


@register_pdf_backend("pymupdf")
def _pdf_pymupdf(path: Path):
    import fitz  # pymupdf (AGPL-3.0 / Artifex commercial)
    units = []
    # Bound the ACCUMULATED text exactly like the office extractors: a flate-compressed
    # PDF text-bomb (a tiny file whose content streams expand to GiBs across many pages /
    # operators) would otherwise OOM the indexer. Each page is clipped to the remaining
    # budget; once the cap is hit we stop and append a truncation marker. (A single page's
    # get_text allocation is still bounded only by PyMuPDF itself — the cap protects the
    # cumulative units list, the realistic multi-page/operator bomb.)
    budget = _ByteBudget()
    with fitz.open(path) as doc:
        for i, page in enumerate(doc, start=1):
            if budget.hit:
                break
            txt = page.get_text("text").strip()
            if not txt:
                continue
            txt = _clip_to_budget(txt, budget.remaining)
            if not txt:
                budget.hit = True   # remaining budget too small for this page's first char — still truncation
                break
            budget.add(txt)
            units.append((f"p.{i}", txt))
    if budget.hit:
        units.append(_truncation_marker("pdf"))
    # A PDF that yields no text at all is almost certainly scanned -> the caller
    # flags it so the reviewer knows OCR is needed (see app/ocr.py + pymupdf_ocr backend).
    return units


@register_pdf_backend("pymupdf_ocr")
def _pdf_pymupdf_ocr(path: Path):
    """Per-PAGE hybrid extraction: a born-digital page uses its TEXT LAYER; a page with
    NO text layer (scanned) is OCR'd. NEVER OCRs a page that already has text (CLAUDE.md:
    never OCR born-digital files), so a MIXED PDF — a born-digital brief with scanned
    exhibit / signature pages, the common real case — keeps the scanned pages instead of
    silently dropping them (the old document-level fallback only OCR'd a PDF with NO text
    on ANY page).

    Opt-in via LAWDATAMAN_PDF_BACKEND=pymupdf_ocr. OCR fires only if a tesseract binary
    is available; otherwise the text-less pages are simply absent (a document with little/
    no resulting text is still flagged needs-OCR by classify, exactly as before)."""
    import fitz  # pymupdf (AGPL-3.0 / Artifex commercial)

    units = []   # (page_index_0based, locator, text)
    scanned = []  # 0-based indices of pages with no text layer
    budget = _ByteBudget()   # bound accumulated text (text-layer + OCR) — see _pdf_pymupdf
    with fitz.open(path) as doc:
        for i, page in enumerate(doc):  # 0-based
            if budget.hit:
                break
            txt = page.get_text("text").strip()
            if txt:
                txt = _clip_to_budget(txt, budget.remaining)
                if not txt:
                    budget.hit = True   # remaining too small for this page's first char — still truncation
                    break
                budget.add(txt)
                units.append((i, f"p.{i + 1}", txt))
            else:
                scanned.append(i)

    # OCR ONLY the text-less (scanned) pages — born-digital pages keep their exact text
    # layer and are never rasterized/OCR'd. Skip OCR entirely if the budget is already spent.
    if scanned and not budget.hit:
        from . import ocr
        if ocr.available():
            ocr_text = ocr.ocr_pdf_pages(path, scanned)
            for i in scanned:
                if budget.hit:
                    break
                t = (ocr_text.get(i) or "").strip()
                if not t:
                    continue
                t = _clip_to_budget(t, budget.remaining)
                if not t:
                    budget.hit = True   # remaining too small for this OCR block's first char — still truncation
                    break
                budget.add(t)
                units.append((i, f"p.{i + 1} (ocr)", t))

    units.sort(key=lambda u: u[0])  # merge text-layer + OCR'd pages in page order
    out = [(loc, txt) for _, loc, txt in units]
    if budget.hit:
        out.append(_truncation_marker("pdf"))   # marker sorts last (appended post-sort)
    return out


def extract_pdf(path: Path):
    """Dispatch to the selected PDF backend (default: pymupdf)."""
    return _select(_PDF_BACKENDS, "LAWDATAMAN_PDF_BACKEND", "pymupdf")(path)


def extract_docx(path: Path):
    import docx
    d = docx.Document(str(path))
    budget = _ByteBudget()
    parts = []
    for p in d.paragraphs:
        if p.text.strip():
            if not budget.add(p.text):
                break
            parts.append(p.text)
    if not budget.hit:
        for tbl in d.tables:
            if budget.hit:
                break
            for row in tbl.rows:
                cells = [c.text.strip() for c in row.cells if c.text.strip()]
                if cells:
                    joined = " | ".join(cells)
                    if not budget.add(joined):
                        break
                    parts.append(joined)
    body = "\n".join(parts).strip()
    units = [("document", body)] if body else []
    if budget.hit:
        units.append(_truncation_marker("docx"))
    return units


def extract_xlsx(path: Path):
    import openpyxl
    # read_only=True keeps an open file handle; close it even if iteration raises
    # mid-workbook (a malformed sheet) so the handle never leaks.
    wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
    budget = _ByteBudget()
    try:
        units = []
        for ws in wb.worksheets:
            if budget.hit:
                break
            rows = []
            for row in ws.iter_rows(values_only=True):
                vals = [str(v) for v in row if v is not None and str(v).strip()]
                if vals:
                    joined = " | ".join(vals)
                    if not budget.add(joined):
                        break
                    rows.append(joined)
            if rows:
                units.append((f"sheet: {ws.title}", "\n".join(rows)))
        if budget.hit:
            units.append(_truncation_marker("xlsx"))
        return units
    finally:
        wb.close()


def extract_pptx(path: Path):
    from pptx import Presentation
    prs = Presentation(str(path))
    budget = _ByteBudget()
    units = []
    for i, slide in enumerate(prs.slides, start=1):
        if budget.hit:
            break
        chunks = []
        for shape in slide.shapes:
            if shape.has_text_frame:
                t = shape.text_frame.text.strip()
                if t:
                    if not budget.add(t):
                        break
                    chunks.append(t)
        if chunks:
            units.append((f"slide {i}", "\n".join(chunks)))
    if budget.hit:
        units.append(_truncation_marker("pptx"))
    return units


def _truncation_marker(fmt: str):
    """The trailing unit appended when an extractor hit its expanded-size budget. Carries
    the `_TRUNCATED_LOCATOR` so `extract()` reports a 'truncated' status; the body is a
    fixed, non-identifying note (no matter content)."""
    return (_TRUNCATED_LOCATOR,
            f"[extraction stopped: this {fmt} expanded past the "
            f"{MAX_EXTRACT_BYTES}-byte text limit; the text above is complete up to that "
            "point. A document this large is unusual — re-export or split it if the rest "
            "matters.]")


def extract_txt(path: Path):
    txt = _decode_text_bytes(path.read_bytes()).strip()
    return [("text", txt)] if txt else []


def _decode_text_bytes(raw: bytes) -> str:
    """Decode a plain-text MATTER file (.txt/.md) to str WITHOUT touching the
    platform locale codec.

    `Path.read_text()` with no `encoding=` decodes via the locale codec — cp1252
    on Windows — which would silently MANGLE a UTF-8 matter file's multi-byte
    characters (an em-dash, a smart-quote, an accented name). That corrupted text
    then feeds SEARCH and REDACTION, so it must be decoded deterministically:
    - try UTF-8 (the modern default + what most exported text files actually are);
    - then try cp1252 (Windows-1252) STRICTLY: it is the codec Word/Office write
      "legacy" text in, so its smart-quote / em-dash / accented bytes (0x80-0x9F)
      decode to the INTENDED punctuation instead of C1 control chars. A blind latin-1
      fallback silently MANGLES exactly those bytes, and that mangled text then feeds
      SEARCH and REDACTION. cp1252 is strict (a handful of bytes are undefined), so it
      can still raise -> we fall through to the floor;
    - finally fall back to latin-1, which maps every byte 1:1 and NEVER raises, so any
      remaining legacy file neither crashes nor drops content.
    ASCII (a strict UTF-8 subset) is preserved byte-for-byte by the UTF-8 path; cp1252
    and latin-1 both agree with ASCII on 0x00-0x7F, so an ASCII-only file decodes
    identically regardless of which rung wins.

    EXTRACTION-ADJACENT: changing this changes what the redaction engine sees.
    """
    # utf-8 (strict) -> cp1252 (strict; recovers Word punctuation) -> latin-1 (total
    # floor, never raises). Widest-fidelity first; each strict rung either decodes or
    # raises UnicodeDecodeError and we try the next.
    for codec in ("utf-8", "cp1252"):
        try:
            return raw.decode(codec)
        except UnicodeDecodeError:
            continue
    # latin-1 is total (no byte is undefined) -> never raises, loses nothing.
    return raw.decode("latin-1")


def extract_eml(path: Path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    header = " | ".join(
        f"{k}: {msg[k]}"
        for k in ("From", "Reply-To", "To", "Cc", "Bcc", "Date", "Subject")
        if msg[k]
    )
    if msg.is_multipart():
        parts = [part.get_content() for part in msg.walk()
                 if part.get_content_type() == "text/plain"]
        body = "\n".join(parts)   # keep parts separated, not run together
    else:
        body = msg.get_content() if msg.get_content_type() == "text/plain" else ""
    full = (header + "\n\n" + (body or "")).strip()
    return [("email", full)] if full else []


@register_msg_backend("extract_msg")
def _msg_extract_msg(path: Path):
    import extract_msg  # GPL
    # closing() releases the underlying OLE/CFB file handle even if reading a
    # property (sender/body/…) raises mid-extraction, so the handle never leaks.
    with closing(extract_msg.Message(str(path))) as m:
        header = " | ".join(
            x for x in (
                f"From: {m.sender}" if m.sender else "",
                f"To: {m.to}" if m.to else "",
                f"Cc: {m.cc}" if m.cc else "",
                f"Bcc: {m.bcc}" if m.bcc else "",
                f"Date: {m.date}" if m.date else "",
                f"Subject: {m.subject}" if m.subject else "",
            ) if x
        )
        full = (header + "\n\n" + (m.body or "")).strip()
    return [("email", full)] if full else []


def extract_msg(path: Path):
    """Dispatch to the selected .msg backend (default: extract_msg, GPL)."""
    return _select(_MSG_BACKENDS, "LAWDATAMAN_MSG_BACKEND", "extract_msg")(path)


EXTRACTORS = {
    ".pdf": extract_pdf,
    ".docx": extract_docx,
    ".xlsx": extract_xlsx,
    ".xlsm": extract_xlsx,
    ".pptx": extract_pptx,
    ".txt": extract_txt,
    ".md": extract_txt,
    ".eml": extract_eml,
    ".msg": extract_msg,
}


def _extract_image_ocr(path: Path):
    from .ocr import ocr_image
    return ocr_image(path)


def extract(path: Path):
    """Return (status, units, error). status in ok|empty|unsupported|error."""
    suffix = path.suffix.lower()
    fn = EXTRACTORS.get(suffix)
    if fn is None:
        # Tier-2 opt-in: OCR image files, only when explicitly enabled AND a
        # tesseract binary is present. Default stays 'unsupported' so images keep
        # their "image — no text (OCR needed)" manifest classification.
        if suffix in IMAGE_EXTS and os.environ.get("LAWDATAMAN_OCR_IMAGES") == "1":
            from .ocr import available
            if available():
                fn = _extract_image_ocr
        if fn is None:
            return "unsupported", [], None
    try:
        units = fn(path)
        if not units:
            return "empty", [], None
        # A bounded extractor appends a marker unit (see `_truncation_marker`) when it hit
        # the expanded-size cap (#7). Surface 'truncated' so the manifest/UI is honest; the
        # text we DID extract is real and still indexed (index.py counts truncated as
        # indexed). 'ok' otherwise.
        if any(loc == _TRUNCATED_LOCATOR for loc, _ in units):
            return "truncated", units, None
        return "ok", units, None
    except Exception as e:  # noqa: BLE001 - we record, never crash the run
        return "error", [], f"{type(e).__name__}: {e}"
