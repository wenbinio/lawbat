"""
Tesseract OCR entry point — CPU only, deterministic. OFF unless a `tesseract`
binary is found (see vendor.bundled_tool). NO GPU / no deep-learning OCR (those
are models, need weights, and need a GPU the target machines lack).

This is the Tier-2 path that makes scanned PDFs / images searchable; the document
manifest's "needs OCR" rows are the worklist. Rasterization for OCR prefers
pypdfium2 (permissive) and falls back to PyMuPDF; if neither is importable,
ocr_pdf returns [] (graceful no-op).

## OCR-quality pipeline (all stages deterministic + FAIL-OPEN)

Every stage degrades to today's plain-OCR behaviour on any error — a broken
preprocessing step must never make OCR WORSE than not preprocessing at all:

1. GEOMETRY (`prepare_page_image`, applied by the caller that owns the raster —
   app/imageredact.py for redaction, this module's own PDF path for indexing):
   tesseract OSD (`--psm 0`) detects 90/180/270 rotation (a rotated scan OCRs to
   garbage -> recognizers blind -> a silent redaction MISS), rotated losslessly via
   PIL transpose; then a small-angle projection-profile deskew (±3°). Geometry is
   the CALLER's job because word boxes come back in the corrected image's pixel
   space — the burn raster must be the same image (see imageredact).
2. PIXELS (`preprocess_for_ocr`, internal to `ocr_words`): grayscale ->
   bounded autocontrast -> pure-python Otsu threshold -> 3px median despeckle.
   Feeds tesseract ONLY; never the output page (the redacted page must look like
   the scan, not a binarized copy). Boxes map 1:1 (no geometry change here).
3. CONFIDENCE (honesty spine): the TSV `conf` column is kept per word;
   `page_confidence` = mean word confidence. Below `LOW_CONF_THRESHOLD` the page
   is flagged "scanned poorly" — the text is STILL indexed/scanned (over-flagging
   is the safe side; a MISS is the leak — never suppress low-confidence text).
4. ADAPTIVE RETRY: a page under the threshold gets exactly ONE retry with
   `--psm 6`; the result with the HIGHER mean confidence wins (tie -> the first,
   default-PSM pass). Bounded: one retry chain per page, ever.

Language packs are opt-in via LAWDATAMAN_OCR_LANGS (see `ocr_langs`): English is
always first; an extra language is passed ONLY if its .traineddata is verifiably
present. Default (no env) is byte-identical to the old hardcoded "eng".
"""

import os
import re
import shutil
import subprocess
import tempfile
from collections import namedtuple
from pathlib import Path

from .vendor import bundled_tool, vendor_dir

#: One OCR'd word with its bounding box in IMAGE-PIXEL coordinates (the same pixel
#: space as the rasterized page the OCR ran on). Used by image-based redaction to map
#: a detected identifier back to the page region to burn out.
#:
#: `line_id` = the word's LINE identity — tesseract's `(block_num, par_num, line_num)`
#: triple — or `None` when unknown (a hand-built word or a malformed TSV row). It lets
#: `imageredact._assemble` reconstruct LINE breaks ('\n') between words on different
#: lines instead of flattening a whole page onto one line; the engine's line-scoped
#: recall + context recognizers (which scan back N lines from a role label) are
#: structurally blind on a one-line page, so line identity restores their recall on
#: OCR'd (scanned) text.
#:
#: `conf` = tesseract's per-word confidence (TSV col 10, 0-100 float) or `None` when
#: unknown (a hand-built word / malformed TSV). Feeds `page_confidence` — the honest
#: "this page scanned poorly" signal. Both extras default to `None` so every existing
#: shorter constructor keeps working.
OcrWord = namedtuple("OcrWord", "text x y w h line_id conf", defaults=(None, None))

# Per-page mean word confidence (TSV conf, 0-100) below which a page is flagged
# "scanned poorly" AND the one-shot PSM-6 retry fires. 60 chosen from the OCR
# harness over the synthetic finance corpus: clean 300-DPI pages score ~90+;
# degraded-but-still-recovered pages ~70-90; pages under ~60 correlated with real
# identifier-recall loss. HONESTY ONLY — low-confidence text is never dropped.
LOW_CONF_THRESHOLD = 60.0
# OSD orientation-confidence floor: below it we do NOT rotate (fail-open = today's
# unrotated behaviour). Real rotated pages measured ~12-17 on the harness corpus;
# blank/garbage pages error out or sit near 0 — 2.0 keeps false rotations off
# legitimate upright pages while catching every real rotation we tested.
OSD_MIN_CONF = 2.0
# Small-angle deskew bounds: sweep ±3° in 0.5° steps on a DOWNSAMPLED binary image;
# apply the best angle only if its projection-profile score beats 0° by the margin
# (so a clean scan is never churned by resampling for a negligible win).
DESKEW_MAX_DEG = 3.0
DESKEW_STEP_DEG = 0.5
DESKEW_MARGIN = 1.12
_DESKEW_DOWNSAMPLE_W = 800  # px; the sweep runs on a small copy (bounded work)


def tesseract_path() -> str | None:
    return bundled_tool("tesseract")


def available() -> bool:
    return tesseract_path() is not None


def tessdata_dir() -> Path | None:
    """Locate the BUNDLED tessdata directory (the dir holding `*.traineddata`). Checks the
    layout the packager stages (`vendor/tesseract/tessdata` — see build/assemble.ps1), the
    legacy `vendor/tessdata`, and a `TESSDATA_PREFIX` override. Returns None if none holds
    language data — then tesseract uses its own (system) tessdata. Never raises."""
    cands = []
    env = os.environ.get("TESSDATA_PREFIX")
    if env:
        cands.append(Path(env))
    vd = vendor_dir()
    cands.append(vd / "tesseract" / "tessdata")  # where the MSI/assemble.ps1 stages it
    cands.append(vd / "tessdata")                 # legacy / alternate layout
    for c in cands:
        try:
            if c.is_dir() and any(c.glob("*.traineddata")):
                return c
        except OSError:
            continue
    return None


# ---- language selection (opt-in packs) ------------------------------------------

# A tesseract language code: short lowercase alnum/underscore (eng, chi_sim, msa,
# tam, ...). Anything else is refused — the env value builds an argv element.
_LANG_TOKEN = re.compile(r"^[a-z][a-z0-9_]{1,15}$")
# Cache of the available-language probe, keyed by (exe, tessdata dir) so a test that
# swaps LAWDATAMAN_VENDOR_DIR/TESSDATA_PREFIX never sees a stale answer.
_langs_cache: dict = {}


def _available_langs() -> set | None:
    """The set of language codes whose .traineddata is actually present, or None if it
    cannot be determined. Bundled tessdata is read from disk; a system install is asked
    via `tesseract --list-langs` (once per (exe, tessdata) pair). Never raises."""
    td = tessdata_dir()
    if td is not None:
        try:
            return {p.stem for p in td.glob("*.traineddata")}
        except OSError:
            return None
    exe = tesseract_path()
    if not exe:
        return None
    key = (exe, None)
    if key in _langs_cache:
        return _langs_cache[key]
    try:
        r = subprocess.run(
            [exe, "--list-langs"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=30, env=_env(),
        )
        langs = {
            ln.strip() for ln in (r.stdout or "").splitlines()
            if _LANG_TOKEN.match(ln.strip())
        }
        out = langs or None
    except Exception:  # noqa: BLE001 - probing must never crash OCR
        out = None
    _langs_cache[key] = out
    return out


def ocr_langs() -> str:
    """The `-l` language argument: always `eng` first, plus any EXTRA languages from
    LAWDATAMAN_OCR_LANGS (comma/plus/space separated, e.g. "chi_sim,msa"). An extra
    language is included ONLY when its .traineddata is verifiably present (tesseract
    hard-errors on an absent lang, which would kill OCR entirely — fail-open to eng).
    With the env unset this returns exactly "eng" (byte-identical to the old default)."""
    raw = os.environ.get("LAWDATAMAN_OCR_LANGS", "")
    if not raw.strip():
        return "eng"
    avail = _available_langs()
    extras = []
    for tok in re.split(r"[,+\s]+", raw.strip().lower()):
        if not tok or tok == "eng" or tok in extras:
            continue
        if not _LANG_TOKEN.match(tok):
            continue  # malformed / injection-shaped token -> refused
        if avail is None or tok not in avail:
            continue  # cannot verify its data exists -> never pass it
        extras.append(tok)
    return "eng" if not extras else "eng+" + "+".join(extras)


def _env() -> dict:
    env = dict(os.environ)
    # Point Tesseract at bundled language data if we ship it (relative to the bundle,
    # never the system) — belt-and-suspenders alongside the explicit --tessdata-dir arg.
    td = tessdata_dir()
    if td is not None:
        env["TESSDATA_PREFIX"] = str(td)
    return env


def _tess_cmd(exe: str, path, lang: str | None, config: str | None = None,
              psm: str | None = None) -> list:
    """Build a tesseract argv. When we ship bundled language data, point at it via
    `--tessdata-dir` (unambiguous across tesseract 4/5, unlike the TESSDATA_PREFIX
    parent-vs-self drift); otherwise let tesseract find its own. `lang=None` omits `-l`
    (OSD mode needs no language). A `config` (e.g. `tsv`) is a CONFIGFILE and MUST come
    last (`tesseract IMG OUT [options] [configfile]`)."""
    cmd = [exe, str(path), "stdout"]
    td = tessdata_dir()
    if td is not None:
        cmd += ["--tessdata-dir", str(td)]
    if lang is not None:
        cmd += ["-l", lang]
    if psm is not None:
        cmd += ["--psm", psm]
    if config:
        cmd.append(config)
    return cmd


# ---- geometry: OSD rotation + small-angle deskew ---------------------------------

def _geo_none() -> dict:
    """The identity geometry meta (fresh dict — callers may store it per page)."""
    return {"rotate": 0, "deskew": 0.0, "osd_conf": None}


def detect_osd(path, timeout: int = 60) -> tuple:
    """Tesseract OSD (`--psm 0`) on an image file -> `(rotate_cw_degrees, confidence)`.
    `rotate_cw_degrees` in {0, 90, 180, 270} is how far the image must be rotated
    CLOCKWISE to put the text upright (tesseract's own `Rotate:` convention).
    FAIL-OPEN: no binary / OSD error (blank page, missing osd.traineddata, timeout)
    -> `(0, None)` — proceed unrotated, exactly today's behaviour. Never raises."""
    exe = tesseract_path()
    if not exe:
        return 0, None
    try:
        r = subprocess.run(
            _tess_cmd(exe, path, None, psm="0"),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=_env(),
        )
    except Exception:  # noqa: BLE001 - OSD must never crash the caller
        return 0, None
    rotate, conf = 0, None
    for line in (r.stdout or "").splitlines():
        m = re.match(r"\s*Rotate:\s*(\d+)", line)
        if m:
            try:
                rotate = int(m.group(1)) % 360
            except ValueError:
                rotate = 0
        m = re.match(r"\s*Orientation confidence:\s*([0-9.]+)", line)
        if m:
            try:
                conf = float(m.group(1))
            except ValueError:
                conf = None
    if rotate not in (90, 180, 270):
        return 0, conf
    return rotate, conf


def _rotate_upright(img, rotate_cw: int):
    """Rotate a PIL image `rotate_cw` degrees CLOCKWISE, losslessly (PIL transpose —
    no resampling). PIL's ROTATE_* constants are COUNTER-clockwise, hence the swap."""
    from PIL import Image
    if rotate_cw == 90:
        return img.transpose(Image.ROTATE_270)
    if rotate_cw == 180:
        return img.transpose(Image.ROTATE_180)
    if rotate_cw == 270:
        return img.transpose(Image.ROTATE_90)
    return img


def _profile_score(binimg) -> float:
    """Projection-profile score of a small BINARY (L-mode, text=255) image: the energy
    of adjacent-row-sum differences. Sharp when text lines are horizontal; flat when
    the image is skewed. Pure python over a bounded (~800px wide) image."""
    w, h = binimg.size
    if w <= 0 or h <= 1:
        return 0.0
    data = list(binimg.getdata())
    rows = [0] * h
    for y in range(h):
        base = y * w
        rows[y] = sum(data[base:base + w])
    return float(sum((rows[i + 1] - rows[i]) ** 2 for i in range(h - 1)))


def _deskew_angle(img) -> float:
    """Best small-angle deskew for `img` (degrees, PIL counter-clockwise-positive), or
    0.0 when no angle beats 0° by `DESKEW_MARGIN`. The sweep (±DESKEW_MAX_DEG in
    DESKEW_STEP_DEG steps) runs on a DOWNSAMPLED inverted-binary copy so the work is
    bounded and deterministic. A page with almost no ink (or an unmeasurable 0° score)
    is never deskewed. Never raises (caller fail-opens anyway)."""
    from PIL import Image
    g = img.convert("L")
    w, h = g.size
    if w > _DESKEW_DOWNSAMPLE_W:
        nh = max(1, int(h * _DESKEW_DOWNSAMPLE_W / w))
        g = g.resize((_DESKEW_DOWNSAMPLE_W, nh), Image.BILINEAR)
    # Invert (text -> high) and binarize at Otsu so fill/background never scores.
    inv = g.point(lambda v: 255 - v)
    thr = _otsu_threshold(inv.histogram())
    binimg = inv.point(lambda v: 255 if v > thr else 0)
    # A near-blank page (under 0.2% ink) has no measurable text lines: skip — a sweep
    # over noise could otherwise "win" at a nonzero angle and churn the page.
    ink = sum(1 for v in binimg.getdata() if v) / float(binimg.size[0] * binimg.size[1])
    if ink < 0.002:
        return 0.0
    zero_score = _profile_score(binimg)
    if zero_score <= 0.0:
        return 0.0
    best_angle, best_score = 0.0, zero_score
    steps = int(round(DESKEW_MAX_DEG / DESKEW_STEP_DEG))
    for i in range(1, steps + 1):
        for sign in (1.0, -1.0):
            a = sign * i * DESKEW_STEP_DEG
            r = binimg.rotate(a, resample=Image.BILINEAR, fillcolor=0)
            s = _profile_score(r)
            if s > best_score:
                best_angle, best_score = a, s
    if best_angle != 0.0 and best_score >= DESKEW_MARGIN * zero_score:
        return best_angle
    return 0.0


def prepare_page_image(img):
    """GEOMETRY correction for one page raster: OSD rotation (90/180/270, lossless
    transpose) then small-angle deskew. Returns `(corrected_img, geo)` where `geo`
    is `{"rotate": cw_degrees, "deskew": ccw_degrees, "osd_conf": float|None}` —
    replayable via `apply_geometry` (imageredact re-renders pages and must land in
    the IDENTICAL pixel space; see the geometry invariant there). FAIL-OPEN: any
    error returns the original image with identity geo — never worse than today.

    The OSD probe writes the raster to a temp PNG under the app-data temp dir
    (matter content — removed in `finally`; a hard kill leaves it where the next
    startup's `paths.sweep_temp()` removes it, never in system temp)."""
    geo = _geo_none()
    try:
        rotate = 0
        if available():
            from .paths import temp_dir
            fd, p = tempfile.mkstemp(suffix=".png", prefix="ldm-osd-", dir=str(temp_dir()))
            os.close(fd)
            try:
                img.save(p, "PNG")
                rotate, conf = detect_osd(p)
                geo["osd_conf"] = conf
                # Low-confidence OSD -> do NOT rotate (fail-open = today's behaviour).
                if conf is None or conf < OSD_MIN_CONF:
                    rotate = 0
            finally:
                try:
                    os.remove(p)
                except OSError:
                    pass
        if rotate:
            img = _rotate_upright(img, rotate)
            geo["rotate"] = rotate
        angle = _deskew_angle(img)
        if angle:
            img = _apply_deskew(img, angle)
            geo["deskew"] = angle
        return img, geo
    except Exception:  # noqa: BLE001 - geometry must never make OCR worse than today
        return img, _geo_none()


def _apply_deskew(img, angle: float):
    """Rotate by the small deskew angle (bilinear, white fill, dims unchanged so
    page-fraction coordinates stay meaningful)."""
    from PIL import Image
    return img.rotate(angle, resample=Image.BILINEAR, fillcolor=(255, 255, 255)
                      if img.mode == "RGB" else 255)


def apply_geometry(img, geo: dict):
    """REPLAY a `prepare_page_image` geo on a fresh render of the same page — used by
    the burn phase (which re-renders rather than holding every raster in memory).
    Deterministic: transpose + the same bilinear rotate give the identical pixel
    space the OCR boxes were measured in. Unknown/malformed geo -> unchanged."""
    try:
        rotate = int((geo or {}).get("rotate", 0))
        deskew = float((geo or {}).get("deskew", 0.0))
    except (TypeError, ValueError):
        return img
    if rotate in (90, 180, 270):
        img = _rotate_upright(img, rotate)
    if deskew and abs(deskew) <= DESKEW_MAX_DEG:
        img = _apply_deskew(img, deskew)
    return img


# ---- pixel preprocessing (feeds tesseract ONLY — never the output page) ----------

def _otsu_threshold(hist) -> int:
    """Otsu's threshold over a 256-bin histogram (pure python, deterministic):
    maximize between-class variance. Returns 0-255 (0 when the histogram is empty)."""
    total = sum(hist[:256])
    if total <= 0:
        return 0
    sum_all = sum(i * hist[i] for i in range(256))
    sum_b = 0.0
    w_b = 0
    best_t, best_var = 0, -1.0
    for t in range(256):
        w_b += hist[t]
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        sum_b += t * hist[t]
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best_var:
            best_var, best_t = var, t
    return best_t


def preprocess_for_ocr(img):
    """Deterministic pixel cleanup fed to tesseract ONLY (boxes map 1:1 — no geometry
    change): grayscale -> extrema-normalizing autocontrast (cutoff=0: maps the darkest/
    lightest pixel to 0/255 — a NO-OP on a normal full-range page, bounded help on a
    faded low-contrast scan) -> 3px median despeckle (kills salt-and-pepper scanner
    noise; recovered the harness salt class 0.44 -> ~0.9).

    DELIBERATELY MILD — the harness REJECTED the two stronger stages this round
    originally specified, both measured on the synthetic finance corpus:
    * autocontrast cutoff=1: on an ink-sparse page (text < 1% of pixels) the 1% clip
      lands INSIDE the background population, so JPEG background noise crushes to
      black blobs — clean-page recall fell 0.89 -> 0.20 and OCR time exploded;
    * global Otsu binarization: fights tesseract's own adaptive binarizer — clean
      0.89 -> 0.58, jpeg40 0.91 -> 0.52 (it only looked good on top of the
      autocontrast damage). `_otsu_threshold` is retained for the deskew sweep.
    May raise — the caller fail-opens to the original raster."""
    from PIL import ImageFilter, ImageOps
    g = img.convert("L")
    g = ImageOps.autocontrast(g, cutoff=0)
    return g.filter(ImageFilter.MedianFilter(3))


# ---- confidence (honesty spine) ---------------------------------------------------

def page_confidence(words) -> float | None:
    """Mean word confidence of a page's OCR words (TSV conf, rows with conf >= 0 only
    — tesseract marks non-real detections with -1). None when nothing carries a
    confidence (hand-built words, empty page)."""
    vals = [w.conf for w in (words or [])
            if getattr(w, "conf", None) is not None and w.conf >= 0]
    if not vals:
        return None
    return sum(vals) / len(vals)


def _pick_better(first, retry):
    """The adaptive-retry decision (pure, unit-testable): keep the retry ONLY if it has
    the HIGHER mean confidence AND does not drastically SHRINK coverage — a retry pass
    can score a higher mean precisely because it read FEWER words, and a dropped word
    can be the identifier (review finding: silently returning less text than the
    default pass is the one edge where the retry could WORSEN recall — a MISS is the
    leak). Coverage floor: >= 80% of the first pass's word count AND total text length
    (an empty first pass is beaten by any words). A TIE (or both unknown) keeps
    `first` — the default-PSM pass, i.e. today's behaviour wins unless the retry is
    measurably better on BOTH confidence and coverage."""
    c1 = page_confidence(first)
    c2 = page_confidence(retry)
    if (c2 if c2 is not None else -1.0) <= (c1 if c1 is not None else -1.0):
        return first
    n1 = len(first or [])
    if n1:
        n2 = len(retry or [])
        t1 = sum(len(w.text) for w in first)
        t2 = sum(len(w.text) for w in (retry or []))
        if n2 < 0.8 * n1 or t2 < 0.8 * t1:
            return first
    return retry


# ---- OCR runs ---------------------------------------------------------------------

def _run_tsv(exe, path, lang: str, timeout: int, psm: str | None = None):
    """One tesseract TSV run -> [`OcrWord`] (with conf). [] on any error."""
    try:
        r = subprocess.run(
            _tess_cmd(exe, path, lang, "tsv", psm=psm),
            # encoding="utf-8" — Tesseract emits UTF-8; Python text mode would otherwise
            # decode it with the locale codec (cp1252 on Windows) and crash on OCR'd
            # non-ASCII text. errors="replace" so a stray byte never wedges the reader.
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=_env(),
        )
    except Exception:  # noqa: BLE001 - OCR must never crash the caller
        return []
    return _parse_tsv_words(r.stdout or "")


def _ocr_words_at(path, lang: str, timeout: int):
    """TSV OCR of an image FILE with the pixel-preprocess + adaptive-retry pipeline:
    preprocess a COPY for tesseract (fail-open to the original on any error), OCR,
    and if the page's mean confidence is under `LOW_CONF_THRESHOLD` retry ONCE with
    PSM 6, keeping the higher-confidence result (`_pick_better`). The preprocessed
    temp PNG is matter content — written under the app-data temp dir and removed in
    `finally` (a survivor is swept by `paths.sweep_temp` on next startup)."""
    exe = tesseract_path()
    if not exe:
        return []
    ocr_path, tmp = path, None
    try:
        try:
            from PIL import Image
            from .paths import temp_dir
            with Image.open(path) as im:
                pre = preprocess_for_ocr(im)
            fd, tmp = tempfile.mkstemp(suffix=".png", prefix="ldm-ocrpre-",
                                       dir=str(temp_dir()))
            os.close(fd)
            pre.save(tmp, "PNG")
            ocr_path = tmp
        except Exception:  # noqa: BLE001 - preprocessing fail-open: OCR the original
            ocr_path = path
        words = _run_tsv(exe, ocr_path, lang, timeout)
        conf = page_confidence(words)
        if conf is None or conf < LOW_CONF_THRESHOLD:
            # Bounded adaptive second pass: exactly ONE retry (PSM 6 — "a single
            # uniform block", which recovers form/statement layouts the default page
            # segmentation fragments). Keep whichever pass scored higher.
            words = _pick_better(words, _run_tsv(exe, ocr_path, lang, timeout, psm="6"))
        return words
    finally:
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass


def words_to_text(words) -> str:
    """Plain text from OCR words for INDEXING/search: same-line words joined by a
    space, a newline whenever the tesseract line identity changes (unknown line ids
    join with a space — the flat prior behaviour). Mirrors imageredact._assemble's
    separator rule (1 char each) without the byte-offset bookkeeping."""
    parts = []
    prev_line = None
    for i, w in enumerate(words or []):
        line_id = getattr(w, "line_id", None)
        if i > 0:
            newline = prev_line is not None and line_id is not None and line_id != prev_line
            parts.append("\n" if newline else " ")
        parts.append(w.text)
        prev_line = line_id
    return "".join(parts)


def ocr_image(path, lang: str | None = None, timeout: int = 120):
    """OCR a single image file. Returns [(locator, text)] or [] (no binary/text).
    Full pipeline: geometry (OSD rotation + deskew — output here is TEXT ONLY, so
    correcting the raster is always safe) -> pixel preprocess -> TSV OCR + adaptive
    retry -> line-aware text. Every stage fail-opens to plain OCR of the file."""
    exe = tesseract_path()
    if not exe:
        return []
    lang = lang or ocr_langs()
    tmp = None
    try:
        try:
            from PIL import Image
            from .paths import temp_dir
            with Image.open(path) as im:
                corrected, geo = prepare_page_image(im.convert("RGB"))
                if geo["rotate"] or geo["deskew"]:
                    fd, tmp = tempfile.mkstemp(suffix=".png", prefix="ldm-ocrgeo-",
                                               dir=str(temp_dir()))
                    os.close(fd)
                    corrected.save(tmp, "PNG")
        except Exception:  # noqa: BLE001 - geometry fail-open: OCR the original file
            tmp = None
        words = _ocr_words_at(tmp if tmp is not None else path, lang, timeout)
        txt = words_to_text(words).strip()
        return [("ocr", txt)] if txt else []
    finally:
        # The geometry-corrected raster is MATTER CONTENT — remove it even on error.
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass


def ocr_words(path, lang: str | None = None, timeout: int = 120):
    """OCR an image to a list of [`OcrWord`] (text + pixel bounding box + confidence),
    via tesseract's TSV output. Returns [] if no binary, a run error, or no words.
    Used by image-based redaction to map detected identifiers back to page regions.

    GEOMETRY IS THE CALLER'S JOB: the boxes come back in `path`'s own pixel space, so
    the caller must hand in the already-rotated/deskewed raster it will burn on (see
    imageredact — it owns the raster and replays the same geometry when re-rendering).
    Pixel preprocessing + the adaptive PSM-6 retry run internally (boxes stay 1:1).
    Never raises."""
    if not available():
        return []
    return _ocr_words_at(path, lang or ocr_langs(), timeout)


def _parse_tsv_words(tsv: str):
    """Parse tesseract TSV into [`OcrWord`]s (level-5 rows with non-empty text). Pure +
    bounds-safe so it is unit-testable without a tesseract binary.

    Tesseract's TSV columns are, in order:
    ``level  page_num  block_num  par_num  line_num  word_num  left  top  width
    height  conf  text`` — so left/top/width/height are cols 6/7/8/9, conf is col 10
    and text is col 11. We also carry each word's LINE identity — the
    `(block_num, par_num, line_num)` triple from cols 2/3/4 — as `OcrWord.line_id`, so
    `imageredact._assemble` can rebuild line breaks (a one-line-per-page assembly
    blinds the engine's line-scoped recall), and the word CONFIDENCE (col 10, feeding
    `page_confidence` — the honesty signal). A row whose line-id/conf cols are
    malformed keeps `None` for that field rather than raising; a genuinely broken box
    is still dropped."""
    words = []
    lines = tsv.splitlines()
    for line in lines[1:]:  # skip the header row
        cols = line.split("\t")
        if len(cols) < 12 or cols[0] != "5":  # 5 == word level
            continue
        text = cols[11].strip()
        if not text:
            continue
        try:
            x, y, w, h = int(cols[6]), int(cols[7]), int(cols[8]), int(cols[9])
        except ValueError:
            continue
        if w <= 0 or h <= 0:
            continue
        try:
            line_id = (int(cols[2]), int(cols[3]), int(cols[4]))
        except ValueError:
            line_id = None  # malformed line-id cols -> unknown line (join as before)
        try:
            conf = float(cols[10])
        except ValueError:
            conf = None  # malformed conf -> unknown (never a raise, never a drop)
        words.append(OcrWord(text, x, y, w, h, line_id, conf))
    return words


def ocr_pdf(path, lang: str | None = None, max_pages=None, timeout: int = 600):
    """OCR a whole PDF — rasterize every page, OCR each. Returns [(locator, text)] in
    page order, or [] if no tesseract / no rasterizer. `max_pages` caps how many pages
    are OCR'd. For a MIXED born-digital/scanned PDF prefer the per-page hybrid in
    `extractors._pdf_pymupdf_ocr`, which OCRs ONLY the text-less pages."""
    if not available():
        return []
    tmp, rendered = _render_pdf_pages(path)
    if max_pages is not None:
        rendered = rendered[:max_pages]
    units = []
    try:
        for idx, img in rendered:
            for _, txt in ocr_image(img, lang=lang, timeout=timeout):
                if txt:
                    units.append((f"p.{idx + 1} (ocr)", txt))
    finally:
        # The rasterized page images contain MATTER CONTENT; remove them (and the
        # temp dir) once OCR'd — even on an exception — so no cleartext residue is
        # left on disk (confidentiality). A no-op when nothing was rendered.
        _cleanup_render_dir(tmp)
    return units


def ocr_pdf_pages(path, page_indices, lang: str | None = None, timeout: int = 600) -> dict:
    """OCR ONLY the given 0-based page indices (the scanned pages of a mixed PDF).
    Returns ``{page_index: text}`` for pages that produced text; ``{}`` if no tesseract
    / no rasterizer / no indices. Never touches a page not in `page_indices` — the
    caller already took the born-digital pages from the text layer (never OCR
    born-digital files — CLAUDE.md)."""
    want = {int(i) for i in page_indices}
    if not available() or not want:
        return {}
    out = {}
    tmp, rendered = _render_pdf_pages(path, only=want)
    try:
        for idx, img in rendered:
            for _, txt in ocr_image(img, lang=lang, timeout=timeout):
                if txt:
                    out[idx] = txt
    finally:
        # See ocr_pdf: the rasters hold matter content — delete them after OCR.
        _cleanup_render_dir(tmp)
    return out


def _cleanup_render_dir(tmp) -> None:
    """Best-effort delete of a `_render_pdf_pages` temp dir (it holds rasterized page
    images = matter content). Never raises — a leftover temp dir must not crash OCR."""
    if tmp is None:
        return
    try:
        shutil.rmtree(tmp, ignore_errors=True)
    except OSError:
        pass


def _clamp_scale(width_pt, height_pt, dpi):
    """Return a render scale (start `dpi/72`) reduced just enough that the rasterized
    page stays at/under `imageredact.MAX_PAGE_MEGAPIXELS`. A crafted PDF with a giant
    MediaBox would otherwise make the rasterizer attempt a multi-GB allocation (an OOM
    DoS); a genuinely large scan still renders, only the pathological case shrinks
    (mirrors imageredact's per-page clamp). Page dims are in POINTS (1/72 in)."""
    from . import imageredact
    scale = dpi / 72.0
    try:
        w_pt = float(width_pt)
        h_pt = float(height_pt)
    except (TypeError, ValueError):
        return scale
    if w_pt <= 0 or h_pt <= 0:
        return scale
    max_px = imageredact.MAX_PAGE_MEGAPIXELS * 1_000_000
    while (w_pt * scale) * (h_pt * scale) > max_px and scale > 0.05:
        scale *= 0.8
    return scale


def _render_pdf_pages(path, dpi: int = 300, only=None):
    """PDF pages -> ``(tmp_dir, [(page_index_0based, png_path)])``. If `only` (a set of
    0-based indices) is given, render ONLY those pages. Prefer pypdfium2 (permissive);
    fall back to PyMuPDF; the image list is `[]` if neither is importable. 300 DPI —
    tesseract's sweet spot; 200 measurably misread checksummed identifiers (NRIC/ISIN
    confusions) on the harness corpus. The megapixel clamp bounds the growth.

    Bounded against a hostile PDF (mirrors imageredact's caps): page COUNT is capped at
    `imageredact.MAX_PAGES` (a huge PDF renders only the first N pages rather than
    spinning unbounded), and each page's raster is MEGAPIXEL-CLAMPED (a giant MediaBox
    can't trigger a multi-GB allocation). The `only` set already bounds a per-page flow.

    The returned `tmp_dir` (a temp directory holding the rasters, which are MATTER
    CONTENT) MUST be cleaned up by the caller via `_cleanup_render_dir` once the images
    are consumed — even on an exception — so no cleartext page raster is left on disk.
    The dir lives UNDER the app-data temp dir (`paths.temp_dir`), not the system temp
    dir, so a hard kill before `_cleanup_render_dir` runs leaves the rasters where the
    next startup's `paths.sweep_temp()` removes them — never in system temp."""
    from .paths import temp_dir
    from . import imageredact
    tmp = Path(tempfile.mkdtemp(prefix="ldm-ocr-", dir=str(temp_dir())))
    want = None if only is None else {int(i) for i in only}
    max_pages = imageredact.MAX_PAGES
    try:
        import pypdfium2 as pdfium
        doc = pdfium.PdfDocument(str(path))
        out = []
        for i in _pages_to_render(len(doc), want, max_pages):
            page = doc[i]
            size = page.get_size()  # (width_pt, height_pt)
            scale = _clamp_scale(size[0], size[1], dpi)
            pil = page.render(scale=scale).to_pil()
            p = tmp / f"p{i + 1}.png"
            pil.save(p)
            out.append((i, str(p)))
        return tmp, out
    except Exception:  # noqa: BLE001
        pass
    # pypdfium2 is unavailable OR failed PART-WAY through. Start the PyMuPDF fallback with a
    # FRESH list so a partial pypdfium2 run can't leave DUPLICATE page entries (#11) — the
    # fallback re-renders from scratch into the same temp dir (paths overwrite cleanly).
    try:
        import fitz
        with fitz.open(str(path)) as doc:
            out = []
            for i in _pages_to_render(doc.page_count, want, max_pages):
                page = doc[i]
                rect = page.rect
                scale = _clamp_scale(rect.width, rect.height, dpi)
                p = tmp / f"p{i + 1}.png"
                page.get_pixmap(matrix=fitz.Matrix(scale, scale)).save(str(p))
                out.append((i, str(p)))
        return tmp, out
    except Exception:  # noqa: BLE001
        return tmp, []


def _pages_to_render(total: int, want, max_pages: int) -> list:
    """The 0-based page indices to render, bounded to `max_pages`.

    Whole-PDF (`want is None`): the first `max_pages` pages — a huge PDF renders only a
    bounded prefix. Per-page (`want` given, e.g. the scanned pages of a mixed PDF): the
    WANTED pages that actually exist, capped by COUNT — so a scanned page whose INDEX is
    beyond `max_pages` is still OCR'd (closing the >MAX_PAGES scanned-tail recall miss, #12),
    while a pathological huge wanted-set still can't render more than `max_pages` rasters."""
    if want is None:
        return list(range(min(total, max_pages)))
    return sorted(i for i in want if 0 <= i < total)[:max_pages]
