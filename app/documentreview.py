"""Immutable, process-local PDF review plans joining native text and OCR decisions.

The server retains the reviewed bytes/configuration/candidate coordinates. Prepare
accepts only plan identity and candidate IDs, never substituted source bytes or
client-supplied burn coordinates. Image-bearing pages are explicitly marked for
flattening; other native pages retain their format. This is not universal PDF
sanitization, and unprobed surfaces remain release exceptions, not a safety claim.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
import threading
import time

from fastapi import Body, Depends
from fastapi.responses import JSONResponse

from . import exportverification, imageredact, redactionmodel, redactionreport, releaseflow

_LOCK = threading.RLock()
_PLANS = {}
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_PAGES = 100
MAX_OCR_PAGES = 20
MAX_PLAN_BYTES = 100 * 1024 * 1024
MAX_CANDIDATES = 20_000
TTL = 3600


def capabilities():
    value = redactionmodel._run({"op": "capabilities"})
    if (not isinstance(value, dict) or value.get("op") != "capabilities"
            or type(value.get("contract_version")) is not int or value.get("contract_version") != 1):
        raise ValueError("The installed engine does not support capability negotiation. Update the bundled engine.")
    for key in ("locales", "profiles", "disable_builtins", "boolean_options"):
        if not isinstance(value.get(key), list) or not all(isinstance(x, str) for x in value[key]):
            raise ValueError("The engine returned invalid capabilities.")
    limits = value.get("limits")
    if (not isinstance(limits, dict) or any(type(limits.get(k)) is not int or limits[k] <= 0
                                         for k in ("terms", "term_bytes"))
            or limits["terms"] > redactionmodel.MAX_TERMS
            or limits["term_bytes"] > redactionmodel.MAX_TERM_BYTES):
        raise ValueError("The engine returned incompatible limits.")
    return value


def checked_options(raw):
    caps = capabilities()
    if not isinstance(raw, dict):
        raise ValueError("Detection settings must be an object.")
    allowed = {"locales", "profiles", "disable_builtins", "terms", *caps["boolean_options"]}
    if set(raw) - allowed:
        raise ValueError("Unsupported detection option; no setting was silently dropped.")
    for key in ("locales", "profiles", "disable_builtins"):
        if key in raw and (not isinstance(raw[key], list) or any(x not in caps[key] for x in raw[key])):
            raise ValueError("Unsupported detection pack; no requested pack was silently dropped.")
    for key in caps["boolean_options"]:
        if key in raw and type(raw[key]) is not bool:
            raise ValueError("Detection toggles must be booleans.")
    terms = raw.get("terms", [])
    if (not isinstance(terms, list) or len(terms) > caps["limits"]["terms"]
            or any(not isinstance(x, str) or not x.strip() or len(x.encode("utf-8")) > caps["limits"]["term_bytes"] for x in terms)):
        raise ValueError("A party name exceeds the engine's term limits; nothing was silently truncated.")
    # Check the exact host-to-engine request too: capability support must not be
    # silently reduced by the older bridge's option allowlist.
    normalized = redactionmodel.normalize_options(raw)
    for key in ("locales", "profiles", "disable_builtins"):
        if set(raw.get(key, [])) != set(normalized.get(key, [])):
            raise ValueError("This app bridge cannot honor a requested pack. Update it before scanning.")
    for key in caps["boolean_options"]:
        if raw.get(key) is True and normalized.get(key) is not True:
            raise ValueError("This app bridge cannot honor a requested option.")
    return json.loads(json.dumps(raw))


def _engine_hash():
    value = redactionreport._sha256_of_file(redactionmodel.redact_cli_path())
    if not value:
        raise ValueError("The current engine cannot be identified.")
    return value


def _purge():
    now = time.monotonic()
    for ident, plan in list(_PLANS.items()):
        if now - plan["created"] > TTL:
            del _PLANS[ident]


def _plan(ident):
    _purge()
    plan = _PLANS.get(ident) if isinstance(ident, str) else None
    if plan is None:
        raise ValueError("The review expired or is unavailable. Scan the document again.")
    return plan


def scan_document(raw, filename, options, visual_all=False):
    import fitz
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError("PDF size must be between 1 byte and 25 MB.")
    if type(visual_all) is not bool:
        raise ValueError("The visual-review setting must be a boolean.")
    opts = checked_options(options)
    engine_hash = _engine_hash()
    native = redactionmodel.pdf_scan(base64.b64encode(raw).decode("ascii"), opts)
    if "error" in native or not isinstance(native.get("candidates"), list):
        raise ValueError("The PDF text scan could not complete.")
    pages, force, limitations = [], [], []
    with fitz.open(stream=raw, filetype="pdf") as doc:
        if doc.needs_pass or not 1 <= len(doc) <= MAX_PAGES:
            raise ValueError("Use an unencrypted PDF with 1–100 pages.")
        for index, page in enumerate(doc):
            text = page.get_text()
            image = bool(page.get_images(full=True))
            vectors = bool(page.get_drawings())
            # Vector outlines can spell names without being either text or images.
            # Conservatively inspect these pages visually; do not infer "decorative".
            should_ocr = visual_all or image or vectors or imageredact._should_image_redact(page)[0] or bool(native.get("unmapped_fonts"))
            if should_ocr:
                force.append(index)
            pages.append({"number": index + 1, "text_characters": len(text.strip()),
                          "has_images": image, "has_vectors": vectors, "processing": "image + text review" if should_ocr else "native text",
                          "ocr": "not run — native-only scope", "width": page.rect.width, "height": page.rect.height})
        if doc.embfile_count():
            limitations.append("Embedded attachments are removed from the rebuilt working copy; their contents were not reviewed.")
    if len(force) > MAX_OCR_PAGES:
        raise ValueError("This document needs OCR on more than 20 pages. Split it before reviewing.")
    candidates, image_pages = [], []
    for item in native["candidates"]:
        if type(item.get("id")) is not int or not isinstance(item.get("value"), str):
            raise ValueError("The engine returned an incomplete candidate record.")
        candidates.append({**item, "id": "text:" + str(item["id"]), "native_id": item["id"], "surface": "text"})
    if force:
        from . import ocr
        if not ocr.available():
            raise ValueError("This document needs image review, but Tesseract is unavailable. No page was silently skipped.")
        def scan_ocr(text):
            result = redactionmodel.scan(text, opts)
            if "error" in result or not isinstance(result.get("candidates"), list):
                raise ValueError("OCR detection did not complete.")
            return [(c["start"], c["end"], c["recognizer"], c.get("advisory", False)) for c in result["candidates"]]
        image_pages, counts = imageredact.scan_scanned_pdf(raw, scan_ocr, force_pages=force)
        if image_pages is None:
            raise ValueError("Image review could not complete. No page was silently skipped.")
        for page in image_pages:
            pages[page["index"]]["ocr"] = "empty / requires inspection" if page["ocr_empty"] else "low confidence" if page["low_conf"] else "completed"
            if page["ocr_empty"] or page["low_conf"]:
                limitations.append("Page " + str(page["index"] + 1) + " has empty or low-confidence OCR; inspect it manually.")
            for item in page["candidates"]:
                candidates.append({**item, "id": "image:" + item["id"], "page": page["index"] + 1,
                                   "recognizer": item["label"], "surface": "image"})
    if len(candidates) > MAX_CANDIDATES or len({c["id"] for c in candidates}) != len(candidates):
        raise ValueError("The candidate plan is too large or contains duplicate identifiers.")
    if engine_hash != _engine_hash():
        raise ValueError("The engine changed during the scan. Scan again.")
    ident = secrets.token_hex(24)
    source_sha = hashlib.sha256(raw).hexdigest()
    # Strip bulky previews from retained page metadata; preview is rendered on demand.
    for page in image_pages:
        page.pop("preview", None)
    plan = {"raw": raw, "filename": filename, "options": opts, "candidates": candidates,
            "pages": pages, "image_pages": image_pages, "force": force, "visual_all": visual_all,
            "limitations": limitations, "source_sha256": source_sha,
            "engine_sha256": engine_hash, "created": time.monotonic()}
    with _LOCK:
        _purge()
        if len(_PLANS) >= 8 or sum(len(p["raw"]) for p in _PLANS.values()) + len(raw) > MAX_PLAN_BYTES:
            raise ValueError("Too many active document reviews; discard one before scanning another.")
        _PLANS[ident] = plan
    return {"ok": True, "review_id": ident, "source_sha256": source_sha,
            "engine_sha256": engine_hash, "pages": pages, "candidates": candidates,
            "limitations": limitations,
            "notice": "Pages with images or vector drawings are flattened after visual review; other pages retain native text unless all-page visual review was selected. Inspect every page; OCR is not exhaustive."}


def prepare_document(ident, accepted, reviewed_pages):
    import fitz
    from .redactionroutes import _emit_report, _safe_stem, _unique_export
    with _LOCK:
        plan = _plan(ident)
        if _engine_hash() != plan["engine_sha256"]:
            raise ValueError("The engine changed after review; scan the document again.")
        by_id = {c["id"]: c for c in plan["candidates"]}
        if (not isinstance(accepted, list) or not accepted or len(accepted) > MAX_CANDIDATES
                or any(not isinstance(x, str) or x not in by_id for x in accepted)
                or len(set(accepted)) != len(accepted)):
            raise ValueError("Select at least one valid redaction; unknown or duplicate IDs are refused.")
        expected_pages = set(range(1, len(plan["pages"]) + 1))
        if (not isinstance(reviewed_pages, list) or any(type(x) is not int for x in reviewed_pages)
                or set(reviewed_pages) != expected_pages):
            raise ValueError("Review every page, including pages with no detected findings.")
        selected = [by_id[x] for x in accepted]
        native_ids = [c["native_id"] for c in selected if c["surface"] == "text"]
        result = redactionmodel.pdf_apply(base64.b64encode(plan["raw"]).decode("ascii"), native_ids, plan["options"])
        if "error" in result:
            raise ValueError("Accepted native-text redactions could not be applied; nothing was released.")
        intermediate = base64.b64decode(result["pdf_b64"], validate=True)
        with fitz.open(stream=intermediate, filetype="pdf") as doc:
            if len(doc) != len(plan["pages"]) or any(abs(doc[i].rect.width-p["width"]) > 0.01 or abs(doc[i].rect.height-p["height"]) > 0.01 for i,p in enumerate(plan["pages"])):
                raise ValueError("The PDF geometry changed after text redaction; image coordinates cannot be reused.")
        rects = {}
        for c in selected:
            if c["surface"] == "image":
                rects.setdefault(c["page"] - 1, []).extend(c["rects"])
        if plan["force"]:
            geometry = {p["index"]: p["geo"] for p in plan["image_pages"]}
            intermediate, counts = imageredact.apply_selection_to_pdf(intermediate, rects, geo=geometry, force_pages=plan["force"])
            if intermediate is None or counts.get("boxes") != sum(len(x) for x in rects.values()):
                raise ValueError("The image-redaction plan was not applied completely.")
        # A full rewrite drops unreferenced original objects. Rebuild the document
        # catalog through insert_pdf so attachments/active catalog content do not
        # ride along. Existing page annotations/links are deliberately excluded.
        with fitz.open(stream=intermediate, filetype="pdf") as src, fitz.open() as out:
            out.insert_pdf(src, links=False, annots=False, widgets=False)
            out.set_metadata({})
            out_bytes = out.tobytes(garbage=4, deflate=True)
        values = [{"value": c["value"], "class": c.get("recognizer", "value")} for c in selected]
        coverage = {"requested": len(selected), "resolved": len(selected), "unresolved": 0, "complete": True}
        reasons = list(plan["limitations"])
        if plan["force"]:
            reasons.append("Visual-review pages were flattened; native searchability on those pages was lost.")
        path = _unique_export(_safe_stem(plan["filename"]) + ".redacted.pdf")
        path.write_bytes(out_bytes)
        evidence = exportverification.check_saved(path, out_bytes, values, plan["options"], kind="pdf", coverage=coverage)
        evidence["reasons"].extend(reasons)
        # Actual output-image recovery, once per planned image page. A positive
        # recovery can only strengthen the verdict; a negative never certifies OCR.
        from . import ocr
        from PIL import Image
        image_hits = 0
        with fitz.open(stream=out_bytes, filetype="pdf") as output:
            for index in plan["force"]:
                pix = imageredact._bounded_pixmap(output[index], 200)
                image = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
                words = imageredact._ocr_pixmap_image(image, ocr.ocr_words)
                text = imageredact._assemble(words)[0]
                normalized = "".join(text.split()).casefold()
                image_hits += sum(bool(c["value"].strip()) and "".join(c["value"].split()).casefold() in normalized for c in selected)
        evidence["image_recovery"] = {"pages_checked": len(plan["force"]), "possible_hits": image_hits}
        if image_hits:
            evidence["state"] = "residuals_possible"
            evidence["reasons"].append("Output-image OCR recovered possible targeted content.")
        if plan["force"]:
            evidence["reasons"].append("Output OCR checked the planned image pages only. Unrecognized text and other visual/container surfaces are not certified.")
        if _engine_hash() != plan["engine_sha256"]:
            raise ValueError("The engine changed during preparation; scan again.")
        report = redactionreport.build_report(
            original_filename=plan["filename"], original_sha256=plan["source_sha256"],
            output_filename=path.name, output_sha256=hashlib.sha256(out_bytes).hexdigest(),
            engine_path=redactionmodel.redact_cli_path(), engine_sha256=plan["engine_sha256"],
            options=plan["options"], findings=len(by_id), accepted=len(selected), rejected=len(by_id)-len(selected),
            per_recognizer={}, ocr_used=bool(plan["force"]), low_text=False, unmapped_fonts=False,
            could_not_remove=0, cleaned=["accepted native text", "accepted image regions", "document-level metadata", "annotations, links, widgets and attachment catalog"],
            not_removed=["unknown identifiers and identifying context", "unrecognized visual text, object-level metadata and unexamined container contents"], verification=evidence,
            export_kind="unified-pdf")
        report["review_binding"] = {"review_id": ident, "source_sha256": plan["source_sha256"],
                                   "engine_sha256": plan["engine_sha256"],
                                   "decision_sha256": hashlib.sha256(json.dumps(sorted(accepted)).encode()).hexdigest(),
                                   "configuration_sha256": hashlib.sha256(json.dumps(plan["options"],sort_keys=True).encode()).hexdigest(),
                                   "reviewed_pages": sorted(expected_pages), "visual_all": plan["visual_all"],
                                   "flattened_pages": [i+1 for i in plan["force"]]}
        report["page_coverage"] = plan["pages"]
        names = _emit_report(path, report)
        return {"ok": True, "filename": path.name, "verification": evidence,
                "report_filename": names[0], "report_txt_filename": names[1]}


def install_routes(router, require_token):
    guard = [Depends(require_token)]
    @router.get("/api/redaction/capabilities", dependencies=guard)
    def engine_capabilities():
        try:
            return JSONResponse(capabilities())
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)

    @router.post("/api/redaction/document-scan", dependencies=guard)
    def scan(payload: dict = Body(...)):
        try:
            encoded = payload.get("data_b64")
            if not isinstance(encoded, str) or len(encoded) > MAX_SOURCE_BYTES * 4 // 3 + 4:
                raise ValueError("The PDF exceeds the 25 MB review limit.")
            raw = base64.b64decode(encoded, validate=True)
            name = payload.get("filename", "document.pdf")
            if not isinstance(name, str) or len(name)>240:
                raise ValueError("Invalid filename.")
            return JSONResponse(scan_document(raw, name.replace("\\", "/").split("/")[-1], payload.get("options", {}), payload.get("visual_all", False)))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except Exception:  # noqa: BLE001 - never return parser diagnostics containing matter content
            return JSONResponse({"error": "The PDF review could not complete. No document was released."}, status_code=500)

    @router.post("/api/redaction/document-prepare", dependencies=guard)
    @releaseflow.prepare_export
    def prepare(payload: dict = Body(...)):
        try:
            return JSONResponse(prepare_document(payload.get("review_id"), payload.get("accepted"), payload.get("reviewed_pages")))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    @router.post("/api/redaction/document-page", dependencies=guard)
    def page(payload: dict = Body(...)):
        import fitz
        try:
            with _LOCK:
                plan = _plan(payload.get("review_id"))
                number = payload.get("page", 1)
                if type(number) is not int or not 1 <= number <= len(plan["pages"]):
                    raise ValueError("Invalid page number.")
                # Display the original source. The findings list does not draw OCR overlays.
                # The burn geometry is retained only in the server-side immutable plan.
                with fitz.open(stream=plan["raw"], filetype="pdf") as doc:
                    pix = imageredact._bounded_pixmap(doc[number-1], 100)
                    png = pix.tobytes("png")
                    return JSONResponse({"image": base64.b64encode(png).decode("ascii"), "page": number})
        except (ValueError, OSError, RuntimeError):
            return JSONResponse({"error": "Page is unavailable."}, status_code=400)

    @router.post("/api/redaction/discard-review", dependencies=guard)
    def discard(payload: dict = Body(...)):
        with _LOCK:
            ident = payload.get("review_id")
            if not isinstance(ident, str):
                return JSONResponse({"error": "Invalid review identity."}, status_code=400)
            _PLANS.pop(ident, None)
        return JSONResponse({"ok": True})
