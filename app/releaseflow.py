"""Private preparation followed by explicit, fail-closed package publication.

No caller-supplied filesystem paths. Jobs are process-local, bounded, expiring and
bound to their exact files. Release copies only allowlisted document/report bytes,
checks their digests, then atomically publishes a new directory without replacing
an existing destination. Re-identification keys are never part of that directory.
This does not assert anonymity, protect against a malicious same-user OS process,
or implement a durable compliance audit or forensic deletion.
"""
from __future__ import annotations

import base64
import contextvars
import ctypes
import functools
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

from fastapi import Body, Depends
from fastapi.responses import JSONResponse

from . import exportverify

STAGE_DIRECTORY = contextvars.ContextVar("redactor_stage_directory", default=None)
MAX_BYTES = 256 * 1024 * 1024
MAX_JOBS = 16
TTL_SECONDS = 3600
_LOCK = threading.RLock()
_JOBS: dict[str, dict] = {}


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _root():
    from .paths import data_dir
    root = data_dir() / "prepared-redactions"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink():
        raise OSError("invalid preparation directory")
    return root


def _purge():
    now = time.monotonic()
    for ident, job in list(_JOBS.items()):
        if now - job["created"] > TTL_SECONDS:
            shutil.rmtree(job["directory"], ignore_errors=True)
            del _JOBS[ident]


def rename_no_replace(source: Path, destination: Path):
    """Atomic directory publication on supported platforms; NEVER overwrite.

    Linux uses RENAME_NOREPLACE rather than an existence-check/rename race.
    Windows os.rename refuses an existing destination. Other platforms fail closed.
    """
    if sys.platform == "win32":
        os.rename(source, destination)
        return
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise OSError("atomic non-replacing publication is unavailable")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
            errno = ctypes.get_errno()
            raise OSError(errno, "atomic publication failed")
        return
    raise OSError("atomic non-replacing publication is unavailable on this platform")


def _read(path: Path, limit=MAX_BYTES):
    if path.is_symlink() or not path.is_file():
        raise OSError("prepared file is unavailable")
    with path.open("rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise OSError("prepared file exceeds the size limit")
    return data


def _snapshot(directory):
    files, total = {}, 0
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise OSError("links are not allowed in prepared packages")
        if not path.is_file():
            continue
        data = _read(path, MAX_BYTES - total)
        total += len(data)
        files[path.relative_to(directory).as_posix()] = {"sha256": _digest(data), "size": len(data)}
    if not files:
        raise OSError("no prepared files")
    return files


def _policy(directory, files, response):
    key_name = response.get("key_filename")
    keys = {key_name} if isinstance(key_name, str) and key_name in files else set()
    documents, reports, blocked, incomplete = [], [], [], []
    for name in files:
        if name in keys or name.endswith((".report.json", ".report.txt")):
            continue
        documents.append(name)
    for name in documents:
        json_name, text_name = name + ".report.json", name + ".report.txt"
        if json_name not in files or text_name not in files:
            blocked.append("A required document report could not be prepared.")
            continue
        report = json.loads(_read(directory / json_name, 8 * 1024 * 1024))
        reports.append(report)
        evidence = report.get("verification", {})
        expected = files[name]["sha256"]
        if (report.get("output", {}).get("sha256") != expected
                or evidence.get("artifact_sha256") != expected):
            blocked.append("A report is not bound to the exact prepared document.")
        if report.get("could_not_remove") != 0:
            blocked.append("An accepted redaction was not removed.")
        coverage = evidence.get("coverage", {})
        if (not isinstance(coverage, dict) or coverage.get("complete") is not True
                or type(coverage.get("requested")) is not int or coverage["requested"] <= 0
                or coverage.get("resolved") != coverage["requested"]
                or type(coverage.get("unresolved")) is not int or coverage["unresolved"] != 0):
            blocked.append("Accepted decisions were not completely bound to source content.")
        state = evidence.get("state")
        if state == exportverify.VERDICT_POSSIBLE:
            blocked.append("Recovery checks found possible residual targeted content.")
        elif state != exportverify.VERDICT_NONE:
            incomplete.append("Verification did not cover every required surface.")
        # Successful protocol execution and exact-byte verification are mandatory,
        # even when the user accepts an explicitly described coverage limitation.
        rust = evidence.get("rust", {})
        if rust.get("status") != "completed" or rust.get("artifact_sha256") != expected:
            blocked.append("The recovery verifier did not complete for these exact bytes.")
        incomplete.extend(str(x) for x in evidence.get("reasons", []) if isinstance(x, str))
        incomplete.extend(str(x) for x in report.get("not_removed", []) if isinstance(x, str))
        if any(report.get("warnings", {}).values()):
            incomplete.append("The document has unresolved text or font coverage warnings.")
    if not documents:
        blocked.append("No document was prepared.")
    if response.get("failed"):
        blocked.append("The batch contains failed files; resolve them before releasing the batch.")
    if response.get("key_failed"):
        blocked.append("The requested re-identification key could not be prepared.")
    return documents, keys, reports, list(dict.fromkeys(blocked)), list(dict.fromkeys(incomplete))


def _describe(ident, job):
    return {"ok": True, "prepared": True, "preparation_id": ident,
            "release_allowed": not job["blocked"],
            "exception_required": bool(job["incomplete"]),
            "blocked_reasons": job["blocked"], "limitations": job["incomplete"],
            "files": [{"name": name, **job["files"][name]} for name in job["documents"]],
            "has_key": bool(job["keys"]), "expires_in_seconds": TTL_SECONDS,
            "note": "Prepared privately, not released. An absence of findings is not proof of anonymity."}


def prepare_export(function):
    """Route adapter: existing writers execute only inside a private stage.

    This is deliberately around every filesystem-producing redaction entry point,
    not a client-side gate. Even an old/direct API caller cannot publish a copy.
    """
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        with _LOCK:
            _purge()
            if len(_JOBS) >= MAX_JOBS:
                return JSONResponse({"error": "Too many prepared jobs. Discard one before continuing."}, status_code=429)
            ident = secrets.token_hex(24)
            directory = Path(tempfile.mkdtemp(prefix="job-", dir=_root()))
            _JOBS[ident] = {"directory": directory, "created": time.monotonic(), "state": "building"}
        token = STAGE_DIRECTORY.set(directory)
        try:
            response = function(*args, **kwargs)
            if not isinstance(response, JSONResponse) or response.status_code >= 400:
                with _LOCK:
                    _JOBS.pop(ident, None)
                shutil.rmtree(directory, ignore_errors=True)
                return response
            body = json.loads(response.body)
            if body.get("error"):
                raise ValueError("preparation failed")
            files = _snapshot(directory)
            documents, keys, reports, blocked, incomplete = _policy(directory, files, body)
            job = {"directory": directory, "created": time.monotonic(), "state": "prepared",
                   "response": body, "files": files, "documents": documents, "keys": keys,
                   "reports": reports, "blocked": blocked, "incomplete": incomplete}
            with _LOCK:
                _JOBS[ident] = job
            return JSONResponse(_describe(ident, job))
        except Exception:  # noqa: BLE001 - never disclose file contents or paths in an error
            with _LOCK:
                _JOBS.pop(ident, None)
            shutil.rmtree(directory, ignore_errors=True)
            return JSONResponse({"error": "Preparation failed. No copy was released."}, status_code=500)
        finally:
            STAGE_DIRECTORY.reset(token)
    return wrapped


def _get(ident):
    _purge()
    job = _JOBS.get(ident) if isinstance(ident, str) else None
    if not job or job["state"] != "prepared":
        raise ValueError("Prepared job is unavailable or expired; prepare it again.")
    return job


def _unchanged(job):
    return _snapshot(job["directory"]) == job["files"]


def release(ident, inspected, exception_reason=""):
    from .paths import data_dir
    with _LOCK:
        job = _get(ident)
        if inspected is not True:
            raise ValueError("Inspect the prepared copy before releasing it.")
        if job["blocked"]:
            raise ValueError("Release blocked: resolve the recovery or processing failures.")
        if not isinstance(exception_reason, str) or len(exception_reason) > 2000:
            raise ValueError("Invalid exception note.")
        exception_reason = exception_reason.strip()
        if job["incomplete"] and len(exception_reason) < 12:
            raise ValueError("Record a specific manual-review exception for the incomplete checks.")
        if not _unchanged(job):
            job["state"] = "invalidated"
            raise ValueError("Prepared files changed. The review is invalid; prepare the document again.")
        export_root = data_dir() / "exports"
        export_root.mkdir(mode=0o700, exist_ok=True)
        if export_root.is_symlink():
            raise OSError("invalid export directory")
        pending = Path(tempfile.mkdtemp(prefix=".publish-", dir=data_dir()))
        key_directory = None
        published = False
        try:
            published_hashes = {}
            for name, record in job["files"].items():
                if name in job["keys"]:
                    continue
                data = _read(job["directory"] / name, record["size"])
                if _digest(data) != record["sha256"]:
                    raise ValueError("Prepared files changed; release cancelled.")
                target = pending / name
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                with target.open("xb") as file:
                    file.write(data)
                    file.flush()
                    os.fsync(file.fileno())
                # Verify the written destination, not only the bytes we intended to copy.
                if _digest(_read(target, record["size"])) != record["sha256"]:
                    raise OSError("Publication readback differed from prepared evidence.")
                published_hashes[name] = record
            receipt = {"schema": "lawbat.release/1", "preparation_id": ident,
                       "released_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "manual_inspection_confirmed": True,
                       "manual_exception": exception_reason or None,
                       "limitations": job["incomplete"], "files": published_hashes,
                       "note": "Workflow record, not a safety certification or durable compliance audit."}
            receipt_data = json.dumps(receipt, ensure_ascii=False, indent=2).encode("utf-8")
            with (pending / "release-receipt.json").open("xb") as file:
                file.write(receipt_data)
                file.flush()
                os.fsync(file.fileno())
            if not _unchanged(job):
                raise ValueError("Prepared files changed; release cancelled.")
            # Never publish a key alongside a deliverable. Preserve it separately.
            if job["keys"]:
                key_directory = data_dir() / "reidentification-keys" / ident
                key_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
                for name in job["keys"]:
                    data = _read(job["directory"] / name)
                    if _digest(data) != job["files"][name]["sha256"]:
                        raise ValueError("Prepared key changed; release cancelled.")
                    with (key_directory / Path(name).name).open("xb") as file:
                        file.write(data)
                        file.flush()
                        os.fsync(file.fileno())
            package = "release-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + secrets.token_hex(8)
            destination = export_root / package
            rename_no_replace(pending, destination)
            published = True
            result = dict(job["response"])
            for field in ("filename", "report_filename", "report_txt_filename", "batch_dir"):
                if isinstance(result.get(field), str):
                    result[field] = package + "/" + result[field]
            result.update(prepared=False, released=True, release_package=package,
                          key_filename=None, key_retained_separately=bool(key_directory),
                          key_reference=ident if key_directory else None,
                          release_receipt=package + "/release-receipt.json")
            job["state"] = "released"
            shutil.rmtree(job["directory"], ignore_errors=True)
            del _JOBS[ident]
            return result
        finally:
            shutil.rmtree(pending, ignore_errors=True)
            if key_directory is not None and not published:
                shutil.rmtree(key_directory, ignore_errors=True)


def install_routes(router, require_token):
    guards = [Depends(require_token)]

    @router.post("/api/redaction/prepared-preview", dependencies=guards)
    def preview(payload: dict = Body(...)):
        try:
            with _LOCK:
                job = _get(payload.get("preparation_id"))
                name = payload.get("filename")
                if not isinstance(name, str) or name not in job["documents"] or not _unchanged(job):
                    raise ValueError("Prepared file is unavailable or changed.")
                data = _read(job["directory"] / name)
                if payload.get("report") is True:
                    return JSONResponse({"text": _read(job["directory"] / (name + ".report.txt"), 8 * 1024 * 1024).decode("utf-8")})
                if name.lower().endswith(".pdf"):
                    import fitz
                    from .imageredact import _bounded_pixmap
                    with fitz.open(stream=data, filetype="pdf") as doc:
                        page = payload.get("page", 1)
                        if type(page) is not int or not 1 <= page <= len(doc):
                            raise ValueError("Page number is out of range.")
                        pix = _bounded_pixmap(doc[page - 1], 100)
                        return JSONResponse({"image": base64.b64encode(pix.tobytes("png")).decode("ascii"),
                                             "pages": len(doc), "page": page})
                return JSONResponse({"text": data.decode("utf-8")})
        except (OSError, ValueError, KeyError, RuntimeError):
            return JSONResponse({"error": "Could not inspect this prepared file. Nothing was released."}, status_code=400)

    @router.post("/api/redaction/release", dependencies=guards)
    def publish(payload: dict = Body(...)):
        try:
            return JSONResponse(release(payload.get("preparation_id"), payload.get("inspected"), payload.get("exception_reason", "")))
        except ValueError as error:
            return JSONResponse({"error": str(error)}, status_code=409)
        except OSError:
            return JSONResponse({"error": "Publication failed. No completed release was created."}, status_code=500)

    @router.post("/api/redaction/discard-prepared", dependencies=guards)
    def discard(payload: dict = Body(...)):
        with _LOCK:
            try:
                job = _get(payload.get("preparation_id"))
            except ValueError:
                return JSONResponse({"error": "Prepared job is unavailable."}, status_code=404)
            shutil.rmtree(job["directory"], ignore_errors=True)
            del _JOBS[payload["preparation_id"]]
        return JSONResponse({"ok": True, "released": False})
