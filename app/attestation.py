"""Privacy-preserving redaction attestation.

A redaction report can name files and a reviewer. This module builds the record
that is allowed to leave the machine: the SHA-256 of the redacted output, a hash
of the non-confidential report projection, category counts, a re-identification
risk level, the tool version, and a timestamp. No document text, filename, or
party name is copied into the attestation.

The risk level is a concern signal. It is never a clearance to disclose.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .reidrisk import K_HIGH_RISK_CEILING, K_UNIQUE_CEILING

SCHEMA = "lawbat.redaction-attestation/1"
PROJECTION_SCHEMA = "lawbat.redaction-report-projection/1"
NOTE = (
    "hashes and counts only; no document text leaves this record. "
    "Not a clearance to disclose the document."
)
SAMPLE_TIMESTAMP = "2026-10-31T00:00:00Z"
_SHA = re.compile(r"^[0-9a-f]{64}$")
_CATEGORY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_STATE = re.compile(r"^[a-z0-9_]{0,32}$")
_MAX_CATEGORIES = 32
_MAX_COUNT = 1_000_000
_REQUEST_KEYS = {
    "output_sha256",
    "counts_by_category",
    "accepted",
    "rejected",
    "could_not_remove",
    "findings",
    "ocr_used",
    "verification_state",
    "reid_k",
    "report",
}
# Top-level fields a caller must not send. Their presence means the request is
# trying to put document text or a name into the attestation, so it is refused
# without echoing the value.
_REJECTED_KEYS = {
    "text", "content", "body", "filename", "document", "name", "reviewer",
    "original", "pii", "value", "values", "terms", "path",
}


class AttestationError(ValueError):
    """The request cannot be turned into an attestation."""


def _int(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttestationError(f"{name} must be a non-negative integer")
    if value < 0 or value > _MAX_COUNT:
        raise AttestationError(f"{name} is out of range")
    return value


def _sha256(value, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AttestationError(f"{name} must be 64 lowercase hex characters")
    return value


def _counts(raw) -> dict:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise AttestationError("counts_by_category must be an object")
    if len(raw) > _MAX_CATEGORIES:
        raise AttestationError("too many redaction categories")
    out = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _CATEGORY.fullmatch(key):
            raise AttestationError("a redaction category name is not allowed")
        out[key] = _int(value, "category count")
    return {k: out[k] for k in sorted(out)}


def _risk(reid_k):
    if reid_k is None:
        score = None
        level, code = "not_assessed", 0
    else:
        if isinstance(reid_k, bool) or not isinstance(reid_k, (int, float)):
            raise AttestationError("reid_k must be a non-negative number")
        score = float(reid_k)
        if score < 0 or score != score or score == float("inf"):
            raise AttestationError("reid_k must be a non-negative number")
        if score <= K_UNIQUE_CEILING:
            level, code = "unique", 3
        elif score <= K_HIGH_RISK_CEILING:
            level, code = "high", 2
        else:
            level, code = "noted", 1
    return {
        "k": score,
        "level": level,
        "level_code": code,
        "is_estimate": True,
        "direction": "optimistic — may under-state risk",
    }


def projection_bytes(
    *,
    document_sha256: str,
    counts_by_category: dict,
    accepted: int,
    rejected: int,
    could_not_remove: int,
    ocr_used: bool,
    verification_state: str,
) -> bytes:
    """Canonical JSON of the non-confidential report facts. This is what is hashed."""
    body = {
        "schema": PROJECTION_SCHEMA,
        "document_sha256": document_sha256,
        "counts_by_category": counts_by_category,
        "accepted": accepted,
        "rejected": rejected,
        "could_not_remove": could_not_remove,
        "ocr_used": bool(ocr_used),
        "verification_state": verification_state,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_attestation(
    *,
    document_sha256: str,
    counts_by_category: dict | None = None,
    accepted: int = 0,
    rejected: int = 0,
    could_not_remove: int = 0,
    ocr_used: bool = False,
    verification_state: str = "",
    reid_k=None,
    timestamp: str | None = None,
) -> dict:
    """Assemble the attestation. Raises AttestationError on a bad input."""
    document_sha256 = _sha256(document_sha256, "document_sha256")
    counts = _counts(counts_by_category)
    accepted = _int(accepted, "accepted")
    rejected = _int(rejected, "rejected")
    could_not_remove = _int(could_not_remove, "could_not_remove")
    if not isinstance(verification_state, str) or not _STATE.fullmatch(verification_state):
        raise AttestationError("verification_state is not allowed")
    digest = hashlib.sha256(projection_bytes(
        document_sha256=document_sha256,
        counts_by_category=counts,
        accepted=accepted,
        rejected=rejected,
        could_not_remove=could_not_remove,
        ocr_used=ocr_used,
        verification_state=verification_state,
    )).hexdigest()
    when = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(when, str) or len(when) != 20 or when[10] != "T" or not when.endswith("Z"):
        raise AttestationError("timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return {
        "schema": SCHEMA,
        "note": NOTE,
        "document_sha256": document_sha256,
        "report_sha256": digest,
        "counts_by_category": counts,
        "accepted": accepted,
        "rejected": rejected,
        "could_not_remove": could_not_remove,
        "ocr_used": bool(ocr_used),
        "verification_state": verification_state,
        "reid_risk": _risk(reid_k),
        "tool_version": __version__,
        "timestamp": when,
    }


def attestation_from_report(report: dict, *, reid_k=None, timestamp: str | None = None) -> dict:
    """Project a redaction report down to an attestation.

    Filenames, the original-document hash, the reviewer name, and engine paths
    are read only so they can be ignored. They are not copied.
    """
    return build_attestation(reid_k=reid_k, timestamp=timestamp, **_facts_from_report(report))


def _facts_from_report(report: dict) -> dict:
    if not isinstance(report, dict):
        raise AttestationError("report must be an object")
    output = report.get("output") if isinstance(report.get("output"), dict) else {}
    verification = report.get("verification") if isinstance(report.get("verification"), dict) else {}
    state = verification.get("state", "")
    if state is None:
        state = ""
    if not isinstance(state, str):
        raise AttestationError("verification state must be a string")
    return {
        "document_sha256": str(output.get("sha256", "")),
        "counts_by_category": report.get("per_recognizer") or {},
        "accepted": report.get("accepted") or 0,
        "rejected": report.get("rejected") or 0,
        "could_not_remove": report.get("could_not_remove") or 0,
        "ocr_used": bool(report.get("ocr_used", False)),
        "verification_state": state,
    }


def attestation_from_request(payload: dict) -> dict:
    """Validate a POST /api/attestation body and return the attestation."""
    if not isinstance(payload, dict):
        raise AttestationError("body must be an object")
    extra = set(payload) - _REQUEST_KEYS
    if extra & _REJECTED_KEYS:
        raise AttestationError("request includes a field that must not be attested")
    if extra:
        raise AttestationError("request includes an unknown field")
    facts = _facts_from_report(payload["report"]) if "report" in payload else {
        "document_sha256": payload.get("output_sha256", ""),
        "counts_by_category": payload.get("counts_by_category"),
        "accepted": payload.get("accepted") or 0,
        "rejected": payload.get("rejected") or 0,
        "could_not_remove": payload.get("could_not_remove") or 0,
        "ocr_used": bool(payload.get("ocr_used", False)),
        "verification_state": payload.get("verification_state") or "",
    }
    if "output_sha256" in payload:
        facts["document_sha256"] = payload["output_sha256"]
    return build_attestation(reid_k=payload.get("reid_k"), **facts)


def sample_attestation(*, now: bool = False) -> dict:
    """A fictional attestation for the local CRE dry-run. No client document."""
    document = hashlib.sha256(b"lawbat-sample-redacted-output-v1").hexdigest()
    return build_attestation(
        document_sha256=document,
        counts_by_category={"email": 2, "phone": 1, "id": 1},
        accepted=4,
        rejected=1,
        could_not_remove=0,
        ocr_used=False,
        verification_state="checked",
        reid_k=12.5,
        timestamp=None if now else SAMPLE_TIMESTAMP,
    )


def _write_out(attestation: dict, path: str) -> None:
    text = json.dumps(attestation, indent=2, sort_keys=True) + "\n"
    if path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def serve(path: str, host: str, port: int) -> None:
    """Serve one already-built attestation on localhost. Nothing else is exposed."""
    if host != "127.0.0.1":
        raise AttestationError("the attestation server binds to 127.0.0.1 only")
    with open(path, encoding="utf-8") as fh:
        loaded = json.load(fh)
    if not isinstance(loaded, dict):
        raise AttestationError("attestation file must be an object")
    risk = loaded.get("reid_risk") if isinstance(loaded.get("reid_risk"), dict) else {}
    # Rebuild from the public facts and serve that object, so a text field added
    # to the file is dropped and a mismatched report hash is refused.
    checked = build_attestation(
        document_sha256=loaded.get("document_sha256", ""),
        counts_by_category=loaded.get("counts_by_category"),
        accepted=loaded.get("accepted") or 0,
        rejected=loaded.get("rejected") or 0,
        could_not_remove=loaded.get("could_not_remove") or 0,
        ocr_used=bool(loaded.get("ocr_used", False)),
        verification_state=loaded.get("verification_state") or "",
        reid_k=risk.get("k"),
        timestamp=loaded.get("timestamp"),
    )
    if checked["report_sha256"] != loaded.get("report_sha256"):
        raise AttestationError("report_sha256 does not match the attestation facts")
    if checked["reid_risk"] != loaded.get("reid_risk"):
        raise AttestationError("reid_risk does not match the score")
    body = json.dumps(checked, sort_keys=True).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            sys.stderr.write("attestation %s\n" % (fmt % args))

        def _send(self, code: int, payload: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path_only = self.path.split("?", 1)[0]
            if path_only == "/health":
                self._send(200, b'{"ok":true}\n', "application/json")
                return
            if path_only == "/attestation":
                self._send(200, body, "application/json")
                return
            self._send(404, b'{"error":"not found"}\n', "application/json")

        def do_POST(self):
            self._send(405, b'{"error":"method not allowed"}\n', "application/json")

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write(f"attestation listening on http://{host}:{port}/attestation\n")
    httpd.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or serve a redaction attestation.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    build = sub.add_parser("build", help="attest a redaction report file")
    build.add_argument("--report", required=True)
    build.add_argument("--reid-k", type=float, default=None)
    build.add_argument("--out", default="-")

    sample = sub.add_parser("sample", help="write a fictional sample attestation")
    sample.add_argument("--out", default="-")
    sample.add_argument("--now", action="store_true")

    served = sub.add_parser("serve", help="serve an attestation file on 127.0.0.1")
    served.add_argument("--file", required=True)
    served.add_argument("--port", type=int, default=8765)
    served.add_argument("--host", default="127.0.0.1")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "build":
            with open(args.report, encoding="utf-8") as fh:
                report = json.load(fh)
            _write_out(attestation_from_report(report, reid_k=args.reid_k), args.out)
            return 0
        if args.cmd == "sample":
            _write_out(sample_attestation(now=args.now), args.out)
            return 0
        serve(args.file, args.host, args.port)
        return 0
    except (AttestationError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"attestation: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
