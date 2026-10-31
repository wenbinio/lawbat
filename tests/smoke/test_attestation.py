"""Redaction attestation: hashes and counts only, token-guarded to build."""

import hashlib
import json
import os
import tempfile

os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app.attestation import (  # noqa: E402
    attestation_from_report,
    build_attestation,
    sample_attestation,
)
from app.web import AppState, create_app  # noqa: E402

_DOC = hashlib.sha256(b"redacted-output").hexdigest()


def _report():
    return {
        "schema": "lawbat.redaction-report/0",
        "original": {"filename": "client-letter.pdf", "sha256": "ab" * 32},
        "output": {"filename": "client-letter.redacted.pdf", "sha256": _DOC},
        "reviewer": "Ada Lovelace",
        "per_recognizer": {"phone": 1, "email": 2},
        "accepted": 3,
        "rejected": 1,
        "could_not_remove": 0,
        "ocr_used": False,
        "verification": {"state": "checked"},
        "engine": {"redact_cli_path": "/tmp/secret/redact-cli"},
    }


def test_attestation_from_report_drops_names_and_original_hash():
    att = attestation_from_report(_report(), reid_k=12.5, timestamp="2026-10-31T00:00:00Z")
    blob = json.dumps(att)
    assert "client-letter" not in blob
    assert "Ada Lovelace" not in blob
    assert "ab" * 32 not in blob
    assert "/tmp/secret" not in blob
    assert att["document_sha256"] == _DOC
    assert att["counts_by_category"] == {"email": 2, "phone": 1}
    assert att["reid_risk"]["level"] == "high"
    assert att["reid_risk"]["level_code"] == 2
    assert "safe" not in att["note"]


def test_attestation_report_hash_ignores_confidential_report_fields():
    first = attestation_from_report(_report(), reid_k=4, timestamp="2026-10-31T00:00:00Z")
    other = _report()
    other["reviewer"] = "Someone Else"
    other["original"]["filename"] = "other-name.docx"
    second = attestation_from_report(other, reid_k=99, timestamp="2026-10-31T01:02:03Z")
    assert first["report_sha256"] == second["report_sha256"]
    assert first["reid_risk"]["level"] != second["reid_risk"]["level"]


def test_attestation_risk_levels_never_clear_a_document():
    unique = build_attestation(document_sha256=_DOC, reid_k=1, timestamp="2026-10-31T00:00:00Z")
    noted = build_attestation(document_sha256=_DOC, reid_k=21, timestamp="2026-10-31T00:00:00Z")
    missing = build_attestation(document_sha256=_DOC, timestamp="2026-10-31T00:00:00Z")
    assert unique["reid_risk"]["level_code"] == 3
    assert noted["reid_risk"]["level"] == "noted"
    assert missing["reid_risk"]["level"] == "not_assessed"
    assert "clear" not in unique["reid_risk"]["level"]


def test_attestation_sample_is_deterministic_and_fictional():
    att = sample_attestation()
    assert att["timestamp"] == "2026-10-31T00:00:00Z"
    assert att["document_sha256"] == hashlib.sha256(b"lawbat-sample-redacted-output-v1").hexdigest()
    assert att["reid_risk"]["k"] == 12.5
    again = sample_attestation()
    assert again == att


def test_attestation_endpoint_requires_token_and_hides_report_text():
    state = AppState()
    client = TestClient(create_app(state))
    body = {"report": _report(), "reid_k": 12.5, "text": "privileged sentence"}
    denied = client.post("/api/attestation", json=body)
    assert denied.status_code == 403
    assert denied.content == b'{"error":"forbidden"}'

    rejected = client.post(
        "/api/attestation",
        json=body,
        headers={"X-DRR-Token": state.token},
    )
    assert rejected.status_code == 400, rejected.text
    assert "privileged" not in rejected.text
    assert "client-letter" not in rejected.text

    ok = client.post(
        "/api/attestation",
        json={"report": _report(), "reid_k": 12.5},
        headers={"X-DRR-Token": state.token},
    )
    assert ok.status_code == 200, ok.text
    assert "client-letter" not in ok.text
    assert "Ada Lovelace" not in ok.text
    latest = client.get("/api/attestation/latest")
    assert latest.status_code == 200
    assert latest.json()["document_sha256"] == _DOC
    assert latest.json()["report_sha256"] == ok.json()["report_sha256"]
