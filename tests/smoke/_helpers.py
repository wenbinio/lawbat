"""
Shared fixtures + helpers for the split smoke suite.

Extracted verbatim from the old monolithic tests/test_smoke.py so the per-area smoke
modules (tests/smoke/test_*.py) can share the TestClient factory, the index/job poll
helpers, and the bundled fixtures. The app-data isolation env is (re)asserted here too
so importing this module is safe before any app import; setdefault => the first importer
in the process wins and everything shares ONE throwaway data dir.
"""

import os
import tempfile
import time  # noqa: F401 - used by the poll helpers below
from pathlib import Path

# Isolate the app-data dir to a fresh temp dir so tests don't share matter DBs (and don't
# collide with a real install or the e2e run). Must be set before any app.* import.
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
# Never actually launch a viewer/file-manager during tests.
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402
from app.web import create_app, AppState  # noqa: E402

# The repo-root _testfixtures dir (this file is tests/smoke/_helpers.py -> three parents up).
FIXTURES = str(Path(__file__).resolve().parent.parent.parent / "_testfixtures")


_BIO_FIXTURE = (
    "[REDACTED] joined J. P. Morgan in 2007 at the CIB Product Control for the Currency "
    "and Emerging Markets (CEM) Trading Desk in Brazil. In 2008, he moved to Asset & "
    "Wealth Management as the Risk Manager responsible for portfolio risk oversight, "
    "operational risk and governance on both businesses. In 2015, he moved to AM Risk in "
    "London, covering Emerging Market Strategies. He expanded his coverage to Multi-Asset "
    "Solutions in 2018 and to the Alternatives Investment Platform in 2023. His team is "
    "based in UK, Luxembourg, India, US and Hong Kong. [REDACTED] was appointed as Asset "
    "Management's EMEA Chief Risk Officer in 2025."
)


def _client():
    """A TestClient whose POSTs carry the per-session token (H-8).

    The server mints a token per AppState and embeds it in the served page; the
    state-changing endpoints (index, open/close, file open/reveal, rename
    apply/undo, manifest export) require it via the X-DRR-Token header. We set it
    as a default header on the client so every request is authorized, mirroring
    the real page's `api()` helper."""
    state = AppState()
    client = TestClient(create_app(state))
    client.headers.update({"X-DRR-Token": state.token})
    return client


def _index_into(client, folder):
    client.post("/api/index", json={"folder": folder})
    for _ in range(100):
        if client.get("/api/index/status").json()["status"] in ("done", "error"):
            return
        time.sleep(0.1)


# ---------------------------------------------------------------- multi-source --
def _wait_index(client, folder, **extra):
    body = {"folder": folder}
    body.update(extra)
    client.post("/api/index", json=body)
    for _ in range(100):
        if client.get("/api/index/status").json()["status"] in ("done", "error"):
            return
        time.sleep(0.1)


def _wait_job(client):
    """Poll the shared index job to completion. /api/sources/add[-files] now run in
    the BACKGROUND (mirroring /api/index — the lock is NOT held across the walk), so a
    test must wait for the job to finish before asserting on the added files/sources."""
    for _ in range(100):
        if client.get("/api/index/status").json()["status"] in ("done", "error"):
            return
        time.sleep(0.1)


def _add_source_and_wait(client, **body):
    """POST /api/sources/add and wait for the background add to finish. Returns the
    kick-off response (the work happens in the worker; poll the job for completion)."""
    r = client.post("/api/sources/add", json=body)
    if r.status_code == 200:
        _wait_job(client)
    return r


def _reidrisk():
    from app import reidrisk
    return reidrisk


# ---------------------------------------------------------- assembled UI JS ----
def _assembled_js_tmpfile(filenames):
    """Concatenate the named app/ui/*.js files, IN ORDER, into ONE temp file — the same
    concatenation app.web._build_page() performs (minus the HTML/marker wrapper), so a node
    harness that wants "the assembled page JS" can load ONE file path. Needed because
    redaction.js was split into fragments (app.ui_manifest.REDACTION_JS_PARTS) that are not
    each independently valid JavaScript — only the assembled concatenation is. The caller
    gets back a Path to a temp file that is NOT auto-deleted (ephemeral test/CI runners
    clean it up; the file is tiny)."""
    ui_dir = Path(__file__).resolve().parent.parent.parent / "app" / "ui"
    text = "\n".join((ui_dir / fn).read_text(encoding="utf-8") for fn in filenames)
    tf = tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", delete=False, encoding="utf-8")
    tf.write(text)
    tf.close()
    return Path(tf.name)


def _assembled_redaction_js_path():
    """The FULL script redaction.html actually ships: base.js (window.LB) + every
    redaction.*.js fragment, in the ONE order app.ui_manifest.REDACTION_JS_PARTS defines."""
    from app.ui_manifest import BASE_JS, REDACTION_JS_PARTS

    return _assembled_js_tmpfile([BASE_JS] + REDACTION_JS_PARTS)


def _assembled_reidrisk_js_path():
    """The FULL script reidrisk.html ships: base.js (window.LB) + reidrisk.js — reidrisk.js
    itself no longer carries its own esc()/$()/post()/announce() (aliased to LB), so a node
    harness must load base.js first for LB to exist."""
    from app.ui_manifest import BASE_JS

    return _assembled_js_tmpfile([BASE_JS, "reidrisk.js"])


def _prepared_result(data):
    """Inspect preparation internals in legacy report/format unit tests.

    This NEVER releases an output or changes the API response. These older tests
    check formatter/report semantics, including deliberately malformed fake PDFs.
    Assertions now read PRIVATE staged files. Real publication, refusal, attestation,
    tampering and keys are separately exercised in test_redactor_release_hardening.
    """
    if not isinstance(data, dict) or data.get("prepared") is not True:
        return data
    from app import releaseflow
    from app.paths import data_dir
    assert "filename" not in data, "Preparation must not masquerade as released output"
    job = releaseflow._JOBS[data["preparation_id"]]
    directory = job["directory"].resolve()
    assert not directory.is_relative_to((data_dir() / "exports").resolve())
    assert job["state"] == "prepared"
    result = dict(job["response"])
    result["_test_prepared_root"] = directory
    result["_test_prepared_manifest"] = data
    return result


def _prepared_root(data):
    """Only resolves a private job already inspected by _prepared_result."""
    return data["_test_prepared_root"]


def _clear_prepared_test_jobs():
    """Per-test teardown: avoid leaking bounded process-local jobs between tests."""
    import shutil
    from app import releaseflow, documentreview
    with releaseflow._LOCK:
        for job in releaseflow._JOBS.values():
            shutil.rmtree(job["directory"], ignore_errors=True)
        releaseflow._JOBS.clear()
    with documentreview._LOCK:
        documentreview._PLANS.clear()
