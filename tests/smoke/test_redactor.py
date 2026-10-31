"""
Standalone Redactor variant smoke tests: create_redactor_app serves the redaction
reviewer as the WHOLE app (redaction page at /, /api/redaction/* only), keeps the
token guard + air-gap guarantee, exposes NONE of Lawbat's data-room / index / reid-risk
surface, and the sector-agnostic copy pass didn't weaken any honest-framing string.
"""

import os
import tempfile

# Isolate the app-data dir BEFORE any app import (mirrors the package __init__; setdefault
# keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.web import create_app, create_redactor_app, AppState  # noqa: E402


def test_redactor_serves_redaction_page_at_root():
    """GET / on the Redactor app returns the SAME assembled redaction reviewer Lawbat
    serves at /redaction: 200, self-contained, carries the session token, and references
    NOTHING over http(s) (the strict air-gap guard the shared page already passes)."""
    state = AppState()
    c = TestClient(create_redactor_app(state))
    page = c.get("/")
    assert page.status_code == 200, page.text
    body = page.text
    # It IS the redaction reviewer (title + the honest engine posture banner).
    assert "Redaction reviewer" in body
    # the per-session token is injected so the page's api() can echo it back
    assert state.token in body, "token must be injected into the Redactor page"
    # AIR-GAP: the served page must reference NO external resource (same strict guard).
    assert "http://" not in body and "https://" not in body, \
        "Redactor page must not reference any external (http/https) resource"


def test_redactor_has_no_dataroom_index_or_reidrisk_routes():
    """STRUCTURAL: the Redactor exposes ONLY / + /api/redaction/* (the redaction surface).
    None of Lawbat's data-room / index / sources / tools / reid-risk / Home routes exist —
    introspected from the route table so a future accidental mount fails here."""
    state = AppState()
    app = create_redactor_app(state)
    paths = {r.path for r in app.routes if isinstance(r, APIRoute)}

    # The redaction API IS present (at least scan + the health probe).
    assert "/api/redaction/scan" in paths, paths
    assert "/api/redaction/health" in paths, paths

    # NONE of the Lawbat-only surface is mounted.
    forbidden_exact = {
        "/app", "/reid-risk", "/api/state", "/api/about", "/api/home",
        "/api/search", "/api/files", "/api/open", "/api/close",
    }
    leaked_exact = forbidden_exact & paths
    assert not leaked_exact, f"Redactor leaked Lawbat routes: {sorted(leaked_exact)}"

    forbidden_prefixes = ("/api/index", "/api/sources", "/api/tools", "/api/reidrisk")
    leaked_prefix = [p for p in paths
                     if any(p.startswith(pre) for pre in forbidden_prefixes)]
    assert not leaked_prefix, f"Redactor leaked Lawbat routes: {sorted(leaked_prefix)}"

    # And the GET / page route exists (served as an HTML route, not an APIRoute path is fine).
    all_paths = {getattr(r, "path", None) for r in app.routes}
    assert "/" in all_paths


def test_redactor_token_guard_is_structural_and_parity():
    """The shared token guard covers the Redactor too: every state-changing route carries
    require_token, the guarded GET /api/redaction/sample stays guarded, and the 403 body is
    byte-identical to Lawbat's ({"error":"forbidden"}). Also re-checks create_app so the ONE
    guard implementation is verified on BOTH factories."""
    def has_guard(route):
        return any(getattr(dep.call, "__name__", "") == "require_token"
                   for dep in route.dependant.dependencies)

    for factory in (create_app, create_redactor_app):
        state = AppState()
        app = factory(state)
        api_routes = [r for r in app.routes if isinstance(r, APIRoute)]
        assert api_routes, f"{factory.__name__}: no APIRoutes found"
        state_changing = {"POST", "PUT", "PATCH", "DELETE"}
        unguarded = [r.path for r in api_routes
                     if (r.methods or set()) & state_changing and not has_guard(r)]
        assert not unguarded, (
            f"{factory.__name__}: state-changing routes missing the token guard: {unguarded}")

    # Redactor-specific: the deliberately guarded GET + 403 parity, no token header.
    state = AppState()
    app = create_redactor_app(state)
    api_routes = [r for r in app.routes if isinstance(r, APIRoute)]
    sample = [r for r in api_routes if r.path == "/api/redaction/sample"]
    assert sample and has_guard(sample[0]), "/api/redaction/sample must stay token-guarded"

    c = TestClient(app)  # NOTE: no token header
    r = c.post("/api/redaction/scan", json={"text": "x"})
    assert r.status_code == 403, r.status_code
    assert r.content == b'{"error":"forbidden"}', r.content
    # With the correct token, auth passes (not a 403 — content may 200/503 on engine state).
    r2 = c.post("/api/redaction/scan", json={"text": "x"},
                headers={"X-DRR-Token": state.token})
    assert r2.status_code != 403, r2.text


def test_redactor_body_size_ceiling_applies():
    """The shared pre-auth 128 MiB body ceiling is installed on the Redactor too: an
    over-ceiling declared Content-Length is 413'd BEFORE the token check (a 413, not a 403)."""
    from app.web import _MAX_REQUEST_BODY_BYTES

    state = AppState()
    c = TestClient(create_redactor_app(state))
    over = str(_MAX_REQUEST_BODY_BYTES + 1)
    r = c.post("/api/redaction/scan", content=b"{}",
               headers={"Content-Length": over, "Content-Type": "application/json"})
    assert r.status_code == 413, r.status_code


def test_copy_pass_kept_honest_framing_and_neutralized_sector_copy():
    """The sector-agnostic copy pass reworded legal-specific strings WITHOUT weakening any
    honest-framing text. Asserted against the ASSEMBLED page (HTML + inlined JS) both apps
    serve — the redaction page is SHARED, so this covers Lawbat's /redaction too."""
    state = AppState()
    page = TestClient(create_redactor_app(state)).get("/").text

    # Honest-framing spine — MUST survive verbatim (never weakened by the copy pass):
    assert "safe to send" in page, "the never-safe-to-send framing must survive"
    assert "Always read the result yourself" in page
    assert "no AI, no model calls" in page, "the rule-based / no-AI footer must survive"
    # the honest over-report gap the UI warns on (engine could-not-remove) is still wired
    assert "could_not_remove" in page, "the could_not_remove honesty field must survive"
    # the scanned/no-text-layer loud warning path + the errored-scan stepper lock survive
    assert "low_text" in page
    assert "markScanFailed" in page, "the scan-error stepper hard-lock must survive"

    # Sector references neutralized (generic now, reads in both contexts):
    assert "reference numbers" in page and "matter numbers" not in page
    assert "Paste a document, an email" in page and "Paste a contract" not in page
    assert "Confidentiality / sensitive-content review" in page
    assert "Confidentiality / privilege review" not in page
