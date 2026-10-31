"""
Web/host-shell smoke tests: Home + data-room pages, view-model, about,
logging, token-guard structure, page-build guards (split from tests/test_smoke.py).
"""

import logging
import os
import tempfile
import time
from pathlib import Path

# Isolate the app-data dir BEFORE any app import (belt-and-suspenders alongside the
# package __init__; setdefault keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402
from app.web import create_app, AppState  # noqa: E402
from tests.smoke._helpers import (  # noqa: E402
    _client, FIXTURES,
)


def test_state_changing_endpoints_require_token():
    """H-8: a localhost POST without the session token is rejected (403); with it,
    accepted. GETs stay open. The token is embedded in the served page so the real
    UI (and only a same-origin caller) can read it."""
    state = AppState()
    c = TestClient(create_app(state))  # NOTE: no default token header here

    # the served page carries the token (so the page's JS can echo it back)
    page = c.get("/").text
    assert state.token in page, "token must be injected into the served HTML"

    # GET endpoints remain reachable without a token
    assert c.get("/api/state").status_code == 200

    # a state-changing POST WITHOUT the token is forbidden
    assert c.post("/api/index", json={"folder": FIXTURES}).status_code == 403
    assert c.post("/api/file/open", json={"path": "x"}).status_code == 403
    assert c.post("/api/tools/rename/undo", json={"manifest": "x"}).status_code == 403
    # rename/PLAN is token-guarded too (#21): it reads a folder, runs the confinement
    # check, and mints a plan_token — an untrusted local caller must not reach it.
    assert c.post("/api/tools/rename/plan",
                  json={"folder": FIXTURES, "rules": {}}).status_code == 403
    assert c.post("/api/tools/rename/plan", json={"folder": FIXTURES, "rules": {}},
                  headers={"X-DRR-Token": "wrong"}).status_code == 403
    # with the correct token it is no longer a 403 (auth passes; content may 200/400).
    assert c.post("/api/tools/rename/plan", json={"folder": FIXTURES, "rules": {}},
                  headers={"X-DRR-Token": state.token}).status_code != 403

    # a wrong token is forbidden too
    assert c.post("/api/index", json={"folder": FIXTURES},
                  headers={"X-DRR-Token": "wrong"}).status_code == 403

    # with the correct token, the same call is accepted (not 403)
    ok = c.post("/api/index", json={"folder": FIXTURES},
                headers={"X-DRR-Token": state.token})
    assert ok.status_code != 403, ok.text


def test_esc_escapes_quote_and_backtick():
    """C2: the SHARED esc() helper must escape the single quote (') and backtick (`), not
    just & < > " — else a matter path like O'Brien breaks out of an onclick attribute or a
    data-* attribute. Asserted against the SHIPPED JS source.

    esc() now has exactly ONE implementation, app/ui/base.js's window.LB.esc — every page
    (home/dataroom/redaction/reid-risk) aliases it (`var esc = LB.esc;` or similar) rather
    than carrying its own copy, so this checks base.js AND that no page redefines esc()."""
    ui = Path(__file__).resolve().parent.parent.parent / "app" / "ui"
    src = (ui / "base.js").read_text(encoding="utf-8")
    # the esc() implementation (chained per-character .replace()) must cover ' and `
    assert ".replace(/'/g,'&#39;')" in src, "base.js: esc() must map ' to &#39;"
    assert ".replace(/`/g,'&#96;')" in src, "base.js: esc() must map ` to &#96;"

    # every page consumes the shared implementation rather than redefining its own.
    for fname in ("home.js", "dataroom.js", "redaction.core.js", "reidrisk.js"):
        page_src = (ui / fname).read_text(encoding="utf-8")
        assert "LB.esc" in page_src, f"{fname}: must alias the shared LB.esc, not redefine esc()"


def test_about_and_version():
    from app import __version__
    c = _client()

    # version is surfaced on the always-available state endpoint…
    assert c.get("/api/state").json()["version"] == __version__

    # …and the support-facing About endpoint reports where data + logs live.
    a = c.get("/api/about").json()
    assert a["version"] == __version__
    assert isinstance(a["fts5"], bool)
    assert a["python"] and a["platform"]
    # data_dir must be the isolated test dir, never a real install. Compare as
    # Paths, not raw strings (Windows normalizes separators / drive case).
    assert Path(a["data_dir"]) == Path(os.environ["LAWDATAMAN_DATA_DIR"])
    assert a["log_file"].endswith("dataroomreview.log")
    assert Path(a["log_file"]).parent.is_dir()


def test_home_is_landing_page():
    """firmOS HOME is the app's landing page (GET /): 200, self-contained, carries
    the session token, and inlines the extracted app/ui/* (no <link>/<script src>)."""
    state = AppState()
    c = TestClient(create_app(state))
    page = c.get("/")
    assert page.status_code == 200, page.text
    body = page.text
    # extracted UI is inlined into one document
    assert "firmOS HOME styles" in body, "home.css must be inlined"
    assert "function esc(" in body, "home.js must be inlined"
    # the per-session token is injected so the page's api() can echo it back
    assert state.token in body, "token must be injected into the Home page"
    # AIR-GAP guard: the landing page must reference NO external resource
    assert "http://" not in body and "https://" not in body, \
        "Home must not reference any external (http/https) resource"
    # the honest-limit caveat control is present in the shell
    assert "Ignore all further warnings" in body
    # an esc()/escaping helper exists and is used (host escapes all cleartext)
    assert "&amp;" in body and "&lt;" in body and "&gt;" in body


def test_home_view_model_contract():
    """GET /api/home returns the firmos.view/0 contract the page renders. Without
    the Rust bin it falls back to the bundled sample, marked preview:true — and the
    worklist (sections/cards/badges/due/caveat/actions) comes through."""
    c = _client()
    v = c.get("/api/home").json()
    assert v["schema"] == "firmos.view/0", v
    assert v["preview"] is True, "no Rust bin in tests -> preview fallback"
    assert v["generated_label"]
    # the worklist renders from the contract: sections with cards
    sections = v["sections"]
    assert sections and any(s["cards"] for s in sections)
    # a card carries the contract's badges / due / actions shapes
    card = next(card for s in sections for card in s["cards"])
    assert "title" in card and "subtitle" in card
    assert isinstance(card["badges"], list) and card["badges"]
    assert {"kind", "label"} <= set(card["badges"][0])
    assert "actions" in card and {"action_id", "label", "target"} <= set(card["actions"][0])
    # 'due' is the {kind,text}|null shape
    dues = [card.get("due") for s in sections for card in s["cards"]]
    assert any(d and {"kind", "text"} <= set(d) for d in dues)
    # the honest-limit caveat is carried on a section, dismissible
    caveats = [cv for s in sections for cv in s.get("caveats", [])]
    assert caveats, "expected at least one honest-limit caveat"
    assert {"id", "message", "dismissible"} <= set(caveats[0])
    assert any(cv["dismissible"] for cv in caveats)


def test_viewgen_locator_and_fallback():
    """The viewgen locator mirrors vendor.py (env override), a live bin's contract
    is used (preview:false), and ANY failure falls back to the sample (preview:true)
    without raising — the Home can never be taken down by a missing/broken bin."""
    import stat
    from app import viewmodel

    d = Path(tempfile.mkdtemp())

    # a fake viewgen that emits a valid contract -> used as live (preview False)
    good = d / "goodgen"
    good.write_text('#!/bin/sh\n'
                    'echo \'{"schema":"firmos.view/0","generated_label":"LIVE",'
                    '"sections":[]}\'\n')
    good.chmod(good.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # a fake viewgen that exits non-zero -> fallback
    bad = d / "badgen"
    bad.write_text('#!/bin/sh\nexit 3\n')
    bad.chmod(bad.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # Locator honors the env override (mirrors vendor.bundled_tool)
    os.environ["LAWDATAMAN_VIEWGEN"] = str(good)
    try:
        assert viewmodel.viewgen_path() == str(good)
        if os.name != "nt":  # the /bin/sh shim only runs on POSIX
            v = viewmodel.get_home_view()
            assert v["generated_label"] == "LIVE" and v["preview"] is False, v

        # a failing bin must fall back to the bundled sample, never raise
        os.environ["LAWDATAMAN_VIEWGEN"] = str(bad)
        v = viewmodel.get_home_view()
        assert v["schema"] == "firmos.view/0" and v["preview"] is True, v
    finally:
        os.environ.pop("LAWDATAMAN_VIEWGEN", None)

    # missing bin -> bundled sample, preview, valid contract
    v = viewmodel.get_home_view()
    assert v["preview"] is True and isinstance(v["sections"], list)


def test_data_room_still_reachable_from_home():
    """The data room is now a MODULE reached from Home (/app), not the landing page,
    but stays fully reachable + token-carrying; search/Tools APIs are unchanged."""
    state = AppState()
    c = TestClient(create_app(state))
    c.headers.update({"X-DRR-Token": state.token})
    page = c.get("/app")
    assert page.status_code == 200, page.text
    assert state.token in page.text, "data-room page must still carry the token"
    # the existing data-room API the page drives is unchanged
    assert c.get("/api/state").status_code == 200
    # index/search still works against the data-room module
    c.post("/api/index", json={"folder": FIXTURES})
    for _ in range(100):
        if c.get("/api/index/status").json()["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert c.get("/api/search", params={"q": "change of control"}).json()["results"]


def test_logging_captures_uncaught_thread_exception():
    # Crash handling: an uncaught exception on a worker thread (the indexer runs on
    # one) must land in the log file instead of vanishing — there is no console in
    # the shipped app.
    import threading
    from app.logsetup import setup_logging

    logfile = Path(setup_logging("test"))
    marker = "ldm-test-boom-" + str(time.time())

    def boom():
        raise RuntimeError(marker)

    t = threading.Thread(target=boom)
    t.start()
    t.join()

    for h in logging.getLogger("dataroomreview").handlers:
        h.flush()
    assert marker in logfile.read_text(encoding="utf-8")


def test_route_table_token_guard_is_structural():
    """Token-guard-as-dependency refactor: EVERY state-changing route (POST/PUT/PATCH/
    DELETE) in the app's route table must carry the declarative require_token dependency
    — introspected from the route table itself, so a future state-changing route added
    WITHOUT the guard fails here instead of shipping open. Also pins the guarded GET
    (/api/redaction/sample) and the byte-level parity of the rejection with the legacy
    imperative guard: 403 with exactly {"error":"forbidden"} (the UI JS may match on it)."""
    from fastapi.routing import APIRoute

    state = AppState()
    app = create_app(state)

    def has_guard(route):
        return any(getattr(dep.call, "__name__", "") == "require_token"
                   for dep in route.dependant.dependencies)

    api_routes = [r for r in app.routes if isinstance(r, APIRoute)]
    assert api_routes, "route-table introspection found no APIRoutes"
    state_changing = {"POST", "PUT", "PATCH", "DELETE"}
    unguarded = [r.path for r in api_routes
                 if (r.methods or set()) & state_changing and not has_guard(r)]
    assert not unguarded, f"state-changing routes missing the token guard: {unguarded}"

    # The deliberately guarded GETs (a uniform surface over the redaction endpoints).
    sample = [r for r in api_routes if r.path == "/api/redaction/sample"]
    assert sample and has_guard(sample[0]), "/api/redaction/sample must stay token-guarded"
    # /api/redaction/health SPAWNS THE BIN on every call (a real round-trip, not a
    # path-exists check) — an unguarded GET would let any local caller repeatedly fork the
    # redact-cli process, so it is guarded like /sample even though it is read-only.
    health = [r for r in api_routes if r.path == "/api/redaction/health"]
    assert health and has_guard(health[0]), "/api/redaction/health must stay token-guarded"

    # Rejection parity: same status, byte-identical body to the pre-dependency guard.
    c = TestClient(app)  # NOTE: no token header
    r = c.post("/api/close")
    assert r.status_code == 403, r.status_code
    assert r.content == b'{"error":"forbidden"}', r.content
    r2 = c.post("/api/close", headers={"X-DRR-Token": "wrong"})
    assert r2.status_code == 403 and r2.content == b'{"error":"forbidden"}', r2.content


def test_page_build_missing_marker_is_a_hard_error():
    """Page-builder refactor: _build_page treats a MISSING inline marker as a HARD build
    error (RuntimeError naming the marker) — never the silent str.replace no-op that
    would ship a page without its css/js. A present marker still inlines normally, and
    the shipped pages all assemble (the module-level *_PAGE constants built at import)."""
    import tempfile as _tempfile
    from app import web

    with _tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "stub.html").write_text(
            "<html><style>/* __STUB_CSS__ */</style></html>", encoding="utf-8")
        (d / "stub.css").write_text("body{color:#000}", encoding="utf-8")
        (d / "stub.js").write_text("var x=1;", encoding="utf-8")

        # Present marker: assembles, inlines, and strips the marker.
        page = web._build_page("stub.html", [("/* __STUB_CSS__ */", "stub.css")],
                               label="Stub", guard=web._airgap_strict, ui_dir=d)
        assert "body{color:#000}" in page and "__STUB_CSS__" not in page

        # Missing marker: a hard error naming the marker — NOT a silent no-op.
        try:
            web._build_page("stub.html", [("/* __MISSING__ */", "stub.js")],
                            label="Stub", guard=web._airgap_strict, ui_dir=d)
        except RuntimeError as e:
            assert "__MISSING__" in str(e), e
        else:
            raise AssertionError("a missing inline marker must raise at build time")

    # The four shipped pages assembled at import (a missing real marker would have
    # aborted the import of app.web itself).
    for const in (web.HOME_PAGE, web.PAGE, web.REDACTION_PAGE, web.REIDRISK_PAGE):
        assert isinstance(const, str) and const
