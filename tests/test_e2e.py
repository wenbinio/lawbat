"""
End-to-end test against the REAL uvicorn server the desktop app launches
(everything except the pywebview window). Exercises the server bootstrap,
the first-run -> index -> search state machine, the document-index/manifest,
CSV export/download, and the rename preview/apply/undo roundtrip.

Run:  PYTHONPATH=. python tests/test_e2e.py

Runs on Windows CI too, so it covers the Windows-only code paths (the \\?\
long-path walker, FTS5 in the runner's Python, the socket-handoff bootstrap)
that can't be exercised on the Linux dev box.
"""

import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# Isolate the app-data dir (fresh matter DBs; no clash with the smoke run).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-e2e-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from app.web import TOKEN_HEADER, create_app, AppState  # noqa: E402
from desktop.main import _bind_localhost_socket, _start_server, _wait_until_up  # noqa: E402

FIXTURES = str(Path(__file__).resolve().parent.parent / "_testfixtures")

# Per-session token (H-8): state-changing endpoints require it. Captured from the
# AppState the test creates and sent on every POST, mirroring the real page's
# `api()` helper which reads it from the injected <meta> tag.
_TOKEN = ""


def _post(url, obj=None):
    data = json.dumps(obj or {}).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", TOKEN_HEADER: _TOKEN},
        method="POST")
    return json.loads(urllib.request.urlopen(req).read())


def _get(url):
    return json.loads(urllib.request.urlopen(url).read())


def test_end_to_end():
    global _TOKEN
    state = AppState()
    _TOKEN = state.token  # H-8: every POST below carries this via _post()
    app = create_app(state)
    sock = _bind_localhost_socket()
    port = sock.getsockname()[1]
    _start_server(app, sock)
    assert _wait_until_up(port), "server failed to come up"
    base = f"http://127.0.0.1:{port}"

    # the firmOS HOME is the landing page (GET /): self-contained, token-carrying,
    # and air-gapped (no external resource). The data room moved to /app.
    page = urllib.request.urlopen(base + "/").read().decode("utf-8")
    assert state.token in page, "token must be injected into the served HTML"
    assert "function esc(" in page, "home.js must be inlined into the Home page"
    assert "Ignore all further warnings" in page, "honest-limit caveat control missing"
    assert "http://" not in page and "https://" not in page, \
        "Home must not reference any external (http/https) resource (air-gap)"

    # the typed HOME view-model contract the page fetches: firmos.view/0, and
    # (no Rust bin on the runner) the bundled sample marked preview:true
    home = _get(base + "/api/home")
    assert home["schema"] == "firmos.view/0", home
    assert home["preview"] is True, "no Rust viewgen bin -> preview fallback"
    assert any(s["cards"] for s in home["sections"]), "worklist must render cards"

    # the data room is still reachable as a module FROM the home (/app)
    app_page = urllib.request.urlopen(base + "/app").read().decode("utf-8")
    assert state.token in app_page, "data-room page must still carry the token"

    # H-8: a state-changing POST WITHOUT the token is forbidden (403)
    try:
        req = urllib.request.Request(
            base + "/api/index", data=b"{}",
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req)
        raise AssertionError("index without a token was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 403, e.code

    # first-run: no matter
    assert _get(base + "/api/state")["has_matter"] is False

    # index the synthetic fixtures
    assert _post(base + "/api/index", {"folder": FIXTURES}).get("ok")
    for _ in range(200):
        job = _get(base + "/api/index/status")
        if job["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert job["status"] == "done", job
    # assert on files seen (stable) rather than 'indexed', which is 0 on an
    # incremental re-run if the matter was already built.
    assert job["stats"]["seen"] >= 5, job

    # matter active + searchable
    st = _get(base + "/api/state")
    assert st["has_matter"] and st["stats"]["total"] >= 5, st
    assert _get(base + "/api/search?q=change%20of%20control")["results"], "no hits"

    # document index + CSV export + download
    assert _get(base + "/api/tools/manifest")["summary"]["total_files"] >= 5
    assert _post(base + "/api/tools/manifest/export")["rows"] >= 5
    csv = urllib.request.urlopen(base + "/api/tools/manifest.csv").read().decode("utf-8-sig")
    # `no` is now the first column (the sequential schedule item number).
    assert csv.splitlines()[0].startswith("no,filename,")
    # an explicit sort order is honored, not 500'd, and an unknown one falls back.
    csv_name = urllib.request.urlopen(
        base + "/api/tools/manifest.csv?order=name").read().decode("utf-8-sig")
    assert csv_name.splitlines()[0].startswith("no,filename,")
    bad = urllib.request.urlopen(
        base + "/api/tools/manifest.csv?order=bogus").read().decode("utf-8-sig")
    assert bad.splitlines()[0].startswith("no,filename,")

    # rename roundtrip on a throwaway folder (NOT the indexed source)
    d = Path(tempfile.mkdtemp())
    (d / "Some  File FINAL.PDF").write_text("x")
    rules = {"spaces_to_underscores": True, "lowercase_ext": True}
    plan = _post(base + "/api/tools/rename/plan", {"folder": str(d), "rules": rules})
    assert plan["summary"]["rename"] == 1
    # C3: apply must carry the preview's plan_token (binds apply to the previewed set)
    assert plan["plan_token"], "preview must return a plan_token"
    ap = _post(base + "/api/tools/rename/apply",
               {"folder": str(d), "rules": rules, "plan_token": plan["plan_token"]})
    assert sorted(p.name for p in d.iterdir()) == ["Some_File_FINAL.pdf"]
    _post(base + "/api/tools/rename/undo", {"manifest": ap["manifest"]})
    assert sorted(p.name for p in d.iterdir()) == ["Some  File FINAL.PDF"]

    # C3: a stale plan_token (folder changed since preview) is rejected (409),
    # never silently applying a re-derived set.
    d2 = Path(tempfile.mkdtemp())
    (d2 / "Alpha  One.TXT").write_text("a")
    p2 = _post(base + "/api/tools/rename/plan", {"folder": str(d2), "rules": rules})
    stale_token = p2["plan_token"]
    (d2 / "Beta  Two.TXT").write_text("b")  # folder changes AFTER preview
    try:
        _post(base + "/api/tools/rename/apply",
              {"folder": str(d2), "rules": rules, "plan_token": stale_token})
        raise AssertionError("stale plan_token was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 409, e.code
    # nothing was renamed (apply aborted before touching disk)
    assert sorted(p.name for p in d2.iterdir()) == ["Alpha  One.TXT", "Beta  Two.TXT"]

    # negative: bad folder rejected
    try:
        _post(base + "/api/index", {"folder": "/no/such/dir"})
        raise AssertionError("bad folder was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 400

    # Phase 2: the on-page PDF visual-preview route is token-guarded and degrades
    # gracefully (preview:false, HTTP 200) — never a 500 — when there are no candidates
    # or PyMuPDF is unavailable on the runner. (Display-only; the removal path is
    # untouched.)
    import base64 as _b64
    try:
        req = urllib.request.Request(
            base + "/api/redaction/pdf-preview",
            data=b'{"data_b64":"eA=="}',
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req)
        raise AssertionError("pdf-preview without a token was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 403, e.code
    tiny_pdf = _b64.b64encode(b"%PDF-1.4\n%%EOF\n").decode()
    pv = _post(base + "/api/redaction/pdf-preview",
               {"data_b64": tiny_pdf, "candidates": []})
    assert pv.get("preview") is False, pv


if __name__ == "__main__":
    test_end_to_end()
    print("e2e OK — real server bootstrap + index/search + manifest + CSV + rename roundtrip")
