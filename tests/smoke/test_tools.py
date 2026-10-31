"""
Tools smoke tests: batch rename (preview/apply/undo) + document schedule/manifest
(split from tests/test_smoke.py).
"""

import os
import tempfile
import time
from pathlib import Path

# Isolate the app-data dir BEFORE any app import (belt-and-suspenders alongside the
# package __init__; setdefault keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from tests.smoke._helpers import (  # noqa: E402
    _client, _wait_index, _add_source_and_wait, FIXTURES,
)


def test_rename_preview_apply_undo(tmp_path=None):
    import tempfile
    from app.automations import RenameRules, plan_rename, apply_plan, undo

    d = Path(tempfile.mkdtemp())
    (d / "Board  Deck FINAL.PDF").write_text("x")
    (d / "cap table.XLSX").write_text("y")

    rules = RenameRules(spaces_to_underscores=True, lowercase_ext=True)
    plan = plan_rename(str(d), rules)
    assert plan.summary()["rename"] == 2, plan.summary()

    report = apply_plan(plan)
    assert report["renamed"] == 2, report
    names = sorted(p.name for p in d.iterdir())
    assert names == ["Board_Deck_FINAL.pdf", "cap_table.xlsx"], names

    # reversible
    undo(report["manifest"])
    names = sorted(p.name for p in d.iterdir())
    assert names == ["Board  Deck FINAL.PDF", "cap table.XLSX"], names


def test_rename_collision_skips():
    from app.automations import RenameRules, plan_rename

    # Use a whitespace collision (not a case collision) so the test holds on
    # case-INSENSITIVE filesystems too (Windows/macOS) — there "A.txt" and
    # "a.txt" are the same file.
    d = Path(tempfile.mkdtemp())
    (d / "x  y.txt").write_text("1")   # two spaces
    (d / "x y.txt").write_text("2")    # one space (already collapsed)
    plan = plan_rename(str(d), RenameRules(collapse_whitespace=True))
    # "x  y.txt" -> "x y.txt" collides with the existing "x y.txt": skip, never overwrite
    assert plan.summary()["collision"] >= 1, plan.summary()


def test_manifest_universal_and_readonly():
    """Tier 1 document index: every file listed (incl. images, no OCR), numbered,
    naturally sorted, honest page count, and never touches the source tree."""
    import tempfile
    import hashlib
    from app.index import index_folder
    from app.automations import build_manifest, manifest_csv, MANIFEST_COLUMNS

    d = Path(tempfile.mkdtemp())
    (d / "memo.txt").write_text("change of control clause here")
    (d / "scan.png").write_bytes(b"\x89PNG\r\n\x1a\n fake image bytes")  # image, no text
    (d / "dupe_a.txt").write_text("identical body")
    (d / "dupe_b.txt").write_text("identical body")                      # same hash as dupe_a
    # Natural-sort probe: "Exhibit 2" must precede "Exhibit 10" under the default
    # sort (NOT the case-sensitive byte order SQLite would give, where 10 < 2).
    (d / "Exhibit 10.txt").write_text("tenth exhibit")
    (d / "Exhibit 2.txt").write_text("second exhibit")
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in d.iterdir()}
    n_files = len(before)

    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(d), db)
    data = build_manifest(db)

    # every file appears, including the image
    names = {r["filename"] for r in data["rows"]}
    assert names == {"memo.txt", "scan.png", "dupe_a.txt", "dupe_b.txt",
                     "Exhibit 10.txt", "Exhibit 2.txt"}, names

    by_name = {r["filename"]: r for r in data["rows"]}
    assert by_name["memo.txt"]["content_status"] == "searchable"
    assert "OCR needed" in by_name["scan.png"]["content_status"]  # image flagged, no Tesseract
    assert data["summary"]["duplicate_files"] == 1               # one of the pair marked dupe
    assert data["summary"]["duplicate_groups"] == 1

    # `no` is the first column, and is a contiguous 1..N in the rendered order.
    assert MANIFEST_COLUMNS[0] == "no"
    assert [r["no"] for r in data["rows"]] == list(range(1, n_files + 1))

    # Default sort is natural: "Exhibit 2.txt" precedes "Exhibit 10.txt".
    order = [r["filename"] for r in data["rows"]]
    assert order.index("Exhibit 2.txt") < order.index("Exhibit 10.txt"), order

    # Honest page count: a non-paginated / image file shows blank pages, never 0.
    assert by_name["scan.png"]["pages"] == ""
    assert by_name["memo.txt"]["pages"] == ""

    # CSV header equals MANIFEST_COLUMNS exactly; one data row per file.
    csv_text = manifest_csv(db)
    assert csv_text.splitlines()[0] == ",".join(MANIFEST_COLUMNS)
    assert len(csv_text.strip().splitlines()) == 1 + n_files
    # CSV is RFC-4180 / Excel-canonical: CRLF line endings.
    assert "\r\n" in csv_text

    # read-only: source files byte-identical after building the manifest
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in d.iterdir()}
    assert after == before, "manifest must not modify the source tree"


def test_distinct_folders_distinct_db():
    """C3: two folders sharing a basename must not collapse to one matter .db."""
    import tempfile
    from app.paths import db_path_for
    a = Path(tempfile.mkdtemp()) / "Project X"
    a.mkdir()
    b = Path(tempfile.mkdtemp()) / "Project_X"
    b.mkdir()
    assert db_path_for(str(a)) != db_path_for(str(b)), "distinct folders collided to one DB"


def test_rename_refused_inside_source_tree():
    """H1: the rename tool must refuse to write inside the indexed (read-only) room."""
    c = _client()
    c.post("/api/index", json={"folder": FIXTURES})
    for _ in range(100):
        if c.get("/api/index/status").json()["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    r = c.post("/api/tools/rename/plan", json={"folder": FIXTURES, "rules": {"lowercase_name": True}})
    assert r.status_code == 400, r.text
    assert "read-only" in r.json()["error"].lower()


def test_undo_manifest_confined():
    """H4: undo must reject a manifest that isn't in our own undo dir."""
    import tempfile
    c = _client()
    bogus = Path(tempfile.mkdtemp()) / "evil.jsonl"
    bogus.write_text('{"from": "/etc/x", "to": "/etc/y"}\n')
    r = c.post("/api/tools/rename/undo", json={"manifest": str(bogus)})
    assert r.status_code == 400, r.text


def test_undo_records_confined_to_recorded_folder():
    """C1: even a manifest placed in our OWN undo dir must not drive a rename to a
    path outside the run's recorded `folder`. A crafted from/to that escapes the
    folder is refused (counted as an error, never executed)."""
    import json as _json
    import tempfile
    from app.automations import undo
    from app.paths import undo_dir

    room = Path(tempfile.mkdtemp()).resolve()
    (room / "a.txt").write_text("REAL")
    # A sensitive file OUTSIDE the recorded room that a crafted manifest tries to move.
    outside_dir = Path(tempfile.mkdtemp()).resolve()
    victim = outside_dir / "secret.txt"
    victim.write_text("DO NOT MOVE")

    # A manifest in our own undo dir whose header records `room`, but whose record
    # points from/to OUTSIDE room (the attack a confinement-less undo would honour).
    mp = undo_dir() / "rename_evilrecord.jsonl"
    with open(mp, "w", encoding="utf-8") as f:
        f.write(_json.dumps({"type": "header", "created_at": "x",
                             "folder": str(room)}) + "\n")
        f.write(_json.dumps({"from": str(victim),
                            "to": str(outside_dir / "moved.txt")}) + "\n")

    res = undo(str(mp))
    assert res["reverted"] == 0, res
    assert res["errors"] and "outside" in res["errors"][0]["error"], res
    # the out-of-folder victim is untouched
    assert victim.read_text() == "DO NOT MOVE"
    assert not (outside_dir / "moved.txt").exists()


def test_undo_rejects_degenerate_root_folder():
    """C1 (adversarial-review follow-up): the reproduced bypass — a crafted manifest
    whose recorded `folder` is a filesystem ROOT confines to the WHOLE disk, re-opening
    arbitrary rename. With the degenerate-base check, a root `folder` must confine to
    NOTHING (fail-closed): every record refused, the out-of-room victim untouched."""
    import json as _json
    import tempfile
    from app.automations import undo
    from app.paths import undo_dir

    outside_dir = Path(tempfile.mkdtemp()).resolve()
    victim = outside_dir / "secret.txt"
    victim.write_text("DO NOT MOVE")

    # The exact attack the reviewer reproduced: folder="/" (the filesystem root;
    # `anchor` is "/" on POSIX, the drive root on Windows) → confines to everything.
    root = victim.anchor or "/"
    mp = undo_dir() / "rename_rootfolder.jsonl"
    with open(mp, "w", encoding="utf-8") as f:
        f.write(_json.dumps({"type": "header", "created_at": "x", "folder": root}) + "\n")
        f.write(_json.dumps({"from": str(victim),
                            "to": str(outside_dir / "moved.txt")}) + "\n")

    res = undo(str(mp))
    assert res["reverted"] == 0, res
    assert res["errors"] and "outside" in res["errors"][0]["error"], res
    assert victim.read_text() == "DO NOT MOVE"
    assert not (outside_dir / "moved.txt").exists()


def test_manifest_endpoints_handle_no_matter():
    """C4 sense-check: the manifest endpoints snapshot active_db under the lock and
    return a clean 400 (never a 500 crash) when no matter is open."""
    c = _client()  # fresh client, no matter opened
    assert c.get("/api/tools/manifest").status_code == 400
    assert c.get("/api/tools/manifest.csv").status_code == 400


def test_undo_legit_roundtrip_still_confined():
    """C1 sense-check: a REAL apply→undo (from/to inside the recorded folder) still
    reverts cleanly under the new confinement."""
    import tempfile
    from app.automations import RenameRules, plan_rename, apply_plan, undo

    d = Path(tempfile.mkdtemp())
    (d / "Board  Deck.PDF").write_text("x")
    plan = plan_rename(str(d), RenameRules(spaces_to_underscores=True, lowercase_ext=True))
    rep = apply_plan(plan)
    assert rep["renamed"] == 1, rep
    assert sorted(p.name for p in d.iterdir()) == ["Board_Deck.pdf"]
    res = undo(rep["manifest"])
    assert res["reverted"] == 1 and not res["errors"], res
    assert sorted(p.name for p in d.iterdir()) == ["Board  Deck.PDF"]


def test_rename_apply_never_overwrites():
    """H3: a target appearing between preview and apply is skipped, not clobbered."""
    import tempfile
    from app.automations import _safe_rename
    d = Path(tempfile.mkdtemp())
    (d / "a.txt").write_text("SRC")
    (d / "b.txt").write_text("EXISTING")
    try:
        _safe_rename(d / "a.txt", d / "b.txt")
        assert False, "should have refused to overwrite b.txt"
    except FileExistsError:
        pass
    assert (d / "b.txt").read_text() == "EXISTING"  # untouched
    assert (d / "a.txt").read_text() == "SRC"


def test_review_loop():
    """Stats drill-down (/api/files), source_root in state, and open/reveal
    confinement (open inside the matter ok; outside rejected)."""
    c = _client()
    c.post("/api/index", json={"folder": FIXTURES})
    for _ in range(100):
        if c.get("/api/index/status").json()["status"] in ("done", "error"):
            break
        time.sleep(0.1)

    st = c.get("/api/state").json()
    assert st["source_root"], "state should expose the matter's source_root"

    # drill-down categories
    assert c.get("/api/files", params={"category": "searchable"}).json()["count"] >= 5
    assert c.get("/api/files", params={"category": "errors"}).json()["count"] == 0
    assert c.get("/api/files", params={"category": "all"}).json()["count"] >= 5
    assert c.get("/api/files", params={"category": "bogus"}).status_code == 400

    # open a file INSIDE the matter -> ok (launch is disabled in tests)
    inside = str(Path(FIXTURES) / "note.txt")
    assert c.post("/api/file/open", json={"path": inside}).json().get("ok") is True
    assert c.post("/api/file/reveal", json={"path": inside}).json().get("ok") is True

    # a file OUTSIDE the matter is refused (this test file itself)
    assert c.post("/api/file/open", json={"path": str(Path(__file__))}).status_code == 400


def test_tool_entry_points():
    """Tesseract / qpdf / pdfium entry points: detection never raises, the app
    runs with none present, and the bundled-tool resolver honors env overrides."""
    from app import vendor, ocr, pdftools, extractors

    # resolver: unknown tool -> None; explicit env override -> that path
    assert vendor.bundled_tool("definitely-not-real-xyz") is None
    f = tempfile.NamedTemporaryFile(delete=False)
    f.close()
    os.environ["LAWDATAMAN_FOOTOOL"] = f.name
    try:
        assert vendor.bundled_tool("footool") == f.name
    finally:
        os.environ.pop("LAWDATAMAN_FOOTOOL", None)

    # opt-in OCR-fallback PDF backend is registered
    assert "pymupdf_ocr" in extractors._PDF_BACKENDS

    # probes return booleans and never raise; graceful no-op when tools absent
    assert isinstance(ocr.available(), bool)
    assert isinstance(pdftools.qpdf_available(), bool)
    assert isinstance(pdftools.pdfium_available(), bool)
    if not ocr.available():
        assert ocr.ocr_image("nope.png") == []
        assert ocr.ocr_pdf("nope.pdf") == []
        assert ocr.ocr_pdf_pages("nope.pdf", [0, 1]) == {}
        assert ocr.ocr_pdf_pages("nope.pdf", []) == {}
    if not pdftools.qpdf_available():
        assert pdftools.repair_pdf("a.pdf", "b.pdf") is False


def test_rename_rules_reject_unknown_field():
    """H-7: an unknown rule key is a client error (400), not an unhandled 500."""
    c = _client()
    r = c.post("/api/tools/rename/plan",
               json={"folder": "/tmp", "rules": {"evil_field": True}})
    assert r.status_code == 400, r.text
    assert "unknown rule" in r.json()["error"].lower()


def test_rename_apply_requires_and_binds_plan_token():
    """C3: /apply must (a) reject a request with no plan_token, and (b) reject a
    STALE token after the folder changed between preview and apply — applying only
    the exact previewed set, never a silently re-derived one."""
    import tempfile
    c = _client()
    d = Path(tempfile.mkdtemp())
    (d / "Alpha  One.TXT").write_text("a")
    rules = {"spaces_to_underscores": True, "lowercase_ext": True}

    # preview returns a plan_token bound to this exact set
    plan = c.post("/api/tools/rename/plan", json={"folder": str(d), "rules": rules}).json()
    assert plan["plan_token"], plan
    assert plan["summary"]["rename"] == 1, plan

    # (a) apply WITHOUT a token is refused
    no_tok = c.post("/api/tools/rename/apply", json={"folder": str(d), "rules": rules})
    assert no_tok.status_code == 400, no_tok.text

    # (b) the folder changes after preview -> the old token is now stale -> 409
    (d / "Beta  Two.TXT").write_text("b")
    stale = c.post("/api/tools/rename/apply",
                   json={"folder": str(d), "rules": rules, "plan_token": plan["plan_token"]})
    assert stale.status_code == 409, stale.text
    # disk untouched (apply aborted before any rename)
    assert sorted(p.name for p in d.iterdir()) == ["Alpha  One.TXT", "Beta  Two.TXT"]

    # a fresh preview yields a token that DOES apply (and renames both files now)
    plan2 = c.post("/api/tools/rename/plan", json={"folder": str(d), "rules": rules}).json()
    ok = c.post("/api/tools/rename/apply",
                json={"folder": str(d), "rules": rules, "plan_token": plan2["plan_token"]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["renamed"] == 2, ok.json()


def test_content_disposition_encodes_special_chars():
    """H-3: Content-Disposition must be safe for a matter name containing `"`, `&`, or
    non-ASCII — both a sanitized ASCII `filename="..."` fallback AND an RFC 5987
    `filename*=UTF-8''<pct>` so no untrusted byte can break the header."""
    from urllib.parse import unquote

    import app.web as web

    # A name with a quote (could terminate the quoted string), an ampersand, and Unicode.
    hdr = web._content_disposition('index_Acme "X" & Søn.csv')
    assert hdr.startswith("attachment; ")
    # ASCII fallback: no raw quote/backslash, ASCII-only, the dangerous chars replaced.
    import re as _re
    m = _re.search(r'filename="([^"]*)"', hdr)
    assert m, hdr
    ascii_name = m.group(1)
    assert '"' not in ascii_name and "\\" not in ascii_name
    assert all(32 <= ord(c) < 127 for c in ascii_name), ascii_name
    # RFC 5987 part present, decodes back to the ORIGINAL unicode name (round-trip).
    m2 = _re.search(r"filename\*=UTF-8''(\S+)", hdr)
    assert m2, hdr
    assert unquote(m2.group(1)) == 'index_Acme "X" & Søn.csv'
    # The header-breaking `"` is percent-encoded in the 5987 token; non-ASCII is too. (`&`
    # is a valid RFC 5987 attr-char and does NOT need encoding — `filename*` is not a quoted
    # string, so `&` can't break the header.)
    assert '"' not in m2.group(1), m2.group(1)
    assert "ø" not in m2.group(1).lower(), m2.group(1)  # the Unicode byte is escaped
    # A blank/None name degrades to a safe default, never an empty token.
    assert 'filename="download"' in web._content_disposition("")


def test_unique_in_dir_bounded_and_never_overwrites():
    """L-7 + #13: _unique_in_dir ATOMICALLY reserves (O_CREAT|O_EXCL) a non-colliding path,
    caps the ` (n)` probe, and falls back to a timestamped name. It never reuses an existing
    name (no-clobber); the returned path is a freshly-created EMPTY placeholder the caller
    then writes into. Uses a tiny max_probes so the bound is exercised cheaply (real cap 10k)."""
    import app.web as web

    d = Path(tempfile.mkdtemp(prefix="ldm-uniq-")).resolve()
    try:
        base = "report.pdf"
        # No collision: returns AND atomically creates the plain name (reserved, empty).
        p0 = web._unique_in_dir(d, base)
        assert p0 == d / "report.pdf" and p0.exists() and p0.stat().st_size == 0
        # A second call cannot reuse the reserved name — it advances to the next free one,
        # each call reserving its own distinct file (this is the TOCTOU fix: no two callers
        # can ever pick the same name).
        p1 = web._unique_in_dir(d, base)
        p2 = web._unique_in_dir(d, base)
        assert p1 == d / "report (1).pdf" and p2 == d / "report (2).pdf"
        assert len({p0, p1, p2}) == 3 and all(p.exists() for p in (p0, p1, p2))
        # Force the BOUND: with report.pdf/(1)/(2) reserved and max_probes=2, the dense scan
        # gives up and returns a timestamp+random fallback (also freshly created/reserved).
        out = web._unique_in_dir(d, base, max_probes=2)
        assert out.exists() and out.parent == d
        assert out.name.startswith("report (") and out.suffix == ".pdf"
        # The fallback is NOT a dense ` (n)` number — it carries the timestamp+random tail.
        assert out.name not in {f"report ({n}).pdf" for n in range(0, 7)}, out.name
    finally:
        import shutil as _sh
        _sh.rmtree(d, ignore_errors=True)


def test_rename_refused_inside_each_of_n_source_roots():
    """SAFETY-CRITICAL: the rename confinement must refuse a target inside EVERY source
    root (primary AND every added source) — shipping multi-source without this leaves an
    added source writable (a read-only-source violation)."""
    c = _client()
    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary")
    _wait_index(c, str(primary))

    extra = Path(tempfile.mkdtemp()).resolve()
    (extra / "added.txt").write_text("added")
    r = _add_source_and_wait(c, root=str(extra))
    assert r.status_code == 200, r.text

    # a rename targeting the PRIMARY root is refused (existing behavior)
    rp = c.post("/api/tools/rename/plan",
                json={"folder": str(primary), "rules": {"lowercase_name": True}})
    assert rp.status_code == 400 and "read-only" in rp.json()["error"].lower(), rp.text

    # a rename targeting the ADDED source root is ALSO refused (the generalization)
    re_ = c.post("/api/tools/rename/plan",
                 json={"folder": str(extra), "rules": {"lowercase_name": True}})
    assert re_.status_code == 400 and "read-only" in re_.json()["error"].lower(), re_.text

    # a rename targeting a subfolder INSIDE the added source is refused too
    sub = extra / "sub"
    sub.mkdir()
    rs = c.post("/api/tools/rename/plan",
                json={"folder": str(sub), "rules": {"lowercase_name": True}})
    assert rs.status_code == 400 and "read-only" in rs.json()["error"].lower(), rs.text

    # an unrelated working-copy folder is still allowed (not a 400 read-only refusal)
    work = Path(tempfile.mkdtemp()).resolve()
    (work / "w.txt").write_text("x")
    rw = c.post("/api/tools/rename/plan",
                json={"folder": str(work), "rules": {"lowercase_name": True}})
    assert rw.status_code == 200, rw.text
