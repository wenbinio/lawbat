"""
Indexing / search / sources / ingestion-safety / extractor smoke tests
(split from tests/test_smoke.py).
"""

import os
import tempfile
import time
from contextlib import closing
from pathlib import Path

# Isolate the app-data dir BEFORE any app import (belt-and-suspenders alongside the
# package __init__; setdefault keeps the whole suite on ONE shared throwaway data dir).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402
from app.db import fts5_available  # noqa: E402
from app.web import create_app, AppState  # noqa: E402
from tests.smoke._helpers import (  # noqa: E402
    _client, _index_into, _wait_index, _add_source_and_wait, FIXTURES,
)


def test_fts5_available():
    assert fts5_available(), "SQLite build lacks FTS5 — search will not work"


def test_index_and_search():
    c = _client()

    # first run: no matter open
    assert c.get("/api/state").json()["has_matter"] is False

    # kick off indexing of the synthetic fixtures
    r = c.post("/api/index", json={"folder": FIXTURES})
    assert r.status_code == 200, r.text

    # poll until the background job finishes
    for _ in range(100):
        job = c.get("/api/index/status").json()
        if job["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert job["status"] == "done", job
    assert job["stats"]["indexed"] >= 4

    # matter is now active
    state = c.get("/api/state").json()
    assert state["has_matter"] is True
    assert state["stats"]["total"] >= 5

    # cross-format search hits
    hits = c.get("/api/search", params={"q": "change of control"}).json()["results"]
    assert hits, "expected at least one hit for 'change of control'"

    # bad folder rejected
    assert c.post("/api/index", json={"folder": "/no/such/dir"}).status_code == 400

    # malformed FTS query reports an error status, not a misleading 200 (M5)
    bad = c.get("/api/search", params={"q": '"unterminated'})
    assert bad.status_code == 400 and "error" in bad.json()


def test_pluggable_pdf_backend():
    """The PDF backend is swappable via env var (licensing hedge)."""
    import os
    from app import extractors

    @extractors.register_pdf_backend("dummy")
    def _dummy(path):
        return [("p.1", "DUMMYTEXT")]

    os.environ["LAWDATAMAN_PDF_BACKEND"] = "dummy"
    try:
        assert extractors.extract_pdf("ignored.pdf") == [("p.1", "DUMMYTEXT")]
    finally:
        os.environ.pop("LAWDATAMAN_PDF_BACKEND", None)
    # unknown backend falls back to the default rather than crashing
    os.environ["LAWDATAMAN_PDF_BACKEND"] = "nope"
    try:
        assert "pymupdf" in extractors._PDF_BACKENDS
    finally:
        os.environ.pop("LAWDATAMAN_PDF_BACKEND", None)


def test_eml_indexes_bcc_and_reply_to():
    """A .eml's Bcc and Reply-To recipients must land in the indexed text so a
    party visible ONLY as a Bcc/Reply-To is searchable — closing the gap with the
    redaction extractor, which already surfaces those recipients. (.eml uses only
    the stdlib `email` module, so this runs without extract-msg installed.)"""
    from email.message import EmailMessage
    from app.extractors import extract_eml

    m = EmailMessage()
    m["From"] = "alice@firm.example"
    m["To"] = "bob@client.example"
    m["Cc"] = "carol@client.example"
    m["Bcc"] = "dave-hidden@opposing.example"
    m["Reply-To"] = "replies@firm.example"
    m["Date"] = "Mon, 23 Jun 2026 10:00:00 +0000"
    m["Subject"] = "Settlement terms"
    m.set_content("Body of the message.")

    d = Path(tempfile.mkdtemp())
    p = d / "hidden-recipient.eml"
    p.write_bytes(m.as_bytes())

    units = extract_eml(p)
    assert units, "expected the .eml to extract to non-empty text"
    text = "\n".join(t for _, t in units)
    # the previously-OMITTED recipients must now be present and searchable
    assert "dave-hidden@opposing.example" in text, "Bcc recipient missing from index"
    assert "replies@firm.example" in text, "Reply-To missing from index"
    # the originally-indexed headers stay present (no regression)
    assert "bob@client.example" in text
    assert "carol@client.example" in text


def test_open_confinement():
    """Confinement is by the indexed files table, not a path prefix: a file
    dropped after indexing is refused; a moved file is distinguished (409); a
    symlink that escapes the matter root is refused."""
    room = Path(tempfile.mkdtemp()).resolve()  # resolve: the indexer stores resolved paths
    (room / "a.txt").write_text("hello world")
    c = _client()
    _index_into(c, str(room))

    # indexed + present -> ok
    assert c.post("/api/file/open", json={"path": str(room / "a.txt")}).json().get("ok")

    # dropped AFTER indexing (never indexed) -> outside (400)
    (room / "dropped.txt").write_text("not indexed")
    assert c.post("/api/file/open", json={"path": str(room / "dropped.txt")}).status_code == 400

    # moved/deleted since indexing -> 409 (distinct from 'outside')
    (room / "a.txt").unlink()
    assert c.post("/api/file/open", json={"path": str(room / "a.txt")}).status_code == 409

    # symlink escaping the room -> refused (POSIX; skip where symlinks need privilege)
    if os.name != "nt":
        secret = Path(tempfile.mkdtemp()).resolve() / "secret.txt"
        secret.write_text("TOPSECRET")
        room2 = Path(tempfile.mkdtemp()).resolve()
        (room2 / "real.txt").write_text("in room")
        try:
            (room2 / "link.txt").symlink_to(secret)
        except OSError:
            return
        c2 = _client()
        _index_into(c2, str(room2))
        assert c2.post("/api/file/open", json={"path": str(room2 / "link.txt")}).status_code == 400
        assert c2.post("/api/file/open", json={"path": str(room2 / "real.txt")}).json().get("ok")


def test_needs_ocr_count_matches_manifest():
    """The header's needs_ocr count must equal the manifest's need_ocr for the
    same corpus (deterministic/auditable — single classifier)."""
    from app.index import index_folder
    from app.automations import build_manifest
    from app.web import corpus_stats

    d = Path(tempfile.mkdtemp())
    (d / "memo.txt").write_text("born digital")
    (d / "scan.png").write_bytes(b"\x89PNG fake")          # image -> needs OCR
    (d / "err.png").write_bytes(b"not really an image")    # also image ext
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(d), db)
    assert corpus_stats(db)["needs_ocr"] == build_manifest(db)["summary"]["need_ocr"]


# ---------------------------------------------------------------- ingestion safety --
def test_scan_guard_classify_root():
    """scan_guard.classify_root: a system / drive root REFUSES; a normal tmp folder is
    OK. (The refusal is the load-bearing server-side guarantee.)"""
    from app import scan_guard

    # A drive / filesystem root refuses (POSIX "/" or, on Windows, the drive root).
    root = Path(tempfile.mkdtemp()).resolve().anchor or "/"
    level, reason = scan_guard.classify_root(root)
    assert level in ("refuse", "warn"), (level, reason)  # never "ok" for a bare root
    if os.name != "nt":
        assert scan_guard.classify_root("/")[0] == "refuse"
        assert scan_guard.classify_root("/etc")[0] == "refuse"

    # The app's own data dir refuses (it is not a source room) — and so does a
    # SUBFOLDER of it (else a user could point the indexer at their matter DBs).
    assert scan_guard.classify_root(scan_guard.paths.data_dir())[0] == "refuse"
    assert scan_guard.classify_root(scan_guard.paths.matters_dir())[0] == "refuse"

    # A normal sub-folder is OK.
    d = Path(tempfile.mkdtemp()) / "Matter Acme"
    d.mkdir()
    assert scan_guard.classify_root(str(d)) == ("ok", "")


def test_scan_guard_offline_placeholder():
    """is_offline_placeholder: False for a normal file/stat (incl. POSIX, where the
    attribute is absent), True only when an OFFLINE/recall bit is set — decided from a
    stat() WITHOUT opening the file (opening would force a cloud download)."""
    from app import scan_guard

    # A real file's stat -> never a placeholder on POSIX (no st_file_attributes); on
    # Windows a normal file has none of the offline/recall bits set either.
    f = Path(tempfile.mkdtemp()) / "real.txt"
    f.write_text("present on disk")
    assert scan_guard.is_offline_placeholder(f.stat()) is False

    # A fake stat carrying the OFFLINE bit -> True (no open needed).
    class _FakeStat:
        st_file_attributes = scan_guard._FILE_ATTRIBUTE_OFFLINE
    assert scan_guard.is_offline_placeholder(_FakeStat()) is True

    # RECALL_ON_DATA_ACCESS (the OneDrive "files on-demand" bit) -> True.
    class _Recall:
        st_file_attributes = scan_guard._FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    assert scan_guard.is_offline_placeholder(_Recall()) is True

    # The bare reparse-point bit (junction/symlink) is NOT treated as a placeholder.
    class _Reparse:
        st_file_attributes = 0x400
    assert scan_guard.is_offline_placeholder(_Reparse()) is False

    # An object with no st_file_attributes (POSIX stat) degrades to False.
    assert scan_guard.is_offline_placeholder(object()) is False


def test_index_skips_offline_without_opening():
    """A file flagged as a cloud OFFLINE placeholder is recorded skipped-offline and is
    NEVER opened (opening forces a download). We force the placeholder verdict via a
    swapped is_offline_placeholder, and assert sha256 is never called on it. (Manual
    save/restore — the suite also runs via the __main__ runner, not just pytest.)"""
    from app import index, scan_guard

    d = Path(tempfile.mkdtemp())
    (d / "online_only.docx").write_text("would-download")     # 14 bytes
    (d / "normal.txt").write_text("change of control text")

    seen_offline = {"hit": False}

    def fake_offline(st):
        # The real index passes the file's stat; flag the one whose size matches the
        # placeholder body length (we can't see the name from st alone).
        if getattr(st, "st_size", -1) == len("would-download"):
            seen_offline["hit"] = True
            return True
        return False

    opened = {"paths": []}
    extracted = {"paths": []}
    orig_offline = scan_guard.is_offline_placeholder
    orig_sha = index.sha256
    orig_extract = index.extract

    def spy_sha(path, *a, **k):
        opened["paths"].append(Path(path).name)
        return orig_sha(path, *a, **k)

    def spy_extract(path, *a, **k):
        extracted["paths"].append(Path(path).name)
        return orig_extract(path, *a, **k)

    scan_guard.is_offline_placeholder = fake_offline
    index.sha256 = spy_sha
    index.extract = spy_extract
    try:
        db = str(Path(tempfile.mkdtemp()) / "m.db")
        stats = index.index_folder(str(d), db)
    finally:
        scan_guard.is_offline_placeholder = orig_offline
        index.sha256 = orig_sha
        index.extract = orig_extract
    assert seen_offline["hit"], "the placeholder file's stat must be checked"
    assert stats["skipped_offline"] == 1, stats
    # The offline placeholder was NEVER hashed/opened NOR text-extracted; the
    # normal file was. (Extraction also opens the file -> would force a download.)
    assert "online_only.docx" not in opened["paths"], opened
    assert "online_only.docx" not in extracted["paths"], extracted
    assert "normal.txt" in opened["paths"], opened


def test_index_skips_too_large_without_opening():
    """A file over MAX_FILE_BYTES is recorded skipped-too-large WITHOUT being opened.
    We shrink the cap (manual save/restore) so we don't create a 2 GiB file."""
    from app import index, scan_guard

    d = Path(tempfile.mkdtemp())
    (d / "big.bin").write_bytes(b"x" * 5000)
    (d / "small.txt").write_text("ok")

    opened = {"paths": []}
    orig_cap = scan_guard.MAX_FILE_BYTES
    orig_sha = index.sha256

    def spy_sha(path, *a, **k):
        opened["paths"].append(Path(path).name)
        return orig_sha(path, *a, **k)

    scan_guard.MAX_FILE_BYTES = 1000
    index.sha256 = spy_sha
    try:
        db = str(Path(tempfile.mkdtemp()) / "m.db")
        stats = index.index_folder(str(d), db)
    finally:
        scan_guard.MAX_FILE_BYTES = orig_cap
        index.sha256 = orig_sha
    assert stats["skipped_too_large"] == 1, stats
    assert "big.bin" not in opened["paths"], opened     # never hashed/opened
    assert "small.txt" in opened["paths"], opened


def test_index_reindex_to_offline_clears_stale_chunks():
    """Round-2 [MEDIUM] #4: when a previously-INDEXED file becomes offline (or too-large /
    unreadable) on a re-index, its FTS5 chunks must be DELETED. Otherwise the files row says
    'skipped-offline' (no content) while search still returns the old text — a stale-content
    inconsistency. The clear is a pure DB delete (never opens the now-offline file)."""
    from app import index, scan_guard
    from app.web import run_search

    body = "confidential pineapple disclosure"
    d = Path(tempfile.mkdtemp())
    (d / "secret.txt").write_text(body)
    db = str(Path(tempfile.mkdtemp()) / "m.db")

    # 1) First index: the file is indexed + searchable.
    index.index_folder(str(d), db)
    assert any(h["filename"] == "secret.txt" for h in run_search(db, "pineapple")), "searchable"

    # 2) Re-index with the file now flagged a cloud OFFLINE placeholder (never opened).
    orig_offline = scan_guard.is_offline_placeholder
    scan_guard.is_offline_placeholder = (
        lambda st: getattr(st, "st_size", -1) == len(body))
    try:
        stats = index.index_folder(str(d), db)
    finally:
        scan_guard.is_offline_placeholder = orig_offline
    assert stats["skipped_offline"] == 1, stats

    # 3) The stale chunks are gone: search no longer surfaces the old text.
    assert not any(h["filename"] == "secret.txt" for h in run_search(db, "pineapple")), \
        "stale FTS5 chunks must be cleared when a file goes offline"


def test_index_stores_norm_path_for_indexed_lookup():
    """#17: every files row carries norm_path = os.normcase(os.normpath(path)), populated at
    index time and backfilled on open for a legacy DB — so the open/reveal case/separator-
    insensitive fallback is an INDEXED lookup, not a full O(N) Python table scan."""
    from app import index
    from app.db import connect, norm_path

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "Memo.txt").write_text("body")
    sub = d / "sub"
    sub.mkdir()
    (sub / "Deed.txt").write_text("body2")
    dbp = str(Path(tempfile.mkdtemp()) / "m.db")
    index.index_folder(str(d), dbp)

    with closing(connect(dbp)) as con:
        rows = con.execute("SELECT path, norm_path FROM files").fetchall()
        assert rows, "indexed at least one file"
        assert all(r["norm_path"] == norm_path(r["path"]) for r in rows), "norm_path set at index time"
        assert con.execute("SELECT count(*) AS n FROM files WHERE norm_path IS NULL").fetchone()["n"] == 0
        # The indexed fallback resolves a path with SEPARATOR drift (portable: normpath
        # collapses a redundant './' on every OS; case is FS-dependent in CI so not asserted).
        target = rows[0]["path"]
        drifted = target.replace(os.sep, os.sep + "." + os.sep, 1)
        hit = con.execute("SELECT path FROM files WHERE norm_path = ? LIMIT 1",
                          (norm_path(drifted),)).fetchone()
        assert hit and hit["path"] == target, ("drifted path resolves via the indexed norm_path", drifted)

    # Legacy backfill: null out norm_path, reopen -> connect() runs _migrate which repopulates.
    with closing(connect(dbp)) as con:
        con.execute("UPDATE files SET norm_path = NULL")
        con.commit()
    with closing(connect(dbp)) as con:
        assert con.execute("SELECT count(*) AS n FROM files WHERE norm_path IS NULL").fetchone()["n"] == 0, \
            "legacy rows backfilled on open"


def test_norm_path_backfill_failure_rolls_back_and_does_not_break_connect():
    """#17 independent-review [Low-Med]: the norm_path backfill runs inside connect(), on read
    paths too. If a backfill UPDATE loses to a concurrent index (single WAL writer) with
    'database is locked', it must NOT leave a dangling transaction that then makes
    executescript(SCHEMA) fail and 500 a search/open. The fix rolls back; connect() still
    returns a usable connection and the backfill self-heals on a later open."""
    from app import db, index

    src = Path(tempfile.mkdtemp())
    (src / "a.txt").write_text("alpha")
    (src / "b.txt").write_text("bravo")   # two rows: one UPDATE lands (opens a txn) before the fail
    dbp = str(Path(tempfile.mkdtemp()) / "m.db")
    index.index_folder(str(src), dbp)
    with closing(db.connect(dbp)) as con:
        con.execute("UPDATE files SET norm_path = NULL")   # simulate a not-yet-backfilled DB
        con.commit()

    orig = db.norm_path
    calls = {"n": 0}

    def _boom(p):
        calls["n"] += 1
        if calls["n"] >= 2:                     # first UPDATE opens a write txn, second blows up
            raise RuntimeError("simulated 'database is locked' mid-backfill")
        return orig(p)

    db.norm_path = _boom
    try:
        con = db.connect(dbp)                   # must NOT raise despite the backfill failing
    finally:
        db.norm_path = orig
    try:
        assert not con.in_transaction, "a failed backfill must not leave a dangling transaction"
        con.execute("SELECT count(*) FROM files").fetchone()   # connection is usable
    finally:
        con.close()

    # Self-heal: a subsequent clean open completes the backfill (idempotent).
    with closing(db.connect(dbp)) as con:
        assert con.execute("SELECT count(*) AS n FROM files WHERE norm_path IS NULL").fetchone()["n"] == 0


def test_search_snippet_uses_collision_proof_sentinels():
    """#16: the FTS5 snippet wraps matches in PRIVATE-USE sentinels (U+E000/U+E001), not
    '[['/']]', so literal '[[' or ']]' in document content cannot be mis-rendered as <mark>
    tags. The client rewrites ONLY the sentinels (after esc()), leaving literal brackets intact."""
    from app import index
    from app.web import run_search

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "doc.txt").write_text("preamble [[verbatim brackets]] keyword pineapple here.")
    dbp = str(Path(tempfile.mkdtemp()) / "m.db")
    index.index_folder(str(d), dbp)
    hits = run_search(dbp, "pineapple")
    assert hits, "the keyword matches"
    snip = hits[0]["snip"]
    assert "\ue000" in snip and "\ue001" in snip, "matches are wrapped in the private-use sentinels"
    assert "[[" in snip, "literal [[ in content is preserved verbatim (not treated as a marker)"
    # The client rewrite maps ONLY the sentinels to <mark>; literal [[ ]] survive untouched.
    client = snip.replace("\ue000", "<mark>").replace("\ue001", "</mark>")
    assert "<mark>pineapple</mark>" in client and "[[verbatim brackets]]" in client


def test_index_symlink_loop_does_not_hang():
    """A symlink LOOP (a dir linking back into itself) must not hang index_folder /
    estimate_folder — the (dev,ino) visited-set prunes the cycle. Skipped cleanly where
    symlinks aren't permitted (Windows / restricted CI)."""
    if os.name == "nt":
        return
    from app import index

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "a.txt").write_text("hello loop")
    sub = d / "sub"
    sub.mkdir()
    try:
        (sub / "back").symlink_to(d, target_is_directory=True)  # cycle: sub/back -> d
    except OSError:
        return  # no symlink permission -> skip cleanly

    # Both must TERMINATE (the test itself hanging would be the failure).
    est = index.estimate_folder(str(d))
    assert est["files"] >= 1, est
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    stats = index.index_folder(str(d), db)
    assert stats["indexed"] >= 1, stats


def test_index_distinct_dirs_sharing_inode_are_both_walked():
    """#13 (recall MISS — the dangerous direction): two genuinely DISTINCT directories that
    happen to share a (dev,ino) — FAT/exFAT report st_ino==0 for everything; some
    bind/overlay/network mounts reuse inodes — must BOTH be walked, never pruned as a
    'cycle'. The OLD global ever-seen visited-set wrongly pruned the second one, silently
    leaving a real subtree UNINDEXED. We simulate the shared key by injecting a real_key()
    that ignores the actual stat. The ANCESTOR-chain guard must NOT prune siblings."""
    from app import index, scan_guard

    d = Path(tempfile.mkdtemp()).resolve()
    # Two distinct sibling subtrees, each with one file.
    for name in ("alpha", "beta"):
        sub = d / name
        sub.mkdir()
        (sub / f"{name}.txt").write_text(f"content of {name}")

    real = scan_guard.real_key
    # Case 1: the two SIBLINGS share a non-zero (dev,ino) with EACH OTHER, but a DIFFERENT
    # key from their common ancestor (the root). Neither sibling is an ancestor of the other,
    # so the ancestor-chain guard must NOT prune either — both are walked. (A GLOBAL ever-seen
    # set, the old bug, would prune the second sibling it encountered. The ancestor-only guard
    # must not.) The root keeps a distinct key so the siblings don't collide with an ancestor.
    def _siblings_share_key(path):
        base = os.path.basename(os.fspath(path))
        if base in ("alpha", "beta"):
            return (42, 99)      # the two distinct siblings share a key
        return (42, 1)           # everything else (incl. the root) is distinct
    scan_guard.real_key = _siblings_share_key
    try:
        est = index.estimate_folder(str(d))
    finally:
        scan_guard.real_key = real
    assert est["files"] == 2, ("both sibling files must be counted (shared-ino must not "
                               "prune distinct dirs)", est)
    db = str(Path(tempfile.mkdtemp()) / "shared.db")
    scan_guard.real_key = _siblings_share_key
    try:
        stats = index.index_folder(str(d), db)
    finally:
        scan_guard.real_key = real
    assert stats["indexed"] == 2, ("both sibling files must index (shared-ino must not "
                                   "prune distinct dirs)", stats)

    # Case 2: st_ino == 0 for EVERY dir (FAT/exFAT). An ino of 0 is meaningless and must
    # NEVER prune — both subtrees are walked even though the WHOLE tree shares (dev, 0).
    def _zero_ino(_path):
        return (7, 0)
    db2 = str(Path(tempfile.mkdtemp()) / "zero_ino.db")
    scan_guard.real_key = _zero_ino
    try:
        est2 = index.estimate_folder(str(d))
        stats2 = index.index_folder(str(d), db2)
    finally:
        scan_guard.real_key = real
    assert est2["files"] == 2, ("st_ino==0 must never prune", est2)
    assert stats2["indexed"] == 2, ("st_ino==0 must never prune", stats2)


def test_index_genuine_ancestor_loop_still_pruned():
    """#13 (preserve the original purpose): a GENUINE loop — a directory whose real (dev,ino)
    equals one of its OWN ANCESTORS on the path being walked — must STILL be caught and pruned
    so the walk terminates. We simulate without a real symlink (works on every OS / no symlink
    privilege needed) by injecting a real_key() that maps a deep child back to its parent's
    key, i.e. an ancestor cycle. The walk must terminate and the loop subtree be pruned."""
    from app import index, scan_guard

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "top.txt").write_text("top level")
    loop = d / "loop"
    loop.mkdir()
    (loop / "inner.txt").write_text("inner")
    # A child UNDER loop/ whose injected key collides with loop/'s key -> ancestor cycle.
    trap = loop / "trap"
    trap.mkdir()
    (trap / "trapped.txt").write_text("should be pruned as a loop")

    loop_str = str(loop)
    real = scan_guard.real_key

    def _ancestor_collide(path):
        # Give `trap` the SAME key as its ancestor `loop` -> a true ancestor cycle (pruned).
        # Everything else gets a unique key from its path so distinct dirs are NOT pruned.
        s = os.fspath(path)
        if os.path.basename(s) == "trap":
            return (1, 1000 + hash(loop_str) % 100000)  # == loop's key below
        if os.path.basename(s) == "loop":
            return (1, 1000 + hash(loop_str) % 100000)
        return (1, 2_000_000 + (hash(s) % 1_000_000))

    scan_guard.real_key = _ancestor_collide
    try:
        # Must TERMINATE (a non-pruned ancestor loop with a real symlink would hang; here the
        # filesystem has no real loop, but the guard must still PRUNE `trap` so we assert it's
        # excluded). Collect the yielded files.
        names = set()
        for p, _depth in index._iter_files(d):
            names.add(p.name)
    finally:
        scan_guard.real_key = real
    assert "top.txt" in names and "inner.txt" in names, ("non-loop files must be walked", names)
    assert "trapped.txt" not in names, ("the ancestor-cycle subtree must be pruned", names)


def test_index_permission_denied_subtree_is_skipped_not_fatal():
    """A permission-denied subtree (POSIX chmod 000) is skipped + counted, never fatal —
    the rest of the tree still indexes. Skipped on Windows (POSIX-mode semantics) and as
    root (chmod 000 doesn't deny root)."""
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    from app import index

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "readable.txt").write_text("change of control")
    locked = d / "locked"
    locked.mkdir()
    (locked / "secret.txt").write_text("inside")
    os.chmod(locked, 0o000)
    try:
        db = str(Path(tempfile.mkdtemp()) / "m.db")
        stats = index.index_folder(str(d), db)
        # The readable file indexed; the run did NOT abort; the denied dir was counted.
        assert stats["indexed"] >= 1, stats
        assert stats["skipped_denied"] >= 1, stats
        est = index.estimate_folder(str(d))
        assert est["denied_dirs"] >= 1, est
    finally:
        os.chmod(locked, 0o700)  # restore so the tempdir can be cleaned


def test_index_folder_bad_root_raises_catchable_exception():
    """C2: index_folder's "not a folder" guard must raise a NORMAL Exception (not
    SystemExit, a BaseException) — the index worker catches `except Exception`, so a
    SystemExit would escape it and leave the job stuck "running" forever."""
    from app import index

    missing = str(Path(tempfile.mkdtemp()) / "does-not-exist")
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    raised = None
    try:
        index.index_folder(missing, db)
    except SystemExit as e:  # would escape the worker's `except Exception`
        raised = ("SystemExit", e)
    except Exception as e:  # noqa: BLE001 - the worker's actual handler
        raised = ("Exception", e)
    assert raised is not None, "index_folder accepted a non-folder root"
    assert raised[0] == "Exception", "guard raised SystemExit — worker can't catch it"
    assert not isinstance(raised[1], SystemExit), raised


def test_ocr_render_temp_rasters_cleaned_up():
    """C3: the rasterized page images (MATTER CONTENT) written to temp during an OCR run
    must be deleted afterwards — even when OCR itself fails — so no cleartext page raster
    is left on disk. We stub the renderer + OCR so this runs without pypdfium2/tesseract."""
    from app import ocr

    tmpdir = Path(tempfile.mkdtemp(prefix="ldm-ocr-test-"))
    raster = tmpdir / "p1.png"
    raster.write_bytes(b"fake page raster bytes")  # stand-in for matter content

    orig_render = ocr._render_pdf_pages
    orig_avail = ocr.available
    orig_ocr_image = ocr.ocr_image
    try:
        ocr.available = lambda: True
        ocr._render_pdf_pages = lambda *a, **k: (tmpdir, [(0, str(raster))])
        # OCR raises mid-run: the finally must STILL clean up the rasters.
        def boom(*a, **k):
            raise RuntimeError("ocr blew up")
        ocr.ocr_image = boom
        try:
            ocr.ocr_pdf("ignored.pdf")
        except RuntimeError:
            pass  # the raise is fine; the cleanup is what we assert
        assert not raster.exists(), "raster left on disk after OCR failure"
        assert not tmpdir.exists(), "temp render dir left on disk after OCR failure"
    finally:
        ocr._render_pdf_pages = orig_render
        ocr.available = orig_avail
        ocr.ocr_image = orig_ocr_image
        # belt-and-suspenders: don't leave the fixture dir behind if an assert tripped
        import shutil as _sh
        _sh.rmtree(tmpdir, ignore_errors=True)


def test_sweep_temp_clears_leftover_rasters():
    """H-2: a hard kill BETWEEN writing an OCR temp raster and its `finally: remove` would
    leave matter-content PNGs in the app-data temp dir. paths.sweep_temp() must delete every
    survivor (files AND subdirs) on the next startup, best-effort, never raising — and
    create_app() must run that sweep when it builds the app."""
    from app import paths

    tmp = paths.temp_dir()
    # Simulate survivors of a crashed OCR run: a stray raster PNG + a render SUBDIR.
    stray = tmp / "ldm-pdfpreview-crashed.png"
    stray.write_bytes(b"matter content raster")
    subdir = tmp / "ldm-ocr-crashed"
    subdir.mkdir(exist_ok=True)
    (subdir / "p1.png").write_bytes(b"another raster")
    assert stray.exists() and subdir.exists()

    removed = paths.sweep_temp()
    assert removed >= 2, removed
    assert not stray.exists(), "stray raster survived the sweep"
    assert not subdir.exists(), "render subdir survived the sweep"
    # Idempotent + safe on an empty dir.
    assert paths.sweep_temp() == 0

    # create_app() sweeps on startup: re-plant a survivor, build the app, assert it's gone.
    again = tmp / "ldm-imgredact-crashed.png"
    again.write_bytes(b"raster")
    assert again.exists()
    from app.web import AppState, create_app
    create_app(AppState())  # building the app runs the startup sweep
    assert not again.exists(), "create_app() did not sweep the leftover temp raster on startup"


def test_temp_dir_under_data_dir_not_system_temp():
    """H-2: the OCR temp dir lives UNDER the app-data root (LAWDATAMAN_DATA_DIR), NOT the
    system temp dir — so a survivor is in a swept, app-owned location, never recoverable in
    /tmp. The three raster sites all mkstemp/mkdtemp with dir=paths.temp_dir()."""
    from app import paths

    td = paths.temp_dir()
    assert td.is_dir()
    assert td.resolve() == (paths.data_dir() / "tmp").resolve()
    # It is inside the configured data dir (the test sets LAWDATAMAN_DATA_DIR), not system tmp.
    assert paths.data_dir().resolve() in td.resolve().parents


def test_estimate_folder_counts_small_tree():
    """estimate_folder returns sane counts on a small synthetic tree (files/bytes/depth)
    and never opens a file (counts are from stat alone)."""
    from app import index

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "one.txt").write_text("aaaa")          # 4 bytes
    (d / "two.txt").write_text("bbbbbb")        # 6 bytes
    sub = d / "deeper"
    sub.mkdir()
    (sub / "three.txt").write_text("cc")        # 2 bytes, depth 2
    (d / ".hidden").write_text("ignored")       # dotfile -> skipped

    est = index.estimate_folder(str(d))
    assert est["files"] == 3, est                # the dotfile is excluded
    assert est["bytes"] == 12, est
    assert est["max_depth"] == 2, est
    assert est["offline"] == 0 and est["too_large"] == 0 and est["denied_dirs"] == 0, est
    assert est["root_level"] == "ok", est
    assert "dirs" not in est, est                # F-2: the dead dirs counter is gone


def test_estimate_folder_opens_nothing():
    """The PRE-WALK estimate must NEVER open or hash any file (counts are from stat
    alone) — opening a cloud OFFLINE placeholder would force a network download. We
    spy index.sha256 AND open()/Path.open() across an estimate over a tree that
    INCLUDES a (monkeypatched) offline placeholder, and assert ZERO opens/hashes."""
    import builtins

    from app import index, scan_guard

    d = Path(tempfile.mkdtemp()).resolve()
    (d / "online_only.docx").write_text("would-download")     # 14-byte placeholder
    (d / "normal.txt").write_text("present on disk")
    sub = d / "deeper"
    sub.mkdir()
    (sub / "more.txt").write_text("nested")

    def fake_offline(st):
        # Flag the placeholder by its body length (st alone can't see the name),
        # mirroring the offline test's faked st_file_attributes approach.
        return getattr(st, "st_size", -1) == len("would-download")

    hashed = {"paths": []}
    opened = {"n": 0}
    orig_offline = scan_guard.is_offline_placeholder
    orig_sha = index.sha256
    orig_open = builtins.open
    orig_path_open = Path.open

    def spy_sha(path, *a, **k):
        hashed["paths"].append(Path(path).name)
        return orig_sha(path, *a, **k)

    def spy_open(*a, **k):
        opened["n"] += 1
        return orig_open(*a, **k)

    def spy_path_open(self, *a, **k):
        opened["n"] += 1
        return orig_path_open(self, *a, **k)

    scan_guard.is_offline_placeholder = fake_offline
    index.sha256 = spy_sha
    builtins.open = spy_open
    Path.open = spy_path_open
    try:
        est = index.estimate_folder(str(d))
    finally:
        scan_guard.is_offline_placeholder = orig_offline
        index.sha256 = orig_sha
        builtins.open = orig_open
        Path.open = orig_path_open

    # The estimate still counted from stat alone, INCLUDING the placeholder...
    assert est["files"] == 3, est
    assert est["offline"] == 1, est
    # ...but opened/hashed NOTHING (the load-bearing no-download guarantee).
    assert hashed["paths"] == [], hashed
    assert opened["n"] == 0, opened


def test_index_estimate_endpoint_and_refuse_gate():
    """The /api/index/estimate endpoint sizes a folder (token-guarded), and /api/index
    HARD-REFUSES a system/drive root server-side regardless of any confirm flag."""
    c = _client()
    # estimate over the fixtures: ok level, files counted, never raises.
    r = c.post("/api/index/estimate", json={"folder": FIXTURES})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["level"] in ("ok", "warn") and body["files"] >= 1, body

    # estimate without the token -> 403.
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/index/estimate", json={"folder": FIXTURES}).status_code == 403

    # /api/index HARD-refuses a refuse root (server-side, even WITH confirm:true).
    refuse_root = "/etc" if os.name != "nt" else "C:\\Windows"
    if Path(refuse_root).is_dir():
        r2 = c.post("/api/index", json={"folder": refuse_root, "confirm": True})
        assert r2.status_code == 400 and r2.json().get("level") == "refuse", r2.text
        # estimate likewise reports refuse as a 400 structured payload.
        r3 = c.post("/api/index/estimate", json={"folder": refuse_root})
        assert r3.status_code == 400 and r3.json().get("level") == "refuse", r3.text


def test_add_source_does_not_change_db_identity():
    """LOAD-BEARING: adding a source must NOT re-key the matter .db. db_path_for
    hashes the PRIMARY root only, and an added source is matter DATA, never a new
    matter — so the .db path is identical before and after add_source."""
    from app.paths import db_path_for
    from app.index import index_folder, add_source

    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary doc")
    extra = Path(tempfile.mkdtemp()).resolve()
    (extra / "e.txt").write_text("added doc")

    db_before = db_path_for(str(primary))
    db = str(db_before)
    index_folder(str(primary), db)
    # the .db key is the primary root's hash; adding a source must not change it
    res = add_source(db, str(extra), "folder")
    assert "error" not in res, res
    assert db_path_for(str(primary)) == db_before, "adding a source re-keyed the .db"
    # and crucially the added folder being itself a matter elsewhere has a DIFFERENT db
    assert db_path_for(str(extra)) != db_before


def test_add_source_tags_files_and_manifest_shows_source():
    """add_source indexes a 2nd folder, tags its files with the new source_id, and the
    manifest shows the `source` column + carries source_id. The new column is placed
    right after `folder`."""
    from app.index import index_folder, add_source
    from app.automations import build_manifest, MANIFEST_COLUMNS

    # `source` is right after `folder` in the CSV column order
    assert MANIFEST_COLUMNS.index("source") == MANIFEST_COLUMNS.index("folder") + 1

    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "primary.txt").write_text("change of control here")
    extra = Path(tempfile.mkdtemp()).resolve()
    (extra / "added.txt").write_text("indemnification clause")

    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(primary), db)
    res = add_source(db, str(extra), "folder", label="Side letters")
    assert "error" not in res and res["source_id"], res
    sid = res["source_id"]

    data = build_manifest(db)
    by_name = {r["filename"]: r for r in data["rows"]}
    assert "primary.txt" in by_name and "added.txt" in by_name, by_name.keys()
    # the added file's row is tagged with the added source's id + shows the label
    assert by_name["added.txt"]["source_id"] == sid
    assert by_name["added.txt"]["source"] == "Side letters"
    # the primary file's source is the primary folder's basename (no label)
    assert by_name["primary.txt"]["source_id"] != sid
    assert by_name["primary.txt"]["source"] == primary.name


def test_add_source_files_kind_common_parent_root():
    """A 'files'-kind source accepts a list of file paths, indexes each, and derives
    root = their common parent dir."""
    from app.index import index_folder, add_source
    from app.web import list_sources

    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary")
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(primary), db)

    base = Path(tempfile.mkdtemp()).resolve()
    sub = base / "deep"
    sub.mkdir()
    f1 = base / "one.txt"
    f1.write_text("file one")
    f2 = sub / "two.txt"
    f2.write_text("file two")
    res = add_source(db, [str(f1), str(f2)], "files")
    assert "error" not in res, res
    assert Path(res["root"]).resolve() == base, res  # common parent of the two files

    srcs = {s["root"]: s for s in list_sources(db)}
    assert str(base) in srcs and srcs[str(base)]["kind"] == "files"
    assert srcs[str(base)]["files"] == 2

    # Fix (Low): adding files whose common parent == an EXISTING source's root must NOT
    # flip that source's kind. Add a file directly under the PRIMARY folder via the
    # 'files' path (common parent == primary root); the primary source must stay 'folder'.
    extra = primary / "extra.txt"
    extra.write_text("under the primary root")
    res2 = add_source(db, [str(extra)], "files")
    assert "error" not in res2, res2
    assert Path(res2["root"]).resolve() == primary, res2  # parent of the single file
    primary_src = {s["root"]: s for s in list_sources(db)}.get(str(primary))
    assert primary_src and primary_src["kind"] == "folder", primary_src  # kind preserved


def test_add_files_skips_offline_without_opening():
    """A cloud OFFLINE placeholder added via the 'files'-kind path is recorded
    skipped-offline and is NEVER opened (opening would force a download) — the SAME
    load-bearing guarantee as the primary index (mirrors
    test_index_skips_offline_without_opening, but through add_source(kind='files'))."""
    from app import index, scan_guard
    from app.index import index_folder, add_source

    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary")
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(primary), db)

    src = Path(tempfile.mkdtemp()).resolve()
    offline = src / "online_only.docx"
    offline.write_text("would-download")          # 14 bytes; the placeholder
    normal = src / "normal.txt"
    normal.write_text("change of control text")

    seen_offline = {"hit": False}

    def fake_offline(st):
        # We can't see the name from st alone; flag the one whose size matches the
        # placeholder body length (same trick as the primary-index offline test).
        if getattr(st, "st_size", -1) == len("would-download"):
            seen_offline["hit"] = True
            return True
        return False

    opened = {"paths": []}
    extracted = {"paths": []}
    orig_offline = scan_guard.is_offline_placeholder
    orig_sha = index.sha256
    orig_extract = index.extract

    def spy_sha(path, *a, **k):
        opened["paths"].append(Path(path).name)
        return orig_sha(path, *a, **k)

    def spy_extract(path, *a, **k):
        extracted["paths"].append(Path(path).name)
        return orig_extract(path, *a, **k)

    scan_guard.is_offline_placeholder = fake_offline
    index.sha256 = spy_sha
    index.extract = spy_extract
    try:
        res = add_source(db, [str(offline), str(normal)], "files")
    finally:
        scan_guard.is_offline_placeholder = orig_offline
        index.sha256 = orig_sha
        index.extract = orig_extract
    assert "error" not in res, res
    assert seen_offline["hit"], "the placeholder file's stat must be checked"
    assert res["skipped_offline"] == 1, res
    # The placeholder was NEITHER hashed/opened NOR text-extracted; the normal file was.
    assert "online_only.docx" not in opened["paths"], opened
    assert "online_only.docx" not in extracted["paths"], extracted
    assert "normal.txt" in opened["paths"], opened


def test_backfill_primary_source_on_legacy_db():
    """Opening a matter whose DB predates the sources table must create the PRIMARY
    source row from meta['source_root'] and set source_id on the legacy (NULL) rows."""
    from app.db import connect, set_meta, backfill_primary_source

    legacy_root = str(Path(tempfile.mkdtemp()).resolve())
    db = str(Path(tempfile.mkdtemp()) / "legacy.db")
    # Simulate a legacy matter: files rows with NULL source_id + a source_root, NO
    # sources rows (mimic a DB created before multi-source).
    with closing(connect(db)) as con:
        set_meta(con, "source_root", legacy_root)
        con.execute("DELETE FROM sources")  # drop the auto-created primary
        con.execute(
            "INSERT INTO files(path, filename, ext, source_id) VALUES(?,?,?,NULL)",
            (legacy_root + "/old.txt", "old.txt", ".txt"))
        con.commit()
        # precondition: no source rows, file untagged
        assert con.execute("SELECT COUNT(*) n FROM sources").fetchone()["n"] == 0
        assert con.execute(
            "SELECT source_id FROM files WHERE filename='old.txt'").fetchone()["source_id"] is None

    with closing(connect(db)) as con:
        backfill_primary_source(con)
        con.commit()
        rows = con.execute("SELECT id, root, kind FROM sources").fetchall()
        assert len(rows) == 1 and rows[0]["root"] == legacy_root and rows[0]["kind"] == "folder"
        sid = rows[0]["id"]
        assert con.execute(
            "SELECT source_id FROM files WHERE filename='old.txt'").fetchone()["source_id"] == sid

    # idempotent: a second backfill changes nothing
    with closing(connect(db)) as con:
        backfill_primary_source(con)
        con.commit()
        assert con.execute("SELECT COUNT(*) n FROM sources").fetchone()["n"] == 1


def test_reindex_missing_source_marks_missing_keeps_rows():
    """A re-index where an added source's root no longer exists marks the source
    status='missing' and KEEPS its (now-stale) file rows — never deletes them (the
    same 'moved' UX as a relocated file)."""
    from app.index import index_folder, add_source, reindex_sources
    from app.db import connect

    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary")
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(primary), db)

    extra = Path(tempfile.mkdtemp()).resolve()
    (extra / "added.txt").write_text("added doc")
    res = add_source(db, str(extra), "folder")
    sid = res["source_id"]

    # the added folder disappears (deleted/unmounted)
    (extra / "added.txt").unlink()
    extra.rmdir()
    assert not extra.exists()

    out = reindex_sources(db)
    assert out[sid]["status"] == "missing" and out[sid]["kept"] is True, out
    with closing(connect(db)) as con:
        # the sources row is marked missing
        assert con.execute(
            "SELECT status FROM sources WHERE id=?", (sid,)).fetchone()["status"] == "missing"
        # its file rows are KEPT (not deleted)
        assert con.execute(
            "SELECT COUNT(*) n FROM files WHERE source_id=?", (sid,)).fetchone()["n"] == 1


def test_remove_source_deletes_only_that_source():
    """remove_source deletes ONLY the target source's files + chunks + sources row;
    the primary (and any other source) is untouched. The primary cannot be removed."""
    from app.index import index_folder, add_source, remove_source
    from app.db import connect

    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("change of control")
    db = str(Path(tempfile.mkdtemp()) / "m.db")
    index_folder(str(primary), db)

    extra = Path(tempfile.mkdtemp()).resolve()
    (extra / "added.txt").write_text("indemnification clause")
    res = add_source(db, str(extra), "folder")
    sid = res["source_id"]

    with closing(connect(db)) as con:
        total_before = con.execute("SELECT COUNT(*) n FROM files").fetchone()["n"]
        primary_row = con.execute(
            "SELECT id FROM sources WHERE root=?", (str(primary),)).fetchone()
        primary_id = primary_row["id"]

    # removing the PRIMARY is refused
    bad = remove_source(db, primary_id)
    assert "error" in bad and bad["deleted"] == 0, bad

    # removing the added source deletes exactly its one file row
    ok = remove_source(db, sid)
    assert ok["deleted"] == 1, ok
    with closing(connect(db)) as con:
        assert con.execute("SELECT COUNT(*) n FROM files").fetchone()["n"] == total_before - 1
        assert con.execute("SELECT COUNT(*) n FROM sources WHERE id=?", (sid,)).fetchone()["n"] == 0
        # the primary's file survives
        assert con.execute(
            "SELECT COUNT(*) n FROM files WHERE source_id=?", (primary_id,)).fetchone()["n"] == 1
        # no orphan chunks left for the removed source
        assert con.execute(
            "SELECT COUNT(*) n FROM chunks WHERE file_id NOT IN (SELECT id FROM files)"
        ).fetchone()["n"] == 0


def test_file_under_second_source_opens_not_outside():
    """A file under a 2nd (added) source must open/reveal (be 'inside' the matter), not
    be rejected as 'outside' — _matter_file checks membership against ALL source roots."""
    c = _client()
    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary")
    _wait_index(c, str(primary))

    extra = Path(tempfile.mkdtemp()).resolve()
    added = extra / "added.txt"
    added.write_text("added doc")
    r = _add_source_and_wait(c, root=str(extra))
    assert r.status_code == 200, r.text

    # the file under the added source opens (launch disabled in tests -> ok:true)
    assert c.post("/api/file/open", json={"path": str(added)}).json().get("ok") is True
    assert c.post("/api/file/reveal", json={"path": str(added)}).json().get("ok") is True

    # a file under NEITHER source is still refused as outside (this test file)
    assert c.post("/api/file/open", json={"path": str(Path(__file__))}).status_code == 400


def test_sources_endpoints_token_and_state():
    """The source endpoints require the token, surface sources in /api/state, and a
    refuse-level root is HARD-blocked server-side."""
    primary = Path(tempfile.mkdtemp()).resolve()
    (primary / "p.txt").write_text("primary")

    # token required
    state = AppState()
    c_noauth = TestClient(create_app(state))
    assert c_noauth.post("/api/sources/add", json={"root": str(primary)}).status_code == 403
    assert c_noauth.post("/api/sources/remove", json={"id": 1}).status_code == 403

    c = _client()
    # no matter open -> add is a clean 400, not a crash
    assert c.post("/api/sources/add", json={"root": str(primary)}).status_code == 400

    _wait_index(c, str(primary))
    # state now lists the primary source
    st = c.get("/api/state").json()
    assert st["sources"] and any(s["primary"] for s in st["sources"]), st.get("sources")

    # a refuse-level root is HARD-blocked even though a matter is open
    refuse_root = "/etc" if os.name != "nt" else "C:\\Windows"
    if Path(refuse_root).is_dir():
        rr = c.post("/api/sources/add", json={"root": refuse_root, "confirm": True})
        assert rr.status_code == 400 and rr.json().get("level") == "refuse", rr.text


def test_extract_txt_non_ascii_does_not_crash_or_mangle():
    """extract_txt must NOT decode a matter .txt/.md via the platform locale codec
    (cp1252 on Windows), which would mangle UTF-8 multi-byte chars and corrupt what
    SEARCH and REDACTION see. EXTRACTION-ADJACENT: read bytes + decode UTF-8 with a
    never-raising latin-1 fallback, preserving ASCII byte-for-byte.

    Covers all three byte profiles regardless of the host locale:
    - pure ASCII round-trips unchanged;
    - a UTF-8 smart-quote / em-dash decodes to the SAME characters (not mojibake);
    - a lone high byte (cp1252/latin-1-only) neither raises nor drops content."""
    from app.extractors import extract_txt

    with tempfile.TemporaryDirectory(prefix="ldm-txtenc-") as d:
        base = Path(d)

        ascii_p = base / "ascii.txt"
        ascii_p.write_bytes(b"Hello, world. Plain ASCII.")
        assert extract_txt(ascii_p) == [("text", "Hello, world. Plain ASCII.")]

        # UTF-8 smart quotes (“ ” = U+201C/U+201D) + em-dash (— = U+2014). These are
        # multi-byte in UTF-8; the locale codec would corrupt them.
        utf8_p = base / "utf8.txt"
        utf8_p.write_text("Acme “Smart” — Résumé", encoding="utf-8")
        units = extract_txt(utf8_p)
        assert units, "non-empty UTF-8 file must extract"
        text = units[0][1]
        assert "“" in text and "”" in text and "—" in text and "Résumé" in text
        assert "�" not in text, "UTF-8 content must NOT become replacement chars"

        # A lone 0x9d byte is invalid UTF-8 and (notoriously) the exact byte that the
        # cp1252 'charmap' codec rejects. Must neither raise nor drop content.
        legacy_p = base / "legacy.txt"
        legacy_p.write_bytes(b"caf\xe9 smart\x9dquote tail")  # \xe9 = é, \x9d = lone high byte
        legacy_units = extract_txt(legacy_p)
        assert legacy_units, "legacy single-byte content must extract (latin-1 fallback)"
        legacy_text = legacy_units[0][1]
        assert legacy_text.startswith("caf") and legacy_text.endswith("quote tail")
        assert "smart" in legacy_text and "quote" in legacy_text  # nothing dropped


# ---------------------------------------------------------------------------
# ROUND 2 fleet-review fixes — regression tests.
# ---------------------------------------------------------------------------
def test_extractors_truncate_decompression_bomb_docx_and_xlsx():
    """[#7] A text-bomb docx/xlsx (small file, huge expanded text) is TRUNCATED at the
    expanded-size cap, not allowed to OOM the indexer. extract() reports 'truncated'
    (still indexed), the bytes are bounded near the cap, and a marker unit is present."""
    import importlib
    import app.extractors as E

    old = os.environ.get("LAWDATAMAN_MAX_EXTRACT_BYTES")
    os.environ["LAWDATAMAN_MAX_EXTRACT_BYTES"] = "2000"
    try:
        importlib.reload(E)
        assert E.MAX_EXTRACT_BYTES == 2000

        try:
            import docx
        except ImportError:
            docx = None
        if docx is not None:
            d = docx.Document()
            for i in range(5000):
                d.add_paragraph("paragraph %d with filler text to consume bytes fast" % i)
            fd, p = tempfile.mkstemp(suffix=".docx")
            os.close(fd)
            d.save(p)
            try:
                status, units, err = E.extract(Path(p))
                assert status == "truncated", status
                total = sum(len(t.encode("utf-8")) for _, t in units)
                # bounded near the cap, NOT 5000 paragraphs worth (~hundreds of KB)
                assert total < 2000 + 4000, total
                assert any(loc == E._TRUNCATED_LOCATOR for loc, _ in units), units
            finally:
                os.remove(p)

        try:
            import openpyxl
        except ImportError:
            openpyxl = None
        if openpyxl is not None:
            wb = openpyxl.Workbook()
            ws = wb.active
            for r in range(5000):
                ws.append(["cell-%d-%d longish value" % (r, c) for c in range(10)])
            fd, p2 = tempfile.mkstemp(suffix=".xlsx")
            os.close(fd)
            wb.save(p2)
            try:
                status, units, err = E.extract(Path(p2))
                assert status == "truncated", status
                assert any(loc == E._TRUNCATED_LOCATOR for loc, _ in units), units
            finally:
                os.remove(p2)
    finally:
        if old is None:
            os.environ.pop("LAWDATAMAN_MAX_EXTRACT_BYTES", None)
        else:
            os.environ["LAWDATAMAN_MAX_EXTRACT_BYTES"] = old
        importlib.reload(E)   # restore the default cap for later tests


def test_add_source_files_kind_refuses_app_data_dir(tmp_path=None):
    """[#15] The picked-files add path must be gated like the folder path: a file inside the
    app's own data dir (where matter DBs live) is REFUSED, both when the common parent IS the
    data dir and when it is broader (one file under data_dir, one elsewhere)."""
    from app import index, paths

    data = paths.data_dir()
    f1 = data / "sneaky.txt"
    f1.write_text("looks like a matter db")
    # (a) all files under the data dir -> common parent is the data dir -> refuse
    res = index.add_source("/nonexistent.db", [str(f1)], "files")
    assert "error" in res and res.get("level") == "refuse", res

    # (b) one file under data dir + one elsewhere -> broad common parent, per-file check fires
    other = Path(tempfile.mkdtemp())
    f2 = other / "real.txt"
    f2.write_text("ok")
    res2 = index.add_source("/nonexistent.db", [str(f1), str(f2)], "files")
    assert res2.get("level") == "refuse", res2


def test_estimate_folder_deadline_bites_on_traversal_not_just_files():
    """[#10] The estimate's timeout must bound the TRAVERSAL (checked per directory), not
    only the per-file loop — a dir-heavy tree yields no files, so the per-file checks would
    never run. With a clock forced past the deadline, estimate_folder stops and reports
    capped=True (it does not walk the whole tree)."""
    import importlib
    import app.scan_guard as SG
    import app.index as IDX

    old = os.environ.get("LAWDATAMAN_ESTIMATE_TIMEOUT_S")
    os.environ["LAWDATAMAN_ESTIMATE_TIMEOUT_S"] = "1"
    real_time = IDX.time.time
    try:
        importlib.reload(SG)
        importlib.reload(IDX)
        assert SG.ESTIMATE_TIMEOUT_S == 1

        calls = {"n": 0}

        def fake_time():
            calls["n"] += 1
            # first read = 'started'; every later read jumps past the 1s deadline
            return 1000.0 if calls["n"] <= 1 else 1100.0

        IDX.time.time = fake_time
        root = Path(tempfile.mkdtemp())
        for a in range(5):
            sub = root / ("d%d" % a)
            sub.mkdir()
            (sub / "f.txt").write_text("hi")
        out = IDX.estimate_folder(str(root))
        assert out["capped"] is True, out
    finally:
        IDX.time.time = real_time
        if old is None:
            os.environ.pop("LAWDATAMAN_ESTIMATE_TIMEOUT_S", None)
        else:
            os.environ["LAWDATAMAN_ESTIMATE_TIMEOUT_S"] = old
        importlib.reload(SG)
        importlib.reload(IDX)


def test_index_safe_error_strips_embedded_paths_and_filenames():
    """[#3/#12] _safe_error strips path-bearing / quoted / extension-bearing runs even when
    they're embedded mid-message (no surrounding whitespace), so a matter file path/name
    never reaches the UI/CSV."""
    from app.index import _safe_error

    e = FileNotFoundError(
        "[Errno 2] No such file or directory: '/matters/Acme/secret-merger.docx'")
    out = _safe_error(e)
    assert "secret-merger" not in out, out
    assert "/matters/Acme" not in out, out
    assert "<path>" in out, out
    assert out.startswith("FileNotFoundError"), out

    # a Windows-style embedded path is also stripped
    e2 = PermissionError(r"access denied: C:\Clients\Beta\board-minutes.pdf")
    out2 = _safe_error(e2)
    assert "board-minutes" not in out2 and "Beta" not in out2, out2


def test_extractors_decode_ladder_recovers_cp1252_word_punctuation():
    """Tier-1 crate-audit fix: the .txt/.md decode ladder recovers Word/cp1252
    punctuation (smart quotes, em/en dash) instead of mangling those bytes to C1
    control chars via a blind latin-1 fallback -- that text feeds search + redaction.
    UTF-8 still wins first; a cp1252-undefined byte still hits the never-raise floor."""
    from app.extractors import _decode_text_bytes
    # cp1252 bytes Word writes (0x93 0x94 = curly quotes, 0x97 em-dash, 0x96 en-dash)
    # must decode to the INTENDED Unicode, not the C1 control chars latin-1 yields.
    raw = b"\x93Smith\x94 \x97 the \x96 dash"
    out = _decode_text_bytes(raw)
    assert "“Smith”" in out, out              # curly double quotes
    assert "—" in out, out                         # em-dash from 0x97
    assert "–" in out, out                         # en-dash from 0x96
    assert "\x93" not in out and "\x94" not in out, out  # not left as raw C1 bytes
    # A genuine UTF-8 file still decodes as UTF-8 (the utf-8 rung wins first).
    assert _decode_text_bytes("café €".encode("utf-8")) == "café €"
    # A byte UNDEFINED in cp1252 (0x81) still decodes via the total latin-1 floor,
    # never raising and never dropping content.
    assert _decode_text_bytes(b"ok\x81end") == "ok\x81end"
