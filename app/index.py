r"""
Walk a folder (the exported data room), extract text, store it.

Dev CLI:  python -m app.index  /path/to/dataroom  matter.db

- Hashes every file (sha256) for integrity + duplicate detection.
- Skips files already indexed with an unchanged hash (incremental re-runs).
- Reads originals only; never writes to the source tree.

The desktop shell calls index_folder() with a `progress` callback (for the
progress bar) and a `should_cancel` predicate (so the user can abort). The CLI
passes neither.

Windows hardening:
  - Deeply nested data rooms blow past MAX_PATH (260). We resolve to a
    `\\?\`-prefixed extended path for filesystem ops so deep files are not
    silently skipped.
  - A single locked/unreadable file (open in Word, permission-denied, etc.)
    must never abort the whole run: every per-file step is guarded and recorded
    as an error row instead of raising.
"""

import hashlib
import os
import re
import stat
import sys
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .db import connect, set_meta, get_meta, backfill_primary_source, norm_path
from .extractors import extract
from .classify import is_scanned_pdf
from . import scan_guard
from . import paths


# Cap on a stored/returned error message. The raw exception string can embed the
# full file path (matter-identifying) and arbitrary content; we keep only a short,
# path-stripped form in the DB (which feeds the browser + CSV). Fuller operational
# detail belongs in the rotating support log, not the per-matter index.
_ERR_MAX_LEN = 200

# Substrings that look like a filesystem path or a quoted run carrying matter-
# identifying content. Each whole match is replaced with `<path>` BEFORE the
# per-token pass — a path embedded mid-token (no surrounding whitespace, the
# common case in OS error strings like `[Errno 2] No such file or directory:
# '/matters/Acme/secret.docx'`) would otherwise survive the whitespace split.
# Over-redaction is the safe side for a non-identifying error string.
_PATH_RUN_RE = re.compile(
    # 1) anything inside single/double quotes (OSError embeds the path quoted);
    r"'[^']*'|\"[^\"]*\""
    # 2) a Windows drive-letter path (C:\... or C:/...);
    r"|[A-Za-z]:[\\/][^\s\"']*"
    # 3) a UNC / POSIX-rooted / any run containing a separator (a path-like token);
    r"|(?:\\\\|/)[^\s\"']*"
    r"|[^\s\"']*[\\/][^\s\"']*"
    # 4) a bare filename with an extension (e.g. secret.docx) — still identifying.
    r"|[^\s\"'\\/]+\.[A-Za-z0-9]{1,8}\b"
)


def _safe_error(exc: BaseException) -> str:
    """A non-identifying error string: exception type + a truncated message with
    any path-like / quoted / extension-bearing runs stripped, so matter file paths
    (and filenames) never reach the UI/CSV. Over-redacts on purpose."""
    msg = str(exc)
    # Replace whole path-bearing / quoted / extension runs first (handles a path
    # with no surrounding whitespace, e.g. a trailing `: '/x/y.docx'`), THEN keep
    # the prior per-token pass as a belt-and-braces fallback for odd shapes.
    msg = _PATH_RUN_RE.sub("<path>", msg)
    cleaned = []
    for tok in msg.split():
        if "/" in tok or "\\" in tok or (len(tok) > 2 and tok[1:3] == ":\\"):
            cleaned.append("<path>")
        else:
            cleaned.append(tok)
    out = " ".join(cleaned).strip()
    if len(out) > _ERR_MAX_LEN:
        out = out[:_ERR_MAX_LEN] + "…"
    return f"{type(exc).__name__}: {out}" if out else type(exc).__name__


def _long(path: Path) -> Path:
    r"""Return a path safe for deep Windows trees (\\?\-prefixed). No-op elsewhere."""
    if os.name != "nt":
        return path
    s = os.fspath(path.resolve())
    if s.startswith("\\\\?\\"):
        return path
    if s.startswith("\\\\"):  # UNC share -> \\?\UNC\server\share\...
        return Path("\\\\?\\UNC\\" + s.lstrip("\\"))
    return Path("\\\\?\\" + s)


def _unlong(s: str) -> str:
    r"""Strip a \\?\ extended-length prefix back to a normal path for storage/display."""
    if os.name != "nt":
        return s
    if s.startswith("\\\\?\\UNC\\"):
        return "\\\\" + s[len("\\\\?\\UNC\\"):]
    if s.startswith("\\\\?\\"):
        return s[len("\\\\?\\"):]
    return s


def sha256(path: Path, buf=1 << 20) -> str:
    h = hashlib.sha256()
    # os.open with O_RDONLY shares read access on Windows, so a file opened
    # elsewhere (read-only) still hashes; an exclusively-locked file raises and
    # is caught by the caller.
    with open(_long(path), "rb") as f:
        for block in iter(lambda: f.read(buf), b""):
            h.update(block)
    return h.hexdigest()


def _iter_files(root: Path, should_cancel=None, on_denied=None):
    r"""STREAMING walk of `root` yielding (file_path, depth) for each regular-ish entry,
    deterministic WITHIN each directory (filenames sorted) but never materializing /
    sorting the whole tree (a whole-disk choice must not OOM building a giant list).

    Safety properties (the ingestion-envelope contract):
      - os.walk(followlinks=False): a symlinked dir is NOT descended (no escape).
      - ANCESTOR-chain loop guard (like GNU find): a subdir whose real (dev, ino)
        equals one of its OWN ANCESTORS on the path being walked is a true CYCLE (a
        symlink/junction pointing back UP the tree) and is pruned — the walk can't
        hang. We do NOT prune against a GLOBAL ever-seen set: two genuinely DISTINCT
        directories can legitimately share a (dev, ino) — FAT/exFAT report st_ino==0
        for everything, and some bind/overlay/network mounts reuse inodes — and a
        global set would silently leave a real subtree UNINDEXED (a recall MISS, the
        worst direction for a search tool). An st_ino of 0 (meaningless) NEVER prunes.
      - MAX_DEPTH: subtrees deeper than the ceiling are pruned (a runaway nest).
      - onerror: a PermissionError/OSError raised while LISTING a directory is caught
        and the subtree skipped + counted (via on_denied) — it never aborts the walk.
    Dotfiles are skipped (matching the prior rglob filter)."""
    walk_root = _long(root)

    def _onerror(err):
        # os.walk calls this with the OSError from a failed scandir/listdir instead of
        # raising — so one unreadable subtree skips quietly rather than killing the run.
        if on_denied is not None:
            on_denied(err)

    # Map each directory we descend INTO -> its real (dev, ino) key, so we can derive
    # the ANCESTOR-chain key set for any dirpath os.walk hands us (os.walk is iterative,
    # not recursive, so we reconstruct ancestors from this map rather than a call stack).
    # Seed the root's own key so a symlink BACK to the root is caught as a loop.
    dir_keys: dict[str, tuple] = {}
    root_key = scan_guard.real_key(walk_root)
    if root_key is not None:
        dir_keys[os.fspath(walk_root)] = root_key

    def _ancestor_keys(dirpath: str) -> set:
        """The set of real keys of dirpath's ancestors AT-OR-ABOVE it (those we've
        recorded on the way down). An ino==0 / unknown key is dropped (never prunes)."""
        keys = set()
        p = dirpath
        while True:
            k = dir_keys.get(p)
            if k is not None and k[1] != 0:   # st_ino==0 is meaningless -> ignore
                keys.add(k)
            parent = os.path.dirname(p)
            if parent == p:                   # reached the filesystem anchor
                break
            p = parent
        return keys

    for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=False,
                                                onerror=_onerror):
        if should_cancel and should_cancel():
            return
        # Depth relative to the root (number of path separators below it).
        try:
            depth = len(Path(dirpath).relative_to(walk_root).parts)
        except ValueError:
            depth = 0
        if depth >= scan_guard.MAX_DEPTH:
            dirnames[:] = []   # prune: do not descend deeper than the ceiling
        else:
            # Loop guard (ANCESTOR chain only): prune a subdir whose real (dev,ino)
            # matches one of its OWN ancestors on this path — a genuine loop (a dir
            # symlinked back up into itself). Record each kept subdir's key so its
            # own children can see it as an ancestor. Mutating dirnames in place is
            # how os.walk is told which subdirs to descend. st_ino==0 never prunes
            # (it's meaningless on FAT/exFAT and would wrongly collapse distinct dirs).
            ancestors = _ancestor_keys(dirpath)
            kept = []
            for d in sorted(dirnames):
                child = Path(dirpath) / d
                key = scan_guard.real_key(child)
                if key is not None and key[1] != 0 and key in ancestors:
                    continue   # this dir loops back to one of its ancestors -> skip
                if key is not None:
                    dir_keys[os.fspath(child)] = key
                kept.append(d)
            dirnames[:] = kept
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            yield Path(dirpath) / name, depth


def estimate_folder(root: str, should_cancel=None) -> dict:
    r"""A bounded PRE-WALK that sizes a chosen root WITHOUT opening any file, so the UI
    can warn / refuse before a single (possibly cloud-downloading) read happens.

    Returns a dict: files, bytes, max_depth, offline (cloud placeholders),
    too_large (files over MAX_FILE_BYTES), denied_dirs, capped (stopped early at
    ESTIMATE_MAX_FILES / ESTIMATE_TIMEOUT_S), root_level, root_reason.

    NEVER opens a file: counts come from stat() alone (an offline placeholder is
    detected by its attributes, never by reading it)."""
    rp = Path(root).expanduser().resolve()
    level, reason = scan_guard.classify_root(rp)
    out = {"files": 0, "bytes": 0, "max_depth": 0, "offline": 0,
           "too_large": 0, "denied_dirs": 0, "capped": False,
           "root_level": level, "root_reason": reason}
    if not rp.is_dir():
        out["error"] = "not a folder"
        return out

    denied = {"n": 0}

    def on_denied(_err):
        denied["n"] += 1

    started = time.time()
    # `iters` counts EVERY loop iteration (regular files, FIFOs/devices, broken
    # symlinks, stat failures alike); the cap/timeout key off it, NOT out["files"]
    # (which only counts regular files) — else a tree of non-regular entries never
    # increments the regular-file count and the "bounded" estimate runs unbounded.
    iters = 0
    # A DEADLINE-aware should_cancel handed to the walker. `_iter_files` checks
    # should_cancel ONCE PER DIRECTORY (not just per yielded file), so wrapping it
    # here makes the timeout/cap bite on a DIR-HEAVY tree too — a tree that descends
    # millions of empty directories yields no files, so the per-`iters` checks below
    # would never run and the "bounded" estimate would walk for far longer than
    # ESTIMATE_TIMEOUT_S. The wrapper bounds the TRAVERSAL itself, not just the
    # file-processing loop (#10). It NEVER raises (a clock read can't here) and is
    # cheap (a time read per directory, not per file). The original `should_cancel`
    # (the user's abort) is still honored.
    deadline = started + scan_guard.ESTIMATE_TIMEOUT_S

    def _walk_should_stop():
        if should_cancel and should_cancel():
            return True
        if iters >= scan_guard.ESTIMATE_MAX_FILES:
            out["capped"] = True
            return True
        if time.time() > deadline:
            out["capped"] = True
            return True
        return False

    for path, depth in _iter_files(rp, should_cancel=_walk_should_stop, on_denied=on_denied):
        if _walk_should_stop():
            break
        iters += 1
        if iters >= scan_guard.ESTIMATE_MAX_FILES:
            out["capped"] = True
            break
        if (iters & 0x3FF) == 0 and (time.time() - started) > scan_guard.ESTIMATE_TIMEOUT_S:
            out["capped"] = True
            break
        try:
            st = path.stat()
        except OSError:
            # Unreadable file -> count it (it'll be an error row at index time), but do
            # not open it. A denied DIRECTORY is handled by onerror above.
            denied["n"] += 1
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        out["files"] += 1
        if depth + 1 > out["max_depth"]:
            out["max_depth"] = depth + 1
        if scan_guard.is_offline_placeholder(st):
            out["offline"] += 1
            continue   # never read its size off the network; it's a stub on disk anyway
        if st.st_size > scan_guard.MAX_FILE_BYTES:
            out["too_large"] += 1
        out["bytes"] += st.st_size

    out["denied_dirs"] = denied["n"]
    return out


def index_folder(root: str, db_path: str, progress=None, should_cancel=None,
                 precount: int | None = None) -> dict:
    """Index `root` into `db_path`.

    progress(done:int, total:int, current:str) -> None   (optional)
    should_cancel() -> bool                                (optional)
    precount: a known file count (from estimate_folder) to use as the progress
              `total` instead of pre-walking the tree a second time. (optional)
    """
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        # A normal exception (NOT SystemExit, a BaseException): the worker thread
        # catches Exception, so SystemExit here would escape and leave the job
        # stuck "running" forever.
        raise ValueError(f"Not a folder: {root}")

    stats = {"seen": 0, "indexed": 0, "skipped": 0, "errors": 0,
             "unsupported": 0, "empty": 0, "scanned_pdfs": 0,
             "skipped_offline": 0, "skipped_too_large": 0, "skipped_denied": 0,
             "cancelled": False}
    started = time.time()

    # closing() releases the SQLite handle (and is paired with reset()'s WAL
    # cleanup elsewhere) even if an exception escapes the loop body.
    with closing(connect(db_path)) as con:
        cur = con.cursor()
        # Record which folder this matter indexes, so the shell can verify the DB
        # belongs to the folder being opened and confine write-tools off the source.
        set_meta(cur, "source_root", str(root))

        # Ensure the PRIMARY source row exists (multi-source ingestion) and tag every
        # file indexed here with it. The primary source's root == source_root (the
        # folder that keyed the .db). This keeps the sources table the single, complete
        # enumeration of read-only roots the confinement guards iterate, and gives the
        # manifest provenance for primary files too.
        now = datetime.now(timezone.utc).isoformat()
        cur.execute(
            "INSERT INTO sources(root, kind, label, added_at, last_indexed_at, status) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(root) DO UPDATE SET last_indexed_at=excluded.last_indexed_at, "
            "  status='ok'",
            (str(root), "folder", None, now, now, "ok"),
        )
        primary_source_id = cur.execute(
            "SELECT id FROM sources WHERE root = ?", (str(root),)
        ).fetchone()["id"]
        # Heal any legacy untagged rows (a DB indexed before multi-source) onto the
        # primary source, so attribution is complete after a re-index.
        cur.execute(
            "UPDATE files SET source_id = ? WHERE source_id IS NULL", (primary_source_id,)
        )

        # STREAMING walk (was: eager sorted(rglob("*"))). Walking the whole tree into a
        # sorted list OOMs on a whole-disk choice and abort-on-PermissionError killed the
        # job mid-walk. _iter_files() instead yields files lazily, deterministic WITHIN
        # each dir, with the symlink-loop guard + depth cap + onerror subtree-skip baked
        # in. We don't know `total` up front without a pre-walk, so use the estimate's
        # `precount` when the caller has one, else fall back to a running counter (the bar
        # shows progress without a hard total — better than re-walking the whole tree).
        def _on_denied(_err):
            # A directory we couldn't list: skip its subtree, count it, never abort.
            stats["skipped_denied"] += 1

        total = precount if isinstance(precount, int) and precount > 0 else 0
        done = 0

        for path, _depth in _iter_files(root, should_cancel=should_cancel,
                                        on_denied=_on_denied):
            if should_cancel and should_cancel():
                stats["cancelled"] = True
                break
            done += 1
            if total and done > total:
                total = done   # estimate undershot (files added since) -> keep bar sane
            if progress:
                progress(done, total or done, path.name)
            _process_file(cur, path, stats, source_id=primary_source_id)

        con.commit()

        dupes = cur.execute(
            """SELECT sha256, COUNT(*) n FROM files
               WHERE sha256 IS NOT NULL GROUP BY sha256 HAVING n > 1"""
        ).fetchall()
        stats["duplicate_groups"] = len(dupes)
    stats["elapsed_s"] = round(time.time() - started, 2)
    return stats


def _empty_stats() -> dict:
    return {"seen": 0, "indexed": 0, "skipped": 0, "errors": 0,
            "unsupported": 0, "empty": 0, "scanned_pdfs": 0,
            "skipped_offline": 0, "skipped_too_large": 0, "skipped_denied": 0,
            "cancelled": False}


def _common_parent(paths: list) -> Path:
    """The deepest directory that contains EVERY path in `paths` (a 'files'-kind
    source's `root`). With one file it's that file's parent; with files on
    different drives/anchors there is no common parent, so fall back to the first
    file's parent (a sane, real directory the confinement guards can compare against)."""
    parents = [p.parent for p in paths]
    try:
        common = Path(os.path.commonpath([str(p) for p in parents]))
    except ValueError:
        # Different drives/anchors (Windows) -> no common path; use the first parent.
        common = parents[0]
    return common


def add_source(db_path: str, target, kind: str, label: str | None = None,
               should_cancel=None, progress=None) -> dict:
    """Add an ADDITIONAL source of documents to an existing matter and index it.

    `kind='folder'`: `target` is a folder path; it is walked exactly like the
    primary index (the streaming walk + sha256 + incremental skip + per-file
    offline/too-large/non-regular pre-flight), and inserted/updated `files` rows
    are tagged with this source's id.

    `kind='files'`: `target` is a LIST of file paths (each must be a regular
    file); `root` is derived as their common parent dir. Each file is stat'd +
    hashed + extracted like a folder file.

    A folder source goes through scan_guard.classify_root first: a 'refuse' root
    is rejected outright (the load-bearing server-side guarantee); a 'warn' root
    is rejected unless the caller passes the confirm through the web layer (this
    function is the engine — the web layer runs the refuse/confirm gate before
    calling, mirroring /api/index).

    Returns a stats dict (same keys as index_folder) plus `source_id` and `root`,
    or `{"error": ...}` on a bad target. Reads originals only; never writes to any
    source tree. Identity (the matter .db) is unchanged — an added source is matter
    DATA, never a new matter."""
    stats = _empty_stats()
    started = time.time()

    if kind == "folder":
        root = Path(target).expanduser().resolve()
        if not root.is_dir():
            return {"error": "not a folder"}
        level, reason = scan_guard.classify_root(root)
        if level == "refuse":
            return {"error": reason, "level": "refuse"}
        targets_iter = None  # walk below
    elif kind == "files":
        if not isinstance(target, (list, tuple)) or not target:
            return {"error": "no files chosen"}
        files: list[Path] = []
        for raw in target:
            try:
                p = Path(raw).expanduser().resolve()
            except (OSError, ValueError):
                continue
            if p.is_file():
                files.append(p)
        if not files:
            return {"error": "no valid files chosen"}
        root = _common_parent(files).resolve()
        # SAFETY (#15): the folder path goes through classify_root; the picked-files
        # path must NOT bypass that gate. Two checks, mirroring the folder branch's
        # "refuse" semantics:
        #   1) classify_root(common_parent) refuses a system/drive/app-data root —
        #      a 'files' add whose chosen files all live under (say) the app's own
        #      data dir would otherwise let the user index their own matter DBs;
        #   2) belt-and-braces, refuse if ANY individual picked file lies inside the
        #      app's own data dir even when the common parent is broader (one file
        #      under data_dir with a sibling elsewhere → common parent escapes the
        #      classify check). data_n covers data_dir() and every subfolder.
        level, reason = scan_guard.classify_root(root)
        if level == "refuse":
            return {"error": reason, "level": "refuse"}
        try:
            data_dir = paths.data_dir().resolve()
            for p in files:
                try:
                    p.relative_to(data_dir)
                except ValueError:
                    continue
                return {"error": "Those files are inside the app's own data folder, "
                                 "not a data room.", "level": "refuse"}
        except (OSError, ValueError):
            pass
        targets_iter = files
    else:
        return {"error": "unknown source kind"}

    with closing(connect(db_path)) as con:
        # Make sure a legacy matter's primary source row exists before we add another,
        # so the source list (and confinement enumeration) is complete + consistent.
        backfill_primary_source(con)
        cur = con.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute(
            # DO NOT overwrite `kind` on conflict — keep the FIRST-SEEN kind. Adding
            # files whose common parent happens to equal an existing source's root
            # (e.g. the primary 'folder' root) would otherwise flip that source's kind
            # to 'files', a cosmetic mislabel in list_sources / the manifest. Refresh
            # only the timestamp + status; the original kind stands.
            "INSERT INTO sources(root, kind, label, added_at, last_indexed_at, status) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(root) DO UPDATE SET "
            "  last_indexed_at=excluded.last_indexed_at, status='ok'",
            (str(root), kind, label, now, now, "ok"),
        )
        row = cur.execute("SELECT id FROM sources WHERE root = ?", (str(root),)).fetchone()
        source_id = row["id"]

        if kind == "folder":
            def _on_denied(_err):
                stats["skipped_denied"] += 1

            for path, _depth in _iter_files(root, should_cancel=should_cancel,
                                            on_denied=_on_denied):
                if should_cancel and should_cancel():
                    stats["cancelled"] = True
                    break
                if progress:
                    progress(stats["seen"], 0, path.name)
                _process_file(cur, path, stats, source_id=source_id)
        else:
            for path in targets_iter:
                if should_cancel and should_cancel():
                    stats["cancelled"] = True
                    break
                if progress:
                    progress(stats["seen"], len(targets_iter), path.name)
                _process_file(cur, path, stats, source_id=source_id)

        con.commit()
    stats["elapsed_s"] = round(time.time() - started, 2)
    stats["source_id"] = source_id
    stats["root"] = str(root)
    return stats


def reindex_sources(db_path: str, should_cancel=None) -> dict:
    """Re-index every ADDITIONAL (non-primary) source, marking any whose root no
    longer exists as status='missing' WITHOUT deleting its (now-stale) files rows
    — the same "moved" UX the open/reveal path already gives a relocated file.

    Returns {source_id: stats}. The primary source is re-indexed by index_folder
    (the caller re-runs the primary index separately); this covers the extras."""
    out: dict = {}
    with closing(connect(db_path)) as con:
        backfill_primary_source(con)
        primary_root = get_meta(con, "source_root")
        rows = con.execute(
            "SELECT id, root, kind, label FROM sources ORDER BY id"
        ).fetchall()
    for r in rows:
        # Skip the primary source — index_folder owns it.
        if primary_root and Path(r["root"]).resolve() == Path(primary_root).resolve():
            continue
        root = Path(r["root"])
        if r["kind"] == "folder" and not root.is_dir():
            with closing(connect(db_path)) as con:
                con.execute("UPDATE sources SET status='missing' WHERE id = ?", (r["id"],))
                con.commit()
            out[r["id"]] = {"status": "missing", "kept": True}
            continue
        if r["kind"] == "files":
            # A files-kind source: re-stat the existing rows; if none survive on
            # disk, the source is missing (rows kept). Re-adding the folder root
            # re-indexes — but here we just refresh status from the rows on disk.
            with closing(connect(db_path)) as con:
                paths = [x["path"] for x in con.execute(
                    "SELECT path FROM files WHERE source_id = ?", (r["id"],)).fetchall()]
            alive = [p for p in paths if Path(p).is_file()]
            status = "ok" if alive else "missing"
            with closing(connect(db_path)) as con:
                con.execute("UPDATE sources SET status=? WHERE id = ?", (status, r["id"]))
                con.commit()
            out[r["id"]] = {"status": status, "kept": True}
            continue
        # A folder source whose root still exists -> re-walk + re-tag.
        res = add_source(db_path, r["root"], "folder", label=r["label"],
                         should_cancel=should_cancel)
        out[r["id"]] = res
    return out


def remove_source(db_path: str, source_id: int) -> dict:
    """Deliberately remove an added source: delete its files' chunks + files rows
    + the sources row. A no-op (deleted=0) if the id doesn't exist or is the
    PRIMARY source (the primary is the matter itself — removing it is "close /
    re-index the matter", not a source removal).

    This is the ONLY path that deletes a source's rows; a re-index of a now-missing
    source KEEPS them (marks status='missing')."""
    try:
        source_id = int(source_id)
    except (TypeError, ValueError):
        return {"error": "bad source id", "deleted": 0}
    with closing(connect(db_path)) as con:
        backfill_primary_source(con)
        primary_root = get_meta(con, "source_root")
        row = con.execute("SELECT root FROM sources WHERE id = ?", (source_id,)).fetchone()
        if row is None:
            return {"error": "no such source", "deleted": 0}
        if primary_root and Path(row["root"]).resolve() == Path(primary_root).resolve():
            return {"error": "cannot remove the primary source", "deleted": 0}
        cur = con.cursor()
        cur.execute(
            "DELETE FROM chunks WHERE file_id IN (SELECT id FROM files WHERE source_id = ?)",
            (source_id,),
        )
        cur.execute("DELETE FROM files WHERE source_id = ?", (source_id,))
        deleted = cur.rowcount
        cur.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        con.commit()
    return {"deleted": deleted, "source_id": source_id}


def _clear_chunks(cur, rel: str) -> None:
    """Drop any FTS5 chunks previously indexed for this path.

    Called on every path that records a NON-content status (offline / too-large /
    error). A file that WAS searchable but is now skipped must not keep returning
    stale content from the index while its files row says it has none — that would
    let a now-offline / now-too-large / now-unreadable file still surface its old
    text in search (a confidentiality-relevant inconsistency). A pure DB delete —
    NEVER opens the file (so an offline placeholder is not forced to download)."""
    cur.execute(
        "DELETE FROM chunks WHERE file_id IN (SELECT id FROM files WHERE path = ?)",
        (rel,),
    )


def _process_file(cur, path: Path, stats: dict, source_id=None) -> None:
    """Pre-flight + hash + extract + record ONE file, updating `stats` in place.

    Shared by index_folder (which passes the PRIMARY source's id) and add_source
    (which passes the ADDED source's id). The `source_id=None` default is a
    defensive fallback only — both production callers now pass a real id. The SAME
    load-bearing guarantees apply to both:
      - a cloud OFFLINE placeholder is SKIPPED, never opened (opening forces a
        network DOWNLOAD — silent egress this app must never cause);
      - an over-cap blob is skipped (hashing it stalls the run);
      - a non-regular entry (FIFO/device/socket) is not a document;
      - a locked/unreadable file becomes an error ROW, never a crash;
      - reads originals only; never writes to the source tree.
    The verdict comes from stat() ALONE, before any open/hash."""
    rel = _unlong(str(path))   # store/look up the clean path, not the \\?\ form
    try:
        st = path.stat()
    except OSError as e:
        stats["seen"] += 1
        stats["errors"] += 1
        _clear_chunks(cur, rel)   # a now-unreadable file must not keep its old searchable text
        _record(cur, path, rel, None, "error", _safe_error(e), source_id=source_id)
        return
    if scan_guard.is_offline_placeholder(st):
        stats["seen"] += 1
        stats["skipped_offline"] += 1
        _clear_chunks(cur, rel)   # a now-offline file must not keep its old searchable text
        _record(cur, path, rel, None, "skipped-offline", None, source_id=source_id)
        return
    if st.st_size > scan_guard.MAX_FILE_BYTES:
        stats["seen"] += 1
        stats["skipped_too_large"] += 1
        _clear_chunks(cur, rel)   # a now-too-large file must not keep its old searchable text
        _record(cur, path, rel, None, "skipped-too-large", None, source_id=source_id)
        return
    if not stat.S_ISREG(st.st_mode):
        return   # FIFO / device / socket — not a document

    stats["seen"] += 1

    # Hash; a locked/unreadable file becomes an error row, not a crash.
    try:
        digest = sha256(path)
    except Exception as e:  # noqa: BLE001
        stats["errors"] += 1
        _record(cur, path, rel, None, "error", _safe_error(e), source_id=source_id)
        return

    existing = cur.execute(
        "SELECT sha256, source_id FROM files WHERE path = ?", (rel,)
    ).fetchone()
    if existing and existing["sha256"] == digest:
        stats["skipped"] += 1
        # Even on a content-unchanged skip, (re)tag the source attribution: a file
        # first seen via the primary index then re-encountered under an added source
        # (or vice-versa) should reflect the current source without a re-extract.
        if source_id is not None and existing["source_id"] != source_id:
            cur.execute("UPDATE files SET source_id = ? WHERE path = ?", (source_id, rel))
        return

    # changed/new -> clear any old chunks for this path
    old = cur.execute("SELECT id FROM files WHERE path = ?", (rel,)).fetchone()
    if old:
        cur.execute("DELETE FROM chunks WHERE file_id = ?", (old["id"],))

    try:
        status, units, err = extract(_long(path))
    except Exception as e:  # noqa: BLE001 - extractor should never escape
        status, units, err = "error", [], _safe_error(e)

    if status == "error":
        stats["errors"] += 1
    elif status == "unsupported":
        stats["unsupported"] += 1
    elif status == "empty":
        stats["empty"] += 1
        if is_scanned_pdf(path.suffix, "empty"):
            stats["scanned_pdfs"] += 1  # empty PDF == almost certainly scanned

    file_id = _record(cur, path, rel, digest, status, err, source_id=source_id)
    for locator, body in units:
        cur.execute(
            "INSERT INTO chunks (file_id, locator, body) VALUES (?,?,?)",
            (file_id, locator, body),
        )
    # 'truncated' (an extractor hit its expanded-size cap, #7) still extracted real text
    # up to the cap — count it as indexed so it stays searchable; the truncation is
    # recorded in the files row status + a marker chunk for an honest manifest.
    if status in ("ok", "truncated"):
        stats["indexed"] += 1


def _record(cur, path: Path, rel: str, digest, status, err, source_id=None) -> int:
    """Upsert the files row and return its id.

    `source_id` (multi-source ingestion) tags the row with the source it came
    from. Both production callers pass a real id (index_folder passes the PRIMARY
    source's id; add_source passes the ADDED source's). The `source_id=None`
    branch is a defensive fallback: it leaves the column as-is rather than nulling
    it, so a (hypothetical) untagged write never clobbers a previously-recorded
    source attribution. It is no longer reached on the normal index/add paths."""
    try:
        size = path.stat().st_size
        mtime = path.stat().st_mtime
    except OSError:
        size, mtime = None, None
    npath = norm_path(rel)   # indexed case/sep-insensitive lookup key for open/reveal
    if source_id is None:
        cur.execute(
            """INSERT INTO files
               (path, norm_path, filename, ext, size_bytes, sha256, mtime, indexed_at,
                extract_status, extract_error)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                 norm_path=excluded.norm_path,
                 sha256=excluded.sha256, size_bytes=excluded.size_bytes,
                 mtime=excluded.mtime, indexed_at=excluded.indexed_at,
                 extract_status=excluded.extract_status,
                 extract_error=excluded.extract_error""",
            (rel, npath, path.name, path.suffix.lower(), size, digest, mtime,
             datetime.now(timezone.utc).isoformat(), status, err),
        )
    else:
        cur.execute(
            """INSERT INTO files
               (path, norm_path, filename, ext, size_bytes, sha256, mtime, indexed_at,
                extract_status, extract_error, source_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                 norm_path=excluded.norm_path,
                 sha256=excluded.sha256, size_bytes=excluded.size_bytes,
                 mtime=excluded.mtime, indexed_at=excluded.indexed_at,
                 extract_status=excluded.extract_status,
                 extract_error=excluded.extract_error,
                 source_id=excluded.source_id""",
            (rel, npath, path.name, path.suffix.lower(), size, digest, mtime,
             datetime.now(timezone.utc).isoformat(), status, err, source_id),
        )
    return cur.execute("SELECT id FROM files WHERE path = ?", (rel,)).fetchone()["id"]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: python -m app.index <folder> <matter.db>")
    s = index_folder(sys.argv[1], sys.argv[2])
    print("\nIndex complete:")
    for k, v in s.items():
        print(f"  {k:18} {v}")
    if s.get("scanned_pdfs"):
        print(f"\n  NOTE: {s['scanned_pdfs']} PDF(s) had no extractable text "
              f"(likely scanned). OCR is the next increment.")
