"""
SQLite + FTS5 storage. One DB file per matter; nothing leaves the machine.

Two tables:
  files   - one row per physical file (path, hash, status, error)
  chunks  - FTS5 virtual table, one row per logical unit
            (PDF page / PPTX slide / XLSX sheet / whole DOCX/EML/MSG/TXT)

Originals are never modified. We only ever read them.

NOTE (Windows/frozen build): the stock `sqlite3` that ships with some Python
builds is compiled WITHOUT the FTS5 extension. When that happens, creating the
`chunks` virtual table raises "no such module: fts5". We detect that at import
time and transparently fall back to `pysqlite3` (which bundles a full SQLite
with FTS5). This must be verified against the installed MSI build, not just
the dev interpreter.
"""

import os
from datetime import datetime, timezone
from pathlib import Path

# --- Pick a sqlite driver that actually has FTS5 -----------------------------
import sqlite3 as _stdlib_sqlite


def _has_fts5(mod) -> bool:
    try:
        con = mod.connect(":memory:")
        try:
            con.execute("CREATE VIRTUAL TABLE _t USING fts5(x)")
            return True
        finally:
            con.close()
    except Exception:
        return False


if _has_fts5(_stdlib_sqlite):
    sqlite3 = _stdlib_sqlite
    FTS5_DRIVER = "sqlite3"
else:
    try:
        import pysqlite3 as _pysqlite  # type: ignore
        if _has_fts5(_pysqlite):
            sqlite3 = _pysqlite
            FTS5_DRIVER = "pysqlite3"
        else:  # pragma: no cover - misconfigured build
            sqlite3 = _stdlib_sqlite
            FTS5_DRIVER = "sqlite3(no-fts5)"
    except ImportError:  # pragma: no cover - dev env without pysqlite3
        sqlite3 = _stdlib_sqlite
        FTS5_DRIVER = "sqlite3(no-fts5)"


def fts5_available() -> bool:
    return not FTS5_DRIVER.endswith("(no-fts5)")


SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY,
    path          TEXT UNIQUE NOT NULL,
    norm_path     TEXT,         -- os.normcase(os.normpath(path)): case/sep-insensitive lookup key
    filename      TEXT NOT NULL,
    ext           TEXT,
    size_bytes    INTEGER,
    sha256        TEXT,
    mtime         REAL,
    indexed_at    TEXT,
    extract_status TEXT,        -- 'ok' | 'empty' | 'error' | 'unsupported'
    extract_error TEXT,
    source_id     INTEGER REFERENCES sources(id)
);

CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(extract_status);
-- Open/reveal confinement looks a file up case/separator-insensitively (Windows). Without
-- this index that fallback was a full O(N) Python table scan per open; with norm_path stored
-- it's an indexed O(log N) lookup.
CREATE INDEX IF NOT EXISTS idx_files_norm ON files(norm_path);

-- Sources of documents in this matter (multi-source ingestion). The PRIMARY
-- source is the folder that keyed the matter .db (meta.source_root, kept for
-- back-compat); ADDITIONAL sources are other folders / picked-file sets the
-- lawyer adds. Each `files` row carries a source_id linking back here so the
-- manifest can show provenance and the confinement guards can enumerate EVERY
-- source root that must stay read-only. `root` is the source folder (for a
-- 'files'-kind source, the common parent dir of the picked files); UNIQUE so
-- the same folder is never added twice.
CREATE TABLE IF NOT EXISTS sources (
    id              INTEGER PRIMARY KEY,
    root            TEXT UNIQUE NOT NULL,
    kind            TEXT,        -- 'folder' | 'files'
    label           TEXT,
    added_at        TEXT,
    last_indexed_at TEXT,
    status          TEXT         -- 'ok' | 'missing'
);

CREATE INDEX IF NOT EXISTS idx_files_source ON files(source_id);

-- FTS5 holds the searchable text. file_id joins back to files.
CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(
    file_id UNINDEXED,
    locator,            -- human label for the hit: "p.4" / "slide 7" / "sheet: Cap Table"
    body,
    tokenize = 'unicode61 remove_diacritics 2'
);

-- Per-matter metadata: notably 'source_root' (the indexed folder), so we can
-- verify a DB belongs to the folder being opened and confine write-tools away
-- from the read-only source tree.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def norm_path(path: str) -> str:
    """The case/separator-normalized form of a stored path, used as the indexed lookup key
    for open/reveal confinement. `os.path.normcase` lowercases + unifies separators on
    Windows (case- and separator-insensitive) and is a no-op on POSIX; `normpath` collapses
    redundant separators. Deterministic on a given OS — and a matter DB is local to one
    machine, so the stored value and a later lookup always normalize the same way."""
    return os.path.normcase(os.path.normpath(path or ""))


def set_meta(con, key: str, value: str) -> None:
    con.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def get_meta(con, key: str):
    row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def _column_names(con, table: str) -> set:
    """The set of column names on `table` (empty if the table doesn't exist)."""
    return {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}


def _migrate(con) -> None:
    """Idempotent, additive schema migrations for a matter DB created by an
    OLDER version. Never drops/renames; safe to run on every open.

    The only migration so far: add `files.source_id` to a legacy `files` table
    (a fresh DB already has it from SCHEMA). Multi-source ingestion needs every
    file tagged with the source it came from. ALTER TABLE ADD COLUMN is the only
    portable SQLite way; we guard it by checking PRAGMA table_info first AND
    catch the duplicate-column error so a race / partial migration is harmless.
    """
    cols = _column_names(con, "files")
    if cols and "source_id" not in cols:
        try:
            # No REFERENCES clause here: the `sources` parent table is created by
            # SCHEMA, which runs AFTER this migration, and SQLite's ALTER TABLE ADD
            # COLUMN cannot add an inline FK to a not-yet-existing parent. The plain
            # INTEGER column is functionally identical (FK enforcement is off), and a
            # fresh DB still gets the documented REFERENCES from SCHEMA.
            con.execute("ALTER TABLE files ADD COLUMN source_id INTEGER")
        except Exception:
            # Duplicate column (another connection migrated first) or an old SQLite
            # that already has it — either way the column now exists; carry on.
            pass
    # The index is in SCHEMA (CREATE INDEX IF NOT EXISTS) and runs after this, so
    # by then files.source_id exists on both fresh and migrated DBs.
    if cols and "norm_path" not in cols:
        try:
            con.execute("ALTER TABLE files ADD COLUMN norm_path TEXT")
        except Exception:
            pass
    # Backfill norm_path for any rows missing it (a legacy DB just got the column; a fresh /
    # already-migrated DB has none null). normcase/normpath are Python — not expressible in
    # SQL — so compute per row. Idempotent (only WHERE norm_path IS NULL) and bounded one-time
    # work on the first open after upgrade.
    if cols:
        try:
            todo = con.execute("SELECT id, path FROM files WHERE norm_path IS NULL").fetchall()
            for r in todo:
                con.execute("UPDATE files SET norm_path = ? WHERE id = ?",
                            (norm_path(r["path"]), r["id"]))
            if todo:
                con.commit()   # persist now, while we hold a clean transaction
        except Exception:
            # The backfill UPDATEs open a WRITE transaction; on a freshly-upgraded DB a
            # concurrent index job (single WAL writer) can make them lose with
            # 'database is locked'. ROLL BACK so we never leave an open transaction that would
            # then make the executescript(SCHEMA) below ALSO fail and 500 a read/open path
            # (run_search / _matter_file connect() here too). The backfill is idempotent — the
            # next connect() after the writer finishes completes it; until then the unbackfilled
            # rows just miss the norm_path fallback (fail-closed 'outside'), never a leak.
            try:
                con.rollback()
            except Exception:
                pass


def backfill_primary_source(con) -> None:
    """Ensure a matter opened from a legacy (pre-multi-source) DB has its PRIMARY
    source row, and that every untagged file points at it.

    Idempotent: if a `sources` row already exists this is a no-op. The primary
    source's `root` is meta['source_root'] (the folder that keyed the .db). A
    matter that has files but no recorded source_root (a very old DB) is left
    alone — there is no root to anchor a primary source to, and a missing
    source_root already disables the confinement-relaxing paths fail-closed.

    Called by index/add_source/the source listing so any read or write path that
    cares about sources sees a consistent picture without a one-shot migration.
    """
    have = con.execute("SELECT id FROM sources LIMIT 1").fetchone()
    if have is not None:
        return
    root = get_meta(con, "source_root")
    if not root:
        return
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "INSERT OR IGNORE INTO sources(root, kind, label, added_at, last_indexed_at, status) "
        "VALUES(?,?,?,?,?,?)",
        (root, "folder", None, now, now, "ok"),
    )
    row = con.execute("SELECT id FROM sources WHERE root = ?", (root,)).fetchone()
    if row is not None:
        con.execute(
            "UPDATE files SET source_id = ? WHERE source_id IS NULL", (row["id"],)
        )


def connect(db_path: str):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    # WAL lets a search read the matter DB while a re-index writes it, instead
    # of "database is locked". Sidecar -wal/-shm files live next to the .db in
    # %APPDATA% (never in the source tree).
    if db_path != ":memory:":
        try:
            con.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
    # Migrate a legacy `files` table BEFORE executescript so the SCHEMA's
    # `CREATE INDEX ... ON files(source_id)` finds the column on every DB.
    _migrate(con)
    con.executescript(SCHEMA)
    return con


def reset(db_path: str) -> None:
    """Wipe the index (e.g. re-indexing a matter from scratch)."""
    # Remove the WAL sidecars too, or stale committed-but-uncheckpointed data
    # could resurrect on the next open.
    for suffix in ("", "-wal", "-shm"):
        p = Path(db_path + suffix)
        if p.exists():
            p.unlink()
