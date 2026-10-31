"""
Read-only SQL helpers over an open matter's `.db` (search / stats / file listings /
source roots). Extracted from app/web.py so the route layer stays thin: these functions
own the FTS5 query, the corpus counters, the stats drill-down, and the source-root
accessors the confinement guards iterate.

All connections go through `closing(connect(db_path))` (WAL; handle released even on a
malformed FTS query). NOTHING here writes to the source tree; the one incidental write
is the idempotent legacy `backfill_primary_source` heal, guarded to never crash a read.
"""

import os
from contextlib import closing
from pathlib import Path

from .db import connect, get_meta, backfill_primary_source
from .classify import IMAGE_EXTS
from .paths import matters_dir, friendly_matter_name


# ---------------------------------------------------------------- search ----
def run_search(db_path: str, q: str, limit: int = 50):
    # closing() guarantees the connection is released even when the FTS query is
    # malformed (an expected error path), instead of leaking handles.
    with closing(connect(db_path)) as con:
        rows = con.execute(
            """
            SELECT f.filename, f.path, f.ext, c.locator,
                   snippet(chunks, 2, char(57344), char(57345), ' … ', 12) AS snip,
                   bm25(chunks) AS rank
            FROM chunks c
            JOIN files f ON f.id = c.file_id
            WHERE chunks MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (q, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# "needs OCR" must match the manifest's classifier exactly (classify.content_status):
# scanned PDFs (empty + .pdf) + image files that are unsupported (no text layer).
# Bound as parameters — never string-interpolated — even though IMAGE_EXTS is a
# constant today.
def _needs_ocr_clause():
    placeholders = ",".join("?" for _ in IMAGE_EXTS)
    sql = ("((extract_status='empty' AND ext='.pdf') OR "
           f"(extract_status='unsupported' AND ext IN ({placeholders})))")
    return sql, tuple(sorted(IMAGE_EXTS))


_DUP_CLAUSE = ("sha256 IN (SELECT sha256 FROM files WHERE sha256 IS NOT NULL "
               "GROUP BY sha256 HAVING COUNT(*) > 1)")


def corpus_stats(db_path: str):
    with closing(connect(db_path)) as con:
        def g(sql, params=()):
            return con.execute(sql, params).fetchone()["n"]
        ocr_sql, ocr_params = _needs_ocr_clause()
        return {
            "total": g("SELECT COUNT(*) n FROM files"),
            "ok": g("SELECT COUNT(*) n FROM files WHERE extract_status='ok'"),
            "scanned": g("SELECT COUNT(*) n FROM files WHERE extract_status='empty' AND ext='.pdf'"),
            "needs_ocr": g(f"SELECT COUNT(*) n FROM files WHERE {ocr_sql}", ocr_params),
            "errors": g("SELECT COUNT(*) n FROM files WHERE extract_status='error'"),
            "duplicates": g(f"SELECT COUNT(*) n FROM files WHERE {_DUP_CLAUSE}"),
        }


def list_files(db_path: str, category: str, limit: int = 1000):
    """Files in a category, for the stats drill-down. Read-only."""
    ocr_sql, ocr_params = _needs_ocr_clause()
    spec = {
        "errors": ("extract_status='error'", ()),
        "scanned": ("extract_status='empty' AND ext='.pdf'", ()),
        "needs_ocr": (ocr_sql, ocr_params),
        "searchable": ("extract_status='ok'", ()),
        "duplicates": (_DUP_CLAUSE, ()),
        "all": ("1=1", ()),
    }.get(category)
    if spec is None:
        return None
    where, params = spec
    with closing(connect(db_path)) as con:
        rows = con.execute(
            f"SELECT filename, path, ext, extract_status, extract_error "
            f"FROM files WHERE {where} ORDER BY path LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def matter_source_root(db_path: str):
    """The PRIMARY folder this matter indexes (from the meta table), or None.

    Kept as the back-compat single-root accessor; the confinement guards use
    matter_source_roots() (ALL sources). Equals matter_source_roots()[0]."""
    with closing(connect(db_path)) as con:
        return get_meta(con, "source_root")


def matter_source_roots(db_path: str) -> list[str]:
    """EVERY active source root for this matter — the primary (source_root) plus
    every ADDITIONAL source (multi-source ingestion). The list the confinement
    guards iterate so a write-tool / open is checked against ALL read-only roots,
    not just the primary. The primary is first (roots[0] == matter_source_root).

    A source whose status is 'missing' is still listed: its root is still a tree
    we must never write into, and the file rows it covers are still matter data."""
    roots: list[str] = []
    seen = set()
    with closing(connect(db_path)) as con:
        primary = get_meta(con, "source_root")
        if primary:
            roots.append(primary)
            try:
                seen.add(os.path.normcase(str(Path(primary).resolve())))
            except (OSError, ValueError):
                seen.add(os.path.normcase(primary))
        try:
            backfill_primary_source(con)
            con.commit()   # persist the one-time legacy heal; harmless no-op otherwise
        except Exception:  # noqa: BLE001 - a read path must never crash on a heal write
            pass
        for r in con.execute("SELECT root FROM sources ORDER BY id"):
            root = r["root"]
            if not root:
                continue
            try:
                key = os.path.normcase(str(Path(root).resolve()))
            except (OSError, ValueError):
                key = os.path.normcase(root)
            if key in seen:
                continue
            seen.add(key)
            roots.append(root)
    return roots


def list_sources(db_path: str) -> list[dict]:
    """The matter's sources for the UI: id, root, kind, label, status, added_at,
    a friendly display name, file count, and whether it's the primary. Read-only."""
    primary = matter_source_root(db_path)
    try:
        primary_key = os.path.normcase(str(Path(primary).resolve())) if primary else None
    except (OSError, ValueError):
        primary_key = os.path.normcase(primary) if primary else None
    out = []
    with closing(connect(db_path)) as con:
        try:
            backfill_primary_source(con)
            con.commit()   # persist the one-time legacy heal; harmless no-op otherwise
        except Exception:  # noqa: BLE001 - a read path must never crash on a heal write
            pass
        rows = con.execute(
            "SELECT id, root, kind, label, added_at, last_indexed_at, status FROM sources "
            "ORDER BY id"
        ).fetchall()
        counts = {r["source_id"]: r["n"] for r in con.execute(
            "SELECT source_id, COUNT(*) n FROM files GROUP BY source_id")}
    for r in rows:
        try:
            key = os.path.normcase(str(Path(r["root"]).resolve()))
        except (OSError, ValueError):
            key = os.path.normcase(r["root"] or "")
        label = r["label"] or Path(r["root"]).name or r["root"]
        out.append({
            "id": r["id"],
            "root": r["root"],
            "kind": r["kind"],
            "label": r["label"],
            "display": label,
            "status": r["status"] or "ok",
            "added_at": r["added_at"],
            "files": int(counts.get(r["id"], 0)),
            "primary": (primary_key is not None and key == primary_key),
        })
    return out


def list_matters():
    out = []
    for p in sorted(matters_dir().glob("*.db")):
        out.append({"name": friendly_matter_name(str(p)), "db": str(p)})
    return out
