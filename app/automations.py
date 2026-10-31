"""
One-click, no-code file automations — the kind of busywork firms do by hand
(renaming a folder of exhibits to a house standard, etc.) that a script does in
seconds. Run from the dashboard's "Tools" panel; the user never sees code.

DESIGN / SAFETY (important — this is the one place the app WRITES to disk):
  - Everything is preview-first. plan_rename() computes what *would* happen and
    is shown to the user before anything changes.
  - apply_plan() writes an undo manifest BEFORE renaming, so any run is
    reversible via undo(). Manifests live in %APPDATA%, never in the room.
  - Collisions (two files -> same name, or target already exists) are detected
    and skipped, never silently overwritten.
  - It only touches the folder the user explicitly picks. The original (real)
    data room is never the target — only the user's exported working copy.
  - Deterministic, local, no model calls.
"""

import csv
import io
import json
import os
import re
import secrets
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .db import connect
from .classify import content_status, is_scanned_pdf, IMAGE_EXTS
from .paths import undo_dir, exports_dir


# ----------------------------------------------------------------- rules ----
# Numeric rule fields come straight off an untrusted request body, so they are
# bounded here: an attacker-supplied sequence_pad of, say, 999999 turns every
# name into a ~1 MB string (str(seq).zfill(999999)) — a cheap memory-exhaustion
# vector. These caps are generous for any real renaming job.
MAX_SEQUENCE_PAD = 6          # 000001 .. 999999 is plenty
MAX_PREFIX_LEN = 200          # a house-style prefix, not a payload


@dataclass
class RenameRules:
    spaces_to_underscores: bool = False
    collapse_whitespace: bool = True       # "a   b" -> "a b"
    lowercase_ext: bool = True             # ".PDF" -> ".pdf"
    strip_special: bool = False            # keep only [A-Za-z0-9._ -]
    lowercase_name: bool = False
    prefix: str = ""                       # e.g. "ProjectX_"
    sequence: bool = False                 # prepend zero-padded counter
    sequence_pad: int = 3
    sequence_start: int = 1

    def __post_init__(self):
        # Coerce + clamp the numeric fields; fields arrive from an untrusted
        # request, so be defensive about type and range.
        try:
            self.sequence_pad = int(self.sequence_pad)
        except (TypeError, ValueError):
            self.sequence_pad = 3
        try:
            self.sequence_start = int(self.sequence_start)
        except (TypeError, ValueError):
            self.sequence_start = 1
        # 0..MAX for pad (negative zfill is a no-op but normalize anyway);
        # a sane, non-negative, bounded start.
        self.sequence_pad = max(0, min(self.sequence_pad, MAX_SEQUENCE_PAD))
        self.sequence_start = max(0, min(self.sequence_start, 1_000_000))
        if not isinstance(self.prefix, str):
            self.prefix = str(self.prefix)
        if len(self.prefix) > MAX_PREFIX_LEN:
            self.prefix = self.prefix[:MAX_PREFIX_LEN]


def normalize_name(name: str, rules: RenameRules, seq: int | None = None) -> str:
    stem, dot, ext = name.rpartition(".")
    if not dot:  # no extension
        stem, ext = name, ""
    if rules.lowercase_ext and ext:
        ext = ext.lower()
    if rules.collapse_whitespace:
        stem = re.sub(r"\s+", " ", stem).strip()
    if rules.strip_special:
        stem = re.sub(r"[^A-Za-z0-9._ -]", "", stem)
    if rules.lowercase_name:
        stem = stem.lower()
    if rules.spaces_to_underscores:
        stem = stem.replace(" ", "_")
    if rules.prefix:
        stem = f"{rules.prefix}{stem}"
    if rules.sequence and seq is not None:
        stem = f"{str(seq).zfill(rules.sequence_pad)}_{stem}"
    return f"{stem}{('.' + ext) if ext else ''}"


# ------------------------------------------------------------------ plan ----
@dataclass
class PlanItem:
    src: str
    dst: str
    status: str   # 'rename' | 'unchanged' | 'collision'


@dataclass
class Plan:
    folder: str
    recursive: bool
    items: list = field(default_factory=list)

    def summary(self) -> dict:
        c = {"rename": 0, "unchanged": 0, "collision": 0}
        for it in self.items:
            c[it.status] += 1
        return c


def _candidate_files(folder: Path, recursive: bool):
    it = folder.rglob("*") if recursive else folder.iterdir()
    return [p for p in sorted(it) if p.is_file() and not p.name.startswith(".")]


def plan_rename(folder: str, rules: RenameRules, recursive: bool = False) -> Plan:
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a folder: {root}")
    plan = Plan(folder=str(root), recursive=recursive)
    files = _candidate_files(root, recursive)

    # Reserve names already taken by files we are NOT renaming, plus detect
    # two sources mapping onto the same target.
    seq = rules.sequence_start
    taken: dict[str, str] = {}   # lowercased target path -> source path
    for p in files:
        newname = normalize_name(p.name, rules, seq if rules.sequence else None)
        if rules.sequence:
            seq += 1
        dst = p.with_name(newname)
        if newname == p.name:
            plan.items.append(PlanItem(str(p), str(dst), "unchanged"))
            taken[str(dst).lower()] = str(p)
            continue
        key = str(dst).lower()
        collision = (key in taken) or (dst.exists() and dst.resolve() != p.resolve())
        plan.items.append(PlanItem(str(p), str(dst), "collision" if collision else "rename"))
        if not collision:
            taken[key] = str(p)
    return plan


# ----------------------------------------------------------------- apply ----
# Undo manifests record from/to paths, which are matter-identifying. They are
# only useful immediately after a rename run (the UI offers "undo last run"), so
# old ones are stale data to be cleaned up rather than retained indefinitely.
UNDO_MANIFEST_MAX_AGE_DAYS = 30


def _prune_old_manifests(max_age_days: int = UNDO_MANIFEST_MAX_AGE_DAYS) -> int:
    """Delete undo manifests older than max_age_days. Best-effort; never raises.

    Run when the undo dir is touched (i.e. on apply), so stale matter-identifying
    from/to paths don't accumulate forever in %APPDATA%."""
    removed = 0
    try:
        d = undo_dir()
    except Exception:  # noqa: BLE001
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
    for p in d.glob("rename_*.jsonl"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        except OSError:
            continue  # locked/gone — skip, cleanup is best-effort
    return removed


def _undo_dir() -> Path:
    return undo_dir()


def _safe_rename(src: Path, dst: Path) -> None:
    """Rename without ever clobbering: refuse if the target already exists.

    Path.rename / os.rename overwrites silently on POSIX, which would violate the
    "never overwrite on collision" guarantee. The collision check at plan time
    is not enough — a file can appear between preview and apply (or before undo).
    A plain `if dst.exists(): raise` re-check still has a TOCTOU window: on POSIX
    a file can appear in the gap between the check and the rename, and the rename
    would then silently clobber it. So we make the move itself atomically refuse
    to overwrite:

      * POSIX: os.link(src, dst) creates the new name and fails with FileExistsError
        if it is already taken (atomic, no clobber); then unlink the old name.
        If the link fails because cross-device/unsupported (EXDEV/EPERM/ENOSYS on
        e.g. some network mounts), fall back to a checked rename.
      * Windows: os.rename already raises FileExistsError if the target exists, so
        it is non-clobbering as-is.
    """
    # Same-path no-op (and lets a case-only rename on case-insensitive FS through).
    if src.resolve() == dst.resolve():
        src.rename(dst)
        return

    if dst.exists():
        raise FileExistsError(f"target exists: {dst}")

    if os.name == "nt":
        # Windows rename is non-clobbering: it raises if dst exists.
        src.rename(dst)
        return

    # POSIX: link-then-unlink is atomic against a racing creation of dst.
    try:
        os.link(src, dst)
    except FileExistsError:
        raise
    except OSError:
        # Cross-device link / FS without hardlinks (EXDEV, ENOSYS, EPERM, ...).
        # Re-check and fall back to a plain rename; the residual TOCTOU window
        # here is unavoidable on such filesystems but the common case is covered.
        if dst.exists():
            raise FileExistsError(f"target exists: {dst}")
        src.rename(dst)
        return
    try:
        os.unlink(src)
    except OSError:
        # The new name (`dst`) is now a HARDLINK to the same inode as `src`, but the
        # old name could not be removed (a transient lock, a permission flip). Leaving
        # `dst` in place would create a SPURIOUS DUPLICATE of the file under the new
        # name while `src` still exists — a half-applied rename. Roll the link back
        # (best-effort) so the move is all-or-nothing, then re-raise so apply_plan
        # records this item as an error (and does NOT log a reversal for it). If the
        # rollback unlink ALSO fails, re-raise the ORIGINAL error regardless — the
        # caller surfaces a failed rename either way.
        try:
            os.unlink(dst)
        except OSError:
            pass
        raise


def apply_plan(plan: Plan) -> dict:
    """Apply the 'rename' items. Writes an undo log first; returns a report that
    includes the manifest path so the UI can offer one-click undo.

    The undo log is JSONL: a header line, then one line appended per successful
    rename. Appending is O(1) and crash-safe (each completed rename is on disk),
    unlike rewriting the whole manifest every iteration."""
    renames = [it for it in plan.items if it.status == "rename"]
    _prune_old_manifests()  # we're about to touch the undo dir — clear stale ones
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # NEVER truncate a prior run's undo log (undo-safety carrier). The timestamp is
    # second-granular, so two applies within the same second would otherwise share
    # `rename_<ts>.jsonl` and the second open("w") would ERASE the first run's reversal
    # records — destroying undo for an already-mutated tree. Route the name through the
    # no-collision helper (sibling export_manifest does the same) AND open EXCLUSIVELY
    # ('x'), so even a true same-name race fails over to a fresh name rather than
    # clobbering. Fail-closed: if we can't secure a private path, refuse before any rename.
    manifest_path = None
    log = None
    for _ in range(8):
        candidate = _unique_export_path(_undo_dir(), f"rename_{ts}.jsonl")
        try:
            log = open(candidate, "x", encoding="utf-8")
            manifest_path = candidate
            break
        except FileExistsError:
            continue
    if log is None:
        raise OSError("could not create a unique undo manifest")

    done, errors = 0, []
    with log:
        log.write(json.dumps({"type": "header", "created_at": ts,
                              "folder": plan.folder}) + "\n")
        log.flush()
        for it in renames:
            src, dst = Path(it.src), Path(it.dst)
            try:
                _safe_rename(src, dst)
                # store the reversal direction (from new name back to old)
                log.write(json.dumps({"from": str(dst), "to": str(src)}) + "\n")
                log.flush()
                done += 1
            except Exception as e:  # noqa: BLE001
                errors.append({"src": it.src, "error": f"{type(e).__name__}: {e}"})

    return {"renamed": done, "errors": errors, "manifest": str(manifest_path)}


def _read_manifest(manifest_path: str) -> tuple[str, list]:
    """Read an undo manifest. Returns (folder, records) where `folder` is the
    rename run's recorded base directory (the apply-time header's "folder").

    The folder is LOAD-BEARING for confinement (C1): undo() refuses to touch any
    from/to path that does not descend from it, so a hand-crafted manifest can't
    drive an arbitrary rename. A manifest with no recorded folder yields "" — and
    undo() then refuses every record (fail-closed)."""
    text = Path(manifest_path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") and '"renames"' in stripped and "\n{" not in stripped:
        # legacy single-object format
        obj = json.loads(text)
        return str(obj.get("folder", "")), obj.get("renames", [])
    folder = ""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("type") == "header":
            folder = str(rec.get("folder", ""))
            continue
        out.append(rec)
    return folder, out


def undo(manifest_path: str) -> dict:
    reverted, errors = 0, []
    folder, records = _read_manifest(manifest_path)
    # CONFINEMENT (C1): every from/to in the manifest must descend from the run's
    # recorded folder, resolved. The undo dir is writable by anything on the box, so
    # a crafted manifest pointing from/to arbitrary paths (e.g. system files) would
    # otherwise drive _safe_rename outside the room. A missing/unresolvable folder
    # confines to nothing -> reject every record. Code-enforced, not advisory.
    base = None
    if folder:
        try:
            rb = Path(folder).resolve()
            # C1 hardening (adversarial review): the recorded folder must be a real,
            # NON-DEGENERATE directory. A crafted manifest with folder="/" (or a drive
            # root like "C:\\") would otherwise confine to the WHOLE disk, re-opening the
            # arbitrary-rename primitive this check exists to close. Treat "confines to
            # everything" as "confines to nothing" (fail-closed), mirroring
            # _reject_source_tree: a filesystem root (len(parts) == 1) or a non-directory
            # is refused.
            if rb.is_dir() and len(rb.parts) > 1:
                base = rb
        except (OSError, ValueError):
            base = None

    def _confined(p: Path) -> bool:
        if base is None:
            return False
        try:
            rp = p.resolve()
        except (OSError, ValueError):
            return False
        try:
            rp.relative_to(base)
            return True
        except ValueError:
            return False

    # reverse order so sequence/collision interplay unwinds cleanly
    for r in reversed(records):
        src, dst = Path(r["from"]), Path(r["to"])
        if not _confined(src) or not _confined(dst):
            errors.append({"src": r.get("from", ""),
                           "error": "refused: outside the manifest's recorded folder"})
            continue
        try:
            _safe_rename(src, dst)   # never clobber a file occupying the old name
            reverted += 1
        except Exception as e:  # noqa: BLE001
            errors.append({"src": r["from"], "error": f"{type(e).__name__}: {e}"})
    return {"reverted": reverted, "errors": errors}


# ====================================================================
# Document index / manifest  (Tier 1 — READ ONLY, no Tesseract)
# ====================================================================
# The "schedule of documents" a paralegal builds by hand: one row per file with
# metadata + a content-status column. Pure read over the matter index DB; never
# touches the source tree, so no preview/undo is needed. Every file is listed
# regardless of type — images and scanned PDFs simply show "needs OCR" in the
# content column, which makes the manifest double as the OCR worklist.

# Order of columns in the exported CSV. `no` is the FIRST column: a sequential
# 1..N item number assigned AFTER the final sort, so the schedule reads like the
# numbered exhibit list a paralegal would hand-build.
MANIFEST_COLUMNS = [
    "no", "filename", "folder", "source", "extension", "content_status", "pages",
    "size", "size_bytes", "modified", "duplicate", "sha256",
    "extract_status", "error", "path",
]


# --------------------------------------------------------------- sorting ----
# How the rows are ordered before the `no` item-number is assigned. The DEFAULT
# is folder-grouped + natural filename order — the way a person reading a binder
# expects it ("Exhibit 2" before "Exhibit 10", not the case-sensitive byte order
# SQLite gives). Sorting happens in PYTHON (SQLite has no natural collation); the
# SQL `ORDER BY f.path` is kept only as a stable, deterministic pre-sort so the
# Python sort's tie-breaks are reproducible.
class SortMode:
    FOLDER = "folder"        # default: group by folder, then natural filename
    NAME = "name"            # flat natural filename order
    TYPE = "type"            # extension group, then folder, then name
    DATE = "date"            # modified ascending
    SEQUENCE = "sequence"    # preserve the path order as listed
    AS_LISTED = "as-listed"  # alias of SEQUENCE

    ALL = (FOLDER, NAME, TYPE, DATE, SEQUENCE, AS_LISTED)
    DEFAULT = FOLDER


def normalize_order(order) -> str:
    """Map an untrusted `order` value onto a known SortMode, falling back to the
    default on anything unrecognized (never raises — callers pass request input)."""
    if isinstance(order, str) and order in SortMode.ALL:
        return order
    return SortMode.DEFAULT


# Split a string into alternating text / integer runs so digit groups compare
# numerically: "Exhibit 10" -> ["exhibit ", 10] sorts AFTER "Exhibit 2" -> ["exhibit ", 2].
# Case-insensitive (casefold) so the order is stable on a case-insensitive FS.
# Pure + deterministic; the int/str segments never compare against each other
# because the digit runs always land at the same tuple positions for like names.
_DIGITS_RE = re.compile(r"(\d+)")


def _natural_key(s: str):
    s = s or ""
    parts = _DIGITS_RE.split(s.casefold())
    # Even indices are non-digit text, odd indices are digit runs.
    return tuple(int(p) if i % 2 else p for i, p in enumerate(parts))


def _human_size(n) -> str:
    if not n:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return (f"{f:.0f} {u}" if u == "B" else f"{f:.1f} {u}")
        f /= 1024
    return f"{n} B"


# Formats where one extracted chunk maps to a real, countable page-equivalent
# (PDF page / PPTX slide / XLSX sheet) — so the chunk count is an HONEST page
# count. For everything else a chunk is "the whole document" (a single DOCX/EML/
# MSG/TXT chunk), which is NOT a page count, so `pages` is left blank there.
_PAGINATED_EXTS = {".pdf", ".pptx", ".xlsx"}


def _sort_rows(rows: list, order: str) -> list:
    """Order the row dicts per SortMode. EVERY key tuple ends with the full
    lowercased `path` so the order is TOTAL + deterministic — two files that are
    otherwise equal (e.g. case-only differences on a case-insensitive FS) still
    get one stable order. Pure; does not mutate the input rows."""
    def folder_key(r):
        return (_natural_key(r["folder"]), _natural_key(r["filename"]),
                r["path"].casefold())

    def name_key(r):
        return (_natural_key(r["filename"]), r["path"].casefold())

    def type_key(r):
        return (r["extension"], _natural_key(r["folder"]),
                _natural_key(r["filename"]), r["path"].casefold())

    def date_key(r):
        # mtime missing -> sort first (treat as oldest), then natural path.
        return (r["mtime"] if r["mtime"] is not None else float("-inf"),
                r["path"].casefold())

    keyfns = {
        SortMode.FOLDER: folder_key,
        SortMode.NAME: name_key,
        SortMode.TYPE: type_key,
        SortMode.DATE: date_key,
    }
    if order in (SortMode.SEQUENCE, SortMode.AS_LISTED):
        # Preserve the SQL pre-sort (ORDER BY f.path) — "as listed".
        return list(rows)
    return sorted(rows, key=keyfns[order])


def build_manifest(db_path: str, *, order: str = SortMode.DEFAULT,
                   number: bool = True) -> dict:
    """Return {'rows': [...], 'summary': {...}} for the matter at db_path.

    `order` (a SortMode value; unknown values fall back to the default) sets the
    row order; `number` assigns a sequential `no` (1..N) AFTER the sort so the
    schedule reads like a numbered exhibit list."""
    order = normalize_order(order)
    with closing(connect(db_path)) as con:
        # One pass over chunks (grouped) joined to files, instead of a correlated
        # COUNT(*) subquery per file. ORDER BY f.path is a stable, deterministic
        # pre-sort; the real ordering is applied in Python (natural collation).
        raw = con.execute(
            """
            SELECT f.id, f.filename, f.ext, f.path, f.size_bytes, f.sha256,
                   f.mtime, f.indexed_at, f.extract_status, f.extract_error,
                   f.source_id, s.label AS source_label, s.root AS source_root,
                   COALESCE(cc.n, 0) AS units
            FROM files f
            LEFT JOIN (SELECT file_id, COUNT(*) AS n FROM chunks GROUP BY file_id) cc
                   ON cc.file_id = f.id
            LEFT JOIN sources s ON s.id = f.source_id
            ORDER BY f.path
            """
        ).fetchall()

    # Mark duplicates: first file of each sha256 is the original, the rest dupes.
    # Duplicate identity follows the sha256 groups, NOT the display order, so the
    # original/dupe split is stable regardless of `order` (the path pre-sort
    # decides which member of a group is the original).
    group_count: dict[str, int] = {}
    for r in raw:
        if r["sha256"]:
            group_count[r["sha256"]] = group_count.get(r["sha256"], 0) + 1
    seen: set[str] = set()

    rows = []
    summary = {
        "total_files": 0, "searchable": 0, "need_ocr": 0, "no_text": 0,
        "unsupported": 0, "errors": 0, "duplicate_files": 0,
        "duplicate_groups": sum(1 for n in group_count.values() if n > 1),
        "total_size_bytes": 0, "by_ext": {},
    }

    for r in raw:
        ext = (r["ext"] or "").lower()
        cstat = content_status(ext, r["extract_status"])
        is_dup = False
        if r["sha256"] and group_count.get(r["sha256"], 0) > 1:
            if r["sha256"] in seen:
                is_dup = True
            else:
                seen.add(r["sha256"])
        mtime = r["mtime"]
        modified = (datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%d")
                    if mtime else "")
        # HONEST page count: only present a count when a chunk == a real page/
        # slide/sheet AND the file is not a scanned/image PDF that yields 0 (0 is
        # NOT a page count — it would under-count a scanned bundle). Everything
        # else gets blank, never a misleading number.
        units = r["units"] or 0
        if (ext in _PAGINATED_EXTS and units > 0
                and not is_scanned_pdf(ext, r["extract_status"])
                and ext not in IMAGE_EXTS):
            pages = units
        else:
            pages = ""
        # Provenance (multi-source ingestion): show the source's label, else a
        # friendly basename of its root; blank for a legacy untagged row.
        source_label = r["source_label"]
        if source_label:
            source_disp = source_label
        elif r["source_root"]:
            source_disp = os.path.basename(str(r["source_root"]).rstrip("/\\")) or r["source_root"]
        else:
            source_disp = ""
        rows.append({
            "filename": r["filename"],
            "folder": os.path.dirname(r["path"]),
            "source": source_disp,
            "source_id": r["source_id"],
            "extension": ext,
            "content_status": cstat,
            "pages": pages,
            "size": _human_size(r["size_bytes"]),
            "size_bytes": r["size_bytes"] or 0,
            "modified": modified,
            "mtime": mtime,
            "duplicate": "yes" if is_dup else "",
            "sha256": r["sha256"] or "",
            "extract_status": r["extract_status"] or "",
            "error": r["extract_error"] or "",
            "path": r["path"],
        })

        # roll up summary
        summary["total_files"] += 1
        summary["total_size_bytes"] += r["size_bytes"] or 0
        summary["by_ext"][ext or "(none)"] = summary["by_ext"].get(ext or "(none)", 0) + 1
        if is_dup:
            summary["duplicate_files"] += 1
        if "OCR needed" in cstat:
            summary["need_ocr"] += 1
        elif cstat.startswith("searchable"):
            # "searchable" AND "searchable (truncated — very large file)" both count as
            # searchable — a truncated file's bounded text is still indexed (not no_text).
            summary["searchable"] += 1
        elif cstat == "error":
            summary["errors"] += 1
        elif cstat.startswith("unsupported"):
            summary["unsupported"] += 1
        else:
            summary["no_text"] += 1

    rows = _sort_rows(rows, order)
    # `mtime` was only needed for the date sort; drop it so it never leaks into
    # the CSV (MANIFEST_COLUMNS doesn't list it, but DictWriter ignores extras —
    # keep the row dict clean for the JSON preview too).
    for row in rows:
        row.pop("mtime", None)
    # Sequential item number AFTER the final sort (1..N), so it reads like a
    # numbered exhibit schedule.
    if number:
        for i, row in enumerate(rows, start=1):
            row["no"] = i
    else:
        for row in rows:
            row["no"] = ""

    summary["total_size"] = _human_size(summary["total_size_bytes"])
    return {"rows": rows, "summary": summary}


# A cell whose first character is one of these is interpreted by Excel / Sheets /
# LibreOffice as a live formula (=cmd, +cmd, -cmd, @cmd). Filenames and extractor
# errors are attacker-influenced (they come from the data room), so neutralize
# them per OWASP CSV-injection guidance by prefixing a single quote, which Excel
# strips on display but which defuses the formula. Tab/CR/LF leading chars are
# also formula-trigger vectors in some parsers, so cover them too.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _csv_safe(value):
    """Defuse spreadsheet formula injection in a single cell value."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _safe_rows(rows):
    return [{k: _csv_safe(v) for k, v in row.items()} for row in rows]


def manifest_csv(db_path: str, *, order: str = SortMode.DEFAULT,
                 number: bool = True) -> str:
    """Render the manifest as CSV text (UTF-8 BOM added by the writer caller).

    `lineterminator="\\r\\n"` pins the line ending so the file is unambiguously
    RFC-4180 / Excel-canonical regardless of the host platform."""
    data = build_manifest(db_path, order=order, number=number)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=MANIFEST_COLUMNS, extrasaction="ignore",
                       lineterminator="\r\n")
    w.writeheader()
    w.writerows(_safe_rows(data["rows"]))
    return buf.getvalue()


def _unique_export_path(directory: Path, name: str, max_probes: int = 50) -> Path:
    """A non-colliding path in `directory` for `name` — adds ` (1)`, ` (2)`, … before the
    suffix, then a timestamp+random fallback (mirrors web._unique_in_dir). NEVER overwrite:
    the export path collides when the same matter is exported twice within the same second
    (the timestamp is second-granular), and the read-only / no-clobber invariant forbids
    silently replacing the prior export. Module-local + dependency-free (automations must
    not import from web)."""
    stem = Path(name).stem or "index"
    suffix = Path(name).suffix or ".csv"
    out = directory / f"{stem}{suffix}"
    n = 1
    while out.exists():
        if n > max_probes:
            stamp = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
            out = directory / f"{stem} ({stamp}){suffix}"
            while out.exists():  # vanishingly unlikely; widen the random tail
                stamp = f"{int(time.time() * 1000)}-{secrets.token_hex(8)}"
                out = directory / f"{stem} ({stamp}){suffix}"
            return out
        out = directory / f"{stem} ({n}){suffix}"
        n += 1
    return out


def export_manifest(db_path: str, matter_name: str = "matter", *,
                    order: str = SortMode.DEFAULT, number: bool = True) -> dict:
    """Write the manifest CSV to %APPDATA%\\DataRoomReview\\exports and return
    {'path': ..., 'rows': N}. Excel-friendly: UTF-8 with BOM, CRLF line endings.
    Never overwrites a prior export (the second-granular timestamp can collide on a
    rapid re-export) — `_unique_export_path` adds a ` (n)` / timestamped suffix."""
    data = build_manifest(db_path, order=order, number=number)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=MANIFEST_COLUMNS, extrasaction="ignore",
                       lineterminator="\r\n")
    w.writeheader()
    w.writerows(_safe_rows(data["rows"]))
    safe = re.sub(r"[^A-Za-z0-9._ -]", "_", matter_name) or "matter"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = _unique_export_path(exports_dir(), f"index_{safe}_{ts}.csv")
    # utf-8-sig so Excel on Windows shows accented names correctly.
    out.write_text(buf.getvalue(), encoding="utf-8-sig")
    # True row count from the data, not a newline count (cells may contain newlines).
    return {"path": str(out), "rows": len(data["rows"])}
