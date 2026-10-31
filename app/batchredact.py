r"""
BATCH (folder) redaction — enumeration, confinement, and output-dir policy.

The redaction reviewer's batch mode runs the SAME per-file scan/review/apply flow over a
whole FOLDER of documents, one file at a time. A browser page cannot read a folder's files
by path (no filesystem access), so — like the indexer — the SERVER reads the source files;
this module is the single place that decides:

  * which folders are SAFE to batch (never a drive / OS root — reuse app/scan_guard.py),
  * which files are IN SCOPE (supported extensions, within the size cap, not a
    cloud-offline placeholder we must not open),
  * and — the load-bearing invariant — that every later per-file read is CONFINED to the
    originally-chosen folder (resolve + containment check; a `..`/symlink escape is refused).

READ-ONLY on the source folder (the non-negotiable): this module only ``stat()``s + reads;
it NEVER writes beside a source file. Redacted OUTPUT goes to a fresh never-overwrite subdir
under the app-data exports dir (``batch_output_dir``), never the source tree.

CLOUD-PLACEHOLDER SAFETY: enumeration ``stat()``s but never OPENS a file (opening a OneDrive/
Dropbox "files on-demand" stub forces a network download — the egress this app forbids), and
skips offline placeholders from the stat result alone (``scan_guard.is_offline_placeholder``).

Stateless by design: each request re-validates ``(folder, rel)`` from scratch, so there is no
server-side batch session to get out of sync — the confinement check is the ONLY trust
boundary and it runs on every read. Deterministic; no network, no model; no cleartext logged.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import scan_guard
from .paths import exports_dir

# The extensions batch mode enumerates — the SAME set the single-file upload accepts
# (.pdf keeps layout; the rest are extracted to text server-side). A file outside this set is
# skipped from enumeration (counted, never silently dropped). Lowercase, dotted.
SUPPORTED_EXTS = (".pdf", ".txt", ".md", ".csv", ".eml", ".msg", ".docx")

# Caps (env-overridable, house style via scan_guard._env_int). A batch is a REVIEW workload —
# a human confirms + reviews each file — so the ceilings are deliberately modest vs the
# indexer's: a folder with thousands of files is not a per-file-review job.
MAX_FILES = scan_guard._env_int("BATCH_MAX_FILES", 200)
# Per-file byte ceiling: aligned with the redaction file cap (_REDACT_FILE_B64_MAX ~= 10.5 MB
# of raw bytes once base64'd). A file bigger than this is enumerated as SKIPPED (oversize),
# never fed to the engine (it would fail the stdin cap anyway).
MAX_FILE_BYTES = scan_guard._env_int("BATCH_MAX_FILE_BYTES", 10 * 1024 * 1024)
# Directory-depth ceiling for the enumeration walk (a runaway/cyclic tree). Generous for a
# real matter folder; mirrors scan_guard.MAX_DEPTH intent but scoped to the batch walk.
MAX_DEPTH = scan_guard._env_int("BATCH_MAX_DEPTH", 25)


def _resolved(p) -> Path:
    """Best-effort resolved path (symlinks + ``..`` collapsed). Falls back to the raw Path if
    resolution fails, so a caller always gets a Path to compare (containment still re-checks)."""
    try:
        return Path(p).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return Path(p)


def _is_within(child: Path, parent: Path) -> bool:
    """True iff resolved ``child`` is the SAME as, or strictly inside, resolved ``parent`` —
    the confinement predicate. Uses ``Path.relative_to`` on the resolved paths (a `..` or
    symlink that escaped ``parent`` raises ValueError -> False). Case-folded via
    ``os.path.normcase`` so a case-only difference on Windows/macOS can't sneak past."""
    try:
        c = os.path.normcase(str(child))
        p = os.path.normcase(str(parent))
    except (TypeError, ValueError):
        return False
    if c == p:
        return True
    sep = os.sep
    return c.startswith(p + sep) or c.startswith(p + "/")


def enumerate_folder(folder: str) -> dict:
    """Enumerate the SUPPORTED, in-scope files under ``folder`` for a batch (estimate+confirm).

    Returns ``{"ok": True, "folder", "name", "files": [{"rel", "name", "size"} ...],
    "count", "total_bytes", "skipped": {"unsupported", "oversize", "unreadable",
    "placeholders"}, "truncated"}`` — or ``{"ok": False, "error", "level"}`` when the folder
    itself is refused (a drive / OS / app-data root, or not a folder).

    ``rel`` is the path RELATIVE to ``folder`` (POSIX-separated, stable across the OS) — the
    key every later per-file read re-validates. ``truncated`` is True when the walk hit
    ``MAX_FILES`` (the list is a bounded prefix; the user is told there are more). READ-ONLY:
    only ``stat()`` + ``scandir`` — never opens a file. NEVER raises."""
    if not isinstance(folder, str) or not folder.strip():
        return {"ok": False, "error": "no folder given", "level": "refuse"}
    base = _resolved(folder)
    if not base.is_dir():
        return {"ok": False, "error": "That path is not a folder.", "level": "refuse"}
    # Reuse the ingestion policy: a drive / OS / app-data root is never a batch source.
    level, reason = scan_guard.classify_root(folder)
    if level == "refuse":
        return {"ok": False, "error": reason, "level": "refuse"}

    files: list[dict] = []
    total_bytes = 0
    skipped = {"unsupported": 0, "oversize": 0, "unreadable": 0, "placeholders": 0}
    truncated = False

    # Iterative DFS with a depth cap + ancestor-cycle guard (a symlink pointing back up the
    # tree). We push (dir_path, depth, ancestor_keys); a dir whose (dev, ino) matches an
    # ancestor is a cycle and is not re-descended (mirrors scan_guard.real_key).
    start_key = scan_guard.real_key(base)
    stack: list[tuple[Path, int, tuple]] = [(base, 0, (start_key,) if start_key else ())]
    while stack:
        cur, depth, ancestors = stack.pop()
        if depth > MAX_DEPTH:
            continue
        try:
            entries = list(os.scandir(cur))
        except OSError:
            skipped["unreadable"] += 1
            continue
        # Deterministic order (case-folded name) so the enumerated list is stable run-to-run.
        entries.sort(key=lambda e: os.path.normcase(e.name))
        for ent in entries:
            try:
                if ent.is_dir(follow_symlinks=False):
                    key = scan_guard.real_key(Path(ent.path))
                    if key and key[1] and key in ancestors:
                        continue  # cycle — do not re-descend
                    stack.append((Path(ent.path), depth + 1,
                                  ancestors + ((key,) if key else ())))
                    continue
                # A file (or a symlink to one): classify by extension FIRST (cheap), then stat.
                ext = os.path.splitext(ent.name)[1].lower()
                if ext not in SUPPORTED_EXTS:
                    skipped["unsupported"] += 1
                    continue
                # A symlink whose target ESCAPES the folder must not be listed or size-counted:
                # reading it is already refused by resolve_confined, but enumerating it would leak
                # the existence + size of an out-of-folder file. Confinement is checked HERE too,
                # not only at read time.
                if ent.is_symlink() and not _is_within(_resolved(Path(ent.path)), base):
                    skipped["unsupported"] += 1
                    continue
                st = ent.stat(follow_symlinks=True)
                # NEVER open a cloud-offline placeholder (opening triggers a network download);
                # decided from stat() alone. Skipped + counted, never fed to the engine.
                if scan_guard.is_offline_placeholder(st):
                    skipped["placeholders"] += 1
                    continue
                size = int(getattr(st, "st_size", 0) or 0)
                if size > MAX_FILE_BYTES:
                    skipped["oversize"] += 1
                    continue
                p = Path(ent.path)
                try:
                    rel = p.resolve().relative_to(base).as_posix()
                except (OSError, ValueError):
                    rel = os.path.relpath(str(p), str(base)).replace("\\", "/")
                files.append({"rel": rel, "name": ent.name, "size": size})
                total_bytes += size
                if len(files) >= MAX_FILES:
                    truncated = True
                    break
            except OSError:
                skipped["unreadable"] += 1
                continue
        if truncated:
            break

    files.sort(key=lambda f: os.path.normcase(f["rel"]))
    return {
        "ok": True,
        "folder": str(base),
        "name": base.name or str(base),
        "files": files,
        "count": len(files),
        "total_bytes": total_bytes,
        "skipped": skipped,
        "truncated": truncated,
    }


def resolve_confined(folder: str, rel: str) -> Path | None:
    """Resolve ``folder / rel`` to an absolute Path IFF it is a supported, in-scope, CONFINED
    file — else ``None``. The single trust boundary for every per-file read: the resolved
    target MUST live inside the resolved ``folder`` (no `..`/symlink escape), be a real file,
    carry a supported extension, and be within the size cap. NEVER raises."""
    if not isinstance(folder, str) or not isinstance(rel, str) or not folder or not rel:
        return None
    # A bare filename or forward-slash rel only — reject anything with a NUL/control char that
    # could break resolve() (an embedded NUL raises ValueError on POSIX).
    if any(ord(ch) < 0x20 or ch == "\x7f" for ch in rel):
        return None
    base = _resolved(folder)
    if not base.is_dir():
        return None
    target = _resolved(base / rel)
    if not _is_within(target, base):
        return None
    try:
        if not target.is_file():
            return None
    except OSError:
        return None
    if target.suffix.lower() not in SUPPORTED_EXTS:
        return None
    try:
        st = target.stat()
    except OSError:
        return None
    if scan_guard.is_offline_placeholder(st):
        return None
    if int(getattr(st, "st_size", 0) or 0) > MAX_FILE_BYTES:
        return None
    return target


def read_confined(folder: str, rel: str) -> tuple[bytes | None, str | None]:
    """Read a CONFINED source file's bytes (``resolve_confined`` gate). Returns
    ``(bytes, None)`` on success or ``(None, reason)``. READ-ONLY; never opens a placeholder
    (already excluded by the gate); never raises."""
    target = resolve_confined(folder, rel)
    if target is None:
        return None, "that file is not part of the chosen folder"
    try:
        return target.read_bytes(), None
    except OSError:
        return None, "that file could not be read"


def _safe_dir_name(name: str) -> str:
    """A filesystem-safe subdir stem derived from the chosen folder's name (the batch label).
    Non-`[A-Za-z0-9._ -]` -> `_`; a blank result falls back to a generic name."""
    import re
    stem = re.sub(r"[^A-Za-z0-9._ -]", "_", str(name or "")).strip()
    return stem or "batch"


def batch_output_dir(folder_name: str) -> Path:
    """Reserve a FRESH, never-overwrite output subdir under the exports dir for a batch run:
    ``<exports>/<folder-name> redacted[ (n)]``. Created here (mkdir); the per-file writes land
    inside it. Bounded ` (n)` probing then a timestamped fallback — the same no-clobber posture
    as the single-file export path. NEVER writes to the source tree."""
    import secrets
    import time
    base = exports_dir()
    stem = f"{_safe_dir_name(folder_name)} redacted"
    out = base / stem
    n = 1
    while True:
        try:
            out.mkdir(parents=True, exist_ok=False)
            return out
        except FileExistsError:
            if n > 10_000:
                stamp = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
                out = base / f"{stem} ({stamp})"
                try:
                    out.mkdir(parents=True, exist_ok=False)
                    return out
                except FileExistsError:
                    continue
            out = base / f"{stem} ({n})"
            n += 1
