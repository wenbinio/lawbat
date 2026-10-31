"""
Where the app keeps its per-matter index databases.

Hard rule from the handover: the .db lives in the user's app-data area, NEVER
inside the (read-only) exported data-room folder. One matter = one .db here.
"""

import hashlib
import os
import re
import sys
from pathlib import Path


def data_dir() -> Path:
    """Per-user app data dir. %APPDATA%\\DataRoomReview on Windows.

    LAWDATAMAN_DATA_DIR overrides the location (used by tests for isolation, and
    handy for relocating the store)."""
    override = os.environ.get("LAWDATAMAN_DATA_DIR")
    if override:
        d = Path(override)
    elif sys.platform == "win32":
        d = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "DataRoomReview"
    elif sys.platform == "darwin":
        d = Path.home() / "Library" / "Application Support" / "DataRoomReview"
    else:
        d = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "DataRoomReview"
    d.mkdir(parents=True, exist_ok=True)
    return d


def matters_dir() -> Path:
    d = data_dir() / "matters"
    d.mkdir(parents=True, exist_ok=True)
    return d


def undo_dir() -> Path:
    d = data_dir() / "undo"
    d.mkdir(parents=True, exist_ok=True)
    return d


def exports_dir() -> Path:
    from .releaseflow import STAGE_DIRECTORY
    prepared = STAGE_DIRECTORY.get()
    if prepared is not None:
        return prepared
    d = data_dir() / "exports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def logs_dir() -> Path:
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def temp_dir() -> Path:
    """A scratch dir UNDER the app-data root for short-lived rasters that hold matter
    content (OCR page PNGs).

    Confidentiality (the reason this exists vs the system `tempfile` dir): a SIGKILL /
    power-loss BETWEEN writing a temp raster and its `finally: remove` would otherwise
    leave a cleartext page image in the OS temp dir, recoverable indefinitely. Keeping
    these under the app-data root means (a) they sit beside the matter store the user
    already trusts with this data, and (b) `sweep_temp()` deletes any survivor at the
    next startup, so a crashed run never leaves a stale matter raster around for long.
    The per-write `finally` cleanup still runs first; this is the crash-safety net."""
    d = data_dir() / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d


def sweep_temp() -> int:
    """Delete every entry under [`temp_dir`] — run ONCE at startup to clear rasters a
    prior run left behind after a hard kill (see [`temp_dir`]). Best-effort + never
    raises (a locked / vanished entry is skipped); returns how many top-level entries
    were removed (for logging/tests). A no-op when the dir is empty or absent."""
    import shutil

    removed = 0
    try:
        base = temp_dir()
    except OSError:
        return 0
    try:
        entries = list(base.iterdir())
    except OSError:
        return 0
    for p in entries:
        try:
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink()
            removed += 1
        except OSError:
            # A locked / already-gone entry must never crash startup; leave it for the
            # next sweep.
            continue
    return removed


def safe_matter_name(folder: str) -> str:
    """Turn a folder path into a filesystem-safe matter name for the .db file."""
    name = Path(folder).name or "matter"
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip() or "matter"
    return name


def db_path_for(folder: str) -> Path:
    """Map a source folder to its matter .db.

    The filename includes a hash of the FULL resolved path, so two different
    folders that share a basename (e.g. /clients/Acme/Project X and
    /other/Project_X) get distinct .db files instead of silently colliding into
    one index — a cross-matter confidentiality leak.
    """
    root = str(Path(folder).expanduser().resolve())
    digest = hashlib.sha256(root.encode("utf-8")).hexdigest()[:8]
    return matters_dir() / f"{safe_matter_name(folder)}_{digest}.db"


# Matter .db filenames end in _<8 hex>. Strip it for a human-friendly label.
_DB_SUFFIX_RE = re.compile(r"_[0-9a-f]{8}$")


def friendly_matter_name(db_path: str) -> str:
    return _DB_SUFFIX_RE.sub("", Path(db_path).stem)
