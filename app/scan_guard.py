r"""
The single source of INGESTION POLICY — what the folder walker is allowed to scan,
and the caps that keep a pathological choice (whole C:\, a cloud-synced tree, a
symlink loop) from hanging, OOMing, or — the load-bearing hazard — silently
DOWNLOADING cloud placeholder files (a network egress this app must never cause).

Mirrors `classify.py`: classification lives in one place, so "is this root safe to
index?" / "is this a cloud placeholder I must NOT open?" / "what are the caps?" are
answered here, not re-derived per call site.

## The cloud-placeholder hazard (why this exists)

A OneDrive / Dropbox / SharePoint "files on-demand" placeholder is a 0-byte stub on
disk; OPENING it (read/hash) forces the sync client to DOWNLOAD the real file from the
network. The indexer hashes + extracts every file, so pointed at a synced folder it
would silently pull gigabytes over the wire — exactly the egress the app forbids.

`is_offline_placeholder(st)` decides this from a `stat()` result ALONE — never opening
the file (opening is what triggers the download). On Windows `stat()` exposes
`st_file_attributes`; on POSIX that attribute is absent, so we degrade to False (no
false positives). Only the SPECIFIC offline/recall bits count — NOT the generic
reparse-point bit (`0x400`), which also flags ordinary junctions/symlinks.

## Caps (all `LAWDATAMAN_*`-overridable, house style)

A whole-disk / hostile tree must surface as a refuse/warn or stop bounded, not hang
before any progress. Constants below; each reads an env override at import time.

## Local / deterministic / no egress

Pure policy: stat bits + path comparison. No I/O beyond the caller's own `stat()`.
"""

import os
import sys
from pathlib import Path

from . import paths


def _env_int(name: str, default: int) -> int:
    """An int module-constant with a `LAWDATAMAN_<NAME>` env override (house style —
    mirrors how the rest of the app reads `LAWDATAMAN_*`). Garbage / negative falls
    back to the default so a typo can't disable a cap."""
    raw = os.environ.get("LAWDATAMAN_" + name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return v if v > 0 else default


# --- caps (override via LAWDATAMAN_MAX_FILE_BYTES, LAWDATAMAN_FILE_COUNT_WARN, …) ---
# A single file bigger than this is SKIPPED (not opened/hashed) — a multi-GB blob is
# almost never a reviewable document, and hashing it stalls the run.
MAX_FILE_BYTES = _env_int("MAX_FILE_BYTES", 2 * 1024 ** 3)         # 2 GiB
# File-count thresholds: WARN = "this is a big room, confirm"; HARD = a sanity ceiling
# the estimate reports as too_large (a whole-disk choice).
FILE_COUNT_WARN = _env_int("FILE_COUNT_WARN", 50_000)
FILE_COUNT_HARD = _env_int("FILE_COUNT_HARD", 2_000_000)
# Total-bytes WARN: a very large corpus to hash+extract (time/space), confirm first.
TOTAL_BYTES_WARN = _env_int("TOTAL_BYTES_WARN", 50 * 1024 ** 3)    # 50 GiB
# Directory depth ceiling: subtrees deeper than this are skipped (a runaway/cyclic
# tree, or a generated nest). Generous for any real data room.
MAX_DEPTH = _env_int("MAX_DEPTH", 40)
# The pre-walk estimate stops early at this many files OR after this many seconds, so a
# huge tree still yields a (capped) estimate fast instead of walking forever.
ESTIMATE_MAX_FILES = _env_int("ESTIMATE_MAX_FILES", 2_000_000)
ESTIMATE_TIMEOUT_S = _env_int("ESTIMATE_TIMEOUT_S", 30)


# --- Windows file-attribute bits (winnt.h FILE_ATTRIBUTE_*) -----------------------
# OFFLINE: the file's data is not immediately available (stub). RECALL_ON_DATA_ACCESS
# / RECALL_ON_OPEN: a cloud-provider placeholder whose bytes are fetched on access.
# Reading ANY of these forces a network download — so we detect + SKIP from stat()
# alone. (We deliberately do NOT use REPARSE_POINT 0x400: it also covers junctions /
# symlinks, which are NOT cloud placeholders.)
_FILE_ATTRIBUTE_OFFLINE = 0x1000
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
_CLOUD_PLACEHOLDER_MASK = (
    _FILE_ATTRIBUTE_OFFLINE
    | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    | _FILE_ATTRIBUTE_RECALL_ON_OPEN
)


def is_offline_placeholder(st) -> bool:
    r"""True iff `st` (an os.stat_result) is a cloud-synced OFFLINE / recall-on-access
    placeholder — i.e. reading the file would force a network DOWNLOAD.

    Decided from the stat() result ALONE: we must NOT open the file, because opening is
    exactly what triggers the download. On POSIX `st_file_attributes` doesn't exist, so
    `getattr(..., 0)` → 0 → False (no false positives off Windows)."""
    attrs = getattr(st, "st_file_attributes", 0) or 0
    return bool(attrs & _CLOUD_PLACEHOLDER_MASK)


def real_key(path: Path):
    r"""A real-path identity key `(st_dev, st_ino)` for loop detection during a walk:
    a directory whose key matches one of its OWN ANCESTORS on the path being walked is
    a cycle (a symlink/junction pointing back UP the tree) and must not be re-descended.
    Returns None if the path can't be stat'd (caller treats that as 'not seen' and lets
    the normal error path handle it).

    The walker compares against the ANCESTOR chain only — NOT a global ever-seen set:
    two distinct dirs can legitimately share a key (FAT/exFAT report st_ino==0 for
    everything; some bind/overlay/network mounts reuse inodes), and a global set would
    wrongly prune a real subtree (a recall MISS). A key with st_ino==0 is meaningless
    and the walker never prunes on it.

    Uses the path's OWN stat (followlinks already handled by the walker); on Windows
    st_ino is populated by CPython, so (dev, ino) is a usable identity there too."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


# --- root classification -----------------------------------------------------------
# Roots we REFUSE to index outright: a whole drive / OS tree is never a data room, and
# scanning one is the worst case (huge + slow + likely cloud-synced). Compared as
# resolved, case-folded paths so trailing slashes / case can't sneak past.
def _norm(p) -> str:
    """Case-folded, separator-normalized resolved string for comparison."""
    try:
        rp = Path(p).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        rp = Path(p)
    return os.path.normcase(str(rp)).rstrip("\\/") or os.path.normcase(str(rp))


def _is_within(child_norm: str, parent_norm: str) -> bool:
    """True iff `child_norm` is the SAME path as, or strictly inside, `parent_norm`
    (both already _norm()'d). Compares on a separator boundary so `/data2` is not
    treated as inside `/data` (a prefix-string false positive)."""
    if child_norm == parent_norm:
        return True
    sep = os.sep
    return child_norm.startswith(parent_norm + sep) or child_norm.startswith(parent_norm + "/")


def _windows_refuse_roots() -> set:
    r"""C:\, C:\Windows, …\System32, Program Files(x86), ProgramData on EVERY drive
    letter present-or-not (we can't enumerate drives portably here, so cover A:..Z:)."""
    out = set()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        out.add(_norm(drive))                                   # the bare drive root
        out.add(_norm(drive + "Windows"))
        out.add(_norm(drive + "Windows\\System32"))
        out.add(_norm(drive + "Program Files"))
        out.add(_norm(drive + "Program Files (x86)"))
        out.add(_norm(drive + "ProgramData"))
    return out


_POSIX_REFUSE_ROOTS = {
    _norm("/"), _norm("/usr"), _norm("/bin"), _norm("/sbin"), _norm("/etc"),
    _norm("/System"), _norm("/Library"), _norm("/private"), _norm("/var"),
}


def _is_drive_root(rp: Path) -> bool:
    r"""True if `rp` is a bare drive/filesystem root (C:\, D:\, or POSIX /)."""
    # A root path's parent is itself; on Windows the anchor equals the path.
    return rp.parent == rp


def _is_unc(p) -> bool:
    r"""A UNC / network share (\\server\share\...). Network paths warn (a synced or
    remote share is a download/latency hazard) but are allowed after confirm."""
    s = str(p)
    return s.startswith("\\\\") or s.startswith("//")


def classify_root(path) -> tuple:
    r"""Classify a chosen index ROOT into ("ok"|"warn"|"refuse", reason).

      refuse — a drive / OS / app-data root: never a data room; scanning it is the
               worst case. HARD-blocked server-side regardless of any client flag.
      warn   — a bare drive root, the user-profile home, or a UNC/network share:
               allowed, but only after an explicit confirm (these are big / remote /
               likely cloud-synced).
      ok     — a normal sub-folder.

    Comparison is on RESOLVED, case-folded paths (robust to case + trailing slash)."""
    try:
        rp = Path(path).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return ("refuse", "That path could not be resolved.")

    n = _norm(rp)

    # The app's own data dir (matter DBs, exports, undo) is never a source room —
    # nor is any SUBFOLDER of it (e.g. data_dir()/matters), else a user could point
    # the indexer at their own matter DBs.
    try:
        data_n = _norm(paths.data_dir())
        if n == data_n:
            return ("refuse", "That is the app's own data folder, not a data room.")
        if _is_within(n, data_n):
            return ("refuse", "That is inside the app's own data folder, not a data room.")
    except Exception:  # noqa: BLE001 - never let a data_dir hiccup break classification
        pass

    refuse_roots = _POSIX_REFUSE_ROOTS if os.name != "nt" else _windows_refuse_roots()
    # On macOS (posix but Mac roots) include the Mac-specific set regardless.
    if sys.platform == "darwin":
        refuse_roots = refuse_roots | {
            _norm("/System"), _norm("/Library"), _norm("/private"),
            _norm("/Applications"), _norm("/Volumes"),
        }
    if n in refuse_roots:
        return ("refuse", "That is a system or drive root — choose a specific folder.")

    # A bare drive / filesystem root that wasn't already refused (e.g. D:\ data drive,
    # or a non-/ POSIX mount root): allowed, but big — confirm.
    if _is_drive_root(rp):
        return ("warn", "That is a whole drive — confirm you want to index all of it.")

    # The user-profile home (~ / %USERPROFILE%): large + mixes app data with documents,
    # and is commonly the cloud-sync root. Warn.
    try:
        if n == _norm(Path.home()):
            return ("warn", "That is your whole user profile — confirm before indexing.")
    except (OSError, RuntimeError):
        pass

    # UNC / network share: a remote or synced share is a download/latency hazard. Warn.
    if _is_unc(path) or _is_unc(rp):
        return ("warn", "That is a network share — confirm before indexing.")

    return ("ok", "")
