"""Index the fictional Harbour Lane sample room for ``python -m app.serve --demo``.

The files under ``demo/sample-room`` are synthetic. They are not a client file.
"""

from pathlib import Path

from .index import index_folder
from .paths import db_path_for, friendly_matter_name


def sample_room() -> Path:
    """Absolute path to the committed fictional data room."""
    return Path(__file__).resolve().parent.parent / "demo" / "sample-room"


def prepare_demo() -> tuple[str, str]:
    """Index the sample room and return ``(db_path, friendly_name)``.

    Re-running is incremental: unchanged files are skipped. The database goes
    wherever ``LAWDATAMAN_DATA_DIR`` points (demo mode sets that to ``.demo-data``
    before this is called).
    """
    root = sample_room()
    if not root.is_dir():
        raise FileNotFoundError(
            f"Sample room not found: {root}. Run this from a full checkout."
        )
    db = db_path_for(str(root))
    index_folder(str(root), str(db))
    return str(db), friendly_matter_name(str(db))
