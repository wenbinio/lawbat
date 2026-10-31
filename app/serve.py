"""
Dev-only CLI: serve the search UI against an existing matter .db.

    python -m app.serve
    python -m app.serve matter.db
    python -m app.serve --demo

``--demo`` indexes the fictional ``demo/sample-room`` folder and opens that
matter. End users never see this entry point — the installed app launches via
``desktop/main.py``.
"""

import os
import sys
from pathlib import Path

# Honour --demo before importing the app, so the sample index is stored under
# <repo>/.demo-data instead of the user's real DataRoomReview directory.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEMO = "--demo" in sys.argv[1:]
if _DEMO and not os.environ.get("LAWDATAMAN_DATA_DIR"):
    os.environ["LAWDATAMAN_DATA_DIR"] = str(_REPO_ROOT / ".demo-data")

import uvicorn  # noqa: E402

from .logsetup import setup_logging  # noqa: E402
from .web import AppState, create_app  # noqa: E402


def main():
    setup_logging("dev")
    args = [a for a in sys.argv[1:] if a != "--demo"]
    db = args[0] if args else None
    if _DEMO and db:
        raise SystemExit("Use either --demo or a matter .db path, not both.")
    state = AppState()
    if _DEMO:
        from .demo import prepare_demo
        db_path, name = prepare_demo()
        state.active_db = db_path
        state.active_name = name
        print(f"Demo matter indexed: {name}")
        print(f"  sample room: {_REPO_ROOT / 'demo' / 'sample-room'}")
    elif db:
        if not Path(db).exists():
            raise SystemExit(f"DB not found: {db}. Run app.index first.")
        state.active_db = db
        from .paths import friendly_matter_name
        state.active_name = friendly_matter_name(db)
    app = create_app(state)
    print("Serving on http://127.0.0.1:8077  (Ctrl-C to stop)")
    if _DEMO:
        print("  Home:       http://127.0.0.1:8077/")
        print("  Data room:  http://127.0.0.1:8077/app")
        print("  Redaction:  http://127.0.0.1:8077/redaction")
        print("  Re-ID risk: http://127.0.0.1:8077/reid-risk")
        print("  Workspace:  http://127.0.0.1:8077/workspace")
    uvicorn.run(app, host="127.0.0.1", port=8077, log_level="warning")


if __name__ == "__main__":
    main()
