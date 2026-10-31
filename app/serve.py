"""
Dev-only CLI: serve the search UI against an existing matter .db.

    python -m app.serve  matter.db
    # then open http://127.0.0.1:8077

End users never see this — the installed app launches via desktop/main.py and
opens a native window with no URL bar. This entry point exists for development.
"""

import sys
from pathlib import Path

import uvicorn

from .logsetup import setup_logging
from .web import create_app, AppState


def main():
    setup_logging("dev")
    db = sys.argv[1] if len(sys.argv) > 1 else None
    state = AppState()
    if db:
        if not Path(db).exists():
            raise SystemExit(f"DB not found: {db}. Run app.index first.")
        state.active_db = db
        from .paths import friendly_matter_name
        state.active_name = friendly_matter_name(db)
    app = create_app(state)
    print("Serving on http://127.0.0.1:8077  (Ctrl-C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=8077, log_level="warning")


if __name__ == "__main__":
    main()
