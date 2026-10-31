"""
The split smoke-test suite (was one 5.5k-line tests/test_smoke.py).

tests/test_smoke.py is now a thin RUNNER that discovers every `test_*` callable across
these modules by introspection and runs them — so a test can never again be silently
dropped by forgetting to list it (the old hand-maintained __main__ footgun). Importing
this package sets the app-data isolation env BEFORE any submodule imports `app`, so the
suite never touches a real install.
"""

import os
import tempfile

# Set the isolation env at PACKAGE import time — this runs before any submodule body
# (Python imports the parent package first), guaranteeing app.paths reads our throwaway
# data dir, not a real install. setdefault => shared across every submodule + the runner.
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")
