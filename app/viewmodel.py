"""
Bridge to the Rust `viewgen` binary that emits the firmOS HOME view-model.

The host shell (the Python pilot) renders a TYPED view-model (the "firmos.view/0"
contract) the trusted Rust core produces. This module is the thin, JSON-over-
subprocess seam between the two: it locates the bin, runs it (no shell, args list,
bounded timeout, captured stdout), parses the contract, and hands it back.

LOCAL-ONLY: this only ever runs a LOCAL executable and reads a LOCAL JSON file.
No network, no model — the same air-gap guarantee as the rest of the app.

GRACEFUL FALLBACK (load-bearing): the Rust bin ships under vendor/core/ (bundled in
the MSI), but may be absent in a dev environment or custom install. The Home must still render. So if
the bin is missing, errors, times out, or emits something that isn't the contract,
we fall back to the bundled `app/ui/sample_home.json`, mark the result
`preview: True`, and NEVER raise out to the server. A missing bin is normal, not a
crash.

The bin locator + the safe subprocess runner are the SHARED core-bridge primitives
(app/corebridge.py): env override `LAWDATAMAN_VIEWGEN` -> bundled <vendor>/core/viewgen
-> system PATH, then a no-shell, args-list, UTF-8, bounded-timeout, never-raise run.
"""

import json
import logging
from pathlib import Path

from . import corebridge

log = logging.getLogger("dataroomreview.viewmodel")

# The contract this module knows how to render. A bin that emits a different schema
# is treated like a failure (we fall back) rather than rendered blindly.
VIEW_SCHEMA = "firmos.view/0"

# Bound the subprocess so a hung/runaway bin can never wedge a request. The view
# generation is pure compute over already-read data; a couple of seconds is ample.
_VIEWGEN_TIMEOUT_S = 5.0

# The bundled sample, served when the bin is unavailable. Lives next to the UI it
# feeds (app/ui/) and is committed, so the Home renders in dev and in the shipped
# pilot before the Rust bin is wired.
_SAMPLE_PATH = Path(__file__).resolve().parent / "ui" / "sample_home.json"


def viewgen_path() -> str | None:
    """Absolute path to the Rust `viewgen` bin, or None if unavailable.

    Delegates to corebridge.locate (env -> vendor/core/ -> PATH); viewgen is a core
    binary, not an optional third-party tool like Tesseract."""
    return corebridge.locate("LAWDATAMAN_VIEWGEN", "viewgen")


def _is_contract(obj) -> bool:
    """True if `obj` looks like the firmos.view/0 contract we render."""
    return (
        isinstance(obj, dict)
        and obj.get("schema") == VIEW_SCHEMA
        and isinstance(obj.get("sections"), list)
    )


def _load_sample() -> dict:
    """The bundled sample contract, marked preview. Never raises: if even the
    sample can't be read, return a minimal valid (empty) contract so the Home still
    renders an honest 'nothing here' rather than erroring."""
    try:
        data = json.loads(_SAMPLE_PATH.read_text(encoding="utf-8"))
        if _is_contract(data):
            data["preview"] = True
            return data
        log.warning("bundled sample_home.json is not a valid %s contract", VIEW_SCHEMA)
    except Exception as e:  # noqa: BLE001 - the fallback itself must never crash
        log.warning("could not read bundled sample_home.json: %s", type(e).__name__)
    return {
        "schema": VIEW_SCHEMA,
        "generated_label": "Preview unavailable.",
        "preview": True,
        "sections": [],
    }


def get_home_view() -> dict:
    """Return the firmOS HOME view-model (the firmos.view/0 contract).

    Runs the Rust `viewgen` bin if present and well-behaved; otherwise falls back to
    the bundled sample marked `preview: True`. ALWAYS returns a dict — it never
    raises, so a missing/broken bin can never take down the Home route."""
    bin_path = viewgen_path()
    if not bin_path:
        log.info("viewgen bin not found; serving bundled sample (preview)")
        return _load_sample()

    # No shell; args as a list; bounded timeout; stdout captured as text (see
    # corebridge.run). The bin gets NO matter content on argv/stdin here — it reads what
    # it needs THROUGH the core; we only consume its stdout.
    res = corebridge.run(bin_path, timeout=_VIEWGEN_TIMEOUT_S)
    if not res.started:
        log.warning("viewgen failed to run (%s); serving sample", res.exc_name)
        return _load_sample()

    if res.returncode != 0:
        log.warning("viewgen exited %s; serving sample", res.returncode)
        return _load_sample()

    try:
        data = json.loads(res.stdout)
    except (ValueError, TypeError) as e:
        log.warning("viewgen stdout was not JSON (%s); serving sample", type(e).__name__)
        return _load_sample()

    if not _is_contract(data):
        log.warning("viewgen output is not a %s contract; serving sample", VIEW_SCHEMA)
        return _load_sample()

    # A real generator drives the live worklist — not a preview.
    data.setdefault("preview", False)
    return data
