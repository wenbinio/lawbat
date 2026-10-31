"""
The localhost web app the desktop window points at.

Binds to 127.0.0.1 on a random free port (chosen by the desktop launcher).
No external requests, no CDN, no web fonts — the page is fully self-contained so
it works on an air-gapped machine. The pywebview window shows this with no URL
bar, so it reads as a native app, not a browser.

create_app(state) returns a FastAPI app driven by an AppState:
  - which matter (.db) is currently open
  - the status of any running index job (for the progress bar)

The folder picker itself is NOT here: a web page cannot read a real folder path.
The desktop window exposes pywebview.api.pick_folder() for that; the page then
POSTs the chosen path to /api/index.
"""

import base64
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
import platform
import re
import secrets
import sys
import threading
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, Body, Depends, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from . import scan_guard
from .ui_manifest import BASE_JS, REDACTION_JS_PARTS
from .db import connect, fts5_available, norm_path
from .index import (
    index_folder, estimate_folder, _safe_error,
    add_source, remove_source,
)
from .logsetup import log_file
from .paths import (
    db_path_for, data_dir, matters_dir, friendly_matter_name, undo_dir,
    sweep_temp,
)
from .osio import open_path, reveal_in_folder
from .viewmodel import get_home_view
from . import redactionmodel
from . import reidrisk
from .queries import (
    run_search, corpus_stats, list_files, matter_source_root,
    matter_source_roots, list_sources, list_matters,
)
# Redaction API routes live in app/redactionroutes.py (factored out of this factory).
# We include the router in create_app; the two caps are re-imported because the
# reid-risk routes below reuse the SAME text / file-size limits, and `_unique_in_dir` is
# re-exported so its unit test (which imports app.web._unique_in_dir) keeps resolving.
from .redactionroutes import (
    build_redaction_router,
    _REDACT_TEXT_MAX,
    _REDACT_FILE_B64_MAX,
    _unique_in_dir,  # noqa: F401 - re-exported for tests / back-compat
)
from .automations import (
    RenameRules, plan_rename, apply_plan, undo,
    build_manifest, manifest_csv, export_manifest, normalize_order,
)


log = logging.getLogger("dataroomreview.web")

# Header carrying the per-session CSRF/auth token (see AppState.token). Even
# though the server is localhost-only, ANY page in the user's browser (or a
# malicious local doc) can POST to 127.0.0.1; a same-origin-only secret on the
# state-changing / file-touching endpoints stops a drive-by from a foreign
# origin renaming files or kicking off an index. The token is minted at startup,
# injected into our own served HTML, and never leaves the machine.
TOKEN_HEADER = "X-DRR-Token"


class _TokenDenied(Exception):
    """Raised by the require_token dependency on a missing/wrong session token.

    Mapped by create_app's exception handler to the EXACT legacy error response —
    a 403 with body {"error": "forbidden"} — so the UI JS (which may match on that
    shape) sees a byte-identical rejection to the old imperative guard."""


# Bound the server-side result limits so a single request can't ask for an
# unbounded fetch (memory / latency). Generous for any real review session.
_SEARCH_LIMIT_MAX = 1000
_FILES_LIMIT_MAX = 10000

# The redaction request caps (`_REDACT_TEXT_MAX`, `_REDACT_FILE_B64_MAX`, plus the
# apply/export/preview bounds) live in app/redactionroutes.py alongside the routes that
# enforce them; the two the reid-risk routes below reuse are imported at the top of this
# module.

# Re-identification risk estimator caps. The estimator is pure-Python + deterministic, but a
# request is still bounded: the pasted/extracted text reuses the redaction text cap, and a
# batch is capped on document count (the engine bounds each doc internally too).
_REID_BATCH_DOCS_MAX = 200          # documents in one /api/reidrisk/batch call
_REID_LINK_TERMS_MAX = 200          # user-supplied link terms in a batch
# A SANE aggregate bound on a batch: per-doc text is already capped at _REDACT_TEXT_MAX, but
# 200 docs at that cap would be ~400 MB of resident text — a memory-blow risk. Cap the SUM of
# the accepted (paste + extracted) text across the batch. Generous for any real release set.
_REID_BATCH_TOTAL_BYTES_MAX = 64_000_000
# Pre-decode aggregate bound on the batch's UPLOADED base64 (#20): the per-doc text cap above
# only bites AFTER each upload is base64-decoded + extracted, so a batch of many ~14 MB-base64
# uploads (200 × 14 MB ≈ 2.8 GB) could buffer gigabytes of base64 before the text cap rejects
# it. Cap the SUM of len(data_b64) across the docs BEFORE decoding ANY of them. Sized to the
# same order as the text cap (64 MB) but on the base64 input directly — generous for a real
# multi-doc batch (a release set is a handful of memos, not hundreds of 10 MB scans), while a
# pathological batch is rejected with a clean 413 instead of buffering GB. Below the global
# body-size ceiling, so this is the SHARPER, batch-specific bound within an authorized request.
_REID_BATCH_B64_TOTAL_MAX = 64_000_000

# Global pre-auth request-body ceiling (#20). FastAPI fully BUFFERS + JSON-parses the entire
# request body BEFORE the require_token dependency or any per-field cap runs, and there is no global
# body-size limit — so an unauthenticated multi-GB POST is buffered into memory before the
# 403/400. An ASGI middleware (see create_app) rejects a request whose DECLARED Content-Length
# exceeds this with HTTP 413 BEFORE the body is read. The ceiling sits comfortably ABOVE every
# legitimate request so nothing regresses: the largest single legit POST is one redaction/upload
# at _REDACT_FILE_B64_MAX (~14 MB base64) plus a small JSON envelope; the batch path is bounded
# to _REID_BATCH_B64_TOTAL_MAX (~64 MB) of base64. 128 MiB clears both with wide margin. A
# request with NO Content-Length (chunked / normal client) is NOT rejected here — it falls
# through to the existing per-field caps. Overridable (LAWDATAMAN_MAX_REQUEST_BODY_BYTES) for an
# unusual deployment; reuses scan_guard._env_int (the house-style int-with-env-override helper).
_MAX_REQUEST_BODY_BYTES = scan_guard._env_int("MAX_REQUEST_BODY_BYTES", 128 * 1024 * 1024)


def _clamp(value, lo, hi, default):
    """Coerce an untrusted ?limit= to an int in [lo, hi]; fall back on garbage."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def _is_within(child: Path, parent: Path) -> bool:
    """True if child == parent or child is nested under parent (resolved)."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass
class IndexJob:
    status: str = "idle"          # idle | running | done | error
    phase: str = ""               # "" | estimating | indexing  (UI: "Scanning…" vs index)
    done: int = 0
    total: int = 0
    current: str = ""
    stats: dict = field(default_factory=dict)
    error: str = ""
    folder: str = ""
    cancel: bool = False


class AppState:
    def __init__(self):
        self.active_db: str | None = None
        self.active_name: str | None = None
        # Bumped under _lock whenever the user EXPLICITLY opens/closes a matter
        # (/api/open, /api/close). A finishing index worker compares the value it
        # captured at start against the current one and DECLINES to publish its matter
        # as active if the user switched in the meantime — so an explicit open during a
        # long index is never silently clobbered when the index completes.
        self.open_gen = 0
        self.job = IndexJob()
        # Per-session secret for the state-changing endpoints (see TOKEN_HEADER).
        # Minted once here; the served page embeds it and echoes it back.
        self.token: str = secrets.token_urlsafe(32)
        self._lock = threading.Lock()


# ---------------------------------------------------------------- queries ---
# The read-only SQL helpers (run_search / corpus_stats / list_files /
# matter_source_root(s) / list_sources / list_matters) live in app/queries.py and are
# imported at the top of this module.


# ---------------------------------------------------------------- home ------
# The firmOS HOME (dashboard) is the app's LANDING page. Its HTML/CSS/JS live in
# app/ui/* (extracted from the old embedded blob pattern) and are INLINED into one
# document at startup, so the page stays fully self-contained / air-gapped (no
# <link>/<script src>, no web fonts, no CDN) — the same guarantee as the data-room
# PAGE. This is the trusted HOST shell, so its JS is first-party (not a module).
_UI_DIR = Path(__file__).resolve().parent / "ui"


def _inline_js(js: str) -> str:
    """Make a first-party JS blob SAFE to splice into an inline <script> element.

    An HTML inline <script> is terminated by the literal byte sequence "</script>" ANYWHERE in
    its text — even inside a JS string/comment. None of our shipped JS contains one today, but
    a future edit that did (e.g. a string literal "</script>") would break OUT of the inlined
    script tag the moment a page builder spliced it in. Escaping the only sequence the HTML
    tokenizer cares about — case-insensitively, with the standard JS `<\\/script` form, which the
    JS engine reads back as "</script" — neutralises that without changing the script's meaning.
    This runs at INLINE time on the page builder's local copy; it does NOT modify any .js file on
    disk (so redaction.state.js's byte-for-byte invariant, incl. its one NUL byte, is untouched)."""
    return re.sub(r"</script", r"<\\/script", js, flags=re.IGNORECASE)


def _airgap_strict(page: str, label: str) -> None:
    """STRICT air-gap guard: the assembled page must reference NOTHING over http(s).

    Air-gap guard, enforced in code: the served page must pull NOTHING from the
    network. (The data-room PAGE links AGPL/source URLs in its footer with
    target=_blank and therefore uses _airgap_resource_load_only; the Home shell —
    and the redaction / reid-risk pages — deliberately carry no external link at
    all, the Home being the landing surface the no-URL-bar window opens.)"""
    assert "http://" not in page and "https://" not in page, \
        f"{label} page must not reference any external (http/https) resource (air-gap)"


def _airgap_resource_load_only(page: str, label: str) -> None:
    """Resource-LOAD-only air-gap guard (the data-room page's DELIBERATELY DIFFERENT check).

    The Home has zero external links, so it can assert "no http(s):// anywhere" (see
    _airgap_strict above). The data-room page, by contrast, LEGITIMATELY carries two
    external footer anchors (target=_blank hrefs to the AGPL-3.0 licence + the source
    repo) — those are NAVIGATION the user clicks, NOT a resource the page loads. A
    verbatim copy of the Home's assert would FALSELY fail the build here. So we forbid
    only externally LOADED resources (remote <link>/<script>/<img> srcs, CSS @import,
    web-font/CDN url()) and ALLOW external URLs that appear only as anchor hrefs —
    still catching a real CDN / web-font / remote-script regression."""
    # Resource-load air-gap check. Whitespace-collapse + lowercase first so a spaced-out
    # `<script   src = "HTTP...` can't slip past; then reject any pattern that PULLS
    # bytes off the network. An <a href="http..."> nav link is intentionally NOT matched.
    norm = re.sub(r"\s+", " ", page).lower()
    forbidden = [
        r"<link\b[^>]*\bhref\s*=\s*[\"']?https?:",    # remote stylesheet / preload
        r"<script\b[^>]*\bsrc\s*=\s*[\"']?https?:",   # remote script
        r"<img\b[^>]*\bsrc\s*=\s*[\"']?https?:",      # remote image
        r"<iframe\b[^>]*\bsrc\s*=\s*[\"']?https?:",   # remote iframe
        r"@import\s+(?:url\()?[\"']?https?:",          # CSS @import of a remote sheet
        r"\burl\(\s*[\"']?https?:",                    # web-font / CDN url() in CSS
    ]
    for pat in forbidden:
        assert not re.search(pat, norm), (
            f"{label} page must not LOAD any external (http/https) resource "
            f"(air-gap); matched: {pat}"
        )


def _build_page(html_name: str, parts: list[tuple[str, str | list[str]]], *, label: str,
                guard, ui_dir: Path | None = None) -> str:
    """Assemble ONE self-contained page: read `html_name` from the UI dir and inline
    each `(marker, filename)` in `parts` (a `.js` part goes through _inline_js so a
    literal "</script>" can never break out of the inline tag; css/other parts are
    spliced verbatim). `filename` is normally a single string; it may also be a LIST of
    filenames, concatenated in that order into the one marker — this is how the split
    redaction.js fragments (app/ui_manifest.REDACTION_JS_PARTS) are reassembled into a
    single <script> block, in the order that list defines (see its docstring). Read once
    at import time (the module-level *_PAGE constants) — the files don't change at runtime.

    A MISSING marker is a HARD STARTUP ERROR (RuntimeError), not a silent no-op: a
    plain str.replace would quietly ship the page with its css/js absent, which is
    exactly the "safe only if you remember" failure this helper exists to remove.

    `guard` is the air-gap check to run on the assembled page — _airgap_strict for a
    page with NO external link at all (Home / redaction / reid-risk), or
    _airgap_resource_load_only for the data-room page (see each guard's docstring for
    why they differ). Both are enforced in code so a stray CDN/web-font link can never
    slip past the air-gap guarantee."""
    base_dir = ui_dir if ui_dir is not None else _UI_DIR
    page = (base_dir / html_name).read_text(encoding="utf-8")
    for marker, filenames in parts:
        if marker not in page:
            raise RuntimeError(
                f"{html_name}: missing inline marker {marker!r} — cannot assemble the "
                f"{label} page (a silent str.replace no-op would ship the page without "
                f"{filenames})")
        names = filenames if isinstance(filenames, list) else [filenames]
        pieces = []
        for fn in names:
            content = (base_dir / fn).read_text(encoding="utf-8")
            if fn.endswith(".js"):
                content = _inline_js(content)
            pieces.append(content)
        page = page.replace(marker, "\n".join(pieces))
    guard(page, label)
    return page


def _build_home_page() -> str:
    """Assemble the Home document: inline home.css + base.js + home.js into home.html.
    (Thin wrapper over _build_page — kept as a named function for tests/callers.)

    base.js (window.LB: esc/$/get/post/announce — see app/ui/base.js) is INLINED via the
    shared /* __BASE_JS__ */ marker, BEFORE home.js in the same <script> block, on every
    page that carries one — never <link src>'d, so the air-gap guarantee holds."""
    return _build_page("home.html", [
        ("/* __HOME_CSS__ */", ["base.css", "home.css"]),
        ("/* __BASE_JS__ */", BASE_JS),
        ("/* __HOME_JS__ */", "home.js"),
    ], label="Home", guard=_airgap_strict)


# Assembled once; the per-session token is injected per request (see the / route).
HOME_PAGE = _build_home_page()


def _build_dataroom_page() -> str:
    """Assemble the data-room document: inline dataroom.css + dataroom.js into dataroom.html.

    Mirrors _build_home_page() — read once at import time (module-level PAGE) — but the
    air-gap guard is DELIBERATELY DIFFERENT: this page legitimately carries two external
    footer anchors, so it uses _airgap_resource_load_only (see that guard's docstring).
    base.js is inlined FIRST via the shared /* __BASE_JS__ */ marker (see _build_home_page)."""
    return _build_page("dataroom.html", [
        ("/* __DATAROOM_CSS__ */", ["base.css", "dataroom.css"]),
        ("/* __BASE_JS__ */", BASE_JS),
        ("/* __DATAROOM_JS__ */", "dataroom.js"),
    ], label="Data-room", guard=_airgap_resource_load_only)


# Assembled once; the per-session token is injected per request (see the /app route).
PAGE = _build_dataroom_page()


def _build_redaction_page() -> str:
    """Assemble the Redaction review document: inline base.css + redaction.css + base.js +
    redaction's split JS fragments into redaction.html. Mirrors _build_home_page() (read
    once at import time) and uses the SAME strict air-gap guard — this page carries no
    external links, so it must reference NOTHING over http(s).

    base.css is the SHARED design-system base (tokens + topbar/banner/btn/chip/card/empty/
    error/spinner + focus ring), reusable for Home/dataroom (Phase 3) but wired in HERE for
    now. It is INLINED via the dedicated /* __BASE_CSS__ */ marker — never <link>'d — so the
    air-gap guarantee holds. redaction.css then carries only the page-specific styles on top.

    redaction.js was split at its own section-comment boundaries into the ordered fragments
    named in app/ui_manifest.REDACTION_JS_PARTS (the SINGLE source of truth for the order —
    see that module's docstring); _build_page concatenates them, in that order, into the one
    /* __REDACTION_JS__ */ marker, forming ONE outer IIFE exactly as the pre-split file did.
    base.js (window.LB) is inlined first via its own /* __BASE_JS__ */ marker, in the same
    <script> block, so LB exists before the fragments run."""
    return _build_page("redaction.html", [
        ("/* __BASE_CSS__ */", "base.css"),
        ("/* __REDACTION_CSS__ */", "redaction.css"),
        ("/* __BASE_JS__ */", BASE_JS),
        ("/* __REDACTION_JS__ */", REDACTION_JS_PARTS),
    ], label="Redaction", guard=_airgap_strict)


# Assembled once; the per-session token is injected per request (see the /redaction route).
REDACTION_PAGE = _build_redaction_page()


def _build_reidrisk_page() -> str:
    """Assemble the Re-identification RISK estimator document: inline base.css + reidrisk.css
    + reidrisk.js into reidrisk.html. Mirrors _build_redaction_page() (read once at import
    time, base.css via the shared /* __BASE_CSS__ */ marker) and uses the SAME strict air-gap
    guard — this page carries no external links, so it must reference NOTHING over http(s).

    This is a NEW, SEPARATE page from the redaction reviewer: it estimates a population-
    uniqueness k-value (an OPTIMISTIC lower bound — see app/reidrisk.py's honesty spine) and
    never touches the redaction carrier. base.js is inlined first via the shared
    /* __BASE_JS__ */ marker (see _build_home_page)."""
    return _build_page("reidrisk.html", [
        ("/* __BASE_CSS__ */", "base.css"),
        ("/* __REIDRISK_CSS__ */", "reidrisk.css"),
        ("/* __BASE_JS__ */", BASE_JS),
        ("/* __REIDRISK_JS__ */", "reidrisk.js"),
    ], label="Re-id risk", guard=_airgap_strict)


# Assembled once; the per-session token is injected per request (see the /reid-risk route).
REIDRISK_PAGE = _build_reidrisk_page()


def _content_disposition(filename: str) -> str:
    """Build a safe `Content-Disposition: attachment` header value for `filename`.

    A matter name can contain `"` / `&` / non-ASCII — putting it RAW into the legacy
    `filename="..."` token can terminate the quoted string early or inject header
    syntax (and a non-ASCII byte is not valid in a token). Per RFC 6266 / RFC 5987 we
    emit BOTH:
      - a sanitized ASCII `filename="..."` fallback (control/quote/backslash/non-ASCII
        replaced with `_`) for legacy clients, and
      - a `filename*=UTF-8''<pct-encoded>` for modern clients, percent-encoding
        everything outside the RFC 5987 `attr-char` set (so `"`/`&`/`%`/space/UTF-8 are
        all escaped).
    Modern browsers prefer `filename*`, so the real (Unicode) name is preserved while no
    untrusted byte can break the header."""
    from urllib.parse import quote

    raw = str(filename or "download")
    # ASCII fallback: keep it a single safe token — replace anything that could break the
    # quoted-string (quote, backslash, control chars) or isn't ASCII.
    ascii_name = "".join(
        c if (32 <= ord(c) < 127 and c not in '"\\') else "_" for c in raw
    ) or "download"
    # RFC 5987: percent-encode to the attr-char set (letters/digits + a small safe punct
    # subset). `quote` with an explicit safe list; everything else (incl. `"`/`&`/`%`)
    # becomes %XX over the UTF-8 bytes.
    enc = quote(raw, safe="!#$&+-.^_`|~")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{enc}"


# The `_unique_in_dir` no-clobber helper and the redaction sample-PDF builder moved to
# app/redactionroutes.py (their only users are the redaction routes); `_unique_in_dir`
# is re-imported above so its unit test keeps resolving app.web._unique_in_dir.


# ---------------------------------------------------------------- app -------
def _install_body_limit_and_token(app: FastAPI, state: "AppState"):
    """Install the shared pre-auth security plumbing on `app` and return the require_token
    dependency to attach to state-changing routes.

    Factored out (not duplicated) because BOTH app factories need it, byte-for-byte:
    create_app (Lawbat, the full app) and create_redactor_app (the standalone Redactor
    variant — the redaction reviewer as the whole app). Keeping ONE implementation means
    the 413 body ceiling and the 403 {"error":"forbidden"} token rejection can never drift
    between the two products. Returns require_token; the caller builds _TOKEN_GUARD from it
    and passes it to build_redaction_router.

    PRE-AUTH BODY-SIZE CEILING (#20): a raw ASGI middleware that inspects the declared
    Content-Length on the request SCOPE and short-circuits an over-ceiling request with a
    413 BEFORE the body is received/buffered/parsed — so a pre-auth multi-GB POST can't be
    buffered into memory ahead of the require_token dependency / the per-field caps. It is a
    memory bound, NOT an auth or a feature change: it runs BEFORE require_token (a pure
    pre-filter, it never bypasses the token guard), and the ceiling (_MAX_REQUEST_BODY_BYTES,
    128 MiB) sits well above every legitimate request, so no normal path regresses. A MISSING
    / unpar'able Content-Length is NOT rejected here (chunked or odd clients) — it falls
    through to the existing per-field caps. Starlette does NOT read the request body before
    dispatching to this middleware — the body is only consumed when a downstream handler
    awaits it — so returning the 413 BEFORE call_next(request) means FastAPI never buffers/
    JSON-parses the over-ceiling body. (The header check is on the SCOPE only; no body bytes
    are touched.)"""
    @app.middleware("http")
    async def _limit_body_size(request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                declared = int(cl)
            except (TypeError, ValueError):
                declared = -1   # unparsable header -> don't reject; fall through to per-field caps
            if declared > _MAX_REQUEST_BODY_BYTES:
                # Reject WITHOUT awaiting request.body() — the body is never read/buffered.
                return JSONResponse(
                    {"error": "request body too large"}, status_code=413)
        return await call_next(request)

    def require_token(x_drr_token: str = Header(default="")) -> None:
        """DECLARATIVE token guard: reject a state-changing call that doesn't carry our
        session token. Attached to a route via `dependencies=_TOKEN_GUARD` in the route
        decorator, so a new state-changing route is guarded by ONE declaration instead
        of four remembered lines in the handler body.

        Raises _TokenDenied (mapped below to the legacy 403 {"error": "forbidden"}
        response, byte-identical to the old imperative guard) or returns None when
        authorized. Constant-time compare so a bad token can't be probed byte-by-byte."""
        if not x_drr_token or not secrets.compare_digest(x_drr_token, state.token):
            raise _TokenDenied()

    @app.exception_handler(_TokenDenied)
    async def _token_denied_handler(request, exc):  # noqa: ARG001 - starlette signature
        # EXACT parity with the pre-dependency guard: same class (JSONResponse), same
        # body dict, same status — so the serialized bytes ({"error":"forbidden"}),
        # content-type and content-length are identical to before.
        return JSONResponse({"error": "forbidden"}, status_code=403)

    return require_token


def _startup_sweep() -> None:
    """Clear any matter-content OCR rasters a PRIOR run left under the app-data temp dir
    after a hard kill / power-loss (the write→`finally: remove` gap). Best-effort + never
    raises (see paths.sweep_temp) — a sweep failure must not stop the app from starting.
    Shared by both app factories (both run the OCR image-redaction path)."""
    try:
        swept = sweep_temp()
        if swept:
            log.info("startup: swept %d leftover temp raster entr%s",
                     swept, "y" if swept == 1 else "ies")
    except Exception:  # noqa: BLE001 - startup sweep is best-effort; never block boot
        pass


def create_app(state: AppState) -> FastAPI:
    # docs_url/redoc_url/openapi_url are DISABLED: the default Swagger/ReDoc pages load
    # their assets from a CDN — an air-gap violation — and the OpenAPI dump needlessly
    # enumerates the localhost API. Applies to BOTH factories (review finding L-1).
    app = FastAPI(title="Lawbat", docs_url=None, redoc_url=None, openapi_url=None)

    # Shared pre-auth plumbing (413 body ceiling + the session-token guard). See
    # _install_body_limit_and_token — the SAME code the Redactor variant uses.
    require_token = _install_body_limit_and_token(app, state)

    # Clear any leftover OCR rasters from a prior crashed run (best-effort; never blocks boot).
    _startup_sweep()

    # Attach to a route decorator as `dependencies=_TOKEN_GUARD`. INTENTIONALLY
    # UNGUARDED routes (read-only or the token-carrying pages themselves — do NOT
    # add the guard to these without a decision; the served pages are what HAND the
    # token to the UI, and the GETs expose no matter-mutating power):
    #   GET /, /app, /redaction, /reid-risk            (the pages; token injected here)
    #   GET /api/state, /api/about, /api/home          (status / support facts / view-model)
    #   GET /api/index/status                          (progress poll)
    #   GET /api/sources, /api/search, /api/files      (read-only over the open matter)
    #   GET /api/tools/manifest, /api/tools/manifest.csv  (read-only schedule + CSV)
    # NOTE: /api/redaction/health is a DELIBERATELY GUARDED GET (like /api/redaction/sample,
    # in app/redactionroutes.py) — it now spawns the redact-cli process per call, not just a
    # path-exists check, so it must not be an open fork-the-bin surface.
    _TOKEN_GUARD = [Depends(require_token)]

    # The Redaction API surface (/api/redaction/*) lives on the APIRouter built in
    # app/redactionroutes.py; it is included here so the SAME require_token dependency
    # (closing over this session's secret) guards every state-changing redaction route
    # exactly as when they were inline. We FLATTEN the router's routes onto the app rather
    # than app.include_router(): newer Starlette mounts an included router as a single lazy
    # sub-router, which hides its sub-routes from a top-level app.routes walk — and the
    # structural token-guard test (and OpenAPI) introspect app.routes for the require_token
    # dependency. Extending directly registers each route as a top-level APIRoute with its
    # baked-in token guard intact (what include_router did historically), byte-identical.
    app.router.routes.extend(build_redaction_router(require_token).routes)

    def _run_index(job: "IndexJob", folder: str, db_path: str):
        # The worker owns its OWN job object (passed in), so a later /api/index
        # that swaps state.job can't make this thread write to the wrong job or
        # have its cancel flag set on a different run.
        def progress(done, total, current):
            job.done, job.total, job.current = done, total, current

        def should_cancel():
            return job.cancel

        # Log a NON-identifying reference — the matter DB filename stem, which is
        # safe-name + an 8-hex hash of the source path — never the full source
        # folder path. That path is matter-identifying and the operational log is
        # not a matter-scoped, access-controlled store (M-12).
        ref = Path(db_path).stem
        # Snapshot the open generation: if the user explicitly opens/closes a matter
        # while this index runs, open_gen advances and we must NOT clobber their choice
        # when we finish (see the publish guard below).
        with state._lock:
            start_open_gen = state.open_gen
        log.info("index start: matter=%s", ref)
        try:
            # PHASE 1 — estimate (a bounded, no-open pre-walk) to get an accurate
            # progress total AND to surface the skip counts; cancellable. A failure here
            # is non-fatal (estimate is best-effort) — fall back to no precount.
            job.phase = "estimating"
            precount = None
            try:
                est = estimate_folder(folder, should_cancel=should_cancel)
                if isinstance(est.get("files"), int) and est["files"] > 0:
                    precount = est["files"]
            except Exception:  # noqa: BLE001 - the estimate must never break the index
                precount = None
            if should_cancel():
                with state._lock:
                    job.stats = {"cancelled": True}
                    job.status = "done"
                log.info("index cancelled (during estimate): matter=%s", ref)
                return
            # PHASE 2 — index, with the estimate's count as the bar total.
            job.phase = "indexing"
            stats = index_folder(folder, db_path, progress=progress,
                                 should_cancel=should_cancel, precount=precount)
            # Publish the active matter BEFORE marking the job done, so a client
            # that polls 'done' and immediately searches never sees active_db=None.
            # Guard the publish: only if this is STILL the current job (a newer index
            # superseded it otherwise) AND the user hasn't explicitly opened/closed a
            # matter since we started (open_gen unchanged) AND we weren't cancelled —
            # so a deliberate matter-switch during a long index is never overwritten.
            with state._lock:
                if (state.job is job and state.open_gen == start_open_gen
                        and not stats.get("cancelled")):
                    state.active_db = db_path
                    state.active_name = friendly_matter_name(db_path)
                # The stored error is already path-stripped at the source
                # (index._safe_error); the user-facing job error is too.
                job.stats = stats
                job.status = "done"
            log.info("index %s: matter=%s stats=%s",
                     "cancelled" if stats.get("cancelled") else "done", ref, stats)
        except Exception as e:  # noqa: BLE001
            # Surface a path-stripped message (the exception text can embed the
            # full source path / file content); keep the FULL detail out of the
            # operational log too — log a sanitized line, NOT log.exception (whose
            # traceback locals can capture matter content).
            safe = _safe_error(e)
            with state._lock:
                job.error = safe
                job.status = "error"
            log.error("index failed: matter=%s err=%s", ref, safe)

    @app.get("/api/state")
    def api_state():
        with state._lock:
            active_db = state.active_db
            s = {
                "has_matter": active_db is not None,
                "matter_name": state.active_name,
                "fts5": fts5_available(),
                "version": __version__,
                "matters": list_matters(),
                "job": vars(state.job),
            }
        if active_db:
            s["stats"] = corpus_stats(active_db)
            s["source_root"] = matter_source_root(active_db)
            s["sources"] = list_sources(active_db)
        return JSONResponse(s)

    @app.get("/api/about")
    def api_about():
        # Support-facing facts a non-technical user can read out or send: version,
        # where their data + logs live, whether full-text search is working, and
        # whether the redaction engine bin is present (so the redaction page can show
        # an up-front "tool unavailable" banner ON LOAD rather than only after a failed
        # scan). Local-only — nothing here is reported anywhere.
        return JSONResponse({
            "version": __version__,
            "fts5": fts5_available(),
            "redaction_engine": redactionmodel.available(),
            "data_dir": str(data_dir()),
            "log_file": log_file(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        })

    @app.post("/api/index/estimate", dependencies=_TOKEN_GUARD)
    def api_index_estimate(payload: dict = Body(...)):
        # A bounded, NO-OPEN pre-walk so the UI can warn / refuse BEFORE the first
        # (possibly cloud-downloading) read. Token-guarded like /api/index. Runs the
        # estimate inline (the worker pattern is overkill for a bounded, cancel-via-cap
        # walk); refuse-level roots are reported as a structured payload AND a 400.
        folder = (payload or {}).get("folder", "").strip()
        if not folder or not Path(folder).is_dir():
            return JSONResponse({"error": "not a folder"}, status_code=400)
        level, reason = scan_guard.classify_root(folder)
        if level == "refuse":
            # 400 with the structured reason so the page can both block + explain.
            return JSONResponse(
                {"level": "refuse", "reason": reason, "error": reason}, status_code=400)
        try:
            est = estimate_folder(folder)
        except Exception as e:  # noqa: BLE001 - never crash; surface a clean error
            return JSONResponse({"error": _safe_error(e)}, status_code=500)
        # Compose the warn/ok level: classify_root may say "warn", and the size caps may
        # ALSO push an "ok" root to a soft warning (a very large room).
        reasons = []
        if reason:
            reasons.append(reason)
        if est.get("files", 0) >= scan_guard.FILE_COUNT_HARD or est.get("too_large", 0):
            level = "warn" if level != "refuse" else level
        if est.get("files", 0) >= scan_guard.FILE_COUNT_WARN:
            reasons.append(f"This folder has {est['files']:,}+ files.")
            if level == "ok":
                level = "warn"
        if est.get("bytes", 0) >= scan_guard.TOTAL_BYTES_WARN:
            reasons.append("This folder is very large to index.")
            if level == "ok":
                level = "warn"
        if est.get("offline", 0):
            reasons.append(
                f"{est['offline']:,} online-only file(s) will be SKIPPED "
                "(reading them would download from the cloud).")
        if est.get("denied_dirs", 0):
            reasons.append(f"{est['denied_dirs']:,} folder(s) could not be read.")
        if est.get("capped"):
            reasons.append("The folder is too big to fully measure — counts are a minimum.")
        return JSONResponse({
            "level": level,
            "files": est.get("files", 0),
            "bytes": est.get("bytes", 0),
            "max_depth": est.get("max_depth", 0),
            "offline": est.get("offline", 0),
            "too_large": est.get("too_large", 0),
            "denied_dirs": est.get("denied_dirs", 0),
            "capped": est.get("capped", False),
            "reasons": reasons,
        })

    @app.post("/api/index", dependencies=_TOKEN_GUARD)
    def api_index(payload: dict = Body(...)):
        folder = (payload or {}).get("folder", "").strip()
        if not folder or not Path(folder).is_dir():
            return JSONResponse({"error": "not a folder"}, status_code=400)
        # SERVER-SIDE ingestion gate — the load-bearing guarantee (never trust a client
        # flag; mirrors _reject_source_tree's "enforced in code" philosophy). Re-run the
        # root classification here:
        #   refuse -> HARD block regardless of any confirm flag (a drive / OS / app-data
        #             root is never a data room; scanning one is the worst case).
        #   warn   -> require an explicit confirm:true so a blind POST can't bypass the
        #             "this is a whole drive / your profile / a network share" gate.
        level, reason = scan_guard.classify_root(folder)
        if level == "refuse":
            return JSONResponse(
                {"error": reason, "level": "refuse", "reason": reason}, status_code=400)
        if level == "warn" and not bool((payload or {}).get("confirm", False)):
            return JSONResponse(
                {"error": reason, "level": "warn", "reason": reason,
                 "needs_confirm": True}, status_code=409)
        db_path = str(db_path_for(folder))
        with state._lock:
            if state.job.status == "running":
                return JSONResponse({"error": "already indexing"}, status_code=409)
            job = IndexJob(status="running", phase="estimating", folder=folder)
            state.job = job
        t = threading.Thread(target=_run_index, args=(job, folder, db_path), daemon=True)
        t.start()
        return JSONResponse({"ok": True})

    @app.get("/api/index/status")
    def api_index_status():
        with state._lock:
            return JSONResponse(vars(state.job))

    @app.post("/api/index/cancel", dependencies=_TOKEN_GUARD)
    def api_index_cancel():
        with state._lock:
            state.job.cancel = True
        return JSONResponse({"ok": True})

    # ---- Multi-source ingestion: add / list / remove sources for the open matter ----
    # An ADDED source brings files/folders from OTHER locations into the open matter's
    # document schedule. Identity is unchanged (the matter .db stays keyed on the
    # PRIMARY root); an added source is matter DATA, not a new matter. Adding a source
    # MUST extend the read-only-source set (see _reject_source_tree / _matter_file,
    # both generalized to ALL roots) — the gating safety piece.
    def _active_db():
        with state._lock:
            return state.active_db

    def _run_add_source(job: "IndexJob", db_path: str, target, kind: str,
                        label: str | None):
        # Mirror _run_index: the add-source walk/hash/extract runs HERE, in a worker
        # thread, WITHOUT holding state._lock for the duration (the lock is taken only
        # to publish progress/status). The primary index does exactly this; doing the
        # walk under the lock would freeze /api/state, /api/search, /api/close and the
        # status poll for the whole add. SQLite WAL handles the DB concurrency.
        def progress(done, total, current):
            job.done, job.total, job.current = done, total, current

        def should_cancel():
            return job.cancel

        ref = Path(db_path).stem
        log.info("add-source start: matter=%s kind=%s", ref, kind)
        job.phase = "indexing"
        try:
            res = add_source(db_path, target, kind, label=label,
                             should_cancel=should_cancel, progress=progress)
            with state._lock:
                if "error" in res:
                    # add_source's errors are already path-stripped (bad target / refuse
                    # root); surface as a job error so the UI shows it.
                    job.error = res["error"]
                    job.status = "error"
                else:
                    job.stats = res
                    job.status = "done"
            log.info("add-source %s: matter=%s",
                     "error" if "error" in res else "done", ref)
        except Exception as e:  # noqa: BLE001
            # A path-stripped message (the exception text can embed source paths /
            # content); keep the full detail out of the operational log too.
            safe = _safe_error(e)
            with state._lock:
                job.error = safe
                job.status = "error"
            log.error("add-source failed: matter=%s err=%s", ref, safe)

    @app.post("/api/sources/add", dependencies=_TOKEN_GUARD)
    def api_sources_add(payload: dict = Body(...)):
        db = _active_db()
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        root = (payload or {}).get("root", "")
        if not isinstance(root, str) or not root.strip() or not Path(root).is_dir():
            return JSONResponse({"error": "not a folder"}, status_code=400)
        # SERVER-SIDE ingestion gate — identical philosophy to /api/index: never trust
        # a client flag. refuse -> HARD block; warn -> require confirm:true.
        level, reason = scan_guard.classify_root(root)
        if level == "refuse":
            return JSONResponse(
                {"error": reason, "level": "refuse", "reason": reason}, status_code=400)
        if level == "warn" and not bool((payload or {}).get("confirm", False)):
            return JSONResponse(
                {"error": reason, "level": "warn", "reason": reason,
                 "needs_confirm": True}, status_code=409)
        label = (payload or {}).get("label")
        if label is not None and not isinstance(label, str):
            label = None
        # Run the walk in a BACKGROUND thread (mirrors /api/index) so the lock is NOT
        # held across the walk/hash/extract — /api/state, /api/search, /api/close and
        # status polling stay responsive. The UI polls /api/index/status (shared job).
        with state._lock:
            if state.job.status == "running":
                return JSONResponse({"error": "already indexing"}, status_code=409)
            job = IndexJob(status="running", phase="indexing", folder=root)
            state.job = job
        t = threading.Thread(target=_run_add_source,
                             args=(job, db, root, "folder", label), daemon=True)
        t.start()
        return JSONResponse({"ok": True})

    @app.post("/api/sources/add-files", dependencies=_TOKEN_GUARD)
    def api_sources_add_files(payload: dict = Body(...)):
        db = _active_db()
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        files = (payload or {}).get("files", [])
        if not isinstance(files, list) or not files:
            return JSONResponse({"error": "no files chosen"}, status_code=400)
        # Bound the count + coerce to strings; a picked-file set is a single document
        # batch, not a bulk import (the folder path is for that).
        if len(files) > 10000:
            return JSONResponse({"error": "too many files in one batch"}, status_code=400)
        paths = [f for f in files if isinstance(f, str) and f.strip()]
        if not paths:
            return JSONResponse({"error": "no valid files chosen"}, status_code=400)
        label = (payload or {}).get("label")
        if label is not None and not isinstance(label, str):
            label = None
        # Background the walk the SAME way as /api/sources/add (lock not held across it).
        with state._lock:
            if state.job.status == "running":
                return JSONResponse({"error": "already indexing"}, status_code=409)
            job = IndexJob(status="running", phase="indexing", folder="(files)")
            state.job = job
        t = threading.Thread(target=_run_add_source,
                             args=(job, db, paths, "files", label), daemon=True)
        t.start()
        return JSONResponse({"ok": True})

    @app.get("/api/sources")
    def api_sources():
        db = _active_db()
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        return JSONResponse({"sources": list_sources(db)})

    @app.post("/api/sources/remove", dependencies=_TOKEN_GUARD)
    def api_sources_remove(payload: dict = Body(...)):
        db = _active_db()   # snapshot the open matter's db path ONCE, under the lock
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        sid = (payload or {}).get("id")
        # M-5: run the SQLite delete/commit OUTSIDE state._lock. remove_source opens its
        # OWN connection (closing()) and touches NO in-memory AppState — holding the lock
        # across a large multi-source delete would needlessly block every reader (search /
        # files / open) for the commit's duration. The db path is already captured above,
        # so there is no torn-state race: a concurrent /api/close only nulls state.active_db
        # (it does not delete the db file), and remove_source operates purely on the path.
        res = remove_source(db, sid)
        if "error" in res:
            return JSONResponse(res, status_code=400)
        return JSONResponse({"ok": True, "deleted": res.get("deleted", 0),
                             "sources": list_sources(db)})

    @app.post("/api/open", dependencies=_TOKEN_GUARD)
    def api_open(payload: dict = Body(...)):
        db = (payload or {}).get("db", "")
        if not Path(db).is_file() or Path(db).parent.resolve() != matters_dir().resolve():
            return JSONResponse({"error": "no such matter"}, status_code=400)
        with state._lock:
            state.active_db = db
            state.active_name = friendly_matter_name(db)
            state.open_gen += 1   # explicit user switch — a finishing index must not clobber it
        return JSONResponse({"ok": True})

    @app.post("/api/close", dependencies=_TOKEN_GUARD)
    def api_close():
        with state._lock:
            state.active_db = None
            state.active_name = None
            state.open_gen += 1   # explicit user close — a finishing index must not re-open it
        return JSONResponse({"ok": True})

    @app.get("/api/search")
    def api_search(q: str = Query(...), limit: int = 50):
        # Snapshot active_db ONCE under the lock (C4). A concurrent /api/close can
        # null state.active_db between a check and a re-read; binding a local here
        # means run_search() never gets passed None mid-request.
        with state._lock:
            db = state.active_db
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        limit = _clamp(limit, 1, _SEARCH_LIMIT_MAX, 50)
        try:
            return JSONResponse({"results": run_search(db, q, limit)})
        except Exception as e:  # malformed FTS query
            return JSONResponse({"error": html.escape(str(e))}, status_code=400)

    @app.get("/api/files")
    def api_files(category: str = Query(...), limit: int = 1000):
        with state._lock:                 # snapshot once (C4 — same race as search)
            db = state.active_db
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        limit = _clamp(limit, 1, _FILES_LIMIT_MAX, 1000)
        files = list_files(db, category, limit)
        if files is None:
            return JSONResponse({"error": "unknown category"}, status_code=400)
        return JSONResponse({"files": files, "count": len(files)})

    # ---- Open / reveal a document --------------------------------------------
    # Confinement basis = the indexed `files` table (auditable + deterministic),
    # NOT a textual prefix of source_root. The requested path must match a file we
    # actually indexed (case-insensitively, to match Windows). This closes the
    # symlink/junction and post-index-drop holes a prefix test would allow.
    #   ("ok", stored)     indexed and still on disk
    #   ("moved", stored)  indexed but gone now (moved/renamed/deleted)
    #   ("outside", None)  not part of this matter
    def _matter_file(req_path: str):
        # Snapshot active_db ONCE under the lock (C4): a concurrent /api/close
        # nulling it between the guard, the connect(), and the source-root read
        # would otherwise hand connect()/matter_source_root() a None.
        with state._lock:
            db = state.active_db
        if not db or not req_path:
            return ("outside", None)
        want = norm_path(req_path)
        with closing(connect(db)) as con:
            row = con.execute("SELECT path FROM files WHERE path = ?", (req_path,)).fetchone()
            stored = row["path"] if row else None
            if stored is None:
                # Case/separator-insensitive fallback (Windows). Indexed (idx_files_norm) so
                # this is an O(log N) lookup, not the full O(N) Python table scan it once was;
                # norm_path is populated at index time and backfilled on open for legacy DBs.
                r = con.execute(
                    "SELECT path FROM files WHERE norm_path = ? LIMIT 1", (want,)).fetchone()
                stored = r["path"] if r else None
        if stored is None:
            return ("outside", None)
        # Symlink/junction escape guard: even if indexed, the file must really
        # resolve under ONE OF the matter's source roots (multi-source ingestion —
        # a file legitimately belongs to the matter if it lives under the primary
        # OR any added source). With no recorded roots we can't make a positive
        # confinement assertion, so we skip the escape check (the files-table
        # membership above is the floor); when roots ARE recorded, the file must
        # resolve under at least one of them or it's treated as outside.
        roots = matter_source_roots(db)
        if roots and Path(stored).exists():
            try:
                resolved = Path(stored).resolve()
            except (OSError, ValueError):
                return ("outside", None)
            inside_any = False
            for root in roots:
                try:
                    if _is_within(resolved, Path(root).resolve()):
                        inside_any = True
                        break
                except (OSError, ValueError):
                    continue
            if not inside_any:
                return ("outside", None)
        return ("ok" if Path(stored).is_file() else "moved", stored)

    def _file_action(payload, action):
        status, stored = _matter_file((payload or {}).get("path", ""))
        if status == "outside":
            return JSONResponse({"error": "That file is not part of this matter."}, status_code=400)
        if status == "moved":
            return JSONResponse(
                {"error": "File moved or deleted since indexing — re-index to refresh."},
                status_code=409)
        try:
            action(stored)
            return JSONResponse({"ok": True})
        except Exception as e:  # noqa: BLE001
            # _safe_error strips path-like / quoted / extension-bearing runs (#12): the
            # raw exception text can embed the matter file's full path, which must never
            # reach the browser response.
            return JSONResponse({"error": _safe_error(e)}, status_code=500)

    @app.post("/api/file/open", dependencies=_TOKEN_GUARD)
    def api_file_open(payload: dict = Body(...)):
        return _file_action(payload, open_path)

    @app.post("/api/file/reveal", dependencies=_TOKEN_GUARD)
    def api_file_reveal(payload: dict = Body(...)):
        return _file_action(payload, reveal_in_folder)

    # ---- Tools: one-click file automations (preview-first, reversible) ----
    def _reject_source_tree(folder: str):
        """Refuse to rename inside (or above) ANY of the open matter's indexed
        source trees — the read-only-source invariant must be enforced by code,
        not just a UI warning. Returns an error JSONResponse, or None if OK.

        SAFETY-CRITICAL multi-source generalization: a matter now has N source
        roots (the primary + every added source). The rename target must be
        refused if it is inside OR above ANY one of them — shipping multi-source
        without this would leave added sources writable (a Critical read-only-source
        violation). We iterate EVERY root and refuse on the first overlap."""
        with state._lock:                 # snapshot once (C4 — same race as search)
            db = state.active_db
        if not db:
            return None
        roots = matter_source_roots(db)
        if not roots:
            return None
        try:
            target = Path(folder).resolve()
        except (OSError, ValueError):
            # An unresolvable target can't be proven OUTSIDE every source -> refuse.
            return JSONResponse(
                {"error": "Refusing to rename: the chosen folder could not be "
                          "resolved."},
                status_code=400)
        for root in roots:
            try:
                src = Path(root).resolve()
            except (OSError, ValueError):
                # An UNRESOLVABLE source root must NOT be silently dropped from the
                # check (that would leave it writable — an asymmetry vs the target,
                # which fails closed above). Stay fail-closed: compare the raw,
                # normcased path strings of target-vs-source so an overlap is still
                # caught even when resolve() can't run on this root.
                try:
                    raw_target = os.path.normcase(os.path.normpath(folder))
                    raw_src = os.path.normcase(os.path.normpath(root))
                except (OSError, ValueError, TypeError):
                    # Cannot even normalize the strings -> can't prove OUTSIDE -> refuse.
                    return JSONResponse(
                        {"error": "Refusing to rename: a source folder could not be "
                                  "resolved for the read-only check."},
                        status_code=400)
                if (raw_target == raw_src
                        or raw_target.startswith(raw_src + os.sep)
                        or raw_src.startswith(raw_target + os.sep)):
                    return JSONResponse(
                        {"error": "Refusing to rename inside the indexed data room "
                                  "(it is read-only). Point the tool at a working copy."},
                        status_code=400)
                continue
            # Refuse if the target is inside a source (writing into the room) OR a
            # source is inside the target (renaming a parent that contains the room).
            if _is_within(target, src) or _is_within(src, target):
                return JSONResponse(
                    {"error": "Refusing to rename inside the indexed data room "
                              "(it is read-only). Point the tool at a working copy."},
                    status_code=400)
        return None

    def _build_rules(raw):
        """Build RenameRules from an untrusted dict. Unknown keys are a client
        error (400), not an unhandled TypeError (500): RenameRules(**{bad: ...})
        would otherwise raise out of the handler as a 500. Field types/ranges are
        clamped in RenameRules.__post_init__."""
        if not isinstance(raw, dict):
            return None, JSONResponse({"error": "rules must be an object"}, status_code=400)
        allowed = set(RenameRules.__dataclass_fields__)
        unknown = set(raw) - allowed
        if unknown:
            return None, JSONResponse(
                {"error": f"unknown rule field(s): {', '.join(sorted(unknown))}"},
                status_code=400)
        try:
            return RenameRules(**raw), None
        except (TypeError, ValueError) as e:
            return None, JSONResponse({"error": f"invalid rules: {e}"}, status_code=400)

    def _plan_token(plan) -> str:
        """HMAC over the EXECUTABLE content of a plan (C3 — apply TOCTOU).

        /apply re-derives the plan fresh, so a file added/removed between preview
        and apply silently changes what runs. Preview returns this token; apply
        recomputes the plan, recomputes the token, and aborts on a mismatch — so
        apply can only execute the exact set the user previewed.

        Bound to the per-session secret (state.token) so the token can't be forged
        offline, and computed over the items apply_plan actually acts on (the
        'rename'-status (src, dst) pairs) — collisions/unchanged don't move a file,
        so they don't belong in the integrity check."""
        renames = [(it.src, it.dst) for it in plan.items if it.status == "rename"]
        canon = json.dumps(renames, ensure_ascii=False, sort_keys=False,
                           separators=(",", ":")).encode("utf-8")
        return hmac.new(state.token.encode("utf-8"), canon, hashlib.sha256).hexdigest()

    @app.post("/api/tools/rename/plan", dependencies=_TOKEN_GUARD)
    def api_rename_plan(payload: dict = Body(...)):
        # Token-guard the PLAN endpoint too (#21), matching /apply + /undo. Plan reads a
        # caller-supplied folder, runs the confinement check, and returns file listings +
        # a plan_token; leaving it unauthenticated let any local process enumerate folders
        # and obtain a valid plan_token without the per-session secret.
        folder = (payload or {}).get("folder", "")
        recursive = bool((payload or {}).get("recursive", False))
        rules, bad = _build_rules((payload or {}).get("rules", {}))
        if bad:
            return bad
        blocked = _reject_source_tree(folder)
        if blocked:
            return blocked
        try:
            plan = plan_rename(folder, rules, recursive)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return JSONResponse({
            "summary": plan.summary(),
            "items": [vars(it) for it in plan.items[:1000]],
            "truncated": len(plan.items) > 1000,
            # Binds a subsequent /apply to THIS plan (C3). The page echoes it back.
            "plan_token": _plan_token(plan),
        })

    @app.post("/api/tools/rename/apply", dependencies=_TOKEN_GUARD)
    def api_rename_apply(payload: dict = Body(...)):
        folder = (payload or {}).get("folder", "")
        recursive = bool((payload or {}).get("recursive", False))
        rules, bad = _build_rules((payload or {}).get("rules", {}))
        if bad:
            return bad
        blocked = _reject_source_tree(folder)
        if blocked:
            return blocked
        # C3: apply must run the plan the user PREVIEWED, not a freshly re-derived
        # one. Require the preview's plan_token; recompute the plan and abort if the
        # executable set changed under us (a file added/removed in the gap).
        supplied = (payload or {}).get("plan_token", "")
        if not isinstance(supplied, str) or not supplied:
            return JSONResponse(
                {"error": "missing plan token — preview again before applying"},
                status_code=400)
        try:
            plan = plan_rename(folder, rules, recursive)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        if not hmac.compare_digest(supplied, _plan_token(plan)):
            return JSONResponse(
                {"error": "The folder changed since your preview. Preview again to "
                          "see the updated plan before applying."},
                status_code=409)
        return JSONResponse(apply_plan(plan))

    @app.post("/api/tools/rename/undo", dependencies=_TOKEN_GUARD)
    def api_rename_undo(payload: dict = Body(...)):
        manifest = (payload or {}).get("manifest", "")
        # Only undo manifests we wrote, in our own undo dir — never an arbitrary
        # .json a caller points us at (which could drive arbitrary renames).
        mp = Path(manifest).resolve()
        if not mp.is_file() or not _is_within(mp, undo_dir().resolve()):
            return JSONResponse({"error": "no such manifest"}, status_code=400)
        return JSONResponse(undo(str(mp)))

    # ---- Tools: document index / manifest (read-only over the open matter) --
    @app.get("/api/tools/manifest")
    def api_manifest(order: str = Query(default="")):
        with state._lock:                 # snapshot once (C4 — same race as search)
            db = state.active_db
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        # normalize_order is the allowlist: any unknown value falls back to the
        # default, so a bad query param renders the default sort, never a 500.
        order = normalize_order(order)
        data = build_manifest(db, order=order)
        return JSONResponse({
            "summary": data["summary"],
            "rows": data["rows"][:1000],
            "truncated": len(data["rows"]) > 1000,
            "order": order,
        })

    @app.post("/api/tools/manifest/export", dependencies=_TOKEN_GUARD)
    def api_manifest_export(order: str = Query(default="")):
        with state._lock:                 # snapshot once (C4 — same race as search)
            db = state.active_db
            name = state.active_name or "matter"
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        return JSONResponse(export_manifest(db, name, order=normalize_order(order)))

    @app.get("/api/tools/manifest.csv")
    def api_manifest_csv(order: str = Query(default="")):
        with state._lock:                 # snapshot once (C4 — same race as search)
            db = state.active_db
            name = state.active_name or "matter"
        if not db:
            return JSONResponse({"error": "no matter open"}, status_code=400)
        from fastapi.responses import Response
        csv_text = manifest_csv(db, order=normalize_order(order))
        fname = f"index_{name}.csv"
        return Response(
            content="﻿" + csv_text,  # BOM for Excel
            media_type="text/csv",
            # RFC 5987/6266-safe: a matter name with `"` / `&` / non-ASCII can't break
            # the header (H-3). See _content_disposition.
            headers={"Content-Disposition": _content_disposition(fname)},
        )

    @app.get("/api/home")
    def api_home():
        # The typed firmOS HOME view-model (the firmos.view/0 contract) the page
        # fetches + renders. Sourced from the Rust `viewgen` bin when present, else a
        # bundled sample marked preview:true (app/viewmodel.py). NEVER raises — a
        # missing bin can't break the landing page.
        return JSONResponse(get_home_view())

    @app.get("/", response_class=HTMLResponse)
    def home():
        # firmOS HOME is the LANDING page. Inject the per-session token (url-safe
        # base64, no HTML-special chars, escaped defensively) into the assembled,
        # self-contained Home document.
        return HTMLResponse(HOME_PAGE.replace("__DRR_TOKEN__", html.escape(state.token)))

    @app.get("/app", response_class=HTMLResponse)
    def dataroom():
        # The data-room search + Tools, now a MODULE reached FROM the Home (the
        # launcher / "open data room" links point here). Same self-contained page +
        # token as before — only the path moved off the landing slot.
        return HTMLResponse(PAGE.replace("__DRR_TOKEN__", html.escape(state.token)))

    # ---- Re-identification RISK estimator (NEW add-on; SEPARATE from redaction) ----
    # A self-contained tool reached from the Home launcher: paste/upload a document (or a
    # SET of them) -> the estimator extracts quasi-identifiers, prices them against bundled
    # population marginal tables, and reports a k-VALUE ESTIMATE (an OPTIMISTIC lower bound on
    # uniqueness — never a safety verdict; see app/reidrisk.py). Pure-Python, deterministic,
    # air-gapped; it NEVER touches the redaction carrier. The text never leaves this process.
    @app.get("/reid-risk", response_class=HTMLResponse)
    def reidrisk_page():
        return HTMLResponse(REIDRISK_PAGE.replace("__DRR_TOKEN__", html.escape(state.token)))

    # ---- Redaction review (module #1 — the two-tier review UI) ----------------
    # A self-contained text tool reached from the Home launcher: paste text -> SCAN
    # (deterministic Rust engine via the redact-cli bin) -> review by confidence tier
    # (quick-confirm vs careful) -> APPLY (redact only accepted spans). The text travels
    # only the local pipe to the bin (air-gapped); we never persist or log it here.
    @app.get("/redaction", response_class=HTMLResponse)
    def redaction_page():
        return HTMLResponse(REDACTION_PAGE.replace("__DRR_TOKEN__", html.escape(state.token)))

    # The redaction API routes (/api/redaction/{sample,scan,scan-file,pdf-scan,pdf-preview,
    # pdf-apply,pdf-ocr-apply,pdf-ocr-scan,pdf-ocr-apply-selection,apply,text-export} + the
    # health probe) are defined on the APIRouter built in app/redactionroutes.py and included
    # above via app.include_router(build_redaction_router(require_token)).

    # ---- Re-identification RISK estimator endpoints (NEW; SEPARATE from redaction) ----
    # These call ONLY app/reidrisk.py (pure-Python, deterministic, no bin) — the estimator
    # never touches the redaction carrier. Best-effort: a malformed request returns a clean
    # 400, an internal hiccup returns a structured error, never an unhandled 500/stack.
    def _reid_extract_text(filename: str, data_b64: str) -> tuple[str | None, str | None]:
        """Decode an uploaded file (base64) and extract its text via the SHARED Python
        extractors (app/extractors.py). Returns (text, None) or (None, error). The bytes are
        written to a short-lived temp file under the app-data temp dir (the extractors take a
        path), then deleted; nothing is written to the source tree and no cleartext is logged.
        A plain-text/unknown extension falls back to a UTF-8 decode. Never raises."""
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            return None, "file data is not valid base64"
        from .extractors import extract as _extract
        import tempfile
        base = os.path.basename(str(filename).replace("\\", "/")) or "upload"
        suffix = Path(base).suffix
        tmpdir = data_dir() / "tmp"
        try:
            tmpdir.mkdir(parents=True, exist_ok=True)
        except OSError:
            tmpdir = None
        try:
            fd, tmppath = tempfile.mkstemp(suffix=suffix, dir=str(tmpdir) if tmpdir else None)
        except OSError:
            return None, "could not stage the uploaded file"
        try:
            # os.fdopen takes OWNERSHIP of fd on success (the `with` then closes it). But if
            # fdopen itself raises (rare, e.g. OOM/EMFILE), fd is NOT yet owned and would LEAK —
            # the `finally` below only removes the path. Close it explicitly on that failure.
            try:
                fh = os.fdopen(fd, "wb")
            except OSError:
                try:
                    os.close(fd)
                except OSError:
                    pass
                return None, "could not stage the uploaded file"
            with fh:
                fh.write(raw)
            status, units, _err = _extract(Path(tmppath))
            if status in ("ok", "truncated") and units:
                # 'truncated' still extracted real text up to the cap (a trailing marker
                # unit explains it) — treat it like 'ok' so a large office file isn't
                # mis-routed to the raw-ZIP-bytes decode below (which would yield garbage).
                return "\n".join(str(u) for u in units), None
            # Unsupported/empty: fall back to a best-effort UTF-8 decode (e.g. .csv/.json/.log).
            text = raw.decode("utf-8", "ignore")
            if text.strip():
                return text, None
            return "", None
        except Exception:  # noqa: BLE001 - extraction is best-effort; surface a clean error
            return None, "could not extract text from the uploaded file"
        finally:
            try:
                os.remove(tmppath)
            except OSError:
                pass

    def _utf8_len(text: str) -> int:
        """UTF-8 byte length that NEVER raises on a lone surrogate (#8). A str carrying a
        half/whole surrogate (e.g. from a latin-1/surrogateescape decode upstream) would
        make a plain `text.encode('utf-8')` raise UnicodeEncodeError; the reidrisk path
        must degrade, not 500. `surrogatepass` measures it; an even-more-pathological case
        falls back to a total `'ignore'` encode."""
        try:
            return len(text.encode("utf-8", "surrogatepass"))
        except (UnicodeError, ValueError):
            return len(text.encode("utf-8", "ignore"))

    def _reid_resolve_text(payload) -> tuple[str | None, JSONResponse | None]:
        """Resolve a request to its document text: either pasted `text` (size-capped) or an
        uploaded `filename` + `data_b64` (extracted via the shared extractors). Returns
        (text, None) or (None, error_response)."""
        body = payload or {}
        data_b64 = body.get("data_b64", "")
        if isinstance(data_b64, str) and data_b64:
            if len(data_b64) > _REDACT_FILE_B64_MAX:
                return None, JSONResponse(
                    {"error": "file is too large to assess here"}, status_code=400)
            filename = body.get("filename", "upload")
            text, err = _reid_extract_text(filename if isinstance(filename, str) else "upload",
                                           data_b64)
            if err:
                return None, JSONResponse({"error": err}, status_code=400)
            text = text or ""
            # Enforce the SAME text-size cap on EXTRACTED text as on pasted text: a ~10 MB upload
            # can extract to far more text than the base64 cap implies, and the paste path is
            # already capped — leaving the upload path uncapped would let a file bypass the bound
            # (and a batch of 200 such files compound it). Cap on the EXTRACTED bytes, not the
            # base64, so the limit is consistent across paste/upload (#4).
            if _utf8_len(text) > _REDACT_TEXT_MAX:
                return None, JSONResponse(
                    {"error": f"extracted text exceeds the {_REDACT_TEXT_MAX}-byte limit"},
                    status_code=400)
            return text, None
        text = body.get("text", "")
        if not isinstance(text, str):
            return None, JSONResponse({"error": "text must be a string"}, status_code=400)
        if _utf8_len(text) > _REDACT_TEXT_MAX:
            return None, JSONResponse(
                {"error": f"text exceeds the {_REDACT_TEXT_MAX}-byte limit"}, status_code=400)
        return text, None

    def _reid_jurisdiction(payload):
        """An OPTIONAL jurisdiction hint (SG/US), allowlisted; anything else -> None (the
        estimator infers it from which reference tables a QI matched)."""
        j = (payload or {}).get("jurisdiction")
        return j if j in ("SG", "US") else None

    @app.post("/api/reidrisk/score", dependencies=_TOKEN_GUARD)
    def api_reidrisk_score(payload: dict = Body(...)):
        """Single document -> k-value ESTIMATE. Accepts pasted `text` or an uploaded file
        (`filename` + `data_b64`). Returns the reidrisk.score_text dict (the estimate + the
        honesty spine flags + coverage). Best-effort: never 500s the page."""
        text, err = _reid_resolve_text(payload)
        if err:
            return err
        try:
            result = reidrisk.score_text(text, _reid_jurisdiction(payload))
        except Exception:  # noqa: BLE001 - the estimator should never raise; degrade cleanly
            return JSONResponse(
                {"error": "the re-identification estimator could not run"}, status_code=500)
        return JSONResponse(result)

    @app.post("/api/reidrisk/batch", dependencies=_TOKEN_GUARD)
    def api_reidrisk_batch(payload: dict = Body(...)):
        """A SET of documents -> a cross-doc release-risk report (in-memory linkage only).

        `docs` is a list of items, each either a string (the text) or an object
        `{filename, data_b64}` (uploaded, extracted) or `{text}`. `link_terms` is an optional
        list of user-supplied exact link keys (names/identifiers). Count-capped; each doc's
        text is bounded by the estimator. Best-effort, never 500s."""
        body = payload or {}
        raw_docs = body.get("docs")
        if not isinstance(raw_docs, list):
            return JSONResponse({"error": "docs must be a list"}, status_code=400)
        if len(raw_docs) > _REID_BATCH_DOCS_MAX:
            return JSONResponse(
                {"error": f"too many documents (max {_REID_BATCH_DOCS_MAX})"}, status_code=400)
        # PRE-DECODE aggregate base64 bound (#20): sum len(data_b64) across the UPLOADED docs
        # and reject an over-cap batch BEFORE base64-decoding ANY of them — the per-doc /
        # per-extracted-text caps only bite AFTER each upload is decoded + extracted, so without
        # this a batch of many ~14 MB-base64 uploads could buffer gigabytes of base64 (even
        # within the global body ceiling). Cheap (a len() per item, no decode); rejects with a
        # clean 413, never a 500/OOM. String/`text` items carry no base64 and don't count here
        # (they're bounded by the per-doc + aggregate TEXT caps in the loop below).
        b64_total = 0
        for item in raw_docs:
            if isinstance(item, dict):
                db = item.get("data_b64")
                if isinstance(db, str):
                    b64_total += len(db)
        if b64_total > _REID_BATCH_B64_TOTAL_MAX:
            return JSONResponse(
                {"error": "the batch's uploaded files exceed the size limit"}, status_code=413)
        docs: list = []
        total_bytes = 0
        for i, item in enumerate(raw_docs):
            doc_id = f"doc-{i + 1}"
            if isinstance(item, str):
                text, err = item, None
                if _utf8_len(text) > _REDACT_TEXT_MAX:
                    return JSONResponse(
                        {"error": f"document {i + 1} exceeds the size limit"}, status_code=400)
            elif isinstance(item, dict):
                if isinstance(item.get("name"), str) and item["name"].strip():
                    doc_id = item["name"].strip()[:120]
                # _reid_resolve_text caps BOTH the pasted and the extracted-upload text at
                # _REDACT_TEXT_MAX (see #4), so each doc is individually bounded here too.
                text, err = _reid_resolve_text(item)
                if err:
                    return err
            else:
                return JSONResponse(
                    {"error": f"document {i + 1} must be a string or object"}, status_code=400)
            text = text or ""
            # Aggregate bound: refuse a batch whose TOTAL accepted text exceeds the cap, even if
            # every individual doc is within the per-doc limit (200 × per-doc would be huge) (#4).
            total_bytes += _utf8_len(text)
            if total_bytes > _REID_BATCH_TOTAL_BYTES_MAX:
                return JSONResponse(
                    {"error": "the batch's total text exceeds the size limit"}, status_code=400)
            docs.append((doc_id, text))
        raw_terms = body.get("link_terms")
        link_terms = ()
        if isinstance(raw_terms, list):
            link_terms = tuple(
                t for t in raw_terms if isinstance(t, str) and t.strip())[:_REID_LINK_TERMS_MAX]
        try:
            result = reidrisk.assess_release_dict(
                docs, link_terms=link_terms, jurisdiction=_reid_jurisdiction(payload))
        except Exception:  # noqa: BLE001 - never 500 the page on an estimator hiccup
            return JSONResponse(
                {"error": "the re-identification estimator could not run"}, status_code=500)
        return JSONResponse(result)

    _install_document_workspace(app, state)
    return app


def _install_document_workspace(app, state):
    page = _build_page("document-workspace.html", [
        ("/* __BASE_JS__ */", "base.js"),
        ("/* __RELEASE_JS__ */", "redaction.release.js"),
        ("/* __WORKSPACE_JS__ */", "document-workspace.js"),
    ], label="document workspace", guard=_airgap_strict)

    @app.get("/workspace", response_class=HTMLResponse)
    def workspace():
        return HTMLResponse(page.replace("__DRR_TOKEN__", html.escape(state.token)))


# ------------------------------------------------------ redactor variant ----
def create_redactor_app(state: AppState) -> FastAPI:
    """The standalone **Redactor** product: the redaction reviewer as the WHOLE app.

    A sector-agnostic sibling of create_app that shares this codebase (a MODE, not a fork).
    It serves ONLY the redaction surface — the same assembled REDACTION_PAGE at GET / (base.js
    + the split fragments, strict air-gap guard) plus the /api/redaction/* router (reused
    verbatim from build_redaction_router) — and deliberately exposes NO Home, NO /app data
    room, and NONE of the index / sources / tools / reid-risk routes. It reuses the SAME
    pre-auth plumbing as create_app via _install_body_limit_and_token (the 128 MiB body
    ceiling + the per-session token guard, byte-for-byte identical 403 rejection), so the
    redaction POSTs stay token-guarded exactly as in Lawbat and the structural guard test
    covers this factory too.

    The redaction page's JS only ever calls /api/redaction/* (verified), so no /api/state or
    /api/about shim is needed; the desktop launcher (desktop/redactor.py) polls GET / for
    readiness. NOTE: the shared page carries a "← Home" link to "/"; in the Redactor "/" IS
    this page, so that link simply reloads the reviewer (harmless — the page is byte-identical
    to Lawbat's, which the 100%-unchanged invariant requires)."""
    app = FastAPI(title="Redactor", docs_url=None, redoc_url=None, openapi_url=None)  # same air-gap hardening as create_app (L-1)

    # Same shared pre-auth plumbing create_app uses (413 ceiling + token guard).
    require_token = _install_body_limit_and_token(app, state)

    # Clear any leftover OCR rasters from a prior crashed run (the Redactor runs the same
    # scanned-PDF OCR burn path, so the same crash-safety sweep applies).
    _startup_sweep()

    # The Redaction API surface (/api/redaction/*), flattened onto the app the SAME way
    # create_app does (see that call site for why we extend rather than include_router):
    # each route keeps its baked-in require_token guard, visible to the route-table walk.
    app.router.routes.extend(build_redaction_router(require_token).routes)

    @app.get("/", response_class=HTMLResponse)
    def redactor_home():
        # The redaction reviewer IS the landing page here. Inject the per-session token into
        # the SAME assembled, self-contained REDACTION_PAGE that Lawbat serves at /redaction.
        return HTMLResponse(REDACTION_PAGE.replace("__DRR_TOKEN__", html.escape(state.token)))


    _install_document_workspace(app, state)
    return app

