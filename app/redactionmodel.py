"""
Bridge to the Rust `redact-cli` binary that runs the deterministic redaction engine.

The host shell (this Python pilot) owns the two-tier review UI; the Rust redaction
ENGINE (the standalone `redact-cli` bin — NOT the audited `Core` path: this shipped
path has no core mediation and no durable audit trail; routing it through an audited
`Core` is the owed follow-up) owns detection + the actual redaction. This module is
the thin JSON-over-subprocess seam between them — the SAME pattern as `app/viewmodel.py` (viewgen), but request/
response instead of one-shot:

  * `scan(text)`  -> candidates with confidence + review tier + a routing summary
  * `apply(text, accept)` -> the text with ONLY the accepted spans redacted

CONFIDENTIALITY: the document text is handed to the bin on STDIN (never argv — process
arguments are visible via `ps`/Task Manager, so cleartext must not go there). The bin
returns cleartext candidates for the in-process review; that travels only the local
parent->child pipe, never the network — the same air-gap as the rest of the app. We do
NOT log the text or any matched value here.

LOCAL-ONLY: this only ever runs a LOCAL executable and exchanges LOCAL JSON. No network,
no model.

GRACEFUL: unlike the Home (which falls back to a sample), redaction has no meaningful
"sample" — a missing/broken bin means the feature is unavailable, surfaced HONESTLY as a
structured `{"error": ...}` the UI shows. This module NEVER raises out to the server.

The bin locator + the safe subprocess runner are the SHARED core-bridge primitives
(app/corebridge.py): env override `LAWDATAMAN_REDACT_CLI` -> bundled
<vendor>/core/redact-cli -> system PATH, then a no-shell, args-list, UTF-8,
bounded-timeout, never-raise run with the document on STDIN (never argv).
"""

import json
import logging

from . import corebridge

log = logging.getLogger("dataroomreview.redactionmodel")

# The contract this module knows how to consume (the bin stamps every response).
REDACTION_SCHEMA = "firmos.redaction/0"

# Bound the subprocess so a hung/runaway bin can never wedge a request. The bound is
# CORRELATED WITH INPUT SIZE: detection/redaction is ~linear in the document, so a large
# PDF (hundreds of pages, base64 on stdin) legitimately needs longer, while a small or
# hung job still fails fast at the floor. ~0.1s/page measured on a real prospectus; the
# per-MB factor carries a generous (~5x) margin for slow machines and operator-dense pages.
_REDACT_TIMEOUT_BASE_S = 30.0     # floor: small docs fail fast if the bin hangs
_REDACT_TIMEOUT_PER_MB_S = 60.0   # added per MB of request payload (base64 ~= bytes)
_REDACT_TIMEOUT_MAX_S = 900.0     # ceiling: never wait longer than this


def _timeout_for(payload: str) -> float:
    """Subprocess timeout scaled to the request size — the JSON payload is dominated by
    the document (base64 PDF for the pdf ops, the text for the text ops). Clamped to
    [base, max]: a small/hung job still fails at the floor, a big PDF gets proportional
    headroom."""
    size_mb = len(payload) / 1_000_000.0
    return min(_REDACT_TIMEOUT_BASE_S + _REDACT_TIMEOUT_PER_MB_S * size_mb, _REDACT_TIMEOUT_MAX_S)

# The OPT-IN recognizer-pack allowlists, mirroring the redact-cli `parse_locale` /
# `parse_profile` allowlists. A label outside these sets is dropped HERE too (defence in
# depth: the route also validates, and the bin ignores unknowns), so the request only
# ever carries packs that actually exist. Lowercase, stable labels.
#   * locales = jurisdiction national-ID packs (Locale::label form)
#   * profiles = compliance profiles (Profile::label form) — ONLY PCI is built today
ALLOWED_LOCALES = ("sg", "us", "uk", "au", "ca")
ALLOWED_PROFILES = ("pci-dss-cardholder",)

# The GLOBAL built-in recognizer NAMES a user may turn OFF, mirroring the redact-cli
# `builtins_from_disables` allowlist (the engine's `Recognizer::label()` spellings). A
# label outside this set is dropped HERE too (defence in depth). Disabling a built-in
# REDUCES recall — the user's deliberate choice; the default (none disabled) keeps full
# recall. A compliance PROFILE's required built-in still wins (re-enabled in the engine),
# so a profile guarantee can't be silently defeated by a disable.
ALLOWED_BUILTINS = (
    "email", "phone", "id", "name", "credit-card", "iban", "ip", "url", "address",
    "bic", "isin",
)

# Bounds on the USER-SUPPLIED TERMS ("super find & replace") — the KNOWN party / director /
# company names + matter numbers a lawyer wants redacted that no recognizer auto-detects.
# Mirrors the redact-cli `MAX_TERMS` / `MAX_TERM_BYTES` caps (defence in depth: the bin caps
# again, and the engine trims + regex-escapes each term so a name is matched as a literal,
# not a pattern). Empty / whitespace-only terms are dropped; an over-length term is dropped
# (never truncated — a truncated literal could match an unintended substring); excess past
# MAX_TERMS is dropped (the kept prefix still redacts). Absent/empty = no terms (today's
# behavior, byte-identical).
MAX_TERMS = 1000
# Per-term length cap measured in UTF-8 BYTES (NOT Python characters / UTF-16 code units).
# This MUST match how the redact-cli bin caps (`MAX_TERM_BYTES`): the bin re-validates each
# term in UTF-8 bytes, so a long multibyte party name (CJK / accented) that passes a CHAR
# cap here would be SILENTLY DROPPED at the bin — that name then never gets redacted = a
# leak-class MISS the lawyer is not told about. Cap + report in the SAME unit so a kept
# term here is a kept term there, and a dropped one is surfaced (see `term_drop_report`).
MAX_TERM_BYTES = 200
# Back-compat alias for the historical name (some callers/tests reference it). The value is
# unchanged; only the unit semantics (now UTF-8 bytes) were corrected.
MAX_TERM_CHARS = MAX_TERM_BYTES


def _is_kept_term(x) -> bool:
    """True if `x` is a non-blank string within the BYTE length cap — the single source of
    truth for which user TERMS survive validation (used by both the request builder and the
    drop report so the two can never disagree). The cap is UTF-8 BYTES to match the bin."""
    return (
        isinstance(x, str)
        and bool(x.strip())
        and len(x.encode("utf-8")) <= MAX_TERM_BYTES
    )


def term_drop_report(options: dict | None) -> dict:
    """Report user TERMS that will be DROPPED for exceeding the byte cap — so the UI can warn
    the lawyer instead of silently failing to redact a name. Returns
    `{"count": int, "terms": [<offending originals>...]}` (count == len(terms)); an empty
    report (`count == 0`, `terms == []`) when nothing is dropped or `terms` is absent.

    Only OVER-LENGTH non-blank terms are reported (those a user clearly meant to redact but
    that exceed the cap). Blank / whitespace-only and duplicate-of-a-kept-term entries are
    NOT reported as drops — they carry no redaction intent / are already covered. The
    offending originals are returned verbatim (the UI MUST esc() them before display); the
    list is de-duped order-preserving and bounded so a hostile payload cannot balloon the
    response. This is a SEPARATE channel from `normalize_options` (which builds the bin
    REQUEST) — the dropped terms are NEVER sent to the bin; they only feed the warning."""
    empty = {"count": 0, "terms": []}
    if not isinstance(options, dict):
        return empty
    raw_terms = options.get("terms")
    if not isinstance(raw_terms, (list, tuple)):
        return empty
    over: list[str] = []
    seen: set[str] = set()
    for x in raw_terms:
        # Over-length = a non-blank string that fails ONLY the byte cap (so a blank term,
        # which carries no intent, is not reported as a "dropped" redaction target).
        if not isinstance(x, str) or not x.strip():
            continue
        if len(x.encode("utf-8")) <= MAX_TERM_BYTES:
            continue
        if x in seen:
            continue
        seen.add(x)
        over.append(x)
    # Bound the surfaced list (the count stays exact for the message; the listed terms are
    # capped so a flood of long strings cannot bloat the JSON the UI renders).
    return {"count": len(over), "terms": over[:MAX_TERMS]}


def normalize_options(options: dict | None) -> dict:
    """Validate a raw options dict against the pack allowlists and return the SANITIZED
    subset to fold into a redact-cli request. ALWAYS returns a dict; never raises.

    Accepts the keys `locales` (list of jurisdiction labels), `profiles` (list of
    compliance-profile labels), `context` (bool), `lei` (bool — the OPT-IN ISO 17442 LEI
    recognizer), `organisations` (bool — OPT-IN organisation-name detection), `addresses_full`
    (bool — OPT-IN full-address detection), `disable_builtins` (list of GLOBAL built-in
    recognizer names to turn OFF), and `terms` (list of USER-SUPPLIED literal strings to
    redact — "super find & replace").
    Unknown locale/profile/built-in labels are DROPPED (recall-first never enables a pack
    that does not exist; an unknown one cannot be honored anyway). A non-list / non-bool
    value degrades to the empty/false default rather than erroring — the engine then runs
    built-ins only, never a crash. Only keys with a non-default value are included, so absent
    options keep the request byte-identical to today's built-ins-only behavior.

    `lei` is OFF by default (a public LEI is borderline PII, so flagging it is a deliberate
    user choice — like `context`, it is included only when explicitly True).

    `sg_nric_loose` (bool, OFF by default — included only when explicitly True) enables the
    OPT-IN AGGRESSIVE SG-NRIC loose net (two `aggressive` SG rows whose hits are ADVISORY,
    default-OFF in apply). It does NOT redact a real NRIC any differently — the precise
    `sg:nric` row still catches + default-redacts those; this only adds the EXTRA possibles.

    `disable_builtins` REDUCES recall (the user's deliberate choice — the default keeps
    full recall). A compliance profile's required built-in is re-enabled in the engine, so
    a disable can never silently defeat a profile guarantee.

    `terms` are the KNOWN party / director / company names + matter numbers a lawyer wants
    redacted that no recognizer auto-detects (a honorific-less full name like `Massimo
    Greco`). They are matched as ESCAPED LITERALS, case-insensitively, by the engine (so a
    name with metacharacters like `A.B (Pte)` is matched verbatim). Empty / whitespace-only
    terms are dropped, an over-`MAX_TERM_BYTES` term is dropped (never truncated), the list
    is de-duped (order-preserving) and capped at `MAX_TERMS`. Absent/empty = no terms (the
    historical byte-identical behavior)."""
    out: dict = {}
    if not isinstance(options, dict):
        return out
    raw_locales = options.get("locales")
    if isinstance(raw_locales, (list, tuple)):
        locales = [str(x).lower() for x in raw_locales if isinstance(x, str)]
        keep = [x for x in locales if x in ALLOWED_LOCALES]
        # De-dup, order-preserving (matches the engine's order-preserving dedup).
        seen: set[str] = set()
        keep = [x for x in keep if not (x in seen or seen.add(x))]
        if keep:
            out["locales"] = keep
    raw_profiles = options.get("profiles")
    if isinstance(raw_profiles, (list, tuple)):
        profiles = [str(x).lower() for x in raw_profiles if isinstance(x, str)]
        keep = [x for x in profiles if x in ALLOWED_PROFILES]
        seen2: set[str] = set()
        keep = [x for x in keep if not (x in seen2 or seen2.add(x))]
        if keep:
            out["profiles"] = keep
    if options.get("context") is True:
        out["context"] = True
    if options.get("lei") is True:
        out["lei"] = True
    # OPT-IN AGGRESSIVE SG-NRIC loose net (default OFF — like `lei`/`context`, included only
    # when explicitly True). Enables the two `aggressive` SG rows (`sg:nric-loose` /
    # `sg:nric-context`); their hits are ADVISORY (surfaced, default-OFF in apply). A real
    # NRIC is still caught + default-redacted by the precise `sg:nric` row.
    if options.get("sg_nric_loose") is True:
        out["sg_nric_loose"] = True
    # OPT-IN ORGANISATION-name detection (default OFF — like `lei`/`context`, included only
    # when explicitly True). OFF is byte-identical to today's built-ins-only behavior. Hits
    # route to careful-review + an entity placeholder; the engine's amplification guard keeps
    # org matches OUT of the propagation seed, so enabling it cannot flood.
    if options.get("name_expansion") is True:
        out["name_expansion"] = True
    if options.get("organisations") is True:
        out["organisations"] = True
    # OPT-IN FULL-ADDRESS detection (default OFF — included only when explicitly True). OFF is
    # byte-identical. CAVEAT surfaced in the UI: in labels mode a person sitting in an address
    # slot (e.g. "Dr … House") can render as [address]; still a redaction, never a leak.
    if options.get("addresses_full") is True:
        out["addresses_full"] = True
    raw_disable = options.get("disable_builtins")
    if isinstance(raw_disable, (list, tuple)):
        disable = [str(x).lower() for x in raw_disable if isinstance(x, str)]
        keep = [x for x in disable if x in ALLOWED_BUILTINS]
        seen3: set[str] = set()
        keep = [x for x in keep if not (x in seen3 or seen3.add(x))]
        if keep:
            out["disable_builtins"] = keep
    raw_terms = options.get("terms")
    if isinstance(raw_terms, (list, tuple)):
        # Keep only non-empty (post-strip) string terms within the BYTE length cap (the SAME
        # unit the bin caps in — a CHAR cap here would pass a long multibyte name that the
        # bin then silently drops = a leak-class MISS; see `MAX_TERM_BYTES`). Terms are NOT
        # lowercased (the engine matches case-insensitively but redacts the ORIGINAL bytes)
        # nor stripped here (the engine trims + escapes); we only validate type, drop
        # blank/over-long, de-dup order-preserving, and cap the count. An over-length drop is
        # NOT silent — `term_drop_report` surfaces it to the UI.
        terms = [x for x in raw_terms if _is_kept_term(x)]
        seen4: set[str] = set()
        terms = [x for x in terms if not (x in seen4 or seen4.add(x))]
        terms = terms[:MAX_TERMS]
        if terms:
            out["terms"] = terms
    return out


# Minimum length (in Python characters, post-strip) for an IMPORTED term. A 1-char cell is
# noise (matches almost anything as a literal) — dropped, and reported so the count is honest.
# Distinct from the byte cap (MAX_TERM_BYTES) which is the UPPER bound the bin enforces.
MIN_TERM_CHARS = 2


def parse_imported_terms(filename: str, data: bytes) -> dict:
    """Parse an uploaded .csv / .txt file into a normalized list of redaction TERMS.

    The "Import list…" affordance on the terms textarea: a lawyer keeps a list of party /
    director / company names in a spreadsheet or text file and imports it in one gesture.

    Parsing:
      * ``.csv`` — every NON-EMPTY cell of every row is a candidate term (the csv module
        handles quoting / embedded commas). A spreadsheet column of names, or a wide row,
        both work.
      * anything else (``.txt`` / no extension) — ONE term per line.

    Normalization mirrors the engine's own term rules (so a kept term here is a kept term at
    the bin): strip; drop empty; drop shorter than ``MIN_TERM_CHARS``; drop longer than
    ``MAX_TERM_BYTES`` UTF-8 bytes (never truncated — a truncated literal could match an
    unintended substring); de-dupe CASE-INSENSITIVELY, keeping the first occurrence's
    original casing (the engine matches case-insensitively but redacts the original bytes);
    cap the total at ``MAX_TERMS`` (excess counted as dropped).

    Returns ``{"terms": [...], "imported": N, "duplicates": M, "dropped": K}``:
      * ``terms``      — the surviving, order-preserving, de-duped list (the merge source).
      * ``imported``   — ``len(terms)``.
      * ``duplicates`` — non-empty candidates skipped as case-insensitive duplicates.
      * ``dropped``    — candidates dropped for being too short / too long / over the count cap.

    CONFIDENTIALITY: a term is a party NAME — cleartext matter data. This function NEVER logs
    a term (or the parsed content); only counts are safe to surface. NEVER raises — a decode /
    parse failure degrades to an empty result rather than breaking the request."""
    empty = {"terms": [], "imported": 0, "duplicates": 0, "dropped": 0}
    if not isinstance(data, (bytes, bytearray)):
        return dict(empty)
    # Decode tolerantly: strip a UTF-8 BOM (utf-8-sig), fall back to latin-1 so a Windows /
    # Excel export in an odd encoding still yields text rather than an exception (latin-1 maps
    # every byte, never raises). No cleartext is logged either way.
    try:
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = bytes(data).decode("latin-1")
        except Exception:  # noqa: BLE001 - never raise out; degrade to empty
            return dict(empty)

    name = str(filename or "")
    is_csv = name.lower().endswith(".csv")
    candidates: list[str] = []
    try:
        if is_csv:
            import csv
            import io
            for row in csv.reader(io.StringIO(text)):
                for cell in row:
                    if isinstance(cell, str):
                        candidates.append(cell)
        else:
            candidates = text.split("\n")
    except Exception:  # noqa: BLE001 - a malformed CSV must not break the import
        candidates = text.split("\n")

    terms: list[str] = []
    seen: set[str] = set()
    duplicates = 0
    dropped = 0
    for raw in candidates:
        if not isinstance(raw, str):
            continue
        t = raw.strip()
        if not t:
            continue  # an empty cell / blank line carries no intent — not a "drop"
        # Reject any term carrying an INTERIOR control/NUL char (.strip() only trims edge
        # whitespace). A NUL or C0/C1 control inside a "name" is corrupt import data — a literal
        # that can never match a real identifier — and would otherwise ride into the textarea;
        # this mirrors the strict control-char refusal on confinement `rel` (batchredact).
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in t):
            dropped += 1
            continue
        if len(t) < MIN_TERM_CHARS or len(t.encode("utf-8")) > MAX_TERM_BYTES:
            dropped += 1
            continue
        key = t.casefold()
        if key in seen:
            duplicates += 1
            continue
        if len(terms) >= MAX_TERMS:
            dropped += 1  # over the count cap — surfaced, not silently swallowed
            continue
        seen.add(key)
        terms.append(t)
    return {"terms": terms, "imported": len(terms), "duplicates": duplicates,
            "dropped": dropped}


def redact_cli_path() -> str | None:
    """Absolute path to the Rust `redact-cli` bin, or None if unavailable.

    Delegates to corebridge.locate (env -> vendor/core/ -> PATH), like viewgen."""
    return corebridge.locate("LAWDATAMAN_REDACT_CLI", "redact-cli")


def available() -> bool:
    """True if the redaction bin can be LOCATED. NOTE: this is a locate-only check — a bin
    that exists on disk can still be unrunnable (missing DLL / wrong arch / corrupt build),
    so this is NOT a readiness signal. For the page's on-load readiness probe use `health()`
    (a real round-trip). Kept for the fail-closed OCR routes, which only need "is a bin
    present at all" before attempting the real run (a genuine spawn failure there still 503s)."""
    return redact_cli_path() is not None


# The health probe runs the bin, so bound it — but with a SHORT timeout, not the size-scaled
# request timeout: an empty-text scan answers in well under a second, and a hung/broken spawn
# must fail fast so the page's on-load probe can't stall the UI.
_HEALTH_TIMEOUT_S = 5.0


def health() -> dict:
    """Determine redaction-engine readiness by an ACTUAL round-trip — never path-existence
    alone. A bin that merely EXISTS can still fail to spawn (a missing DLL, wrong arch, a
    corrupt build) or return garbage; reporting it "ready" from a locate-only check is a lie
    the page then contradicts the instant a real scan fails (a green "Tool ready" chip beside
    a red "tool unavailable" banner). So we EXECUTE the bin with a tiny, side-effect-free scan
    (empty text, default engine) through the normal corebridge.run path and report ready ONLY
    on a well-formed `firmos.redaction/0` scan response.

    Returns `{"ok": bool, "reason": str}`. `reason` distinguishes the failure so the caller /
    logs can tell them apart (no cleartext is ever logged — the probe input is a constant
    empty string):
      * "not-found"     — the bin could not be located (env / vendor / PATH all missed)
      * "spawn-failed"  — located but could not be started or timed out (missing DLL, …)
      * "bad-response"  — ran but produced non-JSON / a non-contract / an error envelope
      * "ready"         — ran and returned a well-formed scan contract
    """
    bin_path = redact_cli_path()
    if not bin_path:
        return {"ok": False, "reason": "not-found"}
    payload = json.dumps({"op": "scan", "text": ""})
    res = corebridge.run(bin_path, input=payload, timeout=_HEALTH_TIMEOUT_S)
    if not res.started:
        log.warning("redact-cli health probe failed to run (%s)", res.exc_name)
        return {"ok": False, "reason": "spawn-failed"}
    try:
        data = json.loads(res.stdout)
    except (ValueError, TypeError):
        log.warning("redact-cli health probe output was not JSON (exit %s)", res.returncode)
        return {"ok": False, "reason": "bad-response"}
    # A well-formed READY response is the schema-stamped scan contract with NO error envelope.
    # A schema-stamped error (or a wrong/absent schema) means the bin ran but is not usable.
    if not isinstance(data, dict) or data.get("schema") != REDACTION_SCHEMA or "error" in data:
        log.warning("redact-cli health probe returned a non-contract / error response")
        return {"ok": False, "reason": "bad-response"}
    return {"ok": True, "reason": "ready"}


def _run(request: dict) -> dict:
    """Run one request through the bin and return its parsed JSON response.

    ALWAYS returns a dict — never raises. On any failure (bin missing, run error,
    timeout, non-JSON output) returns a structured `{"error": <reason>}` the UI can
    surface. A reason here is our own message or the bin's value-free error envelope,
    never matter text."""
    bin_path = redact_cli_path()
    if not bin_path:
        log.info("redact-cli bin not found; redaction unavailable")
        return {"error": "The redaction engine is not installed on this machine."}

    payload = json.dumps(request)
    # No shell; args as a list; the document text goes on STDIN (never argv); bounded,
    # size-scaled timeout; UTF-8 both ways; never raises (see corebridge.run).
    res = corebridge.run(bin_path, input=payload, timeout=_timeout_for(payload))
    if not res.started:
        log.warning("redact-cli failed to run (%s)", res.exc_name)
        return {"error": "The redaction engine could not be started."}

    # The bin prints its contract envelope (incl. its own {"error": ...}) on stdout even
    # when it exits non-zero, so parse stdout regardless of the return code.
    try:
        data = json.loads(res.stdout)
    except (ValueError, TypeError):
        log.warning("redact-cli output was not JSON (exit %s)", res.returncode)
        return {"error": "The redaction engine returned an unreadable response."}

    if not isinstance(data, dict) or data.get("schema") != REDACTION_SCHEMA:
        log.warning("redact-cli output is not a %s contract", REDACTION_SCHEMA)
        return {"error": "The redaction engine returned an unexpected response."}
    return data


def scan(text: str, options: dict | None = None) -> dict:
    """Scan `text` for identifiers. Returns the `firmos.redaction/0` scan contract
    (`candidates` + `summary`) or `{"error": ...}`.

    `options` enables the OPT-IN packs (jurisdiction `locales`, compliance `profiles`,
    `context`) — validated against the allowlists by `normalize_options`. Absent = the
    historical built-ins-only behavior."""
    return _run({"op": "scan", "text": text, **normalize_options(options)})


# The two text-apply replacement styles the bin understands. `redacted` (default/absent)
# replaces every removed span with the flat `[REDACTED]` marker (byte-identical to the
# historical behavior). `labels` is AI-safe PSEUDONYMIZATION: each DISTINCT removed entity
# gets a STABLE, DISTINCT placeholder (`[A]`/`[email 1]`/…) and the response ALSO carries a
# `legend` (the label -> real-value map, cleartext, kept LOCAL for the lawyer — never egressed,
# never audited). An unknown/misspelt style maps to the safe `redacted` default (the bin does
# this too; we mirror it for defence in depth so the request only ever carries a known style).
ALLOWED_REPLACEMENT_STYLES = ("redacted", "labels")


def normalize_replacement_style(style) -> str:
    """Coerce a request's `replacement_style` to an allowlisted value. Anything outside
    {redacted, labels} -> 'redacted' (the safe, byte-identical default). Never raises."""
    if isinstance(style, str) and style in ALLOWED_REPLACEMENT_STYLES:
        return style
    return "redacted"


def apply(
    text: str,
    accept: list,
    options: dict | None = None,
    replacement_style: str = "redacted",
) -> dict:
    """Redact ONLY the accepted spans in `text`. `accept` is a list of `[start, end]`
    byte coordinates (as reported on scan candidates). Returns the apply contract
    (`redacted` + `applied` + `stale`, plus `legend` when `replacement_style="labels"`)
    or `{"error": ...}`.

    `options` MUST match the `scan` that produced `accept` (the bin re-detects with the
    same engine config, so the spans align — a divergent config would mis-resolve the
    coordinates). Same allowlist-validated packs as `scan`.

    `replacement_style` (`"redacted"` | `"labels"`) picks the marker style — see
    `ALLOWED_REPLACEMENT_STYLES`. Allowlisted here (and again in the bin); an unknown style
    degrades to the byte-identical `"redacted"` default, never an error. The `labels`
    legend carries cleartext for the LOCAL review only — the host keeps it on the machine
    and NEVER pastes it anywhere."""
    return _run({
        "op": "apply",
        "text": text,
        "accept": accept,
        "replacement_style": normalize_replacement_style(replacement_style),
        **normalize_options(options),
    })


def extract_scan(filename: str, data_b64: str, options: dict | None = None) -> dict:
    """Extract a FILE's text (`.eml`/`.docx`/`.pdf`, or a UTF-8 plain-text fallback) and
    scan it. `filename` is used only to pick the extractor by extension; `data_b64` is the
    file's bytes base64-encoded (the stdin boundary is JSON/text, so binary travels b64).
    Returns the `extract_scan` contract (`text` + `format` + `warnings` + `candidates` +
    `summary`) or `{"error": ...}`. The returned `text` is what the host scans/echoes back
    on `apply`. `options` enables the OPT-IN packs (same as `scan`)."""
    return _run(
        {
            "op": "extract_scan",
            "filename": filename,
            "data_b64": data_b64,
            **normalize_options(options),
        }
    )


def pdf_scan(data_b64: str, options: dict | None = None) -> dict:
    """FORMAT-PRESERVING PDF: scan a PDF (base64 bytes) for in-PDF identifiers WITHOUT
    writing anything. Returns the `pdf_scan` contract (`candidates` + `summary` +
    `low_text` + `unmapped_fonts` + `diagnostics`) or `{"error": ...}`. Each candidate
    now carries a STABLE `id` + `page` for PER-SPAN review: the reviewer accepts/rejects
    individual ones and echoes the accepted `id`s back to `pdf_apply`. `options` enables
    the OPT-IN packs (same as `scan`).

    HONESTY: `unmapped_fonts` is TRUE when one or more pages used a font whose encoding
    could not be exactly mapped (a Type0/CID/multi-byte font) — those pages were decoded
    only best-effort, so a zero/low candidate count must NOT be read as "clean". DISTINCT
    from `low_text` (image-only/scanned). The review page WARNS on it as loudly as
    `low_text` (a warn banner, not a hint — `app/ui/redaction.review.js`), and the export
    stage gates the headline so an unmapped-font result can never read "all clear". The
    OCR route reads such pages as images and DOES remove their identifiers — empirically
    verified on the bundled Luxembourg/Shariah annexes — so the warning steers the
    reviewer there."""
    return _run({"op": "pdf_scan", "data_b64": data_b64, **normalize_options(options)})


def pdf_apply(
    data_b64: str, accept_ids: list | None = None, options: dict | None = None
) -> dict:
    """FORMAT-PRESERVING PDF: redact a PDF (base64 bytes) removing ONLY the reviewer-
    accepted candidate ids (`accept_ids`, the stable ids from `pdf_scan`) — TRUE byte
    removal of the matched text — and return the redacted PDF bytes base64-encoded
    (`pdf_b64`) plus `redactions`/`low_text`/`diagnostics`, or `{"error": ...}`.

    `accept_ids` MUST be ids from a `pdf_scan` of the SAME bytes AND the SAME `options`
    (detection is deterministic over bytes + engine config, so the ids align). An
    empty/None `accept_ids` removes NOTHING (default-deny). The host writes the bytes to
    disk + reveals them (the bin holds no filesystem capability)."""
    result = _run(
        {
            "op": "pdf_apply",
            "data_b64": data_b64,
            "accept_ids": accept_ids or [],
            **normalize_options(options),
        }
    )

    # This is a pre-write failure gate, NOT evidence that the PDF is fully redacted.
    # The current firmos.redaction/0 pdf_apply contract always includes this count.
    # Missing/malformed counts cannot be treated as zero (including bool, a subclass
    # of int). Never return bytes or engine diagnostics in a blocked response: the
    # single-file route checks "error" before decoding or publishing the output.
    if "error" in result:
        return result
    failed = result.get("could_not_remove")
    if type(failed) is not int or failed < 0:
        return {
            "error": "Export blocked: the engine did not report a valid removal outcome.",
            "reason": "invalid_removal_outcome",
        }
    if failed:
        return {
            "error": "Export blocked: some accepted redactions could not be removed.",
            "reason": "accepted_redactions_not_removed",
            "could_not_remove": failed,
        }
    return result
