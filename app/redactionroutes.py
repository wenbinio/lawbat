"""
The Redaction review API routes (the `/api/redaction/*` surface), factored out of
app/web.py so the app factory stays readable.

`build_redaction_router(require_token)` returns an APIRouter that create_app includes.
The token guard is passed IN (it closes over the per-session secret in AppState) and
attached to every state-changing redaction route via `dependencies=_TOKEN_GUARD`,
byte-for-byte as before — the structural guard test asserts EVERY state-changing route
still carries the `require_token` dependency, and the 403 rejection stays identical.

The Redaction PAGE itself (GET /redaction) and the page-assembly helpers stay in
web.py (page assembly is a web concern); this module owns only the JSON API + the
redaction-specific request helpers. LOCAL-ONLY / air-gapped: the document text travels
only the local pipe to the redact-cli bin (app/redactionmodel.py); we never persist or
log cleartext here. Writes go to the app-data exports dir, never the source tree, and
never overwrite (`_unique_export`).
"""

import base64
import binascii
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from . import __version__, releaseflow
from . import redactionmodel
from . import privilege
from . import textexport
from . import exportverify, exportverification, verificationtargets
from . import redactionreport
from . import batchredact
from .osio import open_path, reveal_in_folder
from .paths import exports_dir


# Bound the redaction request so one call can't hand the bin an unbounded payload
# (the bin caps its stdin at 16 MiB too; this is the host-side first line). Generous
# for a paste-in / single document — the redaction MVP is a text tool.
_REDACT_TEXT_MAX = 2_000_000   # bytes of UTF-8 document text
_REDACT_SPANS_MAX = 100_000    # accepted spans in one apply
# L-7: max ` (n)` collision probes in _unique_export before falling back to a
# timestamped name — bounds the loop against a pathological exports dir.
_UNIQUE_EXPORT_MAX = 10_000
# Cap the base64 of an uploaded file. The bin caps stdin at 16 MiB total (JSON envelope
# + filename + the base64), so keep the base64 comfortably under that — ~14 MB of base64
# is ~10.5 MB of file, generous for a single document.
_REDACT_FILE_B64_MAX = 14_000_000
# The cheap export formats a TEXT redaction may be saved as (plain text / markdown /
# web page / data-JSON). The labeled style adds an AI-safe markdown document PLUS a
# SEPARATE re-identification key file. Bound the inputs: the redacted text is already
# capped at apply, and a legend is bounded by the document size. A generous cap on each
# so a hostile client can't request an unbounded write.
_EXPORT_LEGEND_MAX = 200_000
# Bound the candidate list a pdf-preview request may carry (it is the SAME set the
# prior pdf-scan returned; this caps a hostile client). Generous for any real doc.
_PREVIEW_MAX_CANDS = 200_000
# Cap the base64 of an imported TERMS list (.csv/.txt). ~2 MiB of raw file (its base64 is
# ~4/3 of that) is a very long party list; a hostile client can't hand us an unbounded blob.
_IMPORT_TERMS_B64_MAX = 2_800_000
# Bound the number of files one batch-export request may carry (mirrors batchredact.MAX_FILES —
# a batch is a per-file REVIEW workload, not a bulk pipeline).
_BATCH_EXPORT_MAX_FILES = batchredact.MAX_FILES


# ================= Feature 1 (redact everywhere) + Feature 2 (keep list) ==========
# Both live HERE — the ONE server-side place — so the scan/apply id-parity contract is never
# violated. Feature 1 runs as a SECOND scan+apply pass whose scan AND apply share ONE
# augmented option set (the reviewer's accepted VALUES folded in as user TERMS, whose recall
# is ws-elastic by design). Options never change between a scan and its matching apply, so
# the byte-coordinate / stable-id parity holds. Feature 2's keep list NEVER reaches the
# engine: it only EXCLUDES values from Feature 1's expansion (the review UI does the visible
# auto-dismiss). No cleartext is logged in any of this (values live in-process only).
_WS_RUN = re.compile(r"\s+", re.UNICODE)


def _norm_value(s) -> str:
    """Whitespace-insensitive, case-insensitive normal form for VALUE-equality matching
    (an accepted value <-> a re-scan candidate value, and a keep entry <-> a candidate). Drops
    ALL whitespace + casefolds — the SAME normalization exportverify uses — so an accepted
    value that recurs with different spacing / newlines / casing still matches (recall-first:
    over-match is the safe side of the miss-vs-overflag tradeoff)."""
    return _WS_RUN.sub("", s).casefold() if isinstance(s, str) else ""


def _keep_norms(payload) -> set:
    """FEATURE 2: the normalized "Keep (never redact)" value set from the request `keep` list.
    Parsed with the SAME caps as user TERMS (blank / over-byte dropped, count-capped) but it
    NEVER reaches the engine — it is used ONLY to EXCLUDE values from Feature 1's
    everywhere-expansion. No cleartext is logged (a keep entry is a party NAME)."""
    raw = (payload or {}).get("keep")
    out: set = set()
    if not isinstance(raw, (list, tuple)):
        return out
    for x in raw[: redactionmodel.MAX_TERMS]:
        if not isinstance(x, str):
            continue
        t = x.strip()
        if not t or len(t.encode("utf-8")) > redactionmodel.MAX_TERM_BYTES:
            continue
        n = _norm_value(t)
        if n:
            out.add(n)
    return out


def _redact_everywhere_on(payload) -> bool:
    """FEATURE 1 per-export toggle. The Export-stage checkbox defaults CHECKED and the UI
    always sends `redact_everywhere: true`; the SERVER treats an ABSENT flag as OFF so every
    legacy / non-UI caller keeps the exact reviewed-only behavior byte-for-byte (the default-ON
    is the UI's, applied where a human sees + owns the toggle). Only an explicit `true` turns
    on the two-pass expansion."""
    return (payload or {}).get("redact_everywhere") is True


class _TermCapExceeded(Exception):
    """Raised when the accepted-value set folded into TERMS would exceed MAX_TERMS. Feature 1
    FAILS LOUD here rather than letting normalize_options SILENTLY DROP the overflow — a silent
    subset is exactly the under-redaction hazard the feature exists to fix."""


class _ExpandUnderRecovery(Exception):
    """UNION-FLOOR guard (leak direction): raised when the PDF pass-2 value-matching could not
    re-select AT LEAST as many candidates of an accepted value as pass 1 had accepted of it, or
    when an accepted value cannot be value-matched at all (it normalizes to empty). The
    invariant is: a reviewer's EXPLICIT accept is ALWAYS redacted — 'everywhere' may only ADD.
    When that cannot be guaranteed the export FAILS LOUD, never silently under-redacts."""


_TERMS_CAP_MESSAGE = (
    "Too many different values to redact everywhere (over the "
    f"{redactionmodel.MAX_TERMS}-item limit). Turn off “Redact accepted values "
    "everywhere”, or reduce the number of accepted items, then export again."
)

_EXPAND_FAILED_MESSAGE = (
    "Could not safely expand the accepted values to every occurrence — the re-scan did not "
    "find every reviewed item again. Nothing was saved. Export with “Redact accepted values "
    "everywhere” switched off (only the reviewed occurrences), or scan again and retry."
)

# FIX 3 (over-reach floor): an accepted value whose ws-normal form is SHORTER than this is
# NOT auto-expanded — terms are ws-elastic SUBSTRING matchers with no word boundaries, so
# expanding a 3-char value like 'Tan' would redact inside unrelated words
# ('important' -> 'impor[REDACTED]t'). The reviewed occurrences still redact (the union
# floor); only the everywhere-expansion is skipped, counted in `not_expanded` with an honest
# reason. Measured on the normal form (whitespace dropped), matching how values are matched.
_MIN_EXPAND_CHARS = 4


def _expansion_meta(additional_targeted: int, short_n: int, over_n: int) -> dict:
    """The FEATURE 1 meta record. `additional_targeted` is the SELECTION-time count of extra
    occurrences the expansion targeted — 'targeted', not 'removed': actual removal is
    reconciled against the apply's `could_not_remove` by the report/UI wording, never claimed
    blindly. `short_n`/`over_n` are the DISTINCT accepted values honestly NOT expanded (too
    short / too long), each with a value-free reason string."""
    reasons: list = []
    if short_n:
        reasons.append(f"{short_n} accepted value(s) were too short to expand safely")
    if over_n:
        reasons.append(f"{over_n} accepted value(s) were too long to search for everywhere")
    return {"additional_targeted": additional_targeted,
            "not_expanded": short_n + over_n,
            "not_expanded_reasons": reasons}


def _expansion_off() -> dict:
    """The OFF-mode expansion record (a fresh dict per request — never a shared mutable)."""
    return {"on": False, "additional_targeted": 0, "not_expanded": 0,
            "not_expanded_reasons": []}


def _augmented_options(options: dict, values: list) -> tuple[dict, int]:
    """Fold accepted `values` into `options` as extra user TERMS for the pass-2 scan+apply.
    Returns `(augmented_options, not_expanded)` where `not_expanded` counts the DISTINCT
    accepted values too long (> MAX_TERM_BYTES) to search for everywhere (their reviewed /
    recognizer-detected occurrences are still removed via the accepted-norm selection; only
    their ws-elastic expansion is skipped — surfaced honestly, never silently). RAISES
    `_TermCapExceeded` if the merged term count would exceed MAX_TERMS (fail-loud)."""
    existing = list(options.get("terms", []) or [])
    termable: list = []
    seen: set = set()
    over: set = set()
    for v in values:
        if not isinstance(v, str) or not v.strip():
            continue
        if len(v.encode("utf-8")) > redactionmodel.MAX_TERM_BYTES:
            over.add(_norm_value(v))
            continue
        if v not in seen:
            seen.add(v)
            termable.append(v)
    merged: list = []
    mseen: set = set()
    for t in existing + termable:
        if t not in mseen:
            mseen.add(t)
            merged.append(t)
    if len(merged) > redactionmodel.MAX_TERMS:
        raise _TermCapExceeded()
    aug = dict(options)
    if merged:
        aug["terms"] = merged
    return aug, len(over)


def _expand_text_accept(text, accept, options, keep_norms):
    """FEATURE 1 (text path), passes 1+2. Re-derive the accepted VALUES from the AUTHORITATIVE
    `text` + accepted byte-spans (NEVER a client-sent value list — tamper-safe), fold the
    EXPANDABLE ones (not kept, not too short, not over-byte) in as TERMS, re-scan with those
    augmented options, and return the UNION accept-span set: the reviewer's original spans PLUS
    every ws-elastic occurrence of an expanded value. UNION FLOOR: the original spans are ALWAYS
    in the result — a keep entry / short value limits only the everywhere-EXPANSION delta, never
    a reviewed accept.

    Returns `(new_accept, aug_options, meta)` on success, or `(None, error_dict, None)` if the
    pass-2 engine scan failed (the route surfaces the engine error). RAISES `_TermCapExceeded`
    on overflow. `meta = {"additional_targeted", "not_expanded", "not_expanded_reasons"}`."""
    tb = text.encode("utf-8")
    n = len(tb)
    seen_norms: set = set()
    pairs: list = []   # DISTINCT (value, norm) of the accepted spans
    for s, e in accept:
        if 0 <= s < e <= n:
            try:
                v = tb[s:e].decode("utf-8")
            except UnicodeDecodeError:
                continue
            nv = _norm_value(v)
            if nv and nv not in seen_norms:
                seen_norms.add(nv)
                pairs.append((v, nv))
    # FIX 3 short-value floor + FEATURE 2 keep exclusion — both limit ONLY the expansion.
    expand_pairs = []
    short_n = 0
    for v, nv in pairs:
        if nv in keep_norms:
            continue
        if len(nv) < _MIN_EXPAND_CHARS:
            short_n += 1
            continue
        expand_pairs.append((v, nv))
    orig = {(int(s), int(e)) for s, e in accept}
    if not expand_pairs:
        # Nothing to expand (all kept / too short): the reviewed set applies UNCHANGED under
        # the UNCHANGED options — no pass 2 needed, parity is trivial.
        return ([list(x) for x in sorted(orig)], options,
                _expansion_meta(0, short_n, 0))
    aug, over_n = _augmented_options(options, [v for v, _ in expand_pairs])
    expand_norms = {nv for _, nv in expand_pairs}
    scan2 = redactionmodel.scan(text, aug)
    if not isinstance(scan2, dict) or "error" in scan2:
        return None, (scan2 if isinstance(scan2, dict) else {"error": "the engine could not re-scan"}), None
    new = set(orig)
    for c in (scan2.get("candidates") or []):
        if not isinstance(c, dict):
            continue
        s, e = c.get("start"), c.get("end")
        if (isinstance(s, int) and not isinstance(s, bool)
                and isinstance(e, int) and not isinstance(e, bool) and 0 <= s < e):
            if _norm_value(c.get("value")) in expand_norms:
                new.add((s, e))
    # Signed on purpose (no max(0,…) floor): `new` is a SUPERSET of `orig` by construction, so
    # a negative delta is impossible here — but the arithmetic must surface a regression, not
    # mask one.
    extra = len(new) - len(orig)
    new_accept = [list(x) for x in sorted(new)]
    return new_accept, aug, _expansion_meta(extra, short_n, over_n)


def _expand_pdf_accept(data_b64, accept_ids, options, keep_norms):
    """FEATURE 1 (PDF path). Re-derive the accepted VALUES from the AUTHORITATIVE PDF bytes (a
    pdf_scan of the ORIGINAL under the reviewer's options — never a client value list), fold
    the EXPANDABLE ones in as TERMS, re-scan, and return the new accept-id set. Because PDF
    candidate ids are OPTION-DEPENDENT (they index a specific scan), the reviewer's original
    acceptances and the term expansions are BOTH realized in the pass-2 id space by
    VALUE-matching — the two id spaces are NEVER mixed (a cross-space id could remove the
    wrong span). The pass-2 scan and the pass-2 apply share the augmented options (parity).

    UNION FLOOR (leak direction — do not weaken):
      * RESELECT norms = the values of ALL accepted ids, kept or not — a reviewer's explicit
        accept (e.g. a kept value the reviewer deliberately overturned in Review) is ALWAYS
        redacted; the keep list / short-value floor limit only the everywhere-EXPANSION delta.
      * If ANY accepted value cannot be value-matched (normalizes to EMPTY), or the pass-2
        selection recovers FEWER candidates of an accepted value than pass 1 had accepted of
        it, this RAISES `_ExpandUnderRecovery` — the export fails LOUD, never a silent subset.
      * When nothing is expandable at all, pass 2 is skipped: the ORIGINAL ids apply under the
        ORIGINAL options (id parity is trivial, reviewed positions exact).

    Returns `(new_accept_ids, aug_options, meta)` on success, or `(None, error_dict, None)` if
    an engine scan failed. RAISES `_TermCapExceeded` / `_ExpandUnderRecovery` (fail-loud)."""
    scan1 = redactionmodel.pdf_scan(data_b64, options)
    if not isinstance(scan1, dict) or "error" in scan1:
        return None, (scan1 if isinstance(scan1, dict) else {"error": "the engine could not scan"}), None
    accept_set = set(accept_ids or [])
    accepted_counts: dict = {}   # RESELECT floor: norm -> pass-1 accepted count (ALL accepts)
    seen_norms: set = set()
    pairs: list = []             # DISTINCT (value, norm) of the accepted candidates
    empty_norm_accepts = 0
    for c in (scan1.get("candidates") or []):
        if not isinstance(c, dict) or c.get("id") not in accept_set:
            continue
        nv = _norm_value(c.get("value"))
        if not nv:
            # An accepted candidate whose value cannot be value-matched into the pass-2 id
            # space. It MUST still be redacted (the union floor) — count it; if we end up
            # needing a pass 2 we cannot guarantee it, so we fail loud there.
            empty_norm_accepts += 1
            continue
        accepted_counts[nv] = accepted_counts.get(nv, 0) + 1
        if nv not in seen_norms:
            seen_norms.add(nv)
            pairs.append((c.get("value"), nv))
    # EXPAND values = non-kept, non-short only (FEATURE 2 + FIX 3) — expansion delta only.
    expand_pairs = []
    short_n = 0
    for v, nv in pairs:
        if nv in keep_norms:
            continue
        if len(nv) < _MIN_EXPAND_CHARS:
            short_n += 1
            continue
        expand_pairs.append((v, nv))
    if not expand_pairs:
        # Nothing expandable: apply the ORIGINAL ids under the ORIGINAL options — no pass 2,
        # id parity trivial, the reviewer's exact positions (incl. kept/short/empty-norm
        # accepts) are honored to the letter.
        return list(accept_ids or []), options, _expansion_meta(0, short_n, 0)
    if empty_norm_accepts:
        # A pass 2 is needed (something expands) but an accepted value cannot be re-selected
        # by value — the union floor cannot be guaranteed. FAIL LOUD, never drop the accept.
        raise _ExpandUnderRecovery()
    aug, over_n = _augmented_options(options, [v for v, _ in expand_pairs])
    expand_norms = {nv for _, nv in expand_pairs}
    scan2 = redactionmodel.pdf_scan(data_b64, aug)
    if not isinstance(scan2, dict) or "error" in scan2:
        return None, (scan2 if isinstance(scan2, dict) else {"error": "the engine could not scan"}), None
    # MERGED-SPAN RECOVERY (the 2026-07-17 audit's pdf-apply 400 class). When a folded-in TERM
    # overlaps other detected material, the engine MERGES the overlapping candidates into ONE
    # span whose value is the UNION text (pdf.rs: overlap merge; a ws-term partially covering
    # a primary is removed in FULL — the safe side). That merged value no longer norm-EQUALS
    # the accepted value, so strict equality used to refuse the whole export. For an EXPANDED
    # value the union floor is preserved by CONTAINMENT instead, provably:
    #   * the engine's ws-elastic TERM recall flags EVERY occurrence of an expanded value —
    #     including each reviewed one — so a covering pass-2 candidate always exists;
    #   * the overlap merge only EXTENDS a span (never drops coverage), so that covering
    #     candidate's value CONTAINS the occurrence's text;
    #   * `_norm_value` (ws-strip + casefold) is a character-wise map, so substring
    #     containment survives normalization.
    # Selecting every candidate whose norm CONTAINS an expanded norm therefore covers every
    # reviewed occurrence of that value (over-selection of a longer containing span is the
    # SAFE direction — more removed, never less). NON-expanded accepted values (kept / short /
    # over-byte) have NO term-recall guarantee, so they keep the strict equality floor and
    # still fail LOUD on any drift.
    new_ids: list = []
    seen_ids: set = set()
    eq_counts: dict = {}      # strict norm-equality selections, per accepted norm
    cover_counts: dict = {}   # containment selections, per EXPANDED norm (equality included)
    for c in (scan2.get("candidates") or []):
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if isinstance(cid, bool) or not isinstance(cid, int) or cid < 0:
            continue
        if cid in seen_ids:
            continue
        nv = _norm_value(c.get("value"))
        if not nv:
            continue
        hit_eq = nv in accepted_counts
        covered = [en for en in expand_norms if en in nv]
        if not (hit_eq or covered):
            continue
        seen_ids.add(cid)
        new_ids.append(cid)
        if hit_eq:
            eq_counts[nv] = eq_counts.get(nv, 0) + 1
        for en in covered:
            cover_counts[en] = cover_counts.get(en, 0) + 1
    # PER-VALUE RECONCILIATION: pass 2 must recover AT LEAST as many candidates of each
    # accepted value as pass 1 had accepted of it — else a reviewed accept would silently
    # drop out of the apply set (the under-redaction leak). Fail LOUD. Expanded norms may be
    # satisfied by CONTAINMENT (see above); everything else needs strict equality.
    for nv, cnt in accepted_counts.items():
        got = cover_counts.get(nv, 0) if nv in expand_norms else eq_counts.get(nv, 0)
        if got < cnt:
            raise _ExpandUnderRecovery()
    # `extra` can legitimately be NEGATIVE now: one merged pass-2 candidate can cover several
    # accepted occurrences at once (the per-value floor above is the loss detector — a real
    # under-recovery raised before reaching here). Floor the META at 0 so the honest
    # "additional occurrences targeted" count never reads as a negative.
    extra = max(0, len(new_ids) - sum(accepted_counts.values()))
    return new_ids, aug, _expansion_meta(extra, short_n, over_n)


def _default_spans_from_scan(res: dict):
    """FEATURE 3 (OCR advisory-parity), the ONE-SHOT BURN shape: the DEFAULT candidate span
    set from a `scan` result — ADVISORY (aggressive-recognizer) candidates are EXCLUDED,
    exactly as the born-digital text / format-preserving PDF paths default them OFF (the human
    opts in; the one-shot burn has no review step, so its set IS the default set). Route-level
    ADAPTER filter — the engine still SURFACES advisory candidates for opt-in review elsewhere.
    Returns `(start, end)` pairs."""
    out: list = []
    for c in (res.get("candidates") or []):
        if not isinstance(c, dict) or c.get("advisory") is True:
            continue
        s, e = c.get("start"), c.get("end")
        if isinstance(s, int) and isinstance(e, int) and 0 <= s < e:
            out.append((s, e))
    return out


def _review_spans_from_scan(res: dict):
    """FEATURE 3 completion, the PER-SPAN REVIEW shape: EVERY candidate — advisory INCLUDED —
    as `(start, end, recognizer, advisory)` 4-tuples, mirroring the born-digital review
    exactly: an advisory candidate is SURFACED, visibly marked, and DEFAULT-OFF (the scanned
    review renders it unselected; the human opts in), never silently absent. Default TREATMENT
    matches the burn path (advisory not removed unless opted in); opt-in AVAILABILITY matches
    the text path (the reviewer can see + choose it)."""
    out: list = []
    for c in (res.get("candidates") or []):
        if not isinstance(c, dict):
            continue
        s, e = c.get("start"), c.get("end")
        if isinstance(s, int) and isinstance(e, int) and 0 <= s < e:
            out.append((s, e, str(c.get("recognizer", "")), c.get("advisory") is True))
    return out


def _unique_in_dir(directory: Path, name: str, max_probes: int = _UNIQUE_EXPORT_MAX) -> Path:
    """ATOMICALLY reserve and return a non-colliding path in `directory` for `name`.

    Creates the file with O_CREAT|O_EXCL as it probes, so two concurrent exports can NEVER
    select the SAME name and clobber each other (the exists()-then-write TOCTOU the bare
    probe had — #13). The returned path is a freshly-created EMPTY placeholder; the caller
    then writes into it (write_bytes/write_text truncates the placeholder). Adds ` (1)`,
    ` (2)`, … before the suffix (never overwrite, the read-only / no-clobber invariant).

    L-7: the ` (n)` scan is BOUNDED. After `max_probes` collisions it stops the dense
    numbering and falls back to a high-resolution timestamp + random suffix (still exclusive-
    create, so never-overwrite: the random tail makes a clash astronomically unlikely), so a
    pathological directory can never spin this loop forever. Module-level + dependency-free
    so it is unit-testable in isolation."""
    stem = Path(name).stem or "redacted"
    suffix = Path(name).suffix or ".pdf"

    def _reserve(p: Path) -> bool:
        # Atomic create-if-absent: True iff WE created it (so the name is now ours); False if
        # it already exists. Closes the select-then-write race two concurrent exports could hit.
        try:
            fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        os.close(fd)
        return True

    out = directory / f"{stem}{suffix}"
    n = 1
    while not _reserve(out):
        if n > max_probes:
            # Give up the dense numbering; a unique, non-overwriting timestamped name.
            stamp = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
            out = directory / f"{stem} ({stamp}){suffix}"
            # Defensive: in the (vanishing) chance even this exists, widen the random tail.
            while not _reserve(out):
                stamp = f"{int(time.time() * 1000)}-{secrets.token_hex(8)}"
                out = directory / f"{stem} ({stamp}){suffix}"
            return out
        out = directory / f"{stem} ({n}){suffix}"
        n += 1
    return out


def _unique_export(name: str) -> Path:
    """A non-colliding path in the exports dir for `name` (never overwrite — the
    read-only / no-clobber invariant). Delegates to the module-level, BOUNDED
    `_unique_in_dir` (L-7: the ` (n)` probe is capped, then falls back to a
    timestamped name) so the no-clobber logic is unit-testable."""
    return _unique_in_dir(exports_dir(), name)


# ------------------------------------------------ export report + verification ----
# Cap on the reviewer-name field carried in an export request (a NAME — anything longer is a
# paste mistake; bounds a hostile payload). Mirrors redactionreport's own trim.
_REVIEWER_NAME_MAX = 200


def _reviewer_name(payload) -> str | None:
    """The OPTIONAL reviewer name from an export request (persisted client-side in
    localStorage, sent back on each export). A blank / non-string value is omitted; a long
    one is trimmed. It is a name the user typed — written to the LOCAL report only, never
    logged or egressed."""
    v = (payload or {}).get("reviewer")
    if isinstance(v, str) and v.strip():
        return v.strip()[:_REVIEWER_NAME_MAX]
    return None


def _engine_identity() -> tuple[str | None, str | None]:
    """The redaction ENGINE's identity for the report: the located `redact-cli` path + its
    SHA-256 (best-effort — an unlocatable / unreadable bin yields `(None, None)` rather than
    failing the export). Content-free provenance, no cleartext."""
    path = redactionmodel.redact_cli_path()
    if not path:
        return None, None
    return path, redactionreport._sha256_of_file(path)


def _emit_report_in(directory: Path, out_name: str, report: dict) -> tuple[str | None, str | None]:
    """Write `<out_name>.report.json` + `.report.txt` into `directory`, via the SAME
    never-overwrite mechanics (`_unique_in_dir`) the redacted file used. Returns
    `(json_filename, txt_filename)` — either element is `None` if that write failed. NEVER
    raises. Shared by the single-file export (into the exports dir) and the batch export (into
    the per-batch subdir). Contains NO cleartext value (see app/redactionreport.py)."""
    try:
        json_doc = redactionreport.to_json(report)
        text_doc = redactionreport.to_text(report)
    except Exception:  # noqa: BLE001 - never let report rendering break the export
        return None, None
    json_name: str | None = None
    txt_name: str | None = None
    try:
        json_path = _unique_in_dir(directory, f"{out_name}.report.json")
        json_path.write_text(json_doc, encoding="utf-8")
        json_name = json_path.name
    except OSError:
        json_name = None
    # The .txt is a bonus readable copy; its failure does not sink the JSON report.
    try:
        txt_path = _unique_in_dir(directory, f"{out_name}.report.txt")
        txt_path.write_text(text_doc, encoding="utf-8")
        txt_name = txt_path.name
    except OSError:
        txt_name = None
    return json_name, txt_name


def _emit_report(out_path: Path, report: dict) -> tuple[str | None, str | None]:
    """Write `<output>.report.json` + `<output>.report.txt` beside the export in the exports
    dir. Thin wrapper over `_emit_report_in(exports_dir(), ...)`. NEVER raises. The `.txt`
    filename is returned so the UI's Report stage "View report" action can reveal/open the
    human-readable copy (via the confined open-export route)."""
    return _emit_report_in(exports_dir(), out_path.name, report)


def _verify_pdf_output(out_bytes: bytes, accepted_values: list, options: dict, *,
                       coverage=None, out_path=None) -> dict:
    """Post-export multi-vector evidence; NOT a publication or safety gate."""
    if out_path is not None:
        return exportverification.check_saved(
            out_path, out_bytes, accepted_values, options, kind="pdf", coverage=coverage)
    return exportverification.check(
        out_bytes, accepted_values, options, kind="pdf", coverage=coverage)


def _pdf_findings(data_b64: str, accept_ids: list, options: dict) -> dict:
    """Account for every accepted id, including failed or partially resolved scans."""
    try:
        scan = redactionmodel.pdf_scan(data_b64, options)
    except Exception:  # noqa: BLE001 - no exception text may escape this evidence boundary
        scan = None
    return verificationtargets.from_pdf_scan(scan, accept_ids)


# The OCR (image-burn) path FLATTENS pages to raster and burns boxes over detected regions —
# a fundamentally different operation from the byte-splice PDF path. Its honest cleaned / not-
# removed disclosure differs: it removes text baked into images (its whole point) but does NOT
# run the /Info+XMP metadata or attachment passes, and leaves any genuine text-layer pages to
# the format-preserving path.
_OCR_CLEANED = ["text regions burned out of the page images"]
_OCR_NOT_REMOVED = [
    "document metadata (Info / XMP) — the image path does not scrub it",
    "embedded file attachments",
    "text on pages that were NOT image-redacted (use Save redacted copy for those)",
]


def _accepted_values_from_spans(text: str, accept) -> list:
    """Compatibility view; evidence callers must also pass the returned coverage."""
    return verificationtargets.from_spans(text, accept)["accepted_values"]


def _verify_text_output(redacted_text: str, accepted_values: list, options: dict, *,
                        coverage=None, out_path=None, text_format="txt") -> dict:
    """Probe serialized UTF-8 output, not merely the pre-format text."""
    raw = redacted_text.encode("utf-8")
    if out_path is not None:
        return exportverification.check_saved(
            out_path, raw, accepted_values, options, kind="text",
            coverage=coverage, text_format=text_format)
    return exportverification.check(
        raw, accepted_values, options, kind="text", coverage=coverage, text_format=text_format)


def _finalize_ocr_export(
    out_path: Path, out_bytes: bytes, orig_bytes: bytes, counts: dict,
    options: dict, reviewer: str | None,
) -> dict:
    """Feature A+B for an OCR (image-burn) export: verify the raster output (it re-extracts as
    image-only, so the honest verdict is `could_not_fully_verify`), write the workflow report,
    and return the extra response fields. NEVER raises — the export is already saved."""
    boxes = int(counts.get("boxes", 0) or 0)
    try:
        verification = _verify_pdf_output(
            out_bytes, [], options, out_path=out_path,
            coverage={"requested": boxes, "resolved": 0, "unresolved": boxes, "complete": False})
    except Exception:  # noqa: BLE001
        verification = exportverify.classify(
            accepted_values=[], extract_failed=True,
            low_text_signals=["the exported file could not be checked after saving"])
    engine_path, engine_sha = _engine_identity()
    report = redactionreport.build_report(
        original_filename=out_path.name.replace(".redacted.pdf", "") or "document.pdf",
        original_sha256=redactionreport.sha256_hex(orig_bytes),
        output_filename=out_path.name,
        output_sha256=redactionreport.sha256_hex(out_bytes),
        engine_path=engine_path, engine_sha256=engine_sha,
        options=options,
        findings=boxes, accepted=boxes, rejected=0, per_recognizer={},
        ocr_used=True, low_text=False, unmapped_fonts=False, could_not_remove=0,
        cleaned=_OCR_CLEANED, not_removed=_OCR_NOT_REMOVED,
        verification=verification, reviewer=reviewer, export_kind="ocr",
    )
    report_filename, report_txt_filename = _emit_report(out_path, report)
    return {
        "cleaned": _OCR_CLEANED,
        "not_removed": _OCR_NOT_REMOVED,
        "verification": verification,
        "report_filename": report_filename,
        "report_txt_filename": report_txt_filename,
    }


def _sanitized_low_conf_pages(report) -> list:
    """Coerce imageredact's `low_conf_pages` honesty signal (`[{page, conf}]` — the
    pages whose mean OCR confidence fell under `ocr.LOW_CONF_THRESHOLD`) to plain ints
    for the response. Diagnostics only (page numbers + a percentage, never matter
    text); malformed entries are DROPPED rather than raising after an export is
    already written."""
    out = []
    for e in (report or {}).get("low_conf_pages") or []:
        try:
            out.append({"page": int(e["page"]), "conf": int(e["conf"])})
        except (TypeError, ValueError, KeyError):
            continue
    return out


def _sanitized_page_geo(payload) -> dict:
    """Parse + bound the per-page geometry echo on OCR apply-selection:
    `{page_index: {"rotate": 0|90|180|270, "deskew": float}}`. The scan response
    handed these to the client; replaying them keeps the accepted fractions in the
    exact pixel space the reviewer saw (scan<->apply parity). Bounded hard: rotate
    must be a right angle, deskew within ocr.DESKEW_MAX_DEG, NaN/garbage dropped —
    the client can only misplace boxes it itself supplies, so this adds no new trust
    surface, but the values still never reach PIL unvalidated."""
    from . import ocr

    geo_in = (payload or {}).get("geo", {})
    geo = {}
    if not isinstance(geo_in, dict):
        return geo
    for k, v in geo_in.items():
        try:
            idx = int(k)
        except (TypeError, ValueError):
            continue
        if not isinstance(v, dict):
            continue
        try:
            rot = int(v.get("rotate", 0))
            desk = float(v.get("deskew", 0.0))
        except (TypeError, ValueError):
            continue
        if rot not in (0, 90, 180, 270):
            continue
        if not (desk == desk and abs(desk) <= ocr.DESKEW_MAX_DEG):  # NaN-safe bound
            continue
        if rot or desk:
            geo[idx] = {"rotate": rot, "deskew": desk}
    return geo


# ---------------------------------------------------------------- sample ----
# The "Try it with a sample document" content — CLEARLY-FAKE identifiers only, so it can
# demonstrate detection across recognizer types WITHOUT ever touching real matter data.
# Synthesized into a PDF in memory on demand (never committed as a binary), so the sample
# is always available, deterministic, and adds no on-disk artifact. Every value here is
# fabricated (a placeholder-domain email, the documented test NRIC "S1234567D", an obvious
# fake company / phone) — this is the ONE redaction-surface touch in this feature, and it
# is FAKE-DATA-ONLY: it feeds the SAME upload->scan path a user file does, so it never
# disturbs the real scan/provenance flow (the page treats it exactly like a normal upload).
_SAMPLE_FILENAME = "lawbat-sample.pdf"
_SAMPLE_LINES = (
    "Lawbat — sample document (made-up data, for trying the redactor)",
    "",
    "This is a practice document. Every name and number below is invented.",
    "Nothing here is real client or matter data.",
    "",
    "Client contact: Jane Tan",
    "Email: jane.tan@example.com",
    "Phone: +65 8123 4567",
    "Singapore NRIC: S1234567D",
    "Company: Example Holdings (Pte) Ltd",
    "",
    "Counterparty director: John Lee",
    "Email: john.lee@example.org",
    "",
    "Try it: scan this, review the findings, then save a redacted copy.",
)


def _build_sample_pdf() -> bytes:
    """Synthesize the sample PDF (1 page) IN MEMORY with the fake identifiers above and
    return its bytes. Uses fitz (already a dep). Deterministic; no disk write, no network.

    Raises only on a genuine fitz failure (the route guards it and 503s) — there is no
    fallback because the sample is a convenience, not a guarantee."""
    import fitz  # pymupdf (AGPL-3.0 / Artifex commercial) — already a hard dep

    doc = fitz.open()
    try:
        page = doc.new_page()  # default A4
        text = "\n".join(_SAMPLE_LINES)
        # Insert at a comfortable margin; a built-in font keeps the text layer clean (no
        # subset/unmapped-font path) so the engine reads it normally — this is a HAPPY-PATH
        # demo, not a font edge case.
        page.insert_text((72, 90), text, fontsize=12, fontname="helv")
        return doc.tobytes()
    finally:
        doc.close()


# --------------------------------------------------- request/response helpers ----
def _redaction_text(payload) -> tuple[str | None, JSONResponse | None]:
    """Validate the request's `text`: a string within the size cap. Returns
    `(text, None)` on success or `(None, error_response)`."""
    text = (payload or {}).get("text", "")
    if not isinstance(text, str):
        return None, JSONResponse({"error": "text must be a string"}, status_code=400)
    if len(text.encode("utf-8")) > _REDACT_TEXT_MAX:
        return None, JSONResponse(
            {"error": f"text exceeds the {_REDACT_TEXT_MAX}-byte limit"}, status_code=400)
    return text, None


def _with_engine_provenance(result: dict) -> dict:
    """Stamp the HONEST execution provenance of the SHIPPED redaction path onto a
    response body: this path runs the standalone `redact-cli` engine (plus the local
    OCR burner for scanned PDFs) — it is NOT brokered through the audited Rust `Core`
    and keeps NO durable HMAC audit trail. Both are owed follow-ups (TODO §3/§8);
    until they land the API says so explicitly, so no client can mistake this for the
    audited-Core path. Additive only (setdefault) — never renames or removes an
    existing field."""
    if isinstance(result, dict):
        result.setdefault("core_mediated", False)
        result.setdefault("durable_audit", False)
    return result


def _redaction_response(result: dict) -> JSONResponse:
    """Map a redactionmodel result to an HTTP response: a structured engine error
    (missing/broken bin) is 503 so the UI shows it; a real result is 200. Every body
    carries the engine-provenance honesty fields (see `_with_engine_provenance`)."""
    result = _with_engine_provenance(result)
    if "error" in result:
        return JSONResponse(result, status_code=503)
    return JSONResponse(result)


def _with_passages(result: dict, text: str) -> dict:
    """Augment a redaction-scan result with the Confidentiality / Privilege passage
    flags over the SAME text the engine scanned.

    The passage flagger is deterministic, local-only, linear-time, ENGINE-INDEPENDENT
    (pure Python — needs no redact-cli bin) and NEVER redacts — it only SURFACES
    likely-sensitive paragraphs for the lawyer's judgment (the human-in-the-loop answer
    to contextual re-identification a per-identifier scan cannot solve). It is added
    even when the redaction ENGINE is unavailable (an `error` result still 503s, but the
    passages travel in the body so the page can surface them anyway). NEVER raises — a
    flagger error degrades to no passages rather than breaking the scan."""
    if not isinstance(result, dict):
        return result
    try:
        result["passages"] = privilege.flag_passages_dicts(text)
    except Exception:  # noqa: BLE001 - surfacing is best-effort; never break the scan
        result["passages"] = []
    # The BEFORE side of the re-identification EXPOSURE meter: a document-level
    # aggregate of the SAME quasi-identifier signals (count-derived, no cleartext). An
    # EXPOSURE indicator that prompts review — NOT a safety / anonymity measure. Same
    # best-effort contract as `passages`: a scorer error degrades to no score, never
    # breaks the scan.
    try:
        result["reid_score"] = privilege.score_reidentification_dict(text)
    except Exception:  # noqa: BLE001 - best-effort; never break the scan
        result.pop("reid_score", None)
    return result


def _redaction_raw_options(payload) -> dict:
    """The RAW (pre-sanitize) options dict from the request body — the `options` key, or
    a flat top-level fallback. Used by both `_redaction_options` (which sanitizes it into
    the bin request) and `_with_term_drops` (which reports over-length TERMS from it)."""
    body = payload or {}
    raw = body.get("options")
    if not isinstance(raw, dict):
        # Fall back to top-level keys so a caller can send them flat.
        keys = ("locales", "profiles", "context", "lei", "sg_nric_loose",
                "organisations", "addresses_full", "disable_builtins", "terms")
        raw = {k: body.get(k) for k in keys if k in body}
    return raw


def _redaction_options(payload) -> dict:
    """Extract the OPT-IN recognizer-pack options from the request body and SANITIZE
    them against the allowlists. NEVER raises / never 500s: an unknown jurisdiction or
    profile label is silently dropped (recall-first never enables a pack that does not
    exist), a malformed value degrades to the built-ins-only default. Absent options
    keep the request byte-identical to the historical behavior.

    Options live under the `options` key (`{locales:[...], profiles:[...],
    context:bool, lei:bool, disable_builtins:[...], terms:[...]}`); a top-level form is
    also accepted for convenience. `terms` are the USER-SUPPLIED literal names/strings to
    redact ("super find & replace"). The actual allowlist + bounds check is
    `redactionmodel.normalize_options` (shared with the bridge)."""
    return redactionmodel.normalize_options(_redaction_raw_options(payload))


def _with_term_drops(result: dict, payload) -> dict:
    """Augment a SCAN result with a `terms_dropped` report when one or more user
    "party / names to redact" TERMS exceed the byte cap and will NOT be sent to the
    engine — so the UI WARNS the lawyer instead of the name being silently un-redacted
    (a leak-class MISS). `terms_dropped` = `{count:int, terms:[<offending originals>]}`;
    omitted entirely when nothing is dropped (byte-identical to before). The terms are
    cleartext the UI MUST esc() before display; they never leave the machine. Best-effort
    — never raises out / breaks the scan (an over-length report is advisory)."""
    if not isinstance(result, dict):
        return result
    try:
        report = redactionmodel.term_drop_report(_redaction_raw_options(payload))
    except Exception:  # noqa: BLE001 - advisory; never break the scan
        return result
    if report.get("count"):
        result["terms_dropped"] = report
    return result


def _redaction_file_bytes(payload) -> tuple[str | None, JSONResponse | None]:
    """Validate an uploaded file's base64 `data_b64` (required + size-capped). Returns
    `(data_b64, None)` or `(None, error_response)`."""
    data_b64 = (payload or {}).get("data_b64", "")
    if not isinstance(data_b64, str) or not data_b64:
        return None, JSONResponse({"error": "file data is required"}, status_code=400)
    if len(data_b64) > _REDACT_FILE_B64_MAX:
        return None, JSONResponse({"error": "file is too large to redact here"}, status_code=400)
    return data_b64, None


# ------------------------------------------------------------------- batch export ----
def _safe_stem(name: str) -> str:
    """A filesystem-safe stem from a (rel) filename's basename — non-`[A-Za-z0-9._ -]` -> `_`,
    blank -> 'document'. Mirrors the single-file PDF/text export naming."""
    base = os.path.basename(str(name or "").replace("\\", "/"))
    return re.sub(r"[^A-Za-z0-9._ -]", "_", Path(base).stem).strip() or "document"


def _sanitize_accept_ids(raw) -> list[int]:
    """The reviewer's accepted PDF candidate ids (from pdf_scan): non-negative ints, no bools,
    capped. DEFAULT-DENY — a missing/invalid list removes nothing (same rule as pdf-apply)."""
    out: list[int] = []
    if isinstance(raw, list):
        for v in raw[:100_000]:
            if not isinstance(v, bool) and isinstance(v, int) and v >= 0:
                out.append(v)
    return out


def _validate_accept_spans(raw) -> tuple[list[list[int]] | None, str | None]:
    """Validate the reviewer's accepted text spans and REJECT on anything malformed: a list
    of `[start, end]` non-negative int pairs, count-capped. Returns `(spans, None)` on success
    or `(None, message)` on the FIRST problem — the shared rule for `/apply`, `/labeled-markdown`
    and the batch text path.

    REJECT (not silently drop) is the load-bearing choice: a dropped span on the labeled-markdown
    path would leave an identifier as CLEARTEXT in the AI working copy (a leak-class miss), and a
    dropped span on the batch path would silently under-redact a file. So a bad accept-set fails
    LOUD — the caller turns `message` into a 400 (single-file) or a per-file `failed` record
    (batch), never a quiet best-effort subset. Mirrors the historical inline `/apply` validator."""
    if not isinstance(raw, list):
        return None, "accept must be a list"
    if len(raw) > _REDACT_SPANS_MAX:
        return None, f"too many spans (max {_REDACT_SPANS_MAX})"
    out: list[list[int]] = []
    for span in raw:
        if (not isinstance(span, (list, tuple)) or len(span) != 2
                or not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0
                           for n in span)):
            return None, "each span must be [start, end] non-negative integers"
        out.append([span[0], span[1]])
    return out, None


def _spans_from_candidates(candidates) -> list[list[int]]:
    """The ACCEPT-ALL span set for a labeled-Markdown working copy built from a FILE/PDF: the
    [start, end] byte-coords of EVERY detected candidate. Recall-first / over-label is the SAFE
    side for an AI working copy — a label in place of an identifier can never leak; the reverse
    (a missed identifier left as cleartext for an AI tool) would. Skips a malformed entry; caps
    the count (defence in depth). The spans come from the SAME extract_scan that produced the
    text the labeled apply echoes back, so the coordinates align (the scan<->apply parity
    contract)."""
    out: list[list[int]] = []
    if not isinstance(candidates, list):
        return out
    for c in candidates[:_REDACT_SPANS_MAX]:
        if not isinstance(c, dict):
            continue
        s, e = c.get("start"), c.get("end")
        if (isinstance(s, int) and not isinstance(s, bool)
                and isinstance(e, int) and not isinstance(e, bool)
                and 0 <= s < e):
            out.append([s, e])
    return out


def _batch_export_pdf(batch_dir: Path, folder: str, spec: dict, reviewer: str | None,
                      redact_everywhere: bool = False, keep_norms: set | None = None):
    """Export ONE reviewed PDF from a batch: read the confined source, byte-splice-redact the
    accepted ids, write into `batch_dir` (never-overwrite), verify + write a per-file report.
    Returns `(report_dict, None)` on success or `(None, {"filename", "error"})` on any failure
    (the file is then EXCLUDED from the batch outputs + counted, never silently skipped).

    `redact_everywhere` (FEATURE 1, per-batch) runs the two-pass expansion so every ws-elastic
    occurrence of an accepted value is removed; a term-count overflow FAILS THIS FILE loudly
    (excluded + reason), never a silent subset. `keep_norms` (FEATURE 2) excludes values."""
    keep_norms = keep_norms or set()
    rel = spec.get("rel")
    name = os.path.basename(str(rel or "").replace("\\", "/")) or "document.pdf"
    raw, err = batchredact.read_confined(folder, rel)
    if raw is None:
        return None, {"filename": name, "error": err or "could not read the file"}
    opts = redactionmodel.normalize_options(spec.get("options"))
    accept_ids = _sanitize_accept_ids(spec.get("accept_ids"))
    data_b64 = base64.b64encode(raw).decode("ascii")
    expansion = _expansion_off()
    if redact_everywhere:
        try:
            new_ids, aug, meta = _expand_pdf_accept(data_b64, accept_ids, opts, keep_norms)
        except _TermCapExceeded:
            return None, {"filename": name, "error": _TERMS_CAP_MESSAGE}
        except _ExpandUnderRecovery:
            return None, {"filename": name, "error": _EXPAND_FAILED_MESSAGE}
        if new_ids is None:
            return None, {"filename": name,
                          "error": (aug or {}).get("error", "the engine could not scan the file")}
        accept_ids, opts = new_ids, aug
        expansion = {"on": True, **meta}
    result = redactionmodel.pdf_apply(data_b64, accept_ids, opts)
    if not isinstance(result, dict) or "error" in result:
        return None, {"filename": name,
                      "error": (result or {}).get("error", "the engine could not redact it")}
    pdf_b64 = result.get("pdf_b64")
    if not isinstance(pdf_b64, str):
        return None, {"filename": name, "error": "the engine returned no PDF"}
    try:
        out_bytes = base64.b64decode(pdf_b64, validate=True)
    except (binascii.Error, ValueError):
        return None, {"filename": name, "error": "the engine returned an unreadable PDF"}
    out_path = _unique_in_dir(batch_dir, f"{_safe_stem(name)}.redacted.pdf")
    try:
        out_path.write_bytes(out_bytes)
    except OSError:
        return None, {"filename": name, "error": "could not save the redacted PDF"}
    try:
        tallies = _pdf_findings(data_b64, accept_ids, opts)
        verification = _verify_pdf_output(
            out_bytes, tallies["accepted_values"], opts,
            coverage=tallies["coverage"], out_path=out_path)
    except Exception:  # noqa: BLE001 - never break the batch on the extra checks
        tallies = {"per_recognizer": {}, "findings": 0, "accepted": 0, "rejected": 0}
        verification = exportverify.classify(
            accepted_values=[], extract_failed=True,
            low_text_signals=["the exported file could not be checked after saving"])
    engine_path, engine_sha = _engine_identity()
    report = redactionreport.build_report(
        original_filename=name,
        original_sha256=redactionreport.sha256_hex(raw),
        output_filename=out_path.name,
        output_sha256=redactionreport.sha256_hex(out_bytes),
        engine_path=engine_path, engine_sha256=engine_sha, options=opts,
        findings=tallies["findings"], accepted=tallies["accepted"],
        rejected=tallies["rejected"], per_recognizer=tallies["per_recognizer"],
        ocr_used=False, low_text=bool(result.get("low_text", False)),
        unmapped_fonts=bool(result.get("unmapped_fonts", False)),
        could_not_remove=int(result.get("could_not_remove", 0) or 0),
        cleaned=result.get("cleaned") if isinstance(result.get("cleaned"), list) else [],
        not_removed=result.get("not_removed") if isinstance(result.get("not_removed"), list) else [],
        verification=verification, reviewer=reviewer, export_kind="pdf", expansion=expansion,
    )
    _emit_report_in(batch_dir, out_path.name, report)
    return report, None


def _batch_export_text(batch_dir: Path, folder: str, spec: dict, reviewer: str | None,
                       redact_everywhere: bool = False, keep_norms: set | None = None):
    """Export ONE reviewed text-bearing file (.docx/.eml/.txt/…) from a batch: read the
    confined source, extract its text, apply the accepted spans, write the chosen format into
    `batch_dir`, verify + write a per-file report. Same failure contract as `_batch_export_pdf`.
    The AI-safe label KEY file is NOT written in batch mode (increment 1) — batch uses the
    [REDACTED] marker; labels + the separate key stay on the single-file path."""
    rel = spec.get("rel")
    name = os.path.basename(str(rel or "").replace("\\", "/")) or "document.txt"
    raw, err = batchredact.read_confined(folder, rel)
    if raw is None:
        return None, {"filename": name, "error": err or "could not read the file"}
    opts = redactionmodel.normalize_options(spec.get("options"))
    data_b64 = base64.b64encode(raw).decode("ascii")
    ext = redactionmodel.extract_scan(name, data_b64, opts)
    if not isinstance(ext, dict) or "error" in ext:
        return None, {"filename": name,
                      "error": (ext or {}).get("error", "the file could not be read as text")}
    text = ext.get("text") if isinstance(ext.get("text"), str) else ""
    if len(text.encode("utf-8")) > _REDACT_TEXT_MAX:
        return None, {"filename": name, "error": "the extracted text is too large to redact"}
    # REJECT a malformed span rather than silently dropping it — a dropped span would leave an
    # identifier un-redacted in this file's copy. A bad accept-set fails THIS file only (the
    # honest per-file failure contract), never the whole batch. Missing/empty = redact nothing.
    accept, span_err = _validate_accept_spans(spec.get("accept") or [])
    if span_err is not None:
        return None, {"filename": name, "error": span_err}
    keep_norms = keep_norms or set()
    expansion = _expansion_off()
    if redact_everywhere:
        try:
            new_accept, aug, meta = _expand_text_accept(text, accept, opts, keep_norms)
        except _TermCapExceeded:
            return None, {"filename": name, "error": _TERMS_CAP_MESSAGE}
        except _ExpandUnderRecovery:
            return None, {"filename": name, "error": _EXPAND_FAILED_MESSAGE}
        if new_accept is None:
            return None, {"filename": name,
                          "error": (aug or {}).get("error", "the engine could not re-scan the file")}
        accept, opts = new_accept, aug
        expansion = {"on": True, **meta}
    apply_res = redactionmodel.apply(text, accept, opts, replacement_style="redacted")
    if not isinstance(apply_res, dict) or "error" in apply_res:
        return None, {"filename": name,
                      "error": (apply_res or {}).get("error", "the engine could not redact it")}
    redacted = apply_res.get("redacted") if isinstance(apply_res.get("redacted"), str) else ""
    applied = int(apply_res.get("applied", 0) or 0)
    stale = int(apply_res.get("stale", 0) or 0)
    if stale:
        raise ValueError("Export blocked: accepted text selections became stale.")
    fmt = textexport.normalize_format(spec.get("format"))
    try:
        doc = textexport.build_redacted_document(
            redacted, fmt, labeled=False, applied=applied, stale=stale, legend=[])
    except Exception:  # noqa: BLE001 - a formatter hiccup must not sink the whole batch
        return None, {"filename": name, "error": "could not format the redacted copy"}
    out_path = _unique_in_dir(batch_dir, f"{_safe_stem(name)}.redacted{textexport.suffix_for(fmt)}")
    try:
        out_path.write_bytes(doc.encode("utf-8"))
    except OSError:
        return None, {"filename": name, "error": "could not save the redacted copy"}
    try:
        # 2026-07-17 audit item (b): verify against the REAL accepted values (re-derived from
        # the extracted text + the effective accept spans, both in scope here) — the batch
        # text path used to pass [] and could never produce a real post-check verdict.
        targets = verificationtargets.from_spans(text, accept)
        verification = _verify_text_output(
            doc, targets["accepted_values"], opts, coverage=targets["coverage"],
            out_path=out_path, text_format=fmt)
    except Exception:  # noqa: BLE001
        verification = exportverify.classify(
            accepted_values=[], extract_failed=True,
            low_text_signals=["the redacted text could not be checked after saving"])
    engine_path, engine_sha = _engine_identity()
    report = redactionreport.build_report(
        original_filename=name,
        original_sha256=redactionreport.sha256_hex(raw),
        output_filename=out_path.name,
        output_sha256=redactionreport.sha256_hex(doc.encode("utf-8")),
        engine_path=engine_path, engine_sha256=engine_sha, options=opts,
        findings=applied, accepted=applied, rejected=stale, per_recognizer={},
        ocr_used=False, low_text=False, unmapped_fonts=False, could_not_remove=0,
        cleaned=[], not_removed=[], verification=verification,
        reviewer=reviewer, export_kind="text", expansion=expansion,
    )
    _emit_report_in(batch_dir, out_path.name, report)
    return report, None


def _run_batch_export(folder: str, batch_name: str, specs: list, reviewer: str | None,
                      redact_everywhere: bool = False, keep_norms: set | None = None) -> dict:
    """Redact + write every REVIEWED file in a batch into a fresh never-overwrite subdir under
    the exports dir, then write a batch-summary report aggregating per-file results (incl. the
    files that FAILED — excluded from the outputs, never silently skipped). Returns the
    response dict (matter-free counts + filenames). NEVER raises out."""
    batch_dir = batchredact.batch_output_dir(batch_name or "batch")
    reports: list[dict] = []
    failed: list[dict] = []
    for spec in specs[:_BATCH_EXPORT_MAX_FILES]:
        if not isinstance(spec, dict):
            # A non-dict entry is enumerated as a FAILED file, never silently skipped (the
            # docstring's contract) — there is no rel/name to recover, so it reports generically.
            failed.append({"filename": "document", "error": "malformed entry"})
            continue
        kind = spec.get("kind")
        try:
            if kind == "pdf":
                rep, fail = _batch_export_pdf(batch_dir, folder, spec, reviewer,
                                              redact_everywhere, keep_norms)
            else:
                rep, fail = _batch_export_text(batch_dir, folder, spec, reviewer,
                                               redact_everywhere, keep_norms)
        except Exception:  # noqa: BLE001 - one bad file must not sink the whole batch
            rep, fail = None, {
                "filename": os.path.basename(str(spec.get("rel") or "")) or "document",
                "error": "an unexpected error occurred while redacting this file"}
        if rep is not None:
            reports.append(rep)
        elif fail is not None:
            failed.append(fail)

    summary = redactionreport.build_batch_summary(
        batch_name=batch_name or batch_dir.name, reports=reports, failed=failed,
        reviewer=reviewer)
    summary_json = None
    summary_txt = None
    try:
        sj = _unique_in_dir(batch_dir, "batch-summary.report.json")
        sj.write_text(redactionreport.batch_summary_to_json(summary), encoding="utf-8")
        summary_json = sj.name
    except Exception:  # noqa: BLE001 - the copies are already written; the summary is a bonus
        summary_json = None
    try:
        stx = _unique_in_dir(batch_dir, "batch-summary.report.txt")
        stx.write_text(redactionreport.batch_summary_to_text(summary), encoding="utf-8")
        summary_txt = stx.name
    except Exception:  # noqa: BLE001
        summary_txt = None
    return {
        "ok": True,
        "batch_dir": batch_dir.name,
        "exported": len(reports),
        "failed": failed,
        "summary": summary,
        "summary_filename": summary_json,
        "summary_txt_filename": summary_txt,
    }


def build_redaction_router(require_token) -> APIRouter:
    """Build the `/api/redaction/*` APIRouter. `require_token` is the create_app-local
    token-guard dependency (it closes over the per-session secret); it is attached to
    every state-changing route here exactly as when these routes lived in create_app."""
    router = APIRouter()
    # Attach to a route decorator as `dependencies=_TOKEN_GUARD` — identical to web.py.
    _TOKEN_GUARD = [Depends(require_token)]

    @router.get("/api/redaction/health", dependencies=_TOKEN_GUARD)
    def api_redaction_health():
        # A tiny health probe the redaction page calls ON LOAD to decide whether to show the
        # friendly "engine unavailable" banner up front. It now runs a REAL round-trip (an
        # empty-text scan through the bin) rather than a path-exists check — a bin that exists
        # but cannot spawn (missing DLL) or returns garbage must report unavailable, so the
        # page never shows "✓ Tool ready" and then contradicts itself on the first real scan.
        # No document is touched (the probe input is a constant empty string), nothing is
        # logged, no network. TOKEN-GUARDED (like /api/redaction/sample): unlike the old
        # path-exists-only check, this now SPAWNS A PROCESS on every call — an un-guarded GET
        # would let any local caller repeatedly fork the bin. The page's on-load probe already
        # sends X-DRR-Token (base.js's get()/post() always do), so this is byte-identical for
        # the real UI; only an unauthenticated direct caller now sees 403.
        h = redactionmodel.health()
        # Real OCR-engine (Tesseract) availability, so the page can show the honest `OCR
        # unavailable` status chip WITHOUT waiting for a scanned-PDF flow to 503. Best-effort:
        # a probe failure reads as unavailable (never a false "available"). No process spawn —
        # ocr.available() is a locate-only check.
        try:
            from . import ocr
            ocr_ok = bool(ocr.available())
        except Exception:  # noqa: BLE001 - never let the OCR probe break the health route
            ocr_ok = False
        # Backward-compatible: `ok` is unchanged; `reason` is ADDED (not-found / spawn-failed /
        # bad-response / ready) so a caller can distinguish install-missing from broken-bin;
        # `ocr` is ADDED for the OCR-availability status chip.
        return JSONResponse(
            {"ok": bool(h.get("ok")), "reason": str(h.get("reason", "")), "ocr": ocr_ok})

    @router.get("/api/redaction/sample", dependencies=_TOKEN_GUARD)
    def api_redaction_sample():
        # "Try it with a sample document": synthesize a small PDF of CLEARLY-FAKE identifiers
        # IN MEMORY and hand it back base64-encoded — the SAME shape the upload path consumes
        # (filename + data_b64) — so the page can feed it straight into the real
        # scan->preview->review->apply flow as if the user had uploaded it. Token-guarded
        # like the other redaction endpoints (it returns synthesized bytes, no matter data,
        # but a uniform guard keeps the surface consistent). Air-gap safe: the bytes are
        # generated locally and never fetched from anywhere. FAKE-DATA-ONLY — see
        # _SAMPLE_LINES / _build_sample_pdf.
        try:
            pdf_bytes = _build_sample_pdf()
        except Exception:  # noqa: BLE001 - never leak internals; surface a clean error
            return JSONResponse(
                {"error": "Could not build the sample document."}, status_code=500)
        data_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        return JSONResponse({"filename": _SAMPLE_FILENAME, "data_b64": data_b64})

    @router.post("/api/redaction/scan", dependencies=_TOKEN_GUARD)
    def api_redaction_scan(payload: dict = Body(...)):
        text, err = _redaction_text(payload)
        if err:
            return err
        result = redactionmodel.scan(text, _redaction_options(payload))
        # Surface Confidentiality / Privilege passage flags over the SAME text (surface-only,
        # never redacts) alongside the identifier candidates.
        result = _with_passages(result, text)
        # Warn loudly if any user TERM was too long to redact (never a silent MISS).
        return _redaction_response(_with_term_drops(result, payload))

    @router.post("/api/redaction/scan-file", dependencies=_TOKEN_GUARD)
    def api_redaction_scan_file(payload: dict = Body(...)):
        filename = (payload or {}).get("filename", "")
        data_b64 = (payload or {}).get("data_b64", "")
        if not isinstance(filename, str) or not filename.strip():
            return JSONResponse({"error": "filename is required"}, status_code=400)
        if not isinstance(data_b64, str) or not data_b64:
            return JSONResponse({"error": "file data is required"}, status_code=400)
        if len(data_b64) > _REDACT_FILE_B64_MAX:
            return JSONResponse({"error": "file is too large to redact here"}, status_code=400)
        # Pass only the basename for extension detection — the bin never opens it, but a
        # bare name keeps any path component out of the request.
        base = os.path.basename(filename.replace("\\", "/")) or filename
        result = redactionmodel.extract_scan(base, data_b64, _redaction_options(payload))
        # Keep the EXTRACTED-text size consistent with the paste/apply cap: the apply route
        # enforces _REDACT_TEXT_MAX, so a doc that extracts to more than that would scan
        # here but fail apply with a confusing 400. Surface a clear message early instead.
        text = result.get("text")
        if isinstance(text, str) and len(text.encode("utf-8")) > _REDACT_TEXT_MAX:
            return JSONResponse(
                {"error": "The extracted text is too large to redact here."}, status_code=400)
        # Surface Confidentiality / Privilege passage flags over the EXTRACTED text — the
        # same text the engine scanned + the host echoes back on apply (surface-only).
        if isinstance(text, str):
            result = _with_passages(result, text)
        # Warn loudly if any user TERM was too long to redact (never a silent MISS).
        return _redaction_response(_with_term_drops(result, payload))

    @router.post("/api/redaction/pdf-scan", dependencies=_TOKEN_GUARD)
    def api_redaction_pdf_scan(payload: dict = Body(...)):
        data_b64, err = _redaction_file_bytes(payload)
        if err:
            return err
        result = redactionmodel.pdf_scan(data_b64, _redaction_options(payload))
        # Warn loudly if any user TERM was too long to redact (never a silent MISS).
        return _redaction_response(_with_term_drops(result, payload))

    @router.post("/api/redaction/pdf-preview", dependencies=_TOKEN_GUARD)
    def api_redaction_pdf_preview(payload: dict = Body(...)):
        # PHASE 2 — on-page VISUAL PDF preview (DISPLAY-ONLY): render the finding-pages
        # and locate each detected value's box via PyMuPDF search_for (OCR fallback on
        # unmapped-font pages). Reuses the candidate list from the prior pdf-scan — does
        # NOT re-scan and NEVER touches the removal path. Same token-guard + base64 caps
        # as pdf-scan. The rendered rasters are matter content held in memory only and
        # returned inline as data: URIs (so NO new fetch surface is added and the page's
        # strict air-gap assert keeps holding; page-virtualization bounds the payload).
        # Confidentiality: no cleartext is logged; the box payload carries a value_ref
        # INDEX (not the cleartext value — the UI already holds the value list).
        data_b64, err = _redaction_file_bytes(payload)
        if err:
            return err
        # The candidate list from the prior pdf-scan (each carries a 1-based `page` +
        # `value`). Default-empty / bounded; a malformed entry is skipped downstream.
        raw_cands = (payload or {}).get("candidates", [])
        if not isinstance(raw_cands, list):
            raw_cands = []
        # Keep the ORIGINAL list positions: the box payload's `value_ref` is an index the
        # UI dereferences against the UNFILTERED client `window.__cands`. Filtering out
        # non-dicts here and re-enumerating would shift `value_ref` off-by-N (box -> wrong
        # row). build_preview's helpers (finding_pages / candidates_on_page) already skip a
        # non-dict entry internally, so pass the cap-bounded list WITHOUT re-indexing.
        candidates = raw_cands[:_PREVIEW_MAX_CANDS]
        unmapped = bool((payload or {}).get("unmapped_fonts"))
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "invalid file data"}, status_code=400)
        from . import pdfpreview
        try:
            # build_preview NEVER raises (it returns {"preview": False, ...} on any
            # failure) — the broad guard is belt-and-suspenders so a route never 500s.
            result = pdfpreview.build_preview(raw, candidates, unmapped_fonts=unmapped)
        except Exception:  # noqa: BLE001 - preview is best-effort; fall back to the list
            return JSONResponse({"preview": False, "reason": "could not build the preview"})
        # A structured non-preview result is still a 200 — the UI reads `preview:false`
        # and keeps the existing flat list (this is an enhancement, never an error path).
        return JSONResponse(result)

    @router.post("/api/redaction/pdf-apply", dependencies=_TOKEN_GUARD)
    @releaseflow.prepare_export
    def api_redaction_pdf_apply(payload: dict = Body(...)):
        data_b64, err = _redaction_file_bytes(payload)
        if err:
            return err
        filename = (payload or {}).get("filename", "")
        if not isinstance(filename, str):
            filename = ""
        # The reviewer's accepted PDF candidate ids (the stable ids from pdf-scan).
        # DEFAULT-DENY: a missing/invalid list removes nothing. Coerce to non-negative
        # ints (skipping bools, which are an int subclass), dropping anything malformed —
        # the engine treats an unknown id as a no-op anyway — and cap the count.
        raw_ids = (payload or {}).get("accept_ids", [])
        accept_ids: list[int] = []
        if isinstance(raw_ids, list):
            for v in raw_ids[:100_000]:
                if not isinstance(v, bool) and isinstance(v, int) and v >= 0:
                    accept_ids.append(v)
        # The apply MUST re-detect with the SAME engine config as the pdf-scan that
        # produced these ids (else the deterministic id ordering diverges) — so pass the
        # same opt-in packs through.
        opts = _redaction_options(payload)
        # FEATURE 1 "Redact accepted values everywhere" (+ FEATURE 2 keep-list). When ON, run the
        # TWO-PASS expansion (re-derive accepted values from the PDF bytes, fold them in as TERMS,
        # re-scan, select every candidate whose value matches an accepted value). The pass-2 scan
        # + apply share the augmented options, so the ids align (parity preserved). When OFF, the
        # exact reviewed-only apply. FAIL LOUD (400) on a term-count overflow — never a subset.
        expansion = _expansion_off()
        if _redact_everywhere_on(payload):
            try:
                new_ids, aug, meta = _expand_pdf_accept(data_b64, accept_ids, opts, _keep_norms(payload))
            except _TermCapExceeded:
                # `error_kind` marks the CLASS for the UI (an EXPORT-stage refusal, not a
                # scan problem) so it can render apply-specific copy without string-matching.
                return JSONResponse({"error": _TERMS_CAP_MESSAGE,
                                     "error_kind": "terms_cap"}, status_code=400)
            except _ExpandUnderRecovery:
                return JSONResponse({"error": _EXPAND_FAILED_MESSAGE,
                                     "error_kind": "expand_failed"}, status_code=400)
            if new_ids is None:
                return _redaction_response(aug)   # `aug` carries the engine error envelope
            accept_ids, opts = new_ids, aug
            expansion = {"on": True, **meta}
        result = redactionmodel.pdf_apply(data_b64, accept_ids, opts)
        if "error" in result:
            return _redaction_response(result)   # 503 — engine unavailable / refused PDF
        pdf_b64 = result.get("pdf_b64")
        if not isinstance(pdf_b64, str):
            return JSONResponse({"error": "the engine returned no PDF"}, status_code=502)
        try:
            raw = base64.b64decode(pdf_b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "the engine returned an unreadable PDF"}, status_code=502)
        # Write the REDACTED pdf to the app-data exports dir (never the source tree) and
        # reveal it. Derive a safe name from the upload's basename; never overwrite.
        base = os.path.basename(filename.replace("\\", "/"))
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(base).stem).strip() or "document"
        out_path = _unique_export(f"{safe}.redacted.pdf")
        try:
            out_path.write_bytes(raw)
        except OSError:
            return JSONResponse({"error": "could not save the redacted PDF"}, status_code=500)
        try:
            reveal_in_folder(str(out_path))
        except Exception:  # noqa: BLE001 - reveal is best-effort; the file is already saved
            pass
        # FEATURES A+B+C — the export SURFACE. The redacted file is ALREADY on disk above; the
        # verification + report below can only WARN, never delete/replace it. All of it is
        # best-effort and NEVER raises out (a verification/report failure degrades honestly).
        # `opts`/`accept_ids` here are the EFFECTIVE (possibly Feature-1-augmented) set, so the
        # tallies + verification cover every expanded occurrence.
        try:
            orig_bytes = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            orig_bytes = b""
        cleaned = result.get("cleaned") if isinstance(result.get("cleaned"), list) else []
        not_removed = result.get("not_removed") if isinstance(result.get("not_removed"), list) else []
        try:
            tallies = _pdf_findings(data_b64, accept_ids, opts)
            verification = _verify_pdf_output(
                raw, tallies["accepted_values"], opts,
                coverage=tallies["coverage"], out_path=out_path)
        except Exception:  # noqa: BLE001 - never break the export on the extra checks
            tallies = {"per_recognizer": {}, "findings": 0, "accepted": 0, "rejected": 0}
            verification = exportverify.classify(
                accepted_values=[], extract_failed=True,
                low_text_signals=["the exported file could not be checked after saving"])
        engine_path, engine_sha = _engine_identity()
        report = redactionreport.build_report(
            original_filename=base or "document.pdf",
            original_sha256=redactionreport.sha256_hex(orig_bytes),
            output_filename=out_path.name,
            output_sha256=redactionreport.sha256_hex(raw),
            engine_path=engine_path, engine_sha256=engine_sha,
            options=opts,
            findings=tallies["findings"], accepted=tallies["accepted"],
            rejected=tallies["rejected"], per_recognizer=tallies["per_recognizer"],
            ocr_used=False,
            low_text=bool(result.get("low_text", False)),
            unmapped_fonts=bool(result.get("unmapped_fonts", False)),
            could_not_remove=int(result.get("could_not_remove", 0) or 0),
            cleaned=cleaned, not_removed=not_removed,
            verification=verification, reviewer=_reviewer_name(payload),
            export_kind="pdf", expansion=expansion,
        )
        report_filename, report_txt_filename = _emit_report(out_path, report)
        # TODO (re-identification EXPOSURE meter, PDF residual): unlike the text/paste apply
        # path (which echoes back the redacted text we can re-score for `reid_score_after`),
        # the PDF apply path returns redacted PDF BYTES — re-extracting their text to score
        # the residual is a separate, lossy step (font/layout reconstruction). Until that is
        # wired we DO NOT fabricate an after-score for PDFs (an honest gap beats a made-up
        # number); the UI hides the meter on the PDF flow. The before/after meter is scoped
        # to the text + extract-to-text path for now.
        return JSONResponse(_with_engine_provenance({
            "ok": True,
            "filename": out_path.name,
            "redactions": result.get("redactions", 0),
            "low_text": result.get("low_text", False),
            # HONEST OVER-REPORT GUARD: accepted spans the engine COULD NOT truly remove
            # (no resolvable source bytes — the unmapped-font apply gap). NOT counted in
            # `redactions`; when > 0 the UI MUST warn so the user is never told something
            # was redacted that wasn't. `unmapped_fonts` is forwarded too when present
            # (best-effort-decoded pages → a low count must not read as "clean").
            "could_not_remove": result.get("could_not_remove", 0),
            "unmapped_fonts": result.get("unmapped_fonts", False),
            "diagnostics": result.get("diagnostics", []),
            # FEATURE C — what the engine actually scrubbed this run + its honest gaps.
            "cleaned": cleaned,
            "not_removed": not_removed,
            # FEATURE A — the post-export verification verdict (counts/reasons, no cleartext).
            "verification": verification,
            # FEATURE B — the workflow-record filename written beside the export (or None).
            "report_filename": report_filename,
            # The readable .report.txt name — the Report stage's "View report" opens it.
            "report_txt_filename": report_txt_filename,
            # FEATURE 1 — which export mode ran + how many additional occurrences were removed.
            "expansion": expansion,
        }))

    @router.post("/api/redaction/pdf-ocr-apply", dependencies=_TOKEN_GUARD)
    @releaseflow.prepare_export
    def api_redaction_pdf_ocr_apply(payload: dict = Body(...)):
        # SCANNED-PDF image redaction: OCR each text-less page, detect identifiers via
        # the shared engine, and BURN black boxes into a flat raster (true pixel
        # removal). Writes the redacted PDF to exports + reveals it (like pdf-apply).
        data_b64, err = _redaction_file_bytes(payload)
        if err:
            return err
        from . import imageredact, ocr

        # FAIL-CLOSED: both engines must be present. An absent OCR engine must NEVER
        # yield a silently-unredacted "redacted" PDF.
        if not ocr.available():
            return JSONResponse(
                {"error": "OCR engine (Tesseract) is not installed on this machine."},
                status_code=503,
            )
        if not redactionmodel.available():
            return JSONResponse(
                {"error": "The redaction engine is not installed on this machine."},
                status_code=503,
            )
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "invalid file data"}, status_code=400)
        filename = (payload or {}).get("filename", "")
        if not isinstance(filename, str):
            filename = ""

        # Detector adapter: OCR'd page text -> identifier spans via the SHARED engine
        # (redact-cli scan). A scan error aborts the WHOLE op (fail-closed) so a
        # partially-redacted PDF is never written.
        class _ScanFailed(Exception):
            pass

        opts = _redaction_options(payload)

        def scan_spans(text):
            if not text.strip():
                return []
            res = redactionmodel.scan(text, opts)
            if "error" in res:
                raise _ScanFailed(res["error"])
            # FEATURE 3 (advisory-parity): the OCR burn path used to include EVERY candidate,
            # so an aggressive/advisory recognizer hit (default-OFF on the born-digital text +
            # format-preserving PDF paths) was burned by default here — the SAME document
            # treated two ways diverged. Align on the text path's DEFAULT set (advisory
            # excluded); the engine still SURFACES advisory hits for opt-in elsewhere.
            return _default_spans_from_scan(res)

        try:
            out_bytes, report = imageredact.redact_scanned_pdf(raw, scan_spans, ocr_fn=ocr.ocr_words)
        except _ScanFailed:
            return JSONResponse(
                {"error": "the redaction engine failed while scanning OCR'd text"},
                status_code=502,
            )
        except Exception:  # noqa: BLE001 - never leak an internal error / never crash
            return JSONResponse({"error": "could not OCR-redact the PDF"}, status_code=500)
        if out_bytes is None:
            return JSONResponse(
                {"error": (report or {}).get("error", "could not redact the PDF")},
                status_code=400,
            )
        # Coerce the counts BEFORE writing the file, so a (hypothetical) bad value can't
        # raise a 500 AFTER the redacted PDF is already saved + revealed.
        keys = ("pages", "scanned", "redacted_pages", "boxes", "digital_skipped", "ocr_empty_pages", "mixed_pages")
        try:
            counts = {k: int(report.get(k, 0)) for k in keys}
        except (TypeError, ValueError):
            counts = {k: 0 for k in keys}
        # Honest per-page OCR-quality signal ("page N scanned poorly") — ints only.
        counts["low_conf_pages"] = _sanitized_low_conf_pages(report)
        base = os.path.basename(filename.replace("\\", "/"))
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(base).stem).strip() or "document"
        out_path = _unique_export(f"{safe}.redacted.pdf")
        try:
            out_path.write_bytes(out_bytes)
        except OSError:
            return JSONResponse({"error": "could not save the redacted PDF"}, status_code=500)
        try:
            reveal_in_folder(str(out_path))
        except Exception:  # noqa: BLE001 - reveal is best-effort; the file is saved
            pass
        extras = _finalize_ocr_export(out_path, out_bytes, raw, counts, opts, _reviewer_name(payload))
        return JSONResponse(_with_engine_provenance(
            {"ok": True, "filename": out_path.name, "report": counts, **extras}))

    @router.post("/api/redaction/pdf-ocr-scan", dependencies=_TOKEN_GUARD)
    def api_redaction_pdf_ocr_scan(payload: dict = Body(...)):
        # Per-span review SCAN: OCR + detect each scanned page and return page previews +
        # candidate boxes (page-fraction coords) for the reviewer to accept/reject before
        # applying. Previews/labels are matter data returned in the response only.
        data_b64, err = _redaction_file_bytes(payload)
        if err:
            return err
        from . import imageredact, ocr

        if not ocr.available():
            return JSONResponse(
                {"error": "OCR engine (Tesseract) is not installed on this machine."}, status_code=503
            )
        if not redactionmodel.available():
            return JSONResponse(
                {"error": "The redaction engine is not installed on this machine."}, status_code=503
            )
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "invalid file data"}, status_code=400)

        class _ScanFailed(Exception):
            pass

        opts = _redaction_options(payload)

        def scan_spans_labeled(text):
            if not text.strip():
                return []
            res = redactionmodel.scan(text, opts)
            if "error" in res:
                raise _ScanFailed(res["error"])
            # FEATURE 3 completion (advisory-parity, REVIEW shape): SURFACE advisory
            # (aggressive-recognizer) hits with their flag so the scanned review can show them
            # DEFAULT-OFF — exactly like the born-digital review (shown, marked, opt-in). The
            # one-shot burn path (scan_spans above) still EXCLUDES them (no review step there).
            return _review_spans_from_scan(res)

        try:
            pages, report = imageredact.scan_scanned_pdf(raw, scan_spans_labeled, ocr_fn=ocr.ocr_words)
        except _ScanFailed:
            return JSONResponse(
                {"error": "the redaction engine failed while scanning OCR'd text"}, status_code=502
            )
        except Exception:  # noqa: BLE001 - never leak internals / never crash
            return JSONResponse({"error": "could not scan the PDF"}, status_code=500)
        if pages is None:
            return JSONResponse(
                {
                    "error": (report or {}).get("error", "could not scan the PDF"),
                    "too_many": bool((report or {}).get("too_many")),
                },
                status_code=400,
            )
        keys = ("pages", "scanned", "digital_skipped", "ocr_empty_pages", "candidates")
        rep = {k: int(report.get(k, 0)) for k in keys}
        rep["low_conf_pages"] = _sanitized_low_conf_pages(report)
        return JSONResponse(_with_engine_provenance(
            {"ok": True, "pages": pages, "report": rep}
        ))

    @router.post("/api/redaction/pdf-ocr-apply-selection", dependencies=_TOKEN_GUARD)
    @releaseflow.prepare_export
    def api_redaction_pdf_ocr_apply_selection(payload: dict = Body(...)):
        # Per-span review APPLY: burn ONLY the accepted candidate rects (page-fraction
        # coords) into the scanned pages + save. The server re-classifies pages; the client
        # only chooses WHICH boxes to burn. No OCR/detection here — pure raster + burn.
        data_b64, err = _redaction_file_bytes(payload)
        if err:
            return err
        from . import imageredact

        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "invalid file data"}, status_code=400)
        filename = (payload or {}).get("filename", "")
        if not isinstance(filename, str):
            filename = ""

        # Parse + bound the accepted selection: {page_index: [[fx0,fy0,fx1,fy1], ...]}.
        accepted_in = (payload or {}).get("accepted", {})
        accepted = {}
        total = 0
        if isinstance(accepted_in, dict):
            for k, v in accepted_in.items():
                try:
                    idx = int(k)
                except (TypeError, ValueError):
                    continue
                if not isinstance(v, list):
                    continue
                rects = []
                for fr in v:
                    if isinstance(fr, (list, tuple)) and len(fr) == 4:
                        total += 1
                        if total > imageredact.MAX_SELECTION_RECTS:
                            return JSONResponse({"error": "too many redaction boxes"}, status_code=400)
                        rects.append(fr)
                if rects:
                    accepted[idx] = rects

        # The per-page geometry the scan corrected with (echoed by the client) — the
        # burn must replay it so the accepted fractions land in the reviewed space.
        geo = _sanitized_page_geo(payload)

        try:
            out_bytes, report = imageredact.apply_selection_to_pdf(raw, accepted, geo=geo)
        except Exception:  # noqa: BLE001 - never leak internals / never crash
            return JSONResponse({"error": "could not redact the PDF"}, status_code=500)
        if out_bytes is None:
            return JSONResponse(
                {"error": (report or {}).get("error", "could not redact the PDF")}, status_code=400
            )
        keys = ("pages", "scanned", "redacted_pages", "boxes", "digital_skipped", "mixed_pages")
        try:
            counts = {k: int(report.get(k, 0)) for k in keys}
        except (TypeError, ValueError):
            counts = {k: 0 for k in keys}
        base = os.path.basename(filename.replace("\\", "/"))
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(base).stem).strip() or "document"
        out_path = _unique_export(f"{safe}.redacted.pdf")
        try:
            out_path.write_bytes(out_bytes)
        except OSError:
            return JSONResponse({"error": "could not save the redacted PDF"}, status_code=500)
        try:
            reveal_in_folder(str(out_path))
        except Exception:  # noqa: BLE001 - reveal is best-effort; the file is saved
            pass
        extras = _finalize_ocr_export(
            out_path, out_bytes, raw, counts, _redaction_options(payload), _reviewer_name(payload))
        return JSONResponse(_with_engine_provenance(
            {"ok": True, "filename": out_path.name, "report": counts, **extras}))

    @router.post("/api/redaction/apply", dependencies=_TOKEN_GUARD)
    def api_redaction_apply(payload: dict = Body(...)):
        text, err = _redaction_text(payload)
        if err:
            return err
        # Validate the accept-set: a list of [start, end] non-negative int pairs, capped.
        # Shared validator (REJECTS malformed — same rule as labeled-markdown + batch).
        accept, span_err = _validate_accept_spans((payload or {}).get("accept", []))
        if span_err is not None:
            return JSONResponse({"error": span_err}, status_code=400)
        # The reviewer's chosen replacement style: 'redacted' (flat [REDACTED] marker,
        # default) or 'labels' (AI-safe pseudonymization -> the response also carries a
        # `legend`). Allowlisted by redactionmodel; an unknown value degrades to 'redacted'.
        style = redactionmodel.normalize_replacement_style(
            (payload or {}).get("replacement_style"))
        opts = _redaction_options(payload)
        # FEATURE 1 "Redact accepted values everywhere" (+ FEATURE 2 keep-list exclusion). When
        # ON, run the TWO-PASS expansion (re-derive accepted values server-side, fold them in as
        # TERMS, re-scan, apply the UNION) so every ws-elastic occurrence of an accepted value is
        # removed — never a scattered subset. Pass-2 scan + apply share the augmented options, so
        # parity holds. When OFF, the exact reviewed-only apply (byte-identical to before).
        expansion = _expansion_off()
        if _redact_everywhere_on(payload):
            try:
                new_accept, aug, meta = _expand_text_accept(text, accept, opts, _keep_norms(payload))
            except _TermCapExceeded:
                # `error_kind` marks the CLASS for the UI (an EXPORT-stage refusal, not a
                # scan problem) so it can render apply-specific copy without string-matching.
                return JSONResponse({"error": _TERMS_CAP_MESSAGE,
                                     "error_kind": "terms_cap"}, status_code=400)
            except _ExpandUnderRecovery:
                return JSONResponse({"error": _EXPAND_FAILED_MESSAGE,
                                     "error_kind": "expand_failed"}, status_code=400)
            if new_accept is None:
                return _redaction_response(aug)   # `aug` carries the engine error envelope
            result = redactionmodel.apply(text, new_accept, aug, replacement_style=style)
            expansion = {"on": True, **meta}
        else:
            # Apply MUST use the SAME options as the scan that produced `accept` (the bin
            # re-detects with that engine config, so the spans align). The `labels` legend
            # (label -> real-value map) is cleartext kept LOCAL — never logged, never egressed.
            result = redactionmodel.apply(text, accept, opts, replacement_style=style)
        if isinstance(result, dict) and "error" not in result:
            result["expansion"] = expansion
        # The AFTER side of the re-identification EXPOSURE meter: score the RESIDUAL
        # (redacted) text so the page can show before -> after. Uses the RESIDUAL scorer, which
        # strips the engine's bracketed placeholder tokens (the `labels` style inserts markers
        # like `[Singapore ID]` whose words would otherwise be miscounted as quasi-identifiers).
        # The engine removes named identifiers (emails/IDs/names/cards) but NOT dates/roles/
        # locations/orgs, so `after ~= before` is EXPECTED and is the HONEST message (quasi-
        # identifiers survive removal). Best-effort, count-derived (no cleartext), never breaks
        # apply: a scorer error or a missing `redacted` field simply omits the after-score.
        if isinstance(result, dict) and "error" not in result:
            redacted = result.get("redacted")
            if isinstance(redacted, str):
                try:
                    result["reid_score_after"] = privilege.score_reidentification_residual_dict(redacted)
                except Exception:  # noqa: BLE001 - best-effort; never break apply
                    result.pop("reid_score_after", None)
        return _redaction_response(result)

    @router.post("/api/redaction/text-export", dependencies=_TOKEN_GUARD)
    @releaseflow.prepare_export
    def api_redaction_text_export(payload: dict = Body(...)):
        """Save an ALREADY-REDACTED text to the exports dir in a chosen format, never the
        read-only source tree, never overwriting (the same `_unique_export` the PDF path
        uses), then reveal it.

        The `redacted_text` is the OUTPUT of the prior `apply` (already free of original
        values) — the host does not re-redact here; it only formats + writes. For the
        labeled (AI-safe) style the request also carries the `legend` (label -> original
        value): from it we write a SEPARATE re-identification key file (cleartext, loud
        keep-local banner) that is NEVER embedded in the redacted/labeled document. We log
        NO cleartext here (only counts + the saved filename)."""
        body = payload or {}
        redacted_text = body.get("redacted_text", "")
        if not isinstance(redacted_text, str):
            return JSONResponse({"error": "redacted_text must be a string"}, status_code=400)
        if len(redacted_text.encode("utf-8")) > _REDACT_TEXT_MAX:
            return JSONResponse(
                {"error": f"text exceeds the {_REDACT_TEXT_MAX}-byte limit"}, status_code=400)
        fmt = textexport.normalize_format(body.get("format"))
        labeled = body.get("labeled") is True
        # 2026-07-17 audit item (b): the ORIGINAL text + the accepted spans that produced
        # `redacted_text`, sent by the UI so the post-export check can verify against the
        # REAL accepted values on the flat [REDACTED] flow too (they used to reach the check
        # only in labeled mode via the legend, so a clean flat run was labelled "Post-check:
        # incomplete"). OPTIONAL — a legacy caller that omits them keeps the honest
        # could-not-verify wording. Validated HERE, BEFORE anything is written (a malformed
        # span set fails loud, same rule as /apply); used only below for verification.
        verify_text = body.get("text")
        verify_accept = None
        if verify_text is not None or body.get("accept") is not None:
            if not isinstance(verify_text, str):
                return JSONResponse({"error": "text must be a string"}, status_code=400)
            if len(verify_text.encode("utf-8")) > _REDACT_TEXT_MAX:
                return JSONResponse(
                    {"error": f"text exceeds the {_REDACT_TEXT_MAX}-byte limit"}, status_code=400)
            verify_accept, span_err = _validate_accept_spans(body.get("accept") or [])
            if span_err is not None:
                return JSONResponse({"error": span_err}, status_code=400)
        # FEATURE 1 — the mode the prior /apply ran, echoed back so the WORKFLOW RECORD states
        # which mode ran + how many additional occurrences were removed (the redacted text was
        # already produced by /apply; this route only formats + writes it). Sanitized to the
        # {on, additional, not_expanded} shape; absent -> omitted from the report.
        raw_exp = body.get("expansion")
        expansion = None
        if isinstance(raw_exp, dict):
            raw_reasons = raw_exp.get("not_expanded_reasons")
            expansion = {"on": raw_exp.get("on") is True,
                         "additional_targeted": raw_exp.get("additional_targeted"),
                         "not_expanded": raw_exp.get("not_expanded"),
                         "not_expanded_reasons": raw_reasons if isinstance(raw_reasons, list) else []}
        # Counts for the JSON doc / key — bounded ints; a bad value degrades to 0.
        def _nonneg_int(v):
            return v if (isinstance(v, int) and not isinstance(v, bool) and v >= 0) else 0
        applied = _nonneg_int(body.get("applied"))
        stale = _nonneg_int(body.get("stale"))
        if stale:
            return JSONResponse({"error": "Export blocked: accepted text selections became stale."}, status_code=409)
        # The legend is only meaningful (and only written) in labeled mode. Bound its size;
        # the formatter validates/normalizes each row and drops malformed entries.
        raw_legend = body.get("legend")
        legend = raw_legend[:_EXPORT_LEGEND_MAX] if (labeled and isinstance(raw_legend, list)) else []
        # A base name for the written file(s). Derive a safe stem from a caller-supplied
        # hint or fall back to a generic name; never trust it as a path.
        hint = body.get("filename")
        base = os.path.basename(str(hint).replace("\\", "/")) if isinstance(hint, str) else ""
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(base).stem).strip() or "redacted"

        doc = textexport.build_redacted_document(
            redacted_text, fmt, labeled=labeled, applied=applied, stale=stale, legend=legend)
        # A pasted-text export has no filename hint, so `safe` falls back to "redacted" —
        # blindly appending ".redacted" doubled the marker ("redacted.redacted.txt", then
        # "redacted.redacted (1).txt", …; 2026-07-17 audit cosmetic). Keep it single: the
        # default name is "redacted.txt"; a real stem keeps "<name>.redacted.<ext>". The
        # never-overwrite collision-append is untouched (_unique_export still adds " (n)").
        stem = safe if safe == "redacted" else f"{safe}.redacted"
        out_path = _unique_export(f"{stem}{textexport.suffix_for(fmt)}")
        try:
            out_path.write_bytes(doc.encode("utf-8"))
        except OSError:
            return JSONResponse({"error": "could not save the redacted copy"}, status_code=500)

        # Labeled mode: write the SEPARATE re-identification KEY (cleartext + keep-local
        # banner). NEVER embedded in the document above; its own distinct file. Only when
        # there is at least one label to map. We write JSON when the document is JSON, else a
        # plain-text key (the user-facing default — readable in any editor).
        key_name = None
        key_failed = False
        if labeled and legend:
            if fmt == "json":
                key_doc = textexport.build_key_json(legend)
                key_path = _unique_export(f"{stem}.key.json")
            else:
                key_doc = textexport.build_key_txt(legend)
                key_path = _unique_export(f"{stem}.key.txt")
            try:
                key_path.write_text(key_doc, encoding="utf-8")
                key_name = key_path.name
            except OSError:
                # The redacted document already saved; surface that the key failed rather
                # than failing the whole export (the user still has the AI-safe artifact).
                # The labeled copy is NOT reversible without this key, so the UI must warn
                # loudly — never let a success response imply a recoverable pair exists.
                key_name = None
                key_failed = True
        # Reveal the redacted document (best-effort; the file is already on disk).
        try:
            reveal_in_folder(str(out_path))
        except Exception:  # noqa: BLE001 - reveal is best-effort
            pass
        # FEATURES A+B — verify the written text + write the workflow report. The file is
        # already saved; these can only WARN. Feature C (metadata cleaning) is N/A for a text
        # export — there is no document metadata to scrub — surfaced honestly to the UI.
        opts = _redaction_options(payload)
        # Accepted cleartext values for the post-export check: re-derived server-side from the
        # AUTHORITATIVE original text + accepted spans when the UI sent them (the normal flow
        # — flat AND labeled). A legacy legend-only caller remains incomplete. When neither is
        # available (a legacy caller) the value-search check cannot run and classify() says so
        # honestly. In-process only — never logged, never persisted.
        if verify_accept is not None and isinstance(verify_text, str):
            targets = verificationtargets.from_spans(verify_text, verify_accept)
        else:
            # A legacy legend is evidence of these values, not proof that every
            # accepted decision was reconstructed. Do not trust its length as coverage.
            targets = verificationtargets.from_legend(raw_legend if labeled else None)
        try:
            verification = _verify_text_output(
                doc, targets["accepted_values"], opts, coverage=targets["coverage"],
                out_path=out_path, text_format=fmt)
        except Exception:  # noqa: BLE001 - never break the export
            verification = exportverify.classify(
                accepted_values=[], extract_failed=True,
                low_text_signals=["the redacted text could not be checked after saving"])
        engine_path, engine_sha = _engine_identity()
        report = redactionreport.build_report(
            original_filename=(base or "(pasted text)"),
            original_sha256="",  # the pre-redaction source is not available to this route
            output_filename=out_path.name,
            output_sha256=redactionreport.sha256_hex(doc.encode("utf-8")),
            engine_path=engine_path, engine_sha256=engine_sha,
            options=opts,
            findings=applied, accepted=applied, rejected=stale, per_recognizer={},
            ocr_used=False, low_text=False, unmapped_fonts=False, could_not_remove=0,
            cleaned=[], not_removed=[],
            verification=verification, reviewer=_reviewer_name(payload),
            export_kind="text", expansion=expansion,
        )
        report_filename, report_txt_filename = _emit_report(out_path, report)
        return JSONResponse(_with_engine_provenance({
            "ok": True,
            "filename": out_path.name,
            "format": fmt,
            "labeled": labeled,
            # The key is a SEPARATE artifact (its own filename) or null when not applicable.
            "key_filename": key_name,
            # True ONLY when a key was REQUIRED (labeled + non-empty legend) but its write
            # failed — the labeled copy then cannot be reversed; the UI warns loudly.
            "key_failed": key_failed,
            # FEATURE A — the post-export verification verdict (counts/reasons, no cleartext).
            "verification": verification,
            # FEATURE B — the workflow-record filename written beside the export (or None).
            "report_filename": report_filename,
            # The readable .report.txt name — the Report stage's "View report" opens it.
            "report_txt_filename": report_txt_filename,
            # FEATURE C — metadata cleaning does not apply to a text export (no doc metadata).
            "metadata_na": True,
        }))

    @router.post("/api/redaction/labeled-markdown", dependencies=_TOKEN_GUARD)
    @releaseflow.prepare_export
    def api_redaction_labeled_markdown(payload: dict = Body(...)):
        """Rebuild the reviewed document as a LABELED MARKDOWN working copy for AI-assisted
        drafting — a SECOND, clearly-separated export from the production redacted PDF/copy.

        AI-PREP vs PRODUCTION-PRIVILEGE BOUNDARY (do NOT blur): this artifact is a working
        copy rebuilt from TEXT EXTRACTION with identifiers replaced by LABELS. It is NOT the
        production redacted document; the header says so verbatim.

        SOURCE + ID ALIGNMENT (the parity-critical decision):
          * TEXT-PATH document (pasted / .docx / .eml / .msg / .txt) — the request carries the
            reviewed `text` + the reviewed `accept` spans. The labeled apply re-detects over
            that SAME text with the SAME options, so the reviewed [start,end] spans resolve
            byte-for-byte (the established scan<->apply parity contract). The user's reviewed
            accept-set is honored EXACTLY — scan/review happened once.
          * FILE/PDF bytes (`data_b64`) — there is no text-path reviewed span set (a PDF was
            reviewed on the format-preserving path, whose ids live in a DIFFERENT coordinate
            space). So we run `extract_scan` here and ACCEPT ALL detected identifiers
            (recall-first: over-labeling is the safe side for a working copy — see
            `_spans_from_candidates`). The apply echoes the SAME extract_scan text, so the
            spans align.

        Then: apply with the `labels` style + legend; assemble the Markdown; write
        `<name>.labeled.md` + the SEPARATE `<name>.labelkey.txt` re-identification key (reusing
        the text-export key mechanics EXACTLY — the key is NEVER embedded in the .md); emit the
        standard workflow report (export_kind `labeled-markdown`); and run post-export
        verification on the .md (accepted VALUES must not appear; labels are expected). NO
        cleartext value/term is logged. Never overwrites (the exports-dir no-clobber invariant).

        BATCH increment-1 scope: single-file flow only (batch .md export is deferred)."""
        body = payload or {}
        opts = _redaction_options(payload)
        reviewer = _reviewer_name(payload)
        filename_hint = body.get("filename")
        base = (os.path.basename(str(filename_hint).replace("\\", "/"))
                if isinstance(filename_hint, str) else "")

        source_targets_complete = True
        data_b64 = body.get("data_b64")
        if isinstance(data_b64, str) and data_b64:
            # FILE/PDF shape: extract text HERE, then accept ALL detected identifiers.
            if len(data_b64) > _REDACT_FILE_B64_MAX:
                return JSONResponse({"error": "file is too large to redact here"}, status_code=400)
            ext_name = base or "document"
            ext = redactionmodel.extract_scan(ext_name, data_b64, opts)
            if not isinstance(ext, dict) or "error" in ext:
                return _redaction_response(ext if isinstance(ext, dict)
                                           else {"error": "the file could not be read as text"})
            text = ext.get("text") if isinstance(ext.get("text"), str) else ""
            if len(text.encode("utf-8")) > _REDACT_TEXT_MAX:
                return JSONResponse(
                    {"error": "The extracted text is too large to redact here."}, status_code=400)
            source_candidates = ext.get("candidates")
            accept = _spans_from_candidates(source_candidates)
            source_targets_complete = (
                isinstance(source_candidates, list) and len(accept) == len(source_candidates)
                and isinstance(ext.get("text"), str) and not ext.get("warnings"))
            try:
                orig_bytes = base64.b64decode(data_b64, validate=True)
            except (binascii.Error, ValueError):
                orig_bytes = b""
            source_sha = redactionreport.sha256_hex(orig_bytes)
            source_name = base or "(document)"
        else:
            # TEXT-PATH shape: the reviewed text + reviewed accept spans (honored exactly).
            text, err = _redaction_text(payload)
            if err:
                return err
            # REJECT a malformed span (do NOT silently drop): a dropped span would leave an
            # identifier as cleartext in this AI working copy — a leak-class miss.
            accept, span_err = _validate_accept_spans(body.get("accept", []))
            if span_err is not None:
                return JSONResponse({"error": span_err}, status_code=400)
            source_sha = redactionreport.sha256_hex(text.encode("utf-8"))
            source_name = base or "(pasted text)"

        # FEATURE 1 — when ON, expand the accept-set so every ws-elastic occurrence of an
        # accepted value is labeled too (never a scattered subset in the AI working copy). Both
        # source shapes converge to text + accept + opts, so the SAME two-pass driver applies;
        # the augmented opts flow into the apply + the post-export verification below (parity).
        expansion = _expansion_off()
        if _redact_everywhere_on(payload):
            try:
                new_accept, aug, meta = _expand_text_accept(text, accept, opts, _keep_norms(payload))
            except _TermCapExceeded:
                # `error_kind` marks the CLASS for the UI (an EXPORT-stage refusal, not a
                # scan problem) so it can render apply-specific copy without string-matching.
                return JSONResponse({"error": _TERMS_CAP_MESSAGE,
                                     "error_kind": "terms_cap"}, status_code=400)
            except _ExpandUnderRecovery:
                return JSONResponse({"error": _EXPAND_FAILED_MESSAGE,
                                     "error_kind": "expand_failed"}, status_code=400)
            if new_accept is None:
                return _redaction_response(aug)   # engine error envelope
            accept, opts = new_accept, aug
            expansion = {"on": True, **meta}
        # ONE engine call, the labels style -> labeled text + the label->value legend
        # (cleartext, used ONLY to write the separate key file below; never logged/echoed).
        apply_res = redactionmodel.apply(text, accept, opts, replacement_style="labels")
        if not isinstance(apply_res, dict) or "error" in apply_res:
            return _redaction_response(apply_res if isinstance(apply_res, dict)
                                       else {"error": "the engine could not build the copy"})
        labeled_text = apply_res.get("redacted") if isinstance(apply_res.get("redacted"), str) else ""
        legend = apply_res.get("legend") if isinstance(apply_res.get("legend"), list) else []
        legend = legend[:_EXPORT_LEGEND_MAX]

        def _nonneg_int(v):
            return v if (isinstance(v, int) and not isinstance(v, bool) and v >= 0) else 0
        applied = _nonneg_int(apply_res.get("applied"))
        stale = _nonneg_int(apply_res.get("stale"))
        if stale:
            return JSONResponse({"error": "Export blocked: accepted text selections became stale."}, status_code=409)

        # Assemble the Markdown. extract_scan surfaces NO page boundaries (pages are joined
        # with a bare newline), so `pages=None` -> an honest single flow, NO fake page markers.
        generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        md = textexport.build_labeled_markdown(
            labeled_text,
            source_filename=source_name, source_sha256=source_sha,
            generated_utc=generated_utc, app_version=__version__,
        )
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(base).stem).strip() or "document"
        out_path = _unique_export(f"{safe}.labeled.md")
        try:
            out_path.write_bytes(md.encode("utf-8"))
        except OSError:
            return JSONResponse({"error": "could not save the labeled copy"}, status_code=500)

        # The SEPARATE re-identification KEY (cleartext + keep-local banner) — reusing the
        # text-export key mechanics EXACTLY. NEVER embedded in the .md; its own file; only when
        # there is at least one label to map.
        key_name = None
        key_failed = False
        if legend:
            key_doc = textexport.build_key_txt(legend)
            key_path = _unique_export(f"{safe}.labelkey.txt")
            try:
                key_path.write_text(key_doc, encoding="utf-8")
                key_name = key_path.name
            except OSError:
                # The .md is saved but cannot be reversed without the key — warn loudly.
                key_name = None
                key_failed = True
        try:
            reveal_in_folder(str(out_path))
        except Exception:  # noqa: BLE001 - reveal is best-effort; the file is already saved
            pass

        # Reconstruct targets from the source/effective decisions, NOT the capped
        # legend: omitted or stale legend rows cannot erase verification targets.
        targets = verificationtargets.from_spans(text, accept)
        targets["coverage"]["complete"] &= source_targets_complete
        try:
            verification = _verify_text_output(
                md, targets["accepted_values"], opts, coverage=targets["coverage"],
                out_path=out_path, text_format="md")
        except Exception:  # noqa: BLE001 - never break the export on a verification hiccup
            verification = exportverify.classify(
                accepted_values=[], extract_failed=True,
                low_text_signals=["the labeled copy could not be checked after saving"])
        engine_path, engine_sha = _engine_identity()
        report = redactionreport.build_report(
            original_filename=source_name,
            original_sha256=source_sha,
            output_filename=out_path.name,
            output_sha256=redactionreport.sha256_hex(md.encode("utf-8")),
            engine_path=engine_path, engine_sha256=engine_sha, options=opts,
            findings=applied, accepted=applied, rejected=stale, per_recognizer={},
            ocr_used=False, low_text=False, unmapped_fonts=False, could_not_remove=0,
            cleaned=[], not_removed=[], verification=verification,
            reviewer=reviewer, export_kind="labeled-markdown", expansion=expansion,
        )
        report_filename, report_txt_filename = _emit_report(out_path, report)
        return JSONResponse(_with_engine_provenance({
            "ok": True,
            "filename": out_path.name,
            "kind": "labeled-markdown",
            "expansion": expansion,
            # The re-identification key is a SEPARATE artifact (its own filename) or null.
            "key_filename": key_name,
            # True ONLY when a key was REQUIRED (non-empty legend) but its write failed — the
            # labeled copy then cannot be reversed; the UI warns loudly.
            "key_failed": key_failed,
            "verification": verification,
            "report_filename": report_filename,
            "report_txt_filename": report_txt_filename,
            # No document metadata to scrub in a rebuilt .md — flagged N/A like the text export.
            "metadata_na": True,
        }))

    @router.post("/api/redaction/open-export", dependencies=_TOKEN_GUARD)
    def api_redaction_open_export(payload: dict = Body(...)):
        """Reveal (in the OS file manager) OR open a file that a prior export WROTE — the
        Report stage's "Open folder" / "View report" actions.

        CONFINEMENT (the read-only / no-escape invariant): the caller supplies ONLY a bare
        filename; we reject any path component, resolve it strictly inside the exports dir,
        and refuse anything that resolves outside it or does not exist. The page never touches
        the filesystem itself — this is the one brokered reveal/open. `LAWDATAMAN_DISABLE_OS_OPEN`
        makes the actual reveal/open a no-op (tests/CI), so this route is drivable headless."""
        name = (payload or {}).get("filename", "")
        if not isinstance(name, str) or not name.strip():
            return JSONResponse({"error": "filename is required"}, status_code=400)
        # Reject NUL / control characters BEFORE any Path/resolve() call — an embedded NUL
        # makes Path.resolve() raise an uncaught ValueError ("embedded null byte") on POSIX,
        # which would otherwise surface as a 500 instead of the honest invalid-filename 400.
        if any(ord(ch) < 0x20 or ch == "\x7f" for ch in name):
            return JSONResponse({"error": "invalid filename"}, status_code=400)
        # Legacy bare filenames and receipt-bound release-package files only.
        parts = name.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in parts):
            return JSONResponse({"error": "invalid filename"}, status_code=400)
        action = (payload or {}).get("action", "reveal")
        if action not in ("reveal", "open"):
            action = "reveal"
        ed = exports_dir().resolve()
        target = (ed / name).resolve()
        if not target.is_relative_to(ed) or not target.is_file():
            return JSONResponse({"error": "that file is not in the exports folder"}, status_code=404)
        if len(parts) > 1:
            if not re.fullmatch(r"release-[0-9]{8}-[0-9]{6}-[0-9a-f]{16}", parts[0]):
                return JSONResponse({"error": "invalid release package"}, status_code=400)
            try:
                import json
                package = ed / parts[0]
                receipt = json.loads((package / "release-receipt.json").read_text(encoding="utf-8"))
                rel = "/".join(parts[1:])
                expected = receipt["files"][rel]["sha256"]
                if redactionreport._sha256_of_file(target) != expected:
                    raise ValueError("changed release")
            except (OSError, ValueError, KeyError, TypeError):
                return JSONResponse({"error": "released file is not receipt-bound or has changed"}, status_code=409)
        elif target.parent != ed:
            return JSONResponse({"error": "invalid filename"}, status_code=400)
        try:
            if action == "open":
                open_path(str(target))
            else:
                reveal_in_folder(str(target))
        except Exception:  # noqa: BLE001 - reveal/open is best-effort; never 500
            return JSONResponse({"error": "could not open that file"}, status_code=500)
        return JSONResponse({"ok": True})

    # ============================================================ TERMS import ====
    @router.post("/api/redaction/import-terms", dependencies=_TOKEN_GUARD)
    def api_redaction_import_terms(payload: dict = Body(...)):
        """Parse an uploaded .csv/.txt list of party / names into normalized redaction TERMS
        (the "Import list…" affordance). Returns `{ok, terms, imported, duplicates, dropped}`;
        the page MERGES `terms` into the textarea (which stays the source of truth) and shows
        the honest counts. NO cleartext is logged — a term is a party NAME (see
        redactionmodel.parse_imported_terms). Same base64 upload shape as the scan routes, with
        a tighter size cap (a names list is small)."""
        data_b64 = (payload or {}).get("data_b64", "")
        filename = (payload or {}).get("filename", "")
        if not isinstance(data_b64, str) or not data_b64:
            return JSONResponse({"error": "file data is required"}, status_code=400)
        if len(data_b64) > _IMPORT_TERMS_B64_MAX:
            return JSONResponse(
                {"error": "That list is too large to import. Split it into a smaller file."},
                status_code=400)
        if not isinstance(filename, str):
            filename = ""
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "invalid file data"}, status_code=400)
        base = os.path.basename(filename.replace("\\", "/")) or filename
        result = redactionmodel.parse_imported_terms(base, raw)
        return JSONResponse({"ok": True, **result})

    # ============================================================= BATCH (folder) ==
    @router.post("/api/redaction/batch/enumerate", dependencies=_TOKEN_GUARD)
    def api_redaction_batch_enumerate(payload: dict = Body(...)):
        """List the supported, in-scope files under a chosen FOLDER (estimate+confirm before a
        batch runs). Applies the ingestion safety policy (refuses a drive/OS/app-data root) and
        the batch caps (file count, per-file size, supported extensions), skipping cloud-offline
        placeholders WITHOUT opening them. READ-ONLY on the source folder. See
        app/batchredact.enumerate_folder."""
        folder = (payload or {}).get("folder", "")
        if not isinstance(folder, str) or not folder.strip():
            return JSONResponse({"error": "no folder given"}, status_code=400)
        result = batchredact.enumerate_folder(folder.strip())
        if not result.get("ok"):
            # A refused root (drive/OS/app-data) or a non-folder — 400 with the honest reason.
            return JSONResponse(result, status_code=400)
        return JSONResponse(result)

    @router.post("/api/redaction/batch/scan-file", dependencies=_TOKEN_GUARD)
    def api_redaction_batch_scan_file(payload: dict = Body(...)):
        """Scan ONE confined file in a batch for the QUEUE (findings count + honest flags), the
        server reading the source by path (the browser can't). Returns
        `{ok, kind, findings, low_text, unmapped_fonts}` — meta only, no candidates/bytes (the
        per-file review re-reads via /batch/read-file and runs the normal scan). A read/scan
        failure returns `{error, scan_failed:true}` so the file's queue row shows an error (it
        is then EXCLUDED from batch export, never silently skipped)."""
        folder = (payload or {}).get("folder", "")
        rel = (payload or {}).get("rel", "")
        if not isinstance(folder, str) or not isinstance(rel, str):
            return JSONResponse({"error": "folder and rel are required", "scan_failed": True},
                                status_code=400)
        raw, err = batchredact.read_confined(folder, rel)
        if raw is None:
            return JSONResponse({"error": err or "could not read the file", "scan_failed": True},
                                status_code=400)
        opts = _redaction_options(payload)
        name = os.path.basename(rel.replace("\\", "/")) or rel
        data_b64 = base64.b64encode(raw).decode("ascii")
        is_pdf = name.lower().endswith(".pdf")
        if is_pdf:
            res = redactionmodel.pdf_scan(data_b64, opts)
        else:
            res = redactionmodel.extract_scan(name, data_b64, opts)
        if not isinstance(res, dict) or "error" in res:
            return JSONResponse(_with_engine_provenance(
                {"error": (res or {}).get("error", "the engine could not scan the file"),
                 "scan_failed": True}), status_code=503)
        cands = res.get("candidates") if isinstance(res.get("candidates"), list) else []
        return JSONResponse(_with_engine_provenance({
            "ok": True,
            "kind": "pdf" if is_pdf else "text",
            "findings": len(cands),
            "low_text": bool(res.get("low_text", False)),
            "unmapped_fonts": bool(res.get("unmapped_fonts", False)),
        }))

    @router.post("/api/redaction/batch/read-file", dependencies=_TOKEN_GUARD)
    def api_redaction_batch_read_file(payload: dict = Body(...)):
        """Return ONE confined file's bytes (base64) so the page can load it into the EXISTING
        per-file review flow (build a File -> the normal scan/review/apply path, which keeps the
        provenance + gate discipline intact). READ-ONLY + CONFINED (batchredact.resolve_confined
        refuses any `..`/symlink escape). One file at a time — bounded by the per-file size cap."""
        folder = (payload or {}).get("folder", "")
        rel = (payload or {}).get("rel", "")
        if not isinstance(folder, str) or not isinstance(rel, str):
            return JSONResponse({"error": "folder and rel are required"}, status_code=400)
        raw, err = batchredact.read_confined(folder, rel)
        if raw is None:
            return JSONResponse({"error": err or "could not read the file"}, status_code=400)
        name = os.path.basename(rel.replace("\\", "/")) or rel
        return JSONResponse({
            "ok": True,
            "filename": name,
            "kind": "pdf" if name.lower().endswith(".pdf") else "text",
            "data_b64": base64.b64encode(raw).decode("ascii"),
        })

    @router.post("/api/redaction/batch/export", dependencies=_TOKEN_GUARD)
    @releaseflow.prepare_export
    def api_redaction_batch_export(payload: dict = Body(...)):
        """Redact + write the files the client SENDS into a fresh never-overwrite subdir of the
        exports dir, and write a batch-summary report. HONEST scope of enforcement: "reviewed-only"
        is a CLIENT-side gate (the UI only submits files the user reviewed+acked); the server
        redacts exactly the spec it is handed and does NOT re-verify review state — consistent with
        the settled "the app is NOT the security boundary" decision (single local user). The
        summary is where honesty is load-bearing: it reports each file's accepted count and the
        post-export verification verdict, so a file submitted with an empty accept-set is recorded
        as accepted=0 + could_not_fully_verify, never as clean. Files that fail to read/redact are
        EXCLUDED from the outputs and listed (with a reason) in the summary — never silently
        skipped. NEVER writes to the source tree (batchredact.batch_output_dir). See
        _run_batch_export."""
        folder = (payload or {}).get("folder", "")
        if not isinstance(folder, str) or not folder.strip():
            return JSONResponse({"error": "no folder given"}, status_code=400)
        files = (payload or {}).get("files", [])
        if not isinstance(files, list) or not files:
            return JSONResponse(
                {"error": "no reviewed files to export"}, status_code=400)
        if len(files) > _BATCH_EXPORT_MAX_FILES:
            return JSONResponse(
                {"error": f"too many files (max {_BATCH_EXPORT_MAX_FILES})"}, status_code=400)
        batch_name = (payload or {}).get("batch_name", "")
        if not isinstance(batch_name, str):
            batch_name = ""
        reviewer = _reviewer_name(payload)
        # FEATURE 1 (per-batch toggle) + FEATURE 2 (per-batch keep list).
        result = _run_batch_export(folder.strip(), batch_name, files, reviewer,
                                   _redact_everywhere_on(payload), _keep_norms(payload))
        return JSONResponse(_with_engine_provenance(result))

    from . import documentreview
    documentreview.install_routes(router, require_token)
    releaseflow.install_routes(router, require_token)
    return router
