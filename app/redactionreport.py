"""
The per-export REDACTION REPORT (feature B): a workflow record written ALONGSIDE every
redacted copy.

For each successful export we write ``<output>.report.json`` (machine-readable) and a small
``<output>.report.txt`` (human-readable) into the SAME exports dir, via the SAME
never-overwrite mechanics as the redacted file itself. The report records WHAT the tool did:
the original + output filenames and their SHA-256, a UTC timestamp, the app version, the
engine identity (the ``redact-cli`` path + its SHA-256), the options used (locales / context
/ profiles / toggles — and the term COUNT, NEVER the term cleartext), the findings /
accepted / rejected counts, the per-recognizer counts, whether OCR was used, the warnings
(low-text / unmapped fonts), the ``could_not_remove`` count, what document structure was
``cleaned`` vs ``not_removed``, the post-export verification verdict (feature A), and an
OPTIONAL reviewer name.

HONESTY (load-bearing): the report header states plainly that this is a *workflow record
generated locally*, NOT a tamper-evident audit log — the durable, HMAC-chained audit trail
is the owed ``audit-store`` path, and this file must never be mistaken for it. Nothing here
claims a copy is "safe"/"verified".

CONFIDENTIALITY: NO cleartext matter value is written — not a matched value, not a user
TERM (only its count), not the accepted values that feature A checked (only class counts).
Deterministic + stdlib-only (``hashlib`` + ``json`` + ``datetime``); no network, no model.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from . import __version__

REPORT_SCHEMA = "lawbat.redaction-report/0"
BATCH_SCHEMA = "lawbat.redaction-batch-summary/0"

# The honest header note — the FIRST thing a reader sees in both the JSON and the text
# report. States what this file IS (a local workflow record) and what it is NOT (a
# tamper-evident audit log), so no one relies on it as the durable compliance trail.
REPORT_NOTE = (
    "workflow record generated locally; not a tamper-evident audit log"
)


def sha256_hex(data: bytes) -> str:
    """SHA-256 of ``data`` as lowercase hex. A tiny, stdlib-only helper the routes reuse for
    the original + output byte hashes (so the report's hashes are computed the SAME way)."""
    return hashlib.sha256(data if isinstance(data, (bytes, bytearray)) else b"").hexdigest()


def _sha256_of_file(path) -> str | None:
    """SHA-256 of a file's bytes (for the engine identity), or ``None`` if it can't be read.
    Best-effort — a missing/unreadable engine bin just omits the hash rather than failing the
    whole report."""
    try:
        with open(path, "rb") as fh:
            h = hashlib.sha256()
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
            return h.hexdigest()
    except OSError:
        return None


def _options_summary(options: dict | None) -> dict:
    """The NON-cleartext view of the sanitized engine options for the report. Carries the
    pack selections + toggles verbatim, but reduces the user TERMS to a COUNT only (a term is
    a party/company NAME — cleartext that must never land in a written file)."""
    o = options if isinstance(options, dict) else {}
    terms = o.get("terms")
    return {
        "locales": list(o.get("locales", []) or []),
        "profiles": list(o.get("profiles", []) or []),
        "context": bool(o.get("context", False)),
        "lei": bool(o.get("lei", False)),
        "sg_nric_loose": bool(o.get("sg_nric_loose", False)),
        "disable_builtins": list(o.get("disable_builtins", []) or []),
        # COUNT ONLY — never the term strings themselves.
        "term_count": len(terms) if isinstance(terms, (list, tuple)) else 0,
    }


def build_report(
    *,
    original_filename: str,
    original_sha256: str,
    output_filename: str,
    output_sha256: str,
    engine_path: str | None,
    engine_sha256: str | None,
    options: dict | None,
    findings: int,
    accepted: int,
    rejected: int,
    per_recognizer: dict | None,
    ocr_used: bool,
    low_text: bool,
    unmapped_fonts: bool,
    could_not_remove: int,
    cleaned=None,
    not_removed=None,
    verification: dict | None = None,
    reviewer: str | None = None,
    export_kind: str = "pdf",
    expansion: dict | None = None,
) -> dict:
    """Assemble the report dict (see the module docstring for the field contract). Pure /
    deterministic except the UTC timestamp; NEVER embeds a cleartext matter value. An empty
    / whitespace-only ``reviewer`` is OMITTED (the field is absent, not blank).

    ``expansion`` (Feature 1 "Redact accepted values everywhere") is an OPTIONAL
    ``{"on": bool, "additional_targeted": int, "not_expanded": int, "not_expanded_reasons":
    [str]}`` record of which export mode ran and, when ON, how many ADDITIONAL ws-elastic
    occurrences of accepted values were TARGETED for removal (selection-time COUNTS only —
    never a value; 'targeted', not 'removed': actual removal is reconciled against
    ``could_not_remove`` in the rendering, never claimed blindly). Omitted entirely when
    ``None`` (byte-identical to before for callers that do not pass it)."""
    def _int(v):
        return v if (isinstance(v, int) and not isinstance(v, bool) and v >= 0) else 0

    report = {
        "schema": REPORT_SCHEMA,
        "note": REPORT_NOTE,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "app_version": __version__,
        "export_kind": str(export_kind),
        "engine": {
            "redact_cli_path": engine_path if isinstance(engine_path, str) else None,
            "redact_cli_sha256": engine_sha256 if isinstance(engine_sha256, str) else None,
        },
        "original": {
            "filename": str(original_filename),
            "sha256": str(original_sha256),
        },
        "output": {
            "filename": str(output_filename),
            "sha256": str(output_sha256),
        },
        "options": _options_summary(options),
        "findings": _int(findings),
        "accepted": _int(accepted),
        "rejected": _int(rejected),
        "per_recognizer": {
            str(k): _int(v) for k, v in (per_recognizer or {}).items()
        },
        "ocr_used": bool(ocr_used),
        "warnings": {
            "low_text": bool(low_text),
            "unmapped_fonts": bool(unmapped_fonts),
        },
        "could_not_remove": _int(could_not_remove),
        "cleaned": [str(x) for x in (cleaned or [])],
        "not_removed": [str(x) for x in (not_removed or [])],
        "verification": verification if isinstance(verification, dict) else {},
    }
    if isinstance(expansion, dict):
        raw_reasons = expansion.get("not_expanded_reasons")
        report["expansion"] = {
            "on": bool(expansion.get("on", False)),
            "additional_targeted": _int(expansion.get("additional_targeted", 0)),
            "not_expanded": _int(expansion.get("not_expanded", 0)),
            # Value-free reason strings (counts + why), bounded so a hostile echo can't balloon.
            "not_expanded_reasons": [str(x) for x in raw_reasons][:10]
            if isinstance(raw_reasons, list) else [],
        }
    if isinstance(reviewer, str) and reviewer.strip():
        # Bound the reviewer name so a hostile client can't balloon the file; it is a NAME.
        report["reviewer"] = reviewer.strip()[:200]
    return report


def to_json(report: dict) -> str:
    """The machine-readable report: sorted keys, UTF-8, trailing newline. Deterministic for a
    fixed report dict (aside from its timestamp)."""
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _fmt_list(xs) -> str:
    xs = [str(x) for x in (xs or [])]
    return ", ".join(xs) if xs else "(none)"


def _verification_line(verification: dict | None) -> list[str]:
    v = verification if isinstance(verification, dict) else {}
    state = v.get("state", "")
    lines = [f"Post-export check: {state or '(not run)'}"]
    classes = v.get("classes") or {}
    if classes:
        pairs = ", ".join(f"{k}={classes[k]}" for k in sorted(classes))
        lines.append(f"  possible residual classes: {pairs}")
    for r in (v.get("reasons") or []):
        lines.append(f"  reason: {r}")
    coverage = v.get("coverage") or {}
    if coverage:
        lines.append(f"  target decisions resolved: {coverage.get('resolved', 0)} / "
                     f"{coverage.get('requested', 0)}; complete: {coverage.get('complete', False)}")
    rust = v.get("rust") or {}
    if rust:
        lines.append(f"  Rust recovery probes: {rust.get('status', 'unavailable')}")
    if rust.get("status") == "completed":
        lines.append(f"  probed output SHA-256: {rust['artifact_sha256']}")
        lines.append(f"  values probed: {rust['values_probed']}")
        lines.append(f"  recovery vectors: {_fmt_list(rust.get('vectors'))}")
        lines.append(f"  NOT probed: {_fmt_list(rust.get('not_probed'))}")
        lines.append(f"  skipped/limited-work diagnostics: {rust.get('diagnostic_count', 0)}")
    if rust:
        lines.append("  No recovery finding is not proof of removal; undetected values are outside scope.")
    return lines


def to_text(report: dict) -> str:
    """A small, human-readable rendering of the report — readable in any editor, no markup.
    Mirrors the JSON fields; contains NO cleartext value (same guarantee as the JSON)."""
    r = report if isinstance(report, dict) else {}
    eng = r.get("engine", {}) or {}
    opt = r.get("options", {}) or {}
    warn = r.get("warnings", {}) or {}
    orig = r.get("original", {}) or {}
    out = r.get("output", {}) or {}
    per = r.get("per_recognizer", {}) or {}
    lines: list[str] = []
    lines.append("Lawbat redaction report")
    lines.append(f"({r.get('note', REPORT_NOTE)})")
    lines.append("=" * 60)
    lines.append(f"Generated (UTC): {r.get('generated_utc', '')}")
    lines.append(f"App version:     {r.get('app_version', '')}")
    lines.append(f"Export kind:     {r.get('export_kind', '')}")
    if r.get("reviewer"):
        lines.append(f"Reviewer:        {r.get('reviewer')}")
    lines.append("")
    lines.append(f"Original file:   {orig.get('filename', '')}")
    lines.append(f"  SHA-256:       {orig.get('sha256', '')}")
    lines.append(f"Output file:     {out.get('filename', '')}")
    lines.append(f"  SHA-256:       {out.get('sha256', '')}")
    lines.append("")
    lines.append(f"Engine:          {eng.get('redact_cli_path') or '(unknown)'}")
    lines.append(f"  SHA-256:       {eng.get('redact_cli_sha256') or '(unavailable)'}")
    lines.append("")
    lines.append("Options used:")
    lines.append(f"  jurisdictions: {_fmt_list(opt.get('locales'))}")
    lines.append(f"  profiles:      {_fmt_list(opt.get('profiles'))}")
    lines.append(f"  context:       {opt.get('context', False)}")
    lines.append(f"  LEI:           {opt.get('lei', False)}")
    lines.append(f"  SG NRIC loose: {opt.get('sg_nric_loose', False)}")
    lines.append(f"  disabled:      {_fmt_list(opt.get('disable_builtins'))}")
    lines.append(f"  custom terms:  {opt.get('term_count', 0)}")
    lines.append("")
    lines.append(f"Findings:        {r.get('findings', 0)}")
    lines.append(f"  accepted:      {r.get('accepted', 0)}")
    lines.append(f"  rejected:      {r.get('rejected', 0)}")
    if per:
        lines.append("  by recognizer:")
        for k in sorted(per):
            lines.append(f"    {k}: {per[k]}")
    lines.append(f"OCR used:        {r.get('ocr_used', False)}")
    lines.append(f"Could not remove:{r.get('could_not_remove', 0)}")
    lines.append(f"Warnings:        low_text={warn.get('low_text', False)}, "
                 f"unmapped_fonts={warn.get('unmapped_fonts', False)}")
    lines.append("")
    lines.append(f"Cleaned:         {_fmt_list(r.get('cleaned'))}")
    lines.append(f"NOT removed:     {_fmt_list(r.get('not_removed'))}")
    exp = r.get("expansion")
    if isinstance(exp, dict):
        # HONESTY (do not weaken): the expansion line says TARGETED, never "removed" — the
        # selection count is pre-apply, and `could_not_remove` above may say some targeted
        # items could NOT actually be taken out. When it does, reference the caveat here so
        # the two lines can never read as contradicting each other.
        if exp.get("on"):
            lines.append(
                f"Redact everywhere: ON — {exp.get('additional_targeted', 0)} additional "
                "occurrence(s) of accepted values were targeted for removal across the document.")
            if r.get("could_not_remove"):
                lines.append(
                    "  (See 'Could not remove' above — not every targeted item could actually "
                    "be taken out of this file. Review those yourself.)")
            for reason in (exp.get("not_expanded_reasons") or []):
                lines.append(f"  ({reason}; those keep only their reviewed occurrences.)")
        else:
            lines.append("Redact everywhere: OFF — only the occurrences you reviewed were "
                         "targeted for removal.")
    lines.append("")
    lines.extend(_verification_line(r.get("verification")))
    lines.append("")
    lines.append("This is a first pass, not a certification. Read the redacted copy "
                 "yourself before relying on it.")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ batch summary ----
def build_batch_summary(
    *,
    batch_name: str,
    reports: list,
    failed: list,
    reviewer: str | None = None,
) -> dict:
    """Aggregate a BATCH run's per-file reports into one summary record (the batch-mode
    analogue of :func:`build_report`).

    ``reports`` — the per-file report dicts (each a :func:`build_report` output) for the files
    that were successfully redacted + written. ``failed`` — ``{"filename", "error"}`` dicts for
    files that could not be read / scanned / redacted (excluded from the outputs, NEVER silently
    dropped — they are counted + listed here).

    The summary carries per-file: filenames + SHA-256 hashes, findings / accepted / rejected,
    ``could_not_remove``, and the post-export verification STATE (its class counts, never a
    value) — plus roll-up totals and the honest not-an-audit header. Contains NO cleartext
    matter value (same guarantee as the per-file report). Deterministic except the timestamp."""
    def _int(v):
        return v if (isinstance(v, int) and not isinstance(v, bool) and v >= 0) else 0

    reports = [r for r in (reports or []) if isinstance(r, dict)]
    failed = [f for f in (failed or []) if isinstance(f, dict)]

    per_file: list[dict] = []
    totals = {"findings": 0, "accepted": 0, "rejected": 0, "could_not_remove": 0}
    verdicts = {"no_residuals_detected": 0, "residuals_possible": 0,
                "could_not_fully_verify": 0, "other": 0}
    for r in reports:
        orig = r.get("original", {}) or {}
        out = r.get("output", {}) or {}
        ver = r.get("verification", {}) or {}
        state = ver.get("state") if isinstance(ver, dict) else None
        if state in verdicts:
            verdicts[state] += 1
        elif state:
            verdicts["other"] += 1
        f = _int(r.get("findings"))
        a = _int(r.get("accepted"))
        rej = _int(r.get("rejected"))
        cnr = _int(r.get("could_not_remove"))
        totals["findings"] += f
        totals["accepted"] += a
        totals["rejected"] += rej
        totals["could_not_remove"] += cnr
        per_file.append({
            "original_filename": str(orig.get("filename", "")),
            "original_sha256": str(orig.get("sha256", "")),
            "output_filename": str(out.get("filename", "")),
            "output_sha256": str(out.get("sha256", "")),
            "findings": f,
            "accepted": a,
            "rejected": rej,
            "could_not_remove": cnr,
            "verification_state": state if isinstance(state, str) else "",
            "verification_classes": ver.get("classes", {}) if isinstance(ver, dict) else {},
        })

    failed_out = [{"filename": str(x.get("filename", "")),
                   "error": str(x.get("error", ""))} for x in failed]

    summary = {
        "schema": BATCH_SCHEMA,
        "note": REPORT_NOTE,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "app_version": __version__,
        "batch_name": str(batch_name or ""),
        "totals": {
            "files_exported": len(per_file),
            "files_failed": len(failed_out),
            "findings": totals["findings"],
            "accepted": totals["accepted"],
            "rejected": totals["rejected"],
            "could_not_remove": totals["could_not_remove"],
        },
        "verification": verdicts,
        "files": per_file,
        "failed": failed_out,
    }
    if isinstance(reviewer, str) and reviewer.strip():
        summary["reviewer"] = reviewer.strip()[:200]
    return summary


def batch_summary_to_json(summary: dict) -> str:
    """Machine-readable batch summary (sorted keys, UTF-8, trailing newline)."""
    return json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def batch_summary_to_text(summary: dict) -> str:
    """Human-readable batch summary — readable in any editor, no markup, NO cleartext value
    (same guarantee as the JSON). Mirrors the per-file :func:`to_text` header + note."""
    s = summary if isinstance(summary, dict) else {}
    tot = s.get("totals", {}) or {}
    ver = s.get("verification", {}) or {}
    lines: list[str] = []
    lines.append("Lawbat redaction — batch summary")
    lines.append(f"({s.get('note', REPORT_NOTE)})")
    lines.append("=" * 60)
    lines.append(f"Generated (UTC): {s.get('generated_utc', '')}")
    lines.append(f"App version:     {s.get('app_version', '')}")
    lines.append(f"Batch:           {s.get('batch_name', '')}")
    if s.get("reviewer"):
        lines.append(f"Reviewer:        {s.get('reviewer')}")
    lines.append("")
    lines.append(f"Files exported:  {tot.get('files_exported', 0)}")
    lines.append(f"Files FAILED:    {tot.get('files_failed', 0)}")
    lines.append(f"Total findings:  {tot.get('findings', 0)}")
    lines.append(f"  accepted:      {tot.get('accepted', 0)}")
    lines.append(f"  rejected:      {tot.get('rejected', 0)}")
    lines.append(f"  could NOT remove: {tot.get('could_not_remove', 0)}")
    lines.append("")
    lines.append("Post-export checks:")
    lines.append(f"  no residual detected:   {ver.get('no_residuals_detected', 0)}")
    lines.append(f"  possible residual:      {ver.get('residuals_possible', 0)}")
    lines.append(f"  could not fully verify: {ver.get('could_not_fully_verify', 0)}")
    lines.append("")
    lines.append("Per file:")
    for f in (s.get("files") or []):
        f = f if isinstance(f, dict) else {}
        lines.append(f"  - {f.get('original_filename', '')} -> {f.get('output_filename', '')}")
        lines.append(f"      findings={f.get('findings', 0)} accepted={f.get('accepted', 0)} "
                     f"rejected={f.get('rejected', 0)} could_not_remove="
                     f"{f.get('could_not_remove', 0)} check={f.get('verification_state', '')}")
        lines.append(f"      out SHA-256: {f.get('output_sha256', '')}")
    failed = s.get("failed") or []
    if failed:
        lines.append("")
        lines.append("Files that could NOT be processed (excluded from the outputs):")
        for x in failed:
            x = x if isinstance(x, dict) else {}
            lines.append(f"  - {x.get('filename', '')}: {x.get('error', '')}")
    lines.append("")
    lines.append("This is a first pass, not a certification. Read each redacted copy "
                 "yourself before relying on it.")
    return "\n".join(lines) + "\n"
