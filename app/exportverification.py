"""Combine independent extraction, explicit target coverage and Rust recovery evidence.

Post-export evidence only: this module neither publishes nor authorizes a release.
All free-form engine diagnostics are replaced by fixed reasons. Accepted cleartext
and candidate values exist only in process; the returned evidence is value-free.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json

from . import exportverify, redactionmodel, verificationmodel

_WARNING_MARKERS = ("needs ocr", "scanned", "image-only", "no text layer", "font", "encoding",
                    "unmapped", "truncat", "limit", "skip", "failed", "could not")
_SAFE_CLASSES = frozenset((*redactionmodel.ALLOWED_BUILTINS, "term", "value"))


def _records(accepted_values):
    # Do not lose unusable rows: classify() must still count them as incomplete.
    if not isinstance(accepted_values, (list, tuple)):
        return []
    records = []
    for row in accepted_values:
        if not isinstance(row, dict):
            records.append(None)
            continue
        label = row.get("class")
        label = label if isinstance(label, str) and label in _SAFE_CLASSES else "value"
        records.append({"value": row.get("value"), "class": label})
    return records


def _coverage(raw, records):
    if raw is None:
        resolved = sum(isinstance(r, dict) and isinstance(r.get("value"), str)
                       and bool(r["value"].strip()) for r in records)
        return {"requested": len(records), "resolved": resolved,
                "unresolved": len(records) - resolved, "complete": bool(records) and resolved == len(records)}
    keys = ("requested", "resolved", "unresolved")
    if (isinstance(raw, dict) and all(type(raw.get(k)) is int and raw[k] >= 0 for k in keys)
            and raw["requested"] == raw["resolved"] + raw["unresolved"]
            and type(raw.get("complete")) is bool):
        return {**{k: raw[k] for k in keys}, "complete": raw["complete"] and raw["unresolved"] == 0}
    return {"requested": 0, "resolved": 0, "unresolved": 0, "complete": False}


def _decoded_view(text, text_format):
    """Probe recoverable HTML entities / JSON strings as well as exact serialized bytes."""
    if text_format == "html":
        return html.unescape(text)
    if text_format != "json":
        return text
    pending, parts, visited = [json.loads(text)], [], 0
    while pending:
        visited += 1
        if visited > 100_000:
            raise ValueError("decoded view budget")
        item = pending.pop()
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return "\n".join(parts)


def check(artifact: bytes, accepted_values, options, *, kind: str,
          coverage=None, text_format="txt", extra_reasons=()) -> dict:
    """Run both recovery paths; a failure never discards already observed recovery.

    Rust responses must pass the separate schema, exact-byte hash and per-value/
    per-vector accounting checks. Its unprobed surfaces and diagnostics remain
    explicit. PDF negatives remain incomplete because pixel/container surfaces are
    structurally unprobed. Short-value substring findings are possible residuals,
    not claims that an unrelated occurrence identifies the same person.
    """
    records = _records(accepted_values)
    target_coverage = _coverage(coverage, records)
    reasons = list(extra_reasons)
    candidates, extracted, text = [], "", ""
    failed = False
    try:
        if kind == "pdf":
            response = redactionmodel.extract_scan(
                "verify.pdf", base64.b64encode(artifact).decode("ascii"), options)
            if isinstance(response, dict) and "error" not in response and isinstance(response.get("text"), str):
                extracted = response["text"]
            if (not isinstance(response, dict) or "error" in response
                    or not isinstance(response.get("text"), str)
                    or not isinstance(response.get("candidates"), list)
                    or not isinstance(response.get("warnings"), list)):
                raise ValueError("extraction")
            extracted = response["text"]
            warnings = response["warnings"]
            if any(not isinstance(w, str) for w in warnings):
                raise ValueError("warnings")
            if any(marker in " ".join(warnings).lower() for marker in _WARNING_MARKERS):
                reasons.append("the independent PDF extraction reported incomplete coverage")
            if not extracted.strip():
                reasons.append("no text could be re-extracted from the exported PDF")
        else:
            text = artifact.decode("utf-8")
            extracted = _decoded_view(text, text_format)
            response = redactionmodel.scan(extracted, options)
            if (not isinstance(response, dict) or "error" in response
                    or not isinstance(response.get("candidates"), list)):
                raise ValueError("rescan")
        for candidate in response["candidates"]:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("value"), str):
                failed = True
                continue
            candidates.append({"value": candidate["value"]})
    except Exception:  # noqa: BLE001 - extraction failure must not hide other recovery evidence
        failed = True
    if failed:
        reasons.append("the independent extraction or re-scan could not be completed")
    # Keep available text even when re-scan failed; the deterministic presence
    # check does not depend on recognizer availability. Do not infer empty = clean.
    if kind == "text" and not text:
        try:
            text = artifact.decode("utf-8")
        except (AttributeError, UnicodeError):
            reasons.append("the output bytes could not be decoded as UTF-8")
    values = []
    seen = set()
    for record in records:
        value = record.get("value") if isinstance(record, dict) else None
        if isinstance(value, str) and value.strip() and value not in seen:
            seen.add(value)
            values.append(value)
    rust = verificationmodel.verify(artifact, values, kind=kind)
    if "error" in rust:
        reasons.append("Rust recovery probes could not run completely (" + rust["reason"] + ")")
        rust_evidence = {"status": "unavailable", "reason": rust["reason"]}
    else:
        rust_evidence = {"status": "completed", **rust}
        for row in rust["results"]:
            if row["residual_found"]:
                candidates.append({"value": values[row["value_index"]]})
        if rust["not_probed"]:
            reasons.append("the Rust probes do not examine image pixels, unsupported-filter streams "
                           "or text inside attachment containers")
        if rust["diagnostic_count"]:
            reasons.append("the Rust probes reported skipped or limited recovery work")
        if any(rust.get("flags", {}).values()):
            reasons.append("the Rust PDF decoders reported incomplete text or layout coverage")
    result = exportverify.classify(
        accepted_values=records, reextracted_text=text + "\n" + extracted,
        residual_candidates=candidates, extract_failed=failed,
        low_text_signals=reasons, accepted_values_complete=target_coverage["complete"])
    # Positive findings and incomplete coverage must coexist, not hide each other.
    result["coverage"] = target_coverage
    result["artifact_sha256"] = hashlib.sha256(artifact).hexdigest()
    result["rust"] = rust_evidence
    result["limitations"] = list(verificationmodel.COMMON_LIMITATIONS)
    result["checks"]["rust_values_probed"] = rust.get("values_probed", 0)
    if result["state"] == exportverify.VERDICT_POSSIBLE and any(
            len(exportverify._norm(value)) < 3 for value in values):
        result["reasons"].append("short-value substring findings can include unrelated text; review in context")
    return result


def check_saved(path, expected: bytes, accepted_values, options, *, kind: str,
                coverage=None, text_format="txt") -> dict:
    """Re-read the saved bytes, bounded by the known output size.

    A missing/changed file is incomplete, never mislabeled as the verified output.
    This is a post-write consistency check, not an atomic stage/verify/release gate.
    """
    try:
        with path.open("rb") as file:
            actual = file.read(len(expected) + 1)
        if actual != expected:
            raise ValueError("changed output")
    except (OSError, ValueError):
        result = exportverify.classify(
            accepted_values=_records(accepted_values), extract_failed=True,
            low_text_signals=["the saved output could not be read back unchanged"],
            accepted_values_complete=False)
        result["coverage"] = _coverage(coverage, _records(accepted_values))
        result["rust"] = {"status": "unavailable", "reason": "saved_output_changed_or_unreadable"}
        return result
    return check(actual, accepted_values, options, kind=kind, coverage=coverage, text_format=text_format)
