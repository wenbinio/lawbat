"""Reconstruct verification targets without silently losing requested decisions.

Values stay in process; ``coverage`` is the count-only record safe to persist.
Duplicate decisions count once, but identical values at distinct locations remain
separate decisions. Value deduplication preserves spelling/whitespace variants.
"""

from __future__ import annotations


def _result(values, requested, resolved, *, source_complete=True):
    return {"accepted_values": values,
            "coverage": {"requested": requested, "resolved": resolved,
                         "unresolved": requested - resolved,
                         "complete": source_complete and requested == resolved}}


def _usable(value):
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def from_spans(text, spans) -> dict:
    """Resolve each distinct UTF-8 byte range; count malformed/unresolvable ones."""
    if not isinstance(text, str) or not isinstance(spans, (list, tuple)):
        return _result([], 0, 0, source_complete=False)
    try:
        raw = text.encode("utf-8")
    except UnicodeError:
        return _result([], len(spans), 0, source_complete=False)
    seen_spans, seen_values, values = set(), set(), []
    requested = resolved = 0
    for span in spans:
        if (not isinstance(span, (list, tuple)) or len(span) != 2
                or any(type(x) is not int for x in span)):
            requested += 1
            continue
        pair = tuple(span)
        if pair in seen_spans:
            continue
        seen_spans.add(pair)
        requested += 1
        start, end = pair
        if not 0 <= start < end <= len(raw):
            continue
        try:
            value = raw[start:end].decode("utf-8")
        except UnicodeError:
            continue
        if not _usable(value):
            continue
        resolved += 1
        if value not in seen_values:
            seen_values.add(value)
            values.append({"value": value, "class": "value"})
    return _result(values, requested, resolved)


def from_pdf_scan(scan, accept_ids) -> dict:
    """An error, malformed scan, duplicate candidate id or missing id is incomplete."""
    requested_ids, malformed = set(), 0
    valid_request = isinstance(accept_ids, (list, tuple))
    for index in accept_ids if valid_request else []:
        if type(index) is int and index >= 0:
            requested_ids.add(index)
        else:
            malformed += 1
    requested = len(requested_ids) + malformed
    base = {"per_recognizer": {}, "findings": 0, "accepted": 0, "rejected": 0}
    if (not isinstance(scan, dict) or "error" in scan
            or not isinstance(scan.get("candidates"), list)):
        return {**base, **_result([], requested, 0, source_complete=False)}
    candidates = scan["candidates"]
    by_id, duplicates = {}, set()
    complete = valid_request and malformed == 0
    for candidate in candidates:
        if (not isinstance(candidate, dict) or type(candidate.get("id")) is not int
                or candidate["id"] < 0):
            complete = False
            continue
        index = candidate["id"]
        if index in by_id:
            duplicates.add(index)
            complete = False
        by_id[index] = candidate
    values, seen_values, per = [], set(), {}
    accepted = resolved = 0
    for index in sorted(requested_ids):
        candidate = by_id.get(index)
        if candidate is None or index in duplicates:
            continue
        accepted += 1
        label = candidate.get("recognizer")
        label = label if isinstance(label, str) and label else "value"
        per[label] = per.get(label, 0) + 1
        value = candidate.get("value")
        if not _usable(value):
            continue
        resolved += 1
        if value not in seen_values:
            seen_values.add(value)
            values.append({"value": value, "class": label})
    base.update(per_recognizer=per, findings=len(candidates), accepted=accepted,
                rejected=max(0, len(candidates) - accepted))
    return {**base, **_result(values, requested, resolved, source_complete=complete)}


def from_legend(legend) -> dict:
    """Legacy legend-only evidence is useful, but cannot prove decision completeness."""
    values = []
    rows = legend if isinstance(legend, list) else []
    for row in rows:
        if isinstance(row, dict) and _usable(row.get("value")):
            values.append({"value": row["value"], "class": "value"})
    return _result(values, len(rows), len(values), source_complete=False)
