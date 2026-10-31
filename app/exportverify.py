"""Value-recovery evidence for redaction outputs; never a release authorization.

Accepted cleartext stays in memory. Results contain counts, class labels and fixed
reasons only. Exact candidate matching covers every nonempty accepted value. The
whitespace/case-insensitive substring check excludes one- and two-character values
because it cannot distinguish them from unrelated text. That reduced coverage is
reported as incomplete, not as a clean result.

An empty target set, or a partially unusable one, is also incomplete: callers must
not convert missing verification inputs into evidence that removal succeeded. A
positive recovery takes precedence over incomplete inputs or extraction failure.
This pure classifier does not write, publish, delete, or log any artifact.
"""

from __future__ import annotations

import re

VERDICT_NONE = "no_residuals_detected"
VERDICT_POSSIBLE = "residuals_possible"
VERDICT_UNVERIFIED = "could_not_fully_verify"
_MIN_VALUE_NORM_LEN = 3


def _norm(s: object) -> str:
    """Use the same whitespace/case normalization for values and extracted text."""
    if not isinstance(s, str):
        return ""
    return re.sub(r"\s+", "", s, flags=re.UNICODE).casefold()


def classify(
    *,
    accepted_values,
    reextracted_text: str = "",
    residual_candidates=None,
    extract_failed: bool = False,
    low_text_signals=None,
    accepted_values_complete: bool = True,
) -> dict:
    """Classify recovery evidence without returning any accepted cleartext.

    ``accepted_values`` contains ``{value, class}`` dictionaries. Re-scan candidates
    contain ``{value, recognizer}``. ``accepted_values_complete=False`` lets a caller
    preserve a failed or partial source scan even when some values were recovered.
    No caller may infer completeness merely from a nonempty target list.

    ``checks.values_checked`` counts distinct nonempty values compared against
    candidate values. ``substring_values_checked`` is the subset eligible for the
    broad text search. Short values are exact-only; absent a positive recovery they
    yield ``could_not_fully_verify`` because the broader check did not run for them.
    """
    residual_candidates = list(residual_candidates or [])
    reasons = list(low_text_signals or [])
    accepted_norms: dict[str, str] = {}
    unusable = 0
    for item in accepted_values or []:
        if not isinstance(item, dict):
            unusable += 1
            continue
        nv = _norm(item.get("value"))
        if not nv:
            unusable += 1
            continue
        cls = item.get("class")
        cls = cls if isinstance(cls, str) and cls else "value"
        accepted_norms.setdefault(nv, cls)

    searchable = {
        nv: cls for nv, cls in accepted_norms.items() if len(nv) >= _MIN_VALUE_NORM_LEN
    }
    short_n = len(accepted_norms) - len(searchable)
    hit: dict[str, str] = {}
    text_norm = _norm(reextracted_text)
    if text_norm:
        for nv, cls in searchable.items():
            if nv in text_norm:
                hit[nv] = cls
    # The substring length floor MUST NOT apply to whole-candidate equality.
    for candidate in residual_candidates:
        if not isinstance(candidate, dict):
            continue
        nv = _norm(candidate.get("value"))
        if nv in accepted_norms:
            hit[nv] = accepted_norms[nv]

    classes: dict[str, int] = {}
    for cls in hit.values():
        classes[cls] = classes.get(cls, 0) + 1
    checks = {
        "values_checked": len(accepted_norms),
        "substring_values_checked": len(searchable),
        "exact_only_values": short_n,
        "unusable_values": unusable,
        "residual_candidates": len(residual_candidates),
    }
    if extract_failed and not reasons:
        reasons.append("could not re-open the exported file to check it")
    if accepted_values_complete is not True:
        reasons.append("the complete accepted-value set could not be reconstructed")
    if not accepted_norms:
        reasons.append("accepted values were not available, so removal checks could not run")
    if unusable:
        reasons.append(f"{unusable} accepted value record(s) could not be checked")
    if short_n:
        reasons.append(
            f"{short_n} short accepted value(s) received exact candidate checks only; "
            "the broader text search could not reliably check them"
        )
    if classes:
        return {"state": VERDICT_POSSIBLE, "classes": classes, "reasons": reasons, "checks": checks}
    if reasons:
        return {"state": VERDICT_UNVERIFIED, "classes": {}, "reasons": reasons, "checks": checks}
    return {"state": VERDICT_NONE, "classes": {}, "reasons": [], "checks": checks}
