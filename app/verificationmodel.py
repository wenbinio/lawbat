"""Local, value-free bridge to the Rust ``firmos.verify/0`` recovery probes.

This contract is deliberately separate from ``firmos.redaction/0``. Success means
that the response is bound to these bytes and accounts for every requested probe,
not that the document is safe. Neither requests nor raw engine responses are logged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from . import corebridge, redactionmodel

SCHEMA = "firmos.verify/0"
MAX_VALUES = 1000
MAX_VALUE_BYTES = 1024
TEXT_VECTORS = ("text_raw", "text_case_insensitive", "text_ws_normalized", "text_ws_stripped")
PDF_VECTORS = ("pdf_text_strict", "pdf_text_lenient", "pdf_raw_bytes", "pdf_streams",
               "pdf_annotations", "pdf_metadata")
COMMON_LIMITATIONS = ("supplied_values_scope_only", "no_finding_is_not_removal_proof",
                      "undetected_values_not_covered")
PDF_LIMITATIONS = ("image_pixel_layer_not_probed", "unsupported_filter_streams_not_probed",
                   "attachment_container_content_not_extracted")
PDF_NOT_PROBED = ("image_pixel_content", "unsupported_filter_streams", "attachment_container_content")
MODES = ("raw", "case_insensitive", "ws_normalized", "ws_stripped")


def _error(reason: str) -> dict:
    # Never echo engine diagnostics/errors: this is a confidentiality boundary.
    return {"error": "The recovery probes could not be completed.", "reason": reason}


def _count(value) -> bool:
    return type(value) is int and value >= 0


def _validated(data: dict, kind: str, digest: str, count: int) -> dict:
    """Reject partial/contradictory responses; reconstruct a value-free allowlist."""
    vectors = list(PDF_VECTORS if kind == "pdf" else TEXT_VECTORS)
    limitations = list(COMMON_LIMITATIONS + (PDF_LIMITATIONS if kind == "pdf" else ()))
    not_probed = list(PDF_NOT_PROBED if kind == "pdf" else ())
    if (not isinstance(data, dict) or data.get("schema") != SCHEMA
            or data.get("op") != "verify" or data.get("kind") != kind or "error" in data
            or data.get("artifact_sha256") != digest
            or type(data.get("values_probed")) is not int or data["values_probed"] != count
            or data.get("vectors") != vectors or data.get("limitations") != limitations
            or data.get("not_probed") != not_probed):
        raise ValueError("contract")
    version = data.get("engine_version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError("version")
    raw_results = data.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != count:
        raise ValueError("results")
    results, total, with_residuals = [], 0, 0
    for index, row in enumerate(raw_results):
        if (not isinstance(row, dict) or type(row.get("value_index")) is not int
                or row["value_index"] != index or type(row.get("residual_found")) is not bool
                or not isinstance(row.get("probes"), list) or len(row["probes"]) != len(vectors)):
            raise ValueError("value accounting")
        probes = []
        for vector, probe in zip(vectors, row["probes"], strict=True):
            if (not isinstance(probe, dict) or probe.get("vector") != vector
                    or type(probe.get("residual_found")) is not bool
                    or not _count(probe.get("matches"))
                    or probe["residual_found"] != (probe["matches"] > 0)):
                raise ValueError("probe")
            pages, mode = probe.get("pages"), probe.get("mode")
            if (not isinstance(pages, list)
                    or any(type(p) is not int or not 0 <= p <= 0xFFFFFFFF for p in pages)
                    or pages != sorted(set(pages))
                    or (not probe["residual_found"] and pages)):
                raise ValueError("pages")
            if kind == "pdf" and vector != "pdf_text_strict" and probe["residual_found"]:
                if mode not in MODES:
                    raise ValueError("mode")
            elif mode is not None:
                raise ValueError("unexpected mode")
            clean = {"vector": vector, "residual_found": probe["residual_found"],
                     "matches": probe["matches"], "pages": list(pages)}
            if mode is not None:
                clean["mode"] = mode
            probes.append(clean)
        found = any(p["residual_found"] for p in probes)
        if row["residual_found"] != found:
            raise ValueError("contradictory residual")
        total += sum(p["residual_found"] for p in probes)
        with_residuals += int(found)
        results.append({"value_index": index, "residual_found": found, "probes": probes})
    for key, expected in (("total_residual_findings", total), ("values_with_residuals", with_residuals)):
        if not _count(data.get(key)) or data[key] != expected:
            raise ValueError("totals")
    diagnostics = data.get("diagnostics")
    if not isinstance(diagnostics, list) or any(not isinstance(d, str) for d in diagnostics):
        raise ValueError("diagnostics")
    clean = {"schema": SCHEMA, "op": "verify", "kind": kind, "engine_version": version,
             "artifact_sha256": digest, "vectors": vectors, "results": results,
             "values_probed": count, "total_residual_findings": total,
             "values_with_residuals": with_residuals, "not_probed": not_probed,
             "limitations": limitations, "diagnostic_count": len(diagnostics)}
    # Free-form diagnostics are deliberately NOT persisted. Their presence still
    # makes the outer verdict incomplete and remains visible as a count.
    if kind == "pdf":
        flags = data.get("flags")
        names = ("low_text", "unmapped_fonts", "degenerate_layout")
        if not isinstance(flags, dict) or any(type(flags.get(k)) is not bool for k in names):
            raise ValueError("flags")
        clean["flags"] = {k: flags[k] for k in names}
    return clean


def verify(artifact: bytes, values: list[str], *, kind: str) -> dict:
    """Probe exact bytes, using STDIN only, or return a fixed content-free failure.

    Bounds match the Rust CLI. An empty/oversized/invalid value set is refused in
    full, never truncated into an apparently complete negative. Callers may retain
    other recovery evidence, but must preserve this failure as incomplete coverage.
    """
    if kind not in ("text", "pdf") or not isinstance(artifact, bytes):
        return _error("invalid_artifact")
    if not isinstance(values, list) or not values:
        return _error("no_targets")
    if len(values) > MAX_VALUES:
        return _error("value_count_limit")
    try:
        if any(not isinstance(v, str) or not v.strip() for v in values):
            return _error("invalid_target")
        if any(len(v.strip().encode("utf-8")) > MAX_VALUE_BYTES for v in values):
            return _error("value_size_limit")
        request = {"op": "verify", "kind": kind, "values": values}
        if kind == "pdf":
            request["pdf_b64"] = base64.b64encode(artifact).decode("ascii")
        else:
            request["text"] = artifact.decode("utf-8")
        digest = hashlib.sha256(artifact).hexdigest()
        payload = json.dumps(request)
        binary = redactionmodel.redact_cli_path()
        if not binary:
            return _error("not_found")
        response = corebridge.run(binary, input=payload, timeout=redactionmodel._timeout_for(payload))
        if not response.started:
            return _error("spawn_failed")
        if response.returncode != 0:
            return _error("engine_failed")
        return _validated(json.loads(response.stdout), kind, digest, len(values))
    except Exception:  # noqa: BLE001 - raw exceptions may contain matter text; never echo or log
        return _error("invalid_response")
