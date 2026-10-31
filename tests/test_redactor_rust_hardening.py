"""Deterministic contract/fault tests, not document accuracy or platform acceptance.

The wire factory and monkeypatches are test doubles. Real-engine/corpus tests live
separately in test_redactor_verification_engine.py and fail when CI lacks the bin.
"""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import corebridge, exportverification, exportverify, redactionmodel
from app import verificationmodel as vm
from app import verificationtargets as targets


def wire(artifact=b"removed", values=None, kind="text", hits=()):
    values = values or ["TARGET_A"]
    vectors = vm.PDF_VECTORS if kind == "pdf" else vm.TEXT_VECTORS
    results = []
    for i, _ in enumerate(values):
        probes = []
        for j, vector in enumerate(vectors):
            found = i in hits and j == 0
            probes.append({"vector": vector, "residual_found": found,
                           "matches": int(found), "pages": []})
        results.append({"value_index": i, "residual_found": i in hits, "probes": probes})
    data = {"schema": vm.SCHEMA, "op": "verify", "kind": kind, "engine_version": "0.0.0",
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(), "vectors": list(vectors),
            "results": results, "values_probed": len(values), "total_residual_findings": len(hits),
            "values_with_residuals": len(hits), "diagnostics": [],
            "limitations": list(vm.COMMON_LIMITATIONS + (vm.PDF_LIMITATIONS if kind == "pdf" else ())),
            "not_probed": list(vm.PDF_NOT_PROBED if kind == "pdf" else ())}
    if kind == "pdf":
        data["flags"] = {"low_text": False, "unmapped_fonts": False, "degenerate_layout": False}
    return data


class BridgeTests(unittest.TestCase):
    def invoke(self, data=None, *, code=0, artifact=b"removed", values=None, kind="text", started=True):
        with patch.object(redactionmodel, "redact_cli_path", return_value="/local/engine"), \
             patch.object(corebridge, "run", return_value=corebridge.RunResult(
                 started=started, returncode=code, stdout=json.dumps(data))) as run:
            result = vm.verify(artifact, values or ["TARGET_A"], kind=kind)
        return result, run

    def test_complete_response_is_bound_to_exact_utf8_bytes(self):
        artifact, values = "未移除 林星".encode(), ["林星"]
        result, run = self.invoke(wire(artifact, values, hits=(0,)), artifact=artifact, values=values)
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(artifact).hexdigest())
        self.assertEqual(result["results"][0]["value_index"], 0)
        self.assertNotIn("林星", json.dumps(result, ensure_ascii=False))
        self.assertEqual(run.call_args.args, ("/local/engine",))
        request = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(request, {"op": "verify", "kind": "text", "text": artifact.decode(), "values": values})
        self.assertGreater(run.call_args.kwargs["timeout"], 0)

    def test_pdf_bytes_use_the_pdf_field_and_keep_explicit_unprobed_surfaces(self):
        result, run = self.invoke(wire(kind="pdf"), kind="pdf")
        self.assertEqual(result["not_probed"], list(vm.PDF_NOT_PROBED))
        request = json.loads(run.call_args.kwargs["input"])
        self.assertIn("pdf_b64", request)
        self.assertNotIn("text", request)

    def test_schema_kind_hash_count_op_and_missing_limitations_fail_closed(self):
        mutations = {"schema": "firmos.redaction/0", "op": "scan", "kind": "pdf",
                     "artifact_sha256": "0" * 64, "values_probed": True,
                     "limitations": [], "not_probed": ["unknown"], "vectors": [],
                     "engine_version": "PRIVATE_TEST_DIAGNOSTIC"}
        for field, bad in mutations.items():
            with self.subTest(field=field):
                data = wire(); data[field] = bad
                result, _ = self.invoke(data)
                self.assertEqual(result["reason"], "invalid_response")
                self.assertNotIn("PRIVATE_TEST", json.dumps(result))

    def test_missing_duplicate_out_of_range_or_boolean_value_indices_fail(self):
        for indices in ([], [0], [0, 0], [1, 0], [0, 2], [False, 1]):
            data = wire(values=["TARGET_A", "TARGET_B"])
            data["results"] = [dict(data["results"][0], value_index=i) for i in indices]
            result, _ = self.invoke(data, values=["TARGET_A", "TARGET_B"])
            self.assertIn("error", result)

    def test_missing_duplicate_or_contradictory_probes_fail(self):
        for mutation in range(5):
            data = wire()
            probes = data["results"][0]["probes"]
            if mutation == 0:
                probes.pop()
            elif mutation == 1:
                probes[1] = copy.deepcopy(probes[0])
            elif mutation == 2:
                probes[0]["matches"] = True
            elif mutation == 3:
                probes[0]["matches"] = 1
            else:
                data["results"][0]["residual_found"] = True
            self.assertIn("error", self.invoke(data)[0])

    def test_inconsistent_aggregate_totals_fail(self):
        for field in ("total_residual_findings", "values_with_residuals"):
            for bad in (1, True, -1, "0"):
                data = wire(); data[field] = bad
                self.assertIn("error", self.invoke(data)[0])

    def test_malformed_pages_modes_and_pdf_flags_fail(self):
        for bad in ([True], [-1], [2, 1], [1, 1], "1", [0x100000000]):
            data = wire(kind="pdf", hits=(0,)); data["results"][0]["probes"][0]["pages"] = bad
            self.assertIn("error", self.invoke(data, kind="pdf")[0])
        data = wire(kind="pdf"); data["flags"]["low_text"] = 0
        self.assertIn("error", self.invoke(data, kind="pdf")[0])
        data = wire(); data["results"][0]["probes"][0]["mode"] = "raw"
        self.assertIn("error", self.invoke(data)[0])

    def test_nonzero_exit_does_not_accept_success_shaped_output(self):
        self.assertEqual(self.invoke(wire(), code=1)[0]["reason"], "engine_failed")
        self.assertEqual(self.invoke(wire(), started=False)[0]["reason"], "spawn_failed")

    def test_raw_errors_diagnostics_and_extra_fields_never_escape(self):
        data = wire()
        data["diagnostics"] = ["PRIVATE_TEST_DIAGNOSTIC"]
        data["value"] = "PRIVATE_TEST_VALUE"
        data["results"][0]["value"] = "PRIVATE_TEST_VALUE"
        result, _ = self.invoke(data)
        self.assertEqual(result["diagnostic_count"], 1)
        self.assertNotIn("PRIVATE_TEST", json.dumps(result))
        data["error"] = "PRIVATE_TEST_ERROR"
        result, _ = self.invoke(data)
        self.assertNotIn("PRIVATE_TEST", json.dumps(result))
        self.assertIn("error", result)

    def test_empty_overlong_invalid_and_excess_values_never_silently_truncate(self):
        cases = ([], [" "], [None], ["x" * 1025], ["字" * 342], ["x"] * 1001)
        with patch.object(corebridge, "run") as run:
            for values in cases:
                self.assertIn("error", vm.verify(b"removed", values, kind="text"))
            run.assert_not_called()

    def test_absent_engine_and_invalid_utf8_fail_without_leaking(self):
        with patch.object(redactionmodel, "redact_cli_path", return_value=None):
            self.assertEqual(vm.verify(b"text", ["TARGET_A"], kind="text")["reason"], "not_found")
        self.assertIn("error", vm.verify(b"\xff", ["TARGET_A"], kind="text"))


class TargetTests(unittest.TestCase):
    def test_partial_pdf_scan_counts_every_requested_id(self):
        result = targets.from_pdf_scan({"candidates": [{"id": 0, "value": "TARGET_A"}]}, [0, 4])
        self.assertEqual(result["coverage"], {"requested": 2, "resolved": 1, "unresolved": 1, "complete": False})
        self.assertEqual(len(result["accepted_values"]), 1)

    def test_failed_pdf_scan_is_not_empty_complete_evidence(self):
        for scan in (None, {"error": "PRIVATE_TEST"}, {}, {"candidates": "bad"}):
            result = targets.from_pdf_scan(scan, [0, 1])
            self.assertEqual(result["coverage"]["unresolved"], 2)
            self.assertFalse(result["coverage"]["complete"])

    def test_duplicate_candidate_id_and_boolean_id_cannot_resolve_a_target(self):
        for rows in ([{"id": 0, "value": "A"}, {"id": 0, "value": "B"}],
                     [{"id": False, "value": "A"}], [{"id": 0, "value": " "}]):
            result = targets.from_pdf_scan({"candidates": rows}, [0])
            self.assertFalse(result["coverage"]["complete"])
            self.assertEqual(result["coverage"]["resolved"], 0)

    def test_decision_dedup_does_not_collapse_distinct_locations(self):
        rows = [{"id": i, "value": "TARGET_A"} for i in (0, 1)]
        result = targets.from_pdf_scan({"candidates": rows}, [0, 0, 1])
        self.assertEqual(result["coverage"]["requested"], 2)
        self.assertEqual(result["coverage"]["resolved"], 2)
        self.assertEqual(len(result["accepted_values"]), 1)
        self.assertTrue(result["coverage"]["complete"])

    def test_malformed_spans_utf8_boundaries_and_boolean_offsets_are_counted(self):
        spans = [[0, 6], [0, 1], [7, 99], [False, 6], [0], None]
        result = targets.from_spans("林星 abc", spans)
        self.assertEqual(result["coverage"], {"requested": 6, "resolved": 1, "unresolved": 5, "complete": False})
        self.assertEqual(result["accepted_values"][0]["value"], "林星")

    def test_whitespace_and_case_variants_are_not_dropped_from_rust_input(self):
        result = targets.from_spans("Li LI L i", [[0, 2], [3, 5], [6, 9], [0, 2]])
        self.assertEqual([r["value"] for r in result["accepted_values"]], ["Li", "LI", "L i"])
        self.assertEqual(result["coverage"]["resolved"], 3)

    def test_legacy_legend_remains_incomplete_even_when_nonempty(self):
        result = targets.from_legend([{"value": "TARGET_A"}, {}])
        self.assertEqual(result["coverage"]["unresolved"], 1)
        self.assertFalse(result["coverage"]["complete"])


class EvidenceTests(unittest.TestCase):
    def checked(self, text="removed", value="TARGET_A", *, rust_error=False, hits=(), coverage=None,
                scan_error=False, kind="text", diagnostic=False, text_format="txt"):
        raw, values = text.encode(), [value]
        data = wire(raw, values, kind, hits)
        if diagnostic:
            data["diagnostics"] = ["PRIVATE_TEST_DIAGNOSTIC"]
        res = {"candidates": [], "text": text, "warnings": []}
        if scan_error:
            res = {"error": "PRIVATE_TEST_ERROR"}
        with patch.object(redactionmodel, "redact_cli_path", return_value="/engine"), \
             patch.object(corebridge, "run", return_value=corebridge.RunResult(
                 started=True, returncode=int(rust_error), stdout=json.dumps(data))), \
             patch.object(redactionmodel, "scan", return_value=res), \
             patch.object(redactionmodel, "extract_scan", return_value=res):
            return exportverification.check(raw, [{"value": value, "class": "term"}], {},
                                            kind=kind, coverage=coverage, text_format=text_format)

    def test_complete_negative_text_and_hash(self):
        result = self.checked()
        self.assertEqual(result["state"], exportverify.VERDICT_NONE)
        self.assertEqual(result["rust"]["artifact_sha256"], hashlib.sha256(b"removed").hexdigest())
        self.assertEqual(result["checks"]["rust_values_probed"], 1)
        self.assertTrue(result["limitations"])

    def test_partial_target_reconstruction_cannot_be_clean(self):
        result = self.checked(coverage={"requested": 2, "resolved": 1, "unresolved": 1, "complete": False})
        self.assertEqual(result["state"], exportverify.VERDICT_UNVERIFIED)
        self.assertTrue(any("complete accepted-value" in r for r in result["reasons"]))

    def test_either_failed_verification_path_preserves_incompleteness(self):
        for kw in ({"rust_error": True}, {"scan_error": True}, {"diagnostic": True}):
            self.assertEqual(self.checked(**kw)["state"], exportverify.VERDICT_UNVERIFIED)

    def test_positive_text_recovery_survives_both_engine_failures(self):
        result = self.checked(text="TARGET_A", rust_error=True, scan_error=True)
        self.assertEqual(result["state"], exportverify.VERDICT_POSSIBLE)
        self.assertTrue(result["reasons"])
        self.assertNotIn("PRIVATE_TEST", json.dumps(result))

    def test_positive_rust_recovery_survives_rescan_failure_and_partial_inputs(self):
        result = self.checked(scan_error=True, hits=(0,), coverage={
            "requested": 2, "resolved": 1, "unresolved": 1, "complete": False})
        self.assertEqual(result["state"], exportverify.VERDICT_POSSIBLE)
        self.assertEqual(result["classes"], {"term": 1})
        self.assertGreaterEqual(len(result["reasons"]), 2)

    def test_short_rust_recovery_is_surfaced_with_context_warning(self):
        for value in ("Li", "林星", "李"):
            result = self.checked(value=value, hits=(0,))
            self.assertEqual(result["state"], exportverify.VERDICT_POSSIBLE)
            self.assertTrue(any("short-value" in r for r in result["reasons"]))

    def test_pdf_negative_preserves_unprobed_surfaces(self):
        result = self.checked(kind="pdf")
        self.assertEqual(result["state"], exportverify.VERDICT_UNVERIFIED)
        self.assertEqual(result["rust"]["not_probed"], list(vm.PDF_NOT_PROBED))

    def test_html_and_json_recovery_decodes_the_serialized_document(self):
        for text, value, fmt in (("A &amp; B", "A & B", "html"),
                                 ('{"text":"A\\u0026B"}', "A&B", "json")):
            result = self.checked(text=text, value=value, text_format=fmt)
            self.assertEqual(result["state"], exportverify.VERDICT_POSSIBLE)
            self.assertEqual(result["artifact_sha256"], hashlib.sha256(text.encode()).hexdigest())

    def test_readback_mismatch_does_not_claim_to_have_probed_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "output.txt"; p.write_bytes(b"changed")
            with patch.object(vm, "verify") as verify:
                result = exportverification.check_saved(p, b"expected", [{"value": "TARGET_A"}], {}, kind="text")
            verify.assert_not_called()
            self.assertEqual(result["state"], exportverify.VERDICT_UNVERIFIED)
            self.assertNotIn("artifact_sha256", result)


from tests.smoke._helpers import _prepared_result, _prepared_root, _clear_prepared_test_jobs


class RouteTests(unittest.TestCase):
    def tearDown(self):
        _clear_prepared_test_jobs()

    def setUp(self):
        # Import the established helper first: it isolates the app data directory
        # and disables real OS opens before application imports.
        from tests.smoke._helpers import _client
        from app import redactionroutes
        self.routes = redactionroutes
        self.client = _client()

    def test_text_export_probes_saved_json_bytes_not_preformat_text(self):
        from app.paths import exports_dir
        seen = []
        def execute(binary, *, input, timeout):
            request = json.loads(input); seen.append(request)
            artifact = request["text"].encode()
            return corebridge.RunResult(True, stdout=json.dumps(wire(artifact, request["values"])))
        with patch.object(redactionmodel, "redact_cli_path", return_value="/engine"), \
             patch.object(corebridge, "run", side_effect=execute), \
             patch.object(redactionmodel, "scan", return_value={"candidates": []}):
            response = self.client.post("/api/redaction/text-export", json={
                "redacted_text": "[REDACTED]", "format": "json", "text": "TARGET_A",
                "accept": [[0, 8]], "filename": "roundtrip.txt", "applied": 1})
        self.assertEqual(response.status_code, 200)
        data = _prepared_result(response.json()); raw = (_prepared_root(data) / data["filename"]).read_bytes()
        self.assertEqual(seen[0]["text"].encode(), raw)
        self.assertNotEqual(seen[0]["text"], "[REDACTED]")
        self.assertEqual(data["verification"]["artifact_sha256"], hashlib.sha256(raw).hexdigest())
        report = json.loads((_prepared_root(data) / data["report_filename"]).read_text())
        self.assertEqual(report["output"]["sha256"], report["verification"]["rust"]["artifact_sha256"])

    def test_pdf_route_propagates_missing_accepted_id(self):
        output = b"%PDF controlled non-PDF test double"
        import base64
        with patch.object(redactionmodel, "pdf_scan", return_value={
                "candidates": [{"id": 0, "value": "TARGET_A", "recognizer": "term"}]}), \
             patch.object(redactionmodel, "pdf_apply", return_value={
                 "pdf_b64": base64.b64encode(output).decode(), "could_not_remove": 0}), \
             patch.object(redactionmodel, "extract_scan", return_value={"candidates": [], "text": "removed", "warnings": []}), \
             patch.object(redactionmodel, "redact_cli_path", return_value="/engine"), \
             patch.object(corebridge, "run", return_value=corebridge.RunResult(
                 True, stdout=json.dumps(wire(output, kind="pdf")))):
            response = self.client.post("/api/redaction/pdf-apply", json={
                "data_b64": "eA==", "filename": "partial.pdf", "accept_ids": [0, 9]})
        self.assertEqual(response.status_code, 200)
        verification = _prepared_result(response.json())["verification"]
        self.assertEqual(verification["coverage"]["unresolved"], 1)
        self.assertFalse(verification["coverage"]["complete"])
        self.assertEqual(verification["state"], exportverify.VERDICT_UNVERIFIED)

    def test_labeled_markdown_does_not_trust_an_empty_legend(self):
        with patch.object(redactionmodel, "apply", return_value={
                "redacted": "TARGET_A", "legend": [], "applied": 1, "stale": 0}), \
             patch.object(redactionmodel, "scan", return_value={"candidates": []}), \
             patch.object(vm, "verify", return_value={"error": "unavailable", "reason": "not_found"}):
            response = self.client.post("/api/redaction/labeled-markdown", json={
                "text": "TARGET_A", "accept": [[0, 8]], "filename": "label.txt"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(_prepared_result(response.json())["verification"]["state"], exportverify.VERDICT_POSSIBLE)
        self.assertEqual(_prepared_result(response.json())["verification"]["coverage"]["resolved"], 1)

    def test_new_probe_details_are_visible_in_the_readable_report(self):
        from app import redactionreport
        v = EvidenceTests().checked(kind="pdf")
        text = "\n".join(redactionreport._verification_line(v))
        self.assertIn("target decisions resolved: 1 / 1", text)
        self.assertIn("pdf_metadata", text)
        self.assertIn("image_pixel_content", text)
        self.assertIn("not proof of removal", text)


if __name__ == "__main__":
    unittest.main()
