"""Model-boundary regressions using controlled engine responses, not PDF evidence."""

import json
import unittest
from unittest.mock import patch

from app import redactionmodel


class PdfReleaseGuardTests(unittest.TestCase):
    def apply_with(self, response):
        with patch.object(redactionmodel, "_run", return_value=response):
            return redactionmodel.pdf_apply("SOURCE_TEST_BYTES", [1])

    def test_reported_failed_removals_do_not_escape_with_file_bytes(self):
        response = {
            "pdf_b64": "OUTPUT_TEST_BYTES",
            "redactions": 2,
            "could_not_remove": 1,
            "diagnostics": ["PRIVATE_TEST_DIAGNOSTIC"],
        }
        before = json.dumps(response)
        result = self.apply_with(response)
        self.assertEqual(result["reason"], "accepted_redactions_not_removed")
        self.assertEqual(result["could_not_remove"], 1)
        self.assertTrue(result["error"].startswith("Export blocked:"))
        self.assertNotIn("pdf_b64", result)
        self.assertNotIn("OUTPUT_TEST", json.dumps(result))
        self.assertNotIn("PRIVATE_TEST", json.dumps(result))
        self.assertEqual(json.dumps(response), before)

    def test_missing_failure_count_is_not_assumed_to_be_zero(self):
        result = self.apply_with({"pdf_b64": "OUTPUT_TEST_BYTES", "redactions": 1})
        self.assertEqual(result["reason"], "invalid_removal_outcome")
        self.assertNotIn("pdf_b64", result)

    def test_malformed_failure_counts_are_rejected_without_coercion(self):
        for value in (None, True, False, "0", "1", 0.0, 1.0, -1, [], {}):
            with self.subTest(value=value):
                result = self.apply_with({"pdf_b64": "OUTPUT_TEST_BYTES", "could_not_remove": value})
                self.assertEqual(result["reason"], "invalid_removal_outcome")
                self.assertNotIn("pdf_b64", result)

    def test_zero_preserves_the_engine_response_but_does_not_assert_verification(self):
        response = {"pdf_b64": "OUTPUT_TEST_BYTES", "could_not_remove": 0, "low_text": True}
        self.assertIs(self.apply_with(response), response)
        self.assertNotIn("verified", response)
        self.assertNotIn("safe", response)

    def test_existing_engine_error_is_preserved(self):
        response = {"error": "The redaction engine is not installed."}
        self.assertIs(self.apply_with(response), response)

    def test_request_keeps_existing_ids_and_options(self):
        with patch.object(redactionmodel, "_run", return_value={"could_not_remove": 0}) as run:
            redactionmodel.pdf_apply("SOURCE_TEST_BYTES", [0, 3], {"terms": ["PARTY_TEST"], "locales": ["sg"]})
        request = run.call_args.args[0]
        self.assertEqual(request["op"], "pdf_apply")
        self.assertEqual(request["data_b64"], "SOURCE_TEST_BYTES")
        self.assertEqual(request["accept_ids"], [0, 3])
        self.assertEqual(request["terms"], ["PARTY_TEST"])
        self.assertEqual(request["locales"], ["sg"])

    def test_empty_selection_is_not_promoted_to_accept_all(self):
        with patch.object(redactionmodel, "_run", return_value={"could_not_remove": 0}) as run:
            redactionmodel.pdf_apply("SOURCE_TEST_BYTES")
        self.assertEqual(run.call_args.args[0]["accept_ids"], [])


if __name__ == "__main__":
    unittest.main()
