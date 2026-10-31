"""Deterministic regressions, not real-document recovery or accuracy measurements."""

import json
import unittest

from app import exportverify as verify


class VerificationHardeningTests(unittest.TestCase):
    def classify(self, values, **kwargs):
        return verify.classify(accepted_values=values, **kwargs)

    def test_short_values_are_checked_against_whole_candidates(self):
        for value in ("A", "Li", "林星", "李", " L I "):
            with self.subTest(value=value):
                result = self.classify(
                    [{"value": value, "class": "term"}],
                    residual_candidates=[{"value": value, "recognizer": "term"}],
                )
                self.assertEqual(result["state"], verify.VERDICT_POSSIBLE)
                self.assertEqual(result["classes"], {"term": 1})
                self.assertEqual(result["checks"]["values_checked"], 1)
                self.assertEqual(result["checks"]["substring_values_checked"], 0)

    def test_short_value_absence_is_not_a_complete_check(self):
        result = self.classify([{"value": "Li"}], reextracted_text="unrelated text")
        self.assertEqual(result["state"], verify.VERDICT_UNVERIFIED)
        self.assertEqual(result["checks"]["exact_only_values"], 1)
        self.assertTrue(result["reasons"])

    def test_short_substrings_do_not_create_false_positive_recovery(self):
        result = self.classify([{"value": "Li"}], reextracted_text="litigation")
        self.assertNotEqual(result["state"], verify.VERDICT_POSSIBLE)

    def test_exact_matching_is_case_and_whitespace_insensitive(self):
        result = self.classify(
            [{"value": "LI", "class": "term"}],
            residual_candidates=[{"value": " l\ni ", "recognizer": "other"}],
        )
        self.assertEqual(result["classes"], {"term": 1})

    def test_empty_or_missing_targets_never_look_clean(self):
        for values in (None, []):
            for candidates in ([], [{"value": "unrelated"}]):
                with self.subTest(values=values, candidates=candidates):
                    result = self.classify(values, residual_candidates=candidates)
                    self.assertEqual(result["state"], verify.VERDICT_UNVERIFIED)
                    self.assertEqual(result["checks"]["values_checked"], 0)

    def test_unusable_target_among_valid_targets_preserves_incompleteness(self):
        for bad in (None, [], {}, {"value": ""}, {"value": " \t\n"}, {"value": 12}):
            with self.subTest(bad=bad):
                result = self.classify([{"value": "TARGET_A"}, bad])
                self.assertEqual(result["state"], verify.VERDICT_UNVERIFIED)
                self.assertEqual(result["checks"]["unusable_values"], 1)

    def test_explicit_partial_input_cannot_become_clean(self):
        result = self.classify([{"value": "TARGET_A"}], accepted_values_complete=False)
        self.assertEqual(result["state"], verify.VERDICT_UNVERIFIED)

    def test_long_value_substring_recovery_survives_rewrapping_and_casefold(self):
        result = self.classify(
            [{"value": "TARGET_A", "class": "term"}],
            reextracted_text="prefix t a\nr\tg e t _ a suffix",
        )
        self.assertEqual(result["state"], verify.VERDICT_POSSIBLE)

    def test_unicode_whitespace_and_casefold(self):
        result = self.classify(
            [{"value": "Straße", "class": "term"}],
            reextracted_text="S\u2003T\u00a0RASSE",
        )
        self.assertEqual(result["state"], verify.VERDICT_POSSIBLE)

    def test_duplicate_values_and_two_checks_do_not_double_count(self):
        result = self.classify(
            [{"value": "TARGET_A", "class": "term"}, {"value": "target_a", "class": "other"}],
            reextracted_text="TARGET_A TARGET_A",
            residual_candidates=[{"value": "TARGET_A"}, {"value": "TARGET_A"}],
        )
        self.assertEqual(result["classes"], {"term": 1})
        self.assertEqual(result["checks"]["values_checked"], 1)

    def test_positive_recovery_wins_over_other_failures(self):
        result = self.classify(
            [{"value": "Li", "class": "term"}, {}],
            residual_candidates=[{"value": "LI"}],
            extract_failed=True,
            low_text_signals=["an unexamined page remains"],
            accepted_values_complete=False,
        )
        self.assertEqual(result["state"], verify.VERDICT_POSSIBLE)

    def test_failed_extraction_and_coverage_warnings_never_look_clean(self):
        for kwargs in ({"extract_failed": True}, {"low_text_signals": ["image-only"]}):
            result = self.classify([{"value": "TARGET_A"}], **kwargs)
            self.assertEqual(result["state"], verify.VERDICT_UNVERIFIED)

    def test_complete_negative_check_retains_existing_state(self):
        result = self.classify(
            [{"value": "TARGET_A"}],
            reextracted_text="unrelated readable content",
            residual_candidates=[{"value": "intentionally retained"}],
        )
        self.assertEqual(result["state"], verify.VERDICT_NONE)
        self.assertEqual(result["checks"]["substring_values_checked"], 1)

    def test_results_never_contain_accepted_cleartext(self):
        secret = "PRIVATE_TEST_VALUE_7391"
        for text in (secret, "unrelated"):
            result = self.classify([{"value": secret, "class": "term"}], reextracted_text=text)
            self.assertNotIn(secret, json.dumps(result))

    def test_inputs_are_not_mutated(self):
        values = [{"value": "TARGET_A", "class": "term"}]
        candidates = [{"value": "TARGET_A", "recognizer": "term"}]
        reasons = ["image-only"]
        before = json.dumps([values, candidates, reasons])
        self.classify(values, residual_candidates=candidates, low_text_signals=reasons)
        self.assertEqual(json.dumps([values, candidates, reasons]), before)


if __name__ == "__main__":
    unittest.main()
