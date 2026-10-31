"""Actual compiled-engine integration; no engine/decoder/response test doubles.

The small disclosure PDF is an existing artificial regression fixture, not a real
matter. The prospectus test uses the existing public BGF document unchanged. These
checks prove these specific recovery paths, not broad document accuracy or safety.
"""

import base64
import hashlib
import json
import os
import unittest
from pathlib import Path

from app import exportverification, exportverify, redactionmodel, verificationmodel

ROOT = Path(__file__).resolve().parent.parent


class EngineVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not redactionmodel.redact_cli_path():
            if os.environ.get("REDACTOR_REQUIRE_ENGINE") == "1":
                raise RuntimeError("Real redaction engine required, but unavailable")
            raise unittest.SkipTest("real redaction engine not supplied")

    def test_actual_text_contract_recovers_short_unicode_and_whitespace_variants(self):
        raw = "Contact Li and 林星. T A R G E T _ A remains.".encode()
        result = verificationmodel.verify(raw, ["Li", "林星", "TARGET_A"], kind="text")
        self.assertNotIn("error", result)
        self.assertEqual(result["values_with_residuals"], 3)
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(all(row["residual_found"] for row in result["results"]))

    def test_actual_negative_text_preserves_limitations(self):
        result = exportverification.check(b"[REDACTED]", [{"value": "TARGET_A"}], {}, kind="text")
        self.assertEqual(result["state"], exportverify.VERDICT_NONE)
        self.assertEqual(result["rust"]["status"], "completed")
        self.assertIn("no_finding_is_not_removal_proof", result["limitations"])

    def test_actual_invalid_pdf_is_an_error_not_a_negative(self):
        result = verificationmodel.verify(b"not a PDF", ["TARGET_A"], kind="pdf")
        self.assertEqual(result["reason"], "engine_failed")

    def test_actual_pdf_scan_apply_probe_roundtrip(self):
        source = (ROOT / "_testfixtures" / "disclosure.pdf").read_bytes()
        encoded = base64.b64encode(source).decode()
        import fitz
        with fitz.open(stream=source, filetype="pdf") as doc:
            target = next(line.strip() for line in doc[0].get_text().splitlines()
                          if len(line.strip()) >= 8)
        options = {"terms": [target]}
        scan = redactionmodel.pdf_scan(encoded, options)
        self.assertNotIn("error", scan)
        self.assertTrue(scan["candidates"])
        records = [{"value": c["value"], "class": c["recognizer"]} for c in scan["candidates"]]
        values = list(dict.fromkeys(c["value"] for c in scan["candidates"]))
        before = verificationmodel.verify(source, values, kind="pdf")
        self.assertNotIn("error", before)
        self.assertGreater(before["values_with_residuals"], 0)
        applied = redactionmodel.pdf_apply(encoded, [c["id"] for c in scan["candidates"]], options)
        self.assertNotIn("error", applied)
        output = base64.b64decode(applied["pdf_b64"], validate=True)
        after = exportverification.check(output, records, options, kind="pdf")
        self.assertEqual(after["rust"]["status"], "completed")
        self.assertEqual(after["rust"]["values_with_residuals"], 0)
        self.assertEqual(after["state"], exportverify.VERDICT_UNVERIFIED)
        self.assertEqual(after["artifact_sha256"], hashlib.sha256(output).hexdigest())
        self.assertEqual(after["rust"]["not_probed"], list(verificationmodel.PDF_NOT_PROBED))

    def test_unchanged_public_prospectus_recovers_existing_target(self):
        # A real published corpus document already tracked by the project. The
        # target comes from its actual extracted text, not planted/generated data.
        import fitz
        source = (ROOT / "tests" / "bgf-singapore-prospectus-sg.pdf").read_bytes()
        with fitz.open(stream=source, filetype="pdf") as doc:
            lines = doc[0].get_text().splitlines()
        target = next(line.strip() for line in lines if 8 <= len(line.strip()) <= 80
                      and line.strip().isascii() and any(c.isalpha() for c in line))
        result = verificationmodel.verify(source, [target], kind="pdf")
        self.assertNotIn("error", result)
        self.assertEqual(result["values_with_residuals"], 1)
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(source).hexdigest())
        self.assertNotIn(target, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
