"""
Smoke test for the fresh-corpus generalization harness GENERATOR (tools/genharness.py).

This is a GENERATOR-SANITY check ONLY — it does NOT run the full harness (redact-cli +
OCR over ~21 fixtures is far too slow for the smoke budget). It asserts the deterministic
generator produces a non-empty ground truth AND that the born-digital PDF's TEXT LAYER
actually carries the planted values (so the downstream measurement has something real to
redact). Everything is SYNTHETIC (fictional names + valid-format IDs) — no matter data.
"""

import importlib.util
import os
import tempfile
from pathlib import Path

# App-data isolation before any app.* import (mirrors the package __init__).
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-smoke-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

# Load tools/genharness.py by PATH (tools/ is not a package on sys.path).
_GH_PATH = Path(__file__).resolve().parent.parent.parent / "tools" / "genharness.py"
_spec = importlib.util.spec_from_file_location("genharness", _GH_PATH)
genharness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(genharness)


def test_generator_plants_ground_truth_present_in_text_layer():
    """generate_one(seed=7) is deterministic, yields a non-empty ground truth, and every
    planted value appears (whitespace-normalized) in the born-digital PDF's text layer."""
    pdf_bytes, planted = genharness.generate_one(seed=7)
    assert planted, "ground truth must be non-empty"
    assert isinstance(pdf_bytes, bytes) and pdf_bytes[:4] == b"%PDF", "born-digital PDF bytes"

    # Determinism: same seed -> identical GROUND TRUTH. (The PDF bytes themselves are NOT
    # byte-reproducible — PyMuPDF stamps a fresh /ID on every save — but the planted values
    # are a pure function of the seed, which is what the measurement depends on.)
    _, planted2 = genharness.generate_one(seed=7)
    assert planted2 == planted, "generator ground truth must be deterministic from the seed"

    hay = genharness.normalize(genharness._text_layer(pdf_bytes))
    for value, cls in planted:
        assert cls in genharness.CLASSES, f"unknown class {cls!r}"
        assert genharness.normalize(value) in hay, \
            f"planted {cls} value {value!r} missing from the PDF text layer"
