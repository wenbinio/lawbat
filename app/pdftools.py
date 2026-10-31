"""
Entry points for optional bundled PDF utilities:

- **qpdf** (Apache-2.0): repair/linearize malformed PDFs that the extractor
  chokes on. Writes a clean COPY; never mutates the read-only source.
- **pdfium** (BSD-3, via pypdfium2): rasterization, used by the OCR path and,
  later, the redaction-verify step.

Both are optional; absence is fine and reported by the *_available() probes.
"""

import subprocess
from pathlib import Path

from .vendor import bundled_tool


def qpdf_path() -> str | None:
    return bundled_tool("qpdf")


def qpdf_available() -> bool:
    return qpdf_path() is not None


def repair_pdf(src, dst, timeout: int = 120) -> bool:
    """Rewrite a possibly-malformed PDF to a clean, linearized COPY at `dst`.
    Returns True on success, False if qpdf is unavailable or fails. Never writes
    to `src` (read-only-source invariant)."""
    exe = qpdf_path()
    if not exe:
        return False
    try:
        r = subprocess.run(
            [exe, "--linearize", "--", str(src), str(dst)],
            capture_output=True, timeout=timeout,
        )
    except Exception:  # noqa: BLE001
        return False
    # qpdf exit codes: 0 = ok, 3 = warnings but output was still written.
    return r.returncode in (0, 3) and Path(dst).exists()


def pdfium_available() -> bool:
    """True if a pdfium rasterizer (pypdfium2) is importable."""
    try:
        import pypdfium2  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False
