#!/usr/bin/env python3
"""
redact_pdf.py — one-command, format-preserving PDF redaction for developers.

Put YOUR OWN PDF in, get a redacted PDF back. This is the dead-simple CLI wrapper
around the SAME host path the desktop app uses (`app/redactionmodel.py` ->
the Rust `redact-cli` engine over a stdin/stdout JSON seam). No server, no browser.

    python scripts/redact_pdf.py INPUT.pdf --terms "Name One,Name Two"
    python scripts/redact_pdf.py INPUT.pdf --terms "Acme Pte Ltd" --out clean.pdf

What it does (apply-ALL by default):
  1. reads INPUT.pdf into memory (bytes go to the engine on STDIN only — never argv),
  2. runs `pdf_scan` (the default global recognizers: email / phone / id / credit-card /
     IBAN / IP / URL / name-heuristic) PLUS any party/company names you pass via --terms
     ("super find & replace" — the reliable way to redact KNOWN names),
  3. accepts EVERY detected candidate and runs `pdf_apply` (true byte removal),
  4. writes the redacted PDF next to a chosen output path — NEVER overwriting the input,
  5. prints an honest summary: how many redactions, anything it could NOT remove, and a
     loud warning if the PDF looks SCANNED (image-only) or used fonts it could only decode
     best-effort (so a low count must NOT be read as "clean").

HONEST FRAMING (do not overclaim): this performs reasonable-efforts deterministic
redaction. It is NOT "safe to send". The residual-identifier judgment is the lawyer's.
A scanned/image PDF needs the OCR path (the desktop app's "Redact & save PDF" on a
scanned file, requires Tesseract) — this CLI flags it and refuses rather than returning a
silently-unredacted file.

LOCAL-ONLY: runs one local executable, exchanges local JSON. No network, no model.

ENGINE: the bin is found via app/redactionmodel.py's resolver
(env LAWDATAMAN_REDACT_CLI -> vendor/core/redact-cli -> PATH). On a fresh checkout build
it first:  cd core && cargo build -p redact-cli  (then point LAWDATAMAN_REDACT_CLI at
core/target/debug/redact-cli, or stage it under vendor/core/).
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

# Run from the repo root with the package importable:  PYTHONPATH=. python scripts/redact_pdf.py ...
# Make that robust even if the caller forgot PYTHONPATH, by adding the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app import redactionmodel  # noqa: E402


def _parse_terms(raw: str | None) -> list[str]:
    """Split a comma-separated --terms string into a clean list (the engine trims +
    escapes each; we only split + drop blanks). A name with a comma can't be expressed
    this way — pass --terms multiple times instead (argparse appends)."""
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def _default_out(inp: Path, out_dir: Path | None) -> Path:
    """`<stem>.redacted.pdf` in out_dir (default: alongside the input). NEVER returns the
    input path; if it would collide, append ` (1)`, ` (2)`, ... — never overwrite."""
    d = out_dir if out_dir is not None else inp.parent
    base = f"{inp.stem}.redacted.pdf"
    out = d / base
    n = 1
    # Never overwrite the input, and never overwrite an existing output.
    while out.exists() or out.resolve() == inp.resolve():
        out = d / f"{inp.stem}.redacted ({n}).pdf"
        n += 1
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="redact_pdf.py",
        description="Format-preserving PDF redaction (apply-all). Local, deterministic, no network.",
    )
    ap.add_argument("input", help="path to the PDF to redact")
    ap.add_argument(
        "--terms",
        action="append",
        default=[],
        help='comma-separated KNOWN names/companies to redact, e.g. --terms "Acme Pte Ltd,Jane Tan". '
        "May be given multiple times (use this for names containing a comma).",
    )
    ap.add_argument(
        "--out",
        help="output PDF path (default: <input>.redacted.pdf next to the input, never overwriting it)",
    )
    ap.add_argument(
        "--out-dir",
        help="directory for the default-named output (ignored if --out is given)",
    )
    args = ap.parse_args(argv)

    inp = Path(args.input)
    if not inp.exists() or not inp.is_file():
        print(f"error: not a file: {inp}", file=sys.stderr)
        return 2
    if inp.suffix.lower() != ".pdf":
        print(
            f"error: expected a .pdf (got {inp.suffix or 'no extension'}). "
            "For .docx/.eml/.msg/.txt use the desktop app's Redaction page (extract-then-redact).",
            file=sys.stderr,
        )
        return 2

    # Engine availability — give a build hint, don't just fail silently.
    if not redactionmodel.available():
        print(
            "error: the redaction engine (redact-cli) was not found.\n"
            "  Build it:   cd core && cargo build -p redact-cli\n"
            "  Then point at it:   "
            "export LAWDATAMAN_REDACT_CLI=$(pwd)/core/target/debug/redact-cli\n"
            "  (or stage the binary under vendor/core/redact-cli).",
            file=sys.stderr,
        )
        return 3

    terms: list[str] = []
    for chunk in args.terms:
        terms.extend(_parse_terms(chunk))
    # De-dup, order-preserving (the engine de-dups too; this keeps the printout clean).
    seen: set[str] = set()
    terms = [t for t in terms if not (t in seen or seen.add(t))]

    try:
        pdf_bytes = inp.read_bytes()
    except OSError as e:
        print(f"error: could not read {inp}: {e}", file=sys.stderr)
        return 2

    b64 = base64.b64encode(pdf_bytes).decode("ascii")
    # The engine config: default global recognizers + the user's literal terms. Built
    # ONCE per request inside the bin and reused for scan AND apply, so the ids align.
    options = {"terms": terms} if terms else {}

    # 1) SCAN — find candidates (read-only; nothing written).
    scan = redactionmodel.pdf_scan(b64, options)
    if "error" in scan:
        # The engine refuses encrypted / malformed / over-large PDFs here with a friendly,
        # value-free message; surface it as-is.
        print(f"error: {scan['error']}", file=sys.stderr)
        if "encrypted" in scan["error"].lower():
            print(
                "hint: decrypt the PDF first (e.g. `qpdf --decrypt in.pdf out.pdf`) then re-run.",
                file=sys.stderr,
            )
        return 4

    candidates = scan.get("candidates", [])
    low_text = bool(scan.get("low_text", False))
    unmapped = bool(scan.get("unmapped_fonts", False))

    # SCANNED / image-only PDF: text byte-splicing can't touch identifiers baked into
    # images. Refuse rather than hand back a silently-unredacted "redacted" file.
    if low_text:
        print(
            "REFUSING: this PDF has little or no extractable text — it looks SCANNED / "
            "image-only.\n"
            "Text redaction cannot remove identifiers baked into page images. Use the "
            "desktop app's\n"
            "Redaction page on a scanned PDF (the OCR image-burn path; requires Tesseract), "
            "which\n"
            "detects text via OCR and burns black boxes into the raster.",
            file=sys.stderr,
        )
        return 5

    if not candidates:
        print(
            "No identifiers detected. Nothing to redact — no output written.\n"
            "(If you expected matches, pass the known names via --terms, "
            'e.g. --terms "Acme Pte Ltd".)'
        )
        if unmapped:
            print(
                "WARNING: some pages used fonts that could only be decoded best-effort "
                "(unmapped_fonts).\n"
                "A zero/low count on those pages must NOT be read as 'clean' — review manually."
            )
        return 0

    # 2) APPLY-ALL — accept every detected id (the stable ids from the scan).
    accept_ids = [c["id"] for c in candidates if isinstance(c.get("id"), int)]
    ap_res = redactionmodel.pdf_apply(b64, accept_ids, options)
    if "error" in ap_res:
        print(f"error: {ap_res['error']}", file=sys.stderr)
        return 4

    pdf_b64 = ap_res.get("pdf_b64")
    if not isinstance(pdf_b64, str):
        print("error: the engine returned no PDF bytes.", file=sys.stderr)
        return 4
    try:
        out_bytes = base64.b64decode(pdf_b64, validate=True)
    except (ValueError, Exception):  # noqa: BLE001 - any decode failure is a hard error here
        print("error: the engine returned an unreadable PDF.", file=sys.stderr)
        return 4

    # 3) WRITE — never overwrite the input or an existing output.
    if args.out:
        out_path = Path(args.out)
        if out_path.resolve() == inp.resolve():
            print("error: --out must not be the input file (no in-place redaction).", file=sys.stderr)
            return 2
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = Path(args.out_dir) if args.out_dir else None
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
        out_path = _default_out(inp, out_dir)
    try:
        out_path.write_bytes(out_bytes)
    except OSError as e:
        print(f"error: could not write {out_path}: {e}", file=sys.stderr)
        return 2

    # 4) HONEST SUMMARY.
    redactions = ap_res.get("redactions", 0)
    could_not = ap_res.get("could_not_remove", 0)
    print(f"Redacted PDF written: {out_path}")
    print(f"  redactions applied: {redactions}")
    if terms:
        print(f"  user terms: {', '.join(terms)}")
    if could_not:
        print(
            f"  WARNING: {could_not} accepted span(s) could NOT be truly removed "
            "(no resolvable source bytes).\n"
            "           Those identifiers may SURVIVE — review the output manually before sharing."
        )
    if unmapped:
        print(
            "  WARNING: some pages used fonts decodable only best-effort (unmapped_fonts).\n"
            "           Detection on those pages was incomplete — a low count is NOT a guarantee "
            "of 'clean'."
        )
    diagnostics = ap_res.get("diagnostics") or []
    if diagnostics:
        print(f"  diagnostics: {len(diagnostics)} note(s) (content-free)")
    print(
        "\nHONEST: reasonable-efforts deterministic redaction — NOT a guarantee the document "
        "is safe to send.\nReview the output yourself before sharing."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
