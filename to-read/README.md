# lawdataman — Data Room Review

Local-only full-text search + one-click automations over an **exported** legal data room.
Free, runs entirely on your machine — no internet, no model/LLM calls, no telemetry.
Originals are read-only and never modified.

## What it does
- Indexes PDF, DOCX, XLSX/XLSM, PPTX, TXT/MD, EML, MSG.
- Full-text search (phrase, prefix `term*`, boolean `AND/OR/NOT`); hits point to
  page/slide/named sheet.
- sha256 per file (integrity + dup detection); incremental re-index.
- **Tools:** *Document index* — read-only "schedule of documents" → Excel-friendly CSV,
  flags scanned PDFs/images as "needs OCR"; *Batch rename* — preview → apply → undo, never
  overwrites, confined off the read-only source tree.
- **Redaction review** — deterministically strip identifiers (email, phone, IDs,
  credit-card/IBAN, names, URLs/IPs) from pasted text or an uploaded file
  (`.txt/.md/.csv/.eml/.msg/.docx`), with a **two-tier** (quick-confirm vs careful) review;
  **PDF redaction is format-preserving** (true text removal) and saves a redacted copy.
  Powered by the bundled Rust core (no model/LLM). Reasonable-efforts, **never "safe to
  send"** — the lawyer owns the residual-identification judgment.
- Self-contained dashboard; works air-gapped.

## Develop / test
    PYTHONPATH=. python3 tests/test_smoke.py     # headless unit/integration
    PYTHONPATH=. python3 tests/test_e2e.py       # real-server end-to-end
    ruff check app desktop tests                 # lint

CI runs both suites on Linux + Windows (`.github/workflows/ci.yml`). Dev-only CLIs
(`python -m app.index`, `python -m app.serve`) are never shown to end users — the shipped
app is a native window (`desktop/main.py`).

## License
**AGPL-3.0** (see [`LICENSE`](LICENSE)) — free software: source is available, and the
running app links to it. AGPL obligations fall on whoever *distributes* the binary; a firm
that merely *uses* the app has none. The PDF (PyMuPDF) and `.msg` (extract-msg) backends
are copyleft, both dispatched through a pluggable seam (`LAWDATAMAN_PDF_BACKEND` /
`LAWDATAMAN_MSG_BACKEND`) so a permissive build can swap them. Inventory:
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md); rationale: [`licensing.md`](licensing.md).
