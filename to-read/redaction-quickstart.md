<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Redaction — Quickstart (run it yourself)

Put your own PDF in, get a redacted PDF out. Local, deterministic, no network, no AI, no cloud.

## Prerequisites
- **Python 3.11 or 3.12**, then `pip install -r requirements.txt`
  (PyMuPDF is needed for the scanned/OCR path; the plain CLI path needs very little).
- **Rust toolchain** to build the engine once (1.96 recommended — the version CI pins).
- **Tesseract OCR** installed *only if* you need the scanned-PDF path.

## 1. Build the engine (once)
```bash
cd core
cargo build -p redact-cli --release        # --release = faster; omit it for a quicker debug build
cd ..
export LAWDATAMAN_REDACT_CLI="$(pwd)/core/target/release/redact-cli"
# debug build -> .../core/target/debug/redact-cli
# Windows: set LAWDATAMAN_REDACT_CLI to ...\core\target\release\redact-cli.exe
```

## 2a. Redact a PDF — one command
```bash
PYTHONPATH=. python scripts/redact_pdf.py YOUR.pdf --terms "Jane Tan,Acme Pte Ltd,Director Two"
```
- Output: `YOUR.redacted.pdf` next to the input — **never overwrites**. Use `--out clean.pdf` to choose a path.
- `--terms` = the **known names/companies to hide** (the reliable lever for KNOWN names). Comma-separated;
  repeat `--terms` for a name that itself contains a comma.
- It also auto-detects emails / phone numbers / ID shapes / credit cards / IBAN / IP / URLs + a name heuristic.

## 2b. Or use the web UI
```bash
PYTHONPATH=. python -m app.serve           # serves http://127.0.0.1:8077
```
Open **http://127.0.0.1:8077/redaction** → upload a PDF → **"Redact & save PDF"** → the redacted file lands in
the exports dir (`%APPDATA%\DataRoomReview\exports` on Windows; `$LAWDATAMAN_DATA_DIR/exports` in dev) and is revealed.

## Read the output HONESTLY (important — this is reasonable-efforts, never "safe to send")
- **Born-digital PDFs** (real text layer): **true byte removal** — the text is gone, not visually covered.
- **Subset / CID fonts** (common in professionally-produced PDFs): the engine can **MISS** text on those pages
  and prints a loud **`unmapped_fonts` WARNING**. **A low/zero count on those pages is NOT "clean."** For maximum
  certainty on such a file, use the **OCR image-burn path** (web UI on a scanned/forced-OCR file) — it reads the
  rendered *pixels*, so it is font-independent.
- **Scanned / image-only PDFs**: the CLI **refuses** (exit 5) rather than hand back a silently-unredacted file.
  Use the web UI's OCR path (needs Tesseract): it OCRs the page and burns black boxes (true pixel removal).
- **Large PDFs** (hundreds of pages): handled — the engine subprocess timeout **scales with file size**
  (a ~960-page prospectus takes ~75 s).
- **Always review the output yourself.** Residual re-identification ("the only deal closing this quarter") is the
  reviewer's judgment, not something string-matching removes.

## Troubleshooting (the CLI prints a hint + a distinct exit code)
| Exit | Meaning | Fix |
|---|---|---|
| 3 | engine `redact-cli` not found | build it (step 1) + set `LAWDATAMAN_REDACT_CLI` |
| 4 | encrypted / malformed / over-large PDF | decrypt first: `qpdf --decrypt in.pdf out.pdf`, then re-run |
| 5 | scanned / image-only PDF | use the web UI OCR path (needs Tesseract) |
| 2 | not a `.pdf` (e.g. `.docx`/`.eml`/`.msg`) | use the web UI (extract-then-redact) |
| 0 + "No identifiers detected" | nothing matched | pass the known names via `--terms` |
