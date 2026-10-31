<p align="center">
  <img src="assets/logo/lawbat-logo.svg" alt="Lawbat" width="128">
</p>

# Lawbat

**Local-first redaction and re-identification risk checks for legal documents.**

Search an exported data room, build a schedule of documents, and redact identifiers with a lawyer in the loop. Originals stay read-only. The app does not call a model and does not use the network.

This tree is the public source for the [BLI Legal Tech Hackathon 2](https://bli.tools/hackathon/) submission. Start with the demo, then read [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/BLI_SUBMISSION.md](docs/BLI_SUBMISSION.md).

## The problem

A closing or a regulatory response often arrives as a folder of PDFs, emails, and office files. Someone still has to find the right document, list the room, and remove identifiers before a draft goes out. Hosted review tools assume an IT team and an upload of privileged material. Desktop search and find-and-replace miss messy files and leave identifiers in the copy that is actually sent.

## What it does

- **Search** at `/app`. Full-text over PDF, Word, Excel, PowerPoint, text, and email. Hits point at a page, a slide, or a sheet.
- **Document schedule.** A read-only index of the open room, folder-grouped, with a CSV export. Scanned pages are marked as needing OCR.
- **Redaction review** at `/redaction`. A deterministic Rust engine proposes emails, phone numbers, ID-shaped strings, payment numbers, addresses, and party names you type in. The reviewer is split into stages: Document, Detect, Review (findings and sensitive passages together), Export, and a Report of what was saved. You can also review a folder of files. On a text PDF the engine removes the underlying text.
- **Document workspace** at `/workspace`. Prepare a redaction, inspect it, and only then release the file. Release is a separate step and asks for an explicit inspection attestation. A removal failure cannot be clicked through.
- **Re-identification risk** at `/reid-risk`. Estimates how unique a passage still looks. The figure is an optimistic lower bound. It can raise concern. It never says a document is safe to send.
- **Home** at `/`. A local worklist. If the Rust `viewgen` binary is present it is generated on this machine. If not, the page says it is a preview sample.

Redaction is reasonable-efforts removal of matched identifiers. It is not a clearance to disclose the document.

## Tech stack

| Piece | Role |
|---|---|
| Python 3.11 or 3.12, FastAPI, uvicorn | Localhost app (`app/`, `desktop/`) |
| SQLite FTS5 | Per-matter index, stored outside the source folder |
| PyMuPDF, python-docx, openpyxl, python-pptx, extract-msg | Format extractors |
| Rust (`core/`) | Redaction engine (`redact-cli`), home view-model (`viewgen`) |
| pywebview + WiX | Windows desktop shell and MSI (Lawbat, and a redaction-only Redactor installer) |

License: **AGPL-3.0**. See [LICENSE](LICENSE) and [to-read/THIRD_PARTY_LICENSES.md](to-read/THIRD_PARTY_LICENSES.md). Windows install notes: [docs/INSTALL.md](docs/INSTALL.md).

## Run the demo

From a fresh clone, with Python 3.12 and Rust stable:

```bash
git clone https://github.com/wenbinio/lawbat.git
cd lawbat

python3 -m pip install fastapi "uvicorn[standard]" pymupdf python-docx openpyxl python-pptx pillow

cd core
cargo build -p redact-cli -p viewgen --release
cd ..

./run.sh --demo
```

`./run.sh --demo` indexes the fictional folder `demo/sample-room/` (a made-up Harbour Lane matter, not a client file), stores that index under `.demo-data/` in the clone, and opens <http://127.0.0.1:8077/>.

| Page | URL | What to do |
|---|---|---|
| Home | <http://127.0.0.1:8077/> | Local worklist. A preview banner means `viewgen` was not found. |
| Data room | <http://127.0.0.1:8077/app> | Search `Harbour Lane`. Tools, then Document index, then Build index. |
| Redaction | <http://127.0.0.1:8077/redaction> | **Try it with a sample document**, then scan and review. |
| Workspace | <http://127.0.0.1:8077/workspace> | Inspect a prepared redaction before it is released. |
| Re-ID risk | <http://127.0.0.1:8077/reid-risk> | Paste `demo/sample-room/02-corporate/directors.md` and estimate k. |

On Windows, `run.bat --demo` does the same. Without Rust, search and the schedule still work. Redaction then shows an honest offline state, and Home shows the bundled sample.

Check setup any time with `PYTHONPATH=. python3 -m app.doctor`.

## Tests

```bash
python3 -m pip install httpx
PYTHONPATH=. python3 tests/test_demo.py
PYTHONPATH=. python3 tests/test_smoke.py
PYTHONPATH=. python3 tests/test_e2e.py
python3 -m ruff check app desktop tests
```

`ruff.toml` keeps the lint rule set this tree is written against.

## Layout

- `app/` — indexer, search, redaction reviewer, document workspace, re-identification estimator
- `desktop/` — Windows launcher
- `core/` — Rust workspace. Build notes: [to-read/core.README.md](to-read/core.README.md)
- `demo/sample-room/` — fictional data room used by `--demo`
- `assets/logo/` — logo, app icon, and the DoraHacks cover
- `tests/*.pdf` and `demo/*.pdf` — public fund prospectuses used as redaction fixtures, not client files
