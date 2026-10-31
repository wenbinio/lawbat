# Third-party licenses

Dependency inventory with licenses (verified against PyPI metadata, June 2026).
**Copyleft** deps are called out — they create obligations when the app is *distributed*
as a binary. Rationale + chosen direction: `licensing.md`.

## Runtime dependencies

| Package | Purpose | License | Type |
|---|---|---|---|
| **PyMuPDF** (`fitz`) | PDF text extraction | **AGPL-3.0** OR Artifex commercial | ⚠️ **copyleft (network)** |
| **extract-msg** | Outlook `.msg` extraction | **GPL** | ⚠️ **copyleft** |
| Pillow (PIL) | image handling for the OCR image-redaction path (`app/imageredact.py`) | HPND (permissive, MIT/BSD-like) | permissive |
| python-docx | DOCX extraction | MIT | permissive |
| openpyxl | XLSX/XLSM extraction | MIT | permissive |
| python-pptx | PPTX extraction | MIT | permissive |
| fastapi | localhost web app | MIT | permissive |
| starlette *(via fastapi)* | ASGI framework | BSD-3-Clause | permissive |
| pydantic *(via fastapi)* | validation | MIT | permissive |
| uvicorn | ASGI server | BSD-3-Clause | permissive |
| pywebview | native desktop window | BSD-3-Clause | permissive |
| *(stdlib)* email, sqlite3, hashlib | EML parse, FTS5 store, hashing | PSF | permissive |

## Bundled binaries shipped in the MSI (vendor/, gitignored)

| Component | Purpose | License | Note |
|---|---|---|---|
| Embeddable CPython | the runtime | PSF | official embeddable distribution |
| WebView2 Evergreen bootstrapper | render the window | Microsoft (redistributable) | prerequisite; present on current Win10/11 |
| Tesseract + tessdata | OCR (Tier-2, optional feature) | Apache-2.0 | external binary, not pip |
| qpdf | PDF repair/linearize | Apache-2.0 | external binary, not pip |
| pdfium (via pypdfium2) | rasterize (OCR/verify) | BSD-3-Clause / Apache-2.0 | permissive |

## Build-only (not shipped; on the Windows build host)

| Tool | Purpose | License | Note |
|---|---|---|---|
| WiX Toolset | author the MSI | MS-RL (v3) / MIT (v4+) | installer build |
| ruff | lint (dev/CI) | MIT | dev only |

*(PyInstaller/Inno Setup dropped — packaging is MSI via WiX + embedded Python; see `packaging.md`.)*

## Permissive PDF/MSG alternatives (if a copyleft-free build is wanted)

| Package | Replaces | License | Trade-off |
|---|---|---|---|
| pypdf | PyMuPDF (text) | BSD-3-Clause | pure-Python; weaker on messy/real-world PDFs; no fast rendering |
| pdfminer.six | PyMuPDF (text) | MIT | layout-aware text; slower; less robust than MuPDF |
| pdfplumber | PyMuPDF (text/tables) | MIT | built on pdfminer.six |
| olefile + custom parse | extract-msg | BSD-2-Clause | `.msg` is an OLE compound file; permissive parse possible but more code |

## Bundled reference data (`data/reference/`, tracked in the repo)

The re-identification risk estimator (`app/reidrisk.py`) ships 9 **marginal frequency
tables** (population QI distributions). Full per-file provenance + attribution is in
**`data/reference/SOURCES.md`**; drop-in guidance for the (openly-licensed but un-fetched)
finer tables is in **`data/reference/DROPIN.md`**.

| Group | Files | License | Obligation |
|---|---|---|---|
| Singapore (SingStat / MOM / MOH-HPB via data.gov.sg) | `sg-sex`, `sg-age-band`, `sg-occupation`, `sg-population-by-planning-area`, `sg-medical-prevalence` | **Singapore Open Data Licence v1.0** (<https://data.gov.sg/open-data-licence>) | **Attribution REQUIRED** — recorded per-dataset in `SOURCES.md` |
| United States (Census Bureau / SSA) | `us-sex`, `us-surname`, `us-given-name`, `us-population-by-state` | **US Public Domain (17 U.S.C. § 105)** | none (credited for traceability) |

> **NOT bundled:** an SG surname-frequency table — the only figures located were from a
> **commercial aggregator (forebears.io), NOT redistributable**. There is no open SG
> surname dataset (`DROPIN.md`). Do not add it.
