# Packaging — Windows MSI (no PyInstaller)

**Decision:** ship a standard **MSI** built with the **WiX Toolset**, wrapping an
**embedded CPython** runtime + our (AGPL) `.py` + a small launcher. No PyInstaller / no
freezing — because:
- **IT trust:** MSI is Group-Policy / Intune deployable, with clean install/upgrade/uninstall.
  Right for managed-Windows-VM firms.
- **No freezer:** fewest AV false positives (no bootloader stub), fully transparent; shipping
  readable Python is fine (the project is AGPL/open).
- **Signing is the real trust lever, not the format:** an unsigned MSI still trips
  SmartScreen/UAC. Authenticode deferred for the closed pilot; **EV before public release.**

## Payload layout (inside the MSI)
```
DataRoomReview/
  python/            # official embeddable CPython (python-3.x-embed-amd64)
  app/  desktop/     # our source (AGPL)
  vendor/            # bundled binaries, laid down by the build — NEVER in git
    tesseract/tesseract.exe + tessdata/   # OCR (Apache-2.0)   [optional MSI feature]
    qpdf/qpdf.exe                          # PDF repair (Apache-2.0)
    pdfium/...                             # rasterizer (BSD-3) [or pip pypdfium2]
  DataRoomReview.exe # tiny launcher: runs desktop/main.py with the embedded python
  LICENSE  THIRD_PARTY_LICENSES.md
```
`app/vendor.py` resolves binaries at runtime (env → `vendor/` → PATH). WebView2: bundle the
**Evergreen bootstrapper** as a prerequisite. Verify **FTS5** in the embedded Python; ship
`pysqlite3` only if missing.

## MSI structure (WiX)
A base **Feature** (app + Python + WebView2 + qpdf) + an **optional OCR Feature** (Tesseract +
tessdata) so the base install stays lean and AV-quiet. Per-user install (no admin), Start-menu
shortcut; standard UpgradeCode so versions replace cleanly. **Never change the UpgradeCode**
(breaks upgrade).

---

## Runbook — building it (as built)

### Source artifacts (committed; outputs gitignored)
```
build/
  pins.psd1          # versions + SHA256 for every fetched artifact (THE bump point)
  assemble.ps1       # download+verify -> embed Python -> pip -> payload diet -> vendor -> stage
  payload_census.ps1 # file-count + MB per top-level dir; called from assemble.ps1 (partial) and
                      # the workflow after the Rust core stages (full) — see "Payload size" below
  smoke_check.py     # runs under the EMBEDDED interpreter; asserts imports/FTS5/server
  wix/
    Product.wxs      # the MSI (features, per-user install, shortcuts, harvesting)
    README.md        # wix build invocation + per-machine variant (`to-read/wix.README.md`)
    assets/          # app.ico goes here (NOT committed — add on Windows)
  stage/  out/  _dl/ # build OUTPUT — gitignored, never committed
.github/workflows/package-windows.yml   # CI: assemble -> smoke -> wix build -> artifact
```

### Prerequisites on the build host
Windows 10/11 x64; .NET SDK + `dotnet tool install --global wix --version 5.*`; a real
`build/wix/assets/app.ico`; pinned/verified hashes in `build/pins.psd1`.

### Build steps (local)
```powershell
# 1. Assemble (download+verify, embed Python, pip-install, lay vendor base vs OCR).
#    Add -IncludeOcr:$false to skip OCR.
./build/assemble.ps1

# 2. Smoke-check the ASSEMBLED bundle with its OWN embedded interpreter.
$py = Resolve-Path .\build\stage\DataRoomReview\python\python.exe
& $py .\build\smoke_check.py --install-dir (Resolve-Path .\build\stage\DataRoomReview).Path

# 3. Build the MSI.
$stage = (Resolve-Path .\build\stage\DataRoomReview).Path
wix build .\build\wix\Product.wxs -arch x64 -d Version=0.1.0 -d StageDir=$stage -o .\build\out\DataRoomReview-0.1.0.msi
```
CI (`package-windows.yml`) runs exactly these three steps on `windows-latest`, publishes a
pre-release, and uploads the `.msi`. Triggers: `workflow_dispatch` + pushes to the `packaging`
branch **or any `packaging/**` branch** (no dummy-commit/paths-filter dance — push any
unmodified dev branch straight to `packaging/<name>`). Not a required check, so it can't break
green CI.

### Pinning model: immutable (hard-pinned) vs evergreen (recorded)
`build/pins.psd1` has two artifact kinds:
- **Immutable, version-locked** — embeddable **Python**, **qpdf**, **Tesseract**. HARD-PINNED
  by SHA256; `assemble.ps1` aborts on a placeholder/mismatch. All three are now real, non-
  placeholder pins (Python's captured 2026-07-02 from a CI runner's own fresh download —
  python.org is unreachable from the dev sandbox, so its independence rests on each green
  packaging run's fresh re-download hash-matching, fail-closed on mismatch, rather than a
  python.org-published digest).
- **Evergreen, moving "latest"** — **get-pip** + the **WebView2 bootstrapper**. Marked
  `Evergreen = $true`: the build RECORDS the observed hash but does not gate on it.

A normal build needs **no** `allow_unverified` flag once immutable hashes are pinned. The
input is a one-time escape hatch to capture a NEW immutable hash (e.g. after a Python bump):
set it via `workflow_dispatch`, read the printed `Got: <hash>`, paste into `pins.psd1`, drop
the flag, re-run — verify must then pass. (There is deliberately no commit-message bypass.)

### OCR (Tesseract) staging
The base install omits `vendor\tesseract\`; the OCR feature 7z-**extracts** the pinned
Tesseract installer (rather than executing it silently) and harvests `tesseract.exe` + every
sibling DLL + `eng`/`osd` tessdata by recursive search — this replaced an earlier approach
where a silent NSIS install completed cleanly but laid down no `tesseract.exe`. CI-proven: the
fatal smoke gate runs a real OCR round-trip on the staged bundle.

### Payload size (MSI diet)
A user-reported install was ~195 MB / ~5,600 files. `assemble.ps1` step 8 ("payload diet",
between the pip-install steps and the vendor-binary stage) now removes provably build-time-only
weight from the staged tree before `wix build` ever runs (WiX harvests `<Files
Include="...\**">` globs at build time, so anything deleted here is simply never packed):
- **pip + setuptools + wheel**, from the EMBEDDED INTERPRETER's own `python\Lib\site-packages`
  (+ their `pip*.exe`/`wheel*.exe`/`easy_install*` stubs in `python\Scripts`). They land there
  because `get-pip` and the sdist build-backend install (both needed to make `pip install
  --target site-packages -r requirements.txt` work) run with no `--target`, i.e. into the
  interpreter's own site, not ours. Nothing at runtime imports pip/setuptools/wheel/
  `pkg_resources` (checked: no runtime `pkg_resources` import across the installed deps — only
  a docstring mention in `click`). Scoped to the interpreter's site-packages only, never the
  vendored `site-packages\` our deps live in, so a genuine (currently nonexistent) runtime need
  for setuptools in one of our deps would be left alone rather than silently deleted. pip alone
  is dozens of vendored sub-packages — this is the single biggest **file-count** cut of the four.
- **`tests`/`test`/`testing`/`include` dirs inside the vendored `site-packages\`** — some wheels
  ship their own test suite or C headers as package data; neither is ever imported by `app\`/
  `desktop\` (nothing in this codebase imports a dependency's own tests; nothing compiles a C
  extension at runtime). `*.dist-info\` (RECORD included) is kept everywhere — it carries the
  license metadata the AGPL/GPL third-party-notice obligation needs.
- **`__pycache__`/`*.pyc` are DELIBERATELY KEPT**, not stripped. `assemble.ps1` step 6b
  precompiles `site-packages\`/`app\`/`desktop\` (`--invalidation-mode unchecked-hash`)
  specifically to cut cold-start bytecode-compile cost for a large import graph (uvicorn +
  fastapi/pydantic + pymupdf); CLAUDE.md's Current State still lists cold-start lag diagnosis as
  an OWED verification, i.e. nothing has since shown the precompile is unneeded. Stripping the
  cache here would silently reverse a fix for an already-diagnosed cost in exchange for a
  payload saving — not done without a real cold-start measurement first.
- **`build\payload_census.ps1`** prints file-count + MB per top-level dir after every run: once
  from `assemble.ps1` (partial — before the Rust core lands) and once from the workflow after
  the Rust core + `vendor\core\` staging step (full — the honest "what actually ships" number,
  right before `wix build`). Every packaging CI run now shows the real size in the log instead
  of it only surfacing as a user's install-size complaint.

**Per-product split (NOT done this pass — numbers only):** Lawbat and the Redactor MSI share one
staged tree, so today both ship the full `requirements.txt` set. `python-docx`, `openpyxl`,
`python-pptx`, and `extract-msg` are Lawbat-only (data-room extraction across file formats) —
the standalone Redactor (`app.web.create_redactor_app`) only ever touches PDFs (`redact-cli` +
the scanned-PDF OCR burn path via `fitz`/PIL) and never imports any of those four. Splitting the
staged tree per product would let the Redactor MSI drop them — a rough few-MB-class saving
(each of those four packages is single-digit MB), small next to `pymupdf` (`fitz`), which is
tens of MB and is needed by BOTH products (redaction AND extraction), so it is not a
split-savings candidate. This is a bigger workflow change (two staged trees or a
build-time include/exclude list) — out of scope for this pass, recorded here for later.

### What CI PROVES (machine-verified)
- The embeddable-Python + `._pth` + pip `--target` layout imports our full dependency set
  under the **shipped** interpreter.
- **FTS5 works** (`CREATE VIRTUAL TABLE … USING fts5` + a `MATCH` query).
- The FastAPI/uvicorn server **boots on a localhost socket and `/api/state` → 200**, headless.
- OCR round-trip (Tesseract reads a synthesized test image) on the staged bundle.
- `wix build` emits a single self-contained `.msi` with base + optional-OCR features + license
  files. The published release notes record the artifact's SHA256 (see `TODO.md` §0 for the
  most recent verified-pin build's hash).

### What CI does NOT prove — needs a human on a real Windows box
- **GUI renders under WebView2** — the smoke check imports `webview` but never opens a window.
- **Install / uninstall / upgrade on a clean VM** — per-user shortcuts target `pythonw.exe`
  (no console flash); uninstall leaves nothing; a higher-version MSI upgrades cleanly
  (MajorUpgrade); install root = `%LocalAppData%\Programs\DataRoomReview`. `__version__` is
  now `0.1.1` (bumped from the `0.1.0` first-pin releases) so the NEXT packaging build
  actually exercises the upgrade path on a test machine — same-version MSIs never trigger
  MajorUpgrade. Upgrade-test unblocked; still owed on a real box.
- **`\\?\` long paths + locked files on the INSTALLED app** (CI exercises this in-source via
  `test_e2e` only).
- **WebView2 absent** — confirm the bundled bootstrapper installs it on a box without the
  runtime (manual fallback today; a silent custom action is a later add).
- **The app icon** — `build/wix/assets/app.ico` is committed but is a minimal 16x16-only
  placeholder; swap in a real multi-res icon before a polished/public ship (`to-read/wix-assets.README.md`).

## Stranger-machine install guide (ships with every release)
`docs/INSTALL.md` is a one-page, non-technical install guide for BOTH products — the
SmartScreen "More info -> Run anyway" click-through, a `Get-FileHash` PowerShell one-liner to
verify the download against the SHA256 published in the release notes, where each product
installs/stores data, that Lawbat and Redactor coexist, and how to fully uninstall (incl.
manually clearing `%APPDATA%` since the MSI never touches it). `package-windows.yml`'s
"Publish MSI as a GitHub pre-release" step attaches it as a release asset alongside the two
`.msi` files and the notes point to it as the first line — a stranger's first install attempt
no longer needs anything beyond the release page.

## Open decisions (deferred, documented)
- **Code signing** — unsigned MSI trips SmartScreen/UAC; MSI-vs-exe only buys IT trust.
  **Deferred for the closed pilot; EV Authenticode before public release.** Sign the MSI (+ any
  launcher .exe). Do NOT add UPX/packing (anti-AV-friendly).
- **Per-user vs per-machine** — default per-user/no-admin for the no-IT pilot. The GPO/Intune
  per-machine variant is in `to-read/wix.README.md` (distinct UpgradeCode — never mix scopes
  under one UpgradeCode). Decide per pilot site.
- **WebView2 silent install custom action** — deferred until tested on a clean VM.
- **pysqlite3 fallback** — usually skipped (modern embeddable CPython has FTS5);
  `assemble.ps1` probes and bundles it only if missing.

## Packaging blockers in the app code
None. `app/vendor.py` resolves env → `vendor/` → PATH; `app/paths.py` keeps matter DBs in
`%APPDATA%` (never in the install dir or source tree); `desktop/main.py` is a clean
`pythonw.exe` entry point; `app/db.py` has the FTS5/pysqlite3 fallback.

## Tier-2 tool entry points (already wired in code)
- **OCR (Tesseract):** `app/ocr.py` — `ocr_image`/`ocr_pdf` (CPU only, no GPU/DL). Opt-in via
  `LAWDATAMAN_PDF_BACKEND=pymupdf_ocr` + `LAWDATAMAN_OCR_IMAGES=1`.
- **PDF repair (qpdf):** `app/pdftools.py::repair_pdf` — clean linearized copy, never mutates
  the source.
- **Rasterizer (pdfium):** `pdftools.pdfium_available()` + the OCR render path prefer
  `pypdfium2`, falling back to PyMuPDF.
