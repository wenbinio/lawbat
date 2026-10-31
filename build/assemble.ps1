<#
.SYNOPSIS
  Assemble the lawdataman payload tree for the Windows MSI (embedded CPython +
  our .py + vendored binaries). Run on a Windows box / CI runner — NOT on Linux.

.DESCRIPTION
  Produces a clean, documented staging tree under build\stage\DataRoomReview that
  the WiX source (build\wix\Product.wxs) harvests, and that build\smoke_check.py
  validates BEFORE the MSI is built.

  Steps:
    1. Download + SHA256-verify every artifact pinned in build\pins.psd1.
    2. Lay out the payload tree.
    3. Unzip the embeddable CPython into stage\...\python.
    4. Edit pythonXYZ._pth: uncomment `import site`, add our app dir + the
       vendored site-packages dir to sys.path. (The embeddable distro has `site`
       DISABLED and no pip — this is the step everything else depends on.)
    5. Bootstrap pip via get-pip.py, then `pip install -r requirements.txt
       --target` a vendored site-packages.
    6. Copy app\ + desktop\ source.
    7. Probe FTS5 in the embedded interpreter; pip-install pysqlite3-binary into
       site-packages ONLY if FTS5 is missing (ties to app/db.py's fallback).
    8. Payload diet: remove pip/setuptools/wheel (build-time-only tooling — see
       step 5) from the INTERPRETER's own site-packages, and dev/test dirs from
       OUR vendored site-packages. Precompiled .pyc are DELIBERATELY KEPT (a
       real, already-diagnosed cold-start cost — see the step's own comment).
    9. Lay vendored binaries into BASE (qpdf, WebView2 bootstrapper) vs the
       OPTIONAL-OCR (Tesseract + tessdata) sub-trees.
    10. Drop the license files that MUST ship (AGPL/GPL obligation).
    11. Print a payload census (file count + MB per top-level dir) via
        build\payload_census.ps1, so every CI run shows the assembled size
        honestly.

  Everything network happens HERE, at build time. The shipped app never fetches.

.PARAMETER IncludeOcr
  Also stage Tesseract + tessdata (the optional OCR MSI feature). Default: on.
  Pass -IncludeOcr:$false to stage only the base feature.

.PARAMETER SkipDownloads
  Reuse already-downloaded+verified artifacts in build\_dl (faster local reruns).
#>
[CmdletBinding()]
param(
    [bool]$IncludeOcr = $true,
    [switch]$SkipDownloads
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- paths ------------------------------------------------------------------
$BuildDir = $PSScriptRoot
$RepoRoot = Split-Path -Parent $BuildDir
$DlDir    = Join-Path $BuildDir '_dl'
$StageDir = Join-Path $BuildDir 'stage'
$AppStage = Join-Path $StageDir 'DataRoomReview'      # == the MSI payload root
$PyDir    = Join-Path $AppStage 'python'
$SiteDir  = Join-Path $AppStage 'site-packages'       # our vendored deps
$VendorDir= Join-Path $AppStage 'vendor'              # external binaries (gitignored in repo)

$Pins = Import-PowerShellDataFile -Path (Join-Path $BuildDir 'pins.psd1')

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

# --- 1. download + verify ---------------------------------------------------
function Get-Verified {
    # $Evergreen: a moving "latest" fetch (get-pip, the WebView2 bootstrapper) whose
    # upstream changes by design. We download + RECORD its hash but do NOT gate on it
    # (a fixed pin would false-alarm on every refresh). All other artifacts are
    # hard-pinned: a placeholder OR a mismatch ABORTS the build (supply-chain check),
    # with no global override needed for a normal build.
    param([string]$Url, [string]$Sha256, [string]$OutFile, [bool]$Evergreen = $false)
    $dest = Join-Path $DlDir $OutFile
    if ($SkipDownloads -and (Test-Path $dest)) {
        Write-Host "    (cached) $OutFile"
    } else {
        Write-Host "    downloading $OutFile"
        # System.Net for a clean progress-free download; -UseBasicParsing avoids IE.
        Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $dest).Hash.ToLower()
    $want = $Sha256.ToLower()
    if ($Evergreen) {
        # Not gated — but always surface the observed hash so drift is visible in the
        # log and CAN be promoted to a hard pin later (Evergreen=$false + this hash).
        if ($want -ne ('0' * 64) -and $actual -ne $want) {
            Write-Warning "    evergreen $OutFile drift: was $want, now $actual (informational, not gated)"
        } else {
            Write-Host "    evergreen $OutFile (unpinned by design) sha256=$actual" -ForegroundColor Yellow
        }
    } elseif ($want -eq ('0' * 64)) {
        Write-Warning "    PLACEHOLDER hash for $OutFile — pin its SHA256 in build\pins.psd1. Got: $actual"
        if ($env:LAWDATAMAN_ALLOW_UNVERIFIED -ne '1') {
            throw "Refusing to use $OutFile with a placeholder hash. Pin its SHA256 in build\pins.psd1 (got: $actual), or set LAWDATAMAN_ALLOW_UNVERIFIED=1 to bootstrap a first run and capture it."
        }
    } elseif ($actual -ne $want) {
        throw "SHA256 MISMATCH for $OutFile`n  expected $want`n  got      $actual`nAborting (supply-chain check)."
    } else {
        Write-Host "    verified  $OutFile" -ForegroundColor Green
    }
    return $dest
}

# --- clean staging ----------------------------------------------------------
Write-Step "Clean staging tree"
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Force -Path $DlDir, $AppStage, $PyDir, $SiteDir, $VendorDir | Out-Null

Write-Step "Download + verify artifacts (build-time only; the app never fetches)"
$pyZip   = Get-Verified -Url $Pins.Python.Url   -Sha256 $Pins.Python.Sha256   -OutFile "python-$($Pins.Python.Version)-embed-amd64.zip"
$getPip  = Get-Verified -Url $Pins.GetPip.Url   -Sha256 $Pins.GetPip.Sha256   -OutFile 'get-pip.py' -Evergreen $true
$wv2     = Get-Verified -Url $Pins.WebView2.Url -Sha256 $Pins.WebView2.Sha256 -OutFile $Pins.WebView2.FileName -Evergreen $true
$qpdfZip = Get-Verified -Url $Pins.Qpdf.Url     -Sha256 $Pins.Qpdf.Sha256     -OutFile "qpdf-$($Pins.Qpdf.Version)-mingw64.zip"

# --- 2/3. embeddable python -------------------------------------------------
Write-Step "Unzip embeddable CPython -> $PyDir"
Expand-Archive -Path $pyZip -DestinationPath $PyDir -Force
$pyExe  = Join-Path $PyDir $Pins.Python.Exe
$pywExe = Join-Path $PyDir $Pins.Python.ExeW
if (-not (Test-Path $pyExe)) { throw "python.exe not found after unzip: $pyExe" }

# --- 4. edit ._pth ----------------------------------------------------------
# The embeddable distro ships pythonXYZ._pth with `import site` COMMENTED OUT and
# `site` effectively disabled, so pip / third-party packages aren't importable.
# We must: (a) uncomment `import site` so site-packages processing runs, and
# (b) add the install dir (so `import app` / `import desktop` works) and our
# vendored site-packages dir. Paths in ._pth are relative to the python dir.
Write-Step "Patch $($Pins.Python.PthName) (enable site + add app/site-packages to sys.path)"
$pthFile = Join-Path $PyDir $Pins.Python.PthName
if (-not (Test-Path $pthFile)) { throw "._pth not found: $pthFile (embeddable layout changed?)" }
$pth = Get-Content $pthFile
# Uncomment any `#import site`.
$pth = $pth | ForEach-Object { if ($_ -match '^\s*#\s*import\s+site\s*$') { 'import site' } else { $_ } }
if (-not ($pth -contains 'import site')) { $pth += 'import site' }
# Add our dirs (relative to python\). The install root is one level up; our
# vendored site-packages and the source root sit beside python\.
$extra = @('..', '..\site-packages')
foreach ($e in $extra) { if (-not ($pth -contains $e)) { $pth += $e } }
Set-Content -Path $pthFile -Value $pth -Encoding ascii
Write-Host "    ._pth now:`n$([string]::Join("`n", ($pth | ForEach-Object { '      ' + $_ })))"

# --- 5. bootstrap pip + install requirements into site-packages -------------
# get-pip installs pip into the embeddable interpreter despite the cut-down distro.
# We then `pip install --target site-packages` so deps live in OUR vendored dir
# (added to ._pth above), keeping the python\ dir == the pristine official distro.
Write-Step "Bootstrap pip"
& $pyExe $getPip --no-warn-script-location
if ($LASTEXITCODE -ne 0) { throw "get-pip failed ($LASTEXITCODE)" }

# Install a build backend INTO the embedded interpreter. A few transitive deps are
# sdist-only (e.g. red-black-tree-mod, pulled in by extract-msg) and ship no wheel,
# so pip must BUILD them. They're pure Python — no C toolchain involved — but the
# embeddable distro ships no build backend, so the build dies with
# "Cannot import 'setuptools.build_meta'". Putting setuptools+wheel in the interpreter
# (paired with --no-build-isolation below) gives that build a backend to use.
Write-Step "Install build backend (setuptools + wheel) for sdist-only deps"
& $pyExe -m pip install --no-warn-script-location setuptools wheel
if ($LASTEXITCODE -ne 0) { throw "build-backend install failed ($LASTEXITCODE)" }

Write-Step "pip install -r requirements.txt --target site-packages"
$req = Join-Path $RepoRoot 'requirements.txt'
# --target installs into our vendored dir. --no-compile keeps it lean+transparent
# (AGPL: ship readable source). pip itself is in the python\ dir, invoked via -m.
# --no-build-isolation: build isolation spins up a CLEAN env that can't reach the
# setuptools we just installed, which is exactly what failed; with the backend now
# present in this interpreter, an in-env build of the sdist-only deps is deterministic.
& $pyExe -m pip install --no-cache-dir --no-compile --upgrade --no-build-isolation --target $SiteDir -r $req
if ($LASTEXITCODE -ne 0) { throw "pip install failed ($LASTEXITCODE)" }

# --- 6. copy our source -----------------------------------------------------
Write-Step "Copy app\ + desktop\ source"
Copy-Item -Recurse -Force (Join-Path $RepoRoot 'app')     (Join-Path $AppStage 'app')
Copy-Item -Recurse -Force (Join-Path $RepoRoot 'desktop') (Join-Path $AppStage 'desktop')
# Strip __pycache__ so we ship clean, readable source (no stale .pyc).
Get-ChildItem -Path $AppStage -Recurse -Directory -Filter '__pycache__' |
    Remove-Item -Recurse -Force

# --- 6b. precompile bytecode (COLD-START speed) -----------------------------
# Without this, the embeddable interpreter compiles the WHOLE import graph
# (uvicorn + fastapi/pydantic + pymupdf + ...) to bytecode AT LAUNCH — a big
# cold-start cost. Precompile here so .pyc ship in the MSI. We still ship the .py
# source (AGPL/readability) — .pyc are just caches beside it.
# --invalidation-mode unchecked-hash: MSI install rewrites file mtimes, which would
# invalidate timestamp-based .pyc and force a recompile on first launch; hash-mode
# .pyc are used unconditionally, so the cache survives install.
# Non-fatal: some dependency test files ship intentionally-bad / py2 syntax; a
# per-file compile failure must NOT fail the build (those modules just stay .py).
Write-Step "Precompile bytecode (.pyc, hash-invalidated) for fast cold start"
& $pyExe -m compileall -q -f --invalidation-mode unchecked-hash `
    $SiteDir (Join-Path $AppStage 'app') (Join-Path $AppStage 'desktop')
if ($LASTEXITCODE -ne 0) { Write-Warning "compileall: some files failed to precompile (non-fatal; they stay .py)" }

# --- 7. FTS5 probe -> conditional pysqlite3 ---------------------------------
# app/db.py falls back to pysqlite3 when the stdlib sqlite3 lacks FTS5. Decide it
# HERE: probe the embedded interpreter and only add the wheel if needed, so the
# base install stays lean when FTS5 is present (the usual case for 3.10+ embed).
Write-Step "Probe FTS5 in the embedded interpreter"
$probe = @'
import sqlite3, sys
try:
    c = sqlite3.connect(":memory:")
    c.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
    print("FTS5_OK")
except Exception as e:
    print("FTS5_MISSING:", e)
    sys.exit(3)
'@
$probeFile = Join-Path $DlDir 'fts5_probe.py'
Set-Content -Path $probeFile -Value $probe -Encoding ascii
& $pyExe $probeFile
$fts5 = ($LASTEXITCODE -eq 0)
if ($fts5) {
    Write-Host "    embedded sqlite3 has FTS5 — pysqlite3 NOT needed" -ForegroundColor Green
} else {
    Write-Warning "    embedded sqlite3 lacks FTS5 — installing $($Pins.PySqlite3.Package)==$($Pins.PySqlite3.Version)"
    & $pyExe -m pip install --no-cache-dir --no-compile --target $SiteDir "$($Pins.PySqlite3.Package)==$($Pins.PySqlite3.Version)"
    if ($LASTEXITCODE -ne 0) { throw "pysqlite3 install failed ($LASTEXITCODE)" }
}

# --- 8. payload diet: strip build-time-only tooling + dev/test artifacts ----
# Runs AFTER every pip invocation above (including the conditional pysqlite3
# install just above) so nothing here still needs pip. build\smoke_check.py's
# import + FTS5 + server-boot checks run AFTER this step (locally and in CI)
# against the SAME diet-ed bundle, so a wrong call here fails the build loud
# rather than shipping a silently-broken MSI.
Write-Step "Payload diet: strip pip/setuptools/wheel + dev/test artifacts"

function Remove-DietItem($item) {
    # Helper only: sums bytes removed (dir or file) so the diet can report a
    # total, then deletes. $script: scope writes back to the caller's counters.
    $bytes = if ($item.PSIsContainer) {
        $sum = (Get-ChildItem $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if ($sum) { $sum } else { 0 }
    } else { $item.Length }
    $script:dietBytes += $bytes
    $script:dietCount++
    Remove-Item -Recurse -Force $item.FullName
}

# 8a. pip / setuptools / wheel live in the INTERPRETER's OWN site-packages
# (python\Lib\site-packages), NOT our vendored $SiteDir: step 5's get-pip
# bootstrap and the build-backend install both ran with no --target, so they
# installed pip/setuptools/wheel into sys.prefix, i.e. this dir. They exist
# solely so `pip install --target site-packages -r requirements.txt` (and the
# conditional pysqlite3 install above) can run at BUILD time; nothing at
# runtime imports pip, setuptools, wheel, or pkg_resources (checked: none of
# requirements.txt's deps import pkg_resources — the only hit in the installed
# tree was a DOCSTRING mention in click, not a real import). This is scoped to
# $interpSite ONLY, never $SiteDir, so a genuine transitive runtime need for
# setuptools/pkg_resources in one of OUR deps (none found today) would be left
# alone rather than silently deleted.
$interpSite    = Join-Path $PyDir 'Lib\site-packages'
$interpScripts = Join-Path $PyDir 'Scripts'
$dietBytes = 0L
$dietCount = 0
if (Test-Path $interpSite) {
    $buildTimePatterns = @(
        'pip', 'pip-*',                                # the pip package + its dist-info
        'setuptools', 'setuptools-*',                  # the build backend
        'wheel', 'wheel-*',                             # ditto
        'pkg_resources',                                # ships inside setuptools
        '_distutils_hack', 'distutils-precedence.pth'   # setuptools' import shim
    )
    foreach ($pat in $buildTimePatterns) {
        Get-ChildItem -Path $interpSite -Filter $pat -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-DietItem $_ }
    }
}
if (Test-Path $interpScripts) {
    # Console-script stubs for the same three packages (pip.exe / pip3.exe /
    # pip3.12.exe, wheel.exe, legacy easy_install*). Nothing else has ever
    # written to python\Scripts — get-pip and the build-backend install are the
    # only steps that put anything there.
    Get-ChildItem -Path $interpScripts -Filter 'pip*.exe' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-DietItem $_ }
    Get-ChildItem -Path $interpScripts -Filter 'wheel*.exe' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-DietItem $_ }
    Get-ChildItem -Path $interpScripts -Filter 'easy_install*' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-DietItem $_ }
}
Write-Host ("    removed {0} pip/setuptools/wheel item(s), {1:N1} MB" -f $dietCount, ($dietBytes / 1MB)) -ForegroundColor Yellow

# 8b. Dev/test artifacts INSIDE our vendored $SiteDir: some wheels bundle their
# own test suite as an importable "tests"/"test"/"testing" top-level package,
# or a C-header "include\" dir for building extensions against them. Neither is
# ever imported by app\/desktop\ (nothing in this codebase imports a
# dependency's own test suite, and we never compile a C extension at runtime).
# dist-info\ (RECORD included) is DELIBERATELY KEPT for every remaining
# package — it carries the license metadata our AGPL/GPL third-party-notice
# obligation needs (to-read/THIRD_PARTY_LICENSES.md, to-read/packaging.md).
$siteDietBytes = 0L
$siteDietCount = 0
Get-ChildItem -Path $SiteDir -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @('tests', 'test', 'testing', 'include') } |
    ForEach-Object {
        if (-not (Test-Path $_.FullName)) { return }  # a parent dir may already be gone
        $bytes = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        $siteDietBytes += $(if ($bytes) { $bytes } else { 0 })
        $siteDietCount++
        Remove-Item -Recurse -Force $_.FullName
    }
Write-Host ("    removed {0} test/include dir(s) from site-packages, {1:N1} MB" -f $siteDietCount, ($siteDietBytes / 1MB)) -ForegroundColor Yellow

# 8c. __pycache__/*.pyc are DELIBERATELY KEPT — NOT stripped here. Step 6b
# above precompiled $SiteDir + app\ + desktop\ (--invalidation-mode
# unchecked-hash) specifically to cut cold-start bytecode-compile cost
# (uvicorn + fastapi/pydantic + pymupdf is a large import graph to compile at
# launch). CLAUDE.md's Current-State snapshot still lists "cold-start lag
# diagnosis" as an OWED verification — i.e. nothing has since shown the
# precompile is unnecessary. Stripping the .pyc here would silently undo step
# 6b's fix in exchange for a payload saving that trades away a real,
# already-diagnosed startup cost. Revisit only once a real cold-start
# measurement says the precompile doesn't matter — not on a guess.

# --- 9. vendored binaries: BASE vs OPTIONAL-OCR -----------------------------
Write-Step "Stage vendor\ binaries (base: qpdf + WebView2; optional: Tesseract)"

# qpdf (BASE) -> vendor\qpdf\  (app/vendor.py looks for vendor\qpdf\qpdf.exe)
$qpdfTmp = Join-Path $DlDir 'qpdf_extract'
if (Test-Path $qpdfTmp) { Remove-Item -Recurse -Force $qpdfTmp }
Expand-Archive -Path $qpdfZip -DestinationPath $qpdfTmp -Force
$qpdfDst = Join-Path $VendorDir 'qpdf'
New-Item -ItemType Directory -Force -Path $qpdfDst | Out-Null
# Copy qpdf.exe + its runtime DLLs (mingw64 build) flat into vendor\qpdf\.
Copy-Item -Path (Join-Path $qpdfTmp $Pins.Qpdf.BinGlob) -Destination $qpdfDst -Force
if (-not (Test-Path (Join-Path $qpdfDst 'qpdf.exe'))) { throw "qpdf.exe missing after stage" }

# WebView2 bootstrapper (BASE) -> vendor\webview2\  (MSI runs it as prerequisite)
$wv2Dst = Join-Path $VendorDir 'webview2'
New-Item -ItemType Directory -Force -Path $wv2Dst | Out-Null
Copy-Item -Path $wv2 -Destination (Join-Path $wv2Dst $Pins.WebView2.FileName) -Force

# Tesseract (OPTIONAL OCR) -> vendor\tesseract\  + tessdata\
# NON-FATAL: OCR is an OPTIONAL feature. The pinned artifact is an NSIS installer;
# EXECUTING it (as a prior version of this script did, via `Start-Process ... /S
# /D=...`) is fragile — child-process detach under CI, silent-install flag drift,
# and admin/UAC variance are all plausible causes, and CI run 28568312107 hit
# exactly this: the silent install returned cleanly but left no tesseract.exe on
# disk. Instead we EXTRACT the installer as an archive: NSIS installers are
# 7z-openable, and GitHub-hosted windows-latest runners ship 7-Zip preinstalled.
# Same pinned+hash-verified artifact as before (see Get-Verified below) — only the
# acquisition mechanism changed, no new supply-chain surface. If acquiring/
# extracting/harvesting Tesseract fails (download, 7z missing, exe-not-found, ...),
# WARN and SKIP it so the BASE bundle still assembles and the smoke-check / base
# MSI can proceed. A fragile optional dependency must never abort the whole build.
$ocrStaged = $false
if ($IncludeOcr) {
    # Declared outside the try so the `finally` cleanup can safely reference it even
    # if an earlier step (download, 7z lookup) throws before extraction starts.
    $tessInst = Join-Path $DlDir 'tess_install'
    try {
        $tessExe = Get-Verified -Url $Pins.Tesseract.Url -Sha256 $Pins.Tesseract.Sha256 -OutFile "tesseract-setup-$($Pins.Tesseract.Version).exe"
        $tessDst = Join-Path $VendorDir 'tesseract'
        New-Item -ItemType Directory -Force -Path $tessDst | Out-Null

        # Locate 7-Zip: PATH first, then the default install location windows-latest
        # ships it at. Missing 7z is an acquisition failure -> the warn+skip path below.
        $sevenZip = $null
        $sevenZipCmd = Get-Command '7z' -ErrorAction SilentlyContinue
        if ($sevenZipCmd) { $sevenZip = $sevenZipCmd.Source }
        elseif (Test-Path 'C:\Program Files\7-Zip\7z.exe') { $sevenZip = 'C:\Program Files\7-Zip\7z.exe' }
        if (-not $sevenZip) { throw "7-Zip (7z.exe) not found on PATH or at 'C:\Program Files\7-Zip\7z.exe'" }

        if (Test-Path $tessInst) { Remove-Item -Recurse -Force $tessInst }
        New-Item -ItemType Directory -Force -Path $tessInst | Out-Null
        Write-Host "    extracting the Tesseract NSIS installer with 7-Zip (not executing it)"
        & $sevenZip x $tessExe "-o$tessInst" -y | Out-Null
        # NSIS archives commonly extract with 7z exit code 2 ("warnings" — e.g. NSIS
        # plugin calls 7z can't interpret) even when the payload files land fine, so
        # judge success by what's actually on disk next, not by $LASTEXITCODE alone.
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
            throw "7z extraction failed with exit code $LASTEXITCODE"
        }

        # Harvest LAYOUT-AGNOSTICALLY: the NSIS payload lands under a variable
        # subfolder (e.g. an install-dir-named or '$_OUTDIR'-named directory), not a
        # fixed path, so search recursively for tesseract.exe rather than assume one.
        $tessExeFound = Get-ChildItem -Path $tessInst -Filter 'tesseract.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $tessExeFound) {
            throw "tesseract.exe not found anywhere under the extracted archive (7z layout drift?)"
        }
        $tessExeDir = $tessExeFound.Directory.FullName
        # Copy the exe + every sibling DLL in its directory (tesseract.exe dynamically
        # loads libtesseract/leptonica/zlib/etc.; smoke_check's `tesseract --version`
        # check fails loudly if any is missing).
        Copy-Item -Path (Join-Path $tessExeDir '*.exe') -Destination $tessDst -Force
        Copy-Item -Path (Join-Path $tessExeDir '*.dll') -Destination $tessDst -Force -ErrorAction SilentlyContinue

        # Find tessdata the same way, via eng.traineddata's parent directory (also
        # layout-agnostic). Keep only the configured languages (lean installer);
        # built-in configfiles like `tsv` are compiled into tesseract.exe itself, so no
        # tessdata/configs subdirectory is needed for app/ocr.py's usage.
        $engFound = Get-ChildItem -Path $tessInst -Filter 'eng.traineddata' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $engFound) {
            throw "tessdata (eng.traineddata) not found anywhere under the extracted archive"
        }
        $tessdataSrc = $engFound.Directory.FullName
        $tessdataDst = Join-Path $tessDst 'tessdata'
        New-Item -ItemType Directory -Force -Path $tessdataDst | Out-Null
        foreach ($lang in $Pins.Tesseract.Languages) {
            $f = Join-Path $tessdataSrc "$lang.traineddata"
            if (Test-Path $f) { Copy-Item -Path $f -Destination $tessdataDst -Force }
            else { Write-Warning "    tessdata missing language '$lang' ($f)" }
        }

        # DELIBERATE language models: overwrite the installer's eng with the pinned
        # tessdata_best eng (accuracy-over-speed — OCR feeds redaction detection, a
        # misread identifier is a silent MISS; see pins.psd1 TessdataBest) and stage
        # the opt-in packs (chi_sim+chi_sim_vert, msa, tam). Per file:
        #   * SHA256 MISMATCH  -> ABORT the build (supply-chain check — never loosen);
        #   * fetch FAILURE    -> warn + keep the installer's copy (offline dev box) —
        #     the OCR feature still ships, just without that deliberate model.
        # chi_sim is only usable WITH chi_sim_vert (load-time dependency, verified on
        # tesseract 5.4/5.3), so the pair is staged all-or-nothing below.
        $bestStaged = @()
        foreach ($td in $Pins.TessdataBest.Files) {
            try {
                $f = Get-Verified -Url "$($Pins.TessdataBest.BaseUrl)/$($td.Name)" `
                                  -Sha256 $td.Sha256 -OutFile $td.Name
                Copy-Item -Path $f -Destination (Join-Path $tessdataDst $td.Name) -Force
                $bestStaged += $td.Name
            } catch {
                if ($_.Exception.Message -match 'SHA256 MISMATCH') { throw }  # never fall back on a bad hash
                Write-Warning "    tessdata_best '$($td.Name)' unavailable ($($_.Exception.Message)) — keeping the installer copy / omitting the pack"
            }
        }
        # Pair invariant: chi_sim without chi_sim_vert refuses to load — remove the orphan.
        if (($bestStaged -contains 'chi_sim.traineddata') -and -not ($bestStaged -contains 'chi_sim_vert.traineddata')) {
            Remove-Item -Path (Join-Path $tessdataDst 'chi_sim.traineddata') -Force -ErrorAction SilentlyContinue
            Write-Warning "    chi_sim omitted: its required companion chi_sim_vert did not stage"
        }
        Write-Host "    tessdata_best staged: $(if ($bestStaged) { $bestStaged -join ', ' } else { '(none — installer eng retained)' })"

        if (-not (Test-Path (Join-Path $tessDst 'tesseract.exe'))) {
            throw "tesseract.exe missing from vendor\tesseract after harvest"
        }
        $ocrStaged = $true
        Write-Host "    Tesseract staged via 7z extraction (langs: $($Pins.Tesseract.Languages -join ', '); best-models: $($bestStaged.Count))" -ForegroundColor Green
    } catch {
        # Optional feature: do NOT abort the base build. Remove any partial payload so
        # the OCR feature is cleanly ABSENT, warn loudly, and continue.
        $tessDst = Join-Path $VendorDir 'tesseract'
        if (Test-Path $tessDst) { Remove-Item -Recurse -Force $tessDst }
        Write-Warning "    OCR feature OMITTED — Tesseract acquisition failed: $($_.Exception.Message)"
        Write-Warning "    base bundle continues; see pins.psd1's Tesseract comment for the mitigation note"
    } finally {
        if (Test-Path $tessInst) { Remove-Item -Recurse -Force $tessInst -ErrorAction SilentlyContinue }
    }
} else {
    Write-Host "    OCR feature skipped (-IncludeOcr:`$false)"
}
Write-Host "    OCR in this build: $ocrStaged"

# --- 10. license files that MUST ship (AGPL/GPL obligation) -----------------
Write-Step "Stage license files (AGPL/GPL: source/notice obligations)"
Copy-Item -Path (Join-Path $RepoRoot 'LICENSE')                 -Destination (Join-Path $AppStage 'LICENSE') -Force
# Docs were consolidated into to-read/ (2026-06-23); sources moved, staged names unchanged.
Copy-Item -Path (Join-Path $RepoRoot 'to-read\THIRD_PARTY_LICENSES.md') -Destination (Join-Path $AppStage 'THIRD_PARTY_LICENSES.md') -Force
if (Test-Path (Join-Path $RepoRoot 'to-read\licensing.md')) {
    Copy-Item -Path (Join-Path $RepoRoot 'to-read\licensing.md') -Destination (Join-Path $AppStage 'licensing.md') -Force
}

# --- 11. payload census ------------------------------------------------------
# Honest size accounting on every run: file count + MB per top-level dir, so a
# regression (a dependency bump that quietly balloons site-packages, an OCR
# payload that grows, ...) shows up in the CI log instead of only in a user's
# install size months later. This call sees everything assemble.ps1 itself
# stages (python\, app\, desktop\, site-packages\, vendor\ minus tesseract if
# OCR was skipped) — NOT core\ / vendor\core\, which package-windows.yml stages
# in a LATER step (the Rust core build) after assemble.ps1 returns; that
# workflow makes its own call to this same script for the FULL picture.
& (Join-Path $BuildDir 'payload_census.ps1') -StageDir $AppStage `
    -Label 'assemble.ps1 payload census (python/app/desktop/site-packages/vendor — core/ stages later in CI)'

# --- done -------------------------------------------------------------------
Write-Step "Payload assembled at: $AppStage"
Get-ChildItem $AppStage | Select-Object Mode, Length, Name | Format-Table | Out-String | Write-Host
Write-Host "Next: build\smoke_check.py against $pyExe, then wix build (build\wix\Product.wxs)." -ForegroundColor Green
