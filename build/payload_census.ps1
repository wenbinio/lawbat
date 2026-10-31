<#
.SYNOPSIS
  Print a per-top-level-dir file count + size census of a staged MSI payload
  tree. Read-only — never mutates the tree.

.DESCRIPTION
  Called twice in the packaging pipeline:
    (a) at the end of build\assemble.ps1 — a PARTIAL picture (python\, app\,
        desktop\, site-packages\, vendor\ minus tesseract if OCR was skipped);
        core\ / vendor\core\ don't exist yet at that point.
    (b) again from .github\workflows\package-windows.yml AFTER the Rust core +
        vendor\core staging step — the FULL picture, i.e. every top-level dir
        that actually ends up in the MSI (WiX's <Files Include="...\**"> globs
        harvest exactly what's on disk at build time, so this is an honest
        preview of what ships).

  The point: every packaging CI run prints the real number, so a payload
  regression (a dependency bump that quietly balloons site-packages, a bigger
  OCR/vendor drop, ...) shows up in the log instead of only in a user's
  install-size complaint months later.

.PARAMETER StageDir
  The staged payload root (build\stage\DataRoomReview).

.PARAMETER Label
  A short label identifying which call this is (partial vs full), printed in
  the header so the two census calls in one CI run are distinguishable.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StageDir,
    [string]$Label = 'payload census'
)

function Show-PayloadCensus {
    param([string]$Root, [string]$CensusLabel)
    if (-not (Test-Path $Root)) { Write-Warning "payload census: $Root does not exist"; return }
    Write-Host ""
    Write-Host "==> $CensusLabel" -ForegroundColor Cyan
    Write-Host "    root: $Root"
    $totalFiles = 0
    $totalBytes = 0L
    $dirs = Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($d in $dirs) {
        $files = Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue
        $count = $files.Count
        $bytes = ($files | Measure-Object -Property Length -Sum).Sum
        if (-not $bytes) { $bytes = 0 }
        $mb = [math]::Round($bytes / 1MB, 1)
        Write-Host ("    {0,-16} {1,6:N0} files  {2,9:N1} MB" -f $d.Name, $count, $mb)
        $totalFiles += $count
        $totalBytes += $bytes
    }
    # Loose files directly at the root (LICENSE, THIRD_PARTY_LICENSES.md, ...).
    $looseFiles = Get-ChildItem -Path $Root -File -ErrorAction SilentlyContinue
    if ($looseFiles) {
        $looseBytes = ($looseFiles | Measure-Object -Property Length -Sum).Sum
        if (-not $looseBytes) { $looseBytes = 0 }
        Write-Host ("    {0,-16} {1,6:N0} files  {2,9:N1} MB" -f '(loose files)', $looseFiles.Count, [math]::Round($looseBytes / 1MB, 1))
        $totalFiles += $looseFiles.Count
        $totalBytes += $looseBytes
    }
    Write-Host ("    {0,-16} {1,6:N0} files  {2,9:N1} MB" -f 'TOTAL', $totalFiles, [math]::Round($totalBytes / 1MB, 1)) -ForegroundColor Yellow
    Write-Host ""
}

Show-PayloadCensus -Root $StageDir -CensusLabel $Label
