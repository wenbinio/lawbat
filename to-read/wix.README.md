# WiX MSI authoring (`build/wix/`)

Authors the Lawbat MSI. **Build runs on Windows** (the WiX `wix.exe` .NET tool), after
`build/assemble.ps1` has produced the staged payload.

## Files
- `Product.wxs` — the MSI: product identity, per-user install, Base + optional OCR features,
  Start-menu + desktop shortcuts targeting the bundled `pythonw.exe`, upgrade logic, license files,
  native `<Files>` payload harvesting.
- `assets/app.ico` — the app icon. **Committed, but a minimal 16x16-only placeholder** — enough
  for `wix build` to succeed, not real branding. See `assets/README.md`.

## Prerequisites (Windows build host / CI)
WiX v4/v5 is a .NET global tool: `dotnet tool install --global wix --version 5.*`.

## Build (after assemble.ps1)
```powershell
# from build\wix
$stage = (Resolve-Path ..\stage\DataRoomReview).Path
New-Item -ItemType Directory -Force ..\out | Out-Null
wix build Product.wxs -arch x64 -d Version=0.1.1 -d StageDir=$stage -o ..\out\DataRoomReview.msi
```
`-d StageDir=...` points `<Files Include="$(StageDir)\...">` at the assembled tree, so the harvested
payload is exactly what `smoke_check.py` validated.

## Per-machine (GPO / Intune) variant
Default is **per-user / no-admin** (`Scope="perUser"`, root under `%LocalAppData%\Programs`). For a
per-machine MSI: (1) `Package/@Scope` → `perMachine`; (2) install root `LocalAppDataFolder` →
`ProgramFiles64Folder` (drop the `Programs` subdir); (3) use a **distinct UpgradeCode** OR ship as
separate products — never mix scopes under one UpgradeCode (upgrades break); (4) per-machine
requires elevation (expected for GPO/Intune). Keep both variants out of one MSI; build two with
different `-d` switches or `.wxs` overlays, and document which one a pilot site gets.

## UpgradeCode
`Product.wxs` pins a fixed `UpgradeCode` GUID. **Never change it** once published — it's the stable
identity that lets a new version replace an old one. `ProductCode` regenerates per build (correct).
