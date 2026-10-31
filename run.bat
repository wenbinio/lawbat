@echo off
setlocal enableextensions
rem ============================================================================
rem  Lawbat - one-command launcher (Windows, double-click friendly).
rem
rem  Fixes the first-run setup friction: wrong working directory / missing
rem  PYTHONPATH ("No module named app"), the engine path, and "Tool offline".
rem  Then opens the Redaction page in your browser.
rem
rem  A .bat (not .ps1) so it just double-clicks and runs - no PowerShell
rem  execution-policy prompt, no "open in editor".
rem
rem  It: 1) cd's to its own folder (the repo root); 2) sets PYTHONPATH=.;
rem  3) finds the redact-cli engine (env -> vendor\core -> release -> debug)
rem  and exports LAWDATAMAN_REDACT_CLI; 4) runs the setup doctor; 5) starts the
rem  server, waits for the port, opens the browser. If the engine is not found AND
rem  Rust (cargo) is installed, it OFFERS to build it; otherwise it STILL starts
rem  (redaction shows the honest "Tool offline" state).
rem ============================================================================

rem --- detached helper mode: poll the port, then open the browser -------------
if /i "%~1"=="--open" goto :openbrowser

rem --- 1. cd to this script's own folder (the repo root) ----------------------
cd /d "%~dp0"

rem --- 2. PYTHONPATH=. so `python -m app.serve` finds the `app` package -------
set "PYTHONPATH=."

echo.
echo Lawbat launcher
echo   folder: %CD%

rem --- find a Python interpreter ----------------------------------------------
set "PY="
where python  >nul 2>nul && set "PY=python"
if not defined PY ( where py      >nul 2>nul && set "PY=py -3" )
if not defined PY ( where python3 >nul 2>nul && set "PY=python3" )
if not defined PY (
    echo.
    echo Python was not found.
    echo   Install Python 3.11 or 3.12 from https://www.python.org/downloads/
    echo   and tick "Add python.exe to PATH", then run this again.
    echo.
    pause
    exit /b 1
)

rem --- 3. locate the redaction engine (env -> vendor -> release -> debug) -----
set "ENGINE="
if defined LAWDATAMAN_REDACT_CLI if exist "%LAWDATAMAN_REDACT_CLI%" set "ENGINE=%LAWDATAMAN_REDACT_CLI%"
if not defined ENGINE if exist "%~dp0vendor\core\redact-cli.exe"         set "ENGINE=%~dp0vendor\core\redact-cli.exe"
if not defined ENGINE if exist "%~dp0core\target\release\redact-cli.exe" set "ENGINE=%~dp0core\target\release\redact-cli.exe"
if not defined ENGINE if exist "%~dp0core\target\debug\redact-cli.exe"   set "ENGINE=%~dp0core\target\debug\redact-cli.exe"
if defined ENGINE (
    set "LAWDATAMAN_REDACT_CLI=%ENGINE%"
    echo   engine: %ENGINE%
) else (
    call :try_build
)

rem --- 4. run the setup doctor (informational; never blocks the launch) -------
echo.
echo Running setup doctor...
%PY% -m app.doctor
if errorlevel 1 (
    echo.
    echo The doctor reported a problem ^(see the table above^).
    echo   If a dependency is missing, run:  pip install -r requirements.txt
    echo   Starting anyway so you can see the app...
)

rem --- 5. kick off the browser-opener, then run the server in the foreground --
rem The helper (this same file, re-invoked with --open) polls the port and opens
rem the browser ONLY once the server is listening. The server runs here in the
rem foreground so this window is tied to it: close the window / Ctrl+C to stop.
echo.
echo Starting Lawbat on http://127.0.0.1:8077/redaction ...
start "Lawbat (opening browser)" /min "%~f0" --open
%PY% -m app.serve

echo.
echo Lawbat has stopped. You can close this window.
endlocal
exit /b 0

rem ===========================================================================
:try_build
rem Engine not found. If Rust's cargo is present, OFFER to build it; else honest hint.
rem (The shipped product gets the engine from the MSI; this build path is a dev/tester
rem convenience for someone who has Rust. Never silent: a release build is slow.)
where cargo >nul 2>nul
if errorlevel 1 (
    echo   engine: NOT FOUND, and Rust ^(cargo^) is not installed.
    echo     Install Rust ^(https://rustup.rs^) and re-run to build redaction, or drop a
    echo     prebuilt redact-cli.exe into vendor\core\ . The app still works without it
    echo     ^(redaction shows the honest "Tool offline" state^).
    goto :eof
)
echo   engine: NOT FOUND - but Rust ^(cargo^) is available.
set "_ans=Y"
set /p "_ans=  Build the redaction engine now? First build takes a few minutes [Y/n]: "
if /i "%_ans:~0,1%"=="n" (
    echo   Skipping the build - redaction stays "Tool offline" until it is built.
    goto :eof
)
echo.
echo   Building redact-cli  ^(cargo build -p redact-cli --release^)
echo   The first build compiles dependencies and is SLOW - this is normal, not a hang.
echo.
pushd core
cargo build -p redact-cli --release
set "_rc=%errorlevel%"
popd
if not "%_rc%"=="0" (
    echo.
    echo   The engine build FAILED ^(see the cargo output above^). The app will still
    echo   start; redaction shows the "Tool offline" state. Fix the error and re-run.
    goto :eof
)
if exist "%~dp0core\target\release\redact-cli.exe" (
    set "ENGINE=%~dp0core\target\release\redact-cli.exe"
    set "LAWDATAMAN_REDACT_CLI=%~dp0core\target\release\redact-cli.exe"
    echo   engine: built and ready ^(core\target\release\redact-cli.exe^)
) else (
    echo   Build OK but redact-cli.exe not found at core\target\release\ - staying "Tool offline".
)
goto :eof

rem ===========================================================================
:openbrowser
rem Detached helper: poll until 127.0.0.1:8077 is LISTENING, then open the page.
rem Open ONLY when it actually binds, so a failed startup never pops a dead tab.
set "URL=http://127.0.0.1:8077/redaction"
set /a _tries=0
:pollloop
netstat -an | findstr /c:":8077" | findstr /c:"LISTENING" >nul 2>nul
if not errorlevel 1 (
    start "" "%URL%"
    exit /b 0
)
set /a _tries+=1
if %_tries% geq 60 exit /b 0
ping -n 2 127.0.0.1 >nul 2>nul
goto :pollloop
