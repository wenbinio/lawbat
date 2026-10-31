<#
  pins.psd1 — single source of truth for every fetched build artifact.

  Every URL has a PINNED VERSION and a SHA256. The assemble script (assemble.ps1)
  refuses to use any download whose hash does not match — so the build is
  reproducible and a supply-chain swap can't slip in silently.

  RUNTIME NON-NEGOTIABLE: none of these are fetched by the *shipped* app. They are
  fetched at BUILD time on the Windows/CI box only, verified, then laid into the
  payload. The installed app never reaches the network.

  TWO KINDS of artifact:
    * IMMUTABLE, version-locked (Python embeddable, qpdf, Tesseract): HARD-PINNED by
      SHA256. A mismatch ABORTS the build (supply-chain check). Bump a version =>
      bump its Sha256 in the SAME edit. Never loosen the check.
    * EVERGREEN, moving "latest" (get-pip, the WebView2 bootstrapper): cannot be
      hard-pinned (upstream changes by design, so a fixed pin would false-alarm).
      Marked `Evergreen = $true`; the build RECORDS the observed hash but does not gate.

  To capture/refresh a hash:
      (Get-FileHash -Algorithm SHA256 .\file.zip).Hash.ToLower()
  (or read it from the assemble.ps1 build log, which prints every artifact's hash).
#>
@{
    # ---- Embeddable CPython -------------------------------------------------
    # The official "Windows embeddable package (64-bit)". This is the runtime we
    # ship. Pin to the same minor the app is tested against in CI (3.12).
    # NB: the embeddable distro has NO pip and `site` disabled by default — the
    # assemble script bootstraps pip via get-pip and edits python3xx._pth. That
    # is the fiddliest step; see assemble.ps1.
    Python = @{
        Version = '3.12.7'
        Url     = 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip'
        # IMMUTABLE — hard-pin this. Captured 2026-07-02 from the 2026-07-01
        # packaging-CI run's assemble log (run 28491904556; the runner's own fresh
        # download). python.org is egress-blocked from the dev sandbox, so no local
        # download was possible to independently capture this hash. The NEXT green
        # packaging run re-verifies this pin MECHANICALLY: assemble.ps1 re-downloads
        # on a fresh runner and hard-aborts on any mismatch (fail-closed), so a green
        # run is an independent second-network-path confirmation of this value.
        # Bump the Version => recapture this hash in the same edit.
        Sha256  = '0d57bb6cb078b74d23dbfe91f77d6780d45bed328911609f1f7ee2ba1606bf44'
        # The interpreter executables inside the zip (used to build the ._pth name).
        PthName = 'python312._pth'
        ExeW    = 'pythonw.exe'   # windowed (no console) — the shortcut targets this
        Exe     = 'python.exe'    # console — used by the smoke check / pip bootstrap
    }

    # ---- get-pip bootstrap --------------------------------------------------
    # bootstrap.pypa.io serves a MOVING "latest" get-pip.py (it bundles whatever pip
    # is current). Treated as EVERGREEN: the build records its hash but does not gate
    # on it (a fixed pin would false-alarm on every upstream refresh).
    GetPip = @{
        Version = '24.2'  # informational — get-pip bundles a pip wheel
        Url     = 'https://bootstrap.pypa.io/get-pip.py'
        # EVERGREEN (see header). Not gated; observed hash is logged each build. To
        # harden later, switch to a version-locked source + set Evergreen = $false.
        Evergreen = $true
        Sha256  = '0000000000000000000000000000000000000000000000000000000000000000'
    }

    # ---- WebView2 Evergreen bootstrapper -----------------------------------
    # The tiny online bootstrapper (MicrosoftEdgeWebview2Setup.exe). Present on
    # current Win10/11 already; we ship it as a prerequisite the MSI can run so an
    # older box still gets the runtime pywebview needs. This URL is "evergreen"
    # (redirects to the latest), so the hash drifts — handled as Evergreen below.
    WebView2 = @{
        Version = 'evergreen'
        Url     = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'
        # EVERGREEN (see header): this fwlink redirects to Microsoft's LATEST WebView2
        # bootstrapper, which changes whenever Edge updates — it cannot be hard-pinned.
        # Not gated; observed hash is logged each build. (The bootstrapper is a tiny
        # MS-signed stub that fetches the real runtime; the OS usually already has it.)
        Evergreen = $true
        Sha256  = '0000000000000000000000000000000000000000000000000000000000000000'
        FileName = 'MicrosoftEdgeWebview2Setup.exe'
    }

    # ---- qpdf (PDF repair/linearize) — BASE feature ------------------------
    # Apache-2.0. The Windows mingw64 zip; we lift qpdf.exe + its DLLs into
    # vendor/qpdf/. app/pdftools.py / app/vendor.py locate it.
    Qpdf = @{
        Version  = '11.9.1'
        Url      = 'https://github.com/qpdf/qpdf/releases/download/v11.9.1/qpdf-11.9.1-mingw64.zip'
        # Pinned 2026-06-21 from the official qpdf/qpdf GitHub release asset
        # (downloaded + hashed; zip verified to contain bin/qpdf.exe + runtime DLLs).
        Sha256   = 'c0c31133ef0611049c632b94371a9901d5cf198a9eebc7a9fef1297d628e8cee'
        # Subdir inside the zip that holds qpdf.exe (+ runtime DLLs).
        BinGlob  = 'qpdf-11.9.1-mingw64/bin/*'
    }

    # ---- Tesseract (OCR) — OPTIONAL feature --------------------------------
    # Apache-2.0. The UB-Mannheim Windows build is the de-facto distributable.
    # NB: this is an INSTALLER .exe (NSIS), not a portable zip. CI run 28568312107
    # showed silent EXECUTION (`/S /D=...`) is fragile (no tesseract.exe landed) —
    # the assemble script now EXTRACTS the installer as an archive with 7-Zip
    # (preinstalled on windows-latest) instead of running it, then harvests
    # tesseract.exe + its DLLs + tessdata recursively (layout-agnostic) into
    # vendor/tesseract/. Same pinned artifact, same hash gate, no new
    # supply-chain surface — only the acquisition mechanism changed. tessdata
    # (eng/osd) ships under vendor/tesseract/tessdata; app/ocr.py sets
    # TESSDATA_PREFIX to it.
    Tesseract = @{
        Version    = '5.4.0'
        Url        = 'https://github.com/UB-Mannheim/tesseract/releases/download/v5.4.0.20240606/tesseract-ocr-w64-setup-5.4.0.20240606.exe'
        # Pinned 2026-06-21 from the UB-Mannheim GitHub release asset (downloaded +
        # hashed; verified PE32 NSIS installer).
        Sha256     = 'c885fff6998e0608ba4bb8ab51436e1c6775c2bafc2559a19b423e18678b60c9'
        # Languages harvested FROM THE INSTALLER: `osd` (orientation detection — the
        # rotated-scan correction in app/ocr.py needs it) and `eng` as the OFFLINE
        # FALLBACK only — the deliberate eng model is the tessdata_best pin below,
        # which OVERWRITES the installer's copy when its fetch succeeds.
        Languages  = @('eng', 'osd')
    }

    # ---- tessdata_best language data (deliberate OCR models) ----------------
    # ACCURACY-OVER-SPEED, deliberately: the installer above bundles whatever
    # eng.traineddata UB-Mannheim chose (a fast/integer model). OCR output feeds
    # redaction DETECTION, where one misread character in an identifier is a silent
    # MISS (the leak side) — so we pin the float LSTM models from
    # tesseract-ocr/tessdata_best (tag 4.1.0) and pay the slower OCR gladly.
    #   * eng REPLACES the installer's copy (which remains the offline-dev fallback
    #     when this fetch is unavailable — see assemble.ps1).
    #   * chi_sim / msa / tam are the OPT-IN language packs for the SG pilot
    #     (LAWDATAMAN_OCR_LANGS — see app/ocr.py ocr_langs(); default stays eng-only).
    #   * chi_sim REQUIRES chi_sim_vert AT LOAD TIME (verified empirically on
    #     tesseract 5.3.4: `-l chi_sim` refuses to load without it) — the assemble
    #     script stages them as a PAIR or not at all.
    # IMMUTABLE + hard-pinned: hashes captured 2026-07-16 from
    # raw.githubusercontent.com (tag 4.1.0), then each file FUNCTIONALLY verified by
    # running tesseract 5.3.4 OCR against it. A mismatch ABORTS the build; only a
    # fetch FAILURE (offline dev box) falls back to the installer's eng.
    TessdataBest = @{
        Version = '4.1.0'
        BaseUrl = 'https://raw.githubusercontent.com/tesseract-ocr/tessdata_best/4.1.0'
        Files   = @(
            @{ Name = 'eng.traineddata';          Sha256 = '8280aed0782fe27257a68ea10fe7ef324ca0f8d85bd2fd145d1c2b560bcb66ba' }
            @{ Name = 'chi_sim.traineddata';      Sha256 = '4fef2d1306c8e87616d4d3e4c6c67faf5d44be3342290cf8f2f0f6e3aa7e735b' }
            @{ Name = 'chi_sim_vert.traineddata'; Sha256 = 'ea672a78157199c333aa12ec4e74550077689b545df5fc770903716850c8b2e5' }
            @{ Name = 'msa.traineddata';          Sha256 = '2fa693701d2fb3685cf3e0a64bc1bfb97d66a50f93c07b2ebc0ff360ea62621f' }
            @{ Name = 'tam.traineddata';          Sha256 = '4b9ce85987f629dd31eaf87443a1646452a43cdf91fcf05e017382ad595dcb9e' }
        )
    }

    # ---- pysqlite3-binary (FTS5 fallback) — CONDITIONAL --------------------
    # Only laid into site-packages IF the embeddable interpreter's sqlite3 lacks
    # FTS5 (assemble.ps1 probes it; ties to app/db.py's runtime fallback). Recent
    # embeddable CPython ships FTS5-enabled, so this is usually skipped — but the
    # build must not assume it. Installed via pip and VERSION-PINNED ONLY: there is no
    # constraints/hash file on this pip path, so pip hash-checking never engages here.
    # The tracked requirements.lock (--require-hashes) is the hash-lock gate for the app's
    # own deps; this conditional interpreter-fallback package is out of that lock's scope.
    PySqlite3 = @{
        Package = 'pysqlite3-binary'
        Version = '0.5.3'  # pin a known-good release; bump deliberately
    }
}
