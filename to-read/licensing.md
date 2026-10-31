# Licensing decision record

**Status:** ACCEPTED (2026-06-21) — **AGPL-3.0, Option A**; a CLAUDE.md non-negotiable.

## The finding
The dependency audit (`THIRD_PARTY_LICENSES.md`) surfaced **two copyleft runtime deps**:
- **PyMuPDF** — dual-licensed AGPL-3.0 **or** Artifex commercial.
- **extract-msg** (`.msg`) — **GPL**.

Everything else (web/office/desktop stack) is permissive (MIT/BSD-3/PSF).

## Why it matters
Copyleft triggers on **distribution of a binary** (the Windows installer is exactly that).
**AGPL-3.0** §13 also covers users interacting **over a network**; our localhost web UI to
a single local user is a gray area, but the conservative reading is we must make
corresponding **source available** to that user. Distributing a closed build linked with
PyMuPDF/extract-msg without complying is a violation.

**Removes a false fear:** copyleft burdens the **distributor (us), not the law firm that
merely uses the app** — a firm runs AGPL/GPL software with no obligations. It's a
constraint on how *we* ship and monetize, not an adoption barrier.

## Fit with the settled model
CLAUDE.md fixes the model as **"free software + optional paid on-site VM setup service" —
not feature tiers / not a proprietary edition.** Selling a *service* (setup/hardening) is
not distributing a modified binary, so it never triggers copyleft. There is no planned
closed component that would *need* the Artifex commercial license.

## Options (A chosen)
- **A. Embrace AGPL-3.0 *(chosen)*** — publish the source (it's free software anyway),
  ship a NOTICE/about-box, link to source from the app. Zero cost; keeps **PyMuPDF**,
  whose extraction robustness over messy legal files *is the product*; no user-side
  friction; AGPL+GPL deps are mutually compatible. Cost: source stays public, and any
  *future closed component* needs relicensing or the Artifex license.
- **B. Go permissive (MIT/BSD) + swap the copyleft deps** — PyMuPDF → pypdf/pdfminer.six,
  extract-msg → an olefile parser. Enables a future closed edition, but most work and
  **directly risks core value** (permissive PDF libs are materially weaker on messy/real
  PDFs); needs a quality benchmark first.
- **C. Buy the Artifex commercial license** — keeps PyMuPDF, drops the AGPL obligation,
  enables a proprietary build. Ongoing opaque cost; premature for a free pilot; still must
  resolve extract-msg's GPL separately.

## Recommendation
**Option A for the pilot.** Matches the free-software model, preserves extraction
robustness, costs nothing, burdens no firm. Revisit (→ B or C) only if a closed component
is ever wanted. As cheap insurance, keep the PDF and `.msg` extractors **pluggable**
(`LAWDATAMAN_PDF_BACKEND` / `LAWDATAMAN_MSG_BACKEND`) so a future swap to permissive
backends is a localized change, not a rewrite.

## Platform note
The Rust platform moves PDF work to **pdfium-render (BSD-3) + lopdf (MIT)** — naturally
permissive on PDF. So this question mainly concerns the **current Python tool's**
distribution window.
