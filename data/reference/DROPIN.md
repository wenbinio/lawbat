# Reference data DROP-IN guide

Several **openly-licensed** marginal tables that this estimator wants could **not be
fetched in the build environment** (the data-sourcing session's egress proxy returned 403
for `data.gov.sg` / `api.census.gov`, and `WebFetch` was non-functional — see
`MANIFEST.md` in the sourcing scratchpad). They are **not licensing gaps** — they exist
under the Singapore Open Data Licence v1.0 or US Public Domain — so the firm (or a future
session with working egress) can drop them in to sharpen the estimate. **Nothing here was
fabricated to fill a table.**

## How a dropped-in CSV becomes a reference JSON

1. Download the openly-licensed source table (CSV/XLSX) and put the raw file under
   `data/reference/incoming/`.
2. Normalise it to the bundled schema — one JSON per marginal, schema:
   ```json
   {
     "category": "region|sex|age_band|occupation|surname|given_name|medical_condition",
     "jurisdiction": "SG|US",
     "population_N": 1234567,                // the denominator the probs are over (or null)
     "entries": [ {"key": "<value>", "count": 123, "prob": 0.0123}, ... ],
     "source_name": "...", "source_url": "...", "license": "...",
     "redistributable": true,
     "granularity_notes": "...", "retrieved": "YYYY-MM-DD"
   }
   ```
   - `prob = count / population_N` per row. If the table is a TOP-N (not exhaustive), add a
     single explicit residual `__other_*` row so the probs sum to ~1.0 (the loader treats a
     `__other_*` key as the tail bucket and will not synthesise a second tail).
   - Keep `key` values in the same normal form the engine maps to (surnames UPPERCASE like
     the US Census file; planning-area / state names in their published casing; sex as
     `male`/`female`; medical condition as a lowercase snake_case label).
   - **Honesty:** record the real `license` + attribution and add the row to `SOURCES.md`.
     SG datasets are **Singapore Open Data Licence v1.0 → attribution is REQUIRED**.
3. Place the JSON in `data/reference/` (replacing the coarse/partial stub) — `load_reference`
   picks it up by filename on next start. No code change needed for a like-for-like replace.

## FILLED this session — the 3 high-value SG gaps (user-supplied from data.gov.sg)

These were dropped in from user-supplied, ODL-v1.0-licensed data.gov.sg tables and are now
bundled + WIRED into `app/reidrisk.py`:

| Gap | Now bundled as | Wired |
|---|---|---|
| **SG single-year-of-age** (the DOB denominator) | `sg-age-single-year.json` (91 cohorts 0-89 + `90+`, N=4,204,515) | `estimate_k` prices a `dob` QI via `age = REFERENCE_YEAR(2025) - birth_year` → P(age); birth-year COHORT, not exact DOB; open `90+` top bucket; future/absurd years surfaced unpriced. |
| **SG planning-area region** | `sg-region-workplace.json` (47 workplace planning areas, N=2,208,358) | `region` QIs resolve against real planning areas (replaces the Tampines-only stub). |
| **SG SSOC occupation** | `sg-occupation-full.json` (9 SSOC broad groups, N=2,377,800 employed) | `extract_qi_values` maps a privilege ROLE term → SSOC group (managers & administrators / professionals) by substring (replaces the PMET-only mapping). |

The superseded coarse seeds `sg-occupation.json` (PMET/non-PMET) and
`sg-population-by-planning-area.json` (Tampines-only) were REMOVED — they shared
category+jurisdiction with the new tables and caused `select()` load-order ambiguity. The
medical seed `sg-medical-prevalence.json` was replaced by `sg-medical-prevalence-full.json`
(keys aligned to the engine's `_MEDICAL_TERMS` convention; tiering-only, never priced).

## Openly-licensed tables still blocked by this env (pull when egress allows)

| Want | Juris | Open dataset | Licence | Why it matters |
|---|---|---|---|---|
| **Full surname frequency file** | US | Census "Names_2010Census" full file (162,253 surnames ≥100) | US Public Domain (17 U.S.C. § 105) | Extends `us-surname.json` (top-20) to the full tail — sharper P(surname) for non-top names. |
| **Full per-name given-name counts** | US | SSA national names file (`names.zip`, per-year) | US Public Domain (17 U.S.C. § 105) | Replaces the headline-only `us-given-name.json` (probs currently null) with a real, cohort-summed P(given-name). |
| **Full 50-state / county population** | US | Census 2020 apportionment / table P1 | US Public Domain (17 U.S.C. § 105) | Replaces the CA/TX + residual stub in `us-population-by-state.json` with every state. |

## Structural gaps (NOT just this env — do not "fill" these)

- **SG surname frequency (open licence):** no open dataset exists. Best figures are from a
  COMMERCIAL aggregator (forebears.io) → **NOT redistributable**; `sg-surname.json` is
  therefore **not bundled**. SingStat publishes ethnic-group composition (a coarse proxy at
  best), not name frequencies. A firm with its own licensed data can drop a normalised JSON
  in — do not bundle a commercial source into the repo.
- **SG given-name frequency:** no open dataset located.
- **Rare-disease / condition-by-area-by-age joint prevalences** — the re-identification-
  relevant medical detail — are **suppressed for small-cell privacy** and not openly
  published anywhere. This is exactly why the engine uses medical prevalence only to
  **tier** common/rare, never to compute a precise medical k.
- **IHME / GBD** has more conditions but its public results download is **CC BY-NC 4.0
  (non-commercial)** — a redistribution snag for a commercial product. A firm may use it
  itself; do not bundle it.
