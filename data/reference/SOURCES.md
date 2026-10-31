# Re-identification risk — reference data provenance & licences

These tables are **marginal quasi-identifier (QI) frequency distributions** consumed by
`app/reidrisk.py` to estimate population-uniqueness k-values
(`k ≈ N · P(QI-tuple)`, `P` built from per-QI marginals). Each JSON carries its own
`source_name` / `source_url` / `license` / `redistributable` / `granularity_notes`
fields; this file is the human-readable index + the **attribution required by the
licences**.

> **HONESTY (load-bearing — do not soften):** these are MARGINAL frequencies multiplied
> under an INDEPENDENCE assumption. Real QIs are correlated, so the marginal product
> OVER-states k → UNDER-states risk (the dangerous direction). The k-value is an
> **optimistic lower bound on uniqueness**, never a "% safe" / "safe to send" verdict.
> See `app/reidrisk.py` and the engine's honesty flags. Medical prevalences are
> NATIONAL/CRUDE — used only to **tier** a condition common(weak-QI) / rare(strong-QI),
> never to compute a precise medical-QI k.

## Bundled files (10) — all openly licensed & redistributable

`sg-surname.json` is **deliberately NOT bundled** — the only figures located were from
**forebears.io, a commercial aggregator (NOT redistributable)**. There is no open SG
surname-frequency dataset; see `DROPIN.md`.

### Singapore (SG) — Singapore Open Data Licence v1.0

> **Singapore Open Data Licence v1.0 REQUIRES ATTRIBUTION.** Each SG dataset below is
> attributed to its publisher with a licence link. Licence text:
> <https://data.gov.sg/open-data-licence>

| File | Category | Attribution | Licence |
|---|---|---|---|
| `sg-sex.json` | sex (M/F) | Contains information from **SingStat / population.gov.sg, _Population in Brief 2024_** (sex ratio 948 M per 1,000 F; total residents 4.18M, Jun 2024), accessed under the terms of the **Singapore Open Data Licence v1.0**. M/F counts are DERIVED from total × ratio (flagged). | Singapore Open Data Licence v1.0 — <https://data.gov.sg/open-data-licence> |
| `sg-age-band.json` | age band (3 coarse) | Contains information from **SingStat / population.gov.sg, _Population in Brief 2024_ + _Population Trends 2024_** (65+ = 18.0% / 753,900, end-Jun 2024), accessed under the **Singapore Open Data Licence v1.0**. Only the 65+ band is directly published; 0-14 / 15-64 are approximations/residual (flagged). KEPT alongside `sg-age-single-year.json` — distinct `age_band` category (the coarse bands), not clobbered by the single-year table. | Singapore Open Data Licence v1.0 — <https://data.gov.sg/open-data-licence> |
| `sg-age-single-year.json` | age (single year, 0-89 + `90+`) | Contains information from **SingStat / data.gov.sg, _Singapore Residents By Single Year Of Age And Sex_** (dataset `d_4bd9ffc2595acd61fd1a7f642caf8f36`), accessed under the **Singapore Open Data Licence v1.0**. 91 single-year cohorts, prob-sum 1.0, denominator N = 4,204,515. **The DOB denominator** — `app/reidrisk.py` prices a birth-year QI via `age = REFERENCE_YEAR(2025) - birth_year` against this table (the birth-year COHORT, not an exact day-of-birth). | Singapore Open Data Licence v1.0 — <https://data.gov.sg/open-data-licence> |
| `sg-occupation-full.json` | occupation (9 SSOC broad groups) | Contains information from the SingStat/MOM data.gov.sg dataset **_Employed Residents Aged 15 Years And Over By Occupation_** (e.g. `d_1d7ab908d16d7b9ddf6f2c2985894119`), accessed under the **Singapore Open Data Licence v1.0**. 9 SSOC-2020 broad groups (managers & administrators / professionals / associate professionals & technicians / clerical / service & sales / craftsmen / plant & machine operators / cleaners & labourers / others), prob-sum 1.0, denominator N = 2,377,800 (EMPLOYED residents — occupation P is employment-conditional; folding it against the total-population denominator is OPTIMISTIC, flagged in the engine). **Replaces** the coarse 2-bucket PMET/non-PMET seed. | Singapore Open Data Licence v1.0 — <https://data.gov.sg/open-data-licence> |
| `sg-region-workplace.json` | region (47 workplace planning areas) | Contains information from the SingStat / data.gov.sg **_Census of Population 2020_ — workplace by planning area** series, accessed under the **Singapore Open Data Licence v1.0**. 47 planning areas (workplace), prob-sum 1.0, denominator N = 2,208,358. **Replaces** the Tampines-only `region` stub. NOTE: this is a WORKPLACE distribution (includes "No Fixed Location for Work" / "Works from Home"), not residence — a reasonable region marginal but flag the workplace-vs-residence distinction. Cite the SingStat data.gov.sg dataset, NOT a third-party aggregator. | Singapore Open Data Licence v1.0 — <https://data.gov.sg/open-data-licence> |
| `sg-medical-prevalence-full.json` | medical condition (national crude, 7 conditions) | Contains information from the **MOH / Health Promotion Board _National Population Health Survey_** chronic-disease prevalence series via **data.gov.sg**, accessed under the **Singapore Open Data Licence v1.0**. 7 conditions (hypertension, hyperlipidaemia, overweight, obesity, binge drinking, daily smoking, diabetes mellitus), latest-year crude prevalences — NON-PARTITION (do NOT sum to 1). Keys ALIGNED to the engine's `_MEDICAL_TERMS` convention (original published label kept in `source_label`). **TIERING use only** (common-weak-QI / rare-strong-QI); NEVER priced into the k product (see honesty note). **Replaces** the 5-condition seed. | Singapore Open Data Licence v1.0 — <https://data.gov.sg/open-data-licence> |

### United States (US) — Public Domain (17 U.S.C. § 105)

US Federal Government works are **public domain** (17 U.S.C. § 105) — free to reuse and
redistribute. No attribution is legally required; we credit the source for honesty/traceability.

| File | Category | Source | Licence |
|---|---|---|---|
| `us-sex.json` | sex (M/F, exact) | **U.S. Census Bureau, _2020 Census — Age and Sex Composition_ (C2020BR-06)**. <https://www.census.gov/library/publications/2023/decennial/c2020br-06.html> | US Public Domain (17 U.S.C. § 105) |
| `us-surname.json` | surname (top-20 + tail) | **U.S. Census Bureau, _Frequently Occurring Surnames from the 2010 Census_ (Comenetz, 2016)** — aggregate name frequencies only, no individuals. <https://www.census.gov/topics/population/genealogy/data/2010_surnames.html> | US Public Domain (17 U.S.C. § 105) |
| `us-given-name.json` | given name (headline only) | **U.S. Social Security Administration, _Popular Baby Names / National Data_**. <https://www.ssa.gov/oact/babynames/> Only #1-rank counts captured — a near-empty marginal (DROP-IN to extend). | US Public Domain (17 U.S.C. § 105) |
| `us-population-by-state.json` | region (state) | **U.S. Census Bureau, _2020 Census Apportionment / state population totals_**. <https://www.census.gov/data/tables/2020/dec/2020-apportionment-data.html> Only CA + TX exact; the rest is a residual `__other_48_states_plus_DC` bucket (DROP-IN to complete). | US Public Domain (17 U.S.C. § 105) |

## Notes on derived / partial values

Some values are **DERIVED or PARTIAL** (flagged per-file in `redistribution_notes`):
- SG M/F counts = total × published sex ratio (not a transcribed count table).
- SG 0-14 / 15-64 bands are approximations around the published 65+ figure.
- US state / surname tail buckets (`__other_*`) are arithmetic residuals — the full
  public-domain tables are trivial DROP-INs (`DROPIN.md`).
- `us-given-name.json` carries only headline #1 counts (probs null) → the loader treats
  it as a near-empty marginal (very low coverage); replace with the full SSA file
  (`DROPIN.md`).

The `__other_*` residual keys are **explicit tail buckets** that already make a table sum
to ~1.0; the loader recognises them and does NOT add a second synthetic tail on top.
