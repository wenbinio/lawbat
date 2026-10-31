<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Deterministic PII Recognizer Pack Spec (prior-art-aligned)

**Build status (verified against `core/crates/redaction/src/packs/`):**
- **[BUILT]** Locale packs US/UK/AU/CA/SG (`packs/{us,uk,au,ca,sg}.rs`) — each file header cites
  this spec's PACK section by name/row-ID and the rows match (checksum validators, regexes,
  context gating).
- **[BUILT]** GX-1 IBAN + GX-2 credit-card as always-on GLOBAL built-ins (`BuiltinRecognizers.iban`
  /`.credit_card` in `lib.rs`) — but SIMPLER than spec'd: mod-97 IBAN validation only (no
  per-country registry length gate); Luhn card validation only (no all-zero/all-same-digit guard,
  no IIN issuer-range precision).
- **[NOT YET BUILT]** GX-3 SWIFT/BIC, GX-4 VIN — no dedicated recognizer anywhere (confirmed: the
  `messy_corpus` baseline test explicitly plants a SWIFT/BIC as a documented TRUE MISS).
- **[BUILT]** ADDRESS FAMILY — the global structured-address built-in `Recognizer::Address`
  (GA-1 street / GA-2 floor-unit / GA-3 PO-Box, always-on like email/phone), the OPT-IN locale
  POSTAL rows (`sg:postal`+`sg:postal-bare`, `uk:postcode`, `us:zip`+`us:zip-bare`, `ca:postal`,
  `au:postcode`), and the OPT-IN role-context person-name row `ctx:role-name`. See the new
  "ADDRESS FAMILY" + "ROLE-CONTEXT NAME" sections below.
- **[BUILT, via a different doc]** GX-5 DOB / GX-6 age>89 — as the LEVER2 OPT-IN context
  recognizers `ctx:dob`/`ctx:age-over-89` (see `LEVER2-CONTEXT-CONFIDENCE.md` §3), not as
  standalone GX rows; GX-6's birth-year-inference branch was deliberately dropped (no-clock rule).
- **Profiles: [BUILT]** PCI-DSS-Cardholder only (`packs/profiles.rs`, `Profile::PciDssCardholder`)
  — the simplest, an anchor + gaps. **[NOT YET BUILT]** HIPAA Safe Harbor, GDPR, GLBA — no
  `Profile` variant exists for any of the three; the composition tables below are still the
  DESIGN TARGET, not shipped.

Implementation spec for hand-built Rust recognizers (regex + checksum/range validators; **no ML,
no network, no RNG**). Packs: US, UK, AU, CA. Global extras: SWIFT/BIC, DOB, age>89, VIN. Profiles:
HIPAA Safe Harbor, PCI-DSS, GDPR, GLBA.

**Provenance:** recognizer LIST + regex SHAPES distilled from Microsoft Presidio (MIT), pii-vault
(MIT), OpenRedaction (MIT). Checksum ALGORITHMS are public-domain math from primary specs (SSA,
ABA/Fed, CMS, DEA, NHS, HMRC, ATO/ABR/ASIC, ISO). **No code copied.** Every checksum vector was
independently recomputed in Python; all vectors SYNTHETIC. Reference year for age/DOB = 2026.

## Design posture (every row)
- **Recall-first regex, checksum-as-precision.** Where a checksum supplies precision, omit leading
  `\b`; allow common separators. A checksum miss **DOWNGRADES** confidence, NEVER silently drops.
- **Strip separators (`-`, space, `.`) before any validator.**
- **Two tiers:** checksum-backed (auto-redact-eligible) vs format-only (context-gated, lower
  confidence, human-review-leaning).
- **Audit labels:** `locale:<cc>:<row>`, global extras `builtin:<label>`, profiles `profile:<name>`
  — injective vs `custom:`.
- **Honest framing:** checksum-valid ≠ issued/real; "identifiers-removed and destination-controlled,
  never safe-to-send." Names/free-text/biometrics = later compute.model/human tier.

---

## Locale packs (rows; full regex + checksum math + VALID/INVALID vectors live in `packs/<cc>.rs`)

- **PACK 1 — US (`Locale::UnitedStates`, US-1..US-10):** SSN (structural range rules, no
  checksum — SSA randomized); ITIN (regex-is-validator, group range); ABA routing (weighted
  mod-10 + prefix range); NPI (Luhn over `80840`+9-digit body — **do not reuse plain Luhn**); DEA
  (bespoke digit sum + registrant-letter set); MBI (positional alphabet mask, self-validating);
  EIN (IRS prefix denylist, no checksum — **confirm prefix table before shipping**); bank account
  / passport / driver's licence (format-only, context-required, default-broad).
- **PACK 2 — UK (`Locale::UnitedKingdom`, UK-1..UK-6):** NHS number (Modulus-11); NINO (format
  rules + reserved-prefix denylist, no checksum); UTR (HMRC Mod-11 with a **mapping array**, NOT
  naive `11-remainder`); passport (format-only); driving licence (format-only, DOB-encoded); sort
  code + account / UK IBAN (format-only by default — the VocaLink modulus check needs a bundled
  ~1,151-rule table, not implemented).
- **PACK 3 — AU (`Locale::Australia`, AU-1..AU-7)** — all four core IDs have real checksums: TFN
  (ATO weighted mod-11, weakest checksum ≈1/11 → require context+checksum); ABN (ABR mod-89,
  subtract 1 from first digit); ACN (ASIC complement mod-10 — **`(10-remainder)%10`, not bare
  `10-remainder`**); Medicare (weighted mod-10 over first 8 digits only, first digit 2–6);
  passport/DL/BSB+account (format-only, context-required — DL "OFF-by-default" per state, no
  national format).
- **PACK 4 — CA (`Locale::Canada`, CA-1..CA-9):** SIN (standard Luhn **AND SEPARATELY** reject
  leading digit 0/8 — Luhn alone is insufficient, `046454286` is Luhn-valid but an invalid SIN);
  Ontario OHIP (Luhn over 10 digits, version letters excluded); BC PHN (weighted mod-11 — **confirm
  weight vector vs BC TELEPLAN v4.4**); RAMQ/PHIN (format-only); passport/DL (format-only,
  context-gated); Business Number (Luhn as a BOOSTER only — CRA does not publish the algorithm,
  never hard-reject on a miss); bank transit/account (format-only).

## Global extras (`builtin:*`, not locale-gated)

- **GX-1 IBAN** — country code + ISO 7064 mod-97-10, spec wants the country-registry LENGTH gate
  too (highest-value precision lever, e.g. rejects `US64…` since the US has no IBAN) — **not
  built**; the shipped validator is mod-97 only.
- **GX-2 credit/debit PAN** — Luhn + IIN issuer-range precision (Visa/MC/Amex/Discover/Diners/JCB)
  + a guard rejecting all-same-digit/all-zero (both pass Luhn trivially) — **the IIN + all-same
  guard are not built**; the shipped validator is bounded-length Luhn only.
- **GX-3 SWIFT/BIC** — format + ISO 3166-1 country-code membership, no checksum. **Not built.**
- **GX-4 VIN** — mod-11 check digit (ISO 3779/NHTSA), booster not hard gate (European VINs may not
  compute). **Not built.**
- **GX-5 DOB** — ISO/numeric/long-form date regex + plausibility validator (leap-aware,
  1900–2026), context-mandatory (no DOB keyword in ~30–40 chars → generic DATE_TIME, not DOB).
  Built as `ctx:dob`.
- **GX-6 age>89** — number 90–130 within an age-keyword window; **no birth-year inference** (the
  spec's "DOB-implied if 2026−birth_year>89" branch was deliberately dropped to stay clock-free).
  Built as `ctx:age-over-89`.

---

## ADDRESS FAMILY (global structured-address built-in + locale postal rows) — [BUILT]

The deterministic engine covers the STRUCTURED subset of addresses; FREE-TEXT / prose
addresses with no number+suffix shape remain a `human_review_gap`. Motivated by a real miss
(a 62-page redacted prospectus where every address + role-context name survived). All rows are
recall-first per the PRINCIPLE (over-flag is SAFE; a miss is the leak) and route to the CAREFUL
review tier (address is never checksum/structural → capped below High; postal rows are
structural → Medium, no `postal` class lexicon → never High).

- **GA-1 STREET (global built-in `address`, DEFAULT-ON) — [BUILT]:** house/lot number
  (`\d{1,5}[A-Za-z]?`) + 0–4 `\p{Lu}`-anchored street-name tokens + a case-tolerant street-TYPE
  SUFFIX (Street/St/Road/Rd/Avenue/Ave/Boulevard/Blvd/Drive/Dr/Lane/Way/Place/Quay/Crescent/
  Terrace/Court/Square/Close/Walk/Hill/Park/Gardens/View/Link/Loop/Row/Parade/Rise/Grove/…).
  The `\p{Lu}` anchor on street-name tokens bounds the flood (a lowercase "14 items on the road"
  run does NOT match). Multi-token street names allowed. Linear-time (bounded `{0,4}`).
- **GA-2 FLOOR / UNIT (global built-in `address`) — [BUILT]:** the SG unit form `#NN-NN(NN)`
  (`#16-03`, `#16-0304`) + labelled floor/unit forms (`Level N`, `Suite N`, `Unit N`, `Apt N`,
  `Block N`, …), each requiring a trailing number so a bare "Unit tests" never matches.
- **GA-3 PO-BOX (global built-in `address`) — [BUILT]:** `PO Box N`, `P.O. Box N`, `Post Office
  Box N`, `GPO Box N`, `Locked Bag N` (trailing box number required).
- **Locale POSTAL rows (OPT-IN, ride the locale packs) — [BUILT]:**
  - `sg:postal` (`Singapore NNNNNN` / `S(NNNNNN)`, precise/default-on) + `sg:postal-bare`
    (bare 6-digit, context-gated on postal/address keyword, AGGRESSIVE/advisory);
  - `uk:postcode` (full outward+inward grammar `[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}`, precise);
  - `us:zip` (ZIP+4 or `STATE ZIP5`, precise) + `us:zip-bare` (bare 5-digit, context-gated on
    zip/address keyword, AGGRESSIVE/advisory);
  - `ca:postal` (`A1A 1A1`, recall-first — no FSA letter restriction, precise);
  - `au:postcode` (`STATE NNNN`, state-bound, precise).

## ROLE-CONTEXT NAME — `ctx:role-name` (OPT-IN Lever-2 context row) — [BUILT]

A 2–4-token Capitalized name run gated on a ROLE heading/label keyword in-window (Director(s),
Manager(s), Chairman, Chief … Officer, CEO/CFO/COO/CIO, Trustee, Partner, Secretary, Signatory,
"Name:"). Closes the director/manager LIST miss (`Managers\nLee Wai Keong\nTan Peng Ho\n…`) the
honorific-only `Recognizer::Name` heuristic never caught. Deliberately FP-PRONE (it over-flags a
Capitalized ORG in the same list — fine per the PRINCIPLE); the review layer + candidate GROUPING
absorb the noise. CAPPED at the CAREFUL tier (`cap_tier: Some(Medium)`) so it can NEVER
quick-confirm. HONEST LIMITATION: the keyword gate excludes the matched span, so a role word
INLINE as the first token on the SAME line (`Director Lee Wai Keong`) is absorbed and gated out —
the heading-then-list layout (the reported miss) is the target; inline prose stays a
reviewer / TERM / name-expansion job.

---

## HIPAA Safe Harbor — 18-identifier coverage (DESIGN TARGET — profile not built)

| # | Identifier | Det? | Rows |
|---|---|---|---|
| 1 Names | PARTIAL | title-prefixed heuristic + role-context list `ctx:role-name` + TERMs; UNLABELLED free-text names = gap (NER/human tier) |
| 2 Geographic < state | PARTIAL | ZIP+000-rule; STRUCTURED street address + locale postal now covered (GA-1/2/3 + `*:postal`/`*:zip`/…); FREE-TEXT/prose address = gap |
| 3 Dates (except year) + age>89 | PARTIAL | GX-5, GX-6; "related-to-individual" judgment = gap |
| 4-5 Telephone/Fax | YES | `phone` |
| 6 Email | YES | `email` |
| 7 SSN | YES | US-1 |
| 8 MRN | PARTIAL | known format/prefix only; generic = gap |
| 9 Health-plan beneficiary | PARTIAL | US-6, AU-4/CA-2/CA-3; generic = gap |
| 10 Account numbers | PARTIAL | GX-1/GX-2/US-3; generic account = gap |
| 11 Cert/license | PARTIAL | US-5,US-4,DL rows |
| 12 Vehicle | PARTIAL | GX-4 (VIN, not built); plates = gap |
| 13 Device/serial | PARTIAL | IMEI (Luhn) det; generic = gap |
| 14 URLs / 15 IP | YES | `url` / `ip` |
| 16 Biometric / 17 Photos | NO — gap | (not text) |
| 18 Any-other-unique | NO — gap | open-ended |

`human_review_gaps`: #1, #2(full address), #16, #17, #18 + generic #8/#10/#11/#13 + the
§164.514(b)(2)(ii) "no actual knowledge" attestation (no tool discharges it).

## Profile composition (DESIGN TARGET for HIPAA/GDPR/GLBA; PCI-DSS is BUILT)

| Profile | Status | Bundled rows | human_review_gaps |
|---|---|---|---|
| PCI-DSS | **BUILT** | GX-2 (PAN, Luhn) = anchor; track_data; card_expiry (context); name (gap) | cardholder name; CVV/CVC; service code; PIN |
| HIPAA Safe Harbor | not built | phone, fax, email, url, ip, US-1, US-4/5/6, AU-4/CA-2/CA-3, GX-4, IMEI, zip+000, GX-5/6, GX-1/2/ABA | names, full address, biometrics, photos, free-text; generic MRN/beneficiary/account/license/device; "actual knowledge" prong |
| GDPR | not built | email, phone, fax, ip, url, mac, GX-1/2/3, all locale national-ID + passport rows, GX-5, zip, cookie/device id | names + direct identifiers in free text; "singling out"; Art. 9 special categories; pseudonymisation-vs-anonymisation |
| GLBA | not built | US-1, GX-2/debit, GX-1, US-3/routing, US-7, CA-8, name*, address*/zip, GX-5, phone, email | names, addresses; "financial context/NPI" determination; publicly-available exclusion; generic account/balance/income |

---

## What we MATCH from prior art
1. The checksum core (Luhn, IBAN mod-97, ABA mod-10, NHS mod-11, all AU, UTR, SIN Luhn, OHIP, NPI)
   = the high-value low-FP tier; `validate: Option<fn(&str)->bool>` fits.
2. Two-stage detection (broad recall regex → strip separators → validator).
3. Context-keyword boosting with low base scores — **we add the context-proximity dimension**
   (`LEVER2-CONTEXT-CONFIDENCE.md`) for format-only/weak-checksum rows.
4. Format-only national IDs (US SSN/ITIN/bank/DL/passport, UK NINO, SG NRIC) — our recall-first
   posture is ALIGNED, not a gap.
5. Per-country opt-in packs map onto our `Locale` data-row design.

## What we DELIBERATELY do differently
1. **No spaCy/transformer NER for names** — names/free-text/biometrics = human-review/later
   compute.model tier; an explicit `human_review_gap`, never a silent miss dressed as coverage.
2. **Recall-first checksum: a miss downgrades, never silently drops** (European VINs / test-BICs /
   unconfirmed-BN-Luhn ship lower-confidence, not failed-closed).
3. **Counts-only tamper-evident audit** — never logs a matched value.
4. **Opt-in locale packs, off by default** — a non-AU firm gets no AU false-flags.
5. **Honest framing as a product invariant** — never "HIPAA-compliant"/"safe-to-send," only
   "structured-identifier recall + explicit gap list."
6. **Linear-time regex only (no ReDoS), no RNG in the trusted core** — every validator O(n)
   integer math.

## Correctness traps (do NOT lose)
- CA SIN: Luhn AND first-digit∉{0,8} are TWO checks (`046454286` Luhn-valid but invalid SIN).
- AU ACN: `(10-(sum%10))%10`, not bare `10-(sum%10)`.
- UK UTR: HMRC array `[2,1,9,8,7,6,5,4,3,2,1]`, not `11-remainder`.
- US NPI: prepend `80840` before Luhn.
- AU Medicare: checksum over first 8 digits only (not the issue/IRN digits).
- Presidio `UsLicenseRecognizer` regex typo `A-Z]{2}` (missing `[`) — fixed on port.
- Confirm vs primary before shipping: US EIN prefix allowlist (IRS IRM), BC PHN MOD-11 weights (BC
  TELEPLAN v4.4), whether CA BN9 uses Luhn (CRA unpublished → booster only).

## Sources
Presidio (MIT) · pii-vault (MIT) · OpenRedaction (MIT) · SSA · ABA (Apache Commons) · CMS
NPI/MBI · DEA · IRS IRM 21.7.13 · NHS Data Dictionary · DWP CV0013 · HMRC · ATO/ABR/ASIC ·
Services Australia · Ontario MOH · BC TELEPLAN v4.4 · ISO 3779/NHTSA (VIN) · ISO 9362 (BIC) ·
ISO 13616/7064 (IBAN) · ISO 7812 (Luhn) · Pay.UK v8.70 · 45 CFR §164.514(b)(2) · PCI-DSS · GDPR
Art 4/9 + Recitals 26/30 · GLBA 16 CFR 313. All checksum test vectors independently recomputed in
Python; all vectors synthetic.
