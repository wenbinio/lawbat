<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Lever 2 — Context-Proximity Scoring + Confidence Tier

**[BUILT — see `core/crates/redaction/src/context.rs` + `lib.rs`]**: `Confidence`, `ReviewTier`,
`ReviewPolicy`, `Selection::quick_confirm`, `ReviewSummary`, the four `ContextRecognizer` rows,
and the strict-≤20-byte `Close` gap (`CLOSE_BYTES`) are all present and match the design below.

Context-proximity scoring + a confidence TIER for the deterministic redaction engine, composing
with Lever 1 (the `RegexSet` prefilter): context-required recognizers flow through the same
`pattern_set` + merge; the context GATE + tier assignment happen at candidate finalization. **No
ML, no clock, no network, no new deps.** Sister doc: `RECOGNIZER-PACKS-SPEC.md`. The four
recognizers here are GX-5 (DOB) / GX-6 (age>89) plus an undashed SSN and a generic account/MRN,
all context-gated.

## 0-1. The load-bearing invariant — context is purely ADDITIVE (the finaliser gate)

Context can ONLY (a) raise a candidate's confidence tier, or (b) cause a NEW context-required
recognizer to add a candidate — it must **NEVER** suppress or remove a candidate the engine
surfaces today. All existing recognizers fire EXACTLY as before; `confidence` is an additive
struct field on `RedactionCandidate`, always computed, that changes no spans/merge/which-
candidates-fire. **Default behavior is byte-identical to today** — the four context recognizers
are OFF by default (`ContextRecognizers::none()`); enabling is opt-in. Proven by
`lever2_additive_only_default_off_is_byte_identical_set_and_spans` + the untouched `messy_corpus`
baselines.

The gate is a **finalization filter on merged spans** in `RedactionEngine::merged_spans`, never
an alteration of an existing recognizer: a context-required candidate is dropped **only when
BOTH** (i) no context keyword in-window AND (ii) no non-context recognizer also covers the merged
span — if any normal recognizer also matched, the candidate STAYS. Two facts make this provably
additive-only: (1) **Priority** — `Recognizer::Context` has the highest priority *value* (6), so
if a normal recognizer also covers the span the merge keeps the NORMAL recognizer primary → the
span is NOT context-only → the gate cannot drop it. (2) **short-circuit** — on the default
all-off path the whole gate + proximity block is skipped → the set/spans are byte-identical.

## 2. The confidence ladder (deterministic; no clock)

`Confidence = { Low, Medium, High }` (`Low < Medium < High`), computed in `confidence_for` purely
from (span position, window text, fixed lexicons):

| Rung | Recognizer class | Tier |
|---|---|---|
| 1 | **Checksum-validated** — Luhn card (`CreditCard`) / mod-97 IBAN (`Iban`) | **High** (context-irrelevant) |
| 2 | **Structurally-specific** — `Email`, every `Locale` national-ID row (dashed SSN, NRIC), `Profile` bespoke row | **High** if a class keyword in-window, else **Medium** |
| 3 | **Context-required** — primary is `Recognizer::Context` | **High** if a keyword is CLOSE (strict ≤20-byte gap, §4), else the row's `default_tier` (**Medium**) |
| 4 | **Everything else** — `Phone`/`Id`/`Name`/`Url`/`Ip`, a caller `Term`, a `Custom` rule | **Low**, raised to **Medium** if a class keyword in-window |

- **Rung 1 is the two CHECKSUM built-ins only.** A *structural-only* validator (dashed-SSN range
  rules) is NOT a checksum → dashed SSN is rung 2 (High near "SSN", Medium alone). A checksum-
  bearing locale/profile row (e.g. Luhn NPI) is conservatively rung-2 for now (promoting to rung 1
  needs per-row checksum-vs-structural metadata — a deferred data-row addition); annotation only,
  never changes which candidates fire.
- **Class keywords** (`class_lexicon`): small high-precision per-kind sets (email → {email, e-mail,
  mail, contact}; locale `*:ssn` → {ssn, social security, …}; `*:nric` → {nric, fin, ic, identity
  card}; phone/url/id their own). A kind with no class lexicon stays at its rung floor. Default tier
  for an unhandled candidate = Low (rung 4).

## 3. The four context-required recognizers (DATA rows)

One shared `ContextRecognizer` abstraction in `src/context.rs` — `{ name, pattern,
validate: Option<fn(&str)->bool>, lexicon: &'static [&'static str], default_tier }` (mirroring
`LocaleRecognizer`). They compile into the SAME `TaggedPattern` machinery (prefilter/validate/merge
identically), tagged `Recognizer::Context("ctx:<name>")`. OFF by default.

| Row (`ctx:<name>`) | Shape | Validator | Lexicon (CI, word-boundary, in-window) |
|---|---|---|---|
| `ctx:ssn-undashed` | `\b\d{9}\b` | `ssn_valid` (reuses the US pack's structural SSN rules) | `ssn`, `social security`, `social security number` |
| `ctx:dob` | `d/m/y` or `d-m-y` (1–2/1–2/2–4) or month-name forms | — | `dob`, `d.o.b`, `date of birth`, `born` |
| `ctx:age-over-89` | `\b(?:9\d\|1[0-2]\d)\b` (explicit ages 90..=129) | — | `age`, `years old`, `y/o`, `yo`, `aged` |
| `ctx:account-mrn` | `\b[A-Za-z0-9]*\d[A-Za-z0-9]*\b` (alnum, ≥1 digit) | `acct_len_valid` (len 6–12; `regex` has no lookahead so length is the validator) | `account`, `acct`, `mrn`, `medical record`, `record no`, `record number` |

**age>89 scope / no-clock (load-bearing).** Matches an **explicit age number** 90..=129 near an age
keyword; does **NOT** infer age from a birth YEAR (that needs "today" = non-deterministic,
forbidden — birth-year DOB is covered by `ctx:dob`). The one deliberate deviation from the spec's
GX-6 ("DOB-implied if 2026−birth_year>89"): dropped to stay clock-free
(`lever2_age_over_89_no_clock_dependency_identical_across_calls`,
`lever2_no_systemtime_or_clock_in_crate_source`).

## 4. Proximity probe (`keyword_in_window`) + the `Close` tightening

Deterministic, char-boundary-safe, confidentiality-clean. Scans the ±40-char window
(`CONTEXT_WINDOW_CHARS`, same radius as the review snippet), returns `Proximity { None, Window,
Close }` — **never any text**. A keyword fires only when its full TOKEN lies within the window,
case-insensitive + word-boundary anchored (`ssn` matches "SSN:" not "assignment"). Multibyte-safe.

> **`Close` requires a strict ≤20-byte gap** (`CLOSE_BYTES`) between keyword and match,
> *regardless of line* — TIGHTENED from an earlier same-line OR-arm that was permissive only
> while the tier was purely advisory. The two-tier routing (§9) makes the tier **load-bearing**: a
> rung-3 **High** is auto-pre-accepted by `Selection::quick_confirm`, so an over-eager `Close` =
> an over-eager auto-accept. A same-line-but-far keyword now grades `Window` → Medium → **Tier-2
> careful review** (it still FIRES; only its tier/routing change) — provably additive-only (only
> lowers some tiers) and affects ONLY opted-in context recognizers. Locked by
> `window_when_same_line_but_beyond_close_bytes`.

## 5-6. Confidentiality (audit) + determinism

The audit note appends per-tier counts `{high=H medium=M low=L}` (always all three, zeros incl.)
after the per-recognizer breakdown in every redaction note (`redact_matter`, `scan_matter`,
`apply_selection`, `scan_matter_pdf`, `redact_matter_pdf`). `tier_breakdown` records **COUNTS
only** — never a matched value, cleartext, or which lexicon entry fired
(`lever2_audit_note_has_tier_counts_and_no_cleartext`). `confidence` doesn't perturb span
coordinates, the deterministic total order, the merge, or `Selection` stability;
`candidates(text) == candidates(text)`; regexes are linear-time (no backref/lookaround).

## 7. Adding a context recognizer later (the data-row seam)

1. Add one `ContextRecognizer` row to `CONTEXT_RECOGNIZERS` in `src/context.rs` (+ a small
   validator `fn` if needed). 2. Add one `bool` field to `ContextRecognizers` + its arms in
   `all()`/`none()`/`enabled()`/`any()`. No new `Recognizer` variant / `RecognizerKey` arm /
   detection-driver change — `Recognizer::Context("ctx:<name>")` carries each row's namespaced
   label (like the `Locale`/`Profile` data-row axes).

## 8. Limitations (honest framing)
- **Reasonable-efforts, never "safe-to-send"** — a confidence tier is a reviewer aid, not a safety
  guarantee.
- **age>89 is explicit-age-only** (no birth-year inference, no clock) — §3.
- `ctx:account-mrn` is the broadest — strictly keyword-gated + length-bounded, but a 6–12 alnum run
  near "account" can still be a non-account token. Recall-first by design.
- Statistical / Presidio-class name+PII detection remains the later `compute.model` tier, NOT this
  deterministic increment.

## 9. Two-tier review routing — the LOAD-BEARING consumer of the tier

The tier was *advisory* until this: computed, surfaced, counted (§5), but nothing in the workflow
*consumed* it. The routing makes the tier **drive** the review (HOW a candidate is reviewed), and
justified the `Close` tightening (§4). Slots into scan → review → apply as the **review** step
(pure, between the audited `scan_matter` and `apply_selection`), adding **no `Core` surface and
no new capability**.

| Tier | `ReviewTier` | What | Selection |
|---|---|---|---|
| 1 | `QuickConfirm` | High-confidence (checksum IDs, structural + class keyword, context + CLOSE keyword) | **pre-accepted** by `Selection::quick_confirm` (bulk-confirm / spot-reject) |
| 2 | `CarefulReview` | Medium / Low | **NOT pre-accepted** — reviewer opts each in via `Selection::accept` |

- **`ReviewPolicy`** = the single tunable: a quick-confirm **floor** (`Confidence`, default
  **High** — only the strongest are bulk-confirmable). `with_quick_confirm_floor(Medium)` also
  bulk-confirms Medium; a `Low` floor coincides with `Selection::all`.
- **`Selection::quick_confirm(scan, policy)`** = the graduated middle between `Selection::all` and
  `::none`; pre-accepts only Tier-1 spans.
- **`ReviewSummary::of(scan, policy)`** = the cleartext-FREE face: per-doc `quick_confirm` /
  `careful_review` **counts only** + the floor ("12 to confirm, 5 to review"). Its Tier-1 total
  equals `Selection::quick_confirm(scan, policy).len()` — locked by
  `review_summary_counts_match_quick_confirm_selection`.
- **Audit:** no new note — the existing `scan_matter`/`apply_selection` per-tier counts (§5) ARE
  the routing record.

All test families pass (additive-only / gate / per-rung tier / age-no-clock / determinism / audit-
no-cleartext / multibyte / routing end-to-end), plus all pre-existing redaction tests + both
`messy_corpus` baselines unchanged.
