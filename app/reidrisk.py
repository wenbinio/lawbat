"""
Re-identification RISK estimator — population-uniqueness / k-value.

A NEW, SEPARATE add-on module. It is DISTINCT from the per-document exposure meter
(`app/privilege.py`, the redaction-page re-id index): that one COUNTS quasi-identifier
SIGNALS to prompt review; THIS one estimates a real k-value from REAL population marginal-
frequency reference tables (`data/reference/`):

    k ≈ N · P(QI-tuple)          (population-uniqueness lower bound)
    P(QI-tuple) = ∏ P(value)     (the marginal product — see THE HONESTY SPINE)

It NEVER touches the redaction carrier (`app/privilege.py` / `app/redactionmodel.py` /
`app/ui/redaction.*`). It is local-only, deterministic, linear-time, bounded; no network,
no model/LLM, no RNG. It logs / returns NO cleartext beyond the QI VALUES the caller already
holds (and even those are kept local — never egressed, never audited).

================================================================================
THE HONESTY SPINE (load-bearing — a reviewer WILL reject violations)
================================================================================
This estimator multiplies INDEPENDENT marginal frequencies. Real quasi-identifiers (QIs)
are CORRELATED (age↔condition, area↔surname, sex↔occupation). Positive correlation makes
the marginal product OVER-state k → UNDER-state risk — the DANGEROUS direction for a
privacy tool. Therefore:

  * The k-value is an ESTIMATE and an OPTIMISTIC LOWER BOUND on uniqueness risk. NEVER a
    guarantee, NEVER a "% safe", NEVER a "safe to send" verdict.
  * The estimate may only ever RAISE concern (flag "this looks unique / re-identifiable").
    It NEVER produces a "clear"/"safe" state and is NEVER used to downgrade a redaction
    decision. The word "safe" appears here only NEGATED.
  * Every result carries explicit flags: `is_estimate=True`, `assumes_independence=True`,
    `direction="optimistic — may under-state risk"`, and a coverage disclosure (which QIs
    matched reference data, which did not).
  * MEDICAL: the bundled prevalences are NATIONAL / CRUDE for COMMON conditions (weak QIs).
    They are used ONLY to TIER a detected condition common(weak) / rare(strong). A precise
    medical-QI k is NOT computed from crude national prevalence (it under-counts small-cell
    uniqueness, the wrong direction). The medical tier never enters the k product.

Prosecutor vs journalist risk (we LEAD with prosecutor — the worst case):
  * prosecutor risk = 1 / k_est    (an attacker who knows the target is in the data)
  * journalist risk = average over the cohort (a weaker attacker over a group)
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Protocol

# Reuse app/privilege.py's DETECTION regexes (the SINGLE source of those lexicons) — we
# only borrow the detectors, then MAP matched strings to reference-table keys here. This
# is a read-only import of compiled patterns; it does NOT touch the redaction carrier.
from . import privilege as _priv


# --------------------------------------------------------------- bounds ------
# Bound every loop so a hostile / pathological input can never make this super-linear or
# unbounded. Generous for any genuine legal document.
_MAX_TEXT_BYTES = 4_000_000        # only the first N bytes of a giant input are scanned
_MAX_QI_MATCHES = 5_000            # cap matches per category before we stop counting
_MAX_BATCH_DOCS = 2_000            # docs in one assess_release call
_MAX_LINK_TERMS = 200              # user-supplied link terms

# A k below this reads as "looks unique / highly re-identifiable" (the only direction this
# tool moves — toward MORE concern). It is NOT a safety threshold; there is no "safe" band.
K_UNIQUE_CEILING = 1.0             # k <= 1  -> population-unique on these QIs
K_HIGH_RISK_CEILING = 20.0         # k <= 20 -> small cohort, treat as high concern

# Medical tiering cut: a national crude prevalence at or above this is a COMMON (weak) QI;
# below it the condition is RARE (a strong QI). This only TIERS — it never enters the k.
_MEDICAL_COMMON_PREVALENCE = 0.05  # >= 5% national prevalence -> common / weak QI

# The reference YEAR a birth-year QI is aged against to price a DOB via the single-year-of-age
# table (`age = REFERENCE_YEAR - birth_year`). A FIXED module constant on PURPOSE — this engine
# is DETERMINISTIC and air-gapped, so it must NEVER read Date/now (a wall-clock would make the
# same document score differently on different days). It matches the data year of the bundled
# `sg-age-single-year.json` (2025); bump it in lock-step when that table is refreshed.
REFERENCE_YEAR = 2025


# ----------------------------------------------------- reference tables ------
# The bundled marginal tables live beside the app in data/reference/. Resolve relative to
# the repo root (this file is app/reidrisk.py, so ../data/reference).
_DEFAULT_REFERENCE_DIR = Path(__file__).resolve().parent.parent / "data" / "reference"

# Explicit residual/tail bucket keys the sourcing pipeline emits (a top-N table that already
# carries its own tail). When a table has one of these, its probs already sum to ~1.0 and we
# must NOT synthesise a second tail on top of it.
_TAIL_KEY_PREFIXES = ("__other", "__tail", "__rest")


@dataclass
class ReferenceTable:
    """One marginal QI frequency distribution loaded from a reference JSON.

    `probs` maps a NORMALISED key -> P(value). `tail_prob` is the residual probability mass
    NOT covered by `probs` (a value not in the table gets a CONSERVATIVE tail-derived
    probability, flagged `estimated_from_tail`). `has_explicit_tail` is True when the source
    already carried a `__other_*` bucket (so the tail is real, not synthesised)."""
    category: str
    jurisdiction: str | None
    population_N: int | None
    probs: dict                      # normalised key -> prob (float)
    tail_prob: float                 # residual mass for unseen values (>= 0)
    has_explicit_tail: bool
    n_entries: int
    source_name: str
    source_url: str
    license: str
    granularity_notes: str

    def lookup(self, key: str) -> tuple[float | None, bool]:
        """Return (prob, estimated_from_tail) for a NORMALISED `key`.

        A key present in `probs` returns its marginal P and `estimated_from_tail=False`.
        A key NOT present returns a CONSERVATIVE tail-derived probability and
        `estimated_from_tail=True` — conservative meaning it does NOT claim the value is
        rarer than the tail mass allows (a too-small P would UNDER-state k → over-state risk
        in the wrong, alarmist-but-unfounded way; a too-large P under-states risk which the
        honesty spine already flags). We use the whole residual tail mass as an upper bound
        on the value's probability, so an unseen value is never assigned a probability above
        the mass actually unaccounted-for. Returns (None, False) when the table is empty."""
        if key in self.probs:
            return self.probs[key], False
        if self.tail_prob > 0.0:
            return self.tail_prob, True
        if self.probs:
            # No residual mass but the table is non-empty: fall back to the smallest seen
            # marginal (the value is at least as rare as the rarest listed) — still an
            # estimate, flagged.
            return min(self.probs.values()), True
        return None, False


def _normalise_key(category: str, value: str) -> str:
    """Map a matched cleartext string to the reference table's key normal form.

    Surnames + given names are UPPERCASED to match the US Census surname file; sex is
    lowercased to male/female; everything else is whitespace-collapsed and kept in source
    casing (region / planning-area names are published title-cased). Deterministic."""
    v = re.sub(r"\s+", " ", str(value or "")).strip()
    if category in ("surname", "given_name"):
        return v.upper()
    if category == "sex":
        return v.lower()
    if category == "medical_condition":
        return v.lower()
    return v


def _term_tokens(term) -> list:
    """Normalised, punctuation-trimmed tokens of a link term. Whitespace-collapses, then
    strips leading/trailing non-word chars from each token so a supplied 'Smith,' or 'J.'
    still matches (Finding 3). Drops empties. Deterministic; preserves source casing (the
    caller case-folds where needed)."""
    norm = re.sub(r"\s+", " ", str(term or "")).strip()
    if not norm:
        return []
    out = []
    for tok in norm.split(" "):
        tok = re.sub(r"^\W+|\W+$", "", tok)
        if tok:
            out.append(tok)
    return out


def _term_containing_name(name, terms: tuple) -> str | None:
    """The FIRST supplied term (user order) of which `name` is an exact normalised TOKEN,
    else None.

    So a doc that resolves only the SURNAME TOKEN of a multi-token link_term ('Smith' from
    'John Smith') still joins THAT term's bucket — one person is never SPLIT across a
    `term:`/`name:` key pair (Finding 1). Without this, a doc whose surname a reference table
    resolves keys on `name:SMITH` while the doc carrying the full 'John Smith' keys on
    `term:JOHN SMITH`, so the same person fragments and release risk is UNDER-stated (the
    dangerous direction — and a regression vs the prior name-only linkage that shared
    `name:SMITH`)."""
    if not name:
        return None
    nm = _normalise_key("surname", name)
    if not nm:
        return None
    for t in terms:
        if nm in {_normalise_key("surname", tok) for tok in _term_tokens(t)}:
            return t
    return None


def _match_link_term(text, terms: tuple) -> str | None:
    """Return the FIRST user `link_term` (in supplied order) that appears in `text` as a
    whole, contiguous name, or None.

    Cross-doc linkage MUST key on a term being PRESENT IN THE DOCUMENT — not on whether a
    bundled name reference table happened to resolve it. SG ships NO surname table (the
    commercial source is excluded), so name-only linkage silently dropped every supplied
    party name and UNDER-stated release risk (the dangerous direction). Matching is
    DETERMINISTIC: word-boundary, case-insensitive, literal (re.escape → linear-time, no
    ReDoS); name tokens may be separated by whitespace OR common separators (', ' / '. ')
    so 'Tan, Wei Ming' / 'J. Smith' in the text still link (an under-link is the danger).
    The returned value is the ORIGINAL term (for display); the caller derives the stable link
    key via `_normalise_key`, so the same term links two docs."""
    if not terms:
        return None
    # Bound the scan EXACTLY like extract_qi_values (_bounded -> first _MAX_TEXT_BYTES):
    # an unbounded per-term scan over the 64 MB batch cap × 200 terms is a CPU-amplification
    # DoS (Finding 2), and linkage should see the same text extraction does. _bounded also
    # coerces non-str / drops lone surrogates so this never raises.
    s = _bounded(text)
    if not s:
        return None
    for t in terms:
        toks = _term_tokens(t)
        if not toks:
            continue
        pat = r"\b" + r"[\s,.]+".join(re.escape(tok) for tok in toks) + r"\b"
        try:
            if re.search(pat, s, re.IGNORECASE):
                return t
        except re.error:
            continue
    return None


def _coerce_int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def load_reference(dir: str | Path = _DEFAULT_REFERENCE_DIR) -> dict:
    """Load every reference JSON in `dir` into a {category: {jurisdiction: ReferenceTable}}
    map.

    A category (region, sex, ...) legitimately has a table PER JURISDICTION (SG region AND US
    region both exist), so the map is keyed by category THEN jurisdiction — a flat
    {category: table} would silently drop one jurisdiction (the SG planning-area table would
    be clobbered by the US state table). `select()` picks the right table by jurisdiction.

    PARTIAL-TABLE handling: a table's `entries` probs may not sum to 1.0. The residual
    `tail = max(0, 1 - Σ prob)` becomes the bucket for any value NOT listed (looked up via
    `ReferenceTable.lookup`, flagged `estimated_from_tail`). A `__other_*` residual row that
    the source already provides is treated as the EXPLICIT tail (we do NOT add a second one).

    NEVER crashes: a missing dir, a missing/partial/corrupt file, a row with null prob/count
    — each is skipped or tolerated, never raised. Probs are clamped to [0, 1]. A jurisdiction-
    less table is filed under the key '' (and `select` falls back to it). Returns {} on a
    missing dir; loading is deterministic (sorted by filename)."""
    out: dict = {}
    d = Path(dir)
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - a corrupt/locked table is skipped, never fatal
            continue
        if not isinstance(raw, dict):
            continue
        category = raw.get("category")
        if not isinstance(category, str) or not category:
            continue
        probs: dict = {}
        explicit_tail = 0.0
        has_explicit_tail = False
        entries = raw.get("entries")
        if not isinstance(entries, list):
            entries = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            key = e.get("key")
            if not isinstance(key, str) or not key:
                continue
            prob = e.get("prob")
            try:
                p = float(prob)
            except (TypeError, ValueError):
                # A null/absent prob (headline-only row) contributes nothing to the table —
                # it just means lower coverage. Skip the row; the residual tail covers it.
                continue
            if not math.isfinite(p) or p < 0.0:
                continue
            p = min(p, 1.0)
            low = key.lower()
            if any(low.startswith(pfx) for pfx in _TAIL_KEY_PREFIXES):
                # An explicit residual bucket: its mass IS the tail, not a real value.
                explicit_tail += p
                has_explicit_tail = True
                continue
            # ACCUMULATE (sum) when two raw keys normalise to the SAME key (e.g. "Tan" and
            # "TAN" both upper-case to "TAN"). A last-wins overwrite would DROP the duplicate's
            # mass → covered UNDER-counts → the synthesised tail is INFLATED → an unseen value
            # gets too much probability → it is judged rarer-than-it-is only by the tail being
            # bigger, which makes k LARGER → risk UNDER-stated (the dangerous direction). Summing
            # keeps `covered`/`tail` faithful to the source mass. Re-clamp the sum to [0, 1].
            nkey = _normalise_key(category, key)
            probs[nkey] = min(1.0, probs.get(nkey, 0.0) + p)
        covered = sum(probs.values())
        if has_explicit_tail:
            tail_prob = max(0.0, min(1.0, explicit_tail))
        else:
            tail_prob = max(0.0, 1.0 - covered)
        juris = raw.get("jurisdiction")
        jkey = juris if isinstance(juris, str) and juris else ""
        out.setdefault(category, {})[jkey] = ReferenceTable(
            category=category,
            jurisdiction=juris if isinstance(juris, str) and juris else None,
            population_N=_coerce_int(raw.get("population_N")),
            probs=probs,
            tail_prob=tail_prob,
            has_explicit_tail=has_explicit_tail,
            n_entries=len(probs),
            source_name=str(raw.get("source_name") or ""),
            source_url=str(raw.get("source_url") or ""),
            license=str(raw.get("license") or ""),
            granularity_notes=str(raw.get("granularity_notes") or ""),
        )
    return out


def select(reference: dict, category: str,
           jurisdiction: str | None = None) -> ReferenceTable | None:
    """Pick the ReferenceTable for `category` in `jurisdiction` from a `load_reference` map.

    Resolution order (deterministic): an exact jurisdiction match → a jurisdiction-less ('')
    table → if exactly one jurisdiction's table exists for the category, that one → else None
    (ambiguous: two jurisdictions and no hint, so we refuse to guess). Never raises."""
    if not isinstance(reference, dict):
        return None
    slot = reference.get(category)
    if not isinstance(slot, dict) or not slot:
        return None
    if jurisdiction and jurisdiction in slot:
        return slot[jurisdiction]
    if "" in slot:
        return slot[""]
    if len(slot) == 1:
        return next(iter(slot.values()))
    return None


def _tables_for(reference: dict, category: str) -> list:
    """Every ReferenceTable for `category`, across ALL jurisdictions (deterministic order:
    a jurisdiction-less '' table first, then jurisdictions sorted). Used to resolve a
    JURISDICTION-INDEPENDENT key (an SSOC occupation group, a medical-condition tier) against
    ANY table when no single table can be `select`ed — `select` returns None once two+
    jurisdictions exist, which would leave the QI unpriced/mis-tiered. Never raises."""
    slot = reference.get(category) if isinstance(reference, dict) else None
    if not isinstance(slot, dict) or not slot:
        return []
    out = []
    if "" in slot:
        out.append(slot[""])
    for jk in sorted(k for k in slot if k != ""):
        out.append(slot[jk])
    return out


def _occupation_tables(reference: dict) -> list:
    """All occupation tables (see `_tables_for`)."""
    return _tables_for(reference, "occupation")


def has_category(reference: dict, category: str, key: str,
                 jurisdiction: str | None = None) -> bool:
    """True if `key` is a LISTED value (not just tail-covered) in the category's table for
    `jurisdiction` (or, when jurisdiction is None, in ANY jurisdiction's table). Used by
    extraction to gate name/region matches against what the bundled data can actually price."""
    slot = reference.get(category) if isinstance(reference, dict) else None
    if not isinstance(slot, dict):
        return False
    if jurisdiction:
        t = slot.get(jurisdiction)
        return bool(t and key in t.probs)
    return any(key in t.probs for t in slot.values())


# ----------------------------------------------------- QI extraction ---------
# A detected & NORMALISED quasi-identifier VALUE (not just a category). `category` matches a
# reference-table category; `value` is the cleartext matched string (kept LOCAL); `key` is
# its reference-table normal form.
@dataclass
class QIValue:
    category: str          # surname | given_name | sex | region | age_band | occupation | medical_condition | dob
    value: str             # the matched cleartext (local only — never egressed/audited)
    key: str               # the reference-table normal form of `value`
    detail: str = ""       # optional human note (e.g. "year of birth 1981")


@dataclass
class EntityQIs:
    """The quasi-identifiers extracted for one entity (or one document, when no entity name
    is available — the document is treated as a single entity)."""
    name: str | None                     # an entity name if one anchored the QIs, else None
    qis: list = field(default_factory=list)        # list[QIValue]
    unmatched: list = field(default_factory=list)  # categories DETECTED but with no value to map

    def categories(self) -> set:
        return {q.category for q in self.qis}


# Sex detection — explicit mentions only (recall-first but precise; we never INFER sex from a
# name, which would be a correlated guess, not a QI). Word-boundary, case-insensitive.
_SEX_RE = re.compile(
    r"\b(?P<female>female|woman|women|she|her|hers|mrs|ms|miss|madam|daughter|wife|mother)\b"
    r"|\b(?P<male>male|man|men|he|him|his|mr|sir|son|husband|father)\b",
    re.IGNORECASE,
)

# A DOB / explicit date-of-birth phrase. We only treat a date as a DOB when it is anchored by
# a born/DOB cue — a bare year elsewhere is a weak signal handled by privilege's date regex,
# not a DOB. Bounded alternation, linear-time.
_DOB_RE = re.compile(
    r"\b(?:date of birth|d\.?o\.?b\.?|born(?:\s+on)?)\b[^\n]{0,40}?"
    r"\b((?:19|20)\d{2})\b",
    re.IGNORECASE,
)

# A surname/given-name token: a single Capitalised alphabetic word. We only HARVEST tokens
# that resolve against a reference name table (so random Capitalised words are ignored) — the
# detection is permissive, the MAPPING is what gates it. Bounded length to avoid pathological
# tokens.
_NAME_TOKEN_RE = re.compile(r"\b([A-Z][a-zA-Z'\-]{1,40})\b")

# Medical condition lexicon -> the snake_case reference key in sg-medical-prevalence.json.
# Detection is keyword-based (recall-first); mapping to the table key is explicit. Only
# conditions present in the table can be TIERED; an unknown condition is still surfaced as a
# detected-but-unmatched medical QI (so the lawyer sees it).
_MEDICAL_TERMS = {
    "hypertension": "hypertension",
    "high blood pressure": "hypertension",
    "hyperlipidaemia": "hyperlipidaemia_high_cholesterol",
    "hyperlipidemia": "hyperlipidaemia_high_cholesterol",
    "high cholesterol": "hyperlipidaemia_high_cholesterol",
    "diabetes": "diabetes_mellitus",
    "diabetes mellitus": "diabetes_mellitus",
    "obesity": "obesity_BMI_30plus",
    "obese": "obesity_BMI_30plus",
    # rare / strong-QI conditions: present so they're DETECTED + tiered rare (no table prob)
    "hiv": "__rare__",
    "haemophilia": "__rare__",
    "hemophilia": "__rare__",
    "leukaemia": "__rare__",
    "leukemia": "__rare__",
    "schizophrenia": "__rare__",
    "huntington": "__rare__",
    "cystic fibrosis": "__rare__",
    "sickle cell": "__rare__",
    "lupus": "__rare__",
    "als": "__rare__",
    "motor neurone": "__rare__",
    "multiple sclerosis": "__rare__",
    "parkinson": "__rare__",
    "cancer": "__rare__",
}
_MEDICAL_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(t) for t in sorted(_MEDICAL_TERMS, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)


def _bounded(text) -> str:
    """Coerce any input to a length-bounded str. Non-str / None -> ''. Never raises.

    Uses `errors='surrogatepass'` on the size-check encode so a str carrying a LONE
    SURROGATE (e.g. a `\\ud800` that survived a latin-1/surrogateescape decode upstream)
    does NOT raise `UnicodeEncodeError` here — a privacy tool must never crash on hostile
    text. The truncated tail is re-decoded with `'ignore'`, dropping any half/whole
    surrogate so the returned str is clean for the regex detectors."""
    if not isinstance(text, str):
        return ""
    try:
        encoded = text.encode("utf-8", "surrogatepass")
    except (UnicodeError, ValueError):
        # Defensive: even surrogatepass can't always round-trip pathological input —
        # fall back to a total, never-raising encode.
        encoded = text.encode("utf-8", "ignore")
    # Always round-trip through UTF-8 with 'ignore' so any LONE SURROGATE is dropped from
    # the working str — not just on the over-cap path. A surviving surrogate would survive
    # into a matched QI VALUE and then raise when the web layer json.dumps the result; this
    # tool must degrade, never crash. ASCII / valid UTF-8 round-trips byte-for-byte.
    if len(encoded) > _MAX_TEXT_BYTES:
        encoded = encoded[:_MAX_TEXT_BYTES]
    return encoded.decode("utf-8", "ignore")


def _dedup_qis(qis: list) -> list:
    """De-dup QIValues on (category, key), order-preserving — one value per (category, key)."""
    seen = set()
    out = []
    for q in qis:
        sig = (q.category, q.key)
        if sig not in seen:
            seen.add(sig)
            out.append(q)
    return out


# Map a privilege ROLE term to the SSOC broad-group the occupation table actually carries, by a
# TARGET KEYWORD we substring-match against the table's real (long) key strings (robust to the
# full published label, e.g. "managers & administrators (including working proprietors)"). Senior
# leadership / governance roles -> managers & administrators; professional / counsel / officer /
# head-of roles -> professionals. Every privilege role term is a white-collar SSOC group, so a
# detected role always lands in one of these two; the matched role text is kept as the value.
_SSOC_MANAGER_KW = "managers & administrators"
_SSOC_PROFESSIONAL_KW = "professionals"


def _role_to_ssoc_keyword(role: str) -> str:
    """Return the SSOC target KEYWORD a role term maps to (substring-resolved against the table
    keys by the caller). Deterministic, case-insensitive; defaults professional-ward for any
    other detected white-collar role term."""
    r = (role or "").lower()
    manager_cues = (
        "director", "chairman", "chairperson", "managing director", "president",
        "vice president", "partner",
        # C-suite chiefs (CEO/CFO/COO/CTO/CIO + their spelled-out forms) are leadership.
        "chief", "ceo", "cfo", "coo", "cto", "cio", "cro",
        "manager", "risk manager",
    )
    if any(cue in r for cue in manager_cues):
        return _SSOC_MANAGER_KW
    # counsel / officer / head of / professional and any other detected role -> professionals.
    return _SSOC_PROFESSIONAL_KW


def extract_qi_values(text, reference: dict | None = None) -> EntityQIs:
    """Detect + NORMALISE quasi-identifier VALUES in `text`, mapped to reference-table keys.

    Deterministic, bounded, never raises. Reuses app/privilege.py's compiled detectors
    (dates / roles / locations) for DETECTION, then maps matches to reference keys here:

      * region        — a privilege LOCATION/`based in` match whose key resolves against the
                        region table (else surfaced as detected-but-unmatched).
      * dob           — an explicit `born/DOB <year>` phrase -> a year-of-birth QI.
      * surname/given — a Capitalised token that resolves against a name reference table.
      * sex           — an explicit male/female mention (never INFERRED from a name).
      * occupation    — a privilege ROLE term, mapped to its SSOC broad group (managers &
                        administrators / professionals) resolved against the occupation table.
      * medical       — a condition keyword, mapped to the prevalence table key (for TIERING).

    Coverage is reported by `EntityQIs.qis` (matched, with a reference key) vs `.unmatched`
    (a category was DETECTED but no value could be mapped to a reference table — e.g. a name
    not in the bundled surname table, a region we don't have). `reference` is used to gate
    name/region matches against what we can actually price; passing None still extracts the
    self-evident QIs (dob/sex/occupation/medical) and surfaces names/regions as unmatched.
    """
    s = _bounded(text)
    if not s:
        return EntityQIs(name=None, qis=[], unmatched=[])
    ref = reference if isinstance(reference, dict) else {}

    qis: list = []
    unmatched: list = []

    # --- dob (explicit born/DOB year only) ---
    for m in _DOB_RE.finditer(s):
        year = m.group(1)
        # year-of-birth is the QI key; estimate_k prices it via the single-year-of-age table
        # (age = REFERENCE_YEAR - year). Detected always; priced only when that table exists.
        qis.append(QIValue(category="dob", value=year, key=year,
                           detail=f"year of birth {year}"))
        if len(qis) >= _MAX_QI_MATCHES:
            break

    # --- sex (explicit mentions only) ---
    msex = _SEX_RE.search(s)
    if msex:
        sex = "female" if msex.group("female") else "male"
        qis.append(QIValue(category="sex", value=sex, key=sex))

    # --- region (privilege LOCATION + based-in heuristic) ---
    region_seen = False
    loc_hits = [mm.group(0) for mm in _priv._LOCATION_RE.finditer(s)]
    loc_hits += [mm.group(1) for mm in _priv._BASED_RE.finditer(s)]
    for loc in loc_hits:
        key = _normalise_key("region", loc)
        if has_category(ref, "region", key):
            qis.append(QIValue(category="region", value=loc, key=key))
            region_seen = True
            break  # one region per entity (the most specific match wins by document order)
    if loc_hits and not region_seen:
        unmatched.append("region")

    # --- occupation (privilege ROLE -> coarse PMET / non-PMET bucket) ---
    role_hits = [mm.group(0) for mm in _priv._ROLE_RE.finditer(s)]
    if role_hits:
        # Map the first detected role to its SSOC broad group. We pick a TARGET KEYWORD
        # (managers & administrators / professionals) then resolve it by SUBSTRING against the
        # table's actual key strings (robust to the full published label). The matched role text
        # is the value. (The coarse PMET/non-PMET seed has been replaced by the 9-group SSOC
        # table — see data/reference/sg-occupation-full.json.)
        role = role_hits[0]
        target_kw = _role_to_ssoc_keyword(role)
        ssoc_key = None
        # Resolve the SSOC broad-group KEY against ANY occupation table — the SSOC group labels
        # are jurisdiction-INDEPENDENT, so a name/region-free document must still price
        # occupation even once a SECOND jurisdiction's occupation table exists (where
        # `select(ref,"occupation")` with no hint returns None as ambiguous → occupation would
        # otherwise go UNPRICED → k LARGER → risk UNDER-stated, the dangerous direction). The
        # per-jurisdiction PROB is still looked up jurisdiction-aware in estimate_k via
        # select(); here we only resolve the canonical key string.
        occ_tables = _occupation_tables(ref)
        for occ_table in occ_tables:
            # Exact key match first (so "professionals" is not captured by the longer
            # "associate professionals and technicians" if the table were re-ordered); fall
            # back to substring for a keyword that is only a fragment of the published label
            # (e.g. "managers & administrators").
            for k in occ_table.probs:
                if k.lower() == target_kw:
                    ssoc_key = k
                    break
            if ssoc_key is None:
                for k in occ_table.probs:
                    if target_kw in k.lower():
                        ssoc_key = k
                        break
            if ssoc_key is not None:
                break
        if ssoc_key is not None:
            qis.append(QIValue(category="occupation", value=role, key=ssoc_key,
                               detail=f"SSOC broad group: {ssoc_key}"))
        else:
            unmatched.append("occupation")

    # --- medical condition (TIERING only — never enters the k product) ---
    for mm in _MEDICAL_RE.finditer(s):
        term = mm.group(0).lower()
        mapped = _MEDICAL_TERMS.get(term)
        if mapped is None:
            continue
        if mapped == "__rare__":
            qis.append(QIValue(category="medical_condition", value=term, key=mapped,
                               detail="rare condition (strong quasi-identifier)"))
        else:
            qis.append(QIValue(category="medical_condition", value=term, key=mapped))
        break  # one condition QI is enough to tier; avoid double-counting in one entity

    # --- surname / given name (only tokens that resolve against a name reference table) ---
    have_surname = isinstance(ref.get("surname"), dict) and bool(ref.get("surname"))
    have_given = isinstance(ref.get("given_name"), dict) and bool(ref.get("given_name"))
    name_value = None
    if have_surname or have_given:
        n_name_matches = 0
        for mm in _NAME_TOKEN_RE.finditer(s):
            tok = mm.group(1)
            skey = _normalise_key("surname", tok)
            gkey = _normalise_key("given_name", tok)
            if have_surname and has_category(ref, "surname", skey):
                qis.append(QIValue(category="surname", value=tok, key=skey))
                name_value = name_value or tok
                n_name_matches += 1
            elif have_given and has_category(ref, "given_name", gkey):
                qis.append(QIValue(category="given_name", value=tok, key=gkey))
                name_value = name_value or tok
                n_name_matches += 1
            if n_name_matches >= 4 or len(qis) >= _MAX_QI_MATCHES:
                break

    qis = _dedup_qis(qis)
    # De-dup unmatched categories, keep only those NOT also matched.
    matched_cats = {q.category for q in qis}
    unmatched = [c for c in dict.fromkeys(unmatched) if c not in matched_cats]
    return EntityQIs(name=name_value, qis=qis, unmatched=unmatched)


# ----------------------------------------------------- k estimation ----------
@dataclass
class QIContribution:
    """One QI's contribution to the k estimate (for the coverage disclosure / UI)."""
    category: str
    value: str                 # cleartext (local only)
    prob: float | None         # marginal P(value), or None when not priced (e.g. medical/dob)
    estimated_from_tail: bool  # the prob came from the residual tail, not a listed value
    in_product: bool           # whether this QI multiplied into P(tuple)
    note: str = ""             # e.g. medical tier, or why it was excluded from the product


@dataclass
class ReidRiskEstimate:
    """A population-uniqueness k ESTIMATE for one entity. READ THE HONESTY FLAGS.

    `k_estimate` is `population_N · P(QI-tuple)` — an OPTIMISTIC LOWER BOUND on uniqueness
    (the independence assumption over-states k → under-states risk). `prosecutor_risk` =
    1/k (the worst case we LEAD with); `journalist_risk` is the cohort average. NONE of
    these is a safety verdict; there is no "safe" state — `concern` only ever rises."""
    k_estimate: float | None           # population_N · P(tuple); None when nothing priced
    p_tuple: float | None              # ∏ P(value) over priced QIs
    population_N: int | None           # the denominator used (the jurisdiction's population)
    jurisdiction: str | None
    prosecutor_risk: float | None      # 1 / k  (worst case — LEAD with this)
    journalist_risk: float | None      # cohort-average re-identification risk
    concern: str                       # "looks_unique" | "small_cohort" | "elevated" | "insufficient_data"
    contributions: list = field(default_factory=list)  # list[QIContribution]
    medical_tiers: list = field(default_factory=list)   # [{condition, tier, note}]
    matched_qi_count: int = 0
    detected_qi_count: int = 0
    coverage_note: str = ""
    # ---- the honesty spine (always present, always these values) ----
    is_estimate: bool = True
    assumes_independence: bool = True
    direction: str = "optimistic — may under-state risk"
    not_a_safety_verdict: bool = True
    caveat: str = (
        "k is an ESTIMATE under an independence assumption — an OPTIMISTIC lower bound on "
        "uniqueness that may UNDER-STATE risk because real quasi-identifiers are correlated. "
        "It can only RAISE concern; it is NOT a safety verdict and never means 'safe to send'."
    )

    def to_dict(self) -> dict:
        return asdict(self)


def _medical_tier(condition_key: str, reference: dict) -> tuple[str, str]:
    """TIER a medical condition common(weak QI) / rare(strong QI) from crude national
    prevalence. Returns (tier, note). A precise k is NEVER computed from this — common vs
    rare is the only output. A `__rare__`-mapped or table-absent condition is `rare`."""
    if condition_key == "__rare__":
        return "rare", ("rare condition — a STRONG quasi-identifier; a precise k is NOT "
                        "computed from crude national prevalence (it under-counts small-cell "
                        "uniqueness)")
    # The table's prob keys went through `_normalise_key` (which LOWERCASES a
    # medical_condition key), but `condition_key` here is the raw `_MEDICAL_TERMS` target value
    # (mixed case, e.g. `obesity_BMI_30plus`). Normalise the lookup the SAME way so a mixed-case
    # target resolves against the lowercased stored key — else obesity would mis-tier as "rare".
    norm_key = _normalise_key("medical_condition", condition_key)
    # Resolve the prevalence against ANY medical-condition table: a crude NATIONAL prevalence
    # for a COMMON condition is jurisdiction-independent enough to TIER common/rare. `select`
    # returns None once a SECOND jurisdiction's medical table exists (ambiguous, no hint), which
    # would mis-tier EVERY condition as "rare" (the table-absent fallback) — overstating concern
    # but, more importantly, breaking the deliberate common(weak)/rare(strong) split. We look up
    # the FIRST table that lists this condition. (Tiering only — this never enters the k.)
    p = None
    for med in _tables_for(reference, "medical_condition"):
        if norm_key in med.probs:
            p = med.probs[norm_key]
            break
    if p is not None:
        if p >= _MEDICAL_COMMON_PREVALENCE:
            return "common", (f"common condition (~{p:.0%} national prevalence) — a WEAK "
                              "quasi-identifier; excluded from the k product")
        return "rare", (f"lower-prevalence condition (~{p:.1%}) — a STRONGER quasi-identifier; "
                        "not folded into the precise k (crude national prevalence under-counts "
                        "small-cell uniqueness)")
    return "rare", ("condition not in the national prevalence table — treated as a STRONG "
                    "quasi-identifier for review; no precise k from crude prevalence")


def _price_dob(year_key: str, reference: dict,
               jurisdiction: str | None) -> tuple[float | None, int | None, str | None, bool, str]:
    """Price a birth-year QI via the single-year-of-age table (`age_years`).

    Returns (prob, age, age_key, estimated_from_tail, note). `age = REFERENCE_YEAR - year`; the
    age key is `str(age)`, or the table's OPEN TOP bucket (`"<n>+"`) when age exceeds the max
    listed single year. Edge cases — a non-numeric key, a year > REFERENCE_YEAR (age < 0), or an
    absurd age (> 130) — return (None, …) so the QI is SURFACED unpriced, never priced, never a
    crash. Deterministic. HONEST: this prices the YEAR-OF-BIRTH cohort, not an exact DOB."""
    try:
        year = int(year_key)
    except (TypeError, ValueError):
        return None, None, None, False, "DOB year not numeric — surfaced but not priced"
    age = REFERENCE_YEAR - year
    if age < 0:
        return (None, age, None, False,
                f"birth year {year} is after the reference year {REFERENCE_YEAR} (age {age}) — "
                "surfaced but not priced (no reference cohort)")
    if age > 130:
        return (None, age, None, False,
                f"implied age {age} is implausible — surfaced but not priced")
    table = select(reference, "age_years", jurisdiction)
    if table is None:
        return None, age, None, False, "no single-year-of-age table available (DROP-IN)"
    # The table lists single years 0..max plus an OPEN TOP bucket keyed "<n>+". Find that bucket
    # and the largest listed EXPLICIT single year so an over-max age maps to the open bucket, not
    # the tail. NOTE: `max_single` tracks the largest listed single-year KEY ONLY — the top
    # bucket's stem is NOT folded into it (else an age above the max explicit single year but
    # below the bucket stem would be tail-priced instead of routed to the open bucket — #5).
    # A malformed top key with a non-positive-int stem (a bare "+" → stem "", or "x+") is
    # IGNORED: treated as no top bucket, so it can't swallow every age via int("" or 0)=0 (#7).
    top_bucket = None
    top_stem = None
    max_single = -1
    for k in table.probs:
        if k.endswith("+"):
            stem = k[:-1]
            stem_n = int(stem) if stem.isdigit() else None
            if stem_n is not None and stem_n > 0:
                top_bucket = k
                top_stem = stem_n
        elif k.isdigit():
            max_single = max(max_single, int(k))
    if str(age) in table.probs:
        age_key = str(age)
    elif top_bucket is not None and (age >= top_stem or age > max_single):
        age_key = top_bucket
    else:
        age_key = str(age)
    prob, from_tail = table.lookup(age_key)
    if prob is None or prob <= 0.0:
        return None, age, age_key, from_tail, "age not priced (no usable marginal)"
    return prob, age, age_key, from_tail, ""


def _pick_population_N(jurisdiction: str | None, reference: dict) -> int | None:
    """The population denominator N for `k = N · P(tuple)`. Prefer a jurisdiction-matched
    sex/region table's population_N (the broadest real denominator); fall back to any table
    that carries one. Deterministic."""
    # Prefer sex then region then age tables (these carry the broadest population_N).
    order = ("sex", "region", "age_years", "age_band", "occupation")
    cands = []
    for cat in order:
        t = select(reference, cat, jurisdiction)
        if t and t.population_N:
            if jurisdiction is None or t.jurisdiction is None or t.jurisdiction == jurisdiction:
                cands.append(t.population_N)
    if cands:
        # Use the LARGEST matched population_N as the denominator — a larger N gives a larger
        # (more optimistic) k, which is the consistent, non-alarmist side; the honesty spine
        # already flags that k is an optimistic bound.
        return max(cands)
    return None


def _infer_jurisdiction(entity_qis: EntityQIs, reference: dict) -> str | None:
    """Infer the jurisdiction from which reference table a matched QI key came from. A region
    or surname key that exists only in an SG (resp. US) table implies that jurisdiction. None
    when ambiguous/undeterminable — the caller may pass one explicitly."""
    votes: dict = {}
    for q in entity_qis.qis:
        slot = reference.get(q.category)
        if not isinstance(slot, dict):
            continue
        for juris, t in slot.items():
            if juris and q.key in t.probs:
                votes[juris] = votes.get(juris, 0) + 1
    if not votes:
        return None
    # Deterministic: highest vote, ties broken alphabetically.
    return sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def estimate_k(entity_qis: EntityQIs, reference: dict,
               jurisdiction: str | None = None) -> ReidRiskEstimate:
    """Estimate the population-uniqueness k for one entity's QIs.

    P(tuple) = ∏ P(value) over the QIs we can PRICE (independence assumption). k = N · P(tuple).
    Medical conditions are TIERED (common/rare), never priced into the product. DOB is priced
    via the single-year-of-age table (`age = REFERENCE_YEAR - birth_year`) — the BIRTH-YEAR
    COHORT, not an exact day-of-birth (only the year is known); a future/absurd year is surfaced
    unpriced. prosecutor_risk = 1/k (LEAD), journalist_risk = average over the
    cohort (≈ k records share the tuple, so the average per-record re-id prob is 1/k as well —
    we report it for completeness; in this marginal model the two coincide, which we state
    honestly rather than invent a spurious spread).

    Deterministic, never raises. The honesty flags are ALWAYS set (see `ReidRiskEstimate`)."""
    if not isinstance(reference, dict):
        reference = {}
    juris = jurisdiction or _infer_jurisdiction(entity_qis, reference)
    # The population denominator N is pure in (juris, reference) — compute it ONCE here so the
    # region caveat (#22) can compare a region table's own population_N against the chosen N,
    # and reuse it as the k denominator below (no behaviour change — same value either way).
    population_N = _pick_population_N(juris, reference)

    contributions: list = []
    medical_tiers: list = []
    p_tuple = 1.0
    priced = 0

    for q in entity_qis.qis:
        if q.category == "medical_condition":
            tier, note = _medical_tier(q.key, reference)
            medical_tiers.append({"condition": q.value, "tier": tier, "note": note})
            contributions.append(QIContribution(
                category=q.category, value=q.value, prob=None, estimated_from_tail=False,
                in_product=False, note=f"medical: {tier} — {note}"))
            continue
        if q.category == "dob":
            # A DOB QI carries a 4-digit BIRTH YEAR; price the BIRTH-YEAR COHORT via the
            # single-year-of-age table (`age = REFERENCE_YEAR - year`). HONEST: this is the
            # COHORT for that year of birth, NOT an exact day-of-birth — only the year is known,
            # and we do NOT fabricate a 1/365.25 day factor we have no data for. A nonsense year
            # (future / absurd age) is SURFACED unpriced, never priced, never a crash.
            prob, age, age_key, from_tail, why = _price_dob(q.key, reference, juris)
            if prob is None or prob <= 0.0:
                contributions.append(QIContribution(
                    category=q.category, value=q.value, prob=prob, estimated_from_tail=bool(from_tail),
                    in_product=False, note=why))
                continue
            p_tuple *= prob
            priced += 1
            contributions.append(QIContribution(
                category=q.category, value=q.value, prob=prob, estimated_from_tail=from_tail,
                in_product=True,
                note=(f"prices the BIRTH-YEAR COHORT (born {q.key}, age {age_key} in "
                      f"{REFERENCE_YEAR}), NOT an exact day-of-birth — only the year is known "
                      f"(no 1/365.25 day factor is invented)"
                      + ("; " + why if why else ""))))
            continue
        table = select(reference, q.category, juris)
        if table is None:
            # Detected but no reference table to price it (e.g. dob without an age table).
            contributions.append(QIContribution(
                category=q.category, value=q.value, prob=None, estimated_from_tail=False,
                in_product=False,
                note="no reference table available — surfaced but not priced (DROP-IN)"))
            continue
        prob, from_tail = table.lookup(q.key)
        if prob is None or prob <= 0.0:
            contributions.append(QIContribution(
                category=q.category, value=q.value, prob=prob, estimated_from_tail=from_tail,
                in_product=False, note="unpriced (no usable marginal)"))
            continue
        note = ("probability estimated from the residual tail (value not individually listed)"
                if from_tail else "")
        # CROSS-JURISDICTION caveat (#9): when the only table that priced this QI belongs to a
        # DIFFERENT jurisdiction than the one resolved for this entity (e.g. a surname found
        # only in the US Census table while the doc is SG), the marginal P is from the wrong
        # population. A name's frequency varies sharply by jurisdiction, so a foreign-table P
        # can be far OFF — and if it is LARGER than the true local frequency it OVER-states k /
        # UNDER-states risk (the dangerous direction). This is an ADDITIVE disclosure only: the
        # k math is unchanged (we still price against the best table we have, never fabricate a
        # local one) — the user is just told the pricing crossed jurisdictions so they don't
        # over-trust it. (No fallback is suppressed; suppressing it would silently DROP the QI
        # from the product → an even larger k → worse under-statement.)
        if (table.jurisdiction and juris and table.jurisdiction != juris):
            xj_note = (f"priced against {table.jurisdiction} reference data, but this entity "
                       f"reads as {juris} — a cross-jurisdiction marginal may MIS-state the "
                       "true local frequency (and if higher, UNDER-states risk)")
            note = (note + "; " + xj_note) if note else xj_note
        if q.category == "occupation":
            occ_note = ("occupation P is conditional on the EMPLOYED population; folding it "
                        "against the total-population denominator is OPTIMISTIC (over-states k / "
                        "under-states risk)")
            note = (note + "; " + occ_note) if note else occ_note
        elif q.category == "region":
            # Surface the region table's granularity to the USER (not just SOURCES.md): a
            # "based in / lives in" phrase is matched against whatever distribution the table
            # actually is — e.g. a WORKPLACE planning-area distribution, whose shares differ
            # materially from residence — so the priced P(region) carries that caveat.
            if table.granularity_notes:
                gn = table.granularity_notes.strip()
                reg_note = ("region priced against the source distribution — "
                            + (gn if len(gn) <= 170 else gn[:170].rstrip() + "…"))
                note = (note + "; " + reg_note) if note else reg_note
            # CONDITIONAL-POPULATION caveat (#22), mirroring the occupation OPTIMISTIC note:
            # when the region marginal comes from a table whose OWN population_N is SMALLER
            # than the denominator N used for k (e.g. a sub-population / employed / age-banded
            # base vs the total-population N), P(region) is conditional on that smaller base.
            # Folding such a conditional share against the larger total-population denominator
            # OVER-states k / UNDER-states risk (the dangerous direction). ADDITIVE note only —
            # the k math is unchanged (the largest matched N stays the consistent, flagged
            # optimistic denominator); the user is simply told the region P is conditional.
            if (table.population_N and population_N
                    and table.population_N < population_N):
                pop_note = ("region P is conditional on a smaller base population "
                            f"(~{table.population_N:,}) than the k denominator "
                            f"(~{population_N:,}); folding it against the larger denominator is "
                            "OPTIMISTIC (over-states k / under-states risk)")
                note = (note + "; " + pop_note) if note else pop_note
        p_tuple *= prob
        priced += 1
        contributions.append(QIContribution(
            category=q.category, value=q.value, prob=prob, estimated_from_tail=from_tail,
            in_product=True, note=note))

    detected = len(entity_qis.qis)
    # population_N was computed once above (pure in juris+reference) and reused here.

    if priced == 0 or population_N is None:
        # Nothing we can price into a real k. We do NOT invent one. (This is NOT a "safe"
        # result — it is INSUFFICIENT DATA; concern is simply undeterminable here.)
        k = None
        p = None
        prosecutor = None
        journalist = None
        concern = "insufficient_data"
    else:
        p = p_tuple
        k = population_N * p
        # Cap to a valid probability [0,1]: when k <= 1 (population-unique on these QIs) the
        # re-identification probability is effectively certain (1.0); 1/k would exceed 1.0, which
        # is not a probability. Latent with the coarse tables (k<1 unreachable) but LIVE once the
        # finer DROP-IN tables make the looks_unique band reachable.
        prosecutor = min(1.0, 1.0 / k) if k > 0 else 1.0
        journalist = prosecutor  # marginal model: cohort-average coincides with 1/k (post-cap)
        if k <= K_UNIQUE_CEILING:
            concern = "looks_unique"
        elif k <= K_HIGH_RISK_CEILING:
            concern = "small_cohort"
        else:
            concern = "elevated"

    matched = sum(1 for c in contributions if c.in_product)
    # The "matched N of M" coverage DENOMINATOR counts only PRICEABLE QIs — medical conditions
    # are DELIBERATELY tiered-only (never priced into k by design), so including them in the
    # denominator would misrepresent the intentional medical exclusion as a coverage GAP
    # ("matched 0 of 1" when the 1 is a medical condition that was correctly tiered). Medical
    # conditions are still reported SEPARATELY in the note ("N medical condition(s) TIERED only")
    # so nothing is hidden — they just don't deflate the priced-coverage ratio (#13).
    priceable_detected = sum(1 for q in entity_qis.qis if q.category != "medical_condition")
    coverage_note = _coverage_note(matched, priceable_detected, entity_qis.unmatched, medical_tiers)

    return ReidRiskEstimate(
        k_estimate=k, p_tuple=p, population_N=population_N, jurisdiction=juris,
        prosecutor_risk=prosecutor, journalist_risk=journalist, concern=concern,
        contributions=contributions, medical_tiers=medical_tiers,
        matched_qi_count=matched, detected_qi_count=detected,
        coverage_note=coverage_note,
    )


def _coverage_note(matched: int, detected: int, unmatched: list, medical_tiers: list) -> str:
    """A plain-English coverage disclosure: how many QIs were priced vs detected, and what
    was detected-but-unpriced (so a sparse k is never over-read as low risk)."""
    parts = [f"matched {matched} of {detected} detected quasi-identifier(s) against reference data"]
    if unmatched:
        parts.append("not in reference data: " + ", ".join(sorted(set(unmatched))))
    if medical_tiers:
        parts.append(f"{len(medical_tiers)} medical condition(s) TIERED only (never priced into k)")
    if matched == 0:
        parts.append("no QI could be priced — this is INSUFFICIENT DATA, not a low-risk finding")
    return "; ".join(parts)


# ----------------------------------------------- cross-doc batch linkage -----
class EntityStore(Protocol):
    """The cross-document entity register seam.

    `assess_release` accumulates per-entity QI profiles through this protocol so a future
    persistent register can drop in WITHOUT changing the linkage logic. The ONLY shipped
    implementation is `InMemoryEntityStore` (no disk, no persistence).

    # TODO(optional): persist to the per-matter app-data DB (storage:own pattern); hashed
    # keys + counts, never cleartext, never beside the source. NOT wired — the skeleton only.
    """

    def link_key(self, entity: EntityQIs, link_terms: tuple) -> str | None:  # pragma: no cover
        """Return the EXACT shared key this entity links on (a normalised name, a supplied
        link_term, or an exact shared identifier), or None if it has no linkable key."""
        ...

    def add(self, key: str, entity: EntityQIs, doc_id: str) -> None:  # pragma: no cover
        """Merge `entity`'s QIs into the register bucket for `key`."""
        ...

    def buckets(self) -> dict:  # pragma: no cover
        """Return {link_key: merged EntityQIs} for every linked entity."""
        ...


@dataclass
class _Bucket:
    key: str
    qis: list = field(default_factory=list)   # merged list[QIValue]
    doc_ids: list = field(default_factory=list)
    names: list = field(default_factory=list)


class InMemoryEntityStore:
    """In-memory cross-doc entity register. NO persistence — buckets live only for the call.

    Linkage is DETERMINISTIC EXACT-KEY only: a user-supplied `link_term` found in the doc, OR
    an entity's exact normalised name. It NEVER does fuzzy / role coreference (that needs a
    model we don't have and won't add). Because exact-key linkage UNDER-links (it misses
    references that don't share an exact key), the release k it yields is itself OPTIMISTIC."""

    def __init__(self):
        self._buckets: dict = {}

    def link_key(self, entity: EntityQIs, link_terms: tuple) -> str | None:
        # 1) an explicit user link_term present as the entity name (exact, normalised).
        nm = _normalise_key("surname", entity.name) if entity.name else None
        for t in link_terms:
            tk = _normalise_key("surname", t)
            if tk and nm and tk == nm:
                return "term:" + tk
        # 2) the entity's own exact normalised name.
        if nm:
            return "name:" + nm
        return None

    def add(self, key: str, entity: EntityQIs, doc_id: str) -> None:
        b = self._buckets.get(key)
        if b is None:
            b = _Bucket(key=key)
            self._buckets[key] = b
        b.qis = _dedup_qis(b.qis + list(entity.qis))
        if doc_id not in b.doc_ids:
            b.doc_ids.append(doc_id)
        if entity.name and entity.name not in b.names:
            b.names.append(entity.name)

    def buckets(self) -> dict:
        out = {}
        for k, b in self._buckets.items():
            out[k] = (_Bucket(key=k, qis=list(b.qis), doc_ids=list(b.doc_ids),
                              names=list(b.names)))
        return out


@dataclass
class LinkedEntityRelease:
    """One linked entity's release-level estimate over the UNION of its QIs across docs."""
    link_key: str
    name: str | None
    doc_ids: list
    estimate: ReidRiskEstimate

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class ReleaseRiskReport:
    """The cross-doc batch report. Linked entities carry their UNION-of-QIs release k.

    HONESTY (always present): linkage FOUND is real; ABSENCE of linkage is NOT proof the docs
    are independent. Linkage is deterministic exact-key only — it UNDER-links, so the release
    k is itself OPTIMISTIC. Same honesty spine as the single-doc estimate."""
    linked_entities: list = field(default_factory=list)   # list[LinkedEntityRelease]
    n_docs: int = 0
    n_linked_entities: int = 0
    is_estimate: bool = True
    assumes_independence: bool = True
    direction: str = "optimistic — may under-state risk"
    not_a_safety_verdict: bool = True
    linkage_caveat: str = (
        "Linkage FOUND is real; ABSENCE of linkage is NOT proof the documents are "
        "independent. Linkage is deterministic EXACT-KEY only (a supplied term or an exact "
        "shared name) — it UNDER-links, so the release k is itself OPTIMISTIC. No fuzzy / "
        "role coreference is performed (that needs a model this tool does not use)."
    )

    def to_dict(self) -> dict:
        return asdict(self)


def assess_release(docs, link_terms=(), reference: dict | None = None,
                   store: EntityStore | None = None) -> ReleaseRiskReport:
    """Assess a SELECTED set of documents for cross-doc re-identification risk.

    `docs` is an iterable of doc texts OR (doc_id, text) pairs. For each doc we extract one
    entity's QIs, then LINK across docs ONLY on an explicit shared key (a `link_term` or an
    exact normalised name — NEVER fuzzy). Each linked entity's release k is computed on the
    UNION of its QIs across the docs it appears in (adding QIs can only LOWER k / RAISE risk).

    Accumulation is IN MEMORY (`InMemoryEntityStore`) — no persistence. Deterministic,
    bounded (`_MAX_BATCH_DOCS`, `_MAX_LINK_TERMS`), never raises. The honesty spine + the
    linkage caveat are always present."""
    ref = load_reference() if reference is None else reference
    if not isinstance(ref, dict):
        ref = {}
    st = store if store is not None else InMemoryEntityStore()
    terms = tuple(str(t) for t in (link_terms or ()) if isinstance(t, str) and t.strip())[:_MAX_LINK_TERMS]

    n_docs = 0
    for i, doc in enumerate(docs or []):
        if i >= _MAX_BATCH_DOCS:
            break
        if isinstance(doc, (tuple, list)) and len(doc) == 2:
            doc_id, text = str(doc[0]), doc[1]
        else:
            doc_id, text = f"doc-{i + 1}", doc
        # Per-doc isolation (defense-in-depth): extract_qi_values is documented to never
        # raise, but a hostile/odd single doc must NEVER abort the WHOLE batch — a privacy
        # tool degrading to "I couldn't assess any of your 200 docs" because one was bad is
        # the wrong failure mode. On any error, treat that doc as yielding NO QIs (an empty
        # entity is registered so the doc is still counted) and carry on.
        try:
            entity = extract_qi_values(text, ref)
        except Exception:  # noqa: BLE001 - one bad doc must not abort the batch
            entity = EntityQIs(name=None, qis=[], unmatched=[])
        n_docs += 1
        # LINKAGE — the dangerous direction to get wrong (a MISS UNDER-states release risk).
        # Link on a user `link_term` PRESENT IN THIS DOC'S TEXT, independent of whether a name
        # reference table resolved entity.name. This is the reliable SG path (no surname
        # table); the prior name-only key silently dropped every supplied term there. One
        # entity per doc, so a doc with several terms links on the FIRST (user order) —
        # deterministic; multi-term-per-doc remains a documented limitation.
        matched_term = _match_link_term(text, terms)
        if matched_term is None and entity.name:
            # The full term isn't in THIS doc, but the doc resolved a surname/given token that
            # IS a token of a supplied term (e.g. 'Smith' from 'John Smith'). Route it to that
            # term's bucket so one person is never split term:/name: (Finding 1).
            matched_term = _term_containing_name(entity.name, terms)
        if matched_term is not None:
            # Give a term-linked bucket a display name even when no reference table resolved
            # one (#11): the user's own term is the right label.
            if not entity.name:
                entity.name = matched_term
            key = "term:" + _normalise_key("surname", matched_term)
        else:
            key = st.link_key(entity, terms)
        if key is None:
            # No linkable key: this entity stands alone. We still register it under a unique
            # per-doc key so it gets a release estimate (its single doc IS its union). Two
            # un-linkable entities NEVER merge — the loop index i guarantees a distinct key even
            # when the user-supplied doc_id is duplicated (two uploads both named "Memo").
            key = f"unlinked:{i}:{doc_id}"
        st.add(key, entity, doc_id)

    linked: list = []
    for key, bucket in sorted(st.buckets().items()):
        merged = EntityQIs(
            name=(bucket.names[0] if bucket.names else None),
            qis=list(bucket.qis), unmatched=[])
        est = estimate_k(merged, ref)
        linked.append(LinkedEntityRelease(
            link_key=key, name=merged.name, doc_ids=list(bucket.doc_ids), estimate=est))

    return ReleaseRiskReport(
        linked_entities=linked, n_docs=n_docs, n_linked_entities=len(linked))


# ----------------------------------------------------- web-facing API --------
# A module-level cached reference map so the web layer doesn't reload 9 JSONs per request.
_REFERENCE_CACHE: dict | None = None


def get_reference() -> dict:
    """Lazily load + cache the bundled reference tables. Never raises.

    ONLY a NON-EMPTY successful load is cached; an empty result or an exception is NOT cached
    (it would poison the process for its whole lifetime — every k-estimate then runs against an
    empty map = a permanent INSUFFICIENT-DATA degradation, the wrong direction for a privacy
    tool). A transient failure (a slow disk, a locked file mid-write) therefore RETRIES on the
    next call instead of latching empty. Returns the freshly-loaded (possibly empty) map either
    way — never raises."""
    global _REFERENCE_CACHE
    if _REFERENCE_CACHE:
        return _REFERENCE_CACHE
    try:
        loaded = load_reference()
    except Exception:  # noqa: BLE001 - a load failure degrades to an empty (insufficient) map
        loaded = {}
    if loaded:
        # Cache only a real, non-empty load; leave the cache unset on empty/failure so the
        # NEXT call retries rather than serving a poisoned empty map forever.
        _REFERENCE_CACHE = loaded
    return loaded


def score_text(text, jurisdiction: str | None = None) -> dict:
    """Single-document entry point for the web layer: extract QIs -> estimate k. Returns a
    JSON-ready dict (the ReidRiskEstimate plus the detected QI categories, NO unnecessary
    cleartext beyond the matched values the local reviewer already sees). Never raises."""
    ref = get_reference()
    entity = extract_qi_values(text, ref)
    est = estimate_k(entity, ref, jurisdiction)
    d = est.to_dict()
    d["entity_name"] = entity.name
    d["detected_categories"] = sorted(entity.categories())
    d["unmatched_categories"] = sorted(set(entity.unmatched))
    return d


def assess_release_dict(docs, link_terms=(), jurisdiction: str | None = None) -> dict:
    """Batch entry point for the web layer. Returns a JSON-ready ReleaseRiskReport dict.
    `jurisdiction` is accepted for symmetry but inferred per linked entity. Never raises."""
    ref = get_reference()
    report = assess_release(docs, link_terms=link_terms, reference=ref)
    return report.to_dict()
