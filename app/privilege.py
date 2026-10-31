"""
Confidentiality / Privilege review — a DETERMINISTIC passage flagger.

This is the human-in-the-loop answer to contextual re-identification: per-identifier
redaction (the redaction engine) removes *named* identifiers (emails, IDs, card numbers),
but it cannot solve CONTEXTUAL re-identification — a paragraph that names no person yet
describes a unique career path, a unique deal, or a unique role still re-identifies its
subject. No string-matcher can "fix" that; only a human can judge it. So this module does
NOT redact or delete anything — it SURFACES likely-sensitive PASSAGES (paragraphs) so the
reviewing lawyer reads them and decides.

NON-NEGOTIABLES (mirrors the rest of the app):
  * LOCAL-ONLY / no network, no model, no LLM. Pure rule-based detection.
  * DETERMINISTIC: the same text always yields the same flags (no RNG, no ordering drift).
  * LINEAR-TIME: every regex is anchored/character-class based (no catastrophic
    backtracking); work is bounded on huge inputs (paragraph count + per-paragraph length
    are capped) so a hostile document can't wedge a request.
  * It NEVER auto-redacts. The returned passages are a READ-AND-DECIDE surface only.

HONEST FRAMING: flagging a passage does NOT make the document "safe to send" and does NOT
anonymize anything. It complements — never replaces — the lawyer's own review.

flag_passages(text) -> list[FlaggedPassage]:
  each carries BYTE offsets of the paragraph (char-boundary safe), a category
  (privilege / confidentiality / re_identification), a short human `reason` built from
  COUNTS / matched keywords, a severity (high / medium), and the matched-keyword list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict


# ----------------------------------------------------------------- bounds ----
# A real review document is paragraphs of prose, not millions of lines. Bound the work so
# a hostile / pathological input can never make this super-linear or unbounded: cap how
# many paragraphs we scan, and how many bytes of any one paragraph we look at. These are
# generous for any genuine legal document.
_MAX_PARAGRAPHS = 20_000
_MAX_PARAGRAPH_BYTES = 200_000


# ------------------------------------------------------------- categories ----
CATEGORY_PRIVILEGE = "privilege"
CATEGORY_CONFIDENTIALITY = "confidentiality"
CATEGORY_REIDENTIFICATION = "re_identification"

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"


# --------------------------------------------------------------- lexicons ----
# Privilege markers — a paragraph containing one is flagged `privilege`. Multi-word phrases
# are matched as phrases (internal whitespace flexible); single words match on a word
# boundary. Case-insensitive throughout. SG + general legal practice.
_PRIVILEGE_TERMS = (
    "without prejudice",
    "subject to contract",
    "legally privileged",
    "legal advice privilege",
    "litigation privilege",
    "attorney-client",
    "attorney client",
    "solicitor-client",
    "solicitor client",
    "privileged",
    "in camera",
    "off the record",
)

# Confidentiality + sensitive-content markers — a paragraph containing one is flagged
# `confidentiality`.
_CONFIDENTIALITY_TERMS = (
    "private and confidential",
    "strictly confidential",
    "not for distribution",
    "internal use only",
    "confidential",
    "board minutes",
    "settlement",
    "draft",
    # sensitive personal content
    "medical",
    "diagnosis",
    "salary",
    "remuneration",
)


def _phrase_pattern(terms) -> re.Pattern:
    """Compile a case-insensitive, word-boundary alternation over `terms`.

    Internal runs of whitespace in a phrase are matched flexibly (one-or-more whitespace)
    so 'without   prejudice' across a line wrap still matches. Each alternative is wrapped
    in \\b...\\b so 'draft' does not fire inside 'draughtsman' and 'confidential' is matched
    as a word. Longer phrases are placed first so the alternation prefers the most specific
    match. Linear-time: a fixed alternation of literals, no nested quantifiers."""
    alts = []
    for t in sorted(terms, key=len, reverse=True):
        # Split on whitespace, escape each token, rejoin with a flexible-whitespace gap.
        toks = [re.escape(tok) for tok in t.split()]
        body = r"\s+".join(toks)
        alts.append(r"\b" + body + r"\b")
    return re.compile("(?:" + "|".join(alts) + ")", re.IGNORECASE)


_PRIVILEGE_RE = _phrase_pattern(_PRIVILEGE_TERMS)
_CONFIDENTIALITY_RE = _phrase_pattern(_CONFIDENTIALITY_TERMS)


# ------------------------------------------- re-identification signal sets ----
# Quasi-identifier density: a paragraph that names no person can still re-identify by the
# CONVERGENCE of several quasi-identifiers (years + roles + locations + organisations). We
# count DISTINCT signal categories and the total signal count; a high convergence is flagged
# `re_identification` for the lawyer to judge.

# Years (1900-2099) and a couple of common date forms. Anchored to a 4-digit year so this
# never backtracks.
_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
# Common written date forms ("12 January 2007", "January 2007", "12/03/2019"). Bounded
# alternation, no nested quantifiers.
_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|"
    "November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
)
_DATE_RE = re.compile(
    r"\b(?:\d{1,2}\s+)?(?:" + _MONTHS + r")\b|\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    re.IGNORECASE,
)

# Role / title terms. Multi-word handled as phrases. These are the "what they did" signals
# that, combined with dates + places, narrow an identity.
_ROLE_TERMS = (
    "chief risk officer",
    "chief executive officer",
    "chief financial officer",
    "chief operating officer",
    "risk officer",
    "risk manager",
    "head of",
    "managing director",
    "vice president",
    "chief",
    "officer",
    "director",
    "manager",
    "president",
    "partner",
    "counsel",
    "chairman",
    "chairperson",
    "ceo",
    "cfo",
    "cro",
    "coo",
    "cto",
    "cio",
)
_ROLE_RE = _phrase_pattern(_ROLE_TERMS)

# Locations — a curated set of common countries + major financial-centre cities. Word-
# boundary, matched case-insensitively (a place name in prose is normally capitalised; we
# accept either to be recall-first here, since locations only COUNT toward density — they
# are never redacted).
_LOCATION_TERMS = (
    "United Kingdom", "United States", "Hong Kong", "South Africa", "New Zealand",
    "Saudi Arabia", "United Arab Emirates", "South Korea", "Sri Lanka",
    "Singapore", "Malaysia", "Indonesia", "Thailand", "Vietnam", "Philippines",
    "India", "China", "Japan", "Australia", "Canada", "Brazil", "Mexico",
    "Germany", "France", "Italy", "Spain", "Portugal", "Netherlands", "Belgium",
    "Switzerland", "Luxembourg", "Ireland", "Sweden", "Norway", "Denmark",
    "Finland", "Poland", "Austria", "Greece", "Turkey", "Russia", "Israel",
    "Egypt", "Nigeria", "Kenya", "Argentina", "Chile", "Colombia", "Taiwan",
    "Pakistan", "Bangladesh", "Qatar", "Kuwait", "Bahrain", "Oman",
    "USA", "UK", "UAE", "EMEA", "APAC",
    "London", "New York", "Tokyo", "Shanghai", "Beijing", "Mumbai", "Delhi",
    "Sydney", "Melbourne", "Toronto", "Frankfurt", "Paris", "Zurich", "Geneva",
    "Dublin", "Amsterdam", "Dubai", "Shenzhen", "Seoul", "Bangkok",
    "Jakarta", "Manila", "Kuala Lumpur", "Johannesburg", "Sao Paulo",
)
_LOCATION_RE = _phrase_pattern(_LOCATION_TERMS)

# A light "based in / in <Capitalized>" heuristic catches a place we don't have in the
# curated list. Requires an explicit locative preposition so it doesn't fire on every
# capitalised word. Bounded (one capitalised token, optionally a second), linear-time.
_BASED_RE = re.compile(
    r"\b(?:based in|located in|headquartered in|office in|offices in|in)\s+"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)"
)

# Organisation markers — corporate-form suffixes + sector words that, alongside the above,
# tie the subject to a specific employer/entity. Word-boundary; '& Co' handled literally.
_ORG_TERMS = (
    "Inc", "Ltd", "LLP", "LLC", "Pte", "PLC", "GmbH", "AG", "SA", "NV", "Co",
    "Bank", "Capital", "Management", "Group", "Holdings", "Partners",
    "Securities", "Advisors", "Advisers", "Trust", "Fund", "Asset",
)
# Built specially so "& Co" matches and the suffixes match as words.
_ORG_RE = re.compile(
    r"(?:&\s*Co\b|\b(?:" + "|".join(re.escape(t) for t in _ORG_TERMS) + r")\b)"
)

# Re-identification flag thresholds (tuned so the bio fixture flags `high` while a normal
# "He joined in 2007 as a Director." sentence — 1 year + 1 role, 2 categories — does NOT).
_REID_MIN_CATEGORIES = 3   # distinct quasi-identifier categories present
_REID_MIN_SIGNALS = 6      # total signal hits across all categories
_REID_HIGH_CATEGORIES = 4  # >= this many categories OR a high signal count -> `high`
_REID_HIGH_SIGNALS = 10


# ------------------------------------------------------------- data type ----
@dataclass
class FlaggedPassage:
    start: int                       # BYTE offset of the paragraph in `text`
    end: int                         # BYTE offset (exclusive) of the paragraph end
    category: str                    # privilege | confidentiality | re_identification
    reason: str                      # short human string (counts / matched keywords)
    severity: str                    # high | medium
    keywords: list = field(default_factory=list)   # matched keyword/signal list

    def to_dict(self) -> dict:
        return asdict(self)


# ----------------------------------------------------------- segmentation ----
# Split into paragraphs on a blank line (a double-newline boundary, allowing whitespace on
# the blank line); fall back to single-newline blocks when the document uses only single
# newlines. We keep ACCURATE byte offsets into the original text by walking the split on the
# ORIGINAL string and measuring offsets in UTF-8 bytes (char-boundary safe: offsets are
# computed at code-point boundaries, then encoded to bytes).
_PARA_SPLIT_RE = re.compile(r"\n[ \t\r\f\v]*\n")


def _iter_paragraphs(text: str):
    """Yield (char_start, char_end, paragraph_text) for each non-empty paragraph.

    Splits on blank-line boundaries. If the whole text has no blank-line boundary at all
    but does contain single newlines, fall back to splitting on single newlines so a
    newline-only document still segments into blocks. Offsets are CHAR offsets into `text`;
    the caller converts to byte offsets. Bounded by _MAX_PARAGRAPHS."""
    # Choose the splitter: prefer blank-line paragraphs; only fall back to single-newline
    # blocks when there are NO blank-line boundaries (else we'd over-split normal prose).
    if _PARA_SPLIT_RE.search(text):
        splitter = _PARA_SPLIT_RE
    elif "\n" in text:
        splitter = re.compile(r"\n")
    else:
        splitter = None

    count = 0
    if splitter is None:
        seg = text.strip()
        if seg:
            lead = len(text) - len(text.lstrip())
            yield lead, lead + len(seg), seg
        return

    pos = 0
    for m in splitter.finditer(text):
        block = text[pos:m.start()]
        if block.strip():
            count += 1
            if count > _MAX_PARAGRAPHS:
                return
            lead = len(block) - len(block.lstrip())
            trail = len(block) - len(block.rstrip())
            yield pos + lead, m.start() - trail, block.strip()
        pos = m.end()
    # The final block after the last separator.
    block = text[pos:]
    if block.strip():
        count += 1
        if count > _MAX_PARAGRAPHS:
            return
        lead = len(block) - len(block.lstrip())
        trail = len(block) - len(block.rstrip())
        yield pos + lead, len(text) - trail, block.strip()


# ----------------------------------------------------------- detection ----
def _dedup_keep_order(items):
    seen = set()
    out = []
    for it in items:
        low = it.lower()
        if low not in seen:
            seen.add(low)
            out.append(it)
    return out


def _scan_privilege(para: str):
    """Return matched privilege markers in `para`, order-preserving + deduped."""
    hits = [m.group(0) for m in _PRIVILEGE_RE.finditer(para)]
    return _dedup_keep_order(hits)


def _scan_confidentiality(para: str):
    """Return matched confidentiality / sensitive-content terms, order-preserving + deduped."""
    hits = [m.group(0) for m in _CONFIDENTIALITY_RE.finditer(para)]
    return _dedup_keep_order(hits)


def _scan_reidentification(para: str):
    """Compute the quasi-identifier density of `para`.

    Returns a dict: per-category counts, the distinct-category count, the total signal
    count, and the matched sample keywords. Locations are the union of the curated set and
    the 'based in <Capitalized>' heuristic (de-duped). Linear-time."""
    years = _YEAR_RE.findall(para)
    dates = [m.group(0) for m in _DATE_RE.finditer(para)]
    # Treat year + written-date as ONE "time" category but count both toward total signals.
    time_hits = years + dates

    roles = [m.group(0) for m in _ROLE_RE.finditer(para)]

    loc_curated = [m.group(0) for m in _LOCATION_RE.finditer(para)]
    loc_heur = [m.group(1) for m in _BASED_RE.finditer(para)]
    # De-dup locations case-insensitively; a heuristic hit that duplicates a curated one
    # (e.g. "in London") must not double-count.
    locations = _dedup_keep_order(loc_curated + loc_heur)

    orgs = _dedup_keep_order([m.group(0) for m in _ORG_RE.finditer(para)])

    cats = {
        "time": len(time_hits),
        "roles": len(roles),
        "locations": len(locations),
        "organisations": len(orgs),
    }
    distinct = sum(1 for v in cats.values() if v > 0)
    total = sum(cats.values())
    # A small sample of the matched signals for the keyword list (order-preserving, deduped).
    sample = _dedup_keep_order(
        [str(x) for x in years[:3]]
        + roles[:3]
        + locations[:3]
        + orgs[:3]
    )
    return {
        "counts": cats,
        "distinct": distinct,
        "total": total,
        "keywords": sample,
        "years": len(years),
        "roles": len(roles),
        "locations": len(locations),
        "orgs": len(orgs),
    }


def _reid_reason(info: dict) -> str:
    """Build the counts-based human reason for a re-identification flag."""
    parts = []
    if info["years"]:
        parts.append(f"{info['years']} year{'s' if info['years'] != 1 else ''}")
    if info["roles"]:
        parts.append(f"{info['roles']} role term{'s' if info['roles'] != 1 else ''}")
    if info["locations"]:
        parts.append(f"{info['locations']} location{'s' if info['locations'] != 1 else ''}")
    if info["orgs"]:
        parts.append(f"{info['orgs']} organisation{'s' if info['orgs'] != 1 else ''}")
    return "Possible re-identification: " + ", ".join(parts)


# ----------------------------------------- re-identification EXPOSURE index ----
# A DOCUMENT-LEVEL aggregate of the SAME per-paragraph quasi-identifier signals
# `_scan_reidentification` already computes. It answers ONE question for the redaction
# meter: "after names/IDs are gone, how many quasi-identifiers does this document still
# carry that a reader could triangulate to re-identify someone?"
#
# HONEST FRAMING (load-bearing — do NOT loosen):
#   * This is a re-identification EXPOSURE INDICATOR that PROMPTS REVIEW. It is NOT
#     k-anonymity, NOT a probability, NOT a "percent safe", NOT a safety score. A high
#     value means "more quasi-identifiers a reader could triangulate", nothing more.
#   * Privilege / confidentiality MARKERS are SENSITIVITY, not re-identifiability — they
#     are DELIBERATELY EXCLUDED from this index (they never move it). `score_*` reports
#     `privilege_markers` separately as a boolean note, but it is informational only.
#   * The index is deterministic, linear-time and bounded by the SAME paragraph caps the
#     flagger uses (so a hostile document can never make scoring super-linear).
#
# Scoring (deterministic, MONOTONE, bounded to [0, 100]):
#   Let C = the number of DISTINCT quasi-identifier categories present across the whole
#   document (0..4: time, roles, locations, organisations) and S = the TOTAL quasi-
#   identifier signal count summed over those categories.
#     coverage = 15 * C                       # breadth: each category contributes up to 15 (max 60)
#     density  = round(40 * (1 - 1/(1 + S/8)))  # saturating depth term, asymptote 40 (max 40)
#     index    = min(100, coverage + density)
#   Both terms are NON-DECREASING in their inputs, and adding any quasi-identifier can only
#   raise C and/or S — so adding a quasi-identifier NEVER lowers the index and removing one
#   NEVER raises it. `after <= before` then holds for the residual scored via
#   `score_reidentification_residual`, which strips the engine's bracketed placeholder tokens
#   (the `labels` style INSERTS markers like `[Singapore ID]` whose words — `Singapore` — the
#   scanners would otherwise count); after stripping, the residual is the original minus the
#   removed spans, i.e. a SUBSET of the original's quasi-identifiers.
_REID_INDEX_DENSITY_SCALE = 8.0   # S at which the density term reaches ~44% of its 40-pt asymptote
_REID_INDEX_DENSITY_MAX = 40      # the density term's asymptote (the saturating depth contribution)
_REID_INDEX_PER_CATEGORY = 15     # each distinct category contributes this to coverage (4 * 15 = 60)

# Band cutoffs are read off the INDEX alone, so the band is MONOTONE in the number the meter
# shows beside it — a higher index can NEVER display a lower band. (The earlier flag-threshold
# gating could show "37/100 critical" next to "60/100 medium"; index-driven banding removes
# that contradiction.) The HIGH cut is the MINIMUM index a document at the per-passage flagger's
# re-identification trigger reaches (>= _REID_MIN_CATEGORIES categories of coverage plus the
# density at >= _REID_MIN_SIGNALS), so anything the flagger would flag still reads at least
# `high`; CRITICAL marks a genuine multi-category convergence WITH density.
BAND_NONE = "none"
BAND_LOW = "low"
BAND_MEDIUM = "medium"
BAND_HIGH = "high"
BAND_CRITICAL = "critical"
REID_BANDS = (BAND_NONE, BAND_LOW, BAND_MEDIUM, BAND_HIGH, BAND_CRITICAL)
_REID_BAND_CRITICAL = 75   # index >= this -> critical (strong multi-category + density convergence)
_REID_BAND_HIGH = 62       # index >= this -> high (>= the flagger's re_identification trigger)
_REID_BAND_MEDIUM = 45     # index >= this -> medium (broad-but-sparse); below -> low


@dataclass
class ReidScore:
    """A document-level re-identification EXPOSURE read (NOT a safety / anonymity measure).

    `index` is the 0-100 re-identification exposure index; `band` is its coarse label
    (none/low/medium/high/critical). `counts` mirrors `_scan_reidentification`'s per-category
    totals (time / roles / locations / organisations) aggregated across the document;
    `distinct` is how many of the 4 categories are present; `total` is the summed signal
    count. `privilege_markers` is an INFORMATIONAL flag (sensitivity, NOT re-identifiability)
    that does NOT contribute to `index`."""
    index: int                       # 0-100 re-identification EXPOSURE index (review prompt, NOT safety)
    band: str                        # none | low | medium | high | critical
    counts: dict                     # {time, roles, locations, organisations} totals
    distinct: int                    # number of DISTINCT categories present (0-4)
    total: int                       # total quasi-identifier signal count
    privilege_markers: bool = False  # informational: privilege/confidentiality wording present

    def to_dict(self) -> dict:
        return asdict(self)


def _reid_density(total_signals: int) -> int:
    """The saturating DEPTH term: 0 at S=0, asymptotic to _REID_INDEX_DENSITY_MAX. Non-
    decreasing in `total_signals`, so it can only grow as signals are added (monotone)."""
    s = max(0, int(total_signals))
    if s == 0:
        return 0
    frac = 1.0 - 1.0 / (1.0 + s / _REID_INDEX_DENSITY_SCALE)
    return int(round(_REID_INDEX_DENSITY_MAX * frac))


def _reid_band(index: int) -> str:
    """Map the 0-100 exposure index to a coarse band. MONOTONE in `index` by construction
    (a higher index can never yield a lower band), so the band and the number the meter shows
    beside it can never contradict. index 0 (no quasi-identifiers at all) is always `none`."""
    if index <= 0:
        return BAND_NONE
    if index >= _REID_BAND_CRITICAL:
        return BAND_CRITICAL
    if index >= _REID_BAND_HIGH:
        return BAND_HIGH
    if index >= _REID_BAND_MEDIUM:
        return BAND_MEDIUM
    return BAND_LOW


def score_reidentification(text) -> ReidScore:
    """Aggregate the per-paragraph quasi-identifier signals into a document-level
    re-identification EXPOSURE score (see the module/_reid_band docs for the framing).

    REUSES `_scan_reidentification` per paragraph (the SINGLE source of the lexicons /
    regexes) and `_iter_paragraphs` for the bounded, char-safe segmentation — it defines no
    new detectors. Deterministic, linear-time, bounded by the SAME caps as the flagger.
    Empty / whitespace input -> index 0, band `none`. The result is purely COUNT-DERIVED:
    it carries NO cleartext (only per-category totals)."""
    counts = {"time": 0, "roles": 0, "locations": 0, "organisations": 0}
    privilege_markers = False
    if isinstance(text, str) and text.strip():
        for _cstart, _cend, para in _iter_paragraphs(text):
            scan_para = para
            if len(scan_para.encode("utf-8")) > _MAX_PARAGRAPH_BYTES:
                scan_para = scan_para.encode("utf-8")[:_MAX_PARAGRAPH_BYTES].decode(
                    "utf-8", "ignore")
            info = _scan_reidentification(scan_para)
            for k in counts:
                counts[k] += info["counts"][k]
            # Privilege / confidentiality wording is SENSITIVITY, not re-identifiability —
            # tracked for the informational note only; it does NOT enter the index.
            if not privilege_markers and (
                _scan_privilege(scan_para) or _scan_confidentiality(scan_para)):
                privilege_markers = True

    distinct = sum(1 for v in counts.values() if v > 0)
    total = sum(counts.values())
    coverage = _REID_INDEX_PER_CATEGORY * distinct
    index = min(100, coverage + _reid_density(total))
    band = _reid_band(index)
    return ReidScore(
        index=index, band=band, counts=counts, distinct=distinct, total=total,
        privilege_markers=privilege_markers,
    )


def score_reidentification_dict(text) -> dict:
    """score_reidentification but returning a JSON-ready dict (for the web response).

    Shape (all values are COUNT-DERIVED — no cleartext): `index` (0-100 re-identification
    EXPOSURE index, a review prompt NOT a safety measure), `band`, `counts` (per-category
    totals), `distinct`, `total`, `privilege_markers` (informational, does not move the
    index)."""
    return score_reidentification(text).to_dict()


# The redaction engine's `labels` pseudonymization style does not just DELETE identifiers — it
# substitutes bracketed placeholder tokens (`[REDACTED]`, `[Singapore ID]`, `[UK ID (nino)]`,
# ...). Some of those tokens contain words the quasi-identifier scanners match (`Singapore` /
# `UK` / `Australia` are `locations`), so scoring the RAW residual would count the engine's OWN
# markers as new quasi-identifiers and could push the after-score ABOVE the before-score. Strip
# the placeholder tokens first so the residual reflects only genuine surviving quasi-identifiers
# — which is what keeps `after <= before` true.
_REDACTION_PLACEHOLDER_RE = re.compile(r"\[[^\]]*\]")


def score_reidentification_residual(text) -> ReidScore:
    """Like score_reidentification, but for a REDACTED residual: strip the engine's bracketed
    placeholder tokens (`[REDACTED]`, `[Singapore ID]`, ...) BEFORE scoring so the engine's own
    markers are never miscounted as quasi-identifiers. Use this for the AFTER side of the
    before->after meter — `after <= before` holds because the residual is the original minus the
    removed spans, with the inserted markers stripped."""
    if isinstance(text, str) and text:
        text = _REDACTION_PLACEHOLDER_RE.sub(" ", text)
    return score_reidentification(text)


def score_reidentification_residual_dict(text) -> dict:
    """score_reidentification_residual as a JSON-ready dict (for the apply web response)."""
    return score_reidentification_residual(text).to_dict()


def flag_passages(text: str) -> list:
    """Flag likely-sensitive PASSAGES in `text` for the lawyer's review.

    Returns a list of FlaggedPassage. SURFACE-ONLY: this never redacts or removes anything.
    Each passage carries BYTE offsets of its paragraph (char-boundary safe), a category, a
    short counts/keyword-based reason, a severity, and the matched keywords.

    A single paragraph can produce MULTIPLE flags (e.g. both privilege and confidentiality,
    or confidentiality + re_identification) — they are independent surfaces over the same
    span. Deterministic, linear-time, no model, returns [] on empty/whitespace input."""
    if not isinstance(text, str) or not text.strip():
        return []

    out: list = []
    # Char->byte offset conversion in ONE linear pass. The previous code called
    # _char_to_byte(text, idx) per paragraph boundary, each re-encoding text[:idx] — O(n)
    # per call, O(n^2) overall (a multi-second UI freeze on a multi-MB doc, contradicting
    # this module's documented linear-time bound). Paragraphs are yielded in increasing
    # offset order, so a monotonic cursor advances through the string once; emitted byte
    # offsets are byte-identical to before.
    _cur_char = 0
    _cur_byte = 0

    def _to_byte(ci: int) -> int:
        nonlocal _cur_char, _cur_byte
        if ci < _cur_char:
            # Non-monotonic boundary (not expected from _iter_paragraphs): fall back to the
            # absolute conversion — correct, just O(n) — rather than return a wrong offset.
            return len(text[:ci].encode("utf-8"))
        _cur_byte += len(text[_cur_char:ci].encode("utf-8"))
        _cur_char = ci
        return _cur_byte

    for cstart, cend, para in _iter_paragraphs(text):
        # Bound the per-paragraph work: only look at the first _MAX_PARAGRAPH_BYTES of a
        # giant paragraph (offsets stay accurate; we just don't scan an unbounded tail).
        scan_para = para
        if len(scan_para.encode("utf-8")) > _MAX_PARAGRAPH_BYTES:
            # Truncate on a char boundary near the byte cap (decode-safe).
            scan_para = scan_para.encode("utf-8")[:_MAX_PARAGRAPH_BYTES].decode(
                "utf-8", "ignore")

        bstart = _to_byte(cstart)
        bend = _to_byte(cend)

        # --- privilege ---
        priv = _scan_privilege(scan_para)
        if priv:
            label = priv[0]
            out.append(FlaggedPassage(
                start=bstart, end=bend, category=CATEGORY_PRIVILEGE,
                reason=f"Privilege marker: '{label}'"
                       + (f" (+{len(priv) - 1} more)" if len(priv) > 1 else ""),
                severity=SEVERITY_HIGH, keywords=priv,
            ))

        # --- confidentiality / sensitive content ---
        conf = _scan_confidentiality(scan_para)
        if conf:
            label = conf[0]
            out.append(FlaggedPassage(
                start=bstart, end=bend, category=CATEGORY_CONFIDENTIALITY,
                reason=f"Confidentiality marker: '{label}'"
                       + (f" (+{len(conf) - 1} more)" if len(conf) > 1 else ""),
                severity=SEVERITY_MEDIUM, keywords=conf,
            ))

        # --- re-identification density ---
        info = _scan_reidentification(scan_para)
        if info["distinct"] >= _REID_MIN_CATEGORIES and info["total"] >= _REID_MIN_SIGNALS:
            severity = (
                SEVERITY_HIGH
                if (info["distinct"] >= _REID_HIGH_CATEGORIES
                    or info["total"] >= _REID_HIGH_SIGNALS)
                else SEVERITY_MEDIUM
            )
            out.append(FlaggedPassage(
                start=bstart, end=bend, category=CATEGORY_REIDENTIFICATION,
                reason=_reid_reason(info), severity=severity,
                keywords=info["keywords"],
            ))

    return out


def flag_passages_dicts(text: str) -> list:
    """flag_passages but returning JSON-ready dicts (for the web response)."""
    return [p.to_dict() for p in flag_passages(text)]
