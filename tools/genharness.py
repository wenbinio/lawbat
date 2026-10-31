#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Fresh-corpus redaction GENERALIZATION harness — a deterministic, repeatable red-team
that measures OFF-corpus redaction quality as a NUMBER (post-apply leaks), NOT a
self-scan of "0 candidates".

WHAT IT MEASURES
  For a pool of SYNTHETIC identities (fictional names + valid-format IDs) planted into
  hard document SHAPES (fund directory, engagement letter, agreement parties, email
  thread, trailing-role prose incl. line-wrapped variants, and an identity-FREE
  financial table), it drives the SAME two redaction routes the product ships and then
  RECOVERY-RED-TEAMS the output:
    * TEXT-PDF route  : redact-cli pdf_scan -> accept ALL ids -> pdf_apply (id parity),
      then re-extract the output text AND raw bytes and probe for every planted value.
    * SCANNED route   : rasterize the fixture image-only @200 DPI ->
      imageredact.redact_scanned_pdf (route-mirroring scan_fn) -> burned output, then
      assert ZERO text layer and RE-OCR the output and probe for every planted value.
  A planted value that survives (found in the output) is a LEAK — the headline number.

HONESTY (load-bearing)
  This measures the HARNESS'S SYNTHETIC SHAPES ONLY. A zero here is NOT a general
  safety claim: it does not prove the engine removes every identifier in every real
  document, only that these planted values in these layouts were removed. Finding a
  gap is the POINT — this harness reports gaps, it does not fix them.

RUN
  PYTHONPATH=. LAWDATAMAN_REDACT_CLI=core/target/release/redact-cli \\
      python3 tools/genharness.py --out <dir> [--seed N] [--scanned-subset K]

Everything is SYNTHETIC. No real people, firms, or matter data — ever (CLAUDE.md
invariant). Fictional names + valid-FORMAT identifiers computed offline.
"""

import argparse
import base64
import json
import os
import re
import string
import sys
import tempfile
from pathlib import Path

# App-data isolation BEFORE importing any app.* module (mirrors the smoke suite): the
# harness must never touch a real install's data dir. setdefault so an outer importer
# (e.g. the smoke runner) that already picked a dir wins.
os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-genharness-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

import fitz  # noqa: E402  PyMuPDF — born-digital fixture render + text-layer recovery
from app import imageredact, ocr, redactionmodel  # noqa: E402

# ------------------------------------------------------------------ identity classes ----
# The identity CLASSES tracked in the scorecard (stable display order).
CLASSES = (
    "person_name",
    "sg_nric",
    "us_ssn",
    "sg_uen",
    "iban",
    "phone",
    "email",
    "street",
    "sg_postal",
    "sg_unit",
    "uk_postcode",
    "us_zip",
)

# The redaction OPTIONS the product routes use for GENERALIZATION measurement: the three
# jurisdiction packs + context recognizers, and DELIBERATELY NO user terms (the point is
# to measure RECOGNIZER generalization, not "did super-find-and-replace work").
ROUTE_OPTIONS = {"locales": ["sg", "us", "uk"], "context": True}


# ------------------------------------------------------------------ synthetic pools ----
# Fictional given/surname pools — invented, name-SHAPED tokens (Capitalized). Kept
# disjoint from the firm-token pool so a two-token person probe cannot collide with a
# firm name.
_GIVEN = ["Marlow", "Cerys", "Idris", "Anders", "Rhona", "Tobias", "Selwyn",
          "Marisa", "Emrys", "Delia", "Corwin", "Ianthe"]
_SURNAME = ["Vantol", "Quorley", "Brandt", "Ashby", "Renfell", "Corrigan",
            "Delacroix", "Holl", "Beaumond", "Prewitt", "Varga", "Estcourt"]
_FIRMS = ["Meridian Crest Advisers", "Sundby Holdings (Pte) Ltd",
          "Kestrel & Lowe LLP", "Northfleet Capital Partners"]
_STREET_WORD = ["Vantol", "Quorley", "Kestrel", "Marlow", "Sundby", "Ferrow"]
_STREET_SUFFIX = ["Place", "Road", "Street", "Quay", "Crescent", "Way"]
_UK_POSTCODES = ["SW1A 1AA", "EC2M 7EB", "M1 1AE", "W1U 8ED", "N1 9GU", "L1 8JQ"]
_US_STATES = ["CA", "NY", "TX", "WA", "IL", "MA"]

_NRIC_ST_CHECK = "JZIHGFEDCBA"


# ------------------------------------------------------------------ value factories ----
def _digits(rng, n):
    return "".join(rng.choice(string.digits) for _ in range(n))


def make_nric(rng):
    """A format-valid SG NRIC `S\\d{7}[A-Z]` with a plausible S/T-series check letter
    (the engine's `sg:nric` row is FORMAT-ONLY, so the letter need only be [A-Z])."""
    body = [rng.randint(0, 9) for _ in range(7)]
    weights = [2, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(body, weights))
    check = _NRIC_ST_CHECK[total % 11]
    return "S" + "".join(str(d) for d in body) + check


_KNOWN_FAKE_SSN = {"078-05-1120", "123-45-6789", "219-09-9999"}


def make_ssn(rng):
    """A US SSN that PASSES `ssn_valid` (area not 000/666/>=900, group != 00,
    serial != 0000, not all-identical, not a known fake)."""
    while True:
        area = rng.randint(1, 899)
        if area == 666:
            continue
        group = rng.randint(1, 99)
        serial = rng.randint(1, 9999)
        value = f"{area:03d}-{group:02d}-{serial:04d}"
        if value in _KNOWN_FAKE_SSN:
            continue
        digits = value.replace("-", "")
        if len(set(digits)) == 1:
            continue
        return value


def make_uen(rng):
    """An SG local-company UEN `\\d{9}[A-Z]` (4-digit year + 5 digits + check letter)."""
    year = rng.randint(2000, 2023)
    return f"{year}{_digits(rng, 5)}{rng.choice(string.ascii_uppercase)}"


def _iban_check_digits(country, bban):
    rearranged = bban + country + "00"
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return f"{98 - (int(num) % 97):02d}"


def make_iban(rng):
    """A GB IBAN that PASSES ISO 7064 mod-97-10 (`iban_valid`): 4 bank letters + 14
    account digits, with computed check digits."""
    country = "GB"
    bban = "".join(rng.choice(string.ascii_uppercase) for _ in range(4)) + _digits(rng, 14)
    return country + _iban_check_digits(country, bban) + bban


def make_phone(rng, kind):
    if kind == "sg":
        return f"+65 {_digits(rng, 4)} {_digits(rng, 4)}"
    if kind == "us":
        return f"{_digits(rng, 3)}-{_digits(rng, 3)}-{_digits(rng, 4)}"
    return f"+44 7{_digits(rng, 3)} {_digits(rng, 6)}"  # uk


def make_email(rng, given, surname):
    return f"{given.lower()}.{surname.lower()}@{rng.choice(['kestrel', 'sundby', 'meridian'])}.example"


def make_person(rng, variant):
    """Return `(rendered, planted)` for a person: `rendered` is what appears in the doc,
    `planted` is the contiguous SENSITIVE substring the harness probes for removal."""
    given = rng.choice(_GIVEN)
    surname = rng.choice(_SURNAME)
    if variant == "honorific":
        title = rng.choice(["Ms.", "Mr.", "Dr.", "Mdm."])
        return f"{title} {given} {surname}", f"{given} {surname}"
    if variant == "initials":
        rendered = f"{given[0]}. {surname[0]}. {surname}"
        return rendered, rendered
    if variant == "hyphenated":
        rendered = f"{given} {surname}-{rng.choice(_SURNAME)}"
        return rendered, rendered
    if variant == "nonascii":
        return "José Müller-Tan", "José Müller-Tan"
    return f"{given} {surname}", f"{given} {surname}"  # plain


def make_street(rng):
    return f"{rng.randint(1, 250)} {rng.choice(_STREET_WORD)} {rng.choice(_STREET_SUFFIX)}"


def make_sg_postal(rng):
    return f"Singapore {_digits(rng, 6)}"


def make_sg_unit(rng):
    return f"#{rng.randint(1, 40):02d}-{rng.randint(1, 88):02d}"


def make_us_zip(rng):
    return f"{rng.choice(_US_STATES)} {_digits(rng, 5)}"


# ------------------------------------------------------------------ template builders ----
# Each builder returns `(tag, text, planted)`:
#   tag     — the template family (a..f), used for the scanned-subset diversity pick;
#   text    — the page text (hard `\n` = a line break the renderer keeps; a long prose
#             line SOFT-wraps to the fixture width, so narrow widths wrap mid-list);
#   planted — [(value, class), ...]: every planted identity + its class (ground truth).

def tpl_fund_directory(rng):
    n1, p1 = make_person(rng, "plain")
    n2, p2 = make_person(rng, "plain")
    n3, p3 = make_person(rng, "nonascii")
    street = make_street(rng)
    unit = make_sg_unit(rng)
    postal = make_sg_postal(rng)
    phone = make_phone(rng, "sg")
    email = make_email(rng, _GIVEN[0], _SURNAME[0])
    text = (
        "CONFIDENTIAL — FUND DIRECTORY\n\n"
        f"Directors\n{n1}\n{n2}\n{n3}\n\n"
        f"Registered Office\n{street}\n{unit}\n{postal}\n\n"
        f"Telephone {phone}\nEmail {email}\n"
    )
    planted = [(p1, "person_name"), (p2, "person_name"), (p3, "person_name"),
               (street, "street"), (unit, "sg_unit"), (postal, "sg_postal"),
               (phone, "phone"), (email, "email")]
    return "fund_directory", text, planted


def tpl_engagement_letter(rng):
    firm = rng.choice(_FIRMS)
    street = make_street(rng)
    postcode = rng.choice(_UK_POSTCODES)
    addr_name, addr_p = make_person(rng, "plain")
    salut, salut_p = make_person(rng, "honorific")
    inline1, inline1_p = make_person(rng, "plain")
    inline2, inline2_p = make_person(rng, "plain")
    signer, signer_p = make_person(rng, "honorific")
    email = make_email(rng, _GIVEN[3], _SURNAME[3])
    phone = make_phone(rng, "uk")
    text = (
        f"{firm}\n{street}, London {postcode}\n\n"
        "5 March 2026\n\n"
        f"{addr_name}\n{street}\n\n"
        f"Dear {salut},\n\n"
        "We write regarding the proposed acquisition. Our engagement partner "
        f"{inline1} will lead the matter, supported by {inline2}. Please direct "
        f"correspondence to {email} or call {phone} to arrange a call at your "
        "earliest convenience.\n\n"
        f"Yours faithfully,\n{signer}\n{firm}\n"
    )
    planted = [(addr_p, "person_name"), (salut_p, "person_name"),
               (inline1_p, "person_name"), (inline2_p, "person_name"),
               (signer_p, "person_name"), (street, "street"),
               (postcode, "uk_postcode"), (email, "email"), (phone, "phone")]
    return "engagement_letter", text, planted


def tpl_agreement_parties(rng):
    firm = rng.choice(_FIRMS)
    uen = make_uen(rng)
    street = make_street(rng)
    postal = make_sg_postal(rng)
    person, person_p = make_person(rng, "plain")
    nric = make_nric(rng)
    street2 = make_street(rng)
    iban = make_iban(rng)
    # A US counterparty exercises the us:ssn + us:zip packs alongside the SG ones.
    us_person, us_person_p = make_person(rng, "plain")
    ssn = make_ssn(rng)
    us_street = make_street(rng)
    us_zip = make_us_zip(rng)
    text = (
        "SALE AND PURCHASE AGREEMENT\n\nParties\n"
        f"(1) {firm} (UEN {uen}), a company incorporated in Singapore, with its "
        f"registered office at {street}, {postal};\n"
        f"(2) {person} (NRIC {nric}) of {street2}, in his personal capacity; and\n"
        f"(3) {us_person} (SSN {ssn}) of {us_street}, {us_zip}.\n\n"
        f"Completion monies shall be remitted to account {iban}.\n"
    )
    planted = [(uen, "sg_uen"), (street, "street"), (postal, "sg_postal"),
               (person_p, "person_name"), (nric, "sg_nric"),
               (street2, "street"), (iban, "iban"),
               (us_person_p, "person_name"), (ssn, "us_ssn"),
               (us_street, "street"), (us_zip, "us_zip")]
    return "agreement_parties", text, planted


def tpl_email_thread(rng):
    n1, p1 = make_person(rng, "plain")
    n2, p2 = make_person(rng, "plain")
    n3, p3 = make_person(rng, "plain")
    e1 = make_email(rng, n1.split()[0], n1.split()[-1])
    e2 = make_email(rng, n2.split()[0], n2.split()[-1])
    e3 = make_email(rng, n3.split()[0], n3.split()[-1])
    text = (
        f"From: {n1} <{e1}>\n"
        f"To: {n2} <{e2}>\n"
        f"Cc: {n3} <{e3}>\n"
        "Subject: Re: Completion timeline\n"
        "Date: 5 March 2026\n\n"
        f"{n2}, please confirm the completion date with the registry. Regards, {n1}.\n\n"
        f"On 4 March 2026, {n2} wrote:\n"
        f"> {n1}, the documents are with {n3} for final review this afternoon.\n"
    )
    planted = [(p1, "person_name"), (p2, "person_name"), (p3, "person_name"),
               (e1, "email"), (e2, "email"), (e3, "email")]
    return "email_thread", text, planted


def tpl_trailing_role(rng):
    people = [make_person(rng, "plain") for _ in range(7)]
    r = [x[0] for x in people]
    firm1 = rng.choice(_FIRMS)
    firm2 = rng.choice(_FIRMS)
    firm3 = rng.choice(_FIRMS)
    text = (
        f"{r[0]}, {r[1]} and {r[2]} are employees of {firm1}. "
        f"{r[3]} is a director of {firm2}. "
        f"The investment committee comprises {r[4]}, {r[5]} and {r[6]}, "
        f"who are members of {firm3}.\n"
    )
    planted = [(x[1], "person_name") for x in people]
    return "trailing_role", text, planted


def tpl_financial(rng):
    # NO identities — this page measures FALSE-POSITIVE PRESSURE (candidates the engine
    # raises on NAV-style numbers / amounts are over-flag NOISE to COUNT, not leaks).
    text = (
        "NET ASSET VALUE STATEMENT\n\n"
        "Class A NAV per unit: 12.3456\n"
        "Total net assets: 45,678,901.23\n"
        f"Subscriptions: {_digits(rng, 1)},{_digits(rng, 3)},{_digits(rng, 3)}.00\n"
        "Redemptions: 987,654.00\n"
        "Management fee (0.75%): 342,187.44\n"
        f"Units in issue: {_digits(rng, 7)}\n"
        f"Reference: {_digits(rng, 9)}\n"
        "Valuation date: 31/12/2025\n"
    )
    return "financial", text, []


# The build PLAN: (builder, [widths]) per fixture instance. Prose-heavy families get
# NARROW widths (260) so a name list / trailing phrase WRAPS mid-item — the recent leak
# class. ~21 born-digital fixtures total.
_PLAN = [
    (tpl_fund_directory, [340, 460]),
    (tpl_fund_directory, [300, 420]),
    (tpl_engagement_letter, [300, 460]),
    (tpl_engagement_letter, [260, 420]),
    (tpl_agreement_parties, [300, 460]),
    (tpl_email_thread, [340, 460]),
    (tpl_trailing_role, [260, 340, 460]),
    (tpl_trailing_role, [260, 300, 420]),
    (tpl_financial, [340, 420, 500]),
]


def _render_pdf(text, width_pt, fontsize=10):
    """Render `text` to a single-page born-digital PDF via an insert_textbox of the given
    WIDTH (so a long prose line soft-wraps at that width — the layout variant). Helvetica
    (base-14, WinAnsi) keeps a clean text layer incl. Latin-1 accents (José / Müller)."""
    doc = fitz.open()
    page = doc.new_page(width=width_pt + 144, height=1000)
    rect = fitz.Rect(72, 72, 72 + width_pt, 1000 - 72)
    leftover = page.insert_textbox(rect, text, fontsize=fontsize, fontname="helv")
    if leftover < 0:  # text overflowed the box — shrink until it fits (deterministic)
        doc.close()
        return _render_pdf(text, width_pt, fontsize - 1)
    data = doc.tobytes()
    doc.close()
    return data


def build_fixtures(seed=7):
    """Deterministically build the born-digital fixture set from `seed`. Returns a list of
    dicts `{id, tag, width, pdf, planted}` (planted = [(value, class), ...]). PURE — no
    redact-cli / OCR here (so the smoke test can call it cheaply)."""
    import random

    rng = random.Random(seed)
    fixtures = []
    fid = 0
    for builder, widths in _PLAN:
        tag, text, planted = builder(rng)
        for width in widths:
            fid += 1
            fixtures.append({
                "id": f"{tag}-{fid:02d}-w{width}",
                "tag": tag,
                "width": width,
                "pdf": _render_pdf(text, width),
                "planted": planted,
            })
    return fixtures


def generate_one(seed=7):
    """The FIRST born-digital fixture (for the smoke generator-sanity check): returns
    `(pdf_bytes, planted)`."""
    fx = build_fixtures(seed)[0]
    return fx["pdf"], fx["planted"]


# ------------------------------------------------------------------ normalize / probe ----
_WS = re.compile(r"\s+")


def normalize(s):
    """Whitespace-NORMALIZE for probing: collapse every run of whitespace to one space and
    lowercase, so a value split by a line WRAP in the output still matches its planted
    contiguous form (`Marlow\\nVantol` -> `marlow vantol`)."""
    return _WS.sub(" ", s or "").strip().lower()


def _found(haystack_norm, value):
    v = normalize(value)
    return bool(v) and v in haystack_norm


def _detected(value, cand_norms):
    """Diagnostic: is `value` COVERED by any scan candidate (bidirectional normalized
    containment)? Counts what the engine FLAGGED — the headline is post-apply leaks."""
    v = normalize(value)
    return any(v and cv and (v in cv or cv in v) for cv in cand_norms)


# ------------------------------------------------------------------ recovery helpers ----
def _text_layer(pdf_bytes):
    parts = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page in doc:
            parts.append(page.get_text("text"))
        doc.close()
    except Exception:  # noqa: BLE001 - a recovery hiccup must not crash the harness
        pass
    return "".join(parts)


def _recover_text_pdf(pdf_bytes):
    """Multi-decoder recovery for a byte-splice output: PyMuPDF text extraction (an
    INDEPENDENT decoder from the splice) PLUS the raw latin-1 bytes (catches any
    uncompressed residue). Returns ONE normalized haystack."""
    raw = pdf_bytes.decode("latin-1", errors="ignore")
    return normalize(_text_layer(pdf_bytes) + "\n" + raw)


def _rasterize_image_only(pdf_bytes, dpi=200):
    """Rasterize `pdf_bytes` to an IMAGE-ONLY PDF @`dpi` (no text layer) — the scanned
    input the image-redaction route consumes."""
    src = fitz.open(stream=pdf_bytes, filetype="pdf")
    out = fitz.open()
    try:
        for page in src:
            pix = page.get_pixmap(matrix=fitz.Matrix(dpi / 72.0, dpi / 72.0))
            rect = page.rect
            newp = out.new_page(width=rect.width, height=rect.height)
            newp.insert_image(rect, stream=pix.tobytes("png"))
        return out.tobytes()
    finally:
        out.close()
        src.close()


def _ocr_pdf_text(pdf_bytes):
    """RE-OCR a PDF's pages to text (app.ocr — the same OCR the route uses). Returns the
    joined page text (or '')."""
    fd, path = tempfile.mkstemp(suffix=".pdf", prefix="ldm-gh-")
    os.close(fd)
    try:
        Path(path).write_bytes(pdf_bytes)
        return "\n".join(txt for _, txt in ocr.ocr_pdf(path))
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ------------------------------------------------------------------ path runners ----
def run_text_pdf(fx):
    """TEXT-PDF route: pdf_scan -> accept ALL ids -> pdf_apply (SAME options = id parity),
    then recovery-probe the output. Returns a result dict."""
    b64 = base64.b64encode(fx["pdf"]).decode("ascii")
    scan = redactionmodel.pdf_scan(b64, ROUTE_OPTIONS)
    if not isinstance(scan, dict) or "error" in scan:
        return {"error": (scan or {}).get("error", "pdf_scan failed")}
    cands = scan.get("candidates", []) or []
    cand_norms = [normalize(c.get("value", "")) for c in cands if isinstance(c, dict)]
    ids = [c["id"] for c in cands if isinstance(c, dict) and isinstance(c.get("id"), int)]
    apply_res = redactionmodel.pdf_apply(b64, ids, ROUTE_OPTIONS)
    if not isinstance(apply_res, dict) or "error" in apply_res:
        return {"error": (apply_res or {}).get("error", "pdf_apply failed")}
    pdf_b64 = apply_res.get("pdf_b64")
    if not isinstance(pdf_b64, str):
        return {"error": "pdf_apply returned no PDF"}
    hay = _recover_text_pdf(base64.b64decode(pdf_b64))
    results = [(cls, _detected(val, cand_norms), _found(hay, val), val)
               for val, cls in fx["planted"]]
    return {"results": results, "scan_candidates": len(cands),
            "could_not_remove": int(apply_res.get("could_not_remove", 0) or 0)}


def run_scanned(fx):
    """SCANNED route: rasterize image-only -> imageredact.redact_scanned_pdf with a
    route-mirroring scan_fn -> burned output. Asserts ZERO text layer + re-OCR probes."""
    img_pdf = _rasterize_image_only(fx["pdf"])

    def scan_fn(text):
        if not text.strip():
            return []
        res = redactionmodel.scan(text, ROUTE_OPTIONS)
        if "error" in res:
            raise RuntimeError(res["error"])
        spans = []
        for c in res.get("candidates", []) or []:
            s, e = c.get("start"), c.get("end")
            if isinstance(s, int) and isinstance(e, int) and 0 <= s < e:
                spans.append((s, e))
        return spans

    # Detected-at-scan diagnostic: OCR the ORIGINAL scan + scan its text (what the burn
    # path's engine sees).
    orig_text = _ocr_pdf_text(img_pdf)
    cand_norms = []
    if orig_text.strip():
        sc = redactionmodel.scan(orig_text, ROUTE_OPTIONS)
        if isinstance(sc, dict) and "error" not in sc:
            cand_norms = [normalize(c.get("value", "")) for c in sc.get("candidates", []) or []]

    try:
        out_bytes, report = imageredact.redact_scanned_pdf(img_pdf, scan_fn, ocr_fn=ocr.ocr_words)
    except RuntimeError as exc:
        return {"error": f"scan_fn failed: {exc}"}
    if out_bytes is None:
        return {"error": (report or {}).get("error", "redact_scanned_pdf failed")}

    text_layer_len = len(_text_layer(out_bytes).strip())
    hay = normalize(_ocr_pdf_text(out_bytes))
    results = [(cls, _detected(val, cand_norms), _found(hay, val), val)
               for val, cls in fx["planted"]]
    return {"results": results, "text_layer_len": text_layer_len,
            "boxes": int((report or {}).get("boxes", 0) or 0)}


# ------------------------------------------------------------------ scoring ----
def _blank_scorecard():
    return {cls: {"planted": 0, "detected": 0, "leaks": 0} for cls in CLASSES}


def _score(fixtures, runner, is_text):
    """Run `runner` over `fixtures`, accumulating the per-class scorecard + the leak list +
    (text path only) the per-financial-fixture FP-pressure counts."""
    board = _blank_scorecard()
    leaks = []
    fp_pressure = []
    errors = []
    for fx in fixtures:
        res = runner(fx)
        if "error" in res:
            errors.append({"fixture": fx["id"], "error": res["error"]})
            continue
        if is_text and fx["tag"] == "financial":
            fp_pressure.append({"fixture": fx["id"], "candidates": res["scan_candidates"]})
        for cls, detected, leaked, value in res["results"]:
            board[cls]["planted"] += 1
            if detected:
                board[cls]["detected"] += 1
            if leaked:
                board[cls]["leaks"] += 1
                leaks.append({"path": "text-pdf" if is_text else "scanned",
                              "fixture": fx["id"], "class": cls, "value": value})
    return board, leaks, fp_pressure, errors


def _pick_scanned(fixtures, k):
    """Deterministically choose `k` fixtures covering TEMPLATE diversity: the first fixture
    of each distinct tag, in build order, then fill from the remainder if k > #tags."""
    chosen, seen = [], set()
    for fx in fixtures:
        if fx["tag"] not in seen:
            seen.add(fx["tag"])
            chosen.append(fx)
        if len(chosen) >= k:
            return chosen
    for fx in fixtures:
        if fx not in chosen:
            chosen.append(fx)
        if len(chosen) >= k:
            break
    return chosen[:k]


# ------------------------------------------------------------------ reporting ----
def _fmt_table(title, board):
    rows = [title, f"  {'class':<13} {'planted':>7} {'detected':>8} {'LEAKS':>6}"]
    tot = {"planted": 0, "detected": 0, "leaks": 0}
    for cls in CLASSES:
        b = board[cls]
        if b["planted"] == 0:
            continue
        for k in tot:
            tot[k] += b[k]
        rows.append(f"  {cls:<13} {b['planted']:>7} {b['detected']:>8} {b['leaks']:>6}")
    rows.append(f"  {'TOTAL':<13} {tot['planted']:>7} {tot['detected']:>8} {tot['leaks']:>6}")
    return "\n".join(rows), tot


def _render_report(seed, subset_k, text_board, scan_board, fp_pressure, leaks,
                   errors, scanned_ran):
    out = []
    out.append("=" * 72)
    out.append("FRESH-CORPUS REDACTION GENERALIZATION HARNESS")
    out.append("=" * 72)
    out.append(f"seed={seed}  scanned-subset={subset_k}")
    out.append("HONEST SCOPE: this measures the harness's SYNTHETIC shapes ONLY. A zero")
    out.append("here is NOT a general safety claim — it does not prove the engine removes")
    out.append("every identifier in every real document. Finding a gap is the point.")
    out.append("Headline = POST-APPLY LEAKS (planted values recovered from the output).")
    out.append("")

    text_tbl, _ = _fmt_table("TEXT-PDF route (pdf_scan -> accept all -> pdf_apply):", text_board)
    out.append(text_tbl)
    out.append("")

    if scanned_ran:
        scan_tbl, _ = _fmt_table("SCANNED route (rasterize -> OCR burn -> re-OCR probe):", scan_board)
        out.append(scan_tbl)
    else:
        out.append("SCANNED route: SKIPPED (tesseract OCR engine not available)")
    out.append("")

    out.append("FP pressure — candidates raised on the identity-FREE financial page (noise):")
    if fp_pressure:
        for fp in fp_pressure:
            out.append(f"  {fp['fixture']:<28} candidates={fp['candidates']}")
    else:
        out.append("  (no financial fixtures)")
    out.append("")

    total_leaks = len(leaks)
    out.append(f"TOTAL POST-APPLY LEAKS: {total_leaks}")
    if leaks:
        out.append("Top leaks (path / fixture / class / value):")
        for lk in leaks[:10]:
            out.append(f"  [{lk['path']}] {lk['fixture']:<26} {lk['class']:<12} {lk['value']!r}")
    if errors:
        out.append("")
        out.append(f"ERRORS ({len(errors)}):")
        for e in errors[:10]:
            out.append(f"  {e['fixture']}: {e['error']}")
    out.append("=" * 72)
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fresh-corpus redaction generalization harness.")
    parser.add_argument("--out", required=True, help="output directory for report.json")
    parser.add_argument("--seed", type=int, default=7, help="deterministic corpus seed (default 7)")
    parser.add_argument("--scanned-subset", type=int, default=6,
                        help="how many fixtures to also run through the scanned/OCR route (default 6)")
    args = parser.parse_args(argv)

    if not redactionmodel.available():
        print("ERROR: redact-cli not found. Set LAWDATAMAN_REDACT_CLI or bundle it.",
              file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    fixtures = build_fixtures(args.seed)
    text_board, text_leaks, fp_pressure, text_errors = _score(fixtures, run_text_pdf, True)

    scanned_ran = ocr.available()
    scan_board = _blank_scorecard()
    scan_leaks, scan_errors, scanned = [], [], []
    if scanned_ran:
        scanned = _pick_scanned(fixtures, max(0, args.scanned_subset))
        scan_board, scan_leaks, _, scan_errors = _score(scanned, run_scanned, False)

    all_leaks = text_leaks + scan_leaks
    all_errors = text_errors + scan_errors
    report_text = _render_report(args.seed, args.scanned_subset, text_board, scan_board,
                                 fp_pressure, all_leaks, all_errors, scanned_ran)

    report = {
        "schema": "genharness/0",
        "honest_scope": ("Measures the harness's SYNTHETIC shapes ONLY; a zero is NOT a "
                         "general safety claim. Headline = post-apply leaks."),
        "seed": args.seed,
        "scanned_subset": args.scanned_subset,
        "born_digital_fixtures": len(fixtures),
        "scanned_fixtures": [fx["id"] for fx in scanned],
        "scanned_ran": scanned_ran,
        "text_pdf": {"per_class": text_board, "fp_pressure": fp_pressure},
        "scanned": {"per_class": scan_board},
        "leaks": all_leaks,
        "errors": all_errors,
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(report_text)
    print(f"\nreport.json written to {out_dir / 'report.json'}")
    return 0  # report-only harness: always exit 0 (the leak LIST is the artifact)


if __name__ == "__main__":
    sys.exit(main())
