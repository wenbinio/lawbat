// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `RedactionEngine` (detection + merge + Core-mediated apply) and its
//! config types. Extracted from the former monolithic `lib.rs`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use regex::{Regex, RegexBuilder, RegexSet};
use runtime::{
    Audit, CapabilityBroker, ContentKind, CoreError, CoreResult, DataClass, Egress, MatterContext,
    MatterStore, Storage,
};

use crate::packs::locale_recognizers;
use crate::*;

/// One built-in pattern source row: `(enabled, kind, regex source, optional
/// checksum validator)`. A static table of these drives [`RedactionEngine::base`]
/// (a type alias keeps the table literal readable — clippy `type_complexity`).
type PatternSource = (bool, Recognizer, &'static str, Option<fn(&str) -> bool>);

/// A recognizer's compiled regex tagged with which [`Recognizer`] it is, so a
/// single match pass can attribute every span.
pub(crate) struct TaggedPattern {
    pub(crate) kind: Recognizer,
    pub(crate) re: Regex,
    /// Optional pure validator run on each raw match's text. `None` accepts every
    /// match (format-only recognizers). `Some(f)` keeps a match ONLY if `f` returns
    /// `true` — used for CHECKSUM-defined identifiers (Luhn card, IBAN mod-97) where
    /// the format alone is hopelessly broad (every long digit run) but the checksum
    /// makes it precise WITHOUT a miss risk: a real card/IBAN always passes, so the
    /// validator only ever filters NON-instances. (Deterministic, no allocation of
    /// matter data beyond the matched slice the validator inspects.)
    pub(crate) validate: Option<fn(&str) -> bool>,
}

/// A merged span from the authoritative pass: the public candidate plus the
/// replacement string to write for it (`None` = the default marker).
pub(crate) struct MergedSpan {
    pub(crate) candidate: RedactionCandidate,
    pub(crate) replacement: Option<String>,
}

/// Mutable accumulator used during the sweep-merge.
///
/// FIX F7 (custom replacement no longer silently dropped on containment): instead
/// of a `merged` flag that unconditionally forced the default marker the instant a
/// span absorbed a second member, the accumulator now tracks the DISTINCT custom
/// replacements it has seen (`custom_replacements`). A single custom replacement
/// over the union span is unambiguous and is PRESERVED (so e.g. a `Custom`
/// `jane.roe -> [PARTY]` span contained inside a built-in email span still writes
/// `[PARTY]`); only when ≥2 DIFFERENT custom replacements collide is the union
/// ambiguous and falls back to the marker. A span carrying NO custom replacement
/// (a built-in, or a custom with the default marker) contributes nothing here and
/// never blocks a sibling's distinct replacement.
struct MergeAcc {
    start: usize,
    end: usize,
    /// The PRIMARY recognizer (lowest [`Recognizer::priority`], ties by earliest
    /// start) — used as the candidate's `recognizer` and counted in the breakdown.
    kind: Recognizer,
    /// EVERY distinct recognizer absorbed into this span, in arrival order. FIX #5:
    /// a span matched by two same-pattern firm rules keeps BOTH labels here so
    /// neither is silently lost to the merge. Sorted + deduped at finalization.
    kinds: Vec<Recognizer>,
    /// The DISTINCT custom (`Some`) replacement strings absorbed into this span, in
    /// arrival order, deduplicated. FIX F7: exactly one => preserve it; ≥2 distinct
    /// => ambiguous union, fall back to the marker; empty => marker (the default).
    custom_replacements: Vec<String>,
}

/// Build the WHITESPACE-INSENSITIVE regex source for one user term: a case-insensitive
/// pattern that matches the term's characters with ARBITRARY ASCII whitespace allowed
/// between every adjacent pair. Each NON-whitespace character is `regex::escape`d (so
/// metacharacters in a name like `A.B (Pte)` stay literal) and joined to the next with
/// the elastic `[ \t\r\n\f]*` token; runs of whitespace IN the term collapse to the same
/// elastic separator (so the term's own spacing is also flexible). Leading/trailing term
/// whitespace is trimmed (it cannot anchor a match).
///
/// Example: `Daniel J. Watkins` → `(?i)D[ws]*a[ws]*n…[ws]*J[ws]*\.[ws]*[ws]*W[ws]*a…`
/// — which matches the PDF-reconstructed `Daniel J. W at kins` (the glyph-by-glyph
/// `Td`-nudged layout). The elastic token uses a bracketed ASCII-whitespace class (NOT
/// `\s`, which under `(?i)` is unaffected but the explicit class keeps intent obvious and
/// avoids matching unicode whitespace inside a redaction span).
///
/// PURE + deterministic: a fixed transformation of the input string; no clock/RNG/network.
pub(crate) fn ws_term_regex_source(term: &str) -> String {
    // The user-TERM form is case-INSENSITIVE (a party name matches regardless of case).
    ws_regex_source(term, true)
}

/// The core of [`ws_term_regex_source`]: build the whitespace-ELASTIC regex source for
/// `term`, case-INSENSITIVE when `case_insensitive` (the `(?i)` user-TERM form) or
/// case-SENSITIVE otherwise. The case-sensitive form is the NAME-PROPAGATION (Mechanism A)
/// variant: it re-flags a detected person-name value's EXACT characters elsewhere, so a
/// lowercased coincidence of the same letters is deliberately NOT pulled in — a name is a
/// capitalized proper noun and case-sensitivity keeps the propagation precise. Same elastic
/// separator + per-char escaping either way, so a value a PDF layout fragmented across a
/// `Td`-nudged line break / space run still matches (the very reason the user-TERM pass
/// exists). PURE + deterministic (a fixed transformation of the input string; no
/// clock/RNG/network).
pub(crate) fn ws_regex_source(term: &str, case_insensitive: bool) -> String {
    // Elastic ASCII-whitespace separator inserted between every pair of significant chars.
    const WS: &str = "[ \\t\\r\\n\\x0c]*";
    let mut out = String::new();
    if case_insensitive {
        out.push_str("(?i)");
    }
    let mut first = true;
    for ch in term.trim().chars() {
        // Skip whitespace IN the term — the elastic separator below covers it (and any
        // fabricated PDF-layout whitespace), so the term's own spacing is also flexible.
        if ch.is_ascii_whitespace() {
            continue;
        }
        if !first {
            // Between two significant chars (whether or not whitespace separated them in
            // the term) allow arbitrary whitespace — this is what absorbs the fabricated
            // intra-word separators from a glyph-by-glyph PDF layout.
            out.push_str(WS);
        }
        // Escape this single char as a literal.
        out.push_str(&regex::escape(&ch.to_string()));
        first = false;
    }
    out
}

/// TRAILING employment/role PHRASES (Mechanism B), declared as DATA (mirroring the
/// context-row lexicon philosophy in `context.rs`). A run of 2+ comma/'and'-separated
/// Capitalized multi-word names IMMEDIATELY preceding one of these on the same line-run is a
/// person-name list (`A, B and C are employees of …`) — the FORWARD, in-prose analogue of
/// the role-HEADING `ctx:role-name` row. Recall-first: the list is deliberately broad and
/// may over-flag a Capitalized ORG run before one of these phrases — the SAFE side (a miss
/// is the leak), which review routing absorbs. Adding a phrase is one row here.
pub(crate) const TRAILING_ROLE_PHRASES: &[&str] = &[
    "are employees of",
    "is an employee of",
    "are directors of",
    "is a director of",
    "are officers of",
    "is an officer of",
    "are members of",
    "is a member of",
    "are partners of",
    "is a partner of",
];

/// The recognizer LABEL a NAME-PROPAGATION (Mechanism A) occurrence carries. It is a
/// recognizer NAME (a config string), NEVER a matched value, so it is audit-safe; it rides
/// [`Recognizer::Custom`] so a propagated span routes as the ENTITY family (a letter label
/// in AI-safe-labels mode), consistent with a directly-detected name, and is
/// distinguishable in the audit breakdown from an ordinary `name` heuristic match.
pub(crate) const PROPAGATED_NAME_LABEL: &str = "name:propagated";

/// Cap on the number of DISTINCT person-name VALUES the propagation pass will seed from in
/// one document (a bomb-bound). Beyond this many distinct name values, further NEW values are
/// ignored — a pathological input (thousands of distinct capitalized runs) cannot make the
/// pass compile+scan an unbounded number of per-value regexes.
pub(crate) const MAX_PROPAGATED_VALUES: usize = 500;

/// Cap on the TOTAL propagated candidates emitted in one document (a bomb-bound). Beyond
/// this the pass stops emitting — bounds the added candidate set on adversarial input (a
/// single value repeated a vast number of times), keeping memory + work bounded.
pub(crate) const MAX_PROPAGATED_CANDIDATES: usize = 5000;

/// Is `r` a person-NAME kind for the propagation seed set (Mechanism A)? TRUE ONLY for the
/// honorific/aggressive/closure/trailing-role [`Recognizer::Name`] heuristic; FALSE for
/// every id / amount / email / address / context row (a `ctx:dob` / `ctx:account-mrn`
/// value is NOT a person name and must NOT propagate).
///
/// DELIBERATE TRADE (review fix 1): `ctx:role-name` is EXCLUDED from seeding. Its FP class
/// is role-phrase BOILERPLATE ("Investment Manager", "Management Company", "Share Class"),
/// and propagation MULTIPLIED a single precision error document-wide — measured on the
/// flagship prospectus: +758 candidates, ALL `name:propagated` copies of role-name
/// boilerplate (one value ×311). A `ctx:role-name` candidate still FLAGS AT ITS OWN SITE
/// exactly as before — it just no longer propagates; a person name detected ONLY by
/// `ctx:role-name` (no honorific mention, no trailing-role list membership anywhere) is
/// the accepted recall cost. The propagated
/// [`Recognizer::Custom`]`("name:propagated")` label is also deliberately NOT a name kind
/// here, so propagated candidates never re-seed — propagation is ONE round.
pub(crate) fn is_person_name_kind(r: &Recognizer) -> bool {
    matches!(r, Recognizer::Name)
}

/// Cap on the TOTAL names Mechanism B ([`RedactionEngine::trailing_role_name_spans`]) will
/// emit in one document (a bomb-bound, mirroring [`MAX_PROPAGATED_VALUES`]). A pathological
/// comma-separated list of tens of thousands of Capitalized pairs before one role phrase
/// would otherwise emit an unbounded span set (measured pre-cap: 10k names ≈ 6.3s, 20k ≈
/// 24.9s through the downstream merge/gate). On overflow the pass STOPS emitting — a cap
/// hit means pathological input, and the engine is not the only line of review (honest
/// recall note: names past the cap in such input are not auto-flagged).
pub(crate) const MAX_TRAILING_ROLE_NAMES: usize = 500;

/// Cap on the TOTAL names the ANCHORED-name pass
/// ([`RedactionEngine::anchored_name_candidates`] — display-name-beside-email + name before
/// a parenthesized structured id) will emit in one document (a bomb-bound, mirroring
/// [`MAX_TRAILING_ROLE_NAMES`]). A pathological document with thousands of `<email>` /
/// `(NRIC …)` anchors each preceded by a Capitalized pair cannot emit an unbounded span
/// set. On overflow the pass STOPS emitting (honest recall note: a cap hit means
/// pathological input, and the engine is not the only line of review).
pub(crate) const MAX_ANCHORED_NAMES: usize = 500;

/// How many CHARS the anchored-name pass looks BACK from an anchor (`<` / `(`) for the
/// preceding Capitalized name run. A personal name is 2–4 tokens; 80 chars comfortably
/// covers it (plus a wrap) while bounding the per-anchor work to a constant window.
const ANCHOR_NAME_LOOKBACK_CHARS: usize = 80;

/// Maximum bytes of ID-LABEL text (`NRIC `, `Passport No. `, `UEN: `) allowed between the
/// opening `(` and the detected structured-id span in the paren-id anchor shape
/// `Name (NRIC S1234567D)`. Bounds the backward label walk to a constant; a longer gap is
/// prose in parentheses, not an id label.
const ANCHOR_ID_LABEL_BYTES: usize = 24;

/// Walk BACK from `pos` over at most a few spaces/tabs to an ASCII `<`, returning the `<`
/// byte index — the display-name-beside-email anchor shape `Name <user@host>` (the email
/// candidate starts right after the `<`, possibly with incidental spaces). Byte-safe: only
/// ASCII bytes are inspected, and the returned index is an ASCII byte's position (a char
/// boundary). `None` when the email is not `<`-bracketed. Pure, deterministic, O(1).
fn angle_open_before(text: &str, pos: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = pos;
    // Tolerate a couple of incidental spaces between `<` and the address (bounded).
    let mut budget = 4usize;
    while i > 0 && budget > 0 && matches!(bytes[i - 1], b' ' | b'\t') {
        i -= 1;
        budget -= 1;
    }
    (i > 0 && bytes[i - 1] == b'<').then(|| i - 1)
}

/// Walk BACK from `pos` (the start of a DETECTED structured-id span) over at most
/// [`ANCHOR_ID_LABEL_BYTES`] of id-LABEL bytes (ASCII letters, digits, space/tab, `.`,
/// `:`, `#`, `/`, `-`) to an ASCII `(`, returning the `(` byte index — the paren-id anchor
/// shape `Name (NRIC S1234567D)`. A newline, another paren, or any other byte in the gap
/// disqualifies (the id is not in a name-adjacent parenthetical). Byte-safe as above.
/// Pure, deterministic, O(1).
fn paren_open_before(text: &str, pos: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = pos;
    let mut budget = ANCHOR_ID_LABEL_BYTES;
    while i > 0 {
        let b = bytes[i - 1];
        if b == b'(' {
            return Some(i - 1);
        }
        if budget == 0 {
            return None;
        }
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b' '
            | b'\t'
            | b'.'
            | b':'
            | b'#'
            | b'/'
            | b'-' => {
                i -= 1;
                budget -= 1;
            }
            _ => return None,
        }
    }
    None
}

/// FIELD LABELS (round 4, Mechanism A), as DATA rows: a LINE-LEADING label followed by a
/// `:` (or a 2+-space / tab column gap — forms columnize) anchors the VALUE after it —
/// the forms/transcript class where the LABEL was flagged as role boilerplate while the
/// VALUE (`Student ID: A0219477B`) was missed entirely. Extending coverage = one row.
/// Matching is case-insensitive at line start (leading numbering/bullets stripped) on a
/// word boundary (the required separator enforces it — `Names:` never matches `name`).
pub(crate) const FIELD_LABELS: &[&str] = &[
    "matriculation no",
    "identity card",
    "date of birth",
    "registration no",
    "student id",
    "student no",
    "employee id",
    "client name",
    "passport no",
    "account no",
    "full name",
    "file ref",
    "case no",
    "suit no",
    "id no",
    "nric",
    "name",
    "dob",
    "fin",
    // Round 5 (GAP 2): ADDRESS field labels — a building-name address with no street
    // number (`One World Trade Center, 87th Floor, …`) slips the structured-address
    // recognizer, but the line-leading label + separator anchors it precisely. The bare
    // `address` row is deliberately included (recall-first); corpus drift was measured
    // on both scan paths (see the round-5 report) and did not flood.
    "registered office",
    "registered address",
    "business address",
    "correspondence address",
    "residential address",
    "address",
];

/// The FIELD_LABELS rows whose value is a PERSON NAME candidate. REVIEW FIX (round-4
/// review, HIGH): these are NO LONGER emitted as [`Recognizer::Name`] — a field emission
/// riding the Name kind SEEDED the always-on SAFE tier of `name_propagation_spans`,
/// which has no word-count floor, so a columnar `name:` line wrapping to a bare org
/// token (`JPMorgan`) re-flagged EVERY occurrence document-wide (+393 on the flagship
/// corpus, 2.3x review-list inflation). A PERSON-SHAPED value (see
/// [`is_person_shaped_field_value`]) is emitted under [`FIELD_NAME_LABEL`]
/// (`ctx:field-name` — person-family placeholders in AI-labels mode, EXCLUDED from every
/// propagation seed predicate); any other value after a name label (digits, ALL-CAPS
/// orgs, stock phrases) is emitted under [`FIELD_VALUE_LABEL`] (honest non-person kind).
/// Organic `Recognizer::Name` detections (honorific/list/anchored) keep seeding as
/// before — on a merged span the organic Name (priority 5) out-labels this ctx row (6),
/// so co-detected spans still seed via their organic primary.
const NAME_FIELD_LABELS: &[&str] = &["name", "full name", "client name"];

/// The attribution label of a PERSON-SHAPED name-field value (round-4 review fix):
/// `Recognizer::Context("ctx:field-name")`. ENTITY-family for PLACEHOLDER routing only
/// (see `assign_labels`); NEVER a propagation seed — `name_propagation_spans` seeds from
/// raw `Recognizer::Name` spans and `propagate_name_candidates` from
/// [`is_person_name_kind`] primaries, and this label is neither.
pub(crate) const FIELD_NAME_LABEL: &str = "ctx:field-name";

/// The attribution label of the OPT-IN ORGANISATION recognizer class (`organisations`
/// flag): `Recognizer::Context("ctx:org")`. Its OWN recognizer class, DISTINCT from every
/// person path. It is NOT a row in `context::CONTEXT_RECOGNIZERS`, so — exactly like
/// [`FIELD_VALUE_LABEL`] — `context::row_for_label` has no row for it, the additive ctx
/// gate treats it as ALWAYS-SATISFIED (never suppressed), and it carries priority 6 (loses
/// every overlap, so a person recognizer WINS on an overlapping span). It is ENTITY-family
/// for PLACEHOLDER routing only (see `assign_labels`) — an org renders `[A]`/`[B]`, NOT a
/// person marker — while being EXCLUDED from every propagation seed predicate
/// (`name_propagation_spans` / `propagate_name_candidates` seed from `Recognizer::Name`;
/// `ws_name_seeds_from_scan` seeds from `Name`/`ctx:role-name` only). Broad org detection is
/// FP-prone, so [`confidence_for`](RedactionEngine::confidence_for) PINS it to
/// [`Confidence::Low`] — the CAREFUL review tier, never quick-confirm/auto-accept, even under
/// a lowered quick-confirm floor.
pub(crate) const ORG_CONTEXT_LABEL: &str = "ctx:org";

/// Cap on the org candidates EACH arm (suffix-anchored / org-context) of
/// [`organisation_spans`](RedactionEngine::organisation_spans) emits per document (a
/// bomb-bound, mirroring [`MAX_TRAILING_ROLE_NAMES`]). Broad org detection is inherently
/// FP-prone; this bounds the added set on a large (962pp) doc and on adversarial input.
pub(crate) const MAX_ORG_NAMES: usize = 500;

/// ORG-SIGNAL WORDS for the org-context arm's person-vs-org discriminator. A Capitalized run
/// near an org-context cue that is PERSON-SHAPED ([`is_person_shaped_field_value`]) is emitted
/// as an org ONLY if it also carries one of these tokens (a real person name essentially never
/// does): a person-shaped run with NO org signal near a cue is left to the person path, not
/// flagged as an org. This is the ONLY tightening on the broad arm — and it never suppresses a
/// SUFFIX-anchored org (that arm does not consult this) — so recall on suffixed / org-worded
/// entities is unaffected. Whole-token, case-insensitive (dots/commas trimmed).
const ORG_WORDS: &[&str] = &[
    "fund",
    "funds",
    "sicav",
    "oeic",
    "ucits",
    "aif",
    "aifm",
    "index",
    "indices",
    "scheme",
    "schemes",
    "authority",
    "commission",
    "exchange",
    "board",
    "committee",
    "association",
    "institute",
    "foundation",
    "agency",
    "bureau",
    "council",
    "bank",
    "banks",
    "group",
    "trust",
    "trusts",
    "capital",
    "holding",
    "holdings",
    "partners",
    "management",
    "company",
    "companies",
    "corporation",
    "corp",
    "insurance",
    "securities",
    "investment",
    "investments",
    "adviser",
    "advisers",
    "advisor",
    "advisors",
    "depositary",
    "custodian",
    "registrar",
    "sponsor",
    "administrator",
    "services",
    "limited",
    "ltd",
    "llp",
    "llc",
    "plc",
    "berhad",
];

/// Is a SUFFIX-ANCHORED org match a bare DEFINITE-ARTICLE GENERIC — a leading article
/// (`The`/`A`/`An`/`This`/…) followed by ONLY the suffix word, i.e. NO proper-noun name
/// (`The Company`, `A Group`, `The Bank`)? Such a match carries no organisation identity — it
/// is the generic the definite-article negative forbids — so it is dropped. A match with a
/// real name after the article (`The BlackRock Group`, `The Management Company`) is KEPT
/// (≥2 tokens remain after the article). Whole-token, case-insensitive. Pure, deterministic.
fn org_match_is_generic(m: &str) -> bool {
    let mut toks = m.split_whitespace();
    let Some(first) = toks.next() else {
        return true;
    };
    let is_article = matches!(
        first.to_ascii_lowercase().as_str(),
        "the" | "a" | "an" | "this" | "that" | "these" | "those"
    );
    // Article + exactly one more token (the suffix) ⇒ generic. Article + ≥2 (name + suffix)
    // ⇒ a real org; no leading article ⇒ a real org.
    is_article && toks.count() <= 1
}

/// Is any whitespace-token of `run` (dots/commas trimmed, lowercased) an [`ORG_WORDS`] entry?
/// Pure, deterministic; used only by the org-context arm of [`organisation_spans`].
fn run_contains_org_word(run: &str) -> bool {
    run.split_whitespace().any(|tok| {
        let t = tok
            .trim_matches(|c: char| c == '.' || c == ',')
            .to_lowercase();
        ORG_WORDS.contains(&t.as_str())
    })
}

/// The SUFFIX-ANCHORED organisation regex (arm (a) of [`organisation_spans`]): a Capitalized
/// multi-token run (`{1,6}` tokens, each an uppercase-initial word optionally carrying
/// internal `&`/`.`/`'`/`-`/digits — `J.P.`, `BlackRock`, `AllianceBernstein`) immediately
/// followed by an ORG SUFFIX from a fixed list. WRAP-TOLERANT: every inter-token gap accepts
/// at most ONE line break (the same `≤1-newline` rule the name machinery uses), so a
/// line-wrapped company name still closes; a blank line is never crossed. The suffix
/// alternation is LONGEST-first (the `regex` crate is leftmost-first, no backtracking → LINEAR
/// TIME, no ReDoS): dotted / multiword forms before their prefixes (`S.A.R.L.` before `S.A.`,
/// `Incorporated` before `Inc`, `Company` before `Co`). Compiled once from a fixed static.
/// The org SUFFIX alternation shared by BOTH suffix-anchored arms (the mixed-case arm
/// [`org_suffix_regex`] verbatim, and the ALL-CAPS arm [`org_suffix_caps_regex`] wrapped
/// `(?i:…)`). Longest/most-specific first (leftmost-first alternation → linear-time, no
/// ReDoS). `\.?` absorbs a trailing abbreviation dot after a letter-ending suffix; the
/// inherently-dotted forms carry their dots explicitly. Hoisted to module scope so the two
/// arms can never drift apart (one list, two casings).
const ORG_SUFFIX_ALT: &str = r"(?:S\.A\.R\.L\.?|L\.L\.C\.?|N\.V\.?|B\.V\.?|S\.A\.?|Pte\.?[ \t]+Ltd|Sdn[ \t]+Bhd|soci[ée]t[ée][ \t]+anonyme|Incorporated|Corporation|Berhad|Limited|Holdings|Associates|Management|Partners|Advisers|Advisors|Company|Capital|Group|Trust|Bank|GmbH|Corp|Inc|Ltd|LLP|LLC|PLC|AG|LP|&[ \t]+Co|Co)\b\.?";

fn org_suffix_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Inter-token gap tolerating at most one line break (spaces/tabs, or a single wrap).
        const G: &str = r"(?:[ \t]+(?:\r?\n[ \t]*)?|\r?\n[ \t]*)";
        // A Capitalized run token. A `.` is an INTRA-name abbreviation dot ONLY when it is
        // immediately followed by an alphanumeric (`J.P.`, `E.ON`); a `.` followed by
        // whitespace + a capital is a SENTENCE break (`Ming. The`), so it is NOT part of the
        // token — the run STOPS there and cannot bridge into the next sentence.
        const TOK: &str = r"\p{Lu}(?:[\p{L}0-9&'’\-]|\.[\p{L}0-9])*";
        let src = format!(r"(?:{TOK}{G}){{1,6}}{ORG_SUFFIX_ALT}");
        Regex::new(&src).expect("org suffix-anchored pattern must compile")
    })
}

/// The ALL-CAPS SUFFIX-ANCHORED organisation regex (arm (a2) of [`organisation_spans`],
/// the finance-corpus recall round): an ALL-CAPS token run immediately followed by the
/// SAME org suffix list matched CASE-INSENSITIVELY (`(?i:…)` around [`ORG_SUFFIX_ALT`]).
///
/// WHY a separate arm: the mixed-case arm's suffix literals are case-SENSITIVE
/// (`Pte Ltd`, `Inc`, `GmbH`), so `HELICON ANALYTICS PTE LTD` (a bank-statement
/// narrative) and `NORTHBRIDGE CAPITAL PARTNERS PTE. LTD.` (an agreement party clause)
/// never matched even with an explicit suffix and `organisations: true` — the verified
/// org-recall miss. Making the EXISTING arm's suffix `(?i)` would let a lowercase `ltd`/
/// `co` anchor an ordinary Capitalized prose run (an FP widening of the default arm), so
/// the case-insensitive suffix is ANCHORED to ALL-CAPS run tokens only (each token ≥2
/// chars, uppercase letters/digits/`&`/`'`/`-` — no lowercase anywhere in the run), which
/// ordinary prose never produces. Wrap-tolerant like the mixed-case arm; linear-time.
/// Emits `ctx:org` via the same pass: careful-review pinned, NEVER a propagation seed.
fn org_suffix_caps_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        const G: &str = r"(?:[ \t]+(?:\r?\n[ \t]*)?|\r?\n[ \t]*)";
        // An ALL-CAPS token: uppercase-initial, then ≥1 more uppercase/digit/join chars
        // (dots allowed only before an alphanumeric, mirroring the mixed-case TOK) — so
        // a lone initial or a lowercase-bearing word never joins the run.
        const TOK_CAPS: &str = r"\p{Lu}(?:[\p{Lu}0-9&'’\-]|\.[\p{Lu}0-9])+";
        // A standalone `&` may join two caps tokens (`GRAVENOR & PIKE LLP` — the law-firm
        // shape; the mixed-case arm shares this limitation but is left byte-identical).
        let src = format!(r"(?:{TOK_CAPS}{G}(?:&{G})?){{1,6}}(?i:{ORG_SUFFIX_ALT})");
        Regex::new(&src).expect("org caps-suffix pattern must compile")
    })
}

/// The phone-LABEL cue lexicon for the always-on CUED phone arm
/// ([`RedactionEngine::cued_phone_spans`], review H1+H2). A label from this list
/// directly preceding a digit run (within [`PHONE_CUE_LOOKBACK_CHARS`]) sanctions the
/// RELAXED joiners — same-line multi-space runs and a single line wrap — that the
/// column-gap guard structurally refuses on UNCUED runs. Includes the SG mobile
/// vocabulary (review M2: `mobile` / `hp` / `handphone` / `cell` / the `m:` label —
/// folded into `ctx:phone-wrapped`'s lexicon too). `m:` keeps its colon (the colon IS
/// the anchor; a bare one-letter `m` would be noise). OUR constant strings, matched
/// case-insensitively on a left word boundary.
pub(crate) const PHONE_CUE_LEXICON: &[&str] = &[
    "tel",
    "telephone",
    "phone",
    "fax",
    "mobile",
    "hp",
    "handphone",
    "cell",
    "hotline",
    "freephone",
    "enquiries",
    "enquiry",
    "m:",
];

/// How many CHARS the cued-phone arm looks BACK from a digit run for its label. Short
/// on purpose: the label DIRECTLY precedes the number (`Tel: `, `Mobile — `, `M:`);
/// a distant mention is prose, not a label.
const PHONE_CUE_LOOKBACK_CHARS: usize = 24;

/// Cap on the candidates the cued-phone arm emits per document (the standard
/// bomb-bound pattern).
const MAX_CUED_PHONES: usize = 500;

/// Is a cued-phone match PLAUSIBLE: 7–15 digits (national significant numbers are 7+,
/// E.164 caps at 15 — the same bound `ctx:phone-wrapped` validates) AND the ordinary
/// phone row's >=8-char floor. Pure, deterministic.
fn cued_phone_plausible(s: &str) -> bool {
    let digits = s.bytes().filter(u8::is_ascii_digit).count();
    (7..=15).contains(&digits) && s.chars().count() >= 8
}

/// The SAME-LINE relaxed cued-phone shape: digit groups with unrestricted space/tab
/// runs between them (the `Tel: 6438  1290` double-space form the column guard refuses
/// uncued). Never crosses a newline.
fn cued_phone_sameline_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\+?\d[\d\-\t \u{00A0}\u{202F}().]*\d(?:[ \t]*(?:x|ext\.?)[ \t]*\d+)?")
            .expect("cued same-line phone pattern must compile")
    })
}

/// The SINGLE-WRAP cued-phone shape (`Tel: 6438\n1290`): a same-line run, exactly one
/// line break, a second same-line run — the `ctx:phone-wrapped` shape, sanctioned here
/// by the LABEL instead of the opt-in toggle.
fn cued_phone_wrapped_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\+?\d[\d\-\t \u{00A0}\u{202F}().]*\d[ \t]*\r?\n[ \t]*\d[\d\-\t \u{00A0}\u{202F}().]*\d(?:[ \t]*(?:x|ext\.?)[ \t]*\d+)?",
        )
        .expect("cued wrapped phone pattern must compile")
    })
}

/// Does a [`PHONE_CUE_LEXICON`] label sit within the [`PHONE_CUE_LOOKBACK_CHARS`]-char
/// window BEFORE `start` and POINT AT it? Cue-shadow hardening (the phone-guard
/// review, re-priced after its own review): a cue on the SAME line as `start` always
/// points at it; a cue on the line ABOVE points at it ONLY when the label is
/// LINE-FINAL — exactly one line break between the cue's end and `start`, with nothing
/// but `[ \t:]` (plus the `\r` of a `\r\n`) between the cue and that break
/// ([`phone_cue_reaches_start`]). That one rule keeps BOTH shipped recall classes —
/// same-line labels (`Tel: 6438  1290`) and label-on-its-own-line fields
/// (`Tel:\n6438  1290`, a routine letterhead/table extraction artifact) — while the
/// classic shadow stays dead: in `Tel: 6438 1290\n2026   88.00` a full phone sits
/// between the cue and the newline, so the label never sanctions the next line's
/// columns. (The cued single-wrap arm is unaffected either way: it anchors at the
/// SAME-LINE match start — [`RedactionEngine::cued_phone_spans`] probes the cue at
/// `m.start()` only.) Case-insensitive; left edge word-bounded (so `hotel` never cues
/// via `tel`); the right edge is word-bounded for word cues, while a cue ending in `:`
/// is anchored by its own colon (so `M:9123` still cues). Confidentiality-clean
/// (consults OUR constant lexicon; returns a bool). Pure, deterministic.
fn phone_cue_before(text: &str, start: usize) -> bool {
    let lo = floor_char_boundary_back(text, start, PHONE_CUE_LOOKBACK_CHARS);
    let win = text[lo..start].to_lowercase();
    for cue in PHONE_CUE_LEXICON {
        let mut from = 0usize;
        while let Some(rel) = win[from..].find(cue) {
            let s = from + rel;
            let left_ok = s == 0
                || !win[..s]
                    .chars()
                    .next_back()
                    .map(is_word_char)
                    .unwrap_or(false);
            let e = s + cue.len();
            let right_ok = cue.ends_with(':')
                || e == win.len()
                || !win[e..].chars().next().map(is_word_char).unwrap_or(false);
            if left_ok && right_ok && phone_cue_reaches_start(&win[e..]) {
                return true;
            }
            from = s + 1;
            if from >= win.len() {
                break;
            }
        }
    }
    false
}

/// Does a phone-label cue REACH the digit run, given `rest` = the lookback window's
/// tail from the cue's end up to the match start? Same line (no line break in `rest`):
/// always. Across a line break: ONLY the line-final-label bridge — exactly ONE `\n`,
/// and everything between the cue's end and it is `[ \t:]`-class (an optional `\r`
/// directly before the `\n` is part of the CRLF boundary, not content), i.e. the label
/// ends its line and so points at the NEXT line's value cell. Anything else between
/// cue and newline (a full phone, column text) means the label was consumed by its own
/// line and never sanctions the next one. KNOWN ACCEPTED TRADEOFF (recall-first,
/// ledger-documented): a BARE label line directly above a pure column row
/// (`Tel:\n03/06/2026   88.00`) cues that row and can emit a narrow over-flag
/// candidate — over-flagging is the safe side; the common shadow (a phone already on
/// the cue's line) stays dead. Pure, deterministic.
fn phone_cue_reaches_start(rest: &str) -> bool {
    let Some(nl) = rest.find('\n') else {
        return true; // same line — the cue directly precedes the digits.
    };
    if rest[nl + 1..].contains('\n') {
        return false; // two or more breaks — a distant label, never this field's.
    }
    let before = rest[..nl].strip_suffix('\r').unwrap_or(&rest[..nl]);
    before.chars().all(|c| matches!(c, ' ' | '\t' | ':'))
}

/// The label-cue lexicon for the 8-CHAR BIC form ([`RedactionEngine::bic_labeled_spans`]).
/// The 8-char shape is word-shaped ("DEUTSCHE" carries the valid ISO country "SC" at
/// chars 5–6), so structure alone would FP on ordinary caps words — a nearby BIC/SWIFT
/// label is what corroborates. OUR constant strings, never document text. Lowercased by
/// the window probe (`keyword_in_window` case-folds both sides).
const BIC_LABEL_LEXICON: &[&str] = &["bic", "swift"];

/// The word-bounded 8-OR-11-char BIC shape scanned by the LABEL-CUED pass (both forms
/// fire near a BIC/SWIFT label; structure is checked by [`bic_structure_valid`]).
fn bic_any_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
            .expect("bic pattern must compile")
    })
}

/// The STANDALONE plausibility validator for the always-on 11-char BIC row: full
/// [`bic_structure_valid`] structure PLUS — for a LETTER-ONLY match — the `XXX`
/// head-office branch. WHY: ordinary 11-letter caps words pass the bare structure
/// check whenever chars 5–6 coincide with an ISO country (`INSTRUCTION` → RU,
/// `TRANSACTION` → SA, `PARTNERSHIP` → NE, `SHAREHOLDER` → EH — all verified FPs on
/// caps legal headings), and no English word ends in `XXX` or carries a digit. A real
/// letter-only NON-`XXX` branch BIC (`DEUTDEFFVIE`) is NOT missed by the engine: it
/// rides the label-cued pass ([`RedactionEngine::bic_labeled_spans`]) — in a real
/// payment document a BIC is labeled; only the UNLABELED bare mention of that narrow
/// shape is the documented residual. Pure, deterministic.
fn bic11_standalone_valid(s: &str) -> bool {
    bic_structure_valid(s) && (s.bytes().any(|b| b.is_ascii_digit()) || s.ends_with("XXX"))
}

/// The phone row's MINIMUM-LENGTH validator: at least 8 chars — EXACTLY the length
/// bound the old `\d[…]{6,}\d` pattern carried (2 boundary digits + >=6 interior
/// chars), preserved so the column-gap rebuild changes ONLY the separator structure,
/// never which single-field runs qualify (e.g. the 8-char `12-34-56` UK sort-code shape
/// still rides `phone` as its broad sibling, while the bare 7-digit run inside an
/// un-flagged NRIC stays un-matched, both as before). Pure, deterministic.
fn phone_min_len_valid(s: &str) -> bool {
    s.chars().count() >= 8
}

/// The attribution label of the PAN LAST-4 recognizer (RATIFIED, the finance round):
/// `Recognizer::Context("ctx:pan-last4")`. A masked / referenced payment-card tail —
/// `Card ending 2144`, `ending in 2144`, `last four digits 2144`, `**** **** **** 2144`,
/// `●●●● ●●●● ●●●● 2144`, `XXXX-XXXX-XXXX-2144`, `x-2144` — re-identifies the card
/// line a full PAN redaction
/// removed, so it is SURFACED; but a last-4 is also a legitimate everyday reference, so
/// it is ADVISORY (the sg:nric-loose posture): `advisory: true` on the DTO via
/// [`RedactionEngine::is_aggressive`], DEFAULT-OFF in the apply accept-set — the human
/// opts IN. CUE-ANCHORED ONLY: every arm of the pattern carries its cue (`ending` /
/// `last four` / a masked-PAN prefix) IN the match, so a bare 4-digit number can never
/// fire. ALWAYS-ON when the card family is on (the ratified call — the cue makes it
/// precise and a card tail is a payment identifier in any document class, not a
/// PCI-profile concern; it rides `builtins.credit_card`, so disabling the card family
/// disables the tail reference with it). Like [`FIELD_VALUE_LABEL`] / [`ORG_CONTEXT_LABEL`]
/// it has no `context::CONTEXT_RECOGNIZERS` row: the additive ctx gate treats it as
/// always-satisfied, `confidence_for` gives the no-row Medium default (CAREFUL review),
/// and priority 6 lets any precise recognizer out-label it on overlap. NEVER a
/// propagation seed (a `Context` kind).
pub(crate) const PAN_LAST4_LABEL: &str = "ctx:pan-last4";

/// The attribution label of the ANCHORED ALL-CAPS person-name arm (the finance-corpus
/// recall round): `Recognizer::Context("ctx:caps-name")`. Like [`FIELD_VALUE_LABEL`] /
/// [`ORG_CONTEXT_LABEL`] it is NOT a row in `context::CONTEXT_RECOGNIZERS`, so the
/// additive ctx gate treats it as always-satisfied (the pass does its OWN cue gating
/// before emitting — see [`RedactionEngine::caps_person_spans`]) and `confidence_for`
/// PINS it to `Medium` (CAREFUL review under the default floor, never quick-confirm).
/// The pin is EXPLICIT, not the no-row default (review HIGH): a caps span merged with a
/// satisfied `ctx:role-name` sibling inherits the SPAN's Close proximity, and the
/// label-ASC tie-break elects this label primary — without the pin that promoted a
/// caps-heading FP to High / tier-1 bulk-accept. Priority 6 (a `Context`), so any
/// precise recognizer out-labels it on overlap.
///
/// SEEDING (the AMPLIFICATION-CLASS decision, deliberate): NEVER a propagation seed. An
/// ALL-CAPS FP (`PRIVATE AND CONFIDENTIAL`) propagating document-wide is the recurring
/// flood bug (fixed 3× before), so this label is a `Context` kind — excluded from
/// `name_propagation_spans` (seeds from `Recognizer::Name` raw spans),
/// `propagate_name_candidates` (seeds from [`is_person_name_kind`] primaries = `Name`
/// only), and the PDF `ws_name_seeds_from_scan` (seeds from `Name`/`ctx:role-name`, and
/// its person-shape gate requires a lowercase letter anyway). ALL-CAPS occurrences of a
/// MIXED-CASE detected name are instead covered by the propagation pass's own
/// caps-insensitive ECHO tier (see `propagate_name_candidates`).
pub(crate) const CAPS_NAME_LABEL: &str = "ctx:caps-name";

/// Cap on the candidates [`RedactionEngine::caps_person_spans`] emits per document (the
/// existing bomb-bound pattern, mirroring [`MAX_ORG_NAMES`]).
pub(crate) const CAPS_NAME_MAX: usize = 500;

/// STOPWORD tokens that SPLIT an ALL-CAPS run (never part of a person name). A heading
/// like `STATEMENT OF ACCOUNT` / `TERMS AND CONDITIONS` / `PRIVATE AND CONFIDENTIAL`
/// splits into 1-token fragments (below the 2-token floor → nothing emitted), which is
/// the FP guard that lets the arm stay recall-first on real names. Includes the common
/// finance-document HEAD NOUNS (`STATEMENT`, `ACCOUNT`, `CARD`, …) so a caps document
/// title near a cue never reads as a name. Compared uppercase (the run is all-caps).
const CAPS_SPLIT_STOPWORDS: &[&str] = &[
    // Function words — a person name never contains these.
    "OF",
    "THE",
    "AND",
    "TO",
    "FOR",
    "IN",
    "ON",
    "AT",
    "BY",
    "AS",
    "OR",
    "AN",
    "IS",
    "ARE",
    "BE",
    "NO",
    "NOT",
    "ALL",
    "ANY",
    "PER",
    "WITH",
    "FROM",
    "THIS",
    "THAT",
    "OUR",
    "YOUR",
    "ITS",
    "RE",
    "VIA",
    "WE",
    "YOU",
    // Finance-document head nouns (caps headings/titles, never name tokens).
    "STATEMENT",
    "ACCOUNT",
    "CARD",
    "TABLE",
    "TOTAL",
    "BALANCE",
    "INVOICE",
    "FORM",
    "PAYSLIP",
    "CONFIRMATION",
    "INSTRUCTION",
    "ADVICE",
    "AGREEMENT",
    "RESOLUTION",
    "SUMMARY",
    "NOTICE",
    "SCHEDULE",
    "APPENDIX",
    "ANNEX",
    "SECTION",
    "PAGE",
];

/// TRANSACTION-RAIL / finance-label CUE tokens for the ALL-CAPS person arm. A cue token
/// INSIDE the matched run (it also SPLITS the run — `FAST TRANSFER FR DARIUS OKONKWO-LIM`
/// splits at `TRANSFER`, corroborating the `FR DARIUS OKONKWO-LIM` remainder) or a cue
/// within the ±window corroborates the caps sub-run. These are the payment-narrative
/// words that precede a COUNTERPARTY name in bank/card statements (`CHEQUE 004512 PRIYA
/// VENKATESAN`, `ZELLE FROM TREVOR OAKENSHIELD`) — the verified transaction-narrative
/// person leaks. Uppercase-compared in-run; lowercased for the window probe.
const CAPS_NAME_CUES: &[&str] = &[
    "TRANSFER",
    "CHEQUE",
    "CHECK",
    "ZELLE",
    "GIRO",
    "PAYMENT",
    "REMITTANCE",
    "REMITTER",
    "PAYEE",
    "PAYER",
    "PAYROLL",
    "SALARY",
    "WIRE",
    "ACH",
    "ATTN",
    "BENEFICIARY",
    // Role/finance labels (the ctx:role-name cue vocabulary's caps-relevant core), so a
    // labeled caps name (`ACCOUNT HOLDER: DARIUS OKONKWO-LIM`, `TRADER: …`) corroborates
    // even where the mixed-case row's greedy run swallows the label.
    "DIRECTOR",
    "TRADER",
    "CUSTOMER",
    "CARDHOLDER",
    "SHAREHOLDER",
    "BORROWER",
    "GUARANTOR",
    "APPLICANT",
    "INSURED",
    "POLICYHOLDER",
    "HOLDER",
    "TRUSTEE",
    "SECRETARY",
    "CHAIRMAN",
];

/// The ALL-CAPS token-run shape for [`RedactionEngine::caps_person_spans`]: 2–11
/// whitespace-joined ALL-CAPS tokens on ONE visual line (each token ≥2 chars, uppercase
/// letters with optional interior `-`/`'` joins — `OKONKWO-LIM`, `O'BRIEN` are one token;
/// digits do NOT join, so `CHEQUE 004512 PRIYA VENKATESAN` yields two separate runs).
/// The generous 11-token ceiling exists only so the SPLITTER sees the whole narrative
/// line; the emitted sub-runs are floored/ceilinged at 2–4 tokens.
fn caps_run_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        const TOK: &str = r"\p{Lu}(?:['’]?\p{Lu}|-\p{Lu})+";
        let src = format!(r"{TOK}(?:[ \t]+{TOK}){{1,10}}");
        Regex::new(&src).expect("caps-run pattern must compile")
    })
}

/// The ORG-CONTEXT organisation regex (arm (b) of [`organisation_spans`] — the BROAD,
/// higher-FP arm): an org-context CUE (`incorporated in`, `registered in`, `a company`,
/// `trustee`, `manager`, `sponsor`, `administrator`, `registrar`, `auditor to`, `legal
/// adviser`, …), then a bounded gap (spaces/punctuation, an optional single line break, an
/// optional leading article), then a captured Capitalized RUN of ≥2 tokens (group 1). The
/// ≥2-token floor is what excludes a definite-article generic (`the Company`/`the Fund`/`the
/// Manager` — a single Capitalized token). Linear-time (bounded `{1,5}` — no ReDoS). Compiled
/// once. The person-vs-org discrimination + the person-overlap exclusion happen in the pass,
/// NOT here.
fn org_context_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // A Capitalized run of ≥2 tokens (`{1,5}` extra after the first), SENTENCE-SAFE token
        // shape (a `.` is intra-name only when immediately followed by an alphanumeric — a
        // `. ` + capital is a sentence break the run cannot cross), same as the suffix arm.
        // Same-line only for the run (an org name near a cue is on one line).
        const TOK: &str = r"\p{Lu}(?:[\p{L}0-9&'’\-]|\.[\p{L}0-9])*";
        let run = format!(r"{TOK}(?:[ \t]+{TOK}){{1,5}}");
        // Org-context CUES (case-insensitive). The ratified BROAD set.
        const CUE: &str = r"(?i:incorporated in|registered in|a company|trustee|manager|sponsor|administrator|registrar|auditor to|legal adviser)";
        // Cue, then a bounded gap: spaces/commas/colons/dots, one optional wrap, then up to
        // TWO short lowercase connector/article words (`the`, `is`, `of`, `by`, … — so
        // `trustee is State Street Bank` / `manager of BlackRock Group` reach the run) — then
        // the captured run. Bounded `{0,2}` (linear-time, no ReDoS).
        const FILLER: &str =
            r"(?:(?i:the|a|an|its|their|is|are|was|were|of|being|for|to|by|as|and)[ \t]+)";
        let src = format!(r"{CUE}[ \t,:.]*(?:\r?\n[ \t]*)?{FILLER}{{0,2}}({run})");
        Regex::new(&src).expect("org-context pattern must compile")
    })
}

/// Is a captured name-field VALUE person-shaped (round-4 review fix 2)? An optional
/// honorific, then 2–4 Capitalized tokens (dotted interior initials allowed; the final
/// token may carry an abbreviation dot — `Tan Wei Ming Jr.`), NO digit anywhere, and at
/// least one lowercase letter (an ALL-CAPS org line is not a person). `Name: 12345`,
/// `Name: see attached`, `Name: JPMorgan` (single token) all fail — they get the typed
/// [`FIELD_VALUE_LABEL`] instead of a person-family label. Pure, deterministic.
pub(crate) fn is_person_shaped_field_value(v: &str) -> bool {
    if v.chars().any(|c| c.is_ascii_digit()) || !v.chars().any(char::is_lowercase) {
        return false;
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:(?:Mr|Mrs|Ms|Mdm|Miss|Dr|Prof|Professor|Justice|Judge|Hon)\.?[ \t]+)?(?:(?:\p{Lu}\p{L}+(?:-\p{Lu}\p{L}+)*|\p{Lu}\.)[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}){1,3}\p{Lu}\p{L}+(?:-\p{Lu}\p{L}+)*\.?$",
        )
        .expect("person-shaped field-value pattern must compile")
    })
    .is_match(v)
}

/// The audit/attribution label of a NON-name field value (round 4, Mechanism A):
/// `Recognizer::Context("ctx:field-id")`. KIND MAPPING (per the labels.rs taxonomy):
/// name-labeled fields → `Recognizer::Name` (ENTITY family, letter placeholders in
/// AI-safe-labels mode, seeds propagation); every other label → this `ctx:` label (TYPED
/// family, renders `ID (field-id)`, careful review — `row_for_label` has no row for it,
/// so the additive ctx gate treats it as always-satisfied and it is NEVER suppressed;
/// priority 6 means any precise recognizer that also matches the value out-labels it,
/// e.g. a `Name: …`-adjacent NRIC keeps its `sg:nric` label on overlap).
pub(crate) const FIELD_VALUE_LABEL: &str = "ctx:field-id";

/// Cap on total field-value emissions per document (the existing caps pattern).
pub(crate) const MAX_FIELD_VALUES: usize = 500;

/// Max BYTE length of a captured field value (label-line part and joined continuation
/// alike). A longer rest-of-line is prose, not a form value — skipped entirely.
const MAX_FIELD_VALUE_BYTES: usize = 120;

/// If `led` (a line already [`strip_list_lead`]-ed) starts with a FIELD LABEL + its
/// separator, return `(label, value_offset_in_led)` where the value starts (untrimmed).
/// Separator = optional spaces/tabs then `:`, OR a tab, OR a run of 2+ spaces (the
/// columnar form). A single space is NOT a separator (prose `Name of the fund …` never
/// matches). Case-insensitive ASCII label compare. Pure, deterministic.
fn field_label_at(led: &str) -> Option<(&'static str, usize)> {
    for label in FIELD_LABELS {
        if led.len() < label.len() || !led.is_char_boundary(label.len()) {
            continue;
        }
        if !led[..label.len()].eq_ignore_ascii_case(label) {
            continue;
        }
        let rest = &led[label.len()..];
        // Tolerate one abbreviation dot after the label (`ID No.: 123`, `Student No.  X`).
        let rest = rest.strip_prefix('.').unwrap_or(rest);
        // Colon form: optional spaces/tabs, then `:`.
        let after_ws = rest.trim_start_matches([' ', '\t']);
        if let Some(v) = after_ws.strip_prefix(':') {
            let off = led.len() - v.len();
            return Some((label, off));
        }
        // Columnar form: a tab, or 2+ spaces.
        if rest.starts_with('\t') || rest.starts_with("  ") {
            let v = rest.trim_start_matches([' ', '\t']);
            let off = led.len() - v.len();
            return Some((label, off));
        }
    }
    None
}

/// ROLE-LIST HEADERS (round 3, Mechanism 4), as DATA rows: a line that IS one of these
/// (case-insensitive, allowing leading numbering/bullets and a trailing colon) anchors a
/// VERTICAL NAME LIST — the real-prospectus layout that printed 12 conducting officers as
/// a bare column under a `CONDUCTING OFFICERS` header with NO honorific, NO inline role,
/// NO bio: nothing else in the engine could anchor them (both scan routes emitted zero).
/// The header itself is the anchor. Extending coverage = adding a row here.
pub(crate) const ROLE_LIST_HEADERS: &[&str] = &[
    "board of directors",
    "conducting officers",
    "executive officers",
    "management team",
    "investment committee",
    "supervisory board",
    "management board",
    "directors",
    "officers",
];

/// Max lines scanned BELOW a role-list header (bomb-bound: a header can never sweep an
/// unbounded page run; real officer/director columns are far shorter).
pub(crate) const MAX_HEADER_LIST_LINES: usize = 40;

/// Cap on the TOTAL names the header-list pass emits per document (the existing caps
/// pattern, mirroring [`MAX_TRAILING_ROLE_NAMES`]).
pub(crate) const MAX_HEADER_LIST_NAMES: usize = 500;

/// Is `line` (one visual line, no `\n`) a ROLE-LIST HEADER row? Strips leading
/// numbering/bullets/whitespace and a trailing `:`/whitespace, then requires the line to
/// END WITH one of the [`ROLE_LIST_HEADERS`] rows (case-insensitive) on a word boundary —
/// real prospectus headers carry a QUALIFIER prefix (`MANAGEMENT COMPANY CONDUCTING
/// OFFICERS`, the verbatim JPMIF header), so exact equality missed the very layout this
/// pass exists for. Bounded at 60 bytes (a role header is short; the prose sentence
/// `Role of the conducting officers The conducting officers supervise…` is rejected on
/// length). Pure, deterministic.
fn is_role_list_header(line: &str) -> bool {
    let inner = strip_list_lead(line).trim_end_matches([':', ' ', '\t']);
    if inner.is_empty() || inner.len() > 60 {
        return false;
    }
    // The QUALIFIER prefix before the header row must read like a HEADER, not a PROSE
    // TAIL (review finding F1): a sentence ending in the header word — "as appointed by
    // the directors", "the following persons are officers" — would otherwise anchor a
    // name column and, via propagation, over-flag document-wide. A real header's prefix
    // words are ALL-CAPS or Title-Case ("MANAGEMENT COMPANY CONDUCTING OFFICERS") or a
    // short title connector ("The Directors", "Board of Directors"); a prose tail carries
    // lowercase content words (as/by/appointed/following/persons/are). So: every prefix
    // word must be Title-Case/ALL-CAPS (first char uppercase) OR a title connector. This
    // only TIGHTENS (rejects more) — it can never widen recall, and real headers still
    // fire (verified against the JPMIF officer header).
    const CONNECTORS: &[&str] = &["of", "and", "the", "for", "to", "&", "-"];
    let is_header_prefix = |prefix: &str| {
        prefix.split_whitespace().all(|w| {
            CONNECTORS.contains(&w.to_lowercase().as_str())
                || w.chars().next().is_some_and(|c| c.is_uppercase())
        })
    };
    let lc = inner.to_lowercase();
    ROLE_LIST_HEADERS.iter().any(|h| {
        lc.ends_with(h) && {
            let pre = lc.len() - h.len();
            // Word boundary before the suffix: start-of-line or a non-alphanumeric byte
            // (a UTF-8 continuation byte is >= 0x80, never ASCII-alphanumeric, so the
            // single-byte check is boundary-safe on multibyte text).
            (pre == 0 || !lc.as_bytes()[pre - 1].is_ascii_alphanumeric())
                // Check the prefix in ORIGINAL case (not the lowercased copy) so the
                // Title-Case/ALL-CAPS test is meaningful.
                && is_header_prefix(&inner[..pre])
        }
    })
}

/// Strip LEADING list decoration from a line: whitespace, bullet chars (`-`, `*`, `•`),
/// and a numbering token (digits optionally followed by `.` or `)`). Deliberately does
/// NOT strip a letter followed by `.` — that is an INITIAL (`J. R. Surname`), part of the
/// name. Returns the remaining slice. Pure, deterministic, single forward walk.
fn strip_list_lead(line: &str) -> &str {
    let mut rest = line;
    loop {
        let t = rest.trim_start_matches([' ', '\t', '-', '*', '\u{2022}']);
        // A numbering token: digits then an optional `.`/`)`.
        let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 {
            let after = &t[digits..];
            let after = after.strip_prefix(['.', ')']).unwrap_or(after);
            if after.len() < t.len() || t.len() < rest.len() {
                rest = after;
                continue;
            }
        }
        if t.len() < rest.len() {
            rest = t;
            continue;
        }
        return t;
    }
}

/// ROLE-TITLE words for the header-list pass's boilerplate guard (round 3, Mechanism 4).
/// The interleaved real-world layout alternates NAME lines with ROLE lines (`Philippe
/// Ringard\nManaging Director, Fund Administration\n…`), and a bare role line
/// (`Managing Director`) is SHAPE-identical to a 2-token name — emitting it floods the
/// ENTITY family with boilerplate (the round-2 review's amplification class: measured
/// `Managing Director` ×17 on the flagship corpus). A candidate line whose run contains
/// ANY of these words (case-insensitive, whole token) is a ROLE line: skipped, list
/// continues. A real person name never carries one of these as a token.
const ROLE_TITLE_WORDS: &[&str] = &[
    "director",
    "directors",
    "officer",
    "officers",
    "manager",
    "managers",
    "managing",
    "executive",
    "chairman",
    "chairperson",
    "chair",
    "president",
    "secretary",
    "treasurer",
    "trustee",
    "partner",
    "chief",
    "head",
];

/// Is any whitespace-token of `run` (dots trimmed, lowercased) a [`ROLE_TITLE_WORDS`]
/// entry? Pure, deterministic; used only by the header-list pass.
pub(crate) fn run_contains_role_title(run: &str) -> bool {
    run.split_whitespace().any(|tok| {
        let t = tok.trim_matches('.').to_lowercase();
        ROLE_TITLE_WORDS.contains(&t.as_str())
    })
}

/// The compiled ROLE-LIST NAME-LINE shape (round 3, Mechanism 4): a line that is NOTHING
/// BUT a capitalized person-name run — an optional honorific, then 2–4 tokens (non-final
/// tokens may be dotted single-letter INITIALS per Mechanism 1; the final token is a
/// word), then optionally a comma + a trailing role (`Delia Vantol, Chairman`). Group 1 =
/// the NAME run (the honorific, if any, is the honorific heuristic's own job; the
/// trailing role text is NOT part of the name). Same-line only (each list entry is one
/// visual line). Compiled once from a fixed static (`expect` documents compile-always).
fn role_list_name_line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:(?:Mr|Mrs|Ms|Mdm|Miss|Dr|Prof|Professor|Justice|Judge|Hon)\.?[ \t]+)?((?:(?:\p{Lu}\p{L}+(?:-\p{Lu}\p{L}+)*|\p{Lu}\.)[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}){1,3}\p{Lu}\p{L}+(?:-\p{Lu}\p{L}+)*)[ \t]*(?:,.*)?$",
        )
        .expect("role-list name-line pattern must compile")
    })
}

/// The audit/attribution LABEL of the Luxembourg RCS company-register recognizer
/// (round 3, Mechanism 3) — a jurisdiction-namespaced locale-style label
/// ([`Recognizer::Locale`]`("lu:rcs")`). A recognizer NAME, never a matched value, so it
/// is audit-safe. GLOBAL (not locale-gated): the literal `R.C.S.` anchor is
/// self-identifying (near-zero FP), and Luxembourg is the UCITS domicile — the register
/// number appears in exactly the prospectus class this engine targets, so gating it
/// behind a locale pack nobody enables would be a standing miss.
pub(crate) const RCS_LU_LABEL: &str = "lu:rcs";

/// Compile ONCE the two RCS-registry regexes (round 3, Mechanism 3):
/// - `full`: the ANCHORED form — `R.C.S.` (dotted, optionally un-dotted final `S`),
///   optionally `Luxembourg`, then `B` + optional dot/space + 4–6 digits
///   (`R.C.S. Luxembourg B.6317` / `R.C.S. B 123456`). Gaps tolerate AT MOST ONE line
///   break each (the same 1-newline rule as the name machinery), so the wrapped
///   `R.C.S. Luxembourg\nB.6317` still matches; a blank line is never crossed.
/// - `bare`: the bare `B 123456` register-number form, SAME-LINE only — matched only when
///   `R.C.S` appears within a short PRECEDING window (checked by the caller), because a
///   bare `B`+digits token is meaningless without the register anchor.
///
/// Both are fixed statics (compile-always `expect`), linear-time, no ReDoS.
fn rcs_regexes() -> &'static (Regex, Regex) {
    static RE: OnceLock<(Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        const G: &str = r"(?:[ \t]+(?:\r?\n[ \t]*)?|\r?\n[ \t]*)";
        let full = format!(r"R\.[ \t]?C\.[ \t]?S\.?(?:{G}Luxembourg)?{G}B\.?[ \t]?\d{{4,6}}\b");
        let bare = r"\bB\.?[ \t]?\d{4,6}\b";
        (
            Regex::new(&full).expect("rcs full pattern must compile"),
            Regex::new(bare).expect("rcs bare pattern must compile"),
        )
    })
}

/// How many bytes BEFORE a bare `B 123456` token the RCS pass searches for the literal
/// `R.C.S` anchor. Short on purpose: the bare form is only meaningful right next to the
/// register mention (`R.C.S. Luxembourg, B 123456`); a distant anchor is a different
/// sentence.
const RCS_BARE_WINDOW_BYTES: usize = 60;

/// Compile ONCE the two Mechanism-B regexes: `full` = a Capitalized-name LIST (>= 2 names)
/// followed by a trailing role phrase (group 1 = the list), used to LOCATE a list; `name` =
/// a single 2–4-token Capitalized name run, used to SPLIT a located list into individual
/// name spans. Both are linear-time (bounded `{1,3}` quantifiers + the `regex` crate's
/// no-backtracking guarantee — no ReDoS), compiled from fixed statics so `expect` documents
/// the compile-always invariant.
///
/// LINE-WRAP TOLERANT (the real-world shape): documents wrap lines MID-SENTENCE — OCR-
/// assembled text and PDF-extracted digital text both put a `\n` inside the sentence
/// (`… and Leon Schwab are employees\nof the BlackRock Group`, or a wrap inside the name
/// list after a comma). So every whitespace GAP in the sentence shape — between name tokens,
/// around the list separators, between the list and the phrase, and INSIDE the trailing
/// phrase itself — accepts AT MOST ONE line break ([`WS_REQ`]/[`WS_OPT`]). BOUNDED: one
/// `\n` per gap, so a BLANK line (two consecutive newlines = a paragraph break) can never
/// be crossed — the shape stays a single wrapped sentence, never an unbounded backscan
/// across paragraphs. A miss on the wrapped shape is the leak; per-gap single-wrap
/// tolerance is the recall-first, still-bounded middle.
fn trailing_role_regexes() -> &'static (Regex, Regex) {
    static RE: OnceLock<(Regex, Regex)> = OnceLock::new();
    RE.get_or_init(|| {
        // REQUIRED whitespace gap tolerating at most ONE line break: a space/tab run, or a
        // single `\r?\n` with optional spaces/tabs around it. A second consecutive newline
        // (a blank line) does NOT match — the paragraph bound.
        const WS_REQ: &str = r"(?:[ \t]+(?:\r?\n[ \t]*)?|\r?\n[ \t]*)";
        // OPTIONAL whitespace gap with the same ≤1-line-break bound.
        const WS_OPT: &str = r"[ \t]*(?:\r?\n[ \t]*)?";
        // A 2–4-token Capitalized run (Unicode-aware) — the person-name shape; a name may
        // itself wrap at a token gap. Round 3 (Mechanism 1): a NON-FINAL token may be a
        // single-letter INITIAL with its dot (`John W. Thompson`, `J. R. Surname`); the
        // FINAL token must be a real word (a name never ends in an initial), which also
        // keeps the run end on a word char (no dot-final boundary ambiguity).
        // Round 5: word tokens may be HYPHENATED compounds (`Fox-Geen` = one token; the
        // `-` must abut Capitalized parts, so spaced hyphens / digit ranges never join).
        // Round 6 (Mechanism 2): interior lowercase particles allowed between tokens
        // (`Hendrik van Riel` in a trailing-role list), at most two per gap.
        let particle = r"(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}";
        let name = format!(
            r"(?:(?:\p{{Lu}}\p{{L}}+(?:-\p{{Lu}}\p{{L}}+)*|\p{{Lu}}\.){WS_REQ}{particle}){{1,3}}\p{{Lu}}\p{{L}}+(?:-\p{{Lu}}\p{{L}}+)*"
        );
        // The separator between two list names: a comma (optionally followed by 'and' for
        // the Oxford-comma form) OR a bare ' and ' — each gap wrap-tolerant.
        let sep = format!(r"(?:{WS_OPT},{WS_OPT}(?:and{WS_REQ})?|{WS_REQ}and{WS_REQ})");
        // Trailing-phrase alternation, ASCII case-insensitive, from the DATA rows. Each
        // phrase's own internal spaces become wrap-tolerant gaps (`are employees\nof` is the
        // verified real fixture shape), so a phrase-internal wrap still anchors the list.
        let phrases = TRAILING_ROLE_PHRASES
            .iter()
            .map(|p| {
                p.split_whitespace()
                    .map(regex::escape)
                    .collect::<Vec<_>>()
                    .join(WS_REQ)
            })
            .collect::<Vec<_>>()
            .join("|");
        // RELATIVE-CLAUSE TAIL between the list and the phrase (the wrapped-name round):
        // real prose writes `…, Cerys Corrigan and Delia Vantol, who are members of…` — an
        // optional comma + an optional relative pronoun (optionally quantified: `all of
        // whom`) before the role phrase. Without it the anchor required the phrase to abut
        // the list directly and the WHOLE list went undetected (a miss is the leak).
        // Bounded: at most one comma + one quantifier + one pronoun, each gap <= 1 line
        // break — never an unbounded skip.
        // ROUND 6 (the BGF comma-list leak): a real prospectus separates the LIST from
        // the PHRASE with a run of WHITESPACE-ONLY SPACER LINES (the PDF reconstruction
        // of `…and Leon Schwab\n \n \nare employees…` — each spacer line CONTAINS a
        // space, a positioning artifact), which the single-newline gap refused, so ALL
        // the list names went undetected. The FINAL gap before the phrase now crosses up
        // to two additional SPACER lines (three newlines total) — bounded, and each
        // crossed line must carry `[ \t]+` CONTENT: a bare `\n\n` (a TRUE blank line, a
        // paragraph break) still refuses, preserving the round-4 paragraph bound. Scoped
        // to the tail (name/list gaps keep the strict single-wrap rule).
        let ws_tail =
            r"(?:[ \t]+(?:\r?\n[ \t]*)?|[ \t]*\r?\n(?:[ \t]+\r?\n){0,2}[ \t]*)";
        let tail = format!(
            r"(?:{WS_OPT},)?{ws_tail}(?:(?:(?i:all|each|both){WS_REQ}(?i:of){WS_REQ})?(?i:who|whom|which|that){ws_tail})?"
        );
        // group 1 = the LIST (>= 2 names via the `+`), then the tail + a trailing phrase.
        let full = format!(r"({name}(?:{sep}{name})+){tail}(?i:{phrases})");
        (
            Regex::new(&full).expect("trailing-role list pattern must compile"),
            Regex::new(&name).expect("name-run pattern must compile"),
        )
    })
}

/// Does the half-open byte range `s..e` overlap ANY span in `sorted` (a start-ascending,
/// mutually NON-overlapping span list — as the merge produces)? O(log n): because the spans
/// do not overlap each other, only the two neighbours around `s` can intersect `s..e` — the
/// predecessor (start ≤ s) iff its end reaches past `s`, the successor (start > s) iff its
/// start falls before `e`. Pure, deterministic.
fn span_overlaps_sorted(sorted: &[(usize, usize)], s: usize, e: usize) -> bool {
    let idx = sorted.partition_point(|&(st, _)| st <= s);
    if idx > 0 && sorted[idx - 1].1 > s {
        return true;
    }
    if idx < sorted.len() && sorted[idx].0 < e {
        return true;
    }
    false
}

/// The elastic ASCII-whitespace token [`ws_elastic_pattern`] inserts after every atom:
/// zero-or-more of the whitespace a PDF glyph-by-glyph layout fabricates between clusters.
/// A bracketed ASCII class (NOT `\s`) keeps intent explicit and avoids matching Unicode
/// whitespace inside a redaction span. Same class [`ws_term_regex_source`] uses.
const WS_ELASTIC: &str = "[ \\t\\r\\n\\x0c]*";

/// The three GLOBAL structured-address built-in patterns (spec §"ADDRESS FAMILY"), as
/// named constants so the SAME source feeds BOTH the ordinary [`RedactionEngine::base`]
/// detection AND the whitespace-elastic PDF recall variant (`ws_elastic_pattern`) — one
/// source of truth, no drift. GA-1 street, GA-2 floor/unit, GA-3 PO-Box.
pub(crate) const ADDR_STREET_PATTERN: &str = r"\b\d{1,5}[A-Za-z]?\s+(?:\p{Lu}[\p{L}.'\-]*\s+){0,4}(?i:Street|St|Road|Rd|Avenue|Ave|Av|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Place|Pl|Quay|Crescent|Cres|Terrace|Terr|Court|Ct|Square|Sq|Close|Walk|Hill|Park|Gardens|Gdns|View|Link|Loop|Row|Parade|Rise|Grove|Circle|Circus|Highway|Hwy|Expressway|Junction)\b\.?";
pub(crate) const ADDR_UNIT_PATTERN: &str = r"#\d{1,3}-\d{1,4}(?:-\d{1,4})?\b|\b(?i:Level|Lvl|Suite|Ste|Unit|Apartment|Apt|Floor|Block|Blk)\s*#?\s*\d{1,4}[A-Za-z]?(?:-\d{1,4})?\b";
pub(crate) const ADDR_POBOX_PATTERN: &str =
    r"(?i:P\.?\s?O\.?\s?Box|Post\s+Office\s+Box|G\.?P\.?O\.?\s?Box|Locked\s+Bag)\s*#?\s*\d{1,6}\b";

/// OPT-IN broadened-address row (`addresses_full`): FOREIGN-FORMAT streets where the street
/// TYPE PRECEDES the name (`2, place Winston Churchill`, `19 rue de Bitbourg`, `6, route de
/// Trèves`) — a house NUMBER, an optional comma, a lowercase continental street-type word,
/// an optional article, then a Capitalized name run. `Recognizer::Address` (careful review).
/// Linear-time (bounded `{0,2}`/`{0,3}` — no ReDoS). OFF by default (byte-identical when off).
pub(crate) const ADDR_FOREIGN_STREET_PATTERN: &str = r"\b\d{1,4}[ \t]*,?[ \t]+(?i:rue|route|avenue|boulevard|place|quai|chemin|impasse|allée|allee|cours|voie|passage|faubourg|villa)[ \t]+(?:(?:de|des|du|la|le|von|van)[ \t]+|d'[ \t]*){0,2}\p{Lu}[\p{L}0-9.'’\-]*(?:[ \t]+\p{Lu}[\p{L}0-9.'’\-]*){0,3}";

/// OPT-IN broadened-address row (`addresses_full`): BUILDING / PREMISES NAME lines (`Chater
/// House`, `South Beach Tower`, `Keppel Bay Tower`) — a Capitalized run of ≥1 leading tokens
/// ending in a premises TYPE token (`House`/`Tower`/`Building`/`Centre`/`Center`/`Plaza`/
/// `Complex`/`Mansion(s)`/`Point`/`Arcade`/`Galleria`/`Wing`/`Heights`/`Gardens`/`Quarter`),
/// so ≥2 tokens total (a lone `House` never matches). These premises tokens are DISTINCT from
/// the default street-suffix list, so this complements (not duplicates) the default recognizer.
/// `Recognizer::Address` (careful review). Bounded (`{1,4}`). Broad by design; OFF by default.
pub(crate) const ADDR_BUILDING_PATTERN: &str = r"\b(?:\p{Lu}[\p{L}0-9.'’\-]*[ \t]+){1,4}(?i:House|Tower|Towers|Building|Centre|Center|Plaza|Complex|Mansion|Mansions|Point|Arcade|Galleria|Wing|Heights|Gardens|Quarter)\b";

/// OPT-IN broadened-address row (`addresses_full`): a LUXEMBOURG postal code (`L-1855`,
/// `L-2453`) — the `L-` prefix + 4 digits (the UCITS-domicile postal shape the JPMIF
/// prospectus carries, otherwise unmatched by the SG-oriented default rows).
/// `Recognizer::Address` (careful review). OFF by default.
pub(crate) const ADDR_LU_POSTAL_PATTERN: &str = r"\bL-\d{4}\b";

/// The OFFICE-LABEL anchor regex for the address-block continuation pass (fix C): a
/// `Registered/Operating/Principal/Business/Corporate office|address` label that OPENS an
/// address block, so a proper-noun premises line directly below it (before the first
/// address candidate) is captured. Compiled ONCE (a fixed static, so `expect` documents the
/// compile-always invariant) and cached — `merged_spans` runs per scan, so a per-call
/// compile would be wasteful on the detection hot path.
fn office_label_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:registered|operating|principal|business|corporate)\s+(?:office|address)\b",
        )
        .expect("office-label anchor pattern must compile")
    })
}

/// Is `line` a BUILDING / TOWER name line for the address-block continuation pass (fix C):
/// a short run of 1..=6 tokens, EVERY token starting with an uppercase letter, a digit, or
/// `#` (so `UOB Plaza 1`, `Capital Tower`, `Suntec Tower Three`, `One Raffles Quay`, and the
/// longer `Tower 3 Marina Bay Financial Centre` / `Marina Bay Financial Centre Tower 2`
/// premises names a fitz-typeset directory carries), with at least ONE letter-initial token
/// (so a bare number/postal line — already an address anchor — is not re-captured) and ≤40
/// bytes (a premises name, not a paragraph)? A lowercase-initial token (ordinary prose)
/// rejects the line — the bound that stops the pass sweeping arbitrary text between two
/// address candidates. The token cap is 6 (raised from 5 for the six-token towers above); the
/// ≤40-byte cap plus the every-token-capital/digit/`#` rule remain the real runaway guards, so
/// a lowercase-connectored heading (`Directors of the Managers`) is still rejected on the
/// FIRST lowercase token. Deterministic; Unicode-aware on first char.
fn is_building_name_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.len() > 40 {
        return false;
    }
    let mut count = 0usize;
    let mut has_alpha_start = false;
    for tok in trimmed.split_whitespace() {
        count += 1;
        if count > 6 {
            return false;
        }
        match tok.chars().next() {
            Some(c) if c.is_uppercase() => has_alpha_start = true,
            Some(c) if c.is_ascii_digit() || c == '#' => {} // a numeric/unit token is allowed
            _ => return false,                              // lowercase-initial ⇒ prose, reject
        }
    }
    count >= 1 && has_alpha_start
}

/// Maximum byte length of the GAP between two address-family candidates that the INLINE
/// building-name pass ([`RedactionEngine::address_block_continuation_spans`]) will consider.
/// A genuine premises name sandwiched between a unit/street token and a postal (`#33-01,
/// Capital Tower, Singapore 068912`) is short; a longer gap is prose, not a building name.
/// Bounds the pass to a tight, address-flanked window so it never sweeps a sentence.
const INLINE_ADDR_GAP_BYTES: usize = 60;

/// For the INLINE building-name pass: given the raw text `gap` BETWEEN two address-family
/// candidates, return the byte range `(lo, hi)` (relative to `gap`) of a building/premises
/// proper-noun phrase to capture, or `None` when the gap is not building-name-shaped.
///
/// Strips leading/trailing whitespace + commas, then requires the inner content to be a
/// short run of 1..=6 tokens (splitting on whitespace AND commas — a building name may
/// carry internal commas like `Marina One, East Tower`, and a PDF line wrap injects a
/// `\n`), EVERY token starting with an uppercase letter, a digit, or `#`, with at least
/// one letter-initial token. A lowercase-initial token (ordinary prose) rejects the whole
/// gap — so this fires ONLY on a genuine premises name flanked by two address tokens, not
/// on arbitrary text between two distant address candidates. Deterministic; Unicode-aware
/// on each token's first char. Mirrors [`is_building_name_line`] but tolerates the commas
/// and line-wrap that an INLINE (not own-line) building name carries.
fn inline_building_phrase(gap: &str) -> Option<(usize, usize)> {
    let is_edge = |c: char| c.is_whitespace() || c == ',';
    let inner = gap.trim_matches(is_edge);
    if inner.is_empty() || inner.len() > INLINE_ADDR_GAP_BYTES {
        return None;
    }
    let mut count = 0usize;
    let mut has_alpha_start = false;
    for tok in inner
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
    {
        count += 1;
        if count > 6 {
            return None;
        }
        match tok.chars().next() {
            Some(c) if c.is_uppercase() => has_alpha_start = true,
            Some(c) if c.is_ascii_digit() || c == '#' => {}
            _ => return None,
        }
    }
    if count >= 1 && has_alpha_start {
        // Offsets of the trimmed inner content within `gap` (edge trim is ASCII ws/commas,
        // so the byte arithmetic lands on char boundaries).
        let lo = gap.len() - gap.trim_start_matches(is_edge).len();
        let hi = lo + inner.len();
        Some((lo, hi))
    } else {
        None
    }
}

/// Build a WHITESPACE-ELASTIC variant of a KNOWN address-family regex `src`: the SAME
/// shape but tolerating arbitrary ASCII whitespace (space/tab/CR/LF/FF) between every pair
/// of adjacent atoms — the fabricated separators a PDF glyph-by-glyph layout injects INSIDE
/// a token (`#16-03` reconstructed as `# 16-0 3`, the same defect class as the `Daniel J. W
/// at kins` TERMS miss). This is the address-family analogue of [`ws_term_regex_source`]
/// (which does it for a literal user term). It is applied ONLY to the structured-address
/// built-ins and the PRECISE locale postal rows — shapes that stay DISTINCTIVE under
/// `\s`-interleave (a leading `#`, a `\d{6}` postal run, `S(NNNNNN)`, a `LL9 9LL` postcode).
/// It is NEVER applied to the general recognizers (phone/id/email/…), whose whitespace-
/// elastic form would flood a reviewer — the scoping IS the FP guard.
///
/// A small recursive-descent over the regex SOURCE:
///   - every atom (a literal, an escape like `\d`, a `[...]` class, a `\p{..}` property, or
///     a recursively-transformed group) is emitted followed by the elastic [`WS_ELASTIC`]
///     token;
///   - a quantifier becomes `(?:atom<WS>){quant}`, so COUNTED repetitions (`\d{6}`) ALSO
///     tolerate whitespace BETWEEN the repeated chars — the crux of the fragmentation fix;
///   - author whitespace in the pattern (`\s`/` `/`\t`, with any quantifier) is DROPPED —
///     the ambient elastic token already covers it (so a mandatory `\s+` becomes optional,
///     a recall over-match on the safe side);
///   - anchors (`\b`, `\B`, `^`, `$`, `\A`, `\z`) are DROPPED — the elastic pass is
///     recall-first and an anchor abutting fabricated whitespace only ever restricts.
///
/// PURE + deterministic (a fixed transformation of the input string; no clock/RNG/network).
/// The `regex` crate is linear-time, so the nested `(?:…)*`/`{n}` this emits is NOT a ReDoS
/// risk. Over-matches on the SAFE side (a few reviewer-seconds on an address-shaped run vs a
/// missed identifier), per the crate PRINCIPLE. Callers compile the result NON-fatally (a
/// transform that ever produced an invalid regex is skipped, degrading to no whitespace
/// recall for that row — never a panic, never a miss worse than today's baseline).
pub(crate) fn ws_elastic_pattern(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    ws_elastic_seq(&chars, &mut i, false)
}

/// Transform one alternation-sequence of `chars` starting at `*i`. Stops at end of input,
/// or (when `nested`) at the enclosing group's closing `)` (which the CALLER consumes).
/// Splits on top-level `|` and elastic-joins the atoms of each alternative.
fn ws_elastic_seq(chars: &[char], i: &mut usize, nested: bool) -> String {
    let mut alts: Vec<String> = Vec::new();
    let mut cur = String::new();
    while *i < chars.len() {
        let c = chars[*i];
        if c == '|' {
            *i += 1;
            alts.push(std::mem::take(&mut cur));
            continue;
        }
        if nested && c == ')' {
            break; // the caller (a group open) consumes the ')'
        }
        let core = ws_elastic_atom(chars, i);
        let quant = ws_elastic_quant(chars, i);
        // A dropped atom (anchor / author-whitespace) still had its quantifier consumed.
        if let Some(core) = core {
            cur.push_str(&ws_elastic_emit(&core, &quant));
        }
    }
    alts.push(cur);
    alts.join("|")
}

/// Parse ONE atom starting at `*i` (advancing past the atom, NOT its quantifier). Returns
/// the atom's regex CORE, or `None` for an atom the elastic transform DROPS (an anchor or
/// author whitespace).
fn ws_elastic_atom(chars: &[char], i: &mut usize) -> Option<String> {
    let c = chars[*i];
    match c {
        '\\' => {
            *i += 1;
            let e = chars.get(*i).copied().unwrap_or('\\');
            *i += 1;
            match e {
                // Anchors / word boundaries — dropped (recall-first).
                'b' | 'B' | 'A' | 'z' | 'Z' | '<' | '>' => None,
                // Author whitespace class — dropped (the ambient elastic token covers it).
                's' => None,
                // Unicode property `\p{..}`/`\P{..}` (or single-letter `\pL`) — one atom.
                'p' | 'P' => {
                    let mut core = format!("\\{e}");
                    if chars.get(*i) == Some(&'{') {
                        while *i < chars.len() {
                            let ch = chars[*i];
                            core.push(ch);
                            *i += 1;
                            if ch == '}' {
                                break;
                            }
                        }
                    } else if let Some(&ch) = chars.get(*i) {
                        core.push(ch);
                        *i += 1;
                    }
                    Some(core)
                }
                // Hex escape `\xHH` or `\x{..}` — one atom (kept verbatim).
                'x' => {
                    let mut core = String::from("\\x");
                    if chars.get(*i) == Some(&'{') {
                        while *i < chars.len() {
                            let ch = chars[*i];
                            core.push(ch);
                            *i += 1;
                            if ch == '}' {
                                break;
                            }
                        }
                    } else {
                        for _ in 0..2 {
                            if let Some(&ch) = chars.get(*i) {
                                if ch.is_ascii_hexdigit() {
                                    core.push(ch);
                                    *i += 1;
                                }
                            }
                        }
                    }
                    Some(core)
                }
                // Any other escape (`\d`, `\w`, `\.`, `\(`, `\-`, …) — a one-char atom.
                other => Some(format!("\\{other}")),
            }
        }
        '[' => {
            // Character class — an opaque one-char atom; scan to the matching unescaped ']'.
            let mut core = String::from("[");
            *i += 1;
            if chars.get(*i) == Some(&'^') {
                core.push('^');
                *i += 1;
            }
            // A ']' as the FIRST class member is a literal (regex rule); keep it, don't close.
            if chars.get(*i) == Some(&']') {
                core.push(']');
                *i += 1;
            }
            while *i < chars.len() {
                let ch = chars[*i];
                core.push(ch);
                *i += 1;
                if ch == '\\' {
                    if let Some(&n) = chars.get(*i) {
                        core.push(n);
                        *i += 1;
                    }
                } else if ch == ']' {
                    break;
                }
            }
            Some(core)
        }
        '(' => {
            // Group — copy the opening prefix (`?:`, `?i:`, `?i-x:`, `?<name>`, …), recurse
            // over the body, consume the ')'. The group (with its quantifier) is one atom.
            let mut core = String::from("(");
            *i += 1;
            if chars.get(*i) == Some(&'?') {
                core.push('?');
                *i += 1;
                // Copy flag/prefix chars up to and including the ':' that opens the body,
                // OR stop at ')' for a bodyless inline-flag group like `(?i)`.
                while let Some(&ch) = chars.get(*i) {
                    if ch == ':' {
                        core.push(':');
                        *i += 1;
                        break;
                    }
                    if ch == ')' {
                        break;
                    }
                    core.push(ch);
                    *i += 1;
                }
            }
            let inner = ws_elastic_seq(chars, i, true);
            core.push_str(&inner);
            if chars.get(*i) == Some(&')') {
                core.push(')');
                *i += 1;
            }
            Some(core)
        }
        // Literal author whitespace — dropped (ambient elastic token covers it).
        ' ' | '\t' | '\r' | '\n' | '\u{0c}' => {
            *i += 1;
            None
        }
        // An ordinary literal (`#`, `-`, `S`, a digit, a letter) — a one-char atom.
        _ => {
            *i += 1;
            Some(c.to_string())
        }
    }
}

/// Parse an OPTIONAL quantifier at `*i` (advancing past it), returning it verbatim (`?`,
/// `*`, `+`, `{n}`, `{n,}`, `{n,m}`, with an optional lazy/possessive suffix) or `""`.
fn ws_elastic_quant(chars: &[char], i: &mut usize) -> String {
    match chars.get(*i) {
        Some(&q @ ('?' | '*' | '+')) => {
            *i += 1;
            let mut s = q.to_string();
            if matches!(chars.get(*i), Some('?') | Some('+')) {
                s.push(chars[*i]);
                *i += 1;
            }
            s
        }
        Some('{') => {
            let mut s = String::new();
            while *i < chars.len() {
                let ch = chars[*i];
                s.push(ch);
                *i += 1;
                if ch == '}' {
                    break;
                }
            }
            if matches!(chars.get(*i), Some('?')) {
                s.push('?');
                *i += 1;
            }
            s
        }
        _ => String::new(),
    }
}

/// Emit one transformed atom: `atom<WS>` (no quantifier) or `(?:atom<WS>){quant}` so a
/// quantifier's repetitions are ALSO whitespace-separated (`\d{6}` → each of the six digits
/// may be split apart).
fn ws_elastic_emit(core: &str, quant: &str) -> String {
    if quant.is_empty() {
        format!("{core}{WS_ELASTIC}")
    } else {
        format!("(?:{core}{WS_ELASTIC}){quant}")
    }
}

/// Deterministic identifier recognizers: an explicit caller-supplied term list
/// plus a fixed set of regex patterns. Construction compiles the patterns once.
///
/// The recognizer set is RECALL-TUNED on purpose (see the crate docs): patterns
/// are broad and terms match case-insensitively, preferring an over-match (a few
/// reviewer-seconds) to a miss (a confidentiality breach).
pub struct RedactionEngine {
    /// Per-term recognizers: one case-insensitive regex compiled from
    /// `regex::escape(term)`, so caller terms (party names, deal codenames,
    /// matter numbers) match LITERALLY — metacharacters in a name like
    /// `A.B (Pte)` are escaped, never interpreted — and matches land on real
    /// char boundaries in the ORIGINAL content (no lowercased-offset drift).
    pub(crate) term_patterns: Vec<Regex>,
    /// PERF PREFILTER over `term_patterns` (pure optimization — ZERO effect on
    /// results). When `Some`, a [`RegexSet`] compiled from the EXACT SAME
    /// `(?i)<escaped term>` source strings as `term_patterns`, index-aligned
    /// (`term_set` index `i` <-> `term_patterns[i]`), built in
    /// [`base`](RedactionEngine::base). Same guarantee as `pattern_set`: a term the
    /// set reports as a non-match has zero matches, so skipping its `find_iter` is
    /// exactly equivalent. Empty (but `Some`) when `term_patterns` is empty.
    ///
    /// `None` means the prefilter is UNAVAILABLE — `RegexSet::new` over the COMBINED
    /// term sources exceeded the regex size limit (possible at abusive config scale:
    /// thousands of long terms can overflow the combined program even though each term
    /// compiled fine as a standalone `Regex`). The size cap is on the *combined* set,
    /// not the individual regexes. In that case [`merged_spans`](RedactionEngine::merged_spans)
    /// falls back to scanning EVERY `term_patterns` directly — slower, never wrong, and
    /// crucially NEVER skips a configured term (recall is preserved; the prefilter is
    /// pure speed, so disabling it degrades to the exhaustive scan, never to a miss).
    /// Unlike `pattern_set` (whose sources are all bounded compiled-in `&'static str`),
    /// the term sources are firm-configured and unbounded, so this one can't `expect`.
    pub(crate) term_set: Option<RegexSet>,
    /// Deterministic regex recognizers (emails, phone-like, ids, name heuristic),
    /// each tagged with its kind so one match pass can attribute every span.
    pub(crate) patterns: Vec<TaggedPattern>,
    /// PERF PREFILTER over `patterns` (pure optimization — ZERO effect on results).
    /// A [`RegexSet`] compiled from the EXACT SAME ordered source strings as
    /// `patterns` (index-aligned: `pattern_set` index `i` <-> `patterns[i]`), built
    /// in [`base`](RedactionEngine::base). One `matches(text)` pass tells us which
    /// patterns match SOMEWHERE; in [`merged_spans`](RedactionEngine::merged_spans)
    /// we then run the per-pattern `find_iter` ONLY for the matched indices. A
    /// pattern the set reports as a non-match has provably ZERO matches, so skipping
    /// its `find_iter` is exactly equivalent to running it and collecting nothing —
    /// the raw span set (hence every downstream candidate) is byte-identical. Empty
    /// when `patterns` is empty (`RegexSet::new([])` matches nothing — never panics).
    pub(crate) pattern_set: RegexSet,
    /// OPT-IN aggressive name pattern (capitalized multi-word run). `None` unless
    /// the engine was built with [`RedactionEngine::aggressive`] — it is OFF by
    /// default because it would flag every sentence-initial word / place /
    /// company / heading and make the output unreadable.
    pub(crate) aggressive_name: Option<Regex>,
    /// Firm-defined recognizers ("super find & replace"), each already compiled
    /// (honoring case / whole-word / literal-vs-regex) and tagged with its
    /// config NAME. ADDED to the built-ins (never replacing them); a `Custom`
    /// span is most-specific in the overlap merge (priority 0), so an explicit
    /// firm rule wins as the primary recognizer of a merged span.
    pub(crate) user_recognizers: Vec<Compiled>,
    /// WHITESPACE-INSENSITIVE variants of the user [`term_patterns`], one per term, used
    /// ONLY by [`term_spans_whitespace_insensitive`](RedactionEngine::
    /// term_spans_whitespace_insensitive) — the PDF glyph-by-glyph recall fix. Each
    /// matches the SAME term as `term_patterns[i]` but allows ARBITRARY ASCII whitespace
    /// between every pair of adjacent characters (so a word a PDF generator fragmented
    /// across `Td`-nudged show operators — `W` `at` `kins` → `W at kins` — still matches
    /// `Watkins`). Built ONCE from the same `terms`, case-insensitive, metacharacters
    /// escaped. EMPTY when no terms are configured (the common case — the elastic pass is
    /// then a no-op). NOT used by the general [`candidates`](RedactionEngine::candidates)
    /// pass: ordinary text/file scanning keeps its exact, whitespace-significant behavior.
    ws_term_patterns: Vec<Regex>,
    /// WHITESPACE-ELASTIC variants of the ADDRESS-FAMILY recognizers, used ONLY by
    /// [`address_family_spans_whitespace_insensitive`](RedactionEngine::
    /// address_family_spans_whitespace_insensitive) — the PDF glyph-by-glyph recall fix for
    /// structured addresses (the address-family analogue of `ws_term_patterns`). Each entry
    /// pairs a compiled elastic regex (from [`ws_elastic_pattern`]) with the [`Recognizer`]
    /// the ordinary match would carry, so a fragmented address attributes IDENTICALLY
    /// (`Recognizer::Address` for the three global rows; `Recognizer::Locale(<cc>:postal)`
    /// for a PRECISE locale postal row). Built ONCE in [`base`](RedactionEngine::base) from:
    /// (i) the three global structured-address built-ins WHEN `builtins.address` is on, and
    /// (ii) every enabled locale's PRECISE postal row (unconditional, non-aggressive — the
    /// aggressive/context-gated bare-postal nets are DELIBERATELY excluded to avoid a
    /// whitespace-elastic FP flood over PDF runs). EMPTY when address is off and no precise
    /// postal locale is enabled — then the elastic address pass is a byte-identical no-op
    /// (the common case). NOT used by the ordinary [`candidates`](RedactionEngine::candidates)
    /// pass: plain-text/file scanning keeps its exact, whitespace-significant behavior — a
    /// non-PDF file is not glyph-fragmented, so the ordinary address patterns already match.
    address_ws_patterns: Vec<(Regex, Recognizer)>,
    /// The data classes this engine reads + transforms (must align with the
    /// granted `matter.read:<class>` capabilities; a non-granted class is refused
    /// by the core).
    classes: Vec<DataClass>,
    /// The OPT-IN compliance [`Profile`]s this engine was built with (deduped). Empty
    /// is the default — the common case, byte-identical to before this axis existed.
    /// Held so the engine can (i) record the active profile selection in the audit
    /// note (so the trail shows WHICH compliance regime a scan/redaction targeted) and
    /// (ii) surface each profile's honest [`human_review_gaps`](ProfileSpec) to the
    /// reviewer via [`profile_review_gaps`](RedactionEngine::profile_review_gaps).
    profiles: Vec<Profile>,
    /// Lever 2: which OPT-IN context-required recognizers are active (default all-off).
    /// Held so the finalizer can (i) take the additive-only gate path only when ANY is
    /// on (the default path is byte-identical to before) and (ii) is otherwise unused at
    /// scan time — the per-row lexicon is recovered from a span's `ctx:` label. The
    /// enabled rows are also compiled into `patterns` at build (so they flow through the
    /// same prefilter + merge).
    context_recognizers: ContextRecognizers,
    /// CONTEXT-REQUIRED LOCALE rows: the required-context lexicon of every compiled
    /// [`LocaleRecognizer`] whose `context` field is `Some` (e.g. `us:dl`, `us:passport`,
    /// `au:passport`, `au:drivers-licence`), keyed by its `<locale>:<name>` label. EMPTY
    /// in the common case (no context-required locale row enabled), so the finalizer's
    /// locale-context gate is skipped entirely and the path stays byte-identical to before
    /// this field existed.
    ///
    /// The gate (in [`merged_spans`](RedactionEngine::merged_spans)) mirrors the `ctx:*`
    /// additive-only gate: a span whose ONLY contributors are context-required-AND-
    /// unsatisfied recognizers (no required keyword in-window) is DROPPED; if ANY normal
    /// recognizer also covers the span, OR the keyword is in-window, the span survives.
    /// This stores the lexicon on the engine (rather than a static label→lexicon table
    /// like [`locale_class_lexicon`]) because a label string alone cannot recover its
    /// `Locale`, so the lexicon is captured at build time from the compiled rows.
    locale_required_context: HashMap<Arc<str>, &'static [&'static str]>,
    /// AGGRESSIVE LOCALE ROWS: the `<locale>:<name>` label of every compiled
    /// [`LocaleRecognizer`] whose `aggressive` flag is `true` (the broad, format-only
    /// "last-resort" rows — driver's licence / passport / generic account / BSB /
    /// transit / sort code). Captured at build EXACTLY like `locale_required_context`
    /// (a label string alone cannot recover its `Locale`/`aggressive` flag, so the set
    /// is materialized from the compiled rows). EMPTY in the common case (no aggressive
    /// locale row enabled), so [`recognizer_priority`](RedactionEngine::recognizer_priority)
    /// is a pure passthrough to [`Recognizer::priority`] and every merge order stays
    /// byte-identical to before this field existed.
    ///
    /// PRECEDENCE-ONLY (RECALL-NEUTRAL): membership here DEMOTES a row in the merge's
    /// PRIMARY-LABEL election (it gets a HIGHER priority NUMBER — lower precedence —
    /// than every precise recognizer, so a precise sibling always out-labels it on an
    /// overlapping span). It NEVER changes whether a candidate fires or is dropped — a
    /// token matched only by an aggressive row is still redacted, just labeled by it.
    /// See [`recognizer_priority`](RedactionEngine::recognizer_priority).
    pub(crate) aggressive_locales: HashSet<Arc<str>>,
    /// NAME-PROPAGATION: the OPT-IN EXPANSION tier (default `false`, OFF). When ON, the
    /// name-closure pass (see [`name_propagation_spans`](RedactionEngine::name_propagation_spans))
    /// also redacts any Capitalized multi-word run that CONTAINS an already-detected name
    /// TOKEN as a whole word — so a detected `Greco` (from `Mr Greco`) pulls in the bare
    /// `Massimo Greco`. The SAFE tier (exact re-occurrences of a detected full-name string)
    /// is ALWAYS on; this flag adds only the broader expansion. OFF = byte-identical to
    /// before the propagation pass existed (the pass still runs but the expansion arm
    /// contributes nothing). Enabled via [`RedactionEngineBuilder::name_expansion`].
    pub(crate) name_expansion: bool,
    /// OPT-IN ORGANISATION detection (default `false`, OFF). When ON,
    /// [`organisation_spans`](RedactionEngine::organisation_spans) runs in `merged_spans`,
    /// emitting the `ctx:org` recognizer class (suffix-anchored + org-context). OFF makes that
    /// pass an early-return no-op, so the candidate set is byte-identical to before this
    /// existed. Enabled via [`RedactionEngineBuilder::organisations`].
    pub(crate) organisations: bool,
    /// Whether the BIC recognizer is active (`builtins.bic`, ON by default). Held so
    /// [`bic_labeled_spans`](RedactionEngine::bic_labeled_spans) — the label-cue-gated
    /// 8-CHAR BIC pass — runs iff the 11-char BIC row is also compiled (the two forms
    /// enable/disable together via the single `bic` toggle). OFF ⇒ the pass is a no-op
    /// and the candidate set carries no `bic` spans at all.
    pub(crate) bic: bool,
    /// Whether the PHONE recognizer is active (`builtins.phone`, ON by default). Held
    /// so [`cued_phone_spans`](RedactionEngine::cued_phone_spans) — the always-on
    /// label-cued relaxed-joiner arm (review H1+H2) — enables/disables together with
    /// the ordinary phone row via the single `phone` toggle.
    pub(crate) phone: bool,
}

/// The default class set the engine reads + transforms when none is given:
/// `document` + `party`, matching the module manifest's
/// `matter.read:[document, party]` so every declared-readable class is also
/// stripped.
pub(crate) fn default_classes() -> Vec<DataClass> {
    vec![DataClass::Document, DataClass::Party]
}

/// Per-recognizer enable/disable for the built-in pattern recognizers.
///
/// All built-ins are ON by default (recall-first — see the crate docs): a firm
/// turns one OFF only when it is pure noise for their corpus (e.g. a code-heavy
/// matter where the broad `id` recognizer flags every reference number). The
/// caller-supplied term list and firm [`UserRecognizer`]s are NOT toggled here —
/// they are always active and are configured separately.
///
/// The toggle is a CONVENIENCE, not a security control: it changes which broad
/// recognizers run, never whether a brokered call is checked/audited. A disabled
/// recognizer simply does not contribute candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinRecognizers {
    /// Email addresses ([`Recognizer::Email`]).
    pub email: bool,
    /// Phone-like digit runs ([`Recognizer::Phone`]).
    pub phone: bool,
    /// Structured ids ([`Recognizer::Id`]) — broad; the most common one to disable.
    pub id: bool,
    /// The title-prefixed name HEURISTIC ([`Recognizer::Name`]).
    pub name: bool,
    /// Luhn-validated payment-card numbers ([`Recognizer::CreditCard`]).
    pub credit_card: bool,
    /// Mod-97-validated IBANs ([`Recognizer::Iban`]).
    pub iban: bool,
    /// ISO 9362 BICs / SWIFT codes ([`Recognizer::Bic`]) — structure-validated (real
    /// ISO country code + SWIFT location rules). ON by default like the IBAN (a BIC
    /// beside a redacted IBAN re-identifies the institution). The 11-char form stands
    /// alone; the word-shaped 8-char form fires only with a BIC/SWIFT label cue
    /// in-window. CAREFUL review tier always (structure-only — no checksum).
    pub bic: bool,
    /// ISO 6166 ISINs ([`Recognizer::Isin`]) — checksum-validated (the ISIN Luhn). ON
    /// by default like the IBAN; precise like card/IBAN/LEI (High / quick-confirm).
    pub isin: bool,
    /// IPv4/IPv6 addresses ([`Recognizer::Ip`]).
    pub ip: bool,
    /// URLs ([`Recognizer::Url`]).
    pub url: bool,
    /// Structured postal/street ADDRESSES ([`Recognizer::Address`]) — number+street
    /// +suffix, floor/unit (`#16-03`, `Level N`), and PO-Box forms. ON by default
    /// (recall-first, like email/phone); routes to CAREFUL review (never quick-confirm).
    pub address: bool,
}

impl Default for BuiltinRecognizers {
    /// All built-ins ON (recall-first).
    fn default() -> Self {
        Self::all()
    }
}

impl BuiltinRecognizers {
    /// Every built-in recognizer enabled (the recall-first default).
    pub fn all() -> Self {
        Self {
            email: true,
            phone: true,
            id: true,
            name: true,
            credit_card: true,
            iban: true,
            bic: true,
            isin: true,
            ip: true,
            url: true,
            address: true,
        }
    }

    /// Every built-in recognizer DISABLED — only the term list + firm
    /// [`UserRecognizer`]s (and, if enabled, the aggressive name mode) run. Use as
    /// a base to switch on exactly the recognizers a corpus needs.
    pub fn none() -> Self {
        Self {
            email: false,
            phone: false,
            id: false,
            name: false,
            credit_card: false,
            iban: false,
            bic: false,
            isin: false,
            ip: false,
            url: false,
            address: false,
        }
    }

    /// The per-field OR of two built-in sets — a built-in is enabled iff it is
    /// enabled in EITHER. Used to fold a compliance [`Profile`]'s required built-ins
    /// into the engine's active set: a pure WIDEN (it only ever turns a recognizer
    /// ON, never off), so a profile can guarantee its deterministic coverage without
    /// ever silently DISABLING a recognizer the caller turned on.
    pub fn union(self, other: Self) -> Self {
        Self {
            email: self.email || other.email,
            phone: self.phone || other.phone,
            id: self.id || other.id,
            name: self.name || other.name,
            credit_card: self.credit_card || other.credit_card,
            iban: self.iban || other.iban,
            bic: self.bic || other.bic,
            isin: self.isin || other.isin,
            ip: self.ip || other.ip,
            url: self.url || other.url,
            address: self.address || other.address,
        }
    }
}

/// Lever-2 OPT-IN toggle for the four CONTEXT-REQUIRED recognizers (undashed SSN, DOB,
/// age>89, generic account/MRN). ALL OFF by default — the candidate set is
/// byte-identical to before Lever 2 unless a firm explicitly opts in (these shapes are
/// ambiguous and only meaningful near a relevant keyword; running them globally would
/// flood the reviewer). Mirrors [`BuiltinRecognizers`]'s per-field toggle style.
///
/// Enabling a row turns its [`ContextRecognizer`] on; whether each resulting candidate
/// SURVIVES is decided by the additive-only gate at finalization (keyword in-window OR a
/// normal recognizer also covers the span). The toggle is a CONVENIENCE, not a security
/// control — it changes which broad recognizers run, never whether a call is
/// checked/audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextRecognizers {
    /// Undashed SSN — 9 contiguous digits near {ssn, social security, …}, SSN-structural.
    pub ssn_undashed: bool,
    /// DOB — a date token near {dob, d.o.b, date of birth, born}.
    pub dob: bool,
    /// Age > 89 — an explicit age 90..=129 near {age, years old, y/o, yo, aged}. NO clock.
    pub age_over_89: bool,
    /// Generic account / MRN — a 6–12 alnum run (≥1 digit) near {account, acct, mrn, …}.
    pub account_mrn: bool,
    /// ROLE-CONTEXT PERSON NAME — a 2–4-token Capitalized name run near a role heading/
    /// label ({Director(s), Manager(s), Chairman, CEO/CFO/COO/CIO, Chief … Officer,
    /// Trustee, Partner, Secretary, Signatory, Name:}). Deliberately FP-prone (recall-
    /// first per the crate PRINCIPLE); capped at the CAREFUL review tier (never quick-
    /// confirm) so the review layer + grouping absorb the noise.
    pub role_name: bool,
    /// WRAP-SPLIT PHONE — a phone-like digit run wrapped across exactly ONE line break,
    /// near a telecom keyword ({tel, telephone, phone, fax, freephone, hotline,
    /// enquiries, call}). The general phone recognizer stays newline-blind ON PURPOSE
    /// (HIGH-1); this row covers ONLY the keyword-corroborated wrapped shape. Capped at
    /// the CAREFUL review tier.
    pub phone_wrapped: bool,
}

impl Default for ContextRecognizers {
    /// All OFF (the additive-only default).
    fn default() -> Self {
        Self::none()
    }
}

impl ContextRecognizers {
    /// Every context recognizer ENABLED.
    pub fn all() -> Self {
        Self {
            ssn_undashed: true,
            dob: true,
            age_over_89: true,
            account_mrn: true,
            role_name: true,
            phone_wrapped: true,
        }
    }

    /// All context recognizers DISABLED (the default — byte-identical to before).
    pub fn none() -> Self {
        Self {
            ssn_undashed: false,
            dob: false,
            age_over_89: false,
            account_mrn: false,
            role_name: false,
            phone_wrapped: false,
        }
    }

    /// Is the row with this bare `name` enabled? The single mapping from a
    /// [`ContextRecognizer::name`] to its toggle field, used at engine build to filter
    /// [`context::CONTEXT_RECOGNIZERS`] down to the opted-in rows.
    fn enabled(&self, name: &str) -> bool {
        match name {
            "ssn-undashed" => self.ssn_undashed,
            "dob" => self.dob,
            "age-over-89" => self.age_over_89,
            "account-mrn" => self.account_mrn,
            "role-name" => self.role_name,
            "phone-wrapped" => self.phone_wrapped,
            // An unknown row name is never enabled (fail-closed): a new row added to
            // the table without a toggle field stays OFF until wired here.
            _ => false,
        }
    }

    /// Whether ANY context recognizer is enabled — lets the gate/finalizer skip its
    /// context work entirely on the default (all-off) path.
    fn any(&self) -> bool {
        self.ssn_undashed
            || self.dob
            || self.age_over_89
            || self.account_mrn
            || self.role_name
            || self.phone_wrapped
    }
}

impl RedactionEngine {
    /// Build an engine for an explicit term list and the default class set
    /// (`document` + `party`). Terms match case-insensitively as literal
    /// substrings; the aggressive name mode is OFF; no firm recognizers; and NO
    /// locale packs (jurisdiction-specific recognizers like the SG NRIC are OPT-IN —
    /// use [`RedactionEngine::builder`]`.locales(..)` to enable them).
    ///
    /// FIX #12: this is the thin convenience over [`RedactionEngineBuilder`] for
    /// the common term-only case. With no user recognizers the build is INFALLIBLE
    /// (only firm-rule compilation can fail), so this stays a non-`Result` `new`.
    /// For firm recognizers / explicit classes / locale packs, use
    /// [`RedactionEngine::builder`].
    pub fn new(terms: impl IntoIterator<Item = String>) -> Self {
        // NO locales AND NO profiles by default — jurisdiction-specific and
        // compliance-profile recognizers are both opt-in. NO context recognizers
        // either (Lever 2 is off by default — byte-identical to before).
        Self::base(
            terms,
            default_classes(),
            BuiltinRecognizers::all(),
            &[],
            &[],
            ContextRecognizers::none(),
            // LEI is OPT-IN, OFF by default — `new` and a bare builder do NOT flag an LEI.
            false,
            // SG-NRIC LOOSE NET is OPT-IN, OFF by default — `new` and a bare builder do
            // NOT register the aggressive loose/context SG rows.
            false,
            // ORGANISATION detection is OPT-IN, OFF by default (no org pass runs).
            false,
            // BROADENED ADDRESSES are OPT-IN, OFF by default (no extra address rows).
            false,
        )
    }

    /// Start a [`RedactionEngineBuilder`] (FIX #12): the single fallible
    /// construction path. Set `.classes(..)` / `.recognizers(..)`, then `.build()`
    /// — which surfaces every firm-rule validation error (zero-width / invalid
    /// label / `whole_word`+Regex / over-long replacement / malformed pattern) as a
    /// [`CoreError::Backend`], fail-closed, rather than silently dropping a rule.
    pub fn builder() -> RedactionEngineBuilder {
        RedactionEngineBuilder::default()
    }

    /// Build the base engine (term list + global built-in recognizers + the enabled
    /// LOCALE packs + the enabled compliance PROFILES + classes) with NO firm
    /// recognizers. INFALLIBLE — the term patterns are escaped (always valid) and the
    /// built-in + locale + profile patterns are static. Shared by
    /// [`new`](RedactionEngine::new) and the [`RedactionEngineBuilder`].
    ///
    /// `locales` = the opt-in jurisdiction packs to compile IN ADDITION to the global
    /// built-ins (empty = none, the default). `profiles` = the opt-in compliance
    /// profiles: each one (i) OR-merges its `required_builtins` into the active
    /// built-in set (so e.g. PCI always runs the credit-card recognizer even if the
    /// caller's `builtins` had it off) and (ii) compiles its OWN bespoke rows under
    /// the `profile:<name>:<row>` label (the PCI worked example has none).
    ///
    /// `lei` = the OPT-IN ISO 17442 Legal Entity Identifier recognizer
    /// ([`Recognizer::Lei`]); `false` (the default) compiles NO LEI pattern, so the
    /// candidate set is byte-identical to before this existed. A public LEI is borderline
    /// PII, so flagging it is a deliberate user choice — UNLIKE the global built-ins it is
    /// OFF by default even in [`BuiltinRecognizers::all`].
    // PRIVATE constructor: each argument is an independent, orthogonal engine-config axis
    // (terms / classes / built-ins / locales / profiles / context / lei / sg-nric-loose),
    // threaded 1:1 from the builder's typed setters — bundling them into a struct would just
    // re-spell the builder it is already called from. The opt-in `bool`s (lei, sg_nric_loose)
    // are deliberate, named flags, not a boolean-blindness smell. So allow the arg count.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn base(
        terms: impl IntoIterator<Item = String>,
        classes: Vec<DataClass>,
        builtins: BuiltinRecognizers,
        locales: &[Locale],
        profiles: &[Profile],
        context_recognizers: ContextRecognizers,
        lei: bool,
        sg_nric_loose: bool,
        organisations: bool,
        addresses_full: bool,
    ) -> Self {
        // OR-merge every enabled profile's REQUIRED built-ins into the active set:
        // a profile's deterministic coverage holds even if the caller otherwise
        // disabled that recognizer. (A pure widen — it only ever turns a built-in ON,
        // never off — so the recall-first posture is preserved.)
        let mut builtins = builtins;
        for p in profiles {
            builtins = builtins.union(p.spec().required_builtins);
        }
        // Compile one case-insensitive LITERAL regex per non-empty term. Using
        // `regex::escape` means metacharacters in party names (`.`, `(`, `)`,
        // `/`, `-`, …) are matched literally and cannot panic or mis-match; the
        // `(?i)` flag gives case-insensitive matching WITHOUT lowercasing the
        // haystack — so matches fall on valid char boundaries in the original
        // string even for non-ASCII text whose lowercase differs in byte length
        // (e.g. 'İ'). A stray empty term is dropped so it can never match the
        // whole document. Built from caller input, so `expect` is justified:
        // `escape` always yields a valid pattern and `(?i)` is a fixed flag.
        // Collect the per-term SOURCE strings first, then compile each. The SAME
        // ordered source list feeds both `term_patterns` (the compiled regexes) and
        // `term_set` (the prefilter `RegexSet`) so the set is index-aligned with the
        // pattern vector — `term_set` index `i` is exactly `term_patterns[i]`.
        // Materialize the kept (non-empty) terms ONCE so both the exact `term_patterns`
        // and the whitespace-insensitive `ws_term_patterns` derive from the SAME ordered
        // list (index-aligned with `term_patterns`/`term_set`).
        let kept_terms: Vec<String> = terms.into_iter().filter(|t| !t.trim().is_empty()).collect();
        let term_sources: Vec<String> = kept_terms
            .iter()
            .map(|t| format!("(?i){}", regex::escape(t)))
            .collect();
        let term_patterns: Vec<Regex> = term_sources
            .iter()
            .map(|src| Regex::new(src).expect("escaped term must compile as a literal regex"))
            .collect();
        // WHITESPACE-INSENSITIVE term variants (the PDF glyph-by-glyph recall fix — see
        // `term_spans_whitespace_insensitive`). Each term compiles to a regex that matches
        // its characters with ARBITRARY ASCII whitespace allowed between every adjacent
        // pair, so a word a PDF generator fragmented across `Td`-nudged show operators
        // (`W` `at` `kins` → reconstructed `W at kins`) still matches `Watkins`. Built from
        // the SAME `kept_terms`, case-insensitive, every char escaped. `expect` is
        // justified identically to `term_patterns`: `ws_term_regex_source` only ever emits
        // escaped literals joined by the fixed `\s*` token, always a valid pattern.
        let ws_term_patterns: Vec<Regex> = kept_terms
            .iter()
            .map(|t| {
                Regex::new(&ws_term_regex_source(t))
                    .expect("whitespace-insensitive term must compile")
            })
            .collect();
        // PERF PREFILTER (pure optimization): a `RegexSet` over the IDENTICAL ordered
        // source strings. Each term already compiled as a standalone `Regex` above, so
        // an INDIVIDUAL pattern is valid; an empty source list yields a never-matching
        // set. BUT `RegexSet::new` caps the COMBINED program size (~10 MiB), which a
        // standalone `Regex::new` does NOT — thousands of long firm-configured terms can
        // overflow the combined set while every term compiles alone. So this is `.ok()`,
        // NOT `.expect()`: on overflow `term_set` is `None` and `merged_spans` falls back
        // to the exhaustive direct term scan (slower, identical results, never a skipped
        // term). The prefilter is pure speed; losing it must degrade to a full scan, not
        // a miss. (`pattern_set` below keeps `.expect` — its sources are all bounded
        // compiled-in statics, so it cannot overflow in production.)
        let term_set = RegexSet::new(&term_sources).ok();

        // Deterministic regex recognizers. RECALL-TUNED: deliberately broad.
        // These patterns are fixed, compiled-in, and contain no backreferences /
        // no catastrophic-backtracking constructs (the `regex` crate is linear-
        // time by construction — no ReDoS). The literals are static and known to
        // compile, so `expect` documents that invariant. Each carries an `enabled`
        // flag from `builtins` (a disabled recognizer simply contributes no
        // patterns) and an optional checksum `validate` predicate (`None` =
        // format-only; `Some(f)` = keep a raw match only if `f` passes).
        let pattern_sources: &[PatternSource] = &[
            // Email addresses (broad: any local@domain.tld shape).
            (
                builtins.email,
                Recognizer::Email,
                r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
                None,
            ),
            // Phone-like runs: optional +, then digit groups with in-group separators
            // (`-`/`.`/`()`), joined by SINGLE SPACES only, >=7 digits total (the
            // validator), tolerating a trailing extension (e.g. "x123" / "ext 4").
            // Broad on purpose (recall over precision) WITHIN one visual field.
            //
            // NBSP JOINERS (review C1): the joiner class admits a SINGLE U+00A0 NBSP or
            // U+202F narrow NBSP alongside the ASCII space — word processors insert
            // exactly one INSIDE a phone number to prevent wrapping (the French-
            // convention grouping too), so it is an intra-number join, NOT a column
            // boundary, and sits outside the ratified refusal. A run of >=2 of them (or
            // any 2-char whitespace mix) still ends the match structurally — the second
            // char precedes a non-digit — so column gaps stay refused.
            //
            // COLUMN-GAP GUARD (RATIFIED structural tightening — the finance round):
            // the old separator class was `\s`, which let the pattern stitch TABULAR
            // amount/balance columns across newlines and multi-space column gaps into
            // fake "phones" (`213.57\n03/06/2026`, `000        25.00` — 9–13 FP/page on
            // bank statements, ~90% of the corpus numeric noise). The STRUCTURAL rule: a
            // real phone's internal separators are single spaces or in-group punctuation;
            // a NEWLINE, a TAB, or a run of >=2 whitespace chars is a LAYOUT/COLUMN
            // boundary between different fields — that shape is structurally NOT one
            // phone number. So the group joiner is exactly ONE ASCII space (`[ ]` — two
            // consecutive spaces end the match structurally; no lookahead needed).
            //
            // WRAPPED REAL PHONES (the deliberate choice): a genuine phone wrapped
            // across a single line break (`0800\n917 2112`) is REFUSED by this row —
            // without a telecom cue that shape is indistinguishable from a table-row
            // boundary, and the engine already routes it through the keyword-gated
            // `ctx:phone-wrapped` row (CTX-6, unchanged), which exists precisely because
            // this row must not cross lines (the HIGH-1 flood class; the PDF path
            // line-scoped it for the same structural reason — this makes the text path
            // consistent). Each group ends on a digit (an optional trailing `)`), so a
            // sentence-final `.` is never absorbed; a group after a space starts with a
            // digit or `(`, so a ` - ` range separator (`06/01/2026 - 06/30/2026`) never
            // joins two dates. A `)` attaches to the FRONT of the next separator
            // (`65) 6123-9999` still joins) rather than a group tail, so the whole match
            // always ENDS ON A DIGIT exactly like the old shape (`Form CDD-1 (2026)`
            // never rides a trailing paren in). The validator keeps the OLD >=8-char
            // length floor.
            (
                builtins.phone,
                Recognizer::Phone,
                r"\+?\d(?:[\d\-().]*\d)?(?:\)?[ \u{00A0}\u{202F}]\(?\d(?:[\d\-().]*\d)?)*(?:[ \u{00A0}\u{202F}]?(?:x|ext\.?)[ \u{00A0}\u{202F}]?\d+)?",
                Some(phone_min_len_valid),
            ),
            // PAN LAST-4 (RATIFIED — see [`PAN_LAST4_LABEL`]): a referenced / masked
            // payment-card tail. STRICTLY cue-anchored — every alternation arm carries
            // its cue in the match (worded: `[Card ]ending[ in] NNNN` / `last four
            // [digits] NNNN`, word-bounded so `spending 2144` never fires; masked:
            // four masked groups then digits, a 12–15-masker run, or a word-bounded
            // `x-NNNN`) — so a bare 4-digit amount/year can never fire. The mask class
            // covers the common maskers: `*`, `x`/`X`, and the bullets `\u{25CF}` BLACK
            // CIRCLE / `\u{2022}` BULLET (`●●●● ●●●● ●●●● 2144` — the ledger's
            // bullet-mask gap). `\u{00B7}` MIDDLE DOT is EXCLUDED on purpose: it is the
            // TOC dot-leader character (`Chapter overview ············2144` and its
            // grouped form resurfaced as FPs under review) and a vanishingly rare
            // real-world PAN masker. The cue posture is unchanged (>=4 CONSECUTIVE
            // maskers per group, digit tail required), so a decorative bullet LIST
            // never fires. The unbroken-run arm stays x-free on purpose (a bare
            // `xxxxxxxxxxxx` run is word-shaped placeholder text; a bullet/star run is
            // unambiguously a mask). ADVISORY (default-off in apply; the human opts in)
            // via `is_aggressive`. Rides the card family's toggle
            // (`builtins.credit_card`).
            (
                builtins.credit_card,
                Recognizer::Context(Arc::from(PAN_LAST4_LABEL)),
                r"(?i)\b(?:card[ \t]+)?(?:ending(?:[ \t]+in)?|last[ \t]+(?:four|4)(?:[ \t]+digits)?)[ \t:]+\d{4}\b|(?i)(?:[*x\u{25CF}\u{2022}]{4}[ \t\-]){3}\d{4}\b|[*\u{25CF}\u{2022}]{12,15}\d{4}\b|(?i)\bx+[\-\u{2013}]\d{4}\b",
                None,
            ),
            // Simple ID patterns: an optional uppercase letter run (>=1) with
            // optional `-`/`/` separators, then a digit run, allowing further
            // separated digit/letter groups — catches "AB1234", "PROJ2026",
            // "S-2026-014", "AB/1234". Broad on purpose (recall-first).
            (
                builtins.id,
                Recognizer::Id,
                r"\b[A-Z]{1,}(?:[-/]?[A-Z0-9]+)*[-/]?\d{3,}(?:[-/][A-Z0-9]+)*\b",
                None,
            ),
            // NAME HEURISTIC (default, conservative): a courtesy/honorific title
            // followed by a run of Capitalized words. UNICODE-aware (\p{Lu} =
            // uppercase letter, \p{L} = any letter), so "Dr. Tan Wei Ming" and
            // accented names are caught. This is a HEURISTIC, NOT name detection
            // (see the crate + type docs): it deliberately over-flags and misses
            // names without a title.
            //
            // WRAPPED-NAME TOLERANCE, BOUNDED (the wrapped-name round; design-check
            // finding): the former `\s+` token gap crossed newlines UNBOUNDED — even blank
            // lines — producing arbitrarily long cross-line runs the PDF line-scope filter
            // then silently DROPPED (the leak: `Ms. Marlow Varga` in a letter signature).
            // The gaps are now explicit: same-line `[ \t]+` runs plus AT MOST ONE line
            // break in the WHOLE match (documents wrap mid-sentence; OCR-assembled and
            // PDF-extracted text both do this). Two arms:
            //   arm 1: >= 1 same-line token, then OPTIONALLY one `\r?\n` and further
            //          same-line tokens (`Ms. Marlow\nVarga`; greedily absorbs a
            //          line-leading Capitalized word after a wrap — `Ms. Marlow
            //          Varga\nKestrel` — the DOCUMENTED over-flag, the safe side per the
            //          crate PRINCIPLE);
            //   arm 2: honorific at end-of-line, name on the next line (`Ms.\nVarga`).
            // A BLANK line (two consecutive newlines) is never crossed — the paragraph
            // bound. Every match spans <= 1 newline: exactly what the PDF path's
            // name-wrap sanction admits (see `retain_line_scoped_candidates`).
            (
                builtins.name,
                Recognizer::Name,
                // Token shape (round 3 M1 + round 5 hyphens): a Capitalized word
                // (optionally a HYPHENATED compound — `Fox-Geen` is one token; the `-`
                // must abut Capitalized parts, so `Fox - Geen`/`2019-2024` never join),
                // a bare single letter (as before), OR a single-letter INITIAL with its
                // dot — so `Mr. John W. Thompson`, `Ms. J. R. Surname`, and
                // `Ms. José Müller-Tan` match whole.
                // A multi-letter word can never absorb a sentence dot (the `\.` arm is
                // single-letter only), so `Mr Smith. The` still stops at `Smith`.
                r"(?:Mr|Mrs|Ms|Mdm|Miss|Dr|Prof|Professor|Justice|Judge|Hon|Messrs)\.?(?:[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)*(?:[ \t]*\r?\n[ \t]*\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)*)?|[ \t]*\r?\n[ \t]*\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+(?:(?:van|von|der|den|de|da|di|du|bin|binti|binte|ter|te|al|el)[ \t]+){0,2}\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)*)",
                None,
            ),
            // (SG NRIC/FIN moved to an OPT-IN locale pack — it is jurisdiction-
            // specific, not a global built-in. See [`locale_recognizers`] /
            // [`Locale::Singapore`]; enable with `.locales([Locale::Singapore])`.)
            // Payment-card numbers: a 13–19 digit run, optionally grouped by a
            // single space or dash, that PASSES Luhn. The Luhn checksum is what makes
            // it a card (a real card always passes, so the check filters non-cards
            // WITHOUT a miss). RECALL-FIRST: NO leading/trailing `\b` word-boundary —
            // a `\b` would silently MISS a card glued to a word char (e.g.
            // `customerID4012888888881881`), the exact Rule-6 failure this crate
            // refuses; the CHECKSUM, not a boundary, supplies precision, so an
            // over-match is harmless. (Known limit: a card embedded INSIDE a longer
            // pure-digit run can be skipped — `find_iter` is leftmost / non-
            // overlapping, so a Luhn-failing leading window consumes the position.
            // Rare in real text; the glued-to-letters case is the common one + fixed.)
            (
                builtins.credit_card,
                Recognizer::CreditCard,
                r"\d(?:[ -]?\d){12,18}",
                Some(luhn_valid),
            ),
            // IBAN: 2-letter country code + 2 check digits + 11–30 BBAN chars,
            // optionally space-grouped, that PASSES ISO 7064 mod-97-10. As with the
            // card, the checksum filters non-IBANs without rejecting a real one.
            // RECALL-FIRST: no LEADING `\b` (so an IBAN glued to a word-char prefix is
            // still caught — the mod-97 checksum supplies precision); a trailing `\b`
            // only ends the BBAN run cleanly at a separator.
            (
                builtins.iban,
                Recognizer::Iban,
                r"[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b",
                Some(iban_valid),
            ),
            // ISO 17442 Legal Entity Identifier (LEI): exactly 20 chars
            // `[A-Z0-9]{18}[0-9]{2}` (18 alphanumeric body + 2 mod-97-10 check digits)
            // that PASSES the ISO 7064 mod-97-10 check. OPT-IN, OFF by default (`lei`):
            // a public LEI is borderline PII, so it is enabled by an explicit user
            // choice, NOT a global built-in — when off, this row contributes nothing and
            // the candidate set is byte-identical. The checksum is what makes the broad
            // 20-char pattern precise (a real LEI always passes, so the validator only
            // filters non-LEIs WITHOUT a miss), exactly like the card/IBAN. RECALL-FIRST:
            // leading + trailing `\b` so the 20-char token is matched whole (the LEI is a
            // fixed-length token, not glued into longer alphanumerics); the checksum
            // supplies precision. Unlike the broad `id` recognizer (which requires a
            // LETTER-leading token), this matches a DIGIT-LEADING LEI too (e.g.
            // `549300...`), which is why those are otherwise missed.
            (
                lei,
                Recognizer::Lei,
                r"\b[A-Z0-9]{18}[0-9]{2}\b",
                Some(lei_valid),
            ),
            // ISO 9362 BIC — the STANDALONE 11-CHAR (branch) form ONLY: 4 alpha bank
            // code + 2 alpha country + 2 alnum location + 3 alnum branch,
            // STRUCTURE-validated ([`bic11_standalone_valid`]: real ISO 3166 country at
            // chars 5–6, SWIFT location rules, and — for a letter-only match — the `XXX`
            // head-office branch, which no ordinary 11-letter caps word satisfies
            // ("INSTRUCTION"/"TRANSACTION"/"PARTNERSHIP" all carry a coincidental valid
            // country and would otherwise FP on caps headings). ON by default like the
            // IBAN (`builtins.bic`) — a BIC beside a redacted IBAN re-identifies the
            // institution (the verified finance-corpus leak). The word-shaped 8-CHAR
            // form and the letter-only non-`XXX` 11-char form are NOT rows here: both
            // fire only with a BIC/SWIFT label cue in-window — see
            // [`RedactionEngine::bic_labeled_spans`]. Structure-only (no checksum), so
            // `confidence_for` keeps it in the CAREFUL review tier (never quick-confirm).
            (
                builtins.bic,
                Recognizer::Bic,
                r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{5}\b",
                Some(bic11_standalone_valid),
            ),
            // ISO 6166 ISIN: 2 alpha prefix + 9 alnum NSIN + 1 check digit that PASSES
            // the ISIN Luhn ([`isin_valid`] — letters expanded A..Z → 10..35, then
            // mod-10). ON by default like the IBAN (`builtins.isin`); the checksum makes
            // the 12-char shape precise (a real ISIN always passes, so the validator
            // only filters NON-ISINs — no miss), exactly like card/IBAN/LEI. The final
            // `\d` + exact length keep ordinary 12-char caps words out on shape alone.
            (
                builtins.isin,
                Recognizer::Isin,
                r"\b[A-Z]{2}[A-Z0-9]{9}\d\b",
                Some(isin_valid),
            ),
            // IPv4 dotted-quad with per-octet 0–255 bounds (so "999.1.1.1" does
            // not match). Format-only; an IPv4 shape is specific enough.
            (
                builtins.ip,
                Recognizer::Ip,
                r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
                None,
            ),
            // IPv6: full 8-group form plus the common compressed `::` forms. Every
            // alternative requires real hex groups (never a bare `::`), so it does
            // not match time-like `12:34` text.
            (
                builtins.ip,
                Recognizer::Ip,
                r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{1,4})*|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}",
                None,
            ),
            // URLs: an http/https/ftp scheme URL, or a bare `www.` host. The run
            // stops at whitespace and a few structural delimiters (`<>"'`/`)`/`]`).
            // RECALL-FIRST: it deliberately does NOT exclude a trailing `.`/`,`/`;`
            // (those are valid mid-URL), so a sentence-final `.`/`,` may be swallowed
            // into the match — an over-match (a redacted trailing punctuation char),
            // which is safe; it never leaves an identifier behind.
            (
                builtins.url,
                Recognizer::Url,
                r#"(?:https?|ftp)://[^\s<>"')\]]+|\bwww\.[^\s<>"')\]]+"#,
                None,
            ),
            // STRUCTURED STREET ADDRESS (spec §"ADDRESS FAMILY", GA-1): a house/lot
            // NUMBER (`50`, `221B`), then 0–4 Capitalized street-name tokens, then a
            // street-TYPE suffix (case-tolerant via the `(?i:…)` group). RECALL-FIRST and
            // deliberately broad — a "14 items on the road"-shaped run can match — so it
            // routes to the CAREFUL tier (`Recognizer::Address` is neither checksum nor
            // structural, so `confidence_for` caps it at Medium/Low). The street-name
            // tokens are `\p{Lu}`-anchored so a bare-number + lowercase-word run does NOT
            // match, which keeps the flood bounded while still catching real Capitalized
            // street names ("50 Raffles Place", "221B Baker Street"). Multi-token street
            // names are allowed. Linear-time (bounded `{0,4}` repetition — no ReDoS).
            (
                builtins.address,
                Recognizer::Address,
                ADDR_STREET_PATTERN,
                None,
            ),
            // FLOOR / UNIT forms (spec §"ADDRESS FAMILY", GA-2): the SG unit form
            // `#NN-NN(NN)` (`#16-03`, `#33-01`, `#16-0304`) and the labelled floor/unit
            // forms (`Level 12`, `Suite 4`, `Unit 8`, `Apt 3B`, `Block 5`). Each requires
            // a trailing digit run, so a bare "Unit tests" never matches. CAREFUL tier.
            (
                builtins.address,
                Recognizer::Address,
                ADDR_UNIT_PATTERN,
                None,
            ),
            // PO-BOX forms (spec §"ADDRESS FAMILY", GA-3): `PO Box 123`, `P.O. Box 123`,
            // `Post Office Box 123`, `Locked Bag 5`. Requires a trailing box number, so a
            // stray "post office" without a number never matches. CAREFUL tier.
            (
                builtins.address,
                Recognizer::Address,
                ADDR_POBOX_PATTERN,
                None,
            ),
            // OPT-IN BROADENED ADDRESSES (`addresses_full`, default OFF — plumbed exactly like
            // `lei`): foreign-format streets, building/premises names, and the Luxembourg
            // postal shape. They ride the EXISTING `Recognizer::Address` family (careful
            // review). OFF ⇒ the `enabled` filter drops all three ⇒ no patterns compiled ⇒
            // byte-identical default (the DEFAULT address recognizers above are untouched).
            (
                addresses_full,
                Recognizer::Address,
                ADDR_FOREIGN_STREET_PATTERN,
                None,
            ),
            (
                addresses_full,
                Recognizer::Address,
                ADDR_BUILDING_PATTERN,
                None,
            ),
            (
                addresses_full,
                Recognizer::Address,
                ADDR_LU_POSTAL_PATTERN,
                None,
            ),
        ];
        // Accumulate, IN LOCKSTEP with `patterns`, the regex SOURCE string of every
        // pushed `TaggedPattern` — in the SAME order, with the SAME `enabled` filter.
        // This list builds the `pattern_set` prefilter so its index `i` corresponds
        // EXACTLY to `patterns[i]` (the load-bearing index-alignment invariant: a
        // misaligned set would prune the wrong pattern = a silent miss/mislabel).
        // Every source is a `&'static str`, so this borrows — no allocation.
        let mut pattern_set_sources: Vec<&str> = Vec::new();
        let mut patterns: Vec<TaggedPattern> = pattern_sources
            .iter()
            .filter(|(enabled, ..)| *enabled)
            .map(|(_, kind, p, validate)| {
                pattern_set_sources.push(p);
                TaggedPattern {
                    kind: kind.clone(),
                    re: Regex::new(p).expect("built-in redaction pattern must compile"),
                    validate: *validate,
                }
            })
            .collect();

        // Append the OPT-IN locale packs IN ADDITION to the global built-ins. Each
        // jurisdiction's data rows compile into the SAME `TaggedPattern` machinery
        // (so they merge / dedup / validate identically), tagged with the generic
        // `Recognizer::Locale(<locale>:<name>)` carrying a refcount-shared label
        // (FIX #14). A locale appearing more than once in `locales` is harmless —
        // its rows just compile twice and the duplicate spans merge — but the
        // builder dedups the list first so this is the common case of unique packs.
        // Patterns are static + known-good (linear-time `regex`, no ReDoS), so
        // `expect` documents the compile-always invariant exactly like the built-ins.
        // CONTEXT-REQUIRED LOCALE rows: capture the required-context lexicon of every
        // compiled locale row whose `context` field is `Some`, keyed by its namespaced
        // label, so the finalizer's additive-only gate can recover it. Empty unless a
        // context-required row (e.g. `us:dl`) is enabled — the default path then skips
        // the locale-context gate entirely (byte-identical to before this existed).
        let mut locale_required_context: HashMap<Arc<str>, &'static [&'static str]> =
            HashMap::new();
        // AGGRESSIVE locale rows: the `<locale>:<name>` labels of the broad, format-only
        // "last-resort" rows (DL / passport / generic account / BSB / transit / sort code)
        // — captured here EXACTLY like `locale_required_context` so the merge's primary-
        // election can DEMOTE them below every precise recognizer (precedence-only, never
        // fire/drop — RECALL-NEUTRAL). EMPTY unless an aggressive row is enabled, so the
        // default path's priority comparison is byte-identical.
        let mut aggressive_locales: HashSet<Arc<str>> = HashSet::new();
        for &locale in locales {
            for row in locale_recognizers(locale) {
                let label = format!("{}:{}", locale.label(), row.name);
                let label_arc: Arc<str> = Arc::from(label.as_str());
                // A context-required row records its lexicon under the SAME `Arc<str>`
                // label the recognizer carries, so the gate's `HashMap` lookup is a
                // refcount-shared key (not a re-allocated string).
                if let Some(lexicon) = row.context {
                    locale_required_context.insert(label_arc.clone(), lexicon);
                }
                // An aggressive row records its label under the SAME refcount-shared
                // `Arc<str>` key, so the priority demotion lookup is allocation-free.
                if row.aggressive {
                    aggressive_locales.insert(label_arc.clone());
                }
                // Keep the prefilter source list in lockstep (index-aligned).
                pattern_set_sources.push(row.pattern);
                patterns.push(TaggedPattern {
                    kind: Recognizer::Locale(label_arc),
                    re: Regex::new(row.pattern).expect("locale recognizer pattern must compile"),
                    validate: row.validate,
                });
            }
        }

        // OPT-IN AGGRESSIVE SG-NRIC LOOSE NET (gated by `sg_nric_loose`, default OFF —
        // plumbed exactly like `lei`). These two rows are registered INDEPENDENTLY of the
        // `Locale::Singapore` pack (so they are NOT folded into the always-on `sg:nric`/
        // `sg:uen` rows): an SG firm opts into the loose net SEPARATELY from the precise SG
        // pack. They compile through the IDENTICAL `TaggedPattern` machinery + record their
        // `sg:nric-loose`/`sg:nric-context` labels in `aggressive_locales` (advisory +
        // demoted) and `locale_required_context` (the context row's keyword gate) — so the
        // merge's precise-wins demotion + the additive context gate both apply with no other
        // change. OFF = no patterns added (byte-identical to today). Tagged `sg:*`, so they
        // already map to the `[Singapore ID]` type label.
        if sg_nric_loose {
            for row in packs::sg::loose_rows() {
                let label = format!("{}:{}", Locale::Singapore.label(), row.name);
                let label_arc: Arc<str> = Arc::from(label.as_str());
                if let Some(lexicon) = row.context {
                    locale_required_context.insert(label_arc.clone(), lexicon);
                }
                if row.aggressive {
                    aggressive_locales.insert(label_arc.clone());
                }
                pattern_set_sources.push(row.pattern);
                patterns.push(TaggedPattern {
                    kind: Recognizer::Locale(label_arc),
                    re: Regex::new(row.pattern)
                        .expect("sg loose-net recognizer pattern must compile"),
                    validate: row.validate,
                });
            }
        }

        // Append every enabled PROFILE's OWN bespoke rows the same way, tagged with
        // the generic `Recognizer::Profile(<profile>:<name>)` (FIX #14 refcount-shared
        // label). A profile's required BUILT-INS were already OR-merged above (they
        // keep their own built-in label, not a `profile:` one); only a profile's
        // bespoke rows attribute here. The PCI worked example has zero bespoke rows,
        // so this loop is a no-op for it — but a fan-out profile drops its rows in with
        // no shared-code churn. Static + known-good patterns, so `expect` documents the
        // compile-always invariant exactly like the built-ins/locales.
        for &profile in profiles {
            let spec = profile.spec();
            for row in spec.rows {
                let label = format!("{}:{}", spec.name, row.name);
                // Keep the prefilter source list in lockstep (index-aligned).
                pattern_set_sources.push(row.pattern);
                patterns.push(TaggedPattern {
                    kind: Recognizer::Profile(Arc::from(label.as_str())),
                    re: Regex::new(row.pattern).expect("profile recognizer pattern must compile"),
                    validate: row.validate,
                });
            }
        }

        // LEVER 2: append every ENABLED context-required recognizer row the SAME way,
        // tagged with the generic `Recognizer::Context(ctx:<name>)`. These flow through
        // the IDENTICAL `TaggedPattern` machinery (prefilter + validate + merge) as the
        // built-ins/locales/profiles — they are just gated at FINALIZATION by the
        // additive-only gate in `merged_spans`. OFF by default (the `enabled` filter
        // yields nothing unless the caller opted in), so the default path adds no
        // patterns and stays byte-identical. Static + known-good patterns, so `expect`
        // documents the compile-always invariant exactly like the other axes.
        for row in context::CONTEXT_RECOGNIZERS
            .iter()
            .filter(|r| context_recognizers.enabled(r.name))
        {
            let label = format!("ctx:{}", row.name);
            // Keep the prefilter source list in lockstep (index-aligned).
            pattern_set_sources.push(row.pattern);
            patterns.push(TaggedPattern {
                kind: Recognizer::Context(Arc::from(label.as_str())),
                re: Regex::new(row.pattern).expect("context recognizer pattern must compile"),
                validate: row.validate,
            });
        }

        // WHITESPACE-ELASTIC ADDRESS-FAMILY recall set (the PDF glyph-by-glyph fix for
        // STRUCTURED ADDRESSES — the address-family analogue of `ws_term_patterns`). Built
        // from the SAME sources the ordinary detection uses (the `ADDR_*` consts + each
        // precise postal row's `pattern`) via `ws_elastic_pattern`, so there is no drift.
        // Compiled NON-FATALLY (`.ok()`): a transform that ever produced an invalid regex is
        // SKIPPED (degrade to no whitespace-recall for that one row) — never a panic, never a
        // miss worse than today's baseline (the ordinary pass still runs). EMPTY unless
        // `builtins.address` is on OR a precise postal locale is enabled, so the elastic
        // address pass in `pdf.rs` is then a byte-identical no-op (the common case).
        let mut address_ws_patterns: Vec<(Regex, Recognizer)> = Vec::new();
        if builtins.address {
            for src in [ADDR_STREET_PATTERN, ADDR_UNIT_PATTERN, ADDR_POBOX_PATTERN] {
                if let Ok(re) = Regex::new(&ws_elastic_pattern(src)) {
                    address_ws_patterns.push((re, Recognizer::Address));
                }
            }
        }
        // Every enabled locale's PRECISE postal row (unconditional, non-aggressive). The
        // aggressive/context-gated BARE-postal nets (`sg:postal-bare`, `us:zip-bare`) are
        // DELIBERATELY excluded: a bare `\d{5,6}` run made whitespace-elastic over a PDF run
        // would flood — scoping the elastic recall to the DISTINCTIVE postal shapes IS the FP
        // guard (constraint (a)). `locales` is already deduped by the builder.
        for &locale in locales {
            for row in locale_recognizers(locale) {
                let is_precise_postal = matches!(row.name, "postal" | "postcode" | "zip")
                    && !row.aggressive
                    && row.context.is_none();
                if !is_precise_postal {
                    continue;
                }
                let label: Arc<str> =
                    Arc::from(format!("{}:{}", locale.label(), row.name).as_str());
                if let Ok(re) = Regex::new(&ws_elastic_pattern(row.pattern)) {
                    address_ws_patterns.push((re, Recognizer::Locale(label)));
                }
            }
        }

        // PERF PREFILTER (pure optimization): a `RegexSet` over the SOURCE strings
        // collected IN LOCKSTEP above, so `pattern_set` index `i` == `patterns[i]`.
        // `RegexSet::new` over these same patterns cannot fail — each already compiled
        // as a standalone `Regex` (the `expect`s above ran first); an empty source
        // list (e.g. `BuiltinRecognizers::none()` + no locales/profiles) yields a
        // never-matching set, never a panic.
        let pattern_set = RegexSet::new(&pattern_set_sources)
            .expect("pattern prefilter set must compile (sources valid)");

        Self {
            term_patterns,
            term_set,
            ws_term_patterns,
            address_ws_patterns,
            patterns,
            pattern_set,
            aggressive_name: None,
            user_recognizers: Vec::new(),
            classes,
            profiles: profiles.to_vec(),
            context_recognizers,
            locale_required_context,
            aggressive_locales,
            // NAME-PROPAGATION expansion tier: OFF by default (the SAFE tier always runs;
            // expansion is the opt-in). Turned on by the builder's `name_expansion(true)`.
            name_expansion: false,
            // OPT-IN organisation detection — carried through so `merged_spans` runs the
            // `organisation_spans` pass only when enabled (no-op / byte-identical when off).
            organisations,
            // BIC toggle (post-profile-merge `builtins`) — drives the 8-char labeled pass.
            bic: builtins.bic,
            // PHONE toggle (post-profile-merge) — drives the label-cued relaxed arm.
            phone: builtins.phone,
        }
    }

    /// Compile a set of firm [`UserRecognizer`]s into DEDUPLICATED [`Compiled`]
    /// patterns (FIX #5). Every recognizer is validated up front (fail-closed: a
    /// bad pattern aborts with [`CoreError::Backend`] rather than silently dropping
    /// a firm rule). Recognizers whose validated `(source, case_sensitive)` MATCHES
    /// — i.e. that would compile to a byte-identical regex — share ONE compiled
    /// `Regex`; each contributes a [`CustomTag`], so a single scan attributes the
    /// match to ALL of them. The zero-width-only probe runs ONCE per unique source
    /// (it is a property of that source), not once per duplicate.
    ///
    /// INSERTION ORDER of the FIRST occurrence of each unique pattern is preserved,
    /// keeping the match pass deterministic regardless of how many duplicates of a
    /// pattern were configured.
    pub(crate) fn compile_recognizers(
        recognizers: impl IntoIterator<Item = UserRecognizer>,
    ) -> CoreResult<Vec<Compiled>> {
        let mut compiled: Vec<Compiled> = Vec::new();
        // Map (source, case_sensitive) -> index into `compiled`, so a duplicate
        // pattern adds its tag to the existing entry instead of recompiling.
        let mut index: HashMap<(String, bool), usize> = HashMap::new();

        for r in recognizers {
            // Validate + produce the dedup key + audit-safe tag (fail-closed).
            let spec = r.spec()?;
            let key = (spec.source.clone(), spec.case_sensitive);
            let tag = CustomTag {
                kind: spec.kind,
                replacement: spec.replacement,
            };
            if let Some(&i) = index.get(&key) {
                // Same compiled pattern already present — just attach this label.
                compiled[i].tags.push(tag);
                continue;
            }
            // First time we see this pattern: compile it ONCE, run the zero-width
            // probe ONCE (a property of the source, identical across duplicates).
            let re = RegexBuilder::new(&spec.source)
                .case_insensitive(!spec.case_sensitive)
                .build()
                .map_err(|e| {
                    CoreError::Backend(format!(
                        "user recognizer {}: invalid pattern: {e}",
                        tag.kind
                    ))
                })?;
            if matches_zero_width_only(&re) {
                return Err(CoreError::Backend(format!(
                    "user recognizer {}: pattern matches no non-empty text (empty or zero-width)",
                    tag.kind
                )));
            }
            index.insert(key, compiled.len());
            compiled.push(Compiled {
                re,
                tags: vec![tag],
            });
        }
        Ok(compiled)
    }

    /// Enable the OPT-IN AGGRESSIVE name mode: in addition to title-prefixed
    /// names, flag ANY run of two-or-more Capitalized words as a [`Recognizer::Name`]
    /// candidate.
    ///
    /// OFF by default for a reason: a capitalized-bigram rule flags every
    /// sentence-initial word pair, place name, company name, and heading — it
    /// makes the redacted output unreadable and buries the reviewer in false
    /// flags. Turn it on only when you want maximum recall and will hand the
    /// result to a human who triages aggressively. It remains a HEURISTIC, not
    /// name detection.
    pub fn aggressive(mut self) -> Self {
        // A run of >=2 Capitalized (uppercase-initial) words. Unicode-aware.
        self.aggressive_name = Some(
            Regex::new(r"\p{Lu}\p{L}*(?:\s+\p{Lu}\p{L}*)+")
                .expect("built-in aggressive name pattern must compile"),
        );
        self
    }

    /// The OPT-IN compliance [`Profile`]s this engine was built with (deduped, in
    /// build order). Empty unless built via [`builder`](RedactionEngine::builder)`
    /// .profiles(..)`.
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// Whether the OPT-IN NAME-PROPAGATION EXPANSION tier is enabled (see
    /// [`name_propagation_spans`](RedactionEngine::name_propagation_spans) and
    /// [`RedactionEngineBuilder::name_expansion`]). The SAFE tier is always on regardless.
    pub fn name_expansion(&self) -> bool {
        self.name_expansion
    }

    /// The deduplicated, HONEST human-review gaps across every enabled compliance
    /// profile — the identifier categories the DETERMINISTIC engine cannot cover and
    /// which the reviewer must still handle by judgment (cardholder names, free-text
    /// references, …). This is the "reasonable-efforts, never safe-to-send" posture as
    /// a reachable typed contract: a host/UI calls this to render "this profile
    /// deterministically covers X; THESE categories still need a human." Empty when no
    /// profile is enabled. Order is stable (first-seen across profiles in build order).
    pub fn profile_review_gaps(&self) -> Vec<&'static str> {
        let mut gaps: Vec<&'static str> = Vec::new();
        for p in &self.profiles {
            for &g in p.spec().human_review_gaps() {
                if !gaps.contains(&g) {
                    gaps.push(g);
                }
            }
        }
        gaps
    }

    /// A deterministic, cleartext-FREE one-line note describing the ACTIVE compliance
    /// profile selection for the audit chain (e.g.
    /// `profiles: pci-dss-cardholder; review-gaps: cardholder name | …`). Records the
    /// profile NAMES + their honest review-gap CATEGORIES only — both are static
    /// config strings (recognizer/category names), never a matched value — so it is
    /// audit-safe. Returns `None` when no profile is enabled, so the audit trail of a
    /// plain (no-profile) engine is byte-identical to before this axis existed.
    fn profile_selection_note(&self) -> Option<String> {
        if self.profiles.is_empty() {
            return None;
        }
        let names = self
            .profiles
            .iter()
            .map(|p| p.label())
            .collect::<Vec<_>>()
            .join(", ");
        let gaps = self.profile_review_gaps().join(" | ");
        Some(format!(
            "redaction profiles: {names}; human-review gaps: {gaps}"
        ))
    }

    /// Collect ALL redaction candidates in `text` as merged, deduplicated spans
    /// over the ORIGINAL content. PURE + DETERMINISTIC.
    ///
    /// # Single authoritative pass
    ///
    /// Every recognizer (regex patterns, the optional aggressive name pattern,
    /// and each escaped term) is matched against the ORIGINAL `text` exactly
    /// once. Offsets are therefore valid char boundaries in the original, so
    /// `text[c.start()..c.end()] == c.matched_value()` for every returned candidate.
    ///
    /// # Overlap-resolution rule (deterministic)
    ///
    /// Raw matches may overlap or touch (e.g. a phone run inside a longer id, an
    /// email whose local part also matches a term). We:
    /// 1. collect every raw match `(start, end, recognizer)`;
    /// 2. sort by `start` ASC, then by `end` DESC (longer span first), then by
    ///    recognizer priority (most specific first) — a total, stable order;
    /// 3. sweep left-to-right merging any span that OVERLAPS OR TOUCHES the
    ///    current accumulator (`next.start <= acc.end`) into one union span;
    /// 4. the merged span's recognizer is the PRIMARY one — the highest-priority
    ///    (lowest [`Recognizer::priority`]) among the merged members, ties broken
    ///    by earliest start.
    ///
    /// So overlapping/adjacent matches become ONE candidate (one redaction): no
    /// double-counting, no surviving fragment.
    ///
    /// # Replacement on merge (deterministic — FIX F7)
    ///
    /// A span carrying a `replacement: Some(s)` (a firm-defined find-AND-replace
    /// rule) records that custom replacement. When spans MERGE into one union span,
    /// the resolved replacement is decided by the DISTINCT custom replacements over
    /// the union: exactly ONE distinct custom replacement is unambiguous and is
    /// PRESERVED (so e.g. a `Custom` `jane.roe -> [PARTY]` span wholly contained
    /// inside a built-in email span still writes `[PARTY]`, NOT the default marker);
    /// ZERO custom replacements (all members default) writes the default
    /// [`REDACTION_MARKER`]; ≥2 DIFFERENT custom replacements are genuinely
    /// ambiguous and fall back to the marker — the unambiguous, safe default.
    pub fn candidates(&self, text: &str) -> Vec<RedactionCandidate> {
        self.merged_spans(text)
            .into_iter()
            .map(|m| m.candidate)
            .collect()
    }

    /// Whether `recognizer` is an AGGRESSIVE locale row in THIS engine's config — i.e. a
    /// broad, format-only "last-resort" shape (driver's licence / passport / generic
    /// account / BSB / transit / sort code, and the opt-in loose SG-NRIC net) whose pack
    /// row carries `aggressive: true`. True ONLY for a [`Recognizer::Locale`] whose
    /// namespaced label is registered in the engine's `aggressive_locales` set at build;
    /// false for every PRECISE recognizer (email/phone/checksummed card/IBAN/IP/URL/the
    /// name heuristic, and every non-aggressive locale row such as `sg:nric`/`sg:uen`).
    ///
    /// This is the public seam the host (`redact-cli`) consults to mark a candidate
    /// ADVISORY: an aggressive-row candidate is surfaced for review but DEFAULT-OFF in the
    /// apply accept-set (the human opts IN). It reuses the SAME `aggressive_locales` set the
    /// merge-priority demotion ([`recognizer_priority`](RedactionEngine::recognizer_priority))
    /// already consults, so "advisory" and "demoted in the label contest" can never drift.
    /// Pass a candidate's PRIMARY [`recognizer`](RedactionCandidate::recognizer) — the
    /// precise-wins merge guarantees a token covered by a precise row is labeled by the
    /// precise row, so only an EXTRA token matched solely by an aggressive row is advisory.
    /// Empty `aggressive_locales` (the common case — no aggressive locale enabled) makes
    /// this uniformly `false`, byte-identical to before this method existed.
    pub fn is_aggressive(&self, recognizer: &Recognizer) -> bool {
        match recognizer {
            Recognizer::Locale(label) => self.aggressive_locales.contains(label),
            // PAN LAST-4 (RATIFIED): a referenced/masked card tail is SURFACED but
            // ADVISORY — default-off in apply, the human opts in (the sg:nric-loose
            // posture; see [`PAN_LAST4_LABEL`]).
            Recognizer::Context(label) => label.as_ref() == PAN_LAST4_LABEL,
            _ => false,
        }
    }

    /// WHITESPACE-INSENSITIVE user-TERM matching against `text`, returning each match
    /// as a half-open `(start, end)` byte range over `text`. ONLY the user-supplied
    /// [`terms`](RedactionEngine::terms) are matched here — never the built-in / locale
    /// / name recognizers — and every ASCII-whitespace run in BOTH the term and the
    /// haystack is treated as elastic (zero-or-more whitespace). Returns spans sorted by
    /// start, with nested/overlapping matches coalesced into maximal disjoint ranges.
    ///
    /// # Why this exists (the PDF glyph-by-glyph recall fix)
    ///
    /// Some PDF generators lay out a line GLYPH-CLUSTER BY GLYPH-CLUSTER — each cluster
    /// is its own show operator with a `Td` cursor nudge between them — so a single word
    /// like `Watkins` is emitted as `W` `at` `kins`. The PDF reconstruction inserts a
    /// fabricated separator space at each horizontal nudge, yielding `Daniel J. W at kins`
    /// for the term `Daniel J. Watkins`. The ordinary [`candidates`](RedactionEngine::
    /// candidates) pass then MISSES the term (the spurious internal spaces break the
    /// literal match), so a director name DETECTED elsewhere SURVIVES `pdf_apply` on that
    /// page — a leak. Collapsing whitespace on both sides makes the term match regardless
    /// of how the generator fragmented the word; the PDF layer maps the collapsed span
    /// back to the exact source glyph bytes for true removal.
    ///
    /// SAFE-SIDE by construction: terms are KNOWN, user-supplied literals (party /
    /// director / company names), so a whitespace-elastic match can only OVER-match within
    /// a visual line, which on a redaction tool is the safe side (a few reviewer-seconds vs
    /// a missed identifier). It NEVER matches a built-in pattern, so generic recognizers
    /// keep their exact behavior. With NO terms configured this returns empty (the common
    /// case is untouched). Deterministic: a `find_iter` over a fixed per-term regex; no
    /// clock, no RNG, no network.
    pub fn term_spans_whitespace_insensitive(&self, text: &str) -> Vec<(usize, usize)> {
        if self.ws_term_patterns.is_empty() {
            return Vec::new();
        }
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for re in &self.ws_term_patterns {
            for m in re.find_iter(text) {
                if m.end() > m.start() {
                    spans.push((m.start(), m.end()));
                }
            }
        }
        if spans.is_empty() {
            return spans;
        }
        // Coalesce into maximal disjoint ranges (ascending). Two terms can match
        // overlapping regions of the same line; the PDF layer removes the union.
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (s, e) in spans {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }

    /// Every WHITESPACE-ELASTIC ADDRESS-FAMILY match in `text` as `(start, end, recognizer)`
    /// BYTE ranges — the STRUCTURED-ADDRESS analogue of [`term_spans_whitespace_insensitive`]
    /// (the PDF glyph-by-glyph recall fix). Scans `text` with the pre-built
    /// [`address_ws_patterns`](RedactionEngine::address_ws_patterns) (the three global
    /// address built-ins + the PRECISE locale postal rows, made whitespace-elastic), so a
    /// structured address a PDF generator fragmented across `Td`-nudged show operators
    /// (`#16-03` reconstructed as `# 16-0 3`, `Singapore 048623` as `Singapore 0486 23`)
    /// still matches. Each match carries the SAME [`Recognizer`] the ordinary pass would
    /// attribute, so the fragmented address is labeled/audited identically.
    ///
    /// SCOPED to the address family ON PURPOSE: only shapes that stay DISTINCTIVE under
    /// `\s`-interleave get elastic recall — the general recognizers (phone/id/email/…) are
    /// NEVER whitespace-elastic (that would flood a reviewer). With no address rows enabled
    /// (`address_ws_patterns` empty) this returns empty and the PDF pass is a byte-identical
    /// no-op. Deterministic: `find_iter` over fixed regexes; no clock, no RNG, no network.
    ///
    /// Results are sorted by start; a match FULLY CONTAINED in an earlier kept match is
    /// dropped (a pure duplicate — e.g. the street row and a locale postal row overlapping
    /// the same run). PARTIAL overlaps are KEPT (removed in full by the PDF layer — the safe
    /// side, exactly as the ws-term pass treats a partial overlap).
    pub fn address_family_spans_whitespace_insensitive(
        &self,
        text: &str,
    ) -> Vec<(usize, usize, Recognizer)> {
        if self.address_ws_patterns.is_empty() {
            return Vec::new();
        }
        let mut spans: Vec<(usize, usize, Recognizer)> = Vec::new();
        for (re, rec) in &self.address_ws_patterns {
            for m in re.find_iter(text) {
                // ROUND 6 (the page-7 boundary-drift finding, root-caused): the elastic
                // transform drops the patterns' anchors and makes every token atom
                // whitespace-elastic, so over a MULTI-LINE joined page text one street
                // "word" could sweep an entire directory COLUMN and terminate at the
                // `ST` of a following `REGISTERED …` heading (observed verbatim: a
                // 200+-byte `address` span `3\n \n \nDIRECTORY\n…\nREGIST` that
                // struck six chars off the heading). An elastic address ROW is an
                // intra-line fragmentation fix: bound each match to <= 2 line breaks
                // and <= 120 bytes (a genuinely wrapped `Capital \nTower, Singapore
                // 068912` row fits; a column sweep cannot).
                let too_wide = m.as_str().bytes().filter(|&b| b == b'\n').count() > 2
                    || m.end() - m.start() > 120;
                if m.end() > m.start() && !too_wide {
                    spans.push((m.start(), m.end(), rec.clone()));
                }
            }
        }
        if spans.is_empty() {
            return spans;
        }
        // Deterministic order: by start ASC, then by WIDER span first (larger end), then by
        // recognizer label so equal ranges from two rows order stably. This makes the
        // containing span appear before the ones it contains, so the containment drop below
        // keeps the widest and skips the pure duplicates.
        spans.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.to_string().cmp(&b.2.to_string()))
        });
        let mut kept: Vec<(usize, usize, Recognizer)> = Vec::with_capacity(spans.len());
        for (s, e, rec) in spans {
            // Drop a span FULLY CONTAINED in one already kept (a pure duplicate the wider
            // match already removes). A partial overlap is kept and removed in full.
            if kept.iter().any(|(ks, ke, _)| *ks <= s && e <= *ke) {
                continue;
            }
            kept.push((s, e, rec));
        }
        // Return in ascending start order (the PDF append relies on a stable order; the
        // sort above already ordered by start, and the containment drop preserves it).
        kept
    }

    /// The ENGINE-AWARE merge priority of a recognizer (lower wins the PRIMARY-LABEL
    /// election on an overlapping merged span). Identical to [`Recognizer::priority`]
    /// for every recognizer EXCEPT an AGGRESSIVE locale row (a broad, format-only
    /// last-resort shape registered in `aggressive_locales` at build): that row is
    /// DEMOTED to [`AGGRESSIVE_LOCALE_PRIORITY`] (the Phone/Ip tier) so it ranks BELOW
    /// every precise recognizer — a precise locale row (priority 1), a checksum built-in
    /// (1), email (2), and id/url (3) all out-label it on an overlap. The user's
    /// directive: "make the most aggressive ones the LAST ones for redaction" — a broad
    /// recognizer is elected primary only as a LAST RESORT.
    ///
    /// PRECEDENCE-ONLY / RECALL-NEUTRAL: this only orders WHICH recognizer LABELS a
    /// merged span; it NEVER changes whether a candidate fires or is dropped. A token
    /// matched ONLY by an aggressive row is still redacted (just labeled by it), because
    /// the row still produces a raw span and still survives the merge. `aggressive_locales`
    /// is EMPTY in the common case, so this is a pure passthrough to `Recognizer::priority`
    /// and every merge order is byte-identical to before this method existed.
    ///
    /// The demotion still keeps an aggressive locale row ABOVE the broad `Name` heuristic
    /// (priority 5) and a context-only span (`Context`, priority 6), so it remains the
    /// primary over THOSE — it is "last resort" among real identifier shapes, not below
    /// the deliberately-weakest heuristics. The total/deterministic order is preserved:
    /// only the priority NUMBER changes, and the existing label-ASC tie-break in the merge
    /// sort still totally orders any equal-priority pair.
    fn recognizer_priority(&self, r: &Recognizer) -> u8 {
        match r {
            // An aggressive locale row is demoted below every precise recognizer.
            // (`aggressive_locales` is empty unless such a row is enabled, so the
            // default path never reaches the demoted branch — pure passthrough.)
            Recognizer::Locale(label) if self.aggressive_locales.contains(label) => {
                AGGRESSIVE_LOCALE_PRIORITY
            }
            // Every other recognizer keeps its static priority unchanged.
            other => other.priority(),
        }
    }

    /// OPT-IN ORGANISATION detection — a deterministic pass that emits the `ctx:org`
    /// recognizer class ([`ORG_CONTEXT_LABEL`]) for organisation / company names, the UNION of
    /// two arms:
    ///
    /// - **(a) SUFFIX-ANCHORED** ([`org_suffix_regex`]): a Capitalized multi-token run
    ///   immediately followed by an org SUFFIX (`Pte Ltd`, `LLP`, `S.A.`, `GmbH`, `Limited`,
    ///   `Inc`, `Holdings`, `Group`, `Partners`, `& Co`, `Sdn Bhd`, `Berhad`, …). Wrap-tolerant.
    ///   The whole run + suffix is one org span. Low-FP (the suffix is a strong signal).
    /// - **(b) ORG-CONTEXT** ([`org_context_regex`]): a Capitalized run of ≥2 tokens near an
    ///   org-context cue (`incorporated in`, `trustee`, `manager`, `registrar`, `legal
    ///   adviser`, …). This is the DELIBERATELY BROAD, higher-FP arm (the ratified choice — fund
    ///   / index names WILL flag). The ≥2-token floor excludes definite-article generics
    ///   (`the Company`/`the Fund`/`the Manager`). A person-shaped run with NO org signal is
    ///   left to the person path (not flagged as an org); an org-shaped run that OVERLAPS a
    ///   person `Name` span already in `raw` is skipped (the person is already covered — and on
    ///   any residual overlap the merge keeps the person primary, priority 5 < the `ctx:org`
    ///   priority 6, so a person recognizer WINS the overlap).
    ///
    /// LOAD-BEARING: every emitted span carries [`Recognizer::Context`]`(ctx:org)`, which is
    /// (i) NOT a `Recognizer::Name`, so it NEVER seeds `name_propagation_spans` /
    /// `propagate_name_candidates` / the PDF `ws_name_seeds_from_scan` recall — a broad org
    /// cannot amplify document-wide; (ii) pinned to the CAREFUL review tier by
    /// [`confidence_for`](RedactionEngine::confidence_for) (never quick-confirm/auto-accept);
    /// and (iii) ENTITY-family for placeholder routing (`assign_labels`) so an org renders
    /// `[A]`/`[B]`. Each arm is capped at [`MAX_ORG_NAMES`] emissions (bomb-bound). LINEAR-TIME
    /// (the `regex` crate is backtracking-free — no ReDoS over a 962pp doc), RNG-free.
    ///
    /// No-op unless `self.organisations` is set, so the default path is byte-identical.
    /// CONFIDENTIALITY: builds only IN-PROCESS cleartext (matched org text); the audit note
    /// records counts + recognizer breakdown only.
    fn organisation_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        if !self.organisations {
            return; // OPT-IN OFF ⇒ byte-identical default (no org candidates).
        }
        let org: Arc<str> = Arc::from(ORG_CONTEXT_LABEL);

        // Arm (a) — SUFFIX-ANCHORED. A strong signal; emitted directly (the merge defers to a
        // person on any overlap via the priority-6 demotion). A bare DEFINITE-ARTICLE GENERIC
        // (`The Company` = article + only the suffix, no proper-noun name) is DROPPED — it
        // carries no organisation identity. Capped at MAX_ORG_NAMES (counting emissions).
        let mut emitted_a = 0usize;
        for m in org_suffix_regex().find_iter(text) {
            if emitted_a >= MAX_ORG_NAMES {
                break; // per-arm bomb-bound (pathological input)
            }
            if org_match_is_generic(m.as_str()) {
                continue; // `The Company` / `A Group` — definite-article generic, not an org.
            }
            raw.push((m.start(), m.end(), Recognizer::Context(org.clone()), None));
            emitted_a += 1;
        }

        // Arm (a2) — ALL-CAPS SUFFIX-ANCHORED (the finance-corpus recall round): the SAME
        // suffix list matched case-insensitively, anchored to an ALL-CAPS token run
        // (`HELICON ANALYTICS PTE LTD`, `NORTHBRIDGE CAPITAL PARTNERS PTE. LTD.`) — the
        // mixed-case arm's case-sensitive suffix literals never matched these even with an
        // explicit suffix present. Same generic-guard + cap + `ctx:org` label (careful
        // review, NEVER a propagation seed); an overlap with arm (a) merges into one span.
        let mut emitted_a2 = 0usize;
        for m in org_suffix_caps_regex().find_iter(text) {
            if emitted_a2 >= MAX_ORG_NAMES {
                break; // per-arm bomb-bound (pathological input)
            }
            if org_match_is_generic(m.as_str()) {
                continue; // `THE COMPANY` — definite-article generic, not an org.
            }
            raw.push((m.start(), m.end(), Recognizer::Context(org.clone()), None));
            emitted_a2 += 1;
        }

        // Snapshot the PERSON spans already in `raw` — NOT just the honorific/header/trailing
        // `Recognizer::Name` runs, but ALSO the CONTEXT-detected persons (`ctx:role-name` and
        // the person-shaped `ctx:field-name`, both emitted before this pass) — so the
        // org-context arm can DEFER to any detected person ("not already a person candidate").
        // Recall-neutral: the person span stays; we merely avoid emitting a redundant `ctx:org`
        // over it (and never absorb a person name into an org span).
        let person_spans: Vec<(usize, usize)> = raw
            .iter()
            .filter(|(_, _, kind, _)| {
                matches!(kind, Recognizer::Name)
                    || matches!(kind, Recognizer::Context(l)
                        if l.as_ref() == FIELD_NAME_LABEL || l.as_ref() == "ctx:role-name")
            })
            .map(|(s, e, _, _)| (*s, *e))
            .collect();

        // Arm (b) — ORG-CONTEXT (the broad arm). Capture group 1 = the Capitalized run.
        let mut emitted_b = 0usize;
        for caps in org_context_regex().captures_iter(text) {
            if emitted_b >= MAX_ORG_NAMES {
                break; // per-arm bomb-bound
            }
            let Some(run) = caps.get(1) else { continue };
            let (s, e) = (run.start(), run.end());
            let val = run.as_str();
            // A person-shaped run with NO org signal near a cue is the manager's/adviser's
            // NAME, not an org — leave it to the person path (do NOT flag it as an org). A
            // person-shaped run that DOES carry an org word (`BlackRock Group`, `State Street
            // Bank`) is a real org and is kept. This is the ONLY tightening on the broad arm
            // and it never touches the suffix arm, so recall on suffixed / org-worded entities
            // is unaffected.
            if is_person_shaped_field_value(val) && !run_contains_org_word(val) {
                continue;
            }
            // "Not already a person candidate": skip a run overlapping a detected person span
            // (a `Recognizer::Name` OR a `ctx:role-name`/`ctx:field-name` person).
            if person_spans.iter().any(|(ns, ne)| s < *ne && e > *ns) {
                continue;
            }
            raw.push((s, e, Recognizer::Context(org.clone()), None));
            emitted_b += 1;
        }
    }

    /// ANCHORED ALL-CAPS PERSON-NAME pass (the finance-corpus recall round) — emits the
    /// [`CAPS_NAME_LABEL`] (`ctx:caps-name`) class for a CUE-CORROBORATED all-caps name
    /// run. The verified leak class: bank/card-statement TRANSACTION NARRATIVES print
    /// counterparty person names in ALL CAPS (`FAST TRANSFER FR DARIUS OKONKWO-LIM`,
    /// `CHEQUE 004512 PRIYA VENKATESAN`, `ZELLE FROM TREVOR OAKENSHIELD`) with no
    /// honorific, no `Name:` label, and no role heading — nothing else in the engine
    /// could anchor them.
    ///
    /// ANCHORED, NEVER FREE-RUNNING (the load-bearing FP bound — a bare "any 2+ word
    /// caps run" recognizer is forbidden, headings flood):
    ///  1. each all-caps run ([`caps_run_regex`], one visual line, ≥2-char tokens) is
    ///     SPLIT at [`CAPS_SPLIT_STOPWORDS`] (function words + finance head nouns — a
    ///     person name contains neither) AND at [`CAPS_NAME_CUES`] tokens;
    ///  2. only a 2–4-token surviving sub-run is a candidate NAME shape;
    ///  3. the sub-run must be CORROBORATED: a cue token elsewhere in the SAME run
    ///     (`TRANSFER` splitting `FAST TRANSFER FR DARIUS OKONKWO-LIM`), or a cue in the
    ///     ±[`context::CONTEXT_WINDOW_CHARS`] window (`CHEQUE 004512` before the name).
    ///
    /// So `STATEMENT OF ACCOUNT` / `TERMS AND CONDITIONS` / `PRIVATE AND CONFIDENTIAL`
    /// split to 1-token fragments and emit NOTHING, cue or no cue.
    ///
    /// SEEDING: NEVER — see [`CAPS_NAME_LABEL`] (the amplification-class decision). Tier:
    /// Medium via the no-row `Context` default → CAREFUL review, never quick-confirm.
    /// Gated on the SAME opt-in as `ctx:role-name` (`{"context": true}`), so the default
    /// path is byte-identical. Bomb-bounded at [`CAPS_NAME_MAX`] emissions. Deterministic,
    /// linear-time, no clock/RNG. CONFIDENTIALITY: in-process cleartext only; the audit
    /// note records counts + labels, never values.
    fn caps_person_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        if !self.context_recognizers.role_name {
            return; // OPT-IN OFF ⇒ byte-identical default (no caps-name candidates).
        }
        let label: Arc<str> = Arc::from(CAPS_NAME_LABEL);
        let mut emitted = 0usize;
        for m in caps_run_regex().find_iter(text) {
            if emitted >= CAPS_NAME_MAX {
                break; // bomb-bound (pathological all-caps input)
            }
            let run = m.as_str();
            let base = m.start();
            // Tokenize with byte offsets (ASCII space/tab separators per the run regex).
            let mut tokens: Vec<(usize, usize, &str)> = Vec::new(); // (abs start, abs end, tok)
            let mut off = 0usize;
            while off < run.len() {
                let rest = &run[off..];
                let skip = rest.len() - rest.trim_start_matches([' ', '\t']).len();
                off += skip;
                if off >= run.len() {
                    break;
                }
                let tok_len = run[off..].find([' ', '\t']).unwrap_or(run.len() - off);
                tokens.push((base + off, base + off + tok_len, &run[off..off + tok_len]));
                off += tok_len;
            }
            let is_stop = |t: &str| CAPS_SPLIT_STOPWORDS.contains(&t);
            let is_cue = |t: &str| CAPS_NAME_CUES.contains(&t);
            let run_has_cue = tokens.iter().any(|(_, _, t)| is_cue(t));
            // Split into maximal segments of consecutive non-stopword, non-cue tokens.
            let mut seg_start_idx: Option<usize> = None;
            let mut segments: Vec<(usize, usize)> = Vec::new(); // (abs start, abs end)
            for (i, (_, _, t)) in tokens.iter().enumerate() {
                if is_stop(t) || is_cue(t) {
                    if let Some(s) = seg_start_idx.take() {
                        if (2..=4).contains(&(i - s)) {
                            segments.push((tokens[s].0, tokens[i - 1].1));
                        }
                    }
                } else if seg_start_idx.is_none() {
                    seg_start_idx = Some(i);
                }
            }
            if let Some(s) = seg_start_idx {
                if (2..=4).contains(&(tokens.len() - s)) {
                    segments.push((tokens[s].0, tokens[tokens.len() - 1].1));
                }
            }
            for (s, e) in segments {
                if emitted >= CAPS_NAME_MAX {
                    break;
                }
                // Corroboration: an in-run cue token, or a cue in the ±window (the window
                // probe excludes the span itself, so a cue can never self-corroborate).
                let corroborated = run_has_cue
                    || context::keyword_in_window(text, s, e, CAPS_NAME_CUES, 0, 0)
                        != context::Proximity::None;
                if !corroborated {
                    continue;
                }
                raw.push((s, e, Recognizer::Context(label.clone()), None));
                emitted += 1;
            }
        }
    }

    /// LABEL-CUED PHONE pass (review H1+H2) — ALWAYS-ON (rides `builtins.phone`, NOT
    /// the opt-in ctx pack). RESTORES the old default's coverage on phone-LABELED
    /// shapes the column-gap guard structurally refuses when uncued:
    ///
    ///  - same-line MULTI-SPACE runs (`Tel: 6438  1290` — the old default caught this
    ///    and no config could after the guard; H1);
    ///  - a SINGLE line wrap (`Tel: 6438\n1290` — the old default caught this and the
    ///    `ctx:phone-wrapped` mitigation ships unchecked; H2).
    ///
    /// GOVERNING FRAME: default recall >= the old default on every real-phone shape;
    /// only genuine column-gap shapes stay refused. The LABEL is what separates the
    /// two: a `tel/phone/fax/mobile/hp/m:` label directly before the digits
    /// ([`phone_cue_before`], <=24 chars back, word-bounded) marks a phone FIELD; a
    /// statement column has no such label, so the flood shapes stay dead. Validation:
    /// 7–15 digits + the >=8-char floor ([`cued_phone_plausible`]).
    ///
    /// WRAP DISCIPLINE: the wrapped shape is tried ONLY when the same-line match alone
    /// is implausible (too few digits — a mid-number wrap), and only ANCHORED at the
    /// same start. So `Tel: 6438 1290\n03/06/2026   88.00` emits exactly the same-line
    /// phone and never bridges into the next table row, while `Tel: 6438\n1290` closes
    /// across its wrap. Emits plain [`Recognizer::Phone`] spans (merged/tiered/PDF-
    /// line-scoped exactly like the ordinary row — the PDF path drops cross-line
    /// phones as it always did, parity with the old default there too). Bomb-bounded
    /// at [`MAX_CUED_PHONES`]. No-op when the phone builtin is off.
    fn cued_phone_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        if !self.phone {
            return; // phone builtin off => the cued arm is off with it.
        }
        // Cheap prefilter: no cue substring anywhere => no label can gate anything in.
        let lower = text.to_lowercase();
        if !PHONE_CUE_LEXICON.iter().any(|c| lower.contains(c)) {
            return;
        }
        let mut emitted = 0usize;
        for m in cued_phone_sameline_regex().find_iter(text) {
            if emitted >= MAX_CUED_PHONES {
                break; // bomb-bound
            }
            if !phone_cue_before(text, m.start()) {
                continue; // no label => the column-gap refusal stands.
            }
            if cued_phone_plausible(m.as_str()) {
                raw.push((m.start(), m.end(), Recognizer::Phone, None));
                emitted += 1;
            } else if let Some(w) = cued_phone_wrapped_regex().find_at(text, m.start()) {
                // Same-line part alone is implausible (a mid-number wrap like
                // `Tel: 6438`): try the single-wrap continuation ANCHORED here.
                if w.start() == m.start() && cued_phone_plausible(w.as_str()) {
                    raw.push((w.start(), w.end(), Recognizer::Phone, None));
                    emitted += 1;
                }
            }
        }
    }

    /// LABEL-CUED BIC pass (the finance-corpus recall round). The digit-bearing /
    /// `XXX`-branch 11-char form stands alone as a normal [`TaggedPattern`] row
    /// ([`bic11_standalone_valid`]); every WORD-SHAPED form — the 8-char form
    /// ("DEUTSCHE" is structure-valid: the ISO country "SC" sits at chars 5–6 by
    /// coincidence) and the letter-only non-`XXX` 11-char form ("INSTRUCTION" → RU,
    /// "TRANSACTION" → SA) — fires ONLY with a BIC/SWIFT label in the ±window
    /// ([`BIC_LABEL_LEXICON`]) — the context-style gate, done HERE at emission (not in
    /// the finalization gate) so the always-on default path never runs a gate sweep. All
    /// forms share [`bic_structure_valid`]. Emits [`Recognizer::Bic`] — structure-only,
    /// so `confidence_for` keeps it Low/Medium (CAREFUL review, never quick-confirm) and
    /// it never seeds any propagation (not a name kind). No-op when `builtins.bic` is
    /// off. An overlap with the standalone row merges into one span (same recognizer).
    fn bic_labeled_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        if !self.bic {
            return; // BIC disabled ⇒ neither form contributes.
        }
        // Cheap prefilter: no BIC/SWIFT label anywhere ⇒ no 8-char form can be cued.
        let lower = text.to_lowercase();
        if !BIC_LABEL_LEXICON.iter().any(|kw| lower.contains(kw)) {
            return;
        }
        for m in bic_any_regex().find_iter(text) {
            if !bic_structure_valid(m.as_str()) {
                continue;
            }
            if context::keyword_in_window(text, m.start(), m.end(), BIC_LABEL_LEXICON, 0, 0)
                == context::Proximity::None
            {
                continue; // no BIC/SWIFT label near — an ordinary caps word, not a BIC.
            }
            raw.push((m.start(), m.end(), Recognizer::Bic, None));
        }
    }

    /// NAME-PROPAGATION ("name closure") — a deterministic second pass that closes the
    /// recall gap of the honorific-only [`Recognizer::Name`] heuristic WITHOUT flooding.
    ///
    /// The honorific-only recognizer catches `Mr Greco` but not the bare `Massimo Greco`
    /// (a board director listed with no title). This pass takes the names ALREADY detected
    /// in `raw` (a `Mr Greco` span) and propagates them:
    ///
    /// - **SAFE tier (ALWAYS on, very low FP):** strip the leading honorific from each
    ///   detected `Name` span to its NAME PART (e.g. `Mr Greco` → `Greco`), then redact
    ///   every ADDITIONAL exact, whole-word occurrence of that name-part string elsewhere
    ///   in the doc. This only ever re-flags a string the engine ALREADY decided was (part
    ///   of) a person name, so the false-positive cost is minimal — it is the conservative
    ///   default. (A single-token name part like `Greco` re-flags the bare word `Greco`; it
    ///   does NOT on its own pull in `Massimo Greco` — that is the expansion tier's job.)
    /// - **EXPANSION tier (OPT-IN via [`name_expansion`](RedactionEngine::name_expansion),
    ///   OFF by default):** redact any Capitalized multi-word run that CONTAINS a detected
    ///   name TOKEN (e.g. `Greco`, `Schwicht`) as a whole word — so `Greco` pulls in
    ///   `Massimo Greco` and `Schwicht` pulls in `Peter Thomas Schwicht`. STRICTLY bounded
    ///   to runs that contain an already-detected name token (NOT every capitalized run, so
    ///   it is not the blunt [`aggressive`](RedactionEngine::aggressive) bigram rule).
    ///
    /// Every propagated span is pushed as a plain `Recognizer::Name` raw span, so it flows
    /// through the SAME sort/merge/overlap machinery as a directly-matched name. The seed
    /// set is read ONLY from `Name` spans in `raw`, so a doc with no detected name produces
    /// ZERO propagated spans — the default path is byte-identical. Pure + deterministic: a
    /// `find_iter` over the doc + a sorted token scan; no clock, no RNG, no network.
    ///
    /// CONFIDENTIALITY: builds only IN-PROCESS cleartext (name parts/tokens) that never
    /// leaves the engine — the audit note still records counts + recognizer breakdown only.
    fn name_propagation_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        // SEED set: the NAME PARTS of every already-detected `Name` span (honorific stripped),
        // plus the individual capitalized TOKENS of those parts (for the expansion tier).
        // Built from a SNAPSHOT of the current `raw` so we never read spans we add below.
        let mut name_parts: HashSet<&str> = HashSet::new();
        let mut name_tokens: HashSet<&str> = HashSet::new();
        for (s, e, kind, _) in raw.iter() {
            if !matches!(kind, Recognizer::Name) {
                continue;
            }
            // Slice the matched name out of the ORIGINAL text (offsets are char boundaries),
            // then strip the leading honorific to the name part.
            let matched = &text[*s..*e];
            let part = strip_honorific(matched);
            if part.is_empty() {
                continue;
            }
            name_parts.insert(part);
            for tok in part.split_whitespace() {
                // Only NAME-LIKE tokens seed the expansion (a Capitalized word of ≥2 chars),
                // so a stray initial / particle does not pull in unrelated capitalized runs.
                if is_name_token(tok) {
                    name_tokens.insert(tok);
                }
            }
        }
        if name_parts.is_empty() {
            return; // No detected name ⇒ nothing to propagate (byte-identical default).
        }

        // SAFE tier (always on): every ADDITIONAL whole-word, exact occurrence of each
        // detected name-part string. `find_iter` over a literal `regex::escape`d pattern with
        // unicode word boundaries — so `Greco` matches `Greco` but not `Grecot`/`McGreco`.
        // (The pattern is built once per distinct part; parts are few — one per detected
        // name — so this is cheap. We sort the parts for a deterministic build/scan order.)
        let mut parts_sorted: Vec<&str> = name_parts.into_iter().collect();
        parts_sorted.sort_unstable();
        for part in parts_sorted {
            // `\b<escaped>\b` — a whole-word literal. The part may contain spaces (a
            // multi-word name); `\b` anchors the ends, escape handles `.`/`-` in e.g.
            // `Daniel J. Watkins`. Static-shaped + escaped input, but built from matched
            // text, so fall back to skipping this part if it somehow fails to compile
            // (never a panic, never a miss of OTHER parts).
            let pat = format!(r"\b{}\b", regex::escape(part));
            let re = match Regex::new(&pat) {
                Ok(re) => re,
                Err(_) => continue,
            };
            for m in re.find_iter(text) {
                raw.push((m.start(), m.end(), Recognizer::Name, None));
            }
        }

        // EXPANSION tier (opt-in): any Capitalized multi-word run that CONTAINS a detected
        // name token as a whole word. OFF by default (and a no-op with no name tokens).
        if !self.name_expansion || name_tokens.is_empty() {
            return;
        }
        // A run of >=2 Capitalized (uppercase-initial) words — the same shape as the
        // aggressive bigram, but here only KEPT when it contains a detected name token (so
        // it is bounded — not "every capitalized pair"). Inter-word gaps are `[ \t]+`
        // (spaces/tabs) plus AT MOST ONE line break in the WHOLE run (the wrapped-name
        // round: a wrapped `Massimo\nGreco` must still close; documents wrap mid-sentence).
        // Two arms in preference order: (1) >= 2 same-line tokens with an OPTIONAL single
        // wrap continuation, (2) a run wrapped at its first gap (>= 1 token each side). A
        // BLANK line is never crossed, and a run spans <= 1 newline TOTAL — bounded, so the
        // greedy run cannot sprawl down consecutive capitalized lines (`Luxembourg\n
        // CONNECTED DIRECTORS\nMassimo Greco\nVia Cordusio` yields per-wrap-bounded runs,
        // not one giant span); absorbing ONE line-leading Capitalized word after a wrap is
        // the documented over-flag (safe side). Unicode-aware on the word chars. Compiled
        // once from a fixed static, so `expect` documents the compile-always invariant.
        // Round 3 (Mechanism 1): each token is `\p{Lu}(?:\p{L}+|\.)?` — a Capitalized
        // word, a bare single letter, or a dotted single-letter INITIAL — so a closure run
        // over `John W. Thompson` is one span.
        let run_re = Regex::new(
            r"\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)+(?:[ \t]*\r?\n[ \t]*\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)*)?|\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)*[ \t]*\r?\n[ \t]*\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?(?:[ \t]+\p{Lu}(?:\p{L}+(?:-\p{Lu}\p{L}+)*|\.)?)*",
        )
        .expect("name-expansion run pattern must compile");
        for m in run_re.find_iter(text) {
            let run = m.as_str();
            // Keep the run ONLY if one of its whole-word tokens is a detected name token.
            let contains_seed = run.split_whitespace().any(|tok| name_tokens.contains(tok));
            if contains_seed {
                raw.push((m.start(), m.end(), Recognizer::Name, None));
            }
        }
    }

    /// ADDRESS-BLOCK CONTINUATION (Round-3 fix C) — a deterministic pass that closes the
    /// recall gap on a BUILDING / TOWER name line SANDWICHED between redacted address
    /// components (a street line above, a unit / postal line below). The address-family
    /// recognizers catch the number+street row and the postal code, but a bare proper-noun
    /// premises name (`UOB Plaza`, `Capital Tower`) on its own line matches no address
    /// pattern, so it SURVIVED between two removed neighbours — a leak.
    ///
    /// The pass reads the address-family candidates ALREADY in `raw` (spans tagged
    /// [`Recognizer::Address`] or a postal [`Recognizer::Locale`] row — `…:postal` /
    /// `…:postcode` / `…:zip`) plus OFFICE-LABEL lines (`Registered office:` /
    /// `Operating office` / `Registered address`, which open an address block) as ANCHORS.
    /// For every pair of CONSECUTIVE anchor lines within a small line window (≤3 lines apart)
    /// it captures each line STRICTLY BETWEEN them that is [`is_building_name_line`] as a new
    /// `Recognizer::Address` span over the line's trimmed content — so the sandwiched premises
    /// name is removed with its address. `Recognizer::Address` routes to the CAREFUL review
    /// tier (never quick-confirm).
    ///
    /// BOUNDED + deterministic (no clock/RNG): only lines strictly between two anchors ≤3
    /// lines apart, only proper-noun-shaped lines (every token uppercase/`#`/digit-initial,
    /// ≤6 tokens, ≤40 bytes) — so two DISTANT address candidates never capture arbitrary text
    /// between them, and an ordinary lowercase prose line is never swept. NO-OP unless the
    /// address family is active (`address_ws_patterns` non-empty ⇔ the address built-in is on
    /// OR a precise postal locale is enabled), so the default path is byte-identical.
    /// CONFIDENTIALITY: builds only IN-PROCESS cleartext (line slices) that never leaves the
    /// engine; the audit note still records counts + recognizer breakdown only.
    fn address_block_continuation_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        // Gate: address family inactive ⇒ nothing to continue (byte-identical default).
        if self.address_ws_patterns.is_empty() {
            return;
        }

        // Line table: (start, end) byte offsets, `end` EXCLUDING the terminating '\n'.
        let mut lines: Vec<(usize, usize)> = Vec::new();
        let mut ls = 0usize;
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                lines.push((ls, i));
                ls = i + 1;
            }
        }
        lines.push((ls, text.len()));
        if lines.len() < 3 {
            return; // need a line ABOVE and BELOW a candidate building line
        }

        // A line is an ANCHOR if an address-family candidate overlaps it OR it is an
        // office-label line. `is_addr` marks address-family candidate lines (used to require
        // the pair be a genuine street/unit/postal boundary, not two office labels).
        let office_re = office_label_regex();
        let mut anchor: Vec<bool> = vec![false; lines.len()];
        let mut is_addr: Vec<bool> = vec![false; lines.len()];
        for (idx, &(lstart, lend)) in lines.iter().enumerate() {
            if office_re.is_match(&text[lstart..lend]) {
                anchor[idx] = true;
            }
        }
        for (s, e, rec, _) in raw.iter() {
            let addr_family = matches!(rec, Recognizer::Address)
                || matches!(rec, Recognizer::Locale(l)
                    if matches!(l.rsplit(':').next(), Some("postal" | "postcode" | "zip")));
            if !addr_family {
                continue;
            }
            for (idx, &(lstart, lend)) in lines.iter().enumerate() {
                // Overlap between the candidate span and the line.
                if *s < lend && *e > lstart {
                    anchor[idx] = true;
                    is_addr[idx] = true;
                }
            }
        }

        // Walk anchor lines in order; for each consecutive anchor pair ≤3 lines apart where at
        // least one side is a genuine address candidate (an office label alone opening the
        // block also qualifies), capture the proper-noun-shaped lines strictly between them.
        let anchor_idxs: Vec<usize> = (0..lines.len()).filter(|&i| anchor[i]).collect();
        for pair in anchor_idxs.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if b - a > 3 || b - a < 2 {
                continue; // >3 lines apart (too distant) or adjacent (nothing between)
            }
            // Require the block be anchored by a real address candidate on at least one side
            // (a bare office label with no address candidate near does not sweep prose).
            if !(is_addr[a] || is_addr[b]) {
                continue;
            }
            for &(lstart, lend) in &lines[(a + 1)..b] {
                let line = &text[lstart..lend];
                if !is_building_name_line(line) {
                    continue;
                }
                // Emit the TRIMMED content only (never the surrounding whitespace).
                let lead = line.len() - line.trim_start().len();
                let trail = line.len() - line.trim_end().len();
                let cs = lstart + lead;
                let ce = lend - trail;
                if ce > cs {
                    raw.push((cs, ce, Recognizer::Address, None));
                }
            }
        }
    }

    /// INLINE building-name capture (round-4 fix), a sibling of the OWN-LINE block pass in
    /// [`address_block_continuation_spans`]. The block pass only catches a premises name on
    /// its OWN line strictly between two anchors ≥2 lines apart. But a building name embedded
    /// INLINE in a sentence — `…inspect the Register at 168 Robinson Road #33-01, Capital
    /// Tower, Singapore 068912…`, further split across a PDF line wrap (`Capital \nTower`) —
    /// sits BETWEEN two address candidates on the running text with no own-line of its own,
    /// so it was missed while the street / unit / postal around it were redacted (a
    /// recoverable premises leak). Here we scan consecutive address-family candidates and,
    /// when the SHORT gap between them is a building-name-shaped proper-noun phrase
    /// ([`inline_building_phrase`]), capture it. Tightly bounded: only between two
    /// address-family candidates, gap ≤ [`INLINE_ADDR_GAP_BYTES`], only Capitalized/numeric
    /// tokens — so it fires on a genuine premises name flanked by address tokens, never on
    /// prose. Runs INDEPENDENTLY of the line count (a 2-line inline wrap is the motivating
    /// case), unlike the block pass which needs ≥3 lines. No-op unless the address family is
    /// active, so the default path stays byte-identical.
    fn inline_building_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        if self.address_ws_patterns.is_empty() {
            return;
        }
        let mut addr_spans: Vec<(usize, usize)> = raw
            .iter()
            .filter(|(_, _, rec, _)| {
                matches!(rec, Recognizer::Address)
                    || matches!(rec, Recognizer::Locale(l)
                        if matches!(l.rsplit(':').next(), Some("postal" | "postcode" | "zip")))
            })
            .map(|(s, e, _, _)| (*s, *e))
            .collect();
        addr_spans.sort_unstable();
        addr_spans.dedup();
        let mut inline_hits: Vec<(usize, usize)> = Vec::new();
        for pair in addr_spans.windows(2) {
            let (a_end, b_start) = (pair[0].1, pair[1].0);
            // Non-overlapping, and a genuinely small gap (the length pre-filter also lives
            // in `inline_building_phrase`, but skip the slice+scan early when far apart).
            if b_start <= a_end || b_start - a_end > INLINE_ADDR_GAP_BYTES {
                continue;
            }
            if let Some((lo, hi)) = inline_building_phrase(&text[a_end..b_start]) {
                inline_hits.push((a_end + lo, a_end + hi));
            }
        }
        for (s, e) in inline_hits {
            raw.push((s, e, Recognizer::Address, None));
        }
    }

    /// MECHANISM B — the TRAILING-role name-list pass. When the role-name context recognizer
    /// is enabled, find each `A, B and C are employees of …`-shaped list (2+ comma/'and'-
    /// separated Capitalized multi-word names IMMEDIATELY preceding a trailing employment/
    /// role phrase from [`TRAILING_ROLE_PHRASES`]) and emit EACH name in the list as a
    /// [`Recognizer::Name`] raw span.
    ///
    /// WHY `Recognizer::Name` (a NORMAL, ungated recognizer) rather than a context-gated
    /// `ctx:*` row: the additive ctx gate uses a fixed ±window, which would SUPPRESS the
    /// EARLY names of a LONG inline list (they sit well beyond the window from the trailing
    /// phrase) — exactly the miss this closes (a miss is the leak). The pass's OWN precision
    /// (a real trailing phrase + a genuine 2+-name list) stands in for the gate, so every
    /// list name survives. `Name` routes to CAREFUL review (never quick-confirm — its
    /// confidence is Low/Medium, below the default High floor), matching the role-name
    /// posture; and being a `Name`, each captured list name ALSO seeds the SAFE re-occurrence
    /// tier of [`name_propagation_spans`](RedactionEngine::name_propagation_spans) and the
    /// Mechanism-A closure below (so the same person is caught wherever else they appear).
    ///
    /// LINEAR-TIME + line-run-bounded: the trailing phrase self-bounds each region (no
    /// unbounded backward scan); `find_iter` over fixed, no-backtracking regexes; total
    /// emissions capped at [`MAX_TRAILING_ROLE_NAMES`] (review fix 2 — the bomb-bound for a
    /// pathological many-thousand-name list). NO-OP unless role-name is enabled, so the
    /// default path is byte-identical. Deterministic (no clock/RNG). CONFIDENTIALITY:
    /// builds only in-process cleartext (name slices); the audit note still records counts
    /// + recognizer breakdown only.
    fn trailing_role_name_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        // Gate on the same opt-in as `ctx:role-name` — this is the forward, in-prose
        // companion to that row (so `{"context":true}` lights up both).
        if !self.context_recognizers.role_name {
            return;
        }
        let (full, name) = trailing_role_regexes();
        let mut emitted = 0usize;
        for caps in full.captures_iter(text) {
            // Group 1 = the name LIST (WITHOUT the trailing phrase). Split it into
            // individual name spans, each redacted as a person name.
            let Some(list) = caps.get(1) else { continue };
            let base = list.start();
            for nm in name.find_iter(list.as_str()) {
                if emitted >= MAX_TRAILING_ROLE_NAMES {
                    return; // bomb-bound: stop emitting on a pathological list
                }
                let (s, e) = (base + nm.start(), base + nm.end());
                if e > s {
                    raw.push((s, e, Recognizer::Name, None));
                    emitted += 1;
                }
            }
        }
    }

    /// FIELD-LABEL ANCHORED VALUE pass (round 4, Mechanism A) — the forms/transcript
    /// class. A LINE-LEADING field label (see [`FIELD_LABELS`]) followed by `:` (or a
    /// tab / 2+ spaces — forms columnize) anchors the VALUE after it:
    ///
    /// - a NAME-labeled field (`Name: Tan Wei Ming` — [`NAME_FIELD_LABELS`]) whose value
    ///   is PERSON-SHAPED emits under [`FIELD_NAME_LABEL`] (`ctx:field-name`:
    ///   person-family placeholders, careful review, NEVER a propagation seed — the
    ///   round-4 review fix; see [`NAME_FIELD_LABELS`]);
    /// - every other value (`Student ID: A0219477B`, and any non-person-shaped value
    ///   after a name label) emits under [`FIELD_VALUE_LABEL`] (`ctx:field-id`, careful
    ///   review) — the field evidence: the LABEL was flagged as role boilerplate while
    ///   the VALUE was missed entirely.
    ///
    /// ALWAYS-ON (no opt-in): a line-leading label + explicit separator is a
    /// self-identifying anchor (same posture as the detected-candidate anchors of the
    /// anchored-name pass); the forms-class recall must not depend on a context toggle.
    /// Value shape (round-4 review fix): a NON-EMPTY rest-of-line is the value, bounded
    /// to ITS OWN LINE — never joined across the newline (the earlier short-line join
    /// made a filled field's box swallow the next sentence). An EMPTY rest-of-line is
    /// the true COLUMNAR form: the value is the NEXT line, when that line is a
    /// plausible value (non-blank, <= 40 bytes, colon-free, not a label line) — so
    /// `Label:\nvalue` still captures, and a bare label followed by nothing plausible
    /// emits nothing. Rest-of-line longer than [`MAX_FIELD_VALUE_BYTES`] emits nothing
    /// (prose, not a form value); a same-line value with trailing prose over-covers to
    /// end-of-line (safe, intended — see the inline note). At most ONE trailing
    /// `.`/`,`/`;` is trimmed when DIGIT-preceded (the sentence-final date; a `Jr.` /
    /// `Ltd.` abbreviation is never touched). Total emissions capped at
    /// [`MAX_FIELD_VALUES`]. Deterministic, single line-table walk, no clock/RNG.
    /// Confidentiality: in-process cleartext only.
    fn field_label_value_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        // Line table (end excludes the terminating newline).
        let mut lines: Vec<(usize, usize)> = Vec::new();
        let mut ls = 0usize;
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                lines.push((ls, i));
                ls = i + 1;
            }
        }
        lines.push((ls, text.len()));

        let field_ctx: Arc<str> = Arc::from(FIELD_VALUE_LABEL);
        let field_name_ctx: Arc<str> = Arc::from(FIELD_NAME_LABEL);
        let mut emitted = 0usize;
        for (idx, &(s, e)) in lines.iter().enumerate() {
            if emitted >= MAX_FIELD_VALUES {
                return; // total-emissions bomb-bound
            }
            let line = &text[s..e];
            let led = strip_list_lead(line);
            let Some((label, voff)) = field_label_at(led) else {
                continue;
            };
            let value = &led[voff..];
            let vtrim = value.trim();
            if vtrim.len() > MAX_FIELD_VALUE_BYTES {
                continue; // prose-length rest-of-line: not a form value
            }
            // SPAN-SHAPE FIX (round-4 review): the value is EITHER the label's own
            // rest-of-line OR — only when that is EMPTY — the NEXT line (the true
            // columnar form: label on one line, value on the next). A NON-EMPTY value
            // NEVER joins the next line: the earlier unconditional short-line join made
            // a filled field's box swallow the following sentence
            // (`Date of Birth: 14.03.1998\nMore text.` captured across the newline —
            // the exact "erratic boxes" field complaint). Absolute offsets via pointer
            // arithmetic (led/value borrow from text).
            let (vstart, mut vend) = if vtrim.is_empty() {
                // COLUMNAR form: the value is the whole next line, when it is a
                // plausible VALUE line — non-blank, short (<= 40 bytes), colon-free
                // (any label-shaped line, listed or not, never becomes a value), and
                // not itself a listed label line. NO lowercase requirement here: a bare
                // ID value line (`A0219477B`) is legitimately caseless/upper.
                let Some(&(ns, ne)) = lines.get(idx + 1) else {
                    continue;
                };
                let next = &text[ns..ne];
                let ntrim = next.trim();
                if ntrim.is_empty()
                    || ntrim.len() > 40
                    || ntrim.contains(':')
                    || field_label_at(strip_list_lead(next)).is_some()
                    // An ALL-LOWERCASE next line is a mid-sentence artifact (a
                    // word-per-line extraction puts `address:` on its own line and the
                    // next word is prose — measured: the value `the` on the flagship
                    // corpus), never a form value: real values carry an uppercase
                    // letter or a digit (names, ids, addresses).
                    || !ntrim.chars().any(|c| c.is_uppercase() || c.is_ascii_digit())
                {
                    continue; // a bare label with no plausible value line emits nothing
                }
                let nstart = ntrim.as_ptr() as usize - text.as_ptr() as usize;
                (nstart, nstart + ntrim.len())
            } else {
                // SAME-LINE form: the rest of the label's line, verbatim. HONEST
                // over-cover note: a labeled line with trailing prose captures to
                // end-of-line (`Name: Tan Wei Ming as stated` covers the whole rest) —
                // over-covering a genuine form line is the safe, intended behavior; the
                // fix above only stops CROSS-LINE absorption.
                let vs = vtrim.as_ptr() as usize - text.as_ptr() as usize;
                (vs, vs + vtrim.len())
            };
            // TRAILING-PUNCTUATION trim (round-4 review, the CONSERVATIVE rule): drop at
            // most ONE trailing `.`/`,`/`;` and ONLY when the char before it is an ASCII
            // DIGIT — covers the sentence-final date (`… 14th March 1998.`) with ZERO
            // risk to a name/org abbreviation (`Jr.` / `Ltd.` end in letters, never
            // trimmed).
            if vend - vstart >= 2
                && matches!(text.as_bytes()[vend - 1], b'.' | b',' | b';')
                && text.as_bytes()[vend - 2].is_ascii_digit()
            {
                vend -= 1;
            }
            // REVIEW FIX (round-4 review, HIGH): field emissions NEVER ride the Name
            // kind (which seeds the always-on propagation safe tier — the +393
            // `JPMorgan` amplification). A person-shaped value under a name label gets
            // the non-seeding person-family `ctx:field-name`; everything else the typed
            // `ctx:field-id`. The value still flags AT ITS OWN SITE either way — the
            // transcript fix is intact; only the document-wide propagation is gone.
            let kind = if NAME_FIELD_LABELS.contains(&label)
                && is_person_shaped_field_value(&text[vstart..vend])
            {
                Recognizer::Context(field_name_ctx.clone())
            } else {
                Recognizer::Context(field_ctx.clone())
            };
            raw.push((vstart, vend, kind, None));
            emitted += 1;
        }
    }

    /// HEADER-ANCHORED VERTICAL NAME LIST pass (round 3, Mechanism 4) — the biggest
    /// real-world gap: a prospectus prints its conducting officers/directors as a bare
    /// COLUMN of names under a role header (`CONDUCTING OFFICERS\nAda Quorley\nBen
    /// Vantol\n…`) — no honorific, no inline role, no bio — and NOTHING else in the
    /// engine can anchor them (verified: 12 real officers, zero candidates on both scan
    /// routes). The HEADER is the anchor:
    ///
    /// - a line that IS a [`ROLE_LIST_HEADERS`] row (case-insensitive, leading
    ///   numbering/bullets + trailing `:` tolerated) starts a capture;
    /// - each following line that is NOTHING BUT a capitalized name run (2–4 tokens,
    ///   honorific + dotted interior initials allowed, an optional `, Role` suffix —
    ///   see [`role_list_name_line_regex`]) emits its NAME as a [`Recognizer::Name`] raw
    ///   span (the ENTITY family: careful review, seeds the propagation pass);
    /// - ONE blank line does NOT end the list (officer columns are often 1.5-spaced) but
    ///   TWO consecutive blanks do;
    /// - an ALL-CAPS line (no lowercase letter anywhere — an ORG like
    ///   `BLACKROCK (LUXEMBOURG) S.A.` or a sub-header) is SKIPPED, never absorbed into
    ///   a name and never emitted (the Title-Case requirement of the name shape — the
    ///   final token needs `\p{L}+` after `\p{Lu}` and the line must carry a lowercase
    ///   letter — naturally excludes it); MIXED forms (`John SMITH`) pass the line regex
    ///   only when a Title-Case token is present and are emitted (recall-first — stated
    ///   honestly: an all-caps SURNAME next to a Title-Case given name is flagged);
    /// - any OTHER line (prose, a new header, punctuation) ENDS the list — so a header
    ///   followed by prose sentences emits NOTHING.
    ///
    /// BOUNDED: at most [`MAX_HEADER_LIST_LINES`] lines scanned per header,
    /// [`MAX_HEADER_LIST_NAMES`] total emissions per document (the existing caps
    /// pattern). Gated on the role-name context opt-in (`{"context":true}`), like the
    /// trailing-role pass — this is role-anchored name capture, deliberately FP-tolerant
    /// (careful-review lane). Deterministic, single line-table walk, no clock/RNG.
    fn role_header_list_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        if !self.context_recognizers.role_name {
            return;
        }
        // Line table: (start, end) byte offsets, `end` excluding the terminating `\n`.
        let mut lines: Vec<(usize, usize)> = Vec::new();
        let mut ls = 0usize;
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                lines.push((ls, i));
                ls = i + 1;
            }
        }
        lines.push((ls, text.len()));

        let name_line_re = role_list_name_line_regex();
        let mut emitted = 0usize;
        let mut i = 0usize;
        while i < lines.len() {
            let (hs, he) = lines[i];
            if !is_role_list_header(&text[hs..he]) {
                i += 1;
                continue;
            }
            // Capture the column below the header.
            let mut consecutive_blanks = 0usize;
            let mut j = i + 1;
            let scan_end = (i + 1 + MAX_HEADER_LIST_LINES).min(lines.len());
            while j < scan_end {
                let (s, e) = lines[j];
                let line = &text[s..e];
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    consecutive_blanks += 1;
                    if consecutive_blanks >= 2 {
                        break; // two consecutive blanks end the list
                    }
                    j += 1;
                    continue;
                }
                consecutive_blanks = 0;
                // An ALL-CAPS line (no lowercase letter anywhere) is an ORG/sub-header:
                // SKIPPED (the list continues past it), never emitted, never absorbed.
                if !line.chars().any(char::is_lowercase) {
                    j += 1;
                    continue;
                }
                let stripped = strip_list_lead(line);
                match name_line_re.captures(stripped) {
                    Some(caps) => {
                        if let Some(name) = caps.get(1) {
                            // ROLE-line guard: a bare role title (`Managing Director`) is
                            // shape-identical to a 2-token name in the interleaved
                            // name/role-line layout — SKIP it (the list continues), never
                            // emit boilerplate into the ENTITY family.
                            if run_contains_role_title(name.as_str()) {
                                j += 1;
                                continue;
                            }
                            if emitted >= MAX_HEADER_LIST_NAMES {
                                return; // total-emissions bomb-bound
                            }
                            // Offsets of the name run back in the ORIGINAL text: the
                            // stripped slice borrows from `line`, which borrows from
                            // `text`, so pointer arithmetic recovers the absolute base.
                            let base = s + (stripped.as_ptr() as usize - line.as_ptr() as usize);
                            let (ns, ne) = (base + name.start(), base + name.end());
                            if ne > ns {
                                raw.push((ns, ne, Recognizer::Name, None));
                                emitted += 1;
                            }
                        }
                        j += 1;
                    }
                    // Any other non-blank, non-all-caps line (prose, a new header)
                    // ENDS the list.
                    None => break,
                }
            }
            i = j.max(i + 1);
        }
    }

    /// LUXEMBOURG RCS COMPANY-REGISTER pass (round 3, Mechanism 3) — a raw-phase pass
    /// emitting the `R.C.S. Luxembourg B.6317` register number (and the bare `B 123456`
    /// form when `R.C.S` sits in the short preceding window) as a
    /// [`Recognizer::Locale`]`("lu:rcs")` span. GLOBAL + UNCONDITIONAL: the literal
    /// `R.C.S.` anchor is self-identifying (near-zero FP; see [`RCS_LU_LABEL`]), so it is
    /// not gated behind a locale pack — the UK register number `SC007058` was already
    /// caught while the Luxembourg one never fired (jurisdiction coverage, not format).
    /// Wrap-tolerant (<= 1 line break per gap in the ANCHORED form; the bare form is
    /// same-line only), rides a narrow <= 1-newline PDF line-scope sanction keyed to this
    /// exact label. Deterministic, linear-time, bounded (fixed regexes + a constant
    /// [`RCS_BARE_WINDOW_BYTES`] backward window).
    fn rcs_registry_spans(
        &self,
        text: &str,
        raw: &mut Vec<(usize, usize, Recognizer, Option<String>)>,
    ) {
        // Cheap prefilter: no literal anchor, no work (the common non-Luxembourg doc).
        if !text.contains("R.C") {
            return;
        }
        let (full, bare) = rcs_regexes();
        let label: Arc<str> = Arc::from(RCS_LU_LABEL);
        let mut anchored: Vec<(usize, usize)> = Vec::new();
        for m in full.find_iter(text) {
            anchored.push((m.start(), m.end()));
            raw.push((m.start(), m.end(), Recognizer::Locale(label.clone()), None));
        }
        // Bare `B 123456` form: only with the `R.C.S` anchor in the short PRECEDING
        // window, and skipped when an anchored match already covers it (pure duplicate).
        for m in bare.find_iter(text) {
            if anchored
                .iter()
                .any(|&(s, e)| s <= m.start() && m.end() <= e)
            {
                continue;
            }
            let lo = m.start().saturating_sub(RCS_BARE_WINDOW_BYTES);
            // Byte-space window scan for the ASCII literal (no char-boundary hazard: we
            // only search bytes, never slice text at `lo` for reuse).
            let window = &text.as_bytes()[lo..m.start()];
            if window.windows(5).any(|w| w == b"R.C.S") {
                raw.push((m.start(), m.end(), Recognizer::Locale(label.clone()), None));
            }
        }
    }

    /// ANCHORED-NAME pass (the wrapped-name round, Mechanisms B + C) — a FINALIZATION
    /// post-pass that emits the PERSON NAME immediately preceding a DETECTED
    /// high-precision anchor:
    ///
    /// - **B — display name beside an email:** `Delia Corrigan <delia@meridian.example>` —
    ///   a Capitalized multi-word run flush before `<` + a detected [`Recognizer::Email`]
    ///   candidate. The email was flagged; the display NAME survived (the observed leak).
    /// - **C — name before a parenthesized structured id:**
    ///   `Delia Quorley (NRIC S7034236G)` — a Capitalized multi-word run flush before `(`
    ///   + a short id LABEL + a detected [`Recognizer::Locale`] national-ID candidate
    ///     (NRIC / SSN / UEN / passport class; the locale POSTAL rows are EXCLUDED — a
    ///     postal code is not a personal identifier anchor). Anchoring on the DETECTED
    ///     candidate (never a keyword guess) is what corroborates precision.
    ///
    /// Each captured run is emitted as a [`Recognizer::Name`] candidate (the ENTITY
    /// family) so it (i) routes/labels like any detected person name and (ii) SEEDS the
    /// detected-name PROPAGATION pass below — the same person's bare prose re-mentions in
    /// the same text are then covered too. The run regex is the shared wrapped-name shape
    /// (2–4 Capitalized tokens, each gap tolerating <= 1 line break), so a wrapped display
    /// name (`Delia\nCorrigan <…>`) is caught; the PDF path's name-wrap sanction admits
    /// the resulting <= 1-newline span.
    ///
    /// BOUNDED + deterministic: per-anchor work is a constant lookback window
    /// ([`ANCHOR_NAME_LOOKBACK_CHARS`] chars / [`ANCHOR_ID_LABEL_BYTES`] label bytes);
    /// total emissions capped at [`MAX_ANCHORED_NAMES`] (bomb-bound). DEDUP: a run that
    /// overlaps an already-reported candidate (or a prior anchored emission) is skipped —
    /// no double-report, and the final span set stays non-overlapping (the
    /// `redact_detail` splice invariant). Confidence is `Medium` (anchored corroboration;
    /// never High → never quick-confirm under the default floor). NO-OP when no anchor
    /// candidate exists, so a document without emails/locale-ids is byte-identical.
    /// CONFIDENTIALITY: builds only in-process cleartext; the audit note still records
    /// counts + recognizer breakdown only.
    fn anchored_name_candidates(&self, text: &str, spans: &mut Vec<MergedSpan>) {
        // 1. Collect anchor OPEN positions (`<` / `(`) from the finalized candidates.
        //    (usize = the anchor byte; bool = email-style, which admits a closing quote
        //    between the name and the `<`.)
        let mut anchors: Vec<(usize, bool)> = Vec::new();
        for m in spans.iter() {
            let c = &m.candidate;
            let is_email = c.recognizers.iter().any(|r| matches!(r, Recognizer::Email));
            let is_locale_id = c.recognizers.iter().any(|r| {
                matches!(r, Recognizer::Locale(l)
                    if !matches!(l.rsplit(':').next(), Some("postal" | "postcode" | "zip")))
            });
            if is_email {
                if let Some(open) = angle_open_before(text, c.start) {
                    anchors.push((open, true));
                }
            }
            if is_locale_id {
                if let Some(open) = paren_open_before(text, c.start) {
                    anchors.push((open, false));
                }
            }
        }
        if anchors.is_empty() {
            return; // no anchor candidate ⇒ byte-identical default path
        }

        // 2. Existing candidate spans (sorted, non-overlapping) — the dedup baseline.
        let mut existing: Vec<(usize, usize)> = spans
            .iter()
            .map(|m| (m.candidate.start, m.candidate.end))
            .collect();
        existing.sort_unstable();

        // 3. For each anchor, find the Capitalized name run ending FLUSH at it (modulo
        //    spaces, and a closing `"`/`'` for the quoted email display-name form). The
        //    shared wrapped-name run regex (2–4 tokens, <= 1 line break per gap) scans a
        //    constant lookback window; the LAST qualifying match is the nearest run.
        let name_re = &trailing_role_regexes().1;
        let mut new_spans: Vec<(usize, usize)> = Vec::new();
        for (open, email_style) in anchors {
            if new_spans.len() >= MAX_ANCHORED_NAMES {
                break; // bomb-bound: stop emitting on a pathological anchor flood
            }
            let wlo = floor_char_boundary_back(text, open, ANCHOR_NAME_LOOKBACK_CHARS);
            let window = &text[wlo..open];
            let mut best: Option<(usize, usize)> = None;
            for nm in name_re.find_iter(window) {
                // The residue between the run's end and the anchor must be junk only:
                // spaces/tabs (+ a closing quote in the email form).
                let residue = &window[nm.end()..];
                let ok = residue.chars().all(|ch| {
                    ch == ' ' || ch == '\t' || (email_style && (ch == '"' || ch == '\''))
                });
                if ok {
                    best = Some((wlo + nm.start(), wlo + nm.end()));
                }
            }
            let Some((s, e)) = best else { continue };
            if span_overlaps_sorted(&existing, s, e) {
                continue; // already covered by a reported candidate — no double-report
            }
            if new_spans.iter().any(|(ns, ne)| s < *ne && e > *ns) {
                continue; // overlaps a prior anchored emission — keep the first
            }
            new_spans.push((s, e));
        }
        if new_spans.is_empty() {
            return;
        }

        // 4. Emit each run as a Name candidate, then re-sort by start so the downstream
        //    passes + the redact_detail splice see a sorted, non-overlapping set.
        for (s, e) in new_spans {
            spans.push(MergedSpan {
                candidate: RedactionCandidate {
                    start: s,
                    end: e,
                    matched_value: text[s..e].to_string(),
                    recognizer: Recognizer::Name,
                    recognizers: vec![Recognizer::Name],
                    context: context_snippet(text, s, e),
                    confidence: Confidence::Medium,
                },
                replacement: None,
            });
        }
        spans.sort_by(|a, b| {
            a.candidate
                .start
                .cmp(&b.candidate.start)
                .then(b.candidate.end.cmp(&a.candidate.end))
        });
    }

    /// MECHANISM A — detected-name PROPAGATION ("detected once, readable elsewhere"). A
    /// FINALIZATION post-pass on the merged candidates: for every finalized PERSON-NAME
    /// candidate (primary recognizer is a [`is_person_name_kind`] — the `Name` heuristic
    /// ONLY, per review fix 1; `ctx:role-name` no longer seeds — see the predicate's
    /// deliberate-trade note), take its honorific-STRIPPED name part (so a detected
    /// `Ms. Joanne Fitzgerald` propagates the bare `Joanne Fitzgerald` — the honorific
    /// never re-occurs at a bare mention) and, when that part is >= 2 words AND >= 8 chars,
    /// re-flag every OTHER occurrence of it elsewhere in the document. So a name detected
    /// at its heading/bio/list site no longer survives readable in a mid-prose list
    /// (`… Joanne Fitzgerald … are employees of …`) — the verified motivating leak.
    ///
    /// THE FLOOR (review fix 3 — what it actually does): the >= 2-word / >= 8-char floor
    /// drops SINGLE-TOKEN and very-short name parts (a stripped `Mr Greco` → `Greco`, a
    /// `Li Na`), whose document-wide re-occurrence flood is the SAFE tier's whole-word job,
    /// not elastic propagation's. It is NOT a boilerplate filter — a role-phrase FP like
    /// `The Board` or `Management Company` passes the floor; boilerplate exclusion comes
    /// from the Name-only SEED PREDICATE ([`is_person_name_kind`]), which keeps the
    /// boilerplate-prone `ctx:role-name` class out of the seed set entirely.
    ///
    /// Matching is case-SENSITIVE (a name is a capitalized proper noun — a lowercased
    /// coincidence is not pulled in) but whitespace-ELASTIC (reusing [`ws_regex_source`], so
    /// an occurrence a PDF layout split across a line break / space run still matches — the
    /// same reason the user-TERM elastic pass exists). Each new, NON-overlapping occurrence
    /// is emitted as [`Recognizer::Custom`]`("name:propagated")` at the SOURCE value's review
    /// tier (a name kind is never checksum/structural, so this is Low/Medium → CAREFUL
    /// review, never quick-confirm).
    ///
    /// RUNS ON THE FINAL CANDIDATES so it seeds only from names that actually SURVIVED the
    /// context gate, and both the scan ([`candidates`](RedactionEngine::candidates)) and
    /// apply ([`redact_detail`](RedactionEngine::redact_detail)) paths inherit it identically
    /// (scan/apply parity). ONE round: the emitted `Custom("name:propagated")` spans are not
    /// a name kind, so they never re-seed (no cascade).
    ///
    /// DEDUP: an occurrence that OVERLAPS an already-reported candidate span is dropped (no
    /// double-report), per the mechanism contract — so the surname a narrower sibling already
    /// covers is not re-flagged (it is already redacted). BOMB-BOUNDED: distinct seed values
    /// capped at [`MAX_PROPAGATED_VALUES`] and total emitted candidates at
    /// [`MAX_PROPAGATED_CANDIDATES`], so adversarial input (thousands of distinct names, or
    /// one name repeated a vast number of times) stays linear + memory-bounded. NO-OP when
    /// no qualifying name candidate exists, so the default path is byte-identical.
    /// CONFIDENTIALITY: builds only in-process cleartext; the audit note still records counts
    /// + recognizer breakdown only.
    fn propagate_name_candidates(&self, text: &str, spans: &mut Vec<MergedSpan>) {
        // 1. Seed VALUES from finalized person-NAME candidates (Recognizer::Name primaries
        //    ONLY — review fix 1), honorific-STRIPPED to the bare name part (a bare mention
        //    never carries the `Ms./Dr` prefix, so seeding the raw matched value would
        //    self-match only), then floored at >= 2 words AND >= 8 chars (see the method
        //    docs for what the floor does — and does NOT do). Distinct by stripped value;
        //    keep the strongest source confidence (deterministic `max`) so the propagated
        //    tier mirrors the source. Capped at MAX_PROPAGATED_VALUES distinct NEW values
        //    (bomb-bound).
        let mut seed_order: Vec<String> = Vec::new();
        let mut seed_conf: HashMap<String, Confidence> = HashMap::new();
        for m in spans.iter() {
            let c = &m.candidate;
            if !is_person_name_kind(&c.recognizer) {
                continue;
            }
            let val = strip_honorific(c.matched_value.as_str());
            if val.split_whitespace().count() < 2 || val.chars().count() < 8 {
                continue;
            }
            match seed_conf.get_mut(val) {
                Some(existing) => *existing = (*existing).max(c.confidence),
                None => {
                    if seed_order.len() >= MAX_PROPAGATED_VALUES {
                        continue; // distinct-value cap reached: ignore further NEW values
                    }
                    seed_order.push(val.to_string());
                    seed_conf.insert(val.to_string(), c.confidence);
                }
            }
        }
        if seed_order.is_empty() {
            return; // No qualifying name candidate ⇒ byte-identical default path.
        }

        // 2. Existing candidate spans (sorted; the merge guarantees them non-overlapping) —
        //    the dedup baseline for "don't double-report an already-covered span".
        let mut existing: Vec<(usize, usize)> = spans
            .iter()
            .map(|m| (m.candidate.start, m.candidate.end))
            .collect();
        existing.sort_unstable();

        // 3. For each distinct seed value find every NEW, non-overlapping occurrence,
        //    case-SENSITIVE but whitespace-ELASTIC. Deterministic order (seed order, then
        //    match start). Bounded by MAX_PROPAGATED_CANDIDATES total.
        let mut new_spans: Vec<(usize, usize, Confidence)> = Vec::new();
        'seeds: for val in &seed_order {
            let conf = seed_conf.get(val).copied().unwrap_or(Confidence::Low);
            // TWO matching tiers per seed, sharing one dedup/cap budget:
            //  - EXACT-CASE elastic (the original tier): a name is a capitalized proper
            //    noun — a lowercased coincidence is never pulled in.
            //  - ALL-CAPS ECHO (the finance-corpus round): documents re-print a detected
            //    mixed-case name in ALL CAPS (a bank-statement narrative, an agreement
            //    party clause: `Darius Okonkwo-Lim` → `DARIUS OKONKWO-LIM`). The echo
            //    scans case-INSENSITIVELY but keeps ONLY a match with NO lowercase letter
            //    — an all-caps occurrence of an already-detected person name is
            //    essentially never a coincidence, while `darius okonkwo-lim` (lowercase)
            //    stays un-flagged, preserving the case-sensitivity rationale. Emitted
            //    under the SAME non-seeding `name:propagated` label (one round, no
            //    cascade — the amplification-class guarantee is unchanged).
            // Built from matched text, so a compile failure skips THAT tier of THIS value
            // only (never a panic, never a miss of OTHER values) — the SAFE-tier fallback.
            let tiers: [(String, bool); 2] = [
                (ws_regex_source(val, false), false), // exact-case
                (ws_regex_source(val, true), true),   // caps-echo (case-insensitive scan)
            ];
            for (src, caps_only) in &tiers {
                let re = match Regex::new(src) {
                    Ok(re) => re,
                    Err(_) => continue,
                };
                for mt in re.find_iter(text) {
                    let (s, e) = (mt.start(), mt.end());
                    if e <= s {
                        continue;
                    }
                    // ECHO tier: keep ONLY the all-caps form (any lowercase letter in the
                    // matched text = a case coincidence, not an echo — dropped).
                    if *caps_only && mt.as_str().chars().any(char::is_lowercase) {
                        continue;
                    }
                    if span_overlaps_sorted(&existing, s, e) {
                        continue; // already covered by a reported candidate — no double-report
                    }
                    if new_spans.iter().any(|(ns, ne, _)| s < *ne && e > *ns) {
                        continue; // overlaps an accepted propagated span — keep the first
                    }
                    new_spans.push((s, e, conf));
                    if new_spans.len() >= MAX_PROPAGATED_CANDIDATES {
                        break 'seeds; // total-candidate cap (bomb-bound)
                    }
                }
            }
        }
        if new_spans.is_empty() {
            return;
        }

        // 4. Emit each occurrence as a PROPAGATED candidate, then re-sort the final set by
        //    start so redact_detail's forward splice stays valid (non-overlapping by
        //    construction — every emitted span was checked against existing AND prior new
        //    spans).
        let label: Arc<str> = Arc::from(PROPAGATED_NAME_LABEL);
        for (s, e, conf) in new_spans {
            let rec = Recognizer::Custom(label.clone());
            spans.push(MergedSpan {
                candidate: RedactionCandidate {
                    start: s,
                    end: e,
                    matched_value: text[s..e].to_string(),
                    recognizer: rec.clone(),
                    recognizers: vec![rec],
                    context: context_snippet(text, s, e),
                    confidence: conf,
                },
                replacement: None,
            });
        }
        spans.sort_by(|a, b| {
            a.candidate
                .start
                .cmp(&b.candidate.start)
                .then(b.candidate.end.cmp(&a.candidate.end))
        });
    }

    /// The single authoritative match+merge pass. Returns each merged span as a
    /// [`MergedSpan`] (the candidate + its resolved replacement). Shared by
    /// [`candidates`](RedactionEngine::candidates) (drops the replacement) and
    /// [`redact_detail`](RedactionEngine::redact_detail) (writes it), so both come
    /// from the SAME span set.
    fn merged_spans(&self, text: &str) -> Vec<MergedSpan> {
        // (start, end, recognizer, replacement) raw matches over the ORIGINAL text.
        let mut raw: Vec<(usize, usize, Recognizer, Option<String>)> = Vec::new();

        // PERF PREFILTER (pure optimization — RESULT-IDENTICAL). One `RegexSet`
        // pass reports which `patterns` match the document SOMEWHERE; we then run
        // the per-pattern `find_iter` ONLY for those indices. A pattern the set
        // reports as a non-match has provably ZERO matches in `text`, so its
        // `find_iter` would have yielded nothing — skipping it collects the SAME
        // raw spans. `pattern_set` is index-aligned with `patterns` (built from the
        // identical ordered source list), so `idx` selects the correct pattern.
        for idx in self.pattern_set.matches(text) {
            let tp = &self.patterns[idx];
            for m in tp.re.find_iter(text) {
                // Checksum-validated recognizers (card/IBAN) keep a match only if
                // the validator passes; format-only recognizers (`validate: None`)
                // accept every match. A failed validation drops the match entirely
                // — it never enters the candidate set.
                if let Some(validate) = tp.validate {
                    if !validate(m.as_str()) {
                        continue;
                    }
                }
                raw.push((m.start(), m.end(), tp.kind.clone(), None));
            }
        }
        if let Some(re) = &self.aggressive_name {
            for m in re.find_iter(text) {
                raw.push((m.start(), m.end(), Recognizer::Name, None));
            }
        }
        // PERF PREFILTER (pure optimization — RESULT-IDENTICAL), same guarantee +
        // index alignment as `pattern_set`: only `find_iter` the terms that the
        // `term_set` reports as matching SOMEWHERE; a non-matching term has zero
        // matches, so skipping it changes nothing. If the prefilter set could not be
        // built (`None` — combined size overflow at abusive config scale), fall back to
        // the EXHAUSTIVE direct scan: identical results, just no pruning. The fallback
        // never skips a term, so recall is preserved regardless of the prefilter.
        match &self.term_set {
            Some(set) => {
                for idx in set.matches(text) {
                    for m in self.term_patterns[idx].find_iter(text) {
                        raw.push((m.start(), m.end(), Recognizer::Term, None));
                    }
                }
            }
            None => {
                for re in &self.term_patterns {
                    for m in re.find_iter(text) {
                        raw.push((m.start(), m.end(), Recognizer::Term, None));
                    }
                }
            }
        }
        // Firm-defined recognizers ("super find & replace"). FIX #5: each
        // `Compiled` is ONE deduped regex shared by every firm rule that compiles
        // to the same pattern. We scan that regex ONCE, then attribute each match
        // to ALL its tags — so two same-pattern rules with different labels surface
        // BOTH labels off a SINGLE scan (no duplicate scanning, no dropped label).
        // The `Custom(Arc<str>)` kind clones a refcount, not the label text (#14).
        //
        // NOT `RegexSet`-prefiltered (deliberately left as-is): user recognizers are
        // already deduped to a typically SMALL set, AND each is built with a PER-rule
        // case-insensitivity flag via `RegexBuilder` (not an inline `(?i)` in the
        // source). A correct prefilter set would have to re-encode each rule's flag
        // into its source string to stay byte-equivalent — added fragility on the
        // detection-core hot path for a handful of patterns. The win here is small
        // and the misalignment risk is real, so this loop keeps its direct scan.
        for ur in &self.user_recognizers {
            for m in ur.re.find_iter(text) {
                for tag in &ur.tags {
                    raw.push((
                        m.start(),
                        m.end(),
                        tag.kind.clone(),
                        tag.replacement.clone(),
                    ));
                }
            }
        }

        // FIELD-LABEL ANCHORED VALUES (round 4, Mechanism A) — always-on: a line-leading
        // `Label:` / columnar label anchors its value (`Student ID: A0219477B`), the
        // forms/transcript class. Name-labeled values emit as Name (seed propagation).
        self.field_label_value_spans(text, &mut raw);

        // LUXEMBOURG RCS register numbers (round 3, Mechanism 3) — global, unconditional
        // (the literal `R.C.S.` anchor is self-identifying); a cheap `contains` prefilter
        // makes the common non-Luxembourg document a no-op.
        self.rcs_registry_spans(text, &mut raw);

        // LABEL-CUED 8-CHAR BICs (the 11-char form is a normal pattern row above). Gated
        // at emission on a BIC/SWIFT label in-window; a cheap label prefilter makes the
        // common no-label document a no-op. No-op when `builtins.bic` is off.
        self.bic_labeled_spans(text, &mut raw);

        // LABEL-CUED PHONES (review H1+H2) — always-on: a tel/phone/fax/mobile label
        // directly before the digits sanctions the multi-space / single-wrap joiners
        // the column-gap guard refuses uncued. No-op without a cue substring.
        self.cued_phone_spans(text, &mut raw);

        // HEADER-ANCHORED VERTICAL NAME LISTS (round 3, Mechanism 4) — a role header line
        // anchors the bare name COLUMN below it (the conducting-officers layout nothing
        // else can anchor). Gated on the role-name context opt-in, like the trailing-role
        // pass; emits Name spans that seed propagation.
        self.role_header_list_spans(text, &mut raw);

        // MECHANISM B (trailing-role name list) — when role-name context is enabled, capture
        // the names in an `A, B and C are employees of …` list as `Recognizer::Name` spans.
        // Placed BEFORE the name-closure pass so its names ALSO seed the SAFE re-occurrence
        // tier. No-op unless role-name is on, so the default path is byte-identical.
        self.trailing_role_name_spans(text, &mut raw);

        // ANCHORED ALL-CAPS PERSON NAMES (the finance-corpus round) — cue-corroborated
        // transaction-narrative counterparty names (`FAST TRANSFER FR DARIUS OKONKWO-LIM`).
        // Emits the NON-SEEDING `ctx:caps-name` class (an all-caps FP must never propagate
        // — the amplification-class decision). Gated on the role-name opt-in like the
        // trailing-role pass, so the default path is byte-identical.
        self.caps_person_spans(text, &mut raw);

        // OPT-IN ORGANISATION detection (suffix-anchored + org-context). Its OWN `ctx:org`
        // recognizer class — NEVER a `Recognizer::Name`, so it is EXCLUDED from every
        // person-name propagation seed below (a broad org can never amplify document-wide the
        // way a person name does). Placed AFTER the Name-emitting passes so the org-context
        // arm can see (and defer to) the person spans already in `raw`. No-op unless the
        // `organisations` flag is on, so the default path is byte-identical.
        self.organisation_spans(text, &mut raw);

        // NAME-PROPAGATION second pass (name closure). Seeded from the `Name` candidates
        // ALREADY in `raw`, it adds extra `Recognizer::Name` spans for: (SAFE, always on)
        // every additional EXACT occurrence of a detected full-name string, and (EXPANSION,
        // opt-in) any Capitalized multi-word run containing a detected name TOKEN. The new
        // spans flow through the SAME sort/merge below, so they merge/overlap-resolve like
        // any other Name span. NO `Name` candidate in `raw` ⇒ this contributes nothing, so
        // the default (and any non-name doc) is byte-identical. Deterministic (regex
        // find_iter + a sorted token set; no clock/RNG).
        self.name_propagation_spans(text, &mut raw);

        // ADDRESS-BLOCK CONTINUATION second pass (Round-3 fix C). When two address-family
        // candidates (street / unit / postal) sit within a small line window, the
        // proper-noun-shaped BUILDING/TOWER lines BETWEEN them (`UOB Plaza`, `Capital Tower`)
        // are captured as `Recognizer::Address` spans; an office-label line
        // (`Registered office:` / `Operating office` / `Registered address`) counts as an
        // opening anchor. A no-op unless the address family is active (`address_ws_patterns`
        // non-empty), so the default path is byte-identical. Deterministic, bounded (only
        // strictly between anchors ≤3 lines apart, only proper-noun lines).
        self.address_block_continuation_spans(text, &mut raw);
        // INLINE (line-wrapped, in-prose) building name between two address anchors — the
        // companion to the own-line block pass above; runs regardless of line count.
        self.inline_building_spans(text, &mut raw);

        // Drop empty matches defensively (a zero-width span is never a redaction).
        raw.retain(|(s, e, _, _)| e > s);
        if raw.is_empty() {
            return Vec::new();
        }

        // Deterministic total order: start ASC, end DESC, priority ASC, then the
        // recognizer LABEL ASC so two equal-priority customs are still totally
        // ordered (keeps the merge fully deterministic). Priority is the ENGINE-AWARE
        // `recognizer_priority` (NOT the raw `Recognizer::priority`) so an AGGRESSIVE
        // locale row is ordered at its DEMOTED tier — it loses the primary-LABEL contest
        // to any precise sibling. The label-ASC tie-break keeps the order total even
        // when the demotion makes an aggressive row tie a Phone/Ip-tier recognizer.
        raw.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(b.1.cmp(&a.1))
                .then(
                    self.recognizer_priority(&a.2)
                        .cmp(&self.recognizer_priority(&b.2)),
                )
                .then_with(|| a.2.label().cmp(b.2.label()))
        });

        // Sweep-merge overlapping OR touching spans. Each accumulator records every
        // DISTINCT custom replacement it absorbs (FIX F7): a single custom
        // replacement over the union span is unambiguous and is preserved; ≥2
        // DIFFERENT ones are ambiguous and fall back to the default marker at
        // finalization.
        let mut merged: Vec<MergeAcc> = Vec::new();
        for (s, e, kind, replacement) in raw {
            match merged.last_mut() {
                // Overlap or touch (s <= acc.end): extend the union and keep the
                // most-specific (lowest-priority value) recognizer as primary.
                Some(acc) if s <= acc.end => {
                    if e > acc.end {
                        acc.end = e;
                    }
                    // ENGINE-AWARE priority: an AGGRESSIVE locale row is demoted, so a
                    // precise sibling already in `acc` is never displaced by it (and an
                    // aggressive row only becomes primary when nothing precise covers the
                    // span — a LAST RESORT). The raw sort already placed the lowest-
                    // priority member first, but a later member can still beat the current
                    // primary, so re-check here with the SAME engine-aware ordering.
                    if self.recognizer_priority(&kind) < self.recognizer_priority(&acc.kind) {
                        acc.kind = kind.clone();
                    }
                    // FIX #5: record every distinct recognizer over this span so no
                    // label (e.g. a second same-pattern rule) is lost to the merge.
                    if !acc.kinds.contains(&kind) {
                        acc.kinds.push(kind);
                    }
                    // FIX F7: record this member's custom replacement (if any) as a
                    // DISTINCT entry, instead of forcing the marker the moment a
                    // second member arrives. A contained `Custom` span carrying a
                    // custom replacement is thus preserved rather than overwritten.
                    push_distinct_replacement(&mut acc.custom_replacements, replacement);
                }
                _ => {
                    let mut custom_replacements = Vec::new();
                    push_distinct_replacement(&mut custom_replacements, replacement);
                    merged.push(MergeAcc {
                        start: s,
                        end: e,
                        kind: kind.clone(),
                        kinds: vec![kind],
                        custom_replacements,
                    });
                }
            }
        }

        let mut spans: Vec<MergedSpan> = merged
            .into_iter()
            .filter_map(|acc| {
                // Deterministically order the per-span recognizer list: priority
                // ASC, then label ASC (the same total order the merge sort uses).
                // For an un-merged span this is just `[recognizer]`. Uses the SAME
                // ENGINE-AWARE `recognizer_priority` as the merge sort + primary election,
                // so an AGGRESSIVE locale row sorts to its demoted position in the LIST too
                // (and a re-election to `recognizers[0]` after context-suppression picks the
                // precise head, never an aggressive row, when a precise sibling survives).
                let mut recognizers = acc.kinds;
                recognizers.sort_by(|a, b| {
                    self.recognizer_priority(a)
                        .cmp(&self.recognizer_priority(b))
                        .then_with(|| a.label().cmp(b.label()))
                });

                // LEVER 2 + CONTEXT-REQUIRED LOCALE rows — the additive-only GATE (a
                // FINALIZATION filter). It runs ONLY when ≥1 context-required recognizer is
                // enabled (a `ctx:*` context recognizer OR a `context: Some` locale row such
                // as `us:dl`), so the DEFAULT path is byte-identical (no gate, no change).
                //
                // GENERALIZED RULE: a context-required recognizer is SUPPRESSED (removed
                // from this span's attribution) when NO required keyword is in-window; a
                // span survives iff at least one recognizer remains after suppression. A
                // recognizer is SATISFIED (kept) when:
                //   - it is a NORMAL recognizer (not a `ctx:*` row, not a `context: Some`
                //     locale row) — it always corroborates on its own; OR
                //   - it is a `ctx:*` context row whose lexicon keyword is in-window; OR
                //   - it is a context-required LOCALE row whose required-context keyword is
                //     in-window.
                // SUPPRESSING (rather than only dropping context-ONLY spans) is what fixes
                // the `us:dl` flood: a context-required LOCALE row is priority-1, so on the
                // 962-page footer `NM0426U-5414319-2/962` it merged INTO a span the broad
                // `id` built-in keeps alive and rode along as a co-recognizer (even the
                // PRIMARY). Removing the keyword-less `us:dl` from that span's attribution
                // means NO `us:dl` candidate is surfaced (the `id` span itself is unchanged
                // — a normal match is never removed). This strictly GENERALIZES the old
                // `ctx:*`-only "drop context-only span" gate (a context-only span is one
                // where suppression empties the list → it is dropped), preserving the
                // `ctx:*` axis: a keyword-less `ctx:*` row covered by a normal recognizer
                // was already non-primary (priority 6) and not counted in the breakdown, so
                // dropping it from the cosmetic recognizer LIST changes no tested output.
                let any_context = self.context_recognizers.any();
                let any_locale_required = !self.locale_required_context.is_empty();

                // The strongest in-window proximity over THIS span's `ctx:*` context rows
                // (used both by the gate's `ctx:*` arm and the context rung of the ladder).
                // Only computed when `ctx:*` context is active and the span involves one.
                let span_proximity = if any_context
                    && recognizers
                        .iter()
                        .any(|r| matches!(r, Recognizer::Context(_)))
                {
                    self.context_proximity_for(text, acc.start, acc.end, &recognizers)
                } else {
                    context::Proximity::None
                };

                // Suppress unsatisfied context-required recognizers (only when the gate is
                // active — on the default path `recognizer_unsatisfied` is `false` for every
                // recognizer, so nothing is removed and the list is unchanged). The probe
                // is confidentiality-clean (OUR constant lexicons via `keyword_in_window`,
                // never logs cleartext).
                //
                // PRIMARY-PRESERVATION: keep the merge's elected primary `acc.kind` whenever
                // it SURVIVES suppression (so the default path AND any span whose primary is
                // not a suppressed context-required row are byte-identical — `acc.kind`'s
                // raw-order tie-break is NOT replaced by the list's label-ASC tie-break). The
                // primary is only re-elected (to the surviving `recognizers[0]`, the sorted
                // priority/label-ASC head) when `acc.kind` itself was the suppressed row —
                // e.g. a keyword-less `us:dl` that won the merge over `us:ein` is removed and
                // `us:ein` takes over, so the attribution reflects the real identifier.
                let mut primary = acc.kind;
                if any_context || any_locale_required {
                    recognizers
                        .retain(|r| !self.recognizer_unsatisfied(text, acc.start, acc.end, r));
                    if recognizers.is_empty() {
                        // Every contributor was context-required but keyword-less => NOISE.
                        // (A span any NORMAL recognizer also covers keeps that recognizer,
                        // so it is never empty here — a normal match is never removed.)
                        return None;
                    }
                    // Re-elect the primary ONLY if the merge's primary was suppressed.
                    if !recognizers.contains(&primary) {
                        primary = recognizers[0].clone();
                    }

                    // DATE-NOT-PHONE attribution fixup (round 4, Mechanism B). The dotted
                    // (`14.03.1998`) and ISO (`1998-03-14`) date shapes also satisfy the
                    // broad phone pattern (its char class admits `.`/`-`), and phone
                    // out-priorities a ctx row in the merge — so a DATE reviewed next to a
                    // DOB keyword was LABELED a phone (and in the PDF path a cross-line
                    // phone is line-scope-dropped, a silent leak). A `ctx:dob` member that
                    // SURVIVED the gate is keyword-corroborated (the suppression above
                    // removed any keyword-less one), so it is the truthful attribution:
                    // re-label the span `ctx:dob`. ATTRIBUTION-ONLY + recall-neutral (the
                    // span and the candidate set are unchanged; only the primary label —
                    // and thus the review type + the PDF sanction lane — changes), the
                    // same posture as the aggressive-locale demotion.
                    if matches!(primary, Recognizer::Phone) {
                        if let Some(dob) = recognizers.iter().find(
                            |r| matches!(r, Recognizer::Context(l) if l.as_ref() == "ctx:dob"),
                        ) {
                            primary = dob.clone();
                        }
                    }
                }

                // Tier the surviving candidate (pure, deterministic; annotation only —
                // it does not change the span, the merge, or whether the candidate fires).
                let confidence =
                    self.confidence_for(text, acc.start, acc.end, &primary, span_proximity);

                // FIX F7: resolve the replacement from the DISTINCT custom set —
                // exactly one => preserve it (unambiguous, even when contained
                // inside a default-marker built-in span); zero or ≥2 distinct =>
                // the default marker (no custom replacement, or an ambiguous union).
                let replacement = match acc.custom_replacements.as_slice() {
                    [only] => Some(only.clone()),
                    _ => None,
                };
                Some(MergedSpan {
                    candidate: RedactionCandidate {
                        start: acc.start,
                        end: acc.end,
                        matched_value: text[acc.start..acc.end].to_string(),
                        recognizer: primary,
                        recognizers,
                        context: context_snippet(text, acc.start, acc.end),
                        confidence,
                    },
                    replacement,
                })
            })
            .collect();

        // ANCHORED-NAME pass (the wrapped-name round, Mechanisms B + C): the person name
        // flush before a DETECTED `<email>` / `(NRIC …)`-style anchor is emitted as a Name
        // candidate. Runs BEFORE propagation so an anchored name SEEDS it (the same person's
        // prose re-mentions are then covered too). No-op without an anchor candidate.
        self.anchored_name_candidates(text, &mut spans);
        // MECHANISM A (detected-name propagation) — the general fix for "detected once,
        // readable elsewhere". Runs on the FINAL candidates (post gate) so it seeds only from
        // names that survived, and both scan + apply inherit it (scan/apply parity). No-op
        // when no qualifying name candidate exists (byte-identical default).
        self.propagate_name_candidates(text, &mut spans);
        spans
    }

    /// The strongest [`context::Proximity`] over every CONTEXT recognizer in `recognizers`
    /// for the span `start..end` (Lever 2). Each context row supplies its own lexicon
    /// (recovered from its `ctx:` label); the result is the best (nearest) over all of
    /// them. Pure + deterministic + confidentiality-clean (returns a distance bucket, no
    /// text). Returns [`context::Proximity::None`] if no context recognizer is present.
    fn context_proximity_for(
        &self,
        text: &str,
        start: usize,
        end: usize,
        recognizers: &[Recognizer],
    ) -> context::Proximity {
        let mut best = context::Proximity::None;
        for r in recognizers {
            if let Recognizer::Context(label) = r {
                if let Some(row) = context::row_for_label(label) {
                    let p = context::keyword_in_window(
                        text,
                        start,
                        end,
                        row.lexicon,
                        row.blank_line_tolerance,
                        row.name_line_run_back,
                    );
                    if p == context::Proximity::Close {
                        return context::Proximity::Close; // can't beat Close
                    }
                    if p == context::Proximity::Window {
                        best = context::Proximity::Window;
                    }
                }
            }
        }
        best
    }

    /// Is recognizer `r` CONTEXT-REQUIRED-AND-UNSATISFIED for the span `start..end`?
    /// (The per-recognizer predicate of the additive-only gate in
    /// [`merged_spans`](RedactionEngine::merged_spans).)
    ///
    /// Returns `true` ONLY when `r` needs a context keyword AND none is in-window:
    ///
    /// - a `ctx:*` [`Recognizer::Context`] row whose lexicon has no keyword in-window; or
    /// - a [`Recognizer::Locale`] row registered in `locale_required_context` (its
    ///   `context` field was `Some`, e.g. `us:dl`) whose required-context lexicon has no
    ///   keyword in-window.
    ///
    /// EVERY other recognizer — a normal built-in/term/custom/profile, OR a locale row
    /// with NO required context (the common case, `context: None`) — is UNCONDITIONALLY
    /// SATISFIED, so this returns `false` and the span survives because of it. Pure,
    /// deterministic, confidentiality-clean (it consults OUR constant lexicons via the
    /// same [`context::keyword_in_window`] probe; it never logs cleartext).
    fn recognizer_unsatisfied(&self, text: &str, start: usize, end: usize, r: &Recognizer) -> bool {
        match r {
            Recognizer::Context(label) => match context::row_for_label(label) {
                // Unsatisfied iff no `ctx:` lexicon keyword is in-window AND (for a row that
                // opts in) no role keyword was consumed as the LEADING token of the matched
                // run (fix B — the two-column heading+name shape, where the window probe
                // excludes the span so the head-keyword would otherwise be invisible).
                Some(row) => {
                    let window_none = context::keyword_in_window(
                        text,
                        start,
                        end,
                        row.lexicon,
                        row.blank_line_tolerance,
                        row.name_line_run_back,
                    ) == context::Proximity::None;
                    window_none
                        && !(row.corroborate_from_leading_span
                            && context::span_leads_with_keyword(&text[start..end], row.lexicon))
                }
                // An unknown `ctx:` label has no recoverable lexicon — treat it as
                // SATISFIED (return `false`) rather than silently dropping a candidate
                // (recall-first: never drop on a lookup miss).
                None => false,
            },
            Recognizer::Locale(label) => match self.locale_required_context.get(label) {
                // A context-required locale row (e.g. `us:dl`): unsatisfied iff no
                // required-context keyword is in-window.
                Some(lexicon) => {
                    // Locale required-context rows use the FIXED window (no blank-line
                    // tolerance nor name-line reach — both widenings are scoped to the
                    // role-name ctx row).
                    context::keyword_in_window(text, start, end, lexicon, 0, 0)
                        == context::Proximity::None
                }
                // A locale row with NO required context (`context: None`) is a normal,
                // unconditionally-firing recognizer — never gated.
                None => false,
            },
            // Every other recognizer corroborates on its own — never context-gated.
            _ => false,
        }
    }

    /// Compute the Lever-2 CONFIDENCE tier for a merged span (PURE, deterministic, NO
    /// clock). The ladder, documented in `to-read/redaction.LEVER2-CONTEXT-CONFIDENCE.md`:
    ///
    /// 1. **Checksum-validated** identifier (Luhn card / mod-97 IBAN) => **High**
    ///    (context-irrelevant: a real card/IBAN is a real card/IBAN).
    /// 2. **Structurally-specific** format (email, dashed SSN, NRIC, and the like — a
    ///    shape precise enough to stand alone) => **High** if a CLASS keyword is in-window,
    ///    else **Medium**.
    /// 3. **Context-required** match (the primary is a `Recognizer::Context`) => the row's
    ///    `default_tier` (**Medium**) when a keyword is merely in-window, promoted to
    ///    **High** when a keyword is CLOSE (a strict ≤20-byte gap — the same-line OR-arm was
    ///    dropped when the two-tier routing made the tier load-bearing). (A context-only span
    ///    with NO keyword was already DROPPED by the gate; a context span that SURVIVES
    ///    only because a normal recognizer covers it is tiered by that normal primary,
    ///    not here — the primary is then the normal recognizer.)
    /// 4. **Everything else** (the broad built-ins — phone / id / name heuristic / url /
    ///    ip / a caller term / a custom rule) defaults to **Low**, raised to **Medium** if
    ///    a relevant class keyword is in-window. The documented sensible default.
    fn confidence_for(
        &self,
        text: &str,
        start: usize,
        end: usize,
        primary: &Recognizer,
        span_proximity: context::Proximity,
    ) -> Confidence {
        // Rung 1 — a CHECKSUM-validated identifier (Luhn card / mod-97 IBAN) is precise
        // on its own — a real card/IBAN always passes the checksum, so a passing match is
        // almost certainly the real thing — so it is High independent of context. (A
        // STRUCTURAL-only validator like the dashed-SSN range rules is NOT a checksum; it
        // is treated as a structurally-specific shape at rung 2 below, per the documented
        // ladder, so dashed SSN is Medium alone / High near an SSN keyword.)
        if is_checksum_validated(primary) {
            return Confidence::High;
        }

        // Rung 3 — context-required primary: tier by proximity (the gate guarantees a
        // surviving context-only span has a keyword in-window, so `span_proximity` is
        // Window or Close here). Close => High; Window => the row's default_tier.
        if let Recognizer::Context(label) = primary {
            // OPT-IN ORGANISATION class: deliberately FP-prone (esp. the broad org-context
            // arm), so it is PINNED to `Low` — the CAREFUL review tier, never quick-confirm /
            // auto-accept, even under a lowered quick-confirm floor. (It has no `ctx:org` row
            // in `context::CONTEXT_RECOGNIZERS`, so the generic branch below would default it
            // to Medium; this explicit pin is the "cap_tier Medium equivalent" guardrail.)
            if label.as_ref() == ORG_CONTEXT_LABEL {
                return Confidence::Low;
            }
            // ANCHORED ALL-CAPS person class: PINNED to `Medium` — the CAREFUL review
            // tier under the default floor, never quick-confirm — exactly like the
            // `ctx:org` pin above (review HIGH, the finance round). WHY the pin is
            // load-bearing: `ctx:caps-name` has no row in `context::CONTEXT_RECOGNIZERS`,
            // so without it the generic branch below would take the SPAN's proximity —
            // and a caps-heading span merged with a satisfied `ctx:role-name` SIBLING
            // (whose role heading sits Close) elects `ctx:caps-name` as primary on the
            // label-ASC tie-break and inherited the sibling's Close ⇒ High ⇒ tier-1
            // bulk-accept of a caps FP (`TRANSFERRING SHARES` under `Directors`,
            // verified on the flagship corpus). Medium (not Low) mirrors the
            // `ctx:role-name` `cap_tier` posture the arm rides alongside.
            if label.as_ref() == CAPS_NAME_LABEL {
                return Confidence::Medium;
            }
            let row = context::row_for_label(label);
            let default_tier = row.map(|r| r.default_tier).unwrap_or(Confidence::Medium);
            let computed = match span_proximity {
                context::Proximity::Close => Confidence::High,
                context::Proximity::Window => default_tier,
                // Unreachable for a surviving context-only span (gated out), but a
                // context primary that survives via a normal sibling would land here —
                // give it the default tier rather than over-claiming.
                context::Proximity::None => default_tier,
            };
            // Apply the row's OPTIONAL tier CEILING (`cap_tier`): a deliberately FP-prone
            // row (e.g. `ctx:role-name`) caps at Medium so a CLOSE keyword can NEVER
            // promote it to High/quick-confirm — it stays in the CAREFUL tier. `None`
            // (every other ctx row) leaves the computed tier unchanged.
            return match row.and_then(|r| r.cap_tier) {
                Some(cap) => computed.min(cap),
                None => computed,
            };
        }

        // Rungs 2 & 4 — a class-keyword in-window raises the rung. Structurally-specific
        // recognizers (email/dashed-SSN/NRIC/...) go Medium -> High on a keyword; broad
        // recognizers go Low -> Medium on a keyword.
        let kw_close =
            self.class_keyword_in_window(text, start, end, primary) != context::Proximity::None;
        if is_structural(primary) {
            if kw_close {
                Confidence::High
            } else {
                Confidence::Medium
            }
        } else if kw_close {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }

    /// The strongest [`context::Proximity`] of a CLASS keyword for the primary
    /// recognizer's kind (rungs 2 & 4). The class lexicon ([`class_lexicon`]) is OUR
    /// constant per-kind keyword set (e.g. email -> {email, e-mail, contact}); a kind
    /// with no class lexicon yields `None`. Pure + deterministic + confidentiality-clean.
    fn class_keyword_in_window(
        &self,
        text: &str,
        start: usize,
        end: usize,
        primary: &Recognizer,
    ) -> context::Proximity {
        match class_lexicon(primary) {
            // Class-keyword corroboration uses the FIXED window (blank-line tolerance and
            // name-line reach are scoped to the role-name row's own lexicon gate, not the
            // class-keyword rung).
            Some(lex) => context::keyword_in_window(text, start, end, lex, 0, 0),
            None => context::Proximity::None,
        }
    }

    /// Detect + remove all identifier spans in `text` in a SINGLE authoritative
    /// pass: returns the redacted text, the count, AND the exact candidates that
    /// were replaced. PURE + DETERMINISTIC. The candidates and the redacted
    /// string come from the SAME merged span set, so the returned candidates are
    /// EXACTLY what was replaced (`count == candidates.len() == markers written`).
    ///
    /// This is the authoritative detector the core applies via `document_transform`.
    pub fn redact_detail(&self, text: &str) -> (String, Vec<RedactionCandidate>) {
        let spans = self.merged_spans(text);

        // Rebuild the redacted string by splicing the merged spans (already sorted
        // by start, non-overlapping) — one replacement per span, nothing else
        // touched. This GUARANTEES one written replacement per candidate (no
        // recognizer can double-replace a span another already covered), so
        // `count == candidates.len() == replacements written` holds.
        //
        // A span whose resolved `replacement: Some(s)` writes `s` (configurable
        // find-AND-replace — including a merged span that carries exactly ONE
        // distinct custom replacement, FIX F7); every other span — built-ins, and
        // any span with zero or ≥2 distinct custom replacements — writes the
        // default marker.
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let mut candidates = Vec::with_capacity(spans.len());
        for m in spans {
            out.push_str(&text[cursor..m.candidate.start]);
            match &m.replacement {
                Some(s) => out.push_str(s),
                None => out.push_str(REDACTION_MARKER),
            }
            cursor = m.candidate.end;
            candidates.push(m.candidate);
        }
        out.push_str(&text[cursor..]);

        (out, candidates)
    }

    /// Count + remove all identifier spans in `text`, returning the redacted text
    /// and the number of REPLACEMENTS applied. PURE + DETERMINISTIC. Thin wrapper
    /// over [`redact_detail`](RedactionEngine::redact_detail): the count is exactly
    /// `candidates.len()` (one merged span = one redaction).
    pub fn redact_with_count(&self, text: &str) -> (String, usize) {
        let (out, candidates) = self.redact_detail(text);
        (out, candidates.len())
    }

    /// Back-compat alias: redact `text` and return `(redacted, count)`. Prefer
    /// [`RedactionEngine::redact_with_count`].
    pub fn redact_text(&self, text: &str) -> (String, usize) {
        self.redact_with_count(text)
    }

    /// PURE, Core-free SELECTION apply over raw text — the off-chokepoint analogue of
    /// [`apply_selection`](RedactionEngine::apply_selection) for a host that holds the
    /// text itself (e.g. a CLI / a paste-in tool) and does its OWN logging.
    ///
    /// Re-detects the authoritative merged spans in `text`, redacts ONLY those whose
    /// `(start, end)` appears in `accepted` (a reviewer's accept set, as reported on each
    /// [`RedactionCandidate`] from [`candidates`](RedactionEngine::candidates)), and
    /// returns `(redacted, applied, stale)`:
    /// - `applied` — accepted spans still present and redacted;
    /// - `stale` — accepted coordinates NO LONGER present (the text changed since the scan
    ///   that produced them) — counted, never written at a now-wrong offset (matching
    ///   `apply_selection`'s stale semantics, so a UI gets the same "N stale" signal).
    ///
    /// Deterministic. Holds NO Core/audit/egress — the redacted text is returned
    /// in-process and the caller owns any persistence/logging (this method itself logs
    /// nothing, so no cleartext leaks). An empty `accepted` set redacts nothing.
    pub fn redact_with_selection(
        &self,
        text: &str,
        accepted: &std::collections::HashSet<(usize, usize)>,
    ) -> (String, usize, usize) {
        // Re-detect once; derive applied/stale from the SAME authoritative span set the
        // redact uses, so the reported counts and the written output always agree.
        let present: std::collections::HashSet<(usize, usize)> = self
            .merged_spans(text)
            .iter()
            .map(|m| (m.candidate.start, m.candidate.end))
            .collect();
        let applied = accepted.iter().filter(|k| present.contains(k)).count();
        let stale = accepted.len() - applied;
        (self.redact_selected(text, accepted), applied, stale)
    }

    /// PURE, Core-free SELECTION apply over raw text in the **AI-safe LABELS** style
    /// (pseudonymization) — the sibling of [`redact_with_selection`](RedactionEngine::
    /// redact_with_selection) that, instead of overwriting every accepted span with the
    /// `[REDACTED]` marker, assigns each DISTINCT removed entity a STABLE, DISTINCT
    /// placeholder (`[A]`, `[email 1]`, …). Relationships/coherence survive — the user can
    /// paste the labeled draft into an external AI tool WITHOUT exposing real identities —
    /// and the returned [`Legend`] (label → first-seen surface form + occurrence count) is
    /// the LOCAL key the lawyer keeps to re-identify. This tool makes NO AI/network call; it
    /// only produces the labeled draft + the legend, both returned IN-PROCESS.
    ///
    /// # Recall parity (load-bearing)
    ///
    /// This redacts EXACTLY the same accepted spans as [`redact_with_selection`] — the SAME
    /// authoritative [`merged_spans`](RedactionEngine::merged_spans) pass, the SAME
    /// accept/stale accounting. Pseudonymization changes ONLY the replacement TOKEN, never
    /// WHICH spans are removed. `(applied, stale)` are byte-identical to the marker path for
    /// the same `accepted` set.
    ///
    /// # Labeling scheme (deterministic — see [`assign_labels`])
    ///
    /// Two families, both keyed by the NORMALIZED matched value (ASCII-lowercased, with
    /// leading/trailing whitespace trimmed and internal whitespace runs collapsed to one
    /// space) so every occurrence of the same value reuses the same placeholder, and both
    /// assigned in FIRST-SEEN (document) order:
    /// - **ENTITY family** — user `Term` matches + the `Name` heuristic ("the named
    ///   parties/things to track"): distinct UPPERCASE letters `[A]`, `[B]`, … then after
    ///   `[Z]` the spreadsheet-column continuation `[AA]`, `[AB]`, … (base-26 bijective).
    /// - **TYPED family** — every other recognizer, labeled by a human-readable TYPE
    ///   ([`Recognizer::type_label`]): `[email]`, `[phone]`, `[Singapore ID]`, … NUMBERED
    ///   per-type ONLY when ≥2 DISTINCT values of that type appear (`[email 1]`,
    ///   `[email 2]`); a single distinct value stays UNNUMBERED (`[email]`).
    ///
    /// A value caught by BOTH families follows the merged PRIMARY recognizer (Custom/Term >
    /// typed), so an entity-merged span gets the ENTITY letter — one placeholder per span.
    ///
    /// # Confidentiality
    ///
    /// The legend carries cleartext (the same in-process sensitivity as the candidate list):
    /// it is a RETURN value for the local review only — this method logs NOTHING, holds no
    /// egress, and the legend must NEVER be audited (the audit chain stays counts-only).
    /// Deterministic: no clock, no RNG, no network — same input + same terms + same accept
    /// set ⇒ byte-identical labeled text AND identical legend.
    ///
    /// # Differences from the marker path (by design, NOT recall — both remove the same spans)
    ///
    /// - A firm [`UserRecognizer`]'s configured `replacement` string is IGNORED in labels
    ///   mode: a `Custom`-primary span is an explicitly-named party/thing, so it is routed to
    ///   an ENTITY LETTER (the whole point of pseudonymization is a stable placeholder, not a
    ///   fixed find-AND-replace string). The marker path still honors that replacement.
    /// - The entity and typed families are keyed SEPARATELY, so the rare value that is an
    ///   ENTITY primary in one span (e.g. a `Name`-heuristic hit) but a TYPED primary in a
    ///   different, non-overlapping span can receive BOTH a letter and a `[type]`. This is a
    ///   legend-granularity nicety, NEVER a leak (the SAME spans are removed either way).
    pub fn redact_with_selection_labeled(
        &self,
        text: &str,
        accepted: &std::collections::HashSet<(usize, usize)>,
    ) -> (String, Legend, usize, usize) {
        // The SAME authoritative span set the marker path uses (recall parity by
        // construction — the labeled walk only changes the token written per span).
        let spans = self.merged_spans(text);
        let present: std::collections::HashSet<(usize, usize)> = spans
            .iter()
            .map(|m| (m.candidate.start, m.candidate.end))
            .collect();
        let applied = accepted.iter().filter(|k| present.contains(k)).count();
        let stale = accepted.len() - applied;

        // Assign each ACCEPTED span its stable placeholder in a single first-seen pass
        // over the (already start-sorted, non-overlapping) merged spans, then splice.
        let (labeled, legend) = assign_labels(text, &spans, accepted);
        (labeled, legend, applied, stale)
    }

    /// Redact every document in the matter the engine is granted to read, over
    /// its configured classes. For each doc: LIST via `matter_list_docs`, READ via
    /// `matter_read_text`, detect + count in a single pure pass, AUDIT-NOTE the
    /// count/breakdown, then REWRITE via `document_transform` (so the strip happens
    /// in-place THROUGH the core, mediated + logged). The SAME single-pass detector
    /// that produces the redacted string also yields the returned candidates, so
    /// the count, the candidate list, and the markers written all agree.
    ///
    /// # Fail-closed ordering (act-before-log defect, FIXED)
    ///
    /// The per-doc audit note is recorded BEFORE `document_transform` commits the
    /// strip — so a failed note ABORTS the redaction rather than leaving a
    /// document redacted with no count/breakdown in the audit chain. This mirrors
    /// the runtime's own log-before-write ordering on `document_transform`
    /// (`core/crates/runtime`): log the intent, then perform the irreversible act,
    /// never the reverse.
    ///
    /// # Confidentiality split (load-bearing)
    ///
    /// The returned [`RedactionReport`] carries the actual candidates INCLUDING
    /// cleartext `matched_value`/`context` for the in-process review workflow —
    /// the engine holds no egress capability, so this never leaves the box. The
    /// `audit_note`, by contrast, records ONLY the count + a per-recognizer
    /// breakdown, NEVER the cleartext values, so the tamper-evident audit chain
    /// does not become a cleartext store of the identifiers being redacted.
    ///
    /// Any refusal (un-granted class / transform) propagates as a `CoreResult`
    /// error — fail-closed, consistent with the core.
    pub fn redact_matter<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
    ) -> CoreResult<RedactionReport>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let mut report = RedactionReport::default();

        // Record the active compliance-profile selection ONCE, fail-closed, before any
        // doc is touched — so the audit trail shows WHICH regime this redaction
        // targeted + its honest review-gaps (config strings only, never a value). A
        // no-profile engine emits nothing here, so its audit chain is unchanged.
        if let Some(note) = self.profile_selection_note() {
            core.audit_note(&note)?;
        }

        for &class in &self.classes {
            // Entitlement: the core refuses a non-granted class here (default-deny).
            let docs = core.matter_list_docs(class)?;
            for doc in docs {
                // Content-kind filter INSIDE the chokepoint: this is the TEXT path, so
                // skip a `Blob` doc (a PDF/binary in the same class — the PDF path's
                // job, `redact_matter_pdf`). Without this, `matter_read_text` on a blob
                // would be a content-kind mismatch and `?`-abort the whole text sweep;
                // a `document` class realistically holds BOTH text docs and PDFs, which
                // must coexist. (Every seeded test doc is Text → still processed.)
                if doc.kind != ContentKind::Text {
                    continue;
                }
                // Read the doc THROUGH the core (mediated, entitlement-filtered,
                // audited), then detect in a SINGLE pure pass. The candidates and
                // the redacted string come from the SAME span set, so the count,
                // the candidate list, and the markers written all agree.
                let original = core.matter_read_text(doc.id, class)?;
                let (_redacted, candidates) = self.redact_detail(&original);
                let removed = candidates.len();

                // FIX (HIGH — act-before-log): record the per-doc COUNT +
                // per-recognizer BREAKDOWN as module context (ungated audit.note)
                // BEFORE committing the strip, so a failed note ABORTS the
                // transform instead of leaving the document redacted with no
                // count/breakdown in the chain. CONFIDENTIALITY: this records the
                // count/breakdown ONLY — never a `matched_value` cleartext string,
                // so the audit chain never stores the identifiers being redacted.
                core.audit_note(&format!(
                    "redaction: doc {} ({}) — {} redaction(s) applied [{}] {{{}}}",
                    doc.id,
                    class,
                    removed,
                    recognizer_breakdown(&candidates),
                    tier_breakdown(&candidates),
                ))?;

                // Commit the strip THROUGH the core (itself mediated + logged; its
                // write-back is recorded before it lands). The closure re-runs the
                // SAME deterministic pass over the (unchanged) content, so what is
                // written matches the candidates the note just recorded.
                let engine = self;
                core.document_transform(doc.id, class, |s| engine.redact_detail(s).0)?;

                report.docs.push(DocReport {
                    doc_id: doc.id,
                    class,
                    identifiers_removed: removed,
                    candidates,
                });
            }
        }

        Ok(report)
    }

    /// PHASE 1 of the human-review workflow — SCAN a matter for candidates WITHOUT
    /// writing anything. For each granted class: LIST, READ, detect candidates, and
    /// AUDIT-NOTE the scan (count + per-recognizer breakdown, never cleartext). No
    /// `document_transform` is called, so this needs only `matter.read:<class>`
    /// (NOT `document.transform`) — a scanning/review pass literally cannot mutate a
    /// document, even by mistake.
    ///
    /// Returns a [`ScanReport`] whose candidates carry cleartext for the in-process
    /// review only (the engine holds no egress; nothing leaves the box). Feed it to
    /// [`Selection::all`]/[`Selection::none`], prune, then [`apply_selection`].
    ///
    /// Fail-closed: any refusal (un-granted class) or audit error propagates.
    pub fn scan_matter<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
    ) -> CoreResult<ScanReport>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let mut report = ScanReport::default();
        // Record the active compliance-profile selection ONCE (config strings only,
        // never a value), fail-closed, before scanning. A no-profile engine emits
        // nothing here, so its audit chain is unchanged.
        if let Some(note) = self.profile_selection_note() {
            core.audit_note(&note)?;
        }
        for &class in &self.classes {
            // Entitlement: the core refuses a non-granted class here (default-deny).
            let docs = core.matter_list_docs(class)?;
            for doc in docs {
                // Content-kind filter: this is the TEXT scan, so skip a `Blob` doc (a
                // PDF/binary in the same class — `scan_matter_pdf`'s job). Without it,
                // `matter_read_text` on a blob would `?`-abort the whole text scan; text
                // and PDF docs coexist in one class. (Seeded test docs are all Text.)
                if doc.kind != ContentKind::Text {
                    continue;
                }
                let content = core.matter_read_text(doc.id, class)?;
                let candidates = self.candidates(&content);
                // Audit the SCAN — count + breakdown ONLY, never a cleartext value,
                // and NO write. Distinct wording ("scan"/"candidate(s)") from the
                // apply/redact notes so the audit trail tells the phases apart.
                core.audit_note(&format!(
                    "redaction scan: doc {} ({}) — {} candidate(s) [{}] {{{}}}",
                    doc.id,
                    class,
                    candidates.len(),
                    recognizer_breakdown(&candidates),
                    tier_breakdown(&candidates),
                ))?;
                report.docs.push(DocScan {
                    doc_id: doc.id,
                    class,
                    candidates,
                });
            }
        }
        Ok(report)
    }

    /// PHASE 3 of the human-review workflow — APPLY only the spans the reviewer
    /// accepted (a [`Selection`] built over a [`ScanReport`]). For each (document,
    /// class) that has ≥1 accepted span: READ the current content, re-detect the
    /// authoritative merged spans, keep ONLY those whose byte span the selection
    /// accepted, AUDIT-NOTE the apply (applied count + breakdown + stale count),
    /// then commit them via the mediated `document_transform`.
    ///
    /// # Stale spans (content changed between scan and apply)
    ///
    /// A selection records span COORDINATES. If the document changed since the scan,
    /// a previously-accepted span may no longer be present at those offsets. Such a
    /// span is counted as `stale` and SKIPPED — never written at a now-wrong offset
    /// (which could redact the wrong text). Matching is by re-detected `(start, end)`,
    /// so a span only applies if a live identifier still occupies those exact bytes.
    ///
    /// LIMITATION (offset-based, not content-based): if the document changed such
    /// that a DIFFERENT identifier now occupies the SAME exact byte span an accepted
    /// span had, that identifier is redacted (counted `applied`). This is an
    /// OVER-redaction (it removes more), never a leak, and requires an exact-offset
    /// collision with changed content — astronomically unlikely in practice, since
    /// any real edit shifts offsets (→ correctly `stale`). A future hardening could
    /// fingerprint the accepted value (a non-cleartext hash) to treat a reoccupied
    /// offset as stale; deferred as the realistic risk is negligible.
    ///
    /// # Ordering / capabilities
    ///
    /// The per-doc audit note is recorded BEFORE `document_transform` commits
    /// (fail-closed, mirroring `redact_matter`). A doc whose accepted spans are ALL
    /// stale writes nothing (the transform is skipped) but is still reported +
    /// audited. Needs `matter.read:<class>` AND `document.transform`.
    pub fn apply_selection<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
        selection: &Selection,
    ) -> CoreResult<ApplyReport>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let mut report = ApplyReport::default();

        // Process classes in the engine's configured order, and within a class the
        // affected doc ids ASCENDING, so the apply (and its audit entries) are
        // deterministic regardless of HashSet iteration order.
        for &class in &self.classes {
            let mut doc_ids: Vec<u64> = selection
                .accepted
                .iter()
                .filter(|k| k.class == class)
                .map(|k| k.doc_id)
                .collect();
            doc_ids.sort_unstable();
            doc_ids.dedup();

            for doc_id in doc_ids {
                // The accepted (start, end) spans for THIS (doc, class).
                let accepted: std::collections::HashSet<(usize, usize)> = selection
                    .accepted
                    .iter()
                    .filter(|k| k.doc_id == doc_id && k.class == class)
                    .map(|k| (k.start, k.end))
                    .collect();

                // Read the current content (mediated + audited) and re-detect the
                // authoritative spans, so apply uses live offsets, not scan-time
                // ones. A non-granted class / missing doc fails here, fail-closed.
                let content = core.matter_read_text(doc_id, class)?;
                let spans = self.merged_spans(&content);
                let present: std::collections::HashSet<(usize, usize)> = spans
                    .iter()
                    .map(|m| (m.candidate.start, m.candidate.end))
                    .collect();

                // APPLIED = re-detected spans the selection accepted; STALE =
                // accepted spans no longer present (content changed since the scan).
                let applied_recognizers: Vec<&Recognizer> = spans
                    .iter()
                    .filter(|m| accepted.contains(&(m.candidate.start, m.candidate.end)))
                    .map(|m| &m.candidate.recognizer)
                    .collect();
                let applied = applied_recognizers.len();
                let stale = accepted.iter().filter(|k| !present.contains(k)).count();
                // LEVER 2: per-tier counts over the SAME applied spans (counts only).
                let applied_tiers = tier_breakdown_of(
                    spans
                        .iter()
                        .filter(|m| accepted.contains(&(m.candidate.start, m.candidate.end)))
                        .map(|m| m.candidate.confidence),
                );

                // Audit the apply BEFORE the transform (fail-closed). The note records
                // INTENT ("applying N") not a completed fact: the subsequent
                // document_transform may still be DENIED (e.g. no document.transform
                // grant) and `?`-abort, so an intent note correctly reflects an
                // attempt rather than overclaiming a commit that did not happen. The
                // core's own transform entries are the record of what actually landed.
                // Counts/labels only, never cleartext.
                core.audit_note(&format!(
                    "redaction apply: doc {} ({}) — applying {} span(s) [{}] {{{}}}, {} stale (skipped)",
                    doc_id,
                    class,
                    applied,
                    recognizer_breakdown_of(applied_recognizers),
                    applied_tiers,
                    stale,
                ))?;

                // Nothing live to write (all accepted spans were stale): skip the
                // transform so the audit shows no phantom rewrite, but still report.
                if applied > 0 {
                    let engine = self;
                    let accepted_for_closure = accepted;
                    core.document_transform(doc_id, class, |s| {
                        engine.redact_selected(s, &accepted_for_closure)
                    })?;
                }

                report.docs.push(DocApply {
                    doc_id,
                    class,
                    applied,
                    stale,
                });
            }
        }

        Ok(report)
    }

    /// PHASE 1 of the PDF (blob) workflow — SCAN every `Blob` document the engine is
    /// granted to read for in-PDF redaction candidates, WITHOUT writing anything.
    /// The byte-typed sibling of [`scan_matter`](RedactionEngine::scan_matter), over
    /// the binary content plane (`to-read/runtime.PDF-CORE-WIRING-PROPOSAL.md` §5).
    ///
    /// For each configured class: LIST via `matter_list_docs`, filter the listing to
    /// `Blob` docs by the [`runtime::DocRef`]'s content `kind` (a `Text` doc shares
    /// the class but is the text path's job — `scan_matter` — and is skipped HERE with
    /// NO blob read), then `matter_read_blob` each blob. A blob is run through
    /// [`redact_pdf`]: the candidates are KEPT (cleartext, for review), the redacted
    /// bytes DISCARDED (a scan writes nothing), and a SCAN is audited (candidate count
    /// + per-recognizer breakdown only — never a cleartext value).
    ///
    /// CAPABILITY REDUCTION (mirrors the text scan): no `document_transform_blob` is
    /// called, so this needs ONLY `matter.read:<class>` (NOT `document.transform`) — a
    /// PDF review pass literally cannot mutate a document, even by mistake.
    ///
    /// NO AUDIT NOISE: because the `Text` docs are filtered out by `DocRef.kind`
    /// BEFORE any blob read, a class holding many text docs and few PDFs emits ONE
    /// blob-read audit entry per PDF — never a value-free no-op read for each text doc.
    /// The kind check rides on the listing the core already returned (no raw
    /// out-of-band kind query), so it stays inside the chokepoint.
    ///
    /// A `redact_pdf` PARSE failure on one doc (malformed / encrypted / over-cap PDF)
    /// is fail-closed: it propagates as a `CoreResult` error (the scan does not
    /// silently skip an undecodable PDF as "clean"). A `low_text`/diagnostics PDF is
    /// surfaced on its [`PdfDocScan`], never read as clean.
    pub fn scan_matter_pdf<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
    ) -> CoreResult<PdfScanReport>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let mut report = PdfScanReport::default();
        for &class in &self.classes {
            // Entitlement: the core refuses a non-granted class here (default-deny).
            let docs = core.matter_list_docs(class)?;
            for doc in docs {
                // Content-kind filter INSIDE the chokepoint: only a Blob doc is a PDF
                // candidate. A Text doc of the same class is the text path's job
                // (`scan_matter`) and is skipped HERE with NO blob read, so it emits no
                // value-free blob-read audit no-op (the audit-noise fix).
                if doc.kind != ContentKind::Blob {
                    continue;
                }
                // Read the doc as BYTES through the core (mediated, entitlement +
                // content-kind filtered, audited). FAIL-CLOSED: with the kind filter
                // above, a Backend error here is a genuine failure (a doc that vanished
                // between list and read, or a fail-closed audit error), so it
                // PROPAGATES with `?` rather than being silently skipped as clean.
                let bytes = core.matter_read_blob(doc.id, class)?;
                // Detect over the PDF, KEEP the candidates, DISCARD the redacted
                // bytes (a scan writes nothing). A parse failure is fail-closed.
                let pdf = pdf::redact_pdf(&bytes, self)?;
                let parts = pdf.into_parts();
                // Audit the SCAN — candidate count + breakdown ONLY, never a cleartext
                // value, and NO write. Distinct wording ("scan pdf"/"candidate(s)")
                // from the apply/redact notes so the audit trail tells the phases apart.
                core.audit_note(&format!(
                    "redaction scan pdf: doc {} ({}) — {} candidate(s) [{}] {{{}}}{}",
                    doc.id,
                    class,
                    parts.candidates.len(),
                    recognizer_breakdown(&parts.candidates),
                    tier_breakdown(&parts.candidates),
                    if parts.low_text {
                        ", low-text (image-only/scanned?)"
                    } else {
                        ""
                    },
                ))?;
                report.docs.push(PdfDocScan {
                    doc_id: doc.id,
                    class,
                    candidates: parts.candidates,
                    low_text: parts.low_text,
                    diagnostics: parts.diagnostics,
                });
            }
        }
        Ok(report)
    }

    /// One-shot APPLY-ALL in-PDF redaction over every `Blob` document the engine is
    /// granted to read+transform. The byte-typed sibling of
    /// [`redact_matter`](RedactionEngine::redact_matter), over the binary content
    /// plane (`to-read/runtime.PDF-CORE-WIRING-PROPOSAL.md` §5).
    ///
    /// For each configured class: LIST, filter the listing to `Blob` docs by the
    /// [`runtime::DocRef`]'s content `kind` (a `Text` doc is the text path's job —
    /// `redact_matter` — and is skipped HERE with no blob read, so it emits no audit
    /// noise), then `matter_read_blob` each PDF blob. For each PDF blob: run
    /// [`redact_pdf`] ONCE, AUDIT-NOTE the count/breakdown BEFORE the write
    /// (fail-closed), then write the redacted bytes back via the mediated
    /// [`runtime::Core::document_transform_blob`].
    ///
    /// # v1 scope — apply-all + config-level review (proposal §5)
    ///
    /// There is NO per-span PDF `Selection`: a PDF candidate's offsets are
    /// per-content-stream reconstructed coordinates with no stable cross-call
    /// identity, so a v1 per-span selection would be fragile. The reviewer instead
    /// scans ([`scan_matter_pdf`](RedactionEngine::scan_matter_pdf)), adjusts the
    /// ENGINE CONFIG (disable a recognizer, add/remove terms/rules), re-scans, and
    /// runs THIS apply-all with that config when satisfied. (`PdfCandidateId`-based
    /// per-span selection is the documented v2 follow-on, not built here.)
    ///
    /// # Fail-closed ordering (mirrors `redact_matter`)
    ///
    /// The per-doc audit note is recorded BEFORE `document_transform_blob` commits —
    /// so a failed note ABORTS the redaction rather than leaving a PDF redacted with
    /// no count/breakdown in the audit chain.
    ///
    /// IMPORTANT — the redacted bytes are computed ONCE. [`redact_pdf`] runs a
    /// SINGLE pass above; its redacted bytes (`PdfRedactionParts::bytes`) are the
    /// authoritative output that the audit note's count describes. The closure handed
    /// to `document_transform_blob` (which requires an infallible `FnMut(&[u8]) ->
    /// Vec<u8>`) simply RETURNS those precomputed bytes — it does NOT re-parse or
    /// re-detect. So the bytes written are EXACTLY the audited redaction, by
    /// construction: there is no second `redact_pdf` call that could diverge from the
    /// first, and no write-unchanged-on-error fallback that could silently fail open.
    ///
    /// # Confidentiality split (UNCHANGED)
    ///
    /// The returned [`PdfRedactionReport`] carries the candidates INCLUDING cleartext
    /// for in-process review (the engine holds no egress; nothing leaves the box). The
    /// audit records ONLY counts/breakdown (`audit_note`) and byte lengths (the core's
    /// `document_transform_blob` entries), NEVER the bytes or a matched value.
    pub fn redact_matter_pdf<B, A, S, E, C, M>(
        &self,
        core: &mut runtime::Core<B, A, S, E, C, M>,
    ) -> CoreResult<PdfRedactionReport>
    where
        B: CapabilityBroker,
        A: Audit,
        S: Storage,
        E: Egress,
        C: MatterContext,
        M: MatterStore,
    {
        let mut report = PdfRedactionReport::default();
        for &class in &self.classes {
            // Entitlement: the core refuses a non-granted class here (default-deny).
            let docs = core.matter_list_docs(class)?;
            for doc in docs {
                // Content-kind filter INSIDE the chokepoint: the DocRef the core
                // already returned tells us whether this doc is text or bytes. Only a
                // Blob doc is a PDF candidate; a Text doc of the same class belongs to
                // the text path (`redact_matter`). Skipping it HERE (no blob read) means
                // a Text doc emits NO value-free blob-read audit no-op — the audit-noise
                // fix. (A Text + a Blob doc realistically coexist in one `document`
                // class; they must.)
                if doc.kind != ContentKind::Blob {
                    continue;
                }
                // Read as BYTES through the core (mediated, entitlement +
                // content-kind filtered, audited). FAIL-CLOSED: with the kind filter
                // above, a Backend error here is no longer "not a blob" — it is a
                // genuine failure (a doc that vanished between list and read, or a
                // fail-closed audit error), so it PROPAGATES with `?` rather than being
                // silently skipped as clean.
                let bytes = core.matter_read_blob(doc.id, class)?;
                // Detect + redact in a single pass. The candidates and the redacted
                // bytes come from the SAME pass, so the count, the candidate list, and
                // the bytes written all agree. A parse failure is fail-closed (`?`).
                let pdf = pdf::redact_pdf(&bytes, self)?;
                let parts = pdf.into_parts();
                let removed = parts.total_redactions;

                // FAIL-CLOSED (act-before-log, like redact_matter): record the COUNT +
                // per-recognizer BREAKDOWN (ungated audit.note) BEFORE committing the
                // strip, so a failed note ABORTS the write instead of leaving the PDF
                // redacted with no count/breakdown in the chain. CONFIDENTIALITY: count
                // + breakdown ONLY — never a `matched_value`, never the bytes.
                core.audit_note(&format!(
                    "redaction pdf: doc {} ({}) — {} redaction(s) applied [{}] {{{}}}{}",
                    doc.id,
                    class,
                    removed,
                    recognizer_breakdown(&parts.candidates),
                    tier_breakdown(&parts.candidates),
                    if parts.low_text {
                        ", low-text (image-only/scanned?)"
                    } else {
                        ""
                    },
                ))?;

                // Commit the redacted bytes THROUGH the core (mediated + logged; the
                // core's own blob-transform entries record the input/output byte
                // LENGTHS, never the bytes). The bytes were ALREADY computed by the
                // single `redact_pdf` pass above (`parts.bytes`) — the closure RETURNS
                // those precomputed bytes and never re-parses. By construction the
                // bytes written are EXACTLY the audited redaction: there is no second
                // parse that could diverge and no write-unchanged-on-error fallback to
                // silently fail open. The closure is invoked exactly once (one doc, one
                // transform), so `take()` is sound; a second invocation would panic
                // rather than write something unaudited (it cannot happen here).
                let mut redacted_bytes = Some(parts.bytes);
                core.document_transform_blob(doc.id, class, move |_| {
                    redacted_bytes
                        .take()
                        .expect("transform closure invoked exactly once")
                })?;

                report.docs.push(PdfDocRedaction {
                    doc_id: doc.id,
                    class,
                    identifiers_removed: removed,
                    candidates: parts.candidates,
                    low_text: parts.low_text,
                    diagnostics: parts.diagnostics,
                });
            }
        }
        Ok(report)
    }

    /// Splice ONLY the accepted merged spans (by `(start, end)`) into a redacted
    /// string, leaving every other span's original text untouched. The
    /// authoritative single pass ([`merged_spans`](RedactionEngine::merged_spans))
    /// supplies the spans + their resolved replacements, so a selected span writes
    /// its custom replacement (or the marker) exactly as a full redaction would; a
    /// non-selected span is left verbatim. PURE + DETERMINISTIC.
    fn redact_selected(
        &self,
        text: &str,
        accepted: &std::collections::HashSet<(usize, usize)>,
    ) -> String {
        let spans = self.merged_spans(text);
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for m in spans {
            if !accepted.contains(&(m.candidate.start, m.candidate.end)) {
                continue; // not selected -> the original text stays in place
            }
            out.push_str(&text[cursor..m.candidate.start]);
            match &m.replacement {
                Some(s) => out.push_str(s),
                None => out.push_str(REDACTION_MARKER),
            }
            cursor = m.candidate.end;
        }
        out.push_str(&text[cursor..]);
        out
    }
}
