// SPDX-License-Identifier: AGPL-3.0-or-later
//! Free helper functions shared by the engine / labels / packs: honorific and
//! name heuristics, char-boundary walkers, and the audit breakdown builders.
//! Extracted from `lib.rs`.

use std::collections::HashMap;

use regex::Regex;

use crate::*;

/// The courtesy/honorific TITLES the [`Recognizer::Name`] heuristic prefixes a name with
/// (the SAME set as the name-heuristic pattern in [`RedactionEngine::base`]). Used by
/// [`strip_honorific`] to recover the NAME PART of a detected `Mr Greco` span (`Greco`) for
/// the name-propagation pass. Kept in sync with the recognizer pattern by construction
/// (both list these exact tokens).
const HONORIFICS: &[&str] = &[
    "Mr",
    "Mrs",
    "Ms",
    "Mdm",
    "Miss",
    "Dr",
    "Prof",
    "Professor",
    "Justice",
    "Judge",
    "Hon",
    "Messrs",
];

/// Strip ONE leading honorific (and its trailing `.`) from a detected name string, returning
/// the NAME PART. `Mr Greco` → `Greco`, `Dr. Tan Wei Ming` → `Tan Wei Ming`. A string with no
/// recognized honorific (e.g. an aggressive-mode bare run) is returned UNCHANGED, so the SAFE
/// tier re-flags the whole run as-is. Only the FIRST whitespace-separated token is examined;
/// the comparison strips a trailing `.` so both `Mr` and `Mr.` match. Returns a borrowed slice
/// of the input (no allocation).
pub(crate) fn strip_honorific(name: &str) -> &str {
    let name = name.trim();
    // Split off the first token; if it (sans a trailing dot) is an honorific, return the rest.
    if let Some((first, rest)) = name.split_once(char::is_whitespace) {
        let head = first.strip_suffix('.').unwrap_or(first);
        if HONORIFICS.contains(&head) {
            return rest.trim_start();
        }
    }
    name
}

/// Is `tok` a NAME-LIKE token suitable to SEED the name-expansion tier — a Capitalized word
/// (uppercase first letter) of at least 2 chars. This excludes single initials (`J.`),
/// lowercase particles, and punctuation-only tokens, so a detected name token never pulls in
/// an unrelated capitalized run via a too-generic seed. Unicode-aware on the first char.
pub(crate) fn is_name_token(tok: &str) -> bool {
    let mut chars = tok.chars();
    match chars.next() {
        Some(c) if c.is_uppercase() => tok.chars().count() >= 2,
        _ => false,
    }
}

/// Build a short surrounding snippet for a matched span: up to [`CONTEXT_CHARS`]
/// characters before `start` and after `end`, clamped to char boundaries and the
/// doc edges. Cleartext (review-only).
pub(crate) fn context_snippet(text: &str, start: usize, end: usize) -> String {
    let lo = floor_char_boundary_back(text, start, CONTEXT_CHARS);
    let hi = ceil_char_boundary_fwd(text, end, CONTEXT_CHARS);
    text[lo..hi].to_string()
}

/// LEVER 2 — is this recognizer CHECKSUM-validated (rung 1 of the ladder): a Luhn card,
/// a mod-97 IBAN, or a mod-97-10 LEI. A checksum-valid match is precise on its own (a real
/// card/IBAN/LEI always passes; the checksum filters non-instances WITHOUT a miss), so it
/// is High regardless of context. Deliberately the CHECKSUM built-ins only — a
/// STRUCTURAL-only validator (the dashed-SSN range rules) is NOT a checksum and is
/// treated as a structurally-specific shape (rung 2), so the documented "dashed SSN near
/// 'SSN' => High, alone => Medium" holds. (A checksum-bearing locale/profile row — e.g. a
/// Luhn-based NPI — is conservatively rung-2 structural here: Medium alone, High near a
/// class keyword; raising it to rung 1 would mean per-row checksum-vs-structural metadata,
/// a deferred data-row addition. This never affects WHICH candidates fire — recall is
/// unchanged — only the annotation.)
pub(crate) fn is_checksum_validated(r: &Recognizer) -> bool {
    // The ISIN joins the checksum family (its check digit is the ISIN Luhn — a real ISIN
    // always passes, so a passing match is precise on its own). The BIC does NOT: it is
    // STRUCTURE-only (country table + SWIFT location rules, no checksum), so it stays out
    // of rung 1 (and out of rung 2 — see `is_structural`) → the CAREFUL review tier.
    matches!(
        r,
        Recognizer::CreditCard | Recognizer::Iban | Recognizer::Lei | Recognizer::Isin
    )
}

/// LEVER 2 — is this recognizer a STRUCTURALLY-SPECIFIC format (rung 2 of the ladder):
/// a shape precise enough to stand alone (an email, a dashed/spaced SSN, an NRIC, the
/// other national-ID locale rows), so it is High WITH a class keyword in-window and
/// Medium without? Email is the structural built-in; every LOCALE row is a
/// jurisdiction-specific national ID (structurally specific by construction). A PROFILE
/// bespoke row is likewise an explicit compliance-scoped shape. The broad built-ins
/// (phone/id/name/url/ip), a caller TERM, and a CUSTOM rule are NOT structural — they
/// fall to rung 4 (default Low, Medium on a keyword). (Checksum-validated kinds are
/// caught by rung 1 BEFORE this is consulted, so card/IBAN never reach here.)
pub(crate) fn is_structural(r: &Recognizer) -> bool {
    matches!(
        r,
        Recognizer::Email | Recognizer::Locale(_) | Recognizer::Profile(_)
    )
}

/// LEVER 2 — the CLASS keyword lexicon for a recognizer kind (rungs 2 & 4): OUR
/// constant per-kind keyword set whose in-window presence raises the rung. `None` = no
/// class lexicon for this kind (so its tier never rises off a class keyword). These are
/// constant labels, never document text, so consulting them is confidentiality-clean.
///
/// Kept deliberately SMALL + high-precision (a class keyword should genuinely
/// corroborate the kind): a stray match never inflates the tier.
pub(crate) fn class_lexicon(r: &Recognizer) -> Option<&'static [&'static str]> {
    match r {
        Recognizer::Email => Some(&["email", "e-mail", "mail", "contact"]),
        Recognizer::Phone => Some(&["phone", "tel", "telephone", "mobile", "cell", "fax", "call"]),
        Recognizer::Url => Some(&["url", "link", "website", "site", "http"]),
        // The broad `id` recognizer: a generic identifier keyword corroborates.
        Recognizer::Id => Some(&["id", "ref", "reference", "no", "number", "code"]),
        // The structure-only BIC: a BIC/SWIFT label corroborates (raises Low -> Medium;
        // it never reaches High — a BIC is neither checksum nor `is_structural`, the
        // deliberate careful-review pin). Small + high-precision.
        Recognizer::Bic => Some(&["bic", "swift"]),
        // The structured-address recognizer: an address/premises keyword corroborates
        // (raises Low -> Medium; it never reaches High — address is neither checksum nor
        // structural, so it stays in the CAREFUL review tier). Small + high-precision.
        Recognizer::Address => Some(&[
            "address",
            "located at",
            "registered office",
            "situated at",
            "residing at",
            "premises",
        ]),
        // A LOCALE national-ID row gets its class lexicon by row-name family (so a
        // dashed `us:ssn` near "SSN" is High; an `sg:nric` near "NRIC" is High). The
        // mapping is by the bare row name (the part after `<cc>:`); a family with no
        // entry falls to the structural Medium floor (still recall-complete).
        Recognizer::Locale(label) => locale_class_lexicon(label),
        // Name/IP/term/custom/profile: no generic class lexicon — they stay at their
        // structural floor (locale/profile = Medium) or rung-4 default unless a future
        // row adds a focused lexicon here.
        _ => None,
    }
}

/// LEVER 2 — the CLASS lexicon for a LOCALE national-ID recognizer, keyed by the bare
/// row name (the suffix after `<cc>:`). Covers the spec-named families (SSN, NRIC) so a
/// dashed SSN / an NRIC near its class keyword reaches High; other national IDs fall to
/// the structural Medium floor. Adding a family here is a one-line data edit.
pub(crate) fn locale_class_lexicon(label: &str) -> Option<&'static [&'static str]> {
    let row = label.rsplit(':').next().unwrap_or(label);
    match row {
        "ssn" => Some(&["ssn", "social security", "social security number"]),
        "nric" => Some(&["nric", "fin", "ic", "identity card"]),
        _ => None,
    }
}

/// Walk back from `from` over at most `chars` characters, returning a byte index
/// on a char boundary (`<= from`).
///
/// FIX #15: walk BACKWARDS from `from` one char boundary at a time with an
/// early-exit counter, so the cost is O(`chars`) (== `CONTEXT_CHARS`), NOT O(`from`).
/// `b` is decremented to each preceding char boundary; the loop stops the instant
/// it has stepped back `chars` chars (or reached the start). The RESULT is byte-
/// identical to the previous `text[..from].char_indices().rev().take(chars).last()`:
/// the start byte of the char that is `chars` positions before `from`, or 0 if
/// fewer than `chars` chars precede `from`. All arithmetic stays on char
/// boundaries (multibyte-safe — no mid-codepoint index).
pub(crate) fn floor_char_boundary_back(text: &str, from: usize, chars: usize) -> usize {
    let mut b = from;
    for _ in 0..chars {
        if b == 0 {
            break;
        }
        // Step back to the previous char boundary (at most 4 bytes for UTF-8).
        b -= 1;
        while b > 0 && !text.is_char_boundary(b) {
            b -= 1;
        }
    }
    b
}

/// Walk forward from `from` over at most `chars` characters, returning a byte
/// index on a char boundary (<= text.len()).
pub(crate) fn ceil_char_boundary_fwd(text: &str, from: usize, chars: usize) -> usize {
    match text[from..].char_indices().nth(chars) {
        Some((i, _)) => from + i,
        None => text.len(),
    }
}

/// Fail-closed guard for FIX 1: does this compiled regex match ONLY zero-width
/// text (so it would silently redact nothing — the zero-width guard in the merge
/// drops every match)?
///
/// `is_match("")` is the primary check: it catches a regex that matches the empty
/// string (`""`, `a*`, `(?:)`, `^`, `$`). It does NOT catch a word-boundary
/// anchor like `\b`/`\B` (a boundary cannot match in an empty string), so we add
/// a narrow supplement: probe a few single characters and reject if the regex
/// matches but the match is ZERO-WIDTH. A legitimate pattern either matches a
/// non-empty span (accepted) or does not match the tiny probe at all (accepted),
/// so this never false-rejects a real rule — including word-boundary-wrapped
/// patterns like `\bcat\b` and non-ASCII literals. Deterministic; no allocation
/// of matter data. (Probes are fixed ASCII/newline single chars.)
pub(crate) fn matches_zero_width_only(re: &Regex) -> bool {
    if re.is_match("") {
        return true;
    }
    // Single-char probes that expose word/non-word boundaries and line anchors.
    for probe in ["a", " ", "1", "_", ".", "\n"] {
        if let Some(m) = re.find(probe) {
            if m.start() == m.end() {
                // Matched, but zero-width => a fail-open recognizer (e.g. `\b`).
                return true;
            }
        }
    }
    false
}

/// A deterministic, cleartext-FREE per-recognizer breakdown for the audit note,
/// e.g. `term=1, email=1, locale:sg:nric=1, custom:party-name=2`. Counts +
/// recognizer LABELS only — never the matched values (a label is a config-supplied
/// recognizer name, not an identifier, so it is audit-safe).
///
/// FIX 2 (audit disambiguation): built-ins are emitted under their bare fixed
/// labels (`term`/`email`/`phone`/`id`/`name`); LOCALE recognizers under a
/// `locale:<label>` namespace (e.g. `locale:sg:nric`); CUSTOM recognizers under a
/// distinct `custom:<label>` namespace. So a custom recognizer labelled like a
/// built-in (e.g. `"email"`) reads as `custom:email=N`, NOT a second bare
/// `email=N`, and a locale entry can never collide with a custom one — the
/// breakdown stays INJECTIVE/unambiguous. Custom labels are validated at
/// [`UserRecognizer::compile`] to exclude the `=`/`,`/`[`/`]` delimiters and
/// control chars; locale labels are static + known-good (`<locale>:<name>`), so
/// every namespaced form is always parseable.
///
/// Order is deterministic: the built-ins first in their fixed order, then every
/// LOCALE label in sorted (lexicographic) order, then every CUSTOM label in sorted
/// order — so the audit string is stable regardless of the order recognizers were
/// configured or matched in.
///
/// FIX #13: a SINGLE-PASS `HashMap<RecognizerKey, usize>` fold — O(N) time,
/// O(R) space (R = distinct recognizers present) — instead of any per-variant
/// re-scan of the candidate list. The keys are then SORTED for a stable audit
/// string. Each candidate is counted under its PRIMARY [`recognizer`] only
/// (un-changed), so the emitted counts are byte-identical to before — the
/// per-span multi-label list (FIX #5) does NOT enter the breakdown.
pub(crate) fn recognizer_breakdown(candidates: &[RedactionCandidate]) -> String {
    recognizer_breakdown_of(candidates.iter().map(|c| &c.recognizer))
}

/// LEVER 2 — a deterministic, cleartext-FREE per-CONFIDENCE-TIER breakdown for the
/// audit note, e.g. `high=3 medium=1 low=0`. COUNTS ONLY — never a matched value, never
/// the surrounding cleartext, never which lexicon entry fired (a tier name is not an
/// identifier, so it is audit-safe). Always emits all three tiers in the fixed order
/// `high medium low` (zeros included) so the audit string is stable + parseable
/// regardless of which tiers are present. Mirrors [`recognizer_breakdown`]'s
/// counts-only confidentiality discipline.
pub(crate) fn tier_breakdown(candidates: &[RedactionCandidate]) -> String {
    tier_breakdown_of(candidates.iter().map(|c| c.confidence))
}

/// The tier breakdown over an iterator of [`Confidence`] tiers — the shared engine for
/// both the owned-candidate slice and the apply path's borrowed candidates. Identical
/// deterministic output (`high=H medium=M low=L`).
pub(crate) fn tier_breakdown_of(tiers: impl IntoIterator<Item = Confidence>) -> String {
    let (mut high, mut medium, mut low) = (0usize, 0usize, 0usize);
    for t in tiers {
        match t {
            Confidence::High => high += 1,
            Confidence::Medium => medium += 1,
            Confidence::Low => low += 1,
        }
    }
    format!(
        "{}={high} {}={medium} {}={low}",
        Confidence::High.label(),
        Confidence::Medium.label(),
        Confidence::Low.label(),
    )
}

/// The breakdown over an iterator of PRIMARY recognizers — the shared engine that
/// [`recognizer_breakdown`] (slice of owned candidates) and the apply path (a
/// filtered list of BORROWED candidates) both feed. Identical deterministic output.
pub(crate) fn recognizer_breakdown_of<'a>(
    recognizers: impl IntoIterator<Item = &'a Recognizer>,
) -> String {
    // Single pass: fold each PRIMARY recognizer into a count. The key (see
    // `RecognizerKey`) carries the deterministic sort order, so a later `sort`
    // reproduces "built-ins in fixed order, then customs lexicographically".
    let mut counts: HashMap<RecognizerKey<'_>, usize> = HashMap::new();
    for r in recognizers {
        *counts.entry(RecognizerKey::of(r)).or_insert(0) += 1;
    }

    if counts.is_empty() {
        return "none".to_string();
    }

    // Sort the keys for a STABLE audit string (`HashMap` order is non-deterministic).
    let mut entries: Vec<(RecognizerKey<'_>, usize)> = counts.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
        .into_iter()
        .map(|(key, n)| key.render(n))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A breakdown-bucket key with a deterministic total order: built-ins SORT before
/// locale entries before profile entries before customs
/// (`Builtin(_)` < `Locale(_)` < `Profile(_)` < `Custom(_)`, by the VARIANT ORDER
/// below, on which the derived `Ord` is lexicographic), built-ins by their FIXED
/// display order, and locale/profile/custom entries each lexicographically by label.
/// Used as the single-pass fold key in [`recognizer_breakdown`].
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
enum RecognizerKey<'a> {
    /// A built-in: `(fixed order index, fixed display label)`. The order index is
    /// the leading tuple element so `Ord` reproduces the historical fixed order.
    Builtin(u8, &'a str),
    /// A LOCALE recognizer keyed by its jurisdiction-namespaced label (audit-safe,
    /// e.g. `sg:nric`), emitted under the `locale:<label>` namespace. Declared
    /// BEFORE `Profile`/`Custom` so the derived `Ord` sorts locale buckets first.
    Locale(&'a str),
    /// A compliance-PROFILE bespoke recognizer keyed by its profile-namespaced label
    /// (audit-safe, e.g. `pci-dss-cardholder:account-ref`), emitted under the
    /// `profile:<label>` namespace. Declared AFTER `Locale`, BEFORE `Custom`.
    Profile(&'a str),
    /// A custom recognizer keyed by its config label (audit-safe), emitted under
    /// the `custom:<label>` namespace.
    Custom(&'a str),
    /// A Lever-2 CONTEXT-required recognizer keyed by its `ctx:`-namespaced label
    /// (audit-safe, e.g. `ctx:ssn-undashed`), emitted under the SAME `ctx:` form. The
    /// `Recognizer::Context` label already carries the `ctx:` prefix, so `render`
    /// emits it bare (it is already injective vs `locale:`/`profile:`/`custom:`).
    /// Declared LAST so the derived `Ord` sorts context buckets after every other axis.
    Context(&'a str),
}

impl<'a> RecognizerKey<'a> {
    /// The breakdown key for a recognizer. The `match` is EXHAUSTIVE over
    /// `Recognizer`, so adding a recognizer variant forces a new arm here at COMPILE
    /// time — a new recognizer can never be silently dropped from the audit breakdown.
    fn of(r: &'a Recognizer) -> Self {
        match r {
            Recognizer::Term => RecognizerKey::Builtin(0, "term"),
            Recognizer::Email => RecognizerKey::Builtin(1, "email"),
            Recognizer::Phone => RecognizerKey::Builtin(2, "phone"),
            Recognizer::Id => RecognizerKey::Builtin(3, "id"),
            Recognizer::Name => RecognizerKey::Builtin(4, "name"),
            // New built-ins keep ASCENDING fixed order indices AFTER the original
            // five, so the historical breakdown order (term, email, phone, id,
            // name, …) is preserved and existing audit-string tests are unchanged.
            // (NRIC was index 5 here when it was a built-in; it is now a LOCALE
            // recognizer, so 5 was free — the OPT-IN LEI takes it. It only ever appears
            // in a breakdown when the user enabled it, so the default (no-LEI) breakdown
            // string is unchanged byte-for-byte.)
            Recognizer::Lei => RecognizerKey::Builtin(5, "lei"),
            Recognizer::CreditCard => RecognizerKey::Builtin(6, "credit-card"),
            Recognizer::Iban => RecognizerKey::Builtin(7, "iban"),
            Recognizer::Ip => RecognizerKey::Builtin(8, "ip"),
            Recognizer::Url => RecognizerKey::Builtin(9, "url"),
            // The structured-ADDRESS built-in keeps the next ascending fixed index (10),
            // after the original nine, so the historical breakdown order is preserved and
            // an address bucket only appears when the recognizer actually fired.
            Recognizer::Address => RecognizerKey::Builtin(10, "address"),
            // BIC + ISIN take the next ascending fixed indices (11/12): they only appear
            // in a breakdown when they actually fired, so historical strings are stable.
            Recognizer::Bic => RecognizerKey::Builtin(11, "bic"),
            Recognizer::Isin => RecognizerKey::Builtin(12, "isin"),
            // Locale entries sort AFTER built-ins; profile entries after locale;
            // custom entries last (variant order above).
            Recognizer::Locale(label) => RecognizerKey::Locale(label),
            Recognizer::Profile(label) => RecognizerKey::Profile(label),
            Recognizer::Custom(name) => RecognizerKey::Custom(name),
            // The `ctx:` prefix is already part of the label, so the key carries it
            // verbatim and `render` emits it bare (already injective vs the others).
            Recognizer::Context(label) => RecognizerKey::Context(label),
        }
    }

    /// Render this bucket's `key=count` part. Built-ins are bare (`email=1`); locale,
    /// profile, and custom entries are namespaced (`locale:<label>=N` /
    /// `profile:<label>=N` / `custom:<label>=N`) so none can collide with a built-in
    /// tag nor with each other (custom labels exclude `=`/`,`/`[`/`]`/control chars
    /// validated at compile time; locale labels are static `<locale>:<name>`; profile
    /// labels are static `<profile>:<name>` — so every namespaced form is always
    /// parseable).
    fn render(&self, n: usize) -> String {
        match self {
            RecognizerKey::Builtin(_, label) => format!("{label}={n}"),
            RecognizerKey::Locale(label) => format!("locale:{label}={n}"),
            RecognizerKey::Profile(label) => format!("profile:{label}={n}"),
            RecognizerKey::Custom(label) => format!("custom:{label}={n}"),
            // The label already begins with `ctx:` (e.g. `ctx:ssn-undashed`), so emit
            // it bare — no extra prefix, already injective vs the other namespaces.
            RecognizerKey::Context(label) => format!("{label}={n}"),
        }
    }
}
