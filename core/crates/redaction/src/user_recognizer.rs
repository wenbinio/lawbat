// SPDX-License-Identifier: AGPL-3.0-or-later
//! Firm-supplied user recognizers (`MatchMode` / `UserRecognizer`) and their
//! compiled forms (`Compiled` / `CompiledSpec` / `CustomTag`), plus shared
//! word-boundary + merge helpers. Extracted from the former monolithic `lib.rs`.

use std::sync::Arc;

use regex::{Regex, RegexBuilder};
use runtime::{CoreError, CoreResult};

use crate::{matches_zero_width_only, Recognizer};

/// How a [`UserRecognizer`] pattern is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MatchMode {
    /// The pattern is a LITERAL string: it is `regex::escape`d before
    /// compilation, so metacharacters (`.`, `(`, `)`, `/`, …) match as ordinary
    /// text and can never be interpreted as a pattern (this is the safe default
    /// for a non-technical user typing a party name).
    Literal,
    /// The pattern is an ADVANCED raw regex, compiled as-is. Accepting arbitrary
    /// user regex is SAFE here because the `regex` crate is guaranteed
    /// linear-time in the input (no backreferences, no catastrophic
    /// backtracking) — there is no ReDoS. A malformed pattern fails to compile
    /// and is surfaced as a [`CoreError::Backend`] (never a panic).
    Regex,
}

/// A firm-defined recognizer — the "super find & replace" rule. Compiled to a
/// single [`Regex`] via [`UserRecognizer::compile`], honoring the options below.
///
/// The `label` is a recognizer NAME (e.g. `party-name`, `matter-no`), shown on
/// matching candidates and in the audit breakdown. It is config (a name), NOT a
/// matched value, so it is audit-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserRecognizer {
    /// The recognizer NAME (shown on candidates + in the audit breakdown).
    pub label: String,
    /// The pattern text — interpreted per [`UserRecognizer::mode`].
    pub pattern: String,
    /// Literal (escaped) vs. advanced (raw) regex interpretation.
    pub mode: MatchMode,
    /// Case-sensitive matching. Default `false` (case-insensitive, recall-first,
    /// matching the built-in term behavior) — see [`UserRecognizer::literal`].
    pub case_sensitive: bool,
    /// Anchor the body on word boundaries so it only matches as a whole word — e.g.
    /// `cat` matches `cat` but not `category`. **`Literal` mode ONLY** —
    /// [`UserRecognizer::compile`] REJECTS `whole_word` with `Regex` mode, because
    /// wrapping an arbitrary regex (one that may start/end with `\s`/`\W`) in
    /// `\b...\b` silently and confusingly alters the match. In `Regex` mode put an
    /// explicit `\b` in the pattern instead.
    ///
    /// FIX F1: a `\b` is anchored ONLY on an edge whose boundary char is a word
    /// char. A term that starts or ends with a NON-word char (e.g. `"(Pte Ltd)"`,
    /// `".NET"`) drops the vacuous `\b` on that punctuation edge — otherwise a
    /// `\b(?:\(Pte\ Ltd\))\b` would compile yet silently match NOTHING (the `\b`
    /// requires a word transition that a `(`/`)` edge can never make). The
    /// surviving anchors keep whole-word semantics on the term's real word-char
    /// edges; a term with no word-char edge at all matches as a plain literal.
    pub whole_word: bool,
    /// Optional find-AND-replace: `None` writes the default [`REDACTION_MARKER`]
    /// (`[REDACTED]`); `Some(s)` writes `s` for THIS recognizer's spans. On a merged
    /// overlap (FIX F7): if exactly ONE distinct custom replacement covers the union
    /// span it is preserved; if ≥2 DIFFERENT custom replacements collide (ambiguous)
    /// the default marker is used instead (see the overlap rule on
    /// [`RedactionEngine::candidates`]).
    pub replacement: Option<String>,
}

impl UserRecognizer {
    /// A case-insensitive LITERAL recognizer (the common "find this string"
    /// case): no whole-word constraint, default marker replacement.
    pub fn literal(label: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            pattern: pattern.into(),
            mode: MatchMode::Literal,
            case_sensitive: false,
            whole_word: false,
            replacement: None,
        }
    }

    /// Set the optional find-and-replace string (builder style).
    pub fn with_replacement(mut self, replacement: impl Into<String>) -> Self {
        self.replacement = Some(replacement.into());
        self
    }

    /// Require word boundaries around the match (builder style). Only valid for
    /// `Literal` mode — see the [`whole_word`](UserRecognizer::whole_word) field:
    /// [`compile`](UserRecognizer::compile) rejects it combined with `Regex` mode.
    pub fn whole_word(mut self) -> Self {
        self.whole_word = true;
        self
    }

    /// Make the match case-sensitive (builder style).
    pub fn case_sensitive(mut self) -> Self {
        self.case_sensitive = true;
        self
    }

    /// Compile this recognizer to a [`Regex`] honoring its options.
    ///
    /// - `Literal` mode `regex::escape`s the pattern; `Regex` mode uses it raw.
    /// - `whole_word` wraps the escaped LITERAL body in `\b(...)\b` — it is
    ///   rejected for `Regex` mode (see the field doc / the validation below).
    /// - `case_insensitive(!case_sensitive)` is applied via [`RegexBuilder`].
    ///
    /// FALLIBLE — returns [`CoreError::Backend`] (never a panic/unwrap) on: an
    /// invalid label; an over-long `replacement`; `whole_word` with `Regex` mode;
    /// a malformed `Regex` pattern (e.g. `"("`); or a pattern that can only match
    /// zero-width text. (The `regex` crate is linear-time in the input — no
    /// catastrophic backtracking, no ReDoS — which is why accepting arbitrary user
    /// patterns is safe.)
    pub fn compile(&self) -> CoreResult<Compiled> {
        // Produce the validated regex SOURCE + case flag (the dedup key) and the
        // audit-safe tag. The literal-empty guard is here (per-recognizer; a
        // whitespace-only literal escapes to a non-zero-width regex, so the
        // generic zero-width probe below would MISS it). The zero-width probe on
        // the COMPILED regex stays the responsibility of whoever compiles `source`.
        let spec = self.spec()?;
        let re = RegexBuilder::new(&spec.source)
            .case_insensitive(!spec.case_sensitive)
            .build()
            .map_err(|e| {
                // Surface the COMPILE error only (regex-engine message), never the
                // raw user pattern alongside matter context.
                CoreError::Backend(format!(
                    "user recognizer {:?}: invalid pattern: {e}",
                    self.label
                ))
            })?;

        // FIX 1 (HIGH — fail-open → FAIL-CLOSED): reject a recognizer that can
        // only ever match ZERO-WIDTH text. A zero-width regex (`""`, `a*`, `\b`,
        // `(?:)`, `^`, `$`) compiles fine but every match is dropped by the
        // zero-width guard in the merge — so the firm-defined rule silently redacts
        // NOTHING (a leaked identifier reported as 0). A redaction rule MUST be able
        // to match at least one character. Error names the label only.
        if matches_zero_width_only(&re) {
            return Err(CoreError::Backend(format!(
                "user recognizer {:?}: pattern matches no non-empty text (empty or zero-width)",
                self.label
            )));
        }

        Ok(Compiled {
            re,
            tags: vec![CustomTag {
                kind: spec.kind,
                replacement: spec.replacement,
            }],
        })
    }

    /// Validate this recognizer and produce its [`CompiledSpec`]: the regex SOURCE
    /// string + case flag (which together are the dedup key — two recognizers with
    /// the SAME source AND case flag compile to byte-identical regexes), the
    /// audit-safe `Custom` kind (an [`Arc<str>`] label), and the replacement.
    ///
    /// FALLIBLE for every reason [`compile`](UserRecognizer::compile) is, EXCEPT
    /// the zero-width-only check — that needs the compiled `Regex`, so the caller
    /// runs it once per UNIQUE source (it is a property of the source, identical
    /// across every recognizer that shares it). The per-recognizer empty/whitespace
    /// LITERAL guard, however, IS here: a whitespace-only literal escapes to a
    /// non-zero-width regex, so only this `trim()` check catches it.
    pub(crate) fn spec(&self) -> CoreResult<CompiledSpec> {
        // FIX 3 (label guardrail, fail-closed): a custom label is rendered into
        // the parseable audit breakdown (`custom:<label>=N`), shown on candidates,
        // and namespaced — so validate it here. Reject empty/whitespace, bound the
        // length, and forbid the breakdown delimiters (`=` `,` `[` `]`) and any
        // ASCII control char, so a label can never corrupt or be confused in the
        // audit breakdown string. BOTH brackets are forbidden: a stray `[` (e.g.
        // `"[party"` -> `custom:[party=1]`) would unbalance the `[…]`-wrapped
        // breakdown just as a stray `]` would. The error names the offending label only.
        const MAX_LABEL_LEN: usize = 64;
        if self.label.trim().is_empty() {
            return Err(CoreError::Backend(format!(
                "user recognizer {:?}: label must not be empty or whitespace",
                self.label
            )));
        }
        if self.label.chars().count() > MAX_LABEL_LEN {
            return Err(CoreError::Backend(format!(
                "user recognizer {:?}: label exceeds {MAX_LABEL_LEN} characters",
                self.label
            )));
        }
        if self
            .label
            .chars()
            .any(|c| matches!(c, '=' | ',' | '[' | ']') || c.is_ascii_control())
        {
            return Err(CoreError::Backend(format!(
                "user recognizer {:?}: label must not contain '=', ',', '[', ']' or control characters",
                self.label
            )));
        }

        // FIX 6 (LOW — bound the replacement): `label` is capped, but an
        // unbounded `replacement` is a memory-amplification footgun — a 10 MB
        // replacement times 1,000 matches is a 10 GB output allocation. Cap it
        // with the same discipline as the label (a replacement is a short marker,
        // never document-sized). The bound is generous (markers like
        // `[REDACTED — PARTY A]` fit easily) but kills the amplification.
        const MAX_REPLACEMENT_LEN: usize = 256;
        if let Some(r) = &self.replacement {
            if r.chars().count() > MAX_REPLACEMENT_LEN {
                return Err(CoreError::Backend(format!(
                    "user recognizer {:?}: replacement exceeds {MAX_REPLACEMENT_LEN} characters",
                    self.label
                )));
            }
        }

        // FIX (HIGH — whole_word + Regex silent miss): `whole_word` wraps the
        // body in `\b(?:…)\b`. For a LITERAL that is well-defined (the escaped
        // body is known text whose word/non-word edges are fixed). For a raw
        // Regex it is a FOOTGUN: if the pattern body starts or ends with a
        // non-word construct (`\s`, `\W`, punctuation, an alternation, …), the
        // adjacent `\b` silently changes — or outright defeats — the match, with
        // NO compile or runtime error. A firm writing `r"\s+confidential\s+"` with
        // `whole_word: true` gets a rule that matches inconsistently or not at all
        // (count 0, no redaction, no signal) = a silent confidentiality miss. So
        // `whole_word` is supported for `Literal` mode ONLY; a `Regex` author has
        // full power and must express boundaries with an explicit `\b` in the
        // pattern itself. Fail-closed: reject the combination rather than ship a
        // rule that appears to work but doesn't.
        if self.whole_word && matches!(self.mode, MatchMode::Regex) {
            return Err(CoreError::Backend(format!(
                "user recognizer {:?}: whole_word is only supported for Literal mode; \
                 for Regex mode put \\b word boundaries in the pattern itself",
                self.label
            )));
        }

        // FIX 1 (per-recognizer half): an empty/whitespace-only LITERAL escapes to
        // a regex that matches literal whitespace (non-zero-width), so the generic
        // zero-width probe would NOT catch it. Reject it here, fail-closed, before
        // it becomes a rule that "redacts" only spaces.
        if matches!(self.mode, MatchMode::Literal) && self.pattern.trim().is_empty() {
            return Err(CoreError::Backend(format!(
                "user recognizer {:?}: pattern matches no non-empty text (empty or zero-width)",
                self.label
            )));
        }

        let body = match self.mode {
            MatchMode::Literal => regex::escape(&self.pattern),
            MatchMode::Regex => self.pattern.clone(),
        };
        let source = if self.whole_word {
            // `whole_word` is Literal-mode ONLY (Regex + whole_word was rejected
            // above), so `self.pattern` is the raw literal text and we can inspect
            // its first/last char directly to decide which `\b` anchors are real.
            //
            // FIX F1 (CRITICAL — silent whole-word miss on punctuation edges): a
            // `\b` word-boundary anchor is only meaningful against a WORD char
            // (`\w`). When the term STARTS or ENDS with a NON-word char (e.g.
            // `"(Pte Ltd)"`, `".NET"`), the adjacent `\b` requires a word/non-word
            // transition that can never occur at that edge — so a naive
            // `\b(?:…)\b` compiles, passes the zero-width probe, and then silently
            // matches NOTHING (a leaked, un-redacted term reported as count 0). We
            // anchor a `\b` ONLY on an edge whose boundary char is a word char and
            // DROP the vacuous anchor on a non-word edge, so the term still matches
            // with whole-word semantics on its genuine word-char edges. A term with
            // NO word-char edge at all (e.g. `"(...)"`) gets no anchors and matches
            // as a plain literal — fail-OPEN to a redaction, never a silent miss.
            // `is_word_char` mirrors the `\w` notion the regex `\b` uses.
            let lead_word = self.pattern.chars().next().is_some_and(is_word_char);
            let trail_word = self.pattern.chars().next_back().is_some_and(is_word_char);
            match (lead_word, trail_word) {
                (true, true) => format!(r"\b(?:{body})\b"),
                (true, false) => format!(r"\b(?:{body})"),
                (false, true) => format!(r"(?:{body})\b"),
                (false, false) => body,
            }
        } else {
            body
        };

        Ok(CompiledSpec {
            source,
            case_sensitive: self.case_sensitive,
            kind: Recognizer::Custom(Arc::from(self.label.as_str())),
            replacement: self.replacement.clone(),
        })
    }
}

/// Is `c` a regex `\w` "word" character? Used to decide whether a `\b` anchor is
/// meaningful at a `whole_word` literal's edge (FIX F1): a `\b` is only meaningful
/// against a word char, so anchoring against a non-word edge char is vacuous and
/// would silently match nothing. Mirrors the `regex` crate's Unicode `\w` (any
/// alphanumeric letter/digit, Unicode-aware, plus the ASCII underscore).
pub(crate) fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

// The Luhn (card) + ISO 7064 mod-97 (IBAN) checksum validators — together with the
// generic reusable validators a jurisdiction pack composes — now live in
// `packs::validators` and are re-exported at the crate root ([`luhn_valid`] /
// [`iban_valid`] / [`mod10_valid`] / [`weighted_mod_n`] / [`digit_sum`]). They are
// attached to the global card/IBAN [`TaggedPattern`]s and to pack rows via the same
// `validate: Option<fn(&str) -> bool>` slot.

/// FIX F7 helper: record a span's resolved replacement into the merge
/// accumulator's set of DISTINCT custom replacements. `None` (the default marker)
/// is NOT a custom replacement and is ignored, so a built-in (or a custom rule
/// that opted for the default marker) never blocks a sibling's distinct
/// replacement. A `Some` is appended only if its exact string is not already
/// present, keeping the set deterministic and bounded by the number of DIFFERENT
/// custom replacements over the span. Exactly one distinct entry => that
/// replacement is preserved; ≥2 => the union is ambiguous and falls back to the
/// marker (see the finalization in `merged_spans`).
pub(crate) fn push_distinct_replacement(set: &mut Vec<String>, replacement: Option<String>) {
    if let Some(r) = replacement {
        if !set.iter().any(|existing| existing == &r) {
            set.push(r);
        }
    }
}

/// A validated, not-yet-compiled recognizer spec. `(source, case_sensitive)` is
/// the dedup key (FIX #5): two recognizers with the same pair compile to a
/// byte-identical regex, so the engine builder compiles ONE regex for the pair and
/// attaches every such recognizer's [`CustomTag`] to it.
pub(crate) struct CompiledSpec {
    pub(crate) source: String,
    pub(crate) case_sensitive: bool,
    pub(crate) kind: Recognizer,
    pub(crate) replacement: Option<String>,
}

/// One firm rule's audit-safe tag: the `Custom(Arc<str>)` recognizer it attributes
/// to, plus the replacement string to write for its spans.
pub(crate) struct CustomTag {
    pub(crate) kind: Recognizer,
    pub(crate) replacement: Option<String>,
}

/// A compiled user-recognizer pattern: ONE [`Regex`] plus EVERY firm rule's tag
/// that shares this exact compiled pattern (FIX #5 dedup). A single match of `re`
/// is attributed to ALL `tags`, so two same-pattern rules scan once and both
/// surface — no duplicate scanning, no silently-dropped label.
pub struct Compiled {
    pub(crate) re: Regex,
    pub(crate) tags: Vec<CustomTag>,
}
