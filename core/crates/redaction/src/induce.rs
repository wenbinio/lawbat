// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Induction — programming-by-example regex synthesis (rung 4 of the recognizer ladder).
//!
//! A non-technical user pastes a few EXAMPLES of an identifier shape
//! (`AB-1234`, `CD-5678`) and this module SYNTHESIZES a regex that matches that
//! shape. The output is a plain regex STRING wrapped in the EXISTING
//! [`UserRecognizer`](crate::UserRecognizer) `{ mode: MatchMode::Regex, .. }`,
//! which means the induced recognizer is **just another `Custom` recognizer** —
//! it inherits every fail-closed guard already in the crate:
//!
//! - it compiles through the SAME [`UserRecognizer::compile`](crate::UserRecognizer::compile)
//!   (zero-width rejection, label/replacement validation, `whole_word` rules);
//! - the `regex` crate is linear-time, so there is **NO ReDoS** risk from a
//!   synthesized pattern;
//! - attribution flows through the SAME [`Recognizer::Custom`](crate::Recognizer::Custom)
//!   variant — induction adds **no new `Recognizer` variant** and **no new built-in**.
//!
//! ## SECURITY-CRITICAL — this synthesizes the matchers that drive PII redaction.
//!
//! A synthesized pattern that **silently fails to match its own example** is a
//! direct under-redaction bug (a leak): the user demonstrated the shape, the tool
//! "accepted" it, but the live matcher never fires. So the load-bearing invariant
//! (enforced by tests) is:
//!
//! > **Every normalized (trimmed, de-duplicated) input example MUST be matched by
//! > the COMPILED induced regex, covering the whole example.**
//!
//! ## Confidentiality — the alternation fallback EMBEDS example cleartext.
//!
//! The [`Strategy::LiteralAlternation`] form `(?:exA|exB|…)` literally contains the
//! example strings (the user's identifiers) in its regex source. That source is a
//! recognizer CONFIG string, never a matched value — but it is sensitive, so:
//!
//! - it must **never** reach the audit (the audit logs the recognizer LABEL +
//!   counts only — verified by a test that scans/redacts with an induced recognizer
//!   and asserts no audit `detail` contains the pattern or the example value);
//! - the [`InducedPattern::strategy`] field is exposed precisely so a caller/UI can
//!   **warn before persisting** an alternation that embeds literal example text.
//!
//! ## What this is NOT (honest framing)
//!
//! - **NO ML.** This is a deterministic structural generalization over the example
//!   characters — no clock, no RNG, no network, no fs. `induce(x) == induce(x)`.
//! - **MEDIUM aggressiveness only** (see [`InductionOptions`]): exact character
//!   classes (`\d` / `[A-Z]` / `[a-z]` / `[A-Za-z]`), run lengths a `{min,max}`
//!   RANGE spanning exactly the observed examples (no extra slack), literal
//!   separators kept VERBATIM (`regex::escape`d). It never force-generalizes to a
//!   broad `.*`/`.+`. A Tight/Loose dial and negative/counter examples are
//!   documented-FUTURE (the user edits the emitted regex in v1).

use crate::{is_word_char, MatchMode, UserRecognizer};

/// Hard cap on the number of input examples. More than this is rejected
/// fail-closed: induction over a long paste is almost certainly a mistake (the
/// user wants a few representative shapes, not a column dump), and an alternation
/// fallback over many distinct strings produces an unwieldy regex.
const MAX_EXAMPLES: usize = 8;

/// Hard cap on the length (in `char`s) of any single example. A 200-char "example"
/// is not an identifier shape; rejecting it fail-closed bounds the synthesized
/// pattern's size and keeps the tokenizer's work linear and small.
const MAX_EXAMPLE_CHARS: usize = 200;

/// Which synthesis path produced an [`InducedPattern`]. Exposed so a caller/UI can
/// reason about the result — in particular, [`Strategy::LiteralAlternation`]
/// EMBEDS the example cleartext in the regex source, so a UI should WARN before
/// persisting one (see the module-level confidentiality note).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Strategy {
    /// Exactly one distinct example remained after normalization: the pattern is
    /// that example as a LITERAL (it round-trips as a literal — see
    /// [`InducedPattern::into_user_recognizer`], which may pick `MatchMode::Literal`).
    SingleLiteral,
    /// The examples shared a structure (same token count, same coarse category per
    /// position, identical literal separators): the pattern generalizes per token
    /// into character classes + `{min,max}` run lengths.
    Generalized,
    /// The examples did NOT share a structure: the pattern is a `(?:…|…)`
    /// alternation of the `regex::escape`d, de-duplicated examples (in input
    /// order). This form EMBEDS the example cleartext — see the confidentiality note.
    LiteralAlternation,
}

/// Options controlling induction. v1 has a single dial; the aggressiveness is
/// fixed at MEDIUM (exact classes, no extra run-length slack) — a Tight/Loose
/// knob and negative-example support are documented-FUTURE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InductionOptions {
    /// Word-boundary anchor the induced pattern. Default `true`. A `\b` is added
    /// ONLY at an edge whose adjacent emitted token is a word-character class
    /// (Digit / Upper / Lower / Alpha) — NEVER against a leading/trailing
    /// literal-punctuation token (that would change or defeat the match, the same
    /// hazard `whole_word` documents). For the alternation fallback a `\b` is added
    /// only when EVERY alternative begins AND ends with a word char.
    pub anchored: bool,
}

impl Default for InductionOptions {
    fn default() -> Self {
        Self { anchored: true }
    }
}

/// The result of induction: a synthesized regex STRING, the [`Strategy`] that
/// produced it, and whether word-boundary anchoring was actually applied.
///
/// The `regex` is meant to be wrapped in a [`UserRecognizer`] (use
/// [`into_user_recognizer`](InducedPattern::into_user_recognizer)) and compiled
/// through the EXISTING [`UserRecognizer::compile`](crate::UserRecognizer::compile),
/// inheriting every fail-closed guard. The CORRECTNESS INVARIANT (every input
/// example matches the compiled pattern) is the module's load-bearing property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InducedPattern {
    /// The synthesized regex source string.
    regex: String,
    /// Which path produced it.
    strategy: Strategy,
    /// Whether a `\b` anchor was actually applied (false even when requested if
    /// neither edge was eligible — see [`InductionOptions::anchored`]).
    anchored: bool,
}

impl InducedPattern {
    /// The synthesized regex source string.
    pub fn regex(&self) -> &str {
        &self.regex
    }

    /// Which synthesis path produced this pattern. Note
    /// [`Strategy::LiteralAlternation`] embeds example cleartext — see the
    /// module-level confidentiality note before persisting/displaying.
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// Whether a `\b` word-boundary anchor was actually applied.
    pub fn anchored(&self) -> bool {
        self.anchored
    }

    /// Wrap this induced pattern in a [`UserRecognizer`] with the given label,
    /// ready to compile through the EXISTING
    /// [`UserRecognizer::compile`](crate::UserRecognizer::compile).
    ///
    /// - [`Strategy::SingleLiteral`] is wrapped as `MatchMode::Literal` (so it
    ///   round-trips exactly as the single example, with no regex metacharacter
    ///   interpretation). Its `regex` field still holds the `regex::escape`d form
    ///   for inspection/display, but the recognizer carries the RAW example text as
    ///   a literal pattern so the literal escaping happens once, in `compile`.
    /// - [`Strategy::Generalized`] / [`Strategy::LiteralAlternation`] are wrapped as
    ///   `MatchMode::Regex` (the synthesized source IS a regex).
    ///
    /// `whole_word` is left OFF (anchoring is already baked into the `regex` source
    /// for the regex strategies; `whole_word` is a `Literal`-mode-only feature and
    /// the SingleLiteral round-trips fine without it). `case_sensitive` is left at
    /// the recognizer default (`false`, recall-first) — the caller can flip it.
    pub fn into_user_recognizer(self, label: impl Into<String>) -> UserRecognizer {
        match self.strategy {
            Strategy::SingleLiteral => UserRecognizer {
                label: label.into(),
                // Carry the RAW (un-escaped) example as the literal pattern; the
                // `self.regex` already holds the escaped display form. `compile`
                // re-escapes a literal, so handing it the raw text round-trips to
                // the exact example.
                pattern: self.single_literal_source(),
                mode: MatchMode::Literal,
                case_sensitive: false,
                whole_word: false,
                replacement: None,
            },
            Strategy::Generalized | Strategy::LiteralAlternation => UserRecognizer {
                label: label.into(),
                pattern: self.regex,
                mode: MatchMode::Regex,
                case_sensitive: false,
                whole_word: false,
                replacement: None,
            },
        }
    }

    /// For a [`Strategy::SingleLiteral`], recover the RAW example text from the
    /// stored `regex::escape`d source. (Un-escaping a `regex::escape` output is
    /// well-defined: every escaped metacharacter is a `\` followed by the literal
    /// char; nothing else is escaped.) Used only on the SingleLiteral path.
    fn single_literal_source(&self) -> String {
        unescape_regex_literal(&self.regex)
    }
}

/// Why induction refused to synthesize a pattern. Fail-closed: a refusal is
/// surfaced as a typed error, never a silently-bad pattern. Carries no cleartext
/// example value — only the structural reason and counts/limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InductionError {
    /// No examples were supplied (or all were dropped as empty/whitespace).
    NoExamples,
    /// More than [`MAX_EXAMPLES`] examples were supplied.
    TooManyExamples {
        /// How many were supplied.
        got: usize,
        /// The cap ([`MAX_EXAMPLES`]).
        max: usize,
    },
    /// An example was empty or whitespace-only after trimming.
    EmptyExample,
    /// An example exceeded [`MAX_EXAMPLE_CHARS`] characters after trimming.
    ExampleTooLong {
        /// The cap ([`MAX_EXAMPLE_CHARS`]).
        max: usize,
    },
}

impl std::fmt::Display for InductionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InductionError::NoExamples => f.write_str("induction: no examples supplied"),
            InductionError::TooManyExamples { got, max } => {
                write!(
                    f,
                    "induction: too many examples ({got}); the maximum is {max}"
                )
            }
            InductionError::EmptyExample => {
                f.write_str("induction: an example was empty or whitespace-only")
            }
            InductionError::ExampleTooLong { max } => {
                write!(f, "induction: an example exceeds {max} characters")
            }
        }
    }
}

impl std::error::Error for InductionError {}

/// Synthesize a regex from positive examples using the DEFAULT options
/// (word-boundary anchoring ON). See [`induce_with`].
pub fn induce<I, S>(examples: I) -> Result<InducedPattern, InductionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    induce_with(examples, InductionOptions::default())
}

/// Synthesize a regex from positive examples (programming-by-example).
///
/// DETERMINISTIC and PURE: `induce_with(x, o) == induce_with(x, o)`. No clock, no
/// RNG, no I/O. The output is meant to be wrapped in a [`UserRecognizer`] and
/// compiled through the existing [`UserRecognizer::compile`](crate::UserRecognizer::compile).
///
/// Algorithm (MEDIUM aggressiveness — see [`InductionOptions`]):
///
/// 1. **Normalize:** trim each example; FAIL-CLOSED on zero examples,
///    `> MAX_EXAMPLES`, any empty/whitespace example, or any example
///    `> MAX_EXAMPLE_CHARS`. De-duplicate (preserve first-seen order).
/// 2. **One distinct example** → [`Strategy::SingleLiteral`].
/// 3. **Tokenize** each example into maximal runs of coarse category Digit /
///    Letter / Other; record letter-run case + the exact Other literal text.
/// 4. **Align** (same token count, same category per position, identical Other
///    literals). If aligned → [`Strategy::Generalized`] (per-token class +
///    `{lo,hi}` run length). Else → [`Strategy::LiteralAlternation`] of the
///    escaped, de-duplicated examples.
/// 5. **Anchor** per [`InductionOptions::anchored`] (only on word-char edges).
pub fn induce_with<I, S>(
    examples: I,
    options: InductionOptions,
) -> Result<InducedPattern, InductionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    // --- Step 1: normalize (trim, validate, de-duplicate preserving order) ---
    let raw: Vec<String> = examples
        .into_iter()
        .map(|s| s.as_ref().trim().to_string())
        .collect();

    if raw.is_empty() {
        return Err(InductionError::NoExamples);
    }
    if raw.len() > MAX_EXAMPLES {
        return Err(InductionError::TooManyExamples {
            got: raw.len(),
            max: MAX_EXAMPLES,
        });
    }
    for ex in &raw {
        if ex.is_empty() {
            return Err(InductionError::EmptyExample);
        }
        if ex.chars().count() > MAX_EXAMPLE_CHARS {
            return Err(InductionError::ExampleTooLong {
                max: MAX_EXAMPLE_CHARS,
            });
        }
    }

    // De-duplicate, preserving first-seen order. Small N (<= MAX_EXAMPLES), so an
    // O(N^2) `contains` is fine and avoids needing Hash on the strings.
    let mut distinct: Vec<String> = Vec::with_capacity(raw.len());
    for ex in raw {
        if !distinct.iter().any(|e| e == &ex) {
            distinct.push(ex);
        }
    }

    // --- Step 2: a single distinct example → SingleLiteral ---
    if distinct.len() == 1 {
        let ex = &distinct[0];
        return Ok(InducedPattern {
            // Store the escaped form for display/inspection; the SingleLiteral path
            // round-trips through MatchMode::Literal in `into_user_recognizer`.
            regex: regex::escape(ex),
            strategy: Strategy::SingleLiteral,
            anchored: false,
        });
    }

    // --- Step 3: tokenize each distinct example ---
    let tokenized: Vec<Vec<Token>> = distinct.iter().map(|e| tokenize(e)).collect();

    // --- Step 4: align ---
    if let Some(generalized) = generalize_aligned(&tokenized) {
        let (regex, anchored) = assemble_generalized(&generalized, options.anchored);
        return Ok(InducedPattern {
            regex,
            strategy: Strategy::Generalized,
            anchored,
        });
    }

    // --- Step 5: no alignment → literal alternation fallback ---
    let (regex, anchored) = assemble_alternation(&distinct, options.anchored);
    Ok(InducedPattern {
        regex,
        strategy: Strategy::LiteralAlternation,
        anchored,
    })
}

// =====================================================================
// Tokenization
// =====================================================================

/// The coarse category of a maximal character run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    /// ASCII digits `0-9`.
    Digit,
    /// ASCII letters `A-Za-z`.
    Letter,
    /// Everything else (separators, punctuation, whitespace, non-ASCII).
    Other,
}

/// The case profile of a Letter run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LetterCase {
    AllUpper,
    AllLower,
    Mixed,
}

/// One maximal run within an example.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// A run of `len` ASCII digits.
    Digit { len: usize },
    /// A run of `len` ASCII letters with the given case profile.
    Letter { len: usize, case: LetterCase },
    /// A run of non-alphanumeric chars, kept VERBATIM (the exact text).
    Other { text: String },
}

impl Token {
    fn category(&self) -> Category {
        match self {
            Token::Digit { .. } => Category::Digit,
            Token::Letter { .. } => Category::Letter,
            Token::Other { .. } => Category::Other,
        }
    }
}

/// Classify a single `char` into its coarse [`Category`]. Only ASCII digits and
/// ASCII letters get the Digit/Letter generalization; everything else (including
/// non-ASCII letters/digits) is `Other`, kept verbatim. This keeps the emitted
/// classes EXACT (`\d` / `[A-Z]` / `[a-z]` / `[A-Za-z]` are all ASCII-only here,
/// matching what the user sees in their ASCII examples) and never mis-generalizes
/// a multibyte char into a broad class.
fn classify(c: char) -> Category {
    if c.is_ascii_digit() {
        Category::Digit
    } else if c.is_ascii_alphabetic() {
        Category::Letter
    } else {
        Category::Other
    }
}

/// Tokenize an example into maximal coarse-category runs. Letter runs record their
/// case; Other runs keep the exact verbatim text (so a multibyte separator is
/// preserved intact and never split mid-codepoint).
fn tokenize(example: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut chars = example.chars().peekable();

    while let Some(&c) = chars.peek() {
        let cat = classify(c);
        match cat {
            Category::Digit => {
                let mut len = 0;
                while matches!(chars.peek(), Some(&c) if classify(c) == Category::Digit) {
                    chars.next();
                    len += 1;
                }
                tokens.push(Token::Digit { len });
            }
            Category::Letter => {
                let mut len = 0;
                let mut any_upper = false;
                let mut any_lower = false;
                while matches!(chars.peek(), Some(&c) if classify(c) == Category::Letter) {
                    let ch = chars.next().unwrap();
                    if ch.is_ascii_uppercase() {
                        any_upper = true;
                    } else {
                        any_lower = true;
                    }
                    len += 1;
                }
                let case = match (any_upper, any_lower) {
                    (true, false) => LetterCase::AllUpper,
                    (false, true) => LetterCase::AllLower,
                    _ => LetterCase::Mixed,
                };
                tokens.push(Token::Letter { len, case });
            }
            Category::Other => {
                // Collect the maximal verbatim run of Other chars.
                let mut text = String::new();
                while matches!(chars.peek(), Some(&c) if classify(c) == Category::Other) {
                    text.push(chars.next().unwrap());
                }
                tokens.push(Token::Other { text });
            }
        }
    }

    tokens
}

// =====================================================================
// Generalization (aligned path)
// =====================================================================

/// A generalized token position: the synthesized class spanning every example's
/// run at that position, with a `[lo, hi]` run-length range (lo==hi for an Other
/// literal, which is identical across aligned examples).
#[derive(Debug, Clone, PartialEq, Eq)]
enum GenToken {
    /// `\d{lo,hi}` (or `\d{lo}` if lo==hi).
    Digit { lo: usize, hi: usize },
    /// A letter class (`[A-Z]` / `[a-z]` / `[A-Za-z]`) with `{lo,hi}`.
    Letter {
        lo: usize,
        hi: usize,
        case: LetterCase,
    },
    /// The exact (identical-across-examples) literal separator text, kept verbatim.
    Other { text: String },
}

impl GenToken {
    /// Does this generalized token emit a regex that BEGINS with a word char (so a
    /// leading `\b` is meaningful)? Digit / Letter classes do; an Other literal
    /// does iff its first char is a word char.
    fn starts_word(&self) -> bool {
        match self {
            GenToken::Digit { .. } | GenToken::Letter { .. } => true,
            GenToken::Other { text } => text.chars().next().is_some_and(is_word_char),
        }
    }

    /// Does this generalized token emit a regex that ENDS with a word char (so a
    /// trailing `\b` is meaningful)?
    fn ends_word(&self) -> bool {
        match self {
            GenToken::Digit { .. } | GenToken::Letter { .. } => true,
            GenToken::Other { text } => text.chars().next_back().is_some_and(is_word_char),
        }
    }

    /// Render this generalized token to its regex fragment.
    fn render(&self) -> String {
        match self {
            GenToken::Digit { lo, hi } => format!(r"\d{}", quantifier(*lo, *hi)),
            GenToken::Letter { lo, hi, case } => {
                let class = match case {
                    LetterCase::AllUpper => "[A-Z]",
                    LetterCase::AllLower => "[a-z]",
                    LetterCase::Mixed => "[A-Za-z]",
                };
                format!("{class}{}", quantifier(*lo, *hi))
            }
            GenToken::Other { text } => regex::escape(text),
        }
    }
}

/// Render a `{lo,hi}` quantifier, collapsing to `{n}` when lo==hi.
fn quantifier(lo: usize, hi: usize) -> String {
    if lo == hi {
        format!("{{{lo}}}")
    } else {
        format!("{{{lo},{hi}}}")
    }
}

/// Attempt to align + generalize the tokenized examples. Returns `Some(gen)` iff
/// every example has the SAME token count AND, at every position, the SAME coarse
/// category AND (for Other tokens) IDENTICAL literal text. Otherwise `None` (the
/// caller falls back to alternation).
fn generalize_aligned(tokenized: &[Vec<Token>]) -> Option<Vec<GenToken>> {
    let first = tokenized.first()?;
    let n = first.len();

    // Same token count across all examples.
    if tokenized.iter().any(|t| t.len() != n) {
        return None;
    }

    let mut gen: Vec<GenToken> = Vec::with_capacity(n);

    for pos in 0..n {
        let cat = first[pos].category();
        // Same coarse category at this position across every example.
        if tokenized.iter().any(|t| t[pos].category() != cat) {
            return None;
        }

        match cat {
            Category::Digit => {
                let mut lo = usize::MAX;
                let mut hi = 0usize;
                for t in tokenized {
                    if let Token::Digit { len } = t[pos] {
                        lo = lo.min(len);
                        hi = hi.max(len);
                    }
                }
                gen.push(GenToken::Digit { lo, hi });
            }
            Category::Letter => {
                let mut lo = usize::MAX;
                let mut hi = 0usize;
                let mut any_upper = false;
                let mut any_lower = false;
                for t in tokenized {
                    if let Token::Letter { len, case } = &t[pos] {
                        lo = lo.min(*len);
                        hi = hi.max(*len);
                        match case {
                            LetterCase::AllUpper => any_upper = true,
                            LetterCase::AllLower => any_lower = true,
                            LetterCase::Mixed => {
                                any_upper = true;
                                any_lower = true;
                            }
                        }
                    }
                }
                // Class = [A-Z] if EVERY run is upper, [a-z] if EVERY run is lower,
                // else [A-Za-z]. "any_upper && any_lower" => mixed across the set.
                let case = match (any_upper, any_lower) {
                    (true, false) => LetterCase::AllUpper,
                    (false, true) => LetterCase::AllLower,
                    _ => LetterCase::Mixed,
                };
                gen.push(GenToken::Letter { lo, hi, case });
            }
            Category::Other => {
                // Other tokens must be IDENTICAL across examples to align.
                let text = match &first[pos] {
                    Token::Other { text } => text.clone(),
                    _ => unreachable!("category checked Other above"),
                };
                for t in tokenized {
                    match &t[pos] {
                        Token::Other { text: other } if *other == text => {}
                        _ => return None, // differing literal separator -> not aligned
                    }
                }
                gen.push(GenToken::Other { text });
            }
        }
    }

    Some(gen)
}

/// Concatenate the rendered generalized tokens and apply word-boundary anchoring
/// per the edge rule. Returns `(regex, anchored)` where `anchored` reflects
/// whether ANY `\b` was actually emitted.
fn assemble_generalized(gen: &[GenToken], want_anchor: bool) -> (String, bool) {
    let body: String = gen.iter().map(GenToken::render).collect();

    if !want_anchor || gen.is_empty() {
        return (body, false);
    }

    // A `\b` is added at an edge ONLY when the adjacent emitted token starts/ends
    // with a word char (never against a leading/trailing literal-punctuation
    // token). The two edges are decided independently.
    let lead = gen.first().is_some_and(GenToken::starts_word);
    let trail = gen.last().is_some_and(GenToken::ends_word);

    let mut out = String::new();
    if lead {
        out.push_str(r"\b");
    }
    out.push_str(&body);
    if trail {
        out.push_str(r"\b");
    }
    (out, lead || trail)
}

// =====================================================================
// Alternation fallback (no alignment)
// =====================================================================

/// Build the `(?:escA|escB|…)` literal-alternation fallback over the de-duplicated
/// examples (already distinct, in input order). Each alternative is `regex::escape`d.
///
/// Branch ORDER — LONGEST-FIRST (load-bearing for the correctness invariant). The
/// `regex` crate's unanchored `find()` is leftmost-**first**: among branches that
/// match at the leftmost start position it returns the FIRST LISTED, not the longest.
/// So if one branch is a PREFIX of another and is listed first, the longer example is
/// matched only by its prefix and the tail leaks (e.g. `(?:INV|INV\-1001)` matches just
/// `INV` in `"INV-1001"`). A proper prefix is always strictly shorter, so emitting
/// branches longest-first makes the longer branch win at a shared start — closing the
/// silent under-match. The sort is STABLE on descending char length, so equal-length
/// branches (which can never be a prefix pair) keep first-seen order for determinism.
///
/// Anchoring (simplest correct choice): the alternation is left FULLY UNANCHORED in
/// v1 — `anchored` is always `false` here regardless of [`InductionOptions::anchored`].
/// Rationale: an outer `\b…\b` distributes across EVERY branch, so a single branch
/// with a non-word edge would have its match silently broken by the boundary; and
/// the alternatives in a fallback (by construction, the examples did NOT share a
/// structure) commonly have heterogeneous edges. Unanchored is always CORRECT — it
/// merely matches more loosely at token boundaries, never a silent miss — so the
/// no-alignment fallback never risks a broken `\b`. (A future Tight dial could opt
/// an all-word-edged set into `\b(?:…)\b`; deferred — see `to-read/redaction.INDUCTION-SPEC.md`.)
fn assemble_alternation(distinct: &[String], _want_anchor: bool) -> (String, bool) {
    let mut ordered: Vec<&String> = distinct.iter().collect();
    // Stable sort, longest char length first; ties keep first-seen order.
    ordered.sort_by_key(|s| std::cmp::Reverse(s.chars().count()));
    let alts: Vec<String> = ordered.iter().map(|e| regex::escape(e)).collect();
    (format!("(?:{})", alts.join("|")), false)
}

// =====================================================================
// Regex-literal un-escape (SingleLiteral round-trip helper)
// =====================================================================

/// Recover the raw text from a `regex::escape`d string. `regex::escape` only ever
/// inserts a single `\` before an ASCII-punctuation metacharacter and escapes
/// nothing else, so un-escaping is "drop a `\` that precedes any char, keep that
/// char". Deterministic and total.
fn unescape_regex_literal(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            } else {
                // A trailing lone backslash cannot be produced by `regex::escape`
                // (it would have been escaped to `\\`), but keep it rather than
                // drop a char, for totality.
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

// =====================================================================
// RecognizerLibrary — the in-engine "saved + named" recognizer collection.
// =====================================================================

/// A named, in-memory collection of firm [`UserRecognizer`] specs — the "saved +
/// named" persistence SEAM.
///
/// This crate has NO filesystem access (by design — the redaction module holds no
/// fs capability): actual disk persistence is the HOST/shell's job. The optional
/// `serde` feature (OFF by default) makes this library + [`UserRecognizer`] +
/// [`MatchMode`] serialize to/from the WIRE FORM the host reads/writes; the core
/// logic works WITHOUT serde. So the flow is: a UI/host builds + induces
/// recognizers, adds them here by name, (optionally) serializes the library to
/// disk via serde, and reloads it next session.
///
/// Names are unique: [`add`](RecognizerLibrary::add) replaces by name (last wins).
/// [`list`](RecognizerLibrary::list) returns entries in a DETERMINISTIC
/// (name-sorted) order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecognizerLibrary {
    /// (name, spec) pairs. Kept sorted by name for deterministic `list` order and
    /// O(log n) lookup; uniqueness is enforced on `add`. A `Vec` (not a `BTreeMap`)
    /// keeps the serde wire form a simple ordered array.
    entries: Vec<NamedRecognizer>,
}

/// One named entry in a [`RecognizerLibrary`]: a unique `name` + its
/// [`UserRecognizer`] spec.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NamedRecognizer {
    /// The unique name this recognizer is saved under.
    pub name: String,
    /// The recognizer spec.
    pub recognizer: UserRecognizer,
}

impl RecognizerLibrary {
    /// An empty library.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or REPLACE-by-name, last wins) a named recognizer. Keeps the internal
    /// list sorted by name so [`list`](RecognizerLibrary::list) is deterministic.
    pub fn add(&mut self, name: impl Into<String>, recognizer: UserRecognizer) {
        let name = name.into();
        match self.entries.binary_search_by(|e| e.name.cmp(&name)) {
            Ok(i) => self.entries[i].recognizer = recognizer, // replace, last wins
            Err(i) => self.entries.insert(i, NamedRecognizer { name, recognizer }),
        }
    }

    /// Remove the recognizer saved under `name`. Returns the removed spec, or
    /// `None` if no such name was present.
    pub fn remove(&mut self, name: &str) -> Option<UserRecognizer> {
        match self.entries.binary_search_by(|e| e.name.as_str().cmp(name)) {
            Ok(i) => Some(self.entries.remove(i).recognizer),
            Err(_) => None,
        }
    }

    /// Borrow the recognizer saved under `name`, if present.
    pub fn get(&self, name: &str) -> Option<&UserRecognizer> {
        match self.entries.binary_search_by(|e| e.name.as_str().cmp(name)) {
            Ok(i) => Some(&self.entries[i].recognizer),
            Err(_) => None,
        }
    }

    /// All saved recognizers in DETERMINISTIC (name-sorted) order.
    pub fn list(&self) -> &[NamedRecognizer] {
        &self.entries
    }

    /// How many recognizers are saved.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the library is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Validate EVERY saved recognizer by compiling it through the real
    /// [`UserRecognizer::compile`](crate::UserRecognizer::compile). FAIL-CLOSED:
    /// returns the FIRST compile error (a [`runtime::CoreError`]); `Ok(())` only
    /// when every entry compiles. A host should call this before relying on a
    /// loaded library so a corrupt/edited wire form is rejected up front, never at
    /// scan time.
    pub fn validate_all(&self) -> runtime::CoreResult<()> {
        for entry in &self.entries {
            entry.recognizer.compile()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // The CORRECTNESS INVARIANT helper: every input example MUST be matched
    // (whole-span) by the COMPILED induced pattern, through the REAL compile path.
    // -----------------------------------------------------------------

    /// Induce over `examples`, compile the result through the REAL
    /// `UserRecognizer::compile`, and assert every NORMALIZED (trimmed, de-duped)
    /// example is matched covering the WHOLE example. Returns the induced pattern.
    fn assert_invariant(examples: &[&str]) -> InducedPattern {
        let induced = induce(examples.iter().copied()).expect("induction should succeed");
        let rec = induced.clone().into_user_recognizer("test-induced");
        let compiled = rec.compile().expect("induced pattern must compile");

        for ex in examples {
            let normalized = ex.trim();
            // `Compiled.re` is the crate-private compiled `Regex`; accessible here
            // because this test module is inside the crate.
            let m = compiled.re.find(normalized).unwrap_or_else(|| {
                panic!(
                    "induced regex {:?} did not match example {normalized:?}",
                    induced.regex()
                )
            });
            assert_eq!(
                &normalized[m.start()..m.end()],
                normalized,
                "induced regex {:?} must match the WHOLE example {normalized:?}, matched {:?}",
                induced.regex(),
                &normalized[m.start()..m.end()],
            );
        }
        induced
    }

    // -----------------------------------------------------------------
    // Structural (Generalized) path — the documented golden cases.
    // -----------------------------------------------------------------

    #[test]
    fn generalized_fixed_length() {
        let induced = induce(["AB-1234", "CD-5678"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::Generalized);
        // `regex::escape` escapes `-` to `\-` (both match a literal hyphen); the
        // separator is kept VERBATIM and escaped, per the MEDIUM spec.
        assert_eq!(induced.regex(), r"\b[A-Z]{2}\-\d{4}\b");
        assert!(induced.anchored());
        assert_invariant(&["AB-1234", "CD-5678"]);
    }

    #[test]
    fn generalized_varying_length_emits_range() {
        let induced = induce(["AB-123", "CDE-45678"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::Generalized);
        assert_eq!(induced.regex(), r"\b[A-Z]{2,3}\-\d{3,5}\b");
        assert_invariant(&["AB-123", "CDE-45678"]);
    }

    #[test]
    fn generalized_mixed_case_letters_widen_to_alpha() {
        // Upper in one, lower in another, mixed in a third → [A-Za-z].
        let induced = induce(["AB12", "cd34", "Ef56"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::Generalized);
        assert_eq!(induced.regex(), r"\b[A-Za-z]{2}\d{2}\b");
        assert_invariant(&["AB12", "cd34", "Ef56"]);
    }

    #[test]
    fn generalized_all_lower() {
        let induced = induce(["ab-12", "cd-34"]).unwrap();
        assert_eq!(induced.regex(), r"\b[a-z]{2}\-\d{2}\b");
        assert_invariant(&["ab-12", "cd-34"]);
    }

    #[test]
    fn generalized_literal_separators_are_escaped() {
        // `.` `/` `(` `)` are regex metacharacters — they must be escaped so they
        // match literally, not as "any char" / a group.
        let induced = induce(["A.1/2(3)", "B.4/5(6)"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::Generalized);
        // Leading letter (word edge → `\b`); `.`/`(`/`)` escaped, `/` left as-is
        // (not a metachar); trailing `)` is a punct edge → NO trailing `\b`.
        assert_eq!(induced.regex(), r"\b[A-Z]{1}\.\d{1}/\d{1}\(\d{1}\)");
        assert_invariant(&["A.1/2(3)", "B.4/5(6)"]);
        // Cross-check the escaping is REAL: the dot must NOT match an arbitrary char.
        let rec = induced.into_user_recognizer("x");
        let compiled = rec.compile().unwrap();
        assert!(
            compiled.re.find("AX1/2(3)").is_none(),
            "the escaped '.' must be literal, not any-char"
        );
    }

    #[test]
    fn generalized_single_run_collapses_to_brace_n() {
        let induced = induce(["X-12", "Y-34"]).unwrap();
        // Letter run len 1 → {1}; digit run len 2 → {2}; lo==hi collapses to {n}.
        assert_eq!(induced.regex(), r"\b[A-Z]{1}\-\d{2}\b");
        assert_invariant(&["X-12", "Y-34"]);
    }

    // -----------------------------------------------------------------
    // Alternation (no-alignment) path.
    // -----------------------------------------------------------------

    #[test]
    fn structural_mismatch_falls_back_to_alternation() {
        // Different token counts/categories → no alignment.
        let induced = induce(["AB-12", "9999"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::LiteralAlternation);
        // Each alternative is `regex::escape`d (`-` → `\-`); the no-alignment
        // fallback is always UNANCHORED in v1 (no risk of a `\b` distributing a
        // broken boundary across a branch). This is the documented golden case.
        assert_eq!(induced.regex(), r"(?:AB\-12|9999)");
        assert!(!induced.anchored());
        assert_invariant(&["AB-12", "9999"]);
    }

    #[test]
    fn alternation_is_always_unanchored_in_v1() {
        // Even when every alternative is word-edged, the fallback stays UNANCHORED
        // (the conservative, always-correct v1 choice — see the doc on
        // `assemble_alternation`). "AB12" vs "9999X": differing category sequence.
        // Branches are emitted LONGEST-FIRST, so "9999X" (5) precedes "AB12" (4).
        let induced = induce(["AB12", "9999X"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::LiteralAlternation);
        assert_eq!(induced.regex(), r"(?:9999X|AB12)");
        assert!(!induced.anchored());
        assert_invariant(&["AB12", "9999X"]);
    }

    #[test]
    fn alternation_prefix_collision_is_not_under_matched() {
        // REGRESSION (adversarial review, Critical): the `regex` crate's unanchored
        // alternation is leftmost-FIRST, so a branch that is a PREFIX of another, if
        // listed first, would match only the prefix and leak the tail. Emitting
        // branches longest-first fixes it: "INV-1001" (8) precedes "INV" (3).
        let induced = induce(["INV", "INV-1001"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::LiteralAlternation);
        assert_eq!(induced.regex(), r"(?:INV\-1001|INV)");
        // The invariant: BOTH examples — incl. the longer one that contains the
        // shorter as a prefix — are matched WHOLE-span by the compiled pattern.
        assert_invariant(&["INV", "INV-1001"]);
        // And the standalone shorter example still matches on its own.
        assert_invariant(&["INV-1001", "INV"]);
    }

    #[test]
    fn alternation_chained_prefixes_all_match_whole() {
        // Three branches with nested prefix relations: longest-first orders them
        // ABCD > ABC > AB, so each example matches whole-span regardless of input order.
        assert_invariant(&["AB", "ABCD", "ABC"]);
        assert_invariant(&["A", "A.B"]);
        assert_invariant(&["AB-12", "AB-12-XY"]);
    }

    #[test]
    fn alternation_with_a_punct_edge_alt_is_unanchored() {
        // A punctuation-edged alternative is exactly why alternation stays
        // unanchored — a distributed `\b` would break this branch.
        let induced = induce(["(redacted)", "1234"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::LiteralAlternation);
        assert_eq!(induced.regex(), r"(?:\(redacted\)|1234)");
        assert!(!induced.anchored());
        assert_invariant(&["(redacted)", "1234"]);
    }

    // -----------------------------------------------------------------
    // SingleLiteral path.
    // -----------------------------------------------------------------

    #[test]
    fn single_example_is_single_literal() {
        let induced = induce(["Acme-Corp.Ltd"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::SingleLiteral);
        assert_invariant(&["Acme-Corp.Ltd"]);
        // It round-trips as a LITERAL recognizer.
        let rec = induced.into_user_recognizer("co");
        assert_eq!(rec.mode, MatchMode::Literal);
        assert_eq!(rec.pattern, "Acme-Corp.Ltd");
    }

    #[test]
    fn dedup_collapses_to_single_literal() {
        // Two identical examples de-dup to one → SingleLiteral.
        let induced = induce(["SAME", "SAME"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::SingleLiteral);
        assert_invariant(&["SAME", "SAME"]);
    }

    #[test]
    fn dedup_preserves_first_seen_order_in_alternation() {
        // Distinct after de-dup; order preserved.
        let induced = induce(["ZZ-1", "9", "ZZ-1", "8"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::LiteralAlternation);
        // "9" before "8" (first-seen order), ZZ-1 once; `-` escaped; unanchored.
        assert_eq!(induced.regex(), r"(?:ZZ\-1|9|8)");
    }

    // -----------------------------------------------------------------
    // Anchoring edge rule — never a broken `\b` against punctuation.
    // -----------------------------------------------------------------

    #[test]
    fn leading_punctuation_drops_the_leading_boundary() {
        // Examples start with '(' (a non-word char): no leading `\b`, trailing yes.
        let induced = induce(["(12)", "(34)"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::Generalized);
        // '(' and ')' are punctuation edges → NO `\b` on either edge.
        assert_eq!(induced.regex(), r"\(\d{2}\)");
        assert!(!induced.anchored());
        assert_invariant(&["(12)", "(34)"]);
    }

    #[test]
    fn trailing_word_edge_keeps_only_trailing_boundary() {
        // Starts with punctuation, ends with a word char → only trailing `\b`.
        let induced = induce(["-A1", "-B2"]).unwrap();
        assert_eq!(induced.strategy(), Strategy::Generalized);
        // Leading '-' is a punct edge (no `\b`); trailing digit is a word edge (`\b`).
        assert_eq!(induced.regex(), r"\-[A-Z]{1}\d{1}\b");
        assert!(induced.anchored());
        assert_invariant(&["-A1", "-B2"]);
    }

    #[test]
    fn anchoring_off_emits_no_boundary() {
        let induced = induce_with(["AB-1", "CD-2"], InductionOptions { anchored: false }).unwrap();
        assert_eq!(induced.regex(), r"[A-Z]{2}\-\d{1}");
        assert!(!induced.anchored());
        assert_invariant(&["AB-1", "CD-2"]);
    }

    // -----------------------------------------------------------------
    // Multibyte / punctuation-heavy correctness invariant.
    // -----------------------------------------------------------------

    #[test]
    fn multibyte_separator_is_kept_verbatim_and_matches() {
        // A non-ASCII separator (em-dash) is classified Other and kept verbatim;
        // it must not be split mid-codepoint and the examples must still match.
        let induced = assert_invariant(&["A\u{2014}1", "B\u{2014}2"]);
        assert_eq!(induced.strategy(), Strategy::Generalized);
        assert!(induced.regex().contains('\u{2014}'));
    }

    #[test]
    fn multibyte_whole_token_falls_back_and_matches() {
        // Non-ASCII letters are Other (not generalized); two different ones →
        // alternation, and the invariant must still hold.
        let induced = assert_invariant(&["café-1", "naïve-2"]);
        assert_eq!(induced.strategy(), Strategy::LiteralAlternation);
    }

    #[test]
    fn punctuation_heavy_invariant() {
        assert_invariant(&["+1 (415) 555-0100", "+1 (650) 555-0199"]);
    }

    // -----------------------------------------------------------------
    // Determinism.
    // -----------------------------------------------------------------

    #[test]
    fn determinism_same_input_same_output() {
        let a = induce(["AB-12", "CD-34", "EF-56"]).unwrap();
        let b = induce(["AB-12", "CD-34", "EF-56"]).unwrap();
        assert_eq!(a, b);
        let c = induce(["XY-1", "9999"]).unwrap();
        let d = induce(["XY-1", "9999"]).unwrap();
        assert_eq!(c, d);
    }

    // -----------------------------------------------------------------
    // Fail-closed normalization.
    // -----------------------------------------------------------------

    #[test]
    fn fail_closed_no_examples() {
        let empty: [&str; 0] = [];
        assert_eq!(induce(empty), Err(InductionError::NoExamples));
    }

    #[test]
    fn fail_closed_all_whitespace_is_empty_example() {
        // A single whitespace-only example trims to "" → EmptyExample (it is the
        // first per-example check; the list is non-empty, so not NoExamples).
        assert_eq!(induce(["   \t  "]), Err(InductionError::EmptyExample));
    }

    #[test]
    fn fail_closed_empty_example_among_others() {
        assert_eq!(induce(["AB-1", "  "]), Err(InductionError::EmptyExample));
    }

    #[test]
    fn fail_closed_too_many_examples() {
        let nine = ["a1", "b2", "c3", "d4", "e5", "f6", "g7", "h8", "i9"];
        assert_eq!(
            induce(nine),
            Err(InductionError::TooManyExamples {
                got: 9,
                max: MAX_EXAMPLES
            })
        );
    }

    #[test]
    fn fail_closed_example_too_long() {
        let long = "A".repeat(MAX_EXAMPLE_CHARS + 1);
        assert_eq!(
            induce([long.as_str()]),
            Err(InductionError::ExampleTooLong {
                max: MAX_EXAMPLE_CHARS
            })
        );
    }

    #[test]
    fn trims_before_validating_and_matching() {
        // Surrounding whitespace is trimmed; the trimmed forms align + match.
        let induced = induce(["  AB-12  ", "\tCD-34\n"]).unwrap();
        assert_eq!(induced.regex(), r"\b[A-Z]{2}\-\d{2}\b");
        assert_invariant(&["  AB-12  ", "\tCD-34\n"]);
    }

    // -----------------------------------------------------------------
    // RecognizerLibrary.
    // -----------------------------------------------------------------

    #[test]
    fn library_add_get_list_len_remove() {
        let mut lib = RecognizerLibrary::new();
        assert!(lib.is_empty());
        lib.add("party", UserRecognizer::literal("party", "Acme"));
        lib.add("matter", UserRecognizer::literal("matter", "M-001"));
        assert_eq!(lib.len(), 2);

        // get
        assert_eq!(lib.get("party").unwrap().pattern, "Acme");
        assert!(lib.get("missing").is_none());

        // list is name-sorted (deterministic): "matter" < "party"
        let names: Vec<&str> = lib.list().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["matter", "party"]);

        // remove returns the spec; second remove is None
        let removed = lib.remove("party").unwrap();
        assert_eq!(removed.pattern, "Acme");
        assert!(lib.remove("party").is_none());
        assert_eq!(lib.len(), 1);
    }

    #[test]
    fn library_add_replaces_by_name_last_wins() {
        let mut lib = RecognizerLibrary::new();
        lib.add("k", UserRecognizer::literal("k", "first"));
        lib.add("k", UserRecognizer::literal("k", "second"));
        assert_eq!(lib.len(), 1, "same name replaces, not appends");
        assert_eq!(lib.get("k").unwrap().pattern, "second");
    }

    #[test]
    fn library_validate_all_ok_and_fail_closed() {
        let mut lib = RecognizerLibrary::new();
        // A valid induced recognizer.
        let good = induce(["AB-1", "CD-2"])
            .unwrap()
            .into_user_recognizer("code");
        lib.add("code", good);
        assert!(lib.validate_all().is_ok());

        // An invalid (zero-width) regex recognizer must fail validate_all.
        lib.add(
            "bad",
            UserRecognizer {
                label: "bad".into(),
                pattern: r"a*".into(), // zero-width-capable → rejected by compile
                mode: MatchMode::Regex,
                case_sensitive: false,
                whole_word: false,
                replacement: None,
            },
        );
        assert!(
            lib.validate_all().is_err(),
            "a zero-width entry must fail validate_all"
        );
    }

    #[test]
    fn library_stores_an_induced_recognizer_that_matches_its_examples() {
        // End-to-end: induce → save → reload (get) → compile → matches example.
        let mut lib = RecognizerLibrary::new();
        let induced = induce(["INV-1001", "INV-2002"]).unwrap();
        lib.add("invoice", induced.into_user_recognizer("invoice"));
        let rec = lib.get("invoice").unwrap();
        let compiled = rec.compile().unwrap();
        assert!(compiled.re.find("INV-1001").is_some());
        assert!(
            compiled.re.find("INV-9999").is_some(),
            "the generalized shape matches a new instance"
        );
    }

    // -----------------------------------------------------------------
    // serde round-trip (only under --features serde).
    // -----------------------------------------------------------------

    #[cfg(feature = "serde")]
    #[test]
    fn serde_library_round_trips() {
        let mut lib = RecognizerLibrary::new();
        lib.add("party", UserRecognizer::literal("party", "Acme"));
        lib.add(
            "code",
            induce(["AB-1", "CD-2"])
                .unwrap()
                .into_user_recognizer("code"),
        );
        let json = serde_json::to_string(&lib).expect("serialize");
        let back: RecognizerLibrary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            lib, back,
            "library must round-trip byte-for-byte through serde"
        );
        // And the reloaded library still validates + matches.
        assert!(back.validate_all().is_ok());
        let compiled = back.get("code").unwrap().compile().unwrap();
        assert!(compiled.re.find("AB-1").is_some());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_match_mode_round_trips() {
        let r = UserRecognizer {
            label: "l".into(),
            pattern: r"\d{3}".into(),
            mode: MatchMode::Regex,
            case_sensitive: true,
            whole_word: false,
            replacement: Some("[X]".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: UserRecognizer = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
