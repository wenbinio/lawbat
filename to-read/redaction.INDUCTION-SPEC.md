<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Induction — Programming-by-Example regex synthesis

**[BUILT — see `core/crates/redaction/src/induce.rs`]**: `induce`/`induce_with`,
`InductionOptions`, `Strategy`, `InductionError`, `InducedPattern`, `RecognizerLibrary`,
`NamedRecognizer` all present and match the design below; `assert_invariant`, the
longest-first-alternation test, and the no-clock/no-RNG tests exist in-file.

A non-technical user pastes a few EXAMPLES of an identifier shape (`AB-1234`, `CD-5678`) and the
engine SYNTHESIZES a regex matching that shape. **No ML, no clock, no RNG, no network, no fs** —
a pure deterministic structural generalization over example chars (std + the existing `regex`
only). Sister docs: `LEVER2-CONTEXT-CONFIDENCE.md`, `RECOGNIZER-PACKS-SPEC.md`.

## 0. Architectural insight — induced = `Custom` (rung 4); no new machinery

Induction is a pure function over example strings emitting a regex STRING, wrapped in the EXISTING
`UserRecognizer { mode: MatchMode::Regex, .. }` (SingleLiteral uses `Literal`) and compiled through
the EXISTING `UserRecognizer::compile()`. Load-bearing consequences: an induced recognizer **IS a
`Recognizer::Custom`** — no new `Recognizer` variant, no new built-in; on the Lever-2 ladder it is
**rung 4** (Low, raised to Medium by an in-window class keyword). It inherits **every fail-closed
guard already in the crate** (zero-width rejection, label validation, replacement bound,
`whole_word`-vs-`Regex` rules — §5). `regex` is **linear-time** → a synthesized pattern carries
**NO ReDoS** risk. Induction only *produces the pattern*; matching/merging/auditing downstream is
the unchanged `Custom` path — the `messy_corpus` baselines are unaffected.

## 1. THE CORRECTNESS INVARIANT (security-critical)

> **Every normalized (trimmed, de-duplicated) input example MUST be matched by the COMPILED
> induced regex, covering the WHOLE example.**

The load-bearing safety property. A pattern that **silently fails to match its own example** is a
direct **under-redaction bug = a leak** (the user demonstrated the shape, the tool "accepted" it,
but the live matcher never fires). Proven by `assert_invariant`, which induces, compiles through
the **REAL** `UserRecognizer::compile()`, and asserts `find(example)` returns a whole-span match —
across the Generalized / LiteralAlternation / SingleLiteral paths, with multibyte / punctuation /
mixed-case examples.

## 2. The algorithm (MEDIUM aggressiveness)

`induce(examples)` / `induce_with(examples, InductionOptions { anchored })`:
1. **Normalize.** Trim each; **FAIL-CLOSED** (typed `InductionError`, no cleartext) on: zero
   examples (`NoExamples`); `>8` (`TooManyExamples`); empty/whitespace after trim (`EmptyExample`);
   `>200` chars (`ExampleTooLong`). **De-duplicate** identical examples, first-seen order.
2. **One distinct example** → `SingleLiteral` (the `regex::escape`d literal, wrapped as
   `MatchMode::Literal` so it round-trips exactly).
3. **Tokenize** into maximal runs by coarse category — **Digit**, **Letter** (case-tracked
   AllUpper/AllLower/Mixed), **Other** (verbatim, incl. non-ASCII; never split mid-codepoint).
4. **Align** iff SAME token count AND, per position, SAME coarse category AND (Other) IDENTICAL
   literal text.
   - **Aligned → `Generalized`.** Per position, `lo`/`hi` = min/max run length: Digit → `\d{lo,hi}`;
     Letter → `[A-Z]`/`[a-z]`/`[A-Za-z]` (by case) + `{lo,hi}`; Other → the escaped literal.
   - **Not aligned → `LiteralAlternation`** = `(?:escA|escB|…)` of de-duplicated escaped examples,
     **LONGEST-FIRST** (stable; ties first-seen). **Never** force-generalize to `.*`/`.+`.
5. **Anchor** per §3.

Determinism: `induce(x) == induce(x)`. **Two MEDIUM defaults:** (a) run length is a RANGE
`{min,max}` spanning EXACTLY the observed (no slack); (b) class granularity is `\d`/`[A-Z]`/
`[a-z]`/`[A-Za-z]` only — v1 emits NO alnum `[A-Za-z0-9]`/`\w`/`.`; non-ASCII always stays `Other`
so a multibyte char is never mis-generalized into a broad class.

## 3. Word-boundary anchoring (the edge rule)

`InductionOptions { anchored: bool }` (default **true**). A `\b` is added at an edge ONLY when the
adjacent emitted token is a **word-character class** (Digit/Upper/Lower/Alpha, or an Other literal
whose edge char is a word char). **NEVER** against a leading/trailing literal-punctuation token —
a naive `\b…\b` there would compile yet **silently match nothing** (the `whole_word` FIX-F1
hazard). Edges are decided independently per side.

**Alternation anchoring (v1):** `LiteralAlternation` is left **fully UNANCHORED** regardless of
`anchored` — an outer `\b…\b` would distribute across EVERY branch, silently breaking any single
non-word-edged branch (fallback branches commonly have heterogeneous edges). Unanchored matches
more loosely but never breaks a branch on a `\b`.

**Branch order — LONGEST-FIRST (correctness, not cosmetics).** `regex` unanchored alternation is
leftmost-**first**, not longest: a branch that is a PREFIX of another, if listed first, matches
only the prefix and **leaks the tail** (`(?:INV|INV\-1001)` matches just `INV` in `"INV-1001"`).
Branches emit LONGEST-FIRST → `["INV","INV-1001"]` → `(?:INV\-1001|INV)`. Load-bearing for §1;
locked by `alternation_prefix_collision_is_not_under_matched`.

## 4. Fork decisions + defaults (as built)

Forks: (1) aggressiveness = MEDIUM; (2) class granularity = MEDIUM; (3) positive examples only
(1..=8); (4) no-alignment fallback = LITERAL ALTERNATION, never broad `.*`/`.+`. Defaults: (1)
word-boundary anchoring ON (word-char edges only, §3); (2) "saved + named" persistence = in-engine
`RecognizerLibrary` + optional OFF-by-default `serde` wire form (§6); (3) single distinct example
→ `SingleLiteral` as `MatchMode::Literal`.

## 5. Safety guards (fail-closed)

| Guard | Reason | Where |
|---|---|---|
| zero examples / all-empty | nothing to induce | `NoExamples` / `EmptyExample` |
| `>8` examples | a long paste is a mistake; alternation over many is unwieldy | `TooManyExamples` |
| empty/whitespace example | degenerate / zero-width matcher | `EmptyExample` |
| `>200` chars/example | not an identifier shape; bounds synthesized size | `ExampleTooLong` |
| zero-width regex (`a*`,`\b`,`(?:)`) | a rule that "redacts" nothing = silent miss | inherited from `UserRecognizer::compile` |
| invalid label / over-long replacement | corrupts the audit breakdown / memory-amplifies | inherited from `compile` |

Errors carry **no cleartext** — only the structural reason + the limit/counts.

## 6. Persistence seam — `RecognizerLibrary` (+ optional serde)

The in-engine "saved + named" collection of `UserRecognizer` specs: `add(name, rec)` (replace-by-
name, last wins), `remove`, `get`, `list()` (deterministic name-sorted), `validate_all()` (compiles
EVERY entry through the real `compile`, **fail-closed on the first invalid** — a host rejects a
corrupt/edited library up front, never at scan time).

**Disk persistence is the HOST's job** — the module holds **no fs capability**. The optional
`serde` feature (OFF by default, mirroring `crates/view`) derives the wire form; core logic works
WITHOUT it. Serde is pure compute (no I/O/RNG) — adds no capability/egress, pulls no RNG into the
trusted core (`cargo tree -p runtime -i {getrandom,rand,…}` stays clean).

## 7. Documented-FUTURE (not built in v1)
- **Tight/Loose aggressiveness dial** (v1 is MEDIUM only; user edits the regex directly).
- **Negative/counter examples** (v1 is positive-only; would let induction TIGHTEN a generalization
  — needs a new fail-closed invariant that the pattern rejects every negative).
- **Alternation `\b` anchoring** when every branch is word-edged (§3) — deferred under Tight.
- **Wider classes / `.`** — deliberately excluded from MEDIUM (§2).

## 8. Confidentiality — the alternation form EMBEDS example cleartext

`LiteralAlternation` `(?:exA|exB|…)` literally contains the firm's identifier strings in its regex
SOURCE. The audit chain must NOT become a cleartext store of either the source or a matched value:
- **Audit logs the recognizer LABEL + counts only** — never the pattern source, never a matched
  value (unchanged `Custom` path: count + `custom:<label>`). Verified by
  `induced_recognizer_audit_never_leaks_pattern_or_example_value` (worst-case alternation whose
  source embeds cleartext, scanned+redacted through the real `Core`; asserts no audit `detail`
  contains the pattern source or any example value, while the LABEL is present).
- **`InducedPattern::strategy()` is exposed so a UI can WARN** before persisting an alternation
  that embeds literal example text.

## 9. Public API surface

```text
fn induce<I,S>(examples) -> Result<InducedPattern, InductionError>                  // default options
fn induce_with<I,S>(examples, InductionOptions) -> Result<InducedPattern, InductionError>
struct InductionOptions { anchored: bool }   // Default { anchored: true }
enum   Strategy { SingleLiteral, Generalized, LiteralAlternation }
enum   InductionError { NoExamples, TooManyExamples{got,max}, EmptyExample, ExampleTooLong{max} }
struct InducedPattern { /* private */ }  .regex() .strategy() .anchored() .into_user_recognizer(label)
struct RecognizerLibrary { /* private */ }   // + serde behind `serde`
  ::new() .add() .remove() .get() .list() .len() .is_empty() .validate_all() -> CoreResult<()>
struct NamedRecognizer { name: String, recognizer: UserRecognizer }   // + serde behind `serde`
```
All re-exported from the crate root.
