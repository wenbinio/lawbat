// SPDX-License-Identifier: AGPL-3.0-or-later
//! AI-safe pseudonymization labels + legend assignment. Extracted from `lib.rs`.

use std::collections::HashMap;

use crate::*;

// ===================================================================
// AI-safe LABELS (pseudonymization) — stable, distinct placeholders + a local legend
// ===================================================================

/// The replacement TOKEN style for an apply. The DEFAULT ([`ReplacementStyle::Redacted`])
/// is today's behavior: every removed span becomes the `[REDACTED]` marker. [`Labels`]
/// (pseudonymization) instead assigns each DISTINCT removed entity a STABLE, DISTINCT
/// placeholder so relationships/coherence survive (the "redaction-as-safe-AI-on-ramp").
///
/// This ONLY changes the token written into the redacted text — NOT which spans are
/// removed (recall parity is preserved by construction; see
/// [`redact_with_selection_labeled`](RedactionEngine::redact_with_selection_labeled)).
///
/// [`Labels`]: ReplacementStyle::Labels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplacementStyle {
    /// Every removed span → the `[REDACTED]` marker (today's behavior; the default).
    #[default]
    Redacted,
    /// AI-safe pseudonymization: each distinct entity → a stable, distinct placeholder.
    Labels,
}

/// One row of the AI-safe-labels LEGEND: the placeholder, the first-seen SURFACE FORM of
/// the value it stands for, and how many occurrences it replaced. Cleartext (the `value`),
/// returned IN-PROCESS for the local review only — it is the lawyer's key to re-identify
/// the labeled draft, and (like the candidate list) must NEVER be logged or audited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegendEntry {
    /// The placeholder as written into the text, e.g. `[A]` or `[email 2]`.
    pub label: String,
    /// The FIRST-SEEN surface form of the value (the exact original text of the first
    /// occurrence, NOT the normalized key) — what the lawyer reads to re-identify.
    pub value: String,
    /// How many occurrences (accepted merged spans) this label replaced (>= 1).
    pub count: usize,
}

/// The legend produced alongside a labeled apply: the label → value map in DETERMINISTIC
/// order — the ENTITY rows first (letter order `[A]`, `[B]`, …, then `[AA]`, …), then the
/// TYPED rows (grouped by type in first-seen order, numbered within a type). Cleartext,
/// in-process only (see [`LegendEntry`]).
pub type Legend = Vec<LegendEntry>;

/// NORMALIZE a matched value into the case/whitespace-insensitive KEY used to decide
/// whether two occurrences are "the same value" (so they reuse the same placeholder):
/// ASCII-lowercase, trim leading/trailing whitespace, and collapse every internal
/// whitespace RUN to a single space. This makes `Jefferson Tan` / `JEFFERSON  TAN` /
/// ` jefferson tan ` one key (so `[A]` is reused), and `4111 1111 1111 1111` vs a
/// double-spaced variant one key. Pure + deterministic.
///
/// SAFE-SIDE note: normalization only ever MERGES two surface forms onto one placeholder —
/// it never changes which span is removed (the span set is already fixed by `merged_spans`),
/// so an over-eager merge costs at most a slightly-less-granular legend, never a leak.
pub(crate) fn normalize_label_key(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_ws = false;
    // Trim handled implicitly: leading whitespace sets `prev_ws` but pushes nothing;
    // trailing whitespace is stripped at the end.
    for ch in value.trim().chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.extend(ch.to_lowercase());
            prev_ws = false;
        }
    }
    out
}

/// The base-26 BIJECTIVE ("spreadsheet column") name for a zero-based entity index:
/// `0 → A`, `1 → B`, …, `25 → Z`, `26 → AA`, `27 → AB`, … This is the documented post-`[Z]`
/// continuation rule — deterministic, total, and collision-free for every `usize`.
pub(crate) fn entity_letters(mut index: usize) -> String {
    // Bijective base-26: there is no "zero digit", so each step subtracts 1 before the
    // modulus. Build least-significant first, then reverse.
    let mut buf = Vec::new();
    loop {
        let rem = index % 26;
        buf.push(b'A' + rem as u8);
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    buf.reverse();
    // SAFETY/correctness: every pushed byte is ASCII `A..=Z`, so this is valid UTF-8.
    String::from_utf8(buf).expect("ASCII letters are valid UTF-8")
}

/// Assign each ACCEPTED merged span its stable AI-safe placeholder and SPLICE the labeled
/// text, returning `(labeled_text, legend)`. Single first-seen pass over `spans` (already
/// start-sorted + non-overlapping), so the alias map is built in the SAME authoritative
/// pass that produces the output (no second detection pass that could desync).
///
/// ROUTING: a span whose merged PRIMARY recognizer is the ENTITY family ([`Recognizer::Term`]
/// / [`Recognizer::Name`] / a [`Recognizer::Custom`] firm rule — the "named parties/things")
/// gets a LETTER placeholder; every other (TYPED) span gets a `[type]` / `[type N]`
/// placeholder. Both keyed by [`normalize_label_key`] so the same value reuses the same
/// placeholder, both assigned in first-seen order. A NON-accepted span is left verbatim
/// (exactly like [`redact_selected`](RedactionEngine::redact_selected)).
///
/// NUMBERING: a TYPED placeholder is UNNUMBERED while its type has exactly ONE distinct
/// value; the moment a SECOND distinct value of that type appears, the type is numbered —
/// retroactively too, so the legend always reads `[email 1]`, `[email 2]` (never a bare
/// `[email]` mixed with `[email 2]`). The numbering is resolved in a deterministic second
/// step over the recorded first-seen order, then the splice writes the resolved labels.
///
/// Pure + deterministic + confidentiality-clean (builds only in-process cleartext; logs
/// nothing). The returned legend carries cleartext for the LOCAL review only.
pub(crate) fn assign_labels(
    text: &str,
    spans: &[MergedSpan],
    accepted: &std::collections::HashSet<(usize, usize)>,
) -> (String, Legend) {
    // First-seen records. We cannot write the final TYPED labels until we know how many
    // distinct values each type has (numbered iff >= 2), so we record per-span the
    // resolution inputs, then resolve, then splice.

    /// Whether a span's merged PRIMARY recognizer is the ENTITY family (a letter), vs a
    /// TYPED recognizer (a `[type]`). `Custom` is a firm "super find & replace" rule —
    /// an explicitly-named party/thing — so it joins `Term`/`Name` as an entity. The
    /// `ctx:field-name` label (a PERSON-SHAPED name-field value — round-4 review fix) is
    /// entity-routed for PLACEHOLDER purposes only: it renders as a letter like a
    /// detected name, while staying excluded from every propagation seed predicate.
    fn is_entity(r: &Recognizer) -> bool {
        matches!(
            r,
            Recognizer::Term | Recognizer::Name | Recognizer::Custom(_)
        ) || matches!(r, Recognizer::Context(l)
            if l.as_ref() == FIELD_NAME_LABEL || l.as_ref() == ORG_CONTEXT_LABEL)
    }

    // Per-distinct-ENTITY-value: its assigned zero-based letter index + first surface form
    // + occurrence count, keyed by the normalized value, in first-seen insertion order.
    let mut entity_index: HashMap<String, usize> = HashMap::new();
    let mut entity_rows: Vec<(String, usize)> = Vec::new(); // (first surface form, count)

    // Per-TYPE: an ordered map of distinct-value-key → (slot index within the type, first
    // surface form, count). `type_order` preserves first-seen order of the TYPES themselves.
    struct TypeBucket {
        /// distinct value key → its zero-based slot within this type (for `[type N]`).
        slot_of: HashMap<String, usize>,
        /// (first surface form, count) per distinct value, indexed by slot.
        rows: Vec<(String, usize)>,
    }
    let mut buckets: HashMap<String, TypeBucket> = HashMap::new();
    let mut type_order: Vec<String> = Vec::new();

    // What each ACCEPTED span resolves to, recorded in document order for the splice.
    enum SpanLabel {
        /// An entity letter, by its zero-based entity index.
        Entity(usize),
        /// A typed placeholder: (type name, slot within the type).
        Typed(String, usize),
    }
    // (span_start, span_end, resolution) for each accepted span, in document order.
    let mut resolved: Vec<(usize, usize, SpanLabel)> = Vec::new();

    for m in spans {
        let key = (m.candidate.start, m.candidate.end);
        if !accepted.contains(&key) {
            continue; // not selected -> left verbatim in the splice below
        }
        let value = &m.candidate.matched_value;
        let norm = normalize_label_key(value);
        if is_entity(&m.candidate.recognizer) {
            // Entity: one letter per distinct normalized value, first-seen order.
            let idx = match entity_index.get(&norm) {
                Some(&i) => {
                    entity_rows[i].1 += 1;
                    i
                }
                None => {
                    let i = entity_rows.len();
                    entity_index.insert(norm, i);
                    entity_rows.push((value.clone(), 1));
                    i
                }
            };
            resolved.push((m.candidate.start, m.candidate.end, SpanLabel::Entity(idx)));
        } else {
            // Typed: one slot per distinct value within its type, first-seen order.
            let type_name = m.candidate.recognizer.type_label();
            let bucket = buckets.entry(type_name.clone()).or_insert_with(|| {
                type_order.push(type_name.clone());
                TypeBucket {
                    slot_of: HashMap::new(),
                    rows: Vec::new(),
                }
            });
            let slot = match bucket.slot_of.get(&norm) {
                Some(&s) => {
                    bucket.rows[s].1 += 1;
                    s
                }
                None => {
                    let s = bucket.rows.len();
                    bucket.slot_of.insert(norm, s);
                    bucket.rows.push((value.clone(), 1));
                    s
                }
            };
            resolved.push((
                m.candidate.start,
                m.candidate.end,
                SpanLabel::Typed(type_name, slot),
            ));
        }
    }

    // Resolve each span's FINAL label string. A type with exactly ONE distinct value is
    // UNNUMBERED (`[email]`); with >= 2 it is numbered 1-based by slot (`[email 1]`).
    let label_for = |res: &SpanLabel| -> String {
        match res {
            SpanLabel::Entity(i) => format!("[{}]", entity_letters(*i)),
            SpanLabel::Typed(type_name, slot) => {
                let distinct = buckets.get(type_name).map(|b| b.rows.len()).unwrap_or(1);
                if distinct >= 2 {
                    format!("[{type_name} {}]", slot + 1)
                } else {
                    format!("[{type_name}]")
                }
            }
        }
    };

    // SPLICE the labeled text: walk the accepted resolutions in document order, copying the
    // gaps verbatim and writing each span's resolved label. `resolved` is already in
    // ascending start order (it follows the start-sorted `spans`), and the spans are
    // non-overlapping, so a single forward cursor is correct.
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end, res) in &resolved {
        out.push_str(&text[cursor..*start]);
        out.push_str(&label_for(res));
        cursor = *end;
    }
    out.push_str(&text[cursor..]);

    // Build the LEGEND in deterministic order: ENTITY rows first (letter order == insertion
    // order), then TYPED rows grouped by type in first-seen TYPE order, slot order within.
    let mut legend: Legend = Vec::with_capacity(entity_rows.len());
    for (i, (value, count)) in entity_rows.iter().enumerate() {
        legend.push(LegendEntry {
            label: format!("[{}]", entity_letters(i)),
            value: value.clone(),
            count: *count,
        });
    }
    for type_name in &type_order {
        let bucket = &buckets[type_name];
        let numbered = bucket.rows.len() >= 2;
        for (slot, (value, count)) in bucket.rows.iter().enumerate() {
            let label = if numbered {
                format!("[{type_name} {}]", slot + 1)
            } else {
                format!("[{type_name}]")
            };
            legend.push(LegendEntry {
                label,
                value: value.clone(),
                count: *count,
            });
        }
    }

    (out, legend)
}
