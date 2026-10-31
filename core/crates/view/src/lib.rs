// SPDX-License-Identifier: AGPL-3.0-or-later
//! # `view` — shared, inert, host-renderable VIEW-MODEL types.
//!
//! The "cleaner structure" foundation (the ratified dashboard synthesis:
//! host-composition + a shared `core/crates/view` types crate, **NO `dashboard`
//! module**). This crate GENERALIZES `search::ResultView`/`ResultRow` into a small
//! vocabulary of sanitized, display-ready shapes — [`Section`], [`Card`], [`Badge`],
//! [`DueLabel`], [`Caveat`], [`ActionRef`] — that ANY module (or the trusted host
//! itself) can emit and the **host RENDERS**.
//!
//! ## Ratified architecture (load-bearing — do NOT invert)
//!
//! - **Sanitized, non-scripting HTML into a host-provided slot — NO module JS**
//!   (CLAUDE.md / spec §8). So every type here carries ONLY inert, display-ready
//!   data the host will escape + place into its slot. There is NO raw HTML the
//!   producer controls, NO `<script>`, NO event handler, NO callback — an
//!   interaction is a TYPED [`ActionRef`] (an action id + opaque target) the **HOST
//!   routes** through the broker; the producer never runs code in response.
//! - **Pure types, NO `runtime` dependency.** This crate depends on NOTHING. It must
//!   be usable by a zero-capability presenter / the host without pulling in the
//!   trusted core, and it must carry nothing privileged: no capabilities, no `Core`
//!   handle, no matter access — only data. (A producer that reads matter data does so
//!   THROUGH the core, then hands the already-read, inert result here.)
//!
//! ## Confidentiality (load-bearing)
//!
//! The display strings here (a [`Card`] title/excerpt) MAY be matter-derived
//! cleartext the producer chose to surface FOR IN-PROCESS REVIEW. This crate adds NO
//! egress and NO new capability, so it cannot send anything anywhere — it is a
//! presentation shape, not a transport. The producer's confidentiality split (audit
//! = counts-only; cleartext stays in-process behind an empty egress grant) is
//! UNCHANGED by routing data through these types.
//!
//! ## Honest framing
//!
//! These types render WHAT a producer decided; they do not decide anything. A
//! [`DueLabel`] surfaces a producer's FACTUAL proximity + precision (including the
//! AMBIGUOUS-date QUESTION and the needs-confirm states); it never upgrades a
//! suggestion into a commitment. A [`Caveat`] is a verbatim honest-limits banner.

#![forbid(unsafe_code)]

/// A heading-led group of [`Card`]s — the top-level unit a host composes onto the
/// home/dashboard. Inert: a title, optional caveats, and rows. NO script, NO markup
/// the producer controls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Section {
    /// The section heading (plain text; the host escapes it).
    pub title: String,
    /// Honest-limits banners that apply to this whole section (e.g. "no date ≠ no
    /// deadline"). Rendered verbatim by the host (see [`Caveat`]).
    pub caveats: Vec<Caveat>,
    /// The cards in this section, in the order the producer wants them shown.
    pub cards: Vec<Card>,
}

impl Section {
    /// A section with a title and no cards/caveats yet.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            caveats: Vec::new(),
            cards: Vec::new(),
        }
    }
}

/// One inert card — a single worklist row / result, display-ready. Generalizes
/// `search::ResultRow` (label + snippet) with the richer fields a triage worklist
/// needs: a secondary label, badges, a due label, and typed actions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Card {
    /// The PRIMARY display line (e.g. the body excerpt). Plain text; host-escaped.
    pub title: String,
    /// A SECONDARY label shown alongside the title (e.g. the email subject, the
    /// sender). Plain text; host-escaped. Empty when there is none.
    pub subtitle: String,
    /// Inert badges (internal/external, a surfaced category, protected-handling, a
    /// confidentiality warning). Only what a producer chose to SURFACE.
    pub badges: Vec<Badge>,
    /// The deadline label, if the producer surfaced one. Carries factual proximity +
    /// precision (incl. ambiguous / needs-confirm) — see [`DueLabel`].
    pub due: Option<DueLabel>,
    /// Typed actions the user can invoke on this card. Each is an [`ActionRef`] the
    /// HOST routes (no producer JS). Empty when the card is informational.
    pub actions: Vec<ActionRef>,
}

impl Card {
    /// A card with a title and nothing else yet.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Self::default()
        }
    }
}

/// An inert badge — a small, categorized label chip. The producer chooses the
/// [`BadgeKind`] (so the host can colour/group it) and a short plain-text label.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Badge {
    /// What KIND of badge this is (drives host styling/grouping; never executable).
    pub kind: BadgeKind,
    /// The short display text (plain; host-escaped), e.g. "external", "court /
    /// filing", "⚠ Bcc". The producer keeps this cleartext-FREE of matched content.
    pub label: String,
}

impl Badge {
    /// Construct a badge of `kind` with `label`.
    pub fn new(kind: BadgeKind, label: impl Into<String>) -> Self {
        Self {
            kind,
            label: label.into(),
        }
    }
}

/// The KIND of a [`Badge`] — a fixed, non-extensible vocabulary so the host can
/// style/group badges consistently. NOT matter content; a categorization only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BadgeKind {
    /// Internal-vs-external sender (the trusted classifier).
    Origin,
    /// A surfaced message category (court/filing, newsletter).
    Category,
    /// Protected-handling (privileged / without-prejudice).
    Protected,
    /// A confidentiality / leak-vector warning (Bcc, hidden/nested attachment).
    Warning,
    /// A priority badge (only when the producer can trust it — e.g. the received
    /// anchor is wired). Suppressed otherwise; the producer simply omits it.
    Priority,
    /// A neutral, uncategorized chip.
    Neutral,
}

/// A deadline label — the producer's FACTUAL proximity statement plus how precisely
/// the date was pinned. Inert + honest: it carries the AMBIGUOUS-date QUESTION and
/// the needs-confirm states so the host can render them as questions/warnings,
/// NEVER as a confident committed date.
///
/// `text` is the producer's display string (e.g. "due in 3 days", "overdue by 4
/// days", "3 Apr or 4 Mar?", "deadline detected — confirm date"). `kind` lets the
/// host style it (overdue red, ambiguous as a question, etc.) without re-deriving.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DueLabel {
    /// The display text (plain; host-escaped).
    pub text: String,
    /// The proximity/precision kind (drives styling + the "this is a question / needs
    /// confirmation, not a committed date" treatment).
    pub kind: DueKind,
}

impl DueLabel {
    /// Construct a due label.
    pub fn new(kind: DueKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }
}

/// How a [`DueLabel`] should be treated — a fixed vocabulary mirroring a producer's
/// factual proximity + precision states. HONEST: the non-factual states
/// ([`DueKind::Ambiguous`], [`DueKind::NeedsConfirm`]) are explicit so the host can
/// NEVER render them as a settled date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DueKind {
    /// A resolved deadline already past ("overdue by N days") — a fact.
    Overdue,
    /// A resolved deadline today ("due today") — a fact.
    DueToday,
    /// A resolved deadline in the future ("due in N days") — a fact.
    DueSoon,
    /// The date itself is irreducibly ambiguous ("3 Apr or 4 Mar?") — render as a
    /// QUESTION the user must answer, never a settled date.
    Ambiguous,
    /// A deadline was detected but cannot be resolved/measured yet (relative date
    /// with no received-time anchor, or an explicit date whose proximity is not yet
    /// computable) — render as needs-confirm, never as a resolved date.
    NeedsConfirm,
    /// A vague urgency cue ("ASAP") with no resolvable day.
    Vague,
}

/// An honest-limits banner the host renders verbatim. Inert plain text — the whole
/// point is that the presentation CANNOT omit or soften it (it is data, not a doc
/// comment). Generalizes a producer's caveat enum into a transportable shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Caveat {
    /// A stable, cleartext-free identifier for the caveat (for tests/styling), e.g.
    /// "deadlines-not-all-caught". A producer maps its own caveat label here.
    pub id: String,
    /// The banner text the host shows verbatim (plain; host-escaped).
    pub message: String,
    /// When true, the host renders an **"ignore all further warnings"** control and,
    /// on activation, PERSISTS suppression keyed by [`id`](Caveat::id) so the banner
    /// nags once and can then be silenced (it must not nag forever). The honest-limit
    /// banner is shown until the user dismisses it; suppression is per-`id`, so a new
    /// caveat kind still surfaces. (Host concern — the view model only declares it is
    /// dismissible; it carries no state.)
    pub dismissible: bool,
}

impl Caveat {
    /// Construct a caveat banner. Dismissible by default (the host offers
    /// "ignore all further warnings" + persists suppression by `id`).
    pub fn new(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            message: message.into(),
            dismissible: true,
        }
    }

    /// A caveat that the host must NOT let the user permanently silence (reserved for
    /// any future hard-blocking limit; the current honest-limit banners are all
    /// dismissible per the user's "ignore all further warnings" decision).
    pub fn non_dismissible(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            message: message.into(),
            dismissible: false,
        }
    }
}

/// A TYPED interaction reference — an `on-invoke` action the **HOST routes** (NO
/// module JS, ratified). The producer declares WHAT action and on WHICH opaque
/// target; the host validates + dispatches it through the broker. This is the only
/// "interactivity" the view model carries, and it is pure data — no code, no
/// callback, no script.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ActionRef {
    /// The action identifier the host knows how to route (e.g. "confirm", "dismiss",
    /// "snooze", "open-source"). A stable string, NOT a function/closure.
    pub action_id: String,
    /// The display label for the control (plain; host-escaped), e.g. "Confirm".
    pub label: String,
    /// An OPAQUE target token the host passes back when routing (e.g. the
    /// provenance key `doc_id+rule` for the stable-key overlay invariant). The
    /// producer treats it as opaque; it carries NO capability and is not executable.
    pub target: String,
}

impl ActionRef {
    /// Construct a typed action reference.
    pub fn new(
        action_id: impl Into<String>,
        label: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            action_id: action_id.into(),
            label: label.into(),
            target: target.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_are_inert_data_only() {
        // The whole guarantee: these are plain data shapes. Building them is
        // infallible and they carry no executable hooks (only strings + enums).
        let section = Section {
            title: "Today".to_string(),
            caveats: vec![Caveat::new(
                "deadlines-not-all-caught",
                "\"No date detected\" does NOT mean no deadline.",
            )],
            cards: vec![Card {
                title: "Please review the draft SPA and revert.".to_string(),
                subtitle: "Re: Re: FW: Condor".to_string(),
                badges: vec![
                    Badge::new(BadgeKind::Origin, "external"),
                    Badge::new(BadgeKind::Warning, "⚠ Bcc"),
                ],
                due: Some(DueLabel::new(
                    DueKind::NeedsConfirm,
                    "deadline detected — confirm date",
                )),
                actions: vec![ActionRef::new("confirm", "Confirm", "doc:1|review-cue")],
            }],
        };
        assert_eq!(section.cards.len(), 1);
        assert_eq!(section.cards[0].badges.len(), 2);
        assert_eq!(section.caveats[0].id, "deadlines-not-all-caught");
    }

    #[test]
    fn constructors_default_sensibly() {
        let s = Section::new("Inbox");
        assert!(s.cards.is_empty() && s.caveats.is_empty());
        let c = Card::new("hello");
        assert!(
            c.subtitle.is_empty() && c.badges.is_empty() && c.due.is_none() && c.actions.is_empty()
        );
    }

    #[test]
    fn due_kinds_distinguish_facts_from_questions() {
        // The honest states are DISTINCT from the factual ones so a host can never
        // render an ambiguous/needs-confirm label as a settled date.
        let facts = [DueKind::Overdue, DueKind::DueToday, DueKind::DueSoon];
        let not_facts = [DueKind::Ambiguous, DueKind::NeedsConfirm, DueKind::Vague];
        for f in facts {
            assert!(
                !not_facts.contains(&f),
                "a factual kind must not equal a non-factual one"
            );
        }
    }

    #[test]
    fn action_ref_is_a_string_id_not_a_callback() {
        // An interaction is a typed id + opaque target the HOST routes — never an
        // executable hook. (Asserted at the type level: only strings here.)
        let a = ActionRef::new("dismiss", "Dismiss", "doc:7|no-rule");
        assert_eq!(a.action_id, "dismiss");
        assert_eq!(a.target, "doc:7|no-rule");
    }

    // ---- OPTIONAL serde serialization (only under `--features serde`) -------
    //
    // The view crate stays ZERO-DEP by default; serde is opt-in for the JSON
    // boundary. These tests run only with the `serde` feature. We deliberately do
    // NOT pull `serde_json` into the `view` crate (it would defeat the zero-dep
    // default even under the feature, and the byte-level contract test belongs in
    // `viewgen`, which owns serde_json). So here we assert at the TYPE LEVEL that
    // the shapes derive `serde::Serialize`, plus the kind enums' snake_case mapping
    // via a tiny in-test serializer that captures only the unit-variant name.
    #[cfg(feature = "serde")]
    mod serde_support {
        use super::*;

        /// Assert (at compile time) that `T: serde::Serialize`. If the derive were
        /// missing this would fail to compile under `--features serde`.
        fn assert_serialize<T: serde::Serialize>() {}

        #[test]
        fn all_view_types_derive_serialize() {
            assert_serialize::<Section>();
            assert_serialize::<Card>();
            assert_serialize::<Badge>();
            assert_serialize::<DueLabel>();
            assert_serialize::<Caveat>();
            assert_serialize::<ActionRef>();
            assert_serialize::<BadgeKind>();
            assert_serialize::<DueKind>();
        }

        /// The error type for the minimal in-test [`NameCapture`] serializer below:
        /// it captures the name a UNIT VARIANT serializes as — enough to prove the
        /// `rename_all = "snake_case"` mapping without pulling `serde_json` into the
        /// zero-dep `view` crate. Any non-unit-variant call is unreachable for our
        /// fieldless enums and is refused with this error.
        #[derive(Debug)]
        struct NotAUnitVariant;
        impl std::fmt::Display for NotAUnitVariant {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("only unit-variant serialization is supported in this test serializer")
            }
        }
        impl std::error::Error for NotAUnitVariant {}
        impl serde::ser::Error for NotAUnitVariant {
            fn custom<T: std::fmt::Display>(_: T) -> Self {
                NotAUnitVariant
            }
        }

        /// Serialize a unit-only enum and return the variant string it maps to.
        fn unit_variant_name<T: serde::Serialize>(value: &T) -> String {
            // The only Serializer method our kind enums exercise is
            // `serialize_unit_variant`; capture its `variant` argument.
            value
                .serialize(NameCapture)
                .expect("unit variant serializes")
        }

        struct NameCapture;
        impl serde::Serializer for NameCapture {
            type Ok = String;
            type Error = NotAUnitVariant;
            type SerializeSeq = serde::ser::Impossible<String, NotAUnitVariant>;
            type SerializeTuple = serde::ser::Impossible<String, NotAUnitVariant>;
            type SerializeTupleStruct = serde::ser::Impossible<String, NotAUnitVariant>;
            type SerializeTupleVariant = serde::ser::Impossible<String, NotAUnitVariant>;
            type SerializeMap = serde::ser::Impossible<String, NotAUnitVariant>;
            type SerializeStruct = serde::ser::Impossible<String, NotAUnitVariant>;
            type SerializeStructVariant = serde::ser::Impossible<String, NotAUnitVariant>;

            fn serialize_unit_variant(
                self,
                _name: &'static str,
                _index: u32,
                variant: &'static str,
            ) -> Result<String, NotAUnitVariant> {
                Ok(variant.to_string())
            }

            // Everything else is irrelevant for a fieldless enum — refuse it so a
            // mistaken use of this test serializer fails loudly.
            fn serialize_bool(self, _: bool) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_i8(self, _: i8) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_i16(self, _: i16) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_i32(self, _: i32) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_i64(self, _: i64) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_u8(self, _: u8) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_u16(self, _: u16) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_u32(self, _: u32) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_u64(self, _: u64) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_f32(self, _: f32) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_f64(self, _: f64) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_char(self, _: char) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_str(self, _: &str) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_bytes(self, _: &[u8]) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_none(self) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_some<T: serde::Serialize + ?Sized>(
                self,
                _: &T,
            ) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_unit(self) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_unit_struct(self, _: &'static str) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_newtype_struct<T: serde::Serialize + ?Sized>(
                self,
                _: &'static str,
                _: &T,
            ) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_newtype_variant<T: serde::Serialize + ?Sized>(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: &T,
            ) -> Result<String, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_seq(
                self,
                _: Option<usize>,
            ) -> Result<Self::SerializeSeq, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_tuple_struct(
                self,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeTupleStruct, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_tuple_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeTupleVariant, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_map(
                self,
                _: Option<usize>,
            ) -> Result<Self::SerializeMap, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_struct(
                self,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeStruct, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
            fn serialize_struct_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: usize,
            ) -> Result<Self::SerializeStructVariant, NotAUnitVariant> {
                Err(NotAUnitVariant)
            }
        }

        #[test]
        fn badge_kinds_map_to_lowercase_snake_case() {
            // The host contract's `kind` strings: BadgeKind ∈
            // origin|category|priority|protected|warning (+ neutral).
            assert_eq!(unit_variant_name(&BadgeKind::Origin), "origin");
            assert_eq!(unit_variant_name(&BadgeKind::Category), "category");
            assert_eq!(unit_variant_name(&BadgeKind::Protected), "protected");
            assert_eq!(unit_variant_name(&BadgeKind::Warning), "warning");
            assert_eq!(unit_variant_name(&BadgeKind::Priority), "priority");
            assert_eq!(unit_variant_name(&BadgeKind::Neutral), "neutral");
        }

        #[test]
        fn due_kinds_map_to_lowercase_snake_case() {
            // The host contract's `kind` strings: DueKind ∈
            // overdue|due_today|due_soon|ambiguous|needs_confirm|vague.
            assert_eq!(unit_variant_name(&DueKind::Overdue), "overdue");
            assert_eq!(unit_variant_name(&DueKind::DueToday), "due_today");
            assert_eq!(unit_variant_name(&DueKind::DueSoon), "due_soon");
            assert_eq!(unit_variant_name(&DueKind::Ambiguous), "ambiguous");
            assert_eq!(unit_variant_name(&DueKind::NeedsConfirm), "needs_confirm");
            assert_eq!(unit_variant_name(&DueKind::Vague), "vague");
        }
    }
}
