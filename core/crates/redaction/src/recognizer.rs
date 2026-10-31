// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recognizer taxonomy + confidence/review-tier types (extracted from the
//! former monolithic `lib.rs`; see the crate root for the module map).

use std::sync::Arc;

/// Which recognizer matched a span. Used to attribute a [`RedactionCandidate`]
/// (and to build the per-recognizer breakdown in the audit note).
///
/// Built-ins ([`Recognizer::Term`]/`Email`/`Phone`/`Id`/`Name`) are fixed
/// presets; [`Recognizer::Custom`] carries a firm-supplied recognizer NAME
/// (e.g. `party-name`, `matter-no`) from a [`UserRecognizer`]. The custom label
/// is a CONFIG string (a recognizer name, NOT a matched value), so it is safe to
/// show in candidates and in the audit breakdown.
///
/// [`Recognizer::Locale`] is how an OPT-IN jurisdiction pack (see [`Locale`] /
/// [`LocaleRecognizer`]) attributes a match: it carries a JURISDICTION-NAMESPACED
/// name (e.g. `"sg:nric"`), exactly analogous to `Custom`. Locale recognizers are
/// kept as DATA rows (not per-recognizer enum variants), so adding a jurisdiction
/// later is a `Locale` variant + a data row — it never grows THIS enum. The label
/// is a CONFIG string (a recognizer name, NOT a matched value), so it is audit-safe.
///
/// When overlapping spans from different recognizers MERGE into one candidate,
/// the merged candidate keeps a single PRIMARY recognizer — the one with the
/// smallest priority value, ties broken by the EARLIEST start (see
/// [`Recognizer::priority`] and the overlap rule on
/// [`RedactionEngine::candidates`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Recognizer {
    /// An explicit caller-supplied term (party name, codename, matter number).
    Term,
    /// An email address.
    Email,
    /// A phone-like digit run.
    Phone,
    /// A simple structured-id pattern.
    Id,
    /// A title-prefixed (or, in aggressive mode, capitalized-run) name HEURISTIC.
    Name,
    /// A payment-card number: a 13–19 digit run (optionally space/dash grouped)
    /// that PASSES the Luhn (mod-10) check. The Luhn validator makes an otherwise
    /// hopelessly-broad digit-run precise WITHOUT a miss risk — a real card always
    /// satisfies Luhn, so the check only filters non-cards.
    CreditCard,
    /// An IBAN: a country code + 2 check digits + the BBAN that PASSES the ISO
    /// 7064 mod-97-10 check. Like the card, the checksum filters non-IBANs without
    /// ever rejecting a real one.
    Iban,
    /// An ISO 17442 Legal Entity Identifier (LEI): exactly 20 chars
    /// `[A-Z0-9]{18}[0-9]{2}` (18 alphanumeric body chars + 2 ISO 7064 mod-97-10
    /// CHECK DIGITS) that PASSES the mod-97-10 check (the SAME checksum family as the
    /// IBAN, WITHOUT the IBAN rearrangement). Like the card/IBAN, the checksum filters
    /// non-LEIs without ever rejecting a real one — so the broad format pattern stays
    /// precise.
    ///
    /// OPT-IN, OFF by default: a public LEI is borderline PII, so flagging it is a
    /// USER DECISION (the directive: "suggested AND selectable"). Enabled only via
    /// [`RedactionEngineBuilder::lei`]; absent, the engine is byte-identical to today.
    /// Unlike the digit-leading-blind broad `id` recognizer, the LEI pattern matches a
    /// DIGIT-LEADING token too (e.g. `549300…`), which is why those are otherwise missed.
    Lei,
    /// An ISO 9362 BIC / SWIFT code: 4 alpha bank code + a VALID ISO 3166 alpha-2
    /// country code + a 2-char alphanumeric location code (+ an optional 3-char branch).
    /// STRUCTURE-validated (a BIC carries no checksum — the country table + the SWIFT
    /// location rules supply the precision), so unlike card/IBAN/LEI it is NOT
    /// checksum-precise: it stays in the CAREFUL review tier (never quick-confirm).
    /// GLOBAL + ON by default like the IBAN (a BIC beside a redacted IBAN re-identifies
    /// the institution — the verified finance-corpus leak): the 11-char form stands
    /// alone; the hopelessly word-shaped 8-char form ("DEUTSCHE" is structure-valid)
    /// additionally requires a BIC/SWIFT label cue in-window (the labeled-BIC pass).
    Bic,
    /// An ISO 6166 ISIN: 2 alpha prefix + 9 alphanumeric NSIN + 1 check digit that
    /// PASSES the ISIN Luhn (letters expanded `A..Z` → `10..35`, then mod-10). Like the
    /// card/IBAN/LEI, the checksum filters non-ISINs without ever rejecting a real one,
    /// so it is precise enough to stand alone. GLOBAL + ON by default like the IBAN (an
    /// ISIN identifies the traded security — cheap, checksum-validatable coverage).
    Isin,
    /// An IP address (IPv4 dotted-quad or IPv6, including compressed `::` forms).
    Ip,
    /// A URL (`http`/`https`/`ftp` scheme, or a bare `www.` host).
    Url,
    /// A STRUCTURED postal/street ADDRESS — a number + street-name + suffix run
    /// (`50 Raffles Place`), a floor/unit form (`#16-03`, `Level 12`, `Suite 4`,
    /// `Unit 8`), or a PO-Box form. A GLOBAL, always-on built-in (like email/phone):
    /// it covers the STRUCTURED subset of addresses deterministically. It is
    /// deliberately FP-prone (a "14 items on the road"-shaped run can match), so it
    /// is recall-first per the crate PRINCIPLE and routes to the CAREFUL review tier
    /// (never quick-confirm — it is never checksum/structural, so `confidence_for`
    /// caps it at Medium/Low). FREE-TEXT / unlabelled addresses remain reviewer
    /// territory; locale POSTAL CODES (SG/UK/US/CA/AU) ride the opt-in locale packs.
    Address,
    /// A firm-defined recognizer, tagged with its config-supplied NAME (the
    /// [`UserRecognizer::label`]). The label is a recognizer name, never a
    /// matched value, so it is audit-safe.
    ///
    /// FIX #14 (per-match clone): the label is an [`Arc<str>`], not a `String`, so
    /// attributing each raw match to its recognizer is a refcount bump (a pointer
    /// copy), NOT a heap allocation of the label text. A pattern that matches a
    /// thousand times shares ONE label allocation across all thousand candidates.
    Custom(Arc<str>),
    /// A recognizer from an OPT-IN [`Locale`] pack, tagged with its
    /// JURISDICTION-NAMESPACED name (e.g. `"sg:nric"`). The label is a recognizer
    /// name, never a matched value, so it is audit-safe.
    ///
    /// This single generic variant carries EVERY locale recognizer (NRIC today, an
    /// SG UEN or a US SSN tomorrow) — the recognizers are DATA rows
    /// ([`LocaleRecognizer`]), not enum variants — so adding a jurisdiction grows
    /// the [`Locale`] enum + a data table, never this `Recognizer` enum.
    ///
    /// Like [`Recognizer::Custom`] the label is an [`Arc<str>`] (FIX #14): per-match
    /// attribution is a refcount bump, not a heap copy of the label text.
    Locale(Arc<str>),
    /// A recognizer from an OPT-IN compliance [`Profile`]'s OWN rows, tagged with its
    /// PROFILE-NAMESPACED name (e.g. `"pci-dss-cardholder:account-ref"`). The label is
    /// a recognizer name, never a matched value, so it is audit-safe.
    ///
    /// Exactly like [`Recognizer::Locale`] but for the compliance axis: a single
    /// generic variant carries EVERY profile-specific recognizer (the recognizers are
    /// DATA rows, [`ProfileRecognizer`]), so adding a profile grows the [`Profile`]
    /// enum + a data table, never this `Recognizer` enum. Built-ins a profile merely
    /// REQUIRES (e.g. PCI's credit-card) keep their own built-in label; only a
    /// profile's BESPOKE rows attribute here. The label is an [`Arc<str>`] (FIX #14):
    /// per-match attribution is a refcount bump, not a heap copy.
    Profile(Arc<str>),
    /// A CONTEXT-REQUIRED recognizer (Lever 2): a broad/ambiguous shape (undashed
    /// SSN, DOB, age>89, generic account/MRN) that fires only when ENABLED (opt-in,
    /// OFF by default) and whose candidate SURVIVES finalization only when a relevant
    /// context keyword is in-window OR a normal recognizer also covers the span (the
    /// additive-only gate — see [`RedactionEngine::merged_spans`]). The label is a
    /// `ctx:`-namespaced recognizer NAME (e.g. `"ctx:ssn-undashed"`), never a matched
    /// value, so it is audit-safe.
    ///
    /// Like [`Recognizer::Locale`]/[`Recognizer::Profile`] this single generic variant
    /// carries EVERY context recognizer (the four are DATA rows, [`ContextRecognizer`]),
    /// so adding one grows the data table, never this enum. The label is an `Arc<str>`
    /// (FIX #14): per-match attribution is a refcount bump, not a heap copy.
    Context(Arc<str>),
}

/// A redaction candidate's CONFIDENCE tier (Lever 2). A PURE, deterministic
/// annotation computed from (span position, surrounding window text, fixed keyword
/// lexicons) — NO clock, NO ML, NO current date anywhere. It is purely ADDITIVE: it
/// never changes WHICH candidates fire or their spans/merge; it only annotates a
/// candidate (and, for the opt-in context recognizers, drives the additive-only gate).
///
/// Ordering is `Low < Medium < High` (the derived `Ord`), so "raise the tier" is a
/// `max`. The audit note records per-tier COUNTS only (never a value, never the
/// surrounding cleartext) — see the crate-level confidentiality split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Broad/format-only match with no corroborating context — the lowest rung. A
    /// context-required match that survives ONLY because a normal recognizer also
    /// covers its span (no keyword in-window) lands here.
    Low,
    /// A structurally-specific shape with no class keyword in-window, OR a
    /// context-required match with a keyword somewhere in the window (but not close).
    Medium,
    /// A checksum-validated identifier (context-irrelevant), OR a structurally-specific
    /// shape with a class keyword in-window, OR a context-required match with a keyword
    /// CLOSE to it (a strict ≤20-byte gap; see the `Close` tightening in `context.rs`).
    High,
}

impl Confidence {
    /// Stable lowercase label for the per-tier audit breakdown (`high`/`medium`/`low`).
    /// A tier name, never a matched value, so it is audit-safe.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// The TWO review tiers a [`Confidence`]-annotated candidate routes into — the
/// LOAD-BEARING use of the tier. Before this, `Confidence` was *advisory*: computed,
/// surfaced on each candidate, and counted in the audit, but nothing in the workflow
/// CONSUMED it. The two-tier routing makes the tier decide HOW a candidate is reviewed:
///
/// - [`QuickConfirm`](ReviewTier::QuickConfirm) (Tier 1): high-confidence candidates a
///   reviewer bulk-confirms in one action — checksum-validated IDs, structural shapes
///   corroborated by a class keyword, context matches with a CLOSE keyword. Pre-accepted
///   by [`Selection::quick_confirm`].
/// - [`CarefulReview`](ReviewTier::CarefulReview) (Tier 2): lower-confidence candidates
///   that need a per-item human decision. NOT pre-accepted — the reviewer opts each one
///   IN (or leaves it un-redacted) via [`Selection::accept`].
///
/// The mapping from `Confidence` to `ReviewTier` is a [`ReviewPolicy`] (its quick-confirm
/// FLOOR), so the routing is a single tunable, not scattered thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReviewTier {
    /// Tier 1 — bulk-confirmable high-confidence candidates.
    QuickConfirm,
    /// Tier 2 — per-item careful review; not pre-accepted.
    CarefulReview,
}

impl ReviewTier {
    /// Stable lowercase label for display / a diagnostic breakdown
    /// (`quick-confirm` / `careful-review`). A tier NAME, never a matched value, so it
    /// is confidentiality-safe.
    pub fn label(self) -> &'static str {
        match self {
            ReviewTier::QuickConfirm => "quick-confirm",
            ReviewTier::CarefulReview => "careful-review",
        }
    }
}

/// Routes a [`Confidence`] tier to a [`ReviewTier`]. The single tunable is the
/// quick-confirm FLOOR: the minimum confidence that qualifies for Tier-1 (quick-confirm).
/// Everything strictly below the floor is Tier-2 (careful review).
///
/// The DEFAULT floor is [`Confidence::High`]: only the strongest candidates are
/// bulk-confirmable; Medium + Low get a careful per-item look. This is the conservative
/// default that makes "quick-confirm" trustworthy — a reviewer who bulk-accepts Tier-1 is
/// accepting only the high-precision matches. A firm that wants to bulk-confirm Medium as
/// well sets the floor to [`Confidence::Medium`] via [`with_quick_confirm_floor`]; to
/// review EVERYTHING per-item, start from [`Selection::none`] instead.
///
/// LOAD-BEARING NOTE: because the floor decides what gets pre-accepted, the *precision*
/// of the [`Confidence::High`] tier now matters operationally (an over-eager High =
/// over-eager auto-accept). That is exactly why the context-proximity `Close` rung was
/// tightened to a strict ≤20-byte gap when this routing landed (see `context.rs` /
/// `to-read/redaction.LEVER2-CONTEXT-CONFIDENCE.md` §4) — same-line-but-far corroboration no longer reaches
/// High on its own, so it routes to careful review rather than quick-confirm.
///
/// [`with_quick_confirm_floor`]: ReviewPolicy::with_quick_confirm_floor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewPolicy {
    quick_confirm_floor: Confidence,
}

impl Default for ReviewPolicy {
    /// The default policy: quick-confirm floor = [`Confidence::High`].
    fn default() -> Self {
        Self {
            quick_confirm_floor: Confidence::High,
        }
    }
}

impl ReviewPolicy {
    /// The default policy (quick-confirm floor = [`Confidence::High`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// A policy with a custom quick-confirm floor — the minimum [`Confidence`] routed to
    /// Tier-1. E.g. [`Confidence::Medium`] also bulk-confirms Medium candidates;
    /// [`Confidence::Low`] makes EVERY candidate Tier-1 (equivalent to [`Selection::all`]).
    pub fn with_quick_confirm_floor(floor: Confidence) -> Self {
        Self {
            quick_confirm_floor: floor,
        }
    }

    /// The quick-confirm floor (the minimum [`Confidence`] routed to Tier-1).
    pub fn quick_confirm_floor(&self) -> Confidence {
        self.quick_confirm_floor
    }

    /// Route a [`Confidence`] to its [`ReviewTier`]: `>= floor` ⇒ Tier-1 (quick-confirm),
    /// below the floor ⇒ Tier-2 (careful review). Deterministic + total (relies on the
    /// derived `Low < Medium < High` order on [`Confidence`]).
    pub fn tier(&self, confidence: Confidence) -> ReviewTier {
        if confidence >= self.quick_confirm_floor {
            ReviewTier::QuickConfirm
        } else {
            ReviewTier::CarefulReview
        }
    }
}

/// The DEMOTED merge priority of an AGGRESSIVE locale row (a broad, format-only
/// last-resort shape — driver's licence / passport / generic account / BSB / transit /
/// sort code). It sits in the Phone/Ip tier (4): BELOW every precise recognizer (a
/// precise locale row + the checksum built-ins at 1, email at 2, id/url at 3), so a
/// precise sibling always out-LABELS it on an overlapping merged span — yet ABOVE the
/// broad `Name` heuristic (5) and a context-only `Context` span (6), so it still labels
/// THOSE. Applied by [`RedactionEngine::recognizer_priority`] (consulting the engine's
/// `aggressive_locales` set); a plain `Recognizer::Locale` (not flagged aggressive) keeps
/// the precise priority 1 from [`Recognizer::priority`]. PRECEDENCE-ONLY — see that method
/// for the recall-neutral guarantee.
pub(crate) const AGGRESSIVE_LOCALE_PRIORITY: u8 = 4;

impl Recognizer {
    /// Deterministic priority for picking the PRIMARY recognizer of a merged
    /// candidate (lower wins). `Custom` is an EXPLICIT firm rule, so it is the
    /// MOST specific and wins over every built-in (priority 0); `Term` is the
    /// most specific built-in; the broad `Name` heuristic is least specific, so
    /// it loses. (Two custom recognizers tie on priority — the merge then breaks
    /// the tie by earliest start, keeping the order total + deterministic.)
    ///
    /// NOTE: `Recognizer::Locale(_)` returns the PRECISE priority 1 here uniformly; an
    /// AGGRESSIVE locale row is demoted to [`AGGRESSIVE_LOCALE_PRIORITY`] by the engine-
    /// aware [`RedactionEngine::recognizer_priority`] (it needs the engine's per-row
    /// `aggressive` flag, which a bare `Recognizer` label cannot recover). Every caller
    /// that elects/sorts a PRIMARY must use `recognizer_priority`, NOT this raw method, so
    /// the demotion is honored.
    pub(crate) fn priority(&self) -> u8 {
        match self {
            // Explicit firm rule — most specific.
            Recognizer::Custom(_) => 0,
            // Caller term + the checksum-validated identifiers + every opt-in LOCALE
            // recognizer (a jurisdiction-specific national ID like an SG NRIC) are
            // all highly specific (a Luhn-valid card / mod-97-valid IBAN /
            // NRIC-shaped token is very unlikely to be anything else), so they win
            // over the broad format recognizers — a locale NRIC (priority 1) still
            // beats the broad `id` (priority 3) on overlap. Ties are broken by label
            // ASC in the merge sort, so equal priorities stay a total, deterministic
            // order.
            Recognizer::Term => 1,
            Recognizer::Locale(_) => 1,
            // A profile's BESPOKE row is as specific as a locale national ID — an
            // explicit, compliance-scoped recognizer — so it shares priority 1.
            Recognizer::Profile(_) => 1,
            Recognizer::CreditCard => 1,
            Recognizer::Iban => 1,
            // A mod-97-valid LEI is as specific as an IBAN (a real LEI always passes the
            // checksum, so a passing match is very unlikely to be anything else) — it wins
            // over the broad format recognizers on overlap, exactly like the IBAN.
            Recognizer::Lei => 1,
            // A checksum-valid ISIN is as specific as an LEI/IBAN — same tier.
            Recognizer::Isin => 1,
            Recognizer::Email => 2,
            Recognizer::Id => 3,
            Recognizer::Url => 3,
            // A BIC is STRUCTURE-only (no checksum): more specific than the broad
            // phone/address tier, less than the checksum identifiers — the id/url tier.
            Recognizer::Bic => 3,
            Recognizer::Phone => 4,
            Recognizer::Ip => 4,
            // The structured-address recognizer is broad/format-only (like phone/ip), so it
            // sits in the same tier: a precise sibling (email/id/url/locale/checksum) out-
            // labels it on overlap, but it stays primary on its own address-only span.
            Recognizer::Address => 4,
            // The broad name HEURISTIC is least specific — it loses every overlap.
            Recognizer::Name => 5,
            // A CONTEXT-REQUIRED recognizer is the BROADEST shape (it is gated to a
            // keyword precisely BECAUSE its raw pattern is ambiguous), so it loses
            // every overlap with a normal recognizer (priority 6, > every non-context
            // recognizer above). This is LOAD-BEARING for the additive-only gate: when
            // a normal recognizer also covers a context-recognizer's span, the MERGE
            // keeps the normal recognizer as PRIMARY, so the finalization gate sees a
            // non-context primary and KEEPS the candidate (never removing a normal
            // match). A context-only span (no normal sibling) stays a `Context` primary
            // and is the only thing the gate can drop (and only with no keyword).
            Recognizer::Context(_) => 6,
        }
    }

    /// Stable label for the per-recognizer audit breakdown. Built-ins return a
    /// fixed lowercase tag; a custom recognizer returns its config-supplied name
    /// (audit-safe — a recognizer name, not a matched value).
    pub(crate) fn label(&self) -> &str {
        match self {
            Recognizer::Term => "term",
            Recognizer::Email => "email",
            Recognizer::Phone => "phone",
            Recognizer::Id => "id",
            Recognizer::Name => "name",
            Recognizer::CreditCard => "credit-card",
            Recognizer::Iban => "iban",
            Recognizer::Lei => "lei",
            Recognizer::Bic => "bic",
            Recognizer::Isin => "isin",
            Recognizer::Ip => "ip",
            Recognizer::Url => "url",
            Recognizer::Address => "address",
            Recognizer::Custom(name) => name,
            // The namespaced locale label (e.g. `sg:nric`) IS the recognizer name.
            Recognizer::Locale(name) => name,
            // The namespaced profile label (e.g. `pci-dss-cardholder:account-ref`).
            Recognizer::Profile(name) => name,
            // The `ctx:`-namespaced context-recognizer label (e.g. `ctx:ssn-undashed`).
            Recognizer::Context(name) => name,
        }
    }

    /// A HUMAN-READABLE TYPE name for the AI-safe LABELS (pseudonymization) mode, used to
    /// build a typed placeholder like `[email]` / `[Singapore ID]`. This is a PRESENTATION
    /// string (a recognizer category, never a matched value → confidentiality-safe), DISTINCT
    /// from the audit-/config-facing [`label`](Recognizer::label) — e.g. `label()` is
    /// `sg:nric`, here it reads `Singapore ID`.
    ///
    /// The signed-off mockup names the common types EXACTLY (`email`/`phone`/`Singapore ID`/
    /// `driver's license ID`/`credit card`/`IBAN`/`IP address`/`web address`/`ID`); for the
    /// many OPT-IN jurisdiction/compliance/context rows (each a `<ns>:<row>` namespaced
    /// label) a DETERMINISTIC fallback derives a readable type from the namespaced label so a
    /// new pack drops in WITHOUT touching this method (e.g. `us:ssn` → `US ID (ssn)`,
    /// `uk:driving-licence` → `driver's license ID`). The mapping is TOTAL + deterministic.
    ///
    /// NOTE: `Term` and `Name` are the ENTITY family (letters `[A]`, `[B]`, …) and are
    /// NEVER routed here — they have no typed label. This method is only ever called for a
    /// span whose merged PRIMARY recognizer is typed (see [`assign_labels`]); `Term`/`Name`
    /// return a defensive placeholder that the entity routing never uses.
    pub(crate) fn type_label(&self) -> String {
        // A namespaced locale/profile row whose tail names a common identifier class is
        // mapped to the SAME human type as its global sibling, so e.g. a UK driving licence
        // and an AU drivers-licence both read `driver's license ID`.
        fn from_namespaced(label: &str) -> String {
            // `<ns>:<row>` — split once on the FIRST colon (a profile label can carry a
            // second colon in the row part, which we keep verbatim in the readable tail).
            let (ns, row) = label.split_once(':').unwrap_or(("", label));
            // Common cross-jurisdiction identifier classes get a shared readable type.
            if row.contains("driv") {
                return "driver's license ID".to_string();
            }
            if row.contains("passport") {
                return "passport ID".to_string();
            }
            // A postal/ZIP code row (any jurisdiction) reads as the shared "postal code"
            // type, so an SG `postal`, a UK `postcode`, and a US `zip` all render the same.
            if row.contains("postal") || row.contains("postcode") || row.contains("zip") {
                return "postal code".to_string();
            }
            // A phone-family row (e.g. `ctx:phone-wrapped`) is a phone — render it as the
            // shared "phone" type, same as the global built-in.
            if row.contains("phone") {
                return "phone".to_string();
            }
            // A role-context NAME row (e.g. `ctx:role-name`) is a person name — render it
            // as the `name` type (NOT a generic `ID (...)`), matching the entity family's
            // human-facing intent even though it flows through the typed axis.
            if row.contains("name") {
                return "name".to_string();
            }
            match ns {
                "sg" => "Singapore ID".to_string(),
                "us" => format!("US ID ({row})"),
                "uk" => format!("UK ID ({row})"),
                "au" => format!("Australia ID ({row})"),
                "ca" => format!("Canada ID ({row})"),
                // A compliance-profile bespoke row or an unknown namespace: a generic but
                // deterministic readable type carrying the row name.
                _ => format!("ID ({row})"),
            }
        }
        match self {
            Recognizer::Email => "email".to_string(),
            Recognizer::Phone => "phone".to_string(),
            Recognizer::CreditCard => "credit card".to_string(),
            Recognizer::Iban => "IBAN".to_string(),
            Recognizer::Lei => "legal entity ID".to_string(),
            Recognizer::Bic => "BIC".to_string(),
            Recognizer::Isin => "ISIN".to_string(),
            Recognizer::Ip => "IP address".to_string(),
            Recognizer::Url => "web address".to_string(),
            Recognizer::Id => "ID".to_string(),
            Recognizer::Address => "address".to_string(),
            Recognizer::Locale(name) | Recognizer::Profile(name) | Recognizer::Context(name) => {
                from_namespaced(name)
            }
            // ENTITY family — never typed (routed to a letter by `assign_labels`). A
            // defensive value the entity routing never consumes.
            Recognizer::Term | Recognizer::Name | Recognizer::Custom(_) => "entity".to_string(),
        }
    }
}

impl std::fmt::Display for Recognizer {
    /// Renders a recognizer as its stable [`label`](Recognizer::label) — the bare
    /// fixed tag for a built-in, the config-supplied name for a `Custom`, the
    /// jurisdiction-namespaced name for a `Locale` (a recognizer name, never a
    /// matched value, so it is audit-safe).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}
