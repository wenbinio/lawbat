// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compliance PROFILE axis — a named bundle of recognizers + an HONEST
//! human-review-gap list, sitting ALONGSIDE the [`Locale`](crate::Locale)
//! jurisdiction axis.
//!
//! ## What a profile is (vs. a jurisdiction)
//!
//! A [`Locale`](crate::Locale) answers "which jurisdiction's national IDs am I
//! exposed to". A [`Profile`] answers "which COMPLIANCE REGIME am I preparing
//! content for" (PCI-DSS, and — in the fan-out — HIPAA / GDPR / GLBA). A profile:
//!
//! 1. SELECTS a set of recognizer rows to enable. A profile can (i) require specific
//!    GLOBAL built-ins be on (e.g. PCI needs the credit-card/Luhn recognizer), and/or
//!    (ii) carry its OWN profile-specific rows ([`ProfileRecognizer`]) — namespaced
//!    `profile:<name>:<row>` in the audit breakdown so they never collide with a
//!    `locale:` or `custom:` bucket. (Rows SHARED FROM a jurisdiction keep their
//!    `locale:<…>` label — a profile that wants SG NRICs pairs `.profiles([..])` with
//!    `.locales([Locale::Singapore])`; it does not re-label the locale rows.)
//! 2. Carries an explicit, HONEST [`human_review_gaps`](ProfileSpec::human_review_gaps)
//!    list — identifier categories the DETERMINISTIC engine cannot cover, that MUST be
//!    surfaced to the reviewer. NOTE (address/name coverage, since the address family +
//!    role-context-name rows landed): the engine now DETERMINISTICALLY covers the
//!    STRUCTURED subset — number+street+suffix / floor-unit / PO-Box addresses
//!    (`Recognizer::Address`), locale POSTAL codes (the `packs::*` postal rows), and
//!    role-context PERSON NAMES in a labelled list (`ctx:role-name`). What remains a
//!    reviewer gap is the UNSTRUCTURED residue: FREE-TEXT / prose addresses with no
//!    number+suffix shape, and UNLABELLED person names carrying no honorific, no role
//!    heading, and not supplied as a TERM. This is the project's "reasonable-efforts,
//!    never safe-to-send" posture turned into a TYPED contract: a profile cannot silently
//!    claim to handle what string-matching fundamentally can't.
//!
//! ## Scope of THIS increment (structure + ONE worked example)
//!
//! Only [`Profile::PciDssCardholder`] is built — and it is deliberately the SIMPLEST
//! possible proof of the axis: it needs NO new jurisdiction rows and NO
//! profile-specific rows; it just force-enables the EXISTING credit-card (Luhn)
//! recognizer and lists its gaps. HIPAA/GDPR/GLBA are NOT built here — HIPAA in
//! particular needs US national-ID rows that land with the jurisdiction fan-out.
//!
//! ## ADDING A PROFILE later (mirrors "ADDING A JURISDICTION")
//!
//! 1. add a variant to [`Profile`];
//! 2. add its arm in [`Profile::spec`] returning a [`ProfileSpec`] (its required
//!    built-ins, its `rows()`, and its `human_review_gaps`).
//!
//! That is the whole diff for a profile with no bespoke rows. A profile that DOES need
//! its own rows adds a `&[ProfileRecognizer { .. }]` table in this file (or its own
//! `packs/profiles/<name>.rs` if it grows) — never a new `Recognizer` variant.

use crate::BuiltinRecognizers;

/// One profile-specific recognizer, as DATA — the profile-axis twin of
/// [`LocaleRecognizer`](super::LocaleRecognizer). A static row gives its short `name`
/// (e.g. `account-ref`), its regex `pattern`, and an OPTIONAL `validate` checksum
/// predicate (the same recall-first contract: `None` = format-only).
///
/// The recognizer's audit/attribution label is the profile-NAMESPACED form
/// `<profile>:<name>` (e.g. `pci-dss-cardholder:account-ref`), assembled in
/// [`RedactionEngine::base`](crate::RedactionEngine); the row stores only the bare
/// `name`. The PCI worked example has ZERO of these (it reuses the global card
/// recognizer), but the type exists so a fan-out profile can add bespoke rows with no
/// shared-code churn.
#[derive(Debug, Clone, Copy)]
pub struct ProfileRecognizer {
    /// The bare recognizer name within the profile (e.g. `account-ref`). The
    /// namespaced label `<profile>:<name>` is built from this + the [`Profile`].
    pub name: &'static str,
    /// The (static, known-good) regex source for the identifier shape.
    pub pattern: &'static str,
    /// Optional checksum validator (recall-first; `None` = format-only).
    pub validate: Option<fn(&str) -> bool>,
}

/// A compliance profile whose recognizers + review-gap contract can be enabled as a
/// named bundle, ALONGSIDE the [`Locale`](crate::Locale) packs.
///
/// `#[non_exhaustive]` ON PURPOSE (like [`Locale`](crate::Locale)): adding a profile
/// later is a non-breaking change that nonetheless FORCES downstream `match`es to
/// carry a wildcard arm, so a new profile can never silently fall through an
/// exhaustive caller match.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// PCI-DSS cardholder-data prep (the worked example). Enables the existing
    /// credit-card (Luhn) recognizer; adds NO bespoke rows; lists the cardholder-data
    /// elements deterministic matching cannot cover (cardholder name, non-PAN account
    /// references) as human-review gaps.
    PciDssCardholder,
}

impl Profile {
    /// Every [`Profile`] variant, for exhaustive iteration by a caller (e.g. a label
    /// round-trip / parser-coverage test). See [`Locale::ALL`](crate::Locale::ALL) for
    /// the same pattern; the companion [`assert_all_covers_profile`] is the compile-time
    /// guard that fails to build if a variant is added but not appended here.
    pub const ALL: &'static [Profile] = &[Profile::PciDssCardholder];

    /// The short stable label for this profile (the namespace PREFIX used in a
    /// profile recognizer's name AND in the audit `profile:<label>` form). Lowercase,
    /// audit-safe, and stable across the breakdown delimiters (no `=`/`,`/`[`/`]`).
    pub fn label(self) -> &'static str {
        self.spec().name
    }

    /// This profile's specification: the built-ins it requires on, its
    /// profile-specific rows, and its honest human-review gaps. The `match` is
    /// EXHAUSTIVE over [`Profile`], so adding a variant forces a new arm here at
    /// COMPILE time — a profile can never ship without declaring its gaps.
    pub fn spec(self) -> ProfileSpec {
        match self {
            Profile::PciDssCardholder => ProfileSpec {
                name: "pci-dss-cardholder",
                // PCI cardholder-data prep is, deterministically, the PAN: force the
                // credit-card (Luhn) recognizer ON regardless of the engine's builtin
                // toggles. Everything else PCI cares about is a human-review gap.
                required_builtins: PCI_REQUIRED_BUILTINS,
                // No bespoke rows — the global card recognizer already covers the PAN.
                rows: &[],
                // HONEST gaps: what the DETERMINISTIC engine does NOT cover and which
                // therefore stay the reviewer's responsibility. Never claim these are
                // handled (the "reasonable-efforts, never safe-to-send" posture).
                human_review_gaps: &[
                    "cardholder name",
                    "non-PAN account references",
                    "service codes / expiry printed in free text",
                ],
            },
        }
    }
}

/// COMPILE-TIME exhaustiveness guard for [`Profile::ALL`]: an EXHAUSTIVE match over every
/// variant. Adding a `Profile` variant WITHOUT also appending it to `Profile::ALL` fails to
/// compile here — the reminder to update `ALL` (and the redact-cli `parse_profile` round-trip
/// test). Never called; its existence is the check. (See `assert_all_covers_locale`.)
#[allow(dead_code)]
fn assert_all_covers_profile(p: Profile) {
    match p {
        Profile::PciDssCardholder => {}
    }
}

/// The "force these built-ins ON" set for [`Profile::PciDssCardholder`]: just the
/// credit-card (Luhn) recognizer. A `const` so the [`ProfileSpec`] can borrow it with
/// a `'static` lifetime.
const PCI_REQUIRED_BUILTINS: BuiltinRecognizers = BuiltinRecognizers {
    email: false,
    phone: false,
    id: false,
    name: false,
    credit_card: true,
    iban: false,
    bic: false,
    isin: false,
    ip: false,
    url: false,
    address: false,
};

/// The resolved specification of a [`Profile`]: what it enables and — crucially —
/// what it HONESTLY does not. Returned by [`Profile::spec`]; surfaced to the
/// caller/reviewer through the engine so a UI can render "this profile deterministically
/// covers X; these categories still need human review".
#[derive(Debug, Clone, Copy)]
pub struct ProfileSpec {
    /// The profile's short stable label (the `profile:<name>` namespace prefix).
    pub name: &'static str,
    /// Built-ins this profile REQUIRES enabled. OR-merged into the engine's active
    /// built-in set at construction, so a profile's coverage holds even if the caller
    /// otherwise disabled that recognizer (a PCI engine always runs the card recognizer).
    pub required_builtins: BuiltinRecognizers,
    /// The profile's bespoke recognizer rows (namespaced `profile:<name>:<row>`).
    /// Empty for the PCI worked example.
    pub rows: &'static [ProfileRecognizer],
    /// HONEST human-review gaps — identifier categories the deterministic engine
    /// CANNOT cover, which MUST be surfaced to the reviewer (never silently claimed
    /// as handled). The typed form of "reasonable-efforts, never safe-to-send".
    pub human_review_gaps: &'static [&'static str],
}

impl ProfileSpec {
    /// The honest human-review gaps for this profile — the categories the reviewer
    /// must still handle by judgment. The accessor a host/UI calls to show "covered X;
    /// these still need a human".
    pub fn human_review_gaps(&self) -> &'static [&'static str] {
        self.human_review_gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_profile_shape() {
        let spec = Profile::PciDssCardholder.spec();
        assert_eq!(spec.name, "pci-dss-cardholder");
        assert_eq!(Profile::PciDssCardholder.label(), "pci-dss-cardholder");
        // PCI forces the credit-card recognizer ON and nothing else.
        assert!(spec.required_builtins.credit_card);
        assert!(!spec.required_builtins.email);
        assert!(!spec.required_builtins.iban);
        // No bespoke rows — it reuses the global card recognizer.
        assert!(spec.rows.is_empty());
    }

    #[test]
    fn pci_profile_surfaces_honest_gaps() {
        let gaps = Profile::PciDssCardholder.spec().human_review_gaps();
        assert!(!gaps.is_empty(), "a profile must surface its review gaps");
        assert!(
            gaps.iter().any(|g| g.contains("cardholder name")),
            "PCI must flag cardholder name as a human-review gap, got {gaps:?}"
        );
    }

    #[test]
    fn profile_label_is_breakdown_safe() {
        // The label is rendered into the parseable audit breakdown as
        // `profile:<label>:<row>=N`, so it must avoid the breakdown delimiters.
        let label = Profile::PciDssCardholder.label();
        assert!(
            !label
                .chars()
                .any(|c| matches!(c, '=' | ',' | '[' | ']') || c.is_ascii_control()),
            "profile label must be free of breakdown delimiters / control chars"
        );
    }
}
