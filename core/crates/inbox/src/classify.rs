// SPDX-License-Identifier: AGPL-3.0-or-later
//! Internal-vs-external + message-category classification (DETERMINISTIC).
//!
//! PURE: no [`runtime::Core`] handle, no matter data — it classifies a sender
//! address string + a subject/body already read THROUGH the core by the
//! [`crate::Inbox`] engine. Independently unit-testable, like redaction's pure
//! recognizers.
//!
//! ## Honest framing
//!
//! - **DETERMINISTIC domain + keyword matching ONLY** (CLAUDE.md non-negotiable):
//!   a sender is INTERNAL iff its email domain is one of the firm's configured
//!   domains — a literal, case-insensitive domain compare, no model/heuristic
//!   guessing. The message [`Category`] is a fixed keyword/domain ruleset.
//! - **A classification is a PROPOSAL, not a trust boundary.** "internal" here is
//!   a triage hint for the worklist (e.g. de-prioritize a colleague's CC), NOT a
//!   security/privilege decision. The actual confidentiality boundary stays in
//!   the core (egress control + the matter store's entitlement filter), never in
//!   this label. Do not let a downstream caller treat "internal" as "safe".
//! - **Return [`Classification::Unknown`] / [`Category::Unknown`] when unsure.**
//!   The rules never FABRICATE a label they cannot justify from the address /
//!   keywords — an unparseable sender is `Unknown`, not guessed `External`.

/// The internal-vs-external triage label for a message's sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Sender domain matches a configured firm domain (a colleague).
    Internal,
    /// Sender domain is NOT a firm domain (counterparty, client, court, vendor…).
    External,
    /// The sender address could not be parsed into a domain to compare.
    Unknown,
}

/// A coarse, DETERMINISTIC message category derived from keyword/domain rules.
///
/// This is a triage HINT for the worklist (route a court email differently from a
/// newsletter), NEVER an authoritative or privileged label. The rules are
/// deliberately conservative: a message that matches no category rule (and has no
/// internal-sender fallback signal) is [`Category::Unknown`] — not fabricated into
/// a wrong bucket.
///
/// CHANGE (verdict #5): NOT every category is shown as a confident BADGE. The
/// keyword-only categories [`Category::Client`] and [`Category::OpposingCounsel`]
/// are too WRONG-PRONE on keyword evidence (a "your matter" or "the other side" in
/// quoted text mis-labels constantly), so they are DEMOTED to invisible/internal
/// HINTS — see [`is_surfaced`](Category::is_surfaced). Only the high-signal
/// [`Category::CourtFiling`]/[`Category::Newsletter`] (plus the trusted
/// internal/external classifier, which is separate) are surfaced as badges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Court / filing / hearing / registry correspondence (deadline-bearing).
    /// HIGH-SIGNAL — surfaced as a badge.
    CourtFiling,
    /// Acting-for-a-client cue (a firm↔client thread, identified by keyword cues).
    /// DEMOTED (verdict #5): an INTERNAL HINT only — too wrong-prone to show as a
    /// confident badge ([`is_surfaced`](Category::is_surfaced) == false).
    Client,
    /// From opposing counsel / the other side's solicitors. DEMOTED (verdict #5):
    /// an INTERNAL HINT only — too wrong-prone to show as a confident badge
    /// ([`is_surfaced`](Category::is_surfaced) == false). NOTE: privilege /
    /// without-prejudice handling is a SEPARATE flag ([`ProtectedHandling`]); a
    /// "without prejudice" line must NOT mis-bucket a message as OpposingCounsel.
    OpposingCounsel,
    /// Internal firm administration (IT, accounts, HR, all-staff). The LOWEST-signal
    /// bucket (an internal sender with no other cue). DEMOTED: an internal hint, not
    /// a surfaced badge — and (verdict #5) it must NOT bury a deadline-bearing
    /// internal email (the worklist keeps deadline salience regardless of category).
    InternalAdmin,
    /// A newsletter / bulletin / marketing / no-reply broadcast. HIGH-SIGNAL —
    /// surfaced as a badge (so the lawyer can de-prioritize/skip it confidently).
    Newsletter,
    /// No category rule matched with enough confidence.
    Unknown,
}

impl Category {
    /// Whether this category is trustworthy enough to show as a CONFIDENT BADGE.
    ///
    /// CHANGE (verdict #5): only the HIGH-SIGNAL categories are surfaced. The
    /// keyword-only [`Category::Client`]/[`Category::OpposingCounsel`] and the
    /// lowest-signal [`Category::InternalAdmin`] are demoted to invisible internal
    /// HINTS (the value is still carried for ordering/audit, just not badged). The
    /// presentation calls this to decide whether to render the category label.
    pub fn is_surfaced(self) -> bool {
        matches!(self, Category::CourtFiling | Category::Newsletter)
    }

    /// A stable, cleartext-free label for the audit breakdown / the row. A category
    /// NAME, never matched content — safe to log/show.
    pub fn label(self) -> &'static str {
        match self {
            Category::CourtFiling => "court-filing",
            Category::Client => "client",
            Category::OpposingCounsel => "opposing-counsel",
            Category::InternalAdmin => "internal-admin",
            Category::Newsletter => "newsletter",
            Category::Unknown => "unknown",
        }
    }
}

/// A DETERMINISTIC protected-handling flag derived from explicit privilege markers
/// in the text — a HIGH-VALUE, LOW-RISK signal (verdict #9).
///
/// "without prejudice" / "privileged and confidential" / "legally privileged" are
/// LITERAL markers a lawyer writes deliberately; detecting them is a reliable,
/// non-fabricating flag that this message needs protected handling (do not forward
/// carelessly; privilege/WP rules apply). Distinct from [`Category`]: it does NOT
/// claim the sender is opposing counsel — it only flags the handling posture.
///
/// HONEST FRAMING: this flags a MARKER the author wrote; it is NOT a determination
/// that privilege actually attaches (that is the lawyer's call). Absence of a marker
/// is NOT a claim the message is unprivileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectedHandling {
    /// No explicit privilege / without-prejudice marker detected.
    #[default]
    None,
    /// A "without prejudice" marker — settlement/negotiation correspondence.
    WithoutPrejudice,
    /// A "privileged and confidential" / "legally privileged" marker.
    Privileged,
}

impl ProtectedHandling {
    /// Whether a protected-handling marker was detected (either kind).
    pub fn is_flagged(self) -> bool {
        !matches!(self, ProtectedHandling::None)
    }

    /// A stable, cleartext-free label for the audit breakdown / the row.
    pub fn label(self) -> &'static str {
        match self {
            ProtectedHandling::None => "none",
            ProtectedHandling::WithoutPrejudice => "without-prejudice",
            ProtectedHandling::Privileged => "privileged",
        }
    }
}

/// Literal privilege markers, checked in PRIORITY order (most specific first). All
/// lowercase; matched as substrings of the lowercased subject + body. DETERMINISTIC.
const WITHOUT_PREJUDICE_MARKERS: &[&str] = &[
    "without prejudice",
    "off the record",
    "settlement privilege",
];
const PRIVILEGED_MARKERS: &[&str] = &[
    "privileged and confidential",
    "privileged & confidential",
    "legally privileged",
    "legal professional privilege",
    "attorney-client privilege",
    "attorney work product",
    "subject to legal privilege",
];

/// Detect the [`ProtectedHandling`] posture from explicit privilege markers in
/// `subject`+`body`. PURE + DETERMINISTIC. "without prejudice" takes precedence over
/// a generic privilege marker (it is the narrower, settlement-specific signal).
pub fn classify_protected_handling(subject: &str, body: &str) -> ProtectedHandling {
    let mut hay = String::with_capacity(subject.len() + body.len() + 1);
    hay.push_str(&subject.to_ascii_lowercase());
    hay.push(' ');
    hay.push_str(&body.to_ascii_lowercase());

    if WITHOUT_PREJUDICE_MARKERS.iter().any(|m| hay.contains(m)) {
        ProtectedHandling::WithoutPrejudice
    } else if PRIVILEGED_MARKERS.iter().any(|m| hay.contains(m)) {
        ProtectedHandling::Privileged
    } else {
        ProtectedHandling::None
    }
}

/// The set of firm email domains a sender is matched against. Held as NORMALIZED
/// owned strings (lowercased, leading `@`/whitespace stripped, empties dropped),
/// supplied by the trusted shell from firm config (NOT by a message).
#[derive(Debug, Clone, Default)]
pub struct FirmDomains {
    domains: Vec<String>,
}

impl FirmDomains {
    /// Build from an iterator of firm domains (e.g. `["acme-law.example"]`).
    /// NORMALIZES each entry (lowercase, strip a leading `@` and surrounding
    /// whitespace) and DROPS any entry that is empty after trimming, so a stray
    /// `""` / `"@"` can never match every sender.
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let domains = domains
            .into_iter()
            .map(|d| normalize_domain(&d))
            .filter(|d| !d.is_empty())
            .collect();
        Self { domains }
    }

    /// The configured (normalized) firm domains (borrowed).
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Whether `domain` (already normalized) is one of the firm's domains.
    fn contains(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| d == domain)
    }
}

/// Normalize a domain for a literal compare: trim whitespace, drop a single
/// leading `@` (so both `"acme.example"` and `"@acme.example"` config forms work),
/// trim again, and lowercase. No DNS / no model — a fixed string transform.
fn normalize_domain(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('@')
        .trim()
        .to_ascii_lowercase()
}

/// Parse the domain out of a sender address: the text after the FINAL `@`,
/// trimmed + lowercased. Returns `None` when there is no `@`, the address is
/// empty, or the domain part is empty — so an unparseable sender stays `Unknown`
/// rather than being guessed. Tolerates a display-name form
/// (`"Jane Roe <jane@acme.example>"`) by stripping a trailing `>`.
fn sender_domain(sender: &str) -> Option<String> {
    let s = sender.trim().trim_end_matches('>');
    let at = s.rfind('@')?;
    let domain = normalize_domain(&s[at + 1..]);
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Classify a sender address as internal/external against the firm's domains.
/// PURE + DETERMINISTIC.
///
/// Splits the address at the FINAL `@`, lowercases the domain, and compares it
/// LITERALLY against [`FirmDomains`]. A match → [`Classification::Internal`]; a
/// parsed non-matching domain → [`Classification::External`]; an address with no
/// parseable domain → [`Classification::Unknown`]. No model, no fuzzy matching.
pub fn classify_sender(sender: &str, firm: &FirmDomains) -> Classification {
    match sender_domain(sender) {
        Some(domain) if firm.contains(&domain) => Classification::Internal,
        Some(_) => Classification::External,
        None => Classification::Unknown,
    }
}

/// The deterministic category keyword rules, in PRIORITY order (first match
/// wins). Each entry is `(Category, &[needles])`; a needle is matched
/// case-insensitively as a substring of the lowercased `subject + " " + body`.
/// Court/filing cues are most specific (and most deadline-relevant), so they are
/// checked first; the broad newsletter cues are last. All needles are lowercase
/// (the haystack is lowercased once before matching).
const CATEGORY_RULES: &[(Category, &[&str])] = &[
    (
        Category::CourtFiling,
        &[
            "court",
            "filing",
            "filed",
            "hearing",
            "registry",
            "summons",
            "affidavit",
            "writ",
            "subpoena",
            "tribunal",
            "docket",
            "case no",
        ],
    ),
    (
        // DEMOTED (verdict #5): an internal HINT, never a surfaced badge. NOTE:
        // "without prejudice" was REMOVED from here — it is a privilege MARKER
        // ([`classify_protected_handling`]), not evidence the sender is opposing
        // counsel, and must not mis-bucket the message.
        Category::OpposingCounsel,
        &[
            "opposing counsel",
            "other side",
            "counterparty",
            "acting for the defendant",
            "acting for the plaintiff",
            "our respective clients",
        ],
    ),
    (
        Category::Client,
        &[
            "our client",
            "your matter",
            "your case",
            "engagement letter",
            "retainer",
            "instructions",
        ],
    ),
    (
        Category::InternalAdmin,
        &[
            "all staff",
            "all-staff",
            "it support",
            "helpdesk",
            "payroll",
            "timesheet",
            "expense claim",
            "human resources",
            "office closure",
            "maintenance window",
        ],
    ),
    (
        Category::Newsletter,
        &[
            "newsletter",
            "unsubscribe",
            "no-reply",
            "noreply",
            "bulletin",
            "do not reply",
            "webinar",
        ],
    ),
];

/// Classify a message into a coarse [`Category`] from deterministic keyword rules
/// over its subject+body, with the sender's internal/external status as a tie
/// signal. PURE + DETERMINISTIC.
///
/// Rules, in order:
/// 1. The first [`CATEGORY_RULES`] entry whose any needle appears (case-
///    insensitively) in `subject + body` wins.
/// 2. If NO keyword rule fires but the sender is INTERNAL, default to
///    [`Category::InternalAdmin`] (a colleague with no other signal is firm-
///    internal traffic — a hint, not a guarantee).
/// 3. Otherwise [`Category::Unknown`] — never fabricate a category.
pub fn classify_category(subject: &str, body: &str, classification: Classification) -> Category {
    let mut hay = String::with_capacity(subject.len() + body.len() + 1);
    hay.push_str(&subject.to_ascii_lowercase());
    hay.push(' ');
    hay.push_str(&body.to_ascii_lowercase());

    for (category, needles) in CATEGORY_RULES {
        if needles.iter().any(|n| hay.contains(n)) {
            return *category;
        }
    }
    // No keyword fired: a colleague's message with no other cue is internal-admin
    // traffic; anything else is honestly Unknown (never guessed).
    match classification {
        Classification::Internal => Category::InternalAdmin,
        _ => Category::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn firm() -> FirmDomains {
        FirmDomains::new(vec!["acme-law.example".to_string()])
    }

    #[test]
    fn internal_sender_matches_firm_domain() {
        assert_eq!(
            classify_sender("partner@acme-law.example", &firm()),
            Classification::Internal
        );
        // Case-insensitive domain compare.
        assert_eq!(
            classify_sender("Partner@ACME-LAW.EXAMPLE", &firm()),
            Classification::Internal
        );
        // Display-name form is tolerated.
        assert_eq!(
            classify_sender("Jane Partner <jane@acme-law.example>", &firm()),
            Classification::Internal
        );
    }

    #[test]
    fn external_sender_is_a_non_firm_domain() {
        assert_eq!(
            classify_sender("counsel@other.example", &firm()),
            Classification::External
        );
        assert_eq!(
            classify_sender("clerk@courts.example", &firm()),
            Classification::External
        );
    }

    #[test]
    fn unparseable_sender_is_unknown() {
        // No '@' at all, or an empty domain part — never guessed External.
        assert_eq!(
            classify_sender("not-an-address", &firm()),
            Classification::Unknown
        );
        assert_eq!(
            classify_sender("trailing@", &firm()),
            Classification::Unknown
        );
        assert_eq!(classify_sender("", &firm()), Classification::Unknown);
    }

    #[test]
    fn firm_domains_are_normalized_and_empties_dropped() {
        // A leading '@', mixed case, surrounding whitespace, and a junk empty are
        // all normalized/dropped so they cannot mis-match.
        let f = FirmDomains::new(vec![
            "  @Acme-Law.Example  ".to_string(),
            "".to_string(),
            "@".to_string(),
        ]);
        assert_eq!(f.domains(), ["acme-law.example"]);
        // The dropped empty entry must NOT make every sender internal.
        assert_eq!(
            classify_sender("x@other.example", &f),
            Classification::External
        );
    }

    #[test]
    fn category_court_filing_wins_first() {
        let c = classify_category(
            "Hearing date for case no 2026/0042",
            "The registry has fixed the hearing.",
            Classification::External,
        );
        assert_eq!(c, Category::CourtFiling);
    }

    #[test]
    fn category_newsletter_detected() {
        let c = classify_category(
            "Monthly bulletin",
            "Click here to unsubscribe.",
            Classification::External,
        );
        assert_eq!(c, Category::Newsletter);
    }

    #[test]
    fn category_internal_admin_default_for_internal_with_no_keyword() {
        // An internal colleague with no category keyword falls to InternalAdmin.
        let c = classify_category("lunch?", "anyone free at noon", Classification::Internal);
        assert_eq!(c, Category::InternalAdmin);
    }

    #[test]
    fn category_unknown_when_external_and_no_keyword() {
        // External + no keyword must be honestly Unknown, never fabricated.
        let c = classify_category("hi", "checking in", Classification::External);
        assert_eq!(c, Category::Unknown);
    }

    #[test]
    fn high_signal_categories_are_surfaced_demoted_ones_are_not() {
        // CHANGE (verdict #5): only CourtFiling/Newsletter are surfaced as confident
        // badges; the wrong-prone Client/OpposingCounsel and the lowest-signal
        // InternalAdmin are demoted to invisible internal hints.
        assert!(Category::CourtFiling.is_surfaced());
        assert!(Category::Newsletter.is_surfaced());
        assert!(!Category::Client.is_surfaced(), "Client demoted to a hint");
        assert!(
            !Category::OpposingCounsel.is_surfaced(),
            "OpposingCounsel demoted to a hint"
        );
        assert!(
            !Category::InternalAdmin.is_surfaced(),
            "InternalAdmin is a hint"
        );
        assert!(!Category::Unknown.is_surfaced());
    }

    #[test]
    fn without_prejudice_is_protected_handling_not_opposing_counsel() {
        // MISSING (verdict #9): "without prejudice" flags protected handling but must
        // NOT mis-bucket the message as OpposingCounsel.
        let subject = "Re: settlement";
        let body = "Without prejudice — we propose to settle for the sum discussed.";
        assert_eq!(
            classify_protected_handling(subject, body),
            ProtectedHandling::WithoutPrejudice
        );
        // The category does NOT become OpposingCounsel just from "without prejudice".
        let c = classify_category(subject, body, Classification::External);
        assert_ne!(
            c,
            Category::OpposingCounsel,
            "WP marker must not imply opposing counsel"
        );
    }

    #[test]
    fn privileged_marker_is_flagged() {
        assert_eq!(
            classify_protected_handling("Advice", "Privileged and confidential: our view is…"),
            ProtectedHandling::Privileged
        );
        assert_eq!(
            classify_protected_handling("Memo", "This note is legally privileged."),
            ProtectedHandling::Privileged
        );
        assert!(ProtectedHandling::Privileged.is_flagged());
    }

    #[test]
    fn no_privilege_marker_is_none_not_fabricated() {
        let p = classify_protected_handling("Re: lunch", "see you at noon");
        assert_eq!(p, ProtectedHandling::None);
        assert!(!p.is_flagged(), "absence of a marker is not a flag");
    }

    #[test]
    fn without_prejudice_takes_precedence_over_generic_privilege() {
        // Both markers present: WP (the narrower, settlement-specific) wins.
        let p = classify_protected_handling(
            "Re: dispute",
            "Without prejudice and privileged and confidential.",
        );
        assert_eq!(p, ProtectedHandling::WithoutPrejudice);
    }
}
