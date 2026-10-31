// SPDX-License-Identifier: AGPL-3.0-or-later
//! Map the inbox [`Worklist`](crate::Worklist) into the shared, inert
//! [`view`] types (the "cleaner structure" presentation seam).
//!
//! PURE: this submodule holds NO [`runtime::Core`] handle and touches no matter
//! data — it transforms an ALREADY-triaged worklist (built THROUGH the core) into
//! host-renderable [`view::Section`]s. The host composes these onto the home; this
//! module emits no markup, no script, and adds no capability/egress (mirrors
//! `search::SearchModule::present`, generalized).
//!
//! ## What the view reflects (the Phase-1 verdict, made visible)
//!
//! - the EXCERPT (first new body line) is the card TITLE; the subject is the
//!   SECONDARY subtitle (verdict #4);
//! - FACTUAL deadline PROXIMITY (a [`view::DueLabel`]), NOT the suppressed priority
//!   badge, under the unwired anchor (verdict DANGER fix #3); a priority badge is
//!   emitted ONLY when the producer could trust it (`Some(priority)`);
//! - an AMBIGUOUS date renders as a QUESTION; a relative/unresolved deadline as
//!   needs-confirm (verdict DANGER fixes #2 + #3);
//! - DEMOTED categories (Client/OpposingCounsel/InternalAdmin) are NOT badged —
//!   only [`Category::is_surfaced`](crate::Category::is_surfaced) ones are
//!   (verdict #5);
//! - the confidentiality / leak-vector flag becomes a ⚠ Warning badge (verdict #8);
//! - the protected-handling (privileged / without-prejudice) flag becomes a badge
//!   (verdict #9);
//! - the honest-limits [`Caveat`](crate::Caveat)s become section-level
//!   [`view::Caveat`] banners — INCLUDING "no date detected ≠ no deadline"
//!   (verdict DANGER fix #1).
//!
//! ## Confidentiality (unchanged)
//!
//! Card titles/subtitles carry the SAME cleartext (excerpt/subject) the worklist
//! already holds for in-process review — `view` adds no egress, so nothing can leave
//! the box. The audit split (counts-only) is untouched: this module never logs.

use crate::{
    Category, Caveat, Classification, ConfidentialityFlag, DeadlineProximity, Priority,
    ProtectedHandling, Worklist, WorklistItem,
};

/// The section heading for the single worklist section this increment emits. (The
/// host later RE-GROUPS cards by action/matter with a deadline rail per the
/// ratified layout — that composition is host code; this module hands it cards.)
const WORKLIST_TITLE: &str = "What's next";

/// Map a [`Worklist`] into host-renderable [`view::Section`]s. PURE + DETERMINISTIC.
///
/// This increment emits ONE section (titled [`WORKLIST_TITLE`]) carrying the
/// worklist's honest-limits caveats as banners and one [`view::Card`] per item, in
/// worklist order. The trusted host composes/re-groups these onto the home (the
/// action/matter grouping + deadline rail is host composition, not module logic).
pub fn to_view(worklist: &Worklist) -> Vec<view::Section> {
    let mut section = view::Section::new(WORKLIST_TITLE);
    section.caveats = worklist
        .caveats()
        .iter()
        .map(|c| caveat_to_view(*c))
        .collect();
    section.cards = worklist.items().iter().map(card_for).collect();
    vec![section]
}

/// Map one honest-limits [`Caveat`] to an inert [`view::Caveat`] banner (verbatim
/// message + stable id). The host renders it; it cannot be omitted.
fn caveat_to_view(caveat: Caveat) -> view::Caveat {
    view::Caveat::new(caveat.label(), caveat.message())
}

/// Build one inert [`view::Card`] from a worklist item, reflecting the Phase-1
/// presentation (see the module docs). PURE.
fn card_for(item: &WorklistItem) -> view::Card {
    view::Card {
        // Verdict #4: the EXCERPT (first new body line) leads; the subject is the
        // subtitle.
        title: item.excerpt.clone(),
        subtitle: item.subject_label.clone(),
        badges: badges_for(item),
        due: Some(due_label_for(item)),
        actions: actions_for(item),
    }
}

/// The badges to SURFACE for an item — only the trustworthy ones (verdict #5).
fn badges_for(item: &WorklistItem) -> Vec<view::Badge> {
    let mut badges = Vec::new();

    // The TRUSTED internal/external classifier (verdict KEEP #6) — always surfaced
    // when known (never when Unknown: do not fabricate).
    match item.classification {
        Classification::Internal => {
            badges.push(view::Badge::new(view::BadgeKind::Origin, "internal"));
        }
        Classification::External => {
            badges.push(view::Badge::new(view::BadgeKind::Origin, "external"));
        }
        Classification::Unknown => {}
    }

    // Category: ONLY surfaced (high-signal) categories get a badge (verdict #5).
    // Client/OpposingCounsel/InternalAdmin are demoted to invisible hints.
    if item.category.is_surfaced() {
        let label = match item.category {
            Category::CourtFiling => "court / filing",
            Category::Newsletter => "newsletter",
            // Unreachable: is_surfaced() is true only for the two above.
            _ => item.category.label(),
        };
        badges.push(view::Badge::new(view::BadgeKind::Category, label));
    }

    // Protected handling (verdict #9): a high-value, low-risk badge.
    match item.protected_handling {
        ProtectedHandling::WithoutPrejudice => {
            badges.push(view::Badge::new(
                view::BadgeKind::Protected,
                "without prejudice",
            ));
        }
        ProtectedHandling::Privileged => {
            badges.push(view::Badge::new(view::BadgeKind::Protected, "privileged"));
        }
        ProtectedHandling::None => {}
    }

    // Confidentiality / leak-vector warnings (verdict KEEP #8) — a genuine
    // lawyer-pleaser. Default-unflagged until the warnings seam is wired.
    if let Some(label) = confidentiality_badge_label(item.confidentiality) {
        badges.push(view::Badge::new(view::BadgeKind::Warning, label));
    }

    // M1 (silent-miss fix): when the message carries MORE THAN ONE distinct date, the
    // single shown deadline must NOT be read as the only date present. Surface a
    // VISIBLE ⚠ warning badge so the "review the other date(s)" fact is impossible to
    // miss (the DueLabel still shows the deterministically-chosen date). Cleartext-free
    // (a fixed label, never a matched date value).
    if item.multiple_dates_detected {
        badges.push(view::Badge::new(
            view::BadgeKind::Warning,
            "⚠ multiple dates detected — review",
        ));
    }

    // The priority badge is emitted ONLY when the producer could trust it
    // (Some(..)). Under NO_ANCHOR it is suppressed (None) — the DueLabel carries the
    // factual proximity instead (verdict DANGER fix #3).
    if let Some(priority) = item.priority {
        let label = match priority {
            Priority::High => "high",
            Priority::Normal => "normal",
            Priority::Low => "low",
        };
        badges.push(view::Badge::new(view::BadgeKind::Priority, label));
    }

    badges
}

/// The ⚠ warning label for a confidentiality flag, or `None` when unflagged. Bcc and
/// nested-message are reported together when both fire.
fn confidentiality_badge_label(flag: ConfidentialityFlag) -> Option<&'static str> {
    match (flag.bcc_present, flag.nested_message) {
        (true, true) => Some("⚠ Bcc + hidden attachment"),
        (true, false) => Some("⚠ Bcc"),
        (false, true) => Some("⚠ hidden attachment"),
        (false, false) => None,
    }
}

/// Map the factual [`DeadlineProximity`] (+ precision) onto an inert
/// [`view::DueLabel`]. HONEST: ambiguous → a QUESTION; unresolved → needs-confirm;
/// facts → factual text (verdict DANGER fixes #1/#2/#3).
fn due_label_for(item: &WorklistItem) -> view::DueLabel {
    match item.proximity {
        DeadlineProximity::Overdue { days } => view::DueLabel::new(
            view::DueKind::Overdue,
            format!("overdue by {days} day{}", plural(days)),
        ),
        DeadlineProximity::DueToday => view::DueLabel::new(view::DueKind::DueToday, "due today"),
        DeadlineProximity::DueInDays { days } => view::DueLabel::new(
            view::DueKind::DueSoon,
            format!("due in {days} day{}", plural(days)),
        ),
        // The date itself is a QUESTION — render both readings, never a single guess.
        DeadlineProximity::AmbiguousDate => view::DueLabel::new(
            view::DueKind::Ambiguous,
            "ambiguous date — confirm day/month",
        ),
        // A detected deadline we cannot resolve/measure yet — needs the received
        // time. NEVER shown as a resolved date (verdict DANGER fix #3).
        DeadlineProximity::NeedsAnchor => view::DueLabel::new(
            view::DueKind::NeedsConfirm,
            "deadline detected — confirm date (received time not available)",
        ),
        DeadlineProximity::VagueUrgency => {
            view::DueLabel::new(view::DueKind::Vague, "urgency cue — no date")
        }
        // "No date detected — deadline unclear" (user wording): neutral, not
        // reassuring; the section caveat carries the full honest limit.
        DeadlineProximity::NoDateDetected => view::DueLabel::new(
            view::DueKind::NeedsConfirm,
            "no date detected — deadline unclear",
        ),
    }
}

/// The editable-suggestion actions for an item — typed [`view::ActionRef`]s the HOST
/// routes (verdict KEEP #7: buckets are EDITABLE suggestions, the human curates).
/// The `target` is the stable provenance key (`doc_id|rule`) the host uses for the
/// dismiss/snooze overlay-on-recompute invariant (per the synthesis).
fn actions_for(item: &WorklistItem) -> Vec<view::ActionRef> {
    let target = provenance_key(item);
    vec![
        view::ActionRef::new("confirm", "Confirm", target.clone()),
        view::ActionRef::new("edit", "Edit", target.clone()),
        view::ActionRef::new("dismiss", "Dismiss", target),
    ]
}

/// The STABLE provenance key for an item: `doc:<id>|<rule-label>`. Cleartext-free
/// (an id + a rule NAME) and stable across re-triage, so the host's
/// dismiss/snooze overlay survives a deterministic recompute (the synthesis
/// invariant).
fn provenance_key(item: &WorklistItem) -> String {
    format!(
        "doc:{}|{}",
        item.provenance.doc_id,
        item.provenance.rule.label()
    )
}

/// "" for 1, "s" otherwise — for "1 day" vs "2 days".
fn plural(n: i64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dateparse::DueDate;
    use crate::{Provenance, Rule};
    use runtime::DataClass;

    /// A worklist item with sensible defaults the tests tweak.
    fn item() -> WorklistItem {
        WorklistItem {
            excerpt: "Please review the draft and revert.".to_string(),
            subject_label: "Re: Re: FW: Condor".to_string(),
            action: crate::Action::Review,
            priority: None,
            proximity: DeadlineProximity::NeedsAnchor,
            due_at: None,
            due_precision: crate::DuePrecision::None,
            due_ambiguous_alt: None,
            multiple_dates_detected: false,
            classification: Classification::External,
            category: Category::Unknown,
            protected_handling: ProtectedHandling::None,
            confidentiality: ConfidentialityFlag::default(),
            provenance: Provenance {
                doc_id: 1,
                class: DataClass::Document,
                rule: Rule::ReviewCue,
            },
        }
    }

    fn worklist_of(items: Vec<WorklistItem>) -> Worklist {
        let mut w = Worklist::default();
        for it in items {
            w.items.push(it);
        }
        w
    }

    #[test]
    fn to_view_carries_the_no_date_not_no_deadline_caveat() {
        // VERDICT DANGER fix #1: the section MUST carry the honest-limits banner as a
        // view::Caveat, including "no date detected ≠ no deadline".
        let sections = to_view(&worklist_of(vec![item()]));
        assert_eq!(sections.len(), 1);
        let ids: Vec<&str> = sections[0].caveats.iter().map(|c| c.id.as_str()).collect();
        assert!(
            ids.contains(&"deadlines-not-all-caught"),
            "the no-date caveat must be present: {ids:?}"
        );
        let banner = sections[0]
            .caveats
            .iter()
            .find(|c| c.id == "deadlines-not-all-caught")
            .unwrap();
        assert!(
            banner.message.to_lowercase().contains("deadline unclear"),
            "the caveat text must use the honest 'deadline unclear' wording: {:?}",
            banner.message
        );
    }

    #[test]
    fn card_leads_with_excerpt_subject_is_subtitle() {
        // VERDICT #4: the excerpt is the title; the subject is the subtitle.
        let sections = to_view(&worklist_of(vec![item()]));
        let card = &sections[0].cards[0];
        assert_eq!(card.title, "Please review the draft and revert.");
        assert_eq!(card.subtitle, "Re: Re: FW: Condor");
    }

    #[test]
    fn priority_badge_suppressed_when_none_present_when_some() {
        // VERDICT DANGER fix #3: no priority badge when suppressed (None); a badge
        // when the producer could trust it (Some).
        let suppressed = to_view(&worklist_of(vec![item()]));
        assert!(
            !suppressed[0].cards[0]
                .badges
                .iter()
                .any(|b| b.kind == view::BadgeKind::Priority),
            "no priority badge under suppression"
        );

        let mut high = item();
        high.priority = Some(Priority::High);
        let shown = to_view(&worklist_of(vec![high]));
        assert!(
            shown[0].cards[0]
                .badges
                .iter()
                .any(|b| b.kind == view::BadgeKind::Priority && b.label == "high"),
            "a trusted priority badge is surfaced"
        );
    }

    #[test]
    fn ambiguous_date_renders_as_a_question_not_a_date() {
        // VERDICT DANGER fix #2: an ambiguous date is a question.
        let mut it = item();
        it.proximity = DeadlineProximity::AmbiguousDate;
        it.due_precision = crate::DuePrecision::Ambiguous;
        let sections = to_view(&worklist_of(vec![it]));
        let due = sections[0].cards[0].due.as_ref().unwrap();
        assert_eq!(due.kind, view::DueKind::Ambiguous);
        assert!(
            due.text.to_lowercase().contains("confirm"),
            "asks to confirm: {:?}",
            due.text
        );
    }

    #[test]
    fn needs_anchor_renders_as_needs_confirm_not_resolved() {
        // VERDICT DANGER fix #3: a relative/unresolved deadline is needs-confirm.
        let sections = to_view(&worklist_of(vec![item()]));
        let due = sections[0].cards[0].due.as_ref().unwrap();
        assert_eq!(due.kind, view::DueKind::NeedsConfirm);
    }

    #[test]
    fn factual_proximity_renders_as_a_fact() {
        let mut overdue = item();
        overdue.proximity = DeadlineProximity::Overdue { days: 4 };
        let s = to_view(&worklist_of(vec![overdue]));
        let due = s[0].cards[0].due.as_ref().unwrap();
        assert_eq!(due.kind, view::DueKind::Overdue);
        assert_eq!(due.text, "overdue by 4 days");

        let mut one = item();
        one.proximity = DeadlineProximity::DueInDays { days: 1 };
        let s2 = to_view(&worklist_of(vec![one]));
        assert_eq!(
            s2[0].cards[0].due.as_ref().unwrap().text,
            "due in 1 day",
            "singular day"
        );
    }

    #[test]
    fn demoted_categories_are_not_badged_high_signal_are() {
        // VERDICT #5: Client/OpposingCounsel/InternalAdmin are not surfaced; only
        // CourtFiling/Newsletter get a category badge.
        for demoted in [
            Category::Client,
            Category::OpposingCounsel,
            Category::InternalAdmin,
        ] {
            let mut it = item();
            it.category = demoted;
            let s = to_view(&worklist_of(vec![it]));
            assert!(
                !s[0].cards[0]
                    .badges
                    .iter()
                    .any(|b| b.kind == view::BadgeKind::Category),
                "{demoted:?} must not be badged"
            );
        }
        let mut court = item();
        court.category = Category::CourtFiling;
        let s = to_view(&worklist_of(vec![court]));
        assert!(
            s[0].cards[0]
                .badges
                .iter()
                .any(|b| b.kind == view::BadgeKind::Category && b.label == "court / filing"),
            "CourtFiling is surfaced"
        );
    }

    #[test]
    fn confidentiality_flag_becomes_a_warning_badge() {
        // VERDICT KEEP #8: a Bcc / nested-message flag surfaces as a ⚠ badge.
        let mut it = item();
        it.confidentiality = ConfidentialityFlag {
            bcc_present: true,
            nested_message: true,
        };
        let s = to_view(&worklist_of(vec![it]));
        let warn = s[0].cards[0]
            .badges
            .iter()
            .find(|b| b.kind == view::BadgeKind::Warning)
            .unwrap();
        assert!(
            warn.label.contains("Bcc") && warn.label.contains("hidden"),
            "both vectors flagged: {:?}",
            warn.label
        );
    }

    #[test]
    fn multiple_dates_detected_surfaces_a_review_warning_badge() {
        // M1 (silent-miss fix): when the item carries more than one distinct date, the
        // view MUST surface a visible "multiple dates detected — review" warning badge
        // so the single shown date never reads as the only date present.
        let mut it = item();
        it.multiple_dates_detected = true;
        let s = to_view(&worklist_of(vec![it]));
        let warn = s[0].cards[0]
            .badges
            .iter()
            .find(|b| b.kind == view::BadgeKind::Warning && b.label.contains("multiple dates"));
        assert!(
            warn.is_some(),
            "the multiple-dates review warning is surfaced: {:?}",
            s[0].cards[0].badges
        );
    }

    #[test]
    fn single_date_item_has_no_multiple_dates_warning() {
        // M1: an item with ONE (or no) date must NOT carry the multiple-dates badge.
        let s = to_view(&worklist_of(vec![item()]));
        assert!(
            !s[0].cards[0]
                .badges
                .iter()
                .any(|b| b.label.contains("multiple dates")),
            "no multiple-dates warning for a single-date item: {:?}",
            s[0].cards[0].badges
        );
    }

    #[test]
    fn protected_handling_becomes_a_badge() {
        // VERDICT #9: a without-prejudice / privileged marker surfaces as a badge.
        let mut it = item();
        it.protected_handling = ProtectedHandling::WithoutPrejudice;
        let s = to_view(&worklist_of(vec![it]));
        assert!(
            s[0].cards[0]
                .badges
                .iter()
                .any(|b| b.kind == view::BadgeKind::Protected && b.label == "without prejudice"),
            "WP badge surfaced"
        );
    }

    #[test]
    fn actions_carry_the_stable_provenance_key() {
        // The host's dismiss/snooze overlay keys on doc_id+rule (the synthesis
        // invariant); the action target is that stable key, cleartext-free.
        let s = to_view(&worklist_of(vec![item()]));
        let actions = &s[0].cards[0].actions;
        assert!(
            actions.iter().all(|a| a.target == "doc:1|review-cue"),
            "stable provenance key"
        );
        assert!(
            actions.iter().any(|a| a.action_id == "dismiss"),
            "dismiss is an editable action"
        );
    }

    #[test]
    fn to_view_is_deterministic() {
        let w = worklist_of(vec![item()]);
        assert_eq!(to_view(&w), to_view(&w));
    }

    #[test]
    fn empty_worklist_still_carries_caveats() {
        // VERDICT DANGER fix #1: an empty worklist must NOT read as "nothing due" —
        // the caveats are still present.
        let sections = to_view(&Worklist::default());
        assert!(sections[0].cards.is_empty());
        assert!(
            !sections[0].caveats.is_empty(),
            "caveats present even with no items"
        );
    }

    /// Silence an unused-import lint if `DueDate` is not otherwise referenced.
    #[test]
    fn duedate_helper_compiles() {
        assert_eq!(DueDate::none().precision, crate::DuePrecision::None);
    }
}
