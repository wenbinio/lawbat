// SPDX-License-Identifier: AGPL-3.0-or-later
//! # `viewgen` — the host-wiring JSON CLI (the THIN subprocess/JSON boundary).
//!
//! The ratified "cleaner structure": the Python shell RENDERS the Rust `view`-model
//! over a thin subprocess/JSON boundary — **NO Rust HTTP server, NO pyo3**. This
//! binary is the Rust side of that boundary. It:
//!
//!   1. seeds a SYNTHETIC matter (≈7 emails, NO real matter data — CLAUDE.md
//!      non-negotiable) into an [`InMemoryMatterStore`] as `document`-class text;
//!   2. builds a real trusted [`runtime::Core`] granting `matter.read:document`
//!      (+ ungated `audit.note`) — the SAME mediated, entitlement-filtered, audited
//!      path a shipped module uses;
//!   3. runs [`inbox::Inbox::build_worklist`] (reads each email THROUGH the core,
//!      triages it deterministically), maps the worklist into the inert
//!      [`view::Section`]s via [`inbox::to_view`] (which `Worklist::to_view` calls);
//!   4. wraps the sections in the host contract root and prints the JSON to stdout.
//!
//! ## The host contract (built to EXACTLY — the Python side renders this)
//!
//! ```json
//! { "schema":"firmos.view/0", "generated_label":"<date string>",
//!   "sections":[ { "title":str, "caveats":[{ "id":str,"message":str,"dismissible":bool }],
//!     "cards":[ { "title":str, "subtitle":str,
//!       "badges":[{ "kind":str, "label":str }],
//!       "due":{ "kind":str, "text":str }|null,
//!       "actions":[{ "action_id":str, "label":str, "target":str }] } ] } ] }
//! ```
//!
//! The `sections` array IS `serde`-serialized [`view::Section`]s (the `view` crate's
//! optional `serde` feature); this crate only adds the contract ROOT around them. The
//! enum `kind` strings come from the view enums' `rename_all = "snake_case"` mapping
//! (`BadgeKind::Origin` → `"origin"`, `DueKind::NeedsConfirm` → `"needs_confirm"`, …).
//!
//! ## Determinism (load-bearing)
//!
//! NO wall clock anywhere: the audit chain is keyed/stamped by an injected
//! [`FixedClock`], the engine triages under the deterministic [`inbox::NO_ANCHOR`]
//! sentinel, and `generated_label` is a FIXED placeholder derived from the seed's
//! reference date — so the same run emits BYTE-IDENTICAL JSON.
//!
//! ## Honest framing (NO_ANCHOR — why no "overdue / due today" facts)
//!
//! [`inbox::Inbox::build_worklist`] reads email as the `document` class and has no
//! per-message received-time yet (the metadata seam is unwired), so it triages under
//! [`inbox::NO_ANCHOR`]: the priority badge is SUPPRESSED and a detected deadline
//! surfaces as the honest `needs_confirm` proximity, NEVER a fabricated "due in N
//! days". So the demonstrated `due` kinds are `needs_confirm` (detected/explicit/
//! relative deadlines + no-date), `ambiguous` (an irreducibly ambiguous numeric
//! date), and `vague` (an urgency cue). The factual kinds (`overdue` / `due_today` /
//! `due_soon`) return once the received-time anchor is wired — viewgen does not fake
//! them. (`Worklist`'s fields are private, so the ONLY way to populate one is the
//! real `build_worklist` path — there is no out-of-crate shortcut to inject a
//! real-anchor worklist, which keeps this CLI honest about the NO_ANCHOR limit.)

use std::process::ExitCode;

use inbox::{FirmDomains, Inbox};
use runtime::{
    Capability, Core, CoreContext, CoreResult, DataClass, FixedClock, GrantSet, InMemoryAudit,
    InMemoryEgress, InMemoryMatterStore, InMemoryStorage, StorageScope,
};

/// The host contract schema tag (the Python side keys its renderer on this).
const SCHEMA: &str = "firmos.view/0";

/// The email data class the inbox engine reads (email IS the `document` class).
const EMAIL_CLASS: DataClass = DataClass::Document;

/// The firm's own email domain, for internal/external classification. A SYNTHETIC
/// example domain — never a real firm.
const FIRM_DOMAIN: &str = "acme-law.example";

/// A FIXED reference instant for the deterministic audit clock: 2026-06-19 00:00 UTC
/// (a Friday), as epoch-ms (the `FixedClock` takes `u64`). Used ONLY for the audit
/// timestamp + as the basis of `generated_label`; the engine itself triages under
/// [`inbox::NO_ANCHOR`] (see the module docs).
const REFERENCE_MS: u64 = 1_781_827_200_000;

/// The deterministic, wall-clock-FREE `generated_label`: the seed's reference date
/// rendered in a stable host-style form. NOT read from `now()` — a fixed placeholder
/// so the emitted JSON is byte-identical run to run (the real host will format the
/// actual generation time in the OS region; this is the seed's stand-in).
fn generated_label() -> String {
    // The reference instant is the fixed 2026-06-19 anchor (see REFERENCE_MS). Render
    // it as a stable, human-readable date string. Deterministic literal — never the
    // wall clock.
    "19 June 2026".to_string()
}

/// The host contract ROOT wrapped around the inert [`view::Section`]s. Serializes to
/// `{ "schema": .., "generated_label": .., "sections": [..] }` — the `sections` are
/// the `serde`-serialized view-model (the `view` crate's optional `serde` feature);
/// this crate only adds the three root fields. Borrows the sections (no clone).
#[derive(serde::Serialize)]
struct ContractRoot<'a> {
    schema: &'a str,
    generated_label: String,
    sections: &'a [view::Section],
}

/// The synthetic seed corpus: (doc_id, RFC822-ish email text). NO real matter data
/// (CLAUDE.md non-negotiable) — every address/name/figure is a fabricated `*.example`
/// placeholder. Each item exercises a different verdict path end-to-end:
///
/// 1. an OVERDUE court-filing from external counsel (explicit past date + a court
///    cue) — surfaces an `external` + `court / filing` badge; under NO_ANCHOR its
///    proximity is the honest `needs_confirm` (the date is detected; the "overdue by
///    N days" FACT needs the received-time anchor);
/// 2. a DUE-TODAY client request WITH a Bcc warning — a review cue + an explicit date
///    (proximity `needs_confirm` under NO_ANCHOR). NOTE: the Bcc leak-vector badge is
///    propagated from the extractor's warnings, a seam not yet wired into the inbox
///    (see `inbox::ConfidentialityFlag`), so it does not surface here — documented,
///    never faked;
/// 3. an INTERNAL email naming a deadline — an `internal` origin badge + a detected
///    deadline (`needs_confirm`);
/// 4. a FEE NOTE (Pay) due in a few days — a payment cue (Pay action) + a relative
///    deadline (`needs_confirm` under NO_ANCHOR);
/// 5. a NO-DATE "without prejudice" item with a nested attachment — a `without
///    prejudice` protected-handling badge; no date detected (`needs_confirm` with the
///    "no date detected" text). The nested-attachment leak vector travels the same
///    unwired warnings seam as the Bcc one (see #2);
/// 6. a NEWSLETTER — a `newsletter` category badge; a vague urgency cue (`vague`);
/// 7. a MULTIPLE-DATES item — two distinct date spans, so the `⚠ multiple dates
///    detected — review` warning badge surfaces (the single shown date never reads as
///    the only date present).
fn synthetic_emails() -> Vec<(u64, &'static str)> {
    vec![
        // 1. Overdue court filing, external counsel, explicit (past) date + court cue.
        (
            1,
            "From: clerk@court-registry.example\r\n\
Subject: Notice of filing — Acme v Beta, case no 2026/0042\r\n\
\r\n\
The registry records that your defence was due to be filed by 2026-06-12. \
Please confirm the position by return.",
        ),
        // 2. Due-today client request WITH a Bcc header + a review cue + explicit date.
        (
            2,
            "From: ceo@acme-holdings.example\r\n\
Subject: Re: Re: FW: Project Condor — draft SPA\r\n\
Bcc: assistant@acme-holdings.example\r\n\
\r\n\
Please review the attached draft SPA and revert by 2026-06-19. \
Could you confirm the closing figure?",
        ),
        // 3. Internal colleague naming a deadline.
        (
            3,
            "From: para.legal@acme-law.example\r\n\
Subject: Diary — long-stop date\r\n\
\r\n\
For the file: the long-stop date in the engagement is 2026-09-30. \
Diarise accordingly.",
        ),
        // 4. Fee note (Pay) due in a few days (relative deadline).
        (
            4,
            "From: billing@costs-counsel.example\r\n\
Subject: Fee note 0042 — amount due\r\n\
\r\n\
Our fee note is attached. Amount due: 4,200. Please pay within 7 days.",
        ),
        // 5. No-date "without prejudice" item with a nested forwarded message.
        (
            5,
            "From: solicitor@other-side.example\r\n\
Subject: Re: settlement discussions\r\n\
\r\n\
Without prejudice — we set out our client's position below. \
See the forwarded message for the earlier exchange.\n\n\
-----Original Message-----\nFrom: solicitor@other-side.example\nan earlier note",
        ),
        // 6. Newsletter (vague urgency cue, no real date).
        (
            6,
            "From: no-reply@legal-bulletin.example\r\n\
Subject: This week's legal bulletin\r\n\
\r\n\
Our monthly newsletter is out. Register for the webinar ASAP. \
To unsubscribe, click here.",
        ),
        // 7. Multiple distinct dates in one message (the ⚠ multiple-dates badge).
        (
            7,
            "From: counsel@other.example\r\n\
Subject: Appeal window\r\n\
\r\n\
The order was sealed 2026-01-05; file your appeal by next Friday.",
        ),
    ]
}

/// The concrete `Core` composition viewgen wires (the default in-memory seams).
type ViewgenCore = Core<
    GrantSet,
    InMemoryAudit,
    InMemoryStorage,
    InMemoryEgress,
    CoreContext,
    InMemoryMatterStore,
>;

/// Seed the synthetic matter into an [`InMemoryMatterStore`] (all `document`-class).
fn seeded_store() -> InMemoryMatterStore {
    let mut store = InMemoryMatterStore::new();
    for (id, text) in synthetic_emails() {
        store.insert(id, EMAIL_CLASS, text);
    }
    store
}

/// Build a trusted [`Core`] granting the inbox engine's capabilities over the seeded
/// matter: `matter.read:document` (the enforced, audited read path) + the ungated
/// `audit.note` (the per-run counts/breakdown). DELIBERATELY NO egress grant — the
/// engine holds none, so the cleartext worklist can never leave the box.
fn build_core() -> ViewgenCore {
    let grants = GrantSet::from_manifest(vec![
        Capability::MatterRead(EMAIL_CLASS),
        Capability::Storage(StorageScope::Own),
        Capability::AuditNote,
        // No Capability::Egress(..): the worklist is in-process only.
    ]);
    Core::new(
        // Host-pinned module identity (a module never names its own id).
        "sg.firmos.inbox",
        grants,
        // Deterministic audit: a fixed clock so timestamps (and the run) reproduce.
        InMemoryAudit::with_clock(FixedClock::new(REFERENCE_MS)),
        InMemoryStorage::new(),
        InMemoryEgress::new(),
        // A SYNTHETIC matter + acting user (no real matter data).
        CoreContext::new("Acme v Beta (demo)", "j.smith"),
        seeded_store(),
    )
}

/// Build the worklist through the real brokered path and render the contract JSON.
/// Returns the pretty-printed JSON string. PURE compute + DETERMINISTIC; any core
/// refusal (un-granted class / read) propagates fail-closed as a `CoreResult` error.
fn render_contract_json() -> CoreResult<String> {
    let mut core = build_core();
    let engine = Inbox::new(FirmDomains::new(vec![FIRM_DOMAIN.to_string()]));

    // Read each email THROUGH the core (mediated, entitlement-filtered, audited) and
    // triage it deterministically. `to_view` maps the worklist into inert sections.
    let worklist = engine.build_worklist(&mut core)?;
    let sections: Vec<view::Section> = worklist.to_view();

    let root = ContractRoot {
        schema: SCHEMA,
        generated_label: generated_label(),
        sections: &sections,
    };

    // Pretty-print for human readability over the boundary; serde_json's output is
    // deterministic (the view shapes have a fixed field order), so the bytes are
    // stable run to run. serde_json builds the string in memory; we write it out.
    serde_json::to_string_pretty(&root)
        .map_err(|e| runtime::CoreError::Backend(format!("serialize view contract to JSON: {e}")))
}

fn main() -> ExitCode {
    match render_contract_json() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // A clear stderr message + a non-zero exit on failure (the Python shell
            // distinguishes a clean JSON stdout from a failed run by the exit code).
            eprintln!("viewgen: failed to emit the view contract: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Parse the emitted contract JSON once for the assertions below.
    fn emitted() -> Value {
        let json = render_contract_json().expect("viewgen renders the contract");
        serde_json::from_str(&json).expect("emitted JSON parses")
    }

    /// Collect every `due.kind` string across all cards in all sections.
    fn due_kinds(root: &Value) -> Vec<String> {
        let mut kinds = Vec::new();
        for section in root["sections"].as_array().expect("sections is an array") {
            for card in section["cards"].as_array().expect("cards is an array") {
                if let Some(kind) = card["due"]["kind"].as_str() {
                    kinds.push(kind.to_string());
                }
            }
        }
        kinds
    }

    /// Collect every `badge.kind` string across all cards.
    fn badge_kinds(root: &Value) -> Vec<String> {
        let mut kinds = Vec::new();
        for section in root["sections"].as_array().unwrap() {
            for card in section["cards"].as_array().unwrap() {
                for badge in card["badges"].as_array().unwrap() {
                    kinds.push(badge["kind"].as_str().unwrap().to_string());
                }
            }
        }
        kinds
    }

    /// Every `badge.label` string across all cards (for the specific-label checks).
    fn badge_labels(root: &Value) -> Vec<String> {
        let mut labels = Vec::new();
        for section in root["sections"].as_array().unwrap() {
            for card in section["cards"].as_array().unwrap() {
                for badge in card["badges"].as_array().unwrap() {
                    labels.push(badge["label"].as_str().unwrap().to_string());
                }
            }
        }
        labels
    }

    #[test]
    fn schema_and_root_shape_match_the_contract() {
        let root = emitted();
        assert_eq!(
            root["schema"], "firmos.view/0",
            "the schema tag is the host contract"
        );
        assert!(
            root["generated_label"].is_string(),
            "generated_label is a string"
        );
        assert!(!root["generated_label"].as_str().unwrap().is_empty());
        assert!(root["sections"].is_array(), "sections is an array");
        // One section (the inbox emits a single "What's next" worklist section).
        let sections = root["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 1, "the inbox emits one worklist section");
    }

    #[test]
    fn section_carries_caveats_and_one_card_per_seeded_email() {
        let root = emitted();
        let section = &root["sections"][0];
        assert!(section["title"].is_string());
        // The honest-limits caveats survive into the view (incl. "no date != no
        // deadline"); each has id / message / dismissible per the contract.
        let caveats = section["caveats"].as_array().expect("caveats is an array");
        assert!(
            !caveats.is_empty(),
            "the section carries honest-limits caveats"
        );
        assert!(
            caveats
                .iter()
                .any(|c| c["id"] == "deadlines-not-all-caught"),
            "the 'no date != no deadline' caveat is present"
        );
        for c in caveats {
            assert!(
                c["id"].is_string() && c["message"].is_string() && c["dismissible"].is_boolean()
            );
        }
        // One card per seeded email (7).
        let cards = section["cards"].as_array().expect("cards is an array");
        assert_eq!(
            cards.len(),
            synthetic_emails().len(),
            "one card per seeded email"
        );
    }

    #[test]
    fn each_card_matches_the_contract_field_shape() {
        let root = emitted();
        for card in root["sections"][0]["cards"].as_array().unwrap() {
            assert!(card["title"].is_string(), "card.title is a string");
            assert!(card["subtitle"].is_string(), "card.subtitle is a string");
            assert!(card["badges"].is_array(), "card.badges is an array");
            // due is an object {kind,text} or null (the inbox always surfaces one).
            assert!(card["due"].is_object() || card["due"].is_null());
            if card["due"].is_object() {
                assert!(card["due"]["kind"].is_string());
                assert!(card["due"]["text"].is_string());
            }
            // actions: typed {action_id,label,target}.
            let actions = card["actions"].as_array().expect("actions is an array");
            for a in actions {
                assert!(
                    a["action_id"].is_string() && a["label"].is_string() && a["target"].is_string()
                );
            }
        }
    }

    #[test]
    fn demonstrates_the_expected_badge_kinds() {
        // The seed must exercise each badge kind the verdict surfaces under NO_ANCHOR:
        // origin (internal/external), category (court/filing, newsletter), protected
        // (without prejudice), and warning (the ⚠ multiple-dates review badge). The
        // priority kind is intentionally absent (suppressed under NO_ANCHOR).
        let root = emitted();
        let kinds = badge_kinds(&root);
        for expected in ["origin", "category", "protected", "warning"] {
            assert!(
                kinds.contains(&expected.to_string()),
                "badge kind {expected:?} must appear: {kinds:?}"
            );
        }
        // SAFETY (DANGER fix #3): no priority badge under NO_ANCHOR.
        assert!(
            !kinds.contains(&"priority".to_string()),
            "no priority badge under NO_ANCHOR: {kinds:?}"
        );
    }

    #[test]
    fn demonstrates_the_specific_surfaced_labels() {
        // Spot-check the load-bearing labels the seed is designed to produce.
        let root = emitted();
        let labels = badge_labels(&root);
        assert!(
            labels.iter().any(|l| l == "external"),
            "an external sender: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l == "internal"),
            "an internal sender: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l == "court / filing"),
            "a court/filing category: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l == "newsletter"),
            "a newsletter category: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l == "without prejudice"),
            "a WP protected-handling badge: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l.contains("multiple dates")),
            "the ⚠ multiple-dates review warning: {labels:?}"
        );
    }

    #[test]
    fn demonstrates_the_expected_due_kinds() {
        // Under NO_ANCHOR the demonstrated due kinds are needs_confirm (detected /
        // explicit / relative deadlines + no-date), ambiguous (an irreducibly
        // ambiguous numeric date is NOT seeded here, so it may be absent), and vague
        // (the newsletter's urgency cue). The factual kinds (overdue/due_today/
        // due_soon) require a real anchor and are NOT faked.
        let root = emitted();
        let kinds = due_kinds(&root);
        assert!(!kinds.is_empty(), "every card surfaces a due label");
        assert!(
            kinds.contains(&"needs_confirm".to_string()),
            "a detected deadline -> needs_confirm: {kinds:?}"
        );
        assert!(
            kinds.contains(&"vague".to_string()),
            "an urgency cue -> vague: {kinds:?}"
        );
        // None of the cards claims a fabricated factual proximity under NO_ANCHOR.
        for fact in ["overdue", "due_today", "due_soon"] {
            assert!(
                !kinds.contains(&fact.to_string()),
                "no fabricated factual proximity {fact:?} under NO_ANCHOR: {kinds:?}"
            );
        }
    }

    #[test]
    fn output_is_byte_identical_run_to_run() {
        // DETERMINISM (load-bearing): same run -> byte-identical JSON (fixed clock,
        // NO_ANCHOR triage, fixed generated_label — no wall clock anywhere).
        let a = render_contract_json().expect("render a");
        let b = render_contract_json().expect("render b");
        assert_eq!(a, b, "viewgen must be deterministic");
    }

    #[test]
    fn no_real_matter_data_only_synthetic_example_addresses() {
        // CLAUDE.md non-negotiable: NO real matter data. Every seeded sender uses a
        // reserved `.example` domain — a cheap guard that the corpus stays synthetic.
        for (_id, text) in synthetic_emails() {
            let from_line = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("from:"))
                .expect("each fixture has a From header");
            assert!(
                from_line.contains(".example"),
                "synthetic sender must use a .example domain, got {from_line:?}"
            );
        }
    }
}
