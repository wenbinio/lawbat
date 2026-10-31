// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `RedactionEngineBuilder`. Extracted from `lib.rs`.

use runtime::{CoreResult, DataClass};

use crate::*;

/// FIX #12: the single fallible constructor for a [`RedactionEngine`]. Replaces the
/// former `new` / `with_classes` / `with_recognizers` / `with_recognizers_and_classes`
/// quartet with one chainable builder. (A thin [`RedactionEngine::new`] remains for
/// the common term-only case.)
///
/// All firm-recognizer validation — zero-width / empty patterns, invalid labels,
/// `whole_word`+`Regex`, over-long replacements, malformed regexes — surfaces at
/// [`build`](RedactionEngineBuilder::build) time as a [`CoreError::Backend`],
/// fail-closed (a bad rule aborts the build rather than silently vanishing).
///
/// ```ignore
/// let engine = RedactionEngine::builder()
///     .classes(vec![DataClass::Document])
///     .recognizers(vec![UserRecognizer::literal("party", "Acme")])
///     .build()?;
/// ```
#[derive(Default)]
pub struct RedactionEngineBuilder {
    terms: Vec<String>,
    classes: Option<Vec<DataClass>>,
    recognizers: Vec<UserRecognizer>,
    builtins: Option<BuiltinRecognizers>,
    /// The OPT-IN locale packs to enable (default empty = none). Deduped at build.
    locales: Vec<Locale>,
    /// The OPT-IN compliance profiles to enable (default empty = none). Deduped at
    /// build.
    profiles: Vec<Profile>,
    /// LEVER 2: the OPT-IN context-required recognizers to enable (default all-off =
    /// byte-identical to before). Set via [`context_recognizers`](Self::context_recognizers).
    context_recognizers: ContextRecognizers,
    /// The OPT-IN ISO 17442 LEI recognizer ([`Recognizer::Lei`]). Default `false` (off) =
    /// byte-identical to before. Set via [`lei`](Self::lei). A public LEI is borderline
    /// PII, so it is a deliberate user choice rather than an always-on built-in.
    lei: bool,
    /// NAME-PROPAGATION expansion tier (default `false`, OFF). When ON, the name-closure
    /// pass also redacts any Capitalized multi-word run containing an already-detected name
    /// token (so a detected `Greco` pulls in the bare `Massimo Greco`). The SAFE tier
    /// (exact re-occurrences of a detected full name) is ALWAYS on independent of this flag.
    /// Set via [`name_expansion`](Self::name_expansion). OFF = byte-identical where nothing
    /// propagates.
    name_expansion: bool,
    /// The OPT-IN AGGRESSIVE SG-NRIC loose net (default `false`, OFF). When ON, two extra
    /// `aggressive: true` SG rows are registered — `sg:nric-loose` (any-letter / 6–8-digit /
    /// optionally space-or-dash-separated NRIC-shaped tokens) and `sg:nric-context` (a bare
    /// 7–9-digit run keyword-gated on an NRIC/FIN/IC label). They are ADVISORY (surfaced for
    /// review, default-OFF in apply) and DEMOTED below the precise `sg:nric` row, so a real
    /// NRIC is still attributed to (and default-redacted by) `sg:nric`. INDEPENDENT of the
    /// SG locale pack (NOT folded into `sg:nric`/`sg:uen`). Set via
    /// [`sg_nric_loose`](Self::sg_nric_loose). OFF = byte-identical (no patterns added).
    sg_nric_loose: bool,
    /// The OPT-IN ORGANISATION-name recognizer (default `false`, OFF). When ON, a dedicated
    /// deterministic pass emits its OWN `ctx:org` recognizer class for (a) suffix-anchored
    /// company names (a Capitalized run + an org suffix like `Pte Ltd`/`LLP`/`S.A.`) and (b)
    /// the BROAD org-context arm (a Capitalized run near an org-context cue). Careful-review
    /// only, and EXCLUDED from every person-name propagation seed. Set via
    /// [`organisations`](Self::organisations). OFF = byte-identical (the pass is a no-op).
    organisations: bool,
    /// The OPT-IN BROADENED ADDRESS recognizers (default `false`, OFF). When ON, three extra
    /// `Recognizer::Address` rows are compiled — foreign-format streets (`2, place Winston
    /// Churchill`), building/premises names (`Chater House`, `South Beach Tower`), and the
    /// Luxembourg postal shape (`L-1855`). They ride the EXISTING address family (careful
    /// review); the DEFAULT address recognizers are unchanged. Set via
    /// [`addresses_full`](Self::addresses_full). OFF = byte-identical (no patterns added).
    addresses_full: bool,
}

impl RedactionEngineBuilder {
    /// Set the explicit term list (party names / deal codenames / matter numbers),
    /// matched case-insensitively as escaped literals. Replaces any prior terms.
    pub fn terms(mut self, terms: impl IntoIterator<Item = String>) -> Self {
        self.terms = terms.into_iter().collect();
        self
    }

    /// Set the data classes to read + transform (each must be separately granted
    /// via `matter.read:<class>`). Replaces any prior classes. If never called, the
    /// default set (`document` + `party`) is used.
    pub fn classes(mut self, classes: Vec<DataClass>) -> Self {
        self.classes = Some(classes);
        self
    }

    /// Set the firm-defined [`UserRecognizer`]s ("super find & replace"), ADDED to
    /// the built-in presets + escaped terms (never replacing them). Replaces any
    /// prior recognizers. Validated + DEDUPLICATED at [`build`](Self::build).
    pub fn recognizers(mut self, recognizers: impl IntoIterator<Item = UserRecognizer>) -> Self {
        self.recognizers = recognizers.into_iter().collect();
        self
    }

    /// Choose which built-in pattern recognizers are active (default = all on,
    /// recall-first). Does NOT affect the term list, firm recognizers, or the
    /// aggressive name mode. See [`BuiltinRecognizers`].
    pub fn builtins(mut self, builtins: BuiltinRecognizers) -> Self {
        self.builtins = Some(builtins);
        self
    }

    /// Enable the given OPT-IN [`Locale`] packs' recognizers, IN ADDITION to the
    /// global built-ins + the term list + firm recognizers. Replaces any prior
    /// locale set.
    ///
    /// DEFAULT = NO locales: jurisdiction-specific recognizers (e.g. the SG NRIC)
    /// are NOT on by default — a firm opts in only for the jurisdictions it works
    /// in, e.g. `.locales([Locale::Singapore])`. (So `RedactionEngine::new` and a
    /// bare `builder().build()` do NOT flag an NRIC.) See [`Locale`].
    pub fn locales(mut self, locales: impl IntoIterator<Item = Locale>) -> Self {
        self.locales = locales.into_iter().collect();
        self
    }

    /// Enable the given OPT-IN compliance [`Profile`]s, IN ADDITION to the global
    /// built-ins + the term list + firm recognizers + any locale packs. Replaces any
    /// prior profile set. MIRRORS [`locales`](Self::locales) for the compliance axis.
    ///
    /// Each enabled profile (i) OR-merges its required built-ins into the active set
    /// (so e.g. [`Profile::PciDssCardholder`] always runs the credit-card recognizer
    /// even if `.builtins(BuiltinRecognizers::none())` was set), (ii) compiles its own
    /// bespoke rows under the `profile:<name>:<row>` audit namespace (the PCI worked
    /// example has none), and (iii) contributes its honest
    /// [`human_review_gaps`](ProfileSpec) — reachable via
    /// [`RedactionEngine::profile_review_gaps`] — so a reviewer is never told a
    /// category is handled when deterministic matching cannot cover it.
    ///
    /// DEFAULT = NO profiles: like locales, compliance profiles are strictly opt-in,
    /// so `RedactionEngine::new` and a bare `builder().build()` enable none.
    pub fn profiles(mut self, profiles: impl IntoIterator<Item = Profile>) -> Self {
        self.profiles = profiles.into_iter().collect();
        self
    }

    /// LEVER 2 — enable some/all of the OPT-IN CONTEXT-REQUIRED recognizers (undashed
    /// SSN, DOB, age>89, generic account/MRN), IN ADDITION to the built-ins / terms /
    /// firm recognizers / locale + profile packs. Replaces any prior context selection.
    ///
    /// DEFAULT = ALL OFF (the additive-only invariant): `RedactionEngine::new` and a bare
    /// `builder().build()` enable NONE, so the candidate set + spans are byte-identical to
    /// before Lever 2. A firm opts in with e.g.
    /// `.context_recognizers(ContextRecognizers::all())` or by setting individual fields.
    /// Even ENABLED, a context candidate SURVIVES only if a relevant keyword is in-window
    /// OR a normal recognizer also covers the span (the gate in `merged_spans`).
    pub fn context_recognizers(mut self, context: ContextRecognizers) -> Self {
        self.context_recognizers = context;
        self
    }

    /// Enable the OPT-IN ISO 17442 Legal Entity Identifier ([`Recognizer::Lei`])
    /// recognizer, IN ADDITION to the built-ins / terms / firm recognizers / locale +
    /// profile / context packs. A 20-char `[A-Z0-9]{18}[0-9]{2}` token that PASSES the
    /// ISO 7064 mod-97-10 check is flagged; the checksum makes it precise (a real LEI
    /// always passes, so it only filters non-LEIs — no miss), exactly like the card/IBAN.
    ///
    /// DEFAULT = OFF: a public LEI is borderline PII, so flagging it is a USER DECISION
    /// rather than an always-on default — UNLIKE the global built-ins it is OFF even with
    /// `.builtins(BuiltinRecognizers::all())`. `RedactionEngine::new` and a bare
    /// `builder().build()` therefore do NOT flag an LEI, so the candidate set is
    /// byte-identical to before this existed unless a caller explicitly opts in with
    /// `.lei(true)`.
    pub fn lei(mut self, lei: bool) -> Self {
        self.lei = lei;
        self
    }

    /// NAME-PROPAGATION — enable the OPT-IN EXPANSION tier of the name-closure pass. With it
    /// ON, an already-detected name TOKEN (e.g. `Greco`, recovered from a `Mr Greco` match)
    /// pulls in any Capitalized multi-word run that contains it as a whole word — so the bare
    /// `Massimo Greco` / `Peter Thomas Schwicht` (a board director listed with NO honorific)
    /// is redacted from a single titled mention elsewhere. STRICTLY bounded to runs that
    /// contain a detected name token — it is NOT the blunt [`RedactionEngine::aggressive`]
    /// "every capitalized pair" rule.
    ///
    /// DEFAULT = OFF: the SAFE tier (exact re-occurrences of a detected FULL name) is always
    /// on and very low-FP; the broader expansion is a deliberate user choice (it can pull in
    /// a capitalized run that merely shares a surname). When OFF — or when nothing propagates
    /// — the candidate set is byte-identical to before this existed.
    pub fn name_expansion(mut self, name_expansion: bool) -> Self {
        self.name_expansion = name_expansion;
        self
    }

    /// Enable the OPT-IN AGGRESSIVE SG-NRIC "loose net" — two extra `aggressive: true`
    /// Singapore rows registered IN ADDITION to (and INDEPENDENTLY of) the precise SG locale
    /// pack:
    /// - `sg:nric-loose` — any-letter (either case) + 6–8 digits + a letter, with an
    ///   OPTIONAL single space or dash between groups (so `S 1234567 D` / `s-1234567-d` are
    ///   caught); word-bounded, linear-time;
    /// - `sg:nric-context` — a bare 7–9-digit run that fires ONLY with an NRIC/FIN/IC
    ///   keyword in-window (the same additive context gate `us:dl` uses).
    ///
    /// Both are AGGRESSIVE, so a host that consults [`is_aggressive`](RedactionEngine::
    /// is_aggressive) renders their candidates ADVISORY (surfaced, default-OFF in apply); both
    /// are DEMOTED below the precise `sg:nric` row in the merge, so a REAL NRIC (matching both
    /// the precise and the loose row) is attributed to `sg:nric` → default-redacted, and only
    /// an EXTRA token matched solely by a loose/context row is advisory.
    ///
    /// DEFAULT = OFF: an SG firm opts into the loose net deliberately (it is a recall net that
    /// over-flags NRIC-shaped noise). NOT folded into the SG locale pack — `.locales([Locale::
    /// Singapore])` alone stays byte-identical to today. OFF = no patterns added.
    pub fn sg_nric_loose(mut self, sg_nric_loose: bool) -> Self {
        self.sg_nric_loose = sg_nric_loose;
        self
    }

    /// Enable the OPT-IN ORGANISATION-name recognizer — a dedicated deterministic pass that
    /// emits its OWN `ctx:org` recognizer class, the UNION of:
    /// - a SUFFIX-ANCHORED arm: a Capitalized multi-token run immediately followed by an org
    ///   suffix from a fixed list (`Pte Ltd`, `Ltd`, `LLP`, `LLC`, `S.A.`, `GmbH`, `Limited`,
    ///   `Inc`, `Holdings`, `Group`, `Partners`, `& Co`, `Sdn Bhd`, `Berhad`, …), wrap-tolerant;
    /// - a BROAD ORG-CONTEXT arm: a Capitalized run (≥2 tokens, so a definite-article generic
    ///   like `the Company`/`the Fund` never matches) near an org-context cue (`incorporated
    ///   in`, `trustee`, `manager`, `registrar`, `legal adviser`, …), person-shaped runs with
    ///   no org signal excluded and person candidates left to the merge (person recognizers
    ///   WIN the overlap). This is the DELIBERATELY broad, higher-FP arm (fund / index names
    ///   WILL flag — the ratified choice; the keep-list is the mitigation).
    ///
    /// The `ctx:org` class routes to the CAREFUL review tier ALWAYS (never quick-confirm /
    /// auto-accept) and is EXCLUDED from every person-name propagation seed predicate — so a
    /// broad org can never amplify document-wide the way a person name does. Renders as an
    /// ENTITY placeholder (`[A]`/`[B]`) in AI-safe-labels mode, like a named party.
    ///
    /// DEFAULT = OFF: broad company detection is a deliberate user choice. OFF — and any
    /// document with no organisation — is byte-identical to before this existed (the pass is
    /// a no-op). Enabled via `.organisations(true)`.
    pub fn organisations(mut self, organisations: bool) -> Self {
        self.organisations = organisations;
        self
    }

    /// Enable the OPT-IN BROADENED ADDRESS recognizers — three extra `Recognizer::Address`
    /// rows compiled IN ADDITION to the default structured-address built-ins:
    /// - FOREIGN-FORMAT streets where the street TYPE precedes the name (`2, place Winston
    ///   Churchill`, `19 rue de Bitbourg`, `6, route de Trèves`);
    /// - BUILDING / PREMISES names (`Chater House`, `South Beach Tower`, `Keppel Bay Tower` —
    ///   a Capitalized run ending in a premises token `House`/`Tower`/`Building`/`Centre`/…);
    /// - the LUXEMBOURG postal shape (`L-1855`).
    ///
    /// They ride the EXISTING address family, so they route to CAREFUL review exactly like the
    /// default structured-address recognizer. The DEFAULT address recognizers are UNCHANGED —
    /// with this flag OFF the candidate set is byte-identical (no patterns added). Enabled via
    /// `.addresses_full(true)`.
    pub fn addresses_full(mut self, addresses_full: bool) -> Self {
        self.addresses_full = addresses_full;
        self
    }

    /// Build the engine, validating + compiling (and DEDUPLICATING, FIX #5) every
    /// firm recognizer. FALLIBLE: any firm-rule validation failure surfaces as a
    /// [`CoreError::Backend`], fail-closed — a bad rule aborts the build rather than
    /// silently dropping a redaction rule (a dropped rule = a confidentiality risk).
    pub fn build(self) -> CoreResult<RedactionEngine> {
        // Dedup the requested classes (order-preserving) so a class passed twice is
        // scanned ONCE. A duplicate class would make `scan_matter` emit two `DocScan`s
        // with identical `(doc_id, class)` + spans, which double-counts in
        // `ReviewSummary` while the `Selection` (keyed by `SpanKey`) collapses to one —
        // breaking the documented `ReviewSummary.quick_confirm() ==
        // Selection::quick_confirm(..).len()` invariant. Same order-preserving dedup as
        // `locales`/`profiles` below.
        let mut classes = Vec::new();
        for c in self.classes.unwrap_or_else(default_classes) {
            if !classes.contains(&c) {
                classes.push(c);
            }
        }
        let builtins = self.builtins.unwrap_or_default();
        // Dedup the requested locales (order-preserving) so the same pack is never
        // compiled twice — keeps the candidate set + breakdown counts unambiguous.
        let mut locales: Vec<Locale> = Vec::new();
        for l in self.locales {
            if !locales.contains(&l) {
                locales.push(l);
            }
        }
        // Dedup the requested profiles the SAME way (order-preserving): the same
        // profile selected twice must not double-record the selection note or
        // double-compile its bespoke rows.
        let mut profiles: Vec<Profile> = Vec::new();
        for p in self.profiles {
            if !profiles.contains(&p) {
                profiles.push(p);
            }
        }
        let mut engine = RedactionEngine::base(
            self.terms,
            classes,
            builtins,
            &locales,
            &profiles,
            self.context_recognizers,
            self.lei,
            self.sg_nric_loose,
            self.organisations,
            self.addresses_full,
        );
        engine.user_recognizers = RedactionEngine::compile_recognizers(self.recognizers)?;
        // NAME-PROPAGATION expansion tier (opt-in). `base` defaults it OFF; flip it on here
        // when the builder requested it. (The SAFE tier is unconditional in the pass.)
        engine.name_expansion = self.name_expansion;
        Ok(engine)
    }
}
