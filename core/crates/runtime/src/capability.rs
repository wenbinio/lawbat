// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capability taxonomy (architecture spec §5.1).
//!
//! Default-deny, declared-then-granted. A capability that is not in the grant
//! set is *unreachable*, not merely discouraged (spec §5.2). This module models
//! the taxonomy as plain Rust types; the [`crate::broker`] enforces it.

use std::fmt;
use std::net::IpAddr;

/// Truncate an attacker-/matter-influenced value before echoing it into an error
/// string (M-8). An egress destination or storage key may derive from matter
/// data, so a full-length echo could leak content into operational logs (and
/// bloat them). Keep the first ~32 chars (by `char`, never splitting a UTF-8
/// boundary) and append a marker when truncated. Render with `{:?}` at the call
/// site so control chars stay escaped.
pub(crate) fn truncate_for_error(s: &str) -> String {
    const MAX: usize = 32;
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(MAX).collect();
    if chars.next().is_some() {
        format!("{head:?}... (truncated)")
    } else {
        format!("{head:?}")
    }
}

/// Render a capability for an OPERATIONAL log/stderr line, TRUNCATING + debug-escaping
/// the variants that carry an attacker-/manifest-influenced FREE token (egress
/// destination, ui slot). The plain `Display` impl interpolates those tokens RAW, so a
/// hostile manifest's over-long / control-char egress destination could bloat or
/// line-wrap stderr (F6 / M-8). The other variants are short, fixed taxonomy forms
/// (storage scope is the enum own/shared, not a free token), so they pass through their
/// Display. `pub(crate)` — internal logging helper, not part of the ABI.
pub(crate) fn capability_for_error(cap: &Capability) -> String {
    match cap {
        Capability::Egress(dest) => format!("egress:{}", truncate_for_error(dest)),
        Capability::UiSlot(slot) => format!("ui.slot:{}", truncate_for_error(slot)),
        other => other.to_string(),
    }
}

/// Data classes scope `matter.read` / `matter.write` (spec §5.1: named classes
/// only, never "all"). Mirrors the spec's examples; the canonical taxonomy is
/// owned by the spec, not by a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataClass {
    Document,
    Party,
    Annotation,
    Metadata,
    OcrText,
    /// The matter's ACTIVITY trail — a SAFE, entitlement-filtered projection of the
    /// core audit chain (document-touch events: what the CURRENT user touched in the
    /// CURRENT matter, when), NOT stored matter content. Reached only via the
    /// mediated [`crate::Core::matter_read_activity`]; gating it as a `matter.read`
    /// class (default-deny, current-matter scope) reuses the read entitlement
    /// machinery without a new capability variant. The projection carries NO
    /// cleartext detail (timestamps + event kind + actor only), so granting it
    /// exposes activity METADATA, never matter document content. (Taxonomy addition,
    /// flagged for spec ratification — see `to-read/core.to-fix.md`.)
    Activity,
}

impl fmt::Display for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DataClass::Document => "document",
            DataClass::Party => "party",
            DataClass::Annotation => "annotation",
            DataClass::Metadata => "metadata",
            DataClass::OcrText => "ocr-text",
            DataClass::Activity => "activity",
        };
        f.write_str(s)
    }
}

/// Storage scope (spec §5.1). `own` is the default namespace; `shared` must be
/// explicitly granted. `global` is never representable on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageScope {
    Own,
    Shared,
}

impl fmt::Display for StorageScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageScope::Own => f.write_str("own"),
            StorageScope::Shared => f.write_str("shared"),
        }
    }
}

/// The capability taxonomy (spec §5.1, default-deny).
///
/// Note `Egress` names a *specific destination* — never a wildcard (spec §5.4).
/// There is no `Egress::Any`, by construction. `Ui` names one slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// `matter.read:<class>` — read a named data class in the current matter.
    MatterRead(DataClass),
    /// `matter.write:<class>` — write a named data class.
    /// RESERVED (taxonomy only): there is NO mediated `Core` write method yet — the
    /// sole write path today is `document.transform`. H-3: `validate()` REJECTS it,
    /// so it cannot be granted while unenforced (a grant must not imply a power the
    /// core doesn't enforce). Add a mediated `matter_write` AND re-enable it in
    /// `validate()` when a module genuinely needs class-scoped writes.
    MatterWrite(DataClass),
    /// `storage:<own|shared>` — namespaced storage.
    Storage(StorageScope),
    /// `document.transform` — read/rewrite document content in place via core.
    DocumentTransform,
    /// `egress:<destination>` — a single, named destination. NEVER wildcard.
    Egress(String),
    /// `compute.model` — local, scoped, logged inference (optional tier).
    /// RESERVED (taxonomy only): no mediated `Core` method yet. H-3: `validate()`
    /// REJECTS it so it cannot be granted while unenforced (re-enable when the
    /// compute tier lands).
    ComputeModel,
    /// `ui.slot:<slot>` — a named render surface.
    /// RESERVED (taxonomy only): no mediated `Core` render method yet. H-3:
    /// `validate()` REJECTS it (regardless of token shape) so it cannot be granted
    /// while unenforced. Re-enable it AND restore the named-token shape check in
    /// `validate()` when a mediated ui.slot render method lands.
    UiSlot(String),
    /// `audit.note` — a module ADDS free-text context to the audit chain
    /// (spec §2.7/§4.3). UNGATED on purpose: a module may always append context;
    /// it can never suppress or forge core events. Distinct from
    /// `matter.read:metadata` so a note is never mistaken for a genuine core read.
    AuditNote,
}

impl Capability {
    /// Validate a capability before it can be granted or matched (spec §5.2,
    /// §5.4). Two concerns are enforced here:
    ///
    /// 1. **Shape** of the free-form variants:
    ///    - `Egress(dest)` — a single, named endpoint: it may never be empty,
    ///      contain a wildcard (`*`), be an all-routes CIDR (`0.0.0.0/0`,
    ///      `::/0`), or a broadcast/multicast/loopback ambient form. Such a value
    ///      would be ambient egress by another name.
    ///
    /// 2. **Enforceability (H-3):** a capability is REJECTED outright if the core
    ///    has NO mediated method that actually enforces it yet. Today those are:
    ///    - `MatterWrite(_)` — taxonomy only; the sole write path is
    ///      `document.transform`. There is no `matter_write` mediated method.
    ///    - `ComputeModel` — taxonomy only; no mediated `compute.model` method.
    ///    - `UiSlot(_)` — taxonomy only; no mediated `ui.slot` render method.
    ///
    ///    Granting an UNENFORCED capability would let a manifest imply a power the
    ///    core does not actually mediate or audit — a grant that "looks" allowed
    ///    while the broker silently does nothing with it. Refusing it at
    ///    `validate()` keeps the grant set honest: every granted capability maps
    ///    to a real, mediated, audited code path. RE-ENABLE each variant here when
    ///    its mediated `Core` method lands (restore its shape check at that time;
    ///    `UiSlot`'s shape rule is kept commented below ready to re-use). See the
    ///    "no mediated method" notes on the variants and `to-read/core.to-fix.md`.
    ///
    /// Returns `Err(CoreError::Backend(..))` describing the rejection. The broker
    /// and `from_manifest` both filter on this, so a malformed OR unenforceable
    /// capability can never enter a grant set.
    pub fn validate(&self) -> crate::error::CoreResult<()> {
        match self {
            Capability::Egress(dest) if !egress_destination_is_named(dest) => {
                // M-8: truncate the echoed destination (it may derive from matter
                // data) before putting it in the error string.
                Err(crate::error::CoreError::Backend(format!(
                    "egress destination must be a single named endpoint, not empty/wildcard/all-routes/broadcast/multicast/loopback: {}",
                    truncate_for_error(dest)
                )))
            }
            // H-3: reject capabilities with no mediated, enforcing Core method yet.
            // A grant must never imply an unenforced power.
            Capability::MatterWrite(_) => Err(crate::error::CoreError::Backend(
                "matter.write is taxonomy-only: no mediated core write method exists yet, so it cannot be granted (re-enable when `matter_write` lands)".into(),
            )),
            Capability::ComputeModel => Err(crate::error::CoreError::Backend(
                "compute.model is taxonomy-only: no mediated core method exists yet, so it cannot be granted (re-enable when the compute tier lands)".into(),
            )),
            Capability::UiSlot(_slot) => {
                // When a mediated ui.slot render method lands, restore the SHAPE
                // check below (and drop this blanket rejection):
                //   if !is_named_token(_slot) {
                //       return Err(CoreError::Backend(format!(
                //           "ui.slot must be a single named token, not empty/whitespace/control: {_slot:?}"
                //       )));
                //   }
                Err(crate::error::CoreError::Backend(
                    "ui.slot is taxonomy-only: no mediated core render method exists yet, so it cannot be granted (re-enable + restore the shape check when ui.slot lands)".into(),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// True iff `s` is a single, named token: non-empty after trimming, with no
/// ASCII whitespace and no ASCII control characters anywhere. This is the shared
/// shape rule for named identifiers (egress destinations, ui slots); the egress
/// validator layers its extra wildcard / all-routes checks ON TOP of this.
pub fn is_named_token(s: &str) -> bool {
    if s.trim().is_empty() {
        return false;
    }
    !s.chars()
        .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
}

/// True iff `dest` is a single, named egress endpoint. This is the one place the
/// rule lives (spec §5.4). A value is REFUSED if any of the following hold:
///
/// - empty, or empty AFTER trimming (whitespace-only, e.g. `" "` / `"\t"`);
/// - contains any ASCII whitespace or ASCII control char (so `"a b"` / `"\t"`
///   can never be a destination — these would make a single endpoint ambiguous);
/// - contains a wildcard (`*`);
/// - is a bare all-interfaces / all-routes form (case-insensitive):
///   `0.0.0.0`, `::`, `::0`, `0`, `0.0.0.0/0`, `::/0` — these are ambient egress
///   by another name;
/// - is a broadcast / multicast / loopback ambient form (M-3, case-insensitive):
///   `255.255.255.255` (limited broadcast), `127.0.0.1` / `::1` (loopback),
///   `ff02::1` / `ff02::2` (link-local all-nodes / all-routers multicast),
///   `224.0.0.1` / `224.0.0.2` (IPv4 all-systems / all-routers multicast) — a
///   "named" destination must be a SPECIFIC consented endpoint, never an address
///   that fans a payload out to many hosts or loops it ambiguously.
pub fn egress_destination_is_named(dest: &str) -> bool {
    // Shared shape rule first: non-empty (after trim), no whitespace, no control
    // chars. Egress then layers wildcard / all-routes refusal on top.
    if !is_named_token(dest) {
        return false;
    }
    // No wildcard anywhere (a destination is a single endpoint, not a pattern).
    if dest.contains('*') {
        return false;
    }
    // Bare all-interfaces / all-routes forms, PLUS (M-3) broadcast / multicast /
    // loopback ambient forms (case-insensitive for the IPv6 hex). These are not a
    // single consented endpoint: all-routes/broadcast/multicast fan out to many
    // hosts, loopback is ambiguous self-routing — none is an attributable "named"
    // destination, so each is ambient egress by another name.
    const AMBIENT_FORMS: &[&str] = &[
        // all-interfaces / all-routes
        "0.0.0.0",
        "::",
        "::0",
        "0",
        "0.0.0.0/0",
        "::/0",
        // F4 (High — fixed): the EXPANDED (uncompressed) IPv6 all-zeros forms. `::`
        // and `::/0` are the COMPRESSED spelling of the IPv6 unspecified / all-
        // routes address; the same address written out in full (and the IPv4-mapped
        // unspecified form) is the SAME ambient all-zeros destination and must be
        // rejected identically — otherwise a manifest could smuggle ambient egress
        // past the gate just by un-compressing the address.
        "0:0:0:0:0:0:0:0",   // expanded "::"
        "0:0:0:0:0:0:0:0/0", // expanded "::/0"
        "::ffff:0.0.0.0",    // IPv4-mapped IPv6 unspecified (0.0.0.0)
        // broadcast
        "255.255.255.255",
        // loopback
        "127.0.0.1",
        "::1",
        // link-local multicast (IPv6 all-nodes / all-routers)
        "ff02::1",
        "ff02::2",
        // IPv4 local multicast (all-systems / all-routers)
        "224.0.0.1",
        "224.0.0.2",
    ];
    // Normalize for the comparison: lowercase (IPv6 hex is case-insensitive) AND
    // trimmed (defensive — `is_named_token` already rejects any value carrying
    // surrounding whitespace, so this trim is belt-and-braces, not the gate).
    let normalized = dest.trim().to_ascii_lowercase();
    if AMBIENT_FORMS.contains(&normalized.as_str()) {
        return false;
    }
    // M-3 (defence in depth): the literal AMBIENT_FORMS list above only catches the
    // SPECIFIC spellings enumerated. A destination that PARSES as an IP address can be
    // an ambient/non-attributable form NOT on that list — e.g. `127.0.0.2` (the whole
    // 127.0.0.0/8 loopback block), other multicast groups (`239.x`, `ff0x::…`), the
    // unspecified address in any spelling, or the IPv4 broadcast. Reject those on the
    // PARSED address, which normalises every spelling (compressed/expanded IPv6,
    // IPv4-mapped, etc.) so a manifest cannot smuggle a loopback/multicast/unspecified/
    // broadcast endpoint past the gate by choosing an un-enumerated spelling. A value
    // that does NOT parse as an IP (a hostname like `api.example.com`) is left to the
    // literal checks — it is a named host, not an ambient address.
    if let Some(ip) = parse_ip_endpoint(&normalized) {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || is_broadcast_v4(ip) {
            return false;
        }
    }
    true
}

/// Parse `dest` as a bare IP address, tolerating a bracketed IPv6 form (`[::1]`).
/// Returns `None` for anything that is not a single IP literal (e.g. a hostname, or an
/// `ip:port` form — a port is not part of the address shape we vet here; the literal
/// ambient list and the parsed-IP check both operate on the bare address). Pure, no I/O.
fn parse_ip_endpoint(dest: &str) -> Option<IpAddr> {
    // Strip one matching pair of IPv6 brackets if present (`[::1]` → `::1`).
    let stripped = dest
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(dest);
    stripped.parse::<IpAddr>().ok()
}

/// The IPv4 limited-broadcast address (255.255.255.255). `Ipv4Addr::is_broadcast` is
/// stable; expose a single predicate over `IpAddr` so the call site stays terse.
fn is_broadcast_v4(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::MatterRead(c) => write!(f, "matter.read:{c}"),
            Capability::MatterWrite(c) => write!(f, "matter.write:{c}"),
            Capability::Storage(s) => write!(f, "storage:{s}"),
            Capability::DocumentTransform => f.write_str("document.transform"),
            Capability::Egress(dest) => write!(f, "egress:{dest}"),
            Capability::ComputeModel => f.write_str("compute.model"),
            Capability::UiSlot(slot) => write!(f, "ui.slot:{slot}"),
            Capability::AuditNote => f.write_str("audit.note"),
        }
    }
}

impl std::str::FromStr for DataClass {
    type Err = CapabilityParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "document" => DataClass::Document,
            "party" => DataClass::Party,
            "annotation" => DataClass::Annotation,
            "metadata" => DataClass::Metadata,
            "ocr-text" => DataClass::OcrText,
            "activity" => DataClass::Activity,
            _ => return Err(CapabilityParseError),
        })
    }
}

impl std::str::FromStr for StorageScope {
    type Err = CapabilityParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "own" => StorageScope::Own,
            "shared" => StorageScope::Shared,
            _ => return Err(CapabilityParseError),
        })
    }
}

/// Error from parsing a capability (or one of its sub-tokens) from its canonical
/// [`Display`](fmt::Display) string. Opaque on purpose — it carries no copy of the
/// rejected token (which could derive from matter-influenced data, e.g. an egress
/// destination), so a parse failure never echoes content into a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityParseError;

impl fmt::Display for CapabilityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognised capability token")
    }
}

impl std::error::Error for CapabilityParseError {}

/// Parse a [`Capability`] back from its canonical [`Display`](fmt::Display) form —
/// the EXACT inverse of `Display`, so `Capability -> String -> Capability` round-
/// trips (proven by `capability_display_from_str_round_trips`). Needed by the
/// durable audit backend (`audit-store`) to reconstruct an [`AuditEntry`]'s
/// capability from the on-disk record, whose body stores the same Display string
/// the audit MAC commits to — keeping ONE canonical capability encoding.
///
/// Fail-closed: an unrecognised prefix, a bad sub-token (e.g. an unknown data
/// class / storage scope), or a missing argument is a [`CapabilityParseError`],
/// never a guessed capability. NOTE: this does NOT run [`Capability::validate`] —
/// it faithfully reconstructs whatever was recorded (a recorded audit entry's
/// capability is a fact to replay, not a fresh grant to re-vet); the broker's
/// `validate` remains the gate on GRANTING.
impl std::str::FromStr for Capability {
    type Err = CapabilityParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Exact (argument-free) forms first.
        match s {
            "document.transform" => return Ok(Capability::DocumentTransform),
            "compute.model" => return Ok(Capability::ComputeModel),
            "audit.note" => return Ok(Capability::AuditNote),
            _ => {}
        }
        // Prefixed forms `name:arg`. `split_once` keeps the arg intact even if it
        // itself contains a colon (an egress host:port, a ui slot path).
        if let Some(arg) = s.strip_prefix("matter.read:") {
            return Ok(Capability::MatterRead(arg.parse()?));
        }
        if let Some(arg) = s.strip_prefix("matter.write:") {
            return Ok(Capability::MatterWrite(arg.parse()?));
        }
        if let Some(arg) = s.strip_prefix("storage:") {
            return Ok(Capability::Storage(arg.parse()?));
        }
        if let Some(arg) = s.strip_prefix("egress:") {
            // The destination is free-form; Display preserved it verbatim, so we
            // restore it verbatim. (An empty arg is a malformed record — Egress is
            // never empty by construction — so reject it.)
            if arg.is_empty() {
                return Err(CapabilityParseError);
            }
            return Ok(Capability::Egress(arg.to_string()));
        }
        if let Some(arg) = s.strip_prefix("ui.slot:") {
            if arg.is_empty() {
                return Err(CapabilityParseError);
            }
            return Ok(Capability::UiSlot(arg.to_string()));
        }
        Err(CapabilityParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_destination_validator_rejects_ambient_forms() {
        // Empty / whitespace-only / control chars / embedded whitespace.
        for bad in ["", " ", "\t", "\n", "a b", "counsel vault", "x\u{0001}y"] {
            assert!(
                !egress_destination_is_named(bad),
                "{bad:?} must be rejected"
            );
        }
        // Wildcards.
        for bad in ["*", "a*", "*.example.com"] {
            assert!(
                !egress_destination_is_named(bad),
                "{bad:?} must be rejected"
            );
        }
        // Bare all-interfaces / all-routes forms (case-insensitive).
        for bad in ["0.0.0.0", "::", "::0", "::/0", "0.0.0.0/0", "0", "::"] {
            assert!(
                !egress_destination_is_named(bad),
                "{bad:?} must be rejected"
            );
        }
        // F4: the EXPANDED IPv6 all-zeros forms are the same ambient address as
        // `::` / `::/0` written out in full, and the IPv4-mapped unspecified form —
        // each must be rejected too (and case-insensitively for the hex).
        for bad in [
            "0:0:0:0:0:0:0:0",
            "0:0:0:0:0:0:0:0/0",
            "::ffff:0.0.0.0",
            "::FFFF:0.0.0.0", // case-insensitive
        ] {
            assert!(
                !egress_destination_is_named(bad),
                "{bad:?} (expanded IPv6 all-zeros) must be rejected"
            );
        }
        // M-3: broadcast / multicast / loopback ambient forms (case-insensitive).
        for bad in [
            "255.255.255.255",
            "127.0.0.1",
            "::1",
            "ff02::1",
            "ff02::2",
            "FF02::1", // case-insensitive
            "224.0.0.1",
            "224.0.0.2",
        ] {
            assert!(
                !egress_destination_is_named(bad),
                "{bad:?} (ambient form) must be rejected"
            );
        }
    }

    #[test]
    fn egress_destination_validator_accepts_a_named_endpoint() {
        assert!(egress_destination_is_named("counsel-vault"));
        assert!(egress_destination_is_named("vault.internal.example"));
        // A non-all-routes address is still a single named endpoint.
        assert!(egress_destination_is_named("10.0.0.5"));
    }

    #[test]
    fn egress_destination_validator_rejects_parsed_ambient_ips_off_the_literal_list() {
        // #17: the literal AMBIENT_FORMS list enumerates only specific spellings; the
        // PARSED-IP check catches ambient/non-attributable addresses NOT on that list.
        for bad in [
            // the whole 127.0.0.0/8 loopback block, not just 127.0.0.1
            "127.0.0.2",
            "127.1.2.3",
            "127.255.255.254",
            // IPv6 loopback in a bracketed form
            "[::1]",
            // other IPv4 multicast groups (224.0.0.0/4), not just 224.0.0.{1,2}
            "239.255.255.250", // SSDP multicast — a real ambient fan-out
            "224.0.0.251",     // mDNS
            // other IPv6 multicast (ff00::/8), not just ff02::{1,2}
            "ff05::1",
            "[ff02::fb]",
            // the unspecified address in a non-enumerated spelling
            "[::]",
            // a compressed loopback-ish IPv6 that normalises to ::1 is already listed,
            // but an expanded loopback spelling must also be caught by the parser:
            "0:0:0:0:0:0:0:1",
        ] {
            assert!(
                !egress_destination_is_named(bad),
                "{bad:?} parses as an ambient IP and must be rejected (#17)"
            );
        }
        // A genuinely routable unicast IP (v4 + v6) is STILL a named endpoint.
        assert!(egress_destination_is_named("203.0.113.7"));
        assert!(egress_destination_is_named("2001:db8::1"));
        // A hostname that does not parse as an IP is unaffected by the parsed check.
        assert!(egress_destination_is_named("api.counsel.example"));
    }

    #[test]
    fn egress_capability_validate_mirrors_the_validator() {
        // A malformed egress capability fails `validate`; a named one passes.
        assert!(Capability::Egress(" ".into()).validate().is_err());
        assert!(Capability::Egress("0.0.0.0".into()).validate().is_err());
        assert!(Capability::Egress("counsel-vault".into())
            .validate()
            .is_ok());
    }

    #[test]
    fn unenforced_capabilities_are_rejected_by_validate() {
        // H-3: a capability with NO mediated, enforcing Core method yet must be
        // refused by validate() — a grant may never imply an unenforced power.
        // This holds REGARDLESS of shape: even a "well-formed" ui.slot token is
        // rejected, because nothing in the core renders it / audits it yet.
        assert!(Capability::MatterWrite(DataClass::Document)
            .validate()
            .is_err());
        assert!(Capability::ComputeModel.validate().is_err());
        assert!(Capability::UiSlot("".into()).validate().is_err());
        assert!(Capability::UiSlot(" ".into()).validate().is_err());
        assert!(
            Capability::UiSlot("panel.right".into()).validate().is_err(),
            "a well-formed ui.slot is still rejected while no mediated render method exists"
        );
    }

    #[test]
    fn capability_display_from_str_round_trips() {
        // The on-disk audit record stores the capability's Display string (the SAME
        // string the audit MAC commits to); the durable backend reconstructs it via
        // FromStr. FromStr must therefore be the EXACT inverse of Display for every
        // variant — including args that contain a colon (egress host:port, ui slot
        // path) and the reserved/unenforced variants (a recorded entry replays a
        // FACT, so its capability must round-trip even if it could not be re-granted).
        use std::str::FromStr;
        let cases = [
            Capability::MatterRead(DataClass::Document),
            Capability::MatterRead(DataClass::Metadata),
            Capability::MatterRead(DataClass::Activity),
            Capability::MatterWrite(DataClass::Party),
            Capability::Storage(StorageScope::Own),
            Capability::Storage(StorageScope::Shared),
            Capability::DocumentTransform,
            Capability::Egress("counsel-vault".into()),
            Capability::Egress("vault.internal.example:8443".into()), // arg with a colon
            Capability::ComputeModel,
            Capability::UiSlot("panel.right".into()),
            Capability::UiSlot("a:b:c".into()), // arg with colons
            Capability::AuditNote,
        ];
        for cap in cases {
            let s = cap.to_string();
            let back = Capability::from_str(&s)
                .unwrap_or_else(|_| panic!("FromStr must invert Display for {s:?}"));
            assert_eq!(back, cap, "round-trip mismatch for {s:?}");
        }
        // Fail-closed on garbage / unknown sub-tokens / empty args.
        for bad in [
            "",
            "bogus",
            "matter.read:nope", // unknown data class
            "storage:nope",     // unknown scope
            "matter.read:",     // missing class
            "egress:",          // empty destination
            "ui.slot:",         // empty slot
            "matter.read",      // prefix without arg
        ] {
            assert!(
                Capability::from_str(bad).is_err(),
                "{bad:?} must NOT parse to a capability"
            );
        }
    }

    #[test]
    fn from_manifest_drops_unenforced_capabilities() {
        // H-3: since GrantSet::from_manifest filters on validate(), an unenforced
        // capability (matter.write / compute.model / ui.slot) is dropped, so it
        // can never enter a grant set and imply a power the core does not mediate.
        use crate::broker::CapabilityBroker;
        let g = crate::broker::GrantSet::from_manifest(vec![
            Capability::MatterWrite(DataClass::Document),
            Capability::ComputeModel,
            Capability::UiSlot("panel.right".into()),
            // An enforced capability still survives alongside them.
            Capability::Storage(StorageScope::Own),
        ]);
        assert!(!g.is_granted(&Capability::MatterWrite(DataClass::Document)));
        assert!(!g.is_granted(&Capability::ComputeModel));
        assert!(!g.is_granted(&Capability::UiSlot("panel.right".into())));
        assert!(g.is_granted(&Capability::Storage(StorageScope::Own)));
        assert_eq!(
            g.granted().count(),
            1,
            "only the enforced capability survives"
        );
    }
}
