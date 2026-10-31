// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capability broker (spec §2.6, §5.2).
//!
//! Modules declare required capabilities in a manifest; the core grants or
//! denies at install/sign time; **every runtime request is checked against the
//! grant.** No ambient authority, nothing granted by default (default-deny).

use crate::capability::Capability;
use crate::error::{CoreError, CoreResult};
use std::collections::HashSet;

/// The broker seam. `check` is the enforcement point every mediated call passes
/// through before it acts (spec §0: every brokered call is checked + logged).
pub trait CapabilityBroker {
    /// Add a capability to the grant set (records a grant at install/sign time).
    ///
    /// Granting a malformed capability (e.g. a wildcard/empty/all-routes egress
    /// destination, spec §5.4) is REFUSED with an `Err`; nothing is inserted.
    fn grant(&mut self, cap: Capability) -> CoreResult<()>;

    /// Remove the one NAMED destination/capability passed from the grant set
    /// (spec §2.5). This revokes only that entry, not all egress.
    fn deny(&mut self, cap: &Capability);

    /// True iff `cap` is in the grant set. A malformed capability (e.g. a
    /// wildcard egress destination) is never considered granted, even if such a
    /// value somehow reached the set — the check path refuses it defensively.
    fn is_granted(&self, cap: &Capability) -> bool;

    /// Enforcement: Ok if granted, else `CoreError::Denied` (spec §5.2).
    fn check(&self, cap: &Capability) -> CoreResult<()> {
        // Defensive: a malformed capability can never pass the gate, regardless
        // of what is stored. Validation failure is reported as Denied here so
        // callers treat it as "not granted" at the chokepoint.
        if cap.validate().is_err() {
            return Err(CoreError::Denied(cap.clone()));
        }
        if self.is_granted(cap) {
            Ok(())
        } else {
            Err(CoreError::Denied(cap.clone()))
        }
    }
}

/// In-memory grant set. Starts EMPTY — default-deny is the construction, not a
/// configured policy.
#[derive(Debug, Default)]
pub struct GrantSet {
    granted: HashSet<Capability>,
}

impl GrantSet {
    /// A fresh, empty (default-deny) grant set.
    pub fn new() -> Self {
        Self {
            granted: HashSet::new(),
        }
    }

    /// Build a grant set from a declared manifest list, SURFACING the rejects
    /// (spec §5.2 grant flow). Malformed OR unenforceable capabilities (e.g. a
    /// wildcard/empty egress destination, §5.4; or a taxonomy-only
    /// matter.write/compute.model/ui.slot, H-3) are REFUSED — never inserted, so a
    /// manifest cannot smuggle in ambient egress or an unenforced power. Validation
    /// mirrors [`CapabilityBroker::grant`].
    ///
    /// F6 (High — fixed): returns BOTH the (default-deny) grant set AND the list of
    /// REJECTED capabilities, rather than silently dropping the rejects. A silent
    /// drop meant a manifest could declare N capabilities and the core would build
    /// a smaller grant set with NO signal that some were refused — a module would
    /// then fail brokered calls it "declared", and an operator would have no record
    /// of WHICH capabilities the core refused at load. Callers must inspect the
    /// rejected list (log it; in tests assert it empty). The grant set still
    /// contains ONLY the validated capabilities, so default-deny is unchanged.
    ///
    /// The thin [`GrantSet::from_manifest`] wrapper preserves the old
    /// `-> GrantSet` signature for existing call sites by logging the rejects to
    /// stderr; new/security-sensitive call sites should use THIS method and handle
    /// the rejected list explicitly.
    pub fn from_manifest_checked<I: IntoIterator<Item = Capability>>(
        caps: I,
    ) -> (Self, Vec<Capability>) {
        let mut granted = HashSet::new();
        let mut rejected = Vec::new();
        for cap in caps {
            if cap.validate().is_ok() {
                granted.insert(cap);
            } else {
                rejected.push(cap);
            }
        }
        (Self { granted }, rejected)
    }

    /// Build a grant set from a declared manifest list (spec §5.2 grant flow),
    /// returning just the grant set. Convenience wrapper over
    /// [`GrantSet::from_manifest_checked`] for call sites that only need the
    /// `GrantSet`: it still REFUSES malformed/unenforceable capabilities (never
    /// inserts them — default-deny is preserved), but rather than DROPPING the
    /// rejects with no signal (the F6 defect), it LOGS each refused capability to
    /// stderr. A call site that must act on the rejects (deny load, surface firm
    /// consent, assert none in tests) should call `from_manifest_checked` directly.
    pub fn from_manifest<I: IntoIterator<Item = Capability>>(caps: I) -> Self {
        let (grants, rejected) = Self::from_manifest_checked(caps);
        // The runtime is intentionally std-only (no `log`/`tracing` dep — see the
        // crate Cargo.toml note), so surface the rejects on stderr. This turns a
        // SILENT drop into a visible operational signal without adding a dependency
        // to the most-trusted crate. The detail is rendered via
        // `capability_for_error`, which TRUNCATES + debug-escapes an egress
        // destination (the one variant carrying an attacker-/manifest-influenced,
        // possibly long-or-control-char value) so a hostile manifest can neither
        // bloat nor line-wrap stderr; other variants are short, fixed taxonomy forms.
        for cap in &rejected {
            eprintln!(
                "runtime: from_manifest refused unenforceable/malformed capability (not granted): {}",
                crate::capability::capability_for_error(cap)
            );
        }
        grants
    }

    pub fn granted(&self) -> impl Iterator<Item = &Capability> {
        self.granted.iter()
    }
}

impl CapabilityBroker for GrantSet {
    fn grant(&mut self, cap: Capability) -> CoreResult<()> {
        cap.validate()?; // refuse malformed (e.g. wildcard/empty egress) — §5.4
        self.granted.insert(cap);
        Ok(())
    }

    fn deny(&mut self, cap: &Capability) {
        self.granted.remove(cap);
    }

    fn is_granted(&self, cap: &Capability) -> bool {
        // A malformed capability is never granted, even if present in the set.
        cap.validate().is_ok() && self.granted.contains(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::StorageScope;

    #[test]
    fn default_and_new_grant_nothing() {
        // Default-deny is locked in by construction: a fresh/default grant set
        // grants NO capability of any kind.
        let fresh = GrantSet::new();
        let dflt = GrantSet::default();
        assert_eq!(fresh.granted().count(), 0);
        assert_eq!(dflt.granted().count(), 0);
        assert!(!fresh.is_granted(&Capability::Storage(StorageScope::Own)));
        assert!(!fresh.is_granted(&Capability::Egress("counsel-vault".into())));
        assert!(fresh
            .check(&Capability::Storage(StorageScope::Own))
            .is_err());
    }

    #[test]
    fn granting_wildcard_or_empty_egress_is_refused() {
        let mut g = GrantSet::new();
        // Wildcard and empty destinations are refused at grant time.
        assert!(g.grant(Capability::Egress("*".into())).is_err());
        assert!(g.grant(Capability::Egress("".into())).is_err());
        // An all-routes CIDR is equally refused.
        assert!(g.grant(Capability::Egress("0.0.0.0/0".into())).is_err());
        assert!(g.grant(Capability::Egress("::/0".into())).is_err());
        // Nothing was inserted.
        assert_eq!(g.granted().count(), 0);
        // A check against such a value never passes, even via the gate.
        assert!(g.check(&Capability::Egress("*".into())).is_err());
        assert!(g.check(&Capability::Egress("".into())).is_err());
        // A well-formed destination still grants fine.
        assert!(g.grant(Capability::Egress("counsel-vault".into())).is_ok());
        assert!(g.is_granted(&Capability::Egress("counsel-vault".into())));
    }

    #[test]
    fn from_manifest_drops_malformed_egress() {
        let g = GrantSet::from_manifest(vec![
            Capability::Egress("*".into()),
            Capability::Egress("counsel-vault".into()),
        ]);
        // Only the well-formed destination survived.
        assert!(!g.is_granted(&Capability::Egress("*".into())));
        assert!(g.is_granted(&Capability::Egress("counsel-vault".into())));
        assert_eq!(g.granted().count(), 1);
    }

    #[test]
    fn from_manifest_checked_surfaces_rejects() {
        // F6: rejected capabilities are RETURNED, not silently dropped. Mix
        // malformed (wildcard/empty/all-routes egress) AND unenforceable
        // (matter.write / compute.model / ui.slot, H-3) caps with valid ones.
        use crate::capability::DataClass;
        let (g, rejected) = GrantSet::from_manifest_checked(vec![
            Capability::Egress("*".into()),               // malformed -> reject
            Capability::Egress("".into()),                // malformed -> reject
            Capability::Egress("0.0.0.0/0".into()),       // all-routes -> reject
            Capability::MatterWrite(DataClass::Document), // unenforceable -> reject
            Capability::ComputeModel,                     // unenforceable -> reject
            Capability::UiSlot("panel.right".into()),     // unenforceable -> reject
            Capability::Storage(StorageScope::Own),       // valid -> grant
            Capability::Egress("counsel-vault".into()),   // valid -> grant
        ]);

        // The grant set holds ONLY the two valid capabilities (default-deny intact).
        assert_eq!(g.granted().count(), 2);
        assert!(g.is_granted(&Capability::Storage(StorageScope::Own)));
        assert!(g.is_granted(&Capability::Egress("counsel-vault".into())));

        // ALL six rejects are surfaced (count + identity), not dropped.
        assert_eq!(
            rejected.len(),
            6,
            "every refused capability must be surfaced, got {rejected:?}"
        );
        assert!(rejected.contains(&Capability::Egress("*".into())));
        assert!(rejected.contains(&Capability::Egress("".into())));
        assert!(rejected.contains(&Capability::Egress("0.0.0.0/0".into())));
        assert!(rejected.contains(&Capability::MatterWrite(DataClass::Document)));
        assert!(rejected.contains(&Capability::ComputeModel));
        assert!(rejected.contains(&Capability::UiSlot("panel.right".into())));
        // No valid cap leaked into the reject list.
        assert!(!rejected.contains(&Capability::Storage(StorageScope::Own)));
        assert!(!rejected.contains(&Capability::Egress("counsel-vault".into())));
    }

    #[test]
    fn from_manifest_checked_all_valid_has_empty_rejects() {
        // The common path: a manifest of only valid caps yields NO rejects, so a
        // caller's `assert!(rejected.is_empty())` holds.
        let (g, rejected) = GrantSet::from_manifest_checked(vec![
            Capability::Storage(StorageScope::Own),
            Capability::Egress("counsel-vault".into()),
        ]);
        assert!(
            rejected.is_empty(),
            "no valid cap may be rejected, got {rejected:?}"
        );
        assert_eq!(g.granted().count(), 2);
    }

    #[test]
    fn from_manifest_wrapper_still_drops_rejects_default_deny() {
        // The convenience `from_manifest` wrapper preserves the old behavior for
        // existing call sites: rejects are NOT granted (default-deny), only the
        // valid caps survive. (The wrapper additionally logs the rejects to stderr;
        // we assert the grant-set outcome here.)
        let g = GrantSet::from_manifest(vec![
            Capability::Egress("*".into()),         // dropped
            Capability::ComputeModel,               // dropped (unenforceable)
            Capability::Storage(StorageScope::Own), // kept
        ]);
        assert!(!g.is_granted(&Capability::Egress("*".into())));
        assert!(!g.is_granted(&Capability::ComputeModel));
        assert!(g.is_granted(&Capability::Storage(StorageScope::Own)));
        assert_eq!(g.granted().count(), 1);
    }
}
