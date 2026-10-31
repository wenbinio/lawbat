// SPDX-License-Identifier: AGPL-3.0-or-later
//! Matter context & acting-user (spec §2.1, §2.2).
//!
//! The shell establishes a matter context; a module operates INSIDE it and
//! cannot define or pull arbitrary matters. The acting user is for audit
//! attribution: a module's actions are logged against the human, not the module
//! alone (spec §2.2). Views handed out here are opaque — no path, no raw id.

use crate::error::{CoreError, CoreResult};

/// Private sealing module (#11). [`MatterContext`] has `sealed::Sealed` as a
/// supertrait, and `Sealed` is only implementable INSIDE this crate, so NO
/// out-of-crate type can implement `MatterContext`. That matters because a
/// context impl carries the audit-FIRST invariant: the only sound way to mutate
/// attribution is [`crate::Core::switch_context`], which validates + audits the
/// transition BEFORE it takes effect. Sealing keeps every `MatterContext` impl
/// in this trusted crate (today only `CoreContext`), so a foreign impl can never
/// smuggle in an UNAUDITED `set_context` path. Generic bounds elsewhere
/// (`C: MatterContext`) are unaffected — sealing blocks only foreign *impls*.
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CoreContext {}
}

/// Max length (in chars) for a matter name / acting-user display name (H-2). A
/// legitimate matter/user label is short; an over-long value is almost certainly
/// junk or an attempt to bloat / line-wrap the audit chain, so it is refused.
pub const MAX_CONTEXT_FIELD_LEN: usize = 256;

/// Validate a matter name / acting-user display name BEFORE it is recorded or
/// stored (H-2). A valid field is:
/// - non-empty and non-whitespace-only (after trimming);
/// - free of ASCII control chars / NUL AND non-ASCII control + line/paragraph
///   separators (U+0085 / U+2028 / U+2029) — these could inject line breaks into
///   the audit chain's detail strings or forge log structure;
/// - at most [`MAX_CONTEXT_FIELD_LEN`] chars.
///
/// Returns `Err(CoreError::Backend(..))` (the truncated value is echoed so the
/// message can't leak / bloat on a hostile input). `field` names which field for
/// the error message ("matter" / "user").
pub fn validate_context_field(field: &str, value: &str) -> CoreResult<()> {
    let invalid_len = value.chars().count() > MAX_CONTEXT_FIELD_LEN;
    let invalid = value.trim().is_empty()
        || invalid_len
        || value.chars().any(|c| {
            c.is_ascii_control()
                || c == '\0'
                || c.is_control()
                || c == '\u{2028}'
                || c == '\u{2029}'
        });
    if invalid {
        // Echo a truncated, debug-escaped form so a hostile value can neither leak
        // in full nor bloat / line-wrap the error log.
        let shown: String = value.chars().take(32).collect();
        let ell = if value.chars().count() > 32 {
            "... (truncated)"
        } else {
            ""
        };
        return Err(CoreError::Backend(format!(
            "invalid {field} context field: {shown:?}{ell} (must be non-empty, \u{2264}{MAX_CONTEXT_FIELD_LEN} chars, no control/separator chars)"
        )));
    }
    Ok(())
}

/// Return `value` if it passes [`validate_context_field`], else a fixed, safe
/// placeholder. Used by [`CoreContext::new`] so a malformed initial matter/user name
/// can never reach the audit chain verbatim in a RELEASE build (where the
/// `debug_assert!` is compiled out). The placeholder is deliberately conspicuous and
/// itself control-char-free, so the resulting record is honest ("this field was
/// rejected") rather than carrying an injectable value. `field` is "matter" / "user".
fn sanitize_context_field(field: &str, value: String) -> String {
    if validate_context_field(field, &value).is_ok() {
        value
    } else {
        format!("<invalid {field} context>")
    }
}

/// Opaque matter view (spec §2.1). Deliberately no source path / no raw db id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatterInfo {
    pub name: String,
}

/// Acting-user view (spec §2.2): attribution only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub display_name: String,
}

/// The matter-context seam the core exposes to mediated calls.
///
/// SEALED (#11): supertrait `sealed::Sealed` is only implementable inside this
/// crate, so `MatterContext` cannot be implemented by an out-of-crate type. This
/// prevents a foreign context impl from exposing an UNAUDITED `set_context` path
/// — the audit-first guard in [`crate::Core::switch_context`] stays the single
/// sound way to re-attribute. (`Core` is still generic over `C: MatterContext`,
/// so the seam is preserved; only foreign *impls* are blocked.)
pub trait MatterContext: sealed::Sealed {
    fn current_matter(&self) -> MatterInfo;
    fn acting_user(&self) -> UserInfo;

    /// Re-point the context at a new matter / acting user.
    ///
    /// SECURITY (M-7): the core's [`crate::Core::switch_context`] is the only
    /// intended caller; it VALIDATES the new fields (H-2) and AUDITS the
    /// transition BEFORE calling this (fail-closed), so attribution never changes
    /// without a logged, hash-chained record of the change. This method itself
    /// performs NO validation and NO audit — callers MUST NOT invoke it directly.
    /// It is on the trait only so `Core` can be generic over the context impl;
    /// `Core` keeps its context PRIVATE and never lends out a `&mut C`, so external
    /// code cannot reach this to bypass the guard. (The concrete `CoreContext`'s
    /// inherent mutation, `set`, is `pub(crate)` for the same reason.)
    fn set_context(&mut self, matter_name: &str, user_display_name: &str);
}

/// Simple core-established context for the spike / tests.
#[derive(Debug, Clone)]
pub struct CoreContext {
    matter: MatterInfo,
    user: UserInfo,
}

impl CoreContext {
    /// Establish a context. H-2: the trusted shell is expected to pass a
    /// well-formed matter/user (it controls these, not a module). Construction
    /// stays infallible (it is called widely), but a malformed field is now
    /// handled in RELEASE too, not only flagged by a dev-only `debug_assert!`:
    ///
    /// - a `debug_assert!` still fails fast in dev/test (a bad context is a caller
    ///   bug worth catching loudly);
    /// - in RELEASE the field is SANITIZED to a clearly-marked placeholder rather
    ///   than carried through verbatim. Carrying a malformed value verbatim would
    ///   let a control char / line separator reach the FIRST audit record written
    ///   under this context (before any `switch_context` runs), which is exactly the
    ///   injection [`validate_context_field`] exists to prevent. A visible
    ///   `<invalid …>` placeholder fails closed (the record is honest that the field
    ///   was rejected) without panicking a release build.
    ///
    /// The load-bearing runtime guard for RE-attribution stays
    /// [`crate::Core::switch_context`], which validates BEFORE recording; this just
    /// closes the construction-time gap symmetrically.
    pub fn new(matter_name: impl Into<String>, user_display_name: impl Into<String>) -> Self {
        let matter = matter_name.into();
        let user = user_display_name.into();
        debug_assert!(
            validate_context_field("matter", &matter).is_ok(),
            "CoreContext::new given a malformed matter name"
        );
        debug_assert!(
            validate_context_field("user", &user).is_ok(),
            "CoreContext::new given a malformed acting-user name"
        );
        Self {
            matter: MatterInfo {
                name: sanitize_context_field("matter", matter),
            },
            user: UserInfo {
                display_name: sanitize_context_field("user", user),
            },
        }
    }

    /// Re-point the context at a new matter / acting user. Fields stay private and
    /// this is the ONLY mutation path.
    ///
    /// M-7 / SECURITY: `pub(crate)`, NOT `pub`. Exposing this publicly let any
    /// `&mut CoreContext` holder re-attribute the context WITHOUT going through
    /// [`crate::Core::switch_context`]'s audit-first guard — a silent
    /// misattribution path. Keeping it crate-private means the only way to mutate
    /// attribution is via `switch_context`, which records the transition (and
    /// validates the new fields, H-2) BEFORE the change takes effect. The
    /// `MatterContext::set_context` trait method below stays on the trait (it must,
    /// for `Core` to be generic over `C`), but `Core` never hands out a `&mut C`,
    /// so external code cannot reach it to bypass the guard either.
    pub(crate) fn set(
        &mut self,
        matter_name: impl Into<String>,
        user_display_name: impl Into<String>,
    ) {
        self.matter = MatterInfo {
            name: matter_name.into(),
        };
        self.user = UserInfo {
            display_name: user_display_name.into(),
        };
    }
}

impl MatterContext for CoreContext {
    fn current_matter(&self) -> MatterInfo {
        self.matter.clone()
    }

    fn acting_user(&self) -> UserInfo {
        self.user.clone()
    }

    fn set_context(&mut self, matter_name: &str, user_display_name: &str) {
        self.set(matter_name, user_display_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_context_reads_back_what_it_was_built_with() {
        let ctx = CoreContext::new("Acme v Beta", "j.smith");
        assert_eq!(ctx.current_matter().name, "Acme v Beta");
        assert_eq!(ctx.acting_user().display_name, "j.smith");
    }

    #[test]
    fn crate_internal_set_mutates_attribution() {
        // #11 / M-7: `set` is the ONLY mutation path and is `pub(crate)`, so it is
        // reachable only from inside this crate (e.g. `Core::switch_context`, which
        // validates + audits first). Here we exercise it directly as the crate
        // would; an out-of-crate caller cannot reach this (and cannot implement the
        // SEALED `MatterContext` to add an alternative mutation path).
        let mut ctx = CoreContext::new("Acme v Beta", "j.smith");
        ctx.set("Beta v Gamma", "k.lee");
        assert_eq!(ctx.current_matter().name, "Beta v Gamma");
        assert_eq!(ctx.acting_user().display_name, "k.lee");
    }

    #[test]
    fn validate_context_field_rejects_malformed() {
        // Sanity on the shared validator the audited switch path relies on.
        assert!(validate_context_field("matter", "Acme v Beta").is_ok());
        assert!(validate_context_field("matter", "").is_err());
        assert!(validate_context_field("user", "   ").is_err());
        assert!(validate_context_field("user", "k\u{2028}lee").is_err());
        assert!(validate_context_field("matter", &"x".repeat(257)).is_err());
    }
}
