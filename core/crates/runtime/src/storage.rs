// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mediated, namespaced storage (spec §2.4).
//!
//! Modules get NO raw filesystem or DB access. The core provides a scoped,
//! namespaced storage API: a module reads/writes only its OWN namespace within
//! the current matter by default. Every persistence op goes through the core,
//! which is what makes "data stays local" and "data is auditable" enforceable.
//!
//! Keys are namespaced as `<scope>/<module>/<key>` internally so one module can
//! never read another's `own` namespace. Keys and the module segment are
//! sanitized first (no separators / traversal / control chars) so a crafted key
//! can never escape its namespace.
//!
//! `shared` storage is REFUSED here pending a real design: a single global
//! `shared/<key>` bucket has no per-module isolation, so any module holding
//! `storage:shared` could read or overwrite any other module's shared data. A
//! proper design (a named shared-space granted explicitly to specific modules)
//! is still owed; until then the in-memory store will not hand out an
//! unisolated global bucket.

use crate::capability::{Capability, StorageScope};
use crate::error::{CoreError, CoreResult};
use std::collections::HashMap;

/// The storage seam. Each call is capability-checked + logged by the mediator
/// (see [`crate::Core`]); this trait is just the backing store.
pub trait Storage {
    fn get(&self, scope: StorageScope, module: &str, key: &str) -> CoreResult<Option<Vec<u8>>>;
    fn put(
        &mut self,
        scope: StorageScope,
        module: &str,
        key: &str,
        value: Vec<u8>,
    ) -> CoreResult<()>;
    /// Drain a module's scratch namespace (#3): remove every key under
    /// `<scope>/<module>/...`, returning the count removed. Lets the mediator bound
    /// per-module scratch growth between runs (see [`crate::Core::storage_clear`]).
    fn clear_namespace(&mut self, scope: StorageScope, module: &str) -> CoreResult<usize>;
}

/// Reject a key (or module segment) that could escape its namespace once
/// interpolated into `<scope>/<module>/<key>`. A valid segment is non-empty,
/// is not a bare current-dir `.`, and contains none of: `/`, `\`, `..`, any ASCII
/// control char / NUL, or a NON-ASCII control / line / paragraph separator
/// (U+0085, U+2028, U+2029). Returns `Err(CoreError::Backend(..))`.
fn validate_key(key: &str) -> CoreResult<()> {
    let invalid = key.is_empty()
        // M-5: a bare "." is the current-directory selector — reject it outright
        // (".." is already caught by the `contains("..")` rule below; "." on its
        // own must not be a usable key/module segment either).
        || key == "."
        || key.contains('/')
        || key.contains('\\')
        || key.contains("..")
        // ASCII control / NUL.
        || key.chars().any(|c| c.is_ascii_control() || c == '\0')
        // M-4: also reject NON-ASCII control + Unicode line/paragraph separators.
        // `is_ascii_control` misses these, but U+0085 (NEL), U+2028 (LS) and
        // U+2029 (PS) can still inject line breaks into audit detail strings /
        // logs. Reject the Unicode "control" general category (covers U+0085 and
        // the C1 block) plus the two explicit separators.
        || key.chars().any(|c| {
            c.is_control() || c == '\u{2028}' || c == '\u{2029}'
        });
    if invalid {
        // M-8: truncate the echoed key (it may derive from matter data).
        return Err(CoreError::Backend(format!(
            "invalid storage key: {} (must be non-empty, not \".\", and contain no /, \\, .., or control/separator chars)",
            crate::capability::truncate_for_error(key)
        )));
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    map: HashMap<String, Vec<u8>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn namespaced(scope: StorageScope, module: &str, key: &str) -> CoreResult<String> {
        // `own` is keyed by module so namespaces cannot cross. `shared` is
        // refused before reaching here (no unisolated global bucket) by `guard`,
        // so in practice this match only sees `Own`.
        //
        // H-1: NEVER `unreachable!()` mid-op. Even though `guard` rejects `Shared`
        // before any caller reaches here, a future refactor that re-orders or skips
        // `guard` must FAIL CLOSED, not PANIC inside the trusted core. So `Shared`
        // returns an `Err` (the same backend error `guard` would have raised)
        // rather than aborting the process.
        match scope {
            StorageScope::Own => Ok(format!("own/{module}/{key}")),
            StorageScope::Shared => {
                Err(CoreError::Backend("shared scope is not implemented".into()))
            }
        }
    }

    /// Validate scope (shared is refused pending design) and sanitize the module
    /// segment + key before either is interpolated into a namespace.
    fn guard(scope: StorageScope, module: &str, key: &str) -> CoreResult<()> {
        if scope == StorageScope::Shared {
            return Err(CoreError::Backend(
                "shared storage namespacing is not yet designed; refusing an unisolated global bucket".into(),
            ));
        }
        validate_key(module)?;
        validate_key(key)?;
        Ok(())
    }
}

impl Storage for InMemoryStorage {
    fn get(&self, scope: StorageScope, module: &str, key: &str) -> CoreResult<Option<Vec<u8>>> {
        Self::guard(scope, module, key)?;
        Ok(self
            .map
            .get(&Self::namespaced(scope, module, key)?)
            .cloned())
    }

    fn put(
        &mut self,
        scope: StorageScope,
        module: &str,
        key: &str,
        value: Vec<u8>,
    ) -> CoreResult<()> {
        Self::guard(scope, module, key)?;
        self.map
            .insert(Self::namespaced(scope, module, key)?, value);
        Ok(())
    }

    /// Drain a module's scratch namespace (#3): remove every key stored under
    /// `<scope>/<module>/...` for the given `module` + `scope`, returning how many
    /// entries were removed. The Core calls this between module runs (see
    /// [`crate::Core::storage_clear`]) so a module's scratch storage does not
    /// accumulate without bound — a coarse bound that needs no LRU/TTL design
    /// (those land with persistence).
    ///
    /// SCOPE-ISOLATED: it matches ONLY the exact `own/<module>/` prefix, so
    /// clearing module A's namespace can never touch module B's (their prefixes
    /// differ), nor a key whose module name is a PREFIX of another's (the trailing
    /// `/` makes `own/mod/` not a prefix of `own/mod2/...`). `Shared` is REFUSED
    /// here (same as `get`/`put`): no `shared` entries can exist, so there is
    /// nothing to clear, and erroring keeps the refusal consistent rather than
    /// silently "succeeding". The module segment is validated first (same
    /// sanitization as a key) so a crafted `module` cannot widen the prefix.
    fn clear_namespace(&mut self, scope: StorageScope, module: &str) -> CoreResult<usize> {
        if scope == StorageScope::Shared {
            return Err(CoreError::Backend(
                "shared storage namespacing is not yet designed; nothing to clear".into(),
            ));
        }
        validate_key(module)?;
        // Keys live at `own/<module>/<key>`, so the per-module prefix is
        // `own/<module>/`. The trailing slash is load-bearing: it prevents
        // `own/mod/` from also matching `own/mod2/...`.
        let prefix = format!("own/{module}/");
        let before = self.map.len();
        self.map.retain(|k, _| !k.starts_with(&prefix));
        Ok(before - self.map.len())
    }
}

/// The corresponding capability for a storage op at a given scope.
pub fn storage_capability(scope: StorageScope) -> Capability {
    Capability::Storage(scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = "sg.test.module";

    #[test]
    fn invalid_key_is_rejected() {
        let bad_keys = [
            "",
            "a/b",
            "..",
            "../x",
            "a\\b",
            "a\u{0001}b",
            // M-5: a bare current-dir selector.
            ".",
            // M-4: non-ASCII control + Unicode line/paragraph separators that
            // `is_ascii_control` misses but could inject line breaks into logs.
            "a\u{0085}b", // NEL
            "a\u{2028}b", // LINE SEPARATOR
            "a\u{2029}b", // PARAGRAPH SEPARATOR
        ];
        for key in bad_keys {
            let mut store = InMemoryStorage::new();
            let put = store.put(StorageScope::Own, MODULE, key, b"v".to_vec());
            assert!(
                matches!(put, Err(CoreError::Backend(_))),
                "put with key {key:?} should be rejected, got {put:?}"
            );
            let get = store.get(StorageScope::Own, MODULE, key);
            assert!(
                matches!(get, Err(CoreError::Backend(_))),
                "get with key {key:?} should be rejected, got {get:?}"
            );
        }
    }

    #[test]
    fn shared_scope_is_refused() {
        let mut store = InMemoryStorage::new();
        let put = store.put(StorageScope::Shared, MODULE, "k", b"v".to_vec());
        assert!(
            matches!(put, Err(CoreError::Backend(_))),
            "shared put must be refused"
        );
        let get = store.get(StorageScope::Shared, MODULE, "k");
        assert!(
            matches!(get, Err(CoreError::Backend(_))),
            "shared get must be refused"
        );
    }

    #[test]
    fn namespaced_shared_fails_closed_not_panics() {
        // H-1: `namespaced` must NEVER panic mid-op. `guard` rejects Shared before
        // any caller reaches `namespaced`, but if a future refactor skipped that,
        // `namespaced` itself must FAIL CLOSED with a Backend error, not abort the
        // process with `unreachable!()`.
        let res = InMemoryStorage::namespaced(StorageScope::Shared, MODULE, "k");
        assert!(
            matches!(res, Err(CoreError::Backend(_))),
            "shared scope in namespaced must be a Backend error, got {res:?}"
        );
        // Own still produces the namespaced key.
        assert_eq!(
            InMemoryStorage::namespaced(StorageScope::Own, MODULE, "k").unwrap(),
            format!("own/{MODULE}/k")
        );
    }

    #[test]
    fn own_scope_valid_key_roundtrips() {
        let mut store = InMemoryStorage::new();
        store
            .put(StorageScope::Own, MODULE, "k", b"v".to_vec())
            .unwrap();
        let got = store.get(StorageScope::Own, MODULE, "k").unwrap();
        assert_eq!(got, Some(b"v".to_vec()));
    }

    #[test]
    fn clear_namespace_clears_only_the_named_scope_and_module() {
        // #3: clear_namespace drains exactly one module's `own` namespace and
        // leaves every OTHER module's data untouched (scope isolation).
        const OTHER: &str = "sg.other.module";
        let mut store = InMemoryStorage::new();
        store
            .put(StorageScope::Own, MODULE, "a", b"1".to_vec())
            .unwrap();
        store
            .put(StorageScope::Own, MODULE, "b", b"2".to_vec())
            .unwrap();
        store
            .put(StorageScope::Own, OTHER, "a", b"x".to_vec())
            .unwrap();

        let removed = store.clear_namespace(StorageScope::Own, MODULE).unwrap();
        assert_eq!(removed, 2, "both of MODULE's keys are removed");

        // MODULE's namespace is empty now.
        assert_eq!(store.get(StorageScope::Own, MODULE, "a").unwrap(), None);
        assert_eq!(store.get(StorageScope::Own, MODULE, "b").unwrap(), None);
        // OTHER's namespace is untouched.
        assert_eq!(
            store.get(StorageScope::Own, OTHER, "a").unwrap(),
            Some(b"x".to_vec())
        );
    }

    #[test]
    fn clear_namespace_does_not_match_prefix_module_names() {
        // The trailing `/` in the `own/<module>/` prefix prevents clearing module
        // "mod" from also clearing "mod2" (whose keys start with `own/mod2/`).
        let mut store = InMemoryStorage::new();
        store
            .put(StorageScope::Own, "mod", "k", b"1".to_vec())
            .unwrap();
        store
            .put(StorageScope::Own, "mod2", "k", b"2".to_vec())
            .unwrap();

        let removed = store.clear_namespace(StorageScope::Own, "mod").unwrap();
        assert_eq!(removed, 1, "only exactly module \"mod\" is cleared");
        assert_eq!(store.get(StorageScope::Own, "mod", "k").unwrap(), None);
        assert_eq!(
            store.get(StorageScope::Own, "mod2", "k").unwrap(),
            Some(b"2".to_vec())
        );
    }

    #[test]
    fn clear_namespace_refuses_shared_and_invalid_module() {
        let mut store = InMemoryStorage::new();
        assert!(
            matches!(
                store.clear_namespace(StorageScope::Shared, MODULE),
                Err(CoreError::Backend(_))
            ),
            "shared scope must be refused"
        );
        // A crafted module segment is rejected by the same sanitization as a key.
        assert!(
            matches!(
                store.clear_namespace(StorageScope::Own, "../escape"),
                Err(CoreError::Backend(_))
            ),
            "a traversal-bearing module segment must be refused"
        );
        // Clearing an empty namespace is fine: zero removed.
        assert_eq!(store.clear_namespace(StorageScope::Own, MODULE).unwrap(), 0);
    }
}
