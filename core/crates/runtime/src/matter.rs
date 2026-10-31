// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mediated matter document store (architecture spec §2.3, §6).
//!
//! Modules get NO raw access to matter data. A matter holds documents, each
//! tagged with a [`DataClass`]; a module can only LIST, READ, or TRANSFORM
//! documents through the mediated [`crate::Core`] methods, each of which
//! capability-checks, **entitlement-filters by data class** (spec §2.3: a module
//! sees only the classes it is granted — the Chinese-wall / screen-group filter
//! happens in the CORE, before a module sees anything), and audits.
//!
//! This seam is the backing store ONLY. It performs NO capability check and NO
//! audit — that is the mediator's job ([`crate::Core::matter_list_docs`] /
//! [`crate::Core::matter_read_text`] / [`crate::Core::document_transform`]). The
//! store is owned PRIVATELY by `Core`; a module never holds a reference to it
//! (so it can never read/rewrite content out from under the chokepoint, spec §6).
//!
//! ## Text XOR bytes — the content-kind dimension (to-read/runtime.PDF-CORE-WIRING-PROPOSAL.md §2/§3)
//!
//! A document's content is EITHER UTF-8 text ([`MatterContent::Text`]) OR opaque
//! bytes ([`MatterContent::Blob`]) — never both, never coerced between the two.
//! This is the binary content path that lets `redaction::redact_pdf` run THROUGH
//! the chokepoint (a PDF is bytes; `content: String` could not hold it losslessly).
//! It is a **content-KIND** dimension, NOT an entitlement dimension: a PDF is still
//! a `document`-class doc, gated by the existing `matter.read:document` +
//! `document.transform` — no new capability, no new [`DataClass`]. The
//! text accessors ([`MatterStore::read`] / [`MatterStore::set_content`]) operate on
//! `Text` docs and the blob accessors ([`MatterStore::read_blob`] /
//! [`MatterStore::set_blob`]) on `Blob` docs; a text accessor on a `Blob` doc (and
//! vice-versa) returns `None`/`false` — a content-kind MISMATCH, never a coerced or
//! garbled read.

use crate::capability::DataClass;

/// The content of one matter document: UTF-8 text XOR opaque bytes.
///
/// INERT by design — a plain data enum with no methods that touch I/O, no RNG, no
/// parsing. It lives here (not in a module) because the trusted store owns it and
/// a module never holds it. A document is text XOR bytes (never both): text flows
/// through [`MatterStore::read`]/[`MatterStore::set_content`] (the `&str ->
/// String` path), bytes through [`MatterStore::read_blob`]/[`MatterStore::set_blob`]
/// (the `&[u8] -> Vec<u8>` path). The two never coerce into each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatterContent {
    /// UTF-8 text content (memos, emails, the canonical metadata form, …). The
    /// historical `content: String` case; reached via the text accessors.
    Text(String),
    /// Opaque binary content (a PDF, a `.docx`, …). Reached ONLY via the blob
    /// accessors; the text accessors return `None`/`false` for it (a PDF's bytes
    /// are not valid UTF-8, so coercing them through the text path would corrupt
    /// them — fail-closed to a content-kind mismatch instead).
    Blob(Vec<u8>),
}

/// The content KIND of a matter document, as surfaced on a [`DocRef`] — the
/// type-level shadow of [`MatterContent`] (text XOR bytes) WITHOUT the content
/// itself. A lister learns whether a doc is text or blob from the listing it
/// already received (the mediated `matter_list_docs`), so it can pick the right
/// read accessor (`matter_read_text` vs `matter_read_blob`) WITHOUT a blind read
/// attempt that would audit a value-free no-op entry on every wrong-kind doc.
///
/// This is a content-KIND signal, NOT an entitlement one: it travels INSIDE the
/// chokepoint on the `DocRef` the core already returns (no raw out-of-band kind
/// query), and a `Text` doc and a `Blob` doc of the SAME class still coexist —
/// the kind only tells a sweep which accessor to use, never which class it may
/// reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// The doc holds UTF-8 text ([`MatterContent::Text`]); read via the text
    /// accessor (`matter_read_text` / [`MatterStore::read`]).
    Text,
    /// The doc holds opaque bytes ([`MatterContent::Blob`]); read via the blob
    /// accessor (`matter_read_blob` / [`MatterStore::read_blob`]).
    Blob,
}

/// An opaque reference to a matter document (spec §2.1: opaque views, no path /
/// no raw db id leaked). Carries the stable `id` (used to read/transform), the
/// document's `class` (so a caller knows which entitlement it fell under), and
/// its content `kind` (text XOR blob — so a sweep picks the right accessor
/// WITHOUT a blind wrong-kind read that would emit a value-free audit no-op).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocRef {
    pub id: u64,
    pub class: DataClass,
    pub kind: ContentKind,
}

/// One stored matter document. `content` is the only mutable field — rewritten
/// in place by [`MatterStore::set_content`] (for [`MatterContent::Text`]) or
/// [`MatterStore::set_blob`] (for [`MatterContent::Blob`]), reached ONLY via the
/// core's mediated `document_transform` / `document_transform_blob`. A doc's
/// content KIND is fixed by how it was seeded ([`InMemoryMatterStore::insert`] =
/// text; [`InMemoryMatterStore::insert_blob`] = bytes); the set accessors rewrite a
/// doc's bytes IN ITS OWN KIND only, never converting one kind into the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatterDoc {
    pub id: u64,
    pub class: DataClass,
    pub content: MatterContent,
}

/// The matter-document seam. The mediator ([`crate::Core`]) is the only caller;
/// this trait neither checks capabilities nor audits.
///
/// The text accessors ([`read`](MatterStore::read) /
/// [`set_content`](MatterStore::set_content)) and the blob accessors
/// ([`read_blob`](MatterStore::read_blob) / [`set_blob`](MatterStore::set_blob))
/// are CONTENT-KIND aware: each operates ONLY on documents of its own kind. A text
/// accessor on a [`MatterContent::Blob`] doc (and a blob accessor on a
/// [`MatterContent::Text`] doc) is a content-kind MISMATCH and returns
/// `None`/`false` — NEVER a coerced or garbled read.
pub trait MatterStore {
    /// All docs of EXACTLY `class` (the entitlement pre-filter, spec §2.3). A
    /// class the caller has not been granted is filtered out in the core BEFORE
    /// this is reached; this returns only the matching class so the core never
    /// even materializes a non-granted class for the module.
    ///
    /// Each [`DocRef`] names the doc's id + class + content `kind` (text XOR
    /// blob). The kind lets a reader pick the right accessor up front
    /// ([`read`](MatterStore::read) for text, [`read_blob`](MatterStore::read_blob)
    /// for bytes) WITHOUT a blind wrong-kind read attempt — a wrong-kind read
    /// would still return None, but routed through the mediated core it would also
    /// emit a value-free audit no-op for every wrong-kind doc. The kind is a
    /// content signal carried INSIDE the listing, not an entitlement dimension:
    /// `Text` and `Blob` docs of the same class still both list.
    fn list(&self, class: DataClass) -> Vec<DocRef>;

    /// The TEXT content of `id`, but ONLY if it exists AND is of `class` AND is a
    /// [`MatterContent::Text`] doc. Returns `None` if the doc is absent, is a
    /// DIFFERENT class than the one the caller is entitled to (so a granted `party`
    /// read can never reach a `document`-class doc by guessing its id), OR is a
    /// [`MatterContent::Blob`] (a content-kind mismatch — the bytes are NEVER
    /// coerced to a `String`).
    fn read(&self, id: u64, class: DataClass) -> Option<String>;

    /// The BLOB content of `id`, but ONLY if it exists AND is of `class` AND is a
    /// [`MatterContent::Blob`] doc. The byte-typed sibling of [`read`](MatterStore::read),
    /// with the SAME entitlement semantics (absent / wrong class → `None`) PLUS the
    /// content-kind filter: a [`MatterContent::Text`] doc returns `None` (a mismatch
    /// — text is never re-encoded to bytes here).
    fn read_blob(&self, id: u64, class: DataClass) -> Option<Vec<u8>>;

    /// Rewrite the TEXT content of `id` in place, but ONLY if it exists AND is of
    /// `class` AND is a [`MatterContent::Text`] doc. Returns `true` if a doc was
    /// rewritten, `false` otherwise (absent / wrong class / a [`MatterContent::Blob`]
    /// doc — never converts a blob doc to text). The core calls this only after a
    /// `document.transform` capability check + a successful text read of the same
    /// (id, class).
    fn set_content(&mut self, id: u64, class: DataClass, content: String) -> bool;

    /// Rewrite the BLOB content of `id` in place, but ONLY if it exists AND is of
    /// `class` AND is a [`MatterContent::Blob`] doc. The byte-typed sibling of
    /// [`set_content`](MatterStore::set_content): returns `true` if a blob doc was
    /// rewritten, `false` otherwise (absent / wrong class / a [`MatterContent::Text`]
    /// doc — never converts a text doc to bytes). The core calls this only after a
    /// `document.transform` capability check + a successful blob read of the same
    /// (id, class).
    fn set_blob(&mut self, id: u64, class: DataClass, content: Vec<u8>) -> bool;
}

/// Simple in-memory matter document store for the spike / tests. Owned privately
/// by [`crate::Core`]; seeded by the trusted host/tests via [`MatterStore`]-free
/// inserts ([`InMemoryMatterStore::insert`] / [`InMemoryMatterStore::insert_blob`]).
#[derive(Debug, Default)]
pub struct InMemoryMatterStore {
    docs: Vec<MatterDoc>,
}

impl InMemoryMatterStore {
    pub fn new() -> Self {
        Self { docs: Vec::new() }
    }

    /// Seed/insert a TEXT document (used by the trusted host/tests to populate a
    /// matter). This is NOT a module-reachable path: a module never holds an
    /// `InMemoryMatterStore`, only a `&mut Core`, which exposes no insert — so a
    /// module can never inject documents, only list/read/transform granted ones.
    /// If `id` already exists its content + class are replaced (last write wins),
    /// keeping seeding deterministic. The doc's content KIND becomes
    /// [`MatterContent::Text`] (a prior `Blob` at this id is replaced by text).
    pub fn insert(&mut self, id: u64, class: DataClass, content: impl Into<String>) {
        self.insert_content(id, class, MatterContent::Text(content.into()));
    }

    /// Seed/insert a BLOB (binary) document — the byte-typed sibling of
    /// [`insert`](InMemoryMatterStore::insert), used to seed a PDF / `.docx` / other
    /// binary doc. Same not-module-reachable + last-write-wins seeding semantics;
    /// the doc's content KIND becomes [`MatterContent::Blob`] (a prior `Text` at this
    /// id is replaced by bytes).
    pub fn insert_blob(&mut self, id: u64, class: DataClass, content: impl Into<Vec<u8>>) {
        self.insert_content(id, class, MatterContent::Blob(content.into()));
    }

    /// Shared insert: replace (last write wins) or push a doc with the given
    /// content kind. Keeps `insert`/`insert_blob` a single seeding code path.
    fn insert_content(&mut self, id: u64, class: DataClass, content: MatterContent) {
        if let Some(existing) = self.docs.iter_mut().find(|d| d.id == id) {
            existing.class = class;
            existing.content = content;
        } else {
            self.docs.push(MatterDoc { id, class, content });
        }
    }

    /// Read the raw TEXT content of a doc by id IGNORING class — test/inspection
    /// only (e.g. asserting what the store holds after a transform). Returns `None`
    /// for a [`MatterContent::Blob`] doc (a content-kind mismatch — never coerced).
    /// NOT a mediated path; the core never routes a module through this.
    pub fn raw_content(&self, id: u64) -> Option<&str> {
        self.docs
            .iter()
            .find(|d| d.id == id)
            .and_then(|d| match &d.content {
                MatterContent::Text(s) => Some(s.as_str()),
                MatterContent::Blob(_) => None,
            })
    }

    /// Read the raw BLOB content of a doc by id IGNORING class — test/inspection
    /// only (the byte-typed sibling of [`raw_content`](InMemoryMatterStore::raw_content),
    /// e.g. asserting what the store holds after a blob transform). Returns `None`
    /// for a [`MatterContent::Text`] doc (a content-kind mismatch — never coerced).
    /// NOT a mediated path.
    pub fn raw_blob(&self, id: u64) -> Option<&[u8]> {
        self.docs
            .iter()
            .find(|d| d.id == id)
            .and_then(|d| match &d.content {
                MatterContent::Blob(b) => Some(b.as_slice()),
                MatterContent::Text(_) => None,
            })
    }
}

impl MatterStore for InMemoryMatterStore {
    fn list(&self, class: DataClass) -> Vec<DocRef> {
        // Entitlement pre-filter: return ONLY docs whose class matches. Ordered
        // by id so the listing is deterministic run to run. Each DocRef carries
        // the doc's content KIND (text XOR blob) from the stored MatterContent, so
        // a sweep picks the right accessor without a blind wrong-kind read. Both
        // Text and Blob docs of `class` are listed (kind is informational, not an
        // entitlement filter).
        let mut refs: Vec<DocRef> = self
            .docs
            .iter()
            .filter(|d| d.class == class)
            .map(|d| DocRef {
                id: d.id,
                class: d.class,
                kind: match d.content {
                    MatterContent::Text(_) => ContentKind::Text,
                    MatterContent::Blob(_) => ContentKind::Blob,
                },
            })
            .collect();
        refs.sort_by_key(|r| r.id);
        refs
    }

    fn read(&self, id: u64, class: DataClass) -> Option<String> {
        // Text accessor: matches id AND class AND content KIND = Text. A Blob doc
        // yields None (content-kind mismatch — bytes are never coerced to a String).
        self.docs
            .iter()
            .find(|d| d.id == id && d.class == class)
            .and_then(|d| match &d.content {
                MatterContent::Text(s) => Some(s.clone()),
                MatterContent::Blob(_) => None,
            })
    }

    fn read_blob(&self, id: u64, class: DataClass) -> Option<Vec<u8>> {
        // Blob accessor: matches id AND class AND content KIND = Blob. A Text doc
        // yields None (content-kind mismatch — text is never re-encoded to bytes).
        self.docs
            .iter()
            .find(|d| d.id == id && d.class == class)
            .and_then(|d| match &d.content {
                MatterContent::Blob(b) => Some(b.clone()),
                MatterContent::Text(_) => None,
            })
    }

    fn set_content(&mut self, id: u64, class: DataClass, content: String) -> bool {
        // Rewrite a TEXT doc in place ONLY. A Blob doc at (id, class) is NOT
        // matched, so it is never converted to text (returns false).
        if let Some(doc) = self
            .docs
            .iter_mut()
            .find(|d| d.id == id && d.class == class && matches!(d.content, MatterContent::Text(_)))
        {
            doc.content = MatterContent::Text(content);
            true
        } else {
            false
        }
    }

    fn set_blob(&mut self, id: u64, class: DataClass, content: Vec<u8>) -> bool {
        // Rewrite a BLOB doc in place ONLY. A Text doc at (id, class) is NOT
        // matched, so it is never converted to bytes (returns false).
        if let Some(doc) = self
            .docs
            .iter_mut()
            .find(|d| d.id == id && d.class == class && matches!(d.content, MatterContent::Blob(_)))
        {
            doc.content = MatterContent::Blob(content);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> InMemoryMatterStore {
        let mut s = InMemoryMatterStore::new();
        s.insert(1, DataClass::Document, "doc one");
        s.insert(2, DataClass::Party, "party two");
        s.insert(3, DataClass::Document, "doc three");
        s
    }

    #[test]
    fn list_returns_only_the_named_class_sorted() {
        let s = seeded();
        let docs = s.list(DataClass::Document);
        assert_eq!(
            docs,
            vec![
                DocRef {
                    id: 1,
                    class: DataClass::Document,
                    kind: ContentKind::Text
                },
                DocRef {
                    id: 3,
                    class: DataClass::Document,
                    kind: ContentKind::Text
                },
            ]
        );
        let parties = s.list(DataClass::Party);
        assert_eq!(
            parties,
            vec![DocRef {
                id: 2,
                class: DataClass::Party,
                kind: ContentKind::Text
            }]
        );
        // A class with no docs lists empty.
        assert!(s.list(DataClass::Annotation).is_empty());
    }

    #[test]
    fn read_enforces_class_match() {
        let s = seeded();
        assert_eq!(s.read(1, DataClass::Document).as_deref(), Some("doc one"));
        // Right id, WRONG class -> None (cannot reach a document via a party grant).
        assert_eq!(s.read(1, DataClass::Party), None);
        // Absent id -> None.
        assert_eq!(s.read(99, DataClass::Document), None);
    }

    #[test]
    fn set_content_enforces_class_match() {
        let mut s = seeded();
        assert!(s.set_content(1, DataClass::Document, "rewritten".into()));
        assert_eq!(s.raw_content(1), Some("rewritten"));
        // Wrong class -> no write, returns false.
        assert!(!s.set_content(1, DataClass::Party, "nope".into()));
        assert_eq!(s.raw_content(1), Some("rewritten"));
        // Absent id -> false.
        assert!(!s.set_content(99, DataClass::Document, "x".into()));
    }

    #[test]
    fn insert_replaces_existing_id() {
        let mut s = InMemoryMatterStore::new();
        s.insert(1, DataClass::Document, "first");
        s.insert(1, DataClass::Party, "second");
        assert_eq!(s.raw_content(1), Some("second"));
        // The class was replaced too: it is now a party doc, not a document.
        assert!(s.list(DataClass::Document).is_empty());
        assert_eq!(s.list(DataClass::Party).len(), 1);
    }

    // ---- blob (binary content) accessors + content-kind isolation -------------

    fn seeded_mixed() -> InMemoryMatterStore {
        let mut s = InMemoryMatterStore::new();
        s.insert(1, DataClass::Document, "a text document");
        s.insert_blob(
            2,
            DataClass::Document,
            b"\x89PDF-ish\x00\xff bytes".to_vec(),
        );
        s
    }

    #[test]
    fn list_reports_each_docs_content_kind() {
        // The DocRef's kind mirrors the stored MatterContent, so a sweep can pick
        // the right accessor (text vs blob) without a blind wrong-kind read.
        let s = seeded_mixed();
        let docs = s.list(DataClass::Document);
        assert_eq!(
            docs,
            vec![
                DocRef {
                    id: 1,
                    class: DataClass::Document,
                    kind: ContentKind::Text
                },
                DocRef {
                    id: 2,
                    class: DataClass::Document,
                    kind: ContentKind::Blob
                },
            ]
        );
    }

    #[test]
    fn read_blob_enforces_class_match() {
        let s = seeded_mixed();
        assert_eq!(
            s.read_blob(2, DataClass::Document).as_deref(),
            Some(&b"\x89PDF-ish\x00\xff bytes"[..])
        );
        // Right id, WRONG class -> None.
        assert_eq!(s.read_blob(2, DataClass::Party), None);
        // Absent id -> None.
        assert_eq!(s.read_blob(99, DataClass::Document), None);
    }

    #[test]
    fn text_and_blob_accessors_do_not_coerce_across_kinds() {
        // The load-bearing content-kind isolation: a text accessor on a Blob doc
        // (and a blob accessor on a Text doc) returns None — never a coerced read.
        let s = seeded_mixed();
        // Text accessor on the BLOB doc (id 2) -> None (mismatch).
        assert_eq!(
            s.read(2, DataClass::Document),
            None,
            "text read of a blob must not coerce"
        );
        assert_eq!(s.raw_content(2), None, "raw_content of a blob must be None");
        // Blob accessor on the TEXT doc (id 1) -> None (mismatch).
        assert_eq!(
            s.read_blob(1, DataClass::Document),
            None,
            "blob read of text must not coerce"
        );
        assert_eq!(s.raw_blob(1), None, "raw_blob of text must be None");
        // The correct-kind reads DO succeed.
        assert_eq!(
            s.read(1, DataClass::Document).as_deref(),
            Some("a text document")
        );
        assert!(s.read_blob(2, DataClass::Document).is_some());
    }

    #[test]
    fn set_blob_enforces_class_and_kind() {
        let mut s = seeded_mixed();
        // Rewrite the blob doc.
        assert!(s.set_blob(2, DataClass::Document, b"new bytes".to_vec()));
        assert_eq!(s.raw_blob(2), Some(&b"new bytes"[..]));
        // Wrong class -> no write.
        assert!(!s.set_blob(2, DataClass::Party, b"nope".to_vec()));
        assert_eq!(s.raw_blob(2), Some(&b"new bytes"[..]));
        // KIND mismatch: set_blob on the TEXT doc (id 1) must NOT convert it.
        assert!(!s.set_blob(1, DataClass::Document, b"x".to_vec()));
        assert_eq!(
            s.raw_content(1),
            Some("a text document"),
            "text doc unchanged"
        );
        assert_eq!(s.raw_blob(1), None, "text doc never became a blob");
        // KIND mismatch: set_content on the BLOB doc (id 2) must NOT convert it.
        assert!(!s.set_content(2, DataClass::Document, "y".into()));
        assert_eq!(s.raw_blob(2), Some(&b"new bytes"[..]), "blob doc unchanged");
        assert_eq!(s.raw_content(2), None, "blob doc never became text");
    }

    #[test]
    fn insert_blob_replaces_a_text_id_with_bytes_and_back() {
        let mut s = InMemoryMatterStore::new();
        s.insert(1, DataClass::Document, "text first");
        // Replacing with a blob flips the content kind.
        s.insert_blob(1, DataClass::Document, b"bytes now".to_vec());
        assert_eq!(s.raw_content(1), None);
        assert_eq!(s.raw_blob(1), Some(&b"bytes now"[..]));
        // And back to text.
        s.insert(1, DataClass::Document, "text again");
        assert_eq!(s.raw_content(1), Some("text again"));
        assert_eq!(s.raw_blob(1), None);
    }
}
