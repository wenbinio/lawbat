// SPDX-License-Identifier: AGPL-3.0-or-later
//! The external anchor (`audit.anchor`) — a SEPARATE, small file holding the
//! trusted head reference (count + head hash) the chain alone cannot self-protect.
//!
//! ## Why a separate file
//!
//! The keyed HMAC chain in `audit.log` proves INTERNAL consistency given a trusted
//! head, but — being head-relative — it cannot, on its own, detect:
//!   - **total erasure** (delete the whole log: an empty log "verifies"), nor
//!   - **tail truncation** (drop the last N records: the shorter chain still
//!     verifies internally).
//!
//! The anchor closes both: it records `count` + `head_hash` MAC'd under the key, in
//! a DIFFERENT file. Open-time, the replayed log's count/head MUST equal the
//! anchor's. A log shorter than the anchor = truncation; a missing/empty log with a
//! non-zero anchor = erasure; a tampered anchor = its MAC fails. (Increment 2 will
//! ALSO mirror the anchor to an OS-protected store so an attacker who can delete
//! BOTH files is still caught; for now the separate file is the increment-1 scope.)
//!
//! ## On-disk layout (fixed, hand-rolled — no serde)
//!
//! ```text
//!   magic     : 8 bytes  = b"LWBTANC1"
//!   version   : u8       = ANCHOR_VERSION
//!   key_id    : 32 bytes = SHA-256(key)        (MUST match the log header's)
//!   count     : u64 LE
//!   head_hash : 32 bytes
//!   anchor_mac: 32 bytes = HMAC-SHA-256(key, b"anchor" || count_LE || head_hash)
//! ```
//!
//! The `anchor_mac` is keyed, so an attacker who edits `count`/`head_hash` cannot
//! recompute it without the key → [`verify_anchor`] rejects it ([`AnchorMismatch`]
//! at the `lib.rs` layer). The MAC domain-separates with the `b"anchor"` tag so an
//! anchor MAC can never be confused with a chain-entry MAC.

use hmac::{Hmac, Mac};
use runtime::AuditHash;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Anchor file magic. Distinct from the log's [`crate::format::MAGIC`] so the two
/// files can never be swapped for each other unnoticed.
pub const ANCHOR_MAGIC: [u8; 8] = *b"LWBTANC1";

/// Anchor format version (independent of the log's, though they move together).
pub const ANCHOR_VERSION: u8 = 1;

/// Total anchor file length: magic(8)+version(1)+key_id(32)+count(8)+head(32)+mac(32).
pub const ANCHOR_LEN: usize = 8 + 1 + 32 + 8 + 32 + 32;

/// Domain-separation tag MAC'd into the anchor so its MAC can never collide with a
/// chain-entry MAC (which begins with a 32-byte prev hash, never this tag).
const ANCHOR_TAG: &[u8] = b"anchor";

/// The trusted head reference: how many entries the log SHOULD hold and what its
/// head hash SHOULD be. Compared against the replayed log at open time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub count: u64,
    pub head_hash: AuditHash,
}

impl Anchor {
    /// The genesis anchor: zero entries, genesis head. The anchor a fresh,
    /// never-appended store advances FROM.
    pub fn genesis() -> Self {
        Anchor {
            count: 0,
            head_hash: AuditHash::GENESIS,
        }
    }
}

/// Compute the keyed anchor MAC: `HMAC-SHA-256(key, b"anchor" || count_LE || head)`.
/// Fallible like the chain MAC (HMAC accepts any key length, so this should not
/// fail; threaded as `Option` so the caller fails closed rather than panicking).
fn anchor_mac(key: &[u8], count: u64, head: AuditHash) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(ANCHOR_TAG);
    mac.update(&count.to_le_bytes());
    mac.update(head.as_bytes());
    Some(mac.finalize().into_bytes().into())
}

/// Serialize the anchor file bytes for `anchor`, keyed by `key`, stamped with
/// `key_id` (SHA-256(key), the same id the log header carries). Returns `None` only
/// if the MAC cannot be computed (the caller then fails closed).
pub fn encode_anchor(key: &[u8], key_id: &[u8; 32], anchor: &Anchor) -> Option<Vec<u8>> {
    let mac = anchor_mac(key, anchor.count, anchor.head_hash)?;
    let mut out = Vec::with_capacity(ANCHOR_LEN);
    out.extend_from_slice(&ANCHOR_MAGIC);
    out.push(ANCHOR_VERSION);
    out.extend_from_slice(key_id);
    out.extend_from_slice(&anchor.count.to_le_bytes());
    out.extend_from_slice(anchor.head_hash.as_bytes());
    out.extend_from_slice(&mac);
    Some(out)
}

/// Why an anchor failed to load/verify. Distinct from "the anchor disagrees with
/// the log" (that comparison happens in `lib.rs` once both are loaded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// Wrong length / magic / version — the file is not a v1 anchor.
    Malformed,
    /// The embedded key-id != SHA-256(the supplied key): wrong key for this anchor.
    WrongKey,
    /// The MAC does not verify under the supplied key: the count/head was edited.
    BadMac,
}

/// Parse + verify an anchor file under `key` (whose id is `expected_key_id`).
///
/// Checks, in order: structural validity (magic/version/length), the key-id matches
/// (so we are verifying with the right key), then the keyed MAC over the stored
/// count+head. A tampered count/head fails the MAC ([`AnchorError::BadMac`]); a
/// foreign key fails the id check ([`AnchorError::WrongKey`]). Constant-time MAC
/// comparison is not required for tamper-EVIDENCE (we are not gating a secret on the
/// comparison, only detecting edits), but we use `ct_eq`-style full comparison via
/// `hmac`'s `verify_slice` to avoid an early-exit timing quirk and to reuse the
/// vetted verifier.
pub fn verify_anchor(
    buf: &[u8],
    key: &[u8],
    expected_key_id: &[u8; 32],
) -> Result<Anchor, AnchorError> {
    if buf.len() != ANCHOR_LEN || buf[0..8] != ANCHOR_MAGIC || buf[8] != ANCHOR_VERSION {
        return Err(AnchorError::Malformed);
    }
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&buf[9..9 + 32]);
    if &key_id != expected_key_id {
        return Err(AnchorError::WrongKey);
    }
    let count_off = 9 + 32;
    let count = u64::from_le_bytes([
        buf[count_off],
        buf[count_off + 1],
        buf[count_off + 2],
        buf[count_off + 3],
        buf[count_off + 4],
        buf[count_off + 5],
        buf[count_off + 6],
        buf[count_off + 7],
    ]);
    let head_off = count_off + 8;
    let mut head = [0u8; 32];
    head.copy_from_slice(&buf[head_off..head_off + 32]);
    let mac_off = head_off + 32;
    let stored_mac = &buf[mac_off..mac_off + 32];

    // Recompute + verify the keyed MAC. Use `hmac`'s constant-time `verify_slice`.
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AnchorError::BadMac)?;
    mac.update(ANCHOR_TAG);
    mac.update(&count.to_le_bytes());
    mac.update(&head);
    mac.verify_slice(stored_mac)
        .map_err(|_| AnchorError::BadMac)?;

    Ok(Anchor {
        count,
        head_hash: AuditHash(head),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_id_of(key: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(key);
        h.finalize().into()
    }

    #[test]
    fn anchor_round_trips_under_the_right_key() {
        let key = b"anchor-test-key-0000000000000000";
        let kid = key_id_of(key);
        let anchor = Anchor {
            count: 5,
            head_hash: AuditHash([9u8; 32]),
        };
        let bytes = encode_anchor(key, &kid, &anchor).expect("mac computes");
        assert_eq!(bytes.len(), ANCHOR_LEN);
        let got = verify_anchor(&bytes, key, &kid).expect("verifies");
        assert_eq!(got, anchor);
    }

    #[test]
    fn editing_count_or_head_fails_the_mac() {
        let key = b"anchor-test-key-1111111111111111";
        let kid = key_id_of(key);
        let anchor = Anchor {
            count: 5,
            head_hash: AuditHash([9u8; 32]),
        };
        let mut bytes = encode_anchor(key, &kid, &anchor).unwrap();
        // Flip a byte in the count field (offset 41).
        bytes[9 + 32] ^= 0xFF;
        assert_eq!(verify_anchor(&bytes, key, &kid), Err(AnchorError::BadMac));
    }

    #[test]
    fn wrong_key_id_is_rejected_before_mac() {
        let key = b"anchor-test-key-2222222222222222";
        let other = b"anchor-test-key-3333333333333333";
        let kid = key_id_of(key);
        let other_kid = key_id_of(other);
        let anchor = Anchor {
            count: 1,
            head_hash: AuditHash([1u8; 32]),
        };
        let bytes = encode_anchor(key, &kid, &anchor).unwrap();
        // Verifying with the OTHER key (and its id) → WrongKey (id check first).
        assert_eq!(
            verify_anchor(&bytes, other, &other_kid),
            Err(AnchorError::WrongKey)
        );
    }

    #[test]
    fn malformed_anchor_is_rejected() {
        let key = b"k";
        let kid = key_id_of(key);
        assert_eq!(
            verify_anchor(b"short", key, &kid),
            Err(AnchorError::Malformed)
        );
        let mut bytes = encode_anchor(key, &kid, &Anchor::genesis()).unwrap();
        bytes[0] = b'X'; // bad magic
        assert_eq!(
            verify_anchor(&bytes, key, &kid),
            Err(AnchorError::Malformed)
        );
    }
}
