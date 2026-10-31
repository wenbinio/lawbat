// SPDX-License-Identifier: AGPL-3.0-or-later
//! Injectable clock for audit timestamps (spec §7).
//!
//! Spec §7 mandates a per-call timestamp on every audited event. CLAUDE.md
//! requires the audit chain be DETERMINISTIC under test. We reconcile the two by
//! INJECTING the clock: production wires a [`SystemClock`] (wall time), while
//! tests wire a [`FixedClock`] so the hashed payload — which now folds in the
//! timestamp — stays reproducible. The trait is the only seam; nothing here
//! reads a clock implicitly.
//!
//! std-only: `SystemClock` uses `std::time::SystemTime`; no external dep.

use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

/// The clock seam. Returns milliseconds since the UNIX epoch as a `u64`.
pub trait Clock {
    fn now_millis(&self) -> u64;
}

/// L-3: emit the pre-epoch clock warning AT MOST ONCE per process. A skewed
/// clock would otherwise be a hot, repeated log line on every audited call.
static PRE_EPOCH_WARNED: Once = Once::new();

/// Real wall-clock: milliseconds since `UNIX_EPOCH`. Used on the production /
/// host path. A pre-epoch clock (shouldn't happen) saturates to 0 rather than
/// panicking — the audit log must never abort on a clock anomaly.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => {
                // L-2-style explicit narrowing: ms-since-epoch fits a u64 until the
                // year ~584-million, so the truncation can never lose data on any
                // real clock. `try_from` on the u128 keeps it honest without a
                // panic — a (physically impossible) overflow saturates to u64::MAX
                // rather than wrapping.
                u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
            }
            Err(_) => {
                // L-3: the wall clock is set BEFORE the UNIX epoch (clock skew /
                // misconfiguration). We saturate the timestamp to 0 rather than
                // panicking — the audit log must never abort on a clock anomaly —
                // but warn ONCE so the skew is visible in the operational log
                // without spamming it on every audited call. (std-only: `eprintln!`
                // + `std::sync::Once`, no new dep, no network.)
                PRE_EPOCH_WARNED.call_once(|| {
                    eprintln!(
                        "SECURITY/WARN: system clock is before the UNIX epoch; \
                         audit timestamps are saturating to 0 until the clock is corrected"
                    );
                });
                0
            }
        }
    }
}

/// Deterministic test clock: returns a FIXED timestamp on every read. Lets unit
/// tests construct an audit log whose hashes are reproducible even though the
/// timestamp is now part of the hashed payload.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl FixedClock {
    pub fn new(millis: u64) -> Self {
        Self(millis)
    }
}

impl Clock for FixedClock {
    fn now_millis(&self) -> u64 {
        self.0
    }
}
