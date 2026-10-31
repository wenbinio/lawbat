// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic core errors. There is no variant that implies a model/LLM call
//! (CLAUDE.md non-negotiable: no model calls anywhere). `Backend` is reserved
//! for deterministic backend failures only.

use crate::capability::Capability;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Capability not in the grant set (spec §5.2). Carries what was attempted.
    Denied(Capability),
    /// Deterministic backend failure; never a model call. Also carries shape
    /// validation failures (e.g. a malformed egress destination, §5.4).
    Backend(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Denied(cap) => write!(f, "denied: capability not granted: {cap}"),
            CoreError::Backend(s) => write!(f, "backend: {s}"),
        }
    }
}

impl std::error::Error for CoreError {}

pub type CoreResult<T> = Result<T, CoreError>;
