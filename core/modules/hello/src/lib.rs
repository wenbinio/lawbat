// SPDX-License-Identifier: AGPL-3.0-or-later
//! `hello` — the spike GUEST module (compiled to a wasm32-wasip2 component).
//!
//! It implements the `run` export from `world.wit` and calls the brokered
//! `host::note` import. That is the whole point of the spike:
//!   * `host::note(..)` is a GRANTED, BROKERED call — the host receives it and
//!     records it in the audit chain (spec §0, §2.7).
//!   * there is NO egress / socket / filesystem import available to this module,
//!     because none is in `world.wit`. The guest *cannot even name* a network
//!     call — the absence IS the guarantee (spec §0, §2.5).
//!
//! Determinism / no model calls (CLAUDE.md): this module does pure, fixed work.

// Generate guest-side bindings from the spike world. `wit-bindgen` emits the
// `Guest` trait (for the `run` export) and the `host` module (for the import).
wit_bindgen::generate!({
    path: "../../wit",
    world: "spike-module",
});

// The generated import interface lives under the WIT package path
// (`package dataroom:spike`).
use crate::dataroom::spike::host;

struct SpikeModule;

impl Guest for SpikeModule {
    fn run() -> Result<(), String> {
        // Make the brokered call. If we tried to open a socket here, there would
        // be no symbol to call — the world simply does not import one.
        host::note("hello from the sandboxed guest: brokered note #1");
        host::note("guest performed deterministic work; nothing left the box");
        Ok(())
    }
}

export!(SpikeModule);
