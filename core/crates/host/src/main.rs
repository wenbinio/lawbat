// SPDX-License-Identifier: AGPL-3.0-or-later
//! `host` — the wasmtime substrate SPIKE (architecture spec §3, §10).
//!
//! This binary proves the one idea everything hangs on (spec §0): the sandbox,
//! the capability model, and the audit log are the same chokepoint.
//!
//! It:
//!   1. instantiates the `hello` guest COMPONENT in a WASM sandbox;
//!   2. links ONLY the granted host import (`host.note`) into the guest's world;
//!   3. runs the guest's exported `run`;
//!   4. prints proof that (a) the brokered `note` calls were RECEIVED by the host
//!      and RECORDED in the runtime's append-only, hash-chained audit log, and (b)
//!      there is NO egress/network/filesystem capability in the guest's world — the
//!      import set is exactly `{host.note}`. The ABSENCE is the guarantee (spec §0,
//!      §2.5): the guest cannot even name a socket.
//!
//! No network code anywhere (CLAUDE.md non-negotiable). wasmtime here is an
//! in-process engine; it opens no sockets and touches no files except reading
//! the guest component bytes.

use anyhow::Result;
use runtime::{
    Audit, Capability, CoreContext, DefaultCore, GrantSet, InMemoryAudit, InMemoryEgress,
    InMemoryMatterStore, InMemoryStorage, StorageScope,
};
use std::path::PathBuf;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Engine, Store};

/// Generous OPT-IN fail-closed audit-entry ceiling for the host (#1). A normal
/// spike run records only a handful of entries; this is a DoS ceiling on the
/// in-memory hash chain, NOT a retention policy (durable retention is the
/// deferred persistence gate). Past this, a brokered record returns `Err` and the
/// op aborts (here: the guest TRAPS) rather than the chain growing without limit —
/// it NEVER drops an entry (dropping would break the hash chain).
const HOST_AUDIT_MAX_ENTRIES: usize = 1_000_000;

// Generate host-side bindings from the MINIMAL v0 spike world. This mirrors the
// guest's `wit_bindgen::generate!` over the same `world.wit`. Because the world
// imports only `host`, bindgen generates exactly one host trait (`host::Host`)
// to implement and exactly one export to call (`run`). There is no egress trait
// to implement because there is no egress import — that is the point.
// `imports: { default: trappable }` makes the generated host trait method
// return a `wasmtime::Result<()>` even though the WIT `note` is infallible:
// returning `Err` TRAPS the guest. We use that to refuse an UNGRANTED brokered
// call at the live chokepoint (consult the grant → trap if denied → record
// nothing).
wasmtime::component::bindgen!({
    path: "../../wit",
    world: "spike-module",
    imports: { default: trappable },
});

// The generated import interface lives under the WIT package path
// (`package dataroom:spike`). Alias it for readability.
use dataroom::spike::host;

/// Per-instance host state held in the wasmtime `Store`. The host now HOLDS A
/// `Core` (the trusted-core mediator) rather than re-implementing the chokepoint
/// against a bare audit log (to-fix.md #2): every brokered host call routes
/// through the Core's `check → log → act`, and the host only INSPECTS the Core's
/// read-only views (`audit()`, `broker()`). The guest has no reference to any of
/// this — it only sees the linked `note` import.
struct HostState {
    /// The trusted-core mediator (spec §0): broker + hash-chained audit +
    /// mediated storage/egress/matter, all behind one `check → log → act` seam.
    core: DefaultCore,
}

impl HostState {
    /// Number of brokered notes recorded at the chokepoint. Counted by filtering
    /// the audit log for `audit.note` entries (single source of truth) so a
    /// separate counter can never drift — and so other chokepoint entries
    /// (storage / egress) can never inflate the note count. NOTE: `audit.note` is
    /// NOT note-exclusive at the runtime level — `Core::switch_context` also records
    /// under [`Capability::AuditNote`] — so we additionally require the
    /// `Core::audit_note` detail prefix (`"note: "`). This host never switches
    /// context, but matching the prefix keeps the count precise even if it ever did.
    fn notes_received(&self) -> usize {
        self.core
            .audit()
            .entries()
            .iter()
            .filter(|e| e.capability == Capability::AuditNote && e.detail.starts_with("note: "))
            .count()
    }
}

// Implement the generated host import trait. `host` is the WIT interface name;
// bindgen put the trait at `host::Host`. This is the ONLY host capability the
// guest can reach. Every call here is a brokered call recorded at the chokepoint.
impl host::Host for HostState {
    fn note(&mut self, msg: String) -> wasmtime::Result<()> {
        // Route the brokered note through the Core's MEDIATED `audit_note` (spec
        // §2.7/§4.3) instead of poking the audit log directly (to-fix.md #2). It is
        // UNGATED by design — a module may ALWAYS append context, never suppress or
        // forge a core event — but it is still attributed + hash-chained at the
        // chokepoint under the dedicated `audit.note` marker (NOT a metadata-read
        // stand-in) and length-capped, inside the Core. The default-deny + gated
        // check→act→log guarantee is demonstrated by the GATED capabilities
        // (egress / storage), exercised in the runtime unit tests; egress is
        // additionally proven absent here by the import allowlist (PROOF b).
        //
        // Fail-closed: `audit_note` returns a Result. If the Core cannot record
        // (audit error, note over the length cap, or the OPT-IN fail-closed audit
        // entry cap full) we TRAP the guest (return Err) rather than letting the
        // brokered note proceed unlogged — an unrecorded brokered call must not be
        // allowed to succeed.
        if let Err(e) = self.core.audit_note(&msg) {
            // Return a `wasmtime::Error` (the generated `note` returns
            // `wasmtime::Result<()>`); a returned Err TRAPS the guest.
            return Err(wasmtime::Error::msg(format!(
                "audit record failed (fail-closed): {e}"
            )));
        }
        println!(
            "  [host] brokered note RECORDED at the chokepoint (audit.note, ungated): {msg:?}"
        );
        Ok(())
    }
}

fn guest_component_path() -> PathBuf {
    if let Ok(p) = std::env::var("LAWDATAMAN_SPIKE_GUEST") {
        return PathBuf::from(p);
    }
    // Default: alongside the workspace target dir. The host bin runs from the
    // workspace, so target/ is two levels up from crates/host at runtime via cwd;
    // we resolve relative to the manifest dir at build time for robustness.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../target/wasm32-wasip2/release/hello.wasm")
}

fn main() -> Result<()> {
    let guest_path = guest_component_path();

    println!("== lawdataman trusted-core WASM substrate SPIKE ==");
    println!("(spec §3/§10: prototype the substrate BEFORE the module ABI hardens)\n");
    println!("guest component: {}", guest_path.display());
    if !guest_path.exists() {
        anyhow::bail!(
            "guest component not found at {}.\n\
             Build it first:\n  \
             cargo build -p hello --target wasm32-wasip2 --release\n\
             or point LAWDATAMAN_SPIKE_GUEST at the .wasm.",
            guest_path.display()
        );
    }

    // --- engine + component-model -----------------------------------------
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    let engine =
        Engine::new(&config).map_err(|e| anyhow::anyhow!("create wasmtime engine: {e}"))?;

    let component = Component::from_file(&engine, &guest_path).map_err(|e| {
        anyhow::anyhow!("load guest component (is it a wasm32-wasip2 *component*?): {e}")
    })?;

    // --- PROOF (b): inspect the guest's import set BEFORE running ----------
    // The component type tells us exactly which imports the guest declares. We
    // assert the negative space: no egress / socket / filesystem / wasi import.
    print_import_proof(&engine, &component)?;

    // --- link ONLY the granted host import --------------------------------
    // Default-deny: we start with an empty linker and add EXACTLY the one host
    // capability the guest's manifest is "granted" for this spike. We do NOT add
    // any WASI, sockets, or filesystem. If the guest tried to import anything
    // else, instantiation below would fail with an unresolved import — which is
    // itself the sandbox refusing ungranted authority.
    let mut linker: Linker<HostState> = Linker::new(&engine);
    SpikeModule::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s)
        .map_err(|e| anyhow::anyhow!("link granted host import (host.note): {e}"))?;

    // The trusted-core MEDIATOR. The host holds a `Core` (to-fix.md #2): brokered
    // calls go through its `check → log → act` chokepoint, not a hand-rolled copy.
    //
    // Grants (DEFAULT-DENY, from the verified manifest): the module is granted
    // `storage:own` — a benign per-module scratch namespace, exercised by the
    // teardown drain below — and CRUCIALLY no egress. PROOF (b) asserts the absence
    // of egress in BOTH the guest's WASM import set AND this grant set; `storage:own`
    // is not egress, so the negative space the spike proves is preserved while
    // showing the capability model is GRADUATED (a module can hold benign caps and
    // still reach no socket). The note path itself needs no grant — `audit.note` is
    // UNGATED by design (a module may always add context).
    let (grants, rejected) =
        GrantSet::from_manifest_checked(vec![Capability::Storage(StorageScope::Own)]);
    if !rejected.is_empty() {
        anyhow::bail!("spike grant set rejected capabilities (none should be): {rejected:?}");
    }

    // The audit log for the Core. Production-SHAPED path: stamps timestamps from the
    // real system clock. SECURITY (C-1): this dev SPIKE keys the chain with the
    // public `DEV_AUDIT_KEY` placeholder (via the explicitly-opted-in `dev-audit-key`
    // feature in this crate's Cargo.toml). That is fine for the ungated note spike,
    // but a REAL host must inject a secret via `InMemoryAudit::with_key` and drop
    // the `dev-audit-key` feature before any gated brokered call.
    //
    // ⚠ NOT AUTHENTICATED: because `host` enables `dev-audit-key` unconditionally,
    // even the SHIPPED `host.exe` keys its chain with the COMPILED-IN public
    // placeholder — so the chain it produces is tamper-evident only against someone
    // WITHOUT the key, and the key is in the (open) source. Do NOT present this
    // binary's audit as providing authenticity. Real authenticity is gated on the
    // deferred key-custody / persistence design (a secret key stored separately).
    //
    // BOUNDED (#1): built with the OPT-IN fail-CLOSED soft entry cap — the in-memory
    // hash chain cannot grow without bound (past the ceiling a brokered record
    // returns Err and the op aborts / the guest traps), and it NEVER drops an entry.
    // The ceiling is generous so a normal run is unaffected; durable retention
    // remains the deferred persistence gate.
    let audit = InMemoryAudit::new().with_max_entries(HOST_AUDIT_MAX_ENTRIES);

    let core = DefaultCore::new(
        "sg.spike.hello",
        grants,
        audit,
        InMemoryStorage::new(),
        InMemoryEgress::new(),
        CoreContext::new("Acme Holdings v Beta Corp", "j.smith"),
        InMemoryMatterStore::new(),
    );
    let state = HostState { core };

    let mut store = Store::new(&engine, state);

    // --- instantiate + run the guest's exported entrypoint ----------------
    let bindings = SpikeModule::instantiate(&mut store, &component, &linker)
        .map_err(|e| anyhow::anyhow!("instantiate guest in sandbox: {e}"))?;

    println!("\n-- running guest export `run()` (sandboxed) --");
    let run_result = bindings
        .call_run(&mut store)
        .map_err(|e| anyhow::anyhow!("call guest run(): {e}"))?;

    match run_result {
        Ok(()) => println!("-- guest run() returned Ok --"),
        Err(e) => println!("-- guest run() returned Err: {e} --"),
    }

    // --- module teardown: drain the module's scratch storage (#3) ----------
    // Part of the module LIFECYCLE the host owns (load → run → teardown): on
    // teardown the host drains the module's `own` scratch namespace through the
    // mediated, audited `Core::storage_clear` so per-module scratch cannot
    // accumulate across runs. This is the "the host calls it between runs" hook.
    // It is a BROKERED call (needs the `storage:own` grant) — `check → log → act`,
    // fail-closed. In this v0 spike the guest's world has NO storage import, so it
    // wrote no scratch and the drain is a no-op (0 entries) — but the mediated +
    // audited lifecycle call itself is exercised end-to-end and recorded in the
    // chain (see the `storage clear own` entry below).
    let drained = store
        .data_mut()
        .core
        .storage_clear(StorageScope::Own)
        .map_err(|e| anyhow::anyhow!("module teardown storage_clear failed: {e}"))?;

    // --- PROOF (a): the brokered calls were received + audited ------------
    let st = store.data();
    println!("\n== PROOF (a): brokered call RECORDED at the chokepoint (audit.note, ungated) ==");
    println!(
        "  brokered notes received + recorded : {}",
        st.notes_received()
    );
    println!(
        "  audit log entries recorded      : {}",
        st.core.audit().len()
    );
    println!(
        "  audit hash-chain verifies        : {}",
        st.core.audit().verify_chain()
    );
    println!(
        "  audit head hash                  : {}",
        st.core.audit().head_hash().to_hex()
    );
    for e in st.core.audit().entries() {
        println!(
            "    #{:<2} user={} matter={:?} module={} cap={} | {}",
            e.seq, e.acting_user, e.matter, e.module, e.capability, e.detail
        );
    }

    // Sanity: the core's grant set holds NO egress capability (only `storage:own`).
    // There is also no egress IMPORT in the guest world (proof b), so this is
    // belt-and-braces. Inspected via the Core's read-only `broker()` view — the host
    // can SEE what was granted but cannot widen authority.
    let has_egress_grant = st
        .core
        .broker()
        .granted()
        .any(|c| matches!(c, Capability::Egress(_)));
    println!(
        "\n== PROOF (b, cont'd): no egress in the GRANT set either: {} ==",
        if has_egress_grant {
            "FAIL (egress granted!)"
        } else {
            "ok (no egress grant)"
        }
    );
    // The note path above is UNGATED on purpose (a module may always add
    // context). The GATED check→act→log + default-deny guarantee — for egress and
    // storage — is exercised by the runtime unit tests (`cargo test -p runtime`),
    // not by this note call, so this proof does not overclaim.
    println!(
        "     (gated check->act->log + default-deny for egress/storage is proven by `cargo test -p runtime`)"
    );

    // PROOF (b, cont'd, POSITIVE): the grant set is EXACTLY {storage:own} and
    // nothing more — the spike's authority is bounded and auditable. The spike
    // grants storage:own ONLY to dogfood the teardown drain below; that widened the
    // grant set from empty, so we assert the exact bound here, and an accidental
    // future grant (egress or anything else) fails this check loudly.
    let granted: Vec<&Capability> = st.core.broker().granted().collect();
    let grant_set_is_exactly_storage_own =
        granted.len() == 1 && matches!(granted[0], Capability::Storage(StorageScope::Own));
    println!(
        "  grant set is EXACTLY {{storage:own}} (no more): {}",
        if grant_set_is_exactly_storage_own {
            "ok"
        } else {
            "FAIL (unexpected grant!)"
        }
    );

    // PROOF (c): module teardown drained the module's scratch through the mediated,
    // audited chokepoint (#3) — a per-run bound on scratch growth. (0 here: the v0
    // guest has no storage import, so it wrote no scratch; the lifecycle call still
    // ran + was audited — see the `storage clear own` entry in PROOF (a) above.)
    println!(
        "\n== PROOF (c): module scratch drained at teardown (mediated + audited, #3): {drained} entries =="
    );

    // Graceful checks (NOT assert!): a failed invariant here must not PANIC the
    // process (e.g. a guest that never calls note → DoS). Print a clear FAIL line
    // and bail with a non-zero exit instead.
    if st.notes_received() < 1 {
        println!(
            "FAIL: expected at least one brokered note, got {}",
            st.notes_received()
        );
        anyhow::bail!("spike invariant violated: no brokered note was recorded");
    }
    if !st.core.audit().verify_chain() {
        println!("FAIL: audit hash-chain did not verify");
        anyhow::bail!("spike invariant violated: audit chain must verify");
    }
    if has_egress_grant {
        println!("FAIL: an egress capability was granted in the spike grant set");
        anyhow::bail!(
            "spike invariant violated: no egress capability must be granted in the spike"
        );
    }
    if !grant_set_is_exactly_storage_own {
        println!("FAIL: spike grant set is not exactly {{storage:own}}");
        anyhow::bail!("spike invariant violated: grant set must be exactly {{storage:own}}");
    }

    println!("\nSPIKE OK: a brokered audit.note is recorded at the chokepoint AND the guest's world has no network/egress.");
    Ok(())
}

/// The complete set of imports the guest's world is permitted to declare: the
/// single brokered host interface, and NOTHING else. This is an ALLOWLIST, not a
/// denylist — anything outside it (any wasi:random/clocks/cli/environ/filesystem
/// /sockets/http, etc.) fails the proof loudly. Absence is the guarantee
/// (spec §0, §2.5): you cannot deny what was never linked in.
const EXPECTED_IMPORTS: &[&str] = &["dataroom:spike/host@0.0.0"];

/// PROOF (b): print the guest component's full import list and assert it equals
/// EXACTLY the expected single host interface. Any unexpected import (e.g. a
/// wasi capability) fails the proof. The component model makes the import set
/// explicit and inspectable — an exact-match allowlist is enforced here.
fn print_import_proof(engine: &Engine, component: &Component) -> Result<()> {
    let ty = component.component_type();
    println!("\n== PROOF (b): guest world import set (the negative space is the guarantee) ==");
    let mut names: Vec<String> = Vec::new();
    for (name, _item) in ty.imports(engine) {
        names.push(name.to_string());
    }
    if names.is_empty() {
        println!("  (guest declares no imports at all)");
    } else {
        for n in &names {
            println!("  import: {n}");
        }
    }

    // ALLOWLIST: the declared import set must equal EXACTLY the expected single
    // host interface — no more, no fewer. Compare as sorted sets.
    let mut declared = names.clone();
    declared.sort();
    declared.dedup();
    let mut expected: Vec<String> = EXPECTED_IMPORTS.iter().map(|s| s.to_string()).collect();
    expected.sort();

    let unexpected: Vec<&String> = declared
        .iter()
        .filter(|n| !EXPECTED_IMPORTS.contains(&n.as_str()))
        .collect();
    let missing: Vec<&String> = expected.iter().filter(|n| !declared.contains(n)).collect();

    if !unexpected.is_empty() {
        anyhow::bail!(
            "guest declares UNEXPECTED import(s) outside the allowlist {EXPECTED_IMPORTS:?}: {unexpected:?}"
        );
    }
    if !missing.is_empty() {
        anyhow::bail!(
            "guest is MISSING expected import(s) {missing:?} (expected exactly {EXPECTED_IMPORTS:?})"
        );
    }
    println!(
        "  -> import set is EXACTLY the allowlisted host interface {EXPECTED_IMPORTS:?}; \
         no wasi:random/clocks/cli/environ/filesystem/sockets/http present. PASS."
    );
    Ok(())
}
