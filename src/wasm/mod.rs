//! WASM execution substrate integration.
//!
//! Only compiled when the `wasm` Cargo feature is enabled.
//!
//! # Architecture
//!
//! Lux's enforcement points are exposed as ordinary Rust functions (see
//! [`host`]) that a WASM runtime can register as host imports.  The guest
//! passes opaque `u32` handles; the host translates them to real kernel
//! objects in a private table inside [`WasmShim`].
//!
//! Unlike a classic WASM host, there is no global mutable state here — the
//! caller owns a `WasmShim` instance and passes `&mut WasmShim` to each host
//! function.  This keeps the implementation fully safe and testable.
//!
//! # Security invariants preserved
//!
//! - **I1 (Fail-Closed):** all three host functions fail-closed on invalid
//!   handles, wrong rights, and topology violations.
//! - **I2 (Capability-Gated):** `lux_policy_check` enforces `Policy::check`.
//! - **I3 (Accountable Resources):** `lux_ledger_deduct` enforces `QuotaEnforcer::deduct`.
//! - **I4 (Topology-Bounded):** `lux_topology_traverse` enforces `OperationalGraph::traverse`.
//!
//! # ABI opaqueness
//!
//! Capability tokens are never serialised into the guest's linear memory.
//! The guest holds opaque `u32` handle IDs that the host translates to the
//! actual `Capability` in a private bounded table (see [`WasmShim`]).

pub mod host;
pub mod executor;

pub use executor::WasmExecutor;

use crate::{
    audit::AuditLog,
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    boot::BootState,
    metabolism::{ledger::Ledger, quota::QuotaEnforcer},
    topology::graph::OperationalGraph,
};

/// Maximum number of capability handles the shim table can hold.
const MAX_WASM_CAPS: usize = 64;

/// Return code constants matching the ABI spec in [`host`].
pub(super) const RC_PERMITTED:      i32 = 0;
pub(super) const RC_CAP_DENIED:     i32 = 1;
pub(super) const RC_QUOTA_EXCEEDED: i32 = 2;
pub(super) const RC_TOPO_VIOLATION: i32 = 3;
pub(super) const RC_INVALID_HANDLE: i32 = -1;

/// Kernel state exposed to the WASM guest via the host function ABI.
///
/// Owns the three enforcement subsystems plus a bounded capability handle
/// table.  The guest calls host functions with integer handles; this struct
/// translates them to real `Capability` references without ever exposing the
/// capability bytes to the guest.
///
/// Constructed from a sealed [`BootState`] via [`WasmShim::from_boot_state`].
/// Passed by `&mut` reference to each host function — no global state.
#[derive(Debug)]
pub struct WasmShim {
    policy:    Policy,
    ledger:    Ledger,
    graph:     OperationalGraph,
    audit:     AuditLog,
    cap_table: heapless::Vec<Option<Capability>, MAX_WASM_CAPS>,
}

impl WasmShim {
    /// Construct a shim from a sealed [`BootState`].
    #[must_use]
    pub fn from_boot_state(boot: BootState) -> Self {
        Self {
            policy:    boot.policy,
            ledger:    boot.ledger,
            graph:     boot.graph,
            audit:     AuditLog::new(),
            cap_table: heapless::Vec::new(),
        }
    }

    /// Construct a shim directly from its constituent parts.
    ///
    /// Useful in tests and in embeddings where the caller already holds the
    /// individual subsystem objects rather than a `BootState`.
    #[must_use]
    pub const fn from_parts(policy: Policy, ledger: Ledger, graph: OperationalGraph) -> Self {
        Self {
            policy,
            ledger,
            graph,
            audit:     AuditLog::new(),
            cap_table: heapless::Vec::new(),
        }
    }

    /// Register a capability in the handle table and return its opaque handle.
    ///
    /// Returns `None` if the table is full (`>= 64` entries).
    pub fn register_cap(&mut self, cap: Capability) -> Option<u32> {
        let idx = u32::try_from(self.cap_table.len()).unwrap_or(u32::MAX);
        self.cap_table.push(Some(cap)).ok()?;
        Some(idx)
    }

    /// Borrow the audit log for inspection.
    #[must_use]
    pub const fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Implementation of [`host::lux_policy_check`].
    pub fn policy_check(&mut self, cap_handle: u32, right_bits: u32) -> i32 {
        let idx = cap_handle as usize;
        if idx >= self.cap_table.len() {
            return RC_INVALID_HANDLE;
        }
        let Some(cap) = self.cap_table[idx].as_ref() else { return RC_INVALID_HANDLE };
        let required = CapabilitySet::from_bits_truncate(right_bits);
        match self.policy.check(cap, required, &mut self.audit) {
            Ok(())  => RC_PERMITTED,
            Err(_)  => RC_CAP_DENIED,
        }
    }

    /// Implementation of [`host::lux_ledger_deduct`].
    pub fn ledger_deduct(&mut self, node_id: u32, amount: u64) -> i32 {
        let Some(node) = core::num::NonZeroU32::new(node_id) else { return RC_INVALID_HANDLE };
        let enforcer = QuotaEnforcer;
        match enforcer.deduct(&mut self.ledger, node, amount, "wasm", &mut self.audit) {
            Ok(_)  => RC_PERMITTED,
            Err(_) => RC_QUOTA_EXCEEDED,
        }
    }

    /// Implementation of [`host::lux_topology_traverse`].
    pub fn topology_traverse(&mut self, src_id: u32, dst_id: u32) -> i32 {
        let Some(src) = core::num::NonZeroU32::new(src_id) else { return RC_INVALID_HANDLE };
        let Some(dst) = core::num::NonZeroU32::new(dst_id) else { return RC_INVALID_HANDLE };
        match self.graph.traverse(src, dst, &mut self.audit) {
            Ok(())  => RC_PERMITTED,
            Err(_)  => RC_TOPO_VIOLATION,
        }
    }
}
