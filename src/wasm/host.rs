//! WASM host function ABI specification.
//!
//! These functions define the ABI surface that a WASM guest module calls to
//! request authorized kernel operations.  In a production WASM deployment,
//! they would be registered as host imports by the WASM runtime (e.g.
//! Wasmtime, Wasmer) and wired to a [`super::WasmShim`] instance.
//!
//! # Return codes
//!
//! All functions return `i32`:
//! - `0`  — permitted
//! - `1`  — denied: capability check failed (HALT)
//! - `2`  — denied: resource quota exceeded (FAILURE)
//! - `3`  — denied: topology violation (HALT)
//! - `-1` — denied: invalid handle or uninitialised state
//!
//! # Opaque handle security
//!
//! Capability tokens are **never** passed as raw bytes across the WASM
//! boundary.  The guest holds an opaque `u32` handle that the host maps to a
//! real `Capability` in its private table.  A guest that fabricates a handle
//! value it was not given receives `-1`.
//!
//! # Naming
//!
//! The function names match the intended WASM export names.  In a production
//! build these would be re-exported via a linker script or wit-bindgen
//! component model descriptor.

use super::WasmShim;

/// Gate `cap_handle` for `right_bits` via `Policy::check`.
///
/// # Arguments
///
/// - `cap_handle` — opaque handle returned by a prior `register_cap` call.
/// - `right_bits` — `CapabilitySet` bitmask the guest requests.
///
/// Returns 0 on success, 1 on denial, -1 on invalid handle.
pub fn lux_policy_check(shim: &mut WasmShim, cap_handle: u32, right_bits: u32) -> i32 {
    shim.policy_check(cap_handle, right_bits)
}

/// Deduct `amount` from `node_id`'s resource quota via `QuotaEnforcer::deduct`.
///
/// Returns 0 on success, 2 on quota exceeded, -1 on unknown node.
pub fn lux_ledger_deduct(shim: &mut WasmShim, node_id: u32, amount: u64) -> i32 {
    shim.ledger_deduct(node_id, amount)
}

/// Attempt topology traversal `src_id → dst_id` via `OperationalGraph::traverse`.
///
/// Returns 0 on success, 3 on undeclared edge, -1 on invalid node ID.
pub fn lux_topology_traverse(shim: &mut WasmShim, src_id: u32, dst_id: u32) -> i32 {
    shim.topology_traverse(src_id, dst_id)
}
