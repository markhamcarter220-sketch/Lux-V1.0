//! Wasmtime-backed executor for Lux-governed WASM guests.
//!
//! [`WasmExecutor`] wraps a [`super::WasmShim`] inside a `wasmtime::Store`
//! and registers the three Lux host functions as linker imports:
//!
//! | Import (module "lux") | WASM signature | Enforcement |
//! |-----------------------|---------------|-------------|
//! | `lux_policy_check`    | `(i32 i32) → i32` | [`crate::auth::policy::Policy::check`] |
//! | `lux_ledger_deduct`   | `(i32 i64) → i32` | [`crate::metabolism::ledger::Ledger::deduct`] |
//! | `lux_topology_traverse` | `(i32 i32) → i32` | [`crate::topology::graph::OperationalGraph::traverse`] |
//!
//! WASM types: `i32` for u32 arguments (handles, node IDs, right bits),
//! `i64` for u64 `amount` in `lux_ledger_deduct`.  Return codes match the
//! ABI defined in [`super::host`].
//!
//! # Security invariants preserved
//!
//! All four kernel invariants are enforced on every host-function call through
//! the [`super::WasmShim`] methods — which are identical to the non-WASM paths.
//! Capability handles are opaque `i32` integers; the guest never sees raw
//! `Capability` bytes.

use wasmtime::{Caller, Engine, Linker, Module, Store};

use crate::{error::Error, wasm::WasmShim, Result};

/// Wasmtime-backed executor that enforces Lux kernel invariants on every
/// WASM host-function call.
///
/// Constructed via [`WasmExecutor::new`] with an initial [`WasmShim`] state.
/// Compiled WASM modules can be called repeatedly; the [`WasmShim`] state
/// (including the audit log and ledger balances) persists between calls.
pub struct WasmExecutor {
    engine: Engine,
    linker: Linker<WasmShim>,
    store:  Store<WasmShim>,
}

impl std::fmt::Debug for WasmExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmExecutor").finish_non_exhaustive()
    }
}

impl WasmExecutor {
    /// Construct a new executor with the given [`WasmShim`] state.
    ///
    /// Registers the three Lux host functions (`lux_policy_check`,
    /// `lux_ledger_deduct`, `lux_topology_traverse`) as imports under the
    /// `"lux"` module namespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WasmFault`] if any host function fails to register
    /// in the linker (should not occur under normal conditions).
    #[must_use = "the executor must be used to run WASM modules"]
    pub fn new(shim: WasmShim) -> Result<Self> {
        let engine = Engine::default();
        let mut linker = Linker::<WasmShim>::new(&engine);

        linker
            .func_wrap(
                "lux",
                "lux_policy_check",
                |mut caller: Caller<'_, WasmShim>, cap_handle: i32, right_bits: i32| -> i32 {
                    #[allow(clippy::cast_sign_loss)]
                    caller
                        .data_mut()
                        .policy_check(cap_handle as u32, right_bits as u32)
                },
            )
            .map_err(|_| Error::WasmFault { detail: "failed to register host function" })?;

        linker
            .func_wrap(
                "lux",
                "lux_ledger_deduct",
                |mut caller: Caller<'_, WasmShim>, node_id: i32, amount: i64| -> i32 {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    caller
                        .data_mut()
                        .ledger_deduct(node_id as u32, amount as u64)
                },
            )
            .map_err(|_| Error::WasmFault { detail: "failed to register host function" })?;

        linker
            .func_wrap(
                "lux",
                "lux_topology_traverse",
                |mut caller: Caller<'_, WasmShim>, src_id: i32, dst_id: i32| -> i32 {
                    #[allow(clippy::cast_sign_loss)]
                    caller
                        .data_mut()
                        .topology_traverse(src_id as u32, dst_id as u32)
                },
            )
            .map_err(|_| Error::WasmFault { detail: "failed to register host function" })?;

        let store = Store::new(&engine, shim);

        Ok(Self { engine, linker, store })
    }

    /// Borrow the current [`WasmShim`] state.
    ///
    /// Useful for inspecting the audit log or ledger balances after running
    /// one or more WASM modules.
    #[must_use]
    pub fn shim(&self) -> &WasmShim {
        self.store.data()
    }

    /// Mutably borrow the current [`WasmShim`] state.
    ///
    /// Use this to register capability handles before calling a WASM module.
    pub fn shim_mut(&mut self) -> &mut WasmShim {
        self.store.data_mut()
    }

    /// Compile and instantiate `wasm_bytes`, then call `func_name` (which must
    /// take no arguments and return `i32`).
    ///
    /// The [`WasmShim`] state (including the audit log and ledger balances)
    /// persists between calls, so sequential calls observe prior side-effects.
    ///
    /// Accepts both binary WASM (`.wasm`) and WAT text format; the format is
    /// auto-detected by Wasmtime.
    ///
    /// # Errors
    ///
    /// - [`Error::WasmFault`] with `detail = "failed to compile WASM module"` if
    ///   `wasm_bytes` is not valid WASM or WAT.
    /// - [`Error::WasmFault`] with `detail = "failed to instantiate WASM module"` if
    ///   the module's imports cannot be satisfied by the registered host functions.
    /// - [`Error::WasmFault`] with `detail = "WASM function not found or wrong type"` if
    ///   `func_name` does not exist in the module or has the wrong signature.
    /// - [`Error::WasmFault`] with `detail = "WASM guest trapped"` if the guest
    ///   executes an `unreachable` instruction or otherwise traps.
    pub fn call_nullary(
        &mut self,
        wasm_bytes: impl AsRef<[u8]>,
        func_name: &str,
    ) -> Result<i32> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|_| Error::WasmFault { detail: "failed to compile WASM module" })?;

        let instance = self
            .linker
            .instantiate(&mut self.store, &module)
            .map_err(|_| Error::WasmFault { detail: "failed to instantiate WASM module" })?;

        let func = instance
            .get_typed_func::<(), i32>(&mut self.store, func_name)
            .map_err(|_| Error::WasmFault { detail: "WASM function not found or wrong type" })?;

        func.call(&mut self.store, ())
            .map_err(|_| Error::WasmFault { detail: "WASM guest trapped" })
    }
}
