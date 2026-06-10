//! `PyO3` Python extension module — `lux_kernel`.
//!
//! Exposes three Python classes:
//!   - `PyAuditLog`   — SHA-256 hash-chained audit log (wraps `AuditLog`)
//!   - `PyLuxGate`    — stateless CE authorization gate for Emergo integration
//!   - `PyPolicyGate` — capability-gated feature vector checker
//!
//! Import from Python:
//!   ```python
//!   from lux_kernel import PyAuditLog, PyLuxGate, PyPolicyGate
//!   ```
//!
//! Build with:
//!   ```sh
//!   maturin develop --features python
//!   ```
//!
//! # EDGE H resolution: `unsafe_code`
//!
//! `PyO3`'s `#[pymodule]` macro generates an `unsafe extern "C"` entry point
//! (`PyInit_lux_kernel`) required by the Python C ABI.  The `#![allow(unsafe_code)]`
//! below overrides the crate-level `#![deny(unsafe_code)]` for this module only.
//! All enforcement logic in `audit.rs` and `policy.rs` is safe Rust.

#![allow(unsafe_code)]
#![allow(missing_docs)]

pub mod audit;
pub mod gate;
pub mod policy;

use pyo3::prelude::*;

pub use audit::PyAuditLog;
pub use gate::PyLuxGate;
pub use policy::PyPolicyGate;

/// The `lux_kernel` Python extension module.
///
/// Registered classes:
///   - `PyAuditLog`   — append-only, hash-chained audit log
///   - `PyLuxGate`    — stateless CE authorization gate (Emergo integration)
///   - `PyPolicyGate` — governed policy gate for feature vector checking
#[pymodule]
fn lux_kernel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAuditLog>()?;
    m.add_class::<PyLuxGate>()?;
    m.add_class::<PyPolicyGate>()?;
    Ok(())
}
