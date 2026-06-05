//! `PyO3` Python extension module — `lux_kernel`.
//!
//! Exposes two Python classes:
//!   - `PyAuditLog`   — SHA-256 hash-chained audit log (wraps `AuditLog`)
//!   - `PyPolicyGate` — capability-gated feature vector checker
//!
//! Import from Python:
//!   ```python
//!   from lux_kernel import PyAuditLog, PyPolicyGate
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
pub mod policy;

use pyo3::prelude::*;

pub use audit::PyAuditLog;
pub use policy::PyPolicyGate;

/// The `lux_kernel` Python extension module.
///
/// Registered classes:
///   - `PyAuditLog`   — append-only, hash-chained audit log
///   - `PyPolicyGate` — governed policy gate for feature vector checking
#[pymodule]
fn lux_kernel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAuditLog>()?;
    m.add_class::<PyPolicyGate>()?;
    Ok(())
}
