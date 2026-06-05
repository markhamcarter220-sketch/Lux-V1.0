//! Lux Kernel — fail-closed governance microkernel.
//!
//! # Invariants
//!
//! 1. **Fail-Closed** — every ambiguous or erroneous state denies access.
//! 2. **Capability-Gated** — no operation proceeds without an explicit,
//!    time-scoped capability token.
//! 3. **Accountable Resources** — every allocation is charged to a quota
//!    ledger; excess requests are hard-rejected.
//! 4. **Topology-Bounded** — execution is confined to the declared graph;
//!    unlisted edges are denied.

// When the `python` feature is enabled the crate links against std (required by
// PyO3).  When the `hsm` feature is enabled the crate also requires std because
// the key store uses `Mutex<HashMap>`.  In all other configurations the crate
// remains fully no_std.
#![cfg_attr(not(any(feature = "python", feature = "hsm", feature = "wasm")), no_std)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    missing_docs,
    missing_debug_implementations
)]
// unsafe_code is denied globally but allowed locally in src/python/ where PyO3
// requires an unsafe extern "C" entry point for the Python C ABI.
// The `hsm` feature also opts out because the key store uses std interior
// mutability constructs that require the std prelude.
#![cfg_attr(not(any(feature = "python", feature = "hsm", feature = "wasm")), deny(unsafe_code))]
#![warn(clippy::nursery)]

pub mod audit;
pub mod auth;
pub mod boot;
pub mod consensus;
pub mod error;
pub mod hsm;
pub mod metabolism;
pub mod scheduler;
pub mod topology;
pub mod tpm;
pub mod types;
#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "python")]
pub mod python;

pub use error::{Error, Result};
