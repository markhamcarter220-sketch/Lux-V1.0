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

#![no_std]
#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    missing_docs,
    missing_debug_implementations
)]
#![warn(clippy::nursery)]

pub mod auth;
pub mod boot;
pub mod error;
pub mod metabolism;
pub mod scheduler;
pub mod topology;
pub mod types;

pub use error::{Error, Result};
