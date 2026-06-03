//! Metabolism subsystem — resource accounting and quota enforcement.
//!
//! Every allocation request is charged against a per-node ledger entry.
//! Requests that would exceed the declared ceiling are hard-rejected; the
//! kernel never over-commits and never silently drops the excess.

pub mod ledger;
pub mod quota;

pub use ledger::Ledger;
pub use quota::QuotaEnforcer;
