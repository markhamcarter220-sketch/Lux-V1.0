//! Authentication subsystem — capability token lifecycle.
//!
//! The kernel uses an **object-capability model**: callers prove authority by
//! presenting an unforgeable, scoped token rather than by asserting identity.
//! Every capability is:
//!   - time-bounded (generation counter)
//!   - operation-scoped (bitflag set)
//!   - node-bound (issuer + target pair)
//!
//! Capabilities cannot be synthesised by callers; they are minted only by the
//! boot subsystem and delegated through explicit transfer operations that
//! reduce — never expand — the permission set.

pub mod capability;
pub mod policy;

pub use capability::{Capability, CapabilitySet};
pub use policy::Policy;
