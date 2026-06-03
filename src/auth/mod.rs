//! Authentication subsystem — capability token lifecycle and policy enforcement.
//!
//! The kernel uses an **object-capability model**: callers prove authority by
//! presenting an unforgeable, scoped token rather than by asserting identity.
//! Every capability is:
//!   - time-bounded (generation counter)
//!   - operation-scoped (bitflag set)
//!   - node-bound (issuer + target pair)
//!   - nonce-unique (one-use per generation, replay-protected)
//!   - revocable (explicit pre-use revocation via `Policy::revoke_capability`)
//!
//! Capabilities cannot be synthesised by callers; they are minted only by the
//! boot subsystem and delegated through explicit transfer operations that
//! reduce — never expand — the permission set.

pub mod capability;
pub mod policy;
pub mod revocation;

pub use capability::{Capability, CapabilitySet};
pub use policy::Policy;
pub use revocation::RevocationLedger;
