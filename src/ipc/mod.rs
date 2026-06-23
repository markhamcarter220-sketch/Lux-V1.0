//! Capability-Signed Message protocol — fork-only IPC formalization.
//!
//! Scope: this module, `docs/ipc/`, and `formal/ipc/` only (see
//! `/FORK_CONTEXT.md`). It introduces no new invariant enforcement point —
//! authorization is delegated entirely to
//! [`crate::auth::capability::Capability::authorises`] (I2).

mod message;

pub use message::{SignedMessage, MAX_BODY};
