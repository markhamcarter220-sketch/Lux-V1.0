//! Policy enforcement point — the kernel's single authorisation gate.
//!
//! ## Nonce replay protection
//!
//! `Policy` maintains a per-generation nonce window (`used_nonces`).
//! Every successful `check` records the capability's nonce; a second
//! presentation of the same nonce within the same generation is denied.
//! On `rotate_generation` the window is cleared atomically.
//!
//! When the window is exhausted (`NONCE_WINDOW` unique nonces consumed),
//! further checks are denied — the fail-closed response that forces the
//! caller to rotate the generation rather than silently widening the window.
//!
//! `check` requires `&mut self` because recording a nonce is a state mutation.
//! All subsystems that hold a `Policy` must be declared `mut`.

use heapless::Vec as HVec;

use crate::{
    auth::capability::{Capability, CapabilitySet},
    error::Error,
    types::{Generation, NONCE_WINDOW},
    Result,
};

/// The kernel's central enforcement point.
#[derive(Debug)]
pub struct Policy {
    current_generation: Generation,
    /// Nonces consumed in the current generation.  Cleared on rotation.
    used_nonces: HVec<u64, NONCE_WINDOW>,
}

impl Policy {
    /// Construct a `Policy` anchored at `generation`.
    #[must_use]
    pub fn new(generation: Generation) -> Self {
        Self {
            current_generation: generation,
            used_nonces: HVec::new(),
        }
    }

    /// Gate the operation described by `required_right` on `cap`.
    ///
    /// Returns `Ok(())` iff:
    /// - the token is valid and current (generation + rights check), **and**
    /// - the token's nonce has not been presented before in this generation.
    ///
    /// Every other path returns `Err(CapabilityDenied)` — fail-closed.
    pub fn check(&mut self, cap: &Capability, required_right: CapabilitySet) -> Result<()> {
        if !cap.authorises(required_right, self.current_generation) {
            return Err(Error::CapabilityDenied {
                reason: "token expired, insufficient rights, or wrong generation",
            });
        }

        if self.used_nonces.contains(&cap.nonce) {
            return Err(Error::CapabilityDenied { reason: "nonce replayed" });
        }

        // Fail-closed on window exhaustion: deny rather than silently permit.
        self.used_nonces
            .push(cap.nonce)
            .map_err(|_| Error::CapabilityDenied {
                reason: "nonce window exhausted; rotate generation",
            })?;

        Ok(())
    }

    /// Advance the generation counter, immediately invalidating all tokens
    /// issued under older generations and clearing the nonce replay window.
    pub fn rotate_generation(&mut self) {
        self.current_generation = Generation(self.current_generation.0.saturating_add(1));
        self.used_nonces.clear();
    }

    /// Returns the current generation value (read-only).
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.current_generation
    }
}
