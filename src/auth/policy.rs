//! Policy enforcement point — the kernel's single authorisation gate.
//!
//! All subsystems route capability checks through `Policy::check`.  No
//! subsystem may short-circuit this path.

use crate::{
    auth::capability::{Capability, CapabilitySet},
    error::Error,
    types::Generation,
    Result,
};

/// The kernel's central enforcement point.
#[derive(Debug)]
pub struct Policy {
    current_generation: Generation,
}

impl Policy {
    /// Construct a `Policy` anchored at `generation`.
    #[must_use]
    pub const fn new(generation: Generation) -> Self {
        Self { current_generation: generation }
    }

    /// Gate the operation described by `required_right` on `cap`.
    ///
    /// Returns `Ok(())` iff the token is valid, current, and holds the right.
    /// Every other path returns `Err(CapabilityDenied)` — fail-closed.
    pub fn check(&self, cap: &Capability, required_right: CapabilitySet) -> Result<()> {
        if cap.authorises(required_right, self.current_generation) {
            Ok(())
        } else {
            Err(Error::CapabilityDenied {
                reason: "token expired, insufficient rights, or wrong generation",
            })
        }
    }

    /// Advance the generation counter, immediately invalidating all tokens
    /// issued under older generations.
    pub fn rotate_generation(&mut self) {
        self.current_generation = Generation(self.current_generation.0.saturating_add(1));
    }
}
