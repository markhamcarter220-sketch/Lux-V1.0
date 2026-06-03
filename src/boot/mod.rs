//! Boot subsystem — manifest parsing and kernel initialisation sequence.
//!
//! The boot sequence is the **only** path through which topology edges,
//! capability seeds, and resource quotas may be established.  All subsequent
//! mutations are gated by auth checks against the sealed manifest.

pub mod manifest;

pub use manifest::Manifest;

use crate::Result;

/// Sealed kernel state produced by a successful boot sequence.
/// Once constructed this struct is immutable.
#[derive(Debug)]
pub struct BootState {
    pub(crate) manifest: Manifest,
    pub(crate) generation: crate::types::Generation,
}

impl BootState {
    /// Validate `raw` bytes, construct a `Manifest`, and seal the boot state.
    ///
    /// Returns `Err` — and performs no partial initialisation — if any
    /// validation step fails.
    pub fn initialise(raw: &[u8]) -> Result<Self> {
        let manifest = Manifest::parse_and_verify(raw)?;
        Ok(Self {
            manifest,
            generation: crate::types::Generation(0),
        })
    }
}
