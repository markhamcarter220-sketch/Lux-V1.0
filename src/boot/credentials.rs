//! Boot credentials — HSM-backed or software public-key material for manifest
//! verification.
//!
//! [`BootCredentials`] is generic over an [`HsmProvider`].  By default it
//! uses [`SoftwareHsm`], which reproduces the original software-only Ed25519
//! behaviour.  When compiled with the `hsm` feature, real HSM drivers may be
//! substituted.
//!
//! All existing call sites that write `BootCredentials::from_key_bytes(...)` or
//! hold a `&BootCredentials` reference continue to work unchanged — the
//! default type parameter is applied automatically.

use crate::{
    hsm::{HsmProvider, SoftwareHsm},
    Result,
};

/// Immutable credential material used to authenticate boot manifests.
///
/// Generic over `H: HsmProvider`.  The default `H = SoftwareHsm` means that
/// plain `BootCredentials` (without an explicit type argument) is the software-
/// backed variant — identical to the pre-Tier-3 type.
#[derive(Debug)]
pub struct BootCredentials<H: HsmProvider = SoftwareHsm> {
    hsm: H,
}

/// Convenience constructor for the software-backed default.
impl BootCredentials<SoftwareHsm> {
    /// Construct software-backed credentials from a 32-byte Ed25519 public key.
    ///
    /// This is the backward-compatible constructor.  All existing code that
    /// calls `BootCredentials::from_key_bytes(...)` continues to work.
    ///
    /// # Errors
    ///
    /// Returns `Err(ManifestInvalid)` if the bytes do not represent a valid
    /// point on the Ed25519 curve.
    pub fn from_key_bytes(bytes: [u8; 32]) -> Result<Self> {
        SoftwareHsm::from_verifying_key(bytes).map(|hsm| Self { hsm })
    }

    /// Returns the raw 32-byte encoding of the verifying key.
    #[must_use]
    pub fn key_bytes(&self) -> [u8; 32] {
        self.hsm.verifying_key_bytes()
    }
}

impl<H: HsmProvider> BootCredentials<H> {
    /// Construct credentials from any [`HsmProvider`] implementation.
    #[must_use]
    pub fn new(hsm: H) -> Self {
        Self { hsm }
    }

    /// Verify `signature_bytes` over `message` via the configured HSM.
    ///
    /// Delegates to [`HsmProvider::verify`]; see that method's documentation
    /// for the security contract.
    ///
    /// # Errors
    ///
    /// Returns `Err(ManifestInvalid)` on any verification failure.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> Result<()> {
        self.hsm.verify(message, signature_bytes)
    }

    /// Generate 32 bytes of capability seed material via the configured HSM.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`HsmProvider::generate_capability_seed`].
    pub fn generate_capability_seed(&self) -> Result<[u8; 32]> {
        self.hsm.generate_capability_seed()
    }
}
