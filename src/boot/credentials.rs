//! Boot credentials — sealed public-key material for manifest verification.
//!
//! The `BootCredentials` struct holds the Ed25519 verifying key that the boot
//! sequence uses to authenticate manifests.  It is constructed once and never
//! mutated; callers receive it through the same all-or-nothing boot path that
//! produces `BootState`.
//!
//! The key is stored as a `VerifyingKey` (32 bytes).  Zeroization-on-drop
//! is handled by `ed25519_dalek`'s own implementation.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{error::Error, Result};

/// Immutable public-key material used to authenticate boot manifests.
#[derive(Debug)]
pub struct BootCredentials {
    verifying_key: VerifyingKey,
}

impl BootCredentials {
    /// Construct credentials from a 32-byte Ed25519 public key.
    ///
    /// Returns `Err(ManifestInvalid)` if the bytes do not represent a valid
    /// point on the Ed25519 curve.
    pub fn from_key_bytes(bytes: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes)
            .map(|verifying_key| Self { verifying_key })
            .map_err(|_| Error::ManifestInvalid {
                detail: "invalid Ed25519 public key bytes",
            })
    }

    /// Verify `signature_bytes` over `message` using the stored key.
    ///
    /// Uses `verify_strict` which performs additional validity checks on the
    /// signature (cofactor clearing, small-subgroup checks).
    ///
    /// Returns `Err(ManifestInvalid)` on any verification failure.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> Result<()> {
        let sig = Signature::from_bytes(signature_bytes);
        self.verifying_key
            .verify_strict(message, &sig)
            .map_err(|_| Error::ManifestInvalid {
                detail: "Ed25519 signature verification failed",
            })
    }

    /// Returns the raw 32-byte encoding of the verifying key.
    #[must_use]
    pub fn key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}
