//! Hardware Security Module (HSM) abstraction.
//!
//! Defines the [`HsmProvider`] trait that all HSM backends must implement.
//! The kernel never holds raw signing key material — all cryptographic
//! operations are delegated to the provider.
//!
//! # Feature flag
//!
//! The `hsm` Cargo feature exposes this module for integration with real HSM
//! drivers.  When the feature is disabled (the default), only the software
//! mock [`mock::SoftwareHsm`] is available.
//!
//! # Security contract
//!
//! - [`HsmProvider::verify`] is the only path through which a manifest
//!   signature is accepted.  Implementations must use a cryptographically
//!   sound verification algorithm (Ed25519 with cofactor clearing is the
//!   reference).
//! - [`HsmProvider::sign`] must produce signatures that a corresponding
//!   `verify` call accepts.  Mock implementations that return fixed bytes
//!   must document that they are test-only.
//! - [`HsmProvider::generate_capability_seed`] must return 32 bytes of
//!   material that is computationally unpredictable to an external adversary.
//!   Software mocks that return deterministic values must document this
//!   limitation.

pub mod mock;

pub use mock::SoftwareHsm;

use crate::Result;

/// Abstraction over an HSM or software-equivalent cryptographic provider.
///
/// All methods take `&self` (immutable reference) to allow sharing across the
/// boot pipeline without requiring `&mut`.  Implementations that maintain
/// internal mutable state (e.g. a nonce counter) must use interior mutability
/// with appropriate bounds (no `Send`/`Sync` required — the kernel is
/// single-threaded).
///
/// # `no_std` compatibility
///
/// All method signatures use only fixed-size arrays and `&[u8]` slices.
/// No heap allocations, no `String`, no `Vec`.
pub trait HsmProvider {
    /// Generate 32 bytes of capability seed material.
    ///
    /// A hardware HSM implementation uses its on-chip TRNG.  The software
    /// mock returns a deterministic value derived from the configured key.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if the HSM is
    /// unavailable or entropy generation fails.
    fn generate_capability_seed(&self) -> Result<[u8; 32]>;

    /// Sign `payload` and return the 64-byte Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if no signing key
    /// is configured (verify-only mode) or if the HSM rejects the operation.
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]>;

    /// Verify that `sig` is a valid Ed25519 signature over `payload`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::ManifestInvalid`] on any verification
    /// failure (wrong key, forged signature, malformed bytes).
    fn verify(&self, payload: &[u8], sig: &[u8; 64]) -> Result<()>;
}
