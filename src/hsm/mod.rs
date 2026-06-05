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
//! When `hsm` is enabled, the additional [`KeyManagement`] trait, the
//! [`KeyHandle`] type, and the [`HsmSignedCapability`] helper are available.
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

#[cfg(feature = "hsm")]
pub mod keystore;

#[cfg(feature = "hsm")]
pub mod yubihsm;

#[cfg(feature = "hsm")]
pub mod pkcs11;

pub use mock::SoftwareHsm;

#[cfg(feature = "hsm")]
pub use keystore::SoftwareKeyStore;

#[cfg(feature = "hsm")]
pub use yubihsm::YubiHsmProvider;

#[cfg(feature = "hsm")]
pub use pkcs11::Pkcs11HsmProvider;

use crate::Result;
use zeroize::Zeroize;

/// An opaque handle to a key slot inside an HSM or software key store.
///
/// The 32 bytes are the SHA-256 hash of the associated Ed25519 verifying key.
/// Handles are stable for the lifetime of a key slot; after
/// [`KeyManagement::rotate_key`] the old handle is invalidated and a new one is
/// returned.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub [u8; 32]);

impl core::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyHandle({:x?})", &self.0[..4])
    }
}

impl Zeroize for KeyHandle {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

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

/// Extended key-management operations available when the `hsm` feature is on.
///
/// Complements [`HsmProvider`] with the ability to manage named key slots:
/// generate keypairs, sign and verify per-slot, list active slots, and rotate
/// keys.  All slots are identified by [`KeyHandle`].
///
/// Implementations are expected to store key material securely.  The
/// software reference implementation (`SoftwareKeyStore`) uses
/// `Mutex<HashMap>` with `ZeroizingSigningKey` wrappers.
#[cfg(feature = "hsm")]
pub trait KeyManagement {
    /// Generate a fresh Ed25519 keypair and return its [`KeyHandle`].
    ///
    /// The handle is the SHA-256 hash of the new verifying key.  Callers
    /// must retain the handle to use the key later; handles are not
    /// otherwise enumerable without [`Self::list_keys`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if key generation
    /// fails (hardware unavailable, entropy exhausted, mutex poisoned, etc.).
    fn generate_keypair(&self) -> Result<KeyHandle>;

    /// Sign `payload` with the key identified by `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if `handle` is not
    /// found, the HSM rejects the operation, or the key store mutex is
    /// poisoned.
    fn sign_capability(&self, handle: &KeyHandle, payload: &[u8]) -> Result<[u8; 64]>;

    /// Verify that `sig` is a valid Ed25519 signature over `payload` under the
    /// key identified by `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if `handle` is not
    /// found or the key store mutex is poisoned.
    /// Returns [`crate::error::Error::ManifestInvalid`] if signature
    /// verification fails.
    fn verify_capability_signature(
        &self,
        handle: &KeyHandle,
        payload: &[u8],
        sig: &[u8; 64],
    ) -> Result<()>;

    /// Return the handles of all active key slots.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if the key store
    /// mutex is poisoned or the hardware is unavailable.
    fn list_keys(&self) -> Result<Vec<KeyHandle>>;

    /// Generate a replacement key for the slot identified by `handle`,
    /// atomically replace the slot entry, and return the new handle.
    ///
    /// After this call the old `handle` is invalid; any subsequent call
    /// referencing it returns `Err(CapabilityDenied)`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if `handle` is not
    /// found, key generation fails, or the key store mutex is poisoned.
    fn rotate_key(&self, handle: &KeyHandle) -> Result<KeyHandle>;
}

/// A capability token that has been signed by an HSM key slot.
///
/// Wraps a [`crate::auth::capability::Capability`] together with the
/// [`KeyHandle`] that signed it and the resulting 64-byte Ed25519 signature.
///
/// The signed payload is the 28-byte concatenation:
/// `issuer_le32 || target_le32 || rights_le32 || generation_le64 || nonce_le64`.
#[cfg(feature = "hsm")]
#[derive(Debug)]
pub struct HsmSignedCapability {
    /// The inner capability token.
    pub inner: crate::auth::capability::Capability,
    /// The key handle that was used to sign `inner`.
    pub key_handle: KeyHandle,
    /// The 64-byte Ed25519 signature over the canonical payload.
    pub signature: [u8; 64],
}

#[cfg(feature = "hsm")]
impl HsmSignedCapability {
    /// Sign a capability with the given HSM key handle.
    ///
    /// The payload is
    /// `issuer_le32 || target_le32 || rights_le32 || generation_le64 || nonce_le64`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if `handle` is not
    /// found in the key store or if the HSM rejects the signing operation.
    pub fn sign<H: HsmProvider + KeyManagement>(
        cap: crate::auth::capability::Capability,
        handle: &KeyHandle,
        hsm: &H,
    ) -> Result<Self> {
        let payload = Self::cap_payload(&cap);
        let signature = hsm.sign_capability(handle, &payload)?;
        Ok(Self { inner: cap, key_handle: *handle, signature })
    }

    /// Verify the HSM signature on this capability.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::CapabilityDenied`] if the key handle is
    /// not found.  Returns [`crate::error::Error::ManifestInvalid`] if the
    /// signature does not verify.
    pub fn verify<H: HsmProvider + KeyManagement>(&self, hsm: &H) -> Result<()> {
        let payload = Self::cap_payload(&self.inner);
        hsm.verify_capability_signature(&self.key_handle, &payload, &self.signature)
    }

    /// Compute the canonical 28-byte signing payload for a capability.
    fn cap_payload(cap: &crate::auth::capability::Capability) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(&cap.issuer().get().to_le_bytes());
        buf[4..8].copy_from_slice(&cap.target().get().to_le_bytes());
        buf[8..12].copy_from_slice(&cap.rights_bits().to_le_bytes());
        buf[12..20].copy_from_slice(&cap.generation_raw().to_le_bytes());
        buf[20..28].copy_from_slice(&cap.nonce_raw().to_le_bytes());
        buf
    }
}

/// Construct the default software key store.
///
/// Returns a [`SoftwareKeyStore`] with no primary signing key pre-loaded.
/// This is the reference implementation used in tests and environments
/// without physical HSM hardware.
#[cfg(feature = "hsm")]
#[must_use]
pub fn default_hsm() -> keystore::SoftwareKeyStore {
    keystore::SoftwareKeyStore::new()
}
