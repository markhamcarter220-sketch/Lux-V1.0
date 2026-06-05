//! Software HSM — the existing Ed25519 behaviour behind the [`HsmProvider`] trait.
//!
//! [`SoftwareHsm`] is the default provider used in all non-HSM builds.  It
//! is a behaviorally correct implementation of [`HsmProvider`] using the
//! `ed25519-dalek` crate.
//!
//! # Limitations
//!
//! - [`SoftwareHsm::generate_capability_seed`] returns a SHA-256 digest of
//!   the verifying key bytes.  This is **deterministic** — the same key
//!   always produces the same seed.  A production HSM uses hardware entropy.
//! - Instances constructed with [`SoftwareHsm::from_verifying_key`] cannot
//!   sign; [`HsmProvider::sign`] returns `Err` for those instances.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{error::Error, hsm::HsmProvider, Result};

/// Software-backed HSM provider using Ed25519 and SHA-256.
///
/// Constructed via [`SoftwareHsm::from_verifying_key`] (verify + seed only)
/// or [`SoftwareHsm::from_signing_key`] (sign + verify + seed).
#[derive(Debug)]
pub struct SoftwareHsm {
    verifying_key: VerifyingKey,
    signing_key:   Option<SigningKey>,
}

impl SoftwareHsm {
    /// Construct a verify-only provider from a 32-byte Ed25519 public key.
    ///
    /// [`HsmProvider::sign`] will return `Err` for instances constructed this
    /// way.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ManifestInvalid`] if `bytes` is not a valid Ed25519
    /// curve point.
    pub fn from_verifying_key(bytes: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes)
            .map(|verifying_key| Self { verifying_key, signing_key: None })
            .map_err(|_| Error::ManifestInvalid {
                detail: "invalid Ed25519 public key bytes",
            })
    }

    /// Construct a full (sign + verify) provider from a 32-byte Ed25519
    /// private key seed.
    ///
    /// The verifying key is derived deterministically from the seed.
    #[must_use]
    pub fn from_signing_key(seed: [u8; 32]) -> Self {
        let signing_key   = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self { verifying_key, signing_key: Some(signing_key) }
    }

    /// Returns the raw 32-byte verifying key.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl HsmProvider for SoftwareHsm {
    fn generate_capability_seed(&self) -> Result<[u8; 32]> {
        // Deterministic seed derived from the verifying key.
        // A hardware HSM would use its on-chip TRNG here.
        let mut h = Sha256::new();
        h.update(self.verifying_key.as_bytes());
        Ok(h.finalize().into())
    }

    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        match &self.signing_key {
            Some(sk) => Ok(sk.sign(payload).to_bytes()),
            None     => Err(Error::CapabilityDenied {
                reason: "SoftwareHsm: no signing key configured (verify-only mode)",
            }),
        }
    }

    fn verify(&self, payload: &[u8], sig: &[u8; 64]) -> Result<()> {
        let sig = Signature::from_bytes(sig);
        self.verifying_key
            .verify_strict(payload, &sig)
            .map_err(|_| Error::ManifestInvalid {
                detail: "Ed25519 signature verification failed",
            })
    }
}
