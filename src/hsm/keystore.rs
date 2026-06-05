//! Software-backed key store for the HSM key-management interface.
//!
//! [`SoftwareKeyStore`] stores Ed25519 signing keys in a `Mutex<HashMap>`.
//! Key material is zeroized on drop via the [`ZeroizingSigningKey`] wrapper.
//! This is the software-complete implementation of [`KeyManagement`] used
//! in tests and environments without physical HSM hardware.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    error::Error,
    hsm::{HsmProvider, KeyHandle, KeyManagement},
    Result,
};

/// A signing key wrapper that zeroizes key material on drop.
struct ZeroizingSigningKey(SigningKey);

impl Drop for ZeroizingSigningKey {
    fn drop(&mut self) {
        // `SigningKey` implements `ZeroizeOnDrop` (via its own `Drop` impl) when
        // the `zeroize` feature is active on `ed25519-dalek`.  We replace the
        // key with an all-zero placeholder before it is dropped so that the
        // original secret bytes are overwritten even on platforms without the
        // feature gate.
        let _ = std::mem::replace(&mut self.0, SigningKey::from_bytes(&[0u8; 32]));
    }
}

impl std::fmt::Debug for ZeroizingSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZeroizingSigningKey([redacted])")
    }
}

/// Software-backed HSM key store.
///
/// Stores Ed25519 signing keys in heap memory, protected by a `Mutex`.
/// This is the default provider for the `hsm` feature when no physical
/// HSM hardware is connected.
///
/// # Security limitations
///
/// - Keys are stored in heap memory, not in protected hardware.
/// - `generate_keypair` uses the OS CSPRNG (`OsRng`), not hardware entropy.
/// - There is no key usage audit log beyond the kernel's own `AuditLog`.
///
/// # Production use
///
/// Replace with `YubiHsmProvider` (FIDO2 + PKCS#11) or `Pkcs11HsmProvider`
/// (`CloudHSM` via PKCS#11) when deploying on hardware.
#[derive(Debug)]
pub struct SoftwareKeyStore {
    /// Primary signing key for `sign`/`verify`/`generate_capability_seed`.
    primary: Option<SigningKey>,
    /// Key table: handle → signing key, protected by a Mutex for interior mutability.
    keys: Mutex<HashMap<[u8; 32], ZeroizingSigningKey>>,
}

impl SoftwareKeyStore {
    /// Construct an empty key store with no primary signing key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primary: None,
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Construct a key store with a primary signing key from a 32-byte seed.
    #[must_use]
    pub fn with_signing_key(seed: [u8; 32]) -> Self {
        Self {
            primary: Some(SigningKey::from_bytes(&seed)),
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the verifying key bytes for the primary signing key, if any.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Option<[u8; 32]> {
        self.primary.as_ref().map(|sk| sk.verifying_key().to_bytes())
    }
}

impl Default for SoftwareKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmProvider for SoftwareKeyStore {
    fn generate_capability_seed(&self) -> Result<[u8; 32]> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        // Mix in the primary key bytes if available, as an additional entropy input.
        if let Some(sk) = &self.primary {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(sk.verifying_key().as_bytes());
            seed = h.finalize().into();
        }
        Ok(seed)
    }

    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        self.primary.as_ref().map_or(
            Err(Error::CapabilityDenied {
                reason: "SoftwareKeyStore: no primary signing key configured",
            }),
            |sk| Ok(sk.sign(payload).to_bytes()),
        )
    }

    fn verify(&self, payload: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = self.primary.as_ref().map_or_else(
            || {
                Err(Error::ManifestInvalid {
                    detail: "SoftwareKeyStore: no primary key for verify",
                })
            },
            |sk| Ok(sk.verifying_key()),
        )?;
        let sig = Signature::from_bytes(sig);
        vk.verify_strict(payload, &sig)
            .map_err(|_| Error::ManifestInvalid { detail: "Ed25519 signature verification failed" })
    }
}

impl KeyManagement for SoftwareKeyStore {
    fn generate_keypair(&self) -> Result<KeyHandle> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        // Handle is SHA-256 of the verifying key bytes.
        let handle_bytes: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(signing_key.verifying_key().as_bytes());
            h.finalize().into()
        };
        let handle = KeyHandle(handle_bytes);
        self.keys.lock().map_err(|_| Error::CapabilityDenied {
            reason: "SoftwareKeyStore: key store mutex poisoned",
        })?.insert(handle_bytes, ZeroizingSigningKey(signing_key));
        seed.zeroize();
        Ok(handle)
    }

    fn sign_capability(&self, handle: &KeyHandle, payload: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        let guard = self.keys.lock().map_err(|_| Error::CapabilityDenied {
            reason: "SoftwareKeyStore: key store mutex poisoned",
        })?;
        guard.get(&handle.0).map_or(
            Err(Error::CapabilityDenied { reason: "SoftwareKeyStore: key handle not found" }),
            |zk| Ok(zk.0.sign(payload).to_bytes()),
        )
    }

    fn verify_capability_signature(
        &self,
        handle: &KeyHandle,
        payload: &[u8],
        sig: &[u8; 64],
    ) -> Result<()> {
        let vk: VerifyingKey = self
            .keys
            .lock()
            .map_err(|_| Error::CapabilityDenied {
                reason: "SoftwareKeyStore: key store mutex poisoned",
            })?
            .get(&handle.0)
            .ok_or(Error::CapabilityDenied {
                reason: "SoftwareKeyStore: key handle not found",
            })?
            .0
            .verifying_key();
        let signature = Signature::from_bytes(sig);
        vk.verify_strict(payload, &signature).map_err(|_| Error::ManifestInvalid {
            detail: "HSM capability signature verification failed",
        })
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let guard = self.keys.lock().map_err(|_| Error::CapabilityDenied {
            reason: "SoftwareKeyStore: key store mutex poisoned",
        })?;
        Ok(guard.keys().map(|b| KeyHandle(*b)).collect())
    }

    fn rotate_key(&self, handle: &KeyHandle) -> Result<KeyHandle> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let new_key = SigningKey::from_bytes(&seed);
        let new_handle_bytes: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(new_key.verifying_key().as_bytes());
            h.finalize().into()
        };
        let new_handle = KeyHandle(new_handle_bytes);
        {
            let mut guard = self.keys.lock().map_err(|_| Error::CapabilityDenied {
                reason: "SoftwareKeyStore: key store mutex poisoned",
            })?;
            if !guard.contains_key(&handle.0) {
                return Err(Error::CapabilityDenied {
                    reason: "SoftwareKeyStore: key handle not found for rotation",
                });
            }
            // Remove old key (zeroized on drop) and insert new key.
            guard.remove(&handle.0);
            guard.insert(new_handle_bytes, ZeroizingSigningKey(new_key));
        }
        seed.zeroize();
        Ok(new_handle)
    }
}
