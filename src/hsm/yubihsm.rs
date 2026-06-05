//! `YubiHSM` hardware driver stub.
//!
//! This module defines [`YubiHsmProvider`] implementing [`HsmProvider`] and
//! [`KeyManagement`].  In the current build it is a software stub that returns
//! `Err(CapabilityDenied)` when no hardware is connected.
//!
//! # Production integration
//!
//! When a `YubiHSM` 2 is available:
//! 1. Add `yubihsm = { version = "0.40", features = ["usb", "http-server"] }` to
//!    `[dependencies]` under a `yubihsm_driver` feature gate.
//! 2. Replace the stub body of each method with the corresponding
//!    `yubihsm::Client` call:
//!    - `sign` → `client.sign_ed25519(key_id, message)`
//!    - `verify` → retrieve public key, then `VerifyingKey::verify_strict`
//!    - `generate_keypair` → `client.generate_asymmetric_key`
//!    - `rotate_key` → generate new key, delete old object
//! 3. `YubiHsmProvider::connect(connector_url)` opens the session.

use crate::{
    error::Error,
    hsm::{HsmProvider, KeyHandle, KeyManagement},
    Result,
};

/// `YubiHSM` 2 hardware provider.
///
/// In the current build this is a software stub.  Methods return
/// `Err(CapabilityDenied)` when no hardware session is open.
/// See module documentation for production integration instructions.
#[derive(Debug)]
pub struct YubiHsmProvider {
    /// Placeholder for a `yubihsm::Client` when hardware is connected.
    _connected: bool,
}

impl YubiHsmProvider {
    /// Construct a stub provider. In production, this would open a USB/HTTP
    /// session to the `YubiHSM` device.
    #[must_use]
    pub const fn new_stub() -> Self {
        Self { _connected: false }
    }
}

impl HsmProvider for YubiHsmProvider {
    fn generate_capability_seed(&self) -> Result<[u8; 32]> {
        Err(Error::CapabilityDenied {
            reason: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }

    fn sign(&self, _payload: &[u8]) -> Result<[u8; 64]> {
        Err(Error::CapabilityDenied {
            reason: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }

    fn verify(&self, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> {
        Err(Error::ManifestInvalid {
            detail: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }
}

impl KeyManagement for YubiHsmProvider {
    fn generate_keypair(&self) -> Result<KeyHandle> {
        Err(Error::CapabilityDenied {
            reason: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }

    fn sign_capability(&self, _handle: &KeyHandle, _payload: &[u8]) -> Result<[u8; 64]> {
        Err(Error::CapabilityDenied {
            reason: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }

    fn verify_capability_signature(
        &self,
        _handle: &KeyHandle,
        _payload: &[u8],
        _sig: &[u8; 64],
    ) -> Result<()> {
        Err(Error::ManifestInvalid {
            detail: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        Err(Error::CapabilityDenied {
            reason: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }

    fn rotate_key(&self, _handle: &KeyHandle) -> Result<KeyHandle> {
        Err(Error::CapabilityDenied {
            reason: "YubiHsmProvider: hardware not connected (stub implementation)",
        })
    }
}
