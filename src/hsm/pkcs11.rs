//! PKCS#11 `CloudHSM` driver stub.
//!
//! Defines [`Pkcs11HsmProvider`] for `CloudHSM` (AWS `CloudHSM`, Thales Luna,
//! `SoftHSM2`) via the PKCS#11 interface.
//!
//! # Production integration
//!
//! 1. Add `cryptoki = { version = "0.8", optional = true }` under a
//!    `pkcs11_hsm` feature gate.
//! 2. Initialize via `cryptoki::Pkcs11::new(library_path)`.
//! 3. Open a session: `pkcs11.open_rw_session(slot)`.
//! 4. `sign` → `session.sign(&mechanism, key_handle, data)`.
//! 5. `generate_keypair` → `session.generate_key_pair(...)`.
//! 6. `rotate_key` → generate new pair, delete old private key object.

use crate::{
    error::Error,
    hsm::{HsmProvider, KeyHandle, KeyManagement},
    Result,
};

/// PKCS#11-backed `CloudHSM` provider.
///
/// Current state: software stub.  All methods return `Err(CapabilityDenied)`
/// until a real PKCS#11 library is wired in.
#[derive(Debug)]
pub struct Pkcs11HsmProvider {
    _library_path: Option<std::path::PathBuf>,
}

impl Pkcs11HsmProvider {
    /// Construct a stub provider. In production, pass the PKCS#11 library path
    /// (e.g. `/usr/lib/libCloudhsm_pkcs11.so` for AWS `CloudHSM`).
    #[must_use]
    pub const fn new_stub(library_path: Option<std::path::PathBuf>) -> Self {
        Self { _library_path: library_path }
    }
}

impl HsmProvider for Pkcs11HsmProvider {
    fn generate_capability_seed(&self) -> Result<[u8; 32]> {
        Err(Error::CapabilityDenied {
            reason: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }

    fn sign(&self, _payload: &[u8]) -> Result<[u8; 64]> {
        Err(Error::CapabilityDenied {
            reason: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }

    fn verify(&self, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> {
        Err(Error::ManifestInvalid {
            detail: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }
}

impl KeyManagement for Pkcs11HsmProvider {
    fn generate_keypair(&self) -> Result<KeyHandle> {
        Err(Error::CapabilityDenied {
            reason: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }

    fn sign_capability(&self, _handle: &KeyHandle, _payload: &[u8]) -> Result<[u8; 64]> {
        Err(Error::CapabilityDenied {
            reason: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }

    fn verify_capability_signature(
        &self,
        _handle: &KeyHandle,
        _payload: &[u8],
        _sig: &[u8; 64],
    ) -> Result<()> {
        Err(Error::ManifestInvalid {
            detail: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        Err(Error::CapabilityDenied {
            reason: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }

    fn rotate_key(&self, _handle: &KeyHandle) -> Result<KeyHandle> {
        Err(Error::CapabilityDenied {
            reason: "Pkcs11HsmProvider: no PKCS#11 session open (stub implementation)",
        })
    }
}
