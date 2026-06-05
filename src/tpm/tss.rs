//! TPM 2.0 driver stub for the `tss-esapi` / `tpm2-tss` integration.
//!
//! [`TssTpmProvider`] is a software stub.  All methods return
//! `Err(ManifestInvalid)` until a real TPM 2.0 device is connected.
//!
//! # Production integration
//!
//! 1. Add `tss-esapi = { version = "0.21", features = [] }` to `[dependencies]`
//!    under a `tss_tpm` feature gate.
//! 2. Initialize: `tss_esapi::Context::new(tcti_context)` where `tcti_context` is
//!    a TCTI connector (e.g. `tss_esapi::tcti_ldr::TctiNameConf::from_str("device:/dev/tpm0")`).
//! 3. `extend_pcr` → `context.pcr_extend(pcr_selection, digest_list)`.
//! 4. `quote` → `context.quote(key_handle, qualifying_data, signing_scheme, pcr_selection)`.
//! 5. `read_pcr` → `context.pcr_read(pcr_selection)`.
//! 6. `verify_quote` → verify the `TPMS_ATTEST` structure signature with the
//!    Attestation Key (AK) public key via `tss_esapi::structures::Attest`.

use crate::{
    error::Error,
    tpm::{TpmProvider, TpmQuote},
    Result,
};

/// TPM 2.0 hardware provider backed by the `tss-esapi` / `tpm2-tss` stack.
///
/// In the current build this is a software stub.  All methods return
/// `Err(ManifestInvalid)` until a real TPM 2.0 device is connected and the
/// production integration (described in the module documentation) is complete.
#[derive(Debug)]
pub struct TssTpmProvider {
    _connected: bool,
}

impl TssTpmProvider {
    /// Construct a stub provider.
    ///
    /// In production this would open a TCTI connection to the TPM 2.0 device
    /// (e.g. `/dev/tpm0`).  The stub is useful for compile-time type checking
    /// without requiring hardware.
    #[must_use]
    pub const fn new_stub() -> Self {
        Self { _connected: false }
    }
}

impl TpmProvider for TssTpmProvider {
    fn extend_pcr(&mut self, _pcr_index: u8, _data: &[u8]) -> Result<()> {
        Err(Error::ManifestInvalid {
            detail: "TssTpmProvider: hardware not connected (stub implementation)",
        })
    }

    fn quote(&self, _pcr_index: u8, _nonce: &[u8; 32]) -> Result<TpmQuote> {
        Err(Error::ManifestInvalid {
            detail: "TssTpmProvider: hardware not connected (stub implementation)",
        })
    }

    fn read_pcr(&self, _pcr_index: u8) -> Result<[u8; 32]> {
        Err(Error::ManifestInvalid {
            detail: "TssTpmProvider: hardware not connected (stub implementation)",
        })
    }

    fn verify_quote(&self, _pcr_index: u8, _nonce: &[u8; 32], _quote: &TpmQuote) -> Result<()> {
        Err(Error::ManifestInvalid {
            detail: "TssTpmProvider: hardware not connected (stub implementation)",
        })
    }
}
