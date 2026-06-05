//! Software TPM — a behaviorally correct SHA-256 based attestation mock.
//!
//! [`SoftwareTpm`] maintains a bank of 24 PCR registers (matching the TPM 2.0
//! SHA-256 PCR bank).  Each register starts at all-zeros and is extended via
//! `SHA-256(PCR[i] || data)`.  Quotes are produced as:
//!
//! ```text
//! quote.bytes[0..32]  = PCR[pcr_index]
//! quote.bytes[32..64] = SHA-256(PCR[pcr_index] || nonce)
//! ```
//!
//! This is not hardware-secure — it does not produce TPM-signed attestations —
//! but the logic is structurally equivalent: the quote is deterministically
//! bound to the PCR state, so any subsequent extension invalidates a prior
//! quote.

use sha2::{Digest, Sha256};

use crate::{
    error::Error,
    tpm::{TpmProvider, TpmQuote},
    Result,
};

/// Number of PCR registers in the simulated bank.
const PCR_COUNT: usize = 24;

/// Software-simulated TPM with a 24-register SHA-256 PCR bank.
#[derive(Debug)]
pub struct SoftwareTpm {
    pcrs: [[u8; 32]; PCR_COUNT],
}

impl SoftwareTpm {
    /// Construct a fresh TPM with all PCRs initialised to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pcrs: [[0u8; 32]; PCR_COUNT],
        }
    }

    /// Return the current value of PCR `index`, or `None` if out of range.
    #[must_use]
    pub fn pcr_value(&self, index: usize) -> Option<[u8; 32]> {
        self.pcrs.get(index).copied()
    }
}

impl Default for SoftwareTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmProvider for SoftwareTpm {
    fn extend_pcr(&mut self, pcr_index: u8, data: &[u8]) -> Result<()> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(Error::ManifestInvalid {
                detail: "TPM PCR index out of range",
            });
        }
        let mut h = Sha256::new();
        h.update(self.pcrs[idx]);
        h.update(data);
        self.pcrs[idx] = h.finalize().into();
        Ok(())
    }

    fn quote(&self, pcr_index: u8, nonce: &[u8; 32]) -> Result<TpmQuote> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(Error::ManifestInvalid {
                detail: "TPM PCR index out of range",
            });
        }
        let pcr_value = self.pcrs[idx];

        let mut h = Sha256::new();
        h.update(pcr_value);
        h.update(nonce);
        let signed: [u8; 32] = h.finalize().into();

        let mut quote = [0u8; 64];
        quote[..32].copy_from_slice(&pcr_value);
        quote[32..].copy_from_slice(&signed);

        Ok(TpmQuote(quote))
    }

    fn read_pcr(&self, pcr_index: u8) -> Result<[u8; 32]> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(Error::ManifestInvalid {
                detail: "TPM PCR index out of range",
            });
        }
        Ok(self.pcrs[idx])
    }

    fn verify_quote(&self, pcr_index: u8, nonce: &[u8; 32], quote: &TpmQuote) -> Result<()> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(Error::ManifestInvalid {
                detail: "TPM PCR index out of range",
            });
        }
        let pcr_value = self.pcrs[idx];

        let mut h = Sha256::new();
        h.update(pcr_value);
        h.update(nonce);
        let expected_signed: [u8; 32] = h.finalize().into();

        if quote.0[..32] == pcr_value && quote.0[32..] == expected_signed {
            Ok(())
        } else {
            Err(Error::ManifestInvalid {
                detail: "TPM quote verification failed: PCR value or signature mismatch",
            })
        }
    }
}
