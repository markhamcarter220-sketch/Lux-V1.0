//! Boot attestation — a TPM-anchored proof that a specific manifest was booted.
//!
//! [`BootAttestation`] packages the manifest hash, the PCR index used, the
//! challenge nonce, and the [`TpmQuote`] into a single verifiable structure.
//!
//! # Verification protocol
//!
//! Challenge-response flow:
//! 1. Verifier sends a random 32-byte `nonce` to the booted system.
//! 2. System calls [`crate::boot::BootState::produce_attestation`] → [`BootAttestation`].
//! 3. Verifier reconstructs the expected PCR state by extending a fresh
//!    [`crate::tpm::mock::SoftwareTpm`] with the expected manifest bytes, then
//!    calls [`BootAttestation::verify`] to confirm the quote matches.

use crate::{tpm::{TpmProvider, TpmQuote}, Result};

/// A TPM-anchored boot attestation.
///
/// Produced by [`crate::boot::BootState::produce_attestation`].
/// Verified by [`BootAttestation::verify`] against a [`TpmProvider`] in the
/// same PCR state as when the quote was produced.
#[derive(Debug, Clone, Copy)]
pub struct BootAttestation {
    /// SHA-256 of the raw manifest bytes loaded at boot.
    manifest_hash: [u8; 32],
    /// PCR index that received the manifest measurement.
    pcr_index:     u8,
    /// Challenge nonce mixed into the quote (provided by the verifier).
    nonce:         [u8; 32],
    /// TPM attestation quote binding PCR state to the nonce.
    quote:         TpmQuote,
}

impl BootAttestation {
    /// Construct a new [`BootAttestation`].
    ///
    /// All fields are caller-supplied; no TPM interaction occurs here.
    /// Use [`crate::boot::BootState::produce_attestation`] to create an
    /// attestation that is cryptographically bound to a live TPM state.
    #[must_use]
    pub const fn new(
        manifest_hash: [u8; 32],
        pcr_index:     u8,
        nonce:         [u8; 32],
        quote:         TpmQuote,
    ) -> Self {
        Self { manifest_hash, pcr_index, nonce, quote }
    }

    /// Returns the SHA-256 hash of the raw manifest bytes recorded at boot.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// Returns the PCR index into which the manifest measurement was extended.
    #[must_use]
    pub const fn pcr_index(&self) -> u8 {
        self.pcr_index
    }

    /// Returns the challenge nonce mixed into the attestation quote.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Returns the TPM attestation quote.
    #[must_use]
    pub const fn quote(&self) -> &TpmQuote {
        &self.quote
    }

    /// Verify the attestation against `tpm`.
    ///
    /// Delegates to [`TpmProvider::verify_quote`] with the stored PCR index,
    /// nonce, and quote.  The caller must ensure `tpm` is in the same PCR
    /// state that was present when the quote was produced.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::ManifestInvalid`] if the quote does not
    /// match the current PCR state and nonce as determined by `tpm`.
    pub fn verify<T: TpmProvider>(&self, tpm: &T) -> Result<()> {
        tpm.verify_quote(self.pcr_index, &self.nonce, &self.quote)
    }
}
