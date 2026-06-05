//! Trusted Platform Module (TPM) abstraction.
//!
//! Defines the [`TpmProvider`] trait and the [`TpmQuote`] attestation type.
//! Two implementations are provided:
//!
//! - [`NullTpm`] — zero-cost no-op, always succeeds with an all-zeros quote.
//!   Used as the default in [`crate::boot::BootState::initialise`] so that
//!   existing call sites require no modification.
//! - [`mock::SoftwareTpm`] — a behaviorally correct SHA-256 based mock that
//!   maintains a PCR bank and produces verifiable quotes.
//!
//! # Feature flag
//!
//! The `tpm` Cargo feature exposes this module for integration with real TPM
//! drivers (e.g. via the `tss-esapi` crate).  The default build uses only
//! [`NullTpm`] and [`mock::SoftwareTpm`].
//!
//! # Security contract
//!
//! - [`TpmProvider::extend_pcr`] must be irreversible: once data is mixed into
//!   a PCR, only a full PCR reset (power cycle) can undo it.  Software mocks
//!   do not enforce this constraint.
//! - [`TpmProvider::quote`] must return a value that is cryptographically
//!   bound to the current PCR state.  A quote produced before a subsequent
//!   `extend_pcr` must not match the post-extension state.

pub mod mock;

pub use mock::SoftwareTpm;

use crate::Result;

/// A 64-byte TPM attestation quote.
///
/// Layout (software mock):
/// - bytes `[0..32]`  — current PCR value
/// - bytes `[32..64]` — SHA-256(PCR value || nonce)
///
/// Real TPM quotes carry additional structure (`TPMS_ATTEST`, signature) but
/// the 64-byte newtype is sufficient for the kernel's attestation API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmQuote(pub [u8; 64]);

impl TpmQuote {
    /// Returns the raw quote bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns `true` if the quote is all-zeros (produced by [`NullTpm`]).
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 64]
    }
}

/// Abstraction over a TPM or software-equivalent attestation provider.
///
/// # `no_std` compatibility
///
/// All method signatures use only fixed-size arrays and `&[u8]` slices.
pub trait TpmProvider {
    /// Extend PCR `pcr_index` with `data`.
    ///
    /// The extension operation is `PCR[pcr_index] = SHA-256(PCR[pcr_index] || data)`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::ManifestInvalid`] if `pcr_index` is out
    /// of range or the TPM rejects the operation.
    fn extend_pcr(&mut self, pcr_index: u8, data: &[u8]) -> Result<()>;

    /// Produce a 64-byte attestation quote for PCR `pcr_index`.
    ///
    /// The `nonce` is mixed into the quote to bind it to a specific challenge.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::ManifestInvalid`] if `pcr_index` is out
    /// of range or the TPM cannot produce a quote.
    fn quote(&self, pcr_index: u8, nonce: &[u8; 32]) -> Result<TpmQuote>;
}

/// Zero-cost no-op TPM provider.
///
/// Always succeeds; produces an all-zeros [`TpmQuote`].  Used as the default
/// in [`crate::boot::BootState::initialise`] so that existing code paths work
/// without a real TPM.
#[derive(Debug, Default)]
pub struct NullTpm;

impl TpmProvider for NullTpm {
    fn extend_pcr(&mut self, _pcr_index: u8, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn quote(&self, _pcr_index: u8, _nonce: &[u8; 32]) -> Result<TpmQuote> {
        Ok(TpmQuote([0u8; 64]))
    }
}
