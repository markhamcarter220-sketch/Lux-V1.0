//! Capability-Signed Message — fork-only IPC envelope.
//!
//! See `/FORK_CONTEXT.md` for fork scope and `docs/ipc/DESIGN.md` for the
//! protocol rationale. Gated behind the `ipc` Cargo feature.
//!
//! # Protocol
//!
//! A [`SignedMessage`] is signed by the sender's [`HsmProvider`] over:
//!
//! `issuer_le32 || recipient_le32 || body`
//!
//! and is verified in two independent, fail-closed steps:
//!
//! 1. **Origin** — [`HsmProvider::verify`] checks the Ed25519 signature over
//!    the addressing pair and body.
//! 2. **Authorisation** — the message's `issuer`/`recipient` must match the
//!    presented [`Capability`]'s own [`Capability::issuer`] /
//!    [`Capability::target`] exactly, and the capability must
//!    [`Capability::authorises`] the required right at the caller-supplied
//!    current generation.
//!
//! This module deliberately uses only `Capability`'s unconditionally-public
//! accessors (`issuer`, `target`, `authorises`) — it does not depend on the
//! `hsm`-feature-gated raw-bit accessors (`rights_bits`, `generation_raw`,
//! `nonce_raw`) used by [`crate::hsm::HsmSignedCapability`], so this protocol
//! has no dependency on the `hsm` feature and stays `no_std`-compatible. It
//! introduces no new invariant enforcement point — I2 (capability-gated)
//! continues to be enforced exclusively by [`Capability::authorises`].

use heapless::Vec as HVec;

use crate::{
    auth::capability::{Capability, CapabilitySet},
    error::Error,
    hsm::HsmProvider,
    types::{Generation, NodeId},
    Result,
};

/// Maximum message body size in bytes.
pub const MAX_BODY: usize = 256;

/// Length of the addressing prefix (`issuer_le32 || recipient_le32`).
const ADDR_PREFIX_LEN: usize = 8;

/// A message body signed by its sender and addressed to a recipient.
#[derive(Debug)]
pub struct SignedMessage {
    issuer: NodeId,
    recipient: NodeId,
    body: HVec<u8, MAX_BODY>,
    signature: [u8; 64],
}

impl SignedMessage {
    /// Sign `body` as sent from `issuer` to `recipient`, using `hsm` to
    /// produce the Ed25519 signature.
    ///
    /// # Errors
    /// Returns [`Error::CapabilityDenied`] if `body` exceeds [`MAX_BODY`], or
    /// if `hsm` has no signing key configured (verify-only mode).
    pub fn sign<H: HsmProvider>(
        issuer: NodeId,
        recipient: NodeId,
        body: &[u8],
        hsm: &H,
    ) -> Result<Self> {
        let mut owned_body: HVec<u8, MAX_BODY> = HVec::new();
        owned_body
            .extend_from_slice(body)
            .map_err(|()| Error::CapabilityDenied {
                reason: "ipc: message body exceeds MAX_BODY",
            })?;

        let payload = Self::signed_payload(issuer, recipient, &owned_body)?;
        let signature = hsm.sign(&payload)?;

        Ok(Self {
            issuer,
            recipient,
            body: owned_body,
            signature,
        })
    }

    /// Verify this message's signature, that its addressing matches
    /// `capability`'s bound issuer/target, and that `capability` authorises
    /// `required_right` at `current_generation`. Returns the verified body on
    /// success.
    ///
    /// # Errors
    /// Returns [`Error::ManifestInvalid`] if the signature does not verify.
    /// Returns [`Error::CapabilityDenied`] if the message's addressing does
    /// not match `capability`, or if `capability` does not authorise
    /// `required_right` at `current_generation`. Any failure denies the
    /// message — verification is fail-closed.
    pub fn verify<H: HsmProvider>(
        &self,
        capability: &Capability,
        required_right: CapabilitySet,
        current_generation: Generation,
        hsm: &H,
    ) -> Result<&[u8]> {
        let payload = Self::signed_payload(self.issuer, self.recipient, &self.body)?;
        hsm.verify(&payload, &self.signature)?;

        if self.issuer != capability.issuer() || self.recipient != capability.target() {
            return Err(Error::CapabilityDenied {
                reason: "ipc: message addressing does not match presented capability",
            });
        }

        if !capability.authorises(required_right, current_generation) {
            return Err(Error::CapabilityDenied {
                reason: "ipc: capability does not authorise required right at current generation",
            });
        }

        Ok(&self.body)
    }

    /// Returns the canonical `issuer || recipient || body` buffer that is
    /// signed and verified.
    fn signed_payload(
        issuer: NodeId,
        recipient: NodeId,
        body: &[u8],
    ) -> Result<HVec<u8, { ADDR_PREFIX_LEN + MAX_BODY }>> {
        let mut buf: HVec<u8, { ADDR_PREFIX_LEN + MAX_BODY }> = HVec::new();
        buf.extend_from_slice(&issuer.get().to_le_bytes())
            .map_err(|()| Error::CapabilityDenied {
                reason: "ipc: signing buffer capacity exceeded",
            })?;
        buf.extend_from_slice(&recipient.get().to_le_bytes())
            .map_err(|()| Error::CapabilityDenied {
                reason: "ipc: signing buffer capacity exceeded",
            })?;
        buf.extend_from_slice(body)
            .map_err(|()| Error::CapabilityDenied {
                reason: "ipc: message body exceeds MAX_BODY",
            })?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::capability::CapabilitySet,
        hsm::SoftwareHsm,
        types::{Generation, NodeId},
    };

    fn test_capability(rights: CapabilitySet, generation: Generation, nonce: u64) -> Capability {
        Capability::new_for_test(
            NodeId::new(1).unwrap(),
            NodeId::new(2).unwrap(),
            rights,
            generation,
            nonce,
        )
    }

    #[test]
    fn verify_accepts_matching_addressing_and_capability() {
        let hsm = SoftwareHsm::from_signing_key([7u8; 32]);
        let cap = test_capability(CapabilitySet::SCHEDULE, Generation(1), 42);

        let msg = SignedMessage::sign(
            NodeId::new(1).unwrap(),
            NodeId::new(2).unwrap(),
            b"enqueue",
            &hsm,
        )
        .unwrap();
        let body = msg
            .verify(&cap, CapabilitySet::SCHEDULE, Generation(1), &hsm)
            .unwrap();

        assert_eq!(body, b"enqueue");
    }

    #[test]
    fn verify_rejects_wrong_generation() {
        let hsm = SoftwareHsm::from_signing_key([7u8; 32]);
        let cap = test_capability(CapabilitySet::SCHEDULE, Generation(1), 42);

        let msg = SignedMessage::sign(
            NodeId::new(1).unwrap(),
            NodeId::new(2).unwrap(),
            b"enqueue",
            &hsm,
        )
        .unwrap();

        assert!(msg
            .verify(&cap, CapabilitySet::SCHEDULE, Generation(2), &hsm)
            .is_err());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let hsm = SoftwareHsm::from_signing_key([7u8; 32]);
        let cap = test_capability(CapabilitySet::SCHEDULE, Generation(1), 42);

        let mut msg = SignedMessage::sign(
            NodeId::new(1).unwrap(),
            NodeId::new(2).unwrap(),
            b"enqueue",
            &hsm,
        )
        .unwrap();
        msg.body.clear();
        msg.body.extend_from_slice(b"dequeue").unwrap();

        assert!(msg
            .verify(&cap, CapabilitySet::SCHEDULE, Generation(1), &hsm)
            .is_err());
    }

    #[test]
    fn verify_rejects_missing_right() {
        let hsm = SoftwareHsm::from_signing_key([7u8; 32]);
        let cap = test_capability(CapabilitySet::SCHEDULE, Generation(1), 42);

        let msg = SignedMessage::sign(
            NodeId::new(1).unwrap(),
            NodeId::new(2).unwrap(),
            b"enqueue",
            &hsm,
        )
        .unwrap();

        assert!(msg
            .verify(&cap, CapabilitySet::SHUTDOWN, Generation(1), &hsm)
            .is_err());
    }

    #[test]
    fn verify_rejects_addressing_mismatch() {
        let hsm = SoftwareHsm::from_signing_key([7u8; 32]);
        let cap = test_capability(CapabilitySet::SCHEDULE, Generation(1), 42);

        // Signed as 1 -> 3, but the capability is bound to 1 -> 2.
        let msg = SignedMessage::sign(
            NodeId::new(1).unwrap(),
            NodeId::new(3).unwrap(),
            b"enqueue",
            &hsm,
        )
        .unwrap();

        assert!(msg
            .verify(&cap, CapabilitySet::SCHEDULE, Generation(1), &hsm)
            .is_err());
    }
}
