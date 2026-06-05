//! CBOR manifest wire-format decoder.
//!
//! # Wire format
//!
//! ```text
//! [64 bytes: Ed25519 signature] ++ [CBOR payload]
//! ```
//!
//! The signature covers the CBOR payload bytes verbatim.  Verification is
//! performed **before** any CBOR parsing: a manifest with an invalid
//! signature is rejected without inspecting its contents (fail-closed).
//!
//! The CBOR payload is a 3-element definite-length array:
//!
//! ```text
//! [
//!   uint: version,
//!   array: [ [uint src, uint dst], ... ],   -- directed topology edges
//!   array: [ [uint node, uint ceiling], ... ]  -- per-node resource quotas
//! ]
//! ```
//!
//! All CBOR arrays must use definite lengths; indefinite-length encodings are
//! rejected.  All integer values must be non-zero where a `NodeId` is expected.
//!
//! # Security properties
//! - Signature verified before parse (no speculative parse of unsigned data)
//! - Overflow-safe: quotas that exceed the manifest capacity return `ManifestInvalid`
//! - Every malformed input returns a distinct `ManifestInvalid` reason

use core::num::NonZeroU32;

use minicbor::decode::Decoder;

use crate::{
    boot::{
        credentials::BootCredentials,
        manifest::{EdgeDecl, Manifest, QuotaDecl},
    },
    error::Error,
    hsm::HsmProvider,
    types::Quota,
    Result,
};

/// Minimum wire size: 64-byte signature + at least 1 byte of CBOR.
const MIN_WIRE_LEN: usize = 65;
/// Ed25519 signature size in bytes.
const SIG_LEN: usize = 64;

/// Stateless CBOR manifest decoder.
#[derive(Debug)]
pub struct ManifestDecoder;

impl ManifestDecoder {
    /// Decode and verify a manifest from its wire-format bytes.
    ///
    /// Generic over `H: HsmProvider`.  Callers passing `&BootCredentials`
    /// (i.e. `&BootCredentials<SoftwareHsm>`) do not need an explicit type
    /// annotation — Rust infers `H = SoftwareHsm`.
    ///
    /// Steps (all-or-nothing):
    /// 1. Split signature (first 64 bytes) from CBOR payload.
    /// 2. Verify Ed25519 signature over the payload using `credentials`.
    /// 3. Decode CBOR payload into `Manifest`.
    ///
    /// Any failure at any step returns `Err(ManifestInvalid { detail })`.
    ///
    /// # Errors
    /// Returns `Err(ManifestInvalid)` if the wire format is too short, the signature is
    /// invalid, or the CBOR payload is malformed.
    pub fn decode<H: HsmProvider>(
        bytes: &[u8],
        credentials: &BootCredentials<H>,
    ) -> Result<Manifest> {
        if bytes.len() < MIN_WIRE_LEN {
            return Err(Error::ManifestInvalid {
                detail: "wire format too short (minimum 65 bytes)",
            });
        }

        let (sig_slice, payload) = bytes.split_at(SIG_LEN);
        let sig_bytes: &[u8; 64] = sig_slice.try_into().map_err(|_| Error::ManifestInvalid {
            detail: "signature slice extraction failed",
        })?;

        // Verify BEFORE parsing — fail-closed on bad signature.
        credentials.verify(payload, sig_bytes)?;

        Self::parse_cbor(payload)
    }

    fn parse_cbor(payload: &[u8]) -> Result<Manifest> {
        let mut d = Decoder::new(payload);

        // Outer: definite array of exactly 3 elements.
        let outer_len = d.array().map_err(|_| Error::ManifestInvalid {
            detail: "payload is not a CBOR array",
        })?;
        if outer_len != Some(3) {
            return Err(Error::ManifestInvalid {
                detail: "expected 3-element array [version, edges, quotas]",
            });
        }

        // Element 0: version.
        let version = d.u32().map_err(|_| Error::ManifestInvalid {
            detail: "version is not a uint32",
        })?;

        // Element 1: edges.
        let edges = Self::parse_edges(&mut d)?;

        // Element 2: quotas.
        let quotas = Self::parse_quotas(&mut d)?;

        Ok(Manifest {
            edges,
            quotas,
            version,
        })
    }

    fn parse_edges(
        d: &mut Decoder<'_>,
    ) -> Result<heapless::Vec<EdgeDecl, { crate::types::MAX_EDGES }>> {
        let len = d
            .array()
            .map_err(|_| Error::ManifestInvalid {
                detail: "edges is not a CBOR array",
            })?
            .ok_or(Error::ManifestInvalid {
                detail: "edges array must have definite length",
            })?;

        if len > crate::types::MAX_EDGES as u64 {
            return Err(Error::ManifestInvalid {
                detail: "too many edges",
            });
        }

        let mut edges = heapless::Vec::new();
        for _ in 0..len {
            let edge_len = d.array().map_err(|_| Error::ManifestInvalid {
                detail: "edge is not a CBOR array",
            })?;
            if edge_len != Some(2) {
                return Err(Error::ManifestInvalid {
                    detail: "each edge must be [src, dst]",
                });
            }

            let src_raw = d.u32().map_err(|_| Error::ManifestInvalid {
                detail: "edge src is not uint32",
            })?;
            let dst_raw = d.u32().map_err(|_| Error::ManifestInvalid {
                detail: "edge dst is not uint32",
            })?;

            let src = NonZeroU32::new(src_raw).ok_or(Error::ManifestInvalid {
                detail: "edge src must be non-zero",
            })?;
            let dst = NonZeroU32::new(dst_raw).ok_or(Error::ManifestInvalid {
                detail: "edge dst must be non-zero",
            })?;

            edges
                .push(EdgeDecl { src, dst })
                .map_err(|_| Error::ManifestInvalid {
                    detail: "edge list capacity exceeded",
                })?;
        }

        Ok(edges)
    }

    fn parse_quotas(
        d: &mut Decoder<'_>,
    ) -> Result<heapless::Vec<QuotaDecl, { crate::types::MAX_NODES }>> {
        let len = d
            .array()
            .map_err(|_| Error::ManifestInvalid {
                detail: "quotas is not a CBOR array",
            })?
            .ok_or(Error::ManifestInvalid {
                detail: "quotas array must have definite length",
            })?;

        if len > crate::types::MAX_NODES as u64 {
            return Err(Error::ManifestInvalid {
                detail: "too many quota entries",
            });
        }

        let mut quotas = heapless::Vec::new();
        for _ in 0..len {
            let q_len = d.array().map_err(|_| Error::ManifestInvalid {
                detail: "quota entry is not a CBOR array",
            })?;
            if q_len != Some(2) {
                return Err(Error::ManifestInvalid {
                    detail: "each quota must be [node, ceiling]",
                });
            }

            let node_raw = d.u32().map_err(|_| Error::ManifestInvalid {
                detail: "quota node is not uint32",
            })?;
            let ceiling_raw = d.u64().map_err(|_| Error::ManifestInvalid {
                detail: "quota ceiling is not uint64",
            })?;

            let node = NonZeroU32::new(node_raw).ok_or(Error::ManifestInvalid {
                detail: "quota node must be non-zero",
            })?;

            quotas
                .push(QuotaDecl {
                    node,
                    ceiling: Quota::new(ceiling_raw),
                })
                .map_err(|_| Error::ManifestInvalid {
                    detail: "quota list capacity exceeded",
                })?;
        }

        Ok(quotas)
    }
}
