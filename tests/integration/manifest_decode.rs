//! Integration tests: CBOR manifest decoder + Ed25519 signature verification.
//!
//! Tests are grouped into:
//!  - Valid manifests (5+): decoder must accept them.
//!  - Adversarial manifests (10+): decoder must reject every one.
//!
//! Test signing uses a deterministic key derived from a fixed 32-byte seed so
//! that tests are reproducible without `OsRng`.

use ed25519_dalek::{SigningKey, Signer};
use lux_kernel::boot::{BootCredentials, ManifestDecoder};
use lux_kernel::error::Error;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encode a manifest payload as CBOR [version, edges, quotas].
fn encode_payload(version: u32, edges: &[(u32, u32)], quotas: &[(u32, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();

    // outer array(3)
    buf.push(0x83);

    // version (uint)
    encode_uint(&mut buf, u64::from(version));

    // edges array
    encode_array_header(&mut buf, edges.len());
    for (src, dst) in edges {
        buf.push(0x82); // array(2)
        encode_uint(&mut buf, u64::from(*src));
        encode_uint(&mut buf, u64::from(*dst));
    }

    // quotas array
    encode_array_header(&mut buf, quotas.len());
    for (node, ceiling) in quotas {
        buf.push(0x82); // array(2)
        encode_uint(&mut buf, u64::from(*node));
        encode_uint(&mut buf, *ceiling);
    }

    buf
}

fn encode_array_header(buf: &mut Vec<u8>, n: usize) {
    if n < 24 {
        buf.push(0x80 | n as u8);
    } else {
        buf.push(0x98);
        buf.push(n as u8);
    }
}

fn encode_uint(buf: &mut Vec<u8>, v: u64) {
    if v < 24 {
        buf.push(v as u8);
    } else if v < 256 {
        buf.push(0x18);
        buf.push(v as u8);
    } else if v < 65536 {
        buf.push(0x19);
        buf.push((v >> 8) as u8);
        buf.push(v as u8);
    } else if v < 0x1_0000_0000 {
        buf.push(0x1a);
        buf.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        buf.push(0x1b);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

/// Sign a payload and prepend the 64-byte signature → wire bytes.
fn make_wire(payload: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let sig = signing_key.sign(payload);
    let mut wire = sig.to_bytes().to_vec();
    wire.extend_from_slice(payload);
    wire
}

/// A deterministic test key pair (seed = all-zeros).
fn test_key() -> (SigningKey, BootCredentials) {
    let sk = SigningKey::from_bytes(&[0u8; 32]);
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();
    (sk, creds)
}

/// A second test key (seed = all-ones).
fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

// ── Valid manifests ───────────────────────────────────────────────────────────

#[test]
fn valid_minimal_manifest_empty_edges_and_quotas() {
    let (sk, creds) = test_key();
    let payload = encode_payload(1, &[], &[]);
    let wire    = make_wire(&payload, &sk);

    let m = ManifestDecoder::decode(&wire, &creds).unwrap();
    assert_eq!(m.version(), 1);
    assert!(m.permits_edge(
        core::num::NonZeroU32::new(1).unwrap(),
        core::num::NonZeroU32::new(2).unwrap()
    ) == false);
}

#[test]
fn valid_single_edge_single_quota() {
    let (sk, creds) = test_key();
    let payload = encode_payload(2, &[(1, 2)], &[(1, 1000)]);
    let wire    = make_wire(&payload, &sk);

    let m = ManifestDecoder::decode(&wire, &creds).unwrap();
    assert_eq!(m.version(), 2);
    let n1 = core::num::NonZeroU32::new(1).unwrap();
    let n2 = core::num::NonZeroU32::new(2).unwrap();
    assert!(m.permits_edge(n1, n2));
    assert_eq!(m.quota_for(n1).map(|q| q.get()), Some(1000));
}

#[test]
fn valid_multi_edge_multi_quota() {
    let (sk, creds) = test_key();
    let edges  = &[(1, 2), (1, 3), (2, 3)];
    let quotas = &[(1, 500), (2, 250), (3, 750)];
    let payload = encode_payload(3, edges, quotas);
    let wire    = make_wire(&payload, &sk);

    let m = ManifestDecoder::decode(&wire, &creds).unwrap();
    assert_eq!(m.version(), 3);
    let n1 = core::num::NonZeroU32::new(1).unwrap();
    let n3 = core::num::NonZeroU32::new(3).unwrap();
    assert!(m.permits_edge(n1, n3));
    assert_eq!(m.quota_for(n3).map(|q| q.get()), Some(750));
}

#[test]
fn valid_large_quota_u64_max() {
    let (sk, creds) = test_key();
    let payload = encode_payload(1, &[], &[(1, u64::MAX)]);
    let wire    = make_wire(&payload, &sk);

    let m = ManifestDecoder::decode(&wire, &creds).unwrap();
    let n1 = core::num::NonZeroU32::new(1).unwrap();
    assert_eq!(m.quota_for(n1).map(|q| q.get()), Some(u64::MAX));
}

#[test]
fn valid_version_zero_accepted() {
    let (sk, creds) = test_key();
    let payload = encode_payload(0, &[(1, 2)], &[]);
    let wire    = make_wire(&payload, &sk);

    assert!(ManifestDecoder::decode(&wire, &creds).is_ok());
}

// ── Adversarial manifests ─────────────────────────────────────────────────────

#[test]
fn adversarial_empty_bytes_rejected() {
    let (_, creds) = test_key();
    assert!(matches!(
        ManifestDecoder::decode(&[], &creds),
        Err(Error::ManifestInvalid { .. })
    ));
}

#[test]
fn adversarial_too_short_63_bytes_rejected() {
    let (_, creds) = test_key();
    let wire = vec![0u8; 63];
    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { .. })
    ));
}

#[test]
fn adversarial_valid_sig_garbage_payload_rejected() {
    let (sk, creds) = test_key();
    // Sign garbage so signature is valid over garbage
    let garbage_payload = [0xde, 0xad, 0xbe, 0xef];
    let wire = make_wire(&garbage_payload, &sk);

    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { .. })
    ));
}

#[test]
fn adversarial_wrong_signing_key_rejected() {
    let (_, creds) = test_key();
    let other_sk   = other_key();
    let payload    = encode_payload(1, &[(1, 2)], &[]);
    // Signed with `other_sk` but verified against `test_key` public key.
    let wire = make_wire(&payload, &other_sk);

    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { detail: "Ed25519 signature verification failed" })
    ));
}

#[test]
fn adversarial_tampered_payload_rejected() {
    let (sk, creds) = test_key();
    let payload     = encode_payload(1, &[(1, 2)], &[]);
    let mut wire    = make_wire(&payload, &sk);
    // Flip one bit in the payload.
    let last = wire.len() - 1;
    wire[last] ^= 0x01;

    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { .. })
    ));
}

#[test]
fn adversarial_truncated_after_signature_rejected() {
    let (sk, creds) = test_key();
    let payload     = encode_payload(1, &[(1, 2)], &[]);
    let wire        = make_wire(&payload, &sk);
    // Keep only the 64-byte signature, no payload.
    let truncated = &wire[..64];

    assert!(matches!(
        ManifestDecoder::decode(truncated, &creds),
        Err(Error::ManifestInvalid { .. })
    ));
}

#[test]
fn adversarial_zero_node_id_in_edge_rejected() {
    let (sk, creds) = test_key();
    // Manually encode edge [0, 1] — node 0 is invalid (NodeId = NonZeroU32).
    let mut payload = Vec::new();
    payload.push(0x83); // array(3)
    payload.push(0x01); // version = 1
    payload.push(0x81); // edges: array(1)
    payload.push(0x82); // edge: array(2)
    payload.push(0x00); // src = 0  ← invalid
    payload.push(0x01); // dst = 1
    payload.push(0x80); // quotas: array(0)

    let wire = make_wire(&payload, &sk);
    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { detail: "edge src must be non-zero" })
    ));
}

#[test]
fn adversarial_zero_node_id_in_quota_rejected() {
    let (sk, creds) = test_key();
    let mut payload = Vec::new();
    payload.push(0x83);
    payload.push(0x01); // version
    payload.push(0x80); // edges: empty
    payload.push(0x81); // quotas: array(1)
    payload.push(0x82);
    payload.push(0x00); // node = 0 ← invalid
    payload.push(0x0a); // ceiling = 10

    let wire = make_wire(&payload, &sk);
    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { detail: "quota node must be non-zero" })
    ));
}

#[test]
fn adversarial_wrong_outer_array_len_rejected() {
    let (sk, creds) = test_key();
    let mut payload = Vec::new();
    payload.push(0x82); // array(2) instead of array(3)
    payload.push(0x01);
    payload.push(0x80);

    let wire = make_wire(&payload, &sk);
    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid {
            detail: "expected 3-element array [version, edges, quotas]"
        })
    ));
}

#[test]
fn adversarial_edge_with_wrong_inner_len_rejected() {
    let (sk, creds) = test_key();
    let mut payload = Vec::new();
    payload.push(0x83);
    payload.push(0x01);
    payload.push(0x81); // 1 edge
    payload.push(0x83); // array(3) instead of array(2)
    payload.push(0x01);
    payload.push(0x02);
    payload.push(0x03);
    payload.push(0x80);

    let wire = make_wire(&payload, &sk);
    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { detail: "each edge must be [src, dst]" })
    ));
}

#[test]
fn adversarial_modified_signature_bytes_rejected() {
    let (sk, creds) = test_key();
    let payload     = encode_payload(1, &[(1, 2)], &[]);
    let mut wire    = make_wire(&payload, &sk);
    // Corrupt the 32nd byte of the signature.
    wire[31] ^= 0xff;

    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(Error::ManifestInvalid { .. })
    ));
}
