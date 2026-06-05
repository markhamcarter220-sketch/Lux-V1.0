//! Integration tests: boot sequence and manifest validation.

use lux_kernel::{
    boot::{BootCredentials, BootState},
    hsm::{HsmProvider, SoftwareHsm},
    tpm::{NullTpm, SoftwareTpm, TpmProvider},
};
use ed25519_dalek::SigningKey;

fn dummy_creds() -> BootCredentials {
    let sk = SigningKey::from_bytes(&[0u8; 32]);
    BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap()
}

fn minimal_payload() -> Vec<u8> {
    vec![0x83, 0x01, 0x80, 0x80] // CBOR [1, [], []]
}

fn signed_wire(payload: &[u8], sk: &SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let sig = sk.sign(payload);
    let mut w = sig.to_bytes().to_vec();
    w.extend_from_slice(payload);
    w
}

#[test]
fn empty_manifest_is_rejected() {
    let creds = dummy_creds();
    let result = BootState::initialise(&[], &creds);
    assert!(result.is_err(), "zero-length manifest must be rejected");
}

#[test]
fn malformed_manifest_is_rejected() {
    let creds   = dummy_creds();
    let garbage = b"\xff\xfe\x00\x01bad data";
    let result  = BootState::initialise(garbage, &creds);
    assert!(result.is_err(), "malformed manifest must be rejected");
}

// ── Item 1: SoftwareHsm contract ─────────────────────────────────────────────

#[test]
fn software_hsm_verify_only_rejects_sign() {
    let sk    = SigningKey::from_bytes(&[0u8; 32]);
    let hsm   = SoftwareHsm::from_verifying_key(sk.verifying_key().to_bytes()).unwrap();
    assert!(hsm.sign(b"payload").is_err(), "verify-only SoftwareHsm must reject sign()");
}

#[test]
fn software_hsm_from_signing_key_can_sign_and_verify() {
    let hsm     = SoftwareHsm::from_signing_key([0u8; 32]);
    let payload = b"test payload";
    let sig     = hsm.sign(payload).expect("sign must succeed");
    assert!(hsm.verify(payload, &sig).is_ok(), "verify must accept self-signed payload");
}

#[test]
fn software_hsm_verify_rejects_wrong_key() {
    let hsm1 = SoftwareHsm::from_signing_key([0u8; 32]);
    let hsm2 = SoftwareHsm::from_signing_key([1u8; 32]);
    let sig  = hsm1.sign(b"msg").unwrap();
    assert!(hsm2.verify(b"msg", &sig).is_err(), "wrong key must reject signature");
}

#[test]
fn software_hsm_generate_seed_returns_32_bytes() {
    let hsm  = SoftwareHsm::from_signing_key([42u8; 32]);
    let seed = hsm.generate_capability_seed().expect("seed generation must succeed");
    assert_eq!(seed.len(), 32);
    // Deterministic: same key → same seed.
    let seed2 = hsm.generate_capability_seed().unwrap();
    assert_eq!(seed, seed2);
}

#[test]
fn boot_credentials_from_key_bytes_backward_compatible() {
    let sk    = SigningKey::from_bytes(&[0u8; 32]);
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();
    let key   = creds.key_bytes();
    assert_eq!(key, sk.verifying_key().to_bytes());
}

// ── Item 2: TPM attestation ───────────────────────────────────────────────────

#[test]
fn null_tpm_produces_all_zeros_quote() {
    let mut tpm = NullTpm;
    tpm.extend_pcr(0, b"data").unwrap();
    let quote = tpm.quote(0, &[0u8; 32]).unwrap();
    assert!(quote.is_null(), "NullTpm must produce an all-zeros quote");
}

#[test]
fn software_tpm_quote_is_non_null_and_manifest_bound() {
    let sk   = SigningKey::from_bytes(&[0u8; 32]);
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();

    let payload = minimal_payload();
    let wire    = signed_wire(&payload, &sk);

    let mut tpm  = SoftwareTpm::new();
    let state    = BootState::initialise_with_tpm(&wire, &creds, &mut tpm)
        .expect("valid manifest + SoftwareTpm must succeed");

    let quote = state.attestation_quote();
    assert!(!quote.is_null(), "SoftwareTpm must produce a non-null quote");

    // The first 32 bytes of the quote ARE the post-extension PCR value.
    // A second boot with identical manifest must produce the SAME first half.
    let mut tpm2   = SoftwareTpm::new();
    let state2     = BootState::initialise_with_tpm(&wire, &creds, &mut tpm2).unwrap();
    let quote2     = state2.attestation_quote();
    assert_eq!(
        &quote.as_bytes()[..32],
        &quote2.as_bytes()[..32],
        "identical manifest must produce identical PCR extension"
    );
}

#[test]
fn software_tpm_different_manifests_produce_different_quotes() {
    let sk    = SigningKey::from_bytes(&[0u8; 32]);
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();

    // Two valid manifests with different payloads.
    let p1 = minimal_payload();           // [1, [], []]
    let p2 = {
        // version=2 instead of 1
        let mut v = p1.clone();
        v[1] = 0x02;
        v
    };
    let w1 = signed_wire(&p1, &sk);
    let w2 = signed_wire(&p2, &sk);

    let mut t1 = SoftwareTpm::new();
    let s1 = BootState::initialise_with_tpm(&w1, &creds, &mut t1).unwrap();

    let mut t2 = SoftwareTpm::new();
    let s2 = BootState::initialise_with_tpm(&w2, &creds, &mut t2).unwrap();

    assert_ne!(
        s1.attestation_quote().as_bytes(),
        s2.attestation_quote().as_bytes(),
        "different manifests must produce different TPM quotes"
    );
}

#[test]
fn software_tpm_pcr_out_of_range_fails() {
    let mut tpm = SoftwareTpm::new();
    assert!(tpm.extend_pcr(24, b"data").is_err(), "PCR index 24 must be out of range");
    assert!(tpm.quote(24, &[0u8; 32]).is_err(),   "quote on PCR 24 must be out of range");
}
