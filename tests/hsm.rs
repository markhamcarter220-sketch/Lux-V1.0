//! HSM integration tests — software key store and HSM-signed capability tests.
//!
//! Run with: cargo test --features hsm --test hsm

#![cfg(feature = "hsm")]

use std::num::NonZeroU32;

use lux_kernel::{
    auth::capability::{Capability, CapabilitySet},
    hsm::{
        mock::SoftwareHsm,
        pkcs11::Pkcs11HsmProvider,
        yubihsm::YubiHsmProvider,
        HsmProvider, HsmSignedCapability, KeyManagement, SoftwareKeyStore,
    },
    types::Generation,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn issuer() -> NonZeroU32 {
    NonZeroU32::new(1).unwrap()
}

fn target() -> NonZeroU32 {
    NonZeroU32::new(2).unwrap()
}

fn make_cap(nonce: u64) -> Capability {
    Capability::new_for_test(
        issuer(),
        target(),
        CapabilitySet::READ_TOPOLOGY | CapabilitySet::SCHEDULE,
        Generation(1),
        nonce,
    )
}

// ── Test 1: SoftwareHsm sign/verify roundtrip ─────────────────────────────────

#[test]
fn software_hsm_sign_verify_roundtrip() {
    let seed = [0x42u8; 32];
    let hsm = SoftwareHsm::from_signing_key(seed);
    let payload = b"test payload for sign verify";
    let sig = hsm.sign(payload).expect("sign should succeed");
    hsm.verify(payload, &sig).expect("verify should succeed");
}

// ── Test 2: verify-only SoftwareHsm rejects sign ─────────────────────────────

#[test]
fn software_hsm_verify_only_rejects_sign() {
    let seed = [0x42u8; 32];
    let full = SoftwareHsm::from_signing_key(seed);
    let vk_bytes = full.verifying_key_bytes();
    let verify_only = SoftwareHsm::from_verifying_key(vk_bytes).expect("valid verifying key");
    let err = verify_only.sign(b"payload").expect_err("sign should fail on verify-only");
    assert!(
        matches!(err, lux_kernel::Error::CapabilityDenied { .. }),
        "expected CapabilityDenied, got {err:?}"
    );
}

// ── Test 3: SoftwareHsm seed is deterministic ─────────────────────────────────

#[test]
fn software_hsm_generate_seed_is_deterministic() {
    let seed = [0x11u8; 32];
    let hsm = SoftwareHsm::from_signing_key(seed);
    let s1 = hsm.generate_capability_seed().expect("seed 1");
    let s2 = hsm.generate_capability_seed().expect("seed 2");
    assert_eq!(s1, s2, "SoftwareHsm seed must be deterministic");
}

// ── Test 4: SoftwareKeyStore seed is non-deterministic ───────────────────────

#[test]
fn key_store_generate_capability_seed_is_nondeterministic() {
    let store = SoftwareKeyStore::new();
    let s1 = store.generate_capability_seed().expect("seed 1");
    let s2 = store.generate_capability_seed().expect("seed 2");
    // Probabilistically true; collision would require an OS CSPRNG failure.
    assert_ne!(s1, s2, "SoftwareKeyStore seeds should differ across calls");
}

// ── Test 5: two generate_keypair calls produce different handles ──────────────

#[test]
fn key_store_generate_keypair_returns_unique_handles() {
    let store = SoftwareKeyStore::new();
    let h1 = store.generate_keypair().expect("keypair 1");
    let h2 = store.generate_keypair().expect("keypair 2");
    assert_ne!(h1, h2, "handles must be unique");
}

// ── Test 6: sign_capability + verify_capability_signature roundtrip ──────────

#[test]
fn key_store_sign_and_verify_capability() {
    let store = SoftwareKeyStore::new();
    let handle = store.generate_keypair().expect("generate keypair");
    let payload = b"capability signing payload";
    let sig = store.sign_capability(&handle, payload).expect("sign");
    store.verify_capability_signature(&handle, payload, &sig).expect("verify");
}

// ── Test 7: tampered payload fails verify ────────────────────────────────────

#[test]
fn key_store_verify_with_wrong_payload_fails() {
    let store = SoftwareKeyStore::new();
    let handle = store.generate_keypair().expect("generate keypair");
    let sig = store.sign_capability(&handle, b"original payload").expect("sign");
    let err = store
        .verify_capability_signature(&handle, b"tampered payload", &sig)
        .expect_err("verify with wrong payload should fail");
    assert!(
        matches!(err, lux_kernel::Error::ManifestInvalid { .. }),
        "expected ManifestInvalid, got {err:?}"
    );
}

// ── Test 8: corrupted signature bit fails verify ─────────────────────────────

#[test]
fn key_store_verify_with_corrupted_sig_fails() {
    let store = SoftwareKeyStore::new();
    let handle = store.generate_keypair().expect("generate keypair");
    let payload = b"important payload";
    let mut sig = store.sign_capability(&handle, payload).expect("sign");
    // Flip a bit in the signature.
    sig[0] ^= 0x01;
    let err = store
        .verify_capability_signature(&handle, payload, &sig)
        .expect_err("verify with corrupted sig should fail");
    assert!(
        matches!(err, lux_kernel::Error::ManifestInvalid { .. }),
        "expected ManifestInvalid, got {err:?}"
    );
}

// ── Test 9: list_keys includes newly-generated handle ────────────────────────

#[test]
fn key_store_list_keys_includes_generated() {
    let store = SoftwareKeyStore::new();
    let handle = store.generate_keypair().expect("generate keypair");
    let keys = store.list_keys().expect("list_keys");
    assert!(keys.contains(&handle), "list_keys should include newly-generated handle");
}

// ── Test 10: rotate_key returns a different handle ───────────────────────────

#[test]
fn key_store_rotate_key_returns_new_handle() {
    let store = SoftwareKeyStore::new();
    let old_handle = store.generate_keypair().expect("generate keypair");
    let new_handle = store.rotate_key(&old_handle).expect("rotate key");
    assert_ne!(old_handle, new_handle, "rotated handle should differ from old handle");
}

// ── Test 11: old handle invalid after rotation ───────────────────────────────

#[test]
fn key_store_old_handle_invalid_after_rotation() {
    let store = SoftwareKeyStore::new();
    let old_handle = store.generate_keypair().expect("generate keypair");
    let _new_handle = store.rotate_key(&old_handle).expect("rotate key");
    let err = store
        .sign_capability(&old_handle, b"payload")
        .expect_err("sign with old handle should fail after rotation");
    assert!(
        matches!(err, lux_kernel::Error::CapabilityDenied { .. }),
        "expected CapabilityDenied for old handle, got {err:?}"
    );
}

// ── Test 12: unknown handle sign fails ───────────────────────────────────────

#[test]
fn key_store_unknown_handle_sign_fails() {
    let store = SoftwareKeyStore::new();
    let fake_handle = lux_kernel::hsm::KeyHandle([0xffu8; 32]);
    let err = store
        .sign_capability(&fake_handle, b"payload")
        .expect_err("sign with unknown handle should fail");
    assert!(
        matches!(err, lux_kernel::Error::CapabilityDenied { .. }),
        "expected CapabilityDenied for unknown handle, got {err:?}"
    );
}

// ── Test 13: HsmSignedCapability sign + verify roundtrip ─────────────────────

#[test]
fn hsm_signed_capability_sign_verify_roundtrip() {
    let store = SoftwareKeyStore::new();
    let handle = store.generate_keypair().expect("generate keypair");
    let cap = make_cap(42);
    let signed = HsmSignedCapability::sign(cap, &handle, &store).expect("sign capability");
    signed.verify(&store).expect("verify capability");
}

// ── Test 14: tampered capability bytes rejected ───────────────────────────────

#[test]
fn hsm_signed_capability_tampered_payload_rejected() {
    let store = SoftwareKeyStore::new();
    let handle = store.generate_keypair().expect("generate keypair");
    let cap = make_cap(42);
    let mut signed = HsmSignedCapability::sign(cap, &handle, &store).expect("sign capability");
    // Corrupt one byte of the signature.
    signed.signature[0] ^= 0x01;
    let err = signed.verify(&store).expect_err("verify with tampered sig should fail");
    assert!(
        matches!(err, lux_kernel::Error::ManifestInvalid { .. }),
        "expected ManifestInvalid, got {err:?}"
    );
}

// ── Test 15: YubiHsmProvider stub returns error ───────────────────────────────

#[test]
fn yubihsm_stub_returns_error() {
    let provider = YubiHsmProvider::new_stub();

    assert!(provider.generate_capability_seed().is_err(), "seed should fail");
    assert!(provider.sign(b"test").is_err(), "sign should fail");
    assert!(provider.verify(b"test", &[0u8; 64]).is_err(), "verify should fail");
    assert!(provider.generate_keypair().is_err(), "generate_keypair should fail");
    let fake_handle = lux_kernel::hsm::KeyHandle([0u8; 32]);
    assert!(provider.sign_capability(&fake_handle, b"test").is_err(), "sign_capability should fail");
    assert!(
        provider.verify_capability_signature(&fake_handle, b"test", &[0u8; 64]).is_err(),
        "verify_capability_signature should fail"
    );
    assert!(provider.list_keys().is_err(), "list_keys should fail");
    assert!(provider.rotate_key(&fake_handle).is_err(), "rotate_key should fail");
}

// ── Test 16: Pkcs11HsmProvider stub returns error ────────────────────────────

#[test]
fn pkcs11_stub_returns_error() {
    let provider = Pkcs11HsmProvider::new_stub(None);

    assert!(provider.generate_capability_seed().is_err(), "seed should fail");
    assert!(provider.sign(b"test").is_err(), "sign should fail");
    assert!(provider.verify(b"test", &[0u8; 64]).is_err(), "verify should fail");
    assert!(provider.generate_keypair().is_err(), "generate_keypair should fail");
    let fake_handle = lux_kernel::hsm::KeyHandle([0u8; 32]);
    assert!(provider.sign_capability(&fake_handle, b"test").is_err(), "sign_capability should fail");
    assert!(
        provider.verify_capability_signature(&fake_handle, b"test", &[0u8; 64]).is_err(),
        "verify_capability_signature should fail"
    );
    assert!(provider.list_keys().is_err(), "list_keys should fail");
    assert!(provider.rotate_key(&fake_handle).is_err(), "rotate_key should fail");
}
