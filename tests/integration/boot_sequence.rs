//! Integration tests: boot sequence and manifest validation.

use lux_kernel::boot::{BootCredentials, BootState};
use ed25519_dalek::SigningKey;

fn dummy_creds() -> BootCredentials {
    let sk = SigningKey::from_bytes(&[0u8; 32]);
    BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap()
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
