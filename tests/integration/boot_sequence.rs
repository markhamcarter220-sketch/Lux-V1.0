//! Integration tests: boot sequence and manifest validation.

use lux_kernel::boot::BootState;

#[test]
fn empty_manifest_is_rejected() {
    let result = BootState::initialise(&[]);
    assert!(result.is_err(), "zero-length manifest must be rejected");
}

#[test]
fn malformed_manifest_is_rejected() {
    let garbage = b"\xff\xfe\x00\x01bad data";
    let result = BootState::initialise(garbage);
    assert!(result.is_err(), "malformed manifest must be rejected");
}
