//! Security tests: privilege escalation paths.
//!
//! Every test attempts a known escalation pattern and asserts it is denied.
//! New escalation vectors discovered in audit must have a regression test
//! added here before the fix lands.

use core::num::NonZeroU32;
use lux_kernel::audit::AuditLog;
use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    error::Error,
    types::Generation,
};

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

// Attempt: reuse a token after generation rotation.
#[test]
fn stale_token_after_rotation_is_denied() {
    let mut policy = Policy::new(Generation(0));
    let stale_cap =
        Capability::new_for_test(node(1), node(2), CapabilitySet::SHUTDOWN, Generation(0), 20);
    policy.rotate_generation();
    assert_eq!(
        policy.check(&stale_cap, CapabilitySet::SHUTDOWN, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        }),
        "Stale token must not survive generation rotation"
    );
}

// Attempt: delegate without holding the DELEGATE right.
#[test]
fn delegation_without_delegate_right_fails() {
    let cap = Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::SCHEDULE, // no DELEGATE
        Generation(0),
        21,
    );
    let result = cap.delegate(node(3), CapabilitySet::SCHEDULE, 0);
    assert!(
        result.is_none(),
        "Delegation without DELEGATE right must fail"
    );
}

// Attempt: nonce replay — present the same token a second time.
#[test]
fn nonce_replay_is_denied() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let cap = Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, gen, 42);

    assert!(
        policy
            .check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new())
            .is_ok(),
        "First presentation must succeed"
    );
    // Second check with the same nonce must fail — replay detected.
    assert_eq!(
        policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "nonce replayed"
        }),
        "Replay must be denied"
    );
}

// Attempt: future-generation token must be denied at the current epoch.
//
// A token minted with generation u64::MAX passes `>= current_gen` permanently,
// surviving every rotate_generation() call and defeating the kill switch.
// The fix changes authorises() to require exact equality (`==`), matching
// the TLA+ spec (IsValidCap: cap.gen = epoch).
#[test]
fn future_generation_token_is_denied() {
    let mut policy = Policy::new(Generation(0));
    let future_cap = Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::SHUTDOWN,
        Generation(u64::MAX), // forward-dated: should never be valid at epoch 0
        77,
    );

    // Must be denied at epoch 0 — future gen != current gen.
    assert_eq!(
        policy.check(&future_cap, CapabilitySet::SHUTDOWN, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        }),
        "Future-generation token must be denied at the current epoch"
    );

    // Rotate; token STILL denied — rotation cannot be exploited via
    // forward-dating even after the revocation ledger is cleared.
    policy.rotate_generation();
    assert_eq!(
        policy.check(&future_cap, CapabilitySet::SHUTDOWN, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        }),
        "Future-generation token must remain denied after rotation"
    );
}

// Attempt: nonce replay cleared after generation rotation.
#[test]
fn nonce_window_clears_on_rotation() {
    let mut policy = Policy::new(Generation(0));
    let cap0 =
        Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, Generation(0), 99);
    assert!(policy
        .check(&cap0, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());

    // Rotate; old cap0 is now stale (generation mismatch), but nonce 99
    // should be cleared — a new token with nonce 99 in gen 1 must succeed.
    policy.rotate_generation();
    let cap1 = Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::SCHEDULE,
        policy.generation(), // gen 1
        99,                  // same nonce, new generation — must be accepted
    );
    assert!(
        policy
            .check(&cap1, CapabilitySet::SCHEDULE, &mut AuditLog::new())
            .is_ok(),
        "Nonce 99 must be reusable in the new generation"
    );
}
