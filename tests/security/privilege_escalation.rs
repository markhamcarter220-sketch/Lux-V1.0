//! Security tests: privilege escalation paths.
//!
//! These tests attempt known escalation patterns and assert that each is
//! denied.  Any new escalation vector discovered in audit must have a
//! corresponding regression test added here before the fix lands.

use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    error::Error,
    types::Generation,
};
use core::num::NonZeroU32;

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

// Attempt: reuse a token after generation rotation.
#[test]
fn stale_token_after_rotation_is_denied() {
    let mut policy = Policy::new(Generation(0));
    let stale_cap = Capability {
        issuer:     node(1),
        target:     node(2),
        rights:     CapabilitySet::SHUTDOWN,
        generation: Generation(0),
        nonce:      0,
    };
    policy.rotate_generation();
    assert_eq!(
        policy.check(&stale_cap, CapabilitySet::SHUTDOWN),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        }),
        "Stale token must not survive generation rotation"
    );
}

// Attempt: delegate without holding the DELEGATE right.
#[test]
fn delegation_without_delegate_right_fails() {
    let cap = Capability {
        issuer:     node(1),
        target:     node(2),
        rights:     CapabilitySet::SCHEDULE,   // no DELEGATE
        generation: Generation(0),
        nonce:      0,
    };
    let result = cap.delegate(node(3), CapabilitySet::SCHEDULE, 0);
    assert!(result.is_none(), "Delegation without DELEGATE right must fail");
}
