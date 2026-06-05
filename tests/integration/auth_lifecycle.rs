//! Integration tests: capability lifecycle — minting, delegation, rotation.

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
    NonZeroU32::new(n).expect("test node id must be non-zero")
}

#[test]
fn valid_capability_passes_policy_check() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let cap = Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, gen, 1);
    assert!(policy
        .check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());
}

#[test]
fn expired_generation_is_denied() {
    let mut policy = Policy::new(Generation(5));
    let cap = Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, Generation(3), 2);
    assert_eq!(
        policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        })
    );
}

#[test]
fn delegation_cannot_amplify_rights() {
    let gen = Generation(0);
    let cap = Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::SCHEDULE | CapabilitySet::DELEGATE,
        gen,
        3,
    );
    // Attempt to delegate ALLOC_RESOURCE which the token does not hold.
    let delegated = cap.delegate(node(3), CapabilitySet::ALLOC_RESOURCE, 42);
    assert!(
        delegated.is_none(),
        "privilege amplification must be blocked"
    );
}

#[test]
fn delegation_within_rights_succeeds() {
    let gen = Generation(0);
    let cap = Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::SCHEDULE | CapabilitySet::DELEGATE,
        gen,
        4,
    );
    let delegated = cap.delegate(node(3), CapabilitySet::SCHEDULE, 99);
    assert!(delegated.is_some());
    let delegated = delegated.unwrap();

    let mut policy = Policy::new(gen);
    assert!(policy
        .check(&delegated, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());
}
