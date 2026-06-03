//! Integration tests: capability lifecycle — minting, delegation, rotation.

use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    error::Error,
    types::Generation,
};
use core::num::NonZeroU32;

fn node(n: u32) -> core::num::NonZeroU32 {
    NonZeroU32::new(n).expect("test node id must be non-zero")
}

#[test]
fn valid_capability_passes_policy_check() {
    let gen = Generation(0);
    let policy = Policy::new(gen);
    let cap = Capability {
        issuer:     node(1),
        target:     node(2),
        rights:     CapabilitySet::SCHEDULE,
        generation: gen,
        nonce:      0,
    };
    assert!(policy.check(&cap, CapabilitySet::SCHEDULE).is_ok());
}

#[test]
fn expired_generation_is_denied() {
    let policy = Policy::new(Generation(5));
    let cap = Capability {
        issuer:     node(1),
        target:     node(2),
        rights:     CapabilitySet::SCHEDULE,
        generation: Generation(3),
        nonce:      0,
    };
    assert_eq!(
        policy.check(&cap, CapabilitySet::SCHEDULE),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        })
    );
}

#[test]
fn delegation_cannot_amplify_rights() {
    let gen = Generation(0);
    let cap = Capability {
        issuer:     node(1),
        target:     node(2),
        rights:     CapabilitySet::SCHEDULE | CapabilitySet::DELEGATE,
        generation: gen,
        nonce:      0,
    };
    // Attempt to delegate ALLOC_RESOURCE which the token does not hold.
    let delegated = cap.delegate(node(3), CapabilitySet::ALLOC_RESOURCE, 42);
    assert!(delegated.is_none(), "privilege amplification must be blocked");
}

#[test]
fn delegation_within_rights_succeeds() {
    let gen = Generation(0);
    let cap = Capability {
        issuer:     node(1),
        target:     node(2),
        rights:     CapabilitySet::SCHEDULE | CapabilitySet::DELEGATE,
        generation: gen,
        nonce:      0,
    };
    let delegated = cap.delegate(node(3), CapabilitySet::SCHEDULE, 99);
    assert!(delegated.is_some());
    let delegated = delegated.unwrap();
    assert_eq!(delegated.rights, CapabilitySet::SCHEDULE);
    assert_eq!(delegated.target, node(3));
}
