//! Security tests: core invariant enforcement.
//!
//! Each test corresponds to exactly one kernel security invariant.
//! These tests must pass at 100%.  A failure here is a P0 security regression.

use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    error::Error,
    metabolism::ledger::Ledger,
    metabolism::quota::QuotaEnforcer,
    types::{Generation, Quota},
};
use core::num::NonZeroU32;

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

// Invariant 1: Fail-Closed — missing capability must deny.
#[test]
fn inv1_no_capability_no_access() {
    let mut policy = Policy::new(Generation(0));
    let cap = Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::empty(),
        Generation(0),
        10,
    );
    assert_eq!(
        policy.check(&cap, CapabilitySet::SCHEDULE),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        }),
        "Invariant 1 violated: empty rights must be denied"
    );
}

// Invariant 2: Capability-Gated — delegation cannot amplify.
#[test]
fn inv2_delegation_never_amplifies() {
    let cap = Capability::new_for_test(
        node(10),
        node(11),
        CapabilitySet::READ_TOPOLOGY | CapabilitySet::DELEGATE,
        Generation(0),
        11,
    );
    let all = CapabilitySet::all();
    let result = cap.delegate(node(12), all, 2);
    assert!(result.is_none(), "Invariant 2 violated: delegation amplified rights");
}

// Invariant 3: Accountable Resources — over-quota must hard-reject.
#[test]
fn inv3_quota_overflow_is_rejected() {
    let mut ledger = Ledger::default();
    ledger.seed(node(1), Quota::new(100));
    let enforcer = QuotaEnforcer;
    let result = enforcer.deduct(&mut ledger, node(1), 200, "compute");
    assert_eq!(
        result,
        Err(Error::QuotaExceeded { resource: "compute" }),
        "Invariant 3 violated: over-quota deduction was permitted"
    );
}

// Invariant 3: Accountable Resources — balance is unchanged after rejection.
#[test]
fn inv3_ledger_unchanged_after_failed_deduction() {
    let mut ledger = Ledger::default();
    ledger.seed(node(1), Quota::new(50));
    let enforcer = QuotaEnforcer;
    let _ = enforcer.deduct(&mut ledger, node(1), 999, "memory");
    assert_eq!(
        ledger.balance(node(1)),
        Some(50),
        "Invariant 3: ledger must be unchanged after failed deduction"
    );
}
