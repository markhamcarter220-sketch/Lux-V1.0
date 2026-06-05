//! Integration tests: capability revocation lifecycle.
//!
//! Verifies that:
//! - Revoking a live token causes immediate denial.
//! - Non-revoked tokens continue to work.
//! - Revocation survives nonce-rotation ordering.
//! - Generation rotation clears the revocation set.
//! - Revoked-then-rotated tokens with the same nonce are re-issuable.

use lux_kernel::{
    auth::{capability::{Capability, CapabilitySet}, policy::Policy},
    error::Error,
    types::Generation,
};
use lux_kernel::audit::AuditLog;
use core::num::NonZeroU32;

fn node(n: u32) -> NonZeroU32 { NonZeroU32::new(n).unwrap() }

fn cap(nonce: u64, gen: Generation) -> Capability {
    Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, gen, nonce)
}

// ── Core revocation lifecycle ─────────────────────────────────────────────────

#[test]
fn revoke_live_token_denies_immediately() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    policy.revoke_capability(100);

    let c = cap(100, gen);
    assert_eq!(
        policy.check(&c, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied { reason: "capability revoked" }),
        "revoked token must be denied"
    );
}

#[test]
fn non_revoked_token_is_permitted() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    policy.revoke_capability(100);

    // Different nonce — not revoked.
    let c = cap(200, gen);
    assert!(policy.check(&c, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok());
}

#[test]
fn revocation_checked_before_nonce_consumption() {
    // If a token is revoked, the revocation denial must come first,
    // before the nonce replay window is updated.
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Revoke before use.
    policy.revoke_capability(77);

    let c = cap(77, gen);
    // Check 1: must deny for revocation, NOT consume the nonce.
    let r1 = policy.check(&c, CapabilitySet::SCHEDULE, &mut AuditLog::new());
    assert_eq!(r1, Err(Error::CapabilityDenied { reason: "capability revoked" }));

    // Un-revoke (simulate by using rotation which clears revocation).
    policy.rotate_generation();
    // Now re-issue at gen 1 with the same nonce.
    let gen1 = policy.generation();
    let c2 = cap(77, gen1);
    assert!(policy.check(&c2, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok());
}

#[test]
fn generation_rotation_clears_revocation_set() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    policy.revoke_capability(42);
    assert!(policy.is_revoked(42));

    policy.rotate_generation();
    assert!(!policy.is_revoked(42), "rotation must clear revocations");
}

#[test]
fn revocation_does_not_affect_different_nonces() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Revoke nonces 1, 2, 3.
    policy.revoke_capability(1);
    policy.revoke_capability(2);
    policy.revoke_capability(3);

    // Nonces 4, 5, 6 must still work.
    for n in 4..=6u64 {
        let c = cap(n, gen);
        assert!(policy.check(&c, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok(), "nonce {n} should pass");
    }
}

#[test]
fn revoked_nonce_reusable_in_new_generation() {
    let mut policy = Policy::new(Generation(0));
    policy.revoke_capability(55);

    policy.rotate_generation();
    let gen1 = policy.generation();

    // Nonce 55 in gen 1 must be treated as fresh.
    let c = cap(55, gen1);
    assert!(policy.check(&c, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok());
}

#[test]
fn multiple_revocations_all_deny() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    for n in 0..20u64 {
        policy.revoke_capability(n);
    }
    for n in 0..20u64 {
        let c = cap(n, gen);
        assert!(
            policy.check(&c, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_err(),
            "nonce {n} should be denied"
        );
    }
}
