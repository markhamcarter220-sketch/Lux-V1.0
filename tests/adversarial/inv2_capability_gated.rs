//! Adversarial tests — Invariant 2: Capability-Gated.
//!
//! 12 attack vectors proving that no operation proceeds without a valid,
//! scoped, generation-bounded token.

use core::num::NonZeroU32;
use lux_kernel::audit::AuditLog;
use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    error::Error,
    metabolism::ledger::Ledger,
    types::{Generation, Quota, NONCE_WINDOW},
};

fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

const ALL_RIGHTS: [CapabilitySet; 5] = [
    CapabilitySet::READ_TOPOLOGY,
    CapabilitySet::ALLOC_RESOURCE,
    CapabilitySet::SCHEDULE,
    CapabilitySet::DELEGATE,
    CapabilitySet::SHUTDOWN,
];

// ── Attack 2.1 ────────────────────────────────────────────────────────────────
// Wrong right requested: cap grants READ_TOPOLOGY; requesting SCHEDULE → denied.

#[test]
fn attack_2_1_wrong_right_is_denied() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::READ_TOPOLOGY, gen, 1);
    assert!(matches!(
        policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied { .. })
    ));
}

// ── Attack 2.2 ────────────────────────────────────────────────────────────────
// Each right is independently enforced — holding right X grants only right X.
// authorises() is a pure predicate tested across all right × other-right pairs.

#[test]
fn attack_2_2_each_right_independently_enforced_no_cross_contamination() {
    let gen = Generation(0);

    for &held in &ALL_RIGHTS {
        let cap = Capability::new_for_test(nz(1), nz(2), held, gen, 0);
        // The held right itself is granted.
        assert!(
            cap.authorises(held, gen),
            "cap must authorise its own right {held:?}"
        );
        // Every OTHER right is denied.
        for &other in ALL_RIGHTS.iter().filter(|&&r| r != held) {
            assert!(
                !cap.authorises(other, gen),
                "holding {held:?} must not grant {other:?}"
            );
        }
    }
}

// ── Attack 2.3 ────────────────────────────────────────────────────────────────
// Out-of-scope operation: capability scoped to READ; write-equivalent (SCHEDULE) denied.

#[test]
fn attack_2_3_out_of_scope_operation_denied() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    let read_cap = Capability::new_for_test(
        nz(1),
        nz(2),
        CapabilitySet::READ_TOPOLOGY | CapabilitySet::ALLOC_RESOURCE,
        gen,
        10,
    );
    // SCHEDULE and SHUTDOWN are outside the granted scope.
    assert!(policy
        .check(&read_cap, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_err());
    // (Note: failed check doesn't consume nonce, so same nonce can be re-tested.)
    let cap2 = Capability::new_for_test(
        nz(1),
        nz(2),
        CapabilitySet::READ_TOPOLOGY | CapabilitySet::ALLOC_RESOURCE,
        gen,
        11,
    );
    assert!(policy
        .check(&cap2, CapabilitySet::SHUTDOWN, &mut AuditLog::new())
        .is_err());
}

// ── Attack 2.4 ────────────────────────────────────────────────────────────────
// Delegation without DELEGATE right: every non-delegate-holding cap must return None.

#[test]
fn attack_2_4_delegation_requires_delegate_right() {
    let gen = Generation(0);

    for (i, &right) in ALL_RIGHTS
        .iter()
        .filter(|&&r| r != CapabilitySet::DELEGATE)
        .enumerate()
    {
        let cap = Capability::new_for_test(nz(1), nz(2), right, gen, i as u64);
        assert!(
            cap.delegate(nz(3), right, 999).is_none(),
            "cap without DELEGATE must not delegate, right={right:?}"
        );
    }
}

// ── Attack 2.5 ────────────────────────────────────────────────────────────────
// Privilege escalation via delegation: delegated token cannot exceed parent rights.
// Algebraically enforced by bitwise subset check in delegate().

#[test]
fn attack_2_5_delegation_cannot_escalate_privileges() {
    let gen = Generation(0);
    let parent = CapabilitySet::READ_TOPOLOGY | CapabilitySet::DELEGATE;
    let cap = Capability::new_for_test(nz(1), nz(2), parent, gen, 1);

    // Attempt to delegate the full capability set — must fail.
    assert!(cap.delegate(nz(3), CapabilitySet::all(), 2).is_none());

    // Each right not in parent individually blocked.
    for right in [
        CapabilitySet::ALLOC_RESOURCE,
        CapabilitySet::SCHEDULE,
        CapabilitySet::SHUTDOWN,
    ] {
        assert!(
            cap.delegate(nz(3), right, 3).is_none(),
            "delegating {right:?} not held by parent must be None"
        );
    }

    // A strict subset (READ_TOPOLOGY only) succeeds and produces no escalation.
    let delegated = cap
        .delegate(nz(3), CapabilitySet::READ_TOPOLOGY, 4)
        .expect("strict subset delegation must succeed");
    // The delegated token must not have acquired DELEGATE or any other right.
    assert!(!delegated.authorises(CapabilitySet::DELEGATE, gen));
    assert!(!delegated.authorises(CapabilitySet::SCHEDULE, gen));
    assert!(!delegated.authorises(CapabilitySet::SHUTDOWN, gen));
}

// ── Attack 2.6 ────────────────────────────────────────────────────────────────
// Expired-generation cap denied by policy after multiple rotations.

#[test]
fn attack_2_6_expired_generation_denied_after_multiple_rotations() {
    let mut policy = Policy::new(Generation(0));
    policy.rotate_generation(); // gen 1
    policy.rotate_generation(); // gen 2

    // Cap at gen 0: 0 < 2, so generation check fails.
    let stale0 = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, Generation(0), 42);
    assert!(matches!(
        policy.check(&stale0, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation"
        })
    ));

    // Cap at gen 1: also stale.
    let stale1 = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, Generation(1), 43);
    assert!(policy
        .check(&stale1, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_err());

    // Cap at gen 2 (current): valid.
    let current =
        Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, Generation(2), 44);
    assert!(policy
        .check(&current, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());
}

// ── Attack 2.7 ────────────────────────────────────────────────────────────────
// Unforgeable generation stamp: a cap created before rotation is useless after it.
// Production path: kernel only issues caps at the current generation.

#[test]
fn attack_2_7_pre_rotation_capability_is_invalid_post_rotation() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // "Forge" by stamping gen 0 — valid only during gen 0.
    let pre_rotation_cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SHUTDOWN, gen, 77);

    // At gen 0 it works.
    let demo = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SHUTDOWN, gen, 78);
    assert!(policy
        .check(&demo, CapabilitySet::SHUTDOWN, &mut AuditLog::new())
        .is_ok());

    // After rotation, the "forged" gen-0 cap is invalid.
    policy.rotate_generation();
    assert!(
        policy
            .check(
                &pre_rotation_cap,
                CapabilitySet::SHUTDOWN,
                &mut AuditLog::new()
            )
            .is_err(),
        "gen-0 cap must be denied after rotation"
    );
}

// ── Attack 2.8 ────────────────────────────────────────────────────────────────
// Nonce replay: same nonce can be used at most once per generation.
// After rotation, the nonce is usable again (fresh generation, clean window).

#[test]
fn attack_2_8_same_nonce_can_only_be_used_once_per_generation() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let nonce = 12345u64;

    let cap1 = Capability::new_for_test(nz(1), nz(2), CapabilitySet::ALLOC_RESOURCE, gen, nonce);
    assert!(policy
        .check(&cap1, CapabilitySet::ALLOC_RESOURCE, &mut AuditLog::new())
        .is_ok());

    let cap2 = Capability::new_for_test(nz(1), nz(2), CapabilitySet::ALLOC_RESOURCE, gen, nonce);
    assert!(matches!(
        policy.check(&cap2, CapabilitySet::ALLOC_RESOURCE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "nonce replayed"
        })
    ));

    // After rotation, same nonce valid again.
    policy.rotate_generation();
    let new_gen = policy.generation();
    let cap3 =
        Capability::new_for_test(nz(1), nz(2), CapabilitySet::ALLOC_RESOURCE, new_gen, nonce);
    assert!(policy
        .check(&cap3, CapabilitySet::ALLOC_RESOURCE, &mut AuditLog::new())
        .is_ok());
}

// ── Attack 2.9 ────────────────────────────────────────────────────────────────
// Zero-balance deduction: even 1 unit denied when balance is 0 or node unseeded.

#[test]
fn attack_2_9_zero_balance_denies_any_deduction() {
    let mut ledger = Ledger::new();
    let n = nz(10);
    ledger.seed(n, Quota::new(0)).expect("test node count within MAX_NODES");

    assert!(
        ledger.deduct(n, 1).is_none(),
        "deduct 1 from zero-balance must fail"
    );
    assert_eq!(ledger.balance(n), Some(0), "balance must remain 0");

    // Unseeded node.
    let unseeded = nz(11);
    assert!(
        ledger.deduct(unseeded, 1).is_none(),
        "deduct from unseeded node must fail"
    );
    assert_eq!(
        ledger.balance(unseeded),
        None,
        "unseeded node has no balance"
    );
}

// ── Attack 2.10 ───────────────────────────────────────────────────────────────
// No ambient authority: capability must be an explicit parameter.
// Empty-rights cap denied for every right — no default-permit path exists.

#[test]
fn attack_2_10_no_ambient_authority_path_exists() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // The only way to call check() is to provide a Capability.
    // An empty-rights cap is the minimum possible token and must be denied.
    for (i, &right) in ALL_RIGHTS.iter().enumerate() {
        let cap =
            Capability::new_for_test(nz(1), nz(2), CapabilitySet::empty(), gen, 500 + i as u64);
        assert!(
            policy.check(&cap, right, &mut AuditLog::new()).is_err(),
            "no ambient grant: empty cap must be denied for {right:?}"
        );
    }
}

// ── Attack 2.11 ───────────────────────────────────────────────────────────────
// Delegation chain: subset invariant preserved across multiple hops.
// root → A (READ | DELEGATE) → B (READ only) → B cannot redelegate.

#[test]
fn attack_2_11_delegation_chain_preserves_subset_invariant() {
    let gen = Generation(0);

    let root = Capability::new_for_test(nz(1), nz(2), CapabilitySet::all(), gen, 1);

    // A gets READ_TOPOLOGY | DELEGATE.
    let a_rights = CapabilitySet::READ_TOPOLOGY | CapabilitySet::DELEGATE;
    let cap_a = root
        .delegate(nz(3), a_rights, 2)
        .expect("subset delegation must succeed");

    // B gets READ_TOPOLOGY only.
    let cap_b = cap_a
        .delegate(nz(4), CapabilitySet::READ_TOPOLOGY, 3)
        .expect("strict subset must succeed");

    // B cannot redelegate (no DELEGATE right).
    assert!(cap_b
        .delegate(nz(5), CapabilitySet::READ_TOPOLOGY, 4)
        .is_none());

    // B definitely cannot escalate to rights above the chain.
    assert!(cap_b.delegate(nz(5), CapabilitySet::SHUTDOWN, 5).is_none());
    assert!(cap_b.delegate(nz(5), CapabilitySet::all(), 6).is_none());

    // cap_b holds exactly READ_TOPOLOGY — nothing else.
    assert!(cap_b.authorises(CapabilitySet::READ_TOPOLOGY, gen));
    assert!(!cap_b.authorises(CapabilitySet::SCHEDULE, gen));
    assert!(!cap_b.authorises(CapabilitySet::DELEGATE, gen));
    assert!(!cap_b.authorises(CapabilitySet::SHUTDOWN, gen));
}

// ── Attack 2.12 ───────────────────────────────────────────────────────────────
// Nonce-window exhaustion fails closed: the 257th operation is denied even
// with a fresh, previously-unused nonce.

#[test]
fn attack_2_12_nonce_window_exhaustion_fails_closed() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Fill all NONCE_WINDOW (256) slots.
    for i in 0u64..NONCE_WINDOW as u64 {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, i);
        assert!(
            policy
                .check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new())
                .is_ok(),
            "slot {i} must succeed"
        );
    }

    // 257th attempt with a brand-new nonce — window is full.
    let overflow = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, 99_999);
    assert!(matches!(
        policy.check(&overflow, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied {
            reason: "nonce window exhausted; rotate generation"
        })
    ));
}
