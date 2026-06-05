//! Adversarial tests — Invariant 3: Accountable Resources.
//!
//! 12 attack vectors proving that every allocation is charged and over-quota
//! requests are hard-rejected with no partial grants.

use core::num::NonZeroU32;
use lux_kernel::{
    metabolism::ledger::Ledger,
    types::{Quota, MAX_NODES},
};

fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

// ── Attack 3.1 ────────────────────────────────────────────────────────────────
// Over-quota hard reject: deduct more than balance → None, balance unchanged.

#[test]
fn attack_3_1_over_quota_hard_reject_balance_preserved() {
    let mut ledger = Ledger::new();
    let n = nz(1);
    ledger.seed(n, Quota::new(100));

    assert!(
        ledger.deduct(n, 101).is_none(),
        "deduct 101 from 100 must fail"
    );
    assert_eq!(
        ledger.balance(n),
        Some(100),
        "balance unchanged after reject"
    );

    assert!(
        ledger.deduct(n, u64::MAX).is_none(),
        "u64::MAX deduction must fail"
    );
    assert_eq!(ledger.balance(n), Some(100));

    // Exactly 100 succeeds.
    assert!(ledger.deduct(n, 100).is_some());
    assert_eq!(ledger.balance(n), Some(0));
}

// ── Attack 3.2 ────────────────────────────────────────────────────────────────
// Zero-cost deduction succeeds but does not provide a free resource path.
// Deducting 0 cannot be used to bypass quota tracking.

#[test]
fn attack_3_2_zero_deduction_does_not_drain_balance() {
    let mut ledger = Ledger::new();
    let n = nz(2);
    ledger.seed(n, Quota::new(50));

    // Deducting 0 is a no-op: 50 - 0 = 50. Returns Some(50).
    let result = ledger.deduct(n, 0);
    assert!(result.is_some());
    assert_eq!(
        ledger.balance(n),
        Some(50),
        "deduct 0 must not change balance"
    );
}

// ── Attack 3.3 ────────────────────────────────────────────────────────────────
// Sequential deductions exhaust to exactly zero — no wrap to u64::MAX.

#[test]
fn attack_3_3_sequential_deductions_exhaust_to_zero_no_wrap() {
    let mut ledger = Ledger::new();
    let n = nz(3);
    ledger.seed(n, Quota::new(100));

    for i in 0u64..10 {
        let result = ledger.deduct(n, 10);
        assert!(result.is_some(), "deduction {i} must succeed");
        let expected = 100 - (i + 1) * 10;
        assert_eq!(
            ledger.balance(n),
            Some(expected),
            "balance after deduction {i}"
        );
    }

    assert_eq!(ledger.balance(n), Some(0));

    // One more — must fail, not wrap.
    assert!(
        ledger.deduct(n, 1).is_none(),
        "post-exhaustion deduction must fail"
    );
    assert_eq!(
        ledger.balance(n),
        Some(0),
        "balance must stay 0, not wrap to u64::MAX"
    );
}

// ── Attack 3.4 ────────────────────────────────────────────────────────────────
// Double-charge scenario: same cost charged twice — second charge rejected.

#[test]
fn attack_3_4_double_charge_second_is_rejected() {
    let mut ledger = Ledger::new();
    let n = nz(4);
    ledger.seed(n, Quota::new(100));

    // First charge of 60 succeeds.
    assert!(ledger.deduct(n, 60).is_some());
    assert_eq!(ledger.balance(n), Some(40));

    // Second charge of 60 fails (only 40 remain).
    assert!(
        ledger.deduct(n, 60).is_none(),
        "second deduction of same amount must fail"
    );
    assert_eq!(
        ledger.balance(n),
        Some(40),
        "balance unchanged after failed double-charge"
    );
}

// ── Attack 3.5 ────────────────────────────────────────────────────────────────
// Sequential pressure simulating 10 concurrent actors, each requesting 15.
// Total requested = 150 > quota 100; at most 6 can succeed.

#[test]
fn attack_3_5_concurrent_pressure_cannot_exceed_quota() {
    let mut ledger = Ledger::new();
    let n = nz(5);
    ledger.seed(n, Quota::new(100));

    let mut successes = 0u32;
    let mut total_deducted = 0u64;

    for _ in 0..10 {
        if ledger.deduct(n, 15).is_some() {
            successes += 1;
            total_deducted += 15;
        }
    }

    assert!(
        successes <= 6,
        "at most 6 of 10 actors can deduct 15 (total ≤ 100)"
    );
    assert!(
        total_deducted <= 100,
        "total deducted must not exceed quota"
    );
    assert_eq!(ledger.balance(n), Some(100 - total_deducted));
}

// ── Attack 3.6 ────────────────────────────────────────────────────────────────
// Failed deduction is completely atomic: no bytes of state mutated on failure.

#[test]
fn attack_3_6_failed_deduction_is_completely_atomic() {
    let mut ledger = Ledger::new();
    let n = nz(6);
    ledger.seed(n, Quota::new(30));

    assert!(ledger.deduct(n, 10).is_some()); // 20 left
    assert!(ledger.deduct(n, 10).is_some()); // 10 left

    // 20 requested, only 10 available — must fail atomically.
    let fail = ledger.deduct(n, 20);
    assert!(fail.is_none());
    assert_eq!(
        ledger.balance(n),
        Some(10),
        "failed deduction must leave balance exactly 10"
    );
}

// ── Attack 3.7 ────────────────────────────────────────────────────────────────
// Integer-only arithmetic: no floating-point rounding can grant free resources.
// 10 deductions of 1 exhaust a balance of 10 — the 11th is denied.

#[test]
fn attack_3_7_integer_arithmetic_prevents_rounding_exploitation() {
    let mut ledger = Ledger::new();
    let n = nz(7);
    ledger.seed(n, Quota::new(10));

    for i in 0..10u64 {
        assert!(ledger.deduct(n, 1).is_some(), "deduction {i} must succeed");
    }
    assert_eq!(ledger.balance(n), Some(0));

    // 11th: no rounding grants a free unit.
    assert!(
        ledger.deduct(n, 1).is_none(),
        "11th deduction from 0 must fail"
    );
}

// ── Attack 3.8 ────────────────────────────────────────────────────────────────
// Quota is node-bound: exhausting node A does not transfer from node B.
// No lateral movement between quota pools.

#[test]
fn attack_3_8_quota_is_node_bound_no_lateral_transfer() {
    let mut ledger = Ledger::new();
    let a = nz(8);
    let b = nz(9);
    ledger.seed(a, Quota::new(100));
    // B is unseeded — it has no quota.

    assert!(ledger.deduct(a, 50).is_some());
    assert_eq!(ledger.balance(a), Some(50));

    // B has no balance regardless of A's state.
    assert_eq!(ledger.balance(b), None, "unseeded node has no balance");
    assert!(
        ledger.deduct(b, 1).is_none(),
        "deduct from unseeded node must fail"
    );

    // A's balance unaffected by B's failed deduction.
    assert_eq!(ledger.balance(a), Some(50));
}

// ── Attack 3.9 ────────────────────────────────────────────────────────────────
// u64 quota: no negative balance possible via overflow or wraparound.

#[test]
fn attack_3_9_no_negative_balance_possible() {
    let mut ledger = Ledger::new();
    let n = nz(10);
    ledger.seed(n, Quota::new(5));

    // Attempts that would produce negative balance — all rejected.
    assert!(ledger.deduct(n, 10).is_none());
    assert_eq!(ledger.balance(n), Some(5));

    assert!(ledger.deduct(n, u64::MAX).is_none());
    assert_eq!(ledger.balance(n), Some(5));

    assert!(ledger.deduct(n, u64::MAX - 4).is_none());
    assert_eq!(ledger.balance(n), Some(5));
}

// ── Attack 3.10 ───────────────────────────────────────────────────────────────
// Quota exhaustion under load: exactly 1000 of 1500 ops succeed; clean denial thereafter.

#[test]
fn attack_3_10_quota_exhaustion_under_sustained_load() {
    let mut ledger = Ledger::new();
    let n = nz(11);
    ledger.seed(n, Quota::new(1000));

    let mut succeeded = 0u32;
    let mut denied = 0u32;

    for _ in 0..1500 {
        match ledger.deduct(n, 1) {
            Some(_) => succeeded += 1,
            None => denied += 1,
        }
    }

    assert_eq!(succeeded, 1000, "exactly 1000 ops must succeed");
    assert_eq!(denied, 500, "exactly 500 ops must be cleanly denied");
    assert_eq!(ledger.balance(n), Some(0));
}

// ── Attack 3.11 ───────────────────────────────────────────────────────────────
// Quota isolation: exhausting node A does not propagate failure to node B.

#[test]
fn attack_3_11_quota_exhaustion_does_not_cascade_to_other_nodes() {
    let mut ledger = Ledger::new();
    let a = nz(12);
    let b = nz(13);
    ledger.seed(a, Quota::new(10));
    ledger.seed(b, Quota::new(100));

    // Exhaust A.
    for _ in 0..10 {
        assert!(ledger.deduct(a, 1).is_some());
    }
    assert_eq!(ledger.balance(a), Some(0));
    assert!(ledger.deduct(a, 1).is_none()); // A exhausted

    // B completely unaffected.
    assert_eq!(
        ledger.balance(b),
        Some(100),
        "B must not be affected by A's exhaustion"
    );
    assert!(ledger.deduct(b, 50).is_some());
}

// ── Attack 3.12 ───────────────────────────────────────────────────────────────
// Full-capacity ledger: all MAX_NODES nodes seeded; each independently correct.

#[test]
fn attack_3_12_full_ledger_capacity_all_nodes_independent() {
    let mut ledger = Ledger::new();

    for i in 1u32..=u32::try_from(MAX_NODES).expect("constant fits in u32") {
        let n = nz(i);
        ledger.seed(n, Quota::new(100));
    }

    // Every node can independently deduct.
    for i in 1u32..=u32::try_from(MAX_NODES).expect("constant fits in u32") {
        let n = nz(i);
        assert!(
            ledger.deduct(n, 50).is_some(),
            "node {i} must deduct successfully"
        );
        assert_eq!(ledger.balance(n), Some(50));
    }
}
