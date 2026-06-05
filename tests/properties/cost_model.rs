//! Property tests — Formal cost model (Tier 3, Item 3).
//!
//! These tests correspond to the TLA+ invariants in `tla/CostModel.tla`:
//!
//! - `ResourceConservation`: balance is always in `[0, initial_quota]`.
//! - `CostMonotonicity`:     deductions never increase the balance.
//! - Rejection atomicity:    a deduction that would underflow the balance is
//!   rejected and the balance is unchanged (no partial write).

use lux_kernel::{
    metabolism::{ledger::Ledger, quota::QuotaEnforcer},
    audit::AuditLog,
    types::Quota,
};
use core::num::NonZeroU32;
use proptest::prelude::*;

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..Default::default() })]

    /// ResourceConservation: after any sequence of valid deductions the
    /// balance is always in `[0, initial_quota]`.
    #[test]
    fn resource_conservation_balance_stays_in_range(
        initial_quota in 1u64..=1_000_000u64,
        deductions    in proptest::collection::vec(1u64..=10_000u64, 0..=200usize),
    ) {
        let enforcer = QuotaEnforcer;
        let mut ledger = Ledger::new();
        ledger.seed(node(1), Quota::new(initial_quota));

        for amount in deductions {
            // Each individual deduction may fail — that is correct behaviour.
            let _ = enforcer.deduct(&mut ledger, node(1), amount, "compute", &mut AuditLog::new());
        }

        let balance = ledger.balance(node(1)).unwrap_or(0);
        prop_assert!(balance <= initial_quota,
            "balance {balance} must not exceed initial quota {initial_quota}");
        // Rust's u64 prevents negative balances structurally, but let's be explicit.
        // (The ledger uses saturating arithmetic internally.)
    }

    /// CostMonotonicity: a successful deduction always reduces or preserves
    /// the balance; it never increases it.
    #[test]
    fn cost_monotonicity_deductions_never_increase_balance(
        initial_quota in 1u64..=1_000_000u64,
        amount        in 1u64..=1_000_000u64,
    ) {
        let enforcer = QuotaEnforcer;
        let mut ledger = Ledger::new();
        ledger.seed(node(1), Quota::new(initial_quota));

        let balance_before = ledger.balance(node(1)).unwrap();
        let _ = enforcer.deduct(&mut ledger, node(1), amount, "compute", &mut AuditLog::new());
        let balance_after = ledger.balance(node(1)).unwrap();

        prop_assert!(balance_after <= balance_before,
            "balance must not increase: before={balance_before}, after={balance_after}");
    }

    /// Rejection atomicity: a deduction that exceeds the balance is rejected,
    /// and the balance is left unchanged.
    #[test]
    fn over_quota_deduction_rejected_balance_unchanged(
        initial_quota in 1u64..=1_000_000u64,
    ) {
        let enforcer = QuotaEnforcer;
        let mut ledger = Ledger::new();
        ledger.seed(node(1), Quota::new(initial_quota));

        let balance_before = ledger.balance(node(1)).unwrap();
        // Request one more than available.
        let amount = initial_quota.saturating_add(1);
        let result = enforcer.deduct(&mut ledger, node(1), amount, "compute", &mut AuditLog::new());

        prop_assert!(result.is_err(), "over-quota deduction must be rejected");
        prop_assert_eq!(
            ledger.balance(node(1)).unwrap(),
            balance_before,
            "balance must be unchanged after rejected deduction"
        );
    }

    /// Sum bound: the total amount deducted never exceeds the initial quota.
    #[test]
    fn sum_of_deductions_never_exceeds_initial_quota(
        initial_quota in 1u64..=1_000_000u64,
        deductions    in proptest::collection::vec(1u64..=100_000u64, 0..=100usize),
    ) {
        let enforcer = QuotaEnforcer;
        let mut ledger = Ledger::new();
        ledger.seed(node(1), Quota::new(initial_quota));

        let mut total_deducted: u64 = 0;
        for amount in deductions {
            if enforcer.deduct(&mut ledger, node(1), amount, "compute", &mut AuditLog::new()).is_ok() {
                total_deducted = total_deducted.saturating_add(amount);
            }
        }

        prop_assert!(total_deducted <= initial_quota,
            "total deducted {total_deducted} must not exceed initial quota {initial_quota}");
        let remaining = ledger.balance(node(1)).unwrap_or(0);
        prop_assert_eq!(
            total_deducted + remaining,
            initial_quota,
            "deducted + remaining must equal initial quota"
        );
    }
}
