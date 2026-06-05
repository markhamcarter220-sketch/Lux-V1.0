//! Property tests — Invariant 3: Accountable Resources.
//!
//! ∀ amount > balance: deduction fails, balance unchanged.
//! ∀ amount ≤ balance: deduction succeeds, balance decremented exactly.
//! ∀ sequential deductions summing to ceiling: all succeed, remainder = 0.

use core::num::NonZeroU32;
use lux_kernel::audit::AuditLog;
use lux_kernel::{
    metabolism::{ledger::Ledger, quota::QuotaEnforcer},
    types::Quota,
};
use proptest::prelude::*;

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n.max(1)).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..Default::default() })]

    /// Over-quota deduction must return Err AND leave balance unchanged.
    #[test]
    fn over_quota_denied_and_balance_preserved(
        ceiling in 0u64..=u64::MAX / 2,
        excess  in 1u64..=u64::MAX / 2,
    ) {
        let amount = ceiling.saturating_add(excess);
        let mut ledger = Ledger::default();
        ledger.seed(node(1), Quota::new(ceiling));

        let enforcer = QuotaEnforcer;
        let result = enforcer.deduct(&mut ledger, node(1), amount, "compute", &mut AuditLog::new());

        prop_assert!(result.is_err(), "over-quota deduction must be denied");
        prop_assert_eq!(
            ledger.balance(node(1)),
            Some(ceiling),
            "balance must be unchanged after denied deduction"
        );
    }

    /// Within-quota deduction must succeed and decrement balance exactly.
    #[test]
    fn within_quota_succeeds_exact_decrement(
        ceiling in 0u64..=u64::MAX,
        amount  in 0u64..=u64::MAX,
    ) {
        if amount > ceiling { return Ok(()); } // skip over-quota cases

        let mut ledger = Ledger::default();
        ledger.seed(node(1), Quota::new(ceiling));

        let enforcer  = QuotaEnforcer;
        let result    = enforcer.deduct(&mut ledger, node(1), amount, "compute", &mut AuditLog::new());

        prop_assert!(result.is_ok(), "within-quota deduction must succeed");
        prop_assert_eq!(
            ledger.balance(node(1)),
            Some(ceiling - amount),
            "balance must be decremented by exactly amount"
        );
    }

    /// Sequential deductions must never permit more than the ceiling in aggregate.
    #[test]
    fn cumulative_deductions_never_exceed_ceiling(
        ceiling in 1u64..=1_000_000u64,
        a       in 0u64..=500_000u64,
        b       in 0u64..=500_000u64,
    ) {
        let mut ledger = Ledger::default();
        ledger.seed(node(1), Quota::new(ceiling));
        let enforcer = QuotaEnforcer;

        let r1 = enforcer.deduct(&mut ledger, node(1), a, "compute", &mut AuditLog::new());
        let r2 = enforcer.deduct(&mut ledger, node(1), b, "compute", &mut AuditLog::new());

        // If both succeed, total deducted must not exceed ceiling.
        if r1.is_ok() && r2.is_ok() {
            let total = a.saturating_add(b);
            prop_assert!(total <= ceiling,
                "cumulative deductions must not exceed ceiling");
        }
    }
}
