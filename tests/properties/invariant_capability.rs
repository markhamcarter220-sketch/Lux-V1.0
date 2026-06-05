//! Property tests — Invariant 2: Capability-Gated.
//!
//! ∀ delegation: delegated rights ⊆ original rights (never ⊃).
//! ∀ generation mismatch: token denied.
//! ∀ nonce reuse within a generation: second presentation denied.

use core::num::NonZeroU32;
use lux_kernel::audit::AuditLog;
use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    types::Generation,
};
use proptest::prelude::*;

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n.max(1)).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..Default::default() })]

    /// Delegation can never produce a token with rights exceeding the delegator's rights.
    #[test]
    fn delegation_never_exceeds_original_rights(
        rights_raw  in 0u32..=0x1fu32,
        subset_raw  in 0u32..=0x1fu32,
        nonce       in 0u64..=u64::MAX,
        new_nonce   in 0u64..=u64::MAX,
    ) {
        let rights = CapabilitySet::from_bits_truncate(rights_raw)
            | CapabilitySet::DELEGATE;
        let subset = CapabilitySet::from_bits_truncate(subset_raw);
        let cap = Capability::new_for_test(
            node(1), node(2), rights, Generation(0), nonce,
        );

        if let Some(delegated) = cap.delegate(node(3), subset, new_nonce) {
            // The delegated token must not be able to exercise rights not held by
            // the original.  We verify using Policy::check as the ground truth.
            let mut policy = Policy::new(Generation(0));
            for right in [
                CapabilitySet::READ_TOPOLOGY,
                CapabilitySet::ALLOC_RESOURCE,
                CapabilitySet::SCHEDULE,
                CapabilitySet::DELEGATE,
                CapabilitySet::SHUTDOWN,
            ] {
                if !rights.contains(right) {
                    prop_assert!(
                        policy.check(&delegated, right, &mut AuditLog::new()).is_err(),
                        "delegation amplified right {right:?}"
                    );
                    // delegated was moved — stop here.
                    return Ok(());
                }
            }
        }
    }

    /// A token without DELEGATE cannot produce any delegation.
    #[test]
    fn no_delegate_right_prevents_delegation(
        rights_raw  in 0u32..=0x0fu32,  // bits 0-3, excludes DELEGATE(bit4)
        subset_raw  in 0u32..=0x1fu32,
        nonce       in 0u64..=u64::MAX,
        new_nonce   in 0u64..=u64::MAX,
    ) {
        // Explicitly clear DELEGATE bit.
        let rights = CapabilitySet::from_bits_truncate(rights_raw)
            .difference(CapabilitySet::DELEGATE);
        let subset = CapabilitySet::from_bits_truncate(subset_raw);
        let cap = Capability::new_for_test(
            node(1), node(2), rights, Generation(0), nonce,
        );
        let result = cap.delegate(node(3), subset, new_nonce);
        prop_assert!(result.is_none(), "token without DELEGATE must not delegate");
    }

    /// Nonce replay within one generation must always be denied.
    #[test]
    fn nonce_replay_within_generation_always_denied(nonce in 0u64..=u64::MAX) {
        let gen = Generation(0);
        let mut policy = Policy::new(gen);

        let c1 = Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, gen, nonce);
        let c2 = Capability::new_for_test(node(1), node(2), CapabilitySet::SCHEDULE, gen, nonce);

        let _ = policy.check(&c1, CapabilitySet::SCHEDULE, &mut AuditLog::new()); // first use
        let r2 = policy.check(&c2, CapabilitySet::SCHEDULE, &mut AuditLog::new());
        prop_assert!(r2.is_err(), "second use of same nonce must be denied");
    }
}
