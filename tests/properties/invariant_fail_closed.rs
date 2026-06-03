//! Property tests — Invariant 1: Fail-Closed.
//!
//! ∀ capability with insufficient rights, `Policy::check` returns `Err`.
//! ∀ expired-generation capability, `Policy::check` returns `Err`.
//! ∀ revoked capability nonce, `Policy::check` returns `Err`.

use lux_kernel::{
    auth::{capability::{Capability, CapabilitySet}, policy::Policy},
    types::Generation,
};
use core::num::NonZeroU32;
use proptest::prelude::*;

fn node(n: u32) -> NonZeroU32 { NonZeroU32::new(n.max(1)).unwrap() }

prop_compose! {
    fn arb_rights()(bits in 0u32..=0x1fu32) -> CapabilitySet {
        CapabilitySet::from_bits_truncate(bits)
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..Default::default() })]

    /// Any capability with empty rights must be denied for any non-empty required right.
    #[test]
    fn empty_rights_always_denied(
        required_bits in 1u32..=0x1fu32,
        nonce in 0u64..=u64::MAX,
    ) {
        let gen = Generation(0);
        let mut policy = Policy::new(gen);
        let cap = Capability::new_for_test(
            node(1), node(2),
            CapabilitySet::empty(),
            gen, nonce,
        );
        let required = CapabilitySet::from_bits_truncate(required_bits);
        if !required.is_empty() {
            prop_assert!(policy.check(&cap, required).is_err(),
                "empty rights must always be denied");
        }
    }

    /// If a capability lacks the required right, it must be denied regardless of other rights.
    #[test]
    fn insufficient_rights_always_denied(
        rights_bits    in 0u32..=0x1fu32,
        required_bits  in 1u32..=0x1fu32,
        nonce          in 0u64..=u64::MAX,
    ) {
        let rights   = CapabilitySet::from_bits_truncate(rights_bits);
        let required = CapabilitySet::from_bits_truncate(required_bits);

        if !rights.contains(required) && !required.is_empty() {
            let gen = Generation(0);
            let mut policy = Policy::new(gen);
            let cap = Capability::new_for_test(node(1), node(2), rights, gen, nonce);
            prop_assert!(policy.check(&cap, required).is_err(),
                "insufficient rights must be denied");
        }
    }

    /// Expired-generation tokens must always be denied.
    #[test]
    fn stale_generation_always_denied(
        current_gen in 1u64..=u64::MAX,
        nonce in 0u64..=u64::MAX,
    ) {
        let token_gen   = Generation(current_gen.saturating_sub(1));
        let policy_gen  = Generation(current_gen);
        let mut policy  = Policy::new(policy_gen);
        let cap = Capability::new_for_test(
            node(1), node(2),
            CapabilitySet::SCHEDULE,
            token_gen,
            nonce,
        );
        prop_assert!(policy.check(&cap, CapabilitySet::SCHEDULE).is_err(),
            "token from older generation must be denied");
    }

    /// Revoked tokens must be denied before nonce consumption.
    #[test]
    fn revoked_token_always_denied(nonce in 0u64..=u64::MAX) {
        let gen = Generation(0);
        let mut policy = Policy::new(gen);
        policy.revoke_capability(nonce);
        let cap = Capability::new_for_test(
            node(1), node(2),
            CapabilitySet::SCHEDULE | CapabilitySet::READ_TOPOLOGY,
            gen, nonce,
        );
        prop_assert!(policy.check(&cap, CapabilitySet::SCHEDULE).is_err(),
            "revoked token must always be denied");
    }
}
