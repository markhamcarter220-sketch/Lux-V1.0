#![no_main]
use libfuzzer_sys::fuzz_target;
use lux_kernel::metabolism::ledger::Ledger;
use lux_kernel::types::Quota;
use std::num::NonZeroU32;

fuzz_target!(|data: &[u8; 16]| {
    let ceiling = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let deduction = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let node = NonZeroU32::new(1).unwrap();
    let mut ledger = Ledger::new();
    ledger.seed(node, Quota::new(ceiling));

    match ledger.deduct(node, deduction) {
        Some(new_balance) => {
            // deduction must have been <= ceiling
            assert!(
                deduction <= ceiling,
                "deduct returned Some but deduction > ceiling"
            );
            // balance must be exactly ceiling - deduction
            assert_eq!(
                new_balance,
                ceiling - deduction,
                "balance mismatch after deduct"
            );
        }
        None => {
            // deduction > ceiling (or node unknown) — no state changed
        }
    }
});
