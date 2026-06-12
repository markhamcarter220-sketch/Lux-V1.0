//! Adversarial tests — Invariant 1: Fail-Closed.
//!
//! 10 attack vectors proving that ambiguity and error states produce DENIAL,
//! never ACCESS.  Every test asserts an Err or a failed authorisation.

use core::num::NonZeroU32;
use ed25519_dalek::{Signer, SigningKey};
use lux_kernel::audit::{AuditLog, EventKind};
use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    boot::{BootCredentials, ManifestDecoder},
    error::Error,
    metabolism::{ledger::Ledger, quota::QuotaEnforcer},
    topology::{BootingGraph, OperationalGraph},
    types::{Generation, Quota, MAX_AUDIT_EVENTS},
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

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn signed_wire(payload: &[u8], sk: &SigningKey) -> Vec<u8> {
    let sig = sk.sign(payload);
    let mut w = sig.to_bytes().to_vec();
    w.extend_from_slice(payload);
    w
}

fn minimal_cbor_payload() -> Vec<u8> {
    vec![0x83, 0x01, 0x80, 0x80] // CBOR [1, [], []]
}

// ── Attack 1.1 ────────────────────────────────────────────────────────────────
// Empty-rights capability denied for every possible right.
// Zero bits set → authorises() must return false for any right requested.

#[test]
fn attack_1_1_empty_rights_capability_denied_for_all_rights() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    for (i, &right) in ALL_RIGHTS.iter().enumerate() {
        let cap =
            Capability::new_for_test(nz(1), nz(2), CapabilitySet::empty(), gen, 100 + i as u64);
        // Empty rights fail at step 1 (authorises); nonce is never consumed.
        assert!(
            policy.check(&cap, right, &mut AuditLog::new()).is_err(),
            "empty-rights cap must be denied for {right:?}"
        );
    }
}

// ── Attack 1.2 ────────────────────────────────────────────────────────────────
// Stale-generation capability denied for every right.
// cap.generation < policy.current_generation → authorises() returns false.

#[test]
fn attack_1_2_stale_generation_denied_for_all_rights() {
    let old_gen = Generation(0);
    let current_gen = Generation(3);
    let mut policy = Policy::new(current_gen);

    for (i, &right) in ALL_RIGHTS.iter().enumerate() {
        let cap = Capability::new_for_test(nz(1), nz(2), right, old_gen, 200 + i as u64);
        assert!(
            policy.check(&cap, right, &mut AuditLog::new()).is_err(),
            "stale-gen cap (gen 0 at policy gen 3) must be denied for {right:?}"
        );
    }
}

// ── Attack 1.3 ────────────────────────────────────────────────────────────────
// Full rights but stale generation still denied.
// No right is powerful enough to bypass the generation check.

#[test]
fn attack_1_3_full_rights_stale_generation_still_denied() {
    let mut policy = Policy::new(Generation(10));
    let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::all(), Generation(9), 42);

    assert!(matches!(
        policy.check(&cap, CapabilitySet::SHUTDOWN, &mut AuditLog::new()),
        Err(Error::CapabilityDenied { .. })
    ));
}

// ── Attack 1.4 ────────────────────────────────────────────────────────────────
// Corrupt manifest signature (single-bit flip) rejected at load time.
// Any bit mutation in the 64-byte Ed25519 prefix must invalidate the manifest.

#[test]
fn attack_1_4_single_bit_flip_in_signature_is_denied() {
    let sk = test_key();
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();
    let payload = minimal_cbor_payload();
    let mut wire = signed_wire(&payload, &sk);

    // Flip 8 different bits across the signature region.
    for byte_idx in [0usize, 7, 15, 23, 31, 39, 47, 63] {
        let mut corrupted = wire.clone();
        corrupted[byte_idx] ^= 0x01;
        assert!(
            ManifestDecoder::decode(&corrupted, &creds).is_err(),
            "bit flip at sig byte {byte_idx} must be denied"
        );
    }

    // Original wire is still valid.
    let last_idx = wire.len() - 1;
    wire[last_idx] ^= 0x01; // flip a payload byte instead
    assert!(
        ManifestDecoder::decode(&wire, &creds).is_err(),
        "payload flip must be denied"
    );
}

// ── Attack 1.5 ────────────────────────────────────────────────────────────────
// Temporal expiry modelled via generation rotation.
// Caps issued at gen N are permanently invalid after policy advances to gen N+1.

#[test]
fn attack_1_5_stale_generation_acts_as_temporal_expiry() {
    let gen0 = Generation(0);
    let mut policy = Policy::new(gen0);

    // Caps at gen 0 are valid now.
    let valid = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen0, 1);
    assert!(policy
        .check(&valid, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());

    // Rotate — gen 0 caps are now "expired".
    policy.rotate_generation();
    let gen1 = policy.generation();

    let expired = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen0, 99);
    assert!(
        policy
            .check(&expired, CapabilitySet::SCHEDULE, &mut AuditLog::new())
            .is_err(),
        "gen-0 cap must be expired after rotation to gen 1"
    );

    // Gen 1 caps are valid.
    let current = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen1, 100);
    assert!(policy
        .check(&current, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());

    // Rotate again — gen 1 caps also expire.
    policy.rotate_generation();
    let gen1_expired = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen1, 200);
    assert!(policy
        .check(&gen1_expired, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_err());
}

// ── Attack 1.6 ────────────────────────────────────────────────────────────────
// Revoked capability stays denied throughout the same generation.
// Ten repeated attempts — all denied.

#[test]
fn attack_1_6_revoked_capability_stays_denied_persistently() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let nonce = 0xCAFE_BABE_u64;

    policy.revoke_capability(nonce);

    for i in 0..10u64 {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce);
        assert!(
            matches!(
                policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
                Err(Error::CapabilityDenied {
                    reason: "capability revoked"
                })
            ),
            "attempt {i}: revoked cap must be denied"
        );
    }
}

// ── Attack 1.7 ────────────────────────────────────────────────────────────────
// Deny-wins: revocation takes precedence over all rights.
// A full-rights token is still denied if its nonce is revoked.

#[test]
fn attack_1_7_revocation_takes_priority_over_full_rights() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let nonce = 999u64;

    // Revoke before any use.
    policy.revoke_capability(nonce);

    // Full rights cannot overcome revocation.
    for (i, &right) in ALL_RIGHTS.iter().enumerate() {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::all(), gen, nonce);
        assert!(
            policy.check(&cap, right, &mut AuditLog::new()).is_err(),
            "full-rights revoked cap must be denied for {right:?} (attempt {i})"
        );
    }
}

// ── Attack 1.8 ────────────────────────────────────────────────────────────────
// Over-quota deduction is atomic: balance must be unchanged on failure.
// No partial grants; no silent truncation.

#[test]
fn attack_1_8_over_quota_deduction_is_atomic() {
    let mut ledger = Ledger::new();
    let n = nz(5);
    ledger.seed(n, Quota::new(50)).expect("test node count within MAX_NODES");

    assert_eq!(ledger.balance(n), Some(50));

    // Deduct more than available — must fail atomically.
    assert!(
        ledger.deduct(n, 100).is_none(),
        "deduct 100 from 50 must fail"
    );
    assert_eq!(
        ledger.balance(n),
        Some(50),
        "balance must be unchanged after failed deduction"
    );

    // 1 over limit.
    assert!(ledger.deduct(n, 51).is_none());
    assert_eq!(ledger.balance(n), Some(50));

    // u64::MAX — must not wrap.
    assert!(ledger.deduct(n, u64::MAX).is_none());
    assert_eq!(ledger.balance(n), Some(50));
}

// ── Attack 1.9 ────────────────────────────────────────────────────────────────
// No panic on any error path.
// Every boundary condition, invalid input, and error state returns Err; never panics.

#[test]
fn attack_1_9_error_paths_never_panic() {
    // Topology: out-of-range and inactive nodes.
    let op = BootingGraph::new().seal();
    let _ = op.traverse(nz(1), nz(65), &mut AuditLog::new());
    let _ = op.traverse(nz(65), nz(1), &mut AuditLog::new());
    let _ = op.traverse(nz(1), nz(1), &mut AuditLog::new());
    let _ = op.traverse(nz(u32::MAX), nz(1), &mut AuditLog::new());

    // Ledger: unseeded node, zero balance, u64::MAX deduction.
    let mut ledger = Ledger::new();
    let _ = ledger.balance(nz(99));
    let _ = ledger.deduct(nz(99), 1);
    ledger.seed(nz(1), Quota::new(0)).expect("test node count within MAX_NODES");
    let _ = ledger.deduct(nz(1), u64::MAX);

    // Policy: exhausted generation, empty rights.
    let mut policy = Policy::new(Generation(u64::MAX));
    let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::empty(), Generation(0), 1);
    let _ = policy.check(&cap, CapabilitySet::SHUTDOWN, &mut AuditLog::new());

    // Manifest: too short, all-zeros, garbage.
    let creds = BootCredentials::from_key_bytes([1u8; 32]).unwrap();
    let _ = ManifestDecoder::decode(&[], &creds);
    let _ = ManifestDecoder::decode(&[0u8; 32], &creds);
    let _ = ManifestDecoder::decode(&[0xffu8; 200], &creds);

    // All completed without panic — this line is the assertion.
}

// ── Attack 1.10 ───────────────────────────────────────────────────────────────
// Sequential consistency: check + revoke sequence is deterministic.
// Used nonces stay consumed; revoked nonces stay revoked; no state inversion.

#[test]
fn attack_1_10_check_revoke_sequence_is_consistent() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let nonce_a = 1000u64;
    let nonce_b = 2000u64;

    // Use nonce_a successfully.
    let cap_a = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce_a);
    assert!(policy
        .check(&cap_a, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_ok());

    // Revoke nonce_b, then attempt use.
    policy.revoke_capability(nonce_b);
    let cap_b = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce_b);
    assert!(policy
        .check(&cap_b, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_err());

    // nonce_a replay denied (already consumed in nonce window).
    let cap_a2 = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce_a);
    assert!(policy
        .check(&cap_a2, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_err());

    // nonce_b repeated attempt also denied (still revoked).
    let cap_b2_retry =
        Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce_b);
    assert!(policy
        .check(&cap_b2_retry, CapabilitySet::SCHEDULE, &mut AuditLog::new())
        .is_err());
}

// ── Attack 1.11 ───────────────────────────────────────────────────────────────
// Audit-full on policy gate: an otherwise-permitted capability check is denied
// when the audit log is saturated.
//
// Masking-regression: a pre-existing CapabilityDenied must NOT be replaced by
// AuditFull — the original denial reason is preserved.

fn saturated_audit() -> AuditLog {
    let mut audit = AuditLog::new();
    for i in 0..MAX_AUDIT_EVENTS as u64 {
        let appended = audit.append(EventKind::CapabilityCheck, 0, i, None);
        assert!(appended, "pre-saturation append must succeed at seq {i}");
    }
    // Confirm full.
    assert!(
        !audit.append(EventKind::CapabilityCheck, 0, 0, None),
        "log must be full after MAX_AUDIT_EVENTS appends"
    );
    audit
}

#[test]
fn attack_1_11_policy_check_denied_when_audit_full() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let mut audit = saturated_audit();

    // Otherwise-valid capability → must be denied because it cannot be logged.
    let valid_cap =
        Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, 0xA001);
    assert_eq!(
        policy.check(&valid_cap, CapabilitySet::SCHEDULE, &mut audit),
        Err(Error::AuditFull),
        "valid cap must be denied (not silently permitted) when audit is full"
    );

    // Masking-regression: an INVALID capability (wrong generation) presented to
    // the saturated gate must return the original CapabilityDenied, NOT AuditFull.
    // This proves the constraint: pre-existing denials are never overwritten.
    let invalid_cap =
        Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, Generation(99), 0xA002);
    assert_eq!(
        policy.check(&invalid_cap, CapabilitySet::SCHEDULE, &mut audit),
        Err(Error::CapabilityDenied {
            reason: "token expired, insufficient rights, or wrong generation",
        }),
        "pre-existing denial reason must not be masked by AuditFull"
    );
}

// ── Attack 1.12 ───────────────────────────────────────────────────────────────
// Audit-full on topology gate: an otherwise-permitted traversal is denied when
// the audit log is saturated.

fn single_edge_graph(src: u32, dst: u32) -> OperationalGraph {
    let mut g = BootingGraph::new();
    g.activate(nz(src)).unwrap();
    g.activate(nz(dst)).unwrap();
    g.permit_edge(nz(src), nz(dst)).unwrap();
    g.seal()
}

#[test]
fn attack_1_12_topology_traverse_denied_when_audit_full() {
    let graph = single_edge_graph(1, 2);
    let mut audit = saturated_audit();

    assert_eq!(
        graph.traverse(nz(1), nz(2), &mut audit),
        Err(Error::AuditFull),
        "permitted traversal must be denied when audit is full"
    );
}

// ── Attack 1.13 ───────────────────────────────────────────────────────────────
// Audit-full on quota gate: an otherwise-successful deduction is denied when
// the audit log is saturated.

#[test]
fn attack_1_13_quota_deduct_denied_when_audit_full() {
    let mut ledger = Ledger::new();
    let node = nz(3);
    ledger
        .seed(node, Quota::new(1_000))
        .expect("single node within MAX_NODES");

    let enforcer = QuotaEnforcer;
    let mut audit = saturated_audit();

    assert_eq!(
        enforcer.deduct(&mut ledger, node, 1, "compute", &mut audit),
        Err(Error::AuditFull),
        "permitted deduction must be denied when audit is full"
    );

    // Balance must be unchanged — the operation was refused, not partially applied.
    assert_eq!(
        ledger.balance(node),
        Some(1_000),
        "balance must be unchanged after AuditFull denial"
    );
}
