//! Adversarial tests — Part 5: Stress & Chaos.
//!
//! 10 attack vectors verifying Lux Kernel survives realistic load and
//! failure conditions: sustained operations, saturation, and recovery.

use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    audit::{AuditLog, EventKind},
    boot::{BootCredentials, BootState, ManifestDecoder},
    error::Error,
    metabolism::ledger::Ledger,
    types::{Generation, Quota, MAX_AUDIT_EVENTS, MAX_REVOCATIONS, NONCE_WINDOW},
};
use core::num::NonZeroU32;
use ed25519_dalek::{SigningKey, Signer};

fn nz(n: u32) -> NonZeroU32 { NonZeroU32::new(n).unwrap() }

fn test_key() -> SigningKey { SigningKey::from_bytes(&[0u8; 32]) }

fn minimal_cbor_payload() -> Vec<u8> {
    vec![0x83, 0x01, 0x80, 0x80] // CBOR [1, [], []]
}

fn signed_wire(payload: &[u8], sk: &SigningKey) -> Vec<u8> {
    let sig = sk.sign(payload);
    let mut w = sig.to_bytes().to_vec();
    w.extend_from_slice(payload);
    w
}

// ── Attack 5.1 ────────────────────────────────────────────────────────────────
// Sustained 10,000 mixed operations: capability checks and ledger deductions.
// No panic permitted; graceful denial after window/quota exhaustion.

#[test]
fn attack_5_1_sustained_10k_operations_no_panic() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);
    let mut ledger = Ledger::new();
    ledger.seed(nz(1), Quota::new(u64::MAX));

    for i in 0u64..10_000 {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, i);
        // After NONCE_WINDOW ops the policy denies — that is correct behaviour.
        let _ = policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new());
        let _ = ledger.deduct(nz(1), 1);
    }
    // Reaching this line proves no panic occurred.
}

// ── Attack 5.2 ────────────────────────────────────────────────────────────────
// Quota saturation: deduct until empty, then verify clean denial, no crash.

#[test]
fn attack_5_2_quota_saturation_produces_clean_denial() {
    let mut ledger = Ledger::new();
    ledger.seed(nz(1), Quota::new(10_000));

    // Drain in chunks of 100.
    loop {
        match ledger.deduct(nz(1), 100) {
            Some(0) | None => break,
            _ => {}
        }
    }

    assert_eq!(ledger.balance(nz(1)), Some(0));

    // Post-exhaustion: 100 consecutive denials, no panic.
    for _ in 0..100 {
        assert!(ledger.deduct(nz(1), 1).is_none(), "post-exhaustion deduction must fail");
    }
}

// ── Attack 5.3 ────────────────────────────────────────────────────────────────
// Nonce-window fill then rotate: rotation clears the window and restores capacity.

#[test]
fn attack_5_3_nonce_window_fill_then_rotate_recovers_capacity() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Fill all NONCE_WINDOW slots.
    for i in 0u64..NONCE_WINDOW as u64 {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, i);
        assert!(policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok(), "slot {i}");
    }

    // Window exhausted.
    let overflow = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, 99_999);
    assert!(matches!(
        policy.check(&overflow, CapabilitySet::SCHEDULE, &mut AuditLog::new()),
        Err(Error::CapabilityDenied { reason: "nonce window exhausted; rotate generation" })
    ));

    // Rotate — fresh window and fresh generation.
    policy.rotate_generation();
    let new_gen = policy.generation();
    assert_eq!(new_gen, Generation(1));

    // Nonce 0 is usable again.
    let fresh = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, new_gen, 0);
    assert!(policy.check(&fresh, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok());
}

// ── Attack 5.4 ────────────────────────────────────────────────────────────────
// Generation rotation clears all state atomically (revocations + nonce window).
// Old caps become stale-by-generation; new caps start clean.

#[test]
fn attack_5_4_rotation_clears_revocations_and_nonce_window_atomically() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Revoke some, use some.
    for nonce in [10u64, 20, 30] { policy.revoke_capability(nonce); }
    for nonce in [100u64, 200, 300] {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce);
        assert!(policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok());
    }
    assert!(policy.is_revoked(10));

    // Rotate.
    policy.rotate_generation();
    let new_gen = policy.generation();

    // Revocations cleared.
    assert!(!policy.is_revoked(10), "revocation must be cleared after rotation");

    // Old-gen cap stale.
    let stale = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, 999);
    assert!(policy.check(&stale, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_err());

    // New-gen cap with a previously-revoked nonce now works.
    let fresh = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, new_gen, 10);
    assert!(policy.check(&fresh, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_ok());
}

// ── Attack 5.5 ────────────────────────────────────────────────────────────────
// Partial-failure atomicity: failed boot leaves no partial state.
// A valid boot succeeds immediately after multiple failed attempts.

#[test]
fn attack_5_5_failed_boot_leaves_no_partial_state_recovery_succeeds() {
    let sk = test_key();
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();

    // Multiple bad manifests — each must fail cleanly.
    for bad in [
        vec![],
        vec![0xffu8; 64],
        vec![0u8; 63],                    // 1 byte short of minimum
        b"not cbor at all".to_vec(),
    ] {
        assert!(BootState::initialise(&bad, &creds).is_err(), "bad manifest must fail");
    }

    // Valid manifest succeeds after all failures.
    let payload = minimal_cbor_payload();
    let wire = signed_wire(&payload, &sk);
    assert!(BootState::initialise(&wire, &creds).is_ok(), "valid manifest must succeed");
}

// ── Attack 5.6 ────────────────────────────────────────────────────────────────
// Cascading quota exhaustion: node A exhaustion must not cascade to node B.

#[test]
fn attack_5_6_quota_exhaustion_does_not_cascade_to_peer_nodes() {
    let mut ledger = Ledger::new();
    ledger.seed(nz(1), Quota::new(10));
    ledger.seed(nz(2), Quota::new(10));

    // Exhaust node 1.
    for _ in 0..10 { assert!(ledger.deduct(nz(1), 1).is_some()); }
    assert!(ledger.deduct(nz(1), 1).is_none());

    // Node 2 completely isolated.
    assert_eq!(ledger.balance(nz(2)), Some(10));
    for _ in 0..10 { assert!(ledger.deduct(nz(2), 1).is_some()); }
    assert_eq!(ledger.balance(nz(2)), Some(0));
}

// ── Attack 5.7 ────────────────────────────────────────────────────────────────
// Revocation ledger at MAX_REVOCATIONS capacity: no panic; existing entries still denied.

#[test]
fn attack_5_7_revocation_ledger_at_max_capacity_no_panic() {
    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Fill revocation ledger.
    let mut filled = 0usize;
    for i in 0u64..MAX_REVOCATIONS as u64 {
        if policy.revoke_capability(i) { filled += 1; }
    }
    assert_eq!(filled, MAX_REVOCATIONS);

    // Extra revocation may or may not succeed (capacity-dependent) — must not panic.
    let _ = policy.revoke_capability(0xDEAD_BEEF);

    // All originally revoked nonces still denied.
    for nonce in 0u64..10 {
        let cap = Capability::new_for_test(nz(1), nz(2), CapabilitySet::SCHEDULE, gen, nonce);
        assert!(
            policy.check(&cap, CapabilitySet::SCHEDULE, &mut AuditLog::new()).is_err(),
            "revoked nonce {nonce} must remain denied"
        );
    }
}

// ── Attack 5.8 ────────────────────────────────────────────────────────────────
// Audit log at MAX_AUDIT_EVENTS capacity: overflow returns false (no overwrite),
// chain integrity preserved, no panic.

#[test]
fn attack_5_8_audit_log_at_capacity_no_overwrite_chain_intact() {
    let mut log = AuditLog::new();

    for i in 0..MAX_AUDIT_EVENTS {
        let ok = log.append(EventKind::CapabilityCheck, i as u32, 0, None);
        assert!(ok, "append {i} must succeed");
    }
    assert_eq!(log.len(), MAX_AUDIT_EVENTS);

    // Overflow: must return false, not panic.
    assert!(!log.append(EventKind::CapabilityRevoked, 9999, 0, Some((lux_kernel::audit::DenialClass::Halt, "revoked"))),
        "overflow append must return false");
    assert_eq!(log.len(), MAX_AUDIT_EVENTS, "length must not exceed capacity");

    // Chain must still be valid.
    assert!(log.verify_chain(), "hash chain must be valid at capacity");

    // Events preserved in insertion order.
    let events: Vec<_> = log.events().collect();
    assert_eq!(events[0].actor, 0);
    assert_eq!(events[MAX_AUDIT_EVENTS - 1].actor, (MAX_AUDIT_EVENTS - 1) as u32);
}

// ── Attack 5.9 ────────────────────────────────────────────────────────────────
// Byzantine forged signature: attacker signs with own key; kernel rejects it.

#[test]
fn attack_5_9_byzantine_forged_signature_rejected() {
    let honest_sk = test_key();
    let attacker_sk = SigningKey::from_bytes(&[99u8; 32]);
    let creds = BootCredentials::from_key_bytes(honest_sk.verifying_key().to_bytes()).unwrap();

    let payload = minimal_cbor_payload();
    let wire = signed_wire(&payload, &attacker_sk); // signed by attacker

    assert!(matches!(
        ManifestDecoder::decode(&wire, &creds),
        Err(lux_kernel::error::Error::ManifestInvalid {
            detail: "Ed25519 signature verification failed"
        })
    ));
}

// ── Attack 5.10 ───────────────────────────────────────────────────────────────
// Recovery from invalid manifest: subsequent valid boot succeeds.
// No lingering corruption from failed attempts.

#[test]
fn attack_5_10_kernel_recovers_from_repeated_failed_boots() {
    let sk = test_key();
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();

    // 5 distinct failure modes.
    let bad_manifests: &[&[u8]] = &[
        b"",
        b"\xff\xfe",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", // 64 zeros (too short by 1 byte)
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 65 bytes but garbage CBOR
        b"\x83\x01\x80\x80", // valid CBOR but no signature prefix
    ];
    for bad in bad_manifests {
        assert!(BootState::initialise(bad, &creds).is_err(), "bad manifest must fail: {bad:02x?}");
    }

    // Valid boot after all failures.
    let payload = minimal_cbor_payload();
    let wire = signed_wire(&payload, &sk);
    assert!(BootState::initialise(&wire, &creds).is_ok(), "valid boot must succeed after failures");
}
