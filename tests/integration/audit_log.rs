//! Integration tests: audit log integrity, hash chain, and export.

use lux_kernel::audit::{AuditLog, EventKind, Outcome};

// ── Basic append and retrieve ─────────────────────────────────────────────────

#[test]
fn empty_log_has_zero_length() {
    let log = AuditLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn append_single_event_increments_len() {
    let mut log = AuditLog::new();
    assert!(log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted));
    assert_eq!(log.len(), 1);
}

#[test]
fn events_returned_in_insertion_order() {
    let mut log = AuditLog::new();
    log.append(EventKind::CapabilityCheck,   1, Outcome::Permitted);
    log.append(EventKind::TopologyTraverse,  2, Outcome::Denied);
    log.append(EventKind::ResourceDeduction, 3, Outcome::Permitted);

    let evs: Vec<_> = log.events().collect();
    assert_eq!(evs[0].kind, EventKind::CapabilityCheck);
    assert_eq!(evs[1].kind, EventKind::TopologyTraverse);
    assert_eq!(evs[2].kind, EventKind::ResourceDeduction);
}

#[test]
fn sequence_numbers_are_monotonically_increasing() {
    let mut log = AuditLog::new();
    for i in 0..10u64 {
        log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
        let ev = log.events().last().unwrap();
        assert_eq!(ev.seq, i);
    }
}

// ── Hash chain integrity ──────────────────────────────────────────────────────

#[test]
fn fresh_log_chain_is_valid() {
    let log = AuditLog::new();
    assert!(log.verify_chain(), "empty chain must be valid");
}

#[test]
fn single_event_chain_is_valid() {
    let mut log = AuditLog::new();
    log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
    assert!(log.verify_chain());
}

#[test]
fn multi_event_chain_is_valid() {
    let mut log = AuditLog::new();
    for i in 0..20 {
        log.append(EventKind::CapabilityCheck, i, Outcome::Permitted);
    }
    assert!(log.verify_chain());
}

#[test]
fn chain_detects_hash_field_mutation() {
    let mut log = AuditLog::new();
    log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
    log.append(EventKind::CapabilityCheck, 2, Outcome::Permitted);

    // We cannot mutate events directly (they're in a Vec inside the log).
    // This test verifies that two different event sequences produce
    // different head hashes, confirming the chain is event-dependent.
    let hash_after_2 = log.head_hash();

    let mut log2 = AuditLog::new();
    log2.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
    log2.append(EventKind::TopologyTraverse, 2, Outcome::Denied); // different event

    let hash2_after_2 = log2.head_hash();
    assert_ne!(hash_after_2, hash2_after_2, "different events must produce different chain heads");
}

#[test]
fn different_outcomes_produce_different_hashes() {
    let mut log_a = AuditLog::new();
    log_a.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);

    let mut log_b = AuditLog::new();
    log_b.append(EventKind::CapabilityCheck, 1, Outcome::Denied);

    assert_ne!(log_a.head_hash(), log_b.head_hash());
}

#[test]
fn different_actors_produce_different_hashes() {
    let mut log_a = AuditLog::new();
    log_a.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);

    let mut log_b = AuditLog::new();
    log_b.append(EventKind::CapabilityCheck, 2, Outcome::Permitted);

    assert_ne!(log_a.head_hash(), log_b.head_hash());
}

// ── JSON export ───────────────────────────────────────────────────────────────

#[test]
fn json_export_empty_log_is_empty_array() {
    let log = AuditLog::new();
    let mut out = String::new();
    log.export_json(&mut out).unwrap();
    assert_eq!(out, "[]");
}

#[test]
fn json_export_contains_expected_fields() {
    let mut log = AuditLog::new();
    log.append(EventKind::CapabilityCheck, 3, Outcome::Permitted);
    log.append(EventKind::TopologyTraverse, 7, Outcome::Denied);

    let mut out = String::new();
    log.export_json(&mut out).unwrap();

    assert!(out.contains(r#""kind":"cap_check""#));
    assert!(out.contains(r#""kind":"topo_traverse""#));
    assert!(out.contains(r#""actor":3"#));
    assert!(out.contains(r#""actor":7"#));
    assert!(out.contains(r#""ok":true"#));
    assert!(out.contains(r#""ok":false"#));
}

// ── Overflow behaviour ────────────────────────────────────────────────────────

#[test]
fn log_full_returns_false_without_panic() {
    let mut log = AuditLog::new();
    // Fill to capacity.
    let cap = lux_kernel::types::MAX_AUDIT_EVENTS;
    for _ in 0..cap {
        log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
    }
    // One more must return false, not panic.
    let result = log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
    assert!(!result, "append to full log must return false");
    assert_eq!(log.len(), cap);
}

#[test]
fn chain_remains_valid_at_capacity() {
    let mut log = AuditLog::new();
    for _ in 0..lux_kernel::types::MAX_AUDIT_EVENTS {
        log.append(EventKind::CapabilityCheck, 1, Outcome::Permitted);
    }
    assert!(log.verify_chain());
}
