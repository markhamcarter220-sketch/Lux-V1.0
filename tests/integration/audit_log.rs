//! Integration tests: audit log integrity, hash chain, and export.

use lux_kernel::audit::{AuditLog, DenialClass, EventKind, Outcome};

// Shorthand helpers so test bodies stay readable.
fn permit(log: &mut AuditLog, kind: EventKind, actor: u32) -> bool {
    log.append(kind, actor, 0, None)
}

fn deny(log: &mut AuditLog, kind: EventKind, actor: u32, class: DenialClass, reason: &'static str) -> bool {
    log.append(kind, actor, 0, Some((class, reason)))
}

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
    assert!(permit(&mut log, EventKind::CapabilityCheck, 1));
    assert_eq!(log.len(), 1);
}

#[test]
fn events_returned_in_insertion_order() {
    let mut log = AuditLog::new();
    permit(&mut log, EventKind::CapabilityCheck,   1);
    deny(  &mut log, EventKind::TopologyTraverse,  2, DenialClass::Halt,    "undeclared edge");
    permit(&mut log, EventKind::ResourceDeduction, 3);

    let evs: Vec<_> = log.events().collect();
    assert_eq!(evs[0].kind, EventKind::CapabilityCheck);
    assert_eq!(evs[1].kind, EventKind::TopologyTraverse);
    assert_eq!(evs[2].kind, EventKind::ResourceDeduction);
}

#[test]
fn sequence_numbers_are_monotonically_increasing() {
    let mut log = AuditLog::new();
    for i in 0..10u64 {
        permit(&mut log, EventKind::CapabilityCheck, 1);
        let ev = log.events().last().unwrap();
        assert_eq!(ev.seq, i);
    }
}

// ── HALT / FAILURE classification ─────────────────────────────────────────────

#[test]
fn permitted_event_has_no_denial_fields() {
    let mut log = AuditLog::new();
    permit(&mut log, EventKind::CapabilityCheck, 1);
    let ev = log.events().next().unwrap();
    assert_eq!(ev.outcome,       Outcome::Permitted);
    assert_eq!(ev.denial_class,  None);
    assert_eq!(ev.denial_reason, None);
}

#[test]
fn halt_denial_fields_are_recorded() {
    let mut log = AuditLog::new();
    deny(&mut log, EventKind::CapabilityCheck, 1, DenialClass::Halt, "token expired");
    let ev = log.events().next().unwrap();
    assert_eq!(ev.outcome,                  Outcome::Denied);
    assert_eq!(ev.denial_class,             Some(DenialClass::Halt));
    assert_eq!(ev.denial_reason,            Some("token expired"));
}

#[test]
fn failure_denial_fields_are_recorded() {
    let mut log = AuditLog::new();
    deny(&mut log, EventKind::ResourceDeduction, 5, DenialClass::Failure, "quota exceeded: compute");
    let ev = log.events().next().unwrap();
    assert_eq!(ev.outcome,       Outcome::Denied);
    assert_eq!(ev.denial_class,  Some(DenialClass::Failure));
    assert_eq!(ev.denial_reason, Some("quota exceeded: compute"));
}

#[test]
fn halt_and_failure_produce_different_hashes() {
    let mut log_halt = AuditLog::new();
    deny(&mut log_halt, EventKind::CapabilityCheck, 1, DenialClass::Halt,    "reason");

    let mut log_fail = AuditLog::new();
    deny(&mut log_fail, EventKind::CapabilityCheck, 1, DenialClass::Failure, "reason");

    assert_ne!(
        log_halt.head_hash(), log_fail.head_hash(),
        "Halt and Failure classifications must produce distinct hashes"
    );
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
    permit(&mut log, EventKind::CapabilityCheck, 1);
    assert!(log.verify_chain());
}

#[test]
fn multi_event_chain_is_valid() {
    let mut log = AuditLog::new();
    for i in 0..20 {
        permit(&mut log, EventKind::CapabilityCheck, i);
    }
    assert!(log.verify_chain());
}

#[test]
fn mixed_permit_deny_chain_is_valid() {
    let mut log = AuditLog::new();
    permit(&mut log, EventKind::CapabilityCheck,   1);
    deny(  &mut log, EventKind::TopologyTraverse,  2, DenialClass::Halt,    "undeclared edge");
    deny(  &mut log, EventKind::ResourceDeduction, 3, DenialClass::Failure, "quota exceeded: mem");
    permit(&mut log, EventKind::CapabilityRevoked, 4);
    assert!(log.verify_chain());
}

#[test]
fn chain_detects_hash_field_mutation() {
    let mut log = AuditLog::new();
    permit(&mut log, EventKind::CapabilityCheck, 1);
    permit(&mut log, EventKind::CapabilityCheck, 2);
    let hash_after_2 = log.head_hash();

    let mut log2 = AuditLog::new();
    permit(&mut log2, EventKind::CapabilityCheck,  1);
    deny(  &mut log2, EventKind::TopologyTraverse, 2, DenialClass::Halt, "undeclared edge");
    let hash2_after_2 = log2.head_hash();

    assert_ne!(hash_after_2, hash2_after_2,
        "different events must produce different chain heads");
}

#[test]
fn different_outcomes_produce_different_hashes() {
    let mut log_a = AuditLog::new();
    permit(&mut log_a, EventKind::CapabilityCheck, 1);

    let mut log_b = AuditLog::new();
    deny(&mut log_b, EventKind::CapabilityCheck, 1, DenialClass::Halt, "any reason");

    assert_ne!(log_a.head_hash(), log_b.head_hash());
}

#[test]
fn different_actors_produce_different_hashes() {
    let mut log_a = AuditLog::new();
    permit(&mut log_a, EventKind::CapabilityCheck, 1);

    let mut log_b = AuditLog::new();
    permit(&mut log_b, EventKind::CapabilityCheck, 2);

    assert_ne!(log_a.head_hash(), log_b.head_hash());
}

#[test]
fn different_timestamps_produce_different_hashes() {
    let mut log_a = AuditLog::new();
    log_a.append(EventKind::CapabilityCheck, 1, 100, None);

    let mut log_b = AuditLog::new();
    log_b.append(EventKind::CapabilityCheck, 1, 200, None);

    assert_ne!(log_a.head_hash(), log_b.head_hash());
}

#[test]
fn different_reasons_produce_different_hashes() {
    let mut log_a = AuditLog::new();
    deny(&mut log_a, EventKind::CapabilityCheck, 1, DenialClass::Halt, "reason A");

    let mut log_b = AuditLog::new();
    deny(&mut log_b, EventKind::CapabilityCheck, 1, DenialClass::Halt, "reason B");

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
fn json_export_permitted_event_has_null_denial_fields() {
    let mut log = AuditLog::new();
    permit(&mut log, EventKind::CapabilityCheck, 3);
    let mut out = String::new();
    log.export_json(&mut out).unwrap();
    assert!(out.contains(r#""ok":true"#));
    assert!(out.contains(r#""class":null"#));
    assert!(out.contains(r#""reason":null"#));
}

#[test]
fn json_export_denied_halt_event_has_class_field() {
    let mut log = AuditLog::new();
    deny(&mut log, EventKind::TopologyTraverse, 7, DenialClass::Halt, "undeclared edge");
    let mut out = String::new();
    log.export_json(&mut out).unwrap();
    assert!(out.contains(r#""ok":false"#));
    assert!(out.contains(r#""class":"halt""#));
    assert!(out.contains(r#""reason":"undeclared edge""#));
}

#[test]
fn json_export_denied_failure_event_has_class_field() {
    let mut log = AuditLog::new();
    deny(&mut log, EventKind::ResourceDeduction, 9, DenialClass::Failure, "quota exceeded: io");
    let mut out = String::new();
    log.export_json(&mut out).unwrap();
    assert!(out.contains(r#""class":"failure""#));
    assert!(out.contains(r#""reason":"quota exceeded: io""#));
}

#[test]
fn json_export_contains_expected_fields() {
    let mut log = AuditLog::new();
    permit(&mut log, EventKind::CapabilityCheck, 3);
    deny(  &mut log, EventKind::TopologyTraverse, 7, DenialClass::Halt, "undeclared edge");

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
    let cap = lux_kernel::types::MAX_AUDIT_EVENTS;
    for _ in 0..cap {
        permit(&mut log, EventKind::CapabilityCheck, 1);
    }
    let result = permit(&mut log, EventKind::CapabilityCheck, 1);
    assert!(!result, "append to full log must return false");
    assert_eq!(log.len(), cap);
}

#[test]
fn chain_remains_valid_at_capacity() {
    let mut log = AuditLog::new();
    for _ in 0..lux_kernel::types::MAX_AUDIT_EVENTS {
        permit(&mut log, EventKind::CapabilityCheck, 1);
    }
    assert!(log.verify_chain());
}
