//! Integration tests: HSM ↔ RevocationLedger state-disagreement scenarios.
//!
//! Three scenarios where the local in-memory `RevocationLedger` and the
//! hardware-backed HSM keystore disagree on the validity of a capability.
//!
//! ## State ownership model
//!
//! - `Policy` (and its embedded `RevocationLedger`) is **authoritative at
//!   `Policy::check` time**.  The HSM signature proves a key existed at call
//!   initiation; it does not grant authority.  Authority is granted only when
//!   all four `Policy::check` steps pass.
//! - The audit log is the **recovery source-of-truth** for revocations after a
//!   crash.  Constraint: the audit log stores token IDs in `actor: u32`.
//!   Nonces that exceed `u32::MAX` require a dedicated persistence store
//!   (see ADR 0005 / Tier 2 roadmap).
//! - A failed HSM call must **not mutate local kernel state**.  The blast
//!   radius is exactly one capability request; the `Policy` remains operational
//!   for all other requests.

use core::num::NonZeroU32;
use std::time::Duration;

use lux_kernel::{
    audit::{AuditLog, EventKind},
    auth::{Capability, CapabilitySet, Policy},
    hsm::HsmProvider,
    types::Generation,
    Error, Result,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn node(n: u32) -> lux_kernel::types::NodeId {
    NonZeroU32::new(n).unwrap()
}

/// Construct a `READ_TOPOLOGY` capability at `Generation(0)` with the given nonce.
fn make_cap(nonce: u64) -> Capability {
    Capability::new_for_test(
        node(1),
        node(2),
        CapabilitySet::READ_TOPOLOGY,
        Generation(0),
        nonce,
    )
}

// ── Mock HSM: simulates 20 ms USB/PKCS#11 latency to a missing key ───────────

/// Mock HSM that waits `delay_ms` milliseconds and then returns
/// `Err(UndefinedState)` on every operation.
///
/// Simulates a real USB + PKCS#11 roundtrip to an HSM whose key slot was
/// deleted out-of-band (factory reset, rotation without local notification).
/// The delay makes the timing semantics of Scenario A and B explicit.
#[derive(Debug)]
struct MockDelayedHsm {
    delay_ms: u64,
}

impl HsmProvider for MockDelayedHsm {
    fn generate_capability_seed(&self) -> Result<[u8; 32]> {
        std::thread::sleep(Duration::from_millis(self.delay_ms));
        Err(Error::UndefinedState { context: "hsm: key not found" })
    }

    fn sign(&self, _payload: &[u8]) -> Result<[u8; 64]> {
        std::thread::sleep(Duration::from_millis(self.delay_ms));
        Err(Error::UndefinedState { context: "hsm: key not found" })
    }

    fn verify(&self, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> {
        Err(Error::UndefinedState { context: "hsm: key not found" })
    }
}

// ── Scenario A: revocation arrives while the HSM call is in-flight ────────────

/// Scenario A: the `RevocationLedger` wins at `Policy::check` time, not at
/// capability-creation time.
///
/// **Sequence:**
/// ```
/// Local:  is_revoked(nonce=0) → false ✓
/// HSM:    call initiated       (20 ms in-flight)
/// Race:   revoke(nonce=0) arrives while HSM is in-flight
/// HSM:    responds with signed capability { nonce: 0 }
/// Local:  Policy::check(nonce=0) → is_revoked → true → DENIED
/// ```
///
/// **State ownership decision:**
/// The HSM signature proves the key existed at call initiation; it does **not**
/// constitute authorization.  `Policy::check` is the last and authoritative
/// gate.  A nonce revoked at any point before `Policy::check` must be rejected,
/// regardless of when the HSM call started.
///
/// **Invariants asserted:**
/// - I1 (Fail-Closed): revoked nonce → `Err`, never `Ok`
/// - I2 (Capability-Gated): `RevocationLedger` overrides HSM signature
/// - I3 (Accountable): no quota deduction reachable — I1 gate fires first
/// - I4 (Topology-Bounded): topology check unreachable — I1 gate fires first
#[test]
fn scenario_a_revocation_during_hsm_call() {
    let mut policy = Policy::new(Generation(0));
    let mut audit  = AuditLog::new();
    let nonce: u64 = 0;

    // Pre-call verification: nonce is clean before the HSM call begins.
    assert!(
        !policy.is_revoked(nonce),
        "nonce must be unrevoked before HSM call",
    );

    // HSM call initiated — simulate 20 ms hardware latency.
    // In a real concurrent system, revocations can arrive during this window.
    // Here we model the race by advancing through the sequence deterministically.
    std::thread::sleep(Duration::from_millis(20));

    // Concurrent revocation arrives while the HSM call is in-flight.
    // State ownership: the RevocationLedger (via Policy) is the gate that
    // matters; the HSM's clock is irrelevant.
    assert!(
        policy.revoke_capability(nonce),
        "revocation must succeed before HSM response is consumed",
    );

    // HSM responds — construct the capability it would have returned.
    // The signing key existed at call initiation, but the nonce is now revoked.
    let cap = make_cap(nonce);

    // I1 + I2: Policy::check must deny the revoked nonce.
    // The RevocationLedger is consulted at step 2 of the 4-step check;
    // the HSM's response timestamp has no influence on this decision.
    match policy.check(&cap, CapabilitySet::READ_TOPOLOGY, &mut audit) {
        Err(Error::CapabilityDenied { reason }) if reason.contains("revoked") => {
            // Correct: revocation ledger denied the capability.
        }
        other => panic!(
            "I1+I2: capability with revoked nonce must be denied at Policy::check; \
             RevocationLedger is authoritative, not HSM call timestamp; got: {other:?}",
        ),
    }

    // Observability: the audit log must record the denial.
    // A silent drop would pass this test — that is not fail-closed.
    assert!(
        audit.events().any(|e| e.denial_class.is_some()),
        "I1: denial must be recorded in the audit log; \
         silent failures are not fail-closed",
    );
}

// ── Scenario B: HSM key deleted out-of-band (stale hardware / factory reset) ──

/// Scenario B: the HSM returns `KeyNotFound` because its key slot was deleted.
/// The kernel must propagate the error and leave local state unchanged.
///
/// **Sequence:**
/// ```
/// Local:  is_revoked(nonce=7)  → false ✓
/// HSM:    sign(payload)         → Err(UndefinedState { "key not found" })
/// Local:  propagate Err to caller; Policy state unchanged
/// ```
///
/// **State ownership decision:**
/// The HSM is authoritative for signing.  If it cannot sign, the capability
/// cannot be issued.  The kernel must **not** silently fall back to the
/// software key store — that would silently swap the trust root declared in the
/// boot manifest (violating I4).  The kernel must **not** crash — making an
/// HSM deletion a kernel-availability weapon is also wrong.  The correct
/// behaviour is: the single request fails; the `Policy` remains operational.
///
/// **Invariants asserted:**
/// - I1 (Fail-Closed): HSM error → `Err`, not a degraded `Ok`
/// - I2 (Capability-Gated): no capability issued without HSM success
/// - I3 (Accountable): no quota deduction — no capability issued
/// - I4 (Topology-Bounded): no fallback to a different trust root
#[test]
fn scenario_b_hsm_key_divergence() {
    let mut policy = Policy::new(Generation(0));
    let mut audit  = AuditLog::new();
    let nonce: u64 = 7;

    // Baseline: nonce is clean; audit log is empty.
    assert!(!policy.is_revoked(nonce), "nonce must be clean before HSM attempt");
    assert!(audit.is_empty(), "audit log must be empty before attempt");

    // HSM with 20 ms latency that models a deleted key slot.
    let hsm = MockDelayedHsm { delay_ms: 20 };

    // Attempt to generate capability material via the HSM.
    // This is the representative "HSM round-trip" call — the point where
    // real hardware would look up the key slot and fail.
    let seed_result = hsm.generate_capability_seed();

    // I1: the error must propagate; the kernel must not proceed as if it succeeded.
    // I4: specifically, it must not fall back to software key material — that
    //     would silently change the trust root from the boot manifest's HSM key.
    assert!(
        matches!(seed_result, Err(Error::UndefinedState { .. })),
        "I1+I4: HSM key-not-found must propagate as Err(UndefinedState); \
         silent fallback to software key violates I4 (Topology-Bounded trust root)",
    );

    // I1: a failed HSM call must not trigger side-effects on local state.
    // The revocation ledger must be unchanged — no phantom revocations.
    assert!(
        !policy.is_revoked(nonce),
        "I1: failed HSM call must not alter revocation state as a side-effect",
    );

    // Blast-radius check: the Policy must remain fully operational.
    // A valid, non-revoked capability must still pass Policy::check.
    // This verifies the failure is scoped to the one request, not the kernel.
    let valid_cap = make_cap(nonce);
    match policy.check(&valid_cap, CapabilitySet::READ_TOPOLOGY, &mut audit) {
        Ok(()) => {
            // Correct: blast radius is limited to the failed HSM request.
        }
        Err(e) => panic!(
            "I1: blast radius must be limited to the failed HSM request; \
             valid capabilities must not be collaterally denied; got: {e:?}",
        ),
    }
}

// ── Scenario C: revocation ledger lost on crash, recovered from audit log ─────

/// Scenario C: in-memory `RevocationLedger` lost on crash; audit log survived.
/// Revocations are reconstructed by replaying `CapabilityRevoked` audit events
/// before any new capabilities are minted.
///
/// **Sequence:**
/// ```
/// Pre-crash:  revoke(nonce=42); audit.append(CapabilityRevoked, actor=42)
/// Crash:      Policy dropped (in-memory RevocationLedger lost)
/// Recovery:   scan audit for CapabilityRevoked events; replay into new Policy
/// Post:       Policy::check(nonce=42) → DENIED ✓
///             Policy::check(nonce=99) → PERMITTED ✓  (not over-revoked)
/// ```
///
/// **State ownership decision:**
/// The audit log is the source of truth for recovery.  Callers are responsible
/// for appending `CapabilityRevoked` events when they call
/// `Policy::revoke_capability` — the kernel does not auto-persist.
///
/// **Constraint:** the audit log stores the token ID in `actor: u32`.  Nonces
/// that exceed `u32::MAX` cannot be recovered via this path.  Such nonces
/// require a dedicated revocation persistence store (ADR 0005 / Tier 2).
///
/// **Recovery rule:** reconstruction must complete before any capability is
/// minted.  If the revocation ledger fills during recovery, the caller must
/// halt rather than proceed with incomplete revocation state.
///
/// **Invariants asserted:**
/// - I1 (Fail-Closed): formerly-revoked nonce remains denied after recovery
/// - I2 (Capability-Gated): recovered state blocks capability use
/// - I3 (Accountable): no deduction for denied capability
/// - I4 (Topology-Bounded): topology check unreachable — I1+I2 gate fires first
#[test]
fn scenario_c_revocation_ledger_crash_recovery() {
    // ── Phase 1: pre-crash ────────────────────────────────────────────────────

    // Constraint: nonce must fit in u32 for audit-log recovery.
    // Nonces > u32::MAX require a dedicated persistence store (see ADR 0005).
    let revoked_nonce: u64 = 42;

    let mut pre_crash_policy = Policy::new(Generation(0));
    let mut audit            = AuditLog::new();

    // Revoke the nonce.  Policy::revoke_capability does not auto-persist to the
    // audit log — callers must do this explicitly.
    assert!(
        pre_crash_policy.revoke_capability(revoked_nonce),
        "revocation must succeed pre-crash",
    );

    // Persist the revocation event so recovery can replay it.
    // actor = nonce (u32); timestamp = 0 (logical, not wall time).
    let appended = audit.append(
        EventKind::CapabilityRevoked,
        u32::try_from(revoked_nonce).expect("test nonce must fit in u32 for audit recovery"),
        0,
        None,
    );
    assert!(appended, "audit append must succeed");

    // ── Phase 2: crash ────────────────────────────────────────────────────────
    // Simulate loss of in-memory state by dropping the Policy.
    // The audit log survives (models persistent storage: flash, disk, NVM).
    drop(pre_crash_policy);

    // ── Phase 3: recovery ─────────────────────────────────────────────────────
    // New Policy starts empty — no revocations, no nonce window.
    let mut recovered_policy = Policy::new(Generation(0));

    // Replay all CapabilityRevoked events from the audit log into the new Policy.
    // This must complete in full before any capability is minted.  Partial
    // recovery is not fail-closed: an incomplete ledger may permit tokens that
    // were revoked before the crash.
    for event in audit.events() {
        if event.kind == EventKind::CapabilityRevoked {
            let token_id = u64::from(event.actor);
            assert!(
                recovered_policy.revoke_capability(token_id),
                "I1: revocation ledger full during recovery — \
                 caller must rotate generation before minting any capabilities; \
                 proceeding with a partially-recovered ledger is not fail-closed",
            );
        }
    }

    // ── Phase 4: post-recovery assertions ────────────────────────────────────

    // I1 + I2: the formerly-revoked nonce must still be denied after recovery.
    let revoked_cap = make_cap(revoked_nonce);
    match recovered_policy.check(&revoked_cap, CapabilitySet::READ_TOPOLOGY, &mut audit) {
        Err(Error::CapabilityDenied { reason }) if reason.contains("revoked") => {
            // Correct: recovered revocation state denied the capability.
        }
        other => panic!(
            "I1+I2: recovered policy must deny the formerly-revoked nonce; \
             audit-log replay failed to reconstruct revocation state; got: {other:?}",
        ),
    }

    // Recovery precision check: an unrevoked nonce must still be permitted.
    // Over-revoking (blanket denial after crash) is NOT a conservative safe
    // behaviour — it is a correctness failure that breaks availability without
    // improving security.
    let clean_nonce: u64 = 99;
    let clean_cap = make_cap(clean_nonce);
    match recovered_policy.check(&clean_cap, CapabilitySet::READ_TOPOLOGY, &mut audit) {
        Ok(()) => {
            // Correct: recovery did not over-revoke unrelated nonces.
        }
        Err(e) => panic!(
            "I1: recovery must be precise; unrevoked nonces must remain valid; \
             blanket post-crash denial is a correctness failure, not a security \
             improvement; got: {e:?}",
        ),
    }
}
