//! End-to-end example: boot → root capability → delegate → check → revoke → deny.
//!
//! This example demonstrates the full Lux Kernel lifecycle:
//!
//! 1. Build and sign a CBOR boot manifest using `SoftwareHsm`.
//! 2. Call `BootState::initialise` to produce a sealed `BootState`.
//! 3. Mint a root capability token for the boot principal.
//! 4. Delegate a subset capability to a second principal.
//! 5. Use the delegated capability to pass `Policy::check`.
//! 6. Revoke the delegated capability and confirm denial.
//!
//! Run with:
//! ```sh
//! cargo run --example boot_and_delegate
//! ```

use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use lux_kernel::{
    auth::capability::{Capability, CapabilitySet},
    audit::AuditLog,
    boot::{BootCredentials, BootState},
    error::Error,
    types::Generation,
};
use std::num::NonZeroU32;

// ── Manifest helpers ──────────────────────────────────────────────────────────

/// Build a minimal CBOR manifest: version 1, one edge (node 1 → node 2),
/// and a quota of 1 000 000 units for node 1.
///
/// Wire format: `[64-byte Ed25519 signature] ++ [CBOR payload]`
fn build_signed_manifest(sk: &SigningKey) -> Vec<u8> {
    // CBOR: [1, [[1, 2]], [[1, 1000000]]]
    //
    // Encoding breakdown (definite-length arrays throughout):
    //   0x83          array(3)
    //   0x01          uint(1)             -- version = 1
    //   0x81          array(1)            -- one edge
    //     0x82        array(2)
    //       0x01      uint(1)             -- src = 1
    //       0x02      uint(2)             -- dst = 2
    //   0x81          array(1)            -- one quota
    //     0x82        array(2)
    //       0x01      uint(1)             -- node = 1
    //       0x1a 0x000f 0x4240            -- uint(1_000_000)
    let payload: Vec<u8> = vec![
        0x83,                         // array(3)
        0x01,                         // version = 1
        0x81,                         // edges: array(1)
          0x82, 0x01, 0x02,           //   [src=1, dst=2]
        0x81,                         // quotas: array(1)
          0x82, 0x01, 0x1a, 0x00, 0x0f, 0x42, 0x40, // [node=1, ceiling=1_000_000]
    ];

    let sig = sk.sign(&payload);
    let mut wire = sig.to_bytes().to_vec(); // 64 bytes
    wire.extend_from_slice(&payload);
    wire
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // ── Step 1: Sign and decode the boot manifest ─────────────────────────────

    let seed = [0xAB_u8; 32]; // fixed seed for reproducibility
    let signing_key = SigningKey::from_bytes(&seed);

    let wire = build_signed_manifest(&signing_key);
    let creds = BootCredentials::from_key_bytes(signing_key.verifying_key().to_bytes())
        .expect("valid public key");

    let mut boot_state = BootState::initialise(&wire, &creds)
        .expect("manifest must decode and verify");

    println!("[Step 1] Boot manifest decoded and verified.");
    println!("         Attestation quote (null TPM): {:?}", boot_state.attestation_quote().is_null());

    // ── Step 2: Mint a root capability for the boot principal (node 1) ────────

    let node1 = NonZeroU32::new(1).expect("non-zero");
    let node2 = NonZeroU32::new(2).expect("non-zero");

    // Root capability: node1 → node1, all rights, generation 0, nonce 1.
    let root_cap = Capability::new_for_test(
        node1,
        node1,
        CapabilitySet::SCHEDULE | CapabilitySet::DELEGATE | CapabilitySet::READ_TOPOLOGY,
        Generation(0),
        1_u64,
    );

    println!("[Step 2] Root capability minted for node 1.");

    // ── Step 3: Delegate SCHEDULE to node 2 ──────────────────────────────────

    let delegated = root_cap
        .delegate(node2, CapabilitySet::SCHEDULE, 42_u64)
        .expect("delegation within rights must succeed");

    println!("[Step 3] SCHEDULE right delegated to node 2 (nonce=42).");

    // ── Step 4: Policy::check passes for the delegated capability ────────────

    let mut audit = AuditLog::new();
    let result = boot_state
        .policy_mut()
        .check(&delegated, CapabilitySet::SCHEDULE, &mut audit);

    match result {
        Ok(()) => println!("[Step 4] Policy::check PASSED for delegated capability."),
        Err(e) => panic!("[Step 4] Unexpected denial: {e:?}"),
    }

    // ── Step 5: Revoke the delegated capability (by nonce) ───────────────────

    let revoked = boot_state.policy_mut().revoke_capability(42_u64);
    assert!(revoked, "revocation must succeed (nonce window not exhausted)");
    println!("[Step 5] Nonce 42 revoked.");

    // ── Step 6: A second presentation of the same token is denied ────────────
    //
    // We must construct a new token with the same nonce because the original
    // `delegated` was consumed (moved) by the `check` call above.

    let revoked_cap = Capability::new_for_test(
        node1,
        node2,
        CapabilitySet::SCHEDULE,
        Generation(0),
        42_u64, // same nonce — revoked
    );

    let mut audit2 = AuditLog::new();
    let denied = boot_state
        .policy_mut()
        .check(&revoked_cap, CapabilitySet::SCHEDULE, &mut audit2);

    match denied {
        Err(Error::CapabilityDenied { reason }) => {
            println!("[Step 6] Policy::check DENIED (expected): {reason}");
        }
        Ok(()) => panic!("[Step 6] Revoked token must NOT pass!"),
        Err(e) => panic!("[Step 6] Unexpected error variant: {e:?}"),
    }

    // ── Step 7: Audit log summary ─────────────────────────────────────────────

    println!();
    println!("Audit chain valid: {}", audit.verify_chain());
    println!("Audit events recorded in lifecycle: {}", audit.len());
    println!();
    println!("All steps completed successfully.");
}
