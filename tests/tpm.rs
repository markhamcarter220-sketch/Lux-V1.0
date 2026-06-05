//! TPM integration tests — SoftwareTpm, NullTpm, BootAttestation, and TssTpmProvider stub.

use lux_kernel::{
    boot::{BootCredentials, BootState},
    tpm::{attestation::BootAttestation, mock::SoftwareTpm, NullTpm, TpmProvider, TpmQuote},
};

#[cfg(feature = "tpm")]
use lux_kernel::tpm::TssTpmProvider;

use ed25519_dalek::SigningKey;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0u8; 32])
}

fn boot_creds() -> BootCredentials {
    let sk = signing_key();
    BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap()
}

fn minimal_payload() -> Vec<u8> {
    // CBOR [1, [], []]
    vec![0x83, 0x01, 0x80, 0x80]
}

fn signed_wire(payload: &[u8], sk: &SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let sig = sk.sign(payload);
    let mut w = sig.to_bytes().to_vec();
    w.extend_from_slice(payload);
    w
}

// ── 1. NullTpm: extend always returns Ok ─────────────────────────────────────

#[test]
fn null_tpm_extend_always_ok() {
    let mut tpm = NullTpm;
    assert!(
        tpm.extend_pcr(0, b"data").is_ok(),
        "NullTpm.extend_pcr must always return Ok"
    );
}

// ── 2. NullTpm: quote is all-zeros ───────────────────────────────────────────

#[test]
fn null_tpm_quote_is_all_zeros() {
    let tpm = NullTpm;
    let quote = tpm
        .quote(0, &[0u8; 32])
        .expect("NullTpm.quote must not fail");
    assert!(
        quote.is_null(),
        "NullTpm must produce an all-zeros TpmQuote"
    );
}

// ── 3. NullTpm: read_pcr returns zeros ───────────────────────────────────────

#[test]
fn null_tpm_read_pcr_returns_zeros() {
    let tpm = NullTpm;
    let val = tpm.read_pcr(0).expect("NullTpm.read_pcr must not fail");
    assert_eq!(val, [0u8; 32], "NullTpm.read_pcr must return all-zeros");
}

// ── 4. NullTpm: verify_quote succeeds for null quote ─────────────────────────

#[test]
fn null_tpm_verify_null_quote_succeeds() {
    let tpm = NullTpm;
    let nonce = [0u8; 32];
    let quote = TpmQuote([0u8; 64]);
    assert!(
        tpm.verify_quote(0, &nonce, &quote).is_ok(),
        "NullTpm.verify_quote must accept an all-zeros quote"
    );
}

// ── 5. NullTpm: verify_quote rejects non-null quote ──────────────────────────

#[test]
fn null_tpm_verify_non_null_quote_fails() {
    let tpm = NullTpm;
    let nonce = [0u8; 32];
    let mut data = [0u8; 64];
    data[0] = 0x01; // non-zero → non-null
    let quote = TpmQuote(data);
    assert!(
        tpm.verify_quote(0, &nonce, &quote).is_err(),
        "NullTpm.verify_quote must reject a non-null quote"
    );
}

// ── 6. SoftwareTpm: PCR is zero on init ──────────────────────────────────────

#[test]
fn software_tpm_pcr_zero_on_init() {
    let tpm = SoftwareTpm::new();
    let val = tpm
        .read_pcr(0)
        .expect("read_pcr must succeed on a fresh SoftwareTpm");
    assert_eq!(val, [0u8; 32], "fresh SoftwareTpm PCR[0] must be all-zeros");
}

// ── 7. SoftwareTpm: extend changes the PCR ───────────────────────────────────

#[test]
fn software_tpm_extend_changes_pcr() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"some data")
        .expect("extend_pcr must succeed");
    let val = tpm.read_pcr(0).expect("read_pcr must succeed after extend");
    assert_ne!(val, [0u8; 32], "PCR[0] must be non-zero after extend");
}

// ── 8. SoftwareTpm: extend is deterministic ──────────────────────────────────

#[test]
fn software_tpm_extend_deterministic() {
    let mut tpm_a = SoftwareTpm::new();
    let mut tpm_b = SoftwareTpm::new();
    tpm_a
        .extend_pcr(0, b"deterministic data")
        .expect("extend_pcr A");
    tpm_b
        .extend_pcr(0, b"deterministic data")
        .expect("extend_pcr B");
    let a = tpm_a.read_pcr(0).unwrap();
    let b = tpm_b.read_pcr(0).unwrap();
    assert_eq!(a, b, "same data must produce the same PCR extension result");
}

// ── 9. SoftwareTpm: quote bytes[0..32] == current PCR value ──────────────────

#[test]
fn software_tpm_quote_binds_to_pcr() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"manifest bytes").expect("extend_pcr");
    let pcr_val = tpm.read_pcr(0).unwrap();
    let nonce = [0u8; 32];
    let quote = tpm.quote(0, &nonce).expect("quote");
    assert_eq!(
        &quote.as_bytes()[..32],
        &pcr_val,
        "quote[0..32] must equal the current PCR value"
    );
}

// ── 10. SoftwareTpm: different nonces produce different quotes ────────────────

#[test]
fn software_tpm_quote_binds_to_nonce() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"data").expect("extend_pcr");
    let nonce_a = [0x11u8; 32];
    let nonce_b = [0x22u8; 32];
    let q_a = tpm.quote(0, &nonce_a).expect("quote A");
    let q_b = tpm.quote(0, &nonce_b).expect("quote B");
    assert_ne!(
        q_a.as_bytes(),
        q_b.as_bytes(),
        "different nonces must produce different quote bytes"
    );
}

// ── 11. SoftwareTpm: extend + quote + verify_quote roundtrip ─────────────────

#[test]
fn software_tpm_verify_quote_roundtrip() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"roundtrip payload").expect("extend_pcr");
    let nonce = [0xAAu8; 32];
    let quote = tpm.quote(0, &nonce).expect("quote");
    tpm.verify_quote(0, &nonce, &quote)
        .expect("verify_quote must succeed on a fresh extend+quote pair");
}

// ── 12. SoftwareTpm: wrong nonce fails verify ─────────────────────────────────

#[test]
fn software_tpm_verify_quote_wrong_nonce_fails() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"data").expect("extend_pcr");
    let nonce_orig = [0x01u8; 32];
    let nonce_wrong = [0x02u8; 32];
    let quote = tpm.quote(0, &nonce_orig).expect("quote");
    assert!(
        tpm.verify_quote(0, &nonce_wrong, &quote).is_err(),
        "verify_quote must fail when the nonce differs from the one used during quoting"
    );
}

// ── 13. SoftwareTpm: stale quote fails after further extension ────────────────

#[test]
fn software_tpm_verify_quote_stale_fails() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"first extend")
        .expect("first extend_pcr");
    let nonce = [0x55u8; 32];
    let stale = tpm.quote(0, &nonce).expect("stale quote");

    // Extend again — PCR state changes.
    tpm.extend_pcr(0, b"second extend")
        .expect("second extend_pcr");

    assert!(
        tpm.verify_quote(0, &nonce, &stale).is_err(),
        "verify_quote must reject a quote taken before a subsequent PCR extension"
    );
}

// ── 14. SoftwareTpm: PCR index 24 is out of range ────────────────────────────

#[test]
fn software_tpm_pcr_out_of_range() {
    let mut tpm = SoftwareTpm::new();
    let oob: u8 = 24;
    let nonce = [0u8; 32];
    let null_q = TpmQuote([0u8; 64]);

    assert!(
        tpm.extend_pcr(oob, b"x").is_err(),
        "extend_pcr(24) must return Err"
    );
    assert!(tpm.quote(oob, &nonce).is_err(), "quote(24) must return Err");
    assert!(tpm.read_pcr(oob).is_err(), "read_pcr(24) must return Err");
    assert!(
        tpm.verify_quote(oob, &nonce, &null_q).is_err(),
        "verify_quote(24) must return Err"
    );
}

// ── 15. BootAttestation: produce and verify roundtrip ────────────────────────

#[test]
fn boot_attestation_produce_and_verify() {
    // Build a valid signed manifest wire format.
    let sk = signing_key();
    let creds = boot_creds();
    let wire = signed_wire(&minimal_payload(), &sk);

    // Boot with a SoftwareTpm.
    let mut tpm = SoftwareTpm::new();
    let state = BootState::initialise_with_tpm(&wire, &creds, &mut tpm)
        .expect("boot must succeed with a valid manifest");

    // Produce attestation (tpm is now in the post-boot PCR state).
    let nonce = [0xBBu8; 32];
    let attestation = state
        .produce_attestation(&tpm, nonce)
        .expect("produce_attestation must not fail");

    // Verify against the same tpm in the same state.
    attestation
        .verify(&tpm)
        .expect("verify must succeed for a fresh attestation");
}

// ── 16. BootAttestation: two different nonces produce different attestations ──

#[test]
fn boot_attestation_different_nonces_differ() {
    let sk = signing_key();
    let creds = boot_creds();
    let wire = signed_wire(&minimal_payload(), &sk);

    let mut tpm = SoftwareTpm::new();
    let state = BootState::initialise_with_tpm(&wire, &creds, &mut tpm).expect("boot must succeed");

    let nonce_a = [0x01u8; 32];
    let nonce_b = [0x02u8; 32];

    let att_a = state
        .produce_attestation(&tpm, nonce_a)
        .expect("attestation A");
    let att_b = state
        .produce_attestation(&tpm, nonce_b)
        .expect("attestation B");

    assert_ne!(
        att_a.quote().as_bytes(),
        att_b.quote().as_bytes(),
        "different nonces must produce different attestation quotes"
    );
}

// ── 17. TssTpmProvider stub: all 4 methods return Err ────────────────────────

#[test]
#[cfg(feature = "tpm")]
fn tss_stub_returns_error() {
    let mut provider = TssTpmProvider::new_stub();
    let nonce = [0u8; 32];
    let null_q = TpmQuote([0u8; 64]);

    assert!(
        provider.extend_pcr(0, b"x").is_err(),
        "extend_pcr must return Err"
    );
    assert!(provider.quote(0, &nonce).is_err(), "quote must return Err");
    assert!(provider.read_pcr(0).is_err(), "read_pcr must return Err");
    assert!(
        provider.verify_quote(0, &nonce, &null_q).is_err(),
        "verify_quote must return Err"
    );
}

// ── Bonus: BootAttestation manual construction and verify ─────────────────────
// (Tests BootAttestation::new and ::verify without needing a full boot sequence)

#[test]
fn boot_attestation_manual_construction_verify() {
    let mut tpm = SoftwareTpm::new();
    tpm.extend_pcr(0, b"manifest").expect("extend_pcr");

    let nonce = [0xCCu8; 32];
    let quote = tpm.quote(0, &nonce).expect("quote");
    let m_hash = tpm.read_pcr(0).unwrap(); // use PCR value as a stand-in for manifest hash

    let att = BootAttestation::new(m_hash, 0, nonce, quote);
    assert_eq!(att.pcr_index(), 0);
    assert_eq!(att.nonce(), &nonce);
    assert_eq!(att.manifest_hash(), &m_hash);

    att.verify(&tpm)
        .expect("manual BootAttestation must verify successfully");
}
