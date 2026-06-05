#![no_main]
use libfuzzer_sys::fuzz_target;
use lux_kernel::{
    boot::{credentials::BootCredentials, decode::ManifestDecoder},
    hsm::mock::SoftwareHsm,
};

fuzz_target!(|data: &[u8]| {
    // Use a fixed signing key so the fuzzer can craft valid signatures.
    // The fuzzer explores: short inputs, garbage CBOR, overflow attempts,
    // malformed edges/quotas, and any input that causes an unexpected result.
    let hsm = SoftwareHsm::from_signing_key([42u8; 32]);
    let creds = BootCredentials::new(hsm);

    // Any result other than Ok(_) or Err(ManifestInvalid) is a bug.
    // Any panic is a bug.
    let _ = ManifestDecoder::decode(data, &creds);
});
