import FunctionSpecs.Core

/-!
# Lux Kernel — Function Spec Layer: HSM Module

This file covers every production (non-test, non-kani) function in:
- `src/hsm/mod.rs`
- `src/hsm/keystore.rs`
- `src/hsm/mock.rs`
- `src/hsm/pkcs11.rs`
- `src/hsm/yubihsm.rs`

These files implement the Hardware Security Module (HSM) abstraction: the
`HsmProvider` trait (capability-seed generation, Ed25519 sign/verify) and the
`KeyManagement` trait (multi-slot keypair generation, per-slot sign/verify,
listing, rotation), plus three backends — `SoftwareHsm` (the default
no-`hsm`-feature Ed25519 mock), `SoftwareKeyStore` (the `hsm`-feature
software-complete multi-key reference implementation), `Pkcs11HsmProvider`
and `YubiHsmProvider` (both currently software stubs that unconditionally
return `Err(CapabilityDenied)` / `Err(ManifestInvalid)` pending real hardware
wiring).

**Total functions specified: 51.**

This is a spec-only layer: every declaration below is `opaque` (or, for a
handful of genuinely trivial pure accessors/constructors, a direct `def`),
paired with independent `_pre`/`_post` declarations.  **No theorems, no
`sorry`, no proof obligations are introduced anywhere in this file.**  Per
`Core.lean`'s documented convention, `_pre`/`_post` are best-effort
transcriptions of the Rust doc comments and `Result` shapes — they are not
mechanically checked against the `opaque` signatures.

## Why most of this module is a REFINEMENT_GAP

HSM/PKCS#11/YubiHSM code does real hardware I/O, Ed25519 cryptographic
signing/verification, OS-level CSPRNG calls, mutex locking, and (for the
hardware backends) FFI into vendor libraries.  None of this admits a clean
mathematical pre/post spec in this `Nat`/`List Nat`-based layer:
- "Produces a valid Ed25519 signature" cannot be characterized without
  modelling elliptic-curve arithmetic — out of scope here.
- "Talks to a USB/HTTP HSM device" cannot be characterized as a pure Lean
  predicate at all.
- Mutex poisoning, OS RNG availability, and PKCS#11/YubiHSM session state
  are external, non-deterministic preconditions this layer does not model.

Per the task brief, every function below still gets a best-effort `_pre`/
`_post` pair (e.g. "on success, result bytes are the documented fixed
length; on failure, the result is an `Err`" without characterizing
cryptographic correctness) plus a `REFINEMENT_GAP` tag.  Functions that are
genuinely pure/trivial (struct constructors with no I/O, plain accessors)
are tagged `REFINEMENT_GAP`-free where a real spec is possible.

## REFINEMENT_GAP entries in this file

| Function | file:line | Reason |
|---|---|---|
| `keyHandleZeroize` | `src/hsm/mod.rs:71` | Mutates raw key bytes in place via `zeroize` crate; security property ("bytes are overwritten so they can't be recovered") is a memory-safety/side-channel claim, not expressible as a pure Lean postcondition on `List Nat`. |
| `hsmProviderGenerateCapabilitySeed` (trait contract) | `src/hsm/mod.rs:98` | Cryptographic/entropy contract: "32 bytes computationally unpredictable to an adversary" is not a pure-Lean predicate. |
| `hsmProviderSign` (trait contract) | `src/hsm/mod.rs:106` | Ed25519 signing; "produces a signature `verify` accepts" requires modelling EC crypto. |
| `hsmProviderVerify` (trait contract) | `src/hsm/mod.rs:114` | Ed25519 verification; cryptographic soundness not modelled. |
| `keyManagementGenerateKeypair` (trait contract) | `src/hsm/mod.rs:138` | Keypair generation depends on hardware/OS entropy and mutex state. |
| `keyManagementSignCapability` (trait contract) | `src/hsm/mod.rs:147` | Per-slot Ed25519 signing; same crypto gap as `sign`. |
| `keyManagementVerifyCapabilitySignature` (trait contract) | `src/hsm/mod.rs:158` | Per-slot Ed25519 verification; same crypto gap as `verify`. |
| `keyManagementListKeys` (trait contract) | `src/hsm/mod.rs:171` | Depends on opaque internal key-table/mutex state not modelled in this layer. |
| `keyManagementRotateKey` (trait contract) | `src/hsm/mod.rs:183` | Combines keypair generation (entropy) with atomic slot replacement (mutex state). |
| `hsmSignedCapabilitySign` | `src/hsm/mod.rs:215` | Delegates to `sign_capability`; inherits its crypto/hardware gap. |
| `hsmSignedCapabilityVerify` | `src/hsm/mod.rs:236` | Delegates to `verify_capability_signature`; inherits its crypto/hardware gap. |
| `hsmSignedCapabilityCapPayload` | `src/hsm/mod.rs:242` | Pure byte-layout function, but depends on opaque `Capability` accessor fields not modelled in this file (defined in `src/auth/capability.rs`, outside this module's scope) — included for completeness with a structural-only postcondition. |
| `defaultHsm` | `src/hsm/mod.rs:260` | Trivial delegate to `SoftwareKeyStore::new`; tagged only because its postcondition inherits `softwareKeyStoreNew`'s gap (no primary key state is itself unobservable without further accessors). |
| `zeroizingSigningKeyDrop` | `src/hsm/keystore.rs:26` | Side-effecting `Drop` impl that overwrites secret key material; memory-zeroization guarantee is not expressible as a pure Lean postcondition. |
| `zeroizingSigningKeyFmt` | `src/hsm/keystore.rs:37` | `Debug` formatting of a redacted placeholder string; trivial but tagged since it touches the secret-bearing wrapper type. |
| `softwareKeyStoreNew` | `src/hsm/keystore.rs:69` | Constructs a `Mutex<HashMap>`; mutex/heap-table initial state is opaque in this layer. |
| `softwareKeyStoreWithSigningKey` | `src/hsm/keystore.rs:78` | Ed25519 key derivation from seed bytes (`SigningKey::from_bytes`) is cryptographic, not modelled. |
| `softwareKeyStoreVerifyingKeyBytes` | `src/hsm/keystore.rs:87` | Derives a verifying key from a signing key (EC scalar multiplication); cryptographic derivation not modelled. |
| `softwareKeyStoreDefault` | `src/hsm/keystore.rs:96` | Delegates to `new`; inherits its mutex/heap-state gap. |
| `softwareKeyStoreGenerateCapabilitySeed` | `src/hsm/keystore.rs:101` | OS CSPRNG (`OsRng`) plus optional SHA-256 mixing with key material; entropy source not modelled. |
| `softwareKeyStoreSign` | `src/hsm/keystore.rs:114` | Ed25519 signing; crypto gap. |
| `softwareKeyStoreVerify` | `src/hsm/keystore.rs:124` | Ed25519 verification; crypto gap. |
| `softwareKeyStoreGenerateKeypair` | `src/hsm/keystore.rs:142` | OS CSPRNG, SHA-256 handle derivation, and mutex-guarded `HashMap` insert; none modelled. |
| `softwareKeyStoreSignCapability` | `src/hsm/keystore.rs:163` | Mutex-guarded lookup plus Ed25519 signing; both gaps apply. |
| `softwareKeyStoreVerifyCapabilitySignature` | `src/hsm/keystore.rs:176` | Mutex-guarded lookup plus Ed25519 verification; both gaps apply. |
| `softwareKeyStoreListKeys` | `src/hsm/keystore.rs:201` | Mutex-guarded `HashMap` iteration; internal table state opaque. |
| `softwareKeyStoreRotateKey` | `src/hsm/keystore.rs:208` | OS CSPRNG, SHA-256 derivation, and mutex-guarded atomic remove+insert; none modelled. |
| `softwareHsmFromVerifyingKey` | `src/hsm/mock.rs:40` | Validates raw bytes as an Ed25519 curve point (`VerifyingKey::from_bytes`); curve-membership check not modelled. |
| `softwareHsmFromSigningKey` | `src/hsm/mock.rs:56` | Ed25519 key derivation from seed; cryptographic derivation not modelled. |
| `softwareHsmVerifyingKeyBytes` | `src/hsm/mock.rs:67` | Pure accessor, but the underlying `VerifyingKey` byte encoding is a cryptographic library detail not modelled — tagged for consistency with the other key-byte accessors. |
| `softwareHsmGenerateCapabilitySeed` | `src/hsm/mock.rs:73` | SHA-256 digest of key bytes; hash function not modelled. |
| `softwareHsmSign` | `src/hsm/mock.rs:81` | Ed25519 signing; crypto gap. |
| `softwareHsmVerify` | `src/hsm/mock.rs:91` | Ed25519 verification; crypto gap. |
| `pkcs11HsmProviderNewStub` | `src/hsm/pkcs11.rs:35` | Trivial pure constructor in Rust, but models a placeholder for a future opaque hardware-session/library-path resource; tagged for consistency with the hardware-backend constructors below. |
| `pkcs11HsmProviderGenerateCapabilitySeed` | `src/hsm/pkcs11.rs:43` | Currently an unconditional stub error; real PKCS#11 session/entropy behaviour is unspecifiable until the FFI is wired in. |
| `pkcs11HsmProviderSign` | `src/hsm/pkcs11.rs:49` | Stub; real behaviour depends on unimplemented PKCS#11 FFI signing call. |
| `pkcs11HsmProviderVerify` | `src/hsm/pkcs11.rs:55` | Stub; real behaviour depends on unimplemented PKCS#11 FFI verify call. |
| `pkcs11HsmProviderGenerateKeypair` | `src/hsm/pkcs11.rs:63` | Stub; depends on unimplemented PKCS#11 key generation FFI. |
| `pkcs11HsmProviderSignCapability` | `src/hsm/pkcs11.rs:69` | Stub; depends on unimplemented PKCS#11 per-slot signing FFI. |
| `pkcs11HsmProviderVerifyCapabilitySignature` | `src/hsm/pkcs11.rs:75` | Stub; depends on unimplemented PKCS#11 per-slot verify FFI. |
| `pkcs11HsmProviderListKeys` | `src/hsm/pkcs11.rs:86` | Stub; depends on unimplemented PKCS#11 object enumeration FFI. |
| `pkcs11HsmProviderRotateKey` | `src/hsm/pkcs11.rs:92` | Stub; depends on unimplemented PKCS#11 key rotation FFI. |
| `yubiHsmProviderNewStub` | `src/hsm/yubihsm.rs:41` | Trivial pure constructor, tagged for consistency with the hardware-backend constructors (placeholder for a future opaque USB/HTTP session). |
| `yubiHsmProviderGenerateCapabilitySeed` | `src/hsm/yubihsm.rs:47` | Stub; real behaviour depends on unimplemented `YubiHSM` client FFI/entropy. |
| `yubiHsmProviderSign` | `src/hsm/yubihsm.rs:53` | Stub; depends on unimplemented `YubiHSM` `sign_ed25519` call. |
| `yubiHsmProviderVerify` | `src/hsm/yubihsm.rs:59` | Stub; depends on unimplemented `YubiHSM` public-key retrieval + verify. |
| `yubiHsmProviderGenerateKeypair` | `src/hsm/yubihsm.rs:67` | Stub; depends on unimplemented `YubiHSM` `generate_asymmetric_key` call. |
| `yubiHsmProviderSignCapability` | `src/hsm/yubihsm.rs:73` | Stub; depends on unimplemented `YubiHSM` per-slot signing call. |
| `yubiHsmProviderVerifyCapabilitySignature` | `src/hsm/yubihsm.rs:79` | Stub; depends on unimplemented `YubiHSM` per-slot verify call. |
| `yubiHsmProviderListKeys` | `src/hsm/yubihsm.rs:90` | Stub; depends on unimplemented `YubiHSM` object enumeration call. |
| `yubiHsmProviderRotateKey` | `src/hsm/yubihsm.rs:96` | Stub; depends on unimplemented `YubiHSM` key rotation call. |

Note: the table above lists every tagged function; a small number of purely
structural/trivial functions (e.g. the `KeyHandle` newtype's own field
access, which Rust exposes as a public tuple field rather than a method) are
not separately tagged because they have no corresponding `fn` in the source.
-/

namespace FunctionSpecs

-- ── Local domain types (not yet in Core.lean) ─────────────────────────────────

/-- Mirrors `KeyHandle(pub [u8; 32])` (`src/hsm/mod.rs:62`) — an opaque handle
    to a key slot, documented as the SHA-256 hash of the slot's Ed25519
    verifying key.  Modelled as its raw bytes for this spec layer; the
    "is a SHA-256 hash of some verifying key" relationship is not enforced
    here (would require modelling SHA-256). -/
structure KeyHandleT where
  bytes : List Nat
  deriving DecidableEq, Repr

/-- Mirrors `crate::auth::capability::Capability` (`src/auth/capability.rs`,
    outside this file's scope) — treated as a fully opaque token here.  Only
    used as an argument/field type by `HsmSignedCapability`; this file does
    not attempt to model its internal accessor methods
    (`issuer`/`target`/`rights_bits`/`generation_raw`/`nonce_raw`), which
    belong to the `auth` module's own spec file. -/
opaque CapabilityT : Type

/-- Mirrors `HsmSignedCapability` (`src/hsm/mod.rs:195`) — a capability token
    paired with the `KeyHandle` that signed it and the resulting 64-byte
    Ed25519 signature. -/
structure HsmSignedCapabilityT where
  inner : CapabilityT
  keyHandle : KeyHandleT
  signature : List Nat
  deriving Repr

/-- Opaque receiver type for `SoftwareKeyStore` (`src/hsm/keystore.rs:59`) —
    holds an optional primary signing key plus a mutex-guarded handle→key
    table.  Internal structure (the `HashMap`, the `Mutex`, the raw
    `SigningKey` bytes) is not modelled; the receiver is treated as an
    opaque token whose state evolves only through the methods specified
    below. -/
opaque SoftwareKeyStoreT : Type

/-- Opaque receiver type for `SoftwareHsm` (`src/hsm/mock.rs:25`) — holds a
    verifying key and an optional signing key.  Internal cryptographic key
    material is not modelled. -/
opaque SoftwareHsmT : Type

/-- Opaque receiver type for `Pkcs11HsmProvider` (`src/hsm/pkcs11.rs:27`) —
    currently just an optional library path; modelled as opaque since it is
    a placeholder for a future real PKCS#11 session object. -/
opaque Pkcs11HsmProviderT : Type

/-- Opaque receiver type for `YubiHsmProvider` (`src/hsm/yubihsm.rs:32`) —
    currently just a `_connected : bool` placeholder; modelled as opaque
    since it is a placeholder for a future real hardware session object. -/
opaque YubiHsmProviderT : Type

-- ── `src/hsm/mod.rs` — `KeyHandle` ────────────────────────────────────────────

-- REFINEMENT_GAP: src/hsm/mod.rs:71 — Mutates raw key bytes in place via the
-- `zeroize` crate; the "bytes are overwritten" guarantee is a memory-safety
-- property, not a pure Lean predicate over `List Nat`.
/-- Rust: `impl Zeroize for KeyHandle { fn zeroize(&mut self) }`
    (`src/hsm/mod.rs:70-74`).  Overwrites the 32-byte handle with zero bytes
    in place. -/
opaque keyHandleZeroize (h : KeyHandleT) : KeyHandleT × Unit

def keyHandleZeroize_pre (_h : KeyHandleT) : Prop := True

def keyHandleZeroize_post (_h : KeyHandleT) (r : KeyHandleT × Unit) : Prop :=
  (r.1.bytes.length = 32 → r.1.bytes = List.replicate 32 0)

-- ── `src/hsm/mod.rs` — `HsmProvider` trait contract ───────────────────────────

-- REFINEMENT_GAP: src/hsm/mod.rs:98 — Cryptographic entropy contract ("32
-- bytes computationally unpredictable to an adversary") is not a pure-Lean
-- predicate; hardware TRNG / deterministic-mock behaviour is implementation-
-- specific and specified per-backend below instead.
/-- Rust: `trait HsmProvider { fn generate_capability_seed(&self) -> Result<[u8; 32]> }`
    (`src/hsm/mod.rs:98`).  Generic trait-level contract; concrete backends
    (`SoftwareHsm`, `SoftwareKeyStore`, `Pkcs11HsmProvider`, `YubiHsmProvider`)
    are specified individually below with their own `_pre`/`_post`. -/
opaque hsmProviderGenerateCapabilitySeed (self : Unit) : LuxResult (List Nat)

def hsmProviderGenerateCapabilitySeed_pre (_self : Unit) : Prop := True

def hsmProviderGenerateCapabilitySeed_post (_self : Unit) (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok bytes => bytes.length = 32
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:106 — Ed25519 signing; "produces a signature
-- that `verify` accepts" requires modelling elliptic-curve cryptography, out
-- of scope for this spec layer.
/-- Rust: `trait HsmProvider { fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/mod.rs:106`).  Generic trait-level contract. -/
opaque hsmProviderSign (self : Unit) (payload : List Nat) : LuxResult (List Nat)

def hsmProviderSign_pre (_self : Unit) (_payload : List Nat) : Prop := True

def hsmProviderSign_post (_self : Unit) (_payload : List Nat) (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok sig => sig.length = 64
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:114 — Ed25519 verification; cryptographic
-- soundness of the check is not modelled.
/-- Rust: `trait HsmProvider { fn verify(&self, payload: &[u8], sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/mod.rs:114`).  Generic trait-level contract. -/
opaque hsmProviderVerify (self : Unit) (payload : List Nat) (sig : List Nat) : LuxResult Unit

def hsmProviderVerify_pre (_self : Unit) (_payload : List Nat) (sig : List Nat) : Prop :=
  sig.length = 64

def hsmProviderVerify_post (_self : Unit) (_payload : List Nat) (_sig : List Nat)
    (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- ── `src/hsm/mod.rs` — `KeyManagement` trait contract ─────────────────────────

-- REFINEMENT_GAP: src/hsm/mod.rs:138 — Keypair generation depends on
-- hardware/OS entropy and mutex state, neither modelled here.
/-- Rust: `trait KeyManagement { fn generate_keypair(&self) -> Result<KeyHandle> }`
    (`src/hsm/mod.rs:138`).  Generic trait-level contract. -/
opaque keyManagementGenerateKeypair (self : Unit) : LuxResult KeyHandleT

def keyManagementGenerateKeypair_pre (_self : Unit) : Prop := True

def keyManagementGenerateKeypair_post (_self : Unit) (r : LuxResult KeyHandleT) : Prop :=
  match r with
  | .ok h => h.bytes.length = 32
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:147 — Per-slot Ed25519 signing; same
-- cryptographic gap as `HsmProvider::sign`.
/-- Rust: `trait KeyManagement { fn sign_capability(&self, handle: &KeyHandle, payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/mod.rs:147`).  Generic trait-level contract. -/
opaque keyManagementSignCapability (self : Unit) (handle : KeyHandleT) (payload : List Nat) :
    LuxResult (List Nat)

def keyManagementSignCapability_pre (_self : Unit) (handle : KeyHandleT) (_payload : List Nat) :
    Prop := handle.bytes.length = 32

def keyManagementSignCapability_post (_self : Unit) (_handle : KeyHandleT) (_payload : List Nat)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok sig => sig.length = 64
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:158 — Per-slot Ed25519 verification; same
-- cryptographic gap as `HsmProvider::verify`.
/-- Rust: `trait KeyManagement { fn verify_capability_signature(&self, handle: &KeyHandle, payload: &[u8], sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/mod.rs:158`).  Generic trait-level contract. -/
opaque keyManagementVerifyCapabilitySignature (self : Unit) (handle : KeyHandleT)
    (payload : List Nat) (sig : List Nat) : LuxResult Unit

def keyManagementVerifyCapabilitySignature_pre (_self : Unit) (handle : KeyHandleT)
    (_payload : List Nat) (sig : List Nat) : Prop :=
  handle.bytes.length = 32 ∧ sig.length = 64

def keyManagementVerifyCapabilitySignature_post (_self : Unit) (_handle : KeyHandleT)
    (_payload : List Nat) (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error (.CapabilityDenied _) => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:171 — Depends on opaque internal key-table
-- / mutex state not modelled in this layer.
/-- Rust: `trait KeyManagement { fn list_keys(&self) -> Result<Vec<KeyHandle>> }`
    (`src/hsm/mod.rs:171`).  Generic trait-level contract. -/
opaque keyManagementListKeys (self : Unit) : LuxResult (List KeyHandleT)

def keyManagementListKeys_pre (_self : Unit) : Prop := True

def keyManagementListKeys_post (_self : Unit) (r : LuxResult (List KeyHandleT)) : Prop :=
  match r with
  | .ok handles => handles.all (fun h => h.bytes.length = 32)
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:183 — Combines keypair generation
-- (hardware/OS entropy) with atomic slot replacement (mutex state); neither
-- modelled.
/-- Rust: `trait KeyManagement { fn rotate_key(&self, handle: &KeyHandle) -> Result<KeyHandle> }`
    (`src/hsm/mod.rs:183`).  On success, the old `handle` becomes invalid and
    a new handle is returned. -/
opaque keyManagementRotateKey (self : Unit) (handle : KeyHandleT) : LuxResult KeyHandleT

def keyManagementRotateKey_pre (_self : Unit) (handle : KeyHandleT) : Prop :=
  handle.bytes.length = 32

def keyManagementRotateKey_post (_self : Unit) (handle : KeyHandleT) (r : LuxResult KeyHandleT) :
    Prop :=
  match r with
  | .ok newHandle => newHandle.bytes.length = 32 ∧ newHandle ≠ handle
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- ── `src/hsm/mod.rs` — `HsmSignedCapability` impl block ───────────────────────

-- REFINEMENT_GAP: src/hsm/mod.rs:215 — Delegates to `sign_capability`;
-- inherits its hardware/cryptographic gap.
/-- Rust: `impl HsmSignedCapability { pub fn sign<H: HsmProvider + KeyManagement>(cap: Capability, handle: &KeyHandle, hsm: &H) -> Result<Self> }`
    (`src/hsm/mod.rs:215`).  Signs the canonical 28-byte payload derived from
    `cap` with the key identified by `handle`, via `hsm.sign_capability`. -/
opaque hsmSignedCapabilitySign (cap : CapabilityT) (handle : KeyHandleT) (hsm : Unit) :
    LuxResult HsmSignedCapabilityT

def hsmSignedCapabilitySign_pre (_cap : CapabilityT) (handle : KeyHandleT) (_hsm : Unit) : Prop :=
  handle.bytes.length = 32

def hsmSignedCapabilitySign_post (cap : CapabilityT) (handle : KeyHandleT) (_hsm : Unit)
    (r : LuxResult HsmSignedCapabilityT) : Prop :=
  match r with
  | .ok signed => signed.inner = cap ∧ signed.keyHandle = handle ∧ signed.signature.length = 64
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:236 — Delegates to
-- `verify_capability_signature`; inherits its hardware/cryptographic gap.
/-- Rust: `impl HsmSignedCapability { pub fn verify<H: HsmProvider + KeyManagement>(&self, hsm: &H) -> Result<()> }`
    (`src/hsm/mod.rs:236`).  Verifies `self.signature` against the canonical
    payload of `self.inner` under `self.key_handle`, via
    `hsm.verify_capability_signature`. -/
opaque hsmSignedCapabilityVerify (self : HsmSignedCapabilityT) (hsm : Unit) : LuxResult Unit

def hsmSignedCapabilityVerify_pre (self : HsmSignedCapabilityT) (_hsm : Unit) : Prop :=
  self.keyHandle.bytes.length = 32 ∧ self.signature.length = 64

def hsmSignedCapabilityVerify_post (_self : HsmSignedCapabilityT) (_hsm : Unit)
    (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error (.CapabilityDenied _) => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mod.rs:242 — Pure byte-layout function, but depends
-- on opaque `Capability` accessor fields (`issuer`/`target`/`rights_bits`/
-- `generation_raw`/`nonce_raw`) defined outside this file's scope
-- (`src/auth/capability.rs`); only a structural (length) postcondition is
-- given here.
/-- Rust: `impl HsmSignedCapability { fn cap_payload(cap: &Capability) -> [u8; 28] }`
    (`src/hsm/mod.rs:242`).  Computes the canonical 28-byte signing payload:
    `issuer_le32 || target_le32 || rights_le32 || generation_le64 || nonce_le64`. -/
opaque hsmSignedCapabilityCapPayload (cap : CapabilityT) : List Nat

def hsmSignedCapabilityCapPayload_pre (_cap : CapabilityT) : Prop := True

def hsmSignedCapabilityCapPayload_post (_cap : CapabilityT) (r : List Nat) : Prop :=
  r.length = 28

-- ── `src/hsm/mod.rs` — free function ──────────────────────────────────────────

-- REFINEMENT_GAP: src/hsm/mod.rs:260 — Trivial delegate to
-- `SoftwareKeyStore::new`; inherits that constructor's opaque mutex/heap-
-- table-state gap.
/-- Rust: `pub fn default_hsm() -> keystore::SoftwareKeyStore` (`src/hsm/mod.rs:260`).
    Constructs a `SoftwareKeyStore` with no primary signing key pre-loaded. -/
opaque defaultHsm : SoftwareKeyStoreT

def defaultHsm_pre : Prop := True

def defaultHsm_post (_r : SoftwareKeyStoreT) : Prop := True

-- ── `src/hsm/keystore.rs` — `ZeroizingSigningKey` ─────────────────────────────

-- REFINEMENT_GAP: src/hsm/keystore.rs:26 — Side-effecting `Drop` impl that
-- overwrites secret Ed25519 key material with an all-zero placeholder before
-- deallocation; the "secret bytes are overwritten" memory-zeroization
-- guarantee is not expressible as a pure Lean postcondition.
/-- Rust: `impl Drop for ZeroizingSigningKey { fn drop(&mut self) }`
    (`src/hsm/keystore.rs:26-33`).  Replaces the wrapped `SigningKey` with an
    all-zero placeholder immediately before the value is dropped. -/
opaque zeroizingSigningKeyDrop (self : Unit) : Unit × Unit

def zeroizingSigningKeyDrop_pre (_self : Unit) : Prop := True

def zeroizingSigningKeyDrop_post (_self : Unit) (_r : Unit × Unit) : Prop := True

-- REFINEMENT_GAP: src/hsm/keystore.rs:37 — `Debug` formatting of a redacted
-- placeholder string; trivial, but tagged since it touches the secret-
-- bearing wrapper type and the exact formatter contract is not modelled.
/-- Rust: `impl fmt::Debug for ZeroizingSigningKey { fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result }`
    (`src/hsm/keystore.rs:36-40`).  Always writes the literal string
    `"ZeroizingSigningKey([redacted])"`, never the real key material. -/
opaque zeroizingSigningKeyFmt (self : Unit) : LuxResult Unit

def zeroizingSigningKeyFmt_pre (_self : Unit) : Prop := True

def zeroizingSigningKeyFmt_post (_self : Unit) (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error _ => False

-- ── `src/hsm/keystore.rs` — `SoftwareKeyStore` inherent impl ──────────────────

-- REFINEMENT_GAP: src/hsm/keystore.rs:69 — Constructs a `Mutex<HashMap>`;
-- the mutex/heap-table's initial state is opaque in this layer (no
-- "list of keys" relation is asserted, only that the store is freshly
-- constructed).
/-- Rust: `impl SoftwareKeyStore { pub fn new() -> Self }` (`src/hsm/keystore.rs:69`).
    Constructs an empty key store with no primary signing key. -/
opaque softwareKeyStoreNew : SoftwareKeyStoreT

def softwareKeyStoreNew_pre : Prop := True

def softwareKeyStoreNew_post (_r : SoftwareKeyStoreT) : Prop := True

-- REFINEMENT_GAP: src/hsm/keystore.rs:78 — Ed25519 key derivation from seed
-- bytes (`SigningKey::from_bytes`) is cryptographic and not modelled.
/-- Rust: `impl SoftwareKeyStore { pub fn with_signing_key(seed: [u8; 32]) -> Self }`
    (`src/hsm/keystore.rs:78`).  Constructs a key store whose primary signing
    key is derived from the given 32-byte seed. -/
opaque softwareKeyStoreWithSigningKey (seed : List Nat) : SoftwareKeyStoreT

def softwareKeyStoreWithSigningKey_pre (seed : List Nat) : Prop := seed.length = 32

def softwareKeyStoreWithSigningKey_post (_seed : List Nat) (_r : SoftwareKeyStoreT) : Prop := True

-- REFINEMENT_GAP: src/hsm/keystore.rs:87 — Derives a verifying key from a
-- signing key via elliptic-curve scalar multiplication; cryptographic
-- derivation not modelled.
/-- Rust: `impl SoftwareKeyStore { pub fn verifying_key_bytes(&self) -> Option<[u8; 32]> }`
    (`src/hsm/keystore.rs:87`).  Returns the primary key's verifying-key
    bytes, or `None` if no primary key is configured. -/
opaque softwareKeyStoreVerifyingKeyBytes (self : SoftwareKeyStoreT) : Option (List Nat)

def softwareKeyStoreVerifyingKeyBytes_pre (_self : SoftwareKeyStoreT) : Prop := True

def softwareKeyStoreVerifyingKeyBytes_post (_self : SoftwareKeyStoreT) (r : Option (List Nat)) :
    Prop :=
  match r with
  | some bytes => bytes.length = 32
  | none => True

-- REFINEMENT_GAP: src/hsm/keystore.rs:96 — Delegates to `new`; inherits its
-- mutex/heap-state gap.
/-- Rust: `impl Default for SoftwareKeyStore { fn default() -> Self }`
    (`src/hsm/keystore.rs:94-98`).  Equivalent to `SoftwareKeyStore::new()`. -/
opaque softwareKeyStoreDefault : SoftwareKeyStoreT

def softwareKeyStoreDefault_pre : Prop := True

def softwareKeyStoreDefault_post (_r : SoftwareKeyStoreT) : Prop := True

-- ── `src/hsm/keystore.rs` — `HsmProvider for SoftwareKeyStore` ────────────────

-- REFINEMENT_GAP: src/hsm/keystore.rs:101 — OS CSPRNG (`OsRng`) plus optional
-- SHA-256 mixing with primary-key material; entropy source and hash
-- function not modelled.
/-- Rust: `impl HsmProvider for SoftwareKeyStore { fn generate_capability_seed(&self) -> Result<[u8; 32]> }`
    (`src/hsm/keystore.rs:101`).  Fills 32 bytes from the OS CSPRNG; if a
    primary key is configured, mixes its verifying-key bytes in via SHA-256.
    Always succeeds (no documented `Err` path). -/
opaque softwareKeyStoreGenerateCapabilitySeed (self : SoftwareKeyStoreT) :
    LuxResult (List Nat)

def softwareKeyStoreGenerateCapabilitySeed_pre (_self : SoftwareKeyStoreT) : Prop := True

def softwareKeyStoreGenerateCapabilitySeed_post (_self : SoftwareKeyStoreT)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok bytes => bytes.length = 32
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/keystore.rs:114 — Ed25519 signing with the primary
-- key; cryptographic operation not modelled.
/-- Rust: `impl HsmProvider for SoftwareKeyStore { fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/keystore.rs:114`).  Signs with the primary key if configured;
    otherwise returns `Err(CapabilityDenied)`. -/
opaque softwareKeyStoreSign (self : SoftwareKeyStoreT) (payload : List Nat) :
    LuxResult (List Nat)

def softwareKeyStoreSign_pre (_self : SoftwareKeyStoreT) (_payload : List Nat) : Prop := True

def softwareKeyStoreSign_post (_self : SoftwareKeyStoreT) (_payload : List Nat)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok sig => sig.length = 64
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/keystore.rs:124 — Ed25519 verification with the
-- primary key; cryptographic soundness not modelled.
/-- Rust: `impl HsmProvider for SoftwareKeyStore { fn verify(&self, payload: &[u8], sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/keystore.rs:124`).  Verifies against the primary key if
    configured; `Err(ManifestInvalid)` if no primary key or verification
    fails. -/
opaque softwareKeyStoreVerify (self : SoftwareKeyStoreT) (payload : List Nat) (sig : List Nat) :
    LuxResult Unit

def softwareKeyStoreVerify_pre (_self : SoftwareKeyStoreT) (_payload : List Nat) (sig : List Nat) :
    Prop := sig.length = 64

def softwareKeyStoreVerify_post (_self : SoftwareKeyStoreT) (_payload : List Nat)
    (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- ── `src/hsm/keystore.rs` — `KeyManagement for SoftwareKeyStore` ──────────────

-- REFINEMENT_GAP: src/hsm/keystore.rs:142 — OS CSPRNG, SHA-256 handle
-- derivation, and mutex-guarded `HashMap` insert; none modelled.
/-- Rust: `impl KeyManagement for SoftwareKeyStore { fn generate_keypair(&self) -> Result<KeyHandle> }`
    (`src/hsm/keystore.rs:142`).  Generates a fresh Ed25519 keypair from OS
    entropy, derives its handle as SHA-256 of the verifying key, inserts it
    into the key table, and returns the handle.  `Err(CapabilityDenied)` if
    the key-table mutex is poisoned. -/
opaque softwareKeyStoreGenerateKeypair (self : SoftwareKeyStoreT) :
    LuxResult (SoftwareKeyStoreT × KeyHandleT)

def softwareKeyStoreGenerateKeypair_pre (_self : SoftwareKeyStoreT) : Prop := True

def softwareKeyStoreGenerateKeypair_post (_self : SoftwareKeyStoreT)
    (r : LuxResult (SoftwareKeyStoreT × KeyHandleT)) : Prop :=
  match r with
  | .ok (_, h) => h.bytes.length = 32
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/keystore.rs:163 — Mutex-guarded lookup plus
-- Ed25519 signing; both the mutex state and the cryptographic operation are
-- unmodelled.
/-- Rust: `impl KeyManagement for SoftwareKeyStore { fn sign_capability(&self, handle: &KeyHandle, payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/keystore.rs:163`).  Looks up `handle` in the key table and
    signs `payload` with the corresponding key.  `Err(CapabilityDenied)` if
    the mutex is poisoned or `handle` is not found. -/
opaque softwareKeyStoreSignCapability (self : SoftwareKeyStoreT) (handle : KeyHandleT)
    (payload : List Nat) : LuxResult (List Nat)

def softwareKeyStoreSignCapability_pre (_self : SoftwareKeyStoreT) (handle : KeyHandleT)
    (_payload : List Nat) : Prop := handle.bytes.length = 32

def softwareKeyStoreSignCapability_post (_self : SoftwareKeyStoreT) (_handle : KeyHandleT)
    (_payload : List Nat) (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok sig => sig.length = 64
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/keystore.rs:176 — Mutex-guarded lookup plus
-- Ed25519 verification; both gaps apply.
/-- Rust: `impl KeyManagement for SoftwareKeyStore { fn verify_capability_signature(&self, handle: &KeyHandle, payload: &[u8], sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/keystore.rs:176`).  Looks up `handle`'s verifying key and
    checks `sig` over `payload`.  `Err(CapabilityDenied)` if the mutex is
    poisoned or `handle` is not found; `Err(ManifestInvalid)` if the
    signature does not verify. -/
opaque softwareKeyStoreVerifyCapabilitySignature (self : SoftwareKeyStoreT) (handle : KeyHandleT)
    (payload : List Nat) (sig : List Nat) : LuxResult Unit

def softwareKeyStoreVerifyCapabilitySignature_pre (_self : SoftwareKeyStoreT)
    (handle : KeyHandleT) (_payload : List Nat) (sig : List Nat) : Prop :=
  handle.bytes.length = 32 ∧ sig.length = 64

def softwareKeyStoreVerifyCapabilitySignature_post (_self : SoftwareKeyStoreT)
    (_handle : KeyHandleT) (_payload : List Nat) (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error (.CapabilityDenied _) => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/keystore.rs:201 — Mutex-guarded `HashMap`
-- iteration; internal table state opaque in this layer.
/-- Rust: `impl KeyManagement for SoftwareKeyStore { fn list_keys(&self) -> Result<Vec<KeyHandle>> }`
    (`src/hsm/keystore.rs:201`).  Returns all handles currently in the key
    table.  `Err(CapabilityDenied)` if the mutex is poisoned. -/
opaque softwareKeyStoreListKeys (self : SoftwareKeyStoreT) : LuxResult (List KeyHandleT)

def softwareKeyStoreListKeys_pre (_self : SoftwareKeyStoreT) : Prop := True

def softwareKeyStoreListKeys_post (_self : SoftwareKeyStoreT) (r : LuxResult (List KeyHandleT)) :
    Prop :=
  match r with
  | .ok handles => handles.all (fun h => h.bytes.length = 32)
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/keystore.rs:208 — OS CSPRNG, SHA-256 derivation,
-- and mutex-guarded atomic remove+insert; none modelled.
/-- Rust: `impl KeyManagement for SoftwareKeyStore { fn rotate_key(&self, handle: &KeyHandle) -> Result<KeyHandle> }`
    (`src/hsm/keystore.rs:208`).  Generates a fresh keypair, and if `handle`
    is present in the key table, atomically removes the old entry and
    inserts the new one, returning the new handle.  `Err(CapabilityDenied)`
    if the mutex is poisoned or `handle` is not found (checked after
    generating the new key, but the new key is only inserted on success). -/
opaque softwareKeyStoreRotateKey (self : SoftwareKeyStoreT) (handle : KeyHandleT) :
    LuxResult (SoftwareKeyStoreT × KeyHandleT)

def softwareKeyStoreRotateKey_pre (_self : SoftwareKeyStoreT) (handle : KeyHandleT) : Prop :=
  handle.bytes.length = 32

def softwareKeyStoreRotateKey_post (_self : SoftwareKeyStoreT) (handle : KeyHandleT)
    (r : LuxResult (SoftwareKeyStoreT × KeyHandleT)) : Prop :=
  match r with
  | .ok (_, newHandle) => newHandle.bytes.length = 32 ∧ newHandle ≠ handle
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- ── `src/hsm/mock.rs` — `SoftwareHsm` inherent impl ───────────────────────────

-- REFINEMENT_GAP: src/hsm/mock.rs:40 — Validates raw bytes as an Ed25519
-- curve point (`VerifyingKey::from_bytes`); curve-membership checking is
-- cryptographic and not modelled.
/-- Rust: `impl SoftwareHsm { pub fn from_verifying_key(bytes: [u8; 32]) -> Result<Self> }`
    (`src/hsm/mock.rs:40`).  Constructs a verify-only provider.  `sign` will
    return `Err` on instances built this way.  `Err(ManifestInvalid)` if
    `bytes` is not a valid Ed25519 public key. -/
opaque softwareHsmFromVerifyingKey (bytes : List Nat) : LuxResult SoftwareHsmT

def softwareHsmFromVerifyingKey_pre (bytes : List Nat) : Prop := bytes.length = 32

def softwareHsmFromVerifyingKey_post (_bytes : List Nat) (r : LuxResult SoftwareHsmT) : Prop :=
  match r with
  | .ok _ => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mock.rs:56 — Ed25519 key derivation from a 32-byte
-- seed; cryptographic derivation not modelled.
/-- Rust: `impl SoftwareHsm { pub fn from_signing_key(seed: [u8; 32]) -> Self }`
    (`src/hsm/mock.rs:56`).  Constructs a full sign+verify provider; the
    verifying key is derived deterministically from `seed`.  Infallible. -/
opaque softwareHsmFromSigningKey (seed : List Nat) : SoftwareHsmT

def softwareHsmFromSigningKey_pre (seed : List Nat) : Prop := seed.length = 32

def softwareHsmFromSigningKey_post (_seed : List Nat) (_r : SoftwareHsmT) : Prop := True

-- REFINEMENT_GAP: src/hsm/mock.rs:67 — Pure accessor, but the underlying
-- `VerifyingKey` byte encoding is a cryptographic library detail; tagged for
-- consistency with the other key-byte accessors in this file.
/-- Rust: `impl SoftwareHsm { pub fn verifying_key_bytes(&self) -> [u8; 32] }`
    (`src/hsm/mock.rs:67`).  Returns the raw 32-byte verifying key. -/
opaque softwareHsmVerifyingKeyBytes (self : SoftwareHsmT) : List Nat

def softwareHsmVerifyingKeyBytes_pre (_self : SoftwareHsmT) : Prop := True

def softwareHsmVerifyingKeyBytes_post (_self : SoftwareHsmT) (r : List Nat) : Prop :=
  r.length = 32

-- ── `src/hsm/mock.rs` — `HsmProvider for SoftwareHsm` ─────────────────────────

-- REFINEMENT_GAP: src/hsm/mock.rs:73 — SHA-256 digest of the verifying-key
-- bytes; hash function not modelled.  Also documented as deterministic
-- (not hardware-entropy-backed), unlike a real HSM.
/-- Rust: `impl HsmProvider for SoftwareHsm { fn generate_capability_seed(&self) -> Result<[u8; 32]> }`
    (`src/hsm/mock.rs:73`).  Returns SHA-256 of the verifying key bytes —
    deterministic given the same key, documented as a test-only limitation.
    Always succeeds. -/
opaque softwareHsmGenerateCapabilitySeed (self : SoftwareHsmT) : LuxResult (List Nat)

def softwareHsmGenerateCapabilitySeed_pre (_self : SoftwareHsmT) : Prop := True

def softwareHsmGenerateCapabilitySeed_post (_self : SoftwareHsmT) (r : LuxResult (List Nat)) :
    Prop :=
  match r with
  | .ok bytes => bytes.length = 32
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mock.rs:81 — Ed25519 signing; cryptographic
-- operation not modelled.
/-- Rust: `impl HsmProvider for SoftwareHsm { fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/mock.rs:81`).  Signs with the configured signing key.
    `Err(CapabilityDenied)` if constructed via `from_verifying_key` (no
    signing key). -/
opaque softwareHsmSign (self : SoftwareHsmT) (payload : List Nat) : LuxResult (List Nat)

def softwareHsmSign_pre (_self : SoftwareHsmT) (_payload : List Nat) : Prop := True

def softwareHsmSign_post (_self : SoftwareHsmT) (_payload : List Nat) (r : LuxResult (List Nat)) :
    Prop :=
  match r with
  | .ok sig => sig.length = 64
  | .error (.CapabilityDenied _) => True
  | .error _ => False

-- REFINEMENT_GAP: src/hsm/mock.rs:91 — Ed25519 verification; cryptographic
-- soundness not modelled.
/-- Rust: `impl HsmProvider for SoftwareHsm { fn verify(&self, payload: &[u8], sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/mock.rs:91`).  Verifies `sig` over `payload` against the
    provider's verifying key.  `Err(ManifestInvalid)` on any failure. -/
opaque softwareHsmVerify (self : SoftwareHsmT) (payload : List Nat) (sig : List Nat) :
    LuxResult Unit

def softwareHsmVerify_pre (_self : SoftwareHsmT) (_payload : List Nat) (sig : List Nat) : Prop :=
  sig.length = 64

def softwareHsmVerify_post (_self : SoftwareHsmT) (_payload : List Nat) (_sig : List Nat)
    (r : LuxResult Unit) : Prop :=
  match r with
  | .ok () => True
  | .error (.ManifestInvalid _) => True
  | .error _ => False

-- ── `src/hsm/pkcs11.rs` — `Pkcs11HsmProvider` ─────────────────────────────────

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:35 — Trivial pure constructor in Rust,
-- but models a placeholder for a future opaque hardware-session/library-path
-- resource; tagged for consistency with the other hardware-backend
-- constructors.
/-- Rust: `impl Pkcs11HsmProvider { pub const fn new_stub(library_path: Option<PathBuf>) -> Self }`
    (`src/hsm/pkcs11.rs:35`).  Constructs a stub provider; `library_path` is
    stored but unused until a real PKCS#11 library is wired in. -/
opaque pkcs11HsmProviderNewStub (libraryPath : Option String) : Pkcs11HsmProviderT

def pkcs11HsmProviderNewStub_pre (_libraryPath : Option String) : Prop := True

def pkcs11HsmProviderNewStub_post (_libraryPath : Option String) (_r : Pkcs11HsmProviderT) :
    Prop := True

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:43 — Currently an unconditional stub
-- error; real PKCS#11 session/entropy behaviour is unspecifiable until the
-- FFI is wired in.
/-- Rust: `impl HsmProvider for Pkcs11HsmProvider { fn generate_capability_seed(&self) -> Result<[u8; 32]> }`
    (`src/hsm/pkcs11.rs:43`).  Stub: unconditionally returns
    `Err(CapabilityDenied)` ("no PKCS#11 session open"). -/
opaque pkcs11HsmProviderGenerateCapabilitySeed (self : Pkcs11HsmProviderT) :
    LuxResult (List Nat)

def pkcs11HsmProviderGenerateCapabilitySeed_pre (_self : Pkcs11HsmProviderT) : Prop := True

def pkcs11HsmProviderGenerateCapabilitySeed_post (_self : Pkcs11HsmProviderT)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:49 — Stub; real behaviour depends on
-- unimplemented PKCS#11 FFI signing call.
/-- Rust: `impl HsmProvider for Pkcs11HsmProvider { fn sign(&self, _payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/pkcs11.rs:49`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque pkcs11HsmProviderSign (self : Pkcs11HsmProviderT) (payload : List Nat) :
    LuxResult (List Nat)

def pkcs11HsmProviderSign_pre (_self : Pkcs11HsmProviderT) (_payload : List Nat) : Prop := True

def pkcs11HsmProviderSign_post (_self : Pkcs11HsmProviderT) (_payload : List Nat)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:55 — Stub; real behaviour depends on
-- unimplemented PKCS#11 FFI verify call.
/-- Rust: `impl HsmProvider for Pkcs11HsmProvider { fn verify(&self, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/pkcs11.rs:55`).  Stub: unconditionally returns
    `Err(ManifestInvalid)`. -/
opaque pkcs11HsmProviderVerify (self : Pkcs11HsmProviderT) (payload : List Nat)
    (sig : List Nat) : LuxResult Unit

def pkcs11HsmProviderVerify_pre (_self : Pkcs11HsmProviderT) (_payload : List Nat)
    (_sig : List Nat) : Prop := True

def pkcs11HsmProviderVerify_post (_self : Pkcs11HsmProviderT) (_payload : List Nat)
    (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .error (.ManifestInvalid _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:63 — Stub; depends on unimplemented
-- PKCS#11 key generation FFI.
/-- Rust: `impl KeyManagement for Pkcs11HsmProvider { fn generate_keypair(&self) -> Result<KeyHandle> }`
    (`src/hsm/pkcs11.rs:63`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque pkcs11HsmProviderGenerateKeypair (self : Pkcs11HsmProviderT) : LuxResult KeyHandleT

def pkcs11HsmProviderGenerateKeypair_pre (_self : Pkcs11HsmProviderT) : Prop := True

def pkcs11HsmProviderGenerateKeypair_post (_self : Pkcs11HsmProviderT)
    (r : LuxResult KeyHandleT) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:69 — Stub; depends on unimplemented
-- PKCS#11 per-slot signing FFI.
/-- Rust: `impl KeyManagement for Pkcs11HsmProvider { fn sign_capability(&self, _handle: &KeyHandle, _payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/pkcs11.rs:69`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque pkcs11HsmProviderSignCapability (self : Pkcs11HsmProviderT) (handle : KeyHandleT)
    (payload : List Nat) : LuxResult (List Nat)

def pkcs11HsmProviderSignCapability_pre (_self : Pkcs11HsmProviderT) (_handle : KeyHandleT)
    (_payload : List Nat) : Prop := True

def pkcs11HsmProviderSignCapability_post (_self : Pkcs11HsmProviderT) (_handle : KeyHandleT)
    (_payload : List Nat) (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:75 — Stub; depends on unimplemented
-- PKCS#11 per-slot verify FFI.
/-- Rust: `impl KeyManagement for Pkcs11HsmProvider { fn verify_capability_signature(&self, _handle: &KeyHandle, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/pkcs11.rs:75`).  Stub: unconditionally returns
    `Err(ManifestInvalid)`. -/
opaque pkcs11HsmProviderVerifyCapabilitySignature (self : Pkcs11HsmProviderT)
    (handle : KeyHandleT) (payload : List Nat) (sig : List Nat) : LuxResult Unit

def pkcs11HsmProviderVerifyCapabilitySignature_pre (_self : Pkcs11HsmProviderT)
    (_handle : KeyHandleT) (_payload : List Nat) (_sig : List Nat) : Prop := True

def pkcs11HsmProviderVerifyCapabilitySignature_post (_self : Pkcs11HsmProviderT)
    (_handle : KeyHandleT) (_payload : List Nat) (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .error (.ManifestInvalid _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:86 — Stub; depends on unimplemented
-- PKCS#11 object enumeration FFI.
/-- Rust: `impl KeyManagement for Pkcs11HsmProvider { fn list_keys(&self) -> Result<Vec<KeyHandle>> }`
    (`src/hsm/pkcs11.rs:86`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque pkcs11HsmProviderListKeys (self : Pkcs11HsmProviderT) : LuxResult (List KeyHandleT)

def pkcs11HsmProviderListKeys_pre (_self : Pkcs11HsmProviderT) : Prop := True

def pkcs11HsmProviderListKeys_post (_self : Pkcs11HsmProviderT)
    (r : LuxResult (List KeyHandleT)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/pkcs11.rs:92 — Stub; depends on unimplemented
-- PKCS#11 key rotation FFI.
/-- Rust: `impl KeyManagement for Pkcs11HsmProvider { fn rotate_key(&self, _handle: &KeyHandle) -> Result<KeyHandle> }`
    (`src/hsm/pkcs11.rs:92`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque pkcs11HsmProviderRotateKey (self : Pkcs11HsmProviderT) (handle : KeyHandleT) :
    LuxResult KeyHandleT

def pkcs11HsmProviderRotateKey_pre (_self : Pkcs11HsmProviderT) (_handle : KeyHandleT) : Prop :=
  True

def pkcs11HsmProviderRotateKey_post (_self : Pkcs11HsmProviderT) (_handle : KeyHandleT)
    (r : LuxResult KeyHandleT) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- ── `src/hsm/yubihsm.rs` — `YubiHsmProvider` ──────────────────────────────────

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:41 — Trivial pure constructor, tagged
-- for consistency with the other hardware-backend constructors (placeholder
-- for a future opaque USB/HTTP session).
/-- Rust: `impl YubiHsmProvider { pub const fn new_stub() -> Self }`
    (`src/hsm/yubihsm.rs:41`).  Constructs a stub provider with no hardware
    session open. -/
opaque yubiHsmProviderNewStub : YubiHsmProviderT

def yubiHsmProviderNewStub_pre : Prop := True

def yubiHsmProviderNewStub_post (_r : YubiHsmProviderT) : Prop := True

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:47 — Stub; real behaviour depends on
-- unimplemented `YubiHSM` client FFI/entropy.
/-- Rust: `impl HsmProvider for YubiHsmProvider { fn generate_capability_seed(&self) -> Result<[u8; 32]> }`
    (`src/hsm/yubihsm.rs:47`).  Stub: unconditionally returns
    `Err(CapabilityDenied)` ("hardware not connected"). -/
opaque yubiHsmProviderGenerateCapabilitySeed (self : YubiHsmProviderT) : LuxResult (List Nat)

def yubiHsmProviderGenerateCapabilitySeed_pre (_self : YubiHsmProviderT) : Prop := True

def yubiHsmProviderGenerateCapabilitySeed_post (_self : YubiHsmProviderT)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:53 — Stub; depends on unimplemented
-- `YubiHSM` `sign_ed25519` call.
/-- Rust: `impl HsmProvider for YubiHsmProvider { fn sign(&self, _payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/yubihsm.rs:53`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque yubiHsmProviderSign (self : YubiHsmProviderT) (payload : List Nat) :
    LuxResult (List Nat)

def yubiHsmProviderSign_pre (_self : YubiHsmProviderT) (_payload : List Nat) : Prop := True

def yubiHsmProviderSign_post (_self : YubiHsmProviderT) (_payload : List Nat)
    (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:59 — Stub; depends on unimplemented
-- `YubiHSM` public-key retrieval + verify.
/-- Rust: `impl HsmProvider for YubiHsmProvider { fn verify(&self, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/yubihsm.rs:59`).  Stub: unconditionally returns
    `Err(ManifestInvalid)`. -/
opaque yubiHsmProviderVerify (self : YubiHsmProviderT) (payload : List Nat) (sig : List Nat) :
    LuxResult Unit

def yubiHsmProviderVerify_pre (_self : YubiHsmProviderT) (_payload : List Nat)
    (_sig : List Nat) : Prop := True

def yubiHsmProviderVerify_post (_self : YubiHsmProviderT) (_payload : List Nat)
    (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .error (.ManifestInvalid _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:67 — Stub; depends on unimplemented
-- `YubiHSM` `generate_asymmetric_key` call.
/-- Rust: `impl KeyManagement for YubiHsmProvider { fn generate_keypair(&self) -> Result<KeyHandle> }`
    (`src/hsm/yubihsm.rs:67`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque yubiHsmProviderGenerateKeypair (self : YubiHsmProviderT) : LuxResult KeyHandleT

def yubiHsmProviderGenerateKeypair_pre (_self : YubiHsmProviderT) : Prop := True

def yubiHsmProviderGenerateKeypair_post (_self : YubiHsmProviderT) (r : LuxResult KeyHandleT) :
    Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:73 — Stub; depends on unimplemented
-- `YubiHSM` per-slot signing call.
/-- Rust: `impl KeyManagement for YubiHsmProvider { fn sign_capability(&self, _handle: &KeyHandle, _payload: &[u8]) -> Result<[u8; 64]> }`
    (`src/hsm/yubihsm.rs:73`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque yubiHsmProviderSignCapability (self : YubiHsmProviderT) (handle : KeyHandleT)
    (payload : List Nat) : LuxResult (List Nat)

def yubiHsmProviderSignCapability_pre (_self : YubiHsmProviderT) (_handle : KeyHandleT)
    (_payload : List Nat) : Prop := True

def yubiHsmProviderSignCapability_post (_self : YubiHsmProviderT) (_handle : KeyHandleT)
    (_payload : List Nat) (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:79 — Stub; depends on unimplemented
-- `YubiHSM` per-slot verify call.
/-- Rust: `impl KeyManagement for YubiHsmProvider { fn verify_capability_signature(&self, _handle: &KeyHandle, _payload: &[u8], _sig: &[u8; 64]) -> Result<()> }`
    (`src/hsm/yubihsm.rs:79`).  Stub: unconditionally returns
    `Err(ManifestInvalid)`. -/
opaque yubiHsmProviderVerifyCapabilitySignature (self : YubiHsmProviderT) (handle : KeyHandleT)
    (payload : List Nat) (sig : List Nat) : LuxResult Unit

def yubiHsmProviderVerifyCapabilitySignature_pre (_self : YubiHsmProviderT)
    (_handle : KeyHandleT) (_payload : List Nat) (_sig : List Nat) : Prop := True

def yubiHsmProviderVerifyCapabilitySignature_post (_self : YubiHsmProviderT)
    (_handle : KeyHandleT) (_payload : List Nat) (_sig : List Nat) (r : LuxResult Unit) : Prop :=
  match r with
  | .error (.ManifestInvalid _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:90 — Stub; depends on unimplemented
-- `YubiHSM` object enumeration call.
/-- Rust: `impl KeyManagement for YubiHsmProvider { fn list_keys(&self) -> Result<Vec<KeyHandle>> }`
    (`src/hsm/yubihsm.rs:90`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque yubiHsmProviderListKeys (self : YubiHsmProviderT) : LuxResult (List KeyHandleT)

def yubiHsmProviderListKeys_pre (_self : YubiHsmProviderT) : Prop := True

def yubiHsmProviderListKeys_post (_self : YubiHsmProviderT) (r : LuxResult (List KeyHandleT)) :
    Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

-- REFINEMENT_GAP: src/hsm/yubihsm.rs:96 — Stub; depends on unimplemented
-- `YubiHSM` key rotation call.
/-- Rust: `impl KeyManagement for YubiHsmProvider { fn rotate_key(&self, _handle: &KeyHandle) -> Result<KeyHandle> }`
    (`src/hsm/yubihsm.rs:96`).  Stub: unconditionally returns
    `Err(CapabilityDenied)`. -/
opaque yubiHsmProviderRotateKey (self : YubiHsmProviderT) (handle : KeyHandleT) :
    LuxResult KeyHandleT

def yubiHsmProviderRotateKey_pre (_self : YubiHsmProviderT) (_handle : KeyHandleT) : Prop := True

def yubiHsmProviderRotateKey_post (_self : YubiHsmProviderT) (_handle : KeyHandleT)
    (r : LuxResult KeyHandleT) : Prop :=
  match r with
  | .error (.CapabilityDenied _) => True
  | _ => False

end FunctionSpecs
