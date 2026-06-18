import FunctionSpecs.Core

/-!
# Lux Kernel — Function Spec Layer: Boot Subsystem

Covers every production function in:
- `src/boot/mod.rs`     (`BootState` — boot sequence orchestration, topology consensus)
- `src/boot/credentials.rs` (`BootCredentials` — HSM-backed manifest verification key material)
- `src/boot/decode.rs`  (`ManifestDecoder` — CBOR wire-format decoding + signature verification)
- `src/boot/manifest.rs` (`Manifest`, `EdgeDecl`, `QuotaDecl` — the sealed boot contract)

Total functions specified in this file: **24**.

This is a spec-only layer: every function below gets an `opaque` (or, for
genuinely trivial pure accessors, a direct `def`) signature plus independent
`_pre`/`_post` declarations.  No theorems, no `sorry`, no attempt to link the
declarations together. See `Core.lean`'s module doc for the full disclosure
of scope and the calling convention used throughout this tree.

## REFINEMENT_GAP entries in this file

| Function | file:line | Reason |
|---|---|---|
| `manifestDecoderDecode` | `src/boot/decode.rs:72` | CBOR wire-format decode of untrusted bytes + Ed25519 signature verification; "malformed" is a large, non-enumerable input space |
| `manifestDecoderParseCbor` | `src/boot/decode.rs:93` | Delegates to `minicbor::Decoder`, an external crate's parser; structural validation logic is non-trivial to characterize precisely |
| `manifestDecoderParseEdges` | `src/boot/decode.rs:124` | CBOR array decoding with capacity/non-zero validation against untrusted bytes |
| `manifestDecoderParseQuotas` | `src/boot/decode.rs:177` | CBOR array decoding with capacity/non-zero validation against untrusted bytes |
| `bootCredentialsFromKeyBytes` | `src/boot/credentials.rs:39` | Delegates to `SoftwareHsm::from_verifying_key`, which validates an Ed25519 curve point — curve membership is not modelled here |
| `bootCredentialsVerify` | `src/boot/credentials.rs:65` | Delegates to `HsmProvider::verify`, an Ed25519 signature check (possibly real HSM hardware) — cryptographic verification is not modelled here |
| `bootCredentialsGenerateCapabilitySeed` | `src/boot/credentials.rs:74` | Delegates to `HsmProvider::generate_capability_seed`, which may draw on hardware randomness — randomness is not modelled here |
| `bootStateProduceAttestation` | `src/boot/mod.rs:121` | Delegates to `TpmProvider::quote`, a hardware/firmware TPM operation |
| `bootStateInitialiseWithTpm` | `src/boot/mod.rs:264` | Orchestrates CBOR decode, signature verification, and TPM hardware calls (`extend_pcr`, `quote`) in one all-or-nothing sequence — composite I/O boundary |
| `manifestParseAndVerify` | `src/boot/manifest.rs:55` | Stub parser (`detail: "parser not yet wired (stub)"`); real implementation will be a wire-format decoder, so any spec here is provisional |
-/

namespace FunctionSpecs

-- ── Local domain types (mirror `src/boot/manifest.rs`) ────────────────────────

/-- Mirrors `src/boot/manifest.rs::EdgeDecl` — one row of the manifest's
    topology table: a directed edge `src -> dst`. -/
structure EdgeDecl where
  src : NodeId
  dst : NodeId
  deriving DecidableEq, Repr

/-- Mirrors `src/boot/manifest.rs::QuotaDecl` — one row of the manifest's
    quota table: a per-node resource ceiling. -/
structure QuotaDecl where
  node : NodeId
  ceiling : Quota
  deriving Repr

/-- Mirrors `src/boot/manifest.rs::Manifest` — the sealed, validated boot
    contract.  `edges`/`quotas` are `heapless::Vec` bounded by `MAX_EDGES`
    (256) / `MAX_NODES` (64) in the Rust source; bounds are not enforced in
    this structure's type but are asserted in relevant `_pre`/`_post`
    clauses where load-bearing. -/
structure Manifest where
  edges : List EdgeDecl
  quotas : List QuotaDecl
  version : Nat
  deriving Repr

/-- Mirrors `src/boot/credentials.rs::BootCredentials<H>` — opaque handle
    over an HSM-backed (or software) Ed25519 verifying key.  The wrapped
    `HsmProvider` is not modelled; this is purely a marker for the spec
    layer's `Receiver` position. -/
opaque BootCredentialsHandle : Type

/-- Mirrors `src/boot/mod.rs::BootState` — sealed, immutable kernel state
    produced by a successful boot sequence.  Fields mirror the Rust struct;
    `graph`/`ledger`/`policy` are modelled abstractly since their full
    structure lives outside this file's scope. -/
structure BootState where
  graph : Type
  ledger : Type
  policy : Type
  attestation : List Nat
  manifestHash : List Nat
  localId : NodeId

/-- Mirrors `src/tpm::TpmQuote` — opaque attestation quote bytes. Modelled
    abstractly; only used as an opaque return/field type in this file. -/
opaque TpmQuoteVal : Type

/-- Mirrors `src/tpm::attestation::BootAttestation` — opaque attestation
    record returned by `produce_attestation`. -/
opaque BootAttestationVal : Type

/-- Mirrors `crate::consensus::PeerSet` — opaque set of Raft peers. -/
opaque PeerSetVal : Type

/-- Mirrors `crate::audit::AuditLog` — opaque hash-chained audit log handle
    (full spec lives outside this file's scope; only used as a threaded
    mutable parameter here). -/
opaque AuditLogVal : Type

-- ── `src/boot/manifest.rs::Manifest` impl block ───────────────────────────────

/-- Rust: `impl Manifest { pub const fn parse_and_verify(bytes: &[u8]) -> Result<Self> }`
    (`src/boot/manifest.rs:55`).  Currently a stub: always returns
    `Err(ManifestInvalid)` for non-empty input, and `Err(ManifestInvalid)`
    for empty input too (placeholder, not yet wired to a real decoder).

    REFINEMENT_GAP: src/boot/manifest.rs:55 — stub parser; real implementation
    will be a wire-format decoder, so any spec here is provisional. -/
opaque manifestParseAndVerify (bytes : List Nat) : LuxResult Manifest

def manifestParseAndVerify_pre (_bytes : List Nat) : Prop := True

/-- Best-effort: in the current stub, every input (empty or not) returns
    `Err (.ManifestInvalid _)`.  No `Ok` path exists yet. -/
def manifestParseAndVerify_post (_bytes : List Nat) (r : LuxResult Manifest) : Prop :=
  match r with
  | .error (.ManifestInvalid _) => True
  | .error _ => False
  | .ok _ => False

/-- Rust: `impl Manifest { pub fn permits_edge(&self, src: NodeId, dst: NodeId) -> bool }`
    (`src/boot/manifest.rs:70`).  Pure accessor over `self.edges`. -/
def manifestPermitsEdge (m : Manifest) (src dst : NodeId) : Bool :=
  m.edges.any (fun e => e.src = src && e.dst = dst)

def manifestPermitsEdge_pre (_m : Manifest) (_src _dst : NodeId) : Prop := True

def manifestPermitsEdge_post (m : Manifest) (src dst : NodeId) (r : Bool) : Prop :=
  r = true ↔ ∃ e ∈ m.edges, e.src = src ∧ e.dst = dst

/-- Rust: `impl Manifest { pub fn quota_for(&self, node: NodeId) -> Option<Quota> }`
    (`src/boot/manifest.rs:76`).  Pure accessor: first matching quota row,
    by ascending list order (mirrors `Iterator::find`). -/
opaque manifestQuotaFor (m : Manifest) (node : NodeId) : Option Quota

def manifestQuotaFor_pre (_m : Manifest) (_node : NodeId) : Prop := True

def manifestQuotaFor_post (m : Manifest) (node : NodeId) (r : Option Quota) : Prop :=
  (r = none → ¬ ∃ q ∈ m.quotas, q.node = node) ∧
  (∀ q', r = some q' → ∃ q ∈ m.quotas, q.node = node ∧ q.ceiling = q')

/-- Rust: `impl Manifest { pub const fn version(&self) -> u32 }`
    (`src/boot/manifest.rs:85`).  Trivial pure field accessor. -/
def manifestVersion (m : Manifest) : Nat := m.version

def manifestVersion_pre (_m : Manifest) : Prop := True

def manifestVersion_post (m : Manifest) (r : Nat) : Prop := r = m.version

-- ── `src/boot/credentials.rs::BootCredentials<SoftwareHsm>` impl block ────────

/-- Rust: `impl BootCredentials<SoftwareHsm> { pub fn from_key_bytes(bytes: [u8; 32]) -> Result<Self> }`
    (`src/boot/credentials.rs:39`).  Constructs software-backed credentials
    from a 32-byte Ed25519 public key; fails if the bytes are not a valid
    curve point.

    REFINEMENT_GAP: src/boot/credentials.rs:39 — delegates to
    SoftwareHsm::from_verifying_key, which validates an Ed25519 curve point;
    curve membership is not modelled here. -/
opaque bootCredentialsFromKeyBytes (bytes : List Nat) : LuxResult BootCredentialsHandle

def bootCredentialsFromKeyBytes_pre (bytes : List Nat) : Prop := bytes.length = 32

/-- Best-effort: success is only possible for well-formed 32-byte input;
    failure (when it occurs) is always `ManifestInvalid`. Curve validity
    itself is not characterized. -/
def bootCredentialsFromKeyBytes_post (bytes : List Nat) (r : LuxResult BootCredentialsHandle) : Prop :=
  bytes.length ≠ 32 → ∃ d, r = .error (.ManifestInvalid d)

/-- Rust: `impl BootCredentials<SoftwareHsm> { pub fn key_bytes(&self) -> [u8; 32] }`
    (`src/boot/credentials.rs:45`).  Returns the raw 32-byte verifying key
    encoding. -/
opaque bootCredentialsKeyBytes (h : BootCredentialsHandle) : List Nat

def bootCredentialsKeyBytes_pre (_h : BootCredentialsHandle) : Prop := True

def bootCredentialsKeyBytes_post (_h : BootCredentialsHandle) (r : List Nat) : Prop :=
  r.length = 32

-- ── `src/boot/credentials.rs::BootCredentials<H>` impl block ──────────────────

/-- Rust: `impl<H: HsmProvider> BootCredentials<H> { pub const fn new(hsm: H) -> Self }`
    (`src/boot/credentials.rs:53`).  Wraps the given HSM provider value with
    no validation or transformation; declared `opaque` rather than a direct
    `def` because `H: HsmProvider` is modelled abstractly (as `Type`) in this
    spec layer, so there is no concrete value to construct a real `Self`
    from. -/
opaque bootCredentialsNew (hsm : Type) : BootCredentialsHandle

def bootCredentialsNew_pre (_hsm : Type) : Prop := True

def bootCredentialsNew_post (_hsm : Type) (_r : BootCredentialsHandle) : Prop := True

/-- Rust: `impl<H: HsmProvider> BootCredentials<H> { pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> Result<()> }`
    (`src/boot/credentials.rs:65`).  Delegates to `HsmProvider::verify`.

    REFINEMENT_GAP: src/boot/credentials.rs:65 — delegates to
    HsmProvider::verify, an Ed25519 signature check (possibly real HSM
    hardware); cryptographic verification is not modelled here. -/
opaque bootCredentialsVerify
    (h : BootCredentialsHandle) (message : List Nat) (signatureBytes : List Nat) : LuxResult Unit

def bootCredentialsVerify_pre (_h : BootCredentialsHandle) (_message : List Nat) (signatureBytes : List Nat) : Prop :=
  signatureBytes.length = 64

/-- Best-effort: any failure is `ManifestInvalid`; success/failure on a
    given (message, signature) pair is determined by the underlying HSM and
    is not characterized further. -/
def bootCredentialsVerify_post
    (_h : BootCredentialsHandle) (_message : List Nat) (_signatureBytes : List Nat)
    (r : LuxResult Unit) : Prop :=
  match r with
  | .error e => ∃ d, e = .ManifestInvalid d
  | .ok _ => True

/-- Rust: `impl<H: HsmProvider> BootCredentials<H> { pub fn generate_capability_seed(&self) -> Result<[u8; 32]> }`
    (`src/boot/credentials.rs:74`).  Delegates to `HsmProvider::generate_capability_seed`.

    REFINEMENT_GAP: src/boot/credentials.rs:74 — delegates to
    HsmProvider::generate_capability_seed, which may draw on hardware
    randomness; randomness is not modelled here. -/
opaque bootCredentialsGenerateCapabilitySeed (h : BootCredentialsHandle) : LuxResult (List Nat)

def bootCredentialsGenerateCapabilitySeed_pre (_h : BootCredentialsHandle) : Prop := True

def bootCredentialsGenerateCapabilitySeed_post (_h : BootCredentialsHandle) (r : LuxResult (List Nat)) : Prop :=
  match r with
  | .ok bytes => bytes.length = 32
  | .error _ => True

-- ── `src/boot/decode.rs::ManifestDecoder` impl block ──────────────────────────

/-- Rust: `impl ManifestDecoder { pub fn decode<H: HsmProvider>(bytes: &[u8], credentials: &BootCredentials<H>) -> Result<Manifest> }`
    (`src/boot/decode.rs:72`).  Splits a 64-byte Ed25519 signature from the
    CBOR payload, verifies the signature (fail-closed: before any parsing),
    then decodes the payload into a `Manifest`.

    REFINEMENT_GAP: src/boot/decode.rs:72 — CBOR wire-format decode of
    untrusted bytes + Ed25519 signature verification; "malformed" is a
    large, non-enumerable input space. -/
opaque manifestDecoderDecode (bytes : List Nat) (credentials : BootCredentialsHandle) : LuxResult Manifest

def manifestDecoderDecode_pre (_bytes : List Nat) (_credentials : BootCredentialsHandle) : Prop := True

/-- Best-effort: inputs shorter than 65 bytes (64-byte signature + >=1 byte
    payload) always fail with `ManifestInvalid`; any other failure (bad
    signature, malformed CBOR) is also `ManifestInvalid`. Successful decode
    is not characterized beyond "produces some Manifest". -/
def manifestDecoderDecode_post (bytes : List Nat) (_credentials : BootCredentialsHandle) (r : LuxResult Manifest) : Prop :=
  (bytes.length < 65 → ∃ d, r = .error (.ManifestInvalid d)) ∧
  (match r with
   | .error e => ∃ d, e = .ManifestInvalid d
   | .ok _ => True)

/-- Rust: `impl ManifestDecoder { fn parse_cbor(payload: &[u8]) -> Result<Manifest> }`
    (`src/boot/decode.rs:93`, private helper).  Decodes a 3-element CBOR
    array `[version, edges, quotas]` into a `Manifest`.

    REFINEMENT_GAP: src/boot/decode.rs:93 — delegates to minicbor::Decoder,
    an external crate's parser; structural validation logic is non-trivial
    to characterize precisely. -/
opaque manifestDecoderParseCbor (payload : List Nat) : LuxResult Manifest

def manifestDecoderParseCbor_pre (_payload : List Nat) : Prop := True

/-- Best-effort: any failure is `ManifestInvalid`; a successful decode
    yields a `Manifest` whose edge/quota counts are within the compile-time
    bounds (`MAX_EDGES` = 256, `MAX_NODES` = 64). -/
def manifestDecoderParseCbor_post (_payload : List Nat) (r : LuxResult Manifest) : Prop :=
  match r with
  | .error e => ∃ d, e = .ManifestInvalid d
  | .ok m => m.edges.length ≤ 256 ∧ m.quotas.length ≤ 64

/-- Rust: `impl ManifestDecoder { fn parse_edges(d: &mut Decoder<'_>) -> Result<heapless::Vec<EdgeDecl, MAX_EDGES>> }`
    (`src/boot/decode.rs:124`, private helper).  Decodes the edges array;
    each edge is `[src, dst]` with both non-zero `u32`s; rejects indefinite
    length, wrong arity, zero values, or capacity overflow (> `MAX_EDGES` =
    256).

    REFINEMENT_GAP: src/boot/decode.rs:124 — CBOR array decoding with
    capacity/non-zero validation against untrusted bytes. -/
opaque manifestDecoderParseEdges (cursorState : List Nat) : LuxResult (List EdgeDecl)

def manifestDecoderParseEdges_pre (_cursorState : List Nat) : Prop := True

/-- Best-effort: any failure is `ManifestInvalid`; a successful result has
    length at most `MAX_EDGES` (256) and contains no edge with `src = 0` or
    `dst = 0` (the `NodeId`/`NonZeroU32` invariant). -/
def manifestDecoderParseEdges_post (_cursorState : List Nat) (r : LuxResult (List EdgeDecl)) : Prop :=
  match r with
  | .error e => ∃ d, e = .ManifestInvalid d
  | .ok edges => edges.length ≤ 256 ∧ ∀ e ∈ edges, e.src ≠ 0 ∧ e.dst ≠ 0

/-- Rust: `impl ManifestDecoder { fn parse_quotas(d: &mut Decoder<'_>) -> Result<heapless::Vec<QuotaDecl, MAX_NODES>> }`
    (`src/boot/decode.rs:177`, private helper).  Decodes the quotas array;
    each entry is `[node, ceiling]` with `node` a non-zero `u32` and
    `ceiling` a `u64`; rejects indefinite length, wrong arity, zero node, or
    capacity overflow (> `MAX_NODES` = 64).

    REFINEMENT_GAP: src/boot/decode.rs:177 — CBOR array decoding with
    capacity/non-zero validation against untrusted bytes. -/
opaque manifestDecoderParseQuotas (cursorState : List Nat) : LuxResult (List QuotaDecl)

def manifestDecoderParseQuotas_pre (_cursorState : List Nat) : Prop := True

/-- Best-effort: any failure is `ManifestInvalid`; a successful result has
    length at most `MAX_NODES` (64) and contains no quota row with
    `node = 0`. -/
def manifestDecoderParseQuotas_post (_cursorState : List Nat) (r : LuxResult (List QuotaDecl)) : Prop :=
  match r with
  | .error e => ∃ d, e = .ManifestInvalid d
  | .ok quotas => quotas.length ≤ 64 ∧ ∀ q ∈ quotas, q.node ≠ 0

-- ── `src/boot/mod.rs::BootState` impl block ───────────────────────────────────

/-- Rust: `impl BootState { pub const fn local_id(&self) -> NodeId }`
    (`src/boot/mod.rs:64`).  Trivial pure field accessor. -/
def bootStateLocalId (b : BootState) : NodeId := b.localId

def bootStateLocalId_pre (_b : BootState) : Prop := True

def bootStateLocalId_post (b : BootState) (r : NodeId) : Prop := r = b.localId

/-- Rust: `impl BootState { pub const fn with_local_id(mut self, id: NodeId) -> Self }`
    (`src/boot/mod.rs:72`).  Consumes `self` by value and returns a copy with
    `local_id` overwritten; modelled with the uniform mutator shape since it
    takes `self` and threads a new receiver state, even though Rust's
    signature is `self -> Self` rather than `&mut self`. -/
def bootStateWithLocalId (b : BootState) (id : NodeId) : BootState × Unit :=
  ({ b with localId := id }, ())

def bootStateWithLocalId_pre (_b : BootState) (_id : NodeId) : Prop := True

def bootStateWithLocalId_post (b : BootState) (id : NodeId) (r : BootState × Unit) : Prop :=
  r.1.localId = id ∧ r.1.graph = b.graph ∧ r.1.ledger = b.ledger ∧
  r.1.policy = b.policy ∧ r.1.attestation = b.attestation ∧
  r.1.manifestHash = b.manifestHash

/-- Rust: `impl BootState { pub const fn graph(&self) -> &OperationalGraph }`
    (`src/boot/mod.rs:79`).  Trivial pure field accessor. -/
def bootStateGraph (b : BootState) : Type := b.graph

def bootStateGraph_pre (_b : BootState) : Prop := True

def bootStateGraph_post (b : BootState) (r : Type) : Prop := r = b.graph

/-- Rust: `impl BootState { pub const fn ledger(&self) -> &Ledger }`
    (`src/boot/mod.rs:85`).  Trivial pure field accessor. -/
def bootStateLedger (b : BootState) : Type := b.ledger

def bootStateLedger_pre (_b : BootState) : Prop := True

def bootStateLedger_post (b : BootState) (r : Type) : Prop := r = b.ledger

/-- Rust: `impl BootState { pub fn policy_mut(&mut self) -> &mut Policy }`
    (`src/boot/mod.rs:91`).  Returns a mutable reference to the policy
    enforcement point; the receiver itself is not otherwise changed by the
    accessor call (any mutation happens through the returned reference,
    which is outside this function's own effect). -/
def bootStatePolicyMut (b : BootState) : BootState × Type := (b, b.policy)

def bootStatePolicyMut_pre (_b : BootState) : Prop := True

def bootStatePolicyMut_post (b : BootState) (r : BootState × Type) : Prop :=
  r.1 = b ∧ r.2 = b.policy

/-- Rust: `impl BootState { pub const fn attestation_quote(&self) -> &TpmQuote }`
    (`src/boot/mod.rs:99`).  Trivial pure field accessor. -/
def bootStateAttestationQuote (b : BootState) : List Nat := b.attestation

def bootStateAttestationQuote_pre (_b : BootState) : Prop := True

def bootStateAttestationQuote_post (b : BootState) (r : List Nat) : Prop := r = b.attestation

/-- Rust: `impl BootState { pub const fn manifest_hash(&self) -> &[u8; 32] }`
    (`src/boot/mod.rs:108`).  Trivial pure field accessor. -/
def bootStateManifestHash (b : BootState) : List Nat := b.manifestHash

def bootStateManifestHash_pre (_b : BootState) : Prop := True

def bootStateManifestHash_post (b : BootState) (r : List Nat) : Prop :=
  r = b.manifestHash ∧ r.length = 32

/-- Rust: `impl BootState { pub fn produce_attestation<T: TpmProvider>(&self, tpm: &T, nonce: [u8; 32]) -> Result<BootAttestation> }`
    (`src/boot/mod.rs:121`).  Quotes the boot PCR (index 0) with `nonce` via
    `tpm.quote`, then packages `(manifest_hash, 0, nonce, quote)` into a
    `BootAttestation`. The receiver is not mutated (`&self`).

    REFINEMENT_GAP: src/boot/mod.rs:121 — delegates to TpmProvider::quote, a
    hardware/firmware TPM operation. -/
opaque bootStateProduceAttestation
    (b : BootState) (tpm : Type) (nonce : List Nat) : LuxResult BootAttestationVal

def bootStateProduceAttestation_pre (_b : BootState) (_tpm : Type) (nonce : List Nat) : Prop :=
  nonce.length = 32

/-- Best-effort: any failure is `ManifestInvalid` (per the doc comment on
    the Rust function); the underlying TPM quote success/failure condition
    itself is not modelled. -/
def bootStateProduceAttestation_post
    (_b : BootState) (_tpm : Type) (_nonce : List Nat) (r : LuxResult BootAttestationVal) : Prop :=
  match r with
  | .error e => ∃ d, e = .ManifestInvalid d
  | .ok _ => True

/-- Rust: `impl BootState { pub fn run_topology_consensus<T: RaftTransport>(&mut self, peer_set: &PeerSet, src: NodeId, dst: NodeId, transport: &mut T, audit: &mut AuditLog) -> Result<()> }`
    (`src/boot/mod.rs:161`).  I4 enforcement point: the local sealed graph
    is the authoritative, fail-closed gate — if `(src, dst)` is not declared
    in the boot manifest, the call aborts with `TopologyViolation`
    immediately regardless of peer votes (no Raft round is even attempted).
    Only if the local graph permits the edge does the node attempt leader
    election and replication; an `Ok(())` requires both local permission and
    a committed quorum entry.  An `EventKind::TopologyChange` audit event is
    always appended for the consensus outcome.  The receiver (`self`) is not
    structurally changed by this call (its `graph`/`ledger`/`policy` fields
    are unchanged); the audit log and transport are the mutated externals. -/
opaque bootStateRunTopologyConsensus
    (b : BootState) (peerSet : PeerSetVal) (src dst : NodeId) (transport : Type) (audit : AuditLogVal)
    : BootState × LuxResult Unit

def bootStateRunTopologyConsensus_pre
    (_b : BootState) (_peerSet : PeerSetVal) (_src _dst : NodeId) (_transport : Type) (_audit : AuditLogVal) : Prop :=
  True

/-- I4: an `Ok` outcome requires the edge to be permitted by the local
    sealed graph (gate `graph.traverse src dst` succeeding is necessary,
    though not modelled structurally here since `OperationalGraph` is
    outside this file's scope) and a quorum-committed Raft entry. Any
    `Err` outcome is exactly `TopologyViolation { src, dst }` — this
    function never returns any other error variant. The receiver's
    `graph`/`ledger`/`policy`/`attestation`/`manifestHash`/`localId` fields
    are unchanged across the call. -/
def bootStateRunTopologyConsensus_post
    (b : BootState) (_peerSet : PeerSetVal) (src dst : NodeId) (_transport : Type) (_audit : AuditLogVal)
    (r : BootState × LuxResult Unit) : Prop :=
  r.1 = b ∧
  (match r.2 with
   | .error e => e = .TopologyViolation src dst
   | .ok () => True)

/-- Rust: `impl BootState { pub fn initialise<H: HsmProvider>(raw_manifest: &[u8], credentials: &BootCredentials<H>) -> Result<Self> }`
    (`src/boot/mod.rs:240`).  Backward-compatible entry point: runs the full
    boot sequence with a `NullTpm` (so `attestation` is all-zeros on
    success). Delegates entirely to `initialise_with_tpm`. -/
opaque bootStateInitialise (rawManifest : List Nat) (credentials : BootCredentialsHandle) : LuxResult BootState

def bootStateInitialise_pre (_rawManifest : List Nat) (_credentials : BootCredentialsHandle) : Prop := True

/-- A successful boot yields a `BootState` whose `attestation` is all-zeros
    (32 zero bytes, the `NullTpm` quote) and whose `localId` is `NodeId::MIN`
    (1). Any failure mirrors the underlying decode/seed/seal sequence and is
    not characterized further beyond "some `LuxError`" (see
    `bootStateInitialiseWithTpm_post`, which this function reuses verbatim). -/
def bootStateInitialise_post
    (_rawManifest : List Nat) (_credentials : BootCredentialsHandle) (r : LuxResult BootState) : Prop :=
  match r with
  | .ok b => b.attestation = List.replicate 32 0 ∧ b.localId = 1
  | .error _ => True

/-- Rust: `impl BootState { pub fn initialise_with_tpm<H: HsmProvider, T: TpmProvider>(raw_manifest: &[u8], credentials: &BootCredentials<H>, tpm: &mut T) -> Result<Self> }`
    (`src/boot/mod.rs:264`).  All-or-nothing boot sequence: (1) SHA-256 hash
    the raw manifest bytes, (2) CBOR-decode + signature-verify into a
    `Manifest`, (3) seed a `BootingGraph` with every declared edge
    (activating both endpoints first), (4) seed a `Ledger` with every
    declared quota, (5) seal the graph (typestate transition, irreversible),
    (6) extend TPM PCR 0 with the raw manifest bytes, (7) quote PCR 0 with an
    all-zero nonce, (8) construct a fresh `Policy` at generation 0. Any step
    failing aborts the whole sequence with no partial state retained
    (fail-closed); a TPM `extend_pcr` failure is surfaced as
    `ManifestInvalid`.

    REFINEMENT_GAP: src/boot/mod.rs:264 — orchestrates CBOR decode,
    signature verification, and TPM hardware calls (extend_pcr, quote) in
    one all-or-nothing sequence; composite I/O boundary. -/
opaque bootStateInitialiseWithTpm
    (rawManifest : List Nat) (credentials : BootCredentialsHandle) (tpm : Type) : LuxResult BootState

def bootStateInitialiseWithTpm_pre
    (_rawManifest : List Nat) (_credentials : BootCredentialsHandle) (_tpm : Type) : Prop := True

/-- Best-effort: on success, `manifestHash` is exactly 32 bytes (a SHA-256
    digest) and `localId = NodeId::MIN` (1); the policy/ledger/graph fields
    are freshly constructed and not otherwise characterized here (their full
    specs live outside this file's scope). On failure, no observable partial
    state exists — this is captured at the type level (the function either
    yields a complete `BootState` or an error, never a partially-populated
    value). -/
def bootStateInitialiseWithTpm_post
    (_rawManifest : List Nat) (_credentials : BootCredentialsHandle) (_tpm : Type) (r : LuxResult BootState) : Prop :=
  match r with
  | .ok b => b.manifestHash.length = 32 ∧ b.localId = 1
  | .error _ => True

end FunctionSpecs
