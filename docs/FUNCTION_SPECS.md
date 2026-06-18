# Function Spec Layer — `lean/FunctionSpecs/`

## What this is

For every production function in `src/` (excluding `#[cfg(test)]` and
`#[cfg(kani)]` code), `lean/FunctionSpecs/` records a Lean 4 signature plus a
precondition and a postcondition. **No proofs are attempted anywhere in this
tree.** This is intentionally a much lighter layer than the rest of `lean/`:

| Lean tree | What it contains | Proof status |
|---|---|---|
| `lean/LuxSpec.lean` | Abstract ideal-system specification | N/A (pure math, no implementation) |
| `lean/LuxCostModel.lean` | Concrete model of `src/metabolism/ledger.rs` | **Proved** (7 theorems) |
| `lean/LuxRefinement.lean` | Refinement: `LuxSpec` ↔ `LuxCostModel` | **Proved** |
| `lean/LuxCapabilityBridge.lean` | `u32` bitfield ↔ `Finset Right` isomorphism | **Proved** |
| `lean/Refinement.lean` | I1–I4 invariant obligations | Stated, `sorry`-stubbed (see `docs/REFINEMENT_GAPS.md`) |
| **`lean/FunctionSpecs/`** (this tree) | **Every production function in `src/`** | **Not attempted — contracts only** |

Do not confuse this tree's `opaque`/`def` + `_pre`/`_post` triples with the
proved theorems above. A function appearing here with a clean-looking
postcondition is a **transcription of intent**, not a verified fact.

## Toolchain status (disclosure)

The Lean 4 / Lake toolchain is **not installed** in this development
environment (network-restricted sandbox) — the same limitation already
disclosed for `lean/Refinement.lean` in `docs/REFINEMENT_GAPS.md`. None of
the files below have been run through `lake build`. Treat every signature,
precondition, and postcondition in this tree as an unverified
human/AI-reviewed transcription of the Rust source, not as a
mechanically-checked fact. `lean/lakefile.lean` has been updated with a new
`lean_lib «FunctionSpecs»` entry so that `lake build` will pick up this tree
once the toolchain is available — but that command has not yet been run.

## Methodology

### Scope

All production (non-test, non-kani) functions across every file in `src/` —
**247 functions** in total. This includes hardware/FFI-boundary code (HSM
backends, TPM, WASM execution, PyO3 bindings) where a clean mathematical spec
is often impossible; those functions are flagged as **`REFINEMENT_GAP`**
rather than silently skipped or given a fabricated spec (see below).

### Per-function template

Every function gets exactly three declarations:

```lean
/-- Rust: `fn name(args) -> T` (`src/path/to/file.rs:LINE`). -/
opaque name (args...) : T
-- or `def name (args...) : T := ...` for genuinely trivial pure accessors

def name_pre (args...) : Prop := ...

def name_post (args...) (result : T) : Prop := ...
```

No `theorem`, no `sorry`, and no attempt to link `_pre`/`_post` to the
signature via proof — they are three independent declarations.

### Calling convention

- Free/associated function `Foo::bar(args) -> T` → `bar : Args -> T`.
- `&self` method `fn bar(&self, args) -> T` → `bar : Receiver -> Args -> T`.
- `&mut self` method `fn bar(&mut self, args) -> T` →
  `bar : Receiver -> Args -> Receiver × T`, even when Rust's return type is
  `()` — every mutator gets a uniform paired-return shape.
- Constructor `fn new(args) -> Self` → `new : Args -> Self`.
- `Result<T, Error>` → `LuxResult T`. `Option<T>` → `Option T`.
- `&'static str` / `&str` → `String`. `u32`/`u64`/`usize` → `Nat` (unbounded —
  wraparound/bit-width truncation is not modelled, mirroring the disclosed
  gap in `LuxCostModel.lean`).

### Shared vocabulary

`lean/FunctionSpecs/Core.lean` defines the types every other file in this
tree reuses: `NodeId`, `GenerationNat`, `Quota`, `Balance`, and — most
importantly — `LuxError` (mirroring `src/error.rs::Error`'s 8 variants
exactly), `LuxDenialClass` (Halt | Failure), and
`LuxResult T := Except LuxError T`. Per-module files define their own
minimal local types (e.g. `Auth.Capability`, `Topology.BootingGraph`,
`Consensus.RaftNode`) rather than importing the proved `lean/LuxSpec.lean` /
`lean/LuxCostModel.lean` types, to keep this unproved spec layer decoupled
from the proved one — names are kept in sync by convention, not by import.

### `REFINEMENT_GAP` criteria

A function is flagged `REFINEMENT_GAP` when no clean mathematical pre/post
spec can be constructed without modelling something fundamentally outside
Lean's reach for this project: real hardware I/O (TPM, HSM), cryptographic
primitives treated as black boxes (Ed25519, SHA-256), FFI into external
crates/libraries (`wasmtime`, `minicbor`, PyO3's Python C ABI), randomness, or
arbitrary guest-code execution (WASM). Flagged functions still get a
best-effort (possibly weak, e.g. `True`) `_pre`/`_post` pair — none are
skipped — plus an inline `-- REFINEMENT_GAP: <file>:<line> — <reason>`
comment and an entry in their file's top-of-file REFINEMENT_GAP table.

## Per-module breakdown

| File | Covers | Functions | REFINEMENT_GAP |
|---|---|---|---|
| `Core.lean` | `src/error.rs`, `src/types.rs::Quota` | 5 | 0 |
| `Audit.lean` | `src/audit/log.rs`, `src/audit/event.rs` | 13 | 3 |
| `Auth.lean` | `src/auth/capability.rs`, `policy.rs`, `revocation.rs` | 23 | 0 |
| `Metabolism.lean` | `src/metabolism/ledger.rs`, `quota.rs` | 6 | 0 |
| `Topology.lean` | `src/topology/graph.rs` | 9 | 0 |
| `Boot.lean` | `src/boot/mod.rs`, `credentials.rs`, `decode.rs`, `manifest.rs` | 24 | 10 |
| `PythonBindings.lean` | `src/python/mod.rs`, `audit.rs`, `gate.rs`, `policy.rs` | 22 | 5 |
| `Consensus.lean` | `src/consensus/mod.rs`, `log.rs`, `peer.rs`, `protocol.rs`, `raft.rs` | 39 | 9 |
| `Hsm.lean` | `src/hsm/mod.rs`, `keystore.rs`, `mock.rs`, `pkcs11.rs`, `yubihsm.rs` | 51 | 51 |
| `SchedulerWasmTpm.lean` | `src/scheduler/*.rs`, `src/wasm/*.rs`, `src/tpm/*.rs` | 55 | 11 |
| **Total** | all of `src/` | **247** | **89** |

The `Hsm.lean` 100% REFINEMENT_GAP rate is expected and correct: every
function in that module does real cryptography (Ed25519 signing/verification,
SHA-256), OS entropy (`OsRng`), mutex-guarded state, or unimplemented
hardware-vendor FFI stubs (PKCS#11, YubiHSM) — none of which admit a clean
Lean predicate without modelling cryptography or hardware itself.

## Full `REFINEMENT_GAP` register

### `Audit.lean`

| Function | file:line | Reason |
|---|---|---|
| `verifyChain` | `src/audit/log.rs:178` | Correctness depends on the SHA-256 compression function, not modelled arithmetically. Postcondition is `True` (no claim). |
| `computeHash` | `src/audit/log.rs:281` | Output is a real SHA-256 digest; only length (32) and determinism asserted. |
| `exportJson` | `src/audit/log.rs:240` | Exact JSON serialization byte-for-byte is a formatting concern, not a security property; spec given is weak. |

### `Boot.lean`

| Function | file:line | Reason |
|---|---|---|
| `manifestDecoderDecode` | `src/boot/decode.rs:72` | CBOR decode of untrusted bytes + Ed25519 signature verification; "malformed" is a large, non-enumerable input space. |
| `manifestDecoderParseCbor` | `src/boot/decode.rs:93` | Delegates to `minicbor::Decoder`, an external crate's parser. |
| `manifestDecoderParseEdges` | `src/boot/decode.rs:124` | CBOR array decode w/ capacity/non-zero validation against untrusted bytes. |
| `manifestDecoderParseQuotas` | `src/boot/decode.rs:177` | Same as above, for quotas. |
| `bootCredentialsFromKeyBytes` | `src/boot/credentials.rs:39` | Ed25519 curve-point validation not modelled. |
| `bootCredentialsVerify` | `src/boot/credentials.rs:65` | Ed25519 signature check, possibly real HSM hardware. |
| `bootCredentialsGenerateCapabilitySeed` | `src/boot/credentials.rs:74` | Hardware randomness not modelled. |
| `bootStateProduceAttestation` | `src/boot/mod.rs:121` | TPM hardware/firmware quote operation. |
| `bootStateInitialiseWithTpm` | `src/boot/mod.rs:264` | Composite decode + signature-verify + TPM I/O boundary. |
| `manifestParseAndVerify` | `src/boot/manifest.rs:55` | Stub parser; any spec here is provisional. |

### `PythonBindings.lean`

| Function | file:line | Reason |
|---|---|---|
| `luxKernelModule` | `src/python/mod.rs:45` | PyO3 macro-generated FFI entry point into the Python C ABI. |
| `pyAuditLogExportJson` | `src/python/audit.rs:174` | JSON serialization detail. |
| `pyPolicyGateCheck` | `src/python/policy.rs:163` | GIL acquisition + `PyDict` FFI construction. |
| `pyLuxGateAuthorizeCe` | `src/python/gate.rs:151` | `PyDict` FFI construction (underlying `check` logic is separately specified). |
| `pyLuxGateConfig` | `src/python/gate.rs:173` | `PyDict` FFI construction. |

### `Consensus.lean`

| Function | file:line | Reason |
|---|---|---|
| `startElection` | `src/consensus/raft.rs:146` | Bifurcates on cluster size; unmodelled broadcast side-effect. |
| `step` | `src/consensus/raft.rs:214` | Pure dispatcher to 4 handlers; restating all 4 postconditions would be redundant. |
| `becomeLeader` | `src/consensus/raft.rs:273` | Per-peer array mutation in a loop; unused transport param easy to mis-specify. |
| `sendAeTo` | `src/consensus/raft.rs:301` | Data-dependent loop bound (log contents) building bounded entry batch. |
| `onRequestVote` | `src/consensus/raft.rs:336` | Combines step-down, log-freshness check, and vote-granting in one multi-branch function. |
| `onAppendEntries` | `src/consensus/raft.rs:377` | Classic AppendEntries handler; large case analysis, timing-sensitive. |
| `appendLogEntries` | `src/consensus/raft.rs:426` | Per-slot conditional truncate-then-append, state-dependent on existing log. |
| `onAeReply` | `src/consensus/raft.rs:442` | Combines step-down, peer lookup, index bookkeeping, conditional commit advance. |
| `advanceCommitIndex` | `src/consensus/raft.rs:469` | Descending search-and-stop-at-first-match over arbitrary log length. |

### `Hsm.lean` (all 51 functions — see file for the complete table; module-level reasons below)

| Reason category | Functions affected |
|---|---|
| Ed25519 sign/verify/derive (crypto not modelled) | `hsmProviderSign/Verify`, `keyManagementSignCapability/VerifyCapabilitySignature`, `softwareKeyStore{Sign,Verify,SignCapability,VerifyCapabilitySignature,WithSigningKey,VerifyingKeyBytes}`, `softwareHsm{Sign,Verify,FromVerifyingKey,FromSigningKey,VerifyingKeyBytes}`, `hsmSignedCapability{Sign,Verify}` |
| OS entropy / CSPRNG (randomness not modelled) | `hsmProviderGenerateCapabilitySeed`, `keyManagementGenerateKeypair`, `softwareKeyStore{GenerateCapabilitySeed,GenerateKeypair,RotateKey}`, `softwareHsmGenerateCapabilitySeed` |
| Mutex/heap internal state (opaque) | `softwareKeyStore{New,Default,ListKeys,SignCapability,VerifyCapabilitySignature,RotateKey}`, `keyManagementListKeys` |
| Memory zeroization / redacted Debug (not a pure predicate) | `keyHandleZeroize`, `zeroizingSigningKey{Drop,Fmt}` |
| Unimplemented vendor FFI stubs (PKCS#11 / YubiHSM) | all 8 `pkcs11HsmProvider*` methods, all 8 `yubiHsmProvider*` methods, plus their `*NewStub` constructors |
| Inherits a gap from a delegated-to function | `defaultHsm`, `hsmSignedCapabilityCapPayload` |

### `SchedulerWasmTpm.lean`

| Function | file:line | Reason |
|---|---|---|
| `WorkQueue.drainOrdered` | `src/scheduler/queue.rs:96` | Heap pop tie-break order among equal-priority items not pinned. |
| `WasmExecutor.new` | `src/wasm/executor.rs:57` | `wasmtime::Engine`/`Linker` construction is an external-crate property. |
| `WasmExecutor.callNullary` | `src/wasm/executor.rs:150` | Executing arbitrary guest WASM bytecode requires modelling the WASM spec itself. |
| `SoftwareTpm.extendPcr` | `src/tpm/mock.rs:57` | SHA-256 treated as an opaque cryptographic oracle. |
| `SoftwareTpm.quote` | `src/tpm/mock.rs:71` | Quote bytes defined by SHA-256 output (oracle). |
| `SoftwareTpm.verifyQuote` | `src/tpm/mock.rs:102` | Relies on SHA-256 collision resistance, an unmodelled assumption. |
| `TssTpmProvider.newStub` | `src/tpm/tss.rs:41` | Flagged as the future seam for real TCTI/hardware connection logic. |
| `TssTpmProvider.extendPcr` | `src/tpm/tss.rs:47` | Real-hardware PCR extension; needs the TPM 2.0 spec. |
| `TssTpmProvider.quote` | `src/tpm/tss.rs:53` | Depends on `TPMS_ATTEST` structure and AK signature. |
| `TssTpmProvider.readPcr` | `src/tpm/tss.rs:59` | Depends on unmodelled physical TPM state. |
| `TssTpmProvider.verifyQuote` | `src/tpm/tss.rs:65` | Real-hardware signature verification, out of scope. |

## How this was produced

This tree was generated by Claude Code in five parallel batches: one
covering `audit` + `auth` + `metabolism` + `topology` + `error.rs`/`types.rs`
written directly, and four delegated to background agents covering
`boot`+`python`, `consensus`, `hsm`, and `scheduler`+`wasm`+`tpm`
respectively, each given the identical methodology, calling convention, and
`REFINEMENT_GAP` criteria documented above to keep the output structurally
uniform. No human or mechanical proof-checking has been performed on any of
it — see the toolchain status disclosure above.
