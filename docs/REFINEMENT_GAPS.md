# Lux Kernel — Refinement Gaps

**Status:** Lean 4 proofs in `lean/Refinement.lean` are scaffolded with named
`sorry` placeholders.  **No invariant in that file is mechanically verified.**

This document gives a plain-language description of what each `sorry` represents,
why it exists, and the estimated effort to close it.  It is intended as the
primary briefing document for an independent proof engineer or OSTIF auditor.

---

## Existing proved layer (do not re-prove)

The following are fully proved (no `sorry`) in the existing Lean files:

| Theorem | File | What it proves |
|---------|------|---------------|
| `concreteDeductSpec` | `LuxRefinement.lean` | `deduct` satisfies all 4 properties of `AbstractLedger.Spec` |
| `delegate_non_amplification` | `LuxRefinement.lean` | Delegation never escalates rights (`Finset Right` level) |
| `concreteDelegateSpec` | `LuxRefinement.lean` | Full `DelegateSpec` satisfied by `concreteDelegateCap` |
| `bitsContainsIffSubset` | `LuxCapabilityBridge.lean` | `u32` bitwise AND ↔ `Finset.Subset` (1024-case decision) |
| Roundtrip theorems | `LuxCapabilityBridge.lean` | `bitsToRights ∘ rightsToBits = id` and `rightsToBits ∘ bitsToRights = mask` |

The obligations below sit *above* these proofs: they ask whether the proved
layer is sufficient to discharge the four system-level invariants.

---

## I1 — Fail-Closed

### Gaps: `failClosed_generation`, `failClosed_revocation`, `failClosed_replay`

**What these say in plain language:**
If the generation check fails, or the nonce is revoked, or the nonce has been
replayed, then `policyCheck` returns `false`.

**Why they have `sorry`:**
The `policyCheck` model in `Refinement.lean` is an `&&`-chain of four Boolean
conditions.  Lean's `simp` needs to destructure `Bool.and_eq_false` across all
four conjuncts to show that a single false conjunct makes the whole chain false.
The tactic `simp [Bool.and_eq_false, Bool.not_true]` likely closes all three
immediately, but it has not been attempted.

**Prerequisite knowledge:**
Basic Lean 4 `simp` lemma lookup; no mathematical content.

**Estimated closure:** < 1 day.

**Missing model element:**
`policyCheck` omits the *mutation* side of `Policy::check_inner` — namely,
recording the nonce in `usedNonces` after a successful check.  The full
fail-closed property includes "nonce window exhaustion → deny" (step 4 in
`src/auth/policy.rs:99-103`).  Modelling this requires threading a state monad
through `policyCheck`.  Estimated additional work: 1 day.

---

## I2 — Capability-Gated

### Gap: `capabilityGated_rightRequired`

**What it says in plain language:**
If `policyCheck` returns `true`, then the requested right is actually in the
token's rights set.

**Why it has `sorry`:**
Same `Bool.and_eq_true` decomposition as the I1 gaps — the last conjunct of
`policyCheck` is the rights check.  `simp [Bool.and_eq_true]` applied four
times should extract it.

**Estimated closure:** < 1 day.

### Gap: `delegationNonAmplification` — **no sorry** (already closes)

The theorem in `Refinement.lean` closes directly from its hypotheses.  The
*real* work is constructing the hypotheses at a call site — specifically,
proving that `concreteDelegateCap` (from `LuxRefinement.lean`) satisfies those
hypotheses when called via `Policy::check`.  This coercion from the `Cap` type
used in `LuxRefinement` to the `RustCap` type defined in `Refinement.lean` is
not yet written.

**Estimated closure:** 1 day (write the coercion lemma; the proof then assembles
from existing proved theorems).

### TCB gap affecting I2: `WorkQueue::enqueue` bypass

The `Scheduler::schedule` wrapper in `src/scheduler/mod.rs` enforces
`CapabilitySet::SCHEDULE` via `Policy::check`.  However, `WorkQueue::enqueue`
remains a public method that bypasses the check.  There is no Lean model of
`WorkQueue` and therefore no theorem that closes this gap formally.

**Blast radius:** Any caller that accesses `WorkQueue` directly and calls
`enqueue` without first calling `Scheduler::schedule` bypasses I2 for
scheduling operations.  In the current codebase only test harnesses do this
(using `WorkQueue` directly for capacity tests).

**Estimated closure:** 2–3 days to write a Lean model of `Scheduler` and prove
that the `schedule` method is the only path to `WorkQueue::enqueue` visible
from the public API.

---

## I3 — Accountable Resources

### Gap: `accountableResources_soleDeductionPath`

**What it says in plain language:**
The only way a node's balance can decrease is via a call to `deductFn` that
satisfies `AbstractLedger.Spec`.

**Why it has `sorry`:**
This is a *meta-property* about the `Spec` predicate: it says that the four
Spec properties are *complete* in the sense that no other function satisfying
the Spec can reduce a balance except through `exact_amount`.  The argument
requires showing:
1. `over_quota` forbids deduction when `amount > balance`.
2. `exact_amount` forces the new balance to be `balance - amount`.
3. Combined, these two imply that the only reachable `(l', b')` pairs have
   `b' = balance - amount` for some `amount ≤ balance`.

This is a formal inductive argument over the Spec structure.  No novel
mathematics, but requires careful encoding.

**Estimated closure:** 2–3 days.

### Gap: `accountableResources_ceilingBound`

**What it says in plain language:**
After seeding a node with ceiling `c`, every successful deduction produces a
balance in `[0, c]`.

**Why it has `sorry`:**
`LuxCostModel.ledger_invariant` already proves this for the concrete `deduct`
function.  Lifting to any function satisfying `AbstractLedger.Spec` requires
combining `spec.exact_amount` (gives `b = ceiling - amount`) with
`spec.over_quota` (gives `amount ≤ ceiling` on success).  A 5-line Lean proof
once the induction structure is identified.

**Estimated closure:** 1 day.

### TCB gap affecting I3: u64 vs Lean `Nat`

`Ledger::deduct` in Rust uses `u64` arithmetic with `checked_sub`.  The Lean
model uses `Nat` (unbounded).  There is no Lean theorem bounding ledger
balances to `[0, 2^64 - 1]`.  The `checked_sub` gate prevents underflow
(and the Kani proof `successful_deduction_is_exact` verifies this at the Rust
level), but the 2^64 ceiling is not formally modelled.

**Impact:** The `accountableResources_ceilingBound` theorem would need a
`Fin (2^64)` version of the ledger to fully close this gap.

**Estimated closure:** 3–5 additional days beyond the `Nat` version.

---

## I4 — Topology-Bounded

### Gap: `topologyBounded_traversalSubsetDeclaredEdges` (under hypothesis)

**What it says in plain language:**
Every successful traversal corresponds to a declared edge.

**The theorem closes given `hCorrespondence`.**  The remaining work is proving
`hCorrespondence` — that the 64×64 `u64` bitmask in `OperationalGraph` is
equivalent to the set of edges passed to `permit_edge` during booting.

**Why this is hard:**
1. The Rust `edge_matrix: [u64; 64]` must be modelled in Lean as a
   `Fin 64 → Fin 64 → Bool` or a `Finset (Fin 64 × Fin 64)`.
2. The sealing step `BootingGraph::seal` copies `edge_matrix` verbatim.
   Lean needs a model of both `BootingGraph` and `OperationalGraph` and a
   proof that seal preserves the edge set.
3. `permit_edge` sets bit `di` in `edge_matrix[si]`.  The correspondence
   `(si, di) ∈ declaredEdges ↔ (edge_matrix[si] >> di) & 1 == 1` requires
   the `bitsContainsIffSubset` approach extended to 2D.

**Prerequisites:**
- Lean 4 `BitVec` or `Fin`-indexed array model for the bitmask
- Understanding of `LuxCapabilityBridge.lean`'s bitmask approach (reusable)

**Estimated closure:** 3–5 days for the `hCorrespondence` proof; an additional
1 day to write the `BootingGraph`/`OperationalGraph` Lean types.

### Gap: `topologyBounded_sealingIrreversible`

**What it says in plain language:**
Once the graph is sealed, no new edges can be added.

**Status:** The `Refinement.lean` theorem for this is a trivial placeholder
(proves `True`).  The meaningful statement — that no function of type
`OperationalGraph → Edge → OperationalGraph` can be defined from the current
Lean model — is a *structural property* of the model, not a theorem within it.

It is guaranteed at the Rust level by the ownership/move semantics of `seal`
(`src/topology/graph.rs:94`): `seal(self)` consumes `BootingGraph` by value,
making it impossible to call `permit_edge` on it afterward.  Lean's type system
would provide the same guarantee once `OperationalGraph` is defined without
any mutation methods.

**Estimated closure:** 1 day once the `OperationalGraph` Lean type is written
(dependency of I4-A above).

---

## Cross-cutting gaps

### Concurrent access
All proofs here are sequential.  The TLA+ model (`tla/LuxKernel.tla`) covers
distributed concurrency.  There is no Lean formalisation of concurrent
semantics.  This is a known, documented gap in `lean/LuxRefinement.lean §3`.

### Nonce window mutable state
`Policy::check_inner` mutates `used_nonces` on success (step 4).  The Lean
`policyCheck` model is a pure Boolean function and does not represent this
mutation.  A complete I1 formalisation requires a state-monad model of
`PolicyState` or an explicit `(input, output)` pair for `used_nonces`.

### Scheduler `WorkQueue` bypass
See I2 section above.

---

## Recommended proof engineering sequence

For an auditor closing these gaps top-down (highest value first):

1. **Close I1-A, I2-A** (< 2 days combined): pure `simp` / `Bool` algebra.
   These are the quickest wins and validate the `policyCheck` model.

2. **Write `OperationalGraph` Lean type** (1 day): prerequisite for I4-A and I4-B.
   Model `edge_matrix` as `Fin 64 → Fin 64 → Bool`.

3. **Close I4-A `hCorrespondence`** (3–5 days): the core topology proof.
   Reuse the bitmask approach from `LuxCapabilityBridge.lean`.

4. **Close I3-B `ceilingBound`** (1 day): short proof from existing Spec properties.

5. **Close I3-A `soleDeductionPath`** (2–3 days): the abstract completeness argument.

6. **Model mutable nonce window** (1–2 days): state monad extension of I1.

7. **Write `Scheduler` Lean model and close I2 scheduler gap** (2–3 days).

Total estimated investment to close all gaps: **11–17 days** of focused Lean 4
proof engineering.

---

## FunctionSpecs `REFINEMENT_GAP` triage (89 flags)

**This section is a different registry from everything above.** The I1–I4
gaps above are named `sorry`s in `lean/Refinement.lean`. The 89 entries
triaged below are `REFINEMENT_GAP` flags in `lean/FunctionSpecs/` — places
where the unproved spec layer covering all of `src/` (see
`docs/FUNCTION_SPECS.md`) could not write a clean precondition/postcondition
for a production function. The two registries are unrelated; do not merge
counts between them.

Every flagged function is sorted into exactly one of three buckets so this
becomes a triage document, not just a list. All 89 are accounted for below
— no orphans.

### Buckets

| Bucket | Meaning | Recommended action |
|---|---|---|
| `INVARIANT-BOUNDARY` | The function's own Lux-authored decision/orchestration logic determines whether I1–I4 hold — not merely a delegate to an external crypto/hardware primitive. | High priority for formal verification (Lean modelling). |
| `BELOW-BOUNDARY` | Implementation detail: a bare crypto primitive (Ed25519/SHA-256), OS entropy, mutex/heap-internal state, memory zeroization, serialization (CBOR/JSON/`PyDict`), or FFI marshaling — the I1–I4 decision itself is made by a separately-specified, gap-free function that consumes this one's result. | Adversarial/property/fuzz testing against known test vectors and the real library; not a Lean-modelling priority. |
| `SPEC-GAP` | The function has no real behaviour yet (an unconditional stub awaiting a future hardware/FFI integration) or its intended behaviour is a genuinely undecided design choice (e.g. heap tie-break order). | Needs a design decision before any verification — formal or adversarial — is meaningful. |

### Classification rule

A function is `INVARIANT-BOUNDARY` only if **both**:
1. its result is consumed (directly, or one call away) by one of the four
   enforcement points named in `CLAUDE.md` — `Policy::check`,
   `Capability::authorises`, `Ledger::deduct`, `OperationalGraph::traverse`
   — or by the Raft state machine that decides distributed topology
   commitment (`src/consensus/raft.rs`, per `src/consensus/mod.rs`'s own
   module doc — see caveat below), **and**
2. the `REFINEMENT_GAP` reason cites *Lux-authored* decision/orchestration
   logic, not solely a delegate to an external crypto/hardware/library call.

A bare delegate to a crypto/entropy/hardware primitive is `BELOW-BOUNDARY`
even when it sits structurally close to a decision (e.g.
`BootCredentials::verify` delegating to `HsmProvider::verify`) — the
boundary is the orchestration *around* the primitive (already specified,
not gapped), not the primitive's own mathematical soundness, which Lean
cannot usefully characterize and which is properly the job of the
underlying crypto library's own test suite.

**Caveat found while grounding this triage:** `docs/adr/0004-distributed-topology-consensus.md`
describes a crash-stop single-round quorum-vote protocol ("no leader
election, no log replication"). The code in `src/consensus/` implements
full Raft (leader election + log replication), and `src/consensus/mod.rs`'s
own module doc states it "replaces the earlier single-round quorum protocol
with a correct, linearisable Raft implementation." ADR-0004 was not
updated/superseded when that happened — it currently documents a protocol
the codebase no longer runs. Fixing the ADR is outside this triage's
docs-only, `REFINEMENT_GAPS.md`-only scope, but it is recorded here because
the `INVARIANT-BOUNDARY` calls for all nine `Consensus.lean` entries below
rest on `consensus/mod.rs`'s (current, uncontradicted) module doc, not on
the stale ADR.

**Note on the task's stated "4 invariants":** the prompt for this triage
listed them as "(authorization, revocation, delegation nonce,
auditability)," which does not match the four enforcement points actually
named in `CLAUDE.md` (I1 Fail-Closed / I2 Capability-Gated / I3 Accountable
Resources / I4 Topology-Bounded). The classification below uses the
`CLAUDE.md` definitions as ground truth. This made no practical difference:
`Metabolism.lean` (I3) and `Topology.lean` (I4's graph construction itself)
have zero `REFINEMENT_GAP` entries between them, so no row below depends on
resolving the discrepancy.

### Summary

| Bucket | Count |
|---|---|
| `INVARIANT-BOUNDARY` | 11 |
| `BELOW-BOUNDARY` | 56 |
| `SPEC-GAP` | 22 |
| **Total** | **89** |

### `Audit.lean` (3)

| Function | file:line | Bucket | Why |
|---|---|---|---|
| `exportJson` | `src/audit/log.rs:240` | `BELOW-BOUNDARY` | JSON formatting detail; not consumed by any I1–I4 enforcement point. |
| `verifyChain` | `src/audit/log.rs:178` | `BELOW-BOUNDARY` | SHA-256 chain-integrity check; a forensic tool, not on the live `append`/`is_full` fail-closed path that gates I1. |
| `computeHash` | `src/audit/log.rs:281` | `BELOW-BOUNDARY` | Bare SHA-256 digest primitive. |

### `Boot.lean` (10)

| Function | file:line | Bucket | Why |
|---|---|---|---|
| `manifestDecoderDecode` | `src/boot/decode.rs:72` | `INVARIANT-BOUNDARY` | The accept/reject gate for the entire boot manifest — Lux-authored "verify signature before parsing" ordering feeds I2/I4 trust establishment. |
| `manifestDecoderParseCbor` | `src/boot/decode.rs:93` | `BELOW-BOUNDARY` | Delegates to `minicbor::Decoder`; structural parsing consumed by the already gap-free `BootingGraph::activate`/`permit_edge`. |
| `manifestDecoderParseEdges` | `src/boot/decode.rs:124` | `BELOW-BOUNDARY` | CBOR array decode; same external-parser delegation as `parseCbor`. |
| `manifestDecoderParseQuotas` | `src/boot/decode.rs:177` | `BELOW-BOUNDARY` | Same as `parseEdges`. |
| `bootCredentialsFromKeyBytes` | `src/boot/credentials.rs:39` | `BELOW-BOUNDARY` | Bare delegate to `SoftwareHsm::from_verifying_key` (Ed25519 curve-point check). |
| `bootCredentialsVerify` | `src/boot/credentials.rs:65` | `BELOW-BOUNDARY` | One-line delegate to `HsmProvider::verify`; no Lux-authored logic beyond the call. |
| `bootCredentialsGenerateCapabilitySeed` | `src/boot/credentials.rs:74` | `BELOW-BOUNDARY` | Bare delegate to HSM entropy source. |
| `bootStateProduceAttestation` | `src/boot/mod.rs:121` | `BELOW-BOUNDARY` | Produces TPM quote data; does not itself decide accept/reject (the consumer, `BootAttestation::verify`, is gap-free). |
| `bootStateInitialiseWithTpm` | `src/boot/mod.rs:264` | `INVARIANT-BOUNDARY` | All-or-nothing orchestration (decode + verify + TPM extend) gating the entire boot sequence (I1) — per `mod.rs`'s own doc, failure retains no partial state. |
| `manifestParseAndVerify` | `src/boot/manifest.rs:55` | `SPEC-GAP` | Unconditional stub ("parser not yet wired"); real wire-format design not yet decided. |

### `PythonBindings.lean` (5)

| Function | file:line | Bucket | Why |
|---|---|---|---|
| `luxKernelModule` | `src/python/mod.rs:45` | `BELOW-BOUNDARY` | PyO3 macro-generated module registration; no decision logic. |
| `pyAuditLogExportJson` | `src/python/audit.rs:174` | `BELOW-BOUNDARY` | JSON serialization wrapper. |
| `pyPolicyGateCheck` | `src/python/policy.rs:163` | `BELOW-BOUNDARY` | GIL + `PyDict` marshaling around an already gap-free `Policy::check`-backed decision. |
| `pyLuxGateAuthorizeCe` | `src/python/gate.rs:151` | `BELOW-BOUNDARY` | `PyDict` marshaling; the underlying `check` logic is specified separately (per this file's own doc). |
| `pyLuxGateConfig` | `src/python/gate.rs:173` | `BELOW-BOUNDARY` | `PyDict` marshaling for config exposure; no decision logic. |

### `Consensus.lean` (9)

| Function | file:line | Bucket | Why |
|---|---|---|---|
| `startElection` | `src/consensus/raft.rs:146` | `INVARIANT-BOUNDARY` | Decides which node becomes proposer for a topology-edge commit (I4, per `consensus/mod.rs`'s module doc). |
| `step` | `src/consensus/raft.rs:214` | `INVARIANT-BOUNDARY` | Lux-authored dispatcher driving the Raft state machine that commits topology changes; low marginal value since it reduces to its 4 sub-handlers, but it is decision-routing logic, not a primitive delegate. |
| `becomeLeader` | `src/consensus/raft.rs:273` | `INVARIANT-BOUNDARY` | Sets up per-peer replication state determining how edge proposals reach quorum (I4). |
| `sendAeTo` | `src/consensus/raft.rs:301` | `INVARIANT-BOUNDARY` | Builds the replication batch that propagates a proposed edge to peers (I4). |
| `onRequestVote` | `src/consensus/raft.rs:336` | `INVARIANT-BOUNDARY` | The vote-granting decision itself — directly the quorum mechanism I4 depends on. |
| `onAppendEntries` | `src/consensus/raft.rs:377` | `INVARIANT-BOUNDARY` | Follower's accept/reject of a proposed log entry — directly gates what topology changes can ever be committed. |
| `appendLogEntries` | `src/consensus/raft.rs:426` | `INVARIANT-BOUNDARY` | Mutates the replicated log backing the I4 commit decision. |
| `onAeReply` | `src/consensus/raft.rs:442` | `INVARIANT-BOUNDARY` | Leader-side bookkeeping that triggers the commit-index advance (I4). |
| `advanceCommitIndex` | `src/consensus/raft.rs:469` | `INVARIANT-BOUNDARY` | The commit decision itself — decides an edge proposal is final. |

### `Hsm.lean` (51)

| Function | file:line | Bucket | Why |
|---|---|---|---|
| `keyHandleZeroize` | `src/hsm/mod.rs:71` | `BELOW-BOUNDARY` | Memory-zeroization hygiene; not a decision. |
| `hsmProviderGenerateCapabilitySeed` (trait) | `src/hsm/mod.rs:98` | `BELOW-BOUNDARY` | Entropy contract. |
| `hsmProviderSign` (trait) | `src/hsm/mod.rs:106` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `hsmProviderVerify` (trait) | `src/hsm/mod.rs:114` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `keyManagementGenerateKeypair` (trait) | `src/hsm/mod.rs:138` | `BELOW-BOUNDARY` | Entropy + mutex state. |
| `keyManagementSignCapability` (trait) | `src/hsm/mod.rs:147` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `keyManagementVerifyCapabilitySignature` (trait) | `src/hsm/mod.rs:158` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `keyManagementListKeys` (trait) | `src/hsm/mod.rs:171` | `BELOW-BOUNDARY` | Opaque mutex/table state. |
| `keyManagementRotateKey` (trait) | `src/hsm/mod.rs:183` | `BELOW-BOUNDARY` | Entropy + mutex state. |
| `hsmSignedCapabilitySign` | `src/hsm/mod.rs:215` | `BELOW-BOUNDARY` | Bare delegate to `sign_capability`. |
| `hsmSignedCapabilityVerify` | `src/hsm/mod.rs:236` | `BELOW-BOUNDARY` | Bare delegate to `verify_capability_signature`. |
| `hsmSignedCapabilityCapPayload` | `src/hsm/mod.rs:242` | `BELOW-BOUNDARY` | Byte-layout/serialization of the to-be-signed payload. |
| `defaultHsm` | `src/hsm/mod.rs:260` | `BELOW-BOUNDARY` | Trivial delegate to `SoftwareKeyStore::new`. |
| `zeroizingSigningKeyDrop` | `src/hsm/keystore.rs:26` | `BELOW-BOUNDARY` | Memory-zeroization hygiene. |
| `zeroizingSigningKeyFmt` | `src/hsm/keystore.rs:37` | `BELOW-BOUNDARY` | Redacted `Debug` formatting. |
| `softwareKeyStoreNew` | `src/hsm/keystore.rs:69` | `BELOW-BOUNDARY` | Mutex/heap init state. |
| `softwareKeyStoreWithSigningKey` | `src/hsm/keystore.rs:78` | `BELOW-BOUNDARY` | Ed25519 key derivation. |
| `softwareKeyStoreVerifyingKeyBytes` | `src/hsm/keystore.rs:87` | `BELOW-BOUNDARY` | EC scalar-mult derivation. |
| `softwareKeyStoreDefault` | `src/hsm/keystore.rs:96` | `BELOW-BOUNDARY` | Delegate, inherits `new`'s gap. |
| `softwareKeyStoreGenerateCapabilitySeed` | `src/hsm/keystore.rs:101` | `BELOW-BOUNDARY` | OS CSPRNG. |
| `softwareKeyStoreSign` | `src/hsm/keystore.rs:114` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `softwareKeyStoreVerify` | `src/hsm/keystore.rs:124` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `softwareKeyStoreGenerateKeypair` | `src/hsm/keystore.rs:142` | `BELOW-BOUNDARY` | OS CSPRNG + mutex insert. |
| `softwareKeyStoreSignCapability` | `src/hsm/keystore.rs:163` | `BELOW-BOUNDARY` | Mutex lookup + Ed25519 primitive. |
| `softwareKeyStoreVerifyCapabilitySignature` | `src/hsm/keystore.rs:176` | `BELOW-BOUNDARY` | Mutex lookup + Ed25519 primitive. |
| `softwareKeyStoreListKeys` | `src/hsm/keystore.rs:201` | `BELOW-BOUNDARY` | Mutex/table iteration. |
| `softwareKeyStoreRotateKey` | `src/hsm/keystore.rs:208` | `BELOW-BOUNDARY` | OS CSPRNG + mutex atomic swap. |
| `softwareHsmFromVerifyingKey` | `src/hsm/mock.rs:40` | `BELOW-BOUNDARY` | Ed25519 curve-point validation. |
| `softwareHsmFromSigningKey` | `src/hsm/mock.rs:56` | `BELOW-BOUNDARY` | Ed25519 key derivation. |
| `softwareHsmVerifyingKeyBytes` | `src/hsm/mock.rs:67` | `BELOW-BOUNDARY` | Crypto-library byte encoding. |
| `softwareHsmGenerateCapabilitySeed` | `src/hsm/mock.rs:73` | `BELOW-BOUNDARY` | SHA-256 primitive. |
| `softwareHsmSign` | `src/hsm/mock.rs:81` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `softwareHsmVerify` | `src/hsm/mock.rs:91` | `BELOW-BOUNDARY` | Ed25519 primitive. |
| `pkcs11HsmProviderNewStub` | `src/hsm/pkcs11.rs:35` | `BELOW-BOUNDARY` | Trivial constructor; current behaviour fully decided (stores a path, no logic). |
| `pkcs11HsmProviderGenerateCapabilitySeed` | `src/hsm/pkcs11.rs:43` | `SPEC-GAP` | Unconditional stub error; real PKCS#11 FFI behaviour not yet designed. |
| `pkcs11HsmProviderSign` | `src/hsm/pkcs11.rs:49` | `SPEC-GAP` | Same. |
| `pkcs11HsmProviderVerify` | `src/hsm/pkcs11.rs:55` | `SPEC-GAP` | Same. |
| `pkcs11HsmProviderGenerateKeypair` | `src/hsm/pkcs11.rs:63` | `SPEC-GAP` | Same. |
| `pkcs11HsmProviderSignCapability` | `src/hsm/pkcs11.rs:69` | `SPEC-GAP` | Same. |
| `pkcs11HsmProviderVerifyCapabilitySignature` | `src/hsm/pkcs11.rs:75` | `SPEC-GAP` | Same. |
| `pkcs11HsmProviderListKeys` | `src/hsm/pkcs11.rs:86` | `SPEC-GAP` | Same. |
| `pkcs11HsmProviderRotateKey` | `src/hsm/pkcs11.rs:92` | `SPEC-GAP` | Same. |
| `yubiHsmProviderNewStub` | `src/hsm/yubihsm.rs:41` | `BELOW-BOUNDARY` | Trivial constructor; current behaviour fully decided. |
| `yubiHsmProviderGenerateCapabilitySeed` | `src/hsm/yubihsm.rs:47` | `SPEC-GAP` | Unconditional stub error; real YubiHSM FFI behaviour not yet designed. |
| `yubiHsmProviderSign` | `src/hsm/yubihsm.rs:53` | `SPEC-GAP` | Same. |
| `yubiHsmProviderVerify` | `src/hsm/yubihsm.rs:59` | `SPEC-GAP` | Same. |
| `yubiHsmProviderGenerateKeypair` | `src/hsm/yubihsm.rs:67` | `SPEC-GAP` | Same. |
| `yubiHsmProviderSignCapability` | `src/hsm/yubihsm.rs:73` | `SPEC-GAP` | Same. |
| `yubiHsmProviderVerifyCapabilitySignature` | `src/hsm/yubihsm.rs:79` | `SPEC-GAP` | Same. |
| `yubiHsmProviderListKeys` | `src/hsm/yubihsm.rs:90` | `SPEC-GAP` | Same. |
| `yubiHsmProviderRotateKey` | `src/hsm/yubihsm.rs:96` | `SPEC-GAP` | Same. |

### `SchedulerWasmTpm.lean` (11)

| Function | file:line | Bucket | Why |
|---|---|---|---|
| `WorkQueue.drainOrdered` | `src/scheduler/queue.rs:96` | `SPEC-GAP` | Heap tie-break order among equal-priority items is an undecided design choice, not a crypto/hardware limit. |
| `WasmExecutor.new` | `src/wasm/executor.rs:57` | `BELOW-BOUNDARY` | Constructs a `wasmtime::Engine`/`Linker`; external-crate behaviour. |
| `WasmExecutor.callNullary` | `src/wasm/executor.rs:150` | `BELOW-BOUNDARY` | Executes arbitrary guest bytecode; the capability-gated host-call ABI it runs against (`src/wasm/host.rs`) is itself gap-free, so only the guest's opaque computation is unmodelled. |
| `SoftwareTpm.extendPcr` | `src/tpm/mock.rs:57` | `BELOW-BOUNDARY` | SHA-256 primitive. |
| `SoftwareTpm.quote` | `src/tpm/mock.rs:71` | `BELOW-BOUNDARY` | SHA-256-derived attestation data; the consuming verifier (`BootAttestation::verify`) is gap-free. |
| `SoftwareTpm.verifyQuote` | `src/tpm/mock.rs:102` | `BELOW-BOUNDARY` | SHA-256 collision-resistance assumption; bare primitive. |
| `TssTpmProvider.newStub` | `src/tpm/tss.rs:41` | `BELOW-BOUNDARY` | Trivial constructor (`Self { _connected: false }`); current behaviour fully decided. |
| `TssTpmProvider.extendPcr` | `src/tpm/tss.rs:47` | `SPEC-GAP` | Unconditional stub error; real TPM 2.0/TCTI integration not yet designed (module doc: "until a real TPM 2.0 device is connected"). |
| `TssTpmProvider.quote` | `src/tpm/tss.rs:53` | `SPEC-GAP` | Same. |
| `TssTpmProvider.readPcr` | `src/tpm/tss.rs:59` | `SPEC-GAP` | Same. |
| `TssTpmProvider.verifyQuote` | `src/tpm/tss.rs:65` | `SPEC-GAP` | Same. |

### How this triage was produced

Read-only pass first: re-extracted the full 89-entry register directly from
each `lean/FunctionSpecs/*.lean` file's own `REFINEMENT_GAP` table (not just
`docs/FUNCTION_SPECS.md`'s condensed `Hsm.lean` summary), then cross-checked
the security-relevance of the ambiguous cases against the actual Rust
source (`src/boot/credentials.rs`, `src/boot/mod.rs`, `src/tpm/tss.rs`,
`src/hsm/pkcs11.rs`, `src/wasm/host.rs`, `src/consensus/mod.rs`) and
`docs/adr/0004-distributed-topology-consensus.md` before assigning a single
bucket per function. No Lean or Rust source file was modified by this pass.
