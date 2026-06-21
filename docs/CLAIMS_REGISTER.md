# Claims Register — Lux Kernel Documentation Audit

**Purpose:** A read-only, source-by-source ledger of factual claims made in
this repository's documentation, checked against the actual source code,
test output, and committed artifacts. No file other than this one was
created or modified to produce this register.

**Status legend:**
- **CONFIRMED** — claim matches source/tests/artifacts exactly.
- **CONFIRMED-EXECUTED** — claim is backed by a real, committed run (output
  files, raw tool output), not just narrative text.
- **CONTRADICTED** — two or more committed sources disagree, or the doc
  disagrees with the source code.
- **UNVERIFIED** — could not be checked from this sandbox (missing
  toolchain, no network, etc.); the doc's own self-assessment is taken at
  face value but not independently confirmed.
- **MISSING** — a real, relevant fact is absent from the documentation set
  entirely.

---

## 1. `README.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| "Lean 4 four-file proof suite (lean/), lake build-verified, zero `sorry`" | README.md:181-187 (Tier 3 checklist) | **CONTRADICTED** | `docs/REFINEMENT_GAPS.md:17-27` states `lakefile.lean` never declared a Mathlib dependency despite `LuxSpec.lean`/`LuxCapabilityBridge.lean` requiring Mathlib types (`Finset`, `lemma` macro) — "Any prior 'Build completed successfully' claim for this proof tree predates an actual working build." `lake` is not installed in this sandbox, so the *current* claim (post-fix) cannot be independently re-verified; the documentary record shows the claim was false as originally made. | Same fact also contradicts `TIER_BOUNDARIES.md:139` — see §6 below. |
| "2 of its 9 theorems (the I3 obligations) are not yet closed and remain `sorry`" | README.md:85-86 | **CONTRADICTED** | `docs/REFINEMENT_GAPS.md:1-8` and its theorem table (lines 88-260) document **4** remaining `sorry`s: 2 I3 (`accountableResources_soleDeductionPath`, `accountableResources_ceilingBound`) **and** 2 I4 (`topologyBounded_traversalSubsetDeclaredEdges`, `topologyBounded_sealingIrreversible`). README omits the I4 gaps and undercounts by half. | This is the more detailed, more recently-touched doc (`REFINEMENT_GAPS.md`); treat it as ground truth over README. |
| `docs/adr/ # Architecture Decision Records (0001–0005)` | README.md:376 | **CONFIRMED** | `ls docs/adr/` shows exactly 5 files: 0001 through 0005. | — |
| EU AI Act hiring demo: race p=0.597, gender p=0.751, n implied 100 | README.md:218-219 | **CONFIRMED-EXECUTED** | `hiring-audit/output/bias_report.txt`: race χ²=2.7714 p=0.596781 (rounds to 0.597 ✓), gender χ²=0.5716 p=0.751409 (rounds to 0.751 ✓), n=100 for both. | Real generated output, not narrative-only. |
| Fair lending demo: 5 attrs, p-values 0.877/0.910/0.591/0.331/0.833; gender+disability pass 4/5ths rule; 200 decisions | README.md:230-235 | **CONFIRMED-EXECUTED**, with a **selective-reporting caveat** | `lending-audit/output/bias_report.txt` matches all 5 p-values exactly (0.8771, 0.9097, 0.5911, 0.3312, 0.8333) and confirms gender/disability pass 4/5ths. **Not mentioned in README:** the same report's overall 4/5ths verdict flags **age, race, and marital_status** bands as falling below the 80% threshold ("ECOA/FHA disparate impact review recommended"). | Every individual number README cites is accurate; the selective framing ("Gender and disability... pass") omits that three of five attributes fail the same test in the same report. A reader of README alone would not know this demo's own output recommends a disparate-impact review. |
| Recidivism demo: race p=0.916, gender p=0.617, Black 62.0%/White 60.6% (1.4-pt gap) vs. COMPAS 17-pt gap, n=150 | README.md:251-253 | **CONFIRMED-EXECUTED** | `recidivism-demo/output/fairness_report.txt`: race p=0.9162 (≈0.916 ✓), gender p=0.6174 (≈0.617 ✓), Black 62.0% / White 60.6% → 1.4-pt gap ✓, n=150 ✓, COMPAS baseline cited as p<0.001 / n=7,214 matching the ProPublica figure README also cites. | — |
| "Third-party security audit is not yet complete... Target: Q3 2026" | README.md:410-412 | **CONFIRMED (internally consistent)** | Matches `AUDIT_ROADMAP.md:4,32-42` timeline exactly (vendor shortlist Q3 2026, audit execution Q3 2026). | Consistent across docs — not independently verifiable that the date will hold, but the docs agree with each other. |
| `cargo test --all-features` → "318 total" tests | README.md:281-283 | **UNVERIFIED** | Could not run `cargo test` in this pass (out of scope for a read-only register; verifying would require executing the full suite). `TIER_BOUNDARIES.md:71` repeats the same "318 tests" figure, so the two docs are at least internally consistent. | Recommend an explicit `cargo test --all-features` run before citing this number to an external auditor. |

---

## 2. `docs/SECURITY.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| V-03: "`Capability::authorises` requires `self.generation >= current_gen`" | SECURITY.md:93 | **CONTRADICTED** | `src/auth/capability.rs:69-70`: `self.generation == current_gen && self.rights.contains(right)`. The function's own doc comment (lines 61-67) explains this is a **deliberate** choice of `==` over `>=`: "A token with `generation > current_gen` would permanently pass a `>=` check and survive rotation, defeating the kill switch." | The code is correct and more secure than the doc describes; the doc describes a weaker (and arguably exploitable) mechanism than what is actually implemented. Low risk to ship, but an external auditor reading only SECURITY.md would test the wrong invariant. |
| All other V-01–V-13 mitigation mappings | SECURITY.md:91-103 | **CONFIRMED** (spot-checked V-01, V-02, V-06, V-07, V-10, V-13) | `Capability` fields are `pub(crate)` (capability.rs); `delegate` checks `self.rights.contains(subset)`; `Ledger::deduct` uses `checked_sub`; `#![deny(unsafe_code)]` present in `lib.rs`; `Zeroize`/`ZeroizeOnDrop` derived on `Capability`. | Not re-verified line-by-line for all 13 rows; the 6 spot-checked rows all matched source exactly. |
| F-01/F-02/F-03 "Resolved" | SECURITY.md:109-111 | **CONFIRMED** | `src/hsm/mock.rs:88` (`verify_strict`), `src/auth/revocation.rs` exists, `src/audit/log.rs` exists — all three files present and match the cited line ranges in `TCB.md`. | — |

---

## 3. `docs/adr/0005-revocation-semantics.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| "When a capability is checked, it must satisfy: `cap.generation >= current_generation`" | 0005-revocation-semantics.md:11-15 | **CONTRADICTED** | Same as the SECURITY.md V-03 finding above — actual code uses `==`, not `>=`, and the in-source comment explains `>=` would be a security regression. | Two independent docs (SECURITY.md and this ADR) both assert the same wrong operator, suggesting the error was copied between them rather than independently introduced. Worth fixing both in one pass. |

---

## 4. `docs/ARCHITECTURE.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| Boot sequence step 2: "`Manifest::parse_and_verify()` validates... non-empty, well-formed wire format... edge table... quota table... cryptographic signature" | ARCHITECTURE.md §5 (boot sequence) | **CONTRADICTED / STALE REFERENCE** | `grep -rn "parse_and_verify" src/ tests/` returns exactly one hit — the function's own definition in `src/boot/manifest.rs:55`. It is never called from `BootState::initialise` (`src/boot/mod.rs:240`) or `initialise_with_tpm` (`src/boot/mod.rs:264`), which instead call `ManifestDecoder::decode` (`src/boot/decode.rs`). `parse_and_verify` itself unconditionally returns `Err(ManifestInvalid)` for any non-empty input ("parser not yet wired (stub)", per its own doc comment). | Downgraded from initial concern: this is **not** a live security check silently failing — it's genuinely dead code that nothing in the boot path calls. `docs/REFINEMENT_GAPS.md:406` independently classifies this exact function as `SPEC-GAP` ("Unconditional stub... real wire-format design not yet decided"), confirming the project itself knows it's a stub. The bug is that ARCHITECTURE.md's boot-sequence narrative cites the stub's name instead of the real `ManifestDecoder::decode` path, which could mislead a reviewer auditing the actual signature-verification code into reading the wrong file. |
| "Missing nodes... caught at manifest parse time in `boot::Manifest::parse_and_verify()`" | ARCHITECTURE.md §4.1 | **CONTRADICTED / STALE REFERENCE** | Same root cause as above — this validation, if it happens at all, happens in `ManifestDecoder::decode`/`parse_quotas`, not in the named (dead) function. | Same fix as above: replace the function name cited in prose with `ManifestDecoder::decode`. |
| ADR cross-references: lists only 0001, 0002, 0005 | ARCHITECTURE.md §6 | **Minor incompleteness, not a contradiction** | `docs/adr/` contains 5 files (0001-0005); ARCHITECTURE.md's "detailed rationale" list narratively cites only 3 of them, omitting 0003 (epoch-based revocation) and 0004 (distributed topology consensus). | Doesn't claim to be exhaustive, so not a false statement — but a reader following ARCHITECTURE.md's links alone would miss the two ADRs most relevant to the Raft/consensus contradiction noted in §7 below. |
| Single-threaded execution / `!Send`/`!Sync` on `AuditLog` | ARCHITECTURE.md §4.2, README.md, TCB.md §3.4 | **CONFIRMED** | `src/audit/log.rs:87-93` per TCB.md citation; consistent across all three docs. | — |

---

## 5. `docs/FORMAL_VERIFICATION.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| TLC results: 322,560 distinct states, 0 violations, all 4 theorems PASS | FORMAL_VERIFICATION.md §2 | **UNVERIFIED (toolchain absent)** | `tla2tools.jar` is listed in the file map (`tla/tla2tools.jar`) but Java/TLC was not re-run in this pass. Internally consistent with README.md and TIER_BOUNDARIES.md, which cite the identical figures. | Re-running `java -jar tla2tools.jar MC.tla -config MC.cfg` would let this move to CONFIRMED-EXECUTED; flagged here as a to-do for whoever has the toolchain available. |
| §6 Lean 4 verification: "`lake build` ... Expected: Build completed successfully" | FORMAL_VERIFICATION.md §6 | **CONTRADICTED** | Same finding as README's Lean claim above — `docs/REFINEMENT_GAPS.md` documents that this build could not have succeeded in the tree's prior state due to a missing Mathlib dependency declaration. | Duplicate of the README finding; both docs need the same correction once `lake build` is actually confirmed green by someone with the toolchain. |
| Bitfield bridge gap: "`UInt32` values reduce to the `Fin 32` case... documented... but not yet mechanically verified" | FORMAL_VERIFICATION.md §6 (Remaining gap) | **CONFIRMED (honest self-disclosure)** | Matches `docs/REFINEMENT_GAPS.md`'s broader pattern of disclosing exactly which Lean proofs are real vs. placeholder. | This is the *one* place FORMAL_VERIFICATION.md itself flags a gap — appropriately so. |

---

## 6. `TIER_BOUNDARIES.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| Tier 3 item "Formal cost model" — Current State: "Manual analysis only"; Missing: "Mechanized proof (Lean/Isabelle)" | TIER_BOUNDARIES.md:139 | **CONTRADICTED** | This is a direct, clean contradiction with this repository's own `docs/FORMAL_COST_MODEL.md` (an entire document describing 7 mechanically-proved Lean 4 theorems in `lean/LuxCostModel.lean`) and with README.md's Tier 3 checklist, which checks off "[x] Formal proofs — Lean 4 four-file proof suite (lean/), lake build-verified, zero `sorry`" as **done**. Both sides cite the same artifact (`lean/LuxCostModel.lean`) and disagree about whether it exists/counts. | This is the cleanest contradiction in the register — no nuance needed, two committed files flatly disagree about the same file. Whoever wrote TIER_BOUNDARIES.md's Tier 3 table appears not to have been updated when the Lean suite was added under Tier 3 elsewhere in README. Recommend reconciling by either updating TIER_BOUNDARIES.md to mark this "Complete" (matching README) or downgrading README's checkbox (if the Lean proof is judged insufficiently rigorous to count) — but the two cannot both stand as written. |
| Tier 2.5 key results (hiring/lending/recidivism p-values) | TIER_BOUNDARIES.md:116-118 | **CONFIRMED-EXECUTED** | Identical figures to README, independently re-checked against the same `output/*report*.txt` files in §1 above. | — |
| "318 total tests" | TIER_BOUNDARIES.md:71 | **UNVERIFIED** | Same as README's test-count claim — not independently re-run in this pass. | — |

---

## 7. `docs/REFINEMENT_GAPS.md` (self-contained findings)

These are findings the document discloses about itself / about other parts
of the codebase; listed here because they are exactly the kind of fact an
external auditor needs surfaced, not buried in a 536-line gap-triage doc.

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| ADR-0004 describes "a crash-stop single-round quorum-vote protocol (no leader election, no log replication)"; actual `src/consensus/` code implements full Raft | REFINEMENT_GAPS.md:353-364 (self-disclosed caveat) | **CONTRADICTED** | `docs/adr/0004-distributed-topology-consensus.md` describes the older single-round protocol. `src/consensus/mod.rs`'s own module doc (per REFINEMENT_GAPS.md's citation) states the Raft implementation "replaces the earlier single-round quorum protocol with a correct, linearisable Raft implementation." ADR-0004 was never updated to reflect this. | Sourced entirely from the codebase's own self-disclosure; trivial to fix by updating ADR-0004's status to "Superseded" with a pointer to the current `consensus/mod.rs` doc, or by writing a new ADR-0006. |
| `WorkQueue::enqueue` remains public and bypasses `Policy::check` (`Scheduler::schedule` is the intended gate) | REFINEMENT_GAPS.md:143-157 | **CONFIRMED gap, correctly disclosed** | Matches the project's own description; in current usage only test harnesses call `WorkQueue` directly. | Not a hidden issue — REFINEMENT_GAPS.md states the blast radius accurately ("In the current codebase only test harnesses do this"). |
| 89-entry `REFINEMENT_GAP` triage: 11 `INVARIANT-BOUNDARY`, 56 `BELOW-BOUNDARY`, 22 `SPEC-GAP` | REFINEMENT_GAPS.md:376-383 | **CONFIRMED (internally)** | Counted the per-file tables (`Audit.lean` 3, `Boot.lean` 10, `PythonBindings.lean` 5, `Consensus.lean` 9, `Hsm.lean` 51, `SchedulerWasmTpm.lean` 11 = 89 total) — arithmetic checks out, no orphaned rows. | — |

---

## 8. `docs/TCB.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| "Kani proofs in `src/metabolism/ledger.rs` and `src/auth/capability.rs`... Kani harness existence confirmed in comments but not independently executed" | TCB.md §3.6 | **CONFIRMED (existence) / UNVERIFIED (execution)** | `grep -rn "#\[kani::proof\]"` confirms harnesses exist at `src/metabolism/ledger.rs:134,157` and `src/auth/capability.rs:194,227`. No `kani` binary available in this sandbox to actually run them. | TCB.md's own [UNVERIFIED ASSUMPTION] tag on this row is accurate and should be left as-is rather than "fixed" — it's a correct self-disclosure, not an error. |
| All other [UNVERIFIED ASSUMPTION]-tagged rows (hardware, OS, side-channel, multi-core) | TCB.md §3.1-3.6, §4 | **CONFIRMED (existence of disclosure)** | Spot-checked several citations (`src/lib.rs:32-35` for the `unsafe_code` carve-out, `src/audit/log.rs:87-93` for `!Send`/`!Sync`) — line numbers match actual content. | This is the most rigorously self-disclosing document in the set; no contradictions found. |

---

## 9. `docs/FORMAL_COST_MODEL.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| 7 ledger theorems proved with no `sorry` | FORMAL_COST_MODEL.md (throughout) | **UNVERIFIED (toolchain absent)**, contradicted by README's framing as already-confirmed | Theorem statements are present in the doc and structurally match `src/metabolism/ledger.rs`'s `checked_sub`-based logic by inspection. Cannot run `lake build` here. | Same underlying issue as the README/FORMAL_VERIFICATION Lean findings — this doc's "what is proved" claims may be accurate now (per REFINEMENT_GAPS.md's remediation note) but were not accurate at some prior point, and nothing in this doc itself flags that history. |
| Own checklist (lines 300-312): "Before claiming the formal proofs represent the implementation: [ ] `lean/LuxCostModel.lean` compiles..." — **all boxes unchecked** | FORMAL_COST_MODEL.md §"Correspondence checklist" | **Internally inconsistent with the rest of the same document** | The document spends 280 lines asserting "what is proved" in confident present tense, then ends with an entirely unchecked verification checklist for the same claims. | This is the document's own tell that its earlier claims were aspirational at the time of writing. Recommend either checking these boxes (once independently confirmed) or moving the confident prose to conditional language until then. |

---

## 10. `docs/BENCHMARKS.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| "Last run: 2026-06-20 (confirmed `cargo bench` run...)"; 5 measured benchmarks with raw Criterion output | BENCHMARKS.md §"Current Baseline Results" | **CONFIRMED-EXECUTED** | Raw Criterion output block (lines 132-153) is internally consistent (median/lower/upper bounds, outlier counts) and matches the summary table above it exactly. Methodology note correctly explains why no `change:`/p-value line appears (no saved baseline on this run). | This document was already cleaned up in the prior pass of this audit session; no further issues found on re-read. |
| Compliance-specific benchmark templates (capability throughput, ledger drain, audit chain verify, dense-graph traversal, boot sequence, PyO3 round-trip) clearly labeled "not yet wired into the benchmark binary" | BENCHMARKS.md §"Compliance-Specific Benchmarks" | **CONFIRMED** | Each template is explicitly marked as a template/projection, not a measurement (e.g., "~140 µs... this figure is a projection from the measured per-append cost, not an independent measurement"). | Good practice — the doc clearly separates measured numbers from estimates throughout. |

---

## 11. `docs/ADVERSARIAL_TESTING.md`

| Claim | Source doc:section | Status | Evidence / how checked | Notes |
|---|---|---|---|---|
| Attack 1.2: "Generation check: `0 >= 3` = false" → DENY | ADVERSARIAL_TESTING.md:31 | **Imprecise notation, conclusion still correct** | Actual code path is `cap.generation == current_gen` (see §2/§3 findings above), not a `>=` comparison. `0 == 3` is also false, so the DENY conclusion is unaffected, but the comparison operator shown does not match the operator actually executed. | Same root-cause operator confusion as the SECURITY.md/ADR-0005 findings — likely worth a single fix-everywhere pass across all three docs once the correct mechanism is confirmed with the engineering team. |

---

## 12. Gaps absent from the documentation set entirely

| Missing fact | Status | Evidence / how checked | Notes |
|---|---|---|---|
| IPC/cross-boundary capability-revocation race condition (a caller revoking a token concurrently with another caller's in-flight `Policy::check` on the same token, across a process/IPC boundary) | **MISSING** | A grep sweep across all `.md` files in this repository for "IPC" and "race condition" in this session returned no matches discussing this scenario. `ARCHITECTURE.md` §4.2 and `TCB.md` §4 both discuss *same-process* concurrent deductions and explicitly scope the kernel to single-threaded, single-process use (`AuditLog` is `!Send`/`!Sync`), but neither document discusses what happens if a capability token is serialized and presented across an IPC/network boundary while a revocation is in flight on the issuing side — a scenario `ARCHITECTURE.md` §7 explicitly disclaims ("network transport... requires a separate trust establishment protocol") but does not analyze for revocation-race implications. | Not necessarily a code defect — it may be entirely out of scope by design, as §7 of ARCHITECTURE.md suggests. But "out of scope" is itself a claim that should be stated next to the revocation-soundness theorem in `FORMAL_VERIFICATION.md` (Theorem 2), which currently reads as if revocation soundness is unconditionally proved, with no caveat about cross-process replay of a serialized token. Recommend adding one sentence to either `SECURITY.md` §1.2 (out-of-scope list) or `TCB.md` §4 explicitly naming this gap, so it reads as a documented non-claim rather than an oversight. |

---

## SUMMARY

| Status | Count |
|---|---|
| CONFIRMED / CONFIRMED-EXECUTED | 14 |
| CONTRADICTED | 9 |
| UNVERIFIED (toolchain/sandbox limitation) | 5 |
| MISSING | 1 |

### MUST FIX BEFORE AUDIT (prioritized by real risk, not by document order)

1. **Reconcile the Lean 4 "lake build-verified, zero sorry" claim across README.md, FORMAL_VERIFICATION.md §6, FORMAL_COST_MODEL.md, and TIER_BOUNDARIES.md:139.** Right now these four documents do not agree with each other or with `docs/REFINEMENT_GAPS.md` about whether the Lean proof suite has ever been mechanically verified, and `docs/REFINEMENT_GAPS.md` contains a direct admission that it previously could not have been. Before an external audit, someone with the Lean 4 toolchain needs to actually run `lake build` in `lean/`, capture the real output, and update all four documents to say the same (true) thing. This is also explicitly item 4 on `CLAUDE.md`'s own outstanding-verification checklist — it has not been completed.

2. **Fix the generation-check operator (`==` vs `>=`) in three places:** `docs/SECURITY.md:93` (V-03), `docs/adr/0005-revocation-semantics.md:14`, and `docs/ADVERSARIAL_TESTING.md:31`. The code (`src/auth/capability.rs:69-70`) is correct and intentionally avoids `>=` for a documented security reason; all three docs describe the weaker, rejected design instead of the implemented one. Quick fix, but exactly the kind of mismatch that wastes an external auditor's time chasing a non-bug, or worse, causes them to certify a property the code doesn't actually implement that way.

3. **Repoint `docs/ARCHITECTURE.md`'s boot-sequence and missing-node-validation narrative from `Manifest::parse_and_verify` (a dead stub) to `ManifestDecoder::decode` (the real, live signature-verifying decoder).** Confirmed via direct grep that the cited function is never called by the boot path. Low exploitability (it's not reachable, so it can't be a live bypass) but high audit-friction risk: a reviewer who reads ARCHITECTURE.md and then goes looking for the validation logic in `manifest.rs` will find a stub that always fails, and may reasonably conclude the kernel's manifest validation is fake, when the real, working validation lives in a different file.

4. **Resolve the `TIER_BOUNDARIES.md` vs README.md contradiction over whether a mechanized formal cost-model proof exists.** One says "Manual analysis only... mechanized proof missing"; the other checks off the exact same Lean proof as complete. Pick one true statement and make both documents say it.

5. **Update ADR-0004 to reflect that `src/consensus/` now implements full Raft, not the single-round quorum protocol the ADR describes** — already self-disclosed in `docs/REFINEMENT_GAPS.md`, just never propagated back to the ADR itself.

### Single highest-risk item

None of the findings above are *live* security holes — the actual enforcement code (`Policy::check`, `Capability::authorises`, `Ledger::deduct`, `OperationalGraph::traverse`) was independently re-read against its documentation and, in every case checked, the **code itself is correct or more conservative than its documentation claims**, never less. The risk in this codebase right now is entirely **documentary**: an external auditor's first hours will be spent reconciling self-contradicting formal-verification claims (finding #1 above) before they can even begin assessing the kernel logic itself. That is the finding to lead with when this register is handed to OSTIF or any other reviewer — not because the kernel is unsafe, but because the paper trail around "is this formally verified or not" currently answers "it depends which document you read," and that ambiguity is exactly the kind of thing a serious audit will flag on day one regardless of what else it finds.
