import Lake
open Lake DSL

-- Lux Kernel — formal verification package.
--
-- Seven modules, in dependency order:
--
--   LuxSpec              — abstract ideal-system specification (no imports)
--   LuxCostModel         — concrete Lean model of src/metabolism/ledger.rs
--   LuxRefinement        — refinement proofs (imports both above)
--   LuxCapabilityBridge  — u32 bitfield ↔ Finset Right isomorphism
--   Refinement           — I1–I4 invariant obligation stubs (sorries documented)
--   FunctionSpecs        — full-coverage spec layer for all of src/ (no proofs
--                           attempted; signature + pre/post only — see
--                           docs/FUNCTION_SPECS.md)
--   IpcReservation        — RESERVE-phase model for the not-yet-implemented
--                           Capability-Signed Message IPC protocol; covers
--                           Claims Discipline items 1-5 from
--                           docs/ipc/IPC-SPEC.md (no imports; independent of
--                           the six modules above)
--
-- To verify all proofs:
--   cd lean
--   lake build
--
-- Requires: Lean 4.x + Lake
--   https://leanprover.github.io/lean4/doc/quickstart.html
--
-- Expected output on success:
--   Build completed successfully.
--
-- These proofs are a mandatory CI gate when the Lean 4 toolchain is installed.
-- See scripts/ci_full.sh (Phase 6).

package «lux-cost-model»

-- Mathlib provides `Finset`/`Fintype`, used by `LuxSpec.Rights` and everything
-- downstream of it.  Pinned to v4.14.0 to match this toolchain's Lean version.
require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.14.0"

-- Abstract ideal-system specification (pure math, no implementation details).
lean_lib «LuxSpec»

-- Concrete Lean model of the resource ledger (mirrors src/metabolism/ledger.rs).
lean_lib «LuxCostModel»

-- Refinement proofs: LuxSpec ← LuxRefinement → LuxCostModel.
lean_lib «LuxRefinement»

-- Bitfield ↔ Finset Right bridge: closes representational gap to Rust u32.
lean_lib «LuxCapabilityBridge»

-- I1–I4 invariant refinement obligations (scaffolded with named sorry placeholders).
-- See docs/REFINEMENT_GAPS.md for plain-language descriptions and closure estimates.
lean_lib «Refinement»

-- Full-coverage function spec layer for all of src/ (signature + pre/post
-- only, no proofs attempted). See docs/FUNCTION_SPECS.md.
lean_lib «FunctionSpecs»

-- RESERVE-phase model for the Capability-Signed Message IPC protocol
-- (docs/ipc/IPC-SPEC.md, Claims Discipline items 1-5). Protocol is
-- specification-only — no Rust implementation is wired into Policy::check
-- yet. No imports; independent of the six modules above.
lean_lib «IpcReservation»
