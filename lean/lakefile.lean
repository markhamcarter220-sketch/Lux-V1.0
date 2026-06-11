import Lake
open Lake DSL

-- Lux Kernel — formal verification package.
--
-- Three modules, in dependency order:
--
--   LuxSpec          — abstract ideal-system specification (no imports)
--   LuxCostModel     — concrete Lean model of src/metabolism/ledger.rs
--   LuxRefinement    — refinement proofs (imports both above)
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

-- Abstract ideal-system specification (pure math, no implementation details).
lean_lib «LuxSpec»

-- Concrete Lean model of the resource ledger (mirrors src/metabolism/ledger.rs).
lean_lib «LuxCostModel»

-- Refinement proofs: LuxSpec ← LuxRefinement → LuxCostModel.
lean_lib «LuxRefinement»

-- Bitfield ↔ Finset Right bridge: closes representational gap to Rust u32.
lean_lib «LuxCapabilityBridge»
