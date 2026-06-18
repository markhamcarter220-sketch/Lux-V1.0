/-!
# Lux Kernel — Function Spec Layer (aggregator)

Imports every module in `lean/FunctionSpecs/`, giving full-coverage of
`src/`'s production functions with Lean 4 signatures + precondition /
postcondition pairs.

**This tree contains no proofs.**  It is deliberately lighter-weight than:
- `lean/Refinement.lean` — states real I1–I4 obligations, with named `sorry`s.
- `lean/LuxRefinement.lean` / `lean/LuxCapabilityBridge.lean` — contain real,
  machine-checked (modulo `lake build` availability) theorems.

Every declaration below this point is an unverified transcription of the
Rust source in `src/` — see `docs/FUNCTION_SPECS.md` for the full
methodology, per-module function counts, and the complete REFINEMENT_GAP
table. None of `lean/FunctionSpecs/` has been run through `lake build`; the
Lean 4 toolchain is not installed in this environment (same disclosed
limitation as the rest of `lean/`, see `docs/REFINEMENT_GAPS.md`).
-/

import FunctionSpecs.Core
import FunctionSpecs.Audit
import FunctionSpecs.Auth
import FunctionSpecs.Metabolism
import FunctionSpecs.Topology
import FunctionSpecs.Boot
import FunctionSpecs.PythonBindings
import FunctionSpecs.Consensus
import FunctionSpecs.Hsm
import FunctionSpecs.SchedulerWasmTpm
