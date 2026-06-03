# Contributing to Lux Kernel

This document is the development contract for contributors to Lux.  It is not
advisory — the CI pipeline mechanically enforces every requirement described
here.  A PR that does not satisfy all requirements will not be merged,
regardless of its other merits.

---

## 1. The Development Contract

Lux is governance infrastructure.  The standard of correctness required is
correspondingly higher than for application software.  The following principles
govern all contributions:

### 1.1 Zero-Panic Policy

**The kernel does not panic.**

`panic!`, `unwrap()`, `expect()`, `unreachable!()`, `todo!()`, and `unimplemented!()`
are banned from `src/` in all forms.  If you find yourself reaching for one of
these, you have encountered a design deficiency that needs to be surfaced as an
explicit `Error` variant, not papered over.

The rationale: a panic is an uncontrolled failure.  An error return is a
controlled denial.  Lux only does controlled denial.

Enforcement:
- `clippy::pedantic` includes `clippy::panic` and related lints, which are
  set to `deny` in `.cargo/config.toml`.
- The CI lint pass will reject any `unwrap()` or `expect()` that is not
  inside `tests/` or `benches/`.

**Exception:** `tests/` and `benches/` may use `unwrap()` where the panic
would correctly signal a test setup error, not a kernel defect.

### 1.2 Fail-Closed Coding Standard

Every function that performs an authorisation check, resource deduction, or
topology lookup must:

1. Return `Result<T, Error>` — never `Option<T>` for a security-relevant result.
2. Map every non-success path to an explicit, named `Error` variant.
3. Never return a default or fallback value that grants access.

Reviewers will flag any function that returns `Ok` on an unrecognised input.
The correct response to an unrecognised input is always `Err(UndefinedState)`
or a more specific variant.

### 1.3 No Unsafe Code

`#![deny(unsafe_code)]` is set in `src/lib.rs`.  No exceptions are granted
for V1.0.  If you believe a use of `unsafe` is genuinely necessary, open an
RFC-style issue first; the security team will evaluate it before any
implementation begins.

### 1.4 No Silent Arithmetic

All resource-related arithmetic must use checked operations (`checked_add`,
`checked_sub`, `checked_mul`, or their saturating equivalents where
saturation is the correct semantic).  The profiles in `Cargo.toml` set
`overflow-checks = true` for both `dev` and `release`, which catches
wrapping in debug builds but not release.  Checked operations must be used
explicitly regardless of compiler settings.

---

## 2. Development Workflow

### 2.1 Branch Model

```
main        ← stable, always releasable, protected
  └── feature/<description>   ← one feature or fix per branch
  └── fix/<issue-number>-<description>
  └── audit/<audit-id>        ← audit finding resolution branches
```

Force-push to `main` is prohibited.  All merges require a passing CI gate and
at least one approved review from the security team for changes to `src/auth/`,
`src/boot/`, or `docs/SECURITY.md`.

### 2.2 Commit Messages

```
<subsystem>: <imperative summary under 72 chars>

<optional body — explain WHY, not WHAT>

Closes #<issue>
```

Examples:
```
auth: deny delegation when DELEGATE right is absent
metabolism: use checked_sub in Ledger::deduct to prevent silent underflow
```

### 2.3 Adding an Error Variant

Every new `Error` variant requires:

1. The variant added to `src/error.rs` with a `#[error("...")]` message.
2. A corresponding row in the vulnerability-to-mitigation table in
   `docs/SECURITY.md`.
3. At least one test in `tests/security/invariant_enforcement.rs` that
   exercises the new denial path.

This is enforced by the PR review checklist, not by CI.

---

## 3. Required Test Coverage

### 3.1 Security Paths — 100%

Every code path in `src/auth/`, `src/boot/`, and the security-relevant
branches of `src/metabolism/` and `src/topology/` must be exercised by a test
in `tests/security/`.  The coverage threshold is enforced by `scripts/coverage.sh`.

A PR that reduces security-path coverage below 100% will be blocked.

### 3.2 New Denial Paths

If you add a new `Err(...)` return path in any of the above subsystems, you
must add a corresponding test that:
- Constructs the exact input that triggers the error.
- Asserts the returned error variant by exact match (not `is_err()`).

### 3.3 Property Tests

For any function whose correctness is sensitive to arithmetic (quota arithmetic,
capability bitflag composition), add a `proptest` property test in
`tests/integration/`.  The property test should cover:
- Boundary values (0, 1, u64::MAX).
- Arbitrary valid inputs.
- Inputs that should always trigger denial.

---

## 4. Running the Audit and Lint Suite

All commands below are assumed to be run from the repository root.

### 4.1 Format Check

```sh
cargo fmt --all -- --check
```

Apply auto-formatting (do this before committing):
```sh
cargo fmt --all
```

### 4.2 Clippy

```sh
cargo clippy --all-targets --all-features -- \
  -D warnings \
  -D clippy::pedantic \
  -D clippy::cargo \
  -D clippy::nursery \
  -A clippy::module_name_repetitions
```

### 4.3 Supply-Chain Audit

```sh
# Advisory database check
cargo audit --deny warnings

# License, bans, and source policy
cargo deny check
```

### 4.4 Full Test Suite

```sh
cargo test --all-features --workspace
```

Security invariant tests only:
```sh
cargo test --test invariant_enforcement --test privilege_escalation -- --nocapture
```

### 4.5 Coverage Report

```sh
# Requires: cargo install cargo-llvm-cov
./scripts/coverage.sh
```

The HTML report is written to `coverage/`.  Open `coverage/index.html` in a
browser to inspect line-level coverage.

### 4.6 Full CI Gate (one command)

```sh
./scripts/ci_full.sh
```

This runs all phases in the same order as the GitHub Actions pipeline.  Run
this before opening a PR.

---

## 5. Adding a New Subsystem

If a contribution introduces a new top-level module under `src/`:

1. **Document the invariants it enforces** in the module docstring (see
   `src/auth/mod.rs` for the expected format).
2. **Update `docs/ARCHITECTURE.md`** — add the module to the subsystem map
   table and update the diagram if the trust boundary changes.
3. **Declare the `pub(crate)` boundary** — fields that are not part of the
   public API must be `pub(crate)` or private.  Callers must not be able to
   construct security-relevant types without going through the validated
   constructor.
4. **Wire into `src/lib.rs`** — add the `pub mod` declaration.
5. **Add security tests** in `tests/security/invariant_enforcement.rs`
   covering every new denial path.

---

## 6. Code Review Checklist

For reviewers of PRs touching `src/auth/`, `src/boot/`, `src/topology/`, or
`src/metabolism/`:

- [ ] No `unwrap()` / `expect()` / `panic!()` in `src/`
- [ ] No `unsafe` blocks in `src/`
- [ ] All arithmetic on resource types uses checked operations
- [ ] Every new `Err(...)` path has a corresponding test
- [ ] No new `pub` fields on security-critical types without justification
- [ ] `docs/SECURITY.md` updated if a new vulnerability class is addressed
- [ ] `docs/ARCHITECTURE.md` updated if module responsibilities change
- [ ] CI gate green (all phases)
