//! Simple agent example: a LangChain-style tool-calling agent gated by Lux
//! capability tokens, with a mid-session revocation.
//!
//! This is the smallest faithful demonstration of Lux's enforcement model:
//!
//! 1. An orchestrator (node 1) holds a root capability with `DELEGATE`.
//! 2. The agent (node 7) holds **no standing capability of its own** — every
//!    tool call is authorised by a fresh, single-use token minted on demand.
//!    This is deliberate: there is no ambient authority anywhere in this
//!    example.  A token that is not presented to `Policy::check` grants
//!    nothing, and a token that *is* presented can never be presented again
//!    (nonce replay protection consumes it on first use).
//! 3. Two tool calls succeed under generation 0.
//! 4. The operator revokes the agent's authority by rotating the
//!    generation — the kernel's coarse-grained, O(1) kill switch
//!    (see `docs/adr/0003-epoch-based-revocation.md`).
//! 5. Two more tool calls — using brand-new, never-before-seen tokens — are
//!    denied anyway, because their generation no longer matches.  This is
//!    the point: revocation is structural, not a blocklist of used tokens.
//!
//! Run with:
//! ```sh
//! cargo run --example simple-agent
//! ```

use lux_kernel::{
    audit::{AuditLog, EventKind, UNTIMED},
    auth::capability::{Capability, CapabilitySet},
    error::Error,
    types::Generation,
    Result,
};
use std::num::NonZeroU32;

use lux_kernel::auth::policy::Policy;

const RULE: &str = "------------------------------------------------------------------------";

/// Friendly label for a single-bit `CapabilitySet` right, for trace output only.
fn right_name(right: CapabilitySet) -> &'static str {
    match right {
        CapabilitySet::READ_TOPOLOGY => "READ_TOPOLOGY",
        CapabilitySet::ALLOC_RESOURCE => "ALLOC_RESOURCE",
        CapabilitySet::SCHEDULE => "SCHEDULE",
        CapabilitySet::DELEGATE => "DELEGATE",
        CapabilitySet::SHUTDOWN => "SHUTDOWN",
        _ => "UNKNOWN_RIGHT",
    }
}

/// Mint a fresh, single-use capability from `root` and run it through
/// `Policy::check`. This is the *only* path by which a tool call executes —
/// there is no branch that runs the tool without first calling `check`.
/// Prints the trace for the call and its outcome message, then returns the
/// `Policy::check` result for the caller to assert on.
#[allow(clippy::too_many_arguments)]
fn call_tool(
    tool_call: &str,
    right: CapabilitySet,
    nonce: u64,
    ok_message: &str,
    blocked_message: &str,
    root: &Capability,
    agent: NonZeroU32,
    policy: &mut Policy,
    audit: &mut AuditLog,
) -> Result<()> {
    println!("[TOOL]  {tool_call}");
    println!("        requires: {}   nonce: {nonce}", right_name(right));

    // The orchestrator delegates a single-use token scoped to exactly the
    // right this call needs. The agent never holds a reusable blanket token.
    let cap = root
        .delegate(agent, right, nonce)
        .expect("orchestrator holds DELEGATE and the requested right");

    let result = policy.check(&cap, right, audit);
    match &result {
        Ok(()) => println!("        gate(Policy::check) -> ALLOW"),
        Err(e) => println!(
            "        gate(Policy::check) -> DENY ({})",
            e.denial_reason_str()
        ),
    }
    println!(
        "        -> {}\n",
        if result.is_ok() {
            ok_message
        } else {
            blocked_message
        }
    );
    result
}

/// Mint the orchestrator's root capability and the empty policy/audit state.
/// Root capability: the orchestrator's standing authority. It alone holds
/// DELEGATE — the agent is never given it, so the agent can never mint
/// capabilities for itself or anyone else.
fn setup(orchestrator: NonZeroU32, agent: NonZeroU32) -> (Capability, Policy, AuditLog) {
    let root_cap = Capability::new_for_test(
        orchestrator,
        orchestrator,
        CapabilitySet::SCHEDULE | CapabilitySet::ALLOC_RESOURCE | CapabilitySet::DELEGATE,
        Generation(0),
        1_u64,
    );

    println!("[SETUP] Orchestrator capability minted on node {orchestrator}.");
    println!(
        "[SETUP] Agent bound to node {agent}. Rights it may be delegated this session: \
         SCHEDULE (tool invocation), ALLOC_RESOURCE (compute/network cost)."
    );
    println!(
        "[SETUP] Agent holds no standing token and no DELEGATE, READ_TOPOLOGY, or SHUTDOWN right.\n"
    );

    (root_cap, Policy::new(Generation(0)), AuditLog::new())
}

/// Roll the generation forward — the kernel's O(1) kill switch — and record
/// the operator's decision in the audit trail.
///
/// `rotate_generation` itself emits no audit event (Tier 1; see ADR-0003) —
/// the caller is responsible for recording the revocation decision itself.
fn revoke(policy: &mut Policy, audit: &mut AuditLog, orchestrator: NonZeroU32) {
    println!("{RULE}");
    println!(" OPERATOR ACTION: rotate_generation()");
    println!(" Reason: anomalous tool usage detected — kill switch engaged");
    println!("{RULE}");
    let stale_generation = policy.generation().0;
    policy.rotate_generation();
    println!(
        "[KERNEL] generation {} -> {}  (nonce window + revocation ledger cleared)",
        stale_generation,
        policy.generation().0
    );
    audit.append(
        EventKind::CapabilityRevoked,
        orchestrator.get(),
        UNTIMED,
        None,
    );
    println!();
}

/// Print the hash-chained audit trail and its JSON export.
fn print_audit_trail(audit: &AuditLog) {
    println!("{RULE}");
    println!(" AUDIT TRAIL");
    println!("{RULE}");
    println!(" chain valid:      {}", audit.verify_chain());
    println!(" events recorded:  {}", audit.len());

    let mut json = String::new();
    audit
        .export_json(&mut json)
        .expect("String is an infallible fmt::Write target");
    println!(" export_json:      {json}\n");
}

fn main() {
    println!("{RULE}");
    println!(" LUX KERNEL — SIMPLE AGENT DEMO");
    println!(" A tool-calling agent gated by Lux capability tokens.");
    println!("{RULE}\n");

    let orchestrator = NonZeroU32::new(1).expect("non-zero");
    let agent = NonZeroU32::new(7).expect("non-zero");

    let (root_cap, mut policy, mut audit) = setup(orchestrator, agent);

    println!("{RULE}");
    println!(" BEFORE REVOCATION  (generation {})", policy.generation().0);
    println!("{RULE}");

    let before_search = call_tool(
        "web_search(\"lux kernel capability security\")",
        CapabilitySet::SCHEDULE,
        101,
        "3 results returned (simulated)",
        "BLOCKED — tool did not run",
        &root_cap,
        agent,
        &mut policy,
        &mut audit,
    );
    let before_calc = call_tool(
        "calculator(\"47 * 19\")",
        CapabilitySet::ALLOC_RESOURCE,
        102,
        "result: 893 (simulated)",
        "BLOCKED — tool did not run",
        &root_cap,
        agent,
        &mut policy,
        &mut audit,
    );
    assert!(
        before_search.is_ok() && before_calc.is_ok(),
        "both calls must pass under generation 0"
    );

    revoke(&mut policy, &mut audit, orchestrator);

    println!("{RULE}");
    println!(" AFTER REVOCATION  (generation {})", policy.generation().0);
    println!("{RULE}");

    // Both nonces below are freshly minted — never presented before — which
    // proves the denial is structural (generation mismatch), not replay
    // detection of an already-used token.
    let after_search = call_tool(
        "web_search(\"are there more papers like this\")",
        CapabilitySet::SCHEDULE,
        103,
        "3 results returned (simulated)",
        "BLOCKED. No fallback path. No partial execution.",
        &root_cap,
        agent,
        &mut policy,
        &mut audit,
    );
    let after_calc = call_tool(
        "calculator(\"99 / 3\")",
        CapabilitySet::ALLOC_RESOURCE,
        104,
        "result: 33 (simulated)",
        "BLOCKED. No fallback path. No partial execution.",
        &root_cap,
        agent,
        &mut policy,
        &mut audit,
    );
    assert!(
        matches!(after_search, Err(Error::CapabilityDenied { .. }))
            && matches!(after_calc, Err(Error::CapabilityDenied { .. })),
        "both calls must be denied after revocation, even with brand-new nonces"
    );

    print_audit_trail(&audit);

    println!("{RULE}");
    println!(" RESULT");
    println!("{RULE}");
    println!(" I1 Fail-Closed:      every denial above returned Err, never Ok.");
    println!(" I2 Capability-Gated: every tool call passed through Policy::check;");
    println!("                      there is no code path that runs a tool without it.");
    println!();
    println!("Demo complete.");
}
