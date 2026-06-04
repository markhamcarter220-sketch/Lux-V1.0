/// Adversarial assault on all four Lux Kernel security invariants.
///
/// 63 distinct exploit attempts across 6 attack categories.
/// Every test is a denial — zero successful privilege escalations.

#[path = "adversarial/inv1_fail_closed.rs"]
mod inv1_fail_closed;

#[path = "adversarial/inv2_capability_gated.rs"]
mod inv2_capability_gated;

#[path = "adversarial/inv3_accountable_resources.rs"]
mod inv3_accountable_resources;

#[path = "adversarial/inv4_topology_bounded.rs"]
mod inv4_topology_bounded;

#[path = "adversarial/stress_chaos.rs"]
mod stress_chaos;

#[path = "adversarial/byzantine.rs"]
mod byzantine;
