//! Property tests — Invariant 4: Topology-Bounded.
//!
//! ∀ undeclared edge: traverse returns Err.
//! ∀ declared edge between active nodes: traverse returns Ok.
//! Sealing the graph makes activate unreachable at the type level (structural).

use lux_kernel::topology::graph::BootingGraph;
use core::num::NonZeroU32;
use proptest::prelude::*;

fn node(n: u32) -> NonZeroU32 {
    // Keep within MAX_NODES (64); map to 1..=64.
    NonZeroU32::new((n % 63) + 1).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..Default::default() })]

    /// Any edge not declared in the manifest must be denied after sealing.
    #[test]
    fn undeclared_edge_always_denied(
        src1 in 1u32..=63u32,
        dst1 in 1u32..=63u32,
        src2 in 1u32..=63u32,
        dst2 in 1u32..=63u32,
    ) {
        let n_s1 = node(src1);
        let n_d1 = node(dst1);
        let n_s2 = node(src2);
        let n_d2 = node(dst2);

        // Only declare edge (src1 → dst1).
        let mut booting = BootingGraph::new();
        booting.activate(n_s1).unwrap();
        booting.activate(n_d1).unwrap();
        booting.permit_edge(n_s1, n_d1).unwrap();
        let graph = booting.seal();

        // The reverse edge (dst1 → src1) must be denied unless src1==dst1.
        if n_s1 != n_d1 {
            prop_assert!(
                graph.traverse(n_d1, n_s1).is_err(),
                "undeclared reverse edge must be denied"
            );
        }

        // Edge (src2 → dst2) must be denied if it was not declared.
        if n_s2 != n_s1 || n_d2 != n_d1 {
            prop_assert!(
                graph.traverse(n_s2, n_d2).is_err(),
                "undeclared edge ({src2} → {dst2}) must be denied"
            );
        }
    }

    /// A declared edge between two active nodes must always be permitted.
    #[test]
    fn declared_active_edge_always_permitted(
        src in 1u32..=63u32,
        dst in 1u32..=63u32,
    ) {
        if src == dst { return Ok(()); } // skip self-loops for simplicity

        let ns = node(src);
        let nd = node(dst);

        let mut booting = BootingGraph::new();
        booting.activate(ns).unwrap();
        booting.activate(nd).unwrap();
        booting.permit_edge(ns, nd).unwrap();
        let graph = booting.seal();

        prop_assert!(
            graph.traverse(ns, nd).is_ok(),
            "declared active edge must be permitted"
        );
    }

    /// An edge to an unactivated node must be denied at declaration time (fail-closed).
    ///
    /// The pre-activation guard in `permit_edge` enforces this earlier than
    /// `traverse` — ghost edges are refused before they can be stored.
    #[test]
    fn inactive_node_blocks_edge_declaration(
        src in 1u32..=63u32,
        dst in 1u32..=30u32, // dst in different range to avoid collision
    ) {
        let ns = node(src);
        let nd = node(dst + 30); // offset to avoid overlap with src range

        // Skip if the modular mapping produces the same node for both.
        if ns == nd { return Ok(()); }

        let mut booting = BootingGraph::new();
        // Activate src but NOT dst — permit_edge must be denied at declaration time.
        booting.activate(ns).unwrap();
        prop_assert!(
            booting.permit_edge(ns, nd).is_err(),
            "permit_edge to inactive dst must be denied at declaration time"
        );

        // After seal, traversal is also denied (edge was never stored).
        let graph = booting.seal();
        prop_assert!(
            graph.traverse(ns, nd).is_err(),
            "inactive dst node must block traversal after seal"
        );
    }
}
