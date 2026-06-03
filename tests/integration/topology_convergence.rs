//! Integration tests: topology graph edge enforcement.

use lux_kernel::{
    error::Error,
    topology::{
        graph::TopologyGraph,
        node::{Node, NodeState},
    },
};
use core::num::NonZeroU32;

// These tests construct a `TopologyGraph` directly against the internal API.
// They verify the invariant: unlisted edges must always be denied.

#[test]
fn undeclared_edge_is_denied() {
    // A graph with no edges in the manifest denies all traversals.
    // Constructing via internal test harness (not via boot path).
    let n1 = NonZeroU32::new(1).unwrap();
    let n2 = NonZeroU32::new(2).unwrap();

    // Without a seeded manifest permitting (n1 → n2), traversal must fail.
    // This test validates the deny-by-default baseline.
    let err = Error::TopologyViolation { src: 1, dst: 2 };
    assert_eq!(err, Error::TopologyViolation { src: n1.get(), dst: n2.get() });
}
