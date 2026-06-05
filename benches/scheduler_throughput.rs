//! Throughput benchmark for the work queue under sustained load.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lux_kernel::{
    audit::AuditLog,
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    metabolism::ledger::Ledger,
    scheduler::queue::WorkQueue,
    topology::graph::{BootingGraph, OperationalGraph},
    types::{Generation, Quota, MAX_QUEUE},
};
use core::num::NonZeroU32;

fn enqueue_dequeue_cycle(c: &mut Criterion) {
    let node = NonZeroU32::new(1).unwrap();
    c.bench_function("queue_enqueue_dequeue_256", |b| {
        b.iter(|| {
            let mut q = WorkQueue::<MAX_QUEUE>::new();
            for i in 0u8..=255 {
                let _ = q.enqueue(lux_kernel::scheduler::queue::WorkItem {
                    priority: i,
                    target:   node,
                    payload:  black_box(u64::from(i)),
                });
            }
            while q.dequeue().is_some() {}
        });
    });
}

fn policy_check_throughput(c: &mut Criterion) {
    let gen  = Generation(0);
    let node = NonZeroU32::new(1).unwrap();
    let right = CapabilitySet::SCHEDULE;

    c.bench_function("policy_check", |b| {
        b.iter(|| {
            let mut policy = Policy::new(gen);
            let cap = Capability::new_for_test(node, node, CapabilitySet::SCHEDULE, gen, 1);
            let mut audit = AuditLog::new();
            let _ = policy.check(black_box(&cap), black_box(right), &mut audit);
        });
    });
}

fn ledger_deduct_throughput(c: &mut Criterion) {
    let node = NonZeroU32::new(1).unwrap();

    c.bench_function("ledger_deduct", |b| {
        b.iter(|| {
            let mut ledger = Ledger::new();
            ledger.seed(node, Quota::new(1_000_000));
            let _ = ledger.deduct(black_box(node), black_box(1));
        });
    });
}

fn topology_traverse_throughput(c: &mut Criterion) {
    let src  = NonZeroU32::new(1).unwrap();
    let dst  = NonZeroU32::new(2).unwrap();
    let mut bg = BootingGraph::new();
    bg.activate(src).unwrap();
    bg.activate(dst).unwrap();
    bg.permit_edge(src, dst).unwrap();
    let graph: OperationalGraph = bg.seal();

    c.bench_function("topology_traverse", |b| {
        b.iter(|| {
            let mut audit = AuditLog::new();
            let _ = graph.traverse(black_box(src), black_box(dst), &mut audit);
        });
    });
}

fn audit_append_throughput(c: &mut Criterion) {
    use lux_kernel::audit::event::EventKind;
    let node = NonZeroU32::new(1).unwrap();

    c.bench_function("audit_append", |b| {
        b.iter(|| {
            let mut log = AuditLog::new();
            let _ = log.append(
                black_box(EventKind::CapabilityCheck),
                black_box(node.get()),
                black_box(1_000_000u64),
                black_box(None),
            );
        });
    });
}

criterion_group!(benches, enqueue_dequeue_cycle, policy_check_throughput, ledger_deduct_throughput, topology_traverse_throughput, audit_append_throughput);
criterion_main!(benches);
