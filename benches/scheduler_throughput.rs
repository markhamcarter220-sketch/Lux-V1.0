//! Throughput benchmark for the work queue under sustained load.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lux_kernel::{
    scheduler::queue::WorkQueue,
    types::MAX_QUEUE,
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

criterion_group!(benches, enqueue_dequeue_cycle);
criterion_main!(benches);
