//! Throughput benchmark for the work queue under sustained load.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lux_kernel::scheduler::queue::{WorkItem, WorkQueue};
use core::num::NonZeroU32;

fn enqueue_dequeue_cycle(c: &mut Criterion) {
    let node = NonZeroU32::new(1).unwrap();
    c.bench_function("queue_enqueue_dequeue_1024", |b| {
        b.iter(|| {
            let mut q = WorkQueue::with_capacity(1024);
            for i in 0u8..=255 {
                let _ = q.enqueue(WorkItem { priority: i, target: node, payload: black_box(i as u64) });
            }
            while q.dequeue().is_some() {}
        });
    });
}

criterion_group!(benches, enqueue_dequeue_cycle);
criterion_main!(benches);
