use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn benchmark_time_measurements(c: &mut Criterion) {
    let mut group = c.benchmark_group("clock");

    group.bench_function("SystemTime::now unix_epoch millis", |b| {
        b.iter(|| {
            black_box(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            )
        });
    });

    group.bench_function("Instant::now elapsed micros", |b| {
        let start = Instant::now();
        b.iter(|| black_box(start.elapsed().as_micros() as u64));
    });

    let cached_time = AtomicU64::new(42);
    group.bench_function("AtomicU64 load", |b| {
        b.iter(|| black_box(cached_time.load(SeqCst)));
    });

    group.finish();
}

criterion_group!(benches, benchmark_time_measurements);
criterion_main!(benches);
