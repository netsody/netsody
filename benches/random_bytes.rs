use criterion::{Criterion, black_box, criterion_group, criterion_main};
use drasyl::messages::PUBLIC_HEADER_NONCE_LEN;
use drasyl::utils::crypto::random_bytes;
use drasyl::utils::rand::pseudorandom_bytes;

fn random_bytes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_bytes");

    // Pre-allocate single buffer outside the benchmark loops
    let mut buf = vec![0u8; PUBLIC_HEADER_NONCE_LEN];

    group.bench_function("random_bytes", |b| {
        b.iter(|| {
            random_bytes(&mut buf);
            black_box(&buf);
        });
    });

    group.bench_function("pseudorandom_bytes", |b| {
        b.iter(|| {
            pseudorandom_bytes(&mut buf);
            black_box(&buf);
        });
    });

    group.finish();
}

criterion_group!(benches, random_bytes_benchmark);
criterion_main!(benches);
