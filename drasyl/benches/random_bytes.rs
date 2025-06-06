use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libsodium_sys as sodium;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::{ChaCha12Rng, ChaCha20Rng};

fn random_bytes_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_bytes");

    // Pre-allocate single buffer outside the benchmark loops
    let mut buf = vec![0u8; 32];

    group.bench_function("random_bytes (sodium)", |b| {
        b.iter(|| {
            unsafe {
                sodium::randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len());
            }
            black_box(&buf);
        });
    });

    let mut rng = ChaCha12Rng::from_os_rng();
    group.bench_function("random_bytes (ChaCha12Rng)", |b| {
        b.iter(|| {
            rng.fill_bytes(&mut buf);
            black_box(&buf);
        });
    });

    let mut rng = ChaCha20Rng::from_os_rng();
    group.bench_function("random_bytes (ChaCha20Rng)", |b| {
        b.iter(|| {
            rng.fill_bytes(&mut buf);
            black_box(&buf);
        });
    });

    group.bench_function("random_bytes (ChaCha20Rng sycall)", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::from_os_rng();
            rng.fill_bytes(&mut buf);
            black_box(&buf);
        });
    });

    // group.bench_function("pseudorandom_bytes", |b| {
    //     b.iter(|| {
    //         pseudorandom_bytes(&mut buf);
    //         black_box(&buf);
    //     });
    // });

    group.finish();
}

criterion_group!(benches, random_bytes_benchmark);
criterion_main!(benches);
