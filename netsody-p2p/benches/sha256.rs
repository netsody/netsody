use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libsodium_sys as sodium;
use netsody_p2p::crypto::{Error, sha256};

fn sha256_libsodium(input: &[u8]) -> Result<[u8; 32], Error> {
    let mut hash = [0u8; 32];
    let result = unsafe {
        sodium::crypto_hash_sha256(hash.as_mut_ptr(), input.as_ptr(), input.len() as u64)
    };
    if result != 0 {
        return Err(Error::DalekError);
    }

    Ok(hash)
}

fn sha256_benchmark(c: &mut Criterion) {
    let test_data = b"b9b584d509b12bde360501be9699ed79cbd5736830854e3ab78a2064e4150f49-2147286048";

    let mut group = c.benchmark_group("SHA256");

    group.bench_function("libsodium", |b| {
        b.iter(|| sha256_libsodium(black_box(test_data)).unwrap());
    });

    group.bench_function("dalek/sha2", |b| {
        b.iter(|| sha256(black_box(test_data)).unwrap());
    });

    group.finish();
}

criterion_group!(benches, sha256_benchmark);
criterion_main!(benches);
