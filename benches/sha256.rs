use criterion::{Criterion, black_box, criterion_group, criterion_main};
use drasyl::utils::crypto::{CryptoError, SHA256_BYTES, sha256};
use libsodium_sys as sodium;

fn sha256_libsodium(input: &[u8]) -> Result<[u8; SHA256_BYTES], CryptoError> {
    let mut hash = [0u8; SHA256_BYTES];
    let result = unsafe {
        sodium::crypto_hash_sha256(hash.as_mut_ptr(), input.as_ptr(), input.len() as u64)
    };
    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok(hash)
}

fn sha256_benchmark(c: &mut Criterion) {
    let test_data = b"b9b584d509b12bde360501be9699ed79cbd5736830854e3ab78a2064e4150f49-2147286048";

    let mut group = c.benchmark_group("SHA256");

    group.bench_function("ring", |b| b.iter(|| sha256(black_box(test_data))));

    group.bench_function("libsodium", |b| {
        b.iter(|| sha256_libsodium(black_box(test_data)).unwrap());
    });

    group.finish();
}

criterion_group!(benches, sha256_benchmark);
criterion_main!(benches);
