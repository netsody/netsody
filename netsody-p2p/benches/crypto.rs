// benches/curve25519.rs
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libsodium_sys as sodium;
use netsody_p2p::crypto::{
    AgreementPubKey, AgreementSecKey, SessionKey, SigningPubKey, SigningSecKey,
    compute_kx_session_keys, convert_ed25519_pk_to_curve25519_pk,
    convert_ed25519_sk_to_curve25519_sk, generate_sign_keypair,
};

fn sodium_init_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        let _ = sodium::sodium_init();
    });
}

// --- Helpers: neue Impl ausschließlich über crypto/mod.rs -------------------
fn gen_x25519_pair_new() -> (AgreementPubKey, AgreementSecKey) {
    let (ed_pk, ed_sk): (SigningPubKey, SigningSecKey) = generate_sign_keypair().unwrap();
    let pk = convert_ed25519_pk_to_curve25519_pk(&ed_pk).unwrap();
    let sk = convert_ed25519_sk_to_curve25519_sk(&ed_sk).unwrap();
    (pk, sk)
}

// --- Benchmarks ------------------------------------------------------------

fn bench_kx_session_keys(c: &mut Criterion) {
    sodium_init_once();

    // Feste Test-Schlüssel (einmal erzeugen, in beiden Varianten verwenden)
    let (my_pk, my_sk) = gen_x25519_pair_new();
    let (peer_pk, _peer_sk) = gen_x25519_pair_new();

    let mut group = c.benchmark_group("KX-session-keys");

    // libsodium: crypto_kx_{client,server}_session_keys
    group.bench_function("libsodium/kx", |b| {
        let mut rx = [0u8; 32];
        let mut tx = [0u8; 32];
        b.iter(|| {
            let rc = if my_pk < peer_pk {
                unsafe {
                    sodium::crypto_kx_client_session_keys(
                        rx.as_mut_ptr(),
                        tx.as_mut_ptr(),
                        black_box(my_pk.as_ptr()),
                        black_box(my_sk.as_ptr()),
                        black_box(peer_pk.as_ptr()),
                    )
                }
            } else {
                unsafe {
                    sodium::crypto_kx_server_session_keys(
                        rx.as_mut_ptr(),
                        tx.as_mut_ptr(),
                        black_box(my_pk.as_ptr()),
                        black_box(my_sk.as_ptr()),
                        black_box(peer_pk.as_ptr()),
                    )
                }
            };
            assert_eq!(rc, 0);
            black_box((&rx, &tx));
        });
    });

    // neue Impl: compute_kx_session_keys aus crypto/mod.rs
    group.bench_function("new-impl/kx", |b| {
        b.iter(|| {
            let (rx, tx): (SessionKey, SessionKey) =
                compute_kx_session_keys(black_box(&my_pk), black_box(&my_sk), black_box(&peer_pk))
                    .unwrap();
            black_box((rx, tx));
        });
    });

    group.finish();
}

fn bench_ed25519_to_x25519(c: &mut Criterion) {
    sodium_init_once();

    // fixes Ed25519-Paar (einmal)
    let (ed_pk, ed_sk): (SigningPubKey, SigningSecKey) = generate_sign_keypair().unwrap();

    let mut group = c.benchmark_group("Ed25519->X25519");

    // Public-Key-Konvertierung
    group.bench_function("libsodium/pk_to_curve25519", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            let rc = unsafe {
                sodium::crypto_sign_ed25519_pk_to_curve25519(
                    out.as_mut_ptr(),
                    black_box(ed_pk.as_ptr()),
                )
            };
            assert_eq!(rc, 0);
            black_box(out);
        });
    });

    group.bench_function("new-impl/pk_to_curve25519", |b| {
        b.iter(|| {
            let out = convert_ed25519_pk_to_curve25519_pk(black_box(&ed_pk)).unwrap();
            black_box(out);
        });
    });

    // Secret-Key-Konvertierung
    group.bench_function("libsodium/sk_to_curve25519", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            let rc = unsafe {
                sodium::crypto_sign_ed25519_sk_to_curve25519(
                    out.as_mut_ptr(),
                    black_box(ed_sk.as_ptr()),
                )
            };
            assert_eq!(rc, 0);
            black_box(out);
        });
    });

    group.bench_function("new-impl/sk_to_curve25519", |b| {
        b.iter(|| {
            let out = convert_ed25519_sk_to_curve25519_sk(black_box(&ed_sk)).unwrap();
            black_box(out);
        });
    });

    group.finish();
}

fn curve_benches(c: &mut Criterion) {
    bench_kx_session_keys(c);
    bench_ed25519_to_x25519(c);
}

criterion_group!(benches, curve_benches);
criterion_main!(benches);
