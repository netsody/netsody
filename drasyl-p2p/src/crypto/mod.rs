mod error;
mod session_key;

pub use error::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
pub use session_key::SessionKey;
use std::cell::RefCell;

use blake2b_simd::Params;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

pub(crate) const SHA256_BYTES: usize = 32;
pub(crate) const ED25519_SECRETKEYBYTES: usize = 64;
pub(crate) const ED25519_PUBLICKEYBYTES: usize = 32;
pub(crate) const CURVE25519_SECRETKEYBYTES: usize = 32;
pub(crate) const CURVE25519_PUBLICKEYBYTES: usize = 32;
pub(crate) const AEGIS_KEYBYTES: usize = 32;
pub(crate) const AEGIS_NBYTES: usize = 32;
pub(crate) const AEGIS_ABYTES: usize = 16;

pub(crate) type Nonce = [u8; AEGIS_NBYTES];
pub(crate) type AuthTag = [u8; AEGIS_ABYTES];
pub type SigningSecKey = [u8; ED25519_SECRETKEYBYTES];
pub type SigningPubKey = [u8; ED25519_PUBLICKEYBYTES];
pub type AgreementSecKey = [u8; CURVE25519_SECRETKEYBYTES];
pub type AgreementPubKey = [u8; CURVE25519_PUBLICKEYBYTES];

thread_local! {
    static RNG: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_os_rng());
}
pub fn random_bytes(buf: &mut [u8]) {
    RNG.with(|rng| {
        rng.borrow_mut().fill_bytes(buf);
    });
}

pub fn generate_sign_keypair() -> Result<(SigningPubKey, SigningSecKey), Error> {
    let seed: [u8; 32] = RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        s
    });

    let signing = SigningKey::from_bytes(&seed);
    let verifying: VerifyingKey = signing.verifying_key();
    let pk_bytes: [u8; 32] = verifying.to_bytes();

    // Backwards compatibility with libsodium: seed || pk
    let mut sk_bytes = [0u8; 64];
    sk_bytes[..32].copy_from_slice(&seed);
    sk_bytes[32..].copy_from_slice(&pk_bytes);

    Ok((pk_bytes, sk_bytes))
}

// ========= libsodium compatible key exchange: rx||tx = BLAKE2b-512(p.n || client_pk || server_pk) =========
pub fn compute_kx_session_keys(
    my_pk: &AgreementPubKey,
    my_sk: &AgreementSecKey,
    peer_pk: &AgreementPubKey,
) -> Result<(SessionKey, SessionKey), Error> {
    use core::cmp::Ordering;

    if my_pk == peer_pk {
        return Err(Error::SessionKeysIdentical);
    }

    let (client_pk, server_pk, i_am_client) = match my_pk.cmp(peer_pk) {
        Ordering::Less => (*my_pk, *peer_pk, true),
        Ordering::Greater => (*peer_pk, *my_pk, false),
        Ordering::Equal => unreachable!(),
    };

    // X25519: Shared Secret
    let my_secret = X25519StaticSecret::from(*my_sk); // clamped
    let their_public = X25519PublicKey::from(*peer_pk);
    let shared = my_secret.diffie_hellman(&their_public);

    // optional: "contributory" check
    if !shared.was_contributory() {
        return Err(Error::DalekError);
    }

    // BLAKE2b-512 like libsodium (p.n || client_pk || server_pk)
    let hash = Params::new()
        .hash_length(64)
        .to_state()
        .update(shared.as_bytes())
        .update(&client_pk)
        .update(&server_pk)
        .finalize();
    let digest = hash.as_bytes();

    let mut rx = [0u8; AEGIS_KEYBYTES];
    let mut tx = [0u8; AEGIS_KEYBYTES];
    rx.copy_from_slice(&digest[..32]);
    tx.copy_from_slice(&digest[32..64]);

    // libsodium format: returned keys are relative to the "my_*" keys
    let (rx_key, tx_key) = if i_am_client {
        (rx, tx)
    } else {
        // server uses the keys in the reverse order
        (tx, rx)
    };

    Ok((rx_key.into(), tx_key.into()))
}

pub fn convert_ed25519_pk_to_curve25519_pk(pk: &SigningPubKey) -> Result<AgreementPubKey, Error> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| Error::DalekError)?;
    let mont = vk.to_montgomery(); // Montgomery coordinate (X25519 Public)

    Ok(mont.to_bytes())
}

pub fn convert_ed25519_sk_to_curve25519_sk(sk: &SigningSecKey) -> Result<AgreementSecKey, Error> {
    // see also: https://github.com/jedisct1/libsodium/blob/85ddc5c2c6c7b8f7c99f9af6039e18f1f2ca0daa/src/libsodium/crypto_sign/ed25519/ref10/keypair.c#L71
    let seed: [u8; CURVE25519_SECRETKEYBYTES] = sk[..CURVE25519_SECRETKEYBYTES]
        .try_into()
        .map_err(|_| Error::DalekError)?;

    // 1) SHA-512(seed)
    let mut h: [u8; 64] = Sha512::digest(&seed).into();

    // 2) X25519 clamping
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    // 3) return first 32 Bytes
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);

    h.zeroize();

    Ok(out)
}

pub fn sha256(input: &[u8]) -> Result<[u8; SHA256_BYTES], Error> {
    let mut hash = [0u8; SHA256_BYTES];
    let mut hasher = Sha256::new();
    hasher.update(input);

    let out = hasher.finalize();
    hash.copy_from_slice(&out);

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::hex_to_bytes;

    #[test]
    fn test_generate_long_time_key_pair() {
        match generate_sign_keypair() {
            Ok((pk, sk)) => {
                // Check that the keys don't consist only of zeros
                assert!(
                    pk.iter().any(|&b| b != 0),
                    "Public key consists only of zeros!"
                );
                assert!(
                    sk.iter().any(|&b| b != 0),
                    "Secret key consists only of zeros!"
                );

                match convert_ed25519_pk_to_curve25519_pk(&pk) {
                    Ok(converted_pk) => {
                        assert!(
                            converted_pk.iter().any(|&b| b != 0),
                            "Converted public key consists only of zeros!"
                        )
                    }
                    Err(_) => panic!("Converted public key generation error"),
                }

                match convert_ed25519_sk_to_curve25519_sk(&sk) {
                    Ok(converted_sk) => {
                        assert!(
                            converted_sk.iter().any(|&b| b != 0),
                            "Converted secret key consists only of zeros!"
                        )
                    }
                    Err(_) => panic!("Converted secret key generation error"),
                }
            }
            Err(_) => panic!("Long Time Key Generation Error"),
        }
    }

    #[test]
    fn test_sha256() {
        let input = b"Hello, World!";
        let hash = sha256(input).unwrap();
        assert_eq!(
            hash,
            hex_to_bytes::<32>("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
                .unwrap()
        );
    }
}
