mod error;
mod session_key;

pub use error::*;
use libsodium_sys as sodium;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
pub use session_key::SessionKey;
use std::cell::RefCell;

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
pub(crate) type SigningSecKey = [u8; ED25519_SECRETKEYBYTES];
pub(crate) type SigningPubKey = [u8; ED25519_PUBLICKEYBYTES];
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

pub(crate) fn generate_sign_keypair() -> Result<(SigningPubKey, SigningSecKey), Error> {
    let mut pk_key = [0u8; ED25519_PUBLICKEYBYTES];
    let mut sk_key = [0u8; ED25519_SECRETKEYBYTES];

    let result = unsafe { sodium::crypto_sign_keypair(pk_key.as_mut_ptr(), sk_key.as_mut_ptr()) };

    if result != 0 {
        return Err(Error::LibsodiumError);
    }

    Ok((pk_key, sk_key))
}

pub fn compute_kx_session_keys(
    my_pk: &AgreementPubKey,
    my_sk: &AgreementSecKey,
    peer_pk: &AgreementPubKey,
) -> Result<(SessionKey, SessionKey), Error> {
    let mut rx_key = [0u8; AEGIS_KEYBYTES];
    let mut tx_key = [0u8; AEGIS_KEYBYTES];

    match match my_pk.cmp(peer_pk) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => 0,
    } {
        -1 => {
            let result = unsafe {
                sodium::crypto_kx_client_session_keys(
                    rx_key.as_mut_ptr(),
                    tx_key.as_mut_ptr(),
                    my_pk.as_ptr(),
                    my_sk.as_ptr(),
                    peer_pk.as_ptr(),
                )
            };
            if result != 0 {
                return Err(Error::LibsodiumError);
            }

            Ok((rx_key.into(), tx_key.into()))
        }
        1 => {
            let result = unsafe {
                sodium::crypto_kx_server_session_keys(
                    rx_key.as_mut_ptr(),
                    tx_key.as_mut_ptr(),
                    my_pk.as_ptr(),
                    my_sk.as_ptr(),
                    peer_pk.as_ptr(),
                )
            };
            if result != 0 {
                return Err(Error::LibsodiumError);
            }

            Ok((rx_key.into(), tx_key.into()))
        }
        _ => Err(Error::SessionKeysIdentical),
    }
}

pub fn convert_ed25519_pk_to_curve25519_pk(pk: &SigningPubKey) -> Result<AgreementPubKey, Error> {
    let mut agreement_key = [0u8; CURVE25519_PUBLICKEYBYTES];
    let result = unsafe {
        sodium::crypto_sign_ed25519_pk_to_curve25519(agreement_key.as_mut_ptr(), pk.as_ptr())
    };
    if result != 0 {
        return Err(Error::LibsodiumError);
    }

    Ok(agreement_key)
}

pub fn convert_ed25519_sk_to_curve25519_sk(sk: &SigningSecKey) -> Result<AgreementSecKey, Error> {
    let mut agreement_key = [0u8; CURVE25519_SECRETKEYBYTES];
    let result = unsafe {
        sodium::crypto_sign_ed25519_sk_to_curve25519(agreement_key.as_mut_ptr(), sk.as_ptr())
    };
    if result != 0 {
        return Err(Error::LibsodiumError);
    }

    Ok(agreement_key)
}

pub fn sha256(input: &[u8]) -> Result<[u8; SHA256_BYTES], Error> {
    let mut hash = [0u8; SHA256_BYTES];
    let result = unsafe {
        sodium::crypto_hash_sha256(hash.as_mut_ptr(), input.as_ptr(), input.len() as u64)
    };
    if result != 0 {
        return Err(Error::LibsodiumError);
    }

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
