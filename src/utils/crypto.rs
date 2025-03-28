use libsodium_sys as sodium;
use log::error;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use ring::digest;
use std::cell::RefCell;
use thiserror::Error;

pub const SHA256_BYTES: usize = 32;
pub const ED25519_PUBLICKEYBYTES: usize = 32;
pub const ED25519_SECRETKEYBYTES: usize = 64;
pub const CURVE25519_PUBLICKEYBYTES: usize = 32;
pub const CURVE25519_SECRETKEYBYTES: usize = 32;
pub const XCHACHA20POLY1305_IETF_ABYTES: usize = 16;
pub const SIGN_BYTES: usize = 64;
pub const AEGIS_KEYBYTES: usize = 32;
pub const AEGIS_NBYTES: usize = 32;
pub const AEGIS_ABYTES: usize = 16;

thread_local! {
    static RNG: RefCell<ChaCha20Rng> = RefCell::new(ChaCha20Rng::from_os_rng());
}
pub fn random_bytes(buf: &mut [u8]) {
    RNG.with(|rng| {
        rng.borrow_mut().fill_bytes(buf);
    });
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Generated session keys are identical")]
    SessionKeysIdentical,

    #[error("A Libsodium cryptographic error occurred")]
    LibsodiumError,

    #[error("An AEGIS cryptographic error occurred")]
    DecryptFailed,

    #[error("An AEGIS conversion error occurred")]
    AEGISConversionError,
}

fn compare_keys(k1: &[u8; CURVE25519_PUBLICKEYBYTES], k2: &[u8; CURVE25519_PUBLICKEYBYTES]) -> i32 {
    for i in 0..CURVE25519_PUBLICKEYBYTES {
        if k1[i] != k2[i] {
            return if k1[i] < k2[i] { -1 } else { 1 };
        }
    }
    0
}

pub fn generate_sign_keypair()
-> Result<([u8; ED25519_PUBLICKEYBYTES], [u8; ED25519_SECRETKEYBYTES]), CryptoError> {
    let mut pk_key = [0u8; ED25519_PUBLICKEYBYTES];
    let mut sk_key = [0u8; ED25519_SECRETKEYBYTES];

    let result = unsafe { sodium::crypto_sign_keypair(pk_key.as_mut_ptr(), sk_key.as_mut_ptr()) };

    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok((pk_key, sk_key))
}

pub fn compute_kx_session_keys(
    my_pk: &[u8; CURVE25519_PUBLICKEYBYTES],
    my_sk: &[u8; CURVE25519_SECRETKEYBYTES],
    peer_pk: &[u8; CURVE25519_PUBLICKEYBYTES],
) -> Result<([u8; AEGIS_KEYBYTES], [u8; AEGIS_KEYBYTES]), CryptoError> {
    let mut rx_key = [0u8; AEGIS_KEYBYTES];
    let mut tx_key = [0u8; AEGIS_KEYBYTES];

    match compare_keys(my_pk, peer_pk) {
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
                return Err(CryptoError::LibsodiumError);
            }

            Ok((rx_key, tx_key))
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
                return Err(CryptoError::LibsodiumError);
            }

            Ok((rx_key, tx_key))
        }
        _ => Err(CryptoError::SessionKeysIdentical),
    }
}

pub fn convert_ed25519_pk_to_curve22519_pk(
    pk: &[u8; ED25519_PUBLICKEYBYTES],
) -> Result<[u8; ED25519_PUBLICKEYBYTES], CryptoError> {
    let mut agreement_key = [0u8; CURVE25519_PUBLICKEYBYTES];
    let result = unsafe {
        sodium::crypto_sign_ed25519_pk_to_curve25519(agreement_key.as_mut_ptr(), pk.as_ptr())
    };
    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok(agreement_key)
}

pub fn convert_ed25519_sk_to_curve25519_sk(
    sk: &[u8; ED25519_SECRETKEYBYTES],
) -> Result<[u8; CURVE25519_SECRETKEYBYTES], CryptoError> {
    let mut agreement_key = [0u8; CURVE25519_SECRETKEYBYTES];
    let result = unsafe {
        sodium::crypto_sign_ed25519_sk_to_curve25519(agreement_key.as_mut_ptr(), sk.as_ptr())
    };
    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok(agreement_key)
}

pub fn sha256(input: &[u8]) -> [u8; SHA256_BYTES] {
    let digest = digest::digest(&digest::SHA256, input);

    // `digest.as_ref()` returns a slice reference to the hash data
    let hash_slice = digest.as_ref();

    // Convert the slice to an array [u8; 32]
    let mut hash = [0u8; SHA256_BYTES];
    hash.copy_from_slice(hash_slice);

    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex::hex_to_bytes;

    #[test]
    fn test_compare_keys() {
        // Test with real keys
        let key1 =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");
        let key2 =
            hex_to_bytes::<32>("622d860a23517b0e20e59d8a481db4da2c89649c979d7318bc4ef19828f4663e");
        assert_eq!(compare_keys(&key1, &key2), -1); // key1 is smaller than key2

        // Test for 1 (first key is larger)
        let key1 =
            hex_to_bytes::<32>("f43772fd65e9fa28e729c71c199ef21c7f2b019be924e87f94f3dc27e9e63853");
        let key2 =
            hex_to_bytes::<32>("7a4b877986bd660bf3fc371d74f9049660213d2b39390ff8932307b5a0818b97");
        assert_eq!(compare_keys(&key1, &key2), 1);

        // Test for 0 (keys are identical)
        let key1 =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");
        let key2 =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");
        assert_eq!(compare_keys(&key1, &key2), 0);
    }

    #[test]
    fn test_generate_long_time_key_pair() {
        match generate_sign_keypair() {
            Ok((pk, sk)) => {
                assert_eq!(pk.len(), ED25519_PUBLICKEYBYTES);
                assert_eq!(sk.len(), ED25519_SECRETKEYBYTES);

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
    fn test_generate_session_key_pair() {
        let my_pk =
            hex_to_bytes::<32>("0f2ad6d426694528942df15b8cb3a10140a5bfe28287c7eadfe5121a8badec53");
        let my_sk =
            hex_to_bytes::<32>("d06ed5fe2a4d645cd4770c0b9668a2fedc596ad90cf2cffcd947d26d8287ba7c");
        let peer_pk =
            hex_to_bytes::<32>("fa2667c8cfc5487b5e97f404bc4081d28e3958ad9dcffd2df286a2621b385220");

        // We should be client since our public key is smaller
        match compute_kx_session_keys(&my_pk, &my_sk, &peer_pk) {
            Ok((rx_key, tx_key)) => {
                // Check that we get different keys
                assert_ne!(rx_key, tx_key);
                // Check that the keys are not null

                let expected_rx_key = hex_to_bytes::<32>(
                    "bf5f0ed0e33c08072e5267f2bb0751630ff55b7282afb6867a3cb251325bc117",
                );
                let expected_tx_key = hex_to_bytes::<32>(
                    "326132650d6239a11e0190d45ecf1c13b3051c54027ae9c8322175b23c66feac",
                );

                assert_eq!(
                    rx_key, expected_rx_key,
                    "Generated rx key does not match expected key"
                );
                assert_eq!(
                    tx_key, expected_tx_key,
                    "Generated tx key does not match expected key"
                );
            }
            Err(_) => panic!("Session Key Generation failed"),
        }
    }

    #[test]
    fn test_convert_identity_pk_to_key_agreement_public_key() {
        // Ed25519 Public Key
        let identity_key =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");

        // Known corresponding Curve25519 Public Key
        let expected_agreement_key =
            hex_to_bytes::<32>("0f2ad6d426694528942df15b8cb3a10140a5bfe28287c7eadfe5121a8badec53");

        let agreement_key = convert_ed25519_pk_to_curve22519_pk(&identity_key).unwrap();
        assert_eq!(
            agreement_key, expected_agreement_key,
            "Converted key does not match expected key"
        );
    }

    #[test]
    fn test_convert_identity_private_key_to_key_agreement_private_key() {
        // Ed25519 Public Key
        let identity_key = hex_to_bytes::<64>(
            "65f20fc3fdcaf569cdcf043f79047723d8856b0169bd4c475ba15ef1b37d27ae18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127",
        );

        // Known corresponding Curve25519 Public Key
        let expected_agreement_key =
            hex_to_bytes::<32>("d06ed5fe2a4d645cd4770c0b9668a2fedc596ad90cf2cffcd947d26d8287ba7c");

        let agreement_key = convert_ed25519_sk_to_curve25519_sk(&identity_key).unwrap();
        assert_eq!(
            agreement_key, expected_agreement_key,
            "Converted key does not match expected key"
        );
    }

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = sha256(data);

        // Known SHA-256 hash of "Hello, World!"
        let expected =
            hex_to_bytes::<32>("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");

        assert_eq!(hash, expected, "SHA-256 hash does not match expected value");
    }
}
