use libsodium_sys as sodium;
use ring::digest;
use thiserror::Error;

pub const SHA256_BYTES: usize = 32;
pub const ED25519_PUBLICKEYBYTES: usize = 32;
pub const ED25519_SECRETKEYBYTES: usize = 64;
pub const CURVE25519_PUBLICKEYBYTES: usize = 32;
pub const CURVE25519_SECRETKEYBYTES: usize = 32;
pub const SESSIONKEYBYTES: usize = 32;
pub const XCHACHA20POLY1305_IETF_ABYTES: usize = 16;
pub const XCHACHA20POLY1305_IETF_NPUBBYTES: usize = 24;
pub const SIGN_BYTES: usize = 64;

pub fn random_bytes(buf: &mut [u8]) {
    unsafe {
        sodium::randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len());
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Generated session keys are identical")]
    SessionKeysIdentical,

    #[error("A Libsodium cryptographic error occurred")]
    LibsodiumError,
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
) -> Result<([u8; SESSIONKEYBYTES], [u8; SESSIONKEYBYTES]), CryptoError> {
    // (rx_key, tx_key)
    let mut rx_key = [0u8; SESSIONKEYBYTES];
    let mut tx_key = [0u8; SESSIONKEYBYTES];

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

pub fn decrypt(
    cipher: &[u8],
    auth_tag: &[u8],
    nonce: &[u8; XCHACHA20POLY1305_IETF_NPUBBYTES],
    rx_key: &[u8; SESSIONKEYBYTES],
) -> Result<Vec<u8>, CryptoError> {
    let mut message = vec![0u8; cipher.len() - XCHACHA20POLY1305_IETF_ABYTES];
    unsafe {
        let mut message_len: u64 = 0;

        let result = sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
            message.as_mut_ptr(),
            &mut message_len,
            std::ptr::null_mut(),
            cipher.as_ptr(),
            cipher.len() as u64,
            auth_tag.as_ptr(),
            auth_tag.len() as u64,
            nonce.as_ptr(),
            rx_key.as_ptr(),
        );
        if result != 0 {
            return Err(CryptoError::LibsodiumError);
        }
    }

    Ok(message)
}

pub fn encrypt(
    message: &[u8],
    auth_tag: &[u8],
    nonce: &[u8; XCHACHA20POLY1305_IETF_NPUBBYTES],
    tx_key: &[u8; SESSIONKEYBYTES],
) -> Result<Vec<u8>, CryptoError> {
    let mut cipher = vec![0u8; message.len() + XCHACHA20POLY1305_IETF_ABYTES];
    unsafe {
        let mut cipher_len: u64 = 0;

        let result = sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher.as_mut_ptr(),
            &mut cipher_len,
            message.as_ptr(),
            message.len() as u64,
            auth_tag.as_ptr(),
            auth_tag.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            tx_key.as_ptr(),
        );
        if result != 0 {
            return Err(CryptoError::LibsodiumError);
        }
    }

    Ok(cipher)
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
    fn test_decrypt() {
        // Known test values
        let cipher = hex_to_bytes::<19>("1685d1a2238c1feda14461e1acee45809d7636");
        let auth_tag = hex_to_bytes::<97>(
            "10000000004411282d731a283e6fb788935d82f3ef99625160d6502818622d860a23517b0e20e59d8a481db4da2c89649c979d7318bc4ef19828f4663e18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad912783de129d",
        );
        let nonce = hex_to_bytes("4411282d731a283e6fb788935d82f3ef99625160d6502818");
        let rx_key =
            hex_to_bytes("bf5f0ed0e33c08072e5267f2bb0751630ff55b7282afb6867a3cb251325bc117");

        // Expected decrypted message
        let expected_decrypted = hex_to_bytes::<3>("010000");

        match decrypt(&cipher, &auth_tag, &nonce, &rx_key) {
            Ok(decrypted) => {
                assert_eq!(
                    decrypted, expected_decrypted,
                    "Decrypted message does not match expected message"
                );
            }
            Err(_) => panic!("Decryption failed"),
        }

        // Test for failed decryption (wrong key)
        let wrong_rx_key = [0u8; SESSIONKEYBYTES];
        assert!(
            decrypt(&cipher, &auth_tag, &nonce, &wrong_rx_key).is_err(),
            "Decryption should have failed with wrong key"
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
