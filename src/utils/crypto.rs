use libsodium_sys as sodium;

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
        sodium::randombytes_buf(
            buf.as_mut_ptr() as *mut _,
            buf.len()
        );
    }
}

#[derive(Debug)]
pub enum CryptoError {
    SessionKeysIdentical,
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

pub fn generate_session_key_pair(
    our_public_key: &[u8; CURVE25519_PUBLICKEYBYTES],
    our_secret_key: &[u8; CURVE25519_SECRETKEYBYTES],
    peer_public_key: &[u8; CURVE25519_PUBLICKEYBYTES],
) -> Result<([u8; SESSIONKEYBYTES], [u8; SESSIONKEYBYTES]), CryptoError> {
    // (rx_key, tx_key)
    let mut rx_key = [0u8; SESSIONKEYBYTES];
    let mut tx_key = [0u8; SESSIONKEYBYTES];

    match compare_keys(our_public_key.try_into().unwrap(), peer_public_key) {
        -1 => {
            let result = unsafe {
                sodium::crypto_kx_client_session_keys(
                    rx_key.as_mut_ptr(),
                    tx_key.as_mut_ptr(),
                    our_public_key.as_ptr(),
                    our_secret_key.as_ptr(),
                    peer_public_key.as_ptr(),
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
                    our_public_key.as_ptr(),
                    our_secret_key.as_ptr(),
                    peer_public_key.as_ptr(),
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
    rx_key: [u8; SESSIONKEYBYTES],
) -> Result<Vec<u8>, CryptoError> {
    let mut message = Vec::with_capacity(cipher.len() - XCHACHA20POLY1305_IETF_ABYTES);
    unsafe {
        message.set_len(message.capacity()); // avoid unnecessary initialized of buf

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
    tx_key: [u8; SESSIONKEYBYTES],
) -> Result<Vec<u8>, CryptoError> {
    let mut cipher = Vec::with_capacity(message.len() + XCHACHA20POLY1305_IETF_ABYTES);
    unsafe {
        cipher.set_len(cipher.capacity()); // avoid unnecessary initialized of buf

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

pub fn convert_identity_public_key_to_key_agreement_public_key(
    public_key: &[u8; ED25519_PUBLICKEYBYTES],
) -> Result<[u8; ED25519_PUBLICKEYBYTES], CryptoError> {
    let mut agreement_key = [0u8; CURVE25519_PUBLICKEYBYTES];
    let result = unsafe {
        sodium::crypto_sign_ed25519_pk_to_curve25519(
            agreement_key.as_mut_ptr(),
            public_key.as_ptr(),
        )
    };
    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok(agreement_key)
}

pub fn convert_identity_secret_key_to_key_agreement_secret_key(
    secret_key: &[u8; ED25519_SECRETKEYBYTES],
) -> Result<[u8; CURVE25519_SECRETKEYBYTES], CryptoError> {
    let mut agreement_key = [0u8; CURVE25519_SECRETKEYBYTES];
    let result = unsafe {
        sodium::crypto_sign_ed25519_sk_to_curve25519(
            agreement_key.as_mut_ptr(),
            secret_key.as_ptr(),
        )
    };
    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok(agreement_key)
}

pub fn sha256(input: &[u8]) -> Result<[u8; SHA256_BYTES], CryptoError> {
    let mut hash = [0u8; SHA256_BYTES];
    let result = unsafe {
        sodium::crypto_hash_sha256(hash.as_mut_ptr(), input.as_ptr(), input.len() as u64)
    };
    if result != 0 {
        return Err(CryptoError::LibsodiumError);
    }

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex::hex_to_bytes;

    #[test]
    fn test_compare_keys() {
        // Test mit realen Keys
        let key1 =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");
        let key2 =
            hex_to_bytes::<32>("622d860a23517b0e20e59d8a481db4da2c89649c979d7318bc4ef19828f4663e");
        assert_eq!(compare_keys(&key1, &key2), -1); // key1 ist kleiner als key2

        // Test für 1 (erster Key ist größer)
        let key1 =
            hex_to_bytes::<32>("f43772fd65e9fa28e729c71c199ef21c7f2b019be924e87f94f3dc27e9e63853");
        let key2 =
            hex_to_bytes::<32>("7a4b877986bd660bf3fc371d74f9049660213d2b39390ff8932307b5a0818b97");
        assert_eq!(compare_keys(&key1, &key2), 1);

        // Test für 0 (Keys sind identisch)
        let key1 =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");
        let key2 =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");
        assert_eq!(compare_keys(&key1, &key2), 0);
    }

    #[test]
    fn test_generate_session_key_pair() {
        let our_public_key =
            hex_to_bytes::<32>("0f2ad6d426694528942df15b8cb3a10140a5bfe28287c7eadfe5121a8badec53");
        let our_private_key =
            hex_to_bytes::<32>("d06ed5fe2a4d645cd4770c0b9668a2fedc596ad90cf2cffcd947d26d8287ba7c");
        let peer_public_key =
            hex_to_bytes::<32>("fa2667c8cfc5487b5e97f404bc4081d28e3958ad9dcffd2df286a2621b385220");

        // Wir sollten Client sein, da unser Public Key kleiner ist
        match generate_session_key_pair(&our_public_key, &our_private_key, &peer_public_key) {
            Ok((rx_key, tx_key)) => {
                // Prüfe, dass wir verschiedene Keys bekommen
                assert_ne!(rx_key, tx_key);
                // Prüfe, dass die Keys nicht null sind

                let expected_rx_key = hex_to_bytes::<32>(
                    "bf5f0ed0e33c08072e5267f2bb0751630ff55b7282afb6867a3cb251325bc117",
                );
                let expected_tx_key = hex_to_bytes::<32>(
                    "326132650d6239a11e0190d45ecf1c13b3051c54027ae9c8322175b23c66feac",
                );

                assert_eq!(
                    rx_key, expected_rx_key,
                    "Generierter rx stimmt nicht mit erwartetem Key überein"
                );
                assert_eq!(
                    tx_key, expected_tx_key,
                    "Generierter tx stimmt nicht mit erwartetem Key überein"
                );
            }
            Err(_) => panic!("Session Key Generierung fehlgeschlagen"),
        }
    }

    #[test]
    fn test_convert_identity_public_key_to_key_agreement_public_key() {
        // Ed25519 Public Key
        let identity_key =
            hex_to_bytes::<32>("18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");

        // Bekannter korrespondierender Curve25519 Public Key
        let expected_agreement_key =
            hex_to_bytes::<32>("0f2ad6d426694528942df15b8cb3a10140a5bfe28287c7eadfe5121a8badec53");

        let agreement_key =
            convert_identity_public_key_to_key_agreement_public_key(&identity_key).unwrap();
        assert_eq!(
            agreement_key, expected_agreement_key,
            "Konvertierter Key stimmt nicht mit erwartetem Key überein"
        );
    }

    #[test]
    fn test_convert_identity_private_key_to_key_agreement_private_key() {
        // Ed25519 Public Key
        let identity_key = hex_to_bytes::<64>("65f20fc3fdcaf569cdcf043f79047723d8856b0169bd4c475ba15ef1b37d27ae18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad9127");

        // Bekannter korrespondierender Curve25519 Public Key
        let expected_agreement_key =
            hex_to_bytes::<32>("d06ed5fe2a4d645cd4770c0b9668a2fedc596ad90cf2cffcd947d26d8287ba7c");

        let agreement_key =
            convert_identity_secret_key_to_key_agreement_secret_key(&identity_key).unwrap();
        assert_eq!(
            agreement_key, expected_agreement_key,
            "Konvertierter Key stimmt nicht mit erwartetem Key überein"
        );
    }

    #[test]
    fn test_decrypt() {
        // Bekannte Test-Werte
        let cipher = hex_to_bytes::<19>("1685d1a2238c1feda14461e1acee45809d7636");
        let auth_tag = hex_to_bytes::<97>("10000000004411282d731a283e6fb788935d82f3ef99625160d6502818622d860a23517b0e20e59d8a481db4da2c89649c979d7318bc4ef19828f4663e18cdb282be8d1293f5040cd620a91aca86a475682e4ddc397deabe300aad912783de129d");
        let nonce = hex_to_bytes("4411282d731a283e6fb788935d82f3ef99625160d6502818");
        let rx_key =
            hex_to_bytes("bf5f0ed0e33c08072e5267f2bb0751630ff55b7282afb6867a3cb251325bc117");

        // Erwartete entschlüsselte Nachricht
        let expected_decrypted = hex_to_bytes::<3>("010000");

        match decrypt(&cipher, &auth_tag, &nonce, rx_key) {
            Ok(decrypted) => {
                assert_eq!(
                    decrypted, expected_decrypted,
                    "Entschlüsselte Nachricht stimmt nicht mit erwarteter Nachricht überein"
                );
            }
            Err(_) => panic!("Entschlüsselung fehlgeschlagen"),
        }

        // Test für fehlgeschlagene Entschlüsselung (falscher Key)
        let wrong_rx_key = [0u8; SESSIONKEYBYTES];
        assert!(
            decrypt(&cipher, &auth_tag, &nonce, wrong_rx_key).is_err(),
            "Entschlüsselung hätte mit falschem Key fehlschlagen müssen"
        );
    }

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = sha256(data).unwrap();

        // Known SHA-256 hash of "Hello, World!"
        let expected =
            hex_to_bytes::<32>("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");

        assert_eq!(hash, expected, "SHA-256 hash does not match expected value");
    }
}
