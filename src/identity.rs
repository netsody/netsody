use crate::utils::crypto;
use crate::utils::hex::hex_to_bytes;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

pub const fn derive_public_key(secret_key: &[u8; crypto::ED25519_SECRETKEYBYTES]) -> [u8; crypto::ED25519_PUBLICKEYBYTES] {
    let mut public_key = [0u8; crypto::ED25519_PUBLICKEYBYTES];
    let mut i = 0;
    while i < crypto::ED25519_SECRETKEYBYTES - crypto::ED25519_PUBLICKEYBYTES {
        public_key[i] = secret_key[i + crypto::ED25519_SECRETKEYBYTES - crypto::ED25519_PUBLICKEYBYTES];
        i += 1;
    }
    public_key
}

pub fn load_identity(path: &str) -> io::Result<([u8; crypto::ED25519_SECRETKEYBYTES], [u8; 4])> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut secret_key: Option<[u8; crypto::ED25519_SECRETKEYBYTES]> = None;
    let mut proof_of_work: Option<[u8; 4]> = None;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.starts_with("SecretKey") {
            if let Some(value) = line.split('=').nth(1) {
                secret_key = Some(hex_to_bytes::<64>(value.trim()));
            }
        } else if line.starts_with("ProofOfWork") {
            if let Some(value) = line.split('=').nth(1) {
                proof_of_work = Some(value.trim().to_string().parse::<i32>().unwrap().to_be_bytes());
            }
        }
    }

    match (secret_key, proof_of_work) {
        (Some(sk), Some(pow)) => Ok((sk, pow)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing required fields in identity file",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex::hex_to_bytes;

    #[test]
    fn test_derive_public_key() {
        let secret_key = hex_to_bytes::<64>("3e6499116ba86b4884345891f3421a5a16c902247326928ce41c10ad8a66bd1f668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4");
        let expected_public_key =
            hex_to_bytes::<32>("668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4");

        assert_eq!(derive_public_key(&secret_key), expected_public_key);
    }
}
