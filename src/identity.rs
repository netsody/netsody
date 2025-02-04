use crate::utils::crypto;
use crate::utils::crypto::{generate_long_time_key_pair, CryptoError};
use crate::utils::hex::hex_to_bytes;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

pub const fn derive_public_key(secret_key: &[u8; crypto::ED25519_SECRETKEYBYTES]) -> [u8; crypto::ED25519_PUBLICKEYBYTES] {
    let mut public_key = [0u8; crypto::ED25519_PUBLICKEYBYTES];
    let mut i = 0;
    while i < crypto::ED25519_SECRETKEYBYTES - crypto::ED25519_PUBLICKEYBYTES {
        public_key[i] = secret_key[i + crypto::ED25519_SECRETKEYBYTES - crypto::ED25519_PUBLICKEYBYTES];
        i += 1;
    }
    public_key
}

pub fn generate_identity() -> Result<([u8; crypto::ED25519_SECRETKEYBYTES], [u8; 4]), IdentityError> {
    let (pk, sk) = generate_long_time_key_pair().map_err(|e| IdentityError::GenerationFailed(e))?;
    let pow = generate_proof_of_work(&pk)?;

    Ok((sk, pow))
}

pub fn save_identity(path: &str, secret_key: &[u8; crypto::ED25519_SECRETKEYBYTES], pow: &[u8; 4]) -> io::Result<()> {
    let secret_key_hex: String = secret_key.iter().map(|b| format!("{:02x}", b)).collect();
    let pow_int = i32::from_le_bytes(*pow);

    let mut file = File::create(path)?;

    writeln!(file, "[Identity]")?;
    writeln!(file, "SecretKey = {}", secret_key_hex)?;
    writeln!(file, "ProofOfWork = {}", pow_int)?;

    Ok(())
}

pub fn generate_proof_of_work(
    public_key: &[u8; crypto::ED25519_PUBLICKEYBYTES],
) -> Result<[u8; 4], IdentityError> {
    for candidate in i32::MIN..i32::MAX {
        let candidate_bytes = candidate.to_le_bytes();
        if validate_proof_of_work(public_key, &candidate_bytes) {
            return Ok(candidate_bytes);
        }
    }
    Err(IdentityError::PowNotFound)
}

pub fn validate_proof_of_work(public_key: &[u8; crypto::ED25519_PUBLICKEYBYTES], pow: &[u8; 4]) -> bool {
    // calculate proof of work difficulty
    let public_key_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
    let input = format!("{}{}", public_key_hex, i32::from_be_bytes(*pow));
    let hash = crypto::sha256(input.as_bytes());

    // count leading zero bits
    let mut leading_zeros: u8 = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros() as u8;
            break;
        }
    }

    let is_valid = leading_zeros >= *crate::MIN_POW_DIFFICULTY;

    is_valid
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

#[derive(Debug)]
pub enum IdentityError {
    PowNotFound,
    GenerationFailed(CryptoError),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::PowNotFound => write!(f, "Proof of Work could not be found"),
            IdentityError::GenerationFailed(e) => write!(f, "Identity generation failed: {}", e),
        }
    }
}

impl std::error::Error for IdentityError {}

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
