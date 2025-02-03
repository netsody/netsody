use crate::utils::crypto::{
    CryptoError, ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES, generate_sign_keypair, sha256,
};
use crate::utils::hex::{bytes_to_hex, hex_to_bytes};
use log::info;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use thiserror::Error;

#[derive(Clone)]
pub struct Identity {
    pub sk: [u8; ED25519_SECRETKEYBYTES],
    pub pk: [u8; ED25519_PUBLICKEYBYTES],
    pub pow: [u8; 4],
}

impl Identity {
    pub fn new(sk: [u8; ED25519_SECRETKEYBYTES], pow: [u8; 4]) -> Self {
        Self {
            sk,
            pk: Self::derive_pk(&sk),
            pow,
        }
    }

    pub fn generate(min_pow_difficulty: u8) -> Result<Identity, IdentityError> {
        let (pk, sk) = generate_sign_keypair()?;
        let pow = generate_proof_of_work(&pk, min_pow_difficulty)?;

        Ok(Self::new(sk, pow))
    }

    pub const fn derive_pk(sk: &[u8; ED25519_SECRETKEYBYTES]) -> [u8; ED25519_PUBLICKEYBYTES] {
        let mut pk = [0u8; ED25519_PUBLICKEYBYTES];
        let mut i = 0;
        while i < ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES {
            pk[i] = sk[i + ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES];
            i += 1;
        }
        pk
    }

    pub fn save(path: &str, id: &Identity) -> io::Result<()> {
        let sk_hex = bytes_to_hex(&id.sk);
        let pow_int = i32::from_be_bytes(id.pow);

        let mut file = File::create(path)?;

        writeln!(file, "[Identity]")?;
        writeln!(file, "SecretKey = {sk_hex}")?;
        writeln!(file, "ProofOfWork = {pow_int}")?;

        Ok(())
    }

    pub fn load(path: &str) -> io::Result<Identity> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut sk: Option<[u8; ED25519_SECRETKEYBYTES]> = None;
        let mut proof_of_work: Option<[u8; 4]> = None;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            if line.starts_with("SecretKey") {
                if let Some(value) = line.split('=').nth(1) {
                    sk = Some(hex_to_bytes::<64>(value.trim()));
                }
            } else if line.starts_with("ProofOfWork") {
                if let Some(value) = line.split('=').nth(1) {
                    proof_of_work = Some(
                        value
                            .trim()
                            .to_string()
                            .parse::<i32>()
                            .unwrap()
                            .to_be_bytes(),
                    );
                }
            }
        }

        match (sk, proof_of_work) {
            (Some(sk), Some(pow)) => Ok(Identity {
                sk,
                pk: Self::derive_pk(&sk),
                pow,
            }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing required fields in identity file",
            )),
        }
    }

    pub fn load_or_generate(
        identity_file: &str,
        min_pow_difficulty: u8,
    ) -> Result<Identity, IdentityError> {
        match Identity::load(identity_file) {
            Ok(id) => {
                info!("Loaded identity from file '{}'.", identity_file);
                Ok(id)
            }
            Err(e) => {
                info!(
                    "Could not load identity from file '{}' ({}). Generate new one...",
                    identity_file, e
                );
                let id = Identity::generate(min_pow_difficulty)?;
                Identity::save(identity_file, &id)?;
                Ok(id)
            }
        }
    }
}

fn generate_proof_of_work(
    pk: &[u8; ED25519_PUBLICKEYBYTES],
    min_pow_difficulty: u8,
) -> Result<[u8; 4], IdentityError> {
    for candidate in i32::MIN..i32::MAX {
        let candidate_bytes = candidate.to_be_bytes();
        if validate_proof_of_work(pk, &candidate_bytes, min_pow_difficulty) {
            return Ok(candidate_bytes);
        }
    }
    Err(IdentityError::PowNotFound)
}

pub fn validate_proof_of_work(
    pk: &[u8; ED25519_PUBLICKEYBYTES],
    pow: &[u8; 4],
    min_pow_difficulty: u8,
) -> bool {
    // calculate proof of work difficulty
    let input = format!("{}{}", bytes_to_hex(pk), i32::from_be_bytes(*pow));
    let hash = sha256(input.as_bytes());

    // count leading zero bits
    let mut leading_zeros: u8 = 0;
    for &byte in &hash {
        if byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros() as u8;
            break;
        }
    }

    leading_zeros >= min_pow_difficulty
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Proof of Work could not be found")]
    PowNotFound,

    #[error("Identity generation failed: {0}")]
    GenerationFailed(#[from] CryptoError),

    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex::hex_to_bytes;

    #[test]
    fn test_derive_public_key() {
        let sk = hex_to_bytes::<64>(
            "3e6499116ba86b4884345891f3421a5a16c902247326928ce41c10ad8a66bd1f668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4",
        );
        let expected_pk =
            hex_to_bytes::<32>("668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4");

        assert_eq!(Identity::derive_pk(&sk), expected_pk);
    }

    #[test]
    fn test_validate_proof_of_work_valid() {
        let pk =
            hex_to_bytes::<32>("9331341e09d313baa4027a2fccea4fd471b9637f2305de714009c46b9192e006");
        let pow = (-2130520098i32).to_be_bytes();
        let difficulty = 24;

        assert!(validate_proof_of_work(&pk, &pow, difficulty));
    }

    #[test]
    fn test_validate_proof_of_work_invalid() {
        let pk =
            hex_to_bytes::<32>("38fddd8d068165f227199b521bf91c09577231f05cae822d78c04be7595fb81d");
        let pow = (-2110011455i32).to_be_bytes();
        let difficulty = 24;

        assert!(!validate_proof_of_work(&pk, &pow, difficulty));
    }
}
