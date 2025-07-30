//! Identity management for the drasyl protocol.
//!
//! This module provides functionality for creating, managing, and persisting
//! cryptographic identities used in the drasyl peer-to-peer network.
//!
//! # Overview
//!
//! An identity in drasyl consists of:
//! * A secret key for signing messages and deriving the public key
//! * A public key for node identification and message verification  
//! * A proof of work to prevent Sybil attacks
//!
//! # Example
//!
//! ```rust
//! use drasyl::identity::Identity;
//! use drasyl::node::MIN_POW_DIFFICULTY_DEFAULT;
//!
//! // Load an existing identity or generate a new one
//! let identity = Identity::load_or_generate("drasyl.identity", MIN_POW_DIFFICULTY_DEFAULT).expect("Failed to load identity");
//!
//! // Access the public key for node identification
//! let public_key = identity.pk;
//!
//! // Save the identity to a file
//! Identity::save("backup.identity", &identity).expect("Failed to save identity");
//! ```

mod error;
mod pow;
mod pub_key;
mod sec_key;

pub use error::*;
pub use pow::*;
pub use pub_key::*;
pub use sec_key::*;

// Standard library imports
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::str::FromStr;

// External crate imports
use tracing::{debug, info};
use zerocopy::IntoBytes;
// Crate-internal imports
use crate::crypto::generate_sign_keypair;

const MIN_DERIVED_PORT: u16 = 22528;

/// Represents a complete node identity in the drasyl network.
///
/// An identity consists of:
/// * A secret key (`sk`) for signing messages and deriving the public key
/// * A public key (`pk`) for node identification and message verification
/// * A proof of work (`pow`) to prevent spam and ensure network health
///
/// # Features
///
/// * Secure key generation and management
/// * Persistent storage to/from files
/// * Automatic generation of new identities
/// * Proof of work validation
///
/// # Example
///
/// ```rust
/// use drasyl::identity::Identity;
/// use drasyl::node::MIN_POW_DIFFICULTY_DEFAULT;
///
/// // Load an existing identity or generate a new one
/// let identity = Identity::load_or_generate("drasyl.identity", MIN_POW_DIFFICULTY_DEFAULT).expect("Failed to load identity");
///
/// // Access the public key for node identification
/// let public_key = identity.pk;
///
/// // Save the identity to a file
/// Identity::save("backup.identity", &identity).expect("Failed to save identity");
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Identity {
    /// The secret key used for signing messages and deriving the public key.
    pub sk: SecKey,
    /// The public key used for node identification and message verification.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub pk: PubKey,
    /// The proof of work value that meets the minimum difficulty requirement.
    pub pow: Pow,
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct IdentityHelper {
            sk: SecKey,
            pow: Pow,
        }

        let helper = IdentityHelper::deserialize(deserializer)?;
        Ok(Identity::new(helper.sk, helper.pow))
    }
}

impl Identity {
    /// Create a new identity from a secret key and proof of work.
    ///
    /// The public key is automatically derived from the secret key.
    ///
    /// # Arguments
    /// * `sk` - The secret key for this identity
    /// * `pow` - The proof of work value
    ///
    /// # Returns
    /// A new Identity instance
    pub fn new(sk: SecKey, pow: Pow) -> Self {
        Self {
            sk,
            pk: sk.extract_pk(),
            pow,
        }
    }

    /// Generate a new identity with the specified minimum proof of work difficulty.
    ///
    /// This function creates a new cryptographic key pair and generates a proof of work
    /// that meets the minimum difficulty requirement. The process can be computationally
    /// intensive depending on the difficulty level.
    ///
    /// # Arguments
    /// * `min_pow_difficulty` - Minimum number of leading zero bits required in the proof of work
    ///
    /// # Returns
    /// A new Identity instance or an error if generation fails
    ///
    /// # Errors
    /// * [`Error::GenerationFailed`] - If key generation fails
    /// * [`Error::PowNotFound`] - If no valid proof of work could be found
    pub fn generate(min_pow_difficulty: u8) -> Result<Identity, Error> {
        let (pk, sk) = generate_sign_keypair()?;
        let pow = Pow::generate(&pk.into(), min_pow_difficulty)?;

        Ok(Self::new(sk.into(), pow))
    }

    /// Save an identity to a file.
    ///
    /// The identity is saved in a simple text format with the secret key and
    /// proof of work values. The public key is not saved as it can be derived
    /// from the secret key.
    ///
    /// # Arguments
    /// * `path` - The file path to save the identity to
    /// * `id` - The identity to save
    ///
    /// # Returns
    /// `Ok(())` on success, or an I/O error if the file cannot be written
    ///
    /// # File Format
    /// ```text
    /// [Identity]
    /// SecretKey = <hex_encoded_secret_key>
    /// ProofOfWork = <signed_32bit_integer>
    /// ```
    pub fn save(path: &str, id: &Identity) -> io::Result<()> {
        let pow_int = i32::from_be_bytes(id.pow.as_bytes().try_into().unwrap());

        let mut file = File::create(path)?;

        // Set restrictive file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            std::fs::set_permissions(path, perms)?;
        }

        writeln!(file, "[Identity]")?;
        writeln!(file, "SecretKey = {}", id.sk)?;
        writeln!(file, "ProofOfWork = {pow_int}")?;

        Ok(())
    }

    /// Load an identity from a file.
    ///
    /// This function reads an identity file and reconstructs the Identity instance.
    /// The public key is automatically derived from the loaded secret key.
    ///
    /// # Arguments
    /// * `path` - The file path to load the identity from
    ///
    /// # Returns
    /// The loaded Identity instance or an I/O error if the file cannot be read
    /// or contains invalid data
    ///
    /// # Errors
    /// * I/O errors if the file cannot be opened or read
    /// * [`io::ErrorKind::InvalidData`] if the file format is invalid or missing required fields
    pub fn load(path: &str) -> io::Result<Identity> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut sk: Option<SecKey> = None;
        let mut proof_of_work: Option<Pow> = None;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            if line.starts_with("SecretKey") {
                if let Some(value) = line.split('=').nth(1) {
                    sk = Some(SecKey::from_str(value.trim()).unwrap());
                }
            } else if line.starts_with("ProofOfWork") {
                if let Some(value) = line.split('=').nth(1) {
                    proof_of_work = Some(value.trim().to_string().parse::<i32>().unwrap().into());
                }
            }
        }

        match (sk, proof_of_work) {
            (Some(sk), Some(pow)) => Ok(Identity {
                sk,
                pk: sk.extract_pk(),
                pow,
            }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing required fields in identity file",
            )),
        }
    }

    /// Load an identity from a file, or generate a new one if the file doesn't exist.
    ///
    /// This is a convenience function that attempts to load an existing identity
    /// from the specified file. If the file doesn't exist or cannot be read,
    /// a new identity is generated and saved to the file.
    ///
    /// # Arguments
    /// * `identity_file` - The file path to load/save the identity
    /// * `min_pow_difficulty` - Minimum proof of work difficulty for new identities
    ///
    /// # Returns
    /// An Identity instance (either loaded or newly generated)
    ///
    /// # Errors
    /// * [`Error::GenerationFailed`] - If key generation fails
    /// * [`Error::PowNotFound`] - If no valid proof of work could be found
    /// * [`Error::IoError`] - If the identity file cannot be saved
    pub fn load_or_generate(
        identity_file: &str,
        min_pow_difficulty: u8,
    ) -> Result<Identity, Error> {
        match Identity::load(identity_file) {
            Ok(id) => {
                debug!("Loaded identity from file '{identity_file}'.");
                Ok(id)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!("Identity file '{identity_file}' not found. Generate new one...");
                let id = Identity::generate(min_pow_difficulty)?;
                Identity::save(identity_file, &id)?;
                Ok(id)
            }
            Err(e) => Err(e.into()),
        }
    }
}
