//! Message encryption and decryption utilities.
//!
//! This module provides functions for encrypting (arming) and decrypting (disarming)
//! message bodies using AEGIS authenticated encryption.

// External crate imports
use aegis::aegis256x2::Aegis256X2;

// Crate-internal imports
use crate::crypto::{AEGIS_ABYTES, AEGIS_NBYTES, AuthTag, Nonce, random_bytes};
// Crate-internal imports
use crate::crypto::SessionKey;
use crate::message::error::Error;

// Constants
/// Total size of the encryption header (nonce + authentication tag) in bytes.
pub const ARM_HEADER_LEN: usize = AEGIS_NBYTES + AEGIS_ABYTES;

/// Encrypt (arm) a message body using AEGIS authenticated encryption.
///
/// This function encrypts the message content in-place, adding a nonce
/// and authentication tag to the beginning of the buffer.
///
/// # Arguments
/// * `buf` - Buffer containing the message to encrypt (modified in-place)
/// * `ad` - Additional authenticated data (not encrypted but authenticated)
/// * `tx_key` - Session key for encryption
///
/// # Returns
/// `Ok(())` on success, or an error if encryption fails
pub(crate) fn arm_message_body(
    buf: &mut [u8],
    ad: &[u8],
    tx_key: &SessionKey,
) -> Result<(), Error> {
    let min_len = ARM_HEADER_LEN;
    if buf.len() < min_len {
        return Err(Error::ArmFailedTooShort(buf.len(), min_len));
    }

    // split buf
    let (nonce, remainder) = buf.split_at_mut(AEGIS_NBYTES);
    let (tag_slice, mc) = remainder.split_at_mut(AEGIS_ABYTES);
    let nonce: &mut Nonce = nonce.try_into().unwrap();
    let tag_slice: &mut AuthTag = tag_slice.try_into().unwrap();

    // nonce
    random_bytes(nonce);

    let state = Aegis256X2::<AEGIS_ABYTES>::new(nonce, tx_key.as_bytes());
    let tag = state.encrypt_in_place(mc, ad);
    tag_slice.copy_from_slice(&tag);

    Ok(())
}

/// Decrypt (disarm) a message body using AEGIS authenticated encryption.
///
/// This function decrypts the message content in-place, verifying the
/// authentication tag and removing the encryption header.
///
/// # Arguments
/// * `buf` - Buffer containing the encrypted message (modified in-place)
/// * `ad` - Additional authenticated data (must match what was used during encryption)
/// * `rx_key` - Session key for decryption
///
/// # Returns
/// `Ok(())` on success, or an error if decryption or authentication fails
pub(crate) fn disarm_message_body(
    buf: &mut [u8],
    ad: &[u8],
    rx_key: &SessionKey,
) -> Result<(), Error> {
    let min_len = ARM_HEADER_LEN;
    if buf.len() < min_len {
        return Err(Error::DisarmFailedTooShort(buf.len(), min_len));
    }

    // split buf
    let (nonce, remainder) = buf.split_at_mut(AEGIS_NBYTES);
    let (tag_slice, mc) = remainder.split_at_mut(AEGIS_ABYTES);
    let nonce: &mut Nonce = nonce.try_into().unwrap();
    let tag: &mut AuthTag = tag_slice.try_into().unwrap();

    let state = Aegis256X2::<AEGIS_ABYTES>::new(nonce, rx_key.as_bytes());
    state
        .decrypt_in_place(mc, tag, ad)
        .map_err(|e| Error::DecryptFailed(e.to_string()))?;

    Ok(())
}
