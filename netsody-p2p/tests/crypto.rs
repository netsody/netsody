use netsody_p2p::crypto as new;
use netsody_p2p::crypto::{Error, SessionKey, SigningPubKey, SigningSecKey};
use libsodium_sys as sodium;
use std::sync::Once;

fn sodium_init_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe { assert!(sodium::sodium_init() >= 0) });
}

// ---------------------------------------------------------------------------
// Old (libsodium) references
// ---------------------------------------------------------------------------
mod old_ref {
    use super::*;

    pub(crate) const ED25519_SECRETKEYBYTES: usize = 64;
    pub(crate) const ED25519_PUBLICKEYBYTES: usize = 32;
    pub(crate) const CURVE25519_SECRETKEYBYTES: usize = 32;
    pub(crate) const CURVE25519_PUBLICKEYBYTES: usize = 32;

    pub(crate) type SigningSecKey = [u8; ED25519_SECRETKEYBYTES];
    pub(crate) type SigningPubKey = [u8; ED25519_PUBLICKEYBYTES];
    pub(crate) type AgreementSecKey = [u8; CURVE25519_SECRETKEYBYTES];
    pub(crate) type AgreementPubKey = [u8; CURVE25519_PUBLICKEYBYTES];

    pub(crate) const AEGIS_KEYBYTES: usize = 32;

    pub fn generate_sign_keypair() -> Result<(SigningPubKey, SigningSecKey), Error> {
        let mut pk_key = [0u8; ED25519_PUBLICKEYBYTES];
        let mut sk_key = [0u8; ED25519_SECRETKEYBYTES];

        let result =
            unsafe { sodium::crypto_sign_keypair(pk_key.as_mut_ptr(), sk_key.as_mut_ptr()) };

        if result != 0 {
            return Err(Error::DalekError);
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
                    return Err(Error::DalekError);
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
                    return Err(Error::DalekError);
                }

                Ok((rx_key.into(), tx_key.into()))
            }
            _ => Err(Error::SessionKeysIdentical),
        }
    }

    pub fn convert_ed25519_pk_to_curve25519_pk(
        pk: &SigningPubKey,
    ) -> Result<AgreementPubKey, Error> {
        let mut agreement_key = [0u8; CURVE25519_PUBLICKEYBYTES];
        let result = unsafe {
            sodium::crypto_sign_ed25519_pk_to_curve25519(agreement_key.as_mut_ptr(), pk.as_ptr())
        };
        if result != 0 {
            return Err(Error::DalekError);
        }

        Ok(agreement_key)
    }

    pub fn convert_ed25519_sk_to_curve25519_sk(
        sk: &SigningSecKey,
    ) -> Result<AgreementSecKey, Error> {
        let mut agreement_key = [0u8; CURVE25519_SECRETKEYBYTES];
        let result = unsafe {
            sodium::crypto_sign_ed25519_sk_to_curve25519(agreement_key.as_mut_ptr(), sk.as_ptr())
        };
        if result != 0 {
            return Err(Error::DalekError);
        }

        Ok(agreement_key)
    }
}

// ---------------------------------------------------------------------------
// Tests: new implementation must match the old one exactly
// ---------------------------------------------------------------------------

#[test]
fn ed25519_pk_conversion_matches_old_ref_many() {
    sodium_init_once();
    for _ in 0..64 {
        let (ed_pk, _ed_sk): (SigningPubKey, SigningSecKey) =
            old_ref::generate_sign_keypair().unwrap();
        let ours = new::convert_ed25519_pk_to_curve25519_pk(&ed_pk).unwrap();
        let theirs = old_ref::convert_ed25519_pk_to_curve25519_pk(&ed_pk).unwrap();
        assert_eq!(ours, theirs, "pk_to_curve25519 mismatch");
    }
}

#[test]
fn ed25519_sk_conversion_matches_old_ref_many() {
    sodium_init_once();
    for _ in 0..64 {
        let (_ed_pk, ed_sk): (SigningPubKey, SigningSecKey) =
            old_ref::generate_sign_keypair().unwrap();
        let ours = new::convert_ed25519_sk_to_curve25519_sk(&ed_sk).unwrap();
        let theirs = old_ref::convert_ed25519_sk_to_curve25519_sk(&ed_sk).unwrap();
        assert_eq!(ours, theirs, "sk_to_curve25519 mismatch");
    }
}

#[test]
fn kx_session_keys_match_old_ref_both_roles_many() {
    sodium_init_once();

    for _ in 0..32 {
        // Generate X25519 keypairs using the old reference (libsodium) so that both worlds see identical inputs
        let (my_pk_0, my_sk_0): (SigningPubKey, SigningSecKey) =
            old_ref::generate_sign_keypair().unwrap();
        let (peer_pk_0, peer_sk_0): (SigningPubKey, SigningSecKey) =
            old_ref::generate_sign_keypair().unwrap();
        let mut my_pk = old_ref::convert_ed25519_pk_to_curve25519_pk(&my_pk_0).unwrap();
        let mut my_sk = old_ref::convert_ed25519_sk_to_curve25519_sk(&my_sk_0).unwrap();
        let mut peer_pk = old_ref::convert_ed25519_pk_to_curve25519_pk(&peer_pk_0).unwrap();
        let mut peer_sk = old_ref::convert_ed25519_sk_to_curve25519_sk(&peer_sk_0).unwrap();
        let rc1 = unsafe { sodium::crypto_kx_keypair(my_pk.as_mut_ptr(), my_sk.as_mut_ptr()) };
        let rc2 = unsafe { sodium::crypto_kx_keypair(peer_pk.as_mut_ptr(), peer_sk.as_mut_ptr()) };
        assert_eq!(rc1, 0);
        assert_eq!(rc2, 0);

        // old reference (from the perspective of "my_*")
        let (rx_old, tx_old) = old_ref::compute_kx_session_keys(&my_pk, &my_sk, &peer_pk).unwrap();
        // new implementation (from the perspective of "my_*")
        let (rx_new, tx_new): (SessionKey, SessionKey) =
            new::compute_kx_session_keys(&my_pk, &my_sk, &peer_pk).unwrap();

        assert_eq!(
            rx_new.as_bytes(),
            rx_old.as_bytes(),
            "rx mismatch (my view)"
        );
        assert_eq!(
            tx_new.as_bytes(),
            tx_old.as_bytes(),
            "tx mismatch (my view)"
        );

        // peer perspective
        let (rx_old_p, tx_old_p) =
            old_ref::compute_kx_session_keys(&peer_pk, &peer_sk, &my_pk).unwrap();
        let (rx_new_p, tx_new_p): (SessionKey, SessionKey) =
            new::compute_kx_session_keys(&peer_pk, &peer_sk, &my_pk).unwrap();
        assert_eq!(
            rx_new_p.as_bytes(),
            rx_old_p.as_bytes(),
            "rx mismatch (peer view)"
        );
        assert_eq!(
            tx_new_p.as_bytes(),
            tx_old_p.as_bytes(),
            "tx mismatch (peer view)"
        );
    }
}
