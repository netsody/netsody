use crate::crypto::{AEGIS_KEYBYTES, Error};
use crate::util::{bytes_to_hex, hex_to_bytes};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Hash, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKey([u8; AEGIS_KEYBYTES]);

impl SessionKey {
    /// Get the raw bytes of the session key.
    pub fn as_bytes(&self) -> &[u8; AEGIS_KEYBYTES] {
        &self.0
    }
}

impl From<[u8; AEGIS_KEYBYTES]> for SessionKey {
    fn from(bytes: [u8; AEGIS_KEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl FromStr for SessionKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex_to_bytes(s).map(Self).map_err(Error::HexError)
    }
}

impl Display for SessionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bytes_to_hex(&self.0))
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
