//! Network endpoint representations for the drasyl protocol.
//!
//! This module provides types for representing network endpoints (IP addresses and ports)
//! in a protocol-agnostic way, supporting both IPv4 and IPv6 addresses.

// Standard library imports
use std::collections::HashSet;
use std::fmt::{self, Formatter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

// External crate imports
use zerocopy::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// Crate-internal imports
use crate::message::error::Error;
use crate::message::{HELLO_ENDPOINT_LEN, HELLO_MAX_ENDPOINTS};
use crate::util::{IPV4_LENGTH, IPV6_LENGTH};

/// Network endpoint address that can represent both IPv4 and IPv6 addresses.
///
/// IPv4 addresses are stored as IPv6-mapped IPv4 addresses (::ffff:0:0/96)
/// to provide a unified representation.
#[repr(transparent)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EndpointAddr(pub [u8; IPV6_LENGTH]);

impl EndpointAddr {
    /// Get the raw bytes of the endpoint address.
    pub(crate) fn as_bytes(&self) -> &[u8; IPV6_LENGTH] {
        &self.0
    }

    /// Convert the endpoint address to raw bytes.
    pub(crate) fn to_bytes(self) -> [u8; IPV6_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for EndpointAddr {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|e| Error::EndpointAddrConversionFailed(e.to_string()))
    }
}

impl From<IpAddr> for EndpointAddr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V6(ipv6) => Self(ipv6.octets()),
            IpAddr::V4(ipv4) => {
                let mut bytes = [0u8; IPV6_LENGTH];
                // convert to ipv6 mapped ipv4 (::ffff:0:0/96)
                bytes[..10].fill(0); // set first 10 bytes to 0
                bytes[10] = 0xff;
                bytes[11] = 0xff;
                // copy IPv4 address into the last 4 bytes
                bytes[IPV6_LENGTH - IPV4_LENGTH..IPV6_LENGTH].copy_from_slice(&ipv4.octets());
                Self(bytes)
            }
        }
    }
}

impl From<EndpointAddr> for IpAddr {
    fn from(addr: EndpointAddr) -> Self {
        let buf = addr.to_bytes();
        if buf[..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && buf[10..12] == [0xff, 0xff] {
            // Extract IPv4 bytes and convert to IPv4 address
            IpAddr::V4(std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]))
        } else {
            // Convert slice to array and create IPv6 address
            IpAddr::V6(Ipv6Addr::from(buf))
        }
    }
}

impl fmt::Display for EndpointAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip: IpAddr = (*self).into();
        write!(f, "{ip}")
    }
}

/// Network endpoint combining an IP address and port number.
///
/// This represents a complete network endpoint that can be used to
/// establish connections between peers.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// Port number in big-endian format
    pub(crate) port: U16,
    /// IP address (IPv4 or IPv6)
    pub(crate) addr: EndpointAddr,
}

impl Endpoint {
    /// Parse an endpoint from a byte buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the endpoint data
    ///
    /// # Returns
    /// Reference to the parsed endpoint or an error
    pub(crate) fn parse(buf: &[u8]) -> Result<&Self, Error> {
        let endpoint =
            Self::ref_from_bytes(buf).map_err(|e| Error::EndpointInvalid(e.to_string()))?;

        if endpoint.port == 0 {
            return Err(Error::EndpointPortInvalid);
        }

        Ok(endpoint)
    }

    /// Write the endpoint to a byte buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer to write the endpoint to
    pub fn to_bytes(&self, buf: &mut [u8]) {
        // port
        buf[0..][..2].copy_from_slice(self.port.as_bytes());

        // address
        buf[2..][..IPV6_LENGTH].copy_from_slice(self.addr.as_bytes());
    }
}

impl From<&SocketAddr> for Endpoint {
    fn from(addr: &SocketAddr) -> Endpoint {
        Endpoint {
            addr: addr.ip().into(),
            port: U16::from(addr.port()),
        }
    }
}

impl From<Endpoint> for SocketAddr {
    fn from(addr: Endpoint) -> SocketAddr {
        SocketAddr::new(addr.addr.into(), addr.port.get())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

/// A collection of network endpoints.
///
/// This represents a list of endpoints that a peer can be reached at,
/// used in HELLO and UNITE messages for peer discovery.
#[repr(transparent)]
pub struct EndpointsList(pub HashSet<Endpoint>);

impl From<EndpointsList> for Vec<u8> {
    fn from(from: EndpointsList) -> Vec<u8> {
        let mut w_idx = 0;
        let mut buf = Vec::with_capacity(from.0.len() * HELLO_ENDPOINT_LEN);
        #[allow(clippy::uninit_vec)]
        unsafe {
            buf.set_len(buf.capacity());
        };
        for endpoint in &from.0 {
            endpoint.to_bytes(&mut buf[w_idx..][..HELLO_ENDPOINT_LEN]);
            w_idx += HELLO_ENDPOINT_LEN;
        }
        buf
    }
}

impl From<&[u8]> for EndpointsList {
    fn from(buf: &[u8]) -> Self {
        let mut r_idx = 0;
        let mut endpoints = HashSet::with_capacity(HELLO_MAX_ENDPOINTS);
        while r_idx + HELLO_ENDPOINT_LEN <= buf.len() {
            if let Ok(endpoint) = Endpoint::parse(&buf[r_idx..][..HELLO_ENDPOINT_LEN]) {
                endpoints.insert(endpoint.clone());
            };
            r_idx += HELLO_ENDPOINT_LEN;
        }
        EndpointsList(endpoints)
    }
}

impl fmt::Display for EndpointsList {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.iter();
        if let Some(first) = iter.next() {
            write!(f, "{first}")?;
            for endpoint in iter {
                write!(f, " {endpoint}")?;
            }
        }
        Ok(())
    }
}
