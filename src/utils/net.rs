use std::net::{IpAddr, Ipv6Addr};

const IPV4_LENGTH: usize = 4;
pub(crate) const IPV6_LENGTH: usize = 16;

pub fn addr_from_bytes(bytes: &[u8; IPV6_LENGTH]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(*bytes))
}

pub fn addr_to_bytes(addr: IpAddr, bytes: &mut [u8; IPV6_LENGTH]) {
    match addr {
        IpAddr::V6(ipv6) => {
            bytes.copy_from_slice(&ipv6.octets());
        }
        IpAddr::V4(ipv4) => {
            // convert to ipv6 mapped ipv4 (::ffff:0:0/96)
            bytes[(IPV6_LENGTH - IPV4_LENGTH - 2)..][..2].copy_from_slice(&[0xff, 0xff]);
            bytes[(IPV6_LENGTH - IPV4_LENGTH)..].copy_from_slice(&ipv4.octets());
        }
    }
}
