use if_addrs::{IfAddr, get_if_addrs};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const IPV4_LENGTH: usize = 4;
pub(crate) const IPV6_LENGTH: usize = 16;

/// Checks if an IPv4 address is globally routable.
///
/// This function implements the rules from:
/// - RFC 1918 (Private Address Space)
/// - RFC 3927 (Link-Local Addresses)
/// - RFC 5735 (Special Use IPv4 Addresses)
pub fn is_global_ipv4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();

    // Check for private addresses (RFC 1918)
    if octets[0] == 10 || // 10.0.0.0/8
        (octets[0] == 172 && (16..=31).contains(&octets[1])) || // 172.16.0.0/12
        (octets[0] == 192 && octets[1] == 168)
    // 192.168.0.0/16
    {
        return false;
    }

    // Check for link-local addresses (RFC 3927)
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }

    // Check for special use addresses (RFC 5735)
    if octets[0] == 0 || // 0.0.0.0/8
        octets[0] == 127 || // 127.0.0.0/8
        (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) || // 192.0.0.0/24
        (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) || // 192.0.2.0/24
        (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) || // 198.51.100.0/24
        (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) || // 203.0.113.0/24
        octets[0] >= 224
    // 224.0.0.0/4 (Multicast)
    {
        return false;
    }

    true
}

/// Checks if an IPv6 address is globally routable.
///
/// This function implements the rules from:
/// - RFC 4291 (IPv6 Addressing Architecture)
/// - RFC 4193 (Unique Local IPv6 Unicast Addresses)
/// - RFC 3879 (Deprecating Site Local Addresses)
pub fn is_global_ipv6(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();

    // Check for unspecified address
    if segments == [0; 8] {
        return false;
    }

    // Check for loopback address
    if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        return false;
    }

    // Check for unique local addresses (RFC 4193)
    if segments[0] & 0xfe00 == 0xfc00 {
        return false;
    }

    // Check for link-local addresses (RFC 4291)
    if segments[0] & 0xffc0 == 0xfe80 {
        return false;
    }

    // Check for multicast addresses (RFC 4291)
    if segments[0] & 0xff00 == 0xff00 {
        return false;
    }

    // Check for documentation addresses (RFC 3849)
    if segments[0] == 0x2001 && segments[1] == 0xdb8 {
        return false;
    }

    true
}

fn ip_is_valid_v4(ip: &Ipv4Addr) -> bool {
    ip.is_private() || is_global_ipv4(ip)
}

fn ip_is_valid_v6(ip: &Ipv6Addr) -> bool {
    // FIXME: filter temporary IPv6 addresses
    is_global_ipv6(ip) && !ip.is_unicast_link_local()
}

pub fn get_addrs() -> io::Result<Vec<(String, IpAddr)>> {
    Ok(get_if_addrs()?
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .filter(|iface| {
            !iface.name.starts_with("feth")
                && !iface.name.starts_with("utun")
                && !iface.name.starts_with("tun")
                && !iface.name.starts_with("zt")
                && !iface.name.starts_with("drasyl")
                && !iface.name.starts_with("docker")
                && !iface.name.starts_with("br-")
        }) // FIXME: read from NodeOpts
        .filter_map(|iface| match iface.addr {
            IfAddr::V4(v4) if ip_is_valid_v4(&v4.ip) => Some((iface.name, IpAddr::V4(v4.ip))),
            IfAddr::V6(v6) if ip_is_valid_v6(&v6.ip) => Some((iface.name, IpAddr::V6(v6.ip))),
            _ => None,
        })
        .collect::<Vec<_>>())
}

pub fn listening_addrs(listen_addr: &IpAddr, my_addrs: &[IpAddr]) -> Vec<IpAddr> {
    if listen_addr.is_unspecified() {
        my_addrs
            .iter()
            .filter_map(|addr| match (listen_addr, addr) {
                (IpAddr::V6(_), IpAddr::V6(v6)) => Some(IpAddr::V6(*v6)),
                (_, IpAddr::V4(v4)) => Some(IpAddr::V4(*v4)),
                _ => None,
            })
            .collect()
    } else {
        vec![*listen_addr]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_addrs() {
        let addrs = get_addrs().expect("get_addrs should not fail");

        // check that we have at least one address
        assert!(
            !addrs.is_empty(),
            "Should find at least one network interface"
        );

        // check that there are no loopback addresses
        assert!(
            !addrs
                .iter()
                .any(|(_, ip_addr)| IpAddr::is_loopback(ip_addr)),
            "Should not contain loopback addresses"
        );

        // debug output of found addresses
        println!("Found network interfaces:");
        for (_, addr) in addrs {
            println!("  {addr}");
        }
    }
}
