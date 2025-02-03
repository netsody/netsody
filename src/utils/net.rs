use if_addrs::get_if_addrs;
use std::io;
use std::net::IpAddr;

pub(crate) const IPV4_LENGTH: usize = 4;
pub(crate) const IPV6_LENGTH: usize = 16;
#[cfg(windows)]
pub(crate) const IPV6_MAPPED_IPV4: bool = false;
#[cfg(not(windows))]
pub(crate) const IPV6_MAPPED_IPV4: bool = true;

pub fn get_addrs() -> io::Result<Vec<IpAddr>> {
    let interfaces = get_if_addrs()?;
    let mut addresses = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        if !interface.is_loopback() {
            match interface.addr {
                if_addrs::IfAddr::V4(addr) => {
                    addresses.push(IpAddr::V4(addr.ip));
                }
                if_addrs::IfAddr::V6(addr) => {
                    addresses.push(IpAddr::V6(addr.ip));
                }
            }
        }
    }
    addresses.shrink_to_fit();
    Ok(addresses)
}

pub fn listening_addrs(listen_addr: &IpAddr, my_addrs: &[IpAddr]) -> Vec<IpAddr> {
    if listen_addr.is_unspecified() {
        my_addrs
            .iter()
            .filter_map(|addr| match (listen_addr, addr) {
                (IpAddr::V4(_), IpAddr::V4(v4)) => Some(IpAddr::V4(*v4)),
                (IpAddr::V6(_), IpAddr::V6(v6)) => Some(IpAddr::V6(*v6)),
                (IpAddr::V6(_), IpAddr::V4(v4)) if IPV6_MAPPED_IPV4 => {
                    Some(IpAddr::V6(v4.to_ipv6_mapped()))
                }
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

        // Prüfe dass wir mindestens eine Adresse haben
        assert!(
            !addrs.is_empty(),
            "Should find at least one network interface"
        );

        // Prüfe dass keine Loopback-Adressen dabei sind
        assert!(
            !addrs.iter().any(std::net::IpAddr::is_loopback),
            "Should not contain loopback addresses"
        );

        // Debug-Ausgabe der gefundenen Adressen
        println!("Found network interfaces:");
        for addr in addrs {
            println!("  {addr}");
        }
    }
}
