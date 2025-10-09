use std::net::Ipv4Addr;
use zbus::{proxy, Connection};

#[proxy(
    interface = "org.freedesktop.DBus.Peer",
    default_path = "/org/freedesktop/resolve1",
    default_service = "org.freedesktop.resolve1"
)]
trait Peer {
    fn ping(&self) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_path = "/org/freedesktop/resolve1",
    default_service = "org.freedesktop.resolve1"
)]
trait Manager {
    #[zbus(property, name = "DNSStubListener")]
    fn dns_stub_listener(&self) -> zbus::Result<String>;

    fn flush_caches(&self) -> zbus::Result<()>;

    /// Set DNS servers for a given network link.
    ///
    /// D-Bus signature: `ia(iay)`
    /// - `ifindex`: Interface index (as returned by `ip link` or `resolvectl status`)
    /// - `addresses`: Array of tuples `(address_family, address_bytes)`
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    /// Reverts any per-link configuration (DNS servers, domains, DNSSEC, etc.)
    /// previously set via the Manager API or resolvectl.
    ///
    /// D-Bus signature: `(i)`
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;

    /// Sets routing or search domains for a given link.
    ///
    /// D-Bus signature: `ia(sb)`
    /// Each tuple consists of:
    /// - `s`: domain name (e.g., `"netsody.me"`)
    /// - `b`: routing domain flag (`true` = routing domain `~example.com`,
    ///                            `false` = search domain `example.com`)
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;

    /// Returns the object path for the given network interface index.
    fn get_link(&self, ifindex: i32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.resolve1.Link",
    default_service = "org.freedesktop.resolve1"
)]
trait Link {
    #[zbus(property, name = "DNS")]
    fn dns(&self) -> zbus::Result<Vec<(i32, Vec<u8>)>>;

    #[zbus(property)]
    fn domains(&self) -> zbus::Result<Vec<(String, bool)>>;

    /// Set DNS servers for this link.
    ///
    /// D-Bus signature: `a(iay)`
    /// - `addresses`: Array of tuples `(address_family, address_bytes)`
    #[zbus(name = "SetDNS")]
    fn set_dns(&self, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    /// Set routing or search domains for this link.
    ///
    /// D-Bus signature: `a(sb)`
    /// Each tuple consists of:
    /// - `s`: domain name (e.g., `"netsody.me"`)
    /// - `b`: routing domain flag (`true` = routing domain `~example.com`,
    ///                            `false` = search domain `example.com`)
    #[zbus(name = "SetDomains")]
    fn set_domains(&self, domains: Vec<(String, bool)>) -> zbus::Result<()>;
}

// busctl get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager DNSStubListener

#[tokio::main]
async fn main() {
    if false {
        use std::fs::File;
        use std::io::Read;

        // Read the file
        let mut buf = Vec::with_capacity(4096);
        let mut f = File::open("/etc/resolv.conf").unwrap();
        f.read_to_end(&mut buf).unwrap();

        // Parse the buffer
        let cfg = resolv_conf::Config::parse(&buf).unwrap();

        // Print the config
        println!("---- Parsed /etc/resolv.conf -----\n{:#?}\n", cfg);
    }

    if false {
        // System- oder Session-Bus? resolve1 läuft im System-Bus:
        let connection = Connection::system().await.expect("Failed to connect to system bus");

        // Nachricht erstellen und senden
        let reply = connection
            .call_method(
                Some("org.freedesktop.resolve1"),
                "/org/freedesktop/resolve1",
                Some("org.freedesktop.DBus.Peer"),
                "Ping",
                &(),
            )
            .await.expect("Failed to call method");

        println!("Reply: {:?}", reply);
    }

    if false {
        // System- oder Session-Bus? resolve1 läuft im System-Bus:
        let connection = Connection::system().await.expect("Failed to connect to system bus");

        let proxy = PeerProxy::new(&connection).await.expect("Failed to create proxy");
        let reply = proxy.ping().await.expect("Failed to call method");
        println!("Reply: {:?}", reply);
    }

    if false {
        // System- oder Session-Bus? resolve1 läuft im System-Bus:
        let connection = Connection::system().await.expect("Failed to connect to system bus");

        let proxy = ManagerProxy::new(&connection).await.expect("Failed to create proxy");
        let reply = proxy.dns_stub_listener().await.expect("Failed to call method");
        let stub_active = reply == "yes";
        println!("stub_active: {:?}", stub_active);

        let reply = proxy.flush_caches().await.expect("Failed to call method");
        println!("Reply: {:?}", reply);
    }

    if false {
        use libc::{if_nametoindex};
        use std::ffi::CString;
        use libc::AF_INET;
        let ifname = CString::new("netsody").unwrap();
        let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) };
        if ifindex == 0 {
            eprintln!("Interface nicht gefunden");
        } else {
            println!("Index: {}", ifindex);
            let ifindex : i32 = ifindex as i32;

            let connection = Connection::system().await.expect("Failed to connect to system bus");

            let proxy = ManagerProxy::new(&connection).await.expect("Failed to create proxy");
            if true {
                let ip = Ipv4Addr::new(10, 10, 43, 254);
                let reply = proxy
                    .set_link_dns(ifindex, vec![(AF_INET, ip.octets().to_vec())])
                    .await.expect("Failed to call method");
                println!("Reply: {:?}", reply);

                let reply = proxy
                    .set_link_domains(ifindex, vec![("netsody.me".into(), true)])
                    .await.expect("Failed to call method");
                println!("Reply: {:?}", reply);
            }
            else {
                let reply = proxy
                    .revert_link(ifindex)
                    .await.expect("Failed to call method");
                println!("Reply: {:?}", reply);
            }
        }
    }

    if true {
        use libc::{if_nametoindex};
        use std::ffi::CString;
        let ifname = CString::new("netsody").unwrap();
        let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) };
        if ifindex == 0 {
            eprintln!("Interface nicht gefunden");
        } else {
            println!("Index: {}", ifindex);
            let ifindex: i32 = ifindex as i32;

            let connection = Connection::system().await.expect("Failed to connect to system bus");

            let proxy = ManagerProxy::new(&connection).await.expect("Failed to create proxy");
            let path = proxy.get_link(ifindex).await.expect("Failed to call GetLink");
            println!("Link path: {}", path);

            let link = LinkProxy::builder(&connection)
                .path(path)
                .expect("Invalid object path")
                // .destination("org.freedesktop.resolve1")
                // .expect("Invalid destination")
                .build()
                .await
                .expect("Failed to create LinkProxy");

            // Define desired values
            use libc::AF_INET;
            let desired_dns_ip = Ipv4Addr::new(10, 10, 43, 254);
            let desired_dns = vec![(AF_INET, desired_dns_ip.octets().to_vec())];
            let desired_domains = vec![("netsody.me".to_string(), true)];

            // Get current values
            let current_dns = link.dns().await.expect("Failed to get DNS property");
            let current_domains = link.domains().await.expect("Failed to get domains property");

            println!("Current DNS servers: {:?}", current_dns);
            println!("Current domains: {:?}", current_domains);

            // Check if DNS needs to be updated
            let dns_needs_update = current_dns != desired_dns;
            if dns_needs_update {
                println!("DNS differs from desired value, updating...");
                link.set_dns(desired_dns.clone())
                    .await
                    .expect("Failed to set DNS");
                println!("DNS updated successfully");
            } else {
                println!("DNS already matches desired value");
            }

            // Check if domains need to be updated
            let domains_need_update = current_domains != desired_domains;
            if domains_need_update {
                println!("Domains differ from desired value, updating...");
                link.set_domains(desired_domains.clone())
                    .await
                    .expect("Failed to set domains");
                println!("Domains updated successfully");
            } else {
                println!("Domains already match desired value");
            }
        }
    }
}