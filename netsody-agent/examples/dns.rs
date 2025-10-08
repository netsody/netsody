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

    if true {
        // System- oder Session-Bus? resolve1 läuft im System-Bus:
        let connection = Connection::system().await.expect("Failed to connect to system bus");

        let proxy = ManagerProxy::new(&connection).await.expect("Failed to create proxy");
        let reply = proxy.dns_stub_listener().await.expect("Failed to call method");
        let stub_active = reply == "yes";
        println!("stub_active: {:?}", stub_active);

        let reply = proxy.flush_caches().await.expect("Failed to call method");
        println!("Reply: {:?}", reply);
    }
}