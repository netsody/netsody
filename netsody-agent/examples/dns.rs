use zbus::Connection;

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

    if true {
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

        println!("Ping reply: {:?}", reply);
    }
}