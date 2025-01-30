use log::info;
use std::io::{Read, Write};
use std::net::TcpListener;

pub fn start_http_server() -> std::io::Result<()> {
    let listener = TcpListener::bind(&*crate::MONITORING_SERVER_LISTEN)?;
    info!(
        "HTTP monitoring server listening on {}",
        *crate::MONITORING_SERVER_LISTEN
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Lese Request
                let mut buffer = [0; 1024];
                stream.read(&mut buffer)?;

                // Sende 200 OK Response ohne Body
                let response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
                stream.write(response.as_bytes())?;
                stream.flush()?;

                drop(stream);
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                continue;
            }
        }
    }

    Ok(())
}
