#[macro_use]
mod identity;
mod messages;
mod monitoring;
mod node;
mod peers;
mod server;
mod utils;

use lazy_static::lazy_static;
use log::error;
use node::Node;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use utils::system;

lazy_static! {
    pub static ref ARM_MESSAGES: bool = system::get_env("ARM_MESSAGES", true);
    pub static ref ACCEPT_UNARMED_MESSAGES: bool = system::get_env("ACCEPT_UNARMED_MESSAGES", false);
    pub static ref HOP_COUNT_LIMIT: u8 = system::get_env("HOP_COUNT_LIMIT", 7);
    pub static ref MTU: usize = system::get_env("MTU", 1500); // bytes
    pub static ref MIN_POW_DIFFICULTY: u8 = system::get_env("MIN_POW_DIFFICULTY", 24);
    pub static ref HELLO_ONLINE_TIMEOUT: u64 = system::get_env("HELLO_ONLINE_TIMEOUT", 30 * 1000); // milliseconds
    pub static ref IDENTITY_FILE: String = system::get_env("IDENTITY_FILE", "drasyl.identity".to_string());
    pub static ref NETWORK_ID: [u8; 4] = system::get_env("NETWORK_ID", 1i32).to_be_bytes();
    pub static ref SERVER_LISTEN: String = system::get_env("SERVER_LISTEN", "0.0.0.0:22527".to_string());
    pub static ref SEND_UNITES: i32 = system::get_env("SEND_UNITES", 5 * 1000); // milliseconds, set to -1 disables UNITE sending
    pub static ref POW_VALIDATION_TIMEOUT: u64 = system::get_env("POW_VALIDATION_TIMEOUT", 60 * 60 * 1000); // milliseconds
    pub static ref MAX_PEERS: u64 = system::get_env("MAX_PEERS", 10_000); // set to 0 removes peers limit
    pub static ref MESSAGE_MAX_AGE: u64 = system::get_env("MESSAGE_MAX_AGE", 60_000); // milliseconds
    pub static ref MONITORING_SERVER_LISTEN: String = system::get_env("MONITORING_SERVER_LISTEN", "0.0.0.0:443".to_string()); // use empty string to disable monitoring server
}

fn main() {
    env_logger::init();

    match Node::new() {
        Ok(node) => {
            let node = Arc::new(node);

            if *MONITORING_SERVER_LISTEN != "".to_string() {
                thread::spawn(|| {
                    if let Err(e) = monitoring::start_http_server() {
                        error!("HTTP monitoring server error: {}", e);
                    }
                });
            }

            // background task
            {
                let node = Arc::clone(&node);
                thread::spawn(move || loop {
                    thread::sleep(Duration::from_secs(5));
                    node.housekeeping();
                });
            }

            // listen on UDP socket
            let mut buf = Vec::with_capacity(*MTU);
            unsafe { buf.set_len(buf.capacity()) }; // avoid unnecessary initialized of buf
            loop {
                match node.socket().recv_from(&mut buf) {
                    Ok((size, src)) => match server::on_datagram(&node, &mut buf[..size], src) {
                        Ok(_) => {}
                        Err(e) => error!("Error processing datagram: {}", e),
                    },
                    Err(e) => {
                        error!("Error receiving datagram: {}", e);
                        continue;
                    },
                }
            }
        }
        Err(e) => error!("Error creating node: {}", e),
    }
}
