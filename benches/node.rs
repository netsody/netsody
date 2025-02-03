use ahash::RandomState;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use drasyl::identity::Identity;
use drasyl::messages::AppMessage;
use drasyl::node::{Node, NodeInner, NodeOptsBuilder};
use drasyl::super_peer::MTU_DEFAULT;
use drasyl::utils::crypto::ED25519_PUBLICKEYBYTES;
use drasyl::utils::hex::hex_to_bytes;
use papaya::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicPtr;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;

#[allow(clippy::type_complexity)]
fn create_test_node_rx(
    network_id: &[u8; 4],
    id: &Identity,
) -> (NodeInner, Receiver<([u8; ED25519_PUBLICKEYBYTES], Vec<u8>)>) {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let opts = NodeOptsBuilder::default()
            .network_id(*network_id)
            .arm_messages(false)
            .id(id.clone())
            .build()
            .unwrap();

        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_socket_addr = udp_socket.local_addr().unwrap();

        let (recv_buf_tx, recv_buf_rx) = mpsc::channel(opts.recv_buf_cap);
        let peers = HashMap::builder()
            .capacity(opts.max_peers as usize)
            .hasher(RandomState::new())
            .build();
        (
            NodeInner::new(
                opts,
                peers,
                None,
                None,
                AtomicPtr::default(),
                udp_socket,
                udp_socket_addr,
                recv_buf_tx,
            ),
            recv_buf_rx,
        )
    })
}

async fn create_test_node_tx(network_id: &[u8; 4], id: &Identity) -> Node {
    let opts = NodeOptsBuilder::default()
        .network_id(*network_id)
        .arm_messages(false)
        .id(id.clone())
        .udp_listen("0.0.0.0:0".parse().unwrap())
        .build()
        .unwrap();
    Node::bind(opts).await.unwrap()
}

fn create_app(
    network_id: &[u8; 4],
    sender: &[u8; ED25519_PUBLICKEYBYTES],
    pow: &[u8; 4],
    recipient: &[u8; ED25519_PUBLICKEYBYTES],
) -> Vec<u8> {
    let payload = vec![0u8; 1024];
    AppMessage::build(network_id, sender, pow, None, recipient, &payload).unwrap()
}

fn benchmark_node(c: &mut Criterion) {
    env_logger::init();

    let network_id: [u8; 4] = 0_i32.to_be_bytes();
    let id_1: Identity = Identity::new(
        hex_to_bytes(
            "23ed710af14dce67a77f0d43e5bd470635813261a375ce01cb9c2bbcd7e632867f588b40e13c8758838062865bb9d833d869d3d3d8516b9199c58b4405a36e65",
        ),
        (-2144630954i32).to_be_bytes(),
    );
    let id_2: Identity = Identity::new(
        hex_to_bytes(
            "15bde950a6f5adffe9cf94abdb3b6d2383a1ca681934e0703ac8ee2979c2384d77a27c8b2af5a4584c4398ad5e98204cf29bc572fa7abf436af9103d1c53d63a",
        ),
        (-2116633556i32).to_be_bytes(),
    );
    let id_3: Identity = Identity::new(
        hex_to_bytes(
            "ab01a4acbbbed8cd0f37c1f78d5b92008068de0014423f2fa2aeea4d4e75ecc03dcd2f00ef93aa9552280ea3a46986d28b06751bbee4eec66c9b157bd7909068",
        ),
        (-2131760488i32).to_be_bytes(),
    );

    let (node_rx, _recv_buf_rx) = create_test_node_rx(&network_id, &id_1);
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let bytes = vec![0u8; 1024];
    let mut app = create_app(&network_id, &id_2.pk, &id_2.pow, &id_1.pk);

    let runtime = Runtime::new().unwrap();
    let mut group = c.benchmark_group("node");

    group.bench_function("APP rx", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let mut response_buf = vec![0u8; MTU_DEFAULT];
                black_box(
                    node_rx
                        .on_udp_datagram(src, &mut app, &mut response_buf)
                        .await,
                )
            })
        });
    });

    let node_tx = runtime.block_on(async { create_test_node_tx(&network_id, &id_1).await });

    group.bench_function("APP tx", |b| {
        b.iter(|| runtime.block_on(async { black_box(node_tx.send_to(&id_3.pk, &bytes).await) }));
    });

    group.finish();
}

criterion_group!(benches, benchmark_node);
criterion_main!(benches);
