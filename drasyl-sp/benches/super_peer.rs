use criterion::{Criterion, black_box, criterion_group, criterion_main};
use drasyl::identity::{Identity, Pow, PubKey, SecKey};
use drasyl::message::AppMessage;
use drasyl::message::HelloSuperPeerMessage;
use drasyl::message::NetworkId;
use drasyl::node::MTU_DEFAULT;
use drasyl_sp::sp::SuperPeerInner;
use drasyl_sp::sp::SuperPeerOptsBuilder;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

fn create_test_super_peer(network_id: &NetworkId, id: &Identity) -> SuperPeerInner {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let opts = SuperPeerOptsBuilder::default()
            .network_id(*network_id)
            .arm_messages(false)
            .id(id.clone())
            .build()
            .unwrap();

        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cancellation_token = CancellationToken::new();

        SuperPeerInner::new(
            opts,
            Some(udp_socket),
            None,
            None,
            None,
            None,
            None,
            cancellation_token,
        )
    })
}

fn create_app(network_id: &NetworkId, sender: &PubKey, pow: &Pow, recipient: &PubKey) -> Vec<u8> {
    let payload = vec![0u8; 1024];
    AppMessage::build(network_id, sender, pow, None, recipient, &payload).unwrap()
}

fn create_hello(network_id: &NetworkId, sender: &PubKey, pow: &Pow, recipient: &PubKey) -> Vec<u8> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let endpoints = [0u8; 18];
    HelloSuperPeerMessage::build(network_id, sender, pow, None, recipient, time, &endpoints)
        .unwrap()
}

fn benchmark_on_packet(c: &mut Criterion) {
    tracing_subscriber::fmt::init();

    let network_id: NetworkId = 0_i32.to_be_bytes();
    let id_1: Identity = Identity::new(
        SecKey::from_str(
            "23ed710af14dce67a77f0d43e5bd470635813261a375ce01cb9c2bbcd7e632867f588b40e13c8758838062865bb9d833d869d3d3d8516b9199c58b4405a36e65",
        ).unwrap(),
        (-2144630954i32).into(),
    );
    let id_2: Identity = Identity::new(
        SecKey::from_str(
            "15bde950a6f5adffe9cf94abdb3b6d2383a1ca681934e0703ac8ee2979c2384d77a27c8b2af5a4584c4398ad5e98204cf29bc572fa7abf436af9103d1c53d63a",
        ).unwrap(),
        (-2116633556i32).into(),
    );
    let id_3: Identity = Identity::new(
        SecKey::from_str(
            "ab01a4acbbbed8cd0f37c1f78d5b92008068de0014423f2fa2aeea4d4e75ecc03dcd2f00ef93aa9552280ea3a46986d28b06751bbee4eec66c9b157bd7909068",
        ).unwrap(),
        (-2131760488i32).into(),
    );

    let super_peer = create_test_super_peer(&network_id, &id_1);
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let mut app = create_app(&network_id, &id_3.pk, &id_3.pow, &id_2.pk);
    let mut hello = create_hello(&network_id, &id_2.pk, &id_2.pow, &id_1.pk);
    let mut response_buf = vec![0u8; MTU_DEFAULT];

    let runtime = Runtime::new().unwrap();

    let mut group = c.benchmark_group("on_packet");

    runtime
        .block_on(async {
            black_box(
                super_peer
                    .on_udp_datagram(src, &mut hello, &mut response_buf)
                    .await,
            )
        })
        .unwrap_or(());

    group.bench_function("APP", |b| {
        b.iter(|| {
            runtime.block_on(async {
                black_box(
                    super_peer
                        .on_udp_datagram(src, &mut app, &mut response_buf)
                        .await,
                )
            })
        });
    });

    group.bench_function("HELLO", |b| {
        b.iter(|| {
            runtime.block_on(async {
                black_box(
                    super_peer
                        .on_udp_datagram(src, &mut hello, &mut response_buf)
                        .await,
                )
            })
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_on_packet);
criterion_main!(benches);
