use ahash::RandomState;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use drasyl_p2p::identity::{Identity, Pow, PubKey, SecKey};
use drasyl_p2p::message::AppMessage;
use drasyl_p2p::message::NetworkId;
use drasyl_p2p::node::NodeInner;
use drasyl_p2p::node::{MTU_DEFAULT, MessageSink, NodeOptsBuilder};
use drasyl_p2p::node::{Node, UdpBinding};
use papaya::HashMap as PapayaHashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicPtr;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;

fn create_test_node_rx(
    network_id: NetworkId,
    id: &Identity,
) -> (NodeInner, Receiver<(PubKey, Vec<u8>)>) {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let (recv_buf_tx, recv_buf_rx) = mpsc::channel::<(PubKey, Vec<u8>)>(64);

        let opts = NodeOptsBuilder::default()
            .arm_messages(false)
            .id(id.clone())
            .message_sink(Arc::new(ChannelSink(recv_buf_tx)))
            .build()
            .unwrap();

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_socket_addr = socket.local_addr().unwrap().port();
        let udp_binding = Arc::new(UdpBinding::new(CancellationToken::new(), socket));
        let udp_sockets = vec![udp_binding];

        let peers = PapayaHashMap::builder()
            .capacity(opts.max_peers as usize)
            .hasher(RandomState::new())
            .build();
        (
            NodeInner::new(
                opts,
                network_id,
                peers,
                None,
                None,
                AtomicPtr::default(),
                udp_sockets,
                udp_socket_addr,
                CancellationToken::new(),
            ),
            recv_buf_rx,
        )
    })
}

async fn create_test_node_tx(id: &Identity) -> Node {
    let opts = NodeOptsBuilder::default()
        .arm_messages(false)
        .id(id.clone())
        .udp_port(Some(0))
        .build()
        .unwrap();
    Node::bind(opts).await.unwrap()
}

fn create_app(network_id: &NetworkId, sender: &PubKey, pow: &Pow, recipient: &PubKey) -> Vec<u8> {
    let payload = vec![0u8; 1024];
    AppMessage::build(network_id, sender, pow, None, recipient, &payload).unwrap()
}

fn benchmark_node(c: &mut Criterion) {
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

    let (node_rx, _recv_buf_rx) = create_test_node_rx(network_id, &id_1);
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let bytes = vec![0u8; 1024];
    let mut app = create_app(&network_id, &id_2.pk, &id_2.pow, &id_1.pk);

    let runtime = Runtime::new().unwrap();
    let socket =
        runtime.block_on(async { tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap() });
    let udp_binding = Arc::new(UdpBinding::new(CancellationToken::new(), socket));

    let mut group = c.benchmark_group("node");

    group.bench_function("APP rx", |b| {
        let udp_binding = udp_binding.clone();
        b.iter(|| {
            runtime.block_on(async {
                let mut response_buf = vec![0u8; MTU_DEFAULT];
                black_box(
                    node_rx
                        .on_udp_datagram(src, &mut app, &mut response_buf, udp_binding.clone())
                        .await,
                )
            })
        });
    });

    let node_tx = runtime.block_on(async { create_test_node_tx(&id_1).await });

    group.bench_function("APP tx", |b| {
        b.iter(|| runtime.block_on(async { black_box(node_tx.send_to(&id_3.pk, &bytes).await) }));
    });

    group.finish();
}

pub struct ChannelSink(pub Sender<(PubKey, Vec<u8>)>);

impl MessageSink for ChannelSink {
    fn accept(&self, sender: PubKey, message: Vec<u8>) {
        match self.0.try_send((sender, message)) {
            Ok(_) => {}
            Err(e) => eprintln!("Received APP dropped: {e}"),
        }
    }
}

criterion_group!(benches, benchmark_node);
criterion_main!(benches);
