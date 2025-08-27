use crate::crypto::{ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES};
use crate::identity::{Identity, PubKey};
use crate::node;
use crate::node::{
    HELLO_TIMEOUT_DEFAULT, MessageSink, Node, NodeOpts, NodeOptsBuilder, NodeOptsBuilderError,
};
use crate::peer;
use crate::peer::PeersList;
use crate::peer::SuperPeerUrl;
use crate::peer::SuperPeerUrlError;
use std::borrow::Borrow;
use std::ffi::CStr;
use std::net::IpAddr;
use std::os::raw::{c_char, c_int};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ptr, slice};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};
use zerocopy::IntoBytes;

// Type alias for the complex receiver type
type MessageReceiver = Arc<Mutex<Receiver<(PubKey, Vec<u8>)>>>;
type MessageSender = Arc<Sender<(PubKey, Vec<u8>)>>;

// -1..-100
const ERR_UTF8: c_int = -1;
const ERR_IO: c_int = -2;
const ERR_CHANNEL_CLOSED: c_int = -3;
const ERR_ADDR_PARSE: c_int = -4;
const ERR_INDEX: c_int = -5;
const ERR_NULL_POINTER: c_int = -6;
const ERR_IDENTITY_GENERATION: c_int = -7;

// -101..-300
impl From<node::Error> for c_int {
    fn from(value: node::Error) -> c_int {
        match value {
            node::Error::SendFailed(_, _) => -101,
            node::Error::MessageError(_) => -102,
            node::Error::PeerError(_) => -103,
            node::Error::CryptoError(_) => -104,
            node::Error::BindParseError(_) => -105,
            node::Error::NetworkIdInvalid(_) => -106,
            node::Error::PowInvalid => -107,
            node::Error::MessageUnarmed => -108,
            node::Error::MessageArmed => -109,
            node::Error::MessageTypeUnexpected(_) => -110,
            node::Error::NoSuperPeers => -111,
            node::Error::MessageInvalidRecipient => -112,
            node::Error::HelloTooOld(_) => -113,
            node::Error::AckTimeIsInFuture => -114,
            node::Error::AckTooOld(_) => -115,
            node::Error::RecvBufDisconnected => -116,
            node::Error::MessageTypeInvalid => -117,
            node::Error::GetAddrsFailed(_) => -118,
            node::Error::SendingDirectError(_, _) => -119,
            node::Error::UdpLocalAddrError(_) => -120,
            node::Error::PeerNotPresent => -121,
            node::Error::HousekeepingFailed(_) => -122,
            node::Error::HelloEndpointInvalid(_) => -123,
            node::Error::AppLenInvalid(_, _) => -124,
            node::Error::TcpShutdownError(_) => -125,
            node::Error::PeersListCapacityExceeded(_) => -126,
            node::Error::HelloAddressInvalid(_) => -127,
            node::Error::SuperPeerResolveWrongFamily => -128,
            node::Error::SendHandleAlreadyCreated => -129,
            node::Error::BindError(_, _) => -130,
            node::Error::ShortIdOutdated => -131,
            node::Error::SendHandleClosed => -132,
            node::Error::SendingRelayedError { .. } => -133,
            node::Error::RecipientIsSuperPeer { .. } => -134,
            node::Error::SuperPeerNetworkIdMismatch(_, _) => -135,
            node::Error::NoUdpBindings => -136,
        }
    }
}

// -301..-400
impl From<NodeOptsBuilderError> for c_int {
    fn from(value: NodeOptsBuilderError) -> c_int {
        match value {
            NodeOptsBuilderError::UninitializedField(_) => -301,
            NodeOptsBuilderError::ValidationError(_) => -302,
        }
    }
}

// -401..-500
impl From<SuperPeerUrlError> for c_int {
    fn from(value: SuperPeerUrlError) -> c_int {
        match value {
            SuperPeerUrlError::NoPublicKey => -401,
            SuperPeerUrlError::NoAddr => -402,
            SuperPeerUrlError::InvalidUrl => -403,
            SuperPeerUrlError::InvalidPubKey => -404,
        }
    }
}

//
// MessageSink
//

pub struct ChannelSink(pub MessageSender);

impl MessageSink for ChannelSink {
    fn accept(&self, sender: PubKey, message: Vec<u8>) {
        match self.0.try_send((sender, message)) {
            Ok(_) => {}
            Err(e) => eprintln!("Received APP dropped: {e}"),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_recv_buf_new(
    recv_buf_cap: usize,
) -> *mut (MessageSender, MessageReceiver) {
    let (recv_buf_tx, recv_buf_rx) = mpsc::channel::<(PubKey, Vec<u8>)>(recv_buf_cap);
    Box::into_raw(Box::new((
        Arc::new(recv_buf_tx),
        Arc::new(Mutex::new(recv_buf_rx)),
    )))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_recv_buf_free(recv_buf: *mut (MessageSender, MessageReceiver)) -> c_int {
    unsafe {
        drop(Box::from_raw(recv_buf));
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_recv_buf_tx(
    recv_buf: &mut (MessageSender, MessageReceiver),
) -> *mut MessageSender {
    Box::into_raw(Box::new(recv_buf.0.clone()))
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_recv_buf_rx(
    recv_buf: &mut (MessageSender, MessageReceiver),
) -> *mut MessageReceiver {
    Box::into_raw(Box::new(recv_buf.1.clone()))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_recv_buf_len(
    bind: &mut NodeBind,
    recv_buf_rx: &mut MessageReceiver,
) -> c_int {
    let recv_buf_rx = recv_buf_rx.clone();
    bind.runtime
        .block_on(async { recv_buf_rx.lock_owned().await.len() as c_int })
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_recv_buf_recv(
    bind: &mut NodeBind,
    recv_buf_rx: &mut MessageReceiver,
    sender: *mut u8,
    buf: *mut u8,
    buf_len: usize,
) -> c_int {
    let (sender, buf) = unsafe {
        (
            slice::from_raw_parts_mut(sender, ED25519_PUBLICKEYBYTES),
            slice::from_raw_parts_mut(buf, buf_len),
        )
    };

    match bind
        .runtime
        .block_on(async { recv_buf_rx.lock().await.recv().await })
    {
        Some((my_sender, my_buf)) => {
            let len = my_buf.len();
            buf[..len].copy_from_slice(&my_buf);
            sender.copy_from_slice(my_sender.as_bytes());
            len as c_int
        }
        None => ERR_CHANNEL_CLOSED,
    }
}

//
// NodeOptsBuilder
//
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

/// Extern C function to generate an identity (secret key, public key, and proof of work).
///
/// This function fills the provided buffers with the corresponding values.
/// The caller must ensure that all buffers are non-null and properly sized.
///
/// # Arguments
/// * `sk_buf`   - Pointer to a buffer of at least 64 bytes for the secret key
/// * `pk_buf`   - Pointer to a buffer of at least 32 bytes for the public key
/// * `pow_buf`  - Pointer to a buffer of at least 4 bytes for the proof of work
/// * `pow_diff` - The proof of work difficulty
///
/// # Returns
/// * `0` on success
/// * `1` if any buffer pointer is null
/// * `2` if identity generation fails
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_generate_identity(
    sk_buf: *mut u8,
    pk_buf: *mut u8,
    pow_buf: *mut u8,
    pow_diff: u8,
) -> c_int {
    // Validate input pointers
    if sk_buf.is_null() || pk_buf.is_null() || pow_buf.is_null() {
        return ERR_NULL_POINTER;
    }

    // Attempt to generate identity
    let identity = match Identity::generate(pow_diff) {
        Ok(id) => id,
        Err(_) => return ERR_IDENTITY_GENERATION,
    };

    // Borrow inner byte arrays using known fixed-size types
    let sk_bytes: &[u8; ED25519_SECRETKEYBYTES] = identity.sk.borrow();
    let pk_bytes: &[u8; ED25519_PUBLICKEYBYTES] = identity.pk.borrow();
    let pow_bytes: &[u8] = identity.pow.as_bytes();

    // Copy data into provided buffers
    unsafe {
        ptr::copy_nonoverlapping(sk_bytes.as_ptr(), sk_buf, ED25519_SECRETKEYBYTES);
        ptr::copy_nonoverlapping(pk_bytes.as_ptr(), pk_buf, ED25519_PUBLICKEYBYTES);
        ptr::copy_nonoverlapping(pow_bytes.as_ptr(), pow_buf, 4);
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_new() -> *mut NodeOptsBuilder {
    Box::into_raw(Box::new(NodeOptsBuilder::default()))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_id(
    builder: &mut NodeOptsBuilder,
    sk: *const u8,
    pow: i32,
) -> c_int {
    let sk = unsafe { slice::from_raw_parts(sk, ED25519_SECRETKEYBYTES) }
        .try_into()
        .unwrap();
    let id = Identity::new(sk, pow.into());
    builder.id(id);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_message_sink(
    builder: &mut NodeOptsBuilder,
    recv_buf_tx: &mut MessageSender,
) -> c_int {
    let recv_buf_tx = unsafe { Box::from_raw(recv_buf_tx) };
    builder.message_sink(Arc::new(ChannelSink(*recv_buf_tx)));
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_udp_addrs(
    builder: &mut NodeOptsBuilder,
    udp_addrs: *const c_char,
) -> c_int {
    let udp_addrs = match unsafe { CStr::from_ptr(udp_addrs) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_UTF8,
    };

    let udp_addrs: Vec<IpAddr> = match udp_addrs
        .split_whitespace()
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(addrs) => addrs,
        Err(_) => return ERR_ADDR_PARSE,
    };

    builder.udp_addrs(udp_addrs);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_udp_port(
    builder: &mut NodeOptsBuilder,
    udp_port: u16,
) -> c_int {
    builder.udp_port(Some(udp_port));
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_udp_port_none(builder: &mut NodeOptsBuilder) -> c_int {
    builder.udp_port(None);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_arm_messages(
    builder: &mut NodeOptsBuilder,
    arm_messages: bool,
) -> c_int {
    builder.arm_messages(arm_messages);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_max_peers(
    builder: &mut NodeOptsBuilder,
    max_peers: u64,
) -> c_int {
    builder.max_peers(max_peers);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_min_pow_difficulty(
    builder: &mut NodeOptsBuilder,
    min_pow_difficulty: u8,
) -> c_int {
    builder.min_pow_difficulty(min_pow_difficulty);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_hello_timeout(
    builder: &mut NodeOptsBuilder,
    hello_timeout: u64,
) -> c_int {
    builder.hello_timeout(hello_timeout);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_hello_max_age(
    builder: &mut NodeOptsBuilder,
    hello_max_age: u64,
) -> c_int {
    builder.hello_max_age(hello_max_age);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_super_peers(
    builder: &mut NodeOptsBuilder,
    super_peers: *const c_char,
) -> c_int {
    let super_peers = match unsafe { CStr::from_ptr(super_peers) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_UTF8,
    };

    let super_peers: Vec<SuperPeerUrl> = match super_peers
        .split_whitespace()
        .map(SuperPeerUrl::from_str)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(peers) => peers,
        Err(e) => return e.into(),
    };

    builder.super_peers(super_peers);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_mtu(builder: &mut NodeOptsBuilder, mtu: usize) -> c_int {
    builder.mtu(mtu);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_process_unites(
    builder: &mut NodeOptsBuilder,
    process_unites: bool,
) -> c_int {
    builder.process_unites(process_unites);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_housekeeping_interval(
    builder: &mut NodeOptsBuilder,
    housekeeping_interval: u64,
) -> c_int {
    builder.housekeeping_interval(housekeeping_interval);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_build(
    builder: *mut NodeOptsBuilder,
    opts: *mut *mut NodeOpts,
) -> c_int {
    let builder = unsafe { Box::from_raw(builder) };
    match builder.build() {
        Ok(my_opts) => {
            unsafe { *opts = Box::into_raw(Box::new(my_opts)) };
            0
        }
        Err(e) => e.into(),
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_free(builder: *mut NodeOptsBuilder) -> c_int {
    unsafe {
        drop(Box::from_raw(builder));
    }
    0
}

//
// NodeOpts
//

// TODO: drasyl_node_opts_id

// TODO: drasyl_node_opts_message_sink

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_udp_port(opts: &mut NodeOpts) -> i32 {
    match opts.udp_port {
        Some(port) => port as i32,
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_arm_messages(opts: &mut NodeOpts) -> bool {
    opts.arm_messages
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_max_peers(opts: &mut NodeOpts) -> u64 {
    opts.max_peers
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_min_pow_difficulty(opts: &mut NodeOpts) -> u8 {
    opts.min_pow_difficulty
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_hello_timeout(opts: &mut NodeOpts) -> u64 {
    opts.hello_timeout
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_hello_max_age(opts: &mut NodeOpts) -> u64 {
    opts.hello_max_age
}

// TODO: drasyl_node_opts_super_peers

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_mtu(opts: &mut NodeOpts) -> c_int {
    opts.mtu as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_process_unites(opts: &mut NodeOpts) -> bool {
    opts.process_unites
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_housekeeping_interval(opts: &mut NodeOpts) -> u64 {
    opts.housekeeping_interval
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_udp_sockets(opts: &mut NodeOpts) -> usize {
    opts.udp_sockets
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_enforce_tcp(opts: &mut NodeOpts) -> bool {
    opts.enforce_tcp
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_free(opts: *mut NodeOpts) -> c_int {
    unsafe {
        drop(Box::from_raw(opts));
    }
    0
}

//
// Node
//
#[repr(C)]
pub struct NodeBind {
    node: Node,
    runtime: Runtime,
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_bind(opts: *mut NodeOpts, bind: *mut *mut NodeBind) -> c_int {
    // Set the global subscriber with TRACE level
    // let subscriber = FmtSubscriber::builder()
    //     .with_max_level(Level::TRACE) // or Level::DEBUG, etc.
    //     .finish();
    //
    // tracing::subscriber::set_global_default(subscriber)
    //     .expect("setting default subscriber failed");

    let opts = unsafe { Box::from_raw(opts) };
    let runtime = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return ERR_IO,
    };

    match runtime.block_on(Node::bind(*opts)) {
        Ok(node) => {
            unsafe { *bind = Box::into_raw(Box::new(NodeBind { node, runtime })) };
            0
        }
        Err(e) => e.into(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_bind_free(bind: &mut NodeBind) -> c_int {
    unsafe {
        drop(Box::from_raw(bind));
    }
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_send_to(
    bind: &mut NodeBind,
    recipient: *mut u8,
    buf: *mut u8,
    buf_len: usize,
) -> c_int {
    let (recipient, buf) = unsafe {
        (
            PubKey::try_from(slice::from_raw_parts(recipient, ED25519_PUBLICKEYBYTES)).unwrap(),
            slice::from_raw_parts(buf, buf_len),
        )
    };

    match bind.runtime.block_on(bind.node.send_to(&recipient, buf)) {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_peers_list<'a>(
    bind: &'a mut NodeBind,
    peers_list: *mut *mut &'a PeersList,
) -> c_int {
    unsafe { *peers_list = Box::into_raw(Box::new(bind.node.peers_list())) };
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_udp_port(bind: &mut NodeBind) -> c_int {
    bind.node.udp_port() as c_int
}

//
// PeersList
//
#[repr(C)]
pub struct Peer {
    pk: PubKey,
    super_peer: bool,
    reachable: bool,
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_peers_list_peers(
    peers_list: &mut &PeersList,
    peers: *mut *mut Vec<Peer>,
) -> c_int {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let mut result = Vec::new();
    for (pk, peer) in &peers_list.peers.pin() {
        match peer {
            peer::Peer::SuperPeer(super_peer) => {
                result.push(Peer {
                    pk: *pk,
                    super_peer: true,
                    reachable: super_peer.is_reachable(),
                });
            }
            peer::Peer::NodePeer(node_peer) => {
                result.push(Peer {
                    pk: *pk,
                    super_peer: false,
                    reachable: node_peer.is_reachable(now, HELLO_TIMEOUT_DEFAULT),
                });
            }
        };
    }

    unsafe { *peers = Box::into_raw(Box::new(result)) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_peers_list_peers_len(peers: &mut Vec<Peer>) -> u64 {
    peers.len() as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_peers_list_peers_free(peers: &mut Vec<Peer>) -> c_int {
    unsafe {
        drop(Box::from_raw(peers));
    }
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_peers_list_peer_pk(
    peers: &mut Vec<Peer>,
    index: usize,
    pk: *mut u8,
) -> c_int {
    let pk = unsafe { slice::from_raw_parts_mut(pk, ED25519_PUBLICKEYBYTES) };
    match peers.get(index) {
        Some(peer) => pk.copy_from_slice(peer.pk.as_bytes()),
        None => return ERR_INDEX,
    };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_peers_list_peer_super_peer(peers: &mut Vec<Peer>, index: usize) -> c_int {
    match peers.get(index) {
        Some(peer) => peer.super_peer as i32,
        None => ERR_INDEX,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_peers_list_peer_reachable(peers: &mut Vec<Peer>, index: usize) -> c_int {
    match peers.get(index) {
        Some(peer) => peer.reachable as i32,
        None => ERR_INDEX,
    }
}
