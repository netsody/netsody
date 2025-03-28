use crate::identity::Identity;
use crate::node::NodeOpts;
use crate::node::NodeOptsBuilder;
use crate::node::{Node, NodeError, NodeOptsBuilderError};
use crate::utils::crypto::{ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::slice;
use tokio::runtime::Runtime;

const ERR_UTF8: c_int = -1;
const ERR_IO: c_int = -31;

impl From<NodeError> for c_int {
    fn from(value: NodeError) -> c_int {
        match value {
            NodeError::SendFailed(_, _) => -2,
            NodeError::MessageError(_) => -3,
            NodeError::PeersError(_) => -4,
            NodeError::CryptoError(_) => -5,
            NodeError::BindError(_) => -6,
            NodeError::NetworkIdInvalid(_) => -7,
            NodeError::PowInvalid => -8,
            NodeError::MessageUnarmed => -9,
            NodeError::MessageArmed => -10,
            NodeError::MessageTypeUnexpected(_) => -12,
            NodeError::NoSuperPeers => -13,
            NodeError::MessageInvalidRecipient => -14,
            NodeError::HelloTooOld(_) => -15,
            NodeError::AckTimeIsInFuture => -16,
            NodeError::AckTooOld(_) => -17,
            NodeError::RecvBufClosed => -18,
            NodeError::MessageTypeInvalid => -19,
            NodeError::GetAddrsFailed(_) => -20,
            NodeError::UdpSendToError(_, _) => -21,
            NodeError::UdpLocalAddrError(_) => -22,
            NodeError::PeerNotPresent => -23,
            NodeError::TcpPeerAddrError(_) => -24,
            NodeError::RecipientUnreachable => -25,
            NodeError::HousekeepingFailed(_) => -26,
            NodeError::HelloEndpointInvalid(_) => -27,
            NodeError::AppLenInvalid(_, _) => -28,
            NodeError::TcpShutdownError(_) => -32,
            NodeError::PeersListCapacityExceeded(_) => -33,
            NodeError::HelloAddressInvalid(_) => -34,
            NodeError::SuperPeerResolveFailed(_) => -35,
            NodeError::SuperPeerResolveTimeout(_) => -36,
            NodeError::SuperPeerResolveEmpty => -37,
            NodeError::SuperPeerResolveWrongFamily => -38,
            NodeError::SendHandleAlreadyCreated => -39,
        }
    }
}

impl From<NodeOptsBuilderError> for c_int {
    fn from(value: NodeOptsBuilderError) -> c_int {
        match value {
            NodeOptsBuilderError::UninitializedField(_) => -29,
            NodeOptsBuilderError::ValidationError(_) => -30,
        }
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
    let id = Identity::new(sk, pow.to_be_bytes());
    builder.id(id);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_network_id(
    builder: &mut NodeOptsBuilder,
    network_id: i32,
) -> c_int {
    builder.network_id(network_id.to_be_bytes());
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_udp_listen(
    builder: &mut NodeOptsBuilder,
    udp_listen: *const c_char,
) -> c_int {
    let udp_listen = match unsafe { CStr::from_ptr(udp_listen) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_UTF8,
    };
    builder.udp_listen(udp_listen);
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
    builder.super_peers(super_peers);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_recv_buf_cap(
    builder: &mut NodeOptsBuilder,
    recv_buf_cap: usize,
) -> c_int {
    builder.recv_buf_cap(recv_buf_cap);
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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_hello_endpoints(
    builder: &mut NodeOptsBuilder,
    hello_endpoints: *const c_char,
) -> c_int {
    let hello_endpoints = match unsafe { CStr::from_ptr(hello_endpoints) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_UTF8,
    };
    builder.hello_endpoints(hello_endpoints);
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_hello_addresses_excluded(
    builder: &mut NodeOptsBuilder,
    hello_addresses_excluded: *const c_char,
) -> c_int {
    let hello_addresses_excluded =
        match unsafe { CStr::from_ptr(hello_addresses_excluded) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return ERR_UTF8,
        };
    builder.hello_addresses_excluded(hello_addresses_excluded);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_builder_housekeeping_delay(
    builder: &mut NodeOptsBuilder,
    housekeeping_delay: u64,
) -> c_int {
    builder.housekeeping_delay(housekeeping_delay);
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
pub extern "C" fn drasyl_node_opts_builder_free(builder: *mut NodeOptsBuilder) {
    unsafe {
        drop(Box::from_raw(builder));
    }
}

//
// NodeOpts
//
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_network_id(opts: &mut NodeOpts) -> i32 {
    i32::from_be_bytes(opts.network_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_udp_listen(opts: &mut NodeOpts) -> *const c_char {
    match CString::new(opts.udp_listen.clone()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null(),
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

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_super_peers(opts: &mut NodeOpts) -> *const c_char {
    match CString::new(opts.super_peers.clone()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_recv_buf_cap(opts: &mut NodeOpts) -> c_int {
    opts.recv_buf_cap as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_mtu(opts: &mut NodeOpts) -> c_int {
    opts.mtu as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_process_unites(opts: &mut NodeOpts) -> bool {
    opts.process_unites
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_hello_endpoints(opts: &mut NodeOpts) -> *const c_char {
    match CString::new(opts.hello_endpoints.clone()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_hello_addresses_excluded(opts: &mut NodeOpts) -> *const c_char {
    match CString::new(opts.hello_addresses_excluded.clone()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_housekeeping_delay(opts: &mut NodeOpts) -> u64 {
    opts.housekeeping_delay
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_opts_free(opts: *mut NodeOpts) {
    unsafe {
        drop(Box::from_raw(opts));
    }
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
pub extern "C" fn drasyl_node_bind_free(bind: &mut NodeBind) {
    unsafe {
        drop(Box::from_raw(bind));
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_recv_buf_len(bind: &mut NodeBind) -> c_int {
    match bind
        .runtime
        .block_on(async { bind.node.recv_buf_len().await })
    {
        len => len as c_int,
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_node_recv_from(
    bind: &mut NodeBind,
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

    match bind.runtime.block_on(async { bind.node.recv_from().await }) {
        Ok((my_buf, my_sender)) => {
            let len = my_buf.len();
            buf[..len].copy_from_slice(&my_buf);
            sender.copy_from_slice(&my_sender);
            len as c_int
        }
        Err(e) => e.into(),
    }
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
            slice::from_raw_parts(recipient, ED25519_PUBLICKEYBYTES)
                .try_into()
                .unwrap(),
            slice::from_raw_parts(buf, buf_len),
        )
    };

    match bind.runtime.block_on(bind.node.send_to(recipient, buf)) {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}
