//! # Message type definitions used by the Netsody protocol.
//!
//! This module contains the core message types and utilities for the Netsody peer-to-peer network protocol.
//! It provides a comprehensive set of message formats for network communication, peer discovery,
//! and protocol control operations.
//!
//! ## Message Types
//!
//! The module implements several distinct message types, each serving specific purposes in the
//! Netsody network protocol:
//!
//! ### Control Messages
//! - **ACK**: Acknowledgment messages for reliable delivery confirmation
//! - **HELLO**: Peer discovery and handshake messages for establishing connections
//!   - **HELLO_SUPER_PEER**: Messages for super peer discovery and registration
//!   - **HELLO_NODE_PEER**: Messages for direct node-to-node peer discovery
//! - **UNITE**: NAT traversal messages for direct peer-to-peer connection establishment
//!
//! ### Data Messages
//! - **APP**: Application-level data messages for user payload transmission
//!
//! ### Protocol Infrastructure
//! - **Headers**: Long and short header formats for message framing and routing
//! - **Endpoints**: Network endpoint representations for addressing
//! - **Arming**: Message encryption/decryption utilities for secure communication
//! - **Error**: Comprehensive error types for message processing failures
//!
//! ## Message Structure
//!
//! All Netsody messages follow a consistent structure with headers containing routing information
//! and optional payload data. The protocol supports both encrypted and unencrypted message
//! transmission depending on configuration and message type.
//!
//! ### Header Types
//! - **Long Header**: Full routing information including sender, recipient, and network metadata
//! - **Short Header**: Compressed header format for established connections
//!
//! ## Usage
//!
//! This module provides the foundational message types used throughout the Netsody network stack.
//! Messages are typically constructed, serialized, transmitted over the network, and then
//! deserialized and processed by receiving peers.
//!
//! ```rust,ignore
//! use netsody_p2p::message::{AppMessage, LongHeader, MessageError};
//!
//! // Create an application message
//! let app_msg = AppMessage::new(payload_data);
//!
//! // Construct with routing header
//! let header = LongHeader::new(sender_key, recipient_key, network_id);
//! ```
//!
//! ## Security
//!
//! The module includes cryptographic utilities for message authentication and encryption,
//! ensuring secure communication between peers in the Netsody network.

mod ack;
mod app;
mod arming;
mod endpoints;
mod error;
mod hello;
mod long_header;
mod short_header;
mod unite;

pub use arming::*;
pub use error::*;

pub use ack::*;
pub use app::*;
pub use endpoints::*;
pub use hello::*;
pub use long_header::*;
pub use unite::*;

pub use short_header::*;
