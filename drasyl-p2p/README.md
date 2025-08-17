# drasyl-p2p

**drasyl-p2p** is a lightweight library for establishing direct, secure peer-to-peer connections in minimal time. Each peer is identified by a public key, enabling location-transparent communication across the network. Typical network barriers such as NATs and stateful firewalls are bypassed automatically. This is achieved through a custom protocol that combines multiple NAT traversal techniques with a modern cryptographic handshake. All communication is secured using [AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/), a high-performance authenticated encryption algorithm designed for strong security—even without hardware acceleration.

## Development

### Building Documentation

To build and view the API documentation locally:

```bash
# From the repository root
cargo doc --package drasyl-p2p --open --no-deps
```

This will generate the documentation and open it in your default web browser.

### Running Examples

To run the example node:

```bash
# From the repository root
cargo run --package drasyl-p2p --example node
```

This will start a drasyl node with default configuration. The node will automatically generate an identity if none exists and begin participating in the network. You can use this example to send and receive text messages with other peers in the network. The node will display its public key on startup, which you can use to establish connections with other nodes.

The example node can be configured using environment variables. See `examples/node.rs` for the complete list of available options. Here are some common configuration variables:

```bash
# Network configuration
DRASYL_UDP_PORT=22527        # UDP port to listen on
DRASYL_TCP_PORT=8443         # TCP port to listen on
DRASYL_NETWORK_ID=1          # Network identifier

# Identity configuration
DRASYL_IDENTITY_FILE=node.identity  # Path to the identity file
DRASYL_POW_DIFFICULTY=24     # Minimum proof of work difficulty
```

These variables can be set before starting the node to customize its behavior.