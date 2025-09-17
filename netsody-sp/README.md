# netsody-sp

**netsody-sp** is the super peer component of Netsody, enabling fast and secure communication between nodes. The super peer assists with hole punching and can act as a relay when P2P connections cannot be established. In restricted environments (e.g., blocked UDP or port restrictions), a TCP fallback can be bound to well-known ports such as 80 or 443.

Multiple super peers can be operated in parallel to improve availability and scalability. Nodes automatically select the nearest super peer, resulting in balanced load, lower latency, and faster peer-to-peer connection setup.

## Development

### Building

To build the super peer with Prometheus metrics support:

```bash
# From the repository root
cargo build --package netsody-sp --features prometheus
```

This will create a binary that can be used to run a super peer node. The Prometheus feature enables detailed monitoring of the super peer's performance and network statistics.

### Configuration

The super peer can be configured using environment variables. See `src/main.rs` for the complete list of available options. Here are some common configuration variables:

```bash
# Network configuration
NETSODY_UDP_PORT=22527        # UDP port to listen on
NETSODY_TCP_PORT=8443         # TCP port to listen on
NETSODY_NETWORK_ID=1          # Network identifier

# Identity configuration
NETSODY_IDENTITY_FILE=sp.identity  # Path to the identity file
NETSODY_POW_DIFFICULTY=24     # Minimum proof of work difficulty

# Prometheus configuration
NETSODY_PROMETHEUS_PORT=9090  # Port for Prometheus metrics
```

These variables can be set before starting the super peer to customize its behavior.