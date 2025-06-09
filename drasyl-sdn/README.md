# drasyl-sdn

**drasyl-sdn** is a lightweight library for creating secure, software-defined overlay networks on top of drasyl. It supports both centralized and distributed control planes. The library provides membership management through authentication and enables fine-grained access control between nodes. Nodes can be configured as gateways to provide access to external networks via the overlay. Both centralized and distributed control plane architectures are supported. Built on top of the [drasyl](../drasyl) library, all communication is encrypted and routed via the most local physical path available, bypassing typical network barriers such as NATs and stateful firewalls.

## Development

### Building

To build the SDN node with Prometheus metrics and DNS support:

```bash
# From the repository root
cargo build --package drasyl-sdn --release --features "prometheus dns"
```

This will create a release binary that can be used to run an SDN node. The Prometheus feature enables detailed monitoring of the node's performance and network statistics. The DNS feature allows nodes to be addressed by hostnames (e.g., `$hostname` or `$hostname.drasyl.network`). Note that DNS support is only available on macOS and Linux.

### Configuration

The SDN node can be configured using environment variables. See `src/main.rs` for the complete list of available options. Here are some common configuration variables:

```bash
# Network configuration
DRASYL_NETWORK_ID=1          # Network identifier
DRASYL_CONFIG_URL=file:///path/to/config.toml  # Path to the configuration file

# Identity configuration
DRASYL_IDENTITY_FILE=sdn.identity  # Path to the identity file
DRASYL_POW_DIFFICULTY=24     # Minimum proof of work difficulty

# Prometheus configuration
DRASYL_PROMETHEUS_PORT=9090  # Port for Prometheus metrics
```

These variables can be set before starting the node to customize its behavior.

The SDN node requires a TOML configuration file that defines the network topology and policies. The configuration can be provided either as a local file or via HTTP for centralized control.

Example configuration structure:
```toml
# Network configuration using Carrier-Grade NAT address space
network = "100.64.0.0/24"  # /24 subnet for our company network

# Node definitions
[[node]]
pk       = "9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2d1e0f9e8d7"
ip       = "100.64.0.4"
hostname = "alice"
groups   = ["dev-team"]

[[node]]
pk       = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
ip       = "100.64.0.5"
hostname = "bob"
groups   = ["marketing-team"]

[[node]]
pk       = "8f7e6d5c4b3a2d1e0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2d1e0f9e8d7c"
ip       = "100.64.0.2"
hostname = "git-server"
groups   = ["dev-infra"]

[[node]]
pk       = "6edb9d3aba7747c1f9d5cbbb2e7ce0b62ebb91a264908f7db1795ad5c56b8a56"
ip       = "100.64.0.3"
hostname = "cms-server"
groups   = ["marketing-infra"]

# Route to legacy hardware network (omitted gateway node entry for brevity)
[[route]]
dest   = "192.168.100.0/24"  # Legacy hardware network
gw     = "6edb9d3aba7747c1f9d5cbbb2e7ce0b62ebb91a264908f7db1795ad5c56b8a56"  # Gateway node's public key
groups = ["marketing-team"]  # Only marketing team can access legacy hardware

# Access control policies
[[policy]]
source_groups      = ["dev-team"]
destination_groups = ["dev-infra"]  # Dev team can access dev infrastructure

[[policy]]
source_groups      = ["marketing-team"]
destination_groups = ["marketing-infra"]  # Marketing team can access marketing infrastructure

[[policy]]
source_groups      = ["dev-team", "marketing-team"]
destination_groups = ["dev-team", "marketing-team"]  # Teams can communicate with each other
```

This example showcases a network for a small startup with a development and marketing team and their corresponding services:
- The dev team has access to the dev infrastructure
- The marketing team has access to the marketing infrastructure
- Both teams can communicate with each other to coordinate their work
- Each team has access only to their required infrastructure
- The marketing team can access legacy hardware through a gateway node

### Gateway Configuration

To enable routing on the gateway node, the following steps are required:

1. Enable IP forwarding:
   ```bash
   # Edit /etc/sysctl.conf to uncomment net.ipv4.ip_forward
   # This enables forwarding at boot
   
   # To enable it immediately
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

2. Configure iptables:
   ```bash
   # Set interface names (adjust these to match your system)
   PHY_IFACE=eth0
   DRASYL_IFACE=drasyl230whb89k
   
   # Add NAT and forwarding rules
   sudo iptables -t nat -A POSTROUTING -o $PHY_IFACE -j MASQUERADE
   sudo iptables -A FORWARD -i $PHY_IFACE -o $DRASYL_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
   sudo iptables -A FORWARD -i $DRASYL_IFACE -o $PHY_IFACE -j ACCEPT
   
   # Save rules for persistence across reboots
   sudo apt install iptables-persistent
   sudo bash -c iptables-save > /etc/iptables/rules.v4
   ```

## Running SDN Node as a Service

To ensure your SDN node runs automatically on system startup, follow the instructions for your operating system below. 

### macOS (LaunchDaemon)

The following configuration assumes that `target/release/drasyl` has been moved to `/usr/local/bin/drasyl`.

1. **Create the LaunchDaemon configuration file**  
   This file tells macOS to start the SDN node automatically at boot.
   ```bash
   sudo tee /Library/LaunchDaemons/drasyl.plist > /dev/null <<EOF
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>drasyl</string>
       <key>UserName</key>
       <string>root</string>
       <key>ProgramArguments</key>
       <array>
           <string>/usr/local/bin/drasyl</string>
           <string>run</string>
           <string>NETWORK_URL1</string>
           <string>NETWORK_URL2</string>
           <string>...</string>
       </array>
       <key>WorkingDirectory</key>
       <string>/etc/drasyl/</string>
       <key>StandardOutPath</key>
       <string>/var/log/drasyl.out.log</string>
       <key>StandardErrorPath</key>
       <string>/var/log/drasyl.err.log</string>
       <key>KeepAlive</key>
       <true/>
       <key>EnvironmentVariables</key>
       <dict>
           <key>RUST_LOG</key>
           <string>debug</string>
           <key>RUST_BACKTRACE</key>
           <string>full</string>
           <key>DRASYL_IDENTITY_FILE</key>
           <string>drasyl.identity</string>
       </dict>
   </dict>
   </plist>
   EOF
   ```

2. **Create the working directory for drasyl**  
   This directory is used for configuration and identity files.
   ```bash
   sudo mkdir /etc/drasyl/
   sudo chmod 600 /etc/drasyl/
   ```

3. **Load and start the service**  
   This command enables the service and ensures it starts on boot.
   ```bash
   sudo launchctl load /Library/LaunchDaemons/drasyl.plist
   ```

---

### Linux (systemd)

1. **Create the systemd service file**  
   This file defines how the SDN node is started as a service.
   ```bash
   sudo cat <<EOF > /etc/systemd/system/drasyl.service
   [Unit]
   Description=drasyl
   After=network-online.target network.target
   Wants=network-online.target

   [Service]
   ExecStart=/usr/local/sbin/drasyl run NETWORK_URL1 NETWORK_URL2
   Restart=always
   KillMode=process
   WorkingDirectory=/etc/drasyl/
   Environment=RUST_LOG=info
   Environment=RUST_BACKTRACE=full
   Environment=DRASYL_IDENTITY_FILE=drasyl.identity
   Environment=DRASYL_UDP_SOCKETS=1
   Environment=DRASYL_C2D_THREADS=1
   Environment=DRASYL_D2C_THREADS=1
   Environment=DRASYL_TUN_THREADS=1

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

2. **Create the working directory for drasyl**  
   This directory is used for configuration and identity files.
   ```bash
   sudo mkdir /etc/drasyl/
   sudo chmod 600 /etc/drasyl/
   ```

3. **Enable and start the service**  
   This command enables the service and ensures it starts on boot.
   ```bash
   sudo systemctl enable drasyl
   sudo systemctl start drasyl
   ```

## Accessing REST API

The SDN node provides a REST API accessible at `http://127.0.0.1:22527`. The API is protected by a bearer authentication token, which is stored in the working directory as `auth.token` and is only readable by the root user.

You can access the API using curl:
```bash
curl -H "Authorization: Bearer $(sudo cat /etc/drasyl/auth.token)" http://localhost:22527/status
```

The CLI can also interact with the API and format the output nicely:
```bash
sudo -E DRASYL_AUTH_FILE=/etc/drasyl/auth.token drasyl status
```

To avoid running `drasyl status` with elevated privileges every time, you can store the token in `~/.drasyl/auth.token`. After doing this, you can simply use:
```bash
drasyl status
```