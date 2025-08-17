# drasyl-agent

**drasyl-agent** is the agent component of drasyl that connects a device to one or more drasyl overlay networks. Once started and pointed to a configuration source, the agent continuously monitors the network configuration and autonomously aligns the system with the desired state.


## Development

### Building

To build the agent with Prometheus metrics and DNS support:

```bash
# From the repository root
cargo build --package drasyl-agent --release --features "prometheus dns"
```

This will create a release binary that can be used to run the agent. The Prometheus feature enables detailed monitoring of the agent's performance and network statistics. The DNS feature allows nodes to be addressed by hostnames (e.g., `$hostname` or `$hostname.drasyl.network`). Note that DNS support is only available on macOS and Linux.

### Docker Build

To build multi-platform Docker images for the agent:

```bash
# Build and push multi-platform images (amd64 and arm64)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t drasyl/drasyl-agent:0.1.0 \
  -t drasyl/drasyl-agent:latest \
  -f ./drasyl-agent/Dockerfile \
  --push .
```

This command builds Docker images for both AMD64 and ARM64 architectures and pushes them to the Docker registry with the specified tags.