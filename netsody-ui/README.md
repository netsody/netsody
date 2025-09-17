# netsody-ui

**netsody-ui** is a lightweight desktop client for the locally running [netsody-agent](../netsody-agent) node. It provides a system tray interface that allows you to monitor and control your Netsody node.

## Development

### Building

To build the desktop client:

```bash
# From the repository root
cargo build --package netsody-ui --release
```

For macOS, you can also use the provided build script to bundle the binary in an .app:

```bash
# From the netsody-ui directory
./bundle-macos.sh
```

For debian-based systems, you can use the provided build script to bundle the binary in a .deb package:

```bash
# From the netsody-ui directory
./bundle-debian.sh
```

### Running

To run the desktop client:

```bash
# From the repository root
cargo run --package netsody-ui
```

The application will start and appear in your system tray. It will automatically attempt to connect to the local netsody-agent service running on the default port (22527).