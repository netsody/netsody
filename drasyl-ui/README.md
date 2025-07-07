# drasyl-ui

**drasyl-ui** is a lightweight desktop client for the locally running [drasyl-sdn](../drasyl-sdn) node. It provides a system tray interface that allows you to monitor and control your drasyl node.

## Development

### Building

To build the desktop client:

```bash
# From the repository root
cargo build --package drasyl-ui --release
```

For macOS, you can also use the provided build script to bundle the binary in an .app:

```bash
# From the drasyl-ui directory
./bundle-macos.sh
```

For debian-based systems, you can use the provided build script to bundle the binary in a .deb package:

```bash
# From the drasyl-ui directory
./bundle-debian.sh
```

### Running

To run the desktop client:

```bash
# From the repository root
cargo run --package drasyl-ui
```

The application will start and appear in your system tray. It will automatically attempt to connect to the local drasyl-sdn service running on the default port (22527).