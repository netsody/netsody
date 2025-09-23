# Building netsody-agent for iOS

This document describes how to build the `netsody-agent` for the iOS platform.

## Prerequisites

Install required Rust targets and tools:

```bash
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
```

## Building NetsodyAgent.xcframework

The following command builds the `NetsodyAgent.xcframework` which provides a unified binary for both iOS device and simulator architectures. This framework can be directly integrated into Xcode projects.

```bash
./netsody-agent/build-ios.sh
```

### Build Options

- **Debug build (default):**
  ```bash
  ./netsody-agent/build-ios.sh
  ```

- **Release build:**
  ```bash
  ./netsody-agent/build-ios.sh --release
  ```

## Experimental tvOS Support

Build for tvOS (requires nightly Rust):

**Important:** On tvOS, the configuration cannot be stored in the filesystem due to platform restrictions. As a proof-of-concept hack, the configuration parameters must be provided as environment variables during the build process. These parameters are then embedded directly into the binary at compile time.

```bash
export DRASYL_SK="XXX"
export DRASYL_POW="XXX"
export DRASYL_NETWORK_URL="https://example.com/network.toml"

./netsody-agent/build-ios.sh --tvos
```

