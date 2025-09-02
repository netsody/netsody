# Building drasyl-agent for iOS

This document describes how to build the `drasyl-agent` for the iOS platform.

## Prerequisites

Install required Rust targets and tools:

```bash
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
```

## Building DrasylAgent.xcframework

The following command builds the `DrasylAgent.xcframework` which provides a unified binary for both iOS device and simulator architectures. This framework can be directly integrated into Xcode projects.

```bash
./drasyl-agent/build-ios.sh
```

### Build Options

- **Debug build (default):**
  ```bash
  ./drasyl-agent/build-ios.sh
  ```

- **Release build:**
  ```bash
  ./drasyl-agent/build-ios.sh --release
  ```

## Experimental tvOS Support

Build for tvOS (requires nightly Rust):

```bash
cargo +nightly build -Z build-std=std,panic_abort --package drasyl-agent --features ffi --target aarch64-apple-tvos --release
```

