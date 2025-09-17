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

```bash
cargo +nightly build -Z build-std=std,panic_abort --package netsody-agent --features ffi --target aarch64-apple-tvos --release
```

