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
export IPHONEOS_DEPLOYMENT_TARGET=13.0
cargo build --package drasyl-agent --features ffi --target aarch64-apple-ios --release && \
cargo build --package drasyl-agent --features ffi --target aarch64-apple-ios-sim --release && \
mkdir -p target/drasyl-agent-ios/include && \
cbindgen --config drasyl-agent/ios/cbindgen.toml \
         --crate drasyl-agent \
         --output target/drasyl-agent-ios/include/drasyl_agent.h && \
rm -rf target/drasyl-agent-apple/DrasylAgent.xcframework && \
cp drasyl-agent/apple/module.modulemap target/drasyl-agent-ios/include/module.modulemap && \
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libdrasyl_agent.a \
  -headers target/drasyl-agent-ios/include \
  -library target/aarch64-apple-ios-sim/release/libdrasyl_agent.a \
  -headers target/drasyl-agent-ios/include \
  -output target/drasyl-agent-apple/DrasylAgent.xcframework
```

## Experimental tvOS Support

Build for tvOS (requires nightly Rust):

```bash
cargo +nightly build -Z build-std=std,panic_abort --package drasyl-agent --features ffi --target aarch64-apple-tvos --release
```

