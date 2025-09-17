# Building netsody-agent for Android

This document describes how to build the `netsody-agent` for the Android platform.

## Prerequisites

Install required Rust targets and tools:

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
cargo install cargo-ndk
```

Ensure you have the Android NDK installed. The build script expects it at:
```bash
$HOME/Library/Android/sdk/ndk/29.0.13846066
```

## Building Android Libraries

The following command builds the `netsody-agent` libraries for all Android architectures. The libraries are built as static libraries (`.a` files) and organized by target architecture.

```bash
./netsody-agent/build-android.sh
```

### Build Options

- **Debug build (default):**
  ```bash
  ./netsody-agent/build-android.sh
  ```

- **Release build:**
  ```bash
  ./netsody-agent/build-android.sh --release
  ```

- **Specific architectures:**
  ```bash
  ./netsody-agent/build-android.sh --target arm64-v8a x86_64
  ```

- **Release build for specific architectures:**
  ```bash
  ./netsody-agent/build-android.sh --release --target arm64-v8a
  ```

### Available Architectures

- `arm64-v8a` (aarch64-linux-android) - ARM 64-bit
- `armeabi-v7a` (armv7-linux-androideabi) - ARM 32-bit
- `x86` (i686-linux-android) - Intel 32-bit
- `x86_64` (x86_64-linux-android) - Intel 64-bit

## Output

The built libraries are organized in `target/netsody-agent-android/` with the following structure:

```
target/netsody-agent-android/
├── arm64-v8a/
│   └── libnetsody_agent.a
├── armeabi-v7a/
│   └── libnetsody_agent.a
├── x86/
│   └── libnetsody_agent.a
└── x86_64/
    └── libnetsody_agent.a
```