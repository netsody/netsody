#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
TARGETS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_TYPE="release"
            shift
            ;;
        --target)
            # Clear default targets and collect all specified targets
            TARGETS=()
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do
                TARGETS+=("$1")
                shift
            done
            ;;
        *)
            echo "❌ Unknown parameter: $1"
            echo "Usage: $0 [--release] [--target <target1> <target2> ...]"
            echo "Available targets: arm64-v8a, armeabi-v7a, x86, x86_64"
            exit 1
            ;;
    esac
done

# Configuration
ANDROID_PLATFORM="24"
FRAMEWORK_NAME="DrasylAgent"
CRATE_NAME="drasyl-agent"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_DIR="${WORKSPACE_DIR}/target"
OUTPUT_DIR="${TARGET_DIR}/drasyl-agent-android"

echo "🤖 Building drasyl-agent for Android..."
echo "📁 Workspace directory: ${WORKSPACE_DIR}"
echo "📁 Target directory: ${TARGET_DIR}"
echo "📁 Output directory: ${OUTPUT_DIR}"
echo "🔧 Build type: ${BUILD_TYPE}"
echo "🎯 Targets: ${TARGETS[*]}"
echo "📱 Android platform: ${ANDROID_PLATFORM}"

# Set Android NDK path if not already set
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
    export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/29.0.13846066"
fi

if [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
    echo "❌ Android NDK directory not found: ${ANDROID_NDK_HOME}"
    exit 1
fi

echo "📱 Android NDK: ${ANDROID_NDK_HOME}"

# Set up environment variables for cross-compilation
export CPUPATH="$ANDROID_NDK_HOME/sources/android/cpufeatures"
export CFLAGS_aarch64_linux_android="-I$CPUPATH"
export CFLAGS_armv7_linux_androideabi="-I$CPUPATH"
export CFLAGS_i686_linux_android="-I$CPUPATH"
export CFLAGS_x86_64_linux_android="-I$CPUPATH"

echo "🔧 Environment variables set for cross-compilation"

# Check if cargo-ndk is installed
if ! command -v cargo-ndk &> /dev/null; then
    echo "❌ cargo-ndk is not installed"
    echo "Please install it with: cargo install cargo-ndk"
    exit 1
fi

# Build for specified targets
echo "🚀 Building for Android targets..."
TARGET_ARGS=""
for target in "${TARGETS[@]}"; do
    TARGET_ARGS+="--target $target "
done

if [[ "${BUILD_TYPE}" == "release" ]]; then
    cargo ndk \
        --platform "${ANDROID_PLATFORM}" \
        ${TARGET_ARGS} \
        build --features dns,ffi --release --package "${CRATE_NAME}" --lib
else
    cargo ndk \
        --platform "${ANDROID_PLATFORM}" \
        ${TARGET_ARGS} \
        build --features dns,ffi --package "${CRATE_NAME}" --lib
fi

echo "📁 Creating output directories..."
mkdir -p "${OUTPUT_DIR}"

# C header file generation skipped for Android

echo "📄 Copying built libraries..."
# Map cargo-ndk targets to Rust targets using function
get_rust_target() {
    case "$1" in
        "arm64-v8a") echo "aarch64-linux-android" ;;
        "armeabi-v7a") echo "armv7-linux-androideabi" ;;
        "x86") echo "i686-linux-android" ;;
        "x86_64") echo "x86_64-linux-android" ;;
        *) echo "" ;;
    esac
}

for ndk_target in "${TARGETS[@]}"; do
    rust_target=$(get_rust_target "$ndk_target")
    if [[ -n "$rust_target" ]]; then
        lib_dir="${OUTPUT_DIR}/${ndk_target}"
        mkdir -p "${lib_dir}"
        
        src_lib="${TARGET_DIR}/${rust_target}/${BUILD_TYPE}/libdrasyl_agent.a"
        dst_lib="${lib_dir}/libdrasyl_agent.a"
        
        if [[ -f "$src_lib" ]]; then
            cp "$src_lib" "$dst_lib"
            echo "📁 Copied library for ${ndk_target}: ${dst_lib}"
        else
            echo "⚠️  Library not found for ${ndk_target}: ${src_lib}"
        fi
    fi
done

echo "✅ Android libraries built successfully!"
echo "📁 Output directory: ${OUTPUT_DIR}"
echo "🎯 Built targets:"
for ndk_target in "${TARGETS[@]}"; do
    rust_target=$(get_rust_target "$ndk_target")
    if [[ -n "$rust_target" ]]; then
        lib_path="${TARGET_DIR}/${rust_target}/${BUILD_TYPE}/libdrasyl_agent.a"
        if [[ -f "$lib_path" ]]; then
            echo "  ✅ ${ndk_target} (${rust_target}): ${lib_path}"
        else
            echo "  ❌ ${ndk_target} (${rust_target}): Build failed"
        fi
    fi
done
