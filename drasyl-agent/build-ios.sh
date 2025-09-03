#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
BUILD_TVOS=false

for arg in "$@"; do
    case $arg in
        --release)
            BUILD_TYPE="release"
            ;;
        --tvos)
            BUILD_TVOS=true
            ;;
    esac
done

# Configuration
if [[ "${BUILD_TVOS}" == true ]]; then
    TARGET_DEVICE="aarch64-apple-tvos"
    TARGET_SIMULATOR="aarch64-apple-tvos-sim"
    DEPLOYMENT_TARGET="13.0"
    DEPLOYMENT_VAR="TVOS_DEPLOYMENT_TARGET"
    PLATFORM_NAME="tvOS"
else
    TARGET_DEVICE="aarch64-apple-ios"
    TARGET_SIMULATOR="aarch64-apple-ios-sim"
    DEPLOYMENT_TARGET="13.0"
    DEPLOYMENT_VAR="IPHONEOS_DEPLOYMENT_TARGET"
    PLATFORM_NAME="iOS"
fi
FRAMEWORK_NAME="DrasylAgent"
CRATE_NAME="drasyl-agent"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_DIR="${WORKSPACE_DIR}/target"
FRAMEWORK_OUTPUT_DIR="${TARGET_DIR}/${BUILD_TYPE}"
INCLUDE_DIR="${FRAMEWORK_OUTPUT_DIR}/include"

echo "🍎 Building drasyl-agent XCFramework for ${PLATFORM_NAME}..."
echo "📁 Workspace directory: ${WORKSPACE_DIR}"
echo "📁 Target directory: ${TARGET_DIR}"
echo "🔧 Build type: ${BUILD_TYPE}"

# Set deployment target
export ${DEPLOYMENT_VAR}="${DEPLOYMENT_TARGET}"
echo "📱 ${PLATFORM_NAME} deployment target: ${DEPLOYMENT_TARGET}"

echo "🚀 Building for ${PLATFORM_NAME} device (${TARGET_DEVICE})..."
if [[ "${BUILD_TVOS}" == true ]]; then
    if [[ "${BUILD_TYPE}" == "release" ]]; then
        cargo +nightly build -Z build-std=std,panic_abort --package "${CRATE_NAME}" --features ffi,dns --target "${TARGET_DEVICE}" --release
    else
        cargo +nightly build -Z build-std=std,panic_abort --package "${CRATE_NAME}" --features ffi,dns --target "${TARGET_DEVICE}"
    fi
else
    if [[ "${BUILD_TYPE}" == "release" ]]; then
        cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_DEVICE}" --release
    else
        cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_DEVICE}"
    fi
fi

echo "🚀 Building for ${PLATFORM_NAME} simulator (${TARGET_SIMULATOR})..."
if [[ "${BUILD_TVOS}" == true ]]; then
    if [[ "${BUILD_TYPE}" == "release" ]]; then
        cargo +nightly build -Z build-std=std,panic_abort --package "${CRATE_NAME}" --features ffi,dns --target "${TARGET_SIMULATOR}" --release
    else
        cargo +nightly build -Z build-std=std,panic_abort --package "${CRATE_NAME}" --features ffi,dns --target "${TARGET_SIMULATOR}"
    fi
else
    if [[ "${BUILD_TYPE}" == "release" ]]; then
        cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_SIMULATOR}" --release
    else
        cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_SIMULATOR}"
    fi
fi

echo "📁 Creating include directory..."
mkdir -p "${INCLUDE_DIR}"

echo "🔧 Generating C header file..."
cbindgen --config "${WORKSPACE_DIR}/drasyl-agent/ios/cbindgen.toml" \
         --crate "${CRATE_NAME}" \
         --output "${INCLUDE_DIR}/drasyl_agent.h"

echo "📄 Copying module map..."
cp "${WORKSPACE_DIR}/drasyl-agent/ios/module.modulemap" "${INCLUDE_DIR}/"

echo "🧹 Cleaning up existing framework..."
rm -rf "${FRAMEWORK_OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"

echo "🏗️  Creating XCFramework..."
xcodebuild -create-xcframework \
  -library "${TARGET_DIR}/${TARGET_DEVICE}/${BUILD_TYPE}/libdrasyl_agent.a" \
  -headers "${INCLUDE_DIR}" \
  -library "${TARGET_DIR}/${TARGET_SIMULATOR}/${BUILD_TYPE}/libdrasyl_agent.a" \
  -headers "${INCLUDE_DIR}" \
  -output "${FRAMEWORK_OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"

echo "✅ XCFramework created successfully!"
echo "📁 Framework location: ${FRAMEWORK_OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"
echo "📁 Include files: ${INCLUDE_DIR}"
echo "📁 Device library: ${TARGET_DIR}/${TARGET_DEVICE}/${BUILD_TYPE}/libdrasyl_agent.a"
echo "📁 Simulator library: ${TARGET_DIR}/${TARGET_SIMULATOR}/${BUILD_TYPE}/libdrasyl_agent.a"
