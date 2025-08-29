#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
if [[ "$1" == "--release" ]]; then
    BUILD_TYPE="release"
fi

# Configuration
TARGET_DEVICE="aarch64-apple-ios"
TARGET_SIMULATOR="aarch64-apple-ios-sim"
IPHONEOS_DEPLOYMENT_TARGET="13.0"
FRAMEWORK_NAME="DrasylAgent"
CRATE_NAME="drasyl-agent"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_DIR="${WORKSPACE_DIR}/target"
FRAMEWORK_OUTPUT_DIR="${TARGET_DIR}/${BUILD_TYPE}"
INCLUDE_DIR="${FRAMEWORK_OUTPUT_DIR}/include"

echo "🍎 Building drasyl-agent XCFramework for iOS..."
echo "📁 Workspace directory: ${WORKSPACE_DIR}"
echo "📁 Target directory: ${TARGET_DIR}"
echo "🔧 Build type: ${BUILD_TYPE}"

# Set deployment target
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET}"
echo "📱 iOS deployment target: ${IPHONEOS_DEPLOYMENT_TARGET}"

echo "🚀 Building for iOS device (${TARGET_DEVICE})..."
if [[ "${BUILD_TYPE}" == "release" ]]; then
    cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_DEVICE}" --release
else
    cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_DEVICE}"
fi

echo "🚀 Building for iOS simulator (${TARGET_SIMULATOR})..."
if [[ "${BUILD_TYPE}" == "release" ]]; then
    cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_SIMULATOR}" --release
else
    cargo build --package "${CRATE_NAME}" --lib --features dns,ffi --target "${TARGET_SIMULATOR}"
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
