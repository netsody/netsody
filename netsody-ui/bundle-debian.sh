#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
if [[ "$1" == "--release" ]]; then
    BUILD_TYPE="release"
fi

APP_NAME="Netsody UI"
BINARY_NAME="netsody-ui"
VERSION="0.1.0"
ARCH="$(dpkg --print-architecture)"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_ROOT="${WORKSPACE_DIR}/target/${BUILD_TYPE}"
TARGET_DIR="${TARGET_ROOT}"
PKG_DIR="${TARGET_DIR}/${BINARY_NAME}_${VERSION}"
DEBIAN_DIR="${PKG_DIR}/DEBIAN"
BIN_DIR="${PKG_DIR}/usr/bin"
APP_DIR="${PKG_DIR}/usr/share/applications"
ICON_DIR="${PKG_DIR}/usr/share/pixmaps"

ICON_SRC="${WORKSPACE_DIR}/netsody-ui/resources/app-icon.png"
DESKTOP_FILE_SRC="${WORKSPACE_DIR}/netsody-ui/resources/netsody-ui.desktop"

echo "📁 Ensuring target directory exists..."
mkdir -p "$TARGET_DIR"

echo "📁 Creating package structure..."
rm -rf "$PKG_DIR"
mkdir -p "$DEBIAN_DIR" "$BIN_DIR" "$APP_DIR" "$ICON_DIR"

echo "🚚 Copying netsody-ui binary..."
cp "${TARGET_ROOT}/${BINARY_NAME}" "${BIN_DIR}/"
chmod 755 "${BIN_DIR}/${BINARY_NAME}"

echo "🎨 Copying app icon..."
cp "$ICON_SRC" "${ICON_DIR}/netsody-ui.png"

echo "📝 Copying .desktop file..."
cp "$DESKTOP_FILE_SRC" "${APP_DIR}/"

echo "📝 Creating control file..."
cat > "${DEBIAN_DIR}/control" <<EOF
Package: ${BINARY_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Homepage: https://netsody.io
Depends: libxdo3
Maintainer: Netsody Team <info@netsody.io>
Description: Netsody provides secure, software-defined overlay networks, connecting all your devices.
EOF

echo "📦 Building .deb package..."
dpkg-deb -Zgzip --build "${PKG_DIR}"

DEB_NAME="${BINARY_NAME}_${VERSION}_${ARCH}.deb"
mv "${PKG_DIR}.deb" "${TARGET_DIR}/${DEB_NAME}"

echo "✅ Package created at ${TARGET_DIR}/${DEB_NAME}"