#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
if [[ "$1" == "--release" ]]; then
    BUILD_TYPE="release"
fi

APP_NAME="drasyl UI"
BINARY_NAME="drasyl-ui"
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

ICON_SRC="${WORKSPACE_DIR}/drasyl-ui/resources/app-icon.png"
DESKTOP_FILE_SRC="${WORKSPACE_DIR}/drasyl-ui/resources/drasyl-ui.desktop"

echo "📁 Ensuring target directory exists..."
mkdir -p "$TARGET_DIR"

echo "📁 Creating package structure..."
rm -rf "$PKG_DIR"
mkdir -p "$DEBIAN_DIR" "$BIN_DIR" "$APP_DIR" "$ICON_DIR"

echo "🚚 Copying drasyl-ui binary..."
cp "${TARGET_ROOT}/${BINARY_NAME}" "${BIN_DIR}/"
chmod 755 "${BIN_DIR}/${BINARY_NAME}"

echo "🎨 Copying app icon..."
cp "$ICON_SRC" "${ICON_DIR}/drasyl-ui.png"

echo "📝 Copying .desktop file..."
cp "$DESKTOP_FILE_SRC" "${APP_DIR}/"

echo "📝 Creating control file..."
cat > "${DEBIAN_DIR}/control" <<EOF
Package: ${BINARY_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: libxdo3
Maintainer: drasyl Team <info@drasyl.org>
Description: drasyl provides secure, software-defined overlay networks, connecting all your devices.
EOF

echo "📦 Building .deb package..."
dpkg-deb --build "${PKG_DIR}"

DEB_NAME="${BINARY_NAME}_${VERSION}_${ARCH}.deb"
mv "${PKG_DIR}.deb" "${TARGET_DIR}/${DEB_NAME}"

echo "✅ Package created at ${TARGET_DIR}/${DEB_NAME}"