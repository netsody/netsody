#!/bin/bash
set -e

APP_NAME="drasyl UI"
BINARY_NAME="drasyl-ui"
VERSION="0.1.0"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_ROOT="${WORKSPACE_DIR}/target/release"
TARGET_DIR="${TARGET_ROOT}"
APP_DIR="${TARGET_DIR}/${APP_NAME}.app"
MACOS_DIR="${APP_DIR}/Contents/MacOS"
RES_DIR="${APP_DIR}/Contents/Resources"
ICON_SRC="${WORKSPACE_DIR}/drasyl-ui/resources/app-icon.icns"
ICON_DST="${RES_DIR}/icon.icns"

echo "📁 Ensuring target directory exists..."
mkdir -p "$TARGET_DIR"

echo "📁 Creating .app bundle structure..."
rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RES_DIR"

echo "🚚 Copying drasyl-ui binary..."
cp "${TARGET_ROOT}/${BINARY_NAME}" "$MACOS_DIR/"
chmod +x "$MACOS_DIR/$BINARY_NAME"

if [[ -f "$ICON_SRC" ]]; then
  echo "🎨 Copying app icon..."
  cp "$ICON_SRC" "$ICON_DST"
else
  echo "⚠️  No icon found at $ICON_SRC – skipping icon"
fi

echo "📝 Creating Info.plist..."
cat > "${APP_DIR}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleExecutable</key>
  <string>${BINARY_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>org.drasyl.drasyl-ui</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleIconFile</key>
  <string>icon.icns</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
EOF

echo "✅ .app bundle created at ${APP_DIR}"