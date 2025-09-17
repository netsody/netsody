#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
if [[ "$1" == "--release" ]]; then
    BUILD_TYPE="release"
fi

# Determine architecture
ARCH=$(uname -m)

APP_NAME="Netsody UI"
CLI_NAME="netsody"
PLIST_SRC="${WORKSPACE_DIR}/resources/netsody.plist"
BINARY_NAME="netsody"
VERSION="0.1.0"
IDENTIFIER="io.netsody.netsody-ui"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_ROOT="${WORKSPACE_DIR}/target/${BUILD_TYPE}"
TARGET_DIR="${TARGET_ROOT}"
APP_DIR="${TARGET_DIR}/${APP_NAME}.app"
MACOS_DIR="${APP_DIR}/Contents/MacOS"
RES_DIR="${APP_DIR}/Contents/Resources"
ICON_SRC="${WORKSPACE_DIR}/netsody-ui/resources/app-icon.icns"
ICON_DST="${RES_DIR}/icon.icns"

echo "🔨 Using ${BUILD_TYPE} build from ${TARGET_ROOT}"

# Stage installer contents
PKG_ROOT="${TARGET_DIR}/pkgroot"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/Applications"
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"

echo "🚚 Staging CLI binary..."
cp "${TARGET_ROOT}/${CLI_NAME}" "$PKG_ROOT/usr/local/bin/${CLI_NAME}"
chmod 755 "$PKG_ROOT/usr/local/bin/${CLI_NAME}"

echo "📄 Creating LaunchDaemon plist..."
cat > "$PKG_ROOT/Library/LaunchDaemons/netsody.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>netsody</string>
    <key>UserName</key>
    <string>root</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/netsody</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/etc/netsody/</string>
    <key>StandardOutPath</key>
    <string>/var/log/netsody.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/netsody.err.log</string>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# If you're wondering as a developer why your Netsody UI.app isn't updated, check this source: https://apple.stackexchange.com/a/219144
echo "🚚 Staging Netsody UI.app..."
cp -R "${TARGET_DIR}/${APP_NAME}.app" "$PKG_ROOT/Applications/"

# Create preinstall script to stop existing service
SCRIPTS_DIR="${TARGET_DIR}/scripts"
rm -rf "$SCRIPTS_DIR"
mkdir -p "$SCRIPTS_DIR"
cat > "${SCRIPTS_DIR}/preinstall" <<'EOF'
#!/bin/bash

# Redirect all output to log file
{
  echo "$(date): Starting Netsody preinstall script"

  # Check if the service 'netsody' is loaded
  if launchctl list netsody >/dev/null 2>&1; then
    echo "Service 'netsody' is running. Stopping service..."
    launchctl unload /Library/LaunchDaemons/netsody.plist
    echo "Service stopped."
  else
    echo "Service 'netsody' is not running."
  fi

  echo "$(date): Netsody preinstall script completed"
} > /var/log/netsody.preinstall.log 2>&1
EOF
chmod +x "${SCRIPTS_DIR}/preinstall"

# Create postinstall script to load daemon
cat > "${SCRIPTS_DIR}/postinstall" <<'EOF'
#!/bin/bash

# Redirect all output to log file
{
  echo "$(date): Starting Netsody postinstall script"

  # Determine current GUI user
  CURRENT_USER=$(stat -f%Su /dev/console)
  HOME_DIR=$(eval echo "~$CURRENT_USER")

  USER_TOKEN_FILE="$HOME_DIR/.netsody/auth.token"

  # Determine or generate shared auth token
  if [ ! -f "/etc/netsody/auth.token" ]; then
    echo "🔐 Generating auth token..."
    mkdir -p /etc/netsody
    chmod 600 /etc/netsody
    TOKEN=$(/usr/bin/openssl rand -base64 18)
    echo "$TOKEN" > /etc/netsody/auth.token
    chmod 600 /etc/netsody/auth.token
  else
    TOKEN=$(cat /etc/netsody/auth.token)
  fi

  # Write user token if missing, using shared token
  if [ ! -f "$USER_TOKEN_FILE" ]; then
    echo "🔐 Writing user auth token for $CURRENT_USER..."
    mkdir -p "$(dirname "$USER_TOKEN_FILE")"
    chown "$CURRENT_USER":staff "$(dirname "$USER_TOKEN_FILE")"
    echo "$TOKEN" > "$USER_TOKEN_FILE"
    chown "$CURRENT_USER":staff "$USER_TOKEN_FILE"
    chmod 600 "$USER_TOKEN_FILE"
  fi

  # Load the LaunchDaemon
  echo "Loading LaunchDaemon..."
  /bin/launchctl load /Library/LaunchDaemons/netsody.plist

  echo "$(date): Netsody postinstall script completed"
} > /var/log/netsody.postinstall.log 2>&1
EOF
chmod +x "${SCRIPTS_DIR}/postinstall"

# Build installer package
echo "📦 Building installer package..."
pkgbuild \
  --root "$PKG_ROOT" \
  --scripts "$SCRIPTS_DIR" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  "${TARGET_DIR}/Netsody_${VERSION}_macos_${ARCH}.pkg"
echo "✅ Installer package created at ${TARGET_DIR}/Netsody_${VERSION}_macos_${ARCH}.pkg"