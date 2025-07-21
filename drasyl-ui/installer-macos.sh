#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
if [[ "$1" == "--release" ]]; then
    BUILD_TYPE="release"
fi

# Determine architecture
ARCH=$(uname -m)

APP_NAME="drasyl UI"
CLI_NAME="drasyl"
PLIST_SRC="${WORKSPACE_DIR}/resources/drasyl.plist"
BINARY_NAME="drasyl"
VERSION="0.1.0"
IDENTIFIER="org.drasyl.drasyl-ui"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_ROOT="${WORKSPACE_DIR}/target/${BUILD_TYPE}"
TARGET_DIR="${TARGET_ROOT}"
APP_DIR="${TARGET_DIR}/${APP_NAME}.app"
MACOS_DIR="${APP_DIR}/Contents/MacOS"
RES_DIR="${APP_DIR}/Contents/Resources"
ICON_SRC="${WORKSPACE_DIR}/drasyl-ui/resources/app-icon.icns"
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
cat > "$PKG_ROOT/Library/LaunchDaemons/drasyl.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>drasyl</string>
    <key>UserName</key>
    <string>root</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/drasyl</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/etc/drasyl/</string>
    <key>StandardOutPath</key>
    <string>/var/log/drasyl.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/drasyl.err.log</string>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
        <key>RUST_BACKTRACE</key>
        <string>full</string>
        <key>DRASYL_IDENTITY_FILE</key>
        <string>drasyl.identity</string>
    </dict>
</dict>
</plist>
EOF

# If you're wondering as a developer why your drasyl UI.app isn't updated, check this source: https://apple.stackexchange.com/a/219144
echo "🚚 Staging drasyl UI.app..."
cp -R "${TARGET_DIR}/${APP_NAME}.app" "$PKG_ROOT/Applications/"

# Create preinstall script to stop existing service
SCRIPTS_DIR="${TARGET_DIR}/scripts"
rm -rf "$SCRIPTS_DIR"
mkdir -p "$SCRIPTS_DIR"
cat > "${SCRIPTS_DIR}/preinstall" <<'EOF'
#!/bin/bash

# Redirect all output to log file
{
  echo "$(date): Starting drasyl preinstall script"

  # Check if the service 'drasyl' is loaded
  if launchctl list drasyl >/dev/null 2>&1; then
    echo "Service 'drasyl' is running. Stopping service..."
    launchctl unload /Library/LaunchDaemons/drasyl.plist
    echo "Service stopped."
  else
    echo "Service 'drasyl' is not running."
  fi

  echo "$(date): drasyl preinstall script completed"
} > /var/log/drasyl.preinstall.log 2>&1
EOF
chmod +x "${SCRIPTS_DIR}/preinstall"

# Create postinstall script to load daemon
cat > "${SCRIPTS_DIR}/postinstall" <<'EOF'
#!/bin/bash

# Redirect all output to log file
{
  echo "$(date): Starting drasyl postinstall script"

  # Determine current GUI user
  CURRENT_USER=$(stat -f%Su /dev/console)
  HOME_DIR=$(eval echo "~$CURRENT_USER")

  USER_TOKEN_FILE="$HOME_DIR/.drasyl/auth.token"

  # Determine or generate shared auth token
  if [ ! -f "/etc/drasyl/auth.token" ]; then
    echo "🔐 Generating auth token..."
    TOKEN=$(/usr/bin/openssl rand -base64 18)
    echo "$TOKEN" > /etc/drasyl/auth.token
    chmod 600 /etc/drasyl/auth.token
  else
    TOKEN=$(cat /etc/drasyl/auth.token)
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
  /bin/launchctl load /Library/LaunchDaemons/drasyl.plist

  echo "$(date): drasyl postinstall script completed"
} > /var/log/drasyl.postinstall.log 2>&1
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
  "${TARGET_DIR}/drasyl_${VERSION}_macos_${ARCH}.pkg"
echo "✅ Installer package created at ${TARGET_DIR}/drasyl_${VERSION}_macos_${ARCH}.pkg"