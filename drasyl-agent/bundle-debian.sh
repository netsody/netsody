#!/bin/bash
set -e

# Parse command line arguments
BUILD_TYPE="debug"
if [[ "$1" == "--release" ]]; then
    BUILD_TYPE="release"
fi

BINARY_NAME="drasyl"
VERSION="0.1.0"
ARCH="$(dpkg --print-architecture)"

# Paths
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
TARGET_ROOT="${WORKSPACE_DIR}/target/${BUILD_TYPE}"
TARGET_DIR="${TARGET_ROOT}"
PKG_DIR="${TARGET_DIR}/${BINARY_NAME}_${VERSION}"
DEBIAN_DIR="${PKG_DIR}/DEBIAN"
BIN_DIR="${PKG_DIR}/usr/bin"

echo "📁 Ensuring target directory exists..."
mkdir -p "$TARGET_DIR"

echo "📁 Creating package structure..."
rm -rf "$PKG_DIR"
mkdir -p "$DEBIAN_DIR" "$BIN_DIR"
echo "📁 Creating configuration directory..."
mkdir -p "${PKG_DIR}/etc/drasyl"
chmod 600 "${PKG_DIR}/etc/drasyl"

echo "🚚 Copying drasyl binary..."
cp "${TARGET_ROOT}/${BINARY_NAME}" "${BIN_DIR}/"
chmod 755 "${BIN_DIR}/${BINARY_NAME}"

echo "📝 Creating control file..."
cat > "${DEBIAN_DIR}/control" <<EOF
Package: ${BINARY_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Homepage: https://drasyl.org
Maintainer: drasyl Team <info@drasyl.org>
Description: drasyl provides secure, software-defined overlay networks, connecting all your devices.
EOF

# Create systemd service unit
echo "📄 Creating systemd service unit..."
mkdir -p "${PKG_DIR}/lib/systemd/system"
cat > "${PKG_DIR}/lib/systemd/system/drasyl.service" << 'EOF'
[Unit]
Description=drasyl
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/drasyl run
Restart=always
KillMode=process
WorkingDirectory=/etc/drasyl/
Environment=RUST_BACKTRACE=full
Environment=DRASYL_UDP_SOCKETS=1
Environment=DRASYL_C2D_THREADS=1
Environment=DRASYL_D2C_THREADS=1
Environment=DRASYL_TUN_THREADS=1

[Install]
WantedBy=multi-user.target
EOF

# Add maintainer scripts for systemd
# postinst: enable & start service on install/update
cat > "${DEBIAN_DIR}/postinst" << 'EOF'
#!/bin/sh
set -e

# Always reload systemd daemon and restart service on configure
if [ "$1" = "configure" ]; then
    systemctl daemon-reload
    
    # Check if service is already enabled
    if systemctl is-enabled drasyl.service >/dev/null 2>&1; then
        # Service exists, restart it (for updates)
        systemctl restart drasyl.service || systemctl start drasyl.service
    else
        # First installation, enable and start service
        systemctl enable drasyl.service
        systemctl start drasyl.service
    fi

    # Create auth token only on first installation
    if [ ! -f /etc/drasyl/auth.token ]; then
        mkdir -p /etc/drasyl
        chmod 600 /etc/drasyl
        TOKEN=$(openssl rand -hex 12)
        echo "$TOKEN" > /etc/drasyl/auth.token
        chmod 600 /etc/drasyl/auth.token
    fi

    cat <<-MSG

An API auth token has been created at:
  /etc/drasyl/auth.token

To use drasyl you must copy it into your home directory:
  mkdir -p ~/.drasyl
  su -c "cat /etc/drasyl/auth.token" > ~/.drasyl/auth.token
  chmod 600 ~/.drasyl/auth.token

MSG
fi
EOF
chmod 0755 "${DEBIAN_DIR}/postinst"

# prerm: stop & disable service on remove
cat > "${DEBIAN_DIR}/prerm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
    systemctl stop drasyl.service || true
    systemctl disable drasyl.service || true
fi
EOF
chmod 0755 "${DEBIAN_DIR}/prerm"

# postrm: reload systemd daemon after removal
cat > "${DEBIAN_DIR}/postrm" << 'EOF'
#!/bin/sh
set -e
systemctl daemon-reload

if [ "$1" = "purge" ]; then
    # Remove configuration directory on purge
    rm -rf /etc/drasyl

    # Notify user about manual cleanup of home config
    echo ""
    echo "NOTE: The user configuration directory ~/.drasyl is not removed automatically."
    echo "      Remove it manually if you no longer need it:"
    echo "        rm -rf ~/.drasyl"
    echo ""
fi
EOF
chmod 0755 "${DEBIAN_DIR}/postrm"

echo "📦 Building .deb package..."
dpkg-deb -Zgzip --build "${PKG_DIR}"

DEB_NAME="${BINARY_NAME}_${VERSION}_${ARCH}.deb"
mv "${PKG_DIR}.deb" "${TARGET_DIR}/${DEB_NAME}"

echo "✅ Package created at ${TARGET_DIR}/${DEB_NAME}"