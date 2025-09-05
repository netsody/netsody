#!/bin/bash
set -euo pipefail

# ---------------------- Configuration ----------------------
PKGNAME="${PKGNAME:-drasyl-agent}"
BIN_NAME="${BIN_NAME:-drasyl}"
VERSION="${VERSION:-0.1.0}"      # e.g. 0.1.0
PKGREL="${PKGREL:-1}"

# Build type: --release anywhere -> release, else debug
BUILD_TYPE="debug"
for arg in "$@"; do [[ "$arg" == "--release" ]] && BUILD_TYPE="release"; done

DESC="${DESC:-drasyl provides secure, software-defined overlay networks, connecting all your devices.}"
URL="${URL:-https://github.com/drasyl/drasyl-rs}"
LICENSE="${LICENSE:-MIT}"
# Space-separated runtime deps; extend if needed (e.g. "systemd openssl zstd")
DEPENDS=(${DEPENDS:-systemd})

# Workspace layout (repo root one level up from this script)
WORKSPACE_DIR="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
OUT_DIR="${WORKSPACE_DIR}/target/${BUILD_TYPE}"

# Container settings (Ubuntu runner + macOS/M2 friendly)
DOCKER_IMAGE="${DOCKER_IMAGE:-archlinux:latest}"    # we'll install base-devel inside
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"   # required on arm64 hosts (e.g. M1/M2)

# ---------------------- Helpers ----------------------
msg()  { printf "\033[1;32m==>\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m==>\033[0m %s\n" "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "Required program not found: $1"; }

arch_to_triple() {
  case "$1" in
    armv7h)  echo "armv7-unknown-linux-gnueabihf" ;;
    aarch64) echo "aarch64-unknown-linux-gnu" ;;
    x86_64)  echo "x86_64-unknown-linux-gnu" ;;
    i686)    echo "i686-unknown-linux-gnu" ;;
    riscv64) echo "riscv64gc-unknown-linux-gnu" ;;
    *) echo "" ;;
  esac
}

triple_to_arch() {
  case "$1" in
    armv7-unknown-linux-gnueabihf) echo "armv7h" ;;
    aarch64-unknown-linux-gnu)     echo "aarch64" ;;
    x86_64-unknown-linux-gnu)      echo "x86_64" ;;
    i686-unknown-linux-gnu)        echo "i686" ;;
    riscv64gc-unknown-linux-gnu)   echo "riscv64" ;;
    *) echo "" ;;
  esac
}

auto_arch_pkg_from_uname() {
  case "$(uname -m)" in
    armv7l|armv7*) echo "armv7h" ;;
    aarch64)       echo "aarch64" ;;
    x86_64)        echo "x86_64" ;;
    i686|i386)     echo "i686" ;;
    riscv64)       echo "riscv64" ;;
    *)             echo "" ;;
  esac
}

find_first_existing() {
  for p in "$@"; do [[ -f "$p" ]] && { echo "$p"; return 0; }; done
  return 1
}

# ---------------------- Auto-discover BIN/TRIPLE/ARCH ----------------------
# Candidate triples to try if nothing obvious is set
CANDIDATE_TRIPLES=(
  "armv7-unknown-linux-gnueabihf"
  "aarch64-unknown-linux-gnu"
  "x86_64-unknown-linux-gnu"
  "i686-unknown-linux-gnu"
  "riscv64gc-unknown-linux-gnu"
)

ARCH_PKG="${ARCH_PKG:-}"   # allow env override
TRIPLE=""

# 1) Try native target/<profile>
if [[ -z "${ARCH_PKG}" && -z "${TRIPLE}" ]]; then
  NATIVE_BIN="${WORKSPACE_DIR}/target/${BUILD_TYPE}/${BIN_NAME}"
  if [[ -f "${NATIVE_BIN}" ]]; then
    # We cannot know the arch reliably; prefer uname as hint
    ARCH_PKG="$(auto_arch_pkg_from_uname)"
    TRIPLE="$(arch_to_triple "${ARCH_PKG}")"
    BIN_PATH="${NATIVE_BIN}"
  fi
fi

# 2) Try each known triple folder until a binary is found
if [[ -z "${BIN_PATH:-}" ]]; then
  for t in "${CANDIDATE_TRIPLES[@]}"; do
    for prof in "${BUILD_TYPE}" "$([[ "${BUILD_TYPE}" == "release" ]] && echo debug || echo release)"; do
      cand="${WORKSPACE_DIR}/target/${t}/${prof}/${BIN_NAME}"
      if [[ -f "${cand}" ]]; then
        TRIPLE="${t}"
        ARCH_PKG="$(triple_to_arch "${t}")"
        BIN_PATH="${cand}"
        break 2
      fi
    done
  done
fi

# 3) If still nothing, but ARCH_PKG env was given, use that triple and look there
if [[ -z "${BIN_PATH:-}" && -n "${ARCH_PKG}" ]]; then
  TRIPLE="$(arch_to_triple "${ARCH_PKG}")"
  if [[ -n "${TRIPLE}" ]]; then
    for prof in "${BUILD_TYPE}" "$([[ "${BUILD_TYPE}" == "release" ]] && echo debug || echo release)"; do
      cand="${WORKSPACE_DIR}/target/${TRIPLE}/${prof}/${BIN_NAME}"
      if [[ -f "${cand}" ]]; then
        BIN_PATH="${cand}"
        break
      fi
    done
  fi
fi

# 4) Final fallback: tell user what we tried
if [[ -z "${BIN_PATH:-}" ]]; then
  tried=( "${WORKSPACE_DIR}/target/${BUILD_TYPE}/${BIN_NAME}" )
  for t in "${CANDIDATE_TRIPLES[@]}"; do
    tried+=( "${WORKSPACE_DIR}/target/${t}/${BUILD_TYPE}/${BIN_NAME}" )
    other="$([[ "${BUILD_TYPE}" == "release" ]] && echo debug || echo release)"
    tried+=( "${WORKSPACE_DIR}/target/${t}/${other}/${BIN_NAME}" )
  done
  die "Binary not found. Looked in: ${tried[*]}"
fi

# Infer CHOST and sanity-check ARCH_PKG/TRIPLE
if [[ -z "${TRIPLE}" || -z "${ARCH_PKG}" ]]; then
  # If BIN was native, we at least need some metadata for package
  [[ -z "${ARCH_PKG}" ]] && ARCH_PKG="$(auto_arch_pkg_from_uname)"
  [[ -z "${TRIPLE}"   ]] && TRIPLE="$(arch_to_triple "${ARCH_PKG}")"
fi
CHOST="${TRIPLE}"

# Optional .so alongside the binary (try same discovery)
SO_NAME="libdrasyl_agent.so"
SO_PATH=""
for prof in "${BUILD_TYPE}" "$([[ "${BUILD_TYPE}" == "release" ]] && echo debug || echo release)"; do
  cand1="${WORKSPACE_DIR}/target/${TRIPLE}/${prof}/${SO_NAME}"
  cand2="${WORKSPACE_DIR}/target/${prof}/${SO_NAME}"
  if [[ -f "${cand1}" ]]; then SO_PATH="${cand1}"; break; fi
  if [[ -f "${cand2}" ]]; then SO_PATH="${cand2}"; break; fi
done

msg "Resolved ARCH_PKG=${ARCH_PKG}, TRIPLE=${TRIPLE}"
msg "Using BIN_PATH=${BIN_PATH}"
[[ -n "${SO_PATH}" ]] && msg "Using SO_PATH=${SO_PATH}"

# Now that ARCH_PKG is known, set packaging work dir
PKG_WORK="${OUT_DIR}/${PKGNAME}-pkgbuild-${ARCH_PKG}"

# ---------------------- Host tool checks ----------------------
need docker

# ---------------------- Stage payload (host) ----------------------
msg "Preparing payload for ${ARCH_PKG} (triple: ${TRIPLE})…"
rm -rf "${PKG_WORK}"
mkdir -p "${PKG_WORK}"
STAGE_DIR="${PKG_WORK}/stage"
mkdir -p "${STAGE_DIR}/usr/bin" "${STAGE_DIR}/usr/lib" "${STAGE_DIR}/etc/drasyl" "${STAGE_DIR}/usr/lib/systemd/system"

# Copy binary + optional .so
cp -f "${BIN_PATH}" "${STAGE_DIR}/usr/bin/${BIN_NAME}"
[[ -n "${SO_PATH}" ]] && cp -f "${SO_PATH}" "${STAGE_DIR}/usr/lib/"

# Optional license into payload
if [[ -f "${WORKSPACE_DIR}/LICENSE" ]]; then
  mkdir -p "${STAGE_DIR}/usr/share/licenses/${PKGNAME}"
  cp -f "${WORKSPACE_DIR}/LICENSE" "${STAGE_DIR}/usr/share/licenses/${PKGNAME}/LICENSE"
fi

# systemd unit (mirrors Debian service)
cat > "${STAGE_DIR}/usr/lib/systemd/system/${BIN_NAME}.service" <<'UNIT'
[Unit]
Description=drasyl
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/drasyl run
Restart=always
RestartSec=3
WorkingDirectory=/etc/drasyl/
Environment=DRASYL_UDP_SOCKETS=1
Environment=DRASYL_C2D_THREADS=1
Environment=DRASYL_D2C_THREADS=1
Environment=DRASYL_TUN_THREADS=1

[Install]
WantedBy=multi-user.target
UNIT

# Quick sanity: what did we stage?
msg "Stage contents:"
du -sh "${STAGE_DIR}" || true
ls -lah "${STAGE_DIR}/usr/bin" || true
ls -lah "${STAGE_DIR}/usr/lib" || true
ls -lah "${STAGE_DIR}/usr/lib/systemd/system" || true

# Clean macOS junk if running on macOS
find "${STAGE_DIR}" -name '.DS_Store' -delete -o -name '._*' -delete || true

# ---------------------- Build payload tar INSIDE Arch container (no macOS metadata) ----------------------
PAYLOAD_TAR="${PKG_WORK}/${PKGNAME}-${VERSION}-${ARCH_PKG}.payload.tar.gz"

docker run --rm \
  --platform="${DOCKER_PLATFORM}" \
  -v "${STAGE_DIR}":/in:ro -v "${PKG_WORK}":/out \
  "${DOCKER_IMAGE}" \
  bash -lc "
    set -e
    pacman -Sy --noconfirm tar >/dev/null
    tar --format=gnu --numeric-owner --owner=0 --group=0 \
        --exclude='.DS_Store' --exclude='._*' \
        -C /in -czf \"/out/$(basename "${PAYLOAD_TAR}")\" .
    echo 'Payload entries (first 20):'
    tar -tzf \"/out/$(basename "${PAYLOAD_TAR}")\" | sed -n '1,20p'
    echo 'Payload size:'
    stat -c '%n %s bytes' \"/out/$(basename "${PAYLOAD_TAR}")\"
  "

msg "Payload tar on host:"
ls -lah "${PAYLOAD_TAR}"

# ---------------------- Write PKGBUILD + .install ----------------------
DEPENDS_ARR=""
for d in "${DEPENDS[@]}"; do DEPENDS_ARR+="'$d' "; done

cat > "${PKG_WORK}/${PKGNAME}.install" <<'INSTALL'
post_install() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl is-enabled drasyl.service >/dev/null 2>&1; then
    systemctl restart drasyl.service >/dev/null 2>&1 || systemctl start drasyl.service >/dev/null 2>&1 || true
  else
    systemctl enable --now drasyl.service >/dev/null 2>&1 || true
  fi

  if [[ ! -f /etc/drasyl/auth.token ]]; then
    install -d -m700 /etc/drasyl
    umask 077
    TOKEN="$(openssl rand -hex 12)"
    echo "$TOKEN" > /etc/drasyl/auth.token
    chmod 600 /etc/drasyl/auth.token
  fi

  cat <<'MSG'
An API auth token was created at: /etc/drasyl/auth.token
To use drasyl, copy it into your home directory:
  mkdir -p ~/.drasyl
  sudo cat /etc/drasyl/auth.token > ~/.drasyl/auth.token
  chmod 600 ~/.drasyl/auth.token
MSG
}

post_upgrade() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart drasyl.service >/dev/null 2>&1 || systemctl start drasyl.service >/dev/null 2>&1 || true
}

pre_remove() {
  systemctl stop drasyl.service >/dev/null 2>&1 || true
  systemctl disable drasyl.service >/dev/null 2>&1 || true
}

post_remove() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo
  echo "NOTE: ~/.drasyl is not automatically removed."
  echo "If not needed anymore: rm -rf ~/.drasyl"
  echo
}
INSTALL

cat > "${PKG_WORK}/PKGBUILD" <<PKG
# Maintainer: drasyl Team <info@drasyl.org>
pkgname=${PKGNAME}
pkgver=${VERSION}
pkgrel=${PKGREL}
pkgdesc="${DESC}"
arch=(${ARCH_PKG})
url="${URL}"
license=('${LICENSE}')
depends=(${DEPENDS_ARR})
install=${PKGNAME}.install
source=(${PKGNAME}-${VERSION}-${ARCH_PKG}.payload.tar.gz)
sha256sums=('SKIP')
options=('!debug' '!strip')

package() {
  # Extract staged payload directly into \$pkgdir
  tar -xzf "\${srcdir}/${PKGNAME}-${VERSION}-${ARCH_PKG}.payload.tar.gz" -C "\${pkgdir}"
}
PKG

# ---------------------- Build with makepkg inside Arch container ----------------------
msg "Building Arch package for ${ARCH_PKG} inside ${DOCKER_IMAGE}…"
(
  cd "${PKG_WORK}"
  docker run --rm \
    --platform="${DOCKER_PLATFORM}" \
    -v "$PWD":/pkg -w /pkg \
    "${DOCKER_IMAGE}" \
    bash -lc '
      set -e
      pacman -Sy --noconfirm pacman git base-devel >/dev/null
      # build as non-root (required by makepkg)
      useradd -m build && chown -R build:build /pkg
      su build -c "
        export CARCH='"${ARCH_PKG}"' CHOST='"${CHOST}"'
        makepkg -f --nocheck --nodeps
      "
      chown -R 1000:1000 /pkg
    '
)

sudo chown $(id -u):$(id -g) "${PKG_WORK}"/*.pkg.tar.*

PKG_FILE="$(ls -1 "${PKG_WORK}"/${PKGNAME}-*.pkg.tar.* | tail -n1)"
[[ -f "${PKG_FILE}" ]] || die "Package not produced."

# Rename to match your Debian naming convention
EXT="${PKG_FILE##*.tar.}"    # e.g. zst
FINAL_NAME="${OUT_DIR}/${PKGNAME}_${VERSION}-${PKGREL}_${ARCH_PKG}.pkg.tar.${EXT}"
mv -f "${PKG_FILE}" "${FINAL_NAME}"

msg "✅ Package created: ${FINAL_NAME}"
echo
echo "Install on Arch/PiKVM with:"
echo "  sudo pacman -U '${FINAL_NAME}'"