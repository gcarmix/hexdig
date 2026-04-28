#!/usr/bin/env bash
#
# HexDig install script for Linux.
# Detects the distribution, installs build dependencies, then builds
# and installs hexdig via CMake.
#
# Usage:
#   ./install.sh                  # interactive: asks before installing
#   ./install.sh --yes            # non-interactive
#   ./install.sh --no-install     # build only, skip "sudo make install"
#   ./install.sh --prefix=/path   # custom CMAKE_INSTALL_PREFIX
#
set -euo pipefail

ASSUME_YES=0
DO_INSTALL=1
PREFIX=""
JOBS="$(nproc 2>/dev/null || echo 4)"

for arg in "$@"; do
    case "$arg" in
        -y|--yes)        ASSUME_YES=1 ;;
        --no-install)    DO_INSTALL=0 ;;
        --prefix=*)      PREFIX="${arg#--prefix=}" ;;
        -h|--help)
            sed -n '2,12p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- pretty logging --------------------------------------------------------
if [ -t 1 ]; then
    C_RST=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
    C_YEL=$'\033[33m'; C_BLU=$'\033[34m'
else
    C_RST=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""
fi
log()  { printf "%s==>%s %s\n" "$C_BLU" "$C_RST" "$*"; }
ok()   { printf "%s[ ok ]%s %s\n" "$C_GRN" "$C_RST" "$*"; }
warn() { printf "%s[warn]%s %s\n" "$C_YEL" "$C_RST" "$*"; }
err()  { printf "%s[err ]%s %s\n" "$C_RED" "$C_RST" "$*" >&2; }

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    local prompt="$1"
    read -r -p "$prompt [Y/n] " ans
    case "${ans,,}" in
        ""|y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# ---- distro detection ------------------------------------------------------
DISTRO_ID=""; DISTRO_LIKE=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
fi

case " $DISTRO_ID $DISTRO_LIKE " in
    *" debian "*|*" ubuntu "*)        FAMILY="debian" ;;
    *" fedora "*|*" rhel "*|*" centos "*) FAMILY="fedora" ;;
    *" arch "*)                       FAMILY="arch" ;;
    *" suse "*|*" opensuse "*)        FAMILY="suse" ;;
    *" alpine "*)                     FAMILY="alpine" ;;
    *) FAMILY="" ;;
esac

if [ -z "$FAMILY" ]; then
    warn "Could not detect a supported distribution from /etc/os-release."
    warn "Supported families: Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE, Alpine."
    warn "You will need to install the dependencies manually:"
    warn "  CMake (>=3.12), a C++17 compiler, zlib, liblzma (xz), lzo2."
fi

# ---- sudo helper -----------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        warn "Not running as root and 'sudo' was not found."
        warn "Re-run as root if dependency installation or 'make install' is required."
    fi
fi

# ---- dependency check ------------------------------------------------------
have_header() {
    # tries to compile a tiny program that includes the header
    local hdr="$1"
    local tmp; tmp="$(mktemp --suffix=.cpp)"
    printf "#include <%s>\nint main(){return 0;}\n" "$hdr" > "$tmp"
    local cxx="${CXX:-g++}"
    "$cxx" -E "$tmp" >/dev/null 2>&1
    local rc=$?
    rm -f "$tmp"
    return $rc
}

have_lib() {
    local lib="$1"
    local cxx="${CXX:-g++}"
    echo "int main(){return 0;}" | "$cxx" -x c++ - -l"$lib" -o /dev/null >/dev/null 2>&1
}

MISSING_BIN=()
MISSING_LIB=()

command -v cmake >/dev/null 2>&1 || MISSING_BIN+=("cmake")
command -v make  >/dev/null 2>&1 || MISSING_BIN+=("make")
command -v g++   >/dev/null 2>&1 || command -v c++ >/dev/null 2>&1 || MISSING_BIN+=("g++")

if command -v g++ >/dev/null 2>&1; then
    have_header "zlib.h"     || MISSING_LIB+=("zlib")
    have_header "lzma.h"     || MISSING_LIB+=("lzma")
    have_header "lzo/lzo1x.h" || MISSING_LIB+=("lzo2")
fi

# ---- distro-specific package names ----------------------------------------
pkgs_for() {
    case "$FAMILY" in
        debian)
            echo "build-essential cmake pkg-config zlib1g-dev liblzma-dev liblzo2-dev"
            ;;
        fedora)
            echo "gcc gcc-c++ make cmake pkgconfig zlib-devel xz-devel lzo-devel"
            ;;
        arch)
            echo "base-devel cmake pkgconf zlib xz lzo"
            ;;
        suse)
            echo "gcc gcc-c++ make cmake pkg-config zlib-devel xz-devel lzo-devel"
            ;;
        alpine)
            echo "build-base cmake pkgconfig zlib-dev xz-dev lzo-dev"
            ;;
        *) echo "" ;;
    esac
}

install_pkgs() {
    local pkgs="$1"
    [ -z "$pkgs" ] && return 0
    case "$FAMILY" in
        debian)  $SUDO apt-get update && $SUDO apt-get install -y $pkgs ;;
        fedora)  $SUDO dnf install -y $pkgs ;;
        arch)    $SUDO pacman -S --needed --noconfirm $pkgs ;;
        suse)    $SUDO zypper install -y $pkgs ;;
        alpine)  $SUDO apk add --no-cache $pkgs ;;
        *) return 1 ;;
    esac
}

# ---- summary & installation ------------------------------------------------
log "Detected distribution: ${DISTRO_ID:-unknown} (family: ${FAMILY:-unknown})"

if [ "${#MISSING_BIN[@]}" -eq 0 ] && [ "${#MISSING_LIB[@]}" -eq 0 ]; then
    ok "All build dependencies are present."
else
    if [ "${#MISSING_BIN[@]}" -gt 0 ]; then
        warn "Missing tools: ${MISSING_BIN[*]}"
    fi
    if [ "${#MISSING_LIB[@]}" -gt 0 ]; then
        warn "Missing dev libraries: ${MISSING_LIB[*]}"
    fi

    if [ -z "$FAMILY" ]; then
        err "Cannot install dependencies automatically on this distribution."
        err "Please install them manually and re-run this script."
        exit 1
    fi

    PKGS="$(pkgs_for)"
    log "Will install the following packages: $PKGS"

    if confirm "Proceed with package installation?"; then
        install_pkgs "$PKGS"
        ok "Dependencies installed."
    else
        err "Aborted by user."
        exit 1
    fi
fi

# ---- build -----------------------------------------------------------------
BUILD_DIR="$SCRIPT_DIR/build"
log "Configuring build in $BUILD_DIR"
CMAKE_ARGS=(-S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release)
[ -n "$PREFIX" ] && CMAKE_ARGS+=(-DCMAKE_INSTALL_PREFIX="$PREFIX")
cmake "${CMAKE_ARGS[@]}"

log "Building hexdig (-j$JOBS)"
cmake --build "$BUILD_DIR" -j"$JOBS"
ok "Build complete: $BUILD_DIR/hexdig"

# ---- install ---------------------------------------------------------------
if [ "$DO_INSTALL" -eq 1 ]; then
    if confirm "Install hexdig system-wide via 'cmake --install'?"; then
        $SUDO cmake --install "$BUILD_DIR"
        ok "hexdig installed. Try: hexdig --help"
    else
        warn "Skipped install. Binary is at $BUILD_DIR/hexdig"
    fi
else
    ok "Build-only mode: binary at $BUILD_DIR/hexdig"
fi
