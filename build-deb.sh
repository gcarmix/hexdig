#!/usr/bin/env bash
#
# Build a Debian source + binary package for hexdig.
#
# Requires: dpkg-dev, debhelper, devscripts, cmake, fakeroot, lintian
# Install with:
#   sudo apt-get install dpkg-dev debhelper devscripts cmake fakeroot lintian \
#                        zlib1g-dev liblzma-dev liblzo2-dev pkg-config
#
# Usage:
#   ./build-deb.sh              # builds .deb (binary package only)
#   ./build-deb.sh --source     # also build source package (.dsc / .tar.xz)
#   ./build-deb.sh --lintian    # run lintian on the resulting .deb / .changes
#
set -euo pipefail

DO_SOURCE=0
DO_LINTIAN=0
for arg in "$@"; do
    case "$arg" in
        --source)  DO_SOURCE=1 ;;
        --lintian) DO_LINTIAN=1 ;;
        -h|--help)
            sed -n '2,14p' "$0"
            exit 0
            ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# dpkg-buildpackage drops artefacts in the parent directory by default.
# Stage the source in a clean copy under ../hexdig-build to keep the tree clean.
SRC_NAME="hexdig"
VERSION="$(dpkg-parsechangelog -SVersion | sed 's/-.*$//')"
STAGE_PARENT="$(mktemp -d -t hexdig-deb-XXXXXX)"
STAGE_DIR="$STAGE_PARENT/${SRC_NAME}-${VERSION}"

trap 'echo "Build artefacts left in: $STAGE_PARENT"' EXIT

echo "==> Staging source in $STAGE_DIR"
mkdir -p "$STAGE_DIR"
# Copy everything except build artefacts and VCS metadata.
tar --exclude='./build' \
    --exclude='./debian/.debhelper' \
    --exclude='./.git' \
    --exclude='./.vscode' \
    -cf - . | tar -xf - -C "$STAGE_DIR"

# Create the orig tarball expected by dpkg-source for "3.0 (quilt)".
ORIG_TAR="$STAGE_PARENT/${SRC_NAME}_${VERSION}.orig.tar.xz"
echo "==> Creating $ORIG_TAR"
tar --exclude='./debian' -C "$STAGE_DIR" -cJf "$ORIG_TAR" .

cd "$STAGE_DIR"

if [ "$DO_SOURCE" -eq 1 ]; then
    echo "==> Building source + binary packages"
    dpkg-buildpackage -us -uc
else
    echo "==> Building binary package only"
    dpkg-buildpackage -us -uc -b
fi

echo
echo "==> Artefacts:"
ls -1 "$STAGE_PARENT"/*.deb 2>/dev/null || true
ls -1 "$STAGE_PARENT"/*.dsc "$STAGE_PARENT"/*.changes "$STAGE_PARENT"/*.tar.xz 2>/dev/null || true

if [ "$DO_LINTIAN" -eq 1 ]; then
    echo
    echo "==> Running lintian (--profile debian: changelog targets unstable)"
    lintian --profile debian -i "$STAGE_PARENT"/*.changes || true
    echo
    echo "Notes on remaining lintian messages:"
    echo "  - 'initial-upload-closes-no-bugs' is expected until you file an"
    echo "    ITP bug on wnpp and reference it in debian/changelog as"
    echo "    '(Closes: #NNNNNN)'."
fi
