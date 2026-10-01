#!/bin/sh
# Build the C implementation out of tree and install what the parity test and
# the benchmark compare against.
#
#   scripts/build-c-reference.sh [path-to-the-C-checkout]     (default ../pkcs11-proxy)
#
# Installs libpkcs11-proxy and pkcs11-daemon into $P11_C_REF_DIR, by default
# ~/.local/share/p11-proxy-rs/c-ref. Needs cmake and OpenSSL.
set -eu
SRC=${1:-"$(dirname "$0")/../../pkcs11-proxy"}
DEST=${P11_C_REF_DIR:-$HOME/.local/share/p11-proxy-rs/c-ref}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# a copy of the committed tree, so the checkout itself is not touched
git -C "$SRC" archive HEAD | (mkdir "$WORK/src" && tar -x -C "$WORK/src")
cmake -S "$WORK/src" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DPKCS11_V32=ON >/dev/null
cmake --build "$WORK/build" -j4 >/dev/null
mkdir -p "$DEST"
cp -a "$WORK"/build/libpkcs11-proxy* "$WORK/build/pkcs11-daemon" "$DEST"/
echo "installed in $DEST"
