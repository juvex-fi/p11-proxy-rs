#!/bin/sh
# Build and test on Linux in a container (glibc, Debian bookworm), with the
# distribution's SoftHSM for the end-to-end tests.
#
#   scripts/linux-test.sh                 # cargo test --workspace
#   scripts/linux-test.sh cargo clippy    # any other command
#
# Set IMAGE to use another base image (for example rust:1-alpine for musl).
set -eu
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-rust:1-bookworm}
[ $# -gt 0 ] || set -- cargo test --workspace
exec docker run --rm ${DOCKER_ARGS:-} \
	-v "$PWD":/src -w /src \
	-v p11-cargo-registry:/usr/local/cargo/registry \
	-e CARGO_TARGET_DIR=/src/target-linux \
	-e P11_TEST_WRAPPER="${P11_TEST_WRAPPER:-}" -e EXTRA_PACKAGES="${EXTRA_PACKAGES:-}" \
	-e P11_SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so \
	-e P11_SOFTHSM_UTIL=/usr/bin/softhsm2-util \
	"$IMAGE" sh -c '
		if command -v apt-get >/dev/null; then
			apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends pkg-config libssl-dev softhsm2 ${EXTRA_PACKAGES:-} >/dev/null
		elif command -v apk >/dev/null; then
			apk add --no-cache build-base pkgconf openssl-dev openssl-libs-static softhsm ${EXTRA_PACKAGES:-} >/dev/null
			# a dynamic C runtime, so that the client library can be a shared object
			export RUSTFLAGS="-C target-feature=-crt-static"
			export P11_SOFTHSM_MODULE=${P11_SOFTHSM_MODULE_ALPINE:-/usr/lib/softhsm/libsofthsm2.so}
		fi
		exec "$@"
	' sh "$@"
