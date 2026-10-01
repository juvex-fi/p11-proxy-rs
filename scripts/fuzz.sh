#!/bin/sh
# Run every fuzz target for SECONDS (default 60) each, in a Linux container
# with a nightly toolchain and cargo-fuzz.
#
#   scripts/fuzz.sh [seconds]
set -eu
cd "$(dirname "$0")/.."
SECS=${1:-60}
exec docker run --rm \
	-v "$PWD":/src -w /src/fuzz \
	-v p11-cargo-registry:/usr/local/cargo/registry \
	-v p11-rustup:/usr/local/rustup-nightly \
	-e CARGO_TARGET_DIR=/src/target-fuzz \
	-e SECS="$SECS" \
	rust:1-bookworm sh -eu -c '
		apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends pkg-config libssl-dev clang >/dev/null
		rustup toolchain install nightly --profile minimal >/dev/null 2>&1
		cargo install cargo-fuzz --locked >/dev/null 2>&1 || cargo install cargo-fuzz >/dev/null 2>&1
		for t in frame request dispatch mech stream; do
			mkdir -p corpus/$t
			echo "== $t"
			cargo +nightly fuzz run $t -- -max_total_time=$SECS -max_len=4096 2>&1 | tail -4
		done
	'
