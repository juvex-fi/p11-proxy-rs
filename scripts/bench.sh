#!/bin/sh
# Compare call latency and throughput: straight to SoftHSM, through the Rust
# proxy, and through the C proxy (if built; see scripts/build-c-reference.sh).
#
#   scripts/bench.sh [seconds] [threads]
set -eu
cd "$(dirname "$0")/.."
SECS=${1:-2}
THREADS=${2:-1}
cargo build -q --release -p p11-client -p p11-daemon -p p11-conformance
T=target/release
case $(uname) in Darwin) EXT=dylib ;; *) EXT=so ;; esac
SH=${P11_SOFTHSM_DIR:-$HOME/.local/share/p11-proxy-rs/softhsm}
MOD=${P11_SOFTHSM_MODULE:-$SH/libsofthsm2.$EXT}
UTIL=${P11_SOFTHSM_UTIL:-$SH/softhsm2-util}
CREF=${P11_C_REF_DIR:-$HOME/.local/share/p11-proxy-rs/c-ref}
D=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$D"' EXIT
mkdir -p "$D/tokens" "$D/csock"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$D" > "$D/conf"
export SOFTHSM2_CONF="$D/conf"
"$UTIL" --init-token --free --label bench --so-pin 5678 --pin 1234 --module "$MOD" >/dev/null

echo "== SoftHSM directly"
$T/p11-bench "$MOD" "$SECS" "$THREADS"

echo; echo "== Rust proxy (unix socket)"
$T/p11-daemon --listen "unix://$D/rust.sock" --sandbox off "$MOD" 2>/dev/null &
sleep 1
PKCS11_PROXY_SOCKET="unix://$D/rust.sock" $T/p11-bench "$T/libp11_proxy.$EXT" "$SECS" "$THREADS"

if [ -f "$CREF/pkcs11-daemon" ]; then
	echo; echo "== C proxy (unix socket)"
	PKCS11_DAEMON_SOCKET="$D/csock" "$CREF/pkcs11-daemon" "$MOD" 2>/dev/null &
	sleep 1
	PKCS11_PROXY_SOCKET="$D/csock/socket" $T/p11-bench "$CREF/libpkcs11-proxy.$EXT" "$SECS" "$THREADS"
fi
