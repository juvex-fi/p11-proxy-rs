#!/bin/sh
# Build the daemon and the client library without vendor support and check that it is really gone:
# the library exports none of the vendor entry points and still exports the PKCS#11 ones.
set -eu
cd "$(dirname "$0")/.."
target=${CARGO_TARGET_DIR:-target}/novendor
CARGO_TARGET_DIR=$target cargo build -q --release -p p11-daemon -p p11-client \
    --no-default-features --features p11-daemon/psk,p11-client/psk

case "$(uname)" in
Darwin) lib=$target/release/libp11_proxy.dylib; syms="nm -gU $lib" ;;
*) lib=$target/release/libp11_proxy.so; syms="nm -D --defined-only $lib" ;;
esac
vendor=$($syms | grep -cE "CT_|FMSC_|P11P_" || true)
standard=$($syms | grep -c "C_" || true)
if [ "$vendor" -ne 0 ]; then
    echo "check-novendor: $vendor vendor symbols are still exported by $lib" >&2
    exit 1
fi
if [ "$standard" -lt 100 ]; then
    echo "check-novendor: only $standard PKCS#11 symbols in $lib" >&2
    exit 1
fi
echo "check-novendor: no vendor symbols, $standard PKCS#11 ones"
