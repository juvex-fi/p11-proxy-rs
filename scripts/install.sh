#!/bin/sh
# Install the release build.
#
#   cargo build --release && scripts/install.sh            # into /usr/local
#   PREFIX=/usr DESTDIR=/tmp/stage scripts/install.sh      # for a package
set -eu
cd "$(dirname "$0")/.."
PREFIX=${PREFIX:-/usr/local}
D=${DESTDIR:-}
case $(uname) in Darwin) EXT=dylib ;; *) EXT=so ;; esac
install -d "$D$PREFIX/bin" "$D$PREFIX/lib" "$D$PREFIX/share/doc/p11-proxy" "$D$PREFIX/share/p11-proxy" "$D$PREFIX/lib/systemd/system"
install -m 0755 target/release/p11-daemon "$D$PREFIX/bin/p11-daemon"
# applications load it as libp11-proxy
install -m 0755 "target/release/libp11_proxy.$EXT" "$D$PREFIX/lib/libp11_proxy.$EXT"
install -m 0644 packaging/daemon.toml.example packaging/client.toml.example "$D$PREFIX/share/p11-proxy/"
install -m 0644 README.md CHANGELOG.md docs/*.md "$D$PREFIX/share/doc/p11-proxy/"
if [ "$(uname)" = Linux ]; then
	install -m 0644 packaging/systemd/* "$D$PREFIX/lib/systemd/system/"
fi
echo "installed under $D$PREFIX"
