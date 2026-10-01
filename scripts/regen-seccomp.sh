#!/bin/sh
# Check the seccomp allow-list against what the daemon really does.
#
# Runs the end-to-end tests with the daemon under strace (sandbox off), takes
# the system calls it made, and reports those that crates/p11-sandbox/src/linux.rs
# does not allow. Calls that only startup makes (execve, bind, listen, ...) are
# expected in the report; anything else means the list needs an entry.
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp -d)
P11_TEST_WRAPPER="strace -ff -qq -o /tmp/strace-out/trace" \
DOCKER_ARGS="--cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v $out:/tmp/strace-out" \
EXTRA_PACKAGES=strace \
scripts/linux-test.sh sh -c 'cargo build -q -p p11-daemon && PKCS11_DAEMON_SANDBOX=off cargo test -q -p p11-daemon --test e2e -- --test-threads=1' >/dev/null 2>&1 || true
cat "$out"/trace.* | sed -E 's/^\[pid +[0-9]+\] //' | grep -oE '^[a-z_0-9]+\(' | tr -d '(' | sort -u > "$out/observed"
grep -oE 'SYS_[a-z_0-9]+' crates/p11-sandbox/src/linux.rs | sed 's/^SYS_//' | sort -u > "$out/allowed"
echo "observed but not allowed:"
comm -23 "$out/observed" "$out/allowed" | tr '\n' ' '
echo
rm -rf "$out"
