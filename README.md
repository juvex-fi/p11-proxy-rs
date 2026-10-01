# p11-proxy

Use a PKCS#11 token on another machine as if it were in this one.

`libp11-proxy` is a PKCS#11 module: applications load it like any other
(OpenSSH, OpenSC's `pkcs11-tool`, Firefox, `openssl` with a PKCS#11 provider,
...). Every call goes over an authenticated, encrypted connection to
`p11-daemon`, which runs the call against the real module (SoftHSM, a
hardware HSM's library, ...) and sends the answer back.

This is a from-scratch rewrite in Rust of the C
[pkcs11-proxy](https://github.com/SUNET/pkcs11-proxy). It keeps the idea and
the behaviour (a scripted scenario produces the same transcript through this
proxy, through the C one and straight to the module) and changes the parts
that made it hard to trust, test and maintain. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it is built.

```
  application ── libp11-proxy ══ TLS 1.3, certificates on both sides ══ p11-daemon ── real PKCS#11 module
```

## What you get

- PKCS#11 3.2: all 101 functions of the 3.x specification plus the three local
  entry points, `C_GetInterface` offering 3.2, 3.1, 3.0 and 2.40. Mechanism
  parameters that contain pointers are carried member by member (436
  mechanisms, including AES-GCM/CCM, RSA-OAEP, ECDH, HKDF,
  TLS key derivation, ML-KEM/ML-DSA/SLH-DSA with a context).
- **Mutual TLS by default**: `tcp://` is TLS 1.3 with a client certificate;
  `psk://` is TLS 1.2 with a pre-shared key; `unix://` for local use; `stdio`
  for inetd and systemd `Accept=yes`. There is no plaintext TCP.
- **The daemon is the trust boundary.** It parses untrusted bytes with memory
  safe code, never uses anything it received as a pointer, gives each client
  private session and object handles, and can restrict each client identity to
  slots and mechanisms, make it read-only, or deny attributes.
- **Confinement**: after it has opened the module and its sockets the daemon can
  drop privileges and confine itself (a seccomp allow-list on Linux, a Seatbelt
  profile on macOS).
- **Parallel**: a client keeps a small pool of connections that share one
  context, so threads make calls concurrently and `C_WaitForSlotEvent` blocks
  only its own connection.
- **Fast**: on par with or faster than the C implementation (see
  [docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

Supported platforms: Linux and macOS (64-bit, little endian). Not Windows.

## Quick start

Build:

```sh
cargo build --release
# target/release/p11-daemon
# target/release/libp11_proxy.so   (.dylib on macOS)
```

Build without the TLS-PSK mode (and so without the OpenSSL dependency): `make release-nopsk`, that is
`cargo build --release --no-default-features --features p11-daemon/vendor,p11-client/vendor -p p11-daemon -p p11-client`.
Build without vendor-defined mechanisms and functions (the code for them is left out, and a configuration
that names them is refused): `make release-novendor`, that is
`cargo build --release --no-default-features --features p11-daemon/psk,p11-client/psk -p p11-daemon -p p11-client`.

Serve SoftHSM on a local socket and use it:

```sh
softhsm2-util --init-token --free --label demo --pin 1234 --so-pin 5678
p11-daemon --listen unix:///tmp/p11.sock /usr/lib/softhsm/libsofthsm2.so &
PKCS11_PROXY_SOCKET=unix:///tmp/p11.sock \
    pkcs11-tool --module ./libp11_proxy.so --list-slots
```

Over the network, with certificates (`docs/CONFIG.md` has a walk-through with
`openssl` commands):

```sh
# server
p11-daemon --config /etc/pkcs11/daemon.toml
# client
export PKCS11_PROXY_SOCKET=tcp://hsm.example.org:2345
export PKCS11_PROXY_TLS_CA=/etc/pkcs11/ca.pem
export PKCS11_PROXY_TLS_CERT=/etc/pkcs11/alice.pem
export PKCS11_PROXY_TLS_KEY=/etc/pkcs11/alice.key
```

## Make targets

`make` shows them all: `build`, `release`, `test`, `test-fast`, `test-linux`, `test-musl`, `lint`, `fmt`, `fuzz`, `bench`, `install`, `docker`, `clean`, ...

## Documentation

| | |
|---|---|
| [docs/CONFIG.md](docs/CONFIG.md) | every option of the daemon and the client; certificates; policy; systemd |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | the wire protocol |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the crates, how the code is generated, threads, trust boundaries |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | what is defended against and how |
| [docs/MIGRATION.md](docs/MIGRATION.md) | moving from the C implementation |
| [docs/TESTING.md](docs/TESTING.md) | the test suites, the Linux container, fuzzing, conformance, benchmarks |
| [CHANGELOG.md](CHANGELOG.md) | |

## Layout

```
crates/p11-types       PKCS#11 v3.2 types and constants (bindgen output, committed)
crates/p11-idl         api.idl, the one description of the API, and the code generators
crates/p11-wire        frames, handshake, codecs, generated messages (no unsafe code)
crates/p11-params      C structures <-> wire values: attributes, mechanism parameters
crates/p11-module      the Backend trait; the implementation that loads a real module
crates/p11-daemon      the daemon: contexts, policy, dispatcher, listeners, main()
crates/p11-client      libp11-proxy: C entry points, connection pool
crates/p11-transport   unix sockets, TLS, PSK, stdio
crates/p11-sandbox     privilege dropping, seccomp, Seatbelt
crates/p11-testkit     mock token, SoftHSM fixture, fuzz target bodies
crates/p11-conformance scripted scenario, parity test against the C proxy, benchmark
fuzz/                  libFuzzer targets

packaging/             Dockerfile, systemd units, example configuration
```

## Licence

LGPL-2.1-or-later, like the C project this replaces.

The full text is in `LICENSE`. `crates/p11-types/vendor/` contains the PKCS#11 header files
(`pkcs11.h`, `pkcs11t.h`, `pkcs11f.h`, `pkcs11-platform.h`) published by OASIS. They are
Copyright (c) OASIS Open and distributed under the OASIS IPR Policy, not under the LGPL.
