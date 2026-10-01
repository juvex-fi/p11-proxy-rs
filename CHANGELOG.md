# Changelog

## 1.0.0

The first release: a from-scratch rewrite in Rust of the C
[pkcs11-proxy](https://github.com/SUNET/pkcs11-proxy). It is not wire-compatible with the C version, and the library
and daemon are named `libp11_proxy` and `p11-daemon` so both can be installed side by side. See
[docs/MIGRATION.md](docs/MIGRATION.md) for what changes for a user of the C version.

### PKCS#11

- PKCS#11 3.2, generated from one description of the API (`crates/p11-idl/src/api.idl`): 101 calls, including the
  message-based, asynchronous, encapsulation and authenticated-wrapping ones.
- 436 mechanisms, with the parameters that contain pointers carried member by member.
- `C_GetInterface` with 3.2, 3.1, 3.0 and 2.40 function lists.

### Protocol and transports

- A specified, versioned wire protocol (`docs/PROTOCOL.md`) with golden vectors for every call.
- `tcp://`: TLS 1.3 with client certificates. `psk://`: TLS 1.2 with a pre-shared key (OpenSSL, the default `psk`
  feature). Also unix sockets, and stdio for inetd-style launchers. There is no plaintext TCP.

### Daemon (`p11-daemon`)

- A context per client shared by its pooled connections, private session and object handles, and sessions closed
  when a client leaves.
- Per-identity policy (slots, mechanisms, read-only, denied attributes), limits and timeouts, a TOML
  configuration, signal handling.
- Confinement: privilege dropping, a seccomp allow-list measured with strace (Linux) and a Seatbelt profile
  (macOS).

### Client library (`libp11_proxy`)

- A pool of connections, so threads run in parallel and blocking waits do not stall the library.
- Fork handling, panics contained at the C boundary, timeouts on every call except the wait for a slot event,
  configuration from the environment or a file.

### Vendor extensions

The `vendor` cargo feature is on by default. `make release-novendor` builds without it, and the code is then absent
from the daemon and the client library.

- Vendor-defined mechanisms are declared in the daemon's configuration (`[[vendor_mechanism]]`): an empty
  parameter, a pointer-free structure (optionally holding object handles at known offsets), one object handle, or
  one shaped like a built-in mechanism's. Clients learn of them in the handshake.
- A mechanism parameter that holds pointers, nested structures or handles can be declared member by member
  (`[[vendor_struct]]`), and is carried, translated and checked like a built-in one.
- Vendor-defined functions of a module (not PKCS#11's) are declared with `[[vendor_function]]`, giving their
  signature as a list of argument kinds. Applications call them by the exported names of a known SDK or through
  `P11P_GetVendorFunction`.

### Tests

Unit, property and golden-vector tests; component tests (an in-process daemon over a mock token); end-to-end tests
against SoftHSM (unix, mutual TLS, PSK, stdio); a parity test that runs one scripted scenario directly against
SoftHSM, through this proxy and through the C proxy; seeded and libFuzzer fuzzing. Run on macOS, Debian and
Alpine. Benchmarks are on par with the C implementation.

### Not supported

Windows; 32-bit and big-endian systems; the X3DH, X2Ratchet, Skipjack, Baton, Juniper and GOST 28147 mechanisms;
notification callbacks.
