# Moving from the C implementation

The applications need no change: the library exports the same PKCS#11
functions and is loaded the same way. The daemon and the library have to be
upgraded **together**: the wire protocols are not compatible. An old C client
that reaches a new daemon (or the reverse) is recognised at the first bytes and
refused; the new library reports `CKR_DEVICE_ERROR` and, with
`PKCS11_PROXY_DEBUG` set, says what the daemon told it.

The files are named differently so that the two implementations can be installed side by side: the library is
`libp11_proxy.so` (`.dylib`) instead of `libpkcs11-proxy.so`, and the daemon is `p11-daemon` instead of
`pkcs11-daemon`. Applications that load the library by path need the new name. The environment variables
(`PKCS11_PROXY_*`, `PKCS11_DAEMON_*`) keep their names.

## Addresses and authentication

| | C implementation | this one |
|---|---|---|
| unix socket, daemon | `PKCS11_DAEMON_SOCKET=/some/dir` makes `/some/dir/socket.pkcs11` | `--listen unix:///some/path.sock`, the path is the socket |
| unix socket, client | `PKCS11_PROXY_SOCKET=/some/dir/socket` (`.pkcs11` appended) | `PKCS11_PROXY_SOCKET=unix:///some/path.sock` |
| TCP | `tcp://host:port`, **plaintext** | `tcp://host:port` is **TLS 1.3 with a certificate on each side**; there is no plaintext TCP |
| pre-shared key | `tls://host:port`, key file in GnuTLS `psktool` format, the client uses the first identity in its file | `psk://host:port`, the same file format; a client's file holds exactly one identity; TLS 1.2 with ECDHE-PSK/DHE-PSK/PSK AEAD suites |
| inetd | `pkcs11-daemon module -` | `p11-daemon --listen stdio module` |
| IPv6 and DNS names | yes | yes (`tcp://[::1]:2345`, host names resolved by the client) |

To keep a link that was plaintext working, put it on a unix socket, or move it
to certificates (see [CONFIG.md](CONFIG.md)); there is deliberately no option
to turn TLS off on TCP.

## Daemon options

| C | here |
|---|---|
| `pkcs11-daemon module [socket]` | `p11-daemon [--listen ADDR]... module` (or `PKCS11_DAEMON_SOCKET`) |
| `--drop-privs USER` | `--drop-privs USER` (also `drop_privileges` in the file) |
| `--no-seccomp` | `--sandbox off` |
| build option `PKCS11_SECCOMP_DEBUG` | `PKCS11_DAEMON_SECCOMP_TRAP=1` |
| no access control beyond the network | `[[client]]` entries: per identity slots, mechanisms, read-only, denied attributes |
| a thread per client, sessions shared by the whole daemon | a context per client identity and connection pool; sessions and object handles are private to it |

## Behaviour that changed on purpose

- **Handles are private to a client.** Session and object handles the client
  sees are the daemon's own counters, not the module's. A client cannot use
  another client's handles, and a token object shows up under the same client
  handle every time it is found.
- **`C_WaitForSlotEvent` no longer parks a thread in the module.** The daemon
  asks the module without blocking and checks between asks that the client is
  still there and has not finalised, so a client that leaves or calls
  `C_Finalize` while waiting does not leave a thread (and its sessions) stuck
  inside the module. Events for slots a client's policy hides are skipped.
- **Sessions do not outlive their client.** When a client's last connection
  closes (or it crashes), the daemon closes the sessions it left open.
- **Errors come from the module.** A handle the daemon does not know is passed
  to the module as one no object has, so a bad key handle gives whatever error
  the module gives for one, exactly as if the client were talking to the module
  directly. Parameters and attributes the proxy cannot carry are refused with
  `CKR_MECHANISM_PARAM_INVALID` / `CKR_ATTRIBUTE_VALUE_INVALID` before any
  bytes go out.
- **Mechanism lists are filtered** to the mechanisms the proxy can carry (and to
  the client's policy), as before. X3DH, X2Ratchet and the obsolete Skipjack,
  Baton, Juniper and GOST 28147 families are still not supported. Vendor-defined
  mechanisms can now be declared in the configuration (`[[vendor_mechanism]]`
  in docs/CONFIG.md); the C proxy had no way to carry them.
- **Flat mechanism parameters assume a little-endian client and daemon**, as
  the C version did; 32-bit and big-endian systems are not supported.
- **No Windows.**

Two answers differ from the module's own, the same in the C proxy and this one:
an attribute holding a template whose size is not a whole number of attributes
is refused with `CKR_ATTRIBUTE_VALUE_INVALID`, and a mechanism the proxy cannot
carry with `CKR_MECHANISM_INVALID`, both before anything is sent.

## What is gone

- The build options `PKCS11_V32=OFF` (legacy headers) and the vendored header
  sets: PKCS#11 3.2 is the only interface, and `C_GetInterface` offers 3.2, 3.1,
  3.0 and 2.40 function lists over it.
- `debian/`, `Dockerfile.jenkins`, `build-*.sh`: see `packaging/` and
  `scripts/`.
- The `p11proxy-mitm` helper, which only made sense for the plaintext protocol.

## Checking a migration

`cargo test -p p11-conformance --test parity` runs one scripted scenario
straight against SoftHSM, through this proxy and through a build of the C
proxy, and requires the same transcript from all three (`docs/TESTING.md`).
