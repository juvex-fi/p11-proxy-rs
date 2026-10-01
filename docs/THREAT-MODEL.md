# Threat model

## Assets
- Private and secret keys inside the HSM or software token behind the daemon.
- PINs and other secrets in transit between the client library and the daemon.
- Availability of the token for legitimate clients.

## Actors and trust
| Actor | Trust |
|---|---|
| Client application, and `libp11-proxy` inside it | Untrusted once the connection is established. The application authenticates with a certificate (or PSK), but a stolen credential must not give more than the policy for that identity allows. |
| Network between client and daemon | Hostile: read, modify, replay, drop, delay. |
| Daemon (`p11-daemon`) | Trusted, but it parses attacker-controlled bytes, so it is the primary hardening target. |
| PKCS#11 module loaded by the daemon | Trusted to enforce token policy, but assumed buggy: it must never receive a pointer, handle or structure that a client fabricated. |
| Local users on the daemon host | Untrusted, except for the owners of the configured key, certificate and socket files. |

## Threats and mitigations
| # | Threat | Mitigation |
|---|---|---|
| T1 | Malformed or oversized frames crash or exhaust the daemon | The wire crate is `#![forbid(unsafe_code)]`; every length is checked against `limits` before allocation; fuzz targets on frames, values and the dispatcher |
| T2 | A client forges pointers or handles to reach memory or another client's objects | Nothing but fixed-width integers and byte strings crosses the wire; the daemon rebuilds every C structure in its own arena; session and object handles are per-client virtual handles |
| T3 | Eavesdropping or tampering on the network | TCP is always TLS 1.3 with mutual certificate authentication, or PSK. There is no plaintext TCP mode. |
| T4 | Impersonation of the daemon | The client verifies the daemon certificate against the configured CA (PSK mode: possession of the key) |
| T5 | A legitimate but compromised client abuses the token | Per-identity policy: slot allow-list, mechanism allow-list, read-only mode, attribute filters |
| T6 | Connection floods and slow clients | Connection cap, handshake and idle timeouts, per-client session cap, bounded per-client handle tables |
| T7 | PIN leakage through logs or memory | Secrets are held in zeroizing wrappers that redact `Debug`; PIN-bearing calls are never logged with arguments |
| T8 | Daemon compromise escalates to the host | Privilege dropping and a sandbox (seccomp on Linux, `sandbox_init` on macOS) installed after the module is loaded |
| T9 | Local socket access | `unix://` sockets are created with mode 0660; peer credentials (`SO_PEERCRED`/`LOCAL_PEERCRED`) are checked against an allow-list |
| T10 | A module bug corrupts the daemon | Out of scope for mitigation beyond the sandbox and privilege drop; the daemon does not trust module output lengths and clamps them |

## Out of scope
Side channels inside the token, physical attacks on the HSM, and denial of service by an authorized client that stays within its limits.
