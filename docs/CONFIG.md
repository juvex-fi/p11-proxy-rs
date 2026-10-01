# Configuration

## Addresses

| form | meaning |
|---|---|
| `unix:///path/to/socket` | a local socket, mode 0660 by default; the peer's uid is its identity |
| `tcp://host:port`, `tcp://[::1]:port` | TLS 1.3 with a certificate on each side |
| `psk://host:port` | TLS 1.2 with a pre-shared key (needs the `psk` feature, on by default) |
| `stdio` | the daemon's standard input and output as the one connection, for `inetd`, `xinetd` and systemd `Accept=yes` sockets |

A `tcp://` address is always TLS; there is no plaintext TCP mode.

## The daemon

```
p11-daemon [OPTIONS] [MODULE]
```

`MODULE` is the shared library of the PKCS#11 module to serve.

| option | meaning |
|---|---|
| `-c, --config FILE` | configuration file (TOML, below); `PKCS11_DAEMON_CONFIG` |
| `-l, --listen ADDR` | where to listen; repeatable; `PKCS11_DAEMON_SOCKET` (space separated) |
| `--tls-cert FILE`, `--tls-key FILE` | the server's certificate chain and private key (PEM) |
| `--tls-client-ca FILE` | the CA whose client certificates are accepted (PEM) |
| `--psk-file FILE` | pre-shared keys, one `identity:hex-secret` per line, at least 16 bytes each |
| `--serialize-module` | one call at a time, for modules that are not thread safe |
| `--unix-mode MODE` | file mode of unix sockets (octal, default 0660) |
| `--drop-privs USER` | become this user once the module is open and the sockets are bound |
| `--sandbox auto\|off\|require` | confinement (below); `PKCS11_DAEMON_SANDBOX` |
| `--check-config` | validate the configuration and exit |
| `-v`, `-vv` | log more; `PKCS11_DAEMON_LOG` takes a `tracing` filter such as `p11_daemon=debug` |

Options override the file. The daemon logs to standard error and exits on
SIGINT, SIGTERM or SIGHUP after closing its connections and finalising the
module. It opens the module once and shares it between all clients: a client's
`C_Initialize`/`C_Finalize` affects only that client's context.

### The configuration file

```toml
module = "/usr/lib/softhsm/libsofthsm2.so"
listen = ["tcp://0.0.0.0:2345", "unix:///run/pkcs11/daemon.sock"]
serialize_module = false
drop_privileges = "pkcs11"

[tls]                      # for tcp:// listeners
cert = "/etc/pkcs11/server.pem"
key = "/etc/pkcs11/server.key"
client_ca = "/etc/pkcs11/clients-ca.pem"

[psk]                      # for psk:// listeners
file = "/etc/pkcs11/psk.keys"

[unix]
mode = "0660"

[limits]
max_connections = 256      # connections served at once
max_contexts = 128         # distinct clients
max_conns_per_context = 32 # pooled connections one client may hold
handshake_timeout = 10     # seconds to complete the TLS and protocol handshakes
idle_timeout = 0           # seconds a connection may stay silent; 0 = no limit

[sandbox]
mode = "auto"              # auto, off, require
write_paths = ["/var/lib/softhsm"]   # macOS: where writes stay allowed (empty: unrestricted)

[policy]
default = "allow"          # what identities without a [[client]] entry get; "deny" once any [[client]] exists, unless set

[[client]]
identity = "cert:cn=alice"
slots = [0, 1]                                   # omitted: all
mechanisms = ["CKM_SHA256", "CKM_AES_GCM", 4224] # names or numbers; omitted: all the proxy carries
read_only = true                                 # no calls that change the token, no read-write sessions
max_sessions = 16
deny_attributes = ["CKA_EXTRACTABLE"]            # a template may not contain these
```

Unknown keys are errors, so a typo does not silently open something up.

### Vendor-defined mechanisms

Vendor support (this and the next section, `[[vendor_struct]]` and `[[vendor_function]]`) is the cargo feature
`vendor`, on by default. Built without it (`make release-novendor`) the code for it is not in the daemon or the
client library: the library exports none of the vendor entry points, the by-name lookup of a module's functions is
not compiled, nothing is announced in the handshake, and a daemon configuration that names `vendor_mechanism`,
`vendor_struct` or `vendor_function` is refused at startup with a message that says so.

A mechanism in the vendor range (`0x80000000` and up) is refused and left out
of `C_GetMechanismList`, because the proxy cannot know what its parameter
looks like. An administrator who does can declare it in the daemon's file. The
daemon tells each client library in the handshake, so nothing is configured on
the client. A parameter can be declared in these forms, exactly one per entry:

```toml
[[vendor_mechanism]]
id = 0x80000123     # the mechanism number
length = 16         # the parameter is exactly 16 bytes; 0: the mechanism takes none

[[vendor_mechanism]]
id = 0x80000124
max_length = 64     # or: at most 64 bytes

[[vendor_mechanism]]
id = 0x80000125
handle = true       # the parameter is one object handle (a CK_OBJECT_HANDLE)

[[vendor_mechanism]]
id = 0x80000126
length = 40         # a structure without pointers, exactly 40 bytes,
handles = [8, 32]   # holding object handles at these byte offsets

[[vendor_mechanism]]
id = 0x80000127
same_as = "CKM_AES_GCM"   # the parameter of a mechanism the proxy already carries (name or number)

[[vendor_mechanism]]
id = 0x80000128
struct = "signing_params"  # a structure with pointers: see [[vendor_struct]] below
```

At most 4096 bytes, no standard mechanism, no number twice, offsets inside the
parameter, increasing and at least 8 apart; `p11-daemon --check-config` checks the
entries. Bytes are copied and handed to the module in the daemon's memory, so a
parameter declared as bytes **must not contain pointers**: a structure that does
would give the module pointers into the client's memory, and the daemon cannot
tell. Declare a mechanism whose parameter has pointers as bytes and the module
will read garbage. Object handles are translated only where declared (`handle`,
`handles`): the client's handle goes to the module as the module's own, and one
the client never had goes as a handle no object has. Nothing a module writes into
the parameter is returned to the application. `same_as` gives the mechanism the
parameter handling of the one it names, pointers and handles included, but not
its message-based (`C_Message*`) form. A client policy's `mechanisms` list can
name a vendor mechanism by its number.

#### Structures with pointers

A parameter that holds pointers (to buffers, to arrays of structures, to attribute templates, to strings, to
other mechanisms) is declared by describing its structures, one `[[vendor_struct]]` each, member by member:

```toml
[[vendor_struct]]
name = "item"
size = 16                       # sizeof the C structure
fields = [
  { name = "kind",   offset = 0, kind = "ulong" },
  { name = "object", offset = 8, kind = "handle" },
]

[[vendor_struct]]
name = "signing_params"
size = 48
fields = [
  { name = "flags",   offset = 0,  kind = "ulong" },
  { name = "n_items", offset = 8,  kind = "ulong" },
  { name = "items",   offset = 16, kind = "array", of = "item", by = "n_items" },   # a pointer to n_items items
  { name = "data",    offset = 24, kind = "bytes", by = "data_len" },              # a pointer to data_len bytes
  { name = "data_len",offset = 32, kind = "ulong" },
  { name = "key",     offset = 40, kind = "handle" },
]
```

The kinds are `ulong`, `handle`, `bool`, `byte`, `bytes` (a pointer; `by` names the member holding its length;
`n` caps it), `inline` (`n` bytes in the structure), `ulong_ptr`, `handle_ptr` (a pointer to a handle the module
writes), `struct` (a pointer to the structure `of`), `embedded` (the structure `of` inside this one), `array` (a
pointer to an array of `of`, the count in `by`), `attrs` (a template, the count in `by`), `cstr`, `mech_ptr`, `mech`
(a `CK_MECHANISM` inside the structure, carried with its own parameter) and `handle_array` (a pointer to an array
of handles the module writes: `by` names a `ulong_ptr` member with `dir = "inout"` that holds the room going in and
the number written coming back). `dir` is `in` (the default), `out` (the module writes it and the caller gets it
back; a handle it writes is translated to the client's) or `inout`; an `inline` array can go out too. Every handle in a structure is translated like the handles of every other
call.

**Get the layout right.** The proxy reads the application's structure at these offsets and builds one for the
module at the same ones. Offsets and sizes must be those of the vendor's C structure on the daemon's platform
(check them with `offsetof` and `sizeof` in a compiler, as for the pointer sizes); a wrong layout makes the
client library read memory that is not the structure, or the module receive one it does not expect, and either
can crash the process. What the proxy can check it checks when the daemon starts and again in each client: every
member inside the structure, aligned to 8 where it holds a `CK_ULONG` or a pointer, no two overlapping, every
`of` and `by` resolving, no structure containing itself, at most 64 structures of 64 members and 4096 bytes.
The parameter must be exactly `size` bytes.

`p11-mechs` (see TESTING.md) lists the mechanisms a module offers and which of
them need such a declaration.

### Vendor-defined functions

Some modules export functions that are not PKCS#11's (a vendor's SDK extensions). The daemon carries a
function only if `daemon.toml` declares it, with its C signature written as a list of argument kinds:

```toml
[[vendor_function]]
name = "Vnd_CopyObject"         # the module's exported symbol
args = ["session", "session", "object", "attrs", "o_object"]
rw = true                       # it changes the token: refused for a read-only client

[[vendor_function]]
name = "Vnd_FetchData"          # CK_RV f(unsigned int, CK_ATTRIBUTE_TYPE, CK_CHAR_PTR, CK_ULONG_PTR)
args = ["u32", "u64", "o_bytes"]
```

A kind may stand for more than one C parameter (`attrs` is the template pointer and its count, `o_bytes` a
buffer and the pointer to its length); PROTOCOL.md lists them all: `u8 u16 u32 u64 slot session object bytes
secret cstr label attrs o_u32 o_u64 o_object o_bytes o_buf`. `session`, `slot` and `object` arguments are
translated like the handles of every other call, `secret` is wiped after the call, an `o_object` the function
made is registered under a handle of the client's own. Rules: the name is a C identifier not starting `C_`;
at most 32 arguments and 20 C parameters (8 on macOS on arm64, where the stack is not passed by slot); only
integers and pointers, so nothing taken or returned by value as a structure or a floating point number;
`p11-daemon --check-config` checks the entries.

The daemon tells each client library in the handshake. An application then calls the function by the
exported name of the ones one known vendor SDK defines (listed in `crates/p11-client/src/vendor.rs`)
or, for any declared function, through
`const void *P11P_GetVendorFunction(const char *name)`, which returns a pointer to call with the function's
own arguments (NULL if the daemon declared none of that name; at most 32 names per process). A function the
daemon did not declare answers `CKR_FUNCTION_NOT_SUPPORTED`.

**Declare with care.** A wrong signature makes the daemon pass the module arguments it does not expect, which
can crash the daemon. Many vendor functions are administrative (initialising or erasing a token, disabling an
HSM, a raw channel to custom firmware): declare one only for a deployment where the clients that may call it
are meant to, and consider a policy of separate daemons. A function that returns a handle of the module's own
(such as a session handle) must not be declared: it would hand the client a handle the daemon cannot
translate. The calling code passes 20 arguments to every entry point, so the extra ones are read and ignored
(harmless on the platforms supported, which pass integers and pointers in registers and eight-byte stack slots).

### Identities

A client's identity comes from how it proved itself, and `identity` in a
`[[client]]` entry may be any of its labels:

| label | source |
|---|---|
| `cert:cn=NAME` | the subject common name of the client certificate |
| `cert:san:dns=NAME`, `cert:san:email=ADDR`, `cert:san:uri=URI` | subject alternative names |
| `cert:sha256=HEX` | the certificate's fingerprint (pins one certificate) |
| `psk:NAME` | the PSK identity |
| `unix:uid=N` | the uid of a local peer |
| `stdio` | a daemon started on a pipe |

Each label carries the way it was proved, so a certificate whose common name
is `psk:alice` is still only `cert:cn=psk:alice`.

### Certificates

Anything that makes a CA and signs with it works; for example with OpenSSL:

```sh
# a CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca.key -out ca.pem -days 3650 -subj "/CN=pkcs11 ca"

# the daemon's certificate, valid for the name clients connect to
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout server.key -out server.csr -subj "/CN=hsm.example.org"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 365 -extfile <(printf "subjectAltName=DNS:hsm.example.org")

# a client's
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout alice.key -out alice.csr -subj "/CN=alice"
openssl x509 -req -in alice.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out alice.pem -days 365
```

The daemon needs `server.pem`, `server.key` and `ca.pem` (as `client_ca`); a
client needs `alice.pem`, `alice.key` and `ca.pem`. The client checks the
daemon's certificate against the host in its address, or against
`PKCS11_PROXY_TLS_SERVER_NAME`.

### Pre-shared keys

```sh
printf 'alice:%s\n' "$(openssl rand -hex 32)" >> psk.keys   # on the daemon; give alice's line to alice
```

A client's key file holds exactly one line. PSK mode is TLS 1.2 with
ECDHE-PSK/ChaCha20-Poly1305, DHE-PSK/AES-256-GCM or PSK/AES-256-GCM. Prefer
certificates where you can: they can be revoked per client and rotated without
touching the daemon.

### Confinement

After the module is loaded and the listeners are open, `--drop-privs` changes
the user and `--sandbox` confines the process:

- **Linux**: `no_new_privs`, not dumpable, and a seccomp filter that allows the
  system calls the running daemon makes (measured with strace on the end to end
  tests, `scripts/regen-seccomp.sh`) and kills the process on anything else. No
  network sockets can be opened, nothing can be executed, memory cannot be
  mapped executable. `PKCS11_DAEMON_SECCOMP_TRAP=1` raises SIGSYS instead of
  killing, for finding out what a module needs.
- **macOS**: a Seatbelt profile that forbids exec, fork and outbound
  connections, and, if `write_paths` is set, file writes elsewhere.

`auto` (the default) confines where the platform can and logs a warning where
it cannot; `require` refuses to run unconfined; `off` does nothing. A module
that needs more (a hardware HSM's library opening device nodes and talking to a
daemon of its own) may need `off`, or a wider filter.

### systemd

`packaging/systemd/` has a service unit and a socket-activated
`Accept=yes` pair using the `stdio` transport. The second runs a daemon per
connection, which loads the module every time: use it for cheap modules and low
call rates.

## The client library

Configured by environment variables, or by a TOML file named in
`PKCS11_PROXY_CONFIG` (the variables override it):

| variable | file key | meaning |
|---|---|---|
| `PKCS11_PROXY_SOCKET` | `socket` | the daemon's address; required |
| `PKCS11_PROXY_TLS_CA` | `ca` | PEM file: the CA that signed the daemon's certificate |
| `PKCS11_PROXY_TLS_CERT`, `PKCS11_PROXY_TLS_KEY` | `cert`, `key` | PEM files: this client's certificate chain and key |
| `PKCS11_PROXY_TLS_SERVER_NAME` | `server_name` | the name to verify the daemon's certificate against (default: the host of the address) |
| `PKCS11_PROXY_TLS_PSK_FILE` | `psk_file` | file with one `identity:hex-secret` line, for `psk://` |
| `PKCS11_PROXY_TIMEOUT` | `timeout` | seconds one call may take (default 300); `C_WaitForSlotEvent` has no limit |
| `PKCS11_PROXY_MAX_CONNECTIONS` | `max_connections` | connections kept open (default 16) |
| `PKCS11_PROXY_DEBUG` | | set to log connection problems to standard error |

```toml
# client.toml
socket = "tcp://hsm.example.org:2345"
ca = "/etc/pkcs11/ca.pem"
cert = "/etc/pkcs11/alice.pem"
key = "/etc/pkcs11/alice.key"
timeout = 60
```

Behaviour worth knowing:

- Settings are read at `C_Initialize`. An unreachable daemon makes it return
  `CKR_GENERAL_ERROR` (bad configuration) or `CKR_DEVICE_ERROR` (cannot connect).
- If the daemon goes away, calls return `CKR_DEVICE_ERROR` at once rather than
  hanging; the sessions are gone and the application has to `C_Finalize` and
  start again.
- After `fork()` the child must call `C_Initialize` again (as PKCS#11 requires);
  it does not disturb the parent's connections.
- Notification callbacks given to `C_OpenSession` are ignored (they never fire).
- Mechanisms the proxy cannot carry are refused with `CKR_MECHANISM_INVALID`
  and left out of `C_GetMechanismList`: X3DH, X2Ratchet, the obsolete
  Skipjack, Baton, Juniper and GOST 28147 families, and vendor-defined
  mechanisms unless declared (see "Vendor-defined mechanisms").
