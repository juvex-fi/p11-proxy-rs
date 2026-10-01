# Architecture

## The path of a call

```
application
  │  C_Encrypt(session, data, len, out, &outlen)
  ▼
p11-client  ─ generated extern "C" fn        captures the arguments into wire values
  │            (rt::bytes, rt::out_spec, capture_mech, ...)
  ▼
Core (connection pool) ── frames ══ transport ══ frames ── Server::serve        p11-daemon
                                                              │
                                              dispatch::handle │ decode, policy, contexts
                                                              ▼
                                            xlate_request     client handles → module handles
                                                              ▼
                                              Backend::c_encrypt(&EncryptReq) -> Reply<EncryptResp>
                                                              ▼
p11-module DlBackend  ─ generated method       rebuilds C arguments in the daemon's memory,
                                              calls the module's C_Encrypt, reads the results
                                                              ▼
                                              real PKCS#11 module
```

and the answer takes the same road back: `xlate_response` turns the module's
object handles into the client's, the client stub writes the results into the
caller's buffers after checking that they fit.

## One description of the API

`crates/p11-idl/src/api.idl` lists the 101 calls, each argument with a *kind*
(`session`, `object`, `bytes`, `o_bytes`, `mech`, `attrs`, `attrs_query`, ...)
that fixes its C parameters, its wire type in the request and in the response,
and what each end does with it. Adding or changing a call is an edit to that file;
`build.rs` scripts in the consumer crates run the generators in `p11-idl` and
the compiler checks the result against the bindgen types of the PKCS#11
headers (the generated function lists and the generated calls into the module
have exactly the header's signatures, or nothing compiles).

| generated | in | what |
|---|---|---|
| `Request`/`Response` enums and one struct per call, `CALLS` | `p11-wire` | wire messages, encode and decode |
| sample messages | `p11-wire` | the golden vectors and the fuzzers' seeds |
| `Backend` trait, `dispatch` | `p11-module` | one method per call, `CKR_FUNCTION_NOT_SUPPORTED` by default |
| `Fns`, `impl Backend for DlBackend` | `p11-module` | calls into a loaded module |
| `xlate_request`, `xlate_response` | `p11-daemon` | handle translation and policy hooks by argument kind |
| the `extern "C"` entry points and the function lists | `p11-client` | what applications call |
| the call table in `docs/PROTOCOL.md` | (checked by a test) | |

The parts that are not uniform are written by hand and small: the calls that
change daemon state (`C_Initialize`, sessions, filtered lists) in
`p11-daemon/src/dispatch.rs`, `C_Initialize`/`C_Finalize`/`C_OpenSession`/
`C_WaitForSlotEvent` and the interface functions in `p11-client/src/exports.rs`
(flag `custom` and `special` in `api.idl`).

## Crates and where the unsafe code is

| crate | unsafe? | role |
|---|---|---|
| `p11-types` | generated bindings | C types and constants; no code |
| `p11-idl` | no | the API description, the generators |
| `p11-wire` | **`forbid(unsafe_code)`** | everything that decodes bytes from a peer |
| `p11-params` | yes, all the pointer work | C structures ↔ wire values (attribute arrays, mechanism parameter structures, info structures) |
| `p11-module` | yes | `dlopen` and the call into the module |
| `p11-daemon` | no (except the signal and `getuid` calls in `main`) | contexts, policy, dispatcher, listeners |
| `p11-client` | yes | the C ABI, and copying results into the caller's memory |
| `p11-transport` | small (socket options, peer credentials) | streams and TLS |
| `p11-sandbox` | small (credentials, seccomp, `sandbox_init`) | confinement |

`unsafe_op_in_unsafe_fn` is denied workspace-wide and clippy warns on any unsafe
block without a `SAFETY:` comment.

### Structures with pointers

A mechanism parameter is a C structure that may hold pointers, which mean
nothing in the daemon. `p11-params` has a *descriptor* per structure
(`descs.rs`): its members, in order, each with an offset (taken with
`offset_of!` on the bindgen type), a kind, the phases in which it goes to the
module and whether it comes back. Four walks over a descriptor do everything:

- **capture** (client): read the caller's structure into a `Node` tree;
- **materialize** (daemon): build an equivalent structure in an arena from a
  tree, checking every length against the descriptor and the limits;
- **extract** (daemon): after the call, read back the members the module filled
  in (never more bytes than were allocated);
- **apply** (client): write those into the caller's structure, checking the
  reply against the caller's own lengths, dry run first so a bad reply leaves the
  caller's memory untouched.

`mechtab.rs` says which mechanisms exist and how each one's parameter travels
(none, flat bytes of a checked length, a handle, a descriptor).

## Handles and contexts

The daemon keeps a **context** per client (`ctx.rs`), created by the first
connection and shared by that client's pooled connections. It maps the client's
virtual session and object handles to the module's real ones. Session handles the
context doesn't know are refused; an object handle it doesn't know is replaced
by a value no object has, so the module's own error comes back (which differs
between modules). Handles inside mechanism parameters are translated the same
way in both directions (`walk_handles`).

When a context's last connection closes, the daemon closes the sessions it
opened, so a client that crashes does not leave sessions or logged-in state
behind.

## Threads

Thread per connection, blocking I/O, no async runtime in the trust boundary.
PKCS#11 modules are often not fully thread safe and many calls block (login,
`C_WaitForSlotEvent`), which suits it. The daemon loads the module once and
shares it between connections (the module is initialised with OS locking
allowed); `--serialize-module` puts a lock around every call except the
blocking wait for modules that need it.

The client library keeps a pool of up to 16 connections per process
(configurable). A call takes an idle connection or opens another that joins the
same context; calls from different threads therefore run in parallel and a
thread blocked in `C_WaitForSlotEvent` holds one connection, not the library.
Idle connections are checked for a closed peer before reuse if they have been
idle for half a second.

## Failure behaviour

- A malformed frame or body: the daemon sends `Abort(Protocol)` and closes.
  Unknown call ids are answered with `CKR_FUNCTION_NOT_SUPPORTED`.
- A panic in a backend call becomes `CKR_GENERAL_ERROR` for that call.
- The client library catches panics at the C boundary (`CKR_GENERAL_ERROR`)
  and turns I/O failures into `CKR_DEVICE_ERROR`; every read and write has a
  timeout except the wait for a slot event.
- If the daemon forgets a client (it restarted), the client's next join is
  refused and its calls return `CKR_DEVICE_ERROR` until `C_Finalize`.

## Testing seams

`Backend` is the seam between the daemon and the token, and `Connector` /
`Conn` the seam between the client and the network. That is what lets the
test suites run the whole client → daemon → token path in one process against a
mock token (`p11-testkit`), and the same path with real processes and sockets
against SoftHSM. See [TESTING.md](TESTING.md).
