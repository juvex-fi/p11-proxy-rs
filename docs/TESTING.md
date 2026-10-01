# Testing

```sh
cargo test --workspace          # everything that can run here; tests that need SoftHSM skip themselves
scripts/linux-test.sh           # the same on Linux, in a container, with the distribution's SoftHSM
```

## What runs

| where | what |
|---|---|
| `p11-wire` | codec round trips and limits (proptest); every call's decoder against garbage; **golden vectors** (`tests/vectors/`, byte-exact request and response for all 101 calls, framing and handshake); `docs/PROTOCOL.md` drift check |
| `p11-idl` | the API description parses; naming |
| `p11-params` | attribute arrays through real C memory; every parameter structure family through capture → wire → materialize → module writes → extract → wire → apply; hostile replies that must not overrun the caller's buffers; a module that overwrites the pointers, counts and lengths it was handed (the daemon follows only its own allocations); arbitrary trees against every mechanism (proptest); descriptor consistency |
| `p11-module` | the dlopen backend against SoftHSM (two-call convention, sessions, digest, random, objects, attribute semantics) |
| `p11-daemon` `tests/server.rs` | the daemon core over a mock token: handshake and versions, initialisation, private handles, isolation between clients, policy (slots, mechanisms, read-only, denied attributes), pooled connections sharing a context, cleanup when a client leaves, malformed input, backend panics, message parameters, waiting calls |
| `p11-daemon` `tests/e2e.rs` | **the whole system**: the real `p11-daemon` process on a SoftHSM token and the client's C entry points, over unix sockets, mutual TLS, PSK, stdio; AES-GCM/CBC, RSA-OAEP/PSS, ECDSA/ECDH, ML-DSA with context, ML-KEM; many threads; a killed daemon; policy from a file; seccomp on Linux |
| `p11-daemon` `tests/fork.rs` | a forked child initialises again without disturbing the parent |
| `p11-client` | the C entry points over an in-process daemon and the mock token (`tests/api.rs`, and all the 3.x calls in `tests/api3.rs`) |
| `p11-transport` | TLS with generated CAs (wrong CA on either side, wrong name, silent peer), PSK (right and wrong secret, unknown identity), unix sockets (permissions, stale sockets) |
| `p11-sandbox` | seccomp kills forbidden calls and allows local sockets (Linux); dropping privileges (as root, in a container) |
| `p11-testkit` | the mock token; a seeded mutation fuzzer over the fuzz targets' bodies (`FUZZ_ITERATIONS` raises the count) |
| `p11-conformance` `tests/parity.rs` | **one scenario, three routes, one transcript**: the ~150-step script run straight against SoftHSM, through this proxy (the built `cdylib` loaded with `dlopen`, the real daemon) and through the C proxy; the transcripts must be identical |

## Without vendor support

`make test-novendor` builds the crates without the `vendor` feature (docs/CONFIG.md), runs their tests, and
runs `scripts/check-novendor.sh`, which builds the release daemon and library that way and fails if the library
still exports a vendor entry point or lacks the PKCS#11 ones. The tests that are about vendor support are
compiled out; new ones check that a configuration naming it is refused, that nothing is announced to a client
that asks, and that a vendor call is an unknown call.

## SoftHSM

The end to end and conformance tests need a SoftHSM (2.6 or newer; 2.7 with
ML-DSA/ML-KEM for the post-quantum parts, which skip themselves otherwise).
Point at it with `P11_SOFTHSM_MODULE` (`libsofthsm2`) and `P11_SOFTHSM_UTIL`
(`softhsm2-util`), or put both in `~/.local/share/p11-proxy-rs/softhsm/`. Each
test makes its own token directory in a temporary place. Without SoftHSM the
tests print `SKIP` and pass, so check for that line when it matters.

## Another module

The end to end, `p11-module`, fork and parity suites can run on any PKCS#11
module instead of SoftHSM. The token must already exist and have user PIN
`1234`:

| variable | meaning |
|---|---|
| `P11_TEST_MODULE` | the module's shared library; switches the suites to it |
| `P11_TEST_SLOT` | index in the slot list of the token's slot (default 0; modules that list an admin slot first need 1) |
| `P11_TEST_TOKEN_LABEL` | the token's label (default `testkit`, SoftHSM's) |
| `P11_TEST_NO_SECCOMP` | skip the seccomp test (no seccomp here, e.g. under emulation) |

Two further checks run only in this mode or by hand: `p11-conformance` `tests/mechs.rs`
lists what the module offers and fails on a standard mechanism the proxy does not
recognise, and `cargo run -p p11-conformance --bin p11-mechs -- MODULE [SLOT]`
prints the same list (`--strict` also fails on vendor-defined ones). It has to run
against the module itself: the daemon leaves out of `C_GetMechanismList` whatever
it cannot carry, so through the proxy the gap is invisible.

The tests share the token, so run them one at a time
(`cargo test -- --test-threads=1`), and whatever the module needs in its
environment is inherited by the daemons. Where a module differs from SoftHSM
the tests tolerate it only in this mode (a mechanism it refuses, an empty value
or a length where SoftHSM says "unavailable", nested template values it does
not write into the caller's buffers), and print `SKIP:` for what they did not
check; with SoftHSM they stay strict. The module has to load on the machine
that runs the tests: a module built only for x86-64 Linux, for instance, needs
a container with a Rust toolchain on a Mac.

Run this way, all of it passes against a vendor's software HSM (x86-64 Linux
container under emulation, sandbox off): 18 end to
end tests (including a mixed workload of eight threads, with and without
`--serialize-module`, that checks each thread's own answers), the fork test,
five `p11-module` tests, the parity scenario (direct against the module and
through the proxy give the same transcript) and the mechanism check.
Skipped there: AES-GCM (the module answers `CKR_MECHANISM_PARAM_INVALID`),
ML-DSA/ML-KEM, the seccomp test, the comparison with the C proxy, and the
values of a nested template.

That module offers 279 mechanisms: 186 are carried and 93 are in the vendor
range (`0x80000000` and up). The proxy cannot know what a vendor mechanism's
parameter looks like, so applications do not see those through it unless
`[[vendor_mechanism]]` entries in the daemon's configuration declare them
(docs/CONFIG.md). The vendor's SDK (its C header and API documentation) and its
mechanism reference on the web document most of the parameters; declaring the 73
of the 93 that hold no pointers or object handles adds them to the list the proxy
shows (259 in all). One of them (a Keccak digest) is documented nowhere I could
find and was tried against the module without a parameter. Through the proxy, a
signature with a vendor mechanism, a vendor key generation, an encryption with a
declared IV and key wrapping with three vendor wrap mechanisms all work against the
module. The other 20 stay out: 16 have pointers or object handles in the parameter
(which cannot be declared) and four have no description available.

The module also exports vendor functions that are not PKCS#11's. Declared in the daemon's configuration
(`[[vendor_function]]`, docs/CONFIG.md), the SDK's helper functions work through the proxy against it: the id lookups return the module's
answers, an object copy between two sessions with a template makes an object that is usable under the client's
own handle, the generic lookup by name works, and a function that is not declared, or that the module does not
export (this one lacks one of the SDK's functions), answers `CKR_FUNCTION_NOT_SUPPORTED`. The administrative functions were not called.

Vendor mechanisms whose parameter holds pointers, nested structures or handles were declared with
`[[vendor_struct]]` (offsets and sizes compiled against the vendor's headers) and driven through the proxy
against the module, and the results compared with the same calls made directly on the module. A key
derivation whose parameter holds two attribute templates and returns two handles, and a second one with an
array of path indexes, succeed and return handles that are valid under the client's own numbering; an
encryption whose parameter holds byte buffers round-trips; a length with no buffer is refused before it leaves
the client. A mechanism with a handle inside a flat structure answers as it does directly for a valid handle, for
an unknown one and for another object's. Mechanisms the module does not offer (three of the declared ones) are
not listed, as before.

## The C reference

The parity test compares with the C implementation when it can find a build:

```sh
scripts/build-c-reference.sh ../pkcs11-proxy     # builds it out of tree and installs it in ~/.local/share/p11-proxy-rs/c-ref
```

(`P11_C_REF_DIR` overrides the place.) Without it the comparison is skipped;
the comparison with SoftHSM itself always runs.

## Linux

`scripts/linux-test.sh [command...]` runs a command (default `cargo test
--workspace`) in a `rust:1-bookworm` container with the Debian SoftHSM. The
build directory is `target-linux/`. `IMAGE=rust:1-alpine` runs it on musl.
`scripts/regen-seccomp.sh` re-measures the system calls the daemon makes and
reports any the seccomp allow-list lacks.

## Fuzzing

`scripts/fuzz.sh [seconds]` runs the five libFuzzer targets in `fuzz/`
(frames and the handshake, per-call decoders, request sequences against the
daemon core, mechanism trees, whole connections) in a Linux container with a
nightly toolchain. The target bodies are plain functions
(`p11-testkit/src/fuzz.rs`), so `cargo test` covers them a little all the time.

## Benchmarks

`scripts/bench.sh [seconds] [threads]` compares SoftHSM directly, this proxy
and the C proxy; numbers in [BENCHMARKS.md](BENCHMARKS.md).

## What the C project's tests became

| C test | now |
|---|---|
| `tests/message-test.c`, `mock-module.c`, `protocol-test.c` (message-based API, async, single-part AEAD against a mock module) | `p11-client/tests/api3.rs` and `api.rs` (the mock token in `p11-testkit`), `p11-params/tests/mech.rs` (message parameters per direction), `p11-daemon/tests/server.rs` |
| `tests/mechanism-test.c` (mechanism parameters through the protocol) | `p11-params/tests/mech.rs`, the e2e tests (GCM, OAEP, PSS, ECDH, ML-DSA context) |
| `tests/interface-test.c` (`C_GetInterface`, function lists) | `p11-client/tests/api.rs::function_lists_and_interfaces` |
| `tests/daemon-input.c` (hostile input to the daemon) | `p11-daemon/tests/server.rs` (malformed bodies, unknown calls, handshake abuse), the fuzz targets, `p11-wire` garbage tests |
| `tests/param-fuzz.c` | the `mech` fuzz target and `p11-params` proptests |
| `tests/softhsm-test.c`, `pqc-test.c` | `p11-module/tests/softhsm.rs`, `p11-daemon/tests/e2e.rs`, and the conformance scenario |
| `tests/run-with-daemon.sh` | `p11_testkit::proc::DaemonProc` |

## What has not been verified

- Only aarch64 Linux was used to measure the seccomp allow-list. The x86-64
  legacy equivalents (`open`, `stat`, `poll`, ...) were added by hand and have
  not been run on x86-64. `scripts/regen-seccomp.sh` re-measures on any machine
  that can run Docker.
- There is no continuous integration yet; the `make` targets above are run by hand.
- Mechanisms without a module that implements them (TLS/WTLS key derivation,
  IKE, KIP, CMS, OTP, PBE, SP 800-108 KDFs and the like) are tested at the level
  of the parameter codec (capture, wire, materialize, module writes, extract,
  wire, apply), not against a real implementation. Against SoftHSM the end to
  end and parity tests cover AES-GCM/CBC/key wrap, RSA OAEP/PSS/PKCS,
  ECDSA/ECDH, ML-DSA (with context) and ML-KEM (on the macOS build; the Debian
  SoftHSM lacks them and those steps skip).
- Real HSMs were not tried; SoftHSM, the mock token and one vendor's software
  HSM (see "Another module") were.
- The container image builds and starts; it was not run with a module.
- The musl build is dynamic and passes the whole suite on Alpine. A fully static
  daemon needs the `psk` feature off (or a vendored OpenSSL) and was not built.
- Fuzzing: each of the five libFuzzer targets ran ten minutes in a container
  (15 to 20 million executions each) without a finding. A soak of hours would
  say more.
- PINs and user names are `Secret`s. Key material in templates and passwords
  inside mechanism parameters are not treated that way.
