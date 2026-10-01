# Fuzzing

Coverage-guided fuzzers for everything that parses bytes from a peer. They
need a nightly toolchain and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run request      # one call's request/response decoder
cargo +nightly fuzz run frame        # frames and the handshake
cargo +nightly fuzz run dispatch     # sequences of requests against the daemon core
cargo +nightly fuzz run mech         # mechanism parameter trees against every descriptor
cargo +nightly fuzz run stream       # a whole connection
```

`../scripts/fuzz.sh` runs them all for a given time in a Linux container.
The target bodies are ordinary functions in `crates/p11-testkit/src/fuzz.rs`;
`cargo test` runs them over a seeded mutation of the golden vectors
(`FUZZ_ITERATIONS` raises the count), so a plain test run catches regressions.
Seeds for the corpus: `scripts/fuzz.sh` writes the golden vectors into
`fuzz/corpus/<target>/`.
