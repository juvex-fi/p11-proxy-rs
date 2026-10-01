SHELL := /bin/bash

PREFIX ?= /usr/local
DESTDIR ?=

# Project name for easy customization
PROJECT_NAME=\033[1;35mp11-proxy\033[0m

# Running `make` alone shows the help
.DEFAULT_GOAL := help

# Function to announce steps
define announce
    @set -e; \
    echo ""; \
    echo -e "$(1) $(PROJECT_NAME):";
endef

# Marking each target as .PHONY to indicate they're not associated with files
.PHONY: help
help: # Show details of each Makefile recipe
	@grep -E '^[^ .]+:.*?#' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?#"}; {printf "\033[1;32m%-30s\033[0m %s\n", $$1, $$2}'

# ---- building ----

.PHONY: build
build: # Debug build of everything (daemon, client library, tools)
	$(call announce,Building)
	cargo build --workspace

.PHONY: release
release: # Optimised build: target/release/p11-daemon and libp11_proxy
	$(call announce,Building release)
	cargo build --release -p p11-daemon -p p11-client

.PHONY: release-nopsk
release-nopsk: # Release build without TLS-PSK (no OpenSSL needed)
	$(call announce,Building release without PSK)
	cargo build --release --no-default-features --features p11-daemon/vendor,p11-client/vendor -p p11-daemon -p p11-client

.PHONY: release-novendor
release-novendor: # Release build without vendor-defined mechanisms and functions
	$(call announce,Building release without vendor support)
	cargo build --release --no-default-features --features p11-daemon/psk,p11-client/psk -p p11-daemon -p p11-client

# ---- testing ----

.PHONY: test
test: # Run all tests here (tests needing SoftHSM skip themselves if it is missing)
	$(call announce,Testing)
	cargo test --workspace

.PHONY: test-novendor
test-novendor: # Test the crates built without vendor support, and check the client library exports none of it
	$(call announce,Testing without vendor support)
	cargo test -p p11-wire -p p11-params -p p11-module --no-default-features
	cargo test -p p11-daemon --no-default-features --features psk
	cargo test -p p11-client --no-default-features --features psk
	scripts/check-novendor.sh

.PHONY: test-fast
test-fast: # Run the tests that need no SoftHSM (the mock-token ones); the SoftHSM ones skip
	$(call announce,Testing (fast))
	P11_SOFTHSM_MODULE=/nonexistent P11_SOFTHSM_UTIL=/nonexistent P11_C_REF_DIR=/nonexistent cargo test --workspace

.PHONY: test-linux
test-linux: check-docker # Run all tests on Linux (Debian, glibc) in a container
	$(call announce,Testing on Linux)
	scripts/linux-test.sh

.PHONY: test-musl
test-musl: check-docker # Run all tests on Alpine (musl) in a container
	$(call announce,Testing on musl)
	IMAGE=rust:1-alpine scripts/linux-test.sh cargo test --workspace --no-fail-fast

.PHONY: test-all
test-all: check lint test test-linux test-musl # Everything: checks, lints, tests here, on glibc and on musl

.PHONY: fuzz-smoke
fuzz-smoke: # A longer seeded mutation run of the fuzz targets (FUZZ_ITERATIONS=200000 by default)
	$(call announce,Fuzzing (seeded))
	FUZZ_ITERATIONS=$${FUZZ_ITERATIONS:-200000} cargo test --release -p p11-testkit --test fuzz_smoke

.PHONY: fuzz
fuzz: check-docker # Coverage-guided fuzzing in a container: make fuzz SECS=120
	$(call announce,Fuzzing)
	scripts/fuzz.sh $${SECS:-60}

.PHONY: seccomp-check
seccomp-check: check-docker # Compare the daemon's real system calls with the seccomp allow-list (Linux container)
	$(call announce,Checking the seccomp list)
	scripts/regen-seccomp.sh

.PHONY: bench
bench: # Compare SoftHSM, this proxy and the C proxy: make bench SECS=2 THREADS=1
	$(call announce,Benchmarking)
	scripts/bench.sh $${SECS:-2} $${THREADS:-1}

.PHONY: c-reference
c-reference: # Build the C implementation for the parity test and benchmark: make c-reference C_SRC=../pkcs11-proxy
	scripts/build-c-reference.sh $${C_SRC:-../pkcs11-proxy}

# ---- code quality ----

.PHONY: check
check: # Type-check everything without building
	cargo check --workspace --all-targets

.PHONY: fmt
fmt: # Format the code
	cargo fmt --all

.PHONY: lint
lint: # Formatting check and clippy with warnings as errors
	$(call announce,Linting)
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: deny
deny: # Check dependencies (licenses, advisories, sources) with cargo-deny
	cargo deny check

# ---- generated files ----

.PHONY: vectors
vectors: # Rewrite the golden wire vectors (only after a deliberate protocol version bump)
	UPDATE_VECTORS=1 cargo test -p p11-wire --test vectors

.PHONY: docs-update
docs-update: # Regenerate the call table in docs/PROTOCOL.md
	UPDATE_DOCS=1 cargo test -p p11-wire --test docs

.PHONY: bindings
bindings: # Regenerate the PKCS11 bindings from the vendored headers (needs bindgen-cli)
	crates/p11-types/regen.sh

# ---- packaging ----

.PHONY: docker
docker: check-docker # Build the daemon image: p11-daemon
	$(call announce,Building the image)
	docker build -f packaging/Dockerfile -t p11-daemon .

.PHONY: install
install: release # Install into $(PREFIX) (DESTDIR for packaging)
	$(call announce,Installing)
	PREFIX=$(PREFIX) DESTDIR=$(DESTDIR) scripts/install.sh

.PHONY: uninstall
uninstall: # Remove what install put under $(PREFIX)
	@echo "Uninstalling from $(DESTDIR)$(PREFIX)..."
	@rm -f $(DESTDIR)$(PREFIX)/bin/p11-daemon $(DESTDIR)$(PREFIX)/lib/libp11_proxy.so $(DESTDIR)$(PREFIX)/lib/libp11_proxy.dylib
	@rm -rf $(DESTDIR)$(PREFIX)/share/doc/p11-proxy $(DESTDIR)$(PREFIX)/share/p11-proxy
	@rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/p11-daemon.service $(DESTDIR)$(PREFIX)/lib/systemd/system/p11-daemon.socket $(DESTDIR)$(PREFIX)/lib/systemd/system/p11-daemon@.service
	@echo "Uninstalled."

# ---- housekeeping ----

.PHONY: check-docker
check-docker: # Check if Docker is running
	@{ \
		docker info > /dev/null 2>&1 || { echo >&2 "Docker is not running. Please start Docker and retry."; exit 1; }; \
	}

.PHONY: clean
clean: # Remove build output (target/, target-linux/, fuzz artifacts)
	cargo clean
	rm -rf target-linux target-fuzz fuzz/artifacts fuzz/corpus
	@echo "Cleaned up build output."
