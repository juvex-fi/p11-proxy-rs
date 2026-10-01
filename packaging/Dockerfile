# p11-daemon and libp11-proxy in a small image.
#
#   docker build -f packaging/Dockerfile -t p11-daemon .
#   docker run --rm -v /etc/pkcs11:/etc/pkcs11:ro -v /usr/lib/softhsm:/module:ro -p 2345:2345 \
#       p11-daemon --config /etc/pkcs11/daemon.toml /module/libsofthsm2.so
#
# The PKCS#11 module to serve, and whatever it needs, is mounted or added by
# a derived image; this one carries only the proxy.
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p p11-daemon -p p11-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/p11-daemon /usr/local/bin/p11-daemon
COPY --from=build /src/target/release/libp11_proxy.so /usr/local/lib/libp11_proxy.so
COPY packaging/daemon.toml.example /etc/pkcs11/daemon.toml.example
USER 65534:65534
EXPOSE 2345
ENTRYPOINT ["/usr/local/bin/p11-daemon"]
