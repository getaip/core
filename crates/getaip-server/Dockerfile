# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.94-alpine@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS builder

RUN apk add --no-cache build-base perl
WORKDIR /workspace
COPY . .
ARG TARGETPLATFORM
# Reuse one locked release tree across all workspace binaries so a fleet
# build does not duplicate multi-gigabyte dependency artifacts per image.
RUN --mount=type=cache,id=aip-cargo-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=aip-cargo-target-${TARGETPLATFORM},target=/workspace/target,sharing=locked \
    rm -f rust-toolchain.toml && \
    cargo build --release -p getaip-server --locked && \
    cp /workspace/target/release/getaip-server /tmp/getaip-server

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
ARG SOURCE_REVISION=unknown
ARG IMAGE_VERSION=2.1.0
LABEL org.opencontainers.image.source="https://github.com/getaip/core" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      dev.getaip.component="getaip-server-core"
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 aip && \
    adduser -S -D -H -u 10001 -G aip aip
COPY --from=builder /tmp/getaip-server /usr/local/bin/getaip-server
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/getaip-server"]
