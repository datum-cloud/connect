# syntax=docker/dockerfile:1
#
# Container image for datum-connectd. Build it with connect-lib as the context:
#
#   docker build -f connect-lib/daemon/Dockerfile connect-lib
#
# The build stage runs on the build host's architecture and cross-compiles for
# TARGETPLATFORM, so multi-arch builds do not compile Rust under emulation.

# Keep in sync with connect-lib/rust-toolchain.toml; the build checks it.
ARG RUST_VERSION=1.98.0
ARG DEBIAN_RELEASE=trixie

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS build
ARG RUST_VERSION
ARG BUILDARCH
ARG TARGETARCH
# The publish workflow passes VERSION; datum-connectd --version reports it.
ARG VERSION=v0.0.0-dev
WORKDIR /src
COPY . .
RUN set -eu; \
    grep -Eq "^channel = \"${RUST_VERSION}\"$" rust-toolchain.toml || { \
      echo "RUST_VERSION ${RUST_VERSION} does not match rust-toolchain.toml" >&2; exit 1; }; \
    case "${TARGETARCH}" in \
      amd64) rust_target=x86_64-unknown-linux-gnu; gnu=x86_64-linux-gnu; gcc_pkg=gcc-x86-64-linux-gnu ;; \
      arm64) rust_target=aarch64-unknown-linux-gnu; gnu=aarch64-linux-gnu; gcc_pkg=gcc-aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    packages="pkg-config"; \
    if [ "${TARGETARCH}" = "${BUILDARCH}" ]; then \
      packages="$packages gcc g++ libc6-dev libssl-dev"; \
    else \
      dpkg --add-architecture "${TARGETARCH}"; \
      packages="$packages ${gcc_pkg} g++-$(echo "$gcc_pkg" | cut -d- -f2-) libc6-dev-${TARGETARCH}-cross libssl-dev:${TARGETARCH}"; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends $packages; \
    rm -rf /var/lib/apt/lists/*; \
    echo "$rust_target" > /tmp/rust-target; \
    echo "$gnu" > /tmp/gnu-triple
# RUSTUP_TOOLCHAIN overrides rust-toolchain.toml so rustup does not download
# development components such as rust-analyzer into the build image.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    CARGO_TERM_COLOR=never
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=connectd-target-${TARGETARCH},sharing=locked \
    set -eu; \
    rust_target=$(cat /tmp/rust-target); \
    gnu=$(cat /tmp/gnu-triple); \
    rustup target add "$rust_target"; \
    env_target=$(echo "$rust_target" | tr 'a-z-' 'A-Z_'); \
    env_cc_target=$(echo "$rust_target" | tr '-' '_'); \
    if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      export "CARGO_TARGET_${env_target}_LINKER=${gnu}-gcc"; \
      export "CC_${env_cc_target}=${gnu}-gcc" "CXX_${env_cc_target}=${gnu}-g++" "AR_${env_cc_target}=${gnu}-ar"; \
      export PKG_CONFIG_ALLOW_CROSS=1 "PKG_CONFIG_LIBDIR=/usr/lib/${gnu}/pkgconfig:/usr/share/pkgconfig"; \
    fi; \
    # Release tags arrive as v0.0.0-1.2.3[-pre]; report them as v1.2.3[-pre].
    version=$(echo "${VERSION}" | sed -E 's/^v0\.0\.0-([0-9]+\.[0-9]+\.[0-9]+)/v\1/'); \
    DATUM_CONNECT_RELEASE_VERSION="$version" \
      cargo build --locked --release -p datum-connect-daemon --target "$rust_target"; \
    install -D -m 0755 "target/$rust_target/release/datum-connectd" /out/datum-connectd

FROM debian:${DEBIAN_RELEASE}-slim
ARG VERSION=v0.0.0-dev
LABEL org.opencontainers.image.title="datum-connectd" \
      org.opencontainers.image.description="Datum Connect daemon with a self-configuring container entrypoint" \
      org.opencontainers.image.source="https://github.com/datum-cloud/connect" \
      org.opencontainers.image.version="${VERSION}"
# libssl3t64 is a runtime dependency of the daemon's HTTP client. jq lets the
# entrypoint build and read API JSON without hand-written parsing.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl jq libssl3t64; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 65532 connect; \
    useradd --system --uid 65532 --gid 65532 --home-dir /var/lib/datum-connect \
      --no-create-home --shell /usr/sbin/nologin connect; \
    install -d -m 0700 -o 65532 -g 65532 /var/lib/datum-connect
COPY --from=build /out/datum-connectd /usr/local/bin/datum-connectd
COPY --chmod=0755 daemon/container/connectd-container /usr/local/bin/connectd-container
ENV DATUM_CONNECT_DIR=/var/lib/datum-connect \
    HOME=/var/lib/datum-connect
USER 65532:65532
WORKDIR /var/lib/datum-connect
VOLUME ["/var/lib/datum-connect"]
ENTRYPOINT ["/usr/local/bin/connectd-container"]
