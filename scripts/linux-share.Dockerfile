# Builds datum-connectd for Linux x86_64 and aarch64 against Ubuntu 22.04's
# glibc (2.35) and OpenSSL 3, so the binaries run on Ubuntu 22.04+, Debian 12+,
# and similar distributions. Used by scripts/build-linux-share.sh.
FROM ubuntu:22.04

ARG RUST_VERSION=1.98.0
ENV DEBIAN_FRONTEND=noninteractive

# arm64 packages come from ports.ubuntu.com; restrict the main mirror to amd64.
RUN dpkg --add-architecture arm64 \
 && sed -i 's/^deb /deb [arch=amd64] /' /etc/apt/sources.list \
 && for suite in jammy jammy-updates jammy-security; do \
      echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports $suite main universe" >> /etc/apt/sources.list; \
    done \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates clang cmake curl git perl pkg-config \
      libssl-dev gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross libssl-dev:arm64 \
 && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION" \
      --target x86_64-unknown-linux-gnu --target aarch64-unknown-linux-gnu
ENV PATH=/root/.cargo/bin:$PATH \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    PKG_CONFIG_ALLOW_CROSS=1
