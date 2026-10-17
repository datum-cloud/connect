#!/usr/bin/env bash
# Builds Linux archives of datumctl-connect and datum-connectd for x86_64 and
# arm64, for people who want `datumctl connect local` without the official
# release. Output: dist/share/datum-connect-linux-<arch>.tar.gz; publish with
# scripts/downloads/publish-cli.sh linux.
#
#   scripts/build-linux-share.sh
#
# The daemon builds in an Ubuntu 22.04 container (glibc 2.35, OpenSSL 3); the
# plugin is pure Go and cross-compiles directly. Needs docker and go.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist/share"
image=datum-connect-linux-share
version=$(git -C "$root" describe --tags --always --dirty)

docker build -q -t "$image" -f "$root/scripts/linux-share.Dockerfile" "$root/scripts" >/dev/null
# Cargo's registry and target directory live in volumes so rebuilds are incremental.
docker run --rm \
  -v "$root/connect-lib:/src:ro" \
  -v datum-connect-linux-share-target:/target \
  -v datum-connect-linux-share-cargo:/root/.cargo/registry \
  -e CARGO_TARGET_DIR=/target \
  -e PKG_CONFIG_PATH_aarch64_unknown_linux_gnu=/usr/lib/aarch64-linux-gnu/pkgconfig \
  -e DATUM_CONNECT_RELEASE_VERSION="${version#v}" \
  -w /src "$image" bash -ec '
    for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
      cargo build --locked --release -p datum-connect-daemon --target "$target"
    done'

rm -rf "$out"
mkdir -p "$out"
for arch in x86_64 arm64; do
  case $arch in
    x86_64) target=x86_64-unknown-linux-gnu goarch=amd64 ;;
    arm64) target=aarch64-unknown-linux-gnu goarch=arm64 ;;
  esac
  stage="$out/datum-connect-linux-$arch"
  mkdir -p "$stage"
  docker run --rm -v datum-connect-linux-share-target:/target -v "$stage:/out" "$image" \
    install -m 755 "/target/$target/release/datum-connectd" /out/datum-connectd
  (cd "$root/connect-plugin" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch \
    go build -buildvcs=false -trimpath -ldflags "-X main.version=$version" -o "$stage/datumctl-connect" .)
  cp "$root/LICENSE" "$stage/"
  echo "$version" > "$stage/VERSION"
  tar -C "$out" -czf "$out/datum-connect-linux-$arch.tar.gz" "datum-connect-linux-$arch"
  rm -rf "$stage"
done
ls -l "$out"
