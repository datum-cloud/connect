#!/usr/bin/env bash
# Builds macOS archives of datumctl-connect and datum-connectd for Apple
# silicon (arm64) and Intel (x86_64). Run on a Mac with Xcode command line
# tools, rustup, and Go. Output: dist/share/datum-connect-macos-<arch>.tar.gz;
# publish with scripts/downloads/publish-cli.sh macos.
#
#   scripts/build-macos-share.sh
#
# The binaries are not Developer ID signed or notarized. The linker gives them
# the ad-hoc signature Apple silicon requires; a browser download is still
# quarantined by Gatekeeper, so the download page installs with curl.
set -euo pipefail

[[ "$(uname -s)" == Darwin ]] || { echo "run this on macOS" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist/share"
version=$(git -C "$root" describe --tags --always --dirty)
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/connect-lib/rust-toolchain.toml")

rustup target add --toolchain "$toolchain" aarch64-apple-darwin x86_64-apple-darwin
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  (cd "$root/connect-lib" && DATUM_CONNECT_RELEASE_VERSION="${version#v}" \
    cargo build --locked --release -p datum-connect-daemon --target "$target")
done

rm -f "$out"/datum-connect-macos-*.tar.gz
mkdir -p "$out"
for arch in arm64 x86_64; do
  case $arch in
    arm64) target=aarch64-apple-darwin goarch=arm64 ;;
    x86_64) target=x86_64-apple-darwin goarch=amd64 ;;
  esac
  stage="$out/datum-connect-macos-$arch"
  rm -rf "$stage"
  mkdir -p "$stage"
  install -m 755 "$root/connect-lib/target/$target/release/datum-connectd" "$stage/datum-connectd"
  (cd "$root/connect-plugin" && CGO_ENABLED=0 GOOS=darwin GOARCH=$goarch \
    go build -buildvcs=false -trimpath -ldflags "-X main.version=$version" -o "$stage/datumctl-connect" .)
  cp "$root/LICENSE" "$stage/"
  echo "$version" > "$stage/VERSION"
  for binary in datum-connectd datumctl-connect; do
    file "$stage/$binary" | grep -q "$( [[ $arch == arm64 ]] && echo arm64 || echo x86_64 )" \
      || { echo "$stage/$binary is not $arch" >&2; exit 1; }
  done
  # Keep extended attributes such as quarantine out of the archive.
  COPYFILE_DISABLE=1 tar -C "$out" --no-xattrs -czf "$out/datum-connect-macos-$arch.tar.gz" "datum-connect-macos-$arch"
  rm -rf "$stage"
done

# Smoke test the build for this Mac's architecture.
host=$(uname -m)
tmp=$(mktemp -d)
tar -C "$tmp" -xzf "$out/datum-connect-macos-$host.tar.gz"
"$tmp/datum-connect-macos-$host/datumctl-connect" version
rm -rf "$tmp"
ls -l "$out"
