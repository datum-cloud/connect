#!/usr/bin/env bash
# Package a native, explicitly supplied daemon with a freshly built Go plugin.
# This never publishes, tags, installs, or changes any running service.
set -euo pipefail

if [[ $# != 3 ]]; then
  echo "Usage: bash scripts/package-preview.sh vX.Y.Z-preview.N /absolute/daemon /absolute/new-output-dir" >&2
  exit 2
fi
preview_version=$1
preview_daemon=$2
preview_output=$3
if [[ ! "$preview_version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-preview\.[1-9][0-9]*$ ]]; then
  echo "Use a numbered preview tag, for example v1.0.0-preview.1." >&2
  exit 2
fi
if [[ "$preview_daemon" != /* || ! -f "$preview_daemon" || ! -x "$preview_daemon" || -L "$preview_daemon" ]]; then
  echo "Supply an absolute path to a native regular daemon executable, not a symlink." >&2
  exit 2
fi
if [[ "$preview_output" != /* || -e "$preview_output" || -L "$preview_output" ]]; then
  echo "Output must be an absolute path to a new directory; existing output is never overwritten." >&2
  exit 2
fi
preview_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
preview_os=$(uname -s)
case "$preview_os" in
  Darwin|Linux) ;;
  *) echo "This local packager supports native macOS/Linux only; use release CI for Windows." >&2; exit 2 ;;
esac
preview_arch=$(go env GOHOSTARCH)
case "$preview_arch" in
  arm64) preview_archive_arch=arm64 ;;
  amd64) preview_archive_arch=x86_64 ;;
  *) echo "Unsupported architecture: $preview_arch" >&2; exit 2 ;;
esac
preview_daemon_version=$("$preview_daemon" --version)
case "$preview_daemon_version" in
  datum-connect-daemon*) ;;
  *) echo "The supplied executable is not datum-connect-daemon." >&2; exit 2 ;;
esac
mkdir -m 700 "$preview_output"
mkdir -m 700 "$preview_output/bundle"
(
  cd "$preview_repo/connect-plugin"
  CGO_ENABLED=0 GOOS=$(go env GOHOSTOS) GOARCH="$preview_arch" go build -trimpath \
    -ldflags "-X main.version=$preview_version" \
    -o "$preview_output/bundle/datumctl-connect" .
)
install -m 700 "$preview_daemon" "$preview_output/bundle/datum-connect-daemon"
install -m 600 "$preview_repo/docs/INSTALL.txt" "$preview_output/bundle/INSTALL.txt"
install -m 600 "$preview_repo/LICENSE" "$preview_output/bundle/LICENSE"
# Generated build metadata deliberately includes no environment or credentials.
{
  printf 'Plugin release: %s\n' "$preview_version"
  printf 'Daemon reports: %s\n' "$preview_daemon_version"
  printf 'Platform: %s/%s\n' "$preview_os" "$preview_arch"
  printf 'Base commit: %s\n' "$(git -C "$preview_repo" rev-parse HEAD)"
  printf 'Local worktree: %s\n' "$(if [[ -n "$(git -C "$preview_repo" status --porcelain)" ]]; then echo dirty; else echo clean; fi)"
  printf 'Plugin compiler: %s\n' "$(go version)"
  printf 'Daemon is supplied by the caller; its build profile/toolchain are not certified by this packager.\n'
  printf 'Local evaluation bundle; not CI-validated, signed, notarized, or published.\n'
} > "$preview_output/bundle/BUILDINFO.txt"
preview_archive="datumctl-connect_${preview_os}_${preview_archive_arch}.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$preview_output/$preview_archive" -C "$preview_output/bundle" \
  datumctl-connect datum-connect-daemon INSTALL.txt LICENSE BUILDINFO.txt
(
  cd "$preview_output"
  shasum -a 256 "$preview_archive" > checksums.txt
  shasum -a 256 -c checksums.txt
)
install -m 600 "$preview_repo/docs/INSTALL.txt" "$preview_output/INSTALL.txt"
echo "Prepared $preview_output/$preview_archive"
echo "Share the archive, checksums.txt, and INSTALL.txt together. Nothing was published."
