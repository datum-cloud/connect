#!/usr/bin/env bash
# Shares the Android APK with a phone that already has the Datum Connect app,
# over the same project-less share the app uses. No public URL is involved.
#
#   scripts/share-apk.sh [--no-build] [APK]
#
# Scan the printed QR code in the app, tap Connect, then Open in browser and
# download the APK. Run from connect-mobile/android inside `nix develop .#android`
# unless you pass a prebuilt APK with --no-build.
#
# Environment:
#   RUST_ABIS             ABIs to build (default arm64-v8a)
#   CONNECT               command that runs `connect local` (default: datumctl connect)
#   DATUM_CONNECT_SIGNING release signing properties; when set, builds and shares
#                         the release APK, which phones that installed from the
#                         download bucket require. Otherwise shares a debug build.
set -euo pipefail

cd "$(dirname "$0")/.."
build=1
if [[ "${1:-}" == "--no-build" ]]; then
  build=0
  shift
fi
if [[ -n "${DATUM_CONNECT_SIGNING:-}" ]]; then
  variant=Release
  apk="${1:-app/build/outputs/apk/release/app-release.apk}"
else
  variant=Debug
  apk="${1:-app/build/outputs/apk/debug/app-debug.apk}"
fi
connect="${CONNECT:-datumctl connect}"

# Fail before building if the plugin predates project-less sharing.
if ! $connect local --help >/dev/null 2>&1; then
  echo "\`$connect\` has no local command. Install a newer Connect plugin, or set" >&2
  echo "CONNECT to one, for example CONNECT=../../connect-plugin/datumctl-connect" >&2
  exit 1
fi

if [[ $build == 1 ]]; then
  gradle -q "assemble$variant" -PrustProfile=release -PrustAbis="${RUST_ABIS:-arm64-v8a}"
fi
[[ -f "$apk" ]] || { echo "APK not found: $apk" >&2; exit 1; }

dir=$(mktemp -d)
server_pid=
cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$dir"
}
trap cleanup EXIT

version=$(git -C . describe --tags --always --dirty 2>/dev/null || echo unknown)
cp "$apk" "$dir/datum-connect.apk"
size=$(du -m "$dir/datum-connect.apk" | cut -f1)
sha=$(sha256sum "$dir/datum-connect.apk" | cut -c1-16)
cat > "$dir/index.html" <<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Datum Connect APK</title>
<style>body{font-family:system-ui,sans-serif;margin:1.25rem;line-height:1.5}a{display:inline-block;font-size:1.1rem;padding:.7rem 1rem;border-radius:8px;background:#4f46e5;color:#fff;text-decoration:none}small{color:#555}</style>
</head><body>
<h1>Datum Connect</h1>
<p>Build <code>$version</code>, ${size} MB.</p>
<p><a href="datum-connect.apk" download>Download APK</a></p>
<p><small>SHA-256 starts with <code>$sha</code>. Android replaces the installed app only if this build is signed with the same key.</small></p>
</body></html>
HTML

# Serve on a free loopback port with the APK content type Android expects.
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 - "$dir" "$port" <<'PY' &
import functools, http.server, sys
directory, port = sys.argv[1], int(sys.argv[2])
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
handler.func.extensions_map = {**handler.func.extensions_map, ".apk": "application/vnd.android.package-archive"}
http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
PY
server_pid=$!

echo "Serving $apk on 127.0.0.1:$port"
# Not exec: the trap must run to stop the server and remove the copy.
$connect local --port "$port" --max-peers 1 --name "Datum Connect APK"
