#!/usr/bin/env bash
# Publishes a release-signed APK to the public download bucket for people who
# do not have the app yet. Existing users can update with share-apk.sh.
#
#   scripts/publish-apk.sh [APK]
#
# Uploads, under s3://$BUCKET/connect/android/:
#   datum-connect-YYYYMMDD-<sha256[:12]>.apk   immutable; date is the APK's build date (UTC)
#   index.html                                 download page for the newest build
#   latest.json                                newest build's name, version, and checksum
#
# Environment:
#   BUCKET       default datum-download
#   REGION       default us-east-2
#   AWS_PROFILE  AWS credentials to use
#
# Run inside `nix develop .#android` so apksigner and aapt2 are available.
set -euo pipefail

cd "$(dirname "$0")/.."
apk="${1:-app/build/outputs/apk/release/app-release.apk}"
bucket="${BUCKET:-datum-download}"
region="${REGION:-us-east-2}"
prefix="connect/android"
build_tools="${ANDROID_HOME:?run inside nix develop .#android}/build-tools/35.0.0"

[[ -f "$apk" ]] || { echo "APK not found: $apk" >&2; exit 1; }

# Refuse unsigned and debug-signed builds: once people install from here, every
# later update must carry the same signing key.
certs=$("$build_tools/apksigner" verify --print-certs "$apk" 2>&1) || {
  echo "APK signature does not verify:" >&2
  echo "$certs" >&2
  exit 1
}
if grep -q "CN=Android Debug" <<<"$certs"; then
  echo "Refusing to publish a debug-signed APK; build with DATUM_CONNECT_SIGNING set" >&2
  exit 1
fi
cert=$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' <<<"$certs")

sha=$(sha256sum "$apk" | cut -d' ' -f1)
date=$(date -u -r "$apk" +%Y%m%d)
name="datum-connect-${date}-${sha:0:12}.apk"
badging=$("$build_tools/aapt2" dump badging "$apk")
version_code=$(sed -n "s/.*versionCode='\([0-9]*\)'.*/\1/p" <<<"$badging" | head -1)
version_name=$(sed -n "s/.*versionName='\([^']*\)'.*/\1/p" <<<"$badging" | head -1)
size_mb=$(( $(stat -c %s "$apk") / 1048576 ))
base="https://${bucket}.s3.${region}.amazonaws.com/${prefix}"

# Inline the logo; drop its provenance comment from the page.
logo=$(grep -v '^<!--' scripts/datum-logo.svg)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/latest.json" <<JSON
{
  "name": "$name",
  "url": "$base/$name",
  "sha256": "$sha",
  "versionCode": $version_code,
  "versionName": "$version_name",
  "built": "$date",
  "signingCertSha256": "$cert"
}
JSON

cat > "$work/index.html" <<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Datum Connect for Android</title>
<style>
:root{color-scheme:light dark}
body{font-family:ui-sans-serif,system-ui,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol','Noto Color Emoji';margin:1.25rem;line-height:1.5;max-width:40rem}
header{margin:.5rem 0 1.5rem}
header svg{display:block;height:28px;width:auto}
h1{font-weight:600;letter-spacing:-.01em}
a.btn{display:inline-block;font-size:1.1rem;padding:.7rem 1rem;border-radius:8px;background:#4f46e5;color:#fff;text-decoration:none}
code{word-break:break-all}
small{opacity:.75}
</style></head>
<body>
<header><a href="https://www.datum.net/" style="color:inherit">$logo</a></header>
<h1>Datum Connect for Android</h1>
<p>Open services shared from your computer with <code>datumctl connect local</code>. No account needed.</p>
<p><a class="btn" href="$name">Download APK (${size_mb} MB)</a></p>
<p><small>Build $date, version <code>$version_name</code>. Android 10 or later.
Allow installs from your browser when Android asks.</small></p>
<p><small>File <code>$name</code><br>
SHA-256 <code>$sha</code><br>
Signing certificate SHA-256 <code>$cert</code></small></p>
<p><small>After installing, get newer builds from a computer with
<code>connect-mobile/android/scripts/share-apk.sh</code>.</small></p>
</body></html>
HTML

aws() { command aws --region "$region" "$@"; }
aws s3 cp "$apk" "s3://$bucket/$prefix/$name" \
  --content-type application/vnd.android.package-archive \
  --cache-control "public, max-age=31536000, immutable" --only-show-errors
aws s3 cp "$work/latest.json" "s3://$bucket/$prefix/latest.json" \
  --content-type application/json --cache-control no-cache --only-show-errors
aws s3 cp "$work/index.html" "s3://$bucket/$prefix/index.html" \
  --content-type "text/html; charset=utf-8" --cache-control no-cache --only-show-errors

echo "Published $name"
echo "Download page: $base/index.html"
