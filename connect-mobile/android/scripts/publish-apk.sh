#!/usr/bin/env bash
# Publishes a release-signed APK to the public download bucket for people who
# do not have the app yet. Existing users can update with share-apk.sh.
#
#   scripts/publish-apk.sh [APK]
#
# Uploads, under s3://$BUCKET/connect/android/:
#   datum-connect-YYYYMMDD-<sha256[:12]>.apk   immutable; date is the APK's build date (UTC)
#   latest.json                                newest build's name, version, and checksum
# then re-renders the download page with scripts/downloads/page.py.
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
base="https://${bucket}.s3.${region}.amazonaws.com/${prefix}"

aws() { command aws --region "$region" "$@"; }

# The version, date, and full checksum ride along as object metadata so the
# page can list this build after newer ones replace it.
aws s3 cp "$apk" "s3://$bucket/$prefix/$name" \
  --content-type application/vnd.android.package-archive \
  --cache-control "public, max-age=31536000, immutable" \
  --metadata "version-code=$version_code,version-name=$version_name,sha256=$sha,built=$date" \
  --only-show-errors

latest=$(mktemp)
trap 'rm -f "$latest"' EXIT
cat > "$latest" <<JSON
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
aws s3 cp "$latest" "s3://$bucket/$prefix/latest.json" \
  --content-type application/json --cache-control no-cache --only-show-errors

echo "Published $name"
../../scripts/downloads/page.py --bucket "$bucket" --region "$region"
