#!/usr/bin/env bash
# Publishes the Linux archives from scripts/build-linux-share.sh to the public
# download bucket, then re-renders the download page.
#
#   scripts/downloads/publish-linux.sh [DIST]   (default dist/share)
#
# Uploads, under s3://$BUCKET/connect/linux/:
#   datum-connect-linux-<arch>-YYYYMMDD-<sha256[:12]>.tar.gz   immutable
#   latest.json                                                 newest archives
#
# Environment:
#   BUCKET       default datum-download
#   REGION       default us-east-2
#   AWS_PROFILE  AWS credentials to use
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
dist="${1:-$root/dist/share}"
bucket="${BUCKET:-datum-download}"
region="${REGION:-us-east-2}"
prefix="connect/linux"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The version comes from the built plugin, not from the current checkout.
tar -C "$work" -xzf "$dist/datum-connect-linux-x86_64.tar.gz"
# Capture first: piping into head would SIGPIPE the second line under pipefail.
version_output=$("$work/datum-connect-linux-x86_64/datumctl-connect" version)
version=$(awk 'NR == 1 {print $2}' <<<"$version_output")
[[ -n "$version" ]] || { echo "could not read the plugin version" >&2; exit 1; }

aws() { command aws --region "$region" "$@"; }
entries=()
built=
for arch in x86_64 arm64; do
  archive="$dist/datum-connect-linux-$arch.tar.gz"
  [[ -f "$archive" ]] || { echo "missing $archive" >&2; exit 1; }
  sha=$(sha256sum "$archive" | cut -d' ' -f1)
  date=$(date -u -r "$archive" +%Y%m%d)
  built=${built:-$date}
  name="datum-connect-linux-$arch-$date-${sha:0:12}.tar.gz"
  size=$(stat -c %s "$archive")
  case $arch in
    x86_64) label="Linux x86_64 (amd64)" ;;
    arm64) label="Linux arm64 (aarch64)" ;;
  esac
  aws s3 cp "$archive" "s3://$bucket/$prefix/$name" \
    --content-type application/gzip \
    --cache-control "public, max-age=31536000, immutable" \
    --metadata "version-name=$version,sha256=$sha,built=$date,arch=$arch" \
    --only-show-errors
  echo "Published $name"
  entries+=("{\"arch\": \"$arch\", \"label\": \"$label\", \"name\": \"$name\", \"dir\": \"datum-connect-linux-$arch\", \"sha256\": \"$sha\", \"size\": $size}")
done

joined=$(IFS=,; echo "${entries[*]}")
cat > "$work/latest.json" <<JSON
{"version": "$version", "built": "$built", "files": [$joined]}
JSON
python3 -m json.tool "$work/latest.json" > /dev/null
aws s3 cp "$work/latest.json" "s3://$bucket/$prefix/latest.json" \
  --content-type application/json --cache-control no-cache --only-show-errors

"$root/scripts/downloads/page.py" --bucket "$bucket" --region "$region"
