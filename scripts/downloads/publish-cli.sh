#!/usr/bin/env bash
# Publishes command line archives to the public download bucket, then
# re-renders the download page. Works on Linux and macOS.
#
#   scripts/downloads/publish-cli.sh linux [DIST]   after scripts/build-linux-share.sh
#   scripts/downloads/publish-cli.sh macos [DIST]   after scripts/build-macos-share.sh
#
# DIST defaults to dist/share. Uploads, under s3://$BUCKET/connect/<platform>/:
#   datum-connect-<platform>-<arch>-YYYYMMDD-<sha256[:12]>.tar.gz   immutable
#   latest.json                                                       newest archives
#
# Environment:
#   BUCKET       default datum-download
#   REGION       default us-east-2
#   AWS_PROFILE  AWS credentials to use
set -euo pipefail

platform="${1:?usage: publish-cli.sh linux|macos [DIST]}"
root=$(cd "$(dirname "$0")/../.." && pwd)
dist="${2:-$root/dist/share}"
bucket="${BUCKET:-datum-download}"
region="${REGION:-us-east-2}"
prefix="connect/$platform"

case $platform in
  linux) archs=(x86_64 arm64); labels=("Linux x86_64 (amd64)" "Linux arm64 (aarch64)") ;;
  macos) archs=(arm64 x86_64); labels=("macOS Apple silicon (arm64)" "macOS Intel (x86_64)") ;;
  *) echo "platform must be linux or macos" >&2; exit 2 ;;
esac

# GNU and BSD tools disagree on flags; python3 is required for the page anyway.
sha256() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
size() { wc -c < "$1" | tr -d ' '; }
built() { python3 -c 'import datetime,os,sys; print(datetime.datetime.fromtimestamp(os.path.getmtime(sys.argv[1]), datetime.timezone.utc).strftime("%Y%m%d"))' "$1"; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The version comes from the VERSION file the build script writes into each
# archive, so publishing never has to run the binaries.
probe=${archs[0]}
version=$(tar -xzOf "$dist/datum-connect-$platform-$probe.tar.gz" "datum-connect-$platform-$probe/VERSION" | tr -d '[:space:]')
[[ -n "$version" ]] || { echo "could not read VERSION from the $probe archive" >&2; exit 1; }

aws() { command aws --region "$region" "$@"; }
entries=()
first_built=
for i in "${!archs[@]}"; do
  arch=${archs[$i]}
  archive="$dist/datum-connect-$platform-$arch.tar.gz"
  [[ -f "$archive" ]] || { echo "missing $archive" >&2; exit 1; }
  sha=$(sha256 "$archive")
  date=$(built "$archive")
  first_built=${first_built:-$date}
  name="datum-connect-$platform-$arch-$date-${sha:0:12}.tar.gz"
  aws s3 cp "$archive" "s3://$bucket/$prefix/$name" \
    --content-type application/gzip \
    --cache-control "public, max-age=31536000, immutable" \
    --metadata "version-name=$version,sha256=$sha,built=$date,arch=$arch" \
    --only-show-errors
  echo "Published $name"
  entries+=("{\"arch\": \"$arch\", \"label\": \"${labels[$i]}\", \"name\": \"$name\", \"dir\": \"datum-connect-$platform-$arch\", \"sha256\": \"$sha\", \"size\": $(size "$archive")}")
done

joined=$(IFS=,; echo "${entries[*]}")
cat > "$work/latest.json" <<JSON
{"version": "$version", "built": "$first_built", "files": [$joined]}
JSON
python3 -m json.tool "$work/latest.json" > /dev/null
aws s3 cp "$work/latest.json" "s3://$bucket/$prefix/latest.json" \
  --content-type application/json --cache-control no-cache --only-show-errors

"$root/scripts/downloads/page.py" --bucket "$bucket" --region "$region"
