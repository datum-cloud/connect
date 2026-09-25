#!/bin/sh
# Emulates `datumctl auth get-token --session <session>` for this lab only.
#
# `vpc join` doesn't call the Datum Cloud API for anything yet (see
# ../../../design/vpc-attachment.md — this scaffold takes a VPCAttachment's
# would-be effects as CLI flags instead of a real control plane), but
# datum-connect's shared startup path always constructs an
# ExternalTokenSource, which always executes $DATUM_CREDENTIALS_HELPER and
# parses its stdout as a JWT — so a fake one is needed even here. This is
# never a stand-in for real authentication; do not point real credentials
# helpers at this file or vice versa.
set -eu

b64() {
  printf '%s' "$1" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

exp=$(($(date +%s) + 3600))
header=$(b64 '{"alg":"none","typ":"JWT"}')
payload=$(b64 "{\"sub\":\"lab\",\"exp\":${exp}}")
echo "${header}.${payload}.fake-signature"
