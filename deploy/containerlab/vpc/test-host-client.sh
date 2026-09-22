#!/usr/bin/env bash
#
# Like test-3region.sh, but the "local" client runs on THIS host (bare metal,
# creating a real TUN in the host's network namespace) while the VPC — three
# regions plus the router — runs in containers. Proves a real machine can join
# the containerized VPC over iroh.
#
# Two things differ from the all-in-containers test:
#   1. The host client needs root (CAP_NET_ADMIN) to create/configure its TUN,
#      so you run that one command under sudo yourself. Nothing here calls sudo.
#   2. The router (in a container) dials the host purely by iroh EndpointId —
#      no ip/port — resolved through iroh discovery, the same as a real
#      deployment. Both ends reach n0 discovery + Datum relays over the
#      container/host's normal outbound internet.
#
# Because the host step needs your sudo and must start first (it's the iroh
# accept side, and prints the endpoint id the router then dials), this is
# a three-step manual flow rather than one shot:
#
#   ./test-host-client.sh up                 # build + stand up the containerized VPC, print the host command
#   sudo env ... datum-connect ... vpc join  # (printed by `up`) run on the host; note its endpoint id
#   ./test-host-client.sh dial <endpoint-id> # router dials the host by id (iroh discovery); then ping across
#   ./test-host-client.sh down               # tear down (Ctrl+C the host client separately)
#
set -euo pipefail

IMAGE=connect-vpc-lab:latest
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HOST_BIN="${REPO_ROOT}/connect-lib/target/debug/datum-connect"

PREFIX=vpchost
TRANSPORT_NET=${PREFIX}-transport
declare -a REGIONS=(a b c)

VPC_AGGREGATE=fd00:cafe::/32
TUN_LOCAL=fd00:cafe:100::2      # the host client's VPC address
TUN_ROUTER=fd00:cafe:100::1
TUN_PLEN=64
ROUTER_XPORT=172.29.0.3

region_addr() { echo "fd00:cafe:${1}::1"; }
router_addr() { echo "fd00:cafe:${1}::ff"; }
region_net()  { echo "${PREFIX}-region-${1}"; }
region_ctr()  { echo "${PREFIX}-region-${1}"; }
ROUTER_CTR=${PREFIX}-router

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

teardown() {
  log "Tearing down containers/networks (host client, if running, must be stopped separately)"
  docker rm -f "${ROUTER_CTR}" >/dev/null 2>&1 || true
  for r in "${REGIONS[@]}"; do docker rm -f "$(region_ctr "$r")" >/dev/null 2>&1 || true; done
  docker network rm "${TRANSPORT_NET}" >/dev/null 2>&1 || true
  for r in "${REGIONS[@]}"; do docker network rm "$(region_net "$r")" >/dev/null 2>&1 || true; done
}

cmd_up() {
  if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    log "Building ${IMAGE}"
    docker build -f "${REPO_ROOT}/deploy/containerlab/vpc/Dockerfile" -t "${IMAGE}" "${REPO_ROOT}"
  fi
  if [[ ! -x "${HOST_BIN}" ]]; then
    log "Building the host datum-connect binary"
    ( cd "${REPO_ROOT}/connect-lib" && cargo build -p datum-connect )
  fi

  teardown

  log "Creating networks"
  docker network create --subnet 172.29.0.0/24 "${TRANSPORT_NET}" >/dev/null
  for r in "${REGIONS[@]}"; do
    docker network create --ipv6 --subnet "fd00:cafe:${r}::/64" \
      --gateway "fd00:cafe:${r}::ffff" "$(region_net "$r")" >/dev/null
  done

  log "Starting region devices"
  for r in "${REGIONS[@]}"; do
    docker run -d --name "$(region_ctr "$r")" --network "$(region_net "$r")" \
      --ip6 "$(region_addr "$r")" --cap-add=NET_ADMIN "${IMAGE}" sleep infinity >/dev/null
    docker exec "$(region_ctr "$r")" \
      ip -6 route replace "${VPC_AGGREGATE}" via "$(router_addr "$r")" >/dev/null
  done

  log "Starting router (L3 hub) and attaching it to every regional segment"
  docker run -d --name "${ROUTER_CTR}" --network "${TRANSPORT_NET}" --ip "${ROUTER_XPORT}" \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --sysctl net.ipv6.conf.default.forwarding=1 \
    "${IMAGE}" sleep infinity >/dev/null
  for r in "${REGIONS[@]}"; do
    docker network connect --ip6 "$(router_addr "$r")" "$(region_net "$r")" "${ROUTER_CTR}" >/dev/null
  done

  cat <<EOF

$(log "Containerized VPC is up. Now run the CLIENT on this host, as root:")

  sudo env \\
    DATUM_CONNECT_DIR=/tmp/${PREFIX}-datum \\
    DATUM_SESSION=lab \\
    DATUM_CREDENTIALS_HELPER=${REPO_ROOT}/deploy/containerlab/vpc/fake-credentials-helper.sh \\
    DATUM_API_HOST=https://api.lab.invalid \\
    ${HOST_BIN} --json vpc join \\
      --vpc lab-host --address ${TUN_LOCAL} --prefix-len ${TUN_PLEN} \\
      --mode vpc-only --vpc-prefix ${VPC_AGGREGATE}

It prints a line like:
  {"type":"vpc_ready", ... "endpoint_id":"<ID>", ...}

Leave it running. Then, with that ID:

  $0 dial <ID>

The router dials the host by endpoint id alone — iroh discovery resolves it, no ip/port.
EOF
}

cmd_dial() {
  local eid="${1:?usage: $0 dial <endpoint-id>}"
  log "router: dialing the host client by endpoint id (via iroh discovery)"
  docker exec -d "${ROUTER_CTR}" sh -c "mock-galactic-router \
    --peer-id ${eid} \
    --address ${TUN_ROUTER} --prefix-len ${TUN_PLEN} > /tmp/router.log 2>&1"

  log "Waiting for the tunnel to come up (host -> region-a)"
  for _ in $(seq 1 30); do
    if ping -6 -c1 -W1 "$(region_addr a)" >/dev/null 2>&1; then break; fi
    sleep 1
  done

  log "Reachability from this host into the VPC"
  local fails=0
  for r in "${REGIONS[@]}"; do
    if ping -6 -c2 -W2 "$(region_addr "$r")" >/dev/null 2>&1; then
      ok "host -> region-${r} ($(region_addr "$r"))"
    else
      bad "host -> region-${r} ($(region_addr "$r"))"; fails=$((fails + 1))
    fi
  done
  if ping -6 -c2 -W2 "${TUN_ROUTER}" >/dev/null 2>&1; then ok "host -> router (${TUN_ROUTER})"; else bad "host -> router (${TUN_ROUTER})"; fails=$((fails + 1)); fi

  log "Reachability from the VPC back to this host (${TUN_LOCAL})"
  for r in "${REGIONS[@]}"; do
    if docker exec "$(region_ctr "$r")" ping -6 -c2 -W2 "${TUN_LOCAL}" >/dev/null 2>&1; then
      ok "region-${r} -> host (${TUN_LOCAL})"
    else
      bad "region-${r} -> host (${TUN_LOCAL})"; fails=$((fails + 1))
    fi
  done

  echo
  if [[ ${fails} -eq 0 ]]; then ok "host client is a full member of the containerized VPC"; else bad "${fails} check(s) failed — see /tmp/router.log in the router container"; return 1; fi
}

case "${1:-}" in
  up)   cmd_up ;;
  dial) shift; cmd_dial "$@" ;;
  down) teardown ;;
  *)    echo "usage: $0 {up|dial <endpoint-id> <port>|down}" >&2; exit 2 ;;
esac
