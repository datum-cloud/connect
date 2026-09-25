#!/usr/bin/env bash
#
# Like test-3region.sh, but the "local" client runs as a bare-metal process
# (creating a real TUN), joining the containerized VPC — three regions plus the
# router — over iroh. The client can be on the SAME machine as the containers or
# on an ENTIRELY DIFFERENT machine/network (a laptop joining a VPC on a remote
# VM); iroh dials it by EndpointId either way.
#
# Roles and where each command runs:
#   - VPC side (the docker host, e.g. a VM): `up`, `dial`, `down`. These are the
#     only commands that touch docker. `dial` drives the ROUTER (a container) to
#     dial the client — it is NOT the client.
#   - Client side (this or any other machine): the `datum-connect vpc join`
#     command that `up` prints, plus `client-check`. These need NO docker — just
#     the datum-connect binary (+ fake-credentials-helper.sh for the join).
#
# Notes:
#   1. The client needs root (CAP_NET_ADMIN) to create/configure its TUN, so you
#      run the join under sudo yourself. Nothing here calls sudo.
#   2. The router dials the client purely by iroh EndpointId — no ip/port —
#      resolved through iroh discovery, the same as a real deployment. Both ends
#      reach n0 discovery + Datum relays over normal outbound internet.
#
# Addressing is split so the client reaches the VPC *only* over the tunnel,
# never via a docker bridge (relevant when the client shares the docker host):
#   - The router<->region fabric ("native", docker) uses fd00:d0c:1{a,b,c}::/64.
#   - Each region's VPC address (fd00:cafe:1{a,b,c}::1) is a /128 on top of that
#     link, reachable only by routing through the router.
#   - Nothing routes fd00:cafe:: except the TUN, so every client->VPC packet
#     goes through iroh. Docker plays no part in the client<->VPC path.
#
# Flow (same-machine: run all on one host; cross-machine: `up`/`dial`/`down` on
# the VM, the join + `client-check` on the laptop):
#
#   [VM]     ./test-host-client.sh up                 # stand up the VPC, print the client command
#   [client] sudo env ... datum-connect ... vpc join  # (printed by `up`) note its endpoint id
#   [client] ./test-host-client.sh client-check        # ping the VPC from the client (no docker)
#   [VM]     ./test-host-client.sh dial <endpoint-id>  # router dials the client; checks VPC->client
#   [VM]     ./test-host-client.sh down                # tear down (Ctrl+C the client separately)
#
# For a remote client, copy datum-connect + fake-credentials-helper.sh (and this
# script, for client-check) to that machine; build datum-connect for its OS/arch.
#
set -euo pipefail

IMAGE=connect-vpc-lab:latest
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HOST_BIN="${REPO_ROOT}/connect-lib/target/debug/datum-connect"

PREFIX=vpchost
TRANSPORT_NET=${PREFIX}-transport
declare -a REGIONS=(a b c)

# VPC prefix (reachable from the host only via the tunnel) and the separate
# docker fabric prefix (router<->region links). The docker prefix (fd00:d0c)
# also can't collide with test-3region.sh's fd00:cafe docker networks.
VPC_AGGREGATE=fd00:cafe::/32
TUN_POOL_CIDR=fd00:cafe:1100::/64
TUN_ROUTER=fd00:cafe:1100::1      # router's own pool address
ROUTER_XPORT=172.29.0.3

# The Nth client address in the pool (N=2 → ::2, N=3 → ::3, …). The router
# allocates sequentially from ::2; this mirrors that for dial/check helpers.
pool_nth() {
  local n="$1"
  printf 'fd00:cafe:1100::%x' "${n}"
}

region_addr()      { echo "fd00:cafe:1${1}::1"; }    # region's VPC address (mesh target, tunnel-only)
region_link_addr() { echo "fd00:d0c:1${1}::1"; }     # region's docker-fabric link address
router_link_addr() { echo "fd00:d0c:1${1}::ff"; }    # router's address on that link
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
    docker network create --ipv6 --subnet "fd00:d0c:1${r}::/64" \
      --gateway "fd00:d0c:1${r}::ffff" "$(region_net "$r")" >/dev/null
  done

  log "Starting region devices"
  for r in "${REGIONS[@]}"; do
    docker run -d --name "$(region_ctr "$r")" --network "$(region_net "$r")" \
      --ip6 "$(region_link_addr "$r")" --cap-add=NET_ADMIN "${IMAGE}" sleep infinity >/dev/null
    # VPC address as a /128 on top of the docker link, reachable only via the
    # router; plus a route for the rest of the VPC back through the router.
    docker exec "$(region_ctr "$r")" \
      ip -6 addr add "$(region_addr "$r")/128" dev eth0 >/dev/null
    docker exec "$(region_ctr "$r")" \
      ip -6 route replace "${VPC_AGGREGATE}" via "$(router_link_addr "$r")" >/dev/null
  done

  log "Starting router (L3 hub) and attaching it to every regional segment"
  docker run -d --name "${ROUTER_CTR}" --network "${TRANSPORT_NET}" --ip "${ROUTER_XPORT}" \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --sysctl net.ipv6.conf.default.forwarding=1 \
    "${IMAGE}" sleep infinity >/dev/null
  for r in "${REGIONS[@]}"; do
    docker network connect --ip6 "$(router_link_addr "$r")" "$(region_net "$r")" "${ROUTER_CTR}" >/dev/null
    # Route each region's VPC /128 to it across the docker link.
    docker exec "${ROUTER_CTR}" \
      ip -6 route replace "$(region_addr "$r")/128" via "$(region_link_addr "$r")" >/dev/null
  done

  cat <<EOF

$(log "Containerized VPC is up. Now run the CLIENT (this machine, or a remote one), as root:")

  sudo env \\
    DATUM_CONNECT_DIR=/tmp/${PREFIX}-datum \\
    DATUM_SESSION=lab \\
    DATUM_CREDENTIALS_HELPER=<path to>/fake-credentials-helper.sh \\
    DATUM_API_HOST=https://api.lab.invalid \\
    <path to>/datum-connect --json vpc join \\
      --vpc lab-host --mode vpc-only

  (on THIS machine the paths are:
     helper = ${REPO_ROOT}/deploy/containerlab/vpc/fake-credentials-helper.sh
     binary = ${HOST_BIN}
   on a remote client, copy those two files over — build datum-connect for its OS/arch.)

The router allocates an address from --pool and sends it to the client; the client
configures its TUN from that assignment automatically.

It prints a line like:
  {"type":"vpc_ready", ... "endpoint_id":"<ID>", "address":"<assigned>", ...}

Leave it running, then:

  [on the client] $0 client-check <assigned-address>  # ping the VPC from the client (no docker)
  [on the VM]     $0 dial <ID> [<ID2> ...]             # router dials 1+ clients by id

The router dials clients by endpoint id alone — iroh discovery resolves it, no ip/port.
EOF
}

# One IPv6 ping from THIS machine, OS-aware:
#   - Linux `ping -6` takes -W in seconds; macOS uses `ping6`, which has no
#     per-packet reply timeout flag at all (its -W is a valueless flag, not a
#     waittime), so we don't pass one — a single packet returns fast when the
#     tunnel is up.
#   - On macOS we force the source (-S) to the client's VPC address. Otherwise
#     the kernel may pick the utun link-local as the source for a destination in
#     the tunnel's own subnet (the router), which the router can't answer — a
#     macOS source-selection quirk, not a reachability problem (the VPC address
#     is the right source regardless). TUN_LOCAL is this client's VPC address.
host_ping1() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    ping6 -c1 -S "${TUN_LOCAL}" "$1" >/dev/null 2>&1
  else
    ping -6 -c1 -W2 "$1" >/dev/null 2>&1
  fi
}

# Retry a ping a few times before giving up: the iroh connection is dialed by
# endpoint id and comes up via a relay path first, then upgrades to a direct
# path — a brief blip during that upgrade can drop a packet or two. A genuinely
# unreachable target still fails after all attempts.
#   hping: from this machine (client side, OS-aware).
#   cping: from inside a container (always Linux ping).
hping()  { local dst="$1"; for _ in $(seq 1 5); do host_ping1 "${dst}" && return 0; sleep 1; done; return 1; }
cping()  { local ctr="$1" dst="$2"; for _ in $(seq 1 5); do docker exec "${ctr}" ping -6 -c1 -W2 "${dst}" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

# dial: run on the VM (docker side). Drives the router to dial the client by
# endpoint id, then verifies the VPC->client direction from inside the VPC
# (region -> client TUN, via docker exec). It does NOT ping "from the host" —
# the client may be on a different machine; run `client-check` there for the
# client->VPC direction.
cmd_dial() {
  if [[ $# -eq 0 ]]; then
    echo "usage: $0 dial <endpoint-id> [<endpoint-id> ...]" >&2; exit 2
  fi

  # Build --peer-id flags for each endpoint id.
  local peer_args=()
  local -a client_addrs=()
  local idx=2
  for eid in "$@"; do
    peer_args+=(--peer-id "${eid}")
    client_addrs+=("$(pool_nth "${idx}")")
    idx=$((idx + 1))
  done

  log "router: dialing ${#peer_args[@]} client(s) by endpoint id (via iroh discovery)"
  docker exec -d "${ROUTER_CTR}" sh -c "mock-galactic-router \
    ${peer_args[*]} \
    --address ${TUN_ROUTER} --pool ${TUN_POOL_CIDR} \
    --advertise ${VPC_AGGREGATE} > /tmp/router.log 2>&1"

  # Gate on the tunnel from the VPC side: a region reaching the first client's
  # assigned address means the router dialed in and the tunnel + forwarding are
  # up. iroh comes up via a relay path first and upgrades to a direct path, which
  # can take longer than a few seconds, so wait generously.
  local first_client="${client_addrs[0]}"
  log "Waiting for the tunnel to settle (region-a -> client ${first_client} over iroh, up to 90s)"
  local up=0
  for _ in $(seq 1 90); do
    if docker exec "$(region_ctr a)" ping -6 -c1 -W1 "${first_client}" >/dev/null 2>&1; then up=1; break; fi
    sleep 1
  done
  if [[ ${up} -eq 0 ]]; then
    bad "tunnel did not settle (region-a -> ${first_client} never succeeded)"
    echo "--- router.log ---"; docker exec "${ROUTER_CTR}" cat /tmp/router.log 2>/dev/null || true
    return 1
  fi

  local fails=0
  for addr in "${client_addrs[@]}"; do
    log "Reachability from the VPC to client (${addr})"
    for r in "${REGIONS[@]}"; do
      if cping "$(region_ctr "$r")" "${addr}"; then
        ok "region-${r} -> client (${addr})"
      else
        bad "region-${r} -> client (${addr})"; fails=$((fails + 1))
      fi
    done
  done

  echo
  if [[ ${fails} -eq 0 ]]; then
    ok "VPC -> all client(s) reachable. Run '$0 client-check <addr>' ON EACH CLIENT for the client -> VPC direction."
  else
    bad "${fails} check(s) failed — see /tmp/router.log in the router container"; return 1
  fi
}

# client-check: run on the CLIENT machine (no docker). Pings every VPC device
# from the client, proving the client->VPC direction over the tunnel.
# Usage: $0 client-check [<my-assigned-address>]
# The assigned address is optional — if omitted, defaults to fd00:cafe:1100::2
# (first client in the pool).
cmd_client_check() {
  local my_addr="${1:-fd00:cafe:1100::2}"
  log "Waiting for the tunnel to settle (client ${my_addr} -> router over iroh)"
  local up=0
  for _ in $(seq 1 90); do
    if host_ping1 "${TUN_ROUTER}"; then up=1; break; fi
    sleep 1
  done
  if [[ ${up} -eq 0 ]]; then
    bad "tunnel did not settle (client -> ${TUN_ROUTER} never succeeded)"
    bad "is the client's 'vpc join' running, and has the VM run '$0 dial <id>'?"
    return 1
  fi

  log "Reachability from the client (${my_addr}) into the VPC"
  local fails=0
  for r in "${REGIONS[@]}"; do
    if hping "$(region_addr "$r")"; then
      ok "client -> region-${r} ($(region_addr "$r"))"
    else
      bad "client -> region-${r} ($(region_addr "$r"))"; fails=$((fails + 1))
    fi
  done
  if hping "${TUN_ROUTER}"; then ok "client -> router (${TUN_ROUTER})"; else bad "client -> router (${TUN_ROUTER})"; fails=$((fails + 1)); fi

  echo
  if [[ ${fails} -eq 0 ]]; then ok "client reaches the whole VPC over the tunnel"; else bad "${fails} check(s) failed"; return 1; fi
}

case "${1:-}" in
  up)           cmd_up ;;
  dial)         shift; cmd_dial "$@" ;;
  client-check) shift; cmd_client_check "$@" ;;
  down)         teardown ;;
  *)    echo "usage: $0 {up|dial <id> [<id>...]|client-check [<addr>]|down}" >&2; echo "  up/dial/down run on the docker host (VM); client-check runs on the client machine (no docker)" >&2; exit 2 ;;
esac
