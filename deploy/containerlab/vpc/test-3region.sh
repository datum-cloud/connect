#!/usr/bin/env bash
#
# Repeatable end-to-end test: a 3-region galactic VPC, a router on that VPC,
# and a "local" device joining the VPC through the router over iroh — then a
# full-mesh ping matrix proving every device can reach every other.
#
# Mirrors galactic's own containerlab model (3 regions dfw/sjc/iad, IPv6 ULA,
# full-mesh ping verification — see ../../../../galactic/deploy/containerlab/
# scripts/verify-ns10.sh) but self-contained on plain Docker so it runs and
# verifies without containerlab/root. The canonical containerlab topology is
# vpc-3region.clab.yaml alongside this script; see README.md.
#
# Topology (all containers run the connect-vpc-lab:latest image):
#
#            VPC aggregate fd00:cafe::/32
#
#   region-a ──fd00:cafe:a::/64── ┐
#   fd00:cafe:a::1                 │
#   region-b ──fd00:cafe:b::/64── router ──iroh tunnel──  local
#   fd00:cafe:b::1                 │  (L3 hub,          fd00:cafe:100::2
#   region-c ──fd00:cafe:c::/64── ┘   kernel-forwards   (datum-vpc0)
#   fd00:cafe:c::1                     between all four
#                                      segments)
#   router VPC addrs: fd00:cafe:{a,b,c}::ff, fd00:cafe:100::1 (mock-vpc0)
#
# The router does no VPC-aware routing of its own — it's a plain IPv6
# forwarder. mock-galactic-router only creates its tunnel TUN and pumps
# packets; the kernel forwards between that TUN and the three regional
# segments. That's deliberately the same division of labor a real galactic
# router would have (its VRF/eBPF datapath does the forwarding; see
# ../../../design/vpc-attachment.md §5).
#
# Privileges: needs to talk to the Docker daemon (be in the `docker` group,
# or run this under sudo yourself) and bind /dev/net/tun into two containers.
# Nothing here invokes sudo or tries to elevate — if a docker command is
# denied, supply the privilege yourself.
#
# Usage:
#   ./test-3region.sh            build image if missing, run, verify, tear down
#   ./test-3region.sh --keep     leave the lab up afterwards for inspection
#   ./test-3region.sh --down     just tear down a previous run and exit
#
set -euo pipefail

IMAGE=connect-vpc-lab:latest
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)

PREFIX=vpc3
TRANSPORT_NET=${PREFIX}-transport
declare -a REGIONS=(a b c)

# Static addressing (see the diagram above). The VPC aggregate must actually
# cover the regional subnets: fd00:cafe:{a,b,c,100}::/64 differ in their THIRD
# 16-bit group, so the covering prefix is /32 (fd00:cafe::/32), not /48 — a /48
# fixes the third group and would exclude fd00:cafe:a:: etc. A real gVPC would
# be a tighter block; /32 keeps the lab's addresses short and readable.
VPC_AGGREGATE=fd00:cafe::/32
TUN_LOCAL=fd00:cafe:100::2
TUN_ROUTER=fd00:cafe:100::1
TUN_PLEN=64
LOCAL_XPORT=172.30.0.2   # local's iroh transport (underlay) address
ROUTER_XPORT=172.30.0.3

region_addr()  { echo "fd00:cafe:${1}::1"; }   # region endpoint in the VPC
router_addr()  { echo "fd00:cafe:${1}::ff"; }  # router's address on that segment
region_net()   { echo "${PREFIX}-region-${1}"; }
region_ctr()   { echo "${PREFIX}-region-${1}"; }
LOCAL_CTR=${PREFIX}-local
ROUTER_CTR=${PREFIX}-router

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

teardown() {
  log "Tearing down"
  docker rm -f "${LOCAL_CTR}" "${ROUTER_CTR}" >/dev/null 2>&1 || true
  for r in "${REGIONS[@]}"; do docker rm -f "$(region_ctr "$r")" >/dev/null 2>&1 || true; done
  docker network rm "${TRANSPORT_NET}" >/dev/null 2>&1 || true
  for r in "${REGIONS[@]}"; do docker network rm "$(region_net "$r")" >/dev/null 2>&1 || true; done
}

if [[ "${1:-}" == "--down" ]]; then teardown; exit 0; fi
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

# Build the image if it isn't present. Context is the repo root (see Dockerfile).
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  log "Building ${IMAGE} (not present)"
  docker build -f "${REPO_ROOT}/deploy/containerlab/vpc/Dockerfile" -t "${IMAGE}" "${REPO_ROOT}"
fi

# Idempotent: clear any leftovers from a previous run before starting.
teardown

log "Creating networks"
docker network create --subnet 172.30.0.0/24 "${TRANSPORT_NET}" >/dev/null
for r in "${REGIONS[@]}"; do
  docker network create --ipv6 --subnet "fd00:cafe:${r}::/64" \
    --gateway "fd00:cafe:${r}::ffff" "$(region_net "$r")" >/dev/null
done

log "Starting region devices"
for r in "${REGIONS[@]}"; do
  docker run -d --name "$(region_ctr "$r")" --network "$(region_net "$r")" \
    --ip6 "$(region_addr "$r")" --cap-add=NET_ADMIN \
    "${IMAGE}" sleep infinity >/dev/null
  # Route the whole VPC aggregate back through the router's address on this
  # segment (the on-link /64 stays more specific, so local traffic is direct).
  docker exec "$(region_ctr "$r")" \
    ip -6 route replace "${VPC_AGGREGATE}" via "$(router_addr "$r")" >/dev/null
done

log "Starting local device (iroh accept side)"
docker run -d --name "${LOCAL_CTR}" --network "${TRANSPORT_NET}" --ip "${LOCAL_XPORT}" \
  --cap-add=NET_ADMIN --device=/dev/net/tun "${IMAGE}" sleep infinity >/dev/null

log "Starting router (L3 hub) and attaching it to every regional segment"
docker run -d --name "${ROUTER_CTR}" --network "${TRANSPORT_NET}" --ip "${ROUTER_XPORT}" \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  --sysctl net.ipv6.conf.default.forwarding=1 \
  "${IMAGE}" sleep infinity >/dev/null
for r in "${REGIONS[@]}"; do
  docker network connect --ip6 "$(router_addr "$r")" "$(region_net "$r")" "${ROUTER_CTR}" >/dev/null
done
# Forwarding is enabled via the run-time --sysctl flags above; default.forwarding=1
# means the segment interfaces connected just now inherit forwarding at creation.
# (Some hardened hosts mount the container's /proc/sys read-only, so it can't be
# re-asserted after start — hence setting it at run time instead.)

log "local: joining the VPC through the router"
# The VPC aggregate is routed as a plain dev route out the tunnel: there is only
# one peer on it (the router), which forwards onward to every region.
docker exec -d "${LOCAL_CTR}" sh -c "datumctl-connect vpc join -o json \
  --vpc lab-3region --address ${TUN_LOCAL} --prefix-len ${TUN_PLEN} \
  --mode vpc-only --vpc-prefix ${VPC_AGGREGATE} \
  > /tmp/local.log 2>&1"

# Wait for the client to publish its iroh endpoint id + bound port.
EID=""; PORT=""
for _ in $(seq 1 30); do
  LOCAL_LOG=$(docker exec "${LOCAL_CTR}" cat /tmp/local.log 2>/dev/null || true)
  EID=$(printf '%s' "${LOCAL_LOG}" | grep -oE '"endpoint_id":"[0-9a-f]+"' | head -1 | sed 's/.*:"//;s/"//')
  PORT=$(printf '%s' "${LOCAL_LOG}" | grep -oE '0\.0\.0\.0:[0-9]+' | head -1 | cut -d: -f2)
  [[ -n "${EID}" && -n "${PORT}" ]] && break
  sleep 1
done
if [[ -z "${EID}" || -z "${PORT}" ]]; then
  bad "client never reported an endpoint id / port"; docker exec "${LOCAL_CTR}" cat /tmp/local.log || true
  [[ ${KEEP} -eq 0 ]] && teardown; exit 1
fi
log "client endpoint ${EID} listening on ${LOCAL_XPORT}:${PORT}"

log "router: dialing the client to bring the tunnel up"
docker exec -d "${ROUTER_CTR}" sh -c "mock-galactic-router \
  --peer-id ${EID} --peer-addr ${LOCAL_XPORT}:${PORT} \
  --address ${TUN_ROUTER} --prefix-len ${TUN_PLEN} > /tmp/router.log 2>&1"

# Devices to include in the full mesh: local + the router + the three regions.
# The router joins as a node at its tunnel-side address (fd00:cafe:100::1) — the
# same address on which it terminates the tunnel and forwards; reaching it from a
# region exercises region->router forwarding, from local exercises the direct
# tunnel hop, and the router as a source exercises its own stack toward every
# other device.
declare -A ADDR
ADDR[local]=${TUN_LOCAL}
ADDR[router]=${TUN_ROUTER}
for r in "${REGIONS[@]}"; do ADDR[region-${r}]=$(region_addr "$r"); done
ctr_of() {
  case "$1" in
    local) echo "${LOCAL_CTR}";;
    router) echo "${ROUTER_CTR}";;
    region-*) echo "${PREFIX}-region-${1#region-}";;
  esac
}
DEVICES=(local router region-a region-b region-c)

# Wait for the tunnel/forwarding to converge (local -> region-a is the first
# path that needs both the iroh tunnel and router forwarding working).
log "Waiting for connectivity to converge"
converged=0
for _ in $(seq 1 30); do
  if docker exec "${LOCAL_CTR}" ping -6 -c1 -W1 "${ADDR[region-a]}" >/dev/null 2>&1; then
    converged=1; break
  fi
  sleep 1
done
if [[ ${converged} -eq 0 ]]; then
  bad "tunnel/forwarding did not converge"
  echo "--- local.log ---";  docker exec "${LOCAL_CTR}"  cat /tmp/local.log  2>/dev/null || true
  echo "--- router.log ---"; docker exec "${ROUTER_CTR}" cat /tmp/router.log 2>/dev/null || true
  [[ ${KEEP} -eq 0 ]] && teardown; exit 1
fi

log "Full-mesh ping matrix (${#DEVICES[@]} devices, $(( ${#DEVICES[@]} * (${#DEVICES[@]} - 1) )) ordered pairs)"
fails=0
for src in "${DEVICES[@]}"; do
  for dst in "${DEVICES[@]}"; do
    [[ "${src}" == "${dst}" ]] && continue
    if docker exec "$(ctr_of "${src}")" ping -6 -c2 -W2 "${ADDR[${dst}]}" >/dev/null 2>&1; then
      ok "${src} -> ${dst} (${ADDR[${dst}]})"
    else
      bad "${src} -> ${dst} (${ADDR[${dst}]})"; fails=$((fails + 1))
    fi
  done
done

echo
if [[ ${fails} -eq 0 ]]; then
  ok "all devices can reach all other devices"
  rc=0
else
  bad "${fails} pair(s) could not communicate"
  rc=1
fi

if [[ ${KEEP} -eq 1 ]]; then
  log "Leaving lab up (--keep). Tear down later with: $0 --down"
else
  teardown
fi
exit ${rc}
