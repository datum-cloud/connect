# Staging subnet-router lab

This prototype connects an isolated client to private VPC instances through a
Connect peer. It does not require `iroh-gateway` or changes to Compute, Galactic,
or NSO. The VPC router uses source NAT, so the origin sees the router's VPC address.

## Topology

| Instance | Network | Role |
|---|---|---|
| `connect-subnet-lab-client-dfw-us-central-1-0` | `connect-subnet-lab-client` | Client daemon and privileged helper |
| `connect-subnet-lab-router-dfw-us-central-1-0` | `connect-subnet-lab-vpc` | Router daemon, helper, forwarding firewall, and SNAT |
| `connect-subnet-lab-origin-dfw-us-central-1-0` | `connect-subnet-lab-vpc` | HTTP and UDP listeners; no Connect daemon |

These are three Compute `general-purpose` instances with VM-isolated container
runtimes, not three containers sharing a local Docker network. All run in the
DFW staging lab, with `katars` runtime isolation on the same physical node,
`eris-giune`. Each has IPv6-only non-loopback networking. This does not test
cross-host or cross-region connectivity or a macOS client.

## Current validation status

Validated October 2, 2026: both devices enroll and establish peer CONNECT-IP
through the central staging relay. The router workload requests
`net.ipv6.conf.all.forwarding=1` and `net.ipv6.conf.default.forwarding=1` through
the Compute sandbox sysctl API; both values were read back as `1` inside the
updated router. The router uses source NAT, so the origin sees the router's VPC
address rather than the client's overlay address.

The end-to-end checks passed: private VPC HTTP, UDP payloads from zero through
1,232 bytes, ICMP echo, denial of live unapproved TCP/UDP ports, SNAT, route
removal on leave, and successful rejoin. Both sides reported 12 packets sent
and received, zero protocol/MTU errors, and 1,412 bytes of effective QUIC
DATAGRAM IP capacity at the configured 1,280-byte MTU. The client counted four
expected ACL drops for the unapproved-port probes. Connection logs report
`path: relay` (6 ms client RTT, 15 ms router RTT); this does not demonstrate a
direct UDP path.

The lab uses three IPv6-only Compute instances on the same physical DFW staging
worker. This validates VPC subnet access over a relayed peer tunnel, not
cross-host or cross-region connectivity, a direct path, macOS, HA, production
installation, DNS integration, or preservation of the client's original source
address. Do not treat a connected session alone as proof of subnet reachability;
run the data-plane checks above.

## Approve the attachment

Enroll both Connect devices in the same project. On an unattended machine,
provide renewable service-account credentials to `connect up`. On your laptop,
use your ordinary `datumctl login` session.

On the router:

```sh
datumctl connect join staging-vpc --peer connect-subnet-lab-client \
  --advertise-routes fd20:0:27::/48 \
  --allow-tcp 8080 --allow-udp 5353 --allow-ping --project datum-cloud
```

On the client:

```sh
datumctl connect join staging-vpc --peer connect-subnet-lab-router \
  --routes fd20:0:27::/48 \
  --allow-tcp 8080 --allow-udp 5353 --allow-ping --project datum-cloud
```

Both peers must approve the same network name and prefixes. The CLI displays
the generated IPv6 host addresses and exact privileged approval before asking
for administrator consent. Noninteractive commands never elevate. The lab
harness supplies the reviewed root-owned helper approval separately.

The router's operator must also enable IPv6 forwarding and configure narrowly
scoped firewall and SNAT rules. `staging-subnet-lab.py` sets these only inside
the dedicated router instance. It never changes your Mac's networking.

`join` does not create a cloud Network or NetworkBinding. It names a locally
approved attachment to an authenticated Connector. Advertised prefixes are
explicit bilateral approvals, not a claim that the control plane has approved
VPC access. Use only prefixes that you administer.

## Reproduce the test

Select your staging session. Review the three workload names before deploying:

```sh
datumctl apply --project datum-cloud --validate=false \
  -f scripts/staging-subnet-lab.yaml
python3 scripts/staging-subnet-auth.py
```

The authentication script creates a lab service account, a project-scoped
Connector Admin binding in `milo-system`, and a 24-hour key. It prints the key ID
and a private credential-file path, never the credentials. `--resume` reuses
the exact existing identity and binding but issues a new expiring key. You need
permission to create those resources; the script does not bypass IAM.

Build Linux amd64 binaries for `datumctl`, `datumctl-connect`,
`datum-connect-daemon`, and `datum-connect-network-helper` into
`target/staging-subnet-bin/`. Then run:

```sh
python3 scripts/staging-subnet-lab.py deploy --credentials PRIVATE_FILE
python3 scripts/staging-subnet-lab.py attach
python3 scripts/staging-subnet-lab.py test
```

The harness defaults to `datumctl compute exec`. If staging shell sessions are
unavailable, you can explicitly supply `--kubectl-context CONTEXT --namespace
NAMESPACE` for an already-authorized management connection to those same lab
instances. This does not change the Connect data path.

The test checks isolation before joining, HTTP, UDP payloads from zero through
1,232 bytes, ICMP echo, denial of live unapproved TCP/UDP ports, SNAT source
addresses, unprivileged daemon processes, removal of the route on leave, and
successful rejoin. Evidence goes into `target/staging-subnet-evidence/`.

The harness intentionally refuses duplicate process launches or overwriting an
existing root approval. Inspect an interrupted run before continuing. Workload
updates or recreation can erase this lab's ephemeral filesystem. Do not reapply
the workloads after setup unless you intend to rebuild the lab.

For a partial deployment, use `deploy --roles client --skip-origin` to deploy
only the missing client. After fixing an enrollment dependency, use `enroll` to
retry with saved credentials. `upgrade` replaces only the selected lab daemon
binaries and preserves their state; it disconnects active attachments. Run
`enroll` and explicitly rejoin afterward.

## Limits and cleanup

This is a host-to-subnet prototype, not full site-to-site routing. The client
has one approved source address. Guided setup uses IPv6. Attachments require
explicit rejoin after a daemon restart or session failure. The test does not
establish HA, production installation, automatic route approval, DNS integration,
or preservation of original client addresses through the VPC.

The lab remains running for inspection. Delete the two lab Connectors, the
three workloads and two Networks from `staging-subnet-lab.yaml`, the lab key,
the `milo-system/connect-subnet-lab` PolicyBinding, and the `connect-subnet-lab`
ServiceAccount when finished. Delete only these exact lab resources. Revoke
the key before removing credential files; filesystem removal alone does not
revoke access.
