# Run Connect in a container

The `connectd` image runs the Connect daemon, `datum-connectd`, as a
long-lived, unattended container. Its entrypoint, `connectd-container`, reads
the desired configuration from environment variables and applies it through
the daemon's loopback API: it enrolls the Connector, shares services, and opens
local forwards. It needs no TUN device and no extra Linux capabilities.

Use it to:

- share a service from a Kubernetes cluster, such as
  `some-svc.some-ns.svc.cluster.local:8080`, with other Connectors in your
  project; and
- run a forwarder on a VM or container host that dials a shared service and
  makes it available to other hosts on that network.

The container supports `serve` and `dial`. It does not join managed networks.

## Image

The image is published as `ghcr.io/datum-cloud/connectd` for `linux/amd64` and
`linux/arm64`. Every branch push publishes these tags:

| Tag | Example |
| --- | --- |
| `v0.0.0-BRANCH` (moves with the branch) | `v0.0.0-main` |
| `v0.0.0-BRANCH-COMMITDATE` (immutable) | `v0.0.0-main-20261117-153000` |
| `v0.0.0-SHORTSHA` (immutable) | `v0.0.0-1a2b3c4` |

`/` in branch names becomes `-`. Pin an immutable tag or an image digest in
production. `datum-connectd --version` reports the tag that built the image.

The image runs as the non-root user and group `65532`. It stores daemon state
in `/var/lib/datum-connect`. The daemon API listens only on `127.0.0.1:47780`
inside the container, and the image exposes no ports. Connect needs only
outbound access: UDP for direct peer paths and HTTPS (TCP 443) to the Datum API
and relays.

## Environment

The daemon reads these variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `DATUM_CONNECT_DIR` | No | State directory. Defaults to `/var/lib/datum-connect`. Mount a persistent volume here for a stable identity. |
| `DATUM_CONNECT_CREDENTIALS_FILE` | First enrollment | Path to the service-account credentials JSON, usually a read-only Secret mount. |
| `DATUM_CONNECT_DAEMON_PORT` | No | Loopback API port. Defaults to `47780`. |
| `DATUM_CONNECT_RELAY_URLS` | No | Comma-separated relay URLs that override the default relay selection. |
| `RUST_LOG` | No | Daemon log filter. Defaults to `info`. |

The entrypoint reads these variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `DATUM_CONNECT_PROJECT` | Yes, to apply configuration | Project to enroll in. Without it, the container only runs the daemon. |
| `DATUM_CONNECT_NAME` | No | Fixed Connector name. Requires persistent state (see [Identity and state](#identity-and-state)). |
| `DATUM_CONNECT_NAME_HINT` | No | Preferred name when `DATUM_CONNECT_NAME` is unset. Defaults to the container hostname. |
| `DATUM_CONNECT_EPHEMERAL` | No | `true` for a container without persistent state. Cannot be combined with `DATUM_CONNECT_NAME`. Defaults to `false`. |
| `DATUM_CONNECT_SERVICES` | No | Services to share, separated by whitespace. |
| `DATUM_CONNECT_SERVICE_ALLOW` | No | Comma-separated Connector names or keys allowed to use every service in `DATUM_CONNECT_SERVICES`. Empty means the project default. |
| `DATUM_CONNECT_DIALS` | No | Forwards to open, separated by whitespace. |
| `DATUM_CONNECT_RECONCILE_INTERVAL` | No | Seconds between reapplies once everything succeeds. Defaults to `300`. |

### Service entries

Each service entry is `HOST:PORT` or `HOST:PORT/udp`. TCP is the default.

```text
DATUM_CONNECT_SERVICES="some-svc.some-ns.svc.cluster.local:8080 dns.some-ns.svc.cluster.local:53/udp"
```

`HOST` can be any name or address the container can reach. Other Connectors dial
the service by its port, so each port and protocol can be shared once.

### Dial entries

Each dial entry is `CONNECTOR:PORT@BIND_ADDRESS:BIND_PORT`, with an optional
`/udp` suffix. `CONNECTOR` is the serving Connector's name or public key and
`PORT` is the port it shares. The forward listens on `BIND_ADDRESS:BIND_PORT`.
Put IPv6 bind addresses in brackets.

```text
DATUM_CONNECT_DIALS="server-pod:8080@0.0.0.0:8080 server-pod:53@[::]:5353/udp"
```

`BIND_PORT` must be a fixed port from 1 to 65535. Write `BIND_ADDRESS` in
canonical form, such as `::` rather than `0::0`, so that `probe` can match it.

A forward on a non-loopback address, such as `0.0.0.0` or `::`, lets every
host that can reach that address use the remote service with this container's
Connector identity. Connect does not authenticate those hosts. Restrict them
with a firewall, security group, or network policy. The entrypoint uses the
daemon's setup token, which is required for non-loopback forwards. See
[Share a forward with other hosts](private-services.md#share-a-forward-with-other-hosts).

## How the entrypoint applies configuration

The entrypoint starts `datum-connectd` and waits for `GET /v1/health`. It then
reads the setup token from `$DATUM_CONNECT_DIR/daemon_auth/setup.token` and
applies the configuration in order:

1. **Enroll.** If the project is not running, it sends `POST /v1/up` with
   `DATUM_CONNECT_NAME` as `name`, or with the hint as `name_hint`. On first
   enrollment the daemon imports `DATUM_CONNECT_CREDENTIALS_FILE`. A project that
   is already running is left alone, because `up` restarts its connections.
   After a container restart, the daemon reconnects saved projects by itself, and
   the entrypoint waits for that before sending `up`.
2. **Serve.** It sends `POST /v1/services` for each service entry.
3. **Dial.** It sends `POST /v1/dials` with `bind_address` for each dial entry.

The entrypoint retries failed steps with a backoff of up to 60 seconds. Once
every step succeeds, it reapplies the configuration every
`DATUM_CONNECT_RECONCILE_INTERVAL` seconds. Reapplying is idempotent: the daemon
returns `200` for unchanged services and dials and `201` for new ones.

The entrypoint adds configuration and never removes it. If you remove an entry
or change a saved service's allowlist or a forward's address, the daemon
reports a conflict, which the entrypoint logs and retries. Remove the old
configuration through the daemon API or start with a new state volume.

The entrypoint writes one JSON log line per action, such as `apply_up`,
`apply_service`, or `apply_dial`, with a `result` of `applied`, `unchanged`,
`pending`, or `error`. The lines use the same shape as the daemon's logs. They
never include tokens or credentials.

The entrypoint forwards `SIGTERM` and `SIGINT` to the daemon and exits with the
daemon's status. If the daemon exits on its own, the entrypoint exits non-zero
so the container restarts. The daemon can take up to 30 seconds to stop
cleanly; allow a termination grace period of at least 45 seconds.

## Readiness probe

`connectd-container probe` exits `0` only when all of the following are true:

- the daemon API answers `GET /v1/health`;
- the project is enrolled, intended up, and running, under
  `DATUM_CONNECT_NAME` when that is set;
- every service entry has a saved service with the same endpoint and protocol
  that is active and running; and
- every dial entry has a running forward with the same Connector, port, bind
  address, bind port, and protocol.

Otherwise it prints the first unmet condition and exits `1`. Without
`DATUM_CONNECT_PROJECT`, it checks only the daemon API. A running service means
the Connector advertises it; the probe does not check the application behind
it.

Use the probe for readiness or health checks. Avoid it as a Kubernetes liveness
probe: a control-plane outage would then restart healthy pods. The entrypoint
already exits when the daemon fails.

## Identity and state

A Connector's identity is its key, which the daemon generates and stores in
`DATUM_CONNECT_DIR`. Services, allowlists, and forwards pin keys, not names.

**Stable identity.** Mount a persistent volume at `DATUM_CONNECT_DIR` and set
`DATUM_CONNECT_NAME`. The container keeps its key and name across restarts and
upgrades, so other Connectors can allow it by name with `--allow` or
`DATUM_CONNECT_SERVICE_ALLOW`. The daemon copies the credentials into this
volume at first enrollment and renews them there. Later changes to the mounted
credentials file do not affect an enrolled volume.

Run exactly one replica for each Connector identity. Two containers that share
a volume or a name either fail to enroll or compete for the same Connector. In
Kubernetes, use a StatefulSet with one replica, not a Deployment, so a new pod
does not start before the old one stops.

**Ephemeral identity.** Without persistent storage, every new container
generates a new key. Set `DATUM_CONNECT_EPHEMERAL=true` and leave
`DATUM_CONNECT_NAME` unset. The entrypoint then enrolls with a name hint, which
defaults to the hostname. The daemon does not make a hinted name unique. If an
earlier container's Connector still owns the name, enrollment fails with a
conflict, and the entrypoint retries under the hint plus a random 6-character
suffix, such as `client-vm-3fa91c`. It never adopts or deletes the existing
Connector. Delete stale Connectors from the project yourself.

Because each new ephemeral container has a new key, an allowlist that names it
stops matching after it is recreated. An ephemeral dialer should rely on the
serving Connector's default project-wide access, which applies when
`DATUM_CONNECT_SERVICE_ALLOW` or `--allow` is empty. If the server needs an
explicit allowlist, give the dialer a stable name and persistent storage.

## Kubernetes example

This StatefulSet shares an in-cluster Service. It runs one replica with a
persistent volume for its state and a Secret for its credentials. It runs
without extra capabilities and with a read-only root filesystem.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: connect-credentials
type: Opaque
stringData:
  credentials.json: |
    REPLACE WITH THE SERVICE-ACCOUNT CREDENTIALS JSON
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: connect-server
spec:
  serviceName: connect-server
  replicas: 1 # Exactly one replica per Connector identity.
  selector:
    matchLabels:
      app: connect-server
  template:
    metadata:
      labels:
        app: connect-server
    spec:
      terminationGracePeriodSeconds: 45
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: connectd
          image: ghcr.io/datum-cloud/connectd:v0.0.0-SHORTSHA
          env:
            - name: DATUM_CONNECT_PROJECT
              value: my-project
            - name: DATUM_CONNECT_NAME
              value: some-svc-server
            - name: DATUM_CONNECT_CREDENTIALS_FILE
              value: /etc/datum-connect/credentials.json
            - name: DATUM_CONNECT_SERVICES
              value: some-svc.some-ns.svc.cluster.local:8080
          readinessProbe:
            exec:
              command: ["connectd-container", "probe"]
            initialDelaySeconds: 10
            periodSeconds: 15
            timeoutSeconds: 10
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
          volumeMounts:
            - name: state
              mountPath: /var/lib/datum-connect
            - name: credentials
              mountPath: /etc/datum-connect
              readOnly: true
      volumes:
        - name: credentials
          secret:
            secretName: connect-credentials
            defaultMode: 0400
  volumeClaimTemplates:
    - metadata:
        name: state
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 100Mi
```

The pod needs outbound access to the Datum API, relays, and peers. If a
NetworkPolicy restricts egress, allow UDP and TCP 443 to the internet, and DNS.

## Dial forwarder example

This single container dials the service above and listens on all IPv4
addresses on port 8080, so other hosts on the same network can use it. It has
no persistent state, so it uses an ephemeral identity and relies on the
server's default project-wide access.

```sh
docker run -d --name connect-forwarder --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /var/lib/datum-connect:uid=65532,gid=65532,mode=0700 \
  -v /etc/datum-connect/credentials.json:/etc/datum-connect/credentials.json:ro \
  -e DATUM_CONNECT_PROJECT=my-project \
  -e DATUM_CONNECT_EPHEMERAL=true \
  -e DATUM_CONNECT_CREDENTIALS_FILE=/etc/datum-connect/credentials.json \
  -e DATUM_CONNECT_DIALS="some-svc-server:8080@0.0.0.0:8080" \
  -p 8080:8080 \
  --stop-timeout 45 \
  --health-cmd "connectd-container probe" --health-interval 15s \
  ghcr.io/datum-cloud/connectd:v0.0.0-SHORTSHA
```

The credentials file must be readable by UID `65532`. Other hosts connect to
port 8080 on this host. Restrict which hosts can reach it with your network's
firewall rules. To keep a stable identity instead, replace the `tmpfs` with a
persistent volume and replace `DATUM_CONNECT_EPHEMERAL` with
`DATUM_CONNECT_NAME`.
