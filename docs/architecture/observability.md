# Observability

Connect exposes layered diagnostics so operators can distinguish a local API,
control-plane convergence, transport, native adapter, gateway, and VPC failure.
Sensitive credentials and packet contents are intentionally excluded.

## Correlation Identifiers

| Identifier | Scope | Use |
| --- | --- | --- |
| `request_id` | One loopback API request | Correlate CLI failure with daemon request log |
| `traceparent` | Cross-process traced operation | Continue setup/session traces at the gateway |
| `session_id` | One CONNECT-IP session | Correlate client and gateway health and close events |
| Connector public key | Device identity | Match discovery, policy, and gateway admission |
| project, network, service, dial | User intent | Locate desired and observed state |

## CLI Diagnostics

Verbose client output records method, redacted loopback URL, elapsed time, HTTP
status, and request ID. It never logs authorization headers or request/response
bodies. Transport errors distinguish timeout or reachability failure from a
daemon HTTP rejection.

`datumctl connect status --output json` is the primary joined view. It includes
desired and running state, last failure stages, transport diagnostics, native
adapter names, attachment counters, and current network intent. `doctor` checks
installation and helper readiness without opening an interface.

## Structured Logs

The daemon emits structured request completion, enrollment, reconciliation,
relay, service, dial, and CONNECT-IP lifecycle events. Key network events are:

- `connect_ip_health`, sampled every 10 seconds;
- `connect_ip_attachment_stopped` on the client;
- `connect_ip_session_closed` on the gateway;
- `relay_configuration`, `relay_ready`, and `relay_startup_timeout`.

Health snapshots include packet and byte totals in each direction, QUIC
datagrams, policy drops, protocol and MTU errors, reconnect count, and the last
packet timestamp. Logs record rejected fields and stages without printing
credential values or rejected secrets.

## Metrics

The Connect Gateway service exposes operator-only Prometheus metrics. They are
not exposed on a project VPC interface, regardless of whether gateway capacity
is shared or dedicated. Metrics include:

- active and opened CONNECT-IP sessions;
- transport errors and policy drops;
- datagrams, packets, and bytes by direction;
- effective MTU capacity;
- gateway injection and return-path activity.

The controller exposes its own internal metrics on port 8080 and liveness and
readiness probes on 8081. These are cluster operational endpoints, not project
data-plane interfaces.

## Tracing

Tracing is opt-in. Set `DATUM_CONNECT_OTEL_ENDPOINT`,
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, or `OTEL_EXPORTER_OTLP_ENDPOINT` on both
client daemon and gateway. Export uses batched OTLP/HTTP protobuf with a
three-second request timeout.

The client propagates W3C trace context in CONNECT-IP setup. The gateway
continues the trace and both sides emit setup, session, and periodic health
snapshot spans. Connect does not create one span per packet. Collector failure
does not stop forwarding; it is reported separately in logs.

Trace attributes can include project/network names, peer identifiers, and
connection diagnostics. Collectors therefore need the same retention and
access care as other infrastructure telemetry.

## Diagnosing the Packet Path

Compare counters in this order:

| Observation | Likely segment |
| --- | --- |
| Client adapter count does not advance | Local route, application, or native adapter |
| Client send advances; gateway receive does not | QUIC path, relay, admission, or MTU |
| Gateway receive advances; TUN injection does not | Gateway grant or packet policy |
| Injection advances; NAT/forwarding does not | Gateway OS forwarding, routes, or nftables |
| NAT advances; return does not | VPC route, firewall, destination, or service |
| Gateway return advances; client receive does not | Return QUIC path or local adapter |

Counters identify a segment, not a specific external firewall rule. Combine
them with VPC and gateway-service telemetry for final diagnosis.

## Alerting Guidance

The preview does not ship a complete alert set. Useful production signals are:

- Connector Lease renewal failure or Ready loss;
- repeated project reconciliation failures;
- assigned gateway capacity unavailable or applied-config lag;
- persistent transport errors or MTU capacity below approval;
- growing policy-drop rates;
- desired managed attachment not running;
- absence of expected packet progress while a session is active.

## Related Documentation

- [CONNECT-IP Data Plane](./connect-ip-data-plane.md)
- [Daemon Architecture](../components/daemon-architecture.md)
- [Connect API and controller](../../connect-controller/README.md)
- [Headless preview validation](../headless-preview.md)
