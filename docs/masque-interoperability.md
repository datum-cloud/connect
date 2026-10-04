# MASQUE interoperability plan

This document defines “MASQUE interoperable” as conformance to the published
standards below. Active Internet-Drafts are useful experiments, but are not a
release gate because their wire formats can still change.

- RFC 9297: HTTP Datagrams and the Capsule Protocol
- RFC 9298: CONNECT-UDP
- RFC 9484: CONNECT-IP
- RFC 9114: HTTP/3, including extended CONNECT settings
- RFC 9221: QUIC DATAGRAM
- RFC 9931: safe optimistic protocol transitions when HTTP/1.1 support is added

## Current profile

The transport already has extended CONNECT, HTTP/3 DATAGRAM framing with
context ID zero, bounded queues, UDP forwarding, and a CONNECT-IP prototype.
Its public contract is not yet generic MASQUE: it uses iroh identity and private
ALPNs, private routing headers, one CONNECT stream per QUIC connection, and no
DATAGRAM capsule fallback.

CONNECT-UDP now emits the RFC 9298 default URI template for canonical Datum UDP
destinations (`udp-<port>`), advertises `Capsule-Protocol: ?1`, and retains the
private destination header during migration. The server also accepts a
headerless standard request when its target exactly matches an authorized UDP
policy entry. Opaque destination IDs continue to use the legacy `/` request.
This is deliberately policy lookup, not arbitrary target dialing.

## Conformance work

| Area | Required behavior | State / next work |
| --- | --- | --- |
| HTTP/3 endpoint | WebPKI TLS, `h3` ALPN, extended CONNECT and H3 DATAGRAM settings, ordinary DNS authority | Deferred to the gateway/public listener; the shared codec must not depend on iroh identity |
| CONNECT-UDP request | RFC 9298 URI-template expansion, `:protocol = connect-udp`, Capsule Protocol negotiation, host names and IP literals | Default-template parsing/generation and an explicit target-tuple API are present; configurable non-default URI templates remain |
| CONNECT-UDP response | 2xx response with Capsule Protocol negotiation and correct stream errors | Success and policy-denied responses are independently tested; expand transport failure status and `Proxy-Status` coverage |
| HTTP Datagrams | Quarter Stream ID association, context ID zero, unknown-context handling | Independent multi-stream coverage is present, including a patched Quarter Stream ID encoder; add negotiated size and unknown-context cases |
| Capsule fallback | DATAGRAM capsules when QUIC/H3 datagrams are unavailable | Implemented and end-to-end tested in the standards-facing UDP edge with a bounded incremental decoder; extract the existing UDP/IP codecs into one production module |
| CONNECT-IP | RFC 9484 request plus repeated address/route assignments and withdrawals | Prototype supports the default wildcard path and initial configuration only |
| Multiplexing | Multiple concurrent CONNECT streams per HTTP/3 connection | Implemented in the standards-facing edge and tested with three tunnels plus an isolated denied stream; the private iroh listener still uses one stream per connection |
| HTTP/2 and HTTP/1.1 | RFC 9297/9298 mappings; RFC 9931 optimistic-transition safety for HTTP/1.1 | Deferred until the HTTP/3 edge is conformant; advertise only implemented versions |

## Delivery order

1. Extract request, capsule, and HTTP Datagram codecs from the iroh session
   lifecycle. Add RFC examples, malformed inputs, fuzz targets, and bounded
   allocation tests.
2. Add an explicit `(target_host, target_port)` client API and configurable URI
   templates. Keep Datum destination lookup as an authorization layer outside
   the wire codec.
3. Serve concurrent request streams and isolate stream errors from connection
   errors. Add cancellation, draining, idle timeout, and overload behavior.
4. Add reliable DATAGRAM capsules and negotiate either QUIC DATAGRAM or capsule
   delivery per RFC 9297. Test loss, reordering, path-MTU changes, and oversized
   payloads.
5. Complete CONNECT-IP configuration updates and withdrawals, dual-stack
   policy, ICMP/PMTU behavior, and capsule fallback.
6. Put the codec behind an ordinary WebPKI HTTP/3 gateway and test unmodified
   independent clients. Add HTTP/2 and HTTP/1.1 only if those versions are part
   of the advertised product profile.

## Release gates

- At least two independent MASQUE implementations pass UDP and IP tunnel tests.
- Standard requests require no `x-datum-*` header; private headers remain only
  a backward-compatible extension.
- The conformance suite covers malformed URI templates, Structured Fields,
  context IDs, capsules, settings negotiation, stream cancellation, concurrent
  streams, and policy denial without connection-wide failure.
- Targets are resolved only after authentication and authorization. DNS
  rebinding, loopback/link-local/metadata access, amplification, and open-proxy
  behavior have explicit policy tests.
- Every claimed HTTP version has wire captures and automated interop tests; an
  unsupported version or extension is not advertised.

## Local independent-client lab

Run the first end-to-end interoperability gate with:

```sh
task test:masque-interop
```

The task builds a small standards-facing HTTP/3 edge and a separately pinned
Go client using `github.com/quic-go/masque-go`. The process topology is:

```text
masque-go client
  -> WebPKI-style TLS + h3 + RFC 9298 CONNECT-UDP
  -> local interoperability edge
  -> datum-connect/masque-v1 over iroh
  -> Connect transport policy and UDP association
  -> loopback UDP echo origin
```

The test opens three CONNECT-UDP streams on one HTTP/3 connection, rejects a
fourth unauthorized stream with HTTP 403, then performs a bidirectional
datagram round trip on all three allowed streams. It also opens a connection
without QUIC DATAGRAM support and verifies the RFC 9297 DATAGRAM capsule
fallback. This proves Quarter Stream ID routing, stream-isolated policy
rejection, and both unreliable and reliable delivery modes without letting a
denied request reach the origin. It uses an ephemeral self-signed `localhost`
certificate that is trusted only by the spawned client. Test metadata, the
certificate, and service logs are left in the printed temporary artifacts
directory.

This lab proves CONNECT-UDP interoperability at the HTTP/3 edge and exercises
the real Connect UDP transport behind it. It does not yet prove production
certificate provisioning, authentication, standards-facing CONNECT-IP, or
deployed gateway configuration. Those remain explicit release gates above.
