# Connect two devices directly

Direct device networking gives two Connectors controlled IP connectivity
without a managed project gateway. Use it when software needs IP-level access
and a private service plus local forward is too narrow.

This feature is a preview. Attachments are ephemeral, and both operators must
configure matching intent.

## Choose the policy first

Agree on:

- one network name used on both devices;
- the other device's Connector name;
- the exact inbound TCP or UDP ports each side needs; and
- whether ICMP echo is needed for diagnostics.

Membership by itself grants no traffic access. Each device approves the other
and declares permitted traffic.

## Join from both devices

For example, suppose two devices need TCP port `8080` and ICMP echo.

On the first device:

```sh
datumctl connect join friend --peer THEIR_CONNECTOR --allow-tcp 8080 --allow-ping
```

On the second device, use the same network name and the first device's
Connector name:

```sh
datumctl connect join friend --peer YOUR_CONNECTOR --allow-tcp 8080 --allow-ping
```

Interactive `join` can offer administrator-approved installation of the
networking helper and the exact local interface configuration. The daemon pins
the peer's resolved key and derives matching host addresses.

Use `--allow-udp` for allowed UDP ports. Add only the ports the peer actually
needs.

## Verify connectivity

Check local state and helper health:

```sh
datumctl connect status
datumctl connect doctor
datumctl connect ping THEIR_CONNECTOR
```

The Connect `ping` command checks Connector reachability. Once the interface is
active, use the operating system's tools against the peer's approved address to
test ICMP or an application port.

## Rejoin or leave

Direct attachments are ephemeral. A later interactive join can reuse the saved
configuration:

```sh
datumctl connect join friend
```

Leave the network when it is no longer needed:

```sh
datumctl connect leave friend
```

## Routed direct attachments

Advanced direct setups can add `--routes` on the client and matching
`--advertise-routes` on a routing peer, together with explicit destination-port
permissions. The routing host operator must separately configure forwarding,
firewall policy, and source NAT or return routes. Connect does not enable those
system-wide settings, and the client retains one approved source address rather
than becoming arbitrary site-to-site transit.

For repeatable lab setup and lower-level troubleshooting, see the
[CONNECT-IP daemon guide](../../connect-lib/daemon/README.md).
