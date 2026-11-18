# Share a private service

Use a private service when another approved Connector needs one TCP or UDP
application on your device. The application can stay bound to loopback, and no
public hostname or inbound firewall rule is required.

## Share the application

On the serving device, pass the application's destination to `serve`:

```sh
datumctl connect serve localhost:8080
```

TCP is the default. For UDP, select the protocol explicitly:

```sh
datumctl connect serve localhost:5353 --protocol udp
```

Without `--allow`, project devices can connect, except gateway identities
approved by the Connector's class and aliases of those keys.

To restrict the service, name one or more Connectors or public keys:

```sh
datumctl connect serve localhost:22 --allow TEAMMATE_CONNECTOR
```

An allowlist is resolved and pinned to Connector keys. Explicitly allowing a
gateway is a security-sensitive choice because that gateway may expose the
service through ingress.

## Reach the service

On an allowed device in the same project, connect the device first:

```sh
datumctl connect up
```

Then create a local forward. `CONNECTOR` is the server's name or public key,
not an IP address:

```sh
datumctl connect dial CONNECTOR:8080 --bind 18080
```

If you omit `--bind`, Connect chooses an available local port and reports it.
Use that local port in your application:

```sh
curl http://localhost:18080
```

For UDP, the protocol must match the service:

```sh
datumctl connect dial CONNECTOR:5353 --protocol udp --bind 5353
```

### Share a forward with other hosts

A forward listens on `127.0.0.1` by default, so only applications on the same
device can use it. To let other hosts on your network use it, for example
other machines in the same VPC, choose a listener address with
`--bind-address`:

```sh
datumctl connect dial CONNECTOR:8080 --bind 18080 --bind-address 0.0.0.0
```

The address can be any local IPv4 or IPv6 address, including `0.0.0.0` or `::`
for all addresses. On most Linux hosts `::` also accepts IPv4 connections.

A non-loopback forward exposes the remote service to every host that can reach
that address. Those hosts use the service with your Connector's identity and
the serving Connector cannot tell them apart. Connect does not authenticate
them, so restrict access with a firewall, security group, or network policy.
For this reason the daemon requires its setup token for any address other than
loopback; delegated operate tokens can create only loopback forwards.

Local ports stay unique across addresses. To change the address of an existing
forward, run `hangup` for its port and dial again.

## Inspect and manage

Services and forwards remain active after their commands exit.

```sh
datumctl connect status
datumctl connect ping CONNECTOR
```

`ping` verifies Connector reachability, not the health of the shared
application. Test the local forwarded port to verify the application itself.

Remove a forward by its local port and a service by its destination or the name
shown by `status`:

```sh
datumctl connect hangup 18080
datumctl connect unserve localhost:8080
```

If TCP and UDP services share one destination, use the service name when
running `unserve`.

## Pause and resume a device

To disconnect the project without losing the Connector identity or saved
configuration:

```sh
datumctl connect down
```

Resume the saved services and forwards later:

```sh
datumctl connect up
```

Use `unserve` or `hangup` when you intend to remove configuration rather than
temporarily disconnect it.
