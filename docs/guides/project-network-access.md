# Access a managed project network

Use a managed network attachment when applications on your device need direct
IP access to approved addresses in a project VPC. For a single known
application on another Connector, prefer a [private service](private-services.md).

## Before you begin

The project must have a ready `ConnectGateway` for the named network. The join
also needs administrator approval to install a native interface with the exact
assigned address and routes.

On macOS and Linux, interactive setup can install the separate networking
helper. Scripts never prompt or elevate. Windows support requires
credential-file authentication and still needs native-host validation.

## Join the network

Select the project through your `datumctl` context or `--project`, then run:

```sh
datumctl connect join staging-vpc
```

Connect selects the ready gateway, creates or reuses this device's network
binding, and shows the interface and route changes for approval. Approve only
the network you expect.

A successful managed join is saved. The daemon recreates the session after the
daemon or project resumes, as long as the helper's approved address and routes
still match. A changed or missing approval fails closed and requires another
interactive join.

## Use and verify the attachment

Use your application normally with an approved VPC address. Inspect the Connect
state and local component health with:

```sh
datumctl connect status
datumctl connect doctor
```

`datumctl connect ping` accepts a Connector name or key; it does not test an
arbitrary VPC address. Use the operating system's network tools and an allowed
destination to validate VPC reachability.

The gateway and local route approval do not automatically configure destination
firewalls, source NAT, or return routes. The VPC operator must provide a valid
return path and permit the intended traffic.

## Leave the network

Remove the attachment intent and project binding with:

```sh
datumctl connect leave staging-vpc
```

Confirm with `datumctl connect status`. If the interface or route remains after
a failed operation, run `datumctl connect doctor` and follow the diagnostics in
the [CONNECT-IP daemon guide](../../connect-lib/daemon/README.md).

## Current constraints

Guided managed setup currently uses IPv6. Attachments support an IPv4 or IPv6
overlay over an independently selected IPv4 or IPv6 underlay, but dual-stack
attachments and IPv6 extension headers are not supported in this preview.
