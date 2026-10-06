# Datum Connect

Datum Connect gives a device a private path to another device, a local service,
or an approved project network. Users work through `datumctl connect`; a local
daemon keeps identity and connections alive after the command exits.

Connect is being introduced incrementally. The
[product architecture](docs/architecture/README.md) defines the intended
service boundaries and user-visible contract for that work. It distinguishes
the initial preview from later capabilities so implementation pull requests can
be reviewed against a stable design.

The existing implementation remains available on the
[`develop`](https://github.com/datum-cloud/connect/tree/develop) branch while
the new architecture lands.
