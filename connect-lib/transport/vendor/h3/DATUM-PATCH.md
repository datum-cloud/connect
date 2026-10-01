# Local CONNECT-IP protocol patch

This is h3 0.0.8 from crates.io, with its upstream LICENSE retained.
The only source change adds `Protocol::CONNECT_IP` and its string conversion
and parsing in `src/ext.rs`. The upstream enum otherwise cannot represent
RFC 9484's `connect-ip` extended CONNECT protocol.

Connect and iroh-gateway use the same workspace patch. Remove this vendor copy
when an upstream release supports the protocol. This patch does not imply
general-purpose MASQUE interoperability certification.
