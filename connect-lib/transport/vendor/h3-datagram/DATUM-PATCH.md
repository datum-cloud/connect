# Datum patch

This is `h3-datagram` 0.0.2 with one interoperability fix in
`src/datagram.rs`: `Datagram::encode` now emits the encoded Quarter Stream ID
instead of a zero-filled buffer. Without this fix, response datagrams for every
CONNECT stream are incorrectly associated with stream 0, so multiplexed
CONNECT-UDP works only for the first stream.

The local unit test `encode_preserves_the_quarter_stream_id` protects the wire
encoding, and `task test:masque-interop` exercises three simultaneous streams
with an independent `masque-go` client.
