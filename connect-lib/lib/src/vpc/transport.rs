//! The VPC data-plane protocol: a single iroh/QUIC bidirectional stream
//! carrying length-prefixed IP packets between this client's TUN device and
//! the galactic-side router. There is no HTTP request/target here as there
//! is with `tunnel`'s `IROH_HTTP_CONNECT_ALPN` — just raw L3 packets — so a
//! distinct ALPN and a much simpler framing is used instead of reusing
//! `iroh_proxy_utils`.
//!
//! iroh already provides the encrypted, authenticated, NAT-traversing
//! transport a WireGuard-style tunnel would otherwise need its own Noise
//! handshake and roaming logic for (see design/vpc-attachment.md). What's
//! left to define here is purely the framing and the single-peer identity
//! check that stands in for WireGuard's AllowedIPs source filter.

use std::future::Future;
use std::net::Ipv6Addr;
use std::pin::Pin;
use std::sync::Arc;

use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{Result, StdResultExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tun::{DeviceReader, DeviceWriter};

/// ALPN for the VPC data-plane protocol. Bumped from `/vpc/0` to `/vpc/1`
/// to mark the wire change: the first frame on every stream is now a
/// JSON-encoded `Assignment`, followed by raw length-prefixed packets.
pub const IROH_VPC_ALPN: &[u8] = b"datum-connect/vpc/1";

/// Ceiling on a single framed packet's length — the framing's 2-byte length
/// prefix allows up to `u16::MAX`, but the real bound in practice is the
/// interface MTU (see `Mode`/MTU discussion in design/vpc-attachment.md),
/// which is always far smaller.
const MAX_PACKET_LEN: usize = u16::MAX as usize;

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Writes a single u16-length-prefixed frame to `w`.
pub async fn write_frame(w: &mut (impl AsyncWrite + Unpin + Send), data: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

/// Reads a single u16-length-prefixed frame from `r`. Returns `None` on
/// clean EOF (stream closed), `Some(Vec<u8>)` on success.
pub async fn read_frame(r: &mut (impl AsyncRead + Unpin + Send)) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 2];
    if r.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes(len_buf)).min(MAX_PACKET_LEN);
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

// ---------------------------------------------------------------------------
// Assignment control frame
// ---------------------------------------------------------------------------

/// Router-allocated address assignment sent as the first frame on the
/// stream. Mirrors the future `VPCAttachmentStatus.assignedAddress` +
/// `advertisedPrefixes` CRD fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assignment {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub vpc_prefixes: Vec<String>,
}

/// Sends an `Assignment` as a single JSON-encoded, length-prefixed frame.
pub async fn send_assignment(
    w: &mut (impl AsyncWrite + Unpin + Send),
    assignment: &Assignment,
) -> std::io::Result<()> {
    let json = serde_json::to_vec(assignment)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_frame(w, &json).await
}

/// Reads an `Assignment` from the first length-prefixed frame on the stream.
pub async fn recv_assignment(
    r: &mut (impl AsyncRead + Unpin + Send),
) -> std::io::Result<Assignment> {
    let frame = read_frame(r).await?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "stream closed before assignment")
    })?;
    serde_json::from_slice(&frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Accept handler (client side)
// ---------------------------------------------------------------------------

/// Callback invoked when the router sends an `Assignment` before pumping.
/// The callback must configure the interface + routes from the assignment
/// and return `Ok(())` before packet pumping begins.
pub type OnAssignFn = Arc<
    dyn Fn(Assignment) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Server-side (accept) handler. The client is always the accept side here,
/// mirroring how `tunnel`'s client is dialed by Envoy rather than dialing
/// out itself — for `vpc`, the galactic-side router plays Envoy's role and
/// dials in once it has claimed this attachment.
///
/// In the real (CRD-backed) flow the client always starts first — it has
/// nothing to wait on to learn a router's identity before that router has
/// claimed its `VPCAttachment`, at which point `status.routerEndpointId`
/// tells the client who to allow. `allowed_router` is `None` until then:
/// this is a real, if narrow, window where any peer may dial in and start
/// pumping packets, not just an artifact of this scaffold skipping the CRD.
/// Once wired to the CRD, the client should treat "no allowed router yet" as
/// "don't accept," not "accept anyone" — the current permissive behavior is
/// scaffolding for the containerlab lab (see design/vpc-attachment.md §6)
/// and must not ship as the production default.
#[derive(Clone)]
pub struct VpcAcceptHandler {
    allowed_router: Option<EndpointId>,
    tun_reader: Arc<Mutex<DeviceReader>>,
    tun_writer: Arc<Mutex<DeviceWriter>>,
    mtu: usize,
    on_assign: Option<OnAssignFn>,
}

// `ProtocolHandler` requires `Debug`, but `tun::{DeviceReader, DeviceWriter}`
// don't implement it — print everything except the raw device handles.
impl std::fmt::Debug for VpcAcceptHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpcAcceptHandler")
            .field("allowed_router", &self.allowed_router)
            .field("mtu", &self.mtu)
            .field("on_assign", &self.on_assign.as_ref().map(|_| ".."))
            .finish_non_exhaustive()
    }
}

impl VpcAcceptHandler {
    pub fn new(
        allowed_router: Option<EndpointId>,
        tun_reader: Arc<Mutex<DeviceReader>>,
        tun_writer: Arc<Mutex<DeviceWriter>>,
        mtu: usize,
    ) -> Self {
        Self {
            allowed_router,
            tun_reader,
            tun_writer,
            mtu,
            on_assign: None,
        }
    }

    /// Sets a callback that will be invoked with the router's `Assignment`
    /// before packet pumping begins. The callback must configure the TUN
    /// interface (address, routes) from the assignment.
    pub fn with_on_assign(mut self, f: OnAssignFn) -> Self {
        self.on_assign = Some(f);
        self
    }
}

impl ProtocolHandler for VpcAcceptHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let remote = connection.remote_id();
        match self.allowed_router {
            Some(allowed) if remote != allowed => {
                warn!(
                    peer = %remote.fmt_short(),
                    expected = %allowed.fmt_short(),
                    "rejecting vpc dial-in from unrecognized peer"
                );
                return Err(n0_error::e!(AcceptError::NotAllowed {}));
            }
            Some(_) => {
                info!(peer = %remote.fmt_short(), "accepted vpc attachment connection");
            }
            None => {
                warn!(
                    peer = %remote.fmt_short(),
                    "accepting vpc dial-in with no configured router identity — \
                     trust-on-first-connect, lab/dev use only"
                );
            }
        }

        let (net_send, mut net_recv) = connection.accept_bi().await?;

        // Read the Assignment control frame before pumping.
        let assignment = recv_assignment(&mut net_recv)
            .await
            .map_err(AcceptError::from_err)?;

        if let Some(ref on_assign) = self.on_assign {
            (on_assign)(assignment)
                .await
                .map_err(AcceptError::from_err)?;
        }

        pump(
            net_send,
            net_recv,
            self.tun_reader.clone(),
            self.tun_writer.clone(),
            self.mtu,
        )
        .await
        .map_err(AcceptError::from_err)?;
        connection.closed().await;
        Ok(())
    }
}

/// Client-side (dial) helper — used by the galactic-side router component to
/// dial into an attachment's client once it has claimed it. Kept here,
/// alongside the accept handler, so both sides of this repo's own reference
/// implementation (the client's `vpc join` and the containerlab mock
/// galactic router) share one framing implementation.
#[derive(Debug, Clone)]
pub struct VpcDialer {
    endpoint: Endpoint,
}

impl VpcDialer {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Dials a remote peer, sends the `Assignment` as the first frame, then
    /// returns the raw stream halves for the caller to drive its own I/O
    /// (e.g. an N:1 mux in the router). The caller is responsible for
    /// reading/writing length-prefixed frames via `write_frame`/`read_frame`.
    pub async fn dial_and_send_assignment(
        &self,
        remote: impl Into<EndpointAddr>,
        assignment: &Assignment,
    ) -> Result<(
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
    )> {
        let connection = self
            .endpoint
            .connect(remote, IROH_VPC_ALPN)
            .await
            .std_context("dialing vpc attachment endpoint")?;
        let (mut net_send, net_recv) = connection
            .open_bi()
            .await
            .std_context("opening vpc data stream")?;
        send_assignment(&mut net_send, assignment)
            .await
            .std_context("sending assignment")?;
        Ok((net_send, net_recv))
    }

    /// Convenience: dial, send assignment, then pump a dedicated TUN pair
    /// (single-client shortcut, kept for simple test harnesses).
    pub async fn dial_and_pump(
        &self,
        remote: impl Into<EndpointAddr>,
        assignment: &Assignment,
        tun_reader: Arc<Mutex<DeviceReader>>,
        tun_writer: Arc<Mutex<DeviceWriter>>,
        mtu: usize,
    ) -> Result<()> {
        let (net_send, net_recv) = self.dial_and_send_assignment(remote, assignment).await?;
        pump(net_send, net_recv, tun_reader, tun_writer, mtu)
            .await
            .std_context("vpc packet pump")?;
        Ok(())
    }
}

/// Bridges IP packets between a TUN device and an iroh bidirectional
/// stream, in both directions concurrently, until either side closes.
///
/// Framing is a 2-byte big-endian length prefix per packet: a QUIC stream is
/// an ordered reliable byte stream, not message-preserving, so packet
/// boundaries from the TUN device's discrete reads must be reconstructed
/// explicitly on the other end. (A future iteration may move this onto
/// iroh/QUIC datagrams instead, which preserve message boundaries and are a
/// closer match to IP's own best-effort delivery model — see
/// design/vpc-attachment.md.)
async fn pump<R, W>(
    mut net_send: impl AsyncWrite + Unpin + Send,
    mut net_recv: impl AsyncRead + Unpin + Send,
    tun_reader: Arc<Mutex<R>>,
    tun_writer: Arc<Mutex<W>>,
    mtu: usize,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let to_net = async move {
        let mut reader = tun_reader.lock().await;
        let mut buf = vec![0u8; mtu];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let chunk = buf
                .get(..n)
                .ok_or_else(|| std::io::Error::other("tun read length exceeded buffer"))?;
            write_frame(&mut net_send, chunk).await?;
        }
        std::io::Result::Ok(())
    };
    let to_tun = async move {
        let mut writer = tun_writer.lock().await;
        loop {
            match read_frame(&mut net_recv).await? {
                Some(pkt) => writer.write_all(&pkt).await?,
                None => break,
            }
        }
        std::io::Result::Ok(())
    };
    tokio::try_join!(to_net, to_tun)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Exercises the length-prefix framing directly, without a real TUN
    /// device or iroh connection: independent `tokio::io::duplex` pairs
    /// stand in for the tun-reader/tun-writer/net-send/net-recv sides `pump`
    /// bridges, with the test itself holding the other end of each pair.
    /// Confirms a packet written on the tun side arrives correctly framed
    /// on the net side, and a framed packet written on the net side arrives
    /// as raw bytes on the tun side.
    #[tokio::test]
    async fn pump_round_trips_packets_in_both_directions() {
        let (tun_reader_end, mut tun_in_write) = duplex(4096);
        let (net_send_end, mut net_out_read) = duplex(4096);
        let (mut net_in_write, net_recv_end) = duplex(4096);
        let (tun_writer_end, mut tun_out_read) = duplex(4096);

        let tun_reader = Arc::new(Mutex::new(tun_reader_end));
        let tun_writer = Arc::new(Mutex::new(tun_writer_end));

        let pump_handle = tokio::spawn(pump(
            net_send_end,
            net_recv_end,
            tun_reader,
            tun_writer,
            1500,
        ));

        // tun -> net: a raw packet written on the tun side must arrive on
        // the net side prefixed with its big-endian u16 length.
        let outbound = b"outbound icmp echo request".to_vec();
        tun_in_write
            .write_all(&outbound)
            .await
            .expect("write to tun_in_write");

        let mut len_buf = [0u8; 2];
        net_out_read
            .read_exact(&mut len_buf)
            .await
            .expect("read framed length from net_out_read");
        assert_eq!(u16::from_be_bytes(len_buf) as usize, outbound.len());
        let mut framed_payload = vec![0u8; outbound.len()];
        net_out_read
            .read_exact(&mut framed_payload)
            .await
            .expect("read framed payload from net_out_read");
        assert_eq!(framed_payload, outbound);

        // net -> tun: a framed packet written on the net side must arrive
        // on the tun side as the raw payload, length prefix stripped.
        let inbound = b"inbound icmp echo reply".to_vec();
        let inbound_len = u16::try_from(inbound.len()).expect("test payload fits in u16");
        net_in_write
            .write_all(&inbound_len.to_be_bytes())
            .await
            .expect("write framed length to net_in_write");
        net_in_write
            .write_all(&inbound)
            .await
            .expect("write framed payload to net_in_write");

        let mut raw_payload = vec![0u8; inbound.len()];
        tun_out_read
            .read_exact(&mut raw_payload)
            .await
            .expect("read raw payload from tun_out_read");
        assert_eq!(raw_payload, inbound);

        // Close both inbound sides so pump's two loops see EOF and return,
        // rather than leaking a task that waits forever.
        drop(tun_in_write);
        drop(net_in_write);
        pump_handle
            .await
            .expect("pump task should not panic")
            .expect("pump should exit cleanly once both sides are closed");
    }

    #[tokio::test]
    async fn assignment_round_trips_through_framing() {
        let (mut writer, mut reader) = duplex(4096);
        let original = Assignment {
            address: "fd00:cafe:1100::42".parse().expect("valid ipv6"),
            prefix_len: 64,
            vpc_prefixes: vec!["fd00:cafe::/32".to_string()],
        };
        send_assignment(&mut writer, &original)
            .await
            .expect("send_assignment");
        drop(writer);
        let received = recv_assignment(&mut reader)
            .await
            .expect("recv_assignment");
        assert_eq!(original, received);
    }

    #[tokio::test]
    async fn pump_after_assignment_on_same_stream() {
        // Simulates the real protocol: assignment frame first, then raw
        // packet pumping on the same stream halves.
        let (mut net_send, mut net_recv) = duplex(8192);
        let (tun_reader_end, _tun_in_write) = duplex(4096);
        let (tun_writer_end, tun_out_read) = duplex(4096);

        let assignment = Assignment {
            address: "fd00:cafe:1100::7".parse().expect("valid ipv6"),
            prefix_len: 64,
            vpc_prefixes: vec!["fd00:cafe::/32".to_string()],
        };

        // Dial side: send assignment then a data frame.
        send_assignment(&mut net_send, &assignment)
            .await
            .expect("send assignment");
        let data_pkt = b"hello from router";
        write_frame(&mut net_send, data_pkt)
            .await
            .expect("write data frame");
        drop(net_send);

        // Accept side: recv assignment, then pump the rest.
        let got = recv_assignment(&mut net_recv)
            .await
            .expect("recv assignment");
        assert_eq!(got, assignment);

        // The remaining data on net_recv is a single framed packet that
        // pump would deliver to the TUN writer. Read it manually here.
        let frame = read_frame(&mut net_recv)
            .await
            .expect("read data frame");
        assert_eq!(frame.as_deref(), Some(data_pkt.as_slice()));

        // Sanity: no more frames.
        let eof = read_frame(&mut net_recv).await.expect("eof check");
        assert!(eof.is_none());

        // Clean up unused ends.
        drop(tun_reader_end);
        drop(tun_writer_end);
        drop(tun_out_read);
    }
}
