//! HTTP/3 CONNECT transport for Datum Connect.

mod h3_iroh;
pub mod ip;
pub mod masque;

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use bytes::{Buf, Bytes, BytesMut};
use h3::{error::Code, ext::Protocol};
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError as DatagramSendError};
use http::{Method, Request, Response, StatusCode};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::presets};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// ALPN negotiated for Datum's HTTP/3 transport.
pub const ALPN: &[u8] = b"datum-connect/masque-v1";
/// Maximum UDP application payload accepted by this preview, excluding HTTP/3
/// and CONNECT-UDP framing. No fragmentation or reassembly is provided. This
/// conservative ceiling leaves room beneath the usual QUIC minimum path MTU;
/// a path with a smaller available datagram budget can still drop a packet.
pub const MAX_DATAGRAM_PAYLOAD: usize = 1100;
const DESTINATION_HEADER: &str = "x-datum-destination";
const KIND_HEADER: &str = "x-datum-connect-kind";
const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const CONNECT_UDP_PATH_PREFIX: &str = "/.well-known/masque/udp/";
const TUNNEL_BUFFER: usize = 64 * 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Stable identifier advertised by the control plane for one destination.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DestinationId(Arc<str>);

impl DestinationId {
    /// Creates an identifier safe to carry in an HTTP field value.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(Error::InvalidDestinationId);
        }
        Ok(Self(value.into()))
    }

    /// Canonical destination for an advertised TCP port.
    pub fn tcp(port: u16) -> Self {
        Self(format!("tcp-{port}").into())
    }

    /// Canonical destination for an advertised UDP port.
    pub fn udp(port: u16) -> Self {
        Self(format!("udp-{port}").into())
    }

    /// Returns the wire representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DestinationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for DestinationId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Network target assigned to an advertised destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Tcp(SocketAddr),
    Udp(SocketAddr),
    /// A [`LocalListener`] in this process. Authorized CONNECT-TCP sessions
    /// are handed to it as [`LocalStream`]s instead of opening a socket, for
    /// services with no reachable address of their own, such as a unikernel
    /// without a loopback interface.
    Local(LocalTargetId),
}

/// Identifies a [`LocalListener`] registered on one [`Transport`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LocalTargetId(u64);

/// A byte stream from a peer's CONNECT-TCP session, delivered in process.
pub struct LocalStream {
    peer: EndpointId,
    destination: DestinationId,
    io: DuplexStream,
}

impl LocalStream {
    /// The authenticated peer that opened the session.
    pub fn peer(&self) -> EndpointId {
        self.peer
    }

    pub fn destination(&self) -> &DestinationId {
        &self.destination
    }
}

impl std::fmt::Debug for LocalStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStream")
            .field("peer", &self.peer)
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Receives the sessions for a [`Target::Local`] destination. Dropping it
/// unregisters the target; later sessions get 502 Bad Gateway, as a TCP
/// target that refuses connections would.
pub struct LocalListener {
    id: LocalTargetId,
    streams: mpsc::Receiver<LocalStream>,
    inner: Arc<Inner>,
}

impl LocalListener {
    /// The target to put in a [`DestinationPolicy`].
    pub fn target(&self) -> Target {
        Target::Local(self.id)
    }

    /// The next authorized session, or `None` once the transport shuts down.
    pub async fn accept(&mut self) -> Option<LocalStream> {
        self.streams.recv().await
    }
}

impl Drop for LocalListener {
    fn drop(&mut self) {
        if let Ok(mut targets) = self.inner.local_targets.lock() {
            targets.remove(&self.id);
        }
    }
}

/// Sessions waiting for a slow [`LocalListener::accept`] before new ones are
/// refused with 502.
const LOCAL_BACKLOG: usize = 64;
/// In-memory buffer per direction between a session and its local stream.
const LOCAL_BUFFER: usize = 64 * 1024;

/// Peer authorization for one destination.
#[derive(Clone, Debug)]
pub enum Access {
    Public,
    Peers(HashSet<EndpointId>),
    /// Peers admitted by a set shared with the caller, so adding one takes
    /// effect immediately: a peer may connect the moment it pairs, before
    /// any policy replacement reaches the transport.
    SharedPeers(Arc<SharedPeers>),
}

impl Access {
    fn allows(&self, peer: EndpointId) -> bool {
        match self {
            Self::Public => true,
            Self::Peers(peers) => peers.contains(&peer),
            Self::SharedPeers(peers) => peers.contains(peer),
        }
    }
}

impl PartialEq for Access {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Public, Self::Public) => true,
            (Self::Peers(a), Self::Peers(b)) => a == b,
            (Self::SharedPeers(a), Self::SharedPeers(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Eq for Access {}

/// A peer set that one side adds to and the transport reads. Clones share
/// the same set, and holding one never keeps a transport alive.
#[derive(Debug, Default)]
pub struct SharedPeers(std::sync::RwLock<HashSet<EndpointId>>);

impl SharedPeers {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, peer: EndpointId) -> bool {
        self.0
            .write()
            .expect("shared peers lock poisoned")
            .insert(peer)
    }

    pub fn contains(&self, peer: EndpointId) -> bool {
        self.0
            .read()
            .expect("shared peers lock poisoned")
            .contains(&peer)
    }
}

/// Runtime policy for one advertised destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationPolicy {
    pub target: Target,
    pub access: Access,
}

/// Complete set of currently advertised destinations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    pub destinations: HashMap<DestinationId, DestinationPolicy>,
}

/// Accepts connections for an additional ALPN on the transport's endpoint.
///
/// The transport owns the endpoint's accept loop, so other protocols that must
/// share the endpoint identity register here instead of accepting directly.
pub trait ProtocolHandler: Send + Sync + 'static {
    /// Serves one authenticated connection. Errors are counted and logged.
    fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
}

type Protocols = HashMap<Vec<u8>, Arc<dyn ProtocolHandler>>;

/// Endpoint construction settings.
pub struct TransportConfig {
    secret_key: SecretKey,
    bind_addrs: Vec<SocketAddr>,
    relay_mode: Option<iroh::RelayMode>,
    protocols: Protocols,
}

impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut alpns: Vec<_> = self
            .protocols
            .keys()
            .map(|alpn| String::from_utf8_lossy(alpn))
            .collect();
        alpns.sort();
        f.debug_struct("TransportConfig")
            .field("bind_addrs", &self.bind_addrs)
            .field("relay_mode", &self.relay_mode)
            .field("protocols", &alpns)
            .finish_non_exhaustive()
    }
}

impl TransportConfig {
    /// Uses the caller-owned project/device identity.
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            bind_addrs: Vec::new(),
            relay_mode: None,
            protocols: HashMap::new(),
        }
    }
    /// Overrides the UDP bind address.
    pub fn bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.bind_addrs = vec![bind_addr];
        self
    }

    /// Binds UDP on `port` for both IPv4 and IPv6 instead of a random port,
    /// so a load balancer or firewall rule can forward to it.
    pub fn bind_port(mut self, port: u16) -> Self {
        self.bind_addrs = vec![
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)),
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
        ];
        self
    }

    /// Overrides the preset's relay network without changing the device identity.
    pub fn relay_mode(mut self, relay_mode: iroh::RelayMode) -> Self {
        self.relay_mode = Some(relay_mode);
        self
    }

    /// Accepts `alpn` on the same endpoint and hands its connections to
    /// `handler`. The MASQUE and CONNECT-IP ALPNs cannot be replaced.
    pub fn protocol(mut self, alpn: &[u8], handler: Arc<dyn ProtocolHandler>) -> Self {
        if alpn != ALPN && alpn != ip::ALPN {
            self.protocols.insert(alpn.to_vec(), handler);
        }
        self
    }
}

/// Current addresses safe to publish through the control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionDetails {
    pub endpoint_id: EndpointId,
    pub relay_urls: Vec<String>,
    pub direct_addresses: Vec<SocketAddr>,
}

/// Point-in-time transport telemetry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportStats {
    pub active_tcp: usize,
    pub active_udp: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors: u64,
    pub revoked: u64,
    pub datagrams_dropped: u64,
}

/// Network path selected for an observed peer connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPath {
    Direct,
    Relay,
    Unknown,
}

/// Latest iroh path observation for a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDiagnostics {
    pub path: ConnectionPath,
    pub detail: Option<String>,
    pub latency: Option<Duration>,
}

#[derive(Default)]
struct Metrics {
    active_tcp: AtomicUsize,
    active_udp: AtomicUsize,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    errors: AtomicU64,
    revoked: AtomicU64,
    datagrams_dropped: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionKind {
    Tcp,
    Udp,
}

struct ActiveSession {
    peer: EndpointId,
    destination: DestinationId,
    target: Target,
    kind: SessionKind,
    cancel: CancellationToken,
}

struct Inner {
    endpoint: Endpoint,
    policy: ArcSwap<Policy>,
    active: Mutex<HashMap<u64, ActiveSession>>,
    next_session: AtomicU64,
    shutdown: CancellationToken,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    metrics: Metrics,
    peer_diagnostics: RwLock<HashMap<EndpointId, PeerDiagnostics>>,
    /// Last path report published per peer, and when, for throttling.
    published_paths: std::sync::Mutex<HashMap<EndpointId, (PeerDiagnostics, Instant)>>,
    path_updates: broadcast::Sender<(EndpointId, PeerDiagnostics)>,
    local_targets: std::sync::Mutex<HashMap<LocalTargetId, mpsc::Sender<LocalStream>>>,
    next_local_target: AtomicU64,
    ip_registry: Arc<ip::Registry>,
    protocols: Protocols,
}

/// A clonable, long-lived transport endpoint.
#[derive(Clone)]
pub struct Transport {
    inner: Arc<Inner>,
}

impl Transport {
    /// Binds and immediately starts accepting sessions.
    pub async fn bind(config: TransportConfig) -> Result<Self, Error> {
        let mut alpns = vec![ALPN.to_vec(), ip::ALPN.to_vec()];
        alpns.extend(config.protocols.keys().cloned());
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(config.secret_key)
            .alpns(alpns);
        if let Some(mode) = config.relay_mode {
            builder = builder.relay_mode(mode);
        }
        if !config.bind_addrs.is_empty() {
            // Explicit binding is an underlay restriction, not an additional
            // socket alongside the preset's wildcard IPv4/IPv6 transports.
            builder = builder.clear_ip_transports();
            for addr in config.bind_addrs {
                builder = builder.bind_addr(addr).map_err(error_debug)?;
            }
        }
        let endpoint = builder.bind().await.map_err(error_debug)?;
        let transport = Self::with_protocols(endpoint, config.protocols);
        let task_transport = transport.clone();
        let task = tokio::spawn(async move { task_transport.accept_loop().await });
        *transport.inner.accept_task.lock().await = Some(task);
        Ok(transport)
    }

    /// Wraps an existing endpoint for outbound CONNECT and CONNECT-UDP sessions.
    ///
    /// This preserves the endpoint's identity, discovery, relay, and ALPN
    /// configuration. It does not start an accept loop or consume incoming
    /// connections. The caller can therefore retain its existing protocol
    /// router and discovery setup, while using this transport to dial peers.
    /// Outbound sessions negotiate [`ALPN`] explicitly.
    ///
    /// The transport owns the endpoint's lifecycle: [`Self::shutdown`] cancels
    /// its tunnels and closes the supplied endpoint, including any external
    /// clones. Do not call shutdown while another owner still needs it.
    pub fn client(endpoint: Endpoint) -> Self {
        Self::with_protocols(endpoint, HashMap::new())
    }

    fn with_protocols(endpoint: Endpoint, protocols: Protocols) -> Self {
        let shutdown = CancellationToken::new();
        let ip_registry = Arc::new(ip::Registry::new(shutdown.clone()));
        Self {
            inner: Arc::new(Inner {
                endpoint,
                policy: ArcSwap::from_pointee(Policy::default()),
                active: Mutex::new(HashMap::new()),
                next_session: AtomicU64::new(1),
                shutdown,
                accept_task: Mutex::new(None),
                metrics: Metrics::default(),
                peer_diagnostics: RwLock::new(HashMap::new()),
                published_paths: std::sync::Mutex::new(HashMap::new()),
                path_updates: broadcast::channel(64).0,
                local_targets: std::sync::Mutex::new(HashMap::new()),
                next_local_target: AtomicU64::new(1),
                ip_registry,
                protocols,
            }),
        }
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.inner.endpoint.id()
    }

    /// Registers a join-scoped CONNECT-IP grant on this endpoint's existing
    /// authenticated ALPN dispatcher. No second accept loop or key is created.
    /// Dropping the registration revokes admission and every admitted session.
    /// An outbound-only `Transport::client` cannot register inbound grants.
    pub async fn register_ip_grant(&self, grant: ip::Grant) -> ip::Result<ip::Registration> {
        if self.inner.accept_task.lock().await.is_none() {
            return Err(ip::Error::Configuration(
                "CONNECT-IP registration requires an accepting Transport::bind endpoint",
            ));
        }
        self.inner.ip_registry.register(grant)
    }

    /// Clones the underlying endpoint for additional authenticated protocols.
    /// Closing this clone closes the transport too; keep lifecycle ownership
    /// with the project transport.
    pub fn endpoint(&self) -> Endpoint {
        self.inner.endpoint.clone()
    }

    pub fn connection_details(&self) -> ConnectionDetails {
        let addr = self.inner.endpoint.addr();
        ConnectionDetails {
            endpoint_id: addr.id,
            relay_urls: addr.relay_urls().map(ToString::to_string).collect(),
            direct_addresses: addr.ip_addrs().copied().collect(),
        }
    }

    /// Atomically installs policy and signals every now-unauthorized session.
    pub async fn replace_policy(&self, policy: Policy) -> Result<(), Error> {
        let policy = Arc::new(policy);
        self.inner.policy.store(policy.clone());
        let active = self.inner.active.lock().await;
        for session in active.values() {
            if !policy_allows(
                &policy,
                &session.destination,
                session.peer,
                session.target,
                session.kind,
            ) {
                self.inner.metrics.revoked.fetch_add(1, Ordering::Relaxed);
                session.cancel.cancel();
            }
        }
        Ok(())
    }

    pub fn stats(&self) -> TransportStats {
        let m = &self.inner.metrics;
        TransportStats {
            active_tcp: m.active_tcp.load(Ordering::Relaxed),
            active_udp: m.active_udp.load(Ordering::Relaxed),
            bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
            bytes_received: m.bytes_received.load(Ordering::Relaxed),
            errors: m.errors.load(Ordering::Relaxed),
            revoked: m.revoked.load(Ordering::Relaxed),
            datagrams_dropped: m.datagrams_dropped.load(Ordering::Relaxed),
        }
    }

    /// Returns the most recently selected iroh path for a peer.
    pub fn peer_diagnostics(&self, peer: EndpointId) -> Option<PeerDiagnostics> {
        self.inner.peer_diagnostics.read().ok()?.get(&peer).cloned()
    }

    /// Reports the selected path to each peer as it changes: immediately when
    /// it switches between direct and relayed or to another address, and for
    /// latency only on a change of more than a quarter, at most every
    /// [`PATH_RTT_REPORT_INTERVAL`]. Driven by iroh's path notifications plus
    /// a [`PATH_RTT_SAMPLE_INTERVAL`] latency sample per open connection, so
    /// an idle connection costs nothing extra on the network.
    pub fn path_updates(&self) -> broadcast::Receiver<(EndpointId, PeerDiagnostics)> {
        self.inner.path_updates.subscribe()
    }

    /// Registers an in-process target. Advertise it with
    /// [`LocalListener::target`]; policy and peer authorization apply exactly
    /// as for a TCP target.
    pub fn local_listener(&self) -> LocalListener {
        let id = LocalTargetId(self.inner.next_local_target.fetch_add(1, Ordering::Relaxed));
        let (sender, streams) = mpsc::channel(LOCAL_BACKLOG);
        if let Ok(mut targets) = self.inner.local_targets.lock() {
            targets.insert(id, sender);
        }
        LocalListener {
            id,
            streams,
            inner: Arc::clone(&self.inner),
        }
    }

    /// Verifies QUIC reachability and returns handshake latency.
    pub async fn ping(&self, peer: impl Into<EndpointAddr>) -> Result<Duration, Error> {
        let started = Instant::now();
        let conn = tokio::time::timeout(SETUP_TIMEOUT, self.inner.endpoint.connect(peer, ALPN))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(error_debug)?;
        self.observe_connection(&conn);
        conn.close(0u8.into(), b"ping");
        Ok(started.elapsed())
    }

    /// Opens a regular HTTP/3 CONNECT TCP tunnel.
    pub async fn connect_tcp(
        &self,
        peer: impl Into<EndpointAddr>,
        destination: DestinationId,
        cancel: CancellationToken,
    ) -> Result<TcpTunnel, Error> {
        let result = self
            .connect_tcp_inner(peer.into(), destination, cancel)
            .await;
        if matches!(&result, Err(error) if !matches!(error, Error::Closed)) {
            self.inner.metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn connect_tcp_inner(
        &self,
        peer: EndpointAddr,
        destination: DestinationId,
        cancel: CancellationToken,
    ) -> Result<TcpTunnel, Error> {
        let local_cancel = linked_cancel(cancel, self.inner.shutdown.clone());
        let setup_guard = local_cancel.clone().drop_guard();
        let conn = setup(
            &local_cancel,
            self.inner.endpoint.connect(peer.clone(), ALPN),
        )
        .await?;
        self.observe_connection(&conn);
        let adapter = h3_iroh::Connection::new(conn);
        let (mut driver, mut sender) =
            setup(&local_cancel, h3::client::builder().build(adapter)).await?;
        let request = connect_request(peer.id, &destination, SessionKind::Tcp, None)?;
        let mut stream = setup(&local_cancel, sender.send_request(request)).await?;
        let driver_task = AbortTask::new(tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        let response = setup(&local_cancel, stream.recv_response()).await?;
        if !response.status().is_success() {
            return Err(Error::Rejected(response.status()));
        }
        let sender_guard = sender;
        let (user, bridge) = tokio::io::duplex(TUNNEL_BUFFER);
        let inner = Arc::clone(&self.inner);
        let task_cancel = local_cancel.clone();
        let active_guard = OutboundSessionGuard::new(Arc::clone(&inner), SessionKind::Tcp);
        tokio::spawn(async move {
            let _active_guard = active_guard;
            let _driver_task = driver_task;
            let _cancel_guard = task_cancel.clone().drop_guard();
            let _sender_guard = sender_guard;
            bridge_tcp_h3(bridge, stream, task_cancel, &inner.metrics).await;
        });
        setup_guard.disarm();
        Ok(TcpTunnel {
            io: user,
            cancel: local_cancel,
        })
    }

    /// Opens extended CONNECT-UDP using HTTP Datagrams.
    pub async fn connect_udp(
        &self,
        peer: impl Into<EndpointAddr>,
        destination: DestinationId,
        cancel: CancellationToken,
    ) -> Result<UdpTunnel, Error> {
        let result = self
            .connect_udp_inner(peer.into(), destination, None, cancel)
            .await;
        if matches!(&result, Err(error) if !matches!(error, Error::Closed)) {
            self.inner.metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Opens standards-shaped CONNECT-UDP for an explicit target tuple.
    ///
    /// `destination` remains the authenticated Datum policy identifier, while
    /// `target_host` and `target_port` are encoded into the RFC 9298 default
    /// URI template. The accepting peer rejects the request unless that tuple
    /// describes the authorized UDP target, so this cannot bypass policy.
    pub async fn connect_udp_target(
        &self,
        peer: impl Into<EndpointAddr>,
        destination: DestinationId,
        target_host: impl Into<String>,
        target_port: u16,
        cancel: CancellationToken,
    ) -> Result<UdpTunnel, Error> {
        let result = self
            .connect_udp_inner(
                peer.into(),
                destination,
                Some((target_host.into(), target_port)),
                cancel,
            )
            .await;
        if matches!(&result, Err(error) if !matches!(error, Error::Closed)) {
            self.inner.metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn connect_udp_inner(
        &self,
        peer: EndpointAddr,
        destination: DestinationId,
        target: Option<(String, u16)>,
        cancel: CancellationToken,
    ) -> Result<UdpTunnel, Error> {
        let local_cancel = linked_cancel(cancel, self.inner.shutdown.clone());
        let setup_guard = local_cancel.clone().drop_guard();
        let conn = setup(
            &local_cancel,
            self.inner.endpoint.connect(peer.clone(), ALPN),
        )
        .await?;
        self.observe_connection(&conn);
        let adapter = h3_iroh::Connection::new(conn);
        let (mut driver, mut sender) = setup(
            &local_cancel,
            h3::client::builder()
                .enable_datagram(true)
                .enable_extended_connect(true)
                .build(adapter),
        )
        .await?;
        let request = connect_request(
            peer.id,
            &destination,
            SessionKind::Udp,
            target.as_ref().map(|(host, port)| (host.as_str(), *port)),
        )?;
        let standard_request = request.uri().path() != "/";
        let mut stream = setup(&local_cancel, sender.send_request(request)).await?;
        let stream_id = stream.id();
        let mut datagram_sender = driver.get_datagram_sender(stream_id);
        let mut datagram_reader = driver.get_datagram_reader();
        let response = tokio::select! {
            _ = local_cancel.cancelled() => return Err(Error::Closed),
            result = tokio::time::timeout(SETUP_TIMEOUT, stream.recv_response()) => {
                result.map_err(|_| Error::Timeout)?.map_err(error_display)?
            }
            result = std::future::poll_fn(|cx| driver.poll_close(cx)) => {
                return Err(error_display(result));
            }
        };
        if !response.status().is_success() {
            return Err(Error::Rejected(response.status()));
        }
        if standard_request && !capsule_protocol_enabled(response.headers()) {
            return Err(Error::Protocol(
                "CONNECT-UDP response did not negotiate Capsule Protocol".into(),
            ));
        }
        let sender_guard = sender;
        let (send_tx, mut send_rx) = mpsc::channel::<Bytes>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(64);
        let task_cancel = local_cancel.clone();
        let inner = Arc::clone(&self.inner);
        let active_guard = OutboundSessionGuard::new(Arc::clone(&inner), SessionKind::Udp);
        tokio::spawn(async move {
            let _active_guard = active_guard;
            let _cancel_guard = task_cancel.clone().drop_guard();
            let _sender_guard = sender_guard;
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    outgoing = send_rx.recv() => match outgoing {
                        Some(payload) => {
                            let len = payload.len();
                            match datagram_sender.send_datagram(add_context_id(payload)) {
                                Ok(()) => {},
                                Err(DatagramSendError::TooLarge { .. }) => { dropped_datagram(&inner.metrics); continue; },
                                Err(_) => { inner.metrics.errors.fetch_add(1, Ordering::Relaxed); break; },
                            }
                            inner.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                        }
                        None => break,
                    },
                    incoming = datagram_reader.read_datagram() => match incoming {
                        Ok(datagram) if datagram.stream_id() == stream_id => if let Some(payload) = remove_context_id(datagram.into_payload()) {
                            if payload.len() > MAX_DATAGRAM_PAYLOAD { dropped_datagram(&inner.metrics); continue; }
                            inner.metrics.bytes_received.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            match recv_tx.try_send(payload) {
                                Ok(()) => {},
                                Err(mpsc::error::TrySendError::Full(_)) => dropped_datagram(&inner.metrics),
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        },
                        Ok(_) => {}
                        Err(_) => { inner.metrics.errors.fetch_add(1, Ordering::Relaxed); break; }
                    },
                    result = std::future::poll_fn(|cx| driver.poll_close(cx)) => { let _ = result; break; }
                }
            }
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        });
        setup_guard.disarm();
        Ok(UdpTunnel {
            sender: send_tx,
            receiver: Mutex::new(recv_rx),
            cancel: local_cancel,
            inner: Arc::clone(&self.inner),
        })
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        for session in self.inner.active.lock().await.values() {
            session.cancel.cancel();
        }
        self.inner.endpoint.close().await;
        if let Some(task) = self.inner.accept_task.lock().await.take() {
            let _ = task.await;
        }
    }

    async fn accept_loop(&self) {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let incoming = tokio::select! { biased; _ = self.inner.shutdown.cancelled() => break, _ = connections.join_next(), if !connections.is_empty() => continue, incoming = self.inner.endpoint.accept() => incoming };
            let Some(incoming) = incoming else { break };
            if connections.len() >= 128 {
                incoming.refuse();
                continue;
            }
            let transport = self.clone();
            connections.spawn(async move {
                let cancel = transport.inner.shutdown.child_token();
                let _guard = cancel.clone().drop_guard();
                let result = async {
                    let accepting = incoming.accept().map_err(error_debug)?;
                    let conn = setup(&transport.inner.shutdown, accepting).await?;
                    transport.observe_connection(&conn);
                    if conn.alpn() == ip::ALPN {
                        ip::serve_connection(conn, transport.inner.ip_registry.clone(), cancel)
                            .await
                            .map_err(error_display)
                    } else if conn.alpn() == ALPN {
                        transport.serve_connection(conn).await
                    } else if let Some(handler) = transport.inner.protocols.get(conn.alpn()) {
                        let served = handler.accept(conn);
                        tokio::select! {
                            _ = cancel.cancelled() => Err(Error::Closed),
                            result = served => result.map_err(Error::Protocol),
                        }
                    } else {
                        Err(Error::Protocol("unregistered ALPN".into()))
                    }
                }
                .await;
                if let Err(error) = result {
                    transport
                        .inner
                        .metrics
                        .errors
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(%error, "transport connection failed");
                }
            });
        }
        if tokio::time::timeout(Duration::from_secs(2), async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
    }

    async fn serve_connection(&self, conn: iroh::endpoint::Connection) -> Result<(), Error> {
        let peer = conn.remote_id();
        self.observe_connection(&conn);
        let conn_guard = conn.clone();
        let adapter = h3_iroh::Connection::new(conn);
        let mut h3 = setup(
            &self.inner.shutdown,
            h3::server::builder()
                .enable_datagram(true)
                .enable_extended_connect(true)
                .build::<_, Bytes>(adapter),
        )
        .await?;
        let Some(resolver) = setup(&self.inner.shutdown, h3.accept()).await? else {
            return Ok(());
        };
        let (request, mut stream) = setup(&self.inner.shutdown, resolver.resolve_request()).await?;
        let kind = request_kind(&request)?;
        let Some((destination, destination_policy)) =
            authorized_request(&self.inner.policy.load(), &request, peer, kind)?
        else {
            stream
                .send_response(response(StatusCode::FORBIDDEN))
                .await
                .map_err(error_display)?;
            stream.finish().await.map_err(error_display)?;
            drop(stream);
            h3.shutdown(0).await.map_err(error_display)?;
            let _ = tokio::time::timeout(Duration::from_secs(1), conn_guard.closed()).await;
            return Ok(());
        };
        let cancel = CancellationToken::new();
        let local_destination = destination.clone();
        let Some(session_id) = self
            .register_session(
                peer,
                destination,
                destination_policy.target,
                kind,
                cancel.clone(),
            )
            .await
        else {
            stream
                .send_response(response(StatusCode::FORBIDDEN))
                .await
                .map_err(error_display)?;
            stream.finish().await.map_err(error_display)?;
            drop(stream);
            h3.shutdown(0).await.map_err(error_display)?;
            let _ = tokio::time::timeout(Duration::from_secs(1), conn_guard.closed()).await;
            return Ok(());
        };
        let _guard = SessionGuard {
            inner: Arc::clone(&self.inner),
            id: session_id,
            kind,
        };
        match destination_policy.target {
            Target::Tcp(target) if kind == SessionKind::Tcp => {
                let tcp = match setup(&cancel, TcpStream::connect(target)).await {
                    Ok(tcp) => tcp,
                    Err(error) if cancel.is_cancelled() => return Err(error),
                    Err(error) => {
                        // Flush the 502 before closing, as the 403 path does;
                        // returning at once closed the connection first, so
                        // the client saw a connection error instead.
                        stream
                            .send_response(response(StatusCode::BAD_GATEWAY))
                            .await
                            .map_err(error_display)?;
                        stream.finish().await.map_err(error_display)?;
                        drop(stream);
                        h3.shutdown(0).await.map_err(error_display)?;
                        let _ =
                            tokio::time::timeout(Duration::from_secs(1), conn_guard.closed()).await;
                        return Err(error);
                    }
                };
                stream
                    .send_response(response(StatusCode::OK))
                    .await
                    .map_err(error_display)?;
                bridge_server_tcp(tcp, stream, cancel, &self.inner.metrics).await;
            }
            Target::Udp(target) if kind == SessionKind::Udp => {
                let stream_id = stream.id();
                let mut datagram_sender = h3.get_datagram_sender(stream_id);
                let mut datagram_reader = h3.get_datagram_reader();
                let socket = UdpSocket::bind(if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .await?;
                socket.connect(target).await?;
                stream
                    .send_response(connect_udp_response(StatusCode::OK))
                    .await
                    .map_err(error_display)?;
                let mut buffer = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        incoming = datagram_reader.read_datagram() => match incoming {
                            Ok(datagram) if datagram.stream_id() == stream_id => if let Some(payload) = remove_context_id(datagram.into_payload()) {
                                if payload.len() > MAX_DATAGRAM_PAYLOAD { dropped_datagram(&self.inner.metrics); continue; }
                                socket.send(&payload).await?;
                                self.inner.metrics.bytes_received.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            },
                            Ok(_) => {}
                            Err(error) => return Err(error_display(error)),
                        },
                        received = socket.recv(&mut buffer) => {
                            let len = received?;
                            if len > MAX_DATAGRAM_PAYLOAD { dropped_datagram(&self.inner.metrics); continue; }
                            match datagram_sender.send_datagram(add_context_id(Bytes::copy_from_slice(&buffer[..len]))) {
                                Ok(()) => {},
                                Err(DatagramSendError::TooLarge { .. }) => { dropped_datagram(&self.inner.metrics); continue; },
                                Err(error) => return Err(error_display(error)),
                            }
                            self.inner.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                        }
                    }
                }
                stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            }
            Target::Local(id) if kind == SessionKind::Tcp => {
                let sender = self
                    .inner
                    .local_targets
                    .lock()
                    .ok()
                    .and_then(|targets| targets.get(&id).cloned());
                let (near, far) = tokio::io::duplex(LOCAL_BUFFER);
                let delivered = match sender {
                    Some(sender) => sender
                        .try_send(LocalStream {
                            peer,
                            destination: local_destination,
                            io: far,
                        })
                        .is_ok(),
                    None => false,
                };
                if !delivered {
                    stream
                        .send_response(response(StatusCode::BAD_GATEWAY))
                        .await
                        .map_err(error_display)?;
                    stream.finish().await.map_err(error_display)?;
                    drop(stream);
                    h3.shutdown(0).await.map_err(error_display)?;
                    let _ = tokio::time::timeout(Duration::from_secs(1), conn_guard.closed()).await;
                    return Err(Error::Protocol("local target unavailable or busy".into()));
                }
                stream
                    .send_response(response(StatusCode::OK))
                    .await
                    .map_err(error_display)?;
                bridge_server_tcp(near, stream, cancel, &self.inner.metrics).await;
            }
            _ => return Err(Error::Protocol("destination kind changed".into())),
        }
        Ok(())
    }

    async fn register_session(
        &self,
        peer: EndpointId,
        destination: DestinationId,
        target: Target,
        kind: SessionKind,
        cancel: CancellationToken,
    ) -> Option<u64> {
        let mut active = self.inner.active.lock().await;
        if self.inner.shutdown.is_cancelled()
            || !policy_allows(&self.inner.policy.load(), &destination, peer, target, kind)
        {
            return None;
        }
        let id = self.inner.next_session.fetch_add(1, Ordering::Relaxed);
        active.insert(
            id,
            ActiveSession {
                peer,
                destination,
                target,
                kind,
                cancel,
            },
        );
        match kind {
            SessionKind::Tcp => self
                .inner
                .metrics
                .active_tcp
                .fetch_add(1, Ordering::Relaxed),
            SessionKind::Udp => self
                .inner
                .metrics
                .active_udp
                .fetch_add(1, Ordering::Relaxed),
        };
        Some(id)
    }

    /// Records the connection's selected path now, then follows it until the
    /// connection closes or the transport shuts down. The watcher holds only
    /// iroh's path event stream and a weak handle: a strong `Connection`
    /// clone would keep the connection, and its sessions, open after every
    /// real user is done with it.
    fn observe_connection(&self, conn: &iroh::endpoint::Connection) {
        let peer = conn.remote_id();
        self.record_path(peer, path_diagnostics(conn.paths().iter()));
        let transport = self.clone();
        let weak = conn.weak_handle();
        let mut events = conn.path_events();
        let shutdown = self.inner.shutdown.clone();
        tokio::spawn(async move {
            use futures_util::StreamExt;
            let mut sample = tokio::time::interval(PATH_RTT_SAMPLE_INTERVAL);
            sample.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            sample.tick().await;
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    event = events.next() => if event.is_none() { break },
                    _ = sample.tick() => {}
                }
                let Some(conn) = weak.upgrade() else { break };
                let diagnostics = path_diagnostics(conn.paths().iter());
                drop(conn);
                transport.record_path(peer, diagnostics);
            }
        });
    }

    fn record_path(&self, peer: EndpointId, diagnostics: PeerDiagnostics) {
        if let Ok(mut peers) = self.inner.peer_diagnostics.write() {
            peers.insert(peer, diagnostics.clone());
        }
        let Ok(mut published) = self.inner.published_paths.lock() else {
            return;
        };
        let now = Instant::now();
        if let Some((last, at)) = published.get(&peer)
            && !path_report_due(last, *at, &diagnostics, now)
        {
            return;
        }
        published.insert(peer, (diagnostics.clone(), now));
        // No subscribers is normal; reports are best effort.
        let _ = self.inner.path_updates.send((peer, diagnostics));
    }
}

/// How often an open connection samples its latency between path changes.
pub const PATH_RTT_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
/// Minimum time between latency-only path reports for one peer.
pub const PATH_RTT_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Summarizes the selected path of a connection's open paths.
fn path_diagnostics<'a>(
    mut paths: impl Iterator<Item = iroh::endpoint::Path<'a>>,
) -> PeerDiagnostics {
    match paths.find(|path| path.is_selected()) {
        Some(path) => PeerDiagnostics {
            path: if path.is_ip() {
                ConnectionPath::Direct
            } else if path.is_relay() {
                ConnectionPath::Relay
            } else {
                ConnectionPath::Unknown
            },
            // Plain "1.2.3.4:5" or relay URL, without iroh's "ip:" or
            // "relay:" display prefix.
            detail: Some(match path.remote_addr() {
                iroh::TransportAddr::Ip(addr) => addr.to_string(),
                iroh::TransportAddr::Relay(url) => url.to_string(),
                other => other.to_string(),
            }),
            latency: Some(path.rtt()),
        },
        None => PeerDiagnostics {
            path: ConnectionPath::Unknown,
            detail: None,
            latency: None,
        },
    }
}

/// A path change is always reported; a latency change only when it moved by
/// more than a quarter and the last report is older than
/// [`PATH_RTT_REPORT_INTERVAL`].
fn path_report_due(
    last: &PeerDiagnostics,
    at: Instant,
    next: &PeerDiagnostics,
    now: Instant,
) -> bool {
    if last.path != next.path || last.detail != next.detail {
        return true;
    }
    if now.duration_since(at) < PATH_RTT_REPORT_INTERVAL {
        return false;
    }
    match (last.latency, next.latency) {
        (Some(a), Some(b)) => {
            let (a, b) = (a.as_secs_f64(), b.as_secs_f64());
            (a - b).abs() > a.max(b) * 0.25
        }
        (a, b) => a.is_some() != b.is_some(),
    }
}

struct SessionGuard {
    inner: Arc<Inner>,
    id: u64,
    kind: SessionKind,
}

// Outbound sessions contribute to telemetry without entering the inbound
// authorization registry. Replacing local serving policy must not revoke dials.
struct OutboundSessionGuard {
    inner: Arc<Inner>,
    kind: SessionKind,
}

impl OutboundSessionGuard {
    fn new(inner: Arc<Inner>, kind: SessionKind) -> Self {
        match kind {
            SessionKind::Tcp => inner.metrics.active_tcp.fetch_add(1, Ordering::Relaxed),
            SessionKind::Udp => inner.metrics.active_udp.fetch_add(1, Ordering::Relaxed),
        };
        Self { inner, kind }
    }
}

impl Drop for OutboundSessionGuard {
    fn drop(&mut self) {
        match self.kind {
            SessionKind::Tcp => self
                .inner
                .metrics
                .active_tcp
                .fetch_sub(1, Ordering::Relaxed),
            SessionKind::Udp => self
                .inner
                .metrics
                .active_udp
                .fetch_sub(1, Ordering::Relaxed),
        };
    }
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        let (inner, id, kind) = (Arc::clone(&self.inner), self.id, self.kind);
        tokio::spawn(async move {
            inner.active.lock().await.remove(&id);
            match kind {
                SessionKind::Tcp => inner.metrics.active_tcp.fetch_sub(1, Ordering::Relaxed),
                SessionKind::Udp => inner.metrics.active_udp.fetch_sub(1, Ordering::Relaxed),
            };
        });
    }
}

/// Async TCP byte stream backed by HTTP/3 DATA frames.
pub struct TcpTunnel {
    io: DuplexStream,
    cancel: CancellationToken,
}
impl AsyncRead for TcpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for TcpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
impl Drop for TcpTunnel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Connected UDP association backed by HTTP Datagrams.
pub struct UdpTunnel {
    sender: mpsc::Sender<Bytes>,
    receiver: Mutex<mpsc::Receiver<Bytes>>,
    cancel: CancellationToken,
    inner: Arc<Inner>,
}
impl UdpTunnel {
    /// Queues one UDP packet. Empty payloads are valid. Oversize packets return
    /// [`Error::DatagramTooLarge`] without closing the association. Successful
    /// queueing does not guarantee network delivery; UDP may drop packets.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), Error> {
        let payload = payload.into();
        if payload.len() > MAX_DATAGRAM_PAYLOAD {
            dropped_datagram(&self.inner.metrics);
            return Err(Error::DatagramTooLarge);
        }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(Error::Closed),
            result = self.sender.send(payload) => result.map_err(|_| Error::Closed),
        }
    }
    pub async fn recv(&self) -> Option<Bytes> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => None,
            payload = async { self.receiver.lock().await.recv().await } => payload,
        }
    }
}
impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Transport setup or session error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid destination id")]
    InvalidDestinationId,
    #[error("CONNECT request is missing its destination")]
    MissingDestination,
    #[error("CONNECT rejected with HTTP status {0}")]
    Rejected(StatusCode),
    #[error("transport association is closed")]
    Closed,
    #[error("transport setup timed out")]
    Timeout,
    #[error("UDP payload exceeds the preview limit of {MAX_DATAGRAM_PAYLOAD} bytes")]
    DatagramTooLarge,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("transport protocol error: {0}")]
    Protocol(String),
}

struct AbortTask(Option<JoinHandle<()>>);

impl AbortTask {
    fn new(task: JoinHandle<()>) -> Self {
        Self(Some(task))
    }
}

impl Drop for AbortTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

async fn setup<T, E, F>(cancel: &CancellationToken, future: F) -> Result<T, Error>
where
    E: std::fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(Error::Closed),
        result = tokio::time::timeout(SETUP_TIMEOUT, future) => {
            result.map_err(|_| Error::Timeout)?.map_err(error_display)
        }
    }
}

fn connect_request(
    peer: EndpointId,
    destination: &DestinationId,
    kind: SessionKind,
    udp_target: Option<(&str, u16)>,
) -> Result<Request<()>, Error> {
    let mut builder = Request::builder()
        .method(Method::CONNECT)
        .header(DESTINATION_HEADER, destination.as_str())
        .header(
            KIND_HEADER,
            match kind {
                SessionKind::Tcp => "tcp",
                SessionKind::Udp => "udp",
            },
        );
    if kind == SessionKind::Udp {
        let target = udp_target
            .map(|(host, port)| (host.to_owned(), port))
            .or_else(|| {
                canonical_udp_port(destination).map(|port| (destination.to_string(), port))
            });
        if let Some((host, port)) = target {
            validate_connect_udp_host(&host)?;
            builder = builder
                .uri(format!(
                    "https://{peer}{CONNECT_UDP_PATH_PREFIX}{}/{port}/",
                    encode_uri_template_value(&host)
                ))
                .header(CAPSULE_PROTOCOL_HEADER, "?1");
        } else {
            // Opaque destination IDs predate the RFC 9298 target tuple. Keep
            // their private request shape until callers can supply a target.
            builder = builder.uri(format!("https://{peer}/"));
        }
    } else {
        builder = builder.uri(format!("https://{peer}/"));
    }
    let mut request = builder.body(()).map_err(error_display)?;
    if kind == SessionKind::Udp {
        request.extensions_mut().insert(Protocol::CONNECT_UDP);
    }
    Ok(request)
}

fn validate_connect_udp_host(host: &str) -> Result<(), Error> {
    if host.is_empty()
        || host.len() > 255
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'/')
    {
        return Err(Error::Protocol("invalid CONNECT-UDP target host".into()));
    }
    Ok(())
}

fn request_kind(request: &Request<()>) -> Result<SessionKind, Error> {
    if request.method() != Method::CONNECT {
        return Err(Error::Protocol("only CONNECT is supported".into()));
    }
    match (
        request
            .headers()
            .get(KIND_HEADER)
            .and_then(|v| v.to_str().ok()),
        request.extensions().get::<Protocol>(),
    ) {
        (Some("tcp"), None) => Ok(SessionKind::Tcp),
        (Some("udp"), Some(protocol)) if *protocol == Protocol::CONNECT_UDP => {
            validate_connect_udp_request(request)?;
            Ok(SessionKind::Udp)
        }
        (None, Some(protocol)) if *protocol == Protocol::CONNECT_UDP => {
            validate_connect_udp_request(request)?;
            Ok(SessionKind::Udp)
        }
        _ => Err(Error::Protocol("invalid CONNECT kind or :protocol".into())),
    }
}

fn validate_connect_udp_request(request: &Request<()>) -> Result<(), Error> {
    if request.uri().scheme_str() != Some("https") || request.uri().authority().is_none() {
        return Err(Error::Protocol(
            "CONNECT-UDP requires an https URI with an authority".into(),
        ));
    }
    if request.uri().path() == "/" {
        if request.headers().contains_key(DESTINATION_HEADER) {
            return Ok(());
        }
        return Err(Error::MissingDestination);
    }
    parse_connect_udp_target(request.uri())?;
    if !capsule_protocol_enabled(request.headers()) {
        return Err(Error::Protocol(
            "CONNECT-UDP requires Capsule-Protocol: ?1".into(),
        ));
    }
    Ok(())
}

/// Resolves `target` to the address a TCP service is actually listening on.
///
/// A name such as `localhost` can resolve to both `::1` and `127.0.0.1`, while
/// a service usually listens on only one. Returns the first resolved address
/// that accepts a connection, or the first resolved address when none does
/// (the service may simply not be up yet). `None` means the name did not
/// resolve at all.
pub async fn resolve_tcp_target(target: &str) -> std::io::Result<Option<std::net::SocketAddr>> {
    const PROBE_TIMEOUT: Duration = Duration::from_millis(500);
    let candidates: Vec<_> = tokio::net::lookup_host(target).await?.collect();
    for address in &candidates {
        if let Ok(Ok(_)) = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(address)).await {
            return Ok(Some(*address));
        }
    }
    Ok(candidates.into_iter().next())
}

/// Validates an RFC 9298 HTTP/3 CONNECT-UDP request using the default URI
/// template and returns its decoded target tuple.
///
/// This intentionally accepts no Datum routing headers as a substitute for the
/// standard URI. Standards-facing listeners can use it before applying their
/// own authentication and target authorization policy.
pub fn standard_connect_udp_target(request: &Request<()>) -> Result<(String, u16), Error> {
    if request.method() != Method::CONNECT
        || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP)
    {
        return Err(Error::Protocol(
            "expected an extended CONNECT request with :protocol connect-udp".into(),
        ));
    }
    if request.uri().scheme_str() != Some("https") || request.uri().authority().is_none() {
        return Err(Error::Protocol(
            "CONNECT-UDP requires an https URI with an authority".into(),
        ));
    }
    if !capsule_protocol_enabled(request.headers()) {
        return Err(Error::Protocol(
            "CONNECT-UDP requires Capsule-Protocol: ?1".into(),
        ));
    }
    parse_connect_udp_target(request.uri())
}

fn authorized_request(
    policy: &Policy,
    request: &Request<()>,
    peer: EndpointId,
    kind: SessionKind,
) -> Result<Option<(DestinationId, DestinationPolicy)>, Error> {
    let private_destination = request
        .headers()
        .get(DESTINATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::parse)
        .transpose()?;

    if kind != SessionKind::Udp || request.uri().path() == "/" {
        let destination = private_destination.ok_or(Error::MissingDestination)?;
        return Ok(
            authorized_policy(policy, &destination, peer, kind).map(|entry| (destination, entry))
        );
    }

    let (target_host, target_port) = parse_connect_udp_target(request.uri())?;
    if let Some(destination) = private_destination {
        let Some(entry) = authorized_policy(policy, &destination, peer, kind) else {
            return Ok(None);
        };
        // The private ID selects policy; the standard tuple still has to name
        // that policy's UDP target (or its canonical `udp-<port>` alias).
        let requested_socket = target_host
            .parse()
            .ok()
            .map(|ip| SocketAddr::new(ip, target_port));
        let target_matches = match entry.target {
            Target::Udp(target) => {
                requested_socket == Some(target)
                    || (target_host == destination.as_str()
                        && canonical_udp_port(&destination) == Some(target_port))
            }
            Target::Tcp(_) | Target::Local(_) => false,
        };
        if !target_matches {
            return Err(Error::Protocol(
                "CONNECT-UDP URI conflicts with private destination".into(),
            ));
        }
        return Ok(Some((destination, entry)));
    }

    // A third-party client has no Datum destination header. Resolve the RFC
    // target only through existing policy; never turn this into an open proxy.
    let requested_socket = target_host
        .parse()
        .ok()
        .map(|ip| SocketAddr::new(ip, target_port));
    let named_destination = DestinationId::new(target_host).ok();
    Ok(policy.destinations.iter().find_map(|(destination, entry)| {
        let target_matches = match entry.target {
            Target::Udp(target) => {
                requested_socket == Some(target)
                    || (named_destination.as_ref() == Some(destination)
                        && target.port() == target_port)
            }
            Target::Tcp(_) | Target::Local(_) => false,
        };
        (target_matches && entry.access.allows(peer)).then(|| (destination.clone(), entry.clone()))
    }))
}

fn canonical_udp_port(destination: &DestinationId) -> Option<u16> {
    destination
        .as_str()
        .strip_prefix("udp-")?
        .parse::<u16>()
        .ok()
}

fn parse_connect_udp_target(uri: &http::Uri) -> Result<(String, u16), Error> {
    if uri.query().is_some() {
        return Err(Error::Protocol(
            "CONNECT-UDP default URI must not contain a query".into(),
        ));
    }
    let suffix = uri
        .path()
        .strip_prefix(CONNECT_UDP_PATH_PREFIX)
        .ok_or_else(|| Error::Protocol("invalid CONNECT-UDP URI template".into()))?;
    let suffix = suffix
        .strip_suffix('/')
        .ok_or_else(|| Error::Protocol("CONNECT-UDP URI must end in a slash".into()))?;
    let mut segments = suffix.split('/');
    let encoded_host = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Protocol("CONNECT-UDP target host is missing".into()))?;
    let port = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Protocol("CONNECT-UDP target port is missing".into()))?;
    if segments.next().is_some() {
        return Err(Error::Protocol("invalid CONNECT-UDP URI template".into()));
    }
    let host = decode_uri_template_value(encoded_host)?;
    if host.is_empty() || host.len() > 255 || host.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(Error::Protocol("invalid CONNECT-UDP target host".into()));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::Protocol("invalid CONNECT-UDP target port".into()))?;
    Ok((host, port))
}

fn encode_uri_template_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn decode_uri_template_value(value: &str) -> Result<String, Error> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let hex = bytes
            .get(index + 1..index + 3)
            .ok_or_else(|| Error::Protocol("invalid CONNECT-UDP percent encoding".into()))?;
        let high = decode_hex(hex[0])?;
        let low = decode_hex(hex[1])?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| Error::Protocol("CONNECT-UDP target host is not UTF-8".into()))
}

fn decode_hex(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Protocol(
            "invalid CONNECT-UDP percent encoding".into(),
        )),
    }
}

fn capsule_protocol_enabled(headers: &http::HeaderMap) -> bool {
    let mut values = headers.get_all(CAPSULE_PROTOCOL_HEADER).iter();
    matches!(
        values
            .next()
            .and_then(|value| value.to_str().ok())
            .map(str::trim),
        Some("?1")
    ) && values.next().is_none()
}

fn authorized_policy(
    policy: &Policy,
    destination: &DestinationId,
    peer: EndpointId,
    kind: SessionKind,
) -> Option<DestinationPolicy> {
    let entry = policy.destinations.get(destination)?;
    let kind_matches = matches!(
        (entry.target, kind),
        (Target::Tcp(_) | Target::Local(_), SessionKind::Tcp) | (Target::Udp(_), SessionKind::Udp)
    );
    (kind_matches && entry.access.allows(peer)).then(|| entry.clone())
}

fn policy_allows(
    policy: &Policy,
    destination: &DestinationId,
    peer: EndpointId,
    target: Target,
    kind: SessionKind,
) -> bool {
    authorized_policy(policy, destination, peer, kind).is_some_and(|entry| entry.target == target)
}

fn linked_cancel(external: CancellationToken, shutdown: CancellationToken) -> CancellationToken {
    let local = CancellationToken::new();
    let watched = local.clone();
    let dropped = local.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = external.cancelled() => {},
            _ = shutdown.cancelled() => {},
            _ = dropped.cancelled() => {},
        }
        watched.cancel();
    });
    local
}

async fn bridge_tcp_h3(
    io: DuplexStream,
    stream: h3::client::RequestStream<h3_iroh::BidiStream<Bytes>, Bytes>,
    cancel: CancellationToken,
    metrics: &Metrics,
) {
    let (mut send, mut recv) = stream.split();
    let (mut reader, mut writer) = tokio::io::split(io);
    let upload = async {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let len = reader.read(&mut buffer).await?;
            if len == 0 {
                send.finish().await.map_err(h3_io)?;
                return Ok::<(), io::Error>(());
            }
            send.send_data(Bytes::copy_from_slice(&buffer[..len]))
                .await
                .map_err(h3_io)?;
            metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        }
    };
    let download = async {
        while let Some(mut chunk) = recv.recv_data().await.map_err(h3_io)? {
            let len = chunk.remaining();
            writer.write_all_buf(&mut chunk).await?;
            metrics
                .bytes_received
                .fetch_add(len as u64, Ordering::Relaxed);
        }
        writer.shutdown().await
    };
    tokio::select! { _ = cancel.cancelled() => {}, result = async { tokio::try_join!(upload, download) } => if result.is_err() { metrics.errors.fetch_add(1, Ordering::Relaxed); } }
}

async fn bridge_server_tcp<T: AsyncRead + AsyncWrite + Unpin + Send>(
    tcp: T,
    stream: h3::server::RequestStream<h3_iroh::BidiStream<Bytes>, Bytes>,
    cancel: CancellationToken,
    metrics: &Metrics,
) {
    let (mut h3_send, mut h3_recv) = stream.split();
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
    let toward_tcp = async {
        while let Some(mut chunk) = h3_recv.recv_data().await.map_err(h3_io)? {
            let len = chunk.remaining();
            tcp_write.write_all_buf(&mut chunk).await?;
            metrics
                .bytes_received
                .fetch_add(len as u64, Ordering::Relaxed);
        }
        tcp_write.shutdown().await
    };
    let toward_peer = async {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let len = tcp_read.read(&mut buffer).await?;
            if len == 0 {
                h3_send.finish().await.map_err(h3_io)?;
                return Ok::<(), io::Error>(());
            }
            h3_send
                .send_data(Bytes::copy_from_slice(&buffer[..len]))
                .await
                .map_err(h3_io)?;
            metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        }
    };
    tokio::select! {
        _ = cancel.cancelled() => { h3_send.stop_stream(Code::H3_REQUEST_CANCELLED); h3_recv.stop_sending(Code::H3_REQUEST_CANCELLED); }
        result = async { tokio::try_join!(toward_tcp, toward_peer) } => if result.is_err() { metrics.errors.fetch_add(1, Ordering::Relaxed); }
    }
}

fn response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .body(())
        .expect("static response")
}

fn connect_udp_response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .header(CAPSULE_PROTOCOL_HEADER, "?1")
        .body(())
        .expect("static CONNECT-UDP response")
}
fn add_context_id(payload: Bytes) -> Bytes {
    let mut framed = BytesMut::with_capacity(payload.len() + 1);
    framed.extend_from_slice(&[0]);
    framed.extend_from_slice(&payload);
    framed.freeze()
}
fn dropped_datagram(metrics: &Metrics) {
    metrics.datagrams_dropped.fetch_add(1, Ordering::Relaxed);
    metrics.errors.fetch_add(1, Ordering::Relaxed);
}
fn remove_context_id(mut payload: Bytes) -> Option<Bytes> {
    (payload.first() == Some(&0)).then(|| {
        payload.advance(1);
        payload
    })
}
fn h3_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, error.to_string())
}
fn error_display(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}
fn error_debug(error: impl std::fmt::Debug) -> Error {
    Error::Protocol(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        time::{sleep, timeout},
    };

    #[test]
    fn shared_peers_admit_a_peer_added_after_the_policy_was_installed() {
        // The share installs its policy once, at bind time, and then only adds
        // to the shared set. A peer admitted later must be allowed without
        // another policy replacement, which is what closes the gap between a
        // peer pairing and it opening the service.
        let peers = SharedPeers::new();
        let policy = Policy {
            destinations: HashMap::from([(
                DestinationId::tcp(8080),
                DestinationPolicy {
                    target: Target::Tcp("127.0.0.1:8080".parse().unwrap()),
                    access: Access::SharedPeers(peers.clone()),
                },
            )]),
        };
        let peer = SecretKey::generate().public();
        let destination = DestinationId::tcp(8080);
        let target = Target::Tcp("127.0.0.1:8080".parse().unwrap());

        assert!(!policy_allows(
            &policy,
            &destination,
            peer,
            target,
            SessionKind::Tcp
        ));
        assert!(peers.insert(peer));
        assert!(policy_allows(
            &policy,
            &destination,
            peer,
            target,
            SessionKind::Tcp
        ));
        // Another peer stays out.
        assert!(!policy_allows(
            &policy,
            &destination,
            SecretKey::generate().public(),
            target,
            SessionKind::Tcp
        ));
    }

    #[tokio::test]
    async fn resolve_tcp_target_prefers_the_listening_address() {
        // Listen on IPv4 loopback only; `localhost` may resolve to `::1` first.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let resolved = resolve_tcp_target(&format!("localhost:{port}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved, listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn resolve_tcp_target_falls_back_when_nothing_listens() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let resolved = resolve_tcp_target(&format!("localhost:{port}"))
            .await
            .unwrap();
        assert_eq!(resolved.map(|address| address.port()), Some(port));
    }

    async fn endpoint() -> Transport {
        Transport::bind(
            TransportConfig::new(SecretKey::generate())
                .bind_addr("127.0.0.1:0".parse().expect("valid bind address")),
        )
        .await
        .expect("bind transport")
    }

    fn address(transport: &Transport) -> EndpointAddr {
        let details = transport.connection_details();
        details.direct_addresses.into_iter().fold(
            EndpointAddr::new(details.endpoint_id),
            EndpointAddr::with_ip_addr,
        )
    }

    async fn wait_for_active(transport: &Transport, expected: usize) {
        timeout(Duration::from_secs(5), async {
            loop {
                if transport.stats().active_tcp + transport.stats().active_udp == expected {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("active count converged");
    }

    #[test]
    fn canonical_udp_request_uses_rfc_9298_default_template() {
        let peer = SecretKey::generate().public();
        let request = connect_request(peer, &DestinationId::udp(5353), SessionKind::Udp, None)
            .expect("CONNECT-UDP request");
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/udp-5353/5353/"
        );
        assert_eq!(request.uri().query(), None);
        assert_eq!(
            request.extensions().get::<Protocol>(),
            Some(&Protocol::CONNECT_UDP)
        );
        assert_eq!(
            request.headers().get(CAPSULE_PROTOCOL_HEADER).unwrap(),
            "?1"
        );
        assert_eq!(
            request.headers().get(DESTINATION_HEADER).unwrap(),
            "udp-5353"
        );
        assert_eq!(request_kind(&request).unwrap(), SessionKind::Udp);
        assert!(capsule_protocol_enabled(
            connect_udp_response(StatusCode::OK).headers()
        ));
    }

    #[test]
    fn opaque_udp_destination_retains_legacy_request_contract() {
        let peer = SecretKey::generate().public();
        let destination = DestinationId::new("dns-service").unwrap();
        let request = connect_request(peer, &destination, SessionKind::Udp, None).unwrap();
        assert_eq!(request.uri().path(), "/");
        assert!(!request.headers().contains_key(CAPSULE_PROTOCOL_HEADER));
        assert_eq!(request_kind(&request).unwrap(), SessionKind::Udp);
    }

    #[test]
    fn explicit_udp_target_uses_default_template_for_opaque_policy_id() {
        let peer = SecretKey::generate().public();
        let destination = DestinationId::new("dns-service").unwrap();
        let request = connect_request(
            peer,
            &destination,
            SessionKind::Udp,
            Some(("2001:db8::53", 53)),
        )
        .unwrap();
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A53/53/"
        );
        assert_eq!(
            request.headers().get(DESTINATION_HEADER).unwrap(),
            "dns-service"
        );
        assert!(capsule_protocol_enabled(request.headers()));
    }

    #[test]
    fn standard_udp_request_parses_encoded_target_and_requires_capsules() {
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://proxy.example/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/")
            .header(CAPSULE_PROTOCOL_HEADER, " \t?1 \t")
            .body(())
            .unwrap();
        request.extensions_mut().insert(Protocol::CONNECT_UDP);
        assert_eq!(request_kind(&request).unwrap(), SessionKind::Udp);
        assert_eq!(
            parse_connect_udp_target(request.uri()).unwrap(),
            ("2001:db8::1".to_owned(), 443)
        );
        assert_eq!(
            standard_connect_udp_target(&request).unwrap(),
            ("2001:db8::1".to_owned(), 443)
        );

        request.headers_mut().remove(CAPSULE_PROTOCOL_HEADER);
        assert!(matches!(request_kind(&request), Err(Error::Protocol(_))));
        request.headers_mut().insert(
            CAPSULE_PROTOCOL_HEADER,
            http::HeaderValue::from_static("?0"),
        );
        assert!(matches!(request_kind(&request), Err(Error::Protocol(_))));
        request.headers_mut().insert(
            CAPSULE_PROTOCOL_HEADER,
            http::HeaderValue::from_static("?1"),
        );
        request.headers_mut().append(
            CAPSULE_PROTOCOL_HEADER,
            http::HeaderValue::from_static("?1"),
        );
        assert!(matches!(request_kind(&request), Err(Error::Protocol(_))));
    }

    #[test]
    fn malformed_connect_udp_default_uris_are_rejected() {
        for uri in [
            "https://proxy.example/.well-known/masque/udp/example.com/53",
            "https://proxy.example/.well-known/masque/udp//53/",
            "https://proxy.example/.well-known/masque/udp/example.com/not-a-port/",
            "https://proxy.example/.well-known/masque/udp/example.com/53/extra/",
            "https://proxy.example/.well-known/masque/udp/%GG/53/",
            "https://proxy.example/.well-known/masque/udp/example.com/53/?x=1",
        ] {
            let mut request = Request::builder()
                .method(Method::CONNECT)
                .uri(uri)
                .header(CAPSULE_PROTOCOL_HEADER, "?1")
                .body(())
                .unwrap();
            request.extensions_mut().insert(Protocol::CONNECT_UDP);
            assert!(request_kind(&request).is_err(), "accepted {uri}");
        }
    }

    #[test]
    fn standard_headerless_udp_target_resolves_only_through_policy() {
        let peer = SecretKey::generate().public();
        let destination = DestinationId::new("dns-service").unwrap();
        let policy = Policy {
            destinations: HashMap::from([(
                destination.clone(),
                DestinationPolicy {
                    target: Target::Udp("127.0.0.1:5353".parse().unwrap()),
                    access: Access::Peers(HashSet::from([peer])),
                },
            )]),
        };
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://proxy.example/.well-known/masque/udp/127.0.0.1/5353/")
            .header(CAPSULE_PROTOCOL_HEADER, "?1")
            .body(())
            .unwrap();
        request.extensions_mut().insert(Protocol::CONNECT_UDP);
        let kind = request_kind(&request).unwrap();
        let (resolved, entry) = authorized_request(&policy, &request, peer, kind)
            .unwrap()
            .expect("authorized standard target");
        assert_eq!(resolved, destination);
        assert_eq!(entry.target, Target::Udp("127.0.0.1:5353".parse().unwrap()));

        let denied = SecretKey::generate().public();
        assert!(
            authorized_request(&policy, &request, denied, kind)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn private_and_standard_udp_targets_must_agree() {
        let peer = SecretKey::generate().public();
        let destination = DestinationId::new("udp-echo-service").unwrap();
        let policy = Policy {
            destinations: HashMap::from([(
                destination.clone(),
                DestinationPolicy {
                    target: Target::Udp("127.0.0.1:5353".parse().unwrap()),
                    access: Access::Peers(HashSet::from([peer])),
                },
            )]),
        };
        let mut request = connect_request(peer, &destination, SessionKind::Udp, None)
            .expect("CONNECT-UDP request");
        *request.uri_mut() = format!("https://{peer}{CONNECT_UDP_PATH_PREFIX}udp-5353/5354/")
            .parse()
            .unwrap();
        assert!(matches!(
            authorized_request(&policy, &request, peer, SessionKind::Udp),
            Err(Error::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn explicit_binding_removes_all_wildcard_ip_sockets() {
        let transport = endpoint().await;
        let sockets = transport.endpoint().bound_sockets();
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            sockets[0].ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn client_endpoint_tcp_diagnostics_cancellation_and_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = socket.into_split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        let server = endpoint().await;
        // Minimal has no discovery or relay services. The client wrapper must
        // leave that caller-owned configuration intact and use direct hints.
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![b"caller-owned-protocol".to_vec()])
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let endpoint_clone = endpoint.clone();
        let client = Transport::client(endpoint);
        assert_eq!(client.endpoint_id(), endpoint_clone.id());
        assert!(client.connection_details().relay_urls.is_empty());
        assert!(client.inner.accept_task.lock().await.is_none());
        let destination = DestinationId::tcp(8443);
        server
            .replace_policy(Policy {
                destinations: HashMap::from([(
                    destination.clone(),
                    DestinationPolicy {
                        target: Target::Tcp(target),
                        access: Access::Peers(HashSet::from([client.endpoint_id()])),
                    },
                )]),
            })
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let mut tunnel = timeout(
            Duration::from_secs(10),
            client.connect_tcp(address(&server), destination.clone(), cancel.clone()),
        )
        .await
        .expect("client handshake timeout")
        .expect("client CONNECT");
        tunnel.write_all(b"client-only").await.unwrap();
        let mut reply = [0; 11];
        timeout(Duration::from_secs(5), tunnel.read_exact(&mut reply))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&reply, b"client-only");
        assert!(client.stats().bytes_sent >= 11);
        assert!(client.stats().bytes_received >= 11);
        let diagnostics = client.peer_diagnostics(server.endpoint_id()).unwrap();
        assert_eq!(diagnostics.path, ConnectionPath::Direct);
        assert!(diagnostics.latency.is_some());
        wait_for_active(&server, 1).await;
        assert_eq!(client.stats().active_tcp, 1);
        cancel.cancel();
        wait_for_active(&server, 0).await;
        wait_for_active(&client, 0).await;

        let mut second = timeout(
            Duration::from_secs(10),
            client.connect_tcp(
                address(&server),
                destination.clone(),
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        wait_for_active(&server, 1).await;
        assert_eq!(client.stats().active_tcp, 1);
        client.shutdown().await;
        let mut byte = [0; 1];
        let closed = timeout(Duration::from_secs(5), second.read(&mut byte))
            .await
            .expect("shutdown closes tunnel");
        assert!(matches!(closed, Ok(0) | Err(_)));
        wait_for_active(&server, 0).await;
        wait_for_active(&client, 0).await;
        // Closing the transport must also close the original endpoint handle,
        // not just cancel tunnels opened through this wrapper.
        assert!(
            endpoint_clone
                .connect(address(&server), ALPN)
                .await
                .is_err()
        );
        assert!(
            client
                .connect_tcp(address(&server), destination, CancellationToken::new())
                .await
                .is_err()
        );
        server.shutdown().await;
        echo.abort();
    }

    #[tokio::test]
    async fn local_target_receives_authorized_sessions_in_process() {
        let server = endpoint().await;
        let client = endpoint().await;
        let stranger = endpoint().await;
        let mut listener = server.local_listener();
        let destination = DestinationId::tcp(80);
        server
            .replace_policy(Policy {
                destinations: HashMap::from([(
                    destination.clone(),
                    DestinationPolicy {
                        target: listener.target(),
                        access: Access::Peers(HashSet::from([client.endpoint_id()])),
                    },
                )]),
            })
            .await
            .expect("install policy");

        let mut tunnel = client
            .connect_tcp(
                address(&server),
                destination.clone(),
                CancellationToken::new(),
            )
            .await
            .expect("connect to local target");
        let mut local = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("session delivered")
            .expect("listener open");
        assert_eq!(local.peer(), client.endpoint_id());
        assert_eq!(local.destination(), &destination);
        tunnel.write_all(b"ping").await.expect("tunnel write");
        let mut buffer = [0u8; 4];
        local.read_exact(&mut buffer).await.expect("local read");
        assert_eq!(&buffer, b"ping");
        local.write_all(b"pong").await.expect("local write");
        tunnel.read_exact(&mut buffer).await.expect("tunnel read");
        assert_eq!(&buffer, b"pong");

        // Policy still decides who gets in.
        assert!(
            stranger
                .connect_tcp(
                    address(&server),
                    destination.clone(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );

        // A dropped listener refuses new sessions with a 502 rather than
        // hanging them or closing the connection before the answer arrives.
        drop(listener);
        let refused = timeout(
            Duration::from_secs(5),
            client.connect_tcp(address(&server), destination, CancellationToken::new()),
        )
        .await
        .expect("refused promptly")
        .err();
        assert!(
            matches!(refused, Some(Error::Rejected(StatusCode::BAD_GATEWAY))),
            "{refused:?}"
        );
        server.shutdown().await;
        client.shutdown().await;
        stranger.shutdown().await;
    }

    #[tokio::test]
    async fn tcp_connect_roundtrip_and_policy_revocation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
        let echo_addr = listener.local_addr().expect("echo address");
        let echo = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("echo accept");
                tokio::spawn(async move {
                    let mut buffer = [0u8; 64];
                    loop {
                        let len = socket.read(&mut buffer).await.expect("echo read");
                        if len == 0 {
                            break;
                        }
                        socket.write_all(&buffer[..len]).await.expect("echo write");
                    }
                });
            }
        });

        let server = endpoint().await;
        let client = endpoint().await;
        let destination = DestinationId::tcp(8443);
        server
            .replace_policy(Policy {
                destinations: HashMap::from([(
                    destination.clone(),
                    DestinationPolicy {
                        target: Target::Tcp(echo_addr),
                        access: Access::Peers(HashSet::from([client.endpoint_id()])),
                    },
                )]),
            })
            .await
            .expect("install policy");

        let mut tunnel = client
            .connect_tcp(address(&server), destination, CancellationToken::new())
            .await
            .expect("connect tcp");
        tunnel
            .write_all(b"hello over h3")
            .await
            .expect("tunnel write");
        let mut reply = [0u8; 13];
        tunnel.read_exact(&mut reply).await.expect("tunnel read");
        assert_eq!(&reply, b"hello over h3");
        wait_for_active(&server, 1).await;

        server
            .replace_policy(Policy::default())
            .await
            .expect("revoke policy");
        timeout(Duration::from_secs(5), async {
            let mut byte = [0u8; 1];
            loop {
                if tunnel.read(&mut byte).await.is_err() || tunnel.write_all(b"x").await.is_err() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("revoked tunnel closed");
        wait_for_active(&server, 0).await;
        assert_eq!(server.stats().revoked, 1);

        server
            .replace_policy(Policy {
                destinations: HashMap::from([(
                    DestinationId::tcp(8443),
                    DestinationPolicy {
                        target: Target::Tcp(echo_addr),
                        access: Access::Peers(HashSet::from([client.endpoint_id()])),
                    },
                )]),
            })
            .await
            .expect("restore policy");
        let cancelled = CancellationToken::new();
        let _second = client
            .connect_tcp(
                address(&server),
                DestinationId::tcp(8443),
                cancelled.clone(),
            )
            .await
            .expect("second connect");
        wait_for_active(&server, 1).await;
        cancelled.cancel();
        wait_for_active(&server, 0).await;

        client.shutdown().await;
        server.shutdown().await;
        echo.abort();
    }

    #[tokio::test]
    async fn denied_peer_gets_forbidden() {
        let server = endpoint().await;
        let client = endpoint().await;
        let other = SecretKey::generate().public();
        let destination = DestinationId::tcp(443);
        server
            .replace_policy(Policy {
                destinations: HashMap::from([(
                    destination.clone(),
                    DestinationPolicy {
                        target: Target::Tcp("127.0.0.1:9".parse().unwrap()),
                        access: Access::Peers(HashSet::from([other])),
                    },
                )]),
            })
            .await
            .unwrap();
        let error = client
            .connect_tcp(address(&server), destination, CancellationToken::new())
            .await
            .err()
            .expect("peer denied");
        assert!(
            matches!(error, Error::Rejected(StatusCode::FORBIDDEN)),
            "{error:?}"
        );
        assert_eq!(client.stats().active_tcp, 0);
        assert_eq!(client.stats().errors, 1);
        client.shutdown().await;
        server.shutdown().await;
    }

    #[tokio::test]
    async fn udp_connect_roundtrip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp echo bind");
        let echo_addr = socket.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = [0u8; 65_535];
            loop {
                let (len, peer) = socket.recv_from(&mut buffer).await.expect("udp receive");
                if &buffer[..len] == b"oversize-reply" {
                    socket
                        .send_to(&vec![0; MAX_DATAGRAM_PAYLOAD + 1], peer)
                        .await
                        .unwrap();
                    socket.send_to(b"still-alive", peer).await.unwrap();
                    continue;
                }
                socket
                    .send_to(&buffer[..len], peer)
                    .await
                    .expect("udp echo");
            }
        });
        let server = endpoint().await;
        let client = endpoint().await;
        let destination = DestinationId::new("udp-echo-service").unwrap();
        let policy = Policy {
            destinations: HashMap::from([(
                destination.clone(),
                DestinationPolicy {
                    target: Target::Udp(echo_addr),
                    access: Access::Peers(HashSet::from([client.endpoint_id()])),
                },
            )]),
        };
        server.replace_policy(policy.clone()).await.unwrap();

        let tunnel = client
            .connect_udp_target(
                address(&server),
                destination.clone(),
                echo_addr.ip().to_string(),
                echo_addr.port(),
                CancellationToken::new(),
            )
            .await
            .expect("connect udp");
        tunnel
            .send(Bytes::from_static(b"udp over h3"))
            .await
            .expect("send datagram");
        let reply = timeout(Duration::from_secs(5), tunnel.recv())
            .await
            .expect("udp timeout")
            .unwrap_or_else(|| {
                panic!(
                    "udp closed: client={:?} server={:?}",
                    client.stats(),
                    server.stats()
                )
            });
        assert_eq!(&reply[..], b"udp over h3");
        assert!(client.stats().bytes_sent >= 11);
        assert_eq!(client.stats().active_udp, 1);

        for payload in [Bytes::new(), Bytes::from(vec![7; MAX_DATAGRAM_PAYLOAD])] {
            tunnel.send(payload.clone()).await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(5), tunnel.recv())
                    .await
                    .unwrap(),
                Some(payload)
            );
        }
        assert!(matches!(
            tunnel.send(vec![7; MAX_DATAGRAM_PAYLOAD + 1]).await,
            Err(Error::DatagramTooLarge)
        ));
        assert_eq!(client.stats().datagrams_dropped, 1);
        tunnel
            .send(Bytes::from_static(b"oversize-reply"))
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), tunnel.recv())
                .await
                .unwrap()
                .unwrap(),
            Bytes::from_static(b"still-alive")
        );
        assert_eq!(server.stats().datagrams_dropped, 1);

        // A stalled consumer fills the bounded receive queue. Dropping excess
        // packets must not prevent remote policy revocation or cancellation.
        fill_udp_receiver(&client, &tunnel).await;
        server.replace_policy(Policy::default()).await.unwrap();
        wait_for_active(&server, 0).await;
        wait_for_active(&client, 0).await;
        assert_eq!(
            timeout(Duration::from_secs(1), tunnel.recv())
                .await
                .unwrap(),
            None
        );
        assert!(matches!(
            tunnel.send(Bytes::new()).await,
            Err(Error::Closed)
        ));

        server.replace_policy(policy).await.unwrap();
        let tunnel = client
            .connect_udp(address(&server), destination, CancellationToken::new())
            .await
            .unwrap();
        fill_udp_receiver(&client, &tunnel).await;
        drop(tunnel);
        wait_for_active(&client, 0).await;
        wait_for_active(&server, 0).await;

        client.shutdown().await;
        wait_for_active(&client, 0).await;
        server.shutdown().await;
        echo.abort();
    }

    async fn fill_udp_receiver(client: &Transport, tunnel: &UdpTunnel) {
        let before = client.stats().datagrams_dropped;
        timeout(Duration::from_secs(10), async {
            while client.stats().datagrams_dropped == before {
                for _ in 0..32 {
                    tunnel.send(Bytes::from_static(b"fill")).await.unwrap();
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bounded receive queue drops excess datagrams");
    }
}

#[cfg(test)]
mod path_report_tests {
    use super::*;

    fn report(path: ConnectionPath, detail: &str, rtt_ms: u64) -> PeerDiagnostics {
        PeerDiagnostics {
            path,
            detail: Some(detail.into()),
            latency: Some(Duration::from_millis(rtt_ms)),
        }
    }

    #[test]
    fn path_changes_are_reported_at_once() {
        let now = Instant::now();
        let relay = report(ConnectionPath::Relay, "relay", 150);
        assert!(path_report_due(
            &relay,
            now,
            &report(ConnectionPath::Direct, "[2001:db8::1]:1", 12),
            now
        ));
        assert!(path_report_due(
            &relay,
            now,
            &report(ConnectionPath::Relay, "other-relay", 150),
            now
        ));
    }

    #[test]
    fn latency_changes_are_throttled_and_need_a_real_change() {
        let at = Instant::now();
        let last = report(ConnectionPath::Direct, "a", 100);
        let soon = at + Duration::from_secs(2);
        let later = at + PATH_RTT_REPORT_INTERVAL + Duration::from_secs(1);
        assert!(
            !path_report_due(&last, at, &report(ConnectionPath::Direct, "a", 200), soon),
            "throttled"
        );
        assert!(
            !path_report_due(&last, at, &report(ConnectionPath::Direct, "a", 110), later),
            "small change"
        );
        assert!(
            path_report_due(&last, at, &report(ConnectionPath::Direct, "a", 140), later),
            "large change"
        );
    }
}
