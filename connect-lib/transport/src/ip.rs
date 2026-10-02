//! Static IPv4/IPv6 CONNECT-IP prototype (RFC 9484, RFC 9297).
//!
//! Uses extended CONNECT and ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT capsules.
//! IP packets use HTTP Datagrams over QUIC DATAGRAM frames exclusively. Reliable
//! capsules carry only address and route configuration; there is no packet fallback.
//! No IP options, IPv6 extension headers, fragments, dynamic route updates,
//! default routes, or control-plane approval is implemented here. The OS adapter
//! owns forwarding/TTL/ICMP behavior. The dedicated ALPN is a prototype contract.

pub mod peer_policy;

use bytes::Bytes;
use h3::{ConnectionState, ext::Protocol};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Request, Response, StatusCode};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{Mutex, mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

pub const ALPN: &[u8] = b"datum-connect/connect-ip-v1";
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const DATAGRAM_SETUP_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CAPSULE: usize = 16 * 1024;
const MAX_ROUTES: usize = 32;
const MAX_SESSIONS: usize = 128;
const PATH: &str = "/.well-known/masque/ip/*/*/";
const MTU_CLOSE_CODE: u32 = 0x4443_4950;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid CONNECT-IP configuration: {0}")]
    Configuration(&'static str),
    #[error("CONNECT-IP protocol error: {0}")]
    Protocol(&'static str),
    #[error("CONNECT-IP rejected (HTTP {0})")]
    Rejected(StatusCode),
    #[error("CONNECT-IP session is closed")]
    Closed,
    #[error("CONNECT-IP operation timed out")]
    Timeout,
    #[error(
        "invalid IP packet (IP options, IPv6 extensions, fragments, and invalid lengths/checksums are unsupported)"
    )]
    InvalidPacket,
    #[error("IP packet exceeds the negotiated MTU")]
    PacketTooLarge,
    #[error("CONNECT-IP requires peer support for HTTP/3 and QUIC DATAGRAM")]
    DatagramsUnsupported,
    #[error(
        "CONNECT-IP requires IP MTU {required}, but the QUIC path supports only {available} IP bytes; lower the approved MTU or use a larger-MTU path"
    )]
    InsufficientDatagramMtu { required: u16, available: usize },
    #[error("CONNECT-IP QUIC path MTU changed while sending an IP datagram")]
    DatagramMtuChanged,
    #[error(
        "The peer closed CONNECT-IP because its QUIC path MTU no longer supports the approved IP MTU"
    )]
    PeerDatagramMtu,
    #[error("IP source or destination is outside the session grant")]
    AddressPolicy,
    #[error("CONNECT-IP transport failed")]
    Transport,
    #[error("CONNECT-IP stream I/O failed")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Canonical unicast route: IPv4 /8..32 or global/ULA IPv6 /16..128.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IpPrefix {
    address: IpAddr,
    length: u8,
}
impl IpPrefix {
    pub fn address(self) -> IpAddr {
        self.address
    }
    pub fn prefix_len(self) -> u8 {
        self.length
    }
    pub fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.address.is_ipv4()
            && value(address) & mask(self.length, bits(address)) == value(self.address)
    }
    fn last(self) -> IpAddr {
        let last = value(self.address) | !mask(self.length, bits(self.address));
        match self.address {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(last as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(last)),
        }
    }
}
impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}
impl FromStr for IpPrefix {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self> {
        let (address, length) = input
            .split_once('/')
            .ok_or(Error::Configuration("route must be an IP CIDR"))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| Error::Configuration("route must use an IPv4 or IPv6 address"))?;
        let length = length
            .parse::<u8>()
            .map_err(|_| Error::Configuration("invalid route prefix"))?;
        let minimum = if address.is_ipv4() { 8 } else { 16 };
        if !(minimum..=bits(address)).contains(&length)
            || !unicast(address)
            || value(address) & mask(length, bits(address)) != value(address)
        {
            return Err(Error::Configuration(
                "routes must be canonical unicast IPv4 /8..32 or global/ULA IPv6 /16..128 prefixes; no default routes",
            ));
        }
        let prefix = Self { address, length };
        if !unicast(prefix.last()) {
            return Err(Error::Configuration(
                "route crosses a reserved address range",
            ));
        }
        Ok(prefix)
    }
}
fn bits(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}
fn value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    }
}
fn mask(length: u8, bits: u8) -> u128 {
    u128::MAX << (bits - length)
}
fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let a = ip.octets();
            a[0] != 0 && a[0] != 127 && a[0] < 224 && !(a[0] == 169 && a[1] == 254)
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            (first & 0xe000 == 0x2000 || first & 0xfe00 == 0xfc00) && ip.to_ipv4_mapped().is_none()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    pub address: IpAddr,
    pub routes: Vec<IpPrefix>,
    pub mtu: u16,
}
impl SessionConfig {
    pub fn validate(&self) -> Result<()> {
        if !unicast(self.address)
            || !(1280..=1500).contains(&self.mtu)
            || self.routes.is_empty()
            || self.routes.len() > MAX_ROUTES
        {
            return Err(Error::Configuration(
                "require unicast IP address, 1..32 same-family routes, and MTU 1280..1500",
            ));
        }
        let mut routes = self.routes.clone();
        if routes
            .iter()
            .any(|route| route.address.is_ipv4() != self.address.is_ipv4())
        {
            return Err(Error::Configuration(
                "assigned address and routes must use the same IP family",
            ));
        }
        routes.sort();
        if routes
            .windows(2)
            .any(|pair| pair[0].last() >= pair[1].address)
        {
            return Err(Error::Configuration("overlapping routes are not supported"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Grant {
    pub peer: EndpointId,
    pub network: String,
    pub address: IpAddr,
    pub routes: Vec<IpPrefix>,
    pub mtu: u16,
}
impl Grant {
    fn config(&self) -> Result<SessionConfig> {
        valid_network(&self.network)?;
        let mut config = SessionConfig {
            address: self.address,
            routes: self.routes.clone(),
            mtu: self.mtu,
        };
        config.routes.sort();
        config.validate()?;
        Ok(config)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// Always `quic_datagram`; reliable capsules never carry IP packets.
    pub delivery_mode: &'static str,
    /// Current QUIC datagram budget minus HTTP quarter-stream/context framing.
    pub effective_datagram_ip_capacity: usize,
    /// Accepted by the local QUIC send queue, not acknowledged delivery.
    pub datagrams_sent: u64,
    /// Wire datagrams received, including malformed or policy-rejected packets.
    pub datagrams_received: u64,
    pub mtu_errors: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    /// Malformed protocol frames, excluding path MTU and ordinary I/O failures.
    pub protocol_errors: u64,
}
#[derive(Default)]
struct Counters {
    capacity: std::sync::atomic::AtomicUsize,
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    mtu_errors: AtomicU64,
    last_error: std::sync::Mutex<Option<String>>,
    sent: AtomicU64,
    received: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
}
#[derive(Clone, Copy)]
enum Role {
    Client,
    Gateway,
}

/// Authorized packet channel. Dropping it or calling cancel revokes this session.
/// `config` is a metadata snapshot; changing it does not broaden wire policy.
pub struct IpSession {
    pub config: SessionConfig,
    policy: SessionConfig,
    role: Role,
    sender: mpsc::Sender<Bytes>,
    receiver: Mutex<mpsc::Receiver<Bytes>>,
    cancellation: CancellationToken,
    counters: Arc<Counters>,
}
impl IpSession {
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<()> {
        let packet = payload.into();
        if let Err(error) =
            validate_packet(&packet, &self.policy, matches!(self.role, Role::Client))
        {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        tokio::select! { biased; _ = self.cancellation.cancelled() => Err(Error::Closed), result = self.sender.send(packet) => result.map_err(|_| Error::Closed) }
    }
    pub async fn recv(&self) -> Option<Bytes> {
        tokio::select! { biased; _ = self.cancellation.cancelled() => None, packet = async { self.receiver.lock().await.recv().await } => packet }
    }
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub fn stats(&self) -> Stats {
        Stats {
            delivery_mode: "quic_datagram",
            effective_datagram_ip_capacity: self.counters.capacity.load(Ordering::Relaxed),
            datagrams_sent: self.counters.datagrams_sent.load(Ordering::Relaxed),
            datagrams_received: self.counters.datagrams_received.load(Ordering::Relaxed),
            mtu_errors: self.counters.mtu_errors.load(Ordering::Relaxed),
            packets_sent: self.counters.sent.load(Ordering::Relaxed),
            packets_received: self.counters.received.load(Ordering::Relaxed),
            packets_dropped: self.counters.dropped.load(Ordering::Relaxed),
            protocol_errors: self.counters.errors.load(Ordering::Relaxed),
        }
    }
    /// A safe diagnostic recorded before a transport failure closes this session.
    pub fn last_error(&self) -> Option<String> {
        self.counters
            .last_error
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}
impl Drop for IpSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// A statically authorized peer. The consumer must prepare the OS adapter and
/// acknowledge `ready` within 10 seconds; false/dropped readiness rejects join.
pub struct Incoming {
    pub peer: EndpointId,
    pub network: String,
    pub session: IpSession,
    pub ready: oneshot::Sender<bool>,
}

/// A join-scoped inbound grant. Dropping or cancelling this registration removes
/// admission immediately and cancels every session admitted by this grant.
pub struct Registration {
    registry: Arc<Registry>,
    key: (EndpointId, String),
    generation: u64,
    cancel: CancellationToken,
    incoming: mpsc::Receiver<Incoming>,
}
impl Registration {
    pub async fn recv(&mut self) -> Option<Incoming> {
        tokio::select! { biased; _ = self.cancel.cancelled() => None, value = self.incoming.recv() => value }
    }
    pub fn cancel(&self) {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(&self.key)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            entries.remove(&self.key);
        }
        self.cancel.cancel();
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Clone)]
struct Admission {
    config: SessionConfig,
    incoming: mpsc::Sender<Incoming>,
    cancel: CancellationToken,
    generation: u64,
}
pub(crate) struct Registry {
    entries: std::sync::Mutex<HashMap<(EndpointId, String), Admission>>,
    generation: AtomicU64,
    cancel: CancellationToken,
}
impl Registry {
    pub(crate) fn new(cancel: CancellationToken) -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            cancel,
        }
    }
    fn insert(
        &self,
        grant: Grant,
        incoming: mpsc::Sender<Incoming>,
    ) -> Result<(u64, CancellationToken)> {
        let config = grant.config()?;
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.cancel.is_cancelled() {
            return Err(Error::Closed);
        }
        if entries.len() >= MAX_SESSIONS {
            return Err(Error::Configuration("too many IP grants"));
        }
        if entries.contains_key(&(grant.peer, grant.network.clone()))
            || entries.iter().any(|((_, network), entry)| {
                network == &grant.network && entry.config.address == grant.address
            })
        {
            return Err(Error::Configuration(
                "duplicate peer/network or assigned address",
            ));
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let cancel = self.cancel.child_token();
        entries.insert(
            (grant.peer, grant.network),
            Admission {
                config,
                incoming,
                cancel: cancel.clone(),
                generation,
            },
        );
        Ok((generation, cancel))
    }
    pub(crate) fn register(self: &Arc<Self>, grant: Grant) -> Result<Registration> {
        let key = (grant.peer, grant.network.clone());
        let (sender, incoming) = mpsc::channel(4);
        let (generation, cancel) = self.insert(grant, sender)?;
        Ok(Registration {
            registry: self.clone(),
            key,
            generation,
            cancel,
            incoming,
        })
    }
    fn lookup(&self, peer: EndpointId, network: &str) -> Option<Admission> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&(peer, network.into()))
            .filter(|entry| !entry.cancel.is_cancelled())
            .cloned()
    }
}

fn session_parts(
    config: SessionConfig,
    role: Role,
    cancel: CancellationToken,
) -> (IpSession, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>) {
    let (sender, outgoing) = mpsc::channel(64);
    let (incoming, receiver) = mpsc::channel(64);
    let session = IpSession {
        config: config.clone(),
        policy: config,
        role,
        sender,
        receiver: Mutex::new(receiver),
        cancellation: cancel,
        counters: Arc::new(Counters::default()),
    };
    (session, outgoing, incoming)
}

pub async fn connect(
    endpoint: Endpoint,
    peer: EndpointAddr,
    network: &str,
    cancel: CancellationToken,
) -> Result<IpSession> {
    valid_network(network)?;
    let local = cancel.child_token();
    let guard = local.clone().drop_guard();
    let result = tokio::select! {
        _ = local.cancelled() => Err(Error::Closed),
        result = tokio::time::timeout(SETUP_TIMEOUT, async {
            let conn = endpoint.connect(peer.clone(), ALPN).await.map_err(|error| {
                tracing::warn!(peer=%peer.id, %network, %error, stage="ip_connect", "CONNECT-IP peer connection failed");
                Error::Transport
            })?;
            observe_connection(&conn, "initiator");
            if conn.max_datagram_size().is_none() { return Err(Error::DatagramsUnsupported); }
            let (mut driver, mut sender) = h3::client::builder().enable_datagram(true).enable_extended_connect(true).build(crate::h3_iroh::Connection::new(conn.clone())).await.map_err(|_| Error::Transport)?;
            let mut request = Request::builder().method(Method::CONNECT).uri(format!("https://{}{PATH}", peer.id)).header("capsule-protocol", "?1").header("x-datum-network", network).body(()).map_err(|_| Error::Configuration("invalid network request"))?;
            request.extensions_mut().insert(Protocol::CONNECT_IP);
            let mut stream = sender.send_request(request).await.map_err(|_| Error::Transport)?;
            let stream_id = stream.id().into_inner();
            let driver_guard = crate::AbortTask::new(tokio::spawn(async move { let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await; }));
            let response = stream.recv_response().await.map_err(|_| Error::Transport)?;
            if !response.status().is_success() {
                return Err(match one_header(response.headers(), "x-datum-ip-error") {
                    Some("datagrams_unsupported") => Error::DatagramsUnsupported,
                    Some("insufficient_datagram_mtu") => Error::InsufficientDatagramMtu {
                        required: one_header(response.headers(), "x-datum-ip-mtu").and_then(|value|value.parse().ok()).unwrap_or(1280),
                        available: one_header(response.headers(), "x-datum-ip-capacity").and_then(|value|value.parse().ok()).unwrap_or(0),
                    },
                    _ => Error::Rejected(response.status()),
                });
            }
            wait_h3_datagrams(&mut sender).await?;
            if one_header(response.headers(), "capsule-protocol") != Some("?1") { return Err(Error::Protocol("missing capsule negotiation")); }
            let mtu = one_header(response.headers(), "x-datum-ip-mtu").and_then(|value| value.parse().ok()).ok_or(Error::Protocol("missing valid MTU"))?;
            let capacity = wait_datagram_capacity(&conn, stream_id, mtu).await?;
            let (mut io, bridge) = tokio::io::duplex(64 * 1024);
            let bridge_cancel = local.clone();
            let bridge_guard = crate::AbortTask::new(tokio::spawn(async move {
                let _sender = sender; let _driver = driver_guard;
                crate::bridge_tcp_h3(bridge, stream, bridge_cancel, &crate::Metrics::default()).await;
            }));
            write_capsule(&mut io, 2, &address_requests()).await?;
            let (kind, assignment) = read_capsule(&mut io).await?;
            if kind != 1 { return Err(Error::Protocol("expected ADDRESS_ASSIGN")); }
            let address = decode_assignment(&assignment)?;
            let (kind, routes) = read_capsule(&mut io).await?;
            if kind != 3 { return Err(Error::Protocol("expected ROUTE_ADVERTISEMENT")); }
            let config = SessionConfig { address, routes: decode_routes(&routes)?, mtu }; config.validate()?;
            let (session, outgoing, incoming) = session_parts(config.clone(), Role::Client, local.clone());
            session.counters.capacity.store(capacity, Ordering::Relaxed);
            let counters = session.counters.clone(); let task_cancel = local.clone();
            tokio::spawn(async move { let _bridge = bridge_guard; run_session(io, DatagramPath { connection: conn, stream_id, low_capacity_since: None }, config, Role::Client, outgoing, incoming, task_cancel, counters).await; });
            Ok(session)
        }) => result.map_err(|_| Error::Timeout)?,
    };
    if result.is_ok() {
        guard.disarm();
    }
    result
}

/// Accepts only this module's dedicated ALPN. Configure it on the endpoint
/// before binding; this function owns acceptance but does not close the endpoint.
/// Grants are immutable for this server lifetime. Cancel an Incoming session or
/// the server token to revoke access. At most 128 setup/active sessions exist.
pub async fn serve(
    endpoint: Endpoint,
    grants: Vec<Grant>,
    incoming: mpsc::Sender<Incoming>,
    cancel: CancellationToken,
) -> Result<()> {
    let local = cancel.child_token();
    let _guard = local.clone().drop_guard();
    let policies = Arc::new(Registry::new(local.clone()));
    for grant in grants {
        policies.insert(grant, incoming.clone())?;
    }
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = local.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            request = endpoint.accept() => {
                let Some(request) = request else { break; };
                if tasks.len() >= MAX_SESSIONS { request.refuse(); continue; }
                let policies = policies.clone(); let child = local.child_token();
                tasks.spawn(async move {
                    let _guard = child.clone().drop_guard();
                    let result = async {
                        let conn = tokio::time::timeout(SETUP_TIMEOUT, async { request.accept().map_err(|_|Error::Transport)?.await.map_err(|_|Error::Transport) }).await.map_err(|_|Error::Timeout)??;
                        serve_connection(conn, policies, child).await
                    }.await;
                    if let Err(error) = result { tracing::debug!(stage="connect_ip", %error, "CONNECT-IP session ended"); }
                });
            }
        }
    }
    local.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub(crate) async fn serve_connection(
    conn: iroh::endpoint::Connection,
    policies: Arc<Registry>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut _session_lifetime = None;
    let setup = async {
        if conn.alpn() != ALPN {
            return Err(Error::Protocol("wrong ALPN"));
        }
        let peer = conn.remote_id();
        observe_connection(&conn, "acceptor");
        let mut h3 = h3::server::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build::<_, Bytes>(crate::h3_iroh::Connection::new(conn.clone()))
            .await
            .map_err(|_| Error::Transport)?;
        let resolver = h3
            .accept()
            .await
            .map_err(|_| Error::Transport)?
            .ok_or(Error::Closed)?;
        let (request, mut stream) = resolver
            .resolve_request()
            .await
            .map_err(|_| Error::Transport)?;
        let network = one_header(request.headers(), "x-datum-network")
            .filter(|name| valid_network(name).is_ok());
        let valid = request.method() == Method::CONNECT
            && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_IP)
            && request.uri().scheme_str() == Some("https")
            && request.uri().path() == PATH
            && request.uri().query().is_none()
            && one_header(request.headers(), "capsule-protocol") == Some("?1");
        let admission = if valid {
            network.and_then(|name| policies.lookup(peer, name))
        } else {
            None
        };
        let Some(admission) = admission else {
            stream
                .send_response(
                    Response::builder()
                        .status(if valid { 403 } else { 400 })
                        .body(())
                        .unwrap(),
                )
                .await
                .map_err(|_| Error::Transport)?;
            stream.finish().await.map_err(|_| Error::Transport)?;
            // Let the peer receive the response before the connection closes.
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Err(Error::Rejected(if valid {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            }));
        };
        let Admission {
            config,
            incoming,
            cancel: membership,
            ..
        } = admission;
        let membership_lifetime = membership.clone();
        let connection_cancel = cancel.clone();
        let membership_guard = crate::AbortTask::new(tokio::spawn(async move {
            membership.cancelled().await;
            connection_cancel.cancel();
        }));
        let stream_id = stream.id().into_inner();
        let mut settings = h3.get_datagram_sender(stream.id());
        // Continue polling control streams after accepting the CONNECT. SETTINGS
        // can arrive later than the request. This connection permits one session.
        let driver_guard = crate::AbortTask::new(tokio::spawn(async move {
            let _ = h3.accept().await;
        }));
        let supported = async {
            wait_h3_datagrams(&mut settings).await?;
            wait_datagram_capacity(&conn, stream_id, config.mtu).await
        }
        .await;
        let capacity = match supported {
            Ok(capacity) => capacity,
            Err(error) => {
                let (reason, capacity) = match error {
                    Error::DatagramsUnsupported => ("datagrams_unsupported", 0),
                    Error::InsufficientDatagramMtu { available, .. } => {
                        ("insufficient_datagram_mtu", available)
                    }
                    _ => return Err(error),
                };
                stream
                    .send_response(
                        Response::builder()
                            .status(503)
                            .header("x-datum-ip-error", reason)
                            .header("x-datum-ip-mtu", config.mtu.to_string())
                            .header("x-datum-ip-capacity", capacity.to_string())
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .map_err(|_| Error::Transport)?;
                stream.finish().await.map_err(|_| Error::Transport)?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                return Err(error);
            }
        };
        let session_cancel = membership_lifetime.child_token();
        _session_lifetime = Some(session_cancel.clone().drop_guard());
        let (session, outgoing, packets) =
            session_parts(config.clone(), Role::Gateway, session_cancel.clone());
        let counters = session.counters.clone();
        counters.capacity.store(capacity, Ordering::Relaxed);
        let (ready, accepted) = oneshot::channel();
        let queued = incoming
            .try_send(Incoming {
                peer,
                network: network.unwrap().into(),
                session,
                ready,
            })
            .is_ok();
        if !queued || !matches!(accepted.await, Ok(true)) || session_cancel.is_cancelled() {
            stream
                .send_response(Response::builder().status(503).body(()).unwrap())
                .await
                .map_err(|_| Error::Transport)?;
            stream.finish().await.map_err(|_| Error::Transport)?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Err(Error::Rejected(StatusCode::SERVICE_UNAVAILABLE));
        }
        stream
            .send_response(
                Response::builder()
                    .status(200)
                    .header("capsule-protocol", "?1")
                    .header("x-datum-ip-mtu", config.mtu.to_string())
                    .body(())
                    .unwrap(),
            )
            .await
            .map_err(|_| Error::Transport)?;
        let (io, bridge) = tokio::io::duplex(64 * 1024);
        let bridge_cancel = cancel.clone();
        let guard = crate::AbortTask::new(tokio::spawn(async move {
            let _driver = driver_guard;
            crate::bridge_server_tcp(bridge, stream, bridge_cancel, &crate::Metrics::default())
                .await;
        }));
        Ok((
            io,
            config,
            outgoing,
            packets,
            counters,
            guard,
            session_cancel,
            membership_guard,
            DatagramPath {
                connection: conn,
                stream_id,
                low_capacity_since: None,
            },
        ))
    };
    let (mut io, config, outgoing, packets, counters, _bridge, session_cancel, _membership, path) = tokio::select! { _ = cancel.cancelled() => return Err(Error::Closed), result = tokio::time::timeout(SETUP_TIMEOUT, setup) => result.map_err(|_| Error::Timeout)?? };
    tokio::select! {
        _ = cancel.cancelled() => return Err(Error::Closed),
        result = tokio::time::timeout(SETUP_TIMEOUT, async {
            let (kind, payload) = read_capsule(&mut io).await?;
            if kind != 2 || payload.as_ref() != address_requests() { return Err(Error::Protocol("expected IPv4/IPv6 ADDRESS_REQUEST")); }
            let assignment = encode_assignment(config.address);
            write_capsule(&mut io, 1, &assignment).await?;
            write_capsule(&mut io, 3, &encode_routes(&config.routes)).await
        }) => result.map_err(|_| Error::Timeout)??,
    }
    run_session(
        io,
        path,
        config,
        Role::Gateway,
        outgoing,
        packets,
        session_cancel,
        counters,
    )
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Session ownership and bounded channels stay explicit.
async fn run_session(
    mut io: DuplexStream,
    mut path: DatagramPath,
    config: SessionConfig,
    role: Role,
    mut outgoing: mpsc::Receiver<Bytes>,
    packets: mpsc::Sender<Bytes>,
    cancel: CancellationToken,
    counters: Arc<Counters>,
) {
    let _guard = cancel.clone().drop_guard();
    let control = async {
        loop {
            let (kind, _) = read_capsule(&mut io).await?;
            if kind == 0 {
                return Err::<(), Error>(Error::Protocol(
                    "reliable IP packet capsules are not negotiated; QUIC DATAGRAM is required",
                ));
            }
            if (1..=3).contains(&kind) {
                return Err(Error::Protocol(
                    "dynamic address or route updates are not supported",
                ));
            }
        }
    };
    tokio::pin!(control);
    let mut monitor = tokio::time::interval(Duration::from_millis(100));
    monitor.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result: Result<()> = async {
        loop {
            if cancel.is_cancelled() { return Ok(()); }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = &mut control => return result,
                _ = monitor.tick() => { path.check(config.mtu, &counters)?; },
                next = outgoing.recv() => {
                    let Some(packet) = next else { return Ok(()); };
                    if !path.check(config.mtu, &counters)? {
                        counters.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let wire = encode_datagram(path.stream_id, &packet);
                    match path.connection.send_datagram(wire) {
                        Ok(()) => { counters.sent.fetch_add(1, Ordering::Relaxed); counters.datagrams_sent.fetch_add(1, Ordering::Relaxed); },
                        Err(iroh::endpoint::SendDatagramError::TooLarge) => {
                            return Err(Error::DatagramMtuChanged);
                        },
                        Err(iroh::endpoint::SendDatagramError::UnsupportedByPeer | iroh::endpoint::SendDatagramError::Disabled) => return Err(Error::DatagramsUnsupported),
                        Err(_) => return Err(Error::Transport),
                    }
                },
                incoming = path.connection.read_datagram() => {
                    let wire = incoming.map_err(|_| Error::Transport)?;
                    counters.datagrams_received.fetch_add(1, Ordering::Relaxed);
                    let Some(packet) = decode_datagram(wire, path.stream_id)? else { counters.dropped.fetch_add(1, Ordering::Relaxed); continue; };
                    if validate_packet(&packet, &config, matches!(role, Role::Gateway)).is_err() { counters.dropped.fetch_add(1, Ordering::Relaxed); continue; }
                    match packets.try_send(packet) {
                        Ok(()) => { counters.received.fetch_add(1, Ordering::Relaxed); },
                        Err(mpsc::error::TrySendError::Full(_)) => { counters.dropped.fetch_add(1, Ordering::Relaxed); },
                        Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                    }
                },
            }
        }
    }.await;
    let result = match path.connection.close_reason() {
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(close))
            if close.error_code.into_inner() == u64::from(MTU_CLOSE_CODE) =>
        {
            Err(Error::PeerDatagramMtu)
        }
        _ => result,
    };
    if let Err(error) = result {
        let mtu_error = matches!(
            error,
            Error::InsufficientDatagramMtu { .. }
                | Error::DatagramMtuChanged
                | Error::PeerDatagramMtu
        );
        if mtu_error {
            counters.mtu_errors.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(error, Error::Protocol(_)) {
            counters.errors.fetch_add(1, Ordering::Relaxed);
        }
        *counters
            .last_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.to_string());
        if mtu_error {
            path.connection.close(
                iroh::endpoint::VarInt::from_u32(MTU_CLOSE_CODE),
                b"connect-ip-path-mtu",
            );
        }
        tracing::warn!(stage="ip_datagrams", %error, "CONNECT-IP session closed");
    }
}

struct DatagramPath {
    connection: iroh::endpoint::Connection,
    stream_id: u64,
    low_capacity_since: Option<tokio::time::Instant>,
}
impl DatagramPath {
    fn check(&mut self, mtu: u16, counters: &Counters) -> Result<bool> {
        let capacity = datagram_capacity(self.connection.max_datagram_size(), self.stream_id)?;
        let previous = counters.capacity.swap(capacity, Ordering::Relaxed);
        if previous != capacity {
            for path in self.connection.paths().iter() {
                tracing::debug!(peer=%self.connection.remote_id(), local=?path.local_addr(), remote=?path.remote_addr(), selected=path.is_selected(), effective_datagram_ip_capacity=capacity, previous_capacity=previous, stage="ip_path_capacity", "CONNECT-IP datagram capacity changed");
            }
        }
        let was_reprobing = self.low_capacity_since.is_some();
        let ready = capacity_ready(
            capacity,
            mtu,
            &mut self.low_capacity_since,
            tokio::time::Instant::now(),
        )?;
        if !ready && !was_reprobing {
            tracing::info!(
                stage = "ip_path_capacity",
                capacity,
                mtu,
                "CONNECT-IP pauses sends while path MTU is re-probed"
            );
        } else if ready && was_reprobing {
            tracing::info!(
                stage = "ip_path_capacity",
                capacity,
                mtu,
                "CONNECT-IP path MTU recovered"
            );
        }
        Ok(ready)
    }
}

// Multipath reports the minimum across paths, including newly probed ones.
// Never send oversized packets, but allow a bounded interval for path validation.
fn capacity_ready(
    capacity: usize,
    mtu: u16,
    low_since: &mut Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> Result<bool> {
    if capacity >= usize::from(mtu) {
        *low_since = None;
        return Ok(true);
    }
    let start = *low_since.get_or_insert(now);
    if now.duration_since(start) >= DATAGRAM_SETUP_TIMEOUT {
        require_capacity(capacity, mtu)?;
    }
    Ok(false)
}

async fn wait_h3_datagrams(state: &mut impl ConnectionState) -> Result<()> {
    tokio::time::timeout(DATAGRAM_SETUP_TIMEOUT, async move {
        while !state.settings().enable_datagram() {
            if state.get_conn_error().is_some() {
                return Err(Error::Transport);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| Error::DatagramsUnsupported)?
}

async fn wait_datagram_capacity(
    connection: &iroh::endpoint::Connection,
    stream_id: u64,
    mtu: u16,
) -> Result<usize> {
    let deadline = tokio::time::Instant::now() + DATAGRAM_SETUP_TIMEOUT;
    loop {
        let capacity = datagram_capacity(connection.max_datagram_size(), stream_id)?;
        if capacity >= usize::from(mtu) {
            return Ok(capacity);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::InsufficientDatagramMtu {
                required: mtu,
                available: capacity,
            });
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn require_capacity(capacity: usize, mtu: u16) -> Result<()> {
    if capacity < usize::from(mtu) {
        return Err(Error::InsufficientDatagramMtu {
            required: mtu,
            available: capacity,
        });
    }
    Ok(())
}
fn datagram_capacity(maximum: Option<usize>, stream_id: u64) -> Result<usize> {
    let mut header = Vec::new();
    encode_varint(stream_id / 4, &mut header);
    Ok(maximum
        .ok_or(Error::DatagramsUnsupported)?
        .saturating_sub(header.len() + 1))
}
fn encode_datagram(stream_id: u64, packet: &[u8]) -> Bytes {
    let mut wire = Vec::with_capacity(packet.len() + 9);
    encode_varint(stream_id / 4, &mut wire);
    wire.push(0);
    wire.extend_from_slice(packet);
    wire.into()
}
fn decode_datagram(wire: Bytes, stream_id: u64) -> Result<Option<Bytes>> {
    let (quarter, offset) =
        decode_varint(&wire).ok_or(Error::Protocol("malformed HTTP Datagram quarter stream ID"))?;
    if quarter > ((1u64 << 60) - 1) {
        return Err(Error::Protocol(
            "HTTP Datagram quarter stream ID is out of range",
        ));
    }
    if quarter * 4 != stream_id {
        return Ok(None);
    }
    let (context, length) =
        decode_varint(&wire[offset..]).ok_or(Error::Protocol("missing IP datagram context"))?;
    if context != 0 {
        return Ok(None);
    }
    Ok(Some(wire.slice(offset + length..)))
}

fn observe_connection(connection: &iroh::endpoint::Connection, role: &str) {
    let paths = connection.paths();
    if let Some(path) = paths.iter().find(|path| path.is_selected()) {
        let transport = if path.is_ip() {
            "direct"
        } else if path.is_relay() {
            "relay"
        } else {
            "unknown"
        };
        tracing::info!(peer=%connection.remote_id(), role, path=transport, local=?path.local_addr(), remote=?path.remote_addr(),
            rtt_ms=path.rtt().as_millis() as u64, stage="ip_connected", "CONNECT-IP peer connected");
    } else {
        tracing::info!(peer=%connection.remote_id(), role, path="unknown",
            stage="ip_connected", "CONNECT-IP peer connected");
    }
}

fn valid_network(network: &str) -> Result<()> {
    if network.is_empty()
        || network.len() > 63
        || !network
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(Error::Configuration(
            "network must be 1..63 alphanumeric or hyphen characters",
        ));
    }
    Ok(())
}
fn one_header<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}
fn validate_packet(packet: &[u8], config: &SessionConfig, toward_gateway: bool) -> Result<()> {
    if packet.len() > config.mtu as usize {
        return Err(Error::PacketTooLarge);
    }
    let (source, dest) = if packet.first().is_some_and(|byte| byte >> 4 == 6) {
        if packet.len() < 40
            || packet[7] == 0
            || !matches!(packet[6], 6 | 17 | 58)
            || usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len()
        {
            return Err(Error::InvalidPacket);
        }
        (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
            )),
        )
    } else {
        if packet.len() < 20
            || packet[0] != 0x45
            || u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
            || u16::from_be_bytes([packet[6], packet[7]]) & 0xbfff != 0
            || packet[8] == 0
        {
            return Err(Error::InvalidPacket);
        }
        let mut sum: u32 = packet[..20]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_be_bytes([v[0], v[1]]) as u32)
            .sum();
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        if sum != 65535 {
            return Err(Error::InvalidPacket);
        }
        let source = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let dest = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        (source, dest)
    };
    let (assigned, remote) = if toward_gateway {
        (source, dest)
    } else {
        (dest, source)
    };
    if assigned != config.address
        || !unicast(remote)
        || !config.routes.iter().any(|route| route.contains(remote))
    {
        return Err(Error::AddressPolicy);
    }
    Ok(())
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16384 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}
fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let mut value = u64::from(first & 63);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}
async fn read_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes[..1]).await?;
    let length = 1usize << (bytes[0] >> 6);
    reader.read_exact(&mut bytes[1..length]).await?;
    Ok(decode_varint(&bytes[..length]).unwrap().0)
}
async fn read_capsule(reader: &mut (impl AsyncRead + Unpin)) -> Result<(u64, Bytes)> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    // Once a frame starts, incomplete lengths/bodies cannot retain a task forever.
    tokio::time::timeout(IO_TIMEOUT, async {
        let width = 1usize << (first[0] >> 6);
        let mut encoded = [0u8; 8];
        encoded[0] = first[0];
        reader.read_exact(&mut encoded[1..width]).await?;
        let kind = decode_varint(&encoded[..width]).unwrap().0;
        let length = read_varint(reader).await?;
        if length > MAX_CAPSULE as u64 {
            return Err(Error::Protocol("capsule exceeds bounded size"));
        }
        let mut payload = vec![0; length as usize];
        reader.read_exact(&mut payload).await?;
        Ok((kind, Bytes::from(payload)))
    })
    .await
    .map_err(|_| Error::Timeout)?
}
async fn write_capsule(
    writer: &mut (impl AsyncWrite + Unpin),
    kind: u64,
    payload: &[u8],
) -> Result<()> {
    let mut header = Vec::with_capacity(16);
    encode_varint(kind, &mut header);
    encode_varint(payload.len() as u64, &mut header);
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
fn append_address(bytes: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(ip) => bytes.extend(ip.octets()),
        IpAddr::V6(ip) => bytes.extend(ip.octets()),
    }
}
fn encode_assignment_entry(address: IpAddr) -> Vec<u8> {
    let mut bytes = vec![
        if address.is_ipv4() { 1 } else { 2 },
        if address.is_ipv4() { 4 } else { 6 },
    ];
    append_address(&mut bytes, address);
    bytes.push(bits(address));
    bytes
}
fn address_requests() -> Vec<u8> {
    let mut bytes = encode_assignment_entry(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    bytes.extend(encode_assignment_entry(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    bytes
}
fn encode_assignment(address: IpAddr) -> Vec<u8> {
    // RFC 9484 requires a response for each request ID, including explicit
    // unspecified/max-prefix rejection of the unavailable address family.
    let mut bytes = encode_assignment_entry(if address.is_ipv4() {
        address
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    });
    bytes.extend(encode_assignment_entry(if address.is_ipv6() {
        address
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    }));
    bytes
}
fn decode_address(version: u8, bytes: &[u8]) -> Result<IpAddr> {
    match version {
        4 if bytes.len() == 4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).unwrap(),
        ))),
        6 if bytes.len() == 16 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        ))),
        _ => Err(Error::Protocol("invalid address family or length")),
    }
}
fn decode_assignment(mut payload: &[u8]) -> Result<IpAddr> {
    let mut assigned = None;
    let mut seen = 0u8;
    while !payload.is_empty() {
        let (request, offset) =
            decode_varint(payload).ok_or(Error::Protocol("invalid assignment ID"))?;
        let tail = &payload[offset..];
        let (version, width, prefix, flag) = match request {
            1 => (4, 4, 32, 1),
            2 => (6, 16, 128, 2),
            _ => return Err(Error::Protocol("unexpected assignment ID")),
        };
        if seen & flag != 0
            || tail.len() < width + 2
            || tail[0] != version
            || tail[width + 1] != prefix
        {
            return Err(Error::Protocol("invalid or repeated host assignment"));
        }
        seen |= flag;
        let address = decode_address(version, &tail[1..1 + width])?;
        if !address.is_unspecified() && assigned.replace(address).is_some() {
            return Err(Error::Protocol(
                "this prototype permits one assigned address family per session",
            ));
        }
        payload = &tail[width + 2..];
    }
    if seen != 3 {
        return Err(Error::Protocol("missing address request response"));
    }
    assigned.ok_or(Error::Protocol("gateway rejected both address families"))
}
fn encode_routes(routes: &[IpPrefix]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(routes.len() * 10);
    for route in routes {
        bytes.push(if route.address.is_ipv4() { 4 } else { 6 });
        append_address(&mut bytes, route.address);
        append_address(&mut bytes, route.last());
        bytes.push(0);
    }
    bytes
}
fn decode_routes(mut payload: &[u8]) -> Result<Vec<IpPrefix>> {
    if payload.is_empty() {
        return Err(Error::Protocol("invalid route advertisement length"));
    }
    let mut routes = Vec::new();
    let mut previous = None;
    while !payload.is_empty() {
        let width = match payload[0] {
            4 => 4,
            6 => 16,
            _ => return Err(Error::Protocol("invalid route address family")),
        };
        let length = 2 + width * 2;
        if routes.len() >= MAX_ROUTES || payload.len() < length || payload[length - 1] != 0 {
            return Err(Error::Protocol(
                "invalid route length or unsupported protocol-specific route",
            ));
        }
        let start = decode_address(payload[0], &payload[1..1 + width])?;
        let end = decode_address(payload[0], &payload[1 + width..1 + width * 2])?;
        if start > end || previous.is_some_and(|last| start <= last) {
            return Err(Error::Protocol("unordered or overlapping routes"));
        }
        let size = value(end)
            .checked_sub(value(start))
            .and_then(|range| range.checked_add(1))
            .ok_or(Error::Protocol("route range overflow"))?;
        if !size.is_power_of_two() {
            return Err(Error::Protocol("route range must be an IP prefix"));
        }
        let prefix_len = u32::from(bits(start)) - size.trailing_zeros();
        let prefix = format!("{start}/{prefix_len}").parse()?;
        routes.push(prefix);
        previous = Some(end);
        payload = &payload[length..];
    }
    Ok(routes)
}

#[cfg(test)]
mod tests;
