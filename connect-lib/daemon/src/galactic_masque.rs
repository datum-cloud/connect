//! Versioned client contract for the native Galactic CONNECT-IP provider.
//!
//! This module owns descriptor parsing and fail-closed plan verification. It
//! intentionally shares no field meanings with the legacy iroh gateway path.

use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};

use bytes::{Buf, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use h3::ext::Protocol;
use http::{Method, Request};
use ipnet::Ipv6Net;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use async_trait::async_trait;

pub const TRANSPORT_TYPE: &str = "masque.connect.datum.net/v1";
pub const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/*/*/";
pub const EFFECTIVE_MTU: u16 = 1280;

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SensitiveCredential(String);

impl SensitiveCredential {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SensitiveCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionDescriptor {
    pub binding: String,
    pub policy_revision: String,
    pub network_plan: NetworkPlan,
    pub transport: TransportDescriptor,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPlan {
    pub expected_prefix: Ipv6Net,
    pub destination_prefixes: Vec<Ipv6Net>,
    pub mtu: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportDescriptor {
    #[serde(rename = "type")]
    pub kind: String,
    pub authority: String,
    pub vpc_selector: String,
    pub credential: SensitiveCredential,
    pub expires_at: DateTime<Utc>,
    pub transports: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPlan {
    pub host_address: Ipv6Addr,
    pub prefix: Ipv6Net,
    pub routes: Vec<Ipv6Net>,
    pub mtu: u16,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DescriptorError {
    #[error("unsupported managed transport descriptor")]
    UnsupportedTransport,
    #[error("invalid MASQUE authority")]
    InvalidAuthority,
    #[error("invalid or expired credential descriptor")]
    InvalidCredential,
    #[error("managed CONNECT-IP requires an IPv6 /96 and MTU 1280")]
    InvalidNetworkPlan,
    #[error("assigned prefix differs from the authorized network plan")]
    PrefixMismatch,
    #[error("advertised routes differ from the authorized network plan")]
    RouteMismatch,
}

impl ConnectionDescriptor {
    pub fn parse(input: &[u8], now: DateTime<Utc>) -> Result<Self, DescriptorError> {
        let descriptor: Self =
            serde_json::from_slice(input).map_err(|_| DescriptorError::UnsupportedTransport)?;
        descriptor.validate(now)?;
        Ok(descriptor)
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), DescriptorError> {
        if self.binding.is_empty()
            || self.policy_revision.is_empty()
            || self.transport.kind != TRANSPORT_TYPE
            || self.transport.transports.is_empty()
            || self
                .transport
                .transports
                .iter()
                .any(|transport| transport != "h3" && transport != "h2")
            || self.transport.transports[0] != "h3"
        {
            return Err(DescriptorError::UnsupportedTransport);
        }
        let authority = Url::parse(&format!("https://{}", self.transport.authority))
            .map_err(|_| DescriptorError::InvalidAuthority)?;
        if authority.host_str().is_none()
            || authority.username() != ""
            || authority.password().is_some()
            || authority.path() != "/"
            || authority.query().is_some()
            || authority.fragment().is_some()
            || self.transport.vpc_selector.is_empty()
        {
            return Err(DescriptorError::InvalidAuthority);
        }
        if self.transport.credential.0.is_empty() || self.transport.expires_at <= now {
            return Err(DescriptorError::InvalidCredential);
        }
        if self.network_plan.expected_prefix.prefix_len() != 96
            || self.network_plan.mtu != EFFECTIVE_MTU
            || self.network_plan.destination_prefixes.is_empty()
            || self
                .network_plan
                .destination_prefixes
                .iter()
                .any(|prefix| prefix.prefix_len() == 0)
        {
            return Err(DescriptorError::InvalidNetworkPlan);
        }
        Ok(())
    }

    /// Verify provider capsules before the networking helper is asked to
    /// create an interface or route. Equality is intentional: a subset is a
    /// stale plan and a superset broadens authority.
    pub fn verify_provider_plan(
        &self,
        assigned: Ipv6Net,
        advertised: &[Ipv6Net],
    ) -> Result<VerifiedPlan, DescriptorError> {
        if assigned != self.network_plan.expected_prefix {
            return Err(DescriptorError::PrefixMismatch);
        }
        let expected = self
            .network_plan
            .destination_prefixes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let observed = advertised.iter().copied().collect::<BTreeSet<_>>();
        if expected != observed || advertised.len() != observed.len() {
            return Err(DescriptorError::RouteMismatch);
        }
        let host = Ipv6Addr::from(u128::from(assigned.network()) + 1);
        Ok(VerifiedPlan {
            host_address: host,
            prefix: assigned,
            routes: expected.into_iter().collect(),
            mtu: EFFECTIVE_MTU,
        })
    }
}

/// The helper protocol retains a peer-host field for legacy point-to-point
/// attachments. Galactic routes a delegated prefix instead, so select a
/// deterministic, non-routed ULA sentinel that can never become a TUN route.
pub fn helper_peer_address(plan: &VerifiedPlan) -> Result<Ipv6Addr, DescriptorError> {
    for segment in 0xfc00u16..=0xfdff {
        let candidate = Ipv6Addr::from((u128::from(segment) << 112) | 1);
        if !plan.prefix.contains(&candidate)
            && plan.routes.iter().all(|route| !route.contains(&candidate))
            && candidate != plan.host_address
        {
            return Ok(candidate);
        }
    }
    Err(DescriptorError::InvalidNetworkPlan)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptFailure {
    Connectivity,
    HttpStatus(u16),
    TlsIdentity,
    PlanMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    TryHttp2,
    RemintOnce,
    StopUntilBindingChanges,
    RetryWithBackoff,
    TerminalSecurityFailure,
    FailClosed,
    TerminalProtocolFailure,
}

pub fn recovery_for(transport: &str, failure: AttemptFailure) -> Recovery {
    match failure {
        AttemptFailure::Connectivity if transport == "h3" => Recovery::TryHttp2,
        AttemptFailure::HttpStatus(401) => Recovery::RemintOnce,
        AttemptFailure::HttpStatus(403) => Recovery::StopUntilBindingChanges,
        AttemptFailure::HttpStatus(503) => Recovery::RetryWithBackoff,
        AttemptFailure::TlsIdentity => Recovery::TerminalSecurityFailure,
        AttemptFailure::PlanMismatch => Recovery::FailClosed,
        _ => Recovery::TerminalProtocolFailure,
    }
}

#[derive(Clone, Debug)]
pub struct ObservedProviderPlan {
    pub assigned: Ipv6Net,
    pub advertised: Vec<Ipv6Net>,
}

#[async_trait]
pub trait ConnectIpDialer: Send + Sync {
    async fn dial(
        &self,
        transport: &str,
        descriptor: &ConnectionDescriptor,
    ) -> Result<ObservedProviderPlan, AttemptFailure>;
}

#[async_trait]
pub trait NetworkActivator: Send + Sync {
    async fn activate(&self, plan: VerifiedPlan) -> Result<(), String>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EstablishError {
    #[error("CONNECT-IP failed: {0:?}")]
    Transport(AttemptFailure),
    #[error(transparent)]
    Plan(#[from] DescriptorError),
    #[error("local networking activation failed")]
    Activation,
}

/// Dedicated Galactic adapter orchestration. H2 is attempted only after an H3
/// connectivity failure. Provider setup is verified before activation.
pub async fn establish<D: ConnectIpDialer, A: NetworkActivator>(
    descriptor: &ConnectionDescriptor,
    dialer: &D,
    activator: &A,
) -> Result<VerifiedPlan, EstablishError> {
    let observed = match dialer.dial("h3", descriptor).await {
        Ok(plan) => plan,
        Err(failure)
            if recovery_for("h3", failure) == Recovery::TryHttp2
                && descriptor
                    .transport
                    .transports
                    .iter()
                    .any(|transport| transport == "h2") =>
        {
            dialer
                .dial("h2", descriptor)
                .await
                .map_err(EstablishError::Transport)?
        }
        Err(failure) => return Err(EstablishError::Transport(failure)),
    };
    let verified = descriptor
        .verify_provider_plan(observed.assigned, &observed.advertised)
        .map_err(EstablishError::Plan)?;
    activator
        .activate(verified.clone())
        .await
        .map_err(|_| EstablishError::Activation)?;
    Ok(verified)
}

const MAX_CAPSULE: usize = 16 * 1024;
const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A live RFC 9484 HTTP/3 association. The credential is consumed while the
/// request is built and is never retained in diagnostics.
pub struct H3Session {
    pub observed: ObservedProviderPlan,
    stream_id: u64,
    connection: quinn::Connection,
    endpoint: quinn::Endpoint,
    outgoing: mpsc::Sender<Bytes>,
    incoming: Mutex<mpsc::Receiver<Bytes>>,
    cancel: CancellationToken,
}

pub struct H2Session {
    pub observed: ObservedProviderPlan,
    outgoing: mpsc::Sender<Bytes>,
    incoming: Mutex<mpsc::Receiver<Bytes>>,
    cancel: CancellationToken,
}

pub enum ManagedSession {
    H3(H3Session),
    H2(H2Session),
}

impl ManagedSession {
    pub fn observed(&self) -> &ObservedProviderPlan {
        match self {
            Self::H3(session) => &session.observed,
            Self::H2(session) => &session.observed,
        }
    }

    pub fn transport(&self) -> &'static str {
        match self {
            Self::H3(_) => "h3",
            Self::H2(_) => "h2",
        }
    }

    pub async fn send(&self, packet: impl Into<Bytes>) -> Result<(), AttemptFailure> {
        match self {
            Self::H3(session) => session.send(packet).await,
            Self::H2(session) => session.send(packet).await,
        }
    }

    pub async fn recv(&self) -> Option<Bytes> {
        match self {
            Self::H3(session) => session.recv().await,
            Self::H2(session) => session.recv().await,
        }
    }

    pub fn cancel(&self) {
        match self {
            Self::H3(session) => session.cancel(),
            Self::H2(session) => session.cancel(),
        }
    }
}

pub struct ManagedAttachment {
    project: String,
    network: String,
    binding: String,
    authority: String,
    transport: &'static str,
    interface_name: String,
    routes: Vec<String>,
    assigned_address: String,
    cancel: CancellationToken,
    pub task: JoinHandle<()>,
    sent: Arc<std::sync::atomic::AtomicU64>,
    received: Arc<std::sync::atomic::AtomicU64>,
    failure: Arc<Mutex<Option<String>>>,
}

impl ManagedAttachment {
    pub async fn status(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering;
        serde_json::json!({
            "network": self.network,
            "project": self.project,
            "binding_name": self.binding,
            "mode": "gateway",
            "transport_type": TRANSPORT_TYPE,
            "transport": self.transport,
            "authority": self.authority,
            "assigned_address": self.assigned_address,
            "routes": self.routes,
            "interface_name": self.interface_name,
            "mtu": EFFECTIVE_MTU,
            "running": !self.task.is_finished(),
            "connected": !self.task.is_finished() && self.failure.lock().await.is_none(),
            "state": if self.task.is_finished() { "inactive" } else { "connected" },
            "managed_gateway": true,
            "persistent": true,
            "ephemeral": false,
            "prototype": true,
            "packets_sent": self.sent.load(Ordering::Relaxed),
            "packets_received": self.received.load(Ordering::Relaxed),
            "last_error": self.failure.lock().await.clone(),
        })
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn activate(
    project: &str,
    network: &str,
    binding: &str,
    interface_name: &str,
    descriptor: &ConnectionDescriptor,
    session: ManagedSession,
    cancel: CancellationToken,
    helper: Option<&std::path::Path>,
) -> Result<ManagedAttachment, crate::error::ApiError> {
    use connect_ip_adapter::{IpNet, PacketDevice};
    use std::sync::atomic::{AtomicU64, Ordering};

    let verified = descriptor
        .verify_provider_plan(session.observed().assigned, &session.observed().advertised)
        .map_err(|error| {
            session.cancel();
            crate::error::ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                format!("Galactic assignment does not match the authorized network plan: {error}; no interface was created"),
            )
            .with_code("managed_network_plan_mismatch")
        })?;
    let assigned: IpNet = format!("{}/128", verified.host_address)
        .parse()
        .map_err(|_| crate::error::ApiError::internal("Invalid verified Galactic host address"))?;
    let routes = verified
        .routes
        .iter()
        .map(|route| route.to_string().parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| crate::error::ApiError::internal("Invalid verified Galactic route"))?;
    let peer: IpNet = format!(
        "{}/128",
        helper_peer_address(&verified).map_err(|_| {
            crate::error::ApiError::bad_request(
                "Managed network plan leaves no safe helper peer sentinel",
            )
        })?
    )
    .parse()
    .map_err(|_| crate::error::ApiError::internal("Invalid helper peer sentinel"))?;

    let tun = PacketDevice::create_gateway(
        interface_name,
        assigned,
        peer,
        EFFECTIVE_MTU,
        &routes,
        helper,
    )
    .await
    .map_err(|error| {
        session.cancel();
        crate::error::ApiError::internal(format!(
            "Could not create managed CONNECT-IP interface using {}: {error}",
            connect_ip_adapter::backend()
        ))
    })?;
    let actual_interface = tun.name().to_owned();
    let attachment_cancel = cancel.child_token();
    let task_cancel = attachment_cancel.clone();
    let transport = session.transport();
    let session = Arc::new(session);
    let task_session = session.clone();
    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let task_sent = sent.clone();
    let task_received = received.clone();
    let failure = Arc::new(Mutex::new(None));
    let task_failure = failure.clone();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; usize::from(EFFECTIVE_MTU)];
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => break,
                packet = task_session.recv() => {
                    let Some(packet) = packet else {
                        *task_failure.lock().await = Some("Galactic CONNECT-IP session ended".into());
                        break;
                    };
                    if let Err(error) = tun.write_packet(&packet).await {
                        *task_failure.lock().await = Some(format!("write to managed CONNECT-IP interface: {error}"));
                        break;
                    }
                    task_received.fetch_add(1, Ordering::Relaxed);
                }
                packet = tun.read_packet(&mut buffer) => {
                    let length = match packet {
                        Ok(length) if length > 0 => length,
                        Ok(_) => {
                            *task_failure.lock().await = Some("managed CONNECT-IP interface closed".into());
                            break;
                        }
                        Err(error) => {
                            *task_failure.lock().await = Some(format!("read from managed CONNECT-IP interface: {error}"));
                            break;
                        }
                    };
                    if task_session.send(Bytes::copy_from_slice(&buffer[..length])).await.is_err() {
                        *task_failure.lock().await = Some("Galactic CONNECT-IP packet transport ended".into());
                        break;
                    }
                    task_sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        task_session.cancel();
        task_cancel.cancel();
    });

    Ok(ManagedAttachment {
        project: project.to_owned(),
        network: network.to_owned(),
        binding: binding.to_owned(),
        authority: descriptor.transport.authority.clone(),
        transport,
        interface_name: actual_interface,
        routes: verified.routes.iter().map(ToString::to_string).collect(),
        assigned_address: format!("{}/128", verified.host_address),
        cancel: attachment_cancel,
        task,
        sent,
        received,
        failure,
    })
}

impl H3Session {
    pub async fn send(&self, packet: impl Into<Bytes>) -> Result<(), AttemptFailure> {
        self.outgoing
            .send(packet.into())
            .await
            .map_err(|_| AttemptFailure::Connectivity)
    }

    pub async fn recv(&self) -> Option<Bytes> {
        self.incoming.lock().await.recv().await
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
        self.connection
            .close(0u32.into(), b"managed CONNECT-IP closed");
        self.endpoint
            .close(0u32.into(), b"managed CONNECT-IP closed");
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl Drop for H3Session {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.connection
            .close(0u32.into(), b"managed CONNECT-IP dropped");
    }
}

impl H2Session {
    pub async fn send(&self, packet: impl Into<Bytes>) -> Result<(), AttemptFailure> {
        self.outgoing
            .send(packet.into())
            .await
            .map_err(|_| AttemptFailure::Connectivity)
    }

    pub async fn recv(&self) -> Option<Bytes> {
        self.incoming.lock().await.recv().await
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

impl Drop for H2Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Establish a WebPKI-authenticated HTTP/3 CONNECT-IP association to Galactic.
/// The assignment and advertisement are returned with the live packet channel;
/// callers must verify them against the descriptor before creating an adapter.
pub async fn connect_h3(
    descriptor: &ConnectionDescriptor,
    cancel: CancellationToken,
) -> Result<H3Session, AttemptFailure> {
    tokio::time::timeout(SETUP_TIMEOUT, connect_h3_inner(descriptor, cancel))
        .await
        .map_err(|_| AttemptFailure::Connectivity)?
}

/// Prefer HTTP/3 and use HTTP/2 only when the UDP/QUIC path itself is
/// unreachable. Provider HTTP responses and plan failures never change
/// transports because doing so would bypass an authorization decision.
pub async fn connect_preferred(
    descriptor: &ConnectionDescriptor,
    cancel: CancellationToken,
) -> Result<ManagedSession, AttemptFailure> {
    match connect_h3(descriptor, cancel.child_token()).await {
        Ok(session) => Ok(ManagedSession::H3(session)),
        Err(AttemptFailure::Connectivity)
            if descriptor
                .transport
                .transports
                .iter()
                .any(|transport| transport == "h2") =>
        {
            connect_h2(descriptor, cancel).await.map(ManagedSession::H2)
        }
        Err(error) => Err(error),
    }
}

async fn connect_h3_inner(
    descriptor: &ConnectionDescriptor,
    cancel: CancellationToken,
) -> Result<H3Session, AttemptFailure> {
    let authority = Url::parse(&format!("https://{}", descriptor.transport.authority))
        .map_err(|_| AttemptFailure::TlsIdentity)?;
    let host = authority.host_str().ok_or(AttemptFailure::TlsIdentity)?;
    let port = authority.port().unwrap_or(443);
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| AttemptFailure::Connectivity)?
        .collect::<Vec<_>>();
    let remote = addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv6)
        .or_else(|| addresses.first().copied())
        .ok_or(AttemptFailure::Connectivity)?;

    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| AttemptFailure::TlsIdentity)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| AttemptFailure::TlsIdentity)?;
    let bind: SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
    } else {
        "[::]:0".parse().expect("valid IPv6 wildcard")
    };
    let mut endpoint = quinn::Endpoint::client(bind).map_err(|_| AttemptFailure::Connectivity)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_tls)));
    let connecting = endpoint
        .connect(remote, host)
        .map_err(|_| AttemptFailure::TlsIdentity)?;
    let connection = connecting.await.map_err(classify_quinn_failure)?;
    if connection.max_datagram_size().is_none() {
        return Err(AttemptFailure::Connectivity);
    }

    let (mut driver, mut sender) = h3::client::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|_| AttemptFailure::Connectivity)?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "https://{}{CONNECT_IP_PATH}",
            descriptor.transport.authority
        ))
        .header("capsule-protocol", "?1")
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", descriptor.transport.credential.expose()),
        )
        .header("Galactic-VPC", &descriptor.transport.vpc_selector)
        .body(())
        .map_err(|_| AttemptFailure::Connectivity)?;
    request.extensions_mut().insert(Protocol::CONNECT_IP);
    let mut stream = sender
        .send_request(request)
        .await
        .map_err(|_| AttemptFailure::Connectivity)?;
    let stream_id = stream.id().into_inner();
    let response = stream
        .recv_response()
        .await
        .map_err(|_| AttemptFailure::Connectivity)?;
    if !response.status().is_success() {
        return Err(AttemptFailure::HttpStatus(response.status().as_u16()));
    }
    if response
        .headers()
        .get("capsule-protocol")
        .and_then(|value| value.to_str().ok())
        != Some("?1")
    {
        return Err(AttemptFailure::PlanMismatch);
    }

    let mut capsule_bytes = BytesMut::new();
    let (kind, assignment) = next_capsule(&mut stream, &mut capsule_bytes).await?;
    if kind != 1 {
        return Err(AttemptFailure::PlanMismatch);
    }
    let assigned = decode_assignment_prefix(&assignment)?;
    let (kind, routes) = next_capsule(&mut stream, &mut capsule_bytes).await?;
    if kind != 3 {
        return Err(AttemptFailure::PlanMismatch);
    }
    let advertised = decode_route_advertisement(&routes)?;

    let local = cancel.child_token();
    let task_cancel = local.clone();
    let task_connection = connection.clone();
    let task_advertised = advertised.clone();
    let (outgoing, mut packets_to_provider) = mpsc::channel::<Bytes>(64);
    let (packets_from_provider, incoming) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let drive = async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        };
        tokio::pin!(drive);
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => break,
                _ = &mut drive => break,
                update = stream.recv_data() => {
                    // Dynamic address or route changes require a fresh descriptor.
                    if !matches!(update, Ok(None)) { break; }
                }
                packet = packets_to_provider.recv() => {
                    let Some(packet) = packet else { break };
                    if !packet_allowed(&packet, assigned, &task_advertised, true) { continue; }
                    let wire = encode_http_datagram(stream_id, &packet);
                    if task_connection.send_datagram(wire).is_err() { break; }
                }
                wire = task_connection.read_datagram() => {
                    let Ok(wire) = wire else { break };
                    let Ok(Some(packet)) = decode_http_datagram(wire, stream_id) else { continue };
                    if !packet_allowed(&packet, assigned, &task_advertised, false) { continue; }
                    if packets_from_provider.send(packet).await.is_err() { break; }
                }
            }
        }
        task_cancel.cancel();
        task_connection.close(0u32.into(), b"managed CONNECT-IP ended");
    });

    Ok(H3Session {
        observed: ObservedProviderPlan {
            assigned,
            advertised,
        },
        stream_id,
        connection,
        endpoint,
        outgoing,
        incoming: Mutex::new(incoming),
        cancel: local,
    })
}

pub async fn connect_h2(
    descriptor: &ConnectionDescriptor,
    cancel: CancellationToken,
) -> Result<H2Session, AttemptFailure> {
    tokio::time::timeout(SETUP_TIMEOUT, connect_h2_inner(descriptor, cancel))
        .await
        .map_err(|_| AttemptFailure::Connectivity)?
}

async fn connect_h2_inner(
    descriptor: &ConnectionDescriptor,
    cancel: CancellationToken,
) -> Result<H2Session, AttemptFailure> {
    let authority = Url::parse(&format!("https://{}", descriptor.transport.authority))
        .map_err(|_| AttemptFailure::TlsIdentity)?;
    let host = authority.host_str().ok_or(AttemptFailure::TlsIdentity)?;
    let port = authority.port().unwrap_or(443);
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| AttemptFailure::Connectivity)?
        .collect::<Vec<_>>();
    let mut tcp = None;
    for address in addresses {
        if let Ok(Ok(stream)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            tcp = Some(stream);
            break;
        }
    }
    let tcp = tcp.ok_or(AttemptFailure::Connectivity)?;
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| AttemptFailure::TlsIdentity)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| AttemptFailure::TlsIdentity)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(server_name, tcp)
        .await
        .map_err(|_| AttemptFailure::TlsIdentity)?;
    let (mut sender, connection) = h2::client::handshake(tls)
        .await
        .map_err(|_| AttemptFailure::Connectivity)?;
    sender = sender
        .ready()
        .await
        .map_err(|_| AttemptFailure::Connectivity)?;
    if !sender.is_extended_connect_protocol_enabled() {
        return Err(AttemptFailure::Connectivity);
    }
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "https://{}{CONNECT_IP_PATH}",
            descriptor.transport.authority
        ))
        .header("capsule-protocol", "?1")
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", descriptor.transport.credential.expose()),
        )
        .header("Galactic-VPC", &descriptor.transport.vpc_selector)
        .body(())
        .map_err(|_| AttemptFailure::Connectivity)?;
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-ip"));
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|_| AttemptFailure::Connectivity)?;
    let response = response.await.map_err(|_| AttemptFailure::Connectivity)?;
    if !response.status().is_success() {
        return Err(AttemptFailure::HttpStatus(response.status().as_u16()));
    }
    if response
        .headers()
        .get("capsule-protocol")
        .and_then(|value| value.to_str().ok())
        != Some("?1")
    {
        return Err(AttemptFailure::PlanMismatch);
    }
    let mut recv_stream = response.into_body();
    let mut capsule_bytes = BytesMut::new();
    let (kind, assignment) = next_h2_capsule(&mut recv_stream, &mut capsule_bytes).await?;
    if kind != 1 {
        return Err(AttemptFailure::PlanMismatch);
    }
    let assigned = decode_assignment_prefix(&assignment)?;
    let (kind, routes) = next_h2_capsule(&mut recv_stream, &mut capsule_bytes).await?;
    if kind != 3 {
        return Err(AttemptFailure::PlanMismatch);
    }
    let advertised = decode_route_advertisement(&routes)?;

    let local = cancel.child_token();
    let task_cancel = local.clone();
    let task_advertised = advertised.clone();
    let (outgoing, mut packets_to_provider) = mpsc::channel::<Bytes>(64);
    let (packets_from_provider, incoming) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let drive = connection;
        tokio::pin!(drive);
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => break,
                _ = &mut drive => break,
                capsule = next_h2_capsule(&mut recv_stream, &mut capsule_bytes) => {
                    let Ok((kind, payload)) = capsule else { break };
                    if kind != 0 { break; }
                    let Some((context, context_len)) = decode_varint(&payload) else { break };
                    if context != 0 { continue; }
                    let packet = payload.slice(context_len..);
                    if !packet_allowed(&packet, assigned, &task_advertised, false) { continue; }
                    if packets_from_provider.send(packet).await.is_err() { break; }
                }
                packet = packets_to_provider.recv() => {
                    let Some(packet) = packet else { break };
                    if !packet_allowed(&packet, assigned, &task_advertised, true) { continue; }
                    let mut payload = Vec::with_capacity(packet.len() + 1);
                    encode_varint(0, &mut payload);
                    payload.extend_from_slice(&packet);
                    let capsule = encode_capsule(0, &payload);
                    if send_h2_data(&mut send_stream, capsule).await.is_err() { break; }
                }
            }
        }
        let _ = send_stream.send_data(Bytes::new(), true);
        task_cancel.cancel();
    });

    Ok(H2Session {
        observed: ObservedProviderPlan {
            assigned,
            advertised,
        },
        outgoing,
        incoming: Mutex::new(incoming),
        cancel: local,
    })
}

async fn next_h2_capsule(
    stream: &mut h2::RecvStream,
    buffered: &mut BytesMut,
) -> Result<(u64, Bytes), AttemptFailure> {
    loop {
        if let Some(capsule) = take_capsule(buffered)? {
            return Ok(capsule);
        }
        let chunk = stream
            .data()
            .await
            .ok_or(AttemptFailure::Connectivity)?
            .map_err(|_| AttemptFailure::Connectivity)?;
        if buffered.len().saturating_add(chunk.len()) > MAX_CAPSULE + 16 {
            return Err(AttemptFailure::PlanMismatch);
        }
        buffered.extend_from_slice(&chunk);
    }
}

async fn send_h2_data(
    stream: &mut h2::SendStream<Bytes>,
    bytes: Bytes,
) -> Result<(), AttemptFailure> {
    let length = bytes.len();
    stream.reserve_capacity(length);
    while stream.capacity() < length {
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or(AttemptFailure::Connectivity)?
            .map_err(|_| AttemptFailure::Connectivity)?;
        if capacity == 0 {
            return Err(AttemptFailure::Connectivity);
        }
    }
    stream
        .send_data(bytes, false)
        .map_err(|_| AttemptFailure::Connectivity)
}

fn encode_capsule(kind: u64, payload: &[u8]) -> Bytes {
    let mut capsule = Vec::with_capacity(payload.len() + 16);
    encode_varint(kind, &mut capsule);
    encode_varint(payload.len() as u64, &mut capsule);
    capsule.extend_from_slice(payload);
    Bytes::from(capsule)
}

fn classify_quinn_failure(error: quinn::ConnectionError) -> AttemptFailure {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("certificate")
        || message.contains("unknown issuer")
        || message.contains("not valid for")
        || message.contains("invalid peer")
    {
        AttemptFailure::TlsIdentity
    } else {
        AttemptFailure::Connectivity
    }
}

async fn next_capsule(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    buffered: &mut BytesMut,
) -> Result<(u64, Bytes), AttemptFailure> {
    loop {
        if let Some(capsule) = take_capsule(buffered)? {
            return Ok(capsule);
        }
        let mut chunk = stream
            .recv_data()
            .await
            .map_err(|_| AttemptFailure::Connectivity)?
            .ok_or(AttemptFailure::Connectivity)?;
        let remaining = chunk.remaining();
        if buffered.len().saturating_add(remaining) > MAX_CAPSULE + 16 {
            return Err(AttemptFailure::PlanMismatch);
        }
        buffered.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
}

fn take_capsule(buffered: &mut BytesMut) -> Result<Option<(u64, Bytes)>, AttemptFailure> {
    let Some((kind, kind_len)) = decode_varint(buffered) else {
        return Ok(None);
    };
    let Some((length, length_len)) = decode_varint(&buffered[kind_len..]) else {
        return Ok(None);
    };
    if length > MAX_CAPSULE as u64 {
        return Err(AttemptFailure::PlanMismatch);
    }
    let header = kind_len + length_len;
    let total = header + length as usize;
    if buffered.len() < total {
        return Ok(None);
    }
    buffered.advance(header);
    let payload = buffered.split_to(length as usize).freeze();
    Ok(Some((kind, payload)))
}

fn decode_assignment_prefix(mut payload: &[u8]) -> Result<Ipv6Net, AttemptFailure> {
    let mut assignment = None;
    while !payload.is_empty() {
        let (_, id_len) = decode_varint(payload).ok_or(AttemptFailure::PlanMismatch)?;
        payload = &payload[id_len..];
        let family = *payload.first().ok_or(AttemptFailure::PlanMismatch)?;
        payload = &payload[1..];
        let width = match family {
            4 => 4,
            6 => 16,
            _ => return Err(AttemptFailure::PlanMismatch),
        };
        if payload.len() < width + 1 {
            return Err(AttemptFailure::PlanMismatch);
        }
        let prefix_len = payload[width];
        if family == 6 {
            let address = Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[..width])
                    .map_err(|_| AttemptFailure::PlanMismatch)?,
            );
            if !address.is_unspecified() {
                let prefix =
                    Ipv6Net::new(address, prefix_len).map_err(|_| AttemptFailure::PlanMismatch)?;
                if prefix.network() != address || assignment.replace(prefix).is_some() {
                    return Err(AttemptFailure::PlanMismatch);
                }
            }
        }
        payload = &payload[width + 1..];
    }
    assignment.ok_or(AttemptFailure::PlanMismatch)
}

fn decode_route_advertisement(mut payload: &[u8]) -> Result<Vec<Ipv6Net>, AttemptFailure> {
    let mut routes = Vec::new();
    while !payload.is_empty() {
        if payload.first() != Some(&6) || payload.len() < 34 || payload[33] != 0 {
            return Err(AttemptFailure::PlanMismatch);
        }
        let start = Ipv6Addr::from(
            <[u8; 16]>::try_from(&payload[1..17]).map_err(|_| AttemptFailure::PlanMismatch)?,
        );
        let end = Ipv6Addr::from(
            <[u8; 16]>::try_from(&payload[17..33]).map_err(|_| AttemptFailure::PlanMismatch)?,
        );
        let size = u128::from(end)
            .checked_sub(u128::from(start))
            .and_then(|range| range.checked_add(1))
            .filter(|size| size.is_power_of_two())
            .ok_or(AttemptFailure::PlanMismatch)?;
        let prefix_len = 128 - size.trailing_zeros() as u8;
        let route = Ipv6Net::new(start, prefix_len).map_err(|_| AttemptFailure::PlanMismatch)?;
        if route.network() != start
            || routes
                .last()
                .is_some_and(|last: &Ipv6Net| last.broadcast() >= start)
        {
            return Err(AttemptFailure::PlanMismatch);
        }
        routes.push(route);
        payload = &payload[34..];
    }
    if routes.is_empty() {
        return Err(AttemptFailure::PlanMismatch);
    }
    Ok(routes)
}

fn encode_http_datagram(stream_id: u64, packet: &[u8]) -> Bytes {
    let mut wire = Vec::with_capacity(packet.len() + 9);
    encode_varint(stream_id / 4, &mut wire);
    encode_varint(0, &mut wire);
    wire.extend_from_slice(packet);
    Bytes::from(wire)
}

fn decode_http_datagram(wire: Bytes, stream_id: u64) -> Result<Option<Bytes>, AttemptFailure> {
    let Some((quarter_stream, stream_len)) = decode_varint(&wire) else {
        return Err(AttemptFailure::PlanMismatch);
    };
    if quarter_stream != stream_id / 4 {
        return Ok(None);
    }
    let Some((context, context_len)) = decode_varint(&wire[stream_len..]) else {
        return Err(AttemptFailure::PlanMismatch);
    };
    if context != 0 {
        return Ok(None);
    }
    Ok(Some(wire.slice(stream_len + context_len..)))
}

fn packet_allowed(packet: &[u8], assigned: Ipv6Net, routes: &[Ipv6Net], sending: bool) -> bool {
    if packet.len() < 40 || packet.len() > usize::from(EFFECTIVE_MTU) || packet[0] >> 4 != 6 {
        return false;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("checked length"));
    let destination =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("checked length"));
    let host = Ipv6Addr::from(u128::from(assigned.network()) + 1);
    let (local, remote) = if sending {
        (source, destination)
    } else {
        (destination, source)
    };
    local == host && routes.iter().any(|route| route.contains(&remote))
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16_384 {
        output.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value < 1_073_741_824 {
        output.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 4, 20, 0, 0).unwrap()
    }

    fn descriptor() -> ConnectionDescriptor {
        let input = br#"{
          "binding":"laptop-production","policyRevision":"rev-1",
          "networkPlan":{"expectedPrefix":"fd20:0:27:10:1:1::/96","destinationPrefixes":["fd20:0:27::/48"],"mtu":1280},
          "transport":{"type":"masque.connect.datum.net/v1","authority":"masque.example.test","vpcSelector":"default/vpc","credential":"opaque-secret","expiresAt":"2026-11-04T20:01:00Z","transports":["h3","h2"]}
        }"#;
        ConnectionDescriptor::parse(input, now()).unwrap()
    }

    #[test]
    fn parses_and_redacts_descriptor() {
        let descriptor = descriptor();
        assert_eq!(descriptor.transport.credential.expose(), "opaque-secret");
        let rendered = format!("{descriptor:?}");
        assert!(!rendered.contains("opaque-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn verifies_assignment_and_routes_before_activation() {
        let descriptor = descriptor();
        let assigned = "fd20:0:27:10:1:1::/96".parse().unwrap();
        let routes = vec!["fd20:0:27::/48".parse().unwrap()];
        let verified = descriptor.verify_provider_plan(assigned, &routes).unwrap();
        assert_eq!(
            verified.host_address,
            "fd20:0:27:10:1:1::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(verified.mtu, 1280);
        assert_eq!(
            descriptor.verify_provider_plan("fd20:0:27:10:1:2::/96".parse().unwrap(), &routes),
            Err(DescriptorError::PrefixMismatch)
        );
        assert_eq!(
            descriptor.verify_provider_plan(assigned, &["fd20:0:27::/49".parse().unwrap()]),
            Err(DescriptorError::RouteMismatch)
        );
    }

    #[test]
    fn fallback_and_application_failures_are_distinct() {
        assert_eq!(
            recovery_for("h3", AttemptFailure::Connectivity),
            Recovery::TryHttp2
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(401)),
            Recovery::RemintOnce
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(403)),
            Recovery::StopUntilBindingChanges
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(503)),
            Recovery::RetryWithBackoff
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::TlsIdentity),
            Recovery::TerminalSecurityFailure
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::PlanMismatch),
            Recovery::FailClosed
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(500)),
            Recovery::TerminalProtocolFailure
        );
    }

    #[test]
    fn decodes_galactic_assignment_routes_and_datagrams() {
        let prefix: Ipv6Net = "fd20:0:27:10:1:1::/96".parse().unwrap();
        let mut assignment = Vec::new();
        encode_varint(0, &mut assignment);
        assignment.push(6);
        assignment.extend_from_slice(&prefix.network().octets());
        assignment.push(96);
        assert_eq!(decode_assignment_prefix(&assignment), Ok(prefix));

        let route: Ipv6Net = "fd20:0:27::/48".parse().unwrap();
        let mut advertisement = vec![6];
        advertisement.extend_from_slice(&route.network().octets());
        advertisement.extend_from_slice(&route.broadcast().octets());
        advertisement.push(0);
        assert_eq!(decode_route_advertisement(&advertisement), Ok(vec![route]));

        let packet = Bytes::from_static(&[0x60; 40]);
        let wire = encode_http_datagram(12, &packet);
        assert_eq!(decode_http_datagram(wire, 12).unwrap(), Some(packet));
    }

    #[test]
    fn packet_policy_uses_the_selected_host_and_authorized_routes() {
        let assigned: Ipv6Net = "fd20:0:27:10:1:1::/96".parse().unwrap();
        let route: Ipv6Net = "fd20:0:27::/48".parse().unwrap();
        let host = Ipv6Addr::from(u128::from(assigned.network()) + 1);
        let destination: Ipv6Addr = "fd20:0:27::1234".parse().unwrap();
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&host.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        assert!(packet_allowed(&packet, assigned, &[route], true));
        packet[8..24].copy_from_slice(&destination.octets());
        packet[24..40].copy_from_slice(&host.octets());
        assert!(packet_allowed(&packet, assigned, &[route], false));
        packet[24..40].copy_from_slice(&"fd20:0:28::1".parse::<Ipv6Addr>().unwrap().octets());
        assert!(!packet_allowed(&packet, assigned, &[route], true));
    }

    #[test]
    fn helper_sentinel_is_outside_assignment_and_routes() {
        let plan = descriptor()
            .verify_provider_plan(
                "fd20:0:27:10:1:1::/96".parse().unwrap(),
                &["fd20:0:27::/48".parse().unwrap()],
            )
            .unwrap();
        let peer = helper_peer_address(&plan).unwrap();
        assert!(!plan.prefix.contains(&peer));
        assert!(plan.routes.iter().all(|route| !route.contains(&peer)));
    }

    struct FakeDialer {
        failures: Mutex<Vec<Result<ObservedProviderPlan, AttemptFailure>>>,
        attempts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ConnectIpDialer for FakeDialer {
        async fn dial(
            &self,
            transport: &str,
            _descriptor: &ConnectionDescriptor,
        ) -> Result<ObservedProviderPlan, AttemptFailure> {
            self.attempts.lock().unwrap().push(transport.to_owned());
            self.failures.lock().unwrap().remove(0)
        }
    }

    #[derive(Default)]
    struct FakeActivator(Mutex<Vec<VerifiedPlan>>);

    #[async_trait]
    impl NetworkActivator for FakeActivator {
        async fn activate(&self, plan: VerifiedPlan) -> Result<(), String> {
            self.0.lock().unwrap().push(plan);
            Ok(())
        }
    }

    fn observed(prefix: &str, route: &str) -> ObservedProviderPlan {
        ObservedProviderPlan {
            assigned: prefix.parse().unwrap(),
            advertised: vec![route.parse().unwrap()],
        }
    }

    #[tokio::test]
    async fn activation_waits_for_verified_provider_plan() {
        let dialer = FakeDialer {
            failures: Mutex::new(vec![Ok(observed(
                "fd20:0:27:10:1:2::/96",
                "fd20:0:27::/48",
            ))]),
            attempts: Mutex::new(vec![]),
        };
        let activator = FakeActivator::default();
        assert_eq!(
            establish(&descriptor(), &dialer, &activator).await,
            Err(EstablishError::Plan(DescriptorError::PrefixMismatch))
        );
        assert!(activator.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn falls_back_only_for_h3_connectivity() {
        let dialer = FakeDialer {
            failures: Mutex::new(vec![
                Err(AttemptFailure::Connectivity),
                Ok(observed("fd20:0:27:10:1:1::/96", "fd20:0:27::/48")),
            ]),
            attempts: Mutex::new(vec![]),
        };
        let activator = FakeActivator::default();
        establish(&descriptor(), &dialer, &activator).await.unwrap();
        assert_eq!(&*dialer.attempts.lock().unwrap(), &["h3", "h2"]);
        assert_eq!(activator.0.lock().unwrap().len(), 1);

        let denied = FakeDialer {
            failures: Mutex::new(vec![Err(AttemptFailure::HttpStatus(403))]),
            attempts: Mutex::new(vec![]),
        };
        assert_eq!(
            establish(&descriptor(), &denied, &activator).await,
            Err(EstablishError::Transport(AttemptFailure::HttpStatus(403)))
        );
        assert_eq!(&*denied.attempts.lock().unwrap(), &["h3"]);
    }
}
