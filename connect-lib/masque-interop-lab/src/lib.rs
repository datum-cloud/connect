//! Standards-facing HTTP/3 CONNECT-UDP and CONNECT-IP edge for Datum Connect.
//!
//! The edge deliberately has no resolver or arbitrary-dial API. Every public
//! MASQUE target must be mapped to an already-authorized Connect destination.

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use connect_transport::{
    DestinationId, Transport, ip,
    masque::{ConnectUdpUriTemplate, MasqueFailure, TargetSecurityPolicy},
};
use h3::error::Code;
use h3::ext::Protocol;
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError};
use http::{
    HeaderMap, Method, Response, StatusCode,
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
};
use iroh::EndpointAddr;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const DATAGRAM_CAPSULE: u64 = 0;
const MAX_CAPSULE: usize = 64 * 1024;
const AUTH_REALM: &str = "datum-connect";

/// A single exact public target routed to a policy-checked Connect destination.
#[derive(Clone, Debug)]
pub struct Route {
    pub target_host: String,
    pub target_port: u16,
    pub backend: EndpointAddr,
    pub destination: DestinationId,
}

/// One IPv4 range record carried in an RFC 9484 ROUTE_ADVERTISEMENT capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4RouteRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    /// IP protocol number, or zero for all protocols.
    pub protocol: u8,
}

/// An exact public CONNECT-IP target routed to an authorized Connect IP grant.
/// Each inner vector is a complete route snapshot; an empty snapshot withdraws
/// all routes, allowing callers to publish updates and withdrawals in order.
#[derive(Clone, Debug)]
pub struct IpRoute {
    pub target: String,
    pub protocol: String,
    pub backend: EndpointAddr,
    pub network: String,
    pub assigned_address: Ipv4Addr,
    pub route_updates: Vec<Vec<Ipv4RouteRange>>,
}

/// One caller credential and its exact route grants. Only a SHA-256 digest of
/// the bearer token is retained in memory.
#[derive(Clone)]
pub struct BearerCredential {
    client_id: String,
    token_digest: [u8; 32],
    udp_targets: HashSet<(String, u16)>,
    ip_targets: HashSet<(String, String)>,
}

impl BearerCredential {
    pub fn new(
        client_id: String,
        token: &[u8],
        udp_targets: Vec<(String, u16)>,
        ip_targets: Vec<(String, String)>,
    ) -> Result<Self> {
        if client_id.is_empty() || client_id.len() > 128 || client_id.chars().any(char::is_control)
        {
            bail!("MASQUE client ID must contain 1 to 128 printable characters");
        }
        if token.len() < 32
            || token.len() > 4096
            || !token.is_ascii()
            || token.iter().any(u8::is_ascii_whitespace)
        {
            bail!("MASQUE bearer tokens must contain 32 to 4096 non-whitespace ASCII bytes");
        }
        if udp_targets.is_empty() && ip_targets.is_empty() {
            bail!("MASQUE clients require at least one exact route grant");
        }
        let udp_targets = udp_targets
            .into_iter()
            .map(|(host, port)| (host.to_ascii_lowercase(), port))
            .collect();
        let token_digest: [u8; 32] = Sha256::digest(token).into();
        Ok(Self {
            client_id,
            token_digest,
            udp_targets,
            ip_targets: ip_targets.into_iter().collect(),
        })
    }
}

/// Required HTTP proxy authentication for a MASQUE listener.
#[derive(Clone)]
pub struct ClientAuthentication {
    credentials: Arc<[BearerCredential]>,
}

impl ClientAuthentication {
    pub fn bearer(credentials: Vec<BearerCredential>) -> Result<Self> {
        if credentials.is_empty() {
            bail!("MASQUE listener requires at least one caller credential");
        }
        let mut client_ids = HashSet::new();
        let mut token_digests = HashSet::new();
        for credential in &credentials {
            if !client_ids.insert(credential.client_id.clone()) {
                bail!("duplicate MASQUE client ID");
            }
            if !token_digests.insert(credential.token_digest) {
                bail!("duplicate MASQUE bearer token");
            }
        }
        Ok(Self {
            credentials: credentials.into(),
        })
    }

    fn validate_routes(
        &self,
        udp_routes: &HashMap<(String, u16), Route>,
        ip_routes: &HashMap<(String, String), IpRoute>,
    ) -> Result<()> {
        if self.credentials.is_empty() {
            bail!("MASQUE listener requires caller authentication");
        }
        for credential in self.credentials.iter() {
            if credential
                .udp_targets
                .iter()
                .any(|target| !udp_routes.contains_key(target))
                || credential
                    .ip_targets
                    .iter()
                    .any(|target| !ip_routes.contains_key(target))
            {
                bail!("MASQUE client route grant does not match a configured route");
            }
        }
        Ok(())
    }

    fn authenticate<'a>(&'a self, headers: &HeaderMap) -> Option<&'a BearerCredential> {
        let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        let value = value.as_bytes();
        let separator = value.iter().position(|byte| *byte == b' ')?;
        if !value[..separator].eq_ignore_ascii_case(b"bearer") {
            return None;
        }
        let token = &value[separator + 1..];
        if token.is_empty() || token.iter().any(u8::is_ascii_whitespace) {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token).into();
        self.credentials
            .iter()
            .find(|credential| bool::from(credential.token_digest.ct_eq(&digest)))
    }

    fn authorize_udp(&self, headers: &HeaderMap, target: &(String, u16)) -> AuthDecision {
        let Some(credential) = self.authenticate(headers) else {
            return AuthDecision::AuthenticationRequired;
        };
        credential
            .udp_targets
            .contains(&(target.0.to_ascii_lowercase(), target.1))
            .then_some(AuthDecision::Allowed)
            .unwrap_or(AuthDecision::Forbidden)
    }

    fn authorize_ip(&self, headers: &HeaderMap, target: &str, protocol: &str) -> AuthDecision {
        let Some(credential) = self.authenticate(headers) else {
            return AuthDecision::AuthenticationRequired;
        };
        credential
            .ip_targets
            .contains(&(target.to_owned(), protocol.to_owned()))
            .then_some(AuthDecision::Allowed)
            .unwrap_or(AuthDecision::Forbidden)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthDecision {
    Allowed,
    AuthenticationRequired,
    Forbidden,
}

/// Bound edge listener. Binding is separate from serving so callers can publish
/// readiness only after the UDP socket and TLS configuration are usable.
pub struct Server {
    endpoint: quinn::Endpoint,
    transport: Transport,
    routes: Arc<HashMap<(String, u16), Route>>,
    ip_routes: Arc<HashMap<(String, String), IpRoute>>,
    max_connections: usize,
    max_associations_per_connection: usize,
    connect_udp_uri_template: ConnectUdpUriTemplate,
    target_policy: TargetSecurityPolicy,
    client_authentication: ClientAuthentication,
    drain_timeout: Duration,
}

#[derive(Clone)]
struct ConnectionConfig {
    transport: Transport,
    routes: Arc<HashMap<(String, u16), Route>>,
    ip_routes: Arc<HashMap<(String, String), IpRoute>>,
    connect_udp_uri_template: ConnectUdpUriTemplate,
    target_policy: TargetSecurityPolicy,
    client_authentication: ClientAuthentication,
    max_associations: usize,
}

/// Limits and protocol shape for one standards-facing listener.
#[derive(Clone)]
pub struct ServerOptions {
    pub max_connections: usize,
    pub max_associations_per_connection: usize,
    pub connect_udp_uri_template: ConnectUdpUriTemplate,
    pub drain_timeout: Duration,
    pub client_authentication: ClientAuthentication,
}

impl ServerOptions {
    pub fn authenticated(client_authentication: ClientAuthentication) -> Self {
        Self {
            max_connections: 1024,
            max_associations_per_connection: 128,
            connect_udp_uri_template: ConnectUdpUriTemplate::default(),
            drain_timeout: Duration::from_secs(5),
            client_authentication,
        }
    }
}

impl Server {
    pub fn bind(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
        client_authentication: ClientAuthentication,
    ) -> Result<Self> {
        Self::bind_with_options_and_ip_routes(
            listen,
            tls,
            transport,
            routes,
            vec![],
            ServerOptions::authenticated(client_authentication),
        )
    }

    pub fn bind_with_ip_routes(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
        ip_routes: Vec<IpRoute>,
        client_authentication: ClientAuthentication,
    ) -> Result<Self> {
        Self::bind_with_options_and_ip_routes(
            listen,
            tls,
            transport,
            routes,
            ip_routes,
            ServerOptions::authenticated(client_authentication),
        )
    }

    pub fn bind_with_limits(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
        max_connections: usize,
        max_associations_per_connection: usize,
        client_authentication: ClientAuthentication,
    ) -> Result<Self> {
        Self::bind_with_options_and_ip_routes(
            listen,
            tls,
            transport,
            routes,
            vec![],
            ServerOptions {
                max_connections,
                max_associations_per_connection,
                ..ServerOptions::authenticated(client_authentication)
            },
        )
    }

    pub fn bind_with_limits_and_ip_routes(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
        ip_routes: Vec<IpRoute>,
        max_connections: usize,
        max_associations_per_connection: usize,
        client_authentication: ClientAuthentication,
    ) -> Result<Self> {
        Self::bind_with_options_and_ip_routes(
            listen,
            tls,
            transport,
            routes,
            ip_routes,
            ServerOptions {
                max_connections,
                max_associations_per_connection,
                ..ServerOptions::authenticated(client_authentication)
            },
        )
    }

    pub fn bind_with_options_and_ip_routes(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
        ip_routes: Vec<IpRoute>,
        options: ServerOptions,
    ) -> Result<Self> {
        if options.max_connections == 0
            || options.max_associations_per_connection == 0
            || options.drain_timeout.is_zero()
        {
            bail!("MASQUE connection and association limits must be nonzero");
        }
        let indexed = index_routes(routes, !ip_routes.is_empty())?;
        let indexed_ip = index_ip_routes(ip_routes, !indexed.is_empty())?;
        options
            .client_authentication
            .validate_routes(&indexed, &indexed_ip)?;
        let target_policy = indexed
            .keys()
            .fold(TargetSecurityPolicy::new(), |policy, (host, port)| {
                policy.allow_target(host, *port)
            });
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(tls).context("build QUIC TLS configuration")?,
        ));
        Arc::get_mut(&mut server_config.transport)
            .expect("new transport configuration is unique")
            .datagram_receive_buffer_size(Some(1024 * 1024));
        let endpoint = quinn::Endpoint::server(server_config, listen)
            .context("bind MASQUE HTTP/3 listener")?;
        Ok(Self {
            endpoint,
            transport,
            routes: Arc::new(indexed),
            ip_routes: Arc::new(indexed_ip),
            max_connections: options.max_connections,
            max_associations_per_connection: options.max_associations_per_connection,
            connect_udp_uri_template: options.connect_udp_uri_template,
            target_policy,
            client_authentication: options.client_authentication,
            drain_timeout: options.drain_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("read MASQUE listener address")
    }

    pub async fn serve(self, cancel: CancellationToken) -> Result<()> {
        let connections = Arc::new(Semaphore::new(self.max_connections));
        let connection_config = ConnectionConfig {
            transport: self.transport,
            routes: self.routes,
            ip_routes: self.ip_routes,
            connect_udp_uri_template: self.connect_udp_uri_template,
            target_policy: self.target_policy,
            client_authentication: self.client_authentication,
            max_associations: self.max_associations_per_connection,
        };
        let connection_config = Arc::new(connection_config);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let permit = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tasks.join_next(), if !tasks.is_empty() => continue,
                permit = connections.clone().acquire_owned() => permit.expect("server semaphore is never closed"),
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let connection_cancel = cancel.child_token();
                    let connection_config = connection_config.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve_connection(incoming, connection_config, connection_cancel).await {
                            tracing::warn!(error = %format!("{error:#}"), "masque_connection_failed");
                        }
                    });
                }
            }
        }
        self.endpoint.close(0u32.into(), b"server shutdown");
        if tokio::time::timeout(self.drain_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
}

fn index_routes(
    routes: Vec<Route>,
    other_routes_present: bool,
) -> Result<HashMap<(String, u16), Route>> {
    if routes.is_empty() && !other_routes_present {
        bail!("MASQUE edge requires at least one exact route");
    }
    let mut indexed = HashMap::new();
    for route in routes {
        let key = (route.target_host.to_ascii_lowercase(), route.target_port);
        if indexed.insert(key.clone(), route).is_some() {
            bail!("duplicate MASQUE route for {}:{}", key.0, key.1);
        }
    }
    Ok(indexed)
}

fn index_ip_routes(
    routes: Vec<IpRoute>,
    other_routes_present: bool,
) -> Result<HashMap<(String, String), IpRoute>> {
    if routes.is_empty() && !other_routes_present {
        bail!("MASQUE edge requires at least one exact route");
    }
    let mut indexed = HashMap::new();
    for route in routes {
        if route.target.is_empty()
            || route.target.contains('/')
            || route.protocol.is_empty()
            || route.protocol.contains('/')
            || route.network.is_empty()
            || route.network.len() > 255
            || route.assigned_address.is_unspecified()
            || route.assigned_address.is_multicast()
            || route.route_updates.is_empty()
            || route.route_updates.len() > 128
            || route.route_updates.iter().any(|update| update.len() > 256)
            || route
                .route_updates
                .iter()
                .flatten()
                .any(|range| u32::from(range.start) > u32::from(range.end))
        {
            bail!("CONNECT-IP routes require an exact target, protocol, network, and route update");
        }
        let key = (route.target.clone(), route.protocol.clone());
        if indexed.insert(key.clone(), route).is_some() {
            bail!("duplicate CONNECT-IP route for {}/{}", key.0, key.1);
        }
    }
    Ok(indexed)
}

/// Load a caller-provisioned PEM certificate chain and private key for `h3`.
pub fn load_tls(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("open certificate chain {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("open private key {}", key_path.display()))?;
    load_tls_pem(&cert_pem, &key_pem)
}

/// Build an HTTP/3 TLS configuration from PEM bytes already read by the caller.
pub fn load_tls_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("decode PEM certificate chain")?;
    if certs.is_empty() {
        bail!("certificate chain contains no certificates");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("decode PEM private key")?;
    tls_config(certs, key)
}

pub fn tls_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("certificate and private key do not match")?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

async fn serve_connection(
    incoming: quinn::Incoming,
    config: Arc<ConnectionConfig>,
    cancel: CancellationToken,
) -> Result<()> {
    let connection = incoming.await.context("accept QUIC")?;
    let datagrams_available = connection.max_datagram_size().is_some();
    let mut h3 = h3::server::builder()
        .enable_datagram(datagrams_available)
        .enable_extended_connect(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .context("start HTTP/3")?;
    let mut datagram_reader = datagrams_available.then(|| h3.get_datagram_reader());
    let (closed_tx, mut closed_rx) = mpsc::channel::<u64>(64);
    let mut associations = HashMap::<u64, mpsc::Sender<Bytes>>::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = h3.accept() => {
                let Some(resolver) = accepted.context("accept request")? else { break };
                let (request, mut stream) = resolver.resolve_request().await.context("decode request")?;
                if let Some(failure) = admission_failure(
                    associations.len(),
                    config.max_associations,
                    cancel.is_cancelled(),
                ) {
                    stream.send_response(failure.response()).await?;
                    stream.finish().await?;
                    continue;
                }
                let is_connect_ip = request.method() == Method::CONNECT
                    && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_IP);
                if is_connect_ip {
                    let common_valid = request.uri().scheme_str() == Some("https")
                        && request.uri().query().is_none()
                        && request.headers().get(CAPSULE_PROTOCOL).and_then(|value| value.to_str().ok()) == Some("?1");
                    let target = connect_ip_target(request.uri().path());
                    if !common_valid || target.is_none() {
                        stream.send_response(MasqueFailure::MalformedRequest.response()).await?;
                        stream.finish().await?;
                        continue;
                    }
                    let (target, protocol) = target.expect("checked CONNECT-IP target");
                    match config.client_authentication.authorize_ip(
                        request.headers(),
                        target,
                        protocol,
                    ) {
                        AuthDecision::Allowed => {}
                        AuthDecision::AuthenticationRequired => {
                            stream.send_response(authentication_required_response()).await?;
                            stream.finish().await?;
                            continue;
                        }
                        AuthDecision::Forbidden => {
                            stream.send_response(MasqueFailure::ForbiddenTarget.response()).await?;
                            stream.finish().await?;
                            continue;
                        }
                    }
                    let Some(route) = config.ip_routes.get(&(target.into(), protocol.into())).cloned() else {
                        stream.send_response(MasqueFailure::ForbiddenTarget.response()).await?;
                        stream.finish().await?;
                        continue;
                    };
                    if !datagrams_available {
                        stream.send_response(MasqueFailure::DestinationUnavailable.response()).await?;
                        stream.finish().await?;
                        continue;
                    }
                    let session = match ip::connect(
                        config.transport.endpoint(),
                        route.backend,
                        &route.network,
                        cancel.child_token(),
                    ).await {
                        Ok(session) => session,
                        Err(error) => {
                            tracing::warn!(target, protocol, error = %error, "masque_ip_backend_connect_failed");
                            stream.send_response(ip_backend_failure(&error).response()).await?;
                            stream.finish().await?;
                            continue;
                        }
                    };
                    let stream_id = stream.id();
                    let association_id = stream_id.into_inner();
                    let mut datagram_sender = h3.get_datagram_sender(stream_id);
                    stream.send_response(
                        Response::builder().status(StatusCode::OK).header(CAPSULE_PROTOCOL, "?1").body(())?
                    ).await.context("send CONNECT-IP response")?;

                    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Bytes>(64);
                    associations.insert(association_id, incoming_tx);
                    let closed_tx = closed_tx.clone();
                    let association_cancel = cancel.child_token();
                    tokio::spawn(async move {
                        let result: Result<()> = async {
                            let mut capsule_bytes = BytesMut::new();
                            let request = loop {
                                if let Some(capsule) = take_capsule(&mut capsule_bytes)? {
                                    break capsule;
                                }
                                let Some(mut chunk) = stream.recv_data().await? else {
                                    bail!("CONNECT-IP stream ended before ADDRESS_REQUEST");
                                };
                                let remaining = chunk.remaining();
                                capsule_bytes.extend_from_slice(&chunk.copy_to_bytes(remaining));
                            };
                            let request_id = validate_ipv4_address_request(&request)?;
                            stream.send_data(address_assignment_capsule(request_id, route.assigned_address)).await?;
                            for update in &route.route_updates {
                                stream.send_data(route_advertisement_capsule(update)).await?;
                            }
                            loop {
                                tokio::select! {
                                    _ = association_cancel.cancelled() => break,
                                    incoming = incoming_rx.recv() => {
                                        let Some(packet) = incoming else { break };
                                        session.send(packet).await.context("send internal IP packet")?;
                                    }
                                    incoming = session.recv() => {
                                        let Some(packet) = incoming else { break };
                                        let mut framed = Vec::with_capacity(packet.len() + 1);
                                        framed.push(0);
                                        framed.extend_from_slice(&packet);
                                        match datagram_sender.send_datagram(Bytes::from(framed)) {
                                            Ok(()) => {}
                                            Err(SendDatagramError::TooLarge { .. }) => continue,
                                            Err(error) => return Err(error.into()),
                                        }
                                    }
                                }
                            }
                            Ok(())
                        }.await;
                        if let Err(error) = result {
                            tracing::warn!(error = %format!("{error:#}"), "masque_ip_association_failed");
                        }
                        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                        let _ = closed_tx.send(association_id).await;
                    });
                    continue;
                }
                let target = match config.connect_udp_uri_template.target(&request) {
                    Ok(target) => target,
                    Err(_) => {
                        stream.send_response(MasqueFailure::MalformedRequest.response()).await?;
                        stream.finish().await?;
                        continue;
                    }
                };
                match config
                    .client_authentication
                    .authorize_udp(request.headers(), &target)
                {
                    AuthDecision::Allowed => {}
                    AuthDecision::AuthenticationRequired => {
                        stream.send_response(authentication_required_response()).await?;
                        stream.finish().await?;
                        continue;
                    }
                    AuthDecision::Forbidden => {
                        stream.send_response(MasqueFailure::ForbiddenTarget.response()).await?;
                        stream.finish().await?;
                        continue;
                    }
                }
                if config.target_policy.authorize(&target.0, target.1).is_err() {
                    stream.send_response(MasqueFailure::ForbiddenTarget.response()).await?;
                    stream.finish().await?;
                    continue;
                }
                let route_key = (target.0.to_ascii_lowercase(), target.1);
                let Some(route) = config.routes.get(&route_key).cloned() else {
                    stream.send_response(MasqueFailure::ForbiddenTarget.response()).await?;
                    stream.finish().await?;
                    continue;
                };

                let tunnel = match config.transport.connect_udp(
                    route.backend, route.destination, cancel.child_token()
                ).await {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        tracing::warn!(target_host = target.0, target_port = target.1, error = %error, "masque_backend_connect_failed");
                        stream.send_response(MasqueFailure::from_backend_error(&error).response()).await?;
                        stream.finish().await?;
                        continue;
                    }
                };
                let stream_id = stream.id();
                let association_id = stream_id.into_inner();
                let datagram_sender = datagrams_available.then(|| h3.get_datagram_sender(stream_id));
                stream.send_response(
                    Response::builder().status(StatusCode::OK).header(CAPSULE_PROTOCOL, "?1").body(())?
                ).await.context("send CONNECT-UDP response")?;

                let (incoming_tx, mut incoming_rx) = mpsc::channel::<Bytes>(64);
                associations.insert(association_id, incoming_tx);
                let closed_tx = closed_tx.clone();
                let association_cancel = cancel.child_token();
                tokio::spawn(async move {
                    if let Some(mut datagram_sender) = datagram_sender {
                        loop {
                            tokio::select! {
                                _ = association_cancel.cancelled() => break,
                                incoming = incoming_rx.recv() => {
                                    let Some(payload) = incoming else { break };
                                    if tunnel.send(payload).await.is_err() { break; }
                                }
                                incoming = tunnel.recv() => {
                                    let Some(payload) = incoming else { break };
                                    let mut framed = Vec::with_capacity(payload.len() + 1);
                                    framed.push(0);
                                    framed.extend_from_slice(&payload);
                                    match datagram_sender.send_datagram(Bytes::from(framed)) {
                                        Ok(()) => {}
                                        Err(SendDatagramError::TooLarge { .. }) => continue,
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                    } else {
                        let mut capsules = BytesMut::new();
                        'association: loop {
                            tokio::select! {
                                _ = association_cancel.cancelled() => break,
                                incoming = stream.recv_data() => {
                                    let chunk = match incoming {
                                        Ok(Some(mut chunk)) => {
                                            let remaining = chunk.remaining();
                                            chunk.copy_to_bytes(remaining)
                                        }
                                        Ok(None) | Err(_) => break,
                                    };
                                    capsules.extend_from_slice(&chunk);
                                    loop {
                                        match take_capsule(&mut capsules) {
                                            Ok(Some((DATAGRAM_CAPSULE, payload))) => {
                                                let Some(payload) = context_zero_payload(payload) else { continue };
                                                if tunnel.send(payload).await.is_err() { break; }
                                            }
                                            Ok(Some(_)) => continue,
                                            Ok(None) => break,
                                            Err(_) => break 'association,
                                        }
                                    }
                                }
                                incoming = tunnel.recv() => {
                                    let Some(payload) = incoming else { break };
                                    if stream.send_data(datagram_capsule(&payload)).await.is_err() { break; }
                                }
                            }
                        }
                    }
                    stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                    let _ = closed_tx.send(association_id).await;
                });
            }
            incoming = async { datagram_reader.as_mut().expect("guarded reader").read_datagram().await }, if datagram_reader.is_some() => {
                let datagram = incoming.context("read standard HTTP Datagram")?;
                let association_id = datagram.stream_id().into_inner();
                let Some(payload) = context_zero_payload(datagram.into_payload()) else { continue };
                if let Some(sender) = associations.get(&association_id) {
                    let _ = sender.try_send(payload);
                }
            }
            Some(association_id) = closed_rx.recv() => {
                associations.remove(&association_id);
            }
        }
    }
    cancel.cancel();
    Ok(())
}

fn authentication_required_response() -> Response<()> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, format!("Bearer realm=\"{AUTH_REALM}\""))
        .header(
            connect_transport::masque::PROXY_STATUS_HEADER,
            "datum-connect; error=http_protocol_error",
        )
        .body(())
        .expect("static MASQUE authentication response")
}

fn admission_failure(active: usize, maximum: usize, draining: bool) -> Option<MasqueFailure> {
    if draining {
        Some(MasqueFailure::Draining)
    } else if active >= maximum {
        Some(MasqueFailure::Overloaded)
    } else {
        None
    }
}

fn ip_backend_failure(error: &ip::Error) -> MasqueFailure {
    match error {
        ip::Error::Timeout => MasqueFailure::ConnectionTimeout,
        ip::Error::Rejected(status) | ip::Error::RejectedWithReason { status, .. }
            if *status == StatusCode::GATEWAY_TIMEOUT =>
        {
            MasqueFailure::ConnectionTimeout
        }
        ip::Error::Configuration(_) | ip::Error::Protocol(_) => MasqueFailure::Internal,
        _ => MasqueFailure::DestinationUnavailable,
    }
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16_384 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1usize << (first >> 6);
    if bytes.len() < width {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, width))
}

fn datagram_capsule(payload: &[u8]) -> Bytes {
    let mut capsule = Vec::with_capacity(payload.len() + 4);
    encode_varint(DATAGRAM_CAPSULE, &mut capsule);
    encode_varint((payload.len() + 1) as u64, &mut capsule);
    encode_varint(0, &mut capsule);
    capsule.extend_from_slice(payload);
    Bytes::from(capsule)
}

fn context_zero_payload(payload: Bytes) -> Option<Bytes> {
    let (context, width) = decode_varint(&payload)?;
    (context == 0).then(|| payload.slice(width..))
}

fn connect_ip_target(path: &str) -> Option<(&str, &str)> {
    let suffix = path
        .strip_prefix("/.well-known/masque/ip/")?
        .strip_suffix('/')?;
    let mut parts = suffix.split('/');
    let target = parts.next()?;
    let protocol = parts.next()?;
    (!target.is_empty() && !protocol.is_empty() && parts.next().is_none())
        .then_some((target, protocol))
}

fn capsule(kind: u64, payload: &[u8]) -> Bytes {
    let mut capsule = Vec::with_capacity(payload.len() + 16);
    encode_varint(kind, &mut capsule);
    encode_varint(payload.len() as u64, &mut capsule);
    capsule.extend_from_slice(payload);
    Bytes::from(capsule)
}

fn validate_ipv4_address_request(request: &(u64, Bytes)) -> Result<u64> {
    if request.0 != 2 {
        bail!("expected RFC 9484 ADDRESS_REQUEST capsule");
    }
    let (request_id, width) =
        decode_varint(&request.1).ok_or_else(|| anyhow!("invalid ADDRESS_REQUEST ID"))?;
    if request_id == 0 || request.1[width..] != [4, 0, 0, 0, 0, 32] {
        bail!("edge requires one wildcard IPv4 host ADDRESS_REQUEST");
    }
    Ok(request_id)
}

fn address_assignment_capsule(request_id: u64, assigned: Ipv4Addr) -> Bytes {
    let mut payload = Vec::with_capacity(14);
    encode_varint(request_id, &mut payload);
    payload.push(4);
    payload.extend_from_slice(&assigned.octets());
    payload.push(32);
    capsule(1, &payload)
}

fn route_advertisement_capsule(routes: &[Ipv4RouteRange]) -> Bytes {
    let mut payload = Vec::with_capacity(routes.len() * 10);
    for route in routes {
        payload.push(4);
        payload.extend_from_slice(&route.start.octets());
        payload.extend_from_slice(&route.end.octets());
        payload.push(route.protocol);
    }
    capsule(3, &payload)
}

fn take_capsule(buffer: &mut BytesMut) -> Result<Option<(u64, Bytes)>> {
    let Some((kind, kind_width)) = decode_varint(buffer) else {
        return Ok(None);
    };
    let Some((length, length_width)) = decode_varint(&buffer[kind_width..]) else {
        return Ok(None);
    };
    if length > MAX_CAPSULE as u64 {
        bail!("capsule exceeds {MAX_CAPSULE} bytes");
    }
    let header = kind_width + length_width;
    let total = header + length as usize;
    if buffer.len() < total {
        return Ok(None);
    }
    let capsule = buffer.split_to(total).freeze();
    Ok(Some((kind, capsule.slice(header..))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn duplicate_and_empty_route_tables_fail_closed() {
        let route = Route {
            target_host: "example.test".into(),
            target_port: 53,
            backend: EndpointAddr::new(SecretKey::generate().public()),
            destination: DestinationId::udp(53),
        };
        assert!(index_routes(vec![], false).is_err());
        assert!(index_routes(vec![route.clone(), route], false).is_err());
    }

    #[test]
    fn route_keys_are_case_insensitive() {
        let backend = EndpointAddr::new(SecretKey::generate().public());
        let routes = index_routes(
            vec![Route {
                target_host: "DNS.Example.NET".into(),
                target_port: 53,
                backend,
                destination: DestinationId::udp(53),
            }],
            false,
        )
        .unwrap();
        assert!(routes.contains_key(&("dns.example.net".into(), 53)));
    }

    #[test]
    fn capsule_decoder_is_incremental_and_bounded() {
        let first = datagram_capsule(b"first");
        let mut wire = BytesMut::from(&first[..2]);
        assert!(take_capsule(&mut wire).unwrap().is_none());
        wire.extend_from_slice(&first[2..]);
        assert_eq!(&take_capsule(&mut wire).unwrap().unwrap().1[..], b"\0first");
        let mut header = Vec::new();
        encode_varint(0, &mut header);
        encode_varint((MAX_CAPSULE + 1) as u64, &mut header);
        assert!(take_capsule(&mut BytesMut::from(&header[..])).is_err());
    }

    #[test]
    fn unknown_and_malformed_context_ids_are_dropped_without_affecting_zero() {
        assert_eq!(
            context_zero_payload(Bytes::from_static(b"\0payload")),
            Some(Bytes::from_static(b"payload"))
        );
        assert_eq!(context_zero_payload(Bytes::new()), None);
        assert_eq!(context_zero_payload(Bytes::from_static(&[1, 2, 3])), None);
        assert_eq!(
            context_zero_payload(Bytes::from_static(&[0x40, 0x40, 9])),
            None
        );
    }

    #[test]
    fn admission_is_bounded_and_draining_wins_over_capacity() {
        assert_eq!(admission_failure(0, 2, false), None);
        assert_eq!(
            admission_failure(2, 2, false),
            Some(MasqueFailure::Overloaded)
        );
        assert_eq!(admission_failure(0, 2, true), Some(MasqueFailure::Draining));
        assert_eq!(admission_failure(2, 2, true), Some(MasqueFailure::Draining));
    }

    #[test]
    fn connect_ip_backend_timeout_has_gateway_timeout_status() {
        assert_eq!(
            ip_backend_failure(&ip::Error::Timeout),
            MasqueFailure::ConnectionTimeout
        );
        assert_eq!(
            ip_backend_failure(&ip::Error::Protocol("bad")),
            MasqueFailure::Internal
        );
    }

    #[test]
    fn connect_ip_default_target_is_exact_and_other_targets_remain_policy_scoped() {
        assert_eq!(
            connect_ip_target("/.well-known/masque/ip/*/*/"),
            Some(("*", "*"))
        );
        assert_eq!(
            connect_ip_target("/.well-known/masque/ip/10.30.0.9/17/"),
            Some(("10.30.0.9", "17"))
        );
        assert_eq!(connect_ip_target("/.well-known/masque/ip/*/*"), None);
        assert_eq!(connect_ip_target("/.well-known/masque/ip/*/*/extra/"), None);
    }

    #[test]
    fn connect_ip_capsules_encode_assignment_update_withdrawal_and_restoration() {
        let request = (2, Bytes::from_static(&[7, 4, 0, 0, 0, 0, 32]));
        assert_eq!(validate_ipv4_address_request(&request).unwrap(), 7);
        assert_eq!(
            address_assignment_capsule(7, Ipv4Addr::new(10, 20, 0, 2)).as_ref(),
            &[1, 7, 7, 4, 10, 20, 0, 2, 32]
        );
        assert_eq!(route_advertisement_capsule(&[]).as_ref(), &[3, 0]);
        let route = Ipv4RouteRange {
            start: Ipv4Addr::new(10, 30, 0, 9),
            end: Ipv4Addr::new(10, 30, 0, 9),
            protocol: 0,
        };
        assert_eq!(
            route_advertisement_capsule(&[route]).as_ref(),
            &[3, 10, 4, 10, 30, 0, 9, 10, 30, 0, 9, 0]
        );
    }

    #[test]
    fn bearer_authentication_is_required_and_route_scoped() {
        let token = b"a-secure-test-token-with-at-least-32-bytes";
        let authentication = ClientAuthentication::bearer(vec![
            BearerCredential::new(
                "client-a".into(),
                token,
                vec![("DNS.Example.NET".into(), 53)],
                vec![("*".into(), "*".into())],
            )
            .unwrap(),
        ])
        .unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            authentication.authorize_udp(&headers, &("dns.example.net".into(), 53)),
            AuthDecision::AuthenticationRequired
        );
        headers.insert(PROXY_AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
        assert_eq!(
            authentication.authorize_udp(&headers, &("dns.example.net".into(), 53)),
            AuthDecision::AuthenticationRequired
        );
        headers.insert(
            PROXY_AUTHORIZATION,
            format!("Bearer {}", String::from_utf8_lossy(token))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            authentication.authorize_udp(&headers, &("dns.example.net".into(), 53)),
            AuthDecision::Allowed
        );
        assert_eq!(
            authentication.authorize_udp(&headers, &("dns.example.net".into(), 54)),
            AuthDecision::Forbidden
        );
        assert_eq!(
            authentication.authorize_ip(&headers, "*", "*"),
            AuthDecision::Allowed
        );
        assert_eq!(
            authentication.authorize_ip(&headers, "other", "*"),
            AuthDecision::Forbidden
        );
    }

    #[test]
    fn authentication_challenge_is_standard_and_detail_free() {
        let response = authentication_required_response();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            response.headers().get(PROXY_AUTHENTICATE).unwrap(),
            "Bearer realm=\"datum-connect\""
        );
        assert_eq!(
            response
                .headers()
                .get(connect_transport::masque::PROXY_STATUS_HEADER)
                .unwrap(),
            "datum-connect; error=http_protocol_error"
        );
    }
}
