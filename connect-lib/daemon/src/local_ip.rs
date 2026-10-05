//! Explicit local-only CONNECT-IP approvals. Attachments are never persisted.
use crate::error::ApiError;
use connect_ip_adapter::{IpNet, PacketDevice};
use connect_transport::ip;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalIpConfig {
    /// Root-owned helper socket. Keeps this daemon and its OIDC session unprivileged.
    #[serde(default)]
    pub network_helper: Option<std::path::PathBuf>,
    pub underlay_address: IpAddr,
    #[serde(default)]
    pub underlay_port: u16,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub peer_bindings: Vec<crate::peer_ip::Binding>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub project: String,
    pub network: String,
    pub gateway: String,
    pub addresses: Vec<SocketAddr>,
    /// Relay-only ConnectGateway endpoints are valid when the VPC gateway has
    /// no public underlay address. Existing static approvals leave this empty.
    #[serde(default)]
    pub relay_urls: Vec<String>,
    pub assigned_address: String,
    pub routes: Vec<String>,
    pub interface_name: String,
    pub mtu: u16,
}

impl LocalIpConfig {
    pub async fn load(path: &Path) -> Result<Self, ApiError> {
        #[cfg(windows)]
        connect_lib::secure_fs::validate_private_path(path).await?;
        let path = path.to_path_buf();
        let bytes = tokio::task::spawn_blocking(move || read_config(&path))
            .await
            .map_err(|_| ApiError::internal("Could not read local IP configuration"))??;
        let value: Self = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::bad_request("Invalid local IP configuration JSON; underlay_address must be an IPv4 or IPv6 address, and gateway sockets must use IP:PORT (IPv6: [IP]:PORT)"))?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if let Some(socket) = &self.network_helper
            && (!cfg!(unix)
                || !socket.is_absolute()
                || socket
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || !self.bindings.is_empty())
        {
            return Err(ApiError::bad_request(
                "network_helper requires Unix, an absolute socket path, and peer_bindings only",
            ));
        }
        if !valid_transport_address(self.underlay_address) {
            return Err(ApiError::bad_request(
                "Local IP underlay_address must be an explicit unicast IPv4 or global/ULA IPv6 address; wildcard, loopback, link-local, and IPv4-mapped IPv6 addresses are forbidden",
            ));
        }
        let bindings: Vec<_> = self
            .bindings
            .iter()
            .cloned()
            .chain(
                self.peer_bindings
                    .iter()
                    .map(crate::peer_ip::Binding::as_gateway_binding),
            )
            .collect();
        if bindings.is_empty() || bindings.len() > 32 {
            return Err(ApiError::bad_request(
                "Configure between 1 and 32 local IP bindings",
            ));
        }
        let mut names = HashSet::new();
        let mut interfaces = HashSet::new();
        for binding in &self.peer_bindings {
            binding.validate()?;
        }
        if self.underlay_port != 0
            && bindings
                .iter()
                .map(|b| &b.project)
                .collect::<HashSet<_>>()
                .len()
                > 1
        {
            return Err(ApiError::bad_request(
                "A fixed underlay_port supports one project only; use port 0 for multiple project endpoints",
            ));
        }
        for binding in &bindings {
            connect_lib::ProjectId::try_from(binding.project.as_str())
                .map_err(|_| ApiError::bad_request("Invalid IP binding project"))?;
            connect_lib::TunnelId::try_from(binding.network.as_str())
                .map_err(|_| ApiError::bad_request("Invalid IP network name"))?;
            if binding.network.len() > 63
                || !binding
                    .network
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            {
                return Err(ApiError::bad_request(
                    "Local IP network names must use at most 63 letters, digits, or hyphens",
                ));
            }
            binding.gateway.parse::<EndpointId>().map_err(|_| {
                ApiError::bad_request("Local IP gateway must be a Connector public key")
            })?;
            if !names.insert((&binding.project, &binding.network))
                || !interfaces.insert(&binding.interface_name)
            {
                return Err(ApiError::bad_request(
                    "Duplicate local IP network or interface",
                ));
            }
            if binding.interface_name.is_empty()
                || binding.interface_name.len() > 15
                || !binding
                    .interface_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            {
                return Err(ApiError::bad_request("Invalid local TUN interface name"));
            }
            let discovered = self.peer_bindings.iter().any(|p| {
                p.project == binding.project && p.network == binding.network && p.discover
            });
            if (binding.addresses.is_empty() && !discovered && binding.relay_urls.is_empty())
                || binding.addresses.len() > 16
                || binding.relay_urls.len() > 8
                || binding
                    .addresses
                    .iter()
                    .any(|a| !valid_transport_address(a.ip()) || a.port() == 0)
            {
                return Err(ApiError::bad_request(
                    "Local IP gateway needs explicit unicast IPv4 or IPv6 addresses and nonzero ports; bracket IPv6 sockets as [IP]:PORT",
                ));
            }
            if binding
                .addresses
                .iter()
                .any(|address| address.is_ipv4() != self.underlay_address.is_ipv4())
            {
                return Err(ApiError::bad_request(
                    "Every gateway socket must use the same IP address family as underlay_address; overlay routes may use a different family",
                ));
            }
            let assigned = binding.address()?;
            if assigned.prefix_len() != if assigned.addr().is_ipv4() { 32 } else { 128 }
                || assigned.addr().is_unspecified()
                || assigned.addr().is_multicast()
                || assigned.addr().is_loopback()
                || !valid_transport_address(assigned.addr())
            {
                return Err(ApiError::bad_request(
                    "Assigned local IP address must be a unicast IPv4 /32 or IPv6 /128",
                ));
            }
            if !(1280..=1500).contains(&binding.mtu) {
                return Err(ApiError::bad_request(
                    "Local IP MTU must be between 1280 and 1500",
                ));
            }
            let routes = binding.parsed_routes()?;
            connect_ip_adapter::validate(&binding.interface_name, assigned, binding.mtu, &routes)
                .map_err(|error| {
                ApiError::bad_request(format!("Invalid local IP approval: {error}"))
            })?;
        }
        // TUN routes are process-wide. Check every transport address against
        // every binding, including bindings owned by a different project.
        for overlay in &bindings {
            let assigned = overlay.address()?.addr();
            let routes = overlay.parsed_routes()?;
            let enters_overlay = |address: IpAddr| {
                address == assigned || routes.iter().any(|route| route.contains(&address))
            };
            if enters_overlay(self.underlay_address) {
                return Err(ApiError::bad_request(
                    "Local IP underlay_address must be outside every approved route and assigned address to prevent transport routing through the overlay",
                ));
            }
            for binding in &bindings {
                if binding
                    .addresses
                    .iter()
                    .any(|address| enters_overlay(address.ip()))
                {
                    return Err(ApiError::bad_request(
                        "Local IP gateway addresses must be outside every approved route and assigned address to prevent transport routing through the overlay",
                    ));
                }
            }
        }
        for peer in &self.peer_bindings {
            let local = peer.local_address()?;
            let remote = peer.remote_address()?;
            for other in &bindings {
                if other.project == peer.project && other.network == peer.network {
                    continue;
                }
                let other_address = other.address()?.addr();
                if local.addr() == other_address
                    || remote.addr() == other_address
                    || other.parsed_routes()?.iter().any(|route| {
                        route.contains(&remote.addr()) || route.contains(&local.addr())
                    })
                {
                    return Err(ApiError::bad_request(
                        "Peer host addresses and routes must not overlap another binding's assigned address or routes",
                    ));
                }
            }
        }
        for (i, binding) in bindings.iter().enumerate() {
            let routes = binding.parsed_routes()?;
            for other in &bindings[..i] {
                if routes.iter().any(|route| {
                    other.parsed_routes().is_ok_and(|others| {
                        others
                            .iter()
                            .any(|r| r.contains(&route.network()) || route.contains(&r.network()))
                    })
                }) {
                    return Err(ApiError::bad_request(
                        "Installed IP routes must not overlap another attachment",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn binding(&self, project: &str, network: &str) -> Result<Binding, ApiError> {
        self.bindings.iter().find(|b| b.project == project && b.network == network).cloned()
            .ok_or_else(|| ApiError::new(axum::http::StatusCode::FORBIDDEN, "This project/network has no local IP approval; ask the daemon operator to configure it").with_code("local_ip_approval_required"))
    }

    /// Discovered underlay addresses never enter any approved overlay route.
    pub(crate) fn permits_peer_socket(&self, socket: SocketAddr) -> bool {
        if !valid_transport_address(socket.ip())
            || socket.port() == 0
            || socket.is_ipv4() != self.underlay_address.is_ipv4()
        {
            return false;
        }
        let bindings = self.bindings.iter().cloned().chain(
            self.peer_bindings
                .iter()
                .map(crate::peer_ip::Binding::as_gateway_binding),
        );
        bindings.into_iter().all(|binding| {
            binding
                .address()
                .is_ok_and(|assigned| assigned.addr() != socket.ip())
                && binding
                    .parsed_routes()
                    .is_ok_and(|routes| !routes.iter().any(|route| route.contains(&socket.ip())))
        })
    }
    pub fn approval(&self, project: &str, network: &str) -> Result<Approval, ApiError> {
        if let Some(binding) = self
            .peer_bindings
            .iter()
            .find(|b| b.project == project && b.network == network)
        {
            return Ok(Approval::Peer(binding.clone()));
        }
        self.binding(project, network).map(Approval::Gateway)
    }
}

pub enum Approval {
    Gateway(Binding),
    Peer(crate::peer_ip::Binding),
}

pub enum NetworkAttachment {
    Gateway(Attachment),
    Peer(crate::peer_ip::Attachment),
}
impl NetworkAttachment {
    pub fn is_finished(&self) -> bool {
        match self {
            Self::Gateway(a) => a.task.is_finished(),
            Self::Peer(a) => a.task.is_finished(),
        }
    }
    pub async fn status(&self) -> Value {
        match self {
            Self::Gateway(a) => a.status().await,
            Self::Peer(a) => a.status().await,
        }
    }
    pub async fn stop(self) {
        match self {
            Self::Gateway(a) => a.stop().await,
            Self::Peer(a) => a.stop().await,
        }
    }
}

fn valid_transport_address(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(address) => {
                let octets = address.octets();
                octets[0] != 0 && octets[0] != 127 && octets[0] < 224 && !address.is_link_local()
            }
            IpAddr::V6(address) => {
                let first = address.segments()[0];
                (first & 0xe000 == 0x2000 || first & 0xfe00 == 0xfc00)
                    && address.to_ipv4_mapped().is_none()
            }
        }
}

fn read_config(path: &Path) -> Result<Vec<u8>, ApiError> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(ApiError::bad_request(
            "Local IP configuration must be a regular file under 1 MiB",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.mode() & 0o077 != 0 || (metadata.uid() != uid && metadata.uid() != 0) {
            return Err(ApiError::bad_request(
                "Local IP configuration must be owned by this user or root and owner-only (chmod 600)",
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ApiError::bad_request(
            "Local IP configuration exceeds 1 MiB",
        ));
    }
    Ok(bytes)
}

impl Binding {
    pub(crate) fn address(&self) -> Result<IpNet, ApiError> {
        self.assigned_address.parse().map_err(|_| {
            ApiError::bad_request("Assigned address must be an IPv4 /32 or IPv6 /128 CIDR")
        })
    }
    pub(crate) fn parsed_routes(&self) -> Result<Vec<IpNet>, ApiError> {
        if self.routes.is_empty() || self.routes.len() > 32 {
            return Err(ApiError::bad_request(
                "Local IP bindings require 1 to 32 explicit IPv4 or IPv6 routes",
            ));
        }
        let mut routes = HashSet::new();
        let assigned = self.address()?.addr();
        self.routes.iter().map(|route| {
            let route: IpNet = route.parse().map_err(|_| ApiError::bad_request("Local IP routes must be IPv4 or IPv6 CIDRs"))?;
            if route.addr().is_ipv4() != assigned.is_ipv4() {
                return Err(ApiError::bad_request("Every route in a binding must use the same IP address family as assigned_address; use separate bindings for IPv4 and IPv6 overlays"));
            }
            if route.prefix_len() == 0 || route.network().is_unspecified() || route.network().is_loopback() || route.network().is_multicast() || route.addr() != route.network() || !routes.insert(route) {
                return Err(ApiError::bad_request("Local IP routes must be unique canonical unicast prefixes; default routes are forbidden"));
            }
            Ok(route)
        }).collect()
    }
}

pub struct Attachment {
    binding: Binding,
    interface_name: String,
    adapter: String,
    cancel: CancellationToken,
    pub task: JoinHandle<()>,
    failure: Arc<Mutex<Option<String>>>,
    state: Arc<RwLock<&'static str>>,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    last_sent_at_ms: Arc<AtomicU64>,
    last_received_at_ms: Arc<AtomicU64>,
    session: Arc<RwLock<Arc<ip::IpSession>>>,
}

impl Attachment {
    pub async fn status(&self) -> Value {
        let session = self.session.read().await.clone();
        let state = *self.state.read().await;
        let transport = session.stats();
        let last_transport_error = session.last_error();
        json!({"network":self.binding.network,"project":self.binding.project,"gateway":self.binding.gateway,"mode":"gateway","session_id":session.session_id,
            "assigned_address":self.binding.assigned_address,"routes":self.binding.routes,"interface_name":self.interface_name,
            "interface_label":self.binding.interface_name,"adapter":self.adapter,
            "mtu":self.binding.mtu,"running":!self.task.is_finished(),"connected":state=="connected","state":state,"ephemeral":true,"prototype":true,
            "packets_sent":self.sent.load(Ordering::Relaxed),"packets_received":self.received.load(Ordering::Relaxed),
            "local_tun_to_transport_packets":self.sent.load(Ordering::Relaxed),
            "transport_to_local_tun_packets":self.received.load(Ordering::Relaxed),
            "last_packet_sent_at_unix_ms":nonzero(self.last_sent_at_ms.load(Ordering::Relaxed)),
            "last_packet_received_at_unix_ms":nonzero(self.last_received_at_ms.load(Ordering::Relaxed)),
            "packets_dropped":transport.packets_dropped,"protocol_errors":transport.protocol_errors,
            "delivery_mode":transport.delivery_mode,"effective_datagram_ip_capacity":transport.effective_datagram_ip_capacity,
            "mtu_errors":transport.mtu_errors,"last_transport_error":last_transport_error,
            "transport":transport_status(transport, last_transport_error.clone()),
            "last_error":self.failure.lock().await.clone()})
    }
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

pub async fn join(
    binding: Binding,
    peer_address: Option<connect_ip_adapter::IpNet>,
    endpoint: Endpoint,
    cancel: CancellationToken,
    helper: Option<&Path>,
) -> Result<Attachment, ApiError> {
    let setup_guard = cancel.clone().drop_guard();
    let address = binding.address()?;
    let connector = endpoint.id().to_string();
    let routes = binding.parsed_routes()?;
    let mut peer = EndpointAddr::new(
        binding
            .gateway
            .parse()
            .map_err(|_| ApiError::bad_request("Invalid gateway key"))?,
    );
    for address in &binding.addresses {
        peer = peer.with_ip_addr(*address);
    }
    if !binding.relay_urls.is_empty() {
        let relays = crate::relays::parse(&binding.relay_urls.join(","))?;
        for relay in relays {
            peer = peer.with_relay_url(relay);
        }
    }
    let session = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        ip::connect(
            endpoint.clone(),
            peer.clone(),
            &binding.network,
            cancel.clone(),
        ),
    )
    .await
    .map_err(|_| ApiError::internal("CONNECT-IP gateway setup timed out"))?
    .map_err(|error| {
        tracing::warn!(
            project=%binding.project,
            network=%binding.network,
            connector=%connector,
            peer=%binding.gateway,
            %error,
            stage="connect_ip_setup_failed",
            "local CONNECT-IP setup failed"
        );
        handshake_error(&binding.network, &connector, error)
    })?;
    let actual_routes: HashSet<_> = session
        .config
        .routes
        .iter()
        .map(ToString::to_string)
        .collect();
    let expected_routes: HashSet<_> = routes.iter().map(ToString::to_string).collect();
    if session.config.address != address.addr()
        || session.config.mtu != binding.mtu
        || actual_routes != expected_routes
    {
        session.cancel();
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "Gateway IP assignment or routes differ from local approval; no interface was created. Ask the gateway and daemon operators to agree on the assignment, routes, and MTU",
        ).with_code("local_ip_grant_mismatch"));
    }
    let adapter = if helper.is_some() {
        "privileged_network_helper"
    } else {
        connect_ip_adapter::backend()
    }
    .to_owned();
    let tun_setup = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(ApiError::internal("CONNECT-IP attachment setup was cancelled")),
        result = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            match peer_address {
                Some(peer_address) => PacketDevice::create_gateway(&binding.interface_name, address, peer_address, binding.mtu, &routes, helper).await,
                None => PacketDevice::create(&binding.interface_name, address, binding.mtu, &routes, helper).await,
            }
        }) => result.map_err(|_| ApiError::internal("TUN setup timed out; any partially created interface is removed"))?,
    };
    let tun = match tun_setup {
        Ok(tun) => tun,
        Err(error) => {
            session.cancel();
            return Err(ApiError::internal(format!(
                "Could not create CONNECT-IP interface using {}: {error}",
                adapter
            )));
        }
    };
    let interface_name = tun.name().to_owned();
    tracing::info!(stage="connect_ip_adapter", network=%binding.network, interface=%interface_name, adapter=%adapter, mtu=binding.mtu, "ip_interface_ready");
    let failure = Arc::new(Mutex::new(None));
    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let last_sent_at_ms = Arc::new(AtomicU64::new(0));
    let last_received_at_ms = Arc::new(AtomicU64::new(0));
    let session = Arc::new(session);
    let active_session = Arc::new(RwLock::new(session.clone()));
    let connection_state = Arc::new(RwLock::new("connected"));
    let task_active_session = active_session.clone();
    let (task_failure, task_state, task_sent, task_received, task_last_sent, task_last_received) = (
        failure.clone(),
        connection_state.clone(),
        sent.clone(),
        received.clone(),
        last_sent_at_ms.clone(),
        last_received_at_ms.clone(),
    );
    let task_cancel = cancel.clone();
    let network = binding.network.clone();
    let project = binding.project.clone();
    let gateway = binding.gateway.clone();
    let local_connector = connector.clone();
    let expected_routes = routes.clone();
    let expected_address = address.addr();
    let expected_mtu = binding.mtu;
    let task_peer = peer.clone();
    let task_endpoint = endpoint.clone();
    let task_network = network.clone();
    let task = tokio::spawn(async move {
        let mut session = session;
        let mut buffer = vec![0u8; 65536];
        let mut reconnect_delay = std::time::Duration::from_secs(1);
        let mut reconnect_attempt = 0u64;
        'attachment: loop {
            let session_id = session.session_id.clone();
            let session_span = info_span!("connect_ip.client_session", project=%project, network=%network, gateway=%gateway, %session_id);
            let _ = session_span.set_parent(session.trace_context.clone());
            let mut health_tick = tokio::time::interval(std::time::Duration::from_secs(10));
            health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut session_packets_sent = 0u64;
            let mut session_packets_received = 0u64;
            let mut session_bytes_sent = 0u64;
            let mut session_bytes_received = 0u64;
            let mut fatal_error = None;
            let failure_reason = loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => {
                        session.cancel();
                        break 'attachment;
                    },
                    _ = health_tick.tick() => {
                        let stats = session.stats();
                        let health_span = info_span!("connect_ip.health_snapshot", project=%project, network=%network, gateway=%gateway, connector=%local_connector, %session_id);
                        health_span.in_scope(|| tracing::info!(project=%project, network=%network, gateway=%gateway, connector=%local_connector,
                            session_local_tun_to_transport_packets=session_packets_sent,
                            session_transport_to_local_tun_packets=session_packets_received,
                            session_local_tun_to_transport_bytes=session_bytes_sent,
                            session_transport_to_local_tun_bytes=session_bytes_received,
                            attachment_local_tun_to_transport_packets_total=task_sent.load(Ordering::Relaxed),
                            attachment_transport_to_local_tun_packets_total=task_received.load(Ordering::Relaxed),
                            quic_datagrams_sent=stats.datagrams_sent,
                            quic_datagrams_received=stats.datagrams_received,
                            transport_drops=stats.packets_dropped,
                            protocol_errors=stats.protocol_errors,
                            last_packet_sent_at_unix_ms=nonzero(task_last_sent.load(Ordering::Relaxed)),
                            last_packet_received_at_unix_ms=nonzero(task_last_received.load(Ordering::Relaxed)),
                            stage="connect_ip_health", "CONNECT-IP directional health snapshot"));
                    },
                    packet = session.recv() => {
                        let Some(packet) = packet else {
                            break session.last_error().unwrap_or_else(|| "CONNECT-IP gateway closed the session".to_owned());
                        };
                        if let Err(error) = tun.write_packet(&packet).await {
                            let message = format!("write to CONNECT-IP interface: {error}");
                            fatal_error = Some(message.clone());
                            break message;
                        }
                        task_received.fetch_add(1, Ordering::Relaxed);
                        session_packets_received += 1;
                        session_bytes_received = session_bytes_received.saturating_add(packet.len() as u64);
                        task_last_received.store(unix_time_ms(), Ordering::Relaxed);
                    },
                    read = tun.read_packet(&mut buffer) => {
                        let length = match read {
                            Ok(length) if length > 0 => length,
                            Ok(_) => {
                                let message = "CONNECT-IP interface closed".to_owned();
                                fatal_error = Some(message.clone());
                                break message;
                            },
                            Err(error) => {
                                let message = format!("read from CONNECT-IP interface: {error}");
                                fatal_error = Some(message.clone());
                                break message;
                            },
                        };
                        match session.send(bytes::Bytes::copy_from_slice(&buffer[..length])).await {
                            Ok(()) => {
                                task_sent.fetch_add(1, Ordering::Relaxed);
                                session_packets_sent += 1;
                                session_bytes_sent = session_bytes_sent.saturating_add(length as u64);
                                task_last_sent.store(unix_time_ms(), Ordering::Relaxed);
                            },
                            Err(error @ (ip::Error::InvalidPacket | ip::Error::PacketTooLarge | ip::Error::AddressPolicy)) => {
                                tracing::debug!(%network, %error, stage="connect_ip_packet", "packet_rejected");
                            },
                            Err(error) => break session.last_error().unwrap_or_else(|| error.to_string()),
                        }
                    }
                }
            };
            session.cancel();
            if task_cancel.is_cancelled() {
                break;
            }
            if let Some(error) = fatal_error {
                *task_state.write().await = "failed";
                *task_failure.lock().await = Some(error.clone());
                tracing::error!(%project, %network, %gateway, %error, stage="connect_ip_interface_failed",
                    "CONNECT-IP local interface failed; automatic transport retry stopped");
                break;
            }
            reconnect_attempt += 1;
            *task_state.write().await = "reconnecting";
            *task_failure.lock().await = Some(failure_reason.clone());
            tracing::warn!(%project, %network, %gateway, %session_id, attempt=reconnect_attempt,
                error=%failure_reason, reconnect_delay_ms=reconnect_delay.as_millis() as u64,
                stage="connect_ip_reconnect", "CONNECT-IP session ended; retrying with the approved binding");

            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break 'attachment,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                let attempt = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    ip::connect(task_endpoint.clone(), task_peer.clone(), &task_network, task_cancel.clone()),
                ).await;
                let replacement = match attempt {
                    Ok(Ok(replacement)) => {
                        let actual_routes: HashSet<_> = replacement.config.routes.iter().map(ToString::to_string).collect();
                        let approved_routes: HashSet<_> = expected_routes.iter().map(ToString::to_string).collect();
                        if replacement.config.address != expected_address
                            || replacement.config.mtu != expected_mtu
                            || actual_routes != approved_routes
                        {
                            let error = "gateway assignment or routes changed; leave and rejoin to approve the new settings".to_owned();
                            *task_failure.lock().await = Some(error.clone());
                            tracing::error!(%project, %network, %gateway, attempt=reconnect_attempt, %error,
                                stage="connect_ip_reconnect_rejected", "CONNECT-IP reconnect does not match the approved binding");
                            replacement.cancel();
                            *task_state.write().await = "failed";
                            break 'attachment;
                        }
                        Arc::new(replacement)
                    }
                    Ok(Err(error)) => {
                        let message = error.to_string();
                        *task_failure.lock().await = Some(message.clone());
                        if !retryable_connect_error(&error) {
                            *task_state.write().await = "failed";
                            tracing::error!(%project, %network, %gateway, attempt=reconnect_attempt, error=%message,
                                stage="connect_ip_reconnect_rejected", "CONNECT-IP reconnect requires a binding, gateway, or protocol change");
                            break 'attachment;
                        }
                        tracing::warn!(%project, %network, %gateway, attempt=reconnect_attempt, error=%message,
                            stage="connect_ip_reconnect_attempt_failed", "CONNECT-IP reconnect attempt failed");
                        reconnect_delay = std::cmp::min(reconnect_delay * 2, std::time::Duration::from_secs(30));
                        continue;
                    }
                    Err(_) => {
                        let message = "CONNECT-IP reconnect handshake timed out".to_owned();
                        *task_failure.lock().await = Some(message.clone());
                        tracing::warn!(%project, %network, %gateway, attempt=reconnect_attempt,
                            stage="connect_ip_reconnect_attempt_failed", "CONNECT-IP reconnect attempt timed out");
                        reconnect_delay = std::cmp::min(reconnect_delay * 2, std::time::Duration::from_secs(30));
                        continue;
                    }
                };
                *task_active_session.write().await = replacement.clone();
                *task_state.write().await = "connected";
                *task_failure.lock().await = None;
                tracing::info!(%project, %network, %gateway, session_id=%replacement.session_id,
                    attempt=reconnect_attempt, stage="connect_ip_reconnected", "CONNECT-IP attachment recovered");
                session = replacement;
                reconnect_delay = std::time::Duration::from_secs(1);
                break;
            }
        }
        if *task_state.read().await != "failed" {
            *task_state.write().await = "inactive";
        }
        let final_state = *task_state.read().await;
        let final_session_id = task_active_session.read().await.session_id.clone();
        let final_error = task_failure.lock().await.clone();
        tracing::info!(%project, %network, %gateway, session_id=%final_session_id,
            state=final_state, reconnect_attempts=reconnect_attempt,
            attachment_local_tun_to_transport_packets_total=task_sent.load(Ordering::Relaxed),
            attachment_transport_to_local_tun_packets_total=task_received.load(Ordering::Relaxed),
            last_error=?final_error, stage="connect_ip_attachment_stopped",
            "CONNECT-IP attachment supervisor stopped");
    }.instrument(info_span!("connect_ip.attachment", project=%binding.project, network=%binding.network, gateway=%binding.gateway)));
    let _ = setup_guard.disarm();
    Ok(Attachment {
        binding,
        interface_name,
        adapter,
        cancel,
        task,
        failure,
        sent,
        received,
        last_sent_at_ms,
        last_received_at_ms,
        session: active_session,
        state: connection_state,
    })
}

fn retryable_connect_error(error: &ip::Error) -> bool {
    matches!(
        error,
        ip::Error::Closed | ip::Error::Timeout | ip::Error::Transport | ip::Error::Io(_)
    )
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

pub(crate) fn transport_status(stats: ip::Stats, last_error: Option<String>) -> Value {
    json!({
        "packets_sent":stats.packets_sent,"packets_received":stats.packets_received,
        "packets_dropped":stats.packets_dropped,"protocol_errors":stats.protocol_errors,
        "delivery_mode":stats.delivery_mode,
        "effective_datagram_ip_capacity":stats.effective_datagram_ip_capacity,
        "datagrams_sent":stats.datagrams_sent,"datagrams_received":stats.datagrams_received,
        "mtu_errors":stats.mtu_errors,"last_error":last_error,
    })
}

fn handshake_error(network: &str, connector: &str, error: ip::Error) -> ApiError {
    match error {
        ip::Error::DatagramsUnsupported => ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("Cannot join network {network:?}: the connection does not support QUIC DATAGRAM. Ask the gateway operator to enable HTTP/3 and QUIC DATAGRAM support. CONNECT-IP has no reliable-stream fallback; no local interface was created"),
        ).with_code("local_ip_datagrams_unsupported"),
        ip::Error::InsufficientDatagramMtu { required, available } => ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("Cannot join network {network:?}: the approved IP MTU is {required} bytes, but this path can carry only {available} IP bytes per QUIC datagram. Check the direct or relay path MTU with the gateway operator, or configure matching supported MTUs on both endpoints (minimum 1280). No local interface was created"),
        ).with_code("local_ip_datagram_mtu_insufficient"),
        ip::Error::RejectedWithReason {
            status: axum::http::StatusCode::FORBIDDEN,
            reason: ip::RejectionReason::PeerNetworkNotApproved,
            session_id,
        } => ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            format!("The peer rejected CONNECT-IP because it has no matching approval for network {network:?} and Connector {connector}. Confirm that both sides use the same network name and approve each other's Connector keys. Diagnostic session_id: {session_id}"),
        ).with_code("local_ip_peer_network_not_approved"),
        ip::Error::RejectedWithReason {
            status: axum::http::StatusCode::BAD_REQUEST,
            reason: ip::RejectionReason::InvalidRequest,
            session_id,
        } => ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            format!("The peer rejected the CONNECT-IP request as invalid for network {network:?}. Verify that both sides run compatible Connect versions. Diagnostic session_id: {session_id}"),
        ).with_code("local_ip_invalid_peer_request"),
        ip::Error::RejectedWithReason {
            status,
            reason,
            session_id,
        } => ApiError::new(
            status,
            format!("The peer rejected CONNECT-IP for network {network:?} (reason: {reason}). Diagnostic session_id: {session_id}"),
        ).with_code("local_ip_peer_rejected"),
        ip::Error::Rejected(axum::http::StatusCode::FORBIDDEN) => ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            format!("The gateway has not approved network {network:?} for Connector {connector}. Ask the gateway operator to approve this Connector key and network in its IP grant"),
        ).with_code("local_ip_gateway_approval_required"),
        ip::Error::Rejected(axum::http::StatusCode::SERVICE_UNAVAILABLE) => ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("The gateway could not prepare its attachment for network {network:?}. Ask the gateway operator to check ip_tun_setup logs, its configured interface, /dev/net/tun, and CAP_NET_ADMIN"),
        ).with_code("local_ip_gateway_setup_failed"),
        error => ApiError::internal(format!("CONNECT-IP setup for network {network:?} failed: {error}"))
            .with_code("local_ip_handshake_failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_retries_transient_failures_but_stops_on_configuration_rejections() {
        for error in [
            ip::Error::Timeout,
            ip::Error::Transport,
            ip::Error::Closed,
            ip::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ] {
            assert!(retryable_connect_error(&error), "{error}");
        }
        for error in [
            ip::Error::DatagramsUnsupported,
            ip::Error::InsufficientDatagramMtu {
                required: 1280,
                available: 1200,
            },
            ip::Error::Rejected(axum::http::StatusCode::FORBIDDEN),
            ip::Error::Protocol("invalid negotiation"),
        ] {
            assert!(!retryable_connect_error(&error), "{error}");
        }
    }

    #[test]
    fn datagram_diagnostics_preserve_capacity_and_fatal_reason() {
        let value = transport_status(
            ip::Stats {
                delivery_mode: "quic_datagram",
                effective_datagram_ip_capacity: 1250,
                datagrams_sent: 7,
                datagrams_received: 9,
                mtu_errors: 1,
                packets_dropped: 3,
                ..Default::default()
            },
            Some("path capacity fell below approved MTU".into()),
        );
        assert_eq!(value["delivery_mode"], "quic_datagram");
        assert_eq!(value["effective_datagram_ip_capacity"], 1250);
        assert_eq!(value["datagrams_sent"], 7);
        assert_eq!(value["datagrams_received"], 9);
        assert_eq!(value["mtu_errors"], 1);
        assert_eq!(value["packets_dropped"], 3);
        assert_eq!(value["last_error"], "path capacity fell below approved MTU");
    }

    #[test]
    fn datagram_setup_errors_explain_operator_recovery() {
        let unsupported = handshake_error("vpc", "key", ip::Error::DatagramsUnsupported);
        assert_eq!(
            unsupported.code.as_deref(),
            Some("local_ip_datagrams_unsupported")
        );
        assert!(
            unsupported.message.contains("QUIC DATAGRAM")
                && unsupported.message.contains("no reliable-stream fallback")
        );
        let mtu = handshake_error(
            "vpc",
            "key",
            ip::Error::InsufficientDatagramMtu {
                required: 1280,
                available: 1100,
            },
        );
        assert_eq!(
            mtu.code.as_deref(),
            Some("local_ip_datagram_mtu_insufficient")
        );
        for expected in [
            "1280",
            "1100",
            "vpc",
            "gateway operator",
            "No local interface",
        ] {
            assert!(
                mtu.message.contains(expected),
                "missing {expected}: {}",
                mtu.message
            );
        }
    }
    #[test]
    fn gateway_errors_identify_operator_action_and_preserve_status() {
        let peer_denied = handshake_error(
            "staging-vpc-mac",
            "connector-key",
            ip::Error::RejectedWithReason {
                status: axum::http::StatusCode::FORBIDDEN,
                reason: ip::RejectionReason::PeerNetworkNotApproved,
                session_id: "0123456789abcdef-00000001".into(),
            },
        );
        assert_eq!(peer_denied.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(
            peer_denied.code.as_deref(),
            Some("local_ip_peer_network_not_approved")
        );
        for expected in [
            "staging-vpc-mac",
            "connector-key",
            "both sides",
            "0123456789abcdef-00000001",
        ] {
            assert!(
                peer_denied.message.contains(expected),
                "missing {expected}: {}",
                peer_denied.message
            );
        }

        let denied = handshake_error(
            "vpc",
            "connector-key",
            ip::Error::Rejected(axum::http::StatusCode::FORBIDDEN),
        );
        assert_eq!(denied.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(
            denied.code.as_deref(),
            Some("local_ip_gateway_approval_required")
        );
        assert!(
            denied.message.contains("vpc")
                && denied.message.contains("connector-key")
                && denied.message.contains("IP grant")
        );
        let failed = handshake_error(
            "vpc",
            "connector-key",
            ip::Error::Rejected(axum::http::StatusCode::SERVICE_UNAVAILABLE),
        );
        assert_eq!(failed.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            failed.code.as_deref(),
            Some("local_ip_gateway_setup_failed")
        );
        assert!(
            failed.message.contains("ip_tun_setup") && failed.message.contains("CAP_NET_ADMIN")
        );
    }
    fn config() -> serde_json::Value {
        json!({"underlay_address":"172.20.0.2","bindings":[{"project":"demo","network":"vpc","gateway":iroh::SecretKey::from_bytes(&[7;32]).public().to_string(),"addresses":["172.20.0.3:4433"],"assigned_address":"192.0.2.2/32","routes":["10.78.0.0/24"],"interface_name":"dcip0","mtu":1280}]})
    }
    fn peer_config() -> Value {
        json!({"underlay_address":"172.20.0.2","underlay_port":7777,"peer_bindings":[{"project":"demo","network":"peer-net","peer":iroh::SecretKey::from_bytes(&[8;32]).public().to_string(),"addresses":["172.20.0.3:7777"],"assigned_address":"192.0.2.2/32","peer_address":"192.0.2.3/32","interface_name":"dcp0","mtu":1280,"allow_inbound":[{"protocol":"tcp","ports":[22]}],"allow_outbound":[{"protocol":"icmp_echo"}]}]})
    }
    #[test]
    fn discovered_peer_config_filters_overlay_and_wrong_family_addresses() {
        let mut value = peer_config();
        value["peer_bindings"][0]["discover"] = json!(true);
        value["peer_bindings"][0]
            .as_object_mut()
            .unwrap()
            .remove("addresses");
        value["network_helper"] =
            json!("/Library/PrivilegedHelperTools/datum-connect-network-501/helper.sock");
        let config: LocalIpConfig = serde_json::from_value(value.clone()).unwrap();
        if cfg!(unix) {
            config.validate().unwrap();
        }
        assert!(config.permits_peer_socket("172.20.0.3:7777".parse().unwrap()));
        for socket in [
            "192.0.2.2:7777",
            "192.0.2.3:7777",
            "127.0.0.1:7777",
            "172.20.0.3:0",
            "[fd00::3]:7777",
        ] {
            assert!(
                !config.permits_peer_socket(socket.parse().unwrap()),
                "accepted {socket}"
            );
        }
        value["peer_bindings"][0]["addresses"] = json!(["172.20.0.3:7777"]);
        assert!(
            serde_json::from_value::<LocalIpConfig>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    #[test]
    fn peer_approvals_require_exact_hosts_and_bounded_explicit_rules() {
        let valid: LocalIpConfig = serde_json::from_value(peer_config()).unwrap();
        valid.validate().unwrap();
        assert!(matches!(
            valid.approval("demo", "peer-net").unwrap(),
            Approval::Peer(_)
        ));
        for (field, value) in [
            ("peer_address", json!("192.0.2.0/24")),
            ("peer_address", json!("192.0.2.2/32")),
            ("peer_address", json!("2001:db8::1/128")),
            ("allow_inbound", json!([{"protocol":"tcp","ports":[]}])),
            ("allow_outbound", json!([{"protocol":"udp","ports":[0]}])),
            (
                "allow_inbound",
                json!([{"protocol":"icmp_echo","ports":[22]}]),
            ),
        ] {
            let mut config = peer_config();
            config["peer_bindings"][0][field] = value;
            assert!(
                serde_json::from_value::<LocalIpConfig>(config)
                    .unwrap()
                    .validate()
                    .is_err(),
                "accepted {field}"
            );
        }
        let mut v6 = peer_config();
        v6["peer_bindings"][0]["assigned_address"] = json!("fd00:20::2/128");
        v6["peer_bindings"][0]["peer_address"] = json!("fd00:20::3/128");
        serde_json::from_value::<LocalIpConfig>(v6)
            .unwrap()
            .validate()
            .unwrap();
    }
    #[test]
    fn peer_bindings_cannot_overlap_other_routes_or_reuse_fixed_ports_across_projects() {
        let mut value = peer_config();
        let mut second = value["peer_bindings"][0].clone();
        second["project"] = json!("other");
        second["interface_name"] = json!("dcp1");
        second["assigned_address"] = json!("192.0.2.4/32");
        second["peer_address"] = json!("192.0.2.5/32");
        value["peer_bindings"].as_array_mut().unwrap().push(second);
        assert!(
            serde_json::from_value::<LocalIpConfig>(value.clone())
                .unwrap()
                .validate()
                .unwrap_err()
                .message
                .contains("fixed underlay_port")
        );
        value["underlay_port"] = json!(0);
        serde_json::from_value::<LocalIpConfig>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        value["peer_bindings"][1]["peer_address"] = json!("192.0.2.3/32");
        assert!(
            serde_json::from_value::<LocalIpConfig>(value)
                .unwrap()
                .validate()
                .unwrap_err()
                .message
                .contains("overlap")
        );
        let mut value = peer_config();
        let mut gateway = config()["bindings"][0].clone();
        gateway["network"] = json!("gateway");
        gateway["interface_name"] = json!("dcp1");
        gateway["assigned_address"] = json!("198.51.100.2/32");
        gateway["routes"] = json!(["192.0.2.0/24"]);
        value["bindings"] = json!([gateway]);
        assert!(
            serde_json::from_value::<LocalIpConfig>(value)
                .unwrap()
                .validate()
                .unwrap_err()
                .message
                .contains("overlap")
        );
    }
    fn ipv6_config() -> serde_json::Value {
        let mut value = config();
        value["underlay_address"] = json!("2001:db8:10::2");
        value["bindings"][0]["addresses"] = json!(["[2001:db8:10::3]:4433"]);
        value["bindings"][0]["assigned_address"] = json!("2001:db8:20::2/128");
        value["bindings"][0]["routes"] = json!(["2001:db8:30::/64"]);
        value
    }
    #[test]
    fn ipv6_approval_supports_independent_underlay_and_checks_families() {
        let valid: LocalIpConfig = serde_json::from_value(ipv6_config()).unwrap();
        valid.validate().unwrap();
        let mut ula = ipv6_config();
        ula["underlay_address"] = json!("fd00:10::2");
        ula["bindings"][0]["addresses"] = json!(["[fd00:10::3]:4433"]);
        ula["bindings"][0]["assigned_address"] = json!("fd00:20::2/128");
        ula["bindings"][0]["routes"] = json!(["fd00:30::/64"]);
        serde_json::from_value::<LocalIpConfig>(ula)
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            valid
                .binding("demo", "vpc")
                .unwrap()
                .address()
                .unwrap()
                .prefix_len(),
            128
        );
        let mut v4_underlay = ipv6_config();
        v4_underlay["underlay_address"] = json!("172.20.0.2");
        v4_underlay["bindings"][0]["addresses"] = json!(["172.20.0.3:4433"]);
        serde_json::from_value::<LocalIpConfig>(v4_underlay)
            .unwrap()
            .validate()
            .unwrap();
        let mut v6_underlay = config();
        v6_underlay["underlay_address"] = json!("2001:db8:10::2");
        v6_underlay["bindings"][0]["addresses"] = json!(["[2001:db8:10::3]:4433"]);
        serde_json::from_value::<LocalIpConfig>(v6_underlay)
            .unwrap()
            .validate()
            .unwrap();

        let mut mixed = ipv6_config();
        mixed["bindings"][0]["routes"] = json!(["10.78.0.0/24"]);
        assert!(
            serde_json::from_value::<LocalIpConfig>(mixed)
                .unwrap()
                .validate()
                .unwrap_err()
                .message
                .contains("same IP address family as assigned_address")
        );
        let mut mismatched_gateway = ipv6_config();
        mismatched_gateway["bindings"][0]["addresses"] = json!(["172.20.0.3:4433"]);
        assert!(
            serde_json::from_value::<LocalIpConfig>(mismatched_gateway)
                .unwrap()
                .validate()
                .unwrap_err()
                .message
                .contains("same IP address family as underlay_address")
        );
    }
    #[test]
    fn ipv6_approval_rejects_unsafe_routes_addresses_and_cross_project_recursion() {
        for address in [
            "::",
            "ff02::1",
            "fe80::2",
            "::ffff:192.0.2.2",
            "2001:db8:20::2",
            "2001:db8:30::8",
        ] {
            let mut value = ipv6_config();
            value["underlay_address"] = json!(address);
            assert!(
                serde_json::from_value::<LocalIpConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err(),
                "accepted {address}"
            );
        }
        for (field, value) in [
            ("assigned_address", json!("2001:db8:20::2/64")),
            ("routes", json!(["::/0"])),
            ("routes", json!(["ff00::/16"])),
            ("routes", json!(["fe80::/64"])),
            ("routes", json!(["2001:db8:30::1/64"])),
            ("addresses", json!(["[2001:db8:30::3]:4433"])),
            ("addresses", json!(["[2001:db8:20::2]:4433"])),
        ] {
            let mut config = ipv6_config();
            config["bindings"][0][field] = value;
            assert!(
                serde_json::from_value::<LocalIpConfig>(config)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut value = ipv6_config();
        let mut second = value["bindings"][0].clone();
        second["project"] = json!("other");
        second["interface_name"] = json!("dcip1");
        second["assigned_address"] = json!("2001:db8:20::3/128");
        second["routes"] = json!(["2001:db8:40::/64"]);
        value["bindings"].as_array_mut().unwrap().push(second);
        serde_json::from_value::<LocalIpConfig>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        value["bindings"][0]["addresses"] = json!(["[2001:db8:40::3]:4433"]);
        assert!(
            serde_json::from_value::<LocalIpConfig>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    #[test]
    fn explicit_underlay_excludes_all_projects_overlay_routes() {
        let mut missing = config();
        missing.as_object_mut().unwrap().remove("underlay_address");
        assert!(serde_json::from_value::<LocalIpConfig>(missing).is_err());
        for address in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "192.0.2.2",
            "10.78.0.8",
        ] {
            let mut value = config();
            value["underlay_address"] = json!(address);
            assert!(
                serde_json::from_value::<LocalIpConfig>(value)
                    .map(|v| v.validate().is_err())
                    .unwrap_or(true),
                "accepted underlay {address}"
            );
        }
        for address in ["10.78.0.3:4433", "192.0.2.2:4433"] {
            let mut value = config();
            value["bindings"][0]["addresses"] = json!([address]);
            assert!(
                serde_json::from_value::<LocalIpConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut value = config();
        let mut second = value["bindings"][0].clone();
        second["project"] = json!("other");
        second["interface_name"] = json!("dcip1");
        second["assigned_address"] = json!("192.0.2.3/32");
        second["routes"] = json!(["172.21.0.0/24"]);
        value["bindings"].as_array_mut().unwrap().push(second);
        value["bindings"][0]["addresses"] = json!(["172.21.0.5:4433"]);
        assert!(
            serde_json::from_value::<LocalIpConfig>(value)
                .unwrap()
                .validate()
                .is_err(),
            "gateway must not enter another project's overlay"
        );
    }
    #[test]
    fn local_approval_is_project_scoped_and_rejects_route_expansion() {
        let valid: LocalIpConfig = serde_json::from_value(config()).unwrap();
        valid.validate().unwrap();
        assert!(valid.binding("other", "vpc").is_err());
        assert!(valid.binding("demo", "other").is_err());
        for route in [
            "0.0.0.0/0",
            "0.0.0.0/1",
            "::/0",
            "127.0.0.0/8",
            "224.0.0.0/4",
            "10.78.0.1/24",
        ] {
            let mut value = config();
            value["bindings"][0]["routes"] = json!([route]);
            assert!(
                serde_json::from_value::<LocalIpConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err(),
                "accepted {route}"
            );
        }
        for (field, value) in [
            ("assigned_address", json!("192.0.2.2/24")),
            ("interface_name", json!("../../lo")),
            ("addresses", json!(["[::1]:4433"])),
            ("mtu", json!(9000)),
        ] {
            let mut config = config();
            config["bindings"][0][field] = value;
            assert!(
                serde_json::from_value::<LocalIpConfig>(config)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut duplicate = config();
        let binding = duplicate["bindings"][0].clone();
        duplicate["bindings"].as_array_mut().unwrap().push(binding);
        assert!(
            serde_json::from_value::<LocalIpConfig>(duplicate)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    #[tokio::test]
    #[cfg(unix)]
    async fn local_config_requires_private_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("ip.json");
        std::fs::write(&file, serde_json::to_vec(&config()).unwrap()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LocalIpConfig::load(&file).await.is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        LocalIpConfig::load(&file).await.unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&file, &alias).unwrap();
        assert!(LocalIpConfig::load(&alias).await.is_err());
    }
}
