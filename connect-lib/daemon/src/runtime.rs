use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use connect_lib::successor::{
    CloudConnector, ConnectionDetails as CloudConnectionDetails, Credentials, PeerIdentity,
    ServiceIntent,
};
use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig,
};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use sha2::{Digest, Sha256};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, UdpSocket},
    sync::{Mutex, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    control::{Control, PingResult, ServiceOutcome},
    error::ApiError,
    model::{ConnectorState, DialState, Protocol, ServiceState},
    store::{Store, atomic_write_private},
};

#[derive(Clone)]
pub struct RealControl {
    repo: PathBuf,
    store: Arc<Store>,
    projects: Arc<Mutex<HashMap<String, Arc<ProjectRuntime>>>>,
    up_lock: Arc<Mutex<()>>,
    mutation_lock: Arc<Mutex<()>>,
    local_ip: Option<Arc<crate::local_ip::LocalIpConfig>>,
    relay_urls: Option<Vec<iroh::RelayUrl>>,
}

struct ProjectRuntime {
    underlay: Option<std::net::IpAddr>,
    cloud: CloudConnector,
    transport: Transport,
    services: Mutex<HashMap<String, ServiceState>>,
    dials: Mutex<HashMap<u16, DialRuntime>>,
    networks: Mutex<HashMap<String, crate::local_ip::NetworkAttachment>>,
    policy_lock: Mutex<()>,
    cancel: CancellationToken,
    refresh_task: Mutex<Option<JoinHandle<()>>>,
    authorized: AtomicBool,
    identity: ConnectorState,
}

struct DialRuntime {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct CloudPeerResolver {
    cloud: CloudConnector,
    config: Arc<crate::local_ip::LocalIpConfig>,
}

#[async_trait]
impl crate::peer_ip::PeerResolver for CloudPeerResolver {
    async fn resolve(&self, peer: EndpointId) -> Result<EndpointAddr, ApiError> {
        let mut identity = self
            .cloud
            .resolve_peer(&peer.to_string())
            .await
            .map_err(cloud_error)?;
        if identity.public_key != peer.to_string() {
            return Err(ApiError::bad_request(
                "Discovered Connector key differs from approved peer",
            ));
        }
        identity
            .addresses
            .retain(|address| self.config.permits_peer_socket(*address));
        if !identity.relay_url.is_empty() {
            let relays = crate::relays::parse(&identity.relay_url)?;
            if relays.len() != 1 {
                return Err(ApiError::bad_request(
                    "Peer must publish one HTTPS home relay",
                ));
            }
            // Literal relay addresses obey the same no-overlay recursion rule.
            if let Some(host) = relays[0].host_str()
                && let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>()
                && !self.config.permits_peer_socket(std::net::SocketAddr::new(
                    ip,
                    relays[0].port().unwrap_or(443),
                ))
            {
                return Err(ApiError::bad_request(
                    "Peer relay address overlaps an overlay or uses an unsupported underlay family",
                ));
            }
        }
        if identity.addresses.is_empty() && identity.relay_url.is_empty() {
            return Err(ApiError::bad_request(
                "Approved peer has no usable underlay addresses or relay",
            ));
        }
        tracing::debug!(%peer, direct_addresses=identity.addresses.len(), relay_available=!identity.relay_url.is_empty(), stage="peer_ip_discovery", "peer_ip_resolved");
        endpoint_addr(&identity)
    }
}

impl RealControl {
    fn discovered_peer_binding<'a>(
        config: &'a crate::local_ip::LocalIpConfig,
        project: &str,
        network: &str,
    ) -> Option<&'a crate::peer_ip::Binding> {
        config.peer_bindings.iter().find(|binding| {
            binding.project == project && binding.network == network && binding.discover
        })
    }

    async fn ip_config(
        &self,
        runtime: &ProjectRuntime,
    ) -> Result<Option<Arc<crate::local_ip::LocalIpConfig>>, ApiError> {
        if let Some(config) = &self.local_ip {
            return Ok(Some(config.clone()));
        }
        let state = self.store.snapshot().await;
        if state.projects.values().all(|p| p.peer_networks.is_empty()) {
            return Ok(None);
        }
        let underlay = runtime.underlay.ok_or_else(|| ApiError::bad_request("No physical underlay is available; reconnect with connect up after restoring your network"))?;
        Ok(Some(Arc::new(crate::networking::config(&state, underlay)?)))
    }
    pub fn new(repo: PathBuf, store: Arc<Store>, mutation_lock: Arc<Mutex<()>>) -> Self {
        Self {
            repo,
            store,
            projects: Arc::new(Mutex::new(HashMap::new())),
            up_lock: Arc::new(Mutex::new(())),
            mutation_lock,
            local_ip: None,
            relay_urls: None,
        }
    }

    pub fn with_local_ip_config(mut self, config: Option<crate::local_ip::LocalIpConfig>) -> Self {
        self.local_ip = config.map(Arc::new);
        self
    }

    pub fn with_relay_urls(mut self, relays: Option<Vec<iroh::RelayUrl>>) -> Self {
        self.relay_urls = relays;
        self
    }

    async fn project(&self, project: &str) -> Result<Arc<ProjectRuntime>, ApiError> {
        let runtime = self
            .projects
            .lock()
            .await
            .get(project)
            .cloned()
            .ok_or_else(|| {
                ApiError::new(axum::http::StatusCode::CONFLICT, "project is down")
                    .with_code("project_down")
            })?;
        if !runtime.authorized.load(Ordering::Acquire) || runtime.cancel.is_cancelled() {
            return Err(ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Connector authorization is unavailable; inspect status",
            ));
        }
        Ok(runtime)
    }

    async fn refresh_policy(runtime: &ProjectRuntime) -> Result<(), ApiError> {
        let _policy_guard = runtime.policy_lock.lock().await;
        if runtime.cancel.is_cancelled() {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "project is shutting down",
            ));
        }
        let services: Vec<_> = runtime.services.lock().await.values().cloned().collect();
        let mut destinations = HashMap::new();
        let mut first_error = None;
        for service in services.iter().filter(|service| service.desired_active) {
            let resolved = async {
                let target = resolve_target(service).await?;
                let peers = resolve_service_peers(&runtime.cloud, service).await?;
                let destination = match service.protocol {
                    Protocol::Tcp => DestinationId::tcp(endpoint_port(&service.endpoint)?),
                    Protocol::Udp => DestinationId::udp(endpoint_port(&service.endpoint)?),
                };
                Ok::<_, ApiError>((
                    destination,
                    DestinationPolicy {
                        target,
                        // Public means platform-approved gateways, never arbitrary peers.
                        access: Access::Peers(peers),
                    },
                ))
            }
            .await;
            match resolved {
                Ok((destination, policy)) if !destinations.contains_key(&destination) => {
                    destinations.insert(destination, policy);
                }
                Ok(_) => {
                    first_error.get_or_insert_with(|| {
                        ApiError::new(
                            axum::http::StatusCode::CONFLICT,
                            "duplicate transport destination",
                        )
                    });
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            };
        }
        if runtime.cancel.is_cancelled() {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "project is shutting down",
            ));
        }
        runtime
            .transport
            .replace_policy(Policy { destinations })
            .await
            .map_err(transport_error)?;
        first_error.map_or(Ok(()), Err)
    }

    async fn fail_closed(&self, project: &str, runtime: &ProjectRuntime, stage: &str, error: &str) {
        runtime.authorized.store(false, Ordering::Release);
        tracing::warn!(project, stage, error, "connector_fail_closed");
        for (_, attachment) in std::mem::take(&mut *runtime.networks.lock().await) {
            attachment.stop().await;
        }
        let _policy_guard = runtime.policy_lock.lock().await;
        let _ = runtime.transport.replace_policy(Policy::default()).await;
        let dials = std::mem::take(&mut *runtime.dials.lock().await);
        for (_, dial) in dials {
            dial.cancel.cancel();
            let _ = dial.task.await;
        }
        let _ = self
            .store
            .transact(|root| {
                if let Some(current) = root.projects.get_mut(project) {
                    current.running = false;
                    current.last_error_stage = Some(stage.to_owned());
                    current.last_error = Some(error.to_owned());
                    for service in current.services.values_mut() {
                        service.running = false;
                        service.ready = false;
                        service.last_error_stage = Some(stage.to_owned());
                        service.last_error = Some(error.to_owned());
                    }
                    for dial in current.dials.values_mut() {
                        dial.running = false;
                        dial.last_error_stage = Some(stage.to_owned());
                        dial.last_error = Some(error.to_owned());
                    }
                }
                Ok(())
            })
            .await;
    }

    async fn spawn_refresh(&self, project: String, runtime: Arc<ProjectRuntime>) {
        let control = self.clone();
        let task_runtime = runtime.clone();
        let task = tokio::spawn(async move {
            let runtime = task_runtime;
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = runtime.cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let _mutation_guard = tokio::select! {
                            _ = runtime.cancel.cancelled() => break,
                            guard = control.mutation_lock.lock() => guard,
                        };
                        if runtime.cancel.is_cancelled() { break; }
                        let details = cloud_details(&runtime.transport);
                        let result = async {
                            let identity = runtime.cloud.ensure_connect_connector(&details).await.map_err(cloud_error)?;
                            if identity.uid != runtime.identity.uid || identity.public_key != runtime.identity.public_key {
                                return Err(ApiError::new(axum::http::StatusCode::CONFLICT, "Connector identity changed"));
                            }
                            let desired = control.store.snapshot().await;
                            if let Some(project_state) = desired.projects.get(&project) {
                                for dial in project_state.dials.values().filter(|dial| dial.desired_active) {
                                    runtime.cloud.resolve_peer(&dial.connector).await.map_err(cloud_error)?;
                                }
                            }
                            // Resolve direct peers while revoking listeners waiting for a peer.
                            // Managed gateway bindings are control-plane resources, not entries
                            // in the local peer-approval file; their absence there is expected.
                            if let Some(config) = control.ip_config(&runtime).await? {
                                let networks: Vec<_> = runtime.networks.lock().await.keys().cloned().collect();
                                for network in networks {
                                    if let Some(binding) = Self::discovered_peer_binding(&config, &project, &network) {
                                        runtime.cloud.resolve_peer(&binding.peer).await.map_err(cloud_error)?;
                                    }
                                }
                            }
                            Self::refresh_policy(&runtime).await
                        }.await;
                        if let Err(error) = result {
                            control.fail_closed(&project, &runtime, "authorization_refresh", &error.message).await;
                        } else {
                            runtime.authorized.store(true, Ordering::Release);
                            let services: Vec<_> = runtime.services.lock().await.values().cloned().collect();
                            for service in services.iter().filter(|service| service.desired_active) {
                                let observed = runtime.cloud.reconcile_service(&ServiceIntent {
                                    name: service.id.clone(), endpoint: service.endpoint.clone(), public: service.public,
                                    hostname: service.hostname.clone(), protocol: protocol_name(service.protocol).into(),
                                }).await;
                                let _ = control.store.transact(|root| {
                                    if let Some(current) = root.projects.get_mut(&project).and_then(|p| p.services.get_mut(&service.id)) {
                                        match observed {
                                            Ok(value) => { current.ready = value.ready; current.hostnames = value.hostnames; current.running = true; current.last_error = None; current.last_error_stage = None; }
                                            Err(error) => { current.ready = false; current.last_error = Some(error.to_string()); current.last_error_stage = Some("service_reconcile".into()); }
                                        }
                                    }
                                    Ok(())
                                }).await;
                            }
                            let _ = control.store.transact(|root| {
                                if let Some(current) = root.projects.get_mut(&project) {
                                    current.running = true;
                                    current.last_error = None;
                                    current.last_error_stage = None;
                                }
                                Ok(())
                            }).await;
                            let desired_dials: Vec<_> = control.store.snapshot().await.projects
                                .get(&project).into_iter().flat_map(|state| state.dials.values())
                                .filter(|dial| dial.desired_active).cloned().collect();
                            let active: HashSet<_> = runtime.dials.lock().await.keys().copied().collect();
                            for dial in desired_dials {
                                let key = dial.local_port.unwrap_or(dial.bind);
                                if active.contains(&key) { continue; }
                                match control.reconcile_dial(&project, &dial).await {
                                    Ok(bound) => { let _ = control.store.transact(|root| {
                                        if let Some(mut current) = root.projects.get_mut(&project).and_then(|state| state.dials.remove(&key)) {
                                            current.bind = bound;
                                            current.local_port = Some(bound);
                                            current.running = true;
                                            if let Some(project) = root.projects.get_mut(&project) { project.dials.insert(bound, current); }
                                        }
                                        Ok(())
                                    }).await; }
                                    Err(error) => { control.fail_closed(&project, &runtime, "dial_authorization_refresh", &error.message).await; break; }
                                }
                            }
                        }
                    }
                }
            }
        });
        *runtime.refresh_task.lock().await = Some(task);
    }

    async fn stop_runtime(
        runtime: Arc<ProjectRuntime>,
        remove_cloud_services: bool,
    ) -> Result<(), ApiError> {
        runtime.cancel.cancel();
        if let Some(task) = runtime.refresh_task.lock().await.take()
            && let Err(error) = task.await
        {
            tracing::error!(%error, "authorization_refresh_task_failed");
        }
        let mut first_error = {
            let _policy_guard = runtime.policy_lock.lock().await;
            runtime
                .transport
                .replace_policy(Policy::default())
                .await
                .err()
                .map(transport_error)
        };
        let dials = std::mem::take(&mut *runtime.dials.lock().await);
        for (_, dial) in dials {
            dial.cancel.cancel();
            let _ = dial.task.await;
        }
        if remove_cloud_services {
            let services: Vec<_> = runtime.services.lock().await.keys().cloned().collect();
            for service in services {
                if let Err(error) = runtime.cloud.delete_service(&service).await
                    && first_error.is_none()
                {
                    first_error = Some(cloud_error(error));
                }
            }
        }
        for (_, attachment) in std::mem::take(&mut *runtime.networks.lock().await) {
            attachment.stop().await;
        }
        runtime.transport.shutdown().await;
        first_error.map_or(Ok(()), Err)
    }

    async fn start_project(
        &self,
        project: &str,
        credentials_file: &str,
        expected: Option<&ConnectorState>,
    ) -> Result<ConnectorState, ApiError> {
        let _up_guard = self.up_lock.lock().await;
        let credentials = Credentials::load(credentials_file)
            .await
            .map_err(cloud_error)?;
        let key = load_project_key(&self.repo, project).await?;
        let public_key = key.public().to_string();
        if let Some(previous) = self.projects.lock().await.remove(project) {
            Self::stop_runtime(previous, false).await?;
        }
        let mut transport_config = TransportConfig::new(key);
        if let Some(mode) =
            crate::relays::select(&credentials.api_endpoint, self.relay_urls.as_deref())?
        {
            transport_config = transport_config.relay_mode(mode);
        }
        let underlay = if let Some(config) = &self.local_ip {
            Some(config.underlay_address)
        } else {
            default_underlay().await
        };
        if let Some(address) = underlay {
            // Bind before publishing the Connector or creating any TUN. A
            // wildcard socket can discover overlay addresses and recurse into
            // a CONNECT-IP route after an attachment is established.
            transport_config = transport_config.bind_addr(std::net::SocketAddr::from((
                address,
                self.local_ip
                    .as_ref()
                    .map_or(0, |config| config.underlay_port),
            )));
        }
        let transport = Transport::bind(transport_config)
            .await
            .map_err(transport_error)?;
        // Binding only opens sockets. Publishing before relay discovery completes
        // sends an empty homeRelay, which the control plane rejects with HTTP 422.
        let relay_started = std::time::Instant::now();
        if tokio::time::timeout(Duration::from_secs(15), transport.endpoint().online())
            .await
            .is_err()
        {
            tracing::warn!(
                project,
                duration_ms = relay_started.elapsed().as_millis() as u64,
                "relay_startup_timeout"
            );
            transport.shutdown().await;
            return Err(ApiError::new(axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Could not connect to an iroh relay within 15 seconds. Check network connectivity, relay DNS/TLS, and the daemon's DATUM_CONNECT_RELAY_URLS configuration; retry connect up.")
                .with_code("relay_unavailable"));
        }
        let initial_details = cloud_details(&transport);
        if initial_details.relay_url.is_empty() {
            transport.shutdown().await;
            return Err(ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Relay connection has no published address; retry connect up.",
            )
            .with_code("relay_unavailable"));
        }
        tracing::info!(project, relay = %initial_details.relay_url, direct_address_count = initial_details.addresses.len(), duration_ms = relay_started.elapsed().as_millis() as u64, "relay_ready");
        let mut cloud = CloudConnector::new(credentials, project.to_owned(), public_key)
            .map_err(cloud_error)?;
        let saved = self.store.snapshot().await;
        let name = expected.map(|identity| identity.name.as_str()).or_else(|| {
            saved
                .projects
                .get(project)
                .and_then(|p| p.device_name.as_deref())
        });
        if let Some(name) = name {
            cloud = cloud.with_name(name).map_err(cloud_error)?;
        }
        // Enrollment and liveness belong to the Connect API. Do not create or
        // renew the legacy networking.datumapis.com Connector here; managed
        // gateway joins must work with Connect permissions alone.
        let identity_result = cloud.ensure_connect_connector(&initial_details).await;
        let identity = match identity_result {
            Ok(identity) => identity,
            Err(error) => {
                transport.shutdown().await;
                if expected.is_none()
                    && matches!(error, connect_lib::successor::Error::Ownership(_))
                {
                    return Err(ApiError::new(
                        axum::http::StatusCode::CONFLICT,
                        format!(
                            "Device name {} is already owned by another Connector. Nothing was adopted. Choose a different name with datumctl connect up --name YOUR-DEVICE --project {}.",
                            cloud.name(),
                            project
                        ),
                    ));
                }
                return Err(cloud_error(error));
            }
        };
        if let Some(expected) = expected
            && (identity.name != expected.name || identity.public_key != expected.public_key)
        {
            transport.shutdown().await;
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "persisted Connector identity no longer matches the control plane",
            ));
        }
        let runtime = Arc::new(ProjectRuntime {
            underlay,
            cloud,
            transport,
            services: Mutex::new(HashMap::new()),
            dials: Mutex::new(HashMap::new()),
            networks: Mutex::new(HashMap::new()),
            policy_lock: Mutex::new(()),
            cancel: CancellationToken::new(),
            refresh_task: Mutex::new(None),
            authorized: AtomicBool::new(true),
            identity: connector_state(identity.clone()),
        });
        self.projects
            .lock()
            .await
            .insert(project.to_owned(), Arc::clone(&runtime));
        self.spawn_refresh(project.to_owned(), runtime).await;
        Ok(connector_state(identity))
    }
}

#[async_trait]
impl Control for RealControl {
    async fn managed_network_setup(
        &self,
        project: &str,
        network: &str,
    ) -> Result<Option<serde_json::Value>, ApiError> {
        #[cfg(unix)]
        {
            let runtime = self.project(project).await?;
            let Some(status) = runtime
                .cloud
                .join_gateway_network(network, &cloud_details(&runtime.transport))
                .await
                .map_err(cloud_error)?
            else {
                return Ok(None);
            };
            let endpoint_id = json_string(&status, "gatewayEndpointID")?;
            let assigned_address = json_string(&status, "assignedAddress")?;
            let peer_address = json_string(&status, "peerAddress")?;
            let routes = status["routes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|route| {
                    route.as_str().map(str::to_owned).ok_or_else(|| {
                        ApiError::bad_request("ConnectNetworkBinding returned an invalid route")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut digest = Sha256::new();
            digest.update(project.as_bytes());
            digest.update([0]);
            digest.update(network.as_bytes());
            let hash = digest.finalize();
            let interface_name = format!(
                "dc{:02x}{:02x}{:02x}{:02x}{:02x}",
                hash[0], hash[1], hash[2], hash[3], hash[4]
            );
            let binding = crate::local_ip::Binding {
                project: project.to_owned(),
                network: network.to_owned(),
                gateway: endpoint_id,
                addresses: vec![],
                relay_urls: status["relayURLs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                assigned_address: assigned_address.clone(),
                routes: routes.clone(),
                interface_name: interface_name.clone(),
                mtu: 1280,
            };
            let local = binding.address()?;
            if local.prefix_len() != 128 || local.addr().is_ipv4() {
                return Err(ApiError::bad_request(
                    "ConnectNetworkBinding assignedAddress must be IPv6 /128",
                ));
            }
            let remote: connect_ip_adapter::IpNet = peer_address.parse().map_err(|_| {
                ApiError::bad_request("ConnectNetworkBinding peerAddress is invalid")
            })?;
            if remote.prefix_len() != 128 || remote.addr().is_ipv4() {
                return Err(ApiError::bad_request(
                    "ConnectNetworkBinding peerAddress must be IPv6 /128",
                ));
            }
            let parsed_routes = binding.parsed_routes()?;
            let approval = connect_ip_adapter::helper::Approval {
                interface_name: interface_name.clone(),
                assigned_address: local,
                peer_address: remote,
                mtu: 1280,
                routes: parsed_routes,
                advertise_routes: vec![],
            };
            let config = connect_ip_adapter::helper::Config {
                allowed_uid: unsafe { libc::geteuid() },
                approvals: vec![approval],
            };
            config
                .validate()
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            return Ok(Some(serde_json::json!({
                "network": network,
                "managed_gateway": true,
                "binding": {
                    "peer": status["gatewayEndpointID"],
                    "assigned_address": assigned_address,
                    "peer_address": peer_address,
                    "interface_name": interface_name,
                    "mtu": 1280,
                    "routes": routes,
                    "advertise_routes": [],
                    "allow_inbound": [],
                    "allow_outbound": []
                },
                "helper_socket": crate::networking::helper_socket()?,
                "helper_config": config
            })));
        }
        #[cfg(not(unix))]
        {
            let _ = (project, network);
            Ok(None)
        }
    }

    async fn prepare_network(
        &self,
        project: &str,
        request: &crate::networking::PrepareRequest,
    ) -> Result<crate::peer_ip::Binding, ApiError> {
        if self.local_ip.is_some() {
            return Err(ApiError::bad_request(
                "This daemon uses operator-managed --local-ip-config; remove that override before using guided peer setup",
            ));
        }
        crate::networking::helper_socket()?;
        let runtime = self.project(project).await?;
        require_network_authorization(&runtime.authorized, &runtime.cancel)?;
        let peer = runtime
            .cloud
            .resolve_peer(&request.peer)
            .await
            .map_err(cloud_error)?;
        let binding = crate::networking::binding(
            project,
            &runtime.identity.public_key,
            &peer.public_key,
            request,
        )?;
        let mut snapshot = self.store.snapshot().await;
        snapshot
            .projects
            .entry(project.into())
            .or_default()
            .peer_networks
            .insert(request.network.clone(), binding.clone());
        let underlay = runtime.underlay.ok_or_else(|| {
            ApiError::bad_request(
                "No physical underlay is available; restore your network and run connect up",
            )
        })?;
        crate::networking::config(&snapshot, underlay)?;
        Ok(binding)
    }
    async fn resolve_peer_key(&self, project: &str, peer: &str) -> Result<String, ApiError> {
        Ok(self
            .project(project)
            .await?
            .cloud
            .resolve_peer(peer)
            .await
            .map_err(cloud_error)?
            .public_key)
    }
    async fn validate_credentials(&self, credentials_file: &str) -> Result<(), ApiError> {
        Credentials::load(credentials_file)
            .await
            .map(|_| ())
            .map_err(cloud_error)
    }

    async fn up(&self, project: &str, credentials_file: &str) -> Result<ConnectorState, ApiError> {
        self.start_project(project, credentials_file, None).await
    }

    async fn resume(
        &self,
        project: &str,
        credentials_file: &str,
        expected: &ConnectorState,
    ) -> Result<ConnectorState, ApiError> {
        self.start_project(project, credentials_file, Some(expected))
            .await
    }

    async fn down(&self, project: &str) -> Result<(), ApiError> {
        let Some(runtime) = self.projects.lock().await.remove(project) else {
            return Ok(());
        };
        Self::stop_runtime(runtime, true).await
    }

    async fn reconcile_service(
        &self,
        project: &str,
        service: &ServiceState,
    ) -> Result<ServiceOutcome, ApiError> {
        if service.public && service.protocol == Protocol::Udp {
            return Err(ApiError::new(
                axum::http::StatusCode::NOT_IMPLEMENTED,
                "public UDP services are not supported by the control plane",
            ));
        }
        let runtime = self.project(project).await?;
        let cloud_service = runtime
            .cloud
            .reconcile_service(&ServiceIntent {
                name: service.id.clone(),
                endpoint: service.endpoint.clone(),
                public: service.public,
                hostname: service.hostname.clone(),
                protocol: protocol_name(service.protocol).to_owned(),
            })
            .await
            .map_err(cloud_error)?;
        runtime
            .services
            .lock()
            .await
            .insert(service.id.clone(), service.clone());
        if let Err(error) = Self::refresh_policy(&runtime).await {
            let _ = runtime.transport.replace_policy(Policy::default()).await;
            self.fail_closed(project, &runtime, "service_authorization", &error.message)
                .await;
            return Err(error);
        }
        Ok(ServiceOutcome {
            hostnames: cloud_service.hostnames,
            ready: cloud_service.ready,
        })
    }

    async fn pause_service(&self, project: &str, service: &ServiceState) -> Result<(), ApiError> {
        let runtime = self.project(project).await?;
        runtime.services.lock().await.remove(&service.id);
        Self::refresh_policy(&runtime).await?;
        runtime
            .cloud
            .delete_service(&service.id)
            .await
            .map_err(cloud_error)
    }

    async fn delete_service(&self, project: &str, service: &ServiceState) -> Result<(), ApiError> {
        self.pause_service(project, service).await
    }

    async fn reconcile_dial(&self, project: &str, dial: &DialState) -> Result<u16, ApiError> {
        let runtime = self.project(project).await?;
        let peer = runtime
            .cloud
            .resolve_peer(&dial.connector)
            .await
            .map_err(cloud_error)?;
        let peer = endpoint_addr(&peer)?;
        let cancel = runtime.cancel.child_token();
        let destination = match dial.protocol {
            Protocol::Tcp => DestinationId::tcp(dial.port),
            Protocol::Udp => DestinationId::udp(dial.port),
        };
        let (local_port, task) = match dial.protocol {
            Protocol::Tcp => {
                start_tcp_dial(
                    runtime.transport.clone(),
                    peer,
                    destination,
                    dial.bind,
                    cancel.clone(),
                )
                .await?
            }
            Protocol::Udp => {
                start_udp_dial(
                    runtime.transport.clone(),
                    peer,
                    destination,
                    dial.bind,
                    cancel.clone(),
                )
                .await?
            }
        };
        let mut dials = runtime.dials.lock().await;
        if dials.contains_key(&local_port) {
            cancel.cancel();
            task.abort();
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "local dial port is already active",
            ));
        }
        dials.insert(local_port, DialRuntime { cancel, task });
        Ok(local_port)
    }

    async fn delete_dial(&self, project: &str, port: u16) -> Result<(), ApiError> {
        // Saved intent can exist even when binding failed or the project is down.
        // The API verifies ownership and existence before removing that intent.
        let Some(runtime) = self.projects.lock().await.get(project).cloned() else {
            return Ok(());
        };
        let Some(dial) = runtime.dials.lock().await.remove(&port) else {
            return Ok(());
        };
        dial.cancel.cancel();
        let _ = dial.task.await;
        Ok(())
    }

    async fn ping(&self, project: &str, address: &str) -> Result<PingResult, ApiError> {
        let runtime = self.project(project).await?;
        let peer = runtime
            .cloud
            .resolve_peer(address)
            .await
            .map_err(cloud_error)?;
        let latency = runtime
            .transport
            .ping(endpoint_addr(&peer)?)
            .await
            .map_err(transport_error)?;
        Ok(PingResult {
            address: peer.public_key,
            latency_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
        })
    }

    async fn diagnostics(&self, project: &str) -> serde_json::Value {
        let runtime = self.projects.lock().await.get(project).cloned();
        let Some(runtime) = runtime else {
            return serde_json::Value::Null;
        };
        let stats = runtime.transport.stats();
        let snapshot = self.store.snapshot().await;
        let mut peers = Vec::new();
        if let Some(project) = snapshot.projects.get(project) {
            for dial in project.dials.values() {
                if let Ok(id) = dial.connector.parse::<EndpointId>()
                    && let Some(observed) = runtime.transport.peer_diagnostics(id)
                {
                    peers.push(serde_json::json!({"connector":dial.connector,"path":format!("{:?}",observed.path).to_lowercase(),"remote":observed.detail,"rtt_ms":observed.latency.map(|duration| duration.as_secs_f64()*1000.0)}));
                }
            }
        }
        serde_json::json!({"active_tcp":stats.active_tcp,"active_udp":stats.active_udp,"bytes_sent":stats.bytes_sent,"bytes_received":stats.bytes_received,"errors":stats.errors,"revoked":stats.revoked,"datagrams_dropped":stats.datagrams_dropped,"peers":peers})
    }

    async fn shutdown(&self) {
        let projects = std::mem::take(&mut *self.projects.lock().await);
        for (_, runtime) in projects {
            let _ = Self::stop_runtime(runtime, false).await;
        }
    }

    async fn join_network(
        &self,
        project: &str,
        network: &str,
    ) -> Result<serde_json::Value, ApiError> {
        let runtime = self.project(project).await?;
        // Prefer the project-scoped Connect API. The resource controller owns
        // gateway selection and address assignment; the daemon only applies
        // the returned, approved configuration to the local CONNECT-IP stack.
        if let Some(status) = runtime
            .cloud
            .join_gateway_network(network, &cloud_details(&runtime.transport))
            .await
            .map_err(cloud_error)?
        {
            let endpoint_id = json_string(&status, "gatewayEndpointID")?;
            let assigned_address = json_string(&status, "assignedAddress")?;
            let peer_address = json_string(&status, "peerAddress")?;
            let routes = status["routes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|route| {
                    route.as_str().map(str::to_owned).ok_or_else(|| {
                        ApiError::bad_request("ConnectNetworkBinding returned an invalid route")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let relay_urls = status["relayURLs"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|relay| {
                    relay.as_str().map(str::to_owned).ok_or_else(|| {
                        ApiError::bad_request("ConnectNetworkBinding returned an invalid relay URL")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut digest = Sha256::new();
            digest.update(project.as_bytes());
            digest.update([0]);
            digest.update(network.as_bytes());
            let hash = digest.finalize();
            let interface_name = format!(
                "dc{:02x}{:02x}{:02x}{:02x}{:02x}",
                hash[0], hash[1], hash[2], hash[3], hash[4]
            );
            let binding = crate::local_ip::Binding {
                project: project.to_owned(),
                network: network.to_owned(),
                gateway: endpoint_id.clone(),
                addresses: vec![],
                relay_urls,
                assigned_address,
                routes: routes.clone(),
                interface_name,
                mtu: 1280,
            };
            let assigned = binding.address()?;
            let peer: connect_ip_adapter::IpNet = peer_address.parse().map_err(|_| {
                ApiError::bad_request("ConnectNetworkBinding peerAddress is invalid")
            })?;
            if assigned.addr().is_ipv4()
                || assigned.prefix_len() != 128
                || peer.addr().is_ipv4()
                || peer.prefix_len() != 128
            {
                return Err(ApiError::bad_request(
                    "ConnectNetworkBinding must assign IPv6 /128 host addresses",
                ));
            }
            binding.parsed_routes()?;
            let mut networks = runtime.networks.lock().await;
            require_network_authorization(&runtime.authorized, &runtime.cancel)?;
            if let Some(existing) = networks
                .get(network)
                .filter(|attachment| !attachment.is_finished())
            {
                return Ok(existing.status().await);
            }
            if let Some(previous) = networks.remove(network) {
                previous.stop().await;
            }
            let helper_socket = crate::networking::helper_socket().ok();
            let attachment = crate::local_ip::NetworkAttachment::Gateway(
                crate::local_ip::join(
                    binding,
                    Some(peer),
                    runtime.transport.endpoint(),
                    runtime.cancel.child_token(),
                    helper_socket.as_deref(),
                )
                .await?,
            );
            if let Err(error) = require_network_authorization(&runtime.authorized, &runtime.cancel)
            {
                attachment.stop().await;
                return Err(error);
            }
            let mut result = attachment.status().await;
            result["gateway"] = serde_json::json!(endpoint_id);
            result["routes"] = serde_json::json!(routes);
            networks.insert(network.to_owned(), attachment);
            return Ok(result);
        }
        let config = self.ip_config(&runtime).await?.ok_or_else(|| ApiError::new(axum::http::StatusCode::NOT_IMPLEMENTED, "No saved IP attachment. For a direct peer, run connect join NETWORK --peer CONNECTOR with explicit traffic permissions. VPC membership is not implemented.").with_code("network_not_configured"))?;
        let binding = config.approval(project, network)?;
        let mut networks = runtime.networks.lock().await;
        require_network_authorization(&runtime.authorized, &runtime.cancel)?;
        if let Some(existing) = networks.get(network)
            && !existing.is_finished()
        {
            return Ok(existing.status().await);
        }
        if let Some(previous) = networks.remove(network) {
            previous.stop().await;
        }
        let attachment = match binding {
            crate::local_ip::Approval::Gateway(binding) => {
                crate::local_ip::NetworkAttachment::Gateway(
                    crate::local_ip::join(
                        binding,
                        None,
                        runtime.transport.endpoint(),
                        runtime.cancel.child_token(),
                        config.network_helper.as_deref(),
                    )
                    .await?,
                )
            }
            crate::local_ip::Approval::Peer(binding) => crate::local_ip::NetworkAttachment::Peer(
                crate::peer_ip::join(
                    // Names never retarget an approval: the config pins a public key.
                    binding.clone(),
                    runtime.transport.clone(),
                    runtime.cancel.child_token(),
                    config.network_helper.as_deref(),
                    binding.discover.then(|| {
                        Arc::new(CloudPeerResolver {
                            cloud: runtime.cloud.clone(),
                            config: config.clone(),
                        }) as Arc<dyn crate::peer_ip::PeerResolver>
                    }),
                )
                .await?,
            ),
        };
        if let Err(error) = require_network_authorization(&runtime.authorized, &runtime.cancel) {
            attachment.stop().await;
            return Err(error);
        }
        let status = attachment.status().await;
        networks.insert(network.to_owned(), attachment);
        Ok(status)
    }

    async fn leave_network(
        &self,
        project: &str,
        network: &str,
    ) -> Result<serde_json::Value, ApiError> {
        let mut gateway_left = false;
        if let Some(runtime) = self.projects.lock().await.get(project).cloned() {
            gateway_left = runtime
                .cloud
                .leave_gateway_network(network)
                .await
                .map_err(cloud_error)?;
        }
        if let Some(config) = &self.local_ip {
            if !gateway_left {
                config.approval(project, network)?;
            }
        } else if !self
            .store
            .snapshot()
            .await
            .projects
            .get(project)
            .is_some_and(|p| p.peer_networks.contains_key(network))
            && !gateway_left
        {
            return Err(ApiError::not_found(
                "No saved peer attachment with this name",
            ));
        }
        if let Some(runtime) = self.projects.lock().await.get(project).cloned()
            && let Some(attachment) = runtime.networks.lock().await.remove(network)
        {
            attachment.stop().await;
        }
        Ok(
            serde_json::json!({"network":network,"left":true,"ephemeral":true,"control_plane_binding_removed":gateway_left}),
        )
    }

    async fn networks(&self, project: &str) -> serde_json::Value {
        let Some(runtime) = self.projects.lock().await.get(project).cloned() else {
            return serde_json::json!([]);
        };
        let mut values = Vec::new();
        for attachment in runtime.networks.lock().await.values() {
            values.push(attachment.status().await);
        }
        let active: HashSet<_> = values
            .iter()
            .filter_map(|value| {
                value
                    .get("network")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        match runtime.cloud.managed_network_bindings().await {
            Ok(bindings) => values.extend(bindings.into_iter().filter(|binding| {
                binding
                    .get("network")
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(|network| !active.contains(network))
            })),
            Err(error) => {
                tracing::warn!(project, error = %error, "managed_connect_network_status_failed")
            }
        }
        serde_json::json!(values)
    }
}

// UDP connect selects a route/source without sending a packet. Bind transport
// before opening overlays so it cannot advertise or recurse through their IPs.
async fn default_underlay() -> Option<std::net::IpAddr> {
    for (bind, destination) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        if let Ok(socket) = UdpSocket::bind(bind).await
            && socket.connect(destination).await.is_ok()
            && let Ok(address) = socket.local_addr()
            && !address.ip().is_unspecified()
            && !address.ip().is_loopback()
        {
            tracing::info!(underlay=%address.ip(), stage="network_underlay", "physical_underlay_selected");
            return Some(address.ip());
        }
    }
    None
}

fn require_network_authorization(
    authorized: &AtomicBool,
    cancel: &CancellationToken,
) -> Result<(), ApiError> {
    if !authorized.load(Ordering::Acquire) || cancel.is_cancelled() {
        return Err(ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Connector authorization changed while joining the network; inspect status and reconnect before retrying",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod network_authorization_tests {
    use super::*;

    #[test]
    fn managed_gateway_attachment_is_not_required_in_local_peer_approvals() {
        let config = crate::local_ip::LocalIpConfig {
            network_helper: None,
            underlay_address: "192.0.2.10".parse().unwrap(),
            underlay_port: 0,
            bindings: vec![],
            peer_bindings: vec![],
        };
        assert!(
            RealControl::discovered_peer_binding(&config, "datum-cloud", "connect-subnet-lab-vpc")
                .is_none()
        );
    }

    #[test]
    fn authorization_recheck_rejects_revocation_and_shutdown_without_preventing_recovery() {
        let authorized = AtomicBool::new(true);
        let cancel = CancellationToken::new();
        require_network_authorization(&authorized, &cancel).unwrap();
        authorized.store(false, Ordering::Release);
        assert!(require_network_authorization(&authorized, &cancel).is_err());
        assert!(
            !cancel.is_cancelled(),
            "membership loss must allow existing runtime reauthorization"
        );
        authorized.store(true, Ordering::Release);
        require_network_authorization(&authorized, &cancel).unwrap();
        cancel.cancel();
        assert!(require_network_authorization(&authorized, &cancel).is_err());
    }
}

async fn start_tcp_dial(
    transport: Transport,
    peer: EndpointAddr,
    destination: DestinationId,
    port: u16,
    cancel: CancellationToken,
) -> Result<(u16, JoinHandle<()>), ApiError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let local_port = listener.local_addr()?.port();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = task_cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut local, _)) = accepted else { break };
            let transport = transport.clone();
            let peer = peer.clone();
            let destination = destination.clone();
            let stream_cancel = task_cancel.child_token();
            tokio::spawn(async move {
                let peer_id = peer.id;
                match transport
                    .connect_tcp(peer, destination, stream_cancel)
                    .await
                {
                    Ok(mut remote) => match copy_bidirectional(&mut local, &mut remote).await {
                        Ok((sent, received)) => {
                            tracing::debug!(peer = %peer_id, sent, received, "tcp_dial_complete")
                        }
                        Err(error) => {
                            tracing::warn!(peer = %peer_id, stage = "tcp_forward", %error, "tcp_dial_failed")
                        }
                    },
                    Err(error) => {
                        tracing::warn!(peer = %peer_id, stage = "tcp_connect", %error, "tcp_dial_failed")
                    }
                }
            });
        }
    });
    Ok((local_port, task))
}

async fn start_udp_dial(
    transport: Transport,
    peer: EndpointAddr,
    destination: DestinationId,
    port: u16,
    cancel: CancellationToken,
) -> Result<(u16, JoinHandle<()>), ApiError> {
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await?);
    let local_port = socket.local_addr()?.port();
    let first_tunnel = transport
        .connect_udp(peer.clone(), destination.clone(), cancel.child_token())
        .await
        .map_err(transport_error)?;
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        let mut first_tunnel = Some(first_tunnel);
        let mut clients = HashMap::<std::net::SocketAddr, mpsc::Sender<bytes::Bytes>>::new();
        let mut workers = JoinSet::new();
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => break,
                _ = workers.join_next(), if !workers.is_empty() => {},
                received = socket.recv_from(&mut buffer) => match received {
                    Ok((length, source)) => {
                        clients.retain(|_, sender| !sender.is_closed());
                        if !clients.contains_key(&source) {
                            if clients.len() >= 128 {
                                tracing::warn!(stage="udp_admission", "UDP local association limit reached");
                                continue;
                            }
                            let (sender, receiver) = mpsc::channel(32);
                            clients.insert(source, sender);
                            let preconnected = first_tunnel.take();
                            let transport = transport.clone();
                            let peer = peer.clone();
                            let destination = destination.clone();
                            let socket = socket.clone();
                            let association_cancel = task_cancel.child_token();
                            workers.spawn(async move {
                                let tunnel = match preconnected {
                                    Some(tunnel) => Ok(tunnel),
                                    None => transport.connect_udp(peer.clone(), destination, association_cancel.clone()).await,
                                };
                                match tunnel {
                                    Ok(tunnel) => udp_association(socket, source, tunnel, receiver, association_cancel).await,
                                    Err(error) => tracing::warn!(peer=%peer.id, client=%source, stage="udp_connect", %error, "udp_dial_failed"),
                                }
                            });
                        }
                        if let Some(sender) = clients.get(&source)
                            && sender.try_send(bytes::Bytes::copy_from_slice(&buffer[..length])).is_err() {
                            tracing::debug!(client=%source, "udp_packet_dropped_backpressure");
                        }
                    }
                    Err(_) => break,
                },
            }
        }
        workers.abort_all();
        while workers.join_next().await.is_some() {}
    });
    Ok((local_port, task))
}

async fn udp_association(
    socket: Arc<UdpSocket>,
    source: std::net::SocketAddr,
    tunnel: connect_transport::UdpTunnel,
    mut outbound: mpsc::Receiver<bytes::Bytes>,
    cancel: CancellationToken,
) {
    let idle = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = &mut idle => break,
            payload = outbound.recv() => match payload {
                Some(payload) => {
                    match tunnel.send(payload).await {
                        Ok(()) => {},
                        Err(connect_transport::Error::DatagramTooLarge) => {
                            tracing::debug!(client=%source, stage="udp_send", "udp_packet_dropped_oversize");
                            continue;
                        }
                        Err(_) => break,
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
                }
                None => break,
            },
            payload = tunnel.recv() => match payload {
                Some(payload) => { if socket.send_to(&payload, source).await.is_err() { break; } }
                None => break,
            },
        }
    }
}

async fn resolve_service_peers(
    cloud: &CloudConnector,
    service: &ServiceState,
) -> Result<HashSet<EndpointId>, ApiError> {
    let mut peers = if service.public {
        cloud.public_peers().await.map_err(cloud_error)?
    } else if service.allow.is_empty() {
        cloud.private_peers().await.map_err(cloud_error)?
    } else {
        Vec::new()
    };
    for allowed in &service.allow {
        peers.push(cloud.resolve_peer(allowed).await.map_err(cloud_error)?);
    }
    peers
        .into_iter()
        .map(|peer| {
            peer.public_key
                .parse()
                .map_err(|_| ApiError::internal("control plane returned an invalid peer key"))
        })
        .collect()
}

async fn resolve_target(service: &ServiceState) -> Result<Target, ApiError> {
    let mut resolved = tokio::net::lookup_host(&service.endpoint)
        .await
        .map_err(|error| ApiError::bad_request(format!("resolving service endpoint: {error}")))?;
    let address = resolved
        .next()
        .ok_or_else(|| ApiError::bad_request("service endpoint did not resolve"))?;
    Ok(match service.protocol {
        Protocol::Tcp => Target::Tcp(address),
        Protocol::Udp => Target::Udp(address),
    })
}

fn endpoint_port(endpoint: &str) -> Result<u16, ApiError> {
    endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| ApiError::bad_request("endpoint port is invalid"))
}

fn json_string(value: &serde_json::Value, key: &str) -> Result<String, ApiError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("ConnectNetworkBinding status is missing {key}"),
            )
            .with_code("connect_binding_incomplete")
        })
}

fn endpoint_addr(peer: &PeerIdentity) -> Result<EndpointAddr, ApiError> {
    let id = peer
        .public_key
        .parse()
        .map_err(|_| ApiError::internal("control plane returned an invalid peer key"))?;
    let mut address = EndpointAddr::new(id);
    for direct in &peer.addresses {
        address = address.with_ip_addr(*direct);
    }
    if !peer.relay_url.is_empty() {
        let relay = peer
            .relay_url
            .parse()
            .map_err(|_| ApiError::internal("control plane returned an invalid relay URL"))?;
        address = address.with_relay_url(relay);
    }
    Ok(address)
}

fn cloud_details(transport: &Transport) -> CloudConnectionDetails {
    let details = transport.connection_details();
    CloudConnectionDetails {
        relay_url: details.relay_urls.first().cloned().unwrap_or_default(),
        addresses: details.direct_addresses,
    }
}

async fn load_project_key(repo: &Path, project: &str) -> Result<SecretKey, ApiError> {
    let path = repo
        .join("daemon")
        .join("projects")
        .join(project)
        .join("connector.key");
    if tokio::fs::try_exists(&path).await? {
        connect_lib::secure_fs::set_private_file_permissions(&path).await?;
    }
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ApiError::internal("project connector key has an invalid length"))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            atomic_write_private(&path, &key.to_bytes()).await?;
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn connector_state(identity: PeerIdentity) -> ConnectorState {
    ConnectorState {
        name: identity.name,
        uid: identity.uid,
        public_key: identity.public_key,
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn cloud_error(error: connect_lib::successor::Error) -> ApiError {
    use connect_lib::successor::Error;
    let status = match error {
        Error::Invalid(_) => axum::http::StatusCode::BAD_REQUEST,
        Error::Unsupported(_) => axum::http::StatusCode::NOT_IMPLEMENTED,
        Error::Ownership(_) => axum::http::StatusCode::CONFLICT,
        _ => axum::http::StatusCode::BAD_GATEWAY,
    };
    ApiError::new(status, error.to_string())
}

fn transport_error(error: connect_transport::Error) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::BAD_GATEWAY,
        format!("transport failure: {error}"),
    )
}

#[cfg(test)]
mod udp_association_tests {
    use super::*;
    use bytes::Bytes;
    use connect_transport::MAX_DATAGRAM_PAYLOAD;
    use tokio::time::timeout;

    #[tokio::test]
    async fn oversized_packet_keeps_same_udp_worker_alive_for_valid_reply() {
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (length, source) = origin.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"valid-after-oversize");
            origin.send_to(&buffer[..length], source).await.unwrap();
        });
        let server = Transport::bind(
            TransportConfig::new(SecretKey::generate()).bind_addr("127.0.0.1:0".parse().unwrap()),
        )
        .await
        .unwrap();
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(SecretKey::generate())
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client = Transport::client(endpoint);
        let destination = DestinationId::udp(origin_address.port());
        server
            .replace_policy(Policy {
                destinations: HashMap::from([(
                    destination.clone(),
                    DestinationPolicy {
                        target: Target::Udp(origin_address),
                        access: Access::Peers(HashSet::from([client.endpoint_id()])),
                    },
                )]),
            })
            .await
            .unwrap();
        let details = server.connection_details();
        let peer = details.direct_addresses.into_iter().fold(
            EndpointAddr::new(details.endpoint_id),
            EndpointAddr::with_ip_addr,
        );
        let cancel = CancellationToken::new();
        let tunnel = timeout(
            Duration::from_secs(10),
            client.connect_udp(peer, destination, cancel.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let forwarder_address = forwarder.local_addr().unwrap();
        let (outgoing, incoming) = mpsc::channel(2);
        // Call the private worker directly: no listener can respawn it and mask
        // a regression that closes the association on an oversized packet.
        let worker = tokio::spawn(udp_association(
            forwarder,
            receiver.local_addr().unwrap(),
            tunnel,
            incoming,
            cancel.clone(),
        ));
        outgoing
            .send(Bytes::from(vec![0; MAX_DATAGRAM_PAYLOAD + 1]))
            .await
            .unwrap();
        outgoing
            .send(Bytes::from_static(b"valid-after-oversize"))
            .await
            .unwrap();
        let mut reply = [0u8; 128];
        let (length, source) = timeout(Duration::from_secs(5), receiver.recv_from(&mut reply))
            .await
            .expect("same UDP worker must forward after the oversize rejection")
            .unwrap();
        assert_eq!(&reply[..length], b"valid-after-oversize");
        assert_eq!(source, forwarder_address);
        assert_eq!(client.stats().datagrams_dropped, 1);
        assert!(!worker.is_finished(), "worker must remain available");
        cancel.cancel();
        timeout(Duration::from_secs(5), worker)
            .await
            .expect("worker cancellation must finish promptly")
            .unwrap();
        timeout(Duration::from_secs(5), echo)
            .await
            .unwrap()
            .unwrap();
        client.shutdown().await;
        server.shutdown().await;
    }
}
