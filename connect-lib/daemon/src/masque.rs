//! Explicitly configured production MASQUE listener.
//!
//! This is intentionally separate from project enrollment. The edge uses its
//! own Connector key and an exact route table; the backend must independently
//! authorize that public key for every configured destination.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use connect_masque_edge::{
    BearerCredential, ClientAuthentication, IpRoute, Ipv4RouteRange, Route, Server, ServerOptions,
};
use connect_transport::{DestinationId, Transport, TransportConfig, masque::ConnectUdpUriTemplate};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::ApiError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: SocketAddr,
    certificate_chain: PathBuf,
    private_key: PathBuf,
    connector_key: PathBuf,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_max_associations")]
    max_associations_per_connection: usize,
    #[serde(default = "default_connect_udp_uri_template")]
    connect_udp_uri_template: String,
    #[serde(default = "default_drain_timeout_seconds")]
    drain_timeout_seconds: u64,
    #[serde(default)]
    routes: Vec<RouteConfig>,
    #[serde(default)]
    ip_routes: Vec<IpRouteConfig>,
    clients: Vec<ClientConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteConfig {
    target_host: String,
    target_port: u16,
    backend_endpoint_id: String,
    #[serde(default)]
    backend_addresses: Vec<SocketAddr>,
    #[serde(default)]
    backend_relay_url: Option<String>,
    destination_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IpRouteConfig {
    target: String,
    protocol: String,
    backend_endpoint_id: String,
    #[serde(default)]
    backend_addresses: Vec<SocketAddr>,
    #[serde(default)]
    backend_relay_url: Option<String>,
    network: String,
    assigned_address: Ipv4Addr,
    route_updates: Vec<Vec<Ipv4RouteRangeConfig>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ipv4RouteRangeConfig {
    start: Ipv4Addr,
    end: Ipv4Addr,
    #[serde(default)]
    protocol: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    client_id: String,
    bearer_token_file: PathBuf,
    #[serde(default)]
    udp_targets: Vec<UdpTargetConfig>,
    #[serde(default)]
    ip_targets: Vec<IpTargetConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(deny_unknown_fields)]
struct UdpTargetConfig {
    target_host: String,
    target_port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(deny_unknown_fields)]
struct IpTargetConfig {
    target: String,
    protocol: String,
}

pub struct Runtime {
    transport: Transport,
    task: JoinHandle<()>,
}

impl Runtime {
    pub async fn start(path: &Path, shutdown: CancellationToken) -> Result<Self, ApiError> {
        let bytes = read_private(path, "MASQUE configuration").await?;
        let config: Config = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::bad_request("Invalid MASQUE configuration JSON"))?;
        config.validate()?;
        let server_options = ServerOptions {
            max_connections: config.max_connections,
            max_associations_per_connection: config.max_associations_per_connection,
            connect_udp_uri_template: ConnectUdpUriTemplate::parse(
                config.connect_udp_uri_template.clone(),
            )
            .map_err(|_| ApiError::bad_request("Invalid MASQUE CONNECT-UDP URI template"))?,
            drain_timeout: Duration::from_secs(config.drain_timeout_seconds),
            client_authentication: config.client_authentication().await?,
        };

        let certificate_chain =
            read_file(&config.certificate_chain, "MASQUE certificate chain", false).await?;
        let private_key = read_private(&config.private_key, "MASQUE TLS private key").await?;
        let key = read_private(&config.connector_key, "MASQUE Connector key").await?;
        let key: [u8; 32] = key.try_into().map_err(|_| {
            ApiError::bad_request("MASQUE Connector key must contain exactly 32 raw bytes")
        })?;
        let routes = config
            .routes
            .into_iter()
            .map(RouteConfig::route)
            .collect::<Result<Vec<_>, _>>()?;
        let ip_routes = config
            .ip_routes
            .into_iter()
            .map(IpRouteConfig::route)
            .collect::<Result<Vec<_>, _>>()?;
        let tls = connect_masque_edge::load_tls_pem(&certificate_chain, &private_key).map_err(
            |error| ApiError::bad_request(format!("Invalid MASQUE TLS configuration: {error:#}")),
        )?;
        let transport = Transport::bind(TransportConfig::new(SecretKey::from_bytes(&key)))
            .await
            .map_err(|error| {
                ApiError::internal(format!("binding MASQUE Connect transport: {error}"))
            })?;
        let server = match Server::bind_with_options_and_ip_routes(
            config.listen,
            tls,
            transport.clone(),
            routes,
            ip_routes,
            server_options,
        ) {
            Ok(server) => server,
            Err(error) => {
                transport.shutdown().await;
                return Err(ApiError::bad_request(format!(
                    "Invalid MASQUE listener configuration: {error:#}"
                )));
            }
        };
        let address = server.local_addr().map_err(|error| {
            ApiError::internal(format!("reading MASQUE listener address: {error:#}"))
        })?;
        tracing::info!(
            stage = "masque_startup",
            %address,
            endpoint_id = %transport.endpoint_id(),
            "masque_listener_ready"
        );
        let task = tokio::spawn(async move {
            if let Err(error) = server.serve(shutdown).await {
                tracing::error!(error = %format!("{error:#}"), "masque_listener_failed");
            }
        });
        Ok(Self { transport, task })
    }

    pub async fn shutdown(self) {
        if let Err(error) = self.task.await
            && !error.is_cancelled()
        {
            tracing::error!(%error, "masque_listener_task_failed");
        }
        self.transport.shutdown().await;
    }
}

impl Config {
    fn validate(&self) -> Result<(), ApiError> {
        if self.listen.port() == 0 {
            return Err(ApiError::bad_request("MASQUE listen port must be nonzero"));
        }
        if self.max_connections == 0
            || self.max_connections > 100_000
            || self.max_associations_per_connection == 0
            || self.max_associations_per_connection > 4096
            || self.drain_timeout_seconds == 0
            || self.drain_timeout_seconds > 300
        {
            return Err(ApiError::bad_request(
                "MASQUE connection limits are outside supported bounds",
            ));
        }
        ConnectUdpUriTemplate::parse(self.connect_udp_uri_template.clone())
            .map_err(|_| ApiError::bad_request("Invalid MASQUE CONNECT-UDP URI template"))?;
        if self.routes.len() + self.ip_routes.len() == 0
            || self.routes.len() + self.ip_routes.len() > 1024
        {
            return Err(ApiError::bad_request(
                "MASQUE configuration requires 1 to 1024 UDP or IP routes",
            ));
        }
        for path in [
            &self.certificate_chain,
            &self.private_key,
            &self.connector_key,
        ] {
            if !path.is_absolute() {
                return Err(ApiError::bad_request(
                    "MASQUE certificate and key paths must be absolute",
                ));
            }
        }
        if self.clients.is_empty() || self.clients.len() > 1024 {
            return Err(ApiError::bad_request(
                "MASQUE configuration requires 1 to 1024 authenticated clients",
            ));
        }
        let mut client_ids = HashSet::new();
        let mut token_files = HashSet::new();
        for client in &self.clients {
            if client.client_id.is_empty()
                || client.client_id.len() > 128
                || client.client_id.chars().any(char::is_control)
                || !client.bearer_token_file.is_absolute()
                || (client.udp_targets.is_empty() && client.ip_targets.is_empty())
                || !client_ids.insert(client.client_id.clone())
                || !token_files.insert(client.bearer_token_file.clone())
            {
                return Err(ApiError::bad_request(
                    "Each MASQUE client needs a unique ID, private absolute token file, and at least one route grant",
                ));
            }
            let udp_targets = client
                .udp_targets
                .iter()
                .map(|target| (target.target_host.to_ascii_lowercase(), target.target_port))
                .collect::<HashSet<_>>();
            let ip_targets = client.ip_targets.iter().collect::<HashSet<_>>();
            if udp_targets.len() != client.udp_targets.len()
                || ip_targets.len() != client.ip_targets.len()
                || client.udp_targets.iter().any(|grant| {
                    !self.routes.iter().any(|route| {
                        route.target_host.eq_ignore_ascii_case(&grant.target_host)
                            && route.target_port == grant.target_port
                    })
                })
                || client.ip_targets.iter().any(|grant| {
                    !self.ip_routes.iter().any(|route| {
                        route.target == grant.target && route.protocol == grant.protocol
                    })
                })
            {
                return Err(ApiError::bad_request(
                    "MASQUE client grants must be unique exact configured routes",
                ));
            }
        }
        for route in &self.routes {
            if route.target_host.is_empty()
                || route.target_host.len() > 255
                || route
                    .target_host
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'/')
                || route.target_port == 0
                || route.destination_port == 0
                || (route.backend_addresses.is_empty() && route.backend_relay_url.is_none())
                || route.backend_addresses.iter().any(|address| {
                    address.port() == 0
                        || address.ip().is_unspecified()
                        || address.ip().is_multicast()
                })
            {
                return Err(ApiError::bad_request(
                    "Each MASQUE route needs a valid exact target, destination port, and backend address or relay",
                ));
            }
        }
        for route in &self.ip_routes {
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
                || (route.backend_addresses.is_empty() && route.backend_relay_url.is_none())
                || route.backend_addresses.iter().any(|address| {
                    address.port() == 0
                        || address.ip().is_unspecified()
                        || address.ip().is_multicast()
                })
                || route
                    .route_updates
                    .iter()
                    .flatten()
                    .any(|range| u32::from(range.start) > u32::from(range.end))
            {
                return Err(ApiError::bad_request(
                    "Each MASQUE IP route needs an exact target/protocol, network, IPv4 assignment, route snapshots, and backend address or relay",
                ));
            }
        }
        Ok(())
    }

    async fn client_authentication(&self) -> Result<ClientAuthentication, ApiError> {
        let mut credentials = Vec::with_capacity(self.clients.len());
        for client in &self.clients {
            let mut token = read_private(&client.bearer_token_file, "MASQUE bearer token").await?;
            while matches!(token.last(), Some(b'\n' | b'\r')) {
                token.pop();
            }
            let credential = BearerCredential::new(
                client.client_id.clone(),
                &token,
                client
                    .udp_targets
                    .iter()
                    .map(|target| (target.target_host.clone(), target.target_port))
                    .collect(),
                client
                    .ip_targets
                    .iter()
                    .map(|target| (target.target.clone(), target.protocol.clone()))
                    .collect(),
            );
            token.fill(0);
            let credential = credential.map_err(|_| {
                ApiError::bad_request("Invalid MASQUE client authentication configuration")
            })?;
            credentials.push(credential);
        }
        ClientAuthentication::bearer(credentials).map_err(|_| {
            ApiError::bad_request("Invalid MASQUE client authentication configuration")
        })
    }
}

const fn default_max_connections() -> usize {
    1024
}
const fn default_max_associations() -> usize {
    128
}
fn default_connect_udp_uri_template() -> String {
    "/.well-known/masque/udp/{target_host}/{target_port}/".into()
}
const fn default_drain_timeout_seconds() -> u64 {
    5
}

impl RouteConfig {
    fn route(self) -> Result<Route, ApiError> {
        Ok(Route {
            target_host: self.target_host.to_ascii_lowercase(),
            target_port: self.target_port,
            backend: backend_addr(
                &self.backend_endpoint_id,
                self.backend_addresses,
                self.backend_relay_url,
            )?,
            destination: DestinationId::udp(self.destination_port),
        })
    }
}

impl IpRouteConfig {
    fn route(self) -> Result<IpRoute, ApiError> {
        Ok(IpRoute {
            target: self.target,
            protocol: self.protocol,
            backend: backend_addr(
                &self.backend_endpoint_id,
                self.backend_addresses,
                self.backend_relay_url,
            )?,
            network: self.network,
            assigned_address: self.assigned_address,
            route_updates: self
                .route_updates
                .into_iter()
                .map(|update| {
                    update
                        .into_iter()
                        .map(|range| Ipv4RouteRange {
                            start: range.start,
                            end: range.end,
                            protocol: range.protocol,
                        })
                        .collect()
                })
                .collect(),
        })
    }
}

fn backend_addr(
    endpoint_id: &str,
    addresses: Vec<SocketAddr>,
    relay_url: Option<String>,
) -> Result<EndpointAddr, ApiError> {
    let endpoint = endpoint_id.parse::<EndpointId>().map_err(|_| {
        ApiError::bad_request("MASQUE backend_endpoint_id must be a Connector public key")
    })?;
    let mut backend = addresses
        .into_iter()
        .fold(EndpointAddr::new(endpoint), EndpointAddr::with_ip_addr);
    if let Some(relay) = relay_url {
        backend = backend.with_relay_url(relay.parse().map_err(|_| {
            ApiError::bad_request("MASQUE backend_relay_url must be a valid relay URL")
        })?);
    }
    Ok(backend)
}

async fn read_private(path: &Path, label: &str) -> Result<Vec<u8>, ApiError> {
    #[cfg(windows)]
    connect_lib::secure_fs::validate_private_path(path).await?;
    read_file(path, label, true).await
}

async fn read_file(path: &Path, label: &str, private: bool) -> Result<Vec<u8>, ApiError> {
    let path = path.to_owned();
    let label = label.to_owned();
    tokio::task::spawn_blocking(move || read_file_blocking(&path, &label, private))
        .await
        .map_err(|_| ApiError::internal("Could not join MASQUE configuration file read"))?
}

fn read_file_blocking(path: &Path, label: &str, private: bool) -> Result<Vec<u8>, ApiError> {
    use std::io::Read;
    #[cfg(windows)]
    let _ = private; // Windows validates private paths before this blocking read.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| ApiError::bad_request(format!("Could not open {label}: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| ApiError::bad_request(format!("Could not inspect {label}: {error}")))?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(ApiError::bad_request(format!(
            "{label} must be a regular file under 1 MiB"
        )));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.mode() & 0o077 != 0 || (metadata.uid() != uid && metadata.uid() != 0) {
            return Err(ApiError::bad_request(format!(
                "{label} must be owned by this user or root and owner-only (chmod 600)"
            )));
        }
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ApiError::bad_request(format!("{label} exceeds 1 MiB")));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_client(target_host: &str, target_port: u16) -> ClientConfig {
        ClientConfig {
            client_id: "staging-client".into(),
            bearer_token_file: "/tmp/masque-client.token".into(),
            udp_targets: vec![UdpTargetConfig {
                target_host: target_host.into(),
                target_port,
            }],
            ip_targets: vec![],
        }
    }

    fn ip_client(target: &str, protocol: &str) -> ClientConfig {
        ClientConfig {
            client_id: "staging-client".into(),
            bearer_token_file: "/tmp/masque-client.token".into(),
            udp_targets: vec![],
            ip_targets: vec![IpTargetConfig {
                target: target.into(),
                protocol: protocol.into(),
            }],
        }
    }

    #[test]
    fn config_rejects_implicit_or_unroutable_targets() {
        let base = Config {
            listen: "127.0.0.1:4433".parse().unwrap(),
            certificate_chain: "/tmp/cert.pem".into(),
            private_key: "/tmp/key.pem".into(),
            connector_key: "/tmp/connector.key".into(),
            max_connections: default_max_connections(),
            max_associations_per_connection: default_max_associations(),
            connect_udp_uri_template: default_connect_udp_uri_template(),
            drain_timeout_seconds: default_drain_timeout_seconds(),
            routes: vec![],
            ip_routes: vec![],
            clients: vec![udp_client("target.example", 53)],
        };
        assert!(base.validate().is_err());
        let route = RouteConfig {
            target_host: "target.example".into(),
            target_port: 53,
            backend_endpoint_id: "unused".into(),
            backend_addresses: vec![],
            backend_relay_url: None,
            destination_port: 53,
        };
        assert!(
            Config {
                routes: vec![route],
                ..base
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn config_accepts_explicit_ip_route_and_rejects_reversed_range() {
        let mut config = Config {
            listen: "127.0.0.1:4433".parse().unwrap(),
            certificate_chain: "/tmp/cert.pem".into(),
            private_key: "/tmp/key.pem".into(),
            connector_key: "/tmp/connector.key".into(),
            max_connections: default_max_connections(),
            max_associations_per_connection: default_max_associations(),
            connect_udp_uri_template: default_connect_udp_uri_template(),
            drain_timeout_seconds: default_drain_timeout_seconds(),
            routes: vec![],
            ip_routes: vec![IpRouteConfig {
                target: "ip.example".into(),
                protocol: "connect-ip".into(),
                backend_endpoint_id: "validated when materialized".into(),
                backend_addresses: vec!["127.0.0.1:7777".parse().unwrap()],
                backend_relay_url: None,
                network: "private".into(),
                assigned_address: "10.20.0.2".parse().unwrap(),
                route_updates: vec![vec![Ipv4RouteRangeConfig {
                    start: "10.30.0.1".parse().unwrap(),
                    end: "10.30.0.9".parse().unwrap(),
                    protocol: 0,
                }]],
            }],
            clients: vec![ip_client("ip.example", "connect-ip")],
        };
        assert!(config.validate().is_ok());

        config.ip_routes[0].route_updates[0][0].start = "10.30.0.10".parse().unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validates_uri_template_and_drain_timeout() {
        let mut config = Config {
            listen: "127.0.0.1:4433".parse().unwrap(),
            certificate_chain: "/tmp/cert.pem".into(),
            private_key: "/tmp/key.pem".into(),
            connector_key: "/tmp/connector.key".into(),
            max_connections: default_max_connections(),
            max_associations_per_connection: default_max_associations(),
            connect_udp_uri_template: "/tenant/{target_host}/udp/{target_port}/".into(),
            drain_timeout_seconds: 5,
            routes: vec![RouteConfig {
                target_host: "target.example".into(),
                target_port: 53,
                backend_endpoint_id: "validated when materialized".into(),
                backend_addresses: vec!["127.0.0.1:7777".parse().unwrap()],
                backend_relay_url: None,
                destination_port: 53,
            }],
            ip_routes: vec![],
            clients: vec![udp_client("target.example", 53)],
        };
        assert!(config.validate().is_ok());
        config.connect_udp_uri_template = "/missing/{target_host}/".into();
        assert!(config.validate().is_err());
        config.connect_udp_uri_template = default_connect_udp_uri_template();
        config.drain_timeout_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_requires_authentication_and_exact_route_grants() {
        let mut config = Config {
            listen: "127.0.0.1:4433".parse().unwrap(),
            certificate_chain: "/tmp/cert.pem".into(),
            private_key: "/tmp/key.pem".into(),
            connector_key: "/tmp/connector.key".into(),
            max_connections: default_max_connections(),
            max_associations_per_connection: default_max_associations(),
            connect_udp_uri_template: default_connect_udp_uri_template(),
            drain_timeout_seconds: default_drain_timeout_seconds(),
            routes: vec![RouteConfig {
                target_host: "target.example".into(),
                target_port: 53,
                backend_endpoint_id: "validated when materialized".into(),
                backend_addresses: vec!["127.0.0.1:7777".parse().unwrap()],
                backend_relay_url: None,
                destination_port: 53,
            }],
            ip_routes: vec![],
            clients: vec![],
        };
        assert!(config.validate().is_err());
        config.clients.push(udp_client("other.example", 53));
        assert!(config.validate().is_err());
        config.clients[0] = udp_client("TARGET.EXAMPLE", 53);
        assert!(config.validate().is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_files_reject_broad_permissions() {
        use std::{io::Write, os::unix::fs::PermissionsExt};

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[7; 32]).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(file.path(), "test key").await.is_err());

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private(file.path(), "test key").await.unwrap(),
            vec![7; 32]
        );
    }
}
