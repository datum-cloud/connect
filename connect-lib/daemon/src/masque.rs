//! Explicitly configured production MASQUE listener.
//!
//! This is intentionally separate from project enrollment. The edge uses its
//! own Connector key and an exact route table; the backend must independently
//! authorize that public key for every configured destination.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use connect_masque_edge::{Route, Server};
use connect_transport::{DestinationId, Transport, TransportConfig};
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
    routes: Vec<RouteConfig>,
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
        let tls = connect_masque_edge::load_tls_pem(&certificate_chain, &private_key).map_err(
            |error| ApiError::bad_request(format!("Invalid MASQUE TLS configuration: {error:#}")),
        )?;
        let transport = Transport::bind(TransportConfig::new(SecretKey::from_bytes(&key)))
            .await
            .map_err(|error| {
                ApiError::internal(format!("binding MASQUE Connect transport: {error}"))
            })?;
        let server = match Server::bind_with_limits(
            config.listen,
            tls,
            transport.clone(),
            routes,
            config.max_connections,
            config.max_associations_per_connection,
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
        {
            return Err(ApiError::bad_request(
                "MASQUE connection limits are outside supported bounds",
            ));
        }
        if self.routes.is_empty() || self.routes.len() > 1024 {
            return Err(ApiError::bad_request(
                "MASQUE configuration requires 1 to 1024 routes",
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
        Ok(())
    }
}

const fn default_max_connections() -> usize {
    1024
}
const fn default_max_associations() -> usize {
    128
}

impl RouteConfig {
    fn route(self) -> Result<Route, ApiError> {
        let endpoint = self
            .backend_endpoint_id
            .parse::<EndpointId>()
            .map_err(|_| {
                ApiError::bad_request("MASQUE backend_endpoint_id must be a Connector public key")
            })?;
        let mut backend = self
            .backend_addresses
            .into_iter()
            .fold(EndpointAddr::new(endpoint), EndpointAddr::with_ip_addr);
        if let Some(relay) = self.backend_relay_url {
            backend = backend.with_relay_url(relay.parse().map_err(|_| {
                ApiError::bad_request("MASQUE backend_relay_url must be a valid relay URL")
            })?);
        }
        Ok(Route {
            target_host: self.target_host.to_ascii_lowercase(),
            target_port: self.target_port,
            backend,
            destination: DestinationId::udp(self.destination_port),
        })
    }
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

    #[test]
    fn config_rejects_implicit_or_unroutable_targets() {
        let base = Config {
            listen: "127.0.0.1:4433".parse().unwrap(),
            certificate_chain: "/tmp/cert.pem".into(),
            private_key: "/tmp/key.pem".into(),
            connector_key: "/tmp/connector.key".into(),
            max_connections: default_max_connections(),
            max_associations_per_connection: default_max_associations(),
            routes: vec![],
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
