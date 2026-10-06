//! Connector-owned control-plane reconciliation for the daemon.
//! Existing, unowned resources are never adopted implicitly.
mod credentials;
#[cfg(test)]
mod tests;
pub use credentials::Credentials;

use credentials::TokenProvider;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

pub type Result<T> = std::result::Result<T, Error>;
const GROUP: &str = "networking.datumapis.com/v1alpha1";
const CONNECT_GROUP: &str = "connect.datumapis.com/v1alpha1";
const OWNER: &str = "connect.datum.net/connector";
const PROTOCOL: &str = "connect.datum.net/transport";
const GATEWAYS: &str = "connect.datum.net/gateway-connectors";
const GATEWAY_CONTROLLER: &str = "connect.datum.net/gateway-controller";
const EDGE_INFO_URL: &str = "https://edge.datum.net/";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("credential exchange rejected (HTTP {0})")]
    Authentication(u16),
    #[error("control plane rejected request (HTTP {0})")]
    Api(u16),
    #[error(
        "control plane rejected {method} {resource} (HTTP {status}): {reason}; invalid fields: {fields}"
    )]
    Validation {
        status: u16,
        method: String,
        resource: String,
        reason: String,
        fields: String,
    },
    #[error("resource is not owned by this Connector: {0}")]
    Ownership(String),
    #[error("{0}")]
    NotFound(String),
    #[error("platform capability unavailable: {0}")]
    Unsupported(String),
    #[error("network request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("storage failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub name: String,
    pub uid: String,
    pub public_key: String,
    pub relay_url: String,
    pub addresses: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionDetails {
    pub relay_url: String,
    pub addresses: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct ServiceIntent {
    pub name: String,
    pub endpoint: String,
    pub public: bool,
    pub hostname: Option<String>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudService {
    pub name: String,
    pub hostnames: Vec<String>,
    pub ready: bool,
}

#[derive(Clone)]
pub struct CloudConnector {
    client: reqwest::Client,
    tokens: TokenProvider,
    base: String,
    name: String,
    public_key: String,
    edge_info_url: String,
    lease_lock: Arc<tokio::sync::Mutex<()>>,
}

pub(crate) fn validate_url(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value).map_err(|_| Error::Invalid("invalid API/token URL".into()))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("API/token URL must use HTTPS (HTTP allowed only on loopback), without credentials/query/fragment".into()));
    }
    Ok(url)
}

fn validate_ipv6_prefix(value: &str) -> std::result::Result<(), ()> {
    let (address, prefix) = value.split_once('/').ok_or(())?;
    address.parse::<std::net::Ipv6Addr>().map_err(|_| ())?;
    let prefix = prefix.parse::<u8>().map_err(|_| ())?;
    if !(2..=128).contains(&prefix) {
        return Err(());
    }
    Ok(())
}

fn network_gateway_name(network: &str, location: &str) -> String {
    let hash = sha2::Sha256::digest(format!("{network}/{location}").as_bytes());
    let suffix = hex::encode(&hash[..5]);
    let mut stem = network
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    stem = stem.trim_matches('-').to_owned();
    if stem.is_empty() {
        stem = "network".into();
    }
    stem.truncate(35);
    let location = location.to_ascii_lowercase();
    format!("connect-{stem}-{location}-{suffix}")
}

pub(crate) async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if result.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            return Err(Error::Invalid(
                "control-plane response exceeds 4 MiB".into(),
            ));
        }
        result.extend_from_slice(&chunk);
    }
    Ok(result)
}

impl CloudConnector {
    pub fn new(credentials: Credentials, project: String, public_key: String) -> Result<Self> {
        credentials.validate()?;
        if credentials.project_id != project {
            return Err(Error::Invalid(
                "credential project does not match enrollment".into(),
            ));
        }
        let key: iroh::EndpointId = public_key
            .parse()
            .map_err(|_| Error::Invalid("invalid Connector public key".into()))?;
        let public_key = key.to_string();
        let name = format!("connect-{}", &public_key[..40]);
        let mut base = validate_url(&credentials.api_endpoint)?;
        base.path_segments_mut()
            .map_err(|()| Error::Invalid("API URL is not hierarchical".into()))?
            .pop_if_empty()
            .extend([
                "apis",
                "resourcemanager.miloapis.com",
                "v1alpha1",
                "projects",
                &project,
                "control-plane",
            ]);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            tokens: TokenProvider::new(credentials, client.clone()),
            client,
            base: base.to_string(),
            name,
            public_key,
            edge_info_url: EDGE_INFO_URL.into(),
            lease_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Use a human-readable, project-unique resource name without changing the
    /// transport key. Kubernetes create conflicts prevent taking another device's name.
    pub fn with_name(mut self, name: &str) -> Result<Self> {
        validate_name(name)?;
        self.name = name.to_owned();
        Ok(self)
    }

    fn resource(&self, plural: &str, name: &str) -> String {
        let group = if plural == "httpproxies" {
            "networking.datumapis.com/v1alpha"
        } else {
            GROUP
        };
        format!(
            "{}/apis/{group}/namespaces/default/{plural}/{name}",
            self.base.trim_end_matches('/')
        )
    }

    fn connect_resource(&self, plural: &str, name: &str) -> String {
        format!(
            "{}/apis/{CONNECT_GROUP}/namespaces/default/{plural}/{name}",
            self.base.trim_end_matches('/')
        )
    }

    fn connect_cluster_resource(&self, plural: &str) -> String {
        format!(
            "{}/apis/{CONNECT_GROUP}/{plural}",
            self.base.trim_end_matches('/')
        )
    }

    async fn connect_get(&self, plural: &str, name: &str) -> Result<Option<Value>> {
        self.request(Method::GET, &self.connect_resource(plural, name), None)
            .await
    }

    async fn connect_create(&self, plural: &str, object: &Value) -> Result<Value> {
        let name = object["metadata"]["name"]
            .as_str()
            .ok_or_else(|| Error::Invalid("resource name missing".into()))?;
        match self
            .request(
                Method::POST,
                &self.connect_resource(plural, ""),
                Some(object),
            )
            .await
        {
            Ok(Some(value)) => Ok(value),
            Err(Error::Api(409)) => self.connect_get(plural, name).await?.ok_or(Error::Api(404)),
            Ok(None) => Err(Error::Api(500)),
            Err(error) => Err(error),
        }
    }

    /// Register the live iroh identity with the Connect service.
    pub async fn ensure_connect_connector(
        &self,
        details: &ConnectionDetails,
    ) -> Result<PeerIdentity> {
        self.connect_connector(details, true).await
    }

    /// Refresh an enrolled Connector without recreating it if an administrator
    /// deleted it. This keeps deletion an immediate revocation boundary.
    pub async fn refresh_connect_connector(
        &self,
        details: &ConnectionDetails,
    ) -> Result<PeerIdentity> {
        self.connect_connector(details, false).await
    }

    async fn connect_connector(
        &self,
        details: &ConnectionDetails,
        allow_create: bool,
    ) -> Result<PeerIdentity> {
        let existing = self.connect_get("connectors", &self.name).await?;
        let connector = if let Some(value) = existing {
            if value.pointer("/spec/publicKey").and_then(Value::as_str)
                != Some(self.public_key.as_str())
            {
                return Err(Error::Ownership(self.name.clone()));
            }
            value
        } else {
            if !allow_create {
                return Err(Error::Api(404));
            }
            let classes_url = format!("{}/apis/{CONNECT_GROUP}/connectorclasses", self.base);
            let classes = self
                .request(Method::GET, &classes_url, None)
                .await?
                .ok_or(Error::Api(404))?;
            let ready = classes["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|class| {
                    class["spec"]["transports"]
                        .as_array()
                        .is_some_and(|transports| {
                            transports.iter().any(|transport| transport == "masque-v1")
                        })
                        && current_condition(class, "Ready")
                })
                .collect::<Vec<_>>();
            if ready.len() != 1 {
                return Err(Error::Unsupported(format!(
                    "expected one Ready Connect ConnectorClass advertising masque-v1; found {}",
                    ready.len()
                )));
            }
            let class = string(ready[0], "/metadata/name")?;
            let relays = if details.relay_url.is_empty() {
                Vec::new()
            } else {
                vec![details.relay_url.clone()]
            };
            let mut endpoint = iroh::EndpointAddr::new(
                self.public_key
                    .parse()
                    .map_err(|_| Error::Invalid("invalid Connector public key".into()))?,
            );
            for address in &details.addresses {
                endpoint = endpoint.with_ip_addr(*address);
            }
            if !details.relay_url.is_empty() {
                endpoint = endpoint.with_relay_url(
                    details
                        .relay_url
                        .parse()
                        .map_err(|_| Error::Invalid("invalid relay URL".into()))?,
                );
            }
            let desired = json!({
                "apiVersion": CONNECT_GROUP,
                "kind": "Connector",
                "metadata": {"name": self.name},
                "spec": {"classRef": class, "publicKey": self.public_key, "relayURLs": relays, "endpoint": serde_json::to_string(&endpoint)?}
            });
            self.connect_create("connectors", &desired).await?
        };
        if connector.pointer("/spec/publicKey").and_then(Value::as_str)
            != Some(self.public_key.as_str())
        {
            return Err(Error::Ownership(self.name.clone()));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut connector = connector;
        loop {
            self.renew_connect_connector_lease(&connector).await?;
            if current_condition(&connector, "Ready") {
                return self.connect_identity(&connector, details);
            }
            if tokio::time::Instant::now() >= deadline {
                let reason = connector
                    .pointer("/status/conditions")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|condition| condition["type"] == "Ready")
                    .and_then(|condition| condition["reason"].as_str())
                    .unwrap_or("waiting for controller");
                return Err(Error::Unsupported(format!(
                    "Connect Connector {} is not Ready ({reason}); check ConnectorClass and Lease reconciliation",
                    self.name
                )));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            connector = self
                .connect_get("connectors", &self.name)
                .await?
                .ok_or(Error::Api(404))?;
            if connector.pointer("/spec/publicKey").and_then(Value::as_str)
                != Some(self.public_key.as_str())
            {
                return Err(Error::Ownership(self.name.clone()));
            }
        }
    }

    fn connect_identity(
        &self,
        connector: &Value,
        details: &ConnectionDetails,
    ) -> Result<PeerIdentity> {
        let public_key = string(connector, "/spec/publicKey")?;
        if public_key != self.public_key {
            return Err(Error::Ownership(self.name.clone()));
        }
        Ok(PeerIdentity {
            name: string(connector, "/metadata/name")?,
            uid: string(connector, "/metadata/uid")?,
            public_key,
            relay_url: details.relay_url.clone(),
            addresses: details.addresses.clone(),
        })
    }

    fn connect_peer_identity(&self, connector: &Value) -> Result<PeerIdentity> {
        let name = string(connector, "/metadata/name")?;
        let uid = string(connector, "/metadata/uid")?;
        let public_key = string(connector, "/spec/publicKey")?;
        let id: iroh::EndpointId = public_key.parse().map_err(|_| {
            Error::Invalid("control plane returned an invalid Connector key".into())
        })?;
        let address = connector
            .pointer("/spec/endpoint")
            .and_then(Value::as_str)
            .and_then(|value| serde_json::from_str::<iroh::EndpointAddr>(value).ok());
        let address = address.filter(|address| address.id == id);
        let relay_url = address
            .as_ref()
            .and_then(|address| address.relay_urls().next())
            .map(ToString::to_string)
            .or_else(|| {
                connector
                    .pointer("/spec/relayURLs/0")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let addresses = address
            .as_ref()
            .map(|address| address.ip_addrs().copied().collect())
            .unwrap_or_default();
        Ok(PeerIdentity {
            name,
            uid,
            public_key,
            relay_url,
            addresses,
        })
    }

    async fn renew_connect_connector_lease(&self, connector: &Value) -> Result<()> {
        let Some(name) = connector.pointer("/status/leaseRef").and_then(|lease| {
            lease
                .as_str()
                .or_else(|| lease.get("name").and_then(Value::as_str))
        }) else {
            // The controller creates the Lease after observing the Connector.
            return Ok(());
        };
        validate_name(name)?;
        // Liveness, authorization refresh, and gateway setup can all renew the
        // same Lease concurrently. Serialize updates and retry resourceVersion
        // conflicts so a harmless race cannot fail-close the Connector.
        let _lease_guard = self.lease_lock.lock().await;
        let url = format!(
            "{}/apis/coordination.k8s.io/v1/namespaces/default/leases/{name}",
            self.base
        );
        for attempt in 0..4 {
            let Some(mut lease) = self.request(Method::GET, &url, None).await? else {
                return Ok(());
            };
            lease["spec"]["renewTime"] =
                json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
            match self.request(Method::PUT, &url, Some(&lease)).await {
                Ok(_) => return Ok(()),
                Err(Error::Api(409)) if attempt < 3 => {
                    tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Renew this device's Connect Connector lease without reconciling any
    /// other project resources. The daemon runs this independently of slow
    /// operations such as waiting for a gateway workload rollout.
    pub async fn renew_connect_connector_liveness(&self) -> Result<()> {
        let connector = self
            .connect_get("connectors", &self.name)
            .await?
            .ok_or(Error::Api(404))?;
        if connector.pointer("/spec/publicKey").and_then(Value::as_str)
            != Some(self.public_key.as_str())
        {
            return Err(Error::Ownership(self.name.clone()));
        }
        self.renew_connect_connector_lease(&connector).await
    }

    /// Create or reuse this Connector's project binding to a gateway in the
    /// edge-selected location. If no gateway exists there, create one from the
    /// network's assigned prefix and the operator's default gateway class.
    /// `None` means the ConnectGateway API is not installed yet.
    pub async fn join_gateway_network(
        &self,
        network: &str,
        details: &ConnectionDetails,
    ) -> Result<Option<Value>> {
        validate_name(network)?;
        let Some(gateways) = self
            .request(
                Method::GET,
                &self.connect_resource("connectgateways", ""),
                None,
            )
            .await?
        else {
            // Preserve staged rollout behavior while the ConnectGateway API is
            // unavailable. Once installed, missing gateways are auto-created.
            return Ok(None);
        };
        let network_object = self
            .request(Method::GET, &self.resource("networks", network), None)
            .await?
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "Network {network:?} was not found in this project."
                ))
            })?;
        let location = self.edge_location().await?;
        let matches = gateways["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|gateway| {
                gateway["spec"]["networkRef"] == network
                    && gateway["spec"]["locationRef"] == location
            })
            .cloned()
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            let names = matches
                .iter()
                .filter_map(|item| item["metadata"]["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::Unsupported(format!(
                "multiple ConnectGateways exist for network {network:?} in location {location}: {names}; remove the duplicate or ask your administrator to resolve it"
            )));
        }
        let gateway = if let Some(gateway) = matches.into_iter().next() {
            gateway
        } else {
            self.create_network_gateway(network, &location, &network_object)
                .await?
        };
        let gateway_name = string(&gateway, "/metadata/name")?;
        tracing::info!(
            network,
            location,
            gateway = gateway_name,
            stage = "gateway_selected",
            "selected project ConnectGateway"
        );

        // Register the Connector before creating its binding. An OnDemand
        // gateway stays dormant until a ready Connector binding exists.
        self.ensure_connect_connector(details).await?;
        let binding_name = network_binding_name(network, &self.name);
        let binding = match self
            .connect_get("connectnetworkbindings", &binding_name)
            .await?
        {
            Some(value) => {
                if value["spec"]["connectorRef"] != self.name
                    || value["spec"]["gatewayRef"] != gateway_name
                {
                    return Err(Error::Ownership(format!(
                        "network binding {binding_name} already targets another Connector or gateway; remove it with `datumctl connect leave {network}` first"
                    )));
                }
                value
            }
            None => {
                self.connect_create(
                    "connectnetworkbindings",
                    &json!({
                        "apiVersion": CONNECT_GROUP,
                        "kind": "ConnectNetworkBinding",
                        "metadata": {"name": binding_name},
                        "spec": {"gatewayRef": gateway_name, "connectorRef": self.name}
                    }),
                )
                .await?
            }
        };
        // The controller publishes approval and addresses asynchronously. Wait
        // for that status so `join` never reports a half-created attachment.
        // A fresh OnDemand gateway needs time for its Compute Workload to
        // provision and apply the Connector grant. Match the plugin's default
        // four-minute request budget instead of timing out during startup.
        let until = tokio::time::Instant::now() + Duration::from_secs(240);
        let mut binding = binding;
        let mut connector_not_ready_logged = false;
        let mut gateway_workload_wait_logged = false;
        loop {
            if current_condition(&binding, "Accepted") {
                let mut result = binding["status"].clone();
                result["network"] = json!(network);
                result["gateway"] = json!(gateway_name);
                result["gateway_location"] = json!(gateway["spec"]["locationRef"]);
                if result["endpointID"].is_string() {
                    result["gatewayEndpointID"] = result["endpointID"].clone();
                } else if let Some(endpoint) = gateway.pointer("/status/endpointID") {
                    result["gatewayEndpointID"] = endpoint.clone();
                }
                result["bindingName"] = json!(binding_name);
                result["connectorName"] = json!(self.name);
                return Ok(Some(result));
            }
            if let Some(condition) = binding
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|condition| condition["type"] == "Accepted" && condition["status"] == "False")
            {
                let reason = condition["reason"].as_str().unwrap_or("unknown reason");
                if reason != "ConnectorNotReady" {
                    return Err(Error::Unsupported(format!(
                        "ConnectNetworkBinding was rejected ({reason})"
                    )));
                }
                // Connector Ready can lag behind the liveness lease renewal
                // immediately before binding creation. This rejection is
                // recoverable: keep polling rather than returning stale state.
                if !connector_not_ready_logged {
                    tracing::info!(
                        network,
                        connector = %self.name,
                        binding = %binding_name,
                        stage = "connector_readiness",
                        "waiting for Connector readiness to reconcile"
                    );
                    connector_not_ready_logged = true;
                }
            }
            if !gateway_workload_wait_logged
                && let Some(condition) = binding
                    .pointer("/status/conditions")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|condition| {
                        condition["type"] == "Accepted"
                            && matches!(
                                condition["reason"].as_str(),
                                Some("GatewayProvisioning" | "GatewayApplyingGrant")
                            )
                    })
            {
                tracing::info!(
                    network,
                    gateway = gateway_name,
                    reason = condition["reason"].as_str().unwrap_or("unknown"),
                    stage = "gateway_workload_startup",
                    "waiting for the VPC gateway workload to become ready"
                );
                gateway_workload_wait_logged = true;
            }
            if tokio::time::Instant::now() >= until {
                if connector_not_ready_logged {
                    return Err(Error::Unsupported(format!(
                        "ConnectNetworkBinding {binding_name} is still rejected because Connector {} is not Ready; verify its liveness lease and retry `datumctl connect join {network}`",
                        self.name
                    )));
                }
                return Err(Error::Unsupported(format!(
                    "timed out waiting for ConnectNetworkBinding {binding_name} approval; the VPC gateway may still be starting. Inspect `datumctl get connectnetworkbindings {binding_name}` and retry `datumctl connect join {network}`"
                )));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            binding = self
                .connect_get("connectnetworkbindings", &binding_name)
                .await?
                .ok_or(Error::Api(404))?;
        }
    }

    async fn edge_location(&self) -> Result<String> {
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            self.client.get(&self.edge_info_url).send(),
        )
        .await
        .map_err(|_| {
            Error::Unsupported(
                "could not determine your nearest Connect location because edge.datum.net timed out; check your internet connection and retry".into(),
            )
        })?
        .map_err(|error| {
            tracing::warn!(error = %error, stage = "edge_location_lookup", "could not reach nearest-location service");
            Error::Unsupported(
                "could not reach edge.datum.net to determine your nearest Connect location; check your internet connection and retry".into(),
            )
        })?;
        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                stage = "edge_location_lookup",
                "nearest-location service returned an error"
            );
            return Err(Error::Unsupported(format!(
                "could not determine your nearest Connect location because edge.datum.net returned HTTP {}; retry later or ask your administrator to check edge.datum.net",
                response.status().as_u16()
            )));
        }
        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            tracing::warn!(error = %error, stage = "edge_location_response", "failed to read nearest-location response");
            Error::Unsupported(
                "could not read the response from edge.datum.net; check your internet connection and retry".into(),
            )
        })? {
            if body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err(Error::Unsupported(
                    "edge.datum.net returned an unexpectedly large location response".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).map_err(|_| {
            Error::Unsupported("edge.datum.net returned an invalid location response".into())
        })?;
        let colo = body
            .lines()
            .find_map(|line| line.trim().strip_prefix("colo="))
            .map(str::trim)
            .filter(|colo| colo.len() == 3 && colo.bytes().all(|byte| byte.is_ascii_uppercase()))
            .ok_or_else(|| Error::Unsupported("edge.datum.net did not return a valid three-letter colo; retry later or ask your administrator to check the edge location mapping".into()))?;
        tracing::info!(
            colo,
            stage = "edge_location_resolved",
            "resolved nearest Connect location"
        );
        Ok(colo.to_owned())
    }

    async fn create_network_gateway(
        &self,
        network: &str,
        location: &str,
        network_object: &Value,
    ) -> Result<Value> {
        let prefix = network_object
            .pointer("/status/ipam/ipv6Prefix")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Unsupported(format!("network {network:?} has no assigned IPv6 prefix yet; wait for the Network to become Ready and retry")))?;
        validate_ipv6_prefix(prefix).map_err(|_| Error::Unsupported(format!("network {network:?} has an invalid assigned IPv6 prefix; ask your administrator to check its IPAM status")))?;

        let classes = self
            .request(Method::GET, &self.connect_cluster_resource("connectgatewayclasses"), None)
            .await?
            .ok_or_else(|| Error::Unsupported("the ConnectGatewayClass API is not available; ask your administrator to install the Connect gateway controller and configure a default gateway class".into()))?;
        let ready = classes["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|class| {
                class["spec"]["controllerName"] == GATEWAY_CONTROLLER
                    && current_condition(class, "Ready")
            })
            .collect::<Vec<_>>();
        let defaults = ready
            .iter()
            .copied()
            .filter(|class| class["spec"]["default"] == true)
            .collect::<Vec<_>>();
        let class = match (defaults.as_slice(), ready.as_slice()) {
            ([class], _) => *class,
            ([], [class]) => *class,
            ([], []) => return Err(Error::Unsupported("no Ready ConnectGatewayClass is available; ask your administrator to configure a gateway class".into())),
            ([], _) => return Err(Error::Unsupported("multiple Ready ConnectGatewayClasses exist; ask your administrator to mark exactly one as the default".into())),
            _ => return Err(Error::Unsupported("multiple Ready ConnectGatewayClasses are marked as the default; ask your administrator to leave only one default".into())),
        };
        let class_name = string(class, "/metadata/name")?;
        let name = network_gateway_name(network, location);
        let relay_urls = class["spec"]["relayURLs"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let desired = json!({
            "apiVersion": CONNECT_GROUP,
            "kind": "ConnectGateway",
            "metadata": {"name": name},
            "spec": {"gatewayClassRef": class_name, "networkRef": network, "locationRef": location, "routes": [prefix], "relayURLs": relay_urls}
        });
        tracing::info!(
            network,
            location,
            gateway = name,
            gateway_class = class_name,
            stage = "gateway_create",
            "creating ConnectGateway for project network"
        );
        match self.connect_create("connectgateways", &desired).await {
            Ok(gateway) => Ok(gateway),
            Err(error) => Err(error),
        }
    }

    pub async fn leave_gateway_network(&self, network: &str) -> Result<bool> {
        validate_name(network)?;
        let name = network_binding_name(network, &self.name);
        let Some(binding) = self.connect_get("connectnetworkbindings", &name).await? else {
            return Ok(false);
        };
        if binding["spec"]["connectorRef"] != self.name {
            return Err(Error::Ownership(name));
        }
        let uid = string(&binding, "/metadata/uid")?;
        let resource_version = string(&binding, "/metadata/resourceVersion")?;
        let options = json!({"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":uid,"resourceVersion":resource_version}});
        match self
            .request(
                Method::DELETE,
                &self.connect_resource("connectnetworkbindings", &name),
                Some(&options),
            )
            .await
        {
            Ok(_) | Err(Error::Api(404)) => Ok(true),
            Err(error) => Err(error),
        }
    }

    /// Project-scoped bindings owned by this Connector for `status` output.
    /// Bindings survive a daemon restart; this inventory distinguishes that
    /// control-plane intent from the ephemeral local TUN attachment.
    pub async fn managed_network_bindings(&self) -> Result<Vec<Value>> {
        let Some(list) = self
            .request(
                Method::GET,
                &self.connect_resource("connectnetworkbindings", ""),
                None,
            )
            .await?
        else {
            return Ok(Vec::new());
        };
        if list
            .pointer("/metadata/continue")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty())
        {
            return Err(Error::Unsupported(
                "paginated ConnectNetworkBinding list prevents safe status inventory".into(),
            ));
        }
        let mut result = Vec::new();
        for binding in list["items"].as_array().into_iter().flatten() {
            if binding["spec"]["connectorRef"] != self.name {
                continue;
            }
            let name = string(binding, "/metadata/name")?;
            let gateway_ref = string(binding, "/spec/gatewayRef")?;
            let gateway = self
                .connect_get("connectgateways", &gateway_ref)
                .await?
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "ConnectNetworkBinding {name} references a missing gateway"
                    ))
                })?;
            let network = string(&gateway, "/spec/networkRef")?;
            let status = &binding["status"];
            result.push(json!({
                "network": network,
                "mode": "gateway",
                "binding_name": name,
                "gateway": gateway_ref,
                "assigned_address": status["assignedAddress"],
                "peer_address": status["peerAddress"],
                "routes": status["routes"],
                "running": false,
                "connected": false,
                "state": "inactive",
                "last_error": "Local attachment is ephemeral; run datumctl connect join to attach again"
            }));
        }
        Ok(result)
    }

    #[tracing::instrument(name = "control_plane.request", skip_all, fields(method = %method, connector = %self.name))]
    async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Option<Value>> {
        let started = std::time::Instant::now();
        for attempt in 0..2 {
            let token = self.tokens.token().await?;
            let mut request = self.client.request(method.clone(), url).bearer_auth(token);
            if let Some(body) = body {
                request = request.json(body);
            }
            let response = request.send().await?;
            tracing::debug!(
                attempt,
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_millis() as u64,
                "control-plane response"
            );
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.tokens.invalidate().await;
                continue;
            }
            if response.status() == StatusCode::NOT_FOUND && method == Method::GET {
                return Ok(None);
            }
            if !response.status().is_success() {
                let status = response.status().as_u16();
                let resource = url
                    .strip_prefix(&self.base)
                    .unwrap_or("control-plane resource");
                tracing::warn!(%method, resource, status, "control_plane_request_rejected");
                if status == 422 {
                    // Only return bounded field paths and reason identifiers. Kubernetes
                    // messages can echo rejected values, so never expose raw response bodies.
                    let body = bounded_body(response).await?;
                    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let identifier = |value: &Value| -> String {
                        value
                            .as_str()
                            .unwrap_or("unknown")
                            .chars()
                            .take(160)
                            .filter(|c| {
                                c.is_ascii_alphanumeric()
                                    || matches!(c, '.' | '_' | '-' | '[' | ']')
                            })
                            .collect()
                    };
                    let fields = value
                        .pointer("/details/causes")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .take(8)
                        .map(|cause| identifier(&cause["field"]))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(Error::Validation {
                        status,
                        method: method.to_string(),
                        resource: resource.to_owned(),
                        reason: identifier(&value["reason"]),
                        fields,
                    });
                }
                return Err(Error::Api(status));
            }
            let bytes = bounded_body(response).await?;
            return if bytes.is_empty() {
                Ok(Some(Value::Null))
            } else {
                Ok(Some(serde_json::from_slice(&bytes)?))
            };
        }
        Err(Error::Authentication(401))
    }

    async fn get(&self, plural: &str, name: &str) -> Result<Option<Value>> {
        self.request(Method::GET, &self.resource(plural, name), None)
            .await
    }

    /// Deterministic create + GET-on-conflict makes uncertain retries idempotent.
    async fn create(&self, plural: &str, object: &Value) -> Result<Value> {
        let name = object["metadata"]["name"]
            .as_str()
            .ok_or_else(|| Error::Invalid("resource name missing".into()))?;
        match self
            .request(Method::POST, &self.resource(plural, ""), Some(object))
            .await
        {
            Ok(Some(value)) => Ok(value),
            Err(Error::Api(409)) => self.get(plural, name).await?.ok_or(Error::Api(404)),
            Ok(None) => Err(Error::Api(500)),
            Err(error) => Err(error),
        }
    }

    fn identity(&self, object: &Value) -> Result<PeerIdentity> {
        if !object["metadata"]["deletionTimestamp"].is_null() {
            return Err(Error::Ownership("Connector is terminating".into()));
        }
        let name = string(object, "/metadata/name")?;
        let uid = string(object, "/metadata/uid")?;
        let public_key = string(object, "/status/connectionDetails/publicKey/id")?;
        let _: iroh::EndpointId = public_key
            .parse()
            .map_err(|_| Error::Invalid("control plane returned invalid public key".into()))?;
        let relay_url = object
            .pointer("/status/connectionDetails/publicKey/homeRelay")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !relay_url.is_empty() {
            validate_url(&relay_url)?;
        }
        let mut addresses = Vec::new();
        for address in object
            .pointer("/status/connectionDetails/publicKey/addresses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let ip = string(address, "/address")?
                .parse()
                .map_err(|_| Error::Invalid("invalid Connector address".into()))?;
            let port = address["port"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| Error::Invalid("invalid Connector port".into()))?;
            addresses.push(SocketAddr::new(ip, port));
        }
        Ok(PeerIdentity {
            name,
            uid,
            public_key,
            relay_url,
            addresses,
        })
    }

    async fn owned_connector(&self) -> Result<Value> {
        let connector = self
            .get("connectors", &self.name)
            .await?
            .ok_or(Error::Api(404))?;
        if connector["metadata"]["annotations"]["connect.datum.net/public-key"] != self.public_key
            || !connector["metadata"]["deletionTimestamp"].is_null()
        {
            return Err(Error::Ownership(self.name.clone()));
        }
        Ok(connector)
    }

    async fn owned_connect_connector(&self) -> Result<Value> {
        let connector = self
            .connect_get("connectors", &self.name)
            .await?
            .ok_or(Error::Api(404))?;
        if connector.pointer("/spec/publicKey").and_then(Value::as_str) != Some(&self.public_key)
            || !connector["metadata"]["deletionTimestamp"].is_null()
        {
            return Err(Error::Ownership(self.name.clone()));
        }
        Ok(connector)
    }

    pub async fn ensure_connector(&self, details: &ConnectionDetails) -> Result<PeerIdentity> {
        if self.get("connectors", &self.name).await?.is_none() {
            let classes_url = format!("{}/apis/{GROUP}/connectorclasses", self.base);
            let classes = self
                .request(Method::GET, &classes_url, None)
                .await?
                .ok_or(Error::Api(404))?;
            let classes: Vec<&Value> = classes["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| item["metadata"]["annotations"][PROTOCOL] == "masque-v1")
                .collect();
            if classes.len() != 1 {
                return Err(Error::Unsupported("exactly one ConnectorClass must advertise connect.datum.net/transport=masque-v1".into()));
            }
            self.create("connectors", &json!({"apiVersion":GROUP,"kind":"Connector","metadata":{"name":self.name,"annotations":{"connect.datum.net/public-key":self.public_key,(PROTOCOL):"masque-v1"}},"spec":{"connectorClassName":string(classes[0],"/metadata/name")?}})).await?;
        }
        self.renew(details).await
    }

    pub async fn renew(&self, details: &ConnectionDetails) -> Result<PeerIdentity> {
        let mut uid = None;
        for attempt in 0..4 {
            match self.renew_once(details, &mut uid).await {
                Err(Error::Api(409)) if attempt < 3 => {
                    tracing::warn!(connector = %self.name, attempt = attempt + 1, "connector_renew_conflict_retry");
                    tokio::time::sleep(Duration::from_millis(50 << attempt)).await;
                }
                result => return result,
            }
        }
        unreachable!("last renewal attempt returns")
    }

    async fn renew_once(
        &self,
        details: &ConnectionDetails,
        expected_uid: &mut Option<String>,
    ) -> Result<PeerIdentity> {
        let mut connector = self.owned_connector().await?;
        let uid = string(&connector, "/metadata/uid")?;
        if expected_uid
            .as_ref()
            .is_some_and(|expected| expected != &uid)
        {
            return Err(Error::Ownership(
                "Connector was replaced during renewal".into(),
            ));
        }
        *expected_uid = Some(uid);
        let old_key = connector
            .pointer("/status/connectionDetails/publicKey/id")
            .and_then(Value::as_str);
        if old_key.is_some_and(|key| key != self.public_key) {
            return Err(Error::Ownership(self.name.clone()));
        }
        connector["status"]["connectionDetails"] = json!({"type":"PublicKey","publicKey":{"id":self.public_key,"discoveryMode":"DNS","homeRelay":details.relay_url,"addresses":details.addresses.iter().map(|addr| json!({"address":addr.ip().to_string(),"port":addr.port()})).collect::<Vec<_>>()}});
        let updated = self
            .request(
                Method::PUT,
                &format!("{}/status", self.resource("connectors", &self.name)),
                Some(&connector),
            )
            .await?
            .ok_or(Error::Api(500))?;
        self.renew_connect_connector_lease(&updated).await?;
        if let Some(connector) = self.connect_get("connectors", &self.name).await?
            && connector.pointer("/spec/publicKey").and_then(Value::as_str)
                != Some(self.public_key.as_str())
        {
            return Err(Error::Ownership(self.name.clone()));
        }
        self.identity(&updated)
    }

    pub async fn resolve_peer(&self, name_or_key: &str) -> Result<PeerIdentity> {
        let Ok(key) = name_or_key.parse::<iroh::EndpointId>() else {
            validate_name(name_or_key)?;
            let value = self
                .connect_get("connectors", name_or_key)
                .await?
                .ok_or(Error::Api(404))?;
            return self.connect_peer_identity(&value);
        };
        let public_key = key.to_string();
        let connect_list_url = format!(
            "{}/apis/{CONNECT_GROUP}/namespaces/default/connectors",
            self.base
        );
        let connect_list = self
            .request(Method::GET, &connect_list_url, None)
            .await?
            .ok_or(Error::Api(404))?;
        if connect_list
            .pointer("/metadata/continue")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            return Err(Error::Invalid(
                "Connect Connector discovery is paginated; cannot safely resolve a public key"
                    .into(),
            ));
        }
        let connect_matches: Vec<_> = connect_list["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|value| {
                value.pointer("/spec/publicKey").and_then(Value::as_str)
                    == Some(public_key.as_str())
            })
            .collect();
        let matches = connect_matches;
        match matches.as_slice() {
            [value] => self.connect_peer_identity(value),
            [] => Err(Error::Api(404)),
            _ => Err(Error::Invalid("multiple Connect Connectors advertise this public key; resolve the duplicate identities before connecting".into())),
        }
    }

    /// Default private access includes project devices, excluding approved gateway
    /// keys and all aliases of those keys. An explicit allowlist can opt a gateway
    /// back in; doing so can expose the service through that gateway's ingress.
    pub async fn private_peers(&self) -> Result<Vec<PeerIdentity>> {
        let mut gateway_keys = HashSet::new();
        for name in self.gateway_names().await? {
            let gateway = self.resolve_peer(&name).await?;
            gateway_keys.insert(
                gateway
                    .public_key
                    .parse::<iroh::EndpointId>()
                    .map_err(|_| {
                        Error::Invalid("control plane returned invalid gateway public key".into())
                    })?,
            );
        }
        let list_url = format!(
            "{}/apis/{CONNECT_GROUP}/namespaces/default/connectors",
            self.base
        );
        let list = self
            .request(Method::GET, &list_url, None)
            .await?
            .ok_or(Error::Api(404))?;
        if list
            .pointer("/metadata/continue")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return Err(Error::Unsupported(
                "paginated Connect Connector discovery requires an explicit allowlist".into(),
            ));
        }
        let mut peers = Vec::new();
        for item in list["items"]
            .as_array()
            .ok_or_else(|| Error::Invalid("Connector list lacks items".into()))?
        {
            if item.pointer("/metadata/name").and_then(Value::as_str) == Some(self.name.as_str())
                || !current_condition(item, "Ready")
                || !item["metadata"]["deletionTimestamp"].is_null()
            {
                continue;
            }
            // Pending enrollment has no usable identity yet.
            if item.pointer("/spec/publicKey").is_none() {
                continue;
            }
            let identity = self.connect_peer_identity(item)?;
            let key = identity
                .public_key
                .parse::<iroh::EndpointId>()
                .map_err(|_| Error::Invalid("control plane returned invalid public key".into()))?;
            if !gateway_keys.contains(&key) {
                peers.push(identity);
            }
        }
        Ok(peers)
    }

    /// Gateway identities are explicitly approved by the platform-owned class.
    /// This annotation is part of the new MASQUE deployment contract; older
    /// classes cannot accidentally turn a private destination into an open proxy.
    pub async fn public_peers(&self) -> Result<Vec<PeerIdentity>> {
        let names = self.gateway_names().await?;
        if names.is_empty() {
            return Err(Error::Unsupported(
                "ConnectorClass has no approved MASQUE gateway identities".into(),
            ));
        }
        let mut peers = Vec::new();
        for name in names {
            peers.push(self.resolve_peer(&name).await?);
        }
        Ok(peers)
    }

    /// Missing approval means no gateways. Malformed approval cannot silently
    /// become an empty set, which would broaden the default private policy.
    async fn gateway_names(&self) -> Result<Vec<String>> {
        let connector = self.owned_connect_connector().await?;
        let class = string(&connector, "/spec/classRef")?;
        validate_name(&class)?;
        let url = format!(
            "{}/apis/{CONNECT_GROUP}/connectorclasses/{class}",
            self.base
        );
        let class = self
            .request(Method::GET, &url, None)
            .await?
            .ok_or(Error::Api(404))?;
        let Some(annotation) = class["metadata"]["annotations"].get(GATEWAYS) else {
            return Ok(Vec::new());
        };
        let raw = annotation.as_str().ok_or_else(|| {
            Error::Invalid("gateway-connectors annotation must be a JSON-array string".into())
        })?;
        let names: Vec<String> = serde_json::from_str(raw).map_err(|_| {
            Error::Invalid(
                "gateway-connectors annotation must contain a JSON array of Connector names".into(),
            )
        })?;
        if names.len() > 32 {
            return Err(Error::Unsupported(
                "approved gateway list must contain at most 32 Connectors".into(),
            ));
        }
        for name in &names {
            validate_name(name)?;
        }
        Ok(names)
    }

    fn metadata(&self, name: &str, connector: &Value) -> Result<Value> {
        Ok(
            json!({"name":name,"labels":{(OWNER):self.name},"ownerReferences":[{"apiVersion":CONNECT_GROUP,"kind":"Connector","name":self.name,"uid":string(connector,"/metadata/uid")?,"controller":true,"blockOwnerDeletion":false}]}),
        )
    }

    fn check_owner(&self, name: &str, object: &Value, connector: &Value) -> Result<()> {
        let uid = string(connector, "/metadata/uid")?;
        if object["metadata"]["labels"][OWNER] != self.name
            || !object["metadata"]["ownerReferences"]
                .as_array()
                .is_some_and(|refs| {
                    refs.iter().any(|owner| {
                        owner["uid"] == uid
                            && owner["name"] == self.name
                            && owner["kind"] == "Connector"
                    })
                })
        {
            return Err(Error::Ownership(name.into()));
        }
        Ok(())
    }

    async fn apply_owned(&self, plural: &str, object: Value, connector: &Value) -> Result<Value> {
        let name = string(&object, "/metadata/name")?;
        let existing = match self.get(plural, &name).await? {
            Some(value) => value,
            None => self.create(plural, &object).await?,
        };
        self.check_owner(&name, &existing, connector)?;
        // No overwrite of administrator edits or foreign fields. Explicitly
        // report conflicts so the caller can resolve ownership intent.
        if !contains_intent(&existing["spec"], &object["spec"]) {
            return Err(Error::Ownership(format!(
                "{name}: existing spec differs; refusing overwrite"
            )));
        }
        Ok(existing)
    }

    async fn apply_connect_owned(
        &self,
        plural: &str,
        object: Value,
        connector: &Value,
    ) -> Result<Value> {
        let name = string(&object, "/metadata/name")?;
        let existing = match self.connect_get(plural, &name).await? {
            Some(value) => value,
            None => self.connect_create(plural, &object).await?,
        };
        self.check_owner(&name, &existing, connector)?;
        if !contains_intent(&existing["spec"], &object["spec"]) {
            return Err(Error::Ownership(format!(
                "{name}: existing spec differs; refusing overwrite"
            )));
        }
        Ok(existing)
    }

    pub async fn reconcile_service(&self, intent: &ServiceIntent) -> Result<CloudService> {
        validate_name(&intent.name)?;
        if !matches!(intent.protocol.as_str(), "tcp" | "udp") {
            return Err(Error::Invalid("protocol must be tcp or udp".into()));
        }
        if intent.public && intent.protocol != "tcp" {
            return Err(Error::Invalid("public HTTP ingress requires TCP".into()));
        }
        if !intent.public && intent.hostname.is_some() {
            return Err(Error::Invalid("hostname requires public exposure".into()));
        }
        let endpoint = url::Url::parse(&format!("tcp://{}", intent.endpoint))
            .map_err(|_| Error::Invalid("expected host:port endpoint".into()))?;
        if !matches!(endpoint.path(), "" | "/")
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(Error::Invalid("expected host:port endpoint".into()));
        }
        let _host = endpoint
            .host_str()
            .ok_or_else(|| Error::Invalid("endpoint host missing".into()))?;
        let port = endpoint
            .port()
            .filter(|p| *p != 0)
            .ok_or_else(|| Error::Invalid("endpoint port missing".into()))?;
        let connector = self.owned_connect_connector().await?;
        if !intent.public && self.get("httpproxies", &intent.name).await?.is_some() {
            return Err(Error::Invalid("a public ingress already uses this service name; explicitly remove it before creating a private service".into()));
        }
        let metadata = self.metadata(&intent.name, &connector)?;
        self.apply_connect_owned("connectoradvertisements",json!({"apiVersion":CONNECT_GROUP,"kind":"ConnectorAdvertisement","metadata":metadata,"spec":{"connectorRef":self.name,"services":[{"protocol":intent.protocol.to_uppercase(),"port":port}]}}),&connector).await?;
        if !intent.public {
            return Ok(CloudService {
                name: intent.name.clone(),
                hostnames: vec![],
                ready: true,
            });
        }
        let mut spec = json!({"rules":[{"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"backends":[{"endpoint":format!("http://{}",intent.endpoint),"connector":{"name":self.name}}]}]});
        if let Some(hostname) = &intent.hostname {
            spec["hostnames"] = json!([hostname]);
        }
        // HTTPProxy remains an NSO ingress resource. Its metadata ownership is
        // tied to the Connect Connector UID so cleanup cannot affect another device.
        let proxy = self.apply_owned("httpproxies",json!({"apiVersion":"networking.datumapis.com/v1alpha","kind":"HTTPProxy","metadata":metadata,"spec":spec}),&connector).await?;
        let hostnames = proxy
            .pointer("/status/hostnames")
            .or_else(|| proxy.pointer("/spec/hostnames"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let ready = ["Accepted", "Programmed", "CertificatesReady"]
            .iter()
            .all(|condition| current_condition(&proxy, condition));
        Ok(CloudService {
            name: intent.name.clone(),
            hostnames,
            ready,
        })
    }

    pub async fn delete_service(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let connector = self.owned_connect_connector().await?;
        let mut first_error = None;
        for plural in ["httpproxies", "connectoradvertisements"] {
            let result = async {
                let is_connect_resource = plural == "connectoradvertisements";
                let resource = if is_connect_resource {
                    self.connect_get(plural, name).await?
                } else {
                    self.get(plural, name).await?
                };
                if let Some(resource) = resource {
                    self.check_owner(name,&resource,&connector)?;
                    let preconditions = json!({"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":string(&resource,"/metadata/uid")?,"resourceVersion":string(&resource,"/metadata/resourceVersion")?}});
                    let url = if is_connect_resource { self.connect_resource(plural, name) } else { self.resource(plural, name) };
                    match self.request(Method::DELETE,&url,Some(&preconditions)).await { Ok(_) | Err(Error::Api(404)) => {}, Err(error) => return Err(error) }
                }
                Ok(())
            }.await;
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn string(value: &Value, path: &str) -> Result<String> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid(format!("control-plane response lacks {path}")))
}

fn current_condition(resource: &Value, kind: &str) -> bool {
    let Some(generation) = resource
        .pointer("/metadata/generation")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
    else {
        return false;
    };
    resource
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition["type"] == kind
                    && condition["status"] == "True"
                    && condition["observedGeneration"].as_u64() == Some(generation)
            })
        })
}

fn network_binding_name(network: &str, connector: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(network.as_bytes());
    digest.update([0]);
    digest.update(connector.as_bytes());
    let hash = digest.finalize();
    format!(
        "binding-{}",
        hash[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

// Admission may insert defaults. Compare every field we own, without treating
// additional server fields as drift or removing them during reconciliation.
fn contains_intent(actual: &Value, desired: &Value) -> bool {
    match (actual, desired) {
        (Value::Object(a), Value::Object(d)) => d
            .iter()
            .all(|(key, value)| a.get(key).is_some_and(|a| contains_intent(a, value))),
        (Value::Array(a), Value::Array(d)) => {
            a.len() == d.len() && a.iter().zip(d).all(|(a, d)| contains_intent(a, d))
        }
        _ => actual == desired,
    }
}

fn validate_name(name: &str) -> Result<()> {
    crate::TunnelId::try_from(name).map_err(|_| Error::Invalid("invalid resource name".into()))?;
    Ok(())
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    #[test]
    fn rejects_unsafe_credential_destinations() {
        for url in [
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com?token=secret",
            "file:///tmp/token",
        ] {
            assert!(validate_url(url).is_err());
        }
        assert!(validate_url("https://api.datum.net").is_ok());
        assert!(validate_url("http://127.0.0.1:1234").is_ok());
    }
    #[test]
    fn rejects_resource_path_traversal() {
        for name in ["../other", "a/b", "", "a?x=y"] {
            assert!(validate_name(name).is_err());
        }
    }
}
