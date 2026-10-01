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
use std::{collections::HashSet, net::SocketAddr, time::Duration};

pub type Result<T> = std::result::Result<T, Error>;
const GROUP: &str = "networking.datumapis.com/v1alpha1";
const OWNER: &str = "connect.datum.net/connector";
const PROTOCOL: &str = "connect.datum.net/transport";
const GATEWAYS: &str = "connect.datum.net/gateway-connectors";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("credential exchange rejected (HTTP {0})")]
    Authentication(u16),
    #[error("control plane rejected request (HTTP {0})")]
    Api(u16),
    #[error("resource is not owned by this Connector: {0}")]
    Ownership(String),
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
                return Err(Error::Api(response.status().as_u16()));
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
        let mut connector = self.owned_connector().await?;
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
        if let Some(lease) = updated
            .pointer("/status/leaseRef/name")
            .and_then(Value::as_str)
        {
            validate_name(lease)?;
            let lease_url = format!(
                "{}/apis/coordination.k8s.io/v1/namespaces/default/leases/{lease}",
                self.base
            );
            if let Some(mut resource) = self.request(Method::GET, &lease_url, None).await? {
                resource["spec"]["renewTime"] = json!(chrono::Utc::now().to_rfc3339());
                self.request(Method::PUT, &lease_url, Some(&resource))
                    .await?;
            }
        }
        self.identity(&updated)
    }

    pub async fn resolve_peer(&self, name_or_key: &str) -> Result<PeerIdentity> {
        let Ok(key) = name_or_key.parse::<iroh::EndpointId>() else {
            validate_name(name_or_key)?;
            let value = self
                .get("connectors", name_or_key)
                .await?
                .ok_or(Error::Api(404))?;
            return self.identity(&value);
        };
        let public_key = key.to_string();
        let legacy_name = format!("connect-{}", &public_key[..40]);
        if let Some(value) = self.get("connectors", &legacy_name).await? {
            let identity = self.identity(&value)?;
            if identity.public_key != public_key {
                return Err(Error::Ownership(legacy_name));
            }
            return Ok(identity);
        }
        // Named devices no longer have a key-derived resource name. Resolve by
        // exact key, never a hostname/address, and reject ambiguous/incomplete lists.
        let list = self
            .request(Method::GET, &self.resource("connectors", ""), None)
            .await?
            .ok_or(Error::Api(404))?;
        if list
            .pointer("/metadata/continue")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
        {
            return Err(Error::Invalid(
                "Connector discovery is paginated; cannot safely resolve a public key".into(),
            ));
        }
        let matches: Vec<_> = list["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| {
                v.pointer("/status/connectionDetails/publicKey/id")
                    .and_then(Value::as_str)
                    == Some(public_key.as_str())
            })
            .collect();
        match matches.as_slice() {
            [value] => self.identity(value),
            [] => Err(Error::Api(404)),
            _ => Err(Error::Invalid("multiple Connectors advertise this public key; resolve the duplicate identities before connecting".into())),
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
        let list = self
            .request(Method::GET, &self.resource("connectors", ""), None)
            .await?
            .ok_or(Error::Api(404))?;
        if list
            .pointer("/metadata/continue")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return Err(Error::Unsupported(
                "paginated Connector discovery requires an explicit allowlist".into(),
            ));
        }
        let mut peers = Vec::new();
        for item in list["items"]
            .as_array()
            .ok_or_else(|| Error::Invalid("Connector list lacks items".into()))?
        {
            if item["metadata"]["annotations"][PROTOCOL] != "masque-v1"
                || !item["metadata"]["deletionTimestamp"].is_null()
            {
                continue;
            }
            // Pending enrollment has no usable identity yet.
            if item
                .pointer("/status/connectionDetails/publicKey/id")
                .is_none()
            {
                continue;
            }
            let identity = self.identity(item)?;
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
        let connector = self.owned_connector().await?;
        let class = string(&connector, "/spec/connectorClassName")?;
        validate_name(&class)?;
        let url = format!("{}/apis/{GROUP}/connectorclasses/{class}", self.base);
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
            json!({"name":name,"labels":{(OWNER):self.name},"ownerReferences":[{"apiVersion":GROUP,"kind":"Connector","name":self.name,"uid":string(connector,"/metadata/uid")?,"controller":true,"blockOwnerDeletion":false}]}),
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
        let host = endpoint
            .host_str()
            .ok_or_else(|| Error::Invalid("endpoint host missing".into()))?;
        let port = endpoint
            .port()
            .filter(|p| *p != 0)
            .ok_or_else(|| Error::Invalid("endpoint port missing".into()))?;
        let connector = self.owned_connector().await?;
        if !intent.public && self.get("httpproxies", &intent.name).await?.is_some() {
            return Err(Error::Invalid("a public ingress already uses this service name; explicitly remove it before creating a private service".into()));
        }
        let metadata = self.metadata(&intent.name, &connector)?;
        self.apply_owned("connectoradvertisements",json!({"apiVersion":GROUP,"kind":"ConnectorAdvertisement","metadata":metadata,"spec":{"connectorRef":{"name":self.name},"layer4":[{"name":"service","services":[{"address":host,"ports":[{"name":intent.protocol,"port":port,"protocol":intent.protocol.to_uppercase()}]}]}]}}),&connector).await?;
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
        let connector = self.owned_connector().await?;
        let mut first_error = None;
        for plural in ["httpproxies", "connectoradvertisements"] {
            let result = async {
                if let Some(resource) = self.get(plural,name).await? {
                    self.check_owner(name,&resource,&connector)?;
                    let preconditions = json!({"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":string(&resource,"/metadata/uid")?,"resourceVersion":string(&resource,"/metadata/resourceVersion")?}});
                    match self.request(Method::DELETE,&self.resource(plural,name),Some(&preconditions)).await { Ok(_) | Err(Error::Api(404)) => {}, Err(error) => return Err(error) }
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
