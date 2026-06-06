pub type Hostname = String;
pub type SectionName = String;

pub type GatewayStatusAddress = Vec<String>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorReference {
    pub name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HTTPProxyRuleBackend {
    pub endpoint: String,
    pub connector: Option<ConnectorReference>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HTTPProxyRule {
    pub name: Option<SectionName>,
    pub matches: Vec<String>,
    pub backends: Option<Vec<HTTPProxyRuleBackend>>,
}

#[derive(kube::CustomResource, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[kube(
    group = "networking.datumapis.com",
    version = "v1alpha",
    kind = "HTTPProxy",
    plural = "httpproxies",
    namespaced,
    status = "HTTPProxyStatus",
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct HTTPProxySpec {
    pub hostnames: Option<Vec<Hostname>>,
    pub rules: Vec<HTTPProxyRule>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HTTPProxyStatus {
    pub addresses: Option<Vec<GatewayStatusAddress>>,
    pub hostnames: Option<Vec<Hostname>>,
}

pub const HTTP_PROXY_CONDITION_ACCEPTED: &str = "Accepted";
pub const HTTP_PROXY_CONDITION_PROGRAMMED: &str = "Programmed";
pub const HTTP_PROXY_CONDITION_HOSTNAMES_VERIFIED: &str = "HostnamesVerified";
pub const HTTP_PROXY_CONDITION_HOSTNAMES_IN_USE: &str = "HostnamesInUse";

pub const HTTP_PROXY_REASON_ACCEPTED: &str = "Accepted";
pub const HTTP_PROXY_REASON_PROGRAMMED: &str = "Programmed";
pub const HTTP_PROXY_REASON_CONFLICT: &str = "Conflict";
pub const HTTP_PROXY_REASON_PENDING: &str = "Pending";
