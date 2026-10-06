use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::CustomResource;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "connect.datumapis.com",
    version = "v1alpha1",
    kind = "ConnectorClass",
    plural = "connectorclasses",
    status = "ConnectorClassStatus",
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorClassSpec {
    #[serde(default)]
    pub transports: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorClassStatus {
    #[serde(default)]
    pub observed_generation: i64,
    #[serde(default)]
    pub conditions: Vec<metav1::Condition>,
}
