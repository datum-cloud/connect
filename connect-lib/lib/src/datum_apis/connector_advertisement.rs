use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::CustomResource;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisedService {
    pub protocol: String,
    pub port: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
}

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "connect.datumapis.com",
    version = "v1alpha1",
    kind = "ConnectorAdvertisement",
    plural = "connectoradvertisements",
    namespaced,
    status = "ConnectorAdvertisementStatus",
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorAdvertisementSpec {
    pub connector_ref: String,
    #[serde(default)]
    pub services: Vec<AdvertisedService>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorAdvertisementStatus {
    #[serde(default)]
    pub observed_generation: i64,
    #[serde(default)]
    pub conditions: Vec<metav1::Condition>,
}

pub const CONNECTOR_ADVERTISEMENT_CONDITION_ACCEPTED: &str = "Accepted";
pub const CONNECTOR_ADVERTISEMENT_REASON_ACCEPTED: &str = "Accepted";
pub const CONNECTOR_ADVERTISEMENT_REASON_PENDING: &str = "Pending";
pub const CONNECTOR_ADVERTISEMENT_REASON_CONNECTOR_NOT_FOUND: &str = "ConnectorNotFound";
