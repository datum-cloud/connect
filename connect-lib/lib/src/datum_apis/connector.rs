use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::CustomResource;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "connect.datumapis.com",
    version = "v1alpha1",
    kind = "Connector",
    plural = "connectors",
    namespaced,
    status = "ConnectorStatus",
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorSpec {
    pub class_ref: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(rename = "relayURLs", default, skip_serializing_if = "Vec::is_empty")]
    pub relay_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorStatus {
    #[serde(default)]
    pub observed_generation: i64,
    #[serde(default)]
    pub conditions: Vec<metav1::Condition>,
    #[serde(default)]
    pub assigned_addresses: Vec<String>,
    #[serde(default)]
    pub lease_ref: String,
}

pub const CONNECTOR_CONDITION_READY: &str = "Ready";

#[cfg(test)]
mod tests {
    use super::ConnectorSpec;

    #[test]
    fn spec_uses_the_connect_api_field_names() {
        let spec = ConnectorSpec {
            class_ref: "masque".into(),
            public_key: "ab".repeat(32),
            endpoint: "serialized-endpoint".into(),
            relay_urls: vec!["https://relay.example/".into()],
        };
        let value = serde_json::to_value(spec).unwrap();
        assert_eq!(value["classRef"], "masque");
        assert_eq!(value["publicKey"], "ab".repeat(32));
        assert_eq!(value["relayURLs"][0], "https://relay.example/");
        assert!(value.get("relayUrls").is_none());
    }
}
