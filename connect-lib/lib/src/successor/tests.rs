use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

enum Reply {
    Json(u16, Value),
    EchoCreated,
}

async fn server(replies: Vec<Reply>) -> (String, tokio::task::JoinHandle<Vec<(String, Value)>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            let (header_end, length) = loop {
                let mut buffer = [0; 4096];
                let size = stream.read(&mut buffer).await.unwrap();
                assert_ne!(size, 0);
                bytes.extend_from_slice(&buffer[..size]);
                if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..index]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|s| s.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    break (index + 4, length);
                }
            };
            while bytes.len() < header_end + length {
                let mut buffer = [0; 4096];
                let size = stream.read(&mut buffer).await.unwrap();
                assert_ne!(size, 0);
                bytes.extend_from_slice(&buffer[..size]);
            }
            let first_line = String::from_utf8_lossy(&bytes)
                .lines()
                .next()
                .unwrap()
                .to_string();
            let body = serde_json::from_slice::<Value>(&bytes[header_end..]).unwrap_or(Value::Null);
            let (status, response) = match reply {
                Reply::Json(status, value) => (status, value),
                Reply::EchoCreated => {
                    let mut value = body.clone();
                    value["metadata"]["uid"] = json!("service-uid");
                    value["metadata"]["resourceVersion"] = json!("1");
                    (201, value)
                }
            };
            requests.push((first_line, body));
            let response = response.to_string();
            stream.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    (base, task)
}

fn token() -> Reply {
    Reply::Json(
        200,
        json!({"access_token":"test-secret","token_type":"Bearer","expires_in":3600}),
    )
}

fn client(base: &str) -> CloudConnector {
    let credentials: Credentials = serde_json::from_value(json!({"type":"connector","project_id":"demo","api_endpoint":base,"token_uri":format!("{base}/token"),"client_id":"test","refresh_token":"test-refresh"})).unwrap();
    CloudConnector::new(
        credentials,
        "demo".into(),
        iroh::SecretKey::from_bytes(&[7; 32]).public().to_string(),
    )
    .unwrap()
}

fn connector() -> Value {
    let public = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
    json!({"metadata":{"name":format!("connect-{}",&public[..40]),"uid":"connector-uid","annotations":{"connect.datum.net/public-key":public}},"spec":{"connectorClassName":"masque"},"status":{"connectionDetails":{"publicKey":{"id":public}}}})
}

fn connect_connector() -> Value {
    let public = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
    json!({"metadata":{"name":format!("connect-{}",&public[..40]),"uid":"connector-uid","generation":1},"spec":{"classRef":"masque","publicKey":public},"status":{"conditions":[{"type":"Ready","status":"True","observedGeneration":1}]}})
}

#[test]
fn project_connect_resources_use_the_connect_api_group() {
    let client = client("https://api.example");
    assert!(client
        .connect_resource("connectgateways", "vpc-gateway")
        .ends_with("/apis/connect.datumapis.com/v1alpha1/namespaces/default/connectgateways/vpc-gateway"));
    assert!(
        client
            .connect_resource("connectnetworkbindings", "binding")
            .contains("/projects/demo/control-plane/apis/connect.datumapis.com/v1alpha1/")
    );
    assert!(
        client.resource("connectors", "legacy").contains(
            "/apis/networking.datumapis.com/v1alpha1/namespaces/default/connectors/legacy"
        )
    );
}

#[test]
fn network_binding_name_is_deterministic_and_scoped_to_connector_and_network() {
    let first = network_binding_name("staging-vpc", "macbook");
    assert_eq!(first, network_binding_name("staging-vpc", "macbook"));
    assert_ne!(first, network_binding_name("other-vpc", "macbook"));
    assert_ne!(first, network_binding_name("staging-vpc", "router"));
    assert!(first.len() <= 63);
}

#[tokio::test]
async fn joining_managed_network_creates_connector_owned_binding_and_renews_lease() {
    let peer = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
    let connect_connector = json!({
        "metadata":{"name":format!("connect-{}", &peer[..40]),"uid":"connect-uid","generation":1},
        "spec":{"publicKey":peer},
        "status":{"leaseRef":"connect-lease","conditions":[{"type":"Ready","status":"True","observedGeneration":1}]}
    });
    let gateway = json!({
        "metadata":{"name":"vpc-gateway","generation":2},
        "spec":{"networkRef":"staging-vpc"},
        "status":{"endpointID":iroh::SecretKey::from_bytes(&[9; 32]).public().to_string(),"conditions":[{"type":"Ready","status":"True","observedGeneration":2}]}
    });
    let binding_name = network_binding_name("staging-vpc", &format!("connect-{}", &peer[..40]));
    let created_binding = json!({
        "metadata":{"name":binding_name,"uid":"binding-uid","resourceVersion":"1","generation":1},
        "spec":{"gatewayRef":"vpc-gateway","connectorRef":format!("connect-{}", &peer[..40])},
        "status":{"endpointID":gateway["status"]["endpointID"],"assignedAddress":"fd79::1/128","peerAddress":"fd79::2/128","routes":["fd20:0:27::/48"],"relayURLs":["https://relay.example/"],"conditions":[{"type":"Accepted","status":"True","observedGeneration":1}]}
    });
    let lease = json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"connect-lease","resourceVersion":"4"},"spec":{"leaseDurationSeconds":30}});
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, json!({"items":[gateway]})),
        Reply::Json(200, connect_connector),
        Reply::Json(200, lease),
        Reply::EchoCreated,
        Reply::Json(404, json!({})),
        Reply::Json(201, created_binding.clone()),
    ])
    .await;
    let cloud = client(&base);
    let result = cloud
        .join_gateway_network("staging-vpc", &ConnectionDetails::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["assignedAddress"], "fd79::1/128");
    assert_eq!(result["routes"], json!(["fd20:0:27::/48"]));
    assert_eq!(result["bindingName"], binding_name);
    let requests = task.await.unwrap();
    assert!(requests.iter().any(|(line, body)| {
        line.starts_with("POST ")
            && line.contains("connectnetworkbindings")
            && body["spec"]["gatewayRef"] == "vpc-gateway"
            && body["spec"]["connectorRef"] == cloud.name()
    }));
    assert!(requests.iter().any(|(line, body)| {
        line.starts_with("PUT ")
            && line.contains("/leases/connect-lease")
            && body["metadata"]["resourceVersion"] == "4"
    }));
}

#[tokio::test]
async fn joining_managed_network_waits_for_gateway_readiness_after_a_config_rollout() {
    let peer = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
    let connect_connector = json!({
        "metadata":{"name":format!("connect-{}", &peer[..40]),"uid":"connect-uid","generation":1},
        "spec":{"publicKey":peer},
        "status":{"leaseRef":"connect-lease","conditions":[{"type":"Ready","status":"True","observedGeneration":1}]}
    });
    let endpoint_id = iroh::SecretKey::from_bytes(&[9; 32]).public().to_string();
    let gateway = json!({
        "metadata":{"name":"vpc-gateway","generation":2},
        "spec":{"networkRef":"staging-vpc"},
        "status":{"endpointID":endpoint_id,"conditions":[{"type":"Ready","status":"True","observedGeneration":2}]}
    });
    let mut provisioning = gateway.clone();
    provisioning["status"]["conditions"][0]["status"] = json!("Unknown");
    provisioning["status"]["conditions"][0]["reason"] = json!("WorkloadProvisioning");
    let binding_name = network_binding_name("staging-vpc", &format!("connect-{}", &peer[..40]));
    let created_binding = json!({
        "metadata":{"name":binding_name,"uid":"binding-uid","resourceVersion":"1","generation":1},
        "spec":{"gatewayRef":"vpc-gateway","connectorRef":format!("connect-{}", &peer[..40])},
        "status":{"endpointID":endpoint_id,"assignedAddress":"fd79::1/128","peerAddress":"fd79::2/128","routes":["fd20:0:27::/48"],"relayURLs":["https://relay.example/"],"conditions":[{"type":"Accepted","status":"True","observedGeneration":1}]}
    });
    let lease = json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"connect-lease","resourceVersion":"4"},"spec":{"leaseDurationSeconds":30}});
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, json!({"items":[provisioning]})),
        Reply::Json(200, json!({"items":[gateway]})),
        Reply::Json(200, connect_connector),
        Reply::Json(200, lease),
        Reply::EchoCreated,
        Reply::Json(404, json!({})),
        Reply::Json(201, created_binding),
    ])
    .await;
    let result = client(&base)
        .join_gateway_network("staging-vpc", &ConnectionDetails::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["gateway"], "vpc-gateway");
    assert_eq!(result["assignedAddress"], "fd79::1/128");
    assert_eq!(task.await.unwrap().len(), 8);
}

#[tokio::test]
async fn connect_enrollment_uses_only_the_connect_api() {
    let peer = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
    let class = json!({
        "metadata":{"name":"masque-class","generation":1},
        "spec":{"transports":["masque-v1"]},
        "status":{"conditions":[{"type":"Ready","status":"True","observedGeneration":1}]}
    });
    let connector = json!({
        "metadata":{"name":format!("connect-{}", &peer[..40]),"uid":"connect-uid","generation":1},
        "spec":{"classRef":"masque-class","publicKey":peer,"relayURLs":["https://relay.example/"]},
        "status":{"conditions":[{"type":"Ready","status":"True","observedGeneration":1}]}
    });
    let (base, task) = server(vec![
        token(),
        Reply::Json(404, json!({})),
        Reply::Json(200, json!({"items":[class]})),
        Reply::Json(201, connector),
    ])
    .await;
    let cloud = client(&base);
    let identity = cloud
        .ensure_connect_connector(&ConnectionDetails {
            relay_url: "https://relay.example/".into(),
            addresses: vec![],
        })
        .await
        .unwrap();
    assert_eq!(identity.uid, "connect-uid");
    assert_eq!(identity.public_key, peer);
    let requests = task.await.unwrap();
    assert!(requests.iter().any(|(line, body)| {
        line.starts_with("POST ")
            && line.contains("/apis/connect.datumapis.com/v1alpha1/namespaces/default/connectors/")
            && body["spec"]["classRef"] == "masque-class"
    }));
    assert!(
        requests
            .iter()
            .all(|(line, _)| !line.contains("networking.datumapis.com"))
    );
}

#[tokio::test]
async fn lease_renewal_uses_kubernetes_microtime_precision() {
    let mut value = connector();
    value["status"]["leaseRef"] = json!({"name":"connector-lease"});
    let lease = json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":"connector-lease","resourceVersion":"7"},"spec":{"leaseDurationSeconds":30}});
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, value.clone()),
        Reply::Json(200, value),
        Reply::Json(200, lease),
        Reply::EchoCreated,
        Reply::Json(404, json!({})),
    ])
    .await;
    client(&base)
        .renew(&ConnectionDetails {
            relay_url: "https://relay.example.com/".into(),
            addresses: vec![],
        })
        .await
        .unwrap();
    let requests = task.await.unwrap();
    let renewal = &requests[4];
    assert!(renewal.0.contains("/leases/connector-lease"));
    assert_eq!(renewal.1["metadata"]["resourceVersion"], "7");
    let timestamp = renewal.1["spec"]["renewTime"].as_str().unwrap();
    assert_eq!(timestamp.len(), 27);
    assert!(timestamp.ends_with('Z'));
    assert_eq!(timestamp.split_once('.').unwrap().1.len(), 7);
    chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
}

#[tokio::test]
async fn renewal_retries_conflicts_with_fresh_resource_version_and_preserves_conditions() {
    let mut first = connector();
    first["metadata"]["resourceVersion"] = json!("1");
    let mut fresh = first.clone();
    fresh["metadata"]["resourceVersion"] = json!("2");
    fresh["status"]["conditions"] = json!([{"type":"Accepted","status":"True"}]);
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, first),
        Reply::Json(409, json!({})),
        Reply::Json(200, fresh),
        Reply::EchoCreated,
        Reply::Json(404, json!({})),
    ])
    .await;
    client(&base)
        .renew(&ConnectionDetails {
            relay_url: "https://relay.example.com/".into(),
            addresses: vec![],
        })
        .await
        .unwrap();
    let requests = task.await.unwrap();
    assert_eq!(requests[2].1["metadata"]["resourceVersion"], "1");
    assert_eq!(requests[4].1["metadata"]["resourceVersion"], "2");
    assert_eq!(requests[4].1["status"]["conditions"][0]["type"], "Accepted");
}

#[tokio::test]
async fn renewal_never_retries_into_replaced_connector() {
    let mut replaced = connector();
    replaced["metadata"]["uid"] = json!("replacement");
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connector()),
        Reply::Json(409, json!({})),
        Reply::Json(200, replaced),
    ])
    .await;
    assert!(matches!(
        client(&base).renew(&ConnectionDetails::default()).await,
        Err(Error::Ownership(_))
    ));
    assert_eq!(
        task.await
            .unwrap()
            .iter()
            .filter(|(line, _)| line.starts_with("PUT "))
            .count(),
        1
    );
}

#[tokio::test]
async fn renewal_conflict_retries_are_bounded() {
    let mut replies = vec![token()];
    for _ in 0..4 {
        replies.push(Reply::Json(200, connector()));
        replies.push(Reply::Json(409, json!({})));
    }
    let (base, task) = server(replies).await;
    assert!(matches!(
        client(&base).renew(&ConnectionDetails::default()).await,
        Err(Error::Api(409))
    ));
    assert_eq!(task.await.unwrap().len(), 9);
}

#[tokio::test]
async fn validation_error_exposes_field_not_rejected_values() {
    let (base, task) = server(vec![token(), Reply::Json(200, connector()), Reply::Json(422, json!({"reason":"Invalid","message":"secret-do-not-print", "details":{"causes":[{"field":"status.connectionDetails.publicKey.homeRelay","message":"secret-do-not-print"}]}}))]).await;
    let error = client(&base)
        .renew(&ConnectionDetails::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("status.connectionDetails.publicKey.homeRelay"));
    assert!(error.contains("PUT"));
    assert!(error.contains("HTTP 422"));
    assert!(!error.contains("secret-do-not-print"));
    assert_eq!(task.await.unwrap().len(), 3);
}

#[tokio::test]
async fn named_connector_is_resolved_by_name_and_by_exact_public_key() {
    let mut named = connector();
    named["metadata"]["name"] = json!("alice-mac");
    let key = named["status"]["connectionDetails"]["publicKey"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, named.clone()),
        Reply::Json(404, json!({})),
        Reply::Json(200, json!({"items":[named]})),
    ])
    .await;
    let client = client(&base);
    assert_eq!(
        client.resolve_peer("alice-mac").await.unwrap().public_key,
        key
    );
    assert_eq!(client.resolve_peer(&key).await.unwrap().name, "alice-mac");
    assert_eq!(task.await.unwrap().len(), 4);
}

#[tokio::test]
async fn reused_name_cannot_resolve_a_previously_pinned_key() {
    let mut reused = connector();
    reused["metadata"]["name"] = json!("alice-mac");
    let old_key = reused["status"]["connectionDetails"]["publicKey"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    reused["status"]["connectionDetails"]["publicKey"]["id"] =
        json!(iroh::SecretKey::from_bytes(&[8; 32]).public().to_string());
    let (base, task) = server(vec![
        token(),
        Reply::Json(404, json!({})),
        Reply::Json(200, json!({"items":[reused]})),
    ])
    .await;
    assert!(matches!(
        client(&base).resolve_peer(&old_key).await,
        Err(Error::Api(404))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn named_connector_collision_never_updates_foreign_identity() {
    let mut foreign = connector();
    foreign["metadata"]["name"] = json!("alice-mac");
    foreign["metadata"]["annotations"]["connect.datum.net/public-key"] =
        json!(iroh::SecretKey::from_bytes(&[8; 32]).public().to_string());
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, foreign.clone()),
        Reply::Json(200, foreign),
    ])
    .await;
    let client = client(&base).with_name("alice-mac").unwrap();
    assert!(matches!(
        client.ensure_connector(&ConnectionDetails::default()).await,
        Err(Error::Ownership(_))
    ));
    assert!(
        task.await
            .unwrap()
            .iter()
            .all(|(request, _)| !request.starts_with("PUT"))
    );
}

#[tokio::test]
async fn ambiguous_key_discovery_fails_closed() {
    let value = connector();
    let key = value["status"]["connectionDetails"]["publicKey"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (base, task) = server(vec![
        token(),
        Reply::Json(404, json!({})),
        Reply::Json(200, json!({"items":[value.clone(),value]})),
    ])
    .await;
    assert!(matches!(
        client(&base).resolve_peer(&key).await,
        Err(Error::Invalid(_))
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn legacy_platform_fails_closed_before_connector_creation() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(404, json!({})),
        Reply::Json(200, json!({"items":[{"metadata":{"name":"legacy"}}]})),
    ])
    .await;
    let result = client(&base)
        .ensure_connector(&ConnectionDetails::default())
        .await;
    assert!(matches!(result, Err(Error::Unsupported(_))));
    let requests = task.await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|(line, _)| line.starts_with("POST ") && line.contains("connectors"))
    );
}

#[tokio::test]
async fn private_service_creates_owned_advertisement_and_never_public_ingress() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connect_connector()),
        Reply::Json(404, json!({})),
        Reply::Json(404, json!({})),
        Reply::EchoCreated,
    ])
    .await;
    let cloud = client(&base);
    let result = cloud
        .reconcile_service(&ServiceIntent {
            name: "ssh-22".into(),
            endpoint: "localhost:22".into(),
            public: false,
            hostname: None,
            protocol: "tcp".into(),
        })
        .await
        .unwrap();
    assert!(result.ready);
    assert!(result.hostnames.is_empty());
    let requests = task.await.unwrap();
    assert!(requests.iter().all(|(line, _)| {
        !line.contains("networking.datumapis.com/v1alpha1/namespaces/default/connectors/")
    }));
    assert!(
        !requests
            .iter()
            .any(|(line, _)| line.starts_with("POST ") && line.contains("httpproxies"))
    );
    let (_, ad) = requests.last().unwrap();
    assert_eq!(ad["metadata"]["labels"][OWNER], cloud.name());
    assert_eq!(ad["metadata"]["ownerReferences"][0]["uid"], "connector-uid");
    assert_eq!(ad["apiVersion"], CONNECT_GROUP);
    assert_eq!(ad["spec"]["connectorRef"], cloud.name());
    assert_eq!(ad["spec"]["services"][0]["protocol"], "TCP");
    assert_eq!(ad["spec"]["services"][0]["port"], 22);
}

#[tokio::test]
async fn deleting_foreign_resource_never_sends_delete() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connect_connector()),
        Reply::Json(200, json!({"metadata":{"name":"foreign","uid":"other"}})),
    ])
    .await;
    assert!(matches!(
        client(&base).delete_service("foreign").await,
        Err(Error::Ownership(_))
    ));
    let requests = task.await.unwrap();
    assert!(!requests.iter().any(|(line, _)| line.starts_with("DELETE ")));
}

#[tokio::test]
async fn refusing_private_reuse_of_public_name_prevents_false_privacy_claim() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connect_connector()),
        Reply::Json(200, json!({"metadata":{"name":"web"}})),
    ])
    .await;
    let result = client(&base)
        .reconcile_service(&ServiceIntent {
            name: "web".into(),
            endpoint: "localhost:80".into(),
            public: false,
            hostname: None,
            protocol: "tcp".into(),
        })
        .await;
    assert!(matches!(result, Err(Error::Invalid(_))));
    assert_eq!(task.await.unwrap().len(), 3);
}

#[test]
fn server_defaults_do_not_look_like_user_edits() {
    assert!(contains_intent(
        &json!({"rules":[{"port":80,"weight":1}]}),
        &json!({"rules":[{"port":80}]})
    ));
    assert!(!contains_intent(
        &json!({"rules":[{"port":81}]}),
        &json!({"rules":[{"port":80}]})
    ));
}

#[test]
fn readiness_requires_current_observed_generation() {
    assert!(!current_condition(
        &json!({"status":{"conditions":[{"type":"Programmed","status":"True"}]}}),
        "Programmed"
    ));
    assert!(!current_condition(
        &json!({"metadata":{"generation":2},"status":{"conditions":[{"type":"Programmed","status":"True","observedGeneration":1}]}}),
        "Programmed"
    ));
    assert!(current_condition(
        &json!({"metadata":{"generation":2},"status":{"conditions":[{"type":"Programmed","status":"True","observedGeneration":2}]}}),
        "Programmed"
    ));
}

#[tokio::test]
async fn rotating_refresh_token_is_persisted_before_reuse() {
    let (base, task) = server(vec![Reply::Json(200,json!({"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated-secret"}))]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let input = json!({"type":"connector","project_id":"demo","api_endpoint":base,"token_uri":format!("{base}/token"),"client_id":"test","refresh_token":"original-secret"});
    crate::repo::atomic_write_private(&path, &serde_json::to_vec(&input).unwrap())
        .await
        .unwrap();
    let credentials = Credentials::load(&path).await.unwrap();
    assert!(!format!("{credentials:?}").contains("original-secret"));
    let provider = TokenProvider::new(credentials, reqwest::Client::new());
    assert_eq!(provider.token().await.unwrap(), "access");
    assert_eq!(provider.token().await.unwrap(), "access");
    assert_eq!(task.await.unwrap().len(), 1);
    assert_eq!(
        Credentials::load(&path).await.unwrap().refresh_token,
        "rotated-secret"
    );
}

#[tokio::test]
async fn unauthorized_control_plane_response_refreshes_once() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(401, json!({})),
        token(),
        Reply::Json(200, connector()),
    ])
    .await;
    let cloud = client(&base);
    cloud.resolve_peer(cloud.name()).await.unwrap();
    assert_eq!(task.await.unwrap().len(), 4);
}

#[tokio::test]
async fn private_discovery_ignores_legacy_and_terminating_connectors() {
    let mut eligible = connector();
    eligible["metadata"]["annotations"][PROTOCOL] = json!("masque-v1");
    let mut terminating = eligible.clone();
    terminating["metadata"]["deletionTimestamp"] = json!("2026-09-30T00:00:00Z");
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connector()),
        Reply::Json(200, json!({"metadata":{"annotations":{}}})),
        Reply::Json(200, json!({"items":[connector(),eligible,terminating]})),
    ])
    .await;
    assert_eq!(client(&base).private_peers().await.unwrap().len(), 1);
    task.await.unwrap();
}

#[tokio::test]
async fn default_private_scope_excludes_approved_gateway_key_and_aliases() {
    let mut device = connector();
    device["metadata"]["annotations"][PROTOCOL] = json!("masque-v1");
    let mut gateway = device.clone();
    gateway["metadata"]["name"] = json!("approved-gateway");
    let key = iroh::SecretKey::from_bytes(&[8; 32]).public().to_string();
    gateway["status"]["connectionDetails"]["publicKey"]["id"] = json!(key);
    let mut alias = gateway.clone();
    alias["metadata"]["name"] = json!("gateway-alias");
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connector()),
        Reply::Json(
            200,
            json!({"metadata":{"annotations":{(GATEWAYS):"[\"approved-gateway\"]"}}}),
        ),
        Reply::Json(200, gateway.clone()),
        Reply::Json(200, json!({"items":[device.clone(),gateway,alias]})),
    ])
    .await;
    let peers = client(&base).private_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, device["metadata"]["name"]);
    let requests = task.await.unwrap();
    assert!(requests[3].0.contains("connectors/approved-gateway"));
}

#[tokio::test]
async fn malformed_gateway_approval_fails_closed_before_private_discovery() {
    for annotation in [
        json!(null),
        json!(42),
        json!("invalid"),
        json!("{}"),
        json!("[\"invalid/name\"]"),
        json!(serde_json::to_string(&vec!["gateway"; 33]).unwrap()),
    ] {
        let (base, task) = server(vec![
            token(),
            Reply::Json(200, connector()),
            Reply::Json(
                200,
                json!({"metadata":{"annotations":{(GATEWAYS):annotation}}}),
            ),
        ])
        .await;
        assert!(client(&base).private_peers().await.is_err(), "{annotation}");
        assert_eq!(task.await.unwrap().len(), 3);
    }
}

#[tokio::test]
async fn unresolved_gateway_approval_fails_closed_before_private_discovery() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connector()),
        Reply::Json(
            200,
            json!({"metadata":{"annotations":{(GATEWAYS):"[\"missing-gateway\"]"}}}),
        ),
        Reply::Json(404, json!({})),
    ])
    .await;
    assert!(matches!(
        client(&base).private_peers().await,
        Err(Error::Api(404))
    ));
    assert_eq!(task.await.unwrap().len(), 4);
}

#[tokio::test]
async fn public_scope_still_resolves_only_approved_gateway_identities() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connector()),
        Reply::Json(
            200,
            json!({"metadata":{"annotations":{(GATEWAYS):"[\"approved-gateway\"]"}}}),
        ),
        Reply::Json(200, connector()),
    ])
    .await;
    assert_eq!(client(&base).public_peers().await.unwrap().len(), 1);
    assert_eq!(task.await.unwrap().len(), 4);
}

#[tokio::test]
async fn absent_gateway_approval_does_not_enable_public_access() {
    let (base, task) = server(vec![
        token(),
        Reply::Json(200, connector()),
        Reply::Json(200, json!({"metadata":{"annotations":{}}})),
    ])
    .await;
    assert!(matches!(
        client(&base).public_peers().await,
        Err(Error::Unsupported(_))
    ));
    assert_eq!(task.await.unwrap().len(), 3);
}
