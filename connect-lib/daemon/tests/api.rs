use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use axum::http::StatusCode;
use datum_connect_daemon::{
    api::{self, AppState},
    auth,
    control::{Control, PingResult, ServiceOutcome},
    error::ApiError,
    model::{ConnectorState, DialState, ManagedNetworkState, Protocol, ServiceState},
    store::Store,
};
use serde_json::{Value, json};

#[derive(Default)]
struct MockControl {
    up_calls: AtomicUsize,
    resume_failures: AtomicUsize,
    service_calls: AtomicUsize,
    fail_service: AtomicBool,
    fail_dial: AtomicBool,
    fail_network: AtomicBool,
    approval_required: AtomicBool,
    network_calls: AtomicUsize,
}

#[async_trait]
impl Control for MockControl {
    async fn prepare_network(
        &self,
        project: &str,
        request: &datum_connect_daemon::networking::PrepareRequest,
    ) -> Result<datum_connect_daemon::peer_ip::Binding, ApiError> {
        let local = iroh::SecretKey::from_bytes(&[1; 32]).public().to_string();
        datum_connect_daemon::networking::binding(project, &local, &request.peer, request)
    }
    async fn resolve_peer_key(&self, _project: &str, peer: &str) -> Result<String, ApiError> {
        if peer == "friendly-peer" {
            return Ok("pinned-peer-key".into());
        }
        Ok(peer.to_owned())
    }
    async fn validate_credentials(&self, _credentials_file: &str) -> Result<(), ApiError> {
        Ok(())
    }
    async fn up(&self, project: &str, _credentials_file: &str) -> Result<ConnectorState, ApiError> {
        self.up_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectorState {
            name: format!("connect-{project}"),
            uid: "uid-1".into(),
            public_key: "key-1".into(),
        })
    }
    async fn resume(
        &self,
        project: &str,
        _credentials_file: &str,
        expected: &ConnectorState,
    ) -> Result<ConnectorState, ApiError> {
        self.up_calls.fetch_add(1, Ordering::SeqCst);
        if self
            .resume_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "simulated transient relay failure",
            )
            .with_code("relay_unavailable"));
        }
        Ok(ConnectorState {
            name: format!("connect-{project}"),
            uid: expected.uid.clone(),
            public_key: expected.public_key.clone(),
        })
    }
    async fn down(&self, _project: &str) -> Result<(), ApiError> {
        Ok(())
    }
    async fn reconcile_service(
        &self,
        _project: &str,
        _service: &ServiceState,
    ) -> Result<ServiceOutcome, ApiError> {
        self.service_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_service.load(Ordering::SeqCst) {
            return Err(ApiError::internal("simulated control-plane failure"));
        }
        Ok(ServiceOutcome {
            hostnames: Vec::new(),
            ready: true,
        })
    }
    async fn pause_service(&self, _project: &str, _service: &ServiceState) -> Result<(), ApiError> {
        Ok(())
    }
    async fn delete_service(
        &self,
        _project: &str,
        _service: &ServiceState,
    ) -> Result<(), ApiError> {
        Ok(())
    }
    async fn reconcile_dial(&self, _project: &str, dial: &DialState) -> Result<u16, ApiError> {
        if self.fail_dial.load(Ordering::SeqCst) {
            return Err(ApiError::internal("simulated dial failure"));
        }
        Ok(if dial.bind == 0 { 49152 } else { dial.bind })
    }
    async fn delete_dial(&self, _project: &str, _port: u16) -> Result<(), ApiError> {
        Ok(())
    }
    async fn ping(&self, _project: &str, address: &str) -> Result<PingResult, ApiError> {
        Ok(PingResult {
            address: address.into(),
            latency_ms: 1,
        })
    }
    async fn shutdown(&self) {}
    async fn join_network(&self, project: &str, network: &str) -> Result<Value, ApiError> {
        self.network_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_network.load(Ordering::SeqCst) {
            let error = ApiError::new(
                StatusCode::CONFLICT,
                if self.approval_required.load(Ordering::SeqCst) {
                    "administrator approval does not include the current routes"
                } else {
                    "gateway temporarily unavailable"
                },
            );
            return Err(if self.approval_required.load(Ordering::SeqCst) {
                error.with_code("network_setup_required")
            } else {
                error
            });
        }
        Ok(
            json!({"project":project,"network":network,"running":true,"managed_gateway":true,"persistent":true,"ephemeral":false}),
        )
    }
    async fn leave_network(&self, _project: &str, network: &str) -> Result<Value, ApiError> {
        self.network_calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"network":network,"left":true}))
    }
}

#[cfg(unix)]
#[tokio::test]
async fn managed_peer_plans_are_setup_scoped_durable_and_do_not_grant_privileges() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let token = enroll_test_project(&base, &client, repo.path()).await;
    let peer = iroh::SecretKey::from_bytes(&[2; 32]).public().to_string();
    let plan = json!({"network":"friend","peer":peer,"allow_inbound":[{"protocol":"icmp_echo"}],"allow_outbound":[{"protocol":"icmp_echo"}]});
    let url = format!("{base}/v1/networks/prepare?project=alpha");
    let operator: Value = client
        .post(format!("{base}/v1/tokens?project=alpha"))
        .bearer_auth(&token)
        .json(&json!({"role":"operate","scopes":["project"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(operator["bearer"].as_str().unwrap())
            .json(&plan)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    for name in ["friend", "another"] {
        let mut request = plan.clone();
        request["network"] = json!(name);
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(
            body["helper_config"]["approvals"].as_array().unwrap().len(),
            1,
            "must not approve another pending attachment"
        );
        assert_eq!(body["binding"]["peer"], peer);
    }
    let again = client
        .post(&url)
        .bearer_auth(&token)
        .json(&plan)
        .send()
        .await
        .unwrap();
    assert_eq!(
        again.status(),
        StatusCode::OK,
        "same configuration is idempotent"
    );
    let mut changed = plan.clone();
    changed["allow_inbound"] = json!([]);
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&token)
            .json(&changed)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let disk: Value = serde_json::from_slice(
        &tokio::fs::read(repo.path().join("daemon/state.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        disk["projects"]["alpha"]["peer_networks"]["friend"]["peer"],
        peer
    );
    assert_eq!(
        disk["projects"]["alpha"]["peer_networks"]["friend"]["allow_inbound"],
        json!([{"protocol":"icmp_echo","ports":[]}])
    );
    let status: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        status["networks"],
        json!([]),
        "preparation must not open a network"
    );
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 0);
    let setup_plan: Value = client
        .post(format!("{base}/v1/networks/friend/setup?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(
        setup_plan["approval_action"].as_str(),
        Some("install" | "add")
    ));
    assert_eq!(setup_plan["approval_changes"], json!([]));
    assert_eq!(
        client
            .post(format!("{base}/v1/networks/friend/setup?project=alpha"))
            .bearer_auth(operator["bearer"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    server.abort();
}

#[tokio::test]
async fn network_mutations_require_enrollment_and_project_operate_authority() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let setup_token = tokio::fs::read_to_string(repo.path().join("daemon_auth/setup.token"))
        .await
        .unwrap()
        .trim()
        .to_owned();
    let url = format!("{base}/v1/networks?project=alpha");
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&setup_token)
            .json(&json!({"network":"vpc"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    enroll_test_project(&base, &client, repo.path()).await;
    for role in [
        json!({"role":"viewer"}),
        json!({"role":"operate","scopes":["service:unrelated"]}),
    ] {
        let token: Value = client
            .post(format!("{base}/v1/tokens?project=alpha"))
            .bearer_auth(&setup_token)
            .json(&role)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let response = client
            .post(&url)
            .bearer_auth(token["bearer"].as_str().unwrap())
            .json(&json!({"network":"vpc"}))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
        ));
        let response = client
            .delete(format!("{base}/v1/networks/vpc?project=alpha"))
            .bearer_auth(token["bearer"].as_str().unwrap())
            .send()
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
        ));
    }
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 0);
    let token: Value = client
        .post(format!("{base}/v1/tokens?project=alpha"))
        .bearer_auth(&setup_token)
        .json(&json!({"role":"operate","scopes":["project"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token["bearer"].as_str().unwrap();
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(token)
            .json(&json!({"network":"vpc"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .post(format!("{base}/v1/networks?project=other"))
            .bearer_auth(token)
            .json(&json!({"network":"vpc"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .delete(format!("{base}/v1/networks/vpc?project=alpha"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 2);
    client
        .post(format!("{base}/v1/down?project=alpha"))
        .bearer_auth(&setup_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(token)
            .json(&json!({"network":"vpc"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let state: Value = serde_json::from_slice(
        &tokio::fs::read(repo.path().join("daemon/state.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        state["projects"]["alpha"].get("networks").is_none(),
        "local network intent must not be persisted"
    );
    server.abort();
}

#[tokio::test]
async fn managed_network_join_persists_one_intent_and_leave_revokes_it() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let token = enroll_test_project(&base, &client, repo.path()).await;
    let url = format!("{base}/v1/networks?project=alpha");

    for _ in 0..2 {
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .json(&json!({"network":"vpc"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let saved: Value = serde_json::from_slice(
        &tokio::fs::read(repo.path().join("daemon/state.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        saved["projects"]["alpha"]["managed_networks"]["vpc"]["desired_attached"],
        true
    );
    assert_eq!(
        saved["projects"]["alpha"]["managed_networks"]
            .as_object()
            .unwrap()
            .len(),
        1
    );

    let response = client
        .delete(format!("{base}/v1/networks/vpc?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let saved: Value = serde_json::from_slice(
        &tokio::fs::read(repo.path().join("daemon/state.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        saved["projects"]["alpha"]["managed_networks"]
            .as_object()
            .unwrap()
            .len(),
        0
    );
    server.abort();
}

async fn setup(
    repo: &Path,
    control: Arc<MockControl>,
) -> (String, reqwest::Client, tokio::task::JoinHandle<()>) {
    let store = Store::open(repo).await.unwrap();
    auth::initialize_setup_token(&store, repo).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = AppState {
        store,
        control,
        default_credentials_file: None,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    let task = tokio::spawn(async move {
        axum::serve(listener, api::router(state)).await.unwrap();
    });
    (format!("http://{address}"), reqwest::Client::new(), task)
}

async fn enroll_test_project(base: &str, client: &reqwest::Client, repo: &Path) -> String {
    let token = tokio::fs::read_to_string(repo.join("daemon_auth/setup.token"))
        .await
        .unwrap()
        .trim()
        .to_owned();
    let credentials = repo.join("source-credentials.json");
    tokio::fs::write(&credentials, b"{}").await.unwrap();
    let response = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(&token)
        .json(&json!({"project":"alpha", "credentials_file":credentials}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    token
}

#[tokio::test]
async fn friendly_peer_names_are_pinned_in_saved_services_and_dials() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control).await;
    let token = enroll_test_project(&base, &client, repo.path()).await;
    for (path, intent) in [
        (
            "services",
            json!({"endpoint":"localhost:8080","allow":["friendly-peer"]}),
        ),
        (
            "dials",
            json!({"connector":"friendly-peer","port":8080,"bind":18080}),
        ),
    ] {
        let response = client
            .post(format!("{base}/v1/{path}?project=alpha"))
            .bearer_auth(&token)
            .json(&intent)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let value: Value = response.json().await.unwrap();
        if path == "services" {
            assert_eq!(value["allow"], json!(["pinned-peer-key"]));
            assert_eq!(value["connector"], "connect-alpha");
        } else {
            assert_eq!(value["connector"], "pinned-peer-key");
            assert_eq!(value["connector_name"], "friendly-peer");
        }
    }
    let saved: Value = serde_json::from_slice(
        &tokio::fs::read(repo.path().join("daemon/state.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        saved["projects"]["alpha"]["dials"]["18080"]["connector"],
        "pinned-peer-key"
    );
    let response = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(&token)
        .json(&json!({"project":"alpha","name":"renamed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    for name in ["../bad", "UPPER", "-bad", "bad-"] {
        let response = client
            .post(format!("{base}/v1/up"))
            .bearer_auth(&token)
            .json(&json!({"project":"alpha","name":name}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn oidc_session_enrollment_pins_session_and_requires_setup_to_replace() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control).await;
    let token = tokio::fs::read_to_string(repo.path().join("daemon_auth/setup.token"))
        .await
        .unwrap();
    // The mock control never executes this helper. Use a small trusted Unix
    // executable: the unstripped test binary can exceed the helper size limit.
    let helper = std::fs::canonicalize("/bin/sh").unwrap();
    let descriptor = json!({"helper_path":helper,"session":"session-a","api_endpoint":"https://api.example.test"});
    let response = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(token.trim())
        .json(&json!({"project":"alpha","datumctl_session":descriptor}))
        .send()
        .await
        .unwrap();
    #[cfg(unix)]
    // SAFETY: geteuid takes no arguments and has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: Value = response.json().await.unwrap();
        assert!(
            error.to_string().contains("System daemons cannot use"),
            "root must receive actionable service-account guidance: {error}"
        );
        assert!(
            !repo
                .path()
                .join("daemon/projects/alpha/credentials.json")
                .exists(),
            "rejected host sessions must not persist credentials"
        );
        server.abort();
        return;
    }
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await.unwrap()
    );
    let credentials_path = repo.path().join("daemon/projects/alpha/credentials.json");
    let saved: Value =
        serde_json::from_slice(&tokio::fs::read(&credentials_path).await.unwrap()).unwrap();
    assert_eq!(saved["type"], "datumctl_session");
    assert_eq!(saved["session"], "session-a");
    assert_eq!(saved["project_id"], "alpha");

    let operator: Value = client
        .post(format!("{base}/v1/tokens?project=alpha"))
        .bearer_auth(token.trim())
        .json(&json!({"role":"operate","scopes":["project"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let operator = operator["bearer"].as_str().unwrap();
    let changed = json!({"helper_path":helper,"session":"session-b","api_endpoint":"https://other.example.test"});
    // A new host context does not silently overwrite a saved enrollment,
    // including when an operate token resumes it.
    let resumed: Value = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(operator)
        .json(&json!({"project":"alpha","datumctl_session":changed}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resumed["authentication"]["session"], "session-a");
    assert_eq!(
        serde_json::from_slice::<Value>(&tokio::fs::read(&credentials_path).await.unwrap())
            .unwrap(),
        saved
    );
    let forbidden = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(operator)
        .json(&json!({"project":"alpha","auth":"oidc","datumctl_session":changed}))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let replaced: Value = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(token.trim())
        .json(&json!({"project":"alpha","auth":"oidc","datumctl_session":changed}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replaced["authentication"]["session"], "session-b");
    server.abort();
}

#[tokio::test]
async fn oidc_invalid_modes_and_unprivileged_binding_never_persist_credentials() {
    let repo = tempfile::tempdir().unwrap();
    let (base, client, server) = setup(repo.path(), Arc::new(MockControl::default())).await;
    let token = tokio::fs::read_to_string(repo.path().join("daemon_auth/setup.token"))
        .await
        .unwrap();
    let descriptor = json!({"helper_path":"relative-helper","session":"session-a","api_endpoint":"https://api.example.test"});
    for body in [
        json!({"project":"alpha","auth":"unknown"}),
        json!({"project":"alpha","auth":"stored","datumctl_session":descriptor}),
        json!({"project":"alpha","auth":"oidc"}),
        json!({"project":"alpha","auth":"oidc","credentials_file":"/unused"}),
        json!({"project":"alpha","auth":"stored","credentials_file":"/unused"}),
        json!({"project":"alpha","auth":"oidc","datumctl_session":descriptor}),
    ] {
        let response = client
            .post(format!("{base}/v1/up"))
            .bearer_auth(token.trim())
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_client_error(),
            "{body}: {}",
            response.status()
        );
        assert!(
            !repo
                .path()
                .join("daemon/projects/alpha/credentials.json")
                .exists()
        );
    }
    let operator: Value = client
        .post(format!("{base}/v1/tokens?project=alpha"))
        .bearer_auth(token.trim())
        .json(&json!({"role":"operate","scopes":["project"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let denied = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(operator["bearer"].as_str().unwrap())
        .json(&json!({"project":"alpha","datumctl_session":descriptor}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        !repo
            .path()
            .join("daemon/projects/alpha/credentials.json")
            .exists()
    );
    server.abort();
}

#[tokio::test]
async fn service_retries_preserve_identity_and_refuse_access_changes() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let token = enroll_test_project(&base, &client, repo.path()).await;
    let url = format!("{base}/v1/services?project=alpha");
    let intent = json!({"endpoint":"localhost:8080", "allow":["peer-a", "peer-b"]});
    control.fail_service.store(true, Ordering::SeqCst);
    let failure = client
        .post(&url)
        .bearer_auth(&token)
        .json(&intent)
        .send()
        .await
        .unwrap();
    assert_eq!(failure.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let failure: Value = failure.json().await.unwrap();
    assert!(failure["error"].as_str().unwrap().contains("intent"));
    assert!(
        failure["error"]
            .as_str()
            .unwrap()
            .contains("datumctl connect unserve")
    );
    let before: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = before["services"][0]["id"].clone();
    control.fail_service.store(false, Ordering::SeqCst);
    let retry = client
        .post(&url)
        .bearer_auth(&token)
        .json(&json!({"endpoint":"localhost:8080", "allow":["peer-b", "peer-a", "peer-a"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::OK);
    let retried: Value = retry.json().await.unwrap();
    assert_eq!(retried["id"], id);
    assert_eq!(retried["ready"], true);
    for change in [
        json!({"endpoint":"localhost:8080"}),
        json!({"endpoint":"localhost:8080", "public":true}),
        json!({"endpoint":"otherhost:8080", "allow":["peer-a", "peer-b"]}),
    ] {
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .json(&change)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "service_conflict");
        let message = body["error"].as_str().unwrap();
        assert!(message.contains("datumctl connect unserve localhost:8080 --project alpha"));
        assert!(message.contains("Nothing changed."));
        assert!(!message.contains(id.as_str().unwrap()));
        if change["endpoint"] == "otherhost:8080" {
            assert!(message.contains(
                "Cannot share otherhost:8080: TCP port 8080 is already shared as localhost:8080"
            ));
            assert!(message.contains("only one destination per TCP port"));
        } else {
            assert!(message.contains("allowed Connectors"));
            if change["public"] == true {
                assert!(message.contains("public/private access"));
            }
        }
    }
    let after: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after["services"].as_array().unwrap().len(), 1);
    assert_eq!(after["services"][0]["allow"], intent["allow"]);
    assert_eq!(after["services"][0]["endpoint"], intent["endpoint"]);
    assert_eq!(after["services"][0]["public"], false);
    assert_eq!(control.service_calls.load(Ordering::SeqCst), 2);
    let paused = client
        .post(format!(
            "{base}/v1/services/{}/pause?project=alpha",
            id.as_str().unwrap()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(paused.status(), StatusCode::OK);
    let conflict: Value = client
        .post(&url)
        .bearer_auth(&token)
        .json(&intent)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(conflict["code"], "service_conflict");
    assert!(
        conflict["error"]
            .as_str()
            .unwrap()
            .contains("localhost:8080 (TCP) is stopping or paused")
    );
    server.abort();
}

#[tokio::test]
async fn invalid_service_options_never_save_intent_and_ambiguous_unserve_is_safe() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let token = enroll_test_project(&base, &client, repo.path()).await;
    let url = format!("{base}/v1/services?project=alpha");
    for intent in [
        json!({"endpoint":"localhost:8080", "public":true, "protocol":"udp"}),
        json!({"endpoint":"localhost:8080", "public":true, "allow":["peer"]}),
        json!({"endpoint":"localhost:8080", "hostname":"example.test"}),
        json!({"endpoint":"localhost:0"}),
    ] {
        assert_eq!(
            client
                .post(&url)
                .bearer_auth(&token)
                .json(&intent)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let status: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(status["services"].as_array().unwrap().is_empty());
    assert_eq!(control.service_calls.load(Ordering::SeqCst), 0);
    for protocol in ["tcp", "udp"] {
        assert_eq!(
            client
                .post(&url)
                .bearer_auth(&token)
                .json(&json!({"endpoint":"localhost:8080", "protocol":protocol}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
    }
    assert_eq!(
        client
            .delete(format!("{base}/v1/services/localhost:8080?project=alpha"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let status: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["services"].as_array().unwrap().len(), 2);
    for protocol in ["tcp", "udp"] {
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .json(&json!({"endpoint":"otherhost:8080", "protocol":protocol}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: Value = response.json().await.unwrap();
        let service = status["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["protocol"] == protocol)
            .unwrap();
        let message = body["error"].as_str().unwrap();
        assert!(message.contains(&format!(
            "unserve {} --project alpha",
            service["id"].as_str().unwrap()
        )));
        assert!(message.contains(&format!("{} port 8080", protocol.to_uppercase())));
    }
    server.abort();
}

#[tokio::test]
async fn failed_dial_can_be_retried_without_duplicate_intent() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let token = enroll_test_project(&base, &client, repo.path()).await;
    let url = format!("{base}/v1/dials?project=alpha");
    let intent = json!({"connector":"peer", "port":22, "bind":2222});
    control.fail_dial.store(true, Ordering::SeqCst);
    let failure = client
        .post(&url)
        .bearer_auth(&token)
        .json(&intent)
        .send()
        .await
        .unwrap();
    assert_eq!(failure.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(failure.text().await.unwrap().contains("hangup 2222"));
    control.fail_dial.store(false, Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            client
                .post(&url)
                .bearer_auth(&token)
                .json(&intent)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let change = json!({"connector":"different-peer", "port":22, "bind":2222});
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&token)
            .json(&change)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let status: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["dials"].as_array().unwrap().len(), 1);
    assert_eq!(status["dials"][0]["connector"], "peer");
    server.abort();
}

#[tokio::test]
async fn setup_errors_have_stable_codes_and_failed_ephemeral_dial_can_be_removed() {
    let repo = tempfile::tempdir().unwrap();
    let control = Arc::new(MockControl::default());
    let (base, client, server) = setup(repo.path(), control.clone()).await;
    let token = tokio::fs::read_to_string(repo.path().join("daemon_auth/setup.token"))
        .await
        .unwrap()
        .trim()
        .to_owned();
    let response: Value = client
        .post(format!("{base}/v1/services?project=alpha"))
        .bearer_auth(&token)
        .json(&json!({"endpoint":"0.0.0.0:800"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["code"], "project_not_configured");
    let response: Value = client
        .post(format!("{base}/v1/up"))
        .bearer_auth(&token)
        .json(&json!({"project":"alpha"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["code"], "credentials_required");
    enroll_test_project(&base, &client, repo.path()).await;
    control.fail_dial.store(true, Ordering::SeqCst);
    assert_eq!(
        client
            .post(format!("{base}/v1/dials?project=alpha"))
            .bearer_auth(&token)
            .json(&json!({"connector":"peer", "port":22, "bind":0}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        client
            .delete(format!("{base}/v1/dials/0?project=alpha"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    client
        .post(format!("{base}/v1/down?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let response: Value = client
        .post(format!("{base}/v1/services?project=alpha"))
        .bearer_auth(&token)
        .json(&json!({"endpoint":"localhost:800"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["code"], "project_down");
    let status: Value = client
        .get(format!("{base}/v1/status?project=alpha"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(status["dials"].as_array().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn api_enforces_auth_roles_scope_and_revocation() {
    let repo = tempfile::tempdir().unwrap();
    let (base, client, server) = setup(repo.path(), Arc::new(MockControl::default())).await;
    let setup_token = tokio::fs::read_to_string(repo.path().join("daemon_auth/setup.token"))
        .await
        .unwrap();
    let setup_token = setup_token.trim();
    tokio::fs::write(repo.path().join("source-credentials.json"), b"{}")
        .await
        .unwrap();

    let response = client
        .get(format!("{base}/v1/status?project=alpha"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("x-request-id"));

    let response = client.post(format!("{base}/v1/up")).bearer_auth(setup_token)
        .json(&json!({"project":"alpha","credentials_file":repo.path().join("source-credentials.json")})).send().await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await.unwrap()
    );

    let viewer: Value = client
        .post(format!("{base}/v1/tokens?project=alpha"))
        .bearer_auth(setup_token)
        .json(&json!({"role":"viewer"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let viewer = viewer["bearer"].as_str().unwrap();
    assert_eq!(
        client
            .get(format!("{base}/v1/status?project=alpha"))
            .bearer_auth(viewer)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .post(format!("{base}/v1/down?project=alpha"))
            .bearer_auth(viewer)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let operate: Value = client
        .post(format!("{base}/v1/tokens?project=alpha"))
        .bearer_auth(setup_token)
        .json(&json!({"role":"operate","scopes":["service:some-service"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let operate = operate["bearer"].as_str().unwrap();
    assert_eq!(
        client
            .post(format!("{base}/v1/down?project=alpha"))
            .bearer_auth(operate)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let id = viewer.split_once('.').unwrap().0;
    assert_eq!(
        client
            .delete(format!("{base}/v1/tokens/{id}?project=alpha"))
            .bearer_auth(setup_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{base}/v1/status?project=alpha"))
            .bearer_auth(viewer)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    server.abort();
}

#[tokio::test]
async fn restart_reconciles_only_desired_active_intent() {
    let repo = tempfile::tempdir().unwrap();
    let store = Store::open(repo.path()).await.unwrap();
    let control = Arc::new(MockControl::default());
    let state = AppState {
        store: store.clone(),
        control: control.clone(),
        default_credentials_file: None,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    store
        .transact(|root| {
            let project = root.projects.entry("alpha".into()).or_default();
            project.desired_up = true;
            project.enrolled = true;
            project.connector = Some(ConnectorState {
                name: "connect-alpha".into(),
                uid: "uid-1".into(),
                public_key: "key-1".into(),
            });
            project.credentials_file = Some("/private/credentials.json".into());
            project.managed_networks.insert(
                "vpc".into(),
                ManagedNetworkState {
                    network: "vpc".into(),
                    desired_attached: true,
                    running: true,
                    state: "connected".into(),
                    last_error: None,
                    last_error_stage: None,
                    last_actor: "setup".into(),
                },
            );
            project.services.insert(
                "active".into(),
                ServiceState {
                    id: "active".into(),
                    endpoint: "127.0.0.1:80".into(),
                    protocol: Protocol::Tcp,
                    public: false,
                    hostname: None,
                    allow: vec!["peer".into()],
                    desired_active: true,
                    running: false,
                    ready: false,
                    hostnames: vec![],
                    last_error: None,
                    last_error_stage: None,
                    last_actor: "setup".into(),
                },
            );
            project.services.insert(
                "paused".into(),
                ServiceState {
                    id: "paused".into(),
                    endpoint: "127.0.0.1:81".into(),
                    protocol: Protocol::Tcp,
                    public: false,
                    hostname: None,
                    allow: vec!["peer".into()],
                    desired_active: false,
                    running: false,
                    ready: false,
                    hostnames: vec![],
                    last_error: None,
                    last_error_stage: None,
                    last_actor: "setup".into(),
                },
            );
            Ok(())
        })
        .await
        .unwrap();
    drop(state);
    drop(store);

    let reopened = Store::open(repo.path()).await.unwrap();
    let restarted = AppState {
        store: reopened,
        control: control.clone(),
        default_credentials_file: None,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    api::reconcile_all(&restarted).await;
    assert_eq!(control.up_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.service_calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 1);
    let state = restarted.store.snapshot().await;
    let network = &state.projects["alpha"].managed_networks["vpc"];
    assert!(network.running);
    assert_eq!(network.state, "connected");
}

#[tokio::test]
async fn startup_supervisor_retries_failed_project_resume_and_restores_network_intent() {
    let repo = tempfile::tempdir().unwrap();
    let store = Store::open(repo.path()).await.unwrap();
    store
        .transact(|root| {
            let project = root.projects.entry("alpha".into()).or_default();
            project.desired_up = true;
            project.enrolled = true;
            project.connector = Some(ConnectorState {
                name: "connect-alpha".into(),
                uid: "uid-1".into(),
                public_key: "key-1".into(),
            });
            project.credentials_file = Some("/private/credentials.json".into());
            project.managed_networks.insert(
                "vpc".into(),
                ManagedNetworkState {
                    network: "vpc".into(),
                    desired_attached: true,
                    running: true,
                    state: "connected".into(),
                    last_error: None,
                    last_error_stage: None,
                    last_actor: "setup".into(),
                },
            );
            Ok(())
        })
        .await
        .unwrap();
    let control = Arc::new(MockControl::default());
    control.resume_failures.store(2, Ordering::SeqCst);
    let state = AppState {
        store,
        control: control.clone(),
        default_credentials_file: None,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    let shutdown = tokio_util::sync::CancellationToken::new();

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        api::reconcile_with_retry(&state, shutdown),
    )
    .await
    .expect("resume backoff should recover after two transient failures");

    assert_eq!(control.up_calls.load(Ordering::SeqCst), 3);
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 1);
    let snapshot = state.store.snapshot().await;
    let project = &snapshot.projects["alpha"];
    assert!(project.running);
    assert!(project.last_error.is_none());
    assert!(project.managed_networks["vpc"].running);
    assert_eq!(project.managed_networks["vpc"].state, "connected");
}

#[tokio::test]
async fn startup_supervisor_backoff_is_cancellable_and_does_not_spin() {
    let repo = tempfile::tempdir().unwrap();
    let store = Store::open(repo.path()).await.unwrap();
    store
        .transact(|root| {
            let project = root.projects.entry("alpha".into()).or_default();
            project.desired_up = true;
            project.enrolled = true;
            project.connector = Some(ConnectorState {
                name: "connect-alpha".into(),
                uid: "uid-1".into(),
                public_key: "key-1".into(),
            });
            project.credentials_file = Some("/private/credentials.json".into());
            Ok(())
        })
        .await
        .unwrap();
    let control = Arc::new(MockControl::default());
    control.resume_failures.store(usize::MAX, Ordering::SeqCst);
    let state = AppState {
        store,
        control: control.clone(),
        default_credentials_file: None,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn({
        let state = state.clone();
        let shutdown = shutdown.clone();
        async move { api::reconcile_with_retry(&state, shutdown).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while control.up_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("supervisor should make an initial resume attempt");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(control.up_calls.load(Ordering::SeqCst), 1);
    shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("shutdown should interrupt retry backoff")
        .unwrap();
}

#[tokio::test]
async fn restart_keeps_managed_intent_fail_closed_when_approval_is_stale() {
    let repo = tempfile::tempdir().unwrap();
    let store = Store::open(repo.path()).await.unwrap();
    store
        .transact(|root| {
            let project = root.projects.entry("alpha".into()).or_default();
            project.desired_up = true;
            project.enrolled = true;
            project.connector = Some(ConnectorState {
                name: "connect-alpha".into(),
                uid: "uid-1".into(),
                public_key: "key-1".into(),
            });
            project.credentials_file = Some("/private/credentials.json".into());
            project.managed_networks.insert(
                "vpc".into(),
                ManagedNetworkState {
                    network: "vpc".into(),
                    desired_attached: true,
                    running: true,
                    state: "connected".into(),
                    last_error: None,
                    last_error_stage: None,
                    last_actor: "setup".into(),
                },
            );
            Ok(())
        })
        .await
        .unwrap();
    let control = Arc::new(MockControl::default());
    control.fail_network.store(true, Ordering::SeqCst);
    control.approval_required.store(true, Ordering::SeqCst);
    let state = AppState {
        store,
        control: control.clone(),
        default_credentials_file: None,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    api::reconcile_all(&state).await;

    let snapshot = state.store.snapshot().await;
    let network = &snapshot.projects["alpha"].managed_networks["vpc"];
    assert!(network.desired_attached);
    assert!(!network.running);
    assert_eq!(network.state, "approval_required");
    assert_eq!(network.last_error_stage.as_deref(), Some("restart_network"));
    assert!(network.last_error.as_deref().unwrap().contains("approval"));
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 1);

    // Installing the exact approval allows the same durable intent to recover
    // on the next reconciliation without another join request.
    control.fail_network.store(false, Ordering::SeqCst);
    control.approval_required.store(false, Ordering::SeqCst);
    api::reconcile_all(&state).await;
    let snapshot = state.store.snapshot().await;
    let network = &snapshot.projects["alpha"].managed_networks["vpc"];
    assert!(network.running);
    assert_eq!(network.state, "connected");
    assert!(network.last_error.is_none());
    assert_eq!(control.network_calls.load(Ordering::SeqCst), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn failed_persistence_does_not_publish_memory_transition() {
    let repo = tempfile::tempdir().unwrap();
    let store = Store::open(repo.path()).await.unwrap();
    let daemon_dir = repo.path().join("daemon");
    // A directory at the destination deterministically rejects atomic rename,
    // including when tests run as root or storage repairs directory modes.
    tokio::fs::rename(
        daemon_dir.join("state.json"),
        daemon_dir.join("state.saved"),
    )
    .await
    .unwrap();
    tokio::fs::create_dir(daemon_dir.join("state.json"))
        .await
        .unwrap();
    let result = store
        .transact(|root| {
            root.projects
                .insert("must-not-appear".into(), Default::default());
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert!(
        !store
            .snapshot()
            .await
            .projects
            .contains_key("must-not-appear")
    );
}
