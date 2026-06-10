use std::sync::Arc;

use arc_swap::ArcSwap;
use http::HeaderValue;
use http::header::USER_AGENT;
use kube::{Client, Config};
use n0_error::{Result, StdResultExt};
use n0_future::task::AbortOnDropHandle;
use secrecy::SecretString;
use tokio::sync::watch;
use tracing::warn;

use crate::datum_cloud::DatumCloudClient;
use crate::datum_cloud::LoginState;
use crate::http_user_agent::datum_http_user_agent;

#[derive(derive_more::Debug, Clone)]
pub struct ProjectControlPlaneClient {
    project_id: String,
    server_url: String,
    access_token: Arc<ArcSwap<String>>,
    #[debug("kube::Client")]
    client: Arc<ArcSwap<Client>>,
    datum: DatumCloudClient,
    _auth_task: Option<Arc<AbortOnDropHandle<()>>>,
    token_rx: Option<watch::Receiver<String>>,
}

impl ProjectControlPlaneClient {
    pub fn new(
        project_id: String,
        server_url: String,
        access_token: String,
        datum: DatumCloudClient,
    ) -> Result<Self> {
        let client = Self::build_kube_client(&server_url, &access_token)?;
        let mut this = Self {
            project_id,
            server_url,
            access_token: Arc::new(ArcSwap::from_pointee(access_token)),
            client: Arc::new(ArcSwap::from_pointee(client)),
            datum,
            _auth_task: None,
            token_rx: None,
        };
        this.start_auth_watch();
        Ok(this)
    }

    pub fn new_with_token_source(
        project_id: String,
        server_url: String,
        token_source: crate::datum_cloud::external_token_source::ExternalTokenSource,
    ) -> Result<Self> {
        let initial_token = token_source.token();
        let client = Self::build_kube_client(&server_url, &initial_token)?;
        let datum = DatumCloudClient::with_external_token_source(
            crate::ApiEnv::from_env_with_host_override(),
            token_source.clone(),
        );
        let mut this = Self {
            project_id,
            server_url,
            access_token: Arc::new(ArcSwap::from_pointee(initial_token)),
            client: Arc::new(ArcSwap::from_pointee(client)),
            datum,
            _auth_task: None,
            token_rx: Some(token_source.watch()),
        };
        this.start_auth_watch();
        Ok(this)
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn access_token(&self) -> String {
        self.access_token.load_full().as_ref().clone()
    }

    pub fn client(&self) -> Client {
        self.client.load_full().as_ref().clone()
    }

    pub async fn client_refreshed(&self) -> Result<Client> {
        let access_token = self.datum.token();
        self.rebuild_if_changed(&access_token)?;
        Ok(self.client())
    }

    fn build_kube_client(server_url: &str, access_token: &str) -> Result<Client> {
        let uri = server_url
            .parse()
            .std_context("Invalid project control plane URL")?;
        let mut config = Config::new(uri);
        config.auth_info.token = Some(SecretString::new(access_token.to_string().into_boxed_str()));
        let ua = HeaderValue::from_str(&datum_http_user_agent())
            .std_context("Invalid User-Agent for kube client")?;
        config.headers.push((USER_AGENT, ua));
        Client::try_from(config).std_context("Failed to create project control plane client")
    }

    fn rebuild_if_changed(&self, access_token: &str) -> Result<()> {
        let current = self.access_token.load_full();
        if current.as_ref().as_str() == access_token {
            return Ok(());
        }

        let client = Self::build_kube_client(&self.server_url, access_token)?;
        self.client.store(Arc::new(client));
        self.access_token.store(Arc::new(access_token.to_string()));
        Ok(())
    }

    async fn refresh_client_from_update(&self) -> Result<()> {
        if self.datum.is_plugin_mode() {
            let token = self.datum.token();
            return self.rebuild_if_changed(&token);
        }
        let auth_state = self.datum.auth_state();
        let auth = auth_state.load();
        self.rebuild_if_changed(&auth.tokens.access_token.secret().to_string())
    }

    fn start_auth_watch(&mut self) {
        if self._auth_task.is_some() {
            return;
        }
        let mut client = self.clone();
        let task = tokio::spawn(async move {
            if let Some(token_rx) = client.token_rx.take() {
                if let Err(err) = client.refresh_client_from_update().await {
                    warn!("failed to refresh project control plane client: {err:#}");
                }
                let mut token_rx = token_rx;
                loop {
                    if token_rx.changed().await.is_err() {
                        return;
                    }
                    let new_token = (*token_rx.borrow()).clone();
                    if let Err(err) = client.rebuild_if_changed(&new_token) {
                        warn!("failed to refresh project control plane client: {err:#}");
                    }
                }
            } else {
                let mut login_rx = client.datum.login_state_watch();
                let mut auth_update_rx = client.datum.auth_update_watch();
                if *login_rx.borrow() != LoginState::Missing
                    && let Err(err) = client.refresh_client_from_update().await
                {
                    warn!("failed to refresh project control plane client: {err:#}");
                }
                loop {
                    tokio::select! {
                        res = login_rx.changed() => {
                            if res.is_err() {
                                return;
                            }
                        }
                        res = auth_update_rx.changed() => {
                            if res.is_err() {
                                return;
                            }
                        }
                    }
                    if *login_rx.borrow() != LoginState::Missing
                        && let Err(err) = client.refresh_client_from_update().await
                    {
                        warn!("failed to refresh project control plane client: {err:#}");
                    }
                }
            }
        });
        self._auth_task = Some(Arc::new(AbortOnDropHandle::new(task)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExternalTokenSource;
    use base64::Engine;

    fn make_jwt_with_exp(exp: u64) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({"alg":"HS256","typ":"JWT"}).to_string().as_bytes(),
        );
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({"exp": exp, "sub":"test-user"}).to_string().as_bytes(),
        );
        format!("{header}.{payload}.fake_sig")
    }

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("connect-pcp-test-{ts}"));
            std::fs::create_dir_all(&path).expect("should create temp dir");
            TempDir { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn setup_plugin_env() -> (TempDir, ExternalTokenSource) {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        let dir = TempDir::new();
        let helper_path = dir.path().join("fake-helper.sh");
        let jwt = make_jwt_with_exp(9999999999);
        std::fs::write(&helper_path, format!("#!/bin/sh\necho '{}'\n", jwt))
            .expect("should write helper script");
        #[cfg(unix)]
        std::fs::set_permissions(
            &helper_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("should set executable permission");
        let helper_str = helper_path.to_string_lossy().to_string();

        unsafe {
            std::env::set_var("DATUM_CREDENTIALS_HELPER", &helper_str);
            std::env::set_var("DATUM_SESSION", "test-session");
        }

        let source =
            ExternalTokenSource::from_env(Some("test-session".to_string())).expect("should create token source");
        (dir, source)
    }

    // These tests are integration-style — they require rustls CryptoProvider
    // to be installed (requires 'ring' or 'aws-lc-rs' feature). Marked
    // ignore so they don't fail in CI when those features are disabled.
    // Run manually with: cargo test --lib -- --ignored

    #[test]
    #[ignore]
    fn new_with_token_source_accepts_external_token_source() {
        let (_dir, token_source) = setup_plugin_env();
        let result = ProjectControlPlaneClient::new_with_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        let _ = result;
    }

    #[test]
    #[ignore]
    fn new_with_token_source_sets_project_id() {
        let (_dir, token_source) = setup_plugin_env();
        let pcp = ProjectControlPlaneClient::new_with_token_source(
            "my-project-id".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/my-project-id/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.project_id(), "my-project-id");
        }
    }

    #[test]
    #[ignore]
    fn access_token_returns_token_from_source() {
        let (_dir, token_source) = setup_plugin_env();
        let expected_token = token_source.token();
        let pcp = ProjectControlPlaneClient::new_with_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.access_token(), expected_token);
        }
    }

    #[test]
    #[ignore]
    fn server_url_is_stored() {
        let (_dir, token_source) = setup_plugin_env();
        let server_url = "https://custom.api.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test/control-plane".to_string();
        let pcp = ProjectControlPlaneClient::new_with_token_source(
            "test-project".to_string(),
            server_url.clone(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.server_url(), server_url);
        }
    }

    #[test]
    #[ignore]
    fn datum_is_plugin_mode_after_new_with_token_source() {
        let (_dir, token_source) = setup_plugin_env();
        let pcp = ProjectControlPlaneClient::new_with_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert!(pcp.datum.is_plugin_mode());
        }
    }
}
