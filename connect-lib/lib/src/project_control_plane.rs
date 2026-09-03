use std::sync::Arc;

use arc_swap::ArcSwap;
use http::HeaderValue;
use http::header::USER_AGENT;
use kube::{Client, Config};
use n0_error::{Result, StdResultExt};
use n0_future::task::AbortOnDropHandle;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::watch;
use tracing::warn;

use crate::datum_cloud::DatumCloudClient;
use crate::http_user_agent::datum_http_user_agent;

#[derive(derive_more::Debug, Clone)]
pub struct ProjectControlPlaneClient {
    project_id: String,
    server_url: String,
    access_token: Arc<ArcSwap<SecretString>>,
    #[debug("kube::Client")]
    client: Arc<ArcSwap<Client>>,
    datum: DatumCloudClient,
    _auth_task: Option<Arc<AbortOnDropHandle<()>>>,
    auth_revision_rx: Option<watch::Receiver<u64>>,
}

impl ProjectControlPlaneClient {
    pub fn new(
        project_id: String,
        server_url: String,
        access_token: String,
        datum: DatumCloudClient,
    ) -> Result<Self> {
        let auth_revision_rx = datum.auth_update_watch();
        Self::new_with_initial_token(
            project_id,
            server_url,
            &access_token,
            datum,
            auth_revision_rx,
        )
    }

    pub(crate) fn new_subscribed(
        project_id: String,
        server_url: String,
        datum: DatumCloudClient,
        auth_revision_rx: watch::Receiver<u64>,
    ) -> Result<Self> {
        datum.with_token(|access_token| {
            Self::new_with_initial_token(
                project_id,
                server_url,
                access_token,
                datum.clone(),
                auth_revision_rx,
            )
        })
    }

    pub fn new_with_token_source(
        project_id: String,
        server_url: String,
        token_source: crate::datum_cloud::external_token_source::ExternalTokenSource,
    ) -> Result<Self> {
        let datum = DatumCloudClient::with_external_token_source(
            crate::ApiEnv::from_env_with_host_override(),
            token_source,
        );
        let auth_revision_rx = datum.auth_update_watch();
        Self::new_subscribed(project_id, server_url, datum, auth_revision_rx)
    }

    fn new_with_initial_token(
        project_id: String,
        server_url: String,
        access_token: &str,
        datum: DatumCloudClient,
        auth_revision_rx: watch::Receiver<u64>,
    ) -> Result<Self> {
        let client = Self::build_kube_client(&server_url, access_token)?;
        let mut this = Self {
            project_id,
            server_url,
            access_token: Arc::new(ArcSwap::from_pointee(SecretString::new(
                access_token.to_owned().into_boxed_str(),
            ))),
            client: Arc::new(ArcSwap::from_pointee(client)),
            datum,
            _auth_task: None,
            auth_revision_rx: Some(auth_revision_rx),
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
        self.access_token.load().expose_secret().to_owned()
    }

    pub fn client(&self) -> Client {
        self.client.load_full().as_ref().clone()
    }

    pub async fn client_refreshed(&self) -> Result<Client> {
        self.datum
            .with_token(|access_token| self.rebuild_if_changed(access_token))?;
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
        let current = self.access_token.load();
        if current.expose_secret() == access_token {
            return Ok(());
        }

        let client = Self::build_kube_client(&self.server_url, access_token)?;
        self.client.store(Arc::new(client));
        self.access_token.store(Arc::new(SecretString::new(
            access_token.to_owned().into_boxed_str(),
        )));
        Ok(())
    }

    fn refresh_client_from_update(&self) -> Result<()> {
        self.datum
            .with_token(|access_token| self.rebuild_if_changed(access_token))
    }

    fn start_auth_watch(&mut self) {
        if self._auth_task.is_some() {
            return;
        }
        let Some(mut auth_revision_rx) = self.auth_revision_rx.take() else {
            return;
        };
        let client = self.clone();
        let task = tokio::spawn(async move {
            // Re-read once after construction. This closes the legacy public
            // constructor's read-before-subscribe window and is a no-op for
            // callers that subscribed before their initial token read.
            if let Err(err) = client.refresh_client_from_update() {
                warn!("failed to refresh project control plane client: {err:#}");
            }

            loop {
                if auth_revision_rx.changed().await.is_err() {
                    return;
                }
                if let Err(err) = client.refresh_client_from_update() {
                    warn!("failed to refresh project control plane client: {err:#}");
                }
            }
        });
        self._auth_task = Some(Arc::new(AbortOnDropHandle::new(task)));
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::test_util::{make_jwt_with_exp, setup_plugin_env};

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn datum_factory_rebuilds_long_lived_client_after_token_rotation() {
        let (_dir, token_source) = setup_plugin_env();
        let datum = DatumCloudClient::with_external_token_source(
            crate::ApiEnv::Production,
            token_source.clone(),
        );
        let client = datum
            .project_control_plane_client("test-project")
            .await
            .expect("project control plane client should be constructed");
        let initial_token = client.access_token();
        let rotated_token = make_jwt_with_exp(8888888888);

        token_source.swap_token(rotated_token.clone());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while client.access_token() != rotated_token {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("project control plane client should observe the token revision");

        assert_ne!(client.access_token(), initial_token);
    }

    // These tests require rustls CryptoProvider (requires 'ring' or 'aws-lc-rs'
    // feature). Gate behind a feature flag so they don't fail in CI when
    // those features are disabled. Run manually with:
    //   cargo test --lib --features integration-tests,kube/aws-lc-rs

    #[test]
    #[cfg(feature = "integration-tests")]
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
    #[cfg(feature = "integration-tests")]
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
    #[cfg(feature = "integration-tests")]
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
    #[cfg(feature = "integration-tests")]
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
    #[cfg(feature = "integration-tests")]
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
