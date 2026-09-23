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
use crate::datum_cloud::LoginState;
use crate::datum_cloud::TokenSource;
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
    token_rx: Option<watch::Receiver<SecretString>>,
}

impl ProjectControlPlaneClient {
    /// Construct against an already-built [`DatumCloudClient`], using its
    /// token source's watch channel to keep the kube client fresh across
    /// rotations. `access_token` is the token to build the initial kube
    /// client with; it is expected to be `datum`'s current token (see
    /// [`DatumCloudClient::project_control_plane_client`], the only
    /// production caller), but is taken as a plain argument rather than
    /// re-derived here so callers that already have it in hand don't pay
    /// for a second read of the token source.
    pub fn new(
        project_id: String,
        server_url: String,
        access_token: String,
        datum: DatumCloudClient,
    ) -> Result<Self> {
        let client = Self::build_kube_client(&server_url, &access_token)?;
        // Share datum's token source watch channel so this client keeps
        // observing rotations for as long as it's retained, instead of only
        // ever seeing the token it was constructed with. Every
        // `DatumCloudClient` has a `TokenSource` unconditionally now, so
        // this is always available.
        let token_rx = Some(datum.token_source().watch());
        let mut this = Self {
            project_id,
            server_url,
            access_token: Arc::new(ArcSwap::from_pointee(SecretString::from(access_token))),
            client: Arc::new(ArcSwap::from_pointee(client)),
            datum,
            _auth_task: None,
            token_rx,
        };
        this.start_auth_watch();
        Ok(this)
    }

    /// Construct against a concrete [`ExternalTokenSource`] (plugin mode;
    /// back-compat with the pre-`TokenSource` API). Prefer
    /// [`Self::new_with_shared_token_source`] for new code, which takes any
    /// [`TokenSource`] trait object.
    pub fn new_with_token_source(
        project_id: String,
        server_url: String,
        token_source: crate::datum_cloud::external_token_source::ExternalTokenSource,
    ) -> Result<Self> {
        Self::new_with_shared_token_source(project_id, server_url, Arc::new(token_source))
    }

    /// Construct against any shared [`TokenSource`] — e.g. the one a
    /// [`DatumCloudClient`] already holds, via
    /// [`DatumCloudClient::token_source`] — without first building a
    /// `DatumCloudClient` of your own. A fresh internal `DatumCloudClient`
    /// is built over the same `token_source`.
    pub fn new_with_shared_token_source(
        project_id: String,
        server_url: String,
        token_source: Arc<dyn TokenSource>,
    ) -> Result<Self> {
        let initial_token = token_source.token();
        let client = Self::build_kube_client(&server_url, initial_token.expose_secret())?;
        let datum = DatumCloudClient::with_token_source(
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

    /// Returns the access token currently backing the kube client, as a
    /// plain `String` (back-compat with the pre-`TokenSource` API). Prefer
    /// [`Self::access_token_secret`] for new code.
    pub fn access_token(&self) -> String {
        self.access_token.load_full().expose_secret().to_owned()
    }

    /// Returns the access token currently backing the kube client.
    pub fn access_token_secret(&self) -> SecretString {
        self.access_token.load_full().as_ref().clone()
    }

    pub fn client(&self) -> Client {
        self.client.load_full().as_ref().clone()
    }

    pub async fn client_refreshed(&self) -> Result<Client> {
        let access_token = self.datum.token_secret();
        self.rebuild_if_changed(access_token.expose_secret())?;
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
        if current.expose_secret() == access_token {
            return Ok(());
        }

        let client = Self::build_kube_client(&self.server_url, access_token)?;
        self.client.store(Arc::new(client));
        self.access_token
            .store(Arc::new(SecretString::from(access_token.to_owned())));
        Ok(())
    }

    async fn refresh_client_from_update(&self) -> Result<()> {
        if self.datum.is_plugin_mode() {
            let token = self.datum.token_secret();
            return self.rebuild_if_changed(token.expose_secret());
        }
        let auth_state = self.datum.auth_state();
        let auth = auth_state.load();
        self.rebuild_if_changed(auth.tokens.access_token.secret())
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
                    let new_token = token_rx.borrow().clone();
                    if let Err(err) = client.rebuild_if_changed(new_token.expose_secret()) {
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
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::test_util::static_token_source;

    // These tests build a real kube::Client, which needs a rustls
    // CryptoProvider installed process-wide (kube_client::Client::try_from
    // panics, rather than returning Err, if none is installed — so this
    // must run before any assertion, not be treated as a recoverable
    // error). Gate behind a feature flag so they don't run by default; see
    // the `rustls` dev-dependency doc comment in Cargo.toml. Run manually
    // with:
    //   cargo test --lib --features integration-tests
    #[cfg(feature = "integration-tests")]
    fn ensure_crypto_provider() {
        // install_default() errors if a provider is already installed by an
        // earlier test in this binary; that's fine, ignore it.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn new_with_shared_token_source_accepts_a_trait_object() {
        ensure_crypto_provider();
        let token_source = static_token_source();
        let result = ProjectControlPlaneClient::new_with_shared_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        let _ = result;
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn new_with_shared_token_source_sets_project_id() {
        ensure_crypto_provider();
        let token_source = static_token_source();
        let pcp = ProjectControlPlaneClient::new_with_shared_token_source(
            "my-project-id".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/my-project-id/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.project_id(), "my-project-id");
        }
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn access_token_returns_token_from_source() {
        ensure_crypto_provider();
        let token_source = static_token_source();
        let expected_token = token_source.token().expose_secret().to_owned();
        let pcp = ProjectControlPlaneClient::new_with_shared_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.access_token(), expected_token);
            assert_eq!(pcp.access_token_secret().expose_secret(), expected_token);
        }
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn server_url_is_stored() {
        ensure_crypto_provider();
        let token_source = static_token_source();
        let server_url = "https://custom.api.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test/control-plane".to_string();
        let pcp = ProjectControlPlaneClient::new_with_shared_token_source(
            "test-project".to_string(),
            server_url.clone(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.server_url(), server_url);
        }
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn datum_is_plugin_mode_after_new_with_shared_token_source() {
        ensure_crypto_provider();
        let token_source = static_token_source();
        let pcp = ProjectControlPlaneClient::new_with_shared_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert!(pcp.datum.is_plugin_mode());
        }
    }

    /// Back-compat: the restored `new_with_token_source(..., ExternalTokenSource)`
    /// signature (a concrete type, not a trait object) must still work
    /// directly, exercised against the real credentials-helper exec path.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn new_with_token_source_accepts_concrete_external_token_source() {
        ensure_crypto_provider();
        let (_dir, token_source) = crate::test_util::setup_plugin_env();
        let expected = token_source.token();
        let pcp = ProjectControlPlaneClient::new_with_token_source(
            "test-project".to_string(),
            "https://api.datum.net/apis/resourcemanager.miloapis.com/v1alpha1/projects/test-project/control-plane".to_string(),
            token_source,
        );
        if let Ok(pcp) = pcp {
            assert_eq!(pcp.access_token(), expected);
        }
    }

    /// Regression test for a `ProjectControlPlaneClient` retained across a
    /// token rotation, built the way every production caller builds one:
    /// via `DatumCloudClient::project_control_plane_client`. It must observe
    /// a rotation of the shared token source on its own — via the watch
    /// channel `new()` now always wires up — rather than only ever seeing
    /// the token it was constructed with.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn retained_client_from_normal_factory_observes_rotation() {
        use crate::datum_cloud::{ApiEnv, StaticTokenSource};

        ensure_crypto_provider();
        let source = Arc::new(StaticTokenSource::new("initial-token"));
        let datum = DatumCloudClient::with_token_source(ApiEnv::Production, source.clone());
        let pcp = datum
            .project_control_plane_client("test-project")
            .await
            .expect("crypto provider is installed by ensure_crypto_provider()");
        assert_eq!(pcp.access_token(), "initial-token");

        source.set("rotated-token");
        for _ in 0..40 {
            if pcp.access_token() == "rotated-token" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_eq!(
            pcp.access_token(),
            "rotated-token",
            "a ProjectControlPlaneClient built via project_control_plane_client() must \
             observe a token rotation on its own, not only the token it started with"
        );
    }
}
