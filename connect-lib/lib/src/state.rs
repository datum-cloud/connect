use std::{path::PathBuf, str::FromStr, sync::Arc};

use arc_swap::{ArcSwap, Guard};
use iroh::EndpointId;
use iroh_proxy_utils::Authority;
use iroh_tickets::{ParseError, Ticket};
use n0_error::{Result, StackResultExt, StdResultExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, futures::Notified};

use crate::{DATUM_CONNECT_GATEWAY_DOMAIN_NAME, Repo};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct State {
    pub proxies: Vec<ProxyState>,
}

impl State {
    pub fn set_proxy(&mut self, proxy: ProxyState) {
        if let Some(existing) = self
            .proxies
            .iter_mut()
            .find(|p| p.info.resource_id == proxy.info.resource_id)
        {
            *existing = proxy;
        } else {
            self.proxies.push(proxy);
        }
    }

    pub fn remove_proxy(&mut self, resouce_id: &str) -> Option<ProxyState> {
        if let Some(idx) = self
            .proxies
            .iter()
            .position(|p| p.info.resource_id == resouce_id)
        {
            Some(self.proxies.remove(idx))
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SelectedContext {
    pub org_id: String,
    pub org_name: String,
    pub project_id: String,
    pub project_name: String,
    /// Organization type (e.g. "personal", "team"). Invitations are only allowed when not "personal".
    #[serde(default)]
    pub org_type: String,
}

impl SelectedContext {
    pub fn label(&self) -> String {
        format!("{} / {}", self.org_name, self.project_name)
    }

    /// True if this org is a personal org (invitations not allowed).
    pub fn is_personal_org(&self) -> bool {
        self.org_type.eq_ignore_ascii_case("personal")
    }

    /// True if the user can send invitations (org is not personal and type is known).
    pub fn can_send_invite(&self) -> bool {
        !self.org_type.is_empty() && !self.is_personal_org()
    }
}

#[derive(Debug, Clone)]
pub struct StateWrapper {
    inner: Arc<ArcSwap<State>>,
    notify: Arc<Notify>,
    // Coordinates clones of this wrapper within one process. Atomic file
    // replacement prevents torn reads, but does not coordinate other processes.
    update_lock: Arc<Mutex<()>>,
}

impl StateWrapper {
    pub fn new(state: State) -> Self {
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(state))),
            notify: Default::default(),
            update_lock: Default::default(),
        }
    }

    pub fn get(&self) -> Guard<Arc<State>> {
        self.inner.load()
    }

    pub fn get_cloned(&self) -> Arc<State> {
        self.inner.load_full()
    }

    pub fn updated(&self) -> Notified<'_> {
        self.notify.notified()
    }

    /// Apply one state transaction against the latest contents on disk.
    ///
    /// The repository lock is advisory, so direct writers that ignore it are
    /// outside this transaction boundary. Notifications are process-local and
    /// are emitted only after this wrapper persists and publishes its update.
    /// If this future is cancelled, dropping it releases an acquired lock. A
    /// cancellation during the atomic write can leave an unused temporary file;
    /// the destination remains either the old or new complete state. If the
    /// rename completed before cancellation, disk can be newer than this
    /// wrapper, and the next update reconciles by reloading disk under the lock.
    pub async fn update<R>(
        &self,
        repo: &Repo,
        f: impl FnOnce(&mut State) -> R,
    ) -> n0_error::Result<R> {
        let _update_guard = self.update_lock.lock().await;
        let state_lock = repo.lock_state().await?;
        let mut inner = repo.read_or_initialize_state(&state_lock).await?;
        let res = f(&mut inner);
        let inner = Arc::new(inner);
        repo.write_state_locked(&inner, &state_lock).await?;
        self.inner.store(inner);
        self.notify.notify_waiters();
        Ok(res)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ProxyState {
    pub info: Advertisment,
    pub enabled: bool,
}

impl ProxyState {
    pub fn new(info: Advertisment) -> Self {
        Self {
            info,
            enabled: true,
        }
    }

    pub fn id(&self) -> &str {
        &self.info.resource_id
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Advertisment {
    pub resource_id: String,
    pub label: Option<String>,
    pub data: TcpProxyData,
}

impl Advertisment {
    pub fn new(data: TcpProxyData, label: Option<String>) -> Self {
        let resource_id = format!("proxy-{}", rand_str(12));
        Self {
            resource_id,
            data,
            label,
        }
    }

    pub fn with_id(resource_id: String, data: TcpProxyData, label: Option<String>) -> Self {
        Self {
            resource_id,
            data,
            label,
        }
    }

    pub fn id(&self) -> &str {
        &self.resource_id
    }

    pub fn label(&self) -> &str {
        self.label.as_deref().unwrap_or_else(|| self.id())
    }

    pub fn codename(&self) -> String {
        self.resource_id.clone()
    }

    pub fn service(&self) -> &TcpProxyData {
        &self.data
    }

    pub fn domain(&self) -> String {
        format!("{}.{}", self.id(), DATUM_CONNECT_GATEWAY_DOMAIN_NAME)
    }

    // TODO: Change to HTTPS
    pub fn datum_url(&self) -> String {
        format!("http://{}.{}", self.id(), DATUM_CONNECT_GATEWAY_DOMAIN_NAME)
    }

    // TODO: Not everything is HTTP
    pub fn local_url(&self) -> String {
        format!("http://{}", self.service().address())
    }

    pub fn datum_resource_url(&self) -> String {
        format!("datum://{}", self.id())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TcpProxyData {
    pub host: String,
    pub port: u16,
}

impl From<TcpProxyData> for Authority {
    fn from(value: TcpProxyData) -> Self {
        Self {
            host: value.host,
            port: value.port,
        }
    }
}

impl TcpProxyData {
    pub fn from_host_port_str(s: &str) -> Result<Self> {
        let (host, port) = Self::parse_host_port(s)?;
        Ok(Self { host, port })
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn parse_host_port(s: &str) -> Result<(String, u16)> {
        let (host, port) = s.rsplit_once(":").context("missing port")?;
        let port: u16 = port.parse().std_context("invalid port")?;
        Ok((host.to_string(), port))
    }
}

impl State {
    pub(crate) async fn from_file(path: PathBuf) -> Result<Self> {
        let data = tokio::fs::read(path).await?;
        let state: State = serde_yml::from_slice(&data).anyerr()?;
        Ok(state)
    }

    pub(crate) async fn write_to_file(&self, path: PathBuf) -> Result<()> {
        let data = serde_yml::to_string(&self).anyerr()?;
        crate::repo::atomic_write_private(&path, data.as_bytes()).await?;
        Ok(())
    }
}

impl Advertisment {
    pub fn ticket(&self, endpoint: EndpointId) -> AdvertismentTicket {
        AdvertismentTicket {
            data: self.clone(),
            endpoint,
        }
    }
}

fn rand_str(len: usize) -> String {
    rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .take(len)
        .map(char::from)
        .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdvertismentTicket {
    pub data: Advertisment,
    pub endpoint: EndpointId,
}

impl AdvertismentTicket {
    pub fn service(&self) -> &TcpProxyData {
        &self.data.data
    }
}

impl FromStr for AdvertismentTicket {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        iroh_tickets::Ticket::deserialize(s)
    }
}

impl Ticket for AdvertismentTicket {
    const KIND: &'static str = "datum";

    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&self).expect("serialize should work")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, iroh_tickets::ParseError> {
        let ticket: Self = postcard::from_bytes(bytes)?;
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo_dir() -> PathBuf {
        std::env::temp_dir().join(format!("datum-state-test-{}", uuid::Uuid::new_v4()))
    }

    fn proxy_with_id(id: impl Into<String>) -> ProxyState {
        ProxyState::new(Advertisment::with_id(
            id.into(),
            TcpProxyData {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            None,
        ))
    }

    #[test]
    fn parse_tcp_proxy_data_from_host_port() {
        let data = TcpProxyData::from_host_port_str("example.test:443").unwrap();
        assert_eq!(data.host, "example.test");
        assert_eq!(data.port, 443);
    }

    #[test]
    fn parse_tcp_proxy_data_rejects_missing_port() {
        let err = TcpProxyData::from_host_port_str("example.test").unwrap_err();
        assert!(err.to_string().contains("missing port"));
    }

    #[test]
    fn parse_tcp_proxy_data_rejects_invalid_port() {
        let err = TcpProxyData::from_host_port_str("example.test:abc").unwrap_err();
        assert!(err.to_string().contains("invalid port"));
    }

    #[tokio::test]
    async fn failed_persistence_does_not_publish_state_or_notify_waiters() {
        let directory = temp_repo_dir();
        let repo = Repo::open_or_create(&directory).await.unwrap();
        let wrapper = repo.load_state().await.unwrap();
        let notified = wrapper.updated();
        let state_path = directory.join("state.yml");

        let result = wrapper
            .update(&repo, |state| {
                std::fs::remove_file(&state_path).unwrap();
                std::fs::create_dir(&state_path).unwrap();
                state.set_proxy(proxy_with_id("proxy-failed"));
            })
            .await;

        assert!(result.is_err());
        assert!(wrapper.get().proxies.is_empty());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), notified)
                .await
                .is_err(),
            "failed writes must not announce an update"
        );
    }

    #[tokio::test]
    async fn concurrent_updates_are_serialized_without_lost_changes() {
        const UPDATE_COUNT: usize = 24;

        let directory = temp_repo_dir();
        let repo = Repo::open_or_create(&directory).await.unwrap();
        let wrapper = StateWrapper::new(State::default());
        let mut updates = tokio::task::JoinSet::new();

        for index in 0..UPDATE_COUNT {
            let repo = repo.clone();
            let wrapper = wrapper.clone();
            updates.spawn(async move {
                wrapper
                    .update(&repo, |state| {
                        state.set_proxy(proxy_with_id(format!("proxy-{index}")));
                    })
                    .await
            });
        }

        while let Some(result) = updates.join_next().await {
            result.unwrap().unwrap();
        }

        assert_eq!(wrapper.get().proxies.len(), UPDATE_COUNT);
        let persisted = State::from_file(directory.join("state.yml")).await.unwrap();
        assert_eq!(persisted.proxies.len(), UPDATE_COUNT);
        for index in 0..UPDATE_COUNT {
            let id = format!("proxy-{index}");
            assert!(persisted.proxies.iter().any(|proxy| proxy.id() == id));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn separately_opened_repositories_preserve_concurrent_updates() {
        const UPDATE_COUNT: usize = 24;

        let directory = temp_repo_dir();
        let first_repo = Repo::open_or_create(&directory).await.unwrap();
        let second_repo = Repo::open_or_create(&directory).await.unwrap();
        let first_wrapper = first_repo.load_state().await.unwrap();
        let second_wrapper = second_repo.load_state().await.unwrap();
        let start = Arc::new(tokio::sync::Barrier::new(UPDATE_COUNT));
        let mut updates = tokio::task::JoinSet::new();

        for index in 0..UPDATE_COUNT {
            let (repo, wrapper) = if index % 2 == 0 {
                (first_repo.clone(), first_wrapper.clone())
            } else {
                (second_repo.clone(), second_wrapper.clone())
            };
            let start = start.clone();
            updates.spawn(async move {
                start.wait().await;
                wrapper
                    .update(&repo, |state| {
                        state.set_proxy(proxy_with_id(format!("proxy-{index}")));
                    })
                    .await
            });
        }

        while let Some(result) = updates.join_next().await {
            result.unwrap().unwrap();
        }

        let persisted = State::from_file(directory.join("state.yml")).await.unwrap();
        assert_eq!(persisted.proxies.len(), UPDATE_COUNT);
        for index in 0..UPDATE_COUNT {
            let id = format!("proxy-{index}");
            assert!(persisted.proxies.iter().any(|proxy| proxy.id() == id));
        }
    }
}
