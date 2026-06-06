use std::{path::PathBuf, sync::Arc};

use arc_swap::{ArcSwap, Guard};
use n0_error::{Result, StackResultExt, StdResultExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, futures::Notified};

use crate::Repo;

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
}

impl StateWrapper {
    pub fn new(state: State) -> Self {
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(state))),
            notify: Default::default(),
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

    pub async fn update<R>(
        &self,
        repo: &Repo,
        f: impl FnOnce(&mut State) -> R,
    ) -> n0_error::Result<R> {
        let mut inner = (*self.inner.load_full()).clone();
        let res = f(&mut inner);
        let inner = Arc::new(inner);
        self.inner.store(inner.clone());
        repo.write_state(&inner).await?;
        self.notify.notify_waiters();
        Ok(res)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ProxyState {
    pub info: TcpProxyData,
    pub enabled: bool,
}

impl ProxyState {
    pub fn new(info: TcpProxyData) -> Self {
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
pub struct TcpProxyData {
    pub resource_id: String,
    pub host: String,
    pub port: u16,
}

impl TcpProxyData {
    pub fn from_host_port_str(resource_id: &str, s: &str) -> Result<Self> {
        let (host, port) = Self::parse_host_port(s)?;
        Ok(Self {
            resource_id: resource_id.to_string(),
            host,
            port,
        })
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
        tokio::fs::write(&path, &data).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_proxy_data_from_host_port() {
        let data = TcpProxyData::from_host_port_str("test-proxy", "example.test:443").unwrap();
        assert_eq!(data.host, "example.test");
        assert_eq!(data.port, 443);
    }

    #[test]
    fn parse_tcp_proxy_data_rejects_missing_port() {
        let err = TcpProxyData::from_host_port_str("test-proxy", "example.test").unwrap_err();
        assert!(err.to_string().contains("missing port"));
    }

    #[test]
    fn parse_tcp_proxy_data_rejects_invalid_port() {
        let err = TcpProxyData::from_host_port_str("test-proxy", "example.test:abc").unwrap_err();
        assert!(err.to_string().contains("invalid port"));
    }
}
