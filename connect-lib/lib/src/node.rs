// Stub — full implementation in Wave 3
// ListenNode for iroh endpoint management

use n0_error::Result;

use crate::{ProxyState, Repo, StateWrapper};

#[derive(Debug, Clone)]
pub struct ListenNode {
    _repo: Repo,
}

impl ListenNode {
    pub async fn new(_repo: Repo) -> Result<Self> {
        Ok(Self { _repo })
    }

    pub fn state(&self) -> &StateWrapper {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }

    pub fn endpoint(&self) -> &iroh::Endpoint {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }

    pub fn endpoint_id(&self) -> iroh::EndpointId {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }

    pub async fn set_proxy(&self, _proxy: ProxyState) -> Result<()> {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }

    pub async fn set_proxy_state(&self, _proxy: ProxyState) -> Result<()> {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }

    pub async fn remove_proxy(&self, _resource_id: &str) -> Result<Option<ProxyState>> {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }

    pub async fn remove_proxy_state(&self, _resource_id: &str) -> Result<Option<ProxyState>> {
        unimplemented!("ListenNode stub — full impl in Wave 3")
    }
}
