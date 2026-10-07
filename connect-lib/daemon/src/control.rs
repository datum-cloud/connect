use async_trait::async_trait;
use serde::Serialize;

use crate::{
    error::ApiError,
    model::{ConnectorState, DialState, ServiceState},
};

#[derive(Debug, Clone, Serialize)]
pub struct PingResult {
    pub address: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ServiceOutcome {
    pub hostnames: Vec<String>,
    pub ready: bool,
}

/// Boundary between durable desired state and the live Cloud/iroh runtime.
/// Implementations must make each operation idempotent; restart reconciliation
/// deliberately repeats operations whose prior observed result was not saved.
#[async_trait]
pub trait Control: Send + Sync + 'static {
    async fn validate_credentials(&self, credentials_file: &str) -> Result<(), ApiError>;

    async fn up(&self, project: &str, credentials_file: &str) -> Result<ConnectorState, ApiError>;

    async fn resume(
        &self,
        project: &str,
        credentials_file: &str,
        expected: &ConnectorState,
    ) -> Result<ConnectorState, ApiError>;

    async fn down(&self, project: &str) -> Result<(), ApiError>;

    async fn resolve_peer_key(&self, _project: &str, _peer: &str) -> Result<String, ApiError> {
        Err(ApiError::new(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "peer identity resolution is unavailable",
        ))
    }

    async fn reconcile_service(
        &self,
        project: &str,
        service: &ServiceState,
    ) -> Result<ServiceOutcome, ApiError>;

    async fn pause_service(&self, project: &str, service: &ServiceState) -> Result<(), ApiError>;

    async fn delete_service(&self, project: &str, service: &ServiceState) -> Result<(), ApiError>;

    async fn reconcile_dial(&self, project: &str, dial: &DialState) -> Result<u16, ApiError>;

    async fn delete_dial(&self, project: &str, port: u16) -> Result<(), ApiError>;

    async fn ping(&self, project: &str, address: &str) -> Result<PingResult, ApiError>;

    async fn diagnostics(&self, _project: &str) -> serde_json::Value {
        serde_json::Value::Null
    }

    async fn shutdown(&self);

    async fn join_network(
        &self,
        _project: &str,
        _network: &str,
    ) -> Result<serde_json::Value, ApiError> {
        Err(ApiError::new(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "VPC attachment is unavailable. The Linux local CONNECT-IP prototype requires daemon --local-ip-config; no production NetworkBinding is created",
        ))
    }
    async fn leave_network(
        &self,
        _project: &str,
        _network: &str,
    ) -> Result<serde_json::Value, ApiError> {
        Err(ApiError::new(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "Local CONNECT-IP is not configured on this daemon",
        ))
    }
    /// Return the exact local privileged-helper approval for a controller-
    /// managed VPC attachment, creating its Connector-owned API binding first.
    /// `None` means the named network is not managed by a ConnectGateway.
    async fn managed_network_setup(
        &self,
        _project: &str,
        _network: &str,
    ) -> Result<Option<serde_json::Value>, ApiError> {
        Ok(None)
    }
    async fn networks(&self, _project: &str) -> serde_json::Value {
        serde_json::json!([])
    }
    #[cfg(feature = "networking")]
    async fn prepare_network(
        &self,
        _project: &str,
        _request: &crate::networking::PrepareRequest,
    ) -> Result<crate::peer_ip::Binding, ApiError> {
        Err(ApiError::new(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "Managed peer networking is unavailable on this daemon",
        ))
    }
}

/// Used only until the real control-plane/transport adapter has been
/// constructed during process startup. It fails closed and never reports a
/// network operation as successful.
pub struct UnsupportedControl;

#[async_trait]
impl Control for UnsupportedControl {
    async fn validate_credentials(&self, _credentials_file: &str) -> Result<(), ApiError> {
        self.unsupported()
    }
    async fn up(
        &self,
        _project: &str,
        _credentials_file: &str,
    ) -> Result<ConnectorState, ApiError> {
        Err(ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "network control is not initialized",
        ))
    }
    async fn resume(
        &self,
        _project: &str,
        _credentials_file: &str,
        _expected: &ConnectorState,
    ) -> Result<ConnectorState, ApiError> {
        self.unsupported()
    }
    async fn down(&self, _project: &str) -> Result<(), ApiError> {
        Ok(())
    }
    async fn reconcile_service(
        &self,
        _project: &str,
        _service: &ServiceState,
    ) -> Result<ServiceOutcome, ApiError> {
        self.unsupported()
    }
    async fn pause_service(&self, _project: &str, _service: &ServiceState) -> Result<(), ApiError> {
        self.unsupported()
    }
    async fn delete_service(
        &self,
        _project: &str,
        _service: &ServiceState,
    ) -> Result<(), ApiError> {
        self.unsupported()
    }
    async fn reconcile_dial(&self, _project: &str, _dial: &DialState) -> Result<u16, ApiError> {
        self.unsupported()
    }
    async fn delete_dial(&self, _project: &str, _port: u16) -> Result<(), ApiError> {
        self.unsupported()
    }
    async fn ping(&self, _project: &str, _address: &str) -> Result<PingResult, ApiError> {
        self.unsupported()
    }
    async fn shutdown(&self) {}
}

impl UnsupportedControl {
    fn unsupported<T>(&self) -> Result<T, ApiError> {
        Err(ApiError::new(
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "this network operation is unsupported by the current platform",
        ))
    }
}
