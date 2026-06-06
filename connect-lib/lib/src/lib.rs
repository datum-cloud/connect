pub mod config;
pub mod datum_apis;
pub mod datum_cloud;
pub mod http_user_agent;
pub mod node;
pub mod project_control_plane;
pub mod repo;
pub mod state;
pub mod tunnels;

// HeartbeatAgent — full implementation in Wave 3
pub mod heartbeat;

pub use config::{Config, DiscoveryMode};
pub use datum_cloud::external_token_source::{ExternalTokenError, ExternalTokenSource};
pub use datum_cloud::env::ApiEnv;
pub use datum_cloud::auth::{AuthClient, AuthState, AuthTokens, LoginState, MaybeAuth, UserProfile};
pub use http_user_agent::datum_http_user_agent;
pub use project_control_plane::ProjectControlPlaneClient;
pub use repo::Repo;
pub use state::{Advertisment, SelectedContext, State, StateWrapper, TcpProxyData};
pub use tunnels::{TunnelDeleteOutcome, TunnelService, TunnelSummary};

/// The root domain for datum connect URLs to subdomain from. A proxy URL will
/// be a three-word-codename subdomain off this URL. eg: "https://vast-gold-mine.iroh.datum.net"
pub const DATUM_CONNECT_GATEWAY_DOMAIN_NAME: &str = "iroh.datum.net";
