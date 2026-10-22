//! Project-less sharing of one local TCP service.
//!
//! `datumctl connect local` runs [`share`]: it publishes one local port under
//! an in-memory iroh identity and prints a [`ShareTicket`]. A peer that holds
//! the ticket runs [`dial`]: it proves it knows the ticket's secret over the
//! pairing ALPN, and the sharer then adds that peer's EndpointId to the
//! destination's allowlist. Traffic uses the same MASQUE CONNECT-TCP transport
//! as project-scoped Connect.
//!
//! No Datum Cloud credentials, projects, or stored state are involved. See
//! `docs/design/project-less-local-tunnels.md`.

mod dial;
mod key;
mod pair;
mod path;
mod share;
mod ticket;

pub use connect_transport::LocalStream;
pub use dial::{
    DialEvent, DialOptions, DialReady, LIVENESS_GRACE, LIVENESS_INTERVAL, SHARER_LOST_TIMEOUT, dial,
};
pub use key::{KeyError, ShareKey};
pub use pair::{PAIR_ALPN, PAIR_TIMEOUT};
pub use path::{PathInfo, PathKind};
pub use share::{ShareEvent, ShareOptions, ShareTarget, share};
pub use ticket::{ShareTicket, TicketError};

/// Errors from either side of a share.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("resolving {target}: {source}")]
    Resolve {
        target: String,
        source: std::io::Error,
    },
    #[error("{0} did not resolve to an address")]
    Unresolved(String),
    #[error("binding {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error("transport: {0}")]
    Transport(String),
    #[error("could not connect to an iroh relay within 15 seconds")]
    RelayUnavailable,
    #[error("pairing failed: {0}")]
    Pairing(String),
    /// The sharer did not answer within [`PAIR_TIMEOUT`], or a ready dial's
    /// sharer stopped answering for [`LIVENESS_GRACE`]: usually its share
    /// stopped, or restarted with a new key, which ends the ticket.
    #[error("ticket no longer reachable")]
    Unreachable,
}

/// `None` keeps the transport preset's relays. An empty list disables relays,
/// leaving only direct addresses (same-LAN use and offline tests).
fn configure_relays(
    config: connect_transport::TransportConfig,
    relay_urls: Option<Vec<iroh::RelayUrl>>,
) -> (connect_transport::TransportConfig, bool) {
    match relay_urls {
        None => (config, true),
        Some(relays) if relays.is_empty() => (config.relay_mode(iroh::RelayMode::Disabled), false),
        Some(relays) => (config.relay_mode(iroh::RelayMode::custom(relays)), true),
    }
}

/// Waits for a home relay so the ticket carries an address peers can always reach.
async fn wait_online(transport: &connect_transport::Transport) -> Result<(), Error> {
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        transport.endpoint().online(),
    )
    .await
    .map_err(|_| Error::RelayUnavailable)
}
