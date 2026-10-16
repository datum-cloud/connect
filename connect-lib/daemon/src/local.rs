//! Foreground, project-less publication of one local TCP service.
//!
//! Prototype for `datumctl connect local` (docs/design/project-less-local-tunnels.md).
//! The identity is generated in memory and never written to disk. There is no
//! broker yet, so the caller names the approved gateway identities explicitly.
//! Only those identities may open the advertised destination; public never
//! means arbitrary peers.
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};

use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig,
};
use iroh::{EndpointId, RelayMode, RelayUrl, SecretKey};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

/// Inputs for one foreground session.
#[derive(Clone, Debug)]
pub struct LocalOptions {
    /// Local `HOST:PORT` the tunnel forwards to.
    pub target: String,
    /// Gateway identities allowed to open the destination.
    pub gateway_peers: Vec<EndpointId>,
    /// Relays to use instead of the transport preset's defaults.
    pub relay_urls: Option<Vec<RelayUrl>>,
}

/// Printed once on stdout when the session is reachable.
#[derive(Debug, Serialize)]
pub struct LocalReady {
    pub event: &'static str,
    pub endpoint_id: String,
    pub relay_urls: Vec<String>,
    pub direct_addresses: Vec<SocketAddr>,
    pub target: SocketAddr,
    pub destination: String,
    pub gateway_peers: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error("at least one gateway peer is required")]
    NoGatewayPeers,
    #[error("resolving {target}: {source}")]
    Resolve {
        target: String,
        source: std::io::Error,
    },
    #[error("{0} did not resolve to an address")]
    Unresolved(String),
    #[error("starting transport: {0}")]
    Transport(String),
    #[error("could not connect to an iroh relay within 15 seconds")]
    RelayUnavailable,
}

/// Publishes `options.target` until `cancel` fires, then closes the endpoint.
/// `ready` receives the session details once a relay is connected.
pub async fn run(
    options: LocalOptions,
    cancel: CancellationToken,
    ready: impl FnOnce(&LocalReady),
) -> Result<(), LocalError> {
    if options.gateway_peers.is_empty() {
        return Err(LocalError::NoGatewayPeers);
    }
    let target = tokio::net::lookup_host(&options.target)
        .await
        .map_err(|source| LocalError::Resolve {
            target: options.target.clone(),
            source,
        })?
        .next()
        .ok_or_else(|| LocalError::Unresolved(options.target.clone()))?;

    let mut config = TransportConfig::new(SecretKey::generate());
    if let Some(relays) = options.relay_urls {
        config = config.relay_mode(RelayMode::custom(relays));
    }
    let transport = Transport::bind(config)
        .await
        .map_err(|error| LocalError::Transport(error.to_string()))?;

    // Gateways dial the relay address, so do not report ready without one.
    if tokio::time::timeout(Duration::from_secs(15), transport.endpoint().online())
        .await
        .is_err()
    {
        transport.shutdown().await;
        return Err(LocalError::RelayUnavailable);
    }

    let (destination, policy) = local_policy(target, options.gateway_peers.iter().copied());
    if let Err(error) = transport.replace_policy(policy).await {
        transport.shutdown().await;
        return Err(LocalError::Transport(error.to_string()));
    }

    let details = transport.connection_details();
    ready(&LocalReady {
        event: "local_ready",
        endpoint_id: details.endpoint_id.to_string(),
        relay_urls: details.relay_urls,
        direct_addresses: details.direct_addresses,
        target,
        destination: destination.to_string(),
        gateway_peers: options
            .gateway_peers
            .iter()
            .map(ToString::to_string)
            .collect(),
    });
    tracing::info!(endpoint_id = %details.endpoint_id, %target, "local_ready");

    cancel.cancelled().await;
    transport.shutdown().await;
    tracing::info!("local_stopped");
    Ok(())
}

/// One TCP destination, keyed by the target port, open only to `gateways`.
fn local_policy(
    target: SocketAddr,
    gateways: impl IntoIterator<Item = EndpointId>,
) -> (DestinationId, Policy) {
    let destination = DestinationId::tcp(target.port());
    let policy = Policy {
        destinations: HashMap::from([(
            destination.clone(),
            DestinationPolicy {
                target: Target::Tcp(target),
                access: Access::Peers(gateways.into_iter().collect::<HashSet<_>>()),
            },
        )]),
    };
    (destination, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_empty_gateway_peers() {
        let result = run(
            LocalOptions {
                target: "127.0.0.1:1".into(),
                gateway_peers: Vec::new(),
                relay_urls: None,
            },
            CancellationToken::new(),
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(LocalError::NoGatewayPeers)));
    }

    /// The gateway is a client transport, as in iroh-gateway's MASQUE mode.
    /// Only the approved gateway reaches the target; another peer is refused.
    #[tokio::test]
    async fn only_approved_gateway_reaches_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = origin.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4];
                    if stream.read_exact(&mut buf).await.is_ok() {
                        let _ = stream.write_all(b"pong").await;
                    }
                });
            }
        });

        let local_relays =
            || TransportConfig::new(SecretKey::generate()).relay_mode(RelayMode::Disabled);
        let gateway = Transport::bind(local_relays()).await.unwrap();
        let stranger = Transport::bind(local_relays()).await.unwrap();

        let cancel = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let session = tokio::spawn({
            let cancel = cancel.clone();
            let gateway_id = gateway.endpoint_id();
            async move {
                // Run without the relay wait: tests use direct addresses only.
                run_without_relay(origin_addr, gateway_id, cancel, ready_tx).await
            }
        });
        let (server_addr, destination) = ready_rx.await.unwrap();

        let mut stream = gateway
            .connect_tcp(
                server_addr.clone(),
                destination.clone(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");

        let denied = stranger
            .connect_tcp(server_addr, destination, CancellationToken::new())
            .await;
        assert!(denied.is_err(), "unapproved peer must be refused");

        cancel.cancel();
        session.await.unwrap();
        gateway.shutdown().await;
        stranger.shutdown().await;
    }

    /// Same policy as [`run`], minus the relay wait, for offline tests.
    async fn run_without_relay(
        target: SocketAddr,
        gateway: EndpointId,
        cancel: CancellationToken,
        ready: tokio::sync::oneshot::Sender<(iroh::EndpointAddr, DestinationId)>,
    ) {
        let transport = Transport::bind(
            TransportConfig::new(SecretKey::generate()).relay_mode(RelayMode::Disabled),
        )
        .await
        .unwrap();
        let (destination, policy) = local_policy(target, [gateway]);
        transport.replace_policy(policy).await.unwrap();
        let addr = transport.endpoint().addr();
        ready.send((addr, destination)).unwrap();
        cancel.cancelled().await;
        transport.shutdown().await;
    }
}
