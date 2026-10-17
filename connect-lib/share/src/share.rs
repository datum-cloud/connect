//! Sharer side: publish one local TCP service and admit paired peers.
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig,
};
use iroh::{EndpointId, RelayUrl, SecretKey};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, PathInfo, ShareTicket, configure_relays,
    pair::{PAIR_ALPN, PairingHandler, PairingProtocol},
    wait_online,
};

/// Inputs for one foreground share.
#[derive(Clone, Debug)]
pub struct ShareOptions {
    /// Local `HOST:PORT` to share.
    pub target: String,
    /// Relays to use instead of the transport preset's defaults. An empty
    /// list disables relays.
    pub relay_urls: Option<Vec<RelayUrl>>,
    /// Distinct peers that may pair before pairing closes.
    pub max_peers: usize,
    /// Display name sent to peers when they pair, for example
    /// `laptop:9999`. Peers may rename it locally.
    pub name: Option<String>,
}

/// Progress reported to the caller.
#[derive(Clone, Debug)]
pub enum ShareEvent {
    /// The service is reachable through `ticket`.
    Ready {
        ticket: ShareTicket,
        target: SocketAddr,
    },
    /// `peer` paired and may now open the service.
    Paired {
        peer: EndpointId,
        name: Option<String>,
    },
    /// The path to a paired `peer` changed. Reported only while that peer
    /// has a connection open.
    Path { peer: EndpointId, path: PathInfo },
}

/// Shares `options.target` until `cancel` fires, then closes the endpoint.
pub async fn share(
    options: ShareOptions,
    cancel: CancellationToken,
    mut on_event: impl FnMut(ShareEvent),
) -> Result<(), Error> {
    let target = connect_transport::resolve_tcp_target(&options.target)
        .await
        .map_err(|source| Error::Resolve {
            target: options.target.clone(),
            source,
        })?
        .ok_or_else(|| Error::Unresolved(options.target.clone()))?;

    let secret: [u8; 32] = rand::random();
    let (handler, mut paired) = PairingHandler::new(secret, options.name, options.max_peers);
    let (config, relays) = configure_relays(
        TransportConfig::new(SecretKey::generate())
            .protocol(PAIR_ALPN, Arc::new(PairingProtocol(handler))),
        options.relay_urls,
    );
    let transport = Transport::bind(config)
        .await
        .map_err(|error| Error::Transport(error.to_string()))?;
    let result = run(
        &transport,
        relays,
        target,
        secret,
        &cancel,
        &mut paired,
        &mut on_event,
    )
    .await;
    transport.shutdown().await;
    result
}

async fn run(
    transport: &Transport,
    relays: bool,
    target: SocketAddr,
    secret: [u8; 32],
    cancel: &CancellationToken,
    paired: &mut tokio::sync::mpsc::UnboundedReceiver<crate::pair::Paired>,
    on_event: &mut impl FnMut(ShareEvent),
) -> Result<(), Error> {
    // Subscribe first so no report between pairing and the loop is lost.
    let mut paths = transport.path_updates();
    if relays {
        wait_online(transport).await?;
    }
    // No peer may open the destination until it pairs.
    let mut peers = HashSet::new();
    transport
        .replace_policy(share_policy(target, &peers))
        .await
        .map_err(|error| Error::Transport(error.to_string()))?;
    on_event(ShareEvent::Ready {
        ticket: ShareTicket {
            endpoint: transport.endpoint().addr(),
            port: target.port(),
            secret,
        },
        target,
    });
    tracing::info!(endpoint_id = %transport.endpoint_id(), %target, "share_ready");
    loop {
        let event = tokio::select! {
            _ = cancel.cancelled() => break,
            event = paired.recv() => event,
            update = paths.recv() => {
                match update {
                    // Only paired devices; other peers are refused anyway.
                    Ok((peer, diagnostics)) if peers.contains(&peer) => on_event(ShareEvent::Path {
                        peer,
                        path: diagnostics.into(),
                    }),
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
                continue;
            }
        };
        let Some(event) = event else { break };
        peers.insert(event.peer);
        transport
            .replace_policy(share_policy(target, &peers))
            .await
            .map_err(|error| Error::Transport(error.to_string()))?;
        tracing::info!(peer = %event.peer, name = ?event.name, "share_paired");
        on_event(ShareEvent::Paired {
            peer: event.peer,
            name: event.name,
        });
        // The pairing connection already reported this peer's path, before
        // the peer was paired, so later identical reports are not repeated.
        // Report the current path now.
        if let Some(diagnostics) = transport.peer_diagnostics(event.peer) {
            on_event(ShareEvent::Path {
                peer: event.peer,
                path: diagnostics.into(),
            });
        }
    }
    tracing::info!("share_stopped");
    Ok(())
}

/// One TCP destination, keyed by the target port, open only to `peers`.
pub(crate) fn share_policy(target: SocketAddr, peers: &HashSet<EndpointId>) -> Policy {
    Policy {
        destinations: HashMap::from([(
            DestinationId::tcp(target.port()),
            DestinationPolicy {
                target: Target::Tcp(target),
                access: Access::Peers(peers.clone()),
            },
        )]),
    }
}
