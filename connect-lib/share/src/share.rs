//! Sharer side: publish one local TCP service and admit paired peers.
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use connect_transport::{
    Access, DestinationId, DestinationPolicy, LocalStream, Policy, Target, Transport,
    TransportConfig,
};
use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, PathInfo, ShareTicket, configure_relays,
    pair::{PAIR_ALPN, PairingHandler, PairingProtocol},
    ticket::MAX_ADDRS,
    wait_online,
};

/// Inputs for one foreground share.
#[derive(Clone, Debug)]
pub struct ShareOptions {
    /// What to share.
    pub target: ShareTarget,
    /// Relays to use instead of the transport preset's defaults. An empty
    /// list disables relays.
    pub relay_urls: Option<Vec<RelayUrl>>,
    /// Distinct peers that may pair before pairing closes.
    pub max_peers: usize,
    /// Display name sent to peers when they pair, for example
    /// `laptop:9999`. Peers may rename it locally.
    pub name: Option<String>,
    /// Binds iroh's UDP socket to this port, for IPv4 and IPv6, instead of a
    /// random one, so a load balancer or firewall rule can forward to it.
    pub udp_port: Option<u16>,
    /// Addresses peers can reach this share at directly, such as a load
    /// balancer that forwards to `udp_port`. iroh only discovers the address
    /// it sends from, so these go in the ticket alongside the discovered ones,
    /// and are never dropped to fit its address limit.
    pub public_addrs: Vec<SocketAddr>,
}

/// Progress reported to the caller.
#[derive(Clone, Debug)]
pub enum ShareEvent {
    /// The service is reachable through `ticket`. `target` describes what is
    /// shared: the resolved socket address, or "in-process".
    Ready { ticket: ShareTicket, target: String },
    /// `peer` paired and may now open the service.
    Paired {
        peer: EndpointId,
        name: Option<String>,
    },
    /// The path to a paired `peer` changed. Reported only while that peer
    /// has a connection open.
    Path { peer: EndpointId, path: PathInfo },
}

/// The service a share forwards to.
#[derive(Clone, Debug)]
pub enum ShareTarget {
    /// A TCP `HOST:PORT`, resolved once when the share starts.
    Address(String),
    /// Sessions are delivered to `streams` in this process; nothing is
    /// dialed. For services without a reachable address of their own, such
    /// as on a unikernel with no loopback interface. `port` only names the
    /// destination in the ticket; nothing listens on it.
    InProcess {
        port: u16,
        streams: mpsc::Sender<LocalStream>,
    },
}

impl From<String> for ShareTarget {
    fn from(address: String) -> Self {
        Self::Address(address)
    }
}

impl From<&str> for ShareTarget {
    fn from(address: &str) -> Self {
        Self::Address(address.to_string())
    }
}

/// Shares `options.target` until `cancel` fires, then closes the endpoint.
pub async fn share(
    options: ShareOptions,
    cancel: CancellationToken,
    mut on_event: impl FnMut(ShareEvent),
) -> Result<(), Error> {
    // Resolve before binding so a bad address fails without an endpoint.
    let address = match &options.target {
        ShareTarget::Address(address) => Some(
            connect_transport::resolve_tcp_target(address)
                .await
                .map_err(|source| Error::Resolve {
                    target: address.clone(),
                    source,
                })?
                .ok_or_else(|| Error::Unresolved(address.clone()))?,
        ),
        ShareTarget::InProcess { .. } => None,
    };

    let secret: [u8; 32] = rand::random();
    let (handler, mut paired) = PairingHandler::new(secret, options.name, options.max_peers);
    let mut config = TransportConfig::new(SecretKey::generate())
        .protocol(PAIR_ALPN, Arc::new(PairingProtocol(handler)));
    if let Some(port) = options.udp_port {
        config = config.bind_port(port);
    }
    let (config, relays) = configure_relays(config, options.relay_urls);
    let public_addrs = options.public_addrs;
    let transport = Transport::bind(config)
        .await
        .map_err(|error| Error::Transport(error.to_string()))?;
    let (served, forwarder) = match (options.target, address) {
        (_, Some(address)) => (
            Served {
                port: address.port(),
                target: Target::Tcp(address),
                description: address.to_string(),
                public_addrs: public_addrs.clone(),
            },
            None,
        ),
        (ShareTarget::InProcess { port, streams }, None) => {
            let mut listener = transport.local_listener();
            let served = Served {
                port,
                target: listener.target(),
                description: "in-process".into(),
                public_addrs: public_addrs.clone(),
            };
            // Hand each authorized session to the caller until either side
            // goes away.
            let forwarder = tokio::spawn(async move {
                while let Some(stream) = listener.accept().await {
                    if streams.send(stream).await.is_err() {
                        break;
                    }
                }
            });
            (served, Some(forwarder))
        }
        (ShareTarget::Address(_), None) => unreachable!("addresses resolve above"),
    };
    let result = run(
        &transport,
        relays,
        &served,
        secret,
        &cancel,
        &mut paired,
        &mut on_event,
    )
    .await;
    if let Some(forwarder) = forwarder {
        forwarder.abort();
    }
    transport.shutdown().await;
    result
}

/// The endpoint's address with `public` added. Public addresses always fit
/// in the ticket; discovered direct addresses fill the remaining slots.
fn advertised(discovered: EndpointAddr, public: &[SocketAddr]) -> EndpointAddr {
    let mut out = EndpointAddr::new(discovered.id);
    for relay in discovered.relay_urls() {
        out = out.with_relay_url(relay.clone());
    }
    for addr in public.iter().take(MAX_ADDRS) {
        out = out.with_ip_addr(*addr);
    }
    let room = MAX_ADDRS.saturating_sub(out.ip_addrs().count());
    for addr in discovered
        .ip_addrs()
        .filter(|a| !public.contains(a))
        .take(room)
    {
        out = out.with_ip_addr(*addr);
    }
    out
}

/// What the share's single destination forwards to.
struct Served {
    /// Names the destination (`tcp-<port>`) and goes in the ticket.
    port: u16,
    target: Target,
    description: String,
    /// Advertised in the ticket ahead of discovered addresses.
    public_addrs: Vec<SocketAddr>,
}

async fn run(
    transport: &Transport,
    relays: bool,
    served: &Served,
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
        .replace_policy(share_policy(served, &peers))
        .await
        .map_err(|error| Error::Transport(error.to_string()))?;
    on_event(ShareEvent::Ready {
        ticket: ShareTicket {
            endpoint: advertised(transport.endpoint().addr(), &served.public_addrs),
            port: served.port,
            secret,
        },
        target: served.description.clone(),
    });
    tracing::info!(endpoint_id = %transport.endpoint_id(), target = %served.description, "share_ready");
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
            .replace_policy(share_policy(served, &peers))
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

/// One TCP destination, keyed by the served port, open only to `peers`.
fn share_policy(served: &Served, peers: &HashSet<EndpointId>) -> Policy {
    Policy {
        destinations: HashMap::from([(
            DestinationId::tcp(served.port),
            DestinationPolicy {
                target: served.target,
                access: Access::Peers(peers.clone()),
            },
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses_always_fit_in_the_ticket() {
        let id = SecretKey::generate().public();
        let mut discovered =
            EndpointAddr::new(id).with_relay_url("https://relay.example.net".parse().unwrap());
        for port in 1..=10 {
            discovered = discovered.with_ip_addr(SocketAddr::from(([10, 0, 0, 1], port)));
        }
        // Sorts after every discovered address, so a plain cap would drop it.
        let public: Vec<SocketAddr> = vec![
            "[2001:db8::1]:4433".parse().unwrap(),
            "203.0.113.9:4433".parse().unwrap(),
        ];
        let out = advertised(discovered, &public);
        let addrs: Vec<_> = out.ip_addrs().copied().collect();
        assert_eq!(addrs.len(), MAX_ADDRS);
        assert!(public.iter().all(|p| addrs.contains(p)), "{addrs:?}");
        assert_eq!(out.relay_urls().count(), 1);
    }
}
