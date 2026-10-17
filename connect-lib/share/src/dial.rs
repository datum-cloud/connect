//! Peer side: pair with a sharer, then serve its service on a local port.
use std::net::SocketAddr;

use connect_transport::{DestinationId, Transport, TransportConfig};
use iroh::{RelayUrl, SecretKey};
use tokio::{io::copy_bidirectional, net::TcpListener};
use tokio_util::sync::CancellationToken;

use crate::{Error, PathInfo, ShareTicket, configure_relays, pair::request_pairing, wait_online};

/// Inputs for one dial session.
#[derive(Clone, Debug)]
pub struct DialOptions {
    pub ticket: ShareTicket,
    /// Local listener address, for example `127.0.0.1:8888`. Port 0 picks one.
    pub bind: SocketAddr,
    /// Identity to dial from. A stable key lets a device reconnect to the
    /// same sharer without pairing again; `None` generates one.
    pub secret_key: Option<SecretKey>,
    /// Name shown to the sharer when pairing.
    pub name: Option<String>,
    /// Relays to use instead of the transport preset's defaults. An empty
    /// list disables relays.
    pub relay_urls: Option<Vec<RelayUrl>>,
}

/// Progress reported to the caller.
#[derive(Clone, Debug)]
pub enum DialEvent {
    /// Paired; the local listener accepts connections. Sent once.
    Ready(DialReady),
    /// The path to the sharer changed. Reported only while a connection is
    /// open, so it describes the most recent traffic.
    Path(PathInfo),
}

/// Reported once the local listener accepts connections.
#[derive(Clone, Debug)]
pub struct DialReady {
    pub local_addr: SocketAddr,
    /// The sharer's name for the service, when it sent one.
    pub sharer_name: Option<String>,
}

/// Pairs, then forwards each local connection over MASQUE CONNECT-TCP until
/// `cancel` fires.
pub async fn dial(
    options: DialOptions,
    cancel: CancellationToken,
    on_event: impl FnMut(DialEvent),
) -> Result<(), Error> {
    let key = options.secret_key.unwrap_or_else(SecretKey::generate);
    let (config, relays) = configure_relays(TransportConfig::new(key), options.relay_urls);
    // Bind (not client) so the endpoint has the MASQUE ALPN; the default
    // empty policy admits no inbound sessions.
    let transport = Transport::bind(config)
        .await
        .map_err(|error| Error::Transport(error.to_string()))?;
    let result = run(
        &transport,
        relays,
        options.ticket,
        options.bind,
        options.name,
        &cancel,
        on_event,
    )
    .await;
    if result.is_err() {
        // A graceful endpoint close waits for in-flight connections to drain,
        // which would hold back the error by seconds. Report it now and
        // finish closing in the background.
        tokio::spawn(async move { transport.shutdown().await });
    } else {
        transport.shutdown().await;
    }
    result
}

async fn run(
    transport: &Transport,
    relays: bool,
    ticket: ShareTicket,
    bind: SocketAddr,
    name: Option<String>,
    cancel: &CancellationToken,
    mut on_event: impl FnMut(DialEvent),
) -> Result<(), Error> {
    let mut paths = transport.path_updates();
    if relays && ticket.endpoint.relay_urls().next().is_some() {
        wait_online(transport).await?;
    }
    let sharer_name = request_pairing(
        &transport.endpoint(),
        ticket.endpoint.clone(),
        &ticket.secret,
        name.as_deref(),
    )
    .await?;
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|source| Error::Bind { addr: bind, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| Error::Bind { addr: bind, source })?;
    on_event(DialEvent::Ready(DialReady {
        local_addr,
        sharer_name,
    }));
    tracing::info!(%local_addr, sharer = %ticket.endpoint.id, "dial_ready");

    let destination = DestinationId::tcp(ticket.port);
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => accepted,
            update = paths.recv() => {
                match update {
                    Ok((peer, diagnostics)) if peer == ticket.endpoint.id => {
                        on_event(DialEvent::Path(diagnostics.into()));
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
                continue;
            }
        };
        let (mut local, _) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "dial_accept_failed");
                continue;
            }
        };
        let transport = transport.clone();
        let sharer = ticket.endpoint.clone();
        let destination = destination.clone();
        let stream_cancel = cancel.child_token();
        tokio::spawn(async move {
            match transport
                .connect_tcp(sharer, destination, stream_cancel)
                .await
            {
                Ok(mut remote) => {
                    if let Err(error) = copy_bidirectional(&mut local, &mut remote).await {
                        tracing::debug!(%error, "dial_forward_ended");
                    }
                }
                Err(error) => tracing::warn!(%error, "dial_connect_failed"),
            }
        });
    }
    Ok(())
}
