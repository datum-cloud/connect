//! UniFFI surface over [`connect_share`] for the Datum Connect mobile apps.
//!
//! The surface is deliberately small: inspect a ticket, make a device key, and
//! start or stop one dial. Every call is synchronous for the caller; dials run
//! on a shared Tokio runtime owned by this library and report back through a
//! [`DialListener`].
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
};

use connect_share::{DialEvent, DialOptions, ShareTicket, dial};
use tokio_util::sync::CancellationToken;

uniffi::setup_scaffolding!();

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("connect-share")
        .build()
        .expect("start connect-share runtime")
});

/// Errors surfaced to the app.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ShareError {
    // Not `message`: that collides with Kotlin's Throwable.message.
    #[error("{reason}")]
    InvalidTicket { reason: String },
    #[error("device key must be 32 bytes")]
    InvalidKey,
}

/// What a ticket points at, for display before connecting.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TicketInfo {
    pub endpoint_id: String,
    pub port: u16,
    pub relay_urls: Vec<String>,
    pub direct_addresses: Vec<String>,
}

/// Parses a share ticket without contacting the sharer.
#[uniffi::export]
pub fn parse_ticket(ticket: String) -> Result<TicketInfo, ShareError> {
    let ticket = parse(&ticket)?;
    Ok(TicketInfo {
        endpoint_id: ticket.endpoint.id.to_string(),
        port: ticket.port,
        relay_urls: ticket
            .endpoint
            .relay_urls()
            .map(ToString::to_string)
            .collect(),
        direct_addresses: ticket
            .endpoint
            .ip_addrs()
            .map(ToString::to_string)
            .collect(),
    })
}

/// A new random device key. Store it privately and pass it to every dial so
/// the device keeps one identity.
#[uniffi::export]
pub fn generate_device_key() -> Vec<u8> {
    iroh::SecretKey::generate().to_bytes().to_vec()
}

/// The EndpointId for a device key, as shown to the sharer.
#[uniffi::export]
pub fn device_endpoint_id(device_key: Vec<u8>) -> Result<String, ShareError> {
    Ok(secret_key(&device_key)?.public().to_string())
}

/// How traffic reaches the sharer right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PathKind {
    /// Straight between the devices.
    Direct,
    /// Through an iroh relay.
    Relay,
    Unknown,
}

/// A path report. Sent when the path changes between direct and relayed or
/// to another address, and when latency moves by more than a quarter.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PathReport {
    pub kind: PathKind,
    /// The sharer's address on this path: an IP and port, or the relay URL.
    pub remote: Option<String>,
    pub rtt_ms: Option<u32>,
}

impl From<connect_share::PathInfo> for PathReport {
    fn from(path: connect_share::PathInfo) -> Self {
        Self {
            kind: match path.kind {
                connect_share::PathKind::Direct => PathKind::Direct,
                connect_share::PathKind::Relay => PathKind::Relay,
                connect_share::PathKind::Unknown => PathKind::Unknown,
            },
            remote: path.remote,
            rtt_ms: path
                .rtt
                .map(|rtt| rtt.as_millis().min(u32::MAX as u128) as u32),
        }
    }
}

/// Receives dial progress. Called from a library thread.
#[uniffi::export(with_foreign)]
pub trait DialListener: Send + Sync {
    /// Pairing succeeded and `local_addr` accepts connections.
    /// `sharer_name` is the sharer's name for the service, if it sent one.
    fn on_ready(&self, local_addr: String, sharer_name: Option<String>);
    /// The path to the sharer changed. Only reported while traffic flows.
    fn on_path(&self, path: PathReport);
    /// A local connection could not be forwarded, for example because the
    /// shared service is down. The dial keeps serving; `reason` says why.
    /// Reported again only after [`Self::on_forwarded`].
    fn on_connect_failed(&self, reason: String);
    /// A connection was forwarded after one or more failures: the shared
    /// service is reachable again.
    fn on_forwarded(&self);
    /// The dial ended. `error` is `None` after [`DialSession::stop`].
    fn on_stopped(&self, error: Option<String>);
}

/// One running dial. Dropping it does not stop it; call [`Self::stop`].
#[derive(uniffi::Object)]
pub struct DialSession {
    cancel: CancellationToken,
    local_addr: Mutex<Option<String>>,
}

#[uniffi::export]
impl DialSession {
    /// Pairs with the sharer named by `ticket`, then serves its service on
    /// `127.0.0.1:bind_port` (0 picks a free port).
    #[uniffi::constructor]
    pub fn start(
        ticket: String,
        bind_port: u16,
        device_key: Vec<u8>,
        device_name: Option<String>,
        listener: Arc<dyn DialListener>,
    ) -> Result<Arc<Self>, ShareError> {
        let ticket = parse(&ticket)?;
        let key = secret_key(&device_key)?;
        let session = Arc::new(Self {
            cancel: CancellationToken::new(),
            local_addr: Mutex::new(None),
        });
        let options = DialOptions {
            ticket,
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, bind_port)),
            secret_key: Some(key),
            name: device_name,
            relay_urls: None,
        };
        let task_session = session.clone();
        RUNTIME.spawn(async move {
            let ready_listener = listener.clone();
            let ready_session = task_session.clone();
            let result = dial(
                options,
                task_session.cancel.clone(),
                move |event| match event {
                    DialEvent::Ready(ready) => {
                        let addr = ready.local_addr.to_string();
                        *ready_session.local_addr.lock().expect("local_addr lock") =
                            Some(addr.clone());
                        ready_listener.on_ready(addr, ready.sharer_name);
                    }
                    DialEvent::Path(path) => ready_listener.on_path(path.into()),
                    DialEvent::ConnectFailed(reason) => ready_listener.on_connect_failed(reason),
                    DialEvent::Forwarded => ready_listener.on_forwarded(),
                },
            )
            .await;
            if let Err(error) = &result {
                tracing::warn!(%error, "share_ffi_dial_failed");
            }
            listener.on_stopped(result.err().map(|error| error.to_string()));
        });
        Ok(session)
    }

    /// Stops forwarding and closes the endpoint. Safe to call more than once.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// The local address once ready, for example `127.0.0.1:8888`.
    pub fn local_addr(&self) -> Option<String> {
        self.local_addr.lock().expect("local_addr lock").clone()
    }
}

fn parse(ticket: &str) -> Result<ShareTicket, ShareError> {
    ticket.parse().map_err(
        |error: connect_share::TicketError| ShareError::InvalidTicket {
            reason: error.to_string(),
        },
    )
}

fn secret_key(bytes: &[u8]) -> Result<iroh::SecretKey, ShareError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| ShareError::InvalidKey)?;
    Ok(iroh::SecretKey::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_round_trips_to_endpoint_id() {
        let key = generate_device_key();
        assert_eq!(key.len(), 32);
        let id = device_endpoint_id(key.clone()).unwrap();
        assert_eq!(
            id,
            iroh::SecretKey::from_bytes(&key.try_into().unwrap())
                .public()
                .to_string()
        );
        assert!(matches!(
            device_endpoint_id(vec![0; 31]),
            Err(ShareError::InvalidKey)
        ));
    }

    #[test]
    fn rejects_bad_ticket() {
        assert!(matches!(
            parse_ticket("nope".into()),
            Err(ShareError::InvalidTicket { .. })
        ));
    }
}
