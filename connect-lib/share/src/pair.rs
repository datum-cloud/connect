//! Pairing: a peer proves it holds the ticket secret, and the sharer learns
//! the peer's EndpointId from the authenticated QUIC connection.
//!
//! One bidirectional stream per connection. The peer sends one JSON
//! [`Request`] and finishes its side; the sharer replies with one JSON
//! [`Response`]. The peer's identity is never taken from the request body.
use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connect_transport::ProtocolHandler;
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::Error;

/// ALPN for the pairing exchange. Shares the transport's endpoint identity.
pub const PAIR_ALPN: &[u8] = b"datum-connect/share-pair/1";

const MAX_MESSAGE: usize = 1024;
const MAX_NAME: usize = 64;

#[derive(Serialize, Deserialize)]
struct Request {
    secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// A peer that presented the right secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Paired {
    pub peer: EndpointId,
    pub name: Option<String>,
}

/// Sharer-side handler registered on the transport for [`PAIR_ALPN`].
pub(crate) struct PairingHandler {
    secret: [u8; 32],
    max_peers: usize,
    paired: Mutex<HashSet<EndpointId>>,
    events: mpsc::UnboundedSender<Paired>,
}

impl PairingHandler {
    pub fn new(secret: [u8; 32], max_peers: usize) -> (Arc<Self>, mpsc::UnboundedReceiver<Paired>) {
        let (events, rx) = mpsc::unbounded_channel();
        let handler = Arc::new(Self {
            secret,
            max_peers,
            paired: Mutex::new(HashSet::new()),
            events,
        });
        (handler, rx)
    }

    /// Decides one request. Re-pairing an already approved peer succeeds and
    /// does not count against the limit.
    fn admit(&self, peer: EndpointId, request: &Request) -> Result<Option<Paired>, &'static str> {
        let presented = URL_SAFE_NO_PAD
            .decode(&request.secret)
            .map_err(|_| "invalid secret")?;
        if !constant_time_eq(&presented, &self.secret) {
            return Err("invalid secret");
        }
        let mut paired = self.paired.lock().expect("pairing lock poisoned");
        if paired.contains(&peer) {
            return Ok(None);
        }
        if paired.len() >= self.max_peers {
            return Err("pairing limit reached");
        }
        paired.insert(peer);
        let name = request.name.as_deref().map(|name| {
            name.chars()
                .filter(|c| !c.is_control())
                .take(MAX_NAME)
                .collect()
        });
        Ok(Some(Paired { peer, name }))
    }

    async fn serve(self: Arc<Self>, conn: Connection) -> Result<(), String> {
        let peer = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| e.to_string())?;
        let body = recv
            .read_to_end(MAX_MESSAGE)
            .await
            .map_err(|e| e.to_string())?;
        let decision = match serde_json::from_slice::<Request>(&body) {
            Ok(request) => self.admit(peer, &request),
            Err(_) => Err("malformed request"),
        };
        let response = match &decision {
            Ok(_) => Response {
                ok: true,
                error: None,
            },
            Err(error) => Response {
                ok: false,
                error: Some((*error).to_owned()),
            },
        };
        let reply = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
        send.write_all(&reply).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        // Let the peer read the reply; it closes the connection when done.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.closed()).await;
        match decision {
            Ok(Some(paired)) => {
                let _ = self.events.send(paired);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => {
                tracing::warn!(%peer, error, "share_pair_rejected");
                Err(error.to_owned())
            }
        }
    }
}

/// Adapter that lets the transport hold the shared handler.
pub(crate) struct PairingProtocol(pub Arc<PairingHandler>);

impl ProtocolHandler for PairingProtocol {
    fn accept(
        &self,
        conn: Connection,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>> {
        Box::pin(self.0.clone().serve(conn))
    }
}

/// Peer side: presents `secret` to `sharer` from `endpoint`'s identity.
pub(crate) async fn request_pairing(
    endpoint: &Endpoint,
    sharer: EndpointAddr,
    secret: &[u8; 32],
    name: Option<&str>,
) -> Result<(), Error> {
    let conn = endpoint
        .connect(sharer, PAIR_ALPN)
        .await
        .map_err(|e| Error::Pairing(e.to_string()))?;
    let result = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        let request = Request {
            secret: URL_SAFE_NO_PAD.encode(secret),
            name: name.map(str::to_owned),
        };
        let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        send.write_all(&body).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        let reply = recv
            .read_to_end(MAX_MESSAGE)
            .await
            .map_err(|e| e.to_string())?;
        let response: Response = serde_json::from_slice(&reply).map_err(|e| e.to_string())?;
        if response.ok {
            Ok(())
        } else {
            Err(response.error.unwrap_or_else(|| "rejected".into()))
        }
    }
    .await;
    conn.close(0u32.into(), b"done");
    result.map_err(Error::Pairing)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(secret: &[u8], name: Option<&str>) -> Request {
        Request {
            secret: URL_SAFE_NO_PAD.encode(secret),
            name: name.map(str::to_owned),
        }
    }

    #[test]
    fn admits_right_secret_once_and_enforces_limit() {
        let (handler, _rx) = PairingHandler::new([1; 32], 1);
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        assert_eq!(
            handler
                .admit(a, &request(&[1; 32], Some("phone\n")))
                .unwrap(),
            Some(Paired {
                peer: a,
                name: Some("phone".into())
            })
        );
        assert_eq!(handler.admit(a, &request(&[1; 32], None)).unwrap(), None);
        assert_eq!(
            handler.admit(b, &request(&[1; 32], None)).unwrap_err(),
            "pairing limit reached"
        );
    }

    #[test]
    fn rejects_wrong_secret() {
        let (handler, _rx) = PairingHandler::new([1; 32], 4);
        let a = iroh::SecretKey::generate().public();
        assert_eq!(
            handler.admit(a, &request(&[2; 32], None)).unwrap_err(),
            "invalid secret"
        );
        assert_eq!(
            handler.admit(a, &request(&[1; 31], None)).unwrap_err(),
            "invalid secret"
        );
    }
}
