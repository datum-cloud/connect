//! Share tickets: everything a peer needs to reach and pair with a sharer.
use std::{fmt, net::SocketAddr, str::FromStr};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "dcshare1";

/// A bearer capability to pair with one sharer for as long as it runs.
///
/// Anyone holding the ticket can pair, so treat it like a password. It
/// contains the sharer's relay URL and direct addresses, including LAN
/// addresses.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareTicket {
    pub endpoint: EndpointAddr,
    /// Port of the shared local service; also its MASQUE destination.
    pub port: u16,
    pub secret: [u8; 32],
}

impl fmt::Debug for ShareTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareTicket")
            .field("endpoint", &self.endpoint)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct Wire {
    id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    addrs: Vec<SocketAddr>,
    port: u16,
    secret: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    #[error("not a Datum Connect share ticket")]
    Prefix,
    #[error("malformed share ticket")]
    Malformed,
}

impl fmt::Display for ShareTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = Wire {
            id: self.endpoint.id.to_string(),
            relays: self
                .endpoint
                .relay_urls()
                .map(ToString::to_string)
                .collect(),
            addrs: self.endpoint.ip_addrs().copied().collect(),
            port: self.port,
            secret: URL_SAFE_NO_PAD.encode(self.secret),
        };
        let json = serde_json::to_vec(&wire).map_err(|_| fmt::Error)?;
        write!(f, "{PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }
}

impl FromStr for ShareTicket {
    type Err = TicketError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let body = value
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(TicketError::Prefix)?;
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TicketError::Malformed)?;
        let wire: Wire = serde_json::from_slice(&json).map_err(|_| TicketError::Malformed)?;
        let id = wire
            .id
            .parse::<EndpointId>()
            .map_err(|_| TicketError::Malformed)?;
        let mut endpoint = EndpointAddr::new(id);
        for relay in wire.relays {
            let relay = relay
                .parse::<RelayUrl>()
                .map_err(|_| TicketError::Malformed)?;
            endpoint = endpoint.with_relay_url(relay);
        }
        for addr in wire.addrs {
            endpoint = endpoint.with_ip_addr(addr);
        }
        let secret = URL_SAFE_NO_PAD
            .decode(wire.secret)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(TicketError::Malformed)?;
        if wire.port == 0 {
            return Err(TicketError::Malformed);
        }
        Ok(Self {
            endpoint,
            port: wire.port,
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ShareTicket {
        let id = iroh::SecretKey::generate().public();
        ShareTicket {
            endpoint: EndpointAddr::new(id)
                .with_relay_url("https://relay.example.net".parse().unwrap())
                .with_ip_addr("192.0.2.1:4433".parse().unwrap()),
            port: 9999,
            secret: [7; 32],
        }
    }

    #[test]
    fn round_trips() {
        let ticket = sample();
        let text = ticket.to_string();
        assert!(text.starts_with(PREFIX));
        assert_eq!(text.parse::<ShareTicket>().unwrap(), ticket);
    }

    #[test]
    fn debug_omits_secret() {
        let debug = format!("{:?}", sample());
        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn rejects_other_input() {
        assert!(matches!(
            "datumabc".parse::<ShareTicket>(),
            Err(TicketError::Prefix)
        ));
        assert!(matches!(
            "dcshare1!!".parse::<ShareTicket>(),
            Err(TicketError::Malformed)
        ));
        let short = format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(br#"{"id":"00","port":1,"secret":"AA"}"#)
        );
        assert!(matches!(
            short.parse::<ShareTicket>(),
            Err(TicketError::Malformed)
        ));
    }
}
