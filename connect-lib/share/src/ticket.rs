//! Share tickets: everything a peer needs to reach and pair with a sharer.
//!
//! Text form: `DCSHARE2` followed by unpadded RFC 4648 base32 of a compact
//! binary encoding. Every character is in the QR alphanumeric set, so QR
//! encoders use alphanumeric mode, which keeps the code small enough to scan
//! from a terminal. Parsing ignores case so a typed ticket also works.
//!
//! Binary layout (version 1):
//!
//! | Field | Size |
//! |---|---|
//! | version | 1 byte, `1` |
//! | endpoint id | 32 bytes |
//! | secret | 32 bytes |
//! | port | 2 bytes, big endian, nonzero |
//! | relay count, then each relay | 1 byte; 1-byte length + UTF-8 URL |
//! | address count, then each address | 1 byte; `4` + 4 bytes or `6` + 16 bytes, then 2-byte port |
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use data_encoding::BASE32_NOPAD;
use iroh::{EndpointAddr, EndpointId, RelayUrl};

const PREFIX: &str = "DCSHARE2";
const VERSION: u8 = 1;
const MAX_RELAYS: usize = 4;
/// Direct addresses beyond this are dropped to keep the QR code scannable;
/// the relay still reaches the sharer.
const MAX_ADDRS: usize = 6;

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

#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    #[error("not a Datum Connect share ticket")]
    Prefix,
    #[error("malformed share ticket")]
    Malformed,
}

impl ShareTicket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.push(VERSION);
        out.extend_from_slice(self.endpoint.id.as_bytes());
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.port.to_be_bytes());
        let relays: Vec<String> = self
            .endpoint
            .relay_urls()
            .map(ToString::to_string)
            .filter(|url| url.len() <= usize::from(u8::MAX))
            .take(MAX_RELAYS)
            .collect();
        out.push(relays.len() as u8);
        for relay in relays {
            out.push(relay.len() as u8);
            out.extend_from_slice(relay.as_bytes());
        }
        let addrs: Vec<SocketAddr> = self.endpoint.ip_addrs().copied().take(MAX_ADDRS).collect();
        out.push(addrs.len() as u8);
        for addr in addrs {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes);
        if reader.u8()? != VERSION {
            return None;
        }
        let id = EndpointId::from_bytes(&reader.array::<32>()?).ok()?;
        let secret = reader.array::<32>()?;
        let port = u16::from_be_bytes(reader.array::<2>()?);
        if port == 0 {
            return None;
        }
        let mut endpoint = EndpointAddr::new(id);
        for _ in 0..reader.u8()? {
            let len = usize::from(reader.u8()?);
            let url = std::str::from_utf8(reader.take(len)?).ok()?;
            endpoint = endpoint.with_relay_url(url.parse::<RelayUrl>().ok()?);
        }
        for _ in 0..reader.u8()? {
            let ip = match reader.u8()? {
                4 => IpAddr::V4(Ipv4Addr::from(reader.array::<4>()?)),
                6 => IpAddr::V6(Ipv6Addr::from(reader.array::<16>()?)),
                _ => return None,
            };
            let port = u16::from_be_bytes(reader.array::<2>()?);
            endpoint = endpoint.with_ip_addr(SocketAddr::new(ip, port));
        }
        if !reader.0.is_empty() {
            return None;
        }
        Some(Self {
            endpoint,
            port,
            secret,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
}

impl fmt::Display for ShareTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", BASE32_NOPAD.encode(&self.to_bytes()))
    }
}

impl FromStr for ShareTicket {
    type Err = TicketError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim().to_ascii_uppercase();
        let body = value.strip_prefix(PREFIX).ok_or(TicketError::Prefix)?;
        let bytes = BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| TicketError::Malformed)?;
        Self::from_bytes(&bytes).ok_or(TicketError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ShareTicket {
        let id = iroh::SecretKey::generate().public();
        ShareTicket {
            endpoint: EndpointAddr::new(id)
                .with_relay_url("https://use1-1.relay.n0.iroh.link./".parse().unwrap())
                .with_ip_addr("192.0.2.1:4433".parse().unwrap())
                .with_ip_addr("[2001:db8::1]:4433".parse().unwrap()),
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
        assert_eq!(text.to_lowercase().parse::<ShareTicket>().unwrap(), ticket);
    }

    #[test]
    fn uses_only_qr_alphanumeric_characters() {
        let text = sample().to_string();
        assert!(
            text.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "{text}"
        );
        // A typical ticket stays small enough for a QR version that scans
        // reliably from a terminal.
        assert!(text.len() < 260, "{} characters", text.len());
    }

    #[test]
    fn caps_direct_addresses() {
        let mut ticket = sample();
        for port in 1..=20 {
            ticket.endpoint = ticket
                .endpoint
                .with_ip_addr(SocketAddr::from(([10, 0, 0, 1], port)));
        }
        let parsed: ShareTicket = ticket.to_string().parse().unwrap();
        assert_eq!(parsed.endpoint.ip_addrs().count(), MAX_ADDRS);
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
            "DCSHARE2!!".parse::<ShareTicket>(),
            Err(TicketError::Malformed)
        ));
        let mut bytes = sample().to_bytes();
        bytes.push(0);
        let trailing = format!("{PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        assert!(matches!(
            trailing.parse::<ShareTicket>(),
            Err(TicketError::Malformed)
        ));
        let mut bytes = sample().to_bytes();
        bytes[0] = 2;
        let version = format!("{PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        assert!(matches!(
            version.parse::<ShareTicket>(),
            Err(TicketError::Malformed)
        ));
    }
}
