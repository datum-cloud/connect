//! The network path to a peer, as reported while connections are open.
use std::time::Duration;

use connect_transport::{ConnectionPath, PeerDiagnostics};

/// How traffic to a peer travels right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// Straight between the two devices over UDP.
    Direct,
    /// Forwarded by an iroh relay, because no direct path works yet or at all.
    Relay,
    Unknown,
}

impl PathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Unknown => "unknown",
        }
    }
}

/// A path report: sent when the path changes between direct and relayed or
/// to another address, and when latency moves by more than a quarter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathInfo {
    pub kind: PathKind,
    /// The peer's address on this path: an IP and port, or the relay URL.
    pub remote: Option<String>,
    pub rtt: Option<Duration>,
}

impl From<PeerDiagnostics> for PathInfo {
    fn from(diagnostics: PeerDiagnostics) -> Self {
        Self {
            kind: match diagnostics.path {
                ConnectionPath::Direct => PathKind::Direct,
                ConnectionPath::Relay => PathKind::Relay,
                ConnectionPath::Unknown => PathKind::Unknown,
            },
            remote: diagnostics.detail,
            rtt: diagnostics.latency,
        }
    }
}
