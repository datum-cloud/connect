//! Versioned client contract for the native Galactic CONNECT-IP provider.
//!
//! This module owns descriptor parsing and fail-closed plan verification. It
//! intentionally shares no field meanings with the legacy iroh gateway path.

use std::{collections::BTreeSet, fmt, net::Ipv6Addr};

use chrono::{DateTime, Utc};
use ipnet::Ipv6Net;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use async_trait::async_trait;

pub const TRANSPORT_TYPE: &str = "masque.connect.datum.net/v1";
pub const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/*/*/";
pub const EFFECTIVE_MTU: u16 = 1280;

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SensitiveCredential(String);

impl SensitiveCredential {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SensitiveCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionDescriptor {
    pub binding: String,
    pub policy_revision: String,
    pub network_plan: NetworkPlan,
    pub transport: TransportDescriptor,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPlan {
    pub expected_prefix: Ipv6Net,
    pub destination_prefixes: Vec<Ipv6Net>,
    pub mtu: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportDescriptor {
    #[serde(rename = "type")]
    pub kind: String,
    pub authority: String,
    pub vpc_selector: String,
    pub credential: SensitiveCredential,
    pub expires_at: DateTime<Utc>,
    pub transports: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPlan {
    pub host_address: Ipv6Addr,
    pub prefix: Ipv6Net,
    pub routes: Vec<Ipv6Net>,
    pub mtu: u16,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DescriptorError {
    #[error("unsupported managed transport descriptor")]
    UnsupportedTransport,
    #[error("invalid MASQUE authority")]
    InvalidAuthority,
    #[error("invalid or expired credential descriptor")]
    InvalidCredential,
    #[error("managed CONNECT-IP requires an IPv6 /96 and MTU 1280")]
    InvalidNetworkPlan,
    #[error("assigned prefix differs from the authorized network plan")]
    PrefixMismatch,
    #[error("advertised routes differ from the authorized network plan")]
    RouteMismatch,
}

impl ConnectionDescriptor {
    pub fn parse(input: &[u8], now: DateTime<Utc>) -> Result<Self, DescriptorError> {
        let descriptor: Self =
            serde_json::from_slice(input).map_err(|_| DescriptorError::UnsupportedTransport)?;
        descriptor.validate(now)?;
        Ok(descriptor)
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), DescriptorError> {
        if self.binding.is_empty()
            || self.policy_revision.is_empty()
            || self.transport.kind != TRANSPORT_TYPE
            || self.transport.transports.is_empty()
            || self
                .transport
                .transports
                .iter()
                .any(|transport| transport != "h3" && transport != "h2")
            || self.transport.transports[0] != "h3"
        {
            return Err(DescriptorError::UnsupportedTransport);
        }
        let authority = Url::parse(&format!("https://{}", self.transport.authority))
            .map_err(|_| DescriptorError::InvalidAuthority)?;
        if authority.host_str().is_none()
            || authority.username() != ""
            || authority.password().is_some()
            || authority.path() != "/"
            || authority.query().is_some()
            || authority.fragment().is_some()
            || self.transport.vpc_selector.is_empty()
        {
            return Err(DescriptorError::InvalidAuthority);
        }
        if self.transport.credential.0.is_empty() || self.transport.expires_at <= now {
            return Err(DescriptorError::InvalidCredential);
        }
        if self.network_plan.expected_prefix.prefix_len() != 96
            || self.network_plan.mtu != EFFECTIVE_MTU
            || self.network_plan.destination_prefixes.is_empty()
            || self
                .network_plan
                .destination_prefixes
                .iter()
                .any(|prefix| prefix.prefix_len() == 0)
        {
            return Err(DescriptorError::InvalidNetworkPlan);
        }
        Ok(())
    }

    /// Verify provider capsules before the networking helper is asked to
    /// create an interface or route. Equality is intentional: a subset is a
    /// stale plan and a superset broadens authority.
    pub fn verify_provider_plan(
        &self,
        assigned: Ipv6Net,
        advertised: &[Ipv6Net],
    ) -> Result<VerifiedPlan, DescriptorError> {
        if assigned != self.network_plan.expected_prefix {
            return Err(DescriptorError::PrefixMismatch);
        }
        let expected = self
            .network_plan
            .destination_prefixes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let observed = advertised.iter().copied().collect::<BTreeSet<_>>();
        if expected != observed || advertised.len() != observed.len() {
            return Err(DescriptorError::RouteMismatch);
        }
        let host = Ipv6Addr::from(u128::from(assigned.network()) + 1);
        Ok(VerifiedPlan {
            host_address: host,
            prefix: assigned,
            routes: expected.into_iter().collect(),
            mtu: EFFECTIVE_MTU,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptFailure {
    Connectivity,
    HttpStatus(u16),
    TlsIdentity,
    PlanMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    TryHttp2,
    RemintOnce,
    StopUntilBindingChanges,
    RetryWithBackoff,
    TerminalSecurityFailure,
    FailClosed,
    TerminalProtocolFailure,
}

pub fn recovery_for(transport: &str, failure: AttemptFailure) -> Recovery {
    match failure {
        AttemptFailure::Connectivity if transport == "h3" => Recovery::TryHttp2,
        AttemptFailure::HttpStatus(401) => Recovery::RemintOnce,
        AttemptFailure::HttpStatus(403) => Recovery::StopUntilBindingChanges,
        AttemptFailure::HttpStatus(503) => Recovery::RetryWithBackoff,
        AttemptFailure::TlsIdentity => Recovery::TerminalSecurityFailure,
        AttemptFailure::PlanMismatch => Recovery::FailClosed,
        _ => Recovery::TerminalProtocolFailure,
    }
}

#[derive(Clone, Debug)]
pub struct ObservedProviderPlan {
    pub assigned: Ipv6Net,
    pub advertised: Vec<Ipv6Net>,
}

#[async_trait]
pub trait ConnectIpDialer: Send + Sync {
    async fn dial(
        &self,
        transport: &str,
        descriptor: &ConnectionDescriptor,
    ) -> Result<ObservedProviderPlan, AttemptFailure>;
}

#[async_trait]
pub trait NetworkActivator: Send + Sync {
    async fn activate(&self, plan: VerifiedPlan) -> Result<(), String>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EstablishError {
    #[error("CONNECT-IP failed: {0:?}")]
    Transport(AttemptFailure),
    #[error(transparent)]
    Plan(#[from] DescriptorError),
    #[error("local networking activation failed")]
    Activation,
}

/// Dedicated Galactic adapter orchestration. H2 is attempted only after an H3
/// connectivity failure. Provider setup is verified before activation.
pub async fn establish<D: ConnectIpDialer, A: NetworkActivator>(
    descriptor: &ConnectionDescriptor,
    dialer: &D,
    activator: &A,
) -> Result<VerifiedPlan, EstablishError> {
    let observed = match dialer.dial("h3", descriptor).await {
        Ok(plan) => plan,
        Err(failure)
            if recovery_for("h3", failure) == Recovery::TryHttp2
                && descriptor
                    .transport
                    .transports
                    .iter()
                    .any(|transport| transport == "h2") =>
        {
            dialer
                .dial("h2", descriptor)
                .await
                .map_err(EstablishError::Transport)?
        }
        Err(failure) => return Err(EstablishError::Transport(failure)),
    };
    let verified = descriptor
        .verify_provider_plan(observed.assigned, &observed.advertised)
        .map_err(EstablishError::Plan)?;
    activator
        .activate(verified.clone())
        .await
        .map_err(|_| EstablishError::Activation)?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 4, 20, 0, 0).unwrap()
    }

    fn descriptor() -> ConnectionDescriptor {
        let input = br#"{
          "binding":"laptop-production","policyRevision":"rev-1",
          "networkPlan":{"expectedPrefix":"fd20:0:27:10:1:1::/96","destinationPrefixes":["fd20:0:27::/48"],"mtu":1280},
          "transport":{"type":"masque.connect.datum.net/v1","authority":"masque.example.test","vpcSelector":"default/vpc","credential":"opaque-secret","expiresAt":"2026-11-04T20:01:00Z","transports":["h3","h2"]}
        }"#;
        ConnectionDescriptor::parse(input, now()).unwrap()
    }

    #[test]
    fn parses_and_redacts_descriptor() {
        let descriptor = descriptor();
        assert_eq!(descriptor.transport.credential.expose(), "opaque-secret");
        let rendered = format!("{descriptor:?}");
        assert!(!rendered.contains("opaque-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn verifies_assignment_and_routes_before_activation() {
        let descriptor = descriptor();
        let assigned = "fd20:0:27:10:1:1::/96".parse().unwrap();
        let routes = vec!["fd20:0:27::/48".parse().unwrap()];
        let verified = descriptor.verify_provider_plan(assigned, &routes).unwrap();
        assert_eq!(
            verified.host_address,
            "fd20:0:27:10:1:1::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(verified.mtu, 1280);
        assert_eq!(
            descriptor.verify_provider_plan("fd20:0:27:10:1:2::/96".parse().unwrap(), &routes),
            Err(DescriptorError::PrefixMismatch)
        );
        assert_eq!(
            descriptor.verify_provider_plan(assigned, &["fd20:0:27::/49".parse().unwrap()]),
            Err(DescriptorError::RouteMismatch)
        );
    }

    #[test]
    fn fallback_and_application_failures_are_distinct() {
        assert_eq!(
            recovery_for("h3", AttemptFailure::Connectivity),
            Recovery::TryHttp2
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(401)),
            Recovery::RemintOnce
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(403)),
            Recovery::StopUntilBindingChanges
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(503)),
            Recovery::RetryWithBackoff
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::TlsIdentity),
            Recovery::TerminalSecurityFailure
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::PlanMismatch),
            Recovery::FailClosed
        );
        assert_eq!(
            recovery_for("h3", AttemptFailure::HttpStatus(500)),
            Recovery::TerminalProtocolFailure
        );
    }

    struct FakeDialer {
        failures: Mutex<Vec<Result<ObservedProviderPlan, AttemptFailure>>>,
        attempts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ConnectIpDialer for FakeDialer {
        async fn dial(
            &self,
            transport: &str,
            _descriptor: &ConnectionDescriptor,
        ) -> Result<ObservedProviderPlan, AttemptFailure> {
            self.attempts.lock().unwrap().push(transport.to_owned());
            self.failures.lock().unwrap().remove(0)
        }
    }

    #[derive(Default)]
    struct FakeActivator(Mutex<Vec<VerifiedPlan>>);

    #[async_trait]
    impl NetworkActivator for FakeActivator {
        async fn activate(&self, plan: VerifiedPlan) -> Result<(), String> {
            self.0.lock().unwrap().push(plan);
            Ok(())
        }
    }

    fn observed(prefix: &str, route: &str) -> ObservedProviderPlan {
        ObservedProviderPlan {
            assigned: prefix.parse().unwrap(),
            advertised: vec![route.parse().unwrap()],
        }
    }

    #[tokio::test]
    async fn activation_waits_for_verified_provider_plan() {
        let dialer = FakeDialer {
            failures: Mutex::new(vec![Ok(observed(
                "fd20:0:27:10:1:2::/96",
                "fd20:0:27::/48",
            ))]),
            attempts: Mutex::new(vec![]),
        };
        let activator = FakeActivator::default();
        assert_eq!(
            establish(&descriptor(), &dialer, &activator).await,
            Err(EstablishError::Plan(DescriptorError::PrefixMismatch))
        );
        assert!(activator.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn falls_back_only_for_h3_connectivity() {
        let dialer = FakeDialer {
            failures: Mutex::new(vec![
                Err(AttemptFailure::Connectivity),
                Ok(observed("fd20:0:27:10:1:1::/96", "fd20:0:27::/48")),
            ]),
            attempts: Mutex::new(vec![]),
        };
        let activator = FakeActivator::default();
        establish(&descriptor(), &dialer, &activator).await.unwrap();
        assert_eq!(&*dialer.attempts.lock().unwrap(), &["h3", "h2"]);
        assert_eq!(activator.0.lock().unwrap().len(), 1);

        let denied = FakeDialer {
            failures: Mutex::new(vec![Err(AttemptFailure::HttpStatus(403))]),
            attempts: Mutex::new(vec![]),
        };
        assert_eq!(
            establish(&descriptor(), &denied, &activator).await,
            Err(EstablishError::Transport(AttemptFailure::HttpStatus(403)))
        );
        assert_eq!(&*denied.attempts.lock().unwrap(), &["h3"]);
    }
}
