//! Shared policy and failure mapping for standards-facing MASQUE listeners.

use std::{collections::HashSet, io, net::IpAddr};

use h3::ext::Protocol;
use http::{Method, Request, Response, StatusCode};

use crate::Error;

const TARGET_HOST_VARIABLE: &str = "{target_host}";
const TARGET_PORT_VARIABLE: &str = "{target_port}";

/// A bounded RFC 9298 URI template containing one host and one port variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectUdpUriTemplate {
    source: String,
    prefix: String,
    middle: String,
    suffix: String,
    host_first: bool,
}

impl ConnectUdpUriTemplate {
    /// Parses a path-only template with each required variable exactly once.
    pub fn parse(source: impl Into<String>) -> Result<Self, Error> {
        let source = source.into();
        if source.len() > 2_048
            || !source.starts_with('/')
            || source.contains('?')
            || source.contains('#')
            || source.matches(TARGET_HOST_VARIABLE).count() != 1
            || source.matches(TARGET_PORT_VARIABLE).count() != 1
        {
            return Err(Error::Protocol("invalid CONNECT-UDP URI template".into()));
        }
        let host = source.find(TARGET_HOST_VARIABLE).expect("count checked");
        let port = source.find(TARGET_PORT_VARIABLE).expect("count checked");
        let (prefix, middle, suffix, host_first) = if host < port {
            (
                source[..host].to_owned(),
                source[host + TARGET_HOST_VARIABLE.len()..port].to_owned(),
                source[port + TARGET_PORT_VARIABLE.len()..].to_owned(),
                true,
            )
        } else {
            (
                source[..port].to_owned(),
                source[port + TARGET_PORT_VARIABLE.len()..host].to_owned(),
                source[host + TARGET_HOST_VARIABLE.len()..].to_owned(),
                false,
            )
        };
        if middle.is_empty()
            || prefix.contains('{')
            || prefix.contains('}')
            || middle.contains('{')
            || middle.contains('}')
            || suffix.contains('{')
            || suffix.contains('}')
        {
            return Err(Error::Protocol("invalid CONNECT-UDP URI template".into()));
        }
        Ok(Self {
            source,
            prefix,
            middle,
            suffix,
            host_first,
        })
    }

    /// Returns the configured path template for advertisement.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Expands the template using RFC 6570 simple-string percent encoding.
    pub fn expand(&self, host: &str, port: u16) -> Result<String, Error> {
        validate_host(host)?;
        let host = encode_template_value(host);
        let port = port.to_string();
        let (first, second) = if self.host_first {
            (host.as_str(), port.as_str())
        } else {
            (port.as_str(), host.as_str())
        };
        Ok(format!(
            "{}{}{}{}{}",
            self.prefix, first, self.middle, second, self.suffix
        ))
    }

    /// Validates an HTTP/3 CONNECT-UDP request and extracts its target tuple.
    pub fn target(&self, request: &Request<()>) -> Result<(String, u16), Error> {
        if request.method() != Method::CONNECT
            || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP)
            || request.uri().scheme_str() != Some("https")
            || request.uri().authority().is_none()
            || !super::capsule_protocol_enabled(request.headers())
            || request.uri().query().is_some()
        {
            return Err(Error::Protocol("invalid CONNECT-UDP request".into()));
        }
        let path = request.uri().path();
        let body = path
            .strip_prefix(&self.prefix)
            .and_then(|path| path.strip_suffix(&self.suffix))
            .ok_or_else(|| Error::Protocol("CONNECT-UDP URI does not match template".into()))?;
        let (first, second) = body
            .split_once(&self.middle)
            .ok_or_else(|| Error::Protocol("CONNECT-UDP URI does not match template".into()))?;
        if first.is_empty() || second.is_empty() || second.contains(&self.middle) {
            return Err(Error::Protocol(
                "ambiguous CONNECT-UDP URI template expansion".into(),
            ));
        }
        let (host, port) = if self.host_first {
            (decode_template_value(first)?, second)
        } else {
            (decode_template_value(second)?, first)
        };
        validate_host(&host)?;
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::Protocol("invalid CONNECT-UDP target port".into()))?;
        Ok((host, port))
    }
}

impl Default for ConnectUdpUriTemplate {
    fn default() -> Self {
        Self::parse("/.well-known/masque/udp/{target_host}/{target_port}/")
            .expect("default CONNECT-UDP template is valid")
    }
}

/// RFC 9209 header used to report proxy failures without exposing internals.
pub const PROXY_STATUS_HEADER: &str = "proxy-status";

/// Stable failure categories returned by a MASQUE edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasqueFailure {
    MalformedRequest,
    ForbiddenTarget,
    Overloaded,
    Draining,
    ConnectionTimeout,
    ConnectionRefused,
    DestinationUnavailable,
    Internal,
}

impl MasqueFailure {
    /// HTTP status associated with this failure.
    pub const fn status(self) -> StatusCode {
        match self {
            Self::MalformedRequest => StatusCode::BAD_REQUEST,
            Self::ForbiddenTarget => StatusCode::FORBIDDEN,
            Self::Overloaded | Self::Draining => StatusCode::SERVICE_UNAVAILABLE,
            Self::ConnectionTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::ConnectionRefused | Self::DestinationUnavailable => StatusCode::BAD_GATEWAY,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Registered RFC 9209 proxy error token.
    pub const fn proxy_error(self) -> &'static str {
        match self {
            Self::MalformedRequest => "http_protocol_error",
            Self::ForbiddenTarget => "destination_ip_prohibited",
            Self::Overloaded | Self::Draining | Self::Internal => "proxy_internal_error",
            Self::ConnectionTimeout => "connection_timeout",
            Self::ConnectionRefused => "connection_refused",
            Self::DestinationUnavailable => "destination_unavailable",
        }
    }

    /// Builds a response with a bounded, detail-free RFC 9209 Proxy-Status.
    pub fn response(self) -> Response<()> {
        Response::builder()
            .status(self.status())
            .header(
                PROXY_STATUS_HEADER,
                format!("datum-connect; error={}", self.proxy_error()),
            )
            .body(())
            .expect("static MASQUE failure response")
    }

    /// Maps a Connect backend failure to the edge response category.
    pub fn from_backend_error(error: &Error) -> Self {
        match error {
            Error::Timeout => Self::ConnectionTimeout,
            Error::Io(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                Self::ConnectionRefused
            }
            Error::Rejected(status) if *status == StatusCode::GATEWAY_TIMEOUT => {
                Self::ConnectionTimeout
            }
            Error::Rejected(status) if *status == StatusCode::SERVICE_UNAVAILABLE => {
                Self::DestinationUnavailable
            }
            Error::Rejected(_) | Error::Closed | Error::DatagramTooLarge => {
                Self::DestinationUnavailable
            }
            Error::InvalidDestinationId | Error::MissingDestination | Error::Protocol(_) => {
                Self::Internal
            }
            Error::Io(_) => Self::DestinationUnavailable,
        }
    }
}

/// Reason a target was rejected before any network activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TargetPolicyError {
    #[error("target is not allowlisted")]
    NotAllowlisted,
    #[error("hostname targets require an explicit allowlist entry")]
    HostnameNotAllowlisted,
    #[error("metadata-service targets are prohibited")]
    Metadata,
    #[error("loopback targets are prohibited")]
    Loopback,
    #[error("link-local targets are prohibited")]
    LinkLocal,
    #[error("private targets are prohibited")]
    Private,
    #[error("unspecified targets are prohibited")]
    Unspecified,
    #[error("multicast targets are prohibited")]
    Multicast,
    #[error("non-routable targets are prohibited")]
    NonRoutable,
}

/// Closed-by-default target policy for a standards-facing MASQUE listener.
///
/// Exact allowlist entries take precedence, allowing a deployment to opt into
/// a private or loopback service without enabling that entire address class.
/// Unlisted hostnames are always rejected so DNS resolution and rebinding
/// controls remain the caller's explicit responsibility.
#[derive(Clone, Debug, Default)]
pub struct TargetSecurityPolicy {
    allowed: HashSet<(String, u16)>,
    allow_unlisted_public_ips: bool,
    allow_private_ips: bool,
    allow_loopback: bool,
    allow_link_local: bool,
}

impl TargetSecurityPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one exact host and port. IP spellings are canonicalized.
    pub fn allow_target(mut self, host: impl Into<String>, port: u16) -> Self {
        let host = canonical_host(host.into());
        self.allowed.insert((host, port));
        self
    }

    /// Allows unlisted, globally routable numeric IP targets.
    pub fn allow_unlisted_public_ips(mut self, allow: bool) -> Self {
        self.allow_unlisted_public_ips = allow;
        self
    }

    /// Allows all private/unique-local numeric targets when public IPs are enabled.
    pub fn allow_private_ips(mut self, allow: bool) -> Self {
        self.allow_private_ips = allow;
        self
    }

    /// Allows all loopback numeric targets when public IPs are enabled.
    pub fn allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    /// Allows all link-local numeric targets when public IPs are enabled.
    /// Known metadata-service addresses remain blocked unless exactly listed.
    pub fn allow_link_local(mut self, allow: bool) -> Self {
        self.allow_link_local = allow;
        self
    }

    /// Authorizes a decoded RFC 9298 target tuple without resolving DNS.
    pub fn authorize(&self, host: &str, port: u16) -> Result<(), TargetPolicyError> {
        let canonical = canonical_host(host.to_owned());
        if self.allowed.contains(&(canonical, port)) {
            return Ok(());
        }
        let ip = host
            .parse::<IpAddr>()
            .map_err(|_| TargetPolicyError::HostnameNotAllowlisted)?;
        let ip = match ip {
            IpAddr::V6(ip) => ip.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        if !self.allow_unlisted_public_ips {
            return Err(TargetPolicyError::NotAllowlisted);
        }
        if is_metadata(ip) {
            return Err(TargetPolicyError::Metadata);
        }
        if ip.is_unspecified() {
            return Err(TargetPolicyError::Unspecified);
        }
        if ip.is_multicast() {
            return Err(TargetPolicyError::Multicast);
        }
        if ip.is_loopback() && !self.allow_loopback {
            return Err(TargetPolicyError::Loopback);
        }
        if is_link_local(ip) && !self.allow_link_local {
            return Err(TargetPolicyError::LinkLocal);
        }
        if is_private(ip) && !self.allow_private_ips {
            return Err(TargetPolicyError::Private);
        }
        if is_non_routable(ip) {
            return Err(TargetPolicyError::NonRoutable);
        }
        Ok(())
    }
}

fn canonical_host(host: String) -> String {
    host.parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| host.to_ascii_lowercase())
}

fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets() == [169, 254, 169, 254] || ip.octets() == [169, 254, 170, 2],
        IpAddr::V6(ip) => ip.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254],
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_non_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_broadcast()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && matches!(b, 18 | 19))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

fn validate_host(host: &str) -> Result<(), Error> {
    if host.is_empty()
        || host.len() > 255
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'/')
    {
        return Err(Error::Protocol("invalid CONNECT-UDP target host".into()));
    }
    Ok(())
}

fn encode_template_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn decode_template_value(value: &str) -> Result<String, Error> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let digits = bytes
            .get(index + 1..index + 3)
            .ok_or_else(|| Error::Protocol("invalid CONNECT-UDP percent encoding".into()))?;
        decoded.push((decode_hex(digits[0])? << 4) | decode_hex(digits[1])?);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| Error::Protocol("CONNECT-UDP target host is not UTF-8".into()))
}

fn decode_hex(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Protocol(
            "invalid CONNECT-UDP percent encoding".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_status_mapping_is_stable_and_detail_free() {
        let cases = [
            (MasqueFailure::MalformedRequest, 400, "http_protocol_error"),
            (
                MasqueFailure::ForbiddenTarget,
                403,
                "destination_ip_prohibited",
            ),
            (MasqueFailure::Overloaded, 503, "proxy_internal_error"),
            (MasqueFailure::ConnectionTimeout, 504, "connection_timeout"),
            (MasqueFailure::ConnectionRefused, 502, "connection_refused"),
            (
                MasqueFailure::DestinationUnavailable,
                502,
                "destination_unavailable",
            ),
            (MasqueFailure::Internal, 500, "proxy_internal_error"),
        ];
        for (failure, status, token) in cases {
            let response = failure.response();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(
                response.headers()[PROXY_STATUS_HEADER],
                format!("datum-connect; error={token}")
            );
            assert_eq!(response.headers().len(), 1);
        }
    }

    #[test]
    fn backend_errors_map_without_leaking_details() {
        assert_eq!(
            MasqueFailure::from_backend_error(&Error::Timeout),
            MasqueFailure::ConnectionTimeout
        );
        assert_eq!(
            MasqueFailure::from_backend_error(&Error::Io(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "secret origin name",
            ))),
            MasqueFailure::ConnectionRefused
        );
        assert_eq!(
            MasqueFailure::from_backend_error(&Error::Protocol("sensitive".into())),
            MasqueFailure::Internal
        );
    }

    #[test]
    fn target_policy_is_closed_and_exact_allowlist_overrides_special_ranges() {
        let policy = TargetSecurityPolicy::new().allow_target("127.0.0.1", 5353);
        assert_eq!(policy.authorize("127.0.0.1", 5353), Ok(()));
        assert_eq!(
            policy.authorize("127.0.0.1", 53),
            Err(TargetPolicyError::NotAllowlisted)
        );
        assert_eq!(
            policy.authorize("8.8.8.8", 53),
            Err(TargetPolicyError::NotAllowlisted)
        );
        assert_eq!(
            policy.authorize("example.com", 443),
            Err(TargetPolicyError::HostnameNotAllowlisted)
        );
    }

    #[test]
    fn public_mode_blocks_internal_metadata_and_non_routable_ranges() {
        let policy = TargetSecurityPolicy::new().allow_unlisted_public_ips(true);
        assert_eq!(policy.authorize("8.8.8.8", 53), Ok(()));
        for (target, expected) in [
            ("127.0.0.1", TargetPolicyError::Loopback),
            ("::ffff:127.0.0.1", TargetPolicyError::Loopback),
            ("::127.0.0.1", TargetPolicyError::Loopback),
            ("10.0.0.1", TargetPolicyError::Private),
            ("169.254.1.1", TargetPolicyError::LinkLocal),
            ("169.254.169.254", TargetPolicyError::Metadata),
            ("::ffff:169.254.169.254", TargetPolicyError::Metadata),
            ("169.254.170.2", TargetPolicyError::Metadata),
            ("0.0.0.0", TargetPolicyError::Unspecified),
            ("224.0.0.1", TargetPolicyError::Multicast),
            ("192.0.2.1", TargetPolicyError::NonRoutable),
            ("100.64.0.1", TargetPolicyError::NonRoutable),
            ("198.18.0.1", TargetPolicyError::NonRoutable),
            ("fd00:ec2::254", TargetPolicyError::Metadata),
            ("fe80::1", TargetPolicyError::LinkLocal),
            ("fc00::1", TargetPolicyError::Private),
            ("2001:db8::1", TargetPolicyError::NonRoutable),
        ] {
            assert_eq!(policy.authorize(target, 80), Err(expected), "{target}");
        }
    }

    #[test]
    fn address_class_exceptions_are_configurable_but_metadata_stays_explicit() {
        let policy = TargetSecurityPolicy::new()
            .allow_unlisted_public_ips(true)
            .allow_private_ips(true)
            .allow_loopback(true)
            .allow_link_local(true);
        assert_eq!(policy.authorize("127.0.0.2", 80), Ok(()));
        assert_eq!(policy.authorize("10.0.0.1", 80), Ok(()));
        assert_eq!(policy.authorize("169.254.1.1", 80), Ok(()));
        assert_eq!(
            policy.authorize("169.254.169.254", 80),
            Err(TargetPolicyError::Metadata)
        );
    }

    #[test]
    fn configurable_uri_template_round_trips_and_rejects_ambiguity() {
        let template = ConnectUdpUriTemplate::parse(
            "/tenant/acme/udp/{target_host}/port/{target_port}/session",
        )
        .unwrap();
        assert_eq!(
            template.expand("2001:db8::53", 5353).unwrap(),
            "/tenant/acme/udp/2001%3Adb8%3A%3A53/port/5353/session"
        );
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://proxy.example/tenant/acme/udp/2001%3Adb8%3A%3A53/port/5353/session")
            .header(super::super::CAPSULE_PROTOCOL_HEADER, "?1")
            .body(())
            .unwrap();
        request.extensions_mut().insert(Protocol::CONNECT_UDP);
        assert_eq!(
            template.target(&request).unwrap(),
            ("2001:db8::53".to_owned(), 5353)
        );

        for invalid in [
            "/udp/{target_host}/only",
            "/udp/{target_host}{target_port}/",
            "/udp/{target_host}/{target_port}/{extra}",
            "relative/{target_host}/{target_port}",
        ] {
            assert!(ConnectUdpUriTemplate::parse(invalid).is_err(), "{invalid}");
        }
    }
}
