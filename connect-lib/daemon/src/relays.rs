//! Relay selection follows the pinned Cloud environment, not the user's shell context.
use iroh::{RelayMode, RelayUrl};

use crate::error::ApiError;

const STAGING_RELAYS: &str = "https://iroh-relay.us-central-1.datum-staging.net,https://iroh-relay.us-east-1.datum-staging.net";

/// Explicit configuration fails closed. Never silently fall back to another network.
pub fn parse(raw: &str) -> Result<Vec<RelayUrl>, ApiError> {
    let mut relays = Vec::new();
    for value in raw.split(',').map(str::trim) {
        let relay = value.parse::<RelayUrl>().map_err(|_| invalid())?;
        if relay.scheme() != "https"
            || relay.host_str().is_none()
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.query().is_some()
            || relay.fragment().is_some()
            || relay.path() != "/"
        {
            return Err(invalid());
        }
        if !relays.contains(&relay) {
            relays.push(relay);
        }
    }
    if relays.is_empty() {
        return Err(invalid());
    }
    Ok(relays)
}

fn invalid() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::BAD_REQUEST,
        "Relay configuration must be a nonempty comma-separated list of HTTPS origins, without credentials, paths, queries, or fragments",
    )
}

pub fn select(
    api_endpoint: &str,
    explicit: Option<&[RelayUrl]>,
) -> Result<Option<RelayMode>, ApiError> {
    let relays = if let Some(relays) = explicit {
        relays.to_vec()
    } else {
        let uri = api_endpoint
            .parse::<axum::http::Uri>()
            .map_err(|_| invalid())?;
        if uri.scheme_str() != Some("https") || uri.host() != Some("api.staging.env.datum.net") {
            return Ok(None);
        }
        parse(STAGING_RELAYS)?
    };
    tracing::info!(relays = ?relays, source = if explicit.is_some() { "explicit" } else { "datum-staging" }, "relay_configuration");
    Ok(Some(RelayMode::custom(relays)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires access to Datum staging relays"]
    async fn datum_staging_relays_accept_iroh_connections() {
        for relay in parse(STAGING_RELAYS).unwrap() {
            let transport = connect_transport::Transport::bind(
                connect_transport::TransportConfig::new(iroh::SecretKey::generate())
                    .relay_mode(RelayMode::custom([relay.clone()])),
            )
            .await
            .unwrap();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                transport.endpoint().online(),
            )
            .await;
            let details = transport.connection_details();
            transport.shutdown().await;
            result.unwrap_or_else(|_| panic!("staging relay did not connect: {relay}"));
            assert_eq!(details.relay_urls, vec![relay.to_string()]);
        }
    }

    #[test]
    fn only_exact_staging_environment_selects_staging_relays() {
        let mode = select("https://api.staging.env.datum.net", None)
            .unwrap()
            .unwrap();
        assert_eq!(mode, RelayMode::custom(parse(STAGING_RELAYS).unwrap()));
        for api in [
            "https://api.datum.net",
            "http://127.0.0.1:8000",
            "https://api.staging.env.datum.net.example.com",
            "http://api.staging.env.datum.net",
        ] {
            assert!(select(api, None).unwrap().is_none());
        }
    }

    #[test]
    fn explicit_relays_override_environment_and_deduplicate() {
        let relays = parse("https://relay.example.com, https://relay.example.com/").unwrap();
        assert_eq!(relays.len(), 1);
        assert_eq!(
            select("https://api.staging.env.datum.net", Some(&relays)).unwrap(),
            Some(RelayMode::custom(relays))
        );
    }

    #[test]
    fn invalid_configuration_never_falls_back_or_exposes_input() {
        for raw in [
            "",
            ",",
            "http://relay.example.com",
            "https://secret@relay.example.com",
            "https://relay.example.com/path",
            "https://relay.example.com/?token=secret",
            "https://relay.example.com/#secret",
        ] {
            let error = parse(raw).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
    }
}
