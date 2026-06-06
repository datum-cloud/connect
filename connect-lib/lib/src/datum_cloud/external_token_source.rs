use std::env;

use arc_swap::ArcSwap;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::watch;
use tracing::debug;

use super::env::ApiEnv;

/// Errors that can occur when constructing an [`ExternalTokenSource`] from environment.
#[derive(Debug, thiserror::Error)]
pub enum ExternalTokenError {
    #[error("DATUM_ACCESS_TOKEN environment variable not set")]
    MissingToken,
    #[error("DATUM_CREDENTIALS_HELPER environment variable not set")]
    MissingHelper,
    #[error("invalid JWT token: {0}")]
    InvalidToken(String),
    #[error("failed to parse JWT payload: {0}")]
    JwtParse(#[source] serde_json::Error),
}

/// Manages a bearer token provided from an external source (env var + credentials helper).
///
/// Used in plugin mode.
#[derive(Clone)]
pub struct ExternalTokenSource {
    token: std::sync::Arc<ArcSwap<SecretString>>,
    token_tx: std::sync::Arc<watch::Sender<String>>,
    api_host: String,
}

impl std::fmt::Debug for ExternalTokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalTokenSource")
            .field("api_host", &self.api_host)
            .finish_non_exhaustive()
    }
}

impl ExternalTokenSource {
    /// Reads `DATUM_ACCESS_TOKEN`, `DATUM_CREDENTIALS_HELPER`, and optional
    /// `DATUM_API_HOST` from the environment, parses the JWT for expiry, and
    /// returns a configured [`ExternalTokenSource`].
    pub fn from_env() -> Result<Self, ExternalTokenError> {
        let token =
            env::var("DATUM_ACCESS_TOKEN").map_err(|_| ExternalTokenError::MissingToken)?;

        let _helper =
            env::var("DATUM_CREDENTIALS_HELPER").map_err(|_| ExternalTokenError::MissingHelper)?;

        let api_host =
            env::var("DATUM_API_HOST")
                .unwrap_or_else(|_| ApiEnv::Production.api_url().to_string());

        let exp = parse_jwt_expiry(&token).map_err(|e| {
            ExternalTokenError::InvalidToken(format!("failed to extract expiry: {e}"))
        })?;

        debug!(
            token_len = token.len(),
            exp = ?exp,
            "ExternalTokenSource::from_env — token loaded"
        );

        let (token_tx, _) = watch::channel(token.clone());

        Ok(Self {
            token: std::sync::Arc::new(ArcSwap::from_pointee(SecretString::new(token.clone().into()))),
            token_tx: std::sync::Arc::new(token_tx),
            api_host,
        })
    }

    /// Returns the current token as a plain `String`.
    pub fn token(&self) -> String {
        self.token.load_full().expose_secret().to_string()
    }

    /// Returns a watch channel subscriber for token updates.
    pub fn watch(&self) -> watch::Receiver<String> {
        self.token_tx.subscribe()
    }

    /// Returns the API host string.
    pub fn api_host(&self) -> &str {
        &self.api_host
    }

    /// Atomically swaps the token and notifies watch subscribers.
    pub fn swap_token(&self, new_token: String) {
        debug!(new_token_len = new_token.len(), "ExternalTokenSource::swap_token");
        self.token.store(std::sync::Arc::new(SecretString::new(new_token.clone().into())));
        let _ = self.token_tx.send(new_token);
    }
}

/// Parse the `exp` (expiry) claim from the middle segment of a JWT.
///
/// Returns `None` if the claim is missing (caller may default to 1 h).
fn parse_jwt_expiry(token: &str) -> Result<Option<u64>, JwtParseError> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return Err(JwtParseError::InvalidToken(
            "JWT must have at least 2 segments (header.payload[.signature])".into(),
        ));
    }

    let payload_b64 = parts[1];

    // Base64url decode: replace URL-safe chars with standard base64 chars, then pad.
    let mut standard_b64 = payload_b64.replace('-', "+").replace('_', "/");
    let pad = 4 - standard_b64.len() % 4;
    if pad != 4 {
        standard_b64.extend((0..pad).map(|_| '='));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&standard_b64)
        .map_err(|e| JwtParseError::InvalidBase64(e.to_string()))?;

    let payload_str =
        String::from_utf8(decoded).map_err(|e| JwtParseError::InvalidUtf8(e.to_string()))?;

    let value: serde_json::Value =
        serde_json::from_str(&payload_str).map_err(JwtParseError::Json)?;

    Ok(value.get("exp").and_then(|v| v.as_u64()))
}

#[derive(Debug, thiserror::Error)]
enum JwtParseError {
    #[error("invalid JWT format: {0}")]
    InvalidToken(String),
    #[error("invalid base64url encoding: {0}")]
    InvalidBase64(String),
    #[error("invalid UTF-8 in JWT payload: {0}")]
    InvalidUtf8(String),
    #[error("failed to parse JWT payload as JSON: {0}")]
    Json(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a JWT-like string with a given exp claim.
    fn make_jwt_with_exp(exp: u64) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({"alg":"HS256","typ":"JWT"}).to_string().as_bytes(),
        );
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({"exp": exp, "sub":"test-user"}).to_string().as_bytes(),
        );
        format!("{header}.{payload}.fake_signature_here")
    }

    #[test]
    fn parse_jwt_expiry_extracts_exp() {
        let token = make_jwt_with_exp(1700000000);
        let exp = parse_jwt_expiry(&token).unwrap().unwrap();
        assert_eq!(exp, 1700000000);
    }

    #[test]
    fn parse_jwt_expiry_returns_none_when_missing() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({"sub":"test-user"}).to_string().as_bytes(),
        );
        let token = format!("{header}.{payload}.sig");
        let exp = parse_jwt_expiry(&token).unwrap();
        assert!(exp.is_none());
    }

    #[test]
    fn parse_jwt_expiry_rejects_too_short() {
        let result = parse_jwt_expiry("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn parse_jwt_expiry_rejects_invalid_base64() {
        let token = format!("header.!!!.sig");
        let result = parse_jwt_expiry(&token);
        assert!(result.is_err());
    }

    #[test]
    fn parse_jwt_expiry_rejects_invalid_json() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-json");
        let token = format!("{header}.{payload}.sig");
        let result = parse_jwt_expiry(&token);
        assert!(result.is_err());
    }

    #[test]
    fn parse_jwt_expiry_handles_url_safe_chars() {
        let payload_json = serde_json::json!({"exp": 9999999999u64, "sub": "test"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            payload_json.to_string().as_bytes(),
        );
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload_b64}.sig");
        let exp = parse_jwt_expiry(&token).unwrap().unwrap();
        assert_eq!(exp, 9999999999);
    }

    #[test]
    fn from_env_requires_datum_access_token() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("DATUM_ACCESS_TOKEN");
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let result = ExternalTokenSource::from_env();
        assert!(matches!(result, Err(ExternalTokenError::MissingToken)));
    }

    #[test]
    fn from_env_requires_datum_credentials_helper() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::remove_var("DATUM_CREDENTIALS_HELPER");
        }
        let result = ExternalTokenSource::from_env();
        assert!(matches!(result, Err(ExternalTokenError::MissingHelper)));
    }

    #[test]
    fn from_env_succeeds_with_valid_token_and_helper() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let source = ExternalTokenSource::from_env();
        assert!(source.is_ok());
        let source = source.unwrap();
        assert!(source.token().starts_with("eyJ"));
    }

    #[test]
    fn from_env_uses_datum_api_host_when_set() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
            std::env::set_var("DATUM_API_HOST", "https://custom.api.example.com");
        }
        let source = ExternalTokenSource::from_env().unwrap();
        assert_eq!(source.api_host(), "https://custom.api.example.com");
    }

    #[test]
    fn from_env_falls_back_to_production_when_no_api_host() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("DATUM_API_HOST");
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let source = ExternalTokenSource::from_env().unwrap();
        assert_eq!(source.api_host(), "https://api.datum.net");
    }

    #[test]
    fn swap_token_updates_and_notifies_watch() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let source = ExternalTokenSource::from_env().unwrap();

        let rx = source.watch();
        let new_token = make_jwt_with_exp(8888888888);
        source.swap_token(new_token.clone());

        assert_eq!(source.token(), new_token);
        assert_eq!(*rx.borrow(), new_token);
    }

    #[test]
    fn swap_token_multiple_times() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let source = ExternalTokenSource::from_env().unwrap();

        for i in 1..=5 {
            let new_token = make_jwt_with_exp(7777777000 + i);
            source.swap_token(new_token.clone());
            assert_eq!(source.token(), new_token);
        }
    }

    #[test]
    fn watch_receiver_initial_value() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let source = ExternalTokenSource::from_env().unwrap();
        let rx = source.watch();
        assert_eq!(*rx.borrow(), source.token());
    }

    #[test]
    fn clone_preserves_state() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_ACCESS_TOKEN", make_jwt_with_exp(9999999999));
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/false");
        }
        let source = ExternalTokenSource::from_env().unwrap();
        let cloned = source.clone();

        assert_eq!(source.token(), cloned.token());
        assert_eq!(source.api_host(), cloned.api_host());

        let new_token = make_jwt_with_exp(6666666000);
        source.swap_token(new_token.clone());
        assert_eq!(cloned.token(), new_token);
    }
}
