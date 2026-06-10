use std::env;
use std::process::Command;

use arc_swap::ArcSwap;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::watch;
use tracing::{debug, warn};

/// Errors that can occur when constructing an [`ExternalTokenSource`] from environment.
#[derive(Debug, thiserror::Error)]
pub enum ExternalTokenError {
    #[error("DATUM_CREDENTIALS_HELPER environment variable not set")]
    MissingHelper,
    #[error("DATUM_SESSION not set and no session argument provided")]
    MissingSession,
    #[error("credentials helper exec failed: {0}")]
    HelperExecError(String),
    #[error("invalid JWT token: {0}")]
    InvalidToken(String),
    #[error("failed to parse JWT payload: {0}")]
    JwtParse(#[source] serde_json::Error),
}

/// Manages a bearer token provided from an external source (credentials helper + refresh loop).
///
/// Used in plugin mode. The token is obtained at startup by executing the
/// credentials helper (`DATUM_CREDENTIALS_HELPER auth get-token --session <session>`)
/// and refreshed periodically before JWT expiry or on demand via [`force_refresh()`](Self::force_refresh).
#[derive(Clone)]
pub struct ExternalTokenSource {
    token: std::sync::Arc<ArcSwap<SecretString>>,
    token_tx: std::sync::Arc<watch::Sender<String>>,
    refresh_trigger: std::sync::Arc<watch::Sender<u64>>,
}

impl std::fmt::Debug for ExternalTokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalTokenSource")
            .finish_non_exhaustive()
    }
}

impl ExternalTokenSource {
    /// Creates an `ExternalTokenSource` by executing the credentials helper
    /// at startup to obtain the initial token.
    ///
    /// `session` is the session name to pass to `auth get-token --session <session>`.
    /// If `None`, falls back to `DATUM_SESSION` env var.
    pub fn from_env(session: Option<String>) -> Result<Self, ExternalTokenError> {
        let helper =
            env::var("DATUM_CREDENTIALS_HELPER").map_err(|_| ExternalTokenError::MissingHelper)?;

        let session = match session {
            Some(s) => s,
            None => env::var("DATUM_SESSION").map_err(|_| ExternalTokenError::MissingSession)?,
        };

        let token = Self::exec_helper(&helper, &session)?;

        let exp = parse_jwt_expiry(&token).map_err(|e| {
            ExternalTokenError::InvalidToken(format!("failed to extract expiry: {e}"))
        })?;

        debug!(
            token_len = token.len(),
            exp = ?exp,
            "ExternalTokenSource::from_env — token loaded from helper"
        );

        let (token_tx, _) = watch::channel(token.clone());
        let (refresh_tx, _) = watch::channel(0u64);

        Ok(Self {
            token: std::sync::Arc::new(ArcSwap::from_pointee(SecretString::new(
                token.clone().into(),
            ))),
            token_tx: std::sync::Arc::new(token_tx),
            refresh_trigger: std::sync::Arc::new(refresh_tx),
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

    /// Atomically swaps the token and notifies watch subscribers.
    pub fn swap_token(&self, new_token: String) {
        debug!(
            new_token_len = new_token.len(),
            "ExternalTokenSource::swap_token"
        );
        self.token.store(std::sync::Arc::new(SecretString::new(
            new_token.clone().into(),
        )));
        let _ = self.token_tx.send(new_token);
    }

    /// Start the background refresh loop. Must be called from within a tokio runtime.
    ///
    /// The loop periodically re-executes the credentials helper before the current
    /// token expires, calls [`swap_token()`](Self::swap_token) with the result,
    /// and responds to [`force_refresh()`](Self::force_refresh) signals.
    pub fn start_refresh(&self, helper: String, session: String) {
        let this = self.clone();
        let mut refresh_rx = self.refresh_trigger.subscribe();
        let initial_exp = match parse_jwt_expiry(&self.token()) {
            Ok(exp) => exp,
            Err(_) => None,
        };
        tokio::spawn(async move {
            this.run_refresh_loop(helper, session, &mut refresh_rx, initial_exp)
                .await;
        });
    }

    /// Triggers an immediate token refresh.
    ///
    /// Call this when a 401 response is observed from the API.
    /// The refresh loop wakes up early, re-executes the credentials helper,
    /// and calls [`swap_token()`](Self::swap_token) with the result.
    pub fn force_refresh(&self) {
        let current = *self.refresh_trigger.borrow();
        let _ = self.refresh_trigger.send(current.wrapping_add(1));
    }

    fn exec_helper(helper: &str, session: &str) -> Result<String, ExternalTokenError> {
        let output = Command::new(helper)
            .args(["auth", "get-token", "--session", session])
            .output()
            .map_err(|e| ExternalTokenError::HelperExecError(format!("exec failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ExternalTokenError::HelperExecError(format!(
                "exit code {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if token.is_empty() {
            return Err(ExternalTokenError::HelperExecError(
                "empty token returned".into(),
            ));
        }
        Ok(token)
    }

    async fn run_refresh_loop(
        self,
        helper: String,
        session: String,
        refresh_rx: &mut watch::Receiver<u64>,
        initial_exp: Option<u64>,
    ) {
        // Compute the next refresh time: 60s before JWT expiry, or 1h from now if no expiry.
        let mut next_refresh: std::time::SystemTime = initial_exp
            .and_then(|exp| {
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(exp.saturating_sub(60)))
            })
            .unwrap_or_else(|| {
                std::time::SystemTime::now() + std::time::Duration::from_secs(3600)
            });

        let mut backoff = std::time::Duration::from_secs(5);
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

        loop {
            let now = std::time::SystemTime::now();
            let wait = if next_refresh > now {
                next_refresh
                    .duration_since(now)
                    .unwrap_or(std::time::Duration::ZERO)
            } else {
                std::time::Duration::ZERO
            };

            // Wait either for the timer or a force_refresh signal
            tokio::select! {
                _ = tokio::time::sleep(wait) => {},
                _ = refresh_rx.changed() => {
                    debug!("ExternalTokenSource: forced refresh triggered");
                }
            }

            // Execute helper to get a fresh token
            match Self::exec_helper(&helper, &session) {
                Ok(new_token) => {
                    self.swap_token(new_token.clone());
                    backoff = std::time::Duration::from_secs(5); // Reset backoff

                    // Parse new expiry for next refresh
                    next_refresh = match parse_jwt_expiry(&new_token) {
                        Ok(Some(exp)) => std::time::UNIX_EPOCH
                            + std::time::Duration::from_secs(exp.saturating_sub(60)),
                        _ => {
                            std::time::SystemTime::now()
                                + std::time::Duration::from_secs(3600)
                        }
                    };
                }
                Err(e) => {
                    warn!("token refresh failed: {e}");
                    // Retry with backoff
                    next_refresh = std::time::SystemTime::now() + backoff;
                    backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                }
            }
        }
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
            serde_json::json!({"alg":"HS256","typ":"JWT"})
                .to_string()
                .as_bytes(),
        );
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({"exp": exp, "sub":"test-user"})
                .to_string()
                .as_bytes(),
        );
        format!("{header}.{payload}.fake_signature_here")
    }

    /// A temporary directory that cleans up on drop.
    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("connect-ets-test-{ts}"));
            std::fs::create_dir_all(&path).expect("should create temp dir");
            TempDir { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Create a temporary helper script that outputs a fake JWT, set env vars,
    /// and return a configured [`ExternalTokenSource`].
    ///
    /// The returned `TempDir` keeps the script alive for the test scope.
    fn setup_plugin_env() -> (TempDir, ExternalTokenSource) {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        let dir = TempDir::new();
        let helper_path = dir.path().join("fake-helper.sh");
        let jwt = make_jwt_with_exp(9999999999);
        std::fs::write(&helper_path, format!("#!/bin/sh\necho '{}'\n", jwt))
            .expect("should write helper script");
        #[cfg(unix)]
        std::fs::set_permissions(
            &helper_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("should set executable permission");
        let helper_str = helper_path.to_string_lossy().to_string();

        unsafe {
            std::env::set_var("DATUM_CREDENTIALS_HELPER", &helper_str);
            std::env::set_var("DATUM_SESSION", "test-session");
        }

        let source =
            ExternalTokenSource::from_env(Some("test-session".to_string())).expect("should create token source");
        (dir, source)
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
    fn from_env_requires_helper() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("DATUM_CREDENTIALS_HELPER");
            std::env::set_var("DATUM_SESSION", "test-session");
        }
        let result = ExternalTokenSource::from_env(Some("test-session".to_string()));
        assert!(matches!(result, Err(ExternalTokenError::MissingHelper)));
    }

    #[test]
    fn from_env_requires_session() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/echo");
            std::env::remove_var("DATUM_SESSION");
        }
        let result = ExternalTokenSource::from_env(None);
        assert!(matches!(result, Err(ExternalTokenError::MissingSession)));
    }

    #[test]
    fn from_env_succeeds_with_fake_helper() {
        let (_dir, source) = setup_plugin_env();
        assert!(source.token().starts_with("eyJ"));
    }

    #[test]
    fn from_env_requires_datum_credentials_helper() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("DATUM_CREDENTIALS_HELPER");
            std::env::set_var("DATUM_SESSION", "test-session");
        }
        let result = ExternalTokenSource::from_env(None);
        assert!(matches!(result, Err(ExternalTokenError::MissingHelper)));
    }

    #[test]
    fn swap_token_updates_and_notifies_watch() {
        let (_dir, source) = setup_plugin_env();

        let rx = source.watch();
        let new_token = make_jwt_with_exp(8888888888);
        source.swap_token(new_token.clone());

        assert_eq!(source.token(), new_token);
        assert_eq!(*rx.borrow(), new_token);
    }

    #[test]
    fn swap_token_multiple_times() {
        let (_dir, source) = setup_plugin_env();

        for i in 1..=5 {
            let new_token = make_jwt_with_exp(7777777000 + i);
            source.swap_token(new_token.clone());
            assert_eq!(source.token(), new_token);
        }
    }

    #[test]
    fn watch_receiver_initial_value() {
        let (_dir, source) = setup_plugin_env();
        let rx = source.watch();
        assert_eq!(*rx.borrow(), source.token());
    }

    #[test]
    fn clone_preserves_state() {
        let (_dir, source) = setup_plugin_env();
        let cloned = source.clone();

        assert_eq!(source.token(), cloned.token());

        let new_token = make_jwt_with_exp(6666666000);
        source.swap_token(new_token.clone());
        assert_eq!(cloned.token(), new_token);
    }

    #[test]
    fn force_refresh_triggers_signal() {
        let (_dir, source) = setup_plugin_env();
        let rx = source.refresh_trigger.subscribe();
        // Initial value is 0
        assert_eq!(*rx.borrow(), 0);

        source.force_refresh();
        // After force_refresh, the value should have incremented
        // Since send happens synchronously, borrow() already shows the new value
        assert_eq!(*rx.borrow(), 1);

        source.force_refresh();
        assert_eq!(*rx.borrow(), 2);
    }
}
