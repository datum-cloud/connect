use std::env;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const HELPER_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HELPER_STDOUT_BYTES: usize = 64 * 1024;
const MAX_HELPER_STDERR_BYTES: usize = 4 * 1024;

/// Errors that can occur when constructing an [`ExternalTokenSource`] from environment.
#[derive(Debug, thiserror::Error)]
pub enum ExternalTokenError {
    #[error("DATUM_CREDENTIALS_HELPER environment variable not set")]
    MissingHelper,
    #[error("DATUM_SESSION not set and no session argument provided")]
    MissingSession,
    #[error("credentials helper exec failed: {0}")]
    HelperExecError(String),
    #[error("credentials helper timed out after {0:?}")]
    HelperTimedOut(Duration),
    #[error("credentials helper execution was cancelled")]
    HelperCancelled,
    #[error("credentials helper returned more than {MAX_HELPER_STDOUT_BYTES} bytes")]
    HelperOutputTooLarge,
    #[error("token refresh task is already started")]
    RefreshAlreadyStarted,
    #[error("token refresh task is already shutting down")]
    RefreshShutdownInProgress,
    #[error("token refresh requires a Tokio runtime: {0}")]
    RefreshRuntimeUnavailable(String),
    #[error("token refresh task state lock is poisoned")]
    RefreshStatePoisoned,
    #[error("token refresh task handle is unavailable")]
    RefreshTaskHandleUnavailable,
    #[error("token refresh task failed: {0}")]
    RefreshTaskFailed(#[source] tokio::task::JoinError),
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
    token: Arc<ArcSwap<SecretString>>,
    revision_tx: Arc<watch::Sender<u64>>,
    refresh_trigger: Arc<watch::Sender<u64>>,
    refresh_task: Arc<Mutex<RefreshTaskState>>,
}

struct RefreshTask {
    cancel: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl Drop for RefreshTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

enum RefreshTaskState {
    Stopped,
    Running(RefreshTask),
    Stopping,
}

/// Current state of the supervised credentials-refresh task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTaskHealth {
    Stopped,
    Running,
    Stopping,
    Finished,
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
    pub fn from_env(
        session: Option<String>,
    ) -> impl Future<Output = Result<Self, ExternalTokenError>> {
        let config = (|| {
            let helper = env::var("DATUM_CREDENTIALS_HELPER")
                .map_err(|_| ExternalTokenError::MissingHelper)?;
            let session = match session {
                Some(s) => s,
                None => {
                    env::var("DATUM_SESSION").map_err(|_| ExternalTokenError::MissingSession)?
                }
            };
            Ok((helper, session))
        })();

        async move {
            let (helper, session) = config?;
            let token =
                Self::exec_helper(&helper, &session, &CancellationToken::new(), HELPER_TIMEOUT)
                    .await?;

            let exp = parse_jwt_expiry(&token).map_err(|e| {
                ExternalTokenError::InvalidToken(format!("failed to extract expiry: {e}"))
            })?;

            debug!(
                token_len = token.len(),
                exp = ?exp,
                "ExternalTokenSource::from_env — token loaded from helper"
            );

            Ok(Self::from_token(token))
        }
    }

    fn from_token(token: String) -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        let (refresh_tx, _) = watch::channel(0u64);

        Self {
            token: Arc::new(ArcSwap::from_pointee(SecretString::new(
                token.into_boxed_str(),
            ))),
            revision_tx: Arc::new(revision_tx),
            refresh_trigger: Arc::new(refresh_tx),
            refresh_task: Arc::new(Mutex::new(RefreshTaskState::Stopped)),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_token_for_test(token: String) -> Self {
        Self::from_token(token)
    }

    /// Returns the current token as a plain `String`.
    pub fn token(&self) -> String {
        self.with_token(str::to_owned)
    }

    /// Calls `use_token` with the current token without copying it into an
    /// intermediate plaintext value.
    pub(crate) fn with_token<T>(&self, use_token: impl FnOnce(&str) -> T) -> T {
        let token = self.token.load();
        use_token(token.expose_secret())
    }

    /// Returns a subscriber that is notified when the token changes.
    ///
    /// Only a monotonically increasing revision is published. Subscribers
    /// must fetch the current token through [`Self::with_token`] after an
    /// update, so bearer credentials never travel through the watch channel.
    pub fn watch(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// Atomically swaps the token and notifies watch subscribers.
    pub fn swap_token(&self, new_token: String) {
        debug!(
            new_token_len = new_token.len(),
            "ExternalTokenSource::swap_token"
        );
        self.token
            .store(std::sync::Arc::new(SecretString::new(new_token.into())));
        self.revision_tx
            .send_modify(|revision| *revision = revision.saturating_add(1));
    }

    /// Start the background refresh loop. Must be called from within a tokio runtime.
    ///
    /// The loop periodically re-executes the credentials helper before the current
    /// token expires, calls [`swap_token()`](Self::swap_token) with the result,
    /// and responds to [`force_refresh()`](Self::force_refresh) signals.
    pub fn start_refresh(&self, helper: String, session: String) -> Result<(), ExternalTokenError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|error| ExternalTokenError::RefreshRuntimeUnavailable(error.to_string()))?;
        let mut task = self
            .refresh_task
            .lock()
            .map_err(|_| ExternalTokenError::RefreshStatePoisoned)?;
        if !matches!(*task, RefreshTaskState::Stopped) {
            return Err(ExternalTokenError::RefreshAlreadyStarted);
        }

        let token = self.token.clone();
        let revision_tx = self.revision_tx.clone();
        let mut refresh_rx = self.refresh_trigger.subscribe();
        let initial_exp = parse_jwt_expiry(&self.token()).unwrap_or_default();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = runtime.spawn(async move {
            Self::run_refresh_loop(
                token,
                revision_tx,
                helper,
                session,
                &mut refresh_rx,
                initial_exp,
                task_cancel,
            )
            .await;
        });
        *task = RefreshTaskState::Running(RefreshTask {
            cancel,
            handle: Some(handle),
        });
        Ok(())
    }

    /// Returns whether the refresh task is stopped, running, or has finished unexpectedly.
    pub fn refresh_task_health(&self) -> Result<RefreshTaskHealth, ExternalTokenError> {
        let task = self
            .refresh_task
            .lock()
            .map_err(|_| ExternalTokenError::RefreshStatePoisoned)?;
        Ok(match &*task {
            RefreshTaskState::Stopped => RefreshTaskHealth::Stopped,
            RefreshTaskState::Running(task)
                if task.handle.as_ref().is_some_and(JoinHandle::is_finished) =>
            {
                RefreshTaskHealth::Finished
            }
            RefreshTaskState::Running(_) => RefreshTaskHealth::Running,
            RefreshTaskState::Stopping => RefreshTaskHealth::Stopping,
        })
    }

    /// Cancels and joins the refresh task. Calling this while stopped is a no-op.
    pub async fn shutdown_refresh(&self) -> Result<(), ExternalTokenError> {
        let task = {
            let mut state = self
                .refresh_task
                .lock()
                .map_err(|_| ExternalTokenError::RefreshStatePoisoned)?;
            match std::mem::replace(&mut *state, RefreshTaskState::Stopping) {
                RefreshTaskState::Stopped => {
                    *state = RefreshTaskState::Stopped;
                    None
                }
                RefreshTaskState::Running(task) => Some(task),
                RefreshTaskState::Stopping => {
                    *state = RefreshTaskState::Stopping;
                    return Err(ExternalTokenError::RefreshShutdownInProgress);
                }
            }
        };
        let Some(mut task) = task else {
            return Ok(());
        };

        task.cancel.cancel();
        let join_result = match task.handle.take() {
            Some(handle) => handle.await.map_err(ExternalTokenError::RefreshTaskFailed),
            None => Err(ExternalTokenError::RefreshTaskHandleUnavailable),
        };
        *self
            .refresh_task
            .lock()
            .map_err(|_| ExternalTokenError::RefreshStatePoisoned)? = RefreshTaskState::Stopped;
        join_result
    }

    /// Triggers an immediate token refresh.
    ///
    /// Call this when a 401 response is observed from the API.
    /// The refresh loop wakes up early, re-executes the credentials helper,
    /// and calls [`swap_token()`](Self::swap_token) with the result.
    pub fn force_refresh(&self) {
        let current = *self.refresh_trigger.borrow();
        info!(
            trigger_count = current.wrapping_add(1),
            "token refresh: forced refresh requested (401 or stale auth observed)"
        );
        let _ = self.refresh_trigger.send(current.wrapping_add(1));
    }

    async fn exec_helper(
        helper: &str,
        session: &str,
        cancel: &CancellationToken,
        timeout: Duration,
    ) -> Result<String, ExternalTokenError> {
        let mut command = Command::new(helper);
        command
            .args(["auth", "get-token", "--session", session])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|e| ExternalTokenError::HelperExecError(format!("exec failed: {e}")))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ExternalTokenError::HelperExecError("failed to capture stdout".into())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ExternalTokenError::HelperExecError("failed to capture stderr".into())
        })?;

        enum HelperOutcome {
            Completed(std::io::Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)>),
            Cancelled,
            TimedOut,
        }

        let outcome = {
            let execution = async {
                let (status, stdout, stderr) = tokio::try_join!(
                    child.wait(),
                    read_bounded(stdout, MAX_HELPER_STDOUT_BYTES),
                    read_bounded(stderr, MAX_HELPER_STDERR_BYTES),
                )?;
                Ok((status, stdout, stderr))
            };
            tokio::pin!(execution);
            tokio::select! {
                biased;
                _ = cancel.cancelled() => HelperOutcome::Cancelled,
                _ = tokio::time::sleep(timeout) => HelperOutcome::TimedOut,
                result = &mut execution => HelperOutcome::Completed(result),
            }
        };

        let (status, mut stdout, stderr) = match outcome {
            HelperOutcome::Completed(result) => result.map_err(|e| {
                ExternalTokenError::HelperExecError(format!("process I/O failed: {e}"))
            })?,
            HelperOutcome::Cancelled => {
                terminate_child(&mut child).await;
                return Err(ExternalTokenError::HelperCancelled);
            }
            HelperOutcome::TimedOut => {
                terminate_child(&mut child).await;
                return Err(ExternalTokenError::HelperTimedOut(timeout));
            }
        };

        if !status.success() {
            let stderr = sanitize_stderr(&stderr);
            return Err(ExternalTokenError::HelperExecError(format!(
                "exit code {}: {}",
                status, stderr
            )));
        }
        if stdout.len() > MAX_HELPER_STDOUT_BYTES {
            stdout.fill(0);
            return Err(ExternalTokenError::HelperOutputTooLarge);
        }
        let token = String::from_utf8_lossy(&stdout).trim().to_string();
        stdout.fill(0);
        if token.is_empty() {
            return Err(ExternalTokenError::HelperExecError(
                "empty token returned".into(),
            ));
        }
        Ok(token)
    }

    async fn run_refresh_loop(
        token: Arc<ArcSwap<SecretString>>,
        revision_tx: Arc<watch::Sender<u64>>,
        helper: String,
        session: String,
        refresh_rx: &mut watch::Receiver<u64>,
        initial_exp: Option<u64>,
        cancel: CancellationToken,
    ) {
        // Compute the next refresh time: 60s before JWT expiry, or 1h from now if no expiry.
        let mut next_refresh: SystemTime = initial_exp
            .and_then(|exp| {
                std::time::UNIX_EPOCH.checked_add(Duration::from_secs(exp.saturating_sub(60)))
            })
            .unwrap_or_else(|| SystemTime::now() + Duration::from_secs(3600));

        if let Some(exp) = initial_exp {
            debug!(
                exp = exp,
                next_refresh_in_secs = next_refresh
                    .duration_since(SystemTime::now())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                "token refresh loop started; proactive refresh scheduled 60s before JWT expiry"
            );
        } else {
            debug!(
                "token refresh loop started; no JWT expiry claim, defaulting to 1h refresh interval"
            );
        }

        let mut backoff = Duration::from_secs(5);
        const MAX_BACKOFF: Duration = Duration::from_secs(60);

        loop {
            let now = SystemTime::now();
            let wait = if next_refresh > now {
                next_refresh.duration_since(now).unwrap_or(Duration::ZERO)
            } else {
                Duration::ZERO
            };

            // Wait either for the timer or a force_refresh signal
            let forced = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(wait) => {
                    debug!("token refresh: proactive timer fired");
                    false
                }
                result = refresh_rx.changed() => {
                    if result.is_err() {
                        break;
                    }
                    info!("token refresh: forced refresh signalled (401 or stale auth)");
                    true
                }
            };

            // Execute helper to get a fresh token
            match Self::exec_helper(&helper, &session, &cancel, HELPER_TIMEOUT).await {
                Ok(new_token) => {
                    let prev_exp = {
                        let current = token.load();
                        parse_jwt_expiry(current.expose_secret()).ok().flatten()
                    };
                    let new_exp = parse_jwt_expiry(&new_token).ok().flatten();
                    token.store(Arc::new(SecretString::new(new_token.into())));
                    revision_tx.send_modify(|revision| *revision = revision.saturating_add(1));
                    backoff = Duration::from_secs(5);

                    info!(
                        forced,
                        new_exp = ?new_exp,
                        prev_exp = ?prev_exp,
                        "token refresh: succeeded; token swapped and watchers notified"
                    );

                    // Parse new expiry for next refresh
                    next_refresh = match new_exp {
                        Some(exp) => {
                            std::time::UNIX_EPOCH + Duration::from_secs(exp.saturating_sub(60))
                        }
                        None => SystemTime::now() + Duration::from_secs(3600),
                    };
                }
                Err(ExternalTokenError::HelperCancelled) if cancel.is_cancelled() => break,
                Err(e) => {
                    warn!(
                        forced,
                        "token refresh failed: {e}; retrying in {:?}", backoff
                    );
                    // Retry with backoff
                    next_refresh = SystemTime::now() + backoff;
                    backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                }
            }
        }
    }
}

async fn read_bounded(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

async fn terminate_child(child: &mut Child) {
    if let Err(error) = child.kill().await
        && error.kind() != std::io::ErrorKind::InvalidInput
    {
        warn!(%error, "failed to terminate credentials helper");
    }
    if let Err(error) = child.wait().await
        && error.kind() != std::io::ErrorKind::InvalidInput
    {
        warn!(%error, "failed to reap credentials helper");
    }
}

fn sanitize_stderr(stderr: &[u8]) -> String {
    let truncated = stderr.len() > MAX_HELPER_STDERR_BYTES;
    let bounded = &stderr[..stderr.len().min(MAX_HELPER_STDERR_BYTES)];
    let mut sanitized = String::with_capacity(bounded.len());
    let mut previous_was_space = true;

    for character in String::from_utf8_lossy(bounded).chars() {
        if character.is_control() || character.is_whitespace() {
            if !previous_was_space {
                sanitized.push(' ');
                previous_was_space = true;
            }
        } else {
            sanitized.push(character);
            previous_was_space = false;
        }
    }

    if previous_was_space {
        sanitized.pop();
    }
    if truncated {
        sanitized.push_str(" [truncated]");
    }
    if sanitized.is_empty() {
        sanitized.push_str("no stderr output");
    }
    sanitized
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
    use crate::test_util::{TempDir, make_jwt_with_exp, setup_plugin_env};

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
            serde_json::json!({"sub":"test-user"})
                .to_string()
                .as_bytes(),
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
        let token = "header.!!!.sig".to_string();
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
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(payload_json.to_string().as_bytes());
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload_b64}.sig");
        let exp = parse_jwt_expiry(&token).unwrap().unwrap();
        assert_eq!(exp, 9999999999);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_env_requires_helper() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("DATUM_CREDENTIALS_HELPER");
            std::env::set_var("DATUM_SESSION", "test-session");
        }
        let result = ExternalTokenSource::from_env(Some("test-session".to_string()));
        drop(_lock);
        let result = result.await;
        assert!(matches!(result, Err(ExternalTokenError::MissingHelper)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_env_requires_session() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_CREDENTIALS_HELPER", "/bin/echo");
            std::env::remove_var("DATUM_SESSION");
        }
        let result = ExternalTokenSource::from_env(None);
        drop(_lock);
        let result = result.await;
        assert!(matches!(result, Err(ExternalTokenError::MissingSession)));
    }

    #[tokio::test]
    async fn from_env_succeeds_with_fake_helper() {
        let dir = TempDir::new("ets-from-env");
        let helper_path = dir.path().join("fake-helper.sh");
        let jwt = make_jwt_with_exp(9_999_999_999);
        std::fs::write(&helper_path, format!("#!/bin/sh\nprintf '%s\\n' '{jwt}'\n"))
            .expect("should write helper script");
        #[cfg(unix)]
        std::fs::set_permissions(
            &helper_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("should set executable permission");

        let env_lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DATUM_CREDENTIALS_HELPER", &helper_path);
            std::env::set_var("DATUM_SESSION", "test-session");
        }
        let source = ExternalTokenSource::from_env(Some("test-session".to_string()));
        drop(env_lock);
        let source = source.await.expect("fake helper should produce a token");
        assert!(source.token().starts_with("eyJ"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_env_requires_datum_credentials_helper() {
        let _lock = crate::ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("DATUM_CREDENTIALS_HELPER");
            std::env::set_var("DATUM_SESSION", "test-session");
        }
        let result = ExternalTokenSource::from_env(None);
        drop(_lock);
        let result = result.await;
        assert!(matches!(result, Err(ExternalTokenError::MissingHelper)));
    }

    #[test]
    fn swap_token_updates_and_notifies_revision_watch() {
        let (_dir, source) = setup_plugin_env();

        let mut rx = source.watch();
        let new_token = make_jwt_with_exp(8888888888);
        source.swap_token(new_token.clone());

        assert_eq!(source.token(), new_token);
        assert!(rx.has_changed().expect("revision sender should stay open"));
        assert_eq!(*rx.borrow_and_update(), 1);
    }

    #[test]
    fn swap_token_multiple_times() {
        let (_dir, source) = setup_plugin_env();
        let mut rx = source.watch();

        for i in 1..=5 {
            let new_token = make_jwt_with_exp(7777777000 + i);
            source.swap_token(new_token.clone());
            assert_eq!(source.token(), new_token);
            assert!(rx.has_changed().expect("revision sender should stay open"));
            assert_eq!(*rx.borrow_and_update(), i);
        }
    }

    #[test]
    fn watch_receiver_initial_value() {
        let (_dir, source) = setup_plugin_env();
        let rx = source.watch();
        assert_eq!(*rx.borrow(), 0);
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

    /// Verifies the end-to-end refresh path: when `force_refresh()` is
    /// signalled (e.g. after a 401), the background loop re-executes the
    /// credentials helper and swaps in the new token, notifying watchers.
    ///
    /// This guards against the "stale auth" regression where the heartbeat
    /// observed a 401 but never actually triggered a refresh — the token
    /// stayed dead until the proactive timer eventually fired.
    #[tokio::test]
    async fn force_refresh_swaps_token_via_loop() {
        let dir = TempDir::new("ets-loop");

        // Helper that emits a distinct JWT on every invocation by reading
        // and incrementing a counter file. This lets the test observe that
        // the loop actually re-executed the helper (not just that the signal
        // was sent).
        let counter_path = dir.path().join("counter");
        std::fs::write(&counter_path, "0").expect("should write counter");
        let helper_path = dir.path().join("counter-helper.sh");
        let counter_str = counter_path.to_string_lossy().replace('\'', "'\\''");
        let script = format!(
            "#!/bin/sh\n\
             n=$(cat '{counter_str}')\n\
             n=$((n + 1))\n\
             echo \"$n\" > '{counter_str}'\n\
             exp=$((4000000000 + n))\n\
             header=$(printf '{{\"alg\":\"HS256\",\"typ\":\"JWT\"}}' | base64 | tr -d '=' | tr '/+' '_-')\n\
             payload=$(printf '{{\"exp\":%d,\"sub\":\"rotating\"}}' \"$exp\" | base64 | tr -d '=' | tr '/+' '_-')\n\
             printf '%s.%s.rotated\\n' \"$header\" \"$payload\"\n",
        );
        std::fs::write(&helper_path, script).expect("should write helper script");
        #[cfg(unix)]
        std::fs::set_permissions(
            &helper_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("should set executable permission");

        // Use a token with a far-future expiry so the proactive timer does
        // not fire during the test — only the forced refresh should swap.
        let initial = make_jwt_with_exp(9999999999);
        std::fs::write(&counter_path, "0").expect("should reset counter");
        // Build the source directly so from_env() doesn't consume the first
        // helper invocation (we want the *loop* to be the one rotating).
        let source = ExternalTokenSource::from_token(initial.clone());

        let rx = source.watch();
        assert_eq!(*rx.borrow(), 0, "watch initial revision");

        source
            .start_refresh(
                helper_path.to_string_lossy().to_string(),
                "test-session".to_string(),
            )
            .expect("refresh task should start");

        // Nothing should have rotated yet (proactive timer is far in the
        // future). Give the loop a moment to prove a negative.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(source.token(), initial, "no proactive refresh expected yet");

        // Force a refresh (as the heartbeat does on a 401) and wait for the
        // loop to re-exec the helper and swap the token.
        source.force_refresh();
        for _ in 0..40 {
            if source.token() != initial {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let new_token = source.token();
        assert_ne!(
            new_token, initial,
            "force_refresh must have rotated the token"
        );
        assert!(
            new_token.ends_with(".rotated"),
            "rotated token should come from the counter helper: {new_token}"
        );
        assert_eq!(*rx.borrow(), 1, "watchers notified of token revision");
        source
            .shutdown_refresh()
            .await
            .expect("refresh task should stop cleanly");
    }

    #[tokio::test]
    async fn helper_execution_times_out() {
        let dir = TempDir::new("ets-timeout");
        let helper_path = dir.path().join("slow-helper.sh");
        std::fs::write(&helper_path, "#!/bin/sh\nexec sleep 10\n")
            .expect("should write helper script");
        #[cfg(unix)]
        std::fs::set_permissions(
            &helper_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("should set executable permission");

        let result = ExternalTokenSource::exec_helper(
            &helper_path.to_string_lossy(),
            "test-session",
            &CancellationToken::new(),
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(
            result,
            Err(ExternalTokenError::HelperTimedOut(duration))
                if duration == Duration::from_millis(100)
        ));
    }

    #[tokio::test]
    async fn duplicate_refresh_start_is_rejected() {
        let source = ExternalTokenSource::from_token(make_jwt_with_exp(9_999_999_999));
        source
            .start_refresh("/bin/false".into(), "test-session".into())
            .expect("first refresh task should start");

        assert_eq!(
            source
                .refresh_task_health()
                .expect("refresh health should be readable"),
            RefreshTaskHealth::Running
        );
        assert!(matches!(
            source.start_refresh("/bin/false".into(), "test-session".into()),
            Err(ExternalTokenError::RefreshAlreadyStarted)
        ));

        source
            .shutdown_refresh()
            .await
            .expect("refresh task should stop cleanly");
        assert_eq!(
            source
                .refresh_task_health()
                .expect("refresh health should be readable"),
            RefreshTaskHealth::Stopped
        );
    }

    #[tokio::test]
    async fn shutdown_cancels_in_flight_helper_and_joins_refresh_task() {
        let dir = TempDir::new("ets-cancel");
        let marker_path = dir.path().join("started");
        let helper_path = dir.path().join("blocking-helper.sh");
        let marker = marker_path.to_string_lossy().replace('\'', "'\\''");
        std::fs::write(
            &helper_path,
            format!("#!/bin/sh\ntouch '{marker}'\nexec sleep 10\n"),
        )
        .expect("should write helper script");
        #[cfg(unix)]
        std::fs::set_permissions(
            &helper_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("should set executable permission");

        let source = ExternalTokenSource::from_token(make_jwt_with_exp(9_999_999_999));
        source
            .start_refresh(
                helper_path.to_string_lossy().to_string(),
                "test-session".into(),
            )
            .expect("refresh task should start");
        source.force_refresh();

        tokio::time::timeout(Duration::from_secs(2), async {
            while !marker_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("helper should start");

        tokio::time::timeout(Duration::from_secs(2), source.shutdown_refresh())
            .await
            .expect("shutdown should not wait for helper timeout")
            .expect("refresh task should join cleanly");
        assert_eq!(
            source
                .refresh_task_health()
                .expect("refresh health should be readable"),
            RefreshTaskHealth::Stopped
        );
    }
}
