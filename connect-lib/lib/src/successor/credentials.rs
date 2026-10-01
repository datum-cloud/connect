//! Renewable service credentials and pinned, host-owned OIDC sessions.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::{Error, Result, validate_url};

/// Renewable credentials imported once by a local administrator.
/// Debug deliberately never includes secret fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub project_id: String,
    pub api_endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub helper_path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// Pins a host-owned login session without copying its bearer or refresh token.
    pub fn datumctl_session(project: &str, api: &str, helper: &str, session: &str) -> Result<Self> {
        if !Path::new(helper).is_absolute() {
            return Err(Error::Invalid(
                "datumctl helper must have an absolute path".into(),
            ));
        }
        let helper = std::fs::canonicalize(helper)
            .map_err(|_| Error::Invalid("datumctl helper executable is unavailable".into()))?;
        let credentials = Self {
            credential_type: "datumctl_session".into(),
            project_id: project.into(),
            api_endpoint: api.into(),
            token_uri: String::new(),
            client_id: String::new(),
            helper_path: helper
                .to_str()
                .ok_or_else(|| Error::Invalid("datumctl helper path must be valid UTF-8".into()))?
                .into(),
            session: session.into(),
            scope: String::new(),
            private_key_id: String::new(),
            private_key: String::new(),
            refresh_token: String::new(),
            path: None,
        };
        credentials.validate()?;
        Ok(credentials)
    }

    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = tokio::fs::symlink_metadata(path).await?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Err(Error::Invalid(
                "credential file must be a regular file under 1 MiB".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Invalid(
                    "credential file must be owner-only (chmod 600)".into(),
                ));
            }
        }
        #[cfg(windows)]
        crate::secure_fs::validate_private_path(path)
            .await
            .map_err(|_| Error::Invalid("credential file must have a protected private ACL for the current account, SYSTEM, and Administrators".into()))?;
        let mut credentials: Self = serde_json::from_slice(&tokio::fs::read(path).await?)?;
        credentials.path = Some(path.to_path_buf());
        credentials.validate()?;
        Ok(credentials)
    }

    pub fn validate(&self) -> Result<()> {
        crate::ProjectId::try_from(self.project_id.as_str())
            .map_err(|_| Error::Invalid("invalid credential project".into()))?;
        validate_url(&self.api_endpoint)?;
        if self.credential_type == "datumctl_session" {
            if self.session.trim().is_empty()
                || self.session.len() > 1024
                || self.session.chars().any(char::is_control)
            {
                return Err(Error::Invalid(
                    "datumctl session name is required and must not contain control characters"
                        .into(),
                ));
            }
            if !self.refresh_token.is_empty()
                || !self.private_key.is_empty()
                || !self.token_uri.is_empty()
            {
                return Err(Error::Invalid(
                    "datumctl session descriptors must not contain copied credentials".into(),
                ));
            }
            return validate_helper(Path::new(&self.helper_path));
        }
        validate_url(&self.token_uri)?;
        if self.client_id.is_empty() {
            return Err(Error::Invalid("credential client_id is required".into()));
        }
        match self.credential_type.as_str() {
            "connector" if !self.refresh_token.is_empty() => Ok(()),
            "datum_service_account"
                if !self.private_key_id.is_empty() && !self.private_key.is_empty() =>
            {
                EncodingKey::from_rsa_pem(self.private_key.as_bytes()).map_err(|_| {
                    Error::Invalid("invalid RSA service-account private key".into())
                })?;
                Ok(())
            }
            _ => Err(Error::Invalid(
                "expected datumctl_session, renewable connector, or datum_service_account credentials".into(),
            )),
        }
    }
}

fn validate_helper(path: &Path) -> Result<()> {
    open_validated_helper(path).map(|_| ())
}

fn open_validated_helper(path: &Path) -> Result<std::fs::File> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Error::Unsupported(
            "datumctl login sessions require a verified Unix user daemon".into(),
        ))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // SAFETY: geteuid takes no arguments and has no preconditions.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return Err(Error::Invalid("System daemons cannot use a user's datumctl login session; use service-account credentials instead".into()));
        }
        if !path.is_absolute() {
            return Err(Error::Invalid(
                "datumctl helper must have an absolute path".into(),
            ));
        }
        // O_NOFOLLOW rejects a swapped leaf symlink. Metadata belongs to this
        // opened inode, not a pathname that another user can replace.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Error::Invalid("datumctl helper executable is unavailable".into()))?;
        validate_helper_metadata(
            &file
                .metadata()
                .map_err(|_| Error::Invalid("Could not inspect datumctl helper".into()))?,
            uid,
        )?;
        Ok(file)
    }
}

#[cfg(unix)]
fn validate_helper_metadata(metadata: &std::fs::Metadata, uid: libc::uid_t) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
        || (metadata.uid() != uid && metadata.uid() != 0)
    {
        return Err(Error::Invalid("datumctl helper must be a regular executable owned by this user or root, without group or other write access".into()));
    }
    if metadata.len() > 256 * 1024 * 1024 {
        return Err(Error::Invalid(
            "datumctl helper exceeds the 256 MiB executable limit".into(),
        ));
    }
    Ok(())
}

struct HelperSnapshot {
    _directory: tempfile::TempDir,
    executable: PathBuf,
}

fn snapshot_helper(path: &Path) -> Result<HelperSnapshot> {
    let file = open_validated_helper(path)?;
    snapshot_opened_helper(path, file)
}

#[allow(unused_mut)] // Mutated by the Unix-only snapshot implementation.
fn snapshot_opened_helper(path: &Path, mut file: std::fs::File) -> Result<HelperSnapshot> {
    #[cfg(not(unix))]
    {
        let _ = (path, file);
        Err(Error::Unsupported(
            "datumctl session execution requires Unix".into(),
        ))
    }
    #[cfg(unix)]
    {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        // SAFETY: geteuid takes no arguments and has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let original = file
            .metadata()
            .map_err(|_| Error::Invalid("Could not inspect datumctl helper".into()))?;
        validate_helper_metadata(&original, uid)?;
        let directory = tempfile::Builder::new()
            .prefix("datum-connect-helper-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|_| {
                Error::Invalid("Could not create private datumctl execution directory".into())
            })?;
        let executable = directory.path().join("datumctl");
        match std::fs::hard_link(path, &executable) {
            Ok(()) => {
                let linked = std::fs::symlink_metadata(&executable).map_err(|_| {
                    Error::Invalid("Could not inspect pinned datumctl helper".into())
                })?;
                validate_helper_metadata(&linked, uid)?;
                if original.dev() != linked.dev() || original.ino() != linked.ino() {
                    return Err(Error::Invalid(
                        "datumctl helper changed during validation; retry the command".into(),
                    ));
                }
                // Never chmod a hardlink: that would modify the installed binary.
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EXDEV | libc::EPERM | libc::EACCES)
                ) =>
            {
                // Different filesystems and protected_hardlinks can prohibit a
                // link. Copy from the validated descriptor, never the pathname.
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o700)
                    .open(&executable)
                    .map_err(|_| Error::Invalid("Could not snapshot datumctl helper".into()))?;
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| Error::Invalid("Could not read datumctl helper".into()))?;
                let copied =
                    std::io::copy(&mut file.by_ref().take(256 * 1024 * 1024 + 1), &mut output)
                        .map_err(|_| Error::Invalid("Could not snapshot datumctl helper".into()))?;
                if copied > 256 * 1024 * 1024 {
                    return Err(Error::Invalid(
                        "datumctl helper exceeds the 256 MiB executable limit".into(),
                    ));
                }
                validate_helper_metadata(
                    &file
                        .metadata()
                        .map_err(|_| Error::Invalid("Could not inspect datumctl helper".into()))?,
                    uid,
                )?;
                drop(output);
            }
            Err(_) => {
                return Err(Error::Invalid(
                    "Could not pin datumctl helper for execution; retry the command".into(),
                ));
            }
        }
        Ok(HelperSnapshot {
            _directory: directory,
            executable,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    api_version: String,
    kind: String,
    status: ExecCredentialStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredentialStatus {
    token: String,
    expiration_timestamp: String,
}

// Linux can briefly report ETXTBSY while another thread's forked child still
// holds an inherited writable descriptor. Retry only that error, against the
// same validated snapshot and the existing refresh deadline.
async fn spawn_session_helper(
    command: &mut tokio::process::Command,
    deadline: tokio::time::Instant,
) -> std::io::Result<tokio::process::Child> {
    for attempt in 0..=5 {
        if tokio::time::Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        match command.spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 5 => {
                tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(10)))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
            }
            result => return result,
        }
    }
    unreachable!("final attempt returns its result")
}

async fn session_token(
    credentials: &Credentials,
    timeout: Duration,
) -> Result<(String, SystemTime)> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    const MAX_HELPER_OUTPUT: u64 = 64 * 1024;
    let deadline = tokio::time::Instant::now() + timeout;
    let helper_path = PathBuf::from(&credentials.helper_path);
    let helper = tokio::time::timeout_at(
        deadline,
        tokio::task::spawn_blocking(move || snapshot_helper(&helper_path)),
    )
    .await
    .map_err(|_| Error::Invalid("Preparing datumctl login-session refresh timed out".into()))?
    .map_err(|_| Error::Invalid("Could not prepare datumctl login-session refresh".into()))??;
    let mut command = tokio::process::Command::new(&helper.executable);
    command
        .args([
            "auth",
            "get-token",
            "--session",
            &credentials.session,
            "--output",
            "client.authentication.k8s.io/v1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = spawn_session_helper(&mut command, deadline)
        .await
        .map_err(|_| {
            Error::Invalid("Could not start datumctl to refresh the saved login session".into())
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Invalid("Could not read datumctl credential response".into()))?;
    let result = tokio::time::timeout_at(deadline, async {
        let mut bytes = Vec::new();
        stdout.take(MAX_HELPER_OUTPUT + 1).read_to_end(&mut bytes).await
            .map_err(|_| Error::Invalid("Could not read datumctl credential response".into()))?;
        if bytes.len() as u64 > MAX_HELPER_OUTPUT {
            return Err(Error::Invalid("datumctl credential response exceeds 64 KiB".into()));
        }
        let status = child.wait().await
            .map_err(|_| Error::Invalid("Could not wait for datumctl credential refresh".into()))?;
        if !status.success() {
            return Err(Error::Invalid("The saved datumctl login session is unavailable. Run `datumctl login`, then `datumctl connect up --auth oidc` to select a current session".into()));
        }
        Ok(bytes)
    }).await;
    let bytes = match result {
        Ok(Ok(bytes)) => bytes,
        failure => {
            // Explicitly terminate and reap on both timeout and oversized output.
            // stderr and any partial stdout are never included in errors or traces.
            let _ = child.kill().await;
            let _ = child.wait().await;
            return match failure {
                Ok(Err(error)) => Err(error),
                _ => Err(Error::Invalid("datumctl login-session refresh timed out; check `datumctl whoami` and try again".into())),
            };
        }
    };
    let response: ExecCredential = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Invalid("datumctl returned an invalid credential response".into()))?;
    if response.kind != "ExecCredential"
        || response.api_version != "client.authentication.k8s.io/v1"
        || response.status.token.trim().is_empty()
        || response.status.token.chars().any(char::is_control)
    {
        return Err(Error::Invalid(
            "datumctl returned an invalid credential response".into(),
        ));
    }
    let expiry = chrono::DateTime::parse_from_rfc3339(&response.status.expiration_timestamp)
        .map_err(|_| Error::Invalid("datumctl credential expiry is invalid".into()))?;
    let expiry: SystemTime = expiry.into();
    let now = SystemTime::now();
    if expiry <= now || expiry > now + Duration::from_secs(31_536_000) {
        return Err(Error::Invalid("datumctl credential is expired or has an invalid expiry; run `datumctl login` and try again".into()));
    }
    tracing::debug!(
        source = "datumctl_session",
        "login-session credential refreshed"
    );
    Ok((response.status.token, expiry))
}

#[cfg(all(test, unix))]
#[path = "credentials_session_tests.rs"]
mod session_tests;

#[derive(Clone)]
pub(crate) struct TokenProvider {
    inner: Arc<Mutex<TokenState>>,
    client: reqwest::Client,
}

struct TokenState {
    credentials: Credentials,
    access_token: String,
    expires_at: SystemTime,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
}

impl TokenProvider {
    pub fn new(credentials: Credentials, client: reqwest::Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenState {
                credentials,
                access_token: String::new(),
                expires_at: UNIX_EPOCH,
            })),
            client,
        }
    }

    pub async fn invalidate(&self) {
        self.inner.lock().await.expires_at = UNIX_EPOCH;
    }

    #[tracing::instrument(name = "credentials.refresh", skip_all)]
    pub async fn token(&self) -> Result<String> {
        // A single flight also serializes rotating refresh-token writes.
        let mut state = self.inner.lock().await;
        let host_session = state.credentials.credential_type == "datumctl_session";
        let refresh_margin = if host_session {
            Duration::ZERO
        } else {
            Duration::from_secs(30)
        };
        if !state.access_token.is_empty() && state.expires_at > SystemTime::now() + refresh_margin {
            return Ok(state.access_token.clone());
        }
        let credentials = &state.credentials;
        if host_session {
            credentials.validate()?;
            let (token, expiry) = session_token(credentials, Duration::from_secs(10)).await?;
            state.expires_at = expiry.min(SystemTime::now() + Duration::from_secs(30));
            state.access_token = token;
            return Ok(state.access_token.clone());
        }
        let mut form = vec![("client_id", credentials.client_id.clone())];
        if credentials.credential_type == "connector" {
            form.push(("grant_type", "refresh_token".into()));
            form.push(("refresh_token", credentials.refresh_token.clone()));
        } else {
            let token_uri = validate_url(&credentials.token_uri)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Invalid("system clock precedes Unix epoch".into()))?
                .as_secs();
            let claims = serde_json::json!({"iss":credentials.client_id,"sub":credentials.client_id,
                "aud":token_uri.origin().ascii_serialization(),"iat":now,"exp":now+60,"jti":format!("{:032x}",rand::random::<u128>())});
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(credentials.private_key_id.clone());
            let key = EncodingKey::from_rsa_pem(credentials.private_key.as_bytes())
                .map_err(|_| Error::Invalid("invalid RSA credential".into()))?;
            let assertion = encode(&header, &claims, &key)
                .map_err(|_| Error::Invalid("could not sign service-account assertion".into()))?;
            form.push((
                "grant_type",
                "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
            ));
            form.push(("assertion", assertion));
            form.push((
                "scope",
                if credentials.scope.is_empty() {
                    "openid profile email".into()
                } else {
                    credentials.scope.clone()
                },
            ));
        }
        let response = self
            .client
            .post(&credentials.token_uri)
            .form(&form)
            .send()
            .await?;
        tracing::debug!(
            status = response.status().as_u16(),
            "credential exchange completed"
        );
        if !response.status().is_success() {
            // Token endpoint bodies can contain secrets. Never surface them.
            return Err(Error::Authentication(response.status().as_u16()));
        }
        let bytes = super::bounded_body(response).await?;
        let token: TokenResponse = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Invalid("invalid token response".into()))?;
        if token.access_token.is_empty()
            || !token.token_type.eq_ignore_ascii_case("bearer")
            || token.expires_in == 0
            || token.expires_in > 31_536_000
        {
            return Err(Error::Invalid(
                "token response requires a bearer credential and bounded expires_in".into(),
            ));
        }
        if let Some(refresh) = token.refresh_token.filter(|value| !value.is_empty()) {
            state.credentials.refresh_token = refresh;
            if let Some(path) = &state.credentials.path {
                crate::repo::atomic_write_private(path, &serde_json::to_vec(&state.credentials)?)
                    .await?;
            }
        }
        state.expires_at = SystemTime::now() + Duration::from_secs(token.expires_in);
        state.access_token = token.access_token;
        Ok(state.access_token.clone())
    }
}
