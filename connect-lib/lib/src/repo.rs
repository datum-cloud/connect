use std::path::{Path, PathBuf};

use iroh::SecretKey;
use n0_error::{Result, StackResultExt, StdResultExt};
use tracing::{info, instrument, warn};

use crate::{config::Config, state::State};

/// Error returned by [`Repo::default_location`] when the
/// `DATUM_CONNECT_DIR` environment variable is not set.
///
/// Phase 11.5 D-09/D-10: the binary refuses to invent a default
/// location. The `Display` impl prints the multi-line directive
/// message that tells the user how to fix the situation.
#[derive(Debug, Clone)]
pub struct MissingConnectDir;

impl std::fmt::Display for MissingConnectDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(MISSING_CONNECT_DIR_MSG)
    }
}

impl std::error::Error for MissingConnectDir {}

const MISSING_CONNECT_DIR_MSG: &str = "error: DATUM_CONNECT_DIR is not set

The datum-connect binary expects this variable to point to its state
directory (where it stores the iroh listen_key, config, and per-project
state). It is normally set by the datumctl plugin host.

To run via datumctl (preferred):
  datumctl connect tunnel <subcommand> ...

To run datum-connect directly (development):
  export DATUM_CONNECT_DIR=\"$HOME/.datumctl/connect\"
  datum-connect <subcommand> ...

(exit 64)
";

// Repo builds up a series of file path conventions from a root directory path.
#[derive(Debug, Clone)]
pub struct Repo(PathBuf);

impl Repo {
    /// Create a Repo from a path without opening/creating (for sync use cases like update install).
    pub fn from_path(path: PathBuf) -> Self {
        Self(path)
    }

    const CONFIG_FILE: &str = "config.yml";
    const CONNECT_KEY_FILE: &str = "connect_key";
    pub const LISTEN_KEY_FILE: &str = "listen_key";
    const STATE_FILE: &str = "state.yml";
    pub fn default_location() -> Result<PathBuf, MissingConnectDir> {
        match std::env::var("DATUM_CONNECT_DIR") {
            Ok(path) if !path.is_empty() => Ok(PathBuf::from(path)),
            Ok(_) | Err(_) => Err(MissingConnectDir),
        }
    }

    /// Opens or creates a repo at the given base directory.
    pub async fn open_or_create(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        tokio::fs::create_dir_all(&base_dir).await?;
        info!("opening repo at {}", base_dir.display());

        let this = Self(base_dir);

        Ok(this)
    }

    pub async fn config(&self) -> Result<Config> {
        let config_file_path = self.0.join(Self::CONFIG_FILE);
        if !config_file_path.exists() {
            warn!("config does not exist. creating new config");
            let cfg = Config::default();
            cfg.write(config_file_path).await?;
            return Ok(cfg);
        };

        Config::from_file(config_file_path).await
    }

    pub async fn load_state(&self) -> Result<crate::StateWrapper> {
        let state_file_path = self.0.join(Self::STATE_FILE);
        let state = if !state_file_path.exists() {
            let state = State::default();
            state.write_to_file(state_file_path).await?;
            state
        } else {
            State::from_file(state_file_path).await?
        };
        Ok(crate::StateWrapper::new(state))
    }

    pub async fn write_state(&self, state: &State) -> Result<()> {
        state.write_to_file(self.0.join(Self::STATE_FILE)).await
    }

    pub async fn write_selected_context(
        &self,
        selected: Option<&crate::SelectedContext>,
    ) -> Result<()> {
        let path = self.0.join(Self::CONFIG_FILE);
        let mut config = if path.exists() {
            let data = tokio::fs::read_to_string(&path)
                .await
                .context("reading config file")?;
            serde_yml::from_str(&data).std_context("parsing config file")?
        } else {
            crate::config::Config::default()
        };
        config.selected_context = selected.cloned();
        config.write(path).await
    }

    pub async fn read_selected_context(&self) -> Result<Option<crate::SelectedContext>> {
        let path = self.0.join(Self::CONFIG_FILE);
        if path.exists() {
            let data = tokio::fs::read_to_string(path)
                .await
                .context("reading config file")?;
            let config: crate::config::Config =
                serde_yml::from_str(&data).std_context("parsing config file")?;
            return Ok(config.selected_context);
        }
        Ok(None)
    }

    pub async fn connect_key(&self) -> Result<SecretKey> {
        let key_file_path = self.0.join(Self::CONNECT_KEY_FILE);
        self.secret_key(key_file_path).await
    }

    /// Return a fresh listen key always written to a timestamp-suffixed file
    /// (`listen_key[.<project_id>].<YYYYMMDDHHmmss>`) so a stale key from a previous
    /// `listen` is never accidentally reused. The plain `listen_key` name is only
    /// used inside per-tunnel subdirectories where the key is intentionally stable.
    pub async fn listen_key(&self, project_id: Option<&str>) -> Result<SecretKey> {
        let key = SecretKey::generate(&mut rand::rng());
        let now = chrono::Local::now().format("%Y%m%d%H%M%S");
        let suffix = match project_id {
            Some(pid) => format!("{}.{}", pid, now),
            None => now.to_string(),
        };
        let key_file_path = self.0.join(format!("{}.{}", Self::LISTEN_KEY_FILE, suffix));
        if let Some(parent) = key_file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        write_secret_key(&key_file_path, &key).await?;
        Ok(key)
    }

    /// Project-scoped listen key. Each project gets its own iroh identity so
    /// Connectors registered in different projects don't collide on the iroh
    /// DNS record (the controller assigns ownership to one and leaves the
    /// others with `IrohDNSPublished=False; DeferredToOwner`, which manifests
    /// as a tunnel that reports ready but silently drops data).
    ///
    /// On first access for any project, if the legacy flat `listen_key` exists
    /// it is moved into this project's directory so the user keeps continuity
    /// with whatever Connector that key was registered as. Subsequent projects
    /// (no legacy file left) get freshly generated keys.
    pub async fn listen_key_for_project(&self, project_id: &str) -> Result<SecretKey> {
        let project_dir = self.0.join(project_id);
        let key_file_path = project_dir.join(Self::LISTEN_KEY_FILE);
        if !key_file_path.exists() {
            let legacy = self.0.join(Self::LISTEN_KEY_FILE);
            if legacy.exists() {
                tokio::fs::create_dir_all(&project_dir).await?;
                info!(
                    "migrating legacy listen_key {} -> {} for project {project_id}",
                    legacy.display(),
                    key_file_path.display(),
                );
                tokio::fs::rename(&legacy, &key_file_path).await?;
            }
        }
        self.secret_key(key_file_path).await
    }

    /// Per-tunnel listen key. Each named tunnel gets its own iroh identity so
    /// tunnels in the same project don't collide on the iroh DNS record.
    ///
    /// On first access, if a legacy flat `listen_key` exists at the repo root
    /// for this project, it is moved into `<project_id>/<tunnel_name>/listen_key`
    /// (preserving the key value for continuity with the registered Connector).
    /// Subsequent tunnels in the same project (no legacy file left) get freshly
    /// generated keys.
    /// Legacy flat key location at the repo root (same as the old
    /// `Repo::listen_key()` path).
    const LEGACY_LISTEN_KEY: &'static str = "listen_key";

    ///
    /// Returns `Ok(None)` when no key exists for this tunnel and there is no
    /// legacy key to migrate. A missing key is an expected state (the tunnel
    /// was created on another machine, or the file was removed) and the
    /// caller decides whether to generate a fresh identity.
    #[instrument("repo", skip_all)]
    pub async fn listen_key_for_tunnel(
        &self,
        project_id: &str,
        tunnel_name: &str,
    ) -> Result<Option<SecretKey>> {
        let tunnel_dir = self.0.join(project_id).join(tunnel_name);
        let key_file_path = tunnel_dir.join(Self::LISTEN_KEY_FILE);

        if !key_file_path.exists() {
            // Check for legacy key at repo root (the old flat layout).
            let legacy = self.0.join(Self::LEGACY_LISTEN_KEY);
            if legacy.exists() {
                tokio::fs::create_dir_all(&tunnel_dir).await?;
                info!(
                    "migrating legacy listen_key {} -> {} for project {project_id} tunnel {tunnel_name}",
                    legacy.display(),
                    key_file_path.display(),
                );
                tokio::fs::rename(&legacy, &key_file_path).await?;
            } else {
                return Ok(None);
            }
        }

        let key = tokio::fs::read(&key_file_path).await?;
        let key = key.as_slice().try_into().anyerr()?;
        Ok(Some(SecretKey::from_bytes(key)))
    }

    /// Persist a key for a tunnel (used when regenerating a key for resume).
    pub async fn save_listen_key_for_tunnel(
        &self,
        project_id: &str,
        tunnel_name: &str,
        key: &SecretKey,
    ) -> Result<()> {
        let tunnel_dir = self.0.join(project_id).join(tunnel_name);
        let key_file_path = tunnel_dir.join(Self::LISTEN_KEY_FILE);
        tokio::fs::create_dir_all(&tunnel_dir).await?;
        write_secret_key(&key_file_path, key).await?;
        Ok(())
    }

    async fn secret_key(&self, key_file_path: PathBuf) -> Result<SecretKey> {
        if !key_file_path.exists() {
            warn!("secret key does not exist. creating new key");
            if let Some(parent) = key_file_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            return self.create_key(&key_file_path).await;
        };

        let key = tokio::fs::read(key_file_path).await?;
        let key = key.as_slice().try_into().anyerr()?;
        Ok(SecretKey::from_bytes(key))
    }

    async fn create_key(&self, key_file_path: &Path) -> Result<SecretKey> {
        let key = SecretKey::generate(&mut rand::rng());
        write_secret_key(key_file_path, &key).await?;
        Ok(key)
    }

    /// Get the base directory path of this repo
    pub fn path(&self) -> &PathBuf {
        &self.0
    }

    /// Delete the local state directory for a tunnel
    pub async fn delete_tunnel_dir(&self, project_id: &str, tunnel_name: &str) -> Result<()> {
        let tunnel_dir = self.0.join(project_id).join(tunnel_name);
        if tunnel_dir.exists() {
            tokio::fs::remove_dir_all(&tunnel_dir).await?;
        }
        Ok(())
    }
}

/// Write a secret key to disk atomically, readable only by the current user.
///
/// The key is written to a fresh temporary file beside `path` and then
/// renamed over it, so a crash mid-write can never leave a truncated key
/// behind, and a reader holding a descriptor to the previous file never
/// observes the new key.
///
/// On Unix the temporary file is created with mode 0600 so the iroh
/// identity is not exposed to other local users through the default umask.
/// On other platforms the file inherits the access control of its parent
/// directory; the caller is responsible for choosing a directory that only
/// the current user can read.
async fn write_secret_key(path: &Path, key: &SecretKey) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("secret key path has no file name")?;
    let tmp_path = path.with_file_name(format!(
        "{file_name}.{}.{}.tmp",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let result = async {
        let mut file = options.open(&tmp_path).await?;
        file.write_all(&key.to_bytes()).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp_path, path).await?;
        Ok::<(), std::io::Error>(())
    }
    .await;

    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }
    result?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn temp_repo_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("datum-repo-test-{}", uuid::Uuid::new_v4()));
        path
    }

    #[tokio::test]
    async fn listen_key_for_project_migrates_legacy_into_first_project()
    -> Result<(), Box<dyn std::error::Error>> {
        // The legacy `listen_key` lived at the repo root and was reused for
        // every project the CLI talked to. The migration must move (not copy)
        // it into the first project that requests it, so the second project
        // gets a fresh identity instead of joining the cross-project DNS race.
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        // Create a legacy key at the plain LISTEN_KEY_FILE path (no timestamp).
        let legacy = SecretKey::generate(&mut rand::rng());
        let legacy_bytes = legacy.to_bytes();
        let legacy_path = repo.0.join(Repo::LISTEN_KEY_FILE);
        tokio::fs::write(&legacy_path, &legacy_bytes)
            .await
            .expect("should write legacy key");
        assert!(legacy_path.exists(), "precondition: legacy key exists");

        let p1 = repo.listen_key_for_project("project-a").await?;
        assert_eq!(
            p1.to_bytes(),
            legacy_bytes,
            "first project must adopt the legacy key"
        );
        assert!(
            !legacy_path.exists(),
            "legacy file must be gone after migration"
        );
        let p1_path = repo.0.join("project-a").join(Repo::LISTEN_KEY_FILE);
        assert!(p1_path.exists(), "key must now live under the project dir");

        let p2 = repo.listen_key_for_project("project-b").await?;
        assert_ne!(
            p2.to_bytes(),
            legacy_bytes,
            "second project must get a fresh key, not the legacy one"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listen_key_for_project_is_stable_across_calls()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        let first = repo.listen_key_for_project("project-x").await?;
        let second = repo.listen_key_for_project("project-x").await?;
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "repeat calls must return the same persisted key"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listen_key_for_project_generates_fresh_without_legacy()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        let key = repo.listen_key_for_project("only-project").await?;
        let legacy_path = repo.0.join(Repo::LISTEN_KEY_FILE);
        assert!(!legacy_path.exists(), "no legacy must be created");
        let project_path = repo.0.join("only-project").join(Repo::LISTEN_KEY_FILE);
        assert!(project_path.exists());
        assert_eq!(tokio::fs::read(&project_path).await?, key.to_bytes());
        Ok(())
    }

    // ── Per-tunnel key tests ──────────────────────────────────────────

    #[tokio::test]
    async fn listen_key_for_tunnel_fresh_project_generates_key_at_per_tunnel_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        // Pre-create the key so listen_key_for_tunnel can read it.
        let tunnel_dir = repo.0.join("my-project").join("my-tunnel");
        tokio::fs::create_dir_all(&tunnel_dir).await?;
        let key_path = tunnel_dir.join(Repo::LISTEN_KEY_FILE);
        let seed_key = SecretKey::generate(&mut rand::rng());
        tokio::fs::write(&key_path, seed_key.to_bytes()).await?;

        let key = repo
            .listen_key_for_tunnel("my-project", "my-tunnel")
            .await?
            .expect("key exists");
        assert!(key_path.exists(), "key must exist at per-tunnel path");
        assert_eq!(tokio::fs::read(&key_path).await?, key.to_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn listen_key_for_tunnel_migrates_legacy_key_to_default_tunnel()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        // Create a legacy key at the project root (plain name, no timestamp).
        let legacy_key = SecretKey::generate(&mut rand::rng());
        let legacy_bytes = legacy_key.to_bytes();
        let legacy_path = repo.0.join(Repo::LISTEN_KEY_FILE);
        tokio::fs::write(&legacy_path, &legacy_bytes)
            .await
            .expect("should write legacy key");
        assert!(legacy_path.exists(), "precondition: legacy key exists");

        // Access per-tunnel for "default" tunnel — should migrate.
        let key = repo
            .listen_key_for_tunnel("proj-migrate", "default")
            .await?
            .expect("legacy key migrated");
        assert_eq!(
            key.to_bytes(),
            legacy_bytes,
            "migrated key must match the legacy key value"
        );
        assert!(
            !legacy_path.exists(),
            "legacy file must be removed after migration"
        );
        let expected_path = repo
            .0
            .join("proj-migrate")
            .join("default")
            .join(Repo::LISTEN_KEY_FILE);
        assert!(
            expected_path.exists(),
            "key must now live at per-tunnel path"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listen_key_for_tunnel_is_stable_across_calls() -> Result<(), Box<dyn std::error::Error>>
    {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        // Pre-create the key.
        let tunnel_dir = repo.0.join("stable-proj").join("stable-tunnel");
        tokio::fs::create_dir_all(&tunnel_dir).await?;
        let key_path = tunnel_dir.join(Repo::LISTEN_KEY_FILE);
        let seed_key = SecretKey::generate(&mut rand::rng());
        tokio::fs::write(&key_path, seed_key.to_bytes()).await?;

        let first = repo
            .listen_key_for_tunnel("stable-proj", "stable-tunnel")
            .await?
            .expect("key exists");
        let second = repo
            .listen_key_for_tunnel("stable-proj", "stable-tunnel")
            .await?
            .expect("key exists");
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "repeat calls must return the same persisted key"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listen_key_for_tunnel_two_tunnels_get_distinct_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        // Pre-create distinct keys for two tunnels.
        for name in ["tunnel-a", "tunnel-b"] {
            let tunnel_dir = repo.0.join("multi-proj").join(name);
            tokio::fs::create_dir_all(&tunnel_dir).await?;
            let key_path = tunnel_dir.join(Repo::LISTEN_KEY_FILE);
            let seed_key = SecretKey::generate(&mut rand::rng());
            tokio::fs::write(&key_path, seed_key.to_bytes()).await?;
        }
        let key_a = repo
            .listen_key_for_tunnel("multi-proj", "tunnel-a")
            .await?
            .expect("key exists");
        let key_b = repo
            .listen_key_for_tunnel("multi-proj", "tunnel-b")
            .await?
            .expect("key exists");
        assert_ne!(
            key_a.to_bytes(),
            key_b.to_bytes(),
            "two tunnels in the same project must get distinct keys"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listen_key_for_tunnel_returns_none_when_key_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        let result = repo
            .listen_key_for_tunnel("missing-proj", "missing-tunnel")
            .await?;
        assert!(
            result.is_none(),
            "a missing key with no legacy file to migrate is Ok(None), not an error"
        );
        Ok(())
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> std::io::Result<u32> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
    }

    async fn leftover_temp_files(dir: &Path) -> std::io::Result<Vec<String>> {
        let mut leftovers = Vec::new();
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                leftovers.push(name);
            }
        }
        Ok(leftovers)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generated_keys_are_private() -> TestResult {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;

        repo.connect_key().await?;
        assert_eq!(mode_of(&repo.0.join(Repo::CONNECT_KEY_FILE))?, 0o600);

        repo.listen_key_for_project("proj").await?;
        assert_eq!(
            mode_of(&repo.0.join("proj").join(Repo::LISTEN_KEY_FILE))?,
            0o600
        );

        let key = SecretKey::generate(&mut rand::rng());
        repo.save_listen_key_for_tunnel("proj", "tun", &key).await?;
        assert_eq!(
            mode_of(&repo.0.join("proj").join("tun").join(Repo::LISTEN_KEY_FILE))?,
            0o600
        );

        repo.listen_key(Some("proj")).await?;
        let mut entries = tokio::fs::read_dir(&repo.0).await?;
        let mut found = false;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("listen_key.proj.") && !name.ends_with(".tmp") {
                found = true;
                assert_eq!(mode_of(&entry.path())?, 0o600, "{name}");
            }
        }
        assert!(found, "timestamped listen key must have been written");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replacing_a_world_readable_key_yields_a_private_file() -> TestResult {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        let tunnel_dir = repo.0.join("proj").join("tun");
        tokio::fs::create_dir_all(&tunnel_dir).await?;
        let key_path = tunnel_dir.join(Repo::LISTEN_KEY_FILE);
        tokio::fs::write(&key_path, b"old").await?;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))?;
        assert_eq!(mode_of(&key_path)?, 0o644, "precondition");

        // A reader that opened the old, world-readable file must not see the
        // new key: the write goes to a fresh inode and is renamed into place.
        let old_handle = std::fs::File::open(&key_path)?;

        let key = SecretKey::generate(&mut rand::rng());
        repo.save_listen_key_for_tunnel("proj", "tun", &key).await?;
        assert_eq!(mode_of(&key_path)?, 0o600);
        assert_eq!(tokio::fs::read(&key_path).await?, key.to_bytes());

        let mut through_old_handle = Vec::new();
        std::io::Read::read_to_end(&mut &old_handle, &mut through_old_handle)?;
        assert_eq!(
            through_old_handle, b"old",
            "old descriptor must still point at the old contents"
        );
        Ok(())
    }

    #[tokio::test]
    async fn key_writes_leave_no_temp_files_behind() -> TestResult {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        repo.connect_key().await?;
        let key = SecretKey::generate(&mut rand::rng());
        repo.save_listen_key_for_tunnel("proj", "tun", &key).await?;
        repo.save_listen_key_for_tunnel("proj", "tun", &key).await?;

        assert!(leftover_temp_files(&repo.0).await?.is_empty());
        assert!(
            leftover_temp_files(&repo.0.join("proj").join("tun"))
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_key_write_cleans_up_its_temp_file() -> TestResult {
        let repo = Repo::open_or_create(temp_repo_dir()).await?;
        // Make the rename fail by putting a non-empty directory where the key
        // file should go.
        let key_path = repo.0.join(Repo::CONNECT_KEY_FILE);
        tokio::fs::create_dir_all(key_path.join("occupied")).await?;

        let key = SecretKey::generate(&mut rand::rng());
        assert!(write_secret_key(&key_path, &key).await.is_err());
        assert!(leftover_temp_files(&repo.0).await?.is_empty());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod default_location_tests {
    use super::*;

    // Both crates are Rust edition 2024 — std::env::set_var /
    // remove_var require the `unsafe` block. The shared ENV_LOCK
    // serializes against the other env-mutating tests in the crate
    // (datum_cloud/external_token_source.rs, datum_cloud/mod.rs).

    #[test]
    fn returns_ok_when_var_set() {
        let _lock = crate::test_util::env_lock();
        let saved = std::env::var("DATUM_CONNECT_DIR").ok();
        unsafe {
            std::env::set_var("DATUM_CONNECT_DIR", "/tmp/test-connect-dir");
        }

        let got = Repo::default_location();

        // Restore before asserting so a panic doesn't leak the mutation.
        unsafe {
            match saved {
                Some(v) => std::env::set_var("DATUM_CONNECT_DIR", v),
                None => std::env::remove_var("DATUM_CONNECT_DIR"),
            }
        }

        match got {
            Ok(p) => assert_eq!(p, PathBuf::from("/tmp/test-connect-dir")),
            Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    #[test]
    fn returns_err_when_var_empty() {
        let _lock = crate::test_util::env_lock();
        let saved = std::env::var("DATUM_CONNECT_DIR").ok();
        unsafe {
            std::env::set_var("DATUM_CONNECT_DIR", "");
        }

        let got = Repo::default_location();

        unsafe {
            match saved {
                Some(v) => std::env::set_var("DATUM_CONNECT_DIR", v),
                None => std::env::remove_var("DATUM_CONNECT_DIR"),
            }
        }

        assert!(matches!(got, Err(MissingConnectDir)));
    }

    #[test]
    fn returns_err_when_var_unset() {
        let _lock = crate::test_util::env_lock();
        let saved = std::env::var("DATUM_CONNECT_DIR").ok();
        unsafe {
            std::env::remove_var("DATUM_CONNECT_DIR");
        }

        let got = Repo::default_location();

        unsafe {
            if let Some(v) = saved {
                std::env::set_var("DATUM_CONNECT_DIR", v);
            }
        }

        assert!(matches!(got, Err(MissingConnectDir)));
    }

    #[test]
    fn missing_connect_dir_display_contains_directive() {
        // Pure formatting check — no env mutation needed.
        let msg = format!("{}", MissingConnectDir);
        assert!(msg.contains("DATUM_CONNECT_DIR is not set"), "msg = {msg}");
        assert!(msg.contains("datumctl connect tunnel"), "msg = {msg}");
        assert!(
            msg.contains("export DATUM_CONNECT_DIR=\"$HOME/.datumctl/connect\""),
            "msg = {msg}"
        );
        assert!(msg.contains("(exit 64)"), "msg = {msg}");
    }
}
