use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use connect_lib::secure_fs;
use fs2::FileExt;
use tokio::{io::AsyncWriteExt, sync::Mutex};

use crate::{error::ApiError, model::DaemonState};

pub struct Store {
    repo: PathBuf,
    path: PathBuf,
    state: Mutex<DaemonState>,
    _process_lock: std::fs::File,
}

impl Store {
    pub async fn open(repo: &Path) -> Result<Arc<Self>, ApiError> {
        let dir = repo.join("daemon");
        private_dir(&dir).await?;
        let lock_path = dir.join(".lock");
        let process_lock = tokio::task::spawn_blocking(move || -> io::Result<std::fs::File> {
            let file = secure_fs::open_private_lock(&lock_path)?;
            file.try_lock_exclusive()?;
            Ok(file)
        })
        .await
        .map_err(|error| ApiError::internal(format!("joining repository lock task: {error}")))??;

        let path = dir.join("state.json");
        if tokio::fs::try_exists(&path).await? {
            secure_fs::set_private_file_permissions(&path).await?;
        }
        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<DaemonState>(&bytes).map_err(|error| {
                ApiError::internal(format!("parsing {}: {error}", path.display()))
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => DaemonState::default(),
            Err(error) => return Err(error.into()),
        };
        if state.version != crate::model::STATE_VERSION {
            return Err(ApiError::internal(format!(
                "unsupported daemon state version {}",
                state.version
            )));
        }
        let store = Arc::new(Self {
            repo: repo.to_path_buf(),
            path,
            state: Mutex::new(state),
            _process_lock: process_lock,
        });
        if !tokio::fs::try_exists(&store.path).await? {
            let guard = store.state.lock().await;
            store.persist(&guard).await?;
        }
        Ok(store)
    }

    pub async fn snapshot(&self) -> DaemonState {
        self.state.lock().await.clone()
    }

    /// Import refreshable credentials into daemon-owned private storage. The
    /// persisted state never depends on an arbitrary source path continuing to
    /// exist after `up` returns.
    pub async fn import_credentials(
        &self,
        project: &str,
        source: &Path,
    ) -> Result<String, ApiError> {
        let metadata = tokio::fs::metadata(source).await?;
        if !metadata.is_file() {
            return Err(ApiError::bad_request(
                "credentials_file must be a regular file",
            ));
        }
        const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
        if metadata.len() > MAX_CREDENTIAL_BYTES {
            return Err(ApiError::bad_request("credentials_file exceeds 1 MiB"));
        }
        let bytes = tokio::fs::read(source).await?;
        self.save_credentials(project, &bytes).await
    }

    /// Store a validated credential or a secret-free host-session descriptor.
    pub async fn save_credentials(&self, project: &str, bytes: &[u8]) -> Result<String, ApiError> {
        let destination = self
            .repo
            .join("daemon")
            .join("projects")
            .join(project)
            .join("credentials.json");
        atomic_write_private(&destination, bytes).await?;
        Ok(destination.to_string_lossy().into_owned())
    }

    /// Commit an all-or-nothing state transition. Memory is published only
    /// after the replacement file has been flushed and renamed successfully.
    pub async fn transact<R>(
        &self,
        f: impl FnOnce(&mut DaemonState) -> Result<R, ApiError>,
    ) -> Result<R, ApiError> {
        let mut guard = self.state.lock().await;
        let mut next = guard.clone();
        let result = f(&mut next)?;
        self.persist(&next).await?;
        *guard = next;
        Ok(result)
    }

    async fn persist(&self, state: &DaemonState) -> Result<(), ApiError> {
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| ApiError::internal(format!("serializing state: {error}")))?;
        atomic_write_private(&self.path, &bytes).await?;
        Ok(())
    }
}

async fn private_dir(path: &Path) -> io::Result<()> {
    secure_fs::ensure_private_dir(path).await
}

pub async fn atomic_write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    private_dir(parent).await?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
    let mut file =
        tokio::fs::File::from_std(secure_fs::create_new_private(&temporary, false, true)?);
    let result = async {
        file.write_all(data).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        secure_fs::atomic_replace(&temporary, path).await?;
        #[cfg(unix)]
        tokio::fs::File::open(parent).await?.sync_all().await?;
        Ok::<_, io::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(temporary).await;
    }
    result
}
