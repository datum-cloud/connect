use std::{io, path::Path};

use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::secure_fs;

const TEMP_FILE_ATTEMPTS: usize = 16;

pub(crate) async fn atomic_write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secure_fs::ensure_private_dir(parent).await?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;

    let mut opened = None;
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let candidate = parent.join(format!(
            ".{}.{}.tmp",
            file_name.to_string_lossy(),
            rand::random::<u64>()
        ));
        match secure_fs::create_new_private(&candidate, false, true) {
            Ok(file) => {
                opened = Some((candidate, tokio::fs::File::from_std(file)));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temporary_path, mut file) = opened.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate an atomic-write temporary file",
        )
    })?;

    let result = async {
        file.write_all(data).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        secure_fs::atomic_replace(&temporary_path, path).await?;
        sync_parent_directory(path).await;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary_path).await;
    }
    result
}

#[cfg(unix)]
async fn sync_parent_directory(destination: &Path) {
    let Some(parent) = destination.parent() else {
        return;
    };
    if let Err(error) = async {
        let directory = tokio::fs::File::open(parent).await?;
        directory.sync_all().await
    }
    .await
    {
        warn!(directory = %parent.display(), %error, "could not sync private-file directory");
    }
}

#[cfg(not(unix))]
async fn sync_parent_directory(_destination: &Path) {}
