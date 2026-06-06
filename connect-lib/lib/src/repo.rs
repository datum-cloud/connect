use std::path::PathBuf;

use iroh::SecretKey;
use tracing::{info, warn};
use n0_error::{Result, StackResultExt, StdResultExt};

use crate::{
    config::Config,
    state::State,
};

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
    const LISTEN_KEY_FILE: &str = "listen_key";
    const STATE_FILE: &str = "state.yml";

    pub fn default_location() -> PathBuf {
        match std::env::var("DATUM_CONNECT_REPO") {
            Ok(path) => path.into(),
            Err(_) => {
                let base = dirs_next::data_local_dir()
                    .expect("Failed to get local data dir");
                base.join("datumctl").join("connect")
            }
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

    pub async fn listen_key(&self) -> Result<SecretKey> {
        let key_file_path = self.0.join(Self::LISTEN_KEY_FILE);
        self.secret_key(key_file_path).await
    }

    async fn secret_key(&self, key_file_path: PathBuf) -> Result<SecretKey> {
        if !key_file_path.exists() {
            warn!("secret key does not exist. creating new key");
            tokio::fs::create_dir_all(&self.0).await?;
            return self.create_key(&key_file_path).await;
        };

        let key = tokio::fs::read(key_file_path).await?;
        let key = key.as_slice().try_into().anyerr()?;
        Ok(SecretKey::from_bytes(key))
    }

    async fn create_key(&self, key_file_path: &PathBuf) -> Result<SecretKey> {
        let key = SecretKey::generate(&mut rand::rng());
        tokio::fs::write(key_file_path, key.to_bytes()).await?;
        Ok(key)
    }

    /// Get the base directory path of this repo
    pub fn path(&self) -> &PathBuf {
        &self.0
    }
}
