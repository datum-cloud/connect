//! Share keys: what a sharer keeps to hand out the same ticket across restarts.
//!
//! A ticket names the sharer's iroh identity, the pairing secret, and the
//! destination port. A [`ShareKey`] holds all three, so a share started again
//! with the same key accepts tickets printed by earlier runs. Peers find the
//! restarted sharer by its identity even when its addresses changed, through
//! the transport preset's address lookup.
//!
//! Text form: `DCKEY1` followed by unpadded RFC 4648 base32 of
//!
//! | Field | Size |
//! |---|---|
//! | version | 1 byte, `1` |
//! | iroh secret key | 32 bytes |
//! | pairing secret | 32 bytes |
//! | port | 2 bytes, big endian, nonzero |
use std::{
    fmt, io,
    path::{Path, PathBuf},
    str::FromStr,
};

use data_encoding::BASE32_NOPAD;
use iroh::{EndpointId, SecretKey};

use crate::ticket::Reader;

const PREFIX: &str = "DCKEY1";
const VERSION: u8 = 1;

/// The identity, pairing secret, and destination port behind a share's
/// tickets. Anyone holding it can impersonate the share, so keep it private.
#[derive(Clone)]
pub struct ShareKey {
    pub(crate) secret_key: SecretKey,
    pub(crate) secret: [u8; 32],
    pub(crate) port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("not a Datum Connect share key")]
    Prefix,
    #[error("malformed share key")]
    Malformed,
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    /// Like ssh with private keys, a key file others can read is refused.
    #[error("{} is readable by other users; run chmod 600 on it", path.display())]
    Permissions { path: PathBuf },
}

impl ShareKey {
    /// A new key whose tickets name `port`. The port is the destination the
    /// ticket carries; the share may later forward it to another local port.
    pub fn generate(port: u16) -> Self {
        Self {
            secret_key: SecretKey::generate(),
            secret: rand::random(),
            port,
        }
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Reads the key at `path`, or creates one for `port` there. Returns the
    /// key and whether it was created.
    pub fn load_or_create(path: &Path, port: u16) -> Result<(Self, bool), KeyError> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                check_private(path)?;
                Ok((text.parse()?, false))
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let key = Self::generate(port);
                key.write(path)?;
                Ok((key, true))
            }
            Err(source) => Err(KeyError::Io {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// Writes the key to `path` through a temporary file, readable only by
    /// this user.
    pub fn write(&self, path: &Path) -> Result<(), KeyError> {
        use std::io::Write;
        let io_error = |source| KeyError::Io {
            path: path.to_owned(),
            source,
        };
        let tmp = path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = options
            .open(&tmp)
            .and_then(|mut file| {
                writeln!(file, "{self}")?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(io_error)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(67);
        out.push(VERSION);
        out.extend_from_slice(&self.secret_key.to_bytes());
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.port.to_be_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes);
        if reader.u8()? != VERSION {
            return None;
        }
        let secret_key = SecretKey::from_bytes(&reader.array::<32>()?);
        let secret = reader.array::<32>()?;
        let port = u16::from_be_bytes(reader.array::<2>()?);
        if port == 0 || !reader.0.is_empty() {
            return None;
        }
        Some(Self {
            secret_key,
            secret,
            port,
        })
    }
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|source| KeyError::Io {
            path: path.to_owned(),
            source,
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(KeyError::Permissions {
            path: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), KeyError> {
    Ok(())
}

impl fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareKey")
            .field("endpoint_id", &self.endpoint_id())
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", BASE32_NOPAD.encode(&self.to_bytes()))
    }
}

impl FromStr for ShareKey {
    type Err = KeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim().to_ascii_uppercase();
        let body = value.strip_prefix(PREFIX).ok_or(KeyError::Prefix)?;
        let bytes = BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| KeyError::Malformed)?;
        Self::from_bytes(&bytes).ok_or(KeyError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = ShareKey::generate(9999);
        let parsed: ShareKey = key.to_string().parse().unwrap();
        assert_eq!(parsed.endpoint_id(), key.endpoint_id());
        assert_eq!(parsed.secret, key.secret);
        assert_eq!(parsed.port, 9999);
        let lower: ShareKey = key.to_string().to_lowercase().parse().unwrap();
        assert_eq!(lower.secret, key.secret);
    }

    #[test]
    fn debug_omits_secrets() {
        let key = ShareKey::generate(9999);
        let debug = format!("{key:?}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(!debug.contains(&key.to_string()), "{debug}");
    }

    #[test]
    fn rejects_other_input() {
        assert!(matches!(
            "DCSHARE2AA".parse::<ShareKey>(),
            Err(KeyError::Prefix)
        ));
        assert!(matches!(
            "DCKEY1!!".parse::<ShareKey>(),
            Err(KeyError::Malformed)
        ));
        let mut bytes = ShareKey::generate(1).to_bytes();
        bytes[0] = 2;
        let version = format!("{PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        assert!(matches!(
            version.parse::<ShareKey>(),
            Err(KeyError::Malformed)
        ));
        let mut bytes = ShareKey::generate(1).to_bytes();
        let len = bytes.len();
        bytes[len - 2..].copy_from_slice(&[0, 0]);
        let zero_port = format!("{PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        assert!(matches!(
            zero_port.parse::<ShareKey>(),
            Err(KeyError::Malformed)
        ));
    }

    #[test]
    fn load_or_create_keeps_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("share.key");
        let (created, was_created) = ShareKey::load_or_create(&path, 3000).unwrap();
        assert!(was_created);
        // The port only applies when creating.
        let (loaded, was_created) = ShareKey::load_or_create(&path, 4000).unwrap();
        assert!(!was_created);
        assert_eq!(loaded.endpoint_id(), created.endpoint_id());
        assert_eq!(loaded.secret, created.secret);
        assert_eq!(loaded.port, 3000);
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("share.key");
        ShareKey::load_or_create(&path, 3000).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ShareKey::load_or_create(&path, 3000),
            Err(KeyError::Permissions { .. })
        ));
    }
}
