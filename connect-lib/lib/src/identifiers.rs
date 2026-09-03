use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

/// A validated Datum project identifier.
///
/// Project identifiers are safe to use as a single path component. They may
/// not be empty, absolute, `.` or `..`, contain a path separator, use a
/// Windows drive/stream prefix, alias a Windows device, or contain control
/// characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProjectId(String);

impl ProjectId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProjectIdError> {
        Self::try_from(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectIdError {
    #[error("project ID must not be empty")]
    Empty,
    #[error("project ID must not be '.'")]
    CurrentDirectory,
    #[error("project ID must not be '..'")]
    ParentDirectory,
    #[error("project ID must not be absolute")]
    Absolute,
    #[error("project ID must not contain '/' or '\\'")]
    PathSeparator,
    #[error("project ID must not contain ':'")]
    WindowsPathPrefix,
    #[error("project ID must not end in a dot or space")]
    WindowsTrailingDotOrSpace,
    #[error("project ID must not use reserved Windows device name '{name}'")]
    WindowsReservedName { name: String },
    #[error("project ID must not contain NUL (at byte {index})")]
    Nul { index: usize },
    #[error("project ID must not contain control characters (at byte {index})")]
    ControlCharacter { index: usize },
}

impl TryFrom<String> for ProjectId {
    type Error = ProjectIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_project_id(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for ProjectId {
    type Error = ProjectIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl FromStr for ProjectId {
    type Err = ProjectIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl AsRef<str> for ProjectId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<ProjectId> for String {
    fn from(value: ProjectId) -> Self {
        value.into_inner()
    }
}

impl<'de> Deserialize<'de> for ProjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

fn validate_project_id(value: &str) -> Result<(), ProjectIdError> {
    if value.is_empty() {
        return Err(ProjectIdError::Empty);
    }
    if value == "." {
        return Err(ProjectIdError::CurrentDirectory);
    }
    if value == ".." {
        return Err(ProjectIdError::ParentDirectory);
    }
    if std::path::Path::new(value).is_absolute() {
        return Err(ProjectIdError::Absolute);
    }
    if value.contains('/') || value.contains('\\') {
        return Err(ProjectIdError::PathSeparator);
    }
    if value.contains(':') {
        return Err(ProjectIdError::WindowsPathPrefix);
    }
    if value.ends_with(['.', ' ']) {
        return Err(ProjectIdError::WindowsTrailingDotOrSpace);
    }
    let windows_stem = value.split('.').next().unwrap_or(value);
    let windows_stem_upper = windows_stem.to_ascii_uppercase();
    let is_reserved_windows_name = matches!(
        windows_stem_upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if is_reserved_windows_name {
        return Err(ProjectIdError::WindowsReservedName {
            name: windows_stem.to_string(),
        });
    }
    if let Some(index) = value.find('\0') {
        return Err(ProjectIdError::Nul { index });
    }
    if let Some((index, _)) = value
        .char_indices()
        .find(|(_, character)| character.is_control())
    {
        return Err(ProjectIdError::ControlCharacter { index });
    }
    Ok(())
}

/// A validated Kubernetes DNS subdomain used to identify a tunnel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TunnelId(String);

impl TunnelId {
    pub fn new(value: impl Into<String>) -> Result<Self, TunnelIdError> {
        Self::try_from(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TunnelIdError {
    #[error("tunnel ID must not be empty")]
    Empty,
    #[error("tunnel ID must be at most 253 bytes, got {length}")]
    TooLong { length: usize },
    #[error("tunnel ID label {label} must not be empty")]
    EmptyLabel { label: usize },
    #[error("tunnel ID label {label} must be at most 63 bytes, got {length}")]
    LabelTooLong { label: usize, length: usize },
    #[error("tunnel ID contains invalid character '{character}' at byte {index}")]
    InvalidCharacter { character: char, index: usize },
    #[error("tunnel ID label {label} must start with a lowercase letter or digit")]
    InvalidLabelStart { label: usize },
    #[error("tunnel ID label {label} must end with a lowercase letter or digit")]
    InvalidLabelEnd { label: usize },
}

impl TryFrom<String> for TunnelId {
    type Error = TunnelIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_tunnel_id(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for TunnelId {
    type Error = TunnelIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl FromStr for TunnelId {
    type Err = TunnelIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl AsRef<str> for TunnelId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for TunnelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<TunnelId> for String {
    fn from(value: TunnelId) -> Self {
        value.into_inner()
    }
}

impl<'de> Deserialize<'de> for TunnelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

fn validate_tunnel_id(value: &str) -> Result<(), TunnelIdError> {
    if value.is_empty() {
        return Err(TunnelIdError::Empty);
    }
    if value.len() > 253 {
        return Err(TunnelIdError::TooLong {
            length: value.len(),
        });
    }
    if let Some((index, character)) = value
        .char_indices()
        .find(|(_, character)| !matches!(character, 'a'..='z' | '0'..='9' | '-' | '.'))
    {
        return Err(TunnelIdError::InvalidCharacter { character, index });
    }

    for (label_index, label) in value.split('.').enumerate() {
        if label.is_empty() {
            return Err(TunnelIdError::EmptyLabel { label: label_index });
        }
        if label.len() > 63 {
            return Err(TunnelIdError::LabelTooLong {
                label: label_index,
                length: label.len(),
            });
        }
        if !label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(TunnelIdError::InvalidLabelStart { label: label_index });
        }
        if !label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(TunnelIdError::InvalidLabelEnd { label: label_index });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_id_accepts_single_normal_path_components() {
        for value in ["project", "project-123", "Project ID", "project%2Fname"] {
            let id = ProjectId::try_from(value).expect("valid project ID");
            assert_eq!(id.as_str(), value);
        }
    }

    #[test]
    fn project_id_rejects_unsafe_path_components() {
        let cases = [
            ("", ProjectIdError::Empty),
            (".", ProjectIdError::CurrentDirectory),
            ("..", ProjectIdError::ParentDirectory),
            ("/project", ProjectIdError::Absolute),
            ("parent/project", ProjectIdError::PathSeparator),
            ("parent\\project", ProjectIdError::PathSeparator),
            ("C:", ProjectIdError::WindowsPathPrefix),
            ("C:project", ProjectIdError::WindowsPathPrefix),
            ("project:stream", ProjectIdError::WindowsPathPrefix),
            ("project.", ProjectIdError::WindowsTrailingDotOrSpace),
            ("project ", ProjectIdError::WindowsTrailingDotOrSpace),
            (
                "CON",
                ProjectIdError::WindowsReservedName {
                    name: "CON".to_string(),
                },
            ),
            (
                "nul.txt",
                ProjectIdError::WindowsReservedName {
                    name: "nul".to_string(),
                },
            ),
            ("project\0name", ProjectIdError::Nul { index: 7 }),
            (
                "project\nname",
                ProjectIdError::ControlCharacter { index: 7 },
            ),
        ];

        for (value, expected) in cases {
            assert_eq!(
                ProjectId::try_from(value),
                Err(expected),
                "value: {value:?}"
            );
        }
    }

    #[test]
    fn project_id_serde_shape_is_a_validated_string() {
        let id = ProjectId::try_from("project-alpha").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), r#""project-alpha""#);
        assert_eq!(
            serde_json::from_str::<ProjectId>(r#""project-alpha""#).unwrap(),
            id
        );
        assert!(serde_json::from_str::<ProjectId>(r#""../project""#).is_err());
    }

    #[test]
    fn tunnel_id_accepts_dns_subdomains() {
        for value in ["tunnel", "tunnel-123", "one.two-three.4"] {
            let id = TunnelId::try_from(value).expect("valid tunnel ID");
            assert_eq!(id.as_str(), value);
        }

        let label = "a".repeat(63);
        let max_length = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(max_length.len(), 253);
        assert!(TunnelId::try_from(max_length).is_ok());
    }

    #[test]
    fn tunnel_id_rejects_invalid_dns_subdomains() {
        assert_eq!(TunnelId::try_from(""), Err(TunnelIdError::Empty));
        assert!(matches!(
            TunnelId::try_from("a".repeat(254)),
            Err(TunnelIdError::TooLong { length: 254 })
        ));
        assert!(matches!(
            TunnelId::try_from("a".repeat(64)),
            Err(TunnelIdError::LabelTooLong {
                label: 0,
                length: 64
            })
        ));
        assert_eq!(
            TunnelId::try_from("one..two"),
            Err(TunnelIdError::EmptyLabel { label: 1 })
        );
        assert_eq!(
            TunnelId::try_from("-one"),
            Err(TunnelIdError::InvalidLabelStart { label: 0 })
        );
        assert_eq!(
            TunnelId::try_from("one-"),
            Err(TunnelIdError::InvalidLabelEnd { label: 0 })
        );
        assert_eq!(
            TunnelId::try_from("One"),
            Err(TunnelIdError::InvalidCharacter {
                character: 'O',
                index: 0
            })
        );
        assert_eq!(
            TunnelId::try_from("one_two"),
            Err(TunnelIdError::InvalidCharacter {
                character: '_',
                index: 3
            })
        );
    }

    #[test]
    fn tunnel_id_serde_shape_is_a_validated_string() {
        let id = TunnelId::try_from("tunnel.alpha-1").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), r#""tunnel.alpha-1""#);
        assert_eq!(
            serde_json::from_str::<TunnelId>(r#""tunnel.alpha-1""#).unwrap(),
            id
        );
        assert!(serde_json::from_str::<TunnelId>(r#""Tunnel_1""#).is_err());
    }
}
