//! Connector keys injected from a file, such as a read-only Kubernetes Secret.
//!
//! An injected key gives a container a stable Connector identity while its
//! state directory is ephemeral. The file is only read: Secret mounts are
//! read-only and usually root-owned, so it is never written or chmodded.
//! Errors describe the expected format but never include key material.

use std::path::Path;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use iroh::SecretKey;

use crate::error::ApiError;

/// DER prefix of a PKCS#8 v1 Ed25519 private key, as written by
/// `openssl genpkey -algorithm ed25519`. The 32-byte seed follows it.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";
/// Larger than any supported encoding; refuses to read arbitrary files.
const MAX_KEY_FILE_BYTES: u64 = 4096;

fn invalid_format() -> ApiError {
    ApiError::internal(
        "connector key file must contain a raw 32-byte Ed25519 key or a PEM PRIVATE KEY in PKCS#8 Ed25519 form (openssl genpkey -algorithm ed25519)",
    )
    .with_code("connector_key_invalid")
}

/// Read and parse an injected Connector key without modifying the file.
pub async fn read_connector_key_file(path: &Path) -> Result<SecretKey, ApiError> {
    let unreadable = |error: std::io::Error| {
        ApiError::internal(format!(
            "cannot read connector key file {}: {}",
            path.display(),
            error.kind()
        ))
        .with_code("connector_key_unreadable")
    };
    let metadata = tokio::fs::metadata(path).await.map_err(unreadable)?;
    if !metadata.is_file() || metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(invalid_format());
    }
    let bytes = tokio::fs::read(path).await.map_err(unreadable)?;
    parse_connector_key(&bytes)
}

/// Accept a raw 32-byte seed or a PEM-encoded PKCS#8 Ed25519 private key.
pub fn parse_connector_key(bytes: &[u8]) -> Result<SecretKey, ApiError> {
    if let Ok(seed) = <[u8; 32]>::try_from(bytes) {
        return Ok(SecretKey::from_bytes(&seed));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid_format())?
        .trim();
    let body = text
        .strip_prefix(PEM_BEGIN)
        .and_then(|rest| rest.strip_suffix(PEM_END))
        .ok_or_else(invalid_format)?;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = STANDARD.decode(compact).map_err(|_| invalid_format())?;
    if der.len() != PKCS8_ED25519_PREFIX.len() + 32 || der[..16] != PKCS8_ED25519_PREFIX {
        return Err(invalid_format());
    }
    let seed: [u8; 32] = der[16..].try_into().map_err(|_| invalid_format())?;
    Ok(SecretKey::from_bytes(&seed))
}

/// Refuse an injected key that disagrees with saved project state, instead
/// of silently replacing the identity a project already enrolled with.
pub fn check_injected_key(
    project: &str,
    injected: &SecretKey,
    stored_key: Option<&[u8]>,
    persisted_public_key: Option<&str>,
) -> Result<(), ApiError> {
    let public_key = injected.public().to_string();
    let conflict = |what: &str| {
        ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "The connector key file does not match {what} for project {project}. Nothing was changed. Use the key this state was enrolled with, or start from an empty state directory."
            ),
        )
        .with_code("connector_key_conflict")
    };
    if let Some(stored) = stored_key
        && stored != injected.to_bytes().as_slice()
    {
        return Err(conflict("the saved connector.key"));
    }
    if let Some(persisted) = persisted_public_key
        && persisted != public_key
    {
        return Err(conflict("the saved Connector identity"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only key generated with `openssl genpkey -algorithm ed25519`.
    const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDGCCjjXq5e7uh1oO5HDUvCKwRBUvsUHabWTv29WE1Af\n-----END PRIVATE KEY-----\n";
    // `openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'`
    const PUBLIC_KEY: &str = "03fba577c5a289b42cb771f779faed8273ddc037883fbbb0502584bfc0d504da";

    #[test]
    fn pem_pkcs8_matches_the_documented_public_key_command() {
        let key = parse_connector_key(PEM.as_bytes()).unwrap();
        assert_eq!(key.public().to_string(), PUBLIC_KEY);
        let crlf = PEM.replace('\n', "\r\n");
        assert_eq!(
            parse_connector_key(crlf.as_bytes())
                .unwrap()
                .public()
                .to_string(),
            PUBLIC_KEY
        );
    }

    #[test]
    fn raw_seed_and_pem_produce_the_same_identity() {
        let pem = parse_connector_key(PEM.as_bytes()).unwrap();
        let raw = parse_connector_key(&pem.to_bytes()).unwrap();
        assert_eq!(raw.public(), pem.public());
    }

    #[test]
    fn other_formats_are_rejected_without_echoing_key_material() {
        let seed = parse_connector_key(PEM.as_bytes()).unwrap().to_bytes();
        let mut with_newline = seed.to_vec();
        with_newline.push(b'\n');
        let rsa_like = PEM.replace("MC4CAQAw", "MC4CAQEw");
        let public_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA/uld8WiibQst3H3efrtgnPdwDeIP7uwUCWEv8DVBNo=\n-----END PUBLIC KEY-----\n";
        for input in [
            &with_newline[..],
            &seed[..31],
            b"",
            rsa_like.as_bytes(),
            public_pem.as_bytes(),
            b"-----BEGIN PRIVATE KEY-----\nnot base64!\n-----END PRIVATE KEY-----",
        ] {
            let error = parse_connector_key(input).expect_err("rejected");
            assert_eq!(error.code.as_deref(), Some("connector_key_invalid"));
            assert!(!error.message.contains("MC4CAQ"));
            assert!(!error.message.contains(PUBLIC_KEY));
        }
    }

    #[test]
    fn mismatched_saved_state_is_a_conflict() {
        let injected = parse_connector_key(PEM.as_bytes()).unwrap();
        let other = SecretKey::from_bytes(&[7; 32]);
        assert!(check_injected_key("p", &injected, None, None).is_ok());
        assert!(
            check_injected_key("p", &injected, Some(&injected.to_bytes()), Some(PUBLIC_KEY))
                .is_ok()
        );
        for (stored, persisted) in [
            (Some(other.to_bytes().to_vec()), None),
            (None, Some(other.public().to_string())),
        ] {
            let error = check_injected_key("p", &injected, stored.as_deref(), persisted.as_deref())
                .unwrap_err();
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert_eq!(error.code.as_deref(), Some("connector_key_conflict"));
        }
    }

    #[tokio::test]
    async fn read_only_key_file_is_not_modified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.pem");
        std::fs::write(&path, PEM).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        let before = std::fs::metadata(&path).unwrap();
        let key = read_connector_key_file(&path).await.unwrap();
        assert_eq!(key.public().to_string(), PUBLIC_KEY);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.permissions(), after.permissions());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        let missing = read_connector_key_file(&dir.path().join("missing"))
            .await
            .unwrap_err();
        assert_eq!(missing.code.as_deref(), Some("connector_key_unreadable"));
    }
}
