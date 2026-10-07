use std::{path::Path, sync::Arc};

use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    error::ApiError,
    model::{AuditEntry, Role, TokenRecord, append_audit},
    store::{Store, atomic_write_private},
};

#[derive(Debug, Clone)]
pub struct Actor {
    pub role: Role,
    pub id: String,
    pub project: Option<String>,
    pub scopes: Vec<String>,
}

impl Actor {
    pub fn label(&self) -> String {
        match self.role {
            Role::Setup => "setup".to_owned(),
            Role::Viewer => format!("viewer:{}", self.id),
            Role::Operate => format!("operate:{}", self.id),
        }
    }

    pub fn require_setup(&self) -> Result<(), ApiError> {
        if self.role == Role::Setup {
            Ok(())
        } else {
            Err(ApiError::new(StatusCode::FORBIDDEN, "setup token required"))
        }
    }

    pub fn require_read(&self, project: &str) -> Result<(), ApiError> {
        self.require_project(project)?;
        Ok(())
    }

    pub fn require_operate(&self, project: &str, scope: &str) -> Result<(), ApiError> {
        self.require_project(project)?;
        match self.role {
            Role::Setup => Ok(()),
            Role::Viewer => Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "viewer tokens are strictly read-only",
            )),
            Role::Operate
                if self
                    .scopes
                    .iter()
                    .any(|candidate| candidate == "project" || candidate == scope) =>
            {
                Ok(())
            }
            Role::Operate => Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "token is not scoped to this resource",
            )),
        }
    }

    fn require_project(&self, project: &str) -> Result<(), ApiError> {
        if self.role == Role::Setup || self.project.as_deref() == Some(project) {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "token is not scoped to this project",
            ))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MintedToken {
    pub token_id: String,
    pub bearer: String,
    pub role: Role,
    pub project: Option<String>,
    pub scopes: Vec<String>,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
}

pub async fn initialize_setup_token(store: &Arc<Store>, repo: &Path) -> Result<(), ApiError> {
    let token_path = repo.join("daemon_auth").join("setup.token");
    if tokio::fs::try_exists(&token_path).await? {
        connect_lib::secure_fs::set_private_file_permissions(&token_path).await?;
    }
    let snapshot = store.snapshot().await;
    if let Ok(raw) = tokio::fs::read_to_string(&token_path).await
        && let Some((id, secret)) = raw.trim().split_once('.')
        && snapshot.tokens.iter().any(|token| {
            token.id == id
                && token.role == Role::Setup
                && token.revoked_at_unix_ms.is_none()
                && constant_time_eq(
                    token.secret_hash.as_bytes(),
                    hash_secret(&token.salt, secret).as_bytes(),
                )
        })
    {
        return Ok(());
    }

    let minted = mint(store, Role::Setup, None, Vec::new(), None, "system").await?;
    atomic_write_private(&token_path, format!("{}\n", minted.bearer).as_bytes()).await?;
    Ok(())
}

pub async fn authenticate(store: &Store, headers: &HeaderMap) -> Result<Actor, ApiError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "bearer token required"))?;
    let (id, secret) = raw
        .split_once('.')
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid bearer token"))?;
    let now = Utc::now().timestamp_millis();
    let state = store.snapshot().await;
    let record = state
        .tokens
        .iter()
        .find(|record| record.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid bearer token"))?;
    let valid = record.revoked_at_unix_ms.is_none()
        && record
            .expires_at_unix_ms
            .is_none_or(|expires| expires > now)
        && constant_time_eq(
            record.secret_hash.as_bytes(),
            hash_secret(&record.salt, secret).as_bytes(),
        );
    if !valid {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid, revoked, or expired bearer token",
        ));
    }
    Ok(Actor {
        role: record.role,
        id: record.id.clone(),
        project: record.project.clone(),
        scopes: record.scopes.clone(),
    })
}

pub async fn mint(
    store: &Store,
    role: Role,
    project: Option<String>,
    scopes: Vec<String>,
    ttl_seconds: Option<u64>,
    actor: &str,
) -> Result<MintedToken, ApiError> {
    if role == Role::Setup && project.is_some() {
        return Err(ApiError::bad_request(
            "setup tokens cannot be project scoped",
        ));
    }
    if role != Role::Setup && project.is_none() {
        return Err(ApiError::bad_request(
            "operate and viewer tokens require a project",
        ));
    }
    let now = Utc::now().timestamp_millis();
    let expires = ttl_seconds
        .map(|seconds| {
            i64::try_from(seconds)
                .unwrap_or(i64::MAX)
                .saturating_mul(1000)
        })
        .map(|duration| now.saturating_add(duration));
    let id = random_string(9);
    let secret = random_string(32);
    let salt = random_string(16);
    let record = TokenRecord {
        id: id.clone(),
        role,
        salt: salt.clone(),
        secret_hash: hash_secret(&salt, &secret),
        project: project.clone(),
        scopes: scopes.clone(),
        created_at_unix_ms: now,
        expires_at_unix_ms: expires,
        revoked_at_unix_ms: None,
    };
    store
        .transact(|state| {
            if role == Role::Setup {
                for token in &mut state.tokens {
                    if token.role == Role::Setup && token.revoked_at_unix_ms.is_none() {
                        token.revoked_at_unix_ms = Some(now);
                    }
                }
            }
            state.tokens.push(record);
            append_audit(
                state,
                AuditEntry {
                    ts_unix_ms: now,
                    event: "token_minted".to_owned(),
                    project: project.clone(),
                    resource: Some(id.clone()),
                    actor: actor.to_owned(),
                },
            );
            Ok(())
        })
        .await?;
    Ok(MintedToken {
        token_id: id.clone(),
        bearer: format!("{id}.{secret}"),
        role,
        project,
        scopes,
        created_at_unix_ms: now,
        expires_at_unix_ms: expires,
    })
}

pub async fn revoke(store: &Store, id: &str, project: &str, actor: &str) -> Result<bool, ApiError> {
    let now = Utc::now().timestamp_millis();
    store
        .transact(|state| {
            let token = state
                .tokens
                .iter_mut()
                .find(|token| token.id == id && token.project.as_deref() == Some(project))
                .ok_or_else(|| ApiError::not_found("token not found"))?;
            if token.role == Role::Setup {
                return Err(ApiError::bad_request(
                    "the setup token cannot be revoked here",
                ));
            }
            let changed = token.revoked_at_unix_ms.is_none();
            token.revoked_at_unix_ms.get_or_insert(now);
            append_audit(
                state,
                AuditEntry {
                    ts_unix_ms: now,
                    event: "token_revoked".to_owned(),
                    project: Some(project.to_owned()),
                    resource: Some(id.to_owned()),
                    actor: actor.to_owned(),
                },
            );
            Ok(changed)
        })
        .await
}

fn hash_secret(salt: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"datum-connect-daemon-token-v1\0");
    hasher.update(salt.as_bytes());
    hasher.update(b"\0");
    hasher.update(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn random_string(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
