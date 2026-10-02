use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::Instrument;

use crate::{
    auth::{self, Actor},
    control::Control,
    error::ApiError,
    model::{
        AuditEntry, AuthenticationState, DaemonState, DialState, ProjectState, Protocol, Role,
        ServiceState, TokenRecord, append_audit,
    },
    store::Store,
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub control: Arc<dyn Control>,
    pub default_credentials_file: Option<String>,
    pub mutation_lock: Arc<tokio::sync::Mutex<()>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/status", get(status))
        .route("/v1/up", post(up))
        .route("/v1/down", post(down))
        .route("/v1/services", post(create_service))
        .route("/v1/services/{id}", delete(delete_service))
        .route("/v1/services/{id}/pause", post(pause_service))
        .route("/v1/services/{id}/resume", post(resume_service))
        .route("/v1/dials", post(create_dial))
        .route("/v1/dials/{port}", delete(delete_dial))
        .route("/v1/networks", post(join_network))
        .route("/v1/networks/prepare", post(prepare_network))
        .route("/v1/networks/{network}/setup", get(network_setup))
        .route("/v1/networks/{network}", delete(leave_network))
        .route("/v1/ping", post(ping))
        .route("/v1/tokens", post(mint_token).get(list_tokens))
        .route("/v1/tokens/{id}", delete(revoke_token))
        .route("/v1/audit", get(audit))
        .layer(middleware::from_fn(request_trace))
        .with_state(state)
}

async fn request_trace(request: Request<Body>, next: Next) -> Response {
    let request_id = short_id();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = std::time::Instant::now();
    let span = tracing::info_span!(
        "api_request",
        request_id,
        method = %method,
        path
    );
    let mut response = next.run(request).instrument(span.clone()).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    span.in_scope(|| {
        tracing::info!(
            status = response.status().as_u16(),
            duration_ms = started.elapsed().as_millis() as u64,
            "api_request_complete"
        )
    });
    response
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Debug, Deserialize)]
struct ProjectQuery {
    project: String,
}

fn validate_project(project: &str) -> Result<(), ApiError> {
    connect_lib::ProjectId::try_from(project)
        .map(|_| ())
        .map_err(|error| ApiError::bad_request(format!("invalid project: {error}")))
}

async fn authorized(
    state: &AppState,
    headers: &HeaderMap,
    project: &str,
) -> Result<Actor, ApiError> {
    validate_project(project)?;
    let actor = auth::authenticate(&state.store, headers).await?;
    actor.require_read(project)?;
    Ok(actor)
}

async fn status(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
) -> Result<Json<ProjectStatus>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    let snapshot = state.store.snapshot().await;
    let mut project = snapshot
        .projects
        .get(&query.project)
        .cloned()
        .unwrap_or_default();
    if actor.role == Role::Operate && !actor.scopes.iter().any(|scope| scope == "project") {
        project.services.retain(|id, _| {
            actor
                .scopes
                .iter()
                .any(|scope| scope == &format!("service:{id}"))
        });
        project.dials.retain(|port, _| {
            actor
                .scopes
                .iter()
                .any(|scope| scope == &format!("dial:{port}"))
        });
        project.connector = None;
        project.authentication = None;
    }
    let diagnostics =
        if actor.role != Role::Operate || actor.scopes.iter().any(|scope| scope == "project") {
            state.control.diagnostics(&query.project).await
        } else {
            Value::Null
        };
    let networks =
        if actor.role != Role::Operate || actor.scopes.iter().any(|scope| scope == "project") {
            state.control.networks(&query.project).await
        } else {
            json!([])
        };
    let mut result = ProjectStatus::from_state(query.project, project);
    result.transport = diagnostics;
    result.networks = networks;
    if actor.role != Role::Operate || actor.scopes.iter().any(|scope| scope == "project") {
        result.networking = networking_status(&snapshot, &result.project).await;
    }
    Ok(Json(result))
}

#[derive(Debug, Serialize)]
struct ProjectStatus {
    networking: Value,
    transport: Value,
    project: String,
    desired_up: bool,
    running: bool,
    enrolled: bool,
    credential_configured: bool,
    authentication: Option<AuthenticationState>,
    connector: Option<crate::model::ConnectorState>,
    services: Vec<ServiceState>,
    dials: Vec<DialState>,
    networks: Value,
    last_error: Option<String>,
    last_error_stage: Option<String>,
}

impl ProjectStatus {
    fn from_state(project: String, state: ProjectState) -> Self {
        Self {
            networking: Value::Null,
            transport: Value::Null,
            project,
            desired_up: state.desired_up,
            running: state.running,
            enrolled: state.enrolled,
            credential_configured: state.credentials_file.is_some(),
            authentication: state.authentication,
            connector: state.connector,
            services: state.services.into_values().collect(),
            dials: state.dials.into_values().collect(),
            networks: json!([]),
            last_error: state.last_error,
            last_error_stage: state.last_error_stage,
        }
    }
}

#[derive(Debug, Deserialize)]
struct UpRequest {
    project: String,
    name: Option<String>,
    name_hint: Option<String>,
    credentials_file: Option<String>,
    #[serde(default)]
    auth: AuthMode,
    datumctl_session: Option<DatumctlSession>,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AuthMode {
    #[default]
    Auto,
    Oidc,
    Stored,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatumctlSession {
    helper_path: String,
    session: String,
    api_endpoint: String,
}

async fn up(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpRequest>,
) -> Result<Json<ProjectStatus>, ApiError> {
    validate_project(&request.project)?;
    let actor = auth::authenticate(&state.store, &headers).await?;
    actor.require_operate(&request.project, "project")?;
    let _mutation_guard = state.mutation_lock.lock().await;
    if let Some(name) = request.name.as_ref().or(request.name_hint.as_ref())
        && (name.is_empty()
            || name.len() > 63
            || name.starts_with('-')
            || name.ends_with('-')
            || !name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
    {
        return Err(ApiError::bad_request(
            "Device name must contain 1–63 lowercase letters, digits, or hyphens and start and end with a letter or digit",
        ));
    }
    if request.name.is_some() {
        actor.require_setup()?;
    }
    let previous = state.store.snapshot().await;
    if let Some(connector) = previous
        .projects
        .get(&request.project)
        .and_then(|p| p.connector.as_ref())
        && request
            .name
            .as_ref()
            .is_some_and(|name| *name != connector.name)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "This device is already enrolled as {}. Renaming an enrolled Connector is not supported; omit --name to reconnect.",
                connector.name
            ),
        ));
    }
    if request.credentials_file.is_some() && request.auth != AuthMode::Auto {
        return Err(ApiError::bad_request(
            "--credentials-file cannot be combined with --auth oidc or stored",
        ));
    }
    if (request.credentials_file.is_some() || request.auth == AuthMode::Oidc)
        && actor.role != Role::Setup
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only setup may change the credentials file",
        ));
    }
    let project_name = request.project.clone();
    let actor_label = actor.label();
    let existing_credentials = state
        .store
        .snapshot()
        .await
        .projects
        .get(&project_name)
        .and_then(|project| project.credentials_file.clone());
    let source_credentials = request.credentials_file.clone().or_else(|| {
        if existing_credentials.is_none() && request.auth == AuthMode::Auto {
            state.default_credentials_file.clone()
        } else {
            None
        }
    });
    if source_credentials.is_some() && actor.role != Role::Setup {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only setup may import credentials",
        ));
    }
    let use_session = request.auth == AuthMode::Oidc
        || (request.auth == AuthMode::Auto
            && source_credentials.is_none()
            && existing_credentials.is_none()
            && request.datumctl_session.is_some());
    let authentication = if use_session {
        Some(AuthenticationState {
            kind: "oidc".into(),
            session: request
                .datumctl_session
                .as_ref()
                .map(|value| value.session.clone()),
        })
    } else if source_credentials.is_some() {
        Some(AuthenticationState {
            kind: "credential_file".into(),
            session: None,
        })
    } else {
        None
    };
    let imported_credentials = if use_session {
        if actor.role != Role::Setup {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "only setup may bind a datumctl session",
            ));
        }
        let session = request.datumctl_session.as_ref().ok_or_else(|| {
            ApiError::bad_request("Run `datumctl login`, then `datumctl connect up` through datumctl to select a login session.").with_code("credentials_required")
        })?;
        let credentials = connect_lib::successor::Credentials::datumctl_session(
            &project_name,
            &session.api_endpoint,
            &session.helper_path,
            &session.session,
        )
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
        let bytes = serde_json::to_vec(&credentials)
            .map_err(|_| ApiError::internal("cannot serialize host session configuration"))?;
        Some(state.store.save_credentials(&project_name, &bytes).await?)
    } else {
        match source_credentials {
            Some(path) => {
                state.control.validate_credentials(&path).await?;
                Some(
                    state
                        .store
                        .import_credentials(&project_name, std::path::Path::new(&path))
                        .await?,
                )
            }
            None => existing_credentials,
        }
    };
    let credentials = state
        .store
        .transact(|root| {
            let project = root.projects.entry(project_name.clone()).or_default();
            if project.connector.is_none() && actor.role == Role::Setup {
                if let Some(name) = request.name.clone() { project.device_name = Some(name); }
                else if project.device_name.is_none() { project.device_name = request.name_hint.clone(); }
            }
            project.credentials_file = imported_credentials.clone();
            if let Some(authentication) = authentication.clone() {
                project.authentication = Some(authentication);
            }
            project.desired_up = true;
            project.last_error = None;
            project.last_error_stage = None;
            let credentials = project.credentials_file.clone().ok_or_else(|| {
                ApiError::bad_request(
                    "No authentication is configured. Run `datumctl login`, then `datumctl connect up`. For unattended use, pass --credentials-file PATH.",
                )
                .with_code("credentials_required")
            })?;
            project.credentials_file = Some(credentials.clone());
            append_audit(
                root,
                audit_entry("up_requested", &project_name, None, &actor_label),
            );
            Ok(credentials)
        })
        .await?;

    let expected = state
        .store
        .snapshot()
        .await
        .projects
        .get(&request.project)
        .and_then(|project| project.connector.clone());
    let result = match expected {
        Some(expected) => {
            state
                .control
                .resume(&request.project, &credentials, &expected)
                .await
        }
        None => state.control.up(&request.project, &credentials).await,
    };
    match result {
        Ok(connector) => {
            state
                .store
                .transact(|root| {
                    let project = require_project_mut(root, &request.project)?;
                    project.connector = Some(connector);
                    project.running = true;
                    project.enrolled = true;
                    project.last_error = None;
                    project.last_error_stage = None;
                    Ok(())
                })
                .await?;
            reconcile_project(&state, &request.project).await;
        }
        Err(error) => {
            record_project_error(&state, &request.project, "enrollment", &error.message).await?;
            return Err(error);
        }
    }
    drop(_mutation_guard);
    status(
        State(state),
        Query(ProjectQuery {
            project: request.project,
        }),
        headers,
    )
    .await
}

async fn down(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
) -> Result<Json<ProjectStatus>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, "project")?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let actor_label = actor.label();
    state
        .store
        .transact(|root| {
            let project = root.projects.entry(query.project.clone()).or_default();
            project.desired_up = false;
            project.running = false;
            for service in project.services.values_mut() {
                service.running = false;
                service.ready = false;
            }
            for dial in project.dials.values_mut() {
                dial.running = false;
                dial.local_port = None;
            }
            append_audit(
                root,
                audit_entry("down_requested", &query.project, None, &actor_label),
            );
            Ok(())
        })
        .await?;
    if let Err(error) = state.control.down(&query.project).await {
        state
            .store
            .transact(|root| {
                let project = require_project_mut(root, &query.project)?;
                project.last_error = Some(error.message.clone());
                project.last_error_stage = Some("down".into());
                Ok(())
            })
            .await?;
        return Err(error);
    }
    drop(_mutation_guard);
    status(State(state), Query(query), headers).await
}

#[derive(Debug, Deserialize)]
struct ServiceRequest {
    endpoint: String,
    #[serde(default)]
    protocol: Protocol,
    #[serde(default)]
    public: bool,
    hostname: Option<String>,
    #[serde(default)]
    allow: Vec<String>,
}

async fn create_service(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
    Json(request): Json<ServiceRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, "project")?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let advertised_port = validate_endpoint(&request.endpoint)?;
    if request.public && request.protocol == Protocol::Udp {
        return Err(ApiError::bad_request(
            "Public services require TCP; remove --public to serve UDP privately.",
        ));
    }
    if request.public && !request.allow.is_empty() {
        return Err(ApiError::bad_request(
            "--public cannot be combined with --allow; public services do not restrict access to Connectors.",
        ));
    }
    if request.hostname.is_some() && !request.public {
        return Err(ApiError::bad_request("--hostname requires --public."));
    }
    let id = format!("service-{}", short_id());
    let mut allow = Vec::new();
    for peer in &request.allow {
        allow.push(state.control.resolve_peer_key(&query.project, peer).await?);
    }
    allow.sort();
    allow.dedup();
    let service = ServiceState {
        id: id.clone(),
        endpoint: request.endpoint,
        protocol: request.protocol,
        public: request.public,
        hostname: request.hostname,
        allow,
        desired_active: true,
        running: false,
        ready: false,
        hostnames: Vec::new(),
        last_error: None,
        last_error_stage: None,
        last_actor: actor.label(),
    };
    let service_for_state = service.clone();
    let (service, created) = state
        .store
        .transact(|root| {
            let project = require_project_mut(root, &query.project)?;
            if !project.desired_up {
                return Err(ApiError::new(StatusCode::CONFLICT, "project is down")
                    .with_code("project_down"));
            }
            if let Some(existing) = project.services.values().find(|existing| {
                existing.protocol == service_for_state.protocol
                    && validate_endpoint(&existing.endpoint).ok() == Some(advertised_port)
            }) {
                if existing.desired_active && same_service_intent(existing, &service_for_state) {
                    let existing_id = existing.id.clone();
                    let existing = project.services.get_mut(&existing_id).unwrap();
                    existing.last_actor = actor.label();
                    return Ok((existing.clone(), false));
                }
                // Endpoint selectors are friendlier, but are ambiguous when TCP
                // and UDP both use the same destination. Keep the ID in that case.
                let selector = if project
                    .services
                    .values()
                    .filter(|s| s.endpoint == existing.endpoint)
                    .count()
                    == 1
                {
                    &existing.endpoint
                } else {
                    &existing.id
                };
                return Err(service_conflict(
                    existing,
                    &service_for_state,
                    advertised_port,
                    selector,
                    &query.project,
                ));
            }
            project
                .services
                .insert(id.clone(), service_for_state.clone());
            append_audit(
                root,
                audit_entry(
                    "service_created",
                    &query.project,
                    Some(id.clone()),
                    &actor.label(),
                ),
            );
            Ok((service_for_state, true))
        })
        .await?;
    let id = service.id.clone();
    let outcome = match state
        .control
        .reconcile_service(&query.project, &service)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            record_service_error(
                &state,
                &query.project,
                &id,
                "service_reconcile",
                &error.message,
            )
            .await?;
            return Err(saved_service_error(error, &query.project, &id));
        }
    };
    let updated = state
        .store
        .transact(|root| {
            let service = require_service_mut(root, &query.project, &id)?;
            service.hostnames = outcome.hostnames;
            service.ready = outcome.ready;
            service.running = true;
            service.last_error = None;
            service.last_error_stage = None;
            Ok(service.clone())
        })
        .await?;
    let snapshot = state.store.snapshot().await;
    let mut response = serde_json::to_value(updated)
        .map_err(|_| ApiError::internal("cannot serialize service"))?;
    response["connector"] = snapshot
        .projects
        .get(&query.project)
        .and_then(|p| p.connector.as_ref())
        .map(|c| json!(c.name))
        .unwrap_or(Value::Null);
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(response),
    ))
}

async fn delete_service(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(id_or_endpoint): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let snapshot = state.store.snapshot().await;
    let service = find_service(&snapshot, &query.project, &id_or_endpoint)?;
    actor.require_operate(&query.project, &format!("service:{}", service.id))?;
    state
        .store
        .transact(|root| {
            let service = require_service_mut(root, &query.project, &service.id)?;
            service.desired_active = false;
            Ok(())
        })
        .await?;
    if let Err(error) = state.control.delete_service(&query.project, &service).await {
        record_service_error(
            &state,
            &query.project,
            &service.id,
            "service_delete",
            &error.message,
        )
        .await?;
        return Err(error);
    }
    state
        .store
        .transact(|root| {
            require_project_mut(root, &query.project)?
                .services
                .remove(&service.id);
            append_audit(
                root,
                audit_entry(
                    "service_deleted",
                    &query.project,
                    Some(service.id.clone()),
                    &actor.label(),
                ),
            );
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "deleted": true, "id": service.id })))
}

async fn pause_service(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ServiceState>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, &format!("service:{id}"))?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let service = state
        .store
        .transact(|root| {
            let service = require_service_mut(root, &query.project, &id)?;
            service.desired_active = false;
            service.ready = false;
            service.last_actor = actor.label();
            Ok(service.clone())
        })
        .await?;
    if let Err(error) = state.control.pause_service(&query.project, &service).await {
        record_service_error(&state, &query.project, &id, "service_pause", &error.message).await?;
        return Err(error);
    }
    let updated = state
        .store
        .transact(|root| {
            let updated = {
                let service = require_service_mut(root, &query.project, &id)?;
                service.running = false;
                service.last_error = None;
                service.last_error_stage = None;
                service.clone()
            };
            append_audit(
                root,
                audit_entry(
                    "service_paused",
                    &query.project,
                    Some(id.clone()),
                    &actor.label(),
                ),
            );
            Ok(updated)
        })
        .await?;
    Ok(Json(updated))
}

async fn resume_service(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ServiceState>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, &format!("service:{id}"))?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let service = state
        .store
        .transact(|root| {
            let project = require_project_mut(root, &query.project)?;
            if !project.desired_up {
                return Err(ApiError::new(StatusCode::CONFLICT, "project is down")
                    .with_code("project_down"));
            }
            let service = project
                .services
                .get_mut(&id)
                .ok_or_else(|| ApiError::not_found("service not found"))?;
            service.desired_active = true;
            service.last_actor = actor.label();
            Ok(service.clone())
        })
        .await?;
    let outcome = match state
        .control
        .reconcile_service(&query.project, &service)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            record_service_error(
                &state,
                &query.project,
                &id,
                "service_resume",
                &error.message,
            )
            .await?;
            return Err(saved_service_error(error, &query.project, &id));
        }
    };
    let updated = state
        .store
        .transact(|root| {
            let updated = {
                let service = require_service_mut(root, &query.project, &id)?;
                service.hostnames = outcome.hostnames;
                service.ready = outcome.ready;
                service.running = true;
                service.last_error = None;
                service.last_error_stage = None;
                service.clone()
            };
            append_audit(
                root,
                audit_entry(
                    "service_resumed",
                    &query.project,
                    Some(id.clone()),
                    &actor.label(),
                ),
            );
            Ok(updated)
        })
        .await?;
    Ok(Json(updated))
}

#[derive(Debug, Deserialize)]
struct DialRequest {
    connector: String,
    port: u16,
    bind: u16,
    #[serde(default)]
    protocol: Protocol,
}

async fn create_dial(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
    Json(request): Json<DialRequest>,
) -> Result<(StatusCode, Json<DialState>), ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, "project")?;
    let _mutation_guard = state.mutation_lock.lock().await;
    if request.port == 0 || request.connector.trim().is_empty() {
        return Err(ApiError::bad_request(
            "A Connector and remote port from 1 to 65535 are required.",
        ));
    }
    let connector = state
        .control
        .resolve_peer_key(&query.project, &request.connector)
        .await?;
    let dial = DialState {
        connector,
        connector_name: Some(request.connector),
        port: request.port,
        bind: request.bind,
        local_port: None,
        protocol: request.protocol,
        desired_active: true,
        running: false,
        last_error: None,
        last_error_stage: None,
        last_actor: actor.label(),
    };
    let desired = dial.clone();
    let (dial, created) = state
        .store
        .transact(|root| {
            let project = require_project_mut(root, &query.project)?;
            if !project.desired_up {
                return Err(ApiError::new(StatusCode::CONFLICT, "project is down").with_code("project_down"));
            }
            if let Some(existing) = project.dials.get_mut(&request.bind) {
                if existing.desired_active && existing.connector == desired.connector
                    && existing.port == desired.port && existing.protocol == desired.protocol {
                    existing.last_actor = actor.label();
                    return Ok((existing.clone(), false));
                }
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    format!("Local port {} already has a saved dial with different settings or is stopping. Run `datumctl connect status --project {}` to inspect it, or `datumctl connect hangup {} --project {}` before replacing it.", request.bind, query.project, request.bind, query.project),
                ));
            }
            project.dials.insert(request.bind, desired.clone());
            append_audit(
                root,
                audit_entry(
                    "dial_created",
                    &query.project,
                    Some(request.bind.to_string()),
                    &actor.label(),
                ),
            );
            Ok((desired, true))
        })
        .await?;
    if !created && dial.running {
        return Ok((StatusCode::OK, Json(dial)));
    }
    let bound = match state.control.reconcile_dial(&query.project, &dial).await {
        Ok(value) => value,
        Err(mut error) => {
            record_dial_error(
                &state,
                &query.project,
                request.bind,
                "dial_reconcile",
                &error.message,
            )
            .await?;
            error.message = format!(
                "{}. Dial intent for local port {} is saved. Retry the same command to reconcile it now, or remove it with `datumctl connect hangup {} --project {}`. Restarting Connect also retries saved intent.",
                error.message, request.bind, request.bind, query.project
            );
            return Err(error);
        }
    };
    let updated = state
        .store
        .transact(|root| {
            let project = require_project_mut(root, &query.project)?;
            let mut dial = project
                .dials
                .remove(&request.bind)
                .ok_or_else(|| ApiError::not_found("dial not found"))?;
            if bound != request.bind && project.dials.contains_key(&bound) {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "allocated local port already exists",
                ));
            }
            dial.local_port = Some(bound);
            dial.bind = bound;
            dial.running = true;
            dial.last_error = None;
            dial.last_error_stage = None;
            project.dials.insert(bound, dial.clone());
            Ok(dial)
        })
        .await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(updated),
    ))
}

async fn delete_dial(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(port): Path<u16>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let snapshot = state.store.snapshot().await;
    snapshot
        .projects
        .get(&query.project)
        .and_then(|project| project.dials.get(&port))
        .ok_or_else(|| ApiError::not_found("dial not found"))?;
    actor.require_operate(&query.project, &format!("dial:{port}"))?;
    state
        .store
        .transact(|root| {
            require_project_mut(root, &query.project)?
                .dials
                .get_mut(&port)
                .expect("loaded above")
                .desired_active = false;
            Ok(())
        })
        .await?;
    if let Err(error) = state.control.delete_dial(&query.project, port).await {
        record_dial_error(&state, &query.project, port, "dial_delete", &error.message).await?;
        return Err(error);
    }
    state
        .store
        .transact(|root| {
            let removed = require_project_mut(root, &query.project)?
                .dials
                .remove(&port)
                .is_some();
            if !removed {
                return Err(ApiError::not_found("dial not found"));
            }
            append_audit(
                root,
                audit_entry(
                    "dial_deleted",
                    &query.project,
                    Some(port.to_string()),
                    &actor.label(),
                ),
            );
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "deleted": true, "port": port })))
}

async fn prepare_network(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
    Json(request): Json<crate::networking::PrepareRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_setup()?;
    let _guard = state.mutation_lock.lock().await;
    let snapshot = state.store.snapshot().await;
    let project = snapshot.projects.get(&query.project).ok_or_else(|| {
        ApiError::not_found("Connect this device before configuring a peer attachment")
            .with_code("project_not_configured")
    })?;
    if !project.enrolled || !project.running {
        return Err(
            ApiError::bad_request("Run connect up before configuring a peer attachment")
                .with_code("project_down"),
        );
    }
    let binding = state
        .control
        .prepare_network(&query.project, &request)
        .await?;
    if let Some(existing) = project.peer_networks.get(&request.network)
        && existing != &binding
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "This saved attachment has different permissions or a different pinned peer; existing access was not changed. Choose a new attachment name.",
        ));
    }
    let mut proposed = snapshot.clone();
    proposed
        .projects
        .get_mut(&query.project)
        .expect("project exists")
        .peer_networks
        .insert(request.network.clone(), binding.clone());
    let plan = setup_plan(&proposed, &query.project, &request.network)?;
    state
        .store
        .transact(|root| {
            root.projects
                .get_mut(&query.project)
                .expect("locked project")
                .peer_networks
                .insert(request.network.clone(), binding);
            append_audit(
                root,
                audit_entry(
                    "peer_network_prepared",
                    &query.project,
                    Some(request.network.clone()),
                    &actor.label(),
                ),
            );
            Ok(())
        })
        .await?;
    Ok(Json(plan))
}

async fn network_setup(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(network): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorized(&state, &headers, &query.project)
        .await?
        .require_setup()?;
    setup_plan(&state.store.snapshot().await, &query.project, &network).map(Json)
}

fn setup_plan(state: &DaemonState, project: &str, network: &str) -> Result<Value, ApiError> {
    let binding = state
        .projects
        .get(project)
        .and_then(|p| p.peer_networks.get(network))
        .ok_or_else(|| {
            ApiError::not_found(
                "No saved peer attachment; supply --peer CONNECTOR on the first join",
            )
            .with_code("network_not_configured")
        })?;
    #[cfg(unix)]
    {
        let mut approvals = crate::networking::approvals(state)?;
        // Consent applies to this attachment only, never other pending projects.
        approvals
            .approvals
            .retain(|approval| approval.interface_name == binding.interface_name);
        Ok(
            json!({"network":network, "binding":binding, "helper_socket":crate::networking::helper_socket()?, "helper_config":approvals}),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = binding;
        Err(ApiError::bad_request(
            "Guided networking requires macOS or Linux",
        ))
    }
}

async fn networking_status(state: &DaemonState, project: &str) -> Value {
    let Some(project) = state
        .projects
        .get(project)
        .filter(|p| !p.peer_networks.is_empty())
    else {
        return json!({"state":"not_required"});
    };
    let saved: Vec<_> = project.peer_networks.values().collect();
    #[cfg(unix)]
    {
        let result = match crate::networking::helper_socket() {
            Ok(socket) => connect_ip_adapter::helper::inspect(&socket)
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.message),
        };
        match result {
            Ok(helper) => {
                let approved = saved.iter().all(|binding| {
                    helper.approvals.iter().any(|a| {
                        a.interface_name == binding.interface_name
                            && a.assigned_address.to_string() == binding.assigned_address
                            && a.peer_address.to_string() == binding.peer_address
                            && a.mtu == binding.mtu
                    })
                });
                json!({"state":if approved {"ready"} else {"approval_required"}, "helper_protocol":helper.version, "saved_attachments":saved})
            }
            Err(error) => {
                json!({"state":"setup_required", "last_error":error, "saved_attachments":saved})
            }
        }
    }
    #[cfg(not(unix))]
    {
        json!({"state":"unsupported", "saved_attachments":saved})
    }
}

#[derive(Deserialize)]
struct NetworkRequest {
    network: String,
}

async fn join_network(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
    Json(request): Json<NetworkRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, "project")?;
    connect_lib::TunnelId::try_from(request.network.as_str())
        .map_err(|_| ApiError::bad_request("Invalid network name"))?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let snapshot = state.store.snapshot().await;
    let project = snapshot.projects.get(&query.project).ok_or_else(|| {
        ApiError::not_found("Connect is not set up for this project")
            .with_code("project_not_configured")
    })?;
    if !project.running || !project.enrolled {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Project must be connected before joining a network",
        )
        .with_code("project_down"));
    }
    #[cfg(unix)]
    if let Some(binding) = project.peer_networks.get(&request.network) {
        let helper =
            connect_ip_adapter::helper::inspect(&crate::networking::helper_socket()?).await;
        let approval = connect_ip_adapter::helper::Approval {
            interface_name: binding.interface_name.clone(),
            assigned_address: binding.local_address()?,
            peer_address: binding.remote_address()?,
            mtu: binding.mtu,
            routes: binding
                .routes
                .iter()
                .map(|r| {
                    r.parse()
                        .map_err(|_| ApiError::bad_request("Invalid route"))
                })
                .collect::<Result<_, _>>()?,
            advertise_routes: binding
                .advertise_routes
                .iter()
                .map(|r| {
                    r.parse()
                        .map_err(|_| ApiError::bad_request("Invalid route"))
                })
                .collect::<Result<_, _>>()?,
        };
        if !helper.is_ok_and(|helper| helper.approvals.contains(&approval)) {
            return Err(ApiError::new(StatusCode::CONFLICT, "Administrator approval is required for this IP attachment. Run connect join interactively on this device to set up networking.").with_code("network_setup_required"));
        }
    }
    let result = state
        .control
        .join_network(&query.project, &request.network)
        .await?;
    if let Err(error) = state
        .store
        .transact(|root| {
            append_audit(
                root,
                audit_entry(
                    "local_network_joined",
                    &query.project,
                    Some(request.network.clone()),
                    &actor.label(),
                ),
            );
            Ok(())
        })
        .await
    {
        let _ = state
            .control
            .leave_network(&query.project, &request.network)
            .await;
        return Err(error);
    }
    Ok(Json(result))
}

async fn leave_network(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(network): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, "project")?;
    connect_lib::TunnelId::try_from(network.as_str())
        .map_err(|_| ApiError::bad_request("Invalid network name"))?;
    let _mutation_guard = state.mutation_lock.lock().await;
    let result = state
        .control
        .leave_network(&query.project, &network)
        .await?;
    state
        .store
        .transact(|root| {
            append_audit(
                root,
                audit_entry(
                    "local_network_left",
                    &query.project,
                    Some(network.clone()),
                    &actor.label(),
                ),
            );
            Ok(())
        })
        .await?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PingRequest {
    address: String,
}
async fn ping(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
    Json(request): Json<PingRequest>,
) -> Result<Json<crate::control::PingResult>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_operate(&query.project, "project")?;
    Ok(Json(
        state.control.ping(&query.project, &request.address).await?,
    ))
}

#[derive(Debug, Deserialize)]
struct MintRequest {
    role: Role,
    #[serde(default)]
    scopes: Vec<String>,
    ttl_seconds: Option<u64>,
}

async fn mint_token(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
    Json(request): Json<MintRequest>,
) -> Result<(StatusCode, Json<auth::MintedToken>), ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_setup()?;
    if request.role == Role::Setup {
        return Err(ApiError::bad_request(
            "setup tokens cannot be minted through the API",
        ));
    }
    if request.role == Role::Viewer && !request.scopes.is_empty() {
        return Err(ApiError::bad_request(
            "viewer tokens do not accept mutable resource scopes",
        ));
    }
    let token = auth::mint(
        &state.store,
        request.role,
        Some(query.project),
        request.scopes,
        request.ttl_seconds,
        &actor.label(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(token)))
}

#[derive(Debug, Serialize)]
struct TokenMetadata {
    token_id: String,
    role: Role,
    project: Option<String>,
    scopes: Vec<String>,
    created_at_unix_ms: i64,
    expires_at_unix_ms: Option<i64>,
    revoked: bool,
}
impl From<&TokenRecord> for TokenMetadata {
    fn from(value: &TokenRecord) -> Self {
        Self {
            token_id: value.id.clone(),
            role: value.role,
            project: value.project.clone(),
            scopes: value.scopes.clone(),
            created_at_unix_ms: value.created_at_unix_ms,
            expires_at_unix_ms: value.expires_at_unix_ms,
            revoked: value.revoked_at_unix_ms.is_some(),
        }
    }
}
async fn list_tokens(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<TokenMetadata>>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_setup()?;
    let snapshot = state.store.snapshot().await;
    Ok(Json(
        snapshot
            .tokens
            .iter()
            .filter(|token| token.project.as_deref() == Some(&query.project))
            .map(TokenMetadata::from)
            .collect(),
    ))
}
async fn revoke_token(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_setup()?;
    let revoked = auth::revoke(&state.store, &id, &query.project, &actor.label()).await?;
    Ok(Json(json!({ "revoked": revoked, "token_id": id })))
}
async fn audit(
    State(state): State<AppState>,
    Query(query): Query<ProjectQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let actor = authorized(&state, &headers, &query.project).await?;
    actor.require_setup()?;
    let snapshot = state.store.snapshot().await;
    Ok(Json(
        snapshot
            .audit
            .into_iter()
            .filter(|entry| {
                entry
                    .project
                    .as_deref()
                    .is_none_or(|project| project == query.project)
            })
            .collect(),
    ))
}

pub async fn reconcile_all(state: &AppState) {
    let _ = state
        .store
        .transact(|root| {
            for project in root.projects.values_mut() {
                project.running = false;
                for service in project.services.values_mut() {
                    service.running = false;
                    service.ready = false;
                }
                for dial in project.dials.values_mut() {
                    dial.running = false;
                    dial.local_port = None;
                }
            }
            Ok(())
        })
        .await;
    let snapshot = state.store.snapshot().await;
    for (project, desired) in snapshot.projects {
        if !desired.desired_up {
            continue;
        }
        let Some(credentials) = desired.credentials_file else {
            let _ = record_project_error(
                state,
                &project,
                "credentials",
                "desired up but credentials_file is missing",
            )
            .await;
            continue;
        };
        let Some(expected) = desired.connector.as_ref() else {
            let _ = record_project_error(
                state,
                &project,
                "restart_identity",
                "enrolled project is missing its persisted Connector identity",
            )
            .await;
            continue;
        };
        match state.control.resume(&project, &credentials, expected).await {
            Ok(connector) => {
                let _ = state
                    .store
                    .transact(|root| {
                        let current = root.projects.entry(project.clone()).or_default();
                        current.connector = Some(connector);
                        current.running = true;
                        current.enrolled = true;
                        current.last_error = None;
                        current.last_error_stage = None;
                        Ok(())
                    })
                    .await;
                reconcile_project(state, &project).await;
            }
            Err(error) => {
                let _ = record_project_error(state, &project, "restart_enrollment", &error.message)
                    .await;
            }
        }
    }
}

async fn reconcile_project(state: &AppState, project: &str) {
    let snapshot = state.store.snapshot().await;
    let Some(desired) = snapshot.projects.get(project) else {
        return;
    };
    for service in desired
        .services
        .values()
        .filter(|service| service.desired_active)
    {
        match state.control.reconcile_service(project, service).await {
            Ok(outcome) => {
                let _ = state
                    .store
                    .transact(|root| {
                        let current = require_service_mut(root, project, &service.id)?;
                        current.hostnames = outcome.hostnames;
                        current.ready = outcome.ready;
                        current.running = true;
                        current.last_error = None;
                        current.last_error_stage = None;
                        Ok(())
                    })
                    .await;
            }
            Err(error) => {
                let _ = record_service_error(
                    state,
                    project,
                    &service.id,
                    "restart_service",
                    &error.message,
                )
                .await;
            }
        }
    }
    for dial in desired.dials.values().filter(|dial| dial.desired_active) {
        match state.control.reconcile_dial(project, dial).await {
            Ok(bound) => {
                let key = dial.local_port.unwrap_or(dial.bind);
                let _ = state
                    .store
                    .transact(|root| {
                        if let Some(mut current) =
                            require_project_mut(root, project)?.dials.remove(&key)
                        {
                            current.local_port = Some(bound);
                            current.running = true;
                            current.last_error = None;
                            current.last_error_stage = None;
                            require_project_mut(root, project)?
                                .dials
                                .insert(bound, current);
                        }
                        Ok(())
                    })
                    .await;
            }
            Err(error) => {
                let key = dial.local_port.unwrap_or(dial.bind);
                let message = error.message;
                let _ = record_dial_error(state, project, key, "restart_dial", &message).await;
            }
        }
    }
}

fn require_project_mut<'a>(
    state: &'a mut DaemonState,
    project: &str,
) -> Result<&'a mut ProjectState, ApiError> {
    state.projects.get_mut(project).ok_or_else(|| {
        ApiError::not_found("Connect is not set up for this project.")
            .with_code("project_not_configured")
    })
}
fn require_service_mut<'a>(
    state: &'a mut DaemonState,
    project: &str,
    id: &str,
) -> Result<&'a mut ServiceState, ApiError> {
    require_project_mut(state, project)?
        .services
        .get_mut(id)
        .ok_or_else(|| ApiError::not_found("service not found"))
}
fn find_service(
    state: &DaemonState,
    project: &str,
    id_or_endpoint: &str,
) -> Result<ServiceState, ApiError> {
    let services = &state
        .projects
        .get(project)
        .ok_or_else(|| {
            ApiError::not_found("Connect is not set up for this project.")
                .with_code("project_not_configured")
        })?
        .services;
    if let Some(service) = services.get(id_or_endpoint) {
        return Ok(service.clone());
    }
    let mut matches = services
        .values()
        .filter(|service| service.endpoint == id_or_endpoint);
    let service = matches
        .next()
        .ok_or_else(|| ApiError::not_found("service not found"))?;
    if matches.next().is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "More than one service uses {id_or_endpoint}. Run `datumctl connect status --project {project}`, then `datumctl connect unserve NAME --project {project}` with the service name to remove."
            ),
        ));
    }
    Ok(service.clone())
}

fn service_conflict(
    existing: &ServiceState,
    desired: &ServiceState,
    port: u16,
    selector: &str,
    project: &str,
) -> ApiError {
    let protocol = match existing.protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    };
    let explanation = if !existing.desired_active {
        format!(
            "{} ({protocol}) is stopping or paused and still reserves port {port}.",
            existing.endpoint
        )
    } else if existing.endpoint != desired.endpoint {
        format!(
            "Cannot share {}: {protocol} port {port} is already shared as {}.\nThis device can share only one destination per {protocol} port in project {project}.",
            desired.endpoint, existing.endpoint
        )
    } else {
        let mut changes = Vec::new();
        if existing.public != desired.public {
            changes.push("public/private access");
        }
        if existing.allow != desired.allow {
            changes.push("allowed Connectors");
        }
        if existing.hostname != desired.hostname {
            changes.push("public hostname");
        }
        format!(
            "{} ({protocol}) is already shared with different {}.",
            existing.endpoint,
            changes.join(" and ")
        )
    };
    ApiError::new(StatusCode::CONFLICT, format!(
        "{explanation}\nNothing changed.\n\nTo replace the existing share, stop it first:\n  datumctl connect unserve {} --project {}\nThen run your serve command again.",
        command_arg(selector), command_arg(project),
    )).with_code("service_conflict")
}

// Quote unusual user input before including it in a copyable shell command.
fn command_arg(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn same_service_intent(existing: &ServiceState, desired: &ServiceState) -> bool {
    let mut existing_allow = existing.allow.clone();
    let mut desired_allow = desired.allow.clone();
    existing_allow.sort();
    existing_allow.dedup();
    desired_allow.sort();
    desired_allow.dedup();
    existing.endpoint == desired.endpoint
        && existing.protocol == desired.protocol
        && existing.public == desired.public
        && existing.hostname == desired.hostname
        && existing_allow == desired_allow
}

fn saved_service_error(mut error: ApiError, project: &str, id: &str) -> ApiError {
    error.message = format!(
        "{}. Service intent {id} is saved. Retry the same serve command to reconcile it now, or remove it with `datumctl connect unserve {id} --project {project}`. Restarting Connect also retries saved intent.",
        error.message
    );
    error
}
fn audit_entry(event: &str, project: &str, resource: Option<String>, actor: &str) -> AuditEntry {
    AuditEntry {
        ts_unix_ms: Utc::now().timestamp_millis(),
        event: event.to_owned(),
        project: Some(project.to_owned()),
        resource,
        actor: actor.to_owned(),
    }
}
fn short_id() -> String {
    format!("{:012x}", rand::random::<u64>() & 0x0000_ffff_ffff_ffff)
}
async fn record_project_error(
    state: &AppState,
    project: &str,
    stage: &str,
    message: &str,
) -> Result<(), ApiError> {
    state
        .store
        .transact(|root| {
            let project = root.projects.entry(project.to_owned()).or_default();
            project.running = false;
            project.last_error = Some(message.to_owned());
            project.last_error_stage = Some(stage.to_owned());
            Ok(())
        })
        .await
}
async fn record_service_error(
    state: &AppState,
    project: &str,
    id: &str,
    stage: &str,
    message: &str,
) -> Result<(), ApiError> {
    state
        .store
        .transact(|root| {
            let service = require_service_mut(root, project, id)?;
            service.ready = false;
            service.running = false;
            service.last_error = Some(message.to_owned());
            service.last_error_stage = Some(stage.to_owned());
            Ok(())
        })
        .await
}
async fn record_dial_error(
    state: &AppState,
    project: &str,
    local_port: u16,
    stage: &str,
    message: &str,
) -> Result<(), ApiError> {
    state
        .store
        .transact(|root| {
            let dial = require_project_mut(root, project)?
                .dials
                .get_mut(&local_port)
                .ok_or_else(|| ApiError::not_found("dial not found"))?;
            dial.running = false;
            dial.last_error = Some(message.to_owned());
            dial.last_error_stage = Some(stage.to_owned());
            Ok(())
        })
        .await
}

fn validate_endpoint(endpoint: &str) -> Result<u16, ApiError> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| ApiError::bad_request("endpoint must be host:port"))?;
    if host.is_empty()
        || host.contains('/')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
    {
        return Err(ApiError::bad_request(
            "endpoint must be host:port without a URL scheme or path",
        ));
    }
    port.parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| ApiError::bad_request("Service port must be between 1 and 65535."))
}
