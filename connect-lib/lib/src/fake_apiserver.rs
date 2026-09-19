//! An in-memory fake Kubernetes-style apiserver for testing [`TunnelService`](crate::tunnels::TunnelService)
//! and friends against a real `kube::Client`, without a network, TLS, or a
//! real cluster.
//!
//! [`FakeApiServer`] implements `tower::Service<http::Request<kube::client::Body>>`
//! and is handed straight to `kube::Client::new`. It understands enough of
//! the standard Kubernetes REST conventions to serve everything
//! `connect-lib` actually does against a control plane:
//!
//! - `GET    /apis/{group}/{version}/namespaces/{ns}/{plural}` — list, with
//!   a `fieldSelector` query param evaluated against a dotted JSON path
//!   (only equality clauses joined by `,`/AND, which is all this crate uses)
//! - `GET    /apis/{group}/{version}/namespaces/{ns}/{plural}/{name}` — get
//! - `POST   /apis/{group}/{version}/namespaces/{ns}/{plural}` — create,
//!   honouring `metadata.generateName` when `metadata.name` is absent
//! - `PATCH  .../{name}` and `.../{name}/status` — RFC 7386 JSON merge
//!   patch (the only patch strategy this crate's `Patch::Merge` calls use)
//! - `DELETE .../{name}` — delete
//! - Cluster-scoped resources (no `namespaces/{ns}` segment, e.g.
//!   `ConnectorClass` via `Api::all`) are supported the same way, keyed
//!   under an empty namespace.
//!
//! Error responses are shaped like a real apiserver's `Status` object
//! (`{"kind":"Status","status":"Failure","reason":...,"code":...}`), which
//! is what `kube::Error::Api` and this crate's own [`crate::kube_error`]
//! classifiers parse.
//!
//! What it deliberately does not do: no RBAC, no admission, no controllers
//! reconciling anything (nothing here ever sets a condition or flips
//! `Ready`), no strategic-merge-patch, no resourceVersion/optimistic-lock
//! checking, no watches. Tests that need conditions to exist seed them
//! directly with [`FakeApiServer::insert`].

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use kube::client::Body as KubeBody;
use tower::Service;

/// Object identity within the fake store: resource plural (e.g.
/// `"httpproxies"`), namespace (empty string for cluster-scoped), name.
type ObjectKey = (String, String, String);

#[derive(Debug, Default)]
struct Store {
    objects: BTreeMap<ObjectKey, serde_json::Value>,
    generate_name_counter: u64,
}

/// An in-memory fake apiserver. Cheap to clone; clones share the same
/// backing store, so a test can hold one handle to seed/inspect state and
/// hand `client()` to as many `DatumCloudClient`s as it needs.
#[derive(Debug, Clone, Default)]
pub struct FakeApiServer {
    store: Arc<Mutex<Store>>,
}

impl FakeApiServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a `kube::Client` backed by this fake apiserver. `default_ns`
    /// mirrors `Config::default_namespace`; nothing in this crate reads it
    /// directly (every `Api::namespaced` call names its namespace
    /// explicitly), so any value works.
    pub fn client(&self) -> kube::Client {
        kube::Client::new(self.clone(), "default")
    }

    /// Seed an object directly, bypassing `create`. Useful for setting up
    /// preexisting state (including `status` and `conditions`, which
    /// nothing in this fake ever populates on its own) before exercising
    /// the code under test.
    pub fn insert(&self, plural: &str, namespace: &str, name: &str, obj: serde_json::Value) {
        let mut store = self.store.lock().expect("fake apiserver store poisoned");
        store.objects.insert(key(plural, namespace, name), obj);
    }

    /// Read back a stored object, e.g. to assert on fields a production
    /// code path doesn't return to the caller (annotations set by a
    /// `patch`, for instance).
    pub fn get(&self, plural: &str, namespace: &str, name: &str) -> Option<serde_json::Value> {
        let store = self.store.lock().expect("fake apiserver store poisoned");
        store.objects.get(&key(plural, namespace, name)).cloned()
    }

    /// Names of every stored object of a given plural, across all
    /// namespaces. Useful for asserting "nothing of this kind exists" or
    /// counting leftovers after a delete/cleanup call.
    pub fn names(&self, plural: &str) -> Vec<String> {
        let store = self.store.lock().expect("fake apiserver store poisoned");
        store
            .objects
            .keys()
            .filter(|(p, _, _)| p == plural)
            .map(|(_, _, name)| name.clone())
            .collect()
    }

    async fn handle(&self, req: Request<KubeBody>) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        // Every resource this crate talks to is a non-core-group resource,
        // so the path always starts "apis/{group}/{version}/...". The
        // group/version segments themselves are irrelevant for routing:
        // plural names are unique enough within one fake store per test.
        let Some(rest) = segments.get(3..) else {
            return json_error(StatusCode::NOT_FOUND, 404, "NotFound", "unrecognised path");
        };
        let (namespace, rest): (String, &[&str]) = match rest {
            ["namespaces", ns, tail @ ..] => ((*ns).to_string(), tail),
            tail => (String::new(), tail),
        };
        let Some(&plural) = rest.first() else {
            return json_error(
                StatusCode::NOT_FOUND,
                404,
                "NotFound",
                "missing resource plural",
            );
        };
        let name = rest.get(1).map(|s| s.to_string());
        let is_status = rest.get(2).copied() == Some("status");

        match (method.as_str(), name) {
            ("GET", None) => self.list(plural, &namespace, &query),
            ("GET", Some(name)) => self.get_one(plural, &namespace, &name),
            ("POST", None) => {
                let body = req.into_body().collect_bytes().await.unwrap_or_default();
                self.create(plural, &namespace, &body)
            }
            ("PATCH", Some(name)) => {
                let body = req.into_body().collect_bytes().await.unwrap_or_default();
                self.patch(plural, &namespace, &name, &body, is_status)
            }
            ("DELETE", Some(name)) => self.delete(plural, &namespace, &name),
            (method, _) => json_error(
                StatusCode::METHOD_NOT_ALLOWED,
                405,
                "MethodNotAllowed",
                &format!("fake apiserver does not support {method} on {plural}"),
            ),
        }
    }

    fn list(&self, plural: &str, namespace: &str, query: &str) -> Response<Full<Bytes>> {
        let field_selector = query_param(query, "fieldSelector");
        let store = self.store.lock().expect("fake apiserver store poisoned");
        let items: Vec<serde_json::Value> = store
            .objects
            .iter()
            .filter(|((p, ns, _), _)| p == plural && ns == namespace)
            .filter(|(_, obj)| {
                field_selector
                    .as_deref()
                    .is_none_or(|fs| matches_field_selector(obj, fs))
            })
            .map(|(_, obj)| obj.clone())
            .collect();
        json_response(
            StatusCode::OK,
            &serde_json::json!({ "apiVersion": "v1", "kind": "List", "items": items }),
        )
    }

    fn get_one(&self, plural: &str, namespace: &str, name: &str) -> Response<Full<Bytes>> {
        let store = self.store.lock().expect("fake apiserver store poisoned");
        match store.objects.get(&key(plural, namespace, name)) {
            Some(obj) => json_response(StatusCode::OK, obj),
            None => not_found(plural, name),
        }
    }

    fn create(&self, plural: &str, namespace: &str, body: &[u8]) -> Response<Full<Bytes>> {
        let Ok(mut obj) = serde_json::from_slice::<serde_json::Value>(body) else {
            return json_error(
                StatusCode::BAD_REQUEST,
                400,
                "BadRequest",
                "invalid JSON body",
            );
        };
        let mut store = self.store.lock().expect("fake apiserver store poisoned");
        let explicit_name = obj
            .pointer("/metadata/name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let name = explicit_name.unwrap_or_else(|| {
            let prefix = obj
                .pointer("/metadata/generateName")
                .and_then(|v| v.as_str())
                .unwrap_or("generated-");
            store.generate_name_counter += 1;
            format!("{prefix}{:05}", store.generate_name_counter)
        });
        if let Some(meta) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            meta.insert("name".into(), serde_json::json!(name));
            if !namespace.is_empty() {
                meta.insert("namespace".into(), serde_json::json!(namespace));
            }
            meta.entry("generation").or_insert(serde_json::json!(1));
        }
        store
            .objects
            .insert(key(plural, namespace, &name), obj.clone());
        json_response(StatusCode::CREATED, &obj)
    }

    fn patch(
        &self,
        plural: &str,
        namespace: &str,
        name: &str,
        body: &[u8],
        status_only: bool,
    ) -> Response<Full<Bytes>> {
        let Ok(patch) = serde_json::from_slice::<serde_json::Value>(body) else {
            return json_error(
                StatusCode::BAD_REQUEST,
                400,
                "BadRequest",
                "invalid JSON body",
            );
        };
        let mut store = self.store.lock().expect("fake apiserver store poisoned");
        let Some(existing) = store.objects.get_mut(&key(plural, namespace, name)) else {
            return not_found(plural, name);
        };
        merge_patch(existing, &patch);
        // Real apiservers bump metadata.generation on spec changes, not on
        // status-subresource patches; a few of this crate's own tests
        // (progress staleness) depend on that distinction.
        if !status_only
            && let Some(meta) = existing.get_mut("metadata").and_then(|m| m.as_object_mut())
        {
            let generation = meta.get("generation").and_then(|g| g.as_i64()).unwrap_or(0);
            meta.insert("generation".into(), serde_json::json!(generation + 1));
        }
        json_response(StatusCode::OK, existing)
    }

    fn delete(&self, plural: &str, namespace: &str, name: &str) -> Response<Full<Bytes>> {
        let mut store = self.store.lock().expect("fake apiserver store poisoned");
        match store.objects.remove(&key(plural, namespace, name)) {
            Some(obj) => json_response(StatusCode::OK, &obj),
            None => not_found(plural, name),
        }
    }
}

fn key(plural: &str, namespace: &str, name: &str) -> ObjectKey {
    (plural.to_string(), namespace.to_string(), name.to_string())
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k != name {
            return None;
        }
        Some(urlencoding_decode(v))
    })
}

/// Minimal percent-decoding: kube-core only ever percent-encodes
/// `fieldSelector` values through `url::form_urlencoded`, which is limited
/// to a small set of reserved characters (this crate's own selectors are
/// `key.path=value` with dots, slashes and alphanumerics — none of the
/// bytes url's encoder touches), so a full decoder is unnecessary; handle
/// the one thing it does always encode, `%2C` for `,` (present when a
/// selector is only a single clause, url still escapes the raw string).
fn urlencoding_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte as char);
                continue;
            }
            out.push('%');
            out.push_str(&hex);
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn matches_field_selector(obj: &serde_json::Value, selector: &str) -> bool {
    selector.split(',').all(|clause| {
        let Some((path, expected)) = clause.split_once('=') else {
            return true;
        };
        json_path_str(obj, path) == Some(expected)
    })
}

fn json_path_str<'a>(obj: &'a serde_json::Value, path: &str) -> Option<&'a str> {
    let mut cur = obj;
    for segment in path.split('.') {
        cur = cur.get(segment)?;
    }
    cur.as_str()
}

/// RFC 7386 JSON merge patch: a `null` leaf deletes the key, an object
/// merges recursively, anything else replaces the key wholesale. This is
/// the only patch strategy `connect-lib` uses (`kube::api::Patch::Merge`).
fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(patch_map) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(Default::default());
    }
    let target_map = target
        .as_object_mut()
        .expect("just ensured target is an object");
    for (k, v) in patch_map {
        if v.is_null() {
            target_map.remove(k);
        } else if v.is_object() && target_map.get(k).is_some_and(|t| t.is_object()) {
            merge_patch(target_map.get_mut(k).expect("key just checked present"), v);
        } else {
            target_map.insert(k.clone(), v.clone());
        }
    }
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::from(bytes))
        .expect("fixed set of headers on a fresh builder never fails")
}

fn not_found(plural: &str, name: &str) -> Response<Full<Bytes>> {
    json_error(
        StatusCode::NOT_FOUND,
        404,
        "NotFound",
        &format!("{plural} \"{name}\" not found"),
    )
}

/// Shaped like a real apiserver's `meta/v1.Status` object, which is what
/// `kube::Error::Api` (and this crate's `kube_error::classify_list_error`)
/// deserialize a non-2xx response body into.
fn json_error(status: StatusCode, code: u16, reason: &str, message: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        &serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": message,
            "reason": reason,
            "code": code,
        }),
    )
}

impl Service<Request<KubeBody>> for FakeApiServer {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<KubeBody>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.handle(req).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_patch_deletes_null_leaves_and_merges_nested_objects() {
        let mut target = serde_json::json!({
            "spec": {"a": 1, "b": 2},
            "keep": "me",
        });
        merge_patch(
            &mut target,
            &serde_json::json!({"spec": {"a": null, "c": 3}}),
        );
        assert_eq!(
            target,
            serde_json::json!({"spec": {"b": 2, "c": 3}, "keep": "me"})
        );
    }

    #[test]
    fn field_selector_matches_dotted_path() {
        let obj = serde_json::json!({
            "status": {"connectionDetails": {"publicKey": {"id": "abc123"}}}
        });
        assert!(matches_field_selector(
            &obj,
            "status.connectionDetails.publicKey.id=abc123"
        ));
        assert!(!matches_field_selector(
            &obj,
            "status.connectionDetails.publicKey.id=other"
        ));
    }

    // These exercise the router against `Connector`, one of connect-lib's
    // own CRDs, rather than a stand-in like `k8s_openapi`'s `ConfigMap`:
    // `ConfigMap` is a *core*-group resource (`/api/v1/...`, no `apis`
    // segment, one fewer path component), a shape this fake deliberately
    // does not support since nothing in this crate ever talks to one (see
    // the module doc comment). Every resource `connect-lib` actually uses
    // is a named-group CRD like `Connector`, so that's what these test.

    fn new_connector(generate_name: &str) -> crate::datum_apis::connector::Connector {
        crate::datum_apis::connector::Connector {
            metadata: kube::api::ObjectMeta {
                generate_name: Some(generate_name.to_string()),
                ..Default::default()
            },
            spec: crate::datum_apis::connector::ConnectorSpec {
                connector_class_name: "datum-connect".to_string(),
                capabilities: None,
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn create_list_get_patch_delete_round_trip() {
        let fake = FakeApiServer::new();
        let api: kube::Api<crate::datum_apis::connector::Connector> =
            kube::Api::namespaced(fake.client(), "default");

        let created = api
            .create(&kube::api::PostParams::default(), &new_connector("conn-"))
            .await
            .expect("create");
        let name = created.metadata.name.clone().expect("name set");
        assert!(name.starts_with("conn-"));

        let list = api
            .list(&kube::api::ListParams::default())
            .await
            .expect("list");
        assert_eq!(list.items.len(), 1);

        let fetched = api.get(&name).await.expect("get");
        assert_eq!(fetched.metadata.name.as_deref(), Some(name.as_str()));

        let patch = serde_json::json!({"spec": {"connectorClassName": "other-class"}});
        let patched = api
            .patch(
                &name,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Merge(&patch),
            )
            .await
            .expect("patch");
        assert_eq!(patched.spec.connector_class_name, "other-class");

        api.delete(&name, &kube::api::DeleteParams::default())
            .await
            .expect("delete");
        let missing = api.get_opt(&name).await.expect("get_opt after delete");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn get_opt_returns_none_on_404_not_err() {
        let fake = FakeApiServer::new();
        let api: kube::Api<crate::datum_apis::connector::Connector> =
            kube::Api::namespaced(fake.client(), "default");
        assert!(api.get_opt("missing").await.expect("get_opt").is_none());
    }
}
