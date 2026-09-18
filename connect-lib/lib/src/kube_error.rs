//! Shared kube error classification helpers.

use n0_error::AnyError;

/// A project control-plane request failed in a way the caller should
/// classify rather than retry. Produced by [`classify_list_error`] from the
/// HTTP status of a kube `list` call and carried inside an [`AnyError`];
/// recover it with [`ControlPlaneError::find_in`].
///
/// The library deliberately reports only *what* went wrong. User-facing
/// guidance (which `datumctl` command fixes it) belongs to the binary that
/// knows how it was invoked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneError {
    /// The project's control plane does not exist on this API host (HTTP 404
    /// on a `list`). A `list` against an existing control plane returns 200
    /// even when the namespace is empty, so a 404 can only mean the project
    /// itself is missing or unprovisioned.
    #[error("control plane for project '{project_id}' not found")]
    ProjectNotFound { project_id: String },
    /// The token is valid but not allowed to read this project (HTTP 403).
    #[error("permission denied in project '{project_id}'")]
    PermissionDenied { project_id: String },
    /// The token was rejected outright (HTTP 401).
    #[error("authentication failed for project '{project_id}'")]
    Unauthorized { project_id: String },
}

impl ControlPlaneError {
    /// Locate a `ControlPlaneError` anywhere in `err`'s source chain.
    ///
    /// `AnyError::downcast_ref` only inspects the outermost error, and every
    /// `.context(..)` / `.std_context(..)` call adds a layer, so callers that
    /// want to branch on the classification must look through the chain.
    pub fn find_in(err: &AnyError) -> Option<&ControlPlaneError> {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
        while let Some(e) = current {
            if let Some(found) = e.downcast_ref::<ControlPlaneError>() {
                return Some(found);
            }
            current = e.source();
        }
        None
    }
}

/// Turn a failed kube `list` call into an [`AnyError`], classifying the
/// project-level failures (401, 403, 404) as a [`ControlPlaneError`] so the
/// binary can act on them, and wrapping everything else with `context`.
pub fn classify_list_error(project_id: &str, context: &str, err: kube::Error) -> AnyError {
    let project_id = project_id.to_string();
    let classified = match &err {
        kube::Error::Api(e) if e.code == 404 => {
            Some(ControlPlaneError::ProjectNotFound { project_id })
        }
        kube::Error::Api(e) if e.code == 403 => {
            Some(ControlPlaneError::PermissionDenied { project_id })
        }
        kube::Error::Api(e) if e.code == 401 => {
            Some(ControlPlaneError::Unauthorized { project_id })
        }
        _ => None,
    };
    match classified {
        Some(cp) => AnyError::from_std(cp).context(context.to_string()),
        None => AnyError::from_std(err).context(context.to_string()),
    }
}

/// Returns true if `err` is an HTTP 401 (unauthorized).
pub fn is_unauthorized(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(e) if e.code == 401)
}

/// Returns true if `err` is an HTTP 404 (not found).
pub fn is_not_found(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(e) if e.code == 404)
}

/// Returns true if `err` is the operator's transient quota-check timeout
/// (a 403 whose message says "took too long to be checked against your quota").
/// Distinct from real quota exhaustion, which produces a different message.
pub fn is_quota_check_timeout(err: &kube::Error) -> bool {
    matches!(
        err,
        kube::Error::Api(e)
            if e.code == 403
                && e.message.contains("took too long to be checked against your quota")
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_util::api_error;
    use n0_error::StackResultExt;

    #[test]
    fn classify_list_error_maps_project_level_status_codes() {
        for (code, expected) in [
            (
                404,
                ControlPlaneError::ProjectNotFound {
                    project_id: "p".into(),
                },
            ),
            (
                403,
                ControlPlaneError::PermissionDenied {
                    project_id: "p".into(),
                },
            ),
            (
                401,
                ControlPlaneError::Unauthorized {
                    project_id: "p".into(),
                },
            ),
        ] {
            let err = classify_list_error("p", "listing", api_error(code, "x"));
            assert_eq!(
                ControlPlaneError::find_in(&err),
                Some(&expected),
                "code {code}"
            );
        }
    }

    #[test]
    fn classify_list_error_leaves_other_errors_unclassified() {
        for code in [400, 409, 429, 500, 503] {
            let err = classify_list_error("p", "listing", api_error(code, "x"));
            assert!(ControlPlaneError::find_in(&err).is_none(), "code {code}");
            assert!(err.to_string().contains("listing"));
        }
    }

    #[test]
    fn find_in_sees_through_added_context() {
        let inner = classify_list_error("p", "listing", api_error(404, "x"));
        let wrapped: Result<(), _> = Err(inner);
        let Err(wrapped) = wrapped.context("outer").context("outermost") else {
            panic!("wrapping an Err must stay Err");
        };
        assert!(matches!(
            ControlPlaneError::find_in(&wrapped),
            Some(ControlPlaneError::ProjectNotFound { project_id }) if project_id == "p"
        ));
    }

    #[test]
    fn find_in_returns_none_for_plain_errors() {
        let err = n0_error::anyerr!("nothing to see");
        assert!(ControlPlaneError::find_in(&err).is_none());
    }
}
