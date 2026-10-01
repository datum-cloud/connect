use super::*;
use std::os::unix::fs::PermissionsExt;

fn fixture(script: &str) -> (tempfile::TempDir, Credentials) {
    let dir = tempfile::tempdir().unwrap();
    let helper = dir.path().join("datumctl");
    std::fs::write(&helper, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let credentials = Credentials::datumctl_session(
        "alpha",
        "https://api.datum.net",
        helper.to_str().unwrap(),
        "pinned session; not shell syntax",
    )
    .unwrap();
    (dir, credentials)
}

fn response(token: &str, expiry: chrono::DateTime<chrono::Utc>) -> String {
    serde_json::json!({"apiVersion":"client.authentication.k8s.io/v1", "kind":"ExecCredential",
        "status":{"token":token, "expirationTimestamp":expiry.to_rfc3339()}})
    .to_string()
}

fn future_response() -> String {
    response(
        "TEST-SECRET-TOKEN",
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
}

// Root is deliberately unsupported in production. Root CI still verifies rejection;
// subprocess integration cases run only under the user-daemon identity they cover.
fn user_daemon() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() != 0 }
}

#[tokio::test]
async fn exact_pinned_session_arguments_and_secret_free_descriptor() {
    if !user_daemon() {
        return;
    }
    let (dir, credentials) = fixture(&format!("printf '%s' '{}'", future_response()));
    let args_file = dir.path().join("arguments");
    std::fs::write(
        &credentials.helper_path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '{}'\n",
            args_file.display(),
            future_response()
        ),
    )
    .unwrap();
    let (token, _) = session_token(&credentials, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(token, "TEST-SECRET-TOKEN");
    assert_eq!(
        std::fs::read_to_string(args_file).unwrap(),
        "auth\nget-token\n--session\npinned session; not shell syntax\n--output\nclient.authentication.k8s.io/v1\n"
    );
    let value = serde_json::to_value(&credentials).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 5);
    assert_eq!(value["type"], "datumctl_session");
    assert!(!format!("{credentials:?}").contains("pinned session"));
    let path = dir.path().join("descriptor.json");
    crate::repo::atomic_write_private(&path, &serde_json::to_vec(&credentials).unwrap())
        .await
        .unwrap();
    let loaded = Credentials::load(path).await.unwrap();
    assert_eq!(loaded.session, credentials.session);
}

#[tokio::test]
async fn malformed_expired_and_failed_helpers_never_expose_output() {
    if !user_daemon() {
        return;
    }
    let cases = [
        "printf '%s' 'SECRET-MALFORMED-OUTPUT'".to_owned(),
        "printf '%s' 'SECRET-STDOUT'; printf '%s' 'SECRET-STDERR' >&2; exit 7".to_owned(),
        format!("printf '%s' '{}'", response("SECRET-EXPIRED", chrono::Utc::now() - chrono::Duration::seconds(1))),
        format!("printf '%s' '{}'", response("SECRET-UNBOUNDED", chrono::Utc::now() + chrono::Duration::days(370))),
        "printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"SECRET-NO-EXPIRY\"}}'".into(),
    ];
    for script in cases {
        let (_dir, credentials) = fixture(&script);
        let error = session_token(&credentials, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("SECRET"));
        assert!(!format!("{error:?}").contains("SECRET"));
        assert!(!error.to_string().contains(&credentials.session));
    }
}

#[tokio::test]
async fn timeout_and_output_limit_terminate_and_reap_helpers() {
    if !user_daemon() {
        return;
    }
    for oversized in [false, true] {
        let (dir, credentials) = fixture("exit 1");
        let pid_file = dir.path().join("pid");
        let output = if oversized {
            "dd if=/dev/zero bs=65537 count=1 2>/dev/null\n"
        } else {
            ""
        };
        std::fs::write(
            &credentials.helper_path,
            format!(
                "#!/bin/sh\necho $$ > '{}'\n{output}exec sleep 30\n",
                pid_file.display()
            ),
        )
        .unwrap();
        let error = session_token(&credentials, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(if oversized { "64 KiB" } else { "timed out" })
        );
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal zero checks existence without sending a signal.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "helper remains running or unreaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}

#[tokio::test]
async fn cache_is_short_lived_and_invalidation_observes_logout() {
    if !user_daemon() {
        return;
    }
    let (_dir, credentials) = fixture(&format!("printf '%s' '{}'", future_response()));
    let provider = TokenProvider::new(credentials.clone(), reqwest::Client::new());
    assert_eq!(provider.token().await.unwrap(), "TEST-SECRET-TOKEN");
    let state = provider.inner.lock().await;
    assert!(state.expires_at <= SystemTime::now() + Duration::from_secs(30));
    drop(state);
    std::fs::write(&credentials.helper_path, "#!/bin/sh\nexit 1\n").unwrap();
    assert_eq!(provider.token().await.unwrap(), "TEST-SECRET-TOKEN");
    provider.invalidate().await;
    assert!(
        provider
            .token()
            .await
            .unwrap_err()
            .to_string()
            .contains("datumctl login")
    );
    // An expired cache invokes the pinned session again even without a 401.
    provider.inner.lock().await.expires_at = UNIX_EPOCH;
    assert!(provider.token().await.is_err());
}

#[tokio::test]
async fn helper_permissions_are_revalidated_before_every_execution() {
    if !user_daemon() {
        return;
    }
    let (_dir, credentials) = fixture(&format!("printf '%s' '{}'", future_response()));
    let provider = TokenProvider::new(credentials.clone(), reqwest::Client::new());
    provider.token().await.unwrap();
    std::fs::set_permissions(
        &credentials.helper_path,
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    provider.invalidate().await;
    assert!(
        provider
            .token()
            .await
            .unwrap_err()
            .to_string()
            .contains("write access")
    );
    std::fs::set_permissions(
        &credentials.helper_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(credentials.validate().is_err());
}

#[test]
fn descriptors_reject_unsafe_configuration_and_root() {
    if !user_daemon() {
        assert!(
            Credentials::datumctl_session("alpha", "https://api.datum.net", "/bin/sh", "session")
                .is_err()
        );
        return;
    }
    let (_dir, mut credentials) = fixture("exit 1");
    credentials.session.clear();
    assert!(credentials.validate().is_err());
    credentials.session = "valid".into();
    credentials.refresh_token = "copied-secret".into();
    assert!(credentials.validate().is_err());
    credentials.refresh_token.clear();
    credentials.helper_path = "datumctl".into();
    assert!(credentials.validate().is_err());
}

#[tokio::test]
async fn private_snapshot_survives_source_replacement_and_cleans_up() {
    use std::os::unix::fs::MetadataExt;
    if !user_daemon() {
        return;
    }
    let (dir, credentials) = fixture(&format!("printf '%s' '{}'", future_response()));
    let original = std::fs::metadata(&credentials.helper_path).unwrap();
    let snapshot = snapshot_helper(Path::new(&credentials.helper_path)).unwrap();
    let snapshot_path = snapshot.executable.clone();
    let private_dir = snapshot.executable.parent().unwrap().to_owned();
    assert_eq!(
        std::fs::metadata(&private_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    std::fs::rename(&credentials.helper_path, dir.path().join("old")).unwrap();
    std::fs::write(&credentials.helper_path, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(
        &credentials.helper_path,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let output = tokio::process::Command::new(&snapshot.executable)
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["status"]["token"],
        "TEST-SECRET-TOKEN"
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("old"))
            .unwrap()
            .permissions()
            .mode(),
        original.permissions().mode()
    );
    assert_eq!(
        std::fs::metadata(&snapshot_path).unwrap().ino(),
        original.ino()
    );
    drop(snapshot);
    assert!(!snapshot_path.exists());
    assert!(!private_dir.exists());
}

#[test]
fn source_swap_between_open_and_link_is_rejected() {
    if !user_daemon() {
        return;
    }
    let (dir, credentials) = fixture("exit 0");
    let file = open_validated_helper(Path::new(&credentials.helper_path)).unwrap();
    std::fs::rename(&credentials.helper_path, dir.path().join("original")).unwrap();
    std::fs::write(&credentials.helper_path, "#!/bin/sh\nexit 99\n").unwrap();
    std::fs::set_permissions(
        &credentials.helper_path,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let error = snapshot_opened_helper(Path::new(&credentials.helper_path), file)
        .err()
        .unwrap();
    assert!(error.to_string().contains("changed during validation"));
}

#[tokio::test]
#[ignore = "Uses an explicitly selected real datumctl login session; never prints credentials"]
async fn installed_host_session_uses_private_snapshot() {
    let helper = std::env::var("TEST_DATUMCTL_HELPER").expect("set TEST_DATUMCTL_HELPER");
    let session = std::env::var("TEST_DATUMCTL_SESSION").expect("set TEST_DATUMCTL_SESSION");
    let credentials = Credentials::datumctl_session(
        "local-validation",
        "https://api.datum.net",
        &helper,
        &session,
    )
    .unwrap();
    let provider = TokenProvider::new(credentials, reqwest::Client::new());
    assert!(!provider.token().await.unwrap().is_empty());
}
