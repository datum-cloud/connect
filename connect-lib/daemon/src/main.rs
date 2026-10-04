use std::{future::IntoFuture, path::PathBuf, sync::Arc};

use clap::Parser;
use datum_connect_daemon::{
    api::{self, AppState},
    auth,
    control::Control,
    error::ApiError,
    runtime::RealControl,
    store::Store,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(windows)]
#[path = "main/windows_service.rs"]
mod windows_service;

#[derive(Clone, Debug, Parser)]
#[command(name = "datum-connect-daemon", version)]
struct Args {
    /// Private daemon repository. Overrides DATUM_CONNECT_DIR.
    #[arg(long, env = "DATUM_CONNECT_DIR")]
    repo: PathBuf,

    /// Loopback HTTP port.
    #[arg(long, default_value_t = 47_780, env = "DATUM_CONNECT_DAEMON_PORT")]
    port: u16,

    /// Also write structured JSON logs to this file.
    #[arg(long, env = "DATUM_CONNECT_DAEMON_LOG")]
    log_file: Option<PathBuf>,

    /// Default credential file used when /v1/up omits credentials_file.
    #[arg(long, env = "DATUM_CONNECT_CREDENTIALS_FILE")]
    credentials_file: Option<PathBuf>,

    /// Explicit development marker. It never bypasses Cloud authorization.
    #[arg(long)]
    offline: bool,

    /// Explicit static approvals for the ephemeral native CONNECT-IP prototype.
    #[arg(long)]
    local_ip_config: Option<PathBuf>,

    /// Comma-separated HTTPS relay origins. Staging sessions default to Datum staging relays.
    #[arg(long, env = "DATUM_CONNECT_RELAY_URLS")]
    relay_urls: Option<String>,

    /// Private JSON configuration for the opt-in standards-facing MASQUE listener.
    #[arg(long, env = "DATUM_CONNECT_MASQUE_CONFIG")]
    masque_config: Option<PathBuf>,

    /// Run under the Windows Service Control Manager.
    #[cfg(windows)]
    #[arg(long, hide = true)]
    windows_service: bool,
}

fn main() {
    let args = Args::parse();
    #[cfg(windows)]
    if args.windows_service {
        if let Err(error) = windows_service::dispatch(args) {
            eprintln!("Windows service dispatcher failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| {
            eprintln!("failed to initialize async runtime: {error}");
            std::process::exit(1);
        });
    runtime.block_on(run_console(args));
}

async fn run_console(args: Args) {
    let _log_guard = match init_tracing(args.log_file.as_deref()).await {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("failed to initialize logging: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = run(args, None, None).await {
        tracing::error!(stage = "daemon", error = %error, "daemon_failed");
        std::process::exit(1);
    }
}

async fn run(
    args: Args,
    external_shutdown: Option<CancellationToken>,
    on_ready: Option<fn()>,
) -> Result<(), ApiError> {
    let store = Store::open(&args.repo).await?;
    auth::initialize_setup_token(&store, &args.repo).await?;
    let shutdown = external_shutdown.unwrap_or_default();

    let mutation_lock = Arc::new(tokio::sync::Mutex::new(()));
    let local_ip = match args.local_ip_config {
        Some(path) => Some(datum_connect_daemon::local_ip::LocalIpConfig::load(&path).await?),
        None => None,
    };
    let control: Arc<dyn Control> = Arc::new(
        RealControl::new(args.repo.clone(), store.clone(), mutation_lock.clone())
            .with_local_ip_config(local_ip)
            .with_relay_urls(
                args.relay_urls
                    .as_deref()
                    .map(datum_connect_daemon::relays::parse)
                    .transpose()?,
            ),
    );
    if args.offline {
        tracing::warn!(
            stage = "startup",
            "offline flag does not bypass Cloud enrollment; network operations remain fail-closed"
        );
    }
    let app_state = AppState {
        store,
        control,
        default_credentials_file: args
            .credentials_file
            .map(|path| path.to_string_lossy().into_owned()),
        mutation_lock,
    };
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.port))
        .await
        .map_err(|error| ApiError::internal(format!("binding loopback API: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| ApiError::internal(format!("reading API address: {error}")))?;
    let masque_runtime = match args.masque_config.as_deref() {
        Some(path) => {
            Some(datum_connect_daemon::masque::Runtime::start(path, shutdown.child_token()).await?)
        }
        None => None,
    };
    tracing::info!(stage = "startup", %address, "daemon_listening");
    if let Some(on_ready) = on_ready {
        on_ready();
    }
    let reconcile_state = app_state.clone();
    let reconcile_task = tokio::spawn(async move { api::reconcile_all(&reconcile_state).await });
    #[cfg(windows)]
    let install_console_signal = !args.windows_service;
    #[cfg(not(windows))]
    let install_console_signal = true;
    if install_console_signal {
        let shutdown_wait = shutdown.clone();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            shutdown_wait.cancel();
        });
    }

    let server = axum::serve(listener, api::router(app_state.clone()))
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .into_future();
    tokio::pin!(server);
    let serve_result = tokio::select! {
        result = &mut server => Some(result),
        _ = shutdown.cancelled() => tokio::time::timeout(
            std::time::Duration::from_secs(20), &mut server
        ).await.ok(),
    };
    let serve_error = match serve_result {
        Some(Ok(())) => None,
        Some(Err(error)) => Some(ApiError::internal(format!("serving loopback API: {error}"))),
        None => {
            tracing::error!(
                stage = "shutdown",
                "HTTP graceful shutdown exceeded 20 seconds"
            );
            None
        }
    };
    // Also stop auxiliary listeners when the loopback server exits on error,
    // not only when an external shutdown signal initiated the sequence.
    shutdown.cancel();
    reconcile_task.abort();
    let _ = reconcile_task.await;
    if let Some(runtime) = masque_runtime {
        runtime.shutdown().await;
    }
    if tokio::time::timeout(
        std::time::Duration::from_secs(10),
        app_state.control.shutdown(),
    )
    .await
    .is_err()
    {
        tracing::error!(stage = "shutdown", "network shutdown exceeded 10 seconds");
    }
    tracing::info!(stage = "shutdown", "daemon_stopped");
    serve_error.map_or(Ok(()), Err)
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    tracing::error!(%error, "installing SIGTERM handler failed");
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn init_tracing(
    log_file: Option<&std::path::Path>,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>, std::io::Error> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::io::stderr);
    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            connect_lib::secure_fs::ensure_private_dir(parent).await?;
        }
        let file = connect_lib::secure_fs::open_private_append(path)?;
        let (writer, guard) = tracing_appender::non_blocking(file);
        let file_layer = tracing_subscriber::fmt::layer().json().with_writer(writer);
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
        Ok(Some(guard))
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .init();
        Ok(None)
    }
}
