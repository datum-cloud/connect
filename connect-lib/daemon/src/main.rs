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
use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, layer::SubscriberExt, util::SubscriberInitExt,
};

#[cfg(windows)]
#[path = "main/windows_service.rs"]
mod windows_service;

#[derive(Clone, Debug, Parser)]
#[command(name = "datum-connectd", version = env!("DATUM_CONNECT_RELEASE_VERSION"))]
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
    let (_log_guard, _otel_guard) = match init_tracing(args.log_file.as_deref()).await {
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
    let reconcile_shutdown = shutdown.child_token();
    let reconcile_task = tokio::spawn(async move {
        api::reconcile_with_retry(&reconcile_state, reconcile_shutdown).await
    });
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
) -> Result<
    (
        Option<tracing_appender::non_blocking::WorkerGuard>,
        OtelGuard,
    ),
    std::io::Error,
> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (otel_layer, otel_guard) = init_otel("datum-connectd");
    let otel_enabled = otel_layer.is_some();
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
            .with(otel_layer)
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
        if otel_enabled {
            tracing::info!(
                stage = "otel_exporter_init",
                "OpenTelemetry OTLP tracing enabled"
            );
        }
        Ok((Some(guard), otel_guard))
    } else {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(filter)
            .with(stderr_layer)
            .init();
        if otel_enabled {
            tracing::info!(
                stage = "otel_exporter_init",
                "OpenTelemetry OTLP tracing enabled"
            );
        }
        Ok((None, otel_guard))
    }
}

struct OtelGuard(Option<SdkTracerProvider>);

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take()
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(%error, stage="otel_shutdown", "OpenTelemetry exporter shutdown failed");
        }
    }
}

fn init_otel(
    service_name: &'static str,
) -> (Option<Box<dyn Layer<Registry> + Send + Sync>>, OtelGuard) {
    let endpoint = std::env::var("DATUM_CONNECT_OTEL_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| otlp_traces_endpoint(&value))
        .or_else(|| {
            std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| otlp_traces_endpoint(&value))
        });
    let Some(endpoint) = endpoint else {
        return (None, OtelGuard(None));
    };
    let exporter = match SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(exporter) => exporter,
        Err(error) => {
            eprintln!("OpenTelemetry exporter disabled: {error}");
            return (None, OtelGuard(None));
        }
    };
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name)
                .with_attributes([KeyValue::new("service.namespace", "datum")])
                .build(),
        )
        .build();
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    opentelemetry::global::set_tracer_provider(provider.clone());
    let layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(service_name))
        .boxed();
    (Some(layer), OtelGuard(Some(provider)))
}

fn otlp_traces_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.ends_with("/v1/traces") {
        endpoint.to_owned()
    } else {
        format!("{endpoint}/v1/traces")
    }
}

#[cfg(test)]
mod version_tests {
    use super::Args;
    use clap::CommandFactory;

    #[test]
    fn command_reports_release_version_and_executable_name() {
        let command = Args::command();
        assert_eq!(command.get_name(), "datum-connectd");
        assert_eq!(
            command.get_version(),
            Some(env!("DATUM_CONNECT_RELEASE_VERSION"))
        );
    }
}
