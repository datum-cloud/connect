#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    use connect_ip_adapter::helper::{Config, serve_reloadable};
    #[derive(Parser)]
    #[command(
        version,
        about = "Privileged explicitly approved network adapter helper; never handles cloud credentials"
    )]
    struct Args {
        /// Root-owned private approval file.
        #[arg(long)]
        config: std::path::PathBuf,
        /// Unix socket in a root-owned non-writable directory.
        #[arg(long, required_unless_present = "check")]
        socket: Option<std::path::PathBuf>,
        /// Validate approval file without opening a socket or interface.
        #[arg(long)]
        check: bool,
    }
    let args = Args::parse();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .init();
    let config = Config::load(&args.config)?;
    if args.check {
        return Ok(());
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    serve_reloadable(
        config,
        &args.socket.expect("required socket"),
        Some(&args.config),
        async move {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        },
    )
    .await?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("The networking helper currently supports macOS and Linux only.");
    std::process::exit(1);
}
