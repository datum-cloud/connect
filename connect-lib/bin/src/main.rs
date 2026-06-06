use std::time::Duration;

use clap::{Parser, Subcommand};
use n0_error::StdResultExt;

use connect_lib::datum_cloud::env::ApiEnv;
use connect_lib::datum_cloud::external_token_source::ExternalTokenSource;
use connect_lib::datum_cloud::DatumCloudClient;
use connect_lib::{HeartbeatAgent, ListenNode, Repo, SelectedContext, TunnelService};

#[derive(Parser, Debug)]
#[command(name = "datum-connect", about = "Datum Connect tunnel agent (plugin mode)")]
struct Args {
    #[clap(long, env = "DATUM_CONNECT_REPO")]
    repo: Option<std::path::PathBuf>,
    #[clap(long)]
    project: Option<String>,
    #[clap(long, global = true)]
    json: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all tunnels in the current project.
    List,
    /// Start a tunnel exposing a local service.
    Listen {
        #[clap(long)]
        label: Option<String>,
        #[clap(long)]
        endpoint: String,
    },
    /// Update an existing tunnel.
    Update {
        #[clap(long)]
        id: String,
        #[clap(long)]
        label: Option<String>,
        #[clap(long)]
        endpoint: Option<String>,
    },
    /// Delete a tunnel.
    Delete {
        #[clap(long)]
        id: String,
    },
}

fn resolve_project(project_id: &str) -> SelectedContext {
    SelectedContext {
        project_id: project_id.to_string(),
        project_name: project_id.to_string(),
        org_id: String::new(),
        org_name: String::new(),
        org_type: String::new(),
    }
}

#[tokio::main]
async fn main() {
    let result = run().await;
    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

async fn run() -> n0_error::Result<()> {
    let _ = rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| n0_error::anyerr!("failed to install ring crypto provider for rustls"))?;

    let _ = std::env::var("DATUM_ACCESS_TOKEN").map_err(|_| {
        n0_error::anyerr!("DATUM_ACCESS_TOKEN not set — this binary runs in plugin mode only")
    })?;

    let token_source = ExternalTokenSource::from_env()
        .map_err(|e| n0_error::anyerr!("Failed to create ExternalTokenSource: {e}"))?;
    let datum = DatumCloudClient::with_external_token_source(ApiEnv::default(), token_source);

    let args = Args::parse();

    let json = args.json;

    let project_id = match args.project {
        Some(ref pid) => pid.clone(),
        None => {
            let session = std::env::var("DATUM_SESSION")
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    n0_error::anyerr!(
                        "no project set — pass --project or run 'datumctl config set project <name>'"
                    )
                })?;
            session
        }
    };

    let ctx = resolve_project(&project_id);
    datum.set_selected_context(Some(ctx)).await?;

    let repo_path = args.repo.unwrap_or_else(Repo::default_location);
    let repo = Repo::open_or_create(repo_path).await?;

    match args.command {
        Commands::List => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            let tunnels = service.list_active().await?;
            let output: Vec<serde_json::Value> = tunnels
                .iter()
                .map(|t| {
                    let status = if t.accepted && t.programmed {
                        "ready"
                    } else if t.accepted {
                        "accepted"
                    } else {
                        "pending"
                    };
                    serde_json::json!({
                        "type": "tunnel",
                        "id": t.id,
                        "label": t.label,
                        "endpoint": t.endpoint,
                        "status": status,
                        "enabled": t.enabled,
                        "hostnames": t.hostnames
                    })
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&output).anyerr()?);
            } else {
                if output.is_empty() {
                    println!("No tunnels found.");
                }
                for t in &output {
                    println!("{}", serde_json::to_string(t).anyerr()?);
                }
            }
        }
        Commands::Listen { label, endpoint } => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            let endpoint_id = node.endpoint_id();

            let existing = service.get_active_by_endpoint(&endpoint).await?;
            let tunnel_id = if let Some(t) = existing {
                if let Some(label) = label.filter(|l| l != &t.label) {
                    let updated = service.update_active(&t.id, &label, &endpoint).await?;
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({"type": "tunnel_updated", "id": updated.id})
                        );
                    }
                    updated.id
                } else {
                    t.id
                }
            } else {
                let label = label.unwrap_or_else(|| endpoint.clone());
                let tunnel = service.create_active(&label, &endpoint).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"type": "tunnel_created", "id": tunnel.id})
                    );
                }
                tunnel.id
            };

            let heartbeat = HeartbeatAgent::new(datum.clone(), node.clone());
            heartbeat.start().await;
            heartbeat.register_project(&project_id).await;

            service.set_enabled_active(&tunnel_id, true).await?;

            let setup_start = std::time::Instant::now();
            let tunnel = loop {
                let t = service.get_active(&tunnel_id).await?;
                let Some(t) = t else {
                    return Err(n0_error::anyerr!("Tunnel {} not found after creation", tunnel_id));
                };
                if t.accepted && t.programmed && !t.hostnames.is_empty() {
                    break t;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            };

            let elapsed = setup_start.elapsed().as_secs();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "tunnel_ready",
                        "id": tunnel.id,
                        "label": tunnel.label,
                        "endpoint": tunnel.endpoint,
                        "hostnames": tunnel.hostnames,
                        "endpoint_id": endpoint_id.to_string(),
                        "status": "ready",
                        "elapsed_secs": elapsed
                    })
                );
            } else {
                for hostname in &tunnel.hostnames {
                    println!("Tunnel ready after {} sec: https://{}", elapsed, hostname);
                }
            }

            tokio::signal::ctrl_c().await?;
            service.set_enabled_active(&tunnel_id, false).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"type": "tunnel_disabled", "id": tunnel_id})
                );
            }
        }
        Commands::Update { id, label, endpoint } => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            let current = service
                .get_active(&id)
                .await?
                .ok_or_else(|| n0_error::anyerr!("Tunnel {} not found", id))?;
            let new_label = label.unwrap_or(current.label);
            let new_endpoint = endpoint.unwrap_or(current.endpoint);
            let tunnel = service.update_active(&id, &new_label, &new_endpoint).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "tunnel_updated",
                        "id": tunnel.id,
                        "label": tunnel.label,
                        "endpoint": tunnel.endpoint,
                        "hostnames": tunnel.hostnames
                    })
                );
            } else {
                println!("Updated tunnel {}:", tunnel.id);
                println!("  label: {}", tunnel.label);
                println!("  endpoint: {}", tunnel.endpoint);
            }
        }
        Commands::Delete { id } => {
            let node = ListenNode::new(repo.clone()).await?;
            let service = TunnelService::new(datum.clone(), node.clone());
            service.delete_active(&id).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"type": "tunnel_deleted", "id": id, "deleted": true})
                );
            } else {
                println!("Deleted tunnel {}", id);
            }
        }
    }
    Ok(())
}
