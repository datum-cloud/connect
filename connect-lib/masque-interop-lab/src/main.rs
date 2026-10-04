//! Local independent-client lab using the reusable standards-facing edge.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow, bail};
use connect_masque_edge::{Route, Server, tls_config};
use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig,
};
use iroh::{EndpointAddr, SecretKey};
use rustls::pki_types::PrivateKeyDer;
use tokio_util::sync::CancellationToken;

struct Options {
    listen: SocketAddr,
    origin: SocketAddr,
    cert_out: PathBuf,
    ready_out: PathBuf,
}

fn options() -> Result<Options> {
    let mut listen = "127.0.0.1:0".parse().unwrap();
    let mut origin = None;
    let mut cert_out = None;
    let mut ready_out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| anyhow!("missing value after {arg}"))?;
        match arg.as_str() {
            "--listen" => listen = value.parse().context("invalid --listen")?,
            "--origin" => origin = Some(value.parse().context("invalid --origin")?),
            "--cert-out" => cert_out = Some(value.into()),
            "--ready-out" => ready_out = Some(value.into()),
            _ => bail!("unknown argument {arg}"),
        }
    }
    Ok(Options {
        listen,
        origin: origin.ok_or_else(|| anyhow!("--origin is required"))?,
        cert_out: cert_out.ok_or_else(|| anyhow!("--cert-out is required"))?,
        ready_out: ready_out.ok_or_else(|| anyhow!("--ready-out is required"))?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = options()?;
    let edge = Transport::bind(
        TransportConfig::new(SecretKey::generate()).bind_addr("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .context("bind Connect edge transport")?;
    let backend = Transport::bind(
        TransportConfig::new(SecretKey::generate()).bind_addr("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .context("bind Connect service transport")?;
    let destination = DestinationId::udp(options.origin.port());
    backend
        .replace_policy(Policy {
            destinations: HashMap::from([(
                destination.clone(),
                DestinationPolicy {
                    target: Target::Udp(options.origin),
                    access: Access::Peers(HashSet::from([edge.endpoint_id()])),
                },
            )]),
        })
        .await
        .context("install test service policy")?;
    let details = backend.connection_details();
    let backend_addr = details.direct_addresses.iter().copied().fold(
        EndpointAddr::new(details.endpoint_id),
        EndpointAddr::with_ip_addr,
    );

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&options.cert_out, certified.cert.pem()).context("write test CA certificate")?;
    let tls = tls_config(
        vec![certified.cert.der().clone()],
        PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
    )?;
    let server = Server::bind(
        options.listen,
        tls,
        edge.clone(),
        vec![Route {
            target_host: options.origin.ip().to_string(),
            target_port: options.origin.port(),
            backend: backend_addr,
            destination: destination.clone(),
        }],
    )?;
    let public_addr = server.local_addr()?;
    std::fs::write(&options.ready_out, serde_json::to_vec_pretty(&serde_json::json!({
        "proxy_addr": public_addr.to_string(),
        "proxy_uri_template": format!("https://localhost:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/", public_addr.port()),
        "allowed_target": options.origin.to_string(),
        "service_endpoint": details.endpoint_id.to_string(),
    }))?).context("write readiness metadata")?;
    println!("MASQUE interop lab ready on {public_addr}");

    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal_cancel.cancel();
    });
    server.serve(cancel).await?;
    edge.shutdown().await;
    backend.shutdown().await;
    Ok(())
}
