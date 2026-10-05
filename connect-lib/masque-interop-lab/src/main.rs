//! Local independent-client lab using the reusable CONNECT-UDP and CONNECT-IP edge.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use connect_masque_edge::{
    BearerCredential, ClientAuthentication, IpRoute, Ipv4RouteRange, Route, Server, ServerOptions,
    tls_config,
};
use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig, ip,
};
use iroh::{EndpointAddr, SecretKey};
use rustls::pki_types::PrivateKeyDer;
use tokio_util::sync::CancellationToken;

const IP_PATH: &str = "/.well-known/masque/ip/*/*/";
const IP_NETWORK: &str = "masque-interop";
const IP_ASSIGNED: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
const IP_REMOTE: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 9);
const TEST_BEARER_TOKEN: &str = "datum-masque-interop-client-token-00000001";

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

    let mut ip_registration = backend
        .register_ip_grant(ip::Grant {
            peer: edge.endpoint_id(),
            network: IP_NETWORK.into(),
            address: IpAddr::V4(IP_ASSIGNED),
            routes: vec!["10.30.0.9/32".parse()?],
            mtu: 1280,
        })
        .await
        .context("install test CONNECT-IP grant")?;
    tokio::spawn(async move {
        while let Some(incoming) = ip_registration.recv().await {
            if incoming.ready.send(true).is_err() {
                continue;
            }
            tokio::spawn(async move {
                while let Some(packet) = incoming.session.recv().await {
                    let Some(reply) = reverse_ipv4_packet(packet) else {
                        continue;
                    };
                    if incoming.session.send(reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&options.cert_out, certified.cert.pem()).context("write test CA certificate")?;
    let tls = tls_config(
        vec![certified.cert.der().clone()],
        PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
    )?;
    let advertised_route = Ipv4RouteRange {
        start: IP_REMOTE,
        end: IP_REMOTE,
        protocol: 0,
    };
    let client_authentication = ClientAuthentication::bearer(vec![BearerCredential::new(
        "independent-masque-client".into(),
        TEST_BEARER_TOKEN.as_bytes(),
        vec![(options.origin.ip().to_string(), options.origin.port())],
        vec![("*".into(), "*".into())],
    )?])?;
    let denied_target_port = if options.origin.port() == u16::MAX {
        options.origin.port() - 1
    } else {
        options.origin.port() + 1
    };
    let server = Server::bind_with_options_and_ip_routes(
        options.listen,
        tls,
        edge.clone(),
        vec![
            Route {
                target_host: options.origin.ip().to_string(),
                target_port: options.origin.port(),
                backend: backend_addr.clone(),
                destination: destination.clone(),
            },
            // This route is deliberately real but absent from the test
            // client's grants, proving authorization is per route.
            Route {
                target_host: options.origin.ip().to_string(),
                target_port: denied_target_port,
                backend: backend_addr.clone(),
                destination: destination.clone(),
            },
        ],
        vec![IpRoute {
            target: "*".into(),
            protocol: "*".into(),
            backend: backend_addr,
            network: IP_NETWORK.into(),
            assigned_address: IP_ASSIGNED,
            route_updates: vec![
                vec![advertised_route.clone()],
                vec![],
                vec![advertised_route],
            ],
        }],
        ServerOptions::authenticated(client_authentication),
    )?;
    let public_addr = server.local_addr()?;
    std::fs::write(
        &options.ready_out,
        serde_json::to_vec_pretty(&serde_json::json!({
            "proxy_addr": public_addr.to_string(),
            "proxy_uri_template": format!("https://localhost:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/", public_addr.port()),
            "allowed_target": options.origin.to_string(),
            "denied_target": format!("{}:{denied_target_port}", options.origin.ip()),
            "ip_uri": format!("https://localhost:{}{IP_PATH}", public_addr.port()),
            "ip_assigned": IP_ASSIGNED.to_string(),
            "ip_remote": IP_REMOTE.to_string(),
            "service_endpoint": details.endpoint_id.to_string(),
            "bearer_token": TEST_BEARER_TOKEN,
        }))?,
    )
    .context("write readiness metadata")?;
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

fn reverse_ipv4_packet(packet: Bytes) -> Option<Bytes> {
    if packet.len() < 20 || packet[0] != 0x45 {
        return None;
    }
    let mut bytes = packet.to_vec();
    let source = <[u8; 4]>::try_from(&bytes[12..16]).ok()?;
    let destination = <[u8; 4]>::try_from(&bytes[16..20]).ok()?;
    bytes[12..16].copy_from_slice(&destination);
    bytes[16..20].copy_from_slice(&source);
    bytes[10..12].fill(0);
    let mut sum: u32 = bytes[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    bytes[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Some(Bytes::from(bytes))
}
