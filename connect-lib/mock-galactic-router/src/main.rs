//! Stands in for the imagined galactic-side router component (see
//! `design/vpc-attachment.md` §5) for containerlab e2e testing of the
//! `vpc` verb's data-plane mechanism only — no VRF/BGP/eBPF, just an iroh
//! dial-in target with its own TUN device on the "VPC side" of the tunnel,
//! sharing the exact same framing/pump implementation
//! (`connect_lib::vpc`'s `VpcDialer` + `write_frame`/`read_frame`) that a
//! real router would use.
//!
//! Supports N clients: each `--peer-id` gets a sequentially allocated
//! address from `--pool`, and a per-client task bridges frames between the
//! client's iroh stream and the shared TUN device. The TUN reader parses
//! each outbound packet's IPv6 destination (bytes 24..40) and routes it to
//! the matching client's sender.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use connect_lib::{
    Assignment, Config, VpcDialer, build_endpoint, read_frame, vpc_configure_interface,
    vpc_create_tun_device, write_frame,
};
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use n0_error::{Result, StdResultExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

#[derive(Parser, Debug)]
#[command(
    name = "mock-galactic-router",
    about = "Test-only stand-in for a galactic VPC router — see design/vpc-attachment.md"
)]
struct Args {
    /// iroh EndpointId(s) of the `vpc join` clients to dial (repeatable).
    #[clap(long, required = true)]
    peer_id: Vec<String>,
    /// Optional direct socket address (ip:port) to pin for a single client,
    /// bypassing discovery. Only useful for an offline/same-host lab with
    /// one client; ignored when dialing multiple peers.
    #[clap(long)]
    peer_addr: Option<SocketAddr>,
    /// The router's own address within the pool. Must be inside `--pool`.
    #[clap(long)]
    address: Ipv6Addr,
    /// Client address pool CIDR (e.g. `fd00:cafe:1100::/64`). Clients are
    /// allocated sequentially starting at `::2`.
    #[clap(long)]
    pool: String,
    /// VPC prefix to advertise to clients (repeatable). Sent as
    /// `Assignment.vpc_prefixes`.
    #[clap(long)]
    advertise: Vec<String>,
    #[clap(long, default_value = "mock-vpc0")]
    tun_name: String,
    #[clap(long, default_value_t = 1280)]
    mtu: u16,
}

/// Parses a CIDR into (network base address, prefix_len).
fn parse_pool(cidr: &str) -> Result<(Ipv6Addr, u8)> {
    let (net_str, plen_str) = cidr
        .split_once('/')
        .ok_or_else(|| n0_error::anyerr!("--pool must be a CIDR (e.g. fd00:cafe:1100::/64), got {cidr:?}"))?;
    let base = Ipv6Addr::from_str(net_str).std_context("parsing pool network address")?;
    let plen: u8 = plen_str.parse().std_context("parsing pool prefix length")?;
    Ok((base, plen))
}

/// Returns the Nth address in the pool (N=1 → `::1`, N=2 → `::2`, …).
fn pool_nth(base: Ipv6Addr, n: u128) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(base) + n)
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("mock-galactic-router: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();

    let args = Args::parse();
    let peer_ids: Vec<EndpointId> = args
        .peer_id
        .iter()
        .map(|s| EndpointId::from_str(s).std_context("parsing --peer-id as an endpoint id"))
        .collect::<Result<Vec<_>>>()?;

    let (pool_base, pool_plen) = parse_pool(&args.pool)?;

    let tun = vpc_create_tun_device(&args.tun_name, args.mtu)?;
    let ifname = connect_lib::vpc_device_name(&tun)?;
    vpc_configure_interface(&ifname, args.address, pool_plen, args.mtu).await?;
    let (tun_writer, tun_reader) = tun.split().std_context("splitting tun device")?;
    let tun_writer = Arc::new(Mutex::new(tun_writer));
    let tun_reader = Arc::new(Mutex::new(tun_reader));

    let secret_key = SecretKey::generate();
    let endpoint = build_endpoint(secret_key, &Config::default()).await?;

    eprintln!("mock-galactic-router: endpoint id {}", endpoint.id());
    eprintln!(
        "mock-galactic-router: interface {} up at {} — pool {} — {} client(s)",
        ifname,
        args.address,
        args.pool,
        peer_ids.len()
    );

    let dialer = VpcDialer::new(endpoint);

    // Per-client state: addr → mpsc sender for TUN→client delivery.
    let client_senders: Arc<Mutex<HashMap<Ipv6Addr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut client_handles = Vec::new();

    for (i, peer_id) in peer_ids.iter().enumerate() {
        let client_addr = pool_nth(pool_base, (i as u128) + 2);
        let assignment = Assignment {
            address: client_addr,
            prefix_len: pool_plen,
            vpc_prefixes: args.advertise.clone(),
        };

        let mut remote = EndpointAddr::from(*peer_id);
        if peer_ids.len() == 1 {
            if let Some(addr) = args.peer_addr {
                remote.addrs.insert(TransportAddr::Ip(addr));
            }
        }

        eprintln!(
            "mock-galactic-router: dialing peer {} → assigned {}",
            peer_id.fmt_short(),
            client_addr
        );

        let (net_send, net_recv) = dialer
            .dial_and_send_assignment(remote, &assignment)
            .await?;

        // Per-client channel: TUN reader will send packets destined for
        // this client's address here.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        {
            let mut map = client_senders.lock().await;
            map.insert(client_addr, tx);
        }

        let tun_writer_clone = tun_writer.clone();

        // Per-client task: drain mpsc → write_frame to client stream;
        // read_frame from client stream → write to shared TUN.
        let handle = tokio::spawn(async move {
            let net_send = Arc::new(Mutex::new(net_send));
            let net_recv = Arc::new(Mutex::new(net_recv));

            let send_task = {
                let net_send = net_send.clone();
                async move {
                    while let Some(pkt) = rx.recv().await {
                        let mut w = net_send.lock().await;
                        if let Err(e) = write_frame(&mut *w, &pkt).await {
                            tracing::warn!(client = %client_addr, "write to client failed: {e}");
                            break;
                        }
                    }
                }
            };

            let recv_task = {
                let tun_writer = tun_writer_clone;
                async move {
                    let mut r = net_recv.lock().await;
                    loop {
                        match read_frame(&mut *r).await {
                            Ok(Some(pkt)) => {
                                let mut w = tun_writer.lock().await;
                                if let Err(e) = w.write_all(&pkt).await {
                                    tracing::warn!(client = %client_addr, "write to tun failed: {e}");
                                    break;
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::warn!(client = %client_addr, "read from client failed: {e}");
                                break;
                            }
                        }
                    }
                }
            };

            tokio::select! {
                _ = send_task => {}
                _ = recv_task => {}
            }
        });

        client_handles.push(handle);
    }

    eprintln!(
        "mock-galactic-router: all {} client(s) dialed — starting TUN demux",
        client_handles.len()
    );

    // TUN reader task: parse each outbound packet's IPv6 destination and
    // route it to the matching client's mpsc sender.
    let mtu = args.mtu as usize;
    let tun_demux = tokio::spawn(async move {
        let mut reader = tun_reader.lock().await;
        let mut buf = vec![0u8; mtu];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("tun read error: {e}");
                    break;
                }
            };
            let pkt = match buf.get(..n) {
                Some(p) => p,
                None => continue,
            };
            // IPv6 destination is bytes 24..40 of the packet.
            if n < 40 {
                continue;
            }
            let dst_bytes: [u8; 16] = match pkt.get(24..40) {
                Some(s) => match s.try_into() {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                None => continue,
            };
            let dst = Ipv6Addr::from(dst_bytes);

            let senders = client_senders.lock().await;
            if let Some(tx) = senders.get(&dst) {
                let _ = tx.try_send(pkt.to_vec());
            }
            // Unknown destination: dropped (e.g. multicast, router-local).
        }
    });

    // Wait for Ctrl+C or all clients to disconnect.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("mock-galactic-router: shutting down");
        }
        _ = async {
            for h in client_handles {
                let _ = h.await;
            }
        } => {
            eprintln!("mock-galactic-router: all clients disconnected");
        }
    }

    tun_demux.abort();
    Ok(())
}
