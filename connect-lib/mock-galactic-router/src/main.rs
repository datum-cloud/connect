//! Stands in for the imagined galactic-side router component (see
//! `design/vpc-attachment.md` §5) for containerlab e2e testing of the
//! `vpc` verb's data-plane mechanism only — no VRF/BGP/eBPF, just an iroh
//! dial-in target with its own TUN device on the "VPC side" of the tunnel,
//! sharing the exact same framing/pump implementation
//! (`connect_lib::vpc`'s `VpcDialer`) that a real router would use.
//!
//! Dials the client by iroh `EndpointId` alone — no IP/port — using the same
//! relay + discovery configuration `connect-lib` gives every client
//! (`build_endpoint`), so iroh resolves and connects to the endpoint exactly
//! as a real deployment would. `--peer-addr` is optional and only pins a
//! direct address for an offline/same-host lab where discovery isn't wanted.

use std::net::{Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use connect_lib::{Config, VpcDialer, build_endpoint, vpc_configure_interface, vpc_create_tun_device};
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use n0_error::{Result, StdResultExt};
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(
    name = "mock-galactic-router",
    about = "Test-only stand-in for a galactic VPC router — see design/vpc-attachment.md"
)]
struct Args {
    /// iroh EndpointId of the `vpc join` client to dial (printed by
    /// `datum-connect vpc join` as the endpoint id). This is all that's
    /// needed — iroh discovery resolves how to reach it.
    #[clap(long)]
    peer_id: String,
    /// Optional direct socket address (ip:port) to pin for the client,
    /// bypassing discovery. Only useful for an offline/same-host lab; omit
    /// it to dial purely by endpoint id like a real deployment.
    #[clap(long)]
    peer_addr: Option<SocketAddr>,
    /// This router's own address on the VPC side of the tunnel. Use the
    /// same prefix as the client's `--address`/`--prefix-len` so both ends
    /// pick up an on-link route to each other automatically.
    #[clap(long)]
    address: Ipv6Addr,
    #[clap(long, default_value_t = 120)]
    prefix_len: u8,
    #[clap(long, default_value = "mock-vpc0")]
    tun_name: String,
    #[clap(long, default_value_t = 1280)]
    mtu: u16,
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
    let peer_id =
        EndpointId::from_str(&args.peer_id).std_context("parsing --peer-id as an endpoint id")?;

    let tun = vpc_create_tun_device(&args.tun_name, args.mtu)?;
    let ifname = connect_lib::vpc_device_name(&tun)?;
    vpc_configure_interface(&ifname, args.address, args.prefix_len, args.mtu).await?;
    let (tun_writer, tun_reader) = tun.split().std_context("splitting tun device")?;
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    // Same relay + discovery config every connect-lib client gets, so the
    // client is resolvable by endpoint id and the two share a relay network.
    let secret_key = SecretKey::generate();
    let endpoint = build_endpoint(secret_key, &Config::default()).await?;

    // Dial by endpoint id; add a direct address only if one was pinned.
    let mut remote = EndpointAddr::from(peer_id);
    if let Some(addr) = args.peer_addr {
        remote.addrs.insert(TransportAddr::Ip(addr));
    }

    eprintln!("mock-galactic-router: endpoint id {}", endpoint.id());
    match args.peer_addr {
        Some(addr) => eprintln!(
            "mock-galactic-router: interface {} up at {} — dialing {peer_id} (pinned addr {addr})",
            ifname, args.address
        ),
        None => eprintln!(
            "mock-galactic-router: interface {} up at {} — dialing {peer_id} via discovery",
            ifname, args.address
        ),
    }

    let dialer = VpcDialer::new(endpoint);
    dialer
        .dial_and_pump(remote, tun_reader, tun_writer, args.mtu as usize)
        .await?;
    Ok(())
}
