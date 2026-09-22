//! Stands in for the imagined galactic-side router component (see
//! `design/vpc-attachment.md` §5) for containerlab e2e testing of the
//! `vpc` verb's data-plane mechanism only — no VRF/BGP/eBPF, just an iroh
//! dial-in target with its own TUN device on the "VPC side" of the tunnel,
//! sharing the exact same framing/pump implementation
//! (`connect_lib::vpc`'s `VpcDialer`) that a real router would use.
//!
//! Dials the client directly by IP (no relay, no DNS discovery) — fine for
//! a shared containerlab network segment, not representative of how a real
//! deployment (behind NAT, using Datum's relays) would connect.

use std::net::{Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use connect_lib::{VpcDialer, vpc_configure_interface, vpc_create_tun_device};
use iroh::{
    EndpointAddr, EndpointId, SecretKey, TransportAddr,
    endpoint::{Builder, RelayMode},
};
use n0_error::{Result, StdResultExt};
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(
    name = "mock-galactic-router",
    about = "Test-only stand-in for a galactic VPC router — see design/vpc-attachment.md"
)]
struct Args {
    /// iroh EndpointId of the `vpc join` client to dial (printed by
    /// `datum-connect vpc join` as "Your endpoint ID").
    #[clap(long)]
    peer_id: String,
    /// Direct socket address (ip:port) to dial the client at.
    #[clap(long)]
    peer_addr: SocketAddr,
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
    vpc_configure_interface(&args.tun_name, args.address, args.prefix_len, args.mtu).await?;
    let (tun_writer, tun_reader) = tun.split().std_context("splitting tun device")?;
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let secret_key = SecretKey::generate();
    let endpoint = Builder::empty()
        .crypto_provider(crypto_provider)
        .relay_mode(RelayMode::Disabled)
        .secret_key(secret_key)
        .bind()
        .await
        .std_context("binding mock router iroh endpoint")?;

    eprintln!("mock-galactic-router: endpoint id {}", endpoint.id());
    eprintln!(
        "mock-galactic-router: interface {} up at {} — dialing {peer_id} at {}",
        args.tun_name, args.address, args.peer_addr
    );

    let dialer = VpcDialer::new(endpoint);
    let remote = EndpointAddr {
        id: peer_id,
        addrs: [TransportAddr::Ip(args.peer_addr)].into_iter().collect(),
    };

    dialer
        .dial_and_pump(remote, tun_reader, tun_writer, args.mtu as usize)
        .await?;
    Ok(())
}
