//! `datum-connect vpc join` — the data-plane half of the `vpc` verb.
//!
//! This is scaffolding ahead of the real galactic-side control plane: it
//! takes the VPC attachment's address/prefixes/mode/router-identity as
//! explicit flags rather than resolving them from a `VPCAttachment` CRD
//! (see `design/vpc-attachment.md`), so the data-plane mechanism — TUN
//! creation, the iroh accept handshake, packet framing, and routing-mode
//! installation — is provable in the containerlab lab ahead of that
//! control-plane wiring landing. The CRD type already exists
//! (`connect_lib::datum_apis::vpc_attachment`); wiring `vpc join` to poll it
//! instead of taking these as flags is the natural next step once a real
//! galactic-side router exists to populate its status.

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use clap::ValueEnum;
use connect_lib::{Repo, VpcListener, VpcMode};
use iroh::EndpointId;
use n0_error::{Result, StdResultExt};
use tokio::sync::Mutex;

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ModeArg {
    VpcOnly,
    DefaultRoute,
}

impl From<ModeArg> for VpcMode {
    fn from(v: ModeArg) -> Self {
        match v {
            ModeArg::VpcOnly => VpcMode::VpcOnly,
            ModeArg::DefaultRoute => VpcMode::DefaultRoute,
        }
    }
}

pub struct JoinArgs {
    /// Label only, for now — see module docs on the CRD not being consulted yet.
    pub vpc: String,
    /// iroh EndpointId of the galactic router allowed to dial in. `None`
    /// means accept any dialer — trust-on-first-connect, only ever
    /// appropriate before a real control plane fills this in from
    /// `VPCAttachmentStatus::router_endpoint_id` (see
    /// `connect_lib::vpc::VpcAcceptHandler`'s docs).
    pub router_id: Option<String>,
    pub address: String,
    pub prefix_len: u8,
    pub tun_name: String,
    pub mtu: u16,
    pub mode: ModeArg,
    pub vpc_prefix: Vec<String>,
    pub router_ip: Option<IpAddr>,
    pub json: bool,
}

pub async fn run_join(repo: Repo, args: JoinArgs) -> Result<()> {
    let router_id = args
        .router_id
        .as_deref()
        .map(EndpointId::from_str)
        .transpose()
        .std_context("parsing --router-id as an iroh endpoint id")?;
    if router_id.is_none() {
        eprintln!(
            "  \u{26A0} No --router-id set — accepting any dialer (trust-on-first-connect). \
             This is only appropriate for lab/dev use; see design/vpc-attachment.md."
        );
    }
    let address = Ipv6Addr::from_str(&args.address)
        .std_context("parsing --address as an IPv6 address")?;

    let tun = connect_lib::vpc_create_tun_device(&args.tun_name, args.mtu)?;
    // Use the kernel-assigned name (macOS renames to utunN) for all
    // interface/route configuration, not the requested name.
    let ifname = connect_lib::vpc_device_name(&tun)?;
    connect_lib::vpc_configure_interface(&ifname, address, args.prefix_len, args.mtu).await?;
    let (tun_writer, tun_reader) = tun.split().std_context("splitting tun device")?;
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    let secret_key = iroh::SecretKey::generate();
    let listener = VpcListener::bind(
        &repo,
        secret_key,
        router_id,
        tun_reader,
        tun_writer,
        args.mtu as usize,
    )
    .await?;

    let mode: VpcMode = args.mode.into();
    connect_lib::vpc_install_routes(&ifname, mode, &args.vpc_prefix, args.router_ip).await?;

    let endpoint_id = listener.endpoint_id();
    // Bound direct addresses — a router with no discovery/relay path (e.g.
    // the containerlab mock router, or any deployment dialing by known
    // direct address rather than through Datum's relays) needs one of
    // these for `--peer-addr`/its NodeAddr construction.
    let bound_addrs: Vec<String> = listener
        .endpoint()
        .bound_sockets()
        .iter()
        .map(std::net::SocketAddr::to_string)
        .collect();
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "type": "vpc_ready",
                "vpc": args.vpc,
                "endpoint_id": endpoint_id.to_string(),
                "bound_addrs": bound_addrs,
                "address": address.to_string(),
                "tun_name": ifname,
                "mode": args.mode.to_possible_value().map(|v| v.get_name().to_string()),
            })
        );
    } else {
        eprintln!(
            "  \u{25CB} Interface {} up at {} (mtu {})",
            ifname, address, args.mtu
        );
        eprintln!("  \u{25CB} Listening on: {}", bound_addrs.join(", "));
        match &args.router_id {
            Some(id) => eprintln!(
                "  \u{25CB} Your endpoint ID: {endpoint_id} — waiting for router {id} to connect"
            ),
            None => eprintln!(
                "  \u{25CB} Your endpoint ID: {endpoint_id} — waiting for any router to connect"
            ),
        }
        eprintln!("VPC attachment ready. Press Ctrl+C to stop...");
    }

    tokio::signal::ctrl_c()
        .await
        .std_context("waiting for ctrl-c")?;
    listener.shutdown().await?;
    Ok(())
}
