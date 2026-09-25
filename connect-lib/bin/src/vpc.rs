//! `datum-connect vpc join` — the data-plane half of the `vpc` verb.
//!
//! This is scaffolding ahead of the real galactic-side control plane: it
//! takes the VPC attachment's mode/router-identity as explicit flags rather
//! than resolving them from a `VPCAttachment` CRD (see
//! `design/vpc-attachment.md`), so the data-plane mechanism — TUN creation,
//! the iroh accept handshake, assignment reception, and routing-mode
//! installation — is provable in the containerlab lab ahead of that
//! control-plane wiring landing. The address and VPC prefixes are now
//! **allocated by the router** and received as an `Assignment` frame on the
//! iroh stream before packet pumping begins. The CRD type already exists
//! (`connect_lib::datum_apis::vpc_attachment`); wiring `vpc join` to poll it
//! instead of taking these as flags is the natural next step once a real
//! galactic-side router exists to populate its status.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use clap::ValueEnum;
use connect_lib::{Assignment, OnAssignFn, Repo, VpcListener, VpcMode};
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
    pub tun_name: String,
    pub mtu: u16,
    pub mode: ModeArg,
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

    let tun = connect_lib::vpc_create_tun_device(&args.tun_name, args.mtu)?;
    let ifname = connect_lib::vpc_device_name(&tun)?;
    // TUN is created but NOT addressed — the router's Assignment supplies
    // the address, prefix, and VPC prefixes. Configuration happens in the
    // on_assign callback below, before packet pumping starts.
    let (tun_writer, tun_reader) = tun.split().std_context("splitting tun device")?;
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    let mode: VpcMode = args.mode.into();
    let mtu = args.mtu;
    let router_ip = args.router_ip;
    let ifname_for_assign = ifname.clone();

    // Channel to deliver the router-assigned address back to run_join.
    let (assign_tx, assign_rx) = tokio::sync::oneshot::channel::<Assignment>();
    let assign_tx = Arc::new(std::sync::Mutex::new(Some(assign_tx)));

    let on_assign: OnAssignFn = Arc::new(move |assignment: Assignment| {
        let ifname = ifname_for_assign.clone();
        let assign_tx = assign_tx.clone();
        let vpc_prefixes = assignment.vpc_prefixes.clone();
        let address = assignment.address;
        let prefix_len = assignment.prefix_len;
        Box::pin(async move {
            connect_lib::vpc_configure_interface(&ifname, address, prefix_len, mtu)
                .await
                .map_err(|e| std::io::Error::other(format!("configure interface: {e}")))?;
            connect_lib::vpc_install_routes(&ifname, mode, &vpc_prefixes, router_ip)
                .await
                .map_err(|e| std::io::Error::other(format!("install routes: {e}")))?;
            if let Ok(mut guard) = assign_tx.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(assignment);
                }
            }
            Ok(())
        })
    });

    let secret_key = iroh::SecretKey::generate();
    let listener = VpcListener::bind(
        &repo,
        secret_key,
        router_id,
        tun_reader,
        tun_writer,
        args.mtu as usize,
        Some(on_assign),
    )
    .await?;

    let endpoint_id = listener.endpoint_id();
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
                "type": "vpc_listening",
                "vpc": args.vpc,
                "endpoint_id": endpoint_id.to_string(),
                "bound_addrs": bound_addrs,
                "tun_name": ifname,
            })
        );
    } else {
        eprintln!(
            "  \u{25CB} Interface {} created (unaddressed, mtu {}) — waiting for router assignment",
            ifname, args.mtu
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
    }

    // Wait for the router to dial in and send the assignment.
    let assignment = assign_rx
        .await
        .map_err(|_| n0_error::anyerr!("on_assign callback was never invoked — router did not connect"))?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "type": "vpc_ready",
                "vpc": args.vpc,
                "endpoint_id": endpoint_id.to_string(),
                "bound_addrs": bound_addrs,
                "address": assignment.address.to_string(),
                "tun_name": ifname,
                "mode": args.mode.to_possible_value().map(|v| v.get_name().to_string()),
            })
        );
    } else {
        eprintln!(
            "  \u{2713} Router assigned address {} (/{}) — interface {} configured",
            assignment.address, assignment.prefix_len, ifname
        );
        eprintln!("VPC attachment ready. Press Ctrl+C to stop...");
    }

    tokio::signal::ctrl_c()
        .await
        .std_context("waiting for ctrl-c")?;
    listener.shutdown().await?;
    Ok(())
}
