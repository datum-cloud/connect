//! `ip`-command wrappers for wiring up the VPC attachment's local interface,
//! deliberately mirroring `wg-quick`'s own approach rather than the kernel
//! WireGuard module's: the `tun` crate's own address/netmask configuration
//! is IPv4-shaped and not something to fight for an IPv6-only gVPC (see the
//! originating issue), and routing here needs the same "derive routes from
//! AllowedIPs" logic `wg-quick` implements in its shell script, not
//! anything the kernel driver itself does. See design/vpc-attachment.md.

use std::net::Ipv6Addr;
use std::process::Stdio;

use n0_error::{Result, StdResultExt};
use tokio::process::Command;
use tracing::{info, warn};

use super::Mode;

/// Assigns the interface's address and brings it up. Split from route
/// installation below so callers can configure the interface before it
/// carries any traffic, then decide routes once the attachment's mode is
/// known.
pub async fn configure_interface(
    name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
    mtu: u16,
) -> Result<()> {
    run_ip(&["link", "set", "dev", name, "mtu", &mtu.to_string()]).await?;
    run_ip(&[
        "-6",
        "addr",
        "add",
        &format!("{address}/{prefix_len}"),
        "dev",
        name,
    ])
    .await?;
    run_ip(&["link", "set", "dev", name, "up"]).await?;
    Ok(())
}

/// Installs routes for `mode` — the single-peer collapse of WireGuard's
/// AllowedIPs (exactly one remote peer here, the galactic router, so this is
/// a mode toggle rather than a routing policy trie):
///
/// - `VpcOnly`: only the VPC's own advertised prefixes are routed through
///   the interface.
/// - `DefaultRoute`: uses wg-quick's `::/1` + `8000::/1` split instead of
///   replacing `::/0` outright, so a lower-metric, more-specific pair of
///   routes wins over the real default without literally removing it.
///
/// Before touching the default route, this pins an explicit host route for
/// the galactic router's own iroh path via the pre-existing default gateway.
/// Without this, the moment the split-default routes point at the tun
/// device, the iroh/QUIC traffic that carries this very tunnel would get
/// routed back into itself — this is wg-quick's own well-known gotcha for
/// full-tunnel configs, encountered independently in the WireGuard-linux
/// research this feature is based on.
pub async fn install_routes(
    name: &str,
    mode: Mode,
    vpc_prefixes: &[String],
    router_ip: Option<std::net::IpAddr>,
) -> Result<()> {
    match mode {
        Mode::VpcOnly => {
            for prefix in vpc_prefixes {
                run_ip(&["-6", "route", "add", prefix, "dev", name]).await?;
            }
        }
        Mode::DefaultRoute => {
            if let Some(router_ip) = router_ip {
                if let Some((gateway, iface)) = current_default_route().await? {
                    run_ip(&[
                        "-6",
                        "route",
                        "add",
                        &format!("{router_ip}/128"),
                        "via",
                        &gateway,
                        "dev",
                        &iface,
                    ])
                    .await?;
                } else {
                    warn!(
                        "no existing default route found; skipping the router host-route pin — \
                         the VPC connection's own traffic may end up routed into itself once the \
                         split-default routes are installed"
                    );
                }
            }
            run_ip(&["-6", "route", "add", "::/1", "dev", name]).await?;
            run_ip(&["-6", "route", "add", "8000::/1", "dev", name]).await?;
        }
    }
    Ok(())
}

/// Parses `ip -6 route show default`'s first line for the gateway/interface
/// pair, e.g. `default via fd00::1 dev eth0 metric 1024`. Returns `None`
/// when there is no existing default route to preserve (nothing to pin).
async fn current_default_route() -> Result<Option<(String, String)>> {
    let output = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .stdout(Stdio::piped())
        .output()
        .await
        .std_context("running `ip -6 route show default`")?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first_line = text.lines().next().unwrap_or_default();
    let mut gateway = None;
    let mut iface = None;
    let mut tokens = first_line.split_whitespace();
    while let Some(tok) = tokens.next() {
        match tok {
            "via" => gateway = tokens.next().map(str::to_string),
            "dev" => iface = tokens.next().map(str::to_string),
            _ => {}
        }
    }
    Ok(gateway.zip(iface))
}

/// Runs `ip <args>`, surfacing its stderr on failure. This never attempts to
/// elevate privileges itself (no hardcoded `sudo`, no re-exec-as-root) — if
/// `ip` needs `CAP_NET_ADMIN` and doesn't have it, the failure is reported
/// with a pointer at what's missing, and it's up to the caller to supply
/// that privilege (e.g. by running this process under `sudo` themselves).
async fn run_ip(args: &[&str]) -> Result<()> {
    let cmd = format!("ip {}", args.join(" "));
    info!(cmd = %cmd, "running");
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .std_context("spawning `ip` — is iproute2 installed and on PATH?")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.to_ascii_lowercase().contains("operation not permitted") {
            n0_error::bail_any!(
                "`{cmd}` failed ({}): {stderr}. This needs CAP_NET_ADMIN — re-run as root or \
                 with that capability granted; this will not attempt to elevate privileges \
                 itself.",
                output.status
            );
        }
        n0_error::bail_any!("`{cmd}` failed ({}): {stderr}", output.status);
    }
    Ok(())
}
