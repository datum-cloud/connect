//! Bring up the VPC attachment's local interface and install its routes,
//! deliberately mirroring `wg-quick`'s shell approach (derive routes from the
//! allowed prefixes) rather than anything the kernel WireGuard module does.
//!
//! The mechanics are OS-specific — Linux uses iproute2 (`ip`), macOS uses
//! `ifconfig`/`route` (there is no `ip`), which is why the original issue's
//! reference point was a Mac. The tun crate abstracts the macOS `utun`
//! per-packet protocol header away, so the data plane is identical; only
//! addressing/routing differs. See design/vpc-attachment.md.

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
    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["link", "set", "dev", name, "mtu", &mtu.to_string()]).await?;
        run_cmd(
            "ip",
            &["-6", "addr", "add", &format!("{address}/{prefix_len}"), "dev", name],
        )
        .await?;
        run_cmd("ip", &["link", "set", "dev", name, "up"]).await?;
    }
    #[cfg(target_os = "macos")]
    {
        // MTU is set on the utun at creation (via the tun crate's Configuration);
        // macOS has no iproute2, so assign the address and bring it up with
        // ifconfig.
        //
        // Assign it as a host (/128), NOT the caller's subnet prefix. On macOS a
        // subnet prefix (e.g. /64) makes the kernel install a connected route
        // whose next hop is the utun's own link-local, and it then selects that
        // link-local as the source for any destination in that subnet — notably
        // the router's own tunnel address — which the router can't answer across
        // the tunnel. As a /128 there is no connected subnet route, so every VPC
        // address follows the explicit VPC-prefix route from install_routes with
        // the correct global source. The tunnel is point-to-point (one peer, the
        // router), so an on-link subnet on the interface isn't needed.
        let _ = (mtu, prefix_len);
        run_cmd(
            "ifconfig",
            &[name, "inet6", &address.to_string(), "prefixlen", "128"],
        )
        .await?;
        run_cmd("ifconfig", &[name, "up"]).await?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (name, address, prefix_len, mtu);
        n0_error::bail_any!("VPC interface configuration is only implemented for Linux and macOS");
    }
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
/// Routes are plain interface (`dev`) routes, exactly as `wg-quick` installs
/// AllowedIPs: there is only ever one peer on this interface (the galactic
/// router), so every packet the interface accepts goes to that router
/// regardless — a next-hop gateway would be redundant. The advertised
/// prefixes must genuinely cover the VPC addresses the client needs to reach;
/// a prefix that doesn't (e.g. a `/48` that doesn't contain the target `/64`
/// subnets) simply won't match and the destination is unreachable, which is a
/// configuration error, not a routing-layer one.
///
/// In `DefaultRoute` mode, before touching the default route, this pins an
/// explicit host route for the galactic router's own iroh path via the
/// pre-existing default gateway. Without this, the moment the split-default
/// routes point at the tun device, the iroh/QUIC traffic that carries this
/// very tunnel would get routed back into itself — wg-quick's own well-known
/// full-tunnel gotcha, encountered independently in the WireGuard-linux
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
                route_add_dev(prefix, name).await?;
            }
        }
        Mode::DefaultRoute => {
            if let Some(router_ip) = router_ip {
                if let Some((default_gw, iface)) = current_default_route().await? {
                    route_add_host_via(router_ip, &default_gw, &iface).await?;
                } else {
                    warn!(
                        "no existing default route found; skipping the router host-route pin — \
                         the VPC connection's own traffic may end up routed into itself once the \
                         split-default routes are installed"
                    );
                }
            }
            route_add_dev("::/1", name).await?;
            route_add_dev("8000::/1", name).await?;
        }
    }
    Ok(())
}

/// Adds an interface route for `prefix` (a CIDR like `fd00:cafe::/32`) out the
/// tunnel device.
async fn route_add_dev(prefix: &str, name: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["-6", "route", "add", prefix, "dev", name]).await
    }
    #[cfg(target_os = "macos")]
    {
        let (net, plen) = split_cidr(prefix)?;
        run_cmd(
            "route",
            &["-n", "add", "-inet6", "-prefixlen", &plen, &net, "-interface", name],
        )
        .await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (prefix, name);
        n0_error::bail_any!("VPC route installation is only implemented for Linux and macOS");
    }
}

/// Pins a host route for `host` via an existing `gateway` on `iface` — the
/// DefaultRoute-mode anti-loop pin for the router's own transport address.
async fn route_add_host_via(
    host: std::net::IpAddr,
    gateway: &str,
    iface: &str,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_cmd(
            "ip",
            &["-6", "route", "add", &format!("{host}/128"), "via", gateway, "dev", iface],
        )
        .await
    }
    #[cfg(target_os = "macos")]
    {
        let _ = iface; // the gateway determines the egress interface on macOS
        run_cmd("route", &["-n", "add", "-inet6", &host.to_string(), gateway]).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (host, gateway, iface);
        n0_error::bail_any!("host-route pinning is only implemented for Linux and macOS");
    }
}

/// The pre-existing IPv6 default route's `(gateway, interface)`, or `None`
/// when there is no default route to preserve.
async fn current_default_route() -> Result<Option<(String, String)>> {
    #[cfg(target_os = "linux")]
    {
        // `ip -6 route show default` → e.g. `default via fd00::1 dev eth0 metric 1024`.
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
        let (mut gateway, mut iface) = (None, None);
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
    #[cfg(target_os = "macos")]
    {
        // `route -n get -inet6 default` → lines incl. `  gateway: fd00::1` and
        // `  interface: en0`.
        let output = Command::new("route")
            .args(["-n", "get", "-inet6", "default"])
            .stdout(Stdio::piped())
            .output()
            .await
            .std_context("running `route -n get -inet6 default`")?;
        if !output.status.success() {
            return Ok(None);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let (mut gateway, mut iface) = (None, None);
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("gateway:") {
                gateway = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("interface:") {
                iface = Some(v.trim().to_string());
            }
        }
        Ok(gateway.zip(iface))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(None)
    }
}

/// Splits a CIDR string (`fd00:cafe::/32`) into `(network, prefix_len)`.
#[cfg(target_os = "macos")]
fn split_cidr(cidr: &str) -> Result<(String, String)> {
    match cidr.split_once('/') {
        Some((net, plen)) => Ok((net.to_string(), plen.to_string())),
        None => n0_error::bail_any!("expected a CIDR (addr/prefixlen), got {cidr:?}"),
    }
}

/// Runs `program args…`, surfacing stderr on failure. Never attempts to
/// elevate privileges itself (no hardcoded `sudo`, no re-exec-as-root) — if
/// the command needs root/CAP_NET_ADMIN and doesn't have it, the failure is
/// reported with a pointer at what's missing, and it's up to the caller to
/// supply that privilege (e.g. by running this process under `sudo`).
async fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let cmd = format!("{program} {}", args.join(" "));
    info!(cmd = %cmd, "running");
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .std_context(format!("spawning `{program}` — is it installed and on PATH?"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let low = stderr.to_ascii_lowercase();
        if low.contains("operation not permitted") || low.contains("not permitted") {
            n0_error::bail_any!(
                "`{cmd}` failed ({}): {stderr}. This needs root/CAP_NET_ADMIN — re-run under \
                 sudo (or grant the capability); this will not elevate privileges itself.",
                output.status
            );
        }
        n0_error::bail_any!("`{cmd}` failed ({}): {stderr}", output.status);
    }
    Ok(())
}
