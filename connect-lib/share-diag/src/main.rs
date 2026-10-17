//! Test share for Datum Compute, in one process with no child processes, so
//! it runs on unikernel instances.
//!
//! Shares a live diagnostics page with `connect_share::share` as an
//! in-process target: tunneled sessions are handed straight to the page's
//! HTTP server, with no listening socket. Unikernels may have no loopback
//! interface, so a process cannot reach its own TCP port there. The ticket and the pairing and path
//! events are printed to stdout, so `datumctl compute logs` shows them.
//! Nothing listens on a public address.
//!
//! Optional environment: SHARE_NAME, and DATUM_ACCOUNT, DATUM_ORG,
//! DATUM_PROJECT, WORKLOAD, LOCATION, RUNTIME, which only label the page.
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{Router, response::Html, routing::get};
use connect_share::{
    PathInfo, PathKind, ShareEvent, ShareOptions, ShareTarget, ShareTicket, share,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const VERSION: &str = match option_env!("DATUM_CONNECT_RELEASE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Default)]
struct State {
    phase: String,
    ticket: Option<ShareTicket>,
    paired: Vec<(Instant, String, String)>,
    paths: BTreeMap<String, (Instant, PathInfo)>,
    events: Vec<(SystemTime, String)>,
    probes: Vec<(String, String)>,
    self_checks: Vec<(String, String)>,
    probed_at: Option<Instant>,
}

type Shared = Arc<Mutex<State>>;

fn log(message: &str) {
    println!("{} {message}", clock(SystemTime::now()));
}

fn clock(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!(
        "{:02}:{:02}:{:02}Z",
        secs / 3600 % 24,
        secs / 60 % 60,
        secs % 60
    )
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| "?".into())
}

#[tokio::main]
async fn main() {
    let name = std::env::var("SHARE_NAME").unwrap_or_else(|_| "Datum Compute test".into());
    let started = Instant::now();
    let state: Shared = Arc::new(Mutex::new(State {
        phase: "starting".into(),
        ..State::default()
    }));
    log(&format!("Datum Connect diagnostics {VERSION}: {name}"));
    // Confirm why localhost fails here: check, bring lo up the way
    // `ip link set lo up` does, and check again.
    let mut checks = vec![("lo before".to_string(), loopback_state())];
    checks.extend(self_checks("before bringing lo up").await);
    let up = match bring_up_loopback() {
        Ok(()) => "set IFF_UP on lo".to_string(),
        Err(error) => format!("failed: {error}"),
    };
    log(&format!("bring up lo: {up}"));
    checks.push(("Bring up lo".to_string(), up));
    tokio::time::sleep(Duration::from_millis(500)).await;
    checks.push(("lo after".to_string(), loopback_state()));
    checks.extend(self_checks("after bringing lo up").await);
    set(&state, |s| s.self_checks = checks);

    let app = Router::new()
        .route("/health", get(|| async { "ok\n" }))
        .route(
            "/",
            get({
                let state = state.clone();
                let name = name.clone();
                move || {
                    let state = state.clone();
                    let name = name.clone();
                    async move { Html(page(&state, &name, started)) }
                }
            }),
        );
    // Each tunneled session arrives here as a stream; serve HTTP/1.1 on it.
    let (streams, mut incoming) = mpsc::channel::<connect_share::LocalStream>(64);
    tokio::spawn(async move {
        while let Some(stream) = incoming.recv().await {
            let service = hyper_util::service::TowerToHyperService::new(app.clone());
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    tokio::spawn(probe(state.clone()));

    loop {
        set(&state, |s| s.phase = "sharing".into());
        let options = ShareOptions {
            target: ShareTarget::InProcess {
                port: 80,
                streams: streams.clone(),
            },
            relay_urls: None,
            max_peers: 8,
            name: Some(name.clone()),
        };
        let events = state.clone();
        let result = share(options, CancellationToken::new(), move |event| {
            record(&events, event)
        })
        .await;
        let phase = match result {
            Ok(()) => "share ended".to_string(),
            Err(error) => format!("error: {error}"),
        };
        log(&phase);
        set(&state, |s| s.phase = phase);
        log("restarting the share in 15 s");
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

/// Whether this process can reach itself over TCP: loopback IPv4 and IPv6,
/// then the instance's own global IPv6 addresses. Shown on the page, because
/// a missing loopback breaks any program that talks to localhost.
async fn self_checks(when: &str) -> Vec<(String, String)> {
    let mut candidates: Vec<std::net::IpAddr> = vec![
        std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::Ipv6Addr::LOCALHOST.into(),
    ];
    candidates.extend(global_ipv6());
    let mut results = Vec::new();
    for ip in candidates {
        let result = match tokio::net::TcpListener::bind(SocketAddr::new(ip, 0)).await {
            Err(error) => format!("bind failed: {error}"),
            Ok(listener) => {
                let addr = listener.local_addr().expect("bound address");
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(_)) => "reachable".to_string(),
                    Ok(Err(error)) => format!("connect failed: {error}"),
                    Err(_) => "connect timed out".to_string(),
                }
            }
        };
        log(&format!("self-check {when} {ip}: {result}"));
        results.push((format!("TCP to itself at {ip}, {when}"), result));
    }
    results
}

/// lo's operstate, flags, and addresses, as the kernel reports them.
fn loopback_state() -> String {
    let addresses: Vec<String> = read("/proc/net/if_inet6")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.ends_with(" lo"))
        .map(|_| "::1".to_string())
        .collect();
    format!(
        "operstate {}, flags {}, IPv6 {}",
        or_na(read("/sys/class/net/lo/operstate")),
        or_na(read("/sys/class/net/lo/flags")),
        if addresses.is_empty() {
            "none".to_string()
        } else {
            addresses.join(", ")
        },
    )
}

/// Sets IFF_UP on lo with SIOCSIFFLAGS, as `ip link set lo up` does. The
/// kernel then assigns 127.0.0.1 and ::1 itself.
fn bring_up_loopback() -> std::io::Result<()> {
    // SAFETY: a plain socket used only for interface ioctls; `ifreq` is
    // zeroed, its name is NUL-terminated, and the fd is closed on every path.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut request: libc::ifreq = std::mem::zeroed();
        for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
            *slot = *byte as libc::c_char;
        }
        let result = if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut request) < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            if libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &request) < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        libc::close(fd);
        result
    }
}

fn global_ipv6() -> Vec<std::net::IpAddr> {
    read("/proc/net/if_inet6")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Scope 00 is global; skip loopback.
            if f.get(3) != Some(&"00") || f.get(5) == Some(&"lo") {
                return None;
            }
            let bytes: Vec<u8> = (0..16)
                .filter_map(|i| u8::from_str_radix(f.first()?.get(2 * i..2 * i + 2)?, 16).ok())
                .collect();
            Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).into())
        })
        .collect()
}

fn set(state: &Shared, change: impl FnOnce(&mut State)) {
    if let Ok(mut s) = state.lock() {
        change(&mut s);
    }
}

fn record(state: &Shared, event: ShareEvent) {
    let line = match &event {
        ShareEvent::Ready { ticket, .. } => {
            log(&"=".repeat(72));
            log("SHARE READY");
            log(&format!("TICKET {ticket}"));
            log(&"=".repeat(72));
            format!("ready, endpoint {}", ticket.endpoint.id)
        }
        ShareEvent::Paired { peer, name } => {
            let line = format!(
                "paired {} ({})",
                name.as_deref().unwrap_or("device"),
                short(&peer.to_string())
            );
            log(&line);
            line
        }
        ShareEvent::Path { peer, path } => {
            let line = format!("path {}: {}", short(&peer.to_string()), describe(path));
            log(&line);
            line
        }
    };
    set(state, |s| {
        match event {
            ShareEvent::Ready { ticket, .. } => s.ticket = Some(ticket),
            ShareEvent::Paired { peer, name } => s.paired.push((
                Instant::now(),
                name.unwrap_or_else(|| "device".into()),
                peer.to_string(),
            )),
            ShareEvent::Path { peer, path } => {
                s.paths.insert(peer.to_string(), (Instant::now(), path));
            }
        }
        s.events.push((SystemTime::now(), line));
        let excess = s.events.len().saturating_sub(30);
        s.events.drain(..excess);
    });
}

fn short(id: &str) -> String {
    format!("{}…", &id[..id.len().min(12)])
}

fn describe(path: &PathInfo) -> String {
    let mut out = match path.kind {
        PathKind::Direct => "Direct".to_string(),
        PathKind::Relay => "Relayed".to_string(),
        PathKind::Unknown => "Unknown".to_string(),
    };
    if let Some(rtt) = path.rtt {
        let _ = write!(out, ", {} ms", rtt.as_millis());
    }
    if let Some(remote) = &path.remote {
        let _ = write!(out, " via {remote}");
    }
    out
}

// --- probes, refreshed in the background ------------------------------------

async fn probe(state: Shared) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("HTTP client");
    loop {
        let relays: Vec<String> = state
            .lock()
            .ok()
            .and_then(|s| {
                s.ticket
                    .as_ref()
                    .map(|t| t.endpoint.relay_urls().map(ToString::to_string).collect())
            })
            .unwrap_or_default();
        let mut results = vec![
            (
                "IPv6 TCP to Cloudflare [2606:4700:4700::1111]:443".into(),
                tcp("[2606:4700:4700::1111]:443").await,
            ),
            (
                "IPv4 TCP to Cloudflare 1.1.1.1:443".into(),
                tcp("1.1.1.1:443").await,
            ),
            ("DNS datum.net".into(), resolve("datum.net:443").await),
            (
                "NAT64 (ipv4only.arpa)".into(),
                resolve("ipv4only.arpa:443").await,
            ),
            (
                "Public IPv6 (api6.ipify.org)".into(),
                fetch(&http, "https://api6.ipify.org").await,
            ),
            (
                "Public IPv4 (api4.ipify.org)".into(),
                fetch(&http, "https://api4.ipify.org").await,
            ),
        ];
        for relay in relays {
            // Relay URLs end in a fully qualified "name." that TLS hostname
            // checks reject; probe the same host without the trailing dot.
            let url = relay
                .replacen("./", "/", 1)
                .trim_end_matches('/')
                .to_string()
                + "/ping";
            results.push((format!("iroh relay {relay}"), fetch(&http, &url).await));
        }
        set(&state, |s| {
            s.probes = results;
            s.probed_at = Some(Instant::now());
        });
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn tcp(addr: &str) -> String {
    let started = Instant::now();
    let addr: SocketAddr = addr.parse().expect("probe address");
    match tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => format!("ok in {} ms", started.elapsed().as_millis()),
        Ok(Err(error)) => format!("failed: {error}"),
        Err(_) => "failed: timed out".into(),
    }
}

async fn resolve(host: &str) -> String {
    match tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host(host)).await {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            ips.join(", ")
        }
        Ok(Err(error)) => format!("failed: {error}"),
        Err(_) => "failed: timed out".into(),
    }
}

async fn fetch(http: &reqwest::Client, url: &str) -> String {
    let started = Instant::now();
    match http.get(url).send().await {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let body: String = body.trim().chars().take(80).collect();
            format!("{status} {body} ({} ms)", started.elapsed().as_millis())
        }
        Err(error) => format!("failed: {error}"),
    }
}

// --- machine facts ------------------------------------------------------------

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn or_na(value: Option<String>) -> String {
    value
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "n/a".into())
}

fn ipv6_addresses() -> Vec<String> {
    read("/proc/net/if_inet6")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let bytes: Vec<u8> = (0..16)
                .filter_map(|i| u8::from_str_radix(f.first()?.get(2 * i..2 * i + 2)?, 16).ok())
                .collect();
            let octets: [u8; 16] = bytes.try_into().ok()?;
            let prefix = u8::from_str_radix(f.get(2)?, 16).ok()?;
            Some(format!(
                "{} {}/{prefix}",
                f.get(5)?,
                std::net::Ipv6Addr::from(octets)
            ))
        })
        .collect()
}

fn ipv6_default_routes() -> Vec<String> {
    read("/proc/net/ipv6_route")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[0] != "0".repeat(32) || f[1] != "00" || f[9] == "lo" {
                return None;
            }
            let bytes: Vec<u8> = (0..16)
                .filter_map(|i| u8::from_str_radix(f[4].get(2 * i..2 * i + 2)?, 16).ok())
                .collect();
            let gateway = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
            Some(format!("default via {gateway} dev {}", f[9]))
        })
        .collect()
}

fn meminfo() -> String {
    let info = read("/proc/meminfo").unwrap_or_default();
    let field = |name: &str| {
        info.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| "?".into())
    };
    if info.is_empty() {
        return "n/a".into();
    }
    format!(
        "{} total, {} available",
        field("MemTotal"),
        field("MemAvailable")
    )
}

fn cpu_model() -> String {
    read("/proc/cpuinfo")
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| "n/a".into())
}

fn mtus() -> String {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return "n/a".into();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            format!(
                "{name}={}",
                or_na(read(&format!("/sys/class/net/{name}/mtu")))
            )
        })
        .collect();
    out.sort();
    out.join(", ")
}

const SECRET_WORDS: [&str; 4] = ["TOKEN", "SECRET", "PASSWORD", "KEY"];

// --- page ---------------------------------------------------------------------

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn table(rows: &[(String, String)]) -> String {
    let mut out = String::from("<table>");
    for (k, v) in rows {
        let _ = write!(out, "<tr><th>{}</th><td>{}</td></tr>", escape(k), escape(v));
    }
    out + "</table>"
}

fn ago(at: Instant) -> String {
    format!("{} s ago", at.elapsed().as_secs())
}

fn page(state: &Shared, name: &str, started: Instant) -> String {
    let s = state.lock().expect("state lock");
    let row = |k: &str, v: String| (k.to_string(), v);
    let datum = vec![
        row("Account", env("DATUM_ACCOUNT")),
        row("Organization", env("DATUM_ORG")),
        row("Project", env("DATUM_PROJECT")),
        row("Workload", env("WORKLOAD")),
        row("Location", env("LOCATION")),
        row("Runtime", env("RUNTIME")),
        row(
            "Hostname",
            or_na(read("/proc/sys/kernel/hostname").or_else(|| std::env::var("HOSTNAME").ok())),
        ),
    ];
    let ticket = s.ticket.as_ref();
    let mut share_rows = vec![
        row("Share name", name.to_string()),
        row("Status", s.phase.clone()),
        row("datum-connect-diag", VERSION.to_string()),
        row(
            "Endpoint ID",
            ticket
                .map(|t| t.endpoint.id.to_string())
                .unwrap_or_else(|| "?".into()),
        ),
        row(
            "Relays in ticket",
            ticket
                .map(|t| {
                    t.endpoint
                        .relay_urls()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default(),
        ),
        row(
            "Direct addresses in ticket",
            ticket
                .map(|t| {
                    t.endpoint
                        .ip_addrs()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default(),
        ),
        row(
            "Shared target",
            "this page, in-process (no listening socket)".to_string(),
        ),
        row(
            "Paired devices",
            if s.paired.is_empty() {
                "none yet".into()
            } else {
                s.paired
                    .iter()
                    .map(|(at, n, p)| format!("{n} ({}, {})", short(p), ago(*at)))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        ),
    ];
    let names: BTreeMap<&str, &str> = s
        .paired
        .iter()
        .map(|(_, n, p)| (p.as_str(), n.as_str()))
        .collect();
    for (peer, (at, path)) in &s.paths {
        let who = names
            .get(peer.as_str())
            .map(|n| n.to_string())
            .unwrap_or_else(|| short(peer));
        share_rows.push((
            format!("Path to {who}"),
            format!("{} (updated {})", describe(path), ago(*at)),
        ));
    }
    let uptime = read("/proc/uptime")
        .and_then(|u| {
            u.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map(|secs| format!("{:.0} s", secs));
    let machine = vec![
        row("Kernel", or_na(read("/proc/sys/kernel/osrelease"))),
        row("Kernel version", or_na(read("/proc/version"))),
        row("Architecture", std::env::consts::ARCH.to_string()),
        row(
            "CPU",
            format!(
                "{} × {}",
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(0),
                cpu_model()
            ),
        ),
        row("Memory", meminfo()),
        row(
            "cgroup memory.max",
            or_na(read("/sys/fs/cgroup/memory.max")),
        ),
        row("Uptime (machine)", or_na(uptime)),
        row(
            "Uptime (this test)",
            format!("{} s", started.elapsed().as_secs()),
        ),
        row("Load average", or_na(read("/proc/loadavg"))),
    ];
    let network = vec![
        row("IPv6 addresses", ipv6_addresses().join("; ")),
        row("IPv6 default routes", ipv6_default_routes().join("; ")),
        row("MTU", mtus()),
        row(
            "resolv.conf",
            read("/etc/resolv.conf")
                .map(|r| {
                    r.lines()
                        .filter(|l| !l.starts_with('#') && !l.is_empty())
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .map(Some)
                .map(or_na)
                .unwrap_or_else(|| "n/a".into()),
        ),
    ];
    let events: Vec<(String, String)> = s
        .events
        .iter()
        .map(|(at, line)| (clock(*at), line.clone()))
        .collect();
    let mut env_rows: Vec<(String, String)> = std::env::vars()
        .map(|(k, v)| {
            let hidden = SECRET_WORDS.iter().any(|w| k.contains(w));
            (k, if hidden { "(hidden)".into() } else { v })
        })
        .collect();
    env_rows.sort();
    let probed = s.probed_at.map(ago).unwrap_or_else(|| "never".into());
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Datum Connect test: {title}</title>
<style>
:root{{color-scheme:light dark}}
body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:1rem;line-height:1.45;max-width:52rem}}
h1{{font-size:1.4rem;margin-bottom:.2rem}} h2{{font-size:1.05rem;margin-top:1.6rem}}
table{{border-collapse:collapse;width:100%;font-size:.88rem}}
th,td{{text-align:left;vertical-align:top;padding:.3rem .5rem .3rem 0;border-top:1px solid color-mix(in srgb,currentColor 18%,transparent);overflow-wrap:anywhere}}
th{{font-weight:600;width:36%}} small{{opacity:.75}}
</style></head><body>
<h1>It works: {title}</h1>
<p>Served inside a Datum Compute instance by one static process, <code>datum-connect-diag</code>,
with no listening socket: each tunneled session from a project-less Datum Connect share over
iroh is handed straight to this page's HTTP server.
<small>Network probes from {probed}.</small></p>
<h2>Datum</h2>{datum}
<h2>Share</h2>{share}
<h2>Network</h2>{network}
<h2>Network probes</h2>{probes}
<h2>Local TCP self-checks</h2><small>Whether this process can reach a TCP port of its own,
before and after bringing the loopback interface up.</small>{self_checks}
<h2>Machine</h2>{machine}
<h2>Recent share events</h2>{events}
<h2>Environment</h2><small>Names containing TOKEN, SECRET, PASSWORD, or KEY are hidden.</small>{env}
</body></html>"#,
        title = escape(name),
        self_checks = table(&s.self_checks),
        datum = table(&datum),
        share = table(&share_rows),
        network = table(&network),
        probes = if s.probes.is_empty() {
            "<p>Running…</p>".into()
        } else {
            table(&s.probes)
        },
        machine = table(&machine),
        events = if events.is_empty() {
            "<p>none</p>".into()
        } else {
            table(&events)
        },
        env = table(&env_rows),
    )
}
