//! End to end over loopback with relays disabled: share, pair, dial, forward.
use std::time::Duration;

use connect_share::{
    DialEvent, DialOptions, PathInfo, PathKind, ShareEvent, ShareKey, ShareOptions, ShareTarget,
    ShareTicket, dial, share,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

/// Echoes "pong" for each "ping".
async fn origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                while stream.read_exact(&mut buf).await.is_ok() {
                    if stream.write_all(b"pong").await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Keeps only loopback addresses so the test never leaves the host.
fn loopback_only(mut ticket: ShareTicket) -> ShareTicket {
    let addrs: Vec<_> = ticket
        .endpoint
        .ip_addrs()
        .filter(|addr| addr.is_ipv4())
        .map(|addr| std::net::SocketAddr::from(([127, 0, 0, 1], addr.port())))
        .collect();
    let mut endpoint = iroh::EndpointAddr::new(ticket.endpoint.id);
    for addr in addrs {
        endpoint = endpoint.with_ip_addr(addr);
    }
    ticket.endpoint = endpoint;
    ticket
}

async fn start_share(
    max_peers: usize,
) -> (
    ShareTicket,
    mpsc::UnboundedReceiver<ShareEvent>,
    CancellationToken,
) {
    let target = origin().await;
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            share(
                ShareOptions {
                    target: target.to_string().into(),
                    relay_urls: Some(Vec::new()),
                    max_peers,
                    name: Some("test\u{1b}[31m service".into()),
                    udp_port: None,
                    public_addrs: Vec::new(),
                    key: None,
                },
                cancel,
                |event| {
                    let _ = tx.send(event);
                },
            )
            .await
            .unwrap();
        }
    });
    let Some(ShareEvent::Ready { ticket, .. }) = rx.recv().await else {
        panic!("share did not become ready");
    };
    (loopback_only(ticket), rx, cancel)
}

type Ready = tokio::sync::oneshot::Receiver<(std::net::SocketAddr, Option<String>)>;

async fn start_dial(
    ticket: ShareTicket,
) -> (
    Ready,
    tokio::task::JoinHandle<Result<(), connect_share::Error>>,
    CancellationToken,
) {
    let (ready, task, cancel, _paths) = start_dial_with_paths(ticket).await;
    (ready, task, cancel)
}

async fn start_dial_with_paths(
    ticket: ShareTicket,
) -> (
    Ready,
    tokio::task::JoinHandle<Result<(), connect_share::Error>>,
    CancellationToken,
    mpsc::UnboundedReceiver<PathInfo>,
) {
    let cancel = CancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (path_tx, path_rx) = mpsc::unbounded_channel();
    let mut tx = Some(tx);
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            dial(
                DialOptions {
                    ticket,
                    bind: "127.0.0.1:0".parse().unwrap(),
                    secret_key: None,
                    name: Some("test-phone".into()),
                    relay_urls: Some(Vec::new()),
                },
                cancel,
                move |event| match event {
                    DialEvent::Ready(ready) => {
                        if let Some(tx) = tx.take() {
                            let _ = tx.send((ready.local_addr, ready.sharer_name));
                        }
                    }
                    DialEvent::Path(path) => {
                        let _ = path_tx.send(path);
                    }
                },
            )
            .await
        }
    });
    (rx, task, cancel, path_rx)
}

#[tokio::test]
async fn paired_peer_reaches_shared_service() {
    let (ticket, mut events, share_cancel) = start_share(4).await;
    let (ready, _task, dial_cancel) = start_dial(ticket).await;
    let (local, sharer_name) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    // Control characters from the sharer never reach the peer's display.
    assert_eq!(sharer_name.as_deref(), Some("test[31m service"));

    match events.recv().await {
        Some(ShareEvent::Paired { name, .. }) => assert_eq!(name.as_deref(), Some("test-phone")),
        other => panic!("expected Paired, got {other:?}"),
    }

    let mut stream = TcpStream::connect(local).await.unwrap();
    for _ in 0..3 {
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
    }
    dial_cancel.cancel();
    share_cancel.cancel();
}

/// Both ends report the path once traffic flows. With relays disabled the
/// only possible path is direct.
#[tokio::test]
async fn both_ends_report_a_direct_path() {
    let (ticket, mut events, share_cancel) = start_share(4).await;
    let (ready, _task, dial_cancel, mut dial_paths) = start_dial_with_paths(ticket).await;
    let (local, _) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    let mut stream = TcpStream::connect(local).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();

    let dial_path = tokio::time::timeout(Duration::from_secs(10), dial_paths.recv())
        .await
        .expect("dial path report")
        .unwrap();
    assert_eq!(dial_path.kind, PathKind::Direct, "{dial_path:?}");
    assert!(
        dial_path.remote.is_some() && dial_path.rtt.is_some(),
        "{dial_path:?}"
    );

    let share_path = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(ShareEvent::Path { path, .. }) => break path,
                Some(_) => continue,
                None => panic!("share ended"),
            }
        }
    })
    .await
    .expect("share path report");
    assert_eq!(share_path.kind, PathKind::Direct, "{share_path:?}");
    dial_cancel.cancel();
    share_cancel.cancel();
}

/// A ticket whose share has stopped fails fast with a plain message.
#[tokio::test]
async fn stopped_share_is_unreachable_within_the_timeout() {
    let (ticket, _events, share_cancel) = start_share(4).await;
    share_cancel.cancel();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = std::time::Instant::now();
    let (_ready, task, _cancel) = start_dial(ticket).await;
    let result = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("dial finished")
        .unwrap();
    assert!(
        matches!(result, Err(connect_share::Error::Unreachable)),
        "{result:?}"
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "ticket no longer reachable"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < connect_share::PAIR_TIMEOUT + Duration::from_secs(2),
        "{elapsed:?}"
    );
}

/// An in-process target receives the dialer's bytes with no socket in
/// between.
#[tokio::test]
async fn in_process_target_serves_without_a_socket() {
    let (streams, mut incoming) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            share(
                ShareOptions {
                    target: ShareTarget::InProcess { port: 80, streams },
                    relay_urls: Some(Vec::new()),
                    max_peers: 4,
                    name: Some("in-process".into()),
                    udp_port: None,
                    public_addrs: Vec::new(),
                    key: None,
                },
                cancel,
                |event| {
                    let _ = tx.send(event);
                },
            )
            .await
            .unwrap();
        }
    });
    let Some(ShareEvent::Ready { ticket, target }) = rx.recv().await else {
        panic!("share did not become ready");
    };
    assert_eq!(target, "in-process");
    assert_eq!(ticket.port, 80);
    // Echo each delivered session.
    tokio::spawn(async move {
        while let Some(mut stream) = incoming.recv().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                while stream.read_exact(&mut buf).await.is_ok() {
                    if stream.write_all(b"pong").await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let (ready, _task, dial_cancel) = start_dial(loopback_only(ticket)).await;
    let (local, _) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    let mut stream = TcpStream::connect(local).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    dial_cancel.cancel();
    cancel.cancel();
}

/// A fixed UDP port and a public address show up in the ticket, and the
/// share still pairs and serves over it.
#[tokio::test]
async fn fixed_port_and_public_address_are_advertised() {
    let port = free_udp_port();
    let public: std::net::SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
    let target = origin().await;
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            share(
                ShareOptions {
                    target: target.to_string().into(),
                    relay_urls: Some(Vec::new()),
                    max_peers: 4,
                    name: None,
                    udp_port: Some(port),
                    public_addrs: vec![public],
                    key: None,
                },
                cancel,
                |event| {
                    let _ = tx.send(event);
                },
            )
            .await
            .unwrap();
        }
    });
    let Some(ShareEvent::Ready { ticket, .. }) = rx.recv().await else {
        panic!("share did not become ready");
    };
    let addrs: Vec<_> = ticket.endpoint.ip_addrs().copied().collect();
    assert!(addrs.contains(&public), "{addrs:?}");
    assert!(
        addrs.iter().any(|a| *a != public && a.port() == port),
        "{addrs:?}"
    );
    // The ticket survives encoding with the public address intact.
    let decoded: ShareTicket = ticket.to_string().parse().unwrap();
    assert!(decoded.endpoint.ip_addrs().any(|a| *a == public));

    let (ready, _task, dial_cancel) = start_dial(loopback_only(ticket)).await;
    let (local, _) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    let mut stream = TcpStream::connect(local).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    dial_cancel.cancel();
    cancel.cancel();
}

#[tokio::test]
async fn wrong_secret_is_refused() {
    let (mut ticket, _events, share_cancel) = start_share(4).await;
    ticket.secret[0] ^= 1;
    let (_ready, task, _cancel) = start_dial(ticket).await;
    let result = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("dial finished")
        .unwrap();
    assert!(
        matches!(&result, Err(connect_share::Error::Pairing(msg)) if msg.contains("invalid secret")),
        "{result:?}"
    );
    share_cancel.cancel();
}

#[tokio::test]
async fn pairing_limit_is_enforced() {
    let (ticket, _events, share_cancel) = start_share(1).await;
    let (first, _task1, _c1) = start_dial(ticket.clone()).await;
    tokio::time::timeout(Duration::from_secs(20), first)
        .await
        .expect("first dial ready")
        .unwrap();
    let (_second, task2, _c2) = start_dial(ticket).await;
    let result = tokio::time::timeout(Duration::from_secs(20), task2)
        .await
        .expect("second dial finished")
        .unwrap();
    assert!(
        matches!(&result, Err(connect_share::Error::Pairing(msg)) if msg.contains("limit")),
        "{result:?}"
    );
    share_cancel.cancel();
}

/// Starts a share of `target` on a fixed UDP port, so a restart comes back
/// at the same loopback address. The task ends once the endpoint closes.
async fn start_keyed_share(
    target: std::net::SocketAddr,
    udp_port: u16,
    key: ShareKey,
) -> (ShareTicket, CancellationToken, tokio::task::JoinHandle<()>) {
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            share(
                ShareOptions {
                    target: target.to_string().into(),
                    relay_urls: Some(Vec::new()),
                    max_peers: 4,
                    name: None,
                    udp_port: Some(udp_port),
                    public_addrs: Vec::new(),
                    key: Some(key),
                },
                cancel,
                |event| {
                    let _ = tx.send(event);
                },
            )
            .await
            .unwrap();
        }
    });
    let Some(ShareEvent::Ready { ticket, .. }) = rx.recv().await else {
        panic!("share did not become ready");
    };
    (loopback_only(ticket), cancel, task)
}

/// Dials `ticket` and checks one ping reaches the origin.
async fn ping_through(ticket: ShareTicket) -> Result<(), connect_share::Error> {
    let (ready, task, cancel) = start_dial(ticket).await;
    // A failed dial drops the ready sender, so read its error from the task.
    let Ok(ready) = ready.await else {
        return task.await.unwrap();
    };
    let mut stream = TcpStream::connect(ready.0).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    cancel.cancel();
    Ok(())
}

/// A UDP port free on both the IPv4 and IPv6 wildcard addresses, which is
/// what a share binds, and not handed to another test in this process: the
/// probe sockets close at once, so the kernel may offer the same port again.
fn free_udp_port() -> u16 {
    static TAKEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut taken = TAKEN.lock().unwrap();
    loop {
        let port = std::net::UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // A dual-stack bind fails if either family has the port.
        if !taken.contains(&port) && std::net::UdpSocket::bind(("::", port)).is_ok() {
            taken.push(port);
            return port;
        }
    }
}

/// A share restarted with the same key accepts the ticket from its first
/// run, even after the service moved to another local port. A new key
/// refuses that ticket.
#[tokio::test]
async fn kept_key_reuses_the_ticket_across_restarts() {
    let udp_port = free_udp_port();
    // The key's port names the destination, not the service's port.
    let key = ShareKey::generate(4242);
    let (first, cancel, task) = start_keyed_share(origin().await, udp_port, key.clone()).await;
    assert_eq!(first.port, 4242);
    assert_eq!(first.endpoint.id, key.endpoint_id());
    tokio::time::timeout(Duration::from_secs(20), ping_through(first.clone()))
        .await
        .expect("first run")
        .unwrap();
    cancel.cancel();
    task.await.unwrap();

    let (second, cancel, task) = start_keyed_share(origin().await, udp_port, key).await;
    assert_eq!(second.endpoint.id, first.endpoint.id);
    assert_eq!(second.secret, first.secret);
    tokio::time::timeout(Duration::from_secs(20), ping_through(first.clone()))
        .await
        .expect("restarted run")
        .unwrap();
    cancel.cancel();
    task.await.unwrap();

    let (_third, cancel, _task) =
        start_keyed_share(origin().await, udp_port, ShareKey::generate(4242)).await;
    let result = tokio::time::timeout(Duration::from_secs(20), ping_through(first))
        .await
        .expect("new key run");
    assert!(result.is_err(), "the old ticket still worked");
    cancel.cancel();
}

/// One ping over `stream`, or the reason it failed.
async fn ping(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(b"ping").await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"pong");
    Ok(())
}

/// A ready dial ends with `Unreachable` once its share stops, and a local
/// connection made in the meantime fails instead of hanging.
#[tokio::test]
async fn dial_ends_when_its_share_stops() {
    let (ticket, _events, share_cancel) = start_share(4).await;
    let (ready, task, _dial_cancel) = start_dial(ticket).await;
    let (local, _) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    let mut stream = TcpStream::connect(local).await.unwrap();
    ping(&mut stream).await.unwrap();
    drop(stream);

    share_cancel.cancel();
    let stopped = std::time::Instant::now();
    let bound = connect_share::SHARER_LOST_TIMEOUT + Duration::from_secs(2);
    // Accepted before the dial notices, so its tunnel cannot be set up.
    let mut stream = TcpStream::connect(local).await.unwrap();
    let forwarded = tokio::time::timeout(bound, ping(&mut stream))
        .await
        .expect("local connection hung");
    assert!(forwarded.is_err(), "ping reached a stopped share");

    let result = tokio::time::timeout(bound, task)
        .await
        .expect("dial still running")
        .unwrap();
    assert!(
        matches!(result, Err(connect_share::Error::Unreachable)),
        "{result:?}"
    );
    let elapsed = stopped.elapsed();
    assert!(elapsed < bound, "{elapsed:?}");
    // The listener is gone with the dial.
    assert!(TcpStream::connect(local).await.is_err());
}

/// A dial with no traffic stays up through many liveness checks, past the
/// grace period, and still forwards afterwards.
#[tokio::test]
async fn idle_dial_stays_up() {
    let (ticket, _events, share_cancel) = start_share(4).await;
    let (ready, task, dial_cancel) = start_dial(ticket).await;
    let (local, _) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    tokio::time::sleep(connect_share::LIVENESS_GRACE + 2 * connect_share::LIVENESS_INTERVAL).await;
    assert!(!task.is_finished(), "{:?}", task.await);
    let mut stream = TcpStream::connect(local).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), ping(&mut stream))
        .await
        .expect("ping")
        .unwrap();
    dial_cancel.cancel();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("dial stopped")
        .unwrap();
    assert!(result.is_ok(), "{result:?}");
    share_cancel.cancel();
}

/// A share that restarts with the same key within the grace period keeps
/// the dial up; the liveness check pairs again, so forwarding resumes.
#[tokio::test]
async fn dial_survives_a_quick_restart_with_the_same_key() {
    let udp_port = free_udp_port();
    let key = ShareKey::generate(4242);
    let target = origin().await;
    let (ticket, cancel, share_task) = start_keyed_share(target, udp_port, key.clone()).await;
    let (ready, task, dial_cancel) = start_dial(ticket).await;
    let (local, _) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .expect("dial ready")
        .unwrap();
    cancel.cancel();
    share_task.await.unwrap();
    // With the dial's checks arriving, iroh can still hold the UDP socket
    // for a few milliseconds after the share returns.
    let waited = std::time::Instant::now();
    while std::net::UdpSocket::bind(("::", udp_port)).is_err() {
        assert!(waited.elapsed() < Duration::from_secs(5), "port still held");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (_ticket, cancel, _share_task) = start_keyed_share(target, udp_port, key).await;
    // Long enough that the dial would have ended without the restart.
    tokio::time::sleep(connect_share::SHARER_LOST_TIMEOUT).await;
    assert!(!task.is_finished(), "{:?}", task.await);
    let mut stream = TcpStream::connect(local).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), ping(&mut stream))
        .await
        .expect("ping")
        .unwrap();
    dial_cancel.cancel();
    cancel.cancel();
}

/// Over the real relays and address lookup: a restarted share found by its
/// identity alone, without the addresses from the first run. Needs network
/// access to the n0 relays and DNS, so it is ignored by default.
#[tokio::test]
#[ignore = "uses the public n0 relays and DNS"]
async fn kept_key_is_found_after_its_addresses_change() {
    let target = origin().await;
    let key = ShareKey::generate(target.port());
    let run = |key: ShareKey| async move {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                share(
                    ShareOptions {
                        target: target.to_string().into(),
                        relay_urls: None,
                        max_peers: 4,
                        name: None,
                        udp_port: None,
                        public_addrs: Vec::new(),
                        key: Some(key),
                    },
                    cancel,
                    |event| {
                        let _ = tx.send(event);
                    },
                )
                .await
                .unwrap();
            }
        });
        let Some(ShareEvent::Ready { ticket, .. }) = rx.recv().await else {
            panic!("share did not become ready");
        };
        (ticket, cancel, task)
    };
    let (first, cancel, task) = run(key.clone()).await;
    cancel.cancel();
    task.await.unwrap();
    let (_second, cancel, _task) = run(key).await;
    // Only the identity and secret survive; addresses come from lookup.
    let mut stale = first;
    stale.endpoint = iroh::EndpointAddr::new(stale.endpoint.id);
    let dial_cancel = CancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut tx = Some(tx);
    tokio::spawn({
        let dial_cancel = dial_cancel.clone();
        async move {
            dial(
                DialOptions {
                    ticket: stale,
                    bind: "127.0.0.1:0".parse().unwrap(),
                    secret_key: None,
                    name: None,
                    relay_urls: None,
                },
                dial_cancel,
                move |event| {
                    if let DialEvent::Ready(ready) = event
                        && let Some(tx) = tx.take()
                    {
                        let _ = tx.send(ready.local_addr);
                    }
                },
            )
            .await
        }
    });
    let local = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .expect("dial ready")
        .unwrap();
    let mut stream = TcpStream::connect(local).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    dial_cancel.cancel();
    cancel.cancel();
}
