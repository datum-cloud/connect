use super::*;
use http::Response;
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::sync::atomic::{AtomicUsize, Ordering};

fn tls() -> (rustls::ServerConfig, rustls::RootCertStore) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certified.cert.der().clone()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()).into(),
    )
    .unwrap();
    (server, roots)
}

fn descriptor(authority: &str, network: u16) -> ConnectionDescriptor {
    ConnectionDescriptor {
        binding: format!("binding-{network}"),
        policy_revision: "policy".into(),
        network_plan: NetworkPlan {
            expected_prefix: format!("fd00:{network}::/96").parse().unwrap(),
            destination_prefixes: vec![format!("fd00:{network}::/48").parse().unwrap()],
            mtu: 1280,
        },
        transport: TransportDescriptor {
            kind: TRANSPORT_TYPE.into(),
            authority: authority.into(),
            vpc_selector: format!("internal/vpc-{network}"),
            credential: SensitiveCredential(format!("credential-{network}")),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            transports: vec!["h3".into(), "h2".into()],
        },
    }
}

fn authorized(request: &Request<impl Sized>) -> Option<u16> {
    (1..=2).find(|network| {
        request
            .headers()
            .get("Galactic-VPC")
            .and_then(|value| value.to_str().ok())
            == Some(format!("internal/vpc-{network}").as_str())
            && request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                == Some(format!("Bearer credential-{network}").as_str())
    })
}

fn plans(network: u16) -> Bytes {
    let prefix: Ipv6Net = format!("fd00:{network}::/96").parse().unwrap();
    let route: Ipv6Net = format!("fd00:{network}::/48").parse().unwrap();
    let mut assignment = vec![0, 6];
    assignment.extend_from_slice(&prefix.network().octets());
    assignment.push(96);
    let mut advertisement = vec![6];
    advertisement.extend_from_slice(&route.network().octets());
    advertisement.extend_from_slice(&route.broadcast().octets());
    advertisement.push(0);
    let mut result = encode_capsule(1, &assignment).to_vec();
    result.extend_from_slice(&encode_capsule(3, &advertisement));
    result.into()
}

fn packet(network: u16) -> Bytes {
    let mut packet = vec![0u8; 41];
    packet[0] = 0x60;
    packet[5] = 1;
    packet[6] = 59;
    packet[7] = 64;
    packet[8..24].copy_from_slice(
        &format!("fd00:{network}::1")
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    packet[24..40].copy_from_slice(
        &format!("fd00:{network}:0:1::1")
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    packet[40] = network as u8;
    packet.into()
}

fn reply(packet: Bytes) -> Bytes {
    let mut response = packet.to_vec();
    response[8..24].copy_from_slice(&packet[24..40]);
    response[24..40].copy_from_slice(&packet[8..24]);
    response.into()
}

async fn exchange(session: &ManagedSession, network: u16) {
    session.send(packet(network)).await.unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(3), session.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, reply(packet(network)));
}

fn identity(session: &ManagedSession) -> usize {
    match session {
        ManagedSession::H3(value) => value.connection_id(),
        ManagedSession::H2(value) => value.connection_id(),
    }
}

fn stream_id(session: &ManagedSession) -> u64 {
    match session {
        ManagedSession::H3(value) => value.stream_id(),
        ManagedSession::H2(value) => u64::from(value.stream_id()),
    }
}

async fn open(
    pool: &TransportPool,
    protocol: &str,
    descriptor: &ConnectionDescriptor,
) -> Result<ManagedSession, AttemptFailure> {
    match protocol {
        "h3" => pool
            .connect_h3(descriptor, CancellationToken::new())
            .await
            .map(ManagedSession::H3),
        _ => pool
            .connect_h2(descriptor, CancellationToken::new())
            .await
            .map(ManagedSession::H2),
    }
}

async fn verify_pool(
    protocol: &str,
    authority: String,
    roots: rustls::RootCertStore,
    accepts: Arc<AtomicUsize>,
    revoke: CancellationToken,
) {
    let pool = TransportPool {
        roots,
        ..TransportPool::default()
    };
    let first = open(&pool, protocol, &descriptor(&authority, 1))
        .await
        .unwrap();
    let second = open(&pool, protocol, &descriptor(&authority, 2))
        .await
        .unwrap();
    assert_eq!(identity(&first), identity(&second));
    assert_ne!(stream_id(&first), stream_id(&second));
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    exchange(&first, 1).await;
    exchange(&second, 2).await;
    match &first {
        ManagedSession::H3(session) => session
            .transport
            .connection
            .close(0u32.into(), b"test transport failure"),
        ManagedSession::H2(session) => session.transport.closed.cancel(),
    }
    for session in [&first, &second] {
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), session.recv())
                .await
                .unwrap()
                .is_none()
        );
    }
    let first = open(&pool, protocol, &descriptor(&authority, 1))
        .await
        .unwrap();
    let second = open(&pool, protocol, &descriptor(&authority, 2))
        .await
        .unwrap();
    assert_eq!(identity(&first), identity(&second));
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
    exchange(&first, 1).await;
    exchange(&second, 2).await;
    let mut expiring = descriptor(&authority, 2);
    expiring.transport.expires_at = Utc::now() + chrono::Duration::milliseconds(30_010);
    let expired = open(&pool, protocol, &expiring).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3), expired.recv())
            .await
            .unwrap()
            .is_none()
    );
    exchange(&second, 2).await;
    assert!(matches!(
        open(&pool, protocol, &descriptor(&authority, 3)).await,
        Err(AttemptFailure::HttpStatus(403))
    ));
    let mut replay = descriptor(&authority, 2);
    replay.transport.credential = SensitiveCredential("credential-1".into());
    assert!(matches!(
        open(&pool, protocol, &replay).await,
        Err(AttemptFailure::HttpStatus(403))
    ));
    revoke.cancel();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3), first.recv())
            .await
            .unwrap()
            .is_none()
    );
    first.cancel();
    drop(first);
    exchange(&second, 2).await;
    let refreshed = open(&pool, protocol, &descriptor(&authority, 2))
        .await
        .unwrap();
    assert_eq!(identity(&second), identity(&refreshed));
    second.cancel();
    drop(second);
    exchange(&refreshed, 2).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
    let separate_context = TransportPool {
        roots: pool.roots.clone(),
        ..TransportPool::default()
    };
    let isolated = open(&separate_context, protocol, &descriptor(&authority, 2))
        .await
        .unwrap();
    assert_ne!(identity(&refreshed), identity(&isolated));
    assert_eq!(accepts.load(Ordering::SeqCst), 3);
    exchange(&isolated, 2).await;
    isolated.cancel();
    exchange(&refreshed, 2).await;
}

#[tokio::test]
async fn h2_two_vpcs_share_transport_not_authorization() {
    let (mut tls, roots) = tls();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let accepts = Arc::new(AtomicUsize::new(0));
    let count = accepts.clone();
    let revoke = CancellationToken::new();
    let revoked = revoke.clone();
    let server = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let tls = tls.clone();
            let revoked = revoked.clone();
            tokio::spawn(async move {
                let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                    .accept(tcp)
                    .await
                    .unwrap();
                let mut builder = h2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(tls).await.unwrap();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let Some(network) = authorized(&request) else {
                        respond
                            .send_response(Response::builder().status(403).body(()).unwrap(), true)
                            .unwrap();
                        continue;
                    };
                    let mut outgoing = respond
                        .send_response(
                            Response::builder()
                                .header("capsule-protocol", "?1")
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    outgoing.send_data(plans(network), false).unwrap();
                    let mut incoming = request.into_body();
                    let revoked = revoked.clone();
                    tokio::spawn(async move {
                        let mut buffered = BytesMut::new();
                        loop {
                            tokio::select! {
                                _ = revoked.cancelled(), if network == 1 => break,
                                capsule = next_h2_capsule(&mut incoming, &mut buffered) => {
                                    let Ok((0, payload)) = capsule else { break };
                                    let mut data = vec![0];
                                    data.extend_from_slice(&reply(payload.slice(1..)));
                                    if outgoing.send_data(encode_capsule(0, &data), false).is_err() { break; }
                                }
                            }
                        }
                        outgoing.send_reset(h2::Reason::CANCEL);
                    });
                }
            });
        }
    });
    verify_pool("h2", authority, roots, accepts, revoke).await;
    server.abort();
}

#[tokio::test]
async fn h3_two_vpcs_share_transport_not_authorization() {
    let (mut tls, roots) = tls();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let authority = format!("127.0.0.1:{}", endpoint.local_addr().unwrap().port());
    let accepts = Arc::new(AtomicUsize::new(0));
    let count = accepts.clone();
    let revoke = CancellationToken::new();
    let revoked = revoke.clone();
    let server_endpoint = endpoint.clone();
    let server = tokio::spawn(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let revoked = revoked.clone();
            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                let echo = connection.clone();
                tokio::spawn(async move {
                    while let Ok(wire) = echo.read_datagram().await {
                        let Some((quarter, _)) = decode_varint(&wire) else {
                            continue;
                        };
                        if let Ok(Some(packet)) = decode_http_datagram(wire, quarter * 4) {
                            let _ = echo
                                .send_datagram(encode_http_datagram(quarter * 4, &reply(packet)));
                        }
                    }
                });
                let mut builder = h3::server::builder();
                builder.enable_extended_connect(true).enable_datagram(true);
                let mut h3 = builder
                    .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                    let Some(network) = authorized(&request) else {
                        stream
                            .send_response(Response::builder().status(403).body(()).unwrap())
                            .await
                            .unwrap();
                        stream.finish().await.unwrap();
                        continue;
                    };
                    stream
                        .send_response(
                            Response::builder()
                                .header("capsule-protocol", "?1")
                                .body(())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    stream.send_data(plans(network)).await.unwrap();
                    let revoked = revoked.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = revoked.cancelled(), if network == 1 => {},
                            _ = stream.recv_data() => {},
                        }
                        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    });
                }
            });
        }
    });
    verify_pool("h3", authority, roots, accepts, revoke).await;
    endpoint.close(0u32.into(), b"test complete");
    server.abort();
}
