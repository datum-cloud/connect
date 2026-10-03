use super::*;

// Each real iroh endpoint owns sockets and OS network monitors. Bound concurrent
// integration fixtures so macOS's default per-process FD limit is not exceeded.
static NETWORK_TESTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[tokio::test]
async fn joined_grants_share_one_endpoint_with_tcp_udp_and_revoke_independently() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = crate::Transport::bind(
        crate::TransportConfig::new(iroh::SecretKey::generate())
            .bind_addr("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .unwrap();
    let client = crate::Transport::bind(
        crate::TransportConfig::new(iroh::SecretKey::generate())
            .bind_addr("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .unwrap();
    assert!(matches!(
        connect(
            client.endpoint(),
            server.endpoint().addr(),
            "joined",
            CancellationToken::new()
        )
        .await,
        Err(Error::RejectedWithReason {
            status: StatusCode::FORBIDDEN,
            reason: RejectionReason::PeerNetworkNotApproved,
            ..
        })
    ));
    let config = config();
    let grant = Grant {
        peer: client.endpoint_id(),
        network: "joined".into(),
        address: config.address,
        routes: vec!["10.30.0.9/32".parse().unwrap()],
        mtu: 1280,
    };
    let mut registration = server.register_ip_grant(grant.clone()).await.unwrap();
    assert!(server.register_ip_grant(grant.clone()).await.is_err());
    let joining = tokio::spawn(connect(
        client.endpoint(),
        server.endpoint().addr(),
        "joined",
        CancellationToken::new(),
    ));
    let incoming = tokio::time::timeout(Duration::from_secs(5), registration.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.peer, client.endpoint_id());
    incoming.ready.send(true).unwrap();
    let session = joining.await.unwrap().unwrap();
    let request = packet(config.address, "10.30.0.9".parse().unwrap(), 1280);
    session.send(request.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), incoming.session.recv())
            .await
            .unwrap()
            .unwrap(),
        request
    );

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let tcp_echo = tokio::spawn(async move {
        let (socket, _) = tcp.accept().await.unwrap();
        let (mut read, mut write) = socket.into_split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
    });
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let udp_echo = tokio::spawn(async move {
        let mut buffer = [0; 128];
        loop {
            let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&buffer[..len], peer).await.unwrap();
        }
    });
    let access = crate::Access::Peers(std::collections::HashSet::from([client.endpoint_id()]));
    server
        .replace_policy(crate::Policy {
            destinations: HashMap::from([
                (
                    crate::DestinationId::tcp(2222),
                    crate::DestinationPolicy {
                        target: crate::Target::Tcp(tcp_addr),
                        access: access.clone(),
                    },
                ),
                (
                    crate::DestinationId::udp(3333),
                    crate::DestinationPolicy {
                        target: crate::Target::Udp(udp_addr),
                        access,
                    },
                ),
            ]),
        })
        .await
        .unwrap();
    let mut tcp_session = client
        .connect_tcp(
            server.endpoint().addr(),
            crate::DestinationId::tcp(2222),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let udp_session = client
        .connect_udp(
            server.endpoint().addr(),
            crate::DestinationId::udp(3333),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    for label in [b"before".as_slice(), b"after".as_slice()] {
        if label == b"after" {
            registration.cancel();
            assert!(incoming.session.recv().await.is_none());
            tokio::time::timeout(Duration::from_secs(3), async {
                while session.recv().await.is_some() {}
            })
            .await
            .unwrap();
            assert!(matches!(
                connect(
                    client.endpoint(),
                    server.endpoint().addr(),
                    "joined",
                    CancellationToken::new()
                )
                .await,
                Err(Error::RejectedWithReason {
                    status: StatusCode::FORBIDDEN,
                    reason: RejectionReason::PeerNetworkNotApproved,
                    ..
                })
            ));
        }
        tcp_session.write_all(label).await.unwrap();
        let mut reply = vec![0; label.len()];
        tokio::time::timeout(Duration::from_secs(3), tcp_session.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, label);
        udp_session
            .send(Bytes::copy_from_slice(label))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), udp_session.recv())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            label
        );
    }
    // A stale registration must not remove a newer grant for the same key.
    let mut replacement = server.register_ip_grant(grant.clone()).await.unwrap();
    drop(registration);
    let joining = tokio::spawn(connect(
        client.endpoint(),
        server.endpoint().addr(),
        "joined",
        CancellationToken::new(),
    ));
    let incoming = tokio::time::timeout(Duration::from_secs(3), replacement.recv())
        .await
        .unwrap()
        .unwrap();
    replacement.cancel();
    assert!(incoming.session.recv().await.is_none());
    drop(incoming);
    assert!(joining.await.unwrap().is_err());
    let mut final_registration = server.register_ip_grant(grant.clone()).await.unwrap();
    client.shutdown().await;
    server.shutdown().await;
    assert!(final_registration.recv().await.is_none());
    assert!(server.register_ip_grant(grant.clone()).await.is_err());
    assert!(replacement.recv().await.is_none());
    tcp_echo.abort();
    udp_echo.abort();
    let outbound_only = crate::Transport::client(endpoint().await);
    assert!(outbound_only.register_ip_grant(grant).await.is_err());
    outbound_only.shutdown().await;
}

fn config() -> SessionConfig {
    SessionConfig {
        address: "10.20.0.2".parse().unwrap(),
        routes: vec!["10.30.0.0/24".parse().unwrap()],
        mtu: 1280,
    }
}

fn packet(source: IpAddr, destination: IpAddr, size: usize) -> Bytes {
    let (source, destination) = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => (source, destination),
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            return ipv6_packet(source, destination, size, 58);
        }
        _ => panic!("fixture address family mismatch"),
    };
    let mut packet = vec![0; size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let mut sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_be_bytes([v[0], v[1]]) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet.into()
}

fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr, size: usize, next: u8) -> Bytes {
    assert!(size >= 60);
    let mut packet = vec![0; size];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((size - 40) as u16).to_be_bytes());
    packet[6] = next;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    let checksum_offset = match next {
        58 => {
            packet[40] = 128;
            42
        }
        17 => {
            packet[44..46].copy_from_slice(&((size - 40) as u16).to_be_bytes());
            46
        }
        6 => {
            packet[52] = 0x50;
            56
        }
        _ => return packet.into(),
    };
    let mut pseudo = Vec::new();
    pseudo.extend(source.octets());
    pseudo.extend(destination.octets());
    pseudo.extend(((size - 40) as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, next]);
    pseudo.extend(&packet[40..]);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let mut sum: u32 = pseudo
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
    packet.into()
}

async fn endpoint() -> Endpoint {
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[test]
fn protocol_and_policy_are_strict() {
    assert_eq!(
        Protocol::from_str("connect-ip").ok().unwrap(),
        Protocol::CONNECT_IP
    );
    for value in [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "10.30.0.1/24",
        "::/64",
        "127.0.0.0/8",
        "224.0.0.0/8",
    ] {
        assert!(value.parse::<IpPrefix>().is_err(), "{value}");
    }
    let config = config();
    assert_eq!(
        decode_routes(&encode_routes(&config.routes)).unwrap(),
        config.routes
    );
    let remote = "10.30.0.9".parse().unwrap();
    assert!(validate_packet(&packet(config.address, remote, 1280), &config, true).is_ok());
    assert!(validate_packet(&packet(remote, config.address, 20), &config, false).is_ok());
    assert!(matches!(
        validate_packet(&packet(remote, config.address, 20), &config, true),
        Err(Error::AddressPolicy)
    ));
    assert!(matches!(
        validate_packet(
            &packet(config.address, "10.31.0.1".parse().unwrap(), 20),
            &config,
            true
        ),
        Err(Error::AddressPolicy)
    ));
    assert!(matches!(
        validate_packet(&packet(config.address, remote, 1281), &config, true),
        Err(Error::PacketTooLarge)
    ));
    assert!(matches!(
        validate_packet(&[0x60; 40], &config, true),
        Err(Error::InvalidPacket)
    ));
    let mut invalid = packet(config.address, remote, 20).to_vec();
    invalid[10] ^= 1;
    assert!(matches!(
        validate_packet(&invalid, &config, true),
        Err(Error::InvalidPacket)
    ));
    for (offset, value) in [(8, 0), (6, 0x20), (7, 1)] {
        let mut invalid = packet(config.address, remote, 20).to_vec();
        invalid[offset] = value;
        assert!(matches!(
            validate_packet(&invalid, &config, true),
            Err(Error::InvalidPacket)
        ));
    }
}

#[test]
fn ipv6_packets_and_capsules_are_family_scoped_and_bounded() {
    let config = SessionConfig {
        address: "fd42:20::2".parse().unwrap(),
        routes: vec!["fd42:30::/64".parse().unwrap()],
        mtu: 1280,
    };
    config.validate().unwrap();
    let remote: Ipv6Addr = "fd42:30::9".parse().unwrap();
    for protocol in [6, 17, 58] {
        let good = ipv6_packet("fd42:20::2".parse().unwrap(), remote, 1280, protocol);
        assert!(validate_packet(&good, &config, true).is_ok());
        let mut invalid = good.to_vec();
        invalid[7] = 0;
        assert!(matches!(
            validate_packet(&invalid, &config, true),
            Err(Error::InvalidPacket)
        ));
        invalid = good.to_vec();
        invalid[5] ^= 1;
        assert!(matches!(
            validate_packet(&invalid, &config, true),
            Err(Error::InvalidPacket)
        ));
        for extension in [0, 43, 44, 50, 51, 59, 60, 135] {
            invalid = good.to_vec();
            invalid[6] = extension;
            assert!(
                matches!(
                    validate_packet(&invalid, &config, true),
                    Err(Error::InvalidPacket)
                ),
                "{extension}"
            );
        }
        invalid = good.to_vec();
        invalid[23] = 3;
        assert!(matches!(
            validate_packet(&invalid, &config, true),
            Err(Error::AddressPolicy)
        ));
        invalid = good.to_vec();
        invalid[27] ^= 1;
        assert!(matches!(
            validate_packet(&invalid, &config, true),
            Err(Error::AddressPolicy)
        ));
    }
    for prefix in [
        "::/0",
        "::/16",
        "fe80::/64",
        "ff00::/16",
        "::ffff:192.0.2.0/120",
        "fd00::/8",
        "fd42::1/64",
        "fd42::/129",
    ] {
        assert!(prefix.parse::<IpPrefix>().is_err(), "{prefix}");
    }
    let mut mixed = config.clone();
    mixed.routes.push("10.30.0.0/24".parse().unwrap());
    assert!(mixed.validate().is_err());
    assert!(!config.routes[0].contains("10.30.0.9".parse().unwrap()));
    for address in ["10.20.0.2", "fd42:20::2"] {
        let address: IpAddr = address.parse().unwrap();
        let encoded = encode_assignment(address);
        assert_eq!(decode_assignment(&encoded).unwrap(), address);
        for end in 0..encoded.len() {
            assert!(decode_assignment(&encoded[..end]).is_err());
        }
        let mut duplicate = encoded.clone();
        duplicate.extend(&encoded);
        assert!(decode_assignment(&duplicate).is_err());
    }
    assert!(decode_assignment(&address_requests()).is_err());
    let mut both = encode_assignment_entry("10.20.0.2".parse().unwrap());
    both.extend(encode_assignment_entry(config.address));
    assert!(decode_assignment(&both).is_err());
    let routes: Vec<IpPrefix> = [
        "10.30.0.0/24",
        "2001:db8::/32",
        "fd42:30::/64",
        "fd42:40::9/128",
    ]
    .iter()
    .map(|value| value.parse().unwrap())
    .collect();
    let encoded = encode_routes(&routes);
    assert_eq!(decode_routes(&encoded).unwrap(), routes);
    for end in 11..43 {
        assert!(decode_routes(&encoded[..end]).is_err(), "{end}");
    }
    let mut invalid = encode_routes(&config.routes);
    invalid[0] = 7;
    assert!(decode_routes(&invalid).is_err());
}

async fn endpoint_family(ipv6: bool) -> Endpoint {
    let address = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .clear_ip_transports()
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(address.parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn ipv6_and_cross_family_quic_roundtrips_preserve_packets() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    for (underlay_v6, packet_v6) in [(true, true), (false, true), (true, false)] {
        let server = endpoint_family(underlay_v6).await;
        let client = endpoint_family(underlay_v6).await;
        let config = if packet_v6 {
            SessionConfig {
                address: "fd42:20::2".parse().unwrap(),
                routes: vec!["fd42:30::/64".parse().unwrap()],
                mtu: 1280,
            }
        } else {
            config()
        };
        let remote: IpAddr = if packet_v6 { "fd42:30::9" } else { "10.30.0.9" }
            .parse()
            .unwrap();
        let grant = Grant {
            peer: client.id(),
            network: "test".into(),
            address: config.address,
            routes: config.routes.clone(),
            mtu: config.mtu,
        };
        let cancel = CancellationToken::new();
        let (incoming, mut accepted) = mpsc::channel(4);
        let serving = tokio::spawn(serve(server.clone(), vec![grant], incoming, cancel.clone()));
        let connecting = tokio::spawn(connect(
            client.clone(),
            server.addr(),
            "test",
            CancellationToken::new(),
        ));
        let incoming = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        incoming.ready.send(true).unwrap();
        let session = connecting.await.unwrap().unwrap();
        assert_eq!(session.config, config);
        for protocol in [6, 17, 58] {
            let request = if packet_v6 {
                ipv6_packet(
                    "fd42:20::2".parse().unwrap(),
                    "fd42:30::9".parse().unwrap(),
                    1280,
                    protocol,
                )
            } else {
                packet(config.address, remote, 1280)
            };
            session.send(request.clone()).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), incoming.session.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                request
            );
            let reply = packet(remote, config.address, 1280);
            incoming.session.send(reply.clone()).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), session.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                reply
            );
        }
        assert!(matches!(
            session.send(packet(config.address, remote, 1281)).await,
            Err(Error::PacketTooLarge)
        ));
        assert_eq!(session.stats().delivery_mode, "quic_datagram");
        session.cancel();
        cancel.cancel();
        serving.await.unwrap().unwrap();
        client.close().await;
        server.close().await;
    }
}

#[tokio::test]
async fn real_iroh_assignment_packets_and_revocation() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = endpoint().await;
    let client = endpoint().await;
    let config = config();
    let cancel = CancellationToken::new();
    let grant = Grant {
        peer: client.id(),
        network: "test".into(),
        address: config.address,
        routes: config.routes.clone(),
        mtu: config.mtu,
    };
    let (incoming, mut accepted) = mpsc::channel(4);
    let serving = tokio::spawn(serve(server.clone(), vec![grant], incoming, cancel.clone()));
    let connecting = tokio::spawn(connect(
        client.clone(),
        server.addr(),
        "test",
        CancellationToken::new(),
    ));
    let incoming = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.peer, client.id());
    assert_eq!(incoming.network, "test");
    assert!(!connecting.is_finished(), "200 must wait for OS readiness");
    incoming.ready.send(true).unwrap();
    let mut session = connecting.await.unwrap().unwrap();
    assert_eq!(session.config, config);
    assert_eq!(session.stats().delivery_mode, "quic_datagram");
    assert!(session.stats().effective_datagram_ip_capacity >= usize::from(config.mtu));
    let remote = "10.30.0.9".parse().unwrap();
    assert!(matches!(
        session.send(packet(config.address, remote, 1281)).await,
        Err(Error::PacketTooLarge)
    ));
    let request = packet(config.address, remote, 1280);
    session.send(request.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), incoming.session.recv())
            .await
            .unwrap()
            .unwrap(),
        request
    );
    let response = packet(remote, config.address, 1200);
    incoming.session.send(response.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .unwrap()
            .unwrap(),
        response
    );
    session.config.address = remote;
    assert!(
        matches!(
            session.send(packet(remote, remote, 20)).await,
            Err(Error::AddressPolicy)
        ),
        "metadata mutation must not broaden policy"
    );
    assert_eq!(session.stats().packets_dropped, 2);
    assert_eq!(session.stats().datagrams_sent, 1);
    assert_eq!(session.stats().datagrams_received, 1);
    // Keep both producer queues continuously busy and require bidirectional progress.
    let sending = async {
        loop {
            session.send(request.clone()).await.unwrap();
            incoming.session.send(response.clone()).await.unwrap();
            tokio::task::yield_now().await;
        }
    };
    let receiving = async {
        for _ in 0..100 {
            assert!(session.recv().await.is_some());
            assert!(incoming.session.recv().await.is_some());
        }
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! { _ = sending => unreachable!(), _ = receiving => {} }
    })
    .await
    .unwrap();
    incoming.session.cancel();
    tokio::time::timeout(Duration::from_secs(5), async {
        while session.recv().await.is_some() {}
    })
    .await
    .unwrap();
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn unauthorized_peer_and_failed_readiness_never_join() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = endpoint().await;
    let client = endpoint().await;
    let stranger = endpoint().await;
    let config = config();
    let cancel = CancellationToken::new();
    let grant = Grant {
        peer: client.id(),
        network: "test".into(),
        address: config.address,
        routes: config.routes,
        mtu: config.mtu,
    };
    let (incoming, mut accepted) = mpsc::channel(4);
    let serving = tokio::spawn(serve(server.clone(), vec![grant], incoming, cancel.clone()));
    assert!(matches!(
        connect(
            stranger.clone(),
            server.addr(),
            "test",
            CancellationToken::new()
        )
        .await,
        Err(Error::RejectedWithReason {
            status: StatusCode::FORBIDDEN,
            reason: RejectionReason::PeerNetworkNotApproved,
            ..
        })
    ));
    assert!(matches!(
        connect(
            client.clone(),
            server.addr(),
            "other",
            CancellationToken::new()
        )
        .await,
        Err(Error::RejectedWithReason {
            status: StatusCode::FORBIDDEN,
            reason: RejectionReason::PeerNetworkNotApproved,
            ..
        })
    ));
    assert!(accepted.try_recv().is_err());
    let connecting = tokio::spawn(connect(
        client.clone(),
        server.addr(),
        "test",
        CancellationToken::new(),
    ));
    let incoming = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    incoming.session.cancel();
    incoming.ready.send(false).unwrap();
    drop(incoming.session);
    assert!(matches!(
        connecting.await.unwrap(),
        Err(Error::Rejected(StatusCode::SERVICE_UNAVAILABLE))
    ));
    cancel.cancel();
    serving.await.unwrap().unwrap();
    stranger.close().await;
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn oversized_and_truncated_capsules_fail_boundedly() {
    let (mut tx, mut rx) = tokio::io::duplex(64);
    let mut header = vec![0];
    encode_varint(MAX_CAPSULE as u64 + 1, &mut header);
    tx.write_all(&header).await.unwrap();
    assert!(matches!(
        read_capsule(&mut rx).await,
        Err(Error::Protocol(_))
    ));
    let (mut tx, mut rx) = tokio::io::duplex(64);
    tx.write_all(&[0x40]).await.unwrap();
    drop(tx);
    assert!(matches!(read_capsule(&mut rx).await, Err(Error::Io(_))));
    for wire in [&[0, 0x40][..], &[0, 3, 1][..]] {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(wire).await.unwrap();
        drop(tx);
        assert!(matches!(read_capsule(&mut rx).await, Err(Error::Io(_))));
    }
}

#[tokio::test]
async fn invalid_wire_packets_drop_and_full_receiver_does_not_block_cancel() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = endpoint().await;
    let client = endpoint().await;
    let (server_conn, client_conn) = tokio::join!(
        async {
            server
                .accept()
                .await
                .unwrap()
                .accept()
                .unwrap()
                .await
                .unwrap()
        },
        async { client.connect(server.addr(), ALPN).await.unwrap() }
    );
    wait_datagram_capacity(&server_conn, 0, 1280).await.unwrap();
    let config = config();
    let cancel = CancellationToken::new();
    let (session, outgoing, packets) = session_parts(config.clone(), Role::Gateway, cancel.clone());
    let counters = session.counters.clone();
    let (_wire, io) = tokio::io::duplex(64 * 1024);
    let worker = tokio::spawn(run_session(
        io,
        DatagramPath {
            connection: server_conn,
            stream_id: 0,
            low_capacity_since: None,
        },
        config.clone(),
        Role::Gateway,
        "test-network".into(),
        "test-session".into(),
        outgoing,
        packets,
        cancel.clone(),
        counters,
    ));
    let bad = packet(
        "10.20.0.3".parse().unwrap(),
        "10.30.0.9".parse().unwrap(),
        20,
    );
    client_conn.send_datagram(encode_datagram(0, &bad)).unwrap();
    let good = packet(config.address, "10.30.0.9".parse().unwrap(), 20);
    for _ in 0..100 {
        client_conn
            .send_datagram(encode_datagram(0, &good))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while session.stats().packets_dropped < 37 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(session.stats().packets_received, 64);
    session.cancel();
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(session.recv().await.is_none());
    client.close().await;
    server.close().await;
}

#[test]
fn http_datagram_stream_context_and_capacity_policy() {
    for stream in [0, 4, 252, 256, 65536] {
        let bytes = Bytes::from_static(b"packet");
        let encoded = encode_datagram(stream, &bytes);
        assert_eq!(
            decode_datagram(encoded.clone(), stream).unwrap(),
            Some(bytes)
        );
        assert!(decode_datagram(encoded, stream + 4).unwrap().is_none());
    }
    assert!(
        decode_datagram(Bytes::from_static(&[0, 1]), 0)
            .unwrap()
            .is_none()
    );
    for wire in [
        &[][..],
        &[0x40][..],
        &[0][..],
        &[0, 0x40][..],
        &[0xff; 8][..],
    ] {
        assert!(decode_datagram(Bytes::copy_from_slice(wire), 0).is_err());
    }
    assert_eq!(datagram_capacity(Some(1300), 0).unwrap(), 1298);
    assert_eq!(datagram_capacity(Some(1300), 256).unwrap(), 1297);
    assert!(matches!(
        datagram_capacity(None, 0),
        Err(Error::DatagramsUnsupported)
    ));
    assert!(require_capacity(1280, 1280).is_ok());
    assert!(matches!(
        require_capacity(1279, 1280),
        Err(Error::InsufficientDatagramMtu {
            required: 1280,
            available: 1279
        })
    ));
}

async fn configured_endpoint(config: iroh::endpoint::QuicTransportConfig) -> Endpoint {
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .transport_config(config)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn missing_quic_datagram_support_fails_setup() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = configured_endpoint(
        iroh::endpoint::QuicTransportConfig::builder()
            .datagram_receive_buffer_size(None)
            .build(),
    )
    .await;
    let client = endpoint().await;
    let listening = tokio::spawn({
        let server = server.clone();
        async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let _ = conn.closed().await;
        }
    });
    assert!(matches!(
        connect(
            client.clone(),
            server.addr(),
            "test",
            CancellationToken::new()
        )
        .await,
        Err(Error::DatagramsUnsupported)
    ));
    client.close().await;
    server.close().await;
    listening.await.unwrap();
}

#[tokio::test]
async fn missing_h3_datagram_setting_fails_setup() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = endpoint().await;
    let client = endpoint().await;
    let listening = tokio::spawn({
        let server = server.clone();
        async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let mut h3 = h3::server::builder()
                .enable_datagram(false)
                .enable_extended_connect(true)
                .build::<_, Bytes>(crate::h3_iroh::Connection::new(conn))
                .await
                .unwrap();
            let (_, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream
                .send_response(
                    Response::builder()
                        .status(200)
                        .header("capsule-protocol", "?1")
                        .header("x-datum-ip-mtu", "1280")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            let _ = h3.accept().await;
        }
    });
    assert!(matches!(
        connect(
            client.clone(),
            server.addr(),
            "test",
            CancellationToken::new()
        )
        .await,
        Err(Error::DatagramsUnsupported)
    ));
    client.close().await;
    server.close().await;
    listening.await.unwrap();
}

#[tokio::test]
async fn constrained_mtu_rejects_before_gateway_admission() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = configured_endpoint(
        iroh::endpoint::QuicTransportConfig::builder()
            .mtu_discovery_config(None)
            .build(),
    )
    .await;
    let client = endpoint().await;
    let config = config();
    let cancel = CancellationToken::new();
    let grant = Grant {
        peer: client.id(),
        network: "test".into(),
        address: config.address,
        routes: config.routes,
        mtu: config.mtu,
    };
    let (incoming, mut accepted) = mpsc::channel(4);
    let serving = tokio::spawn(serve(server.clone(), vec![grant], incoming, cancel.clone()));
    let result = connect(
        client.clone(),
        server.addr(),
        "test",
        CancellationToken::new(),
    )
    .await;
    assert!(
        matches!(result, Err(Error::InsufficientDatagramMtu { required:1280,available }) if available<1280)
    );
    assert!(accepted.try_recv().is_err());
    cancel.cancel();
    serving.await.unwrap().unwrap();
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn path_capacity_failure_records_reason_before_close() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    let server = configured_endpoint(
        iroh::endpoint::QuicTransportConfig::builder()
            .mtu_discovery_config(None)
            .build(),
    )
    .await;
    let client = endpoint().await;
    let (server_conn, _client_conn) = tokio::join!(
        async { server.accept().await.unwrap().await.unwrap() },
        async { client.connect(server.addr(), ALPN).await.unwrap() }
    );
    let config = config();
    let cancel = CancellationToken::new();
    let (session, outgoing, packets) = session_parts(config.clone(), Role::Gateway, cancel.clone());
    let counters = session.counters.clone();
    let (_wire, io) = tokio::io::duplex(1024);
    let worker = tokio::spawn(run_session(
        io,
        DatagramPath {
            connection: server_conn,
            stream_id: 0,
            low_capacity_since: None,
        },
        config,
        Role::Gateway,
        "test-network".into(),
        "test-session".into(),
        outgoing,
        packets,
        cancel,
        counters,
    ));
    assert!(
        tokio::time::timeout(
            DATAGRAM_SETUP_TIMEOUT + Duration::from_secs(1),
            session.recv()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(session.last_error().unwrap().contains("MTU 1280"));
    assert_eq!(session.stats().mtu_errors, 1);
    assert!(session.stats().effective_datagram_ip_capacity < 1280);
    worker.await.unwrap();
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn reliable_packet_fallback_is_rejected_and_remote_mtu_reason_is_safe() {
    let _permit = NETWORK_TESTS.acquire().await.unwrap();
    for remote_mtu in [false, true] {
        let server = endpoint().await;
        let client = endpoint().await;
        let (server_conn, client_conn) = tokio::join!(
            async { server.accept().await.unwrap().await.unwrap() },
            async { client.connect(server.addr(), ALPN).await.unwrap() }
        );
        wait_datagram_capacity(&server_conn, 0, 1280).await.unwrap();
        let config = config();
        let cancel = CancellationToken::new();
        let (session, outgoing, packets) =
            session_parts(config.clone(), Role::Gateway, cancel.clone());
        let counters = session.counters.clone();
        let (mut wire, io) = tokio::io::duplex(2048);
        let worker = tokio::spawn(run_session(
            io,
            DatagramPath {
                connection: server_conn,
                stream_id: 0,
                low_capacity_since: None,
            },
            config,
            Role::Gateway,
            "test-network".into(),
            "test-session".into(),
            outgoing,
            packets,
            cancel,
            counters,
        ));
        if remote_mtu {
            client_conn.close(
                iroh::endpoint::VarInt::from_u32(MTU_CLOSE_CODE),
                b"untrusted peer secret should not leak",
            );
        } else {
            write_capsule(&mut wire, 0, &[0]).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(2), session.recv())
                .await
                .unwrap()
                .is_none()
        );
        let error = session.last_error().unwrap();
        if remote_mtu {
            assert!(error.contains("MTU"));
            assert!(!error.contains("secret"));
            assert_eq!(session.stats().mtu_errors, 1);
        } else {
            assert!(error.contains("reliable IP packet capsules"));
            assert_eq!(session.stats().protocol_errors, 1);
        }
        worker.await.unwrap();
        client.close().await;
        server.close().await;
    }
}
#[test]
fn transient_path_mtu_probe_pauses_but_persistent_low_mtu_fails() {
    let now = tokio::time::Instant::now();
    let mut low = None;
    assert!(!super::capacity_ready(1160, 1280, &mut low, now).unwrap());
    assert!(
        !super::capacity_ready(
            1160,
            1280,
            &mut low,
            now + std::time::Duration::from_secs(1)
        )
        .unwrap()
    );
    assert!(
        super::capacity_ready(
            1400,
            1280,
            &mut low,
            now + std::time::Duration::from_secs(2)
        )
        .unwrap()
    );
    assert!(low.is_none());
    assert!(!super::capacity_ready(1160, 1280, &mut low, now).unwrap());
    assert!(matches!(
        super::capacity_ready(1160, 1280, &mut low, now + super::DATAGRAM_SETUP_TIMEOUT),
        Err(super::Error::InsufficientDatagramMtu { .. })
    ));
}
