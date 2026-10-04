//! Local independent-client lab for standard H3 CONNECT-UDP and CONNECT-IP.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig, ip,
    standard_connect_udp_target,
};
use h3::error::Code;
use h3::ext::Protocol;
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError};
use http::{Method, Response, StatusCode};
use iroh::{EndpointAddr, SecretKey};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const DATAGRAM_CAPSULE: u64 = 0;
const MAX_CAPSULE: usize = 64 * 1024;
const IP_PATH: &str = "/.well-known/masque/ip/*/*/";
const IP_NETWORK: &str = "masque-interop";
const IP_ASSIGNED: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
const IP_REMOTE: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 9);

struct Options {
    listen: SocketAddr,
    origin: SocketAddr,
    cert_out: PathBuf,
    ready_out: PathBuf,
}

fn options() -> Result<Options> {
    let mut listen = "127.0.0.1:0".parse().unwrap();
    let mut origin = None;
    let mut cert_out = None;
    let mut ready_out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| anyhow!("missing value after {arg}"))?;
        match arg.as_str() {
            "--listen" => listen = value.parse().context("invalid --listen")?,
            "--origin" => origin = Some(value.parse().context("invalid --origin")?),
            "--cert-out" => cert_out = Some(value.into()),
            "--ready-out" => ready_out = Some(value.into()),
            _ => bail!("unknown argument {arg}"),
        }
    }
    Ok(Options {
        listen,
        origin: origin.ok_or_else(|| anyhow!("--origin is required"))?,
        cert_out: cert_out.ok_or_else(|| anyhow!("--cert-out is required"))?,
        ready_out: ready_out.ok_or_else(|| anyhow!("--ready-out is required"))?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = options()?;

    let edge = Transport::bind(
        TransportConfig::new(SecretKey::generate()).bind_addr("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .context("bind Connect edge transport")?;
    let backend = Transport::bind(
        TransportConfig::new(SecretKey::generate()).bind_addr("127.0.0.1:0".parse().unwrap()),
    )
    .await
    .context("bind Connect service transport")?;
    let destination = DestinationId::udp(options.origin.port());
    backend
        .replace_policy(Policy {
            destinations: HashMap::from([(
                destination.clone(),
                DestinationPolicy {
                    target: Target::Udp(options.origin),
                    access: Access::Peers(HashSet::from([edge.endpoint_id()])),
                },
            )]),
        })
        .await
        .context("install test service policy")?;
    let details = backend.connection_details();
    let backend_addr = details.direct_addresses.into_iter().fold(
        EndpointAddr::new(details.endpoint_id),
        EndpointAddr::with_ip_addr,
    );
    let mut ip_registration = backend
        .register_ip_grant(ip::Grant {
            peer: edge.endpoint_id(),
            network: IP_NETWORK.into(),
            address: IpAddr::V4(IP_ASSIGNED),
            routes: vec!["10.30.0.9/32".parse()?],
            mtu: 1280,
        })
        .await
        .context("install test CONNECT-IP grant")?;
    tokio::spawn(async move {
        while let Some(incoming) = ip_registration.recv().await {
            if incoming.ready.send(true).is_err() {
                continue;
            }
            tokio::spawn(async move {
                while let Some(packet) = incoming.session.recv().await {
                    let Some(reply) = reverse_ipv4_packet(packet) else {
                        continue;
                    };
                    if incoming.session.send(reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let certified = generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&options.cert_out, certified.cert.pem()).context("write test CA certificate")?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
    )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    Arc::get_mut(&mut server_config.transport)
        .expect("new transport config is unique")
        .datagram_receive_buffer_size(Some(1024 * 1024));
    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    let public_addr = endpoint.local_addr()?;
    std::fs::write(
        &options.ready_out,
        serde_json::to_vec_pretty(&serde_json::json!({
            "proxy_addr": public_addr.to_string(),
            "proxy_uri_template": format!(
                "https://localhost:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                public_addr.port()
            ),
            "allowed_target": options.origin.to_string(),
            "ip_uri": format!("https://localhost:{}{IP_PATH}", public_addr.port()),
            "ip_assigned": IP_ASSIGNED.to_string(),
            "ip_remote": IP_REMOTE.to_string(),
            "service_endpoint": details.endpoint_id.to_string(),
        }))?,
    )
    .context("write readiness metadata")?;
    println!("MASQUE interop lab ready on {public_addr}");

    let cancel = CancellationToken::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let edge = edge.clone();
                let backend_addr = backend_addr.clone();
                let destination = destination.clone();
                let allowed = options.origin;
                let cancel = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(incoming, edge, backend_addr, destination, allowed, cancel).await {
                        eprintln!("MASQUE connection failed: {error:#}");
                    }
                });
            }
        }
    }
    cancel.cancel();
    endpoint.close(0u32.into(), b"lab shutdown");
    edge.shutdown().await;
    backend.shutdown().await;
    Ok(())
}

fn reverse_ipv4_packet(packet: Bytes) -> Option<Bytes> {
    if packet.len() < 20 || packet[0] != 0x45 {
        return None;
    }
    let mut bytes = packet.to_vec();
    let source = <[u8; 4]>::try_from(&bytes[12..16]).ok()?;
    let destination = <[u8; 4]>::try_from(&bytes[16..20]).ok()?;
    bytes[12..16].copy_from_slice(&destination);
    bytes[16..20].copy_from_slice(&source);
    bytes[10..12].fill(0);
    let mut sum: u32 = bytes[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    bytes[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Some(Bytes::from(bytes))
}

async fn serve_connection(
    incoming: quinn::Incoming,
    edge: Transport,
    backend: EndpointAddr,
    destination: DestinationId,
    allowed: SocketAddr,
    cancel: CancellationToken,
) -> Result<()> {
    let connection = incoming.await.context("accept QUIC")?;
    let datagrams_available = connection.max_datagram_size().is_some();
    let mut h3 = h3::server::builder()
        .enable_datagram(datagrams_available)
        .enable_extended_connect(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .context("start HTTP/3")?;
    let allowed_host = allowed.ip().to_string();
    let mut datagram_reader = datagrams_available.then(|| h3.get_datagram_reader());
    let (closed_tx, mut closed_rx) = mpsc::channel::<u64>(64);
    let mut associations = HashMap::<u64, mpsc::Sender<Bytes>>::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = h3.accept() => {
                let Some(resolver) = accepted.context("accept request")? else { break };
                let (request, mut stream) = resolver.resolve_request().await.context("decode request")?;
                let is_connect_ip = request.method() == Method::CONNECT
                    && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_IP);
                if is_connect_ip {
                    let common_valid = request.uri().scheme_str() == Some("https")
                        && request.uri().query().is_none()
                        && request.headers().get(CAPSULE_PROTOCOL).and_then(|value| value.to_str().ok()) == Some("?1");
                    let target = connect_ip_target(request.uri().path());
                    if !common_valid || target.is_none() {
                        stream.send_response(
                            Response::builder().status(StatusCode::BAD_REQUEST).body(())?
                        ).await?;
                        stream.finish().await?;
                        continue;
                    }
                    if target != Some(("*", "*")) {
                        stream.send_response(
                            Response::builder().status(StatusCode::FORBIDDEN).body(())?
                        ).await?;
                        stream.finish().await?;
                        continue;
                    }
                    if !datagrams_available {
                        stream.send_response(
                            Response::builder().status(StatusCode::SERVICE_UNAVAILABLE).body(())?
                        ).await?;
                        stream.finish().await?;
                        continue;
                    }
                    let session = match ip::connect(
                        edge.endpoint(),
                        backend.clone(),
                        IP_NETWORK,
                        cancel.child_token(),
                    ).await {
                        Ok(session) => session,
                        Err(error) => {
                            eprintln!("open Connect IP session: {error}");
                            stream.send_response(
                                Response::builder().status(StatusCode::BAD_GATEWAY).body(())?
                            ).await?;
                            stream.finish().await?;
                            continue;
                        }
                    };
                    let stream_id = stream.id();
                    let association_id = stream_id.into_inner();
                    let mut datagram_sender = h3.get_datagram_sender(stream_id);
                    stream.send_response(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CAPSULE_PROTOCOL, "?1")
                            .body(())?
                    ).await.context("send CONNECT-IP response")?;

                    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Bytes>(64);
                    associations.insert(association_id, incoming_tx);
                    let closed_tx = closed_tx.clone();
                    let association_cancel = cancel.child_token();
                    tokio::spawn(async move {
                        let result: Result<()> = async {
                            let mut capsule_bytes = BytesMut::new();
                            let request = loop {
                                if let Some(capsule) = take_capsule(&mut capsule_bytes)? {
                                    break capsule;
                                }
                                let Some(mut chunk) = stream.recv_data().await? else {
                                    bail!("CONNECT-IP stream ended before ADDRESS_REQUEST");
                                };
                                let remaining = chunk.remaining();
                                capsule_bytes.extend_from_slice(&chunk.copy_to_bytes(remaining));
                            };
                            let request_id = validate_ipv4_address_request(&request)?;
                            stream.send_data(address_assignment_capsule(request_id)).await?;
                            stream.send_data(route_advertisement_capsule(false)).await?;
                            // RFC 9484 updates are complete snapshots. Exercise a withdrawal and
                            // restoration before making the route usable for packet forwarding.
                            stream.send_data(route_advertisement_capsule(true)).await?;
                            stream.send_data(route_advertisement_capsule(false)).await?;
                            loop {
                                tokio::select! {
                                    _ = association_cancel.cancelled() => break,
                                    incoming = incoming_rx.recv() => {
                                        let Some(packet) = incoming else { break };
                                        session.send(packet).await.context("send internal IP packet")?;
                                    }
                                    incoming = session.recv() => {
                                        let Some(packet) = incoming else { break };
                                        let mut framed = Vec::with_capacity(packet.len() + 1);
                                        framed.push(0);
                                        framed.extend_from_slice(&packet);
                                        match datagram_sender.send_datagram(Bytes::from(framed)) {
                                            Ok(()) => {}
                                            Err(SendDatagramError::TooLarge { .. }) => continue,
                                            Err(error) => return Err(error.into()),
                                        }
                                    }
                                }
                            }
                            Ok(())
                        }.await;
                        if let Err(error) = result {
                            eprintln!("CONNECT-IP association failed: {error:#}");
                        }
                        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                        let _ = closed_tx.send(association_id).await;
                    });
                    continue;
                }
                let target = match standard_connect_udp_target(&request) {
                    Ok(target) => target,
                    Err(_) => {
                        stream.send_response(
                            Response::builder().status(StatusCode::BAD_REQUEST).body(())?
                        ).await?;
                        stream.finish().await?;
                        continue;
                    }
                };
                if target != (allowed_host.clone(), allowed.port()) {
                    stream.send_response(
                        Response::builder().status(StatusCode::FORBIDDEN).body(())?
                    ).await?;
                    stream.finish().await?;
                    continue;
                }

                let tunnel = match edge
                    .connect_udp(backend.clone(), destination.clone(), cancel.child_token())
                    .await
                {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        eprintln!("open Connect service association: {error:#}");
                        stream.send_response(
                            Response::builder().status(StatusCode::BAD_GATEWAY).body(())?
                        ).await?;
                        stream.finish().await?;
                        continue;
                    }
                };
                let stream_id = stream.id();
                let association_id = stream_id.into_inner();
                let datagram_sender = datagrams_available.then(|| h3.get_datagram_sender(stream_id));
                stream.send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CAPSULE_PROTOCOL, "?1")
                        .body(())?
                ).await.context("send CONNECT-UDP response")?;

                let (incoming_tx, mut incoming_rx) = mpsc::channel::<Bytes>(64);
                associations.insert(association_id, incoming_tx);
                let closed_tx = closed_tx.clone();
                let association_cancel = cancel.child_token();
                tokio::spawn(async move {
                    if let Some(mut datagram_sender) = datagram_sender {
                        loop {
                            tokio::select! {
                                _ = association_cancel.cancelled() => break,
                                incoming = incoming_rx.recv() => {
                                    let Some(payload) = incoming else { break };
                                    if let Err(error) = tunnel.send(payload).await {
                                        eprintln!("send through Connect service: {error:#}");
                                        break;
                                    }
                                }
                                incoming = tunnel.recv() => {
                                    let Some(payload) = incoming else { break };
                                    let mut framed = Vec::with_capacity(payload.len() + 1);
                                    framed.push(0);
                                    framed.extend_from_slice(&payload);
                                    match datagram_sender.send_datagram(Bytes::from(framed)) {
                                        Ok(()) => {}
                                        Err(SendDatagramError::TooLarge { .. }) => continue,
                                        Err(error) => {
                                            eprintln!("send standard HTTP Datagram: {error}");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        let mut capsules = BytesMut::new();
                        loop {
                            tokio::select! {
                                _ = association_cancel.cancelled() => break,
                                incoming = stream.recv_data() => {
                                    let chunk = match incoming {
                                        Ok(Some(mut chunk)) => {
                                            let remaining = chunk.remaining();
                                            chunk.copy_to_bytes(remaining)
                                        }
                                        Ok(None) => break,
                                        Err(error) => {
                                            eprintln!("read capsule stream: {error}");
                                            break;
                                        }
                                    };
                                    capsules.extend_from_slice(&chunk);
                                    loop {
                                        match take_capsule(&mut capsules) {
                                            Ok(Some((DATAGRAM_CAPSULE, payload))) => {
                                                let Some(payload) = payload.strip_prefix(&[0]) else { continue };
                                                if let Err(error) = tunnel.send(Bytes::copy_from_slice(payload)).await {
                                                    eprintln!("send capsule through Connect service: {error:#}");
                                                    break;
                                                }
                                            }
                                            Ok(Some(_)) => continue,
                                            Ok(None) => break,
                                            Err(error) => {
                                                eprintln!("decode capsule: {error:#}");
                                                capsules.clear();
                                                break;
                                            }
                                        }
                                    }
                                }
                                incoming = tunnel.recv() => {
                                    let Some(payload) = incoming else { break };
                                    if let Err(error) = stream.send_data(datagram_capsule(&payload)).await {
                                        eprintln!("send DATAGRAM capsule: {error}");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                    let _ = closed_tx.send(association_id).await;
                });
            }
            incoming = async { datagram_reader.as_mut().unwrap().read_datagram().await }, if datagram_reader.is_some() => {
                let datagram = incoming.context("read standard HTTP Datagram")?;
                let association_id = datagram.stream_id().into_inner();
                let payload = datagram.into_payload();
                if payload.first() != Some(&0) { continue; }
                if let Some(sender) = associations.get(&association_id) {
                    let _ = sender.try_send(payload.slice(1..));
                }
            }
            Some(association_id) = closed_rx.recv() => {
                associations.remove(&association_id);
            }
        }
    }
    cancel.cancel();
    Ok(())
}

fn connect_ip_target(path: &str) -> Option<(&str, &str)> {
    let suffix = path
        .strip_prefix("/.well-known/masque/ip/")?
        .strip_suffix('/')?;
    let mut parts = suffix.split('/');
    let target = parts.next()?;
    let protocol = parts.next()?;
    (!target.is_empty() && !protocol.is_empty() && parts.next().is_none())
        .then_some((target, protocol))
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16_384 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1usize << (first >> 6);
    if bytes.len() < width {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, width))
}

fn datagram_capsule(payload: &[u8]) -> Bytes {
    let mut capsule = Vec::with_capacity(payload.len() + 4);
    encode_varint(DATAGRAM_CAPSULE, &mut capsule);
    encode_varint((payload.len() + 1) as u64, &mut capsule);
    encode_varint(0, &mut capsule);
    capsule.extend_from_slice(payload);
    Bytes::from(capsule)
}

fn capsule(kind: u64, payload: &[u8]) -> Bytes {
    let mut capsule = Vec::with_capacity(payload.len() + 16);
    encode_varint(kind, &mut capsule);
    encode_varint(payload.len() as u64, &mut capsule);
    capsule.extend_from_slice(payload);
    Bytes::from(capsule)
}

fn validate_ipv4_address_request(request: &(u64, Bytes)) -> Result<u64> {
    if request.0 != 2 {
        bail!("expected RFC 9484 ADDRESS_REQUEST capsule");
    }
    let (request_id, width) =
        decode_varint(&request.1).ok_or_else(|| anyhow!("invalid ADDRESS_REQUEST ID"))?;
    if request_id == 0 || request.1[width..] != [4, 0, 0, 0, 0, 32] {
        bail!("lab requires one wildcard IPv4 host ADDRESS_REQUEST");
    }
    Ok(request_id)
}

fn address_assignment_capsule(request_id: u64) -> Bytes {
    let mut payload = Vec::with_capacity(14);
    encode_varint(request_id, &mut payload);
    payload.push(4);
    payload.extend_from_slice(&IP_ASSIGNED.octets());
    payload.push(32);
    capsule(1, &payload)
}

fn route_advertisement_capsule(withdraw: bool) -> Bytes {
    if withdraw {
        return capsule(3, &[]);
    }
    let mut payload = Vec::with_capacity(10);
    payload.push(4);
    payload.extend_from_slice(&IP_REMOTE.octets());
    payload.extend_from_slice(&IP_REMOTE.octets());
    payload.push(0);
    capsule(3, &payload)
}

fn take_capsule(buffer: &mut BytesMut) -> Result<Option<(u64, Bytes)>> {
    let Some((kind, kind_width)) = decode_varint(buffer) else {
        return Ok(None);
    };
    let Some((length, length_width)) = decode_varint(&buffer[kind_width..]) else {
        return Ok(None);
    };
    if length > MAX_CAPSULE as u64 {
        bail!("capsule exceeds {MAX_CAPSULE} bytes");
    }
    let header = kind_width + length_width;
    let total = header + length as usize;
    if buffer.len() < total {
        return Ok(None);
    }
    let capsule = buffer.split_to(total).freeze();
    Ok(Some((kind, capsule.slice(header..))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_decoder_is_incremental_and_preserves_boundaries() {
        let first = datagram_capsule(b"first");
        let second = datagram_capsule(b"second");
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&first[..2]);
        assert!(take_capsule(&mut wire).unwrap().is_none());
        wire.extend_from_slice(&first[2..]);
        wire.extend_from_slice(&second);

        let (_, first_payload) = take_capsule(&mut wire).unwrap().unwrap();
        let (_, second_payload) = take_capsule(&mut wire).unwrap().unwrap();
        assert_eq!(&first_payload[..], b"\0first");
        assert_eq!(&second_payload[..], b"\0second");
        assert!(wire.is_empty());
    }

    #[test]
    fn capsule_decoder_rejects_an_oversized_length_before_allocating() {
        let mut header = Vec::new();
        encode_varint(DATAGRAM_CAPSULE, &mut header);
        encode_varint((MAX_CAPSULE + 1) as u64, &mut header);
        assert!(take_capsule(&mut BytesMut::from(&header[..])).is_err());
    }

    #[test]
    fn connect_ip_default_target_is_exact_and_other_targets_remain_policy_scoped() {
        assert_eq!(connect_ip_target(IP_PATH), Some(("*", "*")));
        assert_eq!(
            connect_ip_target("/.well-known/masque/ip/10.30.0.9/17/"),
            Some(("10.30.0.9", "17"))
        );
        assert_eq!(connect_ip_target("/.well-known/masque/ip/*/*"), None);
        assert_eq!(connect_ip_target("/.well-known/masque/ip/*/*/extra/"), None);
    }

    #[test]
    fn connect_ip_capsules_encode_assignment_update_withdrawal_and_restoration() {
        let request = (2, Bytes::from_static(&[7, 4, 0, 0, 0, 0, 32]));
        assert_eq!(validate_ipv4_address_request(&request).unwrap(), 7);
        assert_eq!(
            address_assignment_capsule(7).as_ref(),
            &[1, 7, 7, 4, 10, 20, 0, 2, 32]
        );
        assert_eq!(route_advertisement_capsule(true).as_ref(), &[3, 0]);
        assert_eq!(
            route_advertisement_capsule(false).as_ref(),
            &[3, 10, 4, 10, 30, 0, 9, 10, 30, 0, 9, 0]
        );
    }
}
