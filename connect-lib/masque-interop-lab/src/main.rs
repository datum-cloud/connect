//! Local independent-client lab: standard H3 CONNECT-UDP -> Connect transport -> UDP origin.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use connect_transport::{
    Access, DestinationId, DestinationPolicy, Policy, Target, Transport, TransportConfig,
    standard_connect_udp_target,
};
use h3::error::Code;
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError};
use http::{Response, StatusCode};
use iroh::{EndpointAddr, SecretKey};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const DATAGRAM_CAPSULE: u64 = 0;
const MAX_CAPSULE: usize = 64 * 1024;

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
}
