//! Standards-facing HTTP/3 CONNECT-UDP edge for Datum Connect.
//!
//! The edge deliberately has no resolver or arbitrary-dial API. Every public
//! MASQUE target must be mapped to an already-authorized Connect destination.

use std::{collections::HashMap, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes, BytesMut};
use connect_transport::{DestinationId, Transport, standard_connect_udp_target};
use h3::error::Code;
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError};
use http::{Response, StatusCode};
use iroh::EndpointAddr;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const DATAGRAM_CAPSULE: u64 = 0;
const MAX_CAPSULE: usize = 64 * 1024;

/// A single exact public target routed to a policy-checked Connect destination.
#[derive(Clone, Debug)]
pub struct Route {
    pub target_host: String,
    pub target_port: u16,
    pub backend: EndpointAddr,
    pub destination: DestinationId,
}

/// Bound edge listener. Binding is separate from serving so callers can publish
/// readiness only after the UDP socket and TLS configuration are usable.
pub struct Server {
    endpoint: quinn::Endpoint,
    transport: Transport,
    routes: Arc<HashMap<(String, u16), Route>>,
    max_connections: usize,
    max_associations_per_connection: usize,
}

impl Server {
    pub fn bind(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
    ) -> Result<Self> {
        Self::bind_with_limits(listen, tls, transport, routes, 1024, 128)
    }

    pub fn bind_with_limits(
        listen: SocketAddr,
        tls: rustls::ServerConfig,
        transport: Transport,
        routes: Vec<Route>,
        max_connections: usize,
        max_associations_per_connection: usize,
    ) -> Result<Self> {
        if max_connections == 0 || max_associations_per_connection == 0 {
            bail!("MASQUE connection and association limits must be nonzero");
        }
        let indexed = index_routes(routes)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(tls).context("build QUIC TLS configuration")?,
        ));
        Arc::get_mut(&mut server_config.transport)
            .expect("new transport configuration is unique")
            .datagram_receive_buffer_size(Some(1024 * 1024));
        let endpoint = quinn::Endpoint::server(server_config, listen)
            .context("bind MASQUE HTTP/3 listener")?;
        Ok(Self {
            endpoint,
            transport,
            routes: Arc::new(indexed),
            max_connections,
            max_associations_per_connection,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("read MASQUE listener address")
    }

    pub async fn serve(self, cancel: CancellationToken) -> Result<()> {
        let connections = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let permit = tokio::select! {
                _ = cancel.cancelled() => break,
                permit = connections.clone().acquire_owned() => permit.expect("server semaphore is never closed"),
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let transport = self.transport.clone();
                    let routes = self.routes.clone();
                    let connection_cancel = cancel.child_token();
                    let max_associations = self.max_associations_per_connection;
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve_connection(
                            incoming, transport, routes, max_associations, connection_cancel
                        ).await {
                            tracing::warn!(error = %format!("{error:#}"), "masque_connection_failed");
                        }
                    });
                }
            }
        }
        self.endpoint.close(0u32.into(), b"server shutdown");
        Ok(())
    }
}

fn index_routes(routes: Vec<Route>) -> Result<HashMap<(String, u16), Route>> {
    if routes.is_empty() {
        bail!("MASQUE edge requires at least one exact route");
    }
    let mut indexed = HashMap::new();
    for route in routes {
        let key = (route.target_host.to_ascii_lowercase(), route.target_port);
        if indexed.insert(key.clone(), route).is_some() {
            bail!("duplicate MASQUE route for {}:{}", key.0, key.1);
        }
    }
    Ok(indexed)
}

/// Load a caller-provisioned PEM certificate chain and private key for `h3`.
pub fn load_tls(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("open certificate chain {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("open private key {}", key_path.display()))?;
    load_tls_pem(&cert_pem, &key_pem)
}

/// Build an HTTP/3 TLS configuration from PEM bytes already read by the caller.
pub fn load_tls_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("decode PEM certificate chain")?;
    if certs.is_empty() {
        bail!("certificate chain contains no certificates");
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("decode PEM private key")?;
    tls_config(certs, key)
}

pub fn tls_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("certificate and private key do not match")?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

async fn serve_connection(
    incoming: quinn::Incoming,
    transport: Transport,
    routes: Arc<HashMap<(String, u16), Route>>,
    max_associations: usize,
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
                        stream.send_response(Response::builder().status(StatusCode::BAD_REQUEST).body(())?).await?;
                        stream.finish().await?;
                        continue;
                    }
                };
                if associations.len() >= max_associations {
                    stream.send_response(Response::builder().status(StatusCode::TOO_MANY_REQUESTS).body(())?).await?;
                    stream.finish().await?;
                    continue;
                }
                let route_key = (target.0.to_ascii_lowercase(), target.1);
                let Some(route) = routes.get(&route_key).cloned() else {
                    stream.send_response(Response::builder().status(StatusCode::FORBIDDEN).body(())?).await?;
                    stream.finish().await?;
                    continue;
                };

                let tunnel = match transport.connect_udp(
                    route.backend, route.destination, cancel.child_token()
                ).await {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        tracing::warn!(target_host = target.0, target_port = target.1, error = %error, "masque_backend_connect_failed");
                        stream.send_response(Response::builder().status(StatusCode::BAD_GATEWAY).body(())?).await?;
                        stream.finish().await?;
                        continue;
                    }
                };
                let stream_id = stream.id();
                let association_id = stream_id.into_inner();
                let datagram_sender = datagrams_available.then(|| h3.get_datagram_sender(stream_id));
                stream.send_response(
                    Response::builder().status(StatusCode::OK).header(CAPSULE_PROTOCOL, "?1").body(())?
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
                                    if tunnel.send(payload).await.is_err() { break; }
                                }
                                incoming = tunnel.recv() => {
                                    let Some(payload) = incoming else { break };
                                    let mut framed = Vec::with_capacity(payload.len() + 1);
                                    framed.push(0);
                                    framed.extend_from_slice(&payload);
                                    match datagram_sender.send_datagram(Bytes::from(framed)) {
                                        Ok(()) => {}
                                        Err(SendDatagramError::TooLarge { .. }) => continue,
                                        Err(_) => break,
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
                                        Ok(None) | Err(_) => break,
                                    };
                                    capsules.extend_from_slice(&chunk);
                                    loop {
                                        match take_capsule(&mut capsules) {
                                            Ok(Some((DATAGRAM_CAPSULE, payload))) => {
                                                let Some(payload) = payload.strip_prefix(&[0]) else { continue };
                                                if tunnel.send(Bytes::copy_from_slice(payload)).await.is_err() { break; }
                                            }
                                            Ok(Some(_)) => continue,
                                            Ok(None) => break,
                                            Err(_) => { capsules.clear(); break; }
                                        }
                                    }
                                }
                                incoming = tunnel.recv() => {
                                    let Some(payload) = incoming else { break };
                                    if stream.send_data(datagram_capsule(&payload)).await.is_err() { break; }
                                }
                            }
                        }
                    }
                    stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                    let _ = closed_tx.send(association_id).await;
                });
            }
            incoming = async { datagram_reader.as_mut().expect("guarded reader").read_datagram().await }, if datagram_reader.is_some() => {
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
    use iroh::SecretKey;

    #[test]
    fn duplicate_and_empty_route_tables_fail_closed() {
        let route = Route {
            target_host: "example.test".into(),
            target_port: 53,
            backend: EndpointAddr::new(SecretKey::generate().public()),
            destination: DestinationId::udp(53),
        };
        assert!(index_routes(vec![]).is_err());
        assert!(index_routes(vec![route.clone(), route]).is_err());
    }

    #[test]
    fn route_keys_are_case_insensitive() {
        let backend = EndpointAddr::new(SecretKey::generate().public());
        let routes = index_routes(vec![Route {
            target_host: "DNS.Example.NET".into(),
            target_port: 53,
            backend,
            destination: DestinationId::udp(53),
        }])
        .unwrap();
        assert!(routes.contains_key(&("dns.example.net".into(), 53)));
    }

    #[test]
    fn capsule_decoder_is_incremental_and_bounded() {
        let first = datagram_capsule(b"first");
        let mut wire = BytesMut::from(&first[..2]);
        assert!(take_capsule(&mut wire).unwrap().is_none());
        wire.extend_from_slice(&first[2..]);
        assert_eq!(&take_capsule(&mut wire).unwrap().unwrap().1[..], b"\0first");
        let mut header = Vec::new();
        encode_varint(0, &mut header);
        encode_varint((MAX_CAPSULE + 1) as u64, &mut header);
        assert!(take_capsule(&mut BytesMut::from(&header[..])).is_err());
    }
}
