//! Join-scoped, explicitly approved peer host and subnet IP attachments.
use crate::{error::ApiError, local_ip};
use connect_ip_adapter::{IpNet, PacketDevice};
use connect_transport::{
    Transport,
    ip::{
        self,
        peer_policy::{PeerPolicy, Protocol, Rule},
    },
};
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub project: String,
    pub network: String,
    pub peer: String,
    /// Resolve this pinned key through the project's Connector resources.
    #[serde(default)]
    pub discover: bool,
    #[serde(default)]
    pub addresses: Vec<SocketAddr>,
    pub assigned_address: String,
    pub peer_address: String,
    pub interface_name: String,
    pub mtu: u16,
    #[serde(default)]
    pub allow_inbound: Vec<AccessRule>,
    #[serde(default)]
    pub allow_outbound: Vec<AccessRule>,
    /// Destinations reached through the peer.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Destinations forwarded for the peer; never installed into this device's TUN.
    #[serde(default)]
    pub advertise_routes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessRule {
    pub protocol: AccessProtocol,
    #[serde(default)]
    pub ports: Vec<u16>,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessProtocol {
    Tcp,
    Udp,
    IcmpEcho,
}
impl AccessRule {
    fn rule(&self) -> Rule {
        Rule {
            protocol: match self.protocol {
                AccessProtocol::Tcp => Protocol::Tcp,
                AccessProtocol::Udp => Protocol::Udp,
                AccessProtocol::IcmpEcho => Protocol::IcmpEcho,
            },
            ports: self.ports.clone(),
        }
    }
}
impl Binding {
    pub(crate) fn tun_routes(&self) -> Vec<String> {
        if self.routes.is_empty() {
            vec![self.peer_address.clone()]
        } else {
            self.routes.clone()
        }
    }
    fn session_config(&self, dialer: bool) -> Result<ip::SessionConfig, ApiError> {
        let routes = if !self.routes.is_empty() {
            self.routes.clone()
        } else if !self.advertise_routes.is_empty() {
            self.advertise_routes.clone()
        } else if dialer {
            vec![self.peer_address.clone()]
        } else {
            vec![self.assigned_address.clone()]
        };
        let mut routes = routes
            .iter()
            .map(|r| {
                r.parse()
                    .map_err(|e| ApiError::bad_request(format!("Invalid subnet route: {e}")))
            })
            .collect::<Result<Vec<ip::IpPrefix>, _>>()?;
        routes.sort();
        Ok(ip::SessionConfig {
            address: if dialer {
                self.local_address()?.addr()
            } else {
                self.remote_address()?.addr()
            },
            routes,
            mtu: self.mtu,
        })
    }
    pub(crate) fn as_gateway_binding(&self) -> local_ip::Binding {
        local_ip::Binding {
            project: self.project.clone(),
            network: self.network.clone(),
            gateway: self.peer.clone(),
            addresses: self.addresses.clone(),
            relay_urls: vec![],
            assigned_address: self.assigned_address.clone(),
            routes: self.tun_routes(),
            interface_name: self.interface_name.clone(),
            mtu: self.mtu,
        }
    }
    pub(crate) fn local_address(&self) -> Result<IpNet, ApiError> {
        self.assigned_address.parse().map_err(|_| {
            ApiError::bad_request("Peer assigned_address must be an IPv4 /32 or IPv6 /128")
        })
    }
    pub(crate) fn remote_address(&self) -> Result<IpNet, ApiError> {
        self.peer_address.parse().map_err(|_| {
            ApiError::bad_request(
                "peer_address must be an IPv4 /32 or IPv6 /128 host, not a subnet",
            )
        })
    }
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.discover && !self.addresses.is_empty() {
            return Err(ApiError::bad_request(
                "Discovered peer bindings must omit static addresses",
            ));
        }
        let local = self.local_address()?;
        let remote = self.remote_address()?;
        if local.addr().is_ipv4() != remote.addr().is_ipv4()
            || local.addr() == remote.addr()
            || remote.prefix_len() != if remote.addr().is_ipv4() { 32 } else { 128 }
        {
            return Err(ApiError::bad_request(
                "Peer bindings require two distinct host addresses in the same family (/32 IPv4 or /128 IPv6); put subnet destinations in routes or advertise_routes",
            ));
        }
        if self.allow_inbound.len() > 64 || self.allow_outbound.len() > 64 {
            return Err(ApiError::bad_request(
                "Peer access lists support at most 64 rules per direction",
            ));
        }
        if (!self.routes.is_empty() && !self.advertise_routes.is_empty())
            || self.routes.len() + self.advertise_routes.len() > 32
        {
            return Err(ApiError::bad_request(
                "Choose either routes or advertise_routes, with at most 32 approved prefixes",
            ));
        }
        let routes = self
            .routes
            .iter()
            .chain(&self.advertise_routes)
            .map(|r| {
                r.parse::<IpNet>()
                    .map_err(|_| ApiError::bad_request("Invalid subnet prefix"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        connect_ip_adapter::validate(&self.interface_name, local, self.mtu, &routes)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        for (i, route) in routes.iter().enumerate() {
            if route.contains(&local.addr())
                || route.contains(&remote.addr())
                || routes[..i]
                    .iter()
                    .any(|r| r.contains(&route.network()) || route.contains(&r.network()))
            {
                return Err(ApiError::bad_request(
                    "Subnet prefixes must be nonoverlapping and exclude both peer host addresses",
                ));
            }
        }
        self.policy()?;
        Ok(())
    }
    fn policy(&self) -> Result<PeerPolicy, ApiError> {
        PeerPolicy::new(
            self.local_address()?.addr(),
            self.remote_address()?.addr(),
            self.allow_inbound.iter().map(AccessRule::rule).collect(),
            self.allow_outbound.iter().map(AccessRule::rule).collect(),
        )
        .and_then(|policy| {
            policy.with_routes(
                self.advertise_routes
                    .iter()
                    .map(|r| r.parse().map_err(|_| "Invalid advertised prefix"))
                    .collect::<Result<_, _>>()?,
                self.routes
                    .iter()
                    .map(|r| r.parse().map_err(|_| "Invalid routed prefix"))
                    .collect::<Result<_, _>>()?,
            )
        })
        .map_err(|error| ApiError::bad_request(format!("Invalid peer packet policy: {error}")))
    }
}

#[async_trait::async_trait]
pub trait PeerResolver: Send + Sync {
    async fn resolve(&self, peer: EndpointId) -> Result<EndpointAddr, ApiError>;
}

struct State {
    phase: &'static str,
    error: Option<String>,
    last_connect_error: Option<String>,
    session: Option<Arc<ip::IpSession>>,
}
struct PolicyDiagnostics {
    policy: PeerPolicy,
    denials: BTreeMap<&'static str, u64>,
}
fn check_packet(
    policy: &StdMutex<PolicyDiagnostics>,
    packet: &[u8],
    outbound: bool,
    network: &str,
    peer: EndpointId,
) -> bool {
    let mut policy = policy.lock().unwrap_or_else(|error| error.into_inner());
    let allowed = if outbound {
        policy.policy.authorize_send(packet)
    } else {
        policy.policy.authorize_receive(packet)
    };
    if !allowed {
        let reason = policy
            .policy
            .last_denial_reason()
            .unwrap_or("policy_denied");
        *policy.denials.entry(reason).or_default() += 1;
        let direction = if outbound { "outbound" } else { "inbound" };
        tracing::debug!(%network,%peer,direction,reason,stage="peer_ip_packet","packet_rejected");
    }
    allowed
}
fn clear_flows(policy: &StdMutex<PolicyDiagnostics>) {
    policy
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .policy
        .clear();
}
pub struct Attachment {
    helper: bool,
    binding: Binding,
    interface_name: String,
    cancel: CancellationToken,
    pub task: JoinHandle<()>,
    state: Arc<Mutex<State>>,
    denied: Arc<AtomicU64>,
    attempts: Arc<AtomicU64>,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    policy: Arc<StdMutex<PolicyDiagnostics>>,
}
impl Attachment {
    pub async fn status(&self) -> Value {
        let state = self.state.lock().await;
        let stats = state
            .session
            .as_ref()
            .map(|session| session.stats())
            .unwrap_or(ip::Stats {
                delivery_mode: "quic_datagram",
                ..Default::default()
            });
        let transport_error = state
            .session
            .as_ref()
            .and_then(|session| session.last_error());
        let denied = self.denied.load(Ordering::Relaxed);
        let (tracked_flows, denials) = {
            let policy = self
                .policy
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            (policy.policy.active_flows(), policy.denials.clone())
        };
        json!({"network":self.binding.network,"project":self.binding.project,"mode":"peer","peer":self.binding.peer,
            "assigned_address":self.binding.assigned_address,"peer_address":self.binding.peer_address,"routes":self.binding.tun_routes(),"advertise_routes":self.binding.advertise_routes,"interface_name":self.interface_name,
            "interface_label":self.binding.interface_name,"adapter":connect_ip_adapter::backend(),
            "mtu":self.binding.mtu,"state":state.phase,"running":!self.task.is_finished(),"connected":state.phase=="connected"&&!self.task.is_finished(),"ephemeral":true,"prototype":true,
            "authorization":"static_operator_approval","network_helper":self.helper,"discovery":if self.binding.discover {"connector"} else {"static"},"connection_attempts":self.attempts.load(Ordering::Relaxed),"last_connect_error":state.last_connect_error,
            "packets_sent":self.sent.load(Ordering::Relaxed),"packets_received":self.received.load(Ordering::Relaxed),"packets_dropped":stats.packets_dropped+denied,"acl_drops":denied,
            "tracked_flows":tracked_flows,"acl_drops_by_reason":denials,
            "protocol_errors":stats.protocol_errors,"delivery_mode":"quic_datagram","effective_datagram_ip_capacity":stats.effective_datagram_ip_capacity,"mtu_errors":stats.mtu_errors,
            "last_error":state.error,"last_transport_error":transport_error,"transport":local_ip::transport_status(stats,transport_error.clone())})
    }
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

pub async fn join(
    binding: Binding,
    transport: Transport,
    cancel: CancellationToken,
    helper: Option<&std::path::Path>,
    resolver: Option<Arc<dyn PeerResolver>>,
) -> Result<Attachment, ApiError> {
    let guard = cancel.clone().drop_guard();
    binding.validate()?;
    let endpoint = transport.endpoint();
    let peer: EndpointId = binding
        .peer
        .parse()
        .map_err(|_| ApiError::bad_request("Peer must be a Connector public key"))?;
    require_distinct_peer(endpoint.id(), peer)?;
    if binding.discover != resolver.is_some() {
        return Err(ApiError::bad_request(
            "Peer discovery resolver is unavailable",
        ));
    }
    // Validate Cloud authorization on both sides before creating privileged state.
    if let Some(resolver) = &resolver {
        resolver.resolve(peer).await?;
    }
    let local = binding.local_address()?;
    let remote = binding.remote_address()?;
    let policy = Arc::new(StdMutex::new(PolicyDiagnostics {
        policy: binding.policy()?,
        denials: BTreeMap::new(),
    }));
    let host_routes = binding
        .tun_routes()
        .iter()
        .map(|r| {
            r.parse::<IpNet>()
                .map_err(|_| ApiError::bad_request("Invalid TUN route"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let create_device = async {
        #[cfg(unix)]
        if let Some(socket) = helper {
            let approval = connect_ip_adapter::helper::Approval {
                interface_name: binding.interface_name.clone(),
                assigned_address: local,
                peer_address: remote,
                mtu: binding.mtu,
                routes: binding
                    .routes
                    .iter()
                    .map(|r| r.parse::<IpNet>())
                    .collect::<Result<_, _>>()
                    .map_err(std::io::Error::other)?,
                advertise_routes: binding
                    .advertise_routes
                    .iter()
                    .map(|r| r.parse::<IpNet>())
                    .collect::<Result<_, _>>()
                    .map_err(std::io::Error::other)?,
            };
            return connect_ip_adapter::helper::Client::connect_approved(socket, approval)
                .await
                .map(PacketDevice::Helper);
        }
        PacketDevice::create(
            &binding.interface_name,
            local,
            binding.mtu,
            &host_routes,
            None,
        )
        .await
    };
    let tun = tokio::select! {
        _=cancel.cancelled()=>return Err(ApiError::internal("Peer IP setup cancelled")),
        result=tokio::time::timeout(Duration::from_secs(10),create_device)=>result.map_err(|_|ApiError::internal("Peer interface setup timed out; partial interface removed"))?.map_err(|e|ApiError::internal(format!("Cannot create peer interface using {}: {e}",connect_ip_adapter::backend())))?,
    };
    let interface_name = tun.name().to_owned();
    tracing::info!(stage="connect_ip_adapter", network=%binding.network, interface=%interface_name, adapter=connect_ip_adapter::backend(), mtu=binding.mtu, "peer_ip_interface_ready");
    let dialer = if !binding.routes.is_empty() {
        true
    } else if !binding.advertise_routes.is_empty() {
        false
    } else {
        endpoint.id() < peer
    };
    let expected = binding.session_config(dialer)?;
    let mut registration = if dialer {
        None
    } else {
        Some(
            transport
                .register_ip_grant(ip::Grant {
                    peer,
                    network: binding.network.clone(),
                    address: remote.addr(),
                    routes: expected.routes.clone(),
                    mtu: binding.mtu,
                })
                .await
                .map_err(|e| ApiError::internal(format!("Cannot approve peer IP listener: {e}")))?,
        )
    };
    let state = Arc::new(Mutex::new(State {
        phase: "waiting_for_peer",
        error: None,
        last_connect_error: None,
        session: None,
    }));
    let denied = Arc::new(AtomicU64::new(0));
    let attempts = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let (task_sent, task_received) = (sent.clone(), received.clone());
    let (task_state, task_denied, task_attempts, task_cancel, task_binding) = (
        state.clone(),
        denied.clone(),
        attempts.clone(),
        cancel.clone(),
        binding.clone(),
    );
    let task_policy = policy.clone();
    let task_interface = interface_name.clone();
    tracing::info!(
        project=%binding.project,
        network=%binding.network,
        %peer,
        dialer,
        interface=%interface_name,
        assigned_address=%binding.assigned_address,
        peer_address=%binding.peer_address,
        routes=?binding.routes,
        advertise_routes=?binding.advertise_routes,
        mtu=binding.mtu,
        stage="peer_ip_attachment_starting",
        "CONNECT-IP attachment starting"
    );
    let task = tokio::spawn(async move {
        let policy = task_policy;
        let outcome: Result<(), String> = tokio::select! {
            _=task_cancel.cancelled()=>Ok(()),
            result=async {
                let session = if dialer {
                    let mut address=EndpointAddr::new(peer);
                    for socket in &task_binding.addresses { address=address.with_ip_addr(*socket); }
                    loop {
                        task_attempts.fetch_add(1,Ordering::Relaxed);
                        if let Some(resolver) = &resolver {
                            address = resolver.resolve(peer).await.map_err(|e|e.message)?;
                        }
                        match ip::connect(endpoint.clone(),address.clone(),&task_binding.network,task_cancel.clone()).await {
                            Ok(session)=>break session,
                            Err(error)=>{
                                task_state.lock().await.last_connect_error=Some(error.to_string());
                                let attempt=task_attempts.load(Ordering::Relaxed);
                                if attempt == 1 || attempt % 10 == 0 {
                                    tracing::warn!(project=%task_binding.project,network=%task_binding.network,%peer,attempt,%error,stage="peer_ip_connect","CONNECT-IP peer session attempt failed; retrying");
                                }
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                } else {
                    let incoming=registration.as_mut().expect("listener registration").recv().await.ok_or("Peer IP listener closed")?;
                    if incoming.peer!=peer || incoming.network!=task_binding.network { let _=incoming.ready.send(false); return Err("Peer IP identity or network did not match approval".into()); }
                    if incoming.session.config!=expected { let _=incoming.ready.send(false); return Err("Peer IP assignment did not match local approval".into()); }
                    incoming.ready.send(true).map_err(|_|"Peer left before attachment was ready")?;
                    incoming.session
                };
                if session.config!=expected { session.cancel(); return Err("Peer IP assignment, routes, or MTU did not match local approval".into()); }
                let session=Arc::new(session);
                { let mut state=task_state.lock().await; state.phase="connected"; state.last_connect_error=None; state.session=Some(session.clone()); }
                tracing::info!(project=%task_binding.project,network=%task_binding.network,%peer,dialer,interface=%task_interface,assigned_address=%task_binding.assigned_address,peer_address=%task_binding.peer_address,routes=?task_binding.routes,advertise_routes=?task_binding.advertise_routes,mtu=task_binding.mtu,stage="peer_ip_connected", "CONNECT-IP peer session connected");
                let mut buffer=vec![0u8;65536];
                let mut authorization = tokio::time::interval(Duration::from_secs(30));
                authorization.tick().await;
                loop {
                    tokio::select! {
                        _=authorization.tick(), if resolver.is_some()=>{
                            resolver.as_ref().expect("enabled resolver").resolve(peer).await.map_err(|e|e.message)?;
                        },
                        packet=session.recv()=>{
                            let packet=packet.ok_or_else(||session.last_error().unwrap_or_else(||"Peer left or closed the IP session; run join again after the peer rejoins".into()))?;
                            if check_packet(&policy,&packet,false,&task_binding.network,peer) { tun.write_packet(&packet).await.map_err(|e|e.to_string())?; task_received.fetch_add(1,Ordering::Relaxed); }
                            else { task_denied.fetch_add(1,Ordering::Relaxed); }
                        },
                        read=tun.read_packet(&mut buffer)=>{
                            let length=read.map_err(|e|e.to_string())?;
                            if length==0 {return Err("Peer TUN closed".into());}
                            if !check_packet(&policy,&buffer[..length],true,&task_binding.network,peer) {task_denied.fetch_add(1,Ordering::Relaxed);continue;}
                            match session.send(bytes::Bytes::copy_from_slice(&buffer[..length])).await {
                                Ok(())=>{task_sent.fetch_add(1,Ordering::Relaxed);},
                                Err(ip::Error::InvalidPacket|ip::Error::PacketTooLarge|ip::Error::AddressPolicy)=>{clear_flows(&policy);},
                                Err(error)=>return Err(session.last_error().unwrap_or_else(||error.to_string())),
                            }
                        }
                    }
                }
            }=>result,
        };
        clear_flows(&policy);
        drop(registration);
        drop(tun);
        let mut state = task_state.lock().await;
        if let Some(session) = &state.session {
            session.cancel();
        }
        state.phase = if outcome.is_err() {
            "failed"
        } else {
            "disconnected"
        };
        state.error = outcome.err();
        if let Some(error) = &state.error {
            tracing::warn!(project=%task_binding.project,network=%task_binding.network,%peer,dialer,interface=%task_interface,assigned_address=%task_binding.assigned_address,peer_address=%task_binding.peer_address,routes=?task_binding.routes,attempts=task_attempts.load(Ordering::Relaxed),packets_sent=task_sent.load(Ordering::Relaxed),packets_received=task_received.load(Ordering::Relaxed),acl_drops=task_denied.load(Ordering::Relaxed),%error,stage="peer_ip_attachment_closed","CONNECT-IP attachment failed or peer session ended");
        } else {
            tracing::info!(project=%task_binding.project,network=%task_binding.network,%peer,dialer,interface=%task_interface,attempts=task_attempts.load(Ordering::Relaxed),packets_sent=task_sent.load(Ordering::Relaxed),packets_received=task_received.load(Ordering::Relaxed),acl_drops=task_denied.load(Ordering::Relaxed),stage="peer_ip_attachment_closed","CONNECT-IP attachment stopped cleanly");
        }
    });
    let _ = guard.disarm();
    Ok(Attachment {
        helper: helper.is_some(),
        binding,
        interface_name,
        cancel,
        task,
        state,
        denied,
        attempts,
        sent,
        received,
        policy,
    })
}

fn require_distinct_peer(local: EndpointId, peer: EndpointId) -> Result<(), ApiError> {
    if peer == local {
        return Err(ApiError::bad_request(
            "A peer binding cannot target this Connector's own key",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routed_peers_agree_on_session_but_install_different_routes() {
        let client_key = iroh::SecretKey::from_bytes(&[1; 32]).public().to_string();
        let router_key = iroh::SecretKey::from_bytes(&[2; 32]).public().to_string();
        let mut request = crate::networking::PrepareRequest {
            network: "vpc".into(),
            peer: router_key.clone(),
            allow_inbound: vec![],
            allow_outbound: vec![],
            routes: vec!["fd20:27::/48".into()],
            advertise_routes: vec![],
        };
        let client =
            crate::networking::binding("demo", &client_key, &router_key, &request).unwrap();
        request.advertise_routes = std::mem::take(&mut request.routes);
        let mut router =
            crate::networking::binding("demo", &router_key, &client_key, &request).unwrap();
        assert_eq!(
            client.session_config(true).unwrap(),
            router.session_config(false).unwrap()
        );
        assert_eq!(client.tun_routes(), vec!["fd20:27::/48"]);
        assert_eq!(router.tun_routes(), vec![client.assigned_address.clone()]);
        router.advertise_routes = vec!["fd20:28::/48".into()];
        assert_ne!(
            client.session_config(true).unwrap(),
            router.session_config(false).unwrap()
        );
        router.routes = vec!["fd20:29::/48".into()];
        assert!(router.validate().is_err());
        router.routes.clear();
        router.advertise_routes.push("fd20:28::/64".into());
        assert!(router.validate().is_err());
    }
    #[test]
    fn denied_packet_diagnostics_contain_only_safe_reasons() {
        let peer = iroh::SecretKey::from_bytes(&[3; 32]).public();
        let policy = StdMutex::new(PolicyDiagnostics {
            policy: PeerPolicy::new(
                "192.0.2.2".parse().unwrap(),
                "192.0.2.3".parse().unwrap(),
                vec![],
                vec![],
            )
            .unwrap(),
            denials: BTreeMap::new(),
        });
        assert!(!check_packet(
            &policy,
            b"private payload",
            true,
            "peer-net",
            peer
        ));
        let snapshot = policy.lock().unwrap();
        assert_eq!(snapshot.denials.get("malformed_packet"), Some(&1));
        assert_eq!(snapshot.policy.active_flows(), 0);
        assert!(
            !serde_json::to_string(&snapshot.denials)
                .unwrap()
                .contains("private payload")
        );
    }
    #[test]
    fn self_peer_is_rejected_before_any_tun_or_listener_setup() {
        let local = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[2; 32]).public();
        assert!(
            require_distinct_peer(local, local)
                .unwrap_err()
                .message
                .contains("own key")
        );
        require_distinct_peer(local, other).unwrap();
    }
}
