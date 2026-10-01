//! Join-scoped, explicitly approved point-to-point IP attachments.
use crate::{error::ApiError, local_ip};
use connect_ip_adapter::{IpNet, Tun};
use connect_transport::{
    Transport,
    ip::{
        self,
        peer_policy::{PeerPolicy, Protocol, Rule},
    },
};
use iroh::{EndpointAddr, EndpointId};
use serde::Deserialize;
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub project: String,
    pub network: String,
    pub peer: String,
    pub addresses: Vec<SocketAddr>,
    pub assigned_address: String,
    pub peer_address: String,
    pub interface_name: String,
    pub mtu: u16,
    #[serde(default)]
    pub allow_inbound: Vec<AccessRule>,
    #[serde(default)]
    pub allow_outbound: Vec<AccessRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRule {
    pub protocol: AccessProtocol,
    #[serde(default)]
    pub ports: Vec<u16>,
}
#[derive(Debug, Clone, Copy, Deserialize)]
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
    pub(crate) fn as_gateway_binding(&self) -> local_ip::Binding {
        local_ip::Binding {
            project: self.project.clone(),
            network: self.network.clone(),
            gateway: self.peer.clone(),
            addresses: self.addresses.clone(),
            assigned_address: self.assigned_address.clone(),
            routes: vec![self.peer_address.clone()],
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
        let local = self.local_address()?;
        let remote = self.remote_address()?;
        if local.addr().is_ipv4() != remote.addr().is_ipv4()
            || local.addr() == remote.addr()
            || remote.prefix_len() != if remote.addr().is_ipv4() { 32 } else { 128 }
        {
            return Err(ApiError::bad_request(
                "Peer bindings require two distinct host addresses in the same family (/32 IPv4 or /128 IPv6); subnet and transit routes are forbidden",
            ));
        }
        if self.allow_inbound.len() > 64 || self.allow_outbound.len() > 64 {
            return Err(ApiError::bad_request(
                "Peer access lists support at most 64 rules per direction",
            ));
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
        .map_err(|error| ApiError::bad_request(format!("Invalid peer packet policy: {error}")))
    }
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
            "assigned_address":self.binding.assigned_address,"peer_address":self.binding.peer_address,"routes":[self.binding.peer_address],"interface_name":self.interface_name,
            "interface_label":self.binding.interface_name,"adapter":connect_ip_adapter::backend(),
            "mtu":self.binding.mtu,"state":state.phase,"running":!self.task.is_finished(),"connected":state.phase=="connected"&&!self.task.is_finished(),"ephemeral":true,"prototype":true,
            "authorization":"static_operator_approval","connection_attempts":self.attempts.load(Ordering::Relaxed),"last_connect_error":state.last_connect_error,
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
) -> Result<Attachment, ApiError> {
    let guard = cancel.clone().drop_guard();
    binding.validate()?;
    let endpoint = transport.endpoint();
    let peer: EndpointId = binding
        .peer
        .parse()
        .map_err(|_| ApiError::bad_request("Peer must be a Connector public key"))?;
    require_distinct_peer(endpoint.id(), peer)?;
    let local = binding.local_address()?;
    let remote = binding.remote_address()?;
    let policy = Arc::new(StdMutex::new(PolicyDiagnostics {
        policy: binding.policy()?,
        denials: BTreeMap::new(),
    }));
    let host_routes = [remote];
    let tun = tokio::select! {
        _=cancel.cancelled()=>return Err(ApiError::internal("Peer IP setup cancelled")),
        result=tokio::time::timeout(Duration::from_secs(8),Tun::create(&binding.interface_name,local,binding.mtu,&host_routes))=>result.map_err(|_|ApiError::internal("Peer TUN setup timed out; partial interface removed"))?.map_err(|e|ApiError::internal(format!("Cannot create peer interface using {}: {e}",connect_ip_adapter::backend())))?,
    };
    let interface_name = tun.name().to_owned();
    tracing::info!(stage="connect_ip_adapter", network=%binding.network, interface=%interface_name, adapter=connect_ip_adapter::backend(), mtu=binding.mtu, "peer_ip_interface_ready");
    let dialer = endpoint.id() < peer;
    let mut registration = if dialer {
        None
    } else {
        Some(
            transport
                .register_ip_grant(ip::Grant {
                    peer,
                    network: binding.network.clone(),
                    address: remote.addr(),
                    routes: vec![local.to_string().parse().map_err(|e| {
                        ApiError::bad_request(format!("Invalid peer host route: {e}"))
                    })?],
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
                        match ip::connect(endpoint.clone(),address.clone(),&task_binding.network,task_cancel.clone()).await {
                            Ok(session)=>break session,
                            Err(error)=>{
                                task_state.lock().await.last_connect_error=Some(error.to_string());
                                tracing::debug!(network=%task_binding.network,%error,stage="peer_ip_connect","peer_not_ready");
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                } else {
                    let incoming=registration.as_mut().expect("listener registration").recv().await.ok_or("Peer IP listener closed")?;
                    if incoming.peer!=peer || incoming.network!=task_binding.network { let _=incoming.ready.send(false); return Err("Peer IP identity or network did not match approval".into()); }
                    let expected=ip::SessionConfig {address:remote.addr(),routes:vec![local.to_string().parse().map_err(|e:ip::Error|e.to_string())?],mtu:task_binding.mtu};
                    if incoming.session.config!=expected { let _=incoming.ready.send(false); return Err("Peer IP assignment did not match local approval".into()); }
                    incoming.ready.send(true).map_err(|_|"Peer left before attachment was ready")?;
                    incoming.session
                };
                let expected=if dialer { ip::SessionConfig {address:local.addr(),routes:vec![remote.to_string().parse().map_err(|e:ip::Error|e.to_string())?],mtu:task_binding.mtu} } else { ip::SessionConfig {address:remote.addr(),routes:vec![local.to_string().parse().map_err(|e:ip::Error|e.to_string())?],mtu:task_binding.mtu} };
                if session.config!=expected { session.cancel(); return Err("Peer IP assignment, host route, or MTU did not match local approval".into()); }
                let session=Arc::new(session);
                { let mut state=task_state.lock().await; state.phase="connected"; state.last_connect_error=None; state.session=Some(session.clone()); }
                let mut buffer=vec![0u8;65536];
                loop {
                    tokio::select! {
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
            tracing::warn!(network=%task_binding.network,%error,stage="peer_ip","peer_attachment_closed");
        }
    });
    let _ = guard.disarm();
    Ok(Attachment {
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
