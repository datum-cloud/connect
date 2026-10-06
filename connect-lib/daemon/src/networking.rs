//! Daemon-owned peer attachment configuration. Root approval remains independent.
use crate::{
    error::ApiError,
    model::DaemonState,
    peer_ip::{AccessRule, Binding},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub network: String,
    pub peer: String,
    #[serde(default)]
    pub allow_inbound: Vec<AccessRule>,
    #[serde(default)]
    pub allow_outbound: Vec<AccessRule>,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub advertise_routes: Vec<String>,
}

pub fn helper_socket() -> Result<PathBuf, ApiError> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return Err(ApiError::bad_request(
                "Guided IP setup requires your ordinary user daemon, not a root daemon",
            ));
        }
        let base = if cfg!(target_os = "macos") {
            "/Library/PrivilegedHelperTools"
        } else {
            "/var/lib"
        };
        Ok(PathBuf::from(base).join(format!("datum-connect-network-{uid}/helper.sock")))
    }
    #[cfg(not(unix))]
    {
        Err(ApiError::bad_request(
            "Guided IP setup currently supports macOS and Linux",
        ))
    }
}

fn digest(parts: &[&str]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"datum-connect/peer-host/v1\0");
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}

pub fn binding(
    project: &str,
    local: &str,
    peer: &str,
    request: &PrepareRequest,
) -> Result<Binding, ApiError> {
    if local == peer {
        return Err(ApiError::bad_request(
            "Choose another Connector; this device cannot join itself",
        ));
    }
    local
        .parse::<iroh::EndpointId>()
        .map_err(|_| ApiError::bad_request("Invalid local Connector key"))?;
    peer.parse::<iroh::EndpointId>()
        .map_err(|_| ApiError::bad_request("Invalid peer Connector key"))?;
    let (a, b) = if local < peer {
        (local, peer)
    } else {
        (peer, local)
    };
    let address = |key| {
        let hash = digest(&[project, &request.network, a, b, key]);
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&hash[..16]);
        bytes[0] = 0xfd;
        format!("{}/128", Ipv6Addr::from(bytes))
    };
    let hash = digest(&[project, &request.network, local]);
    let label: String = hash[..5].iter().map(|b| format!("{b:02x}")).collect();
    let binding = Binding {
        project: project.into(),
        network: request.network.clone(),
        peer: peer.into(),
        discover: true,
        addresses: vec![],
        assigned_address: address(local),
        peer_address: address(peer),
        interface_name: format!("dc{label}"),
        mtu: 1280,
        allow_inbound: request.allow_inbound.clone(),
        allow_outbound: request.allow_outbound.clone(),
        routes: request.routes.clone(),
        advertise_routes: request.advertise_routes.clone(),
    };
    binding.validate()?;
    Ok(binding)
}

pub fn config(
    state: &DaemonState,
    underlay: IpAddr,
) -> Result<crate::local_ip::LocalIpConfig, ApiError> {
    let peer_bindings: Vec<_> = state
        .projects
        .values()
        .flat_map(|p| p.peer_networks.values().cloned())
        .collect();
    if peer_bindings.len() > 16 {
        return Err(ApiError::bad_request(
            "This device supports at most 16 saved peer attachments",
        ));
    }
    let config = crate::local_ip::LocalIpConfig {
        network_helper: Some(helper_socket()?),
        underlay_address: underlay,
        underlay_port: 0,
        bindings: vec![],
        peer_bindings,
    };
    config.validate()?;
    Ok(config)
}

#[cfg(unix)]
pub fn approvals(state: &DaemonState) -> Result<connect_ip_adapter::helper::Config, ApiError> {
    let config = connect_ip_adapter::helper::Config {
        allowed_uid: unsafe { libc::geteuid() },
        approvals: state
            .projects
            .values()
            .flat_map(|p| p.peer_networks.values())
            .map(|b| {
                Ok(connect_ip_adapter::helper::Approval {
                    interface_name: b.interface_name.clone(),
                    assigned_address: b.local_address()?,
                    peer_address: b.remote_address()?,
                    mtu: b.mtu,
                    routes: b
                        .routes
                        .iter()
                        .map(|r| {
                            r.parse()
                                .map_err(|_| ApiError::bad_request("Invalid route"))
                        })
                        .collect::<Result<_, _>>()?,
                    advertise_routes: b
                        .advertise_routes
                        .iter()
                        .map(|r| {
                            r.parse()
                                .map_err(|_| ApiError::bad_request("Invalid route"))
                        })
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
        managed_policy: None,
    };
    config
        .validate()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addresses_are_symmetric_and_project_scoped() {
        let a = iroh::SecretKey::generate().public().to_string();
        let b = iroh::SecretKey::generate().public().to_string();
        let request = PrepareRequest {
            network: "friend".into(),
            peer: b.clone(),
            allow_inbound: vec![],
            allow_outbound: vec![],
            routes: vec![],
            advertise_routes: vec![],
        };
        let left = binding("demo", &a, &b, &request).unwrap();
        let right = binding("demo", &b, &a, &request).unwrap();
        assert_eq!(left.assigned_address, right.peer_address);
        assert_eq!(left.peer_address, right.assigned_address);
        assert_ne!(
            left.assigned_address,
            binding("other", &a, &b, &request).unwrap().assigned_address
        );
        assert!(binding("demo", &a, &a, &request).is_err());
        assert!(left.interface_name.len() < 16);
    }
}
