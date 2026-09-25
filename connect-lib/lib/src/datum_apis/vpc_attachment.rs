use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::CustomResource;
use serde::{Deserialize, Serialize};

use crate::datum_apis::connector::LocalConnectorReference;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVPCReference {
    pub name: String,
}

/// Routing mode requested for the attachment's local interface — the
/// single-peer collapse of WireGuard's AllowedIPs (there is exactly one
/// remote peer, the galactic-side router, so this is a mode toggle rather
/// than a routing policy trie). See design/vpc-attachment.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VPCAttachmentMode {
    /// Only the VPC's own advertised prefixes are routed through the
    /// interface; all other traffic keeps using the host's existing routes.
    #[serde(rename = "VPCOnly")]
    VpcOnly,
    /// The interface becomes the host's default route (via the wg-quick
    /// `::/1` + `8000::/1` split so a real `::/0` is never displaced).
    #[serde(rename = "DefaultRoute")]
    DefaultRoute,
}

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "networking.datumapis.com",
    version = "v1alpha1",
    kind = "VPCAttachment",
    plural = "vpcattachments",
    namespaced,
    status = "VPCAttachmentStatus",
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct VPCAttachmentSpec {
    pub connector_ref: LocalConnectorReference,
    pub vpc_ref: LocalVPCReference,
    pub mode: VPCAttachmentMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VPCAttachmentStatus {
    pub conditions: Option<Vec<metav1::Condition>>,

    /// This client's address within the VPC (an IPv6 host address, no
    /// prefix length — the gVPC this feature targets is IPv6-only per the
    /// originating issue). Populated once the galactic-side router has
    /// claimed the attachment and allocated an address.
    pub assigned_address: Option<String>,

    /// Prefixes routable inside the VPC, as CIDRs. In `VPCOnly` mode these
    /// are installed as the interface's only routes; in `DefaultRoute` mode
    /// they are informational (the `::/1` + `8000::/1` split already covers
    /// everything).
    pub advertised_prefixes: Option<Vec<String>>,

    /// TUN MTU the client should use, derived by the router from its own
    /// iroh/QUIC path overhead budget — not something the client should
    /// guess at (see design/vpc-attachment.md's MTU discussion).
    pub mtu: Option<i32>,

    /// iroh EndpointId (z-base-32) of the galactic-side router instance
    /// that claimed this attachment and will dial in. The client's local
    /// accept handler allow-lists exactly this id before accepting a
    /// connection on the VPC data-plane ALPN — the analogue of WireGuard's
    /// single-peer AllowedIPs check, enforced here since iroh's transport
    /// already replaces the rest of AllowedIPs' job.
    pub router_endpoint_id: Option<String>,
}

pub const VPC_ATTACHMENT_CONDITION_BOUND: &str = "Bound";
pub const VPC_ATTACHMENT_CONDITION_ADDRESS_ASSIGNED: &str = "AddressAssigned";
pub const VPC_ATTACHMENT_CONDITION_READY: &str = "Ready";
