//! Client support for the `vpc` verb: joins a local TUN interface to a
//! Datum Cloud galactic VPC as a remote member, over an iroh connection to
//! a galactic-side router — the `tunnel` feature's sibling, but carrying
//! raw IP packets to a router instead of HTTP requests to Envoy.
//!
//! See `design/vpc-attachment.md` for the full design and the CRD contract
//! this module is scaffolded against, and `transport.rs`/`routing.rs` for
//! why specific choices (framing, routing-mode collapse, MTU) were made.

mod routing;
mod transport;

pub use routing::{configure_interface, install_routes};
pub use transport::{IROH_VPC_ALPN, VpcAcceptHandler, VpcDialer};

use std::sync::Arc;

use iroh::{Endpoint, EndpointId, SecretKey, protocol::Router};
use n0_error::{Result, StdResultExt};
use tokio::sync::Mutex;
use tun::{AsyncDevice, Configuration, DeviceReader, DeviceWriter, Layer};

use crate::{Repo, node::build_endpoint};

/// Routing mode requested for a VPC attachment's local interface. See
/// `routing::install_routes` for what each mode actually installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    VpcOnly,
    DefaultRoute,
}

/// Creates (but does not address or bring up) a TUN device by name. Address
/// assignment, MTU, and bring-up are handled separately by
/// `routing::configure_interface` — this only creates the device itself, so
/// callers can split it into reader/writer halves before the interface
/// starts carrying traffic.
///
/// Creating a TUN device needs `CAP_NET_ADMIN` (root, or that capability
/// grant) — this never attempts to elevate itself (e.g. via `sudo`); it
/// just fails with a message pointing at what's missing, so the caller can
/// supply the privilege themselves.
pub fn create_tun_device(name: &str, mtu: u16) -> Result<AsyncDevice> {
    let mut config = Configuration::default();
    config.tun_name(name).layer(Layer::L3).mtu(mtu);
    tun::create_as_async(&config).map_err(|err| {
        if is_permission_denied(&err) {
            n0_error::anyerr!(
                "creating tun device {name:?} failed (permission denied): {err}. \
                 This needs CAP_NET_ADMIN — re-run as root or with that capability granted; \
                 this will not attempt to elevate privileges itself."
            )
        } else {
            n0_error::anyerr!("creating tun device {name:?}: {err}")
        }
    })
}

fn is_permission_denied(err: &tun::Error) -> bool {
    matches!(err, tun::Error::Io(io_err) if io_err.kind() == std::io::ErrorKind::PermissionDenied)
}

/// A standalone iroh listener dedicated to accepting one VPC attachment's
/// data-plane connection.
///
/// Deliberately independent of `ListenNode` (used by `tunnel`): VPC
/// attachments have their own iroh identity, ALPN, and (once the CRD lands)
/// authorization source, and keeping this separate means the new feature
/// cannot regress tunnel's accept path. Structurally this plays the same
/// role `ListenNode` does for `tunnel` — the client is the accept side,
/// dialed in by the galactic-side router once it claims the attachment,
/// mirroring how Envoy dials in to an existing tunnel.
#[derive(Debug, Clone)]
pub struct VpcListener {
    router: Router,
}

impl VpcListener {
    /// `allowed_router` gates which remote iroh endpoint may dial in and
    /// start pumping packets — the analogue of WireGuard's single-peer
    /// AllowedIPs check, enforced here instead of via a routing trie since
    /// there is exactly one peer. In the CRD-backed version this comes from
    /// `VPCAttachmentStatus::router_endpoint_id`, populated once a router
    /// claims the attachment; `None` here means no router has claimed it
    /// yet (or, in this scaffold, that the caller didn't provide one) and
    /// is accept-any/trust-on-first-connect — see the warning on
    /// `VpcAcceptHandler` about why that must not become the production
    /// default.
    pub async fn bind(
        repo: &Repo,
        secret_key: SecretKey,
        allowed_router: Option<EndpointId>,
        tun_reader: Arc<Mutex<DeviceReader>>,
        tun_writer: Arc<Mutex<DeviceWriter>>,
        mtu: usize,
    ) -> Result<Self> {
        let config = repo.config().await?;
        let endpoint = build_endpoint(secret_key, &config).await?;
        let handler = VpcAcceptHandler::new(allowed_router, tun_reader, tun_writer, mtu);
        let router = Router::builder(endpoint)
            .accept(IROH_VPC_ALPN, handler)
            .spawn();
        Ok(Self { router })
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.router.endpoint().id()
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .std_context("vpc router shutdown")?;
        Ok(())
    }
}
