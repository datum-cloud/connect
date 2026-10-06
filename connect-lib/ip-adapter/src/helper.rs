//! Root-owned, explicit host/subnet interface approvals over authenticated Unix IPC.
//! No cloud credentials, shell commands, arbitrary routes, or file paths cross IPC.
use crate::{IpNet, Tun, invalid, validate};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, ReadHalf, WriteHalf},
    net::{UnixListener, UnixStream},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

const VERSION: u8 = 2;
const MAX_CONTROL: usize = 65535;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub interface_name: String,
    pub assigned_address: IpNet,
    pub peer_address: IpNet,
    pub mtu: u16,
    #[serde(default)]
    pub routes: Vec<IpNet>,
    #[serde(default)]
    pub advertise_routes: Vec<IpNet>,
}

/// Root-owned capability for future managed VPC client attachments. Callers
/// still submit a typed attachment plan; every field is bounded here.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedPolicy {
    pub client_only: bool,
    pub address_ranges: Vec<IpNet>,
    pub route_ranges: Vec<IpNet>,
    pub minimum_route_prefix: u8,
    pub minimum_mtu: u16,
    pub maximum_mtu: u16,
    pub interface_prefix: String,
    pub interface_behavior: String,
    pub maximum_active_attachments: u8,
    pub maximum_routes_per_attachment: u8,
    pub deny_connect_route_overlap: bool,
}

impl ManagedPolicy {
    /// Conservative cross-project default for Datum-managed IPv6 VPC clients.
    /// Direct peers and route advertisement never use this policy.
    pub fn managed_vpc_default() -> Self {
        Self {
            client_only: true,
            address_ranges: vec!["fc00::/7".parse().expect("valid ULA range")],
            route_ranges: vec!["fc00::/7".parse().expect("valid ULA range")],
            minimum_route_prefix: 16,
            minimum_mtu: 1280,
            maximum_mtu: 1500,
            interface_prefix: "dc".into(),
            interface_behavior: "ephemeral_exclusive".into(),
            maximum_active_attachments: 8,
            maximum_routes_per_attachment: 32,
            deny_connect_route_overlap: true,
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if !self.client_only
            || !self.deny_connect_route_overlap
            || self.interface_behavior != "ephemeral_exclusive"
            || self.interface_prefix != "dc"
            || self.address_ranges.is_empty()
            || self.address_ranges.len() > 8
            || self.route_ranges.is_empty()
            || self.route_ranges.len() > 8
            || self.minimum_route_prefix < 8
            || self.minimum_mtu < 1280
            || self.maximum_mtu < self.minimum_mtu
            || self.maximum_mtu > 1500
            || self.maximum_active_attachments == 0
            || self.maximum_active_attachments > 16
            || self.maximum_routes_per_attachment == 0
            || self.maximum_routes_per_attachment > 32
        {
            return Err(invalid(
                "managed policy must describe bounded, ephemeral client-only networking",
            ));
        }
        let ula: IpNet = "fc00::/7".parse().expect("valid ULA range");
        if self
            .address_ranges
            .iter()
            .chain(&self.route_ranges)
            .any(|range| {
                range.addr().is_ipv4()
                    || range.prefix_len() < ula.prefix_len()
                    || range.network() != range.addr()
                    || !ula.contains(&range.network())
            })
        {
            return Err(invalid(
                "managed policy ranges must be canonical IPv6 ULA prefixes",
            ));
        }
        Ok(())
    }

    pub fn approve(&self, approval: &Approval) -> io::Result<()> {
        self.validate()?;
        Config {
            allowed_uid: 1,
            approvals: vec![approval.clone()],
            managed_policy: None,
        }
        .validate()?;
        if !approval.advertise_routes.is_empty() {
            return Err(invalid(
                "managed VPC policy permits client attachments only; advertised routes require exact approval",
            ));
        }
        if approval.interface_name.len() != 12
            || !approval.interface_name.starts_with(&self.interface_prefix)
            || !approval.interface_name[2..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid(
                "managed VPC interface name is outside administrator-approved behavior",
            ));
        }
        if approval.assigned_address.addr().is_ipv4()
            || approval.assigned_address.prefix_len() != 128
            || approval.peer_address.addr().is_ipv4()
            || approval.peer_address.prefix_len() != 128
            || !self
                .address_ranges
                .iter()
                .any(|range| range.contains(&approval.assigned_address.addr()))
            || !self
                .address_ranges
                .iter()
                .any(|range| range.contains(&approval.peer_address.addr()))
        {
            return Err(invalid(
                "managed VPC host addresses are outside administrator-approved ranges",
            ));
        }
        if approval.mtu < self.minimum_mtu || approval.mtu > self.maximum_mtu {
            return Err(invalid(
                "managed VPC MTU is outside administrator-approved limits",
            ));
        }
        if approval.routes.len() > usize::from(self.maximum_routes_per_attachment) {
            return Err(invalid("managed VPC plan has too many routes"));
        }
        for route in &approval.routes {
            if route.addr().is_ipv4()
                || route.prefix_len() < self.minimum_route_prefix
                || !self.route_ranges.iter().any(|range| {
                    route.prefix_len() >= range.prefix_len() && range.contains(&route.network())
                })
            {
                return Err(invalid(
                    "managed VPC route is outside administrator-approved ranges or prefix limits",
                ));
            }
        }
        Ok(())
    }
}

impl Approval {
    pub fn tun_routes(&self) -> Vec<IpNet> {
        if self.routes.is_empty() {
            vec![self.peer_address]
        } else {
            self.routes.clone()
        }
    }
    fn packet_allowed(&self, packet: &[u8], sending: bool) -> bool {
        let (source, destination) = match packet.first().map(|b| b >> 4) {
            Some(4) if packet.len() >= 20 => (
                IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
                IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()),
            ),
            Some(6) if packet.len() >= 40 => (
                IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
                IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
            ),
            _ => return false,
        };
        if !host_pair(packet, source, destination) {
            return false;
        }
        let (local, remote) = if sending {
            (source, destination)
        } else {
            (destination, source)
        };
        let local_ok = if self.advertise_routes.is_empty() {
            local == self.assigned_address.addr()
        } else {
            self.advertise_routes.iter().any(|r| r.contains(&local))
        };
        let remote_ok = if self.routes.is_empty() {
            remote == self.peer_address.addr()
        } else {
            self.routes.iter().any(|r| r.contains(&remote))
        };
        local_ok && remote_ok
    }
}

fn routes_conflict(left: &Approval, right: &Approval) -> bool {
    let left_routes = left.tun_routes();
    let right_routes = right.tun_routes();
    left_routes.iter().any(|route| {
        route.contains(&right.assigned_address.addr())
            || right_routes.iter().any(|candidate| {
                candidate.contains(&route.network()) || route.contains(&candidate.network())
            })
    }) || right_routes
        .iter()
        .any(|route| route.contains(&left.assigned_address.addr()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub allowed_uid: u32,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default)]
    pub managed_policy: Option<ManagedPolicy>,
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if self.allowed_uid == 0
            || self.allowed_uid == u32::MAX
            || (self.approvals.is_empty() && self.managed_policy.is_none())
            || self.approvals.len() > 16
        {
            return Err(invalid(
                "helper requires a non-root user and an explicit approval or managed VPC policy",
            ));
        }
        if let Some(policy) = &self.managed_policy {
            policy.validate()?;
        }
        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        for approval in &self.approvals {
            if (!approval.routes.is_empty() && !approval.advertise_routes.is_empty())
                || approval.routes.len() + approval.advertise_routes.len() > 32
            {
                return Err(invalid(
                    "approve at most 32 prefixes on only one side of a peer attachment",
                ));
            }
            let subnet_routes: Vec<_> = approval
                .routes
                .iter()
                .chain(&approval.advertise_routes)
                .copied()
                .collect();
            validate(
                &approval.interface_name,
                approval.assigned_address,
                approval.mtu,
                &subnet_routes,
            )?;
            for (i, route) in subnet_routes.iter().enumerate() {
                if route.contains(&approval.assigned_address.addr())
                    || route.contains(&approval.peer_address.addr())
                    || subnet_routes[..i]
                        .iter()
                        .any(|r| r.contains(&route.network()) || route.contains(&r.network()))
                {
                    return Err(invalid(
                        "approved subnet routes overlap each other or a peer host address",
                    ));
                }
            }
            validate(
                &approval.interface_name,
                approval.assigned_address,
                approval.mtu,
                &[approval.peer_address],
            )?;
            let peer = approval.peer_address;
            if peer.prefix_len() != if peer.addr().is_ipv4() { 32 } else { 128 }
                || !names.insert(&approval.interface_name)
                || !addresses.insert(approval.assigned_address.addr())
                || !addresses.insert(peer.addr())
            {
                return Err(invalid(
                    "helper approvals require unique labels and distinct, nonoverlapping host addresses",
                ));
            }
        }
        // Approvals are durable authorization records, not installed routes.
        // Different networks can legitimately advertise overlapping prefixes
        // while only one attachment is active. Route conflicts are rejected
        // atomically at session admission, where we know what is live.
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        use std::io::Read;
        trusted_path(path, false)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.len() > 65536 {
            return Err(invalid(
                "helper config must be a root-owned private regular file, at most 64 KiB",
            ));
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid helper configuration"))?;
        config.validate()?;
        Ok(config)
    }
}

/// Refuse symlinks and writable/non-root ancestors, including for socket creation.
pub fn trusted_path(path: &Path, directory: bool) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "helper paths must be absolute without parent traversal",
        ));
    }
    for (index, ancestor) in path.ancestors().enumerate() {
        let meta = std::fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || ((index > 0 || directory) && !meta.is_dir())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper paths and ancestors must be root-owned, non-symlink, and not group/world writable",
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    #[serde(default)]
    approval: Option<Approval>,
    #[serde(default)]
    managed: bool,
    #[serde(default)]
    inspect: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    interface_name: Option<String>,
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approvals: Option<Vec<Approval>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_policy: Option<ManagedPolicy>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub version: u8,
    pub approvals: Vec<Approval>,
    pub managed_policy: Option<ManagedPolicy>,
}

/// Authenticate the privileged service and read approvals without creating an interface.
pub async fn inspect(socket: &Path) -> io::Result<Status> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let stream = UnixStream::connect(socket).await?;
        if stream.peer_cred()?.uid() != 0 { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "network helper is not root-owned")); }
        let (read, mut write) = tokio::io::split(stream);
        send_frame(&mut write, &serde_json::to_vec(&Request { version:VERSION, approval:None, managed:false, inspect:true })?).await?;
        let response: Response = serde_json::from_slice(&receive(&mut reader(read, MAX_CONTROL)).await?)?;
        if response.version != VERSION { return Err(invalid("network helper protocol mismatch; upgrade the helper with the matching Connect release")); }
        Ok(Status { version:response.version, approvals:response.approvals.ok_or_else(|| invalid("network helper needs an upgrade; approval inspection is unavailable"))?, managed_policy:response.managed_policy })
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "network helper did not respond"))?
}

type Reader = FramedRead<ReadHalf<UnixStream>, LengthDelimitedCodec>;
fn reader(read: ReadHalf<UnixStream>, limit: usize) -> Reader {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(limit)
        .new_read(read)
}
async fn send_frame(writer: &mut WriteHalf<UnixStream>, bytes: &[u8]) -> io::Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| invalid("IPC frame exceeds limit"))?;
    writer.write_u16(len).await?;
    writer.write_all(bytes).await
}
async fn receive(reader: &mut Reader) -> io::Result<Vec<u8>> {
    reader
        .next()
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "network helper disconnected"))?
        .map(|b| b.to_vec())
}

pub struct Client {
    name: String,
    mtu: usize,
    read: Mutex<Reader>,
    send: mpsc::Sender<Vec<u8>>,
    writer: JoinHandle<()>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.writer.abort();
    }
}
impl Client {
    pub async fn connect(
        socket: &Path,
        name: &str,
        address: IpNet,
        mtu: u16,
        routes: &[IpNet],
    ) -> io::Result<Self> {
        if routes.len() != 1 {
            return Err(invalid(
                "network helper supports exactly one approved peer host route",
            ));
        }
        let approval = Approval {
            interface_name: name.into(),
            assigned_address: address,
            peer_address: routes[0],
            mtu,
            routes: vec![],
            advertise_routes: vec![],
        };
        Self::connect_approved(socket, approval).await
    }

    pub async fn connect_approved(socket: &Path, approval: Approval) -> io::Result<Self> {
        Self::connect_request(socket, approval, false).await
    }

    pub async fn connect_managed(socket: &Path, approval: Approval) -> io::Result<Self> {
        Self::connect_request(socket, approval, true).await
    }

    async fn connect_request(socket: &Path, approval: Approval, managed: bool) -> io::Result<Self> {
        let mtu = approval.mtu;
        let stream = UnixStream::connect(socket).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Cannot reach networking helper at {}: {e}",
                    socket.display()
                ),
            )
        })?;
        if stream.peer_cred()?.uid() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "networking helper must run as root",
            ));
        }
        let (read, mut write) = tokio::io::split(stream);
        let mut read = reader(read, MAX_CONTROL);
        let response: Response = tokio::time::timeout(Duration::from_secs(8), async {
            send_frame(
                &mut write,
                &serde_json::to_vec(&Request {
                    version: VERSION,
                    approval: Some(approval),
                    managed,
                    inspect: false,
                })?,
            )
            .await?;
            serde_json::from_slice(&receive(&mut read).await?).map_err(io::Error::other)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "network helper setup timed out"))??;
        if response.version != VERSION {
            return Err(invalid("network helper protocol version mismatch"));
        }
        if let Some(error) = response.error {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, error));
        }
        let name = response
            .interface_name
            .ok_or_else(|| invalid("network helper omitted interface name"))?;
        read.decoder_mut().set_max_frame_length(usize::from(mtu));
        let (send, mut queue) = mpsc::channel::<Vec<u8>>(32);
        // Independent writer preserves frame boundaries when a caller's send is cancelled.
        let writer = tokio::spawn(async move {
            while let Some(packet) = queue.recv().await {
                if send_frame(&mut write, &packet).await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            name,
            mtu: usize::from(mtu),
            read: Mutex::new(read),
            send,
            writer,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.len() < self.mtu {
            return Err(invalid("packet buffer is smaller than helper MTU"));
        }
        // FramedRead retains partially received bytes across select! cancellation.
        let packet = receive(&mut *self.read.lock().await).await?;
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > self.mtu {
            return Err(invalid("packet exceeds helper MTU"));
        }
        self.send
            .send(packet.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "network helper disconnected"))
    }
}

/// Serve only the root-approved host pairs. Closing IPC destroys the owned interface.
pub async fn serve(
    config: Config,
    socket: &Path,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    serve_reloadable(config, socket, None, shutdown).await
}

/// Reload root-approved configuration for new requests without dropping live interfaces.
pub async fn serve_reloadable(
    config: Config,
    socket: &Path,
    config_path: Option<&Path>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "network helper requires administrator installation",
        ));
    }
    config.validate()?;
    trusted_path(
        socket
            .parent()
            .ok_or_else(|| invalid("missing socket parent"))?,
        true,
    )?;
    // A lifetime lock permits safe recovery of our stale socket after a crash.
    // Root-only parent prevents another user replacing either path.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(socket.with_extension("lock"))?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(invalid("unsafe helper lock file"));
    }
    fs2::FileExt::try_lock_exclusive(&lock)?;
    match std::fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == config.allowed_uid => {
            if UnixStream::connect(socket).await.is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "helper socket is already active",
                ));
            }
            std::fs::remove_file(socket)?;
        }
        Ok(_) => return Err(invalid("refuse to replace an unrelated helper socket path")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(socket)?;
    struct SocketGuard<'a>(&'a Path);
    impl Drop for SocketGuard<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _guard = SocketGuard(socket);
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let path = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())
        .map_err(|_| invalid("invalid socket path"))?;
    if unsafe { libc::chown(path.as_ptr(), config.allowed_uid, !0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let config = Arc::new(config);
    let active = Arc::new(Mutex::new(HashMap::<String, Approval>::new()));
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    tracing::info!(
        stage = "network_helper",
        uid = config.allowed_uid,
        approvals = config.approvals.len(),
        "helper_ready"
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            incoming = listener.accept() => {
                let (stream, _) = incoming?;
                if stream.peer_cred()?.uid() != config.allowed_uid || tasks.len() >= 32 {
                    tracing::warn!(stage="network_helper", "helper_client_rejected");
                    continue;
                }
                let current = if let Some(path) = config_path {
                    match Config::load(path) {
                        Ok(current) if current.allowed_uid == config.allowed_uid => Arc::new(current),
                        _ => { tracing::warn!(stage="network_helper", "helper_approval_reload_rejected"); continue; }
                    }
                } else { config.clone() };
                let (config, active) = (current, active.clone());
                tasks.spawn(async move {
                    if let Err(error) = session(stream, config, active).await {
                        tracing::warn!(stage="network_helper", %error, "helper_session_closed");
                    }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn session(
    stream: UnixStream,
    config: Arc<Config>,
    active: Arc<Mutex<HashMap<String, Approval>>>,
) -> io::Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut read = reader(read, MAX_CONTROL);
    let request: Request = tokio::time::timeout(Duration::from_secs(3), async {
        serde_json::from_slice(&receive(&mut read).await?)
            .map_err(|_| invalid("invalid helper request"))
    })
    .await
    .map_err(|_| invalid("helper request timed out"))??;
    if request.version == VERSION
        && request.inspect
        && request.approval.is_none()
        && !request.managed
    {
        return send_frame(
            &mut write,
            &serde_json::to_vec(&Response {
                version: VERSION,
                interface_name: None,
                error: None,
                approvals: Some(config.approvals.clone()),
                managed_policy: config.managed_policy.clone(),
            })?,
        )
        .await;
    }
    if request.inspect {
        return Err(invalid("ambiguous helper request"));
    }
    let approval = request
        .approval
        .ok_or_else(|| invalid("missing interface approval"))?;
    let approved = request.version == VERSION
        && if request.managed {
            config
                .managed_policy
                .as_ref()
                .is_some_and(|policy| policy.approve(&approval).is_ok())
        } else {
            config.approvals.contains(&approval)
        };
    let mut active_set = active.lock().await;
    let conflict = active_set
        .values()
        .any(|other| routes_conflict(&approval, other));
    let capacity_reached = request.managed
        && config.managed_policy.as_ref().is_some_and(|policy| {
            active_set.len() >= usize::from(policy.maximum_active_attachments)
        });
    if !approved
        || capacity_reached
        || active_set.contains_key(&approval.interface_name)
        || conflict
    {
        let message = if conflict {
            "Another active Connect IP attachment owns an overlapping route; leave it before joining this network".into()
        } else if capacity_reached {
            "Managed VPC attachment limit is reached; leave another network or ask an administrator to update the policy".into()
        } else if request.managed {
            config
                .managed_policy
                .as_ref()
                .and_then(|policy| policy.approve(&approval).err())
                .map(|error| {
                    format!("Managed VPC plan is outside administrator-approved policy: {error}")
                })
                .unwrap_or_else(|| "Managed VPC networking is not administrator-approved".into())
        } else {
            "Interface configuration is not approved or is already active".into()
        };
        let response = Response {
            approvals: None,
            managed_policy: None,
            version: VERSION,
            interface_name: None,
            error: Some(message),
        };
        send_frame(&mut write, &serde_json::to_vec(&response)?).await?;
        return Ok(());
    }
    active_set.insert(approval.interface_name.clone(), approval.clone());
    drop(active_set);
    // Keep reservation cleanup on all exits, including setup failure.
    let result = session_approved(&approval, &mut read, &mut write).await;
    active.lock().await.remove(&approval.interface_name);
    result
}

async fn session_approved(
    approval: &Approval,
    read: &mut Reader,
    write: &mut WriteHalf<UnixStream>,
) -> io::Result<()> {
    let tun = Tun::create(
        &approval.interface_name,
        approval.assigned_address,
        approval.mtu,
        &approval.tun_routes(),
    )
    .await?;
    let response = Response {
        approvals: None,
        managed_policy: None,
        version: VERSION,
        interface_name: Some(tun.name().into()),
        error: None,
    };
    send_frame(write, &serde_json::to_vec(&response)?).await?;
    read.decoder_mut()
        .set_max_frame_length(usize::from(approval.mtu));
    tracing::info!(
        stage = "network_helper",
        interface = tun.name(),
        "helper_interface_ready"
    );
    let inbound = async {
        loop {
            let packet = receive(read).await?;
            if !approval.packet_allowed(&packet, false) {
                return Err(invalid("helper rejected packet outside approved host pair"));
            }
            tun.write_packet(&packet).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let outbound = async {
        let mut packet = vec![0; usize::from(approval.mtu)];
        loop {
            let len = tun.read_packet(&mut packet).await?;
            if approval.packet_allowed(&packet[..len], true) {
                send_frame(write, &packet[..len]).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let result = tokio::try_join!(inbound, outbound).map(|_| ());
    tracing::info!(
        stage = "network_helper",
        interface = tun.name(),
        "helper_interface_closed"
    );
    result
}

fn host_pair(packet: &[u8], source: IpAddr, destination: IpAddr) -> bool {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet.len() >= 20
                && packet[0] == 0x45
                && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
                && u16::from_be_bytes([packet[6], packet[7]]) & 0xbfff == 0
                && packet[8] != 0
                && (matches!(packet[9], 6 | 17)
                    || (packet[9] == 1 && packet.len() >= 28 && matches!(packet[20], 0 | 8)))
                && packet[12..16] == source.octets()
                && packet[16..20] == destination.octets()
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet.len() >= 40
                && packet[0] >> 4 == 6
                && usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
                && packet[7] != 0
                && (matches!(packet[6], 6 | 17)
                    || (packet[6] == 58 && packet.len() >= 48 && matches!(packet[40], 128 | 129)))
                && packet[8..24] == source.octets()
                && packet[24..40] == destination.octets()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn inspection_rejects_an_unprivileged_server() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("fake.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        assert_eq!(
            inspect(&socket).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[test]
    fn inspection_response_fits_bounded_control_frame() {
        let approvals = (1..=16)
            .map(|n| Approval {
                interface_name: format!("dc{n:013}"),
                assigned_address: format!("fdff:ffff:ffff:ffff:ffff:ffff:ffff:{n:x}/128")
                    .parse()
                    .unwrap(),
                peer_address: format!("fdfe:ffff:ffff:ffff:ffff:ffff:ffff:{n:x}/128")
                    .parse()
                    .unwrap(),
                mtu: 1280,
                routes: vec![],
                advertise_routes: vec![],
            })
            .collect();
        let response = Response {
            version: VERSION,
            interface_name: None,
            error: None,
            approvals: Some(approvals),
            managed_policy: None,
        };
        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_CONTROL);
    }
    fn config() -> Config {
        Config {
            allowed_uid: 501,
            approvals: vec![Approval {
                interface_name: "dcpeer".into(),
                assigned_address: "192.0.2.1/32".parse().unwrap(),
                peer_address: "192.0.2.2/32".parse().unwrap(),
                routes: vec![],
                advertise_routes: vec![],
                mtu: 1280,
            }],
            managed_policy: None,
        }
    }
    #[test]
    fn approvals_are_exact_and_bounded() {
        config().validate().unwrap();
        let mut bad = config();
        bad.allowed_uid = 0;
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.approvals[0].peer_address = "192.0.2.0/24".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.approvals.push(bad.approvals[0].clone());
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.approvals[0].peer_address = bad.approvals[0].assigned_address;
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.approvals[0].mtu = 65535;
        assert!(bad.validate().is_err());
        assert!(
            serde_json::from_str::<Config>(r#"{"allowed_uid":501,"approvals":[],"command":"sh"}"#)
                .is_err()
        );
    }
    #[test]
    fn stored_approvals_may_overlap_but_live_routes_conflict() {
        let mut old = config().approvals[0].clone();
        old.assigned_address = "fd60::10/128".parse().unwrap();
        old.peer_address = "fd8f::10/128".parse().unwrap();
        old.routes = vec!["fd20:0:27::/48".parse().unwrap()];
        let mut new = old.clone();
        new.interface_name = "dcnewnet".into();
        new.assigned_address = "fd60::1/128".parse().unwrap();
        new.peer_address = "fd8f::1/128".parse().unwrap();
        new.routes = vec!["fd20:0:27::1:0:0/128".parse().unwrap()];
        Config {
            allowed_uid: 501,
            approvals: vec![old.clone(), new.clone()],
            managed_policy: None,
        }
        .validate()
        .expect("inactive approvals must not block setup for another network");
        assert!(routes_conflict(&old, &new));
        new.routes = vec!["fd20:0:28::/48".parse().unwrap()];
        assert!(!routes_conflict(&old, &new));
    }
    #[test]
    fn packet_injection_stays_in_approved_host_pair() {
        let src = "192.0.2.2".parse().unwrap();
        let dst = "192.0.2.1".parse().unwrap();
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[3] = 28;
        packet[8] = 64;
        packet[9] = 1;
        packet[20] = 8;
        packet[12..16].copy_from_slice(&[192, 0, 2, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        assert!(host_pair(&packet, src, dst));
        assert!(!host_pair(&packet, dst, src));
        assert!(!host_pair(&packet[..19], src, dst));
        packet[0] = 0x46;
        assert!(
            !host_pair(&packet, src, dst),
            "source-routing options are forbidden"
        );
    }
    #[test]
    fn subnet_approval_enforces_direction_addresses_and_no_transit() {
        let mut client = config().approvals.remove(0);
        client.routes = vec!["10.50.0.0/24".parse().unwrap()];
        let mut router = client.clone();
        std::mem::swap(&mut router.assigned_address, &mut router.peer_address);
        router.advertise_routes = std::mem::take(&mut router.routes);
        Config {
            allowed_uid: 501,
            approvals: vec![client.clone()],
            managed_policy: None,
        }
        .validate()
        .unwrap();
        Config {
            allowed_uid: 501,
            approvals: vec![router.clone()],
            managed_policy: None,
        }
        .validate()
        .unwrap();
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[3] = 28;
        packet[8] = 64;
        packet[9] = 1;
        packet[20] = 8;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[10, 50, 0, 3]);
        assert!(client.packet_allowed(&packet, true));
        assert!(router.packet_allowed(&packet, false));
        assert!(!client.packet_allowed(&packet, false));
        packet[15] = 9;
        assert!(!router.packet_allowed(&packet, false));
        packet[15] = 1;
        packet[17] = 51;
        assert!(!client.packet_allowed(&packet, true));
        client.advertise_routes = router.advertise_routes;
        assert!(
            Config {
                allowed_uid: 501,
                approvals: vec![client],
                managed_policy: None,
            }
            .validate()
            .is_err()
        );
    }
    #[test]
    fn managed_policy_is_client_only_and_bounded() {
        let policy = ManagedPolicy::managed_vpc_default();
        let approval = Approval {
            interface_name: "dc0123456789".into(),
            assigned_address: "fd60::10/128".parse().unwrap(),
            peer_address: "fd60::1/128".parse().unwrap(),
            mtu: 1280,
            routes: vec!["fd20:27::/48".parse().unwrap()],
            advertise_routes: vec![],
        };
        policy.approve(&approval).unwrap();

        let mut public_route = approval.clone();
        public_route.routes = vec!["2001:db8::/32".parse().unwrap()];
        assert!(policy.approve(&public_route).is_err());
        let mut default_route = approval.clone();
        default_route.routes = vec!["::/0".parse().unwrap()];
        assert!(policy.approve(&default_route).is_err());
        let mut router = approval.clone();
        router.advertise_routes = vec!["fd30::/48".parse().unwrap()];
        assert!(policy.approve(&router).is_err());
        let mut arbitrary_interface = approval;
        arbitrary_interface.interface_name = "en0".into();
        assert!(policy.approve(&arbitrary_interface).is_err());
    }
    #[tokio::test]
    async fn framing_survives_cancelled_read_and_rejects_oversized_frames() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, _) = tokio::io::split(a);
        let (_, mut w) = tokio::io::split(b);
        let mut r = reader(r, 1280);
        w.write_all(&[0]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), receive(&mut r))
                .await
                .is_err()
        );
        w.write_all(&[3, 1, 2, 3]).await.unwrap();
        assert_eq!(receive(&mut r).await.unwrap(), vec![1, 2, 3]);
        w.write_u16(1281).await.unwrap();
        assert!(receive(&mut r).await.is_err());
    }
}
