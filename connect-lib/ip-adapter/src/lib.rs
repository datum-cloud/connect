//! Exclusive, nonpersistent IP interfaces for the CONNECT-IP prototype.
//! No existing interface or route is adopted or replaced. Closing the descriptor
//! removes the owned interface and its kernel routes, including on setup error.
use std::{io, net::IpAddr};

pub use ipnet::{IpNet, Ipv4Net};

#[cfg(unix)]
pub mod helper;

/// A native interface, or an interface owned by the separately approved helper.
/// Only the helper owns privileged OS handles; the daemon retains its user identity.
pub enum PacketDevice {
    Native(Tun),
    #[cfg(unix)]
    Helper(helper::Client),
}

impl PacketDevice {
    pub async fn create(
        name: &str,
        address: IpNet,
        mtu: u16,
        routes: &[IpNet],
        helper: Option<&std::path::Path>,
    ) -> io::Result<Self> {
        validate(name, address, mtu, routes)?;
        if let Some(socket) = helper {
            #[cfg(unix)]
            return helper::Client::connect(socket, name, address, mtu, routes)
                .await
                .map(Self::Helper);
            #[cfg(not(unix))]
            {
                let _ = socket;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "The networking helper currently supports Unix only",
                ));
            }
        }
        Tun::create(name, address, mtu, routes)
            .await
            .map(Self::Native)
    }

    /// Create a device while preserving the complete gateway approval sent to
    /// the privileged helper. Unlike `create`, this can authorize subnet
    /// routes and the gateway peer address independently.
    pub async fn create_gateway(
        name: &str,
        address: IpNet,
        peer_address: IpNet,
        mtu: u16,
        routes: &[IpNet],
        helper: Option<&std::path::Path>,
    ) -> io::Result<Self> {
        #[cfg(not(unix))]
        let _ = peer_address;

        validate(name, address, mtu, routes)?;
        if let Some(socket) = helper {
            #[cfg(unix)]
            return helper::Client::connect_approved(
                socket,
                helper::Approval {
                    interface_name: name.into(),
                    assigned_address: address,
                    peer_address,
                    mtu,
                    routes: routes.to_vec(),
                    advertise_routes: vec![],
                },
            )
            .await
            .map(Self::Helper);
            #[cfg(not(unix))]
            {
                let _ = socket;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "The networking helper currently supports Unix only",
                ));
            }
        }
        Tun::create(name, address, mtu, routes)
            .await
            .map(Self::Native)
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Native(tun) => tun.name(),
            #[cfg(unix)]
            Self::Helper(client) => client.name(),
        }
    }

    pub async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Native(tun) => tun.read_packet(buffer).await,
            #[cfg(unix)]
            Self::Helper(client) => client.read_packet(buffer).await,
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        match self {
            Self::Native(tun) => tun.write_packet(packet).await,
            #[cfg(unix)]
            Self::Helper(client) => client.write_packet(packet).await,
        }
    }
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Native driver identifier for diagnostics, not a transport protocol name.
pub const fn backend() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux_tun"
    } else if cfg!(target_os = "macos") {
        "macos_utun"
    } else if cfg!(target_os = "windows") {
        "windows_wintun"
    } else {
        "unsupported"
    }
}

pub struct Tun {
    name: String,
    mtu: u16,
    #[cfg(target_os = "linux")]
    fd: tokio::io::unix::AsyncFd<std::fs::File>,
    #[cfg(target_os = "macos")]
    device: macos::Device,
    #[cfg(target_os = "windows")]
    device: windows::Device,
}

impl Tun {
    pub async fn create(
        name: &str,
        address: IpNet,
        mtu: u16,
        routes: &[IpNet],
    ) -> io::Result<Self> {
        validate(name, address, mtu, routes)?;
        #[cfg(target_os = "linux")]
        {
            linux::create(name, address, mtu, routes).await
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            #[cfg(target_os = "macos")]
            let device = macos::Device::create(name, address, mtu, routes).await?;
            #[cfg(target_os = "windows")]
            let device = windows::Device::create(name, address, mtu, routes).await?;
            Ok(Self {
                name: device.name().to_owned(),
                mtu,
                device,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "CONNECT-IP requires Linux, macOS, or Windows",
            ))
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.len() < usize::from(self.mtu) {
            return Err(invalid("packet receive buffer is smaller than the TUN MTU"));
        }
        #[cfg(target_os = "linux")]
        {
            linux::read(&self.fd, buffer).await
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.device.read_packet(buffer).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "CONNECT-IP requires Linux, macOS, or Windows",
            ))
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let minimum = match packet.first().map(|byte| byte >> 4) {
            Some(4) => 20,
            Some(6) => 40,
            _ => return Err(invalid("packet must use IPv4 or IPv6")),
        };
        if packet.len() < minimum || packet.len() > usize::from(self.mtu) {
            return Err(invalid("IP packet must fit the configured TUN MTU"));
        }
        #[cfg(target_os = "linux")]
        {
            linux::write(&self.fd, packet).await
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.device.write_packet(packet).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "CONNECT-IP requires Linux, macOS, or Windows",
            ))
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub fn validate(name: &str, address: IpNet, mtu: u16, routes: &[IpNet]) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || !name.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(invalid(
            "TUN name must start with a letter and contain at most 15 ASCII letters, digits, underscores, or hyphens",
        ));
    }
    let width = if address.addr().is_ipv4() { 32 } else { 128 };
    if address.prefix_len() != width || !unicast(address.addr()) {
        return Err(invalid(
            "TUN address must be a unicast IPv4 /32 or global/ULA IPv6 /128 address",
        ));
    }
    if !(1280..=1500).contains(&mtu) {
        return Err(invalid("TUN MTU must be between 1280 and 1500"));
    }
    if routes.len() > 64 {
        return Err(invalid("at most 64 TUN routes are allowed"));
    }
    for route in routes {
        if route.addr().is_ipv4() != address.addr().is_ipv4()
            || route.prefix_len() < if route.addr().is_ipv4() { 8 } else { 16 }
            || route.addr() != route.network()
            || !unicast(route.network())
            || !unicast(route.broadcast())
        {
            return Err(invalid(
                "TUN routes must be same-family canonical unicast IPv4 /8..32 or global/ULA IPv6 /16..128 prefixes; default routes are unsupported",
            ));
        }
    }
    Ok(())
}

fn unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
                && address.octets()[0] != 0
                && address.octets()[0] < 224
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            (first & 0xe000 == 0x2000 || first & 0xfe00 == 0xfc00)
                && address.to_ipv4_mapped().is_none()
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
        process::Stdio,
        time::Duration,
    };
    use tokio::io::unix::AsyncFd;

    pub(super) async fn create(
        name: &str,
        address: IpNet,
        mtu: u16,
        routes: &[IpNet],
    ) -> io::Result<Tun> {
        let ip = ip_executable()?;
        let file = open_exclusive_tun(name)?;
        let tun = Tun {
            name: name.to_owned(),
            mtu,
            fd: AsyncFd::new(file)?,
        };
        let family = if address.addr().is_ipv4() { "-4" } else { "-6" };
        if address.addr().is_ipv6() {
            // The operator assigns unique /128s. A point-to-point TUN has no
            // Ethernet neighbor, so DAD would delay a valid static assignment.
            run_ip(
                &ip,
                &[
                    family,
                    "address",
                    "add",
                    &address.to_string(),
                    "dev",
                    name,
                    "nodad",
                ],
            )
            .await?;
        } else {
            run_ip(
                &ip,
                &[family, "address", "add", &address.to_string(), "dev", name],
            )
            .await?;
        }
        run_ip(
            &ip,
            &["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"],
        )
        .await?;
        for route in routes {
            run_ip(
                &ip,
                &[family, "route", "add", &route.to_string(), "dev", name],
            )
            .await?;
        }
        Ok(tun)
    }

    // Keep ifreq's raw-pointer union out of the async state machine. Only the
    // owned descriptor crosses an await; the resulting future remains Send.
    fn open_exclusive_tun(name: &str) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/net/tun")?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (destination, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *destination = byte as libc::c_char;
        }
        // IFF_TUN_EXCL makes TUNSETIFF reject an existing interface atomically.
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        // SAFETY: file is a live descriptor, request has the Linux ifreq layout,
        // and its validated name is NUL-terminated inside IFNAMSIZ.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = unsafe { std::ffi::CStr::from_ptr(request.ifr_name.as_ptr()) }
            .to_str()
            .map_err(|_| invalid("kernel returned an invalid TUN name"))?;
        if actual != name {
            return Err(io::Error::other(
                "kernel changed the requested exclusive TUN name",
            ));
        }
        Ok(file)
    }

    fn ip_executable() -> io::Result<PathBuf> {
        for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
            let path = match Path::new(candidate).canonicalize() {
                Ok(path) => path,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let metadata = std::fs::metadata(&path)?;
            if metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.mode() & 0o111 != 0
            {
                return Ok(path);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ip executable must be root-owned and not group/world writable",
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Linux iproute2 executable was not found in standard system directories",
        ))
    }

    async fn run_ip(executable: &Path, arguments: &[&str]) -> io::Result<()> {
        let mut child = tokio::process::Command::new(executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TUN iproute2 configuration timed out",
                )
            })??;
        if !status.success() {
            return Err(io::Error::other(format!(
                "TUN iproute2 {} failed (check CAP_NET_ADMIN and route conflicts)",
                arguments[0]
            )));
        }
        Ok(())
    }

    pub(super) async fn read(fd: &AsyncFd<File>, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = fd.readable().await?;
            match ready.try_io(|inner| {
                // SAFETY: the buffer is writable for its length and the owned FD remains open.
                let result = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub(super) async fn write(fd: &AsyncFd<File>, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = fd.writable().await?;
            match ready.try_io(|inner| {
                // SAFETY: packet is readable for its length and the owned FD remains open.
                let result = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else if result as usize != packet.len() {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short TUN packet write",
                    ))
                } else {
                    Ok(())
                }
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creation_future_is_send() {
        fn require_send<T: Send>(_: T) {}
        require_send(Tun::create(
            "datum0",
            "192.0.2.2/32".parse().unwrap(),
            1280,
            &[],
        ));
    }
    #[test]
    fn refuses_unsafe_names_addresses_routes_and_mtu() {
        let address = "192.0.2.2/32".parse().unwrap();
        let routes = ["10.78.0.0/24".parse().unwrap()];
        validate("datum0", address, 1280, &routes).unwrap();
        for name in ["", "../lo", "-danger", "lo;echo", "sixteencharacters"] {
            assert!(validate(name, address, 1280, &routes).is_err());
        }
        for route in [
            "0.0.0.0/0",
            "0.0.0.0/1",
            "127.0.0.0/8",
            "224.0.0.0/8",
            "10.78.0.1/24",
        ] {
            assert!(validate("datum0", address, 1280, &[route.parse().unwrap()]).is_err());
        }
        assert!(validate("datum0", "192.0.2.2/24".parse().unwrap(), 1280, &routes).is_err());
        assert!(validate("datum0", address, 1501, &routes).is_err());
    }
    #[test]
    fn ipv6_host_routes_are_bounded_and_family_scoped() {
        let address: IpNet = "fd42:20::2/128".parse().unwrap();
        validate("datum6", address, 1280, &["fd42:30::/64".parse().unwrap()]).unwrap();
        for route in [
            "::/0",
            "::/16",
            "ff00::/16",
            "fe80::/64",
            "::ffff:192.0.2.0/120",
            "fd00::/8",
            "fd42:30::1/64",
            "10.0.0.0/8",
        ] {
            assert!(
                validate("datum6", address, 1280, &[route.parse().unwrap()]).is_err(),
                "{route}"
            );
        }
        for address in [
            "::/128",
            "::1/128",
            "fe80::1/128",
            "ff02::1/128",
            "fd42:20::2/64",
            "::ffff:192.0.2.2/128",
        ] {
            assert!(
                validate("datum6", address.parse().unwrap(), 1280, &[]).is_err(),
                "{address}"
            );
        }
        assert!(validate("datum6", address, 1279, &[]).is_err());
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[tokio::test]
    async fn other_platforms_fail_without_network_changes() {
        let result = Tun::create("datum0", "192.0.2.2/32".parse().unwrap(), 1280, &[]).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
    }
}
