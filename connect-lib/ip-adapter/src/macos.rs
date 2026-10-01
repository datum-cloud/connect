//! macOS utun: an owned control socket owns the interface and its routes.
//! ABI: apple-oss-distributions/xnu bsd/net/if_utun.{c,h}.
use super::{IpNet, invalid};
use std::{
    ffi::CStr,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    process::Stdio,
    time::Duration,
};
use tokio::io::unix::AsyncFd;

pub(super) struct Device {
    name: String,
    fd: AsyncFd<File>,
}

impl Device {
    pub(super) async fn create(
        _label: &str,
        address: IpNet,
        mtu: u16,
        routes: &[IpNet],
    ) -> io::Result<Self> {
        // No interface is created before this check. Do not prompt for elevation
        // from a headless process or borrow the invoking user's login session.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS CONNECT-IP requires a privileged daemon for utun and routes; install a system daemon with service-account credentials (--system --local-ip-config PATH). A user daemon still supports serve and dial",
            ));
        }
        for path in ["/sbin/ifconfig", "/sbin/route"] {
            let meta = std::fs::metadata(path)?;
            if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "macOS network configuration tools must be root-owned and not group/world writable",
                ));
            }
        }
        let (file, name) = open_utun()?;
        let device = Self {
            name,
            fd: AsyncFd::new(file)?,
        };
        // Keep the interface alive until any configuration subprocess has been
        // killed AND reaped. Otherwise cancellation could release the utun name
        // before an old child exits, allowing it to affect a newly reused name.
        let (cancel, mut cancelled) = tokio::sync::oneshot::channel::<()>();
        let commands = configuration(&device.name, address, mtu, routes);
        let task = tokio::spawn(async move {
            for (path, args) in commands {
                run(path, &args, &mut cancelled).await?;
            }
            Ok(device)
        });
        let result = task.await.map_err(|error| {
            io::Error::other(format!(
                "macOS interface configuration task failed: {error}"
            ))
        })?;
        drop(cancel);
        result
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| {
                let mut prefix = [0u8; 4];
                let mut vectors = [
                    libc::iovec {
                        iov_base: prefix.as_mut_ptr().cast(),
                        iov_len: prefix.len(),
                    },
                    libc::iovec {
                        iov_base: buffer.as_mut_ptr().cast(),
                        iov_len: buffer.len(),
                    },
                ];
                // SAFETY: both slices remain live and writable throughout readv.
                let length =
                    unsafe { libc::readv(fd.get_ref().as_raw_fd(), vectors.as_mut_ptr(), 2) };
                if length < 0 {
                    return Err(io::Error::last_os_error());
                }
                let length =
                    usize::try_from(length).map_err(|_| invalid("invalid utun read length"))?;
                if length < 5 {
                    return Err(invalid("short utun packet"));
                }
                validate_header(prefix, buffer[0])?;
                Ok(length - 4)
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub(super) async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let prefix = family_header(packet[0])?;
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| {
                let vectors = [
                    libc::iovec {
                        iov_base: prefix.as_ptr().cast_mut().cast(),
                        iov_len: prefix.len(),
                    },
                    libc::iovec {
                        iov_base: packet.as_ptr().cast_mut().cast(),
                        iov_len: packet.len(),
                    },
                ];
                // SAFETY: writev only reads the two live slices; no references
                // or pointers survive this synchronous system call.
                let length = unsafe { libc::writev(fd.get_ref().as_raw_fd(), vectors.as_ptr(), 2) };
                if length < 0 {
                    Err(io::Error::last_os_error())
                } else if length as usize != packet.len() + 4 {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short utun packet write",
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

fn family_header(first: u8) -> io::Result<[u8; 4]> {
    let family = match first >> 4 {
        4 => libc::AF_INET,
        6 => libc::AF_INET6,
        _ => return Err(invalid("utun packet must be IPv4 or IPv6")),
    };
    Ok((family as u32).to_be_bytes())
}

fn validate_header(header: [u8; 4], first: u8) -> io::Result<()> {
    if header != family_header(first)? {
        return Err(invalid("utun address family does not match packet"));
    }
    Ok(())
}

fn open_utun() -> io::Result<(File, String)> {
    // SAFETY: no borrowed pointers; failure is checked before taking ownership.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(raw) };
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(raw, libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (slot, byte) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: info has the kernel ABI layout and a NUL-terminated control name.
    if unsafe { libc::ioctl(raw, libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    address.sc_len = std::mem::size_of_val(&address) as u8;
    address.sc_family = libc::AF_SYSTEM as u8;
    address.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    address.sc_id = info.ctl_id;
    // Unit zero requests a fresh kernel-assigned interface. It never opens or
    // renames an existing utun used by another VPN or system service.
    address.sc_unit = 0;
    if unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_ctl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            raw,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let name = CStr::from_bytes_until_nul(&name)
        .map_err(|_| invalid("invalid utun interface name"))?
        .to_str()
        .map_err(|_| invalid("invalid utun interface name"))?
        .to_owned();
    if !name
        .strip_prefix("utun")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid("kernel returned an unexpected utun interface name"));
    }
    Ok((file, name))
}

fn configuration(
    name: &str,
    address: IpNet,
    mtu: u16,
    routes: &[IpNet],
) -> Vec<(&'static str, Vec<String>)> {
    let mut commands = Vec::new();
    if address.addr().is_ipv4() {
        commands.push((
            "/sbin/ifconfig",
            vec![
                name.into(),
                "inet".into(),
                address.addr().to_string(),
                address.addr().to_string(),
                "netmask".into(),
                "255.255.255.255".into(),
                "alias".into(),
            ],
        ));
    } else {
        // DAD is not useful on an authenticated point-to-point link with
        // operator-assigned unique hosts. Never change a global sysctl.
        commands.push((
            "/sbin/ifconfig",
            vec![name.into(), "inet6".into(), "-dad".into()],
        ));
        commands.push((
            "/sbin/ifconfig",
            vec![
                name.into(),
                "inet6".into(),
                address.to_string(),
                "alias".into(),
            ],
        ));
    }
    commands.push((
        "/sbin/ifconfig",
        vec![name.into(), "mtu".into(), mtu.to_string(), "up".into()],
    ));
    for route in routes {
        commands.push((
            "/sbin/route",
            vec![
                "-n".into(),
                "add".into(),
                if address.addr().is_ipv4() {
                    "-inet"
                } else {
                    "-inet6"
                }
                .into(),
                "-net".into(),
                route.to_string(),
                "-interface".into(),
                name.into(),
            ],
        ));
    }
    commands
}

async fn run(
    path: &str,
    arguments: &[String],
    cancelled: &mut tokio::sync::oneshot::Receiver<()>,
) -> io::Result<()> {
    if !matches!(
        cancelled.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "macOS TUN setup cancelled",
        ));
    }
    let mut child = tokio::process::Command::new(path)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::select! {
        biased;
        _ = cancelled => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "macOS TUN setup cancelled"));
        }
        result = tokio::time::timeout(Duration::from_secs(5), child.wait()) => match result {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(io::Error::new(io::ErrorKind::TimedOut, "macOS TUN configuration timed out"));
            }
        },
    };
    if !status.success() {
        return Err(io::Error::other(format!(
            "macOS TUN configuration failed in {path} ({status}); check daemon privileges and conflicting routes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utun_header_uses_network_byte_order_and_matching_family() {
        assert_eq!(family_header(0x45).unwrap(), [0, 0, 0, 2]);
        assert_eq!(family_header(0x60).unwrap(), [0, 0, 0, 30]);
        assert!(family_header(0x10).is_err());
        assert!(validate_header([0, 0, 0, 2], 0x60).is_err());
        validate_header([0, 0, 0, 30], 0x60).unwrap();
    }

    #[test]
    fn configuration_only_adds_family_specific_routes_to_owned_interface() {
        for (local, route, family) in [
            ("192.0.2.2/32", "192.0.2.3/32", "-inet"),
            ("fd42:20::2/128", "fd42:20::3/128", "-inet6"),
        ] {
            let commands = configuration(
                "utun42",
                local.parse().unwrap(),
                1280,
                &[route.parse().unwrap()],
            );
            let (path, args) = commands.last().unwrap();
            assert_eq!(*path, "/sbin/route");
            assert_eq!(
                args,
                &["-n", "add", family, "-net", route, "-interface", "utun42"]
            );
            assert!(!commands.iter().any(|(_, args)| {
                args.iter()
                    .any(|arg| ["delete", "change", "default", "flush"].contains(&arg.as_str()))
            }));
        }
    }

    #[tokio::test]
    async fn unprivileged_creation_fails_before_creating_interface() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let error = Device::create("test0", "192.0.2.2/32".parse().unwrap(), 1280, &[])
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("--system"));
    }

    #[tokio::test]
    async fn cancellation_reaps_configuration_process() {
        let (cancel, mut cancelled) = tokio::sync::oneshot::channel::<()>();
        let task =
            tokio::spawn(
                async move { run("/bin/sleep", &["10".to_owned()], &mut cancelled).await },
            );
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(cancel);
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}
