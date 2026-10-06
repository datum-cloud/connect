//! Opt-in host networking tests. Run ONLY on a disposable elevated test host:
//! cargo test -p connect-ip-adapter --test native_tun -- --ignored --test-threads=1
//! Creates a fresh interface and one documentation/ULA host route; never changes
//! a default route, global forwarding, firewall, or any existing interface.
use connect_ip_adapter::{IpNet, PacketDevice};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::UdpSocket;

#[tokio::test]
#[ignore = "requires administrator/root and changes disposable host networking"]
async fn ipv4_native_packet_roundtrip_and_cleanup() {
    roundtrip("192.0.2.241/32", "192.0.2.242/32").await;
}

#[tokio::test]
#[ignore = "requires administrator/root and changes disposable host networking"]
async fn ipv6_native_packet_roundtrip_and_cleanup() {
    roundtrip(
        "fd4d:6174:756d:ffff::241/128",
        "fd4d:6174:756d:ffff::242/128",
    )
    .await;
}

async fn roundtrip(local: &str, remote: &str) {
    let local: IpNet = local.parse().unwrap();
    let remote: IpNet = remote.parse().unwrap();
    // Test process ID limits accidental name clashes on non-macOS platforms.
    let label = std::env::var("DATUM_CONNECT_HELPER_TEST_LABEL").unwrap_or_else(|_| {
        format!(
            "dct{}{}",
            if local.addr().is_ipv4() { 4 } else { 6 },
            std::process::id()
        )
    });
    let helper = std::env::var_os("DATUM_CONNECT_HELPER_TEST_SOCKET").map(std::path::PathBuf::from);
    let tun = PacketDevice::create(&label, local, 1280, &[remote], helper.as_deref())
        .await
        .expect("create native TUN (run elevated; Windows also requires trusted wintun.dll)");
    let name = tun.name().to_owned();
    eprintln!(
        "adapter={} interface={name} address={local}",
        connect_ip_adapter::backend()
    );
    let socket = UdpSocket::bind(SocketAddr::new(local.addr(), 0))
        .await
        .unwrap();
    let destination = SocketAddr::new(remote.addr(), 39427);
    // Cover both a small datagram and a full 1280-byte IP packet.
    for size in [24, if local.addr().is_ipv4() { 1252 } else { 1232 }] {
        let payload = vec![0x63u8; size];
        socket.send_to(&payload, destination).await.unwrap();
        let mut packet = [0u8; 65536];
        let reply = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let length = tun.read_packet(&mut packet).await?;
                if let Some(reply) = udp_reply(
                    &packet[..length],
                    local.addr(),
                    remote.addr(),
                    socket.local_addr()?.port(),
                    destination.port(),
                ) {
                    break Ok::<_, io::Error>(reply);
                }
            }
        })
        .await
        .expect("OS must route UDP into native interface")
        .unwrap();
        tun.write_packet(&reply).await.unwrap();
        let mut received = [0u8; 1500];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut received))
                .await
                .expect("OS must receive the packet injected into native interface")
                .unwrap();
        assert_eq!(source, destination);
        assert_eq!(&received[..length], payload);
    }
    drop(socket);
    drop(tun);
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::NetworkManagement::{
            IpHelper::ConvertInterfaceAliasToLuid, Ndis::NET_LUID_LH,
        };
        let alias: Vec<u16> = OsStr::new(&name).encode_wide().chain(Some(0)).collect();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
                if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } != 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("owned Wintun adapter must disappear after closing the device");
    }
    #[cfg(unix)]
    {
        let name = std::ffi::CString::new(name).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("owned interface must disappear after closing the device");
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires root; runs adapter client as an unprivileged UID on a disposable host"]
async fn helper_ipv4_packet_roundtrip() {
    helper_roundtrip(
        "192.0.2.241/32",
        "192.0.2.242/32",
        "helper_ipv4_packet_roundtrip",
    )
    .await;
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires root; runs adapter client as an unprivileged UID on a disposable host"]
async fn helper_ipv6_packet_roundtrip() {
    helper_roundtrip(
        "fd4d:6174:756d:ffff::241/128",
        "fd4d:6174:756d:ffff::242/128",
        "helper_ipv6_packet_roundtrip",
    )
    .await;
}

#[cfg(unix)]
async fn helper_roundtrip(local: &str, remote: &str, test_name: &str) {
    use connect_ip_adapter::helper::{Approval, Config};
    use std::os::unix::fs::PermissionsExt;
    if std::env::var_os("DATUM_CONNECT_HELPER_TEST_SOCKET").is_some() {
        assert_ne!(unsafe { libc::geteuid() }, 0, "client must not run as root");
        let socket =
            std::path::PathBuf::from(std::env::var_os("DATUM_CONNECT_HELPER_TEST_SOCKET").unwrap());
        let label = std::env::var("DATUM_CONNECT_HELPER_TEST_LABEL").unwrap();
        let status = connect_ip_adapter::helper::inspect(&socket).await.unwrap();
        assert_eq!(status.version, 1);
        assert_eq!(
            status.approvals[0].mtu, 1280,
            "new requests must load the updated root approval file"
        );
        let assigned: IpNet = local.parse().unwrap();
        let peer: IpNet = remote.parse().unwrap();
        assert!(
            PacketDevice::create(&label, assigned, 1400, &[peer], Some(&socket))
                .await
                .is_err(),
            "unapproved MTU must be rejected"
        );
        roundtrip(local, remote).await;
        let device = PacketDevice::create(&label, assigned, 1280, &[peer], Some(&socket))
            .await
            .unwrap();
        assert!(
            PacketDevice::create(&label, assigned, 1280, &[peer], Some(&socket))
                .await
                .is_err(),
            "duplicate interface request must be rejected"
        );
        let name = std::ffi::CString::new(device.name()).unwrap();
        // Bypassing the daemon cannot authorize packet injection outside the host pair.
        device.write_packet(&[0x45u8; 20]).await.unwrap();
        let mut buffer = vec![0; 1280];
        assert!(
            tokio::time::timeout(Duration::from_secs(5), device.read_packet(&mut buffer))
                .await
                .unwrap()
                .is_err()
        );
        drop(device);
        tokio::time::timeout(Duration::from_secs(5), async {
            while unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        return;
    }
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run this opt-in test as root"
    );
    let parent = if cfg!(target_os = "macos") {
        "/Library/PrivilegedHelperTools"
    } else {
        "/run"
    };
    std::fs::create_dir_all(parent).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("datum-helper-test-")
        .tempdir_in(parent)
        .unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    let socket = dir.path().join("helper.sock");
    let label = format!(
        "dch{}{}",
        if local.contains(':') { 6 } else { 4 },
        std::process::id()
    );
    let uid = if cfg!(target_os = "macos") { 501 } else { 1000 };
    let config = Config {
        allowed_uid: uid,
        approvals: vec![Approval {
            interface_name: label.clone(),
            assigned_address: local.parse().unwrap(),
            peer_address: remote.parse().unwrap(),
            mtu: 1280,
            routes: vec![],
            advertise_routes: vec![],
        }],
        managed_policy: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let config_path = dir.path().join("approvals.json");
    let mut initial = config.clone();
    initial.approvals[0].mtu = 1400;
    std::fs::write(&config_path, serde_json::to_vec(&initial).unwrap()).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let server_socket = socket.clone();
    let server_config = config_path.clone();
    let server = tokio::spawn(async move {
        connect_ip_adapter::helper::serve_reloadable(
            initial,
            &server_socket,
            Some(&server_config),
            async {
                let _ = stopped.await;
            },
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            assert!(!server.is_finished(), "helper failed before binding");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    // Root bypasses socket filesystem permissions, but is not the approved
    // client UID. The helper must still reject it at the IPC boundary.
    assert!(
        PacketDevice::create(
            &label,
            local.parse().unwrap(),
            1280,
            &[remote.parse().unwrap()],
            Some(&socket)
        )
        .await
        .is_err()
    );
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", test_name, "--nocapture"])
            .env("DATUM_CONNECT_HELPER_TEST_SOCKET", &socket)
            .env("DATUM_CONNECT_HELPER_TEST_LABEL", label)
            .uid(uid)
            .gid(uid)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let _ = stop.send(());
    server.await.unwrap().unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !socket.exists(),
        "helper socket must be removed on shutdown"
    );
}

fn udp_reply(
    packet: &[u8],
    local: IpAddr,
    remote: IpAddr,
    source_port: u16,
    destination_port: u16,
) -> Option<Vec<u8>> {
    let mut reply = packet.to_vec();
    let (offset, mut pseudo) = match (local, remote) {
        (IpAddr::V4(local), IpAddr::V4(remote))
            if packet.len() >= 28 && packet[0] == 0x45 && packet[9] == 17 =>
        {
            if packet[12..16] != local.octets() || packet[16..20] != remote.octets() {
                return None;
            }
            reply[12..16].copy_from_slice(&remote.octets());
            reply[16..20].copy_from_slice(&local.octets());
            let mut pseudo = reply[12..20].to_vec();
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
            reply[10..12].fill(0);
            let checksum = checksum(&reply[..20]);
            reply[10..12].copy_from_slice(&checksum.to_be_bytes());
            (20, pseudo)
        }
        (IpAddr::V6(local), IpAddr::V6(remote))
            if packet.len() >= 48 && packet[0] >> 4 == 6 && packet[6] == 17 =>
        {
            if packet[8..24] != local.octets() || packet[24..40] != remote.octets() {
                return None;
            }
            reply[8..24].copy_from_slice(&remote.octets());
            reply[24..40].copy_from_slice(&local.octets());
            let mut pseudo = reply[8..40].to_vec();
            pseudo.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
            (40, pseudo)
        }
        _ => return None,
    };
    if packet[offset..offset + 2] != source_port.to_be_bytes()
        || packet[offset + 2..offset + 4] != destination_port.to_be_bytes()
    {
        return None;
    }
    reply[offset..offset + 2].copy_from_slice(&destination_port.to_be_bytes());
    reply[offset + 2..offset + 4].copy_from_slice(&source_port.to_be_bytes());
    reply[offset + 6..offset + 8].fill(0);
    pseudo.extend_from_slice(&reply[offset..]);
    let sum = checksum(&pseudo);
    reply[offset + 6..offset + 8]
        .copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    Some(reply)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn internet_checksum_known_vector() {
    assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
}
