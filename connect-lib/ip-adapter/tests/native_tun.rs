//! Opt-in host networking tests. Run ONLY on a disposable elevated test host:
//! cargo test -p connect-ip-adapter --test native_tun -- --ignored --test-threads=1
//! Creates a fresh interface and one documentation/ULA host route; never changes
//! a default route, global forwarding, firewall, or any existing interface.
use connect_ip_adapter::{IpNet, Tun};
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
    let label = format!(
        "dct{}{}",
        if local.addr().is_ipv4() { 4 } else { 6 },
        std::process::id()
    );
    let tun = Tun::create(&label, local, 1280, &[remote])
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
