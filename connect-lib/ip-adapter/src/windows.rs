use super::{IpNet, invalid};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    net::IpAddr,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, GetLastError,
        INVALID_HANDLE_VALUE, NO_ERROR,
    },
    NetworkManagement::{
        IpHelper::{
            CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
            DeleteUnicastIpAddressEntry, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
            IP_ADDRESS_PREFIX, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
            InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
            MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStatePreferred,
        IpPrefixOriginManual, IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_INET,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    },
};

const RING_CAPACITY: u32 = 4 * 1024 * 1024;
const RETRY_DELAY: Duration = Duration::from_millis(1);

/// A Wintun adapter created and owned exclusively by this process.
pub(super) struct Device {
    name: String,
    session: Arc<wintun::Session>,
    address: MIB_UNICASTIPADDRESS_ROW,
    routes: Vec<MIB_IPFORWARD_ROW2>,
    // Keep the adapter (and therefore its automatically removed device) alive
    // until after the session and IP Helper rows have been torn down.
    _adapter: Arc<wintun::Adapter>,
}

impl Device {
    pub(super) async fn create(
        name: &str,
        address: IpNet,
        mtu: u16,
        routes: &[IpNet],
    ) -> io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_on_drop = CancelOnDrop(cancelled.clone());
        let name = name.to_owned();
        let routes = routes.to_vec();
        let worker_cancelled = cancelled.clone();
        let result = tokio::task::spawn_blocking(move || {
            create_blocking(name, address, mtu, routes, &worker_cancelled)
        })
        .await
        .map_err(|error| io::Error::other(format!("Windows TUN setup worker failed: {error}")))?;
        drop(cancel_on_drop);
        result
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.session.try_receive().map_err(wintun_error)? {
                Some(packet) => {
                    if packet.bytes().len() > buffer.len() {
                        return Err(invalid("packet receive buffer is too small"));
                    }
                    let length = packet.bytes().len();
                    buffer[..length].copy_from_slice(packet.bytes());
                    return Ok(length);
                }
                None => tokio::time::sleep(RETRY_DELAY).await,
            }
        }
    }

    pub(super) async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let length = u16::try_from(packet.len())
            .map_err(|_| invalid("Wintun packets cannot exceed 65535 bytes"))?;
        loop {
            match self.session.allocate_send_packet(length) {
                Ok(mut outgoing) => {
                    outgoing.bytes_mut().copy_from_slice(packet);
                    self.session.send_packet(outgoing);
                    return Ok(());
                }
                Err(wintun::Error::Io(error))
                    if error.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) =>
                {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(error) => return Err(wintun_error(error)),
            }
        }
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn create_blocking(
    name: String,
    address: IpNet,
    mtu: u16,
    routes: Vec<IpNet>,
    cancelled: &AtomicBool,
) -> io::Result<Device> {
    check_cancelled(cancelled)?;
    let (dll_path, _dll_lock) = trusted_dll_path()?;
    // SAFETY: canonical_path_beside_executable only accepts a non-symlinked,
    // absolute DLL in the executable's canonical directory. Distribution
    // packaging is responsible for installing the official signed Wintun DLL.
    let wintun = unsafe { wintun::load_from_path(&dll_path) }.map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to load trusted Wintun DLL at {}: {error}",
                dll_path.display()
            ),
        )
    })?;
    check_cancelled(cancelled)?;
    ensure_routes_absent(&routes)?;
    check_cancelled(cancelled)?;

    // Never adopt an adapter left by another process or an earlier run.
    if let Ok(existing) = wintun::Adapter::open(&wintun, &name) {
        drop(existing);
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("Wintun adapter {name:?} already exists; refusing to adopt it"),
        ));
    }

    check_cancelled(cancelled)?;
    let adapter = wintun::Adapter::create(&wintun, &name, "Datum Connect", None)
        .map_err(|error| adapter_create_error(&name, error))?;
    let luid = adapter.get_luid();
    let mut configured = ConfiguredRows::new(adapter.clone());
    check_cancelled(cancelled)?;
    set_mtu(luid, address.addr(), mtu)?;
    check_cancelled(cancelled)?;
    configured.address = Some(add_address(luid, address)?);
    for route in routes {
        check_cancelled(cancelled)?;
        configured.routes.push(add_route(luid, route)?);
    }
    check_cancelled(cancelled)?;
    let session = Arc::new(adapter.start_session(RING_CAPACITY).map_err(wintun_error)?);
    let (address, routes, adapter) = configured.commit();

    let device = Device {
        name,
        session,
        address,
        routes,
        _adapter: adapter,
    };
    check_cancelled(cancelled)?;
    Ok(device)
}

fn check_cancelled(cancelled: &AtomicBool) -> io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Windows TUN setup was cancelled",
        ))
    } else {
        Ok(())
    }
}

fn ensure_routes_absent(routes: &[IpNet]) -> io::Result<()> {
    for route in routes {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        win32_result(
            unsafe { GetIpForwardTable2(family(route.addr()), &mut table) },
            "inspect existing Windows routes",
        )?;
        let count = unsafe { (*table).NumEntries as usize };
        let first = unsafe { std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>() };
        let found = (0..count).any(|index| {
            let row = unsafe { &*first.add(index) };
            row.DestinationPrefix.PrefixLength == route.prefix_len()
                && sockaddr_ip(row.DestinationPrefix.Prefix) == Some(route.network())
        });
        unsafe { FreeMibTable(table.cast()) };
        if found {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "route {route} already exists; refusing to create an ambiguous or adopted route"
                ),
            ));
        }
    }
    Ok(())
}

fn sockaddr_ip(address: SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { address.si_family } {
        AF_INET => Some(IpAddr::V4(std::net::Ipv4Addr::from(unsafe {
            address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()
        }))),
        AF_INET6 => Some(IpAddr::V6(std::net::Ipv6Addr::from(unsafe {
            address.Ipv6.sin6_addr.u.Byte
        }))),
        _ => None,
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.session.shutdown();
        for route in self.routes.iter().rev() {
            // SAFETY: rows were initialized by InitializeIpForwardEntry and
            // successfully installed by CreateIpForwardEntry2.
            unsafe { DeleteIpForwardEntry2(route) };
        }
        // SAFETY: the row was initialized and successfully installed above.
        unsafe { DeleteUnicastIpAddressEntry(&self.address) };
    }
}

struct ConfiguredRows {
    adapter: Arc<wintun::Adapter>,
    address: Option<MIB_UNICASTIPADDRESS_ROW>,
    routes: Vec<MIB_IPFORWARD_ROW2>,
    committed: bool,
}

impl ConfiguredRows {
    fn new(adapter: Arc<wintun::Adapter>) -> Self {
        Self {
            adapter,
            address: None,
            routes: Vec::new(),
            committed: false,
        }
    }

    fn commit(
        mut self,
    ) -> (
        MIB_UNICASTIPADDRESS_ROW,
        Vec<MIB_IPFORWARD_ROW2>,
        Arc<wintun::Adapter>,
    ) {
        self.committed = true;
        (
            self.address.take().expect("configured address"),
            std::mem::take(&mut self.routes),
            self.adapter.clone(),
        )
    }
}

impl Drop for ConfiguredRows {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for route in self.routes.iter().rev() {
            unsafe { DeleteIpForwardEntry2(route) };
        }
        if let Some(address) = &self.address {
            unsafe { DeleteUnicastIpAddressEntry(address) };
        }
    }
}

fn trusted_dll_path() -> io::Result<(PathBuf, File)> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let directory = executable
        .parent()
        .ok_or_else(|| io::Error::other("executable has no parent directory"))?;
    let path = canonical_path_beside_executable(directory, &directory.join("wintun.dll"))?;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_mut_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut lock = unsafe { File::from_raw_handle(handle as _) };
    verify_dll_hash(&mut lock)?;
    Ok((path, lock))
}

fn canonical_path_beside_executable(directory: &Path, candidate: &Path) -> io::Result<PathBuf> {
    let canonical_directory = directory.canonicalize()?;
    let canonical_candidate = candidate.canonicalize().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "wintun.dll is required beside the executable at {}; install the official architecture-matched DLL from wintun.net",
                    candidate.display()
                ),
            )
        } else {
            error
        }
    })?;
    if canonical_candidate.parent() != Some(canonical_directory.as_path())
        || canonical_candidate
            .file_name()
            .and_then(|name| name.to_str())
            != Some("wintun.dll")
        || !canonical_candidate.is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wintun.dll must be a regular, non-symlinked file beside the executable",
        ));
    }
    Ok(canonical_candidate)
}

fn verify_dll_hash(file: &mut File) -> io::Result<()> {
    let expected = expected_dll_hash().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "this Windows architecture has no pinned Wintun DLL",
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if &digest.finalize()[..] != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wintun.dll does not match the pinned official Wintun 0.14.1 binary for this architecture",
        ));
    }
    Ok(())
}

fn expected_dll_hash() -> Option<&'static [u8; 32]> {
    #[cfg(target_arch = "x86_64")]
    return Some(&[
        0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85,
        0xc1, 0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d,
        0xaf, 0xce,
    ]);
    #[cfg(target_arch = "x86")]
    return Some(&[
        0xd6, 0x94, 0xfa, 0x46, 0xab, 0x4c, 0xfe, 0xbc, 0xb2, 0x63, 0x2d, 0x09, 0x4c, 0x7a, 0xa9,
        0x72, 0x78, 0xee, 0xf2, 0xf8, 0x05, 0x24, 0x38, 0x62, 0x17, 0x66, 0xd8, 0x63, 0xae, 0x98,
        0xa9, 0x31,
    ]);
    #[cfg(target_arch = "aarch64")]
    return Some(&[
        0xf7, 0xba, 0x89, 0x00, 0x55, 0x44, 0xbe, 0x9d, 0x85, 0x23, 0x1a, 0x9e, 0x0d, 0x5f, 0x23,
        0xb2, 0xd1, 0x5b, 0x33, 0x11, 0x66, 0x7e, 0x2d, 0xad, 0x0d, 0xeb, 0xd3, 0x44, 0x91, 0x8a,
        0x3f, 0x80,
    ]);
    #[allow(unreachable_code)]
    None
}

fn set_mtu(luid: NET_LUID_LH, address: IpAddr, mtu: u16) -> io::Result<()> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family(address);
    row.InterfaceLuid = luid;
    win32_result(
        unsafe { GetIpInterfaceEntry(&mut row) },
        "read Wintun IP interface configuration",
    )?;
    row.NlMtu = u32::from(mtu);
    row.DadTransmits = 0;
    win32_result(unsafe { SetIpInterfaceEntry(&mut row) }, "set Wintun MTU")
}

fn add_address(luid: NET_LUID_LH, address: IpNet) -> io::Result<MIB_UNICASTIPADDRESS_ROW> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.Address = sockaddr(address.addr());
    row.OnLinkPrefixLength = address.prefix_len();
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.DadState = IpDadStatePreferred;
    win32_result(
        unsafe { CreateUnicastIpAddressEntry(&row) },
        "assign Wintun address",
    )?;
    Ok(row)
}

fn add_route(luid: NET_LUID_LH, route: IpNet) -> io::Result<MIB_IPFORWARD_ROW2> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(route.network()),
        PrefixLength: route.prefix_len(),
    };
    row.NextHop = unspecified_sockaddr(route.addr());
    row.Protocol = MIB_IPPROTO_NETMGMT;
    win32_result(unsafe { CreateIpForwardEntry2(&row) }, "add Wintun route")?;
    Ok(row)
}

fn family(address: IpAddr) -> u16 {
    if address.is_ipv4() { AF_INET } else { AF_INET6 }
}

fn unspecified_sockaddr(like: IpAddr) -> SOCKADDR_INET {
    match like {
        IpAddr::V4(_) => sockaddr(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        IpAddr::V6(_) => sockaddr(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
    }
}

fn sockaddr(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

fn win32_result(code: u32, operation: &str) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else if code == ERROR_ACCESS_DENIED {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{operation} requires running Datum Connect as Administrator"),
        ))
    } else {
        Err(io::Error::new(
            io::Error::from_raw_os_error(code as i32).kind(),
            format!("{operation}: {}", io::Error::from_raw_os_error(code as i32)),
        ))
    }
}

fn adapter_create_error(name: &str, error: wintun::Error) -> io::Error {
    // The crate's create wrapper currently discards GetLastError; retrieve it
    // immediately so create/open races remain distinguishable from elevation.
    let code = unsafe { GetLastError() };
    let source = wintun_error(error);
    if code == ERROR_ALREADY_EXISTS {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("Wintun adapter {name:?} was created concurrently; refusing to adopt it"),
        )
    } else if code == ERROR_ACCESS_DENIED {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "creating Wintun adapter {name:?} requires running Datum Connect as Administrator ({source})"
            ),
        )
    } else {
        source
    }
}

fn wintun_error(error: wintun::Error) -> io::Error {
    error.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_preserves_ipv4_network_bytes() {
        let address = std::net::Ipv4Addr::new(10, 23, 45, 67);
        let converted = sockaddr(address.into());
        let bytes = unsafe { converted.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() };
        assert_eq!(bytes, address.octets());
    }

    #[test]
    fn sockaddr_preserves_ipv6_bytes() {
        let address: std::net::Ipv6Addr = "fd00:1234::abcd".parse().unwrap();
        let converted = sockaddr(address.into());
        let bytes = unsafe { converted.Ipv6.sin6_addr.u.Byte };
        assert_eq!(bytes, address.octets());
    }
}
