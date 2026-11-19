use crate::model::VlessNode;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::ptr::null_mut;
use std::sync::Once;
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, getsockopt, ioctlsocket, select, setsockopt, socket, WSAGetLastError,
    WSAStartup, AF_INET, FD_SET, FIONBIO, INVALID_SOCKET, IPPROTO_IP, IPPROTO_TCP, IP_UNICAST_IF,
    SOCKADDR, SOCKADDR_IN, SOCK_STREAM, SOL_SOCKET, SO_ERROR, TIMEVAL, WSADATA, WSAEWOULDBLOCK,
};

static WSA_INIT: Once = Once::new();

fn ensure_wsa() {
    WSA_INIT.call_once(|| unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut wsa);
    });
}

// Find the IPv4 interface index of the active physical adapter so TCP ping bypasses TUN.
fn find_physical_ipv4_if_index() -> Option<u32> {
    unsafe {
        let mut buf_len: u32 = 32 * 1024;
        // u64 backing guarantees 8-byte alignment required by IP_ADAPTER_ADDRESSES_LH
        let mut buf = vec![0u64; ((buf_len as usize) + 7) / 8];
        let flags = GAA_FLAG_INCLUDE_GATEWAYS;
        let mut rc = GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        );
        // ERROR_BUFFER_OVERFLOW (111): resize to OS-requested length and retry once
        if rc == 111 && buf_len > 0 && buf_len <= 1024 * 1024 {
            buf.resize(((buf_len as usize) + 7) / 8, 0);
            rc = GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            );
        }
        if rc != 0 {
            return None;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            // OperStatus == 1 (IfOperStatusUp), IfType != 24 (loopback), has IPv4 gateway
            let if_idx = a.Anonymous1.Anonymous.IfIndex;
            let is_up = a.OperStatus == 1;
            let is_loopback = a.IfType == 24;
            let has_gw = !a.FirstGatewayAddress.is_null();

            if is_up && !is_loopback && has_gw && if_idx > 0 {
                let desc = wide_ptr_to_string(a.Description).to_lowercase();
                let name = wide_ptr_to_string(a.FriendlyName).to_lowercase();
                let combined = format!("{} {}", desc, name);
                let is_virtual = combined.contains("wintun")
                    || combined.contains("avel")
                    || combined.contains("tunnel")
                    || combined.contains("vmware")
                    || combined.contains("hyper-v")
                    || combined.contains("virtual")
                    || combined.contains("wireguard")
                    || combined.contains("tap-windows");
                if !is_virtual {
                    return Some(if_idx);
                }
            }
            cur = a.Next;
        }
    }
    None
}

unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 512 && *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

// Measure TCP connect RTT bound directly to the physical interface via IP_UNICAST_IF.
fn tcp_ping_direct_ipv4(ip: Ipv4Addr, port: u16, if_idx: u32, timeout_ms: i32) -> Option<u32> {
    ensure_wsa();
    unsafe {
        let sock = socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP);
        if sock == INVALID_SOCKET {
            return None;
        }

        // IP_UNICAST_IF expects the interface index in network byte order (big-endian)
        let net_idx = if_idx.to_be();
        setsockopt(
            sock,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &net_idx as *const u32 as *const u8,
            4,
        );

        // Switch socket to non-blocking for accurate connect timeout
        let mut non_blocking: u32 = 1;
        ioctlsocket(sock, FIONBIO, &mut non_blocking);

        let mut addr: SOCKADDR_IN = std::mem::zeroed();
        addr.sin_family = AF_INET;
        addr.sin_port = port.to_be();
        addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());

        let start = Instant::now();
        let rc = connect(
            sock,
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        );

        let ok = if rc == 0 {
            true
        } else if WSAGetLastError() != WSAEWOULDBLOCK {
            false
        } else {
            let mut wfds: FD_SET = std::mem::zeroed();
            wfds.fd_count = 1;
            wfds.fd_array[0] = sock;
            let mut efds: FD_SET = std::mem::zeroed();
            efds.fd_count = 1;
            efds.fd_array[0] = sock;
            let tv = TIMEVAL {
                tv_sec: timeout_ms / 1000,
                tv_usec: (timeout_ms % 1000) * 1000,
            };
            let sel = select(0, null_mut(), &mut wfds, &mut efds, &tv);
            if sel > 0 && wfds.fd_count > 0 {
                let mut so_err: i32 = 0;
                let mut err_len: i32 = 4;
                getsockopt(
                    sock,
                    SOL_SOCKET,
                    SO_ERROR,
                    &mut so_err as *mut i32 as *mut u8,
                    &mut err_len,
                );
                so_err == 0
            } else {
                false
            }
        };

        let elapsed = start.elapsed().as_millis() as u32;
        closesocket(sock);
        if ok {
            Some(elapsed.max(1))
        } else {
            None
        }
    }
}

pub fn tcp_ping_node(address: &str, port: u16, phys_if: Option<u32>) -> u32 {
    let target = format!("{}:{}", address, port);
    let Ok(addrs) = target.to_socket_addrs() else {
        return 0;
    };
    let addrs_vec: Vec<SocketAddr> = addrs.collect();

    // Prefer direct physical-interface IPv4 TCP ping so active TUN never fakes 1 ms
    if let Some(if_idx) = phys_if {
        for sa in &addrs_vec {
            if let IpAddr::V4(v4) = sa.ip() {
                if let Some(ms) = tcp_ping_direct_ipv4(v4, port, if_idx, 2000) {
                    return ms;
                }
            }
        }
    }

    // Fallback (e.g., IPv6-only or no physical gateway detected)
    let timeout = Duration::from_millis(2000);
    for sa in addrs_vec {
        let start = Instant::now();
        if TcpStream::connect_timeout(&sa, timeout).is_ok() {
            return (start.elapsed().as_millis() as u32).max(1);
        }
    }
    0
}

pub fn ping_all_async(
    nodes: Vec<(usize, String, u16)>,
    on_result: impl Fn(usize, u32) + Send + Sync + 'static,
    on_done: impl Fn() + Send + 'static,
) {
    let cb = std::sync::Arc::new(on_result);
    std::thread::spawn(move || {
        let phys_if = find_physical_ipv4_if_index();
        for chunk in nodes.chunks(8) {
            let mut handles = Vec::new();
            for &(idx, ref addr, port) in chunk {
                let a = addr.clone();
                let c = cb.clone();
                handles.push(std::thread::spawn(move || {
                    let ms = tcp_ping_node(&a, port, phys_if);
                    c(idx, ms);
                }));
            }
            for h in handles {
                let _ = h.join();
            }
        }
        on_done();
    });
}

pub fn extract_ping_targets(nodes: &[VlessNode]) -> Vec<(usize, String, u16)> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (i, n.address.clone(), n.port))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_physical_interface_and_measures_real_tcp_rtt() {
        let phys = find_physical_ipv4_if_index();
        assert!(phys.is_some(), "Expected an active physical IPv4 interface");
        let ms = tcp_ping_node("1.1.1.1", 443, phys);
        assert!(ms >= 5 && ms < 2000, "Expected real physical TCP RTT (5..2000 ms), got {} ms", ms);
    }
}
