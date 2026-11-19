use crate::model::{StabilityStats, VlessNode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
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

fn probe_resolved_addrs(
    addrs_vec: &[SocketAddr],
    port: u16,
    phys_if: Option<u32>,
    timeout_ms: i32,
) -> u32 {
    if let Some(if_idx) = phys_if {
        for sa in addrs_vec {
            if let IpAddr::V4(v4) = sa.ip() {
                if let Some(ms) = tcp_ping_direct_ipv4(v4, port, if_idx, timeout_ms) {
                    return ms;
                }
            }
        }
    }

    let timeout = Duration::from_millis(timeout_ms.max(100) as u64);
    for sa in addrs_vec {
        let start = Instant::now();
        if TcpStream::connect_timeout(sa, timeout).is_ok() {
            return (start.elapsed().as_millis() as u32).max(1);
        }
    }
    0
}

pub fn tcp_ping_node(address: &str, port: u16, phys_if: Option<u32>) -> u32 {
    let target = format!("{}:{}", address, port);
    let Ok(addrs) = target.to_socket_addrs() else {
        return 0;
    };
    let addrs_vec: Vec<SocketAddr> = addrs.collect();
    probe_resolved_addrs(&addrs_vec, port, phys_if, 2000)
}

pub fn compute_stability_stats(samples: &[u32], probes_total: u8) -> StabilityStats {
    let done = samples.len().min(u8::MAX as usize) as u8;
    let ok: Vec<u32> = samples.iter().copied().filter(|&ms| ms > 0).collect();
    if done == 0 || ok.is_empty() {
        return StabilityStats {
            probes_done: done,
            probes_total,
            avg_ms: 0,
            jitter_ms: 0,
            loss_pct: if done == 0 { 0 } else { 100 },
        };
    }

    let failed = (done as usize).saturating_sub(ok.len());
    let loss_pct = ((failed * 100 + (done as usize) / 2) / (done as usize)).min(100) as u8;
    let sum: u64 = ok.iter().map(|&v| v as u64).sum();
    let avg_ms = ((sum + (ok.len() as u64) / 2) / (ok.len() as u64)) as u32;

    let jitter_ms = if ok.len() >= 2 {
        let diff_sum: u64 = ok
            .windows(2)
            .map(|w| w[0].abs_diff(w[1]) as u64)
            .sum();
        let cnt = (ok.len() - 1) as u64;
        ((diff_sum + cnt / 2) / cnt) as u32
    } else {
        0
    };

    StabilityStats {
        probes_done: done,
        probes_total,
        avg_ms,
        jitter_ms,
        loss_pct,
    }
}

pub fn stability_test_all_async(
    nodes: Vec<(usize, String, u16)>,
    probes: u8,
    interval_ms: u64,
    cancel: Arc<AtomicBool>,
    on_progress: impl Fn(usize, StabilityStats) + Send + Sync + 'static,
    on_done: impl Fn() + Send + 'static,
) {
    let cb = Arc::new(on_progress);
    let total = probes.max(1);
    std::thread::spawn(move || {
        let phys_if = find_physical_ipv4_if_index();
        for chunk in nodes.chunks(8) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let mut handles = Vec::new();
            for &(idx, ref addr, port) in chunk {
                let a = addr.clone();
                let c = cb.clone();
                let cancel_t = cancel.clone();
                handles.push(std::thread::spawn(move || {
                    let target = format!("{}:{}", a, port);
                    let addrs_vec: Vec<SocketAddr> = target
                        .to_socket_addrs()
                        .map(|it| it.collect())
                        .unwrap_or_default();

                    let mut samples: Vec<u32> = Vec::with_capacity(total as usize);
                    for p in 0..total {
                        if cancel_t.load(Ordering::Relaxed) {
                            break;
                        }
                        let t0 = Instant::now();
                        let ms = if addrs_vec.is_empty() {
                            0
                        } else {
                            probe_resolved_addrs(&addrs_vec, port, phys_if, 1500)
                        };
                        samples.push(ms);
                        let stats = compute_stability_stats(&samples, total);
                        c(idx, stats);

                        if p + 1 < total {
                            let elapsed = t0.elapsed().as_millis() as u64;
                            let mut rem = interval_ms.saturating_sub(elapsed);
                            while rem > 0 && !cancel_t.load(Ordering::Relaxed) {
                                let step = rem.min(50);
                                std::thread::sleep(Duration::from_millis(step));
                                rem -= step;
                            }
                        }
                    }
                }));
            }
            for h in handles {
                let _ = h.join();
            }
        }
        on_done();
    });
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

    #[test]
    fn compute_stability_stats_metrics_and_quality() {
        let good = compute_stability_stats(&[30, 32, 31, 33, 30, 32, 31, 30, 32, 31], 10);
        assert_eq!(good.avg_ms, 31);
        assert_eq!(good.jitter_ms, 2);
        assert_eq!(good.loss_pct, 0);
        assert_eq!(good.quality_label(), "Good");

        let fair = compute_stability_stats(&[95, 110, 100, 115, 98], 5);
        assert_eq!(fair.loss_pct, 0);
        assert_eq!(fair.quality_label(), "Fair");

        let lossy = compute_stability_stats(&[30, 0, 32, 31, 30], 5);
        assert_eq!(lossy.loss_pct, 20);
        assert_eq!(lossy.quality_label(), "Poor");

        let dead = compute_stability_stats(&[0, 0, 0], 3);
        assert_eq!(dead.loss_pct, 100);
        assert_eq!(dead.quality_label(), "Dead");
    }
}
