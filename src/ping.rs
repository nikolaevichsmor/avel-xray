use crate::http_win::probe_http_proxy_real_delay;
use crate::model::VlessNode;
use crate::sys_proxy::find_adapter_luid;
use crate::xray_config::{build_batch_test_config, OutboundOpts};
use crate::xray_proc::TempXrayProcess;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, Once};
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

// Find the best physical IPv4 interface (preferring Ethernet=6 / Wi-Fi=71 by lowest metric)
// so probes bypass active TUN/VPN adapters instead of getting fake 1ms local gVisor SYN-ACKs.
fn find_physical_ipv4_if_info() -> Option<(u32, String)> {
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
        const VIRTUAL_KEYWORDS: &[&str] = &[
            "wintun",
            "avel",
            "tunnel",
            "vmware",
            "hyper-v",
            "vethernet",
            "virtual",
            "wireguard",
            "tap-windows",
            "tailscale",
            "zerotier",
            "radmin",
            "hamachi",
            "openvpn",
            "sing-box",
            "clash",
            "mihomo",
            "happ",
            "nekobox",
            "wsl",
            "docker",
            "bluetooth",
            "nordlynx",
            "proton",
            "mullvad",
        ];

        let mut best: Option<((u8, u32), u32, String)> = None;
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            let if_idx = a.Anonymous1.Anonymous.IfIndex;
            let is_up = a.OperStatus == 1;
            let is_loopback = a.IfType == 24;
            let has_gw = !a.FirstGatewayAddress.is_null();

            if is_up && !is_loopback && has_gw && if_idx > 0 {
                let raw_name = wide_ptr_to_string(a.FriendlyName);
                let desc = wide_ptr_to_string(a.Description).to_lowercase();
                let name_lc = raw_name.to_lowercase();
                let combined = format!("{} {}", desc, name_lc);
                let is_virtual = VIRTUAL_KEYWORDS.iter().any(|kw| combined.contains(kw));
                if !is_virtual {
                    // Prefer Ethernet (6) or Wi-Fi (71), then lowest IPv4 metric
                    let hw_rank = if a.IfType == 6 || a.IfType == 71 { 0 } else { 1 };
                    let score = (hw_rank, a.Ipv4Metric);
                    if best.as_ref().map(|(s, _, _)| score < *s).unwrap_or(true) {
                        best = Some((score, if_idx, raw_name));
                    }
                }
            }
            cur = a.Next;
        }
        best.map(|(_, idx, name)| (idx, name))
    }
}

fn find_physical_ipv4_if_index() -> Option<u32> {
    find_physical_ipv4_if_info().map(|(idx, _)| idx)
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

// Measure TCP connect RTT bound directly to the physical interface via IP_UNICAST_IF,
// polling `cancel` in 100ms slices so Stop responds almost immediately.
fn tcp_ping_direct_ipv4(
    ip: Ipv4Addr,
    port: u16,
    if_idx: u32,
    timeout_ms: i32,
    cancel: &AtomicBool,
) -> Option<u32> {
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
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
            let deadline = Duration::from_millis(timeout_ms.max(100) as u64);
            let mut connected = false;
            loop {
                if cancel.load(Ordering::Relaxed) || start.elapsed() >= deadline {
                    break;
                }
                let rem_ms = deadline
                    .saturating_sub(start.elapsed())
                    .as_millis()
                    .clamp(1, 100) as i32;
                let mut wfds: FD_SET = std::mem::zeroed();
                wfds.fd_count = 1;
                wfds.fd_array[0] = sock;
                let mut efds: FD_SET = std::mem::zeroed();
                efds.fd_count = 1;
                efds.fd_array[0] = sock;
                let tv = TIMEVAL {
                    tv_sec: rem_ms / 1000,
                    tv_usec: (rem_ms % 1000) * 1000,
                };
                let sel = select(0, null_mut(), &mut wfds, &mut efds, &tv);
                if sel > 0 {
                    if wfds.fd_count > 0 {
                        let mut so_err: i32 = 0;
                        let mut err_len: i32 = 4;
                        getsockopt(
                            sock,
                            SOL_SOCKET,
                            SO_ERROR,
                            &mut so_err as *mut i32 as *mut u8,
                            &mut err_len,
                        );
                        connected = so_err == 0;
                    }
                    break;
                } else if sel < 0 {
                    break;
                }
            }
            connected
        };

        let elapsed = start.elapsed().as_millis() as u32;
        closesocket(sock);
        if ok && !cancel.load(Ordering::Relaxed) {
            Some(elapsed.max(1))
        } else {
            None
        }
    }
}

// Resolve DNS with an explicit timeout and cancel support so dead hostnames never stall TCP Ping.
fn resolve_addrs_with_timeout(
    address: &str,
    port: u16,
    timeout_ms: u64,
    cancel: &AtomicBool,
) -> Vec<SocketAddr> {
    if cancel.load(Ordering::Relaxed) {
        return Vec::new();
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    let target = format!("{}:{}", address, port);
    let (tx, rx) = mpsc::channel::<Vec<SocketAddr>>();
    std::thread::spawn(move || {
        if let Ok(iter) = target.to_socket_addrs() {
            let _ = tx.send(iter.take(4).collect());
        } else {
            let _ = tx.send(Vec::new());
        }
    });
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Vec::new();
        }
        match rx.recv_timeout(rem.min(Duration::from_millis(50))) {
            Ok(addrs) => return addrs,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Vec::new(),
        }
    }
}

fn probe_resolved_addrs(
    addrs_vec: &[SocketAddr],
    port: u16,
    phys_if: Option<u32>,
    tun_active: bool,
    timeout_ms: i32,
    cancel: &AtomicBool,
) -> u32 {
    if cancel.load(Ordering::Relaxed) || addrs_vec.is_empty() {
        return 0;
    }
    // When a physical interface is bound, NEVER fall back to unbound TcpStream::connect_timeout:
    // unbound connect either enters Wintun TUN (faking 1ms SYN-ACK) or wastes another 2s per IP.
    if let Some(if_idx) = phys_if {
        let mut tried_v4 = 0usize;
        for sa in addrs_vec {
            if cancel.load(Ordering::Relaxed) || tried_v4 >= 2 {
                break;
            }
            if let IpAddr::V4(v4) = sa.ip() {
                tried_v4 += 1;
                if let Some(ms) = tcp_ping_direct_ipv4(v4, port, if_idx, timeout_ms, cancel) {
                    return ms;
                }
            }
        }
        return 0;
    }

    // If TUN is active and no physical adapter was found, do NOT probe via TUN (fake 1ms!).
    if tun_active {
        return 0;
    }

    let timeout = Duration::from_millis(timeout_ms.max(100) as u64);
    for sa in addrs_vec.iter().take(2) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let start = Instant::now();
        if TcpStream::connect_timeout(sa, timeout).is_ok() {
            return (start.elapsed().as_millis() as u32).max(1);
        }
    }
    0
}

pub fn tcp_ping_node(
    address: &str,
    port: u16,
    phys_if: Option<u32>,
    tun_active: bool,
    cancel: &AtomicBool,
) -> u32 {
    let addrs_vec = resolve_addrs_with_timeout(address, port, 2500, cancel);
    probe_resolved_addrs(&addrs_vec, port, phys_if, tun_active, 2000, cancel)
}

pub fn ping_all_async(
    nodes: Vec<(usize, String, u16)>,
    tun_active: bool,
    cancel: Arc<AtomicBool>,
    on_result: impl Fn(usize, u32) + Send + Sync + 'static,
    on_done: impl Fn() + Send + 'static,
) {
    let cb = Arc::new(on_result);
    std::thread::spawn(move || {
        let effective_tun = tun_active || find_adapter_luid("avel0").is_some();
        let phys_if = find_physical_ipv4_if_index();
        for chunk in nodes.chunks(8) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let mut handles = Vec::with_capacity(chunk.len());
            for &(idx, ref addr, port) in chunk {
                let a = addr.clone();
                let c = cb.clone();
                let cancel_t = cancel.clone();
                handles.push(std::thread::spawn(move || {
                    let ms = tcp_ping_node(&a, port, phys_if, effective_tun, &cancel_t);
                    if !cancel_t.load(Ordering::Relaxed) {
                        c(idx, ms);
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

pub fn extract_ping_targets(nodes: &[VlessNode]) -> Vec<(usize, String, u16)> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (i, n.address.clone(), n.port))
        .collect()
}

fn allocate_local_ports(count: usize) -> Option<Vec<u16>> {
    let mut listeners = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let l = TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = l.local_addr().ok()?.port();
        ports.push(port);
        listeners.push(l);
    }
    drop(listeners);
    Some(ports)
}

enum BatchRunStatus {
    Completed,
    Cancelled,
    StartFailed(String),
}

// Run a single batch of nodes through one ephemeral avel-core.exe with a hard watchdog deadline
// that kills the temp core immediately on Cancel or timeout so WinHTTP unblocks in <50ms.
fn run_real_ping_batch(
    chunk: &[(usize, VlessNode)],
    bind_iface: Option<&str>,
    out_opts: OutboundOpts,
    cancel: &Arc<AtomicBool>,
    cb: &Arc<dyn Fn(usize, u32) + Send + Sync>,
) -> BatchRunStatus {
    if cancel.load(Ordering::Relaxed) {
        return BatchRunStatus::Cancelled;
    }
    let Some(ports) = allocate_local_ports(chunk.len()) else {
        return BatchRunStatus::StartFailed(
            "Failed to allocate local loopback ports for Real Ping.".to_string(),
        );
    };
    let batch: Vec<(usize, VlessNode, u16)> = chunk
        .iter()
        .zip(ports.into_iter())
        .map(|((idx, node), port)| (*idx, node.clone(), port))
        .collect();

    let (cfg_json, valid_entries) = match build_batch_test_config(&batch, bind_iface, out_opts) {
        Ok(v) => v,
        Err(_) => {
            for (idx, _, _) in &batch {
                cb(*idx, 0);
            }
            return BatchRunStatus::Completed;
        }
    };

    let valid_set: HashSet<usize> = valid_entries.iter().map(|(i, _)| *i).collect();
    for (idx, _, _) in &batch {
        if !valid_set.contains(idx) {
            cb(*idx, 0);
        }
    }

    let ready_port = valid_entries[0].1;
    let temp_core = match TempXrayProcess::start(&cfg_json, ready_port, cancel) {
        Ok(p) => p,
        Err(e) => {
            return if cancel.load(Ordering::Relaxed) {
                BatchRunStatus::Cancelled
            } else {
                BatchRunStatus::StartFailed(e)
            };
        }
    };
    let killer = temp_core.killer();

    let total = valid_entries.len();
    let done_count = Arc::new(AtomicUsize::new(0));
    let reported: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(vec![false; total]));
    let batch_stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(total);

    for (slot, &(idx, port)) in valid_entries.iter().enumerate() {
        let c = cb.clone();
        let cancel_t = cancel.clone();
        let stop_t = batch_stop.clone();
        let done_t = done_count.clone();
        let rep_t = reported.clone();
        let stagger_ms = (slot as u64) * 40;
        handles.push(std::thread::spawn(move || {
            let ms = probe_http_proxy_real_delay(port, stagger_ms, &stop_t);
            let was_cancelled = cancel_t.load(Ordering::Relaxed);
            if !was_cancelled {
                if let Ok(mut flags) = rep_t.lock() {
                    if !flags[slot] {
                        flags[slot] = true;
                        c(idx, ms);
                    }
                }
            }
            done_t.fetch_add(1, Ordering::AcqRel);
        }));
    }

    // Watchdog: hard 9s ceiling per batch + immediate kill on user Cancel
    let deadline = Instant::now() + Duration::from_secs(9);
    while done_count.load(Ordering::Acquire) < total {
        if cancel.load(Ordering::Relaxed) {
            batch_stop.store(true, Ordering::Relaxed);
            killer.kill_now();
            break;
        }
        if Instant::now() >= deadline {
            batch_stop.store(true, Ordering::Relaxed);
            killer.kill_now();
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }

    for h in handles {
        let _ = h.join();
    }
    drop(temp_core);

    if cancel.load(Ordering::Relaxed) {
        return BatchRunStatus::Cancelled;
    }
    // Ensure any timed-out slot that exited without reporting still gets marked timeout (0)
    if let Ok(mut flags) = reported.lock() {
        for (slot, &(idx, _)) in valid_entries.iter().enumerate() {
            if !flags[slot] {
                flags[slot] = true;
                cb(idx, 0);
            }
        }
    }
    BatchRunStatus::Completed
}

// End-to-end Real Delay test through temporary batched avel-core.exe instances.
// Returns a single real HTTPS /generate_204 latency (ms) or 0 (timeout) per node.
pub fn real_ping_all_async(
    nodes: Vec<(usize, VlessNode)>,
    bind_physical_if: bool,
    out_opts: OutboundOpts,
    cancel: Arc<AtomicBool>,
    on_result: impl Fn(usize, u32) + Send + Sync + 'static,
    on_error: impl Fn(String) + Send + Sync + 'static,
    on_done: impl Fn() + Send + 'static,
) {
    let cb: Arc<dyn Fn(usize, u32) + Send + Sync> = Arc::new(on_result);
    let err_cb = Arc::new(on_error);
    std::thread::spawn(move || {
        let bind_iface = if bind_physical_if {
            find_physical_ipv4_if_info().map(|(_, name)| name)
        } else {
            None
        };

        for chunk in nodes.chunks(8) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            match run_real_ping_batch(chunk, bind_iface.as_deref(), out_opts, &cancel, &cb) {
                BatchRunStatus::Completed => {}
                BatchRunStatus::Cancelled => break,
                BatchRunStatus::StartFailed(e) => {
                    if chunk.len() > 1 {
                        // Isolate any broken node in the chunk so healthy nodes still get tested
                        for single in chunk {
                            if cancel.load(Ordering::Relaxed) {
                                break;
                            }
                            match run_real_ping_batch(
                                std::slice::from_ref(single),
                                bind_iface.as_deref(),
                                out_opts,
                                &cancel,
                                &cb,
                            ) {
                                BatchRunStatus::Completed => {}
                                BatchRunStatus::Cancelled => break,
                                BatchRunStatus::StartFailed(_) => {
                                    cb(single.0, 0);
                                }
                            }
                        }
                    } else {
                        err_cb(format!("Real Ping failed to start core: {}", e));
                        cb(chunk[0].0, 0);
                    }
                }
            }
        }
        on_done();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_physical_interface_and_measures_real_tcp_rtt() {
        let phys = find_physical_ipv4_if_index();
        assert!(phys.is_some(), "Expected an active physical IPv4 interface");
        let cancel = AtomicBool::new(false);
        let ms = tcp_ping_node("1.1.1.1", 443, phys, false, &cancel);
        assert!(ms >= 5 && ms < 2000, "Expected real physical TCP RTT (5..2000 ms), got {} ms", ms);
    }

    #[test]
    fn tun_active_never_falls_back_to_fake_1ms_unbound_ping() {
        let cancel = AtomicBool::new(false);
        let addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)];
        let ms = probe_resolved_addrs(&addrs, 80, None, true, 500, &cancel);
        assert_eq!(ms, 0, "TUN active without physical interface must return timeout (0), never fake 1ms");

        let cancelled = AtomicBool::new(true);
        assert!(resolve_addrs_with_timeout("1.1.1.1", 443, 500, &cancelled).is_empty());
    }
}
