use crate::http_unix::probe_http_proxy_real_delay;
use crate::model::VlessNode;
use crate::xray_config::{build_batch_test_config, OutboundOpts};
use crate::xray_proc_unix::{is_root, TempXrayProcess};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub fn has_avel_tun() -> bool {
    std::path::Path::new("/sys/class/net/avel0").exists()
}

pub fn query_tun_octets(iface: &str) -> Option<(u64, u64)> {
    let rx = std::fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", iface))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    let tx = std::fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", iface))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some((rx, tx))
}

// Parse /proc/net/route to find the physical default IPv4 interface (lowest metric).
pub fn find_default_linux_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    let mut best: Option<(u32, String)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 7 {
            continue;
        }
        let iface = cols[0];
        let dest = cols[1];
        if dest != "00000000" {
            continue;
        }
        let lc = iface.to_lowercase();
        let is_virtual = lc == "lo"
            || lc.starts_with("avel")
            || lc.starts_with("tun")
            || lc.starts_with("tap")
            || lc.starts_with("wg")
            || lc.starts_with("docker")
            || lc.starts_with("br-")
            || lc.starts_with("veth")
            || lc.starts_with("virbr")
            || lc.starts_with("tailscale")
            || lc.starts_with("zt");
        if is_virtual {
            continue;
        }
        let metric = cols[6].parse::<u32>().unwrap_or(u32::MAX);
        if best.as_ref().map(|(m, _)| metric < *m).unwrap_or(true) {
            best = Some((metric, iface.to_string()));
        }
    }
    best.map(|(_, name)| name)
}

fn tcp_ping_ipv4_unix(
    ip: Ipv4Addr,
    port: u16,
    bind_iface: Option<&str>,
    timeout_ms: u64,
    cancel: &AtomicBool,
) -> Option<u32> {
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return None;
        }
        if let Some(iface) = bind_iface {
            let mut bytes = iface.as_bytes().to_vec();
            bytes.push(0);
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len() as libc::socklen_t,
            );
        }

        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = port.to_be();
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        };

        let start = Instant::now();
        let rc = libc::connect(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let ok = if rc == 0 {
            true
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err != libc::EINPROGRESS {
                false
            } else {
                let deadline = Duration::from_millis(timeout_ms.max(100));
                let mut connected = false;
                loop {
                    if cancel.load(Ordering::Relaxed) || start.elapsed() >= deadline {
                        break;
                    }
                    let slice = deadline
                        .saturating_sub(start.elapsed())
                        .as_millis()
                        .clamp(1, 100) as i32;
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let pr = libc::poll(&mut pfd, 1, slice);
                    if pr > 0 {
                        let mut so_err: libc::c_int = 0;
                        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            &mut so_err as *mut libc::c_int as *mut libc::c_void,
                            &mut len,
                        );
                        connected = so_err == 0 && (pfd.revents & (libc::POLLERR | libc::POLLHUP)) == 0;
                        break;
                    } else if pr < 0 {
                        break;
                    }
                }
                connected
            }
        };

        let elapsed = start.elapsed().as_millis() as u32;
        libc::close(fd);
        if ok && !cancel.load(Ordering::Relaxed) {
            Some(elapsed.max(1))
        } else {
            None
        }
    }
}

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

pub fn tcp_ping_node(
    address: &str,
    port: u16,
    bind_iface: Option<&str>,
    tun_active: bool,
    cancel: &AtomicBool,
) -> u32 {
    if tun_active && bind_iface.is_none() {
        // Without SO_BINDTODEVICE (root) while TUN is active, TCP connect hits local TUN stack -> fake 1ms
        return 0;
    }
    let addrs = resolve_addrs_with_timeout(address, port, 2500, cancel);
    let mut tried = 0usize;
    for sa in &addrs {
        if cancel.load(Ordering::Relaxed) || tried >= 2 {
            break;
        }
        if let IpAddr::V4(v4) = sa.ip() {
            tried += 1;
            if let Some(ms) = tcp_ping_ipv4_unix(v4, port, bind_iface, 2000, cancel) {
                return ms;
            }
        }
    }
    if tried == 0 && !tun_active {
        let timeout = Duration::from_millis(2000);
        for sa in addrs.iter().take(2) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let start = Instant::now();
            if TcpStream::connect_timeout(sa, timeout).is_ok() {
                return (start.elapsed().as_millis() as u32).max(1);
            }
        }
    }
    0
}

pub fn extract_ping_targets(nodes: &[VlessNode]) -> Vec<(usize, String, u16)> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (i, n.address.clone(), n.port))
        .collect()
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
        let effective_tun = tun_active || has_avel_tun();
        let bind_iface = if is_root() {
            find_default_linux_interface()
        } else {
            None
        };
        for chunk in nodes.chunks(8) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let mut handles = Vec::with_capacity(chunk.len());
            for &(idx, ref addr, port) in chunk {
                let a = addr.clone();
                let c = cb.clone();
                let cancel_t = cancel.clone();
                let iface = bind_iface.clone();
                handles.push(std::thread::spawn(move || {
                    let ms = tcp_ping_node(&a, port, iface.as_deref(), effective_tun, &cancel_t);
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
        return BatchRunStatus::StartFailed("Failed to allocate local loopback ports.".to_string());
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
            if !cancel_t.load(Ordering::Relaxed) {
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

    let deadline = Instant::now() + Duration::from_secs(9);
    while done_count.load(Ordering::Acquire) < total {
        if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
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
        let bind_iface = if bind_physical_if && is_root() {
            find_default_linux_interface()
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
                                BatchRunStatus::StartFailed(_) => cb(single.0, 0),
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
