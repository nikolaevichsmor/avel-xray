use crate::sys_proxy::to_wide;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts, URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};

const INTERNET_SCHEME_HTTPS: i32 = 2;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024; // 4 MB safety limit

pub struct SubscriptionResponse {
    pub body: String,
}

pub fn fetch_subscription(url: &str, user_agent: &str) -> Result<SubscriptionResponse, String> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return Err("URL must start with https:// or http://".to_string());
    }

    let w_url = to_wide(trimmed);
    let mut host_buf = vec![0u16; 512];
    let mut path_buf = vec![0u16; 2048];
    let mut extra_buf = vec![0u16; 2048];

    let mut comps: URL_COMPONENTS = unsafe { std::mem::zeroed() };
    comps.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
    comps.lpszHostName = host_buf.as_mut_ptr();
    comps.dwHostNameLength = host_buf.len() as u32;
    comps.lpszUrlPath = path_buf.as_mut_ptr();
    comps.dwUrlPathLength = path_buf.len() as u32;
    comps.lpszExtraInfo = extra_buf.as_mut_ptr();
    comps.dwExtraInfoLength = extra_buf.len() as u32;

    unsafe {
        if WinHttpCrackUrl(w_url.as_ptr(), 0, 0, &mut comps) == 0 {
            return Err("Failed to parse subscription URL".to_string());
        }

        let host = String::from_utf16_lossy(&host_buf[..comps.dwHostNameLength as usize]);
        let path_part = String::from_utf16_lossy(&path_buf[..comps.dwUrlPathLength as usize]);
        let extra_part = String::from_utf16_lossy(&extra_buf[..comps.dwExtraInfoLength as usize]);
        let mut full_path = format!("{}{}", path_part, extra_part);
        if full_path.is_empty() {
            full_path.push('/');
        }
        let is_https = comps.nScheme == INTERNET_SCHEME_HTTPS;
        let port = comps.nPort;

        let ua_str = if user_agent.trim().is_empty() {
            "Avel/1.0 (Windows; okhttp)"
        } else {
            user_agent.trim()
        };
        let ua = to_wide(ua_str);
        let h_session = WinHttpOpen(
            ua.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        );
        if h_session.is_null() {
            return Err("WinHttpOpen failed".to_string());
        }

        // Explicit timeouts: resolve 8s, connect 10s, send 10s, receive 15s
        WinHttpSetTimeouts(h_session, 8000, 10000, 10000, 15000);

        let w_host = to_wide(&host);
        let h_connect = WinHttpConnect(h_session, w_host.as_ptr(), port, 0);
        if h_connect.is_null() {
            WinHttpCloseHandle(h_session);
            return Err(format!("WinHttpConnect failed for {}", host));
        }

        let w_method = to_wide("GET");
        let w_path = to_wide(&full_path);
        let flags = if is_https { WINHTTP_FLAG_SECURE } else { 0 };
        let h_req = WinHttpOpenRequest(
            h_connect,
            w_method.as_ptr(),
            w_path.as_ptr(),
            null(),
            null(),
            null_mut(),
            flags,
        );
        if h_req.is_null() {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("WinHttpOpenRequest failed".to_string());
        }

        let sent = WinHttpSendRequest(h_req, null(), 0, null(), 0, 0, 0);
        if sent == 0 || WinHttpReceiveResponse(h_req, null_mut()) == 0 {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("Network request failed (timeout or connection error)".to_string());
        }

        let mut status_code: u32 = 0;
        let mut status_len: u32 = 4;
        WinHttpQueryHeaders(
            h_req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            &mut status_code as *mut u32 as *mut _,
            &mut status_len,
            null_mut(),
        );
        if status_code < 200 || status_code >= 300 {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(format!("Subscription server returned HTTP {}", status_code));
        }

        let mut body_bytes: Vec<u8> = Vec::new();
        loop {
            let mut avail: u32 = 0;
            if WinHttpQueryDataAvailable(h_req, &mut avail) == 0 {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err("Subscription download interrupted before completion".to_string());
            }
            if avail == 0 {
                break;
            }
            let to_read = (avail as usize).min(65536);
            if body_bytes.len() + to_read > MAX_RESPONSE_BYTES {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err("Subscription response exceeded 4 MB limit".to_string());
            }
            let mut chunk = vec![0u8; to_read];
            let mut read_now: u32 = 0;
            if WinHttpReadData(
                h_req,
                chunk.as_mut_ptr() as *mut _,
                to_read as u32,
                &mut read_now,
            ) == 0
            {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err("Subscription read error before completion".to_string());
            }
            if read_now == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..read_now as usize]);
        }

        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);

        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        Ok(SubscriptionResponse { body })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivePingStats {
    pub rtt_ms: u32,
    pub jitter_ms: u32,
    pub loss_pct: u8,
}

impl LivePingStats {
    pub fn quality_label(&self) -> &'static str {
        if self.loss_pct >= 100 {
            "Down"
        } else if self.loss_pct == 0 && self.rtt_ms <= 100 && self.jitter_ms <= 15 {
            "Good"
        } else if self.loss_pct <= 10 && self.rtt_ms <= 180 && self.jitter_ms <= 35 {
            "Fair"
        } else {
            "Poor"
        }
    }

    pub fn format_status(&self) -> String {
        if self.loss_pct >= 100 {
            "Down (100% loss)".to_string()
        } else {
            format!(
                "{}ms ±{}ms {}% ({})",
                self.rtt_ms,
                self.jitter_ms,
                self.loss_pct,
                self.quality_label()
            )
        }
    }
}

fn summarize_live_window(window: &VecDeque<Option<u32>>) -> LivePingStats {
    let total = window.len();
    let ok: Vec<u32> = window.iter().filter_map(|&v| v).collect();
    if total == 0 || ok.is_empty() {
        return LivePingStats {
            rtt_ms: 0,
            jitter_ms: 0,
            loss_pct: 100,
        };
    }
    let failed = total.saturating_sub(ok.len());
    let loss_pct = ((failed * 100 + total / 2) / total).min(100) as u8;
    let sum: u64 = ok.iter().map(|&v| v as u64).sum();
    let rtt_ms = ((sum + (ok.len() as u64) / 2) / (ok.len() as u64)) as u32;
    let jitter_ms = if ok.len() >= 2 {
        let diff_sum: u64 = ok.windows(2).map(|w| w[0].abs_diff(w[1]) as u64).sum();
        let cnt = (ok.len() - 1) as u64;
        ((diff_sum + cnt / 2) / cnt) as u32
    } else {
        0
    };
    LivePingStats {
        rtt_ms,
        jitter_ms,
        loss_pct,
    }
}

unsafe fn probe_once_on_connect(
    h_connect: *mut core::ffi::c_void,
    w_method: &[u16],
    w_path: &[u16],
) -> Option<u32> {
    let h_req = WinHttpOpenRequest(
        h_connect,
        w_method.as_ptr(),
        w_path.as_ptr(),
        null(),
        null(),
        null_mut(),
        WINHTTP_FLAG_SECURE,
    );
    if h_req.is_null() {
        return None;
    }

    let start = Instant::now();
    let ok = WinHttpSendRequest(h_req, null(), 0, null(), 0, 0, 0) != 0
        && WinHttpReceiveResponse(h_req, null_mut()) != 0;
    if !ok {
        WinHttpCloseHandle(h_req);
        return None;
    }

    let mut status_code: u32 = 0;
    let mut status_len: u32 = 4;
    WinHttpQueryHeaders(
        h_req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        null(),
        &mut status_code as *mut u32 as *mut _,
        &mut status_len,
        null_mut(),
    );
    // Drain any unread bytes (0 on 204) so WinHTTP returns the TLS socket to its keep-alive pool.
    let mut avail: u32 = 0;
    while WinHttpQueryDataAvailable(h_req, &mut avail) != 0 && avail > 0 {
        let mut sink = [0u8; 512];
        let mut got: u32 = 0;
        let n = (avail as usize).min(sink.len()) as u32;
        if WinHttpReadData(h_req, sink.as_mut_ptr() as *mut _, n, &mut got) == 0 || got == 0 {
            break;
        }
    }
    WinHttpCloseHandle(h_req);

    if status_code == 204 || status_code == 200 {
        Some((start.elapsed().as_millis() as u32).max(1))
    } else {
        None
    }
}

// Keep a single persistent HTTPS keep-alive tunnel open through the local HTTP inbound
// so each probe measures pure 1-RTT latency, jitter, and packet loss in real time.
pub fn spawn_live_tunnel_monitor(
    http_port: u16,
    stop: Arc<AtomicBool>,
    on_update: impl Fn(LivePingStats) + Send + 'static,
) {
    std::thread::spawn(move || {
        // Brief settle wait after Xray starts
        for _ in 0..4 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(80));
        }

        let ua = to_wide("Avel/1.0");
        let proxy = to_wide(&format!("127.0.0.1:{}", http_port));
        let host = to_wide("www.gstatic.com");
        let w_method = to_wide("GET");
        let w_path = to_wide("/generate_204");

        let mut window: VecDeque<Option<u32>> = VecDeque::with_capacity(12);
        let mut warmed_up = false;

        unsafe {
            let h_session = WinHttpOpen(
                ua.as_ptr(),
                WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                proxy.as_ptr(),
                null(),
                0,
            );
            if h_session.is_null() {
                return;
            }
            WinHttpSetTimeouts(h_session, 3000, 4000, 4000, 4500);

            let mut h_connect = WinHttpConnect(h_session, host.as_ptr(), 443, 0);

            while !stop.load(Ordering::Relaxed) {
                if h_connect.is_null() {
                    h_connect = WinHttpConnect(h_session, host.as_ptr(), 443, 0);
                }

                let sample = if h_connect.is_null() {
                    None
                } else {
                    probe_once_on_connect(h_connect, &w_method, &w_path)
                };

                if stop.load(Ordering::Relaxed) {
                    break;
                }

                // First successful request pays TCP+TLS handshake; treat it as keep-alive warmup
                // and immediately follow up with the first real 1-RTT sample.
                if !warmed_up && sample.is_some() {
                    warmed_up = true;
                    std::thread::sleep(Duration::from_millis(120));
                    continue;
                }

                if sample.is_none() {
                    warmed_up = false;
                    if !h_connect.is_null() {
                        WinHttpCloseHandle(h_connect);
                        h_connect = null_mut();
                    }
                }

                if window.len() >= 12 {
                    window.pop_front();
                }
                window.push_back(sample);
                on_update(summarize_live_window(&window));

                // Wait 2.5s between probes in short slices for instant stop on disconnect
                for _ in 0..25 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }

            if !h_connect.is_null() {
                WinHttpCloseHandle(h_connect);
            }
            WinHttpCloseHandle(h_session);
        }
    });
}

const MAX_GEO_BYTES: usize = 32 * 1024 * 1024;
const MIN_GEO_BYTES: usize = 64 * 1024;
const MAX_UPDATE_ZIP_BYTES: usize = 64 * 1024 * 1024;
const MIN_UPDATE_ZIP_BYTES: usize = 1024 * 1024;
const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/nikolaevichsmor/avel-xray/releases/latest";
const GEOIP_URL: &str =
    "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geoip/geoip-lite.dat";
const GEOSITE_URL: &str =
    "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geosite/geosite.dat";

// Stream an HTTPS download to a temp file and atomically replace `dest`.
fn download_https_asset(
    url: &str,
    dest: &Path,
    user_agent: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<usize, String> {
    if !url.starts_with("https://") {
        return Err("Asset URL must use HTTPS".to_string());
    }
    let w_url = to_wide(url);
    let mut host_buf = vec![0u16; 512];
    let mut path_buf = vec![0u16; 2048];
    let mut extra_buf = vec![0u16; 512];

    let mut comps: URL_COMPONENTS = unsafe { std::mem::zeroed() };
    comps.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
    comps.lpszHostName = host_buf.as_mut_ptr();
    comps.dwHostNameLength = host_buf.len() as u32;
    comps.lpszUrlPath = path_buf.as_mut_ptr();
    comps.dwUrlPathLength = path_buf.len() as u32;
    comps.lpszExtraInfo = extra_buf.as_mut_ptr();
    comps.dwExtraInfoLength = extra_buf.len() as u32;

    unsafe {
        if WinHttpCrackUrl(w_url.as_ptr(), 0, 0, &mut comps) == 0
            || comps.nScheme != INTERNET_SCHEME_HTTPS
        {
            return Err("Invalid HTTPS asset URL".to_string());
        }
        let host = String::from_utf16_lossy(&host_buf[..comps.dwHostNameLength as usize]);
        let path_part = String::from_utf16_lossy(&path_buf[..comps.dwUrlPathLength as usize]);
        let extra_part = String::from_utf16_lossy(&extra_buf[..comps.dwExtraInfoLength as usize]);
        let full_path = format!("{}{}", path_part, extra_part);

        let ua_str = if user_agent.trim().is_empty() {
            "Avel/1.0 (Windows)"
        } else {
            user_agent.trim()
        };
        let ua = to_wide(ua_str);
        let h_session = WinHttpOpen(
            ua.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        );
        if h_session.is_null() {
            return Err("WinHttpOpen failed".to_string());
        }
        WinHttpSetTimeouts(h_session, 10000, 15000, 15000, 45000);

        let w_host = to_wide(&host);
        let h_connect = WinHttpConnect(h_session, w_host.as_ptr(), comps.nPort, 0);
        if h_connect.is_null() {
            WinHttpCloseHandle(h_session);
            return Err(format!("Failed to connect to {}", host));
        }

        let w_method = to_wide("GET");
        let w_path = to_wide(&full_path);
        let h_req = WinHttpOpenRequest(
            h_connect,
            w_method.as_ptr(),
            w_path.as_ptr(),
            null(),
            null(),
            null_mut(),
            WINHTTP_FLAG_SECURE,
        );
        if h_req.is_null() {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("WinHttpOpenRequest failed".to_string());
        }

        let sent = WinHttpSendRequest(h_req, null(), 0, null(), 0, 0, 0);
        if sent == 0 || WinHttpReceiveResponse(h_req, null_mut()) == 0 {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(format!("Network error downloading {}", host));
        }

        let mut status_code: u32 = 0;
        let mut status_len: u32 = 4;
        WinHttpQueryHeaders(
            h_req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            &mut status_code as *mut u32 as *mut _,
            &mut status_len,
            null_mut(),
        );
        if status_code < 200 || status_code >= 300 {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(format!("Server returned HTTP {}", status_code));
        }

        let tmp = dest.with_extension("dat.tmp");
        let file = match File::create(&tmp) {
            Ok(f) => f,
            Err(e) => {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err(format!("Failed to create temp file: {}", e));
            }
        };
        let mut writer = BufWriter::with_capacity(65536, file);
        let mut total: usize = 0;
        let mut chunk = vec![0u8; 65536];
        let mut dl_err: Option<String> = None;

        loop {
            let mut avail: u32 = 0;
            if WinHttpQueryDataAvailable(h_req, &mut avail) == 0 {
                dl_err = Some("Download interrupted before completion".to_string());
                break;
            }
            if avail == 0 {
                break;
            }
            let to_read = (avail as usize).min(chunk.len());
            if total + to_read > max_bytes {
                dl_err = Some(format!(
                    "File exceeded {} MB safety limit",
                    max_bytes / (1024 * 1024)
                ));
                break;
            }
            let mut read_now: u32 = 0;
            if WinHttpReadData(
                h_req,
                chunk.as_mut_ptr() as *mut _,
                to_read as u32,
                &mut read_now,
            ) == 0
            {
                dl_err = Some("Read error before completion".to_string());
                break;
            }
            if read_now == 0 {
                break;
            }
            if let Err(e) = writer.write_all(&chunk[..read_now as usize]) {
                dl_err = Some(format!("Disk write error: {}", e));
                break;
            }
            total += read_now as usize;
        }

        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);

        if let Some(err) = dl_err {
            drop(writer);
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
        if let Err(e) = writer.flush() {
            drop(writer);
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("Disk flush error: {}", e));
        }
        drop(writer);

        if total < min_bytes {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("Downloaded file is unexpectedly small ({} bytes)", total));
        }
        if let Err(e) = std::fs::rename(&tmp, dest) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("Failed to replace {}: {}", dest.display(), e));
        }
        Ok(total)
    }
}

pub fn update_geo_databases(core_dir: &Path, user_agent: &str) -> Result<(usize, usize), String> {
    let geoip_path = core_dir.join("geoip.dat");
    let geosite_path = core_dir.join("geosite.dat");
    let geoip_len =
        download_https_asset(GEOIP_URL, &geoip_path, user_agent, MIN_GEO_BYTES, MAX_GEO_BYTES)
            .map_err(|e| format!("geoip.dat: {}", e))?;
    let geosite_len = download_https_asset(
        GEOSITE_URL,
        &geosite_path,
        user_agent,
        MIN_GEO_BYTES,
        MAX_GEO_BYTES,
    )
    .map_err(|e| format!("geosite.dat: {}", e))?;
    Ok((geoip_len, geosite_len))
}

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub tag: String,
    pub zip_name: String,
    pub zip_url: String,
    pub sums_url: String,
}

pub fn parse_semver(raw: &str) -> Option<(u32, u32, u32)> {
    let clean = raw
        .trim()
        .trim_start_matches('v')
        .trim_start_matches('V')
        .split('-')
        .next()?;
    let mut parts = clean.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(current: &str, remote: &str) -> bool {
    match (parse_semver(current), parse_semver(remote)) {
        (Some(cur), Some(rem)) => rem > cur,
        _ => false,
    }
}

fn fetch_https_text(
    url: &str,
    user_agent: &str,
    extra_headers: Option<&str>,
    max_bytes: usize,
) -> Result<String, String> {
    if !url.starts_with("https://") {
        return Err("URL must use HTTPS".to_string());
    }
    let w_url = to_wide(url);
    let mut host_buf = vec![0u16; 512];
    let mut path_buf = vec![0u16; 2048];
    let mut extra_buf = vec![0u16; 512];

    let mut comps: URL_COMPONENTS = unsafe { std::mem::zeroed() };
    comps.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
    comps.lpszHostName = host_buf.as_mut_ptr();
    comps.dwHostNameLength = host_buf.len() as u32;
    comps.lpszUrlPath = path_buf.as_mut_ptr();
    comps.dwUrlPathLength = path_buf.len() as u32;
    comps.lpszExtraInfo = extra_buf.as_mut_ptr();
    comps.dwExtraInfoLength = extra_buf.len() as u32;

    unsafe {
        if WinHttpCrackUrl(w_url.as_ptr(), 0, 0, &mut comps) == 0
            || comps.nScheme != INTERNET_SCHEME_HTTPS
        {
            return Err("Invalid HTTPS URL".to_string());
        }
        let host = String::from_utf16_lossy(&host_buf[..comps.dwHostNameLength as usize]);
        let path_part = String::from_utf16_lossy(&path_buf[..comps.dwUrlPathLength as usize]);
        let extra_part = String::from_utf16_lossy(&extra_buf[..comps.dwExtraInfoLength as usize]);
        let full_path = format!("{}{}", path_part, extra_part);

        let ua_str = if user_agent.trim().is_empty() {
            "avel-xray"
        } else {
            user_agent.trim()
        };
        let ua = to_wide(ua_str);
        let h_session = WinHttpOpen(
            ua.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        );
        if h_session.is_null() {
            return Err("WinHttpOpen failed".to_string());
        }
        WinHttpSetTimeouts(h_session, 8000, 10000, 10000, 15000);

        let w_host = to_wide(&host);
        let h_connect = WinHttpConnect(h_session, w_host.as_ptr(), comps.nPort, 0);
        if h_connect.is_null() {
            WinHttpCloseHandle(h_session);
            return Err(format!("Failed to connect to {}", host));
        }

        let w_method = to_wide("GET");
        let w_path = to_wide(&full_path);
        let h_req = WinHttpOpenRequest(
            h_connect,
            w_method.as_ptr(),
            w_path.as_ptr(),
            null(),
            null(),
            null_mut(),
            WINHTTP_FLAG_SECURE,
        );
        if h_req.is_null() {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("WinHttpOpenRequest failed".to_string());
        }

        let w_hdrs = extra_headers.map(to_wide);
        let (hdr_ptr, hdr_len) = match &w_hdrs {
            Some(v) => (v.as_ptr(), (v.len().saturating_sub(1)) as u32),
            None => (null(), 0),
        };
        let sent = WinHttpSendRequest(h_req, hdr_ptr, hdr_len, null(), 0, 0, 0);
        if sent == 0 || WinHttpReceiveResponse(h_req, null_mut()) == 0 {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(format!("Network request to {} failed", host));
        }

        let mut status_code: u32 = 0;
        let mut status_len: u32 = 4;
        WinHttpQueryHeaders(
            h_req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            &mut status_code as *mut u32 as *mut _,
            &mut status_len,
            null_mut(),
        );
        if status_code < 200 || status_code >= 300 {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(format!("GitHub returned HTTP {}", status_code));
        }

        let mut bytes = Vec::new();
        loop {
            let mut avail: u32 = 0;
            if WinHttpQueryDataAvailable(h_req, &mut avail) == 0 {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err("Response interrupted".to_string());
            }
            if avail == 0 {
                break;
            }
            let to_read = (avail as usize).min(16384);
            if bytes.len() + to_read > max_bytes {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err("Response size limit exceeded".to_string());
            }
            let mut chunk = vec![0u8; to_read];
            let mut got: u32 = 0;
            if WinHttpReadData(h_req, chunk.as_mut_ptr() as *mut _, to_read as u32, &mut got) == 0 {
                WinHttpCloseHandle(h_req);
                WinHttpCloseHandle(h_connect);
                WinHttpCloseHandle(h_session);
                return Err("Read error".to_string());
            }
            if got == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..got as usize]);
        }

        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

pub fn check_latest_release(user_agent: &str) -> Result<ReleaseInfo, String> {
    let body = fetch_https_text(
        GITHUB_LATEST_RELEASE_URL,
        user_agent,
        Some("Accept: application/vnd.github+json\r\n"),
        512 * 1024,
    )?;
    let root: Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid GitHub JSON: {}", e))?;
    let tag = root
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing tag_name in GitHub release".to_string())?
        .trim()
        .to_string();

    let mut zip_name = String::new();
    let mut zip_url = String::new();
    let mut sums_url = String::new();

    if let Some(assets) = root.get("assets").and_then(|v| v.as_array()) {
        for a in assets {
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let url = a
                .get("browser_download_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !url.starts_with("https://") {
                continue;
            }
            if name.ends_with("windows-x64.zip") {
                zip_name = name.to_string();
                zip_url = url.to_string();
            } else if name.eq_ignore_ascii_case("SHA256SUMS.txt") {
                sums_url = url.to_string();
            }
        }
    }

    Ok(ReleaseInfo {
        tag,
        zip_name,
        zip_url,
        sums_url,
    })
}

fn find_expected_sha256(sums_text: &str, filename: &str) -> Option<String> {
    for line in sums_text.trim_start_matches('\u{FEFF}').lines() {
        let mut it = line.trim().split_whitespace();
        let hash = it.next()?;
        let name = it.next()?;
        if name.eq_ignore_ascii_case(filename)
            && hash.len() == 64
            && hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some(hash.to_lowercase());
        }
    }
    None
}

pub fn download_and_verify_release(
    rel: &ReleaseInfo,
    dest_zip: &Path,
    user_agent: &str,
) -> Result<(), String> {
    if rel.zip_url.is_empty() || rel.zip_name.is_empty() {
        return Err("Release does not include a windows-x64.zip archive.".to_string());
    }
    if rel.sums_url.is_empty() {
        return Err("Release does not include SHA256SUMS.txt for verification.".to_string());
    }
    let sums_text = fetch_https_text(&rel.sums_url, user_agent, None, 64 * 1024)
        .map_err(|e| format!("Failed to fetch SHA256SUMS.txt: {}", e))?;
    let expected = find_expected_sha256(&sums_text, &rel.zip_name)
        .ok_or_else(|| format!("SHA256 entry for {} not found in SHA256SUMS.txt", rel.zip_name))?;

    if let Some(parent) = dest_zip.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    download_https_asset(
        &rel.zip_url,
        dest_zip,
        user_agent,
        MIN_UPDATE_ZIP_BYTES,
        MAX_UPDATE_ZIP_BYTES,
    )
    .map_err(|e| format!("Failed to download {}: {}", rel.zip_name, e))?;

    let actual = sha256_file_hex(dest_zip)?;
    if actual != expected {
        let _ = std::fs::remove_file(dest_zip);
        return Err(format!(
            "SHA256 mismatch for {}: expected {}, got {}",
            rel.zip_name, expected, actual
        ));
    }
    Ok(())
}

// Self-contained FIPS 180-4 SHA-256 (avoids extra crate dependencies).
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bits: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bits: 0,
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(hh);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64) * 8);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let blk = self.buf;
                self.compress(&blk);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut blk = [0u8; 64];
            blk.copy_from_slice(&data[..64]);
            self.compress(&blk);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize_hex(mut self) -> String {
        let bits = self.total_bits;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let blk = self.buf;
            self.compress(&blk);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bits.to_be_bytes());
        let blk = self.buf;
        self.compress(&blk);

        let mut out = String::with_capacity(64);
        for word in self.h {
            use std::fmt::Write as _;
            let _ = write!(out, "{:08x}", word);
        }
        out
    }
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let f = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let mut reader = BufReader::with_capacity(65536, f);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("SHA256 read error: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_ping_window_computes_quality_and_status() {
        let w: VecDeque<Option<u32>> = vec![Some(46), Some(48), Some(47), Some(49)].into();
        let st = summarize_live_window(&w);
        assert_eq!(st.rtt_ms, 48);
        assert_eq!(st.jitter_ms, 2);
        assert_eq!(st.loss_pct, 0);
        assert_eq!(st.quality_label(), "Good");
        assert_eq!(st.format_status(), "48ms ±2ms 0% (Good)");

        let down: VecDeque<Option<u32>> = vec![None, None, None].into();
        let st_down = summarize_live_window(&down);
        assert_eq!(st_down.quality_label(), "Down");
        assert_eq!(st_down.format_status(), "Down (100% loss)");
    }

    #[test]
    fn sha256_and_semver_comparison_work() {
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            h.finalize_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_newer_version("0.1.0", "v0.1.1"));
        assert!(is_newer_version("0.1.1", "v0.2.0"));
        assert!(!is_newer_version("0.1.1", "v0.1.1"));
        assert!(!is_newer_version("0.1.1", "v0.1.0"));
    }
}
