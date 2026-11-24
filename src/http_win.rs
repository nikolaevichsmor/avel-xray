use crate::sys_proxy::to_wide;
use base64::Engine;
use serde_json::Value;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts, URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_CUSTOM,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

const INTERNET_SCHEME_HTTPS: i32 = 2;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024; // 4 MB safety limit

pub struct SubscriptionResponse {
    pub body: String,
    pub profile_title: Option<String>,
    pub update_interval_hours: Option<u32>,
    pub userinfo: Option<String>,
    pub via_proxy: bool,
}

pub fn fetch_subscription_opts(
    url: &str,
    user_agent: &str,
    send_hwid: bool,
    fallback_proxy_port: Option<u16>,
) -> Result<SubscriptionResponse, String> {
    match fetch_subscription_inner(url, user_agent, send_hwid, None) {
        Ok(resp) => Ok(resp),
        Err(direct_err) => {
            if let Some(port) = fallback_proxy_port.filter(|&p| p > 0) {
                match fetch_subscription_inner(url, user_agent, send_hwid, Some(port)) {
                    Ok(mut resp) => {
                        resp.via_proxy = true;
                        Ok(resp)
                    }
                    Err(proxy_err) => Err(format!(
                        "{} (proxy fallback on 127.0.0.1:{} also failed: {})",
                        direct_err, port, proxy_err
                    )),
                }
            } else {
                Err(direct_err)
            }
        }
    }
}

fn read_reg_string(subkey: &str, value_name: &str) -> Option<String> {
    unsafe {
        let mut hkey: HKEY = null_mut();
        let w_sub = to_wide(subkey);
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, w_sub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return None;
        }
        let w_val = to_wide(value_name);
        let mut buf_bytes: u32 = 512;
        let mut buf = vec![0u16; 256];
        let mut ty: u32 = 0;
        let rc = RegQueryValueExW(
            hkey,
            w_val.as_ptr(),
            null_mut(),
            &mut ty,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_bytes,
        );
        RegCloseKey(hkey);
        if rc != 0 || buf_bytes < 2 {
            return None;
        }
        let chars = (buf_bytes as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..chars]);
        let trimmed = s.trim_end_matches('\0').trim().to_string();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    }
}

fn build_hwid_headers() -> String {
    let guid = read_reg_string("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid")
        .unwrap_or_else(|| {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-host".to_string())
        });
    let mut hasher = Sha256::new();
    hasher.update(b"avel-hwid-v1:");
    hasher.update(guid.as_bytes());
    let hwid = &hasher.finalize_hex()[..32];

    let os_ver = read_reg_string(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "CurrentBuildNumber",
    )
    .unwrap_or_else(|| "11".to_string());
    let model = read_reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName")
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "PC".to_string());
    let clean_model: String = model
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(48)
        .collect();

    format!(
        "x-hwid: {}\r\nx-device-os: Windows\r\nx-ver-os: {}\r\nx-device-model: {}\r\n",
        hwid,
        os_ver,
        clean_model.trim()
    )
}

unsafe fn query_custom_header(h_req: *mut core::ffi::c_void, name: &str) -> Option<String> {
    let w_name = to_wide(name);
    let mut buf = vec![0u16; 512];
    let mut buf_bytes = (buf.len() * 2) as u32;
    let ok = WinHttpQueryHeaders(
        h_req,
        WINHTTP_QUERY_CUSTOM,
        w_name.as_ptr(),
        buf.as_mut_ptr() as *mut _,
        &mut buf_bytes,
        null_mut(),
    );
    if ok == 0 || buf_bytes < 2 {
        return None;
    }
    let chars = (buf_bytes as usize / 2).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..chars]);
    let t = s.trim_end_matches('\0').trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

pub fn decode_profile_title(raw: &str) -> String {
    let t = raw.trim();
    if let Some(b64) = t.strip_prefix("base64:").or_else(|| t.strip_prefix("BASE64:")) {
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        for eng in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(bytes) = eng.decode(cleaned.as_bytes()) {
                if let Ok(s) = String::from_utf8(bytes) {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        return s;
                    }
                }
            }
        }
    }
    t.to_string()
}

pub fn format_subscription_userinfo(raw: &str) -> Option<String> {
    let mut upload: u64 = 0;
    let mut download: u64 = 0;
    let mut total: u64 = 0;
    let mut expire: u64 = 0;
    let mut any = false;
    for part in raw.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().parse::<u64>().ok();
            match (key.as_str(), val) {
                ("upload", Some(n)) => { upload = n; any = true; }
                ("download", Some(n)) => { download = n; any = true; }
                ("total", Some(n)) => { total = n; any = true; }
                ("expire", Some(n)) => { expire = n; any = true; }
                _ => {}
            }
        }
    }
    if !any {
        return None;
    }
    let fmt_gb = |b: u64| -> String {
        let gb = b as f64 / (1024.0 * 1024.0 * 1024.0);
        if gb >= 100.0 {
            format!("{:.0} GB", gb)
        } else if gb >= 1.0 {
            format!("{:.1} GB", gb)
        } else {
            format!("{:.0} MB", b as f64 / (1024.0 * 1024.0))
        }
    };
    let used = upload.saturating_add(download);
    let mut parts: Vec<String> = Vec::new();
    if total > 0 {
        parts.push(format!("{} / {}", fmt_gb(used), fmt_gb(total)));
    } else if used > 0 {
        parts.push(fmt_gb(used));
    }
    if expire > 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if expire > now {
            let days = (expire - now) / 86400;
            parts.push(format!("{}d left", days));
        } else {
            parts.push("expired".to_string());
        }
    }
    if parts.is_empty() { None } else { Some(parts.join(", ")) }
}

fn fetch_subscription_inner(
    url: &str,
    user_agent: &str,
    send_hwid: bool,
    proxy_port: Option<u16>,
) -> Result<SubscriptionResponse, String> {
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
        let w_proxy = proxy_port.map(|p| to_wide(&format!("127.0.0.1:{}", p)));
        let (access_type, proxy_ptr) = match w_proxy {
            Some(ref wp) => (WINHTTP_ACCESS_TYPE_NAMED_PROXY, wp.as_ptr()),
            None => (WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, null()),
        };
        let h_session = WinHttpOpen(ua.as_ptr(), access_type, proxy_ptr, null(), 0);
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

        let w_hdrs = if send_hwid {
            Some(to_wide(&build_hwid_headers()))
        } else {
            None
        };
        let (hdr_ptr, hdr_len) = match w_hdrs {
            Some(ref wh) => (wh.as_ptr(), wh.len().saturating_sub(1) as u32),
            None => (null(), 0),
        };
        let sent = WinHttpSendRequest(h_req, hdr_ptr, hdr_len, null(), 0, 0, 0);
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

        let profile_title =
            query_custom_header(h_req, "profile-title").map(|s| decode_profile_title(&s));
        let update_interval_hours = query_custom_header(h_req, "profile-update-interval")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&h| h > 0)
            .map(|h| h.clamp(1, 720));
        let userinfo = query_custom_header(h_req, "subscription-userinfo")
            .and_then(|s| format_subscription_userinfo(&s));

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
        Ok(SubscriptionResponse {
            body,
            profile_title,
            update_interval_hours,
            userinfo,
            via_proxy: false,
        })
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

// End-to-end Real Delay probe through a local Xray HTTP inbound (warm-up + 1-RTT /generate_204).
pub fn probe_http_proxy_real_delay(
    http_port: u16,
    initial_delay_ms: u64,
    cancel: &AtomicBool,
) -> u32 {
    let mut rem = initial_delay_ms;
    while rem > 0 && !cancel.load(Ordering::Relaxed) {
        let step = rem.min(30);
        std::thread::sleep(Duration::from_millis(step));
        rem -= step;
    }
    if cancel.load(Ordering::Relaxed) {
        return 0;
    }

    let ua = to_wide("Avel/1.0");
    let proxy = to_wide(&format!("127.0.0.1:{}", http_port));
    let host = to_wide("www.gstatic.com");
    let w_method = to_wide("GET");
    let w_path = to_wide("/generate_204");

    unsafe {
        let h_session = WinHttpOpen(
            ua.as_ptr(),
            WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            proxy.as_ptr(),
            null(),
            0,
        );
        if h_session.is_null() {
            return 0;
        }
        WinHttpSetTimeouts(h_session, 2000, 2500, 2500, 3000);
        let h_connect = WinHttpConnect(h_session, host.as_ptr(), 443, 0);
        if h_connect.is_null() {
            WinHttpCloseHandle(h_session);
            return 0;
        }

        if cancel.load(Ordering::Relaxed) {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return 0;
        }

        let first = probe_once_on_connect(h_connect, &w_method, &w_path);
        let result = match first {
            None => 0,
            Some(t1) => {
                if cancel.load(Ordering::Relaxed) {
                    0
                } else {
                    match probe_once_on_connect(h_connect, &w_method, &w_path) {
                        Some(t2) => t2.min(t1),
                        None => t1,
                    }
                }
            }
        };

        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        result
    }
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

    #[test]
    fn parses_profile_title_and_userinfo_headers() {
        assert_eq!(decode_profile_title("base64:TXkgVlBO"), "My VPN");
        assert_eq!(decode_profile_title("PlainTitle"), "PlainTitle");
        let ui = format_subscription_userinfo("upload=1073741824; download=2147483648; total=107374182400; expire=0")
            .unwrap();
        assert_eq!(ui, "3.0 GB / 100 GB");
    }
}
