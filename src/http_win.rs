use crate::sys_proxy::to_wide;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Instant;
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

// Send HTTPS GET /generate_204 through the local HTTP inbound and measure RTT in ms.
pub fn test_http_proxy_204(http_port: u16) -> Result<u32, String> {
    let ua = to_wide("Avel/1.0");
    let proxy = to_wide(&format!("127.0.0.1:{}", http_port));
    let host = to_wide("www.gstatic.com");
    let method = to_wide("GET");
    let path = to_wide("/generate_204");

    let start = Instant::now();
    unsafe {
        let h_session = WinHttpOpen(
            ua.as_ptr(),
            WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            proxy.as_ptr(),
            null(),
            0,
        );
        if h_session.is_null() {
            return Err("WinHttpOpen failed".to_string());
        }
        WinHttpSetTimeouts(h_session, 4000, 5000, 5000, 6000);

        let h_connect = WinHttpConnect(h_session, host.as_ptr(), 443, 0);
        if h_connect.is_null() {
            WinHttpCloseHandle(h_session);
            return Err("Failed to connect to local HTTP inbound".to_string());
        }

        let h_req = WinHttpOpenRequest(
            h_connect,
            method.as_ptr(),
            path.as_ptr(),
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

        let ok = WinHttpSendRequest(h_req, null(), 0, null(), 0, 0, 0) != 0
            && WinHttpReceiveResponse(h_req, null_mut()) != 0;
        if !ok {
            WinHttpCloseHandle(h_req);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("Tunnel timeout or handshake error".to_string());
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
        WinHttpCloseHandle(h_req);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);

        let ms = (start.elapsed().as_millis() as u32).max(1);
        if status_code == 204 || status_code == 200 {
            Ok(ms)
        } else {
            Err(format!("Unexpected HTTP {} ({} ms)", status_code, ms))
        }
    }
}

const MAX_GEO_BYTES: usize = 32 * 1024 * 1024;
const MIN_GEO_BYTES: usize = 64 * 1024;
const GEOIP_URL: &str =
    "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geoip/geoip-lite.dat";
const GEOSITE_URL: &str =
    "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geosite/geosite.dat";

// Stream an HTTPS download to a temp file and atomically replace `dest`.
fn download_https_asset(url: &str, dest: &Path, user_agent: &str) -> Result<usize, String> {
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
            if total + to_read > MAX_GEO_BYTES {
                dl_err = Some("File exceeded 32 MB safety limit".to_string());
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

        if total < MIN_GEO_BYTES {
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
    let geoip_len = download_https_asset(GEOIP_URL, &geoip_path, user_agent)
        .map_err(|e| format!("geoip.dat: {}", e))?;
    let geosite_len = download_https_asset(GEOSITE_URL, &geosite_path, user_agent)
        .map_err(|e| format!("geosite.dat: {}", e))?;
    Ok((geoip_len, geosite_len))
}
