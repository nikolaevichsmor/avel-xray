use base64::Engine;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GEO_BYTES: u64 = 32 * 1024 * 1024;
const MIN_GEO_BYTES: usize = 64 * 1024;
const GEOIP_URL: &str =
    "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geoip/geoip-lite.dat";
const GEOSITE_URL: &str =
    "https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/geosite/geosite.dat";

pub struct SubscriptionResponse {
    pub body: String,
    pub profile_title: Option<String>,
    pub update_interval_hours: Option<u32>,
    pub userinfo: Option<String>,
    pub via_proxy: bool,
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
                ("upload", Some(n)) => {
                    upload = n;
                    any = true;
                }
                ("download", Some(n)) => {
                    download = n;
                    any = true;
                }
                ("total", Some(n)) => {
                    total = n;
                    any = true;
                }
                ("expire", Some(n)) => {
                    expire = n;
                    any = true;
                }
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
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn read_trimmed_file(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let t = s.trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

fn linux_hwid_headers() -> [(&'static str, String); 4] {
    let mid = read_trimmed_file("/etc/machine-id")
        .or_else(|| read_trimmed_file("/var/lib/dbus/machine-id"))
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "linux-host".to_string());
    let mut hasher = Sha256::new();
    hasher.update(b"avel-hwid-v1:");
    hasher.update(mid.as_bytes());
    let hwid = hasher.finalize_hex()[..32].to_string();

    let os_ver = read_trimmed_file("/etc/os-release")
        .and_then(|txt| {
            txt.lines().find_map(|l| {
                l.strip_prefix("VERSION_ID=")
                    .map(|v| v.trim_matches('"').trim().to_string())
            })
        })
        .unwrap_or_else(|| "Linux".to_string());

    let model = read_trimmed_file("/sys/devices/virtual/dmi/id/product_name")
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "Linux-PC".to_string());
    let clean_model: String = model
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(48)
        .collect();

    [
        ("x-hwid", hwid),
        ("x-device-os", "Linux".to_string()),
        ("x-ver-os", os_ver),
        ("x-device-model", clean_model.trim().to_string()),
    ]
}

fn build_agent(user_agent: &str, timeout: Duration, proxy_port: Option<u16>) -> Result<ureq::Agent, String> {
    let ua = if user_agent.trim().is_empty() {
        "Avel/1.0 (Linux; okhttp)"
    } else {
        user_agent.trim()
    };
    let mut builder = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .user_agent(ua)
        .http_status_as_error(false);
    if let Some(port) = proxy_port {
        let proxy = ureq::Proxy::new(&format!("http://127.0.0.1:{}", port))
            .map_err(|e| format!("Invalid proxy config: {}", e))?;
        builder = builder.proxy(Some(proxy));
    }
    Ok(builder.build().into())
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
    let agent = build_agent(user_agent, Duration::from_secs(15), proxy_port)?;
    let mut req = agent.get(trimmed);
    if send_hwid {
        for (k, v) in linux_hwid_headers() {
            req = req.header(k, &v);
        }
    }
    let mut resp = req
        .call()
        .map_err(|e| format!("Network request failed: {}", e))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("Subscription server returned HTTP {}", status));
    }

    let get_hdr = |name: &str| -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let profile_title = get_hdr("profile-title").map(|s| decode_profile_title(&s));
    let update_interval_hours = get_hdr("profile-update-interval")
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&h| h > 0)
        .map(|h| h.clamp(1, 720));
    let userinfo = get_hdr("subscription-userinfo").and_then(|s| format_subscription_userinfo(&s));

    let body = resp
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_string()
        .map_err(|e| format!("Failed to read subscription response: {}", e))?;

    Ok(SubscriptionResponse {
        body,
        profile_title,
        update_interval_hours,
        userinfo,
        via_proxy: proxy_port.is_some(),
    })
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

fn probe_once(agent: &ureq::Agent) -> Option<u32> {
    let start = Instant::now();
    let mut resp = agent
        .get("https://www.gstatic.com/generate_204")
        .call()
        .ok()?;
    let status = resp.status().as_u16();
    let _ = resp.body_mut().with_config().limit(8192).read_to_vec();
    if status == 204 || status == 200 {
        Some((start.elapsed().as_millis() as u32).max(1))
    } else {
        None
    }
}

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
    let Ok(agent) = build_agent("Avel/1.0", Duration::from_millis(3200), Some(http_port)) else {
        return 0;
    };
    let Some(t1) = probe_once(&agent) else {
        return 0;
    };
    if cancel.load(Ordering::Relaxed) {
        return 0;
    }
    match probe_once(&agent) {
        Some(t2) => t2.min(t1),
        None => t1,
    }
}

fn download_https_asset(
    url: &str,
    dest: &Path,
    user_agent: &str,
    min_bytes: usize,
    max_bytes: u64,
) -> Result<usize, String> {
    if !url.starts_with("https://") {
        return Err("Asset URL must use HTTPS".to_string());
    }
    let agent = build_agent(user_agent, Duration::from_secs(45), None)?;
    let mut resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("Download error: {}", e))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("Server returned HTTP {}", status));
    }
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(max_bytes)
        .read_to_vec()
        .map_err(|e| format!("Read error: {}", e))?;
    if bytes.len() < min_bytes {
        return Err(format!("Downloaded file too small ({} bytes)", bytes.len()));
    }
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = dest.with_extension("dat.tmp");
    {
        let f = File::create(&tmp).map_err(|e| format!("Create temp file failed: {}", e))?;
        let mut w = BufWriter::new(f);
        w.write_all(&bytes).map_err(|e| format!("Write failed: {}", e))?;
        w.flush().map_err(|e| format!("Flush failed: {}", e))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("Failed to replace {}: {}", dest.display(), e)
    })?;
    Ok(bytes.len())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile_title_and_userinfo_headers() {
        assert_eq!(decode_profile_title("base64:TXkgVlBO"), "My VPN");
        assert_eq!(decode_profile_title("PlainTitle"), "PlainTitle");
        let ui = format_subscription_userinfo(
            "upload=1073741824; download=2147483648; total=107374182400; expire=0",
        )
        .unwrap();
        assert_eq!(ui, "3.0 GB / 100 GB");
    }
}
