use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    SystemProxy,
    Tun,
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::SystemProxy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingPreset {
    #[serde(alias = "SubscriptionRules")]
    Global,
    DirectLanAndRu,
    Custom,
}

impl Default for RoutingPreset {
    fn default() -> Self {
        RoutingPreset::Global
    }
}

impl RoutingPreset {
    pub fn from_index(idx: i32) -> Self {
        match idx {
            1 => RoutingPreset::DirectLanAndRu,
            2 => RoutingPreset::Custom,
            _ => RoutingPreset::Global,
        }
    }

    pub fn to_index(self) -> i32 {
        match self {
            RoutingPreset::Global => 0,
            RoutingPreset::DirectLanAndRu => 1,
            RoutingPreset::Custom => 2,
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            RoutingPreset::Global => "Global",
            RoutingPreset::DirectLanAndRu => "LAN+RU",
            RoutingPreset::Custom => "Rules",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleMatchKind {
    Process,
    Domain,
    Ip,
}

impl RuleMatchKind {
    #[cfg(windows)]
    pub fn from_index(idx: i32) -> Self {
        match idx {
            1 => RuleMatchKind::Domain,
            2 => RuleMatchKind::Ip,
            _ => RuleMatchKind::Process,
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            RuleMatchKind::Process => "PROC  ",
            RuleMatchKind::Domain => "DOMAIN",
            RuleMatchKind::Ip => "IP    ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDefaultAction {
    Proxy,
    Direct,
}

impl Default for RuleDefaultAction {
    fn default() -> Self {
        RuleDefaultAction::Proxy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrayLogLevel {
    Warning,
    Info,
    Error,
    None,
}

impl Default for XrayLogLevel {
    fn default() -> Self {
        XrayLogLevel::Warning
    }
}

impl XrayLogLevel {
    pub fn from_index(idx: i32) -> Self {
        match idx {
            1 => XrayLogLevel::Info,
            2 => XrayLogLevel::Error,
            3 => XrayLogLevel::None,
            _ => XrayLogLevel::Warning,
        }
    }

    pub fn to_index(self) -> i32 {
        match self {
            XrayLogLevel::Warning => 0,
            XrayLogLevel::Info => 1,
            XrayLogLevel::Error => 2,
            XrayLogLevel::None => 3,
        }
    }

    pub fn as_xray_str(self) -> &'static str {
        match self {
            XrayLogLevel::Warning => "warning",
            XrayLogLevel::Info => "info",
            XrayLogLevel::Error => "error",
            XrayLogLevel::None => "none",
        }
    }

    pub fn emits_startup_line(self) -> bool {
        matches!(self, XrayLogLevel::Warning | XrayLogLevel::Info)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainStrategy {
    IpIfNonMatch,
    AsIs,
    IpOnDemand,
}

impl Default for DomainStrategy {
    fn default() -> Self {
        DomainStrategy::IpIfNonMatch
    }
}

impl DomainStrategy {
    pub fn from_index(idx: i32) -> Self {
        match idx {
            1 => DomainStrategy::AsIs,
            2 => DomainStrategy::IpOnDemand,
            _ => DomainStrategy::IpIfNonMatch,
        }
    }

    pub fn to_index(self) -> i32 {
        match self {
            DomainStrategy::IpIfNonMatch => 0,
            DomainStrategy::AsIs => 1,
            DomainStrategy::IpOnDemand => 2,
        }
    }

    pub fn as_xray_str(self) -> &'static str {
        match self {
            DomainStrategy::IpIfNonMatch => "IPIfNonMatch",
            DomainStrategy::AsIs => "AsIs",
            DomainStrategy::IpOnDemand => "IPOnDemand",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryProfile {
    LowRam,
    Performance,
}

impl Default for MemoryProfile {
    fn default() -> Self {
        MemoryProfile::LowRam
    }
}

impl MemoryProfile {
    pub fn from_index(idx: i32) -> Self {
        match idx {
            1 => MemoryProfile::Performance,
            _ => MemoryProfile::LowRam,
        }
    }

    pub fn to_index(self) -> i32 {
        match self {
            MemoryProfile::LowRam => 0,
            MemoryProfile::Performance => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub kind: RuleMatchKind,
    pub value: String,
    // "proxy", "direct", "block", or "node:<server_name>"
    pub target: String,
}

impl RoutingRule {
    pub fn display_target(&self) -> String {
        match self.target.as_str() {
            "proxy" => "Active Server".to_string(),
            "direct" => "Direct".to_string(),
            "block" => "Block".to_string(),
            other => {
                if let Some(name) = other.strip_prefix("node:") {
                    format!("Server: {}", name)
                } else {
                    other.to_string()
                }
            }
        }
    }

    pub fn display_row(&self) -> String {
        let state_tag = if self.enabled { "[ON ]" } else { "[OFF]" };
        let val = if self.value.chars().count() > 30 {
            let mut s: String = self.value.chars().take(27).collect();
            s.push_str("...");
            s
        } else {
            self.value.clone()
        };
        format!(
            "{}  {}  {:<30} -> {}",
            state_tag,
            self.kind.short_label(),
            val,
            self.display_target()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionProfile {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub update_interval_hours: u32,
    #[serde(default)]
    pub last_updated_unix: u64,
    #[serde(default)]
    pub userinfo: String,
}

impl SubscriptionProfile {
    pub fn display_label(&self) -> String {
        let base = if !self.name.trim().is_empty() {
            self.name.trim().to_string()
        } else {
            short_sub_host(&self.url)
        };
        if !self.userinfo.is_empty() {
            format!("{} ({})", base, self.userinfo)
        } else {
            base
        }
    }
}

pub fn short_sub_host(url: &str) -> String {
    let s = url.trim();
    let after = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let host = after.split('/').next().unwrap_or(s);
    if host.is_empty() {
        s.to_string()
    } else {
        host.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessNode {
    pub name: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub ss_method: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default = "default_encryption")]
    pub encryption: String,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub fp: String,
    #[serde(default)]
    pub pbk: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub spx: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub header_type: String,
    #[serde(default)]
    pub extra: String,
    #[serde(default)]
    pub obfs: String,
    #[serde(default)]
    pub obfs_password: String,
    #[serde(default)]
    pub wg_address: String,
    #[serde(default)]
    pub wg_reserved: String,
    #[serde(default)]
    pub wg_mtu: u16,
    #[serde(default)]
    pub proxy_user: String,
    #[serde(default)]
    pub source_sub_id: Option<String>,
    #[serde(default)]
    pub raw_uri: String,
    #[serde(skip)]
    pub ping_ms: Option<u32>,
}

fn default_protocol() -> String {
    "vless".to_string()
}
fn default_encryption() -> String {
    "none".to_string()
}
fn default_security() -> String {
    "none".to_string()
}
fn default_network() -> String {
    "tcp".to_string()
}

impl VlessNode {
    pub fn protocol_tag(&self) -> String {
        match self.protocol.as_str() {
            "shadowsocks" => {
                let m = if self.ss_method.is_empty() { "ss" } else { &self.ss_method };
                format!("ss/{}", m)
            }
            "trojan" => {
                let sec = if self.security == "reality" { "reality" } else { "tls" };
                format!("trojan/{}", sec)
            }
            "vmess" => {
                let net = if self.network.is_empty() { "tcp" } else { &self.network };
                if self.security == "tls" {
                    format!("vmess/{}", net)
                } else {
                    format!("vmess/{}", net)
                }
            }
            "hysteria" => "hysteria2".to_string(),
            "wireguard" => "wireguard".to_string(),
            "socks" => "socks5".to_string(),
            "http" => "http".to_string(),
            _ => {
                let sec = match self.security.as_str() {
                    "reality" => "reality",
                    "tls" => "tls",
                    _ => "none",
                };
                format!("{}/{}", self.network, sec)
            }
        }
    }

    #[cfg(windows)]
    pub fn to_share_uri(&self) -> String {
        let raw = self.raw_uri.trim();
        if !raw.is_empty() && !raw.starts_with("vmess://") {
            let base = match raw.find('#') {
                Some(pos) => &raw[..pos],
                None => raw,
            };
            return format!("{}#{}", base, percent_encode_fragment(&self.name));
        }
        let host = if self.address.contains(':') {
            format!("[{}]", self.address)
        } else {
            self.address.clone()
        };
        let frag = percent_encode_fragment(&self.name);
        match self.protocol.as_str() {
            "vmess" => {
                use base64::Engine;
                let obj = serde_json::json!({
                    "v": "2",
                    "ps": self.name,
                    "add": self.address,
                    "port": self.port.to_string(),
                    "id": self.uuid,
                    "aid": "0",
                    "scy": if self.encryption.is_empty() { "auto" } else { &self.encryption },
                    "net": if self.network.is_empty() { "tcp" } else { &self.network },
                    "type": if self.header_type.is_empty() { "none" } else { &self.header_type },
                    "host": self.host,
                    "path": if self.network == "grpc" && !self.service_name.is_empty() { &self.service_name } else { &self.path },
                    "tls": if self.security == "tls" { "tls" } else { "" },
                    "sni": self.sni,
                    "alpn": self.alpn,
                    "fp": self.fp,
                });
                let b64 = base64::engine::general_purpose::STANDARD.encode(obj.to_string().as_bytes());
                format!("vmess://{}", b64)
            }
            "shadowsocks" => {
                use base64::Engine;
                let method = if self.ss_method.is_empty() {
                    "aes-128-gcm"
                } else {
                    &self.ss_method
                };
                let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(format!("{}:{}", method, self.uuid).as_bytes());
                format!("ss://{}@{}:{}#{}", userinfo, host, self.port, frag)
            }
            "trojan" => format!(
                "trojan://{}@{}:{}?security={}&sni={}#{}",
                self.uuid, host, self.port, self.security, self.sni, frag
            ),
            "hysteria" => format!(
                "hy2://{}@{}:{}?sni={}#{}",
                self.uuid, host, self.port, self.sni, frag
            ),
            "wireguard" => format!(
                "wireguard://{}@{}:{}?publickey={}&address={}#{}",
                self.uuid, host, self.port, self.pbk, self.wg_address, frag
            ),
            "socks" => {
                if self.proxy_user.is_empty() {
                    format!("socks5://{}:{}#{}", host, self.port, frag)
                } else {
                    format!(
                        "socks5://{}:{}@{}:{}#{}",
                        self.proxy_user, self.uuid, host, self.port, frag
                    )
                }
            }
            "http" => {
                if self.proxy_user.is_empty() {
                    format!("http://{}:{}#{}", host, self.port, frag)
                } else {
                    format!(
                        "http://{}:{}@{}:{}#{}",
                        self.proxy_user, self.uuid, host, self.port, frag
                    )
                }
            }
            _ => format!(
                "vless://{}@{}:{}?encryption={}&security={}&type={}&sni={}#{}",
                self.uuid, host, self.port, self.encryption, self.security, self.network, self.sni, frag
            ),
        }
    }

    pub fn identity_key(&self) -> (String, String, String, u16, String, String, String, String) {
        (
            self.protocol.clone(),
            self.uuid.clone(),
            self.address.clone(),
            self.port,
            self.network.clone(),
            self.sni.clone(),
            self.path.clone(),
            self.service_name.clone(),
        )
    }

    #[cfg(windows)]
    pub fn display_row(&self) -> String {
        let ping = match self.ping_ms {
            Some(0) => "timeout".to_string(),
            Some(ms) => format!("{} ms", ms),
            None => "-".to_string(),
        };
        format!("{}  {}  {}  {}", self.name, self.address, self.protocol_tag(), ping)
    }
}

#[cfg(windows)]
fn percent_encode_fragment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    #[serde(default)]
    pub subscription_url: String,
    #[serde(default)]
    pub subscription_info: String,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionProfile>,
    #[serde(default)]
    pub nodes: Vec<VlessNode>,
    #[serde(default)]
    pub selected_index: usize,
    #[serde(default)]
    pub mode: ProxyMode,
    #[serde(default)]
    pub routing: RoutingPreset,
    #[serde(default = "default_true")]
    pub reconnect_after_sleep: bool,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub custom_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub custom_default_action: RuleDefaultAction,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
    #[serde(default = "default_true")]
    pub block_quic: bool,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "default_remote_dns")]
    pub remote_dns: String,
    #[serde(default)]
    pub log_level: XrayLogLevel,
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    #[serde(default)]
    pub memory_profile: MemoryProfile,
    #[serde(default)]
    pub auto_connect_on_launch: bool,
    #[serde(default)]
    pub start_minimized: bool,
    #[serde(default)]
    pub enable_fragment: bool,
    #[serde(default)]
    pub enable_noise: bool,
    #[serde(default)]
    pub enable_mux: bool,
    #[serde(default)]
    pub send_hwid: bool,
    #[serde(default)]
    pub last_update_check_unix: u64,
    #[serde(default = "default_true")]
    pub enable_sniffing: bool,
    #[serde(default = "default_true")]
    pub sniffing_dest_override: bool,
}

fn default_true() -> bool {
    true
}
fn default_socks_port() -> u16 {
    10808
}
fn default_http_port() -> u16 {
    10809
}
fn default_tun_mtu() -> u16 {
    1500
}
pub fn default_remote_dns() -> String {
    "https://1.1.1.1/dns-query".to_string()
}
pub fn default_user_agent() -> String {
    "Avel/1.0 (Windows; okhttp)".to_string()
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            subscription_url: String::new(),
            subscription_info: String::new(),
            subscriptions: Vec::new(),
            nodes: Vec::new(),
            selected_index: 0,
            mode: ProxyMode::SystemProxy,
            routing: RoutingPreset::Global,
            reconnect_after_sleep: true,
            kill_switch: false,
            custom_rules: Vec::new(),
            custom_default_action: RuleDefaultAction::Proxy,
            socks_port: 10808,
            http_port: 10809,
            user_agent: default_user_agent(),
            tun_mtu: default_tun_mtu(),
            block_quic: true,
            allow_lan: false,
            remote_dns: default_remote_dns(),
            log_level: XrayLogLevel::Warning,
            domain_strategy: DomainStrategy::IpIfNonMatch,
            memory_profile: MemoryProfile::LowRam,
            auto_connect_on_launch: false,
            start_minimized: false,
            enable_fragment: false,
            enable_noise: false,
            enable_mux: false,
            send_hwid: false,
            last_update_check_unix: 0,
            enable_sniffing: true,
            sniffing_dest_override: true,
        }
    }
}

fn has_core_binary(dir: &std::path::Path) -> bool {
    let c = dir.join("core");
    #[cfg(windows)]
    {
        c.join("avel-core.exe").exists() || c.join("xray.exe").exists()
    }
    #[cfg(not(windows))]
    {
        c.join("avel-core").exists() || c.join("xray").exists()
    }
}

pub fn app_base_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if has_core_binary(dir) {
                return dir.to_path_buf();
            }
            if let Some(p2) = dir.parent().and_then(|p| p.parent()) {
                if has_core_binary(p2) {
                    return p2.to_path_buf();
                }
            }
            if let Ok(cwd) = std::env::current_dir() {
                if has_core_binary(&cwd) {
                    return cwd;
                }
            }
            #[cfg(windows)]
            {
                return dir.to_path_buf();
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            let t = xdg.trim();
            if !t.is_empty() {
                let d = PathBuf::from(t).join("avel-xray");
                let _ = std::fs::create_dir_all(&d);
                return d;
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let t = home.trim();
            if !t.is_empty() {
                let d = PathBuf::from(t).join(".config").join("avel-xray");
                let _ = std::fs::create_dir_all(&d);
                return d;
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn state_path() -> PathBuf {
    app_base_dir().join("state.json")
}

pub fn custom_routing_path() -> PathBuf {
    app_base_dir().join("routing_custom.txt")
}

pub fn core_dir() -> PathBuf {
    app_base_dir().join("core")
}

// Use core/avel-core[.exe] (auto-renaming xray[.exe] if present) to avoid image-name collisions
// with other local Xray instances or services.
pub fn core_binary_path() -> Result<PathBuf, String> {
    let cdir = core_dir();
    #[cfg(windows)]
    let (pref_name, legacy_name) = ("avel-core.exe", "xray.exe");
    #[cfg(not(windows))]
    let (pref_name, legacy_name) = ("avel-core", "xray");

    let preferred = cdir.join(pref_name);
    if preferred.exists() {
        return Ok(preferred);
    }
    let legacy = cdir.join(legacy_name);
    if legacy.exists() {
        if std::fs::rename(&legacy, &preferred).is_ok() {
            return Ok(preferred);
        }
        return Ok(legacy);
    }
    #[cfg(not(windows))]
    {
        for sys_path in ["/usr/local/bin/avel-core", "/usr/local/bin/xray", "/usr/bin/xray"] {
            let p = PathBuf::from(sys_path);
            if p.exists() {
                return Ok(p);
            }
        }
    }
    Err(format!("Not found: {} (or {})", preferred.display(), legacy_name))
}

pub fn runtime_config_path() -> PathBuf {
    core_dir().join("runtime_config.json")
}

impl AppState {
    pub fn load() -> Self {
        let p = state_path();
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Ok(mut st) = serde_json::from_str::<AppState>(&text) {
                if st.socks_port == 0 {
                    st.socks_port = 10808;
                }
                if st.http_port == 0 || st.http_port == st.socks_port {
                    st.http_port = if st.socks_port == 10809 { 10810 } else { 10809 };
                }
                st.tun_mtu = if st.tun_mtu == 0 {
                    1500
                } else {
                    st.tun_mtu.clamp(1280, 9000)
                };
                if st.remote_dns.trim().is_empty() {
                    st.remote_dns = default_remote_dns();
                }
                if st.user_agent.trim().is_empty() {
                    st.user_agent = default_user_agent();
                }
                // Migrate legacy single subscription_url into multi-subscription list seamlessly.
                let sub_trim = st.subscription_url.trim().to_string();
                if st.subscriptions.is_empty()
                    && (sub_trim.starts_with("https://") || sub_trim.starts_with("http://"))
                {
                    let sub_id = "sub-1".to_string();
                    st.subscriptions.push(SubscriptionProfile {
                        id: sub_id.clone(),
                        name: short_sub_host(&sub_trim),
                        url: sub_trim,
                        update_interval_hours: 0,
                        last_updated_unix: 0,
                        userinfo: st.subscription_info.clone(),
                    });
                    for n in &mut st.nodes {
                        if n.source_sub_id.is_none() {
                            n.source_sub_id = Some(sub_id.clone());
                        }
                    }
                }
                if st.selected_index >= st.nodes.len() && !st.nodes.is_empty() {
                    st.selected_index = 0;
                }
                return st;
            }
        }
        AppState::default()
    }

    pub fn next_subscription_id(&self) -> String {
        let mut n = self.subscriptions.len() + 1;
        loop {
            let cand = format!("sub-{}", n);
            if !self.subscriptions.iter().any(|s| s.id == cand) {
                return cand;
            }
            n += 1;
        }
    }

    pub fn reset_settings_to_defaults(&mut self) {
        self.tun_mtu = default_tun_mtu();
        self.block_quic = true;
        self.allow_lan = false;
        self.socks_port = default_socks_port();
        self.http_port = default_http_port();
        self.remote_dns = default_remote_dns();
        self.log_level = XrayLogLevel::Warning;
        self.domain_strategy = DomainStrategy::IpIfNonMatch;
        self.memory_profile = MemoryProfile::LowRam;
        self.user_agent = default_user_agent();
        self.auto_connect_on_launch = false;
        self.start_minimized = false;
        self.enable_fragment = false;
        self.enable_noise = false;
        self.enable_mux = false;
        self.send_hwid = false;
        self.enable_sniffing = true;
        self.sniffing_dest_override = true;
    }

    pub fn save(&self) -> Result<(), String> {
        let p = state_path();
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(|e| e.to_string())?;
        if std::fs::rename(&tmp, &p).is_err() {
            let _ = std::fs::remove_file(&tmp);
            std::fs::write(&p, &json).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

pub fn ensure_default_custom_routing() {
    let p = custom_routing_path();
    if !p.exists() {
        let sample = "\
# Custom Xray routing rules
# Format: ACTION:RULE   (ACTION = direct | proxy | block)
# Examples:
#   direct:geoip:private
#   direct:domain:example.com
#   proxy:geosite:geolocation-!cn
#   block:geosite:category-ads-all

direct:geoip:private
";
        let _ = std::fs::write(&p, sample);
    }
}
