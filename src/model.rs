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
    pub fn display_row(&self) -> String {
        let ping = match self.ping_ms {
            Some(0) => "timeout".to_string(),
            Some(ms) => format!("{} ms", ms),
            None => "-".to_string(),
        };
        let proto_tag = match self.protocol.as_str() {
            "shadowsocks" => {
                let m = if self.ss_method.is_empty() { "ss" } else { &self.ss_method };
                format!("ss/{}", m)
            }
            "trojan" => {
                let sec = if self.security == "reality" { "reality" } else { "tls" };
                format!("trojan/{}", sec)
            }
            _ => {
                let sec = match self.security.as_str() {
                    "reality" => "reality",
                    "tls" => "tls",
                    _ => "none",
                };
                format!("{}/{}", self.network, sec)
            }
        };
        format!(
            "{}  [{}:{}, {}]  [{}]",
            self.name, self.address, self.port, proto_tag, ping
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    #[serde(default)]
    pub subscription_url: String,
    #[serde(default)]
    pub subscription_info: String,
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
        }
    }
}

fn has_core_binary(dir: &std::path::Path) -> bool {
    let c = dir.join("core");
    c.join("avel-core.exe").exists() || c.join("xray.exe").exists()
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
            return dir.to_path_buf();
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

// Use core/avel-core.exe (auto-renaming xray.exe if present) to avoid image-name collisions
// with other local Xray instances or services.
pub fn core_binary_path() -> Result<PathBuf, String> {
    let cdir = core_dir();
    let preferred = cdir.join("avel-core.exe");
    if preferred.exists() {
        return Ok(preferred);
    }
    let legacy = cdir.join("xray.exe");
    if legacy.exists() {
        if std::fs::rename(&legacy, &preferred).is_ok() {
            return Ok(preferred);
        }
        return Ok(legacy);
    }
    Err(format!("Not found: {} (or xray.exe)", preferred.display()))
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
                if st.selected_index >= st.nodes.len() && !st.nodes.is_empty() {
                    st.selected_index = 0;
                }
                return st;
            }
        }
        AppState::default()
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
