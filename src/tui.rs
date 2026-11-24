use crate::http_unix::{fetch_subscription_opts, update_geo_databases, SubscriptionResponse};
use crate::model::{
    core_dir, default_user_agent, ensure_default_custom_routing, short_sub_host, AppState,
    DomainStrategy, MemoryProfile, ProxyMode, RoutingPreset, RoutingRule, RuleDefaultAction,
    RuleMatchKind, SubscriptionProfile, VlessNode, XrayLogLevel,
};
use crate::ping_unix::{
    extract_ping_targets, ping_all_async, query_tun_octets, real_ping_all_async,
};
use crate::vless::{is_proxy_link_text, parse_subscription_body};
use crate::xray_config::{
    build_xray_config_for, validate_remote_dns, OutboundOpts, TargetPlatform,
};
use crate::xray_proc_unix::{
    has_active_systemd_resolved, is_root, XrayRunner, XrayStartOpts,
};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    Tabs, Wrap,
};
use ratatui::Frame;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

static CLI_STOP_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_cli_signal(_sig: libc::c_int) {
    CLI_STOP_FLAG.store(true, Ordering::Relaxed);
}

pub fn run_entry() {
    ensure_default_custom_routing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "tui" {
        if let Err(e) = run_tui() {
            eprintln!("TUI error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => print_help(),
        "-V" | "--version" | "version" => {
            println!("avel-xray v{} (linux)", APP_VERSION);
        }
        "list" | "ls" => cli_list(),
        "sub" => cli_sub(&args[1..]),
        "import" => cli_import(&args[1..]),
        "ping" => cli_ping(&args[1..]),
        "connect" => cli_connect(&args[1..]),
        "geo" => cli_geo(&args[1..]),
        other => {
            eprintln!("Unknown command: '{}'. Run 'avel --help' for usage.", other);
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "\
avel-xray v{} (Linux TUI & CLI for Xray-core)

USAGE:
  avel                                Launch interactive Terminal UI
  avel tui                            Launch interactive Terminal UI
  avel list                           List saved servers
  avel sub list                       List saved subscriptions
  avel sub add <url>                  Add and fetch a subscription URL
  avel sub update                     Update all saved subscriptions
  avel sub del <id|index>             Delete a subscription and its servers
  avel import <uri-or-file>           Import proxy link(s) without overwriting
  avel ping [--real]                  Run TCP Ping (or Real Ping via Xray)
  avel connect [idx|name] [options]   Connect in foreground (Ctrl+C to stop)
    --proxy                           Use local SOCKS/HTTP proxy mode
    --tun                             Use Linux TUN mode (requires root/sudo)
    --routing <global|ru|rules>       Select routing preset
  avel geo update                     Download geoip.dat and geosite.dat
  avel --version                      Print version",
        APP_VERSION
    );
}

fn cli_list() {
    let st = AppState::load();
    if st.nodes.is_empty() {
        println!("No servers loaded. Use 'avel sub add <url>' or 'avel import <uri>'.");
        return;
    }
    println!("{:<4} {:<24} {:<30} {:<14} {}", "#", "Name", "Host", "Protocol", "Ping");
    for (i, n) in st.nodes.iter().enumerate() {
        let ping = match n.ping_ms {
            Some(0) => "timeout".to_string(),
            Some(ms) => format!("{} ms", ms),
            None => "-".to_string(),
        };
        let mark = if i == st.selected_index { "*" } else { " " };
        println!(
            "{}{:<3} {:<24} {:<30} {:<14} {}",
            mark,
            i + 1,
            truncate_str(&n.name, 23),
            truncate_str(&n.address, 29),
            n.protocol_tag(),
            ping
        );
    }
}

fn cli_sub(args: &[String]) {
    let mut st = AppState::load();
    match args.first().map(|s| s.as_str()) {
        Some("list") | None => {
            if st.subscriptions.is_empty() {
                println!("No saved subscriptions.");
                return;
            }
            for (i, s) in st.subscriptions.iter().enumerate() {
                println!(
                    "{}. [{}] {} ({})",
                    i + 1,
                    s.id,
                    sub_label(s),
                    s.url
                );
            }
        }
        Some("add") => {
            let Some(url) = args.get(1) else {
                eprintln!("Usage: avel sub add <https://...>");
                std::process::exit(2);
            };
            let sub_id = st
                .subscriptions
                .iter()
                .find(|s| s.url == *url)
                .map(|s| s.id.clone())
                .unwrap_or_else(|| st.next_subscription_id());
            println!("Fetching {}...", short_sub_host(url));
            match fetch_subscription_opts(url, &st.user_agent, st.send_hwid, None) {
                Ok(resp) => match parse_subscription_body(&resp.body) {
                    Ok(nodes) if !nodes.is_empty() => {
                        let cnt = nodes.len();
                        merge_sub_nodes(&mut st, &sub_id, url, nodes, &resp);
                        let _ = st.save();
                        println!("Updated '{}': {} server(s).", short_sub_host(url), cnt);
                    }
                    Ok(_) => {
                        eprintln!("No supported proxy links found in subscription.");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Fetch error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some("update") => {
            if st.subscriptions.is_empty() {
                println!("No saved subscriptions to update.");
                return;
            }
            let subs = st.subscriptions.clone();
            for s in subs {
                println!("Updating {}...", short_sub_host(&s.url));
                match fetch_subscription_opts(&s.url, &st.user_agent, st.send_hwid, None) {
                    Ok(resp) => match parse_subscription_body(&resp.body) {
                        Ok(nodes) if !nodes.is_empty() => {
                            let cnt = nodes.len();
                            merge_sub_nodes(&mut st, &s.id, &s.url, nodes, &resp);
                            println!("  OK: {} server(s).", cnt);
                        }
                        Ok(_) => eprintln!("  Empty subscription response."),
                        Err(e) => eprintln!("  Parse error: {}", e),
                    },
                    Err(e) => eprintln!("  Fetch error: {}", e),
                }
            }
            let _ = st.save();
        }
        Some("del") => {
            let Some(key) = args.get(1) else {
                eprintln!("Usage: avel sub del <id|index>");
                std::process::exit(2);
            };
            let target = if let Ok(idx) = key.parse::<usize>() {
                idx.checked_sub(1).and_then(|i| st.subscriptions.get(i)).cloned()
            } else {
                st.subscriptions.iter().find(|s| s.id == *key).cloned()
            };
            let Some(sub) = target else {
                eprintln!("Subscription '{}' not found.", key);
                std::process::exit(1);
            };
            st.subscriptions.retain(|s| s.id != sub.id);
            st.nodes
                .retain(|n| n.source_sub_id.as_deref() != Some(sub.id.as_str()));
            st.subscription_url = st
                .subscriptions
                .first()
                .map(|s| s.url.clone())
                .unwrap_or_default();
            let _ = st.save();
            println!("Deleted subscription '{}' ({}).", sub.id, short_sub_host(&sub.url));
        }
        Some(other) => {
            eprintln!("Unknown subcommand 'sub {}'.", other);
            std::process::exit(2);
        }
    }
}

fn cli_import(args: &[String]) {
    let Some(arg) = args.first() else {
        eprintln!("Usage: avel import <proxy-uri-or-file>");
        std::process::exit(2);
    };
    let text = if std::path::Path::new(arg).exists() {
        match std::fs::read_to_string(arg) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Failed to read {}: {}", arg, e);
                std::process::exit(1);
            }
        }
    } else {
        args.join("\n")
    };
    let mut st = AppState::load();
    match import_manual_links(&mut st, &text) {
        Ok((added, skipped)) => {
            let _ = st.save();
            println!("Imported {} server(s) ({} duplicate skipped).", added, skipped);
        }
        Err(e) => {
            eprintln!("Import failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cli_ping(args: &[String]) {
    let real = args.iter().any(|a| a == "--real" || a == "-r");
    let st = AppState::load();
    if st.nodes.is_empty() {
        println!("No servers to ping.");
        return;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Option<(usize, u32)>>();
    let names: Vec<String> = st.nodes.iter().map(|n| n.name.clone()).collect();
    if real {
        println!("Running Real Ping (HTTPS /generate_204) on {} server(s)...", st.nodes.len());
        let items: Vec<(usize, VlessNode)> = st.nodes.iter().cloned().enumerate().collect();
        let opts = OutboundOpts {
            fragment: st.enable_fragment,
            noise: st.enable_noise,
            mux: st.enable_mux,
        };
        let tx_res = tx.clone();
        let tx_done = tx;
        real_ping_all_async(
            items,
            false,
            opts,
            cancel,
            move |idx, ms| {
                let _ = tx_res.send(Some((idx, ms)));
            },
            move |err| eprintln!("Error: {}", err),
            move || {
                let _ = tx_done.send(None);
            },
        );
    } else {
        println!("Running TCP Ping on {} server(s)...", st.nodes.len());
        let targets = extract_ping_targets(&st.nodes);
        let tx_res = tx.clone();
        let tx_done = tx;
        ping_all_async(
            targets,
            false,
            cancel,
            move |idx, ms| {
                let _ = tx_res.send(Some((idx, ms)));
            },
            move || {
                let _ = tx_done.send(None);
            },
        );
    }

    while let Ok(item) = rx.recv() {
        match item {
            Some((idx, ms)) => {
                let name = names.get(idx).map(|s| s.as_str()).unwrap_or("?");
                if ms == 0 {
                    println!("  {:<24} timeout", name);
                } else {
                    println!("  {:<24} {} ms", name, ms);
                }
            }
            None => break,
        }
    }
}

fn cli_geo(args: &[String]) {
    if args.first().map(|s| s.as_str()) != Some("update") {
        eprintln!("Usage: avel geo update");
        std::process::exit(2);
    }
    let st = AppState::load();
    println!("Downloading geoip.dat and geosite.dat...");
    match update_geo_databases(&core_dir(), &st.user_agent) {
        Ok((ip_sz, site_sz)) => {
            println!(
                "Updated: geoip.dat ({}), geosite.dat ({}).",
                fmt_bytes(ip_sz as u64),
                fmt_bytes(site_sz as u64)
            );
        }
        Err(e) => {
            eprintln!("Geo update failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cli_connect(args: &[String]) {
    let mut st = AppState::load();
    if st.nodes.is_empty() {
        eprintln!("No servers available. Add a subscription or import a link first.");
        std::process::exit(1);
    }
    let mut target_sel: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--tun" => st.mode = ProxyMode::Tun,
            "--proxy" => st.mode = ProxyMode::SystemProxy,
            "--routing" => {
                if let Some(val) = args.get(i + 1) {
                    st.routing = match val.to_lowercase().as_str() {
                        "ru" | "lan+ru" => RoutingPreset::DirectLanAndRu,
                        "rules" | "custom" => RoutingPreset::Custom,
                        _ => RoutingPreset::Global,
                    };
                    i += 1;
                }
            }
            other if !other.starts_with('-') => target_sel = Some(other.to_string()),
            _ => {}
        }
        i += 1;
    }

    if let Some(sel) = target_sel {
        if let Ok(num) = sel.parse::<usize>() {
            if num >= 1 && num <= st.nodes.len() {
                st.selected_index = num - 1;
            } else {
                eprintln!("Server index {} out of range (1..={}).", num, st.nodes.len());
                std::process::exit(1);
            }
        } else if let Some(pos) = st
            .nodes
            .iter()
            .position(|n| n.name.to_lowercase().contains(&sel.to_lowercase()))
        {
            st.selected_index = pos;
        } else {
            eprintln!("No server matching '{}'.", sel);
            std::process::exit(1);
        }
    }

    if st.mode == ProxyMode::Tun && !is_root() {
        eprintln!("TUN mode on Linux requires root privileges (run with sudo or use --proxy).");
        std::process::exit(1);
    }

    let node = st.nodes[st.selected_index].clone();
    let linux_auto_dns = st.mode == ProxyMode::Tun && has_active_systemd_resolved();
    let cfg = match build_xray_config_for(&st, &node, TargetPlatform::Linux, linux_auto_dns) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {}", e);
            std::process::exit(1);
        }
    };

    CLI_STOP_FLAG.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGINT, handle_cli_signal as *const () as usize);
        libc::signal(libc::SIGTERM, handle_cli_signal as *const () as usize);
    }

    let (log_tx, log_rx) = mpsc::channel::<String>();
    let exited_flag = Arc::new(AtomicBool::new(false));
    let exited_cb = exited_flag.clone();
    let mut runner = XrayRunner::new();
    match runner.start(
        &cfg,
        XrayStartOpts {
            memory_profile: st.memory_profile,
            expect_startup_log: st.log_level.emits_startup_line(),
            ready_port: st.socks_port,
            is_tun: st.mode == ProxyMode::Tun,
        },
        log_tx,
        move |_| {
            exited_cb.store(true, Ordering::Relaxed);
        },
    ) {
        Ok(_pid) => {
            let _ = st.save();
            if st.mode == ProxyMode::Tun {
                println!(
                    "Connected: {} [{}:{}] (TUN avel0, {}, auto-DNS={}). Press Ctrl+C to disconnect.",
                    node.name,
                    node.address,
                    node.port,
                    st.routing.short_label(),
                    if linux_auto_dns { "systemd-resolved" } else { "manual" }
                );
            } else {
                println!(
                    "Connected: {} [{}:{}] (SOCKS 127.0.0.1:{} / HTTP 127.0.0.1:{}, {}). Press Ctrl+C to disconnect.",
                    node.name,
                    node.address,
                    node.port,
                    st.socks_port,
                    st.http_port,
                    st.routing.short_label()
                );
            }
            while !CLI_STOP_FLAG.load(Ordering::Relaxed) && !exited_flag.load(Ordering::Relaxed) {
                while let Ok(line) = log_rx.try_recv() {
                    println!("{}", line);
                }
                std::thread::sleep(Duration::from_millis(120));
            }
            runner.stop();
            if exited_flag.load(Ordering::Relaxed) && !CLI_STOP_FLAG.load(Ordering::Relaxed) {
                eprintln!("avel-core exited unexpectedly.");
                std::process::exit(1);
            }
            println!("Disconnected.");
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

// ---------- Interactive Terminal UI (Ratatui + Crossterm) ----------

struct SubFetchOutcome {
    nodes: Vec<VlessNode>,
    resp: SubscriptionResponse,
}

enum TuiEvent {
    LogLine(String),
    SubFetched {
        sub_id: String,
        url: String,
        silent: bool,
        res: Result<SubFetchOutcome, String>,
    },
    PingResult(u32, usize, u32),
    PingFinished(u32),
    RealPingResult(u32, usize, u32),
    RealPingError(u32, String),
    RealPingFinished(u32),
    GeoUpdated(Result<(usize, usize), String>),
    XrayExited(u32),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModalKind {
    AddSubOrLink,
    RenameServer(usize),
    AddRule,
    EditSetting(usize),
}

struct InputModal {
    kind: ModalKind,
    title: String,
    hint: String,
    value: String,
}

struct TuiApp {
    state: AppState,
    runner: XrayRunner,
    connected: bool,
    connected_node_key: Option<(String, String, String, u16, String, String, String, String)>,
    active_tab: usize,
    active_sub_id: Option<String>,
    sub_fetching: bool,
    sub_retry_after: HashMap<String, u64>,
    tcp_ping_cancel: Option<Arc<AtomicBool>>,
    ping_gen: u32,
    real_ping_cancel: Option<Arc<AtomicBool>>,
    real_ping_gen: u32,
    geo_updating: bool,
    stats_base: Option<(u64, u64)>,
    stats_prev: Option<(u64, u64)>,
    last_traffic: Option<String>,
    last_stats_tick: Instant,
    last_sub_check: Instant,
    node_table_state: TableState,
    rule_list_state: ListState,
    settings_table_state: TableState,
    logs: VecDeque<String>,
    modal: Option<InputModal>,
    ev_tx: Sender<TuiEvent>,
    ev_rx: Receiver<TuiEvent>,
    should_quit: bool,
}

const SETTINGS_COUNT: usize = 18;

impl TuiApp {
    fn new() -> Self {
        let mut state = AppState::load();
        if !is_root() && state.mode == ProxyMode::Tun {
            state.mode = ProxyMode::SystemProxy;
        }
        let active_sub_id = state.subscriptions.first().map(|s| s.id.clone());
        let mut node_table_state = TableState::default();
        if !state.nodes.is_empty() {
            node_table_state.select(Some(state.selected_index.min(state.nodes.len() - 1)));
        }
        let mut rule_list_state = ListState::default();
        if !state.custom_rules.is_empty() {
            rule_list_state.select(Some(0));
        }
        let mut settings_table_state = TableState::default();
        settings_table_state.select(Some(0));

        let (ev_tx, ev_rx) = mpsc::channel();
        let mut app = Self {
            state,
            runner: XrayRunner::new(),
            connected: false,
            connected_node_key: None,
            active_tab: 0,
            active_sub_id,
            sub_fetching: false,
            sub_retry_after: HashMap::new(),
            tcp_ping_cancel: None,
            ping_gen: 0,
            real_ping_cancel: None,
            real_ping_gen: 0,
            geo_updating: false,
            stats_base: None,
            stats_prev: None,
            last_traffic: None,
            last_stats_tick: Instant::now(),
            last_sub_check: Instant::now() - Duration::from_secs(292),
            node_table_state,
            rule_list_state,
            settings_table_state,
            logs: VecDeque::with_capacity(200),
            modal: None,
            ev_tx,
            ev_rx,
            should_quit: false,
        };
        app.log(&format!(
            "avel-xray v{} ready (root={}). Press [a] to add subscription/link, [Enter] to connect.",
            APP_VERSION,
            if is_root() { "yes" } else { "no" }
        ));
        if app.state.auto_connect_on_launch && !app.state.nodes.is_empty() {
            app.connect();
        }
        app
    }

    fn log(&mut self, msg: &str) {
        if self.logs.len() >= 180 {
            self.logs.pop_front();
        }
        self.logs.push_back(msg.to_string());
    }

    fn cancel_tcp_ping(&mut self) {
        if let Some(c) = self.tcp_ping_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.ping_gen = self.ping_gen.wrapping_add(1);
    }

    fn cancel_real_ping(&mut self) {
        if let Some(c) = self.real_ping_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.real_ping_gen = self.real_ping_gen.wrapping_add(1);
    }

    fn selected_node_idx(&self) -> Option<usize> {
        self.node_table_state
            .selected()
            .filter(|&i| i < self.state.nodes.len())
    }

    fn select_node(&mut self, idx: usize) {
        if self.state.nodes.is_empty() {
            self.node_table_state.select(None);
            self.state.selected_index = 0;
        } else {
            let clamped = idx.min(self.state.nodes.len() - 1);
            self.node_table_state.select(Some(clamped));
            self.state.selected_index = clamped;
        }
    }

    fn connect(&mut self) {
        if self.state.mode == ProxyMode::Tun && !is_root() {
            self.log("TUN mode requires root privileges. Run with sudo or press [m] for System Proxy.");
            return;
        }
        let Some(idx) = self.selected_node_idx() else {
            self.log("No server selected. Press [a] to add a subscription URL or proxy link.");
            return;
        };
        let node = self.state.nodes[idx].clone();
        if self.state.mode == ProxyMode::Tun && !self.state.enable_sniffing {
            let has_dom = self.state.routing == RoutingPreset::DirectLanAndRu
                || (self.state.routing == RoutingPreset::Custom
                    && self
                        .state
                        .custom_rules
                        .iter()
                        .any(|r| r.enabled && r.kind == RuleMatchKind::Domain));
            if has_dom {
                self.log("Warning: Sniffing is OFF; Domain/GeoSite rules will not match in TUN mode.");
            }
        }

        let linux_auto_dns = self.state.mode == ProxyMode::Tun && has_active_systemd_resolved();
        let cfg = match build_xray_config_for(
            &self.state,
            &node,
            TargetPlatform::Linux,
            linux_auto_dns,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.log(&format!("Config error: {}", e));
                return;
            }
        };

        let tx_log = self.ev_tx.clone();
        let tx_exit = self.ev_tx.clone();
        let (raw_tx, raw_rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in raw_rx {
                let _ = tx_log.send(TuiEvent::LogLine(line));
            }
        });

        match self.runner.start(
            &cfg,
            XrayStartOpts {
                memory_profile: self.state.memory_profile,
                expect_startup_log: self.state.log_level.emits_startup_line(),
                ready_port: self.state.socks_port,
                is_tun: self.state.mode == ProxyMode::Tun,
            },
            raw_tx,
            move |pid| {
                let _ = tx_exit.send(TuiEvent::XrayExited(pid));
            },
        ) {
            Ok(_) => {
                self.connected = true;
                self.connected_node_key = Some(node.identity_key());
                self.stats_base = None;
                self.stats_prev = None;
                self.last_traffic = None;
                let _ = self.state.save();
                if self.state.mode == ProxyMode::Tun {
                    self.stats_prev = query_tun_octets("avel0");
                    self.stats_base = self.stats_prev;
                    self.log(&format!(
                        "Connected: {} [{}:{}] (TUN avel0, {}, auto-DNS={})",
                        node.name,
                        node.address,
                        node.port,
                        self.state.routing.short_label(),
                        if linux_auto_dns { "systemd-resolved" } else { "manual" }
                    ));
                } else {
                    self.log(&format!(
                        "Connected: {} [{}:{}] (SOCKS 127.0.0.1:{} / HTTP 127.0.0.1:{}, {})",
                        node.name,
                        node.address,
                        node.port,
                        self.state.socks_port,
                        self.state.http_port,
                        self.state.routing.short_label()
                    ));
                }
            }
            Err(e) => {
                self.connected = false;
                self.connected_node_key = None;
                self.log(&e);
            }
        }
    }

    fn disconnect(&mut self) {
        self.runner.stop();
        self.stats_base = None;
        self.stats_prev = None;
        self.last_traffic = None;
        if self.connected {
            self.connected = false;
            self.connected_node_key = None;
            self.log("Disconnected.");
        }
    }

    fn reconnect_if_connected(&mut self) {
        if self.connected {
            self.disconnect();
            std::thread::sleep(Duration::from_millis(250));
            self.connect();
        }
    }

    fn start_sub_fetch(&mut self, url: String, sub_id_opt: Option<String>, silent: bool) {
        if self.sub_fetching {
            if !silent {
                self.log("Subscription update already running.");
            }
            return;
        }
        let sub_id = sub_id_opt
            .or_else(|| {
                self.state
                    .subscriptions
                    .iter()
                    .find(|s| s.url == url)
                    .map(|s| s.id.clone())
            })
            .unwrap_or_else(|| self.state.next_subscription_id());
        self.sub_fetching = true;
        self.log(&format!(
            "{} subscription ({})...",
            if silent { "Auto-updating" } else { "Fetching" },
            short_sub_host(&url)
        ));

        let tx = self.ev_tx.clone();
        let ua = self.state.user_agent.clone();
        let send_hwid = self.state.send_hwid;
        let fallback_port = if self.connected {
            Some(self.state.http_port)
        } else {
            None
        };
        std::thread::spawn(move || {
            let res = fetch_subscription_opts(&url, &ua, send_hwid, fallback_port).and_then(
                |resp| {
                    let nodes = parse_subscription_body(&resp.body)?;
                    if nodes.is_empty() {
                        return Err("No supported proxy links found in subscription.".to_string());
                    }
                    Ok(SubFetchOutcome { nodes, resp })
                },
            );
            let _ = tx.send(TuiEvent::SubFetched {
                sub_id,
                url,
                silent,
                res,
            });
        });
    }

    fn toggle_tcp_ping(&mut self) {
        if self.tcp_ping_cancel.is_some() {
            self.cancel_tcp_ping();
            self.log("TCP ping cancelled.");
            return;
        }
        if self.state.nodes.is_empty() {
            return;
        }
        self.cancel_real_ping();
        self.cancel_tcp_ping();
        let gen = self.ping_gen;
        let cancel = Arc::new(AtomicBool::new(false));
        self.tcp_ping_cancel = Some(cancel.clone());
        let tun_active = self.connected && self.state.mode == ProxyMode::Tun;
        self.log("Running TCP ping on all servers...");
        let targets = extract_ping_targets(&self.state.nodes);
        let tx1 = self.ev_tx.clone();
        let tx2 = self.ev_tx.clone();
        ping_all_async(
            targets,
            tun_active,
            cancel,
            move |idx, ms| {
                let _ = tx1.send(TuiEvent::PingResult(gen, idx, ms));
            },
            move || {
                let _ = tx2.send(TuiEvent::PingFinished(gen));
            },
        );
    }

    fn toggle_real_ping(&mut self) {
        if self.real_ping_cancel.is_some() {
            self.cancel_real_ping();
            self.log("Real ping cancelled.");
            return;
        }
        if self.state.nodes.is_empty() {
            return;
        }
        self.cancel_tcp_ping();
        self.cancel_real_ping();
        let gen = self.real_ping_gen;
        let cancel = Arc::new(AtomicBool::new(false));
        self.real_ping_cancel = Some(cancel.clone());
        let bind_phys = self.connected && self.state.mode == ProxyMode::Tun;
        let opts = OutboundOpts {
            fragment: self.state.enable_fragment,
            noise: self.state.enable_noise,
            mux: self.state.enable_mux,
        };
        self.log("Running Real Ping (HTTPS /generate_204) on all servers...");
        let items: Vec<(usize, VlessNode)> = self.state.nodes.iter().cloned().enumerate().collect();
        let tx1 = self.ev_tx.clone();
        let tx2 = self.ev_tx.clone();
        let tx3 = self.ev_tx.clone();
        real_ping_all_async(
            items,
            bind_phys,
            opts,
            cancel,
            move |idx, ms| {
                let _ = tx1.send(TuiEvent::RealPingResult(gen, idx, ms));
            },
            move |err| {
                let _ = tx2.send(TuiEvent::RealPingError(gen, err));
            },
            move || {
                let _ = tx3.send(TuiEvent::RealPingFinished(gen));
            },
        );
    }

    fn check_due_sub_updates(&mut self) {
        if self.sub_fetching {
            return;
        }
        let now = now_unix();
        let due = self.state.subscriptions.iter().find(|s| {
            if s.update_interval_hours == 0 {
                return false;
            }
            if self.sub_retry_after.get(&s.id).copied().unwrap_or(0) > now {
                return false;
            }
            now.saturating_sub(s.last_updated_unix) >= (s.update_interval_hours as u64) * 3600
        });
        if let Some(sub) = due.cloned() {
            self.start_sub_fetch(sub.url, Some(sub.id), true);
        }
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.ev_rx.try_recv() {
            match ev {
                TuiEvent::LogLine(line) => self.log(&line),
                TuiEvent::SubFetched {
                    sub_id,
                    url,
                    silent,
                    res,
                } => {
                    self.sub_fetching = false;
                    match res {
                        Ok(SubFetchOutcome { nodes, resp }) => {
                            self.sub_retry_after.remove(&sub_id);
                            let prev_key = self
                                .selected_node_idx()
                                .and_then(|i| self.state.nodes.get(i))
                                .map(|n| n.identity_key());
                            let cnt = nodes.len();
                            merge_sub_nodes(&mut self.state, &sub_id, &url, nodes, &resp);
                            if !silent || self.active_sub_id.is_none() {
                                self.active_sub_id = Some(sub_id.clone());
                            }
                            let next_idx = prev_key
                                .and_then(|k| {
                                    self.state.nodes.iter().position(|n| n.identity_key() == k)
                                })
                                .unwrap_or(0);
                            self.select_node(next_idx);
                            self.cancel_real_ping();
                            self.cancel_tcp_ping();
                            let _ = self.state.save();
                            let via = if resp.via_proxy { " (via proxy)" } else { "" };
                            self.log(&format!(
                                "Subscription '{}' updated: {} server(s){}.",
                                short_sub_host(&url),
                                cnt,
                                via
                            ));
                            if silent {
                                self.check_due_sub_updates();
                            }
                        }
                        Err(e) => {
                            if silent {
                                self.sub_retry_after
                                    .insert(sub_id, now_unix().saturating_add(900));
                                self.log(&format!("Auto-update failed: {}", e));
                            } else {
                                self.log(&format!("Subscription error: {}", e));
                            }
                        }
                    }
                }
                TuiEvent::PingResult(gen, idx, ms) => {
                    if gen == self.ping_gen {
                        if let Some(n) = self.state.nodes.get_mut(idx) {
                            n.ping_ms = Some(ms);
                        }
                    }
                }
                TuiEvent::PingFinished(gen) => {
                    if gen == self.ping_gen {
                        self.tcp_ping_cancel = None;
                        self.log("TCP ping finished.");
                    }
                }
                TuiEvent::RealPingResult(gen, idx, ms) => {
                    if gen == self.real_ping_gen {
                        if let Some(n) = self.state.nodes.get_mut(idx) {
                            n.ping_ms = Some(ms);
                        }
                    }
                }
                TuiEvent::RealPingError(gen, err) => {
                    if gen == self.real_ping_gen {
                        self.log(&err);
                    }
                }
                TuiEvent::RealPingFinished(gen) => {
                    if gen == self.real_ping_gen {
                        self.real_ping_cancel = None;
                        self.log("Real ping finished.");
                    }
                }
                TuiEvent::GeoUpdated(res) => {
                    self.geo_updating = false;
                    match res {
                        Ok((ip_sz, site_sz)) => self.log(&format!(
                            "Geo databases updated: geoip.dat ({}), geosite.dat ({}).",
                            fmt_bytes(ip_sz as u64),
                            fmt_bytes(site_sz as u64)
                        )),
                        Err(e) => self.log(&format!("Geo update failed: {}", e)),
                    }
                }
                TuiEvent::XrayExited(pid) => {
                    if self.connected && self.runner.active_pid().map(|p| p == pid).unwrap_or(true) {
                        self.runner.stop();
                        self.connected = false;
                        self.connected_node_key = None;
                        self.last_traffic = None;
                        self.log("WARNING: avel-core exited unexpectedly. Disconnected.");
                    }
                }
            }
        }
    }

    fn on_tick(&mut self) {
        if self.connected
            && self.state.mode == ProxyMode::Tun
            && self.last_stats_tick.elapsed() >= Duration::from_secs(1)
        {
            self.last_stats_tick = Instant::now();
            if let Some((rx, tx)) = query_tun_octets("avel0") {
                let (base_rx, base_tx) = *self.stats_base.get_or_insert((rx, tx));
                let (prev_rx, prev_tx) = self.stats_prev.replace((rx, tx)).unwrap_or((rx, tx));
                let drx = rx.saturating_sub(prev_rx);
                let dtx = tx.saturating_sub(prev_tx);
                let total = rx
                    .saturating_sub(base_rx)
                    .saturating_add(tx.saturating_sub(base_tx));
                self.last_traffic = Some(format!(
                    "Dn {}, Up {} ({})",
                    fmt_rate(drx),
                    fmt_rate(dtx),
                    fmt_bytes(total)
                ));
            }
        }
        if self.last_sub_check.elapsed() >= Duration::from_secs(300) {
            self.last_sub_check = Instant::now();
            self.check_due_sub_updates();
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Char('1') => {
                self.active_tab = 0;
                return;
            }
            KeyCode::Char('2') => {
                self.active_tab = 1;
                return;
            }
            KeyCode::Char('3') => {
                self.active_tab = 2;
                return;
            }
            KeyCode::Tab => {
                self.active_tab = (self.active_tab + 1) % 3;
                return;
            }
            KeyCode::BackTab => {
                self.active_tab = (self.active_tab + 2) % 3;
                return;
            }
            _ => {}
        }

        match self.active_tab {
            0 => self.handle_tab0_key(key),
            1 => self.handle_tab1_key(key),
            _ => self.handle_tab2_key(key),
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.modal = None;
            }
            KeyCode::Backspace => {
                if let Some(ref mut m) = self.modal {
                    m.value.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(ref mut m) = self.modal {
                    m.value.push(c);
                }
            }
            KeyCode::Enter => {
                if let Some(m) = self.modal.take() {
                    self.apply_modal(m);
                }
            }
            _ => {}
        }
    }

    fn apply_modal(&mut self, modal: InputModal) {
        let val = modal.value.trim().to_string();
        match modal.kind {
            ModalKind::AddSubOrLink => {
                if val.is_empty() {
                    return;
                }
                if is_proxy_link_text(&val) {
                    match import_manual_links(&mut self.state, &val) {
                        Ok((added, skipped)) => {
                            self.cancel_tcp_ping();
                            self.cancel_real_ping();
                            if added > 0 {
                                self.select_node(self.state.nodes.len() - added);
                            }
                            let _ = self.state.save();
                            self.log(&format!(
                                "Added {} server(s) ({} duplicate skipped).",
                                added, skipped
                            ));
                        }
                        Err(e) => self.log(&format!("Import error: {}", e)),
                    }
                } else if val.starts_with("http://") || val.starts_with("https://") {
                    self.start_sub_fetch(val, None, false);
                } else {
                    match import_manual_links(&mut self.state, &val) {
                        Ok((added, skipped)) => {
                            self.cancel_tcp_ping();
                            self.cancel_real_ping();
                            let _ = self.state.save();
                            self.log(&format!(
                                "Added {} server(s) ({} duplicate skipped).",
                                added, skipped
                            ));
                        }
                        Err(_) => self.log("Enter an https:// subscription URL or proxy link."),
                    }
                }
            }
            ModalKind::RenameServer(idx) => {
                if val.is_empty() || idx >= self.state.nodes.len() {
                    return;
                }
                let old = self.state.nodes[idx].name.clone();
                if old != val {
                    self.state.nodes[idx].name = val.clone();
                    let old_t = format!("node:{}", old);
                    let new_t = format!("node:{}", val);
                    for r in &mut self.state.custom_rules {
                        if r.target == old_t {
                            r.target = new_t.clone();
                        }
                    }
                    let _ = self.state.save();
                    self.log(&format!("Renamed '{}' -> '{}'.", old, val));
                }
            }
            ModalKind::AddRule => {
                // Format: kind:value:target  (e.g. domain:geosite:youtube:direct or process:firefox:direct)
                let parts: Vec<&str> = val.splitn(3, '|').collect();
                let (kind, match_val, target) = if parts.len() == 3 {
                    let k = match parts[0].trim().to_lowercase().as_str() {
                        "proc" | "process" => RuleMatchKind::Process,
                        "ip" => RuleMatchKind::Ip,
                        _ => RuleMatchKind::Domain,
                    };
                    (k, parts[1].trim().to_string(), parts[2].trim().to_string())
                } else if !val.is_empty() {
                    (RuleMatchKind::Domain, val, "direct".to_string())
                } else {
                    return;
                };
                let match_val = crate::xray_config::clean_rule_input(kind, &match_val);
                if match_val.is_empty() {
                    return;
                }
                let target = if target.is_empty() {
                    "direct".to_string()
                } else {
                    target
                };
                self.state.custom_rules.push(RoutingRule {
                    enabled: true,
                    kind,
                    value: match_val,
                    target,
                });
                let _ = self.state.save();
                self.rule_list_state
                    .select(Some(self.state.custom_rules.len() - 1));
                self.log("Rule added. Press [Enter] on Routing tab to apply.");
            }
            ModalKind::EditSetting(row) => {
                match row {
                    0 => {
                        if let Ok(v) = val.parse::<u16>() {
                            if (1280..=9000).contains(&v) {
                                self.state.tun_mtu = v;
                            } else {
                                self.log("TUN MTU must be 1280..9000.");
                            }
                        }
                    }
                    1 => {
                        if let Ok(v) = val.parse::<u16>() {
                            if v >= 1 && v != self.state.http_port {
                                self.state.socks_port = v;
                            } else {
                                self.log("Invalid SOCKS port.");
                            }
                        }
                    }
                    2 => {
                        if let Ok(v) = val.parse::<u16>() {
                            if v >= 1 && v != self.state.socks_port {
                                self.state.http_port = v;
                            } else {
                                self.log("Invalid HTTP port.");
                            }
                        }
                    }
                    5 => match validate_remote_dns(&val) {
                        Ok(clean) => self.state.remote_dns = clean,
                        Err(e) => self.log(&e),
                    },
                    15 => {
                        self.state.user_agent = if val.is_empty() {
                            default_user_agent()
                        } else {
                            val
                        };
                    }
                    _ => {}
                }
                let _ = self.state.save();
            }
        }
    }

    fn handle_tab0_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.state.nodes.is_empty() {
                    let cur = self.selected_node_idx().unwrap_or(0);
                    self.select_node((cur + 1) % self.state.nodes.len());
                    let _ = self.state.save();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.state.nodes.is_empty() {
                    let cur = self.selected_node_idx().unwrap_or(0);
                    let prev = if cur == 0 {
                        self.state.nodes.len() - 1
                    } else {
                        cur - 1
                    };
                    self.select_node(prev);
                    let _ = self.state.save();
                }
            }
            KeyCode::Enter => {
                if let Some(idx) = self.selected_node_idx() {
                    let clicked = self.state.nodes[idx].identity_key();
                    if self.connected && self.connected_node_key.as_ref() == Some(&clicked) {
                        return;
                    }
                    if self.connected {
                        self.reconnect_if_connected();
                    } else {
                        self.connect();
                    }
                }
            }
            KeyCode::Char(' ') => {
                if self.connected {
                    self.disconnect();
                } else {
                    self.connect();
                }
            }
            KeyCode::Char('t') => self.toggle_tcp_ping(),
            KeyCode::Char('r') => self.toggle_real_ping(),
            KeyCode::Char('a') => {
                self.modal = Some(InputModal {
                    kind: ModalKind::AddSubOrLink,
                    title: "Add Subscription URL or Proxy Link".to_string(),
                    hint: "Paste https://... or vless:// / vmess:// / trojan:// / ss:// / hy2:// / wg://".to_string(),
                    value: String::new(),
                });
            }
            KeyCode::Char('u') => {
                let target = self
                    .active_sub_id
                    .as_deref()
                    .and_then(|id| self.state.subscriptions.iter().find(|s| s.id == id))
                    .or_else(|| self.state.subscriptions.first())
                    .cloned();
                if let Some(sub) = target {
                    self.start_sub_fetch(sub.url, Some(sub.id), false);
                } else {
                    self.log("No saved subscription. Press [a] to add one.");
                }
            }
            KeyCode::Char('n') => {
                if self.state.subscriptions.len() > 1 {
                    let cur = self
                        .active_sub_id
                        .as_deref()
                        .and_then(|id| self.state.subscriptions.iter().position(|s| s.id == id))
                        .unwrap_or(0);
                    let next = (cur + 1) % self.state.subscriptions.len();
                    self.active_sub_id = Some(self.state.subscriptions[next].id.clone());
                    self.state.subscription_url = self.state.subscriptions[next].url.clone();
                    let _ = self.state.save();
                }
            }
            KeyCode::Char('d') => {
                let target = self
                    .active_sub_id
                    .as_deref()
                    .and_then(|id| self.state.subscriptions.iter().find(|s| s.id == id))
                    .cloned();
                if let Some(sub) = target {
                    self.cancel_tcp_ping();
                    self.cancel_real_ping();
                    self.state.subscriptions.retain(|s| s.id != sub.id);
                    self.state
                        .nodes
                        .retain(|n| n.source_sub_id.as_deref() != Some(sub.id.as_str()));
                    self.active_sub_id = self.state.subscriptions.first().map(|s| s.id.clone());
                    self.state.subscription_url = self
                        .state
                        .subscriptions
                        .first()
                        .map(|s| s.url.clone())
                        .unwrap_or_default();
                    let _ = self.state.save();
                    self.select_node(0);
                    self.log(&format!("Deleted subscription '{}'.", short_sub_host(&sub.url)));
                }
            }
            KeyCode::Char('e') => {
                if let Some(idx) = self.selected_node_idx() {
                    let cur_name = self.state.nodes[idx].name.clone();
                    self.modal = Some(InputModal {
                        kind: ModalKind::RenameServer(idx),
                        title: "Rename Server".to_string(),
                        hint: "Enter new display name".to_string(),
                        value: cur_name,
                    });
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(idx) = self.selected_node_idx() {
                    self.cancel_tcp_ping();
                    self.cancel_real_ping();
                    let removed = self.state.nodes.remove(idx);
                    self.select_node(idx);
                    let _ = self.state.save();
                    self.log(&format!("Removed server '{}'.", removed.name));
                }
            }
            KeyCode::Char('m') => {
                if self.state.mode == ProxyMode::SystemProxy {
                    if !is_root() {
                        self.log("TUN mode requires root privileges (launch with sudo avel).");
                    } else {
                        self.state.mode = ProxyMode::Tun;
                        let _ = self.state.save();
                        self.log("Mode: TUN (all traffic).");
                        self.reconnect_if_connected();
                    }
                } else {
                    self.state.mode = ProxyMode::SystemProxy;
                    let _ = self.state.save();
                    self.log("Mode: System Proxy (SOCKS/HTTP).");
                    self.reconnect_if_connected();
                }
            }
            KeyCode::Char('g') => {
                let next_idx = (self.state.routing.to_index() + 1) % 3;
                self.state.routing = RoutingPreset::from_index(next_idx);
                let _ = self.state.save();
                self.log(&format!("Routing preset: {}", self.state.routing.short_label()));
                self.reconnect_if_connected();
            }
            KeyCode::Char('c') => self.logs.clear(),
            _ => {}
        }
    }

    fn handle_tab1_key(&mut self, key: KeyEvent) {
        let len = self.state.custom_rules.len();
        let cur = self.rule_list_state.selected().unwrap_or(0);
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    self.rule_list_state.select(Some((cur + 1) % len));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if len > 0 {
                    let prev = if cur == 0 { len - 1 } else { cur - 1 };
                    self.rule_list_state.select(Some(prev));
                }
            }
            KeyCode::Char(' ') => {
                if cur < len {
                    self.state.custom_rules[cur].enabled = !self.state.custom_rules[cur].enabled;
                    let _ = self.state.save();
                }
            }
            KeyCode::Char('K') => {
                if cur > 0 && cur < len {
                    self.state.custom_rules.swap(cur, cur - 1);
                    self.rule_list_state.select(Some(cur - 1));
                    let _ = self.state.save();
                }
            }
            KeyCode::Char('J') => {
                if cur + 1 < len {
                    self.state.custom_rules.swap(cur, cur + 1);
                    self.rule_list_state.select(Some(cur + 1));
                    let _ = self.state.save();
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if cur < len {
                    self.state.custom_rules.remove(cur);
                    let _ = self.state.save();
                    if self.state.custom_rules.is_empty() {
                        self.rule_list_state.select(None);
                    } else {
                        self.rule_list_state
                            .select(Some(cur.min(self.state.custom_rules.len() - 1)));
                    }
                }
            }
            KeyCode::Char('d') => {
                self.state.custom_default_action = match self.state.custom_default_action {
                    RuleDefaultAction::Proxy => RuleDefaultAction::Direct,
                    RuleDefaultAction::Direct => RuleDefaultAction::Proxy,
                };
                let _ = self.state.save();
            }
            KeyCode::Char('a') => {
                self.modal = Some(InputModal {
                    kind: ModalKind::AddRule,
                    title: "Add Routing Rule".to_string(),
                    hint: "Format: domain|youtube.com|direct  or  proc|firefox|direct  or  ip|geoip:ru|direct".to_string(),
                    value: "domain||direct".to_string(),
                });
            }
            KeyCode::Char('R') => {
                if !self
                    .state
                    .custom_rules
                    .iter()
                    .any(|r| r.value.contains("geosite:category-ru"))
                {
                    self.state.custom_rules.push(RoutingRule {
                        enabled: true,
                        kind: RuleMatchKind::Domain,
                        value: "geosite:category-ru, regexp:\\.ru$, regexp:\\.su$, regexp:\\.xn--p1ai$".to_string(),
                        target: "direct".to_string(),
                    });
                }
                if !self
                    .state
                    .custom_rules
                    .iter()
                    .any(|r| r.value.contains("geoip:ru"))
                {
                    self.state.custom_rules.push(RoutingRule {
                        enabled: true,
                        kind: RuleMatchKind::Ip,
                        value: "geoip:ru".to_string(),
                        target: "direct".to_string(),
                    });
                }
                let _ = self.state.save();
                if !self.state.custom_rules.is_empty() {
                    self.rule_list_state
                        .select(Some(self.state.custom_rules.len() - 1));
                }
            }
            KeyCode::Char('B') => {
                if !self
                    .state
                    .custom_rules
                    .iter()
                    .any(|r| r.value.contains("category-ads-all"))
                {
                    self.state.custom_rules.push(RoutingRule {
                        enabled: true,
                        kind: RuleMatchKind::Domain,
                        value: "geosite:category-ads-all".to_string(),
                        target: "block".to_string(),
                    });
                    let _ = self.state.save();
                    self.rule_list_state
                        .select(Some(self.state.custom_rules.len() - 1));
                }
            }
            KeyCode::Enter => {
                self.state.routing = RoutingPreset::Custom;
                let _ = self.state.save();
                self.log("Applied Routing rules.");
                self.reconnect_if_connected();
            }
            _ => {}
        }
    }

    fn handle_tab2_key(&mut self, key: KeyEvent) {
        let cur = self.settings_table_state.selected().unwrap_or(0);
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.settings_table_state
                    .select(Some((cur + 1) % SETTINGS_COUNT));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let prev = if cur == 0 { SETTINGS_COUNT - 1 } else { cur - 1 };
                self.settings_table_state.select(Some(prev));
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate_setting_row(cur),
            KeyCode::Char('s') => {
                let _ = self.state.save();
                self.log("Settings saved.");
                self.reconnect_if_connected();
            }
            _ => {}
        }
    }

    fn activate_setting_row(&mut self, row: usize) {
        match row {
            0 => {
                self.modal = Some(InputModal {
                    kind: ModalKind::EditSetting(0),
                    title: "TUN MTU".to_string(),
                    hint: "1280..9000 (default 1500)".to_string(),
                    value: self.state.tun_mtu.to_string(),
                });
            }
            1 => {
                self.modal = Some(InputModal {
                    kind: ModalKind::EditSetting(1),
                    title: "SOCKS Port".to_string(),
                    hint: "1..65535 (default 10808)".to_string(),
                    value: self.state.socks_port.to_string(),
                });
            }
            2 => {
                self.modal = Some(InputModal {
                    kind: ModalKind::EditSetting(2),
                    title: "HTTP Port".to_string(),
                    hint: "1..65535 (default 10809)".to_string(),
                    value: self.state.http_port.to_string(),
                });
            }
            3 => self.state.block_quic = !self.state.block_quic,
            4 => self.state.allow_lan = !self.state.allow_lan,
            5 => {
                self.modal = Some(InputModal {
                    kind: ModalKind::EditSetting(5),
                    title: "Remote DNS".to_string(),
                    hint: "e.g. https://1.1.1.1/dns-query or 8.8.8.8".to_string(),
                    value: self.state.remote_dns.clone(),
                });
            }
            6 => {
                let next = (self.state.log_level.to_index() + 1) % 4;
                self.state.log_level = XrayLogLevel::from_index(next);
            }
            7 => {
                let next = (self.state.domain_strategy.to_index() + 1) % 3;
                self.state.domain_strategy = DomainStrategy::from_index(next);
            }
            8 => {
                let next = (self.state.memory_profile.to_index() + 1) % 2;
                self.state.memory_profile = MemoryProfile::from_index(next);
            }
            9 => self.state.enable_sniffing = !self.state.enable_sniffing,
            10 => {
                if self.state.enable_sniffing {
                    self.state.sniffing_dest_override = !self.state.sniffing_dest_override;
                }
            }
            11 => self.state.enable_fragment = !self.state.enable_fragment,
            12 => self.state.enable_noise = !self.state.enable_noise,
            13 => self.state.enable_mux = !self.state.enable_mux,
            14 => self.state.send_hwid = !self.state.send_hwid,
            15 => {
                self.modal = Some(InputModal {
                    kind: ModalKind::EditSetting(15),
                    title: "User-Agent".to_string(),
                    hint: "Leave empty to restore default".to_string(),
                    value: self.state.user_agent.clone(),
                });
            }
            16 => {
                if !self.geo_updating {
                    self.geo_updating = true;
                    self.log("Downloading geoip.dat and geosite.dat...");
                    let cdir = core_dir();
                    let ua = self.state.user_agent.clone();
                    let tx = self.ev_tx.clone();
                    std::thread::spawn(move || {
                        let res = update_geo_databases(&cdir, &ua);
                        let _ = tx.send(TuiEvent::GeoUpdated(res));
                    });
                }
            }
            17 => {
                self.state.reset_settings_to_defaults();
                self.log("Settings reset to defaults. Press [s] to apply.");
            }
            _ => {}
        }
        let _ = self.state.save();
    }

    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(f.area());

        // Top tabs + status header
        let tab_titles = vec!["1 Connection", "2 Routing", "3 Settings"];
        let status_label = if self.connected {
            let extra = if let Some(ref tr) = self.last_traffic {
                format!("  {}", tr)
            } else if self.state.mode == ProxyMode::Tun {
                "  TUN avel0".to_string()
            } else {
                format!("  SOCKS:{} HTTP:{}", self.state.socks_port, self.state.http_port)
            };
            format!(" CONNECTED{} ", extra)
        } else {
            " DISCONNECTED ".to_string()
        };
        let header_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" avel-xray v{} ", APP_VERSION))
            .title_bottom(Line::from(Span::styled(
                status_label,
                Style::default()
                    .fg(if self.connected { Color::Green } else { Color::DarkGray })
                    .add_modifier(Modifier::BOLD),
            )));
        let tabs = Tabs::new(tab_titles)
            .block(header_block)
            .select(self.active_tab)
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            );
        f.render_widget(tabs, chunks[0]);

        match self.active_tab {
            0 => self.draw_tab0(f, chunks[1]),
            1 => self.draw_tab1(f, chunks[1]),
            _ => self.draw_tab2(f, chunks[1]),
        }

        // Bottom key hints bar
        let help_line = match self.active_tab {
            0 => " [Enter]Connect  [Space]Toggle  [t]TCP Ping  [r]Real Ping  [a]Add  [u]Update  [m]Mode  [g]Route  [q]Quit",
            1 => " [Space]On/Off  [a]Add  [K/J]Move  [x]Del  [d]Default  [R]+RU  [B]+AdBlock  [Enter]Apply  [q]Quit",
            _ => " [Enter/Space]Toggle or Edit  [s]Apply & Reconnect  [1/2/3/Tab]Switch Tab  [q]Quit",
        };
        f.render_widget(
            Paragraph::new(help_line).style(Style::default().fg(Color::DarkGray)),
            chunks[2],
        );

        if let Some(ref modal) = self.modal {
            draw_modal(f, modal);
        }
    }

    fn draw_tab0(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(7),
                Constraint::Length(3),
                Constraint::Length(7),
            ])
            .split(area);

        // 1. Subscription strip
        let sub_text = if self.state.subscriptions.is_empty() {
            "None (press [a] to add subscription URL or proxy link)".to_string()
        } else {
            let cur_idx = self
                .active_sub_id
                .as_deref()
                .and_then(|id| self.state.subscriptions.iter().position(|s| s.id == id))
                .unwrap_or(0);
            let sub = &self.state.subscriptions[cur_idx];
            format!(
                "[{}/{}] {}",
                cur_idx + 1,
                self.state.subscriptions.len(),
                sub_label(sub)
            )
        };
        let sub_title = if self.sub_fetching {
            " Subscription (Loading...) "
        } else {
            " Subscription ([u]Update [a]Add [d]Del [n]Next) "
        };
        f.render_widget(
            Paragraph::new(sub_text).block(Block::default().borders(Borders::ALL).title(sub_title)),
            rows[0],
        );

        // 2. Servers table
        let tcp_lbl = if self.tcp_ping_cancel.is_some() {
            "TCP:Stop"
        } else {
            "t:TCP"
        };
        let real_lbl = if self.real_ping_cancel.is_some() {
            "Real:Stop"
        } else {
            "r:Real"
        };
        let srv_title = format!(
            " Servers ({})  [{}] [{}] [e:Rename] [x:Remove] ",
            self.state.nodes.len(),
            tcp_lbl,
            real_lbl
        );
        let table_rows: Vec<Row> = self
            .state
            .nodes
            .iter()
            .map(|node| {
                let is_active = self.connected
                    && self
                        .connected_node_key
                        .as_ref()
                        .map(|k| *k == node.identity_key())
                        .unwrap_or(false);
                let marker = if is_active { "*" } else { " " };
                let name_style = if is_active {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let (ping_txt, ping_color) = match node.ping_ms {
                    None => ("-".to_string(), Color::DarkGray),
                    Some(0) => ("timeout".to_string(), Color::Red),
                    Some(ms) if ms > 250 => (format!("{} ms", ms), Color::Red),
                    Some(ms) if ms > 120 => (format!("{} ms", ms), Color::Yellow),
                    Some(ms) => (format!("{} ms", ms), Color::Green),
                };
                Row::new(vec![
                    Cell::from(marker).style(name_style),
                    Cell::from(node.name.clone()).style(name_style),
                    Cell::from(node.address.clone()).style(Style::default().fg(Color::Gray)),
                    Cell::from(node.protocol_tag()).style(Style::default().fg(Color::Gray)),
                    Cell::from(format!("{:>8}", ping_txt)).style(Style::default().fg(ping_color)),
                ])
            })
            .collect();
        let table = Table::new(
            table_rows,
            [
                Constraint::Length(2),
                Constraint::Percentage(26),
                Constraint::Percentage(38),
                Constraint::Length(14),
                Constraint::Length(9),
            ],
        )
        .block(Block::default().borders(Borders::ALL).title(srv_title))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, rows[1], &mut self.node_table_state);

        // 3. Mode & Routing strip
        let mode_str = match self.state.mode {
            ProxyMode::SystemProxy => format!(
                "System Proxy (SOCKS {} / HTTP {})",
                self.state.socks_port, self.state.http_port
            ),
            ProxyMode::Tun => "TUN avel0 (all traffic)".to_string(),
        };
        let route_str = match self.state.routing {
            RoutingPreset::Global => "Global",
            RoutingPreset::DirectLanAndRu => "Direct: LAN + RU",
            RoutingPreset::Custom => "Rules (Routing tab)",
        };
        let info_line = format!("Mode: {}   |   Routing: {}", mode_str, route_str);
        f.render_widget(
            Paragraph::new(info_line).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Connection & Routing ([m]Mode [g]Routing) "),
            ),
            rows[2],
        );

        // 4. Xray Log pane
        let visible_h = rows[3].height.saturating_sub(2) as usize;
        let skip = self.logs.len().saturating_sub(visible_h);
        let log_lines: Vec<Line> = self
            .logs
            .iter()
            .skip(skip)
            .map(|l| Line::from(l.as_str()))
            .collect();
        f.render_widget(
            Paragraph::new(log_lines)
                .block(Block::default().borders(Borders::ALL).title(" Xray Log ([c]Clear) "))
                .wrap(Wrap { trim: false }),
            rows[3],
        );
    }

    fn draw_tab1(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(6)])
            .split(area);

        let def_str = match self.state.custom_default_action {
            RuleDefaultAction::Proxy => "Active Server (Proxy unmatched)",
            RuleDefaultAction::Direct => "Direct (VPN only for rules below)",
        };
        f.render_widget(
            Paragraph::new(format!("Default action: {}   ([d] toggle)", def_str))
                .block(Block::default().borders(Borders::ALL).title(" Routing Policy ")),
            rows[0],
        );

        let items: Vec<ListItem> = self
            .state
            .custom_rules
            .iter()
            .map(|r| {
                let st = if r.enabled {
                    Style::default()
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                ListItem::new(r.display_row()).style(st)
            })
            .collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Rules (top to bottom) "),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(list, rows[1], &mut self.rule_list_state);
    }

    fn draw_tab2(&mut self, f: &mut Frame, area: Rect) {
        let on_off = |b: bool| if b { "ON".to_string() } else { "OFF".to_string() };
        let geo_status = if self.geo_updating {
            "Downloading...".to_string()
        } else {
            let cdir = core_dir();
            let ip = std::fs::metadata(cdir.join("geoip.dat"))
                .map(|m| fmt_bytes(m.len()))
                .unwrap_or_else(|_| "missing".to_string());
            let site = std::fs::metadata(cdir.join("geosite.dat"))
                .map(|m| fmt_bytes(m.len()))
                .unwrap_or_else(|_| "missing".to_string());
            format!("geoip {}, geosite {} (Enter to update)", ip, site)
        };

        let entries: [(&str, String); SETTINGS_COUNT] = [
            ("TUN MTU", self.state.tun_mtu.to_string()),
            ("SOCKS Port", self.state.socks_port.to_string()),
            ("HTTP Port", self.state.http_port.to_string()),
            ("Block QUIC (UDP/443)", on_off(self.state.block_quic)),
            ("Allow LAN (0.0.0.0)", on_off(self.state.allow_lan)),
            ("Remote DNS", self.state.remote_dns.clone()),
            ("Log Level", self.state.log_level.as_xray_str().to_string()),
            (
                "Domain Strategy",
                self.state.domain_strategy.as_xray_str().to_string(),
            ),
            (
                "Memory Profile",
                match self.state.memory_profile {
                    MemoryProfile::LowRam => "Low RAM (GOGC=50)".to_string(),
                    MemoryProfile::Performance => "Performance (GOGC=100)".to_string(),
                },
            ),
            ("Sniffing", on_off(self.state.enable_sniffing)),
            (
                "Dest Override",
                if self.state.enable_sniffing {
                    on_off(self.state.sniffing_dest_override)
                } else {
                    "disabled (Sniffing OFF)".to_string()
                },
            ),
            ("TLS Fragment", on_off(self.state.enable_fragment)),
            ("UDP Noise", on_off(self.state.enable_noise)),
            ("Mux (XUDP)", on_off(self.state.enable_mux)),
            ("Send HWID headers", on_off(self.state.send_hwid)),
            ("User-Agent", self.state.user_agent.clone()),
            ("GeoIP / GeoSite", geo_status),
            ("Reset Defaults", "Press Enter to reset".to_string()),
        ];

        let rows: Vec<Row> = entries
            .iter()
            .map(|(k, v)| {
                Row::new(vec![
                    Cell::from(*k),
                    Cell::from(v.clone()).style(Style::default().fg(Color::Cyan)),
                ])
            })
            .collect();
        let table = Table::new(rows, [Constraint::Length(24), Constraint::Min(20)])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Settings ([Enter/Space]Edit or Toggle, [s]Apply & Reconnect) "),
            )
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(table, area, &mut self.settings_table_state);
    }
}

fn draw_modal(f: &mut Frame, modal: &InputModal) {
    let area = centered_rect(76, 7, f.area());
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(Span::styled(
            modal.hint.as_str(),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("> "),
            Span::styled(
                format!("{}_", modal.value),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "[Enter] Confirm   [Esc] Cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", modal.title)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height.min(r.height)),
            Constraint::Min(0),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(v[1])[1]
}

fn run_tui() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = TuiApp::new();

    let res = loop {
        app.drain_events();
        app.on_tick();
        if let Err(e) = terminal.draw(|f| app.draw(f)) {
            break Err(e);
        }
        if app.should_quit {
            break Ok(());
        }
        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    };

    app.cancel_tcp_ping();
    app.cancel_real_ping();
    app.disconnect();
    let _ = app.state.save();
    ratatui::restore();
    res
}

// ---------- Shared helpers ----------

fn merge_sub_nodes(
    state: &mut AppState,
    sub_id: &str,
    url: &str,
    mut nodes: Vec<VlessNode>,
    resp: &SubscriptionResponse,
) {
    let old_pings: HashMap<(String, String, String, u16, String, String, String, String), u32> =
        state
            .nodes
            .iter()
            .filter_map(|n| n.ping_ms.map(|ms| (n.identity_key(), ms)))
            .collect();
    for n in &mut nodes {
        n.source_sub_id = Some(sub_id.to_string());
        if let Some(&ms) = old_pings.get(&n.identity_key()) {
            n.ping_ms = Some(ms);
        }
    }
    let first_pos = state
        .nodes
        .iter()
        .position(|n| n.source_sub_id.as_deref() == Some(sub_id));
    state
        .nodes
        .retain(|n| n.source_sub_id.as_deref() != Some(sub_id));
    if let Some(pos) = first_pos {
        let at = pos.min(state.nodes.len());
        state.nodes.splice(at..at, nodes);
    } else {
        state.nodes.extend(nodes);
    }

    let now = now_unix();
    if let Some(ex) = state.subscriptions.iter_mut().find(|s| s.id == sub_id) {
        ex.url = url.to_string();
        ex.last_updated_unix = now;
        if let Some(ref title) = resp.profile_title {
            if !title.trim().is_empty() {
                ex.name = title.trim().to_string();
            }
        }
        if let Some(hrs) = resp.update_interval_hours {
            ex.update_interval_hours = hrs;
        }
        if let Some(ref ui) = resp.userinfo {
            ex.userinfo = ui.clone();
        }
    } else {
        state.subscriptions.push(SubscriptionProfile {
            id: sub_id.to_string(),
            name: resp
                .profile_title
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| short_sub_host(url)),
            url: url.to_string(),
            update_interval_hours: resp.update_interval_hours.unwrap_or(0),
            last_updated_unix: now,
            userinfo: resp.userinfo.clone().unwrap_or_default(),
        });
    }
    state.subscription_url = url.to_string();
    if let Some(ref ui) = resp.userinfo {
        state.subscription_info = ui.clone();
    }
}

fn import_manual_links(state: &mut AppState, text: &str) -> Result<(usize, usize), String> {
    let parsed = parse_subscription_body(text)?;
    if parsed.is_empty() {
        return Err("No supported proxy links found.".to_string());
    }
    let mut added = 0usize;
    let mut skipped = 0usize;
    for mut node in parsed {
        node.source_sub_id = None;
        let k = node.identity_key();
        if state.nodes.iter().any(|ex| ex.identity_key() == k) {
            skipped += 1;
        } else {
            state.nodes.push(node);
            added += 1;
        }
    }
    Ok((added, skipped))
}

fn sub_label(sub: &SubscriptionProfile) -> String {
    let host = short_sub_host(&sub.url);
    let custom = !sub.name.trim().is_empty() && sub.name.trim() != host;
    if custom || !sub.userinfo.is_empty() {
        sub.display_label()
    } else {
        sub.url.clone()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        out.push('~');
        out
    }
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.0} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}

fn fmt_rate(bps: u64) -> String {
    if bps >= 1_048_576 {
        format!("{:.1} MB/s", bps as f64 / 1_048_576.0)
    } else if bps >= 1024 {
        format!("{:.0} KB/s", bps as f64 / 1024.0)
    } else {
        format!("{} B/s", bps)
    }
}
