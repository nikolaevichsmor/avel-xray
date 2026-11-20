use crate::model::VlessNode;
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;

fn base_node(
    name: String,
    protocol: &str,
    address: String,
    port: u16,
    uuid: String,
    raw_uri: String,
) -> VlessNode {
    VlessNode {
        name,
        protocol: protocol.to_string(),
        address,
        port,
        uuid,
        ss_method: String::new(),
        flow: String::new(),
        encryption: "none".to_string(),
        security: "none".to_string(),
        sni: String::new(),
        fp: String::new(),
        pbk: String::new(),
        sid: String::new(),
        spx: String::new(),
        alpn: String::new(),
        allow_insecure: false,
        network: "tcp".to_string(),
        path: String::new(),
        host: String::new(),
        service_name: String::new(),
        mode: String::new(),
        header_type: String::new(),
        extra: String::new(),
        obfs: String::new(),
        obfs_password: String::new(),
        wg_address: String::new(),
        wg_reserved: String::new(),
        wg_mtu: 0,
        proxy_user: String::new(),
        source_sub_id: None,
        raw_uri,
        ping_ms: None,
    }
}

pub fn is_proxy_link_text(input: &str) -> bool {
    let t = input.trim().trim_start_matches('\u{FEFF}').trim();
    if t.is_empty() {
        return false;
    }
    for line in t.lines() {
        let l = line.trim();
        if l.starts_with("vless://")
            || l.starts_with("vmess://")
            || l.starts_with("trojan://")
            || l.starts_with("ss://")
            || l.starts_with("hy2://")
            || l.starts_with("hysteria2://")
            || l.starts_with("wireguard://")
            || l.starts_with("wg://")
            || l.starts_with("socks://")
            || l.starts_with("socks5://")
        {
            return true;
        }
        if (l.starts_with("http://") || l.starts_with("https://"))
            && looks_like_http_proxy_uri(l)
        {
            return true;
        }
    }
    false
}

fn looks_like_http_proxy_uri(line: &str) -> bool {
    let rest = line
        .strip_prefix("http://")
        .or_else(|| line.strip_prefix("https://"))
        .unwrap_or("");
    let before_frag = rest.split('#').next().unwrap_or("");
    // Subscription URLs have a path like /sub/...; HTTP proxy URIs have user:pass@host:port or host:port without sub path.
    if before_frag.contains('/') {
        let (auth, path) = before_frag.split_once('/').unwrap_or((before_frag, ""));
        if !path.is_empty() {
            return false;
        }
        return auth.contains('@') && split_host_port(auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth)).is_ok();
    }
    let hostpart = before_frag.rsplit_once('@').map(|(_, h)| h).unwrap_or(before_frag);
    let has_auth_or_frag = before_frag.contains('@') || line.contains('#');
    has_auth_or_frag && split_host_port(hostpart).is_ok()
}

// RFC-3986 percent decoding without turning '+' into space (breaks base64/JSON values).
pub fn percent_decode_strict(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn try_decode_base64_text(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for eng in engines {
        if let Ok(bytes) = eng.decode(cleaned.as_bytes()) {
            if let Ok(s) = String::from_utf8(bytes) {
                if s.contains("vless://") || s.contains("://") {
                    return Some(s);
                }
            }
        }
    }
    // Try adding padding if missing
    let rem = cleaned.len() % 4;
    if rem != 0 {
        let mut padded = cleaned;
        for _ in 0..(4 - rem) {
            padded.push('=');
        }
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()) {
            if let Ok(s) = String::from_utf8(bytes) {
                if s.contains("vless://") || s.contains("://") {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn decode_subscription_text(body: &str) -> String {
    let trimmed = body.trim().trim_start_matches('\u{FEFF}').trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains("vless://")
        || trimmed.contains("vmess://")
        || trimmed.contains("trojan://")
        || trimmed.contains("ss://")
        || trimmed.contains("hy2://")
        || trimmed.contains("hysteria2://")
        || trimmed.contains("wireguard://")
        || trimmed.contains("wg://")
        || trimmed.contains("socks://")
        || trimmed.contains("socks5://")
    {
        trimmed.to_string()
    } else if let Some(decoded) = try_decode_base64_text(trimmed) {
        decoded.trim_start_matches('\u{FEFF}').to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn parse_subscription_body(body: &str) -> Result<Vec<VlessNode>, String> {
    let text = decode_subscription_text(body);
    if text.is_empty() {
        return Ok(Vec::new());
    }

    const MAX_SUB_NODES: usize = 500;
    let mut nodes = Vec::new();
    for line in text.lines() {
        if nodes.len() >= MAX_SUB_NODES {
            break;
        }
        let l = line.trim().trim_start_matches('\u{FEFF}').trim();
        if l.starts_with("vless://") {
            if l.contains("00000000-0000-0000-0000-000000000000@127.0.0.1") {
                return Err("Subscription expired or inactive.".to_string());
            }
            if let Ok(node) = parse_vless_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("vmess://") {
            if let Ok(node) = parse_vmess_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("trojan://") {
            if let Ok(node) = parse_trojan_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("ss://") {
            if let Ok(node) = parse_ss_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("hy2://") || l.starts_with("hysteria2://") {
            if let Ok(node) = parse_hysteria2_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("wireguard://") || l.starts_with("wg://") {
            if let Ok(node) = parse_wireguard_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("socks://") || l.starts_with("socks5://") {
            if let Ok(node) = parse_socks_uri(l) {
                nodes.push(node);
            }
        } else if (l.starts_with("http://") || l.starts_with("https://"))
            && looks_like_http_proxy_uri(l)
        {
            if let Ok(node) = parse_http_proxy_uri(l) {
                nodes.push(node);
            }
        }
    }
    Ok(nodes)
}

pub fn parse_vless_uri(uri: &str) -> Result<VlessNode, String> {
    let rest = uri
        .trim()
        .trim_start_matches('\u{FEFF}')
        .strip_prefix("vless://")
        .ok_or_else(|| "URI must start with vless://".to_string())?;

    // Split fragment (#remark)
    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };

    // Split query (?params)
    let (authority, query_raw) = match before_frag.find('?') {
        Some(pos) => (&before_frag[..pos], &before_frag[pos + 1..]),
        None => (before_frag, ""),
    };

    // Split uuid@host:port
    let (uuid_raw, hostport_raw) = authority
        .split_once('@')
        .ok_or_else(|| "Missing '@' in vless URI".to_string())?;

    let uuid = percent_decode_strict(uuid_raw).trim().to_string();
    if uuid.is_empty() {
        return Err("Empty UUID in vless URI".to_string());
    }

    let (address, port) = split_host_port(hostport_raw)?;

    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query_raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_lowercase(), percent_decode_strict(v));
        }
    }

    let get_p = |k: &str| -> String { params.get(k).cloned().unwrap_or_default() };

    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("{}:{}", address, port);
    }

    let encryption = {
        let e = get_p("encryption");
        if e.is_empty() { "none".to_string() } else { e }
    };

    let security = {
        let s = get_p("security").to_lowercase();
        if s.is_empty() { "none".to_string() } else { s }
    };

    let network = {
        let n = get_p("type").to_lowercase();
        if n.is_empty() || n == "raw" {
            "tcp".to_string()
        } else {
            n
        }
    };

    let allow_insecure = matches!(
        get_p("allowinsecure").to_lowercase().as_str(),
        "1" | "true" | "yes"
    );

    let sni = {
        let s = get_p("sni");
        if s.is_empty() { get_p("peer") } else { s }
    };

    let mut n = base_node(name, "vless", address, port, uuid, uri.trim().to_string());
    n.flow = get_p("flow");
    n.encryption = encryption;
    n.security = security;
    n.sni = sni;
    n.fp = get_p("fp");
    n.pbk = get_p("pbk");
    n.sid = get_p("sid");
    n.spx = get_p("spx");
    n.alpn = get_p("alpn");
    n.allow_insecure = allow_insecure;
    n.network = network;
    n.path = get_p("path");
    n.host = get_p("host");
    n.service_name = get_p("servicename");
    n.mode = get_p("mode");
    n.header_type = get_p("headertype");
    n.extra = get_p("extra");
    Ok(n)
}

pub fn parse_trojan_uri(uri: &str) -> Result<VlessNode, String> {
    let rest = uri
        .trim()
        .trim_start_matches('\u{FEFF}')
        .strip_prefix("trojan://")
        .ok_or_else(|| "URI must start with trojan://".to_string())?;

    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let (authority, query_raw) = match before_frag.find('?') {
        Some(pos) => (&before_frag[..pos], &before_frag[pos + 1..]),
        None => (before_frag, ""),
    };
    let (pass_raw, hostport_raw) = authority
        .split_once('@')
        .ok_or_else(|| "Missing '@' in trojan URI".to_string())?;

    let password = percent_decode_strict(pass_raw).trim().to_string();
    if password.is_empty() {
        return Err("Empty password in trojan URI".to_string());
    }
    let (address, port) = split_host_port(hostport_raw)?;

    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query_raw.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_lowercase(), percent_decode_strict(v));
        }
    }
    let get_p = |k: &str| -> String { params.get(k).cloned().unwrap_or_default() };

    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("{}:{}", address, port);
    }

    let security = {
        let s = get_p("security").to_lowercase();
        if s.is_empty() { "tls".to_string() } else { s }
    };
    let network = {
        let n = get_p("type").to_lowercase();
        if n.is_empty() || n == "raw" { "tcp".to_string() } else { n }
    };
    let allow_insecure = matches!(
        get_p("allowinsecure").to_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    let sni = {
        let s = get_p("sni");
        if s.is_empty() { get_p("peer") } else { s }
    };

    let mut n = base_node(name, "trojan", address, port, password, uri.trim().to_string());
    n.security = security;
    n.sni = sni;
    n.fp = get_p("fp");
    n.pbk = get_p("pbk");
    n.sid = get_p("sid");
    n.spx = get_p("spx");
    n.alpn = get_p("alpn");
    n.allow_insecure = allow_insecure;
    n.network = network;
    n.path = get_p("path");
    n.host = get_p("host");
    n.service_name = get_p("servicename");
    n.mode = get_p("mode");
    n.header_type = get_p("headertype");
    n.extra = get_p("extra");
    Ok(n)
}

pub fn parse_ss_uri(uri: &str) -> Result<VlessNode, String> {
    let rest = uri
        .trim()
        .trim_start_matches('\u{FEFF}')
        .strip_prefix("ss://")
        .ok_or_else(|| "URI must start with ss://".to_string())?;

    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let (main_part, _query_raw) = match before_frag.find('?') {
        Some(pos) => (&before_frag[..pos], &before_frag[pos + 1..]),
        None => (before_frag, ""),
    };

    // Supports SIP002 (userinfo@host:port, where userinfo is base64 or plain method:pass)
    // and legacy full-base64 (base64(method:pass@host:port)).
    let (userinfo_decoded, hostport_raw) = if let Some((ui, hp)) = main_part.split_once('@') {
        let ui_clean = percent_decode_strict(ui);
        let decoded = if ui_clean.contains(':') {
            ui_clean
        } else {
            try_decode_base64_str(&ui_clean)
                .ok_or_else(|| "Invalid base64 userinfo in ss URI".to_string())?
        };
        (decoded, hp.to_string())
    } else {
        let full = try_decode_base64_str(main_part)
            .ok_or_else(|| "Invalid base64 ss URI".to_string())?;
        let (ui, hp) = full
            .rsplit_once('@')
            .ok_or_else(|| "Missing '@' in decoded ss URI".to_string())?;
        (ui.to_string(), hp.to_string())
    };

    let (method, password) = userinfo_decoded
        .split_once(':')
        .ok_or_else(|| "Missing method:password in ss URI".to_string())?;
    let method = method.trim().to_string();
    let password = password.trim().to_string();
    if method.is_empty() || password.is_empty() {
        return Err("Empty method or password in ss URI".to_string());
    }

    let (address, port) = split_host_port(&hostport_raw)?;
    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("{}:{}", address, port);
    }

    let mut n = base_node(name, "shadowsocks", address, port, password, uri.trim().to_string());
    n.ss_method = method;
    Ok(n)
}

pub fn parse_vmess_uri(uri: &str) -> Result<VlessNode, String> {
    let rest = uri
        .trim()
        .trim_start_matches('\u{FEFF}')
        .strip_prefix("vmess://")
        .ok_or_else(|| "URI must start with vmess://".to_string())?;
    let json_text = try_decode_base64_str(rest)
        .ok_or_else(|| "Invalid base64 payload in vmess URI".to_string())?;
    let val: Value = serde_json::from_str(&json_text)
        .map_err(|e| format!("Invalid JSON in vmess URI: {}", e))?;

    let get_s = |k: &str| -> String {
        val.get(k)
            .and_then(|v| match v {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default()
    };

    let address = get_s("add");
    let port: u16 = get_s("port")
        .parse()
        .map_err(|_| "Invalid port in vmess URI".to_string())?;
    let uuid = get_s("id");
    if address.is_empty() || uuid.is_empty() {
        return Err("Missing address or id in vmess URI".to_string());
    }
    let mut name = get_s("ps");
    if name.is_empty() {
        name = format!("{}:{}", address, port);
    }

    let mut n = base_node(name, "vmess", address, port, uuid, uri.trim().to_string());
    let scy = get_s("scy");
    n.encryption = if scy.is_empty() { "auto".to_string() } else { scy };
    let net = get_s("net").to_lowercase();
    n.network = if net.is_empty() || net == "raw" { "tcp".to_string() } else { net };
    let tls = get_s("tls").to_lowercase();
    n.security = if tls == "tls" { "tls".to_string() } else { "none".to_string() };
    n.sni = get_s("sni");
    if n.sni.is_empty() {
        n.sni = get_s("host");
    }
    n.host = get_s("host");
    n.path = get_s("path");
    n.service_name = if n.network == "grpc" { get_s("path") } else { String::new() };
    n.header_type = get_s("type");
    n.alpn = get_s("alpn");
    n.fp = get_s("fp");
    Ok(n)
}

pub fn parse_hysteria2_uri(uri: &str) -> Result<VlessNode, String> {
    let trimmed = uri.trim().trim_start_matches('\u{FEFF}');
    let rest = trimmed
        .strip_prefix("hy2://")
        .or_else(|| trimmed.strip_prefix("hysteria2://"))
        .ok_or_else(|| "URI must start with hy2:// or hysteria2://".to_string())?;

    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let (authority, query_raw) = match before_frag.find('?') {
        Some(pos) => (&before_frag[..pos], &before_frag[pos + 1..]),
        None => (before_frag, ""),
    };
    let (auth_raw, hostport_raw) = authority
        .rsplit_once('@')
        .ok_or_else(|| "Missing '@' in hysteria2 URI".to_string())?;
    let auth = percent_decode_strict(auth_raw).trim().to_string();
    let (address, port) = split_host_port(hostport_raw)?;

    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query_raw.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_lowercase(), percent_decode_strict(v));
        }
    }
    let get_p = |k: &str| -> String { params.get(k).cloned().unwrap_or_default() };

    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("{}:{}", address, port);
    }

    let mut n = base_node(name, "hysteria", address, port, auth, trimmed.to_string());
    n.network = "hysteria".to_string();
    n.security = "tls".to_string();
    n.sni = {
        let s = get_p("sni");
        if s.is_empty() { get_p("peer") } else { s }
    };
    n.alpn = get_p("alpn");
    n.allow_insecure = matches!(
        get_p("insecure").to_lowercase().as_str(),
        "1" | "true" | "yes"
    ) || matches!(
        get_p("allowinsecure").to_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    n.obfs = get_p("obfs").to_lowercase();
    n.obfs_password = get_p("obfs-password");
    Ok(n)
}

pub fn parse_wireguard_uri(uri: &str) -> Result<VlessNode, String> {
    let trimmed = uri.trim().trim_start_matches('\u{FEFF}');
    let rest = trimmed
        .strip_prefix("wireguard://")
        .or_else(|| trimmed.strip_prefix("wg://"))
        .ok_or_else(|| "URI must start with wireguard://".to_string())?;

    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let (authority, query_raw) = match before_frag.find('?') {
        Some(pos) => (&before_frag[..pos], &before_frag[pos + 1..]),
        None => (before_frag, ""),
    };
    let (priv_raw, hostport_raw) = authority
        .rsplit_once('@')
        .ok_or_else(|| "Missing '@' in wireguard URI".to_string())?;
    let secret_key = percent_decode_strict(priv_raw).trim().to_string();
    if secret_key.is_empty() {
        return Err("Empty private key in wireguard URI".to_string());
    }
    let (address, port) = split_host_port(hostport_raw)?;

    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query_raw.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_lowercase(), percent_decode_strict(v));
        }
    }
    let get_p = |k: &str| -> String { params.get(k).cloned().unwrap_or_default() };

    let public_key = {
        let a = get_p("publickey");
        if !a.is_empty() {
            a
        } else {
            let b = get_p("pbk");
            if !b.is_empty() { b } else { get_p("public_key") }
        }
    };
    if public_key.is_empty() {
        return Err("Missing publickey in wireguard URI".to_string());
    }

    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("{}:{}", address, port);
    }

    let mut n = base_node(name, "wireguard", address, port, secret_key, trimmed.to_string());
    n.network = "udp".to_string();
    n.pbk = public_key;
    n.sid = {
        let a = get_p("presharedkey");
        if !a.is_empty() { a } else { get_p("psk") }
    };
    n.wg_address = {
        let a = get_p("address");
        if a.is_empty() { "172.16.0.2/32".to_string() } else { a }
    };
    n.wg_reserved = get_p("reserved");
    n.wg_mtu = get_p("mtu").parse::<u16>().unwrap_or(1420).clamp(1280, 1500);
    Ok(n)
}

pub fn parse_socks_uri(uri: &str) -> Result<VlessNode, String> {
    let trimmed = uri.trim().trim_start_matches('\u{FEFF}');
    let rest = trimmed
        .strip_prefix("socks5://")
        .or_else(|| trimmed.strip_prefix("socks://"))
        .ok_or_else(|| "URI must start with socks:// or socks5://".to_string())?;

    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let main_part = before_frag.split('?').next().unwrap_or(before_frag).trim_end_matches('/');

    let (user, pass, hostport) = if let Some((ui, hp)) = main_part.rsplit_once('@') {
        let ui_dec = percent_decode_strict(ui);
        let cred = if ui_dec.contains(':') {
            ui_dec
        } else {
            try_decode_base64_str(&ui_dec).unwrap_or(ui_dec)
        };
        let (u, p) = cred.split_once(':').unwrap_or((&cred, ""));
        (u.to_string(), p.to_string(), hp.to_string())
    } else if main_part.contains(':') {
        (String::new(), String::new(), main_part.to_string())
    } else if let Some(dec) = try_decode_base64_str(main_part) {
        if let Some((ui, hp)) = dec.rsplit_once('@') {
            let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
            (u.to_string(), p.to_string(), hp.to_string())
        } else {
            (String::new(), String::new(), dec)
        }
    } else {
        return Err("Invalid socks URI".to_string());
    };

    let (address, port) = split_host_port(&hostport)?;
    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("SOCKS {}:{}", address, port);
    }

    let mut n = base_node(name, "socks", address, port, pass, trimmed.to_string());
    n.proxy_user = user;
    Ok(n)
}

pub fn parse_http_proxy_uri(uri: &str) -> Result<VlessNode, String> {
    let trimmed = uri.trim().trim_start_matches('\u{FEFF}');
    let is_https = trimmed.starts_with("https://");
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| "URI must start with http:// or https://".to_string())?;

    let (before_frag, remark_raw) = match rest.find('#') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };
    let main_part = before_frag.split('?').next().unwrap_or(before_frag).trim_end_matches('/');
    let (user, pass, hostport) = if let Some((ui, hp)) = main_part.rsplit_once('@') {
        let ui_dec = percent_decode_strict(ui);
        let (u, p) = ui_dec.split_once(':').unwrap_or((&ui_dec, ""));
        (u.to_string(), p.to_string(), hp.to_string())
    } else {
        (String::new(), String::new(), main_part.to_string())
    };
    let (address, port) = split_host_port(&hostport)?;
    let mut name = percent_decode(remark_raw).trim().to_string();
    if name.is_empty() {
        name = format!("HTTP {}:{}", address, port);
    }

    let mut n = base_node(name, "http", address, port, pass, trimmed.to_string());
    n.proxy_user = user;
    if is_https {
        n.security = "tls".to_string();
    }
    Ok(n)
}

fn split_host_port(hostport_raw: &str) -> Result<(String, u16), String> {
    let hostport = hostport_raw.trim().trim_end_matches('/');
    let (address, port_str) = if hostport.starts_with('[') {
        let end_bracket = hostport
            .find(']')
            .ok_or_else(|| "Invalid IPv6 host".to_string())?;
        let host = &hostport[1..end_bracket];
        let after = &hostport[end_bracket + 1..];
        let p = after
            .strip_prefix(':')
            .ok_or_else(|| "Missing port for IPv6 host".to_string())?;
        (host.to_string(), p)
    } else {
        let (h, p) = hostport
            .rsplit_once(':')
            .ok_or_else(|| "Missing port in URI".to_string())?;
        (h.to_string(), p)
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("Invalid port: {}", port_str))?;
    Ok((address, port))
}

fn try_decode_base64_str(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = eng.decode(cleaned.as_bytes()) {
            if let Ok(s) = String::from_utf8(bytes) {
                return Some(s);
            }
        }
    }
    let rem = cleaned.len() % 4;
    if rem != 0 {
        let mut padded = cleaned;
        for _ in 0..(4 - rem) {
            padded.push('=');
        }
        for eng in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::URL_SAFE,
        ] {
            if let Ok(bytes) = eng.decode(padded.as_bytes()) {
                if let Ok(s) = String::from_utf8(bytes) {
                    return Some(s);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn parses_vless_reality_and_base64_sub() {
        let link1 = "vless://11111111-1111-1111-1111-111111111111@de1.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&sid=12ab&spx=%2F&type=tcp#Germany%20Reality";
        let link2 = "vless://22222222-2222-2222-2222-222222222222@nl.example.com:8443?security=tls&sni=nl.example.com&type=xhttp&path=%2Fapi%2Fv1&host=nl.example.com&mode=auto#NL%20XHTTP";
        let raw_list = format!("{}\n{}\n", link1, link2);
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_list.as_bytes());

        let nodes = parse_subscription_body(&b64).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "Germany Reality");
        assert_eq!(nodes[0].address, "de1.example.com");
        assert_eq!(nodes[0].port, 443);
        assert_eq!(nodes[0].security, "reality");
        assert_eq!(nodes[0].flow, "xtls-rprx-vision");
        assert_eq!(nodes[0].spx, "/");

        assert_eq!(nodes[1].name, "NL XHTTP");
        assert_eq!(nodes[1].network, "xhttp");
        assert_eq!(nodes[1].path, "/api/v1");
        assert_eq!(nodes[1].mode, "auto");
    }

    #[test]
    fn parses_bom_trojan_and_shadowsocks_uris() {
        let body = "\u{FEFF}vless://11111111-1111-1111-1111-111111111111@v.example.com:443?security=tls#FirstBOM\n\
trojan://secretpass@tr.example.com:443?security=tls&sni=tr.example.com&fp=chrome#TrojanNode\n\
ss://YWVzLTI1Ni1nY206bXlwYXNz@ss.example.com:8388#SSNode\n";
        let nodes = parse_subscription_body(body).unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "FirstBOM");
        assert_eq!(nodes[0].protocol, "vless");
        assert_eq!(nodes[1].name, "TrojanNode");
        assert_eq!(nodes[1].protocol, "trojan");
        assert_eq!(nodes[1].uuid, "secretpass");
        assert_eq!(nodes[1].sni, "tr.example.com");
        assert_eq!(nodes[2].name, "SSNode");
        assert_eq!(nodes[2].protocol, "shadowsocks");
        assert_eq!(nodes[2].ss_method, "aes-256-gcm");
        assert_eq!(nodes[2].uuid, "mypass");
    }

    #[test]
    fn parses_vmess_hysteria2_wireguard_socks_http_uris() {
        let vmess_json = r#"{"v":"2","ps":"VMessWS","add":"vm.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}"#;
        let vmess_uri = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(vmess_json.as_bytes())
        );
        let hy2_uri = "hy2://myauth@hy.example.com:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=salpass#Hy2Node";
        let wg_uri = "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@wg.example.com:51820?publickey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB%3D&address=172.16.0.2%2F32&reserved=1,2,3&mtu=1280#WGNode";
        let socks_uri = "socks5://alice:bob@socks.example.com:1080#SocksNode";
        let http_uri = "http://u1:p1@proxy.example.com:8080#HttpProxy";

        let body = format!("{}\n{}\n{}\n{}\n{}\n", vmess_uri, hy2_uri, wg_uri, socks_uri, http_uri);
        assert!(is_proxy_link_text(&body));
        assert!(!is_proxy_link_text("https://sub.example.com/sub/exampleToken123"));

        let nodes = parse_subscription_body(&body).unwrap();
        assert_eq!(nodes.len(), 5);

        assert_eq!(nodes[0].protocol, "vmess");
        assert_eq!(nodes[0].name, "VMessWS");
        assert_eq!(nodes[0].network, "ws");
        assert_eq!(nodes[0].security, "tls");

        assert_eq!(nodes[1].protocol, "hysteria");
        assert_eq!(nodes[1].name, "Hy2Node");
        assert_eq!(nodes[1].obfs, "salamander");
        assert_eq!(nodes[1].obfs_password, "salpass");
        assert!(nodes[1].allow_insecure);

        assert_eq!(nodes[2].protocol, "wireguard");
        assert_eq!(nodes[2].name, "WGNode");
        assert_eq!(nodes[2].wg_mtu, 1280);
        assert_eq!(nodes[2].wg_reserved, "1,2,3");

        assert_eq!(nodes[3].protocol, "socks");
        assert_eq!(nodes[3].proxy_user, "alice");
        assert_eq!(nodes[3].uuid, "bob");

        assert_eq!(nodes[4].protocol, "http");
        assert_eq!(nodes[4].proxy_user, "u1");
        assert_eq!(nodes[4].uuid, "p1");
    }
}
