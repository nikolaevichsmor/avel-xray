use crate::model::VlessNode;
use base64::Engine;
use std::collections::HashMap;

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
        || trimmed.contains("trojan://")
        || trimmed.contains("ss://")
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
        } else if l.starts_with("trojan://") {
            if let Ok(node) = parse_trojan_uri(l) {
                nodes.push(node);
            }
        } else if l.starts_with("ss://") {
            if let Ok(node) = parse_ss_uri(l) {
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

    Ok(VlessNode {
        name,
        protocol: "vless".to_string(),
        address,
        port,
        uuid,
        ss_method: String::new(),
        flow: get_p("flow"),
        encryption,
        security,
        sni,
        fp: get_p("fp"),
        pbk: get_p("pbk"),
        sid: get_p("sid"),
        spx: get_p("spx"),
        alpn: get_p("alpn"),
        allow_insecure,
        network,
        path: get_p("path"),
        host: get_p("host"),
        service_name: get_p("servicename"),
        mode: get_p("mode"),
        header_type: get_p("headertype"),
        extra: get_p("extra"),
        raw_uri: uri.trim().to_string(),
        ping_ms: None,
    })
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

    Ok(VlessNode {
        name,
        protocol: "trojan".to_string(),
        address,
        port,
        uuid: password,
        ss_method: String::new(),
        flow: String::new(),
        encryption: "none".to_string(),
        security,
        sni,
        fp: get_p("fp"),
        pbk: get_p("pbk"),
        sid: get_p("sid"),
        spx: get_p("spx"),
        alpn: get_p("alpn"),
        allow_insecure,
        network,
        path: get_p("path"),
        host: get_p("host"),
        service_name: get_p("servicename"),
        mode: get_p("mode"),
        header_type: get_p("headertype"),
        extra: get_p("extra"),
        raw_uri: uri.trim().to_string(),
        ping_ms: None,
    })
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

    Ok(VlessNode {
        name,
        protocol: "shadowsocks".to_string(),
        address,
        port,
        uuid: password,
        ss_method: method,
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
        raw_uri: uri.trim().to_string(),
        ping_ms: None,
    })
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
}
