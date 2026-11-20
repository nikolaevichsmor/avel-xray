use crate::model::{
    custom_routing_path, AppState, ProxyMode, RoutingPreset, RuleDefaultAction, RuleMatchKind,
    VlessNode,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;

pub fn build_xray_config(state: &AppState, node: &VlessNode) -> Result<String, String> {
    // Resolve any additional servers referenced by enabled custom routing rules (multi-outbound)
    let mut extra_node_tags: HashMap<usize, String> = HashMap::new();
    let mut referenced_nodes: Vec<&VlessNode> = vec![node];

    if state.routing == RoutingPreset::Custom {
        for rule in state.custom_rules.iter().filter(|r| r.enabled) {
            if let Some(target_name) = rule.target.strip_prefix("node:") {
                if let Some((idx, n)) = state
                    .nodes
                    .iter()
                    .enumerate()
                    .find(|(_, n)| n.name == target_name)
                {
                    let same_as_active = n.uuid == node.uuid
                        && n.address == node.address
                        && n.port == node.port
                        && n.protocol == node.protocol;
                    if !same_as_active && !extra_node_tags.contains_key(&idx) {
                        extra_node_tags.insert(idx, format!("node-{}", idx));
                        referenced_nodes.push(n);
                    }
                }
            }
        }
    }

    let mut bootstrap_domains: Vec<String> = Vec::new();
    let mut bootstrap_ips: Vec<String> = Vec::new();
    for rn in &referenced_nodes {
        if rn.address.parse::<IpAddr>().is_ok() {
            let cidr = ip_to_host_cidr(&rn.address);
            if !bootstrap_ips.contains(&cidr) {
                bootstrap_ips.push(cidr);
            }
        } else {
            let full_dom = format!("full:{}", rn.address);
            if !bootstrap_domains.contains(&full_dom) {
                bootstrap_domains.push(full_dom);
            }
        }
    }

    // DNS: local bootstrap via 8.8.4.4 for server domains, scoped RU DNS in direct/whitelist
    // modes, and configured remote DNS through the proxy for everything else.
    let mut dns_servers: Vec<Value> = Vec::new();
    if !bootstrap_domains.is_empty() {
        dns_servers.push(json!({
            "address": "https+local://8.8.4.4/dns-query",
            "domains": bootstrap_domains,
            "skipFallback": true
        }));
        dns_servers.push(json!({
            "address": "tcp+local://8.8.4.4:53",
            "domains": bootstrap_domains,
            "skipFallback": true
        }));
    }
    if state.routing == RoutingPreset::DirectLanAndRu {
        let ru_domains = json!([
            "geosite:category-ru",
            "regexp:\\.ru$",
            "regexp:\\.su$",
            "regexp:\\.xn--p1ai$"
        ]);
        dns_servers.push(json!({
            "address": "https+local://77.88.8.8/dns-query",
            "domains": ru_domains,
            "skipFallback": true
        }));
        dns_servers.push(json!({
            "address": "tcp+local://77.88.8.8:53",
            "domains": ru_domains,
            "skipFallback": true
        }));
    } else if state.routing == RoutingPreset::Custom
        && state.custom_default_action == RuleDefaultAction::Direct
    {
        // Pure regex RU TLD GeoDNS in whitelist mode without forcing geosite.dat into RAM
        let ru_tlds = json!(["regexp:\\.ru$", "regexp:\\.su$", "regexp:\\.xn--p1ai$"]);
        dns_servers.push(json!({
            "address": "https+local://77.88.8.8/dns-query",
            "domains": ru_tlds,
            "skipFallback": true
        }));
        dns_servers.push(json!({
            "address": "tcp+local://77.88.8.8:53",
            "domains": ru_tlds,
            "skipFallback": true
        }));
    }
    let remote_dns = {
        let t = state.remote_dns.trim();
        if t.is_empty() {
            "https://1.1.1.1/dns-query"
        } else {
            t
        }
    };
    let remote_dns_host = extract_dns_host(remote_dns);
    let fallback_dns_ip = if remote_dns_host.as_deref() == Some("1.0.0.1") {
        "8.8.8.8"
    } else {
        "1.0.0.1"
    };
    dns_servers.push(json!(remote_dns));
    dns_servers.push(json!(format!("tcp://{}:53", fallback_dns_ip)));

    // Inbounds (sniffing and destOverride / routeOnly are configurable in Settings)
    let listen_addr = if state.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
    let sniffing = if state.enable_sniffing {
        json!({
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": !state.sniffing_dest_override
        })
    } else {
        json!({
            "enabled": false
        })
    };
    let mut inbounds: Vec<Value> = vec![
        json!({
            "tag": "socks-in",
            "listen": listen_addr,
            "port": state.socks_port,
            "protocol": "socks",
            "settings": { "udp": true },
            "sniffing": sniffing.clone()
        }),
        json!({
            "tag": "http-in",
            "listen": listen_addr,
            "port": state.http_port,
            "protocol": "http",
            "sniffing": sniffing.clone()
        }),
    ];

    if state.mode == ProxyMode::Tun {
        // IPv4-only TUN subnet with private peer DNS (172.21.0.2).
        // Kill-Switch enables Xray 26.11.9+ WFP "allexceptlan" (blocks all non-LAN traffic outside TUN).
        let wfp_block = if state.kill_switch {
            json!(["allexceptlan"])
        } else {
            json!(["dns", "misconfigtun"])
        };
        let tun_mtu = state.tun_mtu.clamp(1280, 9000);
        inbounds.push(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": "avel0",
                "desc": "Avel",
                "mtu": tun_mtu,
                "gateway": ["172.21.0.1/30"],
                "dns": ["172.21.0.2"],
                "userLevel": 0,
                "autoSystemRoutingTable": ["0.0.0.0/0"],
                "autoOutboundsInterface": "auto",
                "autoSystemWfpBlockLeak": wfp_block
            },
            "sniffing": sniffing
        }));
    }

    // 3. Outbounds: active server ("proxy"), any extra per-rule servers ("node-N"), direct, block, dns-out
    let out_opts = OutboundOpts {
        fragment: state.enable_fragment,
        noise: state.enable_noise,
        mux: state.enable_mux,
    };
    let mut outbounds_vec: Vec<Value> = Vec::new();
    outbounds_vec.push(build_node_outbound("proxy", node, out_opts)?);

    let mut extra_sorted: Vec<(usize, String)> = extra_node_tags
        .iter()
        .map(|(&idx, tag)| (idx, tag.clone()))
        .collect();
    extra_sorted.sort_by_key(|(idx, _)| *idx);
    for (idx, tag) in &extra_sorted {
        if let Some(extra_node) = state.nodes.get(*idx) {
            outbounds_vec.push(build_node_outbound(tag, extra_node, out_opts)?);
        }
    }

    outbounds_vec.push(json!({
        "tag": "direct",
        "protocol": "freedom",
        "streamSettings": {
            "sockopt": {
                "domainStrategy": "UseIPv4"
            }
        }
    }));
    outbounds_vec.push(json!({
        "tag": "block",
        "protocol": "blackhole"
    }));
    outbounds_vec.push(json!({
        "tag": "dns-out",
        "protocol": "dns",
        "settings": {}
    }));
    let outbounds = Value::Array(outbounds_vec);

    // 4. Routing rules
    let mut rules: Vec<Value> = Vec::new();

    // 4.0 Intercept DNS from TUN into Xray built-in DNS, and optionally block HTTP/3 QUIC (UDP/443)
    if state.mode == ProxyMode::Tun {
        rules.push(json!({
            "type": "field",
            "inboundTag": ["tun-in"],
            "port": 53,
            "outboundTag": "dns-out"
        }));
        if state.block_quic {
            rules.push(json!({
                "type": "field",
                "inboundTag": ["tun-in"],
                "network": "udp",
                "port": 443,
                "outboundTag": "block"
            }));
        }
    }

    // Loop protection for server IPs and private/LAN CIDRs.
    // Explicit CIDRs avoid loading geoip.dat in Global and process-only modes.
    let mut loop_direct_ips: Vec<String> = bootstrap_ips;
    for cidr in [
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ] {
        loop_direct_ips.push(cidr.to_string());
    }

    rules.push(json!({
        "type": "field",
        "ip": loop_direct_ips,
        "outboundTag": "direct"
    }));
    if !bootstrap_domains.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": bootstrap_domains,
            "outboundTag": "direct"
        }));
    }

    // 4.2 Remote DNS protection through proxy (supports both IP and domain-based DoH/DoT/TCP)
    let mut remote_dns_ips: Vec<String> = vec![ip_to_host_cidr(fallback_dns_ip)];
    let mut remote_dns_domains: Vec<String> = Vec::new();
    if let Some(ref host) = remote_dns_host {
        if host.parse::<IpAddr>().is_ok() {
            let cidr = ip_to_host_cidr(host);
            if !remote_dns_ips.contains(&cidr) {
                remote_dns_ips.insert(0, cidr);
            }
        } else {
            remote_dns_domains.push(format!("full:{}", host));
        }
    }
    rules.push(json!({
        "type": "field",
        "ip": remote_dns_ips,
        "port": "53,443,853",
        "outboundTag": "proxy"
    }));
    if !remote_dns_domains.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": remote_dns_domains,
            "port": "53,443,853",
            "outboundTag": "proxy"
        }));
    }

    // 4.3 Preset-specific rules
    match state.routing {
        RoutingPreset::Global => {}
        RoutingPreset::DirectLanAndRu => {
            rules.push(json!({
                "type": "field",
                "domain": [
                    "geosite:category-ru",
                    "regexp:\\.ru$",
                    "regexp:\\.su$",
                    "regexp:\\.xn--p1ai$"
                ],
                "outboundTag": "direct"
            }));
            rules.push(json!({
                "type": "field",
                "ip": ["geoip:ru"],
                "outboundTag": "direct"
            }));
        }
        RoutingPreset::Custom => {
            for r in state.custom_rules.iter().filter(|r| r.enabled) {
                let items: Vec<String> = r
                    .value
                    .split(|c| c == ',' || c == ';')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| normalize_rule_item(r.kind, s))
                    .collect();
                if items.is_empty() {
                    continue;
                }
                let out_tag = resolve_rule_target(state, node, &extra_node_tags, &r.target);
                let field_rule = match r.kind {
                    RuleMatchKind::Process => json!({
                        "type": "field",
                        "process": items,
                        "outboundTag": out_tag
                    }),
                    RuleMatchKind::Domain => json!({
                        "type": "field",
                        "domain": items,
                        "outboundTag": out_tag
                    }),
                    RuleMatchKind::Ip => json!({
                        "type": "field",
                        "ip": items,
                        "outboundTag": out_tag
                    }),
                };
                rules.push(field_rule);
            }
            // Also keep optional legacy routing_custom.txt support when GUI rule list is empty
            if state.custom_rules.is_empty() {
                rules.extend(parse_custom_routing_file());
            }
        }
    }

    // 4.4 Catch-all default rule
    let final_tag = if state.routing == RoutingPreset::Custom
        && state.custom_default_action == RuleDefaultAction::Direct
    {
        "direct"
    } else {
        "proxy"
    };
    rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": final_tag
    }));

    let cfg = json!({
        "log": {
            "access": "none",
            "loglevel": state.log_level.as_xray_str()
        },
        "dns": {
            "servers": dns_servers,
            "queryStrategy": "UseIPv4"
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": state.domain_strategy.as_xray_str(),
            "rules": rules
        }
    });

    serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OutboundOpts {
    pub fragment: bool,
    pub noise: bool,
    pub mux: bool,
}

// Build a minimal multi-inbound Xray config for batch Real Delay (HTTP /generate_204) probing.
pub fn build_batch_test_config(
    batch: &[(usize, VlessNode, u16)],
    bind_interface: Option<&str>,
    opts: OutboundOpts,
) -> Result<(String, Vec<(usize, u16)>), String> {
    let mut inbounds: Vec<Value> = Vec::with_capacity(batch.len());
    let mut outbounds: Vec<Value> = Vec::with_capacity(batch.len());
    let mut rules: Vec<Value> = Vec::with_capacity(batch.len());
    let mut valid: Vec<(usize, u16)> = Vec::with_capacity(batch.len());

    for (slot, (node_idx, node, port)) in batch.iter().enumerate() {
        let out_tag = format!("out-{}", slot);
        let Ok(mut out) = build_node_outbound(&out_tag, node, opts) else {
            continue;
        };
        if let Some(iface) = bind_interface.filter(|s| !s.is_empty()) {
            if let Some(sockopt) = out
                .get_mut("streamSettings")
                .and_then(|s| s.get_mut("sockopt"))
                .and_then(|s| s.as_object_mut())
            {
                sockopt.insert("interface".to_string(), json!(iface));
            }
        }
        let in_tag = format!("in-{}", slot);
        inbounds.push(json!({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": *port,
            "protocol": "http"
        }));
        outbounds.push(out);
        rules.push(json!({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag
        }));
        valid.push((*node_idx, *port));
    }

    if valid.is_empty() {
        return Err("No valid server configurations in batch.".to_string());
    }

    let cfg = json!({
        "log": {
            "access": "none",
            "loglevel": "none"
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        }
    });

    let text = serde_json::to_string(&cfg).map_err(|e| e.to_string())?;
    Ok((text, valid))
}

pub fn validate_remote_dns(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("Remote DNS cannot be empty.".to_string());
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("Remote DNS cannot contain spaces or control characters.".to_string());
    }
    if s.parse::<IpAddr>().is_ok() {
        return Ok(s.to_string());
    }
    const ALLOWED_SCHEMES: &[&str] = &[
        "https://",
        "https+local://",
        "tcp://",
        "tcp+local://",
        "tls://",
        "tls+local://",
        "quic://",
        "quic+local://",
    ];
    if !ALLOWED_SCHEMES.iter().any(|p| s.starts_with(p)) {
        return Err(
            "Remote DNS must be an IP or start with https://, tcp://, tls://, or quic://."
                .to_string(),
        );
    }
    match extract_dns_host(s) {
        Some(h) if !h.is_empty() => Ok(s.to_string()),
        _ => Err("Remote DNS URL is missing a valid host.".to_string()),
    }
}

fn extract_dns_host(addr: &str) -> Option<String> {
    let s = addr.trim();
    if s.is_empty() {
        return None;
    }
    if s.parse::<IpAddr>().is_ok() {
        return Some(s.to_string());
    }
    let after_scheme = match s.split_once("://") {
        Some((_, rest)) => rest,
        None => s,
    };
    let authority = after_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return if host.is_empty() { None } else { Some(host.to_string()) };
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port_str)) if !h.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn resolve_rule_target(
    state: &AppState,
    active_node: &VlessNode,
    extra_tags: &HashMap<usize, String>,
    target: &str,
) -> String {
    match target {
        "direct" => "direct".to_string(),
        "block" => "block".to_string(),
        "proxy" => "proxy".to_string(),
        other => {
            if let Some(name) = other.strip_prefix("node:") {
                if let Some((idx, n)) = state.nodes.iter().enumerate().find(|(_, n)| n.name == name) {
                    if n.uuid == active_node.uuid
                        && n.address == active_node.address
                        && n.port == active_node.port
                        && n.protocol == active_node.protocol
                    {
                        return "proxy".to_string();
                    }
                    if let Some(tag) = extra_tags.get(&idx) {
                        return tag.clone();
                    }
                }
            }
            "proxy".to_string()
        }
    }
}

fn normalize_rule_item(kind: RuleMatchKind, raw: &str) -> String {
    match kind {
        RuleMatchKind::Process => raw.to_string(),
        RuleMatchKind::Ip => raw.to_string(),
        RuleMatchKind::Domain => {
            if raw.starts_with("geosite:")
                || raw.starts_with("domain:")
                || raw.starts_with("full:")
                || raw.starts_with("regexp:")
                || raw.starts_with("keyword:")
            {
                raw.to_string()
            } else {
                format!("domain:{}", raw)
            }
        }
    }
}

fn build_node_outbound(tag: &str, node: &VlessNode, opts: OutboundOpts) -> Result<Value, String> {
    let mut user = json!({
        "id": node.uuid,
        "encryption": if node.encryption.is_empty() { "none" } else { &node.encryption }
    });
    if !node.flow.is_empty() && (node.network == "tcp" || node.network == "raw") {
        user["flow"] = json!(node.flow);
    }

    let mut stream = json!({
        "network": node.network,
        "security": node.security
    });

    match node.security.as_str() {
        "reality" => {
            stream["realitySettings"] = json!({
                "serverName": node.sni,
                "fingerprint": if node.fp.is_empty() { "chrome" } else { &node.fp },
                "publicKey": node.pbk,
                "shortId": node.sid,
                "spiderX": if node.spx.is_empty() { "/" } else { &node.spx }
            });
        }
        "tls" => {
            let mut tls = json!({
                "serverName": if node.sni.is_empty() { &node.address } else { &node.sni }
            });
            if !node.fp.is_empty() {
                tls["fingerprint"] = json!(node.fp);
            }
            if !node.alpn.is_empty() {
                let list: Vec<&str> = node
                    .alpn
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !list.is_empty() {
                    tls["alpn"] = json!(list);
                }
            }
            stream["tlsSettings"] = tls;
        }
        _ => {}
    }

    match node.network.as_str() {
        "ws" => {
            let mut ws = json!({
                "path": if node.path.is_empty() { "/" } else { &node.path }
            });
            if !node.host.is_empty() {
                ws["host"] = json!(node.host);
            }
            stream["wsSettings"] = ws;
        }
        "grpc" => {
            stream["grpcSettings"] = json!({
                "serviceName": node.service_name,
                "multiMode": node.mode == "multi"
            });
        }
        "xhttp" | "splithttp" => {
            let mut xh = json!({
                "path": if node.path.is_empty() { "/" } else { &node.path }
            });
            if !node.host.is_empty() {
                xh["host"] = json!(node.host);
            }
            if !node.mode.is_empty() {
                xh["mode"] = json!(node.mode);
            }
            if !node.extra.is_empty() {
                let extra_val: Value = serde_json::from_str(&node.extra)
                    .map_err(|e| format!("Invalid JSON in XHTTP extra parameter: {}", e))?;
                xh["extra"] = extra_val;
            }
            stream["xhttpSettings"] = xh;
        }
        "httpupgrade" => {
            let mut hu = json!({
                "path": if node.path.is_empty() { "/" } else { &node.path }
            });
            if !node.host.is_empty() {
                hu["host"] = json!(node.host);
            }
            stream["httpupgradeSettings"] = hu;
        }
        _ => {
            if node.header_type == "http" {
                let mut hdr = json!({ "type": "http" });
                let mut req = json!({});
                if !node.path.is_empty() {
                    req["path"] = json!([node.path]);
                }
                if !node.host.is_empty() {
                    req["headers"] = json!({ "Host": [node.host] });
                }
                hdr["request"] = req;
                stream["tcpSettings"] = json!({ "header": hdr });
            }
        }
    }

    stream["sockopt"] = json!({
        "domainStrategy": "UseIPv4"
    });

    // Apply native Xray-core 26.x finalmask TCP TLS Fragment on TCP-based TLS/REALITY transports
    if opts.fragment
        && matches!(node.protocol.as_str(), "vless" | "vmess" | "trojan")
        && matches!(node.security.as_str(), "tls" | "reality")
        && matches!(
            node.network.as_str(),
            "tcp" | "raw" | "ws" | "grpc" | "xhttp" | "splithttp" | "httpupgrade"
        )
    {
        stream["finalmask"] = json!({
            "tcp": [{
                "type": "fragment",
                "settings": {
                    "packets": "tlshello",
                    "lengths": ["10-20"],
                    "delays": ["10-20"]
                }
            }]
        });
    }

    let mut out = match node.protocol.as_str() {
        "trojan" => json!({
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": node.address,
                    "port": node.port,
                    "password": node.uuid
                }]
            },
            "streamSettings": stream
        }),
        "vmess" => json!({
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": node.address,
                    "port": node.port,
                    "users": [{
                        "id": node.uuid,
                        "security": if node.encryption.is_empty() || node.encryption == "none" {
                            "auto"
                        } else {
                            &node.encryption
                        }
                    }]
                }]
            },
            "streamSettings": stream
        }),
        "shadowsocks" => json!({
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": node.address,
                    "port": node.port,
                    "method": if node.ss_method.is_empty() { "aes-256-gcm" } else { &node.ss_method },
                    "password": node.uuid
                }]
            },
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "UseIPv4"
                }
            }
        }),
        "hysteria" => {
            let mut tls = json!({
                "serverName": if node.sni.is_empty() { &node.address } else { &node.sni }
            });
            if !node.alpn.is_empty() {
                let list: Vec<&str> = node
                    .alpn
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !list.is_empty() {
                    tls["alpn"] = json!(list);
                }
            }
            let mut hy_stream = json!({
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": tls,
                "hysteriaSettings": {
                    "version": 2,
                    "auth": node.uuid,
                    "udpIdleTimeout": 60
                },
                "sockopt": {
                    "domainStrategy": "UseIPv4"
                }
            });
            let mut udp_masks: Vec<Value> = Vec::new();
            if node.obfs == "salamander" && !node.obfs_password.is_empty() {
                udp_masks.push(json!({
                    "type": "salamander",
                    "settings": {
                        "password": node.obfs_password
                    }
                }));
            }
            if opts.noise {
                udp_masks.push(json!({
                    "type": "noise",
                    "settings": {
                        "reset": "30-60",
                        "noise": [{
                            "rand": "10-20",
                            "delay": "10-20"
                        }]
                    }
                }));
            }
            if !udp_masks.is_empty() {
                hy_stream["finalmask"] = json!({ "udp": udp_masks });
            }
            json!({
                "tag": tag,
                "protocol": "hysteria",
                "settings": {
                    "version": 2,
                    "address": node.address,
                    "port": node.port
                },
                "streamSettings": hy_stream
            })
        }
        "wireguard" => {
            let addrs: Vec<String> = node
                .wg_address
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let addrs = if addrs.is_empty() {
                vec!["172.16.0.2/32".to_string()]
            } else {
                addrs
            };
            let ep_host = if node.address.contains(':') {
                format!("[{}]", node.address)
            } else {
                node.address.clone()
            };
            let mut peer = json!({
                "publicKey": node.pbk,
                "endpoint": format!("{}:{}", ep_host, node.port),
                "keepAlive": 25
            });
            if !node.sid.is_empty() {
                peer["preSharedKey"] = json!(node.sid);
            }
            let mtu = if node.wg_mtu >= 1280 { node.wg_mtu } else { 1420 };
            let mut wg_settings = json!({
                "secretKey": node.uuid,
                "address": addrs,
                "peers": [peer],
                "mtu": mtu,
                "noKernelTun": true
            });
            let reserved: Vec<u8> = node
                .wg_reserved
                .split(',')
                .filter_map(|s| s.trim().parse::<u8>().ok())
                .collect();
            if reserved.len() == 3 {
                wg_settings["reserved"] = json!(reserved);
            }
            let mut wg_stream = json!({
                "sockopt": {
                    "domainStrategy": "UseIPv4"
                }
            });
            if opts.noise {
                wg_stream["finalmask"] = json!({
                    "udp": [{
                        "type": "noise",
                        "settings": {
                            "reset": "30-60",
                            "noise": [{
                                "rand": "10-20",
                                "delay": "10-20"
                            }]
                        }
                    }]
                });
            }
            json!({
                "tag": tag,
                "protocol": "wireguard",
                "settings": wg_settings,
                "streamSettings": wg_stream
            })
        }
        "socks" => {
            let mut srv = json!({
                "address": node.address,
                "port": node.port
            });
            if !node.proxy_user.is_empty() || !node.uuid.is_empty() {
                srv["users"] = json!([{
                    "user": node.proxy_user,
                    "pass": node.uuid
                }]);
            }
            json!({
                "tag": tag,
                "protocol": "socks",
                "settings": {
                    "servers": [srv]
                },
                "streamSettings": {
                    "sockopt": {
                        "domainStrategy": "UseIPv4"
                    }
                }
            })
        }
        "http" => {
            let mut srv = json!({
                "address": node.address,
                "port": node.port
            });
            if !node.proxy_user.is_empty() || !node.uuid.is_empty() {
                srv["users"] = json!([{
                    "user": node.proxy_user,
                    "pass": node.uuid
                }]);
            }
            let mut http_stream = json!({
                "sockopt": {
                    "domainStrategy": "UseIPv4"
                }
            });
            if node.security == "tls" {
                http_stream["security"] = json!("tls");
                http_stream["tlsSettings"] = json!({
                    "serverName": if node.sni.is_empty() { &node.address } else { &node.sni }
                });
            }
            json!({
                "tag": tag,
                "protocol": "http",
                "settings": {
                    "servers": [srv]
                },
                "streamSettings": http_stream
            })
        }
        _ => json!({
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node.address,
                    "port": node.port,
                    "users": [user]
                }]
            },
            "streamSettings": stream
        }),
    };

    // Apply Mux (XUDP) only on compatible protocols/transports (skip XTLS Vision, XHTTP, QUIC/WG).
    let mux_compat = match node.protocol.as_str() {
        "vless" => {
            !node.flow.to_lowercase().contains("vision")
                && !matches!(node.network.as_str(), "xhttp" | "splithttp")
        }
        "vmess" | "trojan" | "shadowsocks" => {
            !matches!(node.network.as_str(), "xhttp" | "splithttp")
        }
        _ => false,
    };
    if opts.mux && mux_compat {
        out["mux"] = json!({
            "enabled": true,
            "concurrency": 8,
            "xudpConcurrency": 16,
            "xudpProxyUDP443": "reject"
        });
    }

    Ok(out)
}

fn ip_to_host_cidr(ip: &str) -> String {
    if ip.contains('/') {
        ip.to_string()
    } else if ip.contains(':') {
        format!("{}/128", ip)
    } else {
        format!("{}/32", ip)
    }
}

fn parse_custom_routing_file() -> Vec<Value> {
    let p = custom_routing_path();
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((action_raw, rule_raw)) = l.split_once(':') else {
            continue;
        };
        let action = match action_raw.trim().to_lowercase().as_str() {
            "direct" => "direct",
            "proxy" => "proxy",
            "block" => "block",
            _ => continue,
        };
        let rule = rule_raw.trim();
        if rule.is_empty() {
            continue;
        }
        if is_ip_rule(rule) {
            out.push(json!({
                "type": "field",
                "ip": [rule],
                "outboundTag": action
            }));
        } else {
            out.push(json!({
                "type": "field",
                "domain": [rule],
                "outboundTag": action
            }));
        }
    }
    out
}

fn is_ip_rule(rule: &str) -> bool {
    if rule.starts_with("geoip:") {
        return true;
    }
    if rule.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Some((ip_part, prefix_part)) = rule.split_once('/') {
        if ip_part.parse::<IpAddr>().is_ok() && prefix_part.parse::<u8>().is_ok() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::parse_vless_uri;
    use std::path::PathBuf;
    use std::process::Command;

    fn resolve_test_core_bin(core: &PathBuf) -> PathBuf {
        let preferred = core.join("avel-core.exe");
        if preferred.exists() {
            preferred
        } else {
            core.join("xray.exe")
        }
    }

    fn run_xray_test(core: &PathBuf, name: &str, cfg_json: &str) {
        let xray = resolve_test_core_bin(core);
        assert!(xray.exists(), "avel-core.exe (or xray.exe) must exist in core/");
        let tmp = core.join(format!("_ut_{}.json", name));
        std::fs::write(&tmp, cfg_json).unwrap();
        let out = Command::new(&xray)
            .args(["run", "-test", "-c"])
            .arg(&tmp)
            .current_dir(core)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&tmp);
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "xray -test failed for {}: {}",
            name,
            combined
        );
        let unexpected_warn = combined.lines().any(|l| {
            l.contains("[Warning]")
                && !(name == "trojan" && l.contains("The feature Trojan"))
                && !(name == "ss" && l.contains("The feature Shadowsocks"))
        });
        assert!(
            !unexpected_warn,
            "xray -test emitted warning for {}: {}",
            name,
            combined
        );
    }

    #[test]
    fn generated_configs_pass_real_xray_test() {
        let node = parse_vless_uri(
            "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&sid=12ab&spx=%2F&type=tcp#Example-Reality",
        )
        .unwrap();

        let core = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core");
        for mode in [ProxyMode::SystemProxy, ProxyMode::Tun] {
            for routing in [
                RoutingPreset::Global,
                RoutingPreset::DirectLanAndRu,
                RoutingPreset::Custom,
            ] {
                let mut st = AppState::default();
                st.mode = mode;
                st.routing = routing;
                let cfg_json = build_xray_config(&st, &node).unwrap();
                run_xray_test(&core, &format!("{:?}_{:?}", mode, routing), &cfg_json);
            }
        }
    }

    #[test]
    fn pq_xhttp_numeric_and_range_extra_validate_on_real_xray() {
        let core = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core");
        let xray = resolve_test_core_bin(&core);

        // Generate a syntactically valid ML-KEM-768+X25519 VLESS encryption string via xray vlessenc
        let enc_out = Command::new(&xray)
            .args(["vlessenc"])
            .current_dir(&core)
            .output()
            .unwrap();
        let enc_txt = String::from_utf8_lossy(&enc_out.stdout);
        let pq_enc = enc_txt
            .lines()
            .find_map(|l| {
                let t = l.trim();
                if t.contains("mlkem768x25519plus") && t.contains("\"encryption\"") {
                    t.split('"').nth(3).map(|s| s.to_string())
                } else {
                    None
                }
            })
            .expect("xray vlessenc did not emit mlkem768x25519plus encryption string");

        let uuid = "99999999-aaaa-bbbb-cccc-dddddddddddd";
        let extras = [
            (
                "numeric",
                "%7B%22uplinkHTTPMethod%22%3A%22GET%22%2C%22uplinkDataPlacement%22%3A%22header%22%2C%22uplinkDataKey%22%3A%22X-Frame-Data%22%2C%22uplinkChunkSize%22%3A3000%2C%22scMaxEachPostBytes%22%3A4500%2C%22scMinPostsIntervalMs%22%3A5%2C%22noSSEHeader%22%3Atrue%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A16%2C%22maxConnections%22%3A0%2C%22cMaxReuseTimes%22%3A0%2C%22hMaxRequestTimes%22%3A600%2C%22hMaxReusableSecs%22%3A300%2C%22hKeepAlivePeriod%22%3A5%7D%7D",
            ),
            (
                "ranges",
                "%7B%22uplinkHTTPMethod%22%3A%22GET%22%2C%22uplinkDataPlacement%22%3A%22header%22%2C%22uplinkDataKey%22%3A%22X-Frame-Data%22%2C%22uplinkChunkSize%22%3A%222600-3400%22%2C%22scMaxEachPostBytes%22%3A%223800-5400%22%2C%22scMinPostsIntervalMs%22%3A%223-8%22%2C%22noSSEHeader%22%3Atrue%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-24%22%2C%22maxConnections%22%3A0%2C%22cMaxReuseTimes%22%3A0%2C%22hMaxRequestTimes%22%3A600%2C%22hMaxReusableSecs%22%3A300%2C%22hKeepAlivePeriod%22%3A5%7D%7D",
            ),
        ];

        for (label, extra) in extras {
            let uri = format!(
                "vless://{}@198.51.100.10:443?encryption={}&security=tls&sni=cdn-edge.example.net&fp=firefox&alpn=h2%2Chttp%2F1.1&type=xhttp&host=app.example.org&path=%2Fapi%2Fv2%2Fsync%2F&mode=packet-up&extra={}#PQ-XHTTP",
                uuid, pq_enc, extra
            );
            let node = parse_vless_uri(&uri).unwrap();
            let mut st = AppState::default();
            st.mode = ProxyMode::Tun;
            st.routing = RoutingPreset::Global;
            let cfg_json = build_xray_config(&st, &node).unwrap();

            assert_eq!(cfg_json.matches(uuid).count(), 1);
            assert!(cfg_json.contains("\"serverName\": \"cdn-edge.example.net\""));
            assert!(cfg_json.contains("\"host\": \"app.example.org\""));
            run_xray_test(&core, &format!("pq_xhttp_{}", label), &cfg_json);
        }
    }

    #[test]
    fn tun_and_ru_routing_validate_without_warnings_on_real_xray() {
        let core = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("core");
        let node = parse_vless_uri(
            "vless://11111111-1111-1111-1111-111111111111@node.example.com:443?security=tls&sni=node.example.com&type=tcp#Node1",
        )
        .unwrap();

        // Global mode must NOT reference geoip/geosite (zero .dat load) and must NOT include RU DNS
        let mut st_global = AppState::default();
        st_global.mode = ProxyMode::Tun;
        st_global.routing = RoutingPreset::Global;
        st_global.kill_switch = true;
        let cfg_global = build_xray_config(&st_global, &node).unwrap();
        assert!(!cfg_global.contains("geoip:"));
        assert!(!cfg_global.contains("geosite:"));
        assert!(!cfg_global.contains("77.88.8.8"));
        assert!(cfg_global.contains("allexceptlan"));
        run_xray_test(&core, "global_killswitch", &cfg_global);

        // DirectLanAndRu includes scoped RU GeoDNS and geoip/geosite RU rules
        for mode in [ProxyMode::SystemProxy, ProxyMode::Tun] {
            let mut st = AppState::default();
            st.mode = mode;
            st.routing = RoutingPreset::DirectLanAndRu;

            let cfg_json = build_xray_config(&st, &node).unwrap();
            assert!(!cfg_json.contains("fd21:"));
            assert!(cfg_json.contains("https+local://8.8.4.4/dns-query"));
            assert!(cfg_json.contains("https+local://77.88.8.8/dns-query"));
            assert!(cfg_json.contains("https://1.1.1.1/dns-query"));
            assert!(cfg_json.contains("\"domainStrategy\": \"IPIfNonMatch\""));
            assert!(cfg_json.contains("geosite:category-ru"));
            assert!(cfg_json.contains("geoip:ru"));
            run_xray_test(&core, &format!("ru_ipifnonmatch_{:?}", mode), &cfg_json);
        }

        // Trojan and Shadowsocks outbounds validate on real Xray 26.11.9
        let tr = crate::vless::parse_trojan_uri(
            "trojan://secretpass@tr.example.com:443?security=tls&sni=tr.example.com&fp=chrome#TR",
        )
        .unwrap();
        let ss = crate::vless::parse_ss_uri(
            "ss://YWVzLTI1Ni1nY206bXlwYXNz@ss.example.com:8388#SS",
        )
        .unwrap();
        for (tag, n) in [("trojan", tr), ("ss", ss)] {
            let mut st = AppState::default();
            st.mode = ProxyMode::Tun;
            st.routing = RoutingPreset::Global;
            let cfg = build_xray_config(&st, &n).unwrap();
            run_xray_test(&core, tag, &cfg);
        }

        // Multi-server, per-process, and whitelist routing rules
        let n1 = parse_vless_uri(
            "vless://11111111-1111-1111-1111-111111111111@se.example.com:443?security=tls&sni=se.example.com&type=tcp#Stockholm",
        )
        .unwrap();
        let n2 = parse_vless_uri(
            "vless://22222222-2222-2222-2222-222222222222@al.example.com:443?security=tls&sni=al.example.com&type=tcp#Tirana",
        )
        .unwrap();
        let mut st_div = AppState::default();
        st_div.mode = ProxyMode::Tun;
        st_div.routing = RoutingPreset::Custom;
        st_div.custom_default_action = RuleDefaultAction::Direct;
        st_div.nodes = vec![n1.clone(), n2];
        st_div.custom_rules = vec![
            crate::model::RoutingRule {
                enabled: true,
                kind: RuleMatchKind::Process,
                value: "chrome.exe, discord.exe".to_string(),
                target: "node:Tirana".to_string(),
            },
            crate::model::RoutingRule {
                enabled: true,
                kind: RuleMatchKind::Domain,
                value: "youtube.com, openai.com".to_string(),
                target: "proxy".to_string(),
            },
            crate::model::RoutingRule {
                enabled: true,
                kind: RuleMatchKind::Process,
                value: "steam.exe".to_string(),
                target: "direct".to_string(),
            },
        ];
        let cfg_div = build_xray_config(&st_div, &n1).unwrap();
        assert!(cfg_div.contains("\"tag\": \"node-1\""));
        assert!(cfg_div.contains("\"full:al.example.com\""));
        assert!(cfg_div.contains("\"chrome.exe\""));
        assert!(cfg_div.contains("\"domain:youtube.com\""));
        assert!(!cfg_div.contains("geoip:"));
        assert!(!cfg_div.contains("geosite:"));
        run_xray_test(&core, "multi_process_rules", &cfg_div);

        // Settings tab options: custom MTU, QUIC allowed, Allow LAN, custom DNS (IP & domain),
        // custom loglevel and domainStrategy.
        let mut st_set = AppState::default();
        st_set.mode = ProxyMode::Tun;
        st_set.routing = RoutingPreset::Global;
        st_set.tun_mtu = 1400;
        st_set.block_quic = false;
        st_set.allow_lan = true;
        st_set.socks_port = 10818;
        st_set.http_port = 10819;
        st_set.remote_dns = "https://dns.adguard-dns.com/dns-query".to_string();
        st_set.log_level = crate::model::XrayLogLevel::Info;
        st_set.domain_strategy = crate::model::DomainStrategy::AsIs;
        let cfg_set = build_xray_config(&st_set, &n1).unwrap();
        assert!(cfg_set.contains("\"mtu\": 1400"));
        assert!(cfg_set.contains("\"listen\": \"0.0.0.0\""));
        assert!(cfg_set.contains("\"loglevel\": \"info\""));
        assert!(cfg_set.contains("\"domainStrategy\": \"AsIs\""));
        assert!(cfg_set.contains("\"full:dns.adguard-dns.com\""));
        assert!(!cfg_set.contains("\"network\": \"udp\""));
        run_xray_test(&core, "settings_custom_dns_domain", &cfg_set);

        let mut st_dns_ip = st_set.clone();
        st_dns_ip.remote_dns = "https://8.8.8.8/dns-query".to_string();
        st_dns_ip.log_level = crate::model::XrayLogLevel::None;
        st_dns_ip.domain_strategy = crate::model::DomainStrategy::IpOnDemand;
        let cfg_dns_ip = build_xray_config(&st_dns_ip, &n1).unwrap();
        assert!(cfg_dns_ip.contains("\"8.8.8.8/32\""));
        assert!(cfg_dns_ip.contains("\"loglevel\": \"none\""));
        assert!(cfg_dns_ip.contains("\"domainStrategy\": \"IPOnDemand\""));
        run_xray_test(&core, "settings_custom_dns_ip", &cfg_dns_ip);

        let mut st_sniff_route = st_set.clone();
        st_sniff_route.enable_sniffing = true;
        st_sniff_route.sniffing_dest_override = false;
        let cfg_sniff_route = build_xray_config(&st_sniff_route, &n1).unwrap();
        assert!(cfg_sniff_route.contains("\"routeOnly\": true"));
        assert!(cfg_sniff_route.contains("\"destOverride\""));
        run_xray_test(&core, "sniffing_route_only", &cfg_sniff_route);

        let mut st_sniff_off = st_set.clone();
        st_sniff_off.enable_sniffing = false;
        st_sniff_off.sniffing_dest_override = false;
        let cfg_sniff_off = build_xray_config(&st_sniff_off, &n1).unwrap();
        assert!(cfg_sniff_off.contains("\"enabled\": false"));
        assert!(!cfg_sniff_off.contains("\"destOverride\""));
        run_xray_test(&core, "sniffing_disabled", &cfg_sniff_off);
    }

    #[test]
    fn new_protocols_and_finalmask_pass_real_xray_test() {
        let core = crate::model::core_binary_path().expect("core/avel-core.exe must exist");
        let run_ok = |name: &str, cfg: &str| {
            let p = crate::model::core_dir().join(format!("_ut_{}.json", name));
            std::fs::write(&p, cfg).unwrap();
            let out = std::process::Command::new(&core)
                .args(["run", "-test", "-c"])
                .arg(&p)
                .current_dir(crate::model::core_dir())
                .output()
                .unwrap();
            let _ = std::fs::remove_file(&p);
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.status.success(),
                "xray -test failed for {}: {}",
                name,
                combined
            );
        };

        let vmess_uri = format!(
            "vmess://{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                br#"{"v":"2","ps":"VM","add":"vm.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","scy":"auto","net":"ws","host":"vm.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}"#
            )
        );
        let n_vmess = crate::vless::parse_vmess_uri(&vmess_uri).unwrap();
        let n_hy2 = crate::vless::parse_hysteria2_uri(
            "hy2://secret@hy.example.com:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=salpass#Hy2",
        )
        .unwrap();
        let n_wg = crate::vless::parse_wireguard_uri(
            "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@wg.example.com:51820?publickey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB%3D&address=172.16.0.2%2F32&reserved=1,2,3&mtu=1280#WG",
        )
        .unwrap();
        let n_socks =
            crate::vless::parse_socks_uri("socks5://alice:bob@socks.example.com:1080#Socks")
                .unwrap();
        let n_http =
            crate::vless::parse_http_proxy_uri("http://u1:p1@proxy.example.com:8080#Http").unwrap();
        let n_vless_tls = parse_vless_uri(
            "vless://11111111-1111-1111-1111-111111111111@v.example.com:443?security=tls&sni=v.example.com&type=tcp#VlessTls",
        )
        .unwrap();

        let mut st_adv = AppState::default();
        st_adv.mode = ProxyMode::SystemProxy;
        st_adv.enable_fragment = true;
        st_adv.enable_noise = true;
        st_adv.enable_mux = true;

        let cfg_vless = build_xray_config(&st_adv, &n_vless_tls).unwrap();
        assert!(cfg_vless.contains("\"fragment\""));
        assert!(cfg_vless.contains("\"xudpConcurrency\": 16"));
        run_ok("vless_fragment_mux", &cfg_vless);

        let cfg_vmess = build_xray_config(&st_adv, &n_vmess).unwrap();
        run_ok("vmess_fragment_mux", &cfg_vmess);

        let cfg_hy2 = build_xray_config(&st_adv, &n_hy2).unwrap();
        assert!(cfg_hy2.contains("\"hysteriaSettings\""));
        assert!(cfg_hy2.contains("\"salamander\""));
        assert!(cfg_hy2.contains("\"noise\""));
        run_ok("hysteria2_salamander_noise", &cfg_hy2);

        let cfg_wg = build_xray_config(&st_adv, &n_wg).unwrap();
        assert!(cfg_wg.contains("\"noKernelTun\": true"));
        run_ok("wireguard_noise", &cfg_wg);

        let cfg_socks = build_xray_config(&st_adv, &n_socks).unwrap();
        run_ok("socks5_outbound", &cfg_socks);

        let cfg_http = build_xray_config(&st_adv, &n_http).unwrap();
        run_ok("http_outbound", &cfg_http);

        let (batch_cfg, valid_entries) = build_batch_test_config(
            &[(0, n_vless_tls, 19411), (1, n_hy2, 19412), (2, n_socks, 19413)],
            Some("Wi-Fi"),
            OutboundOpts::default(),
        )
        .unwrap();
        assert_eq!(valid_entries.len(), 3);
        run_ok("batch_real_ping", &batch_cfg);
    }
}
