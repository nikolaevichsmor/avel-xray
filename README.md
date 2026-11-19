<p>
  <img src="assets/logo.svg" alt="avel-xray" width="96" height="96">
</p>

# avel-xray

<p>
  <a href="https://github.com/nikolaevichsmor/avel-xray/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/nikolaevichsmor/avel-xray/release.yml?label=build" alt="build"></a>
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases/latest"><img src="https://img.shields.io/github/v/release/nikolaevichsmor/avel-xray?label=version" alt="version"></a>
  <img src="https://img.shields.io/github/repo-size/nikolaevichsmor/avel-xray" alt="repo size">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/nikolaevichsmor/avel-xray" alt="license"></a>
  <br>
  <img src="https://img.shields.io/github/commit-activity/m/nikolaevichsmor/avel-xray" alt="commit activity">
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases/latest"><img src="https://img.shields.io/github/release-date/nikolaevichsmor/avel-xray?label=release%20date" alt="release date"></a>
  <a href="https://github.com/nikolaevichsmor/avel-xray/stargazers"><img src="https://img.shields.io/github/stars/nikolaevichsmor/avel-xray?style=social" alt="Stars"></a>
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases"><img src="https://img.shields.io/github/downloads/nikolaevichsmor/avel-xray/total?label=downloads" alt="downloads"></a>
</p>

Native Win32 VPN client for Xray-core on Windows x64, written in Rust directly against the Windows API. Built to stay fast, quiet, and battery-friendly without Electron, Qt, Flutter, or WebView2.

## Why avel-xray

| | Electron / Flutter / Qt clients | avel-xray |
| :--- | :--- | :--- |
| GUI stack | Chromium / Skia / Qt6 / .NET | Native Win32 API (Rust) |
| GUI memory | ~80-250 MB RAM | ~5 MB RAM |
| GPU VRAM | ~30-120 MB (can wake dGPU) | 0 MB |
| GUI executable | ~30-120 MB | ~700 KB |
| Background service | 24/7 SYSTEM daemon | None |

- **Zero GPU overhead**: pure Win32 GDI never initializes Direct3D/OpenGL or wakes a laptop discrete GPU.
- **Low core RAM**: Global and process-only modes use explicit LAN CIDRs so `geoip.dat` / `geosite.dat` are not loaded into RAM unless routing rules need them (paired with a `Low RAM` Go GC profile).
- **No permanent background daemon**: `avel-core.exe` runs inside a Windows Job Object only while connected. Elevated TUN autostart uses a standard Task Scheduler logon entry with no UAC prompt.
- **No stale browser leaks on connect**: switching to TUN resets pre-existing external TCP sockets on physical adapters, enforces `Metric=0` and `0.0.0.0/0` across Windows PnP/NLA init, and flushes DNS automatically.
- **Per-app and multi-server routing**: split traffic by `.exe`, folder, domain (`geosite:`), or IP (`geoip:`) to Direct, Block, Active Server, or a specific node from your subscription, with proxy-by-default or whitelist mode.
- **Hardened and verifiable**: DLL search order locked to `System32`, temporary `runtime_config.json` deleted on disconnect, and release builds compiled directly by GitHub Actions with SHA256-verified official `Xray-core` and `Wintun` binaries.

## Download

1. Download `avel-xray-<version>-windows-x64.zip` from [Releases](https://github.com/nikolaevichsmor/avel-xray/releases).
2. Extract to any folder and run `avel.exe` (fully portable, no installer).
3. Paste a subscription URL or a `vless://` / `trojan://` / `ss://` link, click **Update**, pick a server, and click **Connect**.

## Features

- **Protocols**: VLESS (Reality, TLS, XHTTP / SplitHTTP, WebSocket, gRPC, HTTPUpgrade, post-quantum ML-KEM-768+X25519), Trojan, and Shadowsocks (including SS-2022).
- **Modes & protection**: System Proxy (no admin required) or full-device Wintun TUN, IPv4-only leak prevention, built-in DoH DNS interception, optional WFP Kill-Switch (`allexceptlan`), optional QUIC (UDP/443) blocking, and sleep/resume auto-reconnect.
- **Diagnostics**: direct physical-interface TCP ping (`Ping All`), end-to-end tunnel latency check (`Test 204`), and live NDIS traffic speed/total in the status bar.
- **Settings tab**: custom TUN MTU (`1280`-`9000`), SOCKS/HTTP ports, `Allow LAN`, custom Remote DNS, Xray log level (`warning` / `info` / `error` / `none`), `domainStrategy`, Go memory profile (`Low RAM` / `Performance`), custom subscription `User-Agent`, launch options, and one-click HTTPS `geoip.dat` / `geosite.dat` updates.

## Build from source

Requirements: Windows x64 and the Rust toolchain (`rustup`).

1. Place runtime files into `core/`:
   - `avel-core.exe` (official `xray.exe` from [XTLS/Xray-core](https://github.com/XTLS/Xray-core/releases))
   - `wintun.dll` (amd64 build from [wintun.net](https://www.wintun.net/))
   - `geoip.dat` and `geosite.dat` (from Xray-core release or [XTLS/Xray-rules-dat](https://github.com/XTLS/Xray-rules-dat))
2. Run tests and build:

```powershell
cargo test
cargo build --release
```

Copy `target/release/avel.exe` next to the `core/` folder.

## License

Licensed under [GNU GPL-3.0](LICENSE). Bundled components are listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
