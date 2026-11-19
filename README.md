<h1>
  <img src="assets/logo.svg" alt="avel-xray" width="64" height="64" align="absmiddle">&nbsp;&nbsp;avel-xray
</h1>

<p>
  <a href="https://github.com/nikolaevichsmor/avel-xray/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/nikolaevichsmor/avel-xray/release.yml?label=build" alt="build"></a>
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases/latest"><img src="https://img.shields.io/github/v/release/nikolaevichsmor/avel-xray?label=version" alt="version"></a>
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases/latest"><img src="https://img.shields.io/github/release-date/nikolaevichsmor/avel-xray?label=release%20date" alt="release date"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/nikolaevichsmor/avel-xray" alt="license"></a>
  <a href="https://github.com/XTLS/Xray-core"><img src="https://img.shields.io/badge/core-Xray%20v26.11.9-2563EB" alt="core"></a>
  <a href="https://www.wintun.net/"><img src="https://img.shields.io/badge/TUN-Wintun-0EA5E9" alt="TUN"></a>
</p>

Native Win32 VPN client for Xray-core on Windows x64, written in Rust directly against the Windows API.

## Why avel-xray?

### Lightweight by design

Most desktop Xray clients bundle a browser engine, Flutter, Qt, or .NET runtime, taking **80-250 MB of RAM** and holding GPU VRAM for the UI alone even when sitting in the tray. `avel-xray` is a **~700 KB** native Win32 executable whose GUI stays around **3-5 MB of RAM** and **0 MB of VRAM** (plus `avel-core.exe` itself), so it **never wakes a laptop discrete GPU** or eats memory in the background. In Global and process-only modes it skips loading `geoip.dat` and `geosite.dat` altogether, keeping `avel-core.exe` light too.

### Clean TUN networking & leak protection

There is **no 24/7 SYSTEM background service**. `avel-core.exe` runs inside a Windows Job Object only while connected, and elevated TUN autostart uses a standard Task Scheduler logon task with **no UAC prompt**. When TUN starts, the client **resets stale pre-VPN browser TCP sockets** on Wi-Fi/Ethernet, locks `Metric=0` and `0.0.0.0/0` across Windows network init, flushes DNS, and supports a native **WFP Kill-Switch** (`allexceptlan`), **DoH DNS interception**, QUIC (`UDP/443`) blocking, and automatic reconnect after sleep.

### Protocols, routing & verifiable builds

Supports **VLESS** (Reality, TLS, XHTTP / SplitHTTP, WebSocket, gRPC, HTTPUpgrade, post-quantum ML-KEM-768+X25519), **Trojan**, and **Shadowsocks** (including SS-2022) in both **System Proxy** and **Wintun TUN** modes. Route traffic by `.exe`, folder, domain (`geosite:`), or IP (`geoip:`) to Direct, Block, the active server, or another node from your subscription, and configure **TUN MTU**, local ports, `Allow LAN`, custom Remote DNS, log level, Go memory profile, and HTTPS Geo updates in the Settings tab. Release archives are compiled directly by **GitHub Actions** with **SHA256-verified** official `Xray-core` and `Wintun` binaries, DLL loading is locked to `System32`, and temporary configs are deleted on disconnect.

## Download

1. Download `avel-xray-<version>-windows-x64.zip` from [Releases](https://github.com/nikolaevichsmor/avel-xray/releases).
2. Extract to any folder and run `avel.exe` (portable, no installer).
3. Paste a subscription URL or a `vless://` / `trojan://` / `ss://` link, click **Update**, pick a server, and click **Connect**.

> [!NOTE]
> **System Proxy** works with standard user permissions. Switching to **TUN mode** automatically requests UAC elevation once; enabling **Autostart** while elevated registers a silent logon task with no UAC prompt on reboot.

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
