<h1>
  <img src="assets/logo.svg" alt="avel-xray" width="64" height="64" align="absmiddle">&nbsp;&nbsp;avel-xray
</h1>

<p>
  <a href="https://github.com/nikolaevichsmor/avel-xray/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/nikolaevichsmor/avel-xray/release.yml?label=build" alt="build"></a>
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases/latest"><img src="https://img.shields.io/github/v/release/nikolaevichsmor/avel-xray?label=version" alt="version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/nikolaevichsmor/avel-xray" alt="license"></a>
  <img src="https://img.shields.io/github/commit-activity/m/nikolaevichsmor/avel-xray" alt="commit activity">
  <a href="https://github.com/nikolaevichsmor/avel-xray/releases/latest"><img src="https://img.shields.io/github/release-date/nikolaevichsmor/avel-xray?label=release%20date" alt="release date"></a>
</p>

Native Win32 VPN client for Xray-core on Windows x64, written in Rust directly against the Windows API.

## Why avel-xray?

Most desktop Xray clients bundle a browser engine, Flutter, Qt, or .NET runtime, taking 80-250 MB of RAM and holding GPU VRAM even when sitting in the tray. `avel-xray` is a ~700 KB native Win32 executable that stays around 5 MB of RAM and 0 MB of VRAM, so it never wakes a laptop discrete GPU or eats memory in the background. In Global and process-only modes it skips loading `geoip.dat` and `geosite.dat` altogether, keeping `avel-core.exe` light too.

There is no 24/7 SYSTEM background service. `avel-core.exe` only runs while connected inside a Windows Job Object, and elevated TUN autostart uses a regular Task Scheduler logon task with no UAC prompt. When TUN starts, the client resets stale pre-VPN browser TCP sockets on Wi-Fi/Ethernet, enforces `Metric=0` and `0.0.0.0/0` across Windows network init, flushes DNS, and supports a WFP Kill-Switch (`allexceptlan`), DoH DNS interception, QUIC (UDP/443) blocking, and automatic reconnect after sleep.

It supports VLESS (Reality, TLS, XHTTP / SplitHTTP, WebSocket, gRPC, HTTPUpgrade, post-quantum ML-KEM-768+X25519), Trojan, and Shadowsocks (including SS-2022) in both System Proxy and Wintun TUN modes. You can split traffic by `.exe`, folder, domain (`geosite:`), or IP (`geoip:`) to Direct, Block, the active server, or another node from your subscription, and adjust TUN MTU, local ports, `Allow LAN`, custom Remote DNS, log level, Go memory profile, and HTTPS Geo database updates from the Settings tab. Release archives are compiled directly by GitHub Actions with SHA256-verified official `Xray-core` and `Wintun` binaries, DLL loading is locked to `System32`, and temporary configs are removed on disconnect.

## Download

1. Download `avel-xray-<version>-windows-x64.zip` from [Releases](https://github.com/nikolaevichsmor/avel-xray/releases).
2. Extract to any folder and run `avel.exe` (portable, no installer).
3. Paste a subscription URL or a `vless://` / `trojan://` / `ss://` link, click **Update**, pick a server, and click **Connect**.

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
