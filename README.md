# avel-xray

Native Win32 VPN client for Xray-core on Windows x64, written in Rust directly against the Windows API. No Electron, Qt, Flutter, or WebView2 runtime.

## Features

- **Protocols**: VLESS (Reality, TLS, XHTTP / SplitHTTP, WebSocket, gRPC, HTTPUpgrade, post-quantum ML-KEM-768+X25519), Trojan, and Shadowsocks (including SS-2022).
- **Proxy and TUN modes**: System Proxy for non-elevated use, or full-device TUN via Wintun with automatic UAC relaunch, route/metric enforcement, and pre-VPN TCP socket reset.
- **Leak protection**: IPv4-only TUN routing, built-in DoH DNS interception, optional WFP Kill-Switch (`allexceptlan`), and optional QUIC (UDP/443) blocking.
- **Routing tab**: per-process (`.exe` or folder, with file picker and running-app menu), domain / `geosite:`, and IP / `geoip:` rules targeting Active Server, Direct, Block, or another node from the subscription. Supports proxy-by-default and whitelist modes.
- **Settings tab**: custom TUN MTU (`1280`-`9000`), SOCKS/HTTP ports, `Allow LAN`, custom Remote DNS, Xray log level (`warning` / `info` / `error` / `none`), `domainStrategy`, Go memory profile (`GOGC=50` or `100`), custom subscription `User-Agent`, launch options, and HTTPS `geoip.dat` / `geosite.dat` updates.
- **Small footprint**: ~700 KB executable, ~5 MB GUI private memory, 0 MB GPU VRAM, and optional elevated logon autostart via Task Scheduler (no 24/7 background service).

## Download

1. Download `avel-xray-<version>-windows-x64.zip` from [Releases](https://github.com/nikolaevichsmor/avel-xray/releases).
2. Extract the archive to any folder and run `avel.exe`.
3. Paste a subscription URL or a `vless://` / `trojan://` / `ss://` link, click **Update**, pick a server, and click **Connect**.

Release archives are built directly by GitHub Actions from this repository and bundled with SHA256-verified official `Xray-core` and `Wintun` binaries.

## Build from source

Requirements: Windows x64 and the Rust toolchain (`rustup`).

1. Place the following runtime files into `core/`:
   - `avel-core.exe` (official `xray.exe` from [XTLS/Xray-core](https://github.com/XTLS/Xray-core/releases))
   - `wintun.dll` (amd64 build from [wintun.net](https://www.wintun.net/))
   - `geoip.dat` and `geosite.dat` (from Xray-core release or [XTLS/Xray-rules-dat](https://github.com/XTLS/Xray-rules-dat))
2. Run tests and build:

```powershell
cargo test
cargo build --release
```

The compiled executable is written to `target/release/avel.exe`. Copy it next to the `core/` folder.

## License

Licensed under [GNU GPL-3.0](LICENSE). See [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt) for bundled component notices (`Xray-core` MPL-2.0, `Wintun` GPL-2.0, `Xray-rules-dat`).
