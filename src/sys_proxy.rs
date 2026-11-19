use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, GetAdaptersAddresses, GetBestInterface, GetExtendedTcpTable,
    GetIfEntry2, GetIpInterfaceEntry, InitializeIpForwardEntry, SetIpForwardEntry2,
    SetIpInterfaceEntry, SetTcpEntry, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject, CREATE_NO_WINDOW,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

// Restrict DLL loading to System32 when running elevated from a user-writable folder.
pub fn harden_dll_search_order() {
    unsafe {
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
}

fn system32_exe(exe_name: &str) -> std::path::PathBuf {
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len > 0 && len < buf.len() {
        let dir = String::from_utf16_lossy(&buf[..len]);
        return std::path::PathBuf::from(dir).join(exe_name);
    }
    std::path::PathBuf::from(r"C:\Windows\System32").join(exe_name)
}

const INET_SETTINGS_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const AUTOSTART_VAL_NAME: &str = "Avel";
const AUTOSTART_TASK_NAME: &str = "AvelAutostart";

pub fn enable_system_proxy(http_port: u16) -> Result<(), String> {
    let server = format!("127.0.0.1:{}", http_port);
    let bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey = to_wide(INET_SETTINGS_SUBKEY);
        let rc = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey);
        if rc != 0 {
            return Err(format!("RegOpenKeyExW failed: {}", rc));
        }
        let enable_val: u32 = 1;
        let k_enable = to_wide("ProxyEnable");
        let k_server = to_wide("ProxyServer");
        let k_override = to_wide("ProxyOverride");
        let w_server = to_wide(&server);
        let w_bypass = to_wide(bypass);

        let r1 = RegSetValueExW(
            hkey,
            k_enable.as_ptr(),
            0,
            REG_DWORD,
            &enable_val as *const u32 as *const u8,
            4,
        );
        let r2 = RegSetValueExW(
            hkey,
            k_server.as_ptr(),
            0,
            REG_SZ,
            w_server.as_ptr() as *const u8,
            (w_server.len() * 2) as u32,
        );
        let r3 = RegSetValueExW(
            hkey,
            k_override.as_ptr(),
            0,
            REG_SZ,
            w_bypass.as_ptr() as *const u8,
            (w_bypass.len() * 2) as u32,
        );
        RegCloseKey(hkey);

        if r1 != 0 || r2 != 0 || r3 != 0 {
            return Err(format!("RegSetValueExW failed: {}, {}, {}", r1, r2, r3));
        }

        InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0);
        InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0);
    }
    Ok(())
}

// Flush Windows DNS cache via System32\dnsapi.dll!DnsFlushResolverCache.
pub fn flush_dns_cache() {
    unsafe {
        let dll = to_wide("dnsapi.dll");
        let hmod = LoadLibraryExW(dll.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if hmod.is_null() {
            return;
        }
        let proc = GetProcAddress(hmod, b"DnsFlushResolverCache\0".as_ptr());
        if let Some(f) = proc {
            let func: unsafe extern "system" fn() -> i32 = std::mem::transmute(f);
            let _ = func();
        }
        FreeLibrary(hmod);
    }
}

pub fn notify_network_change() {
    unsafe {
        InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0);
        InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0);
    }
}

unsafe fn wide_ptr_to_str(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 260 && *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

fn find_adapter_by_name(target_name: &str) -> Option<(u32, NET_LUID_LH)> {
    unsafe {
        let mut buf_len: u32 = 32 * 1024;
        // u64 backing guarantees 8-byte alignment required by IP_ADAPTER_ADDRESSES_LH
        let mut buf = vec![0u64; ((buf_len as usize) + 7) / 8];
        let mut rc = GetAdaptersAddresses(
            AF_INET as u32,
            0,
            null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        );
        // ERROR_BUFFER_OVERFLOW (111): resize to OS-requested length and retry once
        if rc == 111 && buf_len > 0 && buf_len <= 1024 * 1024 {
            buf.resize(((buf_len as usize) + 7) / 8, 0);
            rc = GetAdaptersAddresses(
                AF_INET as u32,
                0,
                null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            );
        }
        if rc != 0 {
            return None;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            let fname = wide_ptr_to_str(a.FriendlyName);
            if fname.eq_ignore_ascii_case(target_name) {
                let idx = a.Anonymous1.Anonymous.IfIndex;
                if idx > 0 {
                    return Some((idx, a.Luid));
                }
            }
            cur = a.Next;
        }
        None
    }
}

pub fn best_ipv4_route_if_index() -> Option<u32> {
    unsafe {
        let mut best_idx: u32 = 0;
        // 1.1.1.1 in network byte order
        let dest = u32::from_ne_bytes([1, 1, 1, 1]);
        if GetBestInterface(dest, &mut best_idx) == 0 && best_idx > 0 {
            Some(best_idx)
        } else {
            None
        }
    }
}

pub fn find_adapter_luid(tun_name: &str) -> Option<u64> {
    let (_, luid) = find_adapter_by_name(tun_name)?;
    Some(unsafe { luid.Value })
}

// Read cumulative (rx_bytes, tx_bytes) for an interface LUID.
pub fn query_luid_octets(luid_val: u64) -> Option<(u64, u64)> {
    unsafe {
        let mut row: MIB_IF_ROW2 = std::mem::zeroed();
        row.InterfaceLuid = NET_LUID_LH { Value: luid_val };
        if GetIfEntry2(&mut row) == 0 {
            Some((row.InOctets, row.OutOctets))
        } else {
            None
        }
    }
}

// Force Metric=0 and 0.0.0.0/0 on the TUN adapter so it beats physical interfaces.
pub fn enforce_tun_route_and_metric(tun_name: &str) -> Option<(u32, bool)> {
    let mut found = None;
    for _ in 0..12 {
        if let Some(pair) = find_adapter_by_name(tun_name) {
            found = Some(pair);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let (tun_idx, luid) = found?;

    unsafe {
        let mut ipif: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        ipif.Family = AF_INET;
        ipif.InterfaceLuid = luid;
        ipif.InterfaceIndex = tun_idx;
        if GetIpInterfaceEntry(&mut ipif) == 0 {
            ipif.UseAutomaticMetric = 0;
            ipif.Metric = 0;
            // Required by Win32 SetIpInterfaceEntry for AF_INET
            ipif.SitePrefixLength = 0;
            let _ = SetIpInterfaceEntry(&mut ipif);
        }

        let mut route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut route);
        route.InterfaceLuid = luid;
        route.InterfaceIndex = tun_idx;
        route.DestinationPrefix.Prefix.si_family = AF_INET;
        route.DestinationPrefix.PrefixLength = 0;
        route.NextHop.si_family = AF_INET;
        route.Metric = 0;
        route.Protocol = 3; // MIB_IPPROTO_NETMGMT
        if CreateIpForwardEntry2(&route) != 0 {
            let _ = SetIpForwardEntry2(&route);
        }
    }

    let wins_best = best_ipv4_route_if_index() == Some(tun_idx);
    Some((tun_idx, wins_best))
}

fn is_pid_alive(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        // WAIT_TIMEOUT == 258 means process has not signaled exit
        let alive = WaitForSingleObject(h, 0) == 258;
        CloseHandle(h);
        alive
    }
}

// Re-check default route shortly after Wintun comes up in case Windows NLA resets metrics.
pub fn spawn_tun_post_pnp_guard(
    tun_name: &'static str,
    xray_pid: u32,
    on_log: impl Fn(String) + Send + 'static,
) {
    std::thread::spawn(move || {
        for &delay_ms in &[450u64, 650, 1100] {
            std::thread::sleep(Duration::from_millis(delay_ms));
            if !is_pid_alive(xray_pid) {
                return;
            }
            if let Some((tun_idx, _)) = find_adapter_by_name(tun_name) {
                let drifted = best_ipv4_route_if_index() != Some(tun_idx);
                if drifted {
                    let _ = enforce_tun_route_and_metric(tun_name);
                    let _ = reset_external_tcp_connections(xray_pid);
                    flush_dns_cache();
                    notify_network_change();
                    on_log(format!(
                        "Re-applied TUN default route after Windows PnP init (ifIndex={}).",
                        tun_idx
                    ));
                } else if delay_ms == 650 {
                    // Post-NLA sweep (~1.1s total) to catch any socket opened during PnP transition
                    let _ = reset_external_tcp_connections(xray_pid);
                    flush_dns_cache();
                }
            }
        }
    });
}

// Close pre-existing external TCP sockets on physical adapters so apps switch to TUN immediately.
pub fn reset_external_tcp_connections(xray_pid: u32) -> usize {
    let self_pid = std::process::id();
    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );
        if size == 0 || size > 16 * 1024 * 1024 {
            return 0;
        }
        // u32 backing guarantees 4-byte alignment required by MIB_TCPROW_OWNER_PID
        let cap_bytes = (size as usize).saturating_add(1024);
        let mut buf = vec![0u32; (cap_bytes + 3) / 4];
        let mut actual_size = (buf.len() * 4) as u32;
        let rc = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut actual_size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );
        if rc != 0 || actual_size < 4 {
            return 0;
        }

        let num_entries = buf[0] as usize;
        let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
        let needed = match num_entries.checked_mul(row_size).and_then(|n| n.checked_add(4)) {
            Some(v) => v,
            None => return 0,
        };
        if needed > (actual_size as usize).min(buf.len() * 4) {
            return 0;
        }
        let rows_ptr = buf.as_ptr().add(1) as *const MIB_TCPROW_OWNER_PID;
        let rows = std::slice::from_raw_parts(rows_ptr, num_entries);

        let mut closed = 0usize;
        for row in rows {
            if row.dwState != MIB_TCP_STATE_ESTAB as u32 {
                continue;
            }
            let pid = row.dwOwningPid;
            if pid == 0 || pid == 4 || pid == self_pid || pid == xray_pid {
                continue;
            }

            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let lo = local_ip.octets();
            // Skip loopback, unspecified, APIPA, and sockets already on avel0 (172.21.0.0/30)
            if local_ip.is_loopback()
                || local_ip.is_unspecified()
                || local_ip.is_link_local()
                || (lo[0] == 172 && lo[1] == 21 && lo[2] == 0 && lo[3] <= 3)
            {
                continue;
            }

            let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            let ro = remote_ip.octets();
            let is_cgnat = ro[0] == 100 && (ro[1] & 0xC0) == 64;
            if remote_ip.is_private()
                || remote_ip.is_loopback()
                || remote_ip.is_link_local()
                || remote_ip.is_multicast()
                || remote_ip.is_broadcast()
                || is_cgnat
            {
                continue;
            }

            let del_row = MIB_TCPROW_LH {
                Anonymous: MIB_TCPROW_LH_0 {
                    dwState: MIB_TCP_STATE_DELETE_TCB as u32,
                },
                dwLocalAddr: row.dwLocalAddr,
                dwLocalPort: row.dwLocalPort,
                dwRemoteAddr: row.dwRemoteAddr,
                dwRemotePort: row.dwRemotePort,
            };
            if SetTcpEntry(&del_row) == 0 {
                closed += 1;
            }
        }
        closed
    }
}

pub fn disable_system_proxy() {
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey = to_wide(INET_SETTINGS_SUBKEY);
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) == 0 {
            let disable_val: u32 = 0;
            let k_enable = to_wide("ProxyEnable");
            RegSetValueExW(
                hkey,
                k_enable.as_ptr(),
                0,
                REG_DWORD,
                &disable_val as *const u32 as *const u8,
                4,
            );
            RegCloseKey(hkey);
            InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0);
            InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0);
        }
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

pub fn relaunch_as_admin(extra_args: Option<&str>) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let exe_str = exe.to_string_lossy();
    let verb = to_wide("runas");
    let file = to_wide(&exe_str);
    let w_args = extra_args.map(to_wide);
    let args_ptr = match &w_args {
        Some(v) => v.as_ptr(),
        None => null(),
    };
    unsafe {
        let res = ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            args_ptr,
            null(),
            SW_SHOWNORMAL,
        );
        (res as isize) > 32
    }
}

pub fn open_file_in_notepad(path: &std::path::Path) {
    let verb = to_wide("open");
    let notepad = system32_exe("notepad.exe");
    let exe = to_wide(&notepad.to_string_lossy());
    let args = to_wide(&format!("\"{}\"", path.display()));
    unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            null(),
            SW_SHOWNORMAL,
        );
    }
}

pub fn open_folder_in_explorer(dir: &std::path::Path) {
    let mut buf = [0u16; 260];
    let len = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let explorer = if len > 0 && len < buf.len() {
        std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len])).join("explorer.exe")
    } else {
        std::path::PathBuf::from(r"C:\Windows\explorer.exe")
    };
    let verb = to_wide("open");
    let exe = to_wide(&explorer.to_string_lossy());
    let args = to_wide(&format!("\"{}\"", dir.display()));
    unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            null(),
            SW_SHOWNORMAL,
        );
    }
}

// Spawn a detached System32 PowerShell helper that waits for this process to exit,
// extracts the verified release zip over avel.exe and core/ (preserving state.json),
// cleans up _update/, and relaunches the updated binary.
pub fn spawn_self_update_helper(
    zip_path: &std::path::Path,
    app_dir: &std::path::Path,
    reconnect_after: bool,
) -> Result<(), String> {
    let ps = system32_exe(r"WindowsPowerShell\v1.0\powershell.exe");
    let script = r#"
$ErrorActionPreference = 'Stop'
$pidToWait = [int]$env:AVEL_UPD_PID
$zip = $env:AVEL_UPD_ZIP
$dst = $env:AVEL_UPD_DIR
$reconn = $env:AVEL_UPD_RECONNECT
for ($i = 0; $i -lt 100; $i++) {
    if (-not (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 150
}
Start-Sleep -Milliseconds 250
$updDir = Split-Path -Parent $zip
$extDir = Join-Path $updDir 'extracted'
if (Test-Path $extDir) { Remove-Item -Recurse -Force $extDir }
Expand-Archive -Path $zip -DestinationPath $extDir -Force
$srcRoot = Join-Path $extDir 'avel-xray'
if (-not (Test-Path (Join-Path $srcRoot 'avel.exe'))) { $srcRoot = $extDir }
$newExe = Join-Path $srcRoot 'avel.exe'
if (-not (Test-Path $newExe)) { exit 1 }
Copy-Item -Path $newExe -Destination (Join-Path $dst 'avel.exe') -Force
$srcCore = Join-Path $srcRoot 'core'
$dstCore = Join-Path $dst 'core'
if (Test-Path $srcCore) {
    New-Item -ItemType Directory -Force -Path $dstCore | Out-Null
    foreach ($f in @('avel-core.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat')) {
        $p = Join-Path $srcCore $f
        if (Test-Path $p) { Copy-Item -Path $p -Destination (Join-Path $dstCore $f) -Force }
    }
}
foreach ($doc in @('LICENSE', 'THIRD_PARTY_LICENSES.txt')) {
    $p = Join-Path $srcRoot $doc
    if (Test-Path $p) { Copy-Item -Path $p -Destination (Join-Path $dst $doc) -Force }
}
Remove-Item -Recurse -Force $updDir -ErrorAction SilentlyContinue
$exePath = Join-Path $dst 'avel.exe'
if ($reconn -eq '1') {
    Start-Process -FilePath $exePath -ArgumentList '--autoconnect'
} else {
    Start-Process -FilePath $exePath
}
"#;

    Command::new(&ps)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .env("AVEL_UPD_PID", std::process::id().to_string())
        .env("AVEL_UPD_ZIP", zip_path)
        .env("AVEL_UPD_DIR", app_dir)
        .env("AVEL_UPD_RECONNECT", if reconnect_after { "1" } else { "0" })
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Failed to start update helper: {}", e))?;
    Ok(())
}

// List running user .exe names for the routing rule picker.
pub fn list_running_user_processes() -> Vec<String> {
    const SYSTEM_SKIP: &[&str] = &[
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "conhost.exe",
        "sihost.exe",
        "taskhostw.exe",
        "ctfmon.exe",
        "runtimebroker.exe",
        "searchhost.exe",
        "searchindexer.exe",
        "startmenuexperiencehost.exe",
        "shellexperiencehost.exe",
        "textinputhost.exe",
        "dllhost.exe",
        "wmiprvse.exe",
        "audiodg.exe",
        "spoolsv.exe",
        "msmpeng.exe",
        "securityhealthservice.exe",
        "memory compression",
        "idle",
        "avel.exe",
        "avel-core.exe",
    ];

    let mut seen_lower: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return out;
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                let len = pe
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe.szExeFile.len());
                let name = String::from_utf16_lossy(&pe.szExeFile[..len]);
                let lower = name.to_lowercase();
                if lower.ends_with(".exe")
                    && !SYSTEM_SKIP.contains(&lower.as_str())
                    && seen_lower.insert(lower)
                {
                    out.push(name);
                }
                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }

    out.sort_by_key(|s| s.to_lowercase());
    out
}

// Open a Win32 file picker for an .exe and return its filename.
pub fn browse_for_exe(owner: HWND) -> Option<String> {
    let mut file_buf = vec![0u16; 1024];
    let filter: Vec<u16> = "Applications (*.exe)\0*.exe\0All Files (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    let title = to_wide("Select application (.exe) for routing rule");

    unsafe {
        let mut ofn: OPENFILENAMEW = std::mem::zeroed();
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.hwndOwner = owner;
        ofn.lpstrFilter = filter.as_ptr();
        ofn.lpstrFile = file_buf.as_mut_ptr();
        ofn.nMaxFile = file_buf.len() as u32;
        ofn.lpstrTitle = title.as_ptr();
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

        if GetOpenFileNameW(&mut ofn) != 0 {
            let len = file_buf
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(file_buf.len());
            let full = String::from_utf16_lossy(&file_buf[..len]);
            let p = std::path::Path::new(&full);
            let name = p
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or(full);
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn has_autostart_task() -> bool {
    Command::new(system32_exe("schtasks.exe"))
        .args(["/Query", "/TN", AUTOSTART_TASK_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn delete_autostart_task() {
    let _ = Command::new(system32_exe("schtasks.exe"))
        .args(["/Delete", "/F", "/TN", AUTOSTART_TASK_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

fn has_run_key_autostart() -> bool {
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey = to_wide(RUN_SUBKEY);
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return false;
        }
        let val_name = to_wide(AUTOSTART_VAL_NAME);
        let mut typ: u32 = 0;
        let mut sz: u32 = 0;
        let rc = RegQueryValueExW(hkey, val_name.as_ptr(), null_mut(), &mut typ, null_mut(), &mut sz);
        RegCloseKey(hkey);
        rc == 0 && sz > 0
    }
}

fn set_run_key_autostart(enable: bool, cmd_opt: Option<&str>) -> Result<(), String> {
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey = to_wide(RUN_SUBKEY);
        let rc = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey);
        if rc != 0 {
            return Err(format!("RegOpenKeyExW Run failed: {}", rc));
        }
        let val_name = to_wide(AUTOSTART_VAL_NAME);
        let res = if enable {
            let cmd = cmd_opt.unwrap_or("");
            let wcmd = to_wide(cmd);
            RegSetValueExW(
                hkey,
                val_name.as_ptr(),
                0,
                REG_SZ,
                wcmd.as_ptr() as *const u8,
                (wcmd.len() * 2) as u32,
            )
        } else {
            let r = RegDeleteValueW(hkey, val_name.as_ptr());
            if r == 2 { 0 } else { r } // ERROR_FILE_NOT_FOUND is OK
        };
        RegCloseKey(hkey);
        if res != 0 {
            return Err(format!("RegSet/Delete Run failed: {}", res));
        }
    }
    Ok(())
}

pub fn is_autostart_enabled() -> bool {
    has_run_key_autostart() || has_autostart_task()
}

// Use Task Scheduler (/RL HIGHEST) when elevated so TUN autostart needs no UAC prompt;
// otherwise fall back to HKCU\Run.
pub fn set_autostart(enable: bool) -> Result<&'static str, String> {
    if !enable {
        delete_autostart_task();
        let _ = set_run_key_autostart(false, None);
        return Ok("Autostart disabled.");
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cmd = format!("\"{}\" --minimized --autoconnect", exe.display());

    if is_elevated() {
        let out = Command::new(system32_exe("schtasks.exe"))
            .args([
                "/Create",
                "/F",
                "/TN",
                AUTOSTART_TASK_NAME,
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/TR",
                &cmd,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to invoke schtasks.exe: {}", e))?;
        if out.status.success() {
            // Remove legacy HKCU\Run entry to avoid launching twice at logon
            let _ = set_run_key_autostart(false, None);
            return Ok("Autostart enabled (elevated logon task, no UAC prompt).");
        }
    }

    set_run_key_autostart(true, Some(&cmd))?;
    Ok("Autostart enabled (user logon; run as Admin to enable elevated TUN autostart).")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_ipv4_route_returns_valid_interface() {
        let idx = best_ipv4_route_if_index();
        assert!(idx.is_some() && idx.unwrap() > 0, "Expected valid best IPv4 route interface");
    }
}
