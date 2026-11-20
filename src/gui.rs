use crate::http_win::{
    check_latest_release, download_and_verify_release, fetch_subscription_opts, is_newer_version,
    update_geo_databases, ReleaseInfo, SubscriptionResponse,
};
use crate::icon::{create_soft_round_icon, create_watermark_brush};
use crate::model::{
    app_base_dir, core_dir, custom_routing_path, default_user_agent, ensure_default_custom_routing,
    short_sub_host, AppState, DomainStrategy, MemoryProfile, ProxyMode, RoutingPreset, RoutingRule,
    RuleDefaultAction, RuleMatchKind, SubscriptionProfile, VlessNode, XrayLogLevel,
};
use crate::ping::{extract_ping_targets, ping_all_async, real_ping_all_async};
use crate::sys_proxy::{
    browse_for_exe, disable_system_proxy, enable_system_proxy, enforce_tun_route_and_metric,
    find_adapter_luid, flush_dns_cache, get_clipboard_text, is_autostart_enabled, is_elevated,
    list_running_user_processes, notify_network_change, open_file_in_notepad,
    open_folder_in_explorer, query_luid_octets, relaunch_as_admin, reset_external_tcp_connections,
    set_autostart, set_clipboard_text, spawn_self_update_helper, spawn_tun_post_pnp_guard, to_wide,
};
use crate::vless::{is_proxy_link_text, parse_subscription_body};
use crate::xray_config::{build_xray_config, validate_remote_dns, OutboundOpts};
use crate::xray_proc::{XrayRunner, XrayStartOpts};

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Once};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, LPARAM, LRESULT, POINT, RECT,
    WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, DrawFocusRect, DrawTextW, FillRect, GetSysColor, GetSysColorBrush,
    GetViewportOrgEx, InvalidateRect, MapWindowPoints, SelectObject, SetBkMode, SetBrushOrgEx,
    SetTextColor, COLOR_BTNFACE, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT, COLOR_WINDOW,
    COLOR_WINDOWTEXT, DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER,
    HBRUSH, HDC, HFONT, TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, DRAWITEMSTRUCT, ICC_STANDARD_CLASSES, ICC_WIN95_CLASSES,
    INITCOMMONCONTROLSEX, MEASUREITEMSTRUCT, NMHDR, ODS_FOCUS, ODS_SELECTED, TCIF_TEXT, TCITEMW,
    TCM_GETCURSEL, TCM_INSERTITEMW, TCM_SETCURSEL, TCN_SELCHANGE,
};
use windows_sys::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, GetDpiForWindow, SetProcessDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, GetKeyState, SetFocus};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CallWindowProcW, ChangeWindowMessageFilterEx, CheckMenuItem, CreatePopupMenu,
    CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW,
    FindWindowW, GetClientRect, GetCursorPos, GetMessageW, GetParent, GetWindowLongPtrW,
    GetWindowRect, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW, IsWindowVisible,
    KillTimer, LoadCursorW,
    MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW,
    SendMessageW, SetForegroundWindow, SetTimer, SetWindowLongPtrW, SetWindowPos, SetWindowTextW,
    ShowWindow, TrackPopupMenu, TranslateMessage, BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX,
    BS_AUTORADIOBUTTON, BS_DEFPUSHBUTTON, BS_GROUPBOX, BS_PUSHBUTTON, CBS_AUTOHSCROLL,
    CBS_DROPDOWN, CBS_DROPDOWNLIST, CB_ADDSTRING, CB_GETCURSEL, CB_RESETCONTENT, CB_SETCURSEL,
    CBN_SELCHANGE, ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_NUMBER, ES_READONLY,
    GWLP_USERDATA, GWLP_WNDPROC, GWL_ID, HICON, HMENU, IDCANCEL, IDC_ARROW, IDOK, IDYES,
    LBN_DBLCLK, LBN_SELCHANGE, LBS_HASSTRINGS, LBS_NOINTEGRALHEIGHT, LBS_NOTIFY,
    LBS_OWNERDRAWFIXED, LB_ADDSTRING, LB_GETCURSEL, LB_GETITEMRECT, LB_ITEMFROMPOINT,
    LB_RESETCONTENT, LB_SETCURSEL, LB_SETITEMHEIGHT, MB_ICONERROR, MB_ICONINFORMATION,
    MB_ICONQUESTION, MB_OK, MB_YESNO, MF_BYCOMMAND, MF_CHECKED, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MF_UNCHECKED, MSG, MSGFLT_ALLOW, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SW_HIDE, SW_SHOW, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, TPM_TOPALIGN, WM_APP, WM_CLOSE, WM_COMMAND, WM_CTLCOLORBTN,
    WM_CTLCOLORSTATIC, WM_DESTROY, WM_DRAWITEM, WM_ENDSESSION, WM_ERASEBKGND, WM_KEYDOWN,
    WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MEASUREITEM, WM_NOTIFY, WM_POWERBROADCAST,
    WM_PRINTCLIENT, WM_RBUTTONUP, WM_SETFONT, WM_SETICON, WM_TIMER, WNDCLASSEXW, WNDPROC,
    WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE, WS_GROUP, WS_MINIMIZEBOX, WS_OVERLAPPED,
    WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

static ORIG_LISTBOX_PROC: AtomicUsize = AtomicUsize::new(0);

const WINDOW_CLASS: &str = "AvelMainClass";
const WINDOW_TITLE: &str = "avel-xray";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const MUTEX_NAME: &str = "Local\\Avel_SingleInstance_Mutex";

const SS_RIGHT: u32 = 0x0000_0002;
const SS_CENTERIMAGE: u32 = 0x0000_0200;
const SS_SUNKEN: u32 = 0x0000_1000;

// Custom messages
const WM_TRAYICON: u32 = WM_APP + 1;
const WM_UI_EVENT: u32 = WM_APP + 2;
const WM_SHOW_EXISTING: u32 = WM_APP + 3;
const WM_NODE_CTXMENU: u32 = WM_APP + 4;

const TIMER_RESUME_RECONNECT: usize = 101;
const TIMER_STATS: usize = 102;
const TIMER_SUB_AUTO: usize = 103;
const TIMER_SUB_INIT: usize = 104;
const TIMER_UPDATE_CHECK: usize = 105;

// Control IDs
const ID_TAB_MAIN: usize = 1000;
const ID_EDIT_SUB: usize = 1001;
const ID_BTN_FETCH: usize = 1002;
const ID_LIST_NODES: usize = 1004;
const ID_BTN_PING: usize = 1005;
const ID_BTN_DEL: usize = 1007;
const ID_LBL_COUNT: usize = 1008;
const ID_BTN_TOGGLE: usize = 1009;
const ID_RADIO_PROXY: usize = 1010;
const ID_RADIO_TUN: usize = 1011;
const ID_COMBO_ROUTE: usize = 1012;
const ID_BTN_RULES: usize = 1013;
const ID_CHK_SLEEP: usize = 1014;
const ID_CHK_AUTOSTART: usize = 1015;
const ID_BTN_ELEVATE: usize = 1016;
const ID_LBL_STATUS: usize = 1017;
const ID_EDIT_LOG: usize = 1018;
const ID_BTN_CLEAR_LOG: usize = 1019;
const ID_CHK_KILLSWITCH: usize = 1022;
const ID_BTN_OPEN_ROUTING: usize = 1023;
const ID_BTN_SUB_ADD: usize = 1024;
const ID_BTN_SUB_DEL: usize = 1025;
const ID_BTN_REAL_PING: usize = 1026;

// Routing tab (Tab 2) Control IDs
const ID_COMBO_DEFAULT: usize = 1101;
const ID_BTN_RULE_APPLY: usize = 1102;
const ID_LIST_RULES: usize = 1103;
const ID_BTN_RULE_TOGGLE: usize = 1104;
const ID_BTN_RULE_UP: usize = 1105;
const ID_BTN_RULE_DOWN: usize = 1106;
const ID_BTN_RULE_DEL: usize = 1107;
const ID_BTN_PRESET_RU: usize = 1108;
const ID_BTN_PRESET_ADS: usize = 1109;
const ID_COMBO_RULE_TYPE: usize = 1110;
const ID_COMBO_RULE_TARGET: usize = 1111;
const ID_BTN_RULE_ADD: usize = 1112;
const ID_EDIT_RULE_VAL: usize = 1113;
const ID_BTN_RULE_BROWSE: usize = 1114;
const ID_BTN_RULE_PROCS: usize = 1115;

// Settings tab (Tab 3) Control IDs
const ID_EDIT_MTU: usize = 1201;
const ID_EDIT_SOCKS: usize = 1202;
const ID_EDIT_HTTP: usize = 1203;
const ID_CHK_BLOCK_QUIC: usize = 1204;
const ID_CHK_ALLOW_LAN: usize = 1205;
const ID_COMBO_DNS: usize = 1206;
const ID_COMBO_LOGLEVEL: usize = 1207;
const ID_COMBO_STRATEGY: usize = 1208;
const ID_COMBO_MEM: usize = 1209;
const ID_EDIT_UA: usize = 1210;
const ID_CHK_AUTOCONNECT: usize = 1211;
const ID_CHK_START_MIN: usize = 1212;
const ID_BTN_UPDATE_GEO: usize = 1213;
const ID_BTN_OPEN_FOLDER: usize = 1214;
const ID_LBL_GEO_INFO: usize = 1215;
const ID_BTN_SETTINGS_RESET: usize = 1216;
const ID_BTN_SETTINGS_APPLY: usize = 1217;
const ID_BTN_CHECK_UPDATE: usize = 1218;
const ID_LBL_UPDATE_INFO: usize = 1219;
const ID_LBL_VERSION: usize = 1220;
const ID_CHK_FRAGMENT: usize = 1221;
const ID_CHK_NOISE: usize = 1222;
const ID_CHK_MUX: usize = 1223;
const ID_CHK_HWID: usize = 1224;
const ID_CHK_SNIFFING: usize = 1225;
const ID_CHK_DEST_OVERRIDE: usize = 1226;

// Tray menu IDs
const ID_TRAY_SHOW: usize = 2001;
const ID_TRAY_TOGGLE: usize = 2002;
const ID_TRAY_MODE_PROXY: usize = 2003;
const ID_TRAY_MODE_TUN: usize = 2004;
const ID_TRAY_EXIT: usize = 2005;

// Server list context menu IDs
const ID_CTX_CONNECT: usize = 2101;
const ID_CTX_TCP_PING: usize = 2102;
const ID_CTX_REAL_PING: usize = 2103;
const ID_CTX_IMPORT_CLIP: usize = 2104;
const ID_CTX_COPY_URI: usize = 2105;
const ID_CTX_RENAME: usize = 2106;
const ID_CTX_EDIT: usize = 2107;
const ID_CTX_REMOVE: usize = 2108;

struct SubFetchOutcome {
    nodes: Vec<VlessNode>,
    resp: SubscriptionResponse,
}

enum UiEvent {
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
    UpdateChecked {
        silent: bool,
        res: Result<ReleaseInfo, String>,
    },
    UpdateDownloaded(Result<PathBuf, String>),
    XrayExited(u32),
}

struct AppContext {
    hwnd: HWND,
    h_mutex: HANDLE,
    wm_taskbar_created: u32,
    dpi: i32,
    state: AppState,
    runner: XrayRunner,
    connected: bool,
    connected_node_key: Option<(String, String, u16)>,
    was_connected_before_sleep: bool,
    is_admin: bool,
    exiting: bool,
    active_tab: usize,
    tun_luid: Option<u64>,
    stats_base: Option<(u64, u64)>,
    stats_prev: Option<(u64, u64)>,
    last_traffic: Option<String>,
    sub_fetching: bool,
    active_sub_id: Option<String>,
    sub_combo_ids: Vec<String>,
    sub_retry_after: HashMap<String, u64>,
    ping_gen: u32,
    real_ping_cancel: Option<Arc<AtomicBool>>,
    real_ping_gen: u32,
    update_checking: bool,
    pending_update: Option<ReleaseInfo>,

    // Top tab strip & per-tab visibility groups
    h_tab: HWND,
    tab0_ctrls: Vec<HWND>,
    tab1_ctrls: Vec<HWND>,
    tab2_ctrls: Vec<HWND>,

    // Tab 0 (Connection) controls
    h_edit_sub: HWND,
    h_btn_fetch: HWND,
    h_list_nodes: HWND,
    h_btn_ping: HWND,
    h_btn_real_ping: HWND,
    h_lbl_count: HWND,
    h_btn_toggle: HWND,
    h_radio_proxy: HWND,
    h_radio_tun: HWND,
    h_combo_route: HWND,
    h_chk_sleep: HWND,
    h_chk_autostart: HWND,
    h_chk_killswitch: HWND,
    h_btn_elevate: HWND,
    h_edit_log: HWND,

    // Tab 1 (Routing) controls
    h_combo_default: HWND,
    h_list_rules: HWND,
    h_combo_rule_type: HWND,
    h_combo_rule_target: HWND,
    h_edit_rule_val: HWND,
    h_btn_rule_procs: HWND,
    rule_target_values: Vec<String>,

    // Tab 2 (Settings) controls
    h_edit_mtu: HWND,
    h_edit_socks: HWND,
    h_edit_http: HWND,
    h_chk_block_quic: HWND,
    h_chk_allow_lan: HWND,
    h_combo_dns: HWND,
    h_combo_loglevel: HWND,
    h_combo_strategy: HWND,
    h_combo_mem: HWND,
    h_chk_fragment: HWND,
    h_chk_noise: HWND,
    h_chk_mux: HWND,
    h_chk_sniffing: HWND,
    h_chk_dest_override: HWND,
    h_edit_ua: HWND,
    h_chk_autoconnect: HWND,
    h_chk_start_min: HWND,
    h_chk_hwid: HWND,
    h_btn_update_geo: HWND,
    h_lbl_geo_info: HWND,
    h_btn_check_update: HWND,
    h_lbl_update_info: HWND,

    // Shared bottom status bar & version label
    h_lbl_status: HWND,
    h_lbl_version: HWND,

    // GDI & tray resources
    font_ui: HFONT,
    font_mono: HFONT,
    font_mono_bold: HFONT,
    icon_small: HICON,
    icon_big: HICON,
    hbr_bg: HBRUSH,
    bg_w: i32,
    bg_h: i32,
    tray_added: bool,

    // Async event channel
    ev_tx: Sender<UiEvent>,
    ev_rx: Receiver<UiEvent>,
    log_lines: VecDeque<String>,
}

fn scale_dpi(val: i32, dpi: i32) -> i32 {
    (val * dpi + 48) / 96
}

pub fn run_app(start_minimized: bool, autoconnect: bool) {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        // Single instance guard (brief retry if relaunching elevated right as old process closes)
        let mutex_name = to_wide(MUTEX_NAME);
        let mut h_mutex = CreateMutexW(null(), 1, mutex_name.as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if autoconnect {
                CloseHandle(h_mutex);
                std::thread::sleep(std::time::Duration::from_millis(350));
                h_mutex = CreateMutexW(null(), 1, mutex_name.as_ptr());
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let cls = to_wide(WINDOW_CLASS);
                let existing = FindWindowW(cls.as_ptr(), null());
                if !existing.is_null() {
                    PostMessageW(existing, WM_SHOW_EXISTING, 0, 0);
                }
                if !h_mutex.is_null() {
                    CloseHandle(h_mutex);
                }
                return;
            }
        }

        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES,
        };
        InitCommonControlsEx(&icc);

        ensure_default_custom_routing();

        let h_inst = GetModuleHandleW(null());
        let cls_name = to_wide(WINDOW_CLASS);
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: h_inst,
            hIcon: null_mut(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_BTNFACE + 1) as _,
            lpszMenuName: null(),
            lpszClassName: cls_name.as_ptr(),
            hIconSm: null_mut(),
        };
        RegisterClassExW(&wc);

        // Create hidden window first so GetDpiForWindow returns the true monitor DPI (e.g. 144 at 150%)
        // Titlebar buttons: Minimize [_] + Close [X] (Close hides to system tray)
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let title = to_wide(WINDOW_TITLE);
        let hwnd = CreateWindowExW(
            0,
            cls_name.as_ptr(),
            title.as_ptr(),
            style,
            120,
            90,
            600,
            540,
            null_mut(),
            null_mut(),
            h_inst,
            null(),
        );
        if hwnd.is_null() {
            if !h_mutex.is_null() {
                CloseHandle(h_mutex);
            }
            return;
        }
        ChangeWindowMessageFilterEx(hwnd, WM_SHOW_EXISTING, MSGFLT_ALLOW, null_mut());

        let dpi = GetDpiForWindow(hwnd).max(96) as i32;
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: scale_dpi(600, dpi),
            bottom: scale_dpi(568, dpi),
        };
        AdjustWindowRectExForDpi(&mut rect, style, 0, 0, dpi as u32);
        let win_w = rect.right - rect.left;
        let win_h = rect.bottom - rect.top;
        SetWindowPos(
            hwnd,
            null_mut(),
            0,
            0,
            win_w,
            win_h,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );

        let mut client_rc: RECT = std::mem::zeroed();
        GetClientRect(hwnd, &mut client_rc);
        let bg_w = (client_rc.right - client_rc.left).max(1);
        let bg_h = (client_rc.bottom - client_rc.top).max(1);
        let hbr_bg = create_watermark_brush(bg_w, bg_h, GetSysColor(COLOR_BTNFACE));

        let icon_small_px = scale_dpi(16, dpi).clamp(16, 32);
        let icon_big_px = scale_dpi(32, dpi).clamp(32, 64);
        let icon_small = create_soft_round_icon(icon_small_px);
        let icon_big = create_soft_round_icon(icon_big_px);
        SendMessageW(hwnd, WM_SETICON, 0, icon_small as LPARAM);
        SendMessageW(hwnd, WM_SETICON, 1, icon_big as LPARAM);

        // Scale 9pt Segoe UI and 8.5pt Consolas to monitor DPI
        let ui_font_h = -((9 * dpi + 36) / 72);
        let mono_font_h = -((85 * dpi + 360) / 720);
        let font_ui = create_font("Segoe UI", ui_font_h, 400);
        let font_mono = create_font("Consolas", mono_font_h, 400);
        let font_mono_bold = create_font("Consolas", mono_font_h, 700);

        let (ev_tx, ev_rx) = mpsc::channel();
        let mut state = AppState::load();
        let is_admin = is_elevated();
        let taskbar_msg_w = to_wide("TaskbarCreated");
        let wm_taskbar_created = RegisterWindowMessageW(taskbar_msg_w.as_ptr());

        // Fall back to System Proxy when launched non-elevated with TUN saved
        if !is_admin && state.mode == ProxyMode::Tun && !autoconnect {
            state.mode = ProxyMode::SystemProxy;
        }

        let mut ctx = Box::new(AppContext {
            hwnd,
            h_mutex,
            wm_taskbar_created,
            dpi,
            state,
            runner: XrayRunner::new(),
            connected: false,
            connected_node_key: None,
            was_connected_before_sleep: false,
            is_admin,
            exiting: false,
            active_tab: 0,
            tun_luid: None,
            stats_base: None,
            stats_prev: None,
            last_traffic: None,
            sub_fetching: false,
            active_sub_id: None,
            sub_combo_ids: Vec::new(),
            sub_retry_after: HashMap::new(),
            ping_gen: 0,
            real_ping_cancel: None,
            real_ping_gen: 0,
            update_checking: false,
            pending_update: None,
            h_tab: null_mut(),
            tab0_ctrls: Vec::new(),
            tab1_ctrls: Vec::new(),
            tab2_ctrls: Vec::new(),
            h_edit_sub: null_mut(),
            h_btn_fetch: null_mut(),
            h_list_nodes: null_mut(),
            h_btn_ping: null_mut(),
            h_btn_real_ping: null_mut(),
            h_lbl_count: null_mut(),
            h_btn_toggle: null_mut(),
            h_radio_proxy: null_mut(),
            h_radio_tun: null_mut(),
            h_combo_route: null_mut(),
            h_chk_sleep: null_mut(),
            h_chk_autostart: null_mut(),
            h_chk_killswitch: null_mut(),
            h_btn_elevate: null_mut(),
            h_edit_log: null_mut(),
            h_combo_default: null_mut(),
            h_list_rules: null_mut(),
            h_combo_rule_type: null_mut(),
            h_combo_rule_target: null_mut(),
            h_edit_rule_val: null_mut(),
            h_btn_rule_procs: null_mut(),
            rule_target_values: Vec::new(),
            h_edit_mtu: null_mut(),
            h_edit_socks: null_mut(),
            h_edit_http: null_mut(),
            h_chk_block_quic: null_mut(),
            h_chk_allow_lan: null_mut(),
            h_combo_dns: null_mut(),
            h_combo_loglevel: null_mut(),
            h_combo_strategy: null_mut(),
            h_combo_mem: null_mut(),
            h_chk_fragment: null_mut(),
            h_chk_noise: null_mut(),
            h_chk_mux: null_mut(),
            h_chk_sniffing: null_mut(),
            h_chk_dest_override: null_mut(),
            h_edit_ua: null_mut(),
            h_chk_autoconnect: null_mut(),
            h_chk_start_min: null_mut(),
            h_chk_hwid: null_mut(),
            h_btn_update_geo: null_mut(),
            h_lbl_geo_info: null_mut(),
            h_btn_check_update: null_mut(),
            h_lbl_update_info: null_mut(),
            h_lbl_status: null_mut(),
            h_lbl_version: null_mut(),
            font_ui,
            font_mono,
            font_mono_bold,
            icon_small,
            icon_big,
            hbr_bg,
            bg_w,
            bg_h,
            tray_added: false,
            ev_tx,
            ev_rx,
            log_lines: VecDeque::with_capacity(260),
        });

        ctx.build_controls(h_inst);
        ctx.add_tray_icon();
        ctx.sync_ui_from_state();

        let effective_autoconnect = autoconnect || ctx.state.auto_connect_on_launch;
        let effective_minimized = start_minimized || ctx.state.start_minimized;

        if effective_autoconnect && !ctx.state.nodes.is_empty() {
            if ctx.state.mode != ProxyMode::Tun || ctx.is_admin {
                ctx.connect();
            }
        }

        let ctx_ptr = Box::into_raw(ctx);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, ctx_ptr as isize);
        // Periodic lightweight subscription auto-update timer (checks every 5 min; 0% idle load)
        SetTimer(hwnd, TIMER_SUB_AUTO, 300_000, None);
        SetTimer(hwnd, TIMER_SUB_INIT, 8_000, None);
        SetTimer(hwnd, TIMER_UPDATE_CHECK, 12_000, None);

        if effective_minimized {
            ShowWindow(hwnd, SW_HIDE);
        } else {
            ShowWindow(hwnd, SW_SHOW);
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        let ctx_box = Box::from_raw(ctx_ptr);
        ctx_box.cleanup_resources();
    }
}

impl AppContext {
    unsafe fn build_controls(&mut self, h_inst: *mut core::ffi::c_void) {
        let p = self.hwnd;
        let f = self.font_ui;
        let fm = self.font_mono;
        let d = self.dpi;
        let s = |v: i32| scale_dpi(v, d);

        // Top native Win11 tab bar: Connection | Routing | Settings
        self.h_tab = mk_ctrl(
            p,
            h_inst,
            "SysTabControl32",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0,
            s(12),
            s(6),
            s(576),
            s(26),
            ID_TAB_MAIN,
            f,
        );
        for (i, label) in ["Connection", "Routing", "Settings"].iter().enumerate() {
            let mut w_label = to_wide(label);
            let tie = TCITEMW {
                mask: TCIF_TEXT,
                dwState: 0,
                dwStateMask: 0,
                pszText: w_label.as_mut_ptr(),
                cchTextMax: 0,
                iImage: -1,
                lParam: 0,
            };
            SendMessageW(self.h_tab, TCM_INSERTITEMW, i, &tie as *const TCITEMW as LPARAM);
        }

        // Connection tab
        let mut t0 = |h: HWND| -> HWND {
            self.tab0_ctrls.push(h);
            h
        };

        // 1. Subscription group (multi-subscription dropdown + Update / Add / Del)
        t0(mk_ctrl(p, h_inst, "BUTTON", "Subscription", WS_CHILD | WS_VISIBLE | BS_GROUPBOX as u32, 0, s(12), s(38), s(576), s(52), 0, f));
        self.h_edit_sub = t0(mk_ctrl(
            p,
            h_inst,
            "COMBOBOX",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN as u32 | CBS_AUTOHSCROLL as u32,
            0,
            s(22),
            s(55),
            s(374),
            s(160),
            ID_EDIT_SUB,
            f,
        ));
        self.h_btn_fetch = t0(mk_ctrl(p, h_inst, "BUTTON", "Update", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(402), s(55), s(68), s(24), ID_BTN_FETCH, f));
        t0(mk_ctrl(p, h_inst, "BUTTON", "Add", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(474), s(55), s(52), s(24), ID_BTN_SUB_ADD, f));
        t0(mk_ctrl(p, h_inst, "BUTTON", "Del", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(530), s(55), s(48), s(24), ID_BTN_SUB_DEL, f));

        // 2. Servers group
        t0(mk_ctrl(p, h_inst, "BUTTON", "Servers (double-click to connect)", WS_CHILD | WS_VISIBLE | BS_GROUPBOX as u32, 0, s(12), s(96), s(576), s(192), 0, f));
        self.h_list_nodes = t0(mk_ctrl(
            p,
            h_inst,
            "LISTBOX",
            "",
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_VSCROLL
                | WS_BORDER
                | LBS_NOTIFY as u32
                | LBS_NOINTEGRALHEIGHT as u32
                | LBS_OWNERDRAWFIXED as u32
                | LBS_HASSTRINGS as u32,
            WS_EX_CLIENTEDGE,
            s(22),
            s(114),
            s(556),
            s(134),
            ID_LIST_NODES,
            fm,
        ));
        SendMessageW(self.h_list_nodes, LB_SETITEMHEIGHT, 0, s(18) as LPARAM);
        subclass_listbox_empty_deselect(self.h_list_nodes);
        self.h_btn_ping = t0(mk_ctrl(p, h_inst, "BUTTON", "TCP Ping", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(22), s(256), s(80), s(24), ID_BTN_PING, f));
        self.h_btn_real_ping = t0(mk_ctrl(p, h_inst, "BUTTON", "Real Ping", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(108), s(256), s(82), s(24), ID_BTN_REAL_PING, f));
        t0(mk_ctrl(p, h_inst, "BUTTON", "Remove", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(196), s(256), s(72), s(24), ID_BTN_DEL, f));
        self.h_lbl_count = t0(mk_ctrl(p, h_inst, "STATIC", "Status: Disconnected", WS_CHILD | WS_VISIBLE, 0, s(280), s(260), s(298), s(18), ID_LBL_COUNT, f));

        // 3. Connection & Routing group (double && escapes Win32 mnemonic underscore)
        t0(mk_ctrl(p, h_inst, "BUTTON", "Connection && Routing", WS_CHILD | WS_VISIBLE | BS_GROUPBOX as u32, 0, s(12), s(294), s(576), s(106), 0, f));
        self.h_btn_toggle = t0(mk_ctrl(p, h_inst, "BUTTON", "Connect", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(22), s(314), s(136), s(36), ID_BTN_TOGGLE, f));

        self.h_radio_proxy = t0(mk_ctrl(p, h_inst, "BUTTON", "System Proxy", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON as u32, 0, s(172), s(312), s(130), s(18), ID_RADIO_PROXY, f));
        self.h_radio_tun = t0(mk_ctrl(p, h_inst, "BUTTON", "TUN (all traffic)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTORADIOBUTTON as u32, 0, s(172), s(334), s(140), s(18), ID_RADIO_TUN, f));

        t0(mk_ctrl(p, h_inst, "STATIC", "Routing:", WS_CHILD | WS_VISIBLE, 0, s(324), s(316), s(62), s(18), 0, f));
        self.h_combo_route = t0(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(390), s(312), s(188), s(140), ID_COMBO_ROUTE, f));
        for item in [
            "Global (All except LAN)",
            "Direct: LAN + RU",
            "Rules (Routing tab)",
        ] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_route, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }
        t0(mk_ctrl(p, h_inst, "BUTTON", "Configure Rules...", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(390), s(338), s(188), s(22), ID_BTN_OPEN_ROUTING, f));

        self.h_chk_sleep = t0(mk_ctrl(p, h_inst, "BUTTON", "Sleep reconnect", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(22), s(368), s(124), s(20), ID_CHK_SLEEP, f));
        self.h_chk_autostart = t0(mk_ctrl(p, h_inst, "BUTTON", "Autostart", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(152), s(368), s(96), s(20), ID_CHK_AUTOSTART, f));
        self.h_chk_killswitch = t0(mk_ctrl(p, h_inst, "BUTTON", "Kill-Switch", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(254), s(368), s(116), s(20), ID_CHK_KILLSWITCH, f));
        self.h_btn_elevate = t0(mk_ctrl(
            p,
            h_inst,
            "BUTTON",
            if self.is_admin { "Admin Mode (OK)" } else { "Restart as Admin" },
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
            0,
            s(390),
            s(366),
            s(188),
            s(24),
            ID_BTN_ELEVATE,
            f,
        ));
        if self.is_admin {
            EnableWindow(self.h_btn_elevate, 0);
        }

        // 4. Log group
        t0(mk_ctrl(p, h_inst, "BUTTON", "Xray Log", WS_CHILD | WS_VISIBLE | BS_GROUPBOX as u32, 0, s(12), s(406), s(576), s(122), 0, f));
        self.h_edit_log = t0(mk_ctrl(
            p,
            h_inst,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | ES_MULTILINE as u32 | ES_READONLY as u32 | ES_AUTOVSCROLL as u32,
            WS_EX_CLIENTEDGE,
            s(22),
            s(424),
            s(480),
            s(94),
            ID_EDIT_LOG,
            fm,
        ));
        t0(mk_ctrl(p, h_inst, "BUTTON", "Clear", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(510), s(424), s(68), s(24), ID_BTN_CLEAR_LOG, f));

        // Routing tab
        let mut t1 = |h: HWND| -> HWND {
            self.tab1_ctrls.push(h);
            h
        };

        // Routing rules list group
        t1(mk_ctrl(p, h_inst, "BUTTON", "Routing Rules (top to bottom, double-click to toggle)", WS_CHILD | BS_GROUPBOX as u32, 0, s(12), s(38), s(576), s(308), 0, f));
        t1(mk_ctrl(p, h_inst, "STATIC", "Default:", WS_CHILD, 0, s(22), s(61), s(54), s(18), 0, f));
        self.h_combo_default = t1(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(78), s(58), s(260), s(100), ID_COMBO_DEFAULT, f));
        for item in [
            "Active Server (Proxy unmatched)",
            "Direct (VPN only for rules below)",
        ] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_default, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }
        t1(mk_ctrl(p, h_inst, "BUTTON", "Apply && Reconnect", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(426), s(57), s(152), s(24), ID_BTN_RULE_APPLY, f));

        self.h_list_rules = t1(mk_ctrl(
            p,
            h_inst,
            "LISTBOX",
            "",
            WS_CHILD | WS_TABSTOP | WS_VSCROLL | WS_BORDER | LBS_NOTIFY as u32 | LBS_NOINTEGRALHEIGHT as u32,
            WS_EX_CLIENTEDGE,
            s(22),
            s(88),
            s(556),
            s(216),
            ID_LIST_RULES,
            fm,
        ));
        subclass_listbox_empty_deselect(self.h_list_rules);
        t1(mk_ctrl(p, h_inst, "BUTTON", "On / Off", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(22), s(312), s(74), s(24), ID_BTN_RULE_TOGGLE, f));
        t1(mk_ctrl(p, h_inst, "BUTTON", "Up", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(102), s(312), s(52), s(24), ID_BTN_RULE_UP, f));
        t1(mk_ctrl(p, h_inst, "BUTTON", "Down", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(160), s(312), s(56), s(24), ID_BTN_RULE_DOWN, f));
        t1(mk_ctrl(p, h_inst, "BUTTON", "Delete", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(222), s(312), s(68), s(24), ID_BTN_RULE_DEL, f));
        t1(mk_ctrl(p, h_inst, "BUTTON", "+ RU Direct", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(376), s(312), s(98), s(24), ID_BTN_PRESET_RU, f));
        t1(mk_ctrl(p, h_inst, "BUTTON", "+ AdBlock", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(480), s(312), s(98), s(24), ID_BTN_PRESET_ADS, f));

        // 2. Add Rule group
        t1(mk_ctrl(p, h_inst, "BUTTON", "Add Rule (app .exe, folder, domain, geosite or IP)", WS_CHILD | BS_GROUPBOX as u32, 0, s(12), s(354), s(576), s(174), 0, f));
        t1(mk_ctrl(p, h_inst, "STATIC", "Type:", WS_CHILD, 0, s(22), s(379), s(44), s(18), 0, f));
        self.h_combo_rule_type = t1(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(68), s(376), s(156), s(110), ID_COMBO_RULE_TYPE, f));
        for item in ["Process (.exe / dir)", "Domain / GeoSite", "IP / GeoIP"] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_rule_type, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }
        SendMessageW(self.h_combo_rule_type, CB_SETCURSEL, 0, 0);

        t1(mk_ctrl(p, h_inst, "STATIC", "Action:", WS_CHILD, 0, s(236), s(379), s(48), s(18), 0, f));
        self.h_combo_rule_target = t1(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(288), s(376), s(190), s(180), ID_COMBO_RULE_TARGET, f));
        t1(mk_ctrl(p, h_inst, "BUTTON", "Add Rule", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(486), s(375), s(92), s(24), ID_BTN_RULE_ADD, f));

        t1(mk_ctrl(p, h_inst, "STATIC", "Match:", WS_CHILD, 0, s(22), s(411), s(44), s(18), 0, f));
        self.h_edit_rule_val = t1(mk_ctrl(p, h_inst, "EDIT", "", WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(68), s(408), s(322), s(22), ID_EDIT_RULE_VAL, fm));
        t1(mk_ctrl(p, h_inst, "BUTTON", "Browse .exe", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(396), s(407), s(90), s(24), ID_BTN_RULE_BROWSE, f));
        self.h_btn_rule_procs = t1(mk_ctrl(p, h_inst, "BUTTON", "Running...", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(492), s(407), s(86), s(24), ID_BTN_RULE_PROCS, f));

        t1(mk_ctrl(
            p,
            h_inst,
            "STATIC",
            "Process: chrome.exe, discord.exe, C:\\Games\\\r\nDomain: youtube.com, geosite:youtube;  IP: geoip:ru, 1.2.3.0/24",
            WS_CHILD,
            0,
            s(22),
            s(440),
            s(556),
            s(42),
            0,
            f,
        ));
        t1(mk_ctrl(
            p,
            h_inst,
            "STATIC",
            "Click 'Apply && Reconnect' to activate these rules.",
            WS_CHILD,
            0,
            s(22),
            s(494),
            s(452),
            s(20),
            0,
            f,
        ));
        t1(mk_ctrl(p, h_inst, "BUTTON", "Text file...", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(486), s(490), s(92), s(24), ID_BTN_RULES, f));

        // Settings tab
        let mut t2 = |h: HWND| -> HWND {
            self.tab2_ctrls.push(h);
            h
        };

        // 1. TUN & Network group
        t2(mk_ctrl(p, h_inst, "BUTTON", "TUN && Network", WS_CHILD | BS_GROUPBOX as u32, 0, s(12), s(38), s(576), s(112), 0, f));
        t2(mk_ctrl(p, h_inst, "STATIC", "TUN MTU:", WS_CHILD, 0, s(22), s(62), s(68), s(18), 0, f));
        self.h_edit_mtu = t2(mk_ctrl(p, h_inst, "EDIT", "", WS_CHILD | WS_TABSTOP | ES_NUMBER as u32 | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(94), s(59), s(68), s(22), ID_EDIT_MTU, fm));
        t2(mk_ctrl(p, h_inst, "STATIC", "SOCKS Port:", WS_CHILD, 0, s(184), s(62), s(76), s(18), 0, f));
        self.h_edit_socks = t2(mk_ctrl(p, h_inst, "EDIT", "", WS_CHILD | WS_TABSTOP | ES_NUMBER as u32 | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(264), s(59), s(68), s(22), ID_EDIT_SOCKS, fm));
        t2(mk_ctrl(p, h_inst, "STATIC", "HTTP Port:", WS_CHILD, 0, s(354), s(62), s(68), s(18), 0, f));
        self.h_edit_http = t2(mk_ctrl(p, h_inst, "EDIT", "", WS_CHILD | WS_TABSTOP | ES_NUMBER as u32 | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(426), s(59), s(68), s(22), ID_EDIT_HTTP, fm));

        self.h_chk_block_quic = t2(mk_ctrl(p, h_inst, "BUTTON", "Block QUIC (UDP/443)", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(22), s(92), s(184), s(20), ID_CHK_BLOCK_QUIC, f));
        self.h_chk_allow_lan = t2(mk_ctrl(p, h_inst, "BUTTON", "Allow LAN (0.0.0.0)", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(218), s(92), s(184), s(20), ID_CHK_ALLOW_LAN, f));
        t2(mk_ctrl(p, h_inst, "STATIC", "MTU range: 1280-9000 (default 1500; lower to 1400 or 1280 on LTE/PPPoE).", WS_CHILD, 0, s(22), s(120), s(556), s(18), 0, f));

        // 2. DNS & Core group
        t2(mk_ctrl(p, h_inst, "BUTTON", "DNS && Core", WS_CHILD | BS_GROUPBOX as u32, 0, s(12), s(158), s(576), s(148), 0, f));
        t2(mk_ctrl(p, h_inst, "STATIC", "Remote DNS:", WS_CHILD, 0, s(22), s(183), s(96), s(18), 0, f));
        self.h_combo_dns = t2(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN as u32 | CBS_AUTOHSCROLL as u32, 0, s(122), s(179), s(456), s(140), ID_COMBO_DNS, fm));
        for item in [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://9.9.9.9/dns-query",
            "https://dns.adguard-dns.com/dns-query",
        ] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_dns, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }

        t2(mk_ctrl(p, h_inst, "STATIC", "Log Level:", WS_CHILD, 0, s(22), s(217), s(96), s(18), 0, f));
        self.h_combo_loglevel = t2(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(122), s(213), s(146), s(120), ID_COMBO_LOGLEVEL, f));
        for item in ["warning", "info", "error", "none"] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_loglevel, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }

        t2(mk_ctrl(p, h_inst, "STATIC", "Domain Strategy:", WS_CHILD, 0, s(284), s(217), s(108), s(18), 0, f));
        self.h_combo_strategy = t2(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(396), s(213), s(182), s(120), ID_COMBO_STRATEGY, f));
        for item in ["IPIfNonMatch", "AsIs", "IPOnDemand"] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_strategy, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }

        t2(mk_ctrl(p, h_inst, "STATIC", "Memory Profile:", WS_CHILD, 0, s(22), s(251), s(96), s(18), 0, f));
        self.h_combo_mem = t2(mk_ctrl(p, h_inst, "COMBOBOX", "", WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, s(122), s(247), s(212), s(100), ID_COMBO_MEM, f));
        for item in ["Low RAM (GOGC=50)", "Performance (GOGC=100)"] {
            let w = to_wide(item);
            SendMessageW(self.h_combo_mem, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }
        self.h_chk_sniffing = t2(mk_ctrl(p, h_inst, "BUTTON", "Sniffing", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(348), s(249), s(92), s(20), ID_CHK_SNIFFING, f));
        self.h_chk_dest_override = t2(mk_ctrl(p, h_inst, "BUTTON", "Dest Override", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(446), s(249), s(132), s(20), ID_CHK_DEST_OVERRIDE, f));
        self.h_chk_fragment = t2(mk_ctrl(p, h_inst, "BUTTON", "TLS Fragment", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(22), s(278), s(140), s(20), ID_CHK_FRAGMENT, f));
        self.h_chk_noise = t2(mk_ctrl(p, h_inst, "BUTTON", "UDP Noise", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(176), s(278), s(130), s(20), ID_CHK_NOISE, f));
        self.h_chk_mux = t2(mk_ctrl(p, h_inst, "BUTTON", "Mux (XUDP)", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(320), s(278), s(140), s(20), ID_CHK_MUX, f));

        // 3. App & Tools group
        t2(mk_ctrl(p, h_inst, "BUTTON", "App && Tools", WS_CHILD | BS_GROUPBOX as u32, 0, s(12), s(314), s(576), s(164), 0, f));
        t2(mk_ctrl(p, h_inst, "STATIC", "User-Agent:", WS_CHILD, 0, s(22), s(339), s(96), s(18), 0, f));
        self.h_edit_ua = t2(mk_ctrl(p, h_inst, "EDIT", "", WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(122), s(336), s(456), s(22), ID_EDIT_UA, f));

        self.h_chk_autoconnect = t2(mk_ctrl(p, h_inst, "BUTTON", "Auto-connect on launch", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(22), s(370), s(176), s(20), ID_CHK_AUTOCONNECT, f));
        self.h_chk_start_min = t2(mk_ctrl(p, h_inst, "BUTTON", "Start minimized to tray", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(204), s(370), s(172), s(20), ID_CHK_START_MIN, f));
        self.h_chk_hwid = t2(mk_ctrl(p, h_inst, "BUTTON", "Send HWID headers", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, s(382), s(370), s(192), s(20), ID_CHK_HWID, f));

        self.h_btn_update_geo = t2(mk_ctrl(p, h_inst, "BUTTON", "Update GeoIP / GeoSite", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(22), s(402), s(172), s(26), ID_BTN_UPDATE_GEO, f));
        self.h_lbl_geo_info = t2(mk_ctrl(p, h_inst, "STATIC", "", WS_CHILD, 0, s(206), s(406), s(370), s(18), ID_LBL_GEO_INFO, f));

        self.h_btn_check_update = t2(mk_ctrl(p, h_inst, "BUTTON", "Check Updates", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(22), s(438), s(132), s(26), ID_BTN_CHECK_UPDATE, f));
        t2(mk_ctrl(p, h_inst, "BUTTON", "Open Folder", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(164), s(438), s(112), s(26), ID_BTN_OPEN_FOLDER, f));
        self.h_lbl_update_info = t2(mk_ctrl(p, h_inst, "STATIC", &format!("Version: v{}", APP_VERSION), WS_CHILD, 0, s(288), s(442), s(290), s(18), ID_LBL_UPDATE_INFO, f));

        // Bottom settings action buttons
        t2(mk_ctrl(p, h_inst, "BUTTON", "Reset Defaults", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(12), s(492), s(124), s(28), ID_BTN_SETTINGS_RESET, f));
        t2(mk_ctrl(p, h_inst, "BUTTON", "Apply && Reconnect", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(420), s(492), s(168), s(28), ID_BTN_SETTINGS_APPLY, f));

        // Bottom status bar & muted gray version label (shared across all tabs)
        self.h_lbl_status = mk_ctrl(p, h_inst, "STATIC", "", WS_CHILD | WS_VISIBLE | SS_SUNKEN | SS_CENTERIMAGE, 0, s(12), s(536), s(516), s(22), ID_LBL_STATUS, f);
        self.h_lbl_version = mk_ctrl(p, h_inst, "STATIC", &format!("v{}", APP_VERSION), WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, s(532), s(536), s(56), s(22), ID_LBL_VERSION, f);
    }

    unsafe fn switch_tab(&mut self, tab_idx: usize) {
        let idx = if tab_idx <= 2 { tab_idx } else { 0 };
        self.active_tab = idx;
        SendMessageW(self.h_tab, TCM_SETCURSEL, idx, 0);
        let cmd0 = if idx == 0 { SW_SHOW } else { SW_HIDE };
        let cmd1 = if idx == 1 { SW_SHOW } else { SW_HIDE };
        let cmd2 = if idx == 2 { SW_SHOW } else { SW_HIDE };
        for &h in &self.tab0_ctrls {
            ShowWindow(h, cmd0);
        }
        for &h in &self.tab1_ctrls {
            ShowWindow(h, cmd1);
        }
        for &h in &self.tab2_ctrls {
            ShowWindow(h, cmd2);
        }
    }

    unsafe fn rebuild_rule_target_combo(&mut self) {
        if self.h_combo_rule_target.is_null() {
            return;
        }
        let prev_sel = SendMessageW(self.h_combo_rule_target, CB_GETCURSEL, 0, 0);
        let prev_val = if prev_sel >= 0 {
            self.rule_target_values.get(prev_sel as usize).cloned()
        } else {
            None
        };

        SendMessageW(self.h_combo_rule_target, CB_RESETCONTENT, 0, 0);
        self.rule_target_values.clear();

        let base = [
            ("Active Server (Proxy)", "proxy"),
            ("Direct (Bypass VPN)", "direct"),
            ("Block", "block"),
        ];
        for (label, val) in base {
            let w = to_wide(label);
            SendMessageW(self.h_combo_rule_target, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
            self.rule_target_values.push(val.to_string());
        }
        for node in &self.state.nodes {
            let label = format!("Server: {}", node.name);
            let w = to_wide(&label);
            SendMessageW(self.h_combo_rule_target, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
            self.rule_target_values.push(format!("node:{}", node.name));
        }

        let new_sel = prev_val
            .and_then(|pv| self.rule_target_values.iter().position(|v| v == &pv))
            .unwrap_or(1); // default to Direct when adding first exception rule
        SendMessageW(self.h_combo_rule_target, CB_SETCURSEL, new_sel, 0);
    }

    unsafe fn rebuild_rule_list(&self, select_idx: Option<usize>) {
        if self.h_list_rules.is_null() {
            return;
        }
        SendMessageW(self.h_list_rules, LB_RESETCONTENT, 0, 0);
        for r in &self.state.custom_rules {
            let w = to_wide(&r.display_row());
            SendMessageW(self.h_list_rules, LB_ADDSTRING, 0, w.as_ptr() as LPARAM);
        }
        if !self.state.custom_rules.is_empty() {
            let idx = select_idx
                .unwrap_or(0)
                .min(self.state.custom_rules.len() - 1);
            SendMessageW(self.h_list_rules, LB_SETCURSEL, idx, 0);
        }
    }

    unsafe fn append_rule_match_token(&self, token: &str) {
        let cur = get_text(self.h_edit_rule_val);
        let trimmed = cur.trim();
        let next = if trimmed.is_empty() {
            token.to_string()
        } else if trimmed
            .split(|c| c == ',' || c == ';')
            .any(|p| p.trim().eq_ignore_ascii_case(token))
        {
            trimmed.to_string()
        } else {
            format!("{}, {}", trimmed.trim_end_matches(',').trim(), token)
        };
        set_text(self.h_edit_rule_val, &next);
        SendMessageW(self.h_combo_rule_type, CB_SETCURSEL, 0, 0);
    }

    unsafe fn show_running_process_menu(&self) {
        let procs = list_running_user_processes();
        let menu: HMENU = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        if procs.is_empty() {
            let w = to_wide("(No user apps found)");
            AppendMenuW(menu, MF_STRING, 0, w.as_ptr());
        } else {
            for (i, name) in procs.iter().take(40).enumerate() {
                let w = to_wide(name);
                AppendMenuW(menu, MF_STRING, i + 1, w.as_ptr());
            }
        }
        let mut rc: RECT = std::mem::zeroed();
        GetWindowRect(self.h_btn_rule_procs, &mut rc);
        SetForegroundWindow(self.hwnd);
        let chosen = TrackPopupMenu(
            menu,
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
            rc.left,
            rc.bottom,
            0,
            self.hwnd,
            null(),
        ) as usize;
        DestroyMenu(menu);
        if chosen >= 1 && chosen <= procs.len() {
            self.append_rule_match_token(&procs[chosen - 1]);
        }
    }

    unsafe fn on_add_rule(&mut self) {
        let val = get_text(self.h_edit_rule_val).trim().to_string();
        if val.is_empty() {
            msg_box(
                self.hwnd,
                "Enter at least one process (.exe), domain, or IP in Match.",
                "Add Rule",
                MB_OK | MB_ICONINFORMATION,
            );
            return;
        }
        let type_idx = SendMessageW(self.h_combo_rule_type, CB_GETCURSEL, 0, 0) as i32;
        let kind = RuleMatchKind::from_index(type_idx);
        let tgt_idx = SendMessageW(self.h_combo_rule_target, CB_GETCURSEL, 0, 0) as usize;
        let target = self
            .rule_target_values
            .get(tgt_idx)
            .cloned()
            .unwrap_or_else(|| "direct".to_string());

        self.state.custom_rules.push(RoutingRule {
            enabled: true,
            kind,
            value: val,
            target,
        });
        let _ = self.state.save();
        let new_idx = self.state.custom_rules.len() - 1;
        self.rebuild_rule_list(Some(new_idx));
        set_text(self.h_edit_rule_val, "");
    }

    unsafe fn on_toggle_selected_rule(&mut self) {
        let sel = SendMessageW(self.h_list_rules, LB_GETCURSEL, 0, 0);
        if sel >= 0 && (sel as usize) < self.state.custom_rules.len() {
            let idx = sel as usize;
            self.state.custom_rules[idx].enabled = !self.state.custom_rules[idx].enabled;
            let _ = self.state.save();
            self.rebuild_rule_list(Some(idx));
        }
    }

    unsafe fn on_move_selected_rule(&mut self, delta: isize) {
        let sel = SendMessageW(self.h_list_rules, LB_GETCURSEL, 0, 0);
        if sel < 0 {
            return;
        }
        let idx = sel as usize;
        let next = (idx as isize) + delta;
        if next < 0 || (next as usize) >= self.state.custom_rules.len() {
            return;
        }
        let next_u = next as usize;
        self.state.custom_rules.swap(idx, next_u);
        let _ = self.state.save();
        self.rebuild_rule_list(Some(next_u));
    }

    unsafe fn on_delete_selected_rule(&mut self) {
        let sel = SendMessageW(self.h_list_rules, LB_GETCURSEL, 0, 0);
        if sel >= 0 && (sel as usize) < self.state.custom_rules.len() {
            let idx = sel as usize;
            self.state.custom_rules.remove(idx);
            let _ = self.state.save();
            self.rebuild_rule_list(Some(idx));
        }
    }

    unsafe fn on_apply_rules(&mut self) {
        let def_idx = SendMessageW(self.h_combo_default, CB_GETCURSEL, 0, 0) as i32;
        self.state.custom_default_action = if def_idx == 1 {
            RuleDefaultAction::Direct
        } else {
            RuleDefaultAction::Proxy
        };
        self.state.routing = RoutingPreset::Custom;
        SendMessageW(
            self.h_combo_route,
            CB_SETCURSEL,
            RoutingPreset::Custom.to_index() as WPARAM,
            0,
        );
        let _ = self.state.save();
        let enabled_cnt = self.state.custom_rules.iter().filter(|r| r.enabled).count();
        self.append_log(&format!(
            "Applied Routing rules ({} active, default: {:?}).",
            enabled_cnt, self.state.custom_default_action
        ));
        self.update_status_and_tray();
        self.reconnect_if_connected();
    }

    unsafe fn refresh_geo_info_label(&self) {
        if self.h_lbl_geo_info.is_null() {
            return;
        }
        let cdir = core_dir();
        let ip_sz = std::fs::metadata(cdir.join("geoip.dat"))
            .map(|m| fmt_bytes(m.len()))
            .unwrap_or_else(|_| "missing".to_string());
        let site_sz = std::fs::metadata(cdir.join("geosite.dat"))
            .map(|m| fmt_bytes(m.len()))
            .unwrap_or_else(|_| "missing".to_string());
        set_text(
            self.h_lbl_geo_info,
            &format!("geoip {}, geosite {}", ip_sz, site_sz),
        );
    }

    unsafe fn sync_settings_controls(&self) {
        set_text(self.h_edit_mtu, &self.state.tun_mtu.to_string());
        set_text(self.h_edit_socks, &self.state.socks_port.to_string());
        set_text(self.h_edit_http, &self.state.http_port.to_string());
        SendMessageW(
            self.h_chk_block_quic,
            BM_SETCHECK,
            if self.state.block_quic { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_allow_lan,
            BM_SETCHECK,
            if self.state.allow_lan { 1 } else { 0 },
            0,
        );
        set_text(self.h_combo_dns, &self.state.remote_dns);
        SendMessageW(
            self.h_combo_loglevel,
            CB_SETCURSEL,
            self.state.log_level.to_index() as WPARAM,
            0,
        );
        SendMessageW(
            self.h_combo_strategy,
            CB_SETCURSEL,
            self.state.domain_strategy.to_index() as WPARAM,
            0,
        );
        SendMessageW(
            self.h_combo_mem,
            CB_SETCURSEL,
            self.state.memory_profile.to_index() as WPARAM,
            0,
        );
        SendMessageW(
            self.h_chk_fragment,
            BM_SETCHECK,
            if self.state.enable_fragment { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_noise,
            BM_SETCHECK,
            if self.state.enable_noise { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_mux,
            BM_SETCHECK,
            if self.state.enable_mux { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_sniffing,
            BM_SETCHECK,
            if self.state.enable_sniffing { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_dest_override,
            BM_SETCHECK,
            if self.state.sniffing_dest_override { 1 } else { 0 },
            0,
        );
        EnableWindow(
            self.h_chk_dest_override,
            if self.state.enable_sniffing { 1 } else { 0 },
        );
        set_text(self.h_edit_ua, &self.state.user_agent);
        SendMessageW(
            self.h_chk_autoconnect,
            BM_SETCHECK,
            if self.state.auto_connect_on_launch { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_start_min,
            BM_SETCHECK,
            if self.state.start_minimized { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_hwid,
            BM_SETCHECK,
            if self.state.send_hwid { 1 } else { 0 },
            0,
        );
        self.refresh_geo_info_label();
    }

    unsafe fn on_apply_settings(&mut self) {
        let mtu: u16 = match get_text(self.h_edit_mtu).trim().parse::<u16>() {
            Ok(v) if (1280..=9000).contains(&v) => v,
            _ => {
                msg_box(
                    self.hwnd,
                    "TUN MTU must be a number between 1280 and 9000.",
                    "Settings",
                    MB_OK | MB_ICONERROR,
                );
                return;
            }
        };
        let socks_port: u16 = match get_text(self.h_edit_socks).trim().parse::<u16>() {
            Ok(v) if v >= 1 => v,
            _ => {
                msg_box(
                    self.hwnd,
                    "SOCKS Port must be a number between 1 and 65535.",
                    "Settings",
                    MB_OK | MB_ICONERROR,
                );
                return;
            }
        };
        let http_port: u16 = match get_text(self.h_edit_http).trim().parse::<u16>() {
            Ok(v) if v >= 1 => v,
            _ => {
                msg_box(
                    self.hwnd,
                    "HTTP Port must be a number between 1 and 65535.",
                    "Settings",
                    MB_OK | MB_ICONERROR,
                );
                return;
            }
        };
        if socks_port == http_port {
            msg_box(
                self.hwnd,
                "SOCKS Port and HTTP Port cannot be the same.",
                "Settings",
                MB_OK | MB_ICONERROR,
            );
            return;
        }
        let remote_dns = match validate_remote_dns(&get_text(self.h_combo_dns)) {
            Ok(v) => v,
            Err(e) => {
                msg_box(self.hwnd, &e, "Settings", MB_OK | MB_ICONERROR);
                return;
            }
        };

        let block_quic = SendMessageW(self.h_chk_block_quic, BM_GETCHECK, 0, 0) != 0;
        let allow_lan = SendMessageW(self.h_chk_allow_lan, BM_GETCHECK, 0, 0) != 0;
        let log_level =
            XrayLogLevel::from_index(SendMessageW(self.h_combo_loglevel, CB_GETCURSEL, 0, 0) as i32);
        let domain_strategy = DomainStrategy::from_index(
            SendMessageW(self.h_combo_strategy, CB_GETCURSEL, 0, 0) as i32,
        );
        let memory_profile =
            MemoryProfile::from_index(SendMessageW(self.h_combo_mem, CB_GETCURSEL, 0, 0) as i32);
        let enable_fragment = SendMessageW(self.h_chk_fragment, BM_GETCHECK, 0, 0) != 0;
        let enable_noise = SendMessageW(self.h_chk_noise, BM_GETCHECK, 0, 0) != 0;
        let enable_mux = SendMessageW(self.h_chk_mux, BM_GETCHECK, 0, 0) != 0;
        let enable_sniffing = SendMessageW(self.h_chk_sniffing, BM_GETCHECK, 0, 0) != 0;
        let sniffing_dest_override = SendMessageW(self.h_chk_dest_override, BM_GETCHECK, 0, 0) != 0;
        let ua_raw = get_text(self.h_edit_ua).trim().to_string();
        let user_agent = if ua_raw.is_empty() {
            default_user_agent()
        } else {
            ua_raw
        };
        let auto_connect_on_launch =
            SendMessageW(self.h_chk_autoconnect, BM_GETCHECK, 0, 0) != 0;
        let start_minimized = SendMessageW(self.h_chk_start_min, BM_GETCHECK, 0, 0) != 0;
        let send_hwid = SendMessageW(self.h_chk_hwid, BM_GETCHECK, 0, 0) != 0;

        let core_changed = self.state.tun_mtu != mtu
            || self.state.socks_port != socks_port
            || self.state.http_port != http_port
            || self.state.block_quic != block_quic
            || self.state.allow_lan != allow_lan
            || self.state.remote_dns != remote_dns
            || self.state.log_level != log_level
            || self.state.domain_strategy != domain_strategy
            || self.state.memory_profile != memory_profile
            || self.state.enable_fragment != enable_fragment
            || self.state.enable_noise != enable_noise
            || self.state.enable_mux != enable_mux
            || self.state.enable_sniffing != enable_sniffing
            || self.state.sniffing_dest_override != sniffing_dest_override;

        self.state.tun_mtu = mtu;
        self.state.socks_port = socks_port;
        self.state.http_port = http_port;
        self.state.block_quic = block_quic;
        self.state.allow_lan = allow_lan;
        self.state.remote_dns = remote_dns;
        self.state.log_level = log_level;
        self.state.domain_strategy = domain_strategy;
        self.state.memory_profile = memory_profile;
        self.state.enable_fragment = enable_fragment;
        self.state.enable_noise = enable_noise;
        self.state.enable_mux = enable_mux;
        self.state.enable_sniffing = enable_sniffing;
        self.state.sniffing_dest_override = sniffing_dest_override;
        self.state.user_agent = user_agent;
        self.state.auto_connect_on_launch = auto_connect_on_launch;
        self.state.start_minimized = start_minimized;
        self.state.send_hwid = send_hwid;

        let _ = self.state.save();
        self.sync_settings_controls();

        if allow_lan {
            self.append_log(
                "Note: Allow LAN enabled (0.0.0.0) - SOCKS/HTTP ports are accessible on LAN.",
            );
        }
        if self.connected && core_changed {
            self.append_log(&format!(
                "Settings applied (MTU={}, DNS={}, log={}, strategy={}). Reconnecting...",
                self.state.tun_mtu,
                self.state.remote_dns,
                self.state.log_level.as_xray_str(),
                self.state.domain_strategy.as_xray_str()
            ));
            self.reconnect_if_connected();
        } else {
            self.append_log(&format!(
                "Settings saved (MTU={}, SOCKS={}, HTTP={}, log={}).",
                self.state.tun_mtu,
                self.state.socks_port,
                self.state.http_port,
                self.state.log_level.as_xray_str()
            ));
            self.update_status_and_tray();
        }
    }

    unsafe fn on_reset_settings(&mut self) {
        self.state.reset_settings_to_defaults();
        let _ = self.state.save();
        self.sync_settings_controls();
        self.append_log("Settings reset to defaults.");
        self.reconnect_if_connected();
    }

    unsafe fn on_update_geo(&mut self) {
        EnableWindow(self.h_btn_update_geo, 0);
        set_text(self.h_btn_update_geo, "Updating...");
        set_text(self.h_lbl_geo_info, "Downloading geoip + geosite...");
        self.append_log("Downloading geoip.dat and geosite.dat from XTLS/Xray-rules-dat...");

        let cdir = core_dir();
        let ua = self.state.user_agent.clone();
        let tx = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        std::thread::spawn(move || {
            let res = update_geo_databases(&cdir, &ua);
            let _ = tx.send(UiEvent::GeoUpdated(res));
            PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
        });
    }

    unsafe fn on_check_updates(&mut self) {
        self.start_update_check(false);
    }

    unsafe fn start_update_check(&mut self, silent: bool) {
        if self.update_checking {
            return;
        }
        if silent && now_unix().saturating_sub(self.state.last_update_check_unix) < 86_400 {
            return;
        }
        self.update_checking = true;
        if !silent {
            EnableWindow(self.h_btn_check_update, 0);
            set_text(self.h_btn_check_update, "Checking...");
            set_text(self.h_lbl_update_info, "Checking GitHub releases...");
            self.append_log("Checking GitHub for updates...");
        }

        let ua = self.state.user_agent.clone();
        let tx = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        std::thread::spawn(move || {
            let res = check_latest_release(&ua);
            let _ = tx.send(UiEvent::UpdateChecked { silent, res });
            PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
        });
    }

    unsafe fn prompt_update_dialog(&mut self, rel: ReleaseInfo) {
        let prompt = format!(
            "New version {} is available (current: v{}).\n\nDownload, verify SHA256, and restart now?",
            rel.tag, APP_VERSION
        );
        if msg_box(
            self.hwnd,
            &prompt,
            "Update Available",
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES
        {
            self.start_update_download(rel);
        }
    }

    unsafe fn prompt_pending_update_if_any(&mut self) {
        if let Some(rel) = self.pending_update.take() {
            self.update_status_and_tray();
            self.prompt_update_dialog(rel);
        }
    }

    unsafe fn start_update_download(&mut self, rel: ReleaseInfo) {
        EnableWindow(self.h_btn_check_update, 0);
        set_text(self.h_btn_check_update, "Updating...");
        set_text(
            self.h_lbl_update_info,
            &format!("Downloading {}...", rel.tag),
        );
        self.append_log(&format!(
            "Downloading {} and verifying SHA256...",
            rel.zip_name
        ));

        let dest_zip = app_base_dir().join("_update").join("release.zip");
        let ua = self.state.user_agent.clone();
        let tx = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        std::thread::spawn(move || {
            let res = download_and_verify_release(&rel, &dest_zip, &ua).map(|()| dest_zip);
            let _ = tx.send(UiEvent::UpdateDownloaded(res));
            PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
        });
    }

    unsafe fn sync_ui_from_state(&mut self) {
        self.rebuild_sub_combo();
        self.rebuild_node_list();
        self.rebuild_rule_list(Some(0));
        self.sync_settings_controls();

        SendMessageW(
            self.h_combo_default,
            CB_SETCURSEL,
            if self.state.custom_default_action == RuleDefaultAction::Direct { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_radio_proxy,
            BM_SETCHECK,
            if self.state.mode == ProxyMode::SystemProxy { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_radio_tun,
            BM_SETCHECK,
            if self.state.mode == ProxyMode::Tun { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_combo_route,
            CB_SETCURSEL,
            self.state.routing.to_index() as WPARAM,
            0,
        );
        SendMessageW(
            self.h_chk_sleep,
            BM_SETCHECK,
            if self.state.reconnect_after_sleep { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_autostart,
            BM_SETCHECK,
            if is_autostart_enabled() { 1 } else { 0 },
            0,
        );
        SendMessageW(
            self.h_chk_killswitch,
            BM_SETCHECK,
            if self.state.kill_switch { 1 } else { 0 },
            0,
        );
        self.switch_tab(0);
        self.update_status_and_tray();
    }

    unsafe fn rebuild_sub_combo(&mut self) {
        if self.h_edit_sub.is_null() {
            return;
        }
        SendMessageW(self.h_edit_sub, CB_RESETCONTENT, 0, 0);
        self.sub_combo_ids.clear();
        for sub in &self.state.subscriptions {
            let label = sub_combo_label(sub);
            let w = to_wide(&label);
            SendMessageW(self.h_edit_sub, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
            self.sub_combo_ids.push(sub.id.clone());
        }
        if self.state.subscriptions.is_empty() {
            self.active_sub_id = None;
            set_text(self.h_edit_sub, &self.state.subscription_url);
            return;
        }
        let target_idx = self
            .active_sub_id
            .as_deref()
            .and_then(|id| self.sub_combo_ids.iter().position(|x| x == id))
            .or_else(|| {
                let u = self.state.subscription_url.trim();
                self.state.subscriptions.iter().position(|s| s.url == u)
            })
            .unwrap_or(0);
        self.active_sub_id = Some(self.sub_combo_ids[target_idx].clone());
        SendMessageW(self.h_edit_sub, CB_SETCURSEL, target_idx, 0);
    }

    unsafe fn sync_state_from_controls(&mut self) {
        if !self.h_combo_route.is_null() {
            let r_idx = SendMessageW(self.h_combo_route, CB_GETCURSEL, 0, 0) as i32;
            if r_idx >= 0 {
                self.state.routing = RoutingPreset::from_index(r_idx);
            }
        }
        if !self.h_list_nodes.is_null() && !self.state.nodes.is_empty() {
            let n_idx = SendMessageW(self.h_list_nodes, LB_GETCURSEL, 0, 0);
            if n_idx >= 0 && (n_idx as usize) < self.state.nodes.len() {
                self.state.selected_index = n_idx as usize;
            }
        }
    }

    unsafe fn rebuild_node_list(&mut self) {
        self.rebuild_node_list_with_sel(true);
    }

    unsafe fn rebuild_node_list_with_sel(&mut self, select_item: bool) {
        SendMessageW(self.h_list_nodes, LB_RESETCONTENT, 0, 0);
        for node in &self.state.nodes {
            let row = to_wide(&node.display_row());
            SendMessageW(self.h_list_nodes, LB_ADDSTRING, 0, row.as_ptr() as LPARAM);
        }
        if !self.state.nodes.is_empty() {
            let idx = self.state.selected_index.min(self.state.nodes.len() - 1);
            self.state.selected_index = idx;
            if select_item {
                SendMessageW(self.h_list_nodes, LB_SETCURSEL, idx, 0);
            }
        } else {
            self.state.selected_index = 0;
        }
        self.rebuild_rule_target_combo();
    }

    unsafe fn update_single_node_row(&self, idx: usize) {
        if idx >= self.state.nodes.len() || self.h_list_nodes.is_null() {
            return;
        }
        let mut rc: RECT = std::mem::zeroed();
        let ok = SendMessageW(
            self.h_list_nodes,
            LB_GETITEMRECT,
            idx,
            &mut rc as *mut RECT as LPARAM,
        );
        if ok >= 0 {
            InvalidateRect(self.h_list_nodes, &rc, 0);
        } else {
            InvalidateRect(self.h_list_nodes, null(), 0);
        }
    }

    unsafe fn update_status_and_tray(&mut self) {
        let bar_str = if self.connected {
            if self.state.mode == ProxyMode::Tun {
                if let Some(ref tr) = self.last_traffic {
                    format!(" {}", tr)
                } else {
                    " TUN (avel0)".to_string()
                }
            } else {
                format!(" SOCKS {} / HTTP {}", self.state.socks_port, self.state.http_port)
            }
        } else {
            String::new()
        };
        let mut tray_str = if self.connected {
            format!("avel-xray - Connected{}", if bar_str.is_empty() { String::new() } else { format!(" -{}", bar_str) })
        } else {
            "avel-xray - Disconnected".to_string()
        };
        if let Some(ref rel) = self.pending_update {
            tray_str.push_str(&format!(" (Update {})", rel.tag));
        }
        set_text(
            self.h_lbl_count,
            if self.connected {
                "Status: Connected"
            } else {
                "Status: Disconnected"
            },
        );
        set_text(self.h_lbl_status, &bar_str);
        set_text(
            self.h_btn_toggle,
            if self.connected { "Disconnect" } else { "Connect" },
        );
        self.modify_tray_tip(&tray_str);
    }

    unsafe fn on_stats_tick(&mut self) {
        if !self.connected || self.state.mode != ProxyMode::Tun {
            return;
        }
        if self.tun_luid.is_none() {
            self.tun_luid = find_adapter_luid("avel0");
        }
        let Some(luid) = self.tun_luid else {
            return;
        };
        let Some((rx, tx)) = query_luid_octets(luid) else {
            return;
        };
        let (base_rx, base_tx) = *self.stats_base.get_or_insert((rx, tx));
        let (prev_rx, prev_tx) = self.stats_prev.replace((rx, tx)).unwrap_or((rx, tx));
        let drx = rx.saturating_sub(prev_rx);
        let dtx = tx.saturating_sub(prev_tx);
        let total = rx.saturating_sub(base_rx).saturating_add(tx.saturating_sub(base_tx));
        self.last_traffic = Some(format!(
            "Dn {}, Up {} ({})",
            fmt_rate(drx),
            fmt_rate(dtx),
            fmt_bytes(total)
        ));
        self.update_status_and_tray();
    }

    fn clear_traffic_stats(&mut self) {
        self.last_traffic = None;
    }

    unsafe fn add_tray_icon(&mut self) {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = self.icon_small;
        write_tip(&mut nid.szTip, "avel-xray - Disconnected");
        if Shell_NotifyIconW(NIM_ADD, &nid) != 0 {
            self.tray_added = true;
        }
    }

    unsafe fn modify_tray_tip(&self, tip: &str) {
        if !self.tray_added {
            return;
        }
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = self.hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_TIP;
        write_tip(&mut nid.szTip, tip);
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    unsafe fn remove_tray_icon(&mut self) {
        if self.tray_added {
            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = self.hwnd;
            nid.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &nid);
            self.tray_added = false;
        }
    }

    unsafe fn append_log(&mut self, line: &str) {
        if self.log_lines.len() >= 200 {
            self.log_lines.pop_front();
        }
        self.log_lines.push_back(line.to_string());
        let joined: String = self
            .log_lines
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\r\n");
        set_text(self.h_edit_log, &joined);
        let len = GetWindowTextLengthW(self.h_edit_log) as WPARAM;
        SendMessageW(self.h_edit_log, 0x00B1, len, len as LPARAM);
        SendMessageW(self.h_edit_log, 0x00B7, 0, 0);
    }

    fn find_subscription_from_input(&self, input: &str) -> Option<&SubscriptionProfile> {
        let t = input.trim();
        if t.is_empty() {
            return None;
        }
        self.state
            .subscriptions
            .iter()
            .find(|s| s.url == t || sub_combo_label(s) == t)
    }

    unsafe fn start_subscription_fetch(
        &mut self,
        url: String,
        sub_id_opt: Option<String>,
        silent: bool,
    ) {
        if self.sub_fetching {
            if !silent {
                self.append_log("Subscription update is already running.");
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
        EnableWindow(self.h_btn_fetch, 0);
        set_text(self.h_btn_fetch, "Loading...");
        if silent {
            self.append_log(&format!(
                "Auto-updating subscription ({})...",
                short_sub_host(&url)
            ));
        } else if url.starts_with("http://") {
            self.append_log("WARNING: Fetching subscription over unencrypted HTTP.");
        } else {
            self.append_log(&format!(
                "Fetching subscription ({})...",
                short_sub_host(&url)
            ));
        }

        let tx = self.ev_tx.clone();
        let ua = self.state.user_agent.clone();
        let send_hwid = self.state.send_hwid;
        let fallback_proxy_port = if self.connected {
            Some(self.state.http_port)
        } else {
            None
        };
        let hwnd_raw = self.hwnd as usize;
        std::thread::spawn(move || {
            let res = fetch_subscription_opts(&url, &ua, send_hwid, fallback_proxy_port).and_then(
                |resp| {
                    let nodes = parse_subscription_body(&resp.body)?;
                    if nodes.is_empty() {
                        return Err(
                            "No supported proxy links found in subscription response.".to_string()
                        );
                    }
                    Ok(SubFetchOutcome { nodes, resp })
                },
            );
            let _ = tx.send(UiEvent::SubFetched {
                sub_id,
                url,
                silent,
                res,
            });
            PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
        });
    }

    unsafe fn import_proxy_links(&mut self, text: &str, source: &str, show_errors: bool) -> bool {
        let parsed = match parse_subscription_body(text) {
            Ok(n) if !n.is_empty() => n,
            Ok(_) => {
                if show_errors {
                    msg_box(
                        self.hwnd,
                        "No supported proxy links found (vless://, vmess://, trojan://, ss://, hy2://, wireguard://, socks5://, http://).",
                        "Import",
                        MB_OK | MB_ICONERROR,
                    );
                }
                return false;
            }
            Err(e) => {
                if show_errors {
                    msg_box(self.hwnd, &e, "Import Error", MB_OK | MB_ICONERROR);
                }
                return false;
            }
        };

        let first_new_idx = self.state.nodes.len();
        let mut added = 0usize;
        let mut skipped = 0usize;
        for mut node in parsed {
            node.source_sub_id = None;
            let dup = self.state.nodes.iter().any(|ex| {
                ex.protocol == node.protocol
                    && ex.address == node.address
                    && ex.port == node.port
                    && ex.uuid == node.uuid
                    && ex.sni == node.sni
                    && ex.path == node.path
                    && ex.service_name == node.service_name
            });
            if dup {
                skipped += 1;
            } else {
                self.state.nodes.push(node);
                added += 1;
            }
        }

        if added > 0 {
            self.cancel_real_ping();
            self.ping_gen = self.ping_gen.wrapping_add(1);
            self.state.selected_index = first_new_idx;
            let _ = self.state.save();
            self.rebuild_node_list();
            if skipped > 0 {
                self.append_log(&format!(
                    "Added {} server(s) from {} ({} duplicate skipped).",
                    added, source, skipped
                ));
            } else {
                self.append_log(&format!("Added {} server(s) from {}.", added, source));
            }
            true
        } else {
            self.append_log(&format!(
                "No new servers added from {} ({} duplicate already in list).",
                source, skipped
            ));
            true
        }
    }

    unsafe fn on_fetch_subscription(&mut self) {
        let input = get_text(self.h_edit_sub).trim().to_string();
        if input.is_empty() {
            msg_box(
                self.hwnd,
                "Enter a subscription URL or proxy link first.",
                "Subscription",
                MB_OK | MB_ICONINFORMATION,
            );
            return;
        }

        if is_proxy_link_text(&input) {
            self.import_proxy_links(&input, "input", true);
            self.rebuild_sub_combo();
            return;
        }

        if let Some(sub) = self.find_subscription_from_input(&input) {
            let url = sub.url.clone();
            let id = sub.id.clone();
            self.start_subscription_fetch(url, Some(id), false);
            return;
        }

        if input.starts_with("http://") || input.starts_with("https://") {
            self.start_subscription_fetch(input, None, false);
            return;
        }

        if self.import_proxy_links(&input, "input", false) {
            self.rebuild_sub_combo();
            return;
        }

        msg_box(
            self.hwnd,
            "Enter an http(s):// subscription URL or a supported proxy link.",
            "Subscription",
            MB_OK | MB_ICONERROR,
        );
    }

    unsafe fn on_add_nodes_action(&mut self) {
        let input = get_text(self.h_edit_sub).trim().to_string();
        if is_proxy_link_text(&input) {
            self.import_proxy_links(&input, "input", true);
            self.rebuild_sub_combo();
            return;
        }
        if (input.starts_with("http://") || input.starts_with("https://"))
            && !self.state.subscriptions.iter().any(|s| s.url == input)
        {
            self.start_subscription_fetch(input, None, false);
            return;
        }

        if let Some(clip_raw) = get_clipboard_text(self.hwnd) {
            let clip = clip_raw.trim().to_string();
            if !clip.is_empty() {
                if !is_proxy_link_text(&clip)
                    && (clip.starts_with("http://") || clip.starts_with("https://"))
                    && !clip.contains('\n')
                    && !clip.contains('\r')
                {
                    let existing_id = self
                        .state
                        .subscriptions
                        .iter()
                        .find(|s| s.url == clip)
                        .map(|s| s.id.clone());
                    self.start_subscription_fetch(clip, existing_id, false);
                    return;
                }
                if self.import_proxy_links(&clip, "clipboard", false) {
                    return;
                }
            }
        }

        msg_box(
            self.hwnd,
            "Paste a new subscription URL or proxy link into the Subscription field, or copy it to the clipboard and click Add (or press Ctrl+V in Servers).",
            "Add Subscription / Server",
            MB_OK | MB_ICONINFORMATION,
        );
    }

    unsafe fn on_import_from_clipboard(&mut self) {
        let Some(clip_raw) = get_clipboard_text(self.hwnd) else {
            self.append_log("Clipboard does not contain text.");
            return;
        };
        let clip = clip_raw.trim().to_string();
        if clip.is_empty() {
            self.append_log("Clipboard is empty.");
            return;
        }
        if !is_proxy_link_text(&clip)
            && (clip.starts_with("http://") || clip.starts_with("https://"))
            && !clip.contains('\n')
            && !clip.contains('\r')
        {
            let existing_id = self
                .state
                .subscriptions
                .iter()
                .find(|s| s.url == clip)
                .map(|s| s.id.clone());
            self.start_subscription_fetch(clip, existing_id, false);
            return;
        }
        self.import_proxy_links(&clip, "clipboard", true);
    }

    unsafe fn on_delete_subscription(&mut self) {
        let input = get_text(self.h_edit_sub).trim().to_string();
        let target = self
            .find_subscription_from_input(&input)
            .or_else(|| {
                self.active_sub_id
                    .as_deref()
                    .and_then(|id| self.state.subscriptions.iter().find(|s| s.id == id))
            })
            .cloned();

        let Some(sub) = target else {
            msg_box(
                self.hwnd,
                "No saved subscription selected to delete.",
                "Subscription",
                MB_OK | MB_ICONINFORMATION,
            );
            return;
        };

        let node_cnt = self
            .state
            .nodes
            .iter()
            .filter(|n| n.source_sub_id.as_deref() == Some(sub.id.as_str()))
            .count();
        let prompt = format!(
            "Delete subscription '{}' and its {} server(s)?\n\nManual nodes and other subscriptions will remain intact.",
            sub_combo_label(&sub),
            node_cnt
        );
        if msg_box(
            self.hwnd,
            &prompt,
            "Delete Subscription",
            MB_YESNO | MB_ICONQUESTION,
        ) != IDYES
        {
            return;
        }

        self.cancel_real_ping();
        self.ping_gen = self.ping_gen.wrapping_add(1);
        self.state.subscriptions.retain(|s| s.id != sub.id);
        self.state
            .nodes
            .retain(|n| n.source_sub_id.as_deref() != Some(sub.id.as_str()));
        self.sub_retry_after.remove(&sub.id);
        self.active_sub_id = self.state.subscriptions.first().map(|s| s.id.clone());
        self.state.subscription_url = self
            .state
            .subscriptions
            .first()
            .map(|s| s.url.clone())
            .unwrap_or_default();
        let _ = self.state.save();
        self.rebuild_sub_combo();
        self.rebuild_node_list();
        self.append_log(&format!(
            "Removed subscription '{}' ({} server(s)).",
            short_sub_host(&sub.url),
            node_cnt
        ));
    }

    unsafe fn check_due_subscription_updates(&mut self) {
        if self.sub_fetching {
            return;
        }
        let now = now_unix();
        let due = self.state.subscriptions.iter().find(|sub| {
            if sub.update_interval_hours == 0 {
                return false;
            }
            if self.sub_retry_after.get(&sub.id).copied().unwrap_or(0) > now {
                return false;
            }
            let interval_secs = (sub.update_interval_hours as u64).saturating_mul(3600);
            now.saturating_sub(sub.last_updated_unix) >= interval_secs
        });
        if let Some(sub) = due.cloned() {
            self.start_subscription_fetch(sub.url, Some(sub.id), true);
        }
    }

    unsafe fn cancel_real_ping(&mut self) {
        if let Some(cancel) = self.real_ping_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.real_ping_gen = self.real_ping_gen.wrapping_add(1);
        if !self.h_btn_real_ping.is_null() {
            set_text(self.h_btn_real_ping, "Real Ping");
        }
    }

    fn current_outbound_opts(&self) -> OutboundOpts {
        OutboundOpts {
            fragment: self.state.enable_fragment,
            noise: self.state.enable_noise,
            mux: self.state.enable_mux,
        }
    }

    unsafe fn on_ping_all(&mut self) {
        if self.state.nodes.is_empty() {
            return;
        }
        if self.connected && self.state.mode == ProxyMode::Tun && self.state.kill_switch {
            self.append_log(
                "Note: Kill-Switch (allexceptlan) blocks direct Wi-Fi TCP ping; disconnect first.",
            );
        }
        self.ping_gen = self.ping_gen.wrapping_add(1);
        let gen = self.ping_gen;
        EnableWindow(self.h_btn_ping, 0);
        set_text(self.h_btn_ping, "Pinging...");
        self.append_log("Running TCP ping on all servers...");
        let targets = extract_ping_targets(&self.state.nodes);
        let tx1 = self.ev_tx.clone();
        let tx2 = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        ping_all_async(
            targets,
            move |idx, ms| {
                let _ = tx1.send(UiEvent::PingResult(gen, idx, ms));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
            move || {
                let _ = tx2.send(UiEvent::PingFinished(gen));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
        );
    }

    unsafe fn on_ping_single(&mut self, idx: usize) {
        let Some((name, addr, port)) = self
            .state
            .nodes
            .get(idx)
            .map(|n| (n.name.clone(), n.address.clone(), n.port))
        else {
            return;
        };
        if self.connected && self.state.mode == ProxyMode::Tun && self.state.kill_switch {
            self.append_log(
                "Note: Kill-Switch (allexceptlan) blocks direct Wi-Fi TCP ping; disconnect first.",
            );
        }
        self.ping_gen = self.ping_gen.wrapping_add(1);
        let gen = self.ping_gen;
        let targets = vec![(idx, addr, port)];
        self.append_log(&format!("Running TCP ping on {}...", name));
        let tx1 = self.ev_tx.clone();
        let tx2 = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        ping_all_async(
            targets,
            move |i, ms| {
                let _ = tx1.send(UiEvent::PingResult(gen, i, ms));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
            move || {
                let _ = tx2.send(UiEvent::PingFinished(gen));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
        );
    }

    unsafe fn start_real_ping_nodes(&mut self, items: Vec<(usize, VlessNode)>, desc: &str) {
        if items.is_empty() {
            return;
        }
        self.cancel_real_ping();
        if self.connected && self.state.mode == ProxyMode::Tun && self.state.kill_switch {
            self.append_log(
                "Note: Kill-Switch (allexceptlan) blocks direct Real Ping; disconnect first.",
            );
        }
        let gen = self.real_ping_gen;
        let cancel = Arc::new(AtomicBool::new(false));
        self.real_ping_cancel = Some(cancel.clone());
        set_text(self.h_btn_real_ping, "Stop");
        self.append_log(&format!("Running Real Ping (HTTPS /generate_204) on {}...", desc));

        let bind_physical = self.connected && self.state.mode == ProxyMode::Tun;
        let opts = self.current_outbound_opts();
        let tx1 = self.ev_tx.clone();
        let tx2 = self.ev_tx.clone();
        let tx3 = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        real_ping_all_async(
            items,
            bind_physical,
            opts,
            cancel,
            move |idx, ms| {
                let _ = tx1.send(UiEvent::RealPingResult(gen, idx, ms));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
            move |err| {
                let _ = tx2.send(UiEvent::RealPingError(gen, err));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
            move || {
                let _ = tx3.send(UiEvent::RealPingFinished(gen));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
        );
    }

    unsafe fn on_real_ping_toggle(&mut self) {
        if self.real_ping_cancel.is_some() {
            self.cancel_real_ping();
            self.append_log("Real ping cancelled.");
            return;
        }
        if self.state.nodes.is_empty() {
            return;
        }
        let items: Vec<(usize, VlessNode)> = self
            .state
            .nodes
            .iter()
            .cloned()
            .enumerate()
            .collect();
        self.start_real_ping_nodes(items, "all servers");
    }

    unsafe fn on_real_ping_single(&mut self, idx: usize) {
        let Some(node) = self.state.nodes.get(idx).cloned() else {
            return;
        };
        let name = node.name.clone();
        self.start_real_ping_nodes(vec![(idx, node)], &name);
    }

    // Automatically prompts Windows UAC and relaunches elevated; rolls back if UAC is cancelled
    unsafe fn trigger_uac_relaunch(&mut self, autoconnect_after: bool, fallback_to_proxy: bool) {
        self.sync_state_from_controls();
        let was_connected = self.connected;
        if was_connected {
            self.disconnect();
        }
        let _ = self.state.save();

        // Release single-instance mutex BEFORE spawning elevated process
        if !self.h_mutex.is_null() {
            CloseHandle(self.h_mutex);
            self.h_mutex = null_mut();
        }
        self.remove_tray_icon();

        let args = if autoconnect_after { Some("--autoconnect") } else { None };
        if relaunch_as_admin(args) {
            self.exiting = true;
            DestroyWindow(self.hwnd);
        } else {
            // UAC cancelled; restore mutex, tray icon, and fallback mode
            let mutex_name = to_wide(MUTEX_NAME);
            self.h_mutex = CreateMutexW(null(), 1, mutex_name.as_ptr());
            self.add_tray_icon();
            if fallback_to_proxy {
                self.state.mode = ProxyMode::SystemProxy;
                SendMessageW(self.h_radio_proxy, BM_SETCHECK, 1, 0);
                SendMessageW(self.h_radio_tun, BM_SETCHECK, 0, 0);
                let _ = self.state.save();
            }
            self.append_log("Admin elevation (UAC) was cancelled.");
            self.update_status_and_tray();
            if was_connected {
                self.connect();
            }
        }
    }

    unsafe fn select_tun_mode(&mut self) {
        if self.state.mode == ProxyMode::Tun && self.is_admin {
            return;
        }
        let should_autoconnect = self.connected;
        self.state.mode = ProxyMode::Tun;
        SendMessageW(self.h_radio_proxy, BM_SETCHECK, 0, 0);
        SendMessageW(self.h_radio_tun, BM_SETCHECK, 1, 0);
        let _ = self.state.save();

        if !self.is_admin {
            self.append_log("TUN requires admin rights: requesting UAC elevation...");
            self.trigger_uac_relaunch(should_autoconnect, true);
            return;
        }

        self.update_status_and_tray();
        self.reconnect_if_connected();
    }

    unsafe fn connect(&mut self) {
        self.sync_state_from_controls();
        if self.state.mode == ProxyMode::Tun && !self.is_admin {
            self.append_log("TUN requires admin rights: requesting UAC elevation...");
            self.trigger_uac_relaunch(true, true);
            return;
        }

        let Some(node) = self.state.nodes.get(self.state.selected_index).cloned() else {
            msg_box(
                self.hwnd,
                "Load a subscription and select a server first.",
                "Connect",
                MB_OK | MB_ICONINFORMATION,
            );
            return;
        };

        if node.allow_insecure {
            self.append_log("Note: Server URI specifies allowInsecure=1 (removed in Xray 26.x; strict TLS verification is enforced).");
        }

        let cfg = match build_xray_config(&self.state, &node) {
            Ok(c) => c,
            Err(e) => {
                self.append_log(&format!("Config generation error: {}", e));
                msg_box(self.hwnd, &e, "Config Error", MB_OK | MB_ICONERROR);
                return;
            }
        };

        let tx_log = self.ev_tx.clone();
        let tx_exit = self.ev_tx.clone();
        let hwnd_raw = self.hwnd as usize;
        let (raw_tx, raw_rx) = mpsc::channel::<String>();

        std::thread::spawn(move || {
            for line in raw_rx {
                let _ = tx_log.send(UiEvent::LogLine(line));
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
            move || {
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
            move |exited_pid| {
                let _ = tx_exit.send(UiEvent::XrayExited(exited_pid));
                PostMessageW(hwnd_raw as HWND, WM_UI_EVENT, 0, 0);
            },
        ) {
            Ok(xray_pid) => {
                let mut reset_cnt = 0usize;
                if self.state.mode == ProxyMode::SystemProxy {
                    if let Err(e) = enable_system_proxy(self.state.http_port) {
                        self.runner.stop();
                        self.append_log(&format!("System Proxy error: {}", e));
                        msg_box(self.hwnd, &e, "System Proxy Error", MB_OK | MB_ICONERROR);
                        return;
                    }
                    flush_dns_cache();
                } else {
                    // TUN is up: lock Metric=0 + 0.0.0.0/0 on avel0, reset pre-VPN Wi-Fi sockets,
                    // flush DNS, and spawn post-PnP default-route guard.
                    disable_system_proxy();
                    let _ = enforce_tun_route_and_metric("avel0");
                    reset_cnt = reset_external_tcp_connections(xray_pid);
                    flush_dns_cache();
                    notify_network_change();

                    let tx_guard = self.ev_tx.clone();
                    let hwnd_guard = self.hwnd as usize;
                    spawn_tun_post_pnp_guard("avel0", xray_pid, move |msg| {
                        let _ = tx_guard.send(UiEvent::LogLine(msg));
                        PostMessageW(hwnd_guard as HWND, WM_UI_EVENT, 0, 0);
                    });

                    self.tun_luid = find_adapter_luid("avel0");
                    self.stats_prev = self.tun_luid.and_then(query_luid_octets);
                    self.stats_base = self.stats_prev;
                    SetTimer(self.hwnd, TIMER_STATS, 1000, None);
                }
                self.connected = true;
                self.connected_node_key = Some((node.uuid.clone(), node.address.clone(), node.port));
                InvalidateRect(self.h_list_nodes, null(), 1);
                self.clear_traffic_stats();
                let _ = self.state.save();
                // Drain core startup stdout lines first so our Connected summary stays visible at bottom
                self.drain_ui_events();
                if self.state.mode == ProxyMode::Tun && reset_cnt > 0 {
                    self.append_log(&format!(
                        "Connected: {} [{}:{}] (TUN, {}, reset {} pre-VPN socket(s))",
                        node.name,
                        node.address,
                        node.port,
                        self.state.routing.short_label(),
                        reset_cnt
                    ));
                } else {
                    self.append_log(&format!(
                        "Connected: {} [{}:{}] ({:?}, {})",
                        node.name,
                        node.address,
                        node.port,
                        self.state.mode,
                        self.state.routing.short_label()
                    ));
                }
                self.update_status_and_tray();
            }
            Err(e) => {
                disable_system_proxy();
                self.connected = false;
                self.append_log(&e);
                msg_box(self.hwnd, &e, "Xray Start Error", MB_OK | MB_ICONERROR);
                self.update_status_and_tray();
            }
        }
    }

    unsafe fn disconnect(&mut self) {
        KillTimer(self.hwnd, TIMER_STATS);
        self.clear_traffic_stats();
        self.tun_luid = None;
        self.stats_base = None;
        self.stats_prev = None;
        self.runner.stop();
        disable_system_proxy();
        flush_dns_cache();
        if self.connected {
            self.connected = false;
            self.connected_node_key = None;
            InvalidateRect(self.h_list_nodes, null(), 1);
            self.append_log("Disconnected. System Proxy disabled.");
        }
        self.update_status_and_tray();
    }

    unsafe fn reconnect_if_connected(&mut self) {
        if self.connected {
            self.disconnect();
            std::thread::sleep(std::time::Duration::from_millis(350));
            self.connect();
        }
    }

    unsafe fn drain_ui_events(&mut self) {
        while let Ok(ev) = self.ev_rx.try_recv() {
            match ev {
                UiEvent::LogLine(line) => self.append_log(&line),
                UiEvent::SubFetched {
                    sub_id,
                    url,
                    silent,
                    res,
                } => {
                    self.sub_fetching = false;
                    EnableWindow(self.h_btn_fetch, 1);
                    set_text(self.h_btn_fetch, "Update");
                    match res {
                        Ok(SubFetchOutcome { mut nodes, resp }) => {
                            self.sub_retry_after.remove(&sub_id);
                            let had_sel = SendMessageW(self.h_list_nodes, LB_GETCURSEL, 0, 0) >= 0;
                            let prev_key = self.state.nodes.get(self.state.selected_index).map(|n| {
                                (
                                    n.protocol.clone(),
                                    n.uuid.clone(),
                                    n.address.clone(),
                                    n.port,
                                )
                            });
                            let old_pings: HashMap<(String, String, String, u16), u32> = self
                                .state
                                .nodes
                                .iter()
                                .filter_map(|n| {
                                    n.ping_ms.map(|ms| {
                                        (
                                            (
                                                n.protocol.clone(),
                                                n.uuid.clone(),
                                                n.address.clone(),
                                                n.port,
                                            ),
                                            ms,
                                        )
                                    })
                                })
                                .collect();
                            for n in &mut nodes {
                                n.source_sub_id = Some(sub_id.clone());
                                let k = (
                                    n.protocol.clone(),
                                    n.uuid.clone(),
                                    n.address.clone(),
                                    n.port,
                                );
                                if let Some(&ms) = old_pings.get(&k) {
                                    n.ping_ms = Some(ms);
                                }
                            }

                            let cnt = nodes.len();
                            let first_pos = self
                                .state
                                .nodes
                                .iter()
                                .position(|n| n.source_sub_id.as_deref() == Some(sub_id.as_str()));
                            self.state
                                .nodes
                                .retain(|n| n.source_sub_id.as_deref() != Some(sub_id.as_str()));
                            if let Some(pos) = first_pos {
                                let insert_at = pos.min(self.state.nodes.len());
                                self.state.nodes.splice(insert_at..insert_at, nodes);
                            } else {
                                self.state.nodes.extend(nodes);
                            }

                            let now = now_unix();
                            let sub_title = if let Some(existing) =
                                self.state.subscriptions.iter_mut().find(|s| s.id == sub_id)
                            {
                                existing.url = url.clone();
                                existing.last_updated_unix = now;
                                if let Some(ref title) = resp.profile_title {
                                    if !title.trim().is_empty() {
                                        existing.name = title.trim().to_string();
                                    }
                                } else if existing.name.trim().is_empty() {
                                    existing.name = short_sub_host(&url);
                                }
                                if let Some(hrs) = resp.update_interval_hours {
                                    existing.update_interval_hours = hrs;
                                }
                                if let Some(ref ui) = resp.userinfo {
                                    existing.userinfo = ui.clone();
                                }
                                existing.name.clone()
                            } else {
                                let title = resp
                                    .profile_title
                                    .clone()
                                    .filter(|s| !s.trim().is_empty())
                                    .unwrap_or_else(|| short_sub_host(&url));
                                self.state.subscriptions.push(SubscriptionProfile {
                                    id: sub_id.clone(),
                                    name: title.clone(),
                                    url: url.clone(),
                                    update_interval_hours: resp.update_interval_hours.unwrap_or(0),
                                    last_updated_unix: now,
                                    userinfo: resp.userinfo.clone().unwrap_or_default(),
                                });
                                title
                            };

                            if !silent || self.active_sub_id.is_none() {
                                self.active_sub_id = Some(sub_id.clone());
                                self.state.subscription_url = url.clone();
                            }
                            if let Some(ref ui) = resp.userinfo {
                                self.state.subscription_info = ui.clone();
                            }

                            let preserved_idx = prev_key
                                .and_then(|(pr, u, a, p)| {
                                    self.state.nodes.iter().position(|n| {
                                        n.protocol == pr && n.uuid == u && n.address == a && n.port == p
                                    })
                                })
                                .unwrap_or(0);
                            self.state.selected_index = preserved_idx;
                            self.cancel_real_ping();
                            self.ping_gen = self.ping_gen.wrapping_add(1);
                            let _ = self.state.save();
                            self.rebuild_sub_combo();
                            self.rebuild_node_list_with_sel(if silent { had_sel } else { true });

                            let mut extras: Vec<String> = Vec::new();
                            if let Some(ref ui) = resp.userinfo {
                                if !ui.is_empty() {
                                    extras.push(ui.clone());
                                }
                            }
                            if let Some(hrs) = resp.update_interval_hours {
                                if hrs > 0 {
                                    extras.push(format!("auto {}h", hrs));
                                }
                            }
                            if resp.via_proxy {
                                extras.push("via proxy".to_string());
                            }
                            if extras.is_empty() {
                                self.append_log(&format!(
                                    "Subscription '{}' updated: {} server(s).",
                                    sub_title, cnt
                                ));
                            } else {
                                self.append_log(&format!(
                                    "Subscription '{}' updated: {} server(s) ({}).",
                                    sub_title,
                                    cnt,
                                    extras.join(", ")
                                ));
                            }
                            if silent {
                                self.check_due_subscription_updates();
                            }
                        }
                        Err(e) => {
                            if silent {
                                self.sub_retry_after
                                    .insert(sub_id, now_unix().saturating_add(900));
                                self.append_log(&format!("Auto-update failed: {}", e));
                                self.check_due_subscription_updates();
                            } else {
                                self.append_log(&format!("Subscription error: {}", e));
                                msg_box(self.hwnd, &e, "Subscription Error", MB_OK | MB_ICONERROR);
                            }
                        }
                    }
                }
                UiEvent::PingResult(gen, idx, ms) => {
                    if gen == self.ping_gen {
                        if let Some(n) = self.state.nodes.get_mut(idx) {
                            n.ping_ms = Some(ms);
                        }
                        self.update_single_node_row(idx);
                    }
                }
                UiEvent::PingFinished(gen) => {
                    if gen == self.ping_gen {
                        EnableWindow(self.h_btn_ping, 1);
                        set_text(self.h_btn_ping, "TCP Ping");
                        self.append_log("TCP ping finished.");
                    }
                }
                UiEvent::RealPingResult(gen, idx, ms) => {
                    if gen == self.real_ping_gen {
                        if let Some(n) = self.state.nodes.get_mut(idx) {
                            n.ping_ms = Some(ms);
                        }
                        self.update_single_node_row(idx);
                    }
                }
                UiEvent::RealPingError(gen, err) => {
                    if gen == self.real_ping_gen {
                        self.append_log(&err);
                    }
                }
                UiEvent::RealPingFinished(gen) => {
                    if gen == self.real_ping_gen {
                        self.real_ping_cancel = None;
                        set_text(self.h_btn_real_ping, "Real Ping");
                        self.append_log("Real ping finished.");
                    }
                }
                UiEvent::GeoUpdated(res) => {
                    EnableWindow(self.h_btn_update_geo, 1);
                    set_text(self.h_btn_update_geo, "Update GeoIP / GeoSite");
                    self.refresh_geo_info_label();
                    match res {
                        Ok((ip_sz, site_sz)) => {
                            self.append_log(&format!(
                                "Geo databases updated: geoip.dat ({}), geosite.dat ({}). Reconnect to apply.",
                                fmt_bytes(ip_sz as u64),
                                fmt_bytes(site_sz as u64)
                            ));
                        }
                        Err(e) => {
                            self.append_log(&format!("Geo update failed: {}", e));
                            msg_box(self.hwnd, &e, "Geo Update Error", MB_OK | MB_ICONERROR);
                        }
                    }
                }
                UiEvent::UpdateChecked { silent, res } => {
                    self.update_checking = false;
                    if !silent {
                        EnableWindow(self.h_btn_check_update, 1);
                        set_text(self.h_btn_check_update, "Check Updates");
                    }
                    match res {
                        Ok(rel) => {
                            self.state.last_update_check_unix = now_unix();
                            let _ = self.state.save();
                            if is_newer_version(APP_VERSION, &rel.tag) {
                                set_text(
                                    self.h_lbl_update_info,
                                    &format!("Available: {}", rel.tag),
                                );
                                self.append_log(&format!(
                                    "Update available: {} (current v{}).",
                                    rel.tag, APP_VERSION
                                ));
                                if !silent || IsWindowVisible(self.hwnd) != 0 {
                                    self.pending_update = None;
                                    self.update_status_and_tray();
                                    self.prompt_update_dialog(rel);
                                } else {
                                    self.pending_update = Some(rel);
                                    self.update_status_and_tray();
                                }
                            } else {
                                self.pending_update = None;
                                set_text(
                                    self.h_lbl_update_info,
                                    &format!("Up to date (v{})", APP_VERSION),
                                );
                                if !silent {
                                    self.append_log(&format!(
                                        "Already on latest version (v{}, GitHub latest: {}).",
                                        APP_VERSION, rel.tag
                                    ));
                                    msg_box(
                                        self.hwnd,
                                        &format!(
                                            "You are already using the latest version (v{}).",
                                            APP_VERSION
                                        ),
                                        "Check Updates",
                                        MB_OK | MB_ICONINFORMATION,
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            if !silent {
                                set_text(self.h_lbl_update_info, "Update check failed");
                                self.append_log(&format!("Update check failed: {}", e));
                                msg_box(self.hwnd, &e, "Update Check Error", MB_OK | MB_ICONERROR);
                            }
                        }
                    }
                }
                UiEvent::UpdateDownloaded(res) => match res {
                    Ok(zip_path) => {
                        let was_connected = self.connected;
                        self.append_log("Update verified (SHA256 OK). Installing and restarting...");
                        set_text(self.h_lbl_update_info, "Installing & restarting...");
                        self.disconnect();
                        let _ = self.state.save();
                        match spawn_self_update_helper(&zip_path, &app_base_dir(), was_connected) {
                            Ok(()) => self.full_exit(),
                            Err(e) => {
                                EnableWindow(self.h_btn_check_update, 1);
                                set_text(self.h_btn_check_update, "Check Updates");
                                set_text(self.h_lbl_update_info, "Install failed");
                                self.append_log(&format!("Self-update helper failed: {}", e));
                                msg_box(self.hwnd, &e, "Update Error", MB_OK | MB_ICONERROR);
                            }
                        }
                    }
                    Err(e) => {
                        EnableWindow(self.h_btn_check_update, 1);
                        set_text(self.h_btn_check_update, "Check Updates");
                        set_text(self.h_lbl_update_info, "Download failed");
                        self.append_log(&format!("Update download failed: {}", e));
                        msg_box(self.hwnd, &e, "Update Error", MB_OK | MB_ICONERROR);
                    }
                },
                UiEvent::XrayExited(exited_pid) => {
                    if self.connected && self.runner.active_pid() == Some(exited_pid) {
                        KillTimer(self.hwnd, TIMER_STATS);
                        self.clear_traffic_stats();
                        self.tun_luid = None;
                        self.stats_base = None;
                        self.stats_prev = None;
                        self.runner.stop();
                        disable_system_proxy();
                        flush_dns_cache();
                        self.connected = false;
                        self.connected_node_key = None;
                        InvalidateRect(self.h_list_nodes, null(), 1);
                        self.append_log("WARNING: avel-core.exe exited unexpectedly. Disconnected.");
                        self.update_status_and_tray();
                    }
                }
            }
        }
    }

    unsafe fn selected_node_index(&self) -> Option<usize> {
        let sel = SendMessageW(self.h_list_nodes, LB_GETCURSEL, 0, 0);
        if sel >= 0 && (sel as usize) < self.state.nodes.len() {
            Some(sel as usize)
        } else {
            None
        }
    }

    unsafe fn on_remove_selected_node(&mut self) {
        let Some(idx) = self.selected_node_index() else {
            return;
        };
        self.cancel_real_ping();
        self.ping_gen = self.ping_gen.wrapping_add(1);
        self.state.nodes.remove(idx);
        if self.state.selected_index >= self.state.nodes.len() && !self.state.nodes.is_empty() {
            self.state.selected_index = self.state.nodes.len() - 1;
        }
        let _ = self.state.save();
        self.rebuild_node_list();
    }

    unsafe fn on_copy_selected_uri(&mut self) {
        let Some(idx) = self.selected_node_index() else {
            return;
        };
        let uri = self.state.nodes[idx].to_share_uri();
        let name = self.state.nodes[idx].name.clone();
        if set_clipboard_text(self.hwnd, &uri) {
            self.append_log(&format!("Copied URI for '{}' to clipboard.", name));
        } else {
            self.append_log("Failed to write URI to clipboard.");
        }
    }

    unsafe fn on_rename_selected_node(&mut self) {
        let Some(idx) = self.selected_node_index() else {
            return;
        };
        let old_name = self.state.nodes[idx].name.clone();
        if let Some(new_name) = show_rename_dialog(self.hwnd, self.dpi, self.font_ui, &old_name) {
            if new_name != old_name {
                self.state.nodes[idx].name = new_name.clone();
                let old_target = format!("node:{}", old_name);
                let new_target = format!("node:{}", new_name);
                for rule in &mut self.state.custom_rules {
                    if rule.target == old_target {
                        rule.target = new_target.clone();
                    }
                }
                let _ = self.state.save();
                self.state.selected_index = idx;
                self.rebuild_node_list();
                self.rebuild_rule_list(None);
                self.append_log(&format!("Renamed server '{}' -> '{}'.", old_name, new_name));
            }
        }
    }

    unsafe fn on_edit_selected_node(&mut self) {
        let Some(idx) = self.selected_node_index() else {
            return;
        };
        let orig = self.state.nodes[idx].clone();
        if let Some(updated) = show_edit_node_dialog(
            self.hwnd,
            self.dpi,
            self.font_ui,
            self.font_mono,
            &orig,
        ) {
            let old_name = orig.name.clone();
            let new_name = updated.name.clone();
            let net_changed = orig.address != updated.address
                || orig.port != updated.port
                || orig.uuid != updated.uuid
                || orig.sni != updated.sni
                || orig.network != updated.network
                || orig.security != updated.security
                || orig.path != updated.path
                || orig.service_name != updated.service_name;

            self.state.nodes[idx] = updated;
            if new_name != old_name {
                let old_target = format!("node:{}", old_name);
                let new_target = format!("node:{}", new_name);
                for rule in &mut self.state.custom_rules {
                    if rule.target == old_target {
                        rule.target = new_target.clone();
                    }
                }
            }
            let _ = self.state.save();
            self.state.selected_index = idx;
            self.rebuild_node_list();
            self.rebuild_rule_list(None);
            if net_changed && self.connected {
                self.append_log(&format!(
                    "Updated server '{}'. Reconnect to apply changes.",
                    new_name
                ));
            } else {
                self.append_log(&format!("Updated server '{}'.", new_name));
            }
        }
    }

    unsafe fn show_node_context_menu(&mut self) {
        let menu: HMENU = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let has_sel = self.selected_node_index().is_some();
        let node_flag = if has_sel { MF_STRING } else { MF_STRING | MF_GRAYED };

        let s_connect = to_wide("Connect");
        let s_tcp_ping = to_wide("TCP Ping");
        let s_real_ping = to_wide("Real Ping");
        let s_import = to_wide("Import from Clipboard (Ctrl+V)");
        let s_copy = to_wide("Copy URI");
        let s_rename = to_wide("Rename...");
        let s_edit = to_wide("Edit / Details...");
        let s_remove = to_wide("Remove");

        AppendMenuW(menu, node_flag, ID_CTX_CONNECT, s_connect.as_ptr());
        AppendMenuW(menu, node_flag, ID_CTX_TCP_PING, s_tcp_ping.as_ptr());
        AppendMenuW(menu, node_flag, ID_CTX_REAL_PING, s_real_ping.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, ID_CTX_IMPORT_CLIP, s_import.as_ptr());
        AppendMenuW(menu, node_flag, ID_CTX_COPY_URI, s_copy.as_ptr());
        AppendMenuW(menu, node_flag, ID_CTX_RENAME, s_rename.as_ptr());
        AppendMenuW(menu, node_flag, ID_CTX_EDIT, s_edit.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, node_flag, ID_CTX_REMOVE, s_remove.as_ptr());

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(self.hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_TOPALIGN,
            pt.x,
            pt.y,
            0,
            self.hwnd,
            null(),
        );
        DestroyMenu(menu);
    }

    unsafe fn show_tray_menu(&self) {
        let menu: HMENU = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let s_open = to_wide("Open Window");
        let s_toggle = to_wide(if self.connected { "Disconnect" } else { "Connect" });
        let s_proxy = to_wide("Mode: System Proxy");
        let s_tun = to_wide("Mode: TUN (all traffic)");
        let s_exit = to_wide("Exit");

        AppendMenuW(menu, MF_STRING, ID_TRAY_SHOW, s_open.as_ptr());
        AppendMenuW(menu, MF_STRING, ID_TRAY_TOGGLE, s_toggle.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, ID_TRAY_MODE_PROXY, s_proxy.as_ptr());
        AppendMenuW(menu, MF_STRING, ID_TRAY_MODE_TUN, s_tun.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, null());
        AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, s_exit.as_ptr());

        CheckMenuItem(
            menu,
            ID_TRAY_MODE_PROXY as u32,
            MF_BYCOMMAND
                | if self.state.mode == ProxyMode::SystemProxy {
                    MF_CHECKED
                } else {
                    MF_UNCHECKED
                },
        );
        CheckMenuItem(
            menu,
            ID_TRAY_MODE_TUN as u32,
            MF_BYCOMMAND
                | if self.state.mode == ProxyMode::Tun {
                    MF_CHECKED
                } else {
                    MF_UNCHECKED
                },
        );

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(self.hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            0,
            self.hwnd,
            null(),
        );
        DestroyMenu(menu);
    }

    unsafe fn full_exit(&mut self) {
        self.exiting = true;
        self.cancel_real_ping();
        self.disconnect();
        let _ = self.state.save();
        self.remove_tray_icon();
        DestroyWindow(self.hwnd);
    }

    unsafe fn cleanup_resources(&self) {
        if !self.h_mutex.is_null() {
            CloseHandle(self.h_mutex);
        }
        if !self.font_ui.is_null() {
            DeleteObject(self.font_ui as _);
        }
        if !self.font_mono.is_null() {
            DeleteObject(self.font_mono as _);
        }
        if !self.font_mono_bold.is_null() {
            DeleteObject(self.font_mono_bold as _);
        }
        if !self.icon_small.is_null() {
            DestroyIcon(self.icon_small);
        }
        if !self.icon_big.is_null() {
            DestroyIcon(self.icon_big);
        }
        if !self.hbr_bg.is_null() {
            DeleteObject(self.hbr_bg as _);
        }
    }

    unsafe fn paint_watermark_bg(&self, hdc: HDC) -> bool {
        if self.hbr_bg.is_null() || hdc.is_null() {
            return false;
        }
        let mut org = POINT { x: 0, y: 0 };
        GetViewportOrgEx(hdc, &mut org);
        SetBrushOrgEx(hdc, org.x, org.y, null_mut());
        let rc = RECT {
            left: 0,
            top: 0,
            right: self.bg_w,
            bottom: self.bg_h,
        };
        FillRect(hdc, &rc, self.hbr_bg);
        true
    }

    unsafe fn draw_node_list_item(&self, dis: &DRAWITEMSTRUCT) {
        if dis.itemID == u32::MAX {
            return;
        }
        let idx = dis.itemID as usize;
        let Some(node) = self.state.nodes.get(idx) else {
            return;
        };

        let hdc = dis.hDC;
        let selected = (dis.itemState & ODS_SELECTED) != 0;
        let bg_brush = GetSysColorBrush(if selected {
            COLOR_HIGHLIGHT
        } else {
            COLOR_WINDOW
        });
        FillRect(hdc, &dis.rcItem, bg_brush);

        let fg_color = GetSysColor(if selected {
            COLOR_HIGHLIGHTTEXT
        } else {
            COLOR_WINDOWTEXT
        });
        SetTextColor(hdc, fg_color);
        SetBkMode(hdc, TRANSPARENT as i32);

        let is_active = self.connected
            && self
                .connected_node_key
                .as_ref()
                .map(|(u, a, p)| u == &node.uuid && a == &node.address && *p == node.port)
                .unwrap_or(false);

        let pad_x = scale_dpi(6, self.dpi);
        let gap = scale_dpi(12, self.dpi);
        let name_w = scale_dpi(108, self.dpi);
        let proto_w = scale_dpi(88, self.dpi);
        let ping_w = scale_dpi(62, self.dpi);

        let top = dis.rcItem.top;
        let bottom = dis.rcItem.bottom;
        let right = dis.rcItem.right - pad_x;

        let rc_ping = RECT {
            left: (right - ping_w).max(dis.rcItem.left),
            top,
            right,
            bottom,
        };
        let rc_proto = RECT {
            left: (rc_ping.left - gap - proto_w).max(dis.rcItem.left),
            top,
            right: (rc_ping.left - gap).max(dis.rcItem.left),
            bottom,
        };
        let rc_name = RECT {
            left: dis.rcItem.left + pad_x,
            top,
            right: (dis.rcItem.left + pad_x + name_w).min((rc_proto.left - gap).max(dis.rcItem.left + pad_x)),
            bottom,
        };
        let rc_host = RECT {
            left: rc_name.right + gap,
            top,
            right: (rc_proto.left - gap).max(rc_name.right + gap),
            bottom,
        };

        let old_font = SelectObject(
            hdc,
            if is_active {
                self.font_mono_bold as _
            } else {
                self.font_mono as _
            },
        );
        let mut r_name = rc_name;
        let w_name = to_wide(&node.name);
        DrawTextW(
            hdc,
            w_name.as_ptr(),
            (w_name.len().saturating_sub(1)) as i32,
            &mut r_name,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
        );

        SelectObject(hdc, self.font_mono as _);
        if rc_host.right > rc_host.left + scale_dpi(16, self.dpi) {
            let mut r_host = rc_host;
            let w_host = to_wide(&node.address);
            DrawTextW(
                hdc,
                w_host.as_ptr(),
                (w_host.len().saturating_sub(1)) as i32,
                &mut r_host,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
            );
        }

        if rc_proto.right > rc_proto.left {
            let mut r_proto = rc_proto;
            let w_proto = to_wide(&node.protocol_tag());
            DrawTextW(
                hdc,
                w_proto.as_ptr(),
                (w_proto.len().saturating_sub(1)) as i32,
                &mut r_proto,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
            );
        }

        if rc_ping.right > rc_ping.left {
            const fn rgb(r: u8, g: u8, b: u8) -> u32 {
                (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
            }
            let (ping_text, ping_color) = match node.ping_ms {
                None => ("-".to_string(), if selected { fg_color } else { rgb(124, 132, 144) }),
                Some(0) => ("timeout".to_string(), if selected { fg_color } else { rgb(196, 43, 28) }),
                Some(ms) => {
                    let color = if selected {
                        fg_color
                    } else if ms > 250 {
                        rgb(196, 43, 28)
                    } else if ms > 120 {
                        rgb(180, 105, 0)
                    } else {
                        rgb(21, 128, 61)
                    };
                    (format!("{} ms", ms), color)
                }
            };
            SetTextColor(hdc, ping_color);
            let mut r_ping = rc_ping;
            let w_ping = to_wide(&ping_text);
            DrawTextW(
                hdc,
                w_ping.as_ptr(),
                (w_ping.len().saturating_sub(1)) as i32,
                &mut r_ping,
                DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
            SetTextColor(hdc, fg_color);
        }
        SelectObject(hdc, old_font);

        if (dis.itemState & ODS_FOCUS) != 0 {
            DrawFocusRect(hdc, &dis.rcItem);
        }
    }
}

unsafe fn subclass_listbox_empty_deselect(h_list: HWND) {
    if h_list.is_null() {
        return;
    }
    let prev = SetWindowLongPtrW(
        h_list,
        GWLP_WNDPROC,
        listbox_deselect_proc as *const () as usize as isize,
    ) as usize;
    if prev != 0 {
        let _ = ORIG_LISTBOX_PROC.compare_exchange(
            0,
            prev,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
    }
}

unsafe extern "system" fn listbox_deselect_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_LBUTTONDOWN {
        let res = SendMessageW(hwnd, LB_ITEMFROMPOINT, 0, lparam) as u32;
        if (res >> 16) != 0 {
            SendMessageW(hwnd, LB_SETCURSEL, usize::MAX, 0);
            return 0;
        }
    } else if msg == WM_RBUTTONUP {
        if GetWindowLongPtrW(hwnd, GWL_ID) == ID_LIST_NODES as isize {
            let res = SendMessageW(hwnd, LB_ITEMFROMPOINT, 0, lparam) as u32;
            if (res >> 16) != 0 {
                SendMessageW(hwnd, LB_SETCURSEL, usize::MAX, 0);
            } else {
                let idx = (res & 0xFFFF) as usize;
                SendMessageW(hwnd, LB_SETCURSEL, idx, 0);
            }
            let parent = GetParent(hwnd);
            if !parent.is_null() {
                PostMessageW(parent, WM_NODE_CTXMENU, 0, 0);
            }
            return 0;
        }
    } else if msg == WM_KEYDOWN {
        if GetWindowLongPtrW(hwnd, GWL_ID) == ID_LIST_NODES as isize
            && wparam == 0x56
            && ((GetKeyState(0x11) as u16) & 0x8000) != 0
        {
            let parent = GetParent(hwnd);
            if !parent.is_null() {
                PostMessageW(parent, WM_COMMAND, ID_CTX_IMPORT_CLIP, 0);
            }
            return 0;
        }
    }
    let orig = ORIG_LISTBOX_PROC.load(Ordering::Relaxed);
    if orig != 0 {
        let f: WNDPROC = std::mem::transmute(orig);
        CallWindowProcW(f, hwnd, msg, wparam, lparam)
    } else {
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppContext;
    if ptr.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    let ctx = &mut *ptr;

    if ctx.wm_taskbar_created != 0 && msg == ctx.wm_taskbar_created {
        ctx.tray_added = false;
        ctx.add_tray_icon();
        ctx.update_status_and_tray();
        return 0;
    }

    match msg {
        WM_ERASEBKGND => {
            if ctx.paint_watermark_bg(wparam as HDC) {
                return 1;
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_PRINTCLIENT => {
            if ctx.paint_watermark_bg(wparam as HDC) {
                return 0;
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let child = lparam as HWND;
            if child != ctx.h_edit_log && !ctx.hbr_bg.is_null() {
                let hdc = wparam as HDC;
                SetBkMode(hdc, TRANSPARENT as i32);
                if child == ctx.h_lbl_version {
                    SetTextColor(hdc, 0x0078_7878);
                }
                let mut pt = POINT { x: 0, y: 0 };
                MapWindowPoints(child, hwnd, &mut pt, 1);
                SetBrushOrgEx(hdc, -pt.x, -pt.y, null_mut());
                return ctx.hbr_bg as LRESULT;
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_MEASUREITEM => {
            if lparam != 0 {
                let mis = &mut *(lparam as *mut MEASUREITEMSTRUCT);
                if mis.CtlID == ID_LIST_NODES as u32 {
                    mis.itemHeight = scale_dpi(18, ctx.dpi) as u32;
                    return 1;
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_DRAWITEM => {
            if lparam != 0 {
                let dis = &*(lparam as *const DRAWITEMSTRUCT);
                if dis.CtlID == ID_LIST_NODES as u32 {
                    ctx.draw_node_list_item(dis);
                    return 1;
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_LBUTTONDOWN => {
            if ctx.active_tab == 0 {
                SendMessageW(ctx.h_list_nodes, LB_SETCURSEL, usize::MAX, 0);
            } else if ctx.active_tab == 1 {
                SendMessageW(ctx.h_list_rules, LB_SETCURSEL, usize::MAX, 0);
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_CLOSE => {
            if !ctx.exiting {
                ShowWindow(hwnd, SW_HIDE);
                return 0;
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_ENDSESSION => {
            ctx.disconnect();
            let _ = ctx.state.save();
            0
        }
        WM_DESTROY => {
            ctx.disconnect();
            ctx.remove_tray_icon();
            PostQuitMessage(0);
            0
        }
        WM_SHOW_EXISTING => {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            ctx.prompt_pending_update_if_any();
            0
        }
        WM_UI_EVENT => {
            ctx.drain_ui_events();
            0
        }
        WM_NODE_CTXMENU => {
            ctx.show_node_context_menu();
            0
        }
        WM_TRAYICON => {
            let ev = (lparam & 0xFFFF) as u32;
            match ev {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                    ShowWindow(hwnd, SW_SHOW);
                    SetForegroundWindow(hwnd);
                    ctx.prompt_pending_update_if_any();
                }
                WM_RBUTTONUP => {
                    ctx.show_tray_menu();
                }
                _ => {}
            }
            0
        }
        WM_POWERBROADCAST => {
            let pbt = wparam as u32;
            if pbt == PBT_APMSUSPEND {
                if ctx.state.reconnect_after_sleep && ctx.connected {
                    ctx.was_connected_before_sleep = true;
                    ctx.append_log("Entering sleep: stopping Xray...");
                    ctx.disconnect();
                }
            } else if pbt == PBT_APMRESUMEAUTOMATIC {
                if ctx.state.reconnect_after_sleep && ctx.was_connected_before_sleep {
                    ctx.was_connected_before_sleep = false;
                    ctx.append_log("Resumed from sleep: reconnecting in 2.5s...");
                    SetTimer(hwnd, TIMER_RESUME_RECONNECT, 2500, None);
                }
            }
            1
        }
        WM_TIMER => {
            if wparam == TIMER_RESUME_RECONNECT {
                KillTimer(hwnd, TIMER_RESUME_RECONNECT);
                if !ctx.connected && !ctx.state.nodes.is_empty() {
                    ctx.connect();
                }
            } else if wparam == TIMER_STATS {
                ctx.on_stats_tick();
            } else if wparam == TIMER_SUB_INIT {
                KillTimer(hwnd, TIMER_SUB_INIT);
                ctx.check_due_subscription_updates();
            } else if wparam == TIMER_SUB_AUTO {
                ctx.check_due_subscription_updates();
            } else if wparam == TIMER_UPDATE_CHECK {
                KillTimer(hwnd, TIMER_UPDATE_CHECK);
                ctx.start_update_check(true);
            }
            0
        }
        WM_NOTIFY => {
            if lparam != 0 {
                let nm = &*(lparam as *const NMHDR);
                if nm.idFrom == ID_TAB_MAIN && nm.code == TCN_SELCHANGE {
                    let sel = SendMessageW(ctx.h_tab, TCM_GETCURSEL, 0, 0);
                    if sel >= 0 {
                        ctx.switch_tab(sel as usize);
                    }
                }
            }
            0
        }
        WM_COMMAND => {
            let id = wparam & 0xFFFF;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            match id {
                ID_EDIT_SUB => {
                    if code == CBN_SELCHANGE {
                        let sel = SendMessageW(ctx.h_edit_sub, CB_GETCURSEL, 0, 0);
                        if sel >= 0 {
                            if let Some(sub_id) = ctx.sub_combo_ids.get(sel as usize).cloned() {
                                if let Some(sub) =
                                    ctx.state.subscriptions.iter().find(|s| s.id == sub_id)
                                {
                                    ctx.active_sub_id = Some(sub_id);
                                    ctx.state.subscription_url = sub.url.clone();
                                    let _ = ctx.state.save();
                                }
                            }
                        }
                    }
                }
                ID_BTN_FETCH => ctx.on_fetch_subscription(),
                ID_BTN_SUB_ADD => ctx.on_add_nodes_action(),
                ID_BTN_SUB_DEL => ctx.on_delete_subscription(),
                ID_BTN_PING => ctx.on_ping_all(),
                ID_BTN_REAL_PING => ctx.on_real_ping_toggle(),
                ID_BTN_DEL | ID_CTX_REMOVE => ctx.on_remove_selected_node(),
                ID_CTX_CONNECT => {
                    if let Some(idx) = ctx.selected_node_index() {
                        let clicked_key = ctx
                            .state
                            .nodes
                            .get(idx)
                            .map(|n| (n.uuid.clone(), n.address.clone(), n.port));
                        if !(ctx.connected
                            && clicked_key.is_some()
                            && ctx.connected_node_key == clicked_key)
                        {
                            ctx.state.selected_index = idx;
                            let _ = ctx.state.save();
                            if ctx.connected {
                                ctx.reconnect_if_connected();
                            } else {
                                ctx.connect();
                            }
                        }
                    }
                }
                ID_CTX_TCP_PING => {
                    if let Some(idx) = ctx.selected_node_index() {
                        ctx.on_ping_single(idx);
                    }
                }
                ID_CTX_REAL_PING => {
                    if let Some(idx) = ctx.selected_node_index() {
                        ctx.on_real_ping_single(idx);
                    }
                }
                ID_CTX_IMPORT_CLIP => ctx.on_import_from_clipboard(),
                ID_CTX_COPY_URI => ctx.on_copy_selected_uri(),
                ID_CTX_RENAME => ctx.on_rename_selected_node(),
                ID_CTX_EDIT => ctx.on_edit_selected_node(),
                ID_LIST_NODES => {
                    if code == LBN_SELCHANGE {
                        let sel = SendMessageW(ctx.h_list_nodes, LB_GETCURSEL, 0, 0);
                        if sel >= 0 {
                            ctx.state.selected_index = sel as usize;
                            let _ = ctx.state.save();
                        }
                    } else if code == LBN_DBLCLK {
                        let sel = SendMessageW(ctx.h_list_nodes, LB_GETCURSEL, 0, 0);
                        if sel >= 0 {
                            let idx = sel as usize;
                            let clicked_key = ctx
                                .state
                                .nodes
                                .get(idx)
                                .map(|n| (n.uuid.clone(), n.address.clone(), n.port));
                            if ctx.connected && clicked_key.is_some() && ctx.connected_node_key == clicked_key {
                                return 0;
                            }
                            ctx.state.selected_index = idx;
                            let _ = ctx.state.save();
                            if ctx.connected {
                                ctx.reconnect_if_connected();
                            } else {
                                ctx.connect();
                            }
                        }
                    }
                }
                ID_BTN_TOGGLE | ID_TRAY_TOGGLE => {
                    if ctx.connected {
                        ctx.disconnect();
                    } else {
                        ctx.connect();
                    }
                }
                ID_RADIO_PROXY | ID_TRAY_MODE_PROXY => {
                    if ctx.state.mode != ProxyMode::SystemProxy {
                        ctx.state.mode = ProxyMode::SystemProxy;
                        SendMessageW(ctx.h_radio_proxy, BM_SETCHECK, 1, 0);
                        SendMessageW(ctx.h_radio_tun, BM_SETCHECK, 0, 0);
                        let _ = ctx.state.save();
                        ctx.update_status_and_tray();
                        ctx.reconnect_if_connected();
                    }
                }
                ID_RADIO_TUN | ID_TRAY_MODE_TUN => {
                    ctx.select_tun_mode();
                }
                ID_COMBO_ROUTE => {
                    if code == CBN_SELCHANGE {
                        let idx = SendMessageW(ctx.h_combo_route, CB_GETCURSEL, 0, 0) as i32;
                        let next = RoutingPreset::from_index(idx);
                        if next != ctx.state.routing {
                            ctx.state.routing = next;
                            let _ = ctx.state.save();
                            ctx.append_log(&format!("Routing preset: {}", next.short_label()));
                            ctx.update_status_and_tray();
                            ctx.reconnect_if_connected();
                        }
                    }
                }
                ID_BTN_OPEN_ROUTING => {
                    ctx.switch_tab(1);
                }
                ID_BTN_RULES => {
                    ensure_default_custom_routing();
                    open_file_in_notepad(&custom_routing_path());
                }
                ID_COMBO_DEFAULT => {
                    if code == CBN_SELCHANGE {
                        let idx = SendMessageW(ctx.h_combo_default, CB_GETCURSEL, 0, 0) as i32;
                        ctx.state.custom_default_action = if idx == 1 {
                            RuleDefaultAction::Direct
                        } else {
                            RuleDefaultAction::Proxy
                        };
                        let _ = ctx.state.save();
                    }
                }
                ID_LIST_RULES => {
                    if code == LBN_DBLCLK {
                        ctx.on_toggle_selected_rule();
                    }
                }
                ID_BTN_RULE_APPLY => ctx.on_apply_rules(),
                ID_BTN_RULE_TOGGLE => ctx.on_toggle_selected_rule(),
                ID_BTN_RULE_UP => ctx.on_move_selected_rule(-1),
                ID_BTN_RULE_DOWN => ctx.on_move_selected_rule(1),
                ID_BTN_RULE_DEL => ctx.on_delete_selected_rule(),
                ID_BTN_RULE_ADD => ctx.on_add_rule(),
                ID_BTN_SETTINGS_APPLY => ctx.on_apply_settings(),
                ID_BTN_SETTINGS_RESET => ctx.on_reset_settings(),
                ID_CHK_SNIFFING => {
                    let chk = SendMessageW(ctx.h_chk_sniffing, BM_GETCHECK, 0, 0) != 0;
                    EnableWindow(ctx.h_chk_dest_override, if chk { 1 } else { 0 });
                }
                ID_BTN_UPDATE_GEO => ctx.on_update_geo(),
                ID_BTN_CHECK_UPDATE => ctx.on_check_updates(),
                ID_BTN_OPEN_FOLDER => open_folder_in_explorer(&app_base_dir()),
                ID_BTN_RULE_BROWSE => {
                    if let Some(exe_name) = browse_for_exe(hwnd) {
                        ctx.append_rule_match_token(&exe_name);
                    }
                }
                ID_BTN_RULE_PROCS => {
                    ctx.show_running_process_menu();
                }
                ID_BTN_PRESET_RU => {
                    let has_ru_dom = ctx
                        .state
                        .custom_rules
                        .iter()
                        .any(|r| r.value.contains("geosite:category-ru"));
                    if !has_ru_dom {
                        ctx.state.custom_rules.push(RoutingRule {
                            enabled: true,
                            kind: RuleMatchKind::Domain,
                            value: "geosite:category-ru, regexp:\\.ru$, regexp:\\.su$, regexp:\\.xn--p1ai$".to_string(),
                            target: "direct".to_string(),
                        });
                    }
                    let has_ru_ip = ctx
                        .state
                        .custom_rules
                        .iter()
                        .any(|r| r.value.contains("geoip:ru"));
                    if !has_ru_ip {
                        ctx.state.custom_rules.push(RoutingRule {
                            enabled: true,
                            kind: RuleMatchKind::Ip,
                            value: "geoip:ru".to_string(),
                            target: "direct".to_string(),
                        });
                    }
                    let _ = ctx.state.save();
                    let last = ctx.state.custom_rules.len().saturating_sub(1);
                    ctx.rebuild_rule_list(Some(last));
                }
                ID_BTN_PRESET_ADS => {
                    let has_ads = ctx
                        .state
                        .custom_rules
                        .iter()
                        .any(|r| r.value.contains("category-ads-all"));
                    if !has_ads {
                        ctx.state.custom_rules.push(RoutingRule {
                            enabled: true,
                            kind: RuleMatchKind::Domain,
                            value: "geosite:category-ads-all".to_string(),
                            target: "block".to_string(),
                        });
                        let _ = ctx.state.save();
                        let last = ctx.state.custom_rules.len().saturating_sub(1);
                        ctx.rebuild_rule_list(Some(last));
                    }
                }
                ID_CHK_SLEEP => {
                    let chk = SendMessageW(ctx.h_chk_sleep, BM_GETCHECK, 0, 0) != 0;
                    ctx.state.reconnect_after_sleep = chk;
                    let _ = ctx.state.save();
                }
                ID_CHK_AUTOSTART => {
                    let chk = SendMessageW(ctx.h_chk_autostart, BM_GETCHECK, 0, 0) != 0;
                    match set_autostart(chk) {
                        Ok(msg) => ctx.append_log(msg),
                        Err(e) => {
                            ctx.append_log(&format!("Autostart error: {}", e));
                            SendMessageW(
                                ctx.h_chk_autostart,
                                BM_SETCHECK,
                                if !chk { 1 } else { 0 },
                                0,
                            );
                        }
                    }
                }
                ID_CHK_KILLSWITCH => {
                    let chk = SendMessageW(ctx.h_chk_killswitch, BM_GETCHECK, 0, 0) != 0;
                    if chk != ctx.state.kill_switch {
                        ctx.state.kill_switch = chk;
                        let _ = ctx.state.save();
                        ctx.append_log(if chk {
                            "Kill-Switch (WFP allexceptlan) enabled."
                        } else {
                            "Kill-Switch disabled (standard DNS + misconfigtun protection)."
                        });
                        ctx.update_status_and_tray();
                        if ctx.state.mode == ProxyMode::Tun {
                            ctx.reconnect_if_connected();
                        }
                    }
                }
                ID_BTN_ELEVATE => {
                    ctx.trigger_uac_relaunch(ctx.connected, false);
                }
                ID_BTN_CLEAR_LOG => {
                    ctx.log_lines.clear();
                    set_text(ctx.h_edit_log, "");
                }
                ID_TRAY_SHOW => {
                    ShowWindow(hwnd, SW_SHOW);
                    SetForegroundWindow(hwnd);
                    ctx.prompt_pending_update_if_any();
                }
                ID_TRAY_EXIT => {
                    ctx.full_exit();
                }
                _ => {}
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn mk_ctrl(
    parent: HWND,
    h_inst: *mut core::ffi::c_void,
    class: &str,
    text: &str,
    style: u32,
    ex_style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: usize,
    font: HFONT,
) -> HWND {
    let w_cls = to_wide(class);
    let w_txt = to_wide(text);
    let hwnd = CreateWindowExW(
        ex_style,
        w_cls.as_ptr(),
        w_txt.as_ptr(),
        style,
        x,
        y,
        w,
        h,
        parent,
        id as HMENU,
        h_inst,
        null(),
    );
    if !hwnd.is_null() && !font.is_null() {
        SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1);
    }
    hwnd
}

unsafe fn create_font(face: &str, height: i32, weight: i32) -> HFONT {
    let w_face = to_wide(face);
    // Quality 5 = CLEARTYPE_QUALITY
    CreateFontW(height, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, w_face.as_ptr())
}

unsafe fn set_text(hwnd: HWND, text: &str) {
    let w = to_wide(text);
    SetWindowTextW(hwnd, w.as_ptr());
}

unsafe fn get_text(hwnd: HWND) -> String {
    let len = GetWindowTextLengthW(hwnd);
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; (len + 1) as usize];
    let copied = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    String::from_utf16_lossy(&buf[..copied.max(0) as usize])
}

unsafe fn msg_box(hwnd: HWND, text: &str, title: &str, flags: u32) -> i32 {
    let w_t = to_wide(text);
    let w_cap = to_wide(title);
    MessageBoxW(hwnd, w_t.as_ptr(), w_cap.as_ptr(), flags)
}

fn write_tip(dst: &mut [u16; 128], text: &str) {
    let w = to_wide(text);
    let n = w.len().min(dst.len());
    dst[..n].copy_from_slice(&w[..n]);
    if n == dst.len() {
        dst[dst.len() - 1] = 0;
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sub_combo_label(sub: &SubscriptionProfile) -> String {
    let host = short_sub_host(&sub.url);
    let has_custom_title = !sub.name.trim().is_empty() && sub.name.trim() != host;
    if has_custom_title || !sub.userinfo.is_empty() {
        sub.display_label()
    } else {
        sub.url.clone()
    }
}

const MODAL_DLG_CLASS: &str = "AvelModalDlgClass";
static MODAL_CLASS_INIT: Once = Once::new();

struct ModalState {
    done: bool,
    accepted: bool,
}

unsafe extern "system" fn modal_dlg_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ModalState;
    if !ptr.is_null() {
        let st = &mut *ptr;
        match msg {
            WM_COMMAND => {
                let id = (wparam & 0xFFFF) as i32;
                if id == IDOK {
                    st.accepted = true;
                    st.done = true;
                    return 0;
                } else if id == IDCANCEL {
                    st.accepted = false;
                    st.done = true;
                    return 0;
                }
            }
            WM_CLOSE => {
                st.accepted = false;
                st.done = true;
                return 0;
            }
            _ => {}
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

unsafe fn create_modal_window(
    owner: HWND,
    dpi: i32,
    title: &str,
    client_w_dip: i32,
    client_h_dip: i32,
) -> HWND {
    let h_inst = GetModuleHandleW(null());
    MODAL_CLASS_INIT.call_once(|| {
        let cls = to_wide(MODAL_DLG_CLASS);
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(modal_dlg_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: h_inst,
            hIcon: null_mut(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_BTNFACE + 1) as _,
            lpszMenuName: null(),
            lpszClassName: cls.as_ptr(),
            hIconSm: null_mut(),
        };
        RegisterClassExW(&wc);
    });

    let style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: scale_dpi(client_w_dip, dpi),
        bottom: scale_dpi(client_h_dip, dpi),
    };
    AdjustWindowRectExForDpi(&mut rc, style, 0, 0, dpi as u32);
    let w = rc.right - rc.left;
    let h = rc.bottom - rc.top;

    let mut orc: RECT = std::mem::zeroed();
    GetWindowRect(owner, &mut orc);
    let x = ((orc.left + orc.right - w) / 2).max(20);
    let y = ((orc.top + orc.bottom - h) / 2).max(20);

    let cls = to_wide(MODAL_DLG_CLASS);
    let w_title = to_wide(title);
    CreateWindowExW(
        0,
        cls.as_ptr(),
        w_title.as_ptr(),
        style,
        x,
        y,
        w,
        h,
        owner,
        null_mut(),
        h_inst,
        null(),
    )
}

unsafe fn show_rename_dialog(
    owner: HWND,
    dpi: i32,
    font_ui: HFONT,
    current_name: &str,
) -> Option<String> {
    let s = |v: i32| scale_dpi(v, dpi);
    let h_inst = GetModuleHandleW(null());
    let dlg = create_modal_window(owner, dpi, "Rename Server", 360, 118);
    if dlg.is_null() {
        return None;
    }

    mk_ctrl(dlg, h_inst, "STATIC", "Server name:", WS_CHILD | WS_VISIBLE, 0, s(12), s(14), s(336), s(18), 0, font_ui);
    let h_edit = mk_ctrl(
        dlg,
        h_inst,
        "EDIT",
        current_name,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32,
        WS_EX_CLIENTEDGE,
        s(12),
        s(36),
        s(336),
        s(24),
        3001,
        font_ui,
    );
    mk_ctrl(
        dlg,
        h_inst,
        "BUTTON",
        "OK",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
        0,
        s(188),
        s(78),
        s(76),
        s(26),
        IDOK as usize,
        font_ui,
    );
    mk_ctrl(
        dlg,
        h_inst,
        "BUTTON",
        "Cancel",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
        0,
        s(272),
        s(78),
        s(76),
        s(26),
        IDCANCEL as usize,
        font_ui,
    );

    let mut state = ModalState {
        done: false,
        accepted: false,
    };
    SetWindowLongPtrW(dlg, GWLP_USERDATA, &mut state as *mut ModalState as isize);
    EnableWindow(owner, 0);
    ShowWindow(dlg, SW_SHOW);
    SetFocus(h_edit);
    SendMessageW(h_edit, 0x00B1, 0, -1isize); // EM_SETSEL all

    let mut result = None;
    let mut msg: MSG = std::mem::zeroed();
    loop {
        while !state.done && GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(dlg, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if !state.accepted {
            break;
        }
        let next = get_text(h_edit).trim().to_string();
        if next.is_empty() {
            msg_box(dlg, "Server name cannot be empty.", "Rename Server", MB_OK | MB_ICONERROR);
            state.done = false;
            state.accepted = false;
            continue;
        }
        result = Some(next);
        break;
    }

    SetWindowLongPtrW(dlg, GWLP_USERDATA, 0);
    EnableWindow(owner, 1);
    DestroyWindow(dlg);
    SetForegroundWindow(owner);
    result
}

unsafe fn show_edit_node_dialog(
    owner: HWND,
    dpi: i32,
    font_ui: HFONT,
    font_mono: HFONT,
    node: &VlessNode,
) -> Option<VlessNode> {
    let s = |v: i32| scale_dpi(v, dpi);
    let h_inst = GetModuleHandleW(null());
    let dlg = create_modal_window(owner, dpi, "Server Details", 456, 314);
    if dlg.is_null() {
        return None;
    }

    let lbl_w = s(86);
    let ed_x = s(102);
    let ed_w = s(340);

    mk_ctrl(dlg, h_inst, "STATIC", "Name:", WS_CHILD | WS_VISIBLE, 0, s(12), s(17), lbl_w, s(18), 0, font_ui);
    let h_name = mk_ctrl(dlg, h_inst, "EDIT", &node.name, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(14), ed_w, s(22), 3101, font_ui);

    mk_ctrl(dlg, h_inst, "STATIC", "Protocol:", WS_CHILD | WS_VISIBLE, 0, s(12), s(47), lbl_w, s(18), 0, font_ui);
    mk_ctrl(dlg, h_inst, "EDIT", &node.protocol, WS_CHILD | WS_VISIBLE | ES_READONLY as u32, WS_EX_CLIENTEDGE, ed_x, s(44), s(140), s(22), 3102, font_mono);
    mk_ctrl(dlg, h_inst, "STATIC", "Port:", WS_CHILD | WS_VISIBLE, 0, s(258), s(47), s(40), s(18), 0, font_ui);
    let h_port = mk_ctrl(dlg, h_inst, "EDIT", &node.port.to_string(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER as u32 | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(302), s(44), s(140), s(22), 3103, font_mono);

    mk_ctrl(dlg, h_inst, "STATIC", "Address:", WS_CHILD | WS_VISIBLE, 0, s(12), s(77), lbl_w, s(18), 0, font_ui);
    let h_addr = mk_ctrl(dlg, h_inst, "EDIT", &node.address, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(74), ed_w, s(22), 3104, font_mono);

    mk_ctrl(dlg, h_inst, "STATIC", "UUID / Key:", WS_CHILD | WS_VISIBLE, 0, s(12), s(107), lbl_w, s(18), 0, font_ui);
    let h_uuid = mk_ctrl(dlg, h_inst, "EDIT", &node.uuid, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(104), ed_w, s(22), 3105, font_mono);

    mk_ctrl(dlg, h_inst, "STATIC", "SNI / Host:", WS_CHILD | WS_VISIBLE, 0, s(12), s(137), lbl_w, s(18), 0, font_ui);
    let h_sni = mk_ctrl(dlg, h_inst, "EDIT", &node.sni, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(134), ed_w, s(22), 3106, font_mono);

    mk_ctrl(dlg, h_inst, "STATIC", "Network:", WS_CHILD | WS_VISIBLE, 0, s(12), s(167), lbl_w, s(18), 0, font_ui);
    let h_net = mk_ctrl(dlg, h_inst, "EDIT", &node.network, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(164), s(140), s(22), 3107, font_mono);
    mk_ctrl(dlg, h_inst, "STATIC", "Security:", WS_CHILD | WS_VISIBLE, 0, s(250), s(167), s(52), s(18), 0, font_ui);
    let h_sec = mk_ctrl(dlg, h_inst, "EDIT", &node.security, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, s(304), s(164), s(138), s(22), 3108, font_mono);

    let init_path = if node.network == "grpc" && !node.service_name.is_empty() {
        node.service_name.as_str()
    } else {
        node.path.as_str()
    };
    mk_ctrl(dlg, h_inst, "STATIC", "Path / Svc:", WS_CHILD | WS_VISIBLE, 0, s(12), s(197), lbl_w, s(18), 0, font_ui);
    let h_path = mk_ctrl(dlg, h_inst, "EDIT", init_path, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(194), ed_w, s(22), 3109, font_mono);

    let uri_preview = node.to_share_uri();
    mk_ctrl(dlg, h_inst, "STATIC", "Share URI:", WS_CHILD | WS_VISIBLE, 0, s(12), s(227), lbl_w, s(18), 0, font_ui);
    mk_ctrl(dlg, h_inst, "EDIT", &uri_preview, WS_CHILD | WS_VISIBLE | ES_READONLY as u32 | ES_AUTOHSCROLL as u32, WS_EX_CLIENTEDGE, ed_x, s(224), ed_w, s(22), 3110, font_mono);

    mk_ctrl(dlg, h_inst, "BUTTON", "Save", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32, 0, s(274), s(270), s(80), s(26), IDOK as usize, font_ui);
    mk_ctrl(dlg, h_inst, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32, 0, s(362), s(270), s(80), s(26), IDCANCEL as usize, font_ui);

    let mut state = ModalState {
        done: false,
        accepted: false,
    };
    SetWindowLongPtrW(dlg, GWLP_USERDATA, &mut state as *mut ModalState as isize);
    EnableWindow(owner, 0);
    ShowWindow(dlg, SW_SHOW);
    SetFocus(h_name);

    let mut result = None;
    let mut msg: MSG = std::mem::zeroed();
    loop {
        while !state.done && GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(dlg, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if !state.accepted {
            break;
        }
        let name = get_text(h_name).trim().to_string();
        let addr = get_text(h_addr).trim().to_string();
        let port_str = get_text(h_port).trim().to_string();
        if name.is_empty() {
            msg_box(dlg, "Name cannot be empty.", "Server Details", MB_OK | MB_ICONERROR);
            state.done = false;
            state.accepted = false;
            continue;
        }
        if addr.is_empty() {
            msg_box(dlg, "Address cannot be empty.", "Server Details", MB_OK | MB_ICONERROR);
            state.done = false;
            state.accepted = false;
            continue;
        }
        let port = match port_str.parse::<u16>() {
            Ok(p) if p >= 1 => p,
            _ => {
                msg_box(dlg, "Port must be between 1 and 65535.", "Server Details", MB_OK | MB_ICONERROR);
                state.done = false;
                state.accepted = false;
                continue;
            }
        };

        let mut updated = node.clone();
        updated.name = name;
        updated.address = addr;
        updated.port = port;
        updated.uuid = get_text(h_uuid).trim().to_string();
        updated.sni = get_text(h_sni).trim().to_string();
        let net = get_text(h_net).trim().to_lowercase();
        if !net.is_empty() {
            updated.network = net;
        }
        let sec = get_text(h_sec).trim().to_lowercase();
        if !sec.is_empty() {
            updated.security = sec;
        }
        let path_val = get_text(h_path).trim().to_string();
        if updated.network == "grpc" {
            updated.service_name = path_val;
        } else {
            updated.path = path_val;
        }

        let net_changed = updated.address != node.address
            || updated.port != node.port
            || updated.uuid != node.uuid
            || updated.sni != node.sni
            || updated.network != node.network
            || updated.security != node.security
            || updated.path != node.path
            || updated.service_name != node.service_name;
        if net_changed {
            updated.raw_uri.clear();
        }
        result = Some(updated);
        break;
    }

    SetWindowLongPtrW(dlg, GWLP_USERDATA, 0);
    EnableWindow(owner, 1);
    DestroyWindow(dlg);
    SetForegroundWindow(owner);
    result
}
