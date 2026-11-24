#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod model;
mod vless;
mod xray_config;

#[cfg(windows)]
mod gui;
#[cfg(windows)]
mod http_win;
#[cfg(windows)]
mod icon;
#[cfg(windows)]
mod ping;
#[cfg(windows)]
mod sys_proxy;
#[cfg(windows)]
mod xray_proc;

#[cfg(unix)]
mod http_unix;
#[cfg(unix)]
mod ping_unix;
#[cfg(unix)]
mod tui;
#[cfg(unix)]
mod xray_proc_unix;

#[cfg(windows)]
fn main() {
    sys_proxy::harden_dll_search_order();
    let args: Vec<String> = std::env::args().collect();
    let start_minimized = args.iter().any(|a| a == "--minimized");
    let autoconnect = args.iter().any(|a| a == "--autoconnect");
    gui::run_app(start_minimized, autoconnect);
}

#[cfg(unix)]
fn main() {
    tui::run_entry();
}
