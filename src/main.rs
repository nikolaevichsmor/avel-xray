#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;
mod http_win;
mod icon;
mod model;
mod ping;
mod sys_proxy;
mod vless;
mod xray_config;
mod xray_proc;

fn main() {
    sys_proxy::harden_dll_search_order();
    let args: Vec<String> = std::env::args().collect();
    let start_minimized = args.iter().any(|a| a == "--minimized");
    let autoconnect = args.iter().any(|a| a == "--autoconnect");
    gui::run_app(start_minimized, autoconnect);
}
