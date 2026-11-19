#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[allow(dead_code)]
mod http_win;
#[allow(dead_code)]
mod model;
#[allow(dead_code)]
mod ping;
#[allow(dead_code)]
mod sys_proxy;
#[allow(dead_code)]
mod vless;
#[allow(dead_code)]
mod xray_config;
#[allow(dead_code)]
mod xray_proc;

fn main() {
    sys_proxy::harden_dll_search_order();
}
