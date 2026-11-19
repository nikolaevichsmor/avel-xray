use crate::model::{core_binary_path, core_dir, runtime_config_path, MemoryProfile};
use crate::sys_proxy::find_adapter_luid;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE,
};

#[derive(Debug, Clone, Copy)]
pub struct XrayStartOpts {
    pub memory_profile: MemoryProfile,
    pub expect_startup_log: bool,
    pub ready_port: u16,
    pub is_tun: bool,
}

pub struct XrayRunner {
    child: Option<Child>,
    job: HANDLE,
}

unsafe impl Send for XrayRunner {}

impl XrayRunner {
    pub fn new() -> Self {
        Self {
            child: None,
            job: null_mut(),
        }
    }

    pub fn active_pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    pub fn test_config(config_json: &str) -> Result<(), String> {
        let cdir = core_dir();
        let xray = core_binary_path()?;
        let cfg_path = runtime_config_path();
        std::fs::write(&cfg_path, config_json).map_err(|e| format!("Failed to write config: {}", e))?;

        let out = Command::new(&xray)
            .args(["run", "-test", "-c"])
            .arg(&cfg_path)
            .current_dir(&cdir)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to run core -test: {}", e))?;

        if !out.status.success() {
            let err_text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return Err(format!("Xray config validation failed:\n{}", err_text.trim()));
        }
        Ok(())
    }

    pub fn start(
        &mut self,
        config_json: &str,
        opts: XrayStartOpts,
        log_tx: Sender<String>,
        notify_ui: impl Fn() + Send + Sync + 'static,
        on_exit: impl Fn(u32) + Send + 'static,
    ) -> Result<u32, String> {
        self.stop();

        Self::test_config(config_json)?;

        let cdir = core_dir();
        let xray = core_binary_path()?;
        let cfg_path = runtime_config_path();

        let mut cmd = Command::new(&xray);
        cmd.args(["run", "-c"])
            .arg(&cfg_path)
            .current_dir(&cdir)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match opts.memory_profile {
            MemoryProfile::LowRam => {
                cmd.env("GOGC", "50").env("GOMEMLIMIT", "48MiB");
            }
            MemoryProfile::Performance => {
                cmd.env("GOGC", "100").env_remove("GOMEMLIMIT");
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", xray.display(), e))?;

        let xray_pid = child.id();

        // Kill child automatically on parent exit via Job Object, and wait on a duplicated
        // process handle to detect unexpected termination.
        let mut wait_handle_raw: usize = 0;
        unsafe {
            let proc_h = child.as_raw_handle() as HANDLE;
            let job = CreateJobObjectW(null_mut(), null_mut());
            if !job.is_null() {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                AssignProcessToJobObject(job, proc_h);
                self.job = job;
            }

            let cur_proc = GetCurrentProcess();
            let mut dup_h: HANDLE = null_mut();
            if DuplicateHandle(
                cur_proc,
                proc_h,
                cur_proc,
                &mut dup_h,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ) != 0
                && !dup_h.is_null()
            {
                wait_handle_raw = dup_h as usize;
            }
        }

        let notify = Arc::new(notify_ui);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let probe_stop = Arc::new(AtomicBool::new(false));

        if !opts.expect_startup_log && opts.ready_port > 0 {
            let r_tx = ready_tx.clone();
            let stop_flag = probe_stop.clone();
            let port = opts.ready_port;
            let need_tun = opts.is_tun;
            std::thread::spawn(move || {
                let addr: SocketAddr = ([127, 0, 0, 1], port).into();
                for _ in 0..100 {
                    if stop_flag.load(Ordering::Relaxed) {
                        return;
                    }
                    let port_ok = TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_ok();
                    if port_ok && (!need_tun || find_adapter_luid("avel0").is_some()) {
                        let _ = r_tx.send(Ok(()));
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
            });
        }

        if let Some(stdout) = child.stdout.take() {
            let tx = log_tx.clone();
            let n = notify.clone();
            let r_tx = ready_tx.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                let mut started = false;
                let mut tail: Vec<String> = Vec::new();
                for line in reader.lines().map_while(Result::ok) {
                    if !started && line.contains("Xray") && line.contains("started") {
                        started = true;
                        let _ = r_tx.send(Ok(()));
                    } else if !started {
                        if tail.len() >= 6 {
                            tail.remove(0);
                        }
                        tail.push(line.clone());
                    }
                    let _ = tx.send(line);
                    n();
                }
                if !started {
                    let msg = if tail.is_empty() {
                        "VPN core exited before initialization completed.".to_string()
                    } else {
                        tail.join("\n")
                    };
                    let _ = r_tx.send(Err(msg));
                }
            });
        }

        let on_exit_opt = if wait_handle_raw != 0 {
            std::thread::spawn(move || {
                unsafe {
                    let h = wait_handle_raw as HANDLE;
                    let _ = WaitForSingleObject(h, INFINITE);
                    CloseHandle(h);
                }
                on_exit(xray_pid);
            });
            None
        } else {
            Some(on_exit)
        };

        if let Some(stderr) = child.stderr.take() {
            let tx = log_tx;
            let n = notify;
            let r_tx = ready_tx;
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                let mut err_tail: Vec<String> = Vec::new();
                for line in reader.lines().map_while(Result::ok) {
                    if err_tail.len() < 6 {
                        err_tail.push(line.clone());
                    }
                    let _ = tx.send(line);
                    n();
                }
                if !err_tail.is_empty() {
                    let _ = r_tx.send(Err(err_tail.join("\n")));
                }
                if let Some(cb) = on_exit_opt {
                    std::thread::sleep(Duration::from_millis(50));
                    cb(xray_pid);
                }
            });
        }

        self.child = Some(child);

        // Wait until Wintun adapter, routes, DNS, and WFP filters are actually up
        let res = match ready_rx.recv_timeout(Duration::from_millis(5000)) {
            Ok(Ok(())) => Ok(xray_pid),
            Ok(Err(err_msg)) => {
                self.stop();
                Err(format!("Xray failed to start:\n{}", err_msg))
            }
            Err(RecvTimeoutError::Timeout) => {
                if self.is_running() {
                    Ok(xray_pid)
                } else {
                    self.stop();
                    Err("Xray exited unexpectedly during startup.".to_string())
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.stop();
                Err("Xray output stream closed before startup.".to_string())
            }
        };
        probe_stop.store(true, Ordering::Relaxed);
        res
    }

    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut ch) = self.child {
            match ch.try_wait() {
                Ok(None) => return true,
                _ => {
                    self.child = None;
                    self.close_job();
                    return false;
                }
            }
        }
        false
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.close_job();
        let _ = std::fs::remove_file(runtime_config_path());
    }

    fn close_job(&mut self) {
        if !self.job.is_null() {
            unsafe {
                CloseHandle(self.job);
            }
            self.job = null_mut();
        }
    }
}

impl Drop for XrayRunner {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AppState, ProxyMode, RoutingPreset};
    use crate::vless::parse_vless_uri;
    use crate::xray_config::build_xray_config;
    use std::sync::Mutex;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    static PROC_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn external_terminate_triggers_race_free_exit_callback() {
        let _guard = PROC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let node = parse_vless_uri(
            "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?encryption=none&security=none&type=tcp#LocalTest",
        )
        .unwrap();
        let mut st = AppState::default();
        st.mode = ProxyMode::SystemProxy;
        st.routing = RoutingPreset::Global;
        st.socks_port = 18808;
        st.http_port = 18809;
        let cfg = build_xray_config(&st, &node).unwrap();

        let (log_tx, _log_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel::<u32>();

        let mut runner = XrayRunner::new();
        let pid = runner
            .start(
                &cfg,
                XrayStartOpts {
                    memory_profile: MemoryProfile::LowRam,
                    expect_startup_log: true,
                    ready_port: st.socks_port,
                    is_tun: false,
                },
                log_tx,
                || {},
                move |exited_pid| {
                    let _ = exit_tx.send(exited_pid);
                },
            )
            .expect("avel-core.exe failed to start in SystemProxy test");
        assert_eq!(runner.active_pid(), Some(pid));

        // Simulate an external process forcefully terminating the child core process.
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            assert!(!h.is_null(), "OpenProcess failed for test child");
            assert_ne!(TerminateProcess(h, 1), 0, "TerminateProcess failed");
            CloseHandle(h);
        }

        let reported_pid = exit_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("on_exit callback did not fire after external TerminateProcess");
        assert_eq!(reported_pid, pid);
        // At the moment WaitForSingleObject wakes up, kernel has already signaled the process
        assert!(!runner.is_running(), "runner must report not running immediately after on_exit");
    }

    #[test]
    fn loglevel_none_starts_fast_via_port_probe() {
        let _guard = PROC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let node = parse_vless_uri(
            "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?encryption=none&security=none&type=tcp#LocalTest",
        )
        .unwrap();
        let mut st = AppState::default();
        st.mode = ProxyMode::SystemProxy;
        st.routing = RoutingPreset::Global;
        st.socks_port = 18828;
        st.http_port = 18829;
        st.log_level = crate::model::XrayLogLevel::None;
        st.memory_profile = MemoryProfile::Performance;
        let cfg = build_xray_config(&st, &node).unwrap();

        let (log_tx, _log_rx) = mpsc::channel();
        let mut runner = XrayRunner::new();
        let t0 = std::time::Instant::now();
        let pid = runner
            .start(
                &cfg,
                XrayStartOpts {
                    memory_profile: st.memory_profile,
                    expect_startup_log: st.log_level.emits_startup_line(),
                    ready_port: st.socks_port,
                    is_tun: false,
                },
                log_tx,
                || {},
                |_| {},
            )
            .expect("avel-core.exe failed to start with loglevel=none");
        let elapsed = t0.elapsed();
        runner.stop();
        assert!(pid > 0);
        assert!(
            elapsed < Duration::from_secs(2),
            "loglevel=none startup stalled for {:?} instead of fast port probe",
            elapsed
        );
    }
}
