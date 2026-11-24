use crate::model::{core_binary_path, core_dir, runtime_config_path, MemoryProfile};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct XrayStartOpts {
    pub memory_profile: MemoryProfile,
    pub expect_startup_log: bool,
    pub ready_port: u16,
    pub is_tun: bool,
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn has_active_systemd_resolved() -> bool {
    Command::new("resolvectl")
        .arg("status")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub struct XrayRunner {
    child: Arc<Mutex<Option<Child>>>,
    stop_flag: Arc<AtomicBool>,
}

impl XrayRunner {
    pub fn new() -> Self {
        Self {
            child: Arc::new(Mutex::new(None)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn active_pid(&self) -> Option<u32> {
        self.child
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.id()))
    }

    pub fn test_config(config_json: &str) -> Result<(), String> {
        let cdir = core_dir();
        let xray = core_binary_path()?;
        let cfg_path = runtime_config_path();
        if let Some(p) = cfg_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(&cfg_path, config_json)
            .map_err(|e| format!("Failed to write config: {}", e))?;

        let out = Command::new(&xray)
            .args(["run", "-test", "-c"])
            .arg(&cfg_path)
            .current_dir(&cdir)
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

        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let probe_stop = Arc::new(AtomicBool::new(false));
        self.stop_flag = Arc::new(AtomicBool::new(false));

        if !opts.expect_startup_log && opts.ready_port > 0 {
            let r_tx = ready_tx.clone();
            let p_stop = probe_stop.clone();
            let port = opts.ready_port;
            let need_tun = opts.is_tun;
            std::thread::spawn(move || {
                let addr: SocketAddr = ([127, 0, 0, 1], port).into();
                for _ in 0..100 {
                    if p_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let port_ok =
                        TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_ok();
                    let tun_ok = !need_tun || std::path::Path::new("/sys/class/net/avel0").exists();
                    if port_ok && tun_ok {
                        let _ = r_tx.send(Ok(()));
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
            });
        }

        if let Some(stdout) = child.stdout.take() {
            let tx = log_tx.clone();
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

        if let Some(stderr) = child.stderr.take() {
            let tx = log_tx;
            let r_tx = ready_tx;
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                let mut err_tail: Vec<String> = Vec::new();
                for line in reader.lines().map_while(Result::ok) {
                    if err_tail.len() < 6 {
                        err_tail.push(line.clone());
                    }
                    let _ = tx.send(line);
                }
                if !err_tail.is_empty() {
                    let _ = r_tx.send(Err(err_tail.join("\n")));
                }
            });
        }

        if let Ok(mut g) = self.child.lock() {
            *g = Some(child);
        }

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

        if res.is_ok() {
            let child_arc = self.child.clone();
            let stop_arc = self.stop_flag.clone();
            std::thread::spawn(move || {
                loop {
                    if stop_arc.load(Ordering::Relaxed) {
                        return;
                    }
                    let exited = if let Ok(mut g) = child_arc.lock() {
                        match g.as_mut() {
                            Some(ch) => match ch.try_wait() {
                                Ok(Some(_)) | Err(_) => {
                                    *g = None;
                                    true
                                }
                                Ok(None) => false,
                            },
                            None => return,
                        }
                    } else {
                        return;
                    };
                    if exited {
                        if !stop_arc.load(Ordering::Relaxed) {
                            on_exit(xray_pid);
                        }
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
        }
        res
    }

    pub fn is_running(&mut self) -> bool {
        if let Ok(mut g) = self.child.lock() {
            if let Some(ref mut ch) = *g {
                match ch.try_wait() {
                    Ok(None) => return true,
                    _ => {
                        *g = None;
                        return false;
                    }
                }
            }
        }
        false
    }

    // Send SIGTERM first so Xray cleanly removes Linux TUN routes & DNS before SIGKILL fallback.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let child_opt = self.child.lock().ok().and_then(|mut g| g.take());
        if let Some(mut ch) = child_opt {
            let pid = ch.id() as libc::pid_t;
            unsafe {
                let _ = libc::kill(pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_millis(1500);
            let mut exited = false;
            while Instant::now() < deadline {
                if let Ok(Some(_)) = ch.try_wait() {
                    exited = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            if !exited {
                let _ = ch.kill();
                let _ = ch.wait();
            }
        }
        let _ = std::fs::remove_file(runtime_config_path());
    }
}

impl Drop for XrayRunner {
    fn drop(&mut self) {
        self.stop();
    }
}

static TEMP_CFG_SEQ: AtomicU32 = AtomicU32::new(1);

#[derive(Clone)]
pub struct TempCoreKiller {
    child: Arc<Mutex<Option<Child>>>,
}

impl TempCoreKiller {
    pub fn kill_now(&self) {
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut ch) = g.take() {
                let _ = ch.kill();
                let _ = ch.wait();
            }
        }
    }
}

pub struct TempXrayProcess {
    child: Arc<Mutex<Option<Child>>>,
    cfg_path: PathBuf,
}

impl TempXrayProcess {
    pub fn killer(&self) -> TempCoreKiller {
        TempCoreKiller {
            child: self.child.clone(),
        }
    }

    pub fn start(
        config_json: &str,
        ready_port: u16,
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        let cdir = core_dir();
        let xray = core_binary_path()?;
        let seq = TEMP_CFG_SEQ.fetch_add(1, Ordering::Relaxed);
        let cfg_path = cdir.join(format!("realping_{}_{}.json", std::process::id(), seq));
        if let Some(p) = cfg_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(&cfg_path, config_json)
            .map_err(|e| format!("Failed to write test config: {}", e))?;

        let mut cmd = Command::new(&xray);
        cmd.args(["run", "-c"])
            .arg(&cfg_path)
            .current_dir(&cdir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("GOGC", "50")
            .env("GOMEMLIMIT", "48MiB");

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&cfg_path);
                return Err(format!("Failed to start test core: {}", e));
            }
        };

        let proc = Self {
            child: Arc::new(Mutex::new(Some(child))),
            cfg_path,
        };

        let addr: SocketAddr = ([127, 0, 0, 1], ready_port).into();
        for _ in 0..90 {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".to_string());
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(60)).is_ok() {
                return Ok(proc);
            }
            if let Ok(mut g) = proc.child.lock() {
                if let Some(ref mut ch) = *g {
                    if let Ok(Some(_)) = ch.try_wait() {
                        return Err("Test core exited before ready.".to_string());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(35));
        }

        Err("Test core did not open local port in time.".to_string())
    }
}

impl Drop for TempXrayProcess {
    fn drop(&mut self) {
        self.killer().kill_now();
        let _ = std::fs::remove_file(&self.cfg_path);
    }
}
