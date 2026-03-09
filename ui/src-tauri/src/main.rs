use std::collections::VecDeque;
use std::process::Command;
use std::sync::Mutex;

use tauri::{Manager, RunEvent, State};
use tauri_plugin_shell::{
    process::{CommandChild, CommandEvent},
    ShellExt,
};

#[derive(Default)]
struct DaemonState(Mutex<DaemonHandle>);

#[derive(Default)]
struct DaemonHandle {
    child: Option<CommandChild>,
    pid: Option<u32>,
    token: Option<String>,
    last_error: Option<String>,
    last_exit_code: Option<i32>,
    log_tail: VecDeque<String>,
}

#[derive(serde::Serialize)]
struct StartResult {
    pid: u32,
    api_url: String,
    token: String,
}

#[derive(serde::Serialize)]
struct StatusResult {
    running: bool,
    pid: Option<u32>,
    last_error: Option<String>,
    last_exit_code: Option<i32>,
}

fn trim_log_tail(guard: &mut DaemonHandle) {
    const MAX_LOG_LINES: usize = 200;
    while guard.log_tail.len() > MAX_LOG_LINES {
        guard.log_tail.pop_front();
    }
}

fn kill_managed_child(guard: &mut DaemonHandle) {
    if let Some(child) = guard.child.take() {
        let _ = child.kill();
    }
    guard.token = None;
    guard.pid = None;
}

fn parse_port_from_bind(api_bind: &str) -> Result<u16, String> {
    let bind = if api_bind.trim().is_empty() {
        "127.0.0.1:8731"
    } else {
        api_bind.trim()
    };
    let port = bind
        .rsplit(':')
        .next()
        .ok_or_else(|| format!("invalid bind address: {bind}"))?
        .parse::<u16>()
        .map_err(|_| format!("invalid port in bind address: {bind}"))?;
    Ok(port)
}

#[cfg(target_os = "windows")]
fn pids_listening_on_port(port: u16) -> Result<Vec<u32>, String> {
    let output = Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .map_err(|e| format!("netstat failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "netstat returned non-zero status: {}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        if !parts[0].eq_ignore_ascii_case("tcp") {
            continue;
        }

        let local_addr = parts[1];
        let local_port = match local_addr
            .rsplit(':')
            .next()
            .and_then(|v| v.parse::<u16>().ok())
        {
            Some(v) => v,
            None => continue,
        };

        if local_port != port {
            continue;
        }

        if let Ok(pid) = parts[parts.len() - 1].parse::<u32>() {
            if pid != 0 && !pids.contains(&pid) {
                pids.push(pid);
            }
        }
    }

    Ok(pids)
}

#[cfg(not(target_os = "windows"))]
fn pids_listening_on_port(_port: u16) -> Result<Vec<u32>, String> {
    Err("reclaim_port is currently supported only on Windows".into())
}

#[tauri::command]
async fn reclaim_port(api_bind: String, state: State<'_, DaemonState>) -> Result<String, String> {
    let port = parse_port_from_bind(&api_bind)?;

    {
        let mut guard = state.0.lock().unwrap();
        kill_managed_child(&mut guard);
        guard
            .log_tail
            .push_back(format!("[tauri] reclaim requested for port {port}"));
        trim_log_tail(&mut guard);
    }

    let current_pid = std::process::id();
    let mut killed = Vec::new();
    for pid in pids_listening_on_port(port)? {
        if pid == current_pid {
            continue;
        }
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .map_err(|e| format!("taskkill failed for pid {pid}: {e}"))?;

        if status.success() {
            killed.push(pid);
        }
    }

    let mut guard = state.0.lock().unwrap();
    if killed.is_empty() {
        let msg = format!("no process reclaimed on port {port}");
        guard.log_tail.push_back(format!("[tauri] {msg}"));
        trim_log_tail(&mut guard);
        return Ok(msg);
    }

    let summary = format!("reclaimed port {port}; killed pid(s): {:?}", killed);
    guard.log_tail.push_back(format!("[tauri] {summary}"));
    trim_log_tail(&mut guard);
    Ok(summary)
}

#[tauri::command]
async fn start_daemon(
    app: tauri::AppHandle,
    api_bind: String,
    unsafe_expose_api: bool,
    pluggable_transport: Option<String>,
    pluggable_profile: Option<String>,
    realtls_domain: Option<String>,
    stealth_mode: Option<String>,
    assist_relays: Option<String>,
    tor_socks_addr: Option<String>,
    tor_onion_addr: Option<String>,
    state: State<'_, DaemonState>,
) -> Result<StartResult, String> {
    let api_bind = if api_bind.trim().is_empty() {
        "127.0.0.1:8731".to_string()
    } else {
        api_bind
    };

    if api_bind.starts_with("0.0.0.0") && !unsafe_expose_api {
        return Err("unsafe_expose_api required for 0.0.0.0".into());
    }

    if let Ok(port) = parse_port_from_bind(&api_bind) {
        if let Ok(pids) = pids_listening_on_port(port) {
            let current_pid = std::process::id();
            let occupied_by: Vec<u32> =
                pids.into_iter().filter(|pid| *pid != current_pid).collect();
            if !occupied_by.is_empty() {
                return Err(format!(
          "port {port} already in use by pid(s) {:?}; reconnect existing daemon or reclaim port",
          occupied_by
        ));
            }
        }
    }

    // Always require auth for the daemon API so it cannot be abused as a localhost decrypt oracle.
    let needs_token = true;

    let mut guard = state.0.lock().unwrap();
    if guard.child.is_some() {
        return Err("daemon already running".into());
    }

    guard.last_error = None;
    guard.last_exit_code = None;
    guard.log_tail.clear();

    // Keep token in RAM only. Pass it to the daemon via env so the UI can authenticate.
    let token = if needs_token {
        let token = random_hex_token(32);
        Some(token)
    } else {
        None
    };

    let mut cmd = {
        let shell = app.shell();
        if cfg!(debug_assertions) {
            let dev_sidecar = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("bin")
                .join(if cfg!(windows) {
                    "handshacke.exe"
                } else {
                    "handshacke"
                });

            if dev_sidecar.exists() {
                shell.command(dev_sidecar)
            } else {
                shell
                    .sidecar("handshacke")
                    .map_err(|e| format!("sidecar error: {e}"))?
            }
        } else {
            shell
                .sidecar("handshacke")
                .map_err(|e| format!("sidecar error: {e}"))?
        }
    }
    .env("HANDSHACKE_API_BIND", api_bind.as_str());

    let clean = |value: Option<String>| -> Option<String> {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    if let Some(profile) = clean(pluggable_profile) {
        cmd = cmd.env("HANDSHACKE_PLUGGABLE_PROFILE", profile.to_lowercase());
    }

    if let Some(pt) = clean(pluggable_transport) {
        let pt = pt.to_lowercase();
        if pt != "none" {
            cmd = cmd.env("HANDSHACKE_PLUGGABLE_TRANSPORT", pt);
        }
    }

    if let Some(domain) = clean(realtls_domain) {
        cmd = cmd.env("HANDSHACKE_REALTLS_DOMAIN", domain);
    }

    if let Some(mode) = clean(stealth_mode) {
        cmd = cmd.env("HANDSHACKE_STEALTH_MODE", mode.to_lowercase());
    }

    if let Some(relays) = clean(assist_relays) {
        cmd = cmd.env("HANDSHACKE_ASSIST_RELAYS", relays);
    }

    if let Some(socks) = clean(tor_socks_addr) {
        cmd = cmd.env("HANDSHACKE_TOR_SOCKS", socks);
    }

    if let Some(onion) = clean(tor_onion_addr) {
        cmd = cmd.env("HANDSHACKE_TOR_ONION", onion);
    }

    if let Some(ref t) = token {
        cmd = cmd.env("HANDSHACKE_API_TOKEN", t);
    }

    if unsafe_expose_api {
        cmd = cmd.arg("--unsafe-expose-api");
    }

    let (rx, child) = cmd.spawn().map_err(|e| format!("spawn error: {e}"))?;

    let pid = child.pid();

    guard.child = Some(child);
    guard.pid = Some(pid);
    guard.token = token.clone();

    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut rx = rx;
        while let Some(event) = rx.recv().await {
            let state = app_handle.state::<DaemonState>();
            let mut guard = state.0.lock().unwrap();
            match event {
                CommandEvent::Stdout(bytes) => {
                    for line in String::from_utf8_lossy(&bytes).lines() {
                        if !line.trim().is_empty() {
                            guard.log_tail.push_back(format!("[stdout] {line}"));
                        }
                    }
                }
                CommandEvent::Stderr(bytes) => {
                    for line in String::from_utf8_lossy(&bytes).lines() {
                        if !line.trim().is_empty() {
                            guard.log_tail.push_back(format!("[stderr] {line}"));
                        }
                    }
                }
                CommandEvent::Error(err) => {
                    guard.last_error = Some(format!("daemon error: {err}"));
                }
                CommandEvent::Terminated(payload) => {
                    guard.pid = None;
                    guard.child = None;
                    guard.last_exit_code = payload.code;
                    guard.last_error = Some(format!(
                        "daemon exited code={:?} signal={:?}",
                        payload.code, payload.signal
                    ));
                    break;
                }
                _ => {}
            }

            trim_log_tail(&mut guard);
        }
    });

    Ok(StartResult {
        pid,
        api_url: format!("http://{api_bind}"),
        token: token.unwrap_or_default(),
    })
}

#[tauri::command]
async fn stop_daemon(state: State<'_, DaemonState>) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    kill_managed_child(&mut guard);
    Ok(())
}

#[tauri::command]
async fn daemon_status(state: State<'_, DaemonState>) -> Result<StatusResult, String> {
    let guard = state.0.lock().unwrap();
    Ok(StatusResult {
        running: guard.child.is_some(),
        pid: guard.pid,
        last_error: guard.last_error.clone(),
        last_exit_code: guard.last_exit_code,
    })
}

#[tauri::command]
async fn daemon_logs(state: State<'_, DaemonState>) -> Result<Vec<String>, String> {
    let guard = state.0.lock().unwrap();
    Ok(guard.log_tail.iter().cloned().collect())
}

fn random_hex_token(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(DaemonState::default())
        .invoke_handler(tauri::generate_handler![
            start_daemon,
            stop_daemon,
            daemon_status,
            daemon_logs,
            reclaim_port
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
                let state = app_handle.state::<DaemonState>();
                let mut guard = state.0.lock().unwrap();
                kill_managed_child(&mut guard);
            }
        });
}

