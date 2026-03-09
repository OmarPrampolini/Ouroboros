use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use tauri::{Manager, State};
use tauri_plugin_shell::{process::{CommandChild, CommandEvent}, ShellExt};

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

  let mut cmd = app
    .shell()
    .sidecar("handshacke")
    .map_err(|e| format!("sidecar error: {e}"))?
    .env("HANDSHACKE_API_BIND", api_bind.as_str());

  let clean = |value: Option<String>| -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
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
    const MAX_LOG_LINES: usize = 200;
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
          guard.last_error =
            Some(format!("daemon exited code={:?} signal={:?}", payload.code, payload.signal));
          break;
        }
        _ => {}
      }

      while guard.log_tail.len() > MAX_LOG_LINES {
        guard.log_tail.pop_front();
      }
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
  if let Some(child) = guard.child.take() {
    let _ = child.kill();
  }
  guard.token = None;
  guard.pid = None;
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
      daemon_logs
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

