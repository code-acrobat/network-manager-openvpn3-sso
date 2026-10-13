// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! OpenVPN 3 backend for the NetworkManager VPN plugin.
//!
//! Drives the openvpn3-linux D-Bus services (`net.openvpn.v3.configuration`,
//! `.sessions`, `.netcfg`) instead of spawning an `openvpn` 2.x process, so that
//! server-driven web/SSO authentication (second factor at the identity provider) works. SSO browser auth
//! is handled exactly like the `openvpn3 session-start` CLI: on the
//! `(SESSION, SESS_AUTH_URL)` attention we open the URL in the desktop browser
//! and wait for the backend to complete the handshake on its own — no
//! `Connect()` is issued in that case, mirroring `start_session()` in
//! `src/ovpn3cli/commands/session/helpers.cpp`.
//!
//! The privileged `openvpn3-service-netcfg` always owns the tun device, IP
//! setup, routes and DNS (no supported way to hand that to NetworkManager);
//! this plugin only reads the resulting configuration and relays it to NM.

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};
use zbus::zvariant::{Dict, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::config::ConnectionConfig;

/// Events from the OpenVPN 3 backend (consumed by dbus.rs)
pub enum VpnEvent {
    State(VpnState),
    AuthRequired { auth_url: Option<String> },
    Connected(VpnConfig),
    Failed(String),
}

/// VPN connection states (matching NM states)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum VpnState {
    #[default]
    Unknown = 0,
    Init = 1,
    Shutdown = 2,
    Starting = 3,
    Started = 4,
    Stopping = 5,
    Stopped = 6,
    NeedAuth = 7,
    Connecting = 8,
    GettingConfig = 9,
    Connected = 10,
    Failed = 11,
}

/// IP configuration received from OpenVPN
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct VpnConfig {
    pub tun_device: Option<String>,
    pub local_ip: Option<String>,
    pub remote_ip: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
}

// StatusMajor/StatusMinor constants from openvpn3-linux
// (installed copy: /usr/lib/python3/dist-packages/openvpn3/constants.py)
const MAJOR_CFG: u32 = 1;
const MAJOR_CONN: u32 = 2;
const MAJOR_SESS: u32 = 3;
const MINOR_CFG_ERROR: u32 = 1;
const MINOR_CFG_INLINE_MISSING: u32 = 3;
const MINOR_CONN_INIT: u32 = 5;
const MINOR_CONN_CONNECTING: u32 = 6;
const MINOR_CONN_CONNECTED: u32 = 7;
const MINOR_CONN_DISCONNECTED: u32 = 9;
const MINOR_CONN_FAILED: u32 = 10;
const MINOR_CONN_AUTH_FAILED: u32 = 11;
const MINOR_CONN_RECONNECTING: u32 = 12;
const MINOR_SESS_AUTH_URL: u32 = 22;
const MINOR_SESS_AUTH_USERPASS: u32 = 20;
const MINOR_SESS_AUTH_CHALLENGE: u32 = 21;

const SERVICE_SESSIONS: &str = "net.openvpn.v3.sessions";
const SERVICE_CONFIGMGR: &str = "net.openvpn.v3.configuration";
const SERVICE_NETCFG: &str = "net.openvpn.v3.netcfg";
const SESSIONS_PATH: &str = "/net/openvpn/v3/sessions";
const CONFIGMGR_PATH: &str = "/net/openvpn/v3/configuration";

/// OpenVPN 3 backend state, one per NM connect() call.
pub struct OpenVpn3Manager {
    config: ConnectionConfig,
    event_tx: mpsc::Sender<VpnEvent>,
    /// System-bus connection used for this session; shared with the status
    /// watcher so `disconnect()` can address the same session.
    dbus: Mutex<Option<Connection>>,
    /// Basename of the profile imported into the config manager this run
    /// (either the original .ovpn basename or `<uuid>.ovpn` for synthesized
    /// ones); used for stale-session matching and disconnect().
    profile_name: Mutex<Option<String>>,
}

impl OpenVpn3Manager {
    pub fn new(config: ConnectionConfig, event_tx: mpsc::Sender<VpnEvent>) -> Self {
        Self {
            config,
            event_tx,
            dbus: Mutex::new(None),
            profile_name: Mutex::new(None),
        }
    }

    /// Import the profile, create a session and drive it towards connected.
    pub async fn connect(&mut self) -> Result<()> {
        let conn = Connection::system()
            .await
            .context("Failed to connect to system bus")?;
        *self.dbus.lock().await = Some(conn.clone());

        let cfg_file = match self.config.config_path.as_ref() {
            Some(p) => p.clone(),
            // NM fragments an imported .ovpn into separate files + vpn.data
            // keys; reassemble a complete profile for the config manager.
            None => synthesize_profile(&self.config)?,
        };
        let cfg_str = std::fs::read_to_string(&cfg_file)
            .with_context(|| format!("Failed to read config file {}", cfg_file.display()))?;
        let cfg_name = cfg_file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "nm-openvpn3-sso".to_string());
        *self.profile_name.lock().await = Some(cfg_name.clone());
        info!("Importing profile '{}' as single-use config", cfg_name);

        let cfgmgr =
            Proxy::new(&conn, SERVICE_CONFIGMGR, CONFIGMGR_PATH, SERVICE_CONFIGMGR).await?;
        let cfg_path: OwnedObjectPath = cfgmgr
            .call_method("Import", &(&cfg_name, &cfg_str, true, false))
            .await
            .with_context(|| format!("Importing OpenVPN profile {cfg_name}"))?
            .body()
            .deserialize::<OwnedObjectPath>()?;
        // Let NM own DNS (netcfg applies DNS itself otherwise).
        let cfg_obj = Proxy::new(
            &conn,
            SERVICE_CONFIGMGR,
            cfg_path.clone(),
            SERVICE_CONFIGMGR,
        )
        .await?;
        if let Err(e) = cfg_obj
            .call_method("SetOverride", &("dns-setup-disabled", Value::from(true)))
            .await
        {
            warn!("SetOverride dns-setup-disabled failed: {e}");
        }
        debug!("Imported config at {cfg_path}");

        // A stale session of the same profile (e.g. left over from a manual
        // `openvpn3 session-start`) makes NewTunnel fail with "already running".
        disconnect_profile_sessions(&conn, &cfg_name).await;

        let session_path: OwnedObjectPath =
            Proxy::new(&conn, SERVICE_SESSIONS, SESSIONS_PATH, SERVICE_SESSIONS)
                .await?
                .call_method("NewTunnel", &(cfg_path.clone(),))
                .await
                .context("Creating OpenVPN 3 session")?
                .body()
                .deserialize::<OwnedObjectPath>()?;
        info!("Session created: {session_path}");

        let session = Proxy::new(
            &conn,
            SERVICE_SESSIONS,
            session_path.clone(),
            SERVICE_SESSIONS,
        )
        .await?;
        // Subscribe *before* touching the session so no transition is missed.
        let status_stream = session.receive_signal("StatusChange").await?;
        // Raise backend log verbosity and forward session logs — without this
        // the backend client runs nearly silent (the session-start CLI does
        // the same, which is why CLI runs show the full TLS story).
        // NOTE: do NOT set_property("log_verbosity", …) — that write throws
        // "Session not active" inside the sessionmgr daemon and aborts it,
        // taking every session down with it (observed crash file, 0.3.5).
        if let Err(e) = session.call_method("LogForward", &(true,)).await {
            warn!("LogForward: {e}");
        }

        let emitter = self.event_tx.clone();
        let dbus_clone = Mutex::new(Some(conn.clone()));
        let sp = session_path.clone();
        // NM requires the external VPN gateway (the resolved server address)
        // in the Config signal; v20 does not expose it as a session property
        // (connected_to missing), so resolve the first remote entry from the
        // connection data ourselves.
        let remote_raw = self.config.raw_data.get("remote").cloned();
        tokio::spawn(watch_status(
            status_stream,
            sp,
            emitter,
            dbus_clone,
            remote_raw,
        ));

        // Tap the session Log signal (LogForward-ed from the backend) —
        // without a listener the verbosity data lands nowhere.
        if let Ok(log_stream) = session.receive_signal("Log").await {
            tokio::spawn(async move {
                let mut log_stream = log_stream;
                while let Some(msg) = log_stream.next().await {
                    if let Ok((group, level, text)) = msg.body().deserialize::<(u32, u32, String)>()
                    {
                        info!("backend[{group}/{level}] {text}");
                    }
                }
                info!("Log stream closed");
            });
        }

        // Mirror the openvpn3 session-start CLI: Ready() throws when the
        // backend needs something from us or hasn't finished booting yet
        // ("Backend VPN process is not ready"). On the SSO auth-URL attention
        // we open the browser ourselves (the CLI does this via open_uri — the
        // daemon does NOT launch it) and return; the backend finishes the
        // handshake once the browser-based authentication completes.
        // # ponytail: CREDENTIALS attentions (user/password/challenge) and
        // CFG_REQUIRE_USER-only profiles are fatal for now — this backend is
        // for the SSO web-auth profile; add QueueFetchAll + ProvideResponse
        // handling if non-SSO profiles ever need it.
        for attempt in 0..45 {
            match session.call_method("Ready", &()).await {
                Ok(_) => {
                    session.call_method("Connect", &()).await?;
                    // Retry log forwarding now that the backend is active —
                    // the pre-Ready call fails while the backend boots, and
                    // without it the backend's TLS story is invisible.
                    if let Err(e) = session.call_method("LogForward", &(true,)).await {
                        warn!("LogForward retry: {e}");
                    }
                    // Raise verbosity so forwarded handshake/TLS logs actually
                    // reach the Log signal stream. # ponytail: the same write
                    // pre-Ready aborted openvpn3-service-sessionmgr
                    // ('Session not active'); post-Ready the session is
                    // active — keep this after Connect, never earlier.
                    if let Err(e) = session.set_property("log_verbosity", 1u32).await {
                        warn!("log_verbosity set failed: {e}");
                    }
                    // The auth-URL attention can surface as a status change a
                    // few seconds after Connect (seen live: ~60 s later on one
                    // run, ~2 s on others). Poll briefly so the browser opens
                    // well before NM's 60 s connect timeout; anything later is
                    // caught by the status watcher.
                    for _ in 0..8 {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        if let Some((MAJOR_SESS, MINOR_SESS_AUTH_URL, msg)) =
                            last_status(&session).await
                        {
                            warn!("Auth-URL attention visible in status: {msg}");
                            if let Some(url) = extract_url(&msg) {
                                let _ = self.event_tx.try_send(VpnEvent::AuthRequired {
                                    auth_url: Some(url.clone()),
                                });
                                open_in_browser(&url);
                            }
                            return Ok(()); // auth completes externally; watcher takes over
                        }
                    }
                    return Ok(()); // skip the post-loop give-up tail
                }
                Err(e) => {
                    let status = last_status(&session).await;
                    if let Some((MAJOR_SESS, MINOR_SESS_AUTH_URL, msg)) = status.as_ref() {
                        let url = extract_url(msg);
                        info!("Web-based authentication required: {url:?}");
                        let _ = self.event_tx.try_send(VpnEvent::AuthRequired {
                            auth_url: url.clone(),
                        });
                        if let Some(url) = url {
                            open_in_browser(&url);
                        }
                        return Ok(()); // auth completes externally; watcher takes over
                    }
                    if attempt == 0 || attempt % 10 == 9 {
                        info!("Ready() attempt {}: {e}", attempt + 1);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
        // Don't leave the half-started session behind; NM needs a real error.
        let _ = session.call_method("Disconnect", &()).await;
        Err(anyhow!("OpenVPN 3 backend never became ready"))
    }

    /// Disconnect and remove the running session of this profile (if any).
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(conn) = self.dbus.lock().await.clone() {
            let name = self
                .profile_name
                .lock()
                .await
                .clone()
                .unwrap_or_else(|| profile_file_name(&self.config));
            disconnect_profile_sessions(&conn, &name).await;
            *self.profile_name.lock().await = None;
        }
        Ok(())
    }
}

fn profile_file_name(config: &ConnectionConfig) -> String {
    config
        .config_path
        .as_ref()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_default()
}

/// Disconnect every openvpn3 session sourced from `cfg_name` and clear the
/// stored manager state afterwards.
async fn disconnect_profile_sessions(conn: &Connection, cfg_name: &str) {
    if cfg_name.is_empty() {
        return;
    }
    let Ok(mgr) = Proxy::new(conn, SERVICE_SESSIONS, SESSIONS_PATH, SERVICE_SESSIONS).await else {
        return;
    };
    let reply = match mgr.call_method("FetchAvailableSessions", &()).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let paths = reply
        .body()
        .deserialize::<Vec<OwnedObjectPath>>()
        .unwrap_or_default();
    for path in paths {
        let Ok(p) = Proxy::new(conn, SERVICE_SESSIONS, path.clone(), SERVICE_SESSIONS).await else {
            continue;
        };
        if let Ok(name) = p.get_property::<OwnedValue>("config_name").await
            && let Ok(name) = <String>::try_from(name)
            && name == cfg_name
        {
            info!("Disconnecting session {path}");
            let _ = p.call_method("Disconnect", &()).await;
        }
    }
}

/// Read the session `status` property (uus = major, minor, message).
async fn last_status(session: &Proxy<'_>) -> Option<(u32, u32, String)> {
    let val = session.get_property::<OwnedValue>("status").await.ok()?;
    <(u32, u32, String)>::try_from(val).ok()
}

/// Pull the auth URL the backend put into a status message.
fn extract_url(msg: &str) -> Option<String> {
    msg.split_whitespace()
        .find(|t| t.starts_with("http://") || t.starts_with("https://"))
        .map(|s| s.trim_end_matches([',', '.', ')', ';']).to_string())
}

/// Epoch-millis of the last browser open — both the post-Connect status
/// poll and the watch_status signal handler react to (3,SESS_AUTH_URL), and
/// NM may call connect() twice; this collapses all of them into ONE tab.
static LAST_AUTH_OPEN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn open_in_browser(url: &str) {
    use std::sync::atomic::Ordering;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let guard = LAST_AUTH_OPEN_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(guard) < 5_000
        || LAST_AUTH_OPEN_MS
            .compare_exchange(guard, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return; // deduped (5 s window)
    }
    // xdg-open from this root-spawned plugin has no WAYLAND_DISPLAY/DISPLAY
    // inside its environment — observed live: xdg-open goes straight
    // defunct, no browser, no error anywhere. Borrow the graphical
    // session's env and re-run xdg-open as the desktop user.
    // # ponytail: GNOME/KDE/xfce anchor processes, first match wins;
    // a real multi-seat picker is out of scope for a desktop plugin.
    if let Some(session) = find_graphical_session() {
        let mut cmd = std::process::Command::new("/usr/sbin/runuser");
        cmd.args(["-u", &session.0, "--", "xdg-open", url]);
        for (k, v) in &session.1 {
            cmd.env(k, v);
        }
        if cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            return;
        }
    }
    // Last resort / headless fallback.
    let _ = std::process::Command::new("xdg-open")
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Graphical-session env pieces the plugin can discover without
/// CAP_SYS_PTRACE (NM's CapabilityBoundingSet drops it, so /proc environ
/// reads of other users fail): filesystem conventions only.
const X_SOCKET_DIR: &str = "/tmp/.X11-unix";

/// Graphical session candidate for env discovery: (uid, evidence score,
/// username, env pairs needed to reach that session).
type GraphicalCandidate = (u32, u8, String, Vec<(String, String)>);

/// (username, [env pairs needed to reach the graphical session])
fn find_graphical_session() -> Option<(String, Vec<(String, String)>)> {
    let mut dirs: Vec<(u32, String)> = std::fs::read_dir("/run/user")
        .ok()?
        .filter_map(|d| d.ok())
        .filter_map(|d| {
            let name = d.file_name().into_string().ok()?;
            name.parse::<u32>()
                .ok()
                .filter(|&u| u != 0)
                .map(|u| (u, name))
        })
        .collect();
    // Sorted so the pick is deterministic even with several logged-in
    // users; the graphical-evidence ranking decides which session wins.
    dirs.sort();
    // WINNER: most graphical evidence, ties broken by higher uid
    // (real desktop users sort above service accounts).
    let mut candidates: Vec<GraphicalCandidate> = Vec::new();
    for (uid, _) in dirs {
        let runtime = format!("/run/user/{uid}");
        let mut env: Vec<(String, String)> = vec![
            ("XDG_RUNTIME_DIR".into(), runtime.clone()),
            (
                "DBUS_SESSION_BUS_ADDRESS".into(),
                format!("unix:path={runtime}/bus"),
            ),
        ];
        let mut evidence = 0;
        let wayland = format!("{runtime}/wayland-0");
        if std::fs::metadata(&wayland).is_ok() {
            env.push(("WAYLAND_DISPLAY".into(), "wayland-0".into()));
            evidence += 1;
        }
        // First X socket → DISPLAY=:N; on gdm sessions the Xauthority
        // file sits under <runtime>/gdm/Xauthority.
        if let Ok(sockets) = std::fs::read_dir(X_SOCKET_DIR) {
            let mut nums: Vec<u32> = sockets
                .filter_map(|s| s.ok())
                .filter_map(|s| s.file_name().into_string().ok())
                .filter_map(|n| n.strip_prefix("X")?.parse().ok())
                .collect();
            nums.sort();
            if let Some(n) = nums.first() {
                env.push(("DISPLAY".into(), format!(":{n}")));
                evidence += 1;
            }
        }
        let xauthority = format!("{runtime}/gdm/Xauthority");
        if std::fs::metadata(&xauthority).is_ok() {
            env.push(("XAUTHORITY".into(), xauthority));
        }
        // No graphical evidence at all → not a desktop session (e.g. an
        // ssh-only user's runtime dir); skip instead of mis-picking it.
        if evidence == 0 {
            continue;
        }
        let user = passwd_user(uid);
        if let Some(user) = user {
            candidates.push((uid, evidence, user, env));
        }
    }
    candidates.sort_by_key(|&(uid, ev, _, _)| (ev, uid));
    candidates.pop().map(|(_, _, user, env)| (user, env))
}

/// /etc/passwd lookup (root reads it fine).
#[cfg(test)]
mod browser_tests {
    use super::*;

    /// Live self-check: on a machine with a graphical session the discovery
    /// must find it (non-root, display env set); on headless environments
    /// (CI, containers) there is nothing to find and the test skips.
    #[test]
    fn finds_desktop_session_env() {
        match find_graphical_session() {
            None => {
                assert!(
                    std::fs::read_dir("/run/user")
                        .map(|d| d.count())
                        .unwrap_or(0)
                        <= 1,
                    "graphical users exist but no session was discovered"
                );
            }
            Some(session) => {
                assert_ne!(session.0, "root", "picked root, not a desktop user");
                let keys: Vec<String> = session.1.iter().map(|(k, _)| k.clone()).collect();
                assert!(
                    keys.contains(&"DISPLAY".to_string())
                        || keys.contains(&"WAYLAND_DISPLAY".to_string())
                );
            }
        }
    }
}

fn passwd_user(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _ = parts.next()?;
        let uid_field = parts.next()?;
        (uid_field == uid.to_string()).then(|| name.to_string())
    })
}

async fn watch_status(
    mut stream: zbus::proxy::SignalStream<'_>,
    session_path: OwnedObjectPath,
    event_tx: mpsc::Sender<VpnEvent>,
    dbus: Mutex<Option<Connection>>,
    remote_raw: Option<String>,
) {
    info!("Watching StatusChange on {session_path}");
    let mut saw_connected = false;
    let mut saw_any = false;
    let mut auth_opened = false;
    let mut auth_phase = false; // user is completing browser SSO; wait longer
    // openvpn3 v20 does NOT reliably re-emit (2,7) as a signal for the
    // post-SSO connect (observed live: backend connected, routes set up,
    // zero further StatusChange signals) — so signals are only the fast
    // path; when none arrive we poll the status property and treat any
    // change the same as a signal. # ponytail: 5 s poll is plenty fast
    // for NM; keep the signal listener for sub-second transitions.
    let mut last_seen: Option<(u32, u32)> = None;
    let mut last_progress = std::time::Instant::now();
    loop {
        // Watchdog: a backend whose status stops changing for `wait`
        // seconds (and that never connected) must fail NM activation
        // with a real reason instead of NM's own deep timeout. During
        // the auth phase the user is clicking through SSO + second
        // factor, so give that 10 minutes instead of 90 s.
        let wait = if auth_phase { 600 } else { 90 };
        if last_progress.elapsed() >= std::time::Duration::from_secs(wait) {
            if saw_connected {
                info!("Status stream idle; session stays up");
                last_progress = std::time::Instant::now(); // re-arm
                continue;
            }
            let reason = if saw_any {
                "OpenVPN 3 backend went silent before connecting"
            } else {
                "OpenVPN 3 backend never reported any status"
            };
            let _ = event_tx.send(VpnEvent::Failed(reason.into())).await;
            let conn = dbus.lock().await.clone();
            if let Some(conn) = conn
                && let Ok(s) = Proxy::new(
                    &conn,
                    SERVICE_SESSIONS,
                    session_path.clone(),
                    SERVICE_SESSIONS,
                )
                .await
            {
                let _ = s.call_method("Disconnect", &()).await;
            }
            return;
        }

        let (major, minor, message) =
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await {
                Ok(Some(m)) => {
                    saw_any = true;
                    match m.body().deserialize::<(u32, u32, String)>() {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Bad StatusChange payload: {e}");
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    info!("Status stream closed for {session_path}");
                    return;
                }
                Err(_) => {
                    // No signal in 5 s: did the status property change?
                    let conn = dbus.lock().await.clone();
                    let Some(conn) = conn else { continue };
                    let Ok(s) = Proxy::new(
                        &conn,
                        SERVICE_SESSIONS,
                        session_path.clone(),
                        SERVICE_SESSIONS,
                    )
                    .await
                    else {
                        continue;
                    };
                    let Some((maj, min, txt)) = last_status(&s).await else {
                        continue;
                    };
                    if last_seen == Some((maj, min)) {
                        continue; // unchanged
                    }
                    (maj, min, txt)
                }
            };
        if last_seen != Some((major, minor)) {
            last_progress = std::time::Instant::now();
            last_seen = Some((major, minor));
        }
        info!("StatusChange: ({major}, {minor}, {message:?})");

        let fatal = matches!(
            (major, minor),
            (MAJOR_CONN, MINOR_CONN_FAILED)
                | (MAJOR_CONN, MINOR_CONN_AUTH_FAILED)
                | (MAJOR_CFG, MINOR_CFG_ERROR)
                | (MAJOR_CFG, MINOR_CFG_INLINE_MISSING)
        );
        let event = match (major, minor) {
            (MAJOR_CONN, MINOR_CONN_INIT) | (MAJOR_CONN, MINOR_CONN_CONNECTING) => {
                Some(VpnEvent::State(VpnState::Connecting))
            }
            (MAJOR_CONN, MINOR_CONN_RECONNECTING) => Some(VpnEvent::State(VpnState::GettingConfig)),
            (MAJOR_CONN, MINOR_CONN_DISCONNECTED) => Some(VpnEvent::State(VpnState::Stopped)),
            (MAJOR_SESS, MINOR_SESS_AUTH_URL) => {
                // Handled below the match (needs the dedupe flag).
                None
            }
            (MAJOR_SESS, MINOR_SESS_AUTH_USERPASS) | (MAJOR_SESS, MINOR_SESS_AUTH_CHALLENGE) => {
                Some(VpnEvent::State(VpnState::NeedAuth))
            }
            (MAJOR_CFG, MINOR_CFG_ERROR) | (MAJOR_CFG, MINOR_CFG_INLINE_MISSING) => Some(
                VpnEvent::Failed(format!("Invalid configuration: {message}")),
            ),
            (MAJOR_CONN, MINOR_CONN_FAILED) => {
                Some(VpnEvent::Failed(format!("Connection failed: {message}")))
            }
            (MAJOR_CONN, MINOR_CONN_AUTH_FAILED) => {
                Some(VpnEvent::Failed("User authentication failed".into()))
            }
            _ => None,
        };

        // CLI behaviour: kill the session on hard failures.
        if fatal {
            let conn = dbus.lock().await.clone();
            if let Some(conn) = conn
                && let Ok(s) = Proxy::new(
                    &conn,
                    SERVICE_SESSIONS,
                    session_path.clone(),
                    SERVICE_SESSIONS,
                )
                .await
            {
                let _ = s.call_method("Disconnect", &()).await;
            }
        }

        // SSO auth-URL attention: the backend pauses here awaiting external
        // browser auth (mirrors the CLI's start_url_auth path). Open the
        // browser ONCE; the backend completes the handshake alone afterwards.
        if (major, minor) == (MAJOR_SESS, MINOR_SESS_AUTH_URL) && !auth_opened {
            auth_opened = true;
            auth_phase = true; // user is doing SSO in the browser; stretch watchdog
            let url = extract_url(&message);
            info!("Web-based authentication required: {url:?}");
            let _ = event_tx.try_send(VpnEvent::AuthRequired {
                auth_url: url.clone(),
            });
            if let Some(url) = url {
                open_in_browser(&url);
            }
        }
        if let Some(ev) = event
            && event_tx.send(ev).await.is_err()
        {
            info!("Event consumer gone; stopping status watch");
            return;
        }

        if (major, minor) == (MAJOR_CONN, MINOR_CONN_CONNECTED) {
            saw_connected = true;
            let conn = dbus.lock().await.clone();
            if let Some(conn) = conn {
                let session_proxy = Proxy::new(
                    &conn,
                    SERVICE_SESSIONS,
                    session_path.clone(),
                    SERVICE_SESSIONS,
                )
                .await;
                if let Ok(session_proxy) = session_proxy {
                    let cfg = match collect_vpn_config(&session_proxy, remote_raw.as_deref()).await
                    {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            error!("Failed to collect VPN configuration: {e:#}");
                            VpnConfig::default()
                        }
                    };
                    if event_tx.send(VpnEvent::Connected(cfg)).await.is_err() {
                        info!("Event consumer gone; stopping status watch");
                        return;
                    }
                    info!("Connected; continuing to watch for disconnects");
                } else {
                    error!("Session proxy disappeared");
                }
            } else {
                error!("No session connection available");
            }
        }
    }
}

/// Fetch the resulting tun/IP/route/DNS configuration from the session's
/// netcfg device object and build a NM-ready VpnConfig.
async fn collect_vpn_config(session: &Proxy<'_>, remote_raw: Option<&str>) -> Result<VpnConfig> {
    let device_name: String = session
        .get_property("device_name")
        .await
        .map_err(|e| anyhow!("device_name: {e}"))?;
    // v20's device_path is a plain (s) string, NOT an (o) ObjectPath —
    // typed reads as OwnedObjectPath fail with 'incorrect type' (observed
    // live).
    let device_path_str: String = session
        .get_property("device_path")
        .await
        .map_err(|e| anyhow!("device_path: {e}"))?;
    let device_path: OwnedObjectPath =
        zbus::zvariant::ObjectPath::try_from(device_path_str.as_str())
            .map_err(|e| anyhow!("device_path value: {e}"))?
            .into();
    // connected_to = (proto, server_ip, server_port) — openvpn3 v20 does NOT
    // expose this property (No such property), so treat it as optional and
    // fall back to resolving the first remote entry from the connection data.
    let remote_ip = session
        .get_property::<OwnedValue>("connected_to")
        .await
        .ok()
        .and_then(|v| <(String, String, u32)>::try_from(v).ok())
        .map(|t| t.1)
        .or_else(|| remote_raw.and_then(resolve_remote));

    let netcfg = Proxy::new(
        session.connection(),
        SERVICE_NETCFG,
        device_path,
        SERVICE_NETCFG,
    )
    .await
    .map_err(|e| anyhow!("netcfg proxy: {e}"))?;
    let dns_servers: Vec<String> = netcfg
        .get_property("dns_name_servers")
        .await
        .unwrap_or_default();
    let dns_search: Vec<String> = netcfg
        .get_property("dns_search_domains")
        .await
        .unwrap_or_default();
    let network_config = netcfg
        .get_property::<OwnedValue>("network_config")
        .await
        .ok();
    if let Some(ref nc) = network_config {
        debug!("network_config = {nc:?}");
    }

    let mut parser = NetCfgParser::default();
    match network_config.as_ref() {
        Some(nc) => {
            if let Err(e) = parser.walk(nc) {
                warn!("network_config parse issue: {e:#}");
            }
        }
        None => warn!("network_config not readable; falling back to ip scrape"),
    }

    // Fallback scrape when the netcfg property was inaccessible/empty.
    if parser.local_ip.is_none()
        && let Ok((ip, prefix)) = scrape_tun_address(&device_name)
    {
        parser.local_ip = Some(ip);
        parser.prefix = Some(prefix);
    }
    if parser.gateway.is_none() && parser.local_ip.is_some() {
        // Link-local convention used by the server's netcfg (x.x.x.1).
        if let Some(ip) = parser.local_ip.as_ref()
            && let Some(net) = ip.rsplit_once('.')
        {
            parser.gateway = Some(format!("{}.1", net.0));
        }
    }

    let gateway = parser.gateway.clone().or_else(|| remote_ip.clone());
    Ok(VpnConfig {
        tun_device: Some(device_name),
        local_ip: parser.local_ip,
        remote_ip,
        netmask: parser.prefix.map(prefix_netmask),
        gateway,
        dns_servers,
        dns_search,
    })
}

/// Resolve the first remote entry of a comma-separated "host:port:proto"
/// list to its first IPv4 address (system resolver; synchronous but brief).
/// Caveat: only vpn.data 'remote' keys are covered — a direct config_path
/// profile without fragments yields no remote here (ponytail: current
/// live connection is fragment-based; add profile-text scraping if a
/// config_path connection needs NM activation).
fn resolve_remote(raw: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let first = raw.split(',').next()?.trim();
    let mut parts = first.split(':');
    let host = parts.next()?.trim();
    let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(1194);
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.is_ipv4()).map(|a| a.ip().to_string()))
}

/// Scrape the tun device's IPv4 addr (ip, prefix) from `ip -j` output via the
/// textual `-4 -o address` form (no serde dep needed).
fn scrape_tun_address(device: &str) -> Result<(String, u32)> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "address", "show", "dev", device])
        .output()
        .context("ip -o address failed")?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        for word in line.split_whitespace() {
            if let Some((ip, prefix)) = word.split_once('/')
                && let Ok(prefix) = prefix.parse()
            {
                return Ok((ip.to_string(), prefix));
            }
        }
    }
    Err(anyhow!("no inet addr on {device}"))
}

/// Tolerant parser for the netcfg `network_config` a{sv} property:
/// gateway (IPv4), vpn_addresses (s,u,s tuples).
#[derive(Default)]
struct NetCfgParser {
    local_ip: Option<String>,
    prefix: Option<u32>,
    gateway: Option<String>,
}

impl NetCfgParser {
    fn walk(&mut self, owned: &OwnedValue) -> Result<()> {
        let dict = Dict::try_from(owned.clone())
            .map_err(|e| anyhow!("network_config is not a dict: {e}"))?;
        for (k, v) in dict.iter() {
            let Value::Str(key) = k else { continue };
            match key.as_str() {
                "vpn_addresses" => {
                    for (ip, prefix, gw) in tuple_list(v) {
                        if ip.parse::<Ipv4Addr>().is_ok() && self.local_ip.is_none() {
                            self.local_ip = Some(ip.clone());
                            self.prefix = Some(prefix);
                            if gw.parse::<Ipv4Addr>().is_ok() {
                                self.gateway = Some(gw.clone());
                            }
                        }
                    }
                }
                "gateway" if self.gateway.is_none() => {
                    self.first_ip_in(v);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Recursive scan for the first IPv4-looking string under `v` (gateway).
    fn first_ip_in(&mut self, v: &Value<'_>) {
        let found = matches!(
            v,
            Value::Str(s) if s.parse::<Ipv4Addr>().is_ok()
        );
        if found {
            if let Value::Str(s) = v {
                self.gateway = Some(s.to_string());
            }
            return;
        }
        match v {
            Value::Value(inner) => self.first_ip_in(inner.as_ref()),
            Value::Array(a) => {
                for item in a.iter() {
                    self.first_ip_in(item);
                    if self.gateway.is_some() {
                        return;
                    }
                }
            }
            Value::Dict(d) => {
                for (_, v) in d.iter() {
                    self.first_ip_in(v);
                    if self.gateway.is_some() {
                        return;
                    }
                }
            }
            Value::Structure(s) => {
                for f in s.fields() {
                    self.first_ip_in(f);
                    if self.gateway.is_some() {
                        return;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Iterate every `(s,u,s)` tuple reachable in an array or nested variants.
fn tuple_list(v: &Value<'_>) -> Vec<(String, u32, String)> {
    match v {
        Value::Value(inner) => tuple_list(inner.as_ref()),
        Value::Array(a) => a.iter().flat_map(|e| tuple_list(e)).collect(),
        Value::Structure(s) if s.fields().len() == 3 => {
            let f = s.fields();
            let (Ok(ip), Ok(prefix), Ok(gw)) = (
                <&str>::try_from(&f[0]).map(str::to_string),
                u32::try_from(&f[1]),
                <&str>::try_from(&f[2]).map(str::to_string),
            ) else {
                return Vec::new();
            };
            vec![(ip, prefix, gw)]
        }
        _ => Vec::new(),
    }
}

fn prefix_netmask(prefix: u32) -> String {
    if prefix == 0 {
        return "0.0.0.0".into();
    }
    Ipv4Addr::from(u32::MAX << (32 - prefix)).to_string()
}

// ---------------------------------------------------------------------------
// Profile synthesis from NM-fragmented vpn.data
// ---------------------------------------------------------------------------

/// Reassemble an .ovpn profile from the fragment pieces `nmcli connection
/// import type openvpn` produces (ca/cert/key/tls-crypt extracted to files,
/// the rest scattered over vpn.data). Whitelist mapping only — the openvpn3
/// config parser rejects unknown options, so unrecognised keys are dropped.
fn build_profile_text(raw: &HashMap<String, String>) -> String {
    let mut text = String::from("client\n");
    let dev = raw.get("dev").map(|s| s.as_str()).unwrap_or("tun");
    text.push_str(&format!("dev {dev}\n"));

    if let Some(remotes) = raw.get("remote") {
        for token in remotes.split(',') {
            let token = token.trim();
            let mut parts = token.split(':');
            let (Some(host), Some(port)) = (parts.next(), parts.next()) else {
                continue;
            };
            let proto = parts.next().unwrap_or("udp");
            let proto = if proto.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            };
            text.push_str(&format!("remote {host} {port} {proto}\n"));
        }
    }

    // Cert material NM keeps as separate files → inline sections.
    for (key, tag) in [("ca", "ca"), ("cert", "cert"), ("key", "key")] {
        if let Some(pem) = read_inline(raw.get(key)) {
            text.push_str(&format!("<{tag}>\n{pem}\n</{tag}>\n"));
        }
    }
    if let Some(pem) = read_inline(raw.get("tls-crypt")) {
        text.push_str(&format!("<tls-crypt>\n{pem}\n</tls-crypt>\n"));
    } else if let Some(pem) = read_inline(raw.get("ta")) {
        text.push_str(&format!("<tls-auth>\n{pem}\n</tls-auth>\n"));
        if let Some(dir) = raw.get("ta-dir") {
            text.push_str(&format!("key-direction {dir}\n"));
        }
    }

    for (key, directive) in [
        ("cipher", "cipher"),
        ("auth", "auth"),
        ("remote-cert-tls", "remote-cert-tls"),
        ("tls-version-min", "tls-version-min"),
    ] {
        if let Some(v) = raw.get(key) {
            text.push_str(&format!("{directive} {v}\n"));
        }
    }
    if let Some(v) = raw.get("reneg-seconds") {
        text.push_str(&format!("reneg-sec {v}\n"));
    }
    if raw
        .get("push-peer-info")
        .map(|v| v == "yes")
        .unwrap_or(false)
    {
        text.push_str("push-peer-info\n");
    }
    if raw
        .get("connection-type")
        .map(|v| v == "password")
        .unwrap_or(false)
    {
        text.push_str("auth-user-pass\n");
    }
    text
}

fn read_inline(path: Option<&String>) -> Option<String> {
    let p = path?;
    std::fs::read_to_string(p)
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

/// Write the synthesized profile to a plugin-private file and return its path.
fn synthesize_profile(config: &ConnectionConfig) -> Result<PathBuf> {
    let text = build_profile_text(&config.raw_data);
    if !text.contains("<ca>") && !text.contains("<tls-crypt") && !text.contains("<tls-auth") {
        return Err(anyhow!(
            "Cannot use the openvpn3 backend: the connection has neither a vpn.data \
             'config' profile nor enough fragments (ca/cert/key) to rebuild one"
        ));
    }
    let dir = PathBuf::from("/var/lib/nm-openvpn3-sso");
    std::fs::create_dir_all(&dir).context("Creating profile directory /var/lib/nm-openvpn3-sso")?;
    let path = dir.join(format!("{}.ovpn", config.uuid));
    std::fs::write(&path, &text).with_context(|| format!("Writing {}", path.display()))?;
    // Contains the client private key; failing to restrict it would leave a
    // world-readable key behind, so don't swallow the error.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Restricting {} to 0600", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_remotes_directives_and_sections() {
        let dir = std::env::temp_dir();
        let ca = dir.join("nm-sso-test-ca.pem");
        std::fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\nTESTCA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let raw: HashMap<String, String> = HashMap::from([
            (
                "remote".into(),
                "vpn.example.com:1194:udp, vpn.example.com:443:tcp".into(),
            ),
            ("ca".into(), ca.as_os_str().to_string_lossy().to_string()),
            ("cipher".into(), "AES-256-CBC".into()),
            ("reneg-seconds".into(), "604800".into()),
            ("push-peer-info".into(), "yes".into()),
            ("unknown-key".into(), "should-not-appear".into()),
        ]);

        let text = build_profile_text(&raw);
        for expected in [
            "client\n",
            "dev tun\n",
            "remote vpn.example.com 1194 udp\n",
            "remote vpn.example.com 443 tcp\n",
            "<ca>\n-----BEGIN CERTIFICATE-----",
            "</ca>",
            "cipher AES-256-CBC\n",
            "reneg-sec 604800\n",
            "push-peer-info\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("should-not-appear"));
        assert!(!text.contains("unknown-key"));
        std::fs::remove_file(&ca).ok();
    }
}
