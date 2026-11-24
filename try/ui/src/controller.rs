//! Bridges the window and the network Plugin, through the interface contract alone.
//!
//! - **Reading.** `network.devices` and `network.scan` are streams of the whole picture: each frame
//!   replaces what is shown. `network.status` is a stream of changes with a sequence: the panel subscribes
//!   first, then asks `network.status`, and drops every frame at or below the sequence it was answered
//!   with, so that attaching late shows the present without a gap. The profiles have no stream and are
//!   asked again after every command and every change of the connection.
//! - **Acting.** Every button is a command; its acknowledgement is the message under the window. A
//!   connection carries a `request_id`, and the steps `network.status` brings for it are shown as they come.
//! - **The Events tab** is the Core's events about the unit — its state, its health, its occurrences —
//!   and the status' changes.
//! - **No secret is written**: a payload is built, sent and dropped, and nothing here prints one.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel, Weak};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::time::{interval, sleep};
use yoke_sdk::interface::{Attachment, Filter, Options};

use crate::{ApRow, DeviceRow, EapForm, Ipv4Form, MainWindow, PermRow, ProfileEdit, ProfileRow};

const STATUS: &str = "network.status";
const DEVICES: &str = "network.devices";
const SCAN: &str = "network.scan";
/// Events kept in the Events tab.
const MAX_EVENTS: usize = 300;
/// The Events tab is redrawn at most this often, whatever the event rate.
const EVENTS_REDRAW: Duration = Duration::from_millis(500);
/// How long a delivery the Core ended waits before it is asked for again.
const AGAIN: Duration = Duration::from_secs(2);

/// What the panel holds between two frames.
#[derive(Default)]
struct Held {
    devices: Vec<Value>,
    access_points: Vec<Value>,
    profiles: Vec<Value>,
    /// The connections in flight, by request, with the name the window shows them under.
    pending: HashMap<String, String>,
}

#[derive(Default)]
struct Log {
    lines: VecDeque<String>,
    dirty: bool,
}

/// What `finish` needs once the window has closed: the attachment, and the streams this panel started.
pub struct Shared {
    unit: String,
    attachment: OnceLock<Arc<Attachment>>,
    started: Mutex<Vec<String>>,
}

#[derive(Clone)]
struct Ctx {
    at: Arc<Attachment>,
    unit: String,
    ui: Weak<MainWindow>,
    held: Arc<Mutex<Held>>,
    log: Arc<Mutex<Log>>,
    t0: Instant,
    shared: Arc<Shared>,
}

fn say(ui: &Weak<MainWindow>, msg: impl Into<String>) {
    let m = msg.into();
    // Also on stderr, so that a run nobody looks at — the watch's — can read what the panel showed.
    eprintln!("network-ui: {m}");
    let _ = ui.upgrade_in_event_loop(move |u| u.set_message(m.into()));
}

fn set_busy(ui: &Weak<MainWindow>, busy: bool) {
    let _ = ui.upgrade_in_event_loop(move |u| u.set_busy(busy));
}

fn request_id() -> String {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    format!("ui-{ms}")
}

/// Trimmed text; empty means "not provided". For paths, identities, etc.
fn opt(s: &SharedString) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Untrimmed text; empty means "not provided". For passwords, where spaces count.
fn opt_secret(s: &SharedString) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// An object with the fields that have a value.
fn object(fields: Vec<(&str, Option<Value>)>) -> Value {
    let mut m = Map::new();
    for (k, v) in fields {
        if let Some(v) = v {
            m.insert(k.into(), v);
        }
    }
    Value::Object(m)
}

fn eap(f: &EapForm) -> Result<Value, String> {
    let identity = f.identity.trim().to_string();
    if identity.is_empty() {
        return Err("Identity is required for 802.1X".into());
    }
    let tls = f.method == "tls";
    if tls && (f.client_cert.trim().is_empty() || f.private_key.trim().is_empty()) {
        return Err("EAP-TLS needs a client certificate and a private key".into());
    }
    let s = |v: Option<String>| v.map(Value::String);
    Ok(object(vec![
        ("method", Some(json!(f.method.to_string()))),
        ("identity", Some(json!(identity))),
        ("password", if tls { None } else { s(opt_secret(&f.password)) }),
        ("anonymous_identity", if tls { None } else { s(opt(&f.anonymous)) }),
        ("ca_cert_path", s(opt(&f.ca_cert))),
        ("client_cert_path", if tls { s(opt(&f.client_cert)) } else { None }),
        ("private_key_path", if tls { s(opt(&f.private_key)) } else { None }),
        ("private_key_password", if tls { s(opt_secret(&f.private_key_password)) } else { None }),
        ("phase2_auth", if tls { None } else { s(opt(&f.phase2)) }),
    ]))
}

fn parse_ip(label: &str, s: &str) -> Result<Ipv4Addr, String> {
    s.trim().parse().map_err(|_| format!("{label}: \"{}\" is not a valid IPv4 address", s.trim()))
}

fn ipv4(f: &Ipv4Form) -> Result<Value, String> {
    let dns = f
        .dns
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| parse_ip("DNS", s).map(|ip| ip.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if f.method == "auto" {
        return Ok(json!({ "method": "auto", "dns": dns }));
    }
    let address = parse_ip("Address", &f.address)?.to_string();
    let prefix: u8 = f
        .prefix
        .trim()
        .parse()
        .ok()
        .filter(|p| (1..=32).contains(p))
        .ok_or("Prefix length must be between 1 and 32")?;
    let gateway = match opt(&f.gateway) {
        Some(g) => Some(json!(parse_ip("Gateway", &g)?.to_string())),
        None => None,
    };
    Ok(object(vec![
        ("method", Some(json!("manual"))),
        ("address", Some(json!(address))),
        ("prefix", Some(json!(prefix))),
        ("gateway", gateway),
        ("dns", Some(json!(dns))),
    ]))
}

/// Attaches, and wires every callback of the window. The attachment is made on the runtime; until it
/// is, a button says that the panel is not attached.
pub fn start(rt: Handle, address: String, unit: String, ui: &MainWindow) -> Arc<Shared> {
    let shared = Arc::new(Shared { unit: unit.clone(), attachment: OnceLock::new(), started: Mutex::new(Vec::new()) });
    let weak = ui.as_weak();
    let held = Arc::new(Mutex::new(Held::default()));
    let log = Arc::new(Mutex::new(Log::default()));
    let clear = Arc::new(Notify::new());
    let ready: Arc<OnceLock<Ctx>> = Arc::new(OnceLock::new());

    // Registers a callback that runs `body` (a closure taking a `Ctx` plus the callback arguments and
    // returning a future) as a task on the runtime.
    macro_rules! action {
        ($on:ident, ($($arg:ident),*), $body:expr) => {{
            let ready = ready.clone();
            let rt = rt.clone();
            let weak = weak.clone();
            ui.$on(move |$($arg),*| match ready.get() {
                Some(c) => { rt.spawn(($body)(c.clone(), $($arg),*)); }
                None => say(&weak, "Not attached to the application yet"),
            });
        }};
    }

    action!(on_scan, (), |c: Ctx| async move {
        match command(&c, "network.wifi.scan", json!({})).await {
            Ok(_) => say(&c.ui, "Scan requested"),
            Err(e) => say(&c.ui, format!("Scan failed: {e}")),
        }
    });

    action!(on_disconnect, (), |c: Ctx| async move {
        match command(&c, "network.wifi.disconnect", json!({})).await {
            Ok(_) => say(&c.ui, "Disconnected"),
            Err(e) => say(&c.ui, format!("Disconnect failed: {e}")),
        }
    });

    action!(on_connect, (ssid, security, password, hidden), |c: Ctx, ssid: SharedString, security: SharedString, password: SharedString, hidden: bool| async move {
        let id = request_id();
        let payload = object(vec![
            ("ssid", Some(json!(ssid.to_string()))),
            ("security", Some(json!(security.to_string()))),
            ("password", opt_secret(&password).map(Value::String)),
            ("hidden", Some(json!(hidden))),
            ("request_id", Some(json!(id))),
        ]);
        activation(&c, ssid.to_string(), "network.wifi.connect", payload, id).await;
    });

    action!(on_connect_eap, (ssid, form, hidden), |c: Ctx, ssid: SharedString, form: EapForm, hidden: bool| async move {
        let eap = match eap(&form) {
            Ok(e) => e,
            Err(m) => { say(&c.ui, m); return; }
        };
        let id = request_id();
        let payload = json!({ "ssid": ssid.to_string(), "security": "eap", "eap": eap, "hidden": hidden, "request_id": id });
        activation(&c, ssid.to_string(), "network.wifi.connect", payload, id).await;
    });

    action!(on_activate, (uuid), |c: Ctx, uuid: SharedString| async move {
        let label = profile_label(&c, &uuid);
        let id = request_id();
        let payload = json!({ "uuid": uuid.to_string(), "request_id": id });
        activation(&c, label, "network.profiles.activate", payload, id).await;
    });

    action!(on_forget, (uuid), |c: Ctx, uuid: SharedString| async move {
        match command(&c, "network.profiles.forget", json!({ "uuid": uuid.to_string() })).await {
            Ok(_) => say(&c.ui, "Profile removed"),
            Err(e) => say(&c.ui, format!("Forget failed: {e}")),
        }
    });

    action!(on_set_autoconnect, (uuid, on), |c: Ctx, uuid: SharedString, on: bool| async move {
        if let Err(e) = command(&c, "network.profiles.update", json!({ "uuid": uuid.to_string(), "autoconnect": on })).await {
            say(&c.ui, format!("Update failed: {e}"));
        }
    });

    action!(on_edit_profile, (uuid, edit), |c: Ctx, uuid: SharedString, edit: ProfileEdit| async move {
        let mut fields = vec![
            ("uuid", Some(json!(uuid.to_string()))),
            ("password", opt_secret(&edit.password).map(Value::String)),
            ("ipv6_disabled", match edit.ipv6.as_str() {
                "disabled" => Some(json!(true)),
                "auto" => Some(json!(false)),
                _ => None,
            }),
        ];
        if !edit.eap.identity.trim().is_empty() {
            match eap(&edit.eap) {
                Ok(e) => fields.push(("eap", Some(e))),
                Err(m) => { say(&c.ui, m); return; }
            }
        }
        if edit.change_ipv4 {
            match ipv4(&edit.ipv4) {
                Ok(v) => fields.push(("ipv4", Some(v))),
                Err(m) => { say(&c.ui, m); return; }
            }
        }
        match command(&c, "network.profiles.update", object(fields)).await {
            Ok(_) => say(&c.ui, "Profile updated (reconnect to apply)"),
            Err(e) => say(&c.ui, format!("Update failed: {e}")),
        }
    });

    action!(on_apply_ethernet, (device, form), |c: Ctx, device: SharedString, form: Ipv4Form| async move {
        let v = match ipv4(&form) {
            Ok(v) => v,
            Err(m) => { say(&c.ui, m); return; }
        };
        set_busy(&c.ui, true);
        match command(&c, "network.ethernet.apply", json!({ "device": device.to_string(), "ipv4": v })).await {
            Ok(_) => say(&c.ui, format!("Applied to {device}")),
            Err(e) => say(&c.ui, format!("Apply to {device} failed: {e}")),
        }
        set_busy(&c.ui, false);
    });

    action!(on_hotspot_start, (ssid, password, band, channel), |c: Ctx, ssid: SharedString, password: SharedString, band: SharedString, channel: SharedString| async move {
        if password.chars().count() < 8 {
            say(&c.ui, "Hotspot password must be at least 8 characters");
            return;
        }
        let channel = match opt(&channel) {
            None => None,
            Some(ch) => match ch.parse::<u32>() {
                Ok(n) => Some(json!(n)),
                Err(_) => { say(&c.ui, "Channel must be a number"); return; }
            },
        };
        let payload = object(vec![
            ("ssid", Some(json!(ssid.to_string()))),
            ("password", Some(json!(password.to_string()))),
            ("band", Some(json!(band.to_string()))),
            ("channel", channel),
        ]);
        set_busy(&c.ui, true);
        match command(&c, "network.wifi.hotspot.start", payload).await {
            Ok(_) => say(&c.ui, format!("Hotspot \"{ssid}\" started")),
            Err(e) => say(&c.ui, format!("Hotspot failed: {e}")),
        }
        set_busy(&c.ui, false);
    });

    action!(on_hotspot_stop, (), |c: Ctx| async move {
        match command(&c, "network.wifi.hotspot.stop", json!({})).await {
            Ok(_) => say(&c.ui, "Hotspot stopped"),
            Err(e) => say(&c.ui, format!("Stop hotspot failed: {e}")),
        }
    });

    action!(on_refresh_permissions, (), |c: Ctx| async move { permissions(&c).await; });

    {
        let (log, clear, weak) = (log.clone(), clear.clone(), weak.clone());
        ui.on_clear_events(move || {
            let mut l = log.lock().unwrap();
            l.lines.clear();
            l.dirty = false;
            clear.notify_one();
            let _ = weak.upgrade_in_event_loop(|u| u.set_events(ModelRc::new(VecModel::default())));
        });
    }

    let shared2 = shared.clone();
    rt.spawn(async move {
        let at = match Attachment::attach(&address, Options::new()).await {
            Ok(at) => Arc::new(at),
            Err(e) => {
                say(&weak, format!("Cannot attach to {address}: {e}"));
                return;
            }
        };
        let _ = shared2.attachment.set(at.clone());
        let c = Ctx { at, unit, ui: weak, held, log, t0: Instant::now(), shared: shared2 };
        let _ = ready.set(c.clone());
        say(&c.ui, "Attached");
        tokio::spawn(redraw_events(c.clone()));
        tokio::spawn(events(c.clone()));
        tokio::spawn(follow(c.clone(), DEVICES));
        tokio::spawn(follow(c.clone(), SCAN));
        tokio::spawn(follow(c.clone(), STATUS));
        // The pictures the streams will replace, so that the window is not empty until they flow.
        tokio::spawn({
            let c = c.clone();
            async move {
                if let Ok(v) = ask(&c, DEVICES).await {
                    show_devices(&c, &v["devices"]);
                }
                if let Ok(v) = ask(&c, "network.access-points").await {
                    show_access_points(&c, &v["access_points"]);
                }
                profiles(&c).await;
                permissions(&c).await;
            }
        });
    });
    shared
}

/// Once the window has closed: the streams this panel started are stopped, and the attachment ended in
/// order. A stream someone else had started is left as it was.
pub async fn finish(shared: Arc<Shared>) {
    let Some(at) = shared.attachment.get() else { return };
    let started = std::mem::take(&mut *shared.started.lock().unwrap());
    for stream in started {
        let _ = tokio::time::timeout(Duration::from_secs(2), at.stop_stream(&shared.unit, &stream)).await;
    }
}

/// Sends a command and returns the line it was done with; a failure, a refusal of the Core or an
/// acknowledgement of a command still running is an error with its line.
async fn command(c: &Ctx, r#type: &str, payload: Value) -> Result<String, String> {
    let bytes = payload.to_string().into_bytes();
    drop(payload);
    let result = c.at.command(&c.unit, r#type, &bytes).await;
    // Profiles have no stream: whatever the command did, they are read again.
    let c2 = c.clone();
    tokio::spawn(async move { profiles(&c2).await });
    match result {
        Ok(ack) => match ack.outcome {
            2 => Ok(ack.line),
            1 => Err(format!("still running — {}", ack.line)),
            _ => Err(ack.line),
        },
        Err(e) => Err(e.to_string()),
    }
}

async fn ask(c: &Ctx, r#type: &str) -> Result<Value, String> {
    let answer = c.at.ask(&c.unit, r#type, b"").await.map_err(|e| e.to_string())?;
    serde_json::from_slice(&answer).map_err(|e| format!("{type} answered something that is not JSON: {e}", type = r#type))
}

/// Runs a connection, showing its steps as `network.status` brings them.
async fn activation(c: &Ctx, label: String, r#type: &str, payload: Value, id: String) {
    set_busy(&c.ui, true);
    c.held.lock().unwrap().pending.insert(id.clone(), label.clone());
    say(&c.ui, format!("{label}: connecting"));
    match command(c, r#type, payload).await {
        Ok(_) => say(&c.ui, format!("Connected to {label}")),
        Err(e) => say(&c.ui, format!("Connect to {label} failed: {e}")),
    }
    c.held.lock().unwrap().pending.remove(&id);
    set_busy(&c.ui, false);
}

fn profile_label(c: &Ctx, uuid: &str) -> String {
    let held = c.held.lock().unwrap();
    held.profiles
        .iter()
        .find(|p| p["uuid"] == uuid)
        .and_then(|p| p["id"].as_str())
        .unwrap_or(uuid)
        .to_string()
}

fn log(c: &Ctx, line: String) {
    let mut l = c.log.lock().unwrap();
    l.lines.push_front(format!("+{:>8.3}s  {line}", c.t0.elapsed().as_secs_f32()));
    l.lines.truncate(MAX_EVENTS);
    l.dirty = true;
}

/// Follows one stream for the life of the panel: subscribes first, starts it where it does not flow,
/// and subscribes again whenever the Core ends the delivery — the unit restarted, its Session ended.
async fn follow(c: Ctx, stream: &'static str) {
    loop {
        match c.at.subscribe_stream(&c.unit, stream).await {
            Ok(mut delivery) => {
                if !delivery.flowing {
                    match c.at.start_stream(&c.unit, stream).await {
                        Ok(_) => c.shared.started.lock().unwrap().push(stream.to_string()),
                        Err(e) => log(&c, format!("{stream} cannot be started: {e}")),
                    }
                }
                // The status is a stream of changes: what it is now is asked once the subscription
                // holds, and every frame at or below the answer's sequence is already in it.
                let mut seen = 0u64;
                if stream == STATUS {
                    match ask(&c, STATUS).await {
                        Ok(v) => {
                            seen = v["sequence"].as_u64().unwrap_or(0);
                            on_status(&c, &v);
                        }
                        Err(e) => log(&c, format!("{STATUS} cannot be asked: {e}")),
                    }
                }
                loop {
                    match delivery.next().await {
                        Ok(Some(frame)) => {
                            let Ok(v) = serde_json::from_slice::<Value>(&frame.payload) else { continue };
                            match stream {
                                DEVICES => show_devices(&c, &v["devices"]),
                                SCAN => show_access_points(&c, &v["access_points"]),
                                _ => {
                                    let sequence = v["sequence"].as_u64().unwrap_or(0);
                                    if sequence > seen {
                                        seen = sequence;
                                        on_status(&c, &v);
                                    }
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            log(&c, format!("{stream}: {e}"));
                            break;
                        }
                    }
                }
                log(&c, format!("{stream}: the delivery ended; subscribing again"));
            }
            Err(e) => log(&c, format!("{stream} cannot be subscribed to: {e}")),
        }
        sleep(AGAIN).await;
    }
}

fn on_status(c: &Ctx, v: &Value) {
    let phase = v["phase"].as_str().unwrap_or("?").to_string();
    let label = v["request_id"].as_str().and_then(|id| c.held.lock().unwrap().pending.get(id).cloned());
    let on = match v["connection"]["ssid"].as_str() {
        Some(s) => format!(" on {s}"),
        None => v["connection"]["device"].as_str().map(|d| format!(" on {d}")).unwrap_or_default(),
    };
    let error = v["error"]["code"].as_str().map(|e| format!(" ({e})")).unwrap_or_default();
    log(c, format!("status   #{} {phase}{on}{error}", v["sequence"]));
    match label {
        Some(label) => say(&c.ui, format!("{label}: {phase}{error}")),
        None if phase == "connected" || phase == "disconnected" => {
            let c = c.clone();
            tokio::spawn(async move { profiles(&c).await });
        }
        None => {}
    }
}

/// The Core's events about the unit: its state, its health, what it reports.
async fn events(c: Ctx) {
    let filter = Filter { subject_kind: "unit".into(), subject_identity: c.unit.clone(), ..Default::default() };
    let mut sub = match c.at.subscribe(filter).await {
        Ok(s) => s,
        Err(e) => {
            log(&c, format!("events cannot be subscribed to: {e}"));
            return;
        }
    };
    // The library names `Subscribed` and not what it carries, so the definitions are reached directly.
    use yoke_sdk::interface::subscribed::Carries;
    loop {
        match sub.next().await {
            Ok(Some(s)) => match s.carries {
                Some(Carries::Event(e)) => {
                    let detail: Value = serde_json::from_slice(&e.detail).unwrap_or(Value::Null);
                    let line = detail["line"].as_str().map(str::to_string).unwrap_or_else(|| {
                        let d = detail.to_string();
                        if d.len() > 160 { format!("{}…", &d[..160]) } else { d }
                    });
                    let class = if e.occurrence.is_empty() { String::new() } else { format!(" {}", e.occurrence) };
                    log(&c, format!("event    {} {}{class} [{}] {line}", e.seq, e.r#type, e.severity));
                    if e.occurrence == "network.job.finished" {
                        say(&c.ui, line);
                    }
                }
                Some(Carries::Overflow(_)) => log(&c, "events: the panel fell behind and some were dropped".into()),
                _ => {}
            },
            Ok(None) => break,
            Err(e) => {
                log(&c, format!("events: {e}"));
                break;
            }
        }
    }
}

async fn redraw_events(c: Ctx) {
    let mut tick = interval(EVENTS_REDRAW);
    loop {
        tick.tick().await;
        let rows = {
            let mut l = c.log.lock().unwrap();
            if !l.dirty {
                continue;
            }
            l.dirty = false;
            l.lines.iter().map(|s| SharedString::from(s.as_str())).collect::<Vec<_>>()
        };
        let _ = c.ui.upgrade_in_event_loop(move |u| u.set_events(ModelRc::new(VecModel::from(rows))));
    }
}

async fn permissions(c: &Ctx) {
    match ask(c, "network.permissions").await {
        Ok(v) => {
            let rows: Vec<PermRow> = v["permissions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| PermRow { action: s(&p["action"]).into(), result: s(&p["result"]).into() })
                .collect();
            let _ = c.ui.upgrade_in_event_loop(move |u| u.set_permissions(ModelRc::new(VecModel::from(rows))));
        }
        Err(e) => say(&c.ui, format!("Permissions unavailable: {e}")),
    }
}

async fn profiles(c: &Ctx) {
    match ask(c, "network.profiles").await {
        Ok(v) => {
            let list = v["profiles"].as_array().cloned().unwrap_or_default();
            let rows: Vec<ProfileRow> = list
                .iter()
                .map(|p| ProfileRow {
                    uuid: s(&p["uuid"]).into(),
                    id: s(&p["id"]).into(),
                    kind: s(&p["kind"]).into(),
                    ssid: s(&p["ssid"]).into(),
                    security: s(&p["security"]).into(),
                    autoconnect: p["autoconnect"].as_bool().unwrap_or(false),
                    last_used: p["last_used_unix"].as_i64().map(ago).unwrap_or_default().into(),
                })
                .collect();
            c.held.lock().unwrap().profiles = list;
            let _ = c.ui.upgrade_in_event_loop(move |u| u.set_profiles(ModelRc::new(VecModel::from(rows))));
            // A profile saved or forgotten changes which access point is known.
            let aps = c.held.lock().unwrap().access_points.clone();
            show_access_points(c, &Value::Array(aps));
        }
        Err(e) => say(&c.ui, format!("Profiles unavailable: {e}")),
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn ago(unix: i64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let d = (now - unix).max(0);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", d / 60),
        3600..=86_399 => format!("{} h ago", d / 3600),
        _ => format!("{} d ago", d / 86_400),
    }
}

fn show_devices(c: &Ctx, devices: &Value) {
    let devices = devices.as_array().cloned().unwrap_or_default();
    let eth_names: Vec<SharedString> = devices
        .iter()
        .filter(|d| d["kind"] == "ethernet")
        .map(|d| s(&d["name"]).into())
        .collect();
    let rows: Vec<DeviceRow> = devices
        .iter()
        .filter(|d| d["kind"] != "loopback")
        .map(|d| DeviceRow {
            name: s(&d["name"]).into(),
            kind: s(&d["kind"]).into(),
            state: s(&d["state"]).into(),
            link: if d["carrier"].as_bool().unwrap_or(false) { "up" } else { "down" }.into(),
            mac: s(&d["mac"]).into(),
            ssid: s(&d["ssid"]).into(),
            ip4: s(&d["ip4"]).into(),
            ip6: s(&d["ip6"]).into(),
            gw: s(&d["gw"]).into(),
            dns: d["dns"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", ").into(),
            speed: d["speed_mbps"].as_u64().map(|v| format!("{v} Mb/s")).unwrap_or_default().into(),
        })
        .collect();
    c.held.lock().unwrap().devices = devices;
    let _ = c.ui.upgrade_in_event_loop(move |ui| {
        if ui.get_message() == "Starting..." {
            ui.set_message("Ready".into());
        }
        if ui.get_eth_device().is_empty() {
            if let Some(first) = eth_names.first() {
                ui.set_eth_device(first.clone());
            }
        }
        ui.set_devices(ModelRc::new(VecModel::from(rows)));
        ui.set_eth_devices(ModelRc::new(VecModel::from(eth_names)));
    });
}

/// One row per SSID — several BSSIDs share one: the strongest, but never hiding the one in use. A
/// hidden access point has no SSID and is not shown.
fn show_access_points(c: &Ctx, aps: &Value) {
    let aps = aps.as_array().cloned().unwrap_or_default();
    let (saved, rows) = {
        let mut held = c.held.lock().unwrap();
        held.access_points = aps.clone();
        let saved: HashMap<String, String> = held
            .profiles
            .iter()
            .filter(|p| p["kind"] == "wifi")
            .filter_map(|p| Some((p["ssid"].as_str()?.to_string(), s(&p["uuid"]))))
            .collect();
        (saved, aps)
    };
    let mut best: HashMap<String, Value> = HashMap::new();
    for ap in rows {
        let ssid = s(&ap["ssid"]);
        if ssid.is_empty() {
            continue;
        }
        let used = |v: &Value| v["in_use"].as_bool().unwrap_or(false);
        let pct = |v: &Value| v["signal_pct"].as_u64().unwrap_or(0);
        match best.get(&ssid) {
            Some(cur) if used(cur) || (!used(&ap) && pct(cur) >= pct(&ap)) => {}
            _ => {
                best.insert(ssid, ap);
            }
        }
    }
    let mut aps: Vec<Value> = best.into_values().collect();
    aps.sort_by(|a, b| {
        let used = |v: &Value| v["in_use"].as_bool().unwrap_or(false);
        let pct = |v: &Value| v["signal_pct"].as_u64().unwrap_or(0);
        used(b).cmp(&used(a)).then(pct(b).cmp(&pct(a)))
    });
    let rows: Vec<ApRow> = aps
        .iter()
        .map(|a| {
            let ssid = s(&a["ssid"]);
            ApRow {
                saved_uuid: saved.get(&ssid).cloned().unwrap_or_default().into(),
                ssid: ssid.into(),
                signal: a["signal_pct"].as_i64().unwrap_or(0) as i32,
                security: s(&a["security"]).into(),
                channel: a["channel"].as_i64().unwrap_or(0) as i32,
                in_use: a["in_use"].as_bool().unwrap_or(false),
            }
        })
        .collect();
    let _ = c.ui.upgrade_in_event_loop(move |ui| ui.set_aps(ModelRc::new(VecModel::from(rows))));
}
