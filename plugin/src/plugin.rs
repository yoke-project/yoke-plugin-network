//! The network Plugin: what the host's network manager knows and does, as questions, commands, streams
//! and occurrences.
//!
//! - **Questions** read: the status, the devices, the access points the manager has seen, the saved
//!   profiles, what this account may do. Each is answered, or failed with a code and a message.
//! - **Commands** act: scan, connect, disconnect, the hotspot, the profiles, an Ethernet address. Each is
//!   acknowledged: `Done`, `Failed` with `<code>: <message>`, or `Accepted` when it is still running after
//!   [`COMMAND_WAIT`], and then `network.job.finished` says how it ended.
//! - **Streams** follow: `network.status` every change of the connection and every step of a connection
//!   being made; `network.devices` the devices, whole, at every change; `network.scan` the access points
//!   in range, and the manager is asked to scan only while it flows.
//! - **The status carries a sequence.** `network.status` is a question and a stream of the same record: a
//!   client that subscribes and then asks holds the present state, and drops what the stream brings at or
//!   below the sequence it was answered with.
//! - **Every occurrence carries its facts as JSON in its detail**, which is what an interface client
//!   receives; the line is for the log.
//! - **A secret is read and handed on, never written**: no passphrase reaches a log line, an
//!   acknowledgement or a failure's message, and a payload that does not parse is described by where it
//!   fails, not by what it holds.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use yoke_sdk::plugin::{Capability, Command, Declaration, Event, Object, Outcome, Question, Severity, Stream, Unit};

use crate::backend::types as bt;
use crate::backend::{BackendEvent, NetworkBackend, NetworkError};

pub const PLUGIN: &str = "com.yoke.network";
/// The format every answer and every sample states as `schema`.
pub const SCHEMA: u32 = 1;

/// The connection as it stands, with its sequence.
pub const STATUS: &str = "network.status";
/// The devices the manager knows.
pub const DEVICES: &str = "network.devices";
/// The access points the manager has seen.
pub const ACCESS_POINTS: &str = "network.access-points";
/// The saved profiles.
pub const PROFILES: &str = "network.profiles";
/// What this account may do with the manager.
pub const PERMISSIONS: &str = "network.permissions";
pub const QUERIES: [&str; 5] = [STATUS, DEVICES, ACCESS_POINTS, PROFILES, PERMISSIONS];

pub const WIFI_SCAN: &str = "network.wifi.scan";
pub const WIFI_CONNECT: &str = "network.wifi.connect";
pub const WIFI_DISCONNECT: &str = "network.wifi.disconnect";
pub const HOTSPOT_START: &str = "network.wifi.hotspot.start";
pub const HOTSPOT_STOP: &str = "network.wifi.hotspot.stop";
pub const PROFILE_ACTIVATE: &str = "network.profiles.activate";
pub const PROFILE_UPDATE: &str = "network.profiles.update";
pub const PROFILE_FORGET: &str = "network.profiles.forget";
pub const ETHERNET_APPLY: &str = "network.ethernet.apply";
pub const COMMANDS: [&str; 9] = [
    WIFI_SCAN,
    WIFI_CONNECT,
    WIFI_DISCONNECT,
    HOTSPOT_START,
    HOTSPOT_STOP,
    PROFILE_ACTIVATE,
    PROFILE_UPDATE,
    PROFILE_FORGET,
    ETHERNET_APPLY,
];

/// The access points in range, while it flows.
pub const SCAN: &str = "network.scan";
pub const STREAMS: [&str; 3] = [STATUS, DEVICES, SCAN];

/// The host came onto a network.
pub const CONNECTED: &str = "network.connected";
/// The host is on no network any more.
pub const DISCONNECTED: &str = "network.disconnected";
/// A command acknowledged as still running finished.
pub const JOB_FINISHED: &str = "network.job.finished";
pub const OCCURRENCES: [&str; 3] = [CONNECTED, DISCONNECTED, JOB_FINISHED];

/// How long a command waits for the manager before it is acknowledged as accepted and still running.
pub const COMMAND_WAIT: Duration = Duration::from_secs(25);

/// One capability per question, command, stream and occurrence: an operator may grant reading and
/// withhold acting, and grant a scan without granting a connection.
pub fn declaration() -> Declaration {
    let answer = |q: &&str| Capability { name: format!("query.{q}.answer"), governs: Object::Query(q.to_string()) };
    let accept = |c: &&str| Capability { name: format!("command.{c}.accept"), governs: Object::Command(c.to_string()) };
    let publish = |s: &&str| Capability { name: format!("stream.{s}.publish"), governs: Object::Stream(s.to_string()) };
    let report = |o: &&str| Capability { name: format!("event.{o}.report"), governs: Object::Occurrence(o.to_string()) };
    Declaration {
        id: PLUGIN.into(),
        queries: QUERIES.iter().map(|q| q.to_string()).collect(),
        commands: COMMANDS.iter().map(|c| c.to_string()).collect(),
        streams: vec![
            // A change of the connection is not one a client may miss.
            Stream { id: STATUS.into(), tolerates_loss: false, tolerates_reorder: false, max_frame: 0 },
            // Each of these two is the whole picture again, so a lost one is made good by the next.
            Stream { id: DEVICES.into(), tolerates_loss: true, tolerates_reorder: false, max_frame: 0 },
            Stream { id: SCAN.into(), tolerates_loss: true, tolerates_reorder: false, max_frame: 0 },
        ],
        occurrences: OCCURRENCES.iter().map(|o| o.to_string()).collect(),
        capabilities: QUERIES
            .iter()
            .map(answer)
            .chain(COMMANDS.iter().map(accept))
            .chain(STREAMS.iter().map(publish))
            .chain(OCCURRENCES.iter().map(report))
            .collect(),
        ..Default::default()
    }
}

/// What went wrong, in the Plugin's own terms.
#[derive(Debug)]
pub enum Error {
    /// The payload is not what the question or the command takes.
    Invalid(String),
    /// The manager's answer.
    Network(NetworkError),
}

impl From<NetworkError> for Error {
    fn from(e: NetworkError) -> Self {
        Error::Network(e)
    }
}

/// The code a failure is reported under.
pub fn code(e: &Error) -> &'static str {
    match e {
        Error::Invalid(_) => "invalid",
        Error::Network(e) => match e {
            NetworkError::Unavailable(_) => "unavailable",
            NetworkError::PermissionDenied => "permission_denied",
            NetworkError::Unsupported(_) => "unsupported",
            NetworkError::SsidNotFound => "ssid_not_found",
            NetworkError::AuthFailed => "auth_failed",
            NetworkError::NotFound => "not_found",
            NetworkError::Invalid(_) => "invalid",
            NetworkError::Dbus(_) | NetworkError::Other(_) => "backend",
        },
    }
}

/// The message beside the code. The manager's own words are passed on; none of them is a secret, since
/// the manager is handed secrets and never says them back.
pub fn message(e: &Error) -> String {
    match e {
        Error::Invalid(m) => m.clone(),
        Error::Network(e) => e.to_string(),
    }
}

/// Reads a payload, an empty one as `{}`. A payload that does not parse is described by the kind of the
/// fault and where it is, never by the text that failed: the text may be a passphrase.
fn input<T: DeserializeOwned>(what: &str, payload: &[u8]) -> Result<T, Error> {
    let payload = if payload.iter().all(u8::is_ascii_whitespace) { b"{}".as_slice() } else { payload };
    serde_json::from_slice(payload).map_err(|e| {
        let kind = match e.classify() {
            serde_json::error::Category::Data => "a field is missing, unknown or of the wrong type",
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => "it is not JSON",
            serde_json::error::Category::Io => "it cannot be read",
        };
        Error::Invalid(format!("the payload is not what {what} takes: {kind}, at line {} column {}", e.line(), e.column()))
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NoInput {}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceInput {
    pub device: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EapInput {
    /// `peap`, `ttls` or `tls`.
    pub method: String,
    pub identity: String,
    pub password: Option<String>,
    pub anonymous_identity: Option<String>,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_password: Option<String>,
    /// `mschapv2` or `pap`.
    pub phase2_auth: Option<String>,
}

impl From<EapInput> for bt::EapMaterial {
    fn from(e: EapInput) -> Self {
        bt::EapMaterial {
            method: e.method,
            identity: e.identity,
            password: e.password,
            anonymous_identity: e.anonymous_identity,
            ca_cert_path: e.ca_cert_path,
            client_cert_path: e.client_cert_path,
            private_key_path: e.private_key_path,
            private_key_password: e.private_key_password,
            phase2_auth: e.phase2_auth,
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectInput {
    pub ssid: String,
    /// The access point's, as `network.access-points` says it — `open`, `wep`, `wpa-psk`, `wpa2-psk`,
    /// `wpa3-psk`, `wpa-eap` — or `psk` for WPA2 and `eap` for 802.1X.
    pub security: String,
    pub password: Option<String>,
    pub eap: Option<EapInput>,
    /// The network does not announce itself.
    #[serde(default)]
    pub hidden: bool,
    #[serde(default = "yes")]
    pub save_profile: bool,
    pub device: Option<String>,
    /// What the steps of this connection carry on `network.status`; the command's identity when absent.
    pub request_id: Option<String>,
}

fn band() -> String {
    "2.4".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotInput {
    pub ssid: String,
    pub password: String,
    /// `2.4` or `5`.
    #[serde(default = "band")]
    pub band: String,
    pub channel: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateInput {
    pub uuid: String,
    pub device: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv4Input {
    /// `auto` or `manual`.
    pub method: String,
    pub address: Option<String>,
    pub prefix: Option<u8>,
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

impl From<Ipv4Input> for bt::Ipv4Config {
    fn from(p: Ipv4Input) -> Self {
        bt::Ipv4Config { method: p.method, address: p.address, prefix: p.prefix, gateway: p.gateway, dns: p.dns }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateInput {
    pub uuid: String,
    pub autoconnect: Option<bool>,
    pub password: Option<String>,
    pub eap: Option<EapInput>,
    pub ipv4: Option<Ipv4Input>,
    pub ipv6_disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UuidInput {
    pub uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthernetInput {
    pub device: String,
    pub ipv4: Ipv4Input,
}

fn security(s: &str) -> Result<bt::ApSecurity, Error> {
    match s {
        "open" => Ok(bt::ApSecurity::Open),
        "wep" => Ok(bt::ApSecurity::Wep),
        "wpa-psk" => Ok(bt::ApSecurity::WpaPsk),
        "psk" | "wpa2-psk" => Ok(bt::ApSecurity::Wpa2Psk),
        "wpa3-psk" => Ok(bt::ApSecurity::Wpa3Psk),
        "eap" | "wpa-eap" => Ok(bt::ApSecurity::WpaEap),
        _ => Err(Error::Invalid("security is open, wep, wpa-psk, wpa2-psk, wpa3-psk, wpa-eap, psk or eap".into())),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn device_json(d: &bt::Device) -> Value {
    json!({
        "name": d.name, "mac": d.mac, "kind": d.kind.as_str(), "state": d.state.as_str(), "carrier": d.carrier,
        "ssid": d.ssid, "ip4": d.ip4, "ip6": d.ip6, "gw": d.gw, "dns": d.dns, "speed_mbps": d.speed_mbps,
    })
}

fn access_point_json(a: &bt::AccessPoint) -> Value {
    json!({
        "bssid": a.bssid, "ssid": a.ssid, "signal_dbm": a.signal_dbm, "signal_pct": a.signal_pct,
        "frequency_mhz": a.frequency_mhz, "channel": a.channel, "security": a.security.as_str(),
        "in_use": a.in_use, "hidden": a.hidden, "last_seen_ms": a.last_seen_ms,
    })
}

fn profile_json(p: &bt::Profile) -> Value {
    json!({
        "uuid": p.uuid, "id": p.id, "kind": p.kind.as_str(), "ssid": p.ssid,
        "security": p.security.map(|s| s.as_str()), "autoconnect": p.autoconnect, "last_used_unix": p.last_used_unix,
    })
}

fn connection_json(c: &bt::ConnectionInfo) -> Value {
    json!({ "ssid": c.ssid, "device": c.device, "ip4": c.ip4, "ip6": c.ip6, "gw": c.gw, "dns": c.dns, "signal_dbm": c.signal_dbm })
}

/// The device the host is on a network through: an activated Wi-Fi or Ethernet device, one with a
/// gateway before one without.
fn primary(devices: &[bt::Device]) -> Option<&bt::Device> {
    let on = |d: &&bt::Device| {
        d.state == bt::DeviceState::Activated && matches!(d.kind, bt::DeviceKind::Wifi | bt::DeviceKind::Ethernet)
    };
    devices.iter().filter(on).find(|d| d.gw.is_some()).or_else(|| devices.iter().find(on))
}

/// The connection as it stands, from the devices.
fn standing(devices: &[bt::Device]) -> Value {
    match primary(devices) {
        Some(d) => json!({
            "phase": "connected",
            "connection": { "ssid": d.ssid, "device": d.name, "kind": d.kind.as_str(), "ip4": d.ip4, "ip6": d.ip6, "gw": d.gw, "dns": d.dns },
        }),
        None => json!({ "phase": "disconnected", "connection": null }),
    }
}

/// What the Plugin does on the Session, behind a trait so that a test can stand in for the Core.
pub trait Acts {
    fn answer(&self, q: &Question, payload: Vec<u8>) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    fn fail(&self, q: &Question, code: &str, message: &str) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    fn ack(&self, c: &Command, outcome: Outcome, line: &str) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    /// An occurrence, its facts as JSON in its detail.
    fn report(&self, occurrence: &str, severity: u8, line: &str, detail: Value) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
    fn emit(&self, stream: &str, payload: Vec<u8>) -> impl std::future::Future<Output = Result<(), yoke_sdk::base::Error>>;
}

impl Acts for Unit {
    async fn answer(&self, q: &Question, payload: Vec<u8>) -> Result<(), yoke_sdk::base::Error> {
        Unit::answer(self, q, payload).await
    }
    async fn fail(&self, q: &Question, code: &str, message: &str) -> Result<(), yoke_sdk::base::Error> {
        Unit::fail(self, &q.id, code, message).await
    }
    async fn ack(&self, c: &Command, outcome: Outcome, line: &str) -> Result<(), yoke_sdk::base::Error> {
        Unit::ack(self, c, outcome, line).await
    }
    async fn report(&self, occurrence: &str, severity: u8, line: &str, detail: Value) -> Result<(), yoke_sdk::base::Error> {
        Unit::report(self, occurrence, Some(Severity::of(severity)), line, detail.to_string().into_bytes()).await
    }
    async fn emit(&self, stream: &str, payload: Vec<u8>) -> Result<(), yoke_sdk::base::Error> {
        Unit::emit(self, stream, payload).await
    }
}

/// The connection as last said, and what counts it.
struct Status {
    sequence: u64,
    /// The record without its sequence and its time, so that two of them compare.
    body: Value,
    at: u64,
}

impl Status {
    fn record(&self) -> Value {
        let mut v = json!({ "schema": SCHEMA, "sequence": self.sequence, "at": self.at });
        if let (Some(v), Some(body)) = (v.as_object_mut(), self.body.as_object()) {
            v.extend(body.clone());
        }
        v
    }
}

pub type Backend = Result<Arc<dyn NetworkBackend>, NetworkError>;

/// The Plugin's state: the manager, the status and its sequence, and which streams flow.
pub struct Net {
    pub backend: Backend,
    status: Mutex<Status>,
    /// The devices as last emitted, so that an unchanged picture is not emitted again.
    devices: Mutex<String>,
    progress: mpsc::Sender<bt::ProgressUpdate>,
    status_flows: AtomicBool,
    devices_flow: AtomicBool,
    scan_flows: AtomicBool,
}

impl Net {
    /// The second value brings the steps of a connection being made; whoever holds it hands each to
    /// [`Net::on_progress`].
    pub fn new(backend: Backend) -> (Arc<Net>, mpsc::Receiver<bt::ProgressUpdate>) {
        let (progress, steps) = mpsc::channel(64);
        let net = Net {
            backend,
            status: Mutex::new(Status { sequence: 0, body: json!({ "phase": "unknown", "connection": null }), at: now_ms() }),
            devices: Mutex::new(String::new()),
            progress,
            status_flows: AtomicBool::new(false),
            devices_flow: AtomicBool::new(false),
            scan_flows: AtomicBool::new(false),
        };
        (Arc::new(net), steps)
    }

    fn manager(&self) -> Result<&dyn NetworkBackend, Error> {
        match &self.backend {
            Ok(b) => Ok(b.as_ref()),
            Err(e) => Err(Error::Network(NetworkError::Unavailable(e.to_string()))),
        }
    }

    pub fn scanning(&self) -> bool {
        self.scan_flows.load(Ordering::Relaxed)
    }

    fn flag(&self, stream: &str) -> Option<&AtomicBool> {
        match stream {
            STATUS => Some(&self.status_flows),
            DEVICES => Some(&self.devices_flow),
            SCAN => Some(&self.scan_flows),
            _ => None,
        }
    }

    /// Sets the status to a body, counting it when it differs from the last, and returns the record to
    /// emit and whether the host went on or off a network; nothing when it is what was last said.
    fn set(&self, body: Value) -> Option<(Value, Option<bool>)> {
        let mut status = self.status.lock().unwrap();
        if status.body == body {
            return None;
        }
        let was = status.body["phase"] == "connected";
        let is = body["phase"] == "connected";
        let known = status.body["phase"] != "unknown";
        status.sequence += 1;
        status.body = body;
        status.at = now_ms();
        Some((status.record(), (known && was != is).then_some(is)))
    }

    /// Reads the devices and says the status again where it changed. The first reading counts as
    /// sequence 1 and reports nothing: the Plugin did not see the host come onto its network.
    pub async fn refresh(&self, u: &impl Acts) -> Result<(), yoke_sdk::base::Error> {
        let Ok(b) = &self.backend else { return Ok(()) };
        let Ok(devices) = b.list_devices().await else { return Ok(()) };
        let mut first = Ok(());
        if let Some((record, moved)) = self.set(standing(&devices)) {
            if self.status_flows.load(Ordering::Relaxed) {
                first = u.emit(STATUS, record.to_string().into_bytes()).await;
            }
            match moved {
                Some(true) => {
                    let d = primary(&devices);
                    let on = d.map(|d| match &d.ssid {
                        Some(ssid) => format!("{} on {ssid}", d.name),
                        None => d.name.clone(),
                    });
                    let line = format!("connected: {}", on.unwrap_or_default());
                    let detail = json!({
                        "schema": SCHEMA, "line": line, "device": d.map(|d| d.name.clone()),
                        "kind": d.map(|d| d.kind.as_str()), "ssid": d.and_then(|d| d.ssid.clone()),
                    });
                    first = first.and(u.report(CONNECTED, 10, &line, detail).await);
                }
                Some(false) => {
                    let line = "on no network";
                    first = first.and(u.report(DISCONNECTED, 30, line, json!({ "schema": SCHEMA, "line": line })).await)
                }
                None => {}
            }
        }
        if self.devices_flow.load(Ordering::Relaxed) {
            first = first.and(self.emit_devices(u, &devices, false).await);
        }
        first
    }

    async fn emit_devices(&self, u: &impl Acts, devices: &[bt::Device], always: bool) -> Result<(), yoke_sdk::base::Error> {
        let picture = Value::Array(devices.iter().map(device_json).collect()).to_string();
        {
            let mut last = self.devices.lock().unwrap();
            if !always && *last == picture {
                return Ok(());
            }
            last.clone_from(&picture);
        }
        let devices: Value = serde_json::from_str(&picture).unwrap_or(Value::Null);
        u.emit(DEVICES, json!({ "schema": SCHEMA, "at": now_ms(), "devices": devices }).to_string().into_bytes()).await
    }

    /// The access points the manager has seen, as one sample of `network.scan`.
    pub async fn emit_scan(&self, u: &impl Acts) -> Result<(), yoke_sdk::base::Error> {
        let Ok(b) = &self.backend else { return Ok(()) };
        let Ok(aps) = b.list_access_points(None).await else { return Ok(()) };
        let aps: Vec<Value> = aps.iter().map(access_point_json).collect();
        u.emit(SCAN, json!({ "schema": SCHEMA, "at": now_ms(), "access_points": aps }).to_string().into_bytes()).await
    }

    /// Asks the manager to scan again, while `network.scan` flows.
    pub async fn rescan(&self) {
        if let Ok(b) = &self.backend {
            let _ = b.request_scan(None).await;
        }
    }

    /// A stream was activated: it is given the present picture at once, so that its first sample is not
    /// the next change, and a scan is asked for where it is the access points.
    pub async fn activated(&self, u: &impl Acts, stream: &str) -> Result<(), yoke_sdk::base::Error> {
        let Some(flag) = self.flag(stream) else { return Ok(()) };
        flag.store(true, Ordering::Relaxed);
        match stream {
            STATUS => {
                let record = self.status.lock().unwrap().record();
                u.emit(STATUS, record.to_string().into_bytes()).await
            }
            DEVICES => match &self.backend {
                Ok(b) => match b.list_devices().await {
                    Ok(devices) => self.emit_devices(u, &devices, true).await,
                    Err(_) => Ok(()),
                },
                Err(_) => Ok(()),
            },
            _ => {
                self.rescan().await;
                self.emit_scan(u).await
            }
        }
    }

    pub fn stopped(&self, stream: &str) {
        if let Some(flag) = self.flag(stream) {
            flag.store(false, Ordering::Relaxed);
        }
    }

    /// What the manager said changed. Returns whether the access points did, which the caller emits at
    /// its own pace: a signal strength moves many times a second.
    pub async fn on_backend_event(&self, u: &impl Acts, ev: &BackendEvent) -> Result<bool, yoke_sdk::base::Error> {
        match ev {
            BackendEvent::DevicesChanged | BackendEvent::StateChanged => self.refresh(u).await.map(|_| false),
            BackendEvent::AccessPointsChanged => Ok(self.scanning()),
            BackendEvent::Progress(p) => self.on_progress(u, p).await.map(|_| false),
            BackendEvent::Property { .. } => Ok(false),
        }
    }

    /// One step of a connection being made: it becomes the status, with the request it belongs to.
    pub async fn on_progress(&self, u: &impl Acts, p: &bt::ProgressUpdate) -> Result<(), yoke_sdk::base::Error> {
        let error = p.error_code.as_ref().map(|c| json!({ "code": c, "detail": p.error_detail }));
        let body = json!({
            "phase": p.phase.as_str(),
            "request_id": p.request_id,
            "connection": p.connection.as_ref().map(connection_json),
            "error": error,
        });
        match self.set(body) {
            Some((record, _)) if self.status_flows.load(Ordering::Relaxed) => u.emit(STATUS, record.to_string().into_bytes()).await,
            _ => Ok(()),
        }
    }

    /// Answers a question's payload.
    pub async fn answer(&self, query: &str, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let v = match query {
            STATUS => {
                let _: NoInput = input(query, payload)?;
                self.manager()?;
                self.status.lock().unwrap().record()
            }
            DEVICES => {
                let _: NoInput = input(query, payload)?;
                let devices = self.manager()?.list_devices().await?;
                json!({ "schema": SCHEMA, "devices": devices.iter().map(device_json).collect::<Vec<_>>() })
            }
            ACCESS_POINTS => {
                let i: DeviceInput = input(query, payload)?;
                let aps = self.manager()?.list_access_points(i.device.as_deref()).await?;
                json!({ "schema": SCHEMA, "access_points": aps.iter().map(access_point_json).collect::<Vec<_>>() })
            }
            PROFILES => {
                let _: NoInput = input(query, payload)?;
                let profiles = self.manager()?.list_profiles().await?;
                json!({ "schema": SCHEMA, "profiles": profiles.iter().map(profile_json).collect::<Vec<_>>() })
            }
            PERMISSIONS => {
                let _: NoInput = input(query, payload)?;
                let permissions = self.manager()?.permissions().await?;
                let permissions: Vec<Value> = permissions.iter().map(|p| json!({ "action": p.action, "result": p.result })).collect();
                json!({ "schema": SCHEMA, "permissions": permissions })
            }
            other => return Err(Error::Invalid(format!("{other} is not a question of {PLUGIN}"))),
        };
        Ok(v.to_string().into_bytes())
    }

    /// Carries a command out, and returns the line it is acknowledged with. The line names what was done
    /// and never what it was done with.
    pub async fn act(&self, command: &str, id: &str, payload: &[u8]) -> Result<String, Error> {
        match command {
            WIFI_SCAN => {
                let i: DeviceInput = input(command, payload)?;
                self.manager()?.request_scan(i.device.as_deref()).await?;
                Ok("a scan was asked for".into())
            }
            WIFI_CONNECT => {
                let i: ConnectInput = input(command, payload)?;
                let security = security(&i.security)?;
                if i.ssid.is_empty() {
                    return Err(Error::Invalid("ssid is empty".into()));
                }
                let b = self.manager()?;
                let ssid = i.ssid.clone();
                let request = bt::WifiConnectRequest {
                    request_id: i.request_id.unwrap_or_else(|| id.to_string()),
                    ssid: i.ssid,
                    security,
                    password: i.password,
                    eap: i.eap.map(Into::into),
                    hidden: i.hidden,
                    save_profile: i.save_profile,
                    device: i.device,
                };
                let uuid = b.connect_wifi(request, self.progress.clone()).await?;
                Ok(format!("connected to {ssid} (profile {uuid})"))
            }
            WIFI_DISCONNECT => {
                let i: DeviceInput = input(command, payload)?;
                self.manager()?.disconnect_wifi(i.device.as_deref()).await?;
                Ok("disconnected".into())
            }
            HOTSPOT_START => {
                let i: HotspotInput = input(command, payload)?;
                let ssid = i.ssid.clone();
                let request = bt::HotspotRequest { ssid: i.ssid, password: i.password, band: i.band, channel: i.channel };
                let uuid = self.manager()?.start_hotspot(request).await?;
                Ok(format!("the hotspot {ssid} is up (profile {uuid})"))
            }
            HOTSPOT_STOP => {
                let _: NoInput = input(command, payload)?;
                self.manager()?.stop_hotspot().await?;
                Ok("the hotspot is down".into())
            }
            PROFILE_ACTIVATE => {
                let i: ActivateInput = input(command, payload)?;
                let request = i.request_id.unwrap_or_else(|| id.to_string());
                let uuid = self.manager()?.activate_profile(&i.uuid, i.device.as_deref(), request, self.progress.clone()).await?;
                Ok(format!("profile {uuid} is active"))
            }
            PROFILE_UPDATE => {
                let i: UpdateInput = input(command, payload)?;
                let patch = bt::ProfilePatch {
                    autoconnect: i.autoconnect,
                    password: i.password,
                    eap: i.eap.map(Into::into),
                    ipv4: i.ipv4.map(Into::into),
                    ipv6_disabled: i.ipv6_disabled,
                };
                self.manager()?.update_profile(&i.uuid, patch).await?;
                Ok(format!("profile {} updated", i.uuid))
            }
            PROFILE_FORGET => {
                let i: UuidInput = input(command, payload)?;
                self.manager()?.forget_profile(&i.uuid).await?;
                Ok(format!("profile {} forgotten", i.uuid))
            }
            ETHERNET_APPLY => {
                let i: EthernetInput = input(command, payload)?;
                let uuid = self.manager()?.apply_ethernet(&i.device, i.ipv4.into()).await?;
                Ok(format!("{} configured (profile {uuid})", i.device))
            }
            other => Err(Error::Invalid(format!("{other} is not a command of {PLUGIN}"))),
        }
    }
}

/// Answers a question or carries a command out, and says so on the Session.
pub async fn handle(u: &impl Acts, event: &Event, net: &Net) -> Result<(), yoke_sdk::base::Error> {
    match event {
        Event::Question(q) if QUERIES.contains(&q.r#type.as_str()) => match net.answer(&q.r#type, &q.payload).await {
            Ok(answer) => u.answer(q, answer).await,
            Err(e) => u.fail(q, code(&e), &message(&e)).await,
        },
        Event::Command(c) if COMMANDS.contains(&c.r#type.as_str()) => {
            let job = net.act(&c.r#type, &c.id, &c.payload);
            tokio::pin!(job);
            match tokio::time::timeout(COMMAND_WAIT, &mut job).await {
                Ok(Ok(line)) => u.ack(c, Outcome::Done, &line).await,
                Ok(Err(e)) => u.ack(c, Outcome::Failed, &format!("{}: {}", code(&e), message(&e))).await,
                Err(_) => {
                    let line = format!("still running after {} s: {JOB_FINISHED} says how it ends", COMMAND_WAIT.as_secs());
                    u.ack(c, Outcome::Accepted, &line).await?;
                    let (line, severity, failed) = match job.await {
                        Ok(line) => (line, 10, None),
                        Err(e) => (format!("{}: {}", code(&e), message(&e)), 50, Some(code(&e))),
                    };
                    let detail = json!({ "schema": SCHEMA, "line": line, "command": c.r#type, "command_id": c.id, "failed": failed });
                    u.report(JOB_FINISHED, severity, &line, detail).await
                }
            }
        }
        _ => Ok(()),
    }
}
