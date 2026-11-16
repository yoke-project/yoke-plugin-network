//! The Plugin against a manager that is not there: a fake backend stands in for NetworkManager, and a
//! recorder for the Core.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use network::backend::types::*;
use network::backend::{BackendEvent, NetworkBackend, NetworkError};
use network::plugin::*;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use yoke_sdk::plugin::{Command, Event, Outcome, Question};

const SECRET: &str = "correct horse battery staple";

fn device(name: &str, kind: DeviceKind, state: DeviceState, gw: Option<&str>) -> Device {
    Device {
        name: name.into(),
        mac: "00:11:22:33:44:55".into(),
        kind,
        state,
        carrier: true,
        ssid: (kind == DeviceKind::Wifi && state == DeviceState::Activated).then(|| "home".to_string()),
        ip4: Some("192.168.1.10/24".into()),
        ip6: None,
        gw: gw.map(Into::into),
        dns: vec![],
        speed_mbps: None,
    }
}

/// A manager with a loopback and a Wi-Fi device. It records what it is asked, keeps the request of the
/// last connection, and takes a minute to connect to the network `slow`.
struct Fake {
    devices: Mutex<Vec<Device>>,
    asked: Mutex<Vec<String>>,
    connect: Mutex<Option<WifiConnectRequest>>,
    signals: broadcast::Sender<BackendEvent>,
}

impl Fake {
    fn new() -> Arc<Fake> {
        Arc::new(Fake {
            devices: Mutex::new(vec![
                device("lo", DeviceKind::Loopback, DeviceState::Activated, None),
                device("wlan0", DeviceKind::Wifi, DeviceState::Activated, Some("192.168.1.1")),
            ]),
            asked: Mutex::new(vec![]),
            connect: Mutex::new(None),
            signals: broadcast::channel(8).0,
        })
    }
    fn wifi(&self, state: DeviceState) {
        self.devices.lock().unwrap()[1] = device("wlan0", DeviceKind::Wifi, state, Some("192.168.1.1"));
    }
    fn note(&self, what: &str) {
        self.asked.lock().unwrap().push(what.into());
    }
}

#[async_trait]
impl NetworkBackend for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }
    async fn list_devices(&self) -> Result<Vec<Device>, NetworkError> {
        Ok(self.devices.lock().unwrap().clone())
    }
    async fn list_access_points(&self, _device: Option<&str>) -> Result<Vec<AccessPoint>, NetworkError> {
        Ok(vec![AccessPoint {
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            ssid: Some("home".into()),
            signal_dbm: -50,
            signal_pct: 80,
            frequency_mhz: 5180,
            channel: 36,
            security: ApSecurity::Wpa2Psk,
            in_use: true,
            hidden: false,
            last_seen_ms: 1,
        }])
    }
    async fn request_scan(&self, _device: Option<&str>) -> Result<(), NetworkError> {
        self.note("scan");
        Ok(())
    }
    async fn connect_wifi(&self, req: WifiConnectRequest, progress: ProgressSink) -> Result<String, NetworkError> {
        if req.ssid == "slow" {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        if req.ssid == "wrong" {
            return Err(NetworkError::AuthFailed);
        }
        let _ = progress
            .send(ProgressUpdate {
                request_id: req.request_id.clone(),
                phase: ProgressPhase::Authenticating,
                connection: None,
                error_code: None,
                error_detail: None,
            })
            .await;
        *self.connect.lock().unwrap() = Some(req);
        Ok("uuid-1".into())
    }
    async fn activate_profile(&self, uuid: &str, _d: Option<&str>, _r: String, _p: ProgressSink) -> Result<String, NetworkError> {
        self.note(&format!("activate {uuid}"));
        Ok(uuid.into())
    }
    async fn disconnect_wifi(&self, _device: Option<&str>) -> Result<(), NetworkError> {
        self.note("disconnect");
        Ok(())
    }
    async fn start_hotspot(&self, _req: HotspotRequest) -> Result<String, NetworkError> {
        Err(NetworkError::Unsupported("hotspot"))
    }
    async fn stop_hotspot(&self) -> Result<(), NetworkError> {
        Ok(())
    }
    async fn list_profiles(&self) -> Result<Vec<Profile>, NetworkError> {
        Ok(vec![])
    }
    async fn update_profile(&self, _uuid: &str, _patch: ProfilePatch) -> Result<(), NetworkError> {
        Ok(())
    }
    async fn forget_profile(&self, uuid: &str) -> Result<(), NetworkError> {
        self.note(&format!("forget {uuid}"));
        Ok(())
    }
    async fn apply_ethernet(&self, _device: &str, _ipv4: Ipv4Config) -> Result<String, NetworkError> {
        Ok("uuid-2".into())
    }
    fn subscribe_signals(&self) -> broadcast::Receiver<BackendEvent> {
        self.signals.subscribe()
    }
}

/// What the Plugin said on the Session, in order.
#[derive(Default)]
struct Core {
    said: Mutex<Vec<String>>,
}

impl Core {
    fn said(&self) -> Vec<String> {
        self.said.lock().unwrap().clone()
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.said.lock().unwrap())
    }
    fn push(&self, line: String) -> Result<(), yoke_sdk::base::Error> {
        self.said.lock().unwrap().push(line);
        Ok(())
    }
}

impl Acts for Core {
    async fn answer(&self, _q: &Question, payload: Vec<u8>) -> Result<(), yoke_sdk::base::Error> {
        self.push(format!("answer {}", String::from_utf8_lossy(&payload)))
    }
    async fn fail(&self, _q: &Question, code: &str, message: &str) -> Result<(), yoke_sdk::base::Error> {
        self.push(format!("fail {code}: {message}"))
    }
    async fn ack(&self, _c: &Command, outcome: Outcome, line: &str) -> Result<(), yoke_sdk::base::Error> {
        self.push(format!("ack {outcome:?}: {line}"))
    }
    async fn report(&self, occurrence: &str, severity: u8, line: &str, detail: Value) -> Result<(), yoke_sdk::base::Error> {
        assert_eq!(detail["line"], line, "the detail carries the line a client reads");
        self.push(format!("report {occurrence} {severity}: {line}"))
    }
    async fn emit(&self, stream: &str, payload: Vec<u8>) -> Result<(), yoke_sdk::base::Error> {
        self.push(format!("emit {stream} {}", String::from_utf8_lossy(&payload)))
    }
}

fn question(r#type: &str, payload: &str) -> Event {
    Event::Question(Question { id: "q-1".into(), r#type: r#type.into(), payload: payload.as_bytes().to_vec() })
}

fn command(r#type: &str, payload: &str) -> Event {
    Event::Command(Command { id: "c-1".into(), r#type: r#type.into(), payload: payload.as_bytes().to_vec() })
}

/// The JSON a line of the recorder carries after its first two words, or after its first.
fn json_of(line: &str, skip: usize) -> Value {
    serde_json::from_str(line.splitn(skip + 1, ' ').nth(skip).unwrap()).unwrap()
}

#[test]
fn the_manifest_kept_is_the_manifest_declared() {
    assert_eq!(declaration().manifest(), include_str!("../com.yoke.network.yaml"));
}

#[test]
fn every_object_declared_has_one_capability() {
    let d = declaration();
    let objects = d.queries.len() + d.commands.len() + d.streams.len() + d.occurrences.len();
    assert_eq!(d.capabilities.len(), objects);
}

#[tokio::test]
async fn the_status_is_the_device_with_a_gateway_and_never_the_loopback() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    net.refresh(&core).await.unwrap();
    // The first reading is sequence 1, and reports nothing: nobody saw the host come onto its network.
    assert!(core.said().is_empty(), "{:?}", core.said());
    handle(&core, &question(STATUS, ""), &net).await.unwrap();
    let status = json_of(&core.take()[0], 1);
    assert_eq!(status["sequence"], 1);
    assert_eq!(status["phase"], "connected");
    assert_eq!(status["connection"]["device"], "wlan0");
    assert_eq!(status["connection"]["ssid"], "home");
}

#[tokio::test]
async fn a_change_is_counted_once_emitted_where_the_stream_flows_and_reported() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    net.refresh(&core).await.unwrap();

    // Nothing changed: nothing is counted, emitted or reported.
    net.on_backend_event(&core, &BackendEvent::StateChanged).await.unwrap();
    assert!(core.said().is_empty());

    // The stream does not flow: the change is counted and reported, and not emitted.
    fake.wifi(DeviceState::Disconnected);
    net.on_backend_event(&core, &BackendEvent::StateChanged).await.unwrap();
    assert_eq!(core.take(), vec![format!("report {DISCONNECTED} 30: on no network")]);

    // A client that subscribes and then asks: the stream's first sample and the answer are one record.
    net.activated(&core, STATUS).await.unwrap();
    handle(&core, &question(STATUS, ""), &net).await.unwrap();
    let said = core.take();
    let (first, answer) = (json_of(&said[0], 2), json_of(&said[1], 1));
    assert_eq!(first, answer);
    assert_eq!(answer["sequence"], 2);
    assert_eq!(answer["phase"], "disconnected");

    // The stream flows: the next change is emitted with the next sequence, and reported.
    fake.wifi(DeviceState::Activated);
    net.on_backend_event(&core, &BackendEvent::DevicesChanged).await.unwrap();
    let said = core.take();
    assert_eq!(json_of(&said[0], 2)["sequence"], 3);
    assert_eq!(said[1], format!("report {CONNECTED} 10: connected: wlan0 on home"));

    net.stopped(STATUS);
    fake.wifi(DeviceState::Disconnected);
    net.refresh(&core).await.unwrap();
    assert!(core.take().iter().all(|l| !l.starts_with("emit")));
}

#[tokio::test]
async fn a_passphrase_reaches_the_manager_and_nothing_else() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, mut steps) = Net::new(Ok(fake.clone()));
    let payload = json!({ "ssid": "home", "security": "psk", "password": SECRET }).to_string();
    handle(&core, &command(WIFI_CONNECT, &payload), &net).await.unwrap();
    let request = fake.connect.lock().unwrap().take().unwrap();
    assert_eq!(request.password.as_deref(), Some(SECRET));
    assert_eq!(request.security, ApSecurity::Wpa2Psk);
    // The steps of the connection carry the command's identity where the payload names none.
    assert_eq!(request.request_id, "c-1");
    assert_eq!(core.take(), vec!["ack Done: connected to home (profile uuid-1)".to_string()]);

    // The access point's own security is taken as `network.access-points` says it.
    let wpa3 = json!({ "ssid": "home", "security": "wpa3-psk", "password": SECRET }).to_string();
    handle(&core, &command(WIFI_CONNECT, &wpa3), &net).await.unwrap();
    assert_eq!(fake.connect.lock().unwrap().take().unwrap().security, ApSecurity::Wpa3Psk);
    core.take();

    // Its step becomes the status, with the request it belongs to.
    net.activated(&core, STATUS).await.unwrap();
    core.take();
    let step = steps.recv().await.unwrap();
    net.on_progress(&core, &step).await.unwrap();
    let sample = json_of(&core.take()[0], 2);
    assert_eq!(sample["phase"], "authenticating");
    assert_eq!(sample["request_id"], "c-1");

    // A payload that does not parse is described by where it fails: here the passphrase is a number's
    // place, and the text of the fault would have quoted it.
    for bad in [
        format!(r#"{{"ssid":"home","security":"psk","password":["{SECRET}"]}}"#),
        format!(r#"{{"ssid":"home","security":"psk","password":"{SECRET}","passwrd":"{SECRET}"}}"#),
        format!(r#"{{"ssid":"home","security":"psk","password":"{SECRET}""#),
    ] {
        handle(&core, &command(WIFI_CONNECT, &bad), &net).await.unwrap();
    }
    // A manager that refuses the passphrase says so without it.
    let wrong = json!({ "ssid": "wrong", "security": "psk", "password": SECRET }).to_string();
    handle(&core, &command(WIFI_CONNECT, &wrong), &net).await.unwrap();
    let said = core.take();
    assert_eq!(said.len(), 4);
    assert!(said[..3].iter().all(|l| l.starts_with("ack Failed: invalid: ")), "{said:?}");
    assert_eq!(said[3], "ack Failed: auth_failed: authentication failed");
    assert!(said.iter().all(|l| !l.contains(SECRET)), "{said:?}");
}

#[tokio::test(start_paused = true)]
async fn a_command_still_running_is_accepted_and_its_end_reported() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    let payload = json!({ "ssid": "slow", "security": "open" }).to_string();
    handle(&core, &command(WIFI_CONNECT, &payload), &net).await.unwrap();
    let said = core.said();
    assert!(said[0].starts_with("ack Accepted: still running after 25 s"), "{said:?}");
    assert_eq!(said[1], format!("report {JOB_FINISHED} 10: connected to slow (profile uuid-1)"));
}

#[tokio::test]
async fn the_commands_act_and_say_what_was_done() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    handle(&core, &command(WIFI_SCAN, ""), &net).await.unwrap();
    handle(&core, &command(WIFI_DISCONNECT, "{}"), &net).await.unwrap();
    handle(&core, &command(PROFILE_FORGET, r#"{"uuid":"u-9"}"#), &net).await.unwrap();
    handle(&core, &command(PROFILE_ACTIVATE, r#"{"uuid":"u-9"}"#), &net).await.unwrap();
    handle(&core, &command(HOTSPOT_START, r#"{"ssid":"ap","password":"12345678"}"#), &net).await.unwrap();
    handle(&core, &command(WIFI_CONNECT, r#"{"ssid":"home","security":"wpa9"}"#), &net).await.unwrap();
    assert_eq!(*fake.asked.lock().unwrap(), vec!["scan", "disconnect", "forget u-9", "activate u-9"]);
    assert_eq!(
        core.said(),
        vec![
            "ack Done: a scan was asked for",
            "ack Done: disconnected",
            "ack Done: profile u-9 forgotten",
            "ack Done: profile u-9 is active",
            "ack Failed: unsupported: not supported by backend: hotspot",
            "ack Failed: invalid: security is open, wep, wpa-psk, wpa2-psk, wpa3-psk, wpa-eap, psk or eap",
        ]
    );
}

#[tokio::test]
async fn the_access_points_flow_only_while_asked_for() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    // Not flowing: a change of the access points asks nothing of the caller.
    assert!(!net.on_backend_event(&core, &BackendEvent::AccessPointsChanged).await.unwrap());
    net.activated(&core, SCAN).await.unwrap();
    assert_eq!(*fake.asked.lock().unwrap(), vec!["scan"]);
    let sample = json_of(&core.take()[0], 2);
    assert_eq!(sample["access_points"][0]["ssid"], "home");
    assert_eq!(sample["access_points"][0]["security"], "wpa2-psk");
    assert!(net.on_backend_event(&core, &BackendEvent::AccessPointsChanged).await.unwrap());
    net.stopped(SCAN);
    assert!(!net.scanning());
}

#[tokio::test]
async fn the_devices_are_emitted_whole_and_only_when_they_changed() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    net.refresh(&core).await.unwrap();
    net.activated(&core, DEVICES).await.unwrap();
    assert_eq!(json_of(&core.take()[0], 2)["devices"].as_array().unwrap().len(), 2);
    net.refresh(&core).await.unwrap();
    assert!(core.take().is_empty());
    fake.wifi(DeviceState::Failed);
    net.refresh(&core).await.unwrap();
    let said = core.take();
    assert_eq!(json_of(said.iter().find(|l| l.starts_with("emit network.devices")).unwrap(), 2)["devices"][1]["state"], "failed");
}

#[tokio::test]
async fn with_no_manager_every_question_and_command_is_failed_with_the_reason() {
    let core = Core::default();
    let (net, _steps) = Net::new(Err(NetworkError::Unavailable("no bus".into())));
    net.refresh(&core).await.unwrap();
    handle(&core, &question(DEVICES, ""), &net).await.unwrap();
    handle(&core, &question(STATUS, ""), &net).await.unwrap();
    handle(&core, &command(WIFI_SCAN, ""), &net).await.unwrap();
    let said = core.said();
    assert!(said[0].starts_with("fail unavailable: "), "{said:?}");
    assert!(said[1].starts_with("fail unavailable: "), "{said:?}");
    assert!(said[2].starts_with("ack Failed: unavailable: "), "{said:?}");
}

#[tokio::test]
async fn a_question_takes_no_field_it_does_not_know() {
    let (fake, core) = (Fake::new(), Core::default());
    let (net, _steps) = Net::new(Ok(fake.clone()));
    handle(&core, &question(DEVICES, r#"{"all":true}"#), &net).await.unwrap();
    handle(&core, &question(ACCESS_POINTS, r#"{"device":"wlan0"}"#), &net).await.unwrap();
    let said = core.said();
    assert!(said[0].starts_with("fail invalid: the payload is not what network.devices takes"), "{said:?}");
    assert!(said[1].starts_with("answer "), "{said:?}");
}
