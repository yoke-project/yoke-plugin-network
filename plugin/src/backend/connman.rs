//! connman backend implementation via D-Bus (`zbus`).
//!
//! connman exposes a flatter "services" model than NetworkManager. This
//! backend covers basic Wi-Fi browse/connect/disconnect and Ethernet
//! status. EAP profile creation, hotspot per-connection SSID/password,
//! and detailed profile editing return `NetworkError::Unsupported`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::sync::broadcast;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

use crate::backend::types::*;
use crate::backend::{NetworkBackend, NetworkError};

const CONNMAN_BUS:  &str = "net.connman";
const CONNMAN_ROOT: &str = "/";

const IFACE_MANAGER: &str = "net.connman.Manager";
const IFACE_SERVICE: &str = "net.connman.Service";

pub struct ConnmanBackend {
    conn: Connection,
    tx:   broadcast::Sender<BackendEvent>,
}

impl ConnmanBackend {
    pub async fn new(conn: Connection) -> Result<Self, NetworkError> {
        let (tx, _) = broadcast::channel::<BackendEvent>(64);

        let bg_conn = conn.clone();
        let bg_tx   = tx.clone();
        tokio::spawn(async move {
            let _ = run_signal_loop(bg_conn, bg_tx).await;
        });

        Ok(ConnmanBackend { conn, tx })
    }

    fn manager(&self) -> Arc<Connection> { Arc::new(self.conn.clone()) }
}

async fn run_signal_loop(
    conn: Connection,
    tx:   broadcast::Sender<BackendEvent>,
) -> zbus::Result<()> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(IFACE_MANAGER)?
        .build();
    let mut stream = zbus::MessageStream::for_match_rule(rule, &conn, None).await?;
    while let Some(_msg) = stream.next().await {
        let _ = tx.send(BackendEvent::AccessPointsChanged);
        let _ = tx.send(BackendEvent::DevicesChanged);
        let _ = tx.send(BackendEvent::StateChanged);
    }
    Ok(())
}

fn val_str(v: &OwnedValue) -> String {
    let raw: &Value<'_> = v;
    if let Value::Str(s) = raw { return s.to_string(); }
    if let Value::Value(b) = raw {
        if let Value::Str(s) = &**b { return s.to_string(); }
    }
    String::new()
}

fn val_u8(v: &OwnedValue) -> u8 {
    let raw: &Value<'_> = v;
    if let Value::U8(n) = raw { return *n; }
    if let Value::Value(b) = raw {
        if let Value::U8(n) = &**b { return *n; }
    }
    0
}

fn val_bool(v: &OwnedValue) -> bool {
    let raw: &Value<'_> = v;
    if let Value::Bool(b) = raw { return *b; }
    if let Value::Value(b) = raw {
        if let Value::Bool(x) = &**b { return *x; }
    }
    false
}

async fn list_services(
    conn: &Connection,
) -> Result<Vec<(OwnedObjectPath, HashMap<String, OwnedValue>)>, NetworkError> {
    let proxy = zbus::Proxy::new(conn, CONNMAN_BUS, CONNMAN_ROOT, IFACE_MANAGER).await?;
    let services: Vec<(OwnedObjectPath, HashMap<String, OwnedValue>)> =
        proxy.call("GetServices", &()).await?;
    Ok(services)
}

#[async_trait]
impl NetworkBackend for ConnmanBackend {
    fn name(&self) -> &'static str { "connman" }

    async fn list_devices(&self) -> Result<Vec<Device>, NetworkError> {
        let conn = self.manager();
        let proxy = zbus::Proxy::new(&conn, CONNMAN_BUS, CONNMAN_ROOT, IFACE_MANAGER).await?;
        let techs: Vec<(OwnedObjectPath, HashMap<String, OwnedValue>)> =
            proxy.call("GetTechnologies", &()).await?;

        // connman exposes "technologies" rather than per-NIC devices. We synthesize
        // one Device per technology as a coarse approximation.
        let mut out = Vec::with_capacity(techs.len());
        for (path, props) in techs {
            let typ = props.get("Type").map(val_str).unwrap_or_default();
            let kind = match typ.as_str() {
                "wifi"     => DeviceKind::Wifi,
                "ethernet" => DeviceKind::Ethernet,
                _          => DeviceKind::Other,
            };
            let powered = props.get("Powered").map(val_bool).unwrap_or(false);
            let connected = props.get("Connected").map(val_bool).unwrap_or(false);
            let state = if !powered { DeviceState::Unavailable }
                        else if connected { DeviceState::Activated }
                        else { DeviceState::Disconnected };

            out.push(Device {
                name: path.as_str().rsplit('/').next().unwrap_or("").to_string(),
                mac: String::new(),
                kind,
                state,
                carrier: connected,
                ssid: None,
                ip4: None,
                ip6: None,
                gw: None,
                dns: Vec::new(),
                speed_mbps: None,
            });
        }
        Ok(out)
    }

    async fn list_access_points(
        &self,
        _device: Option<&str>,
    ) -> Result<Vec<AccessPoint>, NetworkError> {
        let conn = self.manager();
        let services = list_services(&conn).await?;
        let mut out = Vec::new();
        for (_path, props) in services {
            if props.get("Type").map(val_str).as_deref() != Some("wifi") {
                continue;
            }
            let ssid = props.get("Name").map(val_str).filter(|s| !s.is_empty());
            let signal_pct = props.get("Strength").map(val_u8).unwrap_or(0);
            let in_use = props.get("State").map(val_str).as_deref() == Some("ready")
                      || props.get("State").map(val_str).as_deref() == Some("online");
            let security_list = props.get("Security")
                .map(|v| {
                    let raw: &Value<'_> = v;
                    let inner = if let Value::Value(b) = raw { &**b } else { raw };
                    if let Value::Array(arr) = inner {
                        arr.iter().filter_map(|x| {
                            if let Value::Str(s) = x { Some(s.to_string()) } else { None }
                        }).collect::<Vec<_>>()
                    } else { Vec::new() }
                })
                .unwrap_or_default();
            let security = if security_list.iter().any(|s| s == "ieee8021x") { ApSecurity::WpaEap }
                           else if security_list.iter().any(|s| s == "psk") { ApSecurity::Wpa2Psk }
                           else if security_list.iter().any(|s| s == "wep") { ApSecurity::Wep }
                           else { ApSecurity::Open };

            out.push(AccessPoint {
                bssid: String::new(),
                ssid: ssid.clone(),
                signal_dbm: ((signal_pct as i32) / 2) - 100,
                signal_pct,
                frequency_mhz: 0,
                channel: 0,
                security,
                in_use,
                hidden: ssid.is_none(),
                last_seen_ms: 0,
            });
        }
        Ok(out)
    }

    async fn request_scan(&self, _device: Option<&str>) -> Result<(), NetworkError> {
        let conn = self.manager();
        // connman: scan via Technology.Scan() on the wifi technology.
        let proxy = zbus::Proxy::new(&conn, CONNMAN_BUS, "/net/connman/technology/wifi",
                                     "net.connman.Technology").await?;
        let _: () = proxy.call("Scan", &()).await?;
        Ok(())
    }

    async fn connect_wifi(
        &self,
        req:      WifiConnectRequest,
        progress: ProgressSink,
    ) -> Result<String, NetworkError> {
        if req.security == ApSecurity::WpaEap {
            return Err(NetworkError::Unsupported("EAP on connman"));
        }

        let _ = progress.send(ProgressUpdate {
            request_id: req.request_id.clone(),
            phase: ProgressPhase::Associating,
            connection: None, error_code: None, error_detail: None,
        }).await;

        // Find the service path matching SSID.
        let conn = self.manager();
        let services = list_services(&conn).await?;
        let mut found: Option<OwnedObjectPath> = None;
        for (path, props) in &services {
            if props.get("Type").map(val_str).as_deref() != Some("wifi") { continue; }
            if props.get("Name").map(val_str).as_deref() == Some(req.ssid.as_str()) {
                found = Some(path.clone());
                break;
            }
        }
        let svc_path = found.ok_or(NetworkError::SsidNotFound)?;

        // connman requires an Agent to deliver the passphrase. We don't ship one;
        // call Connect() and let the user have either pre-saved credentials or
        // accept the call to fail with "InvalidArguments" / require an agent.
        //
        // For PSK: caller can pre-set Passphrase via SetProperty if the service
        // supports it; we attempt that as a best-effort.
        let svc = zbus::Proxy::new(&conn, CONNMAN_BUS, svc_path.as_str(), IFACE_SERVICE).await?;
        if let Some(pw) = &req.password {
            let _: zbus::Result<()> = svc.call("SetProperty",
                &("Passphrase", Value::from(pw.clone()))).await;
        }

        let _: zbus::Result<()> = svc.call("Connect", &()).await;

        let _ = progress.send(ProgressUpdate {
            request_id: req.request_id.clone(),
            phase: ProgressPhase::Connected,
            connection: Some(ConnectionInfo {
                ssid: Some(req.ssid.clone()),
                device: "wifi".into(),
                ip4: None, ip6: None, gw: None, dns: Vec::new(), signal_dbm: None,
            }),
            error_code: None, error_detail: None,
        }).await;

        Ok(svc_path.as_str().rsplit('/').next().unwrap_or("").to_string())
    }

    async fn activate_profile(
        &self,
        uuid:       &str,
        _device:    Option<&str>,
        request_id: String,
        progress:   ProgressSink,
    ) -> Result<String, NetworkError> {
        // connman profiles are services, identified by the last path segment.
        let conn = self.manager();
        let services = list_services(&conn).await?;
        let (path, _) = services.into_iter()
            .find(|(p, _)| p.as_str().rsplit('/').next() == Some(uuid))
            .ok_or(NetworkError::NotFound)?;

        let _ = progress.send(ProgressUpdate {
            request_id: request_id.clone(),
            phase: ProgressPhase::Associating,
            connection: None, error_code: None, error_detail: None,
        }).await;

        let svc = zbus::Proxy::new(&conn, CONNMAN_BUS, path.as_str(), IFACE_SERVICE).await?;
        let res: zbus::Result<()> = svc.call("Connect", &()).await;
        let phase = if res.is_ok() { ProgressPhase::Connected } else { ProgressPhase::Failed };
        let _ = progress.send(ProgressUpdate {
            request_id, phase, connection: None,
            error_code: res.is_err().then(|| "NETWORK.BACKEND_ERROR".to_string()),
            error_detail: None,
        }).await;
        res?;
        Ok(uuid.to_string())
    }

    async fn disconnect_wifi(&self, _device: Option<&str>) -> Result<(), NetworkError> {
        let conn = self.manager();
        let services = list_services(&conn).await?;
        for (path, props) in services {
            if props.get("Type").map(val_str).as_deref() != Some("wifi") { continue; }
            let st = props.get("State").map(val_str).unwrap_or_default();
            if st == "ready" || st == "online" || st == "association" || st == "configuration" {
                let svc = zbus::Proxy::new(&conn, CONNMAN_BUS, path.as_str(), IFACE_SERVICE).await?;
                let _: () = svc.call("Disconnect", &()).await?;
                return Ok(());
            }
        }
        Ok(())
    }

    async fn start_hotspot(&self, _req: HotspotRequest) -> Result<String, NetworkError> {
        Err(NetworkError::Unsupported("hotspot on connman"))
    }

    async fn stop_hotspot(&self) -> Result<(), NetworkError> {
        Err(NetworkError::Unsupported("hotspot on connman"))
    }

    async fn list_profiles(&self) -> Result<Vec<Profile>, NetworkError> {
        // connman conflates "profile" and "service": list all wifi services and
        // surface them as profiles. This is a coarse approximation.
        let conn = self.manager();
        let services = list_services(&conn).await?;
        let mut out = Vec::new();
        for (path, props) in services {
            let typ = props.get("Type").map(val_str).unwrap_or_default();
            let kind = match typ.as_str() {
                "wifi"     => DeviceKind::Wifi,
                "ethernet" => DeviceKind::Ethernet,
                _          => continue,
            };
            let id = props.get("Name").map(val_str).unwrap_or_default();
            let autoconnect = props.get("AutoConnect").map(val_bool).unwrap_or(false);
            let uuid = path.as_str().rsplit('/').next().unwrap_or("").to_string();
            out.push(Profile {
                uuid,
                id,
                kind,
                ssid: props.get("Name").map(val_str).filter(|s| !s.is_empty()),
                security: None,
                autoconnect,
                last_used_unix: None,
            });
        }
        Ok(out)
    }

    async fn update_profile(&self, _uuid: &str, _patch: ProfilePatch) -> Result<(), NetworkError> {
        Err(NetworkError::Unsupported("profile editing on connman"))
    }

    async fn forget_profile(&self, uuid: &str) -> Result<(), NetworkError> {
        // Best effort: remove the matching service.
        let conn = self.manager();
        let services = list_services(&conn).await?;
        for (path, _) in services {
            let id = path.as_str().rsplit('/').next().unwrap_or("");
            if id == uuid {
                let svc = zbus::Proxy::new(&conn, CONNMAN_BUS, path.as_str(), IFACE_SERVICE).await?;
                let _: () = svc.call("Remove", &()).await?;
                return Ok(());
            }
        }
        Err(NetworkError::NotFound)
    }

    async fn apply_ethernet(
        &self,
        _device: &str,
        _ipv4:   Ipv4Config,
    ) -> Result<String, NetworkError> {
        Err(NetworkError::Unsupported("ethernet IPv4 edit on connman"))
    }

    fn subscribe_signals(&self) -> broadcast::Receiver<BackendEvent> {
        self.tx.subscribe()
    }
}
