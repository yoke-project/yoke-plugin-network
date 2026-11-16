//! NetworkManager backend implementation via D-Bus (`zbus`).
//!
//! Targets `org.freedesktop.NetworkManager` on the system bus.
//! Translates the high-level [`NetworkBackend`] trait into NM RPCs and
//! property reads, and converts NM's numeric state machine into
//! [`DeviceState`] / [`ApSecurity`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::sync::broadcast;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

use crate::backend::types::*;
use crate::backend::{NetworkBackend, NetworkError};

const NM_BUS:           &str = "org.freedesktop.NetworkManager";
const NM_PATH:          &str = "/org/freedesktop/NetworkManager";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";

const IFACE_NM:           &str = "org.freedesktop.NetworkManager";
const IFACE_NM_DEVICE:    &str = "org.freedesktop.NetworkManager.Device";
const IFACE_NM_WIFI:      &str = "org.freedesktop.NetworkManager.Device.Wireless";
const IFACE_NM_WIRED:     &str = "org.freedesktop.NetworkManager.Device.Wired";
const IFACE_NM_AP:        &str = "org.freedesktop.NetworkManager.AccessPoint";
const IFACE_NM_SETTINGS:  &str = "org.freedesktop.NetworkManager.Settings";
const IFACE_NM_CONN:      &str = "org.freedesktop.NetworkManager.Settings.Connection";
const IFACE_NM_IP4:       &str = "org.freedesktop.NetworkManager.IP4Config";
const IFACE_NM_ACTIVE:    &str = "org.freedesktop.NetworkManager.Connection.Active";
const IFACE_PROPERTIES:   &str = "org.freedesktop.DBus.Properties";

// NM device type constants.
const NM_DEVICE_TYPE_ETHERNET: u32 = 1;
const NM_DEVICE_TYPE_WIFI:     u32 = 2;
const NM_DEVICE_TYPE_LOOPBACK: u32 = 32;

// NM device state constants — translated to DeviceState.
fn map_device_state(n: u32) -> DeviceState {
    match n {
        10  => DeviceState::Unmanaged,
        20  => DeviceState::Unavailable,
        30  => DeviceState::Disconnected,
        40  => DeviceState::Prepare,
        50  => DeviceState::Config,
        60  => DeviceState::NeedAuth,
        70  => DeviceState::IpConfig,
        80  => DeviceState::IpCheck,
        90  => DeviceState::Secondaries,
        100 => DeviceState::Activated,
        110 => DeviceState::Deactivating,
        120 => DeviceState::Failed,
        _   => DeviceState::Unavailable,
    }
}

fn map_device_kind(n: u32) -> DeviceKind {
    match n {
        NM_DEVICE_TYPE_WIFI     => DeviceKind::Wifi,
        NM_DEVICE_TYPE_ETHERNET => DeviceKind::Ethernet,
        NM_DEVICE_TYPE_LOOPBACK => DeviceKind::Loopback,
        _                       => DeviceKind::Other,
    }
}

pub struct NmBackend {
    conn: Connection,
    tx:   broadcast::Sender<BackendEvent>,
}

impl NmBackend {
    pub async fn new(conn: Connection) -> Result<Self, NetworkError> {
        let (tx, _) = broadcast::channel::<BackendEvent>(64);

        // Background task: subscribe to NM signals and republish as BackendEvent.
        let bg_conn = conn.clone();
        let bg_tx   = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_signal_loop(bg_conn, bg_tx).await {
                tracing::warn!("nm signal loop exited: {e:?}");
            }
        });

        Ok(NmBackend { conn, tx })
    }

    fn manager(&self) -> Arc<Connection> { Arc::new(self.conn.clone()) }
}

async fn run_signal_loop(
    conn: Connection,
    tx:   broadcast::Sender<BackendEvent>,
) -> zbus::Result<()> {
    use zbus::MatchRule;

    // PropertiesChanged on any NetworkManager object (devices, access points, ...).
    let rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(IFACE_PROPERTIES)?
        .member("PropertiesChanged")?
        .path_namespace(NM_PATH)?
        .build();
    let mut stream = zbus::MessageStream::for_match_rule(rule, &conn, None).await?;

    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { continue };
        let path = msg.header().path().map(|p| p.to_string()).unwrap_or_default();
        let Ok((interface, changed, _invalidated)) = msg
            .body()
            .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
        else { continue };

        let mut keys: Vec<String> = changed.into_keys().collect();
        keys.sort();
        let _ = tx.send(BackendEvent::Property { path, interface: interface.clone(), keys });
        for ev in classify_interface(&interface) {
            let _ = tx.send(ev);
        }
    }
    Ok(())
}

/// Maps the interface that changed to the coarse "refresh this" events.
fn classify_interface(iface: &str) -> Vec<BackendEvent> {
    if iface == IFACE_NM_AP || iface == IFACE_NM_WIFI {
        vec![BackendEvent::AccessPointsChanged]
    } else if iface == IFACE_NM || iface == IFACE_NM_ACTIVE || iface == IFACE_NM_SETTINGS
        || iface == IFACE_NM_CONN
    {
        vec![BackendEvent::StateChanged, BackendEvent::DevicesChanged]
    } else if iface.starts_with(IFACE_NM_DEVICE) || iface == IFACE_NM_IP4
        || iface == "org.freedesktop.NetworkManager.IP6Config"
    {
        vec![BackendEvent::DevicesChanged, BackendEvent::StateChanged]
    } else {
        Vec::new()
    }
}

// ── Property helpers ─────────────────────────────────────────────────────────

async fn get_property(
    conn:   &Connection,
    bus:    &str,
    path:   &str,
    iface:  &str,
    name:   &str,
) -> Result<OwnedValue, NetworkError> {
    let proxy = zbus::Proxy::new(conn, bus, path, IFACE_PROPERTIES).await?;
    let value: OwnedValue = proxy
        .call("Get", &(iface, name))
        .await
        .map_err(NetworkError::from)?;
    Ok(value)
}

fn val_u32(v: &OwnedValue) -> u32 {
    let raw: &Value<'_> = v;
    if let Value::U32(n) = raw {
        return *n;
    }
    if let Value::Value(boxed) = raw {
        if let Value::U32(n) = &**boxed { return *n; }
    }
    0
}

/// D-Bus type `y` (byte), e.g. `AccessPoint.Strength`.
fn val_u8(v: &OwnedValue) -> u8 {
    let raw: &Value<'_> = v;
    if let Value::U8(n) = raw {
        return *n;
    }
    if let Value::Value(boxed) = raw {
        if let Value::U8(n) = &**boxed { return *n; }
    }
    0
}

fn val_str(v: &OwnedValue) -> String {
    let raw: &Value<'_> = v;
    if let Value::Str(s) = raw { return s.to_string(); }
    if let Value::Value(boxed) = raw {
        if let Value::Str(s) = &**boxed { return s.to_string(); }
    }
    String::new()
}

fn val_bool(v: &OwnedValue) -> bool {
    let raw: &Value<'_> = v;
    if let Value::Bool(b) = raw { return *b; }
    if let Value::Value(boxed) = raw {
        if let Value::Bool(b) = &**boxed { return *b; }
    }
    false
}

fn val_path_vec(v: &OwnedValue) -> Vec<OwnedObjectPath> {
    let raw: &Value<'_> = v;
    let inner = if let Value::Value(boxed) = raw { &**boxed } else { raw };
    if let Value::Array(arr) = inner {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr.iter() {
            if let Value::ObjectPath(p) = item {
                out.push(OwnedObjectPath::from(p.clone()));
            }
        }
        return out;
    }
    Vec::new()
}

fn val_path(v: &OwnedValue) -> Option<OwnedObjectPath> {
    let raw: &Value<'_> = v;
    let inner = if let Value::Value(boxed) = raw { &**boxed } else { raw };
    if let Value::ObjectPath(p) = inner {
        return OwnedObjectPath::try_from(p.clone()).ok();
    }
    None
}

fn val_byte_array(v: &OwnedValue) -> Vec<u8> {
    let raw: &Value<'_> = v;
    let inner = if let Value::Value(boxed) = raw { &**boxed } else { raw };
    if let Value::Array(arr) = inner {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr.iter() {
            if let Value::U8(b) = item { out.push(*b); }
        }
        return out;
    }
    Vec::new()
}

fn ssid_from_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() { return None; }
    Some(String::from_utf8_lossy(bytes).to_string())
}

fn ap_security_from_flags(wpa: u32, rsn: u32, ap_flags: u32) -> ApSecurity {
    // NM_802_11_AP_FLAGS_PRIVACY = 0x1
    const KEY_MGMT_PSK:  u32 = 0x100;
    const KEY_MGMT_8021X: u32 = 0x200;
    const KEY_MGMT_SAE:  u32 = 0x400;

    if rsn & KEY_MGMT_SAE   != 0 { return ApSecurity::Wpa3Psk; }
    if rsn & KEY_MGMT_8021X != 0 || wpa & KEY_MGMT_8021X != 0 { return ApSecurity::WpaEap; }
    if rsn & KEY_MGMT_PSK   != 0 { return ApSecurity::Wpa2Psk; }
    if wpa & KEY_MGMT_PSK   != 0 { return ApSecurity::WpaPsk; }
    if ap_flags & 0x1       != 0 { return ApSecurity::Wep; }
    ApSecurity::Open
}

fn channel_from_freq(freq_mhz: u32) -> u32 {
    if freq_mhz == 2484 { return 14; }
    if (2412..=2472).contains(&freq_mhz) { return (freq_mhz - 2407) / 5; }
    if (5170..=5825).contains(&freq_mhz) { return (freq_mhz - 5000) / 5; }
    0
}

// ── Reading: devices ─────────────────────────────────────────────────────────

async fn read_device(
    conn: &Connection,
    path: &OwnedObjectPath,
) -> Result<Device, NetworkError> {
    let p = path.as_str();

    let iface = val_str(&get_property(conn, NM_BUS, p, IFACE_NM_DEVICE, "Interface").await?);
    let mac   = val_str(&get_property(conn, NM_BUS, p, IFACE_NM_DEVICE, "HwAddress").await?);
    let kind  = map_device_kind(val_u32(
        &get_property(conn, NM_BUS, p, IFACE_NM_DEVICE, "DeviceType").await?,
    ));
    let state = map_device_state(val_u32(
        &get_property(conn, NM_BUS, p, IFACE_NM_DEVICE, "State").await?,
    ));

    // Per-kind extras.
    let mut ssid = None;
    let mut speed_mbps = None;
    if kind == DeviceKind::Wifi {
        if let Ok(active_ap_v) = get_property(conn, NM_BUS, p, IFACE_NM_WIFI, "ActiveAccessPoint").await {
            if let Some(ap_path) = val_path(&active_ap_v) {
                if !ap_path.as_str().is_empty() && ap_path.as_str() != "/" {
                    if let Ok(ssid_v) = get_property(conn, NM_BUS, ap_path.as_str(), IFACE_NM_AP, "Ssid").await {
                        ssid = ssid_from_bytes(&val_byte_array(&ssid_v));
                    }
                }
            }
        }
        if let Ok(rate_v) = get_property(conn, NM_BUS, p, IFACE_NM_WIFI, "Bitrate").await {
            speed_mbps = Some(val_u32(&rate_v) / 1000);
        }
    } else if kind == DeviceKind::Ethernet {
        if let Ok(speed_v) = get_property(conn, NM_BUS, p, IFACE_NM_WIRED, "Speed").await {
            speed_mbps = Some(val_u32(&speed_v));
        }
    }

    // IPv4 config (if any).
    let mut ip4 = None;
    let mut gw  = None;
    let mut dns = Vec::new();
    if let Ok(ip4_path_v) = get_property(conn, NM_BUS, p, IFACE_NM_DEVICE, "Ip4Config").await {
        if let Some(ip4_path) = val_path(&ip4_path_v) {
            if !ip4_path.as_str().is_empty() && ip4_path.as_str() != "/" {
                if let Ok(addr_data_v) = get_property(conn, NM_BUS, ip4_path.as_str(), IFACE_NM_IP4, "AddressData").await {
                    let raw: &Value<'_> = &addr_data_v;
                    let inner = if let Value::Value(b) = raw { &**b } else { raw };
                    if let Value::Array(arr) = inner {
                        if let Some(item) = arr.iter().next() {
                            if let Value::Dict(d) = item {
                                let entries: HashMap<String, OwnedValue> = d.try_clone()
                                    .ok()
                                    .and_then(|d| d.try_into().ok())
                                    .unwrap_or_default();
                                let address = entries.get("address").map(val_str).unwrap_or_default();
                                let prefix  = entries.get("prefix").map(val_u32).unwrap_or(0);
                                if !address.is_empty() {
                                    ip4 = Some(format!("{address}/{prefix}"));
                                }
                            }
                        }
                    }
                }
                if let Ok(gw_v) = get_property(conn, NM_BUS, ip4_path.as_str(), IFACE_NM_IP4, "Gateway").await {
                    let g = val_str(&gw_v);
                    if !g.is_empty() { gw = Some(g); }
                }
                if let Ok(dns_v) = get_property(conn, NM_BUS, ip4_path.as_str(), IFACE_NM_IP4, "NameserverData").await {
                    let raw: &Value<'_> = &dns_v;
                    let inner = if let Value::Value(b) = raw { &**b } else { raw };
                    if let Value::Array(arr) = inner {
                        for item in arr.iter() {
                            if let Value::Dict(d) = item {
                                let entries: HashMap<String, OwnedValue> = d.try_clone()
                                    .ok()
                                    .and_then(|d| d.try_into().ok())
                                    .unwrap_or_default();
                                if let Some(addr_v) = entries.get("address") {
                                    let a = val_str(addr_v);
                                    if !a.is_empty() { dns.push(a); }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let carrier = state == DeviceState::Activated || state == DeviceState::IpConfig
        || state == DeviceState::IpCheck;

    Ok(Device {
        name: iface,
        mac,
        kind,
        state,
        carrier,
        ssid,
        ip4,
        ip6: None,
        gw,
        dns,
        speed_mbps,
    })
}

async fn list_device_paths(conn: &Connection) -> Result<Vec<OwnedObjectPath>, NetworkError> {
    let v = get_property(conn, NM_BUS, NM_PATH, IFACE_NM, "Devices").await?;
    Ok(val_path_vec(&v))
}

async fn find_device_by_type(
    conn: &Connection,
    ty:   u32,
) -> Result<OwnedObjectPath, NetworkError> {
    let paths = list_device_paths(conn).await?;
    for p in paths {
        if let Ok(t_v) = get_property(conn, NM_BUS, p.as_str(), IFACE_NM_DEVICE, "DeviceType").await {
            if val_u32(&t_v) == ty {
                return Ok(p);
            }
        }
    }
    Err(NetworkError::Unavailable("no matching device".into()))
}

async fn find_wifi_device(conn: &Connection) -> Result<OwnedObjectPath, NetworkError> {
    find_device_by_type(conn, NM_DEVICE_TYPE_WIFI)
        .await
        .map_err(|_| NetworkError::Unavailable("no wifi device".into()))
}

fn map_dbus_err(e: zbus::Error) -> NetworkError {
    let s = format!("{e}");
    if s.contains("AccessDenied") || s.contains("NotAuthorized") {
        NetworkError::PermissionDenied
    } else {
        NetworkError::Dbus(s)
    }
}

/// UUID of a settings profile. The `Settings.Connection` interface has no `Uuid`
/// property: it lives in the `connection` section of `GetSettings`.
async fn profile_uuid(conn: &Connection, path: &OwnedObjectPath) -> Result<String, NetworkError> {
    let proxy = zbus::Proxy::new(conn, NM_BUS, path.as_str(), IFACE_NM_CONN).await?;
    let settings: NmSettingsMap = proxy.call("GetSettings", &()).await?;
    settings.get("connection")
        .and_then(|c| c.get("uuid"))
        .map(val_str)
        .ok_or(NetworkError::NotFound)
}

async fn find_profile_by_id(conn: &Connection, id: &str, typ: &str) -> Option<OwnedObjectPath> {
    let v = get_property(conn, NM_BUS, NM_SETTINGS_PATH, IFACE_NM_SETTINGS, "Connections").await.ok()?;
    for p in val_path_vec(&v) {
        let proxy = zbus::Proxy::new(conn, NM_BUS, p.as_str(), IFACE_NM_CONN).await.ok()?;
        if let Ok(settings) = proxy.call::<_, _, NmSettingsMap>("GetSettings", &()).await {
            if let Some(c) = settings.get("connection") {
                let same_id  = c.get("id").map(val_str).as_deref() == Some(id);
                let same_typ = c.get("type").map(val_str).as_deref() == Some(typ);
                if same_id && same_typ { return Some(p); }
            }
        }
    }
    None
}

/// Deletes a profile created by a failed activation, so it does not pile up.
async fn discard_profile(conn: &Connection, path: &OwnedObjectPath) {
    if let Ok(proxy) = zbus::Proxy::new(conn, NM_BUS, path.as_str(), IFACE_NM_CONN).await {
        let _: zbus::Result<()> = proxy.call("Delete", &()).await;
    }
}

fn eap_settings(eap: &EapMaterial) -> HashMap<String, OwnedValue> {
    let mut x: HashMap<String, OwnedValue> = HashMap::new();
    x.insert("eap".into(), Value::from(vec![eap.method.clone()]).try_to_owned().unwrap());
    x.insert("identity".into(), Value::from(eap.identity.clone()).try_to_owned().unwrap());
    let text = [
        ("password",             &eap.password),
        ("anonymous-identity",   &eap.anonymous_identity),
        ("private-key-password", &eap.private_key_password),
        ("phase2-auth",          &eap.phase2_auth),
    ];
    for (key, val) in text {
        if let Some(v) = val {
            x.insert(key.into(), Value::from(v.clone()).try_to_owned().unwrap());
        }
    }
    // NM wants certificate paths as file:// URIs, NUL-terminated byte arrays.
    let certs = [
        ("ca-cert",     &eap.ca_cert_path),
        ("client-cert", &eap.client_cert_path),
        ("private-key", &eap.private_key_path),
    ];
    for (key, val) in certs {
        if let Some(path) = val {
            let mut bytes = format!("file://{path}").into_bytes();
            bytes.push(0);
            x.insert(key.into(), Value::from(bytes).try_to_owned().unwrap());
        }
    }
    x
}

async fn find_device_by_name(
    conn: &Connection,
    name: &str,
) -> Result<OwnedObjectPath, NetworkError> {
    let paths = list_device_paths(conn).await?;
    for p in paths {
        if let Ok(iface_v) = get_property(conn, NM_BUS, p.as_str(), IFACE_NM_DEVICE, "Interface").await {
            if val_str(&iface_v) == name {
                return Ok(p);
            }
        }
    }
    Err(NetworkError::NotFound)
}

// ── Reading: access points ───────────────────────────────────────────────────

async fn read_access_point(
    conn: &Connection,
    path: &OwnedObjectPath,
    active_path: &Option<OwnedObjectPath>,
) -> Result<AccessPoint, NetworkError> {
    let p = path.as_str();
    let bssid = val_str(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "HwAddress").await?);
    let ssid_bytes = val_byte_array(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "Ssid").await?);
    let signal = val_u8(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "Strength").await?);
    let freq   = val_u32(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "Frequency").await?);
    let flags  = val_u32(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "Flags").await?);
    let wpa    = val_u32(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "WpaFlags").await?);
    let rsn    = val_u32(&get_property(conn, NM_BUS, p, IFACE_NM_AP, "RsnFlags").await?);

    let signal_dbm = ((signal as i32) / 2) - 100; // approximate inverse of signal_pct
    let in_use = active_path.as_ref().is_some_and(|a| a.as_str() == p);
    let ssid = ssid_from_bytes(&ssid_bytes);

    Ok(AccessPoint {
        bssid,
        ssid: ssid.clone(),
        signal_dbm,
        signal_pct: signal,
        frequency_mhz: freq,
        channel: channel_from_freq(freq),
        security: ap_security_from_flags(wpa, rsn, flags),
        in_use,
        hidden: ssid.is_none(),
        last_seen_ms: 0,
    })
}

// ── Connect helpers ──────────────────────────────────────────────────────────

fn build_wifi_settings(req: &WifiConnectRequest) -> NmSettingsMap {
    let mut settings: NmSettingsMap = HashMap::new();

    // [connection]
    let mut connection: HashMap<String, OwnedValue> = HashMap::new();
    connection.insert("id".into(),   Value::from(req.ssid.clone()).try_to_owned().unwrap());
    connection.insert("type".into(), Value::from("802-11-wireless").try_to_owned().unwrap());
    if !req.save_profile {
        // 0 = persistent, 1 = volatile
        connection.insert("autoconnect".into(), Value::Bool(false).try_to_owned().unwrap());
    }
    settings.insert("connection".into(), connection);

    // [802-11-wireless]
    let mut wifi: HashMap<String, OwnedValue> = HashMap::new();
    let ssid_bytes: Vec<u8> = req.ssid.as_bytes().to_vec();
    wifi.insert("ssid".into(), Value::from(ssid_bytes).try_to_owned().unwrap());
    wifi.insert("mode".into(), Value::from("infrastructure").try_to_owned().unwrap());
    if req.hidden {
        wifi.insert("hidden".into(), Value::Bool(true).try_to_owned().unwrap());
    }
    settings.insert("802-11-wireless".into(), wifi);

    // [802-11-wireless-security]
    if req.security != ApSecurity::Open {
        let mut sec: HashMap<String, OwnedValue> = HashMap::new();
        match req.security {
            ApSecurity::WpaEap => {
                sec.insert("key-mgmt".into(), Value::from("wpa-eap").try_to_owned().unwrap());
            }
            ApSecurity::Wpa3Psk => {
                sec.insert("key-mgmt".into(), Value::from("sae").try_to_owned().unwrap());
                if let Some(pw) = &req.password {
                    sec.insert("psk".into(), Value::from(pw.clone()).try_to_owned().unwrap());
                }
            }
            ApSecurity::WpaPsk | ApSecurity::Wpa2Psk => {
                sec.insert("key-mgmt".into(), Value::from("wpa-psk").try_to_owned().unwrap());
                if let Some(pw) = &req.password {
                    sec.insert("psk".into(), Value::from(pw.clone()).try_to_owned().unwrap());
                }
            }
            ApSecurity::Wep => {
                sec.insert("key-mgmt".into(), Value::from("none").try_to_owned().unwrap());
                if let Some(pw) = &req.password {
                    sec.insert("wep-key0".into(), Value::from(pw.clone()).try_to_owned().unwrap());
                }
            }
            ApSecurity::Open => {}
        }
        settings.insert("802-11-wireless-security".into(), sec);
    }

    // [802-1x] for EAP
    if let Some(eap) = &req.eap {
        settings.insert("802-1x".into(), eap_settings(eap));
    }

    // [ipv4] / [ipv6]
    let mut ipv4: HashMap<String, OwnedValue> = HashMap::new();
    ipv4.insert("method".into(), Value::from("auto").try_to_owned().unwrap());
    settings.insert("ipv4".into(), ipv4);
    let mut ipv6: HashMap<String, OwnedValue> = HashMap::new();
    ipv6.insert("method".into(), Value::from("auto").try_to_owned().unwrap());
    settings.insert("ipv6".into(), ipv6);

    settings
}

fn build_hotspot_settings(req: &HotspotRequest) -> NmSettingsMap {
    let mut settings: NmSettingsMap = HashMap::new();

    let mut connection: HashMap<String, OwnedValue> = HashMap::new();
    connection.insert("id".into(),   Value::from(format!("netui-hotspot-{}", req.ssid)).try_to_owned().unwrap());
    connection.insert("type".into(), Value::from("802-11-wireless").try_to_owned().unwrap());
    settings.insert("connection".into(), connection);

    let mut wifi: HashMap<String, OwnedValue> = HashMap::new();
    wifi.insert("ssid".into(), Value::from(req.ssid.as_bytes().to_vec()).try_to_owned().unwrap());
    wifi.insert("mode".into(), Value::from("ap").try_to_owned().unwrap());
    let band = if req.band == "5" { "a" } else { "bg" };
    wifi.insert("band".into(), Value::from(band).try_to_owned().unwrap());
    if let Some(ch) = req.channel {
        wifi.insert("channel".into(), Value::U32(ch).try_to_owned().unwrap());
    }
    settings.insert("802-11-wireless".into(), wifi);

    let mut sec: HashMap<String, OwnedValue> = HashMap::new();
    sec.insert("key-mgmt".into(), Value::from("wpa-psk").try_to_owned().unwrap());
    sec.insert("psk".into(), Value::from(req.password.clone()).try_to_owned().unwrap());
    settings.insert("802-11-wireless-security".into(), sec);

    let mut ipv4: HashMap<String, OwnedValue> = HashMap::new();
    ipv4.insert("method".into(), Value::from("shared").try_to_owned().unwrap());
    settings.insert("ipv4".into(), ipv4);

    settings
}

fn ipv4_config_to_settings(cfg: &Ipv4Config) -> HashMap<String, OwnedValue> {
    let mut ipv4: HashMap<String, OwnedValue> = HashMap::new();
    ipv4.insert("method".into(), Value::from(cfg.method.clone()).try_to_owned().unwrap());

    if cfg.method == "manual" {
        if let (Some(addr), Some(prefix)) = (&cfg.address, cfg.prefix) {
            let mut entry: HashMap<String, OwnedValue> = HashMap::new();
            entry.insert("address".into(), Value::from(addr.clone()).try_to_owned().unwrap());
            entry.insert("prefix".into(), Value::U32(prefix as u32).try_to_owned().unwrap());
            if let Some(g) = &cfg.gateway {
                entry.insert("gateway".into(), Value::from(g.clone()).try_to_owned().unwrap());
            }
            ipv4.insert(
                "address-data".into(),
                Value::from(vec![entry]).try_to_owned().unwrap(),
            );
        }
        if !cfg.dns.is_empty() {
            ipv4.insert(
                "dns".into(),
                Value::from(cfg.dns.clone()).try_to_owned().unwrap(),
            );
        }
    }
    ipv4
}

// ── NetworkBackend impl ──────────────────────────────────────────────────────

#[async_trait]
impl NetworkBackend for NmBackend {
    fn name(&self) -> &'static str { "NetworkManager" }

    async fn list_devices(&self) -> Result<Vec<Device>, NetworkError> {
        let conn = self.manager();
        let paths = list_device_paths(&conn).await?;
        let mut out = Vec::with_capacity(paths.len());
        for p in paths {
            if let Ok(d) = read_device(&conn, &p).await {
                out.push(d);
            }
        }
        Ok(out)
    }

    async fn list_access_points(
        &self,
        device: Option<&str>,
    ) -> Result<Vec<AccessPoint>, NetworkError> {
        let conn = self.manager();
        let dev_path = match device {
            Some(name) => find_device_by_name(&conn, name).await?,
            None       => find_wifi_device(&conn).await?,
        };

        let active_path: Option<OwnedObjectPath> = get_property(
            &conn, NM_BUS, dev_path.as_str(), IFACE_NM_WIFI, "ActiveAccessPoint",
        ).await.ok().and_then(|v| val_path(&v));

        let aps_v = get_property(&conn, NM_BUS, dev_path.as_str(), IFACE_NM_WIFI, "AccessPoints").await?;
        let aps = val_path_vec(&aps_v);

        let mut out = Vec::with_capacity(aps.len());
        for ap in aps {
            if let Ok(a) = read_access_point(&conn, &ap, &active_path).await {
                out.push(a);
            }
        }
        Ok(out)
    }

    async fn request_scan(&self, device: Option<&str>) -> Result<(), NetworkError> {
        let conn = self.manager();
        let dev_path = match device {
            Some(name) => find_device_by_name(&conn, name).await?,
            None       => find_wifi_device(&conn).await?,
        };
        let proxy = zbus::Proxy::new(&conn, NM_BUS, dev_path.as_str(), IFACE_NM_WIFI).await?;
        let opts: HashMap<String, OwnedValue> = HashMap::new();
        let _: () = proxy.call("RequestScan", &(opts,)).await?;
        Ok(())
    }

    async fn connect_wifi(
        &self,
        req:      WifiConnectRequest,
        progress: ProgressSink,
    ) -> Result<String, NetworkError> {
        let conn = self.manager();

        let _ = progress.send(ProgressUpdate {
            request_id: req.request_id.clone(),
            phase: ProgressPhase::Associating,
            connection: None, error_code: None, error_detail: None,
        }).await;

        let dev_path = match req.device.as_deref() {
            Some(name) => find_device_by_name(&conn, name).await?,
            None       => find_wifi_device(&conn).await?,
        };

        let settings = build_wifi_settings(&req);

        // AddAndActivateConnection: connection settings + device + specific_object
        let nm_proxy = zbus::Proxy::new(&conn, NM_BUS, NM_PATH, IFACE_NM).await?;
        let specific: OwnedObjectPath = OwnedObjectPath::try_from("/")
            .map_err(|e| NetworkError::Other(format!("op path: {e}")))?;

        let (conn_path, active_path): (OwnedObjectPath, OwnedObjectPath) = nm_proxy
            .call(
                "AddAndActivateConnection",
                &(settings, &dev_path, &specific),
            )
            .await
            .map_err(|e| {
                let s = format!("{e}");
                if s.contains("AccessDenied") || s.contains("NotAuthorized") {
                    NetworkError::PermissionDenied
                } else {
                    NetworkError::Dbus(s)
                }
            })?;

        let res = wait_active(&conn, &dev_path, &active_path, &conn_path, &req.request_id, &progress).await;
        if res.is_err() {
            discard_profile(&conn, &conn_path).await;
        }
        res
    }

    async fn activate_profile(
        &self,
        uuid:       &str,
        device:     Option<&str>,
        request_id: String,
        progress:   ProgressSink,
    ) -> Result<String, NetworkError> {
        let conn = self.manager();
        let conn_path = find_profile_path(&conn, uuid).await?;
        let proxy = zbus::Proxy::new(&conn, NM_BUS, conn_path.as_str(), IFACE_NM_CONN).await?;
        let settings: NmSettingsMap = proxy.call("GetSettings", &()).await?;
        let typ = settings.get("connection")
            .and_then(|c| c.get("type"))
            .map(val_str)
            .unwrap_or_default();

        let dev_path = match device {
            Some(name) => find_device_by_name(&conn, name).await?,
            None => match typ.as_str() {
                "802-11-wireless" => find_device_by_type(&conn, NM_DEVICE_TYPE_WIFI).await?,
                "802-3-ethernet"  => find_device_by_type(&conn, NM_DEVICE_TYPE_ETHERNET).await?,
                _ => return Err(NetworkError::Unsupported("activating this profile type")),
            },
        };

        let _ = progress.send(ProgressUpdate {
            request_id: request_id.clone(),
            phase: ProgressPhase::Associating,
            connection: None, error_code: None, error_detail: None,
        }).await;

        let nm_proxy = zbus::Proxy::new(&conn, NM_BUS, NM_PATH, IFACE_NM).await?;
        let specific: OwnedObjectPath = OwnedObjectPath::try_from("/")
            .map_err(|e| NetworkError::Other(format!("op path: {e}")))?;
        let active_path: OwnedObjectPath = nm_proxy
            .call("ActivateConnection", &(&conn_path, &dev_path, &specific))
            .await
            .map_err(map_dbus_err)?;

        // An existing profile is kept even when activation fails.
        wait_active(&conn, &dev_path, &active_path, &conn_path, &request_id, &progress).await
    }

    async fn permissions(&self) -> Result<Vec<Permission>, NetworkError> {
        let conn = self.manager();
        let nm_proxy = zbus::Proxy::new(&conn, NM_BUS, NM_PATH, IFACE_NM).await?;
        let raw: HashMap<String, String> = nm_proxy.call("GetPermissions", &()).await?;
        let mut out: Vec<Permission> = raw.into_iter().map(|(action, result)| {
            let short = action.strip_prefix("org.freedesktop.NetworkManager.")
                .unwrap_or(&action)
                .to_string();
            Permission { action: short, result }
        }).collect();
        out.sort_by(|a, b| a.action.cmp(&b.action));
        Ok(out)
    }

    async fn disconnect_wifi(&self, device: Option<&str>) -> Result<(), NetworkError> {
        let conn = self.manager();
        let dev_path = match device {
            Some(name) => find_device_by_name(&conn, name).await?,
            None       => find_wifi_device(&conn).await?,
        };
        let proxy = zbus::Proxy::new(&conn, NM_BUS, dev_path.as_str(), IFACE_NM_DEVICE).await?;
        let _: () = proxy.call("Disconnect", &()).await?;
        Ok(())
    }

    async fn start_hotspot(&self, req: HotspotRequest) -> Result<String, NetworkError> {
        let conn = self.manager();
        let dev_path = find_wifi_device(&conn).await?;
        let settings = build_hotspot_settings(&req);
        let nm_proxy = zbus::Proxy::new(&conn, NM_BUS, NM_PATH, IFACE_NM).await?;
        let specific: OwnedObjectPath = OwnedObjectPath::try_from("/")
            .map_err(|e| NetworkError::Other(format!("op path: {e}")))?;
        let (conn_path, _active): (OwnedObjectPath, OwnedObjectPath) = nm_proxy
            .call("AddAndActivateConnection", &(settings, &dev_path, &specific))
            .await
            .map_err(map_dbus_err)?;
        profile_uuid(&conn, &conn_path).await
    }

    async fn stop_hotspot(&self) -> Result<(), NetworkError> {
        let conn = self.manager();
        let dev_path = find_wifi_device(&conn).await?;
        let proxy = zbus::Proxy::new(&conn, NM_BUS, dev_path.as_str(), IFACE_NM_DEVICE).await?;
        let _: () = proxy.call("Disconnect", &()).await?;
        Ok(())
    }

    async fn list_profiles(&self) -> Result<Vec<Profile>, NetworkError> {
        let conn = self.manager();
        let v = get_property(&conn, NM_BUS, NM_SETTINGS_PATH, IFACE_NM_SETTINGS, "Connections").await?;
        let paths = val_path_vec(&v);
        let mut out = Vec::with_capacity(paths.len());
        for p in paths {
            if let Some(prof) = read_profile(&conn, &p).await { out.push(prof); }
        }
        Ok(out)
    }

    async fn update_profile(&self, uuid: &str, patch: ProfilePatch) -> Result<(), NetworkError> {
        let conn = self.manager();
        let path = find_profile_path(&conn, uuid).await?;
        let proxy = zbus::Proxy::new(&conn, NM_BUS, path.as_str(), IFACE_NM_CONN).await?;

        // Read existing settings.
        let existing: NmSettingsMap = proxy.call("GetSettings", &()).await?;
        let mut settings = existing;

        // GetSettings omits secrets and Update replaces the whole profile: re-attach
        // the stored ones, or editing e.g. autoconnect would wipe the Wi-Fi password.
        for name in ["802-11-wireless-security", "802-1x"] {
            if settings.contains_key(name) {
                if let Ok(secrets) = proxy.call::<_, _, NmSettingsMap>("GetSecrets", &(name,)).await {
                    for (section, values) in secrets {
                        settings.entry(section).or_default().extend(values);
                    }
                }
            }
        }

        if let Some(autoconnect) = patch.autoconnect {
            let entry = settings.entry("connection".into()).or_default();
            entry.insert("autoconnect".into(), Value::Bool(autoconnect).try_to_owned().unwrap());
        }
        if let Some(pw) = patch.password {
            let entry = settings.entry("802-11-wireless-security".into()).or_default();
            entry.insert("psk".into(), Value::from(pw).try_to_owned().unwrap());
        }
        if let Some(eap) = patch.eap {
            // Merge so a stored password survives when the patch carries none.
            settings.entry("802-1x".into()).or_default().extend(eap_settings(&eap));
        }
        if let Some(ipv4_cfg) = patch.ipv4 {
            settings.insert("ipv4".into(), ipv4_config_to_settings(&ipv4_cfg));
        }
        if let Some(disabled) = patch.ipv6_disabled {
            let mut ipv6: HashMap<String, OwnedValue> = HashMap::new();
            let method = if disabled { "disabled" } else { "auto" };
            ipv6.insert("method".into(), Value::from(method).try_to_owned().unwrap());
            settings.insert("ipv6".into(), ipv6);
        }

        let _: () = proxy.call("Update", &(settings,)).await?;
        Ok(())
    }

    async fn forget_profile(&self, uuid: &str) -> Result<(), NetworkError> {
        let conn = self.manager();
        let path = find_profile_path(&conn, uuid).await?;
        let proxy = zbus::Proxy::new(&conn, NM_BUS, path.as_str(), IFACE_NM_CONN).await?;
        let _: () = proxy.call("Delete", &()).await?;
        Ok(())
    }

    async fn apply_ethernet(
        &self,
        device: &str,
        ipv4:   Ipv4Config,
    ) -> Result<String, NetworkError> {
        let conn = self.manager();
        let dev_path = find_device_by_name(&conn, device).await?;
        let id = format!("netui-{device}");

        let nm_proxy = zbus::Proxy::new(&conn, NM_BUS, NM_PATH, IFACE_NM).await?;
        let specific: OwnedObjectPath = OwnedObjectPath::try_from("/")
            .map_err(|e| NetworkError::Other(format!("op path: {e}")))?;

        // Re-applying must update the profile we created before, not add another one.
        if let Some(path) = find_profile_by_id(&conn, &id, "802-3-ethernet").await {
            let proxy = zbus::Proxy::new(&conn, NM_BUS, path.as_str(), IFACE_NM_CONN).await?;
            let mut settings: NmSettingsMap = proxy.call("GetSettings", &()).await?;
            settings.insert("ipv4".into(), ipv4_config_to_settings(&ipv4));
            let _: () = proxy.call("Update", &(settings,)).await.map_err(map_dbus_err)?;
            let _: OwnedObjectPath = nm_proxy
                .call("ActivateConnection", &(&path, &dev_path, &specific))
                .await
                .map_err(map_dbus_err)?;
            return profile_uuid(&conn, &path).await;
        }

        let mut settings: NmSettingsMap = HashMap::new();
        let mut connection: HashMap<String, OwnedValue> = HashMap::new();
        connection.insert("id".into(),   Value::from(id.clone()).try_to_owned().unwrap());
        connection.insert("type".into(), Value::from("802-3-ethernet").try_to_owned().unwrap());
        connection.insert("interface-name".into(), Value::from(device.to_string()).try_to_owned().unwrap());
        settings.insert("connection".into(), connection);
        settings.insert("802-3-ethernet".into(), HashMap::new());
        settings.insert("ipv4".into(), ipv4_config_to_settings(&ipv4));
        let mut ipv6: HashMap<String, OwnedValue> = HashMap::new();
        ipv6.insert("method".into(), Value::from("auto").try_to_owned().unwrap());
        settings.insert("ipv6".into(), ipv6);

        let (conn_path, _active): (OwnedObjectPath, OwnedObjectPath) = nm_proxy
            .call("AddAndActivateConnection", &(settings, &dev_path, &specific))
            .await
            .map_err(map_dbus_err)?;
        profile_uuid(&conn, &conn_path).await
    }

    fn subscribe_signals(&self) -> broadcast::Receiver<BackendEvent> {
        self.tx.subscribe()
    }
}

/// Polls the active connection until it is ACTIVATED or FAILED, reporting progress.
/// NM Connection.Active.State: 0=unknown 1=activating 2=activated 3=deactivating 4=deactivated
async fn wait_active(
    conn:        &Connection,
    dev_path:    &OwnedObjectPath,
    active_path: &OwnedObjectPath,
    conn_path:   &OwnedObjectPath,
    request_id:  &str,
    progress:    &ProgressSink,
) -> Result<String, NetworkError> {
    let mut last_phase = ProgressPhase::Associating;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let uuid = loop {
        if tokio::time::Instant::now() > deadline {
            let _ = progress.send(ProgressUpdate {
                request_id: request_id.to_string(),
                phase: ProgressPhase::Failed,
                connection: None,
                error_code: Some("NETWORK.TIMEOUT".into()),
                error_detail: Some("activation timed out".into()),
            }).await;
            return Err(NetworkError::Other("activation timed out".into()));
        }

        let st_v = get_property(&conn, NM_BUS, active_path.as_str(), IFACE_NM_ACTIVE, "State").await
            .unwrap_or_else(|_| OwnedValue::try_from(Value::U32(0)).unwrap());
        let st = val_u32(&st_v);

        // Map underlying device state to a finer-grained phase.
        let dev_state = get_property(&conn, NM_BUS, dev_path.as_str(), IFACE_NM_DEVICE, "State").await
            .map(|v| map_device_state(val_u32(&v)))
            .unwrap_or(DeviceState::Unavailable);

        let phase = match dev_state {
            DeviceState::NeedAuth                     => ProgressPhase::Authenticating,
            DeviceState::Config | DeviceState::Prepare => ProgressPhase::Authenticating,
            DeviceState::IpConfig | DeviceState::IpCheck | DeviceState::Secondaries
                                                      => ProgressPhase::IpConfig,
            DeviceState::Activated                    => ProgressPhase::Connected,
            DeviceState::Failed                       => ProgressPhase::Failed,
            _                                         => last_phase,
        };

        if phase != last_phase {
            let _ = progress.send(ProgressUpdate {
                request_id: request_id.to_string(),
                phase, connection: None, error_code: None, error_detail: None,
            }).await;
            last_phase = phase;
        }

        if st == 2 {
            // Activated — fetch connection's UUID.
            break profile_uuid(conn, conn_path).await.unwrap_or_default();
        }
        if st == 4 || dev_state == DeviceState::Failed {
            let _ = progress.send(ProgressUpdate {
                request_id: request_id.to_string(),
                phase: ProgressPhase::Failed,
                connection: None,
                error_code: Some("NETWORK.AUTH_FAILED".into()),
                error_detail: Some("activation failed".into()),
            }).await;
            return Err(NetworkError::AuthFailed);
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    // Final connected snapshot.
    let dev = read_device(&conn, &dev_path).await.ok();
    let snap = dev.map(|d| ConnectionInfo {
        ssid:       d.ssid,
        device:     d.name,
        ip4:        d.ip4,
        ip6:        d.ip6,
        gw:         d.gw,
        dns:        d.dns,
        signal_dbm: None,
    });
    let _ = progress.send(ProgressUpdate {
        request_id: request_id.to_string(),
        phase: ProgressPhase::Connected,
        connection: snap,
        error_code: None, error_detail: None,
    }).await;

    Ok(uuid)
}

// ── Profile reads ────────────────────────────────────────────────────────────

async fn find_profile_path(
    conn: &Connection,
    uuid: &str,
) -> Result<OwnedObjectPath, NetworkError> {
    let v = get_property(conn, NM_BUS, NM_SETTINGS_PATH, IFACE_NM_SETTINGS, "Connections").await?;
    let paths = val_path_vec(&v);
    for p in paths {
        let proxy = zbus::Proxy::new(conn, NM_BUS, p.as_str(), IFACE_NM_CONN).await?;
        if let Ok(settings) = proxy.call::<_, _, NmSettingsMap>("GetSettings", &()).await {
            if let Some(connection) = settings.get("connection") {
                if let Some(u) = connection.get("uuid") {
                    if val_str(u) == uuid { return Ok(p); }
                }
            }
        }
    }
    Err(NetworkError::NotFound)
}

async fn read_profile(conn: &Connection, path: &OwnedObjectPath) -> Option<Profile> {
    let proxy = zbus::Proxy::new(conn, NM_BUS, path.as_str(), IFACE_NM_CONN).await.ok()?;
    let settings: NmSettingsMap = proxy.call("GetSettings", &()).await.ok()?;
    let connection = settings.get("connection")?;

    let uuid = connection.get("uuid").map(val_str).unwrap_or_default();
    let id   = connection.get("id").map(val_str).unwrap_or_default();
    let typ  = connection.get("type").map(val_str).unwrap_or_default();
    let autoconnect = connection.get("autoconnect").map(val_bool).unwrap_or(true);
    let last_used = connection.get("timestamp").map(|v| val_u32(v) as i64).filter(|&t| t > 0);

    let kind = if typ == "802-11-wireless" { DeviceKind::Wifi }
               else if typ == "802-3-ethernet" { DeviceKind::Ethernet }
               else { DeviceKind::Other };

    let (ssid, security) = if kind == DeviceKind::Wifi {
        let ssid = settings.get("802-11-wireless")
            .and_then(|w| w.get("ssid"))
            .map(|v| ssid_from_bytes(&val_byte_array(v)))
            .unwrap_or(None);
        let key_mgmt = settings.get("802-11-wireless-security")
            .and_then(|s| s.get("key-mgmt"))
            .map(val_str)
            .unwrap_or_default();
        let security = match key_mgmt.as_str() {
            "wpa-psk" => Some(ApSecurity::Wpa2Psk),
            "sae"     => Some(ApSecurity::Wpa3Psk),
            "wpa-eap" => Some(ApSecurity::WpaEap),
            "none"    => Some(ApSecurity::Wep),
            ""        => Some(ApSecurity::Open),
            _         => None,
        };
        (ssid, security)
    } else {
        (None, None)
    };

    Some(Profile {
        uuid,
        id,
        kind,
        ssid,
        security,
        autoconnect,
        last_used_unix: last_used,
    })
}
