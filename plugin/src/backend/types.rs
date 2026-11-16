//! Backend-facing data types: shared between the trait and the two impls.
//! These mirror enough of the NM/connman model to drive Panel/CLI without
//! exposing D-Bus paths or backend-specific identifiers.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Device {
    pub name:       String,
    pub mac:        String,
    pub kind:       DeviceKind,
    pub state:      DeviceState,
    pub carrier:    bool,
    pub ssid:       Option<String>,
    pub ip4:        Option<String>,
    pub ip6:        Option<String>,
    pub gw:         Option<String>,
    pub dns:        Vec<String>,
    pub speed_mbps: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Wifi,
    Ethernet,
    Loopback,
    Other,
}

impl DeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceKind::Wifi     => "wifi",
            DeviceKind::Ethernet => "ethernet",
            DeviceKind::Loopback => "loopback",
            DeviceKind::Other    => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Unmanaged,
    Unavailable,
    Disconnected,
    Prepare,
    Config,
    NeedAuth,
    IpConfig,
    IpCheck,
    Secondaries,
    Activated,
    Deactivating,
    Failed,
}

impl DeviceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceState::Unmanaged    => "unmanaged",
            DeviceState::Unavailable  => "unavailable",
            DeviceState::Disconnected => "disconnected",
            DeviceState::Prepare      => "prepare",
            DeviceState::Config       => "config",
            DeviceState::NeedAuth     => "need_auth",
            DeviceState::IpConfig     => "ip_config",
            DeviceState::IpCheck      => "ip_check",
            DeviceState::Secondaries  => "secondaries",
            DeviceState::Activated    => "activated",
            DeviceState::Deactivating => "deactivating",
            DeviceState::Failed       => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid:         String,
    pub ssid:          Option<String>,
    pub signal_dbm:    i32,
    pub signal_pct:    u8,
    pub frequency_mhz: u32,
    pub channel:       u32,
    pub security:      ApSecurity,
    pub in_use:        bool,
    pub hidden:        bool,
    pub last_seen_ms:  u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApSecurity {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3Psk,
    WpaEap,
}

impl ApSecurity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApSecurity::Open    => "open",
            ApSecurity::Wep     => "wep",
            ApSecurity::WpaPsk  => "wpa-psk",
            ApSecurity::Wpa2Psk => "wpa2-psk",
            ApSecurity::Wpa3Psk => "wpa3-psk",
            ApSecurity::WpaEap  => "wpa-eap",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub uuid:           String,
    pub id:             String,
    pub kind:           DeviceKind,
    pub ssid:           Option<String>,
    pub security:       Option<ApSecurity>,
    pub autoconnect:    bool,
    pub last_used_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Ipv4Config {
    /// "auto" | "manual"
    pub method:  String,
    pub address: Option<String>,
    pub prefix:  Option<u8>,
    pub gateway: Option<String>,
    pub dns:     Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProfilePatch {
    pub autoconnect:   Option<bool>,
    pub password:      Option<String>,
    pub eap:           Option<EapMaterial>,
    pub ipv4:          Option<Ipv4Config>,
    pub ipv6_disabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct EapMaterial {
    pub method:               String,
    pub identity:             String,
    pub password:             Option<String>,
    pub anonymous_identity:   Option<String>,
    pub ca_cert_path:         Option<String>,
    pub client_cert_path:     Option<String>,
    pub private_key_path:     Option<String>,
    pub private_key_password: Option<String>,
    pub phase2_auth:          Option<String>,
}

#[derive(Debug, Clone)]
pub struct WifiConnectRequest {
    pub request_id:   String,
    pub ssid:         String,
    pub security:     ApSecurity,
    pub password:     Option<String>,
    pub eap:          Option<EapMaterial>,
    pub hidden:       bool,
    pub save_profile: bool,
    pub device:       Option<String>,
}

#[derive(Debug, Clone)]
pub struct HotspotRequest {
    pub ssid:     String,
    pub password: String,
    pub band:     String,
    pub channel:  Option<u32>,
}

/// Progress messages emitted by `connect_wifi` while the activation runs.
/// The controller consumes these and shows
/// them as status messages tagged with `request_id`.
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub request_id:    String,
    pub phase:         ProgressPhase,
    pub connection:    Option<ConnectionInfo>,
    pub error_code:    Option<String>,
    pub error_detail:  Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressPhase {
    Scanning,
    Associating,
    Authenticating,
    IpConfig,
    Connected,
    Disconnected,
    Failed,
}

impl ProgressPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProgressPhase::Scanning       => "scanning",
            ProgressPhase::Associating    => "associating",
            ProgressPhase::Authenticating => "authenticating",
            ProgressPhase::IpConfig       => "ip_config",
            ProgressPhase::Connected      => "connected",
            ProgressPhase::Disconnected   => "disconnected",
            ProgressPhase::Failed         => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub ssid:       Option<String>,
    pub device:     String,
    pub ip4:        Option<String>,
    pub ip6:        Option<String>,
    pub gw:         Option<String>,
    pub dns:        Vec<String>,
    pub signal_dbm: Option<i32>,
}

/// Channel handle used by handlers to publish progress updates.
pub type ProgressSink = tokio::sync::mpsc::Sender<ProgressUpdate>;

/// Backend-emitted events used by the streams to refresh their snapshots.
#[derive(Debug, Clone)]
pub enum BackendEvent {
    DevicesChanged,
    AccessPointsChanged,
    StateChanged,
    Progress(ProgressUpdate),
    /// Raw D-Bus `PropertiesChanged` (NetworkManager backend only): which object,
    /// which interface and which properties changed. Useful to inspect the event flow.
    Property { path: String, interface: String, keys: Vec<String> },
}

impl BackendEvent {
    /// One-line human-readable form, e.g. `property  /AccessPoint/181  AccessPoint  [Strength]`.
    pub fn describe(&self) -> String {
        match self {
            BackendEvent::Property { path, interface, keys } => {
                let short = path.strip_prefix("/org/freedesktop/NetworkManager").unwrap_or(path);
                let iface = interface.rsplit('.').next().unwrap_or(interface);
                format!("property  {short}  {iface}  [{}]", keys.join(", "))
            }
            BackendEvent::Progress(p) => format!("progress  {} {}", p.request_id, p.phase.as_str()),
            other => format!("refresh   {other:?}"),
        }
    }
}

/// What the current user may do, as reported by the backend's authorization layer
/// (NetworkManager asks polkit). `result` is "yes", "no" or "auth" (needs authentication).
#[derive(Debug, Clone)]
pub struct Permission {
    pub action: String,
    pub result: String,
}

/// Settings serialized in NetworkManager's `AddAndActivateConnection2` call.
/// (Re-exported for backend implementers; not used outside this module.)
pub type NmSettingsMap = HashMap<String, HashMap<String, zvariant::OwnedValue>>;
