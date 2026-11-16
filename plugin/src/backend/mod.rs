//! Backend abstraction over NetworkManager and connman.
//!
//! `detect_backend()` probes the system D-Bus for a known service in priority
//! order (NM > connman) and returns an `Arc<dyn NetworkBackend>` ready to use.

pub mod types;

#[cfg(feature = "backend-nm")]
pub mod nm;
#[cfg(feature = "backend-connman")]
pub mod connman;

use std::sync::Arc;
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::broadcast;

pub use types::*;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("permission denied (polkit)")]
    PermissionDenied,
    #[error("not supported by backend: {0}")]
    Unsupported(&'static str),
    #[error("ssid not found")]
    SsidNotFound,
    #[error("authentication failed")]
    AuthFailed,
    #[error("not found")]
    NotFound,
    #[error("invalid params: {0}")]
    Invalid(String),
    #[error("dbus: {0}")]
    Dbus(String),
    #[error("backend error: {0}")]
    Other(String),
}

impl From<zbus::Error> for NetworkError {
    fn from(e: zbus::Error) -> Self {
        NetworkError::Dbus(format!("{e}"))
    }
}

/// Maps NetworkError into the canonical wire error_code used by the plugin.
pub fn error_code(err: &NetworkError) -> &'static str {
    match err {
        NetworkError::Unavailable(_)    => "NETWORK.BACKEND_ERROR",
        NetworkError::PermissionDenied  => "NETWORK.PERMISSION_DENIED",
        NetworkError::Unsupported(_)    => "NETWORK.UNSUPPORTED",
        NetworkError::SsidNotFound      => "NETWORK.SSID_NOT_FOUND",
        NetworkError::AuthFailed        => "NETWORK.AUTH_FAILED",
        NetworkError::NotFound          => "NETWORK.NOT_FOUND",
        NetworkError::Invalid(_)        => "NETWORK.INVALID_PARAMS",
        NetworkError::Dbus(_)           => "NETWORK.BACKEND_ERROR",
        NetworkError::Other(_)          => "NETWORK.BACKEND_ERROR",
    }
}

#[async_trait]
pub trait NetworkBackend: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn list_devices(&self) -> Result<Vec<Device>, NetworkError>;
    async fn list_access_points(
        &self,
        device: Option<&str>,
    ) -> Result<Vec<AccessPoint>, NetworkError>;
    async fn request_scan(&self, device: Option<&str>) -> Result<(), NetworkError>;

    async fn connect_wifi(
        &self,
        req:      WifiConnectRequest,
        progress: ProgressSink,
    ) -> Result<String /*uuid*/, NetworkError>;
    /// Activates an existing profile (no new profile is created). `device` defaults to
    /// the first device of the profile's kind. Progress is reported like `connect_wifi`.
    async fn activate_profile(
        &self,
        uuid:       &str,
        device:     Option<&str>,
        request_id: String,
        progress:   ProgressSink,
    ) -> Result<String /*uuid*/, NetworkError>;
    async fn disconnect_wifi(&self, device: Option<&str>) -> Result<(), NetworkError>;

    async fn start_hotspot(&self, req: HotspotRequest) -> Result<String, NetworkError>;
    async fn stop_hotspot(&self) -> Result<(), NetworkError>;

    async fn list_profiles(&self) -> Result<Vec<Profile>, NetworkError>;
    async fn update_profile(&self, uuid: &str, patch: ProfilePatch) -> Result<(), NetworkError>;
    async fn forget_profile(&self, uuid: &str) -> Result<(), NetworkError>;

    async fn apply_ethernet(
        &self,
        device: &str,
        ipv4:   Ipv4Config,
    ) -> Result<String, NetworkError>;

    /// Authorization the current user has on the backend (polkit actions).
    async fn permissions(&self) -> Result<Vec<Permission>, NetworkError> {
        Err(NetworkError::Unsupported("permissions"))
    }

    fn subscribe_signals(&self) -> broadcast::Receiver<BackendEvent>;
}

/// Probe the system bus for a known network service. NM has priority.
pub async fn detect_backend() -> Result<Arc<dyn NetworkBackend>, NetworkError> {
    let conn = zbus::Connection::system()
        .await
        .map_err(|e| NetworkError::Unavailable(format!("system bus: {e}")))?;

    let dbus = zbus::fdo::DBusProxy::new(&conn)
        .await
        .map_err(|e| NetworkError::Unavailable(format!("DBus proxy: {e}")))?;
    let names: Vec<String> = dbus
        .list_names()
        .await
        .map_err(|e| NetworkError::Unavailable(format!("ListNames: {e}")))?
        .into_iter()
        .map(|n| n.to_string())
        .collect();

    #[cfg(feature = "backend-nm")]
    if names.iter().any(|n| n == "org.freedesktop.NetworkManager") {
        let backend = nm::NmBackend::new(conn).await?;
        return Ok(Arc::new(backend));
    }

    #[cfg(feature = "backend-connman")]
    if names.iter().any(|n| n == "net.connman") {
        let backend = connman::ConnmanBackend::new(conn).await?;
        return Ok(Arc::new(backend));
    }

    Err(NetworkError::Unavailable(
        "no supported backend found on system bus (looked for NetworkManager, connman)".into(),
    ))
}
