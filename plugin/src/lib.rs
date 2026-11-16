//! The network of the host as a Yoke Plugin: NetworkManager over D-Bus, with connman as a fallback.
//!
//! `backend` talks to the manager and knows nothing of Yoke; `plugin` is the Plugin around it — what it
//! declares, how a payload is read, what it answers, emits and reports.

pub mod backend;
pub mod plugin;
