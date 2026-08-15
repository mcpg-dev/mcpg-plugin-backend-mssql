//! cdylib sync bridge — adapts the async [`MssqlBackendPlugin`] onto the sync
//! FFI trait the cdylib vtable expects ([`SyncBackendPlugin`]). A private
//! multi-thread runtime `block_on`s the async methods; the make-time
//! [`HostHandle`] is wrapped as `Arc<dyn BackendHost>` for `register_profile`
//! and installed on the inner plugin for observability. MSSQL is
//! request/reply, so it inherits the SDK's single-`Done` streaming default.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::MssqlBackendPlugin;

fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("mssql cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`MssqlBackendPlugin`].
pub struct MssqlBackendCdylib {
    inner: MssqlBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl MssqlBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — MSSQL carries no
    /// plugin-level config (per-binding connection / query arrive via
    /// `register_profile`).
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = MssqlBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-mssql"),
        }
    }
}

impl SyncBackendPlugin for MssqlBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }
}

// cdylib export — one `backend` entity under `dev.mcpg.backend.mssql`.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.mssql",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: MssqlBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                MssqlBackendCdylib::from_host_config(cfg, host),
        },
    ],
}
