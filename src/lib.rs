//! Microsoft SQL Server (TDS) backend binding plugin for mcpg.
//!
//! Implements [`MssqlBackendPlugin`] — `BackendPlugin` for `kind: "mssql"`.
//! Runs a parameterised statement whose `@P1, @P2, …` placeholders are bound
//! from CEL expressions evaluated against the tool arguments (bound as SQL
//! parameters, never interpolated — injection-safe), over a pooled tiberius
//! connection. `op: query` returns rows; `op: execute` returns rows-affected.
//! Structurally mirrors the soap/ldap backends; MSSQL-specific machinery
//! lives in [`mssql`] + [`params`] + [`envelope`].

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
mod mssql;
mod params;
mod types;

use envelope::{build_result_envelope, classify_error};
use mssql::{MssqlManager, MssqlPool, build_pool, run_statement};
use params::{CompiledParam, compile_params, evaluate_params};
pub use types::{EncryptionMode, MssqlBackendSpec, MssqlOp};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.mssql.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.mssql.request_failed"),
        "mssql_error" => Some("dev.mcpg.backend.mssql.query_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.mssql.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.mssql".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("MSSQL plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

// ------------------------------------------------------------------ plugin

/// Per-binding MSSQL runtime — connection pool + compiled statement. Cheap to
/// clone (pool + params behind `Arc`).
#[derive(Clone)]
struct MssqlProfile {
    pool: Arc<MssqlPool>,
    query: String,
    compiled_params: Arc<[CompiledParam]>,
    op: MssqlOp,
    host: String,
    database: String,
    size_limit: usize,
    timeout: Duration,
}

/// `BackendPlugin` implementation for `kind: "mssql"`.
pub struct MssqlBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, MssqlProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for MssqlBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl MssqlBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.mssql",
                name: "MSSQL Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit).
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_mssql_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_mssql_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("mssql-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("mssql-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::mssql::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope (param-eval failures), emit the triad, and
    /// return it as a normal payload — matching the soap/ldap backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &MssqlProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.host,
            &profile.database,
            profile.op.as_str(),
            None,
            None,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }
}

impl std::fmt::Debug for MssqlBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MssqlBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for MssqlBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "mssql"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: MssqlBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("MSSQL binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.database.trim().is_empty() {
            return Err(invalid("database must not be empty".into()));
        }
        if parsed.user.trim().is_empty() {
            return Err(invalid("user must not be empty".into()));
        }
        if parsed.query.trim().is_empty() {
            return Err(invalid("query must not be empty".into()));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if parsed.size_limit == 0 {
            return Err(invalid("size_limit must be greater than 0".into()));
        }
        if parsed.pool_max_size == 0 {
            return Err(invalid("pool_max_size must be greater than 0".into()));
        }
        // Surface the two TLS footguns at boot rather than letting them pass
        // silently: certificate trust disables MITM protection, and
        // encryption=off sends query data + bound parameters in cleartext.
        if parsed.trust_server_certificate {
            tracing::warn!(
                backend = %backend_name,
                "mssql: trust_server_certificate is enabled — the server TLS \
                 certificate is NOT validated, so an active network attacker can \
                 MITM the connection. Use only for dev / a pinned internal CA."
            );
        }
        if parsed.encryption == EncryptionMode::Off {
            tracing::warn!(
                backend = %backend_name,
                "mssql: encryption=off — only the login handshake is encrypted; \
                 query data and bound parameters travel in cleartext. Trusted \
                 networks only."
            );
        }
        // Per-caller `cred://` is unsupported (the pool is per-binding, one
        // service identity). Point operators at the config secret-resolver.
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are \
                 unsupported (the pool is one service identity); use ${env.X} / \
                 vault:// (resolved at config load) instead"
                    .into(),
            ));
        }

        let compiled_params: Arc<[CompiledParam]> =
            compile_params(&parsed.params).map_err(invalid)?.into();

        let manager = MssqlManager::new(
            parsed.host.clone(),
            parsed.port,
            parsed.database.clone(),
            parsed.user,
            parsed.password,
            parsed.encryption,
            parsed.trust_server_certificate,
        );
        let pool = build_pool(manager, parsed.pool_max_size).map_err(invalid)?;

        debug!(
            backend = %backend_name,
            host = %parsed.host,
            database = %parsed.database,
            op = parsed.op.as_str(),
            params = compiled_params.len(),
            "registered MSSQL binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            MssqlProfile {
                pool: Arc::new(pool),
                query: parsed.query,
                compiled_params,
                op: parsed.op,
                host: parsed.host,
                database: parsed.database,
                size_limit: parsed.size_limit,
                timeout: Duration::from_millis(parsed.timeout_ms),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "mssql_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("MSSQL plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // Evaluate the CEL parameter expressions against the arguments.
        let bound = match evaluate_params(&profile.compiled_params, &arguments) {
            Ok(v) => v,
            Err(e) => {
                return self
                    .finish_error(
                        &profile,
                        backend_name,
                        &tool_name,
                        &format!("evaluating params: {e}"),
                        "invalid_spec",
                        identity.as_ref(),
                        &request_id,
                        started,
                        host_span,
                    )
                    .await;
            }
        };

        let result = run_statement(
            &profile.pool,
            &profile.query,
            bound,
            profile.op,
            profile.size_limit,
            profile.timeout,
        )
        .await;

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok(outcome) => (
                    build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.host,
                        &profile.database,
                        profile.op.as_str(),
                        outcome.rows.as_deref(),
                        outcome.rows_affected,
                        started.elapsed().as_millis(),
                        None,
                        None,
                    ),
                    "ok",
                    None,
                ),
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "mssql_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.host,
                        &profile.database,
                        profile.op.as_str(),
                        None,
                        None,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("mssql.transport".to_owned(), json!("plugin"));
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "host": "sql.example.com",
            "database": "appdb",
            "user": "svc",
            "password": "${env.MSSQL_PW}",
            "query": "SELECT id, name FROM users WHERE id = @P1",
            "params": ["arguments.id"],
        })
    }

    #[test]
    fn kind_is_mssql() {
        assert_eq!(MssqlBackendPlugin::new().kind(), "mssql");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            MssqlBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.mssql"
        );
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = MssqlBackendPlugin::new();
        plugin
            .register_profile("users", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("users").unwrap();
        assert_eq!(p.op, MssqlOp::Query);
        assert_eq!(p.database, "appdb");
        assert_eq!(p.compiled_params.len(), 1);
    }

    #[tokio::test]
    async fn register_rejects_cred_password() {
        let plugin = MssqlBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["password"] = json!("cred://vault/mssql");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred password");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_bad_cel_param() {
        let plugin = MssqlBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["params"] = json!(["this is not cel ((("]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bad cel");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_empty_query() {
        let plugin = MssqlBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["query"] = json!("   ");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty query");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = MssqlBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
