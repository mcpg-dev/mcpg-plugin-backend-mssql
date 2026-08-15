//! Operator-facing spec for the MSSQL backend plugin.
//!
//! One binding = one parameterised statement = one MCP tool (or resource).
//! The connection (host/port/database/login) and the statement
//! (query/params/op) all live on the per-binding spec, mirroring the
//! http/soap/ldap one-profile-per-binding shape.

use serde::Deserialize;

/// What the statement does — selects rows, or mutates and reports a count.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MssqlOp {
    /// `SELECT`-style: return the matched rows.
    #[default]
    Query,
    /// `INSERT` / `UPDATE` / `DELETE` / DDL: return rows-affected.
    Execute,
}

impl MssqlOp {
    pub fn as_str(self) -> &'static str {
        match self {
            MssqlOp::Query => "query",
            MssqlOp::Execute => "execute",
        }
    }
}

/// Connection encryption posture.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    /// Require TLS for the whole connection (default).
    #[default]
    Required,
    /// Encrypt only the login handshake (SQL Server always encrypts login),
    /// then continue in cleartext. For trusted networks only.
    Off,
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `MssqlBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct MssqlBackendSpec {
    /// SQL Server host. Operator-configured (not caller-templated), so there
    /// is no SSRF/arg-injection vector on the host.
    pub host: String,

    /// TDS port (default 1433).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Initial database.
    pub database: String,

    /// SQL Server login user.
    pub user: String,

    /// Login password. A literal, or a `${env.X}` / `vault://...` reference
    /// the gateway secret-resolver expands at config load — never plaintext
    /// in committed config. (Per-caller `cred://` is not supported: the pool
    /// is per-binding, one service identity — see README.)
    pub password: String,

    /// Connection encryption (default `required`).
    #[serde(default)]
    pub encryption: EncryptionMode,

    /// Trust a self-signed / privately-issued server certificate. Needed for
    /// dev servers and internal CAs; leave `false` for public CAs.
    #[serde(default)]
    pub trust_server_certificate: bool,

    /// The statement. Uses `@P1, @P2, …` placeholders bound positionally from
    /// `params`. The statement text is operator-fixed — it is NOT templated
    /// from caller arguments.
    pub query: String,

    /// Statement kind (default `query`).
    #[serde(default)]
    pub op: MssqlOp,

    /// Ordered CEL expressions; `params[i]` → `@P{i+1}`. Each is evaluated
    /// against the call arguments (`arguments.*`) and bound as a SQL
    /// parameter — injection-safe.
    #[serde(default)]
    pub params: Vec<String>,

    /// Client-side cap on returned rows (default 100). `query` op only.
    #[serde(default = "default_size_limit")]
    pub size_limit: usize,

    /// Max pooled connections for this binding (default 8).
    #[serde(default = "default_pool_max")]
    pub pool_max_size: usize,

    /// Per-call timeout (ms) for acquire + query + read (default 10 s).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_port() -> u16 {
    1433
}
fn default_size_limit() -> usize {
    100
}
fn default_pool_max() -> usize {
    8
}
fn default_timeout_ms() -> u64 {
    10_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_defaults_to_query() {
        assert_eq!(MssqlOp::default(), MssqlOp::Query);
    }

    #[test]
    fn spec_applies_defaults() {
        let spec: MssqlBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "sql.example.com",
            "database": "appdb",
            "user": "svc",
            "password": "${env.MSSQL_PW}",
            "query": "SELECT id, name FROM users WHERE id = @P1",
            "params": ["arguments.id"],
        }))
        .unwrap();
        assert_eq!(spec.port, 1433);
        assert_eq!(spec.op, MssqlOp::Query);
        assert_eq!(spec.size_limit, 100);
        assert_eq!(spec.pool_max_size, 8);
        assert_eq!(spec.timeout_ms, 10_000);
        assert_eq!(spec.encryption, EncryptionMode::Required);
        assert!(!spec.trust_server_certificate);
        assert_eq!(spec.params, vec!["arguments.id".to_owned()]);
    }

    #[test]
    fn parses_execute_op() {
        let spec: MssqlBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "h", "database": "d", "user": "u", "password": "p",
            "query": "UPDATE t SET v = @P1 WHERE id = @P2",
            "op": "execute",
            "params": ["arguments.v", "arguments.id"],
        }))
        .unwrap();
        assert_eq!(spec.op, MssqlOp::Execute);
    }
}
