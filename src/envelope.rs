//! MSSQL structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is
//! the gateway's `is_error` signal (same contract as the http/soap/ldap
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn mssql_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_mssql.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_database_connectivity_and_retry" } else { "inspect_sql_error" },
    })
}

/// Classify a `run_statement` error string. Connection-level failures
/// (connect / login / pool / timeout / dropped connection) are retryable
/// transport errors; SQL rejections (syntax, constraint, permission) are
/// caller/config problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    let retryable = lower.contains("connect")
        || lower.contains("login failed")
        || lower.contains("pool")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        || lower.contains("eof");
    let kind = if retryable {
        "transport_error"
    } else {
        "mssql_error"
    };
    mssql_downstream_error(kind, message, retryable)
}

/// Build the MSSQL structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    host: &str,
    database: &str,
    op: &str,
    rows: Option<&[Value]>,
    rows_affected: Option<u64>,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "rows": rows,
            "count": rows.map(<[Value]>::len),
            "rowsAffected": rows_affected,
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "host": host,
            "database": database,
            "op": op,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failure_is_retryable_transport_error() {
        let e = classify_error("MSSQL connect sql:1433: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn sql_rejection_is_not_retryable() {
        let e = classify_error("MSSQL query failed: Invalid column name 'bogus'");
        assert_eq!(e["kind"], json!("mssql_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn query_envelope_has_rows_and_count() {
        let rows = vec![json!({ "id": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "sql",
            "appdb",
            "query",
            Some(&rows),
            None,
            7,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["rows"][0]["id"], json!(1));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn execute_envelope_has_rows_affected() {
        let env = build_result_envelope(
            "u.upd",
            "u.upd",
            "sql",
            "appdb",
            "execute",
            None,
            Some(3),
            4,
            None,
            None,
        );
        assert_eq!(env["response"]["rowsAffected"], json!(3));
    }

    #[test]
    fn error_envelope_nulls_response() {
        let d = classify_error("MSSQL execute failed: PK violation");
        let env = build_result_envelope(
            "u.upd",
            "u.upd",
            "sql",
            "appdb",
            "execute",
            None,
            None,
            2,
            Some(&d),
            Some("PK violation"),
        );
        assert!(env["response"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("mssql_error"));
    }
}
