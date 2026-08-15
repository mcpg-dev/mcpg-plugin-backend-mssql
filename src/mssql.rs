//! MSSQL/TDS machinery: a pooled tiberius connection, statement execution,
//! and row → JSON projection.

use std::time::Duration;

use base64::Engine as _;
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use serde_json::{Map, Value};
use tiberius::{AuthMethod, Client, ColumnData, Config, EncryptionLevel, FromSql, Query};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use crate::params::bind_param;
use crate::types::{EncryptionMode, MssqlOp};

/// A pooled SQL Server connection.
pub type MssqlClient = Client<Compat<TcpStream>>;

/// deadpool manager that opens tiberius connections over rustls TLS.
pub struct MssqlManager {
    host: String,
    port: u16,
    database: String,
    user: String,
    password: String,
    encryption: EncryptionMode,
    trust_cert: bool,
}

impl MssqlManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: String,
        port: u16,
        database: String,
        user: String,
        password: String,
        encryption: EncryptionMode,
        trust_cert: bool,
    ) -> Self {
        Self {
            host,
            port,
            database,
            user,
            password,
            encryption,
            trust_cert,
        }
    }

    fn build_config(&self) -> Config {
        let mut config = Config::new();
        config.host(&self.host);
        config.port(self.port);
        config.database(&self.database);
        config.authentication(AuthMethod::sql_server(&self.user, &self.password));
        config.encryption(match self.encryption {
            EncryptionMode::Required => EncryptionLevel::Required,
            EncryptionMode::Off => EncryptionLevel::Off,
        });
        if self.trust_cert {
            config.trust_cert();
        }
        config
    }
}

impl Manager for MssqlManager {
    type Type = MssqlClient;
    type Error = String;

    async fn create(&self) -> Result<MssqlClient, String> {
        let config = self.build_config();
        let addr = config.get_addr();
        let tcp = TcpStream::connect(&addr).await.map_err(|e| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("MSSQL connect {addr}: {e}"))
        })?;
        let _ = tcp.set_nodelay(true);
        Client::connect(config, tcp.compat_write())
            .await
            .map_err(|e| {
                mcpg_plugin_protocol::redact::redact_in_text(&format!("MSSQL login failed: {e}"))
            })
    }

    async fn recycle(&self, client: &mut MssqlClient, _m: &Metrics) -> RecycleResult<String> {
        // Cheap round-trip to confirm the pooled connection is still live.
        client
            .simple_query("SELECT 1")
            .await
            .map_err(|e| RecycleError::Backend(format!("recycle ping failed: {e}")))?
            .into_first_result()
            .await
            .map_err(|e| RecycleError::Backend(format!("recycle drain failed: {e}")))?;
        Ok(())
    }
}

/// Pool alias for one binding.
pub type MssqlPool = Pool<MssqlManager>;

/// Build a per-binding connection pool.
pub fn build_pool(manager: MssqlManager, max_size: usize) -> Result<MssqlPool, String> {
    Pool::builder(manager)
        .max_size(max_size)
        .build()
        .map_err(|e| format!("MSSQL pool build failed: {e}"))
}

/// Result of a completed statement — rows (query) xor a count (execute).
pub struct QueryOutcome {
    pub rows: Option<Vec<Value>>,
    pub rows_affected: Option<u64>,
}

/// Acquire a pooled connection, bind the parameters, and run the statement.
/// Every step is bounded by `timeout`.
pub async fn run_statement(
    pool: &MssqlPool,
    query_sql: &str,
    bound: Vec<Value>,
    op: MssqlOp,
    size_limit: usize,
    timeout: Duration,
) -> Result<QueryOutcome, String> {
    let mut client = match tokio::time::timeout(timeout, pool.get()).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(format!("MSSQL pool acquire failed: {e}")),
        Err(_) => return Err("MSSQL pool acquire timed out".to_owned()),
    };

    let mut query = Query::new(query_sql.to_owned());
    for value in bound {
        bind_param(&mut query, value)?;
    }

    match op {
        MssqlOp::Query => {
            let stream = match tokio::time::timeout(timeout, query.query(&mut client)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(format!("MSSQL query failed: {e}")),
                Err(_) => return Err("MSSQL query timed out".to_owned()),
            };
            let rows = match tokio::time::timeout(timeout, stream.into_first_result()).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(format!("MSSQL result read failed: {e}")),
                Err(_) => return Err("MSSQL result read timed out".to_owned()),
            };
            let json_rows: Vec<Value> =
                rows.into_iter().take(size_limit).map(row_to_json).collect();
            Ok(QueryOutcome {
                rows: Some(json_rows),
                rows_affected: None,
            })
        }
        MssqlOp::Execute => {
            let res = match tokio::time::timeout(timeout, query.execute(&mut client)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(format!("MSSQL execute failed: {e}")),
                Err(_) => return Err("MSSQL execute timed out".to_owned()),
            };
            Ok(QueryOutcome {
                rows: None,
                rows_affected: Some(res.total()),
            })
        }
    }
}

/// One row → `{ column: value, … }`. Column names stay as the server reports
/// them; duplicate names collapse (last wins) — alias them in the query.
fn row_to_json(row: tiberius::Row) -> Value {
    let mut obj = Map::new();
    for (col, data) in row.cells() {
        obj.insert(col.name().to_owned(), column_data_to_json(data));
    }
    Value::Object(obj)
}

/// Project one TDS column value to JSON. `NULL` of any type → JSON `null`.
/// Takes `&ColumnData<'static>` — the shape `Row::cells()` yields, and what
/// tiberius's `FromSql::from_sql` requires for the temporal conversions.
fn column_data_to_json(cd: &ColumnData<'static>) -> Value {
    match cd {
        ColumnData::U8(o) => int_json(o.map(i64::from)),
        ColumnData::I16(o) => int_json(o.map(i64::from)),
        ColumnData::I32(o) => int_json(o.map(i64::from)),
        ColumnData::I64(o) => int_json(*o),
        ColumnData::F32(o) => float_json(o.map(f64::from)),
        ColumnData::F64(o) => float_json(*o),
        ColumnData::Bit(o) => o.map(Value::Bool).unwrap_or(Value::Null),
        ColumnData::String(o) => o
            .as_ref()
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::Guid(o) => o
            .map(|g| Value::String(g.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::Binary(o) => o
            .as_ref()
            .map(|b| Value::String(base64::engine::general_purpose::STANDARD.encode(b)))
            .unwrap_or(Value::Null),
        ColumnData::Numeric(o) => o
            .map(|n| Value::String(n.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::Xml(o) => o
            .as_ref()
            .map(|x| Value::String(x.to_string()))
            .unwrap_or(Value::Null),
        // Temporal types: convert through tiberius's chrono FromSql impls
        // (the `chrono` feature), stringified to ISO-ish form.
        other => temporal_to_json(other),
    }
}

fn temporal_to_json(cd: &ColumnData<'static>) -> Value {
    match cd {
        ColumnData::DateTime(_) | ColumnData::SmallDateTime(_) | ColumnData::DateTime2(_) => {
            chrono::NaiveDateTime::from_sql(cd)
                .ok()
                .flatten()
                .map(|dt| Value::String(dt.to_string()))
                .unwrap_or(Value::Null)
        }
        ColumnData::Date(_) => chrono::NaiveDate::from_sql(cd)
            .ok()
            .flatten()
            .map(|d| Value::String(d.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::Time(_) => chrono::NaiveTime::from_sql(cd)
            .ok()
            .flatten()
            .map(|t| Value::String(t.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::DateTimeOffset(_) => chrono::DateTime::<chrono::FixedOffset>::from_sql(cd)
            .ok()
            .flatten()
            .map(|dt| Value::String(dt.to_rfc3339()))
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn int_json(o: Option<i64>) -> Value {
    o.map(|v| Value::Number(v.into())).unwrap_or(Value::Null)
}

fn float_json(o: Option<f64>) -> Value {
    o.and_then(serde_json::Number::from_f64)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_columns_to_json() {
        assert_eq!(column_data_to_json(&ColumnData::I32(Some(42))), json!(42));
        assert_eq!(
            column_data_to_json(&ColumnData::I64(Some(9_000_000_000))),
            json!(9_000_000_000i64)
        );
        assert_eq!(
            column_data_to_json(&ColumnData::Bit(Some(true))),
            json!(true)
        );
        assert_eq!(
            column_data_to_json(&ColumnData::String(Some("hi".into()))),
            json!("hi")
        );
        assert_eq!(column_data_to_json(&ColumnData::F64(Some(1.5))), json!(1.5));
    }

    #[test]
    fn null_columns_to_json_null() {
        assert_eq!(column_data_to_json(&ColumnData::I32(None)), Value::Null);
        assert_eq!(column_data_to_json(&ColumnData::String(None)), Value::Null);
        assert_eq!(column_data_to_json(&ColumnData::Bit(None)), Value::Null);
    }

    #[test]
    fn binary_column_is_base64() {
        let v = column_data_to_json(&ColumnData::Binary(Some(vec![0u8, 1, 2].into())));
        // base64 of [0,1,2] == "AAEC"
        assert_eq!(v, json!("AAEC"));
    }
}
