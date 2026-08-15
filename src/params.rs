//! CEL-computed query parameters, bound as SQL parameters.
//!
//! Operators declare an ordered `params: ["<CEL>", …]` list on a binding.
//! At `register_profile` each expression is compiled once; per call each is
//! evaluated against the call's `arguments` object and the resulting value is
//! bound positionally — `params[i]` → `@P{i+1}`. Values cross the wire as
//! TDS parameters, never interpolated into the statement text, so caller
//! input cannot alter the query (injection-safe).

use cel::{Context as CelContext, Program, Value as CelValue};
use serde_json::Value;
use tiberius::Query;

/// A compiled `params` entry — the ordinal position and its CEL program.
/// `cel::Program` isn't `Clone`; the profile shares these via `Arc<[_]>`.
#[derive(Debug)]
pub struct CompiledParam {
    /// Zero-based position (bound to `@P{index+1}`).
    pub index: usize,
    /// Compiled CEL program — evaluated per call.
    pub program: Program,
    /// Original source, retained for diagnostics.
    pub source: String,
}

/// Compile every parameter expression. Errors name the offending position.
pub fn compile_params(exprs: &[String]) -> Result<Vec<CompiledParam>, String> {
    exprs
        .iter()
        .enumerate()
        .map(|(index, source)| {
            Program::compile(source)
                .map(|program| CompiledParam {
                    index,
                    program,
                    source: source.clone(),
                })
                .map_err(|e| format!("params[{index}] does not compile as CEL: {e}"))
        })
        .collect()
}

/// Evaluate every compiled expression against `arguments`, returning the
/// values in ordinal order.
pub fn evaluate_params(params: &[CompiledParam], arguments: &Value) -> Result<Vec<Value>, String> {
    let args_cel = json_to_cel(arguments);
    params
        .iter()
        .map(|p| {
            let mut ctx = CelContext::default();
            ctx.add_variable("arguments", args_cel.clone())
                .map_err(|e| format!("params[{}]: bind arguments: {e}", p.index))?;
            let out = p
                .program
                .execute(&ctx)
                .map_err(|e| format!("params[{}] failed: {e} (source: {})", p.index, p.source))?;
            Ok(cel_to_json(out))
        })
        .collect()
}

/// Bind one JSON value as a SQL parameter on `query`. Scalars only — SQL
/// parameters can't carry arrays/objects.
pub fn bind_param(query: &mut Query<'static>, value: Value) -> Result<(), String> {
    match value {
        // A typed NULL: nvarchar NULL is the most portable (SQL Server
        // implicitly converts in comparisons).
        Value::Null => query.bind(Option::<String>::None),
        Value::Bool(b) => query.bind(b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i);
            } else if let Some(f) = n.as_f64() {
                query.bind(f);
            } else {
                return Err("unsupported numeric parameter (out of i64/f64 range)".into());
            }
            return Ok(());
        }
        Value::String(s) => query.bind(s),
        Value::Array(_) | Value::Object(_) => {
            return Err("array/object values cannot be bound as SQL parameters".into());
        }
    }
    Ok(())
}

/// serde_json → CEL value (recursive).
fn json_to_cel(v: &Value) -> CelValue {
    use cel::objects::{Key as CelKey, Map as CelMap};
    use std::sync::Arc;
    match v {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                CelValue::UInt(u)
            } else if let Some(f) = n.as_f64() {
                CelValue::Float(f)
            } else {
                CelValue::String(Arc::new(n.to_string()))
            }
        }
        Value::String(s) => CelValue::String(Arc::new(s.clone())),
        Value::Array(arr) => CelValue::List(Arc::new(arr.iter().map(json_to_cel).collect())),
        Value::Object(map) => {
            let mut out = std::collections::HashMap::new();
            for (k, v) in map {
                out.insert(CelKey::String(Arc::new(k.clone())), json_to_cel(v));
            }
            CelValue::Map(CelMap { map: Arc::new(out) })
        }
    }
}

/// CEL → serde_json value. Lossy for types without JSON equivalents (bytes →
/// base64; duration/timestamp → string).
fn cel_to_json(v: CelValue) -> Value {
    match v {
        CelValue::Null => Value::Null,
        CelValue::Bool(b) => Value::Bool(b),
        CelValue::Int(i) => Value::Number(i.into()),
        CelValue::UInt(u) => Value::Number(u.into()),
        CelValue::Float(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        CelValue::String(s) => Value::String(s.as_ref().clone()),
        CelValue::Bytes(b) => {
            use base64::Engine as _;
            Value::String(base64::engine::general_purpose::STANDARD.encode(b.as_ref()))
        }
        CelValue::List(items) => {
            Value::Array(items.iter().map(|v| cel_to_json(v.clone())).collect())
        }
        CelValue::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in m.map.iter() {
                let key = match k {
                    cel::objects::Key::String(s) => s.as_ref().clone(),
                    cel::objects::Key::Int(i) => i.to_string(),
                    cel::objects::Key::Uint(u) => u.to_string(),
                    cel::objects::Key::Bool(b) => b.to_string(),
                };
                obj.insert(key, cel_to_json(v.clone()));
            }
            Value::Object(obj)
        }
        CelValue::Duration(d) => Value::String(d.to_string()),
        CelValue::Timestamp(t) => Value::String(t.to_rfc3339()),
        other => Value::String(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compile_rejects_invalid_cel() {
        let err = compile_params(&["this is not cel (((".to_owned()]).unwrap_err();
        assert!(err.contains("params[0]"));
    }

    #[test]
    fn evaluates_positional_params_in_order() {
        let compiled =
            compile_params(&["arguments.id".to_owned(), "arguments.page * 10".to_owned()]).unwrap();
        let out = evaluate_params(&compiled, &json!({ "id": 7, "page": 3 })).unwrap();
        assert_eq!(out, vec![json!(7), json!(30)]);
    }

    #[test]
    fn evaluates_string_and_bool() {
        let compiled =
            compile_params(&["arguments.name".to_owned(), "arguments.active".to_owned()]).unwrap();
        let out = evaluate_params(&compiled, &json!({ "name": "alice", "active": true })).unwrap();
        assert_eq!(out, vec![json!("alice"), json!(true)]);
    }

    #[test]
    fn runtime_failure_reports_source() {
        let compiled = compile_params(&["arguments.missing.deeply".to_owned()]).unwrap();
        let err = evaluate_params(&compiled, &json!({})).unwrap_err();
        assert!(err.contains("params[0]") && err.contains("arguments.missing"));
    }

    #[test]
    fn bind_rejects_non_scalar() {
        let mut q = Query::new("SELECT @P1".to_owned());
        let err = bind_param(&mut q, json!([1, 2, 3])).unwrap_err();
        assert!(err.contains("cannot be bound"));
    }

    #[test]
    fn bind_accepts_scalars_and_null() {
        let mut q = Query::new("SELECT @P1, @P2, @P3, @P4".to_owned());
        bind_param(&mut q, json!(1)).unwrap();
        bind_param(&mut q, json!("x")).unwrap();
        bind_param(&mut q, json!(true)).unwrap();
        bind_param(&mut q, Value::Null).unwrap();
    }
}
