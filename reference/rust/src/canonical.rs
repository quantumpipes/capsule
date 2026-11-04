//! Canonical JSON serialization for Capsules.
//!
//! Matches Python's json.dumps(capsule.to_dict(), sort_keys=True, separators=(",", ":"))
//! byte for byte on all 16 CPS golden vectors. Floats small or large enough for
//! Python to write in exponent form (below 1e-4, or 1e16 and above) are not yet
//! specified by CPS, and each reference writes them differently.
//!
//! This is THE critical function for cross-language compatibility.

use serde_json::Value;
use std::collections::BTreeMap;

/// Float-typed field paths that must always include a decimal point.
const FLOAT_PATHS: &[&str] = &[
    "reasoning.confidence",
    "reasoning.options.*.feasibility",
];

/// Serialize a JSON value to canonical form matching the CPS specification.
pub fn canonicalize(value: &Value) -> Result<String, String> {
    let mut buf = String::new();
    write_value(&mut buf, value, "")?;
    Ok(buf)
}

fn write_value(buf: &mut String, value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Null => buf.push_str("null"),
        Value::Bool(b) => buf.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if is_float_path(path) {
                write_float(buf, n);
            } else {
                buf.push_str(&n.to_string());
            }
        }
        Value::String(s) => write_json_string(buf, s),
        Value::Array(arr) => {
            buf.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                let child_path = if path.is_empty() {
                    "*".to_string()
                } else {
                    format!("{}.*", path)
                };
                write_value(buf, item, &child_path)?;
            }
            buf.push(']');
        }
        Value::Object(map) => {
            // serde_json::Map preserves insertion order; we need sorted keys
            let mut sorted: BTreeMap<&str, &Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.as_str(), v);
            }

            buf.push('{');
            let mut first = true;
            for (k, v) in &sorted {
                if !first {
                    buf.push(',');
                }
                first = false;
                write_json_string(buf, k);
                buf.push(':');
                let child_path = if path.is_empty() {
                    k.to_string()
                } else {
                    format!("{}.{}", path, k)
                };
                write_value(buf, v, &child_path)?;
            }
            buf.push('}');
        }
    }
    Ok(())
}

fn is_float_path(path: &str) -> bool {
    FLOAT_PATHS.contains(&path)
}

fn write_float(buf: &mut String, n: &serde_json::Number) {
    if let Some(f) = n.as_f64() {
        let s = format!("{}", f);
        if !s.contains('.') && !s.contains('e') {
            buf.push_str(&format!("{}.0", s));
        } else {
            buf.push_str(&s);
        }
    } else {
        buf.push_str(&n.to_string());
    }
}

fn write_json_string(buf: &mut String, s: &str) {
    buf.push('"');
    for ch in s.chars() {
        match ch {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\u{0008}' => buf.push_str("\\b"),
            '\u{000C}' => buf.push_str("\\f"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                buf.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => buf.push(c),
        }
    }
    buf.push('"');
}
