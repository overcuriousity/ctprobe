use crate::query::QueryResult;
use serde_json::Value;

/// Certificate fields are attacker-controlled: a leading formula character
/// would run in a spreadsheet, so such strings get an apostrophe.
fn neutralise(s: &str) -> String {
    match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{s}"),
        _ => s.to_string(),
    }
}

fn field(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => neutralise(s),
        Value::Array(a) => {
            neutralise(&a.iter().map(field).collect::<Vec<_>>().join(" "))
        }
        other => other.to_string(),
    }
}

fn quote(s: String) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn to_csv(r: &QueryResult) -> String {
    let mut out = r.columns.iter().map(|c| quote(neutralise(c))).collect::<Vec<_>>().join(",");
    out.push('\n');
    for row in &r.rows {
        out.push_str(&row.iter().map(|v| quote(field(v))).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}
