use std::collections::HashMap;

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use crate::dto::{Model, ModelField, ModelRule};
use crate::error::api_error;
use crate::state::AppState;

fn ident(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().next().unwrap().is_ascii_digit() {
        out = format!("f_{out}");
    }
    out
}

fn offset_expr(offset: &Value) -> String {
    if let Some(n) = offset.as_u64() {
        return n.to_string();
    }
    if offset.as_str() == Some("end-2") {
        return "total - 2".to_string();
    }
    "0".to_string()
}

fn length_expr(length: &Value, off: &str) -> String {
    if let Some(n) = length.as_u64() {
        return n.to_string();
    }
    match length.as_str() {
        Some("rest") => format!("total - ({off})"),
        Some("rest-2") => format!("total - ({off}) - 2"),
        _ => "0".to_string(),
    }
}

fn rust_type(ftype: &str) -> &str {
    match ftype {
        "uint8" => "u8",
        "uint16be" | "uint16le" => "u16",
        "uint32be" | "uint32le" => "u32",
        "string" => "String",
        _ => "Vec<u8>",
    }
}

fn rust_decode_field(f: &ModelField) -> String {
    let off = offset_expr(&f.offset);
    let len = length_expr(&f.length, &off);
    let conv = match f.field_type.as_str() {
        "uint8" => "bytes[o] as u64".to_string(),
        "uint16be" => "u16::from_be_bytes([bytes[o], bytes[o + 1]]) as u64".to_string(),
        "uint16le" => "u16::from_le_bytes([bytes[o], bytes[o + 1]]) as u64".to_string(),
        "uint32be" => "u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]) as u64".to_string(),
        "uint32le" => "u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]) as u64".to_string(),
        "string" => "String::from_utf8_lossy(&bytes[o..o + l]).into_owned()".to_string(),
        _ => "bytes[o..o + l].to_vec()".to_string(),
    };
    let store = match f.field_type.as_str() {
        "string" => "FieldValue::Text(v)".to_string(),
        "uint8" | "uint16be" | "uint16le" | "uint32be" | "uint32le" => "FieldValue::Num(v)".to_string(),
        _ => "FieldValue::Bytes(v)".to_string(),
    };
    format!("    let (o, l) = ({off} as usize, {len} as usize);\n    if o + l <= total {{\n        let v = {conv};\n        fields.push(Field {{ name: \"{n}\", value: {store} }});\n    }}", n = f.name)
}

fn rust_condition(rule: &ModelRule) -> String {
    let mut conds = Vec::new();
    if let Some(o) = rule.condition.opcode {
        conds.push(format!("bytes.get(2) == Some(&{o})"));
    }
    if let Some(ref ops) = rule.condition.opcodes {
        conds.push(format!("matches!(bytes.get(2), Some(x) if [{list}].contains(x))", list = ops.iter().map(|o| o.to_string()).collect::<Vec<_>>().join(", ")));
    }
    if let Some(le) = rule.condition.length_equals {
        conds.push(format!("bytes.len() > 4 && u16::from_be_bytes([bytes[3], bytes[4]]) == {le}"));
    }
    if let Some(m) = rule.condition.max_message_length {
        conds.push(format!("(bytes.len() as u32) <= {m}"));
    }
    if conds.is_empty() {
        "true".to_string()
    } else {
        conds.join(" && ")
    }
}

fn gen_rust(model: &Model) -> String {
    let mut out = String::new();
    out.push_str(&format!("// auto-generated from model \"{}\" ({})\n", model.name, model.id));
    out.push_str("// semantics mirror apply_rules_to_bytes: first matching rule wins, opcode = byte 2, length = u16be at 3\n\n");
    out.push_str("#[derive(Debug, Clone, PartialEq)]\npub enum FieldValue { Num(u64), Bytes(Vec<u8>), Text(String) }\n\n");
    out.push_str("#[derive(Debug, Clone, PartialEq)]\npub struct Field { pub name: &'static str, pub value: FieldValue }\n\n");
    out.push_str("#[derive(Debug, Clone, PartialEq)]\npub struct Decoded { pub rule: &'static str, pub fields: Vec<Field> }\n\n");
    for rule in &model.rules {
        let rid = ident(&rule.id);
        out.push_str(&format!("fn rule_{rid}(bytes: &[u8]) -> Option<Decoded> {{\n"));
        out.push_str(&format!("    if !({}) {{ return None; }}\n", rust_condition(rule)));
        out.push_str("    let total = bytes.len();\n    let mut fields = Vec::new();\n");
        for f in &rule.fields {
            out.push_str(&rust_decode_field(f));
            out.push('\n');
        }
        out.push_str(&format!("    Some(Decoded {{ rule: {:?}, fields }})\n}}\n\n", rule.name));
    }
    out.push_str("pub fn decode(bytes: &[u8]) -> Option<Decoded> {\n");
    for rule in &model.rules {
        let rid = ident(&rule.id);
        out.push_str(&format!("    if let Some(d) = rule_{rid}(bytes) {{ return Some(d); }}\n"));
    }
    out.push_str("    None\n}\n\n");
    out.push_str("fn field_layout(rule: &str, name: &str, total: usize) -> Option<(usize, usize)> {\n");
    for rule in &model.rules {
        out.push_str(&format!("    if rule == {:?} {{\n", rule.name));
        for f in &rule.fields {
            let off = offset_expr(&f.offset);
            let len = length_expr(&f.length, &off);
            out.push_str(&format!("        if name == {:?} {{ return Some(({off} as usize, {len} as usize)); }}\n", f.name));
        }
        out.push_str("    }\n");
    }
    out.push_str("    None\n}\n\n");
    out.push_str("pub fn encode(rule: &str, values: &[(&str, FieldValue)], total_len: usize) -> Option<Vec<u8>> {\n");
    out.push_str("    let mut out = vec![0u8; total_len];\n");
    out.push_str("    match rule {\n");
    for rule in &model.rules {
        out.push_str(&format!("        {:?} => {{\n", rule.name));
        if let Some(o) = rule.condition.opcode {
            out.push_str(&format!("            if total_len <= 2 {{ return None; }}\n            out[2] = {o};\n"));
        }
        if let Some(ref ops) = rule.condition.opcodes {
            let first = ops.first().copied().unwrap_or(0);
            out.push_str(&format!("            if total_len <= 2 {{ return None; }}\n            out[2] = {first};\n"));
        }
        if let Some(le) = rule.condition.length_equals {
            out.push_str(&format!("            if total_len <= 4 {{ return None; }}\n            out[3..5].copy_from_slice(&{le}u16.to_be_bytes());\n"));
        }
        if let Some(m) = rule.condition.max_message_length {
            out.push_str(&format!("            if (total_len as u32) > {m} {{ return None; }}\n"));
        }
        out.push_str("        }\n");
    }
    out.push_str("        _ => return None,\n    }\n");
    out.push_str("    for (name, value) in values {\n");
    out.push_str("        let (off, len) = field_layout(rule, name, total_len)?;\n");
    out.push_str("        if off + len > total_len { return None; }\n");
    out.push_str("        match value {\n");
    out.push_str("            FieldValue::Num(v) => { let b = v.to_be_bytes(); let k = len.min(8); out[off + len - k..off + len].copy_from_slice(&b[8 - k..]); }\n");
    out.push_str("            FieldValue::Bytes(v) => { out[off..off + len.min(v.len())].copy_from_slice(&v[..len.min(v.len())]); }\n");
    out.push_str("            FieldValue::Text(v) => { let b = v.as_bytes(); out[off..off + len.min(b.len())].copy_from_slice(&b[..len.min(b.len())]); }\n");
    out.push_str("        }\n    }\n    Some(out)\n}\n");
    out
}

fn gen_python(model: &Model) -> String {
    let mut out = String::new();
    out.push_str(&format!("# auto-generated from model \"{}\" ({})\n", model.name, model.id));
    out.push_str("# first matching rule wins; opcode = byte 2, length = u16be at 3\nimport struct\n\n");
    for rule in &model.rules {
        let rid = ident(&rule.id);
        out.push_str(&format!("def decode_{rid}(data: bytes):\n"));
        let mut conds = Vec::new();
        if let Some(o) = rule.condition.opcode {
            conds.push(format!("len(data) > 2 and data[2] == {o}"));
        }
        if let Some(ref ops) = rule.condition.opcodes {
            conds.push(format!("len(data) > 2 and data[2] in {ops:?}"));
        }
        if let Some(le) = rule.condition.length_equals {
            conds.push(format!("len(data) > 4 and int.from_bytes(data[3:5], 'big') == {le}"));
        }
        if let Some(m) = rule.condition.max_message_length {
            conds.push(format!("len(data) <= {m}"));
        }
        let cond = if conds.is_empty() { "True".to_string() } else { conds.join(" and ") };
        out.push_str(&format!("    if not ({cond}):\n        return None\n"));
        out.push_str("    total = len(data)\n    fields = {}\n");
        for f in &rule.fields {
            let off = offset_expr(&f.offset).replace("total", "total");
            let len = length_expr(&f.length, &off).replace("total", "total");
            let conv = match f.field_type.as_str() {
                "uint8" => "data[o]",
                "uint16be" => "int.from_bytes(data[o:o+2], 'big')",
                "uint16le" => "int.from_bytes(data[o:o+2], 'little')",
                "uint32be" => "int.from_bytes(data[o:o+4], 'big')",
                "uint32le" => "int.from_bytes(data[o:o+4], 'little')",
                "string" => "data[o:o+l].decode('utf-8', 'replace')",
                _ => "bytes(data[o:o+l])",
            };
            out.push_str(&format!("    o, l = {off}, {len}\n    fields[{fname:?}] = {conv} if o + l <= total and l >= 0 and o >= 0 else None\n", fname = f.name));
        }
        out.push_str(&format!("    return {{'rule': {rname:?}, 'fields': fields}}\n\n", rname = rule.name));
    }
    out.push_str("def decode(data: bytes):\n");
    for rule in &model.rules {
        let rid = ident(&rule.id);
        out.push_str(&format!("    r = decode_{rid}(data)\n    if r is not None:\n        return r\n"));
    }
    out.push_str("    return None\n");
    out
}

fn gen_c(model: &Model) -> String {
    let mut out = String::new();
    out.push_str(&format!("/* auto-generated from model \"{}\" ({}) */\n", model.name, model.id));
    out.push_str("/* first matching rule wins; opcode = byte 2, length = u16be at 3 */\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n");
    out.push_str("#define PL_MAX_FIELDS 16\n\ntypedef struct { const char *name; uint64_t num; const uint8_t *bytes; size_t len; int is_num; } pl_field_t;\ntypedef struct { const char *rule; pl_field_t fields[PL_MAX_FIELDS]; size_t nfields; } pl_decoded_t;\n\n");
    out.push_str("static uint16_t pl_u16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }\nstatic uint32_t pl_u32be(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }\n\n");
    for rule in &model.rules {
        let rid = ident(&rule.id);
        out.push_str(&format!("static int decode_{rid}(const uint8_t *data, size_t total, pl_decoded_t *out) {{\n"));
        out.push_str("    size_t n = 0;\n");
        let mut conds = Vec::new();
        if let Some(o) = rule.condition.opcode {
            conds.push(format!("(total > 2 && data[2] == {o})"));
        }
        if let Some(ref ops) = rule.condition.opcodes {
            conds.push(format!("(total > 2 && ({cond}))", cond = ops.iter().map(|o| format!("data[2] == {o}")).collect::<Vec<_>>().join(" || ")));
        }
        if let Some(le) = rule.condition.length_equals {
            conds.push(format!("(total > 4 && pl_u16be(data + 3) == {le})"));
        }
        if let Some(m) = rule.condition.max_message_length {
            conds.push(format!("(total <= {m})"));
        }
        let cond = if conds.is_empty() { "1".to_string() } else { conds.join(" && ") };
        out.push_str(&format!("    if (!({cond})) return 0;\n"));
        for f in &rule.fields {
            let off = offset_expr(&f.offset);
            let len = length_expr(&f.length, &off);
            out.push_str(&format!("    {{ long o = (long)({off}); long l = (long)({len}); if (o >= 0 && l >= 0 && (size_t)(o + l) <= total && n < PL_MAX_FIELDS) {{ pl_field_t *fl = &out->fields[n++]; fl->name = {fname:?}; ", fname = f.name));
            let body = match f.field_type.as_str() {
                "uint8" => "fl->num = data[o]; fl->is_num = 1;".to_string(),
                "uint16be" => "if (l >= 2) { fl->num = pl_u16be(data + o); fl->is_num = 1; } else { n--; }".to_string(),
                "uint16le" => "if (l >= 2) { fl->num = data[o] | ((uint64_t)data[o+1] << 8); fl->is_num = 1; } else { n--; }".to_string(),
                "uint32be" => "if (l >= 4) { fl->num = pl_u32be(data + o); fl->is_num = 1; } else { n--; }".to_string(),
                "uint32le" => "if (l >= 4) { fl->num = data[o] | ((uint64_t)data[o+1] << 8) | ((uint64_t)data[o+2] << 16) | ((uint64_t)data[o+3] << 24); fl->is_num = 1; } else { n--; }".to_string(),
                _ => "fl->bytes = data + o; fl->len = (size_t)l; fl->is_num = 0;".to_string(),
            };
            out.push_str(&body);
            out.push_str(" } }\n");
        }
        out.push_str(&format!("    out->rule = {rname:?}; out->nfields = n; return 1;\n}}\n\n", rname = rule.name));
    }
    out.push_str("static int pl_decode(const uint8_t *data, size_t total, pl_decoded_t *out) {\n");
    for rule in &model.rules {
        let rid = ident(&rule.id);
        out.push_str(&format!("    if (decode_{rid}(data, total, out)) return 1;\n"));
    }
    out.push_str("    return 0;\n}\n");
    out
}

pub(crate) async fn codegen(
    State(state): State<AppState>,
    AxumPath(model_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    use crate::error::api_error;
    let model = match state.models.read().unwrap().get(&model_id).cloned() {
        Some(m) => m,
        None => return Err(api_error("Model not found", StatusCode::NOT_FOUND)),
    };
    let lang = params.get("lang").map(|s| s.as_str()).unwrap_or("rust");
    let (code, filename) = match lang {
        "python" | "py" => (gen_python(&model), format!("model_{}.py", ident(&model.id))),
        "c" => (gen_c(&model), format!("model_{}.c", ident(&model.id))),
        _ => (gen_rust(&model), format!("model_{}.rs", ident(&model.id))),
    };
    Ok(Json(json!({ "lang": lang, "filename": filename, "code": code })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{ModelField, ModelRule, ModelRuleCondition};

    fn model() -> Model {
        Model {
            id: "m".to_string(),
            name: "M".to_string(),
            status: "draft".to_string(),
            created_at: "".to_string(),
            updated_at: "".to_string(),
            rules: vec![ModelRule {
                id: "r 1".to_string(),
                name: "R".to_string(),
                condition: ModelRuleCondition { opcode: Some(1), opcodes: None, length_equals: None, max_message_length: None },
                fields: vec![ModelField {
                    name: "op".to_string(),
                    field_type: "uint8".to_string(),
                    offset: Value::from(2),
                    length: Value::from(1),
                    note: None,
                }],
            }],
        }
    }

    #[test]
    fn rust_contains_dispatcher_and_rule() {
        let code = gen_rust(&model());
        assert!(code.contains("pub fn decode(bytes: &[u8])"));
        assert!(code.contains("bytes.get(2) == Some(&1)"));
        assert!(code.contains("rule_r_1"));
    }

    #[test]
    fn python_and_c_contain_rule() {
        let code = gen_python(&model());
        assert!(code.contains("def decode(data: bytes):"));
        assert!(code.contains("data[2] == 1"));
        let code = gen_c(&model());
        assert!(code.contains("pl_decode"));
        assert!(code.contains("data[2] == 1"));
    }

    #[test]
    fn ident_sanitizes() {
        assert_eq!(ident("r 1"), "r_1");
        assert_eq!(ident("9lives"), "f_9lives");
        assert_eq!(ident(""), "f_");
    }
}
