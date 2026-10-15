use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    Json,
};

use crate::dto::Model;
use crate::error::api_error;
use crate::state::{persist_capture, persist_global, AppState};

fn rule_matches(bytes: &[u8], cond: &crate::dto::ModelRuleCondition) -> bool {
    if let Some(max) = cond.max_message_length {
        if bytes.len() as u32 > max {
            return false;
        }
    }
    if let Some(mlen) = cond.message_length {
        if bytes.len() as u32 != mlen {
            return false;
        }
    }
    if cond.opcode.is_some() || cond.opcodes.is_some() {
        if bytes.len() <= 2 {
            return false;
        }
        let op = bytes[2] as u32;
        if let Some(o) = cond.opcode {
            if op != o {
                return false;
            }
        }
        if let Some(ref ops) = cond.opcodes {
            if !ops.contains(&op) {
                return false;
            }
        }
    }
    if let Some(le) = cond.length_equals {
        if bytes.len() <= 4 {
            return false;
        }
        if u16::from_be_bytes([bytes[3], bytes[4]]) as u32 != le {
            return false;
        }
    }
    true
}

fn resolve_offset(v: &serde_json::Value, total: usize) -> Option<isize> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().map(|x| x as isize),
        serde_json::Value::String(s) if s == "end-2" => Some(total as isize - 2),
        _ => None,
    }
}

fn resolve_length(v: &serde_json::Value, offset: usize, total: usize) -> Option<isize> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().map(|x| x as isize),
        serde_json::Value::String(s) if s == "rest" => Some(total as isize - offset as isize),
        serde_json::Value::String(s) if s == "rest-2" => Some(total as isize - offset as isize - 2),
        _ => None,
    }
}

fn format_field_value(bytes: &[u8], ftype: &str) -> String {
    match ftype {
        "uint8" => {
            if bytes.is_empty() {
                return "—".to_string();
            }
            format!("0x{:02X}", bytes[0])
        }
        "uint16be" => {
            if bytes.len() < 2 {
                return "—".to_string();
            }
            format!("0x{:04X}", u16::from_be_bytes([bytes[0], bytes[1]]))
        }
        "uint32be" => {
            if bytes.len() < 4 {
                return "—".to_string();
            }
            format!(
                "0x{:08X}",
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            )
        }
        "string" => bytes
            .iter()
            .map(|b| {
                if (0x20..=0x7e).contains(b) {
                    *b as char
                } else {
                    '·'
                }
            })
            .collect(),
        _ => format!("{} Б", bytes.len()),
    }
}

pub(crate) fn apply_rules_to_bytes(
    bytes: &[u8],
    model: &crate::dto::Model,
) -> (Vec<crate::dto::MessageField>, String, Option<String>) {
    let total = bytes.len();
    let rule = match model.rules.iter().find(|r| rule_matches(bytes, &r.condition)) {
        Some(r) => r,
        None => return (Vec::new(), "not-parsed".to_string(), None),
    };
    let mut fields = Vec::new();
    for f in &rule.fields {
        let offset = match resolve_offset(&f.offset, total) {
            Some(o) => o,
            None => continue,
        };
        if offset < 0 {
            continue;
        }
        let length = match resolve_length(&f.length, offset as usize, total) {
            Some(l) => l,
            None => continue,
        };
        if length < 0 || offset as usize + length as usize > total {
            continue;
        }
        let (o, l) = (offset as usize, length as usize);
        fields.push(crate::dto::MessageField {
            id: format!("{}-f-{}", rule.id, f.name),
            name: f.name.clone(),
            field_type: f.field_type.clone(),
            value: format_field_value(&bytes[o..o + l], &f.field_type),
            range: crate::dto::ByteRange {
                offset: o as u64,
                length: l as u64,
            },
            note: f.note.clone(),
            rule_id: Some(rule.id.clone()),
        });
    }
    let mut spans: Vec<(usize, usize)> = fields
        .iter()
        .map(|f| (f.range.offset as usize, f.range.length as usize))
        .filter(|(_, l)| *l > 0)
        .collect();
    spans.sort();
    let mut gaps = 0usize;
    let mut covered = 0usize;
    for (o, l) in spans {
        if o > covered {
            gaps += 1;
        }
        covered = covered.max(o + l);
    }
    if covered < total {
        gaps += 1;
    }
    let status = if gaps == 0 { "parsed" } else { "partial" }.to_string();
    (fields, status, Some(rule.id.clone()))
}

pub(crate) fn message_bytes(state: &crate::state::AppState, msg: &crate::dto::Message) -> Vec<u8> {
    let start = msg.byte_offset as usize;
    let sessions = state.sessions.read().unwrap();
    let stream = match sessions.get(&msg.session_id).and_then(|s| state.raw_bytes.read().unwrap().get(&s.capture_id).cloned()) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let end = start.saturating_add(msg.length as usize).min(stream.len());
    if start >= stream.len() { Vec::new() } else { stream[start..end].to_vec() }
}

pub(crate) fn decode_number(bytes: &[u8], ftype: &str) -> Option<f64> {
    match ftype {
        "uint8" => bytes.first().map(|b| *b as f64),
        "uint16be" => (bytes.len() >= 2).then(|| u16::from_be_bytes([bytes[0], bytes[1]]) as f64),
        "uint16le" => (bytes.len() >= 2).then(|| u16::from_le_bytes([bytes[0], bytes[1]]) as f64),
        "uint32be" => (bytes.len() >= 4).then(|| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64),
        "uint32le" => (bytes.len() >= 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64),
        _ => None,
    }
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
pub(crate) struct ApplyBody { modelId: Option<String>, model_id: Option<String> }

pub(crate) async fn apply_model(
    State(state): State<AppState>,
    AxumPath(message_id): AxumPath<String>,
    Json(body): Json<ApplyBody>,
) -> Json<Vec<crate::dto::MessageField>> {
    let mid = body.modelId.or(body.model_id).unwrap_or_default();
    let model = match state.models.read().unwrap().get(&mid).cloned() {
        Some(m) => m,
        None => return Json(vec![]),
    };
    let msg = match state.messages.read().unwrap().get(&message_id).cloned() {
        Some(m) => m,
        None => return Json(vec![]),
    };
    let bytes: Vec<u8> = state
        .sessions
        .read()
        .unwrap()
        .get(&msg.session_id)
        .and_then(|s| state.raw_bytes.read().unwrap().get(&s.capture_id).cloned())
        .map(|stream| {
            let start = msg.byte_offset as usize;
            let end = start.saturating_add(msg.length as usize).min(stream.len());
            if start >= stream.len() {
                Vec::new()
            } else {
                stream[start..end].to_vec()
            }
        })
        .unwrap_or_default();
    let (fields, interpretation, _) = apply_rules_to_bytes(&bytes, &model);
    let status = if interpretation == "not-parsed" {
        "unknown".to_string()
    } else {
        interpretation.clone()
    };
    if let Some(stored) = state.messages.write().unwrap().get_mut(&message_id) {
        stored.fields = fields.clone();
        stored.status = status;
        stored.interpretation = interpretation;
        stored.model_id = Some(mid.clone());
    }
    if let Some(sess) = state.sessions.read().unwrap().get(&msg.session_id) {
        persist_capture(&state, &sess.capture_id);
    }
    Json(fields)
}

pub(crate) async fn list_models(State(state): State<AppState>) -> Json<Vec<Model>> {
    let models = state.models.read().unwrap();
    let list: Vec<Model> = models.values().cloned().collect();
    Json(list)
}

pub(crate) async fn save_model(
    State(state): State<AppState>,
    Json(mut model): Json<Model>,
) -> StatusCode {
    model.updated_at = chrono::Utc::now().to_rfc3339();
    state.models.write().unwrap().insert(model.id.clone(), model);
    persist_global(&state);
    StatusCode::NO_CONTENT
}

pub(crate) async fn remove_model(
    State(state): State<AppState>,
    AxumPath(model_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    eprintln!("[models] remove {model_id}");
    {
        let mut models = state.models.write().unwrap();
        if models.remove(&model_id).is_none() {
            return Err(api_error("Model not found", StatusCode::NOT_FOUND));
        }
        // guard дропается здесь: persist_global ниже снова берёт models.read(),
        // std::sync::RwLock не реентерабелен — держать write через persist нельзя.
    }
    persist_global(&state);
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{ModelField, ModelRule, ModelRuleCondition};

    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xAA, 0x55, opcode];
        let len = payload.len() as u16;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        let crc = v.iter().fold(0u16, |a, b| a.wrapping_add(*b as u16));
        v.extend_from_slice(&crc.to_be_bytes());
        v
    }

    fn model() -> crate::dto::Model {
        crate::dto::Model {
            id: "m".to_string(),
            name: "M".to_string(),
            status: "draft".to_string(),
            created_at: "".to_string(),
            updated_at: "".to_string(),
            rules: vec![crate::dto::ModelRule {
                id: "r".to_string(),
                name: "R".to_string(),
                condition: ModelRuleCondition { opcode: Some(0x01), opcodes: None, length_equals: None, max_message_length: None, message_length: None },
                fields: vec![
                    ModelField { name: "marker".to_string(), field_type: "bytes".to_string(), offset: serde_json::Value::from(0), length: serde_json::Value::from(2), note: None },
                    ModelField { name: "op".to_string(), field_type: "uint8".to_string(), offset: serde_json::Value::from(2), length: serde_json::Value::from(1), note: None },
                    ModelField { name: "len".to_string(), field_type: "uint16be".to_string(), offset: serde_json::Value::from(3), length: serde_json::Value::from(2), note: None },
                    ModelField { name: "payload".to_string(), field_type: "bytes".to_string(), offset: serde_json::Value::from(5), length: serde_json::Value::from("rest-2"), note: None },
                    ModelField { name: "crc".to_string(), field_type: "uint16be".to_string(), offset: serde_json::Value::from("end-2"), length: serde_json::Value::from(2), note: None },
                ],
            }],
        }
    }

    #[test]
    fn roundtrip_opcode_rule() {
        let md = model();
        let bytes = frame(0x01, &[0x07, 0x08]);
        let (fields, status, rule) = apply_rules_to_bytes(&bytes, &md);
        assert_eq!(status, "parsed");
        assert_eq!(rule.as_deref(), Some("r"));
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[1].value, "0x01");
        assert_eq!(fields[2].value, "0x0002");
        for f in &fields {
            let back = decode_number(&bytes[f.range.offset as usize..(f.range.offset + f.range.length) as usize], &f.field_type);
            if ["uint8", "uint16be", "uint16le", "uint32be", "uint32le"].contains(&f.field_type.as_str()) {
                assert!(back.is_some());
            } else {
                assert!(back.is_none());
            }
        }
    }

    #[test]
    fn message_length_disambiguates_same_opcode() {
        let mut md = model();
        md.rules.push(crate::dto::ModelRule {
            id: "r-long".to_string(),
            name: "R-long".to_string(),
            condition: ModelRuleCondition { opcode: Some(0x01), opcodes: None, length_equals: None, max_message_length: None, message_length: Some(9) },
            fields: vec![],
        });
        // короткое сообщение: первое правило (без message_length) срабатывает
        let short = frame(0x01, &[0x07, 0x08]);
        let (_, status, rule) = apply_rules_to_bytes(&short, &md);
        assert_eq!(status, "parsed");
        assert_eq!(rule.as_deref(), Some("r"));
        // длинное сообщение opcode 0x01: первое правило тоже матчится (порядок),
        // а правило с чужой длиной — нет
        let cond = ModelRuleCondition { opcode: Some(0x01), opcodes: None, length_equals: None, max_message_length: None, message_length: Some(100) };
        assert!(!rule_matches(&short, &cond));
        assert!(rule_matches(&short, &ModelRuleCondition { opcode: Some(0x01), opcodes: None, length_equals: None, max_message_length: None, message_length: Some(short.len() as u32) }));
    }

    #[test]
    fn roundtrip_wrong_opcode_no_match() {
        let md = model();
        let bytes = frame(0x02, &[0x07]);
        let (fields, status, rule) = apply_rules_to_bytes(&bytes, &md);
        assert_eq!(status, "not-parsed");
        assert!(rule.is_none());
        assert!(fields.is_empty());
    }

    #[test]
    fn roundtrip_out_of_range_field_skipped() {
        let mut md = model();
        md.rules[0].fields.push(ModelField { name: "big".to_string(), field_type: "uint32be".to_string(), offset: serde_json::Value::from(100), length: serde_json::Value::from(4), note: None });
        let bytes = frame(0x01, &[0x07]);
        let (fields, status, _) = apply_rules_to_bytes(&bytes, &md);
        assert_eq!(status, "parsed");
        assert!(fields.iter().all(|f| f.name != "big")); // out-of-range поле пропущено, остальное покрыло всё
        assert_eq!(decode_number(&[0xA6], "uint8"), Some(166.0));
        assert_eq!(decode_number(&[0xA6], "uint32be"), None);
        assert_eq!(decode_number(&[], "bytes"), None);
    }
}
