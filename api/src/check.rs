use axum::{extract::{Path as AxumPath, State}, Json};

use crate::dto::{Action, CheckResult, CheckRow, CheckSummary};
use crate::models::{apply_rules_to_bytes, decode_number, message_bytes};
use crate::state::AppState;

#[derive(serde::Deserialize)]
struct JournalRow {
    capture: String,
    action_id: String,
    start_utc: String,
    end_utc: String,
    action: String,
    parameters: String,
    observed_result: String,
}

pub(crate) fn parse_action_value(raw: &str) -> Option<f64> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    for key in ["threshold_c", "count", "period_ms"] { //крч проходим по ключам с приоритетным выбором 
        if let Some(n) = v.get(key).and_then(|x| x.as_f64()) { // ключ есть и это число
            return Some(n);
        } 
    }
    None
}

pub(crate) async fn list_actions(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
) -> Json<Vec<Action>> {
    let wanted_file = state.captures.read().unwrap()
        .get(&capture_id).map(|c| c.file_name.clone()).unwrap_or_default();
    let mut rdr = match csv::Reader::from_path("fixtures/action_journal.csv") {
        Ok(r) => r,
        Err(_) => return Json(vec![]),
    };
    let mut out = Vec::new();
    for row in rdr.deserialize::<JournalRow>().flatten() {
        if !wanted_file.is_empty()
            && row.capture != wanted_file
            && !row.capture.ends_with(&wanted_file)
            && !wanted_file.ends_with(&row.capture) {
            continue;
        }
        let timestamp = if row.start_utc.len() >= 19 {
            row.start_utc[11..19].to_string()
        } else {
            row.start_utc.clone()
        };
        out.push(Action {
            id: row.action_id,
            timestamp,
            name: row.action.clone(),
            description: row.action.clone(),
            value: parse_action_value(&row.parameters), 
            expected_message_id: None, 
        });
    }
    Json(out)
}

#[derive(serde::Deserialize)]
pub(crate) struct CheckBody { capture_id: String, model_id: Option<String> }

pub(crate) fn parse_iso(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_micros())
}

fn find_message<'a>(
    msgs: &'a std::collections::HashMap<String, crate::dto::Message>,
    sids: &[String],
    start_us: Option<i64>,
    end_us: Option<i64>,
) -> Option<&'a crate::dto::Message> {
    let mut best_in: Option<(&'a crate::dto::Message, i64)> = None;
    let mut best_near: Option<(&'a crate::dto::Message, i64)> = None;
    for m in msgs.values().filter(|m| sids.contains(&m.session_id)) {
        let t = match parse_iso(&m.timestamp) {
            Some(t) => t,
            None => continue,
        };
        match (start_us, end_us) {
            (Some(s), Some(e)) if t >= s && t <= e => {
                if best_in.map(|(_, bt)| t < bt).unwrap_or(true) {
                    best_in = Some((m, t));
                }
            }
            _ => {
                if let Some(a) = start_us.or(end_us) {
                    let dt = (t - a).abs();
                    if dt <= 60_000_000 && best_near.map(|(_, bdt)| dt < bdt).unwrap_or(true) {
                        best_near = Some((m, dt));
                    }
                }
            }
        }
    }
    best_in.or(best_near).map(|(m, _)| m)
}

fn first_numeric(fields: &[crate::dto::MessageField], bytes: &[u8]) -> Option<(f64, String)> {
    for f in fields {
        let (o, l) = (f.range.offset as usize, f.range.length as usize);
        let slice = match bytes.get(o..o.saturating_add(l)) {
            Some(s) => s,
            None => continue,
        };
        if let Some(v) = decode_number(slice, &f.field_type) {
            return Some((v, format!("0x{:X} ({})", v as u64, v as u64)));
        }
    }
    None
}

pub(crate) fn load_actions(wanted_file: &str, journal: &str) -> Vec<(Action, Option<i64>, Option<i64>)> {
    let mut actions = Vec::new();
    if let Ok(mut rdr) = csv::Reader::from_path(journal) {
        for row in rdr.deserialize::<JournalRow>().flatten() { //парсим каждую строку csv, если не парсится то пропуск
            if !wanted_file.is_empty()
                && row.capture != wanted_file
                && !row.capture.ends_with(&wanted_file)
                && !wanted_file.ends_with(&row.capture) {
                continue;
            }
            let ts = if row.start_utc.len() >= 19 { row.start_utc[11..19].to_string() } else { row.start_utc.clone() }; //вырезка HH:MM:SS из iso
            let act = Action { id: row.action_id, timestamp: ts, name: row.action.clone(), description: row.action.clone(), value: parse_action_value(&row.parameters), expected_message_id: None };
            actions.push((act, parse_iso(&row.start_utc), parse_iso(&row.end_utc)));
        }
    }
    actions
}

pub(crate) async fn check_model(
    State(state): State<AppState>,
    Json(body): Json<CheckBody>,
) -> Json<CheckResult> {
    let wanted_file = state.captures.read().unwrap()
        .get(&body.capture_id).map(|c| c.file_name.clone()).unwrap_or_default(); //ищем файлы только со своими действиями
    let actions = load_actions(&wanted_file, "fixtures/action_journal.csv");
    let msgs = state.messages.read().unwrap();
    let sids: Vec<String> = state.sessions.read().unwrap().values().filter(|s| s.capture_id == body.capture_id).map(|s| s.id.clone()).collect();
    let model = match body.model_id.as_ref().and_then(|id| state.models.read().unwrap().get(id).cloned()) {
        Some(m) => Some(m),
        None => state.models.read().unwrap().values().next().cloned(),
    };
    let mut rows: Vec<CheckRow> = Vec::new();
    for (a, start_us, end_us) in &actions {
        let hit = find_message(&msgs, &sids, *start_us, *end_us);
        let (status, extracted, mid) = match (hit, model.as_ref()) {
            (Some(m), Some(md)) => {
                let bytes = message_bytes(&state, m);
                let (fields, interpretation, _) = apply_rules_to_bytes(&bytes, md);
                if interpretation == "not-parsed" {
                    ("unknown", "-".to_string(), Some(m.id.clone()))
                } else if let Some((v, txt)) = first_numeric(&fields, &bytes) {
                    match a.value {
                        Some(e) if (v - e).abs() < 1e-9 => ("ok", txt, Some(m.id.clone())),
                        Some(_) => ("error", txt, Some(m.id.clone())),
                        None => ("partial", txt, Some(m.id.clone())),
                    }
                } else {
                    let txt = fields.first().map(|f| f.value.clone()).unwrap_or_else(|| "-".to_string());
                    ("partial", txt, Some(m.id.clone()))
                }
            }
            (Some(m), None) => ("unknown", "-".to_string(), Some(m.id.clone())),
            (None, _) => ("unknown", "-".to_string(), None),
        };
        rows.push(CheckRow { id: format!("chk-{}", a.id), action_id: a.id.clone(), time: a.timestamp.clone(), action: a.name.clone(), expected: a.value, extracted, status: status.to_string(), message_id: mid });
    }
    let total = rows.len() as u32;
    let ok = rows.iter().filter(|r| r.status == "ok").count() as u32;
    let partial = rows.iter().filter(|r| r.status == "partial").count() as u32;
    let error = rows.iter().filter(|r| r.status == "error").count() as u32;
    let unknown = total - ok - partial - error;
    state.last_check.write().unwrap().insert(body.capture_id.clone(), CheckResult { rows: rows.clone(), summary: CheckSummary { total, ok, partial, unknown, error }, model_id: body.model_id.clone(), model_name: None });
    Json(CheckResult {
        rows,
        summary: CheckSummary { total, ok, partial, unknown, error },
        model_id: body.model_id,
        model_name: None,
    })
}
