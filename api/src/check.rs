use axum::{extract::{Path as AxumPath, State}, http::StatusCode, Json};

use crate::dto::{Action, CheckResult, CheckRow, CheckSummary};
use crate::error::api_error;
use crate::state::AppState;

#[derive(serde::Deserialize)]
struct JournalRow {
    capture: String,
    action_id: String,
    start_utc: String,
    action: String,
    parameters: String,
    observed_result: String,
}

fn parse_action_value(raw: &str) -> Option<f64> {
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
struct CheckBody { capture_id: String, model_id: Option<String> }

pub(crate) async fn check_model(
    State(state): State<AppState>,
    Json(body): Json<CheckBody>,
) -> Json<CheckResult> {
    let wanted_file = state.captures.read().unwrap()
        .get(&body.capture_id).map(|c| c.file_name.clone()).unwrap_or_default(); //ищем файлы только со своими действиями
    let mut actions: Vec<Action> = Vec::new(); 
    if let Ok(mut rdr) = csv::Reader::from_path("fixtures/action_journal.csv") {
        for row in rdr.deserialize::<JournalRow>().flatten() { //парсим каждую строку csv, если не парсится то пропуск
            if !wanted_file.is_empty()
                && row.capture != wanted_file
                && !row.capture.ends_with(&wanted_file)
                && !wanted_file.ends_with(&row.capture) {
                continue;
            }
            let ts = if row.start_utc.len() >= 19 { row.start_utc[11..19].to_string() } else { row.start_utc.clone() }; //вырезка HH:MM:SS из iso
            actions.push(Action { id: row.action_id, timestamp: ts, name: row.action.clone(), description: row.action.clone(), value: parse_action_value(&row.parameters), expected_message_id: None });
        }
    }
    let msgs = state.messages.read().unwrap();
    let sids: Vec<String> = state.sessions.read().unwrap().values().filter(|s| s.capture_id == body.capture_id).map(|s| s.id.clone()).collect();
    let mut rows: Vec<CheckRow> = Vec::new();
    for a in &actions {
        let hit = msgs.values().find(|m| sids.contains(&m.session_id));
        let (status, extracted, mid) = match hit {
            Some(m) => ("ok", "-".to_string(), Some(m.id.clone())),
            None => ("unknown", "-".to_string(), None),
        };
        rows.push(CheckRow { id: format!("chk-{}", a.id), action_id: a.id.clone(), time: a.timestamp.clone(), action: a.name.clone(), expected: a.value, extracted, status: status.to_string(), message_id: mid });
    }
    let total = rows.len() as u32;
    let ok = rows.iter().filter(|r| r.status == "ok").count() as u32;
    state.last_check.write().unwrap().insert(body.capture_id.clone(), CheckResult { rows: rows.clone(), summary: CheckSummary { total, ok, partial: 0, unknown: total - ok, error: 0 }, model_id: body.model_id.clone(), model_name: None });
    Json(CheckResult {
        rows,
        summary: CheckSummary { total, ok, partial: 0, unknown: total - ok, error: 0 },
        model_id: body.model_id,
        model_name: None,
    })
}
