use axum::{extract::{Multipart, Path as AxumPath, State}, Json};

use crate::dto::{Action, CheckResult, CheckRow, CheckSummary, JournalUploadResult};
use crate::error::api_error;
use crate::models::{apply_rules_to_bytes, decode_number, message_bytes};
use crate::state::AppState;

/// Обязательные колонки журнала действий (см. fixtures/README_RU.md).
pub(crate) const REQUIRED_JOURNAL_COLUMNS: [&str; 8] = [
    "capture", "session", "action_id", "start_utc", "end_utc",
    "action", "parameters", "observed_result",
];

/// Лимит загружаемого журнала: 5 МиБ — журнал это текст, больше не бывает.
pub(crate) const MAX_JOURNAL_BYTES: usize = 5 * 1024 * 1024;

/// Путь per-capture журнала: data/captures/<id>/journal.csv.
pub(crate) fn per_capture_journal_path(data_dir: &std::path::Path, capture_id: &str) -> std::path::PathBuf {
    data_dir.join("captures").join(capture_id).join("journal.csv")
}

/// Путь глобального журнала: data/journal_global.csv.
pub(crate) fn global_journal_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("journal_global.csv")
}

#[derive(serde::Deserialize, Clone)]
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
    let (actions, _, _) = load_actions_for_capture(&state, &capture_id, &wanted_file);
    Json(actions.into_iter().map(|(a, _, _)| a).collect())
}

/// Разобрать байты CSV-журнала: проверка шапки + подсчёт битых строк.
/// Возвращает все строки (с колонкой capture) и число пропущенных.
fn parse_journal_bytes(bytes: &[u8]) -> Result<(Vec<JournalRow>, usize), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "journal must be UTF-8 CSV".to_string())?;
    let mut rdr = csv::Reader::from_reader(text.as_bytes());
    let headers = rdr.headers().map_err(|e| format!("bad CSV header: {}", e))?;
    let names: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    for col in REQUIRED_JOURNAL_COLUMNS {
        if !names.iter().any(|h| h == col) {
            return Err(format!("journal missing column: {}", col));
        }
    }
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for record in rdr.deserialize::<JournalRow>() {
        match record {
            Ok(row) => rows.push(row),
            Err(_) => skipped += 1,
        }
    }
    Ok((rows, skipped))
}

fn row_matches_capture(capture: &str, wanted_file: &str) -> bool {
    capture == wanted_file
        || capture.ends_with(wanted_file)
        || wanted_file.ends_with(capture)
}

/// Строки -> действия. Если ни одна строка не совпала с именем файла
/// (свой журнал, залитый под чужое имя), привязываем все строки к записи —
/// иначе загрузка была бы бессмысленной.
fn rows_to_actions(rows: Vec<JournalRow>, wanted_file: &str) -> Vec<(Action, Option<i64>, Option<i64>)> {
    let filtered: Vec<JournalRow> = rows
        .iter()
        .filter(|row| wanted_file.is_empty() || row_matches_capture(&row.capture, wanted_file))
        .cloned()
        .collect();
    let picked = if filtered.is_empty() && !wanted_file.is_empty() { rows } else { filtered };
    picked
        .into_iter()
        .map(|row| {
            let ts = if row.start_utc.len() >= 19 { row.start_utc[11..19].to_string() } else { row.start_utc.clone() };
            let act = Action { id: row.action_id, timestamp: ts, name: row.action.clone(), description: row.action.clone(), value: parse_action_value(&row.parameters), expected_message_id: None };
            (act, parse_iso(&row.start_utc), parse_iso(&row.end_utc))
        })
        .collect()
}

/// Журнал для записи с приоритетом: per-capture > global > fixtures.
/// Возвращает действия и метку источника ("capture"/"global"/"fixtures"/"none").
pub(crate) fn load_actions_for_capture(
    state: &AppState,
    capture_id: &str,
    wanted_file: &str,
) -> (Vec<(Action, Option<i64>, Option<i64>)>, &'static str, usize) {
    let data_dir = state.data_dir.clone();
    let per_cap = per_capture_journal_path(&data_dir, capture_id);
    if let Ok(bytes) = std::fs::read(&per_cap) {
        if let Ok((rows, _)) = parse_journal_bytes(&bytes) {
            return (rows_to_actions(rows, wanted_file), "capture", 0);
        }
    }
    let glob = global_journal_path(&data_dir);
    if let Ok(bytes) = std::fs::read(&glob) {
        if let Ok((rows, _)) = parse_journal_bytes(&bytes) {
            return (rows_to_actions(rows, wanted_file), "global", 0);
        }
    }
    if let Ok(bytes) = std::fs::read("fixtures/action_journal.csv") {
        if let Ok((rows, _)) = parse_journal_bytes(&bytes) {
            return (rows_to_actions(rows, wanted_file), "fixtures", 0);
        }
    }
    (Vec::new(), "none", 0)
}

#[derive(serde::Deserialize)]
pub(crate) struct CheckBody {
    #[serde(alias = "captureId")]
    capture_id: String,
    #[serde(alias = "modelId")]
    model_id: Option<String>,
}

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
    match std::fs::read(journal) {
        Ok(bytes) => match parse_journal_bytes(&bytes) {
            Ok((rows, _)) => rows_to_actions(rows, wanted_file),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

/// Сохранить загруженный журнал и вернуть сводку. Общая логика обоих роутов.
fn store_journal_bytes(
    state: &AppState,
    scope: &str,
    capture_id: Option<&str>,
    file_name: &str,
    bytes: Vec<u8>,
) -> Result<JournalUploadResult, (axum::http::StatusCode, Json<crate::dto::ErrorResponse>)> {
    use axum::http::StatusCode;
    if bytes.is_empty() {
        return Err(api_error("File is empty or missing", StatusCode::BAD_REQUEST));
    }
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(api_error("Journal too large (max 5 MiB)", StatusCode::BAD_REQUEST));
    }
    let lname = file_name.to_lowercase();
    if !(lname.ends_with(".csv")) {
        return Err(api_error("Need a .csv journal file", StatusCode::BAD_REQUEST));
    }
    let (rows, skipped) = parse_journal_bytes(&bytes).map_err(|e| api_error(&e, StatusCode::BAD_REQUEST))?;
    if rows.is_empty() {
        return Err(api_error("Journal has no valid rows", StatusCode::BAD_REQUEST));
    }
    let data_dir = state.data_dir.clone();
    let (path, scope_name) = match scope {
        "global" => (global_journal_path(&data_dir), "global"),
        _ => match capture_id {
            Some(id) => {
                if !state.captures.read().unwrap().contains_key(id) {
                    return Err(api_error("Capture not found", StatusCode::NOT_FOUND));
                }
                (per_capture_journal_path(&data_dir, id), "capture")
            }
            None => return Err(api_error("Capture not found", StatusCode::NOT_FOUND)),
        },
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| api_error("IO Error", StatusCode::INTERNAL_SERVER_ERROR))?;
    }
    std::fs::write(&path, &bytes).map_err(|_| api_error("IO Error", StatusCode::INTERNAL_SERVER_ERROR))?;
    // Загруженный журнал — свежий: прошлая проверка по старому журналу устарела.
    if scope_name == "capture" {
        if let Some(id) = capture_id {
            state.last_check.write().unwrap().remove(id);
        }
    } else {
        state.last_check.write().unwrap().clear();
    }
    Ok(JournalUploadResult {
        actions: rows.len() as u32,
        skipped: skipped as u32,
        scope: scope_name.to_string(),
        source: file_name.to_string(),
    })
}

/// POST /api/v1/captures/:capture_id/journal — загрузка журнала.
/// multipart: file (csv) + необязательное текстовое поле scope=capture|global.
pub(crate) async fn upload_capture_journal(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
    mut multipart: Multipart,
) -> Result<(axum::http::StatusCode, Json<JournalUploadResult>), (axum::http::StatusCode, Json<crate::dto::ErrorResponse>)> {
    use axum::http::StatusCode;
    let mut file_bytes: Vec<u8> = Vec::new();
    let mut file_name = String::from("journal.csv");
    let mut scope = String::from("capture");
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "file" => {
                file_name = field.file_name().unwrap_or("journal.csv").to_string();
                file_bytes = field.bytes().await.map_err(|_| api_error("Failed to read file", StatusCode::BAD_REQUEST))?.to_vec();
            }
            "scope" => {
                if let Ok(text) = field.text().await {
                    let t = text.trim().to_lowercase();
                    if t == "global" || t == "capture" {
                        scope = t;
                    }
                }
            }
            _ => {}
        }
    }
    let scope_ref = scope.as_str();
    let cid_opt = if scope_ref == "global" { None } else { Some(capture_id.as_str()) };
    // Для global скоупа запись не обязательна, но роут её содержит — проверяем существование только для capture.
    if scope_ref != "global" && capture_id.contains("..") {
        return Err(api_error("Bad capture id", StatusCode::BAD_REQUEST));
    }
    let result = store_journal_bytes(&state, scope_ref, cid_opt, &file_name, file_bytes)?;
    Ok((StatusCode::CREATED, Json(result)))
}

/// POST /api/v1/journal — загрузка глобального журнала без привязки к записи.
pub(crate) async fn upload_global_journal(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(axum::http::StatusCode, Json<JournalUploadResult>), (axum::http::StatusCode, Json<crate::dto::ErrorResponse>)> {
    use axum::http::StatusCode;
    let mut file_bytes: Vec<u8> = Vec::new();
    let mut file_name = String::from("journal.csv");
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            file_name = field.file_name().unwrap_or("journal.csv").to_string();
            file_bytes = field.bytes().await.map_err(|_| api_error("Failed to read file", StatusCode::BAD_REQUEST))?.to_vec();
        }
    }
    let result = store_journal_bytes(&state, "global", None, &file_name, file_bytes)?;
    Ok((StatusCode::CREATED, Json(result)))
}

pub(crate) async fn check_model(
    State(state): State<AppState>,
    Json(body): Json<CheckBody>,
) -> Json<CheckResult> {
    Json(check_capture(&state, &body.capture_id, body.model_id.clone()))
}

/// Прогон модели по журналу без axum-обёрток — переиспользуется MCP-инструментом.
pub(crate) fn check_capture(
    state: &AppState,
    capture_id: &str,
    model_id: Option<String>,
) -> CheckResult {
    let wanted_file = state.captures.read().unwrap()
        .get(capture_id).map(|c| c.file_name.clone()).unwrap_or_default(); //ищем файлы только со своими действиями
    let (actions, _, _) = load_actions_for_capture(state, capture_id, &wanted_file);
    let msgs = state.messages.read().unwrap();
    let sids: Vec<String> = state.sessions.read().unwrap().values().filter(|s| s.capture_id == capture_id).map(|s| s.id.clone()).collect();
    let model = match model_id.as_ref().and_then(|id| state.models.read().unwrap().get(id).cloned()) {
        Some(m) => Some(m),
        None => state.models.read().unwrap().values().next().cloned(),
    };
    let mut rows: Vec<CheckRow> = Vec::new();
    for (a, start_us, end_us) in &actions {
        let hit = find_message(&msgs, &sids, *start_us, *end_us);
        let (status, extracted, mid) = match (hit, model.as_ref()) {
            (Some(m), Some(md)) => {
                let bytes = message_bytes(state, m);
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
    let known = state.captures.read().unwrap().contains_key(capture_id);
    let result = CheckResult {
        rows,
        summary: CheckSummary { total, ok, partial, unknown, error },
        model_id,
        model_name: None,
    };
    // last_check — только для известных записей: иначе report/generate
    // находит чужой мусор по never-импортированному id
    if known {
        state.last_check.write().unwrap().insert(capture_id.to_string(), result.clone());
    }
    result
}
