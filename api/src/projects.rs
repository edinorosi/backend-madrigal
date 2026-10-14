use std::path::Path as StdPath;

use axum::{
    body::Body,
    extract::{Multipart, Path as AxumPath, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use tar::Builder;
use uuid::Uuid;

use crate::dto::Capture;
use crate::error::api_error;
use crate::state::{persist_global, AppState};

pub(crate) async fn create_project(State(state): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let id = Uuid::new_v4().to_string();
    let name = body["name"].as_str().unwrap_or("Untitled Project").to_string();

    let new_capture = Capture {
       id: id.clone(),
       file_name: name,
       imported_at: chrono::Utc::now().to_rfc3339(),
       size_bytes: 0,
       session_count: 0,
   };

   state.captures.write().unwrap().insert(id.clone(), new_capture);

    Json(json!({ "id": id, "status": "created"}))
}

//Священный эндпоинт
pub(crate) async fn get_projects(State(state): State<AppState>) -> Json<serde_json::Value> {
    let captures = state.captures.read().unwrap(); 
    let list: Vec<serde_json::Value> = captures.values().map(|c| {
        json!({"id": c.id, "name": c.file_name})
    }).collect(); 
    Json(json!({"projects": list})) 
}

pub(crate) async fn get_project(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> Result<Json<serde_json::Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    let captures = state.captures.read().unwrap(); // <-- Добавили присваивание
    match captures.get(&id) { 
        Some(c) => Ok(Json(json!(c))),
        None => Err(api_error("Capture not found", StatusCode::NOT_FOUND))
    }
}

pub(crate) async fn generate_report( //мясо, наверное даже фарш. Генератор отчётов
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>
) -> Response<Body> {
    let project_name = body["project_name"].as_str().unwrap_or("Без названия");
    let cid = body["capture_id"].as_str().unwrap_or("");
    let saved = state.last_check.read().unwrap().get(cid).cloned();
    let (total, success, errors, rows) = match saved {
        Some(r) => (r.summary.total as u64, r.summary.ok as u64, r.summary.error as u64, r.rows),
        None => return Response::builder().status(404).body(Body::from("no check for capture")).unwrap(),
    };

    let mut md = String::new();
    md.push_str(&format!("# Отчёт: {}\n\n", project_name));
    md.push_str(&format!("- Всего: {}\n- Успешно: {}\n- Ошибок: {}\n\n", total, success, errors));

    md.push_str("## Контрпримеры\n| Действие | Время | Статус | Сообщение |\n|---|---|---|---|\n");
    for ex in &rows {
        md.push_str(&format!("| {} | {} | {} | {} |\n", ex.action_id, ex.time, ex.status, ex.message_id.clone().unwrap_or("-".to_string())));
    }

    Response::builder()
        .header(header::CONTENT_TYPE, "text/markdown")
        .header(header::CONTENT_DISPOSITION, "attachment; filename=\"report.md\"")
        .body(Body::from(md))
        .unwrap()
}

pub(crate) async fn upload_capture(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    mut form: Multipart 
) -> Json<serde_json::Value> {
    let _ = std::fs::create_dir_all("uploads");
    
    let mut saved_file_path = String::from("uploads/unknown.pcap");

    // Проходим по полям по полям синий трактор едет к нам
    while let Ok(Some(field)) = form.next_field().await {
        let file_name = field.file_name().unwrap_or("upload.pcap").to_string(); //деаноним имя файла
        
        let data = field.bytes().await.unwrap_or_default(); // записываем байты в дату переменную йо

        saved_file_path = format!("uploads/{}", file_name); //генерируем путь истинный

        let _ = std::fs::write(&saved_file_path, &data); // сохран
    }

    let path = StdPath::new(&saved_file_path);

    match protocol_lab_core::pcap::reader::read_pcap(path) { //читаем файл пакетов с продуктами
        Ok(packets) => {
            let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets); //отденьно отсордировываем по группам пакеты чтобы не было мешанины

            if let Ok(mut captures) = state.captures.write() {
                if let Some(capture) = captures.get_mut(&id) { 
                    capture.file_name = saved_file_path.clone();
                    capture.session_count = sessions.len() as u32;
                    capture.size_bytes = std::fs::metadata(&saved_file_path).map(|m| m.len()).unwrap_or(0);
                }
            }

            Json(json!({
                "project_id": id,
                "packets_found": packets.len(),
                "sessions_found": sessions.len(),
                "saved_to": saved_file_path
            }))
        }
        Err(e) => {
            Json(json!({"error": format!("Ошибка чтения pcap: {}", e)}))
        }
    }
}


pub(crate) fn collect_pcaps(dir: &StdPath, out: &mut Vec<std::path::PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_pcaps(&p, out);
            } else if p.extension().and_then(|s| s.to_str()) == Some("pcap") || p.extension().and_then(|s| s.to_str()) == Some("pcapng") {
                out.push(p);
            }
        }
    }
}

pub(crate) async fn import_project(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    let mut archive: Vec<u8> = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            archive = field.bytes().await.map_err(|_| api_error("Failed to read file", StatusCode::BAD_REQUEST))?.to_vec();
        }
    }
    if archive.is_empty() {
        return Err(api_error("File is empty or missing", StatusCode::BAD_REQUEST));
    }
    let tmp = tempfile::tempdir().map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    tar::Archive::new(flate2::read::GzDecoder::new(&archive[..])).unpack(tmp.path())
        .map_err(|e| api_error(&format!("Bad archive: {}", e), StatusCode::BAD_REQUEST))?;
    let mut pcaps = Vec::new();
    collect_pcaps(tmp.path(), &mut pcaps);
    let mut imported = Vec::new();
    let mut skipped = 0u32;
    for p in pcaps {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("upload.pcap").to_string();
        match std::fs::read(&p) {
            Ok(bytes) => match crate::captures::ingest_packets(&state, name, bytes) {
                Ok(c) => imported.push(c.id),
                Err(_) => skipped += 1,
            },
            Err(_) => skipped += 1,
        }
    }
    Ok(Json(json!({ "imported": imported, "skipped": skipped })))
}

pub(crate) async fn export_project(
    Json(body): Json<serde_json::Value>
) -> Response<Body> {
    let mut archive_buffer: Vec<u8> = Vec::new(); //готовим буфер куда туда сюда
    
    let gz_encoder = GzEncoder::new(&mut archive_buffer, Compression::default()); // Газан пишет в наш буфер 

    let mut tar_builder = Builder::new(gz_encoder); // Тартар архиватор который пишет в газана

    let rules_json = serde_json::to_vec_pretty(&body["rules"]) // json->красивые байты
        .unwrap_or_default();

    let mut rules_header = tar::Header::new_gnu();
    rules_header.set_size(rules_json.len() as u64);
    rules_header.set_mode(0o644);
    tar_builder
        .append_data(&mut rules_header, "rules.json", rules_json.as_slice())
        .ok();

    // Какой то манифест проекта
    let manifest = json!({
        "project_name": body["project_name"].as_str().unwrap_or("unnamed"),
        "files": body["files"],
        "expected_at": "2026-10-13T00:00:00Z"
    });

    let manifest_json = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_size(manifest_json.len() as u64);
    manifest_header.set_mode(0o644);
    tar_builder
        .append_data(&mut manifest_header, "manifest.json", manifest_json.as_slice())
        .ok();

    // Добавляем писи-файлы в архив если всё норм
    if let Some(files_arr) = body["files"].as_array() {
        for file_val in files_arr {
            if let Some(file_path) = file_val.as_str() {
                let path = StdPath::new(file_path);
                if path.exists() {
                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown.pcap");
                    
                    tar_builder.append_path_with_name(path, file_name).ok();
                } else {
                    eprintln!("[export] файл не найден, пропущен: {}", file_path);
                }
            }
        }
    }

    // завершаем ритуал с архивом
    let gz_encoder = tar_builder.into_inner().unwrap();
    gz_encoder.finish().unwrap();

    // чтобы у типа загрузка архива началась
    Response::builder()
        .header(header::CONTENT_TYPE, "application/gzip")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"project.tar.gz\""
        )
        .body(Body::from(archive_buffer))
        .unwrap()
}
