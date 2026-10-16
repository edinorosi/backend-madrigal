use std::path::Path as StdPath;

use axum::{
    body::Body,
    extract::{Multipart, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use tar::Builder;

use crate::error::api_error;
use crate::state::AppState;

pub(crate) async fn generate_report( //мясо, наверное даже фарш. Генератор отчётов
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>
) -> Response<Body> {
    let project_name = body["project_name"].as_str().or_else(|| body["projectName"].as_str()).unwrap_or("Без названия");
    let cid = body["capture_id"].as_str().or_else(|| body["captureId"].as_str()).unwrap_or("");
    let saved = state.last_check.read().unwrap().get(cid).cloned();
    let (total, success, errors, rows) = match saved {
        Some(r) => (r.summary.total as u64, r.summary.ok as u64, r.summary.error as u64, r.rows),
        None => return api_error("no check for capture", StatusCode::NOT_FOUND).into_response(),
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
    // Журналы из архива: глобальный + per-capture по имени pcap.
    let mut journals: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    let journals_dir = tmp.path().join("journals");
    if let Ok(rd) = std::fs::read_dir(&journals_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                if let (Some(name), Ok(bytes)) = (p.file_name().and_then(|n| n.to_str()), std::fs::read(&p)) {
                    if let Some(base) = name.strip_suffix(".journal.csv") {
                        journals.insert(base.to_string(), bytes);
                    }
                }
            }
        }
    }
    let mut imported = Vec::new();
    let mut skipped = 0u32;
    let mut journals_restored = 0u32;
    for p in pcaps {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("upload.pcap").to_string();
        match std::fs::read(&p) {
            Ok(bytes) => match crate::captures::ingest_packets(&state, name.clone(), bytes) {
                Ok(c) => {
                    if let Some(jb) = journals.get(&name) {
                        let dest = crate::check::per_capture_journal_path(&state.data_dir, &c.id);
                        if std::fs::write(&dest, jb).is_ok() {
                            journals_restored += 1;
                        }
                    }
                    imported.push(c.id);
                }
                Err(_) => skipped += 1,
            },
            Err(_) => skipped += 1,
        }
    }
    // Глобальный журнал — в стор (валидируем шапку перед записью).
    let global_src = tmp.path().join("journal_global.csv");
    if let Ok(bytes) = std::fs::read(&global_src) {
        let dest = crate::check::global_journal_path(&state.data_dir);
        if std::fs::write(&dest, &bytes).is_ok() {
            journals_restored += 1;
        }
    }
    Ok(Json(json!({ "imported": imported, "skipped": skipped, "journals_restored": journals_restored })))
}

pub(crate) async fn export_project(
    State(state): State<AppState>,
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

    // Журналы: глобальный + per-capture (ключ — имя pcap, id при импорте новые).
    let mut journal_count = 0u32;
    let global_journal = crate::check::global_journal_path(&state.data_dir);
    let mut has_global_journal = false;
    if let Ok(bytes) = std::fs::read(&global_journal) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        tar_builder.append_data(&mut header, "journal_global.csv", bytes.as_slice()).ok();
        has_global_journal = true;
        journal_count += 1;
    }
    for cap in state.captures.read().unwrap().values() {
        let src = crate::check::per_capture_journal_path(&state.data_dir, &cap.id);
        if let Ok(bytes) = std::fs::read(&src) {
            let safe_name: String = cap.file_name.replace(['/', '\\'], "_");
            let entry = format!("journals/{}.journal.csv", safe_name);
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            tar_builder.append_data(&mut header, entry.as_str(), bytes.as_slice()).ok();
            journal_count += 1;
        }
    }

    // Pcap записей: source.pcap каждой записи — иначе перенос проекта
    // на другую машину не работает (фронт шлёт files:[] и путей не знает).
    // Ключ — имя файла (импорт матчит журналы по нему же); дубли имён
    // пропускаем, чтобы не перезаписать друг друга в архиве.
    let mut pcap_names: Vec<String> = Vec::new();
    let mut pcap_dupes = 0u32;
    for cap in state.captures.read().unwrap().values() {
        let safe_name: String = cap.file_name.replace(['/', '\\'], "_");
        if pcap_names.iter().any(|n| n == &safe_name) {
            pcap_dupes += 1;
            continue;
        }
        let src = std::path::Path::new(&crate::state::capture_dir_in(&state.data_dir, &cap.id))
            .join("source.pcap");
        if let Ok(bytes) = std::fs::read(&src) {
            let entry = format!("pcaps/{}", safe_name);
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            tar_builder.append_data(&mut header, entry.as_str(), bytes.as_slice()).ok();
            pcap_names.push(safe_name);
        }
    }

    // Какой то манифест проекта
    let manifest = json!({
        "project_name": body["project_name"].as_str().unwrap_or("unnamed"),
        "files": body["files"],
        "expected_at": chrono::Utc::now().to_rfc3339(),
        "has_global_journal": has_global_journal,
        "journal_count": journal_count,
        "pcaps": pcap_names,
        "pcap_duplicates_skipped": pcap_dupes,
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
                let path = match crate::error::jail_path(file_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[export] путь вне разрешённых, пропущен: {} ({})", file_path, e);
                        continue;
                    }
                };
                if path.exists() {
                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown.pcap")
                        .to_string();
                    
                    tar_builder.append_path_with_name(&path, file_name).ok();
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
