mod dto;

use axum::{
    body::Body,
    extract::{Multipart, Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use protocol_lab_core::interpreter::{apply_rule, FieldType, FramingRule, frame_stream, InterpretationRule};
use protocol_lab_core::pcap::{reader::read_pcap, session::group_into_sessions};
use protocol_lab_core::tcp::stream::StreamChunk;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path as StdPath;
use std::sync::{Arc, RwLock};
use tar::Builder;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use dto::{
    Action, Capture, CheckResult, CheckSummary, Endpoint, Message, Model, Observation, Session,
    SessionTuple,
};


pub struct AppData {
    pub captures: RwLock<HashMap<String, Capture>>,
    pub sessions: RwLock<HashMap<String, Session>>,
    pub messages: RwLock<HashMap<String, Message>>,
    pub observations: RwLock<HashMap<String, Observation>>,
    pub models: RwLock<HashMap<String, Model>>,
    pub raw_bytes: RwLock<HashMap<String, Vec<u8>>>, // хранение пустых писи-файлы 
}

// ВАЖНО: Здесь должно быть AppData, а не AppState, чтобы не было цикла
pub type AppState = Arc<AppData>;


async fn list_captures(State(state): State<AppState>) -> Json<Vec<Capture>> {
    let captures = state.captures.read().unwrap();
    let list: Vec<Capture> = captures.values().cloned().collect();
    Json(list)
}

async fn import_capture(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<Capture>), (StatusCode, Json<dto::ErrorResponse>)> {
    let mut file_bytes: Vec<u8> = Vec::new(); //байтсы
    let mut file_name = String::from("unknown.pcap"); //временное название

    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            file_name = field.file_name().unwrap_or("unknown.pcap").to_string();
            file_bytes = field.bytes().await.map_err(|_| api_error("Failed to read file", StatusCode::BAD_REQUEST))?.to_vec(); //пишем байтсы
        }
    }

    if file_bytes.is_empty() {
        return Err(api_error("File is empty or missing", StatusCode::BAD_REQUEST));
    }

    // парсим pcap во временный файл
    let temp_path = format!("/tmp/{}.pcap", Uuid::new_v4());
    std::fs::write(&temp_path, &file_bytes).map_err(|_| api_error("IO Error", StatusCode::INTERNAL_SERVER_ERROR))?;

    let packets = protocol_lab_core::pcap::reader::read_pcap(StdPath::new(&temp_path))
        .map_err(|e| api_error(&format!("PCAP parse error: {}", e), StatusCode::BAD_REQUEST))?;

    let sessions_core = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    
    let capture_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let capture = Capture {
        id: capture_id.clone(),
        file_name,
        imported_at: now.clone(),
        size_bytes: file_bytes.len() as u64,
        session_count: sessions_core.len() as u32,
    };

    // фотографируем закат будто пару лет назад
    state.captures.write().unwrap().insert(capture_id.clone(), capture.clone());
    state.raw_bytes.write().unwrap().insert(capture_id.clone(), file_bytes);

    // создаём сессии
    for (idx, s_core) in sessions_core.iter().enumerate() {
        let session_id = Uuid::new_v4().to_string();
        let session = Session {
            id: session_id,
            capture_id: capture_id.clone(),
            tuple: SessionTuple {
                source: Endpoint { address: "0.0.0.0".to_string(), port: 12345 }, // TODO: взять из s_core
                destination: Endpoint { address: "0.0.0.0".to_string(), port: 80 },
            },
            message_count: s_core.packets.len() as u32, // Заглушка
            started_at: now.clone(),
        };
        state.sessions.write().unwrap().insert(session.id.clone(), session);
    }

    Ok((StatusCode::CREATED, Json(capture)))
}



async fn get_flow_bytes(
    AxumPath(session_id): AxumPath<String>,
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {

    //fkkf[ ,f,f[]]

    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let path = StdPath::new(file_path);

    let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e.to_string()})),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    let idx: usize = session_id.parse().unwrap_or(0);
    
    if idx >= sessions.len() {
        return Json(json!({"error": "Session not found"}));
    }
    let session = &sessions[idx];

    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

    let result: Vec<serde_json::Value> = chunks.into_iter().map(|chunk| {
        match chunk {
            StreamChunk::Data { flow_offset, length, packet_index } => {
                let hex_data = match session.packets.iter().find(|p| p.index == packet_index) {
                    Some(pkt) => pkt.payload.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                    None => format!("ERR: global packet_index {} not found", packet_index),
                };
            
                json!({
                    "type": "data",
                    "offset": flow_offset,
                    "length": length,
                    "packet_index": packet_index,
                    "hex": hex_data
                })
            }
            StreamChunk::Gap { flow_offset, missing_bytes } => {
                json!({
                    "type": "gap",
                    "offset": flow_offset,
                    "missing_bytes": missing_bytes
                })
            }
            _ => json!({"type": "unknown"})
        }
    }).collect();

    Json(json!({"flow": "client_to_server", "chunks": result}))
}

fn api_error(msg: &str, status: StatusCode) -> (StatusCode, Json<dto::ErrorResponse>) {
    (status, Json(dto::ErrorResponse { error: msg.to_string() }))
}

async fn list_sessions(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
) -> Result<Json<Vec<Session>>, (StatusCode, Json<dto::ErrorResponse>)> {
    // проверяем существования снимка
    if !state.captures.read().unwrap().contains_key(&capture_id) {
        return Err(api_error("Capture not found", StatusCode::NOT_FOUND));
    }

    let sessions = state.sessions.read().unwrap();
    let list: Vec<Session> = sessions
        .values()
        .filter(|s| s.capture_id == capture_id)
        .cloned()
        .collect();
    
    Ok(Json(list))
}


#[derive(serde::Deserialize, Debug)]
struct _JournalEntry {
    timestamp: String,
    action: String,
    parameter: Option<String>,
}


async fn apply_interpretation(
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {
    let framing_str = body["framing"]["type"].as_str().unwrap_or("fixed");
    let framing_size = body["framing"]["size"].as_u64().unwrap_or(12) as usize;
    let framing_rule = match framing_str {
        "length_prefixed" => FramingRule::LengthPrefixed,
        _ => FramingRule::FixedSize(framing_size),
    };
    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let session_idx: usize = body["session_id"].as_u64().unwrap_or(0) as usize;
    let _offset: usize = body["offset"].as_u64().unwrap_or(0) as usize;

    let rule_name = body["rule"]["name"].as_str().unwrap_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unwrap_or("u8");
    let rule_offset = body["rule"]["offset"].as_u64().unwrap_or(0) as usize;
    let field_type = match rule_type_str {
        "u16_big" => FieldType::U16Big,
        _ => FieldType::U8,
    };

    let rule = InterpretationRule {
        name: rule_name.to_string(),
        offset: rule_offset,
        field_type,
    };

    let path = StdPath::new(file_path);
    let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e.to_string()})),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    if session_idx >= sessions.len() {
        return Json(json!({"error": "Session not found"}));
    }
    let session = &sessions[session_idx];

    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);
    let mut gap_offsets: Vec<usize> = Vec::new();

    let mut clean_bytes: Vec<u8> = Vec::new();
    for chunk in &chunks {
        match chunk {
            StreamChunk::Data { packet_index, ..} => {
                if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                    clean_bytes.extend_from_slice(&pkt.payload);
                } 
            }
            StreamChunk::Gap { flow_offset, .. } => {
                gap_offsets.push(*flow_offset);
            }
            _ => {} //игнорируем анонимных
        }
    }
    
    //режем поток на сообщ по законам Шариата(Framing_Rule)
    let messages = frame_stream(&clean_bytes, &framing_rule);
    let results: Vec<serde_json::Value> = messages.into_iter().map(|msg|{  //проходим по сообщению (1...8(развернуть на 90 градусов) аят) отсекаем  неверных
        let is_after_gap = gap_offsets.iter().any(|&gap_off| msg.stream_offset >= gap_off);
        if is_after_gap { //сообщение после дырки
            return json!({
                "stream_offset": msg.stream_offset,
                "success": false,
                "error": "Data after TCP Gap (unreliable)",
                "type": "incomplete"
            });
        }
        match apply_rule(&msg.payload, &rule) { //пробуем применять правила 
            Some(parsed) => json!({
                "stream_offset": msg.stream_offset,
                "success": true,
                "field": parsed
            }),
            None => json!({
                "stream_offset": msg.stream_offset,
                "success": false,
                "error": "Not enough bytes in message"
            }),
        }
    }).collect();

    //платим по долгам
    Json(json!({
        "total_messages": results.len(),
        "results": results
    }))
}

//дал-дал ушел()
async fn verify_corpus(
    Json(body): Json<serde_json::Value>
) -> impl IntoResponse {

    let files = match body["files"].as_array() { //пирсинг файлов входных
        Some(arr) => arr.clone(),
        None => return Json(json!({"error": "files array required"})).into_response(),
    };
    
    let framing_str = body["framing"]["type"].as_str().unwrap_or("fixed");
    let framing_size = body["framing"]["size"].as_u64().unwrap_or(12) as usize;
    let rule_name = body["rule"]["name"].as_str().unwrap_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unwrap_or("u8");
    let rule_offset = body["rule"]["offset"].as_u64().unwrap_or(0) as usize;
    let expected_value = body["expected_value"].as_str().map(|s| s.to_string());

    let journal_path = body["journal_path"].as_str().map(|s| s.to_string());
    let mut journal_entries: Vec<serde_json::Value> = Vec::new();
    if let Some(j_path) = journal_path {
        if let Ok(mut rdr) = csv::Reader::from_path(&j_path) {
            for result in rdr.deserialize() {
                if let Ok(record) = result {
                    journal_entries.push(record);
                }
            }
        }
    }

    let framing_rule = match framing_str {  //правила 
        "length_prefixed" => FramingRule::LengthPrefixed,
        _ => FramingRule::FixedSize(framing_size),
    };
    
    let field_type = match rule_type_str {
        "u16_big" => FieldType::U16Big,
        _ => FieldType::U8,
    };

    let rule = InterpretationRule {
        name: rule_name.to_string(),
        offset: rule_offset,
        field_type,
    };


    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<Event, Infallible>>(); //готовим канал для стрима


    tokio::spawn(async move { //асинхронное фоновое выполнееи
        let mut total_messages = 0;
        let mut success_count = 0;
        let mut error_count = 0;
        let mut counterexamples = Vec::new();

        let total_files = files.len();

        for (file_idx, file_val) in files.iter().enumerate() {
            let file_path = match file_val.as_str() {
                Some(p) => p.to_string(),
                None => continue,
            };


            let _ = tx.send(Ok(Event::default().data(&format!("Обработка файла {}/{}: {}", file_idx + 1, total_files, file_path)))); // отправка события типо что началась обработка файла

            let path = StdPath::new(&file_path);
            let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(Ok(Event::default().data(&format!("Ошибка чтения {}: {}", file_path, e))));
                    continue;
                }
            };

            let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
            let total_sessions = sessions.len();

            for (session_idx, session) in sessions.iter().enumerate() {
                
                let _ = tx.send(Ok(Event::default().data(&format!("  Сессия {}/{}...", session_idx + 1, total_sessions)))); //

                let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
                let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

                let mut clean_bytes: Vec<u8> = Vec::new();
                let mut gap_offsets: Vec<usize> = Vec::new();

                for chunk in &chunks {
                    match chunk {
                        StreamChunk::Data { packet_index, .. } => {
                            if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                                clean_bytes.extend_from_slice(&pkt.payload);
                            }
                        }
                        StreamChunk::Gap { flow_offset, .. } => {
                            gap_offsets.push(*flow_offset);
                        }
                        _ => {}
                    }
                }

                let messages = frame_stream(&clean_bytes, &framing_rule);

                for msg in messages {
                    total_messages += 1;

                    let is_after_gap = gap_offsets.iter().any(|&gap_off| msg.stream_offset >= gap_off);
                    if is_after_gap {
                        counterexamples.push(json!({
                            "file": file_path, 
                            "session": session_idx, 
                            "stream_offset": msg.stream_offset,
                            "error": "Data after TCP Gap", 
                            "type": "incomplete"
                        }));
                        continue;
                    }

                    match apply_rule(&msg.payload, &rule) {
                        Some(parsed) => {
                            success_count += 1;
                            if let Some(ref expected) = expected_value {
                                if parsed["value"] != *expected {
                                    counterexamples.push(json!({
                                        "file": file_path, 
                                        "session": session_idx, 
                                        "stream_offset": msg.stream_offset,
                                        "expected": expected, 
                                        "actual": parsed["value"], 
                                        "type": "value_mismatch"
                                    }));
                                }
                            }
                        }
                        None => {
                            error_count += 1;
                            counterexamples.push(json!({
                                "file": file_path, 
                                "session": session_idx, 
                                "stream_offset": msg.stream_offset,
                                "error": "Not enough bytes", 
                                "type": "parse_error"
                            }));
                        }
                    }
                }
            }
        }

        // 4. Отправляем финальный результат
        let final_result = json!({
            "type": "done",
            "total_messages": total_messages,
            "success_count": success_count,
            "error_count": error_count,
            "journal": journal_entries
        });
        let _ = tx.send(Ok(Event::default().data(&final_result.to_string())));
    });

    // 5. Возвращаем SSE стрим
    Sse::new(UnboundedReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}



async fn get_bytes(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<dto::ErrorResponse>)> {
    if !state.captures.read().unwrap().contains_key(&capture_id) {
        return Err(api_error("Capture not found", StatusCode::NOT_FOUND));
    }

    //берём параметрыы
    let offset: u64 = params.get("offset").and_then(|s| s.parse().ok()).ok_or_else(|| api_error("Missing offset", StatusCode::BAD_REQUEST))?; // <-- Добавь ? здесь
    let length: u64 = params.get("length").and_then(|s| s.parse().ok()).ok_or_else(|| api_error("Missing length", StatusCode::BAD_REQUEST))?; // <-- И здесь

    let raw = state.raw_bytes.read().unwrap();
    let bytes = raw
        .get(&capture_id)
        .ok_or_else(|| api_error("No raw bytes", StatusCode::NOT_FOUND))?;

    let start = offset as usize;
    let end = start + length as usize;

    if end > bytes.len() { //вышли за рамки дозволенного
        return Err(api_error("Range out of bounds", StatusCode::BAD_REQUEST));
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes[start..end].to_vec(),
    ))
}


async fn analyze_autosuggest(
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {
    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let path = StdPath::new(file_path);

    let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e.to_string()})),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    if sessions.is_empty() {
        return Json(json!({"error": "No sessions found"}));
    }

    let session = &sessions[0];
    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

    let mut clean_bytes: Vec<u8> = Vec::new();
    for chunk in &chunks {
        if let StreamChunk::Data { packet_index, .. } = chunk {
            if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                clean_bytes.extend_from_slice(&pkt.payload); //пакистан родненький, привет
            }
        }
    }

    if clean_bytes.len() < 10 {
        return Json(json!({"hypotheses": [], "message": "Недостаточно данных для анализа"}));
    }

    let mut hypotheses = Vec::new(); //гипотезы

    for size in [4, 8, 12, 16, 24, 32, 64, 128] {
        if clean_bytes.len() % size == 0 && (clean_bytes.len() / size) >= 3 {
            
            hypotheses.push(json!({
                "type": "fixed_size",
                "confidence": 0.85,
                "reason": format!("Длина потока ({}) идеально делится на {}. Найдено {} сообщений.", clean_bytes.len(), size, clean_bytes.len() / size),
                "suggested_framing": {"type": "fixed", "size": size}
            }));
            break;
        }
    }

    for prefix_bytes in [1,2] {
        let mut valid_count = 0;
        let mut total_checked = 0;
        let mut offset = 0;

        while offset + prefix_bytes <= clean_bytes.len() {
            let len = if prefix_bytes == 1 {
                clean_bytes[offset] as usize
            } else {
                u16::from_be_bytes([clean_bytes[offset], clean_bytes[offset+1]]) as usize
            };

            if len > 0 && len < 4096 && offset + prefix_bytes + len <= clean_bytes.len() {
                valid_count += 1;
                offset += prefix_bytes + len;
            } else {
                break;
            }
            total_checked += 1;
        }

        if total_checked >= 3 && (valid_count as f64 / total_checked as f64) > 0.7 {
            hypotheses.push(json!({
                "type": "length_prefixed",
                "confidence": 0.90,
                "reason": format!("Первые {} байта успешно интерпретируются как длина payload в {} сообщениях.", prefix_bytes, valid_count),
                "suggested_framing": {"type": "length_prefixed", "size_bytes": prefix_bytes}
            }));
            break;
        }
    }

    let sync_words = [[0xAA, 0x55], [0x55, 0xAA], [0xFF, 0x00], [0x00, 0xFF], [0x7E, 0x7E]];
    for &sync in &sync_words {
        let mut count = 0;
        for i in 0..clean_bytes.len().saturating_sub(1) {
            if clean_bytes[i] == sync[0] && clean_bytes[i+1] == sync[1] {
                count += 1;
            }
        }
        if count >= 3 {
            let sync_hex = format!("{:02X} {:02X}", sync[0], sync[1]);
            hypotheses.push(json!({
                "type": "sync_word",
                "confidence": 0.75,
                "reason": format!("Найден повторяющийся маркер {} {} раз(а). Возможно, это начало фрейма.", sync_hex, count),
                "suggested_framing": {"type": "sync_word", "sync": sync_hex}
            }));

        }
    }

    hypotheses.sort_by(|a, b| {
        b["confidence"].as_f64().unwrap_or(0.0)
            .partial_cmp(&a["confidence"].as_f64().unwrap_or(0.0))
            .unwrap()
    });

    Json(json!({
        "file": file_path,
        "total_bytes_analyzed": clean_bytes.len(),
        "hypotheses": hypotheses
    }))




}


async fn create_project(State(state): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
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
async fn get_projects(State(state): State<AppState>) -> Json<serde_json::Value> {
    let captures = state.captures.read().unwrap(); 
    let list: Vec<serde_json::Value> = captures.values().map(|c| {
        json!({"id": c.id, "name": c.file_name})
    }).collect(); 
    Json(json!({"projects": list})) 
}

async fn get_project(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> Json<serde_json::Value> {
    let captures = state.captures.read().unwrap(); // <-- Добавили присваивание
    match captures.get(&id) { 
        Some(c) => Json(json!(c)),
        None => Json(json!({ "error": "Capture not found" }))
    }
}

async fn list_actions(
    State(_state): State<AppState>,
    AxumPath(_capture_id): AxumPath<String>,
) -> Json<Vec<Action>> {
    // TODO: парсинг action_journal.csv
    Json(vec![])
}

async fn list_messages(
    State(_state): State<AppState>,
    AxumPath(_session_id): AxumPath<String>,
) -> Json<Vec<Message>> {
    // TODO: генерация сообщений из сессий
    Json(vec![])
}

async fn list_observations(
    State(_state): State<AppState>,
    AxumPath(_message_id): AxumPath<String>,
) -> Json<Vec<Observation>> {
    Json(vec![])
}

async fn apply_model(
    State(_state): State<AppState>,
    AxumPath(_message_id): AxumPath<String>,
    Json(_body): Json<serde_json::Value>,
) -> Json<Vec<dto::MessageField>> {
    // TODO: применение модели к сообщению
    Json(vec![])
}

async fn save_observation(
    State(state): State<AppState>,
    Json(obs): Json<Observation>,
) -> StatusCode {
    state
        .observations
        .write()
        .unwrap()
        .insert(obs.id.clone(), obs);
    StatusCode::NO_CONTENT
}


async fn remove_observation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<dto::ErrorResponse>)> {
    let mut observations = state.observations.write().unwrap();
    if observations.remove(&id).is_none() {
        return Err(api_error("Observation not found", StatusCode::NOT_FOUND));
    }
    Ok(StatusCode::NO_CONTENT)
}


async fn check_model(
    State(_state): State<AppState>,
    Json(_body): Json<serde_json::Value>,
) -> Json<CheckResult> {
    // TODO: прогон модели по журналу
    Json(CheckResult {
        rows: vec![],
        summary: CheckSummary {
            total: 0,
            ok: 0,
            partial: 0,
            unknown: 0,
            error: 0,
        },
        model_id: None,
        model_name: None,
    })
}

async fn list_models(State(state): State<AppState>) -> Json<Vec<Model>> {
    let models = state.models.read().unwrap();
    let list: Vec<Model> = models.values().cloned().collect();
    Json(list)
}

async fn save_model(
    State(state): State<AppState>,
    Json(model): Json<Model>,
) -> StatusCode {
    state.models.write().unwrap().insert(model.id.clone(), model);
    StatusCode::NO_CONTENT
}

async fn remove_model(
    State(state): State<AppState>,
    AxumPath(model_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<dto::ErrorResponse>)> {
    let mut models = state.models.write().unwrap();
    if models.remove(&model_id).is_none() {
        return Err(api_error("Model not found", StatusCode::NOT_FOUND));
    }
    Ok(StatusCode::NO_CONTENT)
}



async fn add_observation(
    State(state): State<AppState>, 
    AxumPath(message_id): AxumPath<String>, 
    Json(mut body): Json<dto::Observation>
) -> Json<serde_json::Value> {
    body.message_id = message_id;

    if body.id.is_empty() {
        body.id = uuid::Uuid::new_v4().to_string();
    }
    body.created_at = chrono::Utc::now().to_rfc3339();
    
    //реестр наблюдей
    state.observations.write().unwrap().insert(body.id.clone(), body);
    
    Json(json!({ "status": "saved" }))
}

async fn generate_report( //мясо, наверное даже фарш. Генератор отчётов
    Json(body): Json<serde_json::Value>
) -> Response<Body> {
    let project_name = body["project_name"].as_str().unwrap_or("Без названия");
    let total = body["results"]["total_messages"].as_u64().unwrap_or(0);
    let success = body["results"]["success_count"].as_u64().unwrap_or(0);
    let errors = body["results"]["error_count"].as_u64().unwrap_or(0);

    let mut md = String::new();
    md.push_str(&format!("# Отчёт: {}\n\n", project_name));
    md.push_str(&format!("- Всего: {}\n- Успешно: {}\n- Ошибок: {}\n\n", total, success, errors));

    if let Some(examples) = body["results"]["counterexamples"].as_array() {
        md.push_str("## Контрпримеры\n| Файл | Смещение | Ожидалось | Получено |\n|---|---|---|---|\n");
        for ex in examples {
            md.push_str(&format!("| {} | {} | {} | {} |\n", 
                ex["file"].as_str().unwrap_or("-"),
                ex["stream_offset"].as_u64().unwrap_or(0),
                ex["expected"].as_str().unwrap_or("-"),
                ex["actual"].as_str().unwrap_or("-")
            ));
        }
    }

    Response::builder()
        .header(header::CONTENT_TYPE, "text/markdown")
        .header(header::CONTENT_DISPOSITION, "attachment; filename=\"report.md\"")
        .body(Body::from(md))
        .unwrap()
}

async fn upload_capture(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    mut form: Multipart 
) -> Json<serde_json::Value> {
    std::fs::create_dir_all("uploads").unwrap();
    
    let mut saved_file_path = String::from("uploads/unknown.pcap");

    // Проходим по полям по полям синий трактор едет к нам
    while let Ok(Some(field)) = form.next_field().await {
        let file_name = field.file_name().unwrap_or("upload.pcap").to_string(); //деаноним имя файла
        
        let data = field.bytes().await.unwrap(); // записываем байты в дату переменную йо

        saved_file_path = format!("uploads/{}", file_name); //генерируем путь истинный

        std::fs::write(&saved_file_path, &data).unwrap(); // сохран
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


async fn export_project(
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




#[tokio::main]
async fn main() {
    let state = Arc::new(AppData {
        captures: RwLock::new(HashMap::new()),
        sessions: RwLock::new(HashMap::new()),
        messages: RwLock::new(HashMap::new()),
        observations: RwLock::new(HashMap::new()),
        models: RwLock::new(HashMap::new()),
        raw_bytes: RwLock::new(HashMap::new()),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/v1/captures", get(list_captures).post(import_capture))
        .route("/api/v1/captures/{capture_id}/sessions", get(list_sessions))
        .route("/api/v1/captures/{capture_id}/bytes", get(get_bytes))
        .route("/api/v1/captures/{capture_id}/actions", get(list_actions))
        .route("/api/v1/sessions/{session_id}/messages", get(list_messages))
        .route("/api/v1/messages/{message_id}/observations", get(list_observations))
        .route("/api/v1/messages/{message_id}/apply-model", post(apply_model))
        .route("/api/v1/observations", put(save_observation))
        .route("/api/v1/observations/{id}", delete(remove_observation))
        .route("/api/v1/check", post(check_model))
        .route("/api/v1/models", get(list_models).put(save_model))
        .route("/api/v1/models/{model_id}", delete(remove_model))
        .route("/api/v1/projects", post(create_project).get(get_projects))
        .route("/api/v1/projects/{id}", get(get_project))
        .route("/api/v1/projects/{id}/captures", post(upload_capture))
        .route("/api/v1/projects/{id}/observations", post(add_observation))
        .route("/api/v1/flows/{session_id}/bytes", post(get_flow_bytes))
        .route("/api/v1/interpret/apply", post(apply_interpretation))
        .route("/api/v1/verify/corpus", post(verify_corpus))
        .route("/api/v1/projects/export", post(export_project))
        .route("/api/v1/report/generate", post(generate_report))
        .route("/api/v1/analyze/autosuggest", post(analyze_autosuggest))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Сервер запущен на http://0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}