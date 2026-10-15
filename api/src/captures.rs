use std::path::Path as StdPath;

use axum::{
    extract::{Multipart, Path as AxumPath, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::dto::{Capture, Endpoint, Message, Session, SessionTuple};
use crate::error::api_error;
use crate::state::{capture_dir_in, persist_capture, AppState};

pub(crate) async fn list_captures(State(state): State<AppState>) -> Json<Vec<Capture>> {
    let captures = state.captures.read().unwrap();
    let list: Vec<Capture> = captures.values().cloned().collect();
    Json(list)
}

pub(crate) fn ingest_packets(state: &AppState, file_name: String, file_bytes: Vec<u8>) -> Result<Capture, (StatusCode, Json<crate::dto::ErrorResponse>)> {
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
    let mut stream: Vec<u8> = Vec::new(); //стрим денжерлёхи
    for s_core in sessions_core.iter() { // Штурмуем сессии
        let session_id = Uuid::new_v4().to_string();
        let mut ordered = s_core.packets.clone();
        ordered.sort_by_key(|p| p.timestamp_us);
        let mut msgs: Vec<Message> = Vec::new(); // сообщения этой сессии
        for pkt in ordered.iter().filter(|p| !p.payload.is_empty()) { // только пакеты с данными
            let from_client = pkt.src_ip == s_core.key.client_ip.octets() && pkt.src_port == s_core.key.client_port; 
            let (direction, role) = if from_client { ("request".to_string(), "REQ".to_string()) } else { ("response".to_string(), "RSP".to_string()) };
            let byte_offset = stream.len() as u64; //смещение в общем потоке
            stream.extend_from_slice(&pkt.payload); // не спеша добавляем пакет в поток (Пакистанчик родненький)
            let ts = chrono::DateTime::from_timestamp_micros(pkt.timestamp_us as i64);// время в пакистанчике + сдвиг
            msgs.push(Message {
                id: Uuid::new_v4().to_string(),
                session_id: session_id.clone(),
                packet_number: pkt.index as u32,
                byte_offset,
                direction,
                role,
                length: pkt.payload.len() as u64,
                status: "unknown".to_string(),
                label: format!("{} б", pkt.payload.len()),
                timestamp: ts.map(|d| d.to_rfc3339()).unwrap_or(now.clone()),
                interpretation: "not-parsed".to_string(),
                verified: false,
                model_id: None,
                fields: vec![],
            }); 
        }


        let session = Session {
            id: session_id.clone(), 
            capture_id: capture_id.clone(), 
            tuple: SessionTuple { // реальный тюпл из ядра
                source: Endpoint { address: s_core.key.client_ip.to_string(), port: s_core.key.client_port },
                destination: Endpoint { address: s_core.key.server_ip.to_string(), port: s_core.key.server_port },
            },
            message_count: msgs.len() as u32, // число сообщений
            started_at: now.clone(),
        }; 
        state.sessions.write().unwrap().insert(session_id.clone(), session); 
        let mut all = state.messages.write().unwrap(); // лочим стор (ахаххахаха store типо магазин) сообщений
        for m in msgs { all.insert(m.id.clone(), m); } // кладём сообщения в стор
    } 

    state.raw_bytes.write().unwrap().insert(capture_id.clone(), stream);
    persist_capture(&state, &capture_id);
    std::fs::write(format!("{}/source.pcap", capture_dir_in(&state.data_dir, &capture_id)), &file_bytes).ok();

    Ok(capture)
}

pub(crate) async fn import_capture(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<Capture>), (StatusCode, Json<crate::dto::ErrorResponse>)> {
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

    let capture = ingest_packets(&state, file_name, file_bytes)?;

    Ok((StatusCode::CREATED, Json(capture)))
}

pub(crate) async fn list_sessions(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
) -> Result<Json<Vec<Session>>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    // проверяем существования снимка
    if !state.captures.read().unwrap().contains_key(&capture_id) {
        return Err(api_error("Capture not found", StatusCode::NOT_FOUND));
    }

    let sessions = state.sessions.read().unwrap();
    let mut list: Vec<Session> = sessions
        .values()
        .filter(|s| s.capture_id == capture_id)
        .cloned()
        .collect();
    
    list.sort_by(|a, b| a.started_at.cmp(&b.started_at));
    Ok(Json(list))
}

pub(crate) async fn get_bytes(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<crate::dto::ErrorResponse>)> {
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

pub(crate) async fn remove_capture(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(api_error("Bad capture id", StatusCode::BAD_REQUEST));
    }
    if state.captures.write().unwrap().remove(&id).is_none() {
        return Err(api_error("Capture not found", StatusCode::NOT_FOUND));
    }
    let sids: Vec<String> = state.sessions.read().unwrap().values().filter(|s| s.capture_id == id).map(|s| s.id.clone()).collect();
    let mut mids: Vec<String> = Vec::new();
    state.messages.write().unwrap().retain(|_, m| {
        if sids.contains(&m.session_id) {
            mids.push(m.id.clone());
            false
        } else {
            true
        }
    });
    state.sessions.write().unwrap().retain(|_, s| s.capture_id != id);
    state.raw_bytes.write().unwrap().remove(&id);
    state.observations.write().unwrap().retain(|_, o| !mids.contains(&o.message_id));
    state.last_check.write().unwrap().remove(&id);
    std::fs::remove_dir_all(capture_dir_in(&state.data_dir, &id)).ok();
    crate::state::persist_global(&state);
    Ok(StatusCode::NO_CONTENT)
}
